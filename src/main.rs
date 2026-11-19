// otinv command line.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use otinv::config::{Rules, Site, DEFAULT_RULES, SITE_TEMPLATE};
use otinv::model::Run;
use otinv::oui::Oui;
use otinv::runner::{self, RunnerChoice, DEFAULT_IMAGE};
use otinv::{diff, pipeline, pseudo, report, timefmt, util, zeek};
use std::path::{Path, PathBuf};

// the cli's own module, not the library's: the analysis code stays network-free
mod update;

#[derive(Parser)]
#[command(
    name = "otinv",
    version,
    about = "Turns passive captures from a utility's control network into a plain-English \
             asset inventory and a what-to-fix-first report. Analysis is passive and offline: it never sends anything to the network it describes."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analyze a capture (.pcap/.pcapng) or a folder of zeek logs
    Analyze(AnalyzeArgs),
    /// Compare two saved runs (run.londopy files)
    Diff(DiffArgs),
    /// Print the built-in rules, to save and customize
    Rules,
    /// Print an example site.toml
    SiteTemplate,
    /// Check GitHub for a newer otinv and install it, after asking
    Update(UpdateArgs),
}

#[derive(Args)]
struct AnalyzeArgs {
    /// A capture file, or a folder of zeek logs (conn.log, modbus.log, ...)
    input: PathBuf,
    /// Folder for the reports (use a new one per run, e.g. otinv-2026-11)
    #[arg(short, long, default_value = "otinv-report")]
    out: PathBuf,
    /// The previous run's run.londopy, to flag new devices and write a diff
    #[arg(long)]
    previous: Option<PathBuf>,
    /// Site file: friendly names, your address ranges, expected writers
    #[arg(long)]
    site: Option<PathBuf>,
    /// Rules file to use instead of the built-in rules
    #[arg(long)]
    rules: Option<PathBuf>,
    /// IEEE oui.csv for full MAC vendor names (offline copy)
    #[arg(long)]
    oui: Option<PathBuf>,
    /// Also write a pseudonymized copy of the reports to <out>/share, for sharing
    #[arg(long)]
    pseudonymize: bool,
    /// How to run zeek on a capture
    #[arg(long, value_enum, default_value_t = RunnerChoice::Auto)]
    runner: RunnerChoice,
    /// Path to the zeek binary (native runner)
    #[arg(long)]
    zeek: Option<PathBuf>,
    /// Docker image with zeek and ICSNPP (docker runner)
    #[arg(long, default_value = DEFAULT_IMAGE)]
    docker_image: String,
    /// Keep zeek's raw logs in <out>/zeek-logs (they can hold passwords)
    #[arg(long)]
    keep_logs: bool,
    /// Pseudonym map to keep aliases from (default: the one next to --previous)
    #[arg(long)]
    pseudonym_map: Option<PathBuf>,
    /// Refuse any single log file bigger than this many megabytes
    #[arg(long, default_value_t = zeek::DEFAULT_MAX_LOG_MB)]
    max_log_mb: u64,
}

#[derive(Args)]
struct DiffArgs {
    /// The older run.londopy
    old: PathBuf,
    /// The newer run.londopy
    new: PathBuf,
    /// Folder for diff.txt and diff.html
    #[arg(short, long, default_value = "otinv-diff")]
    out: PathBuf,
    /// Write the diff pseudonymized to <out>/share, for sharing
    #[arg(long)]
    pseudonymize: bool,
    /// Pseudonym map to keep aliases from (default: the one next to OLD)
    #[arg(long)]
    pseudonym_map: Option<PathBuf>,
}

#[derive(Args)]
struct UpdateArgs {
    /// Only say whether a newer release exists; change nothing
    #[arg(long)]
    check: bool,
    /// Install without asking (needed when there's no terminal to ask in)
    #[arg(short, long, conflicts_with = "check")]
    yes: bool,
}

fn main() {
    // the exe an earlier `otinv update` replaced (it can't delete itself)
    update::remove_leftover();
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Analyze(a) => analyze(a),
        Cmd::Diff(d) => diff_cmd(d),
        Cmd::Rules => {
            print!("{DEFAULT_RULES}");
            Ok(())
        }
        Cmd::SiteTemplate => {
            print!("{SITE_TEMPLATE}");
            Ok(())
        }
        Cmd::Update(u) => update::run(u.check, u.yes),
    };
    if let Err(e) = result {
        eprintln!("otinv: {e:#}");
        std::process::exit(1);
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// "otinv-2026-10/run.londopy": enough to tell runs apart, no full path.
fn short_path(p: &Path) -> String {
    let parent = p.parent().map(file_name).filter(|s| !s.is_empty());
    match parent {
        Some(dir) => format!("{dir}/{}", file_name(p)),
        None => file_name(p),
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn is_capture(p: &Path) -> bool {
    let ext = p
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    matches!(ext.as_str(), "pcap" | "pcapng" | "cap" | "dmp")
}

/// The pseudonym map to continue from: `--pseudonym-map`, else the
/// pseudonym-map.csv next to the previous run, else none.
fn previous_map(explicit: Option<&Path>, previous_run: Option<&Path>) -> Result<pseudo::Map> {
    let candidate = match explicit {
        Some(p) => Some(p.to_path_buf()),
        None => previous_run
            .and_then(Path::parent)
            .map(|d| d.join("pseudonym-map.csv"))
            .filter(|p| p.is_file()),
    };
    match candidate {
        Some(p) => {
            let text =
                std::fs::read_to_string(&p).with_context(|| format!("Reading {}", p.display()))?;
            let map =
                pseudo::Map::from_csv(&text).with_context(|| format!("In {}", p.display()))?;
            eprintln!("otinv: keeping the aliases from {}", p.display());
            Ok(map)
        }
        None => Ok(pseudo::Map::default()),
    }
}

/// Removes report files an earlier run left in `out` (and `out/share`), so a
/// stale diff or a stale shared copy never sits next to this run's reports.
/// Only otinv's own file names are touched.
fn clear_outputs(out: &Path) -> Result<()> {
    for dir in [out.to_path_buf(), out.join("share")] {
        for name in report::OUTPUT_FILES {
            let p = dir.join(name);
            if p.is_file() {
                std::fs::remove_file(&p).with_context(|| format!("Removing {}", p.display()))?;
            }
        }
    }
    let share = out.join("share");
    if share.is_dir() && std::fs::read_dir(&share)?.next().is_none() {
        std::fs::remove_dir(&share)?;
    }
    Ok(())
}

/// Pseudonymizes `runs` with one shared map, has `write` render them into
/// `out/share`, and checks the result: no real value in the data, and no IP
/// or MAC address in any written file. On any leak the share folder is
/// deleted and nothing is kept. The map goes to `out`, outside the share.
fn write_shared(
    runs: &[&Run],
    previous_map: &pseudo::Map,
    out: &Path,
    write: impl FnOnce(&[Run], &Path) -> Result<()>,
) -> Result<PathBuf> {
    let map = pseudo::Map::extend(previous_map, runs);
    let mapped: Vec<Run> = runs.iter().map(|r| map.apply(r)).collect();
    if mapped.iter().any(|r| !map.leaks(r).is_empty()) {
        bail!("pseudonymization missed a value; nothing was written. This is a bug in otinv");
    }
    let share = out.join("share");
    std::fs::create_dir_all(&share).with_context(|| format!("Creating {}", share.display()))?;
    let checked = write(&mapped, &share).and_then(|()| {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&share)? {
            let p = entry?.path();
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            found.extend(map.addresses_in(&text));
        }
        if found.is_empty() {
            Ok(())
        } else {
            bail!(
                "a pseudonymized report still held {} address(es); the share folder was \
                 deleted. This is a bug in otinv",
                found.len()
            )
        }
    });
    if let Err(e) = checked {
        let _ = std::fs::remove_dir_all(&share);
        return Err(e);
    }
    let p = out.join("pseudonym-map.csv");
    std::fs::write(&p, map.to_csv()).with_context(|| format!("Writing {}", p.display()))?;
    Ok(share)
}

/// Where zeek writes its logs: a private temp folder that is deleted once
/// the logs are read (raw logs can hold user names, passwords and URLs), or
/// `<out>/zeek-logs` with --keep-logs.
struct LogDir {
    path: PathBuf,
    temporary: bool,
}

impl LogDir {
    fn new(keep_in: Option<PathBuf>) -> Result<Self> {
        let (path, temporary) = match keep_in {
            Some(p) => (p, false),
            None => {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let name = format!("otinv-zeek-{}-{nanos}", std::process::id());
                (std::env::temp_dir().join(name), true)
            }
        };
        if temporary {
            // a fresh folder only this user can read: zeek's raw logs can hold
            // user names. non-recursive, so an existing folder is an error.
            #[allow(unused_mut)] // only unix sets a mode
            let mut b = std::fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            b.create(&path)
                .with_context(|| format!("Creating {}", path.display()))?;
        } else {
            std::fs::create_dir_all(&path)
                .with_context(|| format!("Creating {}", path.display()))?;
        }
        Ok(Self { path, temporary })
    }
}

impl Drop for LogDir {
    fn drop(&mut self) {
        if self.temporary {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn analyze(a: AnalyzeArgs) -> Result<()> {
    let rules = match &a.rules {
        Some(p) => Rules::load(p)?,
        None => Rules::builtin(),
    };
    let site = match &a.site {
        Some(p) => Site::load(p)?,
        None => Site::default(),
    };
    let oui = match &a.oui {
        Some(p) => Oui::with_ieee_csv(p)?,
        None => Oui::builtin(),
    };
    let run_file = a.out.join("run.londopy");
    if let Some(prev) = &a.previous {
        if same_file(prev, &run_file) {
            bail!(
                "--previous points at this run's own output ({}). Use a new --out folder for each run",
                run_file.display()
            );
        }
    }
    let previous = a.previous.as_deref().map(pipeline::load_run).transpose()?;

    std::fs::create_dir_all(&a.out).with_context(|| format!("Creating {}", a.out.display()))?;
    let logs = if a.input.is_dir() {
        zeek::read_dir(&a.input, a.max_log_mb)?
    } else if a.input.is_file() && is_capture(&a.input) {
        let r = runner::detect(a.runner, a.zeek.as_deref(), &a.docker_image)?;
        let dir = LogDir::new(a.keep_logs.then(|| a.out.join("zeek-logs")))?;
        runner::run(&r, &a.input, &dir.path)?;
        zeek::read_dir(&dir.path, a.max_log_mb)?
        // a temporary log folder is deleted here, as `dir` goes out of scope
    } else if a.input.exists() {
        bail!(
            "{} isn't a capture (.pcap, .pcapng) or a folder of zeek logs",
            a.input.display()
        );
    } else {
        bail!("{} doesn't exist", a.input.display());
    };

    let mut run = pipeline::analyze(&pipeline::Inputs {
        logs: &logs,
        rules: &rules,
        site: &site,
        oui: &oui,
        previous: previous.as_ref(),
        source: file_name(&a.input),
        generated: timefmt::rfc3339(timefmt::now()),
    });
    run.compared_to = a.previous.as_deref().map(short_path);

    clear_outputs(&a.out)?;
    let d = previous.as_ref().map(|p| diff::diff(p, &run));
    report::write_all(&run, previous.as_ref().zip(d.as_ref()), &a.out, false)?;
    // saved with the real reports, before the share step: if sharing fails,
    // the analysis (and next month's --previous) isn't lost. always the real
    // data; it lives in the sensitive folder, never in share/
    pipeline::save_run(&run, &run_file)?;
    if a.pseudonymize {
        let mut runs: Vec<&Run> = vec![&run];
        runs.extend(previous.as_ref());
        let old_map = previous_map(a.pseudonym_map.as_deref(), a.previous.as_deref())?;
        write_shared(&runs, &old_map, &a.out, |mapped, dir| {
            let prev = mapped.get(1);
            let d = prev.map(|p| diff::diff(p, &mapped[0]));
            report::write_all(&mapped[0], prev.zip(d.as_ref()), dir, true).map(|_| ())
        })?;
    }

    println!(
        "{} found, {}.",
        util::plural(run.assets.len(), "device", "devices"),
        if run.findings.is_empty() {
            "no problems flagged".to_string()
        } else {
            format!(
                "{} ({})",
                util::plural(run.findings.len(), "problem", "problems"),
                report::severity_counts(&run.findings)
            )
        }
    );
    println!("Start with {}", a.out.join("summary.txt").display());
    if a.pseudonymize {
        println!(
            "Share only {}. Everything else in {} holds real addresses.",
            a.out.join("share").display(),
            a.out.display()
        );
    }
    eprintln!("The report folder is sensitive; see README-SENSITIVE.txt in it.");
    Ok(())
}

fn diff_cmd(a: DiffArgs) -> Result<()> {
    let old = pipeline::load_run(&a.old)?;
    let new = pipeline::load_run(&a.new)?;
    std::fs::create_dir_all(&a.out).with_context(|| format!("Creating {}", a.out.display()))?;
    clear_outputs(&a.out)?;
    let d = diff::diff(&old, &new);
    std::fs::write(a.out.join("README-SENSITIVE.txt"), report::README_SENSITIVE)?;
    std::fs::write(a.out.join("diff.txt"), report::text::diff(&old, &new, &d))?;
    std::fs::write(a.out.join("diff.html"), report::html::diff(&old, &new, &d))?;
    if a.pseudonymize {
        let old_map = previous_map(a.pseudonym_map.as_deref(), Some(&a.old))?;
        write_shared(&[&old, &new], &old_map, &a.out, |mapped, dir| {
            let (o, n) = (&mapped[0], &mapped[1]);
            let pd = diff::diff(o, n);
            std::fs::write(dir.join("README-SHARED.txt"), report::README_SHARED)?;
            std::fs::write(dir.join("diff.txt"), report::text::diff(o, n, &pd))?;
            std::fs::write(dir.join("diff.html"), report::html::diff(o, n, &pd))?;
            Ok(())
        })?;
        println!(
            "Share only {}. Everything else in {} holds real addresses.",
            a.out.join("share").display(),
            a.out.display()
        );
    }
    let see = a.out.join("diff.txt");
    println!(
        "{} new, {} gone, {} changed; {} new problems, {} no longer seen.",
        util::plural(d.new_assets.len(), "device", "devices"),
        d.gone_assets.len(),
        d.changed.len(),
        d.new_findings.len(),
        d.resolved_findings.len()
    );
    println!("See {}", see.display());
    Ok(())
}
