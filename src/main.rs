use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use otinv::config::{DEFAULT_RULES, SITE_TEMPLATE};
use otinv::runner::{RunnerChoice, DEFAULT_IMAGE};
use otinv::{command, report, util, zeek};
use std::path::PathBuf;

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
    /// Analyze a capture (.pcap/.pcapng), a folder of zeek logs, or a Malcolm export
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
    /// A capture, a folder of zeek logs (conn.log, modbus.log, ...), or a Malcolm export
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
    /// A newer IEEE oui.csv (or mam.csv, oui36.csv) over the built-in vendor list
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

/// Prints progress the way the command line always has: notes on stderr,
/// prefixed with "otinv: ", and zeek's command line as is.
fn print_event(e: command::Event) {
    if let command::Event::Note(n) = e {
        if n.starts_with("running: ") {
            eprintln!("{n}");
        } else {
            eprintln!("otinv: {n}");
        }
    }
}

fn analyze(a: AnalyzeArgs) -> Result<()> {
    let job = command::Analysis {
        input: a.input,
        out: a.out,
        previous: a.previous,
        site: a.site,
        rules: a.rules,
        oui: a.oui,
        pseudonymize: a.pseudonymize,
        runner: a.runner,
        zeek: a.zeek,
        docker_image: a.docker_image,
        keep_logs: a.keep_logs,
        pseudonym_map: a.pseudonym_map,
        max_log_mb: a.max_log_mb,
        stop: Default::default(),
    };
    let done = command::analyze(&job, &mut print_event)?;
    let run = &done.run;
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
    println!("Start with {}", done.out.join("summary.txt").display());
    if let Some(share) = &done.share {
        println!(
            "Share only {}. Everything else in {} holds real addresses.",
            share.display(),
            done.out.display()
        );
    }
    eprintln!("The report folder is sensitive; see README-SENSITIVE.txt in it.");
    Ok(())
}

fn diff_cmd(a: DiffArgs) -> Result<()> {
    let done = command::compare(
        &a.old,
        &a.new,
        &a.out,
        a.pseudonymize,
        a.pseudonym_map.as_deref(),
        &mut print_event,
    )?;
    if let Some(share) = &done.share {
        println!(
            "Share only {}. Everything else in {} holds real addresses.",
            share.display(),
            done.out.display()
        );
    }
    let d = &done.diff;
    println!(
        "{} new, {} gone, {} changed; {} new problems, {} no longer seen.",
        util::plural(d.new_assets.len(), "device", "devices"),
        d.gone_assets.len(),
        d.changed.len(),
        d.new_findings.len(),
        d.resolved_findings.len()
    );
    println!("See {}", done.out.join("diff.txt").display());
    Ok(())
}
