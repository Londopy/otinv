// the two things otinv does, `analyze` and `diff`, as one call each, shared
// by the command line and the GUI. each reports what it's doing through a
// callback instead of printing, so the CLI can print and the GUI can show it.

use crate::config::{Rules, Site};
use crate::diff::{self, RunDiff};
use crate::model::Run;
use crate::oui::Oui;
use crate::runner::{self, Runner, RunnerChoice};
use crate::{malcolm, pcap, pipeline, pseudo, report, timefmt, zeek};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Everything `otinv analyze` takes.
#[derive(Debug, Clone)]
pub struct Analysis {
    pub input: PathBuf,
    pub out: PathBuf,
    pub previous: Option<PathBuf>,
    pub site: Option<PathBuf>,
    pub rules: Option<PathBuf>,
    pub oui: Option<PathBuf>,
    pub pseudonymize: bool,
    pub runner: RunnerChoice,
    pub zeek: Option<PathBuf>,
    pub docker_image: String,
    pub keep_logs: bool,
    pub pseudonym_map: Option<PathBuf>,
    pub max_log_mb: u64,
    /// Set from another thread to stop the run before it writes anything.
    pub stop: Arc<AtomicBool>,
}

impl Analysis {
    /// The defaults the command line uses, for one input and output folder.
    pub fn new(input: PathBuf, out: PathBuf) -> Self {
        Self {
            input,
            out,
            previous: None,
            site: None,
            rules: None,
            oui: None,
            pseudonymize: false,
            runner: RunnerChoice::Auto,
            zeek: None,
            docker_image: runner::DEFAULT_IMAGE.to_string(),
            keep_logs: false,
            pseudonym_map: None,
            max_log_mb: zeek::DEFAULT_MAX_LOG_MB,
            stop: Arc::default(),
        }
    }
}

/// Where a run has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Zeek,
    Reading,
    Analyzing,
    Packets,
    Writing,
    Sharing,
}

impl Step {
    pub fn label(self) -> &'static str {
        match self {
            Step::Zeek => "Running Zeek on the capture",
            Step::Reading => "Reading the logs",
            Step::Analyzing => "Building the inventory and checking the rules",
            Step::Packets => "Finding the packet behind each piece of evidence",
            Step::Writing => "Writing the reports",
            Step::Sharing => "Writing the pseudonymized copy",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Step(Step),
    /// Something worth telling the person, like a warning.
    Note(String),
}

pub struct Analyzed {
    pub run: Run,
    pub diff: Option<RunDiff>,
    pub out: PathBuf,
    /// The pseudonymized folder, when one was written.
    pub share: Option<PathBuf>,
}

pub struct Compared {
    pub old: Run,
    pub new: Run,
    pub diff: RunDiff,
    pub out: PathBuf,
    pub share: Option<PathBuf>,
}

/// What `input` is, by looking at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Capture,
    LogFolder,
    MalcolmExport,
}

pub fn input_kind(input: &Path) -> Result<InputKind> {
    if input.is_dir() {
        let export = std::fs::read_dir(input)
            .with_context(|| format!("Reading {}", input.display()))?
            .filter_map(|e| e.ok())
            .any(|e| malcolm::is_export(&e.path()));
        Ok(if export {
            InputKind::MalcolmExport
        } else {
            InputKind::LogFolder
        })
    } else if input.is_file() && malcolm::is_export(input) {
        Ok(InputKind::MalcolmExport)
    } else if input.is_file() && is_capture(input) {
        Ok(InputKind::Capture)
    } else if input.exists() {
        bail!(
            "{} isn't a capture (.pcap, .pcapng), a Malcolm export (.json, .ndjson) \
             or a folder of zeek logs",
            input.display()
        )
    } else {
        bail!("{} doesn't exist", input.display())
    }
}

pub fn is_capture(p: &Path) -> bool {
    let ext = p
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    matches!(ext.as_str(), "pcap" | "pcapng" | "cap" | "dmp")
}

pub fn file_name(p: &Path) -> String {
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

/// A folder of zeek logs, or else the pages of a Malcolm export.
fn read_folder(dir: &Path, max_mb: u64) -> Result<Vec<zeek::Log>> {
    let paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("Reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    if !paths.iter().any(|p| malcolm::is_export(p)) {
        return zeek::read_dir(dir, max_mb);
    }
    let has_logs = paths.iter().any(|p| {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        name.starts_with("conn.") && name.ends_with(".log")
    });
    if has_logs {
        bail!(
            "{} has both zeek logs and a Malcolm export; put them in separate folders",
            dir.display()
        );
    }
    malcolm::read(dir, max_mb)
}

/// The pseudonym map to continue from: the explicit one, else the
/// pseudonym-map.csv next to the previous run, else none.
fn previous_map(
    explicit: Option<&Path>,
    previous_run: Option<&Path>,
    on: &mut dyn FnMut(Event),
) -> Result<pseudo::Map> {
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
            on(Event::Note(format!(
                "keeping the aliases from {}",
                p.display()
            )));
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

/// Where zeek writes its logs: a private temporary folder that is deleted once
/// the logs are read (raw logs can hold user names, passwords and URLs), or
/// `<out>/zeek-logs` with keep_logs.
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

/// A new report folder next to the input, named for the month:
/// "otinv-2026-11", or "otinv-2026-11-2" when that one already exists.
pub fn suggest_out(input: &Path, now: f64) -> PathBuf {
    let dir = input.parent().map(Path::to_path_buf).unwrap_or_default();
    let month = timefmt::utc(now).chars().take(7).collect::<String>();
    let base = format!("otinv-{month}");
    std::iter::once(base.clone())
        .chain((2..).map(|n| format!("{base}-{n}")))
        .map(|name| dir.join(name))
        .find(|p| !p.exists())
        .unwrap_or_else(|| dir.join(base))
}

/// Which zeek otinv found, in words for someone who didn't set it up.
pub fn describe_runner(r: &Runner) -> String {
    let parsers = |yes: bool| {
        if yes {
            "with CISA's ICSNPP parsers"
        } else {
            "without CISA's ICSNPP parsers"
        }
    };
    match r {
        Runner::Native(path, p) => {
            format!(
                "Zeek on this computer ({}), {}",
                path.display(),
                parsers(*p)
            )
        }
        Runner::Wsl(p) => format!("Zeek inside WSL, {}", parsers(*p)),
        Runner::Docker(image) => format!("Zeek in Docker (image {image}), {}", parsers(true)),
    }
}

/// A warning about a zeek that can run but lacks the ICSNPP packages.
pub fn runner_note(r: &Runner) -> Option<String> {
    matches!(r, Runner::Native(_, false) | Runner::Wsl(false)).then(|| {
        "this zeek has no zkg packages, so the CISA ICSNPP parsers won't run; Modbus and \
         DNP3 still work, EtherNet/IP identity and others won't"
            .to_string()
    })
}

fn run_zeek(a: &Analysis, on: &mut dyn FnMut(Event)) -> Result<Vec<zeek::Log>> {
    on(Event::Step(Step::Zeek));
    let r = runner::detect(a.runner, a.zeek.as_deref(), &a.docker_image)?;
    if let Some(n) = runner_note(&r) {
        on(Event::Note(n));
    }
    let dir = LogDir::new(a.keep_logs.then(|| a.out.join("zeek-logs")))?;
    let plan = runner::plan(&r, &a.input, &dir.path)?;
    on(Event::Note(format!("running: {}", plan.display())));
    runner::run(&r, &a.input, &dir.path, &a.stop)?;
    on(Event::Step(Step::Reading));
    zeek::read_dir(&dir.path, a.max_log_mb)
    // a temporary log folder is deleted here, as `dir` goes out of scope
}

fn stopped(a: &Analysis) -> Result<()> {
    if a.stop.load(Ordering::Relaxed) {
        bail!("stopped; no reports were written");
    }
    Ok(())
}

/// Runs one analysis end to end and writes its report folder.
pub fn analyze(a: &Analysis, on: &mut dyn FnMut(Event)) -> Result<Analyzed> {
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
                "the previous run is this run's own output ({}). Use a new output folder for \
                 each run",
                run_file.display()
            );
        }
    }
    let previous = a.previous.as_deref().map(pipeline::load_run).transpose()?;

    let kind = input_kind(&a.input)?;
    std::fs::create_dir_all(&a.out).with_context(|| format!("Creating {}", a.out.display()))?;
    let logs = match kind {
        InputKind::Capture => run_zeek(a, on)?,
        InputKind::LogFolder | InputKind::MalcolmExport => {
            on(Event::Step(Step::Reading));
            if a.input.is_dir() {
                read_folder(&a.input, a.max_log_mb)?
            } else {
                malcolm::read(&a.input, a.max_log_mb)?
            }
        }
    };

    stopped(a)?;
    on(Event::Step(Step::Analyzing));
    let mut run = pipeline::analyze(&pipeline::Inputs {
        logs: &logs,
        rules: &rules,
        site: &site,
        oui: &oui,
        previous: previous.as_ref(),
        source: file_name(&a.input),
        generated: timefmt::rfc3339(timefmt::now()),
    });
    drop(logs);
    run.compared_to = a.previous.as_deref().map(short_path);
    for ip in site.details.keys() {
        if run.asset(ip).is_none() {
            on(Event::Note(format!(
                "site.toml has [details] for {ip}, which wasn't seen in this capture"
            )));
        }
    }
    if kind == InputKind::Capture {
        on(Event::Step(Step::Packets));
        match pcap::number_frames(&a.input, &mut run) {
            Ok(n) => on(Event::Note(format!(
                "matched {n} evidence lines to packets in the capture"
            ))),
            Err(e) => on(Event::Note(format!(
                "no packet numbers in the reports: {e:#}"
            ))),
        }
    }

    stopped(a)?;
    on(Event::Step(Step::Writing));
    clear_outputs(&a.out)?;
    let d = previous.as_ref().map(|p| diff::diff(p, &run));
    report::write_all(&run, previous.as_ref().zip(d.as_ref()), &a.out, false)?;
    // saved with the real reports, before the share step: if sharing fails,
    // the analysis (and next month's previous run) isn't lost. always the real
    // data; it lives in the sensitive folder, never in share/
    pipeline::save_run(&run, &run_file)?;
    let share = if a.pseudonymize {
        on(Event::Step(Step::Sharing));
        let mut runs: Vec<&Run> = vec![&run];
        runs.extend(previous.as_ref());
        let old_map = previous_map(a.pseudonym_map.as_deref(), a.previous.as_deref(), on)?;
        Some(write_shared(&runs, &old_map, &a.out, |mapped, dir| {
            let prev = mapped.get(1);
            let d = prev.map(|p| diff::diff(p, &mapped[0]));
            report::write_all(&mapped[0], prev.zip(d.as_ref()), dir, true).map(|_| ())
        })?)
    } else {
        None
    };
    Ok(Analyzed {
        run,
        diff: d,
        out: a.out.clone(),
        share,
    })
}

/// Compares two saved runs and writes diff.txt and diff.html into `out`.
pub fn compare(
    old_path: &Path,
    new_path: &Path,
    out: &Path,
    pseudonymize: bool,
    pseudonym_map: Option<&Path>,
    on: &mut dyn FnMut(Event),
) -> Result<Compared> {
    // clearing old outputs would delete that analysis's reports
    if out.join("run.londopy").exists() {
        bail!(
            "{} holds an analysis's reports; choose another folder for the comparison",
            out.display()
        );
    }
    let old = pipeline::load_run(old_path)?;
    let new = pipeline::load_run(new_path)?;
    std::fs::create_dir_all(out).with_context(|| format!("Creating {}", out.display()))?;
    on(Event::Step(Step::Writing));
    clear_outputs(out)?;
    let d = diff::diff(&old, &new);
    std::fs::write(out.join("README-SENSITIVE.txt"), report::README_SENSITIVE)?;
    std::fs::write(out.join("diff.txt"), report::text::diff(&old, &new, &d))?;
    std::fs::write(out.join("diff.html"), report::html::diff(&old, &new, &d))?;
    let share = if pseudonymize {
        on(Event::Step(Step::Sharing));
        let old_map = previous_map(pseudonym_map, Some(old_path), on)?;
        Some(write_shared(
            &[&old, &new],
            &old_map,
            out,
            |mapped, dir| {
                let (o, n) = (&mapped[0], &mapped[1]);
                let pd = diff::diff(o, n);
                std::fs::write(dir.join("README-SHARED.txt"), report::README_SHARED)?;
                std::fs::write(dir.join("diff.txt"), report::text::diff(o, n, &pd))?;
                std::fs::write(dir.join("diff.html"), report::html::diff(o, n, &pd))?;
                Ok(())
            },
        )?)
    } else {
        None
    };
    Ok(Compared {
        old,
        new,
        diff: d,
        out: out.to_path_buf(),
        share,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("otinv-command-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_stopped_run_writes_no_reports() {
        let out = tmp("stopped");
        let a = Analysis::new(fixture("lab-bad"), out.clone());
        a.stop.store(true, Ordering::Relaxed);
        let err = analyze(&a, &mut |_| {}).err().unwrap();
        assert!(err.to_string().contains("stopped"), "{err}");
        assert!(!out.join("summary.txt").exists());
        assert!(!out.join("run.londopy").exists());
        let _ = std::fs::remove_dir_all(out);
    }

    #[test]
    fn suggests_a_new_folder_per_month() {
        let d = tmp("suggest");
        std::fs::create_dir_all(d.join("otinv-2026-11")).unwrap();
        let input = d.join("plant.pcapng");
        // 2026-11-20 and 2026-12-01 UTC
        assert_eq!(
            suggest_out(&input, 1_795_132_800.0),
            d.join("otinv-2026-11-2")
        );
        assert_eq!(
            suggest_out(&input, 1_796_083_200.0),
            d.join("otinv-2026-12")
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn says_which_zeek_it_found() {
        let r = Runner::Wsl(false);
        assert_eq!(
            describe_runner(&r),
            "Zeek inside WSL, without CISA's ICSNPP parsers"
        );
        assert!(runner_note(&r).is_some());
        assert!(runner_note(&Runner::Docker("img".into())).is_none());
        assert!(describe_runner(&Runner::Docker("img".into())).contains("image img"));
    }

    #[test]
    fn tells_inputs_apart() {
        assert_eq!(
            input_kind(&fixture("lab-bad")).unwrap(),
            InputKind::LogFolder
        );
        assert_eq!(
            input_kind(&fixture("malcolm-bad")).unwrap(),
            InputKind::MalcolmExport
        );
        assert!(input_kind(&fixture("lab-bad/conn.log")).is_err());
        assert!(input_kind(&fixture("nothing-here")).is_err());
        assert!(is_capture(Path::new("a.PCAPNG")) && !is_capture(Path::new("a.log")));
    }

    #[test]
    fn analyze_reports_its_steps_and_writes_the_folder() {
        let base = tmp("base");
        let mut events = Vec::new();
        let first = analyze(
            &Analysis::new(fixture("lab-baseline"), base.clone()),
            &mut |e| events.push(e),
        )
        .unwrap();
        assert!(first.diff.is_none() && first.share.is_none());
        assert_eq!(
            events,
            [
                Event::Step(Step::Reading),
                Event::Step(Step::Analyzing),
                Event::Step(Step::Writing)
            ]
        );

        let out = tmp("bad");
        let mut a = Analysis::new(fixture("lab-bad"), out.clone());
        a.previous = Some(base.join("run.londopy"));
        a.pseudonymize = true;
        let mut steps = Vec::new();
        let r = analyze(&a, &mut |e| {
            if let Event::Step(s) = e {
                steps.push(s)
            }
        })
        .unwrap();
        assert_eq!(steps.last(), Some(&Step::Sharing));
        assert!(r
            .diff
            .unwrap()
            .new_assets
            .iter()
            .any(|a| a.ip == "10.10.1.50"));
        assert!(out.join("summary.txt").is_file() && out.join("diff.html").is_file());
        assert_eq!(r.share, Some(out.join("share")));

        let cmp = tmp("cmp");
        let c = compare(
            &base.join("run.londopy"),
            &out.join("run.londopy"),
            &cmp,
            false,
            None,
            &mut |_| {},
        )
        .unwrap();
        // a report folder as the comparison's folder would lose its reports
        let into_report = compare(
            &base.join("run.londopy"),
            &out.join("run.londopy"),
            &out,
            false,
            None,
            &mut |_| {},
        );
        assert!(into_report.is_err());
        assert!(out.join("summary.txt").is_file());
        let new: Vec<&str> = c.diff.new_assets.iter().map(|a| a.ip.as_str()).collect();
        assert_eq!(new, ["10.10.1.50"]);
        assert!(cmp.join("diff.txt").is_file() && c.share.is_none());

        // the previous run can't be the one being written
        let mut again = Analysis::new(fixture("lab-bad"), out.clone());
        again.previous = Some(out.join("run.londopy"));
        assert!(analyze(&again, &mut |_| {}).is_err());
        for d in [base, out, cmp] {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}
