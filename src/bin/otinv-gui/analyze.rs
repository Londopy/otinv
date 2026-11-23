// the Analyze page: pick what to analyze and where the reports go, see
// whether zeek is ready (for captures), run it, and follow its progress.

use crate::app::{link, path_row, Go, Page};
use crate::job::Job;
use crate::results::Loaded;
use crate::style;
use eframe::egui::{self, RichText};
use otinv::command::{self, Analysis, Analyzed, InputKind};
use otinv::runner::{self, Runner, RunnerChoice};
use otinv::timefmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;

enum Zeek {
    NotChecked,
    Checking(Receiver<Result<Runner, String>>),
    Found(Runner),
    Missing(String),
}

pub struct Analyze {
    input: Option<PathBuf>,
    kind: Option<Result<InputKind, String>>,
    out: Option<PathBuf>,
    pub site: Option<PathBuf>,
    previous: Option<PathBuf>,
    pseudonymize: bool,
    runner: RunnerChoice,
    zeek: Zeek,
    job: Option<Job<Analyzed>>,
    /// The running job's stop switch.
    stop: Arc<AtomicBool>,
    /// Something worth saying about the input, like a multiple drop.
    pub note: Option<String>,
    error: Option<String>,
}

impl Default for Analyze {
    fn default() -> Self {
        Self {
            input: None,
            kind: None,
            out: None,
            site: None,
            previous: None,
            pseudonymize: false,
            runner: RunnerChoice::Auto,
            zeek: Zeek::NotChecked,
            job: None,
            stop: Arc::default(),
            note: None,
            error: None,
        }
    }
}

fn pick_input_file() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title("Choose a capture or a Malcolm export")
        .add_filter(
            "Captures and Malcolm exports",
            &["pcap", "pcapng", "cap", "dmp", "json", "ndjson"],
        )
        .add_filter("All files", &["*"])
        .pick_file()
}

impl Analyze {
    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn set_input(&mut self, ctx: &egui::Context, path: PathBuf) {
        let kind = command::input_kind(&path).map_err(|e| format!("{e:#}"));
        self.out = Some(command::suggest_out(&path, timefmt::now()));
        if matches!(kind, Ok(InputKind::Capture)) && matches!(self.zeek, Zeek::NotChecked) {
            self.check_zeek(ctx);
        }
        self.kind = Some(kind);
        self.input = Some(path);
        self.note = None;
        self.error = None;
    }

    fn check_zeek(&mut self, ctx: &egui::Context) {
        let (tx, rx) = channel();
        let (choice, ctx) = (self.runner, ctx.clone());
        // `wsl` and `docker` can take a few seconds to answer
        std::thread::spawn(move || {
            let found =
                runner::detect(choice, None, runner::DEFAULT_IMAGE).map_err(|e| format!("{e:#}"));
            let _ = tx.send(found);
            ctx.request_repaint();
        });
        self.zeek = Zeek::Checking(rx);
    }

    /// Picks up a finished analysis, wherever the window is showing.
    pub fn poll(&mut self) -> Go {
        if let Zeek::Checking(rx) = &self.zeek {
            if let Ok(found) = rx.try_recv() {
                self.zeek = match found {
                    Ok(r) => Zeek::Found(r),
                    Err(e) => Zeek::Missing(e),
                };
            }
        }
        let Some(job) = &mut self.job else {
            return Go::Stay;
        };
        let Some(result) = job.poll() else {
            return Go::Stay;
        };
        let notes = std::mem::take(&mut job.notes);
        self.job = None;
        match result {
            Ok(done) => Go::ShowResults(Box::new(Loaded::from_analysis(done, notes))),
            Err(_) if self.stop.load(Ordering::Relaxed) => {
                self.note = Some("Stopped. No reports were written.".into());
                Go::Stay
            }
            Err(e) => {
                self.error = Some(e);
                Go::Stay
            }
        }
    }

    fn ready(&self) -> Result<(), &'static str> {
        match (&self.input, &self.kind) {
            (None, _) => Err("Choose a capture, a log folder or a Malcolm export first."),
            (_, Some(Err(_))) => Err("otinv can't read the chosen input."),
            (_, Some(Ok(InputKind::Capture))) if !matches!(self.zeek, Zeek::Found(_)) => {
                Err("A capture needs Zeek; see below.")
            }
            _ if self.out.is_none() => Err("Choose a folder for the reports."),
            _ => Ok(()),
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        let (Some(input), Some(out)) = (self.input.clone(), self.out.clone()) else {
            return;
        };
        let mut job = Analysis::new(input, out);
        job.site = self.site.clone();
        job.previous = self.previous.clone();
        job.pseudonymize = self.pseudonymize;
        job.runner = self.runner;
        self.stop = job.stop.clone();
        self.error = None;
        self.job = Some(Job::start(ctx, move |on| command::analyze(&job, on)));
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Go {
        let ctx = ui.ctx().clone();
        let mut go = Go::Stay;
        style::heading(ui, "Analyze a capture");
        ui.label(
            "otinv reads traffic that was already captured. It never sends anything to the \
             network it describes. You can also drop a file or folder on this window.",
        );
        if let Some(job) = &self.job {
            style::section(ui, "Working");
            job.show_progress(ui, "Starting");
            ui.add_space(6.0);
            if self.stop.load(Ordering::Relaxed) {
                ui.label(RichText::new("Stopping...").weak());
            } else if ui.button("Stop").clicked() {
                self.stop.store(true, Ordering::Relaxed);
            }
            return go;
        }

        style::section(ui, "What to analyze");
        let mut picked = None;
        path_row(
            ui,
            "Input",
            self.input.clone(),
            "nothing chosen yet",
            |ui| {
                if ui.button("Capture or export file...").clicked() {
                    picked = pick_input_file();
                }
                if ui.button("Folder of Zeek logs...").clicked() {
                    picked = rfd::FileDialog::new()
                        .set_title("Choose a folder of Zeek logs or Malcolm export pages")
                        .pick_folder();
                }
            },
        );
        if let Some(p) = picked {
            self.set_input(&ctx, p);
        }
        match &self.kind {
            Some(Ok(InputKind::Capture)) => {
                ui.label("A packet capture. otinv will run Zeek on it first.");
            }
            Some(Ok(InputKind::LogFolder)) => {
                ui.label("A folder of Zeek logs.");
            }
            Some(Ok(InputKind::MalcolmExport)) => {
                ui.label("An export from Malcolm.");
            }
            Some(Err(e)) => {
                style::notice(ui, ui.visuals().error_fg_color, "Can't use this input", e)
            }
            None => {}
        }
        if let Some(n) = &self.note {
            ui.label(RichText::new(n).weak());
        }

        if matches!(self.kind, Some(Ok(InputKind::Capture))) {
            self.zeek_ui(ui, &ctx);
        }

        style::section(ui, "Reports");
        path_row(
            ui,
            "Report folder",
            self.out.clone(),
            "chosen once you pick an input",
            |ui| {
                if ui.button("Change...").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .set_title("Choose an empty folder for the reports")
                        .pick_folder()
                    {
                        self.out = Some(p);
                    }
                }
            },
        );
        ui.label(
            RichText::new(
                "Use a new folder every month; a rerun into the same folder replaces its reports.",
            )
            .weak(),
        );
        ui.add_space(6.0);
        path_row(
            ui,
            "Site file (optional)",
            self.site.clone(),
            "none: devices are shown by address",
            |ui| {
                if ui.button("Choose...").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("Site file", &["toml"])
                        .pick_file()
                    {
                        self.site = Some(p);
                    }
                }
                if ui.button("Edit site details").clicked() {
                    go = Go::Open(Page::Site);
                }
                if self.site.is_some() && ui.button("Don't use one").clicked() {
                    self.site = None;
                }
            },
        );
        path_row(
            ui,
            "Last month's run (optional)",
            self.previous.clone(),
            "none: no comparison, no new-device check",
            |ui| {
                if ui.button("Choose run.londopy...").clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter("otinv run", &["londopy"])
                        .pick_file()
                    {
                        self.previous = Some(p);
                    }
                }
                if self.previous.is_some() && ui.button("Don't compare").clicked() {
                    self.previous = None;
                }
            },
        );
        ui.checkbox(
            &mut self.pseudonymize,
            "Also write a copy with addresses and names replaced, safe to send to a reviewer",
        );

        ui.add_space(14.0);
        let ready = self.ready();
        let run = ui
            .add_enabled_ui(ready.is_ok(), |ui| style::primary_button(ui, "Analyze"))
            .inner;
        if run.clicked() {
            self.start(&ctx);
        }
        if let Err(why) = ready {
            ui.label(RichText::new(why).weak());
        }
        if let Some(e) = self.error.clone() {
            ui.add_space(8.0);
            style::notice(ui, ui.visuals().error_fg_color, "The analysis failed", &e);
            if ui.button("Dismiss").clicked() {
                self.error = None;
            }
        }
        go
    }

    fn zeek_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        style::section(ui, "Zeek");
        ui.horizontal(|ui| {
            ui.label("Run Zeek with");
            let before = self.runner;
            egui::ComboBox::from_id_salt("runner")
                .selected_text(runner_label(self.runner))
                .show_ui(ui, |ui| {
                    for c in [
                        RunnerChoice::Auto,
                        RunnerChoice::Native,
                        RunnerChoice::Wsl,
                        RunnerChoice::Docker,
                    ] {
                        ui.selectable_value(&mut self.runner, c, runner_label(c));
                    }
                });
            if self.runner != before {
                self.check_zeek(ctx);
            }
            if !matches!(self.zeek, Zeek::Checking(_)) && ui.button("Check again").clicked() {
                self.check_zeek(ctx);
            }
        });
        match &self.zeek {
            Zeek::NotChecked => {}
            Zeek::Checking(_) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Looking for Zeek...");
                });
            }
            Zeek::Found(r) => {
                ui.label(format!("Ready: {}.", command::describe_runner(r)));
                if let Some(n) = command::runner_note(r) {
                    style::notice(
                        ui,
                        ui.visuals().warn_fg_color,
                        "Some parsers are missing",
                        &n,
                    );
                }
            }
            Zeek::Missing(e) => {
                style::notice(
                    ui,
                    ui.visuals().warn_fg_color,
                    "Zeek isn't set up on this computer",
                    &format!(
                        "{e}\n\notinv doesn't install Zeek itself. A folder of Zeek logs or \
                         a Malcolm export works without it."
                    ),
                );
                if let Some(e) = link(
                    ui,
                    "How to set up Zeek (opens the project page)",
                    "https://github.com/Londopy/otinv#install",
                ) {
                    self.error = Some(e);
                }
            }
        }
    }
}

fn runner_label(c: RunnerChoice) -> &'static str {
    match c {
        RunnerChoice::Auto => "whatever is installed",
        RunnerChoice::Native => "Zeek on this computer",
        RunnerChoice::Wsl => "Zeek inside WSL",
        RunnerChoice::Docker => "the Docker image",
    }
}
