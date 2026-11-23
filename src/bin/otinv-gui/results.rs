// the Results page: what to fix first, then the inventory, for the last
// analysis or any saved run.londopy. the full detail stays in appendix.html.

use crate::app::{open, Go, Page};
use crate::style;
use eframe::egui::{self, RichText, Stroke};
use otinv::command::Analyzed;
use otinv::config::Severity;
use otinv::diff::RunDiff;
use otinv::model::Run;
use otinv::{pipeline, report, util};
use std::path::{Path, PathBuf};

/// Actions shown on the page; the appendix has every one.
const SHOWN_ACTIONS: usize = 5;
/// Findings listed under each action before "and N more".
const SHOWN_FINDINGS: usize = 3;

pub struct Loaded {
    pub run: Run,
    pub run_file: PathBuf,
    folder: PathBuf,
    share: Option<PathBuf>,
    diff: Option<RunDiff>,
    notes: Vec<String>,
}

impl Loaded {
    pub fn from_analysis(done: Analyzed, notes: Vec<String>) -> Self {
        Self {
            run_file: done.out.join("run.londopy"),
            folder: done.out,
            share: done.share,
            diff: done.diff,
            run: done.run,
            notes,
        }
    }
}

#[derive(Default)]
pub struct Results {
    loaded: Option<Loaded>,
    error: Option<String>,
}

impl Results {
    pub fn show(&mut self, loaded: Loaded) {
        self.loaded = Some(loaded);
        self.error = None;
    }

    pub fn open_run(&mut self, path: &Path) -> Go {
        match pipeline::load_run(path) {
            Ok(run) => {
                let folder = path.parent().map(Path::to_path_buf).unwrap_or_default();
                let share = Some(folder.join("share")).filter(|p| p.is_dir());
                Go::ShowResults(Box::new(Loaded {
                    run,
                    run_file: path.to_path_buf(),
                    folder,
                    share,
                    diff: None,
                    notes: Vec::new(),
                }))
            }
            Err(e) => {
                self.error = Some(format!("{e:#}"));
                Go::Open(Page::Results)
            }
        }
    }

    /// Addresses and names of the devices in the shown run, for the site form.
    pub fn devices(&self) -> Vec<(String, String)> {
        self.loaded
            .as_ref()
            .map(|l| {
                l.run
                    .assets
                    .iter()
                    .map(|a| (a.ip.clone(), a.name.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Go {
        let mut go = Go::Stay;
        ui.horizontal(|ui| {
            style::heading(ui, "Results");
            if ui.button("Open a saved run...").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("otinv run", &["londopy"])
                    .pick_file()
                {
                    go = self.open_run(&p);
                }
            }
        });
        if let Some(e) = self.error.clone() {
            style::notice(
                ui,
                ui.visuals().error_fg_color,
                "Couldn't open that run",
                &e,
            );
            if ui.button("Dismiss").clicked() {
                self.error = None;
            }
        }
        let Some(l) = &self.loaded else {
            ui.add_space(20.0);
            ui.label("No results yet.");
            ui.label(
                RichText::new(
                    "Analyze a capture on the Analyze page, or open a run.londopy from an \
                     earlier report folder.",
                )
                .weak(),
            );
            if ui.button("Go to Analyze").clicked() {
                go = Go::Open(Page::Analyze);
            }
            return go;
        };
        let run = &l.run;

        ui.label(RichText::new(report::title(run)).size(18.0).strong());
        ui.label(format!("Captured {}", report::period(run)));
        ui.horizontal_wrapped(|ui| {
            ui.label(util::plural(run.assets.len(), "device,", "devices,"));
            if run.findings.is_empty() {
                ui.label("no problems flagged.");
            }
            for sev in [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info,
            ] {
                let n = run.findings.iter().filter(|f| f.severity == sev).count();
                if n > 0 {
                    let text = format!("{n} {}", sev.label().to_ascii_lowercase());
                    ui.label(
                        RichText::new(text)
                            .strong()
                            .color(style::severity_color(ui, sev)),
                    );
                }
            }
        });
        if let Some(d) = &l.diff {
            ui.label(format!(
                "Since the previous run: {} new, {} gone, {} changed; {} new problems, {} fixed.",
                util::plural(d.new_assets.len(), "device", "devices"),
                d.gone_assets.len(),
                d.changed.len(),
                d.new_findings.len(),
                d.resolved_findings.len()
            ));
        }
        for n in &l.notes {
            ui.label(RichText::new(n).weak());
        }

        ui.add_space(6.0);
        let mut failed = None;
        ui.horizontal_wrapped(|ui| {
            let appendix = l.folder.join("appendix.html");
            if appendix.is_file() && style::primary_button(ui, "Open the full report").clicked() {
                failed = open(&appendix).err();
            }
            if ui.button("Open the report folder").clicked() {
                failed = open(&l.folder).err();
            }
            if let Some(share) = &l.share {
                if ui.button("Open the copy for sharing").clicked() {
                    failed = open(share).err();
                }
            }
            if ui.button("Add these devices to Site details").clicked() {
                go = Go::AddDevices(self.devices());
            }
        });
        if let Some(e) = failed {
            self.error = Some(e);
        }
        ui.label(
            RichText::new(
                "This folder maps the plant's control network. Share only the share folder.",
            )
            .weak(),
        );

        style::section(ui, "What to fix first");
        let actions = report::actions(run);
        if actions.is_empty() {
            ui.label("Nothing to fix was found in this capture.");
        }
        for a in actions.iter().take(SHOWN_ACTIONS) {
            // the two worst severities get a border in their color
            let border = if a.severity >= Severity::High {
                Stroke::new(1.5, style::severity_color(ui, a.severity))
            } else {
                ui.visuals().widgets.noninteractive.bg_stroke
            };
            egui::Frame::group(ui.style())
                .stroke(border)
                .inner_margin(10)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        style::severity_tag(ui, a.severity);
                        ui.label(RichText::new(&a.rule.title).strong());
                    });
                    for f in a.findings.iter().take(SHOWN_FINDINGS) {
                        ui.label(report::describe(run, f));
                    }
                    if a.findings.len() > SHOWN_FINDINGS {
                        ui.label(
                            RichText::new(format!(
                                "and {} more in the full report",
                                a.findings.len() - SHOWN_FINDINGS
                            ))
                            .weak(),
                        );
                    }
                    ui.label(RichText::new(format!("Do this: {}", a.rule.action)).strong());
                    ui.label(RichText::new(format!("Why it matters: {}", a.rule.why)).weak());
                });
            ui.add_space(4.0);
        }
        if actions.len() > SHOWN_ACTIONS {
            ui.label(
                RichText::new(format!(
                    "{} more in the full report.",
                    util::plural(
                        actions.len() - SHOWN_ACTIONS,
                        "kind of problem",
                        "kinds of problem"
                    )
                ))
                .weak(),
            );
        }

        style::section(ui, "Inventory");
        egui::ScrollArea::horizontal().show(ui, |ui| {
            egui::Grid::new("inventory")
                .striped(true)
                .num_columns(7)
                .spacing(egui::vec2(18.0, 6.0))
                .show(ui, |ui| {
                    for h in [
                        "Address",
                        "Name",
                        "Role",
                        "Make and model",
                        "Firmware",
                        "Protocols it answers",
                        "Problems",
                    ] {
                        ui.label(RichText::new(h).strong());
                    }
                    ui.end_row();
                    for a in &run.assets {
                        ui.label(RichText::new(&a.ip).monospace());
                        ui.label(&a.name);
                        ui.label(a.role.short());
                        let make = a.make_model();
                        ui.label(if make.is_empty() {
                            a.vendor.clone().unwrap_or_default()
                        } else {
                            make
                        });
                        ui.label(a.identity.get("firmware").cloned().unwrap_or_default());
                        ui.label(a.serves.iter().cloned().collect::<Vec<_>>().join(", "));
                        let mine: Vec<_> = run.findings.iter().filter(|f| f.host == a.ip).collect();
                        match mine.iter().map(|f| f.severity).max() {
                            Some(worst) => ui.label(
                                RichText::new(format!(
                                    "{} ({})",
                                    mine.len(),
                                    worst.label().to_ascii_lowercase()
                                ))
                                .color(style::severity_color(ui, worst)),
                            ),
                            None => ui.label(""),
                        };
                        ui.end_row();
                    }
                });
        });
        go
    }
}
