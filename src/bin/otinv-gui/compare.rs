// the Compare page: two saved runs in, "what changed since last month" out.

use crate::app::{open, path_row};
use crate::job::Job;
use crate::style;
use eframe::egui::{self, RichText};
use otinv::command::{self, Compared};
use otinv::model::{Finding, Run};
use otinv::{report, util};
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct Compare {
    older: Option<PathBuf>,
    newer: Option<PathBuf>,
    out: Option<PathBuf>,
    pseudonymize: bool,
    job: Option<Job<Compared>>,
    done: Option<Compared>,
    error: Option<String>,
}

fn pick_run(title: &str) -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title(title)
        .add_filter("otinv run", &["londopy"])
        .pick_file()
}

/// "Remote-control software...: Operator screen 10.0.2.20 accepts VNC ..."
fn finding(run: &Run, f: &Finding) -> String {
    let title = run
        .rule(&f.rule)
        .map_or(f.rule.as_str(), |r| r.title.as_str());
    format!("{title}: {}", report::describe(run, f))
}

/// "otinv-diff" next to the newer run's report folder.
pub fn default_out(newer: &Path) -> Option<PathBuf> {
    let folder = newer.parent()?;
    let parent = folder.parent()?;
    let name = folder.file_name()?.to_string_lossy();
    Some(parent.join(format!("{name}-changes")))
}

impl Compare {
    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// After an analysis, its run is the obvious newer one to compare.
    pub fn suggest_newer(&mut self, run_file: &Path) {
        if self.newer.is_none() {
            self.set_newer(run_file.to_path_buf());
        }
    }

    fn set_newer(&mut self, p: PathBuf) {
        self.out = default_out(&p);
        self.newer = Some(p);
    }

    pub fn poll(&mut self) {
        let Some(job) = &mut self.job else {
            return;
        };
        if let Some(result) = job.poll() {
            self.job = None;
            match result {
                Ok(c) => self.done = Some(c),
                Err(e) => self.error = Some(e),
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> crate::app::Go {
        style::heading(ui, "Compare two months");
        ui.label("What changed between two saved runs: new and missing devices, changed firmware, new and fixed problems.");
        if let Some(job) = &self.job {
            style::section(ui, "Working");
            job.show_progress(ui, "Comparing");
            return crate::app::Go::Stay;
        }
        style::section(ui, "Runs");
        path_row(ui, "Older run", self.older.clone(), "not chosen", |ui| {
            if ui.button("Choose run.londopy...").clicked() {
                if let Some(p) = pick_run("Choose the older run") {
                    self.older = Some(p);
                }
            }
        });
        let mut newer = None;
        path_row(ui, "Newer run", self.newer.clone(), "not chosen", |ui| {
            if ui.button("Choose run.londopy...").clicked() {
                newer = pick_run("Choose the newer run");
            }
        });
        if let Some(p) = newer {
            self.set_newer(p);
        }
        path_row(
            ui,
            "Folder for the comparison",
            self.out.clone(),
            "chosen once you pick the newer run",
            |ui| {
                if ui.button("Change...").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.out = Some(p);
                    }
                }
            },
        );
        ui.checkbox(
            &mut self.pseudonymize,
            "Also write a copy safe to send to a reviewer",
        );

        let ready = match (&self.older, &self.newer, &self.out) {
            (Some(o), Some(n), Some(_)) if o == n => Err("Pick two different runs."),
            (Some(_), Some(_), Some(_)) => Ok(()),
            _ => Err("Choose both runs first."),
        };
        ui.add_space(10.0);
        let clicked = ui
            .add_enabled_ui(ready.is_ok(), |ui| style::primary_button(ui, "Compare"))
            .inner
            .clicked();
        if let Err(why) = ready {
            ui.label(RichText::new(why).weak());
        }
        if clicked {
            if let (Some(o), Some(n), Some(out)) =
                (self.older.clone(), self.newer.clone(), self.out.clone())
            {
                let share = self.pseudonymize;
                self.error = None;
                self.done = None;
                self.job = Some(Job::start(ui.ctx(), move |on| {
                    command::compare(&o, &n, &out, share, None, on)
                }));
            }
        }
        if let Some(e) = self.error.clone() {
            style::notice(ui, ui.visuals().error_fg_color, "The comparison failed", &e);
            if ui.button("Dismiss").clicked() {
                self.error = None;
            }
        }
        if let Some(c) = &self.done {
            style::section(ui, "Changes");
            let d = &c.diff;
            if d.is_empty() {
                ui.label("Nothing changed between the two runs.");
            }
            let list = |ui: &mut egui::Ui, title: String, items: Vec<String>| {
                if !items.is_empty() {
                    ui.label(RichText::new(&title).strong());
                    ui.indent(&title, |ui| {
                        for i in items {
                            ui.label(i);
                        }
                    });
                }
            };
            list(
                ui,
                util::plural(d.new_assets.len(), "new device", "new devices"),
                d.new_assets.iter().map(|a| a.describe()).collect(),
            );
            list(
                ui,
                util::plural(
                    d.gone_assets.len(),
                    "device not seen any more",
                    "devices not seen any more",
                ),
                d.gone_assets.iter().map(|a| a.describe()).collect(),
            );
            list(
                ui,
                util::plural(d.changed.len(), "changed device", "changed devices"),
                d.changed
                    .iter()
                    .map(|c| format!("{}: {}", c.ip, c.what.join("; ")))
                    .collect(),
            );
            list(
                ui,
                util::plural(d.new_findings.len(), "new problem", "new problems"),
                d.new_findings.iter().map(|f| finding(&c.new, f)).collect(),
            );
            list(
                ui,
                util::plural(
                    d.resolved_findings.len(),
                    "problem no longer seen",
                    "problems no longer seen",
                ),
                d.resolved_findings
                    .iter()
                    .map(|f| finding(&c.old, f))
                    .collect(),
            );
            let mut failed = None;
            ui.horizontal(|ui| {
                if ui.button("Open the full comparison").clicked() {
                    failed = open(&c.out.join("diff.html")).err();
                }
                if ui.button("Open the folder").clicked() {
                    failed = open(&c.out).err();
                }
                if let Some(share) = &c.share {
                    if ui.button("Open the copy for sharing").clicked() {
                        failed = open(share).err();
                    }
                }
            });
            if let Some(e) = failed {
                self.error = Some(e);
            }
        }
        crate::app::Go::Stay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_goes_next_to_the_newer_report() {
        let newer = Path::new("reports")
            .join("otinv-2026-12")
            .join("run.londopy");
        assert_eq!(
            default_out(&newer),
            Some(Path::new("reports").join("otinv-2026-12-changes"))
        );
        assert_eq!(default_out(Path::new("run.londopy")), None);
    }
}
