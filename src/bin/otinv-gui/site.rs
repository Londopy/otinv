// the Site details page: a form for site.toml. names, the utility's own
// address ranges, which computers may send control commands, and each
// device's location, drawings, backup and tools (CISA's CPG 2.0 asks for
// those, and no capture can see them).

use crate::app::Go;
use crate::style;
use eframe::egui::{self, RichText};
use otinv::config::Site;
use otinv::model::Details;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Default, Clone, PartialEq, Debug)]
pub struct Row {
    pub ip: String,
    pub name: String,
    pub details: Details,
}

/// What waits on "discard unsaved changes?".
enum Discard {
    StartNew,
    Open(PathBuf),
    CloseWindow,
}

#[derive(Default)]
pub struct SiteForm {
    path: Option<PathBuf>,
    pub name: String,
    /// One per line, as typed.
    pub networks: String,
    pub writers: String,
    pub rows: Vec<Row>,
    dirty: bool,
    pending: Option<Discard>,
    error: Option<String>,
    saved: Option<String>,
}

fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

impl SiteForm {
    pub fn from_site(site: &Site) -> Self {
        let mut ips: Vec<&String> = site.names.keys().chain(site.details.keys()).collect();
        ips.sort();
        ips.dedup();
        Self {
            name: site.name.clone(),
            networks: site.local_networks.join("\n"),
            writers: site.expected_writers.join("\n"),
            rows: ips
                .into_iter()
                .map(|ip| Row {
                    ip: ip.clone(),
                    name: site.names.get(ip).cloned().unwrap_or_default(),
                    details: site.details.get(ip).cloned().unwrap_or_default(),
                })
                .collect(),
            ..Default::default()
        }
    }

    pub fn to_site(&self) -> Site {
        let mut names = BTreeMap::new();
        let mut details = BTreeMap::new();
        for r in self.rows.iter().filter(|r| !r.ip.trim().is_empty()) {
            let ip = r.ip.trim().to_string();
            if !r.name.trim().is_empty() {
                names.insert(ip.clone(), r.name.trim().to_string());
            }
            if !r.details.is_empty() {
                details.insert(ip, r.details.clone());
            }
        }
        Site {
            name: self.name.trim().to_string(),
            local_networks: lines(&self.networks),
            expected_writers: lines(&self.writers),
            names,
            details,
            ranges: Vec::new(),
        }
    }

    /// Rows for devices not in the form yet, keeping what's already typed.
    pub fn add_devices(&mut self, devices: Vec<(String, String)>) {
        for (ip, name) in devices {
            if !self.rows.iter().any(|r| r.ip == ip) {
                self.rows.push(Row {
                    ip,
                    name,
                    ..Default::default()
                });
                self.dirty = true;
            }
        }
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    /// The window is closing: ask about unsaved changes first.
    pub fn ask_before_close(&mut self) {
        self.pending = Some(Discard::CloseWindow);
    }

    fn discard_or_ask(&mut self, then: Discard) -> Go {
        if self.dirty {
            self.pending = Some(then);
            return Go::Stay;
        }
        self.discard(then)
    }

    fn discard(&mut self, then: Discard) -> Go {
        match then {
            Discard::StartNew => *self = Self::default(),
            Discard::Open(p) => self.load(p),
            Discard::CloseWindow => {
                self.dirty = false;
                return Go::CloseWindow;
            }
        }
        Go::Stay
    }

    fn load(&mut self, path: PathBuf) {
        match Site::load(&path) {
            Ok(site) => {
                *self = Self::from_site(&site);
                self.path = Some(path);
            }
            Err(e) => self.error = Some(format!("{e:#}")),
        }
    }

    fn save(&mut self, path: PathBuf) -> bool {
        let written = self
            .to_site()
            .to_toml()
            .and_then(|text| std::fs::write(&path, text).map_err(Into::into));
        match written {
            Ok(()) => {
                self.saved = Some(format!("Saved {}", path.display()));
                self.error = None;
                self.dirty = false;
                self.pending = None;
                self.path = Some(path);
                true
            }
            Err(e) => {
                self.error = Some(format!("{e:#}"));
                false
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, devices: Vec<(String, String)>) -> Go {
        let mut go = Go::Stay;
        style::heading(ui, "Site details");
        ui.label(
            "Facts about the utility that a capture can't show. They go into every report \
             and the inventory. This file names your devices: keep it private.",
        );
        if self.pending.is_some() {
            style::notice(
                ui,
                ui.visuals().warn_fg_color,
                "Unsaved site details",
                "The details typed here haven't been saved. Discard them?",
            );
            ui.horizontal(|ui| {
                if ui.button("Discard").clicked() {
                    if let Some(then) = self.pending.take() {
                        go = self.discard(then);
                    }
                }
                if ui.button("Keep editing").clicked() {
                    self.pending = None;
                }
            });
            ui.add_space(8.0);
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button("Open site.toml...").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("Site file", &["toml"])
                    .pick_file()
                {
                    go = self.discard_or_ask(Discard::Open(p));
                }
            }
            if ui.button("Start a new one").clicked() {
                go = self.discard_or_ask(Discard::StartNew);
            }
            match &self.path {
                Some(p) => ui.label(RichText::new(p.display().to_string()).monospace()),
                None => ui.label(RichText::new("not saved yet").weak()),
            };
            if self.dirty {
                ui.label(RichText::new("unsaved changes").color(ui.visuals().warn_fg_color));
            }
        });

        style::section(ui, "The utility");
        let mut changed = false;
        let label = ui.label("Name shown at the top of every report");
        changed |= ui
            .add(
                egui::TextEdit::singleline(&mut self.name).hint_text("e.g. Example Water District"),
            )
            .labelled_by(label.id)
            .changed();
        let label = ui.label(
            "Address ranges that belong to the utility besides the private ones, one per line",
        );
        changed |= ui
            .add(
                egui::TextEdit::multiline(&mut self.networks)
                    .desired_rows(2)
                    .hint_text("e.g. 203.0.113.0/28"),
            )
            .labelled_by(label.id)
            .changed();
        let label = ui.label(
            "Computers that are supposed to send control commands (usually the SCADA server), \
             one per line",
        );
        changed |= ui
            .add(
                egui::TextEdit::multiline(&mut self.writers)
                    .desired_rows(2)
                    .hint_text("e.g. 10.0.2.20"),
            )
            .labelled_by(label.id)
            .changed();

        style::section(ui, "Devices");
        ui.horizontal_wrapped(|ui| {
            if ui.button("Add a device").clicked() {
                self.rows.push(Row::default());
                changed = true;
            }
            let more = devices
                .iter()
                .any(|(ip, _)| !self.rows.iter().any(|r| &r.ip == ip));
            if ui
                .add_enabled(more, egui::Button::new("Add devices from the results"))
                .on_disabled_hover_text(
                    "Analyze a capture or open a run first, or they're all here already",
                )
                .clicked()
            {
                self.add_devices(devices.clone());
            }
        });
        if self.rows.is_empty() {
            ui.label(RichText::new("No devices yet.").weak());
        }
        let mut remove = None;
        for (i, r) in self.rows.iter_mut().enumerate() {
            egui::Frame::group(ui.style())
                .inner_margin(8)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::Grid::new(("device", i))
                        .num_columns(2)
                        .show(ui, |ui| {
                            for (label, value, hint) in [
                                ("Address", &mut r.ip, "e.g. 10.0.1.10"),
                                ("Name", &mut r.name, "e.g. Well 2 PLC"),
                                (
                                    "Location",
                                    &mut r.details.location,
                                    "e.g. Well 2 pump house, panel 3",
                                ),
                                (
                                    "Drawings",
                                    &mut r.details.drawings,
                                    "e.g. P&ID W2-004 rev C",
                                ),
                                (
                                    "Configuration backup",
                                    &mut r.details.config_backup,
                                    "e.g. program exported 2026-10-03, office file server",
                                ),
                                (
                                    "Programming tools",
                                    &mut r.details.tools,
                                    "e.g. CLICK Programming Software 3.60",
                                ),
                            ] {
                                let label = ui.label(label);
                                changed |= ui
                                    .add(
                                        egui::TextEdit::singleline(value)
                                            .hint_text(hint)
                                            .desired_width(f32::INFINITY),
                                    )
                                    .labelled_by(label.id)
                                    .changed();
                                ui.end_row();
                            }
                        });
                    if ui.button("Remove this device").clicked() {
                        remove = Some(i);
                    }
                });
        }
        if let Some(i) = remove {
            self.rows.remove(i);
            changed = true;
        }
        if changed {
            self.dirty = true;
            self.saved = None;
        }

        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            let rewrites = "Writes the file from this form; comments in it aren't kept";
            if let Some(p) = self.path.clone() {
                if style::primary_button(ui, "Save")
                    .on_hover_text(rewrites)
                    .clicked()
                {
                    self.save(p);
                }
            }
            if ui.button("Save as...").on_hover_text(rewrites).clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .set_file_name("site.toml")
                    .add_filter("Site file", &["toml"])
                    .save_file()
                {
                    self.save(p);
                }
            }
            if let Some(p) = self.path.clone() {
                if ui
                    .add_enabled(
                        !self.dirty,
                        egui::Button::new("Use it for the next analysis"),
                    )
                    .on_disabled_hover_text("Save first")
                    .clicked()
                {
                    go = Go::UseSite(p);
                }
            }
        });
        if let Some(s) = &self.saved {
            ui.label(RichText::new(s).color(style::accent(ui)));
        }
        if let Some(e) = &self.error {
            style::notice(ui, ui.visuals().error_fg_color, "Not saved", e);
        }
        go
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_round_trips_a_site_file() {
        let site = Site::parse(
            "name = 'Lab'\nlocal_networks = ['203.0.113.0/28']\nexpected_writers = ['10.0.2.20']\n\
             [names]\n'10.0.1.10' = 'Well 2 PLC'\n\
             [details.'10.0.1.11']\nlocation = 'Pump house'\n",
        )
        .unwrap();
        let form = SiteForm::from_site(&site);
        assert_eq!(form.rows.len(), 2);
        let back = Site::parse(&form.to_site().to_toml().unwrap()).unwrap();
        assert_eq!(back.names, site.names);
        assert_eq!(back.details, site.details);
        assert_eq!(back.expected_writers, ["10.0.2.20"]);
    }

    #[test]
    fn blank_rows_and_lines_are_left_out() {
        let mut form = SiteForm {
            networks: "203.0.113.0/28\n\n  \n".into(),
            ..Default::default()
        };
        form.rows.push(Row::default());
        form.add_devices(vec![("10.0.1.10".into(), "PLC".into())]);
        form.add_devices(vec![("10.0.1.10".into(), "again".into())]);
        let site = form.to_site();
        assert_eq!(site.local_networks, ["203.0.113.0/28"]);
        assert_eq!(site.names.len(), 1);
        assert_eq!(site.names["10.0.1.10"], "PLC");
        assert!(site.details.is_empty());
        // a typo is caught before anything is written
        form.writers = "10.0.2.300".into();
        assert!(form.to_site().to_toml().is_err());
    }
}
