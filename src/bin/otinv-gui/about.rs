// the About page: what otinv is, where it lives, and the update check. the
// check is the GUI's only network use, and only when the button is clicked.

use crate::app::{link, Go};
use crate::job::Job;
use crate::style;
use crate::update::{self, Check, Offer};
use eframe::egui::{self, RichText};
use otinv::command::Event;

const REPO: &str = "https://github.com/Londopy/otinv";

#[derive(Default)]
pub struct About {
    checking: Option<Job<Check>>,
    installing: Option<Job<()>>,
    status: Option<String>,
    offer: Option<Offer>,
    installed: bool,
    error: Option<String>,
}

impl About {
    fn poll(&mut self) {
        if let Some(job) = &mut self.checking {
            if let Some(r) = job.poll() {
                self.checking = None;
                match r {
                    Ok(Check::Current(msg)) => self.status = Some(msg),
                    Ok(Check::Available(o)) => {
                        self.status = Some(format!("otinv {} is available.", o.version));
                        self.offer = Some(o);
                    }
                    Err(e) => self.error = Some(e),
                }
            }
        }
        if let Some(job) = &mut self.installing {
            if let Some(r) = job.poll() {
                let log = job.notes.join("\n");
                self.installing = None;
                // what was done before a failure matters as much as the failure
                self.status = Some(log);
                match r {
                    Ok(()) => self.installed = true,
                    Err(e) => self.error = Some(e),
                }
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Go {
        self.poll();
        style::heading(ui, "About otinv");
        ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
        ui.add_space(6.0);
        ui.label(
            "otinv turns passive captures from a utility's control network into an asset \
             inventory and a short list of what to fix first. It only reads traffic that was \
             already captured, and the analysis never uses the network.",
        );
        let guide = format!("{REPO}/blob/main/docs/volunteer-guide.md");
        let issues = format!("{REPO}/issues");
        ui.horizontal_wrapped(|ui| {
            for (text, url) in [
                ("Project page", REPO),
                ("Volunteer guide", guide.as_str()),
                ("Report a problem", issues.as_str()),
            ] {
                if let Some(e) = link(ui, text, url) {
                    self.error = Some(e);
                }
            }
        });
        ui.label(RichText::new("MIT license. Made by Londopy.").weak());

        style::section(ui, "Updates");
        ui.label(
            "Checking asks GitHub for the latest release. It's the only thing otinv does online, \
             and it never happens unless you click. An update is checked against the release's \
             SHA-256 list before it replaces anything.",
        );
        if let Some(job) = &self.checking {
            job.show_progress(ui, "Asking GitHub");
        } else if let Some(job) = &self.installing {
            job.show_progress(ui, "Installing the update");
        } else if !self.installed && ui.button("Check for updates").clicked() {
            self.error = None;
            self.status = None;
            self.offer = None;
            self.checking = Some(Job::start(ui.ctx(), |_| update::check()));
        }
        if let Some(s) = &self.status {
            ui.label(s);
        }
        let page = self
            .offer
            .as_ref()
            .map(|o| (o.page.clone(), o.version.clone()));
        if let (Some((page, version)), false, None) = (page, self.installed, &self.installing) {
            ui.horizontal(|ui| {
                if let Some(e) = link(ui, "What's new", &page) {
                    self.error = Some(e);
                }
                if ui
                    .button(RichText::new(format!("Install {version}")).strong())
                    .clicked()
                {
                    let offer = self.offer.take();
                    self.installing = offer.map(|o| {
                        Job::start(ui.ctx(), move |on| {
                            o.install("otinv-gui", &mut |line| on(Event::Note(line)))
                        })
                    });
                }
            });
        }
        if self.installed {
            ui.label(
                RichText::new("Close otinv and open it again to use the new version.").strong(),
            );
        }
        if let Some(e) = &self.error {
            style::notice(ui, ui.visuals().error_fg_color, "The update didn't work", e);
        }
        Go::Stay
    }
}
