// the window: a list of pages on the left, the current page on the right.
// pages hand each other work through `Go` (a finished analysis opens the
// results, a saved site file is picked for the next analysis, ...).

use crate::{about, analyze, compare, results, site, style};
use eframe::egui::{self, RichText};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Analyze,
    Results,
    Compare,
    Site,
    About,
}

impl Page {
    const ALL: [Page; 5] = [
        Page::Analyze,
        Page::Results,
        Page::Compare,
        Page::Site,
        Page::About,
    ];

    fn label(self) -> &'static str {
        match self {
            Page::Analyze => "Analyze",
            Page::Results => "Results",
            Page::Compare => "Compare months",
            Page::Site => "Site details",
            Page::About => "About",
        }
    }
}

/// What a page asks the rest of the window to do.
pub enum Go {
    Stay,
    ShowResults(Box<results::Loaded>),
    UseSite(PathBuf),
    AddDevices(Vec<(String, String)>),
    Open(Page),
    CloseWindow,
}

pub struct App {
    page: Page,
    /// Results finished while another page was showing.
    fresh_results: bool,
    /// The window was closed during a run: close once zeek has stopped.
    close_when_stopped: bool,
    analyze: analyze::Analyze,
    results: results::Results,
    compare: compare::Compare,
    site: site::SiteForm,
    about: about::About,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        style::install(&cc.egui_ctx);
        Self {
            page: Page::Analyze,
            fresh_results: false,
            close_when_stopped: false,
            analyze: analyze::Analyze::default(),
            results: results::Results::default(),
            compare: compare::Compare::default(),
            site: site::SiteForm::default(),
            about: about::About::default(),
        }
    }

    fn go(&mut self, ctx: &egui::Context, go: Go) {
        match go {
            Go::Stay => {}
            Go::ShowResults(loaded) => {
                self.compare.suggest_newer(&loaded.run_file);
                self.results.show(*loaded);
                self.page = Page::Results;
            }
            Go::UseSite(path) => {
                self.analyze.site = Some(path);
                self.page = Page::Analyze;
            }
            Go::AddDevices(devices) => {
                self.site.add_devices(devices);
                self.page = Page::Site;
            }
            Go::Open(page) => self.page = page,
            Go::CloseWindow => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
        }
    }

    /// An analysis that finishes while someone works on another page shows
    /// up as "new" in the page list instead of taking the window over.
    fn finished(&mut self, ctx: &egui::Context, go: Go) {
        match go {
            Go::ShowResults(loaded) if self.page != Page::Analyze => {
                self.compare.suggest_newer(&loaded.run_file);
                self.results.show(*loaded);
                self.fresh_results = true;
            }
            go => self.go(ctx, go),
        }
    }

    /// The window is being closed. A running zeek is stopped first, so it
    /// doesn't run on unattended and its raw logs get deleted; typed site
    /// details are slow to retype, so those are asked about.
    fn closing(&mut self, ctx: &egui::Context) {
        if self.close_when_stopped {
            return;
        }
        if self.analyze.busy() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.analyze.stop();
            self.close_when_stopped = true;
            self.page = Page::Analyze;
        } else if self.site.dirty() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.site.ask_before_close();
            self.page = Page::Site;
        }
    }

    /// A file dropped on the window: a saved run opens in Results, anything
    /// else becomes the input to analyze.
    fn dropped(&mut self, ctx: &egui::Context) {
        let paths: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        let count = paths.len();
        let Some(path) = paths.into_iter().next() else {
            return;
        };
        let go = if path.extension().is_some_and(|e| e == "londopy") {
            self.results.open_run(&path)
        } else {
            self.analyze.set_input(ctx, path);
            if count > 1 {
                self.analyze.note = Some(format!(
                    "{count} items were dropped; otinv analyzes one at a time, so it took the first."
                ));
            }
            Go::Open(Page::Analyze)
        };
        self.go(ctx, go);
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.dropped(&ctx);
        if ctx.input(|i| i.viewport().close_requested()) {
            self.closing(&ctx);
        }
        egui::Panel::left("pages")
            .exact_size(190.0)
            .resizable(false)
            .show(ui, |ui| {
                ui.add_space(12.0);
                ui.label(RichText::new("otinv").size(22.0).strong());
                ui.label(RichText::new(format!("version {}", env!("CARGO_PKG_VERSION"))).weak());
                ui.add_space(14.0);
                for p in Page::ALL {
                    let busy = match p {
                        Page::Analyze => self.analyze.busy(),
                        Page::Compare => self.compare.busy(),
                        _ => false,
                    };
                    let text = if busy {
                        format!("{} (running)", p.label())
                    } else if p == Page::Results && self.fresh_results {
                        format!("{} (new)", p.label())
                    } else {
                        p.label().to_string()
                    };
                    let item = egui::Button::selectable(self.page == p, text)
                        .min_size(egui::vec2(ui.available_width(), 30.0));
                    if ui.add(item).clicked() {
                        self.page = p;
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(
                            "Works offline. Reports are sensitive: keep them on an \
                             encrypted disk.",
                        )
                        .weak(),
                    );
                });
            });
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add_space(8.0);
                    let go = match self.page {
                        Page::Analyze => self.analyze.ui(ui),
                        Page::Results => self.results.ui(ui),
                        Page::Compare => self.compare.ui(ui),
                        Page::Site => self.site.ui(ui, self.results.devices()),
                        Page::About => self.about.ui(ui),
                    };
                    self.go(&ctx, go);
                });
        });
        if self.page == Page::Results {
            self.fresh_results = false;
        }
        // finished background work is picked up even on another page
        let go = self.analyze.poll();
        self.finished(&ctx, go);
        if self.close_when_stopped && !self.analyze.busy() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        self.compare.poll();
    }
}

/// Opens a file or folder with whatever the system uses for it: the HTML
/// report in the browser, a folder in the file manager.
pub fn open(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let mut cmd = std::process::Command::new("explorer.exe");
    #[cfg(target_os = "macos")]
    let mut cmd = std::process::Command::new("open");
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let mut cmd = std::process::Command::new("xdg-open");
    // explorer exits with 1 even when it worked, so only a failure to start counts
    cmd.arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Couldn't open {}: {e}", path.display()))
}

/// A link that opens in the system's browser, the way the report buttons
/// open files. Returns why it couldn't.
pub fn link(ui: &mut egui::Ui, text: &str, url: &str) -> Option<String> {
    ui.link(text)
        .on_hover_text(url)
        .clicked()
        .then(|| open(Path::new(url)).err())
        .flatten()
}

/// A row with a label, the chosen path (or a hint), and buttons after it.
pub fn path_row(
    ui: &mut egui::Ui,
    label: &str,
    path: Option<PathBuf>,
    hint: &str,
    buttons: impl FnOnce(&mut egui::Ui),
) {
    ui.label(RichText::new(label).strong());
    ui.horizontal_wrapped(|ui| {
        match path {
            Some(p) => ui.label(RichText::new(p.display().to_string()).monospace()),
            None => ui.label(RichText::new(hint).weak()),
        };
        buttons(ui);
    });
    ui.add_space(6.0);
}
