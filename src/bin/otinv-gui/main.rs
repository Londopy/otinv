// otinv-gui: the same analysis as the otinv command, in a window, for people
// who'd rather not use a terminal. like the CLI it works offline; the only
// network use is "Check for updates" on the About page, when clicked.

// a GUI exe never opens a console window on windows; debug builds keep one
// for panics
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod about;
mod analyze;
mod app;
mod compare;
mod job;
mod results;
mod site;
mod style;

// shared with the otinv command; its terminal prompt isn't used here
#[allow(dead_code)]
#[path = "../../update.rs"]
mod update;

fn main() -> eframe::Result {
    update::remove_leftover();
    let icon = eframe::egui::IconData {
        rgba: include_bytes!("../../../assets/icon-64.rgba").to_vec(),
        width: 64,
        height: 64,
    };
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("otinv")
            .with_inner_size([1120.0, 780.0])
            .with_min_inner_size([760.0, 520.0])
            .with_icon(icon)
            .with_drag_and_drop(true),
        ..Default::default()
    };
    let started = eframe::run_native(
        "otinv",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    );
    // with no console there's nowhere else to say why (no OpenGL over remote
    // desktop or in some VMs, say)
    if let Err(e) = &started {
        rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Error)
            .set_title("otinv")
            .set_description(format!(
                "otinv couldn't open its window: {e}\n\nThe otinv command line works without one."
            ))
            .show();
    }
    started
}
