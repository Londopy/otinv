// the look: the icon's slate and a muted teal for actions, the same severity
// colors as the HTML appendix, and the system's light or dark setting.

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontFamily, FontInsert, FontPriority, InsertFontFamily,
    RichText, Stroke, Theme, ThemePreference, Visuals,
};
use otinv::config::Severity;

const ACCENT_LIGHT: Color32 = Color32::from_rgb(0x1f, 0x5f, 0x6e);
const ACCENT_DARK: Color32 = Color32::from_rgb(0x6f, 0xb8, 0xc6);

pub fn install(ctx: &egui::Context) {
    ctx.set_theme(ThemePreference::System);
    ctx.set_visuals_of(Theme::Light, light());
    ctx.set_visuals_of(Theme::Dark, dark());
    ctx.all_styles_mut(|s| {
        // egui's 12.5 px body is small for a window people read reports in
        for (style, size) in [
            (egui::TextStyle::Body, 14.0),
            (egui::TextStyle::Button, 14.0),
            (egui::TextStyle::Monospace, 13.5),
        ] {
            if let Some(f) = s.text_styles.get_mut(&style) {
                f.size = size;
            }
        }
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(10.0, 4.0);
        s.spacing.interact_size.y = 26.0;
    });
    system_font(ctx);
}

// segoe ui on windows, so the window reads like the rest of the system;
// elsewhere egui's own font
fn system_font(ctx: &egui::Context) {
    let windir = std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into());
    let path = std::path::Path::new(&windir)
        .join("Fonts")
        .join("segoeui.ttf");
    if let Ok(bytes) = std::fs::read(path) {
        ctx.add_font(FontInsert::new(
            "Segoe UI",
            FontData::from_owned(bytes),
            vec![InsertFontFamily {
                family: FontFamily::Proportional,
                priority: FontPriority::Highest,
            }],
        ));
    }
}

// text, error and warning colors chosen for at least 4.5:1 on the panel;
// egui's defaults (pure red and orange, gray body text) fall short
fn shared(v: &mut Visuals, accent: Color32, text: Color32) {
    v.selection.bg_fill = accent.gamma_multiply(0.2);
    v.widgets.noninteractive.fg_stroke.color = text;
    v.selection.stroke = Stroke::new(1.5, accent);
    v.hyperlink_color = accent;
    let r = CornerRadius::same(4);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = r;
    }
    // egui draws a focused widget with the `active` look, so this is the
    // keyboard focus ring too
    v.widgets.hovered.bg_stroke = Stroke::new(1.5, accent);
    v.widgets.active.bg_stroke = Stroke::new(2.0, accent);
}

fn light() -> Visuals {
    let mut v = Visuals::light();
    v.panel_fill = Color32::from_rgb(0xf6, 0xf7, 0xf8);
    v.window_fill = Color32::WHITE;
    v.extreme_bg_color = Color32::WHITE;
    v.faint_bg_color = Color32::from_rgb(0xee, 0xf1, 0xf3);
    // hints and notes stay readable: about 7:1 against the panel
    v.weak_text_color = Some(Color32::from_rgb(0x4f, 0x5a, 0x63));
    v.error_fg_color = Color32::from_rgb(0xb3, 0x26, 0x1e);
    v.warn_fg_color = Color32::from_rgb(0x9a, 0x34, 0x12);
    shared(&mut v, ACCENT_LIGHT, Color32::from_rgb(0x1f, 0x24, 0x29));
    v
}

fn dark() -> Visuals {
    let mut v = Visuals::dark();
    v.panel_fill = Color32::from_rgb(0x16, 0x1a, 0x1e);
    v.window_fill = Color32::from_rgb(0x1c, 0x21, 0x26);
    v.extreme_bg_color = Color32::from_rgb(0x10, 0x13, 0x16);
    v.faint_bg_color = Color32::from_rgb(0x1f, 0x25, 0x2b);
    v.weak_text_color = Some(Color32::from_rgb(0x9a, 0xa4, 0xad));
    v.error_fg_color = Color32::from_rgb(0xf2, 0x86, 0x7f);
    v.warn_fg_color = Color32::from_rgb(0xf5, 0xb0, 0x5a);
    shared(&mut v, ACCENT_DARK, Color32::from_rgb(0xd4, 0xd9, 0xde));
    v
}

pub fn accent(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        ACCENT_DARK
    } else {
        ACCENT_LIGHT
    }
}

/// The appendix's colors for each severity, for light and dark.
pub fn severity_color(ui: &egui::Ui, s: Severity) -> Color32 {
    let dark = ui.visuals().dark_mode;
    let (l, d) = match s {
        Severity::Critical => ((0xb3, 0x26, 0x1e), (0xf2, 0x86, 0x7f)),
        Severity::High => ((0xc2, 0x41, 0x0c), (0xfb, 0x92, 0x3c)),
        // darker than the appendix's amber, to stay readable on striped rows
        Severity::Medium => ((0x8f, 0x56, 0x06), (0xfa, 0xcc, 0x15)),
        Severity::Low => ((0x25, 0x63, 0xeb), (0x7a, 0xa7, 0xff)),
        Severity::Info => ((0x4b, 0x55, 0x63), (0x9c, 0xa3, 0xaf)),
    };
    let (r, g, b) = if dark { d } else { l };
    Color32::from_rgb(r, g, b)
}

/// "CRITICAL" in its color, in a fixed-width slot so titles line up.
pub fn severity_tag(ui: &mut egui::Ui, s: Severity) {
    let text = RichText::new(s.label())
        .strong()
        .color(severity_color(ui, s));
    ui.add_sized([78.0, 20.0], egui::Label::new(text));
}

/// A boxed message for errors and warnings, readable in both themes.
pub fn notice(ui: &mut egui::Ui, color: Color32, title: &str, body: &str) {
    egui::Frame::new()
        .stroke(Stroke::new(1.0, color))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(10)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).strong().color(color));
            ui.label(body);
        });
}

/// The one main action on a page, filled with the accent color.
pub fn primary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let label = RichText::new(text).strong().color(ui.visuals().panel_fill);
    ui.add(
        egui::Button::new(label)
            .fill(accent(ui))
            .min_size(egui::vec2(120.0, 32.0)),
    )
}

pub fn heading(ui: &mut egui::Ui, title: &str) {
    ui.label(RichText::new(title).size(24.0).strong());
}

pub fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(10.0);
    ui.label(RichText::new(title).size(17.0).strong());
    ui.add_space(2.0);
}
