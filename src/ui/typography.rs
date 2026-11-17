use super::*;

/// Applies the user's base font size to every window, dialog, popover and
/// source editor. Text rendering follows the current GTK desktop settings.
///
/// The size is expressed in points and becomes the root font size; every
/// spacing and control metric in `style.css` is written in `em`, so changing
/// the font also changes row heights and paddings.
pub(super) struct Typography {
    provider: gtk::CssProvider,
    font_size: Cell<u32>,
}

impl Typography {
    pub(super) fn new(font_size: u32) -> Self {
        let provider = gtk::CssProvider::new();
        gtk::style_context_add_provider_for_display(
            &gtk::gdk::Display::default().expect("Wayland display"),
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION + 1,
        );
        let settings = gtk::Settings::default().expect("GTK settings");
        // GTK reports -1 when the desktop has not supplied a font DPI. Use
        // GTK's 96 DPI fallback before libadwaita measures SP-sized layouts.
        if settings.gtk_xft_dpi() <= 0 {
            settings.set_gtk_xft_dpi(96 * 1024);
        }
        let result = Self {
            provider,
            font_size: Cell::new(model::FONT_SIZE_MIN),
        };
        result.apply(font_size);
        result
    }

    pub(super) fn preview(&self) -> u32 {
        self.font_size.get()
    }

    pub(super) fn apply(&self, font_size: u32) {
        let size = font_size.clamp(model::FONT_SIZE_MIN, model::FONT_SIZE_MAX);
        self.font_size.set(size);
        self.provider
            .load_from_data(&format!("window {{ font-size: {size}pt; }}"));
    }
}
