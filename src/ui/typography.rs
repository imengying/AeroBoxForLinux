use super::*;

/// Applies the user's base font size to every window, dialog, popover and
/// source editor. Text rendering follows the current GTK desktop settings.
///
/// The size is expressed in points and becomes the root font size; every
/// text spacing and control metrics in `resources/styles/` use `em`, so
/// changing the font also changes row heights and paddings.
pub(super) struct Typography {
    provider: gtk::CssProvider,
    font_size: Cell<u32>,
    density: Cell<u32>,
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
            font_size: Cell::new(0),
            density: Cell::new(100),
        };
        result.apply(font_size);
        result
    }

    pub(super) fn preview(&self) -> u32 {
        self.font_size.get()
    }

    pub(super) fn density_percent(&self) -> i32 {
        self.density.get() as i32
    }

    pub(super) fn density(&self) -> f64 {
        f64::from(self.density.get()) / 100.0
    }

    /// A restrained viewport-based scale, separate from the user's font size.
    /// Wide screens increase both text and control sizes; `em` metrics keep
    /// the proportions consistent, including in dialogs and menus.
    pub(super) fn set_viewport_scale(&self, width: i32, height: i32) {
        let density = match (width, height) {
            (0, _) | (_, 0) => 100,
            (_, height) if height < 600 => 100,
            (width, _) if width >= 1700 => 120,
            (width, _) if width >= 1100 => 112,
            _ => 100,
        };
        if self.density.replace(density) != density {
            self.update();
        }
    }

    pub(super) fn apply(&self, font_size: u32) {
        let size = font_size.clamp(model::FONT_SIZE_MIN, model::FONT_SIZE_MAX);
        if self.font_size.replace(size) != size {
            self.update();
        }
    }

    fn update(&self) {
        let size = self.font_size.get();
        self.provider.load_from_data(&format!(
            "window {{ font-size: calc({size}pt * {} / 100); }}",
            self.density.get()
        ));
    }
}
