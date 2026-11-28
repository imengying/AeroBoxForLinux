use super::*;

/// The desktop font name includes both its family and its size. In system mode
/// both are used; an explicit preference changes the size but not the family.
pub(super) struct Typography {
    provider: gtk::CssProvider,
    settings: gtk::Settings,
    font_size: Cell<u32>,
    density: Cell<u32>,
    css: RefCell<String>,
}

impl Typography {
    pub(super) fn new(font_size: u32) -> Self {
        let provider = gtk::CssProvider::new();
        gtk::style_context_add_provider_for_display(
            &gtk::gdk::Display::default().expect("Wayland display"),
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION + 1,
        );
        let result = Self {
            provider,
            settings: gtk::Settings::default().expect("GTK settings"),
            font_size: Cell::new(font_size),
            density: Cell::new(100),
            css: RefCell::new(String::new()),
        };
        result.update();
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

    /// Point-equivalent size at 96 DPI, before viewport scaling. Pixel-based
    /// layout uses this to follow both the font and the desktop's text scale.
    pub(super) fn layout_font_size(&self) -> f64 {
        let font = self.font();
        let size = f64::from(font.size()) / f64::from(gtk::pango::SCALE);
        if font.is_size_absolute() {
            size * 72.0 / 96.0
        } else {
            size * f64::from(self.settings.gtk_xft_dpi()) / (96.0 * 1024.0)
        }
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
        self.density.set(density);
        self.update();
    }

    pub(super) fn set_font_size(&self, font_size: u32) {
        self.font_size.set(font_size);
    }

    fn font(&self) -> gtk::pango::FontDescription {
        let name = self.settings.gtk_font_name();
        let mut font =
            gtk::pango::FontDescription::from_string(name.as_deref().unwrap_or("Sans 11"));
        if self.font_size.get() != 0 {
            font.set_size(self.font_size.get() as i32 * gtk::pango::SCALE);
        } else if font.size() <= 0 {
            font.set_size(11 * gtk::pango::SCALE);
        }
        font
    }

    fn update(&self) {
        let font = self.font();
        let size = f64::from(font.size()) / f64::from(gtk::pango::SCALE);
        let unit = if font.is_size_absolute() { "px" } else { "pt" };
        let families = font
            .family()
            .map(|family| format!("font-family: {};", css_string(&family)))
            .unwrap_or_default();
        let css = format!(
            "window {{ {families}font-size: calc({size}{unit} * {} / 100); }}",
            self.density.get()
        );
        if *self.css.borrow() != css {
            self.provider.load_from_data(&css);
            self.css.replace(css);
        }
    }
}

fn css_string(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}
