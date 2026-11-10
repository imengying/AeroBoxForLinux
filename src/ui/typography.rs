use super::*;

/// One scale for every window, including dialogs, popovers and source editors.
/// Font family and DPI remain the desktop's choices; no font is bundled/forced.
pub(super) struct Typography {
    provider: gtk::CssProvider,
    system_rendering: Vec<(&'static str, glib::Value)>,
}

impl Typography {
    pub(super) fn new(scale: u32, crisp: bool) -> Self {
        let provider = gtk::CssProvider::new();
        gtk::style_context_add_provider_for_display(
            &gtk::gdk::Display::default().expect("Wayland display"),
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION + 1,
        );
        let settings = gtk::Settings::default().expect("GTK settings");
        let system_rendering = [
            "gtk-font-rendering",
            "gtk-hint-font-metrics",
            "gtk-xft-hinting",
            "gtk-xft-hintstyle",
            "gtk-xft-antialias",
        ]
        .into_iter()
        .filter(|name| settings.find_property(name).is_some())
        .map(|name| (name, settings.property_value(name)))
        .collect();
        let result = Self {
            provider,
            system_rendering,
        };
        result.apply(scale, crisp);
        result
    }

    pub(super) fn apply(&self, scale: u32, crisp: bool) {
        self.provider.load_from_data(&format!(
            "window {{ font-size: {}%; }}",
            scale.clamp(100, 150)
        ));
        let settings = gtk::Settings::default().expect("GTK settings");
        if crisp {
            // GTK >= 4.16 otherwise ignores the hinting preference in automatic
            // mode. Older GTK exposes the low-level settings directly.
            if let Some(property) = settings.find_property("gtk-font-rendering")
                && let Some(class) = glib::EnumClass::with_type(property.value_type())
                && let Some(value) = class.value_by_nick("manual")
            {
                settings.set_property_from_value("gtk-font-rendering", &value.to_value(&class));
            }
            settings.set_gtk_hint_font_metrics(true);
            settings.set_gtk_xft_hinting(1);
            settings.set_gtk_xft_hintstyle(Some("hintslight"));
            settings.set_gtk_xft_antialias(1);
        } else {
            for (name, value) in &self.system_rendering {
                settings.set_property_from_value(name, value);
            }
        }
    }
}
