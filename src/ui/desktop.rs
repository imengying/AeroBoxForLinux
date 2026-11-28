use super::*;

/// Read GNOME's native preferences even if the settings portal only exposes
/// part of them. Bindings are read-only and live as long as GtkSettings does.
pub(super) fn follow_settings() {
    let settings = gtk::Settings::default().expect("GTK settings");
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    if platform::desktop_kind(&desktop) == Some(platform::Desktop::Gnome)
        && let Some(source) = gio::SettingsSchemaSource::default()
    {
        if let Some(schema) = source.lookup("org.gnome.desktop.interface", true) {
            let desktop = gio::Settings::new_full(&schema, None::<&gio::SettingsBackend>, None);
            desktop
                .bind("font-name", &settings, "gtk-font-name")
                .get_only()
                .build();
            desktop
                .bind("text-scaling-factor", &settings, "gtk-xft-dpi")
                .get_only()
                .mapping(|value, _| {
                    value
                        .get::<f64>()
                        .map(|scale| ((96.0 * 1024.0 * scale).round() as i32).to_value())
                })
                .build();
        }
        if let Some(schema) = source.lookup("org.gnome.desktop.wm.preferences", true) {
            gio::Settings::new_full(&schema, None::<&gio::SettingsBackend>, None)
                .bind("button-layout", &settings, "gtk-decoration-layout")
                .get_only()
                .build();
        }
    }
    // libadwaita's scaled length units need a positive DPI. Release this
    // fallback when the display later supplies its own value.
    if settings.gtk_xft_dpi() <= 0 {
        settings.set_gtk_xft_dpi(96 * 1024);
        let weak = settings.downgrade();
        gtk::gdk::Display::default()
            .expect("Wayland display")
            .connect_setting_changed(move |_, name| {
                if name == "gtk-xft-dpi"
                    && let Some(settings) = weak.upgrade()
                {
                    settings.reset_property("gtk-xft-dpi");
                }
            });
    }
}
