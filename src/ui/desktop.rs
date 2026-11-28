use super::*;

/// Follow GNOME preferences directly. Bindings live as long as GtkSettings does.
pub(super) fn follow_settings() {
    let settings = gtk::Settings::default().expect("GTK settings");
    let desktop = gio::Settings::new("org.gnome.desktop.interface");
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
    gio::Settings::new("org.gnome.desktop.wm.preferences")
        .bind("button-layout", &settings, "gtk-decoration-layout")
        .get_only()
        .build();
}
