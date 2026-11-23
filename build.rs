use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=resources/resources.gresource.xml");
    println!("cargo:rerun-if-changed=resources/icons");
    println!("cargo:rerun-if-changed=resources/styles");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"))
        .join("aerobox.gresource");
    let status = Command::new("glib-compile-resources")
        .arg("resources/resources.gresource.xml")
        .arg("--sourcedir=resources")
        .arg("--target")
        .arg(output)
        .status()
        .expect("glib-compile-resources is required; install the GLib development tools");
    assert!(status.success(), "Compiling AeroBox resources failed");
}
