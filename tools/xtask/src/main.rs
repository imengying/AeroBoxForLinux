mod bench;
mod desktop;
mod package;
mod peer;
mod process;
mod task_owner;

use anyhow::{Result, bail, ensure};
use std::{env, path::PathBuf, process::Command};

const APP_ID: &str = "io.github.imengying.AeroBoxForLinux";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn target() -> PathBuf {
    env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("target"))
}

fn cargo(args: &[&str]) -> Result<()> {
    process::run(Command::new("cargo").args(args))
}

fn network() -> Result<()> {
    let manifest = "tools/xtask/Cargo.toml";
    cargo(&["fmt", "--manifest-path", manifest, "--check"])?;
    cargo(&[
        "fmt",
        "--manifest-path",
        "tools/xtask/fuzz/Cargo.toml",
        "--check",
    ])?;
    cargo(&[
        "clippy",
        "--manifest-path",
        manifest,
        "--locked",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ])?;
    cargo(&["test", "--manifest-path", manifest, "--locked"])?;
    let files =
        task_owner::check(&root().join("vendor/shoes/src/lib.rs")).map_err(anyhow::Error::msg)?;
    println!("Task ownership: {files} production modules checked");
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    env::set_current_dir(root())?;
    let mut args = env::args_os().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());
    let args: Vec<_> = args.collect();
    if command == "bench" {
        return bench::run(args);
    }
    if command == "desktop" {
        ensure!(args.len() == 1, "Usage: cargo xtask desktop DIRECTORY");
        return desktop::check(&PathBuf::from(&args[0]));
    }
    if command == "desktop-prepare" {
        ensure!(
            args.len() == 1,
            "Usage: cargo xtask desktop-prepare DIRECTORY"
        );
        return desktop::prepare(&PathBuf::from(&args[0]));
    }
    if command == "check-package" {
        ensure!(args.len() == 1, "Usage: cargo xtask check-package ARCHIVE");
        return package::check(&PathBuf::from(&args[0]));
    }
    ensure!(args.is_empty(), "Unexpected arguments: {args:?}");
    match command.to_str() {
        Some("help" | "--help" | "-h") => println!(
            "cargo xtask <command>\n\n  test                 Format, Clippy and application/component tests\n  network              Development tools and network task checks\n  wayland              Build and test the Wayland UI (AEROBOX_TEST_SCALE=1/1.25/2)\n  package              Build, package and verify the release\n  check-package FILE   Verify an existing release archive\n  bench [options]      Loopback performance comparison; --help for options\n  tls12-peer           Build the independent TLS renegotiation test peer"
        ),
        Some("network") => network()?,
        Some("test") => {
            network()?;
            cargo(&["fmt", "--package", "aerobox-for-linux", "--check"])?;
            cargo(&[
                "clippy",
                "--all-targets",
                "--locked",
                "--",
                "-D",
                "warnings",
            ])?;
            cargo(&[
                "clippy",
                "--bin",
                "AeroBox",
                "--features",
                "ui-smoke",
                "--locked",
                "--",
                "-D",
                "warnings",
            ])?;
            cargo(&["test", "--locked"])?;
            process::run(Command::new("scripts/test-protocols.sh").arg("--unit"))?;
        }
        Some("wayland") => {
            cargo(&[
                "build",
                "--bin",
                "AeroBox",
                "--features",
                "ui-smoke",
                "--locked",
            ])?;
            process::run(
                Command::new("scripts/test-wayland.sh").arg(target().join("debug/AeroBox")),
            )?;
        }
        Some("package") => {
            cargo(&["build", "--release", "--locked", "--no-default-features"])?;
            let archive = package::create()?;
            package::check(&archive)?;
            println!("Package: {}", archive.display());
        }
        Some("bench-origin") => bench::origin()?,
        Some("tls12-peer") => peer::build()?,
        _ => bail!(
            "Unknown command: {}. See cargo xtask --help",
            command.to_string_lossy()
        ),
    }
    Ok(())
}
