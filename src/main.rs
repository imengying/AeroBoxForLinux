use aerobox_for_linux::{engine, model, platform};
use anyhow::{Context, Result, bail};
use std::path::PathBuf;
mod ui;

fn main() -> gtk::glib::ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("AeroBox: {e:#}");
            gtk::glib::ExitCode::FAILURE
        }
    }
}
fn run() -> Result<gtk::glib::ExitCode> {
    let mut args = std::env::args().skip(1);
    let mut dir = None;
    let mut smoke = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--watch-core" => {
                engine::watch_core_process()?;
                return Ok(gtk::glib::ExitCode::SUCCESS);
            }
            "--version" => {
                println!(
                    "AeroBox {} · Rust / GTK4 / Wayland",
                    option_env!("AEROBOX_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
                );
                return Ok(gtk::glib::ExitCode::SUCCESS);
            }
            "--data-dir" => dir = Some(PathBuf::from(args.next().context("--data-dir 需要路径")?)),
            "--smoke-test" => {
                smoke = Some(PathBuf::from(
                    args.next().context("--smoke-test 需要截图路径")?,
                ))
            }
            "--install-desktop" => {
                platform::install_desktop(&PathBuf::from(args.next().context("需要安装前缀")?))?;
                return Ok(gtk::glib::ExitCode::SUCCESS);
            }
            "--help" | "-h" => {
                println!("AeroBox [--data-dir PATH] [--version]\n仅支持 Linux Wayland 会话。");
                return Ok(gtk::glib::ExitCode::SUCCESS);
            }
            _ => bail!("未知参数 {arg}"),
        }
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("WAYLAND_SOCKET").is_none()
    {
        bail!("请在 Wayland 桌面会话内启动")
    }
    // Set before any GTK/network worker threads exist. Never fall back to X11.
    unsafe { std::env::set_var("GDK_BACKEND", "wayland") };
    if smoke.is_some() {
        let smoke_dir = dir
            .as_ref()
            .context("--smoke-test 需要显式指定独立的 --data-dir")?;
        if smoke_dir.join("state.json").exists() {
            bail!("界面测试需要空数据目录，已有数据未修改")
        }
    }
    let store = match model::Store::open(dir.clone()) {
        Ok(store) => store,
        Err(error) if smoke.is_none() => {
            if std::env::var_os("GSK_RENDERER").is_none() {
                unsafe { std::env::set_var("GSK_RENDERER", "cairo") };
            }
            match ui::recover_store(dir, error)? {
                Some(store) => store,
                None => return Ok(gtk::glib::ExitCode::FAILURE),
            }
        }
        Err(error) => return Err(error),
    };
    // A dashboard of text and cards does not need a GPU context by default.
    // Mesa's software GPU path can otherwise load LLVM and large render caches.
    // Configure this before any GTK or network worker exists; explicit user
    // renderer overrides still take precedence.
    if !store.state.settings.hardware_acceleration && std::env::var_os("GSK_RENDERER").is_none() {
        unsafe { std::env::set_var("GSK_RENDERER", "cairo") };
    }
    let service = engine::Service::new(store);
    let result = ui::run(service.clone(), smoke);
    if let Err(e) = service.shutdown() {
        eprintln!("停止内核: {e:#}")
    }
    Ok(result)
}
