use aerobox_for_linux::{engine, model, platform};
use anyhow::{Context, Result, bail};
use std::path::PathBuf;
mod ui;

fn main() -> gtk::glib::ExitCode {
    // Standalone startup windows also need the installed desktop entry's ID.
    // Set this before GTK initializes and caches its Wayland application ID.
    gtk::glib::set_prgname(Some(platform::APP_ID));
    gtk::glib::set_application_name("AeroBox");
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
    #[cfg(feature = "ui-smoke")]
    let mut smoke = None;
    let mut resume = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--resume-connection" => resume = true,
            "--version" => {
                println!(
                    "AeroBox {} · Rust / GTK4 / Wayland",
                    option_env!("AEROBOX_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
                );
                return Ok(gtk::glib::ExitCode::SUCCESS);
            }
            "--data-dir" => dir = Some(PathBuf::from(args.next().context("--data-dir 需要路径")?)),
            #[cfg(feature = "ui-smoke")]
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
    #[cfg(feature = "ui-smoke")]
    if smoke.is_some() {
        let smoke_dir = dir
            .as_ref()
            .context("--smoke-test 需要显式指定独立的 --data-dir")?;
        if smoke_dir.join("state.json").exists() {
            bail!("界面测试需要空数据目录，已有数据未修改")
        }
    }
    // Text, cards and forms do not benefit enough from GPU rendering to justify
    // a persistent setting. Cairo avoids loading Mesa/LLVM and graphics caches.
    // Set this before GTK initializes; an explicit renderer override still wins.
    if std::env::var_os("GSK_RENDERER").is_none() {
        unsafe { std::env::set_var("GSK_RENDERER", "cairo") };
    }
    let store = match model::Store::open(dir.clone()) {
        Ok(store) => store,
        Err(error) => {
            #[cfg(feature = "ui-smoke")]
            if smoke.is_some() {
                return Err(error);
            }
            match ui::recover_store(dir, error)? {
                Some(store) => store,
                None => return Ok(gtk::glib::ExitCode::FAILURE),
            }
        }
    };
    let service = engine::Service::new(store);
    let (result, relaunch) = ui::run(
        service.clone(),
        resume,
        #[cfg(feature = "ui-smoke")]
        smoke,
    );
    if let Err(e) = service.shutdown() {
        if relaunch.is_some() {
            return Err(e.context("重启前停止连接失败"));
        }
        eprintln!("停止连接: {e:#}")
    }
    if let Some(resume) = relaunch {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command.arg("--data-dir").arg(service.dir());
        if resume {
            command.arg("--resume-connection");
        }
        return Err(command.exec()).context("授权后重启 AeroBox 失败");
    }
    Ok(result)
}
