//! Linux desktop integration. All proxy writes go through the user's desktop
//! tools and can be restored without replacing unrelated desktop settings.

use anyhow::{Context, Result, bail, ensure};
use std::{
    env, fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use crate::model::{atomic_write, config_home};

pub const APP_ID: &str = "io.github.imengying.AeroBoxForLinux";
const GNOME_PROXY: &str = "org.gnome.system.proxy";

#[derive(Clone, Debug)]
struct DesktopCommand {
    program: PathBuf,
    args: Vec<String>,
}

impl DesktopCommand {
    fn new(program: impl Into<PathBuf>, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    fn run(&self) -> Result<String> {
        run_with_timeout(&self.program, &self.args, Duration::from_secs(5))
    }
}

// File-backed output avoids deadlocks if a tool writes more than a pipe buffer.
fn run_with_timeout(program: &Path, args: &[String], timeout: Duration) -> Result<String> {
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()
        .with_context(|| format!("无法运行 {}", program.display()))?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{} 执行超时", program.display());
        }
        thread::sleep(Duration::from_millis(15));
    };
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut output = String::new();
    let mut errors = String::new();
    stdout.take(128 * 1024).read_to_string(&mut output)?;
    stderr.take(4096).read_to_string(&mut errors)?;
    ensure!(
        status.success(),
        "{} 失败: {}",
        program.display(),
        errors.trim()
    );
    Ok(output.trim_end_matches(['\r', '\n']).to_owned())
}

fn executable(names: &[&str]) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    for name in names {
        for dir in env::split_paths(&paths) {
            let path = dir.join(name);
            if fs::metadata(&path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            {
                return Some(path);
            }
        }
    }
    None
}

#[derive(Clone, Debug)]
enum Backend {
    Gnome {
        settings: PathBuf,
    },
    Kde {
        read: PathBuf,
        write: PathBuf,
        notify: PathBuf,
    },
}

fn desktop_kind(desktop: &str) -> Option<&'static str> {
    let desktop = desktop.to_lowercase();
    let names: Vec<_> = desktop.split([':', ';', ',']).map(str::trim).collect();
    if names.iter().any(|s| ["kde", "plasma"].contains(s)) {
        return Some("kde");
    }
    if names
        .iter()
        .any(|s| ["gnome", "ubuntu", "unity", "budgie"].contains(s))
    {
        return Some("gnome");
    }
    None
}

fn backend() -> Result<Backend> {
    let desktop = env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    match desktop_kind(&desktop) {
        Some("kde") => Ok(Backend::Kde {
            read: executable(&["kreadconfig6", "kreadconfig5"])
                .context("KDE 的 kreadconfig 工具不可用")?,
            write: executable(&["kwriteconfig6", "kwriteconfig5"])
                .context("KDE 的 kwriteconfig 工具不可用")?,
            notify: executable(&["dbus-send"]).context("KDE 的 dbus-send 工具不可用")?,
        }),
        Some("gnome") => {
            let settings = executable(&["gsettings"]).context("GNOME 的 gsettings 工具不可用")?;
            let schemas = DesktopCommand::new(&settings, ["list-schemas"]).run()?;
            ensure!(
                schemas.lines().any(|s| s == GNOME_PROXY),
                "GNOME 系统代理设置不可用"
            );
            ensure!(
                DesktopCommand::new(&settings, ["writable", GNOME_PROXY, "mode"]).run()? == "true",
                "系统代理设置不可写"
            );
            Ok(Backend::Gnome { settings })
        }
        _ => bail!(
            "当前桌面没有可用的系统代理设置。Sway / Hyprland 可使用 TUN，或在应用中填写 HTTP/SOCKS 代理。"
        ),
    }
}

/// A snapshot contains only the keys this application changed. In particular,
/// KDE keys that were absent are removed again instead of being set to empty.
#[derive(Debug)]
pub struct ProxySnapshot {
    restore: Vec<DesktopCommand>,
}

impl ProxySnapshot {
    pub fn restore(&self) -> Result<()> {
        let mut errors = Vec::new();
        for command in &self.restore {
            if let Err(error) = command.run() {
                errors.push(error.to_string());
            }
        }
        ensure!(errors.is_empty(), "恢复系统代理失败: {}", errors.join("; "));
        Ok(())
    }
}

fn gsettings_keys() -> [(&'static str, &'static str); 10] {
    [
        ("org.gnome.system.proxy.http", "host"),
        ("org.gnome.system.proxy.http", "port"),
        ("org.gnome.system.proxy.https", "host"),
        ("org.gnome.system.proxy.https", "port"),
        ("org.gnome.system.proxy.socks", "host"),
        ("org.gnome.system.proxy.socks", "port"),
        ("org.gnome.system.proxy.http", "use-authentication"),
        (GNOME_PROXY, "use-same-proxy"),
        (GNOME_PROXY, "ignore-hosts"),
        (GNOME_PROXY, "mode"),
    ]
}

fn capture(backend: &Backend) -> Result<ProxySnapshot> {
    let mut restore = Vec::new();
    match backend {
        Backend::Gnome { settings } => {
            for (schema, key) in gsettings_keys() {
                let value = DesktopCommand::new(settings, ["get", schema, key]).run()?;
                restore.push(DesktopCommand::new(settings, ["set", schema, key, &value]));
            }
        }
        Backend::Kde {
            read,
            write,
            notify,
        } => {
            let absent = format!("aerobox-for-linux-missing-{}", uuid::Uuid::new_v4());
            for key in [
                "httpProxy",
                "httpsProxy",
                "socksProxy",
                "NoProxyFor",
                "ReversedException",
                "ProxyType",
            ] {
                let value = DesktopCommand::new(
                    read,
                    [
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        key,
                        "--default",
                        &absent,
                    ],
                )
                .run()?;
                let mut args = vec![
                    "--file",
                    "kioslaverc",
                    "--group",
                    "Proxy Settings",
                    "--key",
                    key,
                ];
                if value == absent {
                    args.push("--delete");
                } else {
                    args.push(&value);
                }
                restore.push(DesktopCommand::new(write, args));
            }
            restore.push(kde_notify(notify));
        }
    }
    Ok(ProxySnapshot { restore })
}

fn address(server: &str) -> Result<(String, u16)> {
    let text = if server.contains("://") {
        server.to_owned()
    } else {
        format!("http://{server}")
    };
    let url = url::Url::parse(&text).context("代理地址无效")?;
    ensure!(
        ["http", "https", "socks", "socks5", "socks5h"].contains(&url.scheme()),
        "代理协议无效"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "系统代理不能使用此入站的认证信息；请选择无认证的本地入站"
    );
    let host = url
        .host_str()
        .context("代理缺少地址")?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = url.port_or_known_default().context("代理缺少端口")?;
    ensure!(port > 0, "代理端口不能为 0");
    Ok((host, port))
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn variant_string(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn kde_notify(program: &Path) -> DesktopCommand {
    // KIO Scheduler listens for this signal and reparses its cached settings.
    DesktopCommand::new(
        program,
        [
            "--session",
            "--type=signal",
            "/KIO/Scheduler",
            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
            "string:",
        ],
    )
}

fn enable_commands(backend: &Backend, server: &str, protocol: &str) -> Result<Vec<DesktopCommand>> {
    let (host, port) = address(server)?;
    let protocol = protocol.to_lowercase();
    let http = matches!(protocol.as_str(), "http" | "mixed");
    let socks = matches!(protocol.as_str(), "socks" | "socks5" | "mixed");
    ensure!(http || socks, "不支持的系统代理协议: {protocol}");
    let port = port.to_string();
    let endpoint = host_port(&host, port.parse()?);
    let mut commands = Vec::new();
    match backend {
        Backend::Gnome { settings } => {
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host
            };
            for (kind, enabled) in [("http", http), ("https", http), ("socks", socks)] {
                let schema = format!("{GNOME_PROXY}.{kind}");
                let value = variant_string(if enabled { &host } else { "" });
                commands.push(DesktopCommand::new(
                    settings,
                    ["set", &schema, "host", &value],
                ));
                commands.push(DesktopCommand::new(
                    settings,
                    ["set", &schema, "port", if enabled { &port } else { "0" }],
                ));
            }
            commands.push(DesktopCommand::new(
                settings,
                [
                    "set",
                    "org.gnome.system.proxy.http",
                    "use-authentication",
                    "false",
                ],
            ));
            commands.push(DesktopCommand::new(
                settings,
                ["set", GNOME_PROXY, "use-same-proxy", "false"],
            ));
            commands.push(DesktopCommand::new(
                settings,
                [
                    "set",
                    GNOME_PROXY,
                    "ignore-hosts",
                    "['localhost', '127.0.0.1', '::1']",
                ],
            ));
            // Enable after endpoints have been written, avoiding half-configured proxy use.
            commands.push(DesktopCommand::new(
                settings,
                ["set", GNOME_PROXY, "mode", "'manual'"],
            ));
        }
        Backend::Kde { write, notify, .. } => {
            for (key, value) in [
                (
                    "httpProxy",
                    if http {
                        format!("http://{endpoint}")
                    } else {
                        String::new()
                    },
                ),
                (
                    "httpsProxy",
                    if http {
                        format!("http://{endpoint}")
                    } else {
                        String::new()
                    },
                ),
                (
                    "socksProxy",
                    if socks {
                        format!("socks://{endpoint}")
                    } else {
                        String::new()
                    },
                ),
                ("NoProxyFor", "localhost,127.0.0.1,::1".to_owned()),
                ("ReversedException", "false".to_owned()),
                ("ProxyType", "1".to_owned()),
            ] {
                commands.push(DesktopCommand::new(
                    write,
                    [
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        key,
                        &value,
                    ],
                ));
            }
            commands.push(kde_notify(notify));
        }
    }
    Ok(commands)
}

pub fn enable_proxy(server: &str, protocol: &str) -> Result<ProxySnapshot> {
    let backend = backend()?;
    enable_proxy_for(&backend, server, protocol)
}

/// Read back every field Chromium uses, without changing the desktop.
pub fn verify_proxy(server: &str, protocol: &str) -> Result<bool> {
    let backend = backend()?;
    for command in enable_commands(&backend, server, protocol)? {
        let verification = match &backend {
            Backend::Gnome { settings } => Some((
                DesktopCommand::new(settings, ["get", &command.args[1], &command.args[2]]),
                command.args[3].as_str(),
            )),
            Backend::Kde { read, write, .. } if command.program == *write => Some((
                DesktopCommand::new(read, &command.args[..6]),
                command.args[6].as_str(),
            )),
            Backend::Kde { .. } => None,
        };
        if let Some((read, expected)) = verification
            && read.run()? != expected
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn enable_proxy_for(backend: &Backend, server: &str, protocol: &str) -> Result<ProxySnapshot> {
    let commands = enable_commands(backend, server, protocol)?;
    let snapshot = capture(backend)?;
    let applied = (|| -> Result<()> {
        for command in &commands {
            command.run()?;
        }
        for command in &commands {
            let verification = match backend {
                Backend::Gnome { settings } => Some((
                    DesktopCommand::new(settings, ["get", &command.args[1], &command.args[2]]),
                    command.args[3].as_str(),
                )),
                Backend::Kde { read, write, .. } if command.program == *write => Some((
                    DesktopCommand::new(read, &command.args[..6]),
                    command.args[6].as_str(),
                )),
                Backend::Kde { .. } => None,
            };
            if let Some((read, expected)) = verification {
                ensure!(
                    read.run()? == expected,
                    "系统代理设置未生效，请检查桌面设置权限"
                );
            }
        }
        Ok(())
    })();
    if let Err(error) = applied {
        return match snapshot.restore() {
            Ok(()) => Err(error),
            Err(restore) => Err(error.context(restore.to_string())),
        };
    }
    Ok(snapshot)
}

pub fn disable_proxy() -> Result<()> {
    match backend()? {
        Backend::Gnome { settings } => {
            DesktopCommand::new(settings, ["set", GNOME_PROXY, "mode", "'none'"]).run()?;
        }
        Backend::Kde { write, notify, .. } => {
            DesktopCommand::new(
                write,
                [
                    "--file",
                    "kioslaverc",
                    "--group",
                    "Proxy Settings",
                    "--key",
                    "ProxyType",
                    "0",
                ],
            )
            .run()?;
            kde_notify(&notify).run()?;
        }
    }
    Ok(())
}

fn read_session_proxy() -> Result<Option<String>> {
    match backend()? {
        Backend::Gnome { settings } => {
            if DesktopCommand::new(&settings, ["get", GNOME_PROXY, "mode"]).run()? != "'manual'" {
                return Ok(None);
            }
            for (kind, scheme) in [("http", "http"), ("socks", "socks5")] {
                let schema = format!("{GNOME_PROXY}.{kind}");
                let host = DesktopCommand::new(&settings, ["get", &schema, "host"]).run()?;
                let host = host.trim_matches(['\'', '"', '[', ']']);
                let port = DesktopCommand::new(&settings, ["get", &schema, "port"])
                    .run()?
                    .parse::<u16>()
                    .unwrap_or_default();
                if !host.is_empty() && port != 0 {
                    return Ok(Some(format!("{scheme}://{}", host_port(host, port))));
                }
            }
        }
        Backend::Kde { read, .. } => {
            if DesktopCommand::new(
                &read,
                [
                    "--file",
                    "kioslaverc",
                    "--group",
                    "Proxy Settings",
                    "--key",
                    "ProxyType",
                ],
            )
            .run()?
                != "1"
            {
                return Ok(None);
            }
            for key in ["httpProxy", "socksProxy"] {
                let value = DesktopCommand::new(
                    &read,
                    [
                        "--file",
                        "kioslaverc",
                        "--group",
                        "Proxy Settings",
                        "--key",
                        key,
                    ],
                )
                .run()?;
                let normalized = value.trim().replace(' ', ":");
                if !normalized.is_empty() {
                    return Ok(Some(normalized.replacen("socks://", "socks5://", 1)));
                }
            }
        }
    }
    Ok(None)
}

pub fn session_proxy() -> Option<String> {
    read_session_proxy().ok().flatten()
}

fn desktop_entry(exe: &Path, autostart: bool) -> Result<String> {
    let path = exe.to_str().context("程序路径不是 UTF-8")?;
    ensure!(
        !path.contains(['\r', '\n', '=']),
        "桌面启动器路径不能包含换行或等号"
    );
    let mut quoted = String::new();
    for ch in path.chars() {
        match ch {
            // Desktop Entry strings are unescaped before Exec argument parsing.
            '\\' => quoted.push_str("\\\\\\\\"),
            '"' | '`' | '$' => {
                quoted.push_str("\\\\");
                quoted.push(ch);
            }
            '%' => quoted.push_str("%%"),
            _ => quoted.push(ch),
        }
    }
    // GIO validates the executable before expanding %% field codes. Passing a
    // percent-containing path to env keeps that validation and actual launch valid.
    let command = if path.contains('%') {
        format!("/usr/bin/env \"{quoted}\"")
    } else {
        format!("\"{quoted}\"")
    };
    let mut text = format!(
        "[Desktop Entry]\nType=Application\nName=AeroBox\nComment=Native sing-box manager for Wayland\nComment[zh_CN]=原生 Wayland sing-box 管理器\nExec={command}\nIcon={APP_ID}\nTerminal=false\nCategories=Network;Settings;\nStartupNotify=true\n"
    );
    if autostart {
        text.push_str("X-GNOME-Autostart-enabled=true\n");
    }
    Ok(text)
}

pub fn set_autostart(enabled: bool) -> Result<()> {
    let path = config_home()?
        .join("autostart")
        .join(format!("{APP_ID}.desktop"));
    if !enabled {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        return Ok(());
    }
    let exe = env::current_exe()?.canonicalize()?;
    atomic_write(&path, desktop_entry(&exe, true)?.as_bytes(), 0o600)
}

pub fn autostart_enabled() -> bool {
    config_home().is_ok_and(|dir| {
        dir.join("autostart")
            .join(format!("{APP_ID}.desktop"))
            .is_file()
    })
}

pub fn install_desktop(prefix: &Path) -> Result<()> {
    let prefix = if prefix.is_absolute() {
        prefix.to_owned()
    } else {
        env::current_dir()?.join(prefix)
    };
    let exe = prefix.join("bin/AeroBox");
    let desktop = prefix
        .join("share/applications")
        .join(format!("{APP_ID}.desktop"));
    atomic_write(&desktop, desktop_entry(&exe, false)?.as_bytes(), 0o644)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_detection_does_not_modify_unrelated_gsettings() {
        assert_eq!(desktop_kind("ubuntu:GNOME"), Some("gnome"));
        assert_eq!(desktop_kind("KDE"), Some("kde"));
        assert_eq!(desktop_kind("sway"), None);
        assert_eq!(desktop_kind("Hyprland"), None);
    }

    #[test]
    fn proxy_commands_are_ordered_and_handle_ipv6() {
        let backend = Backend::Gnome {
            settings: PathBuf::from("gsettings"),
        };
        let cmds = enable_commands(&backend, "[::1]:2080", "mixed").unwrap();
        assert_eq!(cmds[0].args.last().unwrap(), "'[::1]'");
        assert_eq!(
            cmds.last().unwrap().args,
            ["set", GNOME_PROXY, "mode", "'manual'"]
        );
        assert!(enable_commands(&backend, "127.0.0.1:0", "http").is_err());
        assert!(enable_commands(&backend, "http://user:pass@localhost:2080", "http").is_err());
        assert!(enable_commands(&backend, "localhost:2080", "unknown").is_err());
    }

    #[test]
    fn system_proxy_checks_readback_and_restores_when_writes_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("gsettings-test");
        let state_path = program.with_extension("json");
        let initial: serde_json::Value = gsettings_keys()
            .iter()
            .map(|(schema, key)| (format!("{schema}/{key}"), serde_json::json!("old-value")))
            .collect();
        fs::write(&state_path, serde_json::to_vec(&initial).unwrap()).unwrap();
        fs::write(&program, "#!/usr/bin/python3\nimport sys,json\nfrom pathlib import Path\np=Path(__file__).with_suffix('.json')\ns=json.loads(p.read_text())\nkey=sys.argv[2]+'/'+sys.argv[3]\nif sys.argv[1]=='get': print(s[key])\nelif not (Path(__file__).with_suffix('.blocked').exists() and sys.argv[3]=='mode' and sys.argv[4]==\"'manual'\"):\n s[key]=sys.argv[4];p.write_text(json.dumps(s))\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let backend = Backend::Gnome {
            settings: program.clone(),
        };
        let snapshot = enable_proxy_for(&backend, "127.0.0.1:2080", "mixed").unwrap();
        snapshot.restore().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&state_path).unwrap()).unwrap(),
            initial
        );
        fs::write(program.with_extension("blocked"), "").unwrap();
        assert!(
            enable_proxy_for(&backend, "127.0.0.1:2080", "mixed")
                .unwrap_err()
                .to_string()
                .contains("未生效")
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&state_path).unwrap()).unwrap(),
            initial
        );
    }

    #[test]
    fn desktop_entry_keeps_paths_quoted_and_escapes_field_codes() {
        let entry = desktop_entry(Path::new("/tmp/a b/100%/$`\"\\/AeroBox"), false).unwrap();
        assert!(
            entry.contains("Exec=/usr/bin/env \"/tmp/a b/100%%/\\\\$\\\\`\\\\\"\\\\\\\\/AeroBox\"")
        );
        assert!(entry.lines().any(|line| line == "Name=AeroBox"));
        assert!(
            entry
                .lines()
                .any(|line| line == "Icon=io.github.imengying.AeroBoxForLinux")
        );
        assert!(desktop_entry(Path::new("/tmp/new\nline/AeroBox"), false).is_err());
    }

    #[test]
    fn command_timeout_reaps_child_without_changing_desktop() {
        let start = Instant::now();
        let args = ["5".to_owned()];
        assert!(
            run_with_timeout(Path::new("/bin/sleep"), &args, Duration::from_millis(30)).is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn installed_desktop_launches_executable_under_quoted_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let prefix = temp.path().join("space $`\"\\ 100% prefix");
        let bin = prefix.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("AeroBox");
        fs::write(
            &exe,
            "#!/bin/sh\nprintf '%s' \"$0\" > \"$(dirname \"$0\")/invoked\"\n",
        )
        .unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        install_desktop(&prefix).unwrap();
        let file = prefix
            .join("share/applications")
            .join(format!("{APP_ID}.desktop"));
        let gio = executable(&["gio"]).expect("GTK installs the gio desktop launcher");
        DesktopCommand::new(gio, ["launch", file.to_str().unwrap()])
            .run()
            .unwrap();
        let marker = bin.join("invoked");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !marker.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::read_to_string(marker).unwrap(), exe.to_string_lossy());
    }
}
