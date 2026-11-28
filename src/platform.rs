//! GNOME desktop integration. Proxy writes use GSettings and restore only the
//! keys changed by AeroBox.

use anyhow::{Context, Result, bail, ensure};
use std::{
    env, fs,
    io::{Read, Seek, SeekFrom},
    num::NonZeroU16,
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

/// A snapshot contains only the keys this application changed.
#[derive(Debug)]
pub struct ProxySnapshot {
    restore: Vec<DesktopCommand>,
    verify: Vec<(DesktopCommand, String)>,
}

impl ProxySnapshot {
    pub fn restore(&self) -> Result<()> {
        let mut errors = Vec::new();
        for command in &self.restore {
            if let Err(error) = command.run() {
                errors.push(error.to_string());
            }
        }
        // gsettings can exit successfully even when dconf could not reach the
        // session bus. Do not discard the snapshot until the saved values are
        // visible again.
        for (command, expected) in &self.verify {
            match command.run() {
                Ok(actual) if &actual == expected => {}
                Ok(_) => {
                    errors.push("系统代理恢复未生效，请检查桌面会话后重试".into());
                    break;
                }
                Err(error) => {
                    errors.push(error.to_string());
                    break;
                }
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

fn capture(settings: &Path) -> Result<ProxySnapshot> {
    let mut restore = Vec::new();
    let mut verify = Vec::new();
    for (schema, key) in gsettings_keys() {
        let read = DesktopCommand::new(settings, ["get", schema, key]);
        let value = read.run()?;
        restore.push(DesktopCommand::new(settings, ["set", schema, key, &value]));
        verify.push((read, value));
    }
    Ok(ProxySnapshot { restore, verify })
}

fn enable_commands(settings: &Path, port: NonZeroU16) -> Vec<DesktopCommand> {
    let port = port.to_string();
    let mut commands = Vec::new();
    for kind in ["http", "https", "socks"] {
        let schema = format!("{GNOME_PROXY}.{kind}");
        commands.push(DesktopCommand::new(
            settings,
            ["set", &schema, "host", "'127.0.0.1'"],
        ));
        commands.push(DesktopCommand::new(
            settings,
            ["set", &schema, "port", &port],
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
    commands
}

pub fn enable_proxy(port: NonZeroU16) -> Result<ProxySnapshot> {
    enable_proxy_with(Path::new("gsettings"), port)
}

/// Read back every field Chromium uses, without changing the desktop.
pub fn verify_proxy(port: NonZeroU16) -> Result<bool> {
    verify_commands(&enable_commands(Path::new("gsettings"), port))
}

fn verify_commands(commands: &[DesktopCommand]) -> Result<bool> {
    for command in commands {
        let read = DesktopCommand::new(
            &command.program,
            ["get", &command.args[1], &command.args[2]],
        );
        if read.run()? != command.args[3] {
            return Ok(false);
        }
    }
    Ok(true)
}

fn enable_proxy_with(settings: &Path, port: NonZeroU16) -> Result<ProxySnapshot> {
    let commands = enable_commands(settings, port);
    let snapshot = capture(settings)?;
    let applied = (|| -> Result<()> {
        for command in &commands {
            command.run()?;
        }
        ensure!(
            verify_commands(&commands)?,
            "系统代理设置未生效，请检查桌面设置权限"
        );
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
        "[Desktop Entry]\nType=Application\nName=AeroBox\nComment=Native proxy client for GNOME\nComment[zh_CN]=GNOME 代理客户端\nExec={command}\nIcon={APP_ID}\nTerminal=false\nCategories=Network;Settings;\nOnlyShowIn=GNOME;\nStartupNotify=true\nStartupWMClass={APP_ID}\nSingleMainWindow=true\n"
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
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn proxy_commands_configure_all_protocols_before_enabling() {
        let cmds = enable_commands(Path::new("gsettings"), NonZeroU16::new(2080).unwrap());
        for (index, kind) in ["http", "https", "socks"].iter().enumerate() {
            assert_eq!(
                cmds[index * 2].args,
                [
                    "set",
                    &format!("{GNOME_PROXY}.{kind}"),
                    "host",
                    "'127.0.0.1'"
                ]
            );
            assert_eq!(cmds[index * 2 + 1].args.last().unwrap(), "2080");
        }
        assert_eq!(
            cmds.last().unwrap().args,
            ["set", GNOME_PROXY, "mode", "'manual'"]
        );
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
        fs::write(&program, r#"#!/usr/bin/python3
import sys,json
from pathlib import Path
p=Path(__file__).with_suffix('.json')
s=json.loads(p.read_text())
key=sys.argv[2]+'/'+sys.argv[3]
if sys.argv[1]=='get': print(s[key])
elif not ((Path(__file__).with_suffix('.blocked').exists() and sys.argv[3]=='mode' and sys.argv[4]=="'manual'") or (Path(__file__).with_suffix('.restore-blocked').exists() and sys.argv[4]=='old-value')):
 s[key]=sys.argv[4];p.write_text(json.dumps(s))
"#).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let snapshot = enable_proxy_with(&program, NonZeroU16::new(2080).unwrap()).unwrap();
        let blocked = program.with_extension("restore-blocked");
        fs::write(&blocked, "").unwrap();
        assert!(
            snapshot
                .restore()
                .unwrap_err()
                .to_string()
                .contains("未生效")
        );
        let actual: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(actual["org.gnome.system.proxy/mode"], "'manual'");
        // The same snapshot remains usable when the desktop starts accepting writes.
        fs::remove_file(blocked).unwrap();
        snapshot.restore().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&state_path).unwrap()).unwrap(),
            initial
        );
        fs::write(program.with_extension("blocked"), "").unwrap();
        assert!(
            enable_proxy_with(&program, NonZeroU16::new(2080).unwrap())
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
        assert!(entry.lines().any(|line| line == "OnlyShowIn=GNOME;"));
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
        DesktopCommand::new("gio", ["launch", file.to_str().unwrap()])
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
