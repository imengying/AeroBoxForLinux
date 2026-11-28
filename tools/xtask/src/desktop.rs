use crate::{APP_ID, process, root};
use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

pub fn prepare(directory: &Path) -> Result<()> {
    fs::copy(std::env::current_exe()?, directory.join("xtask"))?;
    fs::copy(
        root().join("scripts/install.sh"),
        directory.join("install.sh"),
    )?;
    fs::copy(
        root().join(format!("resources/icons/{APP_ID}.png")),
        directory.join(format!("{APP_ID}.png")),
    )?;
    Ok(())
}

struct Session {
    prefix: PathBuf,
    desktop: PathBuf,
}

impl Session {
    fn run(&self, program: impl AsRef<std::ffi::OsStr>, args: &[&str]) -> Result<String> {
        process::output(
            Command::new(program)
                .args(args)
                .env("PREFIX", &self.prefix)
                .env("XDG_DATA_HOME", self.prefix.join("share")),
        )
    }

    fn windows(&self) -> Result<Vec<Value>> {
        fn walk(node: &Value, windows: &mut Vec<Value>) {
            if node["app_id"].is_string() {
                windows
                    .push(json!({"id": node["id"], "pid": node["pid"], "app_id": node["app_id"]}));
            }
            for field in ["nodes", "floating_nodes"] {
                if let Some(nodes) = node[field].as_array() {
                    for node in nodes {
                        walk(node, windows);
                    }
                }
            }
        }
        let mut windows = Vec::new();
        walk(
            &serde_json::from_str(&self.run("swaymsg", &["-t", "get_tree", "-r"])?)?,
            &mut windows,
        );
        Ok(windows)
    }

    fn wait(&self, check: impl Fn() -> Result<bool>) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if check()? {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        bail!("Desktop window check timed out: {:?}", self.windows()?)
    }

    fn launch(&self) -> Result<Value> {
        self.run("gio", &["launch", self.desktop.to_str().unwrap()])?;
        self.wait(|| Ok(!self.windows()?.is_empty()))?;
        let windows = self.windows()?;
        ensure!(
            windows.len() == 1 && windows[0]["app_id"] == APP_ID,
            "Incorrect windows: {windows:?}"
        );
        Ok(windows[0].clone())
    }

    fn close(&self, window: &Value) -> Result<()> {
        self.run("swaymsg", &[&format!("[con_id={}]", window["id"]), "kill"])?;
        self.wait(|| Ok(self.windows()?.is_empty()))?;
        self.wait(|| {
            Ok(self
                .run(
                    "gdbus",
                    &[
                        "call",
                        "--session",
                        "--dest",
                        "org.freedesktop.DBus",
                        "--object-path",
                        "/org/freedesktop/DBus",
                        "--method",
                        "org.freedesktop.DBus.NameHasOwner",
                        APP_ID,
                    ],
                )?
                .contains("false"))
        })
    }
}

pub fn check(directory: &Path) -> Result<()> {
    let directory = directory.canonicalize()?;
    let outputs: Value = serde_json::from_str(&fs::read_to_string(
        directory.join("screenshots/outputs.json"),
    )?)?;
    ensure!(
        outputs
            .as_array()
            .unwrap()
            .iter()
            .any(|output| output["active"] == true && output["scale"] == 1.25),
        "Expected an active 1.25 scale output: {outputs}"
    );
    let prefix = directory.join("installed with spaces");
    let session = Session {
        desktop: prefix.join(format!("share/applications/{APP_ID}.desktop")),
        prefix,
    };
    session.run(directory.join("install.sh"), &[])?;
    let launcher = fs::read_to_string(&session.desktop)?;
    ensure!(
        launcher.contains(&format!("StartupWMClass={APP_ID}"))
            && launcher.contains("SingleMainWindow=true"),
        "Incorrect launcher identity"
    );
    let first = session.launch()?;
    session.run(session.prefix.join("bin/AeroBox"), &[])?;
    session.run("gio", &["launch", session.desktop.to_str().unwrap()])?;
    for _ in 0..10 {
        ensure!(
            session.windows()? == [first.clone()],
            "Repeated launch created another window"
        );
        thread::sleep(Duration::from_millis(50));
    }
    session.close(&first)?;
    let state = PathBuf::from(std::env::var_os("XDG_CONFIG_HOME").unwrap())
        .join("AeroBoxForLinux/state.json");
    fs::create_dir_all(state.parent().unwrap())?;
    let original = b"invalid-state-for-desktop-regression";
    fs::write(&state, original)?;
    let recovery = session.launch()?;
    session.close(&recovery)?;
    ensure!(
        fs::read(&state)? == original,
        "Recovery changed the invalid state"
    );
    fs::write(
        directory.join("screenshots/desktop-windows.json"),
        serde_json::to_vec_pretty(
            &json!({"desktop_id": APP_ID, "main_window": first, "recovery_window": recovery, "repeated_launch": "reused original window and process"}),
        )?,
    )?;
    println!("Installed desktop ID, repeated launch and recovery window checks passed.");
    Ok(())
}
