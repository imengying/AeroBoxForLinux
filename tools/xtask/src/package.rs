use crate::{APP_ID, process, root, target};
use anyhow::{Result, ensure};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const NAME: &str = "AeroBoxForLinux-linux-amd64";

fn files() -> [String; 4] {
    [
        "AeroBox".into(),
        "install.sh".into(),
        "uninstall.sh".into(),
        format!("{APP_ID}.png"),
    ]
}

pub fn create() -> Result<PathBuf> {
    ensure!(
        std::env::consts::ARCH == "x86_64",
        "Release packaging requires x86_64"
    );
    let output = target().join("packages");
    fs::create_dir_all(&output)?;
    let path = output.join(format!("{NAME}.tar.gz"));
    let temporary = tempfile::NamedTempFile::new_in(&output)?;
    let mut archive =
        tar::Builder::new(GzEncoder::new(temporary.reopen()?, Compression::default()));
    for name in files() {
        let source = match name.as_str() {
            "AeroBox" => target().join("release/AeroBox"),
            "install.sh" | "uninstall.sh" => root().join("scripts").join(&name),
            _ => root().join("resources/icons").join(&name),
        };
        let mut file = File::open(&source)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(file.metadata()?.len());
        header.set_mode(if name.ends_with(".png") { 0o644 } else { 0o755 });
        header.set_cksum();
        archive.append_data(&mut header, Path::new(NAME).join(&name), &mut file)?;
    }
    archive.into_inner()?.finish()?.sync_all()?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))?;
    temporary.persist(&path)?;
    Ok(path)
}

pub fn check(path: &Path) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut archive = tar::Archive::new(GzDecoder::new(File::open(path)?));
    let mut expected: BTreeSet<_> = files()
        .map(|name| Path::new(NAME).join(name))
        .into_iter()
        .collect();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if entry.header().entry_type().is_dir() {
            ensure!(
                path == Path::new(NAME),
                "Unexpected archive directory: {}",
                path.display()
            );
            continue;
        }
        ensure!(
            entry.header().entry_type().is_file() && expected.remove(&path),
            "Unexpected or duplicate archive entry: {}",
            path.display()
        );
        ensure!(entry.unpack_in(directory.path())?, "Invalid archive path");
    }
    ensure!(expected.is_empty(), "Missing archive files: {expected:?}");
    let manifest: toml::Value = toml::from_str(&fs::read_to_string(root().join("Cargo.toml"))?)?;
    let version = manifest["package"]["version"].as_str().unwrap();
    let package = directory.path().join(NAME);
    let binary = package.join("AeroBox");
    ensure!(
        fs::metadata(&binary)?.permissions().mode() & 0o111 != 0,
        "Binary is not executable"
    );
    let output = process::output(Command::new(&binary).arg("--version"))?;
    ensure!(
        output.starts_with(&format!("AeroBox {version} ·")),
        "Unexpected version: {output}"
    );
    let (status, _, stderr) = process::capture(
        Command::new(&binary)
            .arg("--smoke-test")
            .arg(directory.path().join("unused.png")),
        Duration::from_secs(10),
    )?;
    ensure!(
        !status.success() && stderr.contains("未知参数 --smoke-test"),
        "Release includes UI test entry point"
    );

    let prefix = directory.path().join("install with spaces");
    let config = directory.path().join("config");
    let script = |name| {
        let mut command = Command::new(package.join(name));
        command
            .env("PREFIX", &prefix)
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_DATA_HOME", prefix.join("share"))
            .env("XDG_CACHE_HOME", directory.path().join("cache"));
        command
    };
    process::output(&mut script("install.sh"))?;
    let installed = prefix.join("bin/AeroBox");
    let desktop = prefix.join(format!("share/applications/{APP_ID}.desktop"));
    let icon = prefix.join(format!("share/icons/hicolor/512x512/apps/{APP_ID}.png"));
    ensure!(
        fs::read(&installed)? == fs::read(&binary)?,
        "Installer changed executable"
    );
    let launcher = fs::read_to_string(&desktop)?;
    ensure!(
        launcher.contains(&format!("Exec=\"{}\"", installed.display()))
            && launcher.contains(&format!("StartupWMClass={APP_ID}"))
            && launcher.contains("OnlyShowIn=GNOME;"),
        "Incorrect desktop launcher"
    );
    ensure!(
        fs::read(&icon)? == fs::read(package.join(format!("{APP_ID}.png")))?,
        "Incorrect installed icon"
    );
    let state = config.join("AeroBoxForLinux/state.json");
    fs::create_dir_all(state.parent().unwrap())?;
    fs::write(&state, "preserve user data\n")?;
    process::output(&mut script("uninstall.sh"))?;
    ensure!(
        [installed, desktop, icon].iter().all(|path| !path.exists()),
        "Uninstall left application files"
    );
    ensure!(
        fs::read_to_string(state)? == "preserve user data\n",
        "Uninstall removed user data"
    );
    println!("Release {version}: archive, production executable, install and uninstall passed");
    Ok(())
}
