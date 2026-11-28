use crate::{process, root, target};
use anyhow::{Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, process::Command};

pub fn digest(path: &Path) -> Result<String> {
    use std::fmt::Write;
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(fs::read(path)?) {
        write!(hex, "{byte:02x}").unwrap();
    }
    Ok(hex)
}

#[derive(Deserialize)]
struct Hashes {
    original: Option<String>,
    patched: String,
}

#[derive(Deserialize)]
struct Upstream {
    module: String,
    version: String,
    files: BTreeMap<String, Hashes>,
}

fn copy(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let to = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy(&entry.path(), &to)?;
        } else {
            // Creating the file here does not inherit Go's read-only cache mode.
            fs::write(to, fs::read(entry.path())?)?;
        }
    }
    Ok(())
}

pub fn build() -> Result<()> {
    let here = root().join("vendor/shoes/tests/fixtures/tls12-renegotiation-peer");
    let meta: Upstream = serde_json::from_slice(&fs::read(here.join("upstream.json"))?)?;
    let go = || {
        let mut command = Command::new("go");
        command.current_dir(&here).envs([
            ("CGO_ENABLED", "0"),
            ("GOMAXPROCS", "1"),
            ("GOMEMLIMIT", "256MiB"),
            ("GOTOOLCHAIN", "local"),
            ("GOPROXY", "off"),
        ]);
        command
    };
    let cache = process::output(go().args(["env", "GOMODCACHE"]))?;
    let source = Path::new(cache.trim()).join(format!("{}@{}", meta.module, meta.version));
    for (name, hashes) in &meta.files {
        if let Some(expected) = &hashes.original {
            ensure!(
                &digest(&source.join(name))? == expected,
                "Upstream source changed: {name}"
            );
        }
    }
    let directory = tempfile::tempdir()?;
    let staged = directory.path().join("source");
    copy(&source, &staged)?;
    process::run(
        Command::new("patch")
            .current_dir(&staged)
            .args(["--batch", "--forward", "-p1", "-i"])
            .arg(here.join("utls-fixture.patch")),
    )?;
    for (name, hashes) in &meta.files {
        ensure!(
            digest(&staged.join(name))? == hashes.patched,
            "Patched reference differs: {name}"
        );
    }
    let modfile = directory.path().join("go.mod");
    fs::copy(here.join("go.mod"), &modfile)?;
    fs::copy(here.join("go.sum"), modfile.with_extension("sum"))?;
    process::run(
        go().args(["mod", "edit"])
            .arg(format!("-modfile={}", modfile.display()))
            .arg(format!("-replace={}={}", meta.module, staged.display())),
    )?;
    let output = target().join("protocol-peers/tls12-renegotiation-peer");
    fs::create_dir_all(output.parent().unwrap())?;
    process::run(
        go().arg("build")
            .arg(format!("-modfile={}", modfile.display()))
            .args(["-mod=readonly", "-p=1", "-trimpath", "-o"])
            .arg(&output)
            .arg("."),
    )?;
    println!("{}", output.display());
    Ok(())
}
