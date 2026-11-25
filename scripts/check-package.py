#!/usr/bin/env python3
"""Check the release archive and install/uninstall it in an isolated prefix."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib

root = Path(__file__).resolve().parent.parent
version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
name = "AeroBoxForLinux-linux-amd64"
app_id = "io.github.imengying.AeroBoxForLinux"
expected = {
    "AeroBox", "install.sh", "uninstall.sh", f"{app_id}.png",
    "README.md", "LICENSE", "THIRD_PARTY.md", "docs/protocols.md",
    "resources/rules/README.md", "resources/rules/sing-geoip-LICENSE",
    "resources/rules/sing-geosite-LICENSE",
}
expected.update(str(path.relative_to(root)) for path in (root / "licenses").rglob("*") if path.is_file())

with tempfile.TemporaryDirectory(prefix="aerobox-package-") as temporary:
    directory = Path(temporary)
    with tarfile.open(sys.argv[1], "r:gz") as archive:
        members = archive.getmembers()
        assert all(member.isfile() or member.isdir() for member in members), "Unexpected archive entry type"
        actual = {member.name for member in members if member.isfile()}
        allowed = {f"{name}/{path}" for path in expected}
        assert actual == allowed, f"Missing: {allowed - actual}; unexpected: {actual - allowed}"
        assert len(actual) == sum(member.isfile() for member in members), "Duplicate archive entries"
        archive.extractall(directory, filter="data")
    package = directory / name
    binary = package / "AeroBox"
    result = subprocess.run([binary, "--version"], text=True, capture_output=True, check=True, timeout=10)
    assert re.match(rf"AeroBox v?{re.escape(version)} ·", result.stdout), result.stdout
    result = subprocess.run(
        [binary, "--smoke-test", str(directory / "unused.png")],
        text=True, capture_output=True, timeout=10,
    )
    assert result.returncode != 0 and "未知参数 --smoke-test" in result.stderr, "Release includes UI test entry point"

    prefix = directory / "install with spaces"
    config = directory / "config"
    env = dict(os.environ, PREFIX=str(prefix), XDG_CONFIG_HOME=str(config),
               XDG_DATA_HOME=str(prefix / "share"), XDG_CACHE_HOME=str(directory / "cache"))
    subprocess.run([package / "install.sh"], env=env, check=True, timeout=15)
    installed = prefix / "bin/AeroBox"
    desktop = prefix / "share/applications" / f"{app_id}.desktop"
    icon = prefix / "share/icons/hicolor/512x512/apps" / f"{app_id}.png"
    assert installed.read_bytes() == binary.read_bytes(), "Installer changed the executable"
    assert f'Exec="{installed}"' in desktop.read_text(), "Launcher does not use the installed path"
    assert f"StartupWMClass={app_id}" in desktop.read_text(), "Launcher identity differs from the window"
    assert icon.read_bytes() == (package / f"{app_id}.png").read_bytes(), "Missing installed icon"

    state = config / "AeroBoxForLinux/state.json"
    state.parent.mkdir(parents=True)
    state.write_text("preserve user data\n")
    subprocess.run([package / "uninstall.sh"], env=env, check=True, timeout=15)
    assert not any(path.exists() for path in (installed, desktop, icon)), "Uninstall left application files"
    assert state.read_text() == "preserve user data\n", "Uninstall removed user data"

print(f"Release {version}: archive contents, production executable, install and uninstall passed")
