#!/usr/bin/env python3
"""Check installed launchers against actual windows in the isolated Sway session."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

directory = Path(sys.argv[1]).resolve()
prefix = directory / "installed with spaces"
env = dict(os.environ, PREFIX=str(prefix), XDG_DATA_HOME=str(prefix / "share"))
app_id = "io.github.imengying.AeroBoxForLinux"
desktop = prefix / "share/applications" / f"{app_id}.desktop"
binary = prefix / "bin/AeroBox"


def run(*args):
    # A launched GUI inherits stdout and outlives `gio launch`; a pipe would
    # wait for the whole GUI to exit even after the launcher has returned.
    with tempfile.TemporaryFile(mode="w+") as output:
        subprocess.run(args, env=env, stdout=output, text=True, timeout=8, check=True)
        output.seek(0)
        return output.read()


def windows():
    def walk(node):
        if node.get("app_id"):
            yield {key: node[key] for key in ("id", "pid", "app_id")}
        for child in node.get("nodes", []) + node.get("floating_nodes", []):
            yield from walk(child)

    return list(walk(json.loads(run("swaymsg", "-t", "get_tree", "-r"))))


def wait_for(check):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError(f"desktop window check timed out: {windows()}")


def launch():
    run("gio", "launch", str(desktop))
    current = wait_for(windows)
    assert len(current) == 1 and current[0]["app_id"] == desktop.stem, current
    return current[0]


def close(window):
    run("swaymsg", f"[con_id={window['id']}]", "kill")
    wait_for(lambda: not windows())
    wait_for(lambda: "false" in run(
        "gdbus", "call", "--session", "--dest", "org.freedesktop.DBus",
        "--object-path", "/org/freedesktop/DBus",
        "--method", "org.freedesktop.DBus.NameHasOwner", app_id,
    ))


run(str(directory / "install.sh"))
assert f"StartupWMClass={app_id}" in desktop.read_text()
assert "SingleMainWindow=true" in desktop.read_text()
log = directory / "screenshots/desktop-launch.log"
with log.open("w") as output:
    # Capture child output too: GIO launches the app asynchronously.
    os.dup2(output.fileno(), sys.stderr.fileno())
    first = launch()
    # The second executable must forward activation and exit, keeping the
    # original window and process. Repeat through the installed launcher too.
    run(str(binary))
    run("gio", "launch", str(desktop))
    for _ in range(10):
        assert windows() == [first], windows()
        time.sleep(0.05)
    close(first)

    # Recovery happens before GtkApplication registration and must use the
    # same desktop ID as ordinary windows, even in a fresh process.
    state = Path(env["XDG_CONFIG_HOME"]) / "AeroBoxForLinux/state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    original = b"invalid-state-for-desktop-regression"
    state.write_bytes(original)
    recovery = launch()
    close(recovery)
    assert state.read_bytes() == original

result = {"desktop_id": desktop.stem, "main_window": first, "recovery_window": recovery,
          "repeated_launch": "reused original window and process"}
(directory / "screenshots/desktop-windows.json").write_text(json.dumps(result, indent=2) + "\n")
print("Installed desktop ID, repeated launch and recovery window checks passed.")
