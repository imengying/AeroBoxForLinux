#!/usr/bin/env python3
"""Build a test-only RFC5746 server from an exact cached uTLS version.
Used by scripts/test-protocols.sh; builds with one Go worker.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import tempfile

here = Path(__file__).resolve().parent
root = here.parents[4]
target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target")).resolve()
meta = json.loads((here / "upstream.json").read_text())
env = os.environ.copy()
env.update(CGO_ENABLED="0", GOMAXPROCS="1", GOMEMLIMIT="256MiB",
           GOTOOLCHAIN="local", GOPROXY="off")
cache = Path(subprocess.check_output(["go", "env", "GOMODCACHE"], env=env, text=True).strip())
source = cache / (meta["module"] + "@" + meta["version"])
dest = target / "reference-utls-renegotiation"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


for name, hashes in meta["files"].items():
    if hashes["original"] is not None:
        assert digest(source / name) == hashes["original"], f"upstream source changed: {name}"
if not dest.exists():
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="utls-patch-", dir=target) as directory:
        staged = Path(directory) / "source"
        shutil.copytree(source, staged)
        # Go's module cache contains read-only directories as well as files.
        # patch creates temporary files beside its inputs, so both must be writable.
        for path in (staged, *staged.rglob("*")):
            path.chmod(0o755 if path.is_dir() else 0o644)
        subprocess.run(["patch", "--batch", "--forward", "-p1", "-i", str(here / "utls-fixture.patch")],
                       cwd=staged, check=True)
        assert all(digest(staged / name) == hashes["patched"] for name, hashes in meta["files"].items()), \
            "patched reference differs from expected hashes"
        staged.rename(dest)
assert all(digest(dest / name) == hashes["patched"] for name, hashes in meta["files"].items()), \
    "reference fork differs; review before replacing"

program = target / "protocol-peers/tls12-renegotiation-peer"
program.parent.mkdir(exist_ok=True, parents=True)
# An alternate module file keeps the source tree unchanged and resolves the
# reference fork correctly even when Cargo outputs live outside this checkout.
with tempfile.TemporaryDirectory(prefix="tls12-peer-", dir=target) as directory:
    modfile = Path(directory) / "go.mod"
    shutil.copyfile(here / "go.mod", modfile)
    shutil.copyfile(here / "go.sum", modfile.with_suffix(".sum"))
    subprocess.run(["go", "mod", "edit", f"-modfile={modfile}",
                    f"-replace={meta['module']}={dest}"], cwd=here, env=env, check=True)
    subprocess.run(["go", "build", f"-modfile={modfile}", "-mod=readonly", "-p=1",
                    "-trimpath", "-o", str(program), "."], cwd=here, env=env, check=True)
print(program)
