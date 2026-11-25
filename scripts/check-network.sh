#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
check_target=${CARGO_TARGET_DIR:-target}/protocol-checks
manifest=tools/protocol-checks/Cargo.toml
cargo fmt --manifest-path "$manifest" --check
cargo fmt --manifest-path tools/protocol-checks/fuzz/Cargo.toml --check
cargo clippy --manifest-path "$manifest" --locked --all-targets --target-dir "$check_target" -- -D warnings
cargo test --manifest-path "$manifest" --locked --target-dir "$check_target"
cargo run --manifest-path "$manifest" --locked --target-dir "$check_target" -- tasks
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-bench-network.py
