#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
duration=${1:-60}
case "$duration" in ''|*[!0-9]*) printf 'Usage: %s [seconds]\n' "$0" >&2; exit 2 ;; esac
if [ "$duration" -lt 1 ] || [ "$duration" -gt 3600 ]; then
    printf 'Duration must be between 1 and 3600 seconds\n' >&2
    exit 2
fi
fuzz_target=${CARGO_TARGET_DIR:-target}/protocol-fuzz
mkdir -p "$fuzz_target"
fuzz_target=$(cd "$fuzz_target" && pwd)
fuzz_host=$(rustc -vV | sed -n 's/^host: //p')
# An explicit target keeps coverage instrumentation out of build scripts.
# Stable Rust supports LLVM coverage instrumentation; sanitizers are not enabled here.
RUSTFLAGS="${RUSTFLAGS:-} -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares -Cdebug-assertions -Coverflow-checks -Ccodegen-units=1" \
    cargo build --manifest-path tools/xtask/fuzz/Cargo.toml --locked \
        --release --target "$fuzz_host" --target-dir "$fuzz_target"
mkdir -p "$fuzz_target/corpus" "$fuzz_target/artifacts"
"$fuzz_target/$fuzz_host/release/vision" -max_total_time="$duration" -timeout=5 \
    -rss_limit_mb=1024 -max_len=4096 -artifact_prefix="$fuzz_target/artifacts/" "$fuzz_target/corpus"
