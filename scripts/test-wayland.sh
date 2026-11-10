#!/bin/sh
set -eu
target_dir=${CARGO_TARGET_DIR:-target}
binary=${1:-"$target_dir/release/AeroBox"}
binary=$(realpath "$binary")
mkdir -p "$target_dir/wayland"
output_dir=$(realpath "$target_dir/wayland")
test_dir=$(mktemp -d)
cleanup() {
  if [ -n "${weston_pid:-}" ]; then
    kill "$weston_pid" 2>/dev/null || true
    wait "$weston_pid" 2>/dev/null || true
  fi
  if [ -f "$test_dir/weston.log" ]; then cp "$test_dir/weston.log" "$output_dir/weston.log"; fi
  rm -rf "$test_dir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
rm -f "$output_dir"/*.png
mkdir -m 700 "$test_dir/runtime"
export XDG_RUNTIME_DIR="$test_dir/runtime"
export XDG_CONFIG_HOME="$test_dir/config"
export XDG_DATA_HOME="$test_dir/data"
export XDG_CACHE_HOME="$test_dir/cache"
export WAYLAND_DISPLAY=aerobox-for-linux-test
export GDK_BACKEND=wayland
export GSK_RENDERER=cairo
export G_DEBUG=fatal-criticals
export GTK_A11Y=none
unset DISPLAY
weston --backend=headless-backend.so --use-pixman --width=1400 --height=1000 --socket="$WAYLAND_DISPLAY" --idle-time=0 --no-config --log="$test_dir/weston.log" &
weston_pid=$!
attempt=0
while [ ! -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ]; do
  attempt=$((attempt+1))
  if [ "$attempt" -ge 50 ]; then cat "$test_dir/weston.log"; exit 1; fi
  sleep 0.1
done
dbus-run-session -- "$binary" --data-dir "$test_dir/data" --smoke-test "$output_dir/overview.png"
test -s "$output_dir/overview.png"
