#!/bin/sh
# Sway provides wp_fractional_scale_v1; Weston headless only accepts integers.
set -eu
binary=$1
output_dir=$2
test_dir=$(mktemp -d)
cleanup() {
  if [ -d "$test_dir/screenshots" ]; then
    cp -R "$test_dir/screenshots/." "$output_dir/"
  fi
  rm -rf "$test_dir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir -m 700 "$test_dir/runtime" "$test_dir/screenshots"
export XDG_RUNTIME_DIR="$test_dir/runtime"
cp "$binary" "$test_dir/AeroBox"
chmod 755 "$test_dir/AeroBox"
cat > "$test_dir/sway.config" <<'CONFIG'
xwayland disable
output * bg #f4f5f8 solid_color
output HEADLESS-1 mode 1750x1250 scale 1.25
default_border none
default_floating_border none
for_window [app_id=".*"] floating enable
focus_follows_mouse no
CONFIG
cat > "$test_dir/session.sh" <<'SESSION'
set -eu
test_dir=$1
export XDG_RUNTIME_DIR="$test_dir/runtime"
export XDG_CONFIG_HOME="$test_dir/config"
export XDG_DATA_HOME="$test_dir/data"
export XDG_CACHE_HOME="$test_dir/cache"
export WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_LIBINPUT_NO_DEVICES=1
export GDK_BACKEND=wayland GSK_RENDERER=cairo G_DEBUG=fatal-criticals GTK_A11Y=none
export AEROBOX_TEST_SCALE=1.25
unset DISPLAY WAYLAND_DISPLAY SWAYSOCK
sway --unsupported-gpu --config "$test_dir/sway.config" > "$test_dir/screenshots/sway.log" 2>&1 &
compositor_pid=$!
cleanup_session() {
  kill "$compositor_pid" 2>/dev/null || true
  wait "$compositor_pid" 2>/dev/null || true
}
trap cleanup_session EXIT
trap 'exit 1' HUP INT TERM
attempt=0
while [ -z "${WAYLAND_DISPLAY:-}" ] || [ -z "${SWAYSOCK:-}" ]; do
  for candidate in "$XDG_RUNTIME_DIR"/wayland-*; do
    if [ -S "$candidate" ]; then export WAYLAND_DISPLAY="${candidate##*/}"; break; fi
  done
  for candidate in "$XDG_RUNTIME_DIR"/sway-ipc.*.sock; do
    if [ -S "$candidate" ]; then export SWAYSOCK="$candidate"; break; fi
  done
  attempt=$((attempt+1))
  if [ "$attempt" -ge 100 ]; then cat "$test_dir/screenshots/sway.log"; exit 1; fi
  sleep 0.1
done
swaymsg -t get_outputs -r > "$test_dir/screenshots/outputs.json"
python3 - "$test_dir/screenshots/outputs.json" <<'PY'
import json, sys
outputs = json.load(open(sys.argv[1]))
assert any(o['active'] and o['scale'] == 1.25 for o in outputs), outputs
PY
"$test_dir/AeroBox" --data-dir "$test_dir/data" --smoke-test "$test_dir/screenshots/home.png"
test -s "$test_dir/screenshots/home.png"
SESSION
# A headless compositor still refuses to run as root. Drop privileges inside
# this disposable directory; all application and D-Bus state stays isolated.
if [ "$(id -u)" = 0 ]; then
  chown -R nobody "$test_dir"
  runuser -u nobody -- dbus-run-session -- sh "$test_dir/session.sh" "$test_dir"
else
  dbus-run-session -- sh "$test_dir/session.sh" "$test_dir"
fi
