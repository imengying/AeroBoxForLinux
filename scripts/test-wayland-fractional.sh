#!/bin/sh
# Sway provides wp_fractional_scale_v1; Weston headless only accepts integers.
set -eu
binary=$1
output_dir=$2
rm -f "$output_dir"/*.png
rm -f "$output_dir/desktop-windows.json" "$output_dir/desktop-launch.log"
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
export XDG_CONFIG_HOME="$test_dir/config"
export XDG_DATA_HOME="$test_dir/data"
export XDG_CACHE_HOME="$test_dir/cache"
cp "$binary" "$test_dir/AeroBox"
chmod 755 "$test_dir/AeroBox"
cargo xtask desktop-prepare "$test_dir"
test_width=${AEROBOX_TEST_WIDTH:-1400}
case "$test_width" in 1400|1920) ;; *) printf '%s\n' 'AEROBOX_TEST_WIDTH must be 1400 or 1920' >&2; exit 1 ;; esac
cat > "$test_dir/sway.config" <<CONFIG
xwayland disable
output * bg #f4f5f8 solid_color
output HEADLESS-1 mode $((test_width * 5 / 4))x1250 scale 1.25
default_border none
default_floating_border none
for_window [app_id=".*"] floating enable
focus_follows_mouse no
CONFIG
cat > "$test_dir/session.sh" <<'SESSION'
set -eu
test_dir=$1
export XDG_RUNTIME_DIR="$test_dir/runtime"
export WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_LIBINPUT_NO_DEVICES=1
export GDK_BACKEND=wayland GSK_RENDERER=cairo G_DEBUG=fatal-criticals GTK_A11Y=none GTK_ANIMATIONS=0
export AEROBOX_TEST_SCALE=1.25
export XDG_CURRENT_DESKTOP=GNOME
gsettings set org.gnome.desktop.wm.preferences button-layout ':close'
gsettings set org.gnome.desktop.interface font-name 'Sans 11'
gsettings set org.gnome.desktop.interface text-scaling-factor 1.0
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
"$test_dir/AeroBox" --data-dir "$test_dir/data" --smoke-test "$test_dir/screenshots/home.png"
test -s "$test_dir/screenshots/home.png"
"$test_dir/xtask" desktop "$test_dir" > "$test_dir/screenshots/desktop-launch.log" 2>&1 || { cat "$test_dir/screenshots/desktop-launch.log"; exit 1; }
SESSION
# A headless compositor still refuses to run as root. Drop privileges inside
# this disposable directory; all application and D-Bus state stays isolated.
if [ "$(id -u)" = 0 ]; then
  chown -R nobody "$test_dir"
  runuser -u nobody -- dbus-run-session -- sh "$test_dir/session.sh" "$test_dir"
else
  dbus-run-session -- sh "$test_dir/session.sh" "$test_dir"
fi
