#!/bin/sh
set -eu
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_prefix=${PREFIX:-"$HOME/.local"}
mkdir -p "$install_prefix/bin"
# Replace atomically so installing an update also works while AeroBox is running.
stage_binary=$(mktemp "$install_prefix/bin/.AeroBox.XXXXXX")
trap 'rm -f "$stage_binary"' EXIT
trap 'exit 1' HUP INT TERM
install -m755 "$package_dir/AeroBox" "$stage_binary"
mv -f "$stage_binary" "$install_prefix/bin/AeroBox"
install -Dm644 "$package_dir/io.github.imengying.AeroBoxForLinux.svg" "$install_prefix/share/icons/hicolor/scalable/apps/io.github.imengying.AeroBoxForLinux.svg"
# Absolute Exec also works when ~/.local/bin is not in the graphical session PATH.
"$install_prefix/bin/AeroBox" --install-desktop "$install_prefix"
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database "$install_prefix/share/applications" || true; fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then gtk-update-icon-cache -q -f -t "$install_prefix/share/icons/hicolor" || true; fi
printf 'Installed: %s/bin/AeroBox\nLaunch AeroBox from your application menu.\n' "$install_prefix"
