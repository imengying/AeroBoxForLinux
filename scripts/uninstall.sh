#!/bin/sh
set -eu
install_prefix=${PREFIX:-"$HOME/.local"}
rm -f "$install_prefix/bin/AeroBox" "$install_prefix/share/applications/io.github.imengying.AeroBoxForLinux.desktop" "$install_prefix/share/icons/hicolor/scalable/apps/io.github.imengying.AeroBoxForLinux.svg"
rm -f "$install_prefix/share/icons/hicolor/512x512/apps/io.github.imengying.AeroBoxForLinux.png"
rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/autostart/io.github.imengying.AeroBoxForLinux.desktop"
if command -v update-desktop-database >/dev/null 2>&1 && [ -d "$install_prefix/share/applications" ]; then update-desktop-database "$install_prefix/share/applications" || true; fi
printf 'Application removed. User data is preserved.\n'
