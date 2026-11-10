#!/bin/sh
set -eu
arch=${1:-$(uname -m)}
case "$arch" in
  amd64|x86_64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) printf 'Unsupported architecture: %s\n' "$arch" >&2; exit 1 ;;
esac
target_dir=${CARGO_TARGET_DIR:-target}
binary=${AEROBOX_BINARY:-"$target_dir/release/AeroBox"}
if [ ! -x "$binary" ]; then
  printf 'Build the executable first: cargo build --release --locked\n' >&2
  exit 1
fi
name="AeroBoxForLinux-linux-$arch"
output_dir="$target_dir/packages"
mkdir -p "$output_dir"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$stage/$name"
install -m755 "$binary" "$stage/$name/AeroBox"
install -m755 scripts/install.sh scripts/uninstall.sh "$stage/$name/"
install -m644 resources/io.github.imengying.AeroBoxForLinux.desktop resources/io.github.imengying.AeroBoxForLinux.png README.md LICENSE "$stage/$name/"
mkdir -p "$stage/$name/resources/rules"
install -m644 resources/rules/README.md resources/rules/*-LICENSE "$stage/$name/resources/rules/"
tar -C "$stage" -czf "$output_dir/$name.tar.gz" "$name"
printf 'Package: %s/%s.tar.gz\n' "$output_dir" "$name"
