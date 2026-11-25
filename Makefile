TARGET_DIR := $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)
BINARY := $(TARGET_DIR)/release/AeroBox

.PHONY: build test wayland package clean
build:
	cargo build --release --locked
test:
	scripts/check-network.sh
	cargo fmt --package aerobox-for-linux --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo clippy --bin AeroBox --features ui-smoke --locked -- -D warnings
	cargo test --locked
	scripts/test-protocols.sh --unit
wayland:
	cargo build --bin AeroBox --features ui-smoke --locked
	scripts/test-wayland.sh "$(TARGET_DIR)/debug/AeroBox"
package: build
	AEROBOX_BINARY="$(BINARY)" scripts/package.sh
	python3 scripts/check-package.py "$(TARGET_DIR)/packages/AeroBoxForLinux-linux-amd64.tar.gz"
clean:
	cargo clean
