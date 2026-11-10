TARGET_DIR := $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)
BINARY := $(TARGET_DIR)/release/AeroBox

.PHONY: build test wayland package clean
build:
	cargo build --release --locked
test:
	cargo fmt --all --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo test --locked
wayland: build
	scripts/test-wayland.sh "$(BINARY)"
package: build
	AEROBOX_BINARY="$(BINARY)" scripts/package.sh
clean:
	cargo clean
