#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
project_dir=$(pwd)
mode=${1:-interop}
case "$mode" in
    --unit|--ktls|interop) ;;
    *) printf 'Usage: %s [--unit|--ktls]\n' "$0" >&2; exit 2 ;;
esac
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$project_dir/target"}
mkdir -p "$CARGO_TARGET_DIR"
export CARGO_TARGET_DIR=$(cd "$CARGO_TARGET_DIR" && pwd)
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0

# Standalone test workspaces reuse the application's resolved dependency
# versions, adding their own dev-dependencies without changing Cargo.lock.
remove_shoes_lock=0
remove_crypto_lock=0
cleanup_locks() {
    if [ "$remove_shoes_lock" = 1 ]; then rm -f vendor/shoes/Cargo.lock; fi
    if [ "$remove_crypto_lock" = 1 ]; then rm -f vendor/support/aerobox-crypto/Cargo.lock; fi
}
trap cleanup_locks EXIT
trap 'exit 1' HUP INT TERM
if [ ! -f vendor/shoes/Cargo.lock ]; then
    remove_shoes_lock=1
    cp Cargo.lock vendor/shoes/Cargo.lock
fi
if [ ! -f vendor/support/aerobox-crypto/Cargo.lock ]; then
    remove_crypto_lock=1
    cp Cargo.lock vendor/support/aerobox-crypto/Cargo.lock
fi

run_unit_tests() {
    cargo test --manifest-path vendor/support/aerobox-crypto/Cargo.toml -- --test-threads=1
    cargo test --manifest-path vendor/shoes/Cargo.toml --lib -- \
        vmess:: packet_encoding:: xudp::client_stream:: tls_client_handler:: anytls:: ss_plugin:: \
        quic_client::tuic_uot_tests quic_client::hop:: quic_client::hysteria2:: \
        quic_client::early_tests ech:: tls_fragment:: tcp::fast_open:: dial_options:: crypto:: \
        config::types::quic_client:: config::types::tls:: config::validate:: \
        dns::builder::tests dns::parsed:: vless::encryption:: rustls_config_util:: reality:: \
        tcp::socket_connector_impl::tests::configured_quic_handshake_timeout --test-threads=1
}
if [ "$mode" = --unit ]; then
    run_unit_tests
    exit 0
fi
if [ "$mode" = --ktls ]; then
    # Explicit environment test: Linux 6.14+ with kTLS and cipher modules.
    # Keep failures fatal when requested; ordinary CI does not assume support.
    cargo test --manifest-path vendor/shoes/Cargo.toml --lib crypto::ktls::tests:: \
        -- --ignored --nocapture --test-threads=1
    exit 0
fi

test_output=$CARGO_TARGET_DIR/protocol-peers
mkdir -p "$test_output"
test_output=$(cd "$test_output" && pwd)

for peer in vmess obfs tuic ech tls-profile; do
    (cd "vendor/shoes/tests/fixtures/$peer-peer" &&
        CGO_ENABLED=0 GOMAXPROCS=1 go build -mod=readonly -p 1 -o "$test_output/$peer-peer" .)
done
export AEROBOX_VMESS_PEER="$test_output/vmess-peer"
export AEROBOX_OBFS_PEER="$test_output/obfs-peer"
export AEROBOX_TUIC_PEER="$test_output/tuic-peer"
export AEROBOX_ECH_PEER="$test_output/ech-peer"
export AEROBOX_TLS_PROFILE_PEER="$test_output/tls-profile-peer"
python3 vendor/shoes/tests/fixtures/tls12-renegotiation-peer/build.py
export AEROBOX_TLS12_RENEGOTIATION_PEER="$test_output/tls12-renegotiation-peer"
(cd vendor/support/aerobox-crypto/tests/fixtures/cbc-peer &&
    CGO_ENABLED=0 GOMAXPROCS=1 go build -p 1 -o "$test_output/cbc-peer" main.go)
export AEROBOX_CBC_PEER="$test_output/cbc-peer"
(cd vendor/shoes/tests/fixtures/tls-fragment-peer &&
    CGO_ENABLED=0 GOMAXPROCS=1 go build -trimpath -p 1 -o "$test_output/tls-fragment-peer" main.go)
export AEROBOX_TLS_FRAGMENT_PEER="$test_output/tls-fragment-peer"
run_unit_tests
cargo test --manifest-path vendor/support/aerobox-crypto/Cargo.toml --locked -- --ignored --test-threads=1
cargo test --manifest-path vendor/shoes/Cargo.toml --lib -- \
    vmess::interop_tests ss_plugin:: quic_client::tuic_uot_tests \
    quic_client::early_tests ech:: tls_fragment:: tcp::socket_connector_impl::early_tests rustls_config_util::browser:: \
    --ignored --nocapture --test-threads=1
# P-384 forces HelloRetryRequest for the default and both browser profiles.
AEROBOX_ECH_CURVE=24 AEROBOX_ECH_TICKETS=1 \
    cargo test --manifest-path vendor/shoes/Cargo.toml --lib \
    ech::tests::interop::tcp_and_quic_ech_accept_rotation_rejection_and_public_auth_with_go \
    -- --ignored --nocapture
if [ "${AEROBOX_TEST_KTLS_REKEY:-0}" = 1 ]; then
    # Requires Linux 6.14+ with TLS and the tested cipher modules enabled.
    cargo test --manifest-path vendor/shoes/Cargo.toml --lib \
        crypto::ktls::tests::linux_tls13_key_updates -- --ignored --nocapture
fi
cargo test --locked --test ss_plugin_interop -- --ignored --nocapture
if [ -n "${AEROBOX_TEST_PEER:-}" ]; then
    cargo test --locked --test interop -- --ignored --nocapture --test-threads=1
fi
