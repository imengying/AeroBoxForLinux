Independent Go sing-mux interoperability peer (test tooling only).

```sh
cd tests/fixtures/mux-peer
CGO_ENABLED=0 go build -trimpath -o /tmp/aerobox-mux-peer .
cd ../../..
AEROBOX_MUX_PEER=/tmp/aerobox-mux-peer cargo test --lib all_mux_protocols_exchange_tcp_and_udp_with_go_sing_mux -- --ignored
```

Exercises smux, yamux and h2mux, padding enabled/disabled, concurrent streams,
flow control, TCP echo and connected UDP framing against the independent
SagerNet implementation pinned in go.mod/go.sum. The peer listens on loopback,
only echoes input, and is killed when its Rust test completes or fails.
