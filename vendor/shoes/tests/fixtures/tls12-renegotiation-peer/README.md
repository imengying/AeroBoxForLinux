# TLS 1.2 renegotiation reference

This **test-only** server is a minimal patch to MetaCubeX/uTLS v1.8.7. Its
existing TLS cryptography, transcripts and record keys remain independent of
the Rust implementation. The patch adds a server HelloRequest entry point,
stores the preceding Finished values, checks the client binding, and returns
the RFC5746 server binding. Fault flags alter binding, certificate, EMS, ALPN,
Finished and application-record timing. It must not be deployed as a TLS server.

The driver pins disposable public client certificate fixtures (their EKU is for
server authentication); the existing TLS CertificateVerify still proves key
possession. A test-only exporter bypasses Go's API prohibition on exporters
when renegotiation is enabled to compare the independent key schedules.

```sh
cargo xtask tls12-peer
AEROBOX_TLS12_RENEGOTIATION_PEER="$PWD/target/protocol-peers/tls12-renegotiation-peer" \
  cargo test --manifest-path vendor/support/aerobox-crypto/Cargo.toml --test tls12_renegotiation -- --include-ignored --test-threads=1
```

The builder patches and verifies a fresh temporary source copy, removed after
compilation. Only the executable is written to the Cargo target directory.
Rust tests cover key changes, client authentication, invalid handshake rejection,
ALPN continuity, EMS downgrade, repeated requests, opt-in policy, old-epoch
application records, cached Chrome ClientHello bytes, and ticket resumption
followed by a fresh authenticated handshake.

Sources: [RFC5746](https://www.rfc-editor.org/rfc/rfc5746.html),
[RFC7627](https://www.rfc-editor.org/rfc/rfc7627.html),
[pinned uTLS](https://github.com/MetaCubeX/utls/tree/v1.8.7).
