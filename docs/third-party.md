# Third-party source and licenses

AeroBox links the Rust proxy implementation into the `AeroBox` executable. It does not install or launch a separate proxy binary or expose a local HTTP control API.

The protocol implementation in `vendor/shoes` derives from [cfal/shoes](https://github.com/cfal/shoes), version 0.3.8, MIT licensed, and the local AeroBox Android Rust development tree. It is reused source, not an independent protocol implementation written from scratch for this desktop application. The maintained vendored source includes its copyright notices, protocol tests and supporting dependencies. Upstream standalone release scripts, Docker/cross-compilation files and JavaScript benchmark drivers are omitted; local build products and Git metadata are excluded.

Desktop integration changes include cancellable startup, typed in-process node selection and connection control, DNS cache preference, SRS source export, Linux network-change handling, capability inheritance for the trusted system nft utility, Trojan UDP framing, per-node UDP restrictions through transport wrappers, explicit VMess/VLESS XUDP encoding, reusable offline node validation, and native Chrome/Firefox ClientHello profiles. `src/protocol` adapts the strict Android subscription converter. Supporting RustCrypto provider and cryptographic adapter code is in `vendor/support`.

SIP003 `obfs-local` and `v2ray-plugin` transports run as Rust code inside the application; no external plugin executable is launched. The implementation includes HTTP/TLS obfuscation, WebSocket/TLS, Xray mux framing and shared QUIC sessions. Native SS UDP keeps its own framing. Protocol details still have explicit limits: Chrome133 includes ALPS, independently generated hybrid/classical shares, real TLS 1.2 CBC/RSA suites, and one authenticated TLS 1.2 renegotiation. Firefox remains a capability-constrained layout. Neither implements browser HTTP behavior. Unsupported options are reported, not silently discarded. The RustCrypto provider used by this source snapshot depends on an upstream alpha provider; local protocol loopback tests do not by themselves prove interoperability with every server version or advanced transport option.

TLS wire preferences and transport defaults were checked against [sing-box v1.14.4](https://github.com/SagerNet/sing-box/tree/v1.14.4/common/tls), its [uTLS v1.8.7 profiles](https://github.com/metacubex/utls/blob/v1.8.7/u_parrots.go), and [sing-anytls v0.0.11](https://github.com/anytls/sing-anytls/tree/v0.0.11). Browser profiles use real supported cryptography and Brotli decompression. Real ECH uses the RustCrypto HPKE adapter in `vendor/support/aerobox-crypto`; GREASE ECH remains a separate browser-profile behavior when real ECH is disabled. Local rustls changes expose authenticated ECH retry information and the existing kernel connection state machine for Linux kTLS record offload. TCP Fast Open, MPTCP, UDP fragmentation, TLS fragmentation, and TUIC early-data handling are integrated into the same transport stack. These Go projects are reference implementations and independent test peers, not runtime dependencies.

Independent VMess, Shadowsocks-plugin, TUIC/UoT and ECH fixtures in `vendor/shoes/tests/fixtures` use pinned SagerNet Go modules. The plugin fixture includes two unmodified MIT-licensed go-gost/x obfuscation connection implementations, with their license retained in `obfs-peer/gost/LICENSE`. The TLS fragmentation fixture uses Go’s standard TLS implementation. These peers only run during protocol interoperability tests.

Vendored dependency trees omit upstream Docker environments, cross-compilation
configuration, standalone C builds, release automation and website tooling.
Rust libraries and protocol fixtures remain; AeroBox's checks and packaging use
`cargo xtask` and the root workflows.

Licenses are retained beside the source they cover. Release archives contain the application, icon and installation scripts; license texts and documentation stay in this repository:

- aerobox-crypto: [LICENSE](../vendor/support/aerobox-crypto/LICENSE)
- aerobox-primitives: [LICENSE](../vendor/support/aerobox-primitives/LICENSE)
- blake3: [LICENSE_A2](../vendor/blake3/LICENSE_A2), [LICENSE_A2LLVM](../vendor/blake3/LICENSE_A2LLVM), [LICENSE_CC0](../vendor/blake3/LICENSE_CC0)
- gotatun: [LICENSE](../vendor/gotatun/LICENSE), [LICENSE-CLOUDFLARE](../vendor/gotatun/LICENSE-CLOUDFLARE)
- h3: [LICENSE](../vendor/h3/LICENSE)
- hickory-dns: [LICENSE-APACHE](../vendor/hickory-dns/LICENSE-APACHE), [LICENSE-MIT](../vendor/hickory-dns/LICENSE-MIT)
- ml-dsa: [LICENSE-MIT](../vendor/ml-dsa/LICENSE-MIT), [LICENSE-APACHE](../vendor/ml-dsa/LICENSE-APACHE)
- nix: [LICENSE](../vendor/nix/LICENSE)
- quinn: [LICENSE-MIT](../vendor/quinn/LICENSE-MIT), [LICENSE-APACHE](../vendor/quinn/LICENSE-APACHE)
- quinn-proto: [LICENSE-MIT](../vendor/quinn-proto/LICENSE-MIT), [LICENSE-APACHE](../vendor/quinn-proto/LICENSE-APACHE)
- quinn-udp: [LICENSE-MIT](../vendor/quinn-udp/LICENSE-MIT), [LICENSE-APACHE](../vendor/quinn-udp/LICENSE-APACHE)
- rcgen: [LICENSE](../vendor/rcgen/LICENSE)
- rustls: [LICENSE](../vendor/rustls/LICENSE), [LICENSE-APACHE](../vendor/rustls/LICENSE-APACHE), [LICENSE-ISC](../vendor/rustls/LICENSE-ISC), [LICENSE-MIT](../vendor/rustls/LICENSE-MIT)
- shoes: [LICENSE](../vendor/shoes/LICENSE)
- smoltcp: [LICENSE-0BSD.txt](../vendor/smoltcp/LICENSE-0BSD.txt)
- tendns: [LICENSE](../vendor/tendns/LICENSE)

Other Cargo dependencies retain their respective upstream licenses. The embedded rule datasets come from [SagerNet/sing-geoip](https://github.com/SagerNet/sing-geoip) and [SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite), both GPL-3.0-or-later, with license texts in `resources/rules`. AeroBox application code is GPL-3.0-only.

The browser TLS extensions and additional RustCrypto algorithms are adapted from the local AeroBox Android Rust project. The test-only TLS profile peer and pinned, patched uTLS v1.8.7 renegotiation peer live under `vendor/shoes/tests/fixtures`; provenance and patch hashes are recorded alongside them. They are not runtime dependencies. TLS CBC/RSA support is enabled by explicit cipher selection or browser policy, not by the default TLS provider. Public disposable certificate/key fixtures under `vendor/support/aerobox-crypto/tests/fixtures` are only used by tests.
