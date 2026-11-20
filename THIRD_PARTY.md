# Third-party source and licenses

AeroBox links the Rust proxy implementation into the `AeroBox` executable. It does not install or launch a separate proxy binary or expose a local HTTP control API.

The protocol implementation in `vendor/shoes` derives from [cfal/shoes](https://github.com/cfal/shoes), version 0.3.8, MIT licensed, and the local AeroBox Android Rust development tree. It is reused source, not an independent protocol implementation written from scratch for this desktop application. The frozen vendored snapshot includes its copyright notices, tests and supporting dependencies; local build products and Git metadata are excluded.

Desktop integration changes include cancellable startup, typed in-process node selection and connection control, DNS cache preference, SRS source export, Linux network-change handling, capability inheritance for the trusted system nft utility, Trojan UDP framing, and enforcement of per-node UDP restrictions through transport wrappers. `src/protocol` adapts the strict Android subscription converter. Supporting RustCrypto provider and cryptographic adapter code is in `vendor/support`.

Protocol details still have explicit limits: browser TLS fingerprint impersonation and Shadowsocks external plugins are rejected. Unsupported options are reported, not silently discarded. The RustCrypto provider used by this source snapshot depends on an upstream alpha provider; local protocol loopback tests do not by themselves prove interoperability with every server version or advanced transport option.

Vendored component license texts are shipped alongside packaged builds:

- blake3: [LICENSE_A2](licenses/blake3/LICENSE_A2), [LICENSE_A2LLVM](licenses/blake3/LICENSE_A2LLVM), [LICENSE_CC0](licenses/blake3/LICENSE_CC0)
- gotatun: [LICENSE](licenses/gotatun/LICENSE), [LICENSE-CLOUDFLARE](licenses/gotatun/LICENSE-CLOUDFLARE)
- h3: [LICENSE](licenses/h3/LICENSE)
- hickory-dns: [LICENSE-APACHE](licenses/hickory-dns/LICENSE-APACHE), [LICENSE-MIT](licenses/hickory-dns/LICENSE-MIT)
- ml-dsa: [LICENSE-MIT](licenses/ml-dsa/LICENSE-MIT), [LICENSE-APACHE](licenses/ml-dsa/LICENSE-APACHE)
- nix: [LICENSE](licenses/nix/LICENSE)
- quinn: [LICENSE-MIT](licenses/quinn/LICENSE-MIT), [LICENSE-APACHE](licenses/quinn/LICENSE-APACHE)
- quinn-proto: [LICENSE-MIT](licenses/quinn-proto/LICENSE-MIT), [LICENSE-APACHE](licenses/quinn-proto/LICENSE-APACHE)
- quinn-udp: [LICENSE-MIT](licenses/quinn-udp/LICENSE-MIT), [LICENSE-APACHE](licenses/quinn-udp/LICENSE-APACHE)
- rcgen: [LICENSE](licenses/rcgen/LICENSE)
- rustls: [LICENSE](licenses/rustls/LICENSE), [LICENSE-APACHE](licenses/rustls/LICENSE-APACHE), [LICENSE-ISC](licenses/rustls/LICENSE-ISC), [LICENSE-MIT](licenses/rustls/LICENSE-MIT)
- shoes: [LICENSE](licenses/shoes/LICENSE)
- smoltcp: [LICENSE-0BSD.txt](licenses/smoltcp/LICENSE-0BSD.txt)
- tendns: [LICENSE](licenses/tendns/LICENSE)

Other Cargo dependencies retain their respective upstream licenses. Rule datasets have separate notices in `resources/rules`. AeroBox application code is GPL-3.0-only.
