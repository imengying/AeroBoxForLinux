# Hickory DNS for AeroBox

DNS libraries from [Hickory DNS](https://github.com/hickory-dns/hickory-dns),
with the fork revision recorded in [AEROBOX-UPSTREAM.json](AEROBOX-UPSTREAM.json).

AeroBox uses [hickory-proto](crates/proto/), [hickory-net](crates/net/) and
[hickory-resolver](crates/resolver/) for DNS messages and transports. The local
RustCrypto changes are described in [AEROBOX-PATCHES.md](AEROBOX-PATCHES.md).

Build and verification commands belong to the
[AeroBox development guide](../../docs/development.md). The upstream container
conformance environment and standalone release scripts are omitted.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
