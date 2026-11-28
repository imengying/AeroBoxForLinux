# GotaTun

A userspace [WireGuard<sup>®</sup>](https://www.wireguard.com/) implementation, and a fork of [BoringTun](https://github.com/cloudflare/boringtun).

## License

All source code in this repository is subject to the terms of the Mozilla Public License, version 2.0 unless stated otherwise. A copy of this license can be found in the file "LICENSE" or at <https://www.mozilla.org/MPL/2.0/>.

Contributions made prior to March 5, 2026 are licensed under the old BSD 3-clause license. A copy of this license can be found in the file "LICENSE-CLOUDFLARE".

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the MPL-2.0 License, shall be licensed as above, without any additional terms or conditions.

## AeroBox integration

AeroBox links the Rust WireGuard library with its RustCrypto provider. The
upstream Docker and privileged standalone-device test harness is omitted.
Application and protocol verification use [AeroBox's development commands](../../docs/development.md).

<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. GotaTun is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
