# AeroBox vendored source

Upstream: https://github.com/cfal/shoes
Revision: 7680938b96a245a21d9e481ad009205b956e4436 (2026-11-16)
Archive: https://codeload.github.com/cfal/shoes/tar.gz/7680938b96a245a21d9e481ad009205b956e4436
License: MIT; upstream LICENSE retained.

This maintained snapshot is statically linked into the AeroBox Linux application.
It includes the native core work developed for AeroBox; no external proxy process
is launched. Native crypto backends use explicit AeroBox RustCrypto
providers and local patches for rustls, Quinn, rcgen, BLAKE3 and related crates.
The upstream license and notices are retained.

AeroBox additions include the embedded lifecycle controller, platform socket
protection/DNS integration, Android borrowed TUN support, strict configuration
conversion, native Shadowsocks/SOCKS UDP, UoT v1/v2, Android stream transports,
SMUX/YAMUX/H2MUX client pooling, Naive HTTP/3, negotiated HY2 bandwidth,
and conditional DNS routing. Linux integration also includes app-owned network
state, native Trojan UDP, VMess/VLESS packet encoding, per-node UDP restrictions,
node admission validation, connection deadlines, configurable TCP/H2 keepalive,
domain-aware DNS rule matching and embedded network recovery. These changes are
tracked by the parent repository.

Protocol support is being validated incrementally. The repository README
describes supported parameters and limitations. Server-side ACME issuance
is deliberately unavailable in this client application; configured file
certificates remain supported. Test-only reference peers are separate programs
and are not runtime dependencies.
