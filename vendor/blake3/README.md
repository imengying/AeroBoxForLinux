# BLAKE3 for AeroBox

Rust hashing source from [cfal/BLAKE3](https://github.com/cfal/BLAKE3), based on
[BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3). The imported revision
is recorded in [AEROBOX-UPSTREAM.json](AEROBOX-UPSTREAM.json).

AeroBox uses the Rust portable and x86 SIMD implementations. `build.rs` does not
compile C or assembly. The standalone C implementation, native upstream build
script, cross-compilation scripts and CLI release tools are omitted.

The reference implementation and test vectors remain available for checking the
hash implementation and the fork's binary-context key derivation.

Licenses: [Apache 2.0](LICENSE_A2), [Apache 2.0 with LLVM exception](LICENSE_A2LLVM),
and [CC0](LICENSE_CC0).
