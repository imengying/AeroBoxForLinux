# Upstream dependency provenance

These notes describe the imported fork revisions and their protocol changes.
Current AeroBox dependency versions and build settings are defined by the root
`Cargo.toml`, `Cargo.lock` and [development guide](../../docs/development.md).

## Protected Sources

The workspace patches in `Cargo.toml` are required by checkout/release builds:

- `cfal/rustls`: REALITY/TLS integration; retain the matching exact rustls
  requirements in both workspace manifests.
- `cfal/BLAKE3`: binary-context derivation for VLESS Encryption.
- `cfal/h3`: empty-DATA handling and idle-stream cancellation, plus the
  [bounded-frame backport](https://github.com/hyperium/h3/pull/366) that rejects
  oversized buffered frames from their declared lengths and skips unknown-frame
  payloads incrementally. The fork also defaults the local decoded-header limit
  to 64 KiB. Used by both Shoes and Hickory through h3/h3-quinn.
- `cfal/hickory-dns`: connection-close recovery, healthy-upstream failover and
  bounded TCP/DoT receive progress.
- `cfal/smoltcp`: TUN/WireGuard TCP retransmission ACK sequencing.

Preserve each repository and full revision unless explicitly updating that fork.
Check every resolved consumer, especially Quinn, tokio-rustls, hyper-rustls,
rustls-platform-verifier, Hickory and Shoes; absence of unused-patch warnings is
not sufficient. Keep `publish = false` while workspace patches remain.

### BLAKE3

The November 15 refresh retains package version **1.8.7**, also the latest
non-yanked stable registry release at that date. The release is based on
[`f3149ec5bb5449af877ba20377a11008ff499fa2`](https://github.com/BLAKE3-team/BLAKE3/releases/tag/1.8.7);
the fork instead targets unreleased upstream master
[`657284b1fa4c4378aa7422b4450dcb5c2c9052fc`](https://github.com/BLAKE3-team/BLAKE3/commit/657284b1fa4c4378aa7422b4450dcb5c2c9052fc).

The source series was `derive-key-bytes-upstream-20261021`, at the previous Shoes
pin `cd98c1c4112ed3b2cf2140e1844f266b3d665b53`, based on upstream
`f55849f89cd85083c1c9daa2c5de20766f309c00`. Its one custom API commit is retained
unchanged by the rebase. A separate test-only fix replaces allocated vectors
with fixed arrays so the binary-context regression also compiles without `std`.
The published candidate is
[`5bd8a7ef060bac222502a449bb89b7bdcdb8ec09`](https://github.com/cfal/BLAKE3/tree/5bd8a7ef060bac222502a449bb89b7bdcdb8ec09)
on `derive-key-bytes-upstream-20261115-1794700800046000`. Existing branches and
tags remain intact, retaining old pins. The fork's default `master` does not
carry the API; discover the published patch series before future refreshes.

The only new upstream change replaces secret-indexed hexadecimal lookup with
nibble arithmetic in `Hash::to_hex`, also used by `Display` and `Debug`.
Lowercase output bytes are unchanged. Upstream describes this as
"constant-ish" time, not a compiler-independent constant-time guarantee.
Earlier stack-buffer alignment and AVX-512 zero-output soundness fixes remain
included; neither is part of released 1.8.7. Release 1.8.7's removal of the
compromised `arrayref` dependency was already included in the previous pin.
Public APIs, features, dependencies, native build scripts, supported targets,
SIMD dispatch and zeroization are unchanged. Upstream CI's Rust 1.85.1 build
still works with a fresh MSRV-compatible dependency resolution; this does not
make newer transitive releases compatible with that compiler. Shoes keeps its
existing Rust floor and locked dependency versions.

[Upstream PR #596](https://github.com/BLAKE3-team/BLAKE3/pull/596) remains unmerged.
Retain the patch until a non-yanked registry release provides equivalent
raw-byte derivation that passes these vectors.
VLESS Encryption requires raw-byte contexts, including NUL and invalid UTF-8:
`DERIVE_KEY_CONTEXT` hashes the context, then `DERIVE_KEY_MATERIAL` hashes the
material using that context key. Text, hex, base64, lossy conversion and ordinary
keyed hashing are not substitutes. Preserve equivalence with `derive_key` for
valid UTF-8 and every Go-derived binary vector, including empty and multi-chunk
contexts. No Shoes API adaptation or wire-format change is needed. Check all
callers, including ordinary hashes in VLESS, NaiveProxy and rule updates, plus
Shadowsocks' textual KDF and XOF-derived subkeys.

Future updates must inspect the complete upstream delta and `range-diff`, then
run the fork's current CI matrix, official vectors and binary-context regression
in native/intrinsics/pure debug and release builds, including `no_std` and public
features. Confirm actual SIMD support: this refresh's local x86_64 Linux tests
executed SSE2, SSE4.1 and AVX2, but not AVX-512 or other architectures. Passing
early-return tests are not hardware coverage. In Shoes, use the current pinned
peer workflow, `binary_context_kdfs_match_go`, the VLESS Encryption fixtures,
Shadowsocks and NaiveProxy tests. Verify the final published full SHA with
`--locked`, inspect every resolved consumer, and regenerate dependency notices.

### GotaTun

Published 0.10.3 replaces the upstream git patch. Its archive identifies
[`c541472b40ec489ba7bdfd048512e89e556c7a3c`](https://github.com/mullvad/gotatun/tree/c541472b40ec489ba7bdfd048512e89e556c7a3c),
not the different main-branch commit also declaring 0.10.3. Both session and
cookie counters retain [#221](https://github.com/mullvad/gotatun/pull/221)'s
conditional portable-atomic fallback. The published crate folds the git-only
`gotatun-crypto` and `gotatun-packet` packages back into the main crate; Shoes'
packet, transport and X25519 APIs remain compatible. AWS-LC and device features
are unchanged, as are Shoes' own conditional atomic imports.

The TAI64N base changes from `2^62 + 37` to wireguard-go's `2^62 + 10`.
The same-key handoff regression keeps a reference responder alive across Shoes
and wireguard-go initiators and requires success before the old 27-second
timestamp lead could expire. Existing both-role/rekey tests alone cannot detect
this difference. A recent old-version initiation can temporarily delay a fast
upgrade against retained responder replay state.

The published archive omits its repository-root license files. Corresponding
source URLs use its VCS metadata; offline notice tests pin the verified upstream
MPL and Cloudflare license hashes. Retain both bundled texts.

### Hickory

The stable base remains [v0.26.3](https://github.com/hickory-dns/hickory-dns/releases/tag/v0.26.3),
[`bd37cafbdd86112a6da32878f8c9bab22e14377e`](https://github.com/hickory-dns/hickory-dns/commit/bd37cafbdd86112a6da32878f8c9bab22e14377e).
As of November 7, 2026, this is the latest non-yanked stable release of
`hickory-net`, `hickory-proto` and `hickory-resolver`; all three published crate
archives identify that exact source commit. The release branch has newer,
unreleased commits despite still declaring 0.26.3; main is 0.27.0-alpha.1.
Neither is a published stable upgrade.

The maintained series is pinned at
[`14df4ec4d6c501e23d7815cecd7f556b1cece4a1`](https://github.com/cfal/hickory-dns/commit/14df4ec4d6c501e23d7815cecd7f556b1cece4a1)
on `shoes/0.26.3-multiplexer-wakeup-20261107-1794067200053000`.
It retains both original commits from `fix/0.26-closed-transport-failover`,
including the previous Shoes pin
[`3fa0a0e3ebd9df778256f18e9264f70d284d31c0`](https://github.com/cfal/hickory-dns/commit/3fa0a0e3ebd9df778256f18e9264f70d284d31c0)
as an ancestor. Existing published branches and tags remain intact. The fork's
default branch does not carry the complete series; discover published refs
before choosing a maintenance source.

The additional patch backports upstream
[`a14d6027eca8a1cdcc3ef1d5d2deeafed21175b0`](https://github.com/hickory-dns/hickory-dns/commit/a14d6027eca8a1cdcc3ef1d5d2deeafed21175b0):
count received messages rather than their zero-based index, so consuming the
100-message receive budget schedules another poll. The budget itself is
unchanged. Shoes retains the 32-request per-connection limit, so this is not a
normal high-concurrency lookup failure. A buffered burst of unsolicited or stale
responses can nevertheless hide a valid answer behind that limit. Local,
certificate-verified DoT regressions reproduce timeouts in both hostname lookup
and raw exchange with 100 unsolicited responses, while 0 and 99 are controls.
The backport lets both paths finish without another query, reconnect or retry.

The original series backports upstream #3861's typed `ConnectionClosed` design
and adds narrowly scoped H3 recovery. Disconnected exchange channels are not
`Busy`; genuine queue pressure still is. H3 body errors retain their type,
remote whole-connection `ApplicationClose` is recognized alongside existing
clean-close handling, and stream-level `H3_REQUEST_CANCELLED` remains distinct.
The pool preserves healthy pending siblings and meaningful exhausted-pool
errors. The existing reused/fresh/repeated-close reconnect budgets remain
unchanged. Upstream merging #3861 does not supersede the complete H3 additions.
Neither this work nor external DNS successes establish the cause of Cloudflare's
original application close.

The multiplexer backport leaves package versions, public APIs, features,
Rust 1.88 minimum, platform support, server scoring and negative-response policy
unchanged. In particular, the
unreleased SERVFAIL retry change and connection-setup SRTT changes are not
included. Keep the resolver/net/proto pins together and verify tendns also uses
the fork proto, with no split registry/git types. Preserve the shared rustls and
h3/h3-quinn fork graph and the publishing guard.

Future refreshes must retain the closed-exchange, H3 body/classification,
pool-failover, error-precedence and exact reconnect-count regressions. Run the
standalone production check `cargo check -p hickory-net --locked --features
h3-aws-lc-rs` as well as tests: H3's test-only backend feature can hide production
compilation errors. Test Shoes' high-level hostname resolver and separate raw
exchange path, including buffered-response progress, deadlines, configured
routing and H3 socket-memory teardown.

### smoltcp

The maintained TCP recovery series originates on published `cfal/smoltcp` main
(`a80fa50dce926117669ef061f55f4d6bdad0904a`), based on upstream
`72a0d7892d696620541b1147c7cac471d421e554`, not the older release-based
`fix/tcp-ack-sequence` branch. The October refresh added regression coverage and
rebased it onto `24bda3b4f982625d8453d4360172557d24921c76`, producing the previous
pin [`042e568bfa39d0f111a23a4718ec257e474fd1e7`](https://github.com/cfal/smoltcp/commit/042e568bfa39d0f111a23a4718ec257e474fd1e7).

The November 2026 refresh retains all three October commits on upstream
[`8b0e5c8598647fe92e2a1b87932d1932354fee0b`](https://github.com/smoltcp-rs/smoltcp/commit/8b0e5c8598647fe92e2a1b87932d1932354fee0b).
The series lives on `shoes/tcp-recovery-20261107-000034`, pinned at
[`7ef43e497f575cb0340a43e4f414f0f0b8760bf6`](https://github.com/cfal/smoltcp/commit/7ef43e497f575cb0340a43e4f414f0f0b8760bf6);
existing branches, tags and old pins remain intact.

The package version and latest stable registry release remain **0.14.0**.
The new upstream changes are unreleased: [#1242](https://github.com/smoltcp-rs/smoltcp/pull/1242)
cancels an armed idle keepalive deadline when `set_keep_alive(None)` is called,
without cancelling retransmission, persist or closing timers. Shoes uses this
when draining orphaned connections. [#1238](https://github.com/smoltcp-rs/smoltcp/pull/1238)
ends SLAAC polling after router solicitations are exhausted, and
[#1240](https://github.com/smoltcp-rs/smoltcp/pull/1240) adds `Interface::reset_slaac()`.
SLAAC remains disabled in Shoes. Features, dependencies, Rust minimum and
platform requirements are unchanged; no Shoes adapter changes are required.
Earlier RTO bounds, zero-window timer recovery, failed-fast-retransmission retry,
no-std CUBIC and full-window FIN clamping fixes remain included.

The refresh also fixes upstream's optional-deadline combination: an exhausted
SLAAC timer must not erase a pending socket deadline, and an idle socket set must
not erase a pending solicitation. An interface regression exercises exhaustion,
a pending TCP SYN, restarted solicitation scheduling and competing deadlines.
The keepalive sequence regression adds an open-window case that distinguishes
SND.UNA from the frontier, alongside the existing closed-window case. Both check
that probes leave the retransmission cursor and send frontier unchanged.

Preserve the complete recovery patch, not only its persistent send frontier:

- Pure ACKs use the non-rewound frontier; a zero peer window with queued stream
  data uses SND.UNA, while FIN-only flight retains the frontier.
- RSTs retain the baseline retransmission cursor. Fast retransmit cannot extend
  the frontier with unsent data. Keepalive probes use SND.UNA minus one.
- Probes and empty emissions do not advance the retransmission cursor; failed
  emission does not advance the send frontier. Socket reuse resets it.
- Relaxed receive acceptance applies only to empty None/PSH segments, bounded
  by scaling slack, physical receive capacity and the one-byte lost-FIN allowance.

The exact lost-FIN allowance, FIN-only ACK frontier and RST cursor are retained
fork policies, not universal RFC or OS behavior. Keepalive sequence placement
does not establish timer reachability with outstanding data.

Shoes retains explicit CUBIC, IPv4/IPv6, medium-IP and 32-segment assembly.
Linux TUN transmit offload remains IPv4-only: the interface still does not
forward IPv6 segmentation metadata. TUN supplies partial TCP checksums when
offload is enabled; WireGuard's queue device uses software checksums and MTU-sized
packets without segmentation capabilities. Do not enable new offload paths
without checking `Device`, tokens, `PacketMeta`, ownership and poll wakeups.

For future refreshes, discover and compare published fork branches before
rebasing, inspect the complete upstream delta and `range-diff`, and pin the
tested full SHA in both manifest and lockfile. Run the fork's `ci.sh` matrix,
`socket::tcp::test::` with Reno/CUBIC, and library tests with the exact Shoes
feature set. Use separate target directories for baseline comparisons.
The oversized-frame offload fixture selects no congestion control; a separate
CUBIC regression checks its real flight limit. This avoids mistaking the old
fixture's 65 KB expectation under a 2,048-byte CUBIC window for a runtime bug.
Require deterministic loss/window/FIN/reset regressions as well as Shoes'
rootless TUN, shared IP-stack, WireGuard, kernel and macOS rootless-TUN checks.
Neither those tests nor the original [Shoes #197](https://github.com/cfal/shoes/pull/197)
establish the historical macOS stall's cause or comprehensive Linux/BSD/XNU interoperability.

### nix

The `nix-rust/nix` patch is upstream, not a maintained fork. Published 0.31.3
still lacks [#2821](https://github.com/nix-rust/nix/pull/2821), despite sharing
the pinned commit's package version. With libc 0.2.191 and Shoes' iOS features
(`fs,ioctl,net,socket,time,uio,user`), registry 0.31.3 fails to compile on
`aarch64-apple-ios`; the pinned commit succeeds. Retain it until a published
release passes that regression and the complete mobile builds.
