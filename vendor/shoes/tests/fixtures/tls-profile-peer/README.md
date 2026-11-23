# Independent TLS profile test peer

This Go tool is only a reference server. It is never linked into AeroBox. It implements a bounded subset of TLS 1.3 directly using
Go's standard cryptographic primitives: AES-128-GCM, X25519, P-256, P-384,
X25519MLKEM768, RSA-PSS-SHA256, HelloRetryRequest,
ALPN h2, optional ALPS at 17513/17613, and optional Brotli certificate compression.
Optional client authentication pins the public test fixture and verifies its
RSA-PSS CertificateVerify. A one-entry ticket store checks PSK binders and
supports resumption plus acceptance/rejection of up to 4 KiB of early data.
It has no ECH, production ticket management, general client PKI, or KeyUpdate.
It must not be used as a deployed TLS server.

Its handshake transcript includes the actual compressed certificate and the
client's EncryptedExtensions. Both Finished values authenticate those bytes.
The settings payload is opaque at TLS level; this is not an HTTP/2 peer.

```sh
CGO_ENABLED=0 go run -mod=readonly . -selftest > selftest.json
CGO_ENABLED=0 go test -mod=readonly -count=1 -v .
CGO_ENABLED=0 go build -mod=readonly -trimpath -o /tmp/aerobox-tls-profile-peer .
/tmp/aerobox-tls-profile-peer -fixtures ../../../../support/aerobox-crypto/tests/fixtures
```

The server prints a localhost port as JSON, checks the offered algorithms,
completes the TLS handshake, echoes application data, then exchanges close_notify.
`-tickets` enables 1-RTT resumption; `-early=accept` or `-early=reject` also
advertises early data in tickets. `-rotate-server-settings` changes settings
on resumed connections and consequently rejects early data. `-mutual` enables
fixture-based client authentication. The `-server-settings` and
`-client-settings` flags carry hexadecimal opaque settings; settings are
fragmented across records when necessary. Malformed-handshake flags exercise
authentication, selection, compression, and length rejection in Rust tests.
The self-test uses the standard Go TLS client and fixed MetaCubeX/uTLS v1.8.7
Chrome133, including a custom old-ALPS variant. It also verifies client rejection
of an incorrect decompressed certificate length and an invalid server Finished.
Certificates and keys are public, disposable test fixtures verified at 2030.

Protocol sources: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html),
[RFC 8879](https://www.rfc-editor.org/rfc/rfc8879.html),
[ALPS draft](https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps-01),
and the pinned uTLS implementation. ALPS remains a draft with browser-specific
codepoints. A successful reference self-test does not imply that AeroBox's
Rust browser fingerprint implementation is finished.

`selftest.json` records fifteen successful handshakes with 65,537-byte echo and
close_notify, plus five correctly rejected handshakes (2026-11-21). It also
checks the hybrid group and P-256/P-384 retries against Chrome133, and a P-384
retry against the standard Go client, plus cookie-only retries for both clients. The retry transcript uses message_hash;
the second ClientHello must preserve its session ID, random, and cipher list.
The self-test also
exposes a fixed-uTLS bug: configured `ApplicationSettings["h2"]` is ignored
because that version looks up the TLS 1.3 ServerHello's empty ALPN field.
The explicit empty-key workaround is only a reference test of nonempty client
settings and their transcript coverage; it is not AeroBox's behavior.

The Go resumption test separately verifies three connections each with standard
Go TLS (X25519 and P-384 HRR) and a Chrome133 template with an explicit PSK
extension added (X25519). Both use
client certificate authentication and independently verify the peer's transcript,
PSK binder, resumption, application data, and close_notify. The unmodified
Chrome133 template does not itself contain a PSK extension. Early data is tested
by the Rust client against this reference's separate key schedule; those tests
do not establish compatibility with every deployed browser or server.

The additional pinned Chrome133 PSK + P-384 HRR case records the expected uTLS
error: that version cannot recompute the PSK binder after HRR. The standard Go
client and Rust client both resume successfully through HRR against this server.
The expected uTLS rejection is recorded separately and is not counted as a
successful resumed handshake.

REALITY modes independently validate X25519/HKDF/AES-GCM ClientHello metadata,
certificate HMAC and Ed25519 CertificateVerify. The pinned sing-box v1.14.4
wrapper strips the hybrid share and uses version 1.8.1; provenance is recorded
in `sing-box-reality-client.json`. Six REALITY reference cases passed, including
bad HMAC/signature/short ID. An additional ordinary-TLS Ed25519 case ensures
the REALITY signature exception cannot leak into normal browser handshakes.
