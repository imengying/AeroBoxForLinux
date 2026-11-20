Legacy VMess request-header vector generated with Go standard-library HMAC-MD5
and AES-CFB. The input UUID, timestamp and 57 header bytes are synthetic.

```sh
go run main.go > request.hex
```

Rust unit tests compare the wire bytes; application builds do not invoke Go.
Independent sing-box interoperability tests cover valid TCP and UDP payloads.
