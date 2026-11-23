# Independent VMess/VLESS peer

This test-only Go executable uses the sing-vmess revision pinned by sing-box
1.14.4. It echoes TCP and UDP payloads, including packetaddr addressing. No Go
code is linked into AeroBox.

Build with `go build -o /tmp/aerobox-vmess-peer .`, then set
`AEROBOX_VMESS_PEER=/tmp/aerobox-vmess-peer` when running the ignored
`vmess::interop_tests` library tests. They exercise VMess padding and
authenticated lengths independently, CFB/AEAD/plain payloads, alter-ID
authentication, IPv4/IPv6, XUDP and packetaddr.
