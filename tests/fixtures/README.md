`dns-routing.srs` is compiled from `dns-routing.json` with sing-box 1.14.4:

```sh
sing-box rule-set compile tests/fixtures/dns-routing.json --output tests/fixtures/dns-routing.srs
```

The fixture tests mixed domain/IP/port and logical rules against the independent binary format. It is project-authored test data; tests do not invoke sing-box.
