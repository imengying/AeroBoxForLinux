use super::{Fields, Result, error, outbound::parse_duration_millis, strings};
use serde_json::{Value, json};

pub(super) fn configure(
    value: Value,
    protocol: Value,
    quic: bool,
    kind: &str,
    vision: bool,
    path: &str,
) -> Result<(Value, Option<Value>)> {
    let mut f = Fields::new(value, &format!("{path}.tls"))?;
    if !f.boolean("enabled", false)? {
        f.finish()?;
        return Ok((protocol, None));
    }
    let mut out =
        json!({"type":"tls", "protocol":protocol, "verify":!f.boolean("insecure", false)?});
    if let Some(server_name) = f.string("server_name")?.filter(|name| !name.is_empty()) {
        out["sni_hostname"] = server_name.into();
    }
    let mut options = json!({});
    if let Some(value) = f.take("handshake_timeout").filter(|value| value != "") {
        options["handshake_timeout_ms"] =
            parse_duration_millis(value, &format!("{}.handshake_timeout", f.path))?.into();
    }
    for key in [
        "disable_sni",
        "min_version",
        "max_version",
        "cipher_suites",
        "certificate_sha256",
        "certificate_chain_sha256",
        "certificate_public_key_sha256",
    ] {
        if let Some(v) = f.take(key) {
            if matches!(key, "min_version" | "max_version") && v == "" {
                continue;
            }
            options[key] = if matches!(
                key,
                "cipher_suites"
                    | "certificate_sha256"
                    | "certificate_chain_sha256"
                    | "certificate_public_key_sha256"
            ) {
                strings(v, &format!("{}.{key}", f.path))?.into()
            } else {
                v
            };
        }
    }
    if let Some(certificate) = pem(&mut f, "certificate", "certificate_path")? {
        options["root_certificates"] = json!([certificate]);
    }
    if [
        "certificate_sha256",
        "certificate_chain_sha256",
        "certificate_public_key_sha256",
    ]
    .iter()
    .any(|key| {
        options[*key]
            .as_array()
            .is_some_and(|values| !values.is_empty())
    }) {
        if options.get("root_certificates").is_some() {
            return Err(error(
                &f.path,
                "certificate pins cannot be combined with certificate or certificate_path",
            ));
        }
        // sing-box pins authenticate the leaf directly, including self-signed
        // certificates. The TLS verifier still checks the handshake signature.
        out["verify"] = false.into();
    }
    if !options.as_object().unwrap().is_empty() {
        out["options"] = options;
    }
    if let Some(alpn) = f.take("alpn") {
        out["alpn_protocols"] = strings(alpn, &format!("{}.alpn", f.path))?.into();
    }
    if out.get("alpn_protocols").is_none() || out["alpn_protocols"] == json!([]) {
        if kind == "naive" || matches!(out["protocol"]["kind"].as_str(), Some("grpc" | "http2")) {
            out["alpn_protocols"] = json!([if quic { "h3" } else { "h2" }]);
        } else if out["protocol"]["type"] == "websocket"
            || kind == "http"
            || matches!(
                out["protocol"]["kind"].as_str(),
                Some("http_upgrade" | "http1")
            )
        {
            out["alpn_protocols"] = json!(["http/1.1"]);
        }
    }
    if let Some(groups) = f.take("curve_preferences") {
        let groups = strings(groups, &format!("{}.curve_preferences", f.path))?;
        if !groups.is_empty() {
            out["key_exchange_groups"] = groups
                .into_iter()
                .map(|group| match group.as_str() {
                    "P256" => "SecP256r1".to_owned(),
                    "P384" => "SecP384r1".to_owned(),
                    "P521" => "SecP521r1".to_owned(),
                    _ => group,
                })
                .collect();
        }
    }
    for (inline, file, target) in [
        ("client_certificate", "client_certificate_path", "cert"),
        ("client_key", "client_key_path", "key"),
    ] {
        if let Some(value) = pem(&mut f, inline, file)? {
            out[target] = value.into();
        }
    }
    if let Some(reality) = f.take("reality") {
        let mut r = Fields::new(reality, &format!("{}.reality", f.path))?;
        if r.boolean("enabled", false)? {
            if quic {
                return Err(error(&r.path, "REALITY requires TCP"));
            }
            if let Some(options) = out.as_object_mut().unwrap().remove("options") {
                let mut options = Fields::new(options, &f.path)?;
                options.default_only("disable_sni", &[json!(false)])?;
                options.default_only("min_version", &[json!("1.2"), json!("1.3")])?;
                options.default_only("max_version", &[json!("1.3")])?;
                options.copy("cipher_suites", &mut out, "cipher_suites");
                options.copy("handshake_timeout_ms", &mut out, "handshake_timeout_ms");
                options.finish()?;
            }
            if out.get("cert").is_some() || out.get("key").is_some() {
                return Err(error(
                    &f.path,
                    "ordinary TLS certificate options do not apply to REALITY",
                ));
            }
            if out["verify"] == false {
                return Err(error(&f.path, "REALITY authentication cannot be disabled"));
            }
            out.as_object_mut().unwrap().remove("verify");
            out["type"] = "reality".into();
            out["public_key"] = r.required("public_key")?;
            r.copy("short_id", &mut out, "short_id");
        }
        r.finish()?;
    }
    if vision {
        out["vision"] = true.into();
    }
    let mut fragmentation = json!({});
    for key in ["fragment", "record_fragment"] {
        let enabled = f.boolean(key, false)?;
        if enabled && quic {
            return Err(error(
                format!("{}.{}", f.path, key),
                "TLS fragmentation requires TCP",
            ));
        }
        fragmentation[key] = enabled.into();
    }
    if let Some(delay) = f
        .string("fragment_fallback_delay")?
        .filter(|value| !value.is_empty())
    {
        if quic {
            return Err(error(
                format!("{}.fragment_fallback_delay", f.path),
                "TLS fragmentation requires TCP",
            ));
        }
        fragmentation["fragment_fallback_delay"] = delay.into();
    }
    if fragmentation["fragment"] == true
        || fragmentation["record_fragment"] == true
        || fragmentation.get("fragment_fallback_delay").is_some()
    {
        if out["type"] == "reality" {
            out["fragmentation"] = fragmentation;
        } else {
            if out.get("options").is_none() {
                out["options"] = json!({});
            }
            out["options"]["fragmentation"] = fragmentation;
        }
    }
    for key in ["kernel_tx", "kernel_rx"] {
        let enabled = f.boolean(key, false)?;
        if enabled {
            if quic || out["type"] == "reality" || out["vision"] == true {
                return Err(error(
                    format!("{}.{}", f.path, key),
                    "kTLS requires ordinary TLS over TCP without Vision",
                ));
            }
            if out.get("options").is_none() {
                out["options"] = json!({});
            }
            out["options"][key] = true.into();
        }
    }
    {
        let utls = f.take("utls").unwrap_or_else(|| json!({"enabled":true}));
        let mut u = Fields::new(utls, &format!("{}.utls", f.path))?;
        let requested = u.string("fingerprint")?;
        // Firefox is the application default, including subscription profiles
        // outside the two browser implementations we provide.
        let fingerprint = if requested
            .as_deref()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("chrome"))
        {
            "chrome"
        } else {
            "firefox"
        };
        if u.boolean("enabled", true)? {
            if out["type"] == "reality" {
                out["client_fingerprint"] = fingerprint.into();
            } else {
                if out.get("options").is_none() {
                    out["options"] = json!({});
                }
                out["options"]["client_fingerprint"] = fingerprint.into();
            }
            // sing-box keeps the browser's default ALPN on raw TCP, while
            // HTTP transports supply their own ALPN before TLS is constructed.
            if !quic && (out.get("alpn_protocols").is_none() || out["alpn_protocols"] == json!([]))
            {
                out["alpn_protocols"] = json!(["h2", "http/1.1"]);
            }
        }
        u.finish()?;
    }
    if let Some(ech) = f.take("ech") {
        let mut e = Fields::new(ech, &format!("{}.ech", f.path))?;
        let enabled = e.boolean("enabled", false)?;
        let config = e
            .take("config")
            .map(|config| match config {
                Value::String(text) => Ok(text),
                Value::Array(lines) => lines
                    .iter()
                    .map(|line| {
                        line.as_str().ok_or_else(|| {
                            error(
                                format!("{}.config", e.path),
                                "expected PEM text or a list of text lines",
                            )
                        })
                    })
                    .collect::<Result<Vec<_>>>()
                    .map(|lines| lines.join("\n")),
                _ => Err(error(
                    format!("{}.config", e.path),
                    "expected PEM text or a list of text lines",
                )),
            })
            .transpose()?;
        let config_path = e.string("config_path")?;
        let query_server_name = e.string("query_server_name")?;
        if enabled {
            if out["type"] == "reality" {
                return Err(error(&e.path, "ECH cannot be combined with REALITY"));
            }
            let mut options = json!({});
            if let Some(config) = config.filter(|text| !text.is_empty()) {
                options["config"] = config.into();
            } else if let Some(config_path) = config_path.filter(|path| !path.is_empty()) {
                options["config_path"] = config_path.into();
            }
            if let Some(query_server_name) = query_server_name.filter(|name| !name.is_empty()) {
                options["query_server_name"] = query_server_name.into();
            }
            if out.get("options").is_none() {
                out["options"] = json!({});
            }
            out["options"]["ech"] = options;
        }
        e.finish()?;
    }
    f.finish()?;
    if quic {
        let protocol = out.as_object_mut().unwrap().remove("protocol").unwrap();
        out.as_object_mut().unwrap().remove("type");
        Ok((protocol, Some(out)))
    } else {
        Ok((out, None))
    }
}

fn pem(fields: &mut Fields, inline: &str, file: &str) -> Result<Option<String>> {
    let text = fields
        .take(inline)
        .map(|value| {
            strings(value, &format!("{}.{inline}", fields.path)).map(|lines| lines.join("\n"))
        })
        .transpose()?;
    let path = fields.string(file)?;
    Ok(text
        .filter(|text| !text.is_empty())
        .or_else(|| path.filter(|path| !path.is_empty())))
}
