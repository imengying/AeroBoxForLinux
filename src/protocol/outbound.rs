use super::{Fields, Result, address, error, seconds};
use serde_json::{Value, json};

/// Convert a single Android/sing-box outbound into a named Rust client group.
/// Returns an error for every field that cannot be represented faithfully.
pub fn convert_outbound(value: Value, path: &str) -> Result<Value> {
    let mut f = Fields::new(value, path)?;
    let kind = f.text("type")?;
    let tag = f.text("tag")?;
    if tag.is_empty() {
        return Err(error(format!("{path}.tag"), "must not be empty"));
    }
    if kind == "selector" || kind == "urltest" {
        let members = f.required("outbounds")?;
        let members = members
            .as_array()
            .ok_or_else(|| error(format!("{path}.outbounds"), "expected array"))?;
        if members.is_empty() || members.iter().any(|v| !v.is_string()) {
            return Err(error(
                format!("{path}.outbounds"),
                "expected nonempty array of tags",
            ));
        }
        let mut group = json!({"client_group":tag, "type":if kind == "selector" {"selector"} else {"url-test"}, "client_chains": members.iter().map(|v| json!({"chain":[v]})).collect::<Vec<_>>()});
        f.copy("default", &mut group, "default");
        if kind == "urltest" {
            group["url"] = f
                .take("url")
                .unwrap_or(json!("https://www.gstatic.com/generate_204"));
            if let Some(v) = f.take("interval") {
                group["interval"] = seconds(v, &format!("{path}.interval"))?.into();
            }
            f.copy("tolerance", &mut group, "tolerance");
        }
        f.default_only("interrupt_exist_connections", &[json!(false)])?;
        f.finish()?;
        return Ok(group);
    }
    let mut client = json!({"name":format!("{tag}-transport")});
    if kind != "direct" {
        let server = f.text("server")?;
        let mut port = f.take("server_port");
        if port.is_none() && kind == "hysteria2" {
            port = f
                .values
                .get("server_ports")
                .and_then(Value::as_array)
                .and_then(|v| v.first())
                .and_then(Value::as_str)
                .and_then(|v| v.split(':').next())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Value::from);
        }
        let port = port
            .and_then(|v| v.as_u64())
            .ok_or_else(|| error(format!("{path}.server_port"), "required port in 1..65535"))?;
        client["address"] = address(&server, port, path)?.into();
    }
    f.copy("bind_interface", &mut client, "bind_interface");
    f.copy("domain_resolver", &mut client, "domain_resolver");
    let udp = match f.string("network")?.as_deref() {
        None | Some("") | Some("tcp,udp") | Some("udp,tcp") => true,
        Some("tcp") => false,
        Some(_) => {
            return Err(error(
                format!("{path}.network"),
                "UDP-only policy needs an explicit routing network rule",
            ));
        }
    };
    let mut vision = false;
    let mut protocol = match kind.as_str() {
        "direct" => json!({"type":"direct"}),
        "shadowsocks" => {
            json!({"type":"shadowsocks", "cipher":f.text("method")?, "password":f.text("password")?, "udp_enabled":udp})
        }
        "vmess" => {
            f.default_only("alter_id", &[json!(0)])?;
            f.default_only("global_padding", &[json!(false)])?;
            f.default_only("authenticated_length", &[json!(false)])?;
            let packet_encoding = packet_encoding(&mut f, false)?;
            let cipher = f.string("security")?.unwrap_or("auto".into());
            let cipher = if cipher == "auto" {
                "any".into()
            } else {
                cipher
            };
            json!({"type":"vmess", "cipher":cipher, "user_id":f.text("uuid")?, "udp_enabled":udp, "packet_encoding":packet_encoding})
        }
        "vless" => {
            let packet_encoding = packet_encoding(&mut f, true)?;
            let flow = f.string("flow")?.unwrap_or_default();
            if !["", "xtls-rprx-vision"].contains(&flow.as_str()) {
                return Err(error(format!("{path}.flow"), "unsupported VLESS flow"));
            }
            vision = flow == "xtls-rprx-vision";
            if vision && udp && packet_encoding.is_empty() {
                return Err(error(
                    format!("{path}.packet_encoding"),
                    "VLESS Vision requires XUDP for UDP payloads",
                ));
            }
            json!({"type":"vless", "user_id":f.text("uuid")?, "udp_enabled":udp, "packet_encoding":packet_encoding})
        }
        "trojan" => json!({"type":"trojan", "password":f.text("password")?, "udp_enabled":udp}),
        "anytls" => {
            let mut p = json!({"type":"anytls", "password":f.text("password")?, "udp_enabled":udp});
            for (src, dst) in [
                (
                    "idle_session_check_interval",
                    "idle_session_check_interval_secs",
                ),
                ("idle_session_timeout", "idle_session_timeout_secs"),
            ] {
                if let Some(v) = f.take(src) {
                    p[dst] = seconds(v, &format!("{path}.{src}"))?.into();
                }
            }
            f.copy("min_idle_session", &mut p, "min_idle_session");
            p
        }
        "hysteria2" => {
            let mut p =
                json!({"type":"hysteria2", "password":f.text("password")?, "udp_enabled":udp});
            f.copy("obfs", &mut p, "obfs");
            for key in ["up_mbps", "down_mbps"] {
                f.copy(key, &mut p, key);
            }
            if let Some(ports) = f.take("server_ports") {
                let values = ports
                    .as_array()
                    .ok_or_else(|| error(format!("{path}.server_ports"), "expected array"))?;
                let ports = values
                    .iter()
                    .map(|v| {
                        v.as_str().map(|s| s.replace(':', "-")).ok_or_else(|| {
                            error(format!("{path}.server_ports"), "expected port strings")
                        })
                    })
                    .collect::<Result<Vec<_>>>()?
                    .join(",");
                let mut hopping = json!({"ports":ports});
                if let Some(v) = f.take("hop_interval") {
                    hopping["interval_secs"] = seconds(v, &format!("{path}.hop_interval"))?.into();
                }
                p["hopping"] = hopping;
            }
            f.default_only("disable_chrome_parrot", &[json!(true)])?;
            f.default_only("brutal_debug", &[json!(false)])?;
            p
        }
        "tuic" => {
            let mut p = json!({"type":"tuic", "uuid":f.text("uuid")?, "password":f.text("password")?, "udp_enabled":udp});
            f.copy("udp_relay_mode", &mut p, "udp_relay_mode");
            if let Some(v) = f.take("heartbeat") {
                p["heartbeat_interval_secs"] = seconds(v, &format!("{path}.heartbeat"))?.into();
            }
            if f.boolean("udp_over_stream", false)? {
                p["udp_relay_mode"] = "quic".into();
            }
            f.default_only("zero_rtt_handshake", &[json!(false)])?;
            f.copy("congestion_control", &mut p, "congestion_control");
            p
        }
        "naive" => {
            let mut settings = json!({"quic":f.boolean("quic",false)?});
            f.copy(
                "congestion_control",
                &mut settings,
                "quic_congestion_control",
            );
            for key in [
                "extra_headers",
                "insecure_concurrency",
                "quic_congestion_control",
            ] {
                f.copy(key, &mut settings, key);
            }
            for (key, target) in [
                ("stream_receive_window", "stream_receive_window"),
                ("quic_session_receive_window", "session_receive_window"),
            ] {
                if let Some(value) = f.take(key) {
                    settings[target] = byte_size(value, &format!("{path}.{key}"))?.into();
                }
            }
            json!({"type":"naiveproxy", "settings":settings, "username":f.string("username")?.unwrap_or_default(), "password":f.string("password")?.unwrap_or_default(), "udp_enabled":udp})
        }
        "socks" | "http" => {
            let mut p = json!({"type":kind});
            f.copy("username", &mut p, "username");
            f.copy("password", &mut p, "password");
            if kind == "socks" {
                p["udp_enabled"] = udp.into();
                f.default_only("version", &[json!("5")])?;
            } else {
                let mut settings = json!({});
                for key in ["path", "headers"] {
                    f.copy(key, &mut settings, key);
                }
                p["settings"] = settings;
            }
            p
        }
        _ => {
            return Err(error(
                format!("{path}.type"),
                "unsupported outbound protocol",
            ));
        }
    };
    if let Some(v) = f.take("multiplex") {
        let mut mux = Fields::new(v, &format!("{path}.multiplex"))?;
        if mux.boolean("enabled", false)? {
            if vision {
                return Err(error(&mux.path, "VLESS Vision does not support multiplex"));
            }
            if !["shadowsocks", "vmess", "vless", "trojan"].contains(&kind.as_str()) {
                return Err(error(
                    &mux.path,
                    "multiplex requires Shadowsocks, VMess, VLESS or Trojan",
                ));
            }
            let mut out = json!({});
            mux.copy("protocol", &mut out, "protocol");
            for key in ["max_connections", "min_streams", "max_streams", "padding"] {
                mux.copy(key, &mut out, key);
            }
            if kind == "shadowsocks" {
                protocol = json!({"type":"multiplex","settings":out,"protocol":protocol});
            } else {
                protocol["h2mux"] = out;
            }
            mux.finish()?;
        } else {
            mux.default_only("protocol", &[json!("smux"), json!("yamux"), json!("h2mux")])?;
            mux.finish()?;
        }
    }
    let tls = f.take("tls");
    let has_tls = tls
        .as_ref()
        .and_then(|v| v.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if vision && !has_tls {
        return Err(error(
            format!("{path}.flow"),
            "VLESS Vision requires TLS or REALITY",
        ));
    }
    if ["anytls", "trojan", "naive", "tuic", "hysteria2"].contains(&kind.as_str()) && !has_tls {
        return Err(error(
            format!("{path}.tls.enabled"),
            "this protocol requires TLS",
        ));
    }
    let native_quic = ["hysteria2", "tuic"].contains(&kind.as_str())
        || (kind == "naive" && protocol["settings"]["quic"] == true);
    let mut quic_transport = native_quic;
    if let Some(v) = f.take("transport") {
        if vision {
            return Err(error(
                format!("{path}.transport"),
                "VLESS Vision requires TCP without an additional stream transport",
            ));
        }
        let (wrapped, quic) = transport(v, protocol, has_tls, path)?;
        protocol = wrapped;
        quic_transport |= quic;
    }
    if let Some(tls) = tls {
        let (wrapped, quic) = tls_config(tls, protocol, quic_transport, &kind, vision, path)?;
        protocol = wrapped;
        if let Some(quic) = quic {
            client["quic_settings"] = quic;
        }
    }
    if quic_transport {
        client["transport"] = "quic".into();
    }
    // Disabled optional features are accepted; enabled variants are never discarded.
    for key in [
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
        "disable_tcp_keep_alive",
    ] {
        f.default_only(key, &[json!(false)])?;
    }
    if let Some(uot) = f.take("udp_over_tcp") {
        let (enabled, version) = match uot {
            Value::Bool(enabled) => (enabled, 2),
            value => {
                let mut u = Fields::new(value, &format!("{path}.udp_over_tcp"))?;
                let enabled = u.boolean("enabled", true)?;
                let version = u
                    .take("version")
                    .unwrap_or(json!(2))
                    .as_u64()
                    .ok_or_else(|| error(&u.path, "invalid UoT version"))?;
                u.finish()?;
                (enabled, version)
            }
        };
        if !matches!(version, 1 | 2) {
            return Err(error(
                format!("{path}.udp_over_tcp.version"),
                "expected 1 or 2",
            ));
        }
        if enabled {
            if !["shadowsocks", "socks", "naive"].contains(&kind.as_str()) {
                return Err(error(
                    format!("{path}.udp_over_tcp"),
                    "UoT is not configurable for this protocol",
                ));
            }
            if kind == "naive" && native_quic {
                protocol["settings"]["udp_over_tcp"] = version.into();
            } else {
                protocol = json!({"type":"udp_over_tcp","version":version,"protocol":protocol});
            }
        }
    }
    client["protocol"] = protocol;
    f.finish()?;
    Ok(json!({"client_group":tag, "client_chains":[{"chain":[client]}]}))
}
fn packet_encoding(f: &mut Fields, default_xudp: bool) -> Result<String> {
    let encoding = f.string("packet_encoding")?.unwrap_or_else(|| {
        if default_xudp {
            "xudp".into()
        } else {
            String::new()
        }
    });
    if !matches!(encoding.as_str(), "" | "xudp") {
        return Err(error(
            format!("{}.packet_encoding", f.path),
            "supported UDP encodings are an empty string or xudp",
        ));
    }
    Ok(encoding)
}
fn transport(value: Value, protocol: Value, tls: bool, path: &str) -> Result<(Value, bool)> {
    let mut f = Fields::new(value, &format!("{path}.transport"))?;
    let kind = f.text("type")?;
    if kind == "quic" {
        if !tls {
            return Err(error(&f.path, "QUIC requires TLS"));
        }
        f.finish()?;
        return Ok((protocol, true));
    }
    let mut out = if kind == "ws" {
        json!({"type":"websocket", "protocol":protocol})
    } else {
        json!({"type":"stream_transport", "kind":match kind.as_str() {"grpc"=>"grpc", "httpupgrade"=>"http_upgrade", "http" if tls=>"http2", "http"=>"http1", _=>return Err(error(format!("{}.type",f.path),"unsupported transport"))}, "protocol":protocol})
    };
    if kind == "ws" {
        f.copy("path", &mut out, "matching_path");
        f.copy("headers", &mut out, "matching_headers");
        f.copy("max_early_data", &mut out, "max_early_data");
        f.copy("early_data_header_name", &mut out, "early_data_header_name");
    } else {
        for key in ["path", "method", "service_name"] {
            f.copy(key, &mut out, key);
        }
        if let Some(headers) = f.take("headers") {
            let mut headers = headers
                .as_object()
                .cloned()
                .ok_or_else(|| error(format!("{}.headers", f.path), "expected headers object"))?;
            for (name, value) in &mut headers {
                if let Value::Array(values) = value {
                    if values.len() != 1 || !values[0].is_string() {
                        return Err(error(
                            format!("{}.headers.{name}", f.path),
                            "requires one header value",
                        ));
                    }
                    *value = values[0].clone();
                }
                if !value.is_string() {
                    return Err(error(
                        format!("{}.headers.{name}", f.path),
                        "expected header string",
                    ));
                }
            }
            out["headers"] = headers.into();
        }
        if let Some(host) = f.take("host") {
            out["host"] = match host {
                Value::Array(v) if v.len() == 1 => v[0].clone(),
                Value::String(_) => host,
                _ => return Err(error(format!("{}.host", f.path), "requires one host")),
            };
        }
        f.default_only("permit_without_stream", &[json!(false)])?;
    }
    f.finish()?;
    Ok((out, false))
}
fn tls_config(
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
    for key in [
        "disable_sni",
        "min_version",
        "max_version",
        "cipher_suites",
        "certificate_public_key_sha256",
    ] {
        if let Some(v) = f.take(key) {
            options[key] = if matches!(key, "cipher_suites" | "certificate_public_key_sha256")
                && v.is_string()
            {
                json!([v])
            } else {
                v
            };
        }
    }
    if let Some(v) = f.take("certificate") {
        options["root_certificates"] = if v.is_string() { json!([v]) } else { v };
    }
    if let Some(v) = f.take("certificate_path") {
        if options.get("root_certificates").is_some() {
            return Err(error(
                &f.path,
                "certificate and certificate_path cannot both be set",
            ));
        }
        options["root_certificates"] = json!([v]);
    }
    if !options.as_object().unwrap().is_empty() {
        out["options"] = options;
    }
    f.copy("alpn", &mut out, "alpn_protocols");
    if out.get("alpn_protocols").is_none()
        && (kind == "naive" || matches!(out["protocol"]["kind"].as_str(), Some("grpc" | "http2")))
    {
        out["alpn_protocols"] = json!([if quic { "h3" } else { "h2" }]);
    }
    f.copy("curve_preferences", &mut out, "key_exchange_groups");
    for (inline, file, target) in [
        ("client_certificate", "client_certificate_path", "cert"),
        ("client_key", "client_key_path", "key"),
    ] {
        f.copy(inline, &mut out, target);
        if let Some(v) = f.take(file) {
            if out.get(target).is_some() {
                return Err(error(
                    &f.path,
                    "inline client credential and path cannot both be set",
                ));
            }
            out[target] = v;
        }
    }
    if let Some(reality) = f.take("reality") {
        let mut r = Fields::new(reality, &format!("{}.reality", f.path))?;
        if r.boolean("enabled", false)? {
            if quic {
                return Err(error(&r.path, "REALITY requires TCP"));
            }
            if out.get("options").is_some() || out.get("cert").is_some() || out.get("key").is_some()
            {
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
    for key in ["fragment", "record_fragment", "kernel_tx", "kernel_rx"] {
        f.default_only(key, &[json!(false)])?;
    }
    if let Some(utls) = f.take("utls") {
        let mut u = Fields::new(utls, &format!("{}.utls", f.path))?;
        if u.boolean("enabled", false)? {
            return Err(error(
                &u.path,
                "browser TLS fingerprints are not implemented",
            ));
        }
        u.finish()?;
    }
    if let Some(ech) = f.take("ech") {
        let mut e = Fields::new(ech, &format!("{}.ech", f.path))?;
        if e.boolean("enabled", false)? {
            return Err(error(&e.path, "ECH is not implemented"));
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

fn byte_size(value: Value, path: &str) -> Result<u32> {
    if let Some(n) = value.as_u64() {
        return u32::try_from(n).map_err(|_| error(path, "byte size overflow"));
    }
    let value = value
        .as_str()
        .ok_or_else(|| error(path, "expected byte count or size string"))?
        .trim();
    let split = value
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(value.len());
    let number: f64 = value[..split]
        .parse()
        .map_err(|_| error(path, "invalid byte size"))?;
    let unit = value[split..].trim().to_ascii_lowercase();
    let factor = match unit.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1000.0,
        "m" | "mb" => 1e6,
        "g" | "gb" => 1e9,
        "ki" | "kib" => 1024.0,
        "mi" | "mib" => 1048576.0,
        "gi" | "gib" => 1073741824.0,
        _ => return Err(error(path, "unknown byte size unit")),
    };
    let size = number * factor;
    if !size.is_finite() || size < 0.0 || size > u32::MAX as f64 {
        return Err(error(path, "byte size overflow"));
    }
    Ok(size as u32)
}
