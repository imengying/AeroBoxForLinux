use super::{Fields, Result, address, error, seconds, strings};
use serde_json::{Value, json};

/// Convert a single Android/sing-box outbound into a named Rust client group.
/// Returns an error for every field that cannot be represented faithfully.
pub fn convert_outbound(value: Value, path: &str) -> Result<Value> {
    let port = super::server_port(&value);
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
        f.take("server_port");
        let port =
            port.ok_or_else(|| error(format!("{path}.server_port"), "required port in 1..65535"))?;
        client["address"] = address(&server, u64::from(port), path)?.into();
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
    let mut vless_encryption = false;
    let mut protocol = match kind.as_str() {
        "direct" => json!({"type":"direct"}),
        "shadowsocks" => {
            let mut p = json!({"type":"shadowsocks", "cipher":f.text("method")?, "password":f.text("password")?, "udp_enabled":udp});
            if let Some(plugin) = super::ss_plugin::convert(&mut f)? {
                p["plugin"] = plugin;
            }
            p
        }
        "vmess" => {
            let alter_id = f.take("alter_id").unwrap_or(json!(0));
            let alter_id = alter_id
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| {
                    error(
                        format!("{path}.alter_id"),
                        "expected an integer in 0..65535",
                    )
                })?;
            let global_padding = f.boolean("global_padding", false)?;
            let authenticated_length = f.boolean("authenticated_length", false)?;
            let packet_encoding = packet_encoding(&mut f, false)?;
            let cipher = f.string("security")?.unwrap_or("auto".into());
            let cipher = if cipher.is_empty() || cipher == "auto" {
                "any".into()
            } else {
                cipher
            };
            json!({"type":"vmess", "cipher":cipher, "user_id":f.text("uuid")?, "alter_id":alter_id, "global_padding":global_padding, "authenticated_length":authenticated_length, "udp_enabled":udp, "packet_encoding":packet_encoding})
        }
        "vless" => {
            let encryption = f.string("encryption")?.unwrap_or_else(|| "none".into());
            vless_encryption = !matches!(encryption.as_str(), "" | "none");
            let packet_encoding = packet_encoding(&mut f, true)?;
            let flow = f.string("flow")?.unwrap_or_default();
            if !["", "xtls-rprx-vision"].contains(&flow.as_str()) {
                return Err(error(format!("{path}.flow"), "unsupported VLESS flow"));
            }
            vision = flow == "xtls-rprx-vision";
            if vision && udp && packet_encoding != "xudp" {
                return Err(error(
                    format!("{path}.packet_encoding"),
                    "VLESS Vision requires XUDP for UDP payloads",
                ));
            }
            json!({"type":"vless", "user_id":f.text("uuid")?, "encryption":encryption, "vision":vision && vless_encryption, "udp_enabled":udp, "packet_encoding":packet_encoding})
        }
        "trojan" => json!({"type":"trojan", "password":f.text("password")?, "udp_enabled":udp}),
        "anytls" => {
            let mut p = json!({"type":"anytls", "password":f.text("password")?, "udp_enabled":udp});
            f.copy("client_metadata", &mut p, "client_metadata");
            // AnyTLS carries UDP inside its multiplexed TLS session using
            // UoT v2. It must not be wrapped in another UoT transport.
            if let Some(uot) = f.take("udp_over_tcp") {
                let enabled = match uot {
                    Value::Bool(enabled) => enabled,
                    value => {
                        let mut options = Fields::new(value, &format!("{path}.udp_over_tcp"))?;
                        let enabled = options.boolean("enabled", false)?;
                        options.default_only("version", &[json!(2)])?;
                        options.finish()?;
                        enabled
                    }
                };
                if !enabled {
                    p["udp_enabled"] = false.into();
                }
            }
            for (src, dst) in [
                (
                    "idle_session_check_interval",
                    "idle_session_check_interval_secs",
                ),
                ("idle_session_timeout", "idle_session_timeout_secs"),
            ] {
                if let Some(v) = f.take(src).filter(|value| value != "") {
                    let interval = seconds(v, &format!("{path}.{src}"))?;
                    if interval != 0 {
                        p[dst] = interval.into();
                    }
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
            let ports = f
                .take("server_ports")
                .map(|ports| strings(ports, &format!("{path}.server_ports")))
                .transpose()?
                .unwrap_or_default();
            if !ports.is_empty() {
                let ports = ports
                    .iter()
                    .map(|v| v.replace(':', "-"))
                    .collect::<Vec<_>>()
                    .join(",");
                let mut hopping = json!({"ports":ports});
                let interval = f
                    .take("hop_interval")
                    .filter(|value| value != "")
                    .map(|v| seconds(v, &format!("{path}.hop_interval")))
                    .transpose()?
                    .filter(|v| *v != 0);
                let max = f
                    .take("hop_interval_max")
                    .filter(|value| value != "")
                    .map(|v| seconds(v, &format!("{path}.hop_interval_max")))
                    .transpose()?
                    .filter(|v| *v != 0);
                if let Some(max) = max {
                    hopping["min_interval_secs"] = interval.unwrap_or(30).into();
                    hopping["max_interval_secs"] = max.into();
                } else if let Some(interval) = interval {
                    hopping["interval_secs"] = interval.into();
                }
                p["hopping"] = hopping;
            } else {
                for key in ["hop_interval", "hop_interval_max"] {
                    if let Some(value) = f.take(key).filter(|value| value != "")
                        && seconds(value, &format!("{path}.{key}"))? != 0
                    {
                        return Err(error(format!("{path}.{key}"), "requires server_ports"));
                    }
                }
            }
            f.default_only("disable_chrome_parrot", &[json!(true)])?;
            f.default_only("brutal_debug", &[json!(false)])?;
            p
        }
        "tuic" => {
            let mut p = json!({"type":"tuic", "uuid":f.text("uuid")?, "password":f.text("password")?, "udp_enabled":udp});
            let udp_over_stream = f.boolean("udp_over_stream", false)?;
            let relay_mode = f.string("udp_relay_mode")?.filter(|v| !v.is_empty());
            if udp_over_stream && relay_mode.is_some() {
                return Err(error(
                    format!("{path}.udp_relay_mode"),
                    "cannot be combined with udp_over_stream",
                ));
            }
            if let Some(mode) = relay_mode {
                if !matches!(mode.as_str(), "native" | "quic") {
                    return Err(error(
                        format!("{path}.udp_relay_mode"),
                        "expected native or quic",
                    ));
                }
                p["udp_relay_mode"] = mode.into();
            }
            p["udp_over_stream"] = udp_over_stream.into();
            if let Some(v) = f.take("heartbeat").filter(|value| value != "") {
                let interval = parse_duration_millis(v, &format!("{path}.heartbeat"))?;
                if interval != 0 {
                    p["heartbeat_interval_ms"] = interval.into();
                }
            }
            f.copy("zero_rtt_handshake", &mut p, "zero_rtt_handshake");
            if let Some(value) = f
                .string("congestion_control")?
                .filter(|value| !value.is_empty())
            {
                p["congestion_control"] = value.into();
            }
            p
        }
        "naive" => {
            let quic = f.boolean("quic", false)?;
            let mut settings = json!({"quic":quic});
            for key in ["congestion_control", "quic_congestion_control"] {
                if let Some(value) = f.string(key)?.filter(|value| !value.is_empty()) {
                    if settings.get("quic_congestion_control").is_some() {
                        return Err(error(
                            format!("{path}.{key}"),
                            "congestion control specified twice",
                        ));
                    }
                    settings["quic_congestion_control"] = value.into();
                }
            }
            f.copy("extra_headers", &mut settings, "extra_headers");
            if let Some(concurrency) = f.take("insecure_concurrency") {
                settings["insecure_concurrency"] = if concurrency == 0 {
                    1.into()
                } else {
                    concurrency
                };
            }
            super::naive::windows(&mut f, &mut settings, quic)?;
            json!({"type":"naiveproxy", "settings":settings, "username":f.string("username")?.unwrap_or_default(), "password":f.string("password")?.unwrap_or_default(), "udp_enabled":udp})
        }
        "socks" | "http" => {
            let mut p = json!({"type":kind});
            f.copy("username", &mut p, "username");
            f.copy("password", &mut p, "password");
            if ["username", "password"].iter().all(|field| {
                p.get(field)
                    .is_none_or(|value| value.is_null() || value == "")
            }) {
                // Empty credentials exported by subscription clients mean no
                // authentication, not an explicit empty username/password pair.
                let values = p.as_object_mut().unwrap();
                values.remove("username");
                values.remove("password");
            }
            if kind == "socks" {
                if p.get("username").is_some() || p.get("password").is_some() {
                    for field in ["username", "password"] {
                        if !p[field]
                            .as_str()
                            .is_some_and(|value| (1..=255).contains(&value.len()))
                        {
                            return Err(error(
                                format!("{path}.{field}"),
                                "SOCKS5 authentication requires 1–255 UTF-8 bytes for each credential",
                            ));
                        }
                    }
                }
                p["udp_enabled"] = udp.into();
                f.default_only("version", &[json!(""), json!("5")])?;
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
        let mut out = json!({});
        for key in [
            "protocol",
            "max_connections",
            "min_streams",
            "max_streams",
            "padding",
        ] {
            mux.copy(key, &mut out, key);
        }
        if out["protocol"] == "" {
            out.as_object_mut().unwrap().remove("protocol");
        }
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
            if kind == "shadowsocks" {
                protocol = json!({"type":"multiplex","settings":out,"protocol":protocol});
            } else {
                protocol["h2mux"] = out;
            }
        }
        mux.finish()?;
    }
    let tls = f.take("tls");
    let has_tls = tls
        .as_ref()
        .and_then(|v| v.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if vision && !has_tls && !vless_encryption {
        return Err(error(
            format!("{path}.flow"),
            "VLESS Vision requires TLS, REALITY or VLESS encryption",
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
    let plugin_quic = super::ss_plugin::uses_quic(&protocol);
    if plugin_quic && (has_tls || f.values.contains_key("transport")) {
        return Err(error(
            path,
            "v2ray-plugin QUIC configures its own TLS and transport through plugin_opts",
        ));
    }
    let mut quic_transport = native_quic || plugin_quic;
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
        let (wrapped, quic) = super::tls::configure(
            tls,
            protocol,
            quic_transport,
            &kind,
            vision && !vless_encryption,
            path,
        )?;
        protocol = wrapped;
        if let Some(quic) = quic {
            client["quic_settings"] = quic;
        }
    }
    if quic_transport {
        client["transport"] = "quic".into();
    }
    if matches!(kind.as_str(), "hysteria2" | "tuic") {
        super::quic::configure(&mut f, &mut client)?;
    }
    dial_options(&mut f, &mut client, quic_transport)?;
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

fn dial_options(f: &mut Fields, client: &mut Value, quic: bool) -> Result<()> {
    let mut options = json!({});
    for key in ["tcp_fast_open", "tcp_multi_path", "udp_fragment"] {
        if f.values.contains_key(key) {
            let enabled = f.boolean(key, false)?;
            if quic && enabled && key != "udp_fragment" {
                return Err(error(
                    format!("{}.{}", f.path, key),
                    "TCP options require a TCP transport",
                ));
            }
            options[key] = enabled.into();
        }
    }
    if !options.as_object().unwrap().is_empty() {
        client["dial_options"] = options;
    }
    if let Some(value) = f.take("connect_timeout").filter(|value| value != "") {
        let millis = parse_duration_millis(value, &format!("{}.connect_timeout", f.path))?;
        if millis != 0 {
            client["connect_timeout_ms"] = millis.into();
        }
    }
    let disable_keep_alive = f.boolean("disable_tcp_keep_alive", false)?;
    if quic && disable_keep_alive {
        return Err(error(
            format!("{}.disable_tcp_keep_alive", f.path),
            "TCP keepalive does not apply to QUIC transport",
        ));
    }
    let mut tcp = json!({});
    if disable_keep_alive {
        tcp["keep_alive"] = false.into();
    }
    for (field, target) in [
        ("tcp_keep_alive", "keep_alive_time_secs"),
        ("tcp_keep_alive_interval", "keep_alive_interval_secs"),
    ] {
        if let Some(value) = f.take(field).filter(|value| value != "") {
            let path = format!("{}.{}", f.path, field);
            if quic {
                return Err(error(
                    path,
                    "TCP keepalive does not apply to QUIC transport",
                ));
            }
            let millis = parse_duration_millis(value, &path)?;
            if millis == 0 {
                continue;
            }
            let seconds = millis.div_ceil(1000);
            if seconds > 32767 {
                return Err(error(
                    path,
                    "TCP keepalive must round up to 1..32767 seconds",
                ));
            }
            tcp[target] = seconds.into();
        }
    }
    if !tcp.as_object().unwrap().is_empty() {
        client["tcp_settings"] = tcp;
    }
    Ok(())
}

/// Android duration strings use Go's unit notation. Preserve fractions and
/// compound values exactly; socket deadlines have millisecond precision.
pub(super) fn parse_duration_millis(value: Value, path: &str) -> Result<u32> {
    let invalid = || {
        error(
            path,
            "expected a non-negative duration in whole milliseconds (for example 0s, 250ms, 1.5s)",
        )
    };
    let text = value.as_str().ok_or_else(invalid)?;
    if matches!(text, "0" | "+0") {
        return Ok(0);
    }
    let mut remaining = text.strip_prefix('+').unwrap_or(text);
    let mut nanos = 0u128;
    while !remaining.is_empty() {
        let end = remaining
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .ok_or_else(invalid)?;
        let (number, rest) = remaining.split_at(end);
        let (unit, multiplier) = [
            ("ns", 1u128),
            ("us", 1_000),
            ("µs", 1_000),
            ("μs", 1_000),
            ("ms", 1_000_000),
            ("s", 1_000_000_000),
            ("m", 60_000_000_000),
            ("h", 3_600_000_000_000),
        ]
        .into_iter()
        .find(|(unit, _)| rest.starts_with(unit))
        .ok_or_else(invalid)?;
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if (whole.is_empty() && fraction.is_empty())
            || fraction.len() > 9
            || !fraction.bytes().all(|v| v.is_ascii_digit())
        {
            return Err(invalid());
        }
        let whole = if whole.is_empty() {
            0
        } else {
            whole.parse::<u128>().map_err(|_| invalid())?
        };
        let fraction = if fraction.is_empty() {
            0
        } else {
            let divisor = 10u128.pow(fraction.len() as u32);
            let product = fraction
                .parse::<u128>()
                .map_err(|_| invalid())?
                .checked_mul(multiplier)
                .ok_or_else(invalid)?;
            if !product.is_multiple_of(divisor) {
                return Err(invalid());
            }
            product / divisor
        };
        nanos = whole
            .checked_mul(multiplier)
            .and_then(|whole| whole.checked_add(fraction))
            .and_then(|part| nanos.checked_add(part))
            .ok_or_else(invalid)?;
        remaining = &rest[unit.len()..];
    }
    if (nanos == 0 && (text.is_empty() || text == "+")) || !nanos.is_multiple_of(1_000_000) {
        return Err(invalid());
    }
    u32::try_from(nanos / 1_000_000)
        .map_err(|_| error(path, "duration exceeds 4294967295 milliseconds"))
}

fn packet_encoding(f: &mut Fields, default_xudp: bool) -> Result<String> {
    let encoding = f.string("packet_encoding")?.unwrap_or_else(|| {
        if default_xudp {
            "xudp".into()
        } else {
            String::new()
        }
    });
    if !matches!(encoding.as_str(), "" | "xudp" | "packetaddr") {
        return Err(error(
            format!("{}.packet_encoding", f.path),
            "supported UDP encodings are an empty string, xudp or packetaddr",
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
        if let Some(path) = f.string("path")?.filter(|v| !v.is_empty()) {
            out["matching_path"] = path.into();
        }
        if let Some(headers) = f.take("headers") {
            let mut headers = headers
                .as_object()
                .cloned()
                .ok_or_else(|| error(format!("{}.headers", f.path), "expected headers object"))?;
            headers.retain(|key, value| !(key.eq_ignore_ascii_case("host") && value == ""));
            out["matching_headers"] = headers.into();
        }
        f.copy("max_early_data", &mut out, "max_early_data");
        f.copy("early_data_header_name", &mut out, "early_data_header_name");
    } else {
        if kind == "grpc" {
            f.default_only("path", &[json!(""), json!("/")])?;
            f.default_only("method", &[json!(""), json!("POST")])?;
            f.copy("service_name", &mut out, "service_name");
        } else {
            f.default_only("service_name", &[json!("")])?;
            if let Some(path) = f.string("path")?.filter(|v| !v.is_empty()) {
                out["path"] = path.into();
            }
            if kind == "httpupgrade" {
                f.default_only("method", &[json!(""), json!("GET")])?;
            } else if let Some(method) = f.string("method")?.filter(|v| !v.is_empty()) {
                out["method"] = method.into();
            }
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
            let hosts = strings(host, &format!("{}.host", f.path))?;
            if kind != "http" && hosts.len() > 1 {
                return Err(error(
                    format!("{}.host", f.path),
                    "multiple hosts require HTTP transport",
                ));
            }
            if !hosts.is_empty() {
                out["host"] = hosts.into();
            }
        }
        if out["kind"] == "http2" || out["kind"] == "grpc" {
            for (key, target) in [
                ("idle_timeout", "idle_timeout_ms"),
                ("ping_timeout", "ping_timeout_ms"),
            ] {
                if let Some(value) = f.take(key).filter(|value| value != "") {
                    out[target] =
                        parse_duration_millis(value, &format!("{}.{key}", f.path))?.into();
                }
            }
        }
        if kind == "grpc" {
            out["permit_without_stream"] = f.boolean("permit_without_stream", false)?.into();
        } else {
            f.default_only("permit_without_stream", &[json!(false)])?;
        }
    }
    f.finish()?;
    Ok((out, false))
}

pub(super) fn byte_size(value: Value, path: &str) -> Result<u32> {
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
