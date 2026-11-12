use crate::model::validate_nodes;
use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use url::Url;

fn decode(text: &str) -> Result<String> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    for e in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(b) = e.decode(&text) {
            return Ok(String::from_utf8(b)?);
        }
    }
    bail!("无效的 Base64 订阅")
}
fn unescape(text: &str) -> String {
    percent_encoding::percent_decode_str(text)
        .decode_utf8_lossy()
        .into_owned()
}
fn number(v: &Value) -> u64 {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

pub fn parse(body: &str) -> Result<Vec<Value>> {
    parse_inner(body, false).map(|(nodes, _)| nodes)
}

/// Subscription downloads and scheduled refreshes keep every usable node and
/// report the rest. This mirrors the Android app: one exotic proxy should not
/// discard an otherwise usable subscription.
pub fn parse_with_skips(body: &str) -> Result<(Vec<Value>, Vec<String>)> {
    parse_inner(body, true)
}

fn parse_inner(body: &str, tolerant: bool) -> Result<(Vec<Value>, Vec<String>)> {
    let body = body.trim_start_matches('\u{feff}').trim();
    let mut skipped = vec![];
    if let Ok(value) = serde_yaml_ng::from_str::<Value>(body)
        && let Some(items) = value
            .as_array()
            .or_else(|| value["outbounds"].as_array())
            .or_else(|| value["proxies"].as_array())
    {
        let mut nodes = vec![];
        for v in items {
            let result = if v.get("name").is_some() {
                clash_nodes(v)
            } else {
                Ok(vec![v.clone()])
            };
            match result {
                Ok(parsed) => nodes.extend(parsed),
                Err(error) if tolerant => skipped.push(format!("{error:#}")),
                Err(error) => return Err(error),
            }
        }
        ensure!(
            !nodes.is_empty(),
            "订阅没有可用的节点{}",
            skip_hint(&skipped)
        );
        validate_nodes(&nodes)?;
        return Ok((nodes, skipped));
    }
    let decoded = if !body.contains("://") {
        decode(body)?
    } else {
        body.to_owned()
    };
    let mut nodes = vec![];
    for (index, line) in decoded
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate()
    {
        match uri_nodes(line) {
            Ok(parsed) => nodes.extend(parsed),
            Err(error) if tolerant => skipped.push(format!("{error:#}")),
            Err(error) => return Err(error.context(format!("第 {} 个节点", index + 1))),
        }
    }
    ensure!(
        !nodes.is_empty(),
        "订阅没有可用的节点{}",
        skip_hint(&skipped)
    );
    validate_nodes(&nodes)?;
    Ok((nodes, skipped))
}

/// A single link can expand into more than one outbound: a Shadowsocks node
/// tunnelled through ShadowTLS is a pair, with the ShadowTLS outbound acting as
/// its `detour`.
fn uri_nodes(input: &str) -> Result<Vec<Value>> {
    let (ss, shadowtls) = split_shadowtls_plugin(input)?;
    let Some(shadowtls) = shadowtls else {
        return uri(input).map(|node| vec![node]);
    };
    Ok(vec![ss, shadowtls])
}

fn clash_nodes(v: &Value) -> Result<Vec<Value>> {
    let (ss, shadowtls) = split_clash_shadowtls(v)?;
    let Some(shadowtls) = shadowtls else {
        return clash(v).map(|node| vec![node]);
    };
    Ok(vec![clash(&ss)?, shadowtls])
}

/// `ss://…?plugin=shadow-tls;host=…;password=…;version=3` describes a
/// Shadowsocks server reached through a ShadowTLS camouflage layer. sing-box
/// models it as two outbounds: ShadowTLS carries the TLS session and the
/// Shadowsocks outbound points at it with `detour`.
fn split_shadowtls_plugin(input: &str) -> Result<(Value, Option<Value>)> {
    let Ok(url) = Url::parse(input) else {
        return Ok((uri(input)?, None));
    };
    if !matches!(url.scheme(), "ss") || url.scheme() == "https" {
        return Ok((uri(input)?, None));
    }
    let plugin = url
        .query_pairs()
        .find(|(key, _)| key == "plugin")
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    let Some(options) = plugin.strip_prefix("shadow-tls") else {
        return Ok((uri(input)?, None));
    };
    let options = options.trim_start_matches(';');
    let mut host = String::new();
    let mut password = String::new();
    let mut version = 3u64;
    for item in options.split(';') {
        let Some((key, value)) = item.split_once('=') else {
            continue;
        };
        match key.trim() {
            "host" => host = value.trim().to_owned(),
            "password" => password = value.trim().to_owned(),
            "version" => version = value.trim().parse().unwrap_or(3),
            _ => {}
        }
    }
    ensure!(
        !password.is_empty(),
        "ShadowTLS 插件缺少密码，无法转换为 ShadowTLS 节点"
    );
    let server = url.host_str().context("节点缺少服务器")?;
    let port = url.port_or_known_default().unwrap_or(443);
    let tag = unescape(url.fragment().unwrap_or(server));
    let shadowtls = shadowtls_node(server, u64::from(port), &password, version, &host, &tag);
    // The Shadowsocks outbound keeps its own tag and gains a detour reference.
    let mut plain = url.clone();
    plain.set_query(None);
    let mut ss = uri(plain.as_str())?;
    ss["tag"] = json!(&tag);
    ss["detour"] = json!(shadowtls["tag"]);
    Ok((ss, Some(shadowtls)))
}

fn split_clash_shadowtls(v: &Value) -> Result<(Value, Option<Value>)> {
    if v["plugin"].as_str() != Some("shadow-tls") {
        return Ok((v.clone(), None));
    }
    let options = v.get("plugin-opts").or_else(|| v.get("plugin_opts"));
    let field = |key: &str| {
        options
            .and_then(|options| options.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let password = field("password");
    ensure!(
        !password.is_empty(),
        "ShadowTLS 插件缺少密码，无法转换为 ShadowTLS 节点"
    );
    let version = options
        .and_then(|options| options.get("version"))
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
        .unwrap_or(3);
    let name = v["name"].as_str().unwrap_or("ShadowTLS");
    let server = v["server"].as_str().context("节点缺少服务器")?;
    let port = number(&v["port"]);
    let shadowtls = shadowtls_node(server, port, &password, version, &field("host"), name);
    let mut ss = v.clone();
    if let Some(options) = ss.as_object_mut() {
        options.remove("plugin");
        options.remove("plugin-opts");
        options.remove("plugin_opts");
    }
    ss["name"] = json!(name);
    ss["detour"] = json!(shadowtls["tag"]);
    Ok((ss, Some(shadowtls)))
}

fn shadowtls_node(
    server: &str,
    port: u64,
    password: &str,
    version: u64,
    host: &str,
    name: &str,
) -> Value {
    let mut node = json!({
        "type":"shadowtls",
        "tag":format!("{name} · ShadowTLS"),
        "server":server,
        "server_port":port,
        "version":version,
        "password":password
    });
    if version >= 2 {
        let mut tls = json!({"enabled":true});
        if !host.is_empty() {
            tls["server_name"] = json!(host)
        }
        node["tls"] = tls;
    }
    node
}

fn skip_hint(skipped: &[String]) -> String {
    if skipped.is_empty() {
        return String::new();
    }
    // A short, de-duplicated sample explains the common cause without dumping
    // every line of a large subscription.
    let mut reasons: Vec<&str> = skipped
        .iter()
        .map(|reason| reason.split(':').next().unwrap_or(reason).trim())
        .collect();
    reasons.dedup();
    let sample = reasons
        .iter()
        .take(2)
        .copied()
        .collect::<Vec<_>>()
        .join("；");
    format!("（跳过 {} 个不支持的节点：{sample}）", skipped.len())
}
/// User-triggered URL, app share link or node content; never a clipboard path.
pub fn import_input(input: &str) -> Result<crate::model::Subscription> {
    let input = input.trim_start_matches('\u{feff}').trim();
    ensure!(!input.is_empty(), "请粘贴订阅链接或节点内容");
    let mut source = input.to_owned();
    let mut name = None;
    if let Some(wrapped) = input.strip_prefix("hiddify://import/") {
        source = if wrapped.starts_with("http://") || wrapped.starts_with("https://") {
            wrapped.to_owned()
        } else {
            unescape(wrapped)
        };
    } else if input.starts_with("sing-box://import-remote-profile")
        || input.starts_with("clash://install-config")
    {
        let wrapped = Url::parse(input).context("导入链接无效")?;
        source = wrapped
            .query_pairs()
            .find(|(k, _)| k == "url")
            .map(|(_, v)| v.into_owned())
            .context("导入链接缺少订阅地址")?;
        name = wrapped
            .query_pairs()
            .find(|(k, _)| k == "name")
            .map(|(_, v)| v.into_owned());
        if name.is_none() {
            name = wrapped.fragment().map(unescape);
        }
    }
    if source.starts_with("http://") || source.starts_with("https://") {
        let mut url = Url::parse(&source).context("订阅地址无效")?;
        ensure!(
            url.host().is_some() && !source.contains(['\n', '\r']),
            "订阅地址无效"
        );
        if name.is_none() {
            name = url.fragment().map(unescape);
        }
        url.set_fragment(None);
        Ok(crate::model::Subscription {
            name: name
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| "新订阅".into()),
            source: url.to_string(),
            ..Default::default()
        })
    } else {
        ensure!(source == input, "导入链接须指向 HTTP 或 HTTPS 订阅");
        let nodes = parse(input)?;
        let name = if nodes.len() == 1 {
            nodes[0]["tag"].as_str().unwrap_or("本地订阅").to_owned()
        } else {
            "本地订阅".into()
        };
        Ok(crate::model::Subscription {
            name,
            nodes,
            auto_update: false,
            updated: crate::model::now(),
            ..Default::default()
        })
    }
}

pub fn uri(input: &str) -> Result<Value> {
    if let Some(v) = input.strip_prefix("vmess://") {
        let v: Value = serde_json::from_str(&decode(v)?)?;
        let mut node = json!({"type":"vmess","tag":v["ps"].as_str().unwrap_or("VMess"),"server":v["add"],"server_port":number(&v["port"]),"uuid":v["id"],"security":"auto","alter_id":number(&v["aid"])});
        if v["tls"] == "tls" {
            node["tls"] = json!({"enabled":true,"server_name":v["sni"].as_str().unwrap_or("")})
        }
        match v["net"].as_str().unwrap_or("tcp") {
            "tcp" | "" => {}
            "ws" => {
                node["transport"] = json!({"type":"ws","path":v["path"].as_str().unwrap_or("/"),"headers":{"Host":v["host"].as_str().unwrap_or("")}})
            }
            "grpc" => {
                node["transport"] =
                    json!({"type":"grpc","service_name":v["path"].as_str().unwrap_or("")})
            }
            "http" | "h2" => {
                node["transport"] = json!({"type":"http","path":v["path"].as_str().unwrap_or("/"),"host":v["host"].as_str().unwrap_or("")})
            }
            other => bail!("不支持 VMess 传输: {other}"),
        };
        validate_server(&node)?;
        return Ok(node);
    }
    let mut raw = input.to_string();
    if let Some(ss) = input.strip_prefix("ss://") {
        let (authority, tag) = ss.split_once('#').unwrap_or((ss, ""));
        if !authority.contains('@') {
            raw = format!("ss://{}#{}", decode(authority.trim_end_matches('/'))?, tag)
        }
    }
    let u = Url::parse(&raw)?;
    let typ = match u.scheme() {
        "ss" => "shadowsocks",
        "hy2" => "hysteria2",
        "socks5" => "socks",
        "https" => "http",
        // Naive is exposed as plain HTTPS/QUIC over HTTP/2 or HTTP/3.
        "naive+https" | "naive" => "naive",
        "naive+quic" => "naive",
        "snell" => "snell",
        other => other,
    };
    ensure!(
        [
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "hysteria2",
            "tuic",
            "anytls",
            "naive",
            "shadowtls",
            "snell",
            "socks",
            "http"
        ]
        .contains(&typ),
        "不支持的节点协议: {typ}"
    );
    let server = u
        .host_str()
        .context("节点缺少服务器")?
        .trim_matches(['[', ']']);
    let port = u.port_or_known_default().unwrap_or(443);
    let tag = unescape(u.fragment().unwrap_or(server));
    let mut node = json!({"type":typ,"tag":tag,"server":server,"server_port":port});
    let q = |key: &str| {
        u.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    };
    let user = unescape(u.username());
    let pass = unescape(u.password().unwrap_or(""));
    match typ {
        "shadowsocks" => {
            let credentials = if pass.is_empty() {
                decode(&user)?
            } else {
                format!("{user}:{pass}")
            };
            let (method, password) = credentials
                .split_once(':')
                .context("无效 Shadowsocks 凭据")?;
            node["method"] = json!(method);
            node["password"] = json!(password);
            if !q("plugin").is_empty() {
                let p = q("plugin");
                let (plugin, opts) = p.split_once(';').unwrap_or((&p, ""));
                node["plugin"] = json!(supported_plugin(plugin)?);
                node["plugin_opts"] = json!(opts)
            }
        }
        "vless" => {
            node["uuid"] = json!(user);
            if !q("flow").is_empty() {
                node["flow"] = json!(q("flow"))
            }
        }
        "trojan" | "hysteria2" => {
            node["password"] = json!(if pass.is_empty() {
                user
            } else {
                format!("{user}:{pass}")
            });
            if !q("obfs").is_empty() {
                node["obfs"] = json!({"type":q("obfs"),"password":q("obfs-password")})
            }
        }
        "tuic" => {
            node["uuid"] = json!(user);
            node["password"] = json!(pass);
            if !q("congestion_control").is_empty() {
                node["congestion_control"] = json!(q("congestion_control"))
            }
        }
        "anytls" => {
            node["password"] = json!(if pass.is_empty() {
                user
            } else {
                format!("{user}:{pass}")
            })
        }
        "naive" => {
            if !user.is_empty() {
                node["username"] = json!(user);
                node["password"] = json!(pass)
            };
            // naive+quic or ?quic=1 switches the outbound to HTTP/3.
            let quic = u.scheme() == "naive+quic" || q("quic") == "1";
            if quic {
                node["quic"] = json!(true);
                if !q("congestion_control").is_empty() {
                    node["quic_congestion_control"] = json!(q("congestion_control"))
                }
            }
        }
        "shadowtls" => {
            // shadowtls://password@host:port?version=3&sni=…&detour=…
            // Version 2+ requires TLS with the camouflage host name.
            node["password"] = json!(if pass.is_empty() {
                user
            } else {
                format!("{user}:{pass}")
            });
            if !q("version").is_empty() {
                ensure!(q("version") == "3", "ShadowTLS 仅支持 v3");
            }
            node["version"] = json!(3);
            if !q("detour").is_empty() {
                node["detour"] = json!(q("detour"))
            }
        }
        "snell" => {
            // snell://psk@host:port?version=6&userkey=…&mode=…
            if !q("version").is_empty() {
                ensure!(q("version") == "6", "Snell 仅支持 v6");
            }
            node["psk"] = json!(if pass.is_empty() {
                user
            } else {
                format!("{user}:{pass}")
            });
            node["version"] = json!(6);
            if !q("userkey").is_empty() {
                node["userkey"] = json!(q("userkey"))
            }
            if q("reuse") == "1" || q("reuse") == "true" {
                node["reuse"] = json!(true)
            }
            if !q("mode").is_empty() {
                node["mode"] = json!(q("mode"))
            }
        }
        "socks" | "http" if !user.is_empty() => {
            node["username"] = json!(user);
            node["password"] = json!(pass)
        }
        _ => {}
    }
    // Every ShadowTLS version runs TLS; v2+ also pins the camouflage host name.
    let shadowtls_tls = typ == "shadowtls";
    if ["trojan", "hysteria2", "tuic", "anytls", "naive"].contains(&typ)
        || shadowtls_tls
        || u.scheme() == "https"
        || ["tls", "reality"].contains(&q("security").as_str())
    {
        let mut tls = json!({"enabled":true});
        if !q("sni").is_empty() {
            tls["server_name"] = json!(q("sni"))
        };
        if q("insecure") == "1" || q("allowInsecure") == "1" {
            tls["insecure"] = json!(true)
        }
        // Naive manages HTTP/2 vs HTTP/3 itself and rejects an explicit ALPN.
        if typ != "naive" && !q("alpn").is_empty() {
            tls["alpn"] = json!(q("alpn").split(',').collect::<Vec<_>>())
        };
        if !q("fp").is_empty() {
            tls["utls"] = json!({"enabled":true,"fingerprint":q("fp")})
        }
        if q("security") == "reality" {
            // Reality requires uTLS; a missing fingerprint would make the
            // generated config fail validation.
            if tls.get("utls").is_none() {
                tls["utls"] = json!({"enabled":true,"fingerprint":"chrome"})
            }
            tls["reality"] = json!({"enabled":true,"public_key":q("pbk"),"short_id":q("sid")})
        };
        node["tls"] = tls;
    }
    match q("type").as_str() {
        "" | "tcp" => {}
        "ws" => {
            node["transport"] = json!({"type":"ws","path":q("path"),"headers":{"Host":q("host")}})
        }
        "grpc" => node["transport"] = json!({"type":"grpc","service_name":q("serviceName")}),
        "httpupgrade" => {
            node["transport"] = json!({"type":"httpupgrade","host":q("host"),"path":q("path")})
        }
        "http" | "h2" => {
            node["transport"] = json!({"type":"http","host":q("host"),"path":q("path")})
        }
        other => bail!("不支持的传输方式: {other}"),
    }
    validate_server(&node)?;
    Ok(node)
}
fn validate_server(node: &Value) -> Result<()> {
    ensure!(
        node["server"].as_str().is_some_and(|s| !s.is_empty()),
        "节点服务器为空"
    );
    ensure!(
        (1..=65535).contains(&number(&node["server_port"])),
        "节点端口无效"
    );
    Ok(())
}

fn supported_plugin(plugin: &str) -> Result<&str> {
    match plugin {
        "obfs" | "simple-obfs" | "obfs-local" => Ok("obfs-local"),
        "v2ray-plugin" => Ok("v2ray-plugin"),
        "shadow-tls" => bail!("ShadowTLS 须作为独立节点导出，不能作为 Shadowsocks 插件"),
        _ => bail!("此 Shadowsocks 插件不受支持（支持 obfs-local 和 v2ray-plugin）"),
    }
}

fn plugin_options(value: &Value, plugin: &str) -> Result<String> {
    if let Some(text) = value.as_str() {
        return Ok(text.into());
    }
    let options = value
        .as_object()
        .context("Shadowsocks 插件参数须为文本或对象")?;
    let mut output = Vec::new();
    for (key, value) in options {
        let key = if plugin == "obfs-local" {
            match key.as_str() {
                "mode" => "obfs",
                "host" => "obfs-host",
                other => other,
            }
        } else {
            key.as_str()
        };
        ensure!(!key.contains([';', '=']), "插件参数名称无效");
        match value {
            Value::Bool(true) => output.push(key.to_owned()),
            Value::Bool(false) | Value::Null => {}
            Value::String(text) => {
                ensure!(!text.contains(';'), "插件参数值不能包含分号");
                output.push(format!("{key}={text}"));
            }
            Value::Number(number) => output.push(format!("{key}={number}")),
            _ => bail!("插件参数须为文本、数字或开关"),
        }
    }
    Ok(output.join(";"))
}
fn clash(v: &Value) -> Result<Value> {
    let typ = match v["type"].as_str().unwrap_or("") {
        "ss" | "shadowsocks" => "shadowsocks",
        "socks5" => "socks",
        "hy2" => "hysteria2",
        "naive+https" | "naive+quic" => "naive",
        "https" => "http",
        t => t,
    };
    ensure!(
        [
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "hysteria2",
            "tuic",
            "anytls",
            "naive",
            "shadowtls",
            "snell",
            "socks",
            "http",
            "direct"
        ]
        .contains(&typ),
        "不支持的 Clash 协议: {typ}"
    );
    let mut n = json!({"type":typ,"tag":v["name"]});
    if typ == "direct" {
        return Ok(n);
    };
    n["server"] = v["server"].clone();
    n["server_port"] = json!(number(&v["port"]));
    if typ == "snell" {
        // Only Snell v6 exists in current cores; older profiles are rejected
        // instead of being silently upgraded.
        let version = v["version"].as_u64().unwrap_or(6);
        ensure!(version == 6, "Snell 仅支持 v6");
        n["version"] = json!(6);
        if let Some(psk) = v.get("psk").or_else(|| v.get("password")) {
            n["psk"] = psk.clone()
        }
        for (from, to) in [
            ("userkey", "userkey"),
            ("reuse", "reuse"),
            ("network", "network"),
            ("mode", "mode"),
        ] {
            if let Some(value) = v.get(from) {
                n[to] = value.clone()
            }
        }
        validate_server(&n)?;
        return Ok(n);
    }
    if typ == "shadowtls" {
        let version = v["version"].as_u64().unwrap_or(3);
        ensure!(version == 3, "ShadowTLS 仅支持 v3");
        n["version"] = json!(3);
        if let Some(detour) = v.get("detour") {
            n["detour"] = detour.clone()
        }
    }
    if typ == "naive" {
        // Naive is HTTP/2 by default; `quic: true` switches it to HTTP/3.
        let quic = v["quic"] == true || v["type"] == "naive+quic";
        if quic {
            n["quic"] = json!(true)
        }
        if let Some(window) = v.get("quic-session-receive-window") {
            n["quic_session_receive_window"] = window.clone()
        }
        if let Some(window) = v.get("stream-receive-window") {
            n["stream_receive_window"] = window.clone()
        }
        if let Some(concurrency) = v.get("insecure-concurrency") {
            n["insecure_concurrency"] = concurrency.clone()
        }
    }
    for (from, to) in [
        ("password", "password"),
        ("username", "username"),
        ("uuid", "uuid"),
        ("alterId", "alter_id"),
        ("flow", "flow"),
        ("congestion-controller", "congestion_control"),
        ("udp-relay-mode", "udp_relay_mode"),
        ("packet-encoding", "packet_encoding"),
        ("packet_encoding", "packet_encoding"),
        ("global-padding", "global_padding"),
        ("authenticated-length", "authenticated_length"),
        // Set by the ShadowTLS unwrapping path; plain proxies never carry it.
        ("detour", "detour"),
    ] {
        if let Some(value) = v.get(from) {
            n[to] = value.clone()
        }
    }
    if typ == "shadowsocks" {
        n["method"] = v["cipher"].clone();
        if let Some(plugin) = v["plugin"].as_str().filter(|p| !p.is_empty()) {
            let plugin = supported_plugin(plugin)?;
            n["plugin"] = json!(plugin);
            if let Some(options) = v.get("plugin-opts").or_else(|| v.get("plugin_opts")) {
                n["plugin_opts"] = json!(plugin_options(options, plugin)?);
            }
        }
        if let Some(uot) = v.get("udp-over-tcp").or_else(|| v.get("udp_over_tcp")) {
            n["udp_over_tcp"] = if uot.is_boolean() {
                json!({"enabled":uot,"version":v["udp-over-tcp-version"].as_u64().unwrap_or(2)})
            } else {
                uot.clone()
            };
        }
    };
    if v["udp"] == false {
        n["network"] = json!("tcp");
    }
    if typ == "vmess" {
        n["security"] = json!(v["cipher"].as_str().unwrap_or("auto"))
    }
    let shadowtls_tls = typ == "shadowtls";
    if v["tls"] == true
        || shadowtls_tls
        || ["trojan", "hysteria2", "tuic", "anytls", "naive"].contains(&typ)
    {
        let mut tls = json!({"enabled":true});
        for (from, to) in [
            ("servername", "server_name"),
            ("sni", "server_name"),
            ("skip-cert-verify", "insecure"),
            // Naive negotiates HTTP/2 or HTTP/3 by itself and rejects ALPN.
            ("alpn", "alpn"),
        ] {
            if let Some(value) = v.get(from).filter(|_| typ != "naive" || to != "alpn") {
                tls[to] = value.clone()
            }
        }
        if let Some(fp) = v.get("client-fingerprint") {
            tls["utls"] = json!({"enabled":true,"fingerprint":fp})
        };
        if let Some(r) = v.get("reality-opts") {
            if tls.get("utls").is_none() {
                tls["utls"] = json!({"enabled":true,"fingerprint":"chrome"})
            }
            tls["reality"] =
                json!({"enabled":true,"public_key":r["public-key"],"short_id":r["short-id"]})
        };
        n["tls"] = tls
    }
    match v["network"].as_str().unwrap_or("") {
        "" | "tcp" => {}
        "ws" => {
            n["transport"] =
                json!({"type":"ws","path":v["ws-opts"]["path"].as_str().unwrap_or("/")});
            if let Some(h) = v["ws-opts"].get("headers") {
                n["transport"]["headers"] = h.clone()
            }
        }
        "grpc" => {
            n["transport"] =
                json!({"type":"grpc","service_name":v["grpc-opts"]["grpc-service-name"]})
        }
        "http" | "h2" => {
            let mut transport = json!({"type":"http"});
            if let Some(path) = v["h2-opts"]["path"].as_str() {
                transport["path"] = json!(path)
            }
            if let Some(host) = v["h2-opts"]["host"].as_str() {
                transport["host"] = json!(host)
            }
            n["transport"] = transport
        }
        "httpupgrade" => {
            let mut transport = json!({"type":"httpupgrade"});
            if let Some(path) = v["http-opts"]["path"].as_str() {
                transport["path"] = json!(path)
            }
            if let Some(host) = v["http-opts"]["headers"]["Host"].as_str() {
                transport["host"] = json!(host)
            }
            n["transport"] = transport
        }
        other => bail!("不支持的 Clash 传输: {other}"),
    }
    if let Some(obfs) = v.get("obfs") {
        n["obfs"] = json!({"type":obfs,"password":v["obfs-password"]})
    }
    validate_server(&n)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shadowsocks_clash_plugins_and_network_flags_survive_conversion() {
        let source = json!({"proxies":[{"name":"fixture","type":"ss","server":"127.0.0.1","port":443,"cipher":"aes-128-gcm","password":"fixture-secret","udp":false,"plugin":"obfs","plugin-opts":{"mode":"http","host":"example.com"},"udp-over-tcp":true,"udp-over-tcp-version":2}]});
        let nodes = parse(&source.to_string()).unwrap();
        assert_eq!(nodes[0]["method"], "aes-128-gcm");
        assert_eq!(nodes[0]["password"], "fixture-secret");
        assert_eq!(nodes[0]["plugin"], "obfs-local");
        assert_eq!(nodes[0]["plugin_opts"], "obfs-host=example.com;obfs=http");
        assert_eq!(nodes[0]["network"], "tcp");
        assert_eq!(
            nodes[0]["udp_over_tcp"],
            json!({"enabled":true,"version":2})
        );
        let mut second = source;
        second["proxies"][0]["plugin"] = json!("v2ray-plugin");
        second["proxies"][0]["plugin-opts"] =
            json!({"mode":"websocket","tls":true,"mux":false,"host":"example.com"});
        let converted = parse(&second.to_string()).unwrap();
        assert_eq!(
            converted[0]["plugin_opts"],
            "host=example.com;mode=websocket;tls"
        );
        second["proxies"][0]["plugin"] = json!("unsupported");
        let error = parse(&second.to_string()).unwrap_err().to_string();
        assert!(error.contains("不受支持"));
        assert!(!error.contains("fixture-secret"));
    }
    #[test]
    fn import_links_and_local_content_keep_their_meaning() {
        for input in [
            "https://example.com/sub?token=x%2Fy#%E8%AE%A2%E9%98%85",
            "hiddify://import/https://example.com/sub?token=x%2Fy#%E8%AE%A2%E9%98%85",
            "hiddify://import/https%3A%2F%2Fexample.com%2Fsub%3Ftoken%3Dx%252Fy%23%E8%AE%A2%E9%98%85",
            "sing-box://import-remote-profile?url=https%3A%2F%2Fexample.com%2Fsub%3Ftoken%3Dx%252Fy&name=%E8%AE%A2%E9%98%85",
        ] {
            let sub = import_input(input).unwrap();
            assert_eq!(sub.name, "订阅");
            assert_eq!(sub.source, "https://example.com/sub?token=x%2Fy");
            assert!(sub.auto_update);
        }
        let local = import_input("\u{feff}{\"outbounds\":[{\"type\":\"socks\",\"tag\":\"本地\",\"server\":\"127.0.0.1\",\"server_port\":1080}]}").unwrap();
        assert!(local.source.is_empty() && !local.auto_update);
        assert_eq!(local.nodes.len(), 1);
        for invalid in [
            "",
            "[]",
            "/etc/passwd",
            "hiddify://import/file:///etc/passwd",
            "sing-box://import-remote-profile?url=file%3A%2F%2F%2Fetc%2Fpasswd",
            "https://example.com/a\nhttps://example.com/b",
        ] {
            assert!(import_input(invalid).is_err(), "accepted {invalid}");
        }
    }
    #[test]
    fn formats() {
        for text in [
            r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#,
            "proxies:\n- name: test\n  type: ss\n  server: example.com\n  port: 443\n  cipher: aes-128-gcm\n  password: secret",
            "vless://uuid@example.com:443?security=reality&pbk=key&sni=example.com#demo",
        ] {
            assert_eq!(parse(text).unwrap().len(), 1)
        }
    }
    #[test]
    fn base64_and_auth() {
        let link = format!(
            "ss://{}@example.com:443#node",
            STANDARD_NO_PAD.encode("aes-128-gcm:p:a:ss")
        );
        let p = parse(&STANDARD.encode(link)).unwrap();
        assert_eq!(p[0]["password"], "p:a:ss");
    }
    #[test]
    fn rejects_bad_nodes() {
        assert!(parse("fake://x@host:1").is_err());
        assert!(parse(r#"[{"type":"direct","tag":"a"},{"type":"direct","tag":"a"}]"#).is_err())
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    #[test]
    fn anytls_and_naive_links_map_to_sing_box_fields() {
        let anytls = uri("anytls://secret@example.com:443?sni=example.com#A").unwrap();
        assert_eq!(anytls["type"], "anytls");
        assert_eq!(anytls["password"], "secret");
        assert_eq!(anytls["tls"]["server_name"], "example.com");

        let h2 = uri("naive+https://user:pass@example.com:443?sni=example.com#N").unwrap();
        assert_eq!(h2["type"], "naive");
        assert_eq!(h2["username"], "user");
        assert_eq!(h2["password"], "pass");
        assert!(h2.get("quic").is_none());

        let h3 = uri("naive+quic://user:pass@example.com:443?congestion_control=bbr#N").unwrap();
        assert_eq!(h3["quic"], true);
        assert_eq!(h3["quic_congestion_control"], "bbr");
    }

    #[test]
    fn reality_always_carries_a_utls_fingerprint() {
        let node = uri("vless://uuid@example.com:443?security=reality&pbk=k&sid=ab#R").unwrap();
        assert_eq!(node["tls"]["reality"]["public_key"], "k");
        // Without uTLS the core refuses to start a Reality client.
        assert!(node["tls"]["utls"]["fingerprint"].is_string());
    }

    #[test]
    fn vmess_and_vless_support_the_documented_transports() {
        let h2 = uri("vless://uuid@example.com:443?type=h2&host=example.com&path=%2Fh2#V").unwrap();
        assert_eq!(h2["transport"]["type"], "http");
        assert_eq!(h2["transport"]["path"], "/h2");

        let unsupported = uri("vless://uuid@example.com:443?type=kcp#V").unwrap_err();
        assert!(unsupported.to_string().contains("传输"));
    }

    #[test]
    fn clash_anytls_naive_and_new_fields_convert() {
        let source = json!({"proxies":[
            {"name":"any","type":"anytls","server":"a.example.com","port":443,"password":"p","sni":"a.example.com"},
            {"name":"n2","type":"naive","server":"n.example.com","port":443,"username":"u","password":"p","sni":"n.example.com"},
            {"name":"n3","type":"naive+quic","server":"n.example.com","port":443,"username":"u","password":"p","congestion-controller":"bbr"},
            {"name":"v","type":"vless","server":"v.example.com","port":443,"uuid":"u","network":"h2","tls":true,"h2-opts":{"host":"v.example.com","path":"/h2"},"packet-encoding":"xudp"}
        ]});
        let nodes = parse(&source.to_string()).unwrap();
        assert_eq!(nodes[0]["type"], "anytls");
        assert_eq!(nodes[1]["type"], "naive");
        assert_eq!(nodes[1]["tls"]["enabled"], true);
        assert_eq!(nodes[2]["quic"], true);
        assert_eq!(nodes[2]["congestion_control"], "bbr");
        assert_eq!(nodes[3]["packet_encoding"], "xudp");
        assert_eq!(nodes[3]["transport"]["type"], "http");
    }

    #[test]
    fn unsupported_lines_are_skipped_with_a_report() {
        let body = [
            "ss://YWVzLTEyOC1nY206c2VjcmV0@example.com:8388#SS",
            "ssh://user:pass@example.com:22#SSH",
            "trojan://secret@example.com:443?sni=example.com#Trojan",
        ]
        .join("\n");
        // Downloads keep the two usable nodes and report the rest.
        let (nodes, skipped) = parse_with_skips(&body).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(skipped.len(), 1);
        // Manual editing stays strict so a typo is not silently dropped.
        let error = format!("{:#}", parse(&body).unwrap_err());
        assert!(error.contains("不支持的节点协议"), "{error}");
    }

    #[test]
    fn a_subscription_with_no_usable_nodes_explains_why() {
        let error = parse_with_skips("ssh://user:pass@example.com:22#SSH\nssh://b@c:22#D")
            .unwrap_err()
            .to_string();
        assert!(error.contains("跳过 2 个"), "{error}");
    }

    #[test]
    fn shadowtls_and_snell_links_carry_their_version_fields() {
        let st3 = uri("shadowtls://secret@example.com:443?version=3&sni=example.com#ST").unwrap();
        assert_eq!(st3["type"], "shadowtls");
        assert_eq!(st3["version"], 3);
        assert_eq!(st3["tls"]["server_name"], "example.com");

        let s6 = uri("snell://psk@example.com:443?version=6&userkey=uk&mode=unshaped#S").unwrap();
        assert_eq!(s6["version"], 6);
        assert_eq!(s6["psk"], "psk");
        assert_eq!(s6["userkey"], "uk");
        assert_eq!(s6["mode"], "unshaped");

        // Only the current versions are accepted.
        for bad in [
            "snell://p@example.com:443?version=4#S",
            "snell://p@example.com:443?version=5#S",
            "shadowtls://p@example.com:443?version=1#ST",
            "shadowtls://p@example.com:443?version=2#ST",
        ] {
            assert!(uri(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn clash_shadowtls_and_snell_convert() {
        let source = json!({"proxies":[
            {"name":"st","type":"shadowtls","server":"s.example.com","port":443,"password":"p","version":3,"sni":"s.example.com"},
            {"name":"s6","type":"snell","server":"n.example.com","port":443,"psk":"key","version":6,"userkey":"uk","reuse":true,"mode":"unshaped"}
        ]});
        let nodes = parse(&source.to_string()).unwrap();
        assert_eq!(nodes[0]["tls"]["server_name"], "s.example.com");
        assert_eq!(nodes[1]["reuse"], true);
        assert_eq!(nodes[1]["mode"], "unshaped");
        assert_eq!(nodes[1]["version"], 6);
    }

    #[test]
    fn protocols_outside_the_android_app_are_rejected() {
        for link in [
            "ssh://user:pass@example.com:22#S",
            "hysteria://secret@example.com:443#H",
            "wireguard://key@example.com:51820?publickey=x&address=10.0.0.2%2F32#W",
        ] {
            assert!(uri(link).is_err(), "accepted {link}");
        }
    }
}

#[cfg(test)]
mod shadowtls_chain_tests {
    use super::*;

    #[test]
    fn shadowsocks_over_shadowtls_expands_into_a_detour_pair() {
        let link = "ss://YWVzLTEyOC1nY206c2VjcmV0@example.com:443?plugin=shadow-tls%3Bhost%3Dexample.com%3Bpassword%3Dstpass%3Bversion%3D3#Node";
        let nodes = uri_nodes(link).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0]["type"], "shadowsocks");
        assert_eq!(nodes[1]["type"], "shadowtls");
        assert_eq!(nodes[0]["detour"], nodes[1]["tag"]);
        assert_eq!(nodes[1]["password"], "stpass");
        assert_eq!(nodes[1]["tls"]["server_name"], "example.com");
        // Only the inner Shadowsocks node is a dialable picker entry.
        assert!(crate::model::is_connection_node(&nodes[0]));
    }

    #[test]
    fn clash_shadowtls_plugin_expands_too() {
        let source = json!({"proxies":[{
            "name":"Node","type":"ss","server":"example.com","port":443,
            "cipher":"aes-128-gcm","password":"secret",
            "plugin":"shadow-tls","plugin-opts":{"host":"example.com","password":"stpass","version":3}
        }]});
        let nodes = parse(&source.to_string()).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0]["type"], "shadowsocks");
        assert!(nodes[0].get("plugin").is_none());
        assert_eq!(nodes[0]["detour"], nodes[1]["tag"]);
        assert_eq!(nodes[1]["type"], "shadowtls");
    }
}
