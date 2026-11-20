use crate::model::validate_nodes;
use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::HashSet};
use url::Url;

const DIAL_FIELDS: [&str; 5] = [
    "bind_interface",
    "connect_timeout",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
];

const TRANSPORT_KEEPALIVE_FIELDS: [(&str, &str); 8] = [
    ("idle_timeout", "idle_timeout"),
    ("idle-timeout", "idle_timeout"),
    ("ping_timeout", "ping_timeout"),
    ("ping-timeout", "ping_timeout"),
    ("permit_without_stream", "permit_without_stream"),
    ("permit-without-stream", "permit_without_stream"),
    ("grpc_permit_without_stream", "permit_without_stream"),
    ("grpc-permit-without-stream", "permit_without_stream"),
];

fn transport_keepalive(source: &Value, transport: &mut Value, context: &str) -> Result<()> {
    for (alias, field) in TRANSPORT_KEEPALIVE_FIELDS {
        if let Some(value) = source.get(alias) {
            ensure!(
                transport["type"] == "grpc"
                    || (transport["type"] == "http" && field != "permit_without_stream"),
                "{context} 的 {alias} 需要 HTTP/2 或 gRPC 传输（permit_without_stream 仅限 gRPC）"
            );
            ensure!(transport.get(field).is_none(), "{context} 重复设置 {field}");
            transport[field] = value.clone();
        }
    }
    Ok(())
}

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

fn known_fields(value: &Value, allowed: &[&str], context: &str) -> Result<()> {
    let fields = value
        .as_object()
        .with_context(|| format!("{context} 须为对象"))?;
    for field in fields.keys() {
        ensure!(
            allowed.contains(&field.as_str()),
            "{context} 不支持参数: {field}"
        );
    }
    Ok(())
}

fn query_bool(value: &str, key: &str) -> Result<bool> {
    match value {
        "" | "0" | "false" => Ok(false),
        "1" | "true" => Ok(true),
        _ => bail!("节点链接的 {key} 参数须为 0、1、false 或 true"),
    }
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
            if matches!(
                v["type"].as_str(),
                Some("selector" | "urltest" | "direct" | "block" | "dns" | "reject")
            ) {
                continue;
            }
            let result = if v.get("name").is_some() {
                clash(v)
            } else {
                Ok(v.clone())
            }
            .and_then(|node| {
                crate::protocol::validate(&node)?;
                Ok(node)
            });
            match result {
                Ok(node) => nodes.push(node),
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
        match uri(line).and_then(|node| {
            crate::protocol::validate(&node)?;
            Ok(node)
        }) {
            Ok(node) => nodes.push(node),
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
        let mut fields = vec![
            "v",
            "ps",
            "add",
            "port",
            "id",
            "aid",
            "scy",
            "net",
            "type",
            "host",
            "path",
            "tls",
            "sni",
            "alpn",
            "fp",
            "packetEncoding",
            "packet_encoding",
            "packet-encoding",
        ];
        fields.extend(DIAL_FIELDS);
        fields.extend(TRANSPORT_KEEPALIVE_FIELDS.iter().map(|(alias, _)| *alias));
        known_fields(&v, &fields, "VMess 链接")?;
        ensure!(
            v.get("v").is_none_or(|v| v == "2" || v == 2),
            "不支持的 VMess 链接版本"
        );
        ensure!(
            v["type"].as_str().is_none_or(|v| matches!(v, "" | "none")),
            "不支持 VMess TCP 伪装参数 type"
        );
        ensure!(
            v["tls"]
                .as_str()
                .is_none_or(|v| matches!(v, "" | "none" | "tls")),
            "不支持的 VMess TLS 设置"
        );
        let mut node = json!({"type":"vmess","tag":v["ps"].as_str().unwrap_or("VMess"),"server":v["add"],"server_port":number(&v["port"]),"uuid":v["id"],"security":v["scy"].as_str().filter(|value| !value.is_empty()).unwrap_or("auto"),"alter_id":number(&v["aid"])});
        for field in DIAL_FIELDS {
            if let Some(value) = v.get(field) {
                node[field] = value.clone();
            }
        }
        for field in ["packetEncoding", "packet_encoding", "packet-encoding"] {
            if let Some(encoding) = v.get(field) {
                ensure!(
                    node.get("packet_encoding").is_none(),
                    "VMess 链接重复设置 UDP 编码"
                );
                node["packet_encoding"] = encoding.clone();
            }
        }
        if v["tls"] == "tls" {
            node["tls"] = json!({"enabled":true,"server_name":v["sni"].as_str().unwrap_or("")});
            if let Some(alpn) = v["alpn"].as_str().filter(|v| !v.is_empty()) {
                node["tls"]["alpn"] = json!(alpn.split(',').collect::<Vec<_>>());
            }
            ensure!(
                v["fp"].as_str().is_none_or(str::is_empty),
                "不支持浏览器 TLS fingerprint 参数 fp"
            );
        } else {
            for field in ["sni", "alpn", "fp"] {
                ensure!(
                    v[field].as_str().is_none_or(str::is_empty),
                    "未启用 TLS 时不支持参数 {field}"
                );
            }
        }
        match v["net"].as_str().unwrap_or("tcp") {
            "tcp" | "" => {
                for field in ["host", "path"] {
                    ensure!(
                        v[field].as_str().is_none_or(str::is_empty),
                        "VMess TCP 不支持参数 {field}"
                    );
                }
            }
            "ws" => {
                node["transport"] = json!({"type":"ws","path":v["path"].as_str().unwrap_or("/"),"headers":{"Host":v["host"].as_str().unwrap_or("")}})
            }
            "grpc" => {
                ensure!(
                    v["host"].as_str().is_none_or(str::is_empty),
                    "VMess gRPC 不支持参数 host"
                );
                node["transport"] =
                    json!({"type":"grpc","service_name":v["path"].as_str().unwrap_or("")})
            }
            "http" | "h2" => {
                node["transport"] = json!({"type":"http","path":v["path"].as_str().unwrap_or("/"),"host":v["host"].as_str().unwrap_or("")})
            }
            other => bail!("不支持 VMess 传输: {other}"),
        };
        if TRANSPORT_KEEPALIVE_FIELDS
            .iter()
            .any(|(alias, _)| v.get(alias).is_some())
        {
            transport_keepalive(&v, &mut node["transport"], "VMess 链接")?;
        }
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
    let mut query_keys = HashSet::new();
    for (key, _) in u.query_pairs() {
        ensure!(
            !matches!(key.as_ref(), "plugin" | "plugin_opts" | "plugin-opts"),
            "不支持 Shadowsocks plugin 参数"
        );
        ensure!(query_keys.insert(key.into_owned()), "节点链接包含重复参数");
    }
    let consumed = RefCell::new(HashSet::new());
    let q = |key: &str| {
        consumed.borrow_mut().insert(key.to_owned());
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
        }
        "vless" => {
            node["uuid"] = json!(user);
            for field in ["packetEncoding", "packet_encoding", "packet-encoding"] {
                if query_keys.contains(field) {
                    ensure!(
                        node.get("packet_encoding").is_none(),
                        "节点链接重复设置 UDP 编码"
                    );
                    node["packet_encoding"] = q(field).into();
                }
            }
            ensure!(
                matches!(q("encryption").as_str(), "" | "none"),
                "不支持的 VLESS encryption 参数"
            );
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
            let quic_query = query_bool(&q("quic"), "quic")?;
            let quic = u.scheme() == "naive+quic" || quic_query;
            if quic {
                node["quic"] = json!(true);
                if !q("congestion_control").is_empty() {
                    node["quic_congestion_control"] = json!(q("congestion_control"))
                }
            }
        }
        "socks" | "http" if !user.is_empty() => {
            node["username"] = json!(user);
            node["password"] = json!(pass)
        }
        _ => {}
    }
    let security = q("security");
    ensure!(
        matches!(security.as_str(), "" | "none" | "tls" | "reality"),
        "不支持的 security 参数"
    );
    if ["trojan", "hysteria2", "tuic", "anytls", "naive"].contains(&typ)
        || u.scheme() == "https"
        || ["tls", "reality"].contains(&security.as_str())
    {
        let mut tls = json!({"enabled":true});
        if !q("sni").is_empty() {
            tls["server_name"] = json!(q("sni"))
        };
        let insecure = query_bool(&q("insecure"), "insecure")?;
        let allow_insecure = query_bool(&q("allowInsecure"), "allowInsecure")?;
        if insecure || allow_insecure {
            tls["insecure"] = json!(true)
        }
        if !q("alpn").is_empty() {
            tls["alpn"] = json!(q("alpn").split(',').collect::<Vec<_>>())
        };
        if !q("fp").is_empty() {
            tls["utls"] = json!({"enabled":true,"fingerprint":q("fp")})
        }
        if q("security") == "reality" {
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
    for key in DIAL_FIELDS {
        if query_keys.contains(key) {
            node[key] = if key == "disable_tcp_keep_alive" {
                query_bool(&q(key), key)?.into()
            } else {
                q(key).into()
            };
        }
    }
    let mut keepalive = json!({});
    for (alias, field) in TRANSPORT_KEEPALIVE_FIELDS {
        if query_keys.contains(alias) {
            keepalive[alias] = if field == "permit_without_stream" {
                query_bool(&q(alias), alias)?.into()
            } else {
                q(alias).into()
            };
        }
    }
    if !keepalive.as_object().unwrap().is_empty() {
        transport_keepalive(&keepalive, &mut node["transport"], "节点链接")?;
    }
    for key in query_keys {
        ensure!(
            consumed.borrow().contains(&key),
            "节点链接不支持参数: {key}"
        );
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

fn clash(v: &Value) -> Result<Value> {
    for field in ["plugin", "plugin-opts", "plugin_opts"] {
        ensure!(
            v.get(field).is_none(),
            "不支持 Shadowsocks plugin 参数: {field}"
        );
    }
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
            "socks",
            "http"
        ]
        .contains(&typ),
        "不支持的 Clash 协议: {typ}"
    );
    let mut fields = vec![
        "name",
        "type",
        "server",
        "port",
        "password",
        "username",
        "uuid",
        "alterId",
        "flow",
        "congestion-controller",
        "udp-relay-mode",
        "packet-encoding",
        "packet_encoding",
        "global-padding",
        "authenticated-length",
        "udp",
        "tls",
        "network",
        "obfs",
        "obfs-password",
    ];
    const DIAL_ALIASES: [(&str, &str); 5] = [
        ("interface-name", "bind_interface"),
        ("connect-timeout", "connect_timeout"),
        ("disable-tcp-keep-alive", "disable_tcp_keep_alive"),
        ("tcp-keep-alive", "tcp_keep_alive"),
        ("tcp-keep-alive-interval", "tcp_keep_alive_interval"),
    ];
    fields.extend(DIAL_FIELDS);
    fields.extend(DIAL_ALIASES.iter().map(|(alias, _)| *alias));
    if matches!(typ, "shadowsocks" | "vmess") {
        fields.push("cipher");
    }
    if typ == "shadowsocks" {
        fields.extend(["udp-over-tcp", "udp_over_tcp", "udp-over-tcp-version"]);
    }
    if typ == "naive" {
        fields.extend([
            "quic",
            "quic-session-receive-window",
            "stream-receive-window",
            "insecure-concurrency",
        ]);
    }
    let tls_enabled = v["tls"] == true
        || v["type"] == "https"
        || ["trojan", "hysteria2", "tuic", "anytls", "naive"].contains(&typ);
    ensure!(
        v.get("tls").is_none_or(Value::is_boolean),
        "Clash tls 参数须为开关"
    );
    ensure!(
        v.get("udp").is_none_or(Value::is_boolean),
        "Clash udp 参数须为开关"
    );
    ensure!(
        v.get("network").is_none_or(Value::is_string),
        "Clash network 参数须为文本"
    );
    if typ == "naive" {
        ensure!(
            v.get("quic").is_none_or(Value::is_boolean),
            "Clash quic 参数须为开关"
        );
    }
    if tls_enabled {
        fields.extend([
            "servername",
            "sni",
            "skip-cert-verify",
            "alpn",
            "client-fingerprint",
            "reality-opts",
        ]);
    }
    match v["network"].as_str().unwrap_or("") {
        "ws" => fields.push("ws-opts"),
        "grpc" => fields.extend([
            "grpc-opts",
            "grpc_permit_without_stream",
            "grpc-permit-without-stream",
        ]),
        "http" | "httpupgrade" => fields.push("http-opts"),
        "h2" => fields.push("h2-opts"),
        _ => {}
    }
    known_fields(v, &fields, "Clash 节点")?;
    let mut n = json!({"type":typ,"tag":v["name"]});
    n["server"] = v["server"].clone();
    n["server_port"] = json!(number(&v["port"]));
    for (alias, field) in DIAL_ALIASES {
        ensure!(
            v.get(alias).is_none() || v.get(field).is_none(),
            "Clash 节点重复设置 {field}"
        );
        if let Some(value) = v.get(alias).or_else(|| v.get(field)) {
            n[field] = value.clone();
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
    ] {
        if let Some(value) = v.get(from) {
            ensure!(
                to != "packet_encoding" || n.get(to).is_none(),
                "Clash 节点重复设置 UDP 编码"
            );
            n[to] = value.clone()
        }
    }
    if typ == "shadowsocks" {
        n["method"] = v["cipher"].clone();
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
    if tls_enabled {
        let mut tls = json!({"enabled":true});
        for (from, to) in [
            ("servername", "server_name"),
            ("sni", "server_name"),
            ("skip-cert-verify", "insecure"),
            ("alpn", "alpn"),
        ] {
            if let Some(value) = v.get(from) {
                tls[to] = value.clone()
            }
        }
        if let Some(fp) = v.get("client-fingerprint") {
            tls["utls"] = json!({"enabled":true,"fingerprint":fp})
        };
        if let Some(r) = v.get("reality-opts") {
            known_fields(r, &["public-key", "short-id"], "Clash reality-opts")?;
            tls["reality"] =
                json!({"enabled":true,"public_key":r["public-key"],"short_id":r["short-id"]})
        };
        n["tls"] = tls
    }
    match v["network"].as_str().unwrap_or("") {
        "" | "tcp" => {}
        "ws" => {
            if let Some(options) = v.get("ws-opts") {
                known_fields(
                    options,
                    &[
                        "path",
                        "headers",
                        "max-early-data",
                        "early-data-header-name",
                    ],
                    "Clash ws-opts",
                )?;
            }
            n["transport"] =
                json!({"type":"ws","path":v["ws-opts"]["path"].as_str().unwrap_or("/")});
            if let Some(h) = v["ws-opts"].get("headers") {
                n["transport"]["headers"] = h.clone()
            }
            for (from, to) in [
                ("max-early-data", "max_early_data"),
                ("early-data-header-name", "early_data_header_name"),
            ] {
                if let Some(value) = v["ws-opts"].get(from) {
                    n["transport"][to] = value.clone();
                }
            }
        }
        "grpc" => {
            let mut fields = vec!["grpc-service-name"];
            fields.extend(TRANSPORT_KEEPALIVE_FIELDS.iter().map(|(alias, _)| *alias));
            if let Some(options) = v.get("grpc-opts") {
                known_fields(options, &fields, "Clash grpc-opts")?;
            }
            let mut transport = json!({"type":"grpc"});
            if let Some(service_name) = v["grpc-opts"].get("grpc-service-name") {
                transport["service_name"] = service_name.clone();
            }
            transport_keepalive(&v["grpc-opts"], &mut transport, "Clash grpc-opts")?;
            transport_keepalive(v, &mut transport, "Clash 节点")?;
            n["transport"] = transport;
        }
        network @ ("http" | "h2") => {
            let mut transport = json!({"type":"http"});
            let options = &v[if network == "h2" {
                "h2-opts"
            } else {
                "http-opts"
            }];
            if !options.is_null() {
                known_fields(
                    options,
                    &[
                        "path",
                        "method",
                        "headers",
                        "host",
                        "idle_timeout",
                        "idle-timeout",
                        "ping_timeout",
                        "ping-timeout",
                    ],
                    "Clash HTTP 传输",
                )?;
            }
            ensure!(
                options["path"]
                    .as_array()
                    .is_none_or(|paths| paths.len() == 1),
                "HTTP 传输只支持一个 path，不能丢弃备用路径"
            );
            if let Some(path) = options["path"]
                .as_str()
                .or_else(|| options["path"].as_array()?.first()?.as_str())
            {
                transport["path"] = json!(path)
            }
            if network == "http" {
                transport["method"] = json!(options["method"].as_str().unwrap_or("GET"));
            } else if let Some(method) = options.get("method") {
                transport["method"] = method.clone();
            }
            if let Some(headers) = options["headers"].as_object() {
                let mut extra = headers.clone();
                // The transport exposes Host separately from other headers.
                extra.retain(|name, value| {
                    if name.eq_ignore_ascii_case("host") {
                        transport["host"] = value.clone();
                        false
                    } else {
                        true
                    }
                });
                if !extra.is_empty() {
                    transport["headers"] = json!(extra);
                }
            }
            if let Some(host) = options.get("host") {
                transport["host"] = host.clone();
            }
            transport_keepalive(options, &mut transport, "Clash HTTP 传输")?;
            n["transport"] = transport
        }
        "httpupgrade" => {
            if let Some(options) = v.get("http-opts") {
                known_fields(options, &["path", "headers"], "Clash HTTPUpgrade")?;
                if let Some(headers) = options.get("headers") {
                    known_fields(headers, &["Host"], "Clash HTTPUpgrade headers")?;
                }
            }
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
    } else {
        ensure!(
            v.get("obfs-password").is_none(),
            "obfs-password 缺少 obfs 类型"
        );
    }
    validate_server(&n)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clash_http_and_h2_keep_host_path_and_headers() {
        let nodes = parse(
            r#"
proxies:
  - name: h2
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
    tls: true
    network: h2
    h2-opts:
      host: [front.example.com]
      path: /secret
  - name: http
    type: vmess
    server: example.com
    port: 80
    uuid: 00000000-0000-4000-8000-000000000001
    network: http
    http-opts:
      method: POST
      path: [/video]
      headers:
        hOsT: [front.example.com]
        X-Token: [fixture]
        User-Agent: AeroBox-test
"#,
        )
        .unwrap();
        assert_eq!(
            nodes[0]["transport"],
            json!({"type":"http","host":["front.example.com"],"path":"/secret"})
        );
        assert_eq!(
            nodes[1]["transport"],
            json!({"type":"http","host":["front.example.com"],"path":"/video","method":"POST","headers":{"X-Token":["fixture"],"User-Agent":"AeroBox-test"}})
        );
    }

    #[test]
    fn unsupported_plugins_are_rejected_without_losing_other_nodes() {
        let source = json!({"proxies":[
            {"name":"plugin","type":"ss","server":"127.0.0.1","port":443,"cipher":"aes-128-gcm","password":"fixture-secret","plugin":"obfs","plugin-opts":{"mode":"http"}},
            {"name":"plain","type":"ss","server":"127.0.0.1","port":443,"cipher":"aes-128-gcm","password":"fixture-secret"}
        ]});
        assert!(parse(&source.to_string()).is_err());
        let (nodes, skipped) = parse_with_skips(&source.to_string()).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["tag"], "plain");
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].contains("plugin"));
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
            r#"{"outbounds":[{"type":"socks","tag":"local","server":"127.0.0.1","server_port":1080},{"type":"direct","tag":"direct"}]}"#,
            "proxies:\n- name: test\n  type: ss\n  server: example.com\n  port: 443\n  cipher: aes-128-gcm\n  password: secret",
            "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&sni=example.com#demo",
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
    fn anytls_and_naive_links_preserve_protocol_settings() {
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
    fn reality_does_not_invent_a_browser_fingerprint() {
        let node = uri("vless://00000000-0000-4000-8000-000000000001@example.com:443?security=reality&pbk=CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk&sid=ab#R").unwrap();
        assert_eq!(
            node["tls"]["reality"]["public_key"],
            "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk"
        );
        crate::protocol::validate(&node).unwrap();
        // Import must not add a browser fingerprint that was not requested.
        assert!(node["tls"].get("utls").is_none());
    }

    #[test]
    fn vmess_and_vless_support_the_documented_transports() {
        let h2 = uri("vless://00000000-0000-4000-8000-000000000001@example.com:443?type=h2&host=example.com&path=%2Fh2#V").unwrap();
        crate::protocol::validate(&h2).unwrap();
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
            {"name":"v","type":"vless","server":"v.example.com","port":443,"uuid":"00000000-0000-4000-8000-000000000001","network":"h2","tls":true,"h2-opts":{"host":"v.example.com","path":"/h2"},"packet-encoding":"xudp"}
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
    fn protocols_outside_the_android_app_are_rejected() {
        for link in [
            "shadowtls://p@example.com:443?version=3#ST",
            "snell://p@example.com:443?version=6#S",
            "ssh://user:pass@example.com:22#S",
            "hysteria://secret@example.com:443#H",
            "wireguard://key@example.com:51820?publickey=x&address=10.0.0.2%2F32#W",
        ] {
            assert!(uri(link).is_err(), "accepted {link}");
        }
    }
}

#[cfg(test)]
mod native_validation_tests {
    use super::*;
    #[test]
    fn rejects_raw_json_unsupported_options_too() {
        let source = json!({"outbounds":[{"type":"vless","tag":"unsupported-fingerprint","server":"example.com","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}}},{"type":"socks","tag":"local","server":"127.0.0.1","server_port":1080}]});
        assert!(parse(&source.to_string()).is_err());
        let (nodes, skipped) = parse_with_skips(&source.to_string()).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].contains("fingerprint"));
    }
}

#[cfg(test)]
mod import_boundary_tests {
    use super::*;

    #[test]
    fn shadowsocks_plugins_are_rejected_in_links_and_clash_without_expansion() {
        let plain = "ss://YWVzLTEyOC1nY206c2VjcmV0@example.com:8388#plain";
        for plugin in ["shadow-tls", "obfs-local", "v2ray-plugin", "unknown-plugin"] {
            let link = format!(
                "ss://YWVzLTEyOC1nY206c2VjcmV0@example.com:443?plugin={plugin}%3Bhost%3Dfront.example%3Bpassword%3Dsecret%3Bversion%3D3#plugin"
            );
            assert!(uri(&link).unwrap_err().to_string().contains("plugin"));
            let (nodes, skipped) = parse_with_skips(&format!("{link}\n{plain}")).unwrap();
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0]["tag"], "plain");
            assert_eq!(skipped.len(), 1);
            assert!(skipped[0].contains("plugin"));
            let clash = json!({"proxies":[
                {"type":"ss","name":"plugin","server":"example.com","port":443,"cipher":"aes-128-gcm","password":"secret","plugin":plugin,"plugin-opts":{"host":"front.example","password":"secret","version":3}},
                {"type":"ss","name":"plain","server":"example.com","port":443,"cipher":"aes-128-gcm","password":"secret"}
            ]});
            assert!(parse(&clash.to_string()).is_err());
            let (nodes, skipped) = parse_with_skips(&clash.to_string()).unwrap();
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0]["tag"], "plain");
            assert!(nodes[0].get("detour").is_none());
            assert_eq!(skipped.len(), 1);
        }
    }

    #[test]
    fn uri_conversion_rejects_unconsumed_and_invalid_parameters() {
        for query in [
            "unknown_option=1",
            "type=grpc&path=ignored",
            "type=tcp&host=ignored",
            "security=unimplemented",
            "security=tls&insecure=maybe",
            "type=ws&type=tcp",
            "plugin_opts=ignored",
        ] {
            let link = format!(
                "vless://00000000-0000-4000-8000-000000000001@example.com:443?{query}#strict"
            );
            assert!(uri(&link).is_err(), "accepted parameters: {query}");
        }
        let mut vmess = json!({"v":"2","ps":"VMess","add":"example.com","port":"443","id":"00000000-0000-4000-8000-000000000001","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":"","scy":"aes-128-gcm"});
        let link = |v: &Value| format!("vmess://{}", STANDARD.encode(v.to_string()));
        assert_eq!(parse(&link(&vmess)).unwrap()[0]["security"], "aes-128-gcm");
        vmess["unsupported_tls_option"] = json!(true);
        assert!(parse(&link(&vmess)).is_err());
    }

    #[test]
    fn clash_conversion_rejects_unrepresented_settings_and_transport_options() {
        let base = json!({"type":"vless","name":"strict","server":"example.com","port":443,"uuid":"00000000-0000-4000-8000-000000000001"});
        for (field, value) in [
            ("unknown_option", json!(true)),
            ("detour", json!("discarded-node")),
            ("client-fingerprint", json!("chrome")),
            ("network", json!("kcp")),
            ("ws-opts", json!({"path":"/ignored"})),
            ("udp", json!("not a boolean")),
        ] {
            let mut node = base.clone();
            node[field] = value;
            assert!(
                parse(&json!({"proxies":[node]}).to_string()).is_err(),
                "accepted {field}"
            );
        }
        for options in [
            json!({"path":["/a","/b"]}),
            json!({"path":"/a","unknown_transport_option":true}),
        ] {
            let mut node = base.clone();
            node["network"] = json!("http");
            node["http-opts"] = options;
            assert!(parse(&json!({"proxies":[node]}).to_string()).is_err());
        }
        for protocol in ["shadowtls", "snell"] {
            let mut node = base.clone();
            node["type"] = protocol.into();
            assert!(parse(&json!({"proxies":[node]}).to_string()).is_err());
        }
    }
}
