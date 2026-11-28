use crate::model::validate_nodes;
use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::HashSet};
use url::Url;
mod quic;
mod ss_plugin;
mod tls;
mod xhttp;

/// Subscription format negotiation follows FlClash's Linux request identifier.
pub(crate) const USER_AGENT: &str = "FlClash/v0.9.4 clash-verge Platform/linux";

const DIAL_FIELDS: [&str; 8] = [
    "tcp_fast_open",
    "tcp_multi_path",
    "udp_fragment",
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

// Share links often omit these fields or serialize their defaults as empty
// strings. Leave them absent so the transport uses `/` and the server authority.
fn link_transport(kind: &str, path: &str, host: &str) -> Value {
    let mut transport = json!({"type":kind});
    if !path.is_empty() {
        transport["path"] = path.into();
    }
    if !host.is_empty() {
        if kind == "ws" {
            transport["headers"] = json!({"Host":host});
        } else {
            transport["host"] = host.into();
        }
    }
    transport
}

fn single_transport_text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .as_str()
        .or_else(|| {
            let values = value.as_array()?;
            (values.len() == 1).then(|| values[0].as_str()).flatten()
        })
        .with_context(|| format!("{field} 须为文本或仅含一个文本的列表"))
}

fn http_hosts(transport: &mut Value, value: &Value) -> Result<()> {
    let hosts = crate::protocol::strings(value.clone(), "Clash HTTP host")?;
    if !hosts.is_empty() {
        if let Some(existing) = transport.get("host") {
            ensure!(
                crate::protocol::strings(existing.clone(), "Clash HTTP host")? == hosts,
                "Clash HTTP host 与 headers.Host 不能设置不同的服务器名"
            );
        }
        transport["host"] = if hosts.len() == 1 {
            hosts[0].clone().into()
        } else {
            hosts.into()
        };
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

/// Share links commonly encode alterId as decimal text; malformed input must
/// never silently switch a legacy VMess node back to AEAD authentication.
fn alter_id(value: Option<&Value>, field: &str) -> Result<u16> {
    let Some(value) = value else { return Ok(0) };
    let parsed = value.as_u64().or_else(|| {
        let text = value.as_str()?;
        (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse().ok())
            .flatten()
    });
    parsed
        .and_then(|value| u16::try_from(value).ok())
        .with_context(|| format!("{field} 须为 0–65535 的整数；0 使用 AEAD，正数使用旧 VMess 认证"))
}

fn node_error(node: &Value, error: anyhow::Error) -> String {
    let message = redact_node_error(node, &format!("{error:#}"));
    if let Some(name) = node
        .get("name")
        .or_else(|| node.get("tag"))
        .and_then(Value::as_str)
    {
        if message.starts_with("节点「") {
            message
        } else {
            format!("节点「{name}」：{message}")
        }
    } else {
        message
    }
}

fn redact_node_error(node: &Value, message: &str) -> String {
    fn secrets(value: &Value, sensitive: bool, output: &mut Vec<String>) {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    let key = key.to_ascii_lowercase();
                    secrets(
                        value,
                        sensitive
                            || key.contains("password")
                            || key.contains("secret")
                            || key.contains("key")
                            || key.contains("certificate")
                            || matches!(key.as_str(), "uuid" | "id" | "server" | "add" | "source"),
                        output,
                    );
                }
            }
            Value::Array(values) => {
                for value in values {
                    secrets(value, sensitive, output);
                }
            }
            Value::String(value) if sensitive && !value.is_empty() => output.push(value.clone()),
            _ => {}
        }
    }
    let mut values = Vec::new();
    secrets(node, false, &mut values);
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    let mut message = message.to_owned();
    for value in values {
        if value.len() >= 4 {
            message = message.replace(&value, "[已隐藏]");
        } else {
            for quoted in [
                format!("\"{value}\""),
                format!("'{value}'"),
                format!("`{value}`"),
            ] {
                message = message.replace(&quoted, "[已隐藏]");
            }
        }
    }
    message
        .chars()
        .filter(|c| !c.is_control())
        .take(500)
        .collect()
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
        for (index, v) in items.iter().enumerate() {
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
                Err(error) if tolerant => skipped.push(format!(
                    "第 {} 项（{}）：{}",
                    index + 1,
                    protocol_label(v["type"].as_str().unwrap_or("未知")),
                    node_error(v, error)
                )),
                Err(error) => bail!("{}", node_error(v, error)),
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
            Err(error) => {
                let error = uri_error(line, error);
                if tolerant {
                    skipped.push(format!(
                        "第 {} 项（{}）：{error}",
                        index + 1,
                        protocol_label(
                            line.split_once("://")
                                .map(|(kind, _)| kind)
                                .unwrap_or("未知")
                        )
                    ));
                } else {
                    bail!("第 {} 个节点：{error}", index + 1);
                }
            }
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

fn protocol_label(kind: &str) -> String {
    kind.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '+'))
        .take(24)
        .collect()
}

fn uri_error(line: &str, error: anyhow::Error) -> String {
    let mut message = format!("{error:#}");
    if let Some(body) = line.strip_prefix("vmess://") {
        if let Ok(body) = decode(body)
            && let Ok(node) = serde_json::from_str::<Value>(&body)
        {
            message = redact_node_error(&node, &message);
        }
    } else if let Ok(url) = Url::parse(line) {
        let node = json!({"username_secret":unescape(url.username()), "password":url.password().map(unescape), "server":url.host_str(), "source":line, "query_secret":url.query_pairs().map(|(_,value)|value.into_owned()).collect::<Vec<_>>()});
        message = redact_node_error(&node, &message);
    }
    message
        .chars()
        .filter(|c| !c.is_control())
        .take(500)
        .collect()
}

fn skip_hint(skipped: &[String]) -> String {
    if skipped.is_empty() {
        return String::new();
    }
    format!("（{}）", skipped_summary(skipped))
}

/// A bounded report shared by all-failed imports and partial-update logs.
/// Keep field names and explanations after ':'; group equivalent errors even
/// when they name different nodes.
pub fn skipped_summary(skipped: &[String]) -> String {
    if skipped.is_empty() {
        return String::new();
    }
    let mut seen = HashSet::new();
    let mut examples = Vec::new();
    for message in skipped {
        let key = message
            .strip_prefix("节点「")
            .and_then(|message| message.split_once('」').map(|(_, rest)| rest))
            .unwrap_or(message)
            .trim_start_matches(['：', ':', ' ']);
        if seen.insert(key) {
            let mut excerpt: String = message
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect();
            if message.chars().count() > 200 {
                excerpt.push('…');
            }
            examples.push(excerpt);
            if examples.len() == 3 {
                break;
            }
        }
    }
    format!("跳过 {} 个节点：{}", skipped.len(), examples.join("；"))
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
        let (nodes, import_issues) = parse_with_skips(input)?;
        let name = if nodes.len() == 1 {
            nodes[0]["tag"].as_str().unwrap_or("本地订阅").to_owned()
        } else {
            "本地订阅".into()
        };
        Ok(crate::model::Subscription {
            name,
            nodes,
            import_issues,
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
            "global_padding",
            "authenticated_length",
        ];
        fields.extend(DIAL_FIELDS);
        fields.extend(tls::link_fields());
        fields.extend(TRANSPORT_KEEPALIVE_FIELDS.iter().map(|(alias, _)| *alias));
        if v["net"] == "xhttp" {
            fields.extend(["mode", "extra"]);
        }
        known_fields(&v, &fields, "VMess 链接")?;
        for field in [
            "type", "net", "scy", "tls", "sni", "alpn", "fp", "host", "path",
        ] {
            ensure!(
                v.get(field).is_none_or(Value::is_string),
                "VMess {field} 须为文本"
            );
        }
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
        let aid = alter_id(v.get("aid"), "VMess aid")?;
        let mut node = json!({"type":"vmess","tag":v["ps"].as_str().unwrap_or("VMess"),"server":v["add"],"server_port":number(&v["port"]),"uuid":v["id"],"security":v["scy"].as_str().filter(|value| !value.is_empty()).unwrap_or("auto"),"alter_id":aid});
        for field in ["global_padding", "authenticated_length"] {
            if let Some(value) = v.get(field) {
                ensure!(value.is_boolean(), "VMess {field} 须为开关");
                node[field] = value.clone();
            }
        }
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
            if let Some(fingerprint) = v["fp"].as_str().filter(|value| !value.is_empty()) {
                node["tls"]["utls"] = json!({"enabled":true,"fingerprint":fingerprint});
            }
            tls::link(&v, &mut node["tls"], false)?;
        } else {
            for field in ["sni", "alpn", "fp"] {
                ensure!(
                    v[field].as_str().is_none_or(str::is_empty),
                    "未启用 TLS 时不支持参数 {field}"
                );
            }
            for field in tls::link_fields() {
                ensure!(v.get(field).is_none(), "未启用 TLS 时不支持参数 {field}");
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
            "xhttp" => {
                node["transport"] = xhttp::link(
                    v["path"].as_str().unwrap_or(""),
                    v["host"].as_str().unwrap_or(""),
                    v.get("mode")
                        .map(|value| value.as_str().context("XHTTP mode 须为文本"))
                        .transpose()?
                        .unwrap_or(""),
                    &v.get("extra")
                        .map(|value| {
                            value
                                .as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|| value.to_string())
                        })
                        .unwrap_or_default(),
                )?;
            }
            "quic" => {
                for field in ["host", "path"] {
                    ensure!(
                        v[field].as_str().is_none_or(str::is_empty),
                        "QUIC 传输不支持参数 {field}"
                    );
                }
                node["transport"] = json!({"type":"quic"});
            }
            "ws" | "httpupgrade" => {
                node["transport"] = link_transport(
                    v["net"].as_str().unwrap(),
                    v["path"].as_str().unwrap_or(""),
                    v["host"].as_str().unwrap_or(""),
                )
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
                node["transport"] = link_transport(
                    "http",
                    v["path"].as_str().unwrap_or(""),
                    v["host"].as_str().unwrap_or(""),
                )
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
        let (authority, query) = authority
            .split_once('?')
            .map_or((authority, String::new()), |(authority, query)| {
                (authority, format!("?{query}"))
            });
        if !authority.contains('@') {
            raw = format!(
                "ss://{}{query}#{}",
                decode(authority.trim_end_matches('/'))?,
                tag
            )
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
            if query_keys.contains("plugin") {
                ss_plugin::link(&q("plugin"), &mut node)?;
            }
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
            if query_keys.contains("encryption") {
                node["encryption"] = q("encryption").into();
            }
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
            if typ == "hysteria2" && query_keys.contains("mport") {
                node["server_ports"] = quic::ports(&q("mport"))?;
            }
        }
        "tuic" => {
            node["uuid"] = json!(user);
            node["password"] = json!(pass);
            if !q("congestion_control").is_empty() {
                node["congestion_control"] = json!(q("congestion_control"))
            }
            for field in ["udp_relay_mode", "heartbeat"] {
                if query_keys.contains(field) {
                    node[field] = q(field).into();
                }
            }
            if query_keys.contains("udp_over_stream") {
                node["udp_over_stream"] =
                    query_bool(&q("udp_over_stream"), "udp_over_stream")?.into();
            }
            for field in ["zero_rtt_handshake", "zero-rtt-handshake", "0rtt"] {
                if query_keys.contains(field) {
                    ensure!(
                        node.get("zero_rtt_handshake").is_none(),
                        "节点链接重复设置 zero_rtt_handshake"
                    );
                    node["zero_rtt_handshake"] = query_bool(&q(field), field)?.into();
                }
            }
        }
        "anytls" => {
            node["password"] = json!(if pass.is_empty() {
                user
            } else {
                format!("{user}:{pass}")
            });
            if query_keys.contains("client_metadata") {
                node["client_metadata"] = q("client_metadata").into();
            }
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
        if query_keys.contains("handshake_timeout") {
            tls["handshake_timeout"] = q("handshake_timeout").into();
        }
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
        let mut optional = json!({});
        for field in tls::link_fields() {
            if query_keys.contains(field) {
                optional[field] = q(field).into();
            }
        }
        tls::link(&optional, &mut tls, true)?;
        node["tls"] = tls;
    }
    match q("type").as_str() {
        "" | "tcp" => {}
        "ws" => node["transport"] = link_transport("ws", &q("path"), &q("host")),
        "grpc" => node["transport"] = json!({"type":"grpc","service_name":q("serviceName")}),
        "httpupgrade" => node["transport"] = link_transport("httpupgrade", &q("path"), &q("host")),
        "http" | "h2" => node["transport"] = link_transport("http", &q("path"), &q("host")),
        "xhttp" => {
            node["transport"] = xhttp::link(&q("path"), &q("host"), &q("mode"), &q("extra"))?
        }
        "quic" => node["transport"] = json!({"type":"quic"}),
        other => bail!("不支持的传输方式: {other}"),
    }
    for key in DIAL_FIELDS {
        if query_keys.contains(key) {
            node[key] = if matches!(
                key,
                "disable_tcp_keep_alive" | "tcp_fast_open" | "tcp_multi_path" | "udp_fragment"
            ) {
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
    ensure!(crate::protocol::server_port(node).is_some(), "节点端口无效");
    Ok(())
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
        "tfo",
        "mptcp",
    ];
    const DIAL_ALIASES: [(&str, &str); 6] = [
        ("udp-fragment", "udp_fragment"),
        ("interface-name", "bind_interface"),
        ("connect-timeout", "connect_timeout"),
        ("disable-tcp-keep-alive", "disable_tcp_keep_alive"),
        ("tcp-keep-alive", "tcp_keep_alive"),
        ("tcp-keep-alive-interval", "tcp_keep_alive_interval"),
    ];
    fields.extend(DIAL_FIELDS);
    fields.extend(DIAL_ALIASES.iter().map(|(alias, _)| *alias));
    if matches!(typ, "shadowsocks" | "vmess" | "vless") {
        fields.push("cipher");
    }
    if typ == "shadowsocks" {
        fields.extend(["plugin", "plugin-opts", "plugin_opts"]);
    }
    // Subscription generators also attach VMess fields to VLESS entries.
    // VLESS ignores them; its encryption and flow have their own fields.
    if matches!(typ, "vmess" | "vless") {
        fields.push("alterId");
    }
    if typ == "vless" {
        fields.push("encryption");
    }
    if matches!(typ, "shadowsocks" | "anytls" | "socks" | "naive") {
        fields.extend(["udp-over-tcp", "udp_over_tcp", "udp-over-tcp-version"]);
    }
    if matches!(typ, "shadowsocks" | "vmess" | "vless" | "trojan") {
        fields.push("smux");
    }
    if typ == "anytls" {
        fields.extend([
            "idle-session-check-interval",
            "idle-session-timeout",
            "min-idle-session",
            "client-metadata",
        ]);
    }
    if typ == "hysteria2" {
        fields.extend(["ports", "hop-interval", "up", "down"]);
    }
    if typ == "tuic" {
        fields.extend([
            "heartbeat-interval",
            "disable-sni",
            "reduce-rtt",
            "udp-over-stream",
        ]);
    }
    if typ == "naive" {
        fields.extend([
            "quic",
            "quic-session-receive-window",
            "stream-receive-window",
            "insecure-concurrency",
        ]);
    }
    if typ == "http" {
        fields.extend([
            "http-version",
            "disable-version-fallback",
            "headers",
            "path",
            "idle-timeout",
            "ping-timeout",
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
    fields.extend([
        "servername",
        "sni",
        "skip-cert-verify",
        "alpn",
        "client-fingerprint",
    ]);
    ensure!(
        v.get("skip-cert-verify").is_none_or(Value::is_boolean),
        "Clash skip-cert-verify 须为开关"
    );
    for field in ["servername", "sni", "client-fingerprint"] {
        ensure!(
            v.get(field).is_none_or(Value::is_string),
            "Clash {field} 须为文本"
        );
    }
    if tls_enabled {
        fields.extend(tls::CLASH_FIELDS);
        fields.push("reality-opts");
        fields.push("handshake-timeout");
        fields.push("ech-opts");
        fields.extend(tls::OPTIONAL_FIELDS.iter().map(|(alias, _, _)| *alias));
    } else {
        ensure!(
            v["skip-cert-verify"] != true,
            "未启用 TLS 时 skip-cert-verify 只能为 false"
        );
        // Subscriptions may attach a browser profile to every node. It only
        // affects TLS handshakes; without TLS it must not discard the node.
        for field in ["servername", "sni"] {
            ensure!(
                v.get(field).is_none_or(|value| value == ""),
                "未启用 TLS 时 {field} 只能为空"
            );
        }
        ensure!(
            v.get("alpn")
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
            "未启用 TLS 时 alpn 只能为空列表"
        );
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
        "xhttp" => fields.push("xhttp-opts"),
        _ => {}
    }
    known_fields(v, &fields, "Clash 节点")?;
    let mut n = json!({"type":typ,"tag":v["name"]});
    if typ == "shadowsocks" {
        ss_plugin::clash(v, &mut n)?;
    }
    n["server"] = v["server"].clone();
    n["server_port"] = json!(number(&v["port"]));
    quic::clash(v, typ, &mut n)?;
    if typ == "http" {
        for (source, target) in [
            ("http-version", "version"),
            ("disable-version-fallback", "disable_version_fallback"),
            ("headers", "headers"),
            ("path", "path"),
            ("idle-timeout", "idle_timeout"),
            ("ping-timeout", "ping_timeout"),
        ] {
            if let Some(value) = v.get(source) {
                n[target] = value.clone();
            }
        }
    }
    for (alias, field) in [("tfo", "tcp_fast_open"), ("mptcp", "tcp_multi_path")] {
        ensure!(
            v.get(alias).is_none() || v.get(field).is_none(),
            "Clash 节点重复设置 {field}"
        );
        if let Some(value) = v.get(alias).or_else(|| v.get(field)) {
            ensure!(value.is_boolean(), "Clash {alias} 须为开关");
            n[field] = value.clone();
        }
    }
    if typ == "vmess" {
        n["alter_id"] = alter_id(v.get("alterId"), "Clash alterId")?.into();
    }
    if typ == "vless"
        && let Some(encryption) = v.get("encryption")
    {
        n["encryption"] = encryption.clone();
    }
    if typ == "anytls" {
        if let Some(metadata) = v.get("client-metadata") {
            n["client_metadata"] = metadata.clone();
        }
        for (source, target) in [
            ("idle-session-check-interval", "idle_session_check_interval"),
            ("idle-session-timeout", "idle_session_timeout"),
            ("min-idle-session", "min_idle_session"),
        ] {
            if let Some(value) = v.get(source) {
                n[target] = if target == "min_idle_session" {
                    value.clone()
                } else {
                    let seconds = value
                        .as_u64()
                        .with_context(|| format!("Clash {source} 须为非负整数秒"))?;
                    format!("{seconds}s").into()
                };
            }
        }
    }
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
    }
    if matches!(typ, "shadowsocks" | "anytls" | "socks" | "naive") {
        ensure!(
            v.get("udp-over-tcp").is_none() || v.get("udp_over_tcp").is_none(),
            "Clash 节点重复设置 udp-over-tcp"
        );
        let uot = v.get("udp-over-tcp").or_else(|| v.get("udp_over_tcp"));
        if uot.is_some() || v.get("udp-over-tcp-version").is_some() {
            let mut options = match uot {
                None => json!({"enabled":false}),
                Some(Value::Bool(enabled)) => json!({"enabled":enabled}),
                Some(options) => {
                    ensure!(options.is_object(), "Clash udp-over-tcp 须为开关或对象");
                    options.clone()
                }
            };
            if let Some(version) = v.get("udp-over-tcp-version") {
                ensure!(
                    options.get("version").is_none(),
                    "Clash 节点重复设置 udp-over-tcp version"
                );
                options["version"] = version.clone();
            }
            n["udp_over_tcp"] = options;
        }
    };
    if let Some(mux) = v.get("smux") {
        known_fields(
            mux,
            &[
                "enabled",
                "protocol",
                "max-connections",
                "min-streams",
                "max-streams",
                "padding",
            ],
            "Clash smux",
        )?;
        let mut options = json!({});
        for (from, to) in [
            ("enabled", "enabled"),
            ("protocol", "protocol"),
            ("max-connections", "max_connections"),
            ("min-streams", "min_streams"),
            ("max-streams", "max_streams"),
            ("padding", "padding"),
        ] {
            if let Some(value) = mux.get(from) {
                options[to] = value.clone();
            }
        }
        n["multiplex"] = options;
    }
    if v["udp"] == false {
        n["network"] = json!("tcp");
    }
    if typ == "vmess" {
        if let Some(cipher) = v.get("cipher") {
            ensure!(cipher.is_string(), "Clash cipher 须为文本");
        }
        n["security"] = json!(
            v["cipher"]
                .as_str()
                .filter(|v| !v.is_empty())
                .unwrap_or("auto")
        )
    }
    if tls_enabled {
        let mut tls = json!({"enabled":true});
        if let Some(value) = v.get("handshake-timeout") {
            tls["handshake_timeout"] = if let Some(seconds) = value.as_u64() {
                format!("{seconds}s").into()
            } else {
                value.clone()
            };
        }
        if typ == "tuic"
            && let Some(value) = v.get("disable-sni")
        {
            ensure!(value.is_boolean(), "Clash disable-sni 须为开关");
            tls["disable_sni"] = value.clone();
        }
        for (from, to) in [
            ("servername", "server_name"),
            ("sni", "server_name"),
            ("skip-cert-verify", "insecure"),
            ("alpn", "alpn"),
        ] {
            if let Some(value) = v.get(from) {
                if to == "server_name" {
                    if value == "" {
                        continue;
                    }
                    ensure!(
                        tls.get(to).is_none_or(|previous| previous == value),
                        "Clash servername 与 sni 不能设置不同的服务器名"
                    );
                }
                tls[to] = value.clone()
            }
        }
        tls::copy_optional(v, &mut tls, false, "Clash 节点")?;
        tls::clash(v, &mut tls)?;
        if let Some(ech) = v.get("ech-opts") {
            known_fields(
                ech,
                &["enable", "config", "config-path", "query-server-name"],
                "Clash ech-opts",
            )?;
            let mut options = json!({"enabled":ech.get("enable").cloned().unwrap_or(json!(false))});
            for (from, to) in [
                ("config", "config"),
                ("config-path", "config_path"),
                ("query-server-name", "query_server_name"),
            ] {
                if let Some(value) = ech.get(from) {
                    options[to] = if from == "config" {
                        let text = value
                            .as_str()
                            .context("Clash ech-opts.config 须为 Base64 文本")?;
                        tls::config_pem(text, "Clash ech-opts.config")?.into()
                    } else {
                        value.clone()
                    };
                }
            }
            tls["ech"] = options;
        }
        if let Some(fp) = v.get("client-fingerprint").filter(|value| *value != "") {
            tls["utls"] = json!({"enabled":true,"fingerprint":fp})
        };
        if let Some(r) = v.get("reality-opts") {
            known_fields(r, &["public-key", "short-id"], "Clash reality-opts")?;
            tls["reality"] = json!({"enabled":true,"public_key":r["public-key"]});
            if let Some(short_id) = r.get("short-id") {
                tls["reality"]["short_id"] = short_id.clone();
            }
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
            n["transport"] = json!({"type":"ws"});
            if let Some(path) = v["ws-opts"].get("path") {
                let path = path.as_str().context("Clash ws-opts.path 须为文本")?;
                if !path.is_empty() {
                    n["transport"]["path"] = path.into();
                }
            }
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
            if let Some(path) = options.get("path") {
                let path = single_transport_text(path, "Clash HTTP path")?;
                if !path.is_empty() {
                    transport["path"] = json!(path);
                }
            }
            if let Some(method) = options.get("method") {
                let method = method.as_str().context("Clash HTTP method 须为文本")?;
                if !method.is_empty() {
                    transport["method"] = method.into();
                }
            }
            if network == "http" && transport.get("method").is_none() {
                transport["method"] = "GET".into();
            }
            if let Some(headers) = options.get("headers") {
                let headers = headers.as_object().context("Clash HTTP headers 须为对象")?;
                let mut extra = headers.clone();
                // The transport exposes Host separately from other headers.
                for (name, value) in headers {
                    if name.eq_ignore_ascii_case("host") {
                        http_hosts(&mut transport, value)?;
                        extra.remove(name);
                    }
                }
                if !extra.is_empty() {
                    transport["headers"] = json!(extra);
                }
            }
            if let Some(host) = options.get("host") {
                http_hosts(&mut transport, host)?;
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
            if let Some(path) = v["http-opts"].get("path") {
                let path = single_transport_text(path, "Clash HTTPUpgrade path")?;
                if !path.is_empty() {
                    transport["path"] = path.into();
                }
            }
            if let Some(host) = v["http-opts"]["headers"].get("Host") {
                let host = single_transport_text(host, "Clash HTTPUpgrade Host")?;
                if !host.is_empty() {
                    transport["host"] = host.into();
                }
            }
            n["transport"] = transport
        }
        "xhttp" => n["transport"] = xhttp::clash(&v["xhttp-opts"])?,
        "quic" => n["transport"] = json!({"type":"quic"}),
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
      host: [front.example.com, alternate.example.com]
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
            json!({"type":"http","host":["front.example.com","alternate.example.com"],"path":"/secret"})
        );
        assert_eq!(
            nodes[1]["transport"],
            json!({"type":"http","host":"front.example.com","path":"/video","method":"POST","headers":{"X-Token":["fixture"],"User-Agent":"AeroBox-test"}})
        );
    }

    #[test]
    fn unsupported_plugins_are_rejected_without_losing_other_nodes() {
        let source = json!({"proxies":[
            {"name":"plugin","type":"ss","server":"127.0.0.1","port":443,"cipher":"aes-128-gcm","password":"fixture-secret","plugin":"unknown-plugin","plugin-opts":{"mode":"http"}},
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
    fn reality_uses_default_firefox_without_changing_authentication() {
        let node = uri("vless://00000000-0000-4000-8000-000000000001@example.com:443?security=reality&pbk=CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk&sid=ab#R").unwrap();
        assert_eq!(
            node["tls"]["reality"]["public_key"],
            "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk"
        );
        crate::protocol::validate(&node).unwrap();
        let converted = crate::protocol::convert_outbound(node, "fixture").unwrap();
        let reality = &converted["client_chains"][0]["chain"][0]["protocol"];
        assert_eq!(reality["client_fingerprint"], "firefox");
        assert_eq!(reality["short_id"], "ab");
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
        let source = json!({"outbounds":[{"type":"vless","tag":"invalid-fingerprint","server":"example.com","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":true}}},{"type":"socks","tag":"local","server":"127.0.0.1","server_port":1080}]});
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
    fn unsupported_plugin_options_are_reported_without_silent_expansion() {
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
            ("client-fingerprint", json!(true)),
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
