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
    if let Ok(value) = serde_yaml_ng::from_str::<Value>(body)
        && let Some(items) = value
            .as_array()
            .or_else(|| value["outbounds"].as_array())
            .or_else(|| value["proxies"].as_array())
    {
        let nodes = items
            .iter()
            .map(|v| {
                if v.get("name").is_some() {
                    clash(v)
                } else {
                    Ok(v.clone())
                }
            })
            .collect::<Result<Vec<_>>>()?;
        validate_nodes(&nodes)?;
        return Ok(nodes);
    }
    let decoded = if !body.contains("://") {
        decode(body)?
    } else {
        body.to_owned()
    };
    let nodes = decoded
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate()
        .map(|(i, line)| uri(line).with_context(|| format!("第 {} 个节点", i + 1)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(!nodes.is_empty(), "订阅没有节点");
    validate_nodes(&nodes)?;
    Ok(nodes)
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
        other => other,
    };
    ensure!(
        [
            "shadowsocks",
            "vless",
            "trojan",
            "hysteria2",
            "tuic",
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
                node["plugin"] = json!(plugin);
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
        _ => {
            if !user.is_empty() {
                node["username"] = json!(user);
                node["password"] = json!(pass)
            }
        }
    }
    if ["trojan", "hysteria2", "tuic"].contains(&typ)
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
fn clash(v: &Value) -> Result<Value> {
    let typ = match v["type"].as_str().unwrap_or("") {
        "ss" => "shadowsocks",
        "socks5" => "socks",
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
    for (from, to) in [
        ("password", "password"),
        ("username", "username"),
        ("uuid", "uuid"),
        ("alterId", "alter_id"),
        ("flow", "flow"),
        ("congestion-controller", "congestion_control"),
    ] {
        if let Some(value) = v.get(from) {
            n[to] = value.clone()
        }
    }
    if typ == "shadowsocks" {
        n["method"] = v["cipher"].clone()
    };
    if typ == "vmess" {
        n["security"] = json!(v["cipher"].as_str().unwrap_or("auto"))
    }
    if v["tls"] == true || ["trojan", "hysteria2", "tuic"].contains(&typ) {
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
