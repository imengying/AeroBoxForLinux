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
    let body = body.trim_start_matches('\u{feff}').trim();
    if let Ok(value) = serde_yaml_ng::from_str::<Value>(body)
        && let Some(items) = value
            .as_array()
            .or_else(|| value["outbounds"].as_array())
            .or_else(|| value["endpoints"].as_array())
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
        ensure!(!nodes.is_empty(), "订阅没有节点");
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
    if let Some(link) = input.strip_prefix("wireguard://") {
        return wireguard(link);
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
        "hysteria" => "hysteria",
        "socks5" => "socks",
        "https" => "http",
        "anytls" => "anytls",
        "ssh" => "ssh",
        other => other,
    };
    ensure!(
        [
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "hysteria",
            "hysteria2",
            "tuic",
            "anytls",
            "ssh",
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
        "hysteria" => {
            node["auth_str"] = json!(if pass.is_empty() {
                user
            } else {
                format!("{user}:{pass}")
            });
            if !q("obfs").is_empty() {
                node["obfs"] = json!(q("obfs"))
            };
            for (from, to) in [
                ("upmbps", "up_mbps"),
                ("downmbps", "down_mbps"),
                ("up", "up_mbps"),
                ("down", "down_mbps"),
            ] {
                if let Ok(value) = q(from).parse::<u64>() {
                    node[to] = json!(value)
                }
            }
        }
        "anytls" => {
            node["password"] = json!(if pass.is_empty() {
                user
            } else {
                format!("{user}:{pass}")
            })
        }
        "ssh" => {
            node["user"] = json!(user);
            node["password"] = json!(pass)
        }
        "tuic" => {
            node["uuid"] = json!(user);
            node["password"] = json!(pass);
            if !q("congestion_control").is_empty() {
                node["congestion_control"] = json!(q("congestion_control"))
            }
        }
        "socks" | "http" if !user.is_empty() => {
            node["username"] = json!(user);
            node["password"] = json!(pass);
        }
        _ => {}
    }
    if ["trojan", "hysteria", "hysteria2", "tuic", "anytls"].contains(&typ)
        || (typ == "http" && u.scheme() == "https")
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
            tls["utls"] = json!({"enabled":true,"fingerprint":if q("fp").is_empty(){"chrome".to_owned()}else{q("fp")}});
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
    if node["type"] == "wireguard" {
        ensure!(
            node["peers"].as_array().is_some_and(|peers| {
                peers.iter().any(|peer| {
                    peer["address"]
                        .as_str()
                        .is_some_and(|host| !host.is_empty())
                        && (1..=65535).contains(&number(&peer["port"]))
                })
            }),
            "WireGuard 节点缺少有效服务器"
        );
        ensure!(
            node["private_key"]
                .as_str()
                .is_some_and(|key| !key.is_empty()),
            "WireGuard 节点缺少私钥"
        );
        return Ok(());
    }
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

/// `wireguard://private_key@host:port?publickey=…&address=…&reserved=…`
/// is what most share links and sysbox exports use. Address values may repeat.
fn wireguard(link: &str) -> Result<Value> {
    let u = Url::parse(&format!("wireguard://{link}"))?;
    let host = u.host_str().context("WireGuard 节点缺少服务器")?;
    let port = u.port().unwrap_or(51820);
    let query = |key: &str| u.query_pairs().find(|(k, _)| k == key).map(|(_, v)| v);
    let private_key = unescape(u.username());
    ensure!(!private_key.is_empty(), "WireGuard 节点缺少私钥");
    let public_key = query("publickey")
        .or_else(|| query("public-key"))
        .or_else(|| query("peer_public_key"))
        .context("WireGuard 节点缺少对端公钥")?
        .into_owned();
    let addresses: Vec<String> = u
        .query_pairs()
        .filter(|(k, _)| k == "address" || k == "local_address")
        .map(|(_, v)| v.into_owned())
        .collect();
    ensure!(!addresses.is_empty(), "WireGuard 节点缺少本地地址");
    let mut peer = json!({"address":host,"port":port,"public_key":public_key,"allowed_ips":["0.0.0.0/0","::/0"]});
    if let Some(key) = query("presharedkey").or_else(|| query("pre-shared-key")) {
        peer["pre_shared_key"] = json!(key)
    }
    if let Some(reserved) = query("reserved").or_else(|| query("reserved-bytes")) {
        peer["reserved"] = json!(
            reserved
                .split(',')
                .filter_map(|s| s.trim().parse::<u8>().ok())
                .collect::<Vec<_>>()
        )
    }
    Ok(json!({
        "type":"wireguard",
        "tag":unescape(u.fragment().unwrap_or("WireGuard")),
        "address":addresses,
        "private_key":private_key,
        "peers":[peer]
    }))
}

fn supported_plugin(plugin: &str) -> Result<&str> {
    match plugin {
        "obfs" | "simple-obfs" | "obfs-local" => Ok("obfs-local"),
        "v2ray-plugin" => Ok("v2ray-plugin"),
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
        "ss" => "shadowsocks",
        "socks5" => "socks",
        "hy" | "hysteria1" => "hysteria",
        t => t,
    };
    ensure!(
        [
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "hysteria",
            "hysteria2",
            "tuic",
            "anytls",
            "ssh",
            "wireguard",
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
    if typ == "wireguard" {
        // Clash keeps the peer fields inline; sing-box 1.13+ expects a
        // standalone endpoint with an address list and a peers array.
        let addresses: Vec<String> = match &v["ip"] {
            Value::String(ip) => vec![if ip.contains('/') {
                ip.clone()
            } else {
                format!("{ip}/32")
            }],
            Value::Array(items) => items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => vec![],
        };
        let mut peer = json!({
            "address":v["server"],
            "port":number(&v["port"]),
            "public_key":v["public-key"],
            "allowed_ips":["0.0.0.0/0","::/0"]
        });
        if let Some(key) = v.get("pre-shared-key") {
            peer["pre_shared_key"] = key.clone()
        }
        if let Some(reserved) = v.get("reserved") {
            peer["reserved"] = match reserved {
                Value::String(text) => json!(
                    text.split(',')
                        .filter_map(|s| s.trim().parse::<u8>().ok())
                        .collect::<Vec<_>>()
                ),
                other => other.clone(),
            }
        }
        let mut endpoint = json!({
            "type":"wireguard",
            "tag":v["name"],
            "private_key":v["private-key"],
            "peers":[peer]
        });
        if !addresses.is_empty() {
            endpoint["address"] = json!(addresses)
        }
        if let Some(mtu) = v.get("mtu") {
            endpoint["mtu"] = mtu.clone()
        }
        validate_server(&endpoint)?;
        return Ok(endpoint);
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
            n[to] = value.clone()
        }
    }
    if typ == "ssh" {
        n["user"] = v["username"].clone()
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
    if typ == "hysteria" {
        for (from, to) in [("up", "up_mbps"), ("down", "down_mbps")] {
            if let Some(value) = v.get(from) {
                n[to] = value.clone()
            }
        }
        if let Some(auth) = v.get("auth-str").or_else(|| v.get("auth_str")) {
            n["auth_str"] = auth.clone()
        }
        if let Some(obfs) = v.get("obfs").and_then(Value::as_str) {
            n["obfs"] = json!(obfs)
        }
    }
    if typ == "hysteria2" {
        for (from, to) in [("up", "up_mbps"), ("down", "down_mbps")] {
            if let Some(value) = v.get(from) {
                n[to] = value.clone()
            }
        }
    }
    if v["tls"] == true || ["trojan", "hysteria", "hysteria2", "tuic", "anytls"].contains(&typ) {
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
            tls["utls"] = json!({"enabled":true,"fingerprint":v
                .get("client-fingerprint")
                .cloned()
                .unwrap_or(json!("chrome"))});
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
            let mut transport = json!({
                "type":"http",
                "path":v["h2-opts"]["path"].as_str().unwrap_or("/")
            });
            if let Some(host) = v["h2-opts"]["host"].as_str() {
                transport["host"] = json!(host)
            }
            n["transport"] = transport
        }
        "httpupgrade" => {
            let mut transport = json!({
                "type":"httpupgrade",
                "path":v["http-opts"]["path"].as_str().unwrap_or("/")
            });
            if let Some(host) = v["http-opts"]["headers"]["Host"].as_str() {
                transport["host"] = json!(host)
            }
            n["transport"] = transport
        }
        other => bail!("不支持的 Clash 传输: {other}"),
    }
    if let Some(obfs) = v.get("obfs").filter(|_| typ == "hysteria2") {
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
    fn share_links_map_to_sing_box_fields() {
        let anytls = uri("anytls://secret@example.com:443?sni=example.com#A").unwrap();
        assert_eq!(anytls["type"], "anytls");
        assert_eq!(anytls["password"], "secret");
        assert_eq!(anytls["tls"]["server_name"], "example.com");

        let hy = uri("hysteria://auth@example.com:443?upmbps=20&downmbps=50&obfs=x#H").unwrap();
        assert_eq!(hy["type"], "hysteria");
        assert_eq!(hy["auth_str"], "auth");
        assert_eq!(hy["up_mbps"], 20);
        assert_eq!(hy["obfs"], "x");

        let reality = uri("vless://uuid@example.com:443?security=reality&pbk=k&sid=ab#R").unwrap();
        assert_eq!(reality["tls"]["reality"]["public_key"], "k");
        // Reality requires uTLS; a missing fingerprint must not silently
        // produce a configuration the core rejects.
        assert!(reality["tls"]["utls"]["fingerprint"].is_string());

        let ssh = uri("ssh://user:pass@example.com:22#S").unwrap();
        assert_eq!(ssh["user"], "user");
        assert_eq!(ssh["password"], "pass");
    }

    #[test]
    fn wireguard_links_use_endpoint_shape() {
        let link = "wireguard://YWJj@example.com:51820?publickey=cHVi&address=10.0.0.2%2F32&address=fd00::2%2F128&reserved=1,2,3#WG";
        let node = uri(link).unwrap();
        assert_eq!(node["type"], "wireguard");
        assert_eq!(node["private_key"], "YWJj");
        assert_eq!(node["address"], json!(["10.0.0.2/32", "fd00::2/128"]));
        assert_eq!(node["peers"][0]["address"], "example.com");
        assert_eq!(node["peers"][0]["port"], 51820);
        // Reserved bytes are a byte array in sing-box, not strings.
        assert_eq!(node["peers"][0]["reserved"], json!([1, 2, 3]));
    }

    #[test]
    fn clash_extra_protocols_and_transports_convert() {
        let source = json!({"proxies":[
            {"name":"wg","type":"wireguard","server":"wg.example.com","port":51820,"ip":"10.9.0.2","private-key":"a","public-key":"b","reserved":"1,2,3"},
            {"name":"any","type":"anytls","server":"a.example.com","port":443,"password":"p","sni":"a.example.com"},
            {"name":"hy","type":"hysteria","server":"h.example.com","port":443,"auth-str":"auth","up":20,"down":50,"obfs":"x"},
            {"name":"ssh","type":"ssh","server":"s.example.com","port":22,"username":"u","password":"p"},
            {"name":"h2","type":"vless","server":"v.example.com","port":443,"uuid":"u","network":"h2","tls":true,"h2-opts":{"host":"v.example.com","path":"/h2"}}
        ]});
        let nodes = parse(&source.to_string()).unwrap();
        assert_eq!(nodes[0]["private_key"], "a");
        assert_eq!(nodes[0]["address"], json!(["10.9.0.2/32"]));
        assert_eq!(nodes[0]["peers"][0]["reserved"], json!([1, 2, 3]));
        assert_eq!(nodes[1]["type"], "anytls");
        assert_eq!(nodes[2]["type"], "hysteria");
        assert_eq!(nodes[2]["auth_str"], "auth");
        assert_eq!(nodes[3]["user"], "u");
        assert_eq!(nodes[4]["transport"]["type"], "http");
        assert_eq!(nodes[4]["transport"]["path"], "/h2");
    }
}
