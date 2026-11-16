use crate::model::Settings;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

const DIRECT_DNS: &str = "aerobox-dns-direct";
const PROXY_DNS: &str = "aerobox-dns-proxy";
const TUN_TAG: &str = "aerobox-tun";

fn object<'a>(value: &'a mut Value, key: &str) -> Result<&'a mut Value> {
    ensure!(value.is_object(), "配置必须是对象");
    if value.get(key).is_none() {
        value[key] = json!({});
    }
    ensure!(value[key].is_object(), "{key} 必须是对象");
    Ok(&mut value[key])
}
fn array<'a>(value: &'a mut Value, key: &str) -> Result<&'a mut Vec<Value>> {
    ensure!(value.is_object(), "配置必须是对象");
    if value.get(key).is_none() {
        value[key] = json!([]);
    }
    value[key]
        .as_array_mut()
        .with_context(|| format!("{key} 必须是数组"))
}
fn unique_tag(items: &[Value], base: &str) -> String {
    let mut tag = base.to_owned();
    let mut suffix = 1;
    while items.iter().any(|v| v["tag"] == tag) {
        tag = format!("{base}-{suffix}");
        suffix += 1;
    }
    tag
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerSpec {
    pub kind: String,
    pub server: String,
    pub port: u16,
    pub path: Option<String>,
}

/// Parse the same UDP/TCP/TLS/HTTPS/QUIC endpoint forms as the Android app.
/// A bootstrap resolver is added to hostname-based endpoints by the caller.
pub fn parse_dns_server(value: &str) -> Result<DnsServerSpec> {
    use std::net::IpAddr;
    let value = value.trim();
    ensure!(!value.is_empty(), "DNS 地址不能为空");
    let (kind, raw) = value
        .split_once("://")
        .map_or(("udp", value), |(scheme, raw)| (scheme, raw));
    ensure!(
        matches!(kind, "udp" | "tcp" | "tls" | "https" | "quic"),
        "DNS 仅支持 UDP、TCP、TLS、HTTPS 或 QUIC"
    );
    let default_port = match kind {
        "https" => 443,
        "tls" | "quic" => 853,
        _ => 53,
    };
    let (server, port, path) = if kind == "https" {
        let url = url::Url::parse(value).context("HTTPS DNS 地址无效")?;
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "HTTPS DNS 不能包含凭据、查询参数或片段"
        );
        (
            url.host_str().context("DNS 缺少主机名")?.to_owned(),
            url.port().unwrap_or(default_port),
            Some(if url.path().is_empty() {
                "/dns-query".into()
            } else {
                url.path().into()
            }),
        )
    } else {
        ensure!(
            !raw.contains(['/', '?', '#', '@']) && !raw.chars().any(char::is_whitespace),
            "DNS 地址只能包含主机名和可选端口"
        );
        // A bracketed IP may include a port too. Handle it before the generic
        // host parser so IPv6's colons cannot be mistaken for a port separator.
        if let Ok(address) = raw.trim_matches(['[', ']']).parse::<std::net::SocketAddr>() {
            (address.ip().to_string(), address.port(), None)
        } else if let Ok(ip) = raw.trim_matches(['[', ']']).parse::<IpAddr>() {
            (ip.to_string(), default_port, None)
        } else {
            let url = url::Url::parse(&format!("{kind}://{raw}")).context("DNS 地址无效")?;
            ensure!(
                url.username().is_empty()
                    && url.password().is_none()
                    && url.path().is_empty()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "DNS 地址无效"
            );
            (
                url.host_str().context("DNS 缺少主机名")?.to_owned(),
                url.port().unwrap_or(default_port),
                None,
            )
        }
    };
    let server = server.trim_matches(['[', ']']);
    ensure!(
        server.parse::<IpAddr>().is_ok()
            || (server.len() <= 253
                && server.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                })),
        "DNS 主机名或 IP 地址无效"
    );
    Ok(DnsServerSpec {
        kind: kind.into(),
        server: server.into(),
        port,
        path,
    })
}

pub fn dns_server_json(tag: &str, address: &str, resolver: &str) -> Result<Value> {
    use std::net::IpAddr;
    let spec = parse_dns_server(address)?;
    let mut server = json!({
        "type": spec.kind,
        "tag": tag,
        "server": spec.server,
        "server_port": spec.port,
    });
    if let Some(path) = spec.path {
        server["path"] = json!(path);
    }
    if spec.server.parse::<IpAddr>().is_err() {
        server["domain_resolver"] = json!({"server":resolver,"strategy":"prefer_ipv4"});
    }
    Ok(server)
}

pub fn validate_dns_settings(settings: &Settings) -> Result<()> {
    parse_dns_server(&settings.direct_dns).context("直连 DNS 地址无效")?;
    parse_dns_server(&settings.remote_dns).context("远程 DNS 地址无效")?;
    Ok(())
}

/// Apply the app's network controls to a generated copy. The editable profile
/// stays intact; unrelated inbound, outbound, DNS and route fields are preserved.
pub fn apply_settings(config: &mut Value, settings: &Settings) -> Result<()> {
    apply_profile_settings(config, settings, None, None)
}

pub fn apply_profile_settings(
    config: &mut Value,
    settings: &Settings,
    lan_tag: Option<&str>,
    _ads_tag: Option<&str>,
) -> Result<()> {
    settings.validate()?;
    ensure!(config.is_object(), "配置必须是对象");
    object(config, "log")?["level"] = json!(settings.log_level);
    let final_outbound = config["route"]["final"].as_str().map(str::to_owned);
    let outbounds = array(config, "outbounds")?;
    for outbound in outbounds.iter_mut() {
        if matches!(outbound["type"].as_str(), Some("selector" | "urltest")) {
            outbound["interrupt_exist_connections"] = json!(true);
        }
    }
    let direct = if let Some(tag) = outbounds
        .iter()
        .find(|v| v["type"] == "direct" && v["tag"].is_string())
        .and_then(|v| v["tag"].as_str())
    {
        tag.to_string()
    } else {
        let tag = unique_tag(outbounds, "aerobox-direct");
        outbounds.push(json!({"type":"direct", "tag":tag}));
        tag
    };
    let eligible_proxy = |v: &&Value| {
        !matches!(v["type"].as_str(), Some("direct" | "block" | "dns"))
            && v["tag"].as_str().is_some_and(|tag| !tag.is_empty())
    };
    // A valid final selector is the profile's intended default group. A node
    // merely named "proxy" must not override it or turn global mode into direct.
    let proxy = outbounds
        .iter()
        .filter(eligible_proxy)
        .find(|v| v["tag"].as_str() == final_outbound.as_deref())
        .or_else(|| {
            outbounds
                .iter()
                .filter(eligible_proxy)
                .find(|v| v["tag"] == "proxy")
        })
        .or_else(|| {
            outbounds
                .iter()
                .find(|v| v["type"] == "selector" && v["tag"].is_string())
        })
        .or_else(|| outbounds.iter().find(eligible_proxy))
        .and_then(|v| v["tag"].as_str())
        .unwrap_or(&direct)
        .to_string();
    let direct_has_options = outbounds
        .iter()
        .any(|v| v["tag"] == direct && v.as_object().is_some_and(|fields| fields.len() > 2));
    let rule_outbound = final_outbound
        .as_deref()
        .filter(|tag| !tag.is_empty())
        .or_else(|| outbounds.first().and_then(|v| v["tag"].as_str()))
        .unwrap_or(&direct)
        .to_owned();

    let inbounds = array(config, "inbounds")?;
    if !settings.tun_enabled {
        inbounds.retain(|v| v["type"] != "tun");
    }
    if settings.tun_enabled && !inbounds.iter().any(|v| v["type"] == "tun") {
        let tag = unique_tag(inbounds, TUN_TAG);
        inbounds.push(json!({"type":"tun", "tag":tag, "interface_name":"aerobox0"}));
    }
    for inbound in inbounds.iter_mut() {
        if inbound["type"] == "tun" {
            let mut addresses: Vec<Value> =
                inbound["address"].as_array().cloned().unwrap_or_default();
            if let Some(single) = inbound["address"].as_str() {
                addresses.push(json!(single));
            }
            if !addresses
                .iter()
                .any(|v| v.as_str().is_some_and(|s| !s.contains(':')))
            {
                addresses.push(json!("172.19.0.1/30"));
            }
            if settings.ipv6 {
                if !addresses
                    .iter()
                    .any(|v| v.as_str().is_some_and(|s| s.contains(':')))
                {
                    addresses.push(json!("fdfe:dcba:9876::1/126"));
                }
            } else {
                addresses.retain(|v| v.as_str().is_some_and(|s| !s.contains(':')));
            }
            inbound["address"] = json!(addresses);
            inbound["auto_route"] = json!(true);
            inbound["strict_route"] = json!(settings.strict_route);
            inbound["stack"] = json!(settings.tun_stack);
            inbound["mtu"] = json!(settings.tun_mtu);
            // Supported since sing-box 1.14. Native DNS setup must respect the
            // same switch as the explicit DNS interception rules below.
            inbound["dns_mode"] = json!(if settings.dns_hijack {
                "hijack"
            } else {
                "disabled"
            });
        } else if matches!(inbound["type"].as_str(), Some("mixed" | "http" | "socks")) {
            let host = inbound["listen"].as_str().unwrap_or("127.0.0.1");
            if settings.allow_lan && inbound["tag"] != "aerobox-download-in" {
                if matches!(host, "127.0.0.1" | "::1" | "localhost" | "0.0.0.0" | "::") {
                    inbound["listen"] = json!(if settings.ipv6 { "::" } else { "0.0.0.0" });
                }
            } else {
                inbound["listen"] = json!(if settings.ipv6 && host.contains(':') {
                    "::1"
                } else {
                    "127.0.0.1"
                });
            }
        }
    }
    // Authenticated and TUN-only imports still need an application-local entry.
    if !inbounds.iter().any(|v| {
        matches!(v["type"].as_str(), Some("mixed" | "http" | "socks"))
            && v["users"].as_array().is_none_or(Vec::is_empty)
            && v["listen_port"]
                .as_u64()
                .is_some_and(|p| p > 0 && p <= 65535)
    }) {
        let tag = unique_tag(inbounds, "aerobox-download-in");
        let port = (2081..=65535)
            .find(|port| !inbounds.iter().any(|v| v["listen_port"] == *port))
            .context("没有可用的本地下载端口")?;
        inbounds.push(json!({"type":"mixed","tag":tag,"listen":"127.0.0.1","listen_port":port}));
    }

    let dns = object(config, "dns")?;
    dns["strategy"] = json!(if settings.ipv6 {
        "prefer_ipv4"
    } else {
        "ipv4_only"
    });
    dns["disable_cache"] = json!(!settings.dns_cache);
    if !settings.dns_cache {
        dns.as_object_mut().unwrap().remove("optimistic");
    }
    let servers = array(dns, "servers")?;
    let direct_dns = unique_tag(servers, DIRECT_DNS);
    let mut direct_server = dns_server_json(&direct_dns, &settings.direct_dns, "dns-local")?;
    if direct_has_options {
        direct_server["detour"] = json!(direct);
    }
    servers.push(direct_server);
    let proxy_dns = unique_tag(servers, PROXY_DNS);
    let mut proxy_server = dns_server_json(&proxy_dns, &settings.remote_dns, &direct_dns)?;
    if proxy != direct || direct_has_options {
        proxy_server["detour"] = json!(proxy);
    }
    servers.push(proxy_server);
    dns["final"] = json!(proxy_dns);
    let strategy = if settings.ipv6 {
        "prefer_ipv4"
    } else {
        "ipv4_only"
    };
    let mut dns_rules = vec![];
    if !settings.ipv6 {
        dns_rules.push(json!({"query_type":"AAAA","action":"predefined","rcode":"NOERROR"}));
    }
    dns_rules.push(json!({"clash_mode":"direct","server":direct_dns,"action":"route"}));
    dns_rules.push(json!({"clash_mode":"global","server":proxy_dns,"action":"route"}));
    let previous = std::mem::take(array(dns, "rules")?);
    dns_rules.extend(
        previous
            .into_iter()
            .filter(|r| r.get("clash_mode").is_none()),
    );
    dns["rules"] = json!(dns_rules);

    let route = object(config, "route")?;
    route["auto_detect_interface"] = json!(true);
    // The node hostname resolver must also obey the IPv6 preference.
    let resolver = route
        .get("default_domain_resolver")
        .cloned()
        .unwrap_or(json!(direct_dns));
    route["default_domain_resolver"] = if resolver.is_object() {
        let mut resolver = resolver;
        resolver["strategy"] = json!(strategy);
        resolver
    } else {
        json!({"server":resolver.as_str().unwrap_or(&direct_dns),"strategy":strategy})
    };
    let previous = std::mem::take(array(route, "rules")?);
    let mut rules = vec![];
    if !settings.ipv6 {
        rules.push(json!({"ip_version":6,"action":"reject"}));
    }
    if settings.sniff {
        rules.push(json!({"action":"sniff"}));
    }
    if settings.dns_hijack {
        rules.push(json!({"type":"logical","mode":"or","rules":[{"protocol":"dns"},{"port":53}],"action":"hijack-dns"}));
    }
    // Mode overrides traffic policy, including LAN bypass and ad blocking.
    // DNS interception and the explicit IPv6 switch remain transport controls.
    rules.push(json!({"clash_mode":"direct","action":"route","outbound":direct}));
    rules.push(json!({"clash_mode":"global","action":"route","outbound":proxy}));
    if settings.bypass_lan {
        rules.push(json!({"ip_is_private":true,"action":"route","outbound":direct}));
        if let Some(tag) = lan_tag {
            rules.push(json!({"rule_set":tag,"action":"route","outbound":direct}));
        }
    }
    rules.extend(previous.into_iter().filter(|r| {
        !matches!(r["action"].as_str(), Some("sniff" | "hijack-dns"))
            && r.get("clash_mode").is_none()
            && !(r["ip_is_private"] == true && r["outbound"] == direct)
    }));
    // sing-box builds its available modes from referenced rule modes. Keep
    // "rule" selectable even when the core starts in direct/global mode.
    rules.push(json!({"clash_mode":"rule","action":"route","outbound":rule_outbound}));
    route["rules"] = json!(rules);
    let experimental = object(config, "experimental")?;
    let api = object(experimental, "clash_api")?;
    if api["external_controller"]
        .as_str()
        .is_none_or(str::is_empty)
    {
        api["external_controller"] = json!("127.0.0.1:9090");
    }
    if api.get("secret").is_none() {
        api["secret"] = json!(crate::model::id());
    }
    api["default_mode"] = json!(settings.routing_mode);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Profile;
    #[test]
    fn authenticated_imports_get_a_private_download_listener_without_port_collisions() {
        let mut config = Profile::new("import").config;
        config["inbounds"][0]["users"] = json!([{"username":"u","password":"p"}]);
        config["inbounds"][0]["listen_port"] = json!(2081);
        let settings = Settings {
            allow_lan: true,
            ..Settings::default()
        };
        apply_settings(&mut config, &settings).unwrap();
        let local = &config["inbounds"][1];
        assert_eq!(local["tag"], "aerobox-download-in");
        assert_eq!(local["listen"], "127.0.0.1");
        assert_eq!(local["listen_port"], 2082);
        assert_eq!(config["inbounds"][0]["users"][0]["password"], "p");
    }
    #[test]
    fn controls_cover_dual_stack_and_keep_custom_fields() {
        let mut config = Profile::new("test").config;
        config["inbounds"][0]["tcp_fast_open"] = json!(true);
        let settings = Settings {
            tun_enabled: true,
            ipv6: true,
            ..Settings::default()
        };
        apply_settings(&mut config, &settings).unwrap();
        let tun = config["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["type"] == "tun")
            .unwrap();
        assert_eq!(tun["address"].as_array().unwrap().len(), 2);
        assert_eq!(config["inbounds"][0]["tcp_fast_open"], true);
        assert!(
            config["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["clash_mode"] == "global")
        );
    }
    #[test]
    fn ipv4_only_disables_aaaa_and_tun_and_does_not_open_lan() {
        let mut config = Profile::new("test").config;
        config["inbounds"][0]["listen"] = json!("::");
        let settings = Settings {
            ipv6: false,
            dns_cache: false,
            sniff: false,
            dns_hijack: false,
            bypass_lan: false,
            ..Settings::default()
        };
        apply_settings(&mut config, &settings).unwrap();
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["dns"]["rules"][0]["query_type"], "AAAA");
        assert_eq!(config["dns"]["disable_cache"], true);
        assert!(
            config["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["type"] != "tun")
        );
        assert!(
            config["route"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["action"] != "sniff"
                    && r["action"] != "hijack-dns"
                    && r["ip_is_private"] != true)
        );
    }
    #[test]
    fn malformed_imports_return_errors() {
        let mut config = json!({"dns":{"servers":42}});
        assert!(apply_settings(&mut config, &Settings::default()).is_err());
        let mut config = Profile::new("test").config;
        let settings = Settings {
            tun_enabled: true,
            tun_mtu: 900,
            ..Settings::default()
        };
        assert!(apply_settings(&mut config, &settings).is_err());
    }

    #[test]
    fn custom_dns_servers_preserve_protocols_bootstrap_and_routing() {
        for address in [
            "223.5.5.5",
            "tcp://223.5.5.5:5353",
            "tls://dns.alidns.com",
            "https://dns.alidns.com/dns-query",
            "quic://dns.adguard-dns.com",
            "udp://[2400:3200::1]:53",
        ] {
            let spec = parse_dns_server(address).unwrap();
            assert!(!spec.server.is_empty());
        }
        for invalid in [
            "",
            "http://1.1.1.1",
            "https://user:password@1.1.1.1/dns-query",
            "udp://example.com/path",
            "udp://-invalid.example",
        ] {
            assert!(parse_dns_server(invalid).is_err(), "accepted {invalid}");
        }
        let settings = Settings {
            direct_dns: "https://dns.alidns.com/dns-query".into(),
            remote_dns: "tls://one.one.one.one".into(),
            ..Settings::default()
        };
        let mut config = Profile::new("dns").config;
        config["route"]["final"] = json!("proxy");
        apply_settings(&mut config, &settings).unwrap();
        let direct = config["dns"]["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|server| server["tag"] == "aerobox-dns-direct")
            .unwrap()
            .clone();
        let remote = config["dns"]["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|server| server["tag"] == "aerobox-dns-proxy")
            .unwrap()
            .clone();
        assert_eq!(direct["type"], "https");
        assert_eq!(direct["domain_resolver"]["server"], "dns-local");
        assert_eq!(remote["type"], "tls");
        assert_eq!(remote["server_port"], 853);
        assert_eq!(remote["domain_resolver"]["server"], "aerobox-dns-direct");
        assert_eq!(remote["detour"], "proxy");
        assert_eq!(config["dns"]["final"], "aerobox-dns-proxy");
        assert!(
            config["dns"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| rule["clash_mode"] == "global"
                    && rule["server"] == "aerobox-dns-proxy")
        );
    }
}
