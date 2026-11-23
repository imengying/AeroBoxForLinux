use crate::model::Settings;
use anyhow::{Context, Result, ensure};

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
    ensure!(port > 0, "DNS 端口须在 1 到 65535 之间");
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

pub fn validate_dns_settings(settings: &Settings) -> Result<()> {
    parse_dns_server(&settings.direct_dns)?;
    parse_dns_server(&settings.remote_dns)?;
    Ok(())
}
