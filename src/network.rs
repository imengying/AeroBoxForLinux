use anyhow::{Context, Result, bail, ensure};
use reqwest::{Proxy, blocking::Client};
use serde_json::Value;
use std::{fs, io::Read, net::IpAddr, time::Duration};

#[derive(Clone, Debug, Default)]
pub struct NetworkInfo {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub via_proxy: bool,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryUsage {
    pub app_bytes: Option<u64>,
    pub core_bytes: Option<u64>,
}

/// None means the running configuration has TUN routing and no usable local
/// HTTP/SOCKS listener. A stopped core is handled separately by the caller.
pub(crate) fn proxy_url(config: &Value) -> Result<Option<url::Url>> {
    let inbounds = config["inbounds"]
        .as_array()
        .context("运行配置缺少代理入口")?;
    let inbound = inbounds
        .iter()
        .filter(|inbound| {
            matches!(inbound["type"].as_str(), Some("mixed" | "http" | "socks"))
                && inbound["users"].as_array().is_none_or(Vec::is_empty)
                && inbound["listen_port"]
                    .as_u64()
                    .is_some_and(|port| (1..=65535).contains(&port))
        })
        .min_by_key(|inbound| {
            if inbound["tag"] == "aerobox-download-in" {
                0
            } else {
                1
            }
        });
    let Some(inbound) = inbound else {
        if inbounds.iter().any(|inbound| inbound["type"] == "tun") {
            return Ok(None);
        }
        bail!("运行配置没有可用的本地下载代理入口")
    };
    let host = match inbound["listen"].as_str().unwrap_or("127.0.0.1") {
        "0.0.0.0" | "" => "127.0.0.1",
        "::" => "::1",
        host => host,
    };
    let host: IpAddr = host.parse().context("代理监听地址无效")?;
    let scheme = if inbound["type"] == "socks" {
        "socks5h"
    } else {
        "http"
    };
    let mut endpoint = url::Url::parse(&format!("{scheme}://127.0.0.1"))?;
    endpoint
        .set_ip_host(host)
        .map_err(|_| anyhow::anyhow!("代理监听地址无效"))?;
    endpoint
        .set_port(Some(inbound["listen_port"].as_u64().unwrap() as u16))
        .map_err(|_| anyhow::anyhow!("代理端口无效"))?;
    Ok(Some(endpoint))
}

pub(crate) fn client(config: Option<&Value>, timeout: Duration) -> Result<Client> {
    let mut builder = Client::builder()
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(concat!("AeroBox/", env!("CARGO_PKG_VERSION")));
    if let Some(config) = config
        && let Some(endpoint) = proxy_url(config)?
    {
        builder = builder.proxy(Proxy::all(endpoint)?);
    }
    Ok(builder.build()?)
}

pub(crate) fn detect(client: Client, ipv6: bool, via_proxy: bool) -> Result<NetworkInfo> {
    let (v4, v6) = std::thread::scope(|scope| {
        let client_v4 = client.clone();
        let v4 = scope.spawn(move || detect_family(&client_v4, false));
        let v6 = ipv6.then(|| scope.spawn(move || detect_family(&client, true)));
        (
            v4.join()
                .unwrap_or_else(|_| Err(anyhow::anyhow!("IPv4 检测中断"))),
            v6.map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("IPv6 检测中断")))
            }),
        )
    });
    let ipv4 = v4.ok();
    let ipv6 = v6.and_then(Result::ok);
    ensure!(
        ipv4.is_some() || ipv6.is_some(),
        "无法检测出口 IP，请检查当前连接后重试"
    );
    Ok(NetworkInfo {
        ipv4,
        ipv6,
        via_proxy,
    })
}

fn detect_family(client: &Client, ipv6: bool) -> Result<String> {
    let endpoints = if ipv6 {
        ["https://api6.ipify.org", "https://ipv6.icanhazip.com"]
    } else {
        ["https://api4.ipify.org", "https://ipv4.icanhazip.com"]
    };
    for endpoint in endpoints {
        if let Ok(ip) = detect_endpoint(client, endpoint, ipv6) {
            return Ok(ip);
        }
    }
    bail!("此地址族不可用")
}

fn detect_endpoint(client: &Client, endpoint: &str, ipv6: bool) -> Result<String> {
    let response = client
        .get(endpoint)
        .timeout(Duration::from_secs(4))
        .send()?
        .error_for_status()?;
    let mut body = String::new();
    response.take(129).read_to_string(&mut body)?;
    ensure!(body.len() <= 128, "IP 检测响应过长");
    parse_ip(&body, ipv6)
}

fn parse_ip(body: &str, ipv6: bool) -> Result<String> {
    let ip: IpAddr = body.trim().parse().context("IP 检测响应无效")?;
    ensure!(ip.is_ipv6() == ipv6, "IP 检测返回了错误的地址族");
    ensure!(
        !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast(),
        "IP 检测返回无效地址"
    );
    Ok(ip.to_string())
}

pub(crate) fn memory_usage(core_pid: Option<u32>) -> MemoryUsage {
    MemoryUsage {
        app_bytes: resident_bytes(std::process::id()),
        core_bytes: core_pid.and_then(resident_bytes),
    }
}

fn resident_bytes(pid: u32) -> Option<u64> {
    parse_resident_bytes(&fs::read_to_string(format!("/proc/{pid}/status")).ok()?)
}

fn parse_resident_bytes(status: &str) -> Option<u64> {
    let row = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?;
    let mut fields = row.split_whitespace();
    let kib: u64 = fields.next()?.parse().ok()?;
    (fields.next()? == "kB")
        .then(|| kib.checked_mul(1024))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{io::Write, net::TcpListener};

    #[test]
    fn resolves_ipv4_ipv6_and_socks_listeners() {
        for (kind, listen, expected) in [
            ("mixed", "0.0.0.0", "http://127.0.0.1:2080/"),
            ("http", "::", "http://[::1]:2080/"),
            ("socks", "::1", "socks5h://[::1]:2080"),
        ] {
            let config = json!({"inbounds":[{"type":kind,"listen":listen,"listen_port":2080}]});
            assert_eq!(proxy_url(&config).unwrap().unwrap().as_str(), expected);
        }
    }

    #[test]
    fn only_tun_allows_a_running_core_without_a_local_proxy() {
        assert!(proxy_url(&json!({"inbounds":[]})).is_err());
        assert!(
            proxy_url(&json!({"inbounds":[{"type":"tun"}]}))
                .unwrap()
                .is_none()
        );
        assert!(proxy_url(&json!({"inbounds":[{"type":"mixed","listen_port":0}]})).is_err());
        assert!(proxy_url(&json!({"inbounds":[{"type":"mixed","listen_port":80,"users":[{"username":"user","password":"pass"}]}]})).is_err());
    }

    #[test]
    fn prefers_the_dedicated_listener_and_sends_requests_through_it() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0; 4096];
            let size = stream.read(&mut request).unwrap();
            assert!(
                String::from_utf8_lossy(&request[..size])
                    .starts_with("GET http://download.invalid/file ")
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });
        let config = json!({"inbounds":[
            {"type":"mixed","listen":"127.0.0.1","listen_port":1},
            {"type":"mixed","tag":"aerobox-download-in","listen":"0.0.0.0","listen_port":port}
        ]});
        let body = client(Some(&config), Duration::from_secs(2))
            .unwrap()
            .get("http://download.invalid/file")
            .send()
            .unwrap()
            .text()
            .unwrap();
        assert_eq!(body, "ok");
        worker.join().unwrap();
    }

    #[test]
    fn failed_proxy_does_not_fall_back_to_direct_requests() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        drop(proxy);
        let config =
            json!({"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":proxy_port}]});
        assert!(
            client(Some(&config), Duration::from_secs(1))
                .unwrap()
                .get(format!("http://{}/", server.local_addr().unwrap()))
                .send()
                .is_err()
        );
        assert_eq!(
            server.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn validates_ip_responses_and_reads_real_rss() {
        assert_eq!(parse_ip(" 1.1.1.1\n", false).unwrap(), "1.1.1.1");
        assert_eq!(
            parse_ip("2606:4700:4700::1111", true).unwrap(),
            "2606:4700:4700::1111"
        );
        assert!(parse_ip("<html>error</html>", false).is_err());
        assert!(parse_ip("1.1.1.1", true).is_err());
        assert!(parse_ip("::", true).is_err());
        assert_eq!(
            parse_resident_bytes("Name: core\nVmRSS:\t2048 kB\nVmSwap: 0 kB"),
            Some(2 * 1024 * 1024)
        );
        assert_eq!(parse_resident_bytes("VmRSS: 2048 MB"), None);
        assert_eq!(parse_resident_bytes("VmRSS: 18446744073709551615 kB"), None);
        assert!(memory_usage(None).app_bytes.is_some_and(|bytes| bytes > 0));
    }
}
