use anyhow::{Context, Result, ensure};
use reqwest::{Proxy, blocking::Client};
use serde_json::Value;
use std::{
    fs,
    io::Read,
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Default)]
pub struct NetworkInfo {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryUsage {
    /// Application and integrated networking share one process.
    pub total_bytes: Option<u64>,
    pub basis: MemoryBasis,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MemoryBasis {
    #[default]
    Proportional,
    Resident,
}

impl MemoryBasis {
    pub fn label(self) -> &'static str {
        match self {
            Self::Proportional => "PSS",
            Self::Resident => "RSS",
        }
    }
}

/// Every native configuration has a local mixed listener. Missing listeners
/// are errors, so an active connection can never fall back to direct downloads.
pub(crate) fn proxy_url(config: &Value) -> Result<url::Url> {
    let inbounds = config.as_array().context("运行配置缺少代理入口")?;
    let inbound = inbounds
        .iter()
        .find(|inbound| inbound["name"] == "mixed-in")
        .context("运行配置没有本地代理入口")?;
    let address: std::net::SocketAddr = inbound["address"]
        .as_str()
        .context("入站缺少地址")?
        .parse()?;
    ensure!(
        address.ip().is_loopback() && address.port() > 0,
        "代理入口必须是本机地址"
    );
    Ok(url::Url::parse(&format!("http://{address}"))?)
}

fn client_builder(config: Option<&Value>) -> Result<reqwest::blocking::ClientBuilder> {
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(concat!("AeroBox/", env!("CARGO_PKG_VERSION")));
    if let Some(config) = config {
        builder = builder.proxy(Proxy::all(proxy_url(config)?)?);
    }
    Ok(builder)
}

pub(crate) fn client(config: Option<&Value>, timeout: Duration) -> Result<Client> {
    Ok(client_builder(config)?
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(5))
        .build()?)
}

const EXIT_REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
const EXIT_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

fn exit_client_builder(config: Option<&Value>) -> Result<reqwest::blocking::ClientBuilder> {
    // CONNECT includes proxy-side DNS and the node's handshake. A five-second
    // connect timeout can expire even when ordinary browser requests succeed.
    Ok(client_builder(config)?
        .timeout(EXIT_REQUEST_TIMEOUT)
        .connect_timeout(EXIT_REQUEST_TIMEOUT))
}

pub(crate) fn exit_client(config: Option<&Value>) -> Result<Client> {
    Ok(exit_client_builder(config)?.build()?)
}

/// Expose the failure stage without copying URLs, endpoints or credentials
/// from an underlying resolver, TLS or proxy error into a shareable report.
pub(crate) fn request_failure(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "连接超时".into();
    }
    if let Some(status) = error.status() {
        return format!("HTTP {}", status.as_u16());
    }
    let mut causes = String::new();
    let mut source = std::error::Error::source(error);
    while let Some(error) = source {
        causes.push_str(&error.to_string().to_lowercase());
        source = error.source();
    }
    if causes.contains("certificate") {
        "TLS 证书验证失败"
    } else if causes.contains("dns") || causes.contains("resolve") || causes.contains("lookup") {
        "DNS 解析失败"
    } else if causes.contains("tunnel") || causes.contains("proxy") {
        "代理隧道建立失败"
    } else if causes.contains("tls") || causes.contains("handshake") {
        "TLS 握手失败"
    } else if causes.contains("refused") {
        "连接被拒绝"
    } else if causes.contains("reset") {
        "连接被重置"
    } else if error.is_connect() {
        "连接建立失败"
    } else {
        "请求失败"
    }
    .into()
}

pub(crate) fn detect(
    client: Client,
    ipv6: bool,
    progress: impl Fn(&NetworkInfo),
) -> Result<NetworkInfo> {
    detect_with_endpoints(
        &client,
        ipv6,
        &["https://api4.ipify.org", "https://ipv4.icanhazip.com"],
        &["https://api6.ipify.org", "https://ipv6.icanhazip.com"],
        EXIT_TOTAL_TIMEOUT,
        progress,
    )
}

fn detect_with_endpoints(
    client: &Client,
    ipv6: bool,
    v4_endpoints: &[&str],
    v6_endpoints: &[&str],
    budget: Duration,
    progress: impl Fn(&NetworkInfo),
) -> Result<NetworkInfo> {
    let deadline = Instant::now() + budget;
    let mut info = NetworkInfo::default();
    let mut last_error = anyhow::anyhow!("检测超时");
    // Publish each family as soon as it completes. IPv6 can never hold back a
    // usable IPv4 address, and a failed family cannot discard a successful one.
    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel();
        for (family, endpoints) in [(false, v4_endpoints), (true, v6_endpoints)] {
            if family && !ipv6 {
                continue;
            }
            let tx = tx.clone();
            scope.spawn(move || {
                let _ = tx.send((family, detect_family(client, endpoints, family, deadline)));
            });
        }
        drop(tx);
        for (family, result) in rx {
            match result {
                Ok(ip) => {
                    if family {
                        info.ipv6 = Some(ip);
                    } else {
                        info.ipv4 = Some(ip);
                    }
                    progress(&info);
                }
                Err(error) => last_error = error,
            }
        }
    });
    if info.ipv4.is_some() || info.ipv6.is_some() {
        Ok(info)
    } else {
        Err(last_error.context("无法检测出口 IP"))
    }
}

fn detect_family(
    client: &Client,
    endpoints: &[&str],
    ipv6: bool,
    deadline: Instant,
) -> Result<String> {
    let mut last_error = anyhow::anyhow!("检测超时");
    for endpoint in endpoints {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match detect_endpoint(client, endpoint, ipv6, remaining.min(EXIT_REQUEST_TIMEOUT)) {
            Ok(ip) => return Ok(ip),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn detect_endpoint(
    client: &Client,
    endpoint: &str,
    ipv6: bool,
    timeout: Duration,
) -> Result<String> {
    let response = client
        .get(endpoint)
        .timeout(timeout)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|error| anyhow::anyhow!(request_failure(&error)))?;
    let mut body = String::new();
    response
        .take(129)
        .read_to_string(&mut body)
        .context("无法读取检测响应")?;
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

#[cfg(test)]
#[path = "network_tests.rs"]
mod exit_tests;

pub(crate) fn memory_usage() -> MemoryUsage {
    process_memory().usage()
}

#[derive(Clone, Copy, Default)]
struct ProcessMemory {
    pss: Option<u64>,
    rss: Option<u64>,
}

fn process_memory() -> ProcessMemory {
    let rollup = fs::read_to_string("/proc/self/smaps_rollup").ok();
    ProcessMemory {
        pss: rollup.as_deref().and_then(|data| parse_kib(data, "Pss:")),
        rss: rollup
            .as_deref()
            .and_then(|data| parse_kib(data, "Rss:"))
            .or_else(|| parse_kib(&fs::read_to_string("/proc/self/status").ok()?, "VmRSS:")),
    }
}

impl ProcessMemory {
    fn usage(self) -> MemoryUsage {
        if self.pss.is_some() {
            MemoryUsage {
                total_bytes: self.pss,
                basis: MemoryBasis::Proportional,
            }
        } else {
            MemoryUsage {
                total_bytes: self.rss,
                basis: MemoryBasis::Resident,
            }
        }
    }
}

fn parse_kib(data: &str, field: &str) -> Option<u64> {
    let row = data.lines().find_map(|line| line.strip_prefix(field))?;
    let mut fields = row.split_whitespace();
    let kib: u64 = fields.next()?.parse().ok()?;
    (fields.next()? == "kB" && fields.next().is_none())
        .then(|| kib.checked_mul(1024))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{io::Write, net::TcpListener};

    #[test]
    fn resolves_ipv4_and_ipv6_native_listeners() {
        for (address, expected) in [
            ("127.0.0.1:2080", "http://127.0.0.1:2080/"),
            ("[::1]:2080", "http://[::1]:2080/"),
        ] {
            let config = json!([{"name":"mixed-in","address":address,"protocol":{"type":"mixed"}}]);
            assert_eq!(proxy_url(&config).unwrap().as_str(), expected);
        }
        assert!(proxy_url(&json!([])).is_err());
        for address in [
            "0.0.0.0:2080",
            "[::]:2080",
            "192.168.1.1:2080",
            "127.0.0.1:0",
        ] {
            assert!(proxy_url(&json!([{"name":"mixed-in","address":address}])).is_err());
        }
    }

    #[test]
    fn download_requests_use_the_native_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
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
        let config =
            json!([{"name":"mixed-in","address":address.to_string(),"protocol":{"type":"mixed"}}]);
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
        let config = json!([{"name":"mixed-in","address":format!("127.0.0.1:{proxy_port}"),"protocol":{"type":"mixed"}}]);
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
    fn validates_ip_responses() {
        assert_eq!(parse_ip(" 1.1.1.1\n", false).unwrap(), "1.1.1.1");
        assert_eq!(
            parse_ip("2606:4700:4700::1111", true).unwrap(),
            "2606:4700:4700::1111"
        );
        assert!(parse_ip("<html>error</html>", false).is_err());
        assert!(parse_ip("1.1.1.1", true).is_err());
        assert!(parse_ip("::", true).is_err());
    }

    #[test]
    fn memory_prefers_pss_and_falls_back_to_rss() {
        let app = ProcessMemory {
            pss: Some(3000),
            rss: Some(5000),
        };
        let total = app.usage();
        assert_eq!(total.total_bytes, Some(3000));
        assert_eq!(total.basis, MemoryBasis::Proportional);

        let fallback = ProcessMemory { pss: None, ..app }.usage();
        assert_eq!(fallback.total_bytes, Some(5000));
        assert_eq!(fallback.basis, MemoryBasis::Resident);
        assert_eq!(fallback.basis.label(), "RSS");
        assert_eq!(ProcessMemory::default().usage().total_bytes, None);
    }

    #[test]
    fn reads_exact_proc_memory_fields_and_rejects_invalid_totals() {
        let rollup = "Pss_Anon: 12 kB\nPss:\t2048 kB\nRss: 4096 kB\nSwapPss: 10 kB\n";
        assert_eq!(parse_kib(rollup, "Pss:"), Some(2 * 1024 * 1024));
        assert_eq!(parse_kib("VmRSS: 2048 kB", "VmRSS:"), Some(2 * 1024 * 1024));
        assert_eq!(parse_kib("Pss: 2048 MB", "Pss:"), None);
        assert_eq!(parse_kib("Pss: 18446744073709551615 kB", "Pss:"), None);
        assert!(memory_usage().total_bytes.is_some_and(|bytes| bytes > 0));
    }
}
