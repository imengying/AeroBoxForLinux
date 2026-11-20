#![allow(dead_code)]

use aerobox_for_linux::{
    engine::Service,
    model::{Store, Subscription},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

// DNS caches and the embedded runtime's state directory are process-local.
// Distinct integration test binaries are already isolated by the test runner.
pub fn runtime_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub struct App {
    pub dir: tempfile::TempDir,
    pub service: Arc<Service>,
}
impl App {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(Some(dir.path().into())).unwrap();
        store
            .update(|state| {
                state.settings.system_proxy = false;
                state.settings.ipv6 = false;
                state.settings.bypass_lan = false;
                state.settings.sniff = false;
                state.settings.dns_cache = false;
                // Fixtures use literal loopback addresses. Tests that exercise
                // DNS install their own resolver; never bootstrap a public DoH
                // hostname just to start a local protocol test.
                state.settings.direct_dns = "udp://127.0.0.1:9".into();
                state.settings.remote_dns = "tcp://127.0.0.1:9".into();
                state.settings.routing_mode = "global".into();
                state.settings.mixed_port = free_port();
                state.rulesets.clear();
                Ok(())
            })
            .unwrap();
        Self {
            dir,
            service: Service::new(store),
        }
    }
    pub fn import(&self, name: &str, nodes: Vec<Value>) -> String {
        let sub = Subscription {
            name: name.into(),
            nodes,
            ..Subscription::default()
        };
        let id = sub.id.clone();
        self.service.import_subscription(sub).unwrap();
        id
    }
}
impl Drop for App {
    fn drop(&mut self) {
        let _ = self.service.shutdown();
    }
}

pub fn socks_node(name: &str, address: SocketAddr) -> Value {
    json!({"type":"socks", "tag":name, "server":address.ip().to_string(), "server_port":address.port()})
}

pub struct Server {
    pub address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    pub fn spawn(handler: impl Fn(TcpStream) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let handler = Arc::new(handler);
        let worker = thread::spawn(move || {
            let mut clients = Vec::new();
            while !done.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let handler = handler.clone();
                        clients.push(thread::spawn(move || handler(stream)));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("fixture accept failed: {e}"),
                }
            }
            for client in clients {
                client.join().unwrap();
            }
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take()
            && let Err(error) = worker.join()
            && !thread::panicking()
        {
            std::panic::resume_unwind(error);
        }
    }
}

pub fn headers(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut result = Vec::new();
    while result.len() < 32 * 1024 {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        result.push(byte[0]);
        if result.ends_with(b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&result).into_owned());
        }
    }
    Err(std::io::Error::other("fixture headers too large"))
}

pub fn respond(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

pub fn http(body: impl Into<Vec<u8>>) -> (Server, Arc<AtomicUsize>) {
    let body = body.into();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    let server = Server::spawn(move |mut stream| {
        if headers(&mut stream).is_ok() {
            count.fetch_add(1, Ordering::Relaxed);
            let _ = respond(&mut stream, &body);
        }
    });
    (server, hits)
}

pub fn socks_handshake(stream: &mut TcpStream) -> std::io::Result<(String, u16)> {
    let mut hello = [0; 2];
    stream.read_exact(&mut hello)?;
    assert_eq!(hello[0], 5);
    let mut methods = vec![0; hello[1] as usize];
    stream.read_exact(&mut methods)?;
    assert!(methods.contains(&0));
    stream.write_all(&[5, 0])?;
    let mut request = [0; 4];
    stream.read_exact(&mut request)?;
    assert_eq!(&request[..3], &[5, 1, 0]);
    let host = match request[3] {
        1 => {
            let mut ip = [0; 4];
            stream.read_exact(&mut ip)?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0; 16];
            stream.read_exact(&mut ip)?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        3 => {
            let mut len = [0];
            stream.read_exact(&mut len)?;
            let mut host = vec![0; len[0] as usize];
            stream.read_exact(&mut host)?;
            String::from_utf8(host).unwrap()
        }
        other => panic!("unexpected SOCKS address type {other}"),
    };
    let mut port = [0; 2];
    stream.read_exact(&mut port)?;
    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])?;
    Ok((host, u16::from_be_bytes(port)))
}

pub fn socks_http(body: impl Into<Vec<u8>>) -> (Server, Arc<AtomicUsize>) {
    let body = body.into();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    let server = Server::spawn(move |mut stream| {
        if socks_handshake(&mut stream).is_ok() && headers(&mut stream).is_ok() {
            count.fetch_add(1, Ordering::Relaxed);
            let _ = respond(&mut stream, &body);
        }
    });
    (server, hits)
}

pub fn request(service: &Service, url: &str) -> reqwest::Result<String> {
    request_via(service, url, "http")
}
pub fn request_via(service: &Service, url: &str, scheme: &str) -> reqwest::Result<String> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(format!(
            "{scheme}://127.0.0.1:{}",
            service.snapshot().settings.mixed_port
        ))?)
        .timeout(Duration::from_secs(4))
        .build()?
        .get(url)
        .send()?
        .error_for_status()?
        .text()
}

pub fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "condition did not become true before deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

pub struct BlockStateWrite {
    path: PathBuf,
    saved: PathBuf,
}
impl BlockStateWrite {
    pub fn new(directory: &Path) -> Self {
        let path = directory.join("state.json");
        let saved = directory.join("state.saved");
        fs::rename(&path, &saved).unwrap();
        fs::create_dir(&path).unwrap();
        Self { path, saved }
    }
}
impl Drop for BlockStateWrite {
    fn drop(&mut self) {
        fs::remove_dir(&self.path).unwrap();
        fs::rename(&self.saved, &self.path).unwrap();
    }
}

pub fn echo_tunnel(service: &Service, target: SocketAddr) -> TcpStream {
    let mut stream =
        TcpStream::connect(("127.0.0.1", service.snapshot().settings.mixed_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        stream,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
    )
    .unwrap();
    assert!(headers(&mut stream).unwrap().starts_with("HTTP/1.1 200"));
    stream
}

pub fn echo_server() -> Server {
    Server::spawn(|mut stream| {
        let mut bytes = [0; 1024];
        while let Ok(n) = stream.read(&mut bytes) {
            if n == 0 || stream.write_all(&bytes[..n]).is_err() {
                break;
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
    })
}

pub fn socks_forward() -> Server {
    Server::spawn(|mut client| {
        let Ok((host, port)) = socks_handshake(&mut client) else {
            return;
        };
        let Ok(mut upstream) = TcpStream::connect((host.as_str(), port)) else {
            return;
        };
        upstream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        upstream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut client_reader = client.try_clone().unwrap();
        let mut upstream_writer = upstream.try_clone().unwrap();
        thread::scope(|scope| {
            scope.spawn(move || {
                let _ = std::io::copy(&mut client_reader, &mut upstream_writer);
                let _ = upstream_writer.shutdown(Shutdown::Write);
            });
            let _ = std::io::copy(&mut upstream, &mut client);
            let _ = client.shutdown(Shutdown::Write);
        });
    })
}

// Independently frame SOCKS5 UDP traffic and require an actual datagram to reach
// an OS UDP socket. The TCP association stays open for the entire exchange.
pub fn udp_roundtrip(inbound: u16) -> std::io::Result<()> {
    let origin = std::net::UdpSocket::bind("127.0.0.1:0")?;
    origin.set_read_timeout(Some(Duration::from_secs(5)))?;
    let origin_port = origin.local_addr()?.port();
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut packet = [0; 2048];
        let (len, sender) = origin.recv_from(&mut packet)?;
        assert_eq!(&packet[..len], b"AeroBox datagram");
        origin.send_to(b"UDP echoed", sender)?;
        Ok(())
    });
    let mut association = TcpStream::connect(("127.0.0.1", inbound))?;
    association.set_read_timeout(Some(Duration::from_secs(5)))?;
    association.write_all(&[5, 1, 0])?;
    let mut hello = [0; 2];
    association.read_exact(&mut hello)?;
    assert_eq!(hello, [5, 0]);
    association.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])?;
    let mut response = [0; 10];
    association.read_exact(&mut response)?;
    assert_eq!(&response[..4], &[5, 0, 0, 1]);
    let relay = u16::from_be_bytes([response[8], response[9]]);
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(6)))?;
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
    packet.extend_from_slice(&origin_port.to_be_bytes());
    packet.extend_from_slice(b"AeroBox datagram");
    socket.send_to(&packet, ("127.0.0.1", relay))?;
    let mut reply = [0; 2048];
    let result = socket.recv_from(&mut reply);
    let echoed = worker.join().unwrap();
    let (len, _) = result?;
    echoed?;
    assert_eq!(&reply[..4], &[0, 0, 0, 1]);
    assert_eq!(&reply[10..len], b"UDP echoed");
    Ok(())
}
