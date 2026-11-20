//! Small independent SOCKS peer: no native engine code is used by the server.
use std::{
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

pub struct Peer {
    tcp: super::support::Server,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    dns: Arc<Mutex<Vec<String>>>,
}

fn address(reader: &mut impl Read) -> io::Result<(String, u16)> {
    let mut kind = [0];
    reader.read_exact(&mut kind)?;
    let host = match kind[0] {
        1 => {
            let mut ip = [0; 4];
            reader.read_exact(&mut ip)?;
            IpAddr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0; 16];
            reader.read_exact(&mut ip)?;
            IpAddr::from(ip).to_string()
        }
        3 => {
            let mut size = [0];
            reader.read_exact(&mut size)?;
            let mut host = vec![0; size[0] as usize];
            reader.read_exact(&mut host)?;
            String::from_utf8(host).map_err(io::Error::other)?
        }
        _ => return Err(io::Error::other("invalid fixture SOCKS address")),
    };
    let mut port = [0; 2];
    reader.read_exact(&mut port)?;
    Ok((host, u16::from_be_bytes(port)))
}

fn tcp(mut stream: TcpStream, udp_port: u16) -> io::Result<()> {
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting)?;
    assert_eq!(greeting[0], 5);
    let mut methods = vec![0; greeting[1] as usize];
    stream.read_exact(&mut methods)?;
    assert!(methods.contains(&0));
    stream.write_all(&[5, 0])?;
    let mut request = [0; 3];
    stream.read_exact(&mut request)?;
    assert_eq!(request[0], 5);
    let (_, port) = address(&mut stream)?;
    let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
    reply.extend_from_slice(&udp_port.to_be_bytes());
    stream.write_all(&reply)?;
    if request[1] == 3 {
        // The TCP control channel owns the SOCKS UDP association.
        let mut buffer = [0; 1];
        while stream.read(&mut buffer)? != 0 {}
        return Ok(());
    }
    assert_eq!(request[1], 1);
    if port == 19123 {
        let mut buffer = [0; 4];
        while stream.read_exact(&mut buffer).is_ok() {
            stream.write_all(&buffer)?;
        }
    } else {
        assert_eq!(
            port, 80,
            "DNS TCP queries must be intercepted before reaching the node"
        );
        super::support::headers(&mut stream)?;
        super::support::respond(&mut stream, b"through-tun")?;
    }
    Ok(())
}

pub fn dns_query(ipv6: bool) -> Vec<u8> {
    let mut query = vec![0xa1, 0x42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in [
        uuid::Uuid::new_v4().simple().to_string(),
        "example".into(),
        "test".into(),
    ] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, if ipv6 { 28 } else { 1 }, 0, 1]);
    query
}

fn dns_reply(query: &[u8]) -> Vec<u8> {
    assert!(query.len() >= 12);
    let mut end = 12;
    while query[end] != 0 {
        end += query[end] as usize + 1;
    }
    end += 1;
    let kind = &query[end..end + 2];
    let mut reply = query[..end + 4].to_vec();
    reply[2..4].copy_from_slice(&[0x81, 0x80]);
    reply[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
    reply.extend_from_slice(&[0xc0, 0x0c]);
    reply.extend_from_slice(kind);
    reply.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    let ip = if kind == [0, 28] {
        "2001:db8:2::42"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec()
    } else {
        assert_eq!(kind, [0, 1]);
        vec![203, 0, 113, 42]
    };
    reply.extend_from_slice(&(ip.len() as u16).to_be_bytes());
    reply.extend_from_slice(&ip);
    reply
}

impl Peer {
    pub fn new() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();
        let tcp = super::support::Server::spawn(move |stream| {
            let _ = tcp(stream, port);
        });
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let dns = Arc::new(Mutex::new(Vec::new()));
        let observed = dns.clone();
        let worker = thread::spawn(move || {
            let mut buffer = [0; 65536];
            while !done.load(Ordering::Relaxed) {
                let Ok((n, source)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                assert_eq!(&buffer[..3], &[0, 0, 0]);
                let mut cursor = io::Cursor::new(&buffer[3..n]);
                let (host, port) = address(&mut cursor).unwrap();
                let offset = 3 + cursor.position() as usize;
                let mut response = buffer[..offset].to_vec();
                if port == 53 {
                    observed.lock().unwrap().push(format!("{host}:{port}"));
                    response.extend_from_slice(&dns_reply(&buffer[offset..n]));
                } else {
                    assert_eq!(port, 19123);
                    response.extend_from_slice(&buffer[offset..n]);
                }
                socket.send_to(&response, source).unwrap();
            }
        });
        Self {
            tcp,
            stop,
            worker: Some(worker),
            dns,
        }
    }
    pub fn address(&self) -> SocketAddr {
        self.tcp.address
    }
    pub fn dns_targets(&self) -> Vec<String> {
        self.dns.lock().unwrap().clone()
    }
}

impl Drop for Peer {
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

/// Direct resolver for the remote DNS server's hostname. Switching to NXDOMAIN
/// makes rebuilding the runtime DNS registry fail without touching its sockets.
pub struct BootstrapDns {
    address: SocketAddr,
    failed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl BootstrapDns {
    pub fn new() -> Self {
        assert_eq!(
            std::env::var("AEROBOX_TUN_TEST_NAMESPACE").as_deref(),
            Ok("1")
        );
        let (namespace_tx, namespace_rx) = std::sync::mpsc::channel();
        let (configured_tx, configured_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let failed = Arc::new(AtomicBool::new(false));
        let rejecting = failed.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let worker = thread::spawn(move || {
            // The managed runtime deliberately rejects host-local DNS servers.
            // Put the fixture on a separate network, just like a LAN resolver.
            // SAFETY: only this new fixture thread changes network namespace;
            // it has no sockets or async tasks inherited from the engine.
            assert_eq!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) },
                0,
                "unshare DNS peer: {}",
                io::Error::last_os_error()
            );
            namespace_tx.send(unsafe { libc::gettid() }).unwrap();
            configured_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            Self::ip(&["link", "set", "lo", "up"]);
            Self::ip(&["addr", "add", "198.18.1.2/30", "dev", "dns-peer"]);
            Self::ip(&["link", "set", "dns-peer", "up"]);
            let socket = UdpSocket::bind("198.18.1.2:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            ready_tx.send(socket.local_addr().unwrap()).unwrap();
            let mut buffer = [0; 4096];
            while !done.load(Ordering::Relaxed) {
                let Ok((size, peer)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                if let Some(response) =
                    Self::reply(&buffer[..size], rejecting.load(Ordering::Acquire))
                {
                    let _ = socket.send_to(&response, peer);
                }
            }
        });
        let namespace = namespace_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self::ip(&[
            "link",
            "add",
            "dns-local",
            "type",
            "veth",
            "peer",
            "name",
            "dns-peer",
        ]);
        Self::ip(&["link", "set", "dns-peer", "netns", &namespace.to_string()]);
        Self::ip(&["addr", "add", "198.18.1.1/30", "dev", "dns-local"]);
        Self::ip(&["link", "set", "dns-local", "up"]);
        configured_tx.send(()).unwrap();
        let address = ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            address,
            failed,
            stop,
            worker: Some(worker),
        }
    }

    fn ip(args: &[&str]) {
        let output = std::process::Command::new("ip")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "DNS fixture ip {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn set_failed(&self, failed: bool) {
        self.failed.store(failed, Ordering::Release);
    }

    fn reply(query: &[u8], failed: bool) -> Option<Vec<u8>> {
        if query.len() < 12 || query[4..6] != [0, 1] {
            return None;
        }
        let mut end = 12;
        loop {
            let size = usize::from(*query.get(end)?);
            end += 1;
            if size == 0 {
                break;
            }
            if size > 63 {
                return None;
            }
            end = end.checked_add(size)?;
        }
        let question = query.get(end..end + 4)?;
        let answer = !failed && question == [0, 1, 0, 1];
        let mut reply = query[..end + 4].to_vec();
        reply[2..4].copy_from_slice(&[0x81, if failed { 0x83 } else { 0x80 }]);
        // Strip EDNS/additional records; AAAA gets an empty successful response.
        reply[6..12].copy_from_slice(&[0, u8::from(answer), 0, 0, 0, 0]);
        if answer {
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 9, 9, 9, 9]);
        }
        Some(reply)
    }
}

impl Drop for BootstrapDns {
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
