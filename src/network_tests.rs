use super::*;
use std::{
    io::Write,
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

fn headers(stream: &mut impl Read) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 16384);
    }
    String::from_utf8(bytes).unwrap()
}

#[test]
fn exit_detection_waits_for_cold_proxy_setup_and_respects_disabled_ipv6() {
    let cert = rcgen::generate_simple_self_signed(vec!["exit.example.test".into()]).unwrap();
    let root = reqwest::Certificate::from_der(cert.cert.der()).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = NonZeroU16::new(listener.local_addr().unwrap().port());
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    unused.set_nonblocking(true).unwrap();
    let ipv6_endpoint = format!("http://{}/", unused.local_addr().unwrap());
    let worker = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        assert!(headers(&mut socket).starts_with("CONNECT exit.example.test:443 "));
        // Longer than both old limits: four seconds per request and five for CONNECT.
        thread::sleep(Duration::from_millis(5200));
        socket
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        let connection = rustls::ServerConnection::new(Arc::new(tls)).unwrap();
        let mut socket = rustls::StreamOwned::new(connection, socket);
        assert!(headers(&mut socket).starts_with("GET / "));
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n203.0.113.7",
            )
            .unwrap();
        socket.conn.send_close_notify();
        socket.flush().unwrap();
    });
    let client = exit_client_builder(port)
        .unwrap()
        .add_root_certificate(root)
        .build()
        .unwrap();
    let result = detect_with_endpoints(
        &client,
        false,
        &["https://exit.example.test/"],
        &[&ipv6_endpoint],
        EXIT_TOTAL_TIMEOUT,
        |_| {},
    );
    worker.join().unwrap();
    let result = result.unwrap();
    assert_eq!(result.ipv4.as_deref(), Some("203.0.113.7"));
    assert!(result.ipv6.is_none());
    assert_eq!(
        unused.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

struct Probes {
    base: String,
    paths: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}

impl Probes {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let paths = Arc::new(Mutex::new(Vec::new()));
        let seen = paths.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let task = thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        socket
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let path = headers(&mut socket)
                            .split_whitespace()
                            .nth(1)
                            .unwrap()
                            .to_owned();
                        seen.lock().unwrap().push(path.clone());
                        let body = match path.as_str() {
                            "/v4" => "203.0.113.8".to_owned(),
                            "/v6" => "2001:db8::1".to_owned(),
                            "/large" => "9".repeat(129),
                            "/slow" => {
                                thread::sleep(Duration::from_millis(250));
                                "203.0.113.8".to_owned()
                            }
                            _ => "not an IP".to_owned(),
                        };
                        let _ = write!(
                            socket,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => panic!("{error}"),
                }
            }
        });
        Self {
            base,
            paths,
            stop,
            task: Some(task),
        }
    }
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}
impl Drop for Probes {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.task.take().unwrap().join().unwrap();
    }
}

#[test]
fn exit_detection_falls_back_only_when_needed_and_respects_family_and_body_limits() {
    let probes = Probes::new();
    let client = exit_client(None).unwrap();
    let v6 = probes.url("/v6");
    let endpoints = [
        &probes.url("/bad")[..],
        &probes.url("/large"),
        &probes.url("/v4"),
    ];
    let result = detect_with_endpoints(
        &client,
        false,
        &endpoints,
        &[&v6],
        Duration::from_secs(2),
        |_| {},
    )
    .unwrap();
    assert_eq!(result.ipv4.as_deref(), Some("203.0.113.8"));
    assert_eq!(*probes.paths.lock().unwrap(), ["/bad", "/large", "/v4"]);
    probes.paths.lock().unwrap().clear();
    let result = detect_with_endpoints(
        &client,
        true,
        &[&v6],
        &[&v6],
        Duration::from_secs(2),
        |_| {},
    )
    .unwrap();
    assert_eq!(result.ipv6.as_deref(), Some("2001:db8::1"));
    assert!(result.ipv4.is_none());
    probes.paths.lock().unwrap().clear();
    assert!(
        detect_with_endpoints(
            &client,
            false,
            &[&probes.url("/bad")],
            &[&v6],
            Duration::from_secs(2),
            |_| {}
        )
        .is_err()
    );
    assert_eq!(*probes.paths.lock().unwrap(), ["/bad"]);
}

#[test]
fn exit_detection_has_one_total_deadline_and_keeps_a_failed_proxy_route() {
    let probes = Probes::new();
    let client = exit_client(None).unwrap();
    assert!(
        detect_with_endpoints(
            &client,
            false,
            &[&probes.url("/slow"), &probes.url("/v4")],
            &[&probes.url("/v6")],
            Duration::from_millis(50),
            |_| {}
        )
        .is_err()
    );
    assert_eq!(*probes.paths.lock().unwrap(), ["/slow"]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = NonZeroU16::new(listener.local_addr().unwrap().port());
    drop(listener);
    let client = exit_client(port).unwrap();
    assert!(
        detect_with_endpoints(
            &client,
            false,
            &[&probes.url("/v4")],
            &[],
            Duration::from_secs(1),
            |_| {}
        )
        .is_err()
    );
    assert_eq!(*probes.paths.lock().unwrap(), ["/slow"]);
}

#[test]
fn exit_detection_publishes_ipv4_before_slow_ipv6_and_keeps_both_addresses() {
    let ipv4 = Probes::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let v6 = format!("http://{}/", listener.local_addr().unwrap());
    let (release, ready) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        headers(&mut socket);
        ready
            .recv_timeout(Duration::from_secs(2))
            .expect("IPv4 was held back by IPv6");
        let body = "2001:db8::7";
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let updates = std::cell::RefCell::new(Vec::new());
    let result = detect_with_endpoints(
        &exit_client(None).unwrap(),
        true,
        &[&ipv4.url("/v4")],
        &[&v6],
        Duration::from_secs(3),
        |info| {
            if info.ipv4.is_some() && info.ipv6.is_none() {
                release.send(()).unwrap();
            }
            updates.borrow_mut().push(info.clone());
        },
    )
    .unwrap();
    worker.join().unwrap();
    assert_eq!(result.ipv4.as_deref(), Some("203.0.113.8"));
    assert_eq!(result.ipv6.as_deref(), Some("2001:db8::7"));
    assert_eq!(updates.borrow().len(), 2);
}
