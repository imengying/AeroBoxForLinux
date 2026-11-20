//! Exercise the public embedded server with independently encoded Trojan UDP.
//! Only this local wire-format fixture omits TLS; application Trojan nodes still
//! require TLS and have separate end-to-end interoperability coverage.
use serde_json::json;
use shoes::embedding::EmbeddedCore;
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddrV4, TcpListener, TcpStream, UdpSocket},
    time::Duration,
};

const IO_TIMEOUT: Duration = Duration::from_secs(3);
// SHA-224("password"): fixed independently of the implementation under test.
const PASSWORD_HASH: &[u8] = b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01";

struct Peer {
    runtime: tokio::runtime::Runtime,
    core: EmbeddedCore,
    port: u16,
}

impl Peer {
    fn start() -> Self {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let config = json!([{
            "address": format!("127.0.0.1:{port}"),
            "protocol": {"type": "trojan", "password": "password"},
            "rules": [{"conditions": {"any_destination": true}, "action": "allow"}]
        }]);
        let core = runtime
            .block_on(EmbeddedCore::start_json(&config.to_string(), None))
            .unwrap();
        Self {
            runtime,
            core,
            port,
        }
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", self.port).parse().unwrap(),
            IO_TIMEOUT,
        )
        .unwrap();
        stream.set_nodelay(true).unwrap();
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        stream
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        // Even an assertion failure must release the process-global core.
        let _ = self
            .runtime
            .block_on(async { tokio::time::timeout(IO_TIMEOUT, self.core.shutdown()).await });
    }
}

fn address(target: SocketAddrV4) -> Vec<u8> {
    let mut bytes = vec![0x01];
    bytes.extend_from_slice(&target.ip().octets());
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes
}

fn handshake(target: SocketAddrV4) -> Vec<u8> {
    let mut bytes = PASSWORD_HASH.to_vec();
    bytes.extend_from_slice(b"\r\n\x03");
    bytes.extend(address(target));
    bytes.extend_from_slice(b"\r\n");
    bytes
}

fn frame(target: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let mut bytes = address(target);
    bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(payload);
    bytes
}

fn reply(stream: &mut TcpStream, target: SocketAddrV4) -> Vec<u8> {
    let mut header = [0; 11];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(&header[..7], address(target), "reply source address");
    assert_eq!(&header[9..], b"\r\n", "reply separator");
    let mut payload = vec![0; u16::from_be_bytes([header[7], header[8]]) as usize];
    stream.read_exact(&mut payload).unwrap();
    payload
}

fn echo(origin: &UdpSocket) -> Vec<u8> {
    origin.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    let mut bytes = vec![0; u16::MAX as usize];
    let (len, source) = origin.recv_from(&mut bytes).unwrap();
    bytes.truncate(len);
    assert_eq!(origin.send_to(&bytes, source).unwrap(), len);
    bytes
}

fn no_packet(origin: &UdpSocket, context: &str) {
    origin
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let result = origin.recv_from(&mut [0; 64]);
    assert!(
        matches!(&result, Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)),
        "{context}: malformed or incomplete data reached UDP target: {result:?}"
    );
}

fn rejected(peer: &Peer, origin: &UdpSocket, bytes: &[u8], context: &str) {
    let mut stream = peer.connect();
    stream.write_all(bytes).unwrap();
    if let Err(error) = stream.shutdown(Shutdown::Write) {
        // A complete malformed header may already have been rejected before
        // this half-close; truncated frames need the EOF to finish parsing.
        assert!(matches!(
            error.kind(),
            io::ErrorKind::NotConnected
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
        ));
    }
    let result = stream.read(&mut [0; 1]);
    assert!(
        matches!(&result, Ok(0))
            || matches!(&result, Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe)),
        "{context}: rejected stream must close without a reply: {result:?}"
    );
    no_packet(origin, context);
}

#[test]
fn trojan_udp_frames_preserve_datagrams_and_reject_malformed_input() {
    let peer = Peer::start();
    let origin = UdpSocket::bind("127.0.0.1:0").unwrap();
    origin.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    let std::net::SocketAddr::V4(target) = origin.local_addr().unwrap() else {
        unreachable!()
    };
    let mut stream = peer.connect();

    // The server's handshake reader may have already consumed the first frame.
    let first = b"frame coalesced with handshake";
    let mut request = handshake(target);
    request.extend(frame(target, first));
    stream.write_all(&request).unwrap();
    assert_eq!(echo(&origin), first);
    assert_eq!(reply(&mut stream, target), first);

    // Split inside the address, length, CRLF and payload. No fragment is a UDP
    // datagram until its declared payload is complete.
    let fragmented = b"fragmented payload stays in one datagram";
    let packet = frame(target, fragmented);
    let mut start = 0;
    for end in [2, 7, 8, 9, 10, 11, 23, packet.len() - 1] {
        stream.write_all(&packet[start..end]).unwrap();
        no_packet(&origin, &format!("fragment ending at byte {end}"));
        start = end;
    }
    stream.write_all(&packet[start..]).unwrap();
    assert_eq!(echo(&origin), fragmented);
    assert_eq!(reply(&mut stream, target), fragmented);

    // Several frames in one write must remain distinct, including an empty UDP
    // datagram between nonempty ones. Echoing the empty datagram also exercises
    // the server's write path rather than treating it as stream EOF.
    let payloads: [&[u8]; 3] = [b"before empty", b"", b"after empty"];
    let combined: Vec<u8> = payloads
        .iter()
        .flat_map(|bytes| frame(target, bytes))
        .collect();
    stream.write_all(&combined).unwrap();
    let mut received: Vec<_> = (0..payloads.len()).map(|_| echo(&origin)).collect();
    let mut replies: Vec<_> = (0..payloads.len())
        .map(|_| reply(&mut stream, target))
        .collect();
    let mut expected: Vec<_> = payloads.iter().map(|bytes| bytes.to_vec()).collect();
    received.sort();
    replies.sort();
    expected.sort();
    assert_eq!(received, expected);
    assert_eq!(replies, expected);

    let large: Vec<u8> = (0..32_768).map(|i| (i % 251) as u8).collect();
    stream.write_all(&frame(target, &large)).unwrap();
    assert_eq!(echo(&origin), large);
    assert_eq!(reply(&mut stream, target), large);
    drop(stream);

    let valid = frame(target, b"must never reach the target");
    for separator in [b"\n\r", b"\rX", b"X\n"] {
        let mut bad = valid.clone();
        bad[9..11].copy_from_slice(separator);
        let mut request = handshake(target);
        request.extend(bad);
        // A parser must not resynchronize after a bad separator and forward a
        // subsequent valid frame from the same rejected session.
        request.extend(&valid);
        rejected(&peer, &origin, &request, "invalid packet CRLF");
    }
    let mut request = handshake(target);
    *request.last_mut().unwrap() = b'X';
    request.extend(&valid);
    rejected(&peer, &origin, &request, "invalid handshake CRLF");

    for end in [1, 4, 7, 8, 9, 10, 11, valid.len() - 1] {
        let mut request = handshake(target);
        request.extend_from_slice(&valid[..end]);
        rejected(
            &peer,
            &origin,
            &request,
            &format!("truncated frame at byte {end}"),
        );
    }

    // Bad sessions must not damage the listener or later UDP associations.
    let mut stream = peer.connect();
    let mut request = handshake(target);
    request.extend(frame(target, b"healthy after rejection"));
    stream.write_all(&request).unwrap();
    assert_eq!(echo(&origin), b"healthy after rejection");
    assert_eq!(reply(&mut stream, target), b"healthy after rejection");
    drop(stream);
    peer.runtime.block_on(peer.core.shutdown()).unwrap();
    TcpListener::bind(("127.0.0.1", peer.port)).expect("Trojan listener released after shutdown");
}
