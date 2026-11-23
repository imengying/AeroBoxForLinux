//! Inspect the actual VLESS request and datagram framing with an independent
//! byte-oriented peer. A server accepting both modes cannot detect an ignored
//! packet_encoding option by successful traffic alone.
mod support;

use serde_json::json;
use std::{
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const UUID: &str = "00000000-0000-4000-8000-000000000001";
const TARGET: [u8; 4] = [203, 0, 113, 17];
const PORT: u16 = 5353;
const PAYLOAD_SIZES: [usize; 7] = [1, 64, 1400, 3000, 7527, 32768, 60000];

#[test]
fn packet_encoding_survives_each_subscription_format() {
    use aerobox_for_linux::subscription;
    use base64::{Engine, engine::general_purpose::STANDARD};
    for kind in ["vless", "vmess"] {
        for encoding in ["xudp", "", "packetaddr"] {
            let uri = if kind == "vless" {
                format!("vless://{UUID}@example.com:443?packetEncoding={encoding}#fixture")
            } else {
                let body = json!({"v":"2","ps":"fixture","add":"example.com","port":"443","id":UUID,"aid":"0","net":"tcp","packetEncoding":encoding});
                format!("vmess://{}", STANDARD.encode(body.to_string()))
            };
            let sources = [
                uri,
                json!({"proxies":[{"type":kind,"name":"fixture","server":"example.com","port":443,"uuid":UUID,"packet-encoding":encoding}]}).to_string(),
                json!({"outbounds":[{"type":kind,"tag":"fixture","server":"example.com","server_port":443,"uuid":UUID,"packet_encoding":encoding}]}).to_string(),
            ];
            for source in sources {
                assert_eq!(
                    subscription::parse(&source).unwrap()[0]["packet_encoding"],
                    encoding
                );
            }
        }
    }
    for query in [
        "packetEncoding=xudp&packet_encoding=",
        "packetEncoding=unknown",
    ] {
        assert!(subscription::parse(&format!("vless://{UUID}@example.com:443?{query}")).is_err());
    }
    let conflict = json!({"v":"2","add":"example.com","port":"443","id":UUID,"aid":"0","net":"tcp","packetEncoding":"xudp","packet_encoding":""});
    assert!(
        subscription::parse(&format!(
            "vmess://{}",
            STANDARD.encode(conflict.to_string())
        ))
        .is_err()
    );
    let conflict = json!({"proxies":[{"type":"vless","name":"fixture","server":"example.com","port":443,"uuid":UUID,"packet-encoding":"xudp","packet_encoding":""}]});
    assert!(subscription::parse(&conflict.to_string()).is_err());
}

fn sized_bytes(stream: &mut TcpStream) -> Vec<u8> {
    let mut length = [0; 2];
    stream.read_exact(&mut length).unwrap();
    let length = u16::from_be_bytes(length) as usize;
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

#[test]
fn vless_udp_encodings_use_the_requested_wire_format() {
    let _serial = support::runtime_lock();
    for (encoding, xudp) in [
        (None, true),
        (Some("xudp"), true),
        (Some(""), false),
        (Some("packetaddr"), false),
    ] {
        let packetaddr = encoding == Some("packetaddr");
        let packets = Arc::new(AtomicUsize::new(0));
        let seen = packets.clone();
        let peer = support::Server::spawn(move |mut stream| {
            let mut request = [0; 19];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request[0], 0);
            assert_eq!(
                &request[1..17],
                uuid::Uuid::parse_str(UUID).unwrap().as_bytes()
            );
            assert_eq!(request[17], 0, "no VLESS addons");
            assert_eq!(request[18], if xudp { 3 } else { 2 }, "{encoding:?}");
            if packetaddr {
                let magic = b"sp.packet-addr.v2fly.arpa";
                let mut destination = vec![0; 4 + magic.len()];
                stream.read_exact(&mut destination).unwrap();
                assert_eq!(&destination[..4], &[0, 0, 2, magic.len() as u8]);
                assert_eq!(&destination[4..], magic);
            } else if !xudp {
                let mut destination = [0; 7];
                stream.read_exact(&mut destination).unwrap();
                assert_eq!(&destination[..2], PORT.to_be_bytes());
                assert_eq!(destination[2], 1);
                assert_eq!(&destination[3..], TARGET);
            }
            stream.write_all(&[0, 0]).unwrap();
            for index in 0..PAYLOAD_SIZES.len() {
                if xudp {
                    let metadata = sized_bytes(&mut stream);
                    assert_eq!(metadata.len(), 12);
                    assert_eq!(&metadata[..2], &[0, 0]);
                    assert_eq!(metadata[2], if index == 0 { 1 } else { 2 });
                    assert_eq!(&metadata[3..5], &[1, 2]);
                    assert_eq!(&metadata[5..7], PORT.to_be_bytes());
                    assert_eq!(metadata[7], 1);
                    assert_eq!(&metadata[8..], TARGET);
                }
                let payload = sized_bytes(&mut stream);
                if packetaddr {
                    assert_eq!(payload[0], 1);
                    assert_eq!(&payload[1..5], TARGET);
                    assert_eq!(&payload[5..7], PORT.to_be_bytes());
                    assert!(payload.len() > 7);
                }
                assert!(!payload.is_empty());
                seen.fetch_add(1, Ordering::Relaxed);
                if xudp {
                    // KEEP + DATA with the same session ID; no repeated target
                    // is needed on a response for this association.
                    stream.write_all(&[0, 4, 0, 0, 2, 1]).unwrap();
                }
                stream
                    .write_all(&(payload.len() as u16).to_be_bytes())
                    .unwrap();
                stream.write_all(&payload).unwrap();
                stream.flush().unwrap();
            }
        });
        let app = support::App::new();
        let mut node = json!({"type":"vless","tag":"wire-format","uuid":UUID,"server":"127.0.0.1","server_port":peer.address.port()});
        if let Some(encoding) = encoding {
            node["packet_encoding"] = encoding.into();
        }
        app.import("wire-format", vec![node]);
        app.service.start().unwrap();
        let mut association =
            TcpStream::connect(("127.0.0.1", app.service.snapshot().settings.mixed_port)).unwrap();
        association
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        association.write_all(&[5, 1, 0]).unwrap();
        let mut hello = [0; 2];
        association.read_exact(&mut hello).unwrap();
        assert_eq!(hello, [5, 0]);
        association
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let mut reply = [0; 10];
        association.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let relay = ("127.0.0.1", u16::from_be_bytes([reply[8], reply[9]]));
        let mut address = vec![0, 0, 0, 1];
        address.extend_from_slice(&TARGET);
        address.extend_from_slice(&PORT.to_be_bytes());
        for size in PAYLOAD_SIZES {
            let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut request = address.clone();
            request.extend_from_slice(&payload);
            socket.send_to(&request, relay).unwrap();
            let mut response = vec![0; 65535];
            let (length, _) = socket.recv_from(&mut response).unwrap();
            assert_eq!(
                &response[..length],
                request,
                "{encoding:?}: datagram changed"
            );
        }
        assert_eq!(packets.load(Ordering::Relaxed), PAYLOAD_SIZES.len());
        app.service.stop().unwrap();
    }
}
