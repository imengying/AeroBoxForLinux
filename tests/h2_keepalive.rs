//! HTTP/2 wire peer independent of the embedded client's H2 implementation.
//! TLS is terminated by a native port-forward listener in the same test core;
//! the peer itself handles framing, PING ACKs and gRPC envelopes by hand.
mod support;

use aerobox_for_linux::{protocol, subscription};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use shoes::embedding::EmbeddedCore;
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

const UUID: &str = "00000000-0000-4000-8000-000000000001";

fn h2_options(value: &Value) -> &Value {
    if value["type"] == "stream_transport" {
        value
    } else {
        h2_options(
            value
                .get("protocol")
                .expect("stream transport missing from native config"),
        )
    }
}

#[test]
fn keepalive_parameters_survive_subscription_formats_and_validate_units() {
    let expected = json!({"type":"grpc", "service_name":"tunnel", "idle_timeout":"1.5s", "ping_timeout":"500ms", "permit_without_stream":true});
    let vmess = json!({"v":"2", "ps":"fixture", "add":"example.com", "port":"443", "id":UUID, "net":"grpc", "path":"tunnel", "idle-timeout":"1.5s", "ping_timeout":"500ms", "grpc_permit_without_stream":true});
    for body in [
        json!([{"type":"vless", "tag":"fixture", "server":"example.com", "server_port":443, "uuid":UUID, "transport":expected}]).to_string(),
        json!({"proxies":[{"type":"vless", "name":"fixture", "server":"example.com", "port":443, "uuid":UUID, "network":"grpc", "grpc-opts":{"grpc-service-name":"tunnel", "idle-timeout":"1.5s", "ping_timeout":"500ms", "permit-without-stream":true}}]}).to_string(),
        format!("vless://{UUID}@example.com:443?type=grpc&serviceName=tunnel&idle_timeout=1.5s&ping-timeout=500ms&grpc-permit-without-stream=true#fixture"),
        format!("vmess://{}", STANDARD.encode(vmess.to_string())),
    ] {
        let node = subscription::parse(&body).unwrap().remove(0);
        assert_eq!(node["transport"], expected, "{body}");
        let native = protocol::convert_outbound(node, "fixture").unwrap();
        let options = h2_options(&native["client_chains"][0]["chain"][0]["protocol"]);
        assert_eq!(options["idle_timeout_ms"], 1500);
        assert_eq!(options["ping_timeout_ms"], 500);
        assert_eq!(options["permit_without_stream"], true);
    }
    for network in ["h2", "http"] {
        let options = if network == "h2" {
            "h2-opts"
        } else {
            "http-opts"
        };
        let mut node = json!({"type":"vless", "name":"fixture", "server":"example.com", "port":443, "uuid":UUID, "network":network, "tls":true});
        node[options] = json!({"idle_timeout":"0", "ping-timeout":"0s"});
        let node = subscription::parse(&json!({"proxies":[node]}).to_string())
            .unwrap()
            .remove(0);
        let native = protocol::convert_outbound(node, "fixture").unwrap();
        let options = h2_options(&native["client_chains"][0]["chain"][0]["protocol"]);
        assert_eq!(options["kind"], "http2");
        assert_eq!(options["idle_timeout_ms"], 0);
        assert_eq!(options["ping_timeout_ms"], 0);
    }
    let valid = json!({"type":"vless", "tag":"fixture", "server":"example.com", "server_port":443, "uuid":UUID, "transport":expected});
    for (field, value) in [
        ("idle_timeout", json!("-1s")),
        ("idle_timeout", json!("0.1ms")),
        ("ping_timeout", json!("4294967296ms")),
        ("ping_timeout", json!(15)),
        ("permit_without_stream", json!("false")),
    ] {
        let mut node = valid.clone();
        node["transport"][field] = value;
        assert!(
            subscription::parse(&json!([node]).to_string()).is_err(),
            "{field}"
        );
    }
    let mut defaults = valid.clone();
    defaults["transport"]["idle_timeout"] = "".into();
    defaults["transport"]["ping_timeout"] = "".into();
    protocol::validate(&defaults).unwrap();
    for query in [
        "type=grpc&idle_timeout=1s&idle-timeout=2s",
        "type=grpc&permit_without_stream=true&grpc_permit_without_stream=false",
        "type=ws&idle_timeout=1s",
        "type=tcp&ping_timeout=1s",
        "type=http&idle_timeout=1s", // HTTP/1 without TLS has no H2 PING.
        "type=http&security=tls&permit_without_stream=true",
    ] {
        assert!(
            subscription::parse(&format!("vless://{UUID}@example.com:443?{query}")).is_err(),
            "{query}"
        );
    }
    let duplicate = json!({"proxies":[{"type":"vless", "name":"fixture", "server":"example.com", "port":443, "uuid":UUID, "network":"grpc", "grpc_permit_without_stream":true, "grpc-opts":{"permit-without-stream":false}}]});
    assert!(subscription::parse(&duplicate.to_string()).is_err());
}

fn write_frame(
    stream: &mut TcpStream,
    kind: u8,
    flags: u8,
    id: u32,
    data: &[u8],
) -> io::Result<()> {
    stream.write_all(&(data.len() as u32).to_be_bytes()[1..])?;
    stream.write_all(&[kind, flags])?;
    stream.write_all(&id.to_be_bytes())?;
    stream.write_all(data)
}

fn read_frame(stream: &mut TcpStream) -> io::Result<(u8, u8, u32, Vec<u8>)> {
    let mut header = [0; 9];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    assert!(length <= 64 * 1024, "unexpected fixture H2 frame size");
    let mut data = vec![0; length];
    stream.read_exact(&mut data)?;
    Ok((
        header[3],
        header[4],
        u32::from_be_bytes(header[5..].try_into().unwrap()),
        data,
    ))
}

fn grpc_frame(data: &[u8]) -> Vec<u8> {
    let mut varint = Vec::new();
    let mut length = data.len();
    while length > 127 {
        varint.push((length as u8 & 127) | 128);
        length >>= 7;
    }
    varint.push(length as u8);
    let mut frame = vec![0];
    frame.extend_from_slice(&((1 + varint.len() + data.len()) as u32).to_be_bytes());
    frame.push(0x0a);
    frame.extend(varint);
    frame.extend_from_slice(data);
    frame
}

fn grpc_payload(buffer: &mut Vec<u8>) -> Vec<u8> {
    let mut output = Vec::new();
    while buffer.len() >= 5 {
        assert_eq!(buffer[0], 0);
        let length = u32::from_be_bytes(buffer[1..5].try_into().unwrap()) as usize;
        assert!(length <= 64 * 1024);
        if buffer.len() < length + 5 {
            break;
        }
        assert_eq!(buffer[5], 0x0a);
        let mut size = 0usize;
        let mut start = 6;
        for shift in (0..35).step_by(7) {
            let byte = buffer[start];
            start += 1;
            size |= usize::from(byte & 127) << shift;
            if byte & 128 == 0 {
                break;
            }
        }
        assert_eq!(start + size, length + 5);
        output.extend_from_slice(&buffer[start..start + size]);
        buffer.drain(..length + 5);
    }
    output
}

struct Control {
    writer: Arc<Mutex<TcpStream>>,
    id: u32,
    grpc: bool,
}
impl Control {
    fn data(&self, data: &[u8]) {
        let bytes = if self.grpc {
            grpc_frame(data)
        } else {
            data.to_vec()
        };
        write_frame(&mut self.writer.lock().unwrap(), 0, 0, self.id, &bytes).unwrap();
    }
}

fn peer(
    grpc: bool,
) -> (
    support::Server,
    mpsc::Receiver<Control>,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
) {
    let (ready_tx, ready_rx) = mpsc::channel();
    let pings = Arc::new(AtomicUsize::new(0));
    let ack = Arc::new(AtomicBool::new(true));
    let count = pings.clone();
    let acknowledge = ack.clone();
    let server = support::Server::spawn(move |mut reader| {
        let writer = Arc::new(Mutex::new(reader.try_clone().unwrap()));
        let mut preface = [0; 24];
        reader.read_exact(&mut preface).unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        write_frame(&mut writer.lock().unwrap(), 4, 0, 0, &[]).unwrap();
        let mut grpc_buffer = Vec::new();
        let mut inner = Vec::new();
        let mut connected = false;
        while let Ok((kind, flags, id, data)) = read_frame(&mut reader) {
            match kind {
                4 if flags == 0 => write_frame(&mut writer.lock().unwrap(), 4, 1, 0, &[]).unwrap(),
                1 => {
                    let mut headers = vec![0x88]; // HPACK :status=200.
                    if grpc {
                        headers.extend_from_slice(b"\x00\x0ccontent-type\x10application/grpc");
                    }
                    write_frame(&mut writer.lock().unwrap(), 1, 4, id, &headers).unwrap();
                }
                0 => {
                    assert_eq!(flags & 8, 0, "fixture expects unpadded DATA");
                    if grpc {
                        grpc_buffer.extend(data);
                        inner.extend(grpc_payload(&mut grpc_buffer));
                    } else {
                        inner.extend(data);
                    }
                    let control = Control {
                        writer: writer.clone(),
                        id,
                        grpc,
                    };
                    if !connected {
                        let Some(end) = inner.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                        else {
                            continue;
                        };
                        assert!(inner.starts_with(b"CONNECT 203.0.113.17:443 HTTP/1.1\r\n"));
                        inner.drain(..end + 4);
                        control.data(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                        connected = true;
                        ready_tx
                            .send(Control {
                                writer: writer.clone(),
                                id,
                                grpc,
                            })
                            .unwrap();
                    }
                    if !inner.is_empty() {
                        control.data(&inner);
                        inner.clear();
                    }
                }
                6 if flags == 0 => {
                    assert_eq!((id, data.len()), (0, 8));
                    if acknowledge.load(Ordering::SeqCst) {
                        write_frame(&mut writer.lock().unwrap(), 6, 1, 0, &data).unwrap();
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
        }
    });
    (server, ready_rx, pings, ack)
}

fn tunnel(port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(b"CONNECT 203.0.113.17:443 HTTP/1.1\r\nHost: 203.0.113.17:443\r\n\r\n")
        .unwrap();
    assert!(
        support::headers(&mut stream)
            .unwrap()
            .starts_with("HTTP/1.1 200")
    );
    stream
}

#[test]
fn grpc_and_http2_ping_health_checks_preserve_live_streams_and_close_blackholes() {
    let _serial = support::runtime_lock();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, certified.cert.pem()).unwrap();
    std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
    for grpc in [true, false] {
        let (peer, ready, pings, ack) = peer(grpc);
        let tls_port = support::free_port();
        let mut node = json!({"tag":"h2-test", "type":"http", "server":"127.0.0.1", "server_port":if grpc { peer.address.port() } else { tls_port }, "transport":{"type":if grpc { "grpc" } else { "http" }, "idle_timeout":"400ms", "ping_timeout":"2s"}});
        let (app, core, inbound) = if grpc {
            let app = support::App::new();
            app.import("keepalive", vec![node]);
            app.service.start().unwrap();
            let inbound = app.service.local_proxy_port();
            (Some(app), None, inbound)
        } else {
            node["tls"] = json!({"enabled":true, "server_name":"localhost", "certificate":certified.cert.pem(), "alpn":["h2"]});
            protocol::validate(&node).unwrap();
            let inbound = support::free_port();
            let config = json!([
                protocol::convert_outbound(node, "fixture").unwrap(),
                {"address":format!("127.0.0.1:{inbound}"), "protocol":{"type":"mixed"}, "rules":[{"conditions":{"any_destination":true}, "action":"allow", "client_chain":"h2-test"}]},
                {"address":format!("127.0.0.1:{tls_port}"), "protocol":{"type":"tls", "tls_targets":{"localhost":{"cert":cert, "key":key, "alpn_protocols":["h2"], "protocol":{"type":"forward", "targets":peer.address.to_string()}}}}, "rules":[{"conditions":{"any_destination":true}, "action":"allow"}]},
            ]);
            let core = rt
                .block_on(EmbeddedCore::start_json(&config.to_string(), None))
                .unwrap();
            (None, Some(core), inbound)
        };
        let mut stream = tunnel(inbound);
        let control = ready.recv_timeout(Duration::from_secs(4)).unwrap();
        control.data(b"live");
        let mut data = [0; 4];
        stream.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"live");
        // Scheduling pauses on slow CI machines can legitimately trigger PING.
        // Paused-clock native tests cover exact deadlines and DATA postponement;
        // this wire peer verifies acknowledged probes and eventual disconnection.
        let deadline = Instant::now() + Duration::from_secs(4);
        while pings.load(Ordering::SeqCst) < 2 {
            assert!(
                Instant::now() < deadline,
                "configured idle timeout did not send PINGs, grpc={grpc}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        stream.write_all(b"echo").unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(
            &response, b"echo",
            "acknowledged PINGs must keep the tunnel usable"
        );
        ack.store(false, Ordering::SeqCst);
        match stream.read(&mut [0]) {
            Ok(0) => {}
            Err(error)
                if !matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            result => panic!("missing PONG must close an active tunnel, grpc={grpc}: {result:?}"),
        }
        drop(control);
        drop(stream);
        if let Some(core) = core {
            rt.block_on(core.shutdown()).unwrap();
        }
        if let Some(app) = app {
            app.service.stop().unwrap();
        }
    }
}
