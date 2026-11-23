#![cfg(target_os = "linux")]

mod support;

use aerobox_for_linux::{engine::Service, protocol, subscription};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::fd::{AsRawFd, FromRawFd},
    sync::mpsc,
    time::{Duration, Instant},
};
use support::{App, Server, socks_node};

#[test]
fn subscription_dial_options_keep_units_and_reject_invalid_values() {
    let node = socks_node("dial", "127.0.0.1:1080".parse().unwrap());
    for (duration, millis) in [
        ("250ms", 250),
        ("1.5s", 1500),
        ("1m30s", 90000),
        (".001s", 1),
        ("500us500us", 1),
    ] {
        let mut value = node.clone();
        value["connect_timeout"] = duration.into();
        protocol::validate(&value).unwrap();
        let converted = protocol::convert_outbound(value, "node").unwrap();
        assert_eq!(
            converted["client_chains"][0]["chain"][0]["connect_timeout_ms"],
            millis
        );
    }

    let expected = json!({
        "bind_interface":"lo", "connect_timeout":"1.5s", "disable_tcp_keep_alive":false,
        "tcp_keep_alive":"2m", "tcp_keep_alive_interval":"3s",
    });
    let mut json_node = node.clone();
    json_node
        .as_object_mut()
        .unwrap()
        .extend(expected.as_object().unwrap().clone());
    let vmess = json!({
        "v":"2", "ps":"dial", "add":"127.0.0.1", "port":1080,
        "id":"0193a3dd-a00c-40c5-95c7-512ba016575c", "net":"tcp",
        "bind_interface":"lo", "connect_timeout":"1.5s", "disable_tcp_keep_alive":false,
        "tcp_keep_alive":"2m", "tcp_keep_alive_interval":"3s",
    });
    for body in [
        json!([json_node]).to_string(),
        "proxies:\n- {name: dial, type: socks5, server: 127.0.0.1, port: 1080, interface-name: lo, connect-timeout: 1.5s, disable-tcp-keep-alive: false, tcp-keep-alive: 2m, tcp-keep-alive-interval: 3s}".into(),
        "socks5://127.0.0.1:1080?bind_interface=lo&connect_timeout=1.5s&disable_tcp_keep_alive=false&tcp_keep_alive=2m&tcp_keep_alive_interval=3s#dial".into(),
        format!("vmess://{}", STANDARD.encode(vmess.to_string())),
    ] {
        let nodes = subscription::parse(&body).unwrap();
        for (field, value) in expected.as_object().unwrap() {
            assert_eq!(&nodes[0][field], value, "{field}: {body}");
        }
    }
    for (field, value) in [
        ("connect_timeout", json!(0)),
        ("connect_timeout", json!("0s")),
        ("connect_timeout", json!("-1s")),
        ("connect_timeout", json!("0.5ms")),
        ("connect_timeout", json!("1..5s")),
        ("connect_timeout", json!("4294967296ms")),
        ("tcp_keep_alive", json!("0s")),
        ("tcp_keep_alive", json!("1500ms")),
        ("tcp_keep_alive_interval", json!("32768s")),
        ("disable_tcp_keep_alive", json!("true")),
        ("tcp_fast_open", json!("true")),
    ] {
        let mut invalid = node.clone();
        invalid[field] = value;
        let (kept, skipped) =
            subscription::parse_with_skips(&json!([node, invalid]).to_string()).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].contains(field), "{skipped:?}");
    }
    let duplicate = "proxies:\n- {name: dial, type: socks5, server: localhost, port: 1080, connect-timeout: 1s, connect_timeout: 2s}";
    assert!(subscription::parse(duplicate).is_err());

    let mut quic = json!({"type":"hysteria2", "tag":"quic", "server":"127.0.0.1", "server_port":443, "password":"test", "tls":{"enabled":true,"insecure":true}, "connect_timeout":"250ms"});
    protocol::validate(&quic).unwrap();
    quic["tcp_keep_alive"] = "1m".into();
    assert!(
        protocol::validate(&quic)
            .unwrap_err()
            .to_string()
            .contains("tcp_keep_alive")
    );
}

/// The application and peer run in this process, so inspect a duplicated fd
/// selected by both socket endpoints. This checks the OS option on the actual
/// outbound stream, without exposing production-only testing hooks.
fn outbound_socket(local: SocketAddr, remote: SocketAddr) -> TcpStream {
    for entry in fs::read_dir("/proc/self/fd").unwrap() {
        let entry = entry.unwrap();
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        // SAFETY: fcntl duplicates an open descriptor; the owned duplicate is
        // closed exactly once by TcpStream, including all non-socket entries.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            continue;
        }
        let stream = unsafe { TcpStream::from_raw_fd(duplicate) };
        if stream.local_addr().ok() == Some(local) && stream.peer_addr().ok() == Some(remote) {
            return stream;
        }
    }
    panic!("outbound socket {local} -> {remote} was not found");
}

fn socket_option(stream: &TcpStream, level: libc::c_int, option: libc::c_int) -> i32 {
    let mut value = 0i32;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: both output pointers point to initialized values of the length
    // supplied, and stream owns a live socket descriptor for the call.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            level,
            option,
            (&raw mut value).cast(),
            &mut length,
        )
    };
    assert_eq!(result, 0, "getsockopt: {}", std::io::Error::last_os_error());
    assert_eq!(length as usize, std::mem::size_of::<i32>());
    value
}

#[test]
fn service_applies_keepalive_to_real_outbound_sockets() {
    let _serial = support::runtime_lock();
    for (options, expected) in [
        (json!({}), Some((120, 30))),
        (
            json!({"tcp_keep_alive":"7s", "tcp_keep_alive_interval":"3s"}),
            Some((7, 3)),
        ),
        (json!({"disable_tcp_keep_alive":true}), None),
    ] {
        let (connected, accepted) = mpsc::channel();
        let peer = Server::spawn(move |mut stream| {
            if support::socks_handshake(&mut stream).is_err() {
                return;
            }
            if connected.send(stream.peer_addr().unwrap()).is_err() {
                return;
            }
            let mut bytes = [0; 4096];
            while let Ok(n) = stream.read(&mut bytes) {
                if n == 0 || stream.write_all(&bytes[..n]).is_err() {
                    break;
                }
            }
        });
        let app = App::new();
        let mut node = socks_node("keepalive", peer.address);
        node.as_object_mut()
            .unwrap()
            .extend(options.as_object().unwrap().clone());
        node["connect_timeout"] = "1s".into();
        app.import("keepalive", vec![node]);
        app.service.start().unwrap();
        let mut tunnel = support::echo_tunnel(&app.service, "192.0.2.1:443".parse().unwrap());
        let local = accepted.recv_timeout(Duration::from_secs(2)).unwrap();
        let outbound = outbound_socket(local, peer.address);
        assert_eq!(
            socket_option(&outbound, libc::SOL_SOCKET, libc::SO_KEEPALIVE),
            i32::from(expected.is_some())
        );
        if let Some((idle, interval)) = expected {
            assert_eq!(
                socket_option(&outbound, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE),
                idle
            );
            assert_eq!(
                socket_option(&outbound, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL),
                interval
            );
        }
        let payload = [0xa5; 4096];
        tunnel.write_all(&payload).unwrap();
        let mut echoed = [0; 4096];
        tunnel.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, payload);
        tunnel.shutdown(Shutdown::Both).unwrap();
        drop(outbound);
        app.service.stop().unwrap();
    }
}

fn assert_dial_times_out(service: &Service) {
    let mut stream =
        TcpStream::connect(("127.0.0.1", service.snapshot().settings.mixed_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut hello = [0; 2];
    stream.read_exact(&mut hello).unwrap();
    assert_eq!(hello, [5, 0]);
    let started = Instant::now();
    stream
        .write_all(&[5, 1, 0, 1, 192, 0, 2, 1, 1, 187])
        .unwrap();
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).unwrap_or_else(|error| {
        panic!(
            "dial reply after {:?}: {error}\n{}",
            started.elapsed(),
            service.logs()
        )
    });
    assert_eq!(reply[0], 5);
    assert_ne!(reply[1], 0, "unreachable peer must fail closed");
    assert!(
        started.elapsed() >= Duration::from_millis(70),
        "fixture failed immediately instead of waiting for the dial deadline: {:?}\n{}",
        reply,
        service.logs()
    );
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "dial exceeded its 150ms budget: {:?}\n{}",
        started.elapsed(),
        service.logs()
    );
}

#[test]
fn service_connect_timeout_bounds_tcp_quic_and_node_dns() {
    let _serial = support::runtime_lock();
    // A full localhost accept queue drops SYNs. Unlike an arbitrary unreachable
    // Internet IP, this reliably exercises a pending TCP connect offline.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    // SAFETY: listener owns the socket and listen merely changes its backlog.
    assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
    let address = listener.local_addr().unwrap();
    let _pending = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err());

    let quiet_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    for kind in ["tcp", "quic", "dns"] {
        let app = App::new();
        let mut node = if kind == "quic" {
            json!({"type":"hysteria2", "tag":"timeout", "server":"127.0.0.1", "server_port":quiet_udp.local_addr().unwrap().port(), "password":"test", "tls":{"enabled":true,"insecure":true}})
        } else {
            socks_node("timeout", address)
        };
        if kind == "dns" {
            node["server"] = format!("dial-{}.example.test", uuid::Uuid::new_v4().simple()).into();
            let mut settings = app.service.snapshot().settings;
            settings.direct_dns = format!("udp://{}", quiet_udp.local_addr().unwrap());
            app.service.apply_settings(settings).unwrap();
        }
        node["connect_timeout"] = "150ms".into();
        app.import(kind, vec![node]);
        app.service.start().unwrap();
        assert_dial_times_out(&app.service);
        app.service.stop().unwrap();
    }
}
