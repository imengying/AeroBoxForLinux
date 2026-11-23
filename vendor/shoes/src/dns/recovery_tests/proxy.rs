use super::*;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Relay {
    address: SocketAddr,
    blackhole: Arc<AtomicBool>,
    opens: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
    _task: AbortOnDropHandle<()>,
}

impl Relay {
    async fn start(target: SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let blackhole = Arc::new(AtomicBool::new(false));
        let opens = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let state = (blackhole.clone(), opens.clone(), live.clone());
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            let (blackhole, opens, live) = state;
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (downstream, _) = accepted.unwrap();
                        opens.fetch_add(1, Ordering::SeqCst);
                        let blackhole = blackhole.clone();
                        let live = live.clone();
                        connections.spawn(async move {
                            struct Active(Arc<AtomicUsize>);
                            impl Drop for Active {
                                fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
                            }
                            live.fetch_add(1, Ordering::SeqCst);
                            let _active = Active(live);
                            let upstream = tokio::net::TcpStream::connect(target).await.unwrap();
                            let (down_read, down_write) = downstream.into_split();
                            let (up_read, up_write) = upstream.into_split();
                            let forward = |mut read: tokio::net::tcp::OwnedReadHalf, mut write: tokio::net::tcp::OwnedWriteHalf| {
                                let blackhole = blackhole.clone();
                                async move {
                                    let mut bytes = [0; 16384];
                                    loop {
                                        let length = read.read(&mut bytes).await?;
                                        if length == 0 { return Ok::<_, std::io::Error>(()); }
                                        if !blackhole.load(Ordering::SeqCst) {
                                            write.write_all(&bytes[..length]).await?;
                                        }
                                    }
                                }
                            };
                            tokio::select! {
                                _ = forward(down_read, up_write) => {},
                                _ = forward(up_read, down_write) => {},
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        }));
        Self {
            address,
            blackhole,
            opens,
            live,
            _task: task,
        }
    }
}

struct Proxy {
    relay: Relay,
    client: serde_json::Value,
    network: crate::network_tasks::NetworkLifetime,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Proxy {
    async fn start(xhttp: bool) -> Self {
        let reservation = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], reservation.local_addr().unwrap().port()));
        let protocol = json!({"type":"vless", "user_id":"550e8400-e29b-41d4-a716-446655440000"});
        let (server, client) = if xhttp {
            let server =
                json!({"type":"xhttp", "path":"/tunnel", "http_version":"h2", "protocol":protocol});
            let mut client = server.clone();
            client["mode"] = json!("stream-one");
            client["pool"] = json!({"max_connections":1, "idle_timeout_secs":600});
            (server, client)
        } else {
            let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let digest = aerobox_primitives::digest::digest(
                &aerobox_primitives::digest::SHA256,
                certificate.cert.der(),
            );
            let fingerprint: String = digest
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            (
                json!({"type":"tls", "default_target":{"cert":certificate.cert.pem(), "key":certificate.signing_key.serialize_pem(), "protocol":protocol}}),
                json!({"type":"tls", "verify":false, "server_fingerprints":[fingerprint], "sni_hostname":"localhost", "protocol":protocol}),
            )
        };
        let config = crate::config::create_server_configs(
            serde_json::from_value(json!([
                {"address":address.to_string(), "protocol":server}
            ]))
            .unwrap(),
        )
        .unwrap()
        .configs
        .remove(0);
        let network = crate::network_tasks::NetworkLifetime::default();
        drop(reservation);
        let handles = network
            .scope(crate::tcp::tcp_server::start_servers(
                config,
                Arc::new(NativeResolver::new()),
            ))
            .await
            .unwrap();
        let relay = Relay::start(address).await;
        let client = json!({"name":if xhttp {"xhttp"} else {"tls"}, "address":relay.address.to_string(), "protocol":client});
        Self {
            relay,
            client,
            network,
            handles,
        }
    }

    async fn stop(self) {
        self.network.cancel();
        self.network.wait().await;
        for handle in self.handles {
            let _ = handle.await;
        }
    }
}

#[tokio::test]
async fn doh_over_xhttp_recovers_after_blackhole_and_uses_current_selector() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let fixture = DohFixture::start().await;
        let xhttp = Proxy::start(true).await;
        let tls = Proxy::start(false).await;
        let mut config = crate::config::create_server_configs(serde_json::from_value(json!([
            {"client_group":"a1-selected", "type":"selector", "default":"xhttp", "client_chains":[
                {"chain":[xhttp.client.clone()]}, {"chain":[tls.client.clone()]}
            ]},
            {"dns_group":"desktop-dns", "dns_servers":[{"url":"https://1.1.1.1/dns-query", "client_chain":"a1-selected"}]}
        ])).unwrap()).unwrap();
        let mut selection = crate::control::selection::SelectionOwner::new(None).unwrap();
        selection.activate(config.catalog.take().unwrap().selection).unwrap();
        let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chains = config.dns_groups.remove(0).specs.remove(0).client_chains;
        let group = Arc::new(crate::tcp::chain_builder::try_build_client_chain_group(
            crate::option_util::NoneOrSome::Some(chains), bootstrap.clone()).unwrap());
        let resolver = fixture.refreshing_via(group, bootstrap).await;
        resolver.exchange(query(0)).await.unwrap();
        assert_eq!(xhttp.relay.opens.load(Ordering::SeqCst), 1);

        xhttp.relay.blackhole.store(true, Ordering::SeqCst);
        assert_eq!(resolver.exchange(query(1)).await.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(xhttp.relay.opens.load(Ordering::SeqCst), 1);
        // Real sockets carry the nested protocols; only watchdog time is accelerated.
        tokio::time::pause();
        for _ in 0..57 {
            tokio::time::advance(Duration::from_secs(1)).await;
            for _ in 0..10 { tokio::task::yield_now().await; }
        }
        tokio::time::resume();
        tokio::time::timeout(Duration::from_secs(1), async {
            while xhttp.relay.live.load(Ordering::SeqCst) != 0 { tokio::task::yield_now().await; }
        }).await.expect("watchdog did not close blackholed carrier");
        xhttp.relay.blackhole.store(false, Ordering::SeqCst);
        resolver.exchange(query(2)).await.unwrap();
        assert_eq!(xhttp.relay.opens.load(Ordering::SeqCst), 2);

        resolver.resolve_location(&NetLocation::from_str("before-stall.example.:443", None).unwrap()).await.unwrap();

        xhttp.relay.blackhole.store(true, Ordering::SeqCst);
        assert_eq!(resolver.resolve_location(&NetLocation::from_str("during-stall.example.:443", None).unwrap()).await.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(resolver.exchange(query(3)).await.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        selection.select("a1-selected", "tls").unwrap();
        resolver.exchange_with_deadline(query(4), tokio::time::Instant::now() + Duration::from_secs(1)).await.unwrap();
        assert_eq!(tls.relay.opens.load(Ordering::SeqCst), 1);
        assert_eq!(xhttp.relay.opens.load(Ordering::SeqCst), 2, "fresh DNS ignored selector switch");
        resolver.resolve_location(&NetLocation::from_str("selected.example.:443", None).unwrap()).await.unwrap();
        assert_eq!(tls.relay.opens.load(Ordering::SeqCst), 2, "lookup uses its own transport but the current route");
        drop(resolver);
        xhttp.stop().await;
        tls.stop().await;
        fixture.wait_closed().await;
    }).await.unwrap();
}

#[tokio::test]
async fn doh_over_xhttp_stream_reset_reconnects_without_retiring_the_carrier() {
    for lookup in [false, true] {
        let fixture = DohFixture::start().await;
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let reset = Arc::new(tokio::sync::Notify::new());
        let opens = Arc::new(AtomicUsize::new(0));
        let streams = Arc::new(AtomicUsize::new(0));
        let target = fixture.address;
        let server = {
            let reset = reset.clone();
            let opens = opens.clone();
            let streams = streams.clone();
            AbortOnDropHandle::new(tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (tcp, _) = accepted.unwrap();
                            opens.fetch_add(1, Ordering::SeqCst);
                            let reset = reset.clone();
                            let streams = streams.clone();
                            connections.spawn(async move {
                                let mut h2 = h2::server::handshake(tcp).await.unwrap();
                                let mut sessions = tokio::task::JoinSet::new();
                                while let Some(Ok((request, mut respond))) = h2.accept().await {
                                    let first = streams.fetch_add(1, Ordering::SeqCst) == 0;
                                    let reset = reset.clone();
                                    sessions.spawn(async move {
                                        let send = respond.send_response(http::Response::new(()), false).unwrap();
                                        let mut stream = crate::http2::stream::H2MultiStream::new(send, request.into_body());
                                        let mut upstream = tokio::net::TcpStream::connect(target).await.unwrap();
                                        tokio::select! {
                                            _ = reset.notified(), if first => respond.send_reset(h2::Reason::CANCEL),
                                            _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream) => {},
                                        }
                                    });
                                }
                            });
                        }
                        _ = connections.join_next(), if !connections.is_empty() => {},
                    }
                }
            }))
        };
        let chain = crate::config::test_support::from_json(json!([{
            "address":address.to_string(), "protocol":{
                "type":"xhttp", "path":"/tunnel", "mode":"stream-one", "http_version":"h2",
                "pool":{"max_connections":1}, "protocol":{"type":"noop"}
            }
        }]))
        .unwrap();
        let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let group = Arc::new(
            crate::tcp::chain_builder::try_build_client_chain_group(
                crate::option_util::NoneOrSome::One(chain),
                bootstrap.clone(),
            )
            .unwrap(),
        );
        let resolver = Arc::new(fixture.refreshing_via(group, bootstrap).await);
        let perform = |index| {
            let resolver = resolver.clone();
            async move {
                if lookup {
                    resolver
                        .resolve_location(
                            &NetLocation::from_str(&format!("reset{index}.example:80"), None)
                                .unwrap(),
                        )
                        .await
                        .map(|_| ())
                } else {
                    resolver.exchange(query(index)).await.map(|_| ())
                }
            }
        };
        perform(0).await.unwrap();
        fixture.stall.store(true, Ordering::SeqCst);
        let active = tokio::spawn(perform(1));
        tokio::time::timeout(Duration::from_secs(1), async {
            while fixture.requests.load(Ordering::SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        fixture.stall.store(false, Ordering::SeqCst);
        reset.notify_one();
        active.await.unwrap().unwrap();
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
        assert_eq!(
            opens.load(Ordering::SeqCst),
            1,
            "stream reset retired a shared carrier"
        );
        assert_eq!(streams.load(Ordering::SeqCst), 2);
        resolver.retire();
        drop(resolver);
        drop(server);
        fixture.wait_closed().await;
    }
}

#[tokio::test]
async fn doh_pool_fails_over_after_proxy_setup_other_error() {
    let failed = DohFixture::start().await;
    let healthy = DohFixture::start().await;
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
    let failed_address = failed.address;
    let healthy_address = healthy.address;
    let rejected = Arc::new(AtomicUsize::new(0));
    let count = rejected.clone();
    let proxy = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (tcp, _) = accepted.unwrap();
                    let count = count.clone();
                    tasks.spawn(async move {
                        let mut h2 = h2::server::handshake(tcp).await.unwrap();
                        let mut tunnels = tokio::task::JoinSet::new();
                        while let Some(Ok((request, mut respond))) = h2.accept().await {
                            assert_eq!(request.method(), http::Method::CONNECT);
                            let target = request.uri().authority().unwrap().as_str().parse::<SocketAddr>().unwrap();
                            if target == failed_address {
                                count.fetch_add(1, Ordering::SeqCst);
                                respond.send_response(http::Response::builder().status(503).body(()).unwrap(), true).unwrap();
                            } else {
                                assert_eq!(target, healthy_address);
                                tunnels.spawn(async move {
                                    // Ensure the setup error arrives before the healthy parallel answer.
                                    tokio::time::sleep(Duration::from_millis(30)).await;
                                    let mut upstream = tokio::net::TcpStream::connect(target).await.unwrap();
                                    let send = respond.send_response(http::Response::new(()), false).unwrap();
                                    let mut stream = crate::http2::stream::H2MultiStream::new(send, request.into_body());
                                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                                });
                            }
                        }
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {},
            }
        }
    }));
    let chain = crate::config::test_support::from_json(json!([{
        "address":address.to_string(), "protocol":{"type":"http", "http_version":"h2"}
    }]))
    .unwrap();
    let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
    let group = Arc::new(
        crate::tcp::chain_builder::try_build_client_chain_group(
            crate::option_util::NoneOrSome::One(chain),
            bootstrap.clone(),
        )
        .unwrap(),
    );
    let servers = [failed.address, healthy.address]
        .into_iter()
        .map(|address| {
            let mut connection = hickory_resolver::config::ConnectionConfig::https(
                "localhost".into(),
                Some("/dns-query".into()),
            );
            connection.port = address.port();
            (address.ip(), connection)
        })
        .collect();
    let resolver = crate::rustls_config_util::with_test_roots(healthy.roots.clone(), || {
        HickoryResolver::build_pooled(
            servers,
            group,
            bootstrap,
            HickoryResolverOptions {
                ip_strategy: super::super::IpStrategy::Ipv4Only,
                request_timeout: Some(Duration::from_millis(150)),
                attempts: 1,
                ..Default::default()
            },
            "proxy setup failover".into(),
        )
        .unwrap()
    });
    resolver
        .resolve_location(&NetLocation::from_str("pooled.example:80", None).unwrap())
        .await
        .unwrap();
    assert_eq!(rejected.load(Ordering::SeqCst), 1);
    assert_eq!(failed.requests.load(Ordering::SeqCst), 0);
    assert_eq!(healthy.requests.load(Ordering::SeqCst), 1);
    resolver.retire();
    drop(proxy);
    healthy.wait_closed().await;
}

#[tokio::test]
async fn rejected_proxy_pin_is_not_retried_or_bypassed() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = DohFixture::start().await;
        let mut proxy = Proxy::start(false).await;
        proxy.client["protocol"]["server_fingerprints"] = json!(["00".repeat(32)]);
        let chain = crate::config::test_support::from_json(json!([proxy.client.clone()])).unwrap();
        let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let group = Arc::new(
            crate::tcp::chain_builder::try_build_client_chain_group(
                crate::option_util::NoneOrSome::One(chain),
                bootstrap.clone(),
            )
            .unwrap(),
        );
        let resolver = fixture.refreshing_via(group, bootstrap).await;
        let error = resolver.exchange(query(0)).await.unwrap_err();
        assert!(error.to_string().contains("fingerprint"), "{error:?}");
        assert!(!crate::resolver::RefreshingResolver::should_refresh_for_error(&error));
        assert_eq!(proxy.relay.opens.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
        drop(resolver);
        proxy.stop().await;
    })
    .await
    .unwrap();
}

struct RealityDohPeer {
    child: std::process::Child,
    log: std::path::PathBuf,
    _directory: tempfile::TempDir,
    address: SocketAddr,
    public_key: String,
}

impl RealityDohPeer {
    async fn start(executable: &std::path::Path, vision: bool) -> Self {
        use aerobox_primitives::{
            agreement,
            rand::{SecureRandom, SystemRandom},
        };
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use std::process::{Command, Stdio};

        let mut private = [0; 32];
        SystemRandom::new().fill(&mut private).unwrap();
        let public = agreement::PrivateKey::from_private_key(&agreement::X25519, &private)
            .unwrap()
            .compute_public_key()
            .unwrap();
        let public_key = URL_SAFE_NO_PAD.encode(public.as_ref());
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        let template = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let template_address = template.local_addr().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("reality-doh.json");
        let log = directory.path().join("peer.log");
        let certificate = directory.path().join("template.pem");
        let key = directory.path().join("template-key.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(&certificate, certified.cert.pem()).unwrap();
        std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
        std::fs::write(
            &config,
            serde_json::to_vec(&json!({
                "log":{"level":"error"},
                "inbounds":[{
                    "type":"vless", "listen":"127.0.0.1", "listen_port":address.port(),
                    "users":[{
                        "uuid":"550e8400-e29b-41d4-a716-446655440000",
                        "flow":if vision { "xtls-rprx-vision" } else { "" }
                    }],
                    "tls":{
                        "enabled":true, "server_name":"localhost",
                        "reality":{
                            "enabled":true,
                            "handshake":{"server":"127.0.0.1", "server_port":template_address.port()},
                            "private_key":URL_SAFE_NO_PAD.encode(private),
                            "short_id":["0123456789abcdef"]
                        }
                    }
                },{
                    // Use the independent server's supported TLS flight as the
                    // REALITY template. The actual DoH endpoint remains Rustls.
                    "type":"http", "listen":"127.0.0.1", "listen_port":template_address.port(),
                    "tls":{
                        "enabled":true, "server_name":"localhost", "min_version":"1.3",
                        "certificate_path":certificate, "key_path":key
                    }
                }],
                "outbounds":[{"type":"direct", "tag":"local"}],
                "route":{"final":"local"}
            }))
            .unwrap(),
        )
        .unwrap();
        let output = std::fs::File::create(&log).unwrap();
        drop(reservation);
        drop(template);
        let child = Command::new(executable)
            .args(["run", "--disable-color", "-c"])
            .arg(config)
            .current_dir(directory.path())
            .env("GOMAXPROCS", "1")
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .expect("cannot start the independent sing-box peer");
        let mut peer = Self {
            child,
            log,
            _directory: directory,
            address,
            public_key,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                peer.child.try_wait().unwrap().is_none(),
                "sing-box exited before listening: {}",
                peer.logs()
            );
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                return peer;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "sing-box did not become ready: {}",
                peer.logs()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for RealityDohPeer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
#[ignore = "requires an independent sing-box in AEROBOX_TEST_PEER; all traffic stays on loopback"]
async fn recursive_doh_over_reality_with_and_without_vision_uses_inner_tls() {
    let executable = std::path::PathBuf::from(
        std::env::var_os("AEROBOX_TEST_PEER")
            .expect("set AEROBOX_TEST_PEER to the independent sing-box executable"),
    )
    .canonicalize()
    .expect("AEROBOX_TEST_PEER must name an existing executable");
    tokio::time::timeout(Duration::from_secs(60), async {
        for vision in [false, true] {
            for fingerprint in ["chrome", "firefox"] {
                let fixture = DohFixture::start().await;
                fixture
                    .reply
                    .store(Reply::RequireRecursive as u8, Ordering::SeqCst);
                let peer = RealityDohPeer::start(&executable, vision).await;
                let chain = crate::config::test_support::from_json(json!([{
                    "address":peer.address.to_string(),
                    "protocol":{
                        "type":"reality", "public_key":peer.public_key,
                        "short_id":"0123456789abcdef", "sni_hostname":"localhost",
                        "client_fingerprint":fingerprint, "vision":vision,
                        "protocol":{
                            "type":"vless", "user_id":"550e8400-e29b-41d4-a716-446655440000"
                        }
                    }
                }]))
                .unwrap();
                let bootstrap: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
                let group = Arc::new(
                    crate::tcp::chain_builder::try_build_client_chain_group(
                        crate::option_util::NoneOrSome::One(chain),
                        bootstrap.clone(),
                    )
                    .unwrap(),
                );
                // Keep ordinary deadlines here: this case performs two TLS
                // handshakes and does not exercise the 150 ms recovery timer.
                let upstream: Arc<dyn Resolver> = Arc::new(
                    crate::rustls_config_util::with_test_roots(fixture.roots.clone(), || {
                        HickoryResolver::https(
                            fixture.address,
                            "localhost".into(),
                            "/dns-query".into(),
                            group,
                            bootstrap,
                            HickoryResolverOptions {
                                ip_strategy: super::super::IpStrategy::Ipv4Only,
                                attempts: 1,
                                ..Default::default()
                            },
                        )
                        .unwrap()
                    }),
                );
                // A raw, intercepted RD=0 request must be preserved and rejected
                // by the fixture; locally generated lookups below must set RD=1.
                let nonrecursive = Message::from_vec(&query(0)).unwrap();
                assert!(!nonrecursive.metadata.recursion_desired);
                let response = upstream
                    .exchange(nonrecursive.to_vec().unwrap())
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "REALITY DoH exchange failed (vision={vision}, {fingerprint}): {error:?}\n{}",
                            peer.logs()
                        )
                    });
                assert_eq!(
                    Message::from_vec(&response).unwrap().metadata.response_code,
                    ResponseCode::ServFail
                );
                assert_eq!(fixture.recursion_rejections.load(Ordering::SeqCst), 1);

                let routed = crate::dns::routing::RoutingResolver::new(
                    crate::config::dns::DnsRoutingConfig {
                        final_server: "local-reality-doh".into(),
                        ip_strategy: super::super::IpStrategy::Ipv4Only,
                        rules: Vec::new(),
                    },
                    |name| (name == "local-reality-doh").then(|| upstream.clone()),
                )
                .unwrap();
                for sequence in 1..=2 {
                    let location = NetLocation::from_str(
                        &format!("recursive-{sequence}.example:443"),
                        None,
                    )
                    .unwrap();
                    let addresses = routed.resolve_location(&location).await.unwrap_or_else(|error| {
                        panic!(
                            "recursive REALITY DoH lookup failed (vision={vision}, {fingerprint}): {error:?}\n{}",
                            peer.logs()
                        )
                    });
                    assert_eq!(addresses, vec![SocketAddr::from(([192, 0, 2, 42], 443))]);
                }
                assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
                assert_eq!(fixture.recursion_rejections.load(Ordering::SeqCst), 1);
                routed.retire();
                drop(routed);
                drop(upstream);
                drop(peer);
                fixture.wait_closed().await;
            }
        }
    })
    .await
    .expect("local REALITY DoH matrix timed out");
}
