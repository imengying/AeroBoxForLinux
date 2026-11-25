//! Isolated application service for scripts/bench-network.py. The load generator
//! and independent server run in other processes, outside measured CPU/memory.
use aerobox_for_linux::{
    engine::Service,
    model::{RuleSet, Store, Subscription},
};
use anyhow::{Context, Result, bail};
use serde_json::json;
use std::{
    io::{self, BufRead, Write},
    net::TcpListener,
};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let case = args.first().map(String::as_str).unwrap_or("direct");
    let dir = tempfile::tempdir()?;
    let mut store = Store::open(Some(dir.path().into()))?;
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    store.update(|state| {
        state.settings.system_proxy = false;
        state.settings.ipv6 = false;
        state.settings.bypass_lan = false;
        state.settings.sniff = false;
        state.settings.dns_cache = false;
        state.settings.direct_dns = "udp://127.0.0.1:9".into();
        state.settings.remote_dns = "tcp://127.0.0.1:9".into();
        state.settings.routing_mode = if case == "direct" { "rule" } else { "global" }.into();
        state.rulesets.clear();
        if case == "direct" {
            state.rulesets.push(RuleSet {
                name: "benchmark loopback".into(),
                action: "direct".into(),
                content: json!({"version":3,"rules":[{"ip_cidr":["127.0.0.1/32"]}]}),
                ..Default::default()
            });
        }
        Ok(())
    })?;
    let service = Service::with_local_port(store, port.try_into()?);
    let node = match case {
        "direct" => json!({"type":"socks", "tag":"unused", "server":"127.0.0.1", "server_port":9}),
        "ss-aes128" => json!({"type":"shadowsocks", "tag":"benchmark", "server":"127.0.0.1",
            "server_port":args.get(1).context("SS peer port is required")?.parse::<u16>()?,
            "method":"aes-128-gcm", "password":"aerobox-loopback-benchmark"}),
        _ => bail!("unknown benchmark case: {case}"),
    };
    service.import_subscription(Subscription {
        name: "benchmark".into(),
        nodes: vec![node],
        ..Default::default()
    })?;
    service.start()?;
    println!(
        "{}",
        json!({"port":port, "case":case, "debug":cfg!(debug_assertions), "version":env!("CARGO_PKG_VERSION")})
    );
    io::stdout().flush()?;
    if let Some(line) = io::stdin().lock().lines().next()
        && line? != "quit"
    {
        bail!("unknown benchmark command");
    }
    service.shutdown()?;
    Ok(())
}
