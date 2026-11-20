//! The application's in-process proxy runtime. No executable or HTTP controller.
use crate::{
    model::{self, NodeSelection, Settings, State},
    protocol,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    fs,
    path::Path,
    sync::{Arc, Mutex, OnceLock, Weak},
};

pub(crate) use shoes::embedding::EmbeddedCore;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Node {
    pub tag: String,
    pub source: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Prepared {
    pub config: Value,
    pub nodes: HashMap<NodeSelection, Node>,
    pub selected_node: Option<NodeSelection>,
    pub settings: Settings,
}

pub(crate) fn executor() -> &'static tokio::runtime::Runtime {
    static EXECUTOR: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    EXECUTOR.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 4)))
            .thread_name("aerobox-network")
            .enable_all()
            .build()
            .expect("network executor")
    })
}

type LogBuffer = Mutex<VecDeque<String>>;
static LOGS: Mutex<Option<Weak<LogBuffer>>> = Mutex::new(None);
struct Logger;
impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }
    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if let Some(logs) = LOGS.lock().unwrap().as_ref().and_then(Weak::upgrade) {
            let mut logs = logs.lock().unwrap();
            if logs.len() >= 2000 {
                logs.pop_front();
            }
            logs.push_back(format!("{} {}", record.level(), record.args()));
        }
    }
    fn flush(&self) {}
}
pub(crate) fn configure(settings: &Settings, logs: &Arc<LogBuffer>) {
    static LOGGER: OnceLock<()> = OnceLock::new();
    LOGGER.get_or_init(|| {
        let _ = log::set_logger(&Logger);
    });
    *LOGS.lock().unwrap() = Some(Arc::downgrade(logs));
    log::set_max_level(
        settings
            .log_level
            .parse()
            .unwrap_or(log::LevelFilter::Error),
    );
    shoes::embedding::set_dns_cache(settings.dns_cache);
}

pub(crate) fn parse(config: &Value) -> Result<Vec<shoes::config::Config>> {
    serde_json::from_value(config.clone()).context("原生运行配置无效")
}

const PRIVATE_NETWORKS: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

pub(crate) fn prepare(state: &State, dir: &Path) -> Result<Prepared> {
    state.validate()?;
    let settings = &state.settings;
    let sub = state
        .subscriptions
        .iter()
        .find(|s| s.id == settings.active_subscription)
        .context("请先导入并选择订阅")?;
    let mut entries = vec![];
    let mut nodes = HashMap::new();
    let mut members = vec![];
    let mut selected_node = None;
    for (i, source) in model::selectable_nodes(&sub.nodes).enumerate() {
        let name = source["tag"].as_str().context("节点缺少名称")?;
        let key = NodeSelection {
            subscription_id: sub.id.clone(),
            node_tag: name.into(),
        };
        let tag = format!("node-{i}");
        let mut value = source.clone();
        value["tag"] = tag.clone().into();
        value["domain_resolver"] = json!({"server":"dns-direct", "ip_strategy":strategy(settings)});
        entries.push(protocol::convert_outbound(
            value,
            &format!("节点「{name}」"),
        )?);
        members.push(json!({"chain":[tag]}));
        if sub.selected_node.as_deref() == Some(name) {
            selected_node = Some(key.clone());
        }
        nodes.insert(
            key,
            Node {
                tag,
                source: source.clone(),
            },
        );
    }
    let selected = selected_node
        .as_ref()
        .and_then(|key| nodes.get(key))
        .context("当前订阅没有选中的可用节点")?;
    entries.push(json!({"client_group":"proxy", "type":"selector", "default":selected.tag, "client_chains":members}));

    let direct = dns_endpoint(&settings.direct_dns)?;
    let remote = dns_endpoint(&settings.remote_dns)?;
    let mut direct_dns = json!({"url":direct, "ip_strategy":strategy(settings)});
    // Bootstrap is always a real underlay resolver; it never refers back to the proxy.
    if crate::config::parse_dns_server(&settings.direct_dns)?
        .server
        .parse::<std::net::IpAddr>()
        .is_err()
    {
        direct_dns["bootstrap_url"] = "system".into();
    }
    let remote_chain = if settings.routing_mode == "direct" {
        "direct"
    } else {
        "proxy"
    };
    entries.push(json!({"dns_group":"dns-direct", "dns_servers":[direct_dns]}));
    entries.push(json!({"dns_group":"dns-remote", "dns_servers":[{"url":remote,"client_chain":remote_chain,"bootstrap_url":"dns-direct","ip_strategy":strategy(settings)}]}));

    let mut rules = vec![];
    let mut dns_rules = vec![];
    if !settings.ipv6 {
        rules.push(json!({"conditions":{"ip_cidr":["::/0"]},"no_resolve":true,"action":"block"}));
    }
    if settings.routing_mode == "rule" {
        let mut enabled: Vec<_> = state.rulesets.iter().filter(|r| r.enabled).collect();
        enabled.sort_by_key(|r| r.action != "reject");
        for rule in enabled {
            let path = rule_file(rule, dir)?;
            let mut source =
                json!({"path":path,"format":if rule.binary {"srs"} else {"singbox_json"}});
            if rule.is_remote() {
                source["url"] = rule.source.clone().into();
                source["update_interval"] = format!("{}m", rule.update_interval_minutes).into();
                source["download"] =
                    json!({"client_chain":remote_chain,"bootstrap_url":"dns-direct"});
            }
            entries.push(json!({"rule_source_group":rule.id, "rules":[source]}));
            let conditions = json!({"rule_source_group":rule.id});
            let mut route = json!({"conditions":conditions,"action":if rule.action == "reject" {"block"} else {"allow"}});
            if rule.action != "reject" {
                route["client_chain"] = rule.action.clone().into();
            }
            rules.push(route);
            if matches!(
                rule.id.as_str(),
                model::BUILTIN_DOMESTIC_ID | model::BUILTIN_ADS_ID
            ) {
                dns_rules.push(if rule.action == "reject" { json!({"conditions":conditions,"rcode":3}) }
                    else { json!({"conditions":conditions,"server":if rule.action == "direct" {"dns-direct"} else {"dns-remote"}}) });
            }
        }
        if settings.bypass_lan {
            // Local destinations take precedence over downloaded country rules.
            rules.insert(usize::from(!settings.ipv6), json!({"conditions":{"ip_cidr":PRIVATE_NETWORKS},"action":"allow","client_chain":"direct"}));
        }
    }
    rules.push(
        json!({"conditions":{"any_destination":true},"action":"allow","client_chain":remote_chain}),
    );
    entries.push(json!({"dns_group":"dns-policy","routing":{"final_server":if settings.routing_mode == "direct" {"dns-direct"} else {"dns-remote"},"ip_strategy":strategy(settings),"rules":dns_rules}}));
    entries.push(json!({"global_settings":{"max_connections":4096,"max_streams":8192,"quic_memory_bytes":134217728,"quic_socket_buffer":1048576,"reload_grace_secs":0,"default_dns":{"servers":"dns-policy"},"rule_cache_dir":dir.join("rules/cache")}}));
    let host = if settings.allow_lan {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    entries.push(json!({"name":"mixed-in","address":format!("{host}:{}",settings.mixed_port),"protocol":{"type":"mixed","udp_enabled":true},"sniff":settings.sniff,"dns_hijack":settings.dns_hijack,"rules":rules}));
    if settings.tun_enabled {
        let mut addresses = vec!["172.19.0.1/30"];
        if settings.ipv6 {
            addresses.push("fdfe:dcba:9876::1/126");
        }
        entries.push(json!({"name":"tun-in","device_name":"aerobox0","addresses":addresses,"auto_route":true,"route_address":if settings.ipv6 {vec!["0.0.0.0/0","::/0"]} else {vec!["0.0.0.0/0"]},"auto_dns":false,"bootstrap_dns":["223.5.5.5:53","1.1.1.1:53"],"mtu":settings.tun_mtu,"tcp_enabled":true,"udp_enabled":true,"icmp_enabled":true,"sniff":settings.sniff,"dns_hijack":settings.dns_hijack,"rules":rules}));
    }
    let config = Value::Array(entries);
    parse(&config)?;
    Ok(Prepared {
        config,
        nodes,
        selected_node,
        settings: settings.clone(),
    })
}

fn strategy(settings: &Settings) -> &'static str {
    if settings.ipv6 {
        "ipv4_then_ipv6"
    } else {
        "ipv4_only"
    }
}
fn dns_endpoint(address: &str) -> Result<String> {
    let spec = crate::config::parse_dns_server(address)?;
    let host = if spec.server.contains(':') {
        format!("[{}]", spec.server)
    } else {
        spec.server
    };
    Ok(format!(
        "{}://{host}:{}{}",
        spec.kind,
        spec.port,
        spec.path.unwrap_or_default()
    ))
}

fn rule_file(rule: &model::RuleSet, dir: &Path) -> Result<std::path::PathBuf> {
    let cache = dir.join("rules").join(format!(
        "{}.{}",
        rule.id,
        if rule.binary { "srs" } else { "json" }
    ));
    let bytes = if !rule.binary {
        // A newly added online rule starts with an empty editor placeholder.
        // It must be fetched before running, while an explicitly downloaded
        // empty rule set remains a valid cached result.
        if rule.is_remote()
            && rule.updated == 0
            && rule.content["rules"].as_array().is_some_and(Vec::is_empty)
        {
            vec![]
        } else {
            serde_json::to_vec(&rule.content)?
        }
    } else if cache.exists() {
        fs::read(&cache)?
    } else if let Some(seed) = model::builtin_seed(&rule.id) {
        seed.to_vec()
    } else if !rule.source.is_empty() && !rule.is_remote() {
        fs::read(&rule.source)?
    } else {
        vec![]
    };
    // Immutable files let a failed edit restore precisely the previous rules.
    let digest = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let path = if rule.is_remote() {
        remote_rule_path(rule, dir)
    } else {
        dir.join("rules/runtime").join(format!(
            "{}-{digest}.{}",
            rule.id,
            if rule.binary { "srs" } else { "json" }
        ))
    };
    if !bytes.is_empty() && !path.exists() {
        model::atomic_write(&path, &bytes, 0o600)?;
    }
    ensure!(
        !bytes.is_empty() || rule.is_remote(),
        "规则集「{}」没有数据",
        rule.name
    );
    Ok(path)
}

pub(crate) fn remote_rule_path(rule: &model::RuleSet, dir: &Path) -> std::path::PathBuf {
    let digest = Sha256::digest(format!("{}:{}", rule.source, rule.updated).as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    dir.join("rules/cache").join(format!(
        "{}-{digest}.{}",
        rule.id,
        if rule.binary { "srs" } else { "json" }
    ))
}
