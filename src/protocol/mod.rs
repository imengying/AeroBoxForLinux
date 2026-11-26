//! Strict conversion of AeroBox Android node settings to the Rust runtime.
//! Unrecognized options return a field path, never a silent security downgrade.
#![forbid(unsafe_code)]
mod naive;
mod outbound;
mod quic;
pub(crate) mod ss_plugin;
mod tls;
use anyhow::Context;
pub use outbound::convert_outbound;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashSet, VecDeque},
    sync::{Mutex, OnceLock},
};
#[derive(Debug, thiserror::Error)]
#[error("{path}: {message}")]
pub struct Error {
    pub path: String,
    pub message: String,
}
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn error(path: impl Into<String>, message: impl Into<String>) -> Error {
    Error {
        path: path.into(),
        message: message.into(),
    }
}
pub(crate) struct Fields {
    pub path: String,
    pub values: Map<String, Value>,
}
impl Fields {
    pub fn new(value: Value, path: &str) -> Result<Self> {
        let Value::Object(values) = value else {
            return Err(error(path, "expected an object"));
        };
        Ok(Self {
            path: path.into(),
            values,
        })
    }
    pub fn take(&mut self, key: &str) -> Option<Value> {
        self.values.remove(key)
    }
    pub fn required(&mut self, key: &str) -> Result<Value> {
        self.take(key)
            .ok_or_else(|| error(format!("{}.{}", self.path, key), "required field"))
    }
    pub fn string(&mut self, key: &str) -> Result<Option<String>> {
        self.take(key)
            .map(|v| {
                v.as_str()
                    .map(String::from)
                    .ok_or_else(|| error(format!("{}.{}", self.path, key), "expected a string"))
            })
            .transpose()
    }
    pub fn text(&mut self, key: &str) -> Result<String> {
        self.string(key)?
            .ok_or_else(|| error(format!("{}.{}", self.path, key), "required string"))
    }
    pub fn boolean(&mut self, key: &str, default: bool) -> Result<bool> {
        self.take(key).map_or(Ok(default), |v| {
            v.as_bool()
                .ok_or_else(|| error(format!("{}.{}", self.path, key), "expected a boolean"))
        })
    }
    pub fn default_only(&mut self, key: &str, allowed: &[Value]) -> Result<()> {
        if let Some(v) = self.take(key)
            && !allowed.contains(&v)
        {
            return Err(error(
                format!("{}.{}", self.path, key),
                "this non-default option is not implemented by the Rust backend",
            ));
        }
        Ok(())
    }
    pub fn copy(&mut self, key: &str, output: &mut Value, to: &str) {
        if let Some(value) = self.take(key) {
            output[to] = value;
        }
    }
    pub fn finish(self) -> Result<()> {
        if let Some(key) = self.values.keys().next() {
            Err(error(
                format!("{}.{}", self.path, key),
                "unrecognized or not yet implemented option",
            ))
        } else {
            Ok(())
        }
    }
}
pub(crate) fn address(host: &str, port: u64, path: &str) -> Result<String> {
    if host.is_empty()
        || host.chars().any(char::is_whitespace)
        || host.contains(['/', '\\', '@', '#', '?'])
        || !(1..=65535).contains(&port)
    {
        return Err(error(path, "invalid server address or port"));
    }
    Ok(if host.contains(':') {
        format!("[{}]:{port}", host.trim_matches(['[', ']']))
    } else {
        format!("{host}:{port}")
    })
}

/// Hysteria2 hopping ports supersede its single port. Use the same endpoint
/// test for import, selection and runtime conversion.
pub(crate) fn server_port(node: &Value) -> Option<u16> {
    let port = if node["type"] == "hysteria2"
        && let Some(ports) = node.get("server_ports")
        && ports != ""
        && ports.as_array().is_none_or(|ports| !ports.is_empty())
    {
        ports
            .as_array()
            .map_or(Some(ports), |ports| ports.first())?
            .as_str()?
            .split(':')
            .next()?
            .parse()
            .ok()?
    } else {
        u16::try_from(node["server_port"].as_u64()?).ok()?
    };
    (port != 0).then_some(port)
}

pub(super) fn strings(value: Value, path: &str) -> Result<Vec<String>> {
    match value {
        Value::String(value) => Ok(if value.is_empty() {
            vec![]
        } else {
            vec![value]
        }),
        Value::Array(values) => values
            .into_iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| error(path, "expected text or an array of text"))
            })
            .collect(),
        _ => Err(error(path, "expected text or an array of text")),
    }
}
pub(crate) fn seconds(value: Value, path: &str) -> Result<u64> {
    let text = value
        .as_str()
        .ok_or_else(|| error(path, "duration must be a string"))?;
    let (number, factor) = if let Some(n) = text.strip_suffix("ms") {
        (n, 0)
    } else if let Some(n) = text.strip_suffix('s') {
        (n, 1)
    } else if let Some(n) = text.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = text.strip_suffix('h') {
        (n, 3600)
    } else {
        return Err(error(path, "expected duration with ms/s/m/h suffix"));
    };
    let count: u64 = number
        .parse()
        .map_err(|_| error(path, "duration must be a non-negative integer"))?;
    if factor == 0 {
        if !count.is_multiple_of(1000) {
            return Err(error(path, "this option requires whole seconds"));
        }
        return Ok(count / 1000);
    }
    count
        .checked_mul(factor)
        .ok_or_else(|| error(path, "duration overflow"))
}

/// Validate external subscription fields before they can become stored nodes.
pub fn validate(node: &Value) -> anyhow::Result<()> {
    anyhow::ensure!(
        node.get("domain_resolver").is_none(),
        "节点域名解析由设置中的直连 DNS 控制，不支持单节点 domain_resolver"
    );
    let kind = node["type"].as_str().unwrap_or_default();
    anyhow::ensure!(
        [
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "anytls",
            "hysteria2",
            "tuic",
            "naive",
            "socks",
            "http"
        ]
        .contains(&kind),
        "不支持的节点协议：{kind}"
    );
    // State validation runs on ordinary settings saves too. Cache only pure
    // static successes, keyed by every source field; never retain credential
    // copies or let cached results replace startup's file/connection checks.
    let key: [u8; 32] = Sha256::digest(serde_json::to_vec(node)?).into();
    static CACHE: OnceLock<Mutex<ValidationCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(ValidationCache::default()));
    if cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .known
        .contains(&key)
    {
        return Ok(());
    }
    let name = node["tag"].as_str().unwrap_or("未命名节点");
    let value = convert_outbound(node.clone(), &format!("节点「{name}」"))?;
    let config: shoes::config::Config =
        serde_json::from_value(value).with_context(|| format!("节点「{name}」参数无效"))?;
    let shoes::config::Config::ClientConfigGroup(group) = config else {
        anyhow::bail!("节点「{name}」未转换成客户端配置");
    };
    let mut members = group.client_chains.into_vec().into_iter();
    let Some(shoes::config::ClientGroupMember::Client(shoes::config::ConfigSelection::Config(
        client,
    ))) = members.next()
    else {
        anyhow::bail!("节点「{name}」必须转换成一个独立客户端");
    };
    anyhow::ensure!(members.next().is_none(), "节点「{name}」包含多个客户端");
    shoes::config::validate_client_config(client)
        .with_context(|| format!("节点「{name}」参数无效"))?;
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(key);
    Ok(())
}

#[derive(Default)]
struct ValidationCache {
    known: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl ValidationCache {
    fn insert(&mut self, key: [u8; 32]) {
        if self.known.insert(key) {
            self.order.push_back(key);
            if self.order.len() > 2048 {
                self.known.remove(&self.order.pop_front().unwrap());
            }
        }
    }
}
