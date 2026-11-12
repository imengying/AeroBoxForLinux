use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn pretty(value: &impl Serialize) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

/// Bounds for the configurable base font size, in points. The range keeps
/// labels readable while still fitting the smallest supported window.
pub const FONT_SIZE_MIN: u32 = 9;
pub const FONT_SIZE_MAX: u32 = 18;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: String,
    /// Base UI font size in points. Row heights and paddings derive from it,
    /// so text and layout scale together instead of only the glyphs.
    pub font_size: u32,
    pub crisp_text: bool,
    pub hardware_acceleration: bool,
    pub core_path: String,
    pub active_subscription: String,
    pub mixed_port: u16,
    pub api_port: u16,
    pub auto_start: bool,
    pub auto_restart: bool,
    pub system_proxy: bool,
    pub routing_mode: String,
    pub ipv6: bool,
    pub tun_enabled: bool,
    pub tun_stack: String,
    pub tun_mtu: u32,
    pub strict_route: bool,
    pub allow_lan: bool,
    pub sniff: bool,
    pub dns_hijack: bool,
    pub dns_cache: bool,
    pub bypass_lan: bool,
    pub auto_detect_ip: bool,
    pub update_subscriptions_on_start: bool,
    pub log_level: String,
    pub test_url: String,
    pub test_timeout: u32,
    pub width: i32,
    pub height: i32,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            font_size: 11,
            crisp_text: true,
            hardware_acceleration: false,
            core_path: String::new(),
            active_subscription: String::new(),
            mixed_port: 2080,
            api_port: 9090,
            auto_start: false,
            auto_restart: false,
            system_proxy: true,
            routing_mode: "rule".into(),
            ipv6: true,
            tun_enabled: false,
            tun_stack: "system".into(),
            tun_mtu: 1500,
            strict_route: true,
            allow_lan: false,
            sniff: true,
            dns_hijack: true,
            dns_cache: true,
            bypass_lan: true,
            auto_detect_ip: true,
            update_subscriptions_on_start: false,
            log_level: "error".into(),
            test_url: "https://www.gstatic.com/generate_204".into(),
            test_timeout: 5000,
            width: 1180,
            height: 800,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.mixed_port > 0 && self.api_port > 0 && self.mixed_port != self.api_port,
            "本地代理与控制端口须为不同的非零端口"
        );
        ensure!(
            (FONT_SIZE_MIN..=FONT_SIZE_MAX).contains(&self.font_size),
            "字体大小须在 {FONT_SIZE_MIN} 到 {FONT_SIZE_MAX} 之间"
        );
        ensure!(
            matches!(self.routing_mode.as_str(), "rule" | "global" | "direct"),
            "无效的出站模式"
        );
        ensure!(
            matches!(self.tun_stack.as_str(), "system" | "gvisor" | "mixed"),
            "无效的 TUN 协议栈"
        );
        ensure!(
            (576..=9000).contains(&self.tun_mtu),
            "MTU 必须在 576 到 9000 之间"
        );
        ensure!(
            !self.tun_enabled || !self.ipv6 || self.tun_mtu >= 1280,
            "IPv6 的 TUN MTU 不能小于 1280"
        );
        ensure!(
            matches!(
                self.log_level.as_str(),
                "trace" | "debug" | "info" | "warn" | "error" | "fatal" | "panic"
            ),
            "无效的日志级别"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct NodeSelection {
    pub subscription_id: String,
    pub node_tag: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub config: Value,
    #[serde(default)]
    pub subscriptions: Vec<String>,
    #[serde(default)]
    pub rulesets: Vec<String>,
    #[serde(default)]
    pub selected_node: Option<NodeSelection>,
}
impl Profile {
    pub fn new(name: &str) -> Self {
        Self {
            id: id(),
            name: name.into(),
            subscriptions: vec![],
            rulesets: vec![],
            selected_node: None,
            config: json!({
                "log":{"level":"error","timestamp":true},
                "dns":{"servers":[{"type":"udp","tag":"dns-local","server":"223.5.5.5"}],"final":"dns-local"},
                "inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":2080}],
                "outbounds":[{"type":"selector","tag":"proxy","outbounds":["direct"],"interrupt_exist_connections":true},{"type":"direct","tag":"direct"}],
                "route":{"auto_detect_interface":true,"default_domain_resolver":"dns-local","rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"},{"ip_is_private":true,"outbound":"direct"}],"final":"proxy"},
                "experimental":{"clash_api":{"external_controller":"127.0.0.1:9090","secret":id(),"default_mode":"rule"},"cache_file":{"enabled":true}}
            }),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub source: String,
    pub auto_update: bool,
    pub update_interval_hours: u32,
    pub nodes: Vec<Value>,
    pub selected_node: Option<String>,
    pub updated: u64,
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub expires: u64,
}
impl Default for Subscription {
    fn default() -> Self {
        Self {
            id: id(),
            name: "新订阅".into(),
            source: String::new(),
            auto_update: true,
            update_interval_hours: 24,
            nodes: vec![],
            selected_node: None,
            updated: 0,
            upload: 0,
            download: 0,
            total: 0,
            expires: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleSet {
    pub id: String,
    pub name: String,
    pub source: String,
    pub binary: bool,
    pub enabled: bool,
    pub action: String,
    pub content: Value,
    pub updated: u64,
    pub update_interval_hours: u32,
}
impl Default for RuleSet {
    fn default() -> Self {
        Self {
            id: id(),
            name: "新规则集".into(),
            source: String::new(),
            binary: false,
            enabled: true,
            action: "direct".into(),
            content: json!({"version":3,"rules":[]}),
            updated: 0,
            update_interval_hours: 24,
        }
    }
}

impl RuleSet {
    pub fn is_remote(&self) -> bool {
        is_online_source(&self.source)
    }
}

pub fn is_online_source(source: &str) -> bool {
    url::Url::parse(source)
        .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
}

pub const BUILTIN_DOMESTIC_ID: &str = "aeb00000-0000-4000-8000-000000000002";
pub const BUILTIN_ADS_ID: &str = "aeb00000-0000-4000-8000-000000000003";
pub const BUILTIN_CHINA_IP_ID: &str = "aeb00000-0000-4000-8000-000000000004";

/// The same three official SagerNet lists used by AeroBox for Android.
pub fn builtin_resources() -> Vec<RuleSet> {
    [
        (
            BUILTIN_CHINA_IP_ID,
            "中国大陆 IP",
            "sing-geoip",
            "geoip-cn.srs",
        ),
        (
            BUILTIN_DOMESTIC_ID,
            "中国大陆域名",
            "sing-geosite",
            "geosite-cn.srs",
        ),
        (
            BUILTIN_ADS_ID,
            "广告拦截",
            "sing-geosite",
            "geosite-category-ads-all.srs",
        ),
    ]
    .into_iter()
    .map(|(id, name, repo, file)| RuleSet {
        id: id.into(),
        name: name.into(),
        binary: true,
        enabled: id != BUILTIN_ADS_ID,
        action: if id == BUILTIN_ADS_ID {
            "reject"
        } else {
            "direct"
        }
        .into(),
        source: format!("https://raw.githubusercontent.com/SagerNet/{repo}/rule-set/{file}"),
        ..RuleSet::default()
    })
    .collect()
}

pub fn builtin_seed(id: &str) -> Option<&'static [u8]> {
    match id {
        BUILTIN_CHINA_IP_ID => Some(include_bytes!("../resources/rules/geoip-cn.srs")),
        BUILTIN_DOMESTIC_ID => Some(include_bytes!("../resources/rules/geosite-cn.srs")),
        BUILTIN_ADS_ID => Some(include_bytes!(
            "../resources/rules/geosite-category-ads-all.srs"
        )),
        _ => None,
    }
}

pub fn add_builtin_resources(state: &mut State) -> Result<usize> {
    let mut added = 0;
    for rule in builtin_resources() {
        if !state.rulesets.iter().any(|r| r.id == rule.id) {
            ensure!(
                !state.rulesets.iter().any(|r| r.name == rule.name),
                "已有同名规则集：{}",
                rule.name
            );
            state.rulesets.push(rule);
            added += 1;
        }
    }
    state.validate()?;
    Ok(added)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema: u32,
    pub settings: Settings,
    pub subscriptions: Vec<Subscription>,
    pub rulesets: Vec<RuleSet>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            schema: 2,
            settings: Settings::default(),
            subscriptions: vec![],
            rulesets: builtin_resources(),
        }
    }
}
impl State {
    pub fn normalize_selection(&mut self) {
        for sub in &mut self.subscriptions {
            if sub.selected_node.as_ref().is_none_or(|tag| {
                !sub.nodes
                    .iter()
                    .any(|n| n["tag"] == *tag && is_connection_node(n))
            }) {
                sub.selected_node = sub
                    .nodes
                    .iter()
                    .find(|n| is_connection_node(n))
                    .and_then(|n| n["tag"].as_str())
                    .map(str::to_owned);
            }
        }
        if !self.settings.active_subscription.is_empty()
            && !self
                .subscriptions
                .iter()
                .any(|s| s.id == self.settings.active_subscription)
        {
            self.settings.active_subscription = self
                .subscriptions
                .iter()
                .find(|s| s.selected_node.is_some())
                .map(|s| s.id.clone())
                .unwrap_or_default();
        }
    }

    /// A transient generation helper; configurations are never stored separately.
    pub fn current_profile(&self) -> Result<Profile> {
        let sub = self
            .subscriptions
            .iter()
            .find(|s| s.id == self.settings.active_subscription)
            .context("请先导入并选择订阅")?;
        let node = sub
            .selected_node
            .as_deref()
            .and_then(|tag| {
                sub.nodes
                    .iter()
                    .find(|n| n["tag"] == tag && is_connection_node(n))
            })
            .or_else(|| sub.nodes.iter().find(|n| is_connection_node(n)))
            .context("当前订阅没有可连接节点，请更新或更换订阅")?;
        let mut profile = Profile::new(&sub.name);
        profile.id = sub.id.clone();
        profile.subscriptions = vec![sub.id.clone()];
        profile.selected_node = Some(NodeSelection {
            subscription_id: sub.id.clone(),
            node_tag: node["tag"].as_str().unwrap().into(),
        });
        profile.rulesets = self
            .rulesets
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.id.clone())
            .collect();
        profile.config["inbounds"][0]["listen_port"] = json!(self.settings.mixed_port);
        profile.config["experimental"]["clash_api"]["external_controller"] =
            json!(format!("127.0.0.1:{}", self.settings.api_port));
        profile.config["experimental"]["clash_api"]["secret"] = json!(sub.id);
        profile.config["dns"]["servers"].as_array_mut().unwrap().push(json!({"type":"https","tag":"dns-remote","server":"1.1.1.1","path":"/dns-query","detour":"proxy"}));
        profile.config["dns"]["final"] = json!("dns-remote");
        let mut routes = vec![];
        let mut dns = vec![];
        // Reject policy precedes domestic direct rules. Mode overrides are
        // inserted by config::apply_settings ahead of all these rules.
        let mut rules: Vec<_> = self.rulesets.iter().filter(|r| r.enabled).collect();
        rules.sort_by_key(|r| r.action != "reject");
        for rule in rules {
            routes.push(if rule.action == "reject" {
                json!({"rule_set":rule.name,"action":"reject"})
            } else {
                json!({"rule_set":rule.name,"action":"route","outbound":rule.action})
            });
            if matches!(rule.id.as_str(), BUILTIN_DOMESTIC_ID | BUILTIN_ADS_ID) {
                dns.push(if rule.action == "reject" { json!({"rule_set":rule.name,"action":"reject"}) } else {
                    json!({"rule_set":rule.name,"action":"route","server":if rule.action == "direct" {"dns-local"} else {"dns-remote"}})
                });
            }
        }
        profile.config["route"]["rules"] = json!(routes);
        profile.config["dns"]["rules"] = json!(dns);
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == 2,
            "不支持的数据格式版本 {}；本版本仅支持全新订阅数据，原文件未更改",
            self.schema
        );
        self.settings.validate()?;
        let mut ids = HashSet::new();
        for (id, name) in self
            .subscriptions
            .iter()
            .map(|v| (&v.id, &v.name))
            .chain(self.rulesets.iter().map(|v| (&v.id, &v.name)))
        {
            ensure!(uuid::Uuid::parse_str(id).is_ok(), "无效的资源 ID");
            ensure!(ids.insert(id), "资源 ID 重复");
            ensure!(!name.trim().is_empty(), "名称不能为空");
        }
        ensure!(
            self.settings.active_subscription.is_empty()
                || self
                    .subscriptions
                    .iter()
                    .any(|s| s.id == self.settings.active_subscription),
            "当前订阅不存在"
        );
        for s in &self.subscriptions {
            ensure!(
                (1..=168).contains(&s.update_interval_hours),
                "订阅更新间隔必须在 1 到 168 小时之间"
            );
            validate_nodes(&s.nodes)?;
            ensure!(
                s.selected_node.as_ref().is_none_or(|tag| s
                    .nodes
                    .iter()
                    .any(|n| n["tag"] == *tag && is_connection_node(n))),
                "订阅所选节点不存在"
            );
        }
        let mut rule_tags = HashSet::new();
        for rule in &self.rulesets {
            ensure!(rule_tags.insert(&rule.name), "规则集名称重复");
            ensure!(
                matches!(rule.action.as_str(), "direct" | "proxy" | "reject"),
                "规则集动作无效"
            );
            ensure!(
                (1..=168).contains(&rule.update_interval_hours),
                "规则集更新间隔须在 1 到 168 小时之间"
            );
            if rule.source.contains("://") {
                let url = url::Url::parse(&rule.source).context("规则集地址无效")?;
                ensure!(
                    matches!(url.scheme(), "https" | "http") && url.host().is_some(),
                    "规则集地址须为 HTTP 或 HTTPS"
                );
            }
        }
        Ok(())
    }
}

pub fn validate_nodes(nodes: &[Value]) -> Result<()> {
    let mut tags = HashSet::new();
    for node in nodes {
        let tag = node["tag"].as_str().context("节点缺少名称")?;
        ensure!(
            !tag.is_empty() && tags.insert(tag),
            "节点名称为空或重复: {tag}"
        );
        ensure!(node["type"].is_string(), "节点缺少协议");
    }
    Ok(())
}

/// Only dialable subscription outbounds belong in the node picker. Helper
/// groups and terminal routing actions stay available to generated references.
pub fn is_connection_node(node: &Value) -> bool {
    let kind = node["type"].as_str().unwrap_or("");
    if matches!(
        kind,
        "selector" | "urltest" | "direct" | "block" | "dns" | "reject" | "hysteria-realm"
    ) {
        return false;
    }
    // Endpoint links (WireGuard and friends) have no top-level server; they
    // carry one or more peers instead.
    if matches!(
        kind,
        "wireguard" | "tailscale" | "openvpn-client" | "openvpn-server" | "openconnect"
    ) {
        return node["peers"].as_array().is_some_and(|peers| {
            peers.iter().any(|peer| {
                peer["address"]
                    .as_str()
                    .is_some_and(|host| !host.trim().is_empty())
                    && peer["port"]
                        .as_u64()
                        .is_some_and(|port| (1..=65535).contains(&port))
            })
        }) || kind == "tailscale";
    }
    node["server"]
        .as_str()
        .is_some_and(|host| !host.trim().is_empty())
        && node["server_port"]
            .as_u64()
            .is_some_and(|port| (1..=65535).contains(&port))
}

pub struct Store {
    pub dir: PathBuf,
    pub state: State,
}
impl Store {
    /// Explicit user action only: archive the entire old state without parsing
    /// or migrating it. Restore it if creating the new state fails.
    pub fn reset(dir: Option<PathBuf>) -> Result<(Self, Option<PathBuf>)> {
        let dir = match dir {
            Some(dir) => dir,
            None => config_home()?.join("AeroBoxForLinux"),
        };
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let path = dir.join("state.json");
        let backup = path
            .exists()
            .then(|| dir.join(format!("state.backup-{}-{}.json", now(), id())));
        if let Some(backup) = &backup {
            fs::rename(&path, backup)?;
        }
        match Self::open(Some(dir)) {
            Ok(store) => Ok((store, backup)),
            Err(error) => {
                if let Some(backup) = backup {
                    fs::rename(backup, path).context("创建新数据失败且无法恢复旧文件")?;
                }
                Err(error)
            }
        }
    }

    pub fn open(dir: Option<PathBuf>) -> Result<Self> {
        let dir = match dir {
            Some(p) => p,
            None => config_home()?.join("AeroBoxForLinux"),
        };
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let path = dir.join("state.json");
        let state = if path.exists() {
            let bytes = fs::read(&path)?;
            let value: Value =
                serde_json::from_slice(&bytes).context("无法读取 AeroBox 数据；原文件未更改")?;
            ensure!(
                value["schema"] == 2 && value.get("profiles").is_none(),
                "不支持旧版数据结构；请使用新的数据目录，原文件未更改"
            );
            // The percentage text scale was replaced by an absolute font size.
            // Silently defaulting it would leave every existing install at a
            // size the user never picked, so say so instead of guessing.
            ensure!(
                value["settings"].get("text_scale").is_none(),
                "旧版的「文字大小（%）」设置已改为「字体大小」；请删除 {} 后重新打开，原文件未更改",
                path.display()
            );
            serde_json::from_value::<State>(value).context("无法读取 AeroBox 数据；原文件未更改")?
        } else {
            State::default()
        };
        state.validate()?;
        if !path.exists() {
            atomic_write(&path, &serde_json::to_vec_pretty(&state)?, 0o600)?;
        }
        Ok(Self { dir, state })
    }
    // Commit only after serialization and atomic replacement have succeeded.
    pub fn update(&mut self, edit: impl FnOnce(&mut State) -> Result<()>) -> Result<()> {
        let mut next = self.state.clone();
        edit(&mut next)?;
        next.normalize_selection();
        next.validate()?;
        atomic_write(
            &self.dir.join("state.json"),
            &serde_json::to_vec_pretty(&next)?,
            0o600,
        )?;
        self.state = next;
        Ok(())
    }
    pub fn rule_path(&self, r: &RuleSet) -> PathBuf {
        self.dir.join("rules").join(format!(
            "{}.{}",
            r.id,
            if r.binary { "srs" } else { "json" }
        ))
    }
}
pub fn config_home() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME").filter(|p| Path::new(p).is_absolute()) {
        return Ok(path.into());
    };
    Ok(PathBuf::from(std::env::var_os("HOME").context("HOME 未设置")?).join(".config"))
}
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("文件没有父目录")?;
    fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}
pub fn remove_resource(state: &mut State, kind: &str, id: &str) -> Result<()> {
    match kind {
        "subscriptions" => {
            state.subscriptions.retain(|s| s.id != id);
            state.normalize_selection();
        }
        "rulesets" => {
            state.rulesets.retain(|s| s.id != id);
        }
        _ => bail!("未知资源类型"),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_reset_archives_legacy_state_without_touching_the_core() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = br#"{"schema":1,"profiles":[]}"#;
        fs::write(dir.path().join("state.json"), legacy).unwrap();
        fs::create_dir(dir.path().join("core")).unwrap();
        fs::write(dir.path().join("core/sing-box"), b"core fixture").unwrap();
        let (store, backup) = Store::reset(Some(dir.path().into())).unwrap();
        assert_eq!(store.state.schema, 2);
        assert!(store.state.subscriptions.is_empty());
        assert_eq!(fs::read(backup.unwrap()).unwrap(), legacy);
        assert_eq!(
            fs::read(dir.path().join("core/sing-box")).unwrap(),
            b"core fixture"
        );
    }
    #[test]
    fn defaults_are_single_subscription_and_enable_desktop_proxy() {
        let state = State::default();
        assert_eq!(state.schema, 2);
        assert!(state.settings.system_proxy);
        assert_eq!(state.settings.log_level, "error");
        assert!(!state.settings.hardware_acceleration);
        assert!(state.current_profile().is_err());
        let value = serde_json::to_value(&state).unwrap();
        assert!(value.get("profiles").is_none());
        assert!(value["settings"].get("active_profile").is_none());
        for level in ["info", "debug", "warn", "error"] {
            let saved: Settings = serde_json::from_value(
                json!({"log_level":level,"hardware_acceleration":true,"system_proxy":false}),
            )
            .unwrap();
            assert_eq!(saved.log_level, level);
            assert!(saved.hardware_acceleration);
            assert!(!saved.system_proxy);
        }
    }
    #[test]
    fn android_rule_sources_have_real_binary_seeds() {
        let state = State::default();
        assert_eq!(state.rulesets.len(), 3);
        for rule in &state.rulesets {
            assert!(rule.binary && rule.is_remote());
            assert!(rule.source.contains("/SagerNet/sing-"));
            let seed = builtin_seed(&rule.id).unwrap();
            assert!(seed.starts_with(b"SRS") && seed.len() > 1000);
        }
    }
    #[test]
    fn legacy_and_corrupt_data_are_rejected_without_overwriting() {
        for original in [
            br#"{"schema":1,"settings":{},"profiles":[],"subscriptions":[],"rulesets":[]}"#
                .as_slice(),
            b"not-json",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("state.json");
            fs::write(&path, original).unwrap();
            assert!(Store::open(Some(dir.path().into())).is_err());
            assert_eq!(fs::read(path).unwrap(), original);
        }
    }
    #[test]
    fn failed_update_leaves_state_and_disk_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(Some(dir.path().into())).unwrap();
        let original = fs::read(dir.path().join("state.json")).unwrap();
        assert!(
            store
                .update(|s| {
                    s.settings.mixed_port = s.settings.api_port;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(fs::read(dir.path().join("state.json")).unwrap(), original);
    }
    #[test]
    fn removed_nodes_fall_back_within_subscription_and_deletion_selects_remaining() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(Some(dir.path().into())).unwrap();
        let sub = Subscription {
            nodes: vec![
                json!({"type":"socks","tag":"first","server":"localhost","server_port":1080}),
                json!({"type":"socks","tag":"second","server":"localhost","server_port":1081}),
            ],
            selected_node: Some("second".into()),
            ..Subscription::default()
        };
        let id = sub.id.clone();
        store
            .update(|s| {
                s.settings.active_subscription = id.clone();
                s.subscriptions.push(sub);
                Ok(())
            })
            .unwrap();
        store
            .update(|s| {
                s.subscriptions[0].nodes.pop();
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store.state.subscriptions[0].selected_node.as_deref(),
            Some("first")
        );
        store
            .update(|s| remove_resource(s, "subscriptions", &id))
            .unwrap();
        assert!(store.state.settings.active_subscription.is_empty());
        assert!(store.state.current_profile().is_err());
    }
}
