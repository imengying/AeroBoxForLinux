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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: String,
    pub text_scale: u32,
    pub crisp_text: bool,
    pub hardware_acceleration: bool,
    pub core_path: String,
    pub active_profile: String,
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
    pub block_ads: bool,
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
            text_scale: 120,
            crisp_text: true,
            hardware_acceleration: false,
            core_path: String::new(),
            active_profile: String::new(),
            auto_start: false,
            auto_restart: false,
            system_proxy: false,
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
            block_ads: false,
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
            (100..=150).contains(&self.text_scale),
            "文字大小须在 100% 到 150% 之间"
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub config: Value,
    #[serde(default)]
    pub subscriptions: Vec<String>,
    #[serde(default)]
    pub rulesets: Vec<String>,
}
impl Profile {
    pub fn new(name: &str) -> Self {
        Self {
            id: id(),
            name: name.into(),
            subscriptions: vec![],
            rulesets: vec![],
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

pub const BUILTIN_LAN_ID: &str = "aeb00000-0000-4000-8000-000000000001";
pub const BUILTIN_DOMESTIC_ID: &str = "aeb00000-0000-4000-8000-000000000002";
pub const BUILTIN_ADS_ID: &str = "aeb00000-0000-4000-8000-000000000003";
pub const BUILTIN_CHINA_IP_ID: &str = "aeb00000-0000-4000-8000-000000000004";

/// Maintained online lists. Small initial rules let the first connection start
/// before the core refreshes and caches the full online source.
pub fn builtin_resources() -> (Vec<Profile>, Vec<RuleSet>) {
    let rulesets = vec![
        RuleSet {
            id: BUILTIN_LAN_ID.into(),
            name: "局域网".into(),
            source: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/private.json".into(),
            content: json!({"version":3,"rules":[{"ip_cidr":["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16","100.64.0.0/10","::1/128","fc00::/7","fe80::/10"]},{"domain_suffix":["localhost","local","lan"]}]}),
            ..RuleSet::default()
        },
        RuleSet {
            id: BUILTIN_DOMESTIC_ID.into(),
            name: "中国大陆域名".into(),
            source: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.json".into(),
            content: json!({"version":3,"rules":[{"domain_suffix":["baidu.com","qq.com","tencent.com","aliyun.com","alipay.com","taobao.com","tmall.com","jd.com","bilibili.com","163.com","126.com","sina.com.cn","weibo.com","zhihu.com","douban.com","mi.com"]}]}),
            ..RuleSet::default()
        },
        RuleSet {
            id: BUILTIN_ADS_ID.into(),
            name: "广告拦截".into(),
            source: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ads-all.json".into(),
            content: json!({"version":3,"rules":[{"domain_suffix":["doubleclick.net","googlesyndication.com","googleadservices.com","adservice.google.com","ad.qq.com","pos.baidu.com","cpro.baidu.com"]}]}),
            ..RuleSet::default()
        },
        RuleSet {
            id: BUILTIN_CHINA_IP_ID.into(),
            name: "中国大陆 IP".into(),
            source: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.json".into(),
            ..RuleSet::default()
        },
    ];
    let mut profiles = vec![];
    for (index, name) in ["智能分流", "代理优先", "直连网络"].iter().enumerate() {
        let mut profile = Profile::new(name);
        profile.id = format!("aeb10000-0000-4000-8000-{:012}", index + 1);
        profile.rulesets = rulesets.iter().map(|r| r.id.clone()).collect();
        profile.config["route"]["rules"] = json!([]);
        if index == 0 {
            profile.config["route"]["rules"] = json!([
                {"rule_set":["中国大陆域名", "中国大陆 IP"],"action":"route","outbound":"direct"}
            ]);
            profile.config["dns"]["rules"] = json!([
                {"rule_set":"中国大陆域名","action":"route","server":"dns-local"}
            ]);
        }
        if index == 2 {
            profile.config["route"]["final"] = json!("direct");
        } else {
            profile.config["dns"]["servers"].as_array_mut().unwrap().push(json!({
                "type":"https","tag":"dns-remote","server":"1.1.1.1","path":"/dns-query","detour":"proxy"
            }));
            profile.config["dns"]["final"] = json!("dns-remote");
        }
        profiles.push(profile);
    }
    (profiles, rulesets)
}

/// Add missing presets while preserving existing edits, selection and IDs.
pub fn add_builtin_resources(state: &mut State) -> Result<usize> {
    let (mut profiles, rulesets) = builtin_resources();
    let mut added = 0;
    for rule in rulesets {
        if let Some(existing) = state
            .rulesets
            .iter()
            .find(|r| r.id == rule.id || r.name == rule.name)
        {
            for profile in &mut profiles {
                for id in &mut profile.rulesets {
                    if *id == rule.id {
                        *id = existing.id.clone();
                    }
                }
                replace_rule_tag(&mut profile.config, &rule.name, &existing.name);
            }
        } else {
            state.rulesets.push(rule);
            added += 1;
        }
    }
    for mut profile in profiles {
        if state.profiles.iter().any(|p| p.id == profile.id) {
            continue;
        }
        if state.profiles.iter().any(|p| p.name == profile.name) {
            profile.name.push_str("（内置）");
        }
        state.profiles.push(profile);
        added += 1;
    }
    if state.settings.active_profile.is_empty() {
        state.settings.active_profile = state
            .profiles
            .first()
            .map(|p| p.id.clone())
            .unwrap_or_default();
    }
    state.validate()?;
    Ok(added)
}

/// Explicitly connect built-in lists to their maintained sources. Custom lists,
/// names and contents are kept; the seed remains available for the first start.
pub fn use_online_builtin_rules(state: &mut State) -> Result<()> {
    for builtin in builtin_resources().1 {
        if let Some(rule) = state.rulesets.iter_mut().find(|r| r.id == builtin.id) {
            rule.source = builtin.source;
            rule.binary = false;
            rule.update_interval_hours = 24;
        } else if !state.rulesets.iter().any(|r| r.name == builtin.name) {
            state.rulesets.push(builtin);
        }
    }
    state.validate()
}

fn replace_rule_tag(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if key == "rule_set" {
                    if child.as_str() == Some(from) {
                        *child = json!(to);
                    } else if let Some(tags) = child.as_array_mut() {
                        for tag in tags {
                            if tag.as_str() == Some(from) {
                                *tag = json!(to);
                            }
                        }
                    }
                } else {
                    replace_rule_tag(child, from, to);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                replace_rule_tag(item, from, to);
            }
        }
        _ => {}
    }
}

pub fn rename_rule_references(state: &mut State, id: &str, from: &str, to: &str) {
    for profile in &mut state.profiles {
        if profile.rulesets.iter().any(|linked| linked == id) {
            replace_rule_tag(&mut profile.config, from, to);
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema: u32,
    pub settings: Settings,
    pub profiles: Vec<Profile>,
    pub subscriptions: Vec<Subscription>,
    pub rulesets: Vec<RuleSet>,
}
impl Default for State {
    fn default() -> Self {
        let (profiles, rulesets) = builtin_resources();
        Self {
            schema: 1,
            settings: Settings {
                active_profile: profiles[0].id.clone(),
                ..Settings::default()
            },
            profiles,
            subscriptions: vec![],
            rulesets,
        }
    }
}
impl State {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == 1, "不支持的数据格式版本 {}", self.schema);
        self.settings.validate()?;
        let mut ids = HashSet::new();
        for (id, name) in self
            .profiles
            .iter()
            .map(|v| (&v.id, &v.name))
            .chain(self.subscriptions.iter().map(|v| (&v.id, &v.name)))
            .chain(self.rulesets.iter().map(|v| (&v.id, &v.name)))
        {
            ensure!(uuid::Uuid::parse_str(id).is_ok(), "无效的资源 ID");
            ensure!(ids.insert(id), "资源 ID 重复");
            ensure!(!name.trim().is_empty(), "名称不能为空");
        }
        for p in &self.profiles {
            ensure!(p.config.is_object(), "配置必须是 JSON 对象");
            for id in &p.subscriptions {
                ensure!(
                    self.subscriptions.iter().any(|s| &s.id == id),
                    "配置「{}」引用的订阅不存在",
                    p.name
                )
            }
            for id in &p.rulesets {
                ensure!(
                    self.rulesets.iter().any(|s| &s.id == id),
                    "配置「{}」引用的规则集不存在",
                    p.name
                )
            }
        }
        for s in &self.subscriptions {
            ensure!(
                (1..=168).contains(&s.update_interval_hours),
                "订阅更新间隔必须在 1 到 168 小时之间"
            );
            validate_nodes(&s.nodes)?;
        }
        for rule in &self.rulesets {
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

pub struct Store {
    pub dir: PathBuf,
    pub state: State,
}
impl Store {
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
            serde_json::from_slice::<State>(&bytes)
                .context("无法读取 AeroBox 数据；原文件未更改")?
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
        "profiles" => {
            state.profiles.retain(|p| p.id != id);
            if state.settings.active_profile == id {
                state.settings.active_profile = state
                    .profiles
                    .first()
                    .map(|p| p.id.clone())
                    .unwrap_or_default()
            }
        }
        "subscriptions" => {
            state.subscriptions.retain(|s| s.id != id);
            for p in &mut state.profiles {
                p.subscriptions.retain(|s| s != id)
            }
        }
        "rulesets" => {
            state.rulesets.retain(|s| s.id != id);
            for p in &mut state.profiles {
                p.rulesets.retain(|s| s != id)
            }
        }
        _ => bail!("未知资源类型"),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn error_is_the_log_default_without_overwriting_saved_choices() {
        let fresh = State::default();
        assert_eq!(fresh.settings.log_level, "error");
        assert!(
            fresh
                .profiles
                .iter()
                .all(|profile| profile.config["log"]["level"] == "error")
        );
        for level in ["info", "debug", "warn", "error"] {
            let saved: Settings = serde_json::from_value(json!({"log_level": level})).unwrap();
            assert_eq!(saved.log_level, level);
        }
    }
    #[test]
    fn renderer_preference_preserves_an_explicit_acceleration_choice() {
        assert!(!Settings::default().hardware_acceleration);
        let settings: Settings =
            serde_json::from_value(json!({"hardware_acceleration": true})).unwrap();
        assert!(settings.hardware_acceleration);
        let restored: Settings =
            serde_json::from_value(serde_json::to_value(settings).unwrap()).unwrap();
        assert!(restored.hardware_acceleration);
    }
    #[test]
    fn adding_presets_preserves_edits_and_reconnects_renamed_rules() {
        let mut state = State::default();
        let active = state.settings.active_profile.clone();
        state.profiles[0].name = "我的配置".into();
        rename_rule_references(
            &mut state,
            BUILTIN_DOMESTIC_ID,
            "中国大陆域名",
            "自定义国内域名",
        );
        state.rulesets[1].name = "自定义国内域名".into();
        state.rulesets[1].content["rules"] = json!([{"domain_suffix":"example.cn"}]);
        let before = pretty(&state);
        assert_eq!(add_builtin_resources(&mut state).unwrap(), 0);
        assert_eq!(pretty(&state), before);
        state.profiles.clear();
        state.settings.active_profile.clear();
        assert_eq!(add_builtin_resources(&mut state).unwrap(), 3);
        assert_eq!(state.settings.active_profile, active);
        assert_eq!(
            state.profiles[0].config["route"]["rules"][0]["rule_set"][0],
            "自定义国内域名"
        );
        assert_eq!(
            state.rulesets[1].content["rules"][0]["domain_suffix"],
            "example.cn"
        );
        state.validate().unwrap();
    }
    #[test]
    fn online_builtin_rules_preserve_custom_lists_and_profile_selection() {
        let mut state = State::default();
        let profiles = pretty(&state.profiles);
        let active = state.settings.active_profile.clone();
        state.rulesets[0].source.clear();
        state.rulesets[0].name = "我的局域网".into();
        let seed = state.rulesets[0].content.clone();
        let custom = RuleSet {
            name: "私人规则".into(),
            ..RuleSet::default()
        };
        let custom_id = custom.id.clone();
        state.rulesets.push(custom);
        use_online_builtin_rules(&mut state).unwrap();
        assert!(state.rulesets[0].is_remote());
        assert_eq!(state.rulesets[0].name, "我的局域网");
        assert_eq!(state.rulesets[0].content, seed);
        assert!(
            !state
                .rulesets
                .iter()
                .find(|r| r.id == custom_id)
                .unwrap()
                .is_remote()
        );
        assert_eq!(profiles, pretty(&state.profiles));
        assert_eq!(active, state.settings.active_profile);
        state.rulesets[0].update_interval_hours = 0;
        assert!(state.validate().is_err());
    }
    #[test]
    fn failed_update_leaves_state_and_disk_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(Some(dir.path().into())).unwrap();
        store.update(|_| Ok(())).unwrap();
        let old = fs::read(dir.path().join("state.json")).unwrap();
        assert!(
            store
                .update(|s| {
                    s.profiles[0].name.clear();
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(old, fs::read(dir.path().join("state.json")).unwrap());
        assert_eq!(store.state.profiles[0].name, "智能分流");
    }
    #[test]
    fn corrupt_state_is_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, b"broken").unwrap();
        assert!(Store::open(Some(dir.path().into())).is_err());
        assert_eq!(fs::read(path).unwrap(), b"broken");
    }
}
