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
    pub core_path: String,
    pub active_profile: String,
    pub auto_start: bool,
    pub auto_restart: bool,
    pub system_proxy: bool,
    pub request_proxy: String,
    pub test_url: String,
    pub test_timeout: u32,
    pub width: i32,
    pub height: i32,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            core_path: String::new(),
            active_profile: String::new(),
            auto_start: false,
            auto_restart: false,
            system_proxy: false,
            request_proxy: String::new(),
            test_url: "https://www.gstatic.com/generate_204".into(),
            test_timeout: 5000,
            width: 1180,
            height: 800,
        }
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
    #[serde(default)]
    pub script: String,
}
impl Profile {
    pub fn new(name: &str) -> Self {
        Self {
            id: id(),
            name: name.into(),
            subscriptions: vec![],
            rulesets: vec![],
            script: String::new(),
            config: json!({
                "log":{"level":"info","timestamp":true},
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
    pub include: String,
    pub exclude: String,
    pub prefix: String,
    pub script: String,
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
            include: String::new(),
            exclude: String::new(),
            prefix: String::new(),
            script: String::new(),
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
        let p = Profile::new("默认配置");
        Self {
            schema: 1,
            settings: Settings {
                active_profile: p.id.clone(),
                ..Settings::default()
            },
            profiles: vec![p],
            subscriptions: vec![],
            rulesets: vec![],
        }
    }
}
impl State {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == 1, "不支持的数据格式版本 {}", self.schema);
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
            validate_nodes(&s.nodes)?;
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
            None => data_home()?.join("singbox"),
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
pub fn data_home() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return Ok(path.into());
    };
    Ok(PathBuf::from(std::env::var_os("HOME").context("HOME 未设置")?).join(".local/share"))
}
pub fn config_home() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
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
        assert_eq!(store.state.profiles[0].name, "默认配置");
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
