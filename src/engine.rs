use crate::{
    model::{self, NodeSelection, RuleSet, Settings, State, Store, atomic_write, now, pretty},
    network, platform,
    runtime::{self, EmbeddedCore, Prepared},
    subscription,
};
use anyhow::{Context, Result, bail, ensure};
use reqwest::blocking::Client;
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    fs,
    io::Read,
    mem::DropGuard,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Default)]
pub struct CoreStatus {
    pub running: bool,
    pub generation: Option<u64>,
    pub uptime: u64,
    pub proxy: bool,
}
#[derive(Clone, Debug)]
pub struct CoreInfo {
    pub name: String,
    pub version: String,
    pub status: CoreStatus,
    pub routing_mode: String,
}
#[derive(Clone, Debug)]
pub struct SubscriptionNode {
    pub subscription_id: String,
    pub node_tag: String,
    pub name: String,
    pub protocol: String,
    pub selected: bool,
    pub delay_ms: Option<u64>,
    pub available: bool,
}
#[derive(Default)]
struct Running {
    core: Option<Arc<EmbeddedCore>>,
    prepared: Option<Prepared>,
    started: Option<Instant>,
    generation: Option<u64>,
    delays: HashMap<NodeSelection, u64>,
}
pub struct Service {
    pub store: Mutex<Store>,
    running: Mutex<Running>,
    operation: Mutex<()>,
    logs: Arc<Mutex<VecDeque<String>>>,
    proxy: Mutex<Option<platform::ProxySnapshot>>,
    proxy_active: AtomicBool,
    closing: AtomicBool,
    desired_running: AtomicBool,
    subscriptions: Mutex<HashMap<String, SubscriptionAttempt>>,
    subscription_revision: AtomicU64,
    next_generation: AtomicU64,
    starting: Mutex<Option<shoes::embedding::CancellationToken>>,
}
#[derive(Default)]
struct SubscriptionAttempt {
    pending: bool,
    failed_at: Option<Instant>,
}
impl Service {
    pub fn new(store: Store) -> Arc<Self> {
        Arc::new(Self {
            store: Mutex::new(store),
            running: Mutex::new(Running::default()),
            operation: Mutex::new(()),
            logs: Arc::new(Mutex::new(VecDeque::new())),
            proxy: Mutex::new(None),
            proxy_active: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            desired_running: AtomicBool::new(false),
            subscriptions: Mutex::new(HashMap::new()),
            subscription_revision: AtomicU64::new(0),
            next_generation: AtomicU64::new(1),
            starting: Mutex::new(None),
        })
    }
    pub fn shutdown(&self) -> Result<()> {
        self.closing.store(true, Ordering::SeqCst);
        self.stop()
    }
    pub fn dir(&self) -> PathBuf {
        self.store.lock().unwrap().dir.clone()
    }
    pub fn snapshot(&self) -> State {
        self.store.lock().unwrap().state.clone()
    }
    pub fn update(&self, edit: impl FnOnce(&mut State) -> Result<()>) -> Result<()> {
        self.store.lock().unwrap().update(edit)
    }
    pub fn log(&self, line: impl Into<String>) {
        let mut logs = self.logs.lock().unwrap();
        if logs.len() >= 2000 {
            logs.pop_front();
        }
        logs.push_back(line.into());
    }
    pub fn logs(&self) -> String {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }
    pub fn clear_logs(&self) {
        self.logs.lock().unwrap().clear();
    }
    pub fn status(&self) -> CoreStatus {
        let run = self.running.lock().unwrap();
        let running = run.core.as_ref().is_some_and(|core| core.is_running());
        CoreStatus {
            running,
            generation: run.generation.filter(|_| running),
            uptime: run
                .started
                .filter(|_| running)
                .map_or(0, |at| at.elapsed().as_secs()),
            proxy: self.proxy_active.load(Ordering::SeqCst),
        }
    }
    pub fn poll(&self) {
        if self.closing.load(Ordering::SeqCst) {
            return;
        }
        let Ok(_op) = self.operation.try_lock() else {
            return;
        };
        let failed = self
            .running
            .lock()
            .unwrap()
            .core
            .as_ref()
            .is_some_and(|core| !core.is_running());
        if failed {
            self.log("网络运行已结束");
            if let Err(e) = self.stop_locked() {
                self.log(format!("清理连接失败：{e:#}"));
            }
        }
    }
    pub fn core_info(&self) -> Result<CoreInfo> {
        Ok(CoreInfo {
            name: "AeroBox Rust".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            status: self.status(),
            routing_mode: self.runtime_mode()?,
        })
    }
    pub fn generate_current(&self) -> Result<Value> {
        Ok(self.prepare_current(&self.snapshot())?.config)
    }
    fn prepare_current(&self, state: &State) -> Result<Prepared> {
        runtime::prepare(state, &self.dir())
    }
    pub fn check_current(&self) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let prepared = self.prepare_current(&self.snapshot())?;
        let cancelled = shoes::embedding::CancellationToken::new();
        *self.starting.lock().unwrap() = Some(cancelled.clone());
        let _clear = DropGuard::new((), |()| {
            self.starting.lock().unwrap().take();
        });
        runtime::executor().block_on(self.fetch_missing_rules(&prepared, &cancelled))?;
        ensure!(!cancelled.is_cancelled(), "检查已取消");
        self.check(&prepared.config)
    }
    pub fn check(&self, config: &Value) -> Result<()> {
        runtime::executor()
            .block_on(EmbeddedCore::check(runtime::parse(config)?))
            .context("运行配置检查失败")
    }
    pub fn start(&self) -> Result<()> {
        ensure!(!self.closing.load(Ordering::SeqCst), "应用正在退出");
        self.desired_running.store(true, Ordering::SeqCst);
        let _op = self.operation.lock().unwrap();
        if self.status().running {
            return Ok(());
        }
        let state = self.snapshot();
        let prepared = self.prepare_current(&state)?;
        self.start_config_locked(prepared, state.settings.system_proxy)
    }
    fn start_config_locked(&self, prepared: Prepared, proxy: bool) -> Result<()> {
        ensure!(
            self.desired_running.load(Ordering::SeqCst) && !self.closing.load(Ordering::SeqCst),
            "启动已取消"
        );
        self.ensure_tun_available(&prepared.settings)?;
        shoes::embedding::set_state_directory(self.dir().join("network"))?;
        runtime::configure(&prepared.settings, &self.logs);
        let cancelled = shoes::embedding::CancellationToken::new();
        *self.starting.lock().unwrap() = Some(cancelled.clone());
        if !self.desired_running.load(Ordering::SeqCst) {
            cancelled.cancel();
        }
        let started = runtime::executor().block_on(async {
            self.fetch_missing_rules(&prepared, &cancelled).await?;
            Ok::<_, anyhow::Error>(
                EmbeddedCore::start_cancellable(runtime::parse(&prepared.config)?, None, cancelled)
                    .await?,
            )
        });
        self.starting.lock().unwrap().take();
        let core = Arc::new(started.context("启动失败")?);
        if !self.desired_running.load(Ordering::SeqCst) || self.closing.load(Ordering::SeqCst) {
            runtime::executor().block_on(core.shutdown())?;
            bail!("启动已取消");
        }
        *self.running.lock().unwrap() = Running {
            core: Some(core),
            prepared: Some(prepared),
            started: Some(Instant::now()),
            generation: Some(self.next_generation.fetch_add(1, Ordering::SeqCst)),
            delays: HashMap::new(),
        };
        if let Err(error) = self.set_proxy(proxy) {
            let cleanup = self.stop_locked();
            return Err(error.context(format!("设置系统代理失败；清理结果：{cleanup:?}")));
        }
        self.log("连接已启动");
        Ok(())
    }
    pub fn stop(&self) -> Result<()> {
        self.desired_running.store(false, Ordering::SeqCst);
        if let Some(cancelled) = self.starting.lock().unwrap().as_ref() {
            cancelled.cancel();
        }
        let _op = self.operation.lock().unwrap();
        self.stop_locked()
    }
    fn stop_locked(&self) -> Result<()> {
        let restore = self.restore_proxy();
        let core = self.running.lock().unwrap().core.clone();
        if let Some(core) = core {
            runtime::executor().block_on(core.shutdown())?;
        }
        let run = std::mem::take(&mut *self.running.lock().unwrap());
        if run.generation.is_some() {
            self.log("连接已停止");
        }
        restore
    }
    pub fn restart(&self) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let prepared = self.prepare_current(&self.snapshot())?;
        self.check(&prepared.config)?;
        if self.status().running {
            let old = self.running_config()?;
            let proxy = self.status().proxy;
            self.stop_locked()?;
            if let Err(error) = self.start_config_locked(prepared, proxy) {
                self.start_config_locked(old, proxy)
                    .context("恢复原连接失败")?;
                return Err(error);
            }
        }
        Ok(())
    }
    fn core(&self) -> Result<Arc<EmbeddedCore>> {
        self.running
            .lock()
            .unwrap()
            .core
            .clone()
            .filter(|core| core.is_running())
            .context("请先启动连接")
    }
    fn running_config(&self) -> Result<Prepared> {
        self.running
            .lock()
            .unwrap()
            .prepared
            .clone()
            .context("请先启动连接")
    }
    pub fn set_proxy(&self, enabled: bool) -> Result<()> {
        if !enabled {
            return self.restore_proxy();
        }
        let mut saved = self.proxy.lock().unwrap();
        let prepared = self.running_config()?;
        let server = format!("127.0.0.1:{}", prepared.settings.mixed_port);
        if saved.is_some() && platform::verify_proxy(&server, "mixed")? {
            return Ok(());
        }
        let snapshot = platform::enable_proxy(&server, "mixed")?;
        if saved.is_none() {
            *saved = Some(snapshot);
        }
        self.proxy_active.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn restore_proxy(&self) -> Result<()> {
        let mut saved = self.proxy.lock().unwrap();
        if let Some(snapshot) = &*saved {
            snapshot.restore()?;
            *saved = None;
            self.proxy_active.store(false, Ordering::SeqCst);
        }
        Ok(())
    }
    pub fn set_system_proxy_enabled(&self, enabled: bool) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let mut candidate = before.clone();
        candidate.settings.system_proxy = enabled;
        self.commit_state(&before, candidate)
    }
    pub fn runtime_mode(&self) -> Result<String> {
        Ok(self
            .running
            .lock()
            .unwrap()
            .prepared
            .as_ref()
            .map(|p| p.settings.routing_mode.clone())
            .unwrap_or_else(|| self.snapshot().settings.routing_mode))
    }
    pub fn set_routing_mode(&self, mode: &str) -> Result<()> {
        ensure!(
            matches!(mode, "rule" | "global" | "direct"),
            "无效的出站模式"
        );
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let mut candidate = before.clone();
        candidate.settings.routing_mode = mode.into();
        self.commit_state(&before, candidate)
    }
    pub fn connections(&self) -> Result<Value> {
        let _op = self.operation.lock().unwrap();
        let prepared = self.running_config()?;
        let mut connections = runtime::executor().block_on(self.core()?.connections())?;
        let mut names = HashMap::from([
            ("proxy".to_owned(), "代理".to_owned()),
            ("direct".to_owned(), "直连".to_owned()),
            ("DIRECT".to_owned(), "直连".to_owned()),
        ]);
        for (selection, node) in &prepared.nodes {
            names.insert(node.tag.clone(), selection.node_tag.clone());
            names.insert(
                format!("{}-transport", node.tag),
                selection.node_tag.clone(),
            );
        }
        for connection in connections["connections"]
            .as_array_mut()
            .into_iter()
            .flatten()
        {
            for chain in connection["chains"].as_array_mut().into_iter().flatten() {
                if let Some(name) = chain.as_str().and_then(|tag| names.get(tag)) {
                    *chain = Value::String(name.clone());
                }
            }
        }
        Ok(connections)
    }
    pub fn close_connection(&self, id: &str) -> Result<()> {
        runtime::executor().block_on(self.core()?.close_connection(id.into()))?;
        Ok(())
    }
    pub fn close_all_connections(&self) -> Result<()> {
        runtime::executor().block_on(self.core()?.close_all())?;
        Ok(())
    }
    pub fn traffic(&self) -> Result<crate::traffic::Counters> {
        let stats = runtime::executor().block_on(self.core()?.stats())?;
        Ok(crate::traffic::Counters {
            download: stats.download_total,
            upload: stats.upload_total,
            connections: stats.active_connections,
        })
    }
    pub fn subscription_nodes(&self, id: &str) -> Result<Vec<SubscriptionNode>> {
        let state = self.snapshot();
        let sub = state
            .subscriptions
            .iter()
            .find(|s| s.id == id)
            .context("订阅不存在")?;
        let run = self.running.lock().unwrap();
        let prepared = run
            .prepared
            .as_ref()
            .filter(|_| run.core.as_ref().is_some_and(|c| c.is_running()));
        Ok(model::selectable_nodes(&sub.nodes)
            .map(|source| {
                let tag = source["tag"].as_str().unwrap_or_default();
                let key = NodeSelection {
                    subscription_id: id.into(),
                    node_tag: tag.into(),
                };
                let available = prepared
                    .is_some_and(|p| p.nodes.get(&key).is_some_and(|n| n.source == *source));
                let selected = prepared.map_or(
                    state.settings.active_subscription == id
                        && sub.selected_node.as_deref() == Some(tag),
                    |p| available && p.selected_node.as_ref() == Some(&key),
                );
                SubscriptionNode {
                    subscription_id: id.into(),
                    node_tag: tag.into(),
                    name: tag.into(),
                    protocol: source["type"].as_str().unwrap_or_default().into(),
                    selected,
                    available,
                    delay_ms: run.delays.get(&key).copied(),
                }
            })
            .collect())
    }
    pub fn subscription_nodes_runtime(&self, id: &str) -> Result<Vec<SubscriptionNode>> {
        self.subscription_nodes(id)
    }
    pub fn select_subscription(&self, id: &str) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let mut candidate = before.clone();
        ensure!(
            candidate
                .subscriptions
                .iter()
                .any(|s| s.id == id && model::has_selectable_node(&s.nodes)),
            "此订阅没有可连接节点"
        );
        candidate.settings.active_subscription = id.into();
        self.commit_state(&before, candidate)
    }
    pub fn select_subscription_node(&self, id: &str, tag: &str) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let mut candidate = before.clone();
        let sub = candidate
            .subscriptions
            .iter_mut()
            .find(|s| s.id == id)
            .context("订阅不存在")?;
        ensure!(
            model::selectable_nodes(&sub.nodes).any(|n| n["tag"] == tag),
            "节点不存在"
        );
        sub.selected_node = Some(tag.into());
        candidate.settings.active_subscription = id.into();
        self.commit_state(&before, candidate)
    }
    pub fn test_subscription_node(&self, id: &str, tag: &str) -> Result<u64> {
        let state = self.snapshot();
        let generation = self.status().generation;
        let revision = self.subscription_revision();
        let key = NodeSelection {
            subscription_id: id.into(),
            node_tag: tag.into(),
        };
        let prepared = self.running_config()?;
        let node = prepared.nodes.get(&key).context("请先选择此订阅")?;
        let delay = runtime::executor().block_on(self.core()?.urltest(
            node.tag.clone(),
            state.settings.test_url,
            u64::from(state.settings.test_timeout),
        ))? as u64;
        let _op = self.operation.lock().unwrap();
        ensure!(
            self.status().generation == generation && self.subscription_revision() == revision,
            "连接已变化，请重新测速"
        );
        self.running.lock().unwrap().delays.insert(key, delay);
        Ok(delay)
    }
    pub fn apply_settings(&self, settings: Settings) -> Result<()> {
        settings.validate()?;
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let mut candidate = before.clone();
        candidate.settings = settings;
        self.commit_state(&before, candidate)
    }

    pub fn export_backup(&self, path: &Path) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let mut state = self.snapshot();
        for rule in &mut state.rulesets {
            if !rule.binary && rule.is_remote() {
                rule.content = serde_json::from_slice(&self.rule_bytes(rule)?)?;
            }
        }
        crate::backup::export(path, &state, |rule| self.rule_bytes(rule).ok())
    }

    pub fn restore_backup(&self, path: &Path) -> Result<(usize, usize)> {
        let (imported, files) = crate::backup::read(path)?;
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let (candidate, files) = crate::backup::merge(&before, imported, files)?;
        // Only new IDs are written during a merge; rollback can safely remove
        // these files without touching an existing resource's cached bytes.
        let store = self.store.lock().unwrap();
        for rule in &candidate.rulesets {
            if !before.rulesets.iter().any(|current| current.id == rule.id) && rule.binary {
                ensure!(
                    files.contains_key(&rule.id),
                    "SRS 规则集「{}」缺少二进制数据",
                    rule.name
                );
            }
        }
        let mut installed = DropGuard::new(Vec::<PathBuf>::new(), |paths| {
            for path in paths {
                let _ = fs::remove_file(path);
            }
        });
        for rule in &candidate.rulesets {
            if let Some(bytes) = files.get(&rule.id) {
                let path = store.rule_path(rule);
                ensure!(!path.exists(), "规则集缓存已存在：{}", rule.name);
                crate::model::atomic_write(&path, bytes, 0o600)
                    .with_context(|| format!("无法写入规则集「{}」", rule.name))?;
                installed.push(path);
            }
        }
        drop(store);
        self.commit_state(&before, candidate)?;
        DropGuard::dismiss(installed);
        let counts = (
            self.snapshot().subscriptions.len() - before.subscriptions.len(),
            self.snapshot().rulesets.len() - before.rulesets.len(),
        );
        self.log("备份已合并恢复");
        Ok(counts)
    }

    pub fn apply_settings_form(&self, previous: Settings, settings: Settings) -> Result<()> {
        settings.validate()?;
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        ensure!(
            before.settings.same_preferences(&previous),
            "其他操作已更改设置，请重新打开设置页后再保存"
        );
        let mut candidate = before.clone();
        candidate.settings = settings;
        self.commit_state(&before, candidate)
    }

    pub fn reset_settings(&self, previous: Settings) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        ensure!(
            before.settings.same_preferences(&previous),
            "其他操作已更改设置，请重新打开设置页后再保存"
        );
        let mut candidate = before.clone();
        candidate.settings = Settings {
            // These describe the local desktop and the live resource selection,
            // not preference defaults. Resources themselves remain untouched.
            active_subscription: before.settings.active_subscription.clone(),
            routing_mode: before.settings.routing_mode.clone(),
            width: before.settings.width,
            height: before.settings.height,
            ..Settings::default()
        };
        self.commit_state(&before, candidate)
    }

    pub fn autostart_enabled(&self) -> bool {
        platform::autostart_enabled()
    }

    pub fn save_form(&self, previous: Settings, settings: Settings, login: bool) -> Result<()> {
        // Change the machine-local setting first. If it fails, neither the
        // form baseline nor the portable application state has moved.
        platform::set_autostart(login)?;
        self.apply_settings_form(previous, settings)
            .map_err(|error| error.context("设置未保存；登录启动状态可能已更改，请检查设置页"))
    }

    pub fn reset_form(&self, previous: Settings, login: bool) -> Result<()> {
        platform::set_autostart(login)?;
        self.reset_settings(previous)
            .map_err(|error| error.context("未恢复默认设置；登录启动状态可能已更改，请检查设置页"))
    }

    pub fn restore_backup_form(&self, path: &Path, login: bool) -> Result<(usize, usize)> {
        platform::set_autostart(login)?;
        self.restore_backup(path)
            .map_err(|error| error.context("备份未恢复；登录启动状态可能已更改，请检查设置页"))
    }

    pub fn network_info(&self) -> Result<network::NetworkInfo> {
        let generation = self.status().generation;
        let revision = self.subscription_revision();
        let settings = self.snapshot().settings;
        let client = self.client_with_timeout(Duration::from_secs(4))?;
        let info = network::detect(client, settings.ipv6, generation.is_some())?;
        ensure!(
            self.status().generation == generation && self.subscription_revision() == revision,
            "连接已变化，请重新检测"
        );
        Ok(info)
    }
    pub fn diagnose_connection(&self) -> Result<String> {
        let generation = self.status().generation.context("请先启动连接")?;
        let prepared = self.running_config()?;
        let server = format!("127.0.0.1:{}", prepared.settings.mixed_port);
        let reachable =
            std::net::TcpStream::connect_timeout(&server.parse()?, Duration::from_secs(2)).is_ok();
        let mut lines = vec![
            format!(
                "本地入口：{}",
                if reachable {
                    "可连接"
                } else {
                    "连接失败"
                }
            ),
            format!("出站模式：{}", prepared.settings.routing_mode),
            format!(
                "系统代理：{}",
                if platform::verify_proxy(&server, "mixed")? {
                    "已指向 AeroBox"
                } else {
                    "未指向 AeroBox"
                }
            ),
        ];
        let client = self.client_with_timeout(Duration::from_secs(10))?;
        for (name, url) in [
            ("HTTP", "http://www.gstatic.com/generate_204"),
            ("HTTPS", prepared.settings.test_url.as_str()),
        ] {
            let start = Instant::now();
            let result = client
                .get(url)
                .send()
                .and_then(reqwest::blocking::Response::error_for_status);
            lines.push(match result {
                Ok(response) => format!(
                    "{name}：成功（{}，{} ms）",
                    response.status(),
                    start.elapsed().as_millis()
                ),
                Err(e) => format!("{name}：{}", network::request_failure(&e)),
            });
        }
        ensure!(
            self.status().generation == Some(generation),
            "检测期间连接已变化，请重试"
        );
        Ok(lines.join("\n"))
    }
    pub fn memory_usage(&self) -> network::MemoryUsage {
        network::memory_usage(None)
    }
    fn ensure_tun_available(&self, settings: &Settings) -> Result<()> {
        if settings.tun_enabled {
            ensure!(
                self.tun_available()?,
                "虚拟网卡需要网络管理权限，请授权后重启 AeroBox"
            );
        }
        Ok(())
    }
    pub fn tun_available(&self) -> Result<bool> {
        let status = fs::read_to_string("/proc/self/status")?;
        let effective = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:\t"))
            .context("无法读取进程权限")?;
        let caps = u64::from_str_radix(effective.trim(), 16)?;
        Ok(caps & (1 << 12) != 0 && caps & (1 << 13) != 0)
    }
    pub fn authorize_tun(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let executable = std::env::current_exe()?.canonicalize()?;
        let metadata = fs::metadata(&executable)?;
        ensure!(
            metadata.is_file() && metadata.mode() & 0o022 == 0,
            "应用文件不能由其他用户修改"
        );
        let setcap = ["/usr/sbin/setcap", "/sbin/setcap"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .context("请先安装 libcap 工具")?;
        let status = Command::new("pkexec")
            .arg(setcap)
            .arg("cap_net_admin,cap_net_raw+ep")
            .arg(executable)
            .status()
            .context("无法启动权限授权")?;
        ensure!(status.success(), "虚拟网卡授权未完成");
        Ok(())
    }
    fn client_with_timeout(&self, timeout: Duration) -> Result<Client> {
        let run = self.running.lock().unwrap();
        // Until shutdown has finished, requests must keep using the listener;
        // an unavailable listener is an error, never a direct-download fallback.
        let config = run.prepared.as_ref().map(|p| &p.config);
        network::client(config, timeout)
    }
    async fn fetch_missing_rules(
        &self,
        prepared: &Prepared,
        cancelled: &shoes::embedding::CancellationToken,
    ) -> Result<()> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(5))
            .user_agent(concat!("AeroBox/", env!("CARGO_PKG_VERSION")));
        let current = self
            .running
            .lock()
            .unwrap()
            .prepared
            .as_ref()
            .map(|p| p.config.clone());
        if let Some(config) = current {
            builder = builder.proxy(reqwest::Proxy::all(network::proxy_url(&config)?)?);
        }
        let client = builder.build()?;
        for source in prepared
            .config
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry["rules"].as_array())
            .flatten()
            .filter(|source| source["url"].is_string())
        {
            let path = PathBuf::from(source["path"].as_str().context("规则缓存路径无效")?);
            if path.exists() {
                continue;
            }
            let binary = source["format"] == "srs";
            let request = async {
                let mut response = client
                    .get(source["url"].as_str().unwrap())
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(|e| {
                        anyhow::anyhow!("规则下载失败：{}", network::request_failure(&e))
                    })?;
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|e| {
                    anyhow::anyhow!("规则下载失败：{}", network::request_failure(&e))
                })? {
                    ensure!(
                        bytes.len() + chunk.len() <= 32 * 1024 * 1024,
                        "规则文件超过32 MiB"
                    );
                    bytes.extend_from_slice(&chunk);
                }
                shoes::rule_set::validate_bytes(&bytes, binary)?;
                atomic_write(&path, &bytes, 0o600)
            };
            tokio::select! {
                biased;
                _=cancelled.cancelled()=>bail!("启动已取消"),
                result=request=>result?,
            }
        }
        Ok(())
    }
    fn client(&self) -> Result<Client> {
        self.client_with_timeout(Duration::from_secs(60))
    }
    fn download(&self, url: &str) -> Result<(Vec<u8>, reqwest::header::HeaderMap)> {
        let parsed = url::Url::parse(url)?;
        ensure!(
            ["http", "https"].contains(&parsed.scheme()),
            "仅支持 HTTP / HTTPS 地址"
        );
        let r = self
            .client()?
            .get(url)
            .send()
            .map_err(reqwest::Error::without_url)?
            .error_for_status()
            .map_err(reqwest::Error::without_url)?;
        let headers = r.headers().clone();
        let mut bytes = vec![];
        r.take(128 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 128 * 1024 * 1024, "下载超过 128 MiB");
        Ok((bytes, headers))
    }
    pub fn update_subscription(&self, id: &str) -> Result<()> {
        ensure!(self.begin_subscription_update(id, false)?, "订阅正在更新");
        self.finish_subscription_update(id)
    }

    pub fn save_subscription(
        &self,
        original: &model::Subscription,
        next: model::Subscription,
    ) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let current = before
            .subscriptions
            .iter()
            .find(|sub| sub.id == original.id)
            .context("订阅已被删除，请重新打开编辑器")?;
        // Downloaded nodes and quota are live data, not form fields. Preserve
        // them while still rejecting a source/settings edit from an old form.
        ensure!(
            current.name == original.name
                && current.source == original.source
                && current.auto_update == original.auto_update
                && current.update_interval_minutes == original.update_interval_minutes,
            "订阅在编辑期间已被修改，请重新打开编辑器"
        );
        let mut candidate = before.clone();
        let target = candidate
            .subscriptions
            .iter_mut()
            .find(|sub| sub.id == original.id)
            .context("订阅已被删除")?;
        let mut next = next;
        next.nodes = current.nodes.clone();
        next.selected_node = current.selected_node.clone();
        next.updated = current.updated;
        next.upload = current.upload;
        next.download = current.download;
        next.total = current.total;
        next.expires = current.expires;
        if next.source != current.source {
            next.updated = 0;
        }
        *target = next;
        self.commit_state(&before, candidate)
    }

    pub fn save_subscription_nodes(
        &self,
        original: &model::Subscription,
        nodes: Vec<Value>,
    ) -> Result<()> {
        model::validate_nodes(&nodes)?;
        ensure!(model::has_selectable_node(&nodes), "订阅没有可连接节点");
        let mut next = original.clone();
        next.nodes = nodes;
        next.updated = now();
        self.apply_subscription_update(&original.id, original, &next)
    }

    pub fn import_subscription(&self, mut sub: model::Subscription) -> Result<()> {
        if !sub.source.trim().is_empty() {
            ensure!(
                !self
                    .snapshot()
                    .subscriptions
                    .iter()
                    .any(|existing| existing.source == sub.source),
                "此订阅已导入"
            );
            self.fetch_subscription(&mut sub, true)?;
        } else {
            ensure!(!sub.nodes.is_empty(), "订阅没有节点");
            model::validate_nodes(&sub.nodes)?;
            sub.updated = now();
        }
        ensure!(model::has_selectable_node(&sub.nodes), "订阅没有可连接节点");
        let name = sub.name.clone();
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        ensure!(
            sub.source.is_empty() || !before.subscriptions.iter().any(|s| s.source == sub.source),
            "此订阅已导入"
        );
        let mut candidate = before.clone();
        candidate.settings.active_subscription = sub.id.clone();
        candidate.subscriptions.push(sub);
        self.commit_state(&before, candidate)?;
        self.log(format!("订阅「{name}」已导入并选用"));
        Ok(())
    }

    /// Save an applied change together with the most recent window dimensions.
    fn persist_if_current(&self, before: &State, mut candidate: State) -> Result<()> {
        self.update(|state| {
            ensure!(
                state.settings.same_preferences(&before.settings)
                    && state.subscriptions == before.subscriptions
                    && state.rulesets == before.rulesets,
                "数据在操作期间已改变，请重试"
            );
            candidate.settings.width = state.settings.width;
            candidate.settings.height = state.settings.height;
            *state = candidate;
            Ok(())
        })
    }

    /// Runtime changes and persistence form one transaction. Rollback restores
    /// both the effective route and the desktop proxy on any failed save.
    fn commit_state(&self, before: &State, mut candidate: State) -> Result<()> {
        candidate.normalize_selection();
        candidate.validate()?;
        let old = self
            .status()
            .running
            .then(|| self.running_config())
            .transpose()?;
        let old_proxy = self.status().proxy;
        let new_proxy = if before.settings.system_proxy == candidate.settings.system_proxy {
            old_proxy
        } else {
            candidate.settings.system_proxy
        };
        let next = if old.is_some() && !candidate.settings.active_subscription.is_empty() {
            Some(self.prepare_current(&candidate)?)
        } else {
            None
        };
        let mut changed = false;
        let apply = (|| -> Result<()> {
            if let Some(previous) = &old {
                if let Some(next) = &next {
                    self.ensure_tun_available(&next.settings)?;
                    if next.config != previous.config
                        || next.settings.dns_cache != previous.settings.dns_cache
                    {
                        let cancelled = shoes::embedding::CancellationToken::new();
                        *self.starting.lock().unwrap() = Some(cancelled.clone());
                        let _clear = DropGuard::new((), |()| {
                            self.starting.lock().unwrap().take();
                        });
                        if !self.desired_running.load(Ordering::SeqCst) {
                            cancelled.cancel();
                        }
                        runtime::executor().block_on(self.fetch_missing_rules(next, &cancelled))?;
                        ensure!(self.desired_running.load(Ordering::SeqCst), "操作已取消");
                        self.check(&next.config)?;
                        changed = true;
                        self.replace_running(next.clone())?;
                    } else {
                        runtime::configure(&next.settings, &self.logs);
                        self.running.lock().unwrap().prepared = Some(next.clone());
                    }
                    if changed || new_proxy != old_proxy {
                        self.set_proxy(new_proxy)?;
                    }
                } else {
                    changed = true;
                    self.stop_locked()?;
                }
            }
            self.persist_if_current(before, candidate)
        })();
        if let Err(error) = apply {
            if let Some(previous) = old {
                let restore = (|| -> Result<()> {
                    if changed {
                        if self.status().running {
                            self.replace_running(previous)?;
                        } else {
                            self.start_config_locked(previous, old_proxy)?;
                        }
                    } else {
                        runtime::configure(&previous.settings, &self.logs);
                        self.running.lock().unwrap().prepared = Some(previous);
                    }
                    self.set_proxy(old_proxy)
                })();
                if let Err(restore) = restore {
                    let _ = self.stop_locked();
                    return Err(error.context(format!("恢复原连接失败：{restore:#}")));
                }
            }
            return Err(error.context("未保存更改"));
        }
        if self.snapshot().settings.active_subscription.is_empty() {
            self.desired_running.store(false, Ordering::SeqCst);
        }
        self.subscription_revision.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn replace_running(&self, next: Prepared) -> Result<()> {
        let previous = self.running_config()?;
        let topology_changed = previous.settings.dns_cache != next.settings.dns_cache
            || previous.settings.tun_enabled != next.settings.tun_enabled
            || (next.settings.tun_enabled
                && (previous.settings.tun_mtu != next.settings.tun_mtu
                    || previous.settings.ipv6 != next.settings.ipv6
                    || previous.settings.dns_hijack != next.settings.dns_hijack));
        if topology_changed {
            let proxy = self.status().proxy;
            self.stop_locked()?;
            return self.start_config_locked(next, proxy);
        }
        let mut comparable = previous.config.clone();
        let selected = next
            .selected_node
            .as_ref()
            .and_then(|key| next.nodes.get(key));
        if let Some(selected) = selected
            && let Some(group) = comparable
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|v| v["client_group"] == "proxy")
        {
            group["default"] = selected.tag.clone().into();
        }
        let core = self.core()?;
        runtime::configure(&next.settings, &self.logs);
        let result = if comparable == next.config
            && previous.nodes == next.nodes
            && previous.settings.dns_cache == next.settings.dns_cache
        {
            runtime::executor().block_on(core.select(
                "proxy".into(),
                selected.context("缺少选中节点")?.tag.clone(),
            ))
        } else {
            runtime::executor().block_on(core.reload(runtime::parse(&next.config)?))
        };
        if let Err(error) = result {
            runtime::configure(&previous.settings, &self.logs);
            return Err(error.into());
        }
        runtime::executor().block_on(core.close_all())?;
        let mut run = self.running.lock().unwrap();
        run.prepared = Some(next);
        run.delays.clear();
        Ok(())
    }
    pub fn apply_ruleset_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let mut candidate = before.clone();
        candidate
            .rulesets
            .iter_mut()
            .find(|r| r.id == id)
            .context("规则集不存在")?
            .enabled = enabled;
        self.commit_state(&before, candidate)
    }

    pub fn save_ruleset(&self, mut rule: RuleSet) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let mut candidate = before.clone();
        if let Some(existing) = candidate.rulesets.iter_mut().find(|r| r.id == rule.id) {
            if existing.content != rule.content {
                rule.updated = now().max(existing.updated.saturating_add(1));
            }
            *existing = rule;
        } else {
            candidate.rulesets.push(rule);
        }
        self.commit_state(&before, candidate)
    }

    pub fn delete_resource(&self, kind: &str, id: &str) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let mut candidate = before.clone();
        model::remove_resource(&mut candidate, kind, id)?;
        self.commit_state(&before, candidate)
    }

    pub fn subscription_revision(&self) -> u64 {
        self.subscription_revision.load(Ordering::SeqCst)
    }

    pub fn update_due_subscriptions(&self) -> Result<usize> {
        let mut updated = 0;
        for subscription in self.snapshot().subscriptions {
            if self.begin_subscription_update(&subscription.id, true)?
                && self.finish_subscription_update(&subscription.id).is_ok()
            {
                updated += 1;
            }
        }
        Ok(updated)
    }

    fn begin_subscription_update(&self, id: &str, only_due: bool) -> Result<bool> {
        let mut attempts = self.subscriptions.lock().unwrap();
        let subscription = self
            .snapshot()
            .subscriptions
            .into_iter()
            .find(|sub| sub.id == id)
            .context("订阅不存在")?;
        let attempt = attempts.entry(id.into()).or_default();
        if attempt.pending {
            return Ok(false);
        }
        if only_due
            && (!subscription.auto_update
                || subscription.source.trim().is_empty()
                || now().saturating_sub(subscription.updated)
                    < u64::from(subscription.update_interval_minutes) * 60
                || attempt
                    .failed_at
                    .is_some_and(|at| at.elapsed() < Duration::from_secs(300)))
        {
            return Ok(false);
        }
        attempt.pending = true;
        Ok(true)
    }

    fn finish_subscription_update(&self, id: &str) -> Result<()> {
        let result = self.update_subscription_inner(id);
        let mut attempts = self.subscriptions.lock().unwrap();
        let attempt = attempts.entry(id.into()).or_default();
        attempt.pending = false;
        attempt.failed_at = result.as_ref().err().map(|_| Instant::now());
        drop(attempts);
        if let Err(error) = &result {
            let name = self
                .snapshot()
                .subscriptions
                .into_iter()
                .find(|sub| sub.id == id)
                .map(|sub| sub.name)
                .unwrap_or_else(|| id.to_owned());
            self.log(format!("订阅「{name}」更新失败：{error:#}"));
        }
        result
    }

    fn update_subscription_inner(&self, id: &str) -> Result<()> {
        let original = self
            .snapshot()
            .subscriptions
            .into_iter()
            .find(|s| s.id == id)
            .context("订阅不存在")?;
        let mut sub = original.clone();
        self.fetch_subscription(&mut sub, false)?;
        self.apply_subscription_update(id, &original, &sub)
    }

    fn fetch_subscription(&self, sub: &mut model::Subscription, importing: bool) -> Result<()> {
        ensure!(!sub.source.trim().is_empty(), "请填写订阅来源");
        let bytes = if model::is_online_source(&sub.source) {
            let (bytes, headers) = self.download(&sub.source)?;
            if importing {
                if sub.name == "新订阅"
                    && let Some(title) = headers
                        .get("profile-title")
                        .and_then(|value| value.to_str().ok())
                {
                    let decoded = title.strip_prefix("base64:").and_then(|encoded| {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD
                            .decode(encoded)
                            .ok()
                            .and_then(|bytes| String::from_utf8(bytes).ok())
                    });
                    let title = decoded.as_deref().unwrap_or(title).trim();
                    if !title.is_empty() && !title.starts_with("base64:") {
                        sub.name = title.to_owned();
                    }
                }
                if sub.update_interval_minutes == model::UPDATE_INTERVAL_DEFAULT_MINUTES
                    && let Some(hours) = headers
                        .get("profile-update-interval")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse::<u32>().ok())
                        .filter(|hours| (1..=168).contains(hours))
                {
                    sub.update_interval_minutes = hours * 60;
                }
            }
            if let Some(info) = headers
                .get("subscription-userinfo")
                .and_then(|h| h.to_str().ok())
            {
                for part in info.split(';') {
                    if let Some((k, v)) = part.trim().split_once('=') {
                        let n = v.parse().unwrap_or(0);
                        match k {
                            "upload" => sub.upload = n,
                            "download" => sub.download = n,
                            "total" => sub.total = n,
                            "expire" => sub.expires = n,
                            _ => {}
                        }
                    }
                }
            };
            bytes
        } else {
            fs::read(&sub.source).context("无法读取订阅文件")?
        };
        let (nodes, skipped) = subscription::parse_with_skips(std::str::from_utf8(&bytes)?)?;
        if !skipped.is_empty() {
            self.log(format!(
                "订阅「{}」{}",
                sub.name,
                subscription::skipped_summary(&skipped)
            ));
        }
        sub.nodes = nodes;
        ensure!(!sub.nodes.is_empty(), "订阅没有节点");
        model::validate_nodes(&sub.nodes)?;
        sub.updated = now();
        Ok(())
    }

    fn apply_subscription_update(
        &self,
        id: &str,
        original: &model::Subscription,
        sub: &model::Subscription,
    ) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let current = before
            .subscriptions
            .iter()
            .find(|sub| sub.id == id)
            .context("订阅已被删除")?;
        ensure!(
            current.source == original.source
                && current.updated == original.updated
                && current.nodes == original.nodes,
            "订阅在更新期间已被编辑，请重试"
        );
        let mut candidate = before.clone();
        copy_subscription_data(
            candidate
                .subscriptions
                .iter_mut()
                .find(|sub| sub.id == id)
                .unwrap(),
            sub,
        );
        self.commit_state(&before, candidate)?;
        self.log(format!("订阅「{}」更新完成", sub.name));
        Ok(())
    }
    pub fn update_all_subscriptions(&self) -> Result<usize> {
        let mut updated = 0;
        let mut errors = Vec::new();
        for subscription in self.snapshot().subscriptions {
            if subscription.source.trim().is_empty() {
                continue;
            }
            match self.update_subscription(&subscription.id) {
                Ok(()) => updated += 1,
                Err(error) => errors.push(format!("{}：{error:#}", subscription.name)),
            }
        }
        ensure!(errors.is_empty(), "{}", errors.join("\n"));
        Ok(updated)
    }
    pub fn update_ruleset(&self, id: &str) -> Result<()> {
        let mut r = self
            .snapshot()
            .rulesets
            .into_iter()
            .find(|r| r.id == id)
            .context("规则集不存在")?;
        ensure!(!r.source.is_empty(), "请填写规则集来源");
        let bytes = if r.is_remote() {
            self.download(&r.source)?.0
        } else {
            fs::read(&r.source)?
        };
        let original_content = r.content.clone();
        shoes::rule_set::validate_bytes(&bytes, r.binary)?;
        if !r.binary {
            r.content = serde_json::from_slice(&bytes)?;
            ensure!(r.content["rules"].is_array(), "规则集缺少 rules 数组")
        };
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let current = before
            .rulesets
            .iter()
            .find(|rule| rule.id == id)
            .context("规则集已被删除")?;
        ensure!(
            current.source == r.source
                && current.binary == r.binary
                && current.content == original_content
                && current.updated == r.updated,
            "规则集更新期间被编辑，请重试"
        );
        let mut candidate = before.clone();
        let target = candidate
            .rulesets
            .iter_mut()
            .find(|rule| rule.id == id)
            .context("规则集已被删除")?;
        target.content = r.content;
        // Each manual download owns a distinct immutable runtime cache, even
        // when two updates finish within the same clock second.
        target.updated = now().max(current.updated.saturating_add(1));
        candidate.validate()?;
        let path = self.store.lock().unwrap().rule_path(current);
        let original_file = fs::read(&path).ok();
        atomic_write(&path, &bytes, 0o600)?;
        if let Err(error) = self.commit_state(&before, candidate) {
            if let Some(bytes) = original_file {
                atomic_write(&path, &bytes, 0o600).context("恢复规则文件失败")?;
            } else {
                let _ = fs::remove_file(&path);
            }
            return Err(error);
        }
        self.log(format!("规则集「{}」更新完成", r.name));
        Ok(())
    }
    fn rule_path(&self, r: &RuleSet) -> PathBuf {
        self.store.lock().unwrap().rule_path(r)
    }
    fn rule_bytes(&self, rule: &RuleSet) -> Result<Vec<u8>> {
        if rule.is_remote() {
            let cached = runtime::remote_rule_path(rule, &self.dir());
            if cached.exists() {
                return Ok(fs::read(cached)?);
            }
        }
        if !rule.binary {
            return Ok(serde_json::to_vec(&rule.content)?);
        }
        Ok(fs::read(self.rule_path(rule)).or_else(|_| {
            model::builtin_seed(&rule.id)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        })?)
    }
    pub fn rule_source(&self, id: &str) -> Result<String> {
        let rule = self
            .snapshot()
            .rulesets
            .into_iter()
            .find(|r| r.id == id)
            .context("规则集不存在")?;
        let bytes = self.rule_bytes(&rule)?;
        if !rule.binary {
            return Ok(pretty(&serde_json::from_slice::<Value>(&bytes)?));
        }
        Ok(pretty(&shoes::rule_set::decompile_srs(&bytes)?))
    }
    pub fn save_rule_source(&self, id: &str, text: &str) -> Result<()> {
        let value: Value = serde_json::from_str(text)?;
        shoes::rule_set::validate_bytes(text.as_bytes(), false)?;
        let _op = self.operation.lock().unwrap();
        let before = self.snapshot();
        let mut candidate = before.clone();
        let rule = candidate
            .rulesets
            .iter_mut()
            .find(|r| r.id == id)
            .context("规则集不存在")?;
        rule.binary = false;
        rule.source.clear();
        rule.content = value;
        rule.updated = now();
        self.commit_state(&before, candidate)
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Some(core) = self.running.get_mut().unwrap().core.take() {
            let _ = runtime::executor().block_on(core.shutdown());
        }
        if let Some(snapshot) = self.proxy.get_mut().unwrap().take() {
            let _ = snapshot.restore();
        }
    }
}
fn copy_subscription_data(target: &mut model::Subscription, source: &model::Subscription) {
    target.nodes.clone_from(&source.nodes);
    target.updated = source.updated;
    target.upload = source.upload;
    target.download = source.download;
    target.total = source.total;
    target.expires = source.expires;
}
