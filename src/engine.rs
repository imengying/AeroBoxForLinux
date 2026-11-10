use crate::{
    model::{self, Profile, RuleSet, Settings, State, Store, atomic_write, now, pretty},
    network, platform, script, subscription,
};
use anyhow::{Context, Result, bail, ensure};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashSet, VecDeque},
    fs,
    io::{BufRead, BufReader, Read},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Default)]
pub struct CoreStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub uptime: u64,
    pub proxy: bool,
}
#[derive(Default)]
struct Running {
    child: Option<Child>,
    config: Value,
    started: Option<Instant>,
    binary: Option<PathBuf>,
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
        push_log(&self.logs, line.into())
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
        self.logs.lock().unwrap().clear()
    }
    pub fn status(&self) -> CoreStatus {
        let run = self.running.lock().unwrap();
        CoreStatus {
            running: run.child.is_some(),
            pid: run.child.as_ref().map(Child::id),
            uptime: run.started.map(|s| s.elapsed().as_secs()).unwrap_or(0),
            proxy: self.proxy_active.load(Ordering::SeqCst),
        }
    }
    pub fn poll(&self) {
        if self.closing.load(Ordering::SeqCst) {
            return;
        }
        // Starting and stopping also reap children. Do not observe their
        // intermediate state or restart a child while either operation runs.
        let Ok(operation) = self.operation.try_lock() else {
            return;
        };
        let ended = {
            let mut run = self.running.lock().unwrap();
            match run.child.as_mut().and_then(|c| c.try_wait().ok()).flatten() {
                Some(status) => {
                    run.child = None;
                    Some((status, run.started.take().map(|t| t.elapsed())))
                }
                None => None,
            }
        };
        if let Some((status, uptime)) = ended {
            self.log(format!("内核退出: {status}"));
            if let Err(e) = self.restore_proxy() {
                self.log(format!("恢复代理失败: {e:#}"))
            };
            let restart = self.snapshot().settings.auto_restart
                && !status.success()
                && self.desired_running.load(Ordering::SeqCst);
            drop(operation);
            if restart {
                if uptime.is_some_and(|t| t < Duration::from_secs(2)) {
                    thread::sleep(Duration::from_secs(1));
                }
                if let Err(e) = self.start_inner() {
                    self.log(format!("重新启动失败: {e:#}"))
                }
            }
        }
    }
    pub fn core_binary(&self) -> Result<PathBuf> {
        let settings = self.snapshot().settings;
        self.core_binary_for(&settings)
    }
    fn core_binary_for(&self, settings: &Settings) -> Result<PathBuf> {
        if !settings.core_path.is_empty() {
            let p = PathBuf::from(&settings.core_path);
            ensure!(p.is_file(), "内核路径不存在");
            return Ok(p.canonicalize()?);
        }
        let local = self.dir().join("core/sing-box");
        if local.is_file() {
            return Ok(local.canonicalize()?);
        }
        for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
            let p = dir.join("sing-box");
            if p.is_file() {
                return Ok(p.canonicalize()?);
            }
        }
        bail!("尚未安装 sing-box 内核。请在设置中下载或选择内核文件。")
    }
    pub fn generate(&self, id: &str) -> Result<Value> {
        let state = self.snapshot();
        let profile = state
            .profiles
            .iter()
            .find(|p| p.id == id)
            .context("请选择一个配置")?;
        self.generate_profile(&state, profile)
    }
    pub fn generate_profile(&self, state: &State, profile: &Profile) -> Result<Value> {
        let mut config = profile.config.clone();
        ensure!(config.is_object(), "配置必须是 JSON 对象");
        let outbounds = config
            .as_object_mut()
            .unwrap()
            .entry("outbounds")
            .or_insert(json!([]))
            .as_array_mut()
            .context("outbounds 必须是数组")?;
        let mut tags: HashSet<String> = outbounds
            .iter()
            .filter_map(|v| v["tag"].as_str().map(str::to_string))
            .collect();
        let mut added = vec![];
        for id in &profile.subscriptions {
            let sub = state
                .subscriptions
                .iter()
                .find(|s| &s.id == id)
                .context("引用的订阅不存在")?;
            ensure!(
                !sub.nodes.is_empty(),
                "订阅「{}」没有节点，请先更新",
                sub.name
            );
            for node in &sub.nodes {
                let tag = node["tag"].as_str().context("订阅节点缺少名称")?;
                ensure!(
                    tags.insert(tag.into()),
                    "节点名称重复: {tag}，请设置订阅名称前缀"
                );
                outbounds.push(node.clone());
                added.push(Value::String(tag.into()));
            }
        }
        if !added.is_empty() {
            let group = outbounds
                .iter_mut()
                .find(|o| o["tag"] == "proxy" && o["type"] == "selector")
                .context("添加订阅需要一个标签为 proxy 的 selector 代理组")?;
            group["outbounds"] = json!(added);
        }
        let mut rules = vec![];
        for id in &profile.rulesets {
            let r = state
                .rulesets
                .iter()
                .find(|r| &r.id == id)
                .context("规则集不存在")?;
            let path = self.rule_path(r);
            if !r.binary {
                atomic_write(&path, &serde_json::to_vec(&r.content)?, 0o600)?
            } else {
                ensure!(path.is_file(), "请先下载二进制规则集「{}」", r.name)
            };
            rules.push(json!({"type":"local","tag":r.name,"format":if r.binary{"binary"}else{"source"},"path":path}));
        }
        if !rules.is_empty() {
            if config.get("route").is_none() {
                config["route"] = json!({})
            };
            let existing = config["route"]
                .as_object_mut()
                .context("route 必须是对象")?
                .entry("rule_set")
                .or_insert(json!([]))
                .as_array_mut()
                .context("route.rule_set 必须是数组")?;
            for rule in rules {
                ensure!(
                    !existing.iter().any(|r| r["tag"] == rule["tag"]),
                    "规则集标签重复"
                );
                existing.push(rule)
            }
        }
        let mut config = script::transform(&profile.script, "onGenerate", &config)?;
        ensure!(config.is_object(), "配置脚本必须返回对象");
        if config["experimental"]["clash_api"].is_object()
            && config["experimental"]["clash_api"].get("secret").is_none()
        {
            config["experimental"]["clash_api"]["secret"] = json!(profile.id);
        } else if config.get("experimental").is_none() {
            config["experimental"] = json!({"clash_api":{"secret":profile.id}});
        } else if config["experimental"].is_object()
            && config["experimental"].get("clash_api").is_none()
        {
            config["experimental"]["clash_api"] = json!({"secret":profile.id});
        }
        let rule_tag = |id: &str| {
            profile
                .rulesets
                .iter()
                .any(|item| item == id)
                .then(|| state.rulesets.iter().find(|rule| rule.id == id))
                .flatten()
                .map(|rule| rule.name.as_str())
                .filter(|tag| {
                    config["route"]["rule_set"].as_array().is_some_and(|rules| {
                        rules.iter().any(|rule| rule["tag"].as_str() == Some(*tag))
                    })
                })
        };
        let lan_tag = rule_tag(model::BUILTIN_LAN_ID);
        let ads_tag = rule_tag(model::BUILTIN_ADS_ID);
        crate::config::apply_profile_settings(&mut config, &state.settings, lan_tag, ads_tag)?;
        Ok(config)
    }
    fn rule_path(&self, r: &RuleSet) -> PathBuf {
        self.store.lock().unwrap().rule_path(r)
    }
    pub fn check_profile(&self, id: &str) -> Result<()> {
        self.check(&self.generate(id)?)
    }
    pub fn reload(&self) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        ensure!(self.status().running, "请先启动内核");
        let state = self.snapshot();
        let config = self.generate(&state.settings.active_profile)?;
        let binary = self.core_binary_for(&state.settings)?;
        self.check_with_binary(&config, &binary)?;
        self.ensure_tun_available(&config, &binary)?;
        let (previous, previous_binary) = self.running_config()?;
        let proxy = self.status().proxy;
        let result = self
            .stop_locked()
            .and_then(|()| self.start_config_locked(config, binary, proxy));
        if let Err(error) = result {
            let _ = self.stop_locked();
            let restore = self.start_config_locked(previous, previous_binary, proxy);
            return match restore {
                Ok(()) => Err(error.context("重新加载失败，已恢复原连接")),
                Err(restore) => {
                    let _ = self.stop_locked();
                    Err(error.context(format!("重新加载失败，恢复原连接失败：{restore:#}")))
                }
            };
        }
        Ok(())
    }
    pub fn check(&self, config: &Value) -> Result<()> {
        self.check_with_binary(config, &self.core_binary()?)
    }
    fn check_with_binary(&self, config: &Value, binary: &Path) -> Result<()> {
        let dir = self.dir().join("core");
        fs::create_dir_all(&dir)?;
        let tmp = tempfile::NamedTempFile::new_in(&dir)?;
        atomic_write(tmp.path(), &serde_json::to_vec(config)?, 0o600)?;
        let mut cmd = Command::new(binary);
        cmd.args(["check", "-c"]).arg(tmp.path()).arg("-D").arg(dir);
        run_command(cmd, Duration::from_secs(15)).context("sing-box 配置检查失败")?;
        Ok(())
    }
    pub fn start(&self) -> Result<()> {
        self.desired_running.store(true, Ordering::SeqCst);
        self.start_inner()
    }
    fn start_inner(&self) -> Result<()> {
        let _op = self.operation.lock().unwrap();
        ensure!(!self.closing.load(Ordering::SeqCst), "程序正在退出");
        ensure!(self.desired_running.load(Ordering::SeqCst), "启动已取消");
        ensure!(!self.status().running, "内核已运行");
        let state = self.snapshot();
        let config = self.generate(&state.settings.active_profile)?;
        let binary = self.core_binary_for(&state.settings)?;
        self.check_with_binary(&config, &binary)?;
        self.ensure_tun_available(&config, &binary)?;
        let result = self.start_config_locked(config, binary, state.settings.system_proxy);
        if result.is_err() {
            let _ = self.stop_locked();
        }
        result
    }
    fn start_config_locked(&self, config: Value, binary: PathBuf, proxy: bool) -> Result<()> {
        ensure!(!self.closing.load(Ordering::SeqCst), "程序正在退出");
        ensure!(self.desired_running.load(Ordering::SeqCst), "启动已取消");
        let dir = self.dir().join("core");
        let path = dir.join("config.json");
        atomic_write(&path, &serde_json::to_vec_pretty(&config)?, 0o600)?;
        let mut cmd = Command::new(&binary);
        cmd.args(["run", "--disable-color", "-c"])
            .arg(path)
            .arg("-D")
            .arg(&dir)
            .current_dir(dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        // Only async-signal-safe libc calls run between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) < 0 {
                    return Err(std::io::Error::last_os_error());
                };
                Ok(())
            });
        }
        let mut child = cmd.spawn().context("无法启动内核")?;
        if let Some(stdout) = child.stdout.take() {
            read_logs(stdout, self.logs.clone())
        };
        if let Some(stderr) = child.stderr.take() {
            read_logs(stderr, self.logs.clone())
        };
        {
            let mut r = self.running.lock().unwrap();
            r.child = Some(child);
            r.config = config;
            r.started = Some(Instant::now());
            r.binary = Some(binary);
        }
        thread::sleep(Duration::from_millis(200));
        {
            let mut r = self.running.lock().unwrap();
            if let Some(exit) = r.child.as_mut().unwrap().try_wait()? {
                r.child = None;
                r.started = None;
                bail!("内核启动后退出: {exit}。详情见日志。")
            }
        }
        // The cache file can restore a mode different from default_mode. Match
        // the generated configuration before exposing the connection as ready.
        let api = self.running.lock().unwrap().config["experimental"]["clash_api"].clone();
        if api["external_controller"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
        {
            let mode = api["default_mode"].as_str().unwrap_or("rule");
            let until = Instant::now() + Duration::from_secs(3);
            loop {
                match self.api_with_timeout(
                    "PATCH",
                    "/configs",
                    Some(&json!({"mode":mode})),
                    Duration::from_millis(500),
                ) {
                    Ok(_) => break,
                    Err(error) if Instant::now() >= until => {
                        return Err(error.context("内核模式同步失败"));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(30)),
                }
            }
        }
        self.log("内核已启动");
        if proxy {
            self.set_proxy(true)?
        };
        Ok(())
    }
    pub fn stop(&self) -> Result<()> {
        self.desired_running.store(false, Ordering::SeqCst);
        let _op = self.operation.lock().unwrap();
        self.stop_locked()
    }
    fn stop_locked(&self) -> Result<()> {
        let mut child = {
            let mut r = self.running.lock().unwrap();
            r.started = None;
            r.child.take()
        };
        let result = (|| -> Result<()> {
            if let Some(ref mut child) = child {
                signal_group(child.id(), libc::SIGTERM);
                let deadline = Instant::now() + Duration::from_secs(4);
                loop {
                    if child.try_wait()?.is_some() {
                        break;
                    };
                    if Instant::now() > deadline {
                        signal_group(child.id(), libc::SIGKILL);
                        child.wait()?;
                        break;
                    };
                    thread::sleep(Duration::from_millis(30))
                }
                self.log("内核已停止");
                Ok(())
            } else {
                Ok(())
            }
        })();
        let restore = self.restore_proxy();
        result.and(restore)
    }
    pub fn set_proxy(&self, enabled: bool) -> Result<()> {
        if !enabled {
            return self.restore_proxy();
        }
        let mut proxy = self.proxy.lock().unwrap();
        if proxy.is_some() {
            return Ok(());
        }
        let config = {
            let run = self.running.lock().unwrap();
            ensure!(run.child.is_some(), "请先启动内核");
            run.config.clone()
        };
        let inbound = config["inbounds"]
            .as_array()
            .and_then(|a| {
                a.iter()
                    .filter(|v| {
                        ["mixed", "http", "socks"].contains(&v["type"].as_str().unwrap_or(""))
                            && v["users"].as_array().is_none_or(Vec::is_empty)
                            && v["listen_port"]
                                .as_u64()
                                .is_some_and(|port| (1..=65535).contains(&port))
                    })
                    .min_by_key(|v| {
                        if v["tag"] == "aerobox-download-in" {
                            0
                        } else {
                            1
                        }
                    })
            })
            .context("配置没有 HTTP / SOCKS 入站")?;
        ensure!(
            inbound["users"]
                .as_array()
                .is_none_or(|users| users.is_empty()),
            "系统代理需要无认证的本地 HTTP / SOCKS 入站"
        );
        let host = match inbound["listen"].as_str().unwrap_or("127.0.0.1") {
            "0.0.0.0" | "" => "127.0.0.1",
            "::" => "::1",
            h => h,
        };
        let port = inbound["listen_port"].as_u64().context("入站缺少端口")?;
        let server = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        *proxy = Some(platform::enable_proxy(
            &server,
            inbound["type"].as_str().unwrap_or("mixed"),
        )?);
        self.proxy_active.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn restore_proxy(&self) -> Result<()> {
        let mut proxy = self.proxy.lock().unwrap();
        if let Some(s) = &*proxy {
            s.restore()?;
            *proxy = None;
            self.proxy_active.store(false, Ordering::SeqCst);
        };
        Ok(())
    }

    fn running_config(&self) -> Result<(Value, PathBuf)> {
        let running = self.running.lock().unwrap();
        ensure!(running.child.is_some(), "请先启动内核");
        Ok((
            running.config.clone(),
            running.binary.clone().context("运行内核路径不可用")?,
        ))
    }

    pub fn set_routing_mode(&self, mode: &str) -> Result<()> {
        ensure!(
            matches!(mode, "rule" | "global" | "direct"),
            "无效的出站模式"
        );
        let _op = self.operation.lock().unwrap();
        let previous = self.snapshot().settings.routing_mode;
        let running = self.status().running;
        if running && let Err(error) = self.set_runtime_mode(mode) {
            return Err(match self.set_runtime_mode(&previous) {
                Ok(()) => error,
                Err(restore) => error.context(format!("恢复出站模式失败：{restore:#}")),
            });
        }
        if let Err(error) = self.update(|state| {
            state.settings.routing_mode = mode.into();
            Ok(())
        }) {
            if running && let Err(restore) = self.set_runtime_mode(&previous) {
                return Err(error.context(format!("恢复出站模式失败：{restore:#}")));
            }
            return Err(error);
        }
        if running {
            self.running.lock().unwrap().config["experimental"]["clash_api"]["default_mode"] =
                json!(mode);
        }
        Ok(())
    }

    fn set_runtime_mode(&self, mode: &str) -> Result<()> {
        self.api("PATCH", "/configs", Some(&json!({"mode":mode})))?;
        let actual = self.api("GET", "/configs", None)?;
        ensure!(actual["mode"].as_str() == Some(mode), "内核未应用出站模式");
        Ok(())
    }

    /// Validate before interrupting the current core. If the new listener or
    /// TUN cannot start, restore both persisted settings and the old process.
    pub fn apply_settings(&self, settings: Settings) -> Result<()> {
        settings.validate()?;
        let url = url::Url::parse(&settings.test_url).context("测速地址无效")?;
        ensure!(
            matches!(url.scheme(), "http" | "https"),
            "测速地址必须使用 HTTP 或 HTTPS"
        );
        ensure!(
            (500..=60_000).contains(&settings.test_timeout),
            "测速超时必须在 500 到 60000 毫秒之间"
        );
        let _op = self.operation.lock().unwrap();
        let previous_settings = self.snapshot().settings;
        if !self.status().running {
            return self.update(|state| {
                state.settings = settings;
                Ok(())
            });
        }
        let mut candidate = self.snapshot();
        candidate.settings = settings.clone();
        candidate.validate()?;
        let profile = candidate
            .profiles
            .iter()
            .find(|profile| profile.id == candidate.settings.active_profile)
            .context("请选择一个配置")?;
        let config = self.generate_profile(&candidate, profile)?;
        let binary = self.core_binary_for(&settings)?;
        self.check_with_binary(&config, &binary)?;
        self.ensure_tun_available(&config, &binary)?;
        let (old_config, old_binary) = self.running_config()?;
        let old_proxy = self.status().proxy;
        let proxy = if previous_settings.system_proxy == settings.system_proxy {
            old_proxy
        } else {
            settings.system_proxy
        };
        self.update(|state| {
            state.settings = settings;
            Ok(())
        })?;
        let result = if config == old_config && binary == old_binary {
            if proxy == old_proxy {
                Ok(())
            } else {
                self.set_proxy(proxy)
            }
        } else {
            self.stop_locked()
                .and_then(|()| self.start_config_locked(config, binary, proxy))
        };
        if let Err(error) = result {
            let restore_settings = self.update(|state| {
                state.settings = previous_settings;
                Ok(())
            });
            let _ = self.stop_locked();
            let restore_core = self.start_config_locked(old_config, old_binary, old_proxy);
            if restore_core.is_err() {
                let _ = self.stop_locked();
            }
            if let Err(restore) = restore_settings.and(restore_core) {
                return Err(error.context(format!("应用设置失败，恢复失败：{restore:#}")));
            }
            return Err(error.context("应用设置失败，已恢复原连接"));
        }
        Ok(())
    }

    pub fn network_info(&self) -> Result<network::NetworkInfo> {
        let (pid, config) = {
            let running = self.running.lock().unwrap();
            (
                running.child.as_ref().map(Child::id),
                running.child.as_ref().map(|_| running.config.clone()),
            )
        };
        let ipv6 = self.snapshot().settings.ipv6;
        let client = network::client(config.as_ref(), Duration::from_secs(4))?;
        let info = network::detect(client, ipv6, config.is_some())?;
        let unchanged = {
            let running = self.running.lock().unwrap();
            running.child.as_ref().map(Child::id) == pid
                && config
                    .as_ref()
                    .is_none_or(|config| &running.config == config)
        };
        ensure!(
            unchanged && self.snapshot().settings.ipv6 == ipv6,
            "连接已变化，请重新检测"
        );
        Ok(info)
    }

    pub fn memory_usage(&self) -> network::MemoryUsage {
        network::memory_usage(self.status().pid)
    }

    fn ensure_tun_available(&self, config: &Value, binary: &Path) -> Result<()> {
        if config["inbounds"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["type"] == "tun"))
        {
            ensure!(
                tun_available(binary)?,
                "虚拟网卡需要网络管理权限，请先在设置中授权"
            );
        }
        Ok(())
    }

    pub fn tun_available(&self) -> Result<bool> {
        tun_available(&self.core_binary()?)
    }

    /// Called only after the user chooses the dedicated TUN authorization action.
    pub fn authorize_tun(&self) -> Result<()> {
        let binary = self.core_binary()?;
        ensure!(
            binary.file_name().is_some_and(|name| name == "sing-box"),
            "只允许授权 sing-box 内核文件"
        );
        let metadata = fs::metadata(&binary)?;
        ensure!(
            metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
            "内核不是可执行文件"
        );
        ensure!(
            metadata.permissions().mode() & 0o022 == 0,
            "请先移除内核的组或其他用户写入权限"
        );
        let mut header = [0; 4];
        fs::File::open(&binary)?.read_exact(&mut header)?;
        ensure!(&header == b"\x7fELF", "只允许授权 sing-box 原生可执行文件");
        let mut version = Command::new(&binary);
        version.arg("version");
        ensure!(
            run_command(version, Duration::from_secs(5))?.starts_with("sing-box version "),
            "所选文件不是 sing-box 内核"
        );
        let pkexec = Path::new("/usr/bin/pkexec");
        ensure!(pkexec.is_file(), "请安装 polkit 并启用桌面授权代理");
        let setcap = ["/usr/sbin/setcap", "/usr/bin/setcap", "/sbin/setcap"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .context("请安装 libcap（setcap）")?;
        let mut command = Command::new(pkexec);
        command
            .arg(setcap)
            .arg("cap_net_admin,cap_net_bind_service=+ep")
            .arg(&binary);
        run_command(command, Duration::from_secs(120)).context("虚拟网卡授权未完成")?;
        ensure!(
            tun_available(&binary)?,
            "权限未生效，请检查系统能力限制或文件系统挂载选项"
        );
        Ok(())
    }
    pub fn api(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let timeout = if path
            .split('?')
            .next()
            .is_some_and(|p| p.ends_with("/delay"))
        {
            Duration::from_millis(
                u64::from(self.snapshot().settings.test_timeout).min(60_000) + 2000,
            )
        } else {
            Duration::from_secs(15)
        };
        self.api_with_timeout(method, path, body, timeout)
    }

    pub fn traffic(&self) -> Result<crate::traffic::Counters> {
        crate::traffic::Counters::from_api(&self.api_with_timeout(
            "GET",
            "/connections",
            None,
            Duration::from_secs(2),
        )?)
    }

    fn api_with_timeout(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        timeout: Duration,
    ) -> Result<Value> {
        let api = {
            let r = self.running.lock().unwrap();
            ensure!(r.child.is_some(), "内核未运行");
            r.config["experimental"]["clash_api"].clone()
        };
        let raw = api["external_controller"]
            .as_str()
            .context("配置未启用 Clash API")?;
        let mut endpoint =
            url::Url::parse(&format!("http://{raw}{path}")).context("Clash API 地址无效")?;
        match endpoint.host() {
            Some(url::Host::Ipv4(ip)) if ip.is_unspecified() => {
                endpoint.set_host(Some("127.0.0.1"))?
            }
            Some(url::Host::Ipv6(ip)) if ip.is_unspecified() => endpoint.set_host(Some("[::1]"))?,
            _ => {}
        };
        let client = Client::builder().no_proxy().timeout(timeout).build()?;
        let mut req = client
            .request(Method::from_bytes(method.as_bytes())?, endpoint)
            .bearer_auth(api["secret"].as_str().unwrap_or(""));
        if let Some(v) = body {
            req = req.json(v)
        };
        let response = req.send()?.error_for_status()?;
        let bytes = response.bytes()?;
        if bytes.is_empty() {
            Ok(json!({}))
        } else {
            Ok(serde_json::from_slice(&bytes)?)
        }
    }
    fn client(&self) -> Result<Client> {
        let config = {
            let running = self.running.lock().unwrap();
            running.child.as_ref().map(|_| running.config.clone())
        };
        network::client(config.as_ref(), Duration::from_secs(60))
    }
    fn download(&self, url: &str) -> Result<(Vec<u8>, reqwest::header::HeaderMap)> {
        let parsed = url::Url::parse(url)?;
        ensure!(
            ["http", "https"].contains(&parsed.scheme()),
            "仅支持 HTTP / HTTPS 地址"
        );
        let r = self.client()?.get(url).send()?.error_for_status()?;
        let headers = r.headers().clone();
        let mut bytes = vec![];
        r.take(128 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 128 * 1024 * 1024, "下载超过 128 MiB");
        Ok((bytes, headers))
    }
    pub fn update_subscription(&self, id: &str) -> Result<()> {
        let mut sub = self
            .snapshot()
            .subscriptions
            .into_iter()
            .find(|s| s.id == id)
            .context("订阅不存在")?;
        let bytes = if sub.source.starts_with("https://") || sub.source.starts_with("http://") {
            let (bytes, headers) = self.download(&sub.source)?;
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
        let nodes = subscription::parse(std::str::from_utf8(&bytes)?)?;
        let include = if sub.include.is_empty() {
            None
        } else {
            Some(regex::Regex::new(&sub.include).context("包含条件无效")?)
        };
        let exclude = if sub.exclude.is_empty() {
            None
        } else {
            Some(regex::Regex::new(&sub.exclude).context("排除条件无效")?)
        };
        let nodes: Vec<_> = nodes
            .into_iter()
            .filter_map(|mut n| {
                let tag = n["tag"].as_str().unwrap_or("");
                if include.as_ref().is_some_and(|r| !r.is_match(tag))
                    || exclude.as_ref().is_some_and(|r| r.is_match(tag))
                {
                    return None;
                };
                n["tag"] = json!(format!("{}{tag}", sub.prefix));
                Some(n)
            })
            .collect();
        sub.nodes = serde_json::from_value(script::transform(
            &sub.script,
            "onSubscribe",
            &json!(nodes),
        )?)
        .context("订阅脚本应返回节点数组")?;
        model::validate_nodes(&sub.nodes)?;
        sub.updated = now();
        self.update(|state| {
            let target = state
                .subscriptions
                .iter_mut()
                .find(|s| s.id == id)
                .context("订阅已被删除")?;
            ensure!(
                target.source == sub.source
                    && target.script == sub.script
                    && target.include == sub.include
                    && target.exclude == sub.exclude
                    && target.prefix == sub.prefix,
                "订阅在更新期间已被编辑，请重试"
            );
            target.nodes = sub.nodes;
            target.updated = sub.updated;
            target.upload = sub.upload;
            target.download = sub.download;
            target.total = sub.total;
            target.expires = sub.expires;
            Ok(())
        })?;
        self.log(format!("订阅「{}」更新完成", sub.name));
        Ok(())
    }
    pub fn update_all_subscriptions(&self) -> Result<usize> {
        let mut updated = 0;
        let mut errors = Vec::new();
        for subscription in self.snapshot().subscriptions {
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
        let bytes = if r.source.starts_with("http://") || r.source.starts_with("https://") {
            self.download(&r.source)?.0
        } else {
            fs::read(&r.source)?
        };
        if r.binary {
            ensure!(bytes.starts_with(b"SRS"), "文件不是有效 SRS 规则集")
        } else {
            r.content = serde_json::from_slice(&bytes)?;
            ensure!(r.content["rules"].is_array(), "规则集缺少 rules 数组")
        };
        let path = self.rule_path(&r);
        self.update(|state| {
            let target = state
                .rulesets
                .iter_mut()
                .find(|s| s.id == id)
                .context("规则集已被删除")?;
            ensure!(
                target.source == r.source && target.binary == r.binary,
                "规则集更新期间被编辑，请重试"
            );
            atomic_write(&path, &bytes, 0o600)?;
            target.content = r.content;
            target.updated = now();
            Ok(())
        })?;
        self.log(format!("规则集「{}」更新完成", r.name));
        Ok(())
    }
    pub fn rule_source(&self, id: &str) -> Result<String> {
        let r = self
            .snapshot()
            .rulesets
            .into_iter()
            .find(|r| r.id == id)
            .context("规则集不存在")?;
        if !r.binary {
            return Ok(pretty(&r.content));
        };
        if r.updated == 0 && r.source.is_empty() && !self.rule_path(&r).exists() {
            return Ok(pretty(&r.content));
        }
        let dir = tempfile::tempdir()?;
        let output = dir.path().join("rules.json");
        let mut cmd = Command::new(self.core_binary()?);
        cmd.args(["rule-set", "decompile", "--output"])
            .arg(&output)
            .arg(self.rule_path(&r));
        run_command(cmd, Duration::from_secs(20))?;
        Ok(fs::read_to_string(output)?)
    }
    pub fn save_rule_source(&self, id: &str, text: &str) -> Result<()> {
        let value: Value = serde_json::from_str(text)?;
        ensure!(value["rules"].is_array(), "缺少 rules 数组");
        let r = self
            .snapshot()
            .rulesets
            .into_iter()
            .find(|r| r.id == id)
            .context("规则集不存在")?;
        let path = self.rule_path(&r);
        let compiled = if r.binary {
            let dir = tempfile::tempdir()?;
            let src = dir.path().join("rules.json");
            let dst = dir.path().join("rules.srs");
            fs::write(&src, text)?;
            let mut cmd = Command::new(self.core_binary()?);
            cmd.args(["rule-set", "compile", "--output"])
                .arg(&dst)
                .arg(src);
            run_command(cmd, Duration::from_secs(20))?;
            Some(fs::read(dst)?)
        } else {
            None
        };
        self.update(|s| {
            let target = s
                .rulesets
                .iter_mut()
                .find(|r| r.id == id)
                .context("规则集已被删除")?;
            ensure!(
                target.binary == r.binary
                    && target.source == r.source
                    && target.content == r.content
                    && target.updated == r.updated,
                "规则集在保存期间已被修改，请重新打开编辑器"
            );
            if let Some(bytes) = compiled {
                atomic_write(&path, &bytes, 0o600)?;
            }
            target.content = value;
            target.updated = now();
            Ok(())
        })
    }
    pub fn install_core(&self) -> Result<()> {
        let release: Value = self
            .client()?
            .get("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
            .send()?
            .error_for_status()?
            .json()?;
        let version = release["tag_name"]
            .as_str()
            .context("无法读取内核版本")?
            .trim_start_matches('v');
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => bail!("不支持的架构"),
        };
        let name = format!("sing-box-{version}-linux-{arch}.tar.gz");
        let asset = release["assets"]
            .as_array()
            .context("缺少内核文件")?
            .iter()
            .find(|a| a["name"] == name)
            .context("此版本不包含当前架构的内核")?;
        let digest = asset["digest"]
            .as_str()
            .and_then(|d| d.strip_prefix("sha256:"))
            .context("发布缺少 SHA256 校验摘要")?;
        self.log(format!("正在下载 sing-box {version}"));
        let bytes = self
            .download(
                asset["browser_download_url"]
                    .as_str()
                    .context("下载链接缺失")?,
            )?
            .0;
        ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == digest,
            "内核 SHA256 校验失败"
        );
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]));
        for entry in tar.entries()? {
            let mut entry = entry?;
            if entry.header().entry_type().is_file()
                && entry.path()?.file_name().is_some_and(|n| n == "sing-box")
            {
                ensure!(entry.size() <= 128 * 1024 * 1024, "内核文件过大");
                let mut binary = vec![];
                entry.read_to_end(&mut binary)?;
                let _op = self.operation.lock().unwrap();
                atomic_write(&self.dir().join("core/sing-box"), &binary, 0o700)?;
                self.log(format!(
                    "sing-box {version} 安装完成{}",
                    if self.status().running {
                        "，下次启动生效"
                    } else {
                        ""
                    }
                ));
                return Ok(());
            }
        }
        bail!("归档内未找到 sing-box")
    }
}

fn tun_available(binary: &Path) -> Result<bool> {
    if fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .is_err()
    {
        return Ok(false);
    }
    let status = fs::read_to_string("/proc/self/status")?;
    let capability = 1_u64 << 12; // CAP_NET_ADMIN
    let bits = |name: &str| -> Option<u64> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
    };
    if bits("CapEff:").is_some_and(|effective| effective & capability != 0) {
        return Ok(true);
    }
    if bits("CapBnd:").is_none_or(|bounding| bounding & capability == 0)
        || status.lines().any(|line| {
            line.strip_prefix("NoNewPrivs:")
                .is_some_and(|value| value.trim() == "1")
        })
    {
        return Ok(false);
    }
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(binary.as_os_str().as_bytes())?;
    let mut attribute = [0_u8; 24];
    let length = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"security.capability".as_ptr(),
            attribute.as_mut_ptr().cast(),
            attribute.len(),
        )
    };
    if length < 12 {
        return Ok(false);
    }
    let magic = u32::from_le_bytes(attribute[0..4].try_into().unwrap());
    let permitted = u32::from_le_bytes(attribute[4..8].try_into().unwrap());
    Ok(magic & 1 != 0 && permitted & capability as u32 != 0)
}

fn push_log(logs: &Mutex<VecDeque<String>>, line: String) {
    let mut logs = logs.lock().unwrap();
    logs.push_back(line);
    while logs.len() > 2000 {
        logs.pop_front();
    }
}
fn read_logs(reader: impl Read + Send + 'static, logs: Arc<Mutex<VecDeque<String>>>) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(s) => push_log(&logs, s),
                Err(_) => break,
            }
        }
    });
}
fn signal_group(pid: u32, signal: i32) {
    unsafe {
        libc::kill(-(pid as i32), signal);
    }
}
pub fn run_command(mut cmd: Command, timeout: Duration) -> Result<String> {
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = thread::spawn(move || {
        let mut b = vec![];
        let _ = stdout.take(8 * 1024 * 1024).read_to_end(&mut b);
        b
    });
    let err = thread::spawn(move || {
        let mut b = vec![];
        let _ = stderr.take(8 * 1024 * 1024).read_to_end(&mut b);
        b
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        };
        if Instant::now() > deadline {
            signal_group(child.id(), libc::SIGKILL);
            child.wait()?;
            bail!("命令执行超时")
        };
        thread::sleep(Duration::from_millis(20))
    };
    let text = String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned();
    let errors = String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned();
    ensure!(status.success(), "{text}{errors}");
    Ok(text)
}
