//! Controlled embedding API for the AeroBox host.
//!
//! Configuration is a JSON array of shoes `Config` values, not sing-box JSON.
//! The runtime owns duplicates of supplied TUN descriptors. Call `shutdown`
//! before destroying the Tokio runtime so connection cleanup can finish.

use crate::{config::Config, resolver::Resolver};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
pub use tokio_util::sync::CancellationToken;
pub use crate::control::probes::probe_outbound;

/// Android must supply the current physical network's DNS servers and protect
/// every outgoing socket before connect/bind. Callbacks must not reenter the core.
pub trait Platform: Send + Sync + 'static {
    fn protect(&self, fd: i32) -> io::Result<()>;
    fn dns_servers(&self) -> io::Result<Vec<SocketAddr>>;
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Stats {
    pub upload_total: u64,
    pub download_total: u64,
    pub active_connections: usize,
}

type Reply<T> = oneshot::Sender<io::Result<T>>;
pub(crate) enum Command {
    Reload(Vec<Config>, Reply<()>),
    NetworkChanged(Reply<()>),
    Stats(Reply<Stats>),
    Connections(Reply<serde_json::Value>),
    Close(String, Reply<()>),
    UrlTest {
        name: String,
        url: String,
        timeout_ms: u64,
        reply: Reply<u16>,
    },
    Select(String, String, Reply<()>),
    CloseAll(Reply<()>),
    Shutdown(Reply<()>),
}

/// One running core. The backend's resource limits and Android socket callback
/// are process-wide, so starting a second instance returns `AlreadyExists`.
pub struct EmbeddedCore {
    commands: mpsc::Sender<Command>,
    task: Mutex<Option<JoinHandle<io::Result<()>>>>,
    running: Arc<AtomicBool>,
}

impl EmbeddedCore {
    pub fn parse_json(json: &str) -> io::Result<Vec<Config>> {
        serde_json::from_str(json)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }

    pub async fn check(configs: Vec<Config>) -> io::Result<()> {
        crate::process::check_embedded(configs).await
    }

    pub async fn check_json(json: &str) -> io::Result<()> {
        Self::check(Self::parse_json(json)?).await
    }

    pub async fn start_json(json: &str, platform: Option<Arc<dyn Platform>>) -> io::Result<Self> {
        Self::start(Self::parse_json(json)?, platform).await
    }

    pub async fn start(
        configs: Vec<Config>,
        platform: Option<Arc<dyn Platform>>,
    ) -> io::Result<Self> {
        Self::start_cancellable(configs, platform, CancellationToken::new()).await
    }

    pub async fn start_cancellable(configs: Vec<Config>, platform: Option<Arc<dyn Platform>>, cancelled: CancellationToken) -> io::Result<Self> {
        #[cfg(target_os = "android")]
        if platform.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Android requires protect and physical-network DNS callbacks",
            ));
        }
        #[cfg(not(any(target_os = "android", target_os = "ios", all(unix, feature = "ffi"))))]
        if platform.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "platform socket callbacks require the ffi feature on this target",
            ));
        }
        let context = PlatformContext::acquire(platform)?;
        let process = crate::process::EmbeddedProcess::start(configs, &context, &cancelled).await?;
        let (commands, receiver) = mpsc::channel(32);
        let running = Arc::new(AtomicBool::new(true));
        let state = running.clone();
        let task = tokio::spawn(async move {
            struct RunningFlag(Arc<AtomicBool>);
            impl Drop for RunningFlag {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            let _running = RunningFlag(state);
            process.run(receiver, context).await
        });
        Ok(Self {
            commands,
            task: Mutex::new(Some(task)),
            running,
        })
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    async fn request<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> io::Result<T> {
        let (reply, received) = oneshot::channel();
        self.commands
            .send(make(reply))
            .await
            .map_err(|_| stopped())?;
        received.await.map_err(|_| stopped())?
    }

    pub async fn reload(&self, configs: Vec<Config>) -> io::Result<()> {
        self.request(|reply| Command::Reload(configs, reply)).await
    }
    pub async fn reload_json(&self, json: &str) -> io::Result<()> {
        self.reload(Self::parse_json(json)?).await
    }
    pub async fn network_changed(&self) -> io::Result<()> {
        self.request(Command::NetworkChanged).await
    }
    pub async fn stats(&self) -> io::Result<Stats> {
        self.request(Command::Stats).await
    }
    /// At most 500 live connection records; totals include every tracked flow.
    pub async fn connections(&self) -> io::Result<serde_json::Value> {
        self.request(Command::Connections).await
    }
    pub async fn close_connection(&self, id: String) -> io::Result<()> {
        self.request(|reply| Command::Close(id, reply)).await
    }
    pub async fn urltest(&self, name: String, url: String, timeout_ms: u64) -> io::Result<u16> {
        self.request(|reply| Command::UrlTest {
            name,
            url,
            timeout_ms,
            reply,
        })
        .await
    }
    pub async fn select(&self, group: String, member: String) -> io::Result<()> {
        self.request(|reply| Command::Select(group, member, reply)).await
    }
    pub async fn close_all(&self) -> io::Result<()> {
        self.request(Command::CloseAll).await
    }
    pub async fn shutdown(&self) -> io::Result<()> {
        let mut task = self.task.lock().await;
        let Some(worker) = task.take() else {
            return Ok(());
        };
        // The worker also shuts down when all command senders are dropped.
        let _ = self.request(Command::Shutdown).await;
        worker.await.map_err(io::Error::other)?
    }
}

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "embedded core is stopped")
}

struct Bootstrap {
    resolver: Arc<dyn Resolver>,
    endpoints: Vec<SocketAddr>,
}
static BOOTSTRAP: parking_lot::RwLock<Option<Bootstrap>> = parking_lot::RwLock::new(None);

pub(crate) fn platform_resolver() -> Option<Arc<dyn Resolver>> {
    BOOTSTRAP
        .read()
        .as_ref()
        .map(|state| state.resolver.clone())
}
pub(crate) fn platform_dns_endpoints() -> Option<Vec<SocketAddr>> {
    BOOTSTRAP
        .read()
        .as_ref()
        .map(|state| state.endpoints.clone())
}

pub(crate) struct PlatformContext {
    platform: Option<Arc<dyn Platform>>,
    #[cfg(any(target_os = "android", target_os = "ios", all(unix, feature = "ffi")))]
    protector: Arc<dyn crate::tun::SocketProtector>,
    _lease: OwnedSemaphorePermit,
}

impl PlatformContext {
    fn acquire(platform: Option<Arc<dyn Platform>>) -> io::Result<Self> {
        static ACTIVE: OnceLock<Arc<Semaphore>> = OnceLock::new();
        let lease = ACTIVE
            .get_or_init(|| Arc::new(Semaphore::new(1)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "an embedded core is already active",
                )
            })?;
        #[cfg(any(target_os = "android", target_os = "ios", all(unix, feature = "ffi")))]
        let protector: Arc<dyn crate::tun::SocketProtector> = {
            let platform = platform.clone();
            Arc::new(crate::tun::FnSocketProtector::new(move |fd| {
                platform
                    .as_ref()
                    .map_or(Ok(()), |platform| platform.protect(fd))
            }))
        };
        #[cfg(any(target_os = "android", target_os = "ios", all(unix, feature = "ffi")))]
        crate::tun::set_global_socket_protector(protector.clone());
        Ok(Self {
            platform,
            #[cfg(any(target_os = "android", target_os = "ios", all(unix, feature = "ffi")))]
            protector,
            _lease: lease,
        })
    }

    pub(crate) fn refresh_dns(&self) -> io::Result<()> {
        let Some(platform) = &self.platform else {
            return Ok(());
        };
        let endpoints = platform.dns_servers()?;
        if endpoints.is_empty()
            || endpoints.iter().any(|endpoint| {
                endpoint.port() == 0
                    || endpoint.ip().is_unspecified()
                    || endpoint.ip().is_multicast()
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "physical network has no usable DNS endpoints",
            ));
        }
        let resolver = crate::dns::controlled_bootstrap(&endpoints)?;
        let old = BOOTSTRAP.write().replace(Bootstrap {
            resolver,
            endpoints,
        });
        drop(old);
        Ok(())
    }
}

impl Drop for PlatformContext {
    fn drop(&mut self) {
        let previous = BOOTSTRAP.write().take();
        drop(previous);
        #[cfg(any(target_os = "android", target_os = "ios", all(unix, feature = "ffi")))]
        crate::tun::clear_global_socket_protector_if_current(&self.protector);
    }
}

static DNS_CACHE: AtomicBool = AtomicBool::new(true);
/// Cache preference is applied to new resolver generations during start/reload.
pub fn set_dns_cache(enabled: bool) { DNS_CACHE.store(enabled, Ordering::Release); }
pub(crate) fn dns_cache_enabled() -> bool { DNS_CACHE.load(Ordering::Acquire) }

static STATE_DIRECTORY: parking_lot::RwLock<Option<std::path::PathBuf>> = parking_lot::RwLock::new(None);
pub fn set_state_directory(path: std::path::PathBuf) -> io::Result<()> {
    if !path.is_absolute() { return Err(io::Error::new(io::ErrorKind::InvalidInput,"network state directory must be absolute")); }
    *STATE_DIRECTORY.write() = Some(path);
    Ok(())
}
pub(crate) fn state_directory() -> std::path::PathBuf {
    STATE_DIRECTORY.read().clone().unwrap_or_else(||std::path::PathBuf::from("/run/aerobox"))
}
