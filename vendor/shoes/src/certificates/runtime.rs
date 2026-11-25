use std::io;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::task::JoinHandle;

use super::{Input, Source, Spec, visit_resolved};
use crate::config::ValidatedConfigs;

#[derive(Default)]
pub(crate) struct Registry {
    workers: Vec<Arc<Worker>>,
}

struct Worker {
    source: Arc<Source>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Worker {
    fn matches_source(&self, source: &Source) -> bool {
        // Implicit file-source names depend on discovery order, not identity.
        self.source.spec == source.spec
            && (self.source.name == source.name
                || (self.source.name.starts_with('@') && source.name.starts_with('@')))
    }

    async fn stop_task(&self) {
        let task = self.task.lock().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(task) = self.task.get_mut().take() {
            task.abort();
        }
    }
}

impl Registry {
    pub(crate) async fn prepare(
        validated: &mut ValidatedConfigs,
        previous: Option<&Self>,
    ) -> io::Result<Self> {
        let mut registry = Self::default();
        for source in &mut validated.certificates {
            let reused = previous.and_then(|previous| {
                previous
                    .workers
                    .iter()
                    .find(|worker| worker.matches_source(source))
            });
            let worker = if let Some(worker) = reused {
                worker.clone()
            } else {
                Arc::new(Worker {
                    source: source.clone(),
                    task: Mutex::new(None),
                })
            };
            *source = worker.source.clone();
            registry.workers.push(worker);
        }
        visit_resolved(&mut validated.configs, &mut |binding, _, _, _, _| {
            if let Some(source) = binding {
                *source = registry
                    .workers
                    .iter()
                    .find(|worker| worker.matches_source(source))
                    .expect("validated certificate source")
                    .source
                    .clone();
            }
            Ok(())
        })?;
        Ok(registry)
    }

    pub(crate) async fn start(&self) {
        for worker in &self.workers {
            let mut task = worker.task.lock();
            if task.is_some() {
                continue;
            }
            let source = worker.source.clone();
            *task = Some(tokio::spawn(async move { watch_files(&source).await }));
        }
    }

    pub(crate) async fn shutdown(&mut self) {
        for worker in self.workers.drain(..) {
            if Arc::strong_count(&worker) == 1 {
                worker.stop_task().await;
            }
        }
    }

    pub(crate) async fn retire_unused(&self, next: &Self) {
        for worker in &self.workers {
            if !next
                .workers
                .iter()
                .any(|retained| Arc::ptr_eq(worker, retained))
            {
                worker.stop_task().await;
            }
        }
    }

    pub(crate) async fn stop(&self) {
        for worker in &self.workers {
            worker.stop_task().await;
        }
    }
}

async fn watch_files(source: &Source) {
    const DEBOUNCE: Duration = Duration::from_millis(250);
    const RETRY: Duration = Duration::from_secs(1);
    const RECONCILE: Duration = Duration::from_secs(60);
    let Spec { cert, key } = &source.spec;
    let paths: Vec<_> = [cert, key]
        .into_iter()
        .filter_map(|input| match input {
            Input::File(path) => Some(path),
            Input::Inline(_) => None,
        })
        .collect();
    let (tx, mut changes) = tokio::sync::mpsc::channel(1);
    let mut _watcher = None;
    let mut refresh_watch = true;
    let mut watch_error = None;
    let mut next_warning = tokio::time::Instant::now();
    loop {
        // Build replacement watches before dropping the old ones, including symlink targets.
        if refresh_watch {
            watch_error = match crate::file_watcher::watch(&paths, tx.clone()) {
                Ok(next) => {
                    _watcher = Some(next);
                    None
                }
                Err(error) => Some(error),
            };
        }
        let result = source.refresh_files();
        if matches!(result, Ok(true)) {
            log::info!("Certificate source {} rotated", source.name);
        }
        if (watch_error.is_some() || result.is_err()) && tokio::time::Instant::now() >= next_warning
        {
            if let Some(error) = &watch_error {
                log::error!(
                    "Certificate source {} watch failed: {error}; using reconciliation",
                    source.name
                );
            }
            if let Err(error) = &result {
                log::error!(
                    "Certificate source {} update failed: {error}; retrying and retaining last good pair (expired certificates are not served)",
                    source.name
                );
            }
            next_warning = tokio::time::Instant::now() + RECONCILE;
        }
        // Retry separate writes promptly; reconcile missed events and watch failures periodically.
        let delay = if result.is_err() { RETRY } else { RECONCILE };
        tokio::select! {
            _ = changes.recv() => {
                crate::file_watcher::debounce(&mut changes, DEBOUNCE).await;
                refresh_watch = true;
            }
            _ = tokio::time::sleep(delay) => {
                refresh_watch = watch_error.is_some() || matches!(result, Ok(true));
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &std::path::Path) -> ValidatedConfigs {
        crate::config::create_server_configs(
            serde_yaml::from_str(&format!(
                r#"
- certificate_source: shared
  type: files
  cert: '{}'
  key: '{}'
- address: 127.0.0.1:18443
  protocol:
    type: tls
    default_tls_target:
      certificate_source: shared
      protocol: {{ type: socks }}
- address: 127.0.0.1:18444
  protocol:
    type: tls
    default_tls_target:
      certificate_source: shared
      protocol: {{ type: socks }}
"#,
                dir.join("cert.pem").display(),
                dir.join("key.pem").display()
            ))
            .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn one_worker_is_reused_and_removal_cancels_it() {
        let dir = tempfile::tempdir().unwrap();
        let first = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        std::fs::write(dir.path().join("cert.pem"), first.cert.pem()).unwrap();
        std::fs::write(
            dir.path().join("key.pem"),
            first.signing_key.serialize_pem(),
        )
        .unwrap();
        let mut validated = config(dir.path());
        let mut old = Registry::prepare(&mut validated, None).await.unwrap();
        assert_eq!(old.workers.len(), 1);
        old.start().await;
        tokio::task::yield_now().await;
        let mut replacement = config(dir.path());
        let mut next = Registry::prepare(&mut replacement, Some(&old))
            .await
            .unwrap();
        next.start().await;
        assert_eq!(next.workers.len(), 1);
        assert!(Arc::ptr_eq(&old.workers[0], &next.workers[0]));
        let second = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
        std::fs::write(dir.path().join("cert.pem"), second.cert.pem()).unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            validated.certificates[0].current().unwrap().cert[0],
            *first.cert.der()
        );
        std::fs::write(
            dir.path().join("key.pem"),
            second.signing_key.serialize_pem(),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while validated.certificates[0].current().unwrap().cert[0] != *second.cert.der() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            validated.certificates[0].current().unwrap().cert[0],
            *second.cert.der()
        );
        old.shutdown().await;
        assert!(!next.workers[0].task.lock().as_ref().unwrap().is_finished());
        let task = next.workers[0].task.lock().as_ref().unwrap().abort_handle();
        next.shutdown().await;
        assert!(task.is_finished());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn file_watches_follow_symlink_replacement_and_release_on_stop() {
        use std::os::unix::fs::symlink;
        tokio::time::timeout(Duration::from_secs(10), async {
            let dir = tempfile::tempdir().unwrap();
            let a = dir.path().join("a");
            let b = dir.path().join("b");
            std::fs::create_dir(&a).unwrap();
            std::fs::create_dir(&b).unwrap();
            let first = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            let second = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
            for (directory, certificate) in [(&a, &first), (&b, &second)] {
                std::fs::write(directory.join("cert.pem"), certificate.cert.pem()).unwrap();
                std::fs::write(
                    directory.join("key.pem"),
                    certificate.signing_key.serialize_pem(),
                )
                .unwrap();
            }
            let current = dir.path().join("current");
            symlink(&a, &current).unwrap();
            let mut validated = config(&current);
            let mut registry = Registry::prepare(&mut validated, None).await.unwrap();
            registry.start().await;
            tokio::task::yield_now().await;
            symlink(&b, dir.path().join("next")).unwrap();
            std::fs::rename(dir.path().join("next"), &current).unwrap();
            let source = &validated.certificates[0];
            tokio::time::timeout(Duration::from_secs(3), async {
                while source.current().unwrap().cert[0] != *second.cert.der() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let unchanged = source.current().unwrap();
            std::fs::write(b.join("cert.pem"), second.cert.pem()).unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(Arc::ptr_eq(&source.current().unwrap(), &unchanged));
            std::fs::remove_file(b.join("key.pem")).unwrap();
            std::fs::write(b.join("cert.pem"), first.cert.pem()).unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(Arc::ptr_eq(&source.current().unwrap(), &unchanged));
            std::fs::write(b.join("new.key"), first.signing_key.serialize_pem()).unwrap();
            std::fs::rename(b.join("new.key"), b.join("key.pem")).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while source.current().unwrap().cert[0] != *first.cert.der() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            registry.shutdown().await;
            std::fs::write(b.join("cert.pem"), second.cert.pem()).unwrap();
            std::fs::write(b.join("key.pem"), second.signing_key.serialize_pem()).unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(source.current().unwrap().cert[0], *first.cert.der());
        })
        .await
        .unwrap();
    }
}
