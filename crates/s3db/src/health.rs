//! A health check that actually reaches the backend, every time -- as
//! opposed to one that could be answered from memory. If a caller builds
//! [`HealthProbe`] around a [`Backend`] that includes
//! [`crate::cache::CachedBackend`] (or any other decorator that can answer
//! `get` without touching the network), `ready()` ends up measuring "do I
//! have a copy of this in RAM", not "can I reach the backend right now" --
//! exactly backwards from what a health check feeding an orchestrator's
//! restart/routing decisions needs. This type doesn't build its own
//! decorator stack (this crate doesn't own the driver construction its
//! caller does), it just documents the one rule a caller building the probe
//! backend has to follow: no response-caching layer anywhere in it. Retry/
//! throttle/metrics layers are fine to keep -- they don't hide whether the
//! backend is reachable, they only reintroduce it after a delay.

use crate::backend::Backend;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const HEALTH_PING_KEY: &str = ".conf/health-ping.json";

/// `probe_backend` must be built without any response-caching decorator
/// (see this module's doc comment) -- everything else about it (which
/// driver, whether it shares retry/throttle/metrics layers with the app's
/// main backend) is up to the caller.
pub struct HealthProbe {
    probe_backend: Arc<dyn Backend>,
    last_ready: AtomicBool,
}

impl std::fmt::Debug for HealthProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthProbe").field("last_ready", &self.last_ready.load(Ordering::Relaxed)).finish()
    }
}

impl HealthProbe {
    pub fn new(probe_backend: Arc<dyn Backend>) -> Self {
        HealthProbe { probe_backend, last_ready: AtomicBool::new(false) }
    }

    /// Does a real `get` against the backend right now. `true` if it
    /// succeeds (the key doesn't need to exist -- a clean "not found" still
    /// proves the backend answered); `false` on any error. Updates
    /// [`Self::last_ready`] as a side effect, so a caller polling this
    /// periodically can also expose the last-known state cheaply between
    /// checks without re-probing.
    pub async fn ready(&self) -> bool {
        let ok = self.probe_backend.get(HEALTH_PING_KEY).await.is_ok();
        self.last_ready.store(ok, Ordering::Relaxed);
        ok
    }

    /// The outcome of the most recent [`Self::ready`] call, without
    /// probing again -- `false` if [`Self::ready`] has never been called.
    pub fn last_ready(&self) -> bool {
        self.last_ready.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocalParams;
    use crate::local::LocalBackend;

    #[tokio::test]
    async fn ready_is_true_for_a_reachable_backend_even_without_the_key_existing() {
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn Backend> = Arc::new(LocalBackend::new(&LocalParams { bucket: dir.path().to_string_lossy().to_string() }));
        let probe = HealthProbe::new(backend);
        assert!(probe.ready().await);
        assert!(probe.last_ready());
    }

    #[derive(Debug)]
    struct AlwaysFailsBackend;

    #[async_trait::async_trait]
    impl Backend for AlwaysFailsBackend {
        async fn get(&self, _key: &str) -> anyhow::Result<(Vec<u8>, Option<String>)> {
            anyhow::bail!("simulated unreachable backend")
        }
        async fn put_cas(&self, _key: &str, _body: Vec<u8>, _expected_etag: Option<&str>) -> anyhow::Result<crate::backend::Cas> {
            unreachable!()
        }
        async fn delete(&self, _key: &str) -> anyhow::Result<crate::backend::DeleteOutcome> {
            unreachable!()
        }
        async fn delete_many(&self, _keys: &[String]) -> anyhow::Result<crate::backend::DeleteOutcome> {
            unreachable!()
        }
        async fn list_prefix(&self, _prefix: &str) -> anyhow::Result<Vec<(String, u64)>> {
            unreachable!()
        }
        #[cfg(feature = "streaming")]
        async fn put_stream(&self, _key: &str, _source: &std::path::Path) -> anyhow::Result<()> {
            unreachable!()
        }
        #[cfg(feature = "streaming")]
        async fn get_stream(&self, _key: &str, _dest: &std::path::Path) -> anyhow::Result<()> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn ready_is_false_when_the_backend_is_unreachable() {
        let probe = HealthProbe::new(Arc::new(AlwaysFailsBackend));
        assert!(!probe.ready().await);
        assert!(!probe.last_ready());
    }

    #[tokio::test]
    async fn last_ready_is_false_before_the_first_probe() {
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn Backend> = Arc::new(LocalBackend::new(&LocalParams { bucket: dir.path().to_string_lossy().to_string() }));
        let probe = HealthProbe::new(backend);
        assert!(!probe.last_ready());
    }
}
