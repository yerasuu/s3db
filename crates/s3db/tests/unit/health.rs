use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;

#[tokio::test]
async fn ready_is_true_for_a_reachable_backend_even_without_the_key_existing() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(LocalBackend::new(&LocalParams {
        bucket: dir.path().to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    }));
    let probe = HealthProbe::new(backend);
    assert!(probe.ready().await);
    assert!(probe.last_ready());
}

#[derive(Debug)]
struct AlwaysFailsBackend;

#[async_trait::async_trait]
impl Backend for AlwaysFailsBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, _key: &str) -> anyhow::Result<(Vec<u8>, Option<String>)> {
        anyhow::bail!("simulated unreachable backend")
    }
    async fn put_cas(
        &self,
        _key: &str,
        _body: Vec<u8>,
        _expected_etag: Option<&str>,
    ) -> anyhow::Result<crate::backend::Cas> {
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
    async fn get_range(&self, _key: &str, _offset: u64, _len: u64) -> anyhow::Result<Vec<u8>> {
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
    let backend: Arc<dyn Backend> = Arc::new(LocalBackend::new(&LocalParams {
        bucket: dir.path().to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    }));
    let probe = HealthProbe::new(backend);
    assert!(!probe.last_ready());
}
