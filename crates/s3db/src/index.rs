//! A generic pointer index: `{root}/{kind}/{segment(raw)}.json` -> `T`.
//! Replaces the pattern every lookup index (pubkey, email, namespace,
//! reverse-uid, repo-name, ...) used to hand-roll separately: its own key
//! builder, its own segment-encoding choice, and its own claim/conflict
//! strategy.

use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use crate::json::{delete_object, get_json, put_json};
use anyhow::Result;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// How a raw claim key becomes a safe path segment.
#[derive(Debug, Clone, Copy)]
pub enum Segment {
    /// `raw` is already a validated safe path component (no `/`, `\`,
    /// control chars) — used as-is.
    Raw,
    /// `raw` is arbitrary bytes (a fingerprint, an email) that may contain
    /// path-unsafe characters — URL-safe base64, no padding. Reversible,
    /// not a hash: nothing here needs `raw` to stay secret.
    Base64,
}

impl Segment {
    fn encode(&self, raw: &str) -> String {
        match self {
            Segment::Raw => raw.to_string(),
            Segment::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SecondaryIndex {
    pub root: &'static str,
    pub kind: &'static str,
    pub segment: Segment,
}

impl SecondaryIndex {
    pub const fn new(root: &'static str, kind: &'static str, segment: Segment) -> Self {
        SecondaryIndex { root, kind, segment }
    }

    pub fn key(&self, raw: &str) -> String {
        format!("{}/{}/{}.json", self.root, self.kind, self.segment.encode(raw))
    }

    pub async fn resolve<T: DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &str,
    ) -> Result<(Option<T>, Option<String>)> {
        let (value, etag) = get_json::<T>(backend, &self.key(raw), cipher).await?;
        Ok((etag.is_some().then_some(value), etag))
    }

    /// Single-attempt CAS claim, no retry, no self-heal — correct when the
    /// key space can't meaningfully collide (a random uid) or the first
    /// claimant should simply win (a namespace reservation).
    pub async fn claim_once<T: Serialize>(&self, backend: &dyn Backend, cipher: &Cipher, raw: &str, value: &T) -> Result<bool> {
        match put_json(backend, &self.key(raw), value, None, cipher).await? {
            Cas::Ok => Ok(true),
            Cas::Conflict => Ok(false),
        }
    }

    /// Fire-and-forget claim: errors are swallowed. For reverse-lookup
    /// hints whose correctness never depends on the write actually landing.
    pub async fn claim_best_effort<T: Serialize>(&self, backend: &dyn Backend, cipher: &Cipher, raw: &str, value: &T) {
        let _ = self.claim_once(backend, cipher, raw, value).await;
    }

    /// Self-healing claim: on conflict, re-fetch the existing pointer. If it
    /// already names `value`, this is an idempotent retry. Otherwise
    /// `is_genuine` (typically: look up whatever the existing pointer
    /// refers to, and check it still actually holds this claim) decides
    /// whether to refuse (still genuinely held) or reclaim a stale pointer
    /// with one more CAS attempt using the etag just read.
    pub async fn claim_self_healing<T, F, Fut>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &str,
        value: &T,
        is_genuine: F,
    ) -> Result<bool>
    where
        T: Serialize + DeserializeOwned + Default + PartialEq,
        F: FnOnce(T) -> Fut,
        Fut: std::future::Future<Output = Result<bool>>,
    {
        let key = self.key(raw);
        match put_json(backend, &key, value, None, cipher).await? {
            Cas::Ok => Ok(true),
            Cas::Conflict => {
                let (existing, etag) = get_json::<T>(backend, &key, cipher).await?;
                if &existing == value {
                    return Ok(true);
                }
                if is_genuine(existing).await? {
                    return Ok(false);
                }
                match put_json(backend, &key, value, etag.as_deref(), cipher).await? {
                    Cas::Ok => Ok(true),
                    Cas::Conflict => Ok(false),
                }
            }
        }
    }

    pub async fn release(&self, backend: &dyn Backend, raw: &str) {
        delete_object(backend, &self.key(raw)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalBackend;

    fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
        let backend = LocalBackend::new(&crate::config::LocalParams { bucket: root.to_string_lossy().to_string() });
        let cipher = Cipher::derive("test passphrase", &[8u8; crate::cipher::SALT_LEN]).unwrap();
        (backend, cipher)
    }

    #[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Pointer {
        owner: String,
    }

    #[test]
    fn base64_segment_matches_the_original_url_safe_no_pad_scheme() {
        // Parity check against `auth::access::index_segment`'s exact output
        // (URL_SAFE_NO_PAD, no other transform), for a fingerprint-shaped
        // value that contains `/` and `+`-triggering bytes.
        let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
        use base64::Engine;
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"SHA256:abc/def+ghi");
        assert_eq!(idx.key("SHA256:abc/def+ghi"), format!(".conf/index/pubkey/{expected}.json"));
    }

    #[test]
    fn raw_segment_is_used_verbatim() {
        let idx = SecondaryIndex::new(".conf/index", "namespace", Segment::Raw);
        assert_eq!(idx.key("alice"), ".conf/index/namespace/alice.json");
    }

    #[tokio::test]
    async fn claim_once_conflicts_on_a_second_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "namespace", Segment::Raw);
        assert!(idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "alice".into() }).await.unwrap());
        assert!(!idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "bob".into() }).await.unwrap());
    }

    #[tokio::test]
    async fn self_healing_claim_succeeds_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
        let ok = idx
            .claim_self_healing(&backend, &cipher, "fp1", &Pointer { owner: "alice".into() }, |_existing: Pointer| async { Ok(false) })
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn self_healing_claim_is_idempotent_for_the_same_claimant() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
        idx.claim_self_healing(&backend, &cipher, "fp1", &Pointer { owner: "alice".into() }, |_: Pointer| async { Ok(true) })
            .await
            .unwrap();
        let ok = idx
            .claim_self_healing(&backend, &cipher, "fp1", &Pointer { owner: "alice".into() }, |_: Pointer| async { Ok(true) })
            .await
            .unwrap();
        assert!(ok, "reclaiming with the identical value must be idempotent, not a conflict");
    }

    #[tokio::test]
    async fn self_healing_claim_refuses_a_genuinely_live_owner() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
        idx.claim_self_healing(&backend, &cipher, "fp1", &Pointer { owner: "alice".into() }, |_: Pointer| async { Ok(true) })
            .await
            .unwrap();
        let ok = idx
            .claim_self_healing(&backend, &cipher, "fp1", &Pointer { owner: "bob".into() }, |existing: Pointer| async move {
                Ok(existing.owner == "alice")
            })
            .await
            .unwrap();
        assert!(!ok, "a claim genuinely still held by someone else must be refused");
    }

    #[tokio::test]
    async fn self_healing_claim_reclaims_a_stale_owner() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
        idx.claim_self_healing(&backend, &cipher, "fp1", &Pointer { owner: "alice".into() }, |_: Pointer| async { Ok(true) })
            .await
            .unwrap();
        // `alice` no longer genuinely holds it (simulated via is_genuine=false).
        let ok = idx
            .claim_self_healing(&backend, &cipher, "fp1", &Pointer { owner: "bob".into() }, |_: Pointer| async { Ok(false) })
            .await
            .unwrap();
        assert!(ok, "a stale claim must be reclaimable");
        let (resolved, _etag) = idx.resolve::<Pointer>(&backend, &cipher, "fp1").await.unwrap();
        assert_eq!(resolved, Some(Pointer { owner: "bob".into() }));
    }

    #[tokio::test]
    async fn release_makes_resolve_report_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "namespace", Segment::Raw);
        idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "alice".into() }).await.unwrap();
        idx.release(&backend, "alice").await;
        let (resolved, _etag) = idx.resolve::<Pointer>(&backend, &cipher, "alice").await.unwrap();
        assert_eq!(resolved, None);
    }
}
