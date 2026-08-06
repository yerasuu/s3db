//! A generic pointer index: `{root}/{kind}/{segment(raw)}.json` -> `T`.
//! Replaces the pattern every lookup index (pubkey, email, namespace,
//! reverse-uid, repo-name, ...) used to hand-roll separately: its own key
//! builder, its own segment-encoding choice, and its own claim/conflict
//! strategy.

use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use crate::payload::{delete_object, get_json, put_json};
use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::borrow::Cow;

/// A type with a cheap, natural byte representation for use as an index
/// segment -- so a field that's already a `u64`/fixed-size id/raw bytes
/// never has to round-trip through `.to_string()` (an allocation, for a
/// value that never needed to be text) just to satisfy [`SecondaryIndex`]'s
/// `&str`-shaped API. [`Segment::Raw`]/[`Segment::Base64`] stay the right
/// choice for a field that's naturally text (an email, a namespace) --
/// this is for the common case where it isn't.
///
/// Implement this for your own id type (a uid newtype, ...) to use
/// [`SecondaryIndex::claim_once_typed`]/[`SecondaryIndex::resolve_typed`]/
/// [`SecondaryIndex::release_typed`] with it directly.
pub trait IndexKey {
    fn key_bytes(&self) -> Cow<'_, [u8]>;
}

impl IndexKey for str {
    fn key_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl IndexKey for String {
    fn key_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl IndexKey for [u8] {
    fn key_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self)
    }
}

impl IndexKey for u64 {
    fn key_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_be_bytes().to_vec())
    }
}

impl IndexKey for u128 {
    fn key_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_be_bytes().to_vec())
    }
}

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
    pub(crate) fn encode(&self, raw: &str) -> String {
        match self {
            Segment::Raw => raw.to_string(),
            Segment::Base64 => {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
            }
        }
    }

    /// Reverses [`Self::encode`] -- [`crate::sharded_index::ShardedIndex`]'s
    /// rebalance needs the original `raw` back from a listed key's segment
    /// to recompute which new shard it belongs in, since a shard listing
    /// only ever has the encoded segment, never the `raw` that produced it.
    pub(crate) fn decode(&self, encoded: &str) -> Result<String> {
        match self {
            Segment::Raw => Ok(encoded.to_string()),
            Segment::Base64 => {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(encoded)
                    .context("invalid base64 segment")?;
                String::from_utf8(bytes).context("segment bytes aren't valid utf8")
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

    /// Raw CAS write against an arbitrary `expected_etag` — the primitive
    /// [`Self::claim_once`]/[`Self::claim_self_healing`] build on. For a
    /// caller that already has an etag in hand (e.g. reclaiming after its
    /// own liveness check) and wants the real [`Cas`] outcome rather than a
    /// collapsed bool.
    pub async fn put_raw<T: Serialize>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &str,
        value: &T,
        expected_etag: Option<&str>,
    ) -> Result<Cas> {
        put_json(backend, &self.key(raw), value, expected_etag, cipher).await
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
    pub async fn claim_once<T: Serialize>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &str,
        value: &T,
    ) -> Result<bool> {
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

    /// Same key shape as [`Self::key`], but for an [`IndexKey`] instead of
    /// an already-`&str` `raw` -- always base64 of [`IndexKey::key_bytes`],
    /// regardless of this index's own [`Self::segment`] choice (that field
    /// only governs the `&str`-based methods; a typed key never needed a
    /// `Segment::Raw` option in the first place, since it's never already a
    /// safe path component the way a validated `&str` can be).
    pub fn key_typed(&self, raw: &(impl IndexKey + ?Sized)) -> String {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.key_bytes());
        format!("{}/{}/{encoded}.json", self.root, self.kind)
    }

    /// [`Self::claim_once`], for an [`IndexKey`] `raw`.
    pub async fn claim_once_typed<T: Serialize>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &(impl IndexKey + ?Sized),
        value: &T,
    ) -> Result<bool> {
        match put_json(backend, &self.key_typed(raw), value, None, cipher).await? {
            Cas::Ok => Ok(true),
            Cas::Conflict => Ok(false),
        }
    }

    /// [`Self::resolve`], for an [`IndexKey`] `raw`.
    pub async fn resolve_typed<T: DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &(impl IndexKey + ?Sized),
    ) -> Result<(Option<T>, Option<String>)> {
        let (value, etag) = get_json::<T>(backend, &self.key_typed(raw), cipher).await?;
        Ok((etag.is_some().then_some(value), etag))
    }

    /// [`Self::release`], for an [`IndexKey`] `raw`.
    pub async fn release_typed(&self, backend: &dyn Backend, raw: &(impl IndexKey + ?Sized)) {
        delete_object(backend, &self.key_typed(raw)).await;
    }

    /// Opt-in alternative to [`Self::claim_once`]: the pointer entry
    /// includes a denormalized copy of `value` itself, so
    /// [`Self::resolve_inline`] is a single `get` instead of
    /// [`Self::resolve`]'s pointer-then-fetch two round trips. Trades more
    /// writes (every update to the real entity needs a matching
    /// `claim_inline` call to keep this copy from going stale -- there's no
    /// automatic propagation) for fewer reads -- worth it only where lookup
    /// volume dominates over update volume.
    pub async fn claim_inline<P: Serialize, V: Serialize>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &str,
        pointer: &P,
        value: &V,
    ) -> Result<bool> {
        match put_json(backend, &self.key(raw), &(pointer, value), None, cipher).await? {
            Cas::Ok => Ok(true),
            Cas::Conflict => Ok(false),
        }
    }

    /// Reads the denormalized value straight from the pointer entry a
    /// prior [`Self::claim_inline`] wrote -- one `get`, no second fetch
    /// against the entity's own `Collection`.
    pub async fn resolve_inline<P: DeserializeOwned + Default, V: DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &str,
    ) -> Result<Option<V>> {
        let (entry, etag) = get_json::<(P, V)>(backend, &self.key(raw), cipher).await?;
        Ok(etag.map(|_| entry.1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalBackend;

    fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
        let backend = LocalBackend::new(&crate::config::LocalParams {
            bucket: root.to_string_lossy().to_string(),
        });
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
        assert_eq!(
            idx.key("SHA256:abc/def+ghi"),
            format!(".conf/index/pubkey/{expected}.json")
        );
    }

    #[tokio::test]
    async fn typed_key_claims_and_resolves_a_u64() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "byid", Segment::Raw);
        let id: u64 = 42;
        assert!(
            idx.claim_once_typed(&backend, &cipher, &id, &Pointer { owner: "alice".into() })
                .await
                .unwrap()
        );
        let (resolved, _etag) = idx.resolve_typed::<Pointer>(&backend, &cipher, &id).await.unwrap();
        assert_eq!(resolved, Some(Pointer { owner: "alice".into() }));
    }

    #[test]
    fn typed_key_never_allocates_an_intermediate_string_representation() {
        // Same u64 encoded two different (wrong) ways -- decimal text vs
        // its natural big-endian bytes -- must not collide, proving
        // key_typed really uses key_bytes(), not `.to_string()`.
        let idx = SecondaryIndex::new(".conf/index", "byid", Segment::Raw);
        let as_typed_key = idx.key_typed(&42u64);
        let as_raw_string_key = idx.key("42");
        assert_ne!(as_typed_key, as_raw_string_key);
    }

    #[tokio::test]
    async fn typed_key_release_removes_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "byid", Segment::Raw);
        let id: u64 = 7;
        idx.claim_once_typed(&backend, &cipher, &id, &Pointer { owner: "alice".into() })
            .await
            .unwrap();
        idx.release_typed(&backend, &id).await;
        let (resolved, _) = idx.resolve_typed::<Pointer>(&backend, &cipher, &id).await.unwrap();
        assert_eq!(resolved, None);
    }

    #[tokio::test]
    async fn inline_resolve_reads_the_denormalized_value_in_one_get() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "email", Segment::Base64);
        assert!(
            idx.claim_inline(
                &backend,
                &cipher,
                "alice@example.com",
                &Pointer { owner: "alice".into() },
                &Widget { count: 9 }
            )
            .await
            .unwrap()
        );
        let value: Option<Widget> = idx
            .resolve_inline::<Pointer, Widget>(&backend, &cipher, "alice@example.com")
            .await
            .unwrap();
        assert_eq!(value, Some(Widget { count: 9 }));
    }

    #[tokio::test]
    async fn inline_resolve_is_none_before_any_claim() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "email", Segment::Base64);
        let value: Option<Widget> = idx
            .resolve_inline::<Pointer, Widget>(&backend, &cipher, "nobody@example.com")
            .await
            .unwrap();
        assert_eq!(value, None);
    }

    #[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Widget {
        count: u32,
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
        assert!(
            idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "alice".into() })
                .await
                .unwrap()
        );
        assert!(
            !idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "bob".into() })
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn self_healing_claim_succeeds_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
        let ok = idx
            .claim_self_healing(
                &backend,
                &cipher,
                "fp1",
                &Pointer { owner: "alice".into() },
                |_existing: Pointer| async { Ok(false) },
            )
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn self_healing_claim_is_idempotent_for_the_same_claimant() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
        idx.claim_self_healing(
            &backend,
            &cipher,
            "fp1",
            &Pointer { owner: "alice".into() },
            |_: Pointer| async { Ok(true) },
        )
        .await
        .unwrap();
        let ok = idx
            .claim_self_healing(
                &backend,
                &cipher,
                "fp1",
                &Pointer { owner: "alice".into() },
                |_: Pointer| async { Ok(true) },
            )
            .await
            .unwrap();
        assert!(
            ok,
            "reclaiming with the identical value must be idempotent, not a conflict"
        );
    }

    #[tokio::test]
    async fn self_healing_claim_refuses_a_genuinely_live_owner() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
        idx.claim_self_healing(
            &backend,
            &cipher,
            "fp1",
            &Pointer { owner: "alice".into() },
            |_: Pointer| async { Ok(true) },
        )
        .await
        .unwrap();
        let ok = idx
            .claim_self_healing(
                &backend,
                &cipher,
                "fp1",
                &Pointer { owner: "bob".into() },
                |existing: Pointer| async move { Ok(existing.owner == "alice") },
            )
            .await
            .unwrap();
        assert!(!ok, "a claim genuinely still held by someone else must be refused");
    }

    #[tokio::test]
    async fn self_healing_claim_reclaims_a_stale_owner() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
        idx.claim_self_healing(
            &backend,
            &cipher,
            "fp1",
            &Pointer { owner: "alice".into() },
            |_: Pointer| async { Ok(true) },
        )
        .await
        .unwrap();
        // `alice` no longer genuinely holds it (simulated via is_genuine=false).
        let ok = idx
            .claim_self_healing(
                &backend,
                &cipher,
                "fp1",
                &Pointer { owner: "bob".into() },
                |_: Pointer| async { Ok(false) },
            )
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
        idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "alice".into() })
            .await
            .unwrap();
        idx.release(&backend, "alice").await;
        let (resolved, _etag) = idx.resolve::<Pointer>(&backend, &cipher, "alice").await.unwrap();
        assert_eq!(resolved, None);
    }
}
