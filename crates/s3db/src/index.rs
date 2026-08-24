//! A generic pointer index: `{root}/{kind}/{segment(raw)}.json` -> `T`.
//! Replaces the pattern every lookup index (pubkey, email, namespace,
//! reverse-uid, repo-name, ...) used to hand-roll separately: its own key
//! builder, its own segment-encoding choice, and its own claim/conflict
//! strategy.
//!
//! [`SecondaryIndex::resolve_range`] is the one method here that isn't
//! backend-agnostic: it needs a real ordered range scan
//! ([`crate::range::RangeBackend`]) underneath, which today only
//! [`crate::local::RedbBackend`] gives.

use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use crate::naming::validate_segment;
use crate::payload::{delete_object, get_json, put_json};
use crate::range::as_range;
use anyhow::{Context, Result, bail};
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
    /// `raw` must already be a safe path component (no `/`, `\`, control
    /// chars, no leading `.`) — used as-is, after
    /// [`crate::naming::validate_segment`] checks that it really is one.
    ///
    /// The check is enforced, not assumed: this variant is what
    /// `#[derive(Entity)]` picks by default, so an index over a
    /// user-supplied field (an email, a username) lands here without the
    /// caller having chosen it, and a `raw` carrying a `/` would silently
    /// relocate the pointer object into a sibling namespace rather than
    /// producing a merely odd-looking key.
    Raw,
    /// `raw` is arbitrary bytes (a fingerprint, an email) that may contain
    /// path-unsafe characters — URL-safe base64, no padding. Reversible,
    /// not a hash: nothing here needs `raw` to stay secret. Safe by
    /// construction, so nothing is rejected here.
    Base64,
}

impl Segment {
    pub(crate) fn encode(&self, raw: &str) -> Result<String> {
        match self {
            Segment::Raw => {
                validate_segment(raw, "index segment")?;
                Ok(raw.to_string())
            }
            Segment::Base64 => {
                use base64::Engine;
                Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes()))
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

    pub fn key(&self, raw: &str) -> Result<String> {
        Ok(format!(
            "{}/{}/{}.json",
            self.root,
            self.kind,
            self.segment.encode(raw)?
        ))
    }

    /// Same prefix as [`Self::key`], deliberately *without* the `.json`
    /// suffix — used only as a range bound (see [`Self::resolve_range`]),
    /// never as an object key on its own.
    ///
    /// The suffix has to be left off here specifically because appending it
    /// to `raw` first would corrupt the bound in exactly the case a range
    /// query most needs to get right: one `raw` value that's a proper
    /// prefix of another (`"ab"` vs. `"ab1"`). `"ab.json"` sorts *after*
    /// `"ab1"` (`.` is `0x2e`, `1` is `0x31`), which would silently exclude
    /// `"ab1"` from an upper bound of `"ab"`, or include `"ab"` past an
    /// upper bound that should have excluded it right at `"ab"` itself.
    /// Comparing the bound against `raw` directly, with no suffix on either
    /// side, has no such edge case: extending a string (with `.json` or
    /// anything else) can never make it sort before the string it extends.
    fn segment_prefix(&self, raw: &str) -> Result<String> {
        Ok(format!("{}/{}/{}", self.root, self.kind, self.segment.encode(raw)?))
    }

    /// The `raw` segment [`Self::segment_prefix`] came from, reversing
    /// [`Self::key`]'s `.json` suffix and `{root}/{kind}/` prefix so
    /// [`Self::resolve_range`] can hand a caller back the same `raw` value
    /// [`Self::key`] would have taken, not a raw storage key.
    fn raw_from_key(&self, key: &str) -> Result<String> {
        let encoded = key
            .strip_prefix(&format!("{}/{}/", self.root, self.kind))
            .and_then(|s| s.strip_suffix(".json"))
            .with_context(|| format!("{key}: not a valid key for this index"))?;
        self.segment.decode(encoded)
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
        put_json(backend, &self.key(raw)?, value, expected_etag, cipher).await
    }

    pub async fn resolve<T: DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &str,
    ) -> Result<(Option<T>, Option<String>)> {
        let (value, etag) = get_json::<T>(backend, &self.key(raw)?, cipher).await?;
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
        match put_json(backend, &self.key(raw)?, value, None, cipher).await? {
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
        let key = self.key(raw)?;
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

    pub async fn release(&self, backend: &dyn Backend, raw: &str) -> Result<()> {
        delete_object(backend, &self.key(raw)?).await;
        Ok(())
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
        match put_json(backend, &self.key(raw)?, &(pointer, value), None, cipher).await? {
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
        let (entry, etag) = get_json::<(P, V)>(backend, &self.key(raw)?, cipher).await?;
        Ok(etag.map(|_| entry.1))
    }

    /// Every pointer entry with `start_raw <= raw < end_raw`, ascending, in
    /// one native range scan — see [`crate::range::RangeBackend`]'s module
    /// doc for exactly which backend can honestly give this
    /// (`docs/s3db-local-mode.md`'s whole point) and which can't. Requires
    /// [`Segment::Raw`]: [`Segment::Base64`] doesn't preserve `raw`'s own
    /// ordering, so a range bound over the encoded segment wouldn't mean
    /// what a caller thinks it means.
    ///
    /// Callers own picking a `raw` representation that actually sorts the
    /// way they want (zero-padded decimal, ISO-8601 timestamp, ...) — this
    /// index has no notion of "this field is really a number," it only ever
    /// compares the bytes it's given, same as [`Self::key`] always has.
    pub async fn resolve_range<T: DeserializeOwned>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        start_raw: &str,
        end_raw: &str,
    ) -> Result<Vec<(String, T)>> {
        if !matches!(self.segment, Segment::Raw) {
            bail!("resolve_range needs Segment::Raw -- Segment::Base64 doesn't preserve the raw value's ordering");
        }
        let range =
            as_range(backend).context("this backend has no native range capability (see docs/s3db-local-mode.md)")?;
        let entries = range
            .range(&self.segment_prefix(start_raw)?, &self.segment_prefix(end_raw)?)
            .await?;
        let mut out = Vec::with_capacity(entries.len());
        for (key, sealed) in entries {
            let plain = cipher.open(&key, &sealed)?;
            let value: T = rmp_serde::from_slice(&plain).with_context(|| format!("{key} is invalid"))?;
            out.push((self.raw_from_key(&key)?, value));
        }
        Ok(out)
    }
}

#[cfg(test)]
#[path = "../tests/unit/index.rs"]
#[allow(deprecated)] // test_backend_and_cipher_with is parameterized over both engines
mod tests;
