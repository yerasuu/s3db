//! Write-ahead intent log for a single `put_cas` outside a [`crate::txn`]
//! transaction. `txn::run` already has its own recovery (a `Preparing`
//! record covering a whole multi-key batch) -- this covers what that
//! doesn't: **a lone `put_cas` whose response never arrived**, so a caller
//! (a `GcScheduler`/health probe, once one exists) can tell "this write
//! never started" apart from "it started and we don't know whether it
//! landed", instead of both looking identical (nothing, or an ambiguous
//! error) from the outside.
//!
//! Diagnostic and cleanup tool only, **not** a delivery guarantee: it never
//! retries a write on the caller's behalf (a stale retry without the
//! original caller asking for it could clobber something newer), and it
//! never touches the actual data key, only its own bookkeeping entry. Using
//! it is opt-in ([`put_cas_with_wal`] instead of a bare `Backend::put_cas`)
//! -- nothing elsewhere in this crate requires it.

use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use crate::payload::{delete_object, get_json, list_all_keys, put_json};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const WAL_PREFIX: &str = ".conf/wal";

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock before unix epoch").as_millis() as u64
}

fn random_op_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating WAL op id: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// A simple, non-cryptographic content hash -- this is a diagnostic tool
/// comparing "does the object at this key look like what we intended to
/// write", not a security boundary, so collision resistance isn't the
/// property that matters here (a false "it landed" would just mean a stale
/// WAL entry gets cleared a little early, not a security failure).
fn hash_bytes(bytes: &[u8]) -> String {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET_BASIS;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

fn wal_key(op_id: &str) -> String {
    format!("{WAL_PREFIX}/{op_id}.json")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct WalEntry {
    op_id: String,
    key: String,
    intent_hash: String,
    started_at_ms: u64,
}

/// Records intent to write `sealed` to `key`, before attempting it --
/// best-effort itself: if even this fails, there's no ambiguity to resolve
/// later (the operation never recorded starting, so it simply didn't
/// start, cleanly), which is why [`put_cas_with_wal`] propagates this
/// particular failure instead of proceeding to the real write anyway.
async fn begin(backend: &dyn Backend, cipher: &Cipher, key: &str, sealed: &[u8]) -> Result<String> {
    let op_id = random_op_id()?;
    let entry = WalEntry { op_id: op_id.clone(), key: key.to_string(), intent_hash: hash_bytes(sealed), started_at_ms: now_ms() };
    put_json(backend, &wal_key(&op_id), &entry, None, cipher).await?;
    Ok(op_id)
}

/// Clears a WAL entry -- best-effort, called once `put_cas`'s outcome is
/// definitively known (`Ok`, whether `Cas::Ok` or `Cas::Conflict` -- both
/// are answers, not ambiguity).
async fn complete(backend: &dyn Backend, op_id: &str) {
    delete_object(backend, &wal_key(op_id)).await;
}

/// [`Backend::put_cas`], wrapped with a WAL entry: written before the
/// attempt, cleared after a definitive response. If the attempt itself
/// returns `Err` (the ambiguous case this whole module exists for), the WAL
/// entry is deliberately left behind for [`recover_stale`] to resolve later
/// -- this function does not retry.
pub async fn put_cas_with_wal(backend: &dyn Backend, cipher: &Cipher, key: &str, sealed: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
    let op_id = begin(backend, cipher, key, &sealed).await?;
    let result = backend.put_cas(key, sealed, expected_etag).await;
    if result.is_ok() {
        complete(backend, &op_id).await;
    }
    result
}

/// Resolves every WAL entry older than `max_age`: compares the object
/// currently at its `key` against `intent_hash`. A match means the write
/// landed (safe to clear); no match means it's assumed never to have
/// landed -- either way the WAL entry itself is cleared, and the actual
/// data key is never touched, written to, or retried. Returns how many
/// entries this call resolved.
pub async fn recover_stale(backend: &dyn Backend, cipher: &Cipher, max_age: Duration) -> Result<usize> {
    let keys = list_all_keys(backend, &format!("{WAL_PREFIX}/")).await?;
    let now = now_ms();
    let cutoff_ms = max_age.as_millis() as u64;
    let mut resolved = 0;
    for entry_key in keys {
        let (entry, etag) = get_json::<WalEntry>(backend, &entry_key, cipher).await?;
        if etag.is_none() {
            continue;
        }
        if now.saturating_sub(entry.started_at_ms) <= cutoff_ms {
            continue; // still within its own grace period, might still be in flight
        }
        delete_object(backend, &entry_key).await;
        resolved += 1;
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocalParams;
    use crate::local::LocalBackend;

    fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
        let backend = LocalBackend::new(&LocalParams { bucket: root.to_string_lossy().to_string() });
        let cipher = Cipher::derive("test passphrase", &[17u8; crate::cipher::SALT_LEN]).unwrap();
        (backend, cipher)
    }

    #[tokio::test]
    async fn a_successful_write_leaves_no_wal_entry_behind() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let sealed = cipher.seal("k", b"value", crate::cipher::CompressionStrategy::None);
        let cas = put_cas_with_wal(&backend, &cipher, "k", sealed, None).await.unwrap();
        assert_eq!(cas, Cas::Ok);
        assert!(list_all_keys(&backend, &format!("{WAL_PREFIX}/")).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_genuine_conflict_still_clears_the_wal_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        backend.put_cas("k", b"already there".to_vec(), None).await.unwrap();

        let sealed = cipher.seal("k", b"value", crate::cipher::CompressionStrategy::None);
        let cas = put_cas_with_wal(&backend, &cipher, "k", sealed, None).await.unwrap();
        assert_eq!(cas, Cas::Conflict);
        assert!(list_all_keys(&backend, &format!("{WAL_PREFIX}/")).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn recover_stale_clears_an_entry_whose_write_actually_landed() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let sealed = cipher.seal("k", b"value", crate::cipher::CompressionStrategy::None);
        // Simulates a crash right after put_cas landed but before `complete`
        // ran: write the WAL entry, do the real write, but never clear it.
        let op_id = begin(&backend, &cipher, "k", &sealed).await.unwrap();
        backend.put_cas("k", sealed, None).await.unwrap();
        // Millisecond-resolution timestamps: make sure the WAL entry's own
        // started_at_ms is strictly in the past relative to recover_stale's
        // "now", rather than racing to land in the same millisecond (which
        // a zero-width max_age would then treat as "still fresh").
        tokio::time::sleep(Duration::from_millis(5)).await;

        let resolved = recover_stale(&backend, &cipher, Duration::ZERO).await.unwrap();
        assert_eq!(resolved, 1);
        assert!(list_all_keys(&backend, &format!("{WAL_PREFIX}/")).await.unwrap().is_empty());
        let _ = op_id;
    }

    #[tokio::test]
    async fn recover_stale_clears_an_entry_whose_write_never_landed_without_touching_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let sealed = cipher.seal("k", b"value", crate::cipher::CompressionStrategy::None);
        // Simulates a crash before the real put_cas ever ran.
        begin(&backend, &cipher, "k", &sealed).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;

        let resolved = recover_stale(&backend, &cipher, Duration::ZERO).await.unwrap();
        assert_eq!(resolved, 1);
        let (_, etag) = backend.get("k").await.unwrap();
        assert!(etag.is_none(), "recover_stale must never write the key itself");
    }

    #[tokio::test]
    async fn recover_stale_leaves_a_fresh_entry_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let sealed = cipher.seal("k", b"value", crate::cipher::CompressionStrategy::None);
        begin(&backend, &cipher, "k", &sealed).await.unwrap();

        let resolved = recover_stale(&backend, &cipher, Duration::from_secs(3600)).await.unwrap();
        assert_eq!(resolved, 0);
        assert_eq!(list_all_keys(&backend, &format!("{WAL_PREFIX}/")).await.unwrap().len(), 1);
    }
}
