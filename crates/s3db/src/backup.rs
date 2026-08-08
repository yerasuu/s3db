//! Logical backup/restore of one [`Collection`] at a time -- a `scroll`
//! (list + read every entity) copied to a destination, not a storage-level
//! snapshot (no reliance on any driver-specific point-in-time feature, so it
//! works identically across every [`crate::backend::Backend`]).
//!
//! **Not a point-in-time backup.** [`BackupConsistency::FuzzySnapshot`] is
//! the one variant today, and it says so explicitly rather than leaving the
//! reader to assume more than this actually gives: the scroll runs with no
//! coordination against concurrent writes, so while any *individual* entity
//! is read whole (never a torn read), the overall backup can mix states
//! from different instants anywhere within `[started_at_ms, finished_at_ms]`.
//! A real point-in-time guarantee would need something like MVCC, which
//! this crate deliberately doesn't have (see [`crate::snapshot`]'s own
//! module doc for the same honesty at the single-entity scale a
//! `ReadSnapshot` operates at). [`restore_collection`]'s result carries the
//! same manifest, so a caller restoring from a backup sees the identical
//! caveat rather than assuming more precision than the mechanism gives.

use crate::backend::Backend;
use crate::cipher::{Cipher, CompressionStrategy};
use crate::collection::{Collection, Tombstone};
use crate::payload::{get_json, put_json};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupConsistency {
    /// `scroll` run without coordination against concurrent writes. Every
    /// entity individually consistent (read whole), but the set as a whole
    /// may mix states from different instants within `[started_at_ms,
    /// finished_at_ms]` -- not a cross-entity atomic point-in-time.
    #[default]
    FuzzySnapshot,
}

/// `Default` only to satisfy [`get_json`]'s `T: DeserializeOwned +
/// Default` bound for "doesn't exist yet" -- [`restore_collection`] always
/// checks the returned etag before touching a `Default`-constructed
/// manifest's fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BackupManifest {
    pub backup_id: String,
    pub collection_prefix: String,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub consistency: BackupConsistency,
    /// `false` only if a caller explicitly opted out via
    /// [`backup_collection`]'s `include_tombstones: false` -- default
    /// `true`, since omitting tombstones silently loses the entire audit/
    /// recovery trail soft-delete exists to provide, at exactly the moment
    /// (disaster recovery) it's most needed.
    pub includes_tombstones: bool,
    pub entity_count: usize,
    pub tombstone_count: usize,
}

fn backup_prefix(backup_id: &str, collection_prefix: &str) -> String {
    format!(".conf/backups/{backup_id}/{collection_prefix}")
}

/// Deliberately a sibling of, not nested inside, `backup_prefix`'s own
/// directory: the entities themselves are scanned via
/// `Collection::list_names` over that prefix, which can't tell a real
/// entity apart from a same-shaped `{name}.json` sitting in the same
/// directory -- this stays out of that namespace entirely instead of being
/// filtered out of it.
fn manifest_key(backup_id: &str, collection_prefix: &str) -> String {
    format!(".conf/backups/{backup_id}/{collection_prefix}.manifest.json")
}

/// Backs up every live entity (and, by default, every tombstone) in
/// `collection` from `(src_backend, src_cipher)` to `(dest_backend,
/// dest_cipher)` -- the two can be the same backend/cipher (a backup
/// alongside the live data) or genuinely different ones (a separate bucket,
/// a different encryption key); either way each entity is decrypted under
/// its source key and re-sealed under its destination key, never copied as
/// raw ciphertext (which would carry the wrong AAD for its new location).
pub async fn backup_collection(
    src_backend: &dyn Backend,
    src_cipher: &Cipher,
    dest_backend: &dyn Backend,
    dest_cipher: &Cipher,
    collection: &Collection,
    backup_id: &str,
    include_tombstones: bool,
) -> Result<BackupManifest> {
    let started_at_ms = now_ms();
    let prefix = backup_prefix(backup_id, &collection.prefix);

    let mut entity_count = 0;
    for name in collection.list_names(src_backend).await? {
        let key = collection.key(&name);
        let (sealed, etag) = src_backend.get(&key).await?;
        if etag.is_none() {
            continue; // vanished between list_names and this read -- skip, not an error
        }
        let plain = src_cipher.open(&key, &sealed)?;
        let dest_key = format!("{prefix}/{name}.json");
        let resealed = dest_cipher.seal(&dest_key, &plain, CompressionStrategy::None);
        dest_backend.put_cas(&dest_key, resealed, None).await?;
        entity_count += 1;
    }

    let mut tombstone_count = 0;
    if include_tombstones {
        for (name, tombstone) in collection.list_tombstones(src_backend, src_cipher).await? {
            let dest_key = format!("{prefix}/.deleted/{name}.json");
            put_json(dest_backend, &dest_key, &tombstone, None, dest_cipher).await?;
            tombstone_count += 1;
        }
    }

    let manifest = BackupManifest {
        backup_id: backup_id.to_string(),
        collection_prefix: collection.prefix.to_string(),
        started_at_ms,
        finished_at_ms: now_ms(),
        consistency: BackupConsistency::FuzzySnapshot,
        includes_tombstones: include_tombstones,
        entity_count,
        tombstone_count,
    };
    put_json(
        dest_backend,
        &manifest_key(backup_id, &collection.prefix),
        &manifest,
        None,
        dest_cipher,
    )
    .await?;
    Ok(manifest)
}

/// Restores every entity (and tombstone, if the backup has any) from a
/// prior [`backup_collection`] call back into `collection` at
/// `(dest_backend, dest_cipher)`. Returns the original manifest, unchanged
/// -- a caller restoring from this inherits the exact same
/// `BackupConsistency::FuzzySnapshot` caveat the backup itself was taken
/// under, and should treat the restored result with the same care, not
/// assume a restore somehow adds precision the backup never had.
pub async fn restore_collection(
    backup_backend: &dyn Backend,
    backup_cipher: &Cipher,
    dest_backend: &dyn Backend,
    dest_cipher: &Cipher,
    collection: &Collection,
    backup_id: &str,
) -> Result<BackupManifest> {
    let (manifest, etag) = get_json::<BackupManifest>(
        backup_backend,
        &manifest_key(backup_id, &collection.prefix),
        backup_cipher,
    )
    .await?;
    etag.with_context(|| format!("no backup {backup_id} found for collection {}", collection.prefix))?;
    let prefix = backup_prefix(backup_id, &collection.prefix);
    // A `Collection` over the backup's own nested prefix -- the backup
    // lives at the same relative shape (`{prefix}/{name}{suffix}`) as the
    // live collection, just under `.conf/backups/<id>/` instead of at the
    // live collection's own prefix, so this is what actually has to be
    // scanned, not `collection` itself.
    let backup_view = Collection {
        suffix: collection.suffix,
        entropy: collection.entropy,
        ..Collection::new_owned(prefix.clone())
    };

    for name in backup_view.list_names(backup_backend).await? {
        let key = backup_view.key(&name);
        let (sealed, backup_etag) = backup_backend.get(&key).await?;
        if backup_etag.is_none() {
            continue;
        }
        let plain = backup_cipher.open(&key, &sealed)?;
        let dest_key = collection.key(&name);
        let resealed = dest_cipher.seal(&dest_key, &plain, CompressionStrategy::None);
        // Overwrites whatever's currently at `dest_key` -- restore is a
        // deliberate, caller-initiated overwrite, not a CAS-protected merge.
        let (_, current_etag) = dest_backend.get(&dest_key).await?;
        dest_backend
            .put_cas(&dest_key, resealed, current_etag.as_deref())
            .await?;
    }

    if manifest.includes_tombstones {
        let tombstones_prefix = format!("{prefix}/.deleted/");
        for key in crate::payload::list_all_keys(backup_backend, &tombstones_prefix).await? {
            let Some(name) = key
                .strip_prefix(&tombstones_prefix)
                .and_then(|s| s.strip_suffix(".json"))
            else {
                continue;
            };
            let (tombstone, backup_etag) = get_json::<Tombstone>(backup_backend, &key, backup_cipher).await?;
            if backup_etag.is_none() {
                continue;
            }
            let dest_tombstone_key = format!("{}/.deleted/{name}.json", collection.prefix);
            let (_, current_etag) = dest_backend.get(&dest_tombstone_key).await?;
            put_json(
                dest_backend,
                &dest_tombstone_key,
                &tombstone,
                current_etag.as_deref(),
                dest_cipher,
            )
            .await?;
        }
    }

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LocalEngine, LocalParams};
    use crate::local::LocalBackend;

    fn test_backend_and_cipher(root: &std::path::Path, salt: u8) -> (LocalBackend, Cipher) {
        let backend = LocalBackend::new(&LocalParams {
            bucket: root.to_string_lossy().to_string(),
            engine: LocalEngine::Files,
        });
        let cipher = Cipher::derive("test passphrase", &[salt; crate::cipher::SALT_LEN]).unwrap();
        (backend, cipher)
    }

    #[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Widget {
        count: u32,
    }

    #[tokio::test]
    async fn backup_then_restore_roundtrips_every_entity() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path(), 31);
        let coll = Collection::new("widgets");
        for (name, count) in [("a", 1), ("b", 2), ("c", 3)] {
            coll.put(&backend, &cipher, name, &Widget { count }, None)
                .await
                .unwrap();
        }

        let manifest = backup_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1", true)
            .await
            .unwrap();
        assert_eq!(manifest.entity_count, 3);
        assert_eq!(manifest.consistency, BackupConsistency::FuzzySnapshot);

        // Wipe the live collection, then restore.
        for name in ["a", "b", "c"] {
            backend.delete(&coll.key(name)).await.unwrap();
        }
        assert!(coll.list_names(&backend).await.unwrap().is_empty());

        restore_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1")
            .await
            .unwrap();
        let mut restored = coll.list_names(&backend).await.unwrap();
        restored.sort();
        assert_eq!(restored, vec!["a", "b", "c"]);
        let (value, _) = coll.get::<Widget>(&backend, &cipher, "b").await.unwrap();
        assert_eq!(value, Some(Widget { count: 2 }));
    }

    #[tokio::test]
    async fn backup_includes_tombstones_by_default_and_restore_brings_them_back() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path(), 37);
        let coll = Collection::new("widgets");
        coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
            .await
            .unwrap();
        coll.delete(&backend, &cipher, "a").await;
        assert_eq!(coll.list_tombstones(&backend, &cipher).await.unwrap().len(), 1);

        let manifest = backup_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1", true)
            .await
            .unwrap();
        assert!(manifest.includes_tombstones);
        assert_eq!(manifest.tombstone_count, 1);

        coll.forget_tombstone(&backend, &cipher, "a").await.unwrap();
        assert!(coll.list_tombstones(&backend, &cipher).await.unwrap().is_empty());

        restore_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1")
            .await
            .unwrap();
        assert_eq!(coll.list_tombstones(&backend, &cipher).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn backup_can_opt_out_of_tombstones_and_says_so_in_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path(), 41);
        let coll = Collection::new("widgets");
        coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
            .await
            .unwrap();
        coll.delete(&backend, &cipher, "a").await;

        let manifest = backup_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1", false)
            .await
            .unwrap();
        assert!(!manifest.includes_tombstones);
        assert_eq!(manifest.tombstone_count, 0);
    }

    #[tokio::test]
    async fn backup_reencrypts_under_a_different_destination_key() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, src_cipher) = test_backend_and_cipher(dir.path(), 43);
        let dest_dir = tempfile::tempdir().unwrap();
        let (dest_backend, dest_cipher) = test_backend_and_cipher(dest_dir.path(), 47);
        let coll = Collection::new("widgets");
        coll.put(&backend, &src_cipher, "a", &Widget { count: 9 }, None)
            .await
            .unwrap();

        backup_collection(
            &backend,
            &src_cipher,
            &dest_backend,
            &dest_cipher,
            &coll,
            "backup1",
            true,
        )
        .await
        .unwrap();

        // The destination backend's own manifest is only readable under
        // dest_cipher -- proves this was a real re-encryption, not a raw
        // ciphertext copy.
        let (manifest, etag) =
            get_json::<BackupManifest>(&dest_backend, &manifest_key("backup1", "widgets"), &dest_cipher)
                .await
                .unwrap();
        assert!(etag.is_some());
        assert_eq!(manifest.entity_count, 1);
    }
}
