# Changelog

## v0.6.0

### Backend drivers

- Dropped the Azure and GCS drivers: `azure.rs`, `gcs.rs`,
  `BackendConfig::Azure`/`::Gcs`, `AzureParams`/`GcsParams`, and their
  crate dependencies are gone. `local`, `s3` (and `r2`, the same driver)
  remain.

### Local storage

- `local::FilesBackend`: closed the live-race half of its two-file CAS
  tear — reads now take a shared flock, writes an exclusive one, so a
  concurrent reader can no longer observe a data file and its rev
  sidecar mid-update. The crash-only tear (a kill between the two writes)
  is unchanged; only `RedbBackend` closes that one.
- `local::RedbBackend`: the bucket directory and `s3db.redb` are now
  created owner-only (0700/0600).
- `bin/s3db-local-migrate`: added a verify pass — every migrated key is
  read back from the new `redb` file and compared byte-for-byte against
  the original before the tool reports success.

### Transactions

- `txn_update::apply`: `already_ours` now decrypts and compares
  plaintext instead of comparing ciphertext, which was never equal
  across two seals of the same value (each seal uses a fresh random
  nonce) — recovery re-running an already-applied op no longer
  spuriously conflicts with its own prior write.

### Resilience

- `resilience::build_resilient_backend` now returns a `ResilientBackend`
  exposing the `SpooledBackend` handle it wires in, so callers can drive
  `recover_pending()` themselves.
- `wal::put_cas_with_wal` is deprecated in favor of
  `spool::SpooledBackend`, which retries automatically instead of only
  diagnosing.

### Performance

- `collection::put_versioned` now writes the archived version's body and
  its `archive_history_timestamp` concurrently; the live put still runs
  strictly after both, since `ReadSnapshot::get` falls back to the live
  value when no archived version is retired yet.

### Logging

- Replaced bare `eprintln!`/`println!` call sites with structured
  `tracing::warn!`, one target per module (`cache.rs`, `s3.rs`,
  `collection.rs`, `local/files.rs`, `local/redb_backend.rs`).
