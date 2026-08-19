# s3db

Typed, encrypted, CAS-consistent database over object storage — S3, R2, Azure Blob, GCS, or a plain local directory. No daemon, no coordination service, no extra port: a `Backend`, a passphrase, and typed values in and out is the whole surface.

Extracted from gitquarry, where it started as storage plumbing that turned out to have no dependency on the host application at all.

## Crates

| Crate | What it is |
|---|---|
| [`s3db`](crates/s3db) | The engine (plus the `s3db-inspect` and `s3db-local-migrate` binaries): `Backend` drivers, `Collection`/`Singleton`/`Blob`, `SecondaryIndex`, transactions, the `lsm` table engine, GC, backup, caching |
| [`s3db-crypto`](crates/s3db-crypto) | The AEAD primitive behind encryption-at-rest (XChaCha20Poly1305 or AES-256-GCM + Argon2id + optional zstd), usable standalone |
| [`s3db-macros`](crates/s3db-macros) | `#[derive(Entity)]` — generates the `Collection`/`SecondaryIndex` boilerplate for a struct |

Start with [`crates/s3db/README.md`](crates/s3db/README.md) for the API, or [`docs/s3db.md`](docs/s3db.md) for the full architecture write-up.

## Design docs

> The `docs/` directory these three entries point at was deleted in 74d5330 (a `chore(deps)` commit) and has not been restored; the links are dead until it is. Recover it from that commit's parent if the write-ups are still wanted.

- `docs/s3db.md` — architecture as it stands today.
- `docs/s3db-fulldb-roadmap.md` — the LSM engine over object storage. **Implemented**, phases 1-8: `lsm::Wal`, `Memtable`, `sstable` flush, CAS-controlled `manifest`, `compactor`, typed columnar blocks with per-column stats, `Table::scan`, `SecondaryLsmIndex`, `TableLocation`/`BackendRegistry` multi-backend routing, and `query::Predicate` block pruning. One structural limit to know before reaching for it: a `Table`'s WAL and memtable are local to the process, so a table has a single writer and other processes see only what has been flushed.
- `docs/s3db-local-mode.md` — `redb`-backed local mode with real ACID transactions. Implemented: `engine = "redb"`, `s3db-local-migrate`, `AtomicBackend`, `RangeBackend`, `atomic::put_with_index`.

## Status

Prealpha. The on-disk and on-bucket formats are not stable yet, and there is no migration tooling between versions.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
