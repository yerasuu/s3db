# s3db

Typed, encrypted, CAS-consistent database over object storage — S3, R2, Azure Blob, GCS, or a plain local directory. No daemon, no coordination service, no extra port: a `Backend`, a passphrase, and typed values in and out is the whole surface.

Extracted from gitquarry, where it started as storage plumbing that turned out to have no dependency on the host application at all.

## Crates

| Crate | What it is |
|---|---|
| [`s3db`](crates/s3db) | The engine: `Backend` drivers, `Collection`/`Singleton`, `SecondaryIndex`, transactions, GC, backup, caching |
| [`s3db-crypto`](crates/s3db-crypto) | The AEAD primitive behind encryption-at-rest (XChaCha20Poly1305 + Argon2id + optional zstd), usable standalone |
| [`s3db-macros`](crates/s3db-macros) | `#[derive(Entity)]` — generates the `Collection`/`SecondaryIndex` boilerplate for a struct |

Start with [`crates/s3db/README.md`](crates/s3db/README.md) for the API, or [`docs/s3db.md`](docs/s3db.md) for the full architecture write-up.

## Design docs

- [`docs/s3db.md`](docs/s3db.md) — architecture as it stands today.
- [`docs/s3db-fulldb-roadmap.md`](docs/s3db-fulldb-roadmap.md) — planned LSM engine over object storage: WAL, memtable, SSTable flush, CAS-controlled manifest, compaction. Not implemented.
- [`docs/s3db-local-mode.md`](docs/s3db-local-mode.md) — planned `redb`-backed local mode with real ACID transactions. Not implemented.

## Status

Prealpha. The on-disk and on-bucket formats are not stable yet, and there is no migration tooling between versions.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
