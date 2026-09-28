# s3db

Typed, encrypted, CAS-consistent database over S3-compatible object storage (S3, R2, or a plain local directory). A `Backend`, a passphrase, and typed values in and out is the whole surface — no daemon, no coordination service.

Full reasoning and trade-offs for everything below live in the module docs (`cargo doc --open`, or [docs.rs](https://docs.rs/s3db)). This is the map, not the territory.

## Quickstart

```rust
let cfg: BackendConfig = toml::from_str(&config_text)?;
let backend: Arc<dyn Backend> = build_backend(&cfg)?;
let cipher = s3db::bootstrap::get_or_create_cipher(backend.as_ref(), &passphrase).await?;

const USERS: Collection = Collection::new(".conf/users"); // .conf/users/<name>.json

let (user, etag): (Option<User>, Option<String>) = USERS.get(&backend, &cipher, "alice").await?;
USERS.put(&backend, &cipher, "alice", &user, etag.as_deref()).await?;
```

## Backends

| `driver` | Params |
|---|---|
| `s3` | `S3Params { bucket, region, endpoint_url, access_key_id, secret_access_key, path_style }` |
| `r2` | `R2Params { bucket, account_id, access_key_id, secret_access_key }` |
| `local` | `LocalParams { bucket, engine }` — a filesystem directory, `engine = "redb"` (single file, real ACID CAS) or the deprecated `"files"` |

Every tuning type — `ResilienceConfig`, `CacheConfig`, `GcConfig`, `ExpiryConfig`, `LsmMaintenanceConfig`, `MemoryBudget`, `EncryptionMode` — loads from the same config file, `#[serde(default)]` so it only spells out what it changes:

```toml
driver = "s3"
bucket = "novels"
access_key_id = "..."
secret_access_key = "..."

[encryption]
mode = "enabled"

[resilience]
local_dir = "./local"   # SpooledBackend's write-intent journal
max_concurrent_get = 128
```

**A serialized config is secret material** — these types derive `Serialize`, so writing one out puts every credential in the clear. Set file permissions accordingly.

## Encryption

On by default, XChaCha20Poly1305 (or AES-256-GCM) with an Argon2id-derived key, one salt per bucket. `EncryptionMode::Disabled` needs an explicit opt-out and gives up tamper-evidence along with confidentiality — see `bootstrap`/`cipher`'s module docs for the AEAD framing and how it survives an algorithm change without re-sealing everything.

## Resilience stack (opt-in)

```rust
let backend = s3db::resilience::build_resilient_backend(raw_backend, config, metrics);
```

`MeteredBackend -> SpooledBackend -> CachedBackend -> RetryBackend -> ThrottledBackend -> driver`. Spooling (durable local write-intent) is unconditional for any driver that isn't already `local` — see `resilience`/`spool`'s module docs for the composition order and why. `cache::TypedCache<T>` is the opt-in alternative that caches decrypted values instead of raw bytes.

## Storage primitives

- **`Collection`** — one object per entity, CAS'd, with `update` (CAS retry loop), `put_versioned` (history), soft-`delete`/`restore` (tombstones).
- **`Singleton`** — same shape, one fixed key.
- **`Blob`** — a value spanning several objects past the 256 KiB single-object cap, still addressed and CAS'd as one thing.
- **`SecondaryIndex`** / **`MultiIndex`** — unique and non-unique lookup pointers.
- **`ShardedIndex`** — `SecondaryIndex` that spreads across shards for a hot index, with online rebalancing.
- **`#[derive(Entity)]`** (from `s3db-macros`) — generates the `Collection`/`SecondaryIndex`/claim-resolve-release boilerplate above from field attributes.

```rust
#[derive(Serialize, Deserialize, Default, Entity)]
#[entity(collection = ".conf/users")]
struct User {
    #[entity(key)]
    username: String,
    #[entity(index)]
    email: Option<String>,
}
```

Object keys sort as bytes — `ordinal::encode_u64`/`encode_i64` give fixed-width names so numeric order matches lexicographic order.

## Transactions

- `txn::run` — several create-only writes as one all-or-nothing unit; `txn::recover_stale` sweeps a crash mid-transaction.
- `txn_update::run_update` — the same for a mix of creates and updates, on drivers without a native transaction (`redb`'s `AtomicBackend` skips this entirely).

## Maintenance (all opt-in)

- `migrate` — versioned, resumable schema rewrites per collection.
- `gc::sweep` / `MaintenanceScanner` — tombstone purge, history pruning, expiry, run together across every registered collection.
- `ttl` — deadline-in-the-key expiry, identical on every driver.
- `backup::backup_collection`/`restore_collection` — logical backup/restore, fuzzy-snapshot consistency.
- `snapshot::ReadSnapshot` — best-effort, time-bounded point-in-time reads over a collection's history.
- `key_rotation` — rotate the encryption passphrase without losing access to what's already encrypted.
- `wal::put_cas_with_wal` — closes the "did that write land" gap for a single `put_cas` outside a transaction.

## LSM tables (opt-in)

`lsm::Table` — WAL + memtable + SSTables + compaction, for rows instead of one-object-per-entity. Single-writer per table, enforced by `WriterLease`, not just documented; `Table::open_read_only` for every other reader. Drive `lsm::maintenance::tick` from your own timer.

## Everything else

`BatchLoader` (bounded concurrent fan-out), `HealthProbe` (real round-trip readiness), `WriteCoalescer` (debounced writes), `RequestCache` (per-request cache), `s3db-inspect` (CLI for looking at a bucket by hand), `rest::serve` (read-only HTTP browser, behind the `rest` feature).

## Raw primitive

`Backend::list_page(prefix, after, limit)` — a portable, stateless cursor (a key, not an opaque token) that `payload::delete_prefix`/`count_prefix` and everything above builds on. Wire format is MessagePack, always encrypted except `.conf/encryption.json` itself.
