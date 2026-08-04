# s3db

Typed, encrypted, CAS-consistent database over S3-compatible object storage (S3, R2, Azure Blob, GCS, or a plain local directory). Extracted from [gitquarry](../..): everything here started as gitquarry-specific plumbing (`storage::*`, `crypto::*`) that turned out to have no gitquarry dependency at all — a `Backend`, a passphrase, and JSON in and out is the whole surface.

## Design

One trait, one entry format, transparent backend: everything above `Backend` (`Collection`/`Singleton`, `SecondaryIndex`, `txn::run`, `RequestCache`, the raw `json` primitives) codes only against `&dyn Backend`. None of it ever touches a provider SDK, a key format, or a request shape directly — swap the driver, nothing above it changes.

```rust
#[async_trait::async_trait]
pub trait Backend: Send + Sync + std::fmt::Debug {
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)>;
    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas>;
    async fn delete(&self, key: &str);
    async fn delete_many(&self, keys: &[String]) -> Result<()>;
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>>;
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()>;
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()>;
}
```

`put_cas` is the one operation every driver must give real compare-and-swap semantics for — `expected_etag: None` means "must not exist yet" — even a driver with no native conditional-write support (e.g. a shared filesystem) has to fake it properly, not best-effort. That single guarantee is what every other layer in the crate (claims, transactions, versioned writes) is built on top of.

Deliberately small surface: no presign, multipart, byte-range, or ACLs — derived from an audit of every call the original codebase actually made, not a speculative superset.

## Backends

Five drivers, selected via `BackendConfig` (a `#[serde(tag = "driver")]` enum) and `build_backend`:

| `driver` | Struct | Params |
|---|---|---|
| `s3` | `S3Backend::new` | `S3Params { bucket, region, endpoint_url, access_key_id, secret_access_key, path_style }` |
| `r2` | `S3Backend::new_r2` | `R2Params { bucket, account_id, access_key_id, secret_access_key }` |
| `azure` | `AzureBackend::new` | `AzureParams { bucket, account_name, account_key }` |
| `gcs` | `GcsBackend::new` | `GcsParams { bucket, service_account_json_path }` |
| `local` | `LocalBackend::new` | `LocalParams { bucket }` (a filesystem directory) |

```rust
let cfg: BackendConfig = toml::from_str(&config_text)?; // { driver = "s3", bucket = "...", ... }
let backend: Arc<dyn Backend> = build_backend(&cfg);
```

## Encryption

Mandatory, no opt-out. XChaCha20Poly1305 (24-byte nonce), key derived with Argon2id at fixed params (19 MiB / 2 iterations / 1 thread — OWASP's low-memory profile), one random 16-byte salt per bucket.

`Cipher::seal(aad, plaintext)` / `open(aad, sealed)` bind ciphertext to `aad` as AEAD associated data — every caller passes the object's own S3 key as `aad`, so ciphertext copied onto a different key fails to decrypt. Sealed format: `nonce(24) || ciphertext+tag`.

Streaming variants (`seal_stream`/`open_stream`, for `put_stream`/`get_stream`-sized payloads) chunk at 4 MiB, each chunk's AAD binding the base `aad`, the declared total length, and the chunk index — reordering, truncating, or duplicating chunks is detectable.

```rust
let cipher = s3db::bootstrap::get_or_create_cipher(backend.as_ref(), &passphrase).await?;
```

On first use, `get_or_create_cipher` generates the salt and writes it — **unencrypted, on purpose** — to `.conf/encryption.json`, alongside a sealed verifier. On every later start it re-derives the key from `passphrase` and opens that verifier: a wrong passphrase fails right here, as one clear startup error, instead of turning into scattered decrypt failures deeper in the app.

## Typed storage primitives

**`Collection`** — one JSON object per entity, keyed `<prefix>/<name><suffix>` (default suffix `.json`):

```rust
const USERS: Collection = Collection::new(".conf/users"); // .conf/users/<name>.json

let (user, etag): (Option<User>, Option<String>) = USERS.get(backend, &cipher, "alice").await?;
USERS.put(backend, &cipher, "alice", &user, etag.as_deref()).await?;
let names: Vec<String> = USERS.list_names(backend).await?;
```

`put_versioned` archives the previous value (under its own etag, at `<prefix>/.history/<name>/<etag>.json`) before overwriting — `list_versions`/`get_version` read it back. `list_all`/`find_all` fan out concurrently across every entry — full scan, only for admin views or small collections.

**`Singleton`** — same shape, one fixed key, no name:

```rust
const GLOBAL: Singleton = Singleton::new(".conf/global.json");
let (cfg, etag) = GLOBAL.get::<GlobalConfig>(backend, &cipher).await?;
```

**`SecondaryIndex`** — a lookup pointer keyed `<root>/<kind>/<encoded-raw>.json`, `Segment::Raw` (already a safe path component) or `Segment::Base64` (arbitrary bytes — fingerprints, emails):

```rust
const PUBKEY_INDEX: SecondaryIndex = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
let claimed: bool = PUBKEY_INDEX.claim_once(backend, &cipher, &fingerprint, &pointer).await?;
let (pointer, _etag) = PUBKEY_INDEX.resolve::<UsernamePointer>(backend, &cipher, &fingerprint).await?;
```

`claim_self_healing` handles the "name squatted by something since-deleted" case: on conflict it re-fetches the existing pointer and calls a caller-supplied `is_genuine` check before deciding to refuse or reclaim.

## Multi-key transactions

`txn::run` bundles several create-only writes into one all-or-nothing unit — no update/liveness protocol needed, because every op is a create and the target key is its own lock:

```rust
let ops = vec![
    TxnOp::create(NAMESPACE_INDEX.key(name), &reservation)?,
    TxnOp::create(USERS.key(name), &user)?,
];
match s3db::txn::run(backend, &cipher, ops).await? {
    Cas::Ok => { /* every op landed */ }
    Cas::Conflict => { /* none did — something else already held one of the keys */ }
}
```

A `Preparing` record at `.conf/txn/<txn_id>.json` survives a crash mid-transaction; `txn::recover_stale(backend, &cipher, max_age)` — run at server startup — sweeps records older than `max_age` still `Preparing`, aborts and rolls them back, and returns how many it cleaned up.

## RequestCache

A decorator over `Backend` that caches `get()` results for the lifetime of one request or connection — never process-wide, since multiple server instances share one bucket and a stale cached permission record must not outlive its revocation. `put_cas`/`delete`/`delete_many` invalidate the touched keys regardless of outcome; `list_prefix`/`put_stream`/`get_stream` pass through uncached.

```rust
let cached: Arc<dyn Backend> = Arc::new(RequestCache::new(Arc::clone(&backend)));
// use `cached` for this one connection/request, then drop it
```

## Raw primitive

Everything above builds on `json::{get_json, put_json}` — encrypt/decrypt plus a single `Backend::get`/`put_cas` call — and `delete_object`/`list_all_keys` as thin wrappers over `Backend::delete`/`list_prefix`.
