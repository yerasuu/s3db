# s3db

Typed, encrypted, CAS-consistent database over S3-compatible object storage (S3, R2, Azure Blob, GCS, or a plain local directory). Extracted from [gitquarry](../..): everything here started as gitquarry-specific plumbing (`storage::*`, `crypto::*`) that turned out to have no gitquarry dependency at all — a `Backend`, a passphrase, and JSON in and out is the whole surface.

## Design

One trait, one entry format, transparent backend: everything above `Backend` (`Collection`/`Singleton`, `SecondaryIndex`, `txn::run`, `RequestCache`, the raw `json` primitives) codes only against `&dyn Backend`. None of it ever touches a provider SDK, a key format, or a request shape directly — swap the driver, nothing above it changes.

```rust
#[async_trait::async_trait]
pub trait Backend: Send + Sync + std::fmt::Debug {
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)>;
    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas>;
    async fn delete(&self, key: &str) -> Result<DeleteOutcome>;
    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome>;
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>>;
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()>;
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()>;
}
```

`put_cas` is the one operation every driver must give real compare-and-swap semantics for — `expected_etag: None` means "must not exist yet" — even a driver with no native conditional-write support (e.g. a shared filesystem) has to fake it properly, not best-effort. That single guarantee is what every other layer in the crate (claims, transactions, versioned writes) is built on top of.

`delete`/`delete_many` stay best-effort (a single key's own failure never aborts the call, and nothing in the crate depends on either actually landing), but both now report a `DeleteOutcome { attempted, confirmed }` instead of swallowing the result — informative bookkeeping for a caller that does want to know (`Collection::delete`'s tombstone, a future GC sweep), never a business-logic failure signal.

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

`delete` is a soft-delete: it archives the current value the same way `put_versioned` does, writes a tombstone at `<prefix>/.deleted/<name>.json` recording that archive's etag, then best-effort-deletes the real object — the tombstone's `purge_state` stays `Pending` if that underlying delete never confirms, `Purged` once it does. `restore` reads the tombstone's `restore_etag`, writes that archived value back (winning over any orphaned object still occupying the key), and clears the tombstone:

```rust
USERS.delete(backend, &cipher, "alice").await;                     // soft-delete, archives + tombstones
USERS.restore::<User>(backend, &cipher, "alice").await?;            // undo, if there's something to restore
```

`get`/`list_names`/`list_all` never consult the tombstone — they read the real object's state directly, so a delete whose underlying `Backend::delete` hasn't confirmed yet is still visible for that (self-healing, not immediately consistent) window rather than doubling every read's cost to close it.

### `#[derive(Entity)]` — the same primitives, without the boilerplate

Every hand-written entity above ends up writing the same handful of things: a `Collection` const, a `SecondaryIndex` const per lookup field, a tiny pointer struct, and a claim/resolve/release trio. `#[derive(Entity)]` (from the `s3db-macros` crate, re-exported at the crate root) generates exactly that — no query planner, no ORM magic underneath, it still bottoms out in plain `Collection`/`SecondaryIndex` calls:

```rust
#[derive(Serialize, Deserialize, Default, Entity)]
#[entity(collection = ".conf/users")]
struct User {
    #[entity(key)]
    username: String,
    #[entity(index)]
    email: Option<String>,
    #[entity(index(segment = "base64"))]
    fingerprint: Option<String>,
    is_admin: bool,
}

let (user, etag) = User::get(backend, &cipher, "alice").await?;
user.put(backend, &cipher, etag.as_deref()).await?;
user.claim_email(backend, &cipher).await?;                 // CAS-claim email in its own index
let by_mail = User::find_by_email(backend, &cipher, "alice@example.com").await?; // index -> pointer -> Collection::get
user.release_email(backend).await;                          // best-effort unclaim
```

`#[entity(key)]` marks the field the `Collection` is keyed by (exactly one, required). `#[entity(index)]` (`segment` defaults to `Raw`; `base64` for arbitrary bytes like a fingerprint or email) generates a `<FIELD>_INDEX` const, a private pointer type, and `find_by_<field>`/`claim_<field>`/`release_<field>` — a no-op success on `claim_`/`release_` when the field is `None` on an `Option<T>` index. `get`/`put`/`delete`/`list_keys` are generated once per entity, straight passthroughs to the underlying `Collection` (`delete` takes `&cipher` now too, for the tombstone it writes).

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
