# s3db

Typed, encrypted, CAS-consistent database over S3-compatible object storage (S3, R2, Azure Blob, GCS, or a plain local directory). A `Backend`, a passphrase, and typed values in and out is the whole surface.

## Design

One trait, one entry format, transparent backend: everything above `Backend` (`Collection`/`Singleton`, `SecondaryIndex`, `txn::run`, `RequestCache`, the raw `payload` primitives) codes only against `&dyn Backend`. None of it ever touches a provider SDK, a key format, or a request shape directly — swap the driver, nothing above it changes.

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

`put_stream`/`get_stream` sit behind this crate's `streaming` cargo feature (off by default). This crate's own default profile assumes small, uniform objects (see `payload::MAX_OBJECT_BYTES`), so every driver's chunked-upload code is otherwise dead weight, never exercised. Without the feature both are provided methods that return an error instead of required ones each driver has to stub out; a caller that does need large blobs (git packs, LFS objects, ...) just enables the feature in its own `Cargo.toml`.

## Backends

Five drivers, selected via `BackendConfig` (a `#[serde(tag = "driver")]` enum) and `build_backend`:

| `driver` | Struct | Params |
|---|---|---|
| `s3` | `S3Backend::new` | `S3Params { bucket, region, endpoint_url, access_key_id, secret_access_key, path_style }` |
| `r2` | `S3Backend::new_r2` | `R2Params { bucket, account_id, access_key_id, secret_access_key }` |
| `azure` | `AzureBackend::new` | `AzureParams { bucket, account_name, tenant_id, client_id, client_secret }` |
| `gcs` | `GcsBackend::new` | `GcsParams { bucket, service_account_json_path }` |
| `local` | `LocalBackend::new` | `LocalParams { bucket }` (a filesystem directory) |

```rust
let cfg: BackendConfig = toml::from_str(&config_text)?; // { driver = "s3", bucket = "...", ... }
let backend: Arc<dyn Backend> = build_backend(&cfg);
```

## Encryption

On by default. Key derived with Argon2id at fixed params (19 MiB / 2 iterations / 1 thread — OWASP's low-memory profile), one random 16-byte salt per bucket.

`EncryptionMode` picks the policy: `Enabled { algorithm }` (the default, `CipherAlgorithm::XChaCha20Poly1305`) or `Disabled`, which takes an explicit opt-out and gives up confidentiality *and* tamper-evidence — with no AEAD tag, a storage provider can rewrite content undetectably. `CipherAlgorithm` is `XChaCha20Poly1305` (24-byte nonce) or `Aes256Gcm` (12-byte).

The two never mix by accident: an encrypting `Cipher` refuses an object marked unencrypted and vice versa, so `Disabled` can't be used to downgrade an encrypted deployment by writing plaintext into its bucket. `bootstrap::get_or_create_cipher_for` refuses `Disabled` outright against a bucket that was bootstrapped encrypted.

`Cipher::seal(aad, plaintext, compression)` / `open(aad, sealed)` bind ciphertext to `aad` as AEAD associated data — every caller passes the object's own S3 key as `aad`, so ciphertext copied onto a different key fails to decrypt. Sealed format: `nonce(24) || header(1) || ciphertext+tag`, header bound into the AAD alongside `aad` so it can't be flipped independently of the ciphertext. The header's high nibble is the algorithm (or "unencrypted"), the low nibble the compression — so each object records what sealed it, and a `Cipher` opens objects sealed by any algorithm regardless of which one it writes with. Changing the algorithm therefore affects new writes only, never forcing a re-seal; and because the default algorithm's nibble is zero, objects written before the header carried an algorithm at all are still valid input.

The nonce field is a fixed 24 bytes whichever algorithm sealed the object (AES-256-GCM uses the first 12 and ignores the rest) — the header that names the algorithm sits right after it, so a variable-length nonce would mean needing the algorithm to find the byte that tells you the algorithm.

`compression: CompressionStrategy` is `None` (this crate's own default — see `payload::MAX_OBJECT_BYTES`, small uniform objects rarely compress worth the CPU) or `Auto { threshold_bytes }` (zstd above that size, falling back to raw if compression doesn't actually shrink the input). `seal_stream`/`open_stream` (below) deliberately don't compress at all — what goes through them is already-compressed git pack data, a second pass buys nothing.

Streaming variants (`seal_stream`/`open_stream`, for `put_stream`/`get_stream`-sized payloads) chunk at 4 MiB, each chunk's AAD binding the base `aad`, the declared total length, and the chunk index — reordering, truncating, or duplicating chunks is detectable. Its 8-byte magic carries the algorithm in its last byte (the chunk framing has nowhere else to put one), so streams get the same per-object dispatch as small objects.

```rust
let cipher = s3db::bootstrap::get_or_create_cipher(backend.as_ref(), &passphrase).await?;
```

On first use, `get_or_create_cipher` generates the salt and writes it — **unencrypted, on purpose** — to `.conf/encryption.json`, alongside a sealed verifier. On every later start it re-derives the key from `passphrase` and opens that verifier: a wrong passphrase fails right here, as one clear startup error, instead of turning into scattered decrypt failures deeper in the app.

## Resilience stack (opt-in)

`resilience::build_resilient_backend(inner, config, metrics)` wraps a raw driver in a fixed decorator order:

```text
MeteredBackend -> RetryBackend -> ThrottledBackend -> CachedBackend -> driver
```

`RetryBackend` sits *outside* `ThrottledBackend` on purpose: each attempt (including retries) acquires and releases its own concurrency permit around just that one call, so a retry's backoff sleep never holds a permit hostage — the reverse order lets a slow retry sequence starve the very budget everything else is competing for. The circuit breaker lives inside `ThrottledBackend` (per-call permit + breaker share the same layer) and opens after `CircuitBreakerConfig::failure_threshold` consecutive real errors (never a `Cas::Conflict`), failing fast without touching the inner backend until `open_duration` elapses and lets one trial call through.

Capabilities beyond `Backend`'s required surface (`as_atomic`, `as_range`) are discovered by asking the chain, not by downcasting its top: a driver behind this stack keeps its native transaction instead of silently losing it. The observe-only layers forward the capability; the caches implement it themselves and invalidate the keys a batch touched, since that is the one bypass that would turn into wrong reads rather than lost bookkeeping.

`CachedBackend` (raw bytes + etag, cross-request LRU) sits innermost, right above the driver — see [`cache::CacheConfig`]: `max_entries` is the primary O(1) budget, `max_bytes` an optional safety net checked only once entries are already at capacity. `request_cache::RequestCache` is *not* part of this stack — it belongs outside all of it, at the application layer, wrapping whatever `build_resilient_backend` returns, since its own invalidation needs to see a write's result after retry/throttle already ran.

```rust
let metrics: s3db::SharedMetrics = std::sync::Arc::new(s3db::NoopMetrics); // or your own MetricsRecorder
let backend = s3db::resilience::build_resilient_backend(raw_backend, s3db::ResilienceConfig::default(), metrics);
```

The connection pool for the underlying HTTP client (each driver's own construction) isn't part of `ResilienceConfig` — it's sized once, at driver-construction time — but should match (not exceed) `max_concurrent_get + max_concurrent_put + max_concurrent_list`, with keep-alive and a generous idle timeout, so the concurrency this config grants doesn't end up bottlenecked on re-establishing connections.

### Typed caching (opt-in, per-`Collection`)

`cache::TypedCache<T>` is the alternative to `CachedBackend`'s raw-bytes cache: it caches the decrypted, deserialized `T` itself (wrapped in `Arc`, so a hit is a refcount bump, not a struct copy), trading away reusability across other types that might share the same S3 key (rare — `Collection`/`SecondaryIndex` use distinct key namespaces by design) for skipping AEAD-open + deserialize on every hit. Not wired into `Collection` itself — a caller reaching for it owns the cache instance and calls `get`/`insert`/`invalidate` around its own `Collection::get`/`put`/`delete` calls.

## Key rotation (opt-in)

`bootstrap::get_or_create_cipher` and a bare `Cipher` are all that most callers need. `key_rotation` is additive on top, for a caller that wants to rotate its passphrase without losing access to everything already encrypted under the old one — `Collection`/`SecondaryIndex`/`txn::run`/`payload` are untouched, still `&Cipher`-only.

```rust
let mut ring = s3db::key_rotation::get_or_create_keyring(backend, &passphrase, &retired_passphrases).await?;
// writes always use the active key:
let sealed = ring.active().seal("k", &plain, CompressionStrategy::None);
// reads try the active key, then retired keys most-recently-retired first:
let plain = ring.open("k", &sealed)?;

let new_key_id = s3db::key_rotation::rotate(backend, &mut ring, &new_passphrase).await?;
```

`EncryptionConfig` (at `.conf/encryption.json`, replacing the single-key `bootstrap` format) holds one `active_key_id` plus every `KeyMaterial` generation, retired ones flagged with `retired_at_ms`. Argon2id only runs once per key, at bootstrap/rotate time — `KeyRing::open`'s dual-read is cheap AEAD verification per attempt, not a repeated KDF, so falling back through several retired keys never becomes a latency cliff. Surviving a process restart mid-rotation still needs every retired key's original passphrase supplied via `retired_passphrases` (`key_id -> passphrase`) — there's no master-key-wraps-data-keys scheme here, so that map is the caller's own bookkeeping, same as its `passphrase` config field, never persisted in the bucket.

`KeyRing::forget_retired(key_id)` drops a retired key from process memory as soon as the caller's own accounting confirms it's unneeded, ahead of `key_rotation::forget_key`'s slower on-disk removal from `EncryptionConfig` — the trade-off this widens (derived key material now lives in memory as long as `EncryptionConfig` still lists it, not just for the duration of one `open` call) is deliberate, not an oversight: it's what makes dual-read cheap in the first place.

## Typed storage primitives

**`Collection`** — one object per entity, keyed `<prefix>/<name><suffix>` (default suffix `.json`, but the object itself is MessagePack on the wire, not literal JSON — see [Raw primitive](#raw-primitive)):

```rust
const USERS: Collection = Collection::new(".conf/users"); // .conf/users/<name>.json

let (user, etag): (Option<User>, Option<String>) = USERS.get(backend, &cipher, "alice").await?;
USERS.put(backend, &cipher, "alice", &user, etag.as_deref()).await?;
let names: Vec<String> = USERS.list_names(backend).await?;
```

`update` is the CAS read-modify-write loop every upsert and counter otherwise hand-rolls: it reads the entry (`T::default()` when absent, so it creates), hands `mutate` a copy, writes conditioned on the etag it read, and on conflict re-reads and re-runs `mutate` against the fresh value — with jittered backoff, since a conflict means a competing write landed. `mutate` answers `Update::Write` or `Update::Keep` (SQL's `ON CONFLICT DO NOTHING`, without paying a write to express it), and must be a pure function of the value it's handed — it runs once per attempt and earlier results are discarded. `Singleton::update` is the same against its one fixed key.

```rust
let total = COUNTERS.update::<Counters, _>(backend, &cipher, "chapters", |c| {
    c.total += 1;
    Ok(Update::Write)
}).await?;
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

`#[entity(key)]` marks the field the `Collection` is keyed by (exactly one, required). `#[entity(index)]` (`segment` defaults to `Raw`; `base64` for arbitrary bytes like a fingerprint or email) generates a `<FIELD>_INDEX` const, a private pointer type, and `find_by_<field>`/`claim_<field>`/`release_<field>` — a no-op success on `claim_`/`release_` when the field is `None` on an `Option<T>` index. `get`/`put`/`delete`/`list_keys` are generated once per entity, straight passthroughs to the underlying `Collection` (`delete` takes `&cipher` now too, for the tombstone it writes). `write_key(buf, key)` writes the entity's key into a caller-owned, reused buffer instead of allocating a fresh `String` — see [Raw primitive](#raw-primitive) for `Collection::write_key`, which this just forwards to.

**A note on entity field types.** Every `String` field is its own heap allocation — a struct with 6-8 short text fields (names, ids-as-text, slugs) makes 6-8 allocations per instance deserialized, which shows up at this crate's target volume for objects that get cached (`cache::TypedCache`) or moved through `BatchLoader`. For text that's short and bounded (usernames, ids, slugs — not free-form/long text like descriptions), consider [`compact_str::CompactString`](https://docs.rs/compact_str) in place of `String`: it inlines strings up to ~24 bytes with no heap allocation at all, and is drop-in compatible with `serde`. This is a recommendation for how you define your own entity structs, not something this crate enforces or depends on itself.

**`Blob`** — a value too big for one object, spanning several, still addressed and CAS'd as one thing:

```rust
const PAGES: Blob = Blob::new("pages");

PAGES.put(backend, &cipher, "chapter-1", &html, None).await?;          // CAS on the manifest
let (html, etag) = PAGES.get(&backend, &cipher, "chapter-1").await?;   // assembled, length-checked
let (manifest, etag) = PAGES.head(backend, &cipher, "chapter-1").await?; // size without the parts
```

`put_json`'s 256 KiB cap exists for good reasons and `put_stream` gives up encryption, CAS, and history to get past it; this is the middle ground, on `Backend`'s required surface only — no feature flag, no driver support, identical on every driver. The manifest at `<prefix>/<name>.json` is the blob's identity and the thing etags refer to; parts live under `<prefix>/.parts/<name>/<generation>/<index>`.

Each write puts its parts under a **fresh random generation** and CAS-writes the manifest last. Overwriting parts in place would let a reader holding the previous manifest assemble part 0 of the new value with part 1 of the old — tearing below the level CAS protects. Generations make that impossible, and reduce the worst case to a read that fails because its generation was already swept. A crash mid-write leaves orphan parts nothing references; a lost CAS race sweeps its own; `sweep_orphan_parts(min_age_ms)` clears the rest, skipping generations young enough to still be an in-flight write (which is why a generation id carries its own timestamp — nothing in `Backend` reports an mtime).

`get` checks the assembled length against the manifest, so a missing part is an `Err`, never a silently short body. `delete` is a hard delete, not a tombstone: keeping parts this size around to be restorable is a storage decision a caller should make explicitly.

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

`claim_once_typed`/`resolve_typed`/`release_typed` are the same operations for a field that already has a natural byte representation (a `u64`, raw bytes, ...) via the `IndexKey` trait, instead of paying a `.to_string()` allocation just to satisfy the `&str`-shaped API:

```rust
impl IndexKey for MyUid { fn key_bytes(&self) -> Cow<'_, [u8]> { Cow::Borrowed(self.as_bytes()) } }
idx.claim_once_typed(backend, &cipher, &my_uid, &pointer).await?;
```

`claim_inline`/`resolve_inline` are the opt-in alternative to `claim_once`/`resolve`: the pointer entry carries a denormalized copy of the target value itself, so `resolve_inline` is one `get` instead of pointer-then-fetch's two round trips — at the cost of every update to the real entity needing a matching `claim_inline` call to keep the copy from going stale (no automatic propagation). Worth it only where lookup volume dominates over update volume.

```rust
idx.claim_inline(backend, &cipher, &fingerprint, &pointer, &user).await?;
let user: Option<User> = idx.resolve_inline(backend, &cipher, &fingerprint).await?;
```

**`ShardedIndex`** — `SecondaryIndex`, but the key spreads across `2^prefix_bits` shards instead of one flat prefix, for an index hot enough to hit a single S3 partition's throughput ceiling:

```rust
let idx = ShardedIndex::new(".conf/index", "pubkey", Segment::Base64);
idx.claim_once(backend, &cipher, &fingerprint, &pointer).await?;
let (pointer, _etag) = idx.resolve::<UsernamePointer>(backend, &cipher, &fingerprint).await?;

idx.begin_rebalance(backend, &cipher).await?;      // doubles prefix_bits, pins writers to the old layout
idx.complete_rebalance(backend, &cipher).await?;    // copies every old entry to its new shard, clears the pin
// or, from periodic maintenance:
idx.maybe_rebalance(backend, &cipher, &metrics, /* threshold */ 8000).await?;
```

Rebalancing is gated by a single `ShardEpoch` record for the whole index (a documented simplification versus one epoch per old shard — see `sharded_index`'s module doc comment for the throughput trade-off that simplification costs during a rebalance, expected to be rare and brief). `resolve` checks both the new and (while a rebalance is in flight) old shard layout, so nothing becomes unresolvable mid-migration.

`Collection` gets the same idea for the data itself, not just a pointer to it — `KeyEntropy::HashPrefix`, opt-in:

```rust
const USERS: Collection = Collection::new(".conf/users").with_hash_prefix(256);
// .conf/users/<name>.json becomes .conf/users/<bucket:04x>/<name>.json;
// get/put/list_names are unaffected, still keyed by `name`.
```

## Numeric names

Object storage sorts keys as bytes, and so does `Collection::list_names` — so `"10"` sorts before `"9"`, invisibly, until an entity keyed by a number reaches double digits. `ordinal::encode_u64`/`decode_u64` (and the `i64` pair, which biases negatives so they sort correctly without a `'-'`) write fixed-width zero-padded names, making lexicographic order and numeric order the same thing for every value the type can hold.

```rust
chapters.put(backend, &cipher, &ordinal::encode_u64(10), &chapter, None).await?;
let n = ordinal::decode_u64(&name);  // None for anything it didn't write, unpadded names included
```

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

`txn::run_with_publisher` (opt-in; `run` is a thin wrapper using a no-op publisher) publishes a `ChangeEvent` per op through a `ChangePublisher` — all of them together, once, after the record reaches `Committed`, never as each op's own `put_cas` lands. A subscriber (search index, webhook, replica) that saw events mid-apply could react to writes from a transaction that then genuinely conflicted and rolled everything back, with no compensating event telling it so; publishing only after commit rules that out. An aborted transaction publishes nothing.

```rust
s3db::txn::run_with_publisher(backend, &cipher, ops, &my_publisher).await?;
```

## Point-in-time reads (opt-in)

`snapshot::ReadSnapshot` gives a best-effort, time-bounded view over a `Collection`'s `.history/` archive — **not** real MVCC, no cross-entity atomicity, same honesty `backup::BackupConsistency::FuzzySnapshot` already commits to for a full-bucket backup, just at single-entity scale:

```rust
let snap = s3db::snapshot::ReadSnapshot::open(backend, &cipher, Duration::from_secs(300)).await?;
let value: Option<User> = snap.get(backend, &cipher, &USERS, "alice").await?;
snap.close(backend).await; // best-effort, releases the lease early
```

`open`'s `max_duration` is a hard cap, not a suggestion — this isn't for long-lived snapshots (that's a real point-in-time backup restore's job), it only exists so a GC/maintenance sweep that happens to prune `.history/` mid-read doesn't yank a version out from under an in-flight snapshot. It registers a `SnapshotLease` at `.conf/snapshots/<snapshot_id>.json`; a sweep is expected to check `now - timestamp_ms < max_duration_ms` before pruning any history entry whose own timestamp falls inside that window.

`Collection::version_timestamp` (the timestamp behind this) records when a `.history/` entry was *retired* (overwritten by the next write), stored in a companion `{etag}.meta.json` object alongside the archive itself — orthogonal to `T`, so both `put_versioned`'s typed archiving and `Collection::delete`'s raw-byte archiving write one the same way.

## Backup / restore (opt-in)

`backup::backup_collection`/`restore_collection` do a logical backup of one `Collection` at a time — a `scroll` (list + read every entity) copied to a destination, not a storage-level snapshot, so it works identically across every `Backend`:

```rust
let manifest = s3db::backup::backup_collection(
    src_backend, &src_cipher, dest_backend, &dest_cipher, &USERS, "2026-01-15", /* include_tombstones */ true,
).await?;
// ... later, onto a live destination:
s3db::backup::restore_collection(backup_backend, &backup_cipher, dest_backend, &dest_cipher, &USERS, "2026-01-15").await?;
```

Source and destination backend/cipher can be the same (a backup alongside the live data) or genuinely different (a separate bucket, a different encryption key) — every entity is decrypted under its source key and re-sealed under its destination key, never copied as raw ciphertext, which would carry the wrong AAD for its new location.

`BackupManifest.consistency` is always `BackupConsistency::FuzzySnapshot` today, and says so explicitly: the scroll runs with no coordination against concurrent writes, so while any individual entity is read whole, the overall backup can mix states from different instants within `[started_at_ms, finished_at_ms]` — not a cross-entity atomic point-in-time (the same honesty `snapshot::ReadSnapshot` commits to at single-entity scale). `restore_collection` returns the same manifest, so a caller restoring from a backup inherits the identical caveat rather than assuming more precision than the mechanism gives.

Tombstones are included by default (`include_tombstones: true`) — omitting them silently loses the entire soft-delete audit/recovery trail at exactly the moment (disaster recovery) it's most needed; `manifest.includes_tombstones` records whichever way a caller chose.

## Garbage collection / maintenance (opt-in)

`gc::sweep` runs one collection's cleanup: retries `PurgeState::Pending` tombstones' underlying delete once they're older than `tombstone_retry_age`, forgets `PurgeState::Purged` tombstone records past `tombstone_purge_age`, and (if `history_max_age` is set) prunes `.history/` entries past that age — checking `snapshot::list_leases` first, so a live `ReadSnapshot` never loses a version it still needs.

```rust
let report = s3db::gc::sweep(backend, &cipher, &USERS, &GcConfig::default()).await?;
// or, across every collection an app registers:
let scanner = s3db::MaintenanceScanner::new(GcConfig::default());
scanner.run(backend, &cipher, &[&USERS, &GROUPS]).await?;
```

`MaintenanceScanner` is narrower than a single-scan-many-conditions design might suggest: there's no schema-migration or key-rotation rescan in this crate to fuse in (see `maintenance`'s own module doc for why neither applies today), so what it actually consolidates is running `gc::sweep` over every registered collection from one call and one config, not fusing separate scans into a single read per object.

## Write-ahead log (opt-in)

`txn::run` already recovers a crashed multi-key transaction; `wal` covers the gap that leaves — a single `put_cas` outside a transaction whose response never arrives, so nobody can tell "never attempted" from "attempted, landed or not, we don't know" from the outside:

```rust
let sealed = cipher.seal(key, &plaintext, CompressionStrategy::None);
let cas = s3db::wal::put_cas_with_wal(backend, &cipher, key, sealed, expected_etag).await?;
// at startup, or periodically:
s3db::wal::recover_stale(backend, &cipher, Duration::from_secs(60)).await?;
```

A WAL entry at `.conf/wal/<op_id>.json` records the write's intent (a hash of the exact sealed bytes) before attempting it, and is cleared once the outcome is definitively known (`Cas::Ok` or `Cas::Conflict` — both are answers). `recover_stale` resolves entries older than a threshold by comparing the object currently at that key against the recorded hash — diagnostic and cleanup only, never a delivery guarantee: it clears the WAL entry either way and never retries the write itself or touches the data key, since a stale retry the original caller never asked for could clobber something newer.

## BatchLoader, HealthProbe, WriteCoalescer (all opt-in)

`batch_loader::BatchLoader` fans a key list out concurrently, bounded by a `MemoryBudget` (`max_buffer_bytes / MAX_OBJECT_BYTES` concurrent fetches — every object is capped, so that's exactly how many can be in flight without risking more than the configured buffer):

```rust
let loader = BatchLoader::new(MemoryBudget::default());
let results: HashMap<String, Result<Option<User>>> = loader.load_many(&backend, &cipher, keys).await;
```

`Ok(None)` means the key doesn't exist — the same parity `Collection::get` already has, not conflated with `Err` (reserved for a real backend/deserialization failure).

`health::HealthProbe` does a real `get` every time `ready()` is called — the one rule it needs its `Backend` to follow is no response-caching decorator anywhere in it (`CachedBackend` in particular), or `ready()` ends up measuring "do I have a copy in RAM" instead of "can I reach the backend right now", exactly backwards from what an orchestrator's restart/routing decisions need:

```rust
let probe = HealthProbe::new(probe_backend); // built without CachedBackend
probe.ready().await; // real network round trip
probe.last_ready();   // cheap, last-known state between probes
```

`coalescer::WriteCoalescer` debounces repeated writes to the same key into one real `put_cas` after `flush_interval`:

```rust
let coalescer = WriteCoalescer::new(backend.clone(), Duration::from_millis(200));
coalescer.write(key, sealed_bytes); // remembers the latest value, schedules a flush if none is pending
```

`flush` never does a blind CAS against the etag captured when the debounce window started — it re-reads and retries (CAS-with-reread, same discipline as `Collection::restore`'s own write), so a write that landed elsewhere during the debounce window can't cause the coalesced write to be silently dropped.

## RequestCache

A decorator over `Backend` that caches `get()` results for the lifetime of one request or connection — never process-wide, since multiple server instances share one bucket and a stale cached permission record must not outlive its revocation. `put_cas`/`delete`/`delete_many` invalidate the touched keys regardless of outcome; `list_prefix`/`put_stream`/`get_stream` pass through uncached.

```rust
let cached: Arc<dyn Backend> = Arc::new(RequestCache::new(Arc::clone(&backend)));
// use `cached` for this one connection/request, then drop it
```

## Raw primitive

`payload::delete_prefix` sweeps every object under a prefix — the cascade object storage has no equivalent for, since the children of a deleted entity are just keys sharing a prefix. Each pass re-lists, so it is idempotent and resumable: a partial sweep (crash, exhausted pass budget, a delete that didn't confirm) is finished by calling it again, no cursor to persist. It returns a `SweepReport` whose `remaining` says whether it is done, and stops early if a pass confirms nothing rather than re-listing the same keys eight times. An empty prefix is refused.

`payload::count_prefix` answers "how many objects, how many bytes" from one listing — the right fallback for a count not hot enough to justify maintaining a counter with `Collection::update`, and O(number of keys) in requests and memory for one that is.

Everything above builds on `payload::{get_json, put_json}` — encrypt/decrypt plus a single `Backend::get`/`put_cas` call — and `delete_object`/`list_all_keys` as thin wrappers over `Backend::delete`/`list_prefix`.

The wire format is MessagePack (`rmp-serde`), not JSON: this crate's own entities are always Rust structs with `serde`, and the object is *always* encrypted, so JSON's "it's readable if you squint at the raw bytes" benefit never applied in the first place — MessagePack is smaller and faster to parse for the same schema-evolution story (`#[entity(...)]`'s migrations tolerate added/removed fields the same way either format). `.conf/encryption.json` is the one deliberate exception, via `get_json_plain`/`put_json_plain`: unencrypted and plain JSON on purpose, since it's the one object meant to be read by hand during an incident.

`put_json` rejects anything over `payload::MAX_OBJECT_BYTES` (256 KiB) before it ever reaches `Cipher::seal` — a guard against an application bug accidentally serializing a large blob through the small-object path instead of `put_stream`.
