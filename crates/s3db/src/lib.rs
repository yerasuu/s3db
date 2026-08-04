//! `s3db`: a typed database over S3-compatible object storage (S3, R2,
//! Azure Blob, GCS, or a plain local directory), encryption mandatory,
//! CAS-consistent. Extracted from gitquarry: everything here used to be
//! gitquarry-specific plumbing (`storage::*`, `crypto::*`) that turned out
//! to have no gitquarry dependency at all — a `Backend`, a passphrase, and
//! JSON in and out is the whole surface.
//!
//! [`backend::Backend`] is the storage abstraction (5 implementors, one per
//! driver); [`cipher::Cipher`]/[`bootstrap`] handle mandatory encryption at
//! rest; [`payload`] is the raw encrypted-object primitive everything else
//! builds on (MessagePack on the wire, see [`cipher::CompressionStrategy`]
//! for the optional compression underneath).
//!
//! One entry format, transparent backend: every layer above `Backend`
//! ([`payload`], [`collection::Collection`]/[`collection::Singleton`],
//! [`index::SecondaryIndex`], [`txn::run`], [`request_cache::RequestCache`])
//! codes only against `&dyn Backend` — get/put_cas/delete/list_prefix/
//! put_stream/get_stream, same CAS-etag semantics from every driver. None of
//! it ever touches a provider SDK, a key format, or a request shape
//! directly, so swapping drivers ([`build_backend`]) changes nothing above
//! this line.

pub mod backend;
pub mod bootstrap;
pub mod cache;
pub mod cipher;
pub mod collection;
pub mod config;
pub mod index;
pub mod key_rotation;
pub mod metrics;
pub mod payload;
pub mod request_cache;
pub mod resilience;
pub mod txn;

mod azure;
mod gcs;
mod local;
mod s3;

pub use backend::{Backend, Cas, DeleteOutcome, build_backend};
pub use cache::{CacheConfig, CachedBackend, TypedCache};
pub use cipher::{Cipher, CompressionStrategy};
pub use collection::{Collection, PurgeState, Singleton, Tombstone};
pub use config::{AzureParams, BackendConfig, GcsParams, LocalParams, R2Params, S3Params};
pub use index::{Segment, SecondaryIndex};
pub use key_rotation::{EncryptionConfig, KeyMaterial, KeyRing};
pub use metrics::{MetricsRecorder, NoopMetrics, SharedMetrics};
pub use payload::{MAX_OBJECT_BYTES, delete_object, get_json, list_all_keys, put_json};
pub use request_cache::RequestCache;
pub use resilience::{CircuitBreakerConfig, MeteredBackend, ResilienceConfig, RetryBackend, ThrottledBackend, build_resilient_backend};

/// ORM-style shortcut: `#[derive(Entity)]` generates the `Collection`/
/// `SecondaryIndex` boilerplate a hand-written entity would otherwise repeat
/// per struct. See `s3db_macros` for the attribute grammar
/// (`#[entity(collection = "...")]`, `#[entity(key)]`, `#[entity(index)]`).
pub use s3db_macros::Entity;

pub use azure::AzureBackend;
pub use gcs::GcsBackend;
pub use local::LocalBackend;
pub use s3::S3Backend;
