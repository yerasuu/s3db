//! `s3db`: a typed database over S3-compatible object storage (S3, R2,
//! Azure Blob, GCS, or a plain local directory), encryption mandatory,
//! CAS-consistent. Extracted from gitquarry: everything here used to be
//! gitquarry-specific plumbing (`storage::*`, `crypto::*`) that turned out
//! to have no gitquarry dependency at all — a `Backend`, a passphrase, and
//! JSON in and out is the whole surface.
//!
//! [`backend::Backend`] is the storage abstraction (5 implementors, one per
//! driver); [`cipher::Cipher`]/[`bootstrap`] handle mandatory encryption at
//! rest; [`json`] is the raw encrypted-JSON-object primitive everything
//! else builds on.

pub mod backend;
pub mod bootstrap;
pub mod cipher;
pub mod collection;
pub mod config;
pub mod index;
pub mod json;

mod azure;
mod gcs;
mod local;
mod s3;

pub use backend::{Backend, Cas, build_backend};
pub use cipher::Cipher;
pub use collection::{Collection, Singleton};
pub use config::{AzureParams, BackendConfig, GcsParams, LocalParams, R2Params, S3Params};
pub use index::{Segment, SecondaryIndex};
pub use json::{delete_object, get_json, list_all_keys, put_json};

pub use azure::AzureBackend;
pub use gcs::GcsBackend;
pub use local::LocalBackend;
pub use s3::S3Backend;
