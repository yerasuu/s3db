//! `s3db-crypto`: the pure encryption primitive behind `s3db`'s mandatory
//! encryption-at-rest — derives a key from a passphrase and seals/opens
//! bytes with AEAD, no storage backend, no `S3`/bucket concept at all. Split
//! out from `s3db` itself into its own crate specifically so a caller that
//! doesn't need object storage (sealing session cookies, say — unrelated to
//! anything in a bucket) doesn't have to pull in `s3db`'s driver
//! dependencies (`aws-sdk-s3`, ...) just to get `Cipher`. `s3db` itself re-exports this crate's types
//! from its own `cipher` module unchanged, so nothing inside `s3db` had to
//! change to use it from here instead.
//!
//! See `s3db::bootstrap` for deriving/creating a bucket's [`Cipher`] from a
//! passphrase plus a durably-stored salt — that part does need `Backend`,
//! so it stays in `s3db` proper, not here.
//!
//! Five independent concerns, one module each, so extending or swapping any
//! one of them never touches the others -- this file itself is wiring only,
//! no logic of its own:
//! - [`kdf`] -- passphrase + salt -> key (Argon2id today).
//! - [`algorithm`] -- which AEAD sealed an object, and the header byte that
//!   records it.
//! - [`compression`] -- optional pre-encryption compression (zstd today).
//! - [`cipher`] -- the keyed AEAD instances and the small-object
//!   `seal`/`open` format tying the three above together.
//! - [`stream`] -- the separate, large-object streaming format.

mod algorithm;
mod cipher;
mod compression;
mod kdf;
mod stream;

pub use algorithm::{CipherAlgorithm, EncryptionMode};
pub use cipher::Cipher;
pub use compression::CompressionStrategy;
pub use kdf::{KDF_VERSION, KEY_LEN, SALT_LEN};
