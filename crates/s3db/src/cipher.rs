//! Re-exports `s3db-crypto`'s [`Cipher`]/[`CompressionStrategy`]/
//! [`CipherAlgorithm`]/[`EncryptionMode`] unchanged.
//! The actual encryption primitive moved to its own crate specifically so a
//! caller that only needs `Cipher` (sealing session cookies, say —
//! unrelated to anything in a bucket) doesn't have to pull in every driver
//! dependency (`aws-sdk-s3`, Azure/GCS SDKs, ...) just to get it. Every internal `crate::cipher::...` path in this crate
//! stays exactly as it was — only this one module changed, not its callers.

pub use s3db_crypto::{Cipher, CipherAlgorithm, CompressionStrategy, EncryptionMode, KDF_VERSION, KEY_LEN, SALT_LEN};
