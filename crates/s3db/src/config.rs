use serde::{Deserialize, Serialize};

/// Which storage driver a bucket entry uses, and that driver's own
/// connection parameters — tagged on `driver` so every entry shares the
/// same top-level shape no matter which backend it points at.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "driver", rename_all = "snake_case")]
pub enum BackendConfig {
    S3(S3Params),
    R2(R2Params),
    Azure(AzureParams),
    Gcs(GcsParams),
    Local(LocalParams),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Params {
    /// The literal S3 bucket name — deliberately a separate field from
    /// whatever local name a caller's config uses to refer to this entry.
    pub bucket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub path_style: bool,
}

/// Cloudflare R2 — same S3 API as [`S3Params`] underneath (see
/// [`crate::s3::S3Backend::new_r2`]), but a narrower field set: no
/// `endpoint_url`/`region`/`path_style` to fill in by hand, R2's account id
/// determines all three.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2Params {
    /// The literal R2 bucket name — same reasoning as [`S3Params::bucket`].
    pub bucket: String,
    /// Cloudflare account id: `<account_id>.r2.cloudflarestorage.com` is
    /// this bucket's S3-compatible endpoint.
    pub account_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

/// Plain local filesystem directory — no external storage provider at all,
/// see [`crate::local`]'s module doc for the CAS/single-machine tradeoffs
/// that come with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalParams {
    /// Filesystem directory this driver reads/writes under — same `bucket`
    /// field name every other driver uses for its own physical storage
    /// target, so every config entry shares one shape regardless of driver,
    /// even though a directory isn't literally a "bucket".
    pub bucket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureParams {
    /// The literal Azure Blob container name — same reasoning as
    /// [`S3Params::bucket`] (kept as `bucket` rather than `container` so
    /// every driver's config shares one field name for its physical
    /// storage target).
    pub bucket: String,
    /// Storage account name — still needed to build the
    /// `https://<account_name>.blob.core.windows.net/` service URL even
    /// though auth itself no longer goes through this account (see below).
    pub account_name: String,
    /// Entra ID app registration's directory (tenant) id. The
    /// `azure_storage_blob` crate line paired with `azure_core` 1.x dropped
    /// account-key/HMAC auth entirely — only `azure_identity` credentials
    /// are supported, so `account_key` is gone in favor of these three.
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcsParams {
    /// The literal GCS bucket name — same reasoning as [`S3Params::bucket`].
    pub bucket: String,
    /// Path to a service-account JSON key file. Read lazily, on this
    /// driver's first real request (see [`crate::gcs`]'s module doc), not
    /// at startup.
    pub service_account_json_path: String,
}
