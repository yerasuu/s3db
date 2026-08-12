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

#[derive(Clone, Serialize, Deserialize)]
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
    /// A plain `http://` `endpoint_url` is refused by default -- credentials
    /// and every object's body would ride cleartext on the wire. Set this to
    /// opt in explicitly (a local MinIO/dev endpoint with no TLS in front of
    /// it, say); real S3/R2 and any `https://` endpoint are unaffected
    /// either way.
    #[serde(default)]
    pub allow_insecure_http: bool,
}

impl std::fmt::Debug for S3Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Params")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("endpoint_url", &self.endpoint_url)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"REDACTED")
            .field("path_style", &self.path_style)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish()
    }
}

/// Cloudflare R2 — same S3 API as [`S3Params`] underneath (see
/// [`crate::s3::S3Backend::new_r2`]), but a narrower field set: no
/// `endpoint_url`/`region`/`path_style` to fill in by hand, R2's account id
/// determines all three.
#[derive(Clone, Serialize, Deserialize)]
pub struct R2Params {
    /// The literal R2 bucket name — same reasoning as [`S3Params::bucket`].
    pub bucket: String,
    /// Cloudflare account id: `<account_id>.r2.cloudflarestorage.com` is
    /// this bucket's S3-compatible endpoint.
    pub account_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl std::fmt::Debug for R2Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("R2Params")
            .field("bucket", &self.bucket)
            .field("account_id", &self.account_id)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"REDACTED")
            .finish()
    }
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
    /// Which on-disk representation this directory uses. Defaults to
    /// [`LocalEngine::Files`] — the format every existing deployment already
    /// has on disk — so upgrading this crate never silently reinterprets a
    /// directory nobody asked to migrate. See [`crate::local`]'s module doc
    /// for what `Redb` gives up the file format for.
    #[serde(default)]
    pub engine: LocalEngine,
}

/// [`LocalParams::engine`]'s two on-disk representations for the `local`
/// driver. Not additive/mergeable: a directory is entirely one or the other,
/// never a mix, so changing this on a directory that already has data needs
/// an explicit migration (`s3db-local-migrate`), not just flipping the
/// field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalEngine {
    /// One real file per key plus its CAS sidecars (`<key>.s3dbrev`,
    /// `<key>.s3dblock`) — see [`crate::local::files`]. The long-standing
    /// default; every directory that predates this field is one of these.
    #[default]
    Files,
    /// A single `redb` database file — see [`crate::local::redb_backend`].
    /// Real ACID transactions, native range scans, no CAS emulation.
    Redb,
}

#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for AzureParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureParams")
            .field("bucket", &self.bucket)
            .field("account_name", &self.account_name)
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("client_secret", &"REDACTED")
            .finish()
    }
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
