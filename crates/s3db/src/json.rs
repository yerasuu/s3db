use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Reads a JSON object from the bucket and decrypts it with `cipher` (bound
/// to `key` as AAD, see [`Cipher::open`]). Returns `(value, etag)`; if the
/// key doesn't exist yet returns the `Default` and `None` as etag, which is
/// exactly what [`put_json`] expects for a "create if not exists".
pub async fn get_json<T: DeserializeOwned + Default>(
    backend: &dyn Backend,
    key: &str,
    cipher: &Cipher,
) -> Result<(T, Option<String>)> {
    let (sealed, etag) = backend.get(key).await?;
    if sealed.is_empty() {
        return Ok((T::default(), etag));
    }
    let plain = cipher.open(key, &sealed)?;
    let value = serde_json::from_slice(&plain).with_context(|| format!("{key} is invalid"))?;
    Ok((value, etag))
}

/// Compare-and-swap write of a JSON object, encrypted before uploading.
/// `expected_etag = None` means "must not exist yet".
pub async fn put_json<T: Serialize>(
    backend: &dyn Backend,
    key: &str,
    value: &T,
    expected_etag: Option<&str>,
    cipher: &Cipher,
) -> Result<Cas> {
    let plain = serde_json::to_vec_pretty(value).with_context(|| format!("serializing {key}"))?;
    let sealed = cipher.seal(key, &plain);
    backend.put_cas(key, sealed, expected_etag).await
}

/// Same as [`get_json`] but WITHOUT encryption: only for
/// [`crate::bootstrap::get_or_create_cipher`], which needs to read the
/// derivation salt before it can build a `Cipher`. A salt isn't secret;
/// nothing else should use this.
pub(crate) async fn get_json_plain<T: DeserializeOwned + Default>(
    backend: &dyn Backend,
    key: &str,
) -> Result<(T, Option<String>)> {
    let (bytes, etag) = backend.get(key).await?;
    let value = if bytes.is_empty() {
        T::default()
    } else {
        serde_json::from_slice(&bytes).with_context(|| format!("{key} is invalid"))?
    };
    Ok((value, etag))
}

/// Unencrypted counterpart of [`put_json`], see [`get_json_plain`].
pub(crate) async fn put_json_plain<T: Serialize>(
    backend: &dyn Backend,
    key: &str,
    value: &T,
    expected_etag: Option<&str>,
) -> Result<Cas> {
    let body = serde_json::to_vec_pretty(value).with_context(|| format!("serializing {key}"))?;
    backend.put_cas(key, body, expected_etag).await
}

/// [`Backend::delete`], as a free function so most call sites read the same
/// as [`get_json`]/[`put_json`] instead of needing the trait itself in
/// scope.
pub async fn delete_object(backend: &dyn Backend, key: &str) {
    let _ = backend.delete(key).await;
}

/// [`Backend::list_prefix`], keys only — what most prefix-scans need.
/// Callers that need size too call `Backend::list_prefix` directly.
pub async fn list_all_keys(backend: &dyn Backend, prefix: &str) -> Result<Vec<String>> {
    Ok(backend
        .list_prefix(prefix)
        .await?
        .into_iter()
        .map(|(key, _size)| key)
        .collect())
}
