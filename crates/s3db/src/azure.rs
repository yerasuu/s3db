//! [`Backend`] over Azure Blob Storage. Unlike `s3`/`r2` (both real S3),
//! this speaks a genuinely different wire protocol, hence its own crate
//! (`azure_storage_blob`) rather than another config variant over
//! `S3Backend`. Azure's own conditional-write headers (`If-Match`/
//! `If-None-Match`) map directly onto [`Backend::put_cas`], same as S3 —
//! this driver doesn't need the local driver's flock emulation.
//!
//! Auth is Entra ID (`azure_identity::ClientSecretCredential`), not a
//! storage account key: the `azure_storage_blob`/`azure_core` 1.x line this
//! driver is built on dropped shared-key auth entirely in favor of
//! `TokenCredential`. Building the credential needs a fallible URL parse
//! and tenant/client validation, unlike every other driver's synchronous,
//! infallible `new()` — so, like [`crate::gcs`]'s client pair, construction
//! is deferred to first real use behind a `OnceCell`.

use crate::backend::{Backend, Cas, DeleteOutcome};
use crate::config::AzureParams;
#[cfg(feature = "streaming")]
use anyhow::bail;
use anyhow::{Context, Result};
use azure_core::Error as AzureError;
use azure_core::credentials::Secret;
use azure_core::http::{Etag, RequestContent, StatusCode, Url};
use azure_identity::ClientSecretCredential;
#[cfg(feature = "streaming")]
use azure_storage_blob::models::BlockLookupList;
use azure_storage_blob::models::{
    BlobClientDownloadOptions, BlobClientUploadOptions, BlobContainerClientListBlobsOptions,
};
use azure_storage_blob::{BlobContainerClient, BlobServiceClient};
use futures::TryStreamExt;
use futures::stream::{self, StreamExt};
#[cfg(feature = "streaming")]
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "streaming")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::OnceCell;

/// How many keys [`AzureBackend::delete_many`] deletes at once — this API
/// has no S3-style batch delete, so bounded concurrency is what stands in
/// for it instead of one request at a time.
const DELETE_CONCURRENCY: usize = 8;
/// Plaintext-agnostic upload chunk size for [`AzureBackend::put_stream`]'s
/// block-blob upload — bounds peak memory for uploading `source` regardless
/// of its size. Doesn't need to match `crypto`'s own chunk size (`source`
/// here is already-sealed ciphertext, this is just how big a piece this
/// driver hands to one `Put Block` call at a time).
#[cfg(feature = "streaming")]
const UPLOAD_BLOCK_LEN: u64 = 4 * 1024 * 1024;

pub struct AzureBackend {
    account_name: String,
    bucket: String,
    tenant_id: String,
    client_id: String,
    client_secret: String,
    container: OnceCell<BlobContainerClient>,
}

impl std::fmt::Debug for AzureBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureBackend")
            .field("account_name", &self.account_name)
            .field("bucket", &self.bucket)
            .finish_non_exhaustive()
    }
}

impl AzureBackend {
    pub fn new(cfg: &AzureParams) -> Self {
        AzureBackend {
            account_name: cfg.account_name.clone(),
            bucket: cfg.bucket.clone(),
            tenant_id: cfg.tenant_id.clone(),
            client_id: cfg.client_id.clone(),
            client_secret: cfg.client_secret.clone(),
            container: OnceCell::new(),
        }
    }

    async fn container(&self) -> Result<&BlobContainerClient> {
        self.container
            .get_or_try_init(|| async {
                let credential = ClientSecretCredential::new(
                    &self.tenant_id,
                    self.client_id.clone(),
                    Secret::from(self.client_secret.clone()),
                    None,
                )
                .context("building Entra ID credential")?;
                let service_url = Url::parse(&format!("https://{}.blob.core.windows.net/", self.account_name))
                    .with_context(|| format!("{}: invalid storage account name", self.account_name))?;
                let service = BlobServiceClient::new(service_url, Some(credential), None)
                    .context("building Azure Blob Storage client")?;
                Ok(service.blob_container_client(&self.bucket))
            })
            .await
    }

    async fn blob(&self, key: &str) -> Result<azure_storage_blob::BlobClient> {
        Ok(self.container().await?.blob_client(key))
    }
}

fn is_not_found(err: &AzureError) -> bool {
    err.http_status() == Some(StatusCode::NotFound)
}

fn is_precondition_failed(err: &AzureError) -> bool {
    err.http_status() == Some(StatusCode::PreconditionFailed)
}

#[async_trait::async_trait]
impl Backend for AzureBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        match self.blob(key).await?.download(None).await {
            Ok(result) => {
                let etag = result.properties.etag.as_ref().map(|e| e.to_string());
                let bytes = result
                    .body
                    .collect()
                    .await
                    .with_context(|| format!("reading body of {key}"))?;
                Ok((bytes.to_vec(), etag))
            }
            Err(e) if is_not_found(&e) => Ok((Vec::new(), None)),
            Err(e) => Err(e).with_context(|| format!("couldn't read {key} from Azure Blob Storage")),
        }
    }

    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        let options = BlobClientDownloadOptions {
            range: Some((offset..offset + len).into()),
            ..Default::default()
        };
        let result = self
            .blob(key)
            .await?
            .download(Some(options))
            .await
            .with_context(|| format!("couldn't read range of {key} from Azure Blob Storage"))?;
        let bytes = result
            .body
            .collect()
            .await
            .with_context(|| format!("reading ranged body of {key}"))?;
        Ok(bytes.to_vec())
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let options = match expected_etag {
            Some(etag) => BlobClientUploadOptions {
                if_match: Some(Etag::from(etag)),
                ..Default::default()
            },
            None => BlobClientUploadOptions {
                if_none_match: Some(Etag::from("*")),
                ..Default::default()
            },
        };
        match self
            .blob(key)
            .await?
            .upload(RequestContent::from(body), Some(options))
            .await
        {
            Ok(_) => Ok(Cas::Ok),
            Err(e) if is_precondition_failed(&e) => Ok(Cas::Conflict),
            Err(e) => Err(e).with_context(|| format!("couldn't write {key} to Azure Blob Storage")),
        }
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        match self.blob(key).await?.delete(None).await {
            Ok(_) => Ok(DeleteOutcome {
                attempted: 1,
                confirmed: 1,
            }),
            Err(e) if is_not_found(&e) => Ok(DeleteOutcome {
                attempted: 1,
                confirmed: 1,
            }),
            Err(e) => {
                eprintln!("warning: couldn't delete {key} from Azure Blob Storage: {e}");
                Ok(DeleteOutcome {
                    attempted: 1,
                    confirmed: 0,
                })
            }
        }
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        // No S3-style batch-delete in this crate (Azure's own "Blob Batch"
        // REST call isn't exposed here) — bounded concurrency instead of
        // one request at a time. A single key's failure only counts against
        // `confirmed`, it never aborts the keys still in flight.
        let container = match self.container().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "warning: couldn't delete {} keys from Azure Blob Storage: {e:#}",
                    keys.len()
                );
                return Ok(DeleteOutcome {
                    attempted: keys.len(),
                    confirmed: 0,
                });
            }
        };
        let confirmed = AtomicUsize::new(0);
        let confirmed_ref = &confirmed;
        stream::iter(keys)
            .for_each_concurrent(Some(DELETE_CONCURRENCY), |key| async move {
                match container.blob_client(key).delete(None).await {
                    Ok(_) => {
                        confirmed_ref.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) if is_not_found(&e) => {
                        confirmed_ref.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => eprintln!("warning: couldn't delete {key} from Azure Blob Storage: {e}"),
                }
            })
            .await;
        Ok(DeleteOutcome {
            attempted: keys.len(),
            confirmed: confirmed.load(Ordering::Relaxed),
        })
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        let container = self.container().await?;
        let options = BlobContainerClientListBlobsOptions {
            prefix: Some(prefix.to_string()),
            ..Default::default()
        };
        let mut pages = container.list_blobs(Some(options))?.into_pages();
        let mut out = Vec::new();
        while let Some(page) = pages
            .try_next()
            .await
            .with_context(|| format!("listing {prefix} in Azure Blob Storage"))?
        {
            let page = page
                .into_model()
                .with_context(|| format!("listing {prefix} in Azure Blob Storage"))?;
            for item in page.blob_items {
                let Some(name) = item.name else { continue };
                let content_length = item.properties.as_ref().and_then(|p| p.content_length).unwrap_or(0);
                out.push((name, content_length));
            }
        }
        Ok(out)
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        let total_len = tokio::fs::metadata(source)
            .await
            .with_context(|| format!("checking size of {}", source.display()))?
            .len();
        let block_blob = self.blob(key).await?.block_blob_client();

        // No blocks to commit for a genuinely empty object — Azure still
        // needs the blob to exist, `upload` with an empty body is the same
        // call the small-object `put_cas` already makes.
        if total_len == 0 {
            block_blob
                .upload(RequestContent::from(Vec::new()), None)
                .await
                .with_context(|| format!("uploading {key} to Azure Blob Storage"))?;
            return Ok(());
        }

        let mut file = tokio::fs::File::open(source)
            .await
            .with_context(|| format!("opening {}", source.display()))?;
        let num_chunks = total_len.div_ceil(UPLOAD_BLOCK_LEN);
        let mut block_ids = Vec::with_capacity(num_chunks as usize);
        let mut remaining = total_len;
        for idx in 0..num_chunks {
            let this_len = remaining.min(UPLOAD_BLOCK_LEN) as usize;
            let mut buf = vec![0u8; this_len];
            file.read_exact(&mut buf)
                .await
                .with_context(|| format!("reading block {idx} of {}", source.display()))?;
            remaining -= this_len as u64;

            // Fixed-width block id (16 hex digits, well under the 64-byte
            // cap): every block id in one blob's list must be the same
            // length.
            let block_id = format!("{idx:016x}").into_bytes();
            block_blob
                .stage_block(&block_id, this_len as u64, RequestContent::from(buf), None)
                .await
                .with_context(|| format!("uploading block {idx} of {key} to Azure Blob Storage"))?;
            block_ids.push(block_id);
        }
        let block_list = BlockLookupList {
            committed: None,
            latest: Some(block_ids),
            uncommitted: None,
        };
        block_blob
            .commit_block_list(block_list.try_into().context("encoding block list")?, None)
            .await
            .with_context(|| format!("committing blocks of {key} to Azure Blob Storage"))?;
        Ok(())
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        let result = match self.blob(key).await?.download(None).await {
            Ok(result) => result,
            Err(e) if is_not_found(&e) => bail!("{key} doesn't exist in Azure Blob Storage"),
            Err(e) => return Err(e).with_context(|| format!("couldn't read {key} from Azure Blob Storage")),
        };
        // `download()` streams the whole blob (not just one page like the
        // old prelude API), so a single `collect()` already gets everything
        // — checked against the declared length so a body that ends early
        // fails loud instead of silently writing a short file to `dest`.
        let expected_len = result.properties.content_length;
        let bytes = result
            .body
            .collect()
            .await
            .with_context(|| format!("reading body of {key}"))?;
        if let Some(expected_len) = expected_len
            && bytes.len() as u64 != expected_len
        {
            bail!(
                "incomplete download of {key}: {} bytes arrived, Azure declared {expected_len} \
                 (connection cut off midway)",
                bytes.len()
            );
        }
        let mut file = tokio::fs::File::create(dest)
            .await
            .with_context(|| format!("creating {}", dest.display()))?;
        file.write_all(&bytes)
            .await
            .with_context(|| format!("writing {}", dest.display()))?;
        // See the S3 driver's matching `flush()`: `tokio::fs::File` spawns
        // the last write without awaiting it, so without this it can still
        // be in flight when this returns.
        file.flush().await?;
        Ok(())
    }
}
