//! [`Backend`] over Azure Blob Storage. Unlike `s3`/`r2` (both real S3),
//! this speaks a genuinely different wire protocol, hence its own crate
//! (`azure_storage_blobs`) rather than another config variant over
//! `S3Backend`. Azure's own conditional-write headers (`If-Match`/
//! `If-None-Match`) map directly onto [`Backend::put_cas`], same as S3 —
//! this driver doesn't need the local driver's flock emulation.

use crate::backend::{Backend, Cas, DeleteOutcome};
use crate::config::AzureParams;
use anyhow::{Context, Result, bail};
use azure_core::StatusCode;
use azure_core::error::ErrorKind;
use azure_core::prelude::IfMatchCondition;
use azure_storage::StorageCredentials;
use azure_storage_blobs::prelude::{BlobBlockType, BlobClient, BlockId, BlockList, ClientBuilder, ContainerClient};
use futures::StreamExt;
use futures::stream;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How many keys [`AzureBackend::delete_many`] deletes at once — this API
/// has no S3-style batch delete, so bounded concurrency is what stands in
/// for it instead of one request at a time.
const DELETE_CONCURRENCY: usize = 8;
/// Plaintext-agnostic upload chunk size for [`AzureBackend::put_stream`]'s
/// block-blob upload — bounds peak memory for uploading `source` regardless
/// of its size. Doesn't need to match `crypto`'s own chunk size (`source`
/// here is already-sealed ciphertext, this is just how big a piece this
/// driver hands to one `Put Block` call at a time).
const UPLOAD_BLOCK_LEN: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct AzureBackend {
    container: ContainerClient,
}

impl AzureBackend {
    pub fn new(cfg: &AzureParams) -> Self {
        let credentials = StorageCredentials::access_key(cfg.account_name.clone(), cfg.account_key.clone());
        let container = ClientBuilder::new(cfg.account_name.clone(), credentials).container_client(&cfg.bucket);
        AzureBackend { container }
    }

    fn blob(&self, key: &str) -> BlobClient {
        self.container.blob_client(key)
    }
}

fn is_not_found(err: &azure_core::Error) -> bool {
    matches!(err.kind(), ErrorKind::HttpResponse { status, .. } if *status == StatusCode::NotFound)
}

fn is_precondition_failed(err: &azure_core::Error) -> bool {
    matches!(err.kind(), ErrorKind::HttpResponse { status, .. } if *status == StatusCode::PreconditionFailed)
}

#[async_trait::async_trait]
impl Backend for AzureBackend {
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        let mut stream = self.blob(key).get().into_stream();
        let mut bytes = Vec::new();
        let mut etag = None;
        loop {
            match stream.next().await {
                Some(Ok(page)) => {
                    etag = Some(page.blob.properties.etag.to_string());
                    let chunk = page
                        .data
                        .collect()
                        .await
                        .with_context(|| format!("reading body of {key}"))?;
                    bytes.extend_from_slice(&chunk);
                }
                Some(Err(e)) if is_not_found(&e) => return Ok((Vec::new(), None)),
                Some(Err(e)) => return Err(e).with_context(|| format!("couldn't read {key} from Azure Blob Storage")),
                None => break,
            }
        }
        Ok((bytes, etag))
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let condition = match expected_etag {
            Some(etag) => IfMatchCondition::Match(etag.to_string()),
            None => IfMatchCondition::NotMatch("*".to_string()),
        };
        match self.blob(key).put_block_blob(body).if_match(condition).await {
            Ok(_) => Ok(Cas::Ok),
            Err(e) if is_precondition_failed(&e) => Ok(Cas::Conflict),
            Err(e) => Err(e).with_context(|| format!("couldn't write {key} to Azure Blob Storage")),
        }
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        match self.blob(key).delete().await {
            Ok(_) => Ok(DeleteOutcome { attempted: 1, confirmed: 1 }),
            Err(e) if is_not_found(&e) => Ok(DeleteOutcome { attempted: 1, confirmed: 1 }),
            Err(e) => {
                eprintln!("warning: couldn't delete {key} from Azure Blob Storage: {e}");
                Ok(DeleteOutcome { attempted: 1, confirmed: 0 })
            }
        }
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        // No S3-style batch-delete in this crate (Azure's own "Blob Batch"
        // REST call isn't exposed here) — bounded concurrency instead of
        // one request at a time. A single key's failure only counts against
        // `confirmed`, it never aborts the keys still in flight.
        let confirmed = AtomicUsize::new(0);
        let confirmed_ref = &confirmed;
        stream::iter(keys)
            .for_each_concurrent(Some(DELETE_CONCURRENCY), |key| async move {
                match self.blob(key).delete().await {
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
        Ok(DeleteOutcome { attempted: keys.len(), confirmed: confirmed.load(Ordering::Relaxed) })
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        let mut out = Vec::new();
        let mut stream = self.container.list_blobs().prefix(prefix.to_string()).into_stream();
        while let Some(page) = stream.next().await {
            let page = page.with_context(|| format!("listing {prefix} in Azure Blob Storage"))?;
            out.extend(page.blobs.blobs().map(|b| (b.name.clone(), b.properties.content_length)));
        }
        Ok(out)
    }

    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        let total_len = tokio::fs::metadata(source)
            .await
            .with_context(|| format!("checking size of {}", source.display()))?
            .len();
        let blob = self.blob(key);

        // No blocks to commit for a genuinely empty object — Azure still
        // needs the blob to exist, `put_block_blob` with an empty body is
        // the same call the small-object `put` already makes.
        if total_len == 0 {
            blob.put_block_blob(Vec::new())
                .await
                .with_context(|| format!("uploading {key} to Azure Blob Storage"))?;
            return Ok(());
        }

        let mut file = tokio::fs::File::open(source)
            .await
            .with_context(|| format!("opening {}", source.display()))?;
        let num_chunks = total_len.div_ceil(UPLOAD_BLOCK_LEN);
        let mut blocks = Vec::with_capacity(num_chunks as usize);
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
            let block_id = BlockId::new(format!("{idx:016x}").into_bytes());
            blob.put_block(block_id.clone(), buf)
                .await
                .with_context(|| format!("uploading block {idx} of {key} to Azure Blob Storage"))?;
            blocks.push(BlobBlockType::new_uncommitted(block_id));
        }
        blob.put_block_list(BlockList { blocks })
            .await
            .with_context(|| format!("committing blocks of {key} to Azure Blob Storage"))?;
        Ok(())
    }

    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        let mut stream = self.blob(key).get().into_stream();
        let mut file = tokio::fs::File::create(dest)
            .await
            .with_context(|| format!("creating {}", dest.display()))?;
        loop {
            match stream.next().await {
                Some(Ok(page)) => {
                    // `content_length` here is the Content-Length header of
                    // THIS ranged response (Azure paginates get_stream in
                    // chunks internally), not the whole blob — checked
                    // against what `.collect()` actually produced so a body
                    // that ends early inside one page fails loud instead of
                    // silently writing a short chunk to `dest`.
                    let expected_len = page.blob.properties.content_length;
                    let chunk = page
                        .data
                        .collect()
                        .await
                        .with_context(|| format!("reading body of {key}"))?;
                    if chunk.len() as u64 != expected_len {
                        bail!(
                            "incomplete download of {key}: a chunk brought {} bytes, \
                             Azure declared {expected_len} (connection cut off midway)",
                            chunk.len()
                        );
                    }
                    file.write_all(&chunk)
                        .await
                        .with_context(|| format!("writing {}", dest.display()))?;
                }
                Some(Err(e)) if is_not_found(&e) => bail!("{key} doesn't exist in Azure Blob Storage"),
                Some(Err(e)) => return Err(e).with_context(|| format!("couldn't read {key} from Azure Blob Storage")),
                None => break,
            }
        }
        // See the S3 driver's matching `flush()`: `tokio::fs::File` spawns
        // the last write without awaiting it, so without this it can still
        // be in flight when this returns.
        file.flush().await?;
        Ok(())
    }
}
