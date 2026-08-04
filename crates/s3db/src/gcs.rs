//! [`Backend`] over Google Cloud Storage, via the native JSON/gRPC API
//! (`google-cloud-storage`) rather than GCS's S3-interop XML endpoint:
//! GCS's own generation-precondition semantics (`ifGenerationMatch`) give a
//! documented CAS guarantee the S3-compatibility endpoint doesn't promise
//! with the same confidence, and `refs.json`'s CAS is what stops a
//! concurrent push from silently clobbering another one.
//!
//! Two clients, matching how the crate itself splits the API: [`Storage`]
//! (data plane — read/write object bytes) and [`StorageControl`] (control
//! plane — delete/list, no read/write of object bodies). Building either is
//! async and can fail (a bad service-account key file), unlike every other
//! driver's synchronous, infallible `new()` — so construction is deferred
//! to first real use behind a `OnceCell`. That's not a special case this
//! driver invented: no driver actually verifies connectivity at
//! construction, this just makes the deferral explicit for the one driver
//! where building the client handle itself, not only the first request,
//! needs `.await`.

use crate::backend::{Backend, Cas, DeleteOutcome};
use crate::config::GcsParams;
use anyhow::{Context, Result};
#[cfg(feature = "streaming")]
use anyhow::bail;
use futures::stream::{self, StreamExt};
use google_cloud_auth::credentials::service_account;
use google_cloud_gax::paginator::ItemPaginator;
use google_cloud_storage::client::{Storage, StorageControl};
#[cfg(feature = "streaming")]
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "streaming")]
use tokio::io::AsyncWriteExt;
use tokio::sync::OnceCell;

const RESOURCE_PREFIX: &str = "projects/_/buckets/";
/// How many keys [`GcsBackend::delete_many`] deletes at once — this API has
/// no batch delete, so bounded concurrency is what stands in for it instead
/// of one request at a time.
const DELETE_CONCURRENCY: usize = 8;

#[derive(Debug)]
pub struct GcsBackend {
    bucket: String,
    service_account_json_path: String,
    clients: OnceCell<(Storage, StorageControl)>,
}

impl GcsBackend {
    pub fn new(cfg: &GcsParams) -> Self {
        GcsBackend {
            bucket: cfg.bucket.clone(),
            service_account_json_path: cfg.service_account_json_path.clone(),
            clients: OnceCell::new(),
        }
    }

    fn bucket_resource(&self) -> String {
        format!("{RESOURCE_PREFIX}{}", self.bucket)
    }

    async fn client_pair(&self) -> Result<&(Storage, StorageControl)> {
        self.clients
            .get_or_try_init(|| async {
                let key_json = tokio::fs::read_to_string(&self.service_account_json_path)
                    .await
                    .with_context(|| format!("reading {}", self.service_account_json_path))?;
                let key: serde_json::Value = serde_json::from_str(&key_json)
                    .with_context(|| format!("{}: invalid JSON", self.service_account_json_path))?;
                let credentials = service_account::Builder::new(key)
                    .build()
                    .context("building Google Cloud credentials")?;
                let storage = Storage::builder()
                    .with_credentials(credentials.clone())
                    .build()
                    .await
                    .context("connecting to Google Cloud Storage")?;
                let control = StorageControl::builder()
                    .with_credentials(credentials)
                    .build()
                    .await
                    .context("connecting to the Google Cloud Storage control plane")?;
                Ok((storage, control))
            })
            .await
    }
}

fn status_code(err: &google_cloud_gax::error::Error) -> Option<u16> {
    err.http_status_code()
}

#[async_trait::async_trait]
impl Backend for GcsBackend {
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        let (storage, _) = self.client_pair().await?;
        let mut resp = match storage.read_object(self.bucket_resource(), key).send().await {
            Ok(r) => r,
            Err(e) if status_code(&e) == Some(404) => return Ok((Vec::new(), None)),
            Err(e) => return Err(e).with_context(|| format!("couldn't read {key} from Google Cloud Storage")),
        };
        let etag = resp.object().generation.to_string();
        let mut bytes = Vec::new();
        while let Some(chunk) = resp
            .next()
            .await
            .transpose()
            .with_context(|| format!("reading body of {key}"))?
        {
            bytes.extend_from_slice(&chunk);
        }
        Ok((bytes, Some(etag)))
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let (storage, _) = self.client_pair().await?;
        let builder = storage.write_object(self.bucket_resource(), key, bytes::Bytes::from(body));
        let builder = match expected_etag {
            // GCS's own "create only" convention: generation 0 means the
            // object doesn't exist yet.
            None => builder.set_if_generation_match(0),
            Some(etag) => {
                let generation: i64 = etag
                    .parse()
                    .with_context(|| format!("{key}: invalid generation ({etag})"))?;
                builder.set_if_generation_match(generation)
            }
        };
        match builder.send_unbuffered().await {
            Ok(_) => Ok(Cas::Ok),
            Err(e) if status_code(&e) == Some(412) => Ok(Cas::Conflict),
            Err(e) => Err(e).with_context(|| format!("couldn't write {key} to Google Cloud Storage")),
        }
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        let clients = match self.client_pair().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("gitquarry: warning: couldn't delete {key} from Google Cloud Storage: {e:#}");
                return Ok(DeleteOutcome { attempted: 1, confirmed: 0 });
            }
        };
        let (_, control) = clients;
        match control.delete_object().set_bucket(self.bucket_resource()).set_object(key).send().await {
            Ok(_) => Ok(DeleteOutcome { attempted: 1, confirmed: 1 }),
            Err(e) if status_code(&e) == Some(404) => Ok(DeleteOutcome { attempted: 1, confirmed: 1 }),
            Err(e) => {
                eprintln!("gitquarry: warning: couldn't delete {key} from Google Cloud Storage: {e}");
                Ok(DeleteOutcome { attempted: 1, confirmed: 0 })
            }
        }
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        // No batch-delete in this API — bounded concurrency instead of one
        // request at a time. A single key's failure only counts against
        // `confirmed`, it never aborts the keys still in flight.
        let (_, control) = self.client_pair().await?;
        let confirmed = AtomicUsize::new(0);
        let confirmed_ref = &confirmed;
        stream::iter(keys)
            .for_each_concurrent(Some(DELETE_CONCURRENCY), |key| async move {
                match control.delete_object().set_bucket(self.bucket_resource()).set_object(key.as_str()).send().await {
                    Ok(_) => {
                        confirmed_ref.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) if status_code(&e) == Some(404) => {
                        confirmed_ref.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => eprintln!("gitquarry: warning: couldn't delete {key} from Google Cloud Storage: {e}"),
                }
            })
            .await;
        Ok(DeleteOutcome { attempted: keys.len(), confirmed: confirmed.load(Ordering::Relaxed) })
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        let (_, control) = self.client_pair().await?;
        let mut pager = control
            .list_objects()
            .set_parent(self.bucket_resource())
            .set_prefix(prefix)
            .by_item();
        let mut out = Vec::new();
        // `ItemPaginator::into_stream` needs the crate's "unstable-stream"
        // feature; a plain `next()` loop needs nothing extra and paginates
        // the same way underneath.
        while let Some(item) = pager.next().await {
            let obj = item.with_context(|| format!("listing {prefix} in Google Cloud Storage"))?;
            out.push((obj.name, obj.size.max(0) as u64));
        }
        Ok(out)
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        let (storage, _) = self.client_pair().await?;
        // The crate accepts a `tokio::fs::File` directly as the upload
        // source (`Payload<FileSource>`) — streamed from disk, never
        // buffered into one `Vec` regardless of `source`'s size.
        let file = tokio::fs::File::open(source)
            .await
            .with_context(|| format!("opening {}", source.display()))?;
        storage
            .write_object(self.bucket_resource(), key, file)
            .send_unbuffered()
            .await
            .with_context(|| format!("uploading {key} to Google Cloud Storage"))?;
        Ok(())
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        let (storage, _) = self.client_pair().await?;
        let mut resp = match storage.read_object(self.bucket_resource(), key).send().await {
            Ok(r) => r,
            Err(e) if status_code(&e) == Some(404) => bail!("{key} doesn't exist in Google Cloud Storage"),
            Err(e) => return Err(e).with_context(|| format!("couldn't read {key} from Google Cloud Storage")),
        };
        // GCS's own declared size, checked against what actually lands on
        // disk below — same reasoning as the S3 driver's `get_stream`: a
        // body stream that ends early just makes `.next()` return `None`
        // like a normal end-of-stream, with no error anywhere in this
        // function otherwise.
        let expected_len = resp.object().size;
        let mut file = tokio::fs::File::create(dest)
            .await
            .with_context(|| format!("creating {}", dest.display()))?;
        let mut actual_len: i64 = 0;
        while let Some(chunk) = resp
            .next()
            .await
            .transpose()
            .with_context(|| format!("reading body of {key}"))?
        {
            actual_len += chunk.len() as i64;
            file.write_all(&chunk)
                .await
                .with_context(|| format!("writing {}", dest.display()))?;
        }
        if actual_len != expected_len {
            bail!(
                "incomplete download of {key}: {actual_len} bytes arrived, \
                 Google Cloud Storage declared {expected_len} (connection cut off midway)"
            );
        }
        // See the S3 driver's matching `flush()`: `tokio::fs::File` spawns
        // the last write without awaiting it, so without this it can still
        // be in flight when this returns.
        file.flush().await?;
        Ok(())
    }
}
