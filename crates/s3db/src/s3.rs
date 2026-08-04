//! [`Backend`] over real S3 (or any S3-compatible endpoint reachable via
//! `endpoint_url`/`path_style` — MinIO, etc). Also serves the `r2` driver
//! ([`S3Backend::new_r2`]): Cloudflare R2 speaks the same S3 API and
//! documents the same conditional-write (`If-Match`/`If-None-Match`)
//! guarantee real S3 gives, so it only needs its endpoint/region derived
//! from an account id instead of typed in by hand — same `aws-sdk-s3`
//! client either way.

use crate::backend::{Backend, Cas, DeleteOutcome};
use crate::config::{R2Params, S3Params};
use anyhow::{Context, Result};
#[cfg(feature = "streaming")]
use anyhow::bail;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region, retry::RetryConfig};
use aws_sdk_s3::primitives::ByteStream;
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use aws_smithy_runtime_api::client::result::SdkError;
#[cfg(feature = "streaming")]
use std::path::Path;
use std::time::Duration;
#[cfg(feature = "streaming")]
use tokio::io::AsyncWriteExt;

/// Default region: many S3-compatibles ignore it, but the SDK requires one.
const DEFAULT_REGION: &str = "us-east-1";
/// Enough to retry transient outages without hanging a push/clone.
const MAX_RETRY_ATTEMPTS: u32 = 4;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// `DeleteObjects` caps out at 1000 keys per request — chunking here used to
/// fall out for free from deleting one `ListObjectsV2` page at a time (a
/// page is never more than 1000 objects either, see `list_prefix`); now
/// that every caller goes through [`Backend::delete_many`] this makes that
/// same limit explicit instead of duplicated at each call site the way
/// `remote.rs` and `fsck.rs` used to.
const DELETE_BATCH_SIZE: usize = 1000;

#[derive(Debug)]
pub struct S3Backend {
    client: Client,
    bucket: String,
}

impl S3Backend {
    pub fn new(cfg: &S3Params) -> Self {
        let region = cfg.region.clone().unwrap_or_else(|| DEFAULT_REGION.to_string());
        Self::from_parts(
            &cfg.bucket,
            &cfg.access_key_id,
            &cfg.secret_access_key,
            &region,
            cfg.endpoint_url.as_deref(),
            cfg.path_style,
        )
    }

    /// R2's own S3-compatible endpoint is derived from the account id
    /// (`https://<account_id>.r2.cloudflarestorage.com`), and R2 ignores
    /// region but the SDK still requires one — Cloudflare's own docs use
    /// `"auto"`. No path-style knob: R2 only supports path-style addressing,
    /// so there's nothing for a config field to toggle.
    pub fn new_r2(cfg: &R2Params) -> Self {
        let endpoint = format!("https://{}.r2.cloudflarestorage.com", cfg.account_id);
        Self::from_parts(&cfg.bucket, &cfg.access_key_id, &cfg.secret_access_key, "auto", Some(&endpoint), true)
    }

    fn from_parts(
        bucket: &str,
        access_key_id: &str,
        secret_access_key: &str,
        region: &str,
        endpoint_url: Option<&str>,
        path_style: bool,
    ) -> Self {
        let creds = Credentials::new(access_key_id, secret_access_key, None, None, "gitquarry-config");

        let mut builder = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(creds)
            .region(Region::new(region.to_string()))
            .force_path_style(path_style)
            .retry_config(RetryConfig::standard().with_max_attempts(MAX_RETRY_ATTEMPTS))
            // Connect timeout only: uploading/downloading a big pack can
            // legitimately take a while, capping the whole request would
            // cut off valid transfers.
            .timeout_config(
                aws_sdk_s3::config::timeout::TimeoutConfig::builder()
                    .connect_timeout(CONNECT_TIMEOUT)
                    .build(),
            );

        if let Some(endpoint) = endpoint_url {
            builder = builder.endpoint_url(endpoint);
        }

        S3Backend { client: Client::from_conf(builder.build()), bucket: bucket.to_string() }
    }
}

#[async_trait::async_trait]
impl Backend for S3Backend {
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        let resp = self.client.get_object().bucket(&self.bucket).key(key).send().await;
        match resp {
            Ok(out) => {
                let etag = out.e_tag().map(str::to_string);
                let bytes = out
                    .body
                    .collect()
                    .await
                    .with_context(|| format!("reading body of {key}"))?
                    .into_bytes();
                Ok((bytes.to_vec(), etag))
            }
            Err(err) if is_not_found(&err) => Ok((Vec::new(), None)),
            Err(err) => Err(err).with_context(|| format!("couldn't read {key} from S3")),
        }
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body));
        let req = match expected_etag {
            Some(etag) => req.if_match(etag),
            None => req.if_none_match("*"),
        };
        match req.send().await {
            Ok(_) => Ok(Cas::Ok),
            Err(err) if is_precondition_failed(&err) => Ok(Cas::Conflict),
            Err(err) => Err(err).with_context(|| format!("couldn't write {key} to S3")),
        }
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        match self.client.delete_object().bucket(&self.bucket).key(key).send().await {
            Ok(_) => Ok(DeleteOutcome { attempted: 1, confirmed: 1 }),
            Err(err) if is_not_found(&err) => Ok(DeleteOutcome { attempted: 1, confirmed: 1 }),
            Err(err) => {
                eprintln!("gitquarry: warning: couldn't delete {key} from S3: {err}");
                Ok(DeleteOutcome { attempted: 1, confirmed: 0 })
            }
        }
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        let mut outcome = DeleteOutcome::default();
        for chunk in keys.chunks(DELETE_BATCH_SIZE) {
            outcome.attempted += chunk.len();
            let objects: Vec<aws_sdk_s3::types::ObjectIdentifier> = chunk
                .iter()
                .map(|k| {
                    aws_sdk_s3::types::ObjectIdentifier::builder()
                        .key(k)
                        .build()
                        .expect("ObjectIdentifier with a non-empty key is always valid")
                })
                .collect();
            let delete = aws_sdk_s3::types::Delete::builder()
                .set_objects(Some(objects))
                .build()
                .context("building the delete request")?;
            let out = self
                .client
                .delete_objects()
                .bucket(&self.bucket)
                .delete(delete)
                .send()
                .await
                .context("deleting objects from S3")?;
            outcome.confirmed += out.deleted().len();
            for err in out.errors() {
                eprintln!(
                    "gitquarry: warning: couldn't delete {} from S3: {}",
                    err.key().unwrap_or("?"),
                    err.message().unwrap_or("unknown error")
                );
            }
        }
        Ok(outcome)
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        let mut objects = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut req = self.client.list_objects_v2().bucket(&self.bucket).prefix(prefix);
            if let Some(tok) = &continuation {
                req = req.continuation_token(tok);
            }
            let out = req
                .send()
                .await
                .with_context(|| format!("listing {prefix} in {}", self.bucket))?;
            objects.extend(out.contents().iter().filter_map(|o| {
                let key = o.key()?.to_string();
                let size = o.size().unwrap_or(0).max(0) as u64;
                Some((key, size))
            }));
            if !out.is_truncated().unwrap_or(false) {
                break;
            }
            continuation = out.next_continuation_token().map(str::to_string);
            if continuation.is_none() {
                break; // truncated response with no token: cut instead of looping
            }
        }
        Ok(objects)
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        let expected_len = tokio::fs::metadata(source)
            .await
            .with_context(|| format!("checking size of {}", source.display()))?
            .len();
        // Streams the file straight off disk instead of reading it into a
        // `Vec` first — bounded memory regardless of `source`'s size.
        let body = ByteStream::from_path(source)
            .await
            .with_context(|| format!("opening {} for upload", source.display()))?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .send()
            .await
            .with_context(|| format!("uploading {key} to S3"))?;
        // `put_object` returning Ok only means the endpoint accepted and
        // acknowledged the request — it doesn't guarantee the object it now
        // serves back is actually the same length that was sent (seen in
        // practice against this project's S3-compatible endpoint: a PUT
        // that returns success followed by a GET whose declared
        // Content-Length, and actual bytes, are both short). A HEAD here
        // catches that before the caller treats the push as done, instead
        // of a future read silently decrypting a truncated object.
        let head = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .with_context(|| format!("verifying {key} just uploaded to S3"))?;
        let actual_len = head.content_length().unwrap_or(-1);
        if actual_len != expected_len as i64 {
            bail!(
                "incomplete upload of {key}: the S3 provider acknowledged the upload but the \
                 object ended up at {actual_len} bytes, {expected_len} were uploaded \
                 (check the S3 endpoint/proxy, this isn't a local network issue)"
            );
        }
        Ok(())
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        let resp = self.client.get_object().bucket(&self.bucket).key(key).send().await;
        let mut out = match resp {
            Ok(out) => out,
            Err(err) if is_not_found(&err) => bail!("{key} doesn't exist in S3"),
            Err(err) => return Err(err).with_context(|| format!("couldn't read {key} from S3")),
        };
        // S3's own declared size for this object — checked against what
        // actually lands on disk below. Without this, a body stream that
        // ends early (a dropped connection, a proxy in front of the
        // endpoint cutting the response short) just makes `.next()` return
        // `None` like a normal end-of-stream: no error anywhere in this
        // function, a silently truncated file written under `dest`, and
        // the corruption only surfaces later, confusingly, wherever that
        // file next gets read (e.g. `Cipher::open_stream` failing on a
        // pack's ciphertext with "early eof").
        let expected_len = out.content_length();
        let mut file = tokio::fs::File::create(dest)
            .await
            .with_context(|| format!("creating {}", dest.display()))?;
        // Writes each chunk as it arrives instead of `.collect()`-ing the
        // whole body first — bounded memory regardless of `key`'s size.
        let mut actual_len: i64 = 0;
        while let Some(chunk) = out.body.next().await {
            let chunk = chunk.with_context(|| format!("reading body of {key}"))?;
            actual_len += chunk.len() as i64;
            file.write_all(&chunk)
                .await
                .with_context(|| format!("writing {}", dest.display()))?;
        }
        if let Some(expected_len) = expected_len
            && actual_len != expected_len
        {
            bail!(
                "incomplete download of {key}: {actual_len} bytes arrived, \
                 S3 declared {expected_len} (connection cut off midway)"
            );
        }
        // `tokio::fs::File::poll_write` returns once the write is spawned
        // on the blocking pool, not once it lands — without this, the last
        // `write_all` above can still be in flight when this returns,
        // racing whatever reads `dest` next (e.g. `Cipher::open_stream`).
        file.flush().await?;
        Ok(())
    }
}

pub fn is_not_found<E: std::error::Error + 'static>(err: &SdkError<E, HttpResponse>) -> bool {
    raw_status(err) == Some(404)
}

/// CAS precondition failure. AWS returns 412; several S3-compatible
/// implementations return 409 for `If-None-Match: *`, so we accept both or
/// the CAS would look like a hard error instead of a retry.
pub fn is_precondition_failed<E: std::error::Error + 'static>(
    err: &SdkError<E, HttpResponse>,
) -> bool {
    matches!(raw_status(err), Some(412 | 409))
}

fn raw_status<E>(err: &SdkError<E, HttpResponse>) -> Option<u16> {
    err.raw_response().map(|r| r.status().as_u16())
}
