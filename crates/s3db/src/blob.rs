//! Values too big for one object, split across several.
//!
//! [`crate::payload::put_json`] caps a single object at
//! [`MAX_OBJECT_BYTES`] on purpose: this crate's profile is small, uniform,
//! typed entities, and `Cipher::seal` buffers whatever it's handed. A caller
//! with something genuinely bigger — a scraped HTML page, a rendered
//! document, an attachment — had exactly two options, and neither was one:
//! raise a limit that exists for good reasons, or drop to
//! `Backend::put_stream` (the `streaming` feature), which is raw bytes at a
//! raw key with no encryption, no CAS, no history, and no tombstone.
//!
//! [`Blob`] is the middle: a value that spans several objects but is still
//! addressed, encrypted, and compare-and-swapped as *one* thing. It needs no
//! feature flag and no driver support beyond [`Backend`]'s required surface,
//! so it works identically on S3, R2, Azure, GCS, and a local directory.
//!
//! ```text
//! <prefix>/<name>.json                      manifest (sealed, CAS'd, the blob's identity)
//! <prefix>/.parts/<name>/<generation>/0000  sealed part
//! <prefix>/.parts/<name>/<generation>/0001  ...
//! ```
//!
//! **Why parts are never overwritten.** Each write puts its parts under a
//! fresh random `generation` and only then CAS-writes the manifest that
//! names it. Overwriting parts in place would let a reader that fetched the
//! manifest a moment earlier assemble part 0 of the new value with part 1 of
//! the old one — a torn read that no amount of CAS on the manifest prevents,
//! because the tearing happens below it. With generations the old parts stay
//! whole and readable until they're swept, so the worst case degrades from
//! "silently wrong bytes" to "a read that fails because the generation it
//! was promised is gone", which is [`Backend::delete`]'s familiar
//! best-effort tolerance rather than a correctness hole.
//!
//! **Order of operations.** Parts first, manifest last: a crash mid-write
//! leaves orphan parts that nothing references and no reader can see, which
//! is the failure mode worth having. The reverse order would publish a
//! manifest pointing at parts that don't exist yet.
//!
//! **In memory, not streamed.** [`Blob::get`] assembles the whole value in
//! memory and [`Blob::put`] takes it that way, bounded by
//! [`Blob::max_total_bytes`]. A value too big to hold at all is what
//! `put_stream`/`get_stream` are for; this is for the wide middle ground
//! between one object and a file.

use crate::backend::{Backend, Cas};
use crate::cipher::{Cipher, CompressionStrategy};
use crate::naming::validate_path;
use crate::payload::{MAX_OBJECT_BYTES, SweepReport, delete_prefix, get_json, list_all_keys, put_json};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Default ceiling on one blob's assembled size. A guard against an
/// application bug (a runaway generated document, an unbounded scrape), not
/// a statement about what object storage can hold: raise it deliberately
/// with [`Blob::with_max_total_bytes`] for a caller that really does handle
/// values this large, and reach for `put_stream` rather than raising it past
/// what the process can hold at once.
pub const DEFAULT_MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;

/// Bytes of plaintext per part. Deliberately equal to
/// [`MAX_OBJECT_BYTES`]: parts are what the rest of this crate calls
/// objects, and sizing them the same keeps one memory profile across the
/// whole crate instead of two.
pub const DEFAULT_PART_BYTES: usize = MAX_OBJECT_BYTES;

/// How many parts one [`Blob::get`] fetches at a time. Same reasoning as
/// [`crate::MemoryBudget`], expressed as a count because a part's size is
/// already fixed by the manifest.
const PART_FETCH_CONCURRENCY: usize = 8;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

/// A blob's identity: what its parts are and where they live. Sealed and
/// CAS-written like any other entry, so a truncated or re-pointed blob is
/// not something a storage provider can forge, and `parts`/`total_len` are
/// an authenticated statement about what a complete read must find.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobManifest {
    /// Assembled plaintext length. [`Blob::get`] checks what it read
    /// against this rather than trusting that every part showed up.
    pub total_len: u64,
    /// Plaintext bytes per part; the last part may be shorter.
    pub part_bytes: u32,
    pub parts: u32,
    /// Which generation of parts this manifest names — see the module doc
    /// for why a write never reuses one.
    pub generation: String,
    pub written_at_ms: u64,
}

/// A set of blobs sharing one key prefix — [`crate::Collection`]'s shape for
/// values that don't fit in a single object.
#[derive(Debug, Clone)]
pub struct Blob {
    pub prefix: Cow<'static, str>,
    pub part_bytes: usize,
    pub max_total_bytes: usize,
}

impl Blob {
    pub const fn new(prefix: &'static str) -> Self {
        Blob {
            prefix: Cow::Borrowed(prefix),
            part_bytes: DEFAULT_PART_BYTES,
            max_total_bytes: DEFAULT_MAX_BLOB_BYTES,
        }
    }

    pub fn new_owned(prefix: String) -> Self {
        Blob {
            prefix: Cow::Owned(prefix),
            part_bytes: DEFAULT_PART_BYTES,
            max_total_bytes: DEFAULT_MAX_BLOB_BYTES,
        }
    }

    /// Overrides [`DEFAULT_PART_BYTES`]. Capped at [`MAX_OBJECT_BYTES`] when
    /// read back (see [`Self::effective_part_bytes`]) so a mis-set value
    /// can't produce parts this crate's own limits would reject on write.
    pub const fn with_part_bytes(mut self, bytes: usize) -> Self {
        self.part_bytes = bytes;
        self
    }

    pub const fn with_max_total_bytes(mut self, bytes: usize) -> Self {
        self.max_total_bytes = bytes;
        self
    }

    fn effective_part_bytes(&self) -> usize {
        self.part_bytes.clamp(1, MAX_OBJECT_BYTES)
    }

    /// This blob's manifest key — the key that *is* the blob, as far as CAS
    /// and etags are concerned.
    pub fn manifest_key(&self, name: &str) -> Result<String> {
        validate_path(name, "blob name")?;
        Ok(format!("{}/{name}.json", self.prefix))
    }

    /// Prefix holding every generation of `name`'s parts. Under `.parts/`,
    /// which [`validate_path`] forbids a name from reaching (no component
    /// may start with `.`), so a blob name can never collide with it — the
    /// same reserved-namespace discipline as `Collection`'s `.history/` and
    /// `.deleted/`.
    fn parts_prefix(&self, name: &str) -> Result<String> {
        validate_path(name, "blob name")?;
        Ok(format!("{}/.parts/{name}", self.prefix))
    }

    fn part_key(&self, name: &str, generation: &str, index: u32) -> Result<String> {
        Ok(format!("{}/{generation}/{index:04}", self.parts_prefix(name)?))
    }

    /// A fresh generation id: `<millis>-<128 random bits>`, hex, so it's
    /// always a safe path component.
    ///
    /// The random half is what keeps two concurrent writers from picking the
    /// same generation and quietly interleaving parts. The timestamp half is
    /// what makes [`Self::sweep_orphan_parts`] possible at all: nothing in
    /// [`Backend`] reports an object's mtime (deliberately -- it isn't part
    /// of that trait's minimal surface), so a generation that no manifest
    /// names any more has to carry its own age, or a sweep could not tell an
    /// abandoned write from one still in flight. Fixed width and
    /// millis-first, so the id also sorts chronologically.
    fn new_generation() -> Result<String> {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).context("generating a blob generation id")?;
        let random: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(format!("{:013}-{random}", now_ms()))
    }

    /// How long ago the generation id says its write started, or `None` if
    /// the id isn't one [`Self::new_generation`] produced.
    fn generation_age_ms(generation: &str, now: u64) -> Option<u64> {
        let (millis, _random) = generation.split_once('-')?;
        let written: u64 = millis.parse().ok()?;
        Some(now.saturating_sub(written))
    }

    /// Compare-and-swap write of a whole value. `expected_etag = None` means
    /// "must not exist yet"; otherwise pass the etag from [`Self::get`] or
    /// [`Self::head`].
    ///
    /// On [`Cas::Conflict`] the parts this call wrote are swept before
    /// returning: nothing references them, and leaving them behind would
    /// make every lost race cost storage until a GC pass noticed.
    pub async fn put(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
        body: &[u8],
        expected_etag: Option<&str>,
    ) -> Result<Cas> {
        if body.len() > self.max_total_bytes {
            bail!(
                "{}: blob is {} bytes, over this blob's {}-byte ceiling",
                self.manifest_key(name)?,
                body.len(),
                self.max_total_bytes
            );
        }
        let part_bytes = self.effective_part_bytes();
        let generation = Self::new_generation()?;
        let previous = get_json::<BlobManifest>(backend, &self.manifest_key(name)?, cipher)
            .await?
            .0;

        // Parts first, manifest last -- see the module doc.
        let mut parts: u32 = 0;
        for (index, chunk) in body.chunks(part_bytes).enumerate() {
            let index = u32::try_from(index).context("blob has more parts than a u32 can index")?;
            let key = self.part_key(name, &generation, index)?;
            let sealed = cipher.seal(&key, chunk, CompressionStrategy::None)?;
            // A fresh generation means a fresh key, so this is a create, not
            // an overwrite: a `Conflict` here would mean two writers drew
            // the same 128-bit generation, which is worth failing loudly
            // over rather than silently interleaving parts.
            if backend.put_cas(&key, sealed, None).await? == Cas::Conflict {
                bail!("{key}: blob part already exists (generation collision)");
            }
            parts = index + 1;
        }

        let manifest = BlobManifest {
            total_len: body.len() as u64,
            part_bytes: u32::try_from(part_bytes).context("part size does not fit a u32")?,
            parts,
            generation: generation.clone(),
            written_at_ms: now_ms(),
        };
        let cas = put_json(backend, &self.manifest_key(name)?, &manifest, expected_etag, cipher).await?;

        match cas {
            // The manifest now names the new generation, so the previous
            // one is unreachable. Best-effort: a reader that fetched the old
            // manifest before this point may still be assembling from it,
            // and the same tolerance every other delete in this crate has
            // applies -- a sweep that doesn't land leaves storage to
            // reclaim, not a wrong answer.
            Cas::Ok => {
                if !previous.generation.is_empty() && previous.generation != generation {
                    let _ = delete_prefix(
                        backend,
                        &format!("{}/{}/", self.parts_prefix(name)?, previous.generation),
                    )
                    .await;
                }
            }
            Cas::Conflict => {
                let _ = delete_prefix(backend, &format!("{}/{generation}/", self.parts_prefix(name)?)).await;
            }
        }
        Ok(cas)
    }

    /// Reads the manifest without fetching a single part — size and write
    /// time for the cost of one `get`, and the etag to pass back to
    /// [`Self::put`].
    pub async fn head(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
    ) -> Result<(Option<BlobManifest>, Option<String>)> {
        let (manifest, etag) = get_json::<BlobManifest>(backend, &self.manifest_key(name)?, cipher).await?;
        Ok((etag.is_some().then_some(manifest), etag))
    }

    /// Assembles the whole value. `None` means the blob doesn't exist.
    ///
    /// A blob whose manifest exists but whose parts don't (a generation
    /// swept out from under an in-flight read, a partially deleted blob) is
    /// an `Err`, not a `None`: "gone" and "here but broken" are different
    /// facts and a caller retrying the first would loop forever on the
    /// second. The assembled length is checked against the manifest's
    /// `total_len`, so a short read fails rather than returning truncated
    /// bytes.
    pub async fn get(
        &self,
        backend: &Arc<dyn Backend>,
        cipher: &Arc<Cipher>,
        name: &str,
    ) -> Result<(Option<Vec<u8>>, Option<String>)> {
        let (manifest, etag) = self.head(backend.as_ref(), cipher, name).await?;
        let Some(manifest) = manifest else {
            return Ok((None, etag));
        };

        let semaphore = Arc::new(Semaphore::new(PART_FETCH_CONCURRENCY));
        let mut set = JoinSet::new();
        for index in 0..manifest.parts {
            let key = self.part_key(name, &manifest.generation, index)?;
            let backend = Arc::clone(backend);
            let cipher = Arc::clone(cipher);
            let semaphore = Arc::clone(&semaphore);
            set.spawn(async move {
                let _permit = semaphore.acquire_owned().await.expect("semaphore is never closed");
                let (sealed, found) = backend.get(&key).await?;
                if found.is_none() {
                    bail!("{key}: blob part is missing");
                }
                let plain = cipher.open(&key, &sealed)?;
                Ok::<(u32, Vec<u8>), anyhow::Error>((index, plain))
            });
        }

        let mut chunks: Vec<Option<Vec<u8>>> = vec![None; manifest.parts as usize];
        while let Some(joined) = set.join_next().await {
            let (index, plain) = joined.context("blob part fetch panicked")??;
            chunks[index as usize] = Some(plain);
        }

        let mut body = Vec::with_capacity(manifest.total_len as usize);
        for (index, chunk) in chunks.into_iter().enumerate() {
            let chunk = chunk.with_context(|| format!("blob {name}: part {index} never arrived"))?;
            body.extend_from_slice(&chunk);
        }
        if body.len() as u64 != manifest.total_len {
            bail!(
                "blob {name}: assembled {} bytes but its manifest declares {}",
                body.len(),
                manifest.total_len
            );
        }
        Ok((Some(body), etag))
    }

    /// Removes the manifest and every generation of parts.
    ///
    /// A hard delete, unlike [`crate::Collection::delete`]'s tombstone: a
    /// soft-deleted blob would keep its parts around to be restorable, which
    /// for values this size is a storage decision a caller should make
    /// explicitly (copy it elsewhere first) rather than inherit by default.
    /// The manifest goes first, so a partial delete leaves unreferenced
    /// parts rather than a blob that reads as present but broken; the
    /// returned [`SweepReport`] says whether the parts are actually gone.
    pub async fn delete(&self, backend: &dyn Backend, name: &str) -> Result<SweepReport> {
        let _ = backend.delete(&self.manifest_key(name)?).await;
        delete_prefix(backend, &format!("{}/", self.parts_prefix(name)?)).await
    }

    /// Every blob name under this prefix, sorted. Skips the `.parts/`
    /// namespace, same as [`crate::Collection::list_names`] skips its own
    /// bookkeeping prefixes.
    pub async fn list_names(&self, backend: &dyn Backend) -> Result<Vec<String>> {
        let scan_prefix = format!("{}/", self.prefix);
        let mut names: Vec<String> = list_all_keys(backend, &scan_prefix)
            .await?
            .into_iter()
            .filter_map(|key| {
                let rest = key.strip_prefix(&scan_prefix)?;
                if rest.starts_with(".parts/") {
                    return None;
                }
                rest.strip_suffix(".json").map(str::to_string)
            })
            .collect();
        names.sort();
        Ok(names)
    }

    /// Sweeps parts belonging to generations no manifest names any more --
    /// the orphans a crash between "parts written" and "manifest CAS'd"
    /// leaves behind, and any generation whose post-write cleanup didn't
    /// land.
    ///
    /// Skips generations younger than `min_age_ms`: a generation that no
    /// manifest points at yet is exactly what an *in-flight* write looks
    /// like from the outside, and deleting those out from under it would
    /// turn a concurrent writer's success into a blob with missing parts.
    pub async fn sweep_orphan_parts(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
        min_age_ms: u64,
    ) -> Result<SweepReport> {
        let parts_prefix = self.parts_prefix(name)?;
        let live = match self.head(backend, cipher, name).await? {
            (Some(manifest), _etag) => manifest.generation,
            (None, _etag) => String::new(),
        };

        let mut generations: Vec<String> = list_all_keys(backend, &format!("{parts_prefix}/"))
            .await?
            .into_iter()
            .filter_map(|key| {
                let rest = key.strip_prefix(&format!("{parts_prefix}/"))?;
                rest.split_once('/').map(|(generation, _part)| generation.to_string())
            })
            .filter(|generation| *generation != live)
            .collect();
        generations.sort();
        generations.dedup();

        let now = now_ms();
        let mut report = SweepReport::default();
        for generation in generations {
            // A generation id this version didn't write (`None`) is left
            // alone: without an age there's no way to tell it from an
            // in-flight write, and the cost of keeping it is storage, while
            // the cost of removing it could be someone else's blob.
            match Self::generation_age_ms(&generation, now) {
                Some(age) if age >= min_age_ms => {}
                _ => continue,
            }
            let swept = delete_prefix(backend, &format!("{parts_prefix}/{generation}/")).await?;
            report.attempted += swept.attempted;
            report.confirmed += swept.confirmed;
            report.remaining += swept.remaining;
        }
        Ok(report)
    }

    /// Sweeps orphan parts across every blob under this `Blob`'s prefix in
    /// one pass, instead of requiring the caller to already know and loop
    /// over every `name` individually. Derives names directly from the
    /// `.parts/` key structure rather than [`Self::list_names`] (which reads
    /// every manifest) -- cheaper, and it's the shape a large corpus
    /// actually needs: hundreds of thousands of blobs, where enumerating
    /// names first would be its own expensive scan before the real one
    /// starts.
    pub async fn sweep_all_orphan_parts(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        min_age_ms: u64,
    ) -> Result<SweepReport> {
        let parts_root = format!("{}/.parts/", self.prefix);
        let mut names: Vec<String> = list_all_keys(backend, &parts_root)
            .await?
            .into_iter()
            .filter_map(|key| {
                let rest = key.strip_prefix(&parts_root)?;
                rest.split_once('/').map(|(name, _rest)| name.to_string())
            })
            .collect();
        names.sort();
        names.dedup();

        let mut report = SweepReport::default();
        for name in names {
            let swept = self.sweep_orphan_parts(backend, cipher, &name, min_age_ms).await?;
            report.attempted += swept.attempted;
            report.confirmed += swept.confirmed;
            report.remaining += swept.remaining;
        }
        Ok(report)
    }
}

#[cfg(test)]
#[path = "../tests/unit/blob.rs"]
mod tests;
