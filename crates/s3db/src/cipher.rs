//! The pure encryption primitive (no storage backend, no async) — derives a
//! key from a passphrase and seals/opens bytes with AEAD. Everything this
//! crate uploads goes through here before leaving — the storage provider is
//! an intermediary, it never sees plaintext or the key. See [`super::bootstrap`]
//! for the one exception (the derivation salt itself) and for deriving/
//! creating the [`Cipher`] every encrypted read/write is built from.

use anyhow::{Context, Result, bail};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroize;

pub const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// XChaCha20Poly1305: 24-byte nonce (vs. 12 for plain ChaCha20Poly1305).
/// With random nonces (not a counter) the extra 12 bytes matter: at this
/// object volume, a 96-bit nonce collision is no longer astronomically
/// unlikely, a 192-bit one still is.
const NONCE_LEN: usize = 24;

/// Header for [`Cipher::seal_stream`]'s output: a fixed 8-byte magic (so
/// [`Cipher::open_stream`] fails with a clear "not a stream" error instead
/// of a confusing AEAD failure if ever pointed at the wrong kind of blob),
/// no version byte beyond that — this is a single, deliberately breaking
/// format with no predecessor to stay compatible with (see
/// `storage::remote`'s callers: nothing reads pack objects any other way).
const STREAM_MAGIC: &[u8; 8] = b"GQCSTRM1";
/// Plaintext bytes per chunk in [`Cipher::seal_stream`]'s framing. Bounds
/// peak memory for sealing/opening a pack to roughly this, regardless of
/// the pack's actual size.
const STREAM_CHUNK_LEN: usize = 4 * 1024 * 1024;

/// How many chunks a [`Cipher::seal_stream`]/[`Cipher::open_stream`] stream
/// of `total_len` plaintext bytes is framed into. A zero-byte file is still
/// exactly one (empty) chunk, never zero — `open_stream` always expects at
/// least one chunk frame.
fn stream_chunk_count(total_len: u64) -> u64 {
    if total_len == 0 { 1 } else { total_len.div_ceil(STREAM_CHUNK_LEN as u64) }
}

#[derive(Clone)]
pub struct Cipher(XChaCha20Poly1305);

// Manual, no derive: we don't want an accidental `{:?}` (log, panic message)
// to have the slightest chance of printing key material.
impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cipher(..)")
    }
}

impl Cipher {
    /// Derives the encryption key from a passphrase + salt via Argon2id.
    /// Fixed parameters (not configurable): OWASP's low-memory
    /// recommendation, 19 MiB / 2 iterations / 1 thread. Not made choosable
    /// on purpose — a weak choice would weaken everyone sharing the bucket,
    /// and if they ever change, that's a format version bump, not a flag.
    pub fn derive(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Self> {
        let mut key_bytes = [0u8; KEY_LEN];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("deriving encryption key: {e}"))?;
        let cipher = XChaCha20Poly1305::new(&Key::from(key_bytes));
        // The local copy of the raw key isn't needed anymore once the
        // cipher is built; don't leave it sitting on the stack longer than
        // necessary.
        key_bytes.zeroize();
        Ok(Cipher(cipher))
    }

    /// Encrypts `plaintext`, bound to `aad` (the object's S3 key). This
    /// stops a malicious storage provider from copying one object's
    /// ciphertext onto another and passing it off as valid: `open` with an
    /// `aad` different from the one used in `seal` fails authentication.
    ///
    /// Format: `nonce(24 bytes) || ciphertext+tag`.
    pub fn seal(&self, aad: &str, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).expect("system RNG unavailable");
        let nonce = XNonce::from(nonce_bytes);
        let mut ciphertext = self
            .0
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            // The only way this fails in this API is a plaintext bigger than
            // the cipher's theoretical limit (hundreds of GiB); never due to
            // the key or the content itself.
            .expect("XChaCha20Poly1305::encrypt never fails at these sizes");
        let mut sealed = nonce.to_vec();
        sealed.append(&mut ciphertext);
        sealed
    }

    /// Opens what [`Self::seal`] sealed. Fails if the key, the `aad`, or the
    /// content aren't the originals — a single generic error on purpose, to
    /// avoid giving an attacker an "almost" signal (padding oracle).
    pub fn open(&self, aad: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN {
            bail!("invalid ciphertext (too short)");
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).context("nonce has invalid length")?;
        self.0
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "couldn't decrypt (wrong passphrase, or data was modified/moved \
                     from a different key)"
                )
            })
    }

    /// Streaming counterpart of [`Self::seal`], for objects too big to want
    /// fully buffered (pack files) — bounds peak memory to roughly one
    /// chunk (see [`STREAM_CHUNK_LEN`]) regardless of `plaintext_path`'s
    /// size. Not a variant of the same on-disk format: output starts with
    /// [`STREAM_MAGIC`] followed by the total plaintext length, then that
    /// many chunks of `[len: u32 LE][nonce: 24 bytes][ciphertext+tag]`, each
    /// independently AEAD-sealed with a fresh random nonce and an AAD that
    /// binds `aad`, the declared total length, and this chunk's index —
    /// which is what makes reordering, truncating, or duplicating chunks
    /// all detectable by [`Self::open_stream`] (see its doc comment).
    pub async fn seal_stream(&self, aad: &str, plaintext_path: &Path, sealed_path: &Path) -> Result<()> {
        let total_len = tokio::fs::metadata(plaintext_path)
            .await
            .with_context(|| format!("checking size of {}", plaintext_path.display()))?
            .len();
        let num_chunks = stream_chunk_count(total_len);

        let mut input = tokio::fs::File::open(plaintext_path)
            .await
            .with_context(|| format!("opening {}", plaintext_path.display()))?;
        let mut output = tokio::fs::File::create(sealed_path)
            .await
            .with_context(|| format!("creating {}", sealed_path.display()))?;

        output.write_all(STREAM_MAGIC).await?;
        output.write_all(&total_len.to_le_bytes()).await?;

        let mut remaining = total_len;
        for idx in 0..num_chunks {
            let chunk_len = remaining.min(STREAM_CHUNK_LEN as u64) as usize;
            let mut plain = vec![0u8; chunk_len];
            input
                .read_exact(&mut plain)
                .await
                .with_context(|| format!("reading chunk {idx} of {}", plaintext_path.display()))?;
            remaining -= chunk_len as u64;

            let mut nonce_bytes = [0u8; NONCE_LEN];
            getrandom::fill(&mut nonce_bytes).expect("system RNG unavailable");
            let nonce = XNonce::from(nonce_bytes);
            let chunk_aad = format!("{aad}\0stream\0{total_len}\0{idx}");
            let ciphertext = self
                .0
                .encrypt(&nonce, Payload { msg: &plain, aad: chunk_aad.as_bytes() })
                // Same reasoning as `seal`: only fails on a plaintext bigger
                // than the cipher's theoretical limit, never on content/key,
                // and a chunk is always far under that limit.
                .expect("XChaCha20Poly1305::encrypt never fails at these sizes");

            output.write_all(&(ciphertext.len() as u32).to_le_bytes()).await?;
            output.write_all(&nonce_bytes).await?;
            output.write_all(&ciphertext).await?;
        }
        // `tokio::fs::File::poll_write` returns as soon as it has *spawned*
        // the blocking write, not once it's actually landed — the write
        // only gets awaited to completion on the next operation on this
        // handle. Without this, the very last `write_all` above can still
        // be in flight when this function returns, racing the `metadata`
        // check below (and any caller reading `sealed_path` right after)
        // against a write that hasn't finished yet.
        output.flush().await?;
        drop(output);

        // Belt-and-suspenders, same reasoning as `open_stream`'s own
        // per-chunk length check: the sealed size is fully determined by
        // `total_len`/`num_chunks` (each chunk adds exactly 4 + NONCE_LEN +
        // 16 bytes of framing/tag overhead on top of its own plaintext), so
        // any mismatch means a bug in this accounting itself and produced a
        // truncated ciphertext that would otherwise upload successfully and
        // only fail much later, confusingly, whenever something next tries
        // to read it (exactly the failure this caught in practice: a
        // repo's `.idx` landing as a bare 16-byte header with no chunk data
        // at all — before the missing `flush()` above was found and fixed).
        let actual_len = tokio::fs::metadata(sealed_path)
            .await
            .with_context(|| format!("verifying size of {}", sealed_path.display()))?
            .len();
        let expected_len = STREAM_MAGIC.len() as u64
            + 8
            + num_chunks * (4 + NONCE_LEN as u64 + 16)
            + total_len;
        if actual_len != expected_len {
            bail!(
                "incomplete sealing: {} ended up at {actual_len} bytes, expected {expected_len} \
                 (not uploaded)",
                sealed_path.display()
            );
        }
        Ok(())
    }

    /// Reverses [`Self::seal_stream`]. Fails the same ways [`Self::open`]
    /// does (wrong key, tampered content), plus explicitly on:
    /// - a missing/wrong [`STREAM_MAGIC`] (not a stream blob at all, or a
    ///   plain [`Self::seal`]-format one);
    /// - a truncated stream (fewer than the header's declared chunk count,
    ///   or a chunk frame cut off mid-way) — reaching EOF early always
    ///   surfaces as an error here, never a silently-short output file;
    /// - a reordered chunk (each chunk's AAD binds its own index, so a
    ///   chunk read at position `idx` that was actually sealed at a
    ///   different index fails to decrypt);
    /// - trailing bytes after the last expected chunk (an appended/
    ///   duplicated chunk) — checked explicitly once the expected chunk
    ///   count has been read.
    pub async fn open_stream(&self, aad: &str, sealed_path: &Path, plaintext_path: &Path) -> Result<()> {
        let mut input = tokio::fs::File::open(sealed_path)
            .await
            .with_context(|| format!("opening {}", sealed_path.display()))?;
        let mut output = tokio::fs::File::create(plaintext_path)
            .await
            .with_context(|| format!("creating {}", plaintext_path.display()))?;

        let mut magic = [0u8; STREAM_MAGIC.len()];
        input
            .read_exact(&mut magic)
            .await
            .context("invalid ciphertext (not a gitquarry stream, incomplete header)")?;
        if &magic != STREAM_MAGIC {
            bail!("invalid ciphertext (not a gitquarry stream)");
        }
        let mut total_len_bytes = [0u8; 8];
        input
            .read_exact(&mut total_len_bytes)
            .await
            .context("invalid ciphertext (incomplete stream header)")?;
        let total_len = u64::from_le_bytes(total_len_bytes);
        let num_chunks = stream_chunk_count(total_len);

        let mut remaining = total_len;
        for idx in 0..num_chunks {
            let mut len_bytes = [0u8; 4];
            input
                .read_exact(&mut len_bytes)
                .await
                .with_context(|| format!("truncated ciphertext (chunk {idx} of {num_chunks})"))?;
            let ciphertext_len = u32::from_le_bytes(len_bytes) as usize;

            let mut nonce_bytes = [0u8; NONCE_LEN];
            input
                .read_exact(&mut nonce_bytes)
                .await
                .with_context(|| format!("truncated ciphertext (chunk {idx} of {num_chunks})"))?;
            let nonce = XNonce::from(nonce_bytes);

            let mut ciphertext = vec![0u8; ciphertext_len];
            input
                .read_exact(&mut ciphertext)
                .await
                .with_context(|| format!("truncated ciphertext (chunk {idx} of {num_chunks})"))?;

            let chunk_aad = format!("{aad}\0stream\0{total_len}\0{idx}");
            let plain = self
                .0
                .decrypt(&nonce, Payload { msg: &ciphertext, aad: chunk_aad.as_bytes() })
                .map_err(|_| {
                    anyhow::anyhow!(
                        "couldn't decrypt (wrong passphrase, out-of-order chunk, or the \
                         data was modified/moved from a different key)"
                    )
                })?;

            // Belt-and-suspenders: every chunk but the last must be exactly
            // STREAM_CHUNK_LEN, the last exactly whatever's left. A chunk
            // that decrypts validly but at the wrong length would mean
            // `seal_stream` itself framed it inconsistently with the
            // declared total_len — this can't happen from tampering alone
            // (the AEAD tag already ties the ciphertext to this exact
            // plaintext), but it's a cheap, direct check on the one
            // invariant this whole scheme depends on.
            let expected_len = remaining.min(STREAM_CHUNK_LEN as u64) as usize;
            if plain.len() != expected_len {
                bail!("invalid ciphertext (inconsistent chunk size at {idx})");
            }
            remaining -= expected_len as u64;

            output
                .write_all(&plain)
                .await
                .with_context(|| format!("writing {}", plaintext_path.display()))?;
        }

        // No trailing bytes allowed after the declared final chunk —
        // catches an appended/duplicated extra chunk.
        let mut probe = [0u8; 1];
        match input.read(&mut probe).await {
            Ok(0) => {}
            Ok(_) => bail!("invalid ciphertext (extra bytes after last chunk)"),
            Err(e) => return Err(e).context("verifying end of stream"),
        }
        // Same reasoning as `seal_stream`'s matching `flush()`: the last
        // `write_all` above can still be spawned-but-not-landed on
        // `tokio::fs::File`'s blocking pool at this point, racing the
        // `metadata` check below (and any caller reading `plaintext_path`
        // right after this returns) against a write that hasn't finished.
        output.flush().await?;
        drop(output);

        // Belt-and-suspenders, mirroring `seal_stream`'s own post-write
        // check: every `plain.len()` above was already verified against
        // `total_len`'s accounting before being handed to `write_all`, but
        // that only proves the bytes handed to the writer were correct —
        // not that they actually landed on `plaintext_path`.
        let actual_len = tokio::fs::metadata(plaintext_path)
            .await
            .with_context(|| format!("verifying size of {}", plaintext_path.display()))?
            .len();
        if actual_len != total_len {
            bail!(
                "incomplete write: {} ended up at {actual_len} bytes, expected {total_len}",
                plaintext_path.display()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cipher() -> Cipher {
        Cipher::derive("correct horse battery staple", &[7u8; SALT_LEN]).unwrap()
    }

    #[test]
    fn roundtrips() {
        let c = test_cipher();
        let sealed = c.seal("repo/refs.json", b"secret content");
        let opened = c.open("repo/refs.json", &sealed).unwrap();
        assert_eq!(opened, b"secret content");
    }

    #[test]
    fn rejects_wrong_passphrase() {
        let sealed = test_cipher().seal("k", b"x");
        let other = Cipher::derive("another passphrase", &[7u8; SALT_LEN]).unwrap();
        assert!(other.open("k", &sealed).is_err());
    }

    #[test]
    fn rejects_wrong_aad() {
        let c = test_cipher();
        let sealed = c.seal("repo-a/refs.json", b"x");
        // Simulates a storage provider moving ciphertext to another key.
        assert!(c.open("repo-b/refs.json", &sealed).is_err());
    }

    #[test]
    fn rejects_truncated_or_tampered() {
        let c = test_cipher();
        let mut sealed = c.seal("k", b"test content");
        assert!(c.open("k", &sealed[..10]).is_err());
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(c.open("k", &sealed).is_err());
    }

    #[test]
    fn different_salts_give_different_keys() {
        let a = Cipher::derive("pw", &[1u8; SALT_LEN]).unwrap();
        let b = Cipher::derive("pw", &[2u8; SALT_LEN]).unwrap();
        let sealed = a.seal("k", b"x");
        assert!(b.open("k", &sealed).is_err());
    }

    /// Splits a `seal_stream`-produced file into `(total_len, chunk_frames)`
    /// — each frame is the raw `[len][nonce][ciphertext]` bytes, kept whole
    /// so the reorder/truncate/duplicate tests below can shuffle them
    /// without needing to understand anything past the frame boundary.
    async fn read_stream_chunks(path: &std::path::Path) -> (u64, Vec<Vec<u8>>) {
        let bytes = tokio::fs::read(path).await.unwrap();
        assert_eq!(&bytes[..STREAM_MAGIC.len()], STREAM_MAGIC);
        let total_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let mut chunks = Vec::new();
        let mut pos = 16;
        while pos < bytes.len() {
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            let frame_len = 4 + NONCE_LEN + len;
            chunks.push(bytes[pos..pos + frame_len].to_vec());
            pos += frame_len;
        }
        (total_len, chunks)
    }

    async fn write_stream_file(path: &std::path::Path, total_len: u64, chunks: &[Vec<u8>]) {
        let mut out = Vec::new();
        out.extend_from_slice(STREAM_MAGIC);
        out.extend_from_slice(&total_len.to_le_bytes());
        for c in chunks {
            out.extend_from_slice(c);
        }
        tokio::fs::write(path, out).await.unwrap();
    }

    /// Under heavy concurrent filesystem load, a single `write_all` call on
    /// this environment's `/tmp` has been observed to return `Ok` while the
    /// file it wrote to ends up short (always at a page-aligned boundary —
    /// consistent with the underlying write silently landing short rather
    /// than a logic bug in this module's own chunk accounting). Neither
    /// `seal_stream` nor `open_stream` can prevent that write from
    /// happening; what they must guarantee is never serving the result as
    /// if it were correct. This hammers both with real concurrency and
    /// asserts exactly that: every task either roundtrips byte-for-byte, or
    /// fails with an explicit error — a truncated/wrong-but-`Ok` result
    /// anywhere is the one outcome that's never acceptable.
    #[tokio::test(flavor = "multi_thread", worker_threads = 32)]
    async fn stream_stress_never_silently_corrupts_under_concurrency() {
        let c = test_cipher();
        let mut handles = Vec::new();
        for n in 0..300u64 {
            let c = c.clone();
            handles.push(tokio::spawn(async move {
                let len = 700_000 + (n as usize * 37) % 50_000;
                let plain: Vec<u8> = (0..len).map(|i| ((i as u64 + n) % 251) as u8).collect();
                let dir = tempfile::tempdir().unwrap();
                let plain_path = dir.path().join("plain");
                let sealed_path = dir.path().join("sealed");
                let opened_path = dir.path().join("opened");
                tokio::fs::write(&plain_path, &plain).await.unwrap();

                if c.seal_stream("repo/pack", &plain_path, &sealed_path).await.is_err() {
                    return; // loud failure: acceptable
                }
                if c.open_stream("repo/pack", &sealed_path, &opened_path).await.is_err() {
                    return; // loud failure: acceptable
                }
                // Reached only on a claimed success from both — this is the
                // one path that must be trustworthy.
                let opened = tokio::fs::read(&opened_path).await.unwrap();
                assert_eq!(opened, plain, "task {n} len {len}: claimed success but content is wrong");
            }));
        }
        for h in handles {
            // A panicked task (the assert above) is the real failure mode;
            // a clean Err from seal_stream/open_stream already returned
            // early above and isn't one.
            h.await.unwrap_or_else(|e| panic!("task panicked: {e}"));
        }
    }

    #[tokio::test]
    async fn stream_roundtrips_various_sizes() {
        let c = test_cipher();
        for &len in &[0usize, 1, STREAM_CHUNK_LEN, STREAM_CHUNK_LEN + 1, STREAM_CHUNK_LEN * 2 + 100] {
            let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let dir = tempfile::tempdir().unwrap();
            let plain_path = dir.path().join("plain");
            let sealed_path = dir.path().join("sealed");
            let opened_path = dir.path().join("opened");
            tokio::fs::write(&plain_path, &plain).await.unwrap();
            c.seal_stream("repo/pack", &plain_path, &sealed_path).await.unwrap();
            c.open_stream("repo/pack", &sealed_path, &opened_path).await.unwrap();
            let opened = tokio::fs::read(&opened_path).await.unwrap();
            assert_eq!(opened, plain, "size {len}");
        }
    }

    #[tokio::test]
    async fn stream_rejects_reordered_chunks() {
        let c = test_cipher();
        let dir = tempfile::tempdir().unwrap();
        let plain_path = dir.path().join("plain");
        let sealed_path = dir.path().join("sealed");
        let opened_path = dir.path().join("opened");
        let plain = vec![0xABu8; STREAM_CHUNK_LEN * 2 + 10]; // 3 chunks
        tokio::fs::write(&plain_path, &plain).await.unwrap();
        c.seal_stream("repo/pack", &plain_path, &sealed_path).await.unwrap();

        let (total_len, mut chunks) = read_stream_chunks(&sealed_path).await;
        assert_eq!(chunks.len(), 3);
        chunks.swap(0, 1);
        write_stream_file(&sealed_path, total_len, &chunks).await;

        assert!(c.open_stream("repo/pack", &sealed_path, &opened_path).await.is_err());
    }

    #[tokio::test]
    async fn stream_rejects_truncated_stream() {
        let c = test_cipher();
        let dir = tempfile::tempdir().unwrap();
        let plain_path = dir.path().join("plain");
        let sealed_path = dir.path().join("sealed");
        let opened_path = dir.path().join("opened");
        let plain = vec![0xCDu8; STREAM_CHUNK_LEN * 2 + 10]; // 3 chunks
        tokio::fs::write(&plain_path, &plain).await.unwrap();
        c.seal_stream("repo/pack", &plain_path, &sealed_path).await.unwrap();

        let (total_len, mut chunks) = read_stream_chunks(&sealed_path).await;
        chunks.pop(); // drop the real last chunk
        write_stream_file(&sealed_path, total_len, &chunks).await;

        assert!(c.open_stream("repo/pack", &sealed_path, &opened_path).await.is_err());
    }

    #[tokio::test]
    async fn stream_rejects_duplicated_trailing_chunk() {
        let c = test_cipher();
        let dir = tempfile::tempdir().unwrap();
        let plain_path = dir.path().join("plain");
        let sealed_path = dir.path().join("sealed");
        let opened_path = dir.path().join("opened");
        let plain = vec![0xEFu8; STREAM_CHUNK_LEN + 10]; // 2 chunks
        tokio::fs::write(&plain_path, &plain).await.unwrap();
        c.seal_stream("repo/pack", &plain_path, &sealed_path).await.unwrap();

        let (total_len, mut chunks) = read_stream_chunks(&sealed_path).await;
        let last = chunks.last().unwrap().clone();
        chunks.push(last); // append a duplicate of the legitimate last chunk
        write_stream_file(&sealed_path, total_len, &chunks).await;

        assert!(c.open_stream("repo/pack", &sealed_path, &opened_path).await.is_err());
    }

    #[tokio::test]
    async fn stream_rejects_tampered_chunk_bytes() {
        let c = test_cipher();
        let dir = tempfile::tempdir().unwrap();
        let plain_path = dir.path().join("plain");
        let sealed_path = dir.path().join("sealed");
        let opened_path = dir.path().join("opened");
        tokio::fs::write(&plain_path, b"test content").await.unwrap();
        c.seal_stream("repo/pack", &plain_path, &sealed_path).await.unwrap();

        let mut bytes = tokio::fs::read(&sealed_path).await.unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        tokio::fs::write(&sealed_path, &bytes).await.unwrap();

        assert!(c.open_stream("repo/pack", &sealed_path, &opened_path).await.is_err());
    }

    #[tokio::test]
    async fn stream_rejects_bad_magic_without_panicking() {
        let c = test_cipher();
        let dir = tempfile::tempdir().unwrap();
        let sealed_path = dir.path().join("sealed");
        let opened_path = dir.path().join("opened");

        // Too short to even contain the magic.
        tokio::fs::write(&sealed_path, b"ab").await.unwrap();
        assert!(c.open_stream("repo/pack", &sealed_path, &opened_path).await.is_err());

        // Long enough, but it's a plain `seal`-format blob (no magic at all).
        let legacy = c.seal("repo/pack", b"test content");
        tokio::fs::write(&sealed_path, &legacy).await.unwrap();
        assert!(c.open_stream("repo/pack", &sealed_path, &opened_path).await.is_err());
    }

    #[tokio::test]
    async fn stream_rejects_wrong_key_or_aad() {
        let c = test_cipher();
        let dir = tempfile::tempdir().unwrap();
        let plain_path = dir.path().join("plain");
        let sealed_path = dir.path().join("sealed");
        let opened_path = dir.path().join("opened");
        tokio::fs::write(&plain_path, b"test content").await.unwrap();
        c.seal_stream("repo-a/pack", &plain_path, &sealed_path).await.unwrap();

        assert!(c.open_stream("repo-b/pack", &sealed_path, &opened_path).await.is_err());

        let other = Cipher::derive("another passphrase", &[7u8; SALT_LEN]).unwrap();
        assert!(other.open_stream("repo-a/pack", &sealed_path, &opened_path).await.is_err());
    }
}
