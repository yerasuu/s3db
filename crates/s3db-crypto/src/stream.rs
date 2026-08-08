//! Streaming seal/open for objects too big to want fully buffered (git
//! packs) -- a completely separate on-disk format from [`crate::Cipher::seal`]/
//! [`crate::Cipher::open`]'s (chunked, file-to-file, no compression -- see
//! this module's own reasoning below), isolated here so changing the chunking
//! scheme, chunk size, or framing never touches the small-object path at
//! all.

use crate::Cipher;
use crate::algorithm::{CipherAlgorithm, Sealer};
use crate::cipher::NONCE_LEN;
use anyhow::{Context, Result, bail};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Header for [`seal_stream`]'s output: an 8-byte magic, so [`open_stream`]
/// fails with a clear "not a stream" error instead of a confusing AEAD
/// failure if ever pointed at the wrong kind of blob.
///
/// The first seven bytes are fixed and date from this crate's life inside
/// gitquarry -- every stream object already sealed in a live bucket carries
/// them, so renaming would make all of those unreadable for nothing but
/// cosmetics. The eighth byte is the [`CipherAlgorithm`] that sealed the
/// stream (see [`magic_suffix`]): the chunk framing has nowhere else to put
/// it, and `'1'` -- what every existing stream already ends its magic with
/// -- is exactly the algorithm those streams used.
const STREAM_MAGIC_PREFIX: &[u8; 7] = b"GQCSTRM";
const STREAM_MAGIC_LEN: usize = STREAM_MAGIC_PREFIX.len() + 1;

/// The magic's algorithm byte, one entry per [`Sealer`]. Permanent, same
/// rule as [`CipherAlgorithm::code`]: never renumbered, never reused. One
/// table rather than two matches, so a new entry can't be added to the write
/// side and forgotten on the read side.
const STREAM_SEALERS: [(u8, Sealer); 3] = [
    (b'0', Sealer::Plaintext),
    (b'1', Sealer::Algorithm(CipherAlgorithm::XChaCha20Poly1305)),
    (b'2', Sealer::Algorithm(CipherAlgorithm::Aes256Gcm)),
];

fn magic_suffix(sealer: Sealer) -> u8 {
    STREAM_SEALERS
        .into_iter()
        .find_map(|(byte, s)| (s == sealer).then_some(byte))
        .expect("every Sealer has a stream magic byte")
}

fn sealer_from_magic(magic: &[u8; STREAM_MAGIC_LEN]) -> Result<Sealer> {
    let byte = magic[STREAM_MAGIC_PREFIX.len()];
    STREAM_SEALERS
        .into_iter()
        .find_map(|(b, s)| (b == byte).then_some(s))
        .with_context(|| format!("invalid ciphertext (stream sealed by an unknown cipher algorithm {byte:#x})"))
}

fn stream_magic(sealer: Sealer) -> [u8; STREAM_MAGIC_LEN] {
    let mut magic = [0u8; STREAM_MAGIC_LEN];
    magic[..STREAM_MAGIC_PREFIX.len()].copy_from_slice(STREAM_MAGIC_PREFIX);
    magic[STREAM_MAGIC_PREFIX.len()] = magic_suffix(sealer);
    magic
}
/// Plaintext bytes per chunk in [`seal_stream`]'s framing. Bounds peak
/// memory for sealing/opening a pack to roughly this, regardless of the
/// pack's actual size.
const STREAM_CHUNK_LEN: usize = 4 * 1024 * 1024;

/// How many chunks a [`seal_stream`]/[`open_stream`] stream of `total_len`
/// plaintext bytes is framed into. A zero-byte file is still exactly one
/// (empty) chunk, never zero — `open_stream` always expects at least one
/// chunk frame.
fn stream_chunk_count(total_len: u64) -> u64 {
    if total_len == 0 {
        1
    } else {
        total_len.div_ceil(STREAM_CHUNK_LEN as u64)
    }
}

/// `true` if `prefix` (as little as the sealed object's first 7 bytes —
/// callers don't need to read more than that to decide) starts with
/// [`STREAM_MAGIC_PREFIX`] — for a caller that has to handle objects sealed
/// by either format without knowing ahead of time which one a given object
/// used (a re-encrypting sweep over every object under a prefix, say,
/// regardless of whether each one is a large blob sealed by
/// [`seal_stream`] or a small record sealed by [`crate::Cipher::seal`]).
///
/// Deliberately doesn't check the magic's algorithm byte: a stream sealed by
/// an algorithm this build doesn't know is still a stream, and routing it to
/// [`open_stream`] gets the caller a clear error about the algorithm instead
/// of a baffling AEAD failure from [`crate::Cipher::open`].
pub(crate) fn is_stream_sealed(prefix: &[u8]) -> bool {
    prefix.starts_with(STREAM_MAGIC_PREFIX.as_slice())
}

/// Streaming counterpart of [`crate::Cipher::seal`], for objects too big to
/// want fully buffered (pack files) — bounds peak memory to roughly one
/// chunk (see [`STREAM_CHUNK_LEN`]) regardless of `plaintext_path`'s size.
/// Not a variant of the same on-disk format: output starts with the 8-byte
/// magic (see [`STREAM_MAGIC_PREFIX`]) followed by the total plaintext
/// length, then that many chunks of
/// `[len: u32 LE][nonce: 24 bytes][ciphertext+tag]`, each
/// independently AEAD-sealed with a fresh random nonce and an AAD that
/// binds `aad`, the declared total length, and this chunk's index — which
/// is what makes reordering, truncating, or duplicating chunks all
/// detectable by [`open_stream`] (see its doc comment). Deliberately no
/// compression here -- what goes through this path is always an
/// already-compressed git pack, a second pass would buy nothing but CPU.
pub(crate) async fn seal_stream(cipher: &Cipher, aad: &str, plaintext_path: &Path, sealed_path: &Path) -> Result<()> {
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

    let sealer = cipher.sealer();
    output.write_all(&stream_magic(sealer)).await?;
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
        let chunk_aad = format!("{aad}\0stream\0{total_len}\0{idx}");
        let ciphertext = cipher.seal_chunk(&nonce_bytes, &plain, chunk_aad.as_bytes());

        output.write_all(&(ciphertext.len() as u32).to_le_bytes()).await?;
        output.write_all(&nonce_bytes).await?;
        output.write_all(&ciphertext).await?;
    }
    // `tokio::fs::File::poll_write` returns as soon as it has *spawned* the
    // blocking write, not once it's actually landed — the write only gets
    // awaited to completion on the next operation on this handle. Without
    // this, the very last `write_all` above can still be in flight when
    // this function returns, racing the `metadata` check below (and any
    // caller reading `sealed_path` right after) against a write that
    // hasn't finished yet.
    output.flush().await?;
    drop(output);

    // Belt-and-suspenders, same reasoning as `open_stream`'s own per-chunk
    // length check: the sealed size is fully determined by
    // `total_len`/`num_chunks` (each chunk adds exactly 4 + NONCE_LEN + 16
    // bytes of framing/tag overhead on top of its own plaintext), so any
    // mismatch means a bug in this accounting itself and produced a
    // truncated ciphertext that would otherwise upload successfully and
    // only fail much later, confusingly, whenever something next tries to
    // read it (exactly the failure this caught in practice: a repo's
    // `.idx` landing as a bare 16-byte header with no chunk data at all —
    // before the missing `flush()` above was found and fixed).
    let actual_len = tokio::fs::metadata(sealed_path)
        .await
        .with_context(|| format!("verifying size of {}", sealed_path.display()))?
        .len();
    let expected_len =
        STREAM_MAGIC_LEN as u64 + 8 + num_chunks * (4 + NONCE_LEN as u64 + sealer.tag_len() as u64) + total_len;
    if actual_len != expected_len {
        bail!(
            "incomplete sealing: {} ended up at {actual_len} bytes, expected {expected_len} \
             (not uploaded)",
            sealed_path.display()
        );
    }
    Ok(())
}

/// Reverses [`seal_stream`]. Fails the same ways [`crate::Cipher::open`]
/// does (wrong key, tampered content), plus explicitly on:
/// - a missing/wrong [`STREAM_MAGIC`] (not a stream blob at all, or a plain
///   [`crate::Cipher::seal`]-format one);
/// - a truncated stream (fewer than the header's declared chunk count, or
///   a chunk frame cut off mid-way) — reaching EOF early always surfaces
///   as an error here, never a silently-short output file;
/// - a reordered chunk (each chunk's AAD binds its own index, so a chunk
///   read at position `idx` that was actually sealed at a different index
///   fails to decrypt);
/// - trailing bytes after the last expected chunk (an appended/duplicated
///   chunk) — checked explicitly once the expected chunk count has been
///   read.
pub(crate) async fn open_stream(cipher: &Cipher, aad: &str, sealed_path: &Path, plaintext_path: &Path) -> Result<()> {
    let mut input = tokio::fs::File::open(sealed_path)
        .await
        .with_context(|| format!("opening {}", sealed_path.display()))?;
    let mut output = tokio::fs::File::create(plaintext_path)
        .await
        .with_context(|| format!("creating {}", plaintext_path.display()))?;

    let mut magic = [0u8; STREAM_MAGIC_LEN];
    input
        .read_exact(&mut magic)
        .await
        .context("invalid ciphertext (not an s3db stream, incomplete header)")?;
    if &magic[..STREAM_MAGIC_PREFIX.len()] != STREAM_MAGIC_PREFIX.as_slice() {
        bail!("invalid ciphertext (not an s3db stream)");
    }
    let sealer = sealer_from_magic(&magic)?;
    // Fail on a mode mismatch before reading a single chunk, so the error
    // names the real problem instead of surfacing as a decrypt failure.
    cipher.accept(sealer)?;
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

        let mut ciphertext = vec![0u8; ciphertext_len];
        input
            .read_exact(&mut ciphertext)
            .await
            .with_context(|| format!("truncated ciphertext (chunk {idx} of {num_chunks})"))?;

        let chunk_aad = format!("{aad}\0stream\0{total_len}\0{idx}");
        let plain = cipher
            .open_chunk(sealer, &nonce_bytes, &ciphertext, chunk_aad.as_bytes())
            .context("couldn't decrypt (wrong passphrase, out-of-order chunk, or the data was modified)")?;

        // Belt-and-suspenders: every chunk but the last must be exactly
        // STREAM_CHUNK_LEN, the last exactly whatever's left. A chunk that
        // decrypts validly but at the wrong length would mean `seal_stream`
        // itself framed it inconsistently with the declared total_len —
        // this can't happen from tampering alone (the AEAD tag already
        // ties the ciphertext to this exact plaintext), but it's a cheap,
        // direct check on the one invariant this whole scheme depends on.
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

    // No trailing bytes allowed after the declared final chunk — catches an
    // appended/duplicated extra chunk.
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

    // Belt-and-suspenders, mirroring `seal_stream`'s own post-write check:
    // every `plain.len()` above was already verified against `total_len`'s
    // accounting before being handed to `write_all`, but that only proves
    // the bytes handed to the writer were correct — not that they actually
    // landed on `plaintext_path`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SALT_LEN;

    fn test_cipher() -> Cipher {
        Cipher::derive("correct horse battery staple", &[7u8; SALT_LEN]).unwrap()
    }

    /// Splits a `seal_stream`-produced file into `(total_len, chunk_frames)`
    /// — each frame is the raw `[len][nonce][ciphertext]` bytes, kept whole
    /// so the reorder/truncate/duplicate tests below can shuffle them
    /// without needing to understand anything past the frame boundary.
    async fn read_stream_chunks(path: &std::path::Path) -> ([u8; STREAM_MAGIC_LEN], u64, Vec<Vec<u8>>) {
        let bytes = tokio::fs::read(path).await.unwrap();
        let magic: [u8; STREAM_MAGIC_LEN] = bytes[..STREAM_MAGIC_LEN].try_into().unwrap();
        assert_eq!(&magic[..STREAM_MAGIC_PREFIX.len()], STREAM_MAGIC_PREFIX.as_slice());
        let total_len = u64::from_le_bytes(bytes[STREAM_MAGIC_LEN..STREAM_MAGIC_LEN + 8].try_into().unwrap());
        let mut chunks = Vec::new();
        let mut pos = STREAM_MAGIC_LEN + 8;
        while pos < bytes.len() {
            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            let frame_len = 4 + NONCE_LEN + len;
            chunks.push(bytes[pos..pos + frame_len].to_vec());
            pos += frame_len;
        }
        (magic, total_len, chunks)
    }

    async fn write_stream_file(
        path: &std::path::Path,
        magic: &[u8; STREAM_MAGIC_LEN],
        total_len: u64,
        chunks: &[Vec<u8>],
    ) {
        let mut out = Vec::new();
        out.extend_from_slice(magic);
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
                assert_eq!(
                    opened, plain,
                    "task {n} len {len}: claimed success but content is wrong"
                );
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
        for &len in &[
            0usize,
            1,
            STREAM_CHUNK_LEN,
            STREAM_CHUNK_LEN + 1,
            STREAM_CHUNK_LEN * 2 + 100,
        ] {
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

    fn test_cipher_with(algorithm: CipherAlgorithm) -> Cipher {
        Cipher::derive_with("correct horse battery staple", &[7u8; SALT_LEN], algorithm).unwrap()
    }

    /// Same guarantee the small-object format gives: the magic records which
    /// algorithm sealed a stream, so a reader that seals with a different one
    /// still opens it. Without this, changing the default would strand every
    /// large blob already in the bucket.
    #[tokio::test]
    async fn every_algorithm_roundtrips_and_any_cipher_opens_it() {
        for sealer_algorithm in CipherAlgorithm::ALL {
            let dir = tempfile::tempdir().unwrap();
            let plain_path = dir.path().join("plain");
            let sealed_path = dir.path().join("sealed");
            let plain = vec![0x5Au8; STREAM_CHUNK_LEN + 10]; // 2 chunks
            tokio::fs::write(&plain_path, &plain).await.unwrap();
            test_cipher_with(sealer_algorithm)
                .seal_stream("repo/pack", &plain_path, &sealed_path)
                .await
                .unwrap();

            let (magic, _, _) = read_stream_chunks(&sealed_path).await;
            assert_eq!(
                magic[STREAM_MAGIC_PREFIX.len()],
                magic_suffix(Sealer::Algorithm(sealer_algorithm))
            );

            for reader_algorithm in CipherAlgorithm::ALL {
                let opened_path = dir.path().join(format!("opened-{reader_algorithm:?}"));
                test_cipher_with(reader_algorithm)
                    .open_stream("repo/pack", &sealed_path, &opened_path)
                    .await
                    .unwrap();
                assert_eq!(tokio::fs::read(&opened_path).await.unwrap(), plain);
            }
        }
    }

    #[tokio::test]
    async fn a_disabled_cipher_streams_plaintext_and_refuses_encrypted_streams() {
        let dir = tempfile::tempdir().unwrap();
        let plain_path = dir.path().join("plain");
        let sealed_path = dir.path().join("sealed");
        let opened_path = dir.path().join("opened");
        let plain = vec![0x7Bu8; STREAM_CHUNK_LEN + 10]; // 2 chunks
        tokio::fs::write(&plain_path, &plain).await.unwrap();

        let disabled = Cipher::disabled();
        disabled
            .seal_stream("repo/pack", &plain_path, &sealed_path)
            .await
            .unwrap();
        disabled
            .open_stream("repo/pack", &sealed_path, &opened_path)
            .await
            .unwrap();
        assert_eq!(tokio::fs::read(&opened_path).await.unwrap(), plain);

        // Both directions of the downgrade guard, on the stream format too.
        let err = test_cipher()
            .open_stream("repo/pack", &sealed_path, &opened_path)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("encryption enabled"), "got: {err}");

        let encrypted_path = dir.path().join("encrypted");
        test_cipher()
            .seal_stream("repo/pack", &plain_path, &encrypted_path)
            .await
            .unwrap();
        let err = disabled
            .open_stream("repo/pack", &encrypted_path, &opened_path)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("encryption disabled"), "got: {err}");
    }

    #[tokio::test]
    async fn stream_rejects_an_unknown_algorithm_in_the_magic() {
        let c = test_cipher();
        let dir = tempfile::tempdir().unwrap();
        let plain_path = dir.path().join("plain");
        let sealed_path = dir.path().join("sealed");
        let opened_path = dir.path().join("opened");
        tokio::fs::write(&plain_path, b"test content").await.unwrap();
        c.seal_stream("repo/pack", &plain_path, &sealed_path).await.unwrap();

        let (mut magic, total_len, chunks) = read_stream_chunks(&sealed_path).await;
        magic[STREAM_MAGIC_PREFIX.len()] = b'9'; // sealed by a version this build doesn't have
        write_stream_file(&sealed_path, &magic, total_len, &chunks).await;

        let err = c
            .open_stream("repo/pack", &sealed_path, &opened_path)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown cipher algorithm"), "got: {err}");
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

        let (magic, total_len, mut chunks) = read_stream_chunks(&sealed_path).await;
        assert_eq!(chunks.len(), 3);
        chunks.swap(0, 1);
        write_stream_file(&sealed_path, &magic, total_len, &chunks).await;

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

        let (magic, total_len, mut chunks) = read_stream_chunks(&sealed_path).await;
        chunks.pop(); // drop the real last chunk
        write_stream_file(&sealed_path, &magic, total_len, &chunks).await;

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

        let (magic, total_len, mut chunks) = read_stream_chunks(&sealed_path).await;
        let last = chunks.last().unwrap().clone();
        chunks.push(last); // append a duplicate of the legitimate last chunk
        write_stream_file(&sealed_path, &magic, total_len, &chunks).await;

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
        let legacy = c.seal("repo/pack", b"test content", crate::CompressionStrategy::None);
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
        assert!(
            other
                .open_stream("repo-a/pack", &sealed_path, &opened_path)
                .await
                .is_err()
        );
    }
}
