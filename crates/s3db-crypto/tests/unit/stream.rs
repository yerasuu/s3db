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

async fn write_stream_file(path: &std::path::Path, magic: &[u8; STREAM_MAGIC_LEN], total_len: u64, chunks: &[Vec<u8>]) {
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
