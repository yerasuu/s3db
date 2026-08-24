use super::*;

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Widget {
    count: u32,
}

#[tokio::test]
async fn load_many_reports_found_and_missing_keys_distinctly() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(crate::local::test_support::files_backend(dir.path()));
    let cipher = Arc::new(Cipher::derive("test passphrase", &[53u8; crate::cipher::SALT_LEN]).unwrap());
    crate::payload::put_json(backend.as_ref(), "a.json", &Widget { count: 1 }, None, &cipher)
        .await
        .unwrap();

    let loader = BatchLoader::new(MemoryBudget::default());
    let results = loader
        .load_many::<Widget>(&backend, &cipher, ["a.json".to_string(), "missing.json".to_string()])
        .await;

    assert_eq!(
        results.get("a.json").unwrap().as_ref().unwrap(),
        &Some(Widget { count: 1 })
    );
    assert_eq!(results.get("missing.json").unwrap().as_ref().unwrap(), &None);
}

#[test]
fn memory_budget_derives_concurrency_from_object_size_cap() {
    let budget = MemoryBudget {
        max_buffer_bytes: MAX_OBJECT_BYTES * 10,
    };
    assert_eq!(budget.max_concurrency(), 10);
    // Never zero, even for a tiny budget -- one in flight at a time
    // beats refusing to load anything at all.
    assert_eq!(MemoryBudget { max_buffer_bytes: 1 }.max_concurrency(), 1);
}
