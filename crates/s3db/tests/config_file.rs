//! Loads this crate's whole configuration surface out of one TOML document, the
//! way an application's own config file does.
//!
//! `BackendConfig` has always been `Deserialize`; the tuning types
//! (`ResilienceConfig`, `CacheConfig`, `GcConfig`, `ExpiryConfig`,
//! `LsmMaintenanceConfig`, `MemoryBudget`) and the crypto policy enums were not,
//! so a caller reading them from a file had to hand-map every field of types it
//! did not define — and silently drift when one changed. These tests are the
//! guarantee that a config file keeps working.

use s3db::{
    BackendConfig, CacheConfig, CipherAlgorithm, EncryptionMode, ExpiryConfig, GcConfig, LsmMaintenanceConfig,
    MemoryBudget, ResilienceConfig,
};

#[derive(Debug, serde::Deserialize)]
struct AppConfig {
    #[serde(flatten)]
    backend: BackendConfig,
    #[serde(default)]
    resilience: ResilienceConfig,
    #[serde(default)]
    gc: GcConfig,
    #[serde(default)]
    expiry: ExpiryConfig,
    #[serde(default)]
    lsm: LsmMaintenanceConfig,
    #[serde(default)]
    budget: MemoryBudget,
    encryption: EncryptionMode,
}

#[test]
fn a_full_config_document_round_trips_into_typed_values() {
    let text = r#"
driver = "s3"
bucket = "novels"
region = "eu-west-1"
endpoint_url = "https://example.invalid"
access_key_id = "AK"
secret_access_key = "SK"
path_style = true

[encryption]
mode = "enabled"
algorithm = "aes256_gcm"

[resilience]
max_concurrent_get = 128
base_backoff = 250

[resilience.cache]
max_entries = 500
ttl = 5000

[gc]
tombstone_retry_age = 30000
history_max_age = 86400000

[expiry]
soft = true

[lsm]
flush_even_if_small = true

[budget]
max_buffer_bytes = 1048576
"#;

    let config: AppConfig = toml::from_str(text).expect("the whole surface must parse");

    match config.backend {
        BackendConfig::S3(params) => {
            assert_eq!(params.bucket, "novels");
            assert!(params.path_style);
        }
        other => panic!("expected the s3 driver, got {other:?}"),
    }
    assert_eq!(
        config.encryption,
        EncryptionMode::Enabled {
            algorithm: CipherAlgorithm::Aes256Gcm
        }
    );
    assert_eq!(config.resilience.max_concurrent_get, 128);
    assert_eq!(
        config.resilience.base_backoff,
        std::time::Duration::from_millis(250),
        "durations are milliseconds, not serde's {{ secs, nanos }}"
    );
    assert_eq!(config.resilience.cache.max_entries, 500);
    assert_eq!(config.gc.tombstone_retry_age, std::time::Duration::from_secs(30));
    assert_eq!(config.gc.history_max_age, Some(std::time::Duration::from_secs(86_400)));
    assert!(config.expiry.soft);
    assert!(config.lsm.flush_even_if_small);
    assert_eq!(config.budget.max_buffer_bytes, 1_048_576);
}

/// Whatever a config omits comes from `Default`, so a real file only ever
/// spells out what it actually changes.
#[test]
fn omitted_sections_and_fields_fall_back_to_defaults() {
    let text = r#"
driver = "local"
bucket = "/srv/bucket"

[encryption]
mode = "enabled"

[resilience]
max_retries = 9
"#;

    let config: AppConfig = toml::from_str(text).unwrap();

    assert_eq!(config.resilience.max_retries, 9);
    assert_eq!(
        config.resilience.max_concurrent_get,
        ResilienceConfig::default().max_concurrent_get,
        "an omitted field keeps its default"
    );
    assert_eq!(config.resilience.cache.ttl, CacheConfig::default().ttl);
    assert_eq!(config.gc.tombstone_purge_age, GcConfig::default().tombstone_purge_age);
    assert_eq!(config.lsm, LsmMaintenanceConfig::default());
    assert_eq!(
        config.encryption,
        EncryptionMode::Enabled {
            algorithm: CipherAlgorithm::default()
        },
        "an omitted algorithm is the default one, not an error"
    );
}

/// Turning encryption off has to be spelled out, and has to survive a round
/// trip — a config that silently read as `Disabled` would be a catastrophe.
#[test]
fn encryption_disabled_is_explicit_in_both_directions() {
    let text = r#"
driver = "local"
bucket = "/srv/bucket"

[encryption]
mode = "disabled"
"#;
    let config: AppConfig = toml::from_str(text).unwrap();
    assert_eq!(config.encryption, EncryptionMode::Disabled);

    let rendered = toml::to_string(&EncryptionMode::Enabled {
        algorithm: CipherAlgorithm::XChaCha20Poly1305,
    })
    .unwrap();
    assert!(rendered.contains("mode = \"enabled\""), "{rendered}");
    assert!(rendered.contains("algorithm = \"x_cha_cha20_poly1305\""), "{rendered}");
}

#[test]
fn an_unknown_driver_is_a_clear_error_not_a_silent_default() {
    let text = r#"
driver = "postgres"
bucket = "novels"

[encryption]
mode = "enabled"
"#;
    let err = toml::from_str::<AppConfig>(text).unwrap_err().to_string();
    assert!(err.contains("postgres") || err.contains("variant"), "{err}");
}
