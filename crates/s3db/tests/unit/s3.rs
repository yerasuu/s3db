//! The one thing in this driver that can be checked without a live
//! endpoint: whether it refuses to carry credentials over cleartext.

use super::*;
use crate::config::S3Params;

fn params(endpoint: Option<&str>, allow_insecure_http: bool) -> S3Params {
    S3Params {
        bucket: "b".to_string(),
        region: Some("us-east-1".to_string()),
        endpoint_url: endpoint.map(str::to_string),
        access_key_id: "AKIA".to_string(),
        secret_access_key: "s3cret".to_string().into(),
        path_style: true,
        allow_insecure_http,
    }
}

#[test]
fn a_plain_http_endpoint_is_refused_whatever_case_its_scheme_is_in() {
    for endpoint in ["http://minio:9000", "HTTP://minio:9000", "HtTp://minio:9000"] {
        let err = S3Backend::new(&params(Some(endpoint), false))
            .err()
            .unwrap_or_else(|| panic!("{endpoint} should have been refused"));
        assert!(err.to_string().contains("cleartext"), "{err}");
    }
}

#[test]
fn https_and_an_explicit_opt_in_are_both_accepted() {
    assert!(S3Backend::new(&params(Some("https://minio:9000"), false)).is_ok());
    assert!(S3Backend::new(&params(Some("HTTPS://minio:9000"), false)).is_ok());
    // The escape hatch still works -- a dev MinIO with no TLS in front.
    assert!(S3Backend::new(&params(Some("http://minio:9000"), true)).is_ok());
    // No endpoint at all is real S3, always TLS.
    assert!(S3Backend::new(&params(None, false)).is_ok());
}
