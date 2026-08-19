use super::*;

#[test]
fn a_segment_accepts_an_ordinary_name() {
    for name in ["alice", "user-42", "a.b.c", "Ünïcödé", "with space", "a:b+c"] {
        assert!(
            validate_segment(name, "entity name").is_ok(),
            "{name:?} should be accepted"
        );
    }
}

#[test]
fn a_segment_rejects_anything_that_would_escape_its_namespace() {
    for name in ["", "a/b", "..", ".", ".history", ".deleted/x", "a\\b", "a\nb", "a\0b"] {
        assert!(
            validate_segment(name, "entity name").is_err(),
            "{name:?} should be rejected"
        );
    }
}

/// A hierarchical collection name is a supported layout (see
/// `Collection::new_with_suffix`), so `/` has to keep working here even
/// though `validate_segment` rejects it.
#[test]
fn a_path_accepts_a_hierarchical_name() {
    for name in ["alice", "acme/web", "a/b/c", "acme/web-2.0"] {
        assert!(
            validate_path(name, "entity name").is_ok(),
            "{name:?} should be accepted"
        );
    }
}

#[test]
fn a_path_rejects_a_component_that_would_reach_a_reserved_namespace() {
    for name in [
        "",
        "a/.deleted/b",
        "a/.history",
        "../elsewhere",
        "a/../b",
        "a//b",
        "/leading",
        "trailing/",
        "a/b\\c",
        "a/b\nc",
    ] {
        assert!(
            validate_path(name, "entity name").is_err(),
            "{name:?} should be rejected"
        );
    }
}

#[test]
fn the_error_names_what_was_being_validated() {
    let err = validate_segment("a/b", "index segment").unwrap_err().to_string();
    assert!(err.contains("index segment"), "{err}");
}
