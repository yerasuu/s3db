//! Fails the build of a version that has no release notes: `tag-changelog/v<version>.md` at the
//! workspace root is written before the version bump, so a bump without it stops here.

use std::path::Path;

fn main() {
    let version = std::env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let notes = Path::new(&manifest_dir)
        .join("../../tag-changelog")
        .join(format!("v{version}.md"));
    println!("cargo::rerun-if-changed={}", notes.display());
    assert!(
        notes.is_file(),
        "no release notes for {version}: write tag-changelog/v{version}.md before bumping the workspace version"
    );
}
