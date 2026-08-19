//! The one place that decides whether a caller-supplied name is safe to
//! interpolate into an object key.
//!
//! Every durable key in this crate is built by `format!`-ing a
//! caller-controlled name into a fixed layout --
//! `{prefix}/{name}{suffix}`, `{prefix}/.history/{name}/...`,
//! `{root}/{kind}/{segment}.json`. Without a check here, a name carrying
//! the right characters doesn't just produce an odd-looking key: it
//! *relocates* the object into a sibling namespace. `name =
//! "x/.deleted/y"` lands exactly where
//! [`crate::collection::Collection::tombstone_key`] would have put a
//! tombstone, and [`crate::collection::Collection::list_names`] already
//! filters `.history/`/`.deleted/`/`.created/` out of its listing precisely
//! because those namespaces are supposed to be unreachable by name.
//!
//! [`crate::lsm::secondary_index`] has enforced the equivalent invariant on
//! its own composite keys (`ensure_no_separator`) from the start; this is
//! that same discipline applied to the object-key layer, which had been
//! documenting the requirement without checking it.
//!
//! Two rules, not one, because the two layers genuinely differ:
//! [`validate_segment`] is for a name that must stay a *single* path
//! component, and [`validate_path`] is for one that's allowed to be several
//! (see its own doc for why a `/` has to keep working there).

use anyhow::{Result, bail};

/// Rejects a name that wouldn't stay a single, self-contained path
/// component once interpolated into an object key. `what` names the kind of
/// thing being validated (`"entity name"`, `"index segment"`) so the error
/// speaks the caller's vocabulary rather than this module's.
pub(crate) fn validate_segment(raw: &str, what: &str) -> Result<()> {
    if raw.is_empty() {
        bail!("invalid {what}: must not be empty");
    }
    if let Some(bad) = raw.chars().find(|&c| c == '/' || c == '\\' || c.is_control()) {
        bail!(
            "invalid {what} {raw:?}: must not contain {bad:?} (it would split the object key into another namespace)"
        );
    }
    // `.` and `..` are only meaningful to a filesystem, but the `local`
    // driver *is* one, and its own `validate_key` rejects `..` at the
    // backend boundary -- catching it here instead means every driver
    // behaves the same way rather than one of them failing later than the
    // rest.
    if raw == "." || raw == ".." {
        bail!("invalid {what} {raw:?}: must not be a filesystem relative-path component");
    }
    // A leading `.` is how this crate marks its own reserved namespaces
    // (`.history/`, `.deleted/`, `.created/`, `.conf/`), so a name is not
    // allowed to start one. This is the check that actually closes the
    // namespace-escape hole: every reserved namespace begins with a `.`,
    // so a name that can't start one can't reach any of them.
    if raw.starts_with('.') {
        bail!("invalid {what} {raw:?}: a leading \".\" is reserved for this crate's own namespaces");
    }
    Ok(())
}

/// Same rules as [`validate_segment`], applied to every `/`-separated
/// component of `raw` rather than to `raw` as a whole.
///
/// A [`crate::collection::Collection`] name is deliberately allowed to be
/// hierarchical: `Collection::new_with_suffix("repos", "/.conf/config.json")`
/// with `name = "acme/web"` is a supported layout (an entity whose object
/// lives nested under its own storage prefix), so a blanket ban on `/`
/// would break a real, documented use rather than close a hole.
///
/// Validating component-wise keeps everything that matters: an empty
/// component (`a//b`, a leading or trailing `/`), a `.`/`..` component, and
/// a component starting with `.` are all still rejected, so `"a/.deleted/b"`
/// and `"../elsewhere"` cannot reach a reserved namespace or climb out of
/// the collection -- while `"acme/web"` stays exactly as valid as it was.
pub(crate) fn validate_path(raw: &str, what: &str) -> Result<()> {
    if raw.is_empty() {
        bail!("invalid {what}: must not be empty");
    }
    for component in raw.split('/') {
        if component.is_empty() {
            bail!("invalid {what} {raw:?}: has an empty path component (a leading, trailing, or doubled \"/\")");
        }
        validate_segment(component, what)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/naming.rs"]
mod tests;
