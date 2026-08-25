//! Time-to-live for [`Collection`] entries.
//!
//! Object storage providers all offer lifecycle rules, but those are console
//! configuration on a bucket, invisible to the code that decided the data
//! should expire and unavailable at all on a plain local directory. This is
//! the same idea inside the crate, working identically on every driver.
//!
//! **Expiry is a deletion, not a hiding.** [`Collection::get`] is not going to
//! consult a second object on every read to find out whether this one has
//! expired — the same call that [`crate::collection::Tombstone`] already
//! documents for soft deletes, for the same reason: doubling every read's cost
//! forever to serve a sweep that runs on a timer anyway. So the guarantee is
//! "gone shortly after it expires", and a caller that needs the instant to be
//! exact reads [`expiry_of`] itself and decides.
//!
//! **The deadline lives in the key.** A due marker is
//! `<prefix>/.expiry/<expires-at as an ordinal>/<name>.json`, so
//! [`Backend::list_page`]'s ascending key order *is* time order:
//! [`expire_due`] pages until the first deadline in the future and stops,
//! having read no object at all to find out which entries were due. Storing
//! the deadline inside the marker instead would mean fetching every pending
//! marker on every sweep just to discard most of them.
//!
//! A second, reverse marker at `<prefix>/.expiry-at/<name>.json` records one
//! entry's current deadline, so [`expiry_of`] and [`clear_expiry`] are
//! single-key operations rather than a scan, and so a re-scheduled expiry can
//! find and drop the deadline it replaces.

use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use crate::collection::Collection;
use crate::naming::validate_path;
use crate::ordinal;
use crate::payload::{delete_object, get_json, put_json};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Due markers examined per page. They carry no body, so a page is pure key
/// listing.
const EXPIRY_PAGE: usize = 500;

/// Reserved `expires_at_ms` no real deadline is ever set to (see
/// [`set_expiry`]/[`set_ttl`], both derived from a real clock reading).
/// [`expire_due`] CAS-writes the reverse marker to this value, under the
/// etag it just read, before deleting anything -- seeing `Cas::Ok` back is
/// the only way it can know nothing else (a concurrent [`set_expiry`] or
/// [`clear_expiry`]) touched that marker since. [`Backend`] has no
/// conditional *delete*, only a conditional write, so this is what turns
/// "read, then three unconditioned deletes" into something that can't
/// destroy a renewal that raced it -- but only because [`set_expiry`]'s own
/// retry loop refuses to write straight over this value: without that,
/// a rename racing just after the claim lands would win its retry, and
/// `expire_due` would still delete the entry and then wipe out the
/// "successful" rename along with it.
const CLAIMED_FOR_PURGE_MS: u64 = u64::MAX;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

/// One entry's current deadline, at `<prefix>/.expiry-at/<name>.json`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpiryAt {
    pub expires_at_ms: u64,
}

/// How [`expire_due`] removes an expired entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExpiryConfig {
    /// `true` routes the removal through [`Collection::delete`], so the entry
    /// leaves a tombstone and an archived version and stays restorable.
    ///
    /// Off by default, unlike everywhere else in this crate that deletes:
    /// a TTL exists to reclaim space, and archiving the value it was told to
    /// get rid of reclaims none of it. Turn it on for data whose expiry is a
    /// retention policy rather than a cleanup.
    pub soft: bool,
}

/// What one [`expire_due`] sweep did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExpiryReport {
    /// Entries removed.
    pub expired: u64,
    /// Due markers dropped without removing anything: the entry had been
    /// re-scheduled to a later deadline, or was already gone.
    pub stale_markers: u64,
}

fn due_prefix(collection: &Collection) -> String {
    format!("{}/.expiry/", collection.prefix)
}

fn due_key(collection: &Collection, name: &str, expires_at_ms: u64) -> Result<String> {
    validate_path(name, "entity name")?;
    Ok(format!(
        "{}{}/{name}.json",
        due_prefix(collection),
        ordinal::encode_u64(expires_at_ms)
    ))
}

fn expiry_at_key(collection: &Collection, name: &str) -> Result<String> {
    validate_path(name, "entity name")?;
    Ok(format!("{}/.expiry-at/{name}.json", collection.prefix))
}

/// Schedules `name` for removal at or after `expires_at_ms`.
///
/// Re-scheduling is supported: the deadline this replaces is dropped, so an
/// entry never has two live due markers. Nothing here reads or touches the
/// entry itself, so scheduling an expiry for a name that doesn't exist yet is
/// allowed — [`expire_due`] will simply find nothing to remove.
pub async fn set_expiry(
    backend: &dyn Backend,
    cipher: &Cipher,
    collection: &Collection,
    name: &str,
    expires_at_ms: u64,
) -> Result<()> {
    let reverse_key = expiry_at_key(collection, name)?;

    // New due marker first: if this process dies before the reverse marker
    // below lands, the worst case is a superseded marker that the sweep
    // recognizes as stale, never an entry whose expiry was forgotten. Its
    // content is fixed (`()`), so a `Cas::Conflict` here just means an
    // earlier, otherwise-identical attempt (this call's own retry below, or
    // a resolved race) already created it -- fine either way.
    put_json(backend, &due_key(collection, name, expires_at_ms)?, &(), None, cipher).await?;

    let (mut previous_value, mut reverse_etag) = get_json::<ExpiryAt>(backend, &reverse_key, cipher).await?;
    // CAS-with-reread, not a single blind attempt: a `Cas::Conflict` means a
    // concurrent `set_expiry`/`clear_expiry` (or `expire_due`'s own claim,
    // see `CLAIMED_FOR_PURGE_MS`) changed this name's reverse marker since
    // the read above. Silently returning `Ok(())` on that (as this used to)
    // would leave the caller believing its deadline is now live when the
    // real one is whoever else's won.
    for _ in 0..3 {
        // `expire_due` has already committed to deleting this entry and is
        // partway through doing so -- writing over the sentinel (whether
        // that's this call's very first attempt, or a retry after losing a
        // CAS to it) would make this call report `Ok(())` for a reschedule
        // that the sweep's still-in-flight deletes are about to undo anyway,
        // exactly the false success this marker exists to prevent (see
        // `CLAIMED_FOR_PURGE_MS`'s own doc). The caller finds out now,
        // honestly, instead of later discovering the entry is gone despite
        // this "success".
        if previous_value.expires_at_ms == CLAIMED_FOR_PURGE_MS {
            anyhow::bail!("{name}: an expiry sweep is currently purging this entry; retry once it's gone");
        }
        match put_json(
            backend,
            &reverse_key,
            &ExpiryAt { expires_at_ms },
            reverse_etag.as_deref(),
            cipher,
        )
        .await?
        {
            Cas::Ok => {
                if reverse_etag.is_some() && previous_value.expires_at_ms != expires_at_ms {
                    delete_object(backend, &due_key(collection, name, previous_value.expires_at_ms)?).await;
                }
                return Ok(());
            }
            Cas::Conflict => {
                let (fresh_value, fresh_etag) = get_json::<ExpiryAt>(backend, &reverse_key, cipher).await?;
                previous_value = fresh_value;
                reverse_etag = fresh_etag;
            }
        }
    }
    anyhow::bail!("{name}: lost the race to set its expiry to {expires_at_ms}ms too many times, try again")
}

/// Convenience over [`set_expiry`]: a deadline `ttl_ms` from now.
pub async fn set_ttl(
    backend: &dyn Backend,
    cipher: &Cipher,
    collection: &Collection,
    name: &str,
    ttl_ms: u64,
) -> Result<()> {
    set_expiry(backend, cipher, collection, name, now_ms().saturating_add(ttl_ms)).await
}

/// `name`'s current deadline, or `None` if it has none. One `get`.
pub async fn expiry_of(
    backend: &dyn Backend,
    cipher: &Cipher,
    collection: &Collection,
    name: &str,
) -> Result<Option<u64>> {
    let (value, etag) = get_json::<ExpiryAt>(backend, &expiry_at_key(collection, name)?, cipher).await?;
    Ok(etag.is_some().then_some(value.expires_at_ms))
}

/// Cancels `name`'s expiry, if it has one. Idempotent.
pub async fn clear_expiry(backend: &dyn Backend, cipher: &Cipher, collection: &Collection, name: &str) -> Result<()> {
    let reverse_key = expiry_at_key(collection, name)?;
    let (current, etag) = get_json::<ExpiryAt>(backend, &reverse_key, cipher).await?;
    if etag.is_none() {
        return Ok(());
    }
    delete_object(backend, &due_key(collection, name, current.expires_at_ms)?).await;
    delete_object(backend, &reverse_key).await;
    Ok(())
}

/// Removes every entry whose deadline has passed, and clears their markers.
///
/// Stops at the first deadline still in the future: due markers are keyed by
/// deadline, so ascending key order is chronological and everything past that
/// point is by definition not due.
///
/// A due marker whose entry has since been re-scheduled to a later deadline —
/// or removed by other means — is dropped without touching the entry, and
/// counted in [`ExpiryReport::stale_markers`]. That check is what makes
/// re-scheduling safe: the reverse marker, not the due marker, is the
/// authority on when an entry expires.
pub async fn expire_due(
    backend: &dyn Backend,
    cipher: &Cipher,
    collection: &Collection,
    now: u64,
    config: &ExpiryConfig,
) -> Result<ExpiryReport> {
    let prefix = due_prefix(collection);
    let mut report = ExpiryReport::default();
    let mut after: Option<String> = None;
    'pages: loop {
        let page = backend.list_page(&prefix, after.as_deref(), EXPIRY_PAGE).await?;
        if page.entries.is_empty() {
            return Ok(report);
        }
        for (key, _size) in &page.entries {
            let Some((deadline, name)) = parse_due_key(key, &prefix) else {
                // A key under `.expiry/` this module didn't write. Left alone
                // rather than guessed at: deleting an object whose layout
                // isn't understood is not a cleanup, it's data loss.
                continue;
            };
            if deadline > now {
                break 'pages;
            }
            let reverse_key = expiry_at_key(collection, &name)?;
            let (current, etag) = get_json::<ExpiryAt>(backend, &reverse_key, cipher).await?;
            if etag.is_none() || current.expires_at_ms != deadline {
                // The reverse marker disagrees (re-scheduled, cleared, or
                // never existed) -- this due marker is stale, and nothing
                // else here has been touched, so there's nothing to race.
                delete_object(backend, key).await;
                report.stale_markers += 1;
                continue;
            }
            // Claim the reverse marker before deleting anything: a `Backend`
            // has no conditional delete, only a conditional write, so this
            // CAS (against the exact etag just read) is what stands in for
            // one. `Cas::Ok` means nothing else touched it in between --
            // only then is it safe to actually delete the entry. `Conflict`
            // means a concurrent `set_expiry`/`clear_expiry` won the race
            // since the read above; treat this due marker as stale instead
            // of deleting an entry whose real, current deadline just moved.
            let claim = put_json(
                backend,
                &reverse_key,
                &ExpiryAt {
                    expires_at_ms: CLAIMED_FOR_PURGE_MS,
                },
                etag.as_deref(),
                cipher,
            )
            .await?;
            if claim == Cas::Conflict {
                delete_object(backend, key).await;
                report.stale_markers += 1;
                continue;
            }
            if config.soft {
                collection.delete(backend, cipher, &name).await?;
            } else {
                delete_object(backend, &collection.key(&name)?).await;
            }
            delete_object(backend, &reverse_key).await;
            delete_object(backend, key).await;
            report.expired += 1;
        }
        match page.next_after {
            Some(next) => after = Some(next),
            None => return Ok(report),
        }
    }
    Ok(report)
}

/// `(deadline, entry name)` from a due marker's key, or `None` if the key
/// isn't one this module wrote.
fn parse_due_key(key: &str, prefix: &str) -> Option<(u64, String)> {
    let rest = key.strip_prefix(prefix)?;
    let (bucket, name_and_suffix) = rest.split_once('/')?;
    let deadline = ordinal::decode_u64(bucket)?;
    let name = name_and_suffix.strip_suffix(".json")?;
    Some((deadline, name.to_string()))
}

#[cfg(test)]
#[path = "../tests/unit/ttl.rs"]
mod tests;
