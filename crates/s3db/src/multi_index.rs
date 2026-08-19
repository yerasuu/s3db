//! A one-to-many index: `value -> every member that has it`.
//!
//! [`crate::SecondaryIndex`] answers "which entity has this unique value" —
//! one pointer per value, `claim_once` enforcing that only one entity can
//! hold it. A field that isn't unique needs the other shape: every chapter in
//! a volume, every work carrying a genre, every job in a state. There was no
//! way to express that in the `Collection` model at all, only in the `lsm`
//! engine (`SecondaryLsmIndex`), which a caller on S3 can't reach.
//!
//! **Membership lives in the key, not in a value.** One object per
//! `(value, member)` pair:
//!
//! ```text
//! <root>/<kind>/<encoded value>/<member>.json
//! ```
//!
//! The obvious alternative — one object per value holding a list of members —
//! is worse in all three ways that matter here. It grows past
//! [`crate::MAX_OBJECT_BYTES`] on the first value with a few thousand
//! members; every add and remove serializes on one key, so a crawler writing
//! chapters would spend its life losing CAS races; and it can't be read
//! without fetching and decrypting the whole list. With the member in the
//! key, adds are independent writes, size is unbounded, and
//! [`MultiIndex::members`] answers from a listing alone — no object is read,
//! nothing is decrypted, because the answer was already in the key names.
//!
//! The per-entry payload is therefore optional in spirit: pass `&()` when the
//! member name is the whole answer, or a small denormalized struct when a
//! reader would otherwise have to fetch each member's entity just to display
//! a list (the same trade [`crate::SecondaryIndex::claim_inline`] makes,
//! with the same obligation to keep it fresh).

use crate::backend::{Backend, Cas};
use crate::batch_loader::{BatchLoader, MemoryBudget};
use crate::cipher::Cipher;
use crate::index::Segment;
use crate::naming::validate_path;
use crate::payload::{SweepReport, delete_object, delete_prefix, get_json, put_json};
use anyhow::{Result, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::borrow::Cow;
use std::sync::Arc;

/// Members per page while listing. Membership keys are small and a caller
/// asking for "every member of this value" wants them all, so this is about
/// bounding one request's response, not the answer.
const MEMBER_PAGE: usize = 1000;

/// How many times [`MultiIndex::add`] retries a lost CAS race before giving
/// up. Two writers adding the *same* member to the same value is the only
/// way to collide here (different members are different keys), and both want
/// the same end state, so one retry past the initial create is already
/// generous.
const MAX_ADD_ATTEMPTS: u32 = 3;

/// A one-to-many index — see the module doc for the key layout and why
/// membership lives in the key.
#[derive(Debug, Clone)]
pub struct MultiIndex {
    pub root: Cow<'static, str>,
    pub kind: Cow<'static, str>,
    pub segment: Segment,
}

impl MultiIndex {
    pub const fn new(root: &'static str, kind: &'static str, segment: Segment) -> Self {
        MultiIndex {
            root: Cow::Borrowed(root),
            kind: Cow::Borrowed(kind),
            segment,
        }
    }

    pub fn new_owned(root: String, kind: String, segment: Segment) -> Self {
        MultiIndex {
            root: Cow::Owned(root),
            kind: Cow::Owned(kind),
            segment,
        }
    }

    /// Key prefix holding every member of `raw`. Always ends in `/`, so it
    /// can't match a sibling value whose encoded form starts with this one
    /// (`"ab"` vs `"ab1"`).
    pub fn members_prefix(&self, raw: &str) -> Result<String> {
        Ok(format!("{}/{}/{}/", self.root, self.kind, self.segment.encode(raw)?))
    }

    /// Key recording that `member` has `raw`.
    ///
    /// `member` may be hierarchical (`"<lang>/<uuid>"` is a normal member
    /// name), so it's validated component-wise like a
    /// [`crate::Collection`] name rather than as a single segment — the
    /// checks that matter (no empty component, no `..`, no component
    /// starting with `.`) all still apply, so a member can't climb out of
    /// its value's prefix or reach a reserved namespace.
    pub fn entry_key(&self, raw: &str, member: &str) -> Result<String> {
        validate_path(member, "index member")?;
        Ok(format!("{}{member}.json", self.members_prefix(raw)?))
    }

    /// Records that `member` has `raw`, with `payload` alongside it.
    /// Idempotent: adding an existing membership overwrites its payload
    /// rather than failing.
    ///
    /// Tries a create first (one request in the common case, since a
    /// membership is usually new) and only pays for the read when the entry
    /// already exists.
    pub async fn add<T: Serialize>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &str,
        member: &str,
        payload: &T,
    ) -> Result<()> {
        let key = self.entry_key(raw, member)?;
        let mut expected: Option<String> = None;
        for attempt in 0..MAX_ADD_ATTEMPTS {
            let cas = put_json(backend, &key, payload, expected.as_deref(), cipher).await?;
            if cas == Cas::Ok {
                return Ok(());
            }
            // Someone else wrote this exact membership. Take its etag and
            // overwrite: both writers want the entry to exist, and the last
            // payload written is the one the caller asked for.
            if attempt + 1 < MAX_ADD_ATTEMPTS {
                let (_ignored, etag) = backend.get(&key).await?;
                expected = etag;
            }
        }
        bail!("multi_index: too many CAS conflicts adding {key} (gave up after {MAX_ADD_ATTEMPTS} attempts)")
    }

    /// [`Self::add`] for the common case where the member name is the whole
    /// answer and there's no payload worth denormalizing.
    pub async fn add_member(&self, backend: &dyn Backend, cipher: &Cipher, raw: &str, member: &str) -> Result<()> {
        self.add(backend, cipher, raw, member, &()).await
    }

    /// Drops one membership. Best-effort, like every other unclaim in this
    /// crate: a delete that doesn't land leaves a stale member that a later
    /// remove (or [`Self::clear`]) cleans up, not a wrong answer elsewhere.
    pub async fn remove(&self, backend: &dyn Backend, raw: &str, member: &str) {
        if let Ok(key) = self.entry_key(raw, member) {
            delete_object(backend, &key).await;
        }
    }

    /// Every member of `raw`, in ascending name order.
    ///
    /// Listings only — no object is fetched and nothing is decrypted, because
    /// the member names are the key names. Paged, so a value with a very
    /// large membership costs one page of keys at a time on the wire.
    pub async fn members(&self, backend: &dyn Backend, raw: &str) -> Result<Vec<String>> {
        let prefix = self.members_prefix(raw)?;
        let mut members = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = backend.list_page(&prefix, after.as_deref(), MEMBER_PAGE).await?;
            for (key, _size) in &page.entries {
                if let Some(member) = key.strip_prefix(&prefix).and_then(|rest| rest.strip_suffix(".json")) {
                    members.push(member.to_string());
                }
            }
            match page.next_after {
                Some(next) => after = Some(next),
                None => return Ok(members),
            }
        }
    }

    /// [`Self::members`] plus each entry's payload, fetched concurrently
    /// under `budget`. For an index whose payload is a denormalized copy the
    /// reader needs (a title, a status) rather than `()`.
    ///
    /// A member whose payload fails to fetch or decode is dropped, same
    /// tolerance as [`crate::Collection::list_all`]: a membership can vanish
    /// between the listing and the read.
    pub async fn members_with<T>(
        &self,
        backend: &Arc<dyn Backend>,
        cipher: &Arc<Cipher>,
        raw: &str,
        budget: MemoryBudget,
    ) -> Result<Vec<(String, T)>>
    where
        T: DeserializeOwned + Default + Send + 'static,
    {
        let prefix = self.members_prefix(raw)?;
        let members = self.members(backend.as_ref(), raw).await?;
        let keys: Vec<String> = members.iter().map(|member| format!("{prefix}{member}.json")).collect();
        let mut loaded = BatchLoader::new(budget).load_many::<T>(backend, cipher, keys).await;
        let mut out = Vec::with_capacity(members.len());
        for member in members {
            let key = format!("{prefix}{member}.json");
            if let Some(Ok(Some(payload))) = loaded.remove(&key) {
                out.push((member, payload));
            }
        }
        Ok(out)
    }

    /// How many members `raw` has, from listings alone.
    pub async fn count(&self, backend: &dyn Backend, raw: &str) -> Result<u64> {
        Ok(crate::payload::count_prefix(backend, &self.members_prefix(raw)?)
            .await?
            .0)
    }

    /// Whether `member` has `raw`. One `get` of a key whose body is
    /// irrelevant — the existence of the object *is* the answer.
    pub async fn contains(&self, backend: &dyn Backend, raw: &str, member: &str) -> Result<bool> {
        let (_body, etag) = backend.get(&self.entry_key(raw, member)?).await?;
        Ok(etag.is_some())
    }

    /// Drops every membership of `raw`. Resumable, like every prefix sweep —
    /// check [`SweepReport::is_complete`].
    pub async fn clear(&self, backend: &dyn Backend, raw: &str) -> Result<SweepReport> {
        delete_prefix(backend, &self.members_prefix(raw)?).await
    }

    /// Reads one membership's payload. `None` if `member` doesn't have `raw`.
    pub async fn payload<T: DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &str,
        member: &str,
    ) -> Result<Option<T>> {
        let (value, etag) = get_json::<T>(backend, &self.entry_key(raw, member)?, cipher).await?;
        Ok(etag.is_some().then_some(value))
    }
}

#[cfg(test)]
#[path = "../tests/unit/multi_index.rs"]
mod tests;
