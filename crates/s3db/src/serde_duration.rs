//! Milliseconds on the wire for every [`Duration`] in this crate's config
//! types.
//!
//! `serde`'s own `Duration` impl is a `{ secs, nanos }` struct, which in a TOML
//! or JSON config file reads as `base_backoff = { secs = 0, nanos = 100000000 }`
//! — technically a duration, practically unwritable by hand and impossible to
//! skim. Every one of these fields is a timeout, an age, or a backoff, and the
//! natural unit for all of them is milliseconds, so that is what the config
//! surface uses.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::Duration;

pub(crate) fn serialize<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    (value.as_millis() as u64).serialize(serializer)
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    u64::deserialize(deserializer).map(Duration::from_millis)
}

/// The same, for an `Option<Duration>` — where `None` means "no limit" rather
/// than zero, so it has to stay distinguishable from `0`.
pub(crate) mod optional {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error> {
        value.map(|duration| duration.as_millis() as u64).serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Duration>, D::Error> {
        Ok(Option::<u64>::deserialize(deserializer)?.map(Duration::from_millis))
    }
}
