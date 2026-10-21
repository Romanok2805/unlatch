//! Limits on failed attempts: passwords per account and per address, codes per account.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// Keys tracked at once. Beyond this, expired entries are dropped, and if that isn't enough new
/// keys go untracked: a flood from many addresses can't grow memory without bound, and the
/// per-account limits still hold.
const CAPACITY: usize = 100_000;

pub(crate) struct Limits {
    pub(crate) password_by_address: Limiter,
    pub(crate) password_by_account: Limiter,
    /// A six-digit code has a million values, so its limits are much tighter than a password's.
    pub(crate) code_per_quarter_hour: Limiter,
    pub(crate) code_per_day: Limiter,
}

impl Limits {
    pub(crate) fn new() -> Self {
        Self {
            password_by_address: Limiter::new(50, 15 * 60),
            password_by_account: Limiter::new(10, 15 * 60),
            code_per_quarter_hour: Limiter::new(5, 15 * 60),
            code_per_day: Limiter::new(20, 24 * 60 * 60),
        }
    }
}

/// At most `max` failures per key in a fixed window of `window` seconds.
pub(crate) struct Limiter {
    max: u32,
    window: i64,
    entries: Mutex<HashMap<String, Window>>,
}

struct Window {
    started: i64,
    failures: u32,
}

impl Limiter {
    fn new(max: u32, window: i64) -> Self {
        Self {
            max,
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn allows(&self, key: &str) -> bool {
        let now = crate::time::now();
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries
            .get(key)
            .is_none_or(|entry| self.expired(entry, now) || entry.failures < self.max)
    }

    pub(crate) fn fail(&self, key: &str) {
        let now = crate::time::now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= CAPACITY && !entries.contains_key(key) {
            entries.retain(|_, entry| !self.expired(entry, now));
            if entries.len() >= CAPACITY {
                return;
            }
        }
        let entry = entries.entry(key.to_owned()).or_insert(Window {
            started: now,
            failures: 0,
        });
        if self.expired(entry, now) {
            *entry = Window {
                started: now,
                failures: 0,
            };
        }
        entry.failures = entry.failures.saturating_add(1);
    }

    pub(crate) fn reset(&self, key: &str) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }

    fn expired(&self, entry: &Window, now: i64) -> bool {
        now.saturating_sub(entry.started) >= self.window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_the_limit_until_reset() {
        let limiter = Limiter::new(2, 60);
        assert!(limiter.allows("anna"));
        limiter.fail("anna");
        limiter.fail("anna");
        assert!(!limiter.allows("anna"));
        assert!(limiter.allows("boris"));
        limiter.reset("anna");
        assert!(limiter.allows("anna"));
    }
}
