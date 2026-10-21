//! Limits on failed attempts: passwords per account and per address, codes per account.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};

use crate::crypto::sha256;

/// Keys tracked at once, each a 32-byte hash however long the input was. When the table is full
/// of live entries, new keys are refused rather than let through untracked: an attacker who
/// fills it with junk must not thereby get unlimited guesses.
const CAPACITY: usize = 100_000;

pub(crate) struct Limits {
    password_by_address: Limiter,
    password_by_account: Limiter,
    /// A six-digit code has a million values, so its limits are much tighter than a password's.
    code_per_quarter_hour: Limiter,
    code_per_day: Limiter,
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

    /// Counts a password attempt from `address` for `account` and says whether it may go ahead.
    pub(crate) fn password_attempt(&self, address: IpAddr, account: &str) -> bool {
        let address = address_key(address);
        if !self.password_by_address.attempt(&address) {
            return false;
        }
        if !self.password_by_account.attempt(account) {
            self.password_by_address.forgive(&address);
            return false;
        }
        true
    }

    /// A password attempt succeeded: it doesn't count against the address, and the account's
    /// failures are forgiven.
    pub(crate) fn password_succeeded(&self, address: IpAddr, account: &str) {
        self.password_by_address.forgive(&address_key(address));
        self.password_by_account.reset(account);
    }

    /// Counts a code attempt for an account and says whether it may go ahead.
    pub(crate) fn code_attempt(&self, account: &str) -> bool {
        if !self.code_per_quarter_hour.attempt(account) {
            return false;
        }
        if !self.code_per_day.attempt(account) {
            self.code_per_quarter_hour.forgive(account);
            return false;
        }
        true
    }

    pub(crate) fn code_succeeded(&self, account: &str) {
        self.code_per_quarter_hour.reset(account);
        self.code_per_day.forgive(account);
    }
}

/// IPv6 addresses are counted per /64, the smallest block a home or hosting customer gets; one
/// such network holds more addresses than anyone could ever try from.
fn address_key(address: IpAddr) -> String {
    match address {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let [a, b, c, d, ..] = v6.segments();
            format!("{a:x}:{b:x}:{c:x}:{d:x}::/64")
        }
    }
}

/// At most `max` attempts per key in a fixed window of `window` seconds. An attempt is counted
/// before it runs, in the same step as the check, so parallel attempts can't all pass a check
/// made before any of them failed. Successful attempts are taken back afterwards.
struct Limiter {
    max: u32,
    window: i64,
    entries: Mutex<HashMap<[u8; 32], Window>>,
}

struct Window {
    started: i64,
    attempts: u32,
}

impl Limiter {
    fn new(max: u32, window: i64) -> Self {
        Self {
            max,
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn attempt(&self, key: &str) -> bool {
        let now = crate::time::now();
        let key = sha256(key.as_bytes());
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= CAPACITY && !entries.contains_key(&key) {
            entries.retain(|_, entry| now.saturating_sub(entry.started) < self.window);
            if entries.len() >= CAPACITY {
                return false;
            }
        }
        let entry = entries.entry(key).or_insert(Window {
            started: now,
            attempts: 0,
        });
        if now.saturating_sub(entry.started) >= self.window {
            *entry = Window {
                started: now,
                attempts: 0,
            };
        }
        if entry.attempts >= self.max {
            return false;
        }
        entry.attempts = entry.attempts.saturating_add(1);
        true
    }

    /// Takes back one counted attempt.
    fn forgive(&self, key: &str) {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = entries.get_mut(&sha256(key.as_bytes())) {
            entry.attempts = entry.attempts.saturating_sub(1);
        }
    }

    fn reset(&self, key: &str) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&sha256(key.as_bytes()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_attempts_before_they_run() {
        let limiter = Limiter::new(2, 60);
        assert!(limiter.attempt("anna"));
        assert!(limiter.attempt("anna"));
        assert!(!limiter.attempt("anna"));
        assert!(limiter.attempt("boris"));
        limiter.forgive("anna");
        assert!(limiter.attempt("anna"));
        limiter.reset("anna");
        assert!(limiter.attempt("anna"));
    }

    #[test]
    fn ipv6_addresses_share_their_64() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(address_key(a), address_key(b));
        assert_ne!(address_key(a), address_key(c));
    }
}
