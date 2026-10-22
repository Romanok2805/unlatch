//! Remembering proofs that were accepted, so that none is accepted twice: DPoP proofs and answers
//! to passkey challenges.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// Proofs remembered at once. A full log refuses new proofs rather than forget ones that could
/// still be replayed.
const CAPACITY: usize = 65_536;
/// How often expired entries are swept out, in seconds.
const CLEANUP_INTERVAL: i64 = 60;

pub(crate) struct ReplayLog(Mutex<Seen>);

struct Seen {
    /// When each proof stops being acceptable anyway, by a hash that identifies it.
    entries: HashMap<[u8; 32], i64>,
    next_cleanup: i64,
}

impl ReplayLog {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(Seen {
            entries: HashMap::new(),
            next_cleanup: 0,
        }))
    }

    /// Notes a proof that is acceptable until `until`. False if it was seen before, or if the
    /// log is full.
    pub(crate) fn first_use(&self, id: [u8; 32], until: i64, now: i64) -> bool {
        let mut seen = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if now >= seen.next_cleanup || seen.entries.len() >= CAPACITY {
            seen.entries.retain(|_, until| *until > now);
            seen.entries.shrink_to_fit();
            seen.next_cleanup = now.saturating_add(CLEANUP_INTERVAL);
        }
        if seen.entries.len() >= CAPACITY || seen.entries.contains_key(&id) {
            return false;
        }
        seen.entries.insert(id, until);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proof_is_accepted_once_while_it_is_fresh() {
        let log = ReplayLog::new();
        assert!(log.first_use([1; 32], 160, 100));
        assert!(!log.first_use([1; 32], 160, 101));
        assert!(log.first_use([2; 32], 160, 101));
        // Past its window it can be forgotten; by then it would be refused as too old anyway.
        assert!(log.first_use([1; 32], 230, 170));
    }
}
