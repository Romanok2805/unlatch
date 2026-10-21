//! Wall-clock time in Unix seconds, the unit of every timestamp we store or send.

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}
