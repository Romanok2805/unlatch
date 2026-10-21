//! Wall-clock time in Unix seconds, the unit of every timestamp we store or send.

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// `2026-10-22 13:05:07` in UTC, for logs and the interface.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "the timestamp is clamped to years 1970-9999, where none of this can overflow"
)]
pub(crate) fn format_utc(timestamp: i64) -> String {
    let timestamp = timestamp.clamp(0, 253_402_300_799);
    let (days, seconds) = (timestamp / 86_400, timestamp % 86_400);
    // Days since 1970-01-01 to a civil date, from Howard Hinnant's "chrono-compatible low-level
    // date algorithms", with eras of 400 years starting on 0000-03-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_dates_across_leap_years() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(format_utc(1_792_666_807), "2026-10-22 11:00:07");
        assert_eq!(format_utc(-5), "1970-01-01 00:00:00");
    }
}
