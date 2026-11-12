//! Timestamp formatting without a calendar dependency.
//!
//! The audit log needs RFC 3339 timestamps in UTC. The civil-date conversion
//! is the standard days-from-epoch algorithm, kept here so the project does
//! not need a date-time crate.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current time as an RFC 3339 UTC timestamp with millisecond precision,
/// for example `2026-11-13T09:15:02.123Z`.
pub fn now_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_rfc3339(now.as_secs() as i64, now.subsec_millis())
}

/// Formats a unix timestamp and millisecond offset as RFC 3339 UTC.
pub fn format_rfc3339(unix_seconds: i64, millis: u32) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Converts a count of days since 1970-01-01 into a civil (year, month, day).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (year + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_epoch() {
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn formats_a_known_instant() {
        // 2026-11-13T09:15:02Z
        assert_eq!(
            format_rfc3339(1_794_561_302, 123),
            "2026-11-13T09:15:02.123Z"
        );
    }

    #[test]
    fn handles_leap_days() {
        // 2024-02-29T00:00:00Z
        assert_eq!(format_rfc3339(1_709_164_800, 0), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn now_has_the_expected_shape() {
        let now = now_rfc3339();
        assert_eq!(now.len(), 24, "{now}");
        assert!(now.ends_with('Z'), "{now}");
        assert_eq!(&now[4..5], "-");
        assert_eq!(&now[10..11], "T");
    }
}
