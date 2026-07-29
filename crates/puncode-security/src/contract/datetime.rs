//! RFC 3339 timestamp validation.
//!
//! Ported from `validRfc3339DateTime` in `src/contract.ts`.
//!
//! JSON Schema's built-in `date-time` format is advisory and, in most
//! validators, only checks shape. The contract needs a timestamp that is also a
//! real calendar date, so this is registered as a custom format and rejects
//! things like February 30th that a shape check would wave through.

#![allow(dead_code)]

/// Whether `value` is an RFC 3339 timestamp naming a real instant.
///
/// Accepts a lowercase `t`/`z` separator, optional fractional seconds, and
/// either `Z` or a `±HH:MM` offset. Leap seconds are refused, matching
/// upstream's `second > 59` check.
#[must_use]
pub(crate) fn valid_rfc3339_date_time(value: &str) -> bool {
    let bytes = value.as_bytes();

    let (Some(year), Some(month), Some(day)) = (
        digits(bytes, 0, 4),
        digits(bytes, 5, 2),
        digits(bytes, 8, 2),
    ) else {
        return false;
    };
    let (Some(hour), Some(minute), Some(second)) = (
        digits(bytes, 11, 2),
        digits(bytes, 14, 2),
        digits(bytes, 17, 2),
    ) else {
        return false;
    };
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }

    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        // A fraction must have at least one digit.
        if index == start {
            return false;
        }
    }

    let (offset_hour, offset_minute) = match bytes.get(index) {
        Some(b'Z' | b'z') if index + 1 == bytes.len() => (0, 0),
        Some(b'+' | b'-') => {
            let (Some(offset_hour), Some(offset_minute)) =
                (digits(bytes, index + 1, 2), digits(bytes, index + 4, 2))
            else {
                return false;
            };
            if bytes.get(index + 3) != Some(&b':') || index + 6 != bytes.len() {
                return false;
            }
            (offset_hour, offset_minute)
        }
        _ => return false,
    };

    if year < 1
        || !(1..=12).contains(&month)
        || day < 1
        || hour > 23
        || minute > 59
        || second > 59
        || offset_hour > 23
        || offset_minute > 59
    {
        return false;
    }
    day <= days_in_month(year, month)
}

fn digits(bytes: &[u8], start: usize, length: usize) -> Option<u32> {
    let slice = bytes.get(start..start + length)?;
    if !slice.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(slice).ok()?.parse().ok()
}

fn days_in_month(year: u32, month: u32) -> u32 {
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        _ => 28,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_timestamps() {
        for value in [
            "2026-01-01T00:00:00Z",
            "2026-07-28T21:16:00Z",
            "2026-01-01T00:00:00.123Z",
            "2026-01-01T00:00:00.000000001Z",
            "2026-01-01T12:30:45+05:30",
            "2026-01-01T12:30:45-08:00",
        ] {
            assert!(valid_rfc3339_date_time(value), "{value} should be accepted");
        }
    }

    // The pattern is case-insensitive upstream.
    #[test]
    fn accepts_lowercase_separators() {
        assert!(valid_rfc3339_date_time("2026-01-01t00:00:00z"));
        assert!(valid_rfc3339_date_time("2026-01-01T00:00:00z"));
        assert!(valid_rfc3339_date_time("2026-01-01t00:00:00Z"));
    }

    // A shape-only check would accept these; the calendar check is the point.
    #[test]
    fn rejects_calendar_invalid_dates() {
        for value in [
            "2026-02-30T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-01-32T00:00:00Z",
            "0000-01-01T00:00:00Z",
        ] {
            assert!(!valid_rfc3339_date_time(value), "{value} should be refused");
        }
    }

    #[test]
    fn applies_gregorian_leap_year_rules() {
        assert!(
            valid_rfc3339_date_time("2024-02-29T00:00:00Z"),
            "divisible by 4"
        );
        assert!(
            valid_rfc3339_date_time("2000-02-29T00:00:00Z"),
            "divisible by 400"
        );
        assert!(
            !valid_rfc3339_date_time("1900-02-29T00:00:00Z"),
            "divisible by 100"
        );
        assert!(
            !valid_rfc3339_date_time("2026-02-29T00:00:00Z"),
            "ordinary year"
        );
    }

    #[test]
    fn rejects_out_of_range_times() {
        for value in [
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            // Leap seconds are refused, matching `second > 59`.
            "2026-01-01T23:59:60Z",
            "2026-01-01T12:30:45+24:00",
            "2026-01-01T12:30:45+00:60",
        ] {
            assert!(!valid_rfc3339_date_time(value), "{value} should be refused");
        }
    }

    #[test]
    fn rejects_malformed_timestamps() {
        for value in [
            "",
            "2026-01-01",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00+0530",
            "2026-01-01T00:00:00.Z",
            "2026-01-01T00:00:00Z ",
            "2026-01-01T00:00:00Zextra",
            "2026-01-01 00:00:00Z",
            "2026/01/01T00:00:00Z",
            "26-01-01T00:00:00Z",
            "2026-1-01T00:00:00Z",
            "not a timestamp at all",
        ] {
            assert!(
                !valid_rfc3339_date_time(value),
                "{value:?} should be refused"
            );
        }
    }

    #[test]
    fn rejects_non_ascii_digits() {
        // Arabic-Indic digits are digits to Unicode but not to `\d` here.
        assert!(!valid_rfc3339_date_time("٢٠٢٦-01-01T00:00:00Z"));
    }
}

/// Converts a count of days since the Unix epoch to a civil date.
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * shifted_month + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    })
    .unwrap_or(1);
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The current UTC time as an RFC 3339 timestamp with milliseconds.
///
/// Matches the shape of JavaScript's `Date.prototype.toISOString`, which is
/// what the plugin is given upstream.
pub fn utc_rfc3339_now() -> String {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = elapsed.as_secs();
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let time_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60,
        elapsed.subsec_millis()
    )
}

#[cfg(test)]
mod date_tests {
    use super::*;

    #[test]
    fn formats_a_civil_date_from_the_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(31), (1970, 2, 1));
        assert_eq!(civil_from_days(365), (1971, 1, 1));
        // 2024 is a leap year, so day 59 of that year is 29 February.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(20_662), (2026, 7, 28));
    }

    // The plugin parses this, so its shape must match what upstream produces.
    #[test]
    fn formats_the_current_time_as_rfc3339() {
        let stamp = utc_rfc3339_now();

        assert!(
            valid_rfc3339_date_time(&stamp),
            "not a valid timestamp: {stamp}"
        );
        assert!(stamp.ends_with('Z'), "not UTC: {stamp}");
        assert_eq!(stamp.len(), 24, "unexpected shape: {stamp}");
    }
}
