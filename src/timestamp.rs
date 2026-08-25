//! Minimal UTC timestamp parsing and formatting.
//!
//! Deliberately hand-rolled rather than pulling in a date crate: this runs in the
//! path that gates a 9.86M SOL signature, and a twenty-line integer conversion with
//! tests is easier to review than a new dependency tree. Only UTC is accepted, so
//! there is no zone database and no ambiguity about what a horizon means.

use anyhow::{bail, Result};

/// Days since the Unix epoch for a civil date, by Howard Hinnant's `days_from_civil`.
/// Integer-only and exact over the whole proleptic Gregorian range.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2), month, day)
}

fn field(value: &str, name: &str, low: i64, high: i64) -> Result<i64> {
    let parsed: i64 = value
        .parse()
        .map_err(|_| anyhow::anyhow!("{name} '{value}' is not a number"))?;
    if parsed < low || parsed > high {
        bail!("{name} {parsed} is outside {low}..={high}");
    }
    Ok(parsed)
}

/// Parses `YYYY-MM-DDTHH:MM:SSZ` (UTC only) or a bare Unix-seconds integer.
///
/// Accepting raw seconds as well keeps the flag usable when a value was copied from
/// chain state, where timestamps are already epoch seconds.
pub fn parse_utc(value: &str) -> Result<i64> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<i64>() {
        return Ok(seconds);
    }
    let rest = value
        .strip_suffix('Z')
        .or_else(|| value.strip_suffix("+00:00"))
        .ok_or_else(|| {
            anyhow::anyhow!("'{value}' must end in Z or +00:00 — only UTC is accepted")
        })?;
    let (date, time) = rest
        .split_once('T')
        .or_else(|| rest.split_once(' '))
        .ok_or_else(|| anyhow::anyhow!("'{value}' is not YYYY-MM-DDTHH:MM:SSZ"))?;
    let date: Vec<&str> = date.split('-').collect();
    let time: Vec<&str> = time.split(':').collect();
    if date.len() != 3 || time.len() != 3 {
        bail!("'{value}' is not YYYY-MM-DDTHH:MM:SSZ");
    }
    let (year, month, day) = (
        field(date[0], "year", 1970, 9999)?,
        field(date[1], "month", 1, 12)?,
        field(date[2], "day", 1, 31)?,
    );
    // Round-tripping rejects 31 April and 29 February in a common year, which the
    // per-field range check alone would let through.
    if civil_from_days(days_from_civil(year, month, day)) != (year, month, day) {
        bail!("'{value}' is not a real date");
    }
    // Leap seconds are not representable in Unix time, so 60 is rejected rather than
    // silently folded into the next minute.
    let (hour, minute, second) = (
        field(time[0], "hour", 0, 23)?,
        field(time[1], "minute", 0, 59)?,
        field(time[2], "second", 0, 59)?,
    );
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Renders a duration as hours and minutes, for a window a reader has to judge.
pub fn humanise_seconds(seconds: i64) -> String {
    let (hours, minutes) = (seconds / 3_600, (seconds % 3_600) / 60);
    if hours >= 48 {
        format!("{}d {}h", hours / 24, hours % 24)
    } else {
        format!("{hours}h {minutes}m")
    }
}

/// Renders Unix seconds back as `YYYY-MM-DDTHH:MM:SSZ`, so every printed deadline is
/// readable rather than an epoch integer the reader has to convert.
pub fn format_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected values produced independently by `date -u -j -f`.
    const KNOWN: [(&str, i64); 5] = [
        ("1970-01-01T00:00:00Z", 0),
        ("2026-08-29T19:17:00Z", 1_788_031_020),
        ("2026-08-25T12:00:00Z", 1_787_659_200),
        ("2000-02-29T00:00:00Z", 951_782_400),
        ("2026-12-31T23:59:59Z", 1_798_761_599),
    ];

    #[test]
    fn known_timestamps_parse_to_the_right_epoch() {
        for (text, epoch) in KNOWN {
            assert_eq!(parse_utc(text).unwrap(), epoch, "parsing {text}");
        }
    }

    #[test]
    fn formatting_round_trips() {
        for (text, epoch) in KNOWN {
            assert_eq!(format_utc(epoch), text, "formatting {epoch}");
            assert_eq!(parse_utc(&format_utc(epoch)).unwrap(), epoch);
        }
    }

    #[test]
    fn bare_epoch_seconds_are_accepted() {
        assert_eq!(parse_utc("1788031020").unwrap(), 1_788_031_020);
        assert_eq!(parse_utc("  1788031020  ").unwrap(), 1_788_031_020);
    }

    #[test]
    fn non_utc_and_malformed_input_is_rejected() {
        for bad in [
            "2026-08-29T19:17:00-04:00", // a zone offset would silently shift the horizon
            "2026-08-29T19:17:00",       // no marker at all
            "2026-02-30T00:00:00Z",      // not a real date
            "2025-02-29T00:00:00Z",      // 2025 is not a leap year
            "2026-13-01T00:00:00Z",
            "2026-08-29T24:00:00Z",
            "2026-08-29T19:17:60Z", // leap second, not representable
            "not-a-date",
            "",
        ] {
            assert!(parse_utc(bad).is_err(), "'{bad}' should be rejected");
        }
    }

    #[test]
    fn leap_day_is_accepted_in_a_leap_year() {
        assert!(parse_utc("2024-02-29T00:00:00Z").is_ok());
        assert!(parse_utc("2000-02-29T00:00:00Z").is_ok());
        assert!(
            parse_utc("1900-02-29T00:00:00Z").is_err(),
            "1900 is not a leap year"
        );
    }
}
