//! Timestamp parsing helpers.

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime};

use crate::error::{Error, Result};

/// The `strftime` format used by Nginx/Apache (`$time_local`), e.g.
/// `14/Mar/2026:10:00:01 +0000`.
pub const NGINX_TIME_FORMAT: &str = "%d/%b/%Y:%H:%M:%S %z";

/// Parses an Nginx/Apache access-log timestamp (without the surrounding brackets).
pub fn parse_nginx_time(s: &str) -> Option<DateTime<FixedOffset>> {
    DateTime::parse_from_str(s, NGINX_TIME_FORMAT).ok()
}

/// Parses a timestamp string in any supported textual format.
///
/// Supported: RFC3339, the Nginx format, `YYYY-MM-DD HH:MM:SS[.fff]±HH:MM`, and
/// offset-less `YYYY-MM-DD[T ]HH:MM:SS[.fff]` (interpreted as UTC).
pub fn parse_timestamp(s: &str) -> Option<DateTime<FixedOffset>> {
    let s = s.trim();
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(t);
    }
    if let Some(t) = parse_nginx_time(s) {
        return Some(t);
    }
    for fmt in ["%Y-%m-%d %H:%M:%S%.f%:z", "%Y-%m-%d %H:%M:%S%.f%z"] {
        if let Ok(t) = DateTime::parse_from_str(s, fmt) {
            return Some(t);
        }
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(n.and_utc().fixed_offset());
        }
    }
    None
}

/// Converts a numeric Unix timestamp to a date-time.
///
/// Values above `1e11` are treated as milliseconds, smaller values as seconds.
pub fn parse_epoch(value: f64) -> Option<DateTime<FixedOffset>> {
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let millis = if value > 1e11 { value } else { value * 1000.0 };
    // Range check before the cast so absurd values cannot saturate silently.
    if millis > 1e16 {
        return None;
    }
    DateTime::from_timestamp_millis(millis.round() as i64).map(|t| t.fixed_offset())
}

/// Parses a user supplied time bound (`--since` / `--until`).
///
/// Accepts everything [`parse_timestamp`] accepts plus a bare date
/// (`YYYY-MM-DD`, midnight UTC).
pub fn parse_time_bound(s: &str) -> Result<DateTime<FixedOffset>> {
    if let Some(t) = parse_timestamp(s) {
        return Ok(t);
    }
    NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|n| n.and_utc().fixed_offset())
        .ok_or_else(|| Error::InvalidTimestamp(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nginx_format() {
        let t = parse_nginx_time("14/Mar/2026:10:00:01 +0100").expect("valid");
        assert_eq!(t.to_rfc3339(), "2026-03-14T10:00:01+01:00");
    }

    #[test]
    fn parses_rfc3339_and_variants() {
        assert!(parse_timestamp("2026-03-14T10:00:01Z").is_some());
        assert!(parse_timestamp("2026-03-14T10:00:01.123+02:00").is_some());
        assert!(parse_timestamp("2026-03-14 10:00:01+00:00").is_some());
        let naive = parse_timestamp("2026-03-14 10:00:01").expect("naive utc");
        assert_eq!(naive.to_rfc3339(), "2026-03-14T10:00:01+00:00");
        assert!(parse_timestamp("2026-03-14T10:00:01.5").is_some());
        assert!(parse_timestamp("yesterday").is_none());
    }

    #[test]
    fn parses_epoch_seconds_and_millis() {
        let secs = parse_epoch(1_773_482_401.0).expect("secs");
        let millis = parse_epoch(1_773_482_401_000.0).expect("millis");
        assert_eq!(secs, millis);
        assert!(parse_epoch(-1.0).is_none());
        assert!(parse_epoch(f64::NAN).is_none());
    }

    #[test]
    fn parses_time_bounds() {
        let d = parse_time_bound("2026-03-14").expect("date");
        assert_eq!(d.to_rfc3339(), "2026-03-14T00:00:00+00:00");
        assert!(parse_time_bound("14/Mar/2026:10:00:00 +0000").is_ok());
        assert!(matches!(
            parse_time_bound("not a time"),
            Err(Error::InvalidTimestamp(_))
        ));
    }
}
