//! Streaming aggregation of [`LogRecord`]s and the resulting [`Report`].
//!
//! [`Stats`] only stores counters: memory grows with the number of *distinct*
//! keys (paths, IPs, status codes, time buckets), never with the number of lines.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, FixedOffset, SecondsFormat};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::record::LogRecord;

/// Width of the time buckets used for the per-window breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSpec {
    seconds: i64,
}

impl WindowSpec {
    /// Creates a window of `seconds` seconds. Returns `None` for non-positive widths.
    pub fn from_seconds(seconds: i64) -> Option<Self> {
        (seconds > 0).then_some(WindowSpec { seconds })
    }

    /// Width of the window in seconds.
    pub fn seconds(self) -> i64 {
        self.seconds
    }

    /// Start (Unix seconds) of the bucket containing `ts`.
    pub fn bucket_start(self, ts: &DateTime<FixedOffset>) -> i64 {
        ts.timestamp().div_euclid(self.seconds) * self.seconds
    }
}

impl fmt::Display for WindowSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.seconds;
        if s % 86_400 == 0 {
            write!(f, "{}d", s / 86_400)
        } else if s % 3_600 == 0 {
            write!(f, "{}h", s / 3_600)
        } else if s % 60 == 0 {
            write!(f, "{}m", s / 60)
        } else {
            write!(f, "{s}s")
        }
    }
}

impl FromStr for WindowSpec {
    type Err = Error;

    /// Parses `<number><unit>` where unit is `s`, `m`, `h` or `d` (e.g. `5m`).
    fn from_str(s: &str) -> Result<Self> {
        let invalid = || Error::InvalidWindow(s.to_string());
        let t = s.trim();
        let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
        let (num, unit) = t.split_at(split);
        let n: i64 = num.parse().map_err(|_| invalid())?;
        let mult = match unit.to_ascii_lowercase().as_str() {
            "s" | "sec" => 1,
            "m" | "min" => 60,
            "h" | "hr" => 3_600,
            "d" | "day" => 86_400,
            _ => return Err(invalid()),
        };
        n.checked_mul(mult)
            .and_then(WindowSpec::from_seconds)
            .ok_or_else(invalid)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Counter {
    count: u64,
    bytes: u64,
}

impl Counter {
    fn add(&mut self, bytes: u64) {
        self.count += 1;
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct WindowCounter {
    count: u64,
    bytes: u64,
    client_errors: u64,
    server_errors: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct LatencyAcc {
    samples: u64,
    sum: f64,
    min: f64,
    max: f64,
}

impl LatencyAcc {
    fn add(&mut self, v: f64) {
        if self.samples == 0 {
            self.min = v;
            self.max = v;
        } else {
            self.min = self.min.min(v);
            self.max = self.max.max(v);
        }
        self.samples += 1;
        self.sum += v;
    }
}

/// Streaming aggregator.
#[derive(Debug, Clone)]
pub struct Stats {
    window: Option<WindowSpec>,
    lines: u64,
    malformed: u64,
    matched: u64,
    bytes: u64,
    status: BTreeMap<u16, Counter>,
    no_status: Counter,
    methods: HashMap<String, Counter>,
    paths: HashMap<String, Counter>,
    ips: HashMap<String, Counter>,
    windows: BTreeMap<i64, WindowCounter>,
    latency: LatencyAcc,
    first: Option<DateTime<FixedOffset>>,
    last: Option<DateTime<FixedOffset>>,
}

fn bump(map: &mut HashMap<String, Counter>, key: Option<&str>, bytes: u64) {
    let Some(key) = key else { return };
    // Look up first so that the common "already seen" case does not allocate.
    if let Some(c) = map.get_mut(key) {
        c.add(bytes);
    } else {
        map.entry(key.to_string()).or_default().add(bytes);
    }
}

impl Stats {
    /// Creates an empty aggregator, optionally bucketing by `window`.
    pub fn new(window: Option<WindowSpec>) -> Self {
        Stats {
            window,
            lines: 0,
            malformed: 0,
            matched: 0,
            bytes: 0,
            status: BTreeMap::new(),
            no_status: Counter::default(),
            methods: HashMap::new(),
            paths: HashMap::new(),
            ips: HashMap::new(),
            windows: BTreeMap::new(),
            latency: LatencyAcc::default(),
            first: None,
            last: None,
        }
    }

    /// Counts one non-blank input line.
    pub fn count_line(&mut self) {
        self.lines += 1;
    }

    /// Counts one malformed (skipped) line.
    pub fn count_malformed(&mut self) {
        self.malformed += 1;
    }

    /// Non-blank lines read.
    pub fn lines(&self) -> u64 {
        self.lines
    }

    /// Lines that could not be parsed.
    pub fn malformed(&self) -> u64 {
        self.malformed
    }

    /// Lines that parsed successfully.
    pub fn parsed(&self) -> u64 {
        self.lines - self.malformed
    }

    /// Records that passed the filters and were aggregated.
    pub fn matched(&self) -> u64 {
        self.matched
    }

    /// Adds a record that passed the filters.
    pub fn record(&mut self, r: &LogRecord) {
        self.matched += 1;
        let bytes = r.bytes.unwrap_or(0);
        self.bytes = self.bytes.saturating_add(bytes);

        match r.status {
            Some(s) => self.status.entry(s).or_default().add(bytes),
            None => self.no_status.add(bytes),
        }
        bump(&mut self.methods, r.method.as_deref(), bytes);
        bump(&mut self.paths, r.path.as_deref(), bytes);
        bump(&mut self.ips, r.ip.as_deref(), bytes);

        if let Some(l) = r.latency_ms {
            self.latency.add(l);
        }

        if let Some(ts) = r.timestamp {
            if self.first.is_none_or(|f| ts < f) {
                self.first = Some(ts);
            }
            if self.last.is_none_or(|l| ts > l) {
                self.last = Some(ts);
            }
            if let Some(w) = self.window {
                let wc = self.windows.entry(w.bucket_start(&ts)).or_default();
                wc.count += 1;
                wc.bytes = wc.bytes.saturating_add(bytes);
                match r.status {
                    Some(400..=499) => wc.client_errors += 1,
                    Some(500..=599) => wc.server_errors += 1,
                    _ => {}
                }
            }
        }
    }

    /// Builds a report, keeping the `top` most frequent paths, IPs and methods
    /// (`0` keeps all of them).
    pub fn report(&self, top: usize) -> Report {
        let total = self.matched;
        let fmt_ts = |t: &DateTime<FixedOffset>| t.to_rfc3339_opts(SecondsFormat::Secs, true);

        let mut classes: BTreeMap<&'static str, Counter> = BTreeMap::new();
        for (&code, c) in &self.status {
            let class = match code {
                100..=199 => "1xx",
                200..=299 => "2xx",
                300..=399 => "3xx",
                400..=499 => "4xx",
                500..=599 => "5xx",
                _ => "other",
            };
            let e = classes.entry(class).or_default();
            e.count += c.count;
            e.bytes = e.bytes.saturating_add(c.bytes);
        }
        let mut status_classes: Vec<CountEntry> = classes
            .into_iter()
            .map(|(k, c)| CountEntry::new(k.to_string(), c, total))
            .collect();
        let mut status_codes: Vec<CountEntry> = self
            .status
            .iter()
            .map(|(code, c)| CountEntry::new(code.to_string(), *c, total))
            .collect();
        if self.no_status.count > 0 {
            status_classes.push(CountEntry::new("unknown".into(), self.no_status, total));
            status_codes.push(CountEntry::new("-".into(), self.no_status, total));
        }

        let latency = (self.latency.samples > 0).then(|| LatencySummary {
            samples: self.latency.samples,
            avg_ms: round(self.latency.sum / self.latency.samples as f64, 3),
            min_ms: round(self.latency.min, 3),
            max_ms: round(self.latency.max, 3),
        });

        let windows = self.window.map(|w| WindowReport {
            width: w.to_string(),
            buckets: self
                .windows
                .iter()
                .map(|(&start, c)| WindowEntry {
                    start: DateTime::from_timestamp(start, 0)
                        .map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true))
                        .unwrap_or_else(|| start.to_string()),
                    count: c.count,
                    bytes: c.bytes,
                    client_errors: c.client_errors,
                    server_errors: c.server_errors,
                })
                .collect(),
        });

        Report {
            summary: Summary {
                lines: self.lines,
                parsed: self.parsed(),
                malformed: self.malformed,
                matched: self.matched,
                total_bytes: self.bytes,
                unique_ips: self.ips.len() as u64,
                unique_paths: self.paths.len() as u64,
                first_seen: self.first.as_ref().map(fmt_ts),
                last_seen: self.last.as_ref().map(fmt_ts),
                latency,
            },
            status_classes,
            status_codes,
            methods: top_entries(&self.methods, top, total),
            top_paths: top_entries(&self.paths, top, total),
            top_ips: top_entries(&self.ips, top, total),
            windows,
        }
    }
}

fn round(v: f64, decimals: i32) -> f64 {
    let f = 10f64.powi(decimals);
    (v * f).round() / f
}

fn top_entries(map: &HashMap<String, Counter>, top: usize, total: u64) -> Vec<CountEntry> {
    let mut v: Vec<(&String, &Counter)> = map.iter().collect();
    v.sort_unstable_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));
    if top > 0 {
        v.truncate(top);
    }
    v.into_iter()
        .map(|(k, c)| CountEntry::new(k.clone(), *c, total))
        .collect()
}

/// A complete, serializable analysis result.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Report {
    /// Totals.
    pub summary: Summary,
    /// Requests per status class (`2xx`, `4xx`, ...), in class order.
    pub status_classes: Vec<CountEntry>,
    /// Requests per status code, in code order.
    pub status_codes: Vec<CountEntry>,
    /// Most frequent HTTP methods.
    pub methods: Vec<CountEntry>,
    /// Most requested paths.
    pub top_paths: Vec<CountEntry>,
    /// Most active client addresses.
    pub top_ips: Vec<CountEntry>,
    /// Per time-window breakdown, present when a window was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows: Option<WindowReport>,
}

/// Overall totals.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Summary {
    /// Non-blank lines read.
    pub lines: u64,
    /// Lines parsed successfully.
    pub parsed: u64,
    /// Lines skipped as malformed.
    pub malformed: u64,
    /// Records that passed the filters.
    pub matched: u64,
    /// Sum of response bytes over matched records.
    pub total_bytes: u64,
    /// Distinct client addresses among matched records.
    pub unique_ips: u64,
    /// Distinct paths among matched records.
    pub unique_paths: u64,
    /// Earliest timestamp among matched records (RFC3339).
    pub first_seen: Option<String>,
    /// Latest timestamp among matched records (RFC3339).
    pub last_seen: Option<String>,
    /// Latency statistics, if any record carried a latency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<LatencySummary>,
}

/// Latency statistics in milliseconds.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LatencySummary {
    /// Number of records with a latency value.
    pub samples: u64,
    /// Mean latency.
    pub avg_ms: f64,
    /// Smallest latency.
    pub min_ms: f64,
    /// Largest latency.
    pub max_ms: f64,
}

/// A key with its request count, share of matched requests and bytes.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CountEntry {
    /// The grouped value (path, IP, status code, ...).
    pub key: String,
    /// Number of matched requests.
    pub count: u64,
    /// Percentage of all matched requests, rounded to two decimals.
    pub percent: f64,
    /// Sum of response bytes.
    pub bytes: u64,
}

impl CountEntry {
    fn new(key: String, c: Counter, total: u64) -> Self {
        let percent = if total == 0 {
            0.0
        } else {
            round(c.count as f64 * 100.0 / total as f64, 2)
        };
        CountEntry {
            key,
            count: c.count,
            percent,
            bytes: c.bytes,
        }
    }
}

/// Per-window breakdown.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct WindowReport {
    /// Bucket width, e.g. `5m`.
    pub width: String,
    /// Non-empty buckets in chronological order.
    pub buckets: Vec<WindowEntry>,
}

/// One time bucket.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct WindowEntry {
    /// Bucket start in UTC (RFC3339).
    pub start: String,
    /// Matched requests in the bucket.
    pub count: u64,
    /// Response bytes in the bucket.
    pub bytes: u64,
    /// 4xx responses in the bucket.
    pub client_errors: u64,
    /// 5xx responses in the bucket.
    pub server_errors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::parse_timestamp;

    fn rec(status: u16, path: &str, ip: &str, bytes: u64, ts: &str) -> LogRecord {
        LogRecord {
            timestamp: parse_timestamp(ts),
            ip: Some(ip.into()),
            method: Some("GET".into()),
            path: Some(path.into()),
            status: Some(status),
            bytes: Some(bytes),
            latency_ms: None,
        }
    }

    #[test]
    fn window_spec_parsing() {
        assert_eq!("1m".parse::<WindowSpec>().expect("1m").seconds(), 60);
        assert_eq!("5m".parse::<WindowSpec>().expect("5m").seconds(), 300);
        assert_eq!("1h".parse::<WindowSpec>().expect("1h").seconds(), 3600);
        assert_eq!("1d".parse::<WindowSpec>().expect("1d").seconds(), 86_400);
        assert_eq!("90s".parse::<WindowSpec>().expect("90s").to_string(), "90s");
        assert_eq!(
            "120m".parse::<WindowSpec>().expect("120m").to_string(),
            "2h"
        );
        for bad in ["", "m", "0m", "5", "5w", "-1m", "99999999999999999d"] {
            assert!(bad.parse::<WindowSpec>().is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn aggregates_counts_and_top_n() {
        let mut s = Stats::new("1h".parse().ok());
        s.record(&rec(200, "/a", "192.0.2.1", 100, "2026-03-14T10:10:00Z"));
        s.record(&rec(200, "/a", "192.0.2.2", 100, "2026-03-14T10:20:00Z"));
        s.record(&rec(404, "/b", "192.0.2.1", 10, "2026-03-14T11:00:00Z"));
        s.record(&rec(503, "/c", "192.0.2.1", 0, "2026-03-14T09:59:59Z"));
        for _ in 0..5 {
            s.count_line();
        }
        s.count_malformed();

        let r = s.report(2);
        assert_eq!(r.summary.lines, 5);
        assert_eq!(r.summary.parsed, 4);
        assert_eq!(r.summary.malformed, 1);
        assert_eq!(r.summary.matched, 4);
        assert_eq!(r.summary.total_bytes, 210);
        assert_eq!(r.summary.unique_ips, 2);
        assert_eq!(r.summary.unique_paths, 3);
        assert_eq!(
            r.summary.first_seen.as_deref(),
            Some("2026-03-14T09:59:59Z")
        );
        assert_eq!(r.summary.last_seen.as_deref(), Some("2026-03-14T11:00:00Z"));

        let classes: Vec<_> = r
            .status_classes
            .iter()
            .map(|e| (e.key.as_str(), e.count))
            .collect();
        assert_eq!(classes, [("2xx", 2), ("4xx", 1), ("5xx", 1)]);
        assert_eq!(r.status_classes[0].percent, 50.0);

        assert_eq!(r.top_paths.len(), 2);
        assert_eq!(r.top_paths[0].key, "/a");
        assert_eq!(r.top_paths[1].key, "/b");
        assert_eq!(r.top_ips[0].key, "192.0.2.1");
        assert_eq!(r.top_ips[0].count, 3);

        let w = r.windows.expect("windows requested");
        assert_eq!(w.width, "1h");
        let buckets: Vec<_> = w
            .buckets
            .iter()
            .map(|b| (b.start.as_str(), b.count))
            .collect();
        assert_eq!(
            buckets,
            [
                ("2026-03-14T09:00:00Z", 1),
                ("2026-03-14T10:00:00Z", 2),
                ("2026-03-14T11:00:00Z", 1)
            ]
        );
        assert_eq!(w.buckets[0].server_errors, 1);
        assert_eq!(w.buckets[2].client_errors, 1);
    }

    #[test]
    fn top_zero_keeps_everything_and_latency_is_summarized() {
        let mut s = Stats::new(None);
        for (i, l) in [10.0, 20.0, 60.0].into_iter().enumerate() {
            let mut r = rec(
                200,
                &format!("/p{i}"),
                "10.0.0.1",
                1,
                "2026-03-14T10:00:00Z",
            );
            r.latency_ms = Some(l);
            s.record(&r);
        }
        let report = s.report(0);
        assert_eq!(report.top_paths.len(), 3);
        assert!(report.windows.is_none());
        let lat = report.summary.latency.expect("latency");
        assert_eq!(lat.samples, 3);
        assert_eq!(lat.avg_ms, 30.0);
        assert_eq!(lat.min_ms, 10.0);
        assert_eq!(lat.max_ms, 60.0);
    }

    #[test]
    fn empty_report_is_well_formed() {
        let r = Stats::new(None).report(10);
        assert_eq!(r.summary.matched, 0);
        assert!(r.status_classes.is_empty());
        assert!(r.summary.first_seen.is_none());
    }
}
