//! The normalized representation of a single log entry.

use chrono::{DateTime, FixedOffset};

/// A single parsed log entry, independent of the source format.
///
/// Every field is optional: JSON logs in particular may omit any of them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LogRecord {
    /// When the request happened.
    pub timestamp: Option<DateTime<FixedOffset>>,
    /// Client address as written in the log.
    pub ip: Option<String>,
    /// HTTP method, e.g. `GET`.
    pub method: Option<String>,
    /// Request path (query string removed unless configured otherwise).
    pub path: Option<String>,
    /// HTTP status code.
    pub status: Option<u16>,
    /// Response size in bytes.
    pub bytes: Option<u64>,
    /// Request latency in milliseconds.
    pub latency_ms: Option<f64>,
}
