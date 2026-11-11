//! Line parsers for the supported log formats.
//!
//! Two families are supported:
//!
//! * **Combined / common** access logs as written by Nginx and Apache
//!   (`$remote_addr - $remote_user [$time_local] "$request" $status
//!   $body_bytes_sent "$http_referer" "$http_user_agent"`). The referer and
//!   user-agent are optional, so the plain "common" format works too. A single
//!   trailing numeric field (commonly `$request_time`, in seconds) is read as the
//!   request latency.
//! * **JSON lines**: one JSON object per line. Field names are auto-detected
//!   from a list of common candidates and can be overridden per field with
//!   [`JsonFields`]. Dotted keys (`http.status`) address nested objects.

use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::record::LogRecord;
use crate::time::{parse_epoch, parse_nginx_time, parse_timestamp};

/// Input log format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Detect the format from the content of each input.
    #[default]
    Auto,
    /// Nginx/Apache combined (or common) access log format.
    Combined,
    /// One JSON object per line.
    Json,
}

impl LogFormat {
    /// Guesses the concrete format of a single non-blank line.
    ///
    /// Lines starting with `{` are treated as JSON, everything else as an
    /// access-log line. Never returns [`LogFormat::Auto`].
    pub fn detect(line: &str) -> LogFormat {
        if line.trim_start().starts_with('{') {
            LogFormat::Json
        } else {
            LogFormat::Combined
        }
    }
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LogFormat::Auto => "auto",
            LogFormat::Combined => "combined",
            LogFormat::Json => "json",
        })
    }
}

/// Unit of a numeric latency value found in JSON logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LatencyUnit {
    /// Milliseconds.
    #[default]
    Milliseconds,
    /// Seconds.
    Seconds,
}

impl LatencyUnit {
    /// Converts a value expressed in this unit to milliseconds.
    pub fn to_millis(self, value: f64) -> f64 {
        match self {
            LatencyUnit::Milliseconds => value,
            LatencyUnit::Seconds => value * 1000.0,
        }
    }
}

/// A logical field of a [`LogRecord`] that can be mapped to a JSON key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    /// Request time.
    Timestamp,
    /// HTTP status code.
    Status,
    /// HTTP method.
    Method,
    /// Request path.
    Path,
    /// Client IP.
    Ip,
    /// Response size in bytes.
    Bytes,
    /// Request latency.
    Latency,
}

impl Field {
    /// JSON keys tried, in order, when no explicit mapping is configured.
    pub fn candidates(self) -> &'static [&'static str] {
        match self {
            Field::Timestamp => &[
                "timestamp",
                "@timestamp",
                "time",
                "ts",
                "time_local",
                "datetime",
                "date",
            ],
            Field::Status => &[
                "status",
                "status_code",
                "statusCode",
                "response_status",
                "code",
            ],
            Field::Method => &["method", "request_method", "http_method", "verb"],
            Field::Path => &["path", "request_path", "uri", "request_uri", "url", "route"],
            Field::Ip => &[
                "ip",
                "remote_addr",
                "client_ip",
                "remote_ip",
                "clientip",
                "client",
            ],
            Field::Bytes => &[
                "bytes",
                "body_bytes_sent",
                "bytes_sent",
                "response_size",
                "size",
            ],
            Field::Latency => &[
                "latency_ms",
                "duration_ms",
                "elapsed_ms",
                "response_time_ms",
                "request_time",
                "upstream_response_time",
                "latency",
                "duration",
            ],
        }
    }

    /// Unit implied by an auto-detected latency key.
    fn latency_unit_for(key: &str) -> LatencyUnit {
        match key {
            "request_time" | "upstream_response_time" => LatencyUnit::Seconds,
            _ => LatencyUnit::Milliseconds,
        }
    }
}

impl FromStr for Field {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "timestamp" | "time" | "ts" => Ok(Field::Timestamp),
            "status" => Ok(Field::Status),
            "method" => Ok(Field::Method),
            "path" | "uri" | "url" => Ok(Field::Path),
            "ip" | "client" => Ok(Field::Ip),
            "bytes" | "size" => Ok(Field::Bytes),
            "latency" | "duration" => Ok(Field::Latency),
            _ => Err(Error::InvalidFieldMapping(s.to_string())),
        }
    }
}

/// Explicit JSON key overrides for record fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JsonFields {
    overrides: Vec<(Field, String)>,
}

impl JsonFields {
    /// Maps `field` to the JSON key `key`, replacing any earlier mapping.
    pub fn set(&mut self, field: Field, key: impl Into<String>) {
        self.overrides.retain(|(f, _)| *f != field);
        self.overrides.push((field, key.into()));
    }

    /// Returns the configured key for `field`, if any.
    pub fn get(&self, field: Field) -> Option<&str> {
        self.overrides
            .iter()
            .find(|(f, _)| *f == field)
            .map(|(_, k)| k.as_str())
    }

    /// Parses and applies a mapping of the form `field=key`, e.g. `status=http.code`.
    pub fn parse_mapping(&mut self, spec: &str) -> Result<()> {
        let (field, key) = spec
            .split_once('=')
            .ok_or_else(|| Error::InvalidFieldMapping(spec.to_string()))?;
        let key = key.trim();
        if key.is_empty() {
            return Err(Error::InvalidFieldMapping(spec.to_string()));
        }
        let field: Field = field
            .parse()
            .map_err(|_| Error::InvalidFieldMapping(spec.to_string()))?;
        self.set(field, key);
        Ok(())
    }
}

/// Options that influence how lines are parsed.
#[derive(Debug, Clone, Default)]
pub struct ParseOptions {
    /// Keep the query string as part of the path (default: strip it).
    pub keep_query: bool,
    /// Explicit JSON key mappings.
    pub json_fields: JsonFields,
    /// Unit of latency values read through an explicit `latency` mapping.
    pub latency_unit: LatencyUnit,
}

/// Matches a combined/common access-log line.
///
/// Groups: 1 = client, 2 = time, 3 = request, 4 = status, 5 = bytes,
/// 6 = optional trailing fields.
static COMBINED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"^(\S+) \S+ \S+ \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-)"#,
        r#"(?: "(?:[^"\\]|\\.)*" "(?:[^"\\]|\\.)*")?"#,
        r#"(?:\s+(.*?))?\s*$"#,
    ))
    .expect("combined log regex is valid")
});

/// Parses log lines into [`LogRecord`]s.
#[derive(Debug, Clone, Default)]
pub struct Parser {
    options: ParseOptions,
}

impl Parser {
    /// Creates a parser with the given options.
    pub fn new(options: ParseOptions) -> Self {
        Parser { options }
    }

    /// Returns the parser options.
    pub fn options(&self) -> &ParseOptions {
        &self.options
    }

    /// Parses one line in the given format. Returns `None` if the line is malformed.
    ///
    /// With [`LogFormat::Auto`] the format is detected from this line alone.
    pub fn parse_line(&self, format: LogFormat, line: &str) -> Option<LogRecord> {
        match format {
            LogFormat::Combined => self.parse_combined(line),
            LogFormat::Json => self.parse_json(line),
            LogFormat::Auto => self.parse_line(LogFormat::detect(line), line),
        }
    }

    /// Parses a combined or common access-log line.
    pub fn parse_combined(&self, line: &str) -> Option<LogRecord> {
        let caps = COMBINED_RE.captures(line)?;
        let timestamp = Some(parse_nginx_time(caps.get(2)?.as_str())?);
        let status: u16 = caps.get(4)?.as_str().parse().ok()?;
        let bytes = match caps.get(5)?.as_str() {
            "-" => None,
            b => Some(b.parse().ok()?),
        };
        let (method, path) = split_request(caps.get(3)?.as_str(), self.options.keep_query);
        let latency_ms = caps
            .get(6)
            .and_then(|m| m.as_str().split_whitespace().next())
            .and_then(|tok| tok.parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
            .map(|secs| LatencyUnit::Seconds.to_millis(secs));
        Some(LogRecord {
            timestamp,
            ip: Some(caps.get(1)?.as_str().to_string()),
            method,
            path,
            status: Some(status),
            bytes,
            latency_ms,
        })
    }

    /// Parses a JSON-lines entry. Returns `None` unless the line is a JSON object.
    pub fn parse_json(&self, line: &str) -> Option<LogRecord> {
        let obj: Map<String, Value> = serde_json::from_str(line).ok()?;
        let keep_query = self.options.keep_query;

        let timestamp = self
            .find(&obj, Field::Timestamp)
            .and_then(|(_, v)| match v {
                Value::String(s) => parse_timestamp(s),
                Value::Number(n) => n.as_f64().and_then(parse_epoch),
                _ => None,
            });
        let status = self
            .find(&obj, Field::Status)
            .and_then(|(_, v)| value_u64(v))
            .and_then(|s| u16::try_from(s).ok())
            .filter(|s| (100..=999).contains(s));
        let mut method = self
            .find(&obj, Field::Method)
            .and_then(|(_, v)| value_string(v))
            .map(|m| m.to_ascii_uppercase());
        let mut path = self
            .find(&obj, Field::Path)
            .and_then(|(_, v)| value_string(v))
            .map(|p| normalize_path(&p, keep_query));
        if method.is_none() || path.is_none() {
            // Fall back to an access-log style `"request": "GET /x HTTP/1.1"`.
            if let Some(Value::String(req)) = obj.get("request") {
                let (m, p) = split_request(req, keep_query);
                method = method.or(m);
                path = path.or(p);
            }
        }
        let ip = self
            .find(&obj, Field::Ip)
            .and_then(|(_, v)| value_string(v));
        let bytes = self
            .find(&obj, Field::Bytes)
            .and_then(|(_, v)| value_u64(v));
        let latency_ms = self.find(&obj, Field::Latency).and_then(|(key, v)| {
            let unit = if self.options.json_fields.get(Field::Latency).is_some() {
                self.options.latency_unit
            } else {
                Field::latency_unit_for(key)
            };
            value_f64(v)
                .filter(|x| x.is_finite() && *x >= 0.0)
                .map(|x| unit.to_millis(x))
        });

        Some(LogRecord {
            timestamp,
            ip,
            method,
            path,
            status,
            bytes,
            latency_ms,
        })
    }

    /// Looks up `field` in `obj`, returning the key that matched and its value.
    fn find<'a>(
        &'a self,
        obj: &'a Map<String, Value>,
        field: Field,
    ) -> Option<(&'a str, &'a Value)> {
        match self.options.json_fields.get(field) {
            Some(key) => lookup(obj, key).filter(|v| !v.is_null()).map(|v| (key, v)),
            None => field
                .candidates()
                .iter()
                .find_map(|key| obj.get(*key).filter(|v| !v.is_null()).map(|v| (*key, v))),
        }
    }
}

/// Resolves `key` in `obj`; a dotted key walks into nested objects when no
/// literal key of that name exists.
fn lookup<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    if let Some(v) = obj.get(key) {
        return Some(v);
    }
    let mut parts = key.split('.');
    let mut current = obj.get(parts.next()?)?;
    for part in parts {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

fn value_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() && s != "-" => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn value_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn value_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Splits a request line such as `GET /index.html HTTP/1.1` into method and path.
fn split_request(request: &str, keep_query: bool) -> (Option<String>, Option<String>) {
    let mut parts = request.split_whitespace();
    match parts.next() {
        Some(m) if m.bytes().all(|b| b.is_ascii_uppercase()) => (
            Some(m.to_string()),
            parts.next().map(|p| normalize_path(p, keep_query)),
        ),
        _ => (None, None),
    }
}

/// Removes the query string from `path` unless `keep_query` is set.
pub fn normalize_path(path: &str, keep_query: bool) -> String {
    if keep_query {
        path.to_string()
    } else {
        path.split_once('?').map_or(path, |(p, _)| p).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMBINED: &str = r#"192.0.2.10 - - [14/Mar/2026:10:00:01 +0000] "GET /index.html?x=1 HTTP/1.1" 200 5120 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)""#;

    #[test]
    fn detects_format() {
        assert_eq!(LogFormat::detect("  {\"a\":1}"), LogFormat::Json);
        assert_eq!(LogFormat::detect(COMBINED), LogFormat::Combined);
    }

    #[test]
    fn parses_combined_line() {
        let r = Parser::default().parse_combined(COMBINED).expect("valid");
        assert_eq!(r.ip.as_deref(), Some("192.0.2.10"));
        assert_eq!(r.method.as_deref(), Some("GET"));
        assert_eq!(r.path.as_deref(), Some("/index.html"));
        assert_eq!(r.status, Some(200));
        assert_eq!(r.bytes, Some(5120));
        assert_eq!(r.latency_ms, None);
        assert_eq!(
            r.timestamp.map(|t| t.to_rfc3339()).as_deref(),
            Some("2026-03-14T10:00:01+00:00")
        );
    }

    #[test]
    fn keeps_query_when_asked() {
        let parser = Parser::new(ParseOptions {
            keep_query: true,
            ..ParseOptions::default()
        });
        let r = parser.parse_combined(COMBINED).expect("valid");
        assert_eq!(r.path.as_deref(), Some("/index.html?x=1"));
    }

    #[test]
    fn parses_common_line_and_dash_bytes() {
        let line = r#"10.0.0.8 - - [14/Mar/2026:10:05:00 +0000] "GET /health HTTP/1.1" 304 -"#;
        let r = Parser::default().parse_combined(line).expect("valid");
        assert_eq!(r.status, Some(304));
        assert_eq!(r.bytes, None);
    }

    #[test]
    fn parses_escaped_quotes_and_trailing_request_time() {
        let line = r#"203.0.113.5 - - [14/Mar/2026:10:05:00 +0000] "GET /q?s=\"x\" HTTP/1.1" 200 10 "-" "agent \"quoted\"" 0.250"#;
        let r = Parser::default().parse_combined(line).expect("valid");
        assert_eq!(r.path.as_deref(), Some("/q"));
        assert_eq!(r.latency_ms, Some(250.0));
    }

    #[test]
    fn rejects_malformed_combined() {
        let p = Parser::default();
        assert!(p.parse_combined("garbage").is_none());
        assert!(p
            .parse_combined(r#"192.0.2.1 - - [bad time] "GET / HTTP/1.1" 200 1"#)
            .is_none());
        assert!(p
            .parse_combined(r#"192.0.2.1 - - [14/Mar/2026:10:00:00 +0000] "GET / HTTP/1.1" abc 1"#)
            .is_none());
    }

    #[test]
    fn non_http_request_has_no_method() {
        let line = r#"192.0.2.1 - - [14/Mar/2026:10:00:00 +0000] "-" 400 0 "-" "-""#;
        let r = Parser::default().parse_combined(line).expect("valid");
        assert_eq!(r.method, None);
        assert_eq!(r.path, None);
        assert_eq!(r.status, Some(400));
    }

    #[test]
    fn parses_json_with_detected_fields() {
        let line = r#"{"timestamp":"2026-03-14T10:00:03Z","method":"get","path":"/api?x=1","status":"404","bytes":12,"request_time":0.5,"remote_addr":"198.51.100.7"}"#;
        let r = Parser::default().parse_json(line).expect("valid");
        assert_eq!(r.method.as_deref(), Some("GET"));
        assert_eq!(r.path.as_deref(), Some("/api"));
        assert_eq!(r.status, Some(404));
        assert_eq!(r.bytes, Some(12));
        assert_eq!(r.ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(r.latency_ms, Some(500.0));
        assert!(r.timestamp.is_some());
    }

    #[test]
    fn parses_json_with_mapped_nested_fields() {
        let mut fields = JsonFields::default();
        fields.parse_mapping("status=res.code").expect("mapping");
        fields.parse_mapping("latency=took").expect("mapping");
        fields.parse_mapping("timestamp=when").expect("mapping");
        let parser = Parser::new(ParseOptions {
            json_fields: fields,
            latency_unit: LatencyUnit::Seconds,
            ..ParseOptions::default()
        });
        let line = r#"{"when":1773482401,"res":{"code":503},"took":0.02,"request":"POST /submit HTTP/1.1"}"#;
        let r = parser.parse_json(line).expect("valid");
        assert_eq!(r.status, Some(503));
        assert_eq!(r.latency_ms, Some(20.0));
        assert_eq!(r.method.as_deref(), Some("POST"));
        assert_eq!(r.path.as_deref(), Some("/submit"));
        assert!(r.timestamp.is_some());
    }

    #[test]
    fn rejects_non_object_json() {
        let p = Parser::default();
        assert!(p.parse_json("[1,2,3]").is_none());
        assert!(p.parse_json("{not json").is_none());
    }

    #[test]
    fn rejects_bad_field_mappings() {
        let mut fields = JsonFields::default();
        assert!(fields.parse_mapping("status").is_err());
        assert!(fields.parse_mapping("colour=x").is_err());
        assert!(fields.parse_mapping("status=").is_err());
    }
}
