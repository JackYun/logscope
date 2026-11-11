//! Record filters (`--status`, `--path`, `--method`, `--since`, `--until`, `--ip`).

use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, FixedOffset};
use regex::Regex;

use crate::error::{Error, Result};
use crate::record::LogRecord;

/// One element of a status filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusRule {
    Exact(u16),
    Range(u16, u16),
}

/// A set of status codes, parsed from expressions like `404`, `5xx`,
/// `400-499` or comma separated combinations (`404,5xx`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusFilter {
    rules: Vec<StatusRule>,
}

impl StatusFilter {
    /// Returns `true` if `status` is selected by this filter.
    pub fn matches(&self, status: u16) -> bool {
        self.rules.iter().any(|rule| match *rule {
            StatusRule::Exact(code) => status == code,
            StatusRule::Range(lo, hi) => (lo..=hi).contains(&status),
        })
    }
}

fn parse_code(expr: &str, s: &str) -> Result<u16> {
    let invalid = |reason: &str| Error::InvalidStatusFilter {
        expr: expr.to_string(),
        reason: reason.to_string(),
    };
    let code: u16 = s
        .trim()
        .parse()
        .map_err(|_| invalid(&format!("`{s}` is not a status code")))?;
    if (100..=999).contains(&code) {
        Ok(code)
    } else {
        Err(invalid(&format!("{code} is outside 100-999")))
    }
}

impl FromStr for StatusFilter {
    type Err = Error;

    fn from_str(expr: &str) -> Result<Self> {
        let invalid = |reason: &str| Error::InvalidStatusFilter {
            expr: expr.to_string(),
            reason: reason.to_string(),
        };
        let mut rules = Vec::new();
        for token in expr.split(',').map(str::trim) {
            if token.is_empty() {
                return Err(invalid("empty element"));
            }
            let lower = token.to_ascii_lowercase();
            let rule = if let Some(class) = lower.strip_suffix("xx") {
                match class.parse::<u16>() {
                    Ok(d) if (1..=9).contains(&d) && class.len() == 1 => {
                        StatusRule::Range(d * 100, d * 100 + 99)
                    }
                    _ => return Err(invalid(&format!("`{token}` is not a status class"))),
                }
            } else if let Some((lo, hi)) = token.split_once('-') {
                let (lo, hi) = (parse_code(expr, lo)?, parse_code(expr, hi)?);
                if lo > hi {
                    return Err(invalid(&format!("range {lo}-{hi} is reversed")));
                }
                StatusRule::Range(lo, hi)
            } else {
                StatusRule::Exact(parse_code(expr, token)?)
            };
            rules.push(rule);
        }
        Ok(StatusFilter { rules })
    }
}

/// One element of an IP filter.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IpRule {
    Addr(IpAddr),
    Net { addr: IpAddr, prefix: u8 },
    Literal(String),
}

/// A set of client addresses: exact IPs, CIDR networks (`192.0.2.0/24`) or,
/// for non-IP client fields such as host names, literal strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFilter {
    rules: Vec<IpRule>,
}

impl IpFilter {
    /// Returns `true` if the client field `ip` is selected by this filter.
    pub fn matches(&self, ip: &str) -> bool {
        let parsed: Option<IpAddr> = ip.parse().ok();
        self.rules.iter().any(|rule| match (rule, parsed) {
            (IpRule::Addr(a), Some(p)) => *a == p,
            (IpRule::Net { addr, prefix }, Some(p)) => in_network(p, *addr, *prefix),
            (IpRule::Literal(s), _) => s == ip,
            _ => false,
        })
    }
}

fn in_network(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

impl FromStr for IpFilter {
    type Err = Error;

    fn from_str(expr: &str) -> Result<Self> {
        let invalid = || Error::InvalidIpFilter(expr.to_string());
        let mut rules = Vec::new();
        for token in expr.split(',').map(str::trim) {
            if token.is_empty() {
                return Err(invalid());
            }
            let rule = if let Some((addr, prefix)) = token.split_once('/') {
                let addr: IpAddr = addr.parse().map_err(|_| invalid())?;
                let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
                let max = if addr.is_ipv4() { 32 } else { 128 };
                if prefix > max {
                    return Err(invalid());
                }
                IpRule::Net { addr, prefix }
            } else if let Ok(addr) = token.parse::<IpAddr>() {
                IpRule::Addr(addr)
            } else if token.chars().any(char::is_whitespace) {
                return Err(invalid());
            } else {
                IpRule::Literal(token.to_string())
            };
            rules.push(rule);
        }
        Ok(IpFilter { rules })
    }
}

/// A conjunction of optional criteria; a record passes when it satisfies all
/// configured criteria. The default filter accepts everything.
///
/// Records lacking a field that a criterion needs (e.g. no timestamp while
/// `since` is set) are rejected.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Allowed status codes.
    pub status: Option<StatusFilter>,
    /// Regex the (normalized) path must match.
    pub path: Option<Regex>,
    /// Allowed HTTP methods (case-insensitive); empty means any.
    pub methods: Vec<String>,
    /// Inclusive lower time bound.
    pub since: Option<DateTime<FixedOffset>>,
    /// Exclusive upper time bound.
    pub until: Option<DateTime<FixedOffset>>,
    /// Allowed client addresses.
    pub ip: Option<IpFilter>,
}

impl Filter {
    /// Returns `true` if the filter accepts everything.
    pub fn is_empty(&self) -> bool {
        self.status.is_none()
            && self.path.is_none()
            && self.methods.is_empty()
            && self.since.is_none()
            && self.until.is_none()
            && self.ip.is_none()
    }

    /// Returns `true` if `record` passes every configured criterion.
    pub fn matches(&self, record: &LogRecord) -> bool {
        self.status_ok(record)
            && self.method_ok(record)
            && self.path_ok(record)
            && self.time_ok(record)
            && self.ip_ok(record)
    }

    fn status_ok(&self, r: &LogRecord) -> bool {
        match &self.status {
            None => true,
            Some(f) => r.status.is_some_and(|s| f.matches(s)),
        }
    }

    fn method_ok(&self, r: &LogRecord) -> bool {
        self.methods.is_empty()
            || r.method
                .as_deref()
                .is_some_and(|m| self.methods.iter().any(|x| x.eq_ignore_ascii_case(m)))
    }

    fn path_ok(&self, r: &LogRecord) -> bool {
        match &self.path {
            None => true,
            Some(re) => r.path.as_deref().is_some_and(|p| re.is_match(p)),
        }
    }

    fn time_ok(&self, r: &LogRecord) -> bool {
        if self.since.is_none() && self.until.is_none() {
            return true;
        }
        let Some(ts) = r.timestamp else {
            return false;
        };
        self.since.is_none_or(|s| ts >= s) && self.until.is_none_or(|u| ts < u)
    }

    fn ip_ok(&self, r: &LogRecord) -> bool {
        match &self.ip {
            None => true,
            Some(f) => r.ip.as_deref().is_some_and(|ip| f.matches(ip)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::parse_timestamp;

    fn record(status: u16, method: &str, path: &str, ip: &str, ts: &str) -> LogRecord {
        LogRecord {
            timestamp: parse_timestamp(ts),
            ip: Some(ip.to_string()),
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            status: Some(status),
            bytes: Some(100),
            latency_ms: None,
        }
    }

    #[test]
    fn status_filter_forms() {
        let f: StatusFilter = "404, 5xx,300-302".parse().expect("valid");
        assert!(f.matches(404));
        assert!(f.matches(503));
        assert!(f.matches(301));
        assert!(!f.matches(200));
        assert!(!f.matches(403));
        assert!(!f.matches(303));
    }

    #[test]
    fn status_filter_errors() {
        for bad in ["", "abc", "10xx", "0xx", "499-400", "42", "404,", "1000"] {
            assert!(bad.parse::<StatusFilter>().is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn ip_filter_forms() {
        let f: IpFilter = "192.0.2.0/24,198.51.100.7,2001:db8::/32,gateway"
            .parse()
            .expect("valid");
        assert!(f.matches("192.0.2.200"));
        assert!(f.matches("198.51.100.7"));
        assert!(!f.matches("198.51.100.8"));
        assert!(f.matches("2001:db8::1"));
        assert!(f.matches("gateway"));
        assert!(!f.matches("203.0.113.1"));
        let all: IpFilter = "0.0.0.0/0".parse().expect("valid");
        assert!(all.matches("203.0.113.1"));
        assert!(!all.matches("2001:db8::1"));
    }

    #[test]
    fn ip_filter_errors() {
        for bad in ["", "192.0.2.0/33", "nonsense/8", "a b", "192.0.2.1,"] {
            assert!(bad.parse::<IpFilter>().is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn default_filter_accepts_everything() {
        let f = Filter::default();
        assert!(f.is_empty());
        assert!(f.matches(&LogRecord::default()));
    }

    #[test]
    fn combined_criteria() {
        let f = Filter {
            status: Some("2xx".parse().expect("valid")),
            path: Some(Regex::new("^/api/").expect("valid")),
            methods: vec!["get".to_string()],
            since: parse_timestamp("2026-03-14T10:00:00Z"),
            until: parse_timestamp("2026-03-14T11:00:00Z"),
            ip: Some("192.0.2.0/24".parse().expect("valid")),
        };
        assert!(!f.is_empty());
        let ok = record(200, "GET", "/api/x", "192.0.2.1", "2026-03-14T10:30:00Z");
        assert!(f.matches(&ok));
        assert!(!f.matches(&LogRecord {
            status: Some(500),
            ..ok.clone()
        }));
        assert!(!f.matches(&record(
            200,
            "POST",
            "/api/x",
            "192.0.2.1",
            "2026-03-14T10:30:00Z"
        )));
        assert!(!f.matches(&record(
            200,
            "GET",
            "/web",
            "192.0.2.1",
            "2026-03-14T10:30:00Z"
        )));
        assert!(!f.matches(&record(
            200,
            "GET",
            "/api/x",
            "10.0.0.1",
            "2026-03-14T10:30:00Z"
        )));
        // `until` is exclusive, `since` inclusive.
        assert!(!f.matches(&record(
            200,
            "GET",
            "/api/x",
            "192.0.2.1",
            "2026-03-14T11:00:00Z"
        )));
        assert!(f.matches(&record(
            200,
            "GET",
            "/api/x",
            "192.0.2.1",
            "2026-03-14T10:00:00Z"
        )));
        assert!(!f.matches(&LogRecord {
            timestamp: None,
            ..ok
        }));
    }
}
