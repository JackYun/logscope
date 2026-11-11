//! Error types for the `logscope` library.

use std::io;

use thiserror::Error;

/// Errors produced by the `logscope` library.
#[derive(Debug, Error)]
pub enum Error {
    /// Reading an input source failed.
    #[error("failed to read {source_name}: {source}")]
    Io {
        /// Human-readable name of the input (file path or `<stdin>`).
        source_name: String,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// A line could not be parsed and strict mode is enabled.
    #[error("{source_name}:{line}: malformed log line (strict mode)")]
    Malformed {
        /// Human-readable name of the input.
        source_name: String,
        /// 1-based line number of the offending line.
        line: u64,
    },

    /// A `--status` filter expression is invalid.
    #[error("invalid status filter `{expr}`: {reason}")]
    InvalidStatusFilter {
        /// The offending expression.
        expr: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A `--ip` filter expression is invalid.
    #[error("invalid IP filter `{0}`: expected an address, a CIDR network or a comma list")]
    InvalidIpFilter(String),

    /// A `--window` value is invalid.
    #[error("invalid window `{0}`: expected <number><s|m|h|d>, e.g. 5m or 1h")]
    InvalidWindow(String),

    /// A timestamp given on the command line could not be parsed.
    #[error(
        "invalid timestamp `{0}`: expected RFC3339 (2026-03-14T10:00:00Z), \
         nginx format (14/Mar/2026:10:00:00 +0000) or a date (2026-03-14)"
    )]
    InvalidTimestamp(String),

    /// A JSON field mapping (`--field name=key`) is invalid.
    #[error(
        "invalid field mapping `{0}`: expected <field>=<json-key> where field is one of \
         timestamp, status, method, path, ip, bytes, latency"
    )]
    InvalidFieldMapping(String),
}

/// Convenience result alias for the library.
pub type Result<T> = std::result::Result<T, Error>;
