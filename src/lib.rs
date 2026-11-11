//! # logscope
//!
//! A fast, streaming analyzer for HTTP access logs.
//!
//! `logscope` reads Nginx/Apache *combined* (or *common*) access logs and
//! JSON-lines logs line by line, applies optional filters and aggregates
//! counters (status codes, paths, client IPs, methods, time windows, bytes and
//! latency). Memory usage depends on the number of distinct keys, not on the
//! number of lines.
//!
//! The pipeline is: [`input::open_input`] → [`Parser`] → [`Filter`] →
//! [`Stats`] → [`Report`] → [`output::write_report`]. [`Analyzer`] wires the
//! middle part together.
//!
//! ```
//! use logscope::{Analyzer, Filter, LogFormat, Parser, Stats};
//!
//! let log = concat!(
//!     "192.0.2.1 - - [14/Mar/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 512 \"-\" \"curl/8.5.0\"\n",
//!     "{\"time\":\"2026-03-14T10:00:05Z\",\"status\":404,\"path\":\"/missing\"}\n",
//! );
//! let filter = Filter { status: Some("2xx".parse()?), ..Filter::default() };
//! let mut analyzer = Analyzer::new(LogFormat::Combined, Parser::default(), filter, Stats::new(None));
//! analyzer.process_reader("example", log.as_bytes())?;
//!
//! let report = analyzer.stats().report(10);
//! assert_eq!(report.summary.lines, 2);
//! assert_eq!(report.summary.malformed, 1); // the JSON line is not a combined line
//! assert_eq!(report.summary.matched, 1);
//! assert_eq!(report.top_paths[0].key, "/");
//! # Ok::<(), logscope::Error>(())
//! ```

#![warn(missing_docs)]

pub mod analyzer;
pub mod error;
pub mod filter;
pub mod input;
pub mod output;
pub mod parser;
pub mod record;
pub mod stats;
pub mod time;

pub use analyzer::Analyzer;
pub use error::{Error, Result};
pub use filter::{Filter, IpFilter, StatusFilter};
pub use output::{write_report, OutputFormat};
pub use parser::{Field, JsonFields, LatencyUnit, LogFormat, ParseOptions, Parser};
pub use record::LogRecord;
pub use stats::{Report, Stats, WindowSpec};
