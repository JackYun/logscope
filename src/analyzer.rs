//! Drives parsing, filtering and aggregation over line-oriented readers.

use std::io::BufRead;

use crate::error::{Error, Result};
use crate::filter::Filter;
use crate::parser::{LogFormat, Parser};
use crate::stats::Stats;

/// Streams lines from one or more readers through a [`Parser`], a [`Filter`]
/// and into [`Stats`].
#[derive(Debug, Clone)]
pub struct Analyzer {
    format: LogFormat,
    parser: Parser,
    filter: Filter,
    stats: Stats,
    strict: bool,
}

impl Analyzer {
    /// Creates an analyzer. With [`LogFormat::Auto`] the format is detected
    /// separately for every input passed to [`Analyzer::process_reader`].
    pub fn new(format: LogFormat, parser: Parser, filter: Filter, stats: Stats) -> Self {
        Analyzer {
            format,
            parser,
            filter,
            stats,
            strict: false,
        }
    }

    /// In strict mode the first malformed line aborts processing with
    /// [`Error::Malformed`].
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Processes every line of `reader`. `source` names the input in errors.
    ///
    /// Blank lines are ignored. Invalid UTF-8 is replaced rather than
    /// rejected. In auto mode the format is locked to the first line that
    /// parses successfully; earlier lines that fail are counted as malformed.
    ///
    /// Returns the concrete format that was used (`Auto` if no line parsed).
    pub fn process_reader<R: BufRead>(&mut self, source: &str, mut reader: R) -> Result<LogFormat> {
        let mut format = self.format;
        let mut buf = Vec::with_capacity(1024);
        let mut line_no: u64 = 0;
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf).map_err(|e| Error::Io {
                source_name: source.to_string(),
                source: e,
            })?;
            if n == 0 {
                break;
            }
            line_no += 1;
            let text = String::from_utf8_lossy(&buf);
            let line = text.trim_end_matches(['\n', '\r']);
            if line.trim().is_empty() {
                continue;
            }
            self.stats.count_line();

            let parsed = if format == LogFormat::Auto {
                let guess = LogFormat::detect(line);
                let parsed = self.parser.parse_line(guess, line);
                if parsed.is_some() {
                    format = guess;
                }
                parsed
            } else {
                self.parser.parse_line(format, line)
            };

            match parsed {
                Some(record) => {
                    if self.filter.matches(&record) {
                        self.stats.record(&record);
                    }
                }
                None => {
                    self.stats.count_malformed();
                    if self.strict {
                        return Err(Error::Malformed {
                            source_name: source.to_string(),
                            line: line_no,
                        });
                    }
                }
            }
        }
        Ok(format)
    }

    /// The statistics gathered so far.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Consumes the analyzer, returning the statistics.
    pub fn into_stats(self) -> Stats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIXED: &str = concat!(
        "garbage first\n",
        "\n",
        "192.0.2.1 - - [14/Mar/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 10\r\n",
        "198.51.100.2 - - [14/Mar/2026:10:00:01 +0000] \"GET /x HTTP/1.1\" 404 5\n",
        "{\"status\": 200}\n",
    );

    fn analyzer(format: LogFormat) -> Analyzer {
        Analyzer::new(
            format,
            Parser::default(),
            Filter::default(),
            Stats::new(None),
        )
    }

    #[test]
    fn auto_detects_and_counts_malformed() {
        let mut a = analyzer(LogFormat::Auto);
        let used = a.process_reader("test", MIXED.as_bytes()).expect("ok");
        assert_eq!(used, LogFormat::Combined);
        let s = a.stats();
        assert_eq!(s.lines(), 4);
        assert_eq!(s.malformed(), 2);
        assert_eq!(s.matched(), 2);
    }

    #[test]
    fn strict_mode_reports_line_number() {
        let mut a = analyzer(LogFormat::Combined).strict(true);
        let err = a
            .process_reader("test.log", MIXED.as_bytes())
            .expect_err("strict");
        assert_eq!(
            err.to_string(),
            "test.log:1: malformed log line (strict mode)"
        );
    }

    #[test]
    fn filters_are_applied() {
        let filter = Filter {
            status: Some("4xx".parse().expect("valid")),
            ..Filter::default()
        };
        let mut a = Analyzer::new(
            LogFormat::Combined,
            Parser::default(),
            filter,
            Stats::new(None),
        );
        a.process_reader("test", MIXED.as_bytes()).expect("ok");
        let stats = a.into_stats();
        assert_eq!(stats.parsed(), 2);
        assert_eq!(stats.matched(), 1);
    }

    #[test]
    fn invalid_utf8_is_tolerated() {
        let mut data = b"192.0.2.1 - - [14/Mar/2026:10:00:00 +0000] \"GET /caf".to_vec();
        data.extend_from_slice(&[0xff, 0xfe]);
        data.extend_from_slice(b" HTTP/1.1\" 200 10\n");
        let mut a = analyzer(LogFormat::Auto);
        a.process_reader("test", data.as_slice()).expect("ok");
        assert_eq!(a.stats().matched(), 1);
    }
}
