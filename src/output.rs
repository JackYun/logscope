//! Rendering a [`Report`] as a human-readable table, JSON or CSV.

use std::io::{self, Write};

use crate::stats::{CountEntry, Report};

/// Output format for [`write_report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Aligned plain-text tables for terminals.
    #[default]
    Table,
    /// Pretty-printed JSON document.
    Json,
    /// Flat CSV with the columns `section,key,value,percent,bytes`.
    Csv,
}

/// Writes `report` to `out` in the requested format.
pub fn write_report<W: Write>(report: &Report, format: OutputFormat, out: W) -> io::Result<()> {
    match format {
        OutputFormat::Table => write_table(report, out),
        OutputFormat::Json => write_json(report, out),
        OutputFormat::Csv => write_csv(report, out),
    }
}

/// Writes the report as pretty JSON followed by a newline.
pub fn write_json<W: Write>(report: &Report, mut out: W) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut out, report)?;
    writeln!(out)
}

/// Writes the report as CSV.
///
/// Every row has the columns `section,key,value,percent,bytes`. Summary rows
/// use `section=summary` with the metric name as key; time-window rows use
/// `section=window` with the bucket start as key and the request count as value.
pub fn write_csv<W: Write>(report: &Report, out: W) -> io::Result<()> {
    let mut w = csv::Writer::from_writer(out);
    w.write_record(["section", "key", "value", "percent", "bytes"])?;

    let s = &report.summary;
    let mut summary: Vec<(&str, String)> = vec![
        ("lines", s.lines.to_string()),
        ("parsed", s.parsed.to_string()),
        ("malformed", s.malformed.to_string()),
        ("matched", s.matched.to_string()),
        ("total_bytes", s.total_bytes.to_string()),
        ("unique_ips", s.unique_ips.to_string()),
        ("unique_paths", s.unique_paths.to_string()),
        ("first_seen", s.first_seen.clone().unwrap_or_default()),
        ("last_seen", s.last_seen.clone().unwrap_or_default()),
    ];
    if let Some(l) = &s.latency {
        summary.extend([
            ("latency_samples", l.samples.to_string()),
            ("latency_avg_ms", l.avg_ms.to_string()),
            ("latency_min_ms", l.min_ms.to_string()),
            ("latency_max_ms", l.max_ms.to_string()),
        ]);
    }
    for (key, value) in summary {
        w.write_record(["summary", key, value.as_str(), "", ""])?;
    }

    let sections: [(&str, &[CountEntry]); 5] = [
        ("status_class", &report.status_classes),
        ("status", &report.status_codes),
        ("method", &report.methods),
        ("path", &report.top_paths),
        ("ip", &report.top_ips),
    ];
    for (section, entries) in sections {
        for e in entries {
            w.write_record([
                section,
                e.key.as_str(),
                e.count.to_string().as_str(),
                format!("{:.2}", e.percent).as_str(),
                e.bytes.to_string().as_str(),
            ])?;
        }
    }
    if let Some(windows) = &report.windows {
        for b in &windows.buckets {
            w.write_record([
                "window",
                b.start.as_str(),
                b.count.to_string().as_str(),
                "",
                b.bytes.to_string().as_str(),
            ])?;
        }
    }
    w.flush()
}

/// Groups the digits of `n` with commas: `1234567` -> `1,234,567`.
pub fn group_digits(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Formats a byte count with binary units: `2048` -> `2.0 KiB`.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Shortens `s` to at most `max` characters, marking the cut with `...`.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max.saturating_sub(3)).collect();
        format!("{kept}...")
    }
}

const MAX_KEY_WIDTH: usize = 60;

/// Writes one aligned table: the first column left-aligned, the rest right-aligned.
fn table<W: Write>(
    out: &mut W,
    title: &str,
    headers: &[&str],
    rows: &[Vec<String>],
) -> io::Result<()> {
    writeln!(out, "{title}")?;
    if rows.is_empty() {
        writeln!(out, "  (no data)")?;
        return writeln!(out);
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let render = |cells: &[&str]| -> String {
        let mut line = String::from(" ");
        for (i, (cell, w)) in cells.iter().zip(&widths).enumerate() {
            line.push(' ');
            if i == 0 {
                line.push_str(&format!("{cell:<w$}"));
            } else {
                line.push_str(&format!(" {cell:>w$}"));
            }
        }
        line.trim_end().to_string()
    };
    writeln!(out, "{}", render(headers))?;
    let rule: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    let rule_refs: Vec<&str> = rule.iter().map(String::as_str).collect();
    writeln!(out, "{}", render(&rule_refs))?;
    for row in rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        writeln!(out, "{}", render(&cells))?;
    }
    writeln!(out)
}

fn count_rows(entries: &[CountEntry]) -> Vec<Vec<String>> {
    entries
        .iter()
        .map(|e| {
            vec![
                truncate(&e.key, MAX_KEY_WIDTH),
                group_digits(e.count),
                format!("{:.2}%", e.percent),
                human_bytes(e.bytes),
            ]
        })
        .collect()
}

/// Writes the report as aligned plain-text tables.
pub fn write_table<W: Write>(report: &Report, mut out: W) -> io::Result<()> {
    let s = &report.summary;
    let mut kv: Vec<(&str, String)> = vec![
        ("Lines read", group_digits(s.lines)),
        ("Parsed", group_digits(s.parsed)),
        ("Malformed (skipped)", group_digits(s.malformed)),
        ("Matched filters", group_digits(s.matched)),
        (
            "Total bytes",
            format!(
                "{} ({} bytes)",
                human_bytes(s.total_bytes),
                group_digits(s.total_bytes)
            ),
        ),
        ("Unique IPs", group_digits(s.unique_ips)),
        ("Unique paths", group_digits(s.unique_paths)),
    ];
    if let (Some(first), Some(last)) = (&s.first_seen, &s.last_seen) {
        kv.push(("Time range", format!("{first} .. {last}")));
    }
    if let Some(l) = &s.latency {
        kv.push((
            "Latency (ms)",
            format!(
                "avg {:.1}, min {:.1}, max {:.1} ({} samples)",
                l.avg_ms,
                l.min_ms,
                l.max_ms,
                group_digits(l.samples)
            ),
        ));
    }
    writeln!(out, "Summary")?;
    let width = kv.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in &kv {
        writeln!(out, "  {k:<width$}  {v}")?;
    }
    writeln!(out)?;

    let headers = ["", "REQUESTS", "PERCENT", "BYTES"];
    let sections: [(&str, &str, &[CountEntry]); 5] = [
        ("Status classes", "CLASS", &report.status_classes),
        ("Status codes", "STATUS", &report.status_codes),
        ("Methods", "METHOD", &report.methods),
        ("Top paths", "PATH", &report.top_paths),
        ("Top IPs", "IP", &report.top_ips),
    ];
    for (title, first, entries) in sections {
        let mut h = headers;
        h[0] = first;
        table(&mut out, title, &h, &count_rows(entries))?;
    }

    if let Some(windows) = &report.windows {
        let rows: Vec<Vec<String>> = windows
            .buckets
            .iter()
            .map(|b| {
                vec![
                    b.start.clone(),
                    group_digits(b.count),
                    group_digits(b.client_errors),
                    group_digits(b.server_errors),
                    human_bytes(b.bytes),
                ]
            })
            .collect();
        table(
            &mut out,
            &format!("Requests per {} window (UTC)", windows.width),
            &["WINDOW START", "REQUESTS", "4XX", "5XX", "BYTES"],
            &rows,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;
    use crate::stats::Stats;

    fn sample_report() -> Report {
        let parser = Parser::default();
        let mut stats = Stats::new("1h".parse().ok());
        for line in [
            r#"192.0.2.1 - - [14/Mar/2026:10:00:00 +0000] "GET /a HTTP/1.1" 200 2048 "-" "x""#,
            r#"192.0.2.2 - - [14/Mar/2026:10:30:00 +0000] "POST /b,c HTTP/1.1" 500 10 "-" "x""#,
        ] {
            stats.count_line();
            stats.record(&parser.parse_combined(line).expect("valid"));
        }
        stats.report(10)
    }

    #[test]
    fn formats_numbers() {
        assert_eq!(group_digits(0), "0");
        assert_eq!(group_digits(999), "999");
        assert_eq!(group_digits(1_000), "1,000");
        assert_eq!(group_digits(1_234_567), "1,234,567");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(truncate("abcdef", 5), "ab...");
        assert_eq!(truncate("abc", 5), "abc");
    }

    #[test]
    fn table_contains_sections() {
        let mut out = Vec::new();
        write_report(&sample_report(), OutputFormat::Table, &mut out).expect("write");
        let text = String::from_utf8(out).expect("utf8");
        for needle in [
            "Summary",
            "Status classes",
            "Top paths",
            "/b,c",
            "Requests per 1h window (UTC)",
            "2026-03-14T10:00:00Z",
        ] {
            assert!(text.contains(needle), "missing {needle}:\n{text}");
        }
    }

    #[test]
    fn json_round_trips() {
        let mut out = Vec::new();
        write_report(&sample_report(), OutputFormat::Json, &mut out).expect("write");
        let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
        assert_eq!(v["summary"]["matched"], 2);
        assert_eq!(v["status_codes"][1]["key"], "500");
        assert_eq!(v["windows"]["buckets"][0]["server_errors"], 1);
    }

    #[test]
    fn csv_is_quoted_correctly() {
        let mut out = Vec::new();
        write_report(&sample_report(), OutputFormat::Csv, &mut out).expect("write");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.starts_with("section,key,value,percent,bytes\n"));
        assert!(text.contains("path,\"/b,c\",1,50.00,10\n"), "{text}");
        assert!(
            text.contains("window,2026-03-14T10:00:00Z,2,,2058\n"),
            "{text}"
        );
    }
}
