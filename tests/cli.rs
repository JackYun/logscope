//! End-to-end tests that run the `logscope` binary against the fixtures.

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn logscope() -> Command {
    Command::new(env!("CARGO_BIN_EXE_logscope"))
}

/// Runs logscope with `--output json` and the given arguments, returning the parsed report.
fn json_report(args: &[&str]) -> Value {
    let output = logscope()
        .args(["--output", "json"])
        .args(args)
        .output()
        .expect("run logscope");
    assert!(
        output.status.success(),
        "logscope failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("valid JSON output")
}

fn counts(list: &Value) -> Vec<(String, u64)> {
    list.as_array()
        .expect("array")
        .iter()
        .map(|e| {
            (
                e["key"].as_str().expect("key").to_string(),
                e["count"].as_u64().expect("count"),
            )
        })
        .collect()
}

fn pairs(items: &[(&str, u64)]) -> Vec<(String, u64)> {
    items.iter().map(|(k, c)| (k.to_string(), *c)).collect()
}

#[test]
fn combined_log_summary() {
    let r = json_report(&[&fixture("access.log")]);
    let s = &r["summary"];
    assert_eq!(s["lines"], 32);
    assert_eq!(s["parsed"], 32);
    assert_eq!(s["malformed"], 0);
    assert_eq!(s["matched"], 32);
    assert_eq!(s["unique_ips"], 7);
    assert_eq!(s["first_seen"], "2026-03-14T10:00:01Z");
    assert_eq!(s["last_seen"], "2026-03-14T10:58:59Z");
    assert_eq!(
        counts(&r["status_classes"]),
        pairs(&[("2xx", 21), ("3xx", 3), ("4xx", 5), ("5xx", 3)])
    );
    assert_eq!(r["top_paths"][0]["key"], "/api/v1/items");
    assert_eq!(r["top_paths"][0]["count"], 7);
    assert_eq!(
        counts(&r["top_ips"])[..2],
        pairs(&[("10.0.0.8", 6), ("192.0.2.23", 6)])[..]
    );
    assert!(r.get("windows").is_none());
}

#[test]
fn table_output_is_default() {
    logscope()
        .arg(fixture("access.log"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Summary"))
        .stdout(predicate::str::contains("Status classes"))
        .stdout(predicate::str::contains("Top paths"))
        .stdout(predicate::str::contains("/api/v1/items"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn status_filters() {
    assert_eq!(
        json_report(&["--status", "5xx", &fixture("access.log")])["summary"]["matched"],
        3
    );
    assert_eq!(
        json_report(&["--status", "404,502", &fixture("access.log")])["summary"]["matched"],
        5
    );
    let r = json_report(&[
        "--status",
        "400-499",
        "--method",
        "get",
        &fixture("access.log"),
    ]);
    assert_eq!(r["summary"]["matched"], 4);
}

#[test]
fn path_ip_and_method_filters() {
    let api = json_report(&["--path", "^/api/", &fixture("access.log")]);
    assert_eq!(api["summary"]["matched"], 12);

    let net = json_report(&["--ip", "192.0.2.0/24", &fixture("access.log")]);
    assert_eq!(net["summary"]["matched"], 11);

    let one = json_report(&["--ip", "10.0.0.8", &fixture("access.log")]);
    assert_eq!(one["summary"]["matched"], 6);

    let writes = json_report(&["-m", "POST,PUT,DELETE", &fixture("access.log")]);
    assert_eq!(writes["summary"]["matched"], 5);
}

#[test]
fn time_range_filter_accepts_rfc3339_and_nginx_formats() {
    let r = json_report(&[
        "--since",
        "2026-03-14T10:30:00Z",
        "--until",
        "14/Mar/2026:10:45:00 +0000",
        &fixture("access.log"),
    ]);
    assert_eq!(r["summary"]["matched"], 6);
    assert_eq!(r["summary"]["first_seen"], "2026-03-14T10:30:00Z");
}

#[test]
fn time_windows() {
    let r = json_report(&["--window", "10m", &fixture("access.log")]);
    assert_eq!(r["windows"]["width"], "10m");
    let buckets: Vec<(String, u64)> = r["windows"]["buckets"]
        .as_array()
        .expect("array")
        .iter()
        .map(|b| {
            (
                b["start"].as_str().expect("start").to_string(),
                b["count"].as_u64().expect("count"),
            )
        })
        .collect();
    assert_eq!(
        buckets,
        pairs(&[
            ("2026-03-14T10:00:00Z", 10),
            ("2026-03-14T10:10:00Z", 8),
            ("2026-03-14T10:20:00Z", 4),
            ("2026-03-14T10:30:00Z", 3),
            ("2026-03-14T10:40:00Z", 4),
            ("2026-03-14T10:50:00Z", 3),
        ])
    );
}

#[test]
fn top_n_limits_lists() {
    let r = json_report(&["--top", "3", &fixture("access.log")]);
    assert_eq!(r["top_paths"].as_array().expect("array").len(), 3);
    assert_eq!(r["top_ips"].as_array().expect("array").len(), 3);
    let all = json_report(&["--top", "0", &fixture("access.log")]);
    assert_eq!(
        all["top_paths"].as_array().expect("array").len() as u64,
        all["summary"]["unique_paths"].as_u64().expect("u64")
    );
}

#[test]
fn keep_query_preserves_query_strings() {
    let r = json_report(&["--keep-query", "--top", "0", &fixture("access.log")]);
    let paths = counts(&r["top_paths"]);
    assert!(paths.iter().any(|(k, _)| k == "/api/v1/items?page=2"));
}

#[test]
fn json_lines_are_auto_detected() {
    let r = json_report(&[&fixture("app.jsonl")]);
    let s = &r["summary"];
    assert_eq!(s["lines"], 16);
    assert_eq!(s["matched"], 16);
    assert_eq!(s["malformed"], 0);
    assert_eq!(s["latency"]["samples"], 16);
    assert_eq!(s["latency"]["max_ms"], 1500.0);
    let codes = counts(&r["status_codes"]);
    assert!(codes.contains(&("204".to_string(), 1)), "{codes:?}");
    assert!(codes.contains(&("401".to_string(), 2)), "{codes:?}");
}

#[test]
fn json_field_mapping() {
    let r = json_report(&[
        "--format",
        "json",
        "--field",
        "timestamp=when",
        "--field",
        "ip=client.addr",
        "--field",
        "method=req.verb",
        "--field",
        "path=req.uri",
        "--field",
        "status=res.code",
        "--field",
        "bytes=res.size",
        "--field",
        "latency=took",
        "--latency-unit",
        "s",
        &fixture("custom.jsonl"),
    ]);
    let s = &r["summary"];
    assert_eq!(s["matched"], 4);
    assert_eq!(s["total_bytes"], 18_676);
    assert_eq!(s["first_seen"], "2026-03-14T11:00:00Z");
    assert_eq!(s["latency"]["max_ms"], 120.0);
    assert_eq!(r["top_paths"][0]["key"], "/feed.xml");
    assert_eq!(r["top_ips"][0]["key"], "192.0.2.50");
}

#[test]
fn malformed_lines_are_counted_and_reported() {
    let output = logscope()
        .args(["--output", "json", &fixture("malformed.log")])
        .output()
        .expect("run");
    assert!(output.status.success());
    let r: Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(r["summary"]["lines"], 7);
    assert_eq!(r["summary"]["malformed"], 3);
    assert_eq!(r["summary"]["matched"], 4);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("skipped 3 malformed line(s) out of 7"),
        "{stderr}"
    );

    logscope()
        .args(["--quiet", &fixture("malformed.log")])
        .assert()
        .success()
        .stderr(predicate::str::is_empty());
}

#[test]
fn strict_mode_fails_on_first_malformed_line() {
    logscope()
        .args(["--strict", &fixture("malformed.log")])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "malformed.log:2: malformed log line",
        ));
}

#[test]
fn forced_wrong_format_marks_everything_malformed() {
    let r = json_report(&["--quiet", "--format", "json", &fixture("access.log")]);
    assert_eq!(r["summary"]["malformed"], 32);
    assert_eq!(r["summary"]["matched"], 0);
}

#[test]
fn reads_stdin_without_args_and_with_dash() {
    let input = std::fs::read(fixture("access.log")).expect("fixture");
    for args in [&[][..], &["-"][..]] {
        let output = logscope()
            .args(["--output", "json"])
            .args(args)
            .write_stdin(input.clone())
            .output()
            .expect("run");
        assert!(output.status.success());
        let r: Value = serde_json::from_slice(&output.stdout).expect("json");
        assert_eq!(r["summary"]["matched"], 32);
    }
}

#[test]
fn gzip_input_matches_plain_input() {
    let plain = json_report(&[&fixture("access.log")]);
    let gz = json_report(&[&fixture("access.log.gz")]);
    assert_eq!(plain, gz);
}

#[test]
fn multiple_files_with_mixed_formats() {
    let r = json_report(&[&fixture("access.log"), &fixture("app.jsonl")]);
    assert_eq!(r["summary"]["lines"], 48);
    assert_eq!(r["summary"]["matched"], 48);
    assert_eq!(r["summary"]["last_seen"], "2026-03-14T11:14:00Z");
}

#[test]
fn csv_output() {
    logscope()
        .args(["--output", "csv", "--window", "1h", &fixture("access.log")])
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "section,key,value,percent,bytes\n",
        ))
        .stdout(predicate::str::contains("summary,lines,32,,\n"))
        .stdout(predicate::str::contains("status_class,2xx,21,65.63,"))
        .stdout(predicate::str::contains("window,2026-03-14T10:00:00Z,32,,"));
}

#[test]
fn invalid_arguments_are_rejected() {
    for args in [
        &["--status", "abc"][..],
        &["--window", "5x"][..],
        &["--since", "yesterday"][..],
        &["--ip", "192.0.2.0/99"][..],
        &["--path", "("][..],
        &["--field", "colour=x"][..],
    ] {
        logscope()
            .args(args)
            .arg(fixture("access.log"))
            .assert()
            .failure()
            .stderr(predicate::str::contains("invalid"));
    }
    logscope()
        .args(["--since", "2026-03-15", "--until", "2026-03-14"])
        .arg(fixture("access.log"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("must be earlier"));
}

#[test]
fn missing_file_is_an_error() {
    logscope()
        .arg(fixture("does-not-exist.log"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("does-not-exist.log"));
}
