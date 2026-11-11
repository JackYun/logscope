//! Command-line entry point for `logscope`.

use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Result};
use chrono::{DateTime, FixedOffset};
use clap::{Parser as ClapParser, ValueEnum};
use regex::Regex;

use logscope::input::{display_name, open_input};
use logscope::time::parse_time_bound;
use logscope::{
    write_report, Analyzer, Filter, IpFilter, JsonFields, LatencyUnit, LogFormat, OutputFormat,
    ParseOptions, Parser, Stats, StatusFilter, WindowSpec,
};

const EXAMPLES: &str = "\
Examples:
  logscope access.log
  logscope --top 5 --window 5m access.log.gz
  logscope --status 5xx,404 --method GET,POST --output json access.log
  logscope --since 2026-03-14T10:00:00Z --until '14/Mar/2026:11:00:00 +0000' access.log
  cat app.jsonl | logscope --format json --field status=http.code -";

/// Fast, streaming analyzer for Nginx/Apache access logs and JSON-lines logs.
#[derive(Debug, ClapParser)]
#[command(name = "logscope", version, about, after_help = EXAMPLES)]
struct Cli {
    /// Log files to analyze; `-` or no file reads stdin. Gzip input is
    /// decompressed automatically.
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Input format (`auto` detects it per file).
    #[arg(short, long, value_enum, default_value_t = FormatArg::Auto)]
    format: FormatArg,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputArg::Table)]
    output: OutputArg,

    /// Number of entries in the top-N lists (paths, IPs, methods); 0 = all.
    #[arg(short = 'n', long, default_value_t = 10, value_name = "N")]
    top: usize,

    /// Add a per-time-window breakdown, e.g. 1m, 5m, 1h, 1d.
    #[arg(short, long, value_name = "WIDTH")]
    window: Option<WindowSpec>,

    /// Keep only these status codes: 404, 5xx, 400-499 or a comma list.
    #[arg(short, long, value_name = "SPEC")]
    status: Option<StatusFilter>,

    /// Keep only paths matching this regular expression.
    #[arg(short, long, value_name = "REGEX", value_parser = Regex::new)]
    path: Option<Regex>,

    /// Keep only these HTTP methods (comma separated, case-insensitive).
    #[arg(short, long, value_name = "METHOD", value_delimiter = ',')]
    method: Vec<String>,

    /// Keep entries at or after this time (RFC3339, nginx format or YYYY-MM-DD).
    #[arg(long, value_name = "TIME", value_parser = parse_time_bound)]
    since: Option<DateTime<FixedOffset>>,

    /// Keep entries strictly before this time (same formats as --since).
    #[arg(long, value_name = "TIME", value_parser = parse_time_bound)]
    until: Option<DateTime<FixedOffset>>,

    /// Keep only these clients: IPs, CIDR networks, comma separated.
    #[arg(long, value_name = "ADDRS")]
    ip: Option<IpFilter>,

    /// Fail on the first malformed line instead of skipping it.
    #[arg(long)]
    strict: bool,

    /// Keep query strings in paths (default: strip `?...`).
    #[arg(long)]
    keep_query: bool,

    /// Map a field to a JSON key, e.g. `status=http.code` (repeatable).
    /// Fields: timestamp, status, method, path, ip, bytes, latency.
    #[arg(long = "field", value_name = "FIELD=KEY")]
    fields: Vec<String>,

    /// Unit of the JSON key given with `--field latency=...`.
    #[arg(long, value_enum, default_value_t = LatencyUnitArg::Ms, value_name = "UNIT")]
    latency_unit: LatencyUnitArg,

    /// Do not print the malformed-line notice on stderr.
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatArg {
    Auto,
    #[value(alias = "common")]
    Combined,
    #[value(alias = "jsonl")]
    Json,
}

impl From<FormatArg> for LogFormat {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Auto => LogFormat::Auto,
            FormatArg::Combined => LogFormat::Combined,
            FormatArg::Json => LogFormat::Json,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputArg {
    Table,
    Json,
    Csv,
}

impl From<OutputArg> for OutputFormat {
    fn from(o: OutputArg) -> Self {
        match o {
            OutputArg::Table => OutputFormat::Table,
            OutputArg::Json => OutputFormat::Json,
            OutputArg::Csv => OutputFormat::Csv,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LatencyUnitArg {
    Ms,
    S,
}

impl From<LatencyUnitArg> for LatencyUnit {
    fn from(u: LatencyUnitArg) -> Self {
        match u {
            LatencyUnitArg::Ms => LatencyUnit::Milliseconds,
            LatencyUnitArg::S => LatencyUnit::Seconds,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) if is_broken_pipe(&err) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("logscope: error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// `logscope ... | head` closes stdout early; that is not an error.
fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        e.downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
    })
}

fn run(cli: Cli) -> Result<()> {
    if let (Some(since), Some(until)) = (cli.since, cli.until) {
        if since >= until {
            bail!("--since ({since}) must be earlier than --until ({until})");
        }
    }

    let mut json_fields = JsonFields::default();
    for spec in &cli.fields {
        json_fields.parse_mapping(spec)?;
    }
    let parser = Parser::new(ParseOptions {
        keep_query: cli.keep_query,
        json_fields,
        latency_unit: cli.latency_unit.into(),
    });
    let filter = Filter {
        status: cli.status,
        path: cli.path,
        methods: cli
            .method
            .iter()
            .map(|m| m.trim().to_ascii_uppercase())
            .collect(),
        since: cli.since,
        until: cli.until,
        ip: cli.ip,
    };
    let mut analyzer =
        Analyzer::new(cli.format.into(), parser, filter, Stats::new(cli.window)).strict(cli.strict);

    let inputs = if cli.files.is_empty() {
        vec![PathBuf::from("-")]
    } else {
        cli.files
    };
    for path in &inputs {
        let name = display_name(path);
        let reader = open_input(path)?;
        analyzer.process_reader(&name, reader)?;
    }

    let stats = analyzer.into_stats();
    let report = stats.report(cli.top);
    let mut out = BufWriter::new(io::stdout().lock());
    write_report(&report, cli.output.into(), &mut out)?;
    out.flush()?;

    if stats.malformed() > 0 && !cli.quiet {
        eprintln!(
            "logscope: skipped {} malformed line(s) out of {}",
            stats.malformed(),
            stats.lines()
        );
    }
    Ok(())
}
