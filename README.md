# logscope

[中文](#中文) | [English](#english)

---

## 中文

**logscope** 是一个用 Rust 编写的流式命令行日志分析工具，支持 Nginx/Apache 访问日志（combined / common 格式）和 JSON-lines 日志。它逐行读取，内存占用与日志行数无关，可以直接处理很大的日志文件、`.gz` 压缩日志或管道输入，并以表格、JSON 或 CSV 输出统计结果。

### 功能

- **输入格式**：Nginx/Apache `combined` 与 `common` 格式；JSON-lines（每行一个 JSON 对象）。`--format auto` 会按文件自动识别。
- **JSON 字段映射**：自动识别常见字段名；也可用 `--field status=http.code` 这类写法把任意（含嵌套）键映射到 timestamp / status / method / path / ip / bytes / latency。
- **输入来源**：一个或多个文件，或标准输入（不带文件或使用 `-`）。gzip 文件按文件头自动解压。
- **流式处理**：`BufReader` 逐行读取，只保存计数器；格式错误的行会被计数并跳过，`--strict` 时遇到第一条错误行即报错退出。
- **统计**：总量、状态码与状态类别（2xx/3xx/4xx/5xx）、路径、IP、方法、流量字节数、延迟（JSON 日志）、按时间窗口分桶（`--window 1m|5m|1h|1d`），Top-N（`--top N`，默认 10，0 表示全部）。
- **过滤**：`--status`（如 `404`、`5xx`、`400-499`、逗号列表）、`--path` 正则、`--method`、`--since` / `--until`（RFC3339、nginx 时间格式或 `YYYY-MM-DD`）、`--ip`（IP 或 CIDR 网段）。
- **输出**：`--output table|json|csv`。

### 安装

需要 Rust 1.82 或更新版本。

```bash
# 从源码安装到 ~/.cargo/bin
cargo install --path .

# 或者只编译
cargo build --release
./target/release/logscope --help
```

### 使用示例

下面的输出都是用仓库 `tests/fixtures/` 中的示例日志实际运行得到的。更多示例（gzip、CSV、JSON、自定义字段映射）见英文部分。

只看错误请求（4xx 和 5xx），每个排行显示前 3 条：

```console
$ logscope --status 4xx,5xx --top 3 tests/fixtures/access.log
Summary
  Lines read           32
  Parsed               32
  Malformed (skipped)  0
  Matched filters      8
  Total bytes          1.4 KiB (1,384 bytes)
  Unique IPs           4
  Unique paths         6
  Time range           2026-03-14T10:01:17Z .. 2026-03-14T10:41:30Z

Status classes
  CLASS  REQUESTS  PERCENT  BYTES
  -----  --------  -------  -----
  4xx           5   62.50%  639 B
  5xx           3   37.50%  745 B

Status codes
  STATUS  REQUESTS  PERCENT  BYTES
  ------  --------  -------  -----
  400            1   12.50%   98 B
  403            1   12.50%  153 B
  404            3   37.50%  388 B
  500            1   12.50%  431 B
  502            2   25.00%  314 B

Methods
  METHOD  REQUESTS  PERCENT  BYTES
  ------  --------  -------  -----
  GET            6   75.00%  855 B
  DELETE         1   12.50%  431 B
  POST           1   12.50%   98 B

Top paths
  PATH           REQUESTS  PERCENT  BYTES
  -------------  --------  -------  -----
  /api/v1/items         3   37.50%  412 B
  /.env                 1   12.50%  162 B
  /admin                1   12.50%  153 B

Top IPs
  IP             REQUESTS  PERCENT  BYTES
  -------------  --------  -------  -----
  198.51.100.42         3   37.50%  477 B
  198.51.100.7          2   25.00%  162 B
  203.0.113.99          2   25.00%  314 B
```

含格式错误行的日志：默认跳过错误行并在 stderr 提示；加 `--strict` 则直接报错退出：

```console
$ logscope --strict tests/fixtures/malformed.log
logscope: error: tests/fixtures/malformed.log:2: malformed log line (strict mode)
```

### 输出格式说明

- `table`：默认，适合终端阅读。
- `json`：一个 JSON 对象，顶层键为 `summary`, `status_classes`, `status_codes`, `methods`, `top_paths`, `top_ips`，便于脚本处理。
- `csv`：列为 `section,key,value,percent,bytes`，每项一行，便于导入表格软件。

### 测试

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

测试包括各模块的单元测试、`tests/cli.rs` 中针对示例日志运行 CLI 的集成测试，以及文档测试。示例日志全部为虚构数据，IP 只使用文档保留网段和私有网段。

### 许可证

MIT，见 [LICENSE](LICENSE)。

---

## English

**logscope** is a fast, streaming command-line analyzer for Nginx/Apache access logs (combined / common format) and JSON-lines logs, written in Rust. It reads line by line with memory use independent of the number of lines, so it handles large files, `.gz` archives and piped input, and prints its report as a table, JSON or CSV.

### Features

- **Formats**: Nginx/Apache `combined` and `common`; JSON-lines (one object per line). `--format auto` detects the format per file.
- **JSON field mapping**: common key names are detected automatically; `--field status=http.code` maps any (nested) key to timestamp / status / method / path / ip / bytes / latency.
- **Inputs**: one or more files, or stdin (no file, or `-`). Gzip input is detected by its magic bytes and decompressed transparently.
- **Streaming**: `BufReader`, line by line; only counters are kept. Malformed lines are counted and skipped, or rejected with `--strict`.
- **Stats**: totals, status codes and classes (2xx/3xx/4xx/5xx), paths, IPs, methods, bytes, latency (JSON logs), time-window buckets (`--window 1m|5m|1h|1d`), top-N lists (`--top N`, default 10, 0 = all).
- **Filters**: `--status` (`404`, `5xx`, `400-499`, comma lists), `--path` regex, `--method`, `--since` / `--until` (RFC3339, nginx timestamp, or `YYYY-MM-DD`), `--ip` (addresses or CIDR networks).
- **Output**: `--output table|json|csv`.

### Install

Requires Rust 1.82 or newer.

```bash
cargo install --path .        # installs into ~/.cargo/bin
# or
cargo build --release && ./target/release/logscope --help
```

### Usage

All output below was produced by running the release binary against the sample logs in `tests/fixtures/` (long outputs are trimmed where marked).

Full report of a combined-format access log, top 5:

```console
$ logscope --top 5 tests/fixtures/access.log
Summary
  Lines read           32
  Parsed               32
  Malformed (skipped)  0
  Matched filters      32
  Total bytes          104.3 KiB (106,794 bytes)
  Unique IPs           7
  Unique paths         16
  Time range           2026-03-14T10:00:01Z .. 2026-03-14T10:58:59Z

Status classes
  CLASS  REQUESTS  PERCENT      BYTES
  -----  --------  -------  ---------
  2xx          21   65.63%  102.9 KiB
  3xx           3    9.38%        0 B
  4xx           5   15.63%      639 B
  5xx           3    9.38%      745 B

Status codes
  STATUS  REQUESTS  PERCENT      BYTES
  ------  --------  -------  ---------
  200           19   59.38%  102.6 KiB
  201            1    3.13%      345 B
  204            1    3.13%        0 B
  302            2    6.25%        0 B
  304            1    3.13%        0 B
  400            1    3.13%       98 B
  403            1    3.13%      153 B
  404            3    9.38%      388 B
  500            1    3.13%      431 B
  502            2    6.25%      314 B

Methods
  METHOD  REQUESTS  PERCENT      BYTES
  ------  --------  -------  ---------
  GET           26   81.25%  103.4 KiB
  POST           3    9.38%      443 B
  DELETE         1    3.13%      431 B
  HEAD           1    3.13%        0 B
  PUT            1    3.13%        0 B

Top paths
  PATH              REQUESTS  PERCENT     BYTES
  ----------------  --------  -------  --------
  /api/v1/items            7   21.88%   7.5 KiB
  /health                  6   18.75%      12 B
  /api/v1/items/42         3    9.38%     943 B
  /                        2    6.25%  10.0 KiB
  /search                  2    6.25%  13.1 KiB

Top IPs
  IP            REQUESTS  PERCENT     BYTES
  ------------  --------  -------  --------
  10.0.0.8             6   18.75%      12 B
  192.0.2.23           6   18.75%  14.1 KiB
  192.0.2.10           5   15.63%  66.7 KiB
  198.51.100.7         5   15.63%   3.3 KiB
  203.0.113.5          4   12.50%  17.2 KiB
```

Errors only:

```console
$ logscope --status 4xx,5xx --top 3 tests/fixtures/access.log
Summary
  Lines read           32
  Parsed               32
  Malformed (skipped)  0
  Matched filters      8
  Total bytes          1.4 KiB (1,384 bytes)
  Unique IPs           4
  Unique paths         6
  Time range           2026-03-14T10:01:17Z .. 2026-03-14T10:41:30Z

Status classes
  CLASS  REQUESTS  PERCENT  BYTES
  -----  --------  -------  -----
  4xx           5   62.50%  639 B
  5xx           3   37.50%  745 B

Status codes
  STATUS  REQUESTS  PERCENT  BYTES
  ------  --------  -------  -----
  400            1   12.50%   98 B
  403            1   12.50%  153 B
  404            3   37.50%  388 B
  500            1   12.50%  431 B
  502            2   25.00%  314 B

Methods
  METHOD  REQUESTS  PERCENT  BYTES
  ------  --------  -------  -----
  GET            6   75.00%  855 B
  DELETE         1   12.50%  431 B
  POST           1   12.50%   98 B

Top paths
  PATH           REQUESTS  PERCENT  BYTES
  -------------  --------  -------  -----
  /api/v1/items         3   37.50%  412 B
  /.env                 1   12.50%  162 B
  /admin                1   12.50%  153 B

Top IPs
  IP             REQUESTS  PERCENT  BYTES
  -------------  --------  -------  -----
  198.51.100.42         3   37.50%  477 B
  198.51.100.7          2   25.00%  162 B
  203.0.113.99          2   25.00%  314 B
```

Gzip input, 15-minute windows, CSV output (trimmed):

```console
$ logscope --window 15m --top 3 --output csv tests/fixtures/access.log.gz
section,key,value,percent,bytes
summary,lines,32,,
summary,parsed,32,,
summary,malformed,0,,
summary,matched,32,,
summary,total_bytes,106794,,
summary,unique_ips,7,,
summary,unique_paths,16,,
summary,first_seen,2026-03-14T10:00:01Z,,
summary,last_seen,2026-03-14T10:58:59Z,,
...
window,2026-03-14T10:00:00Z,14,,84209
window,2026-03-14T10:15:00Z,8,,10398
window,2026-03-14T10:30:00Z,6,,5567
window,2026-03-14T10:45:00Z,4,,6620
```

JSON-lines input, `/api/` GET requests only, JSON output (excerpt: `summary` and `status_classes`):

```console
$ logscope --path '^/api/' --method GET --output json --top 2 tests/fixtures/app.jsonl
{
  "summary": {
    "lines": 16,
    "parsed": 16,
    "malformed": 0,
    "matched": 7,
    "total_bytes": 16438,
    "unique_ips": 4,
    "unique_paths": 4,
    "first_seen": "2026-03-14T11:00:03Z",
    "last_seen": "2026-03-14T11:12:30Z",
    "latency": {
      "samples": 7,
      "avg_ms": 265.857,
      "min_ms": 3.0,
      "max_ms": 1500.0
    }
  },
  "status_classes": [
    {
      "key": "2xx",
      "count": 5,
      "percent": 71.43,
      "bytes": 16254
    },
    {
      "key": "4xx",
      "count": 1,
      "percent": 14.29,
      "bytes": 64
    },
    {
      "key": "5xx",
      "count": 1,
      "percent": 14.29,
      "bytes": 120
    }
  ]
}
```

Custom JSON schema from stdin, with explicit field mapping and latency in seconds:

```console
$ cat tests/fixtures/custom.jsonl | logscope --format json \
    --field timestamp=when --field ip=client.addr --field method=req.verb \
    --field path=req.uri --field status=res.code --field bytes=res.size \
    --field latency=took --latency-unit s --top 3 -
Summary
  Lines read           4
  Parsed               4
  Malformed (skipped)  0
  Matched filters      4
  Total bytes          18.2 KiB (18,676 bytes)
  Unique IPs           3
  Unique paths         3
  Time range           2026-03-14T11:00:00Z .. 2026-03-14T11:02:10Z
  Latency (ms)         avg 39.2, min 2.0, max 120.0 (4 samples)

Status classes
  CLASS  REQUESTS  PERCENT     BYTES
  -----  --------  -------  --------
  2xx           2   50.00%  18.1 KiB
  3xx           1   25.00%       0 B
  4xx           1   25.00%     150 B

Status codes
  STATUS  REQUESTS  PERCENT     BYTES
  ------  --------  -------  --------
  200            1   25.00%  18.0 KiB
  201            1   25.00%      96 B
  304            1   25.00%       0 B
  404            1   25.00%     150 B

Methods
  METHOD  REQUESTS  PERCENT     BYTES
  ------  --------  -------  --------
  GET            3   75.00%  18.1 KiB
  POST           1   25.00%      96 B

Top paths
  PATH       REQUESTS  PERCENT     BYTES
  ---------  --------  -------  --------
  /feed.xml         2   50.00%  18.0 KiB
  /comments         1   25.00%      96 B
  /missing          1   25.00%     150 B

Top IPs
  IP             REQUESTS  PERCENT     BYTES
  -------------  --------  -------  --------
  192.0.2.50            2   50.00%  18.1 KiB
  192.0.2.51            1   25.00%       0 B
  198.51.100.60         1   25.00%     150 B
```

Malformed lines are skipped and reported on stderr; `--strict` fails instead:

```console
$ logscope --strict tests/fixtures/malformed.log
logscope: error: tests/fixtures/malformed.log:2: malformed log line (strict mode)
```

### Output formats

- `table` (default): human-friendly terminal report.
- `json`: a single object with the keys `summary`, `status_classes`, `status_codes`, `methods`, `top_paths`, `top_ips`.
- `csv`: columns `section,key,value,percent,bytes`, one row per entry.

### Testing

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The suite contains unit tests in each module, CLI integration tests in `tests/cli.rs` that run against the fixtures, and a doc test. All fixtures are synthetic and use only documentation and private IP ranges.

### License

MIT, see [LICENSE](LICENSE).
