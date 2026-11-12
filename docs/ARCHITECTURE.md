# Architecture

KAFKA is a small pipeline. Each stage has one job and the safety-critical stages are kept
separate from the presentation code.

```text
 URL text
    |
    v
 scope.validate_url ----------------------> ScanTarget          (offline, no network)
    |
    v
 ui.ask_authorization  -- "no" --> stop, zero network activity
    |
    v
 scanner.run_scan
    |-- scope.resolve_and_check --------> validated IP address   (DNS lookup + policy)
    |-- http_client.fetch --------------> ResponseSnapshot       (one bounded GET)
    |-- modules.*.scan (x5) ------------> list[Finding]          (pure, passive)
    '-- risk.sort_findings -------------> ScanResult
    |
    v
 reports.write_reports  (HTML / JSON / TXT)      database.add_scan (SQLite)      ui.print_scan_summary
```

## Packages and modules

| File | Responsibility |
|---|---|
| `main.py` | Typer commands only: parse arguments, call the pieces, choose exit codes |
| `ui.py` | All Rich output. Remote text is always wrapped in `Text`, never parsed as markup |
| `config.py` | Constants, `HttpLimits`, `ScanConfig`, per-user data directory |
| `models.py` | `Severity`, `Confidence`, `Finding`, `ScanError`, `ResponseSnapshot`, `ScanResult` |
| `scope.py` | URL validation, `ScanTarget`, address classification, `resolve_and_check` |
| `http_client.py` | The single bounded request (`fetch`), connect-failure fallback across validated addresses, `FetchError` |
| `scanner.py` | Orchestration, progress callbacks, error-to-status mapping |
| `modules/` | `https`, `headers`, `cookies`, `cors`, `technology`, plus the module registry |
| `risk.py` | Severity counts, triage text, sorting, top recommendations |
| `reports/` | `html.py` (Jinja2), `json_report.py`, `text.py`, and safe file writing |
| `database.py` | SQLite history with automatic schema upgrades |
| `doctor.py` | Environment checks for `kafka doctor` (no network) |
| `util.py` | Text sanitising, filename sanitising, UTC helpers |

## Key design decisions

**Modules are pure functions of a snapshot.** A module receives a `ResponseSnapshot` that has
already been fetched and returns findings. Modules cannot make requests, which is what keeps
the tool passive and makes them easy to unit-test.

**Authorization comes before the network, and DNS counts as the network.** `validate_url` is
offline. The prompt comes next. Only then does `resolve_and_check` perform the DNS lookup.

**The checked address is the connected address.** `resolve_and_check` returns the validated IPs
and `fetch` connects to one of them directly, setting the `Host` header and the TLS server name
from the original host name. The HTTP library never resolves the name a second time. If a TCP
connection cannot be established (`ConnectFailed`), the next validated address is tried, so a
dual-stack host with an unreachable IPv6 route still works; any later failure is final and at
most one HTTP request is ever sent. See `docs/SECURITY.md` for what this does and does not
guarantee.

**Findings are sanitised at construction.** `Finding.__post_init__` strips control, format and
private-use characters and bounds field lengths, so every output channel (terminal, HTML,
JSON, TXT, SQLite) receives safe text regardless of what the server sent. Output channels
still escape for their own context (Jinja2 auto-escaping, Rich `Text`, parameterised SQL).

**`ScanResult` holds no secrets.** It contains findings, a small `http` summary (status, IP,
TLS protocol, byte counts) and error messages. The response body and headers exist only in the
in-memory `ResponseSnapshot` and are discarded after the modules run. The target is stored in
its display form with the query string replaced by `<query omitted>`.

**Scans never raise for network problems.** `run_scan` converts scope, DNS, TLS, timeout and
module failures into a `ScanResult` with a `status` of `completed`, `partial`, `failed` or
`blocked`, and a list of `ScanError`s with short safe messages (never stack traces).

## Finding IDs

IDs are stable: `KAFKA-<AREA>-<nnn>`. Areas are `TLS`, `HDR`, `CKE`, `CORS`, `TECH`. A given
condition always has the same ID, and an ID appears at most once per scan. Aggregate findings
(for example "cookie set without Secure") list all affected cookie *names* in their evidence.

## Report formats

* **JSON** (`schema_version` `1.0`): tool, target, UTC times, status, authorization record,
  HTTP summary, modules run, severity summary, findings, errors, warnings, limitations and
  disclaimer. Any incompatible change must bump the schema version.
* **HTML**: one self-contained file. Jinja2 auto-escaping is on, there are no scripts or
  external assets, and a restrictive Content-Security-Policy `<meta>` tag is embedded.
  Severity is a text label plus a text marker, never colour alone.
* **TXT**: the same information in plain text.

## Database

`scans(id, target, started_at, status_code, tool_version, findings_json, status)` plus a small
`schema_meta` table. The first release of the table (without `status`) is upgraded in place by
`database._migrate`. All SQL is parameterised; no statement is built from data.

## Why Requests

The specification allows Requests or HTTPX. Requests was chosen because its urllib3 layer
allows connecting to a pre-validated IP while keeping SNI and certificate verification on the
original host name (via the adapter's `server_hostname` pool option), and because
`urllib3.HTTPResponse.read1` lets the overall deadline be checked after every network read.
