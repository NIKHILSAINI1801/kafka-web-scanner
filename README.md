# KAFKA

**KAFKA** is a passive, permission-based website security **configuration** scanner for
websites you own or are explicitly authorized to assess. It sends **one bounded HTTP(S) GET
request**, examines the response and reports findings with evidence, severity, confidence and
remediation advice.

It is an educational tool. It is **not** a penetration-testing suite, a vulnerability scanner
in the exploit sense, or a security certification.

> **Authorized use only.** Scanning systems you do not own or have written permission to test
> may be illegal. KAFKA asks you to confirm authorization before it makes any network request.

## What it checks

| Module | Checks |
|---|---|
| HTTPS / transport | HTTP vs HTTPS, a verified HTTPS connection, redirects (reported, never followed) |
| Security headers | `Content-Security-Policy`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy` |
| Cookies | `Secure`, `HttpOnly`, `SameSite`, cookie prefixes. Cookie **values are never stored or printed** |
| CORS | `Access-Control-Allow-Origin` and `-Credentials`. A wildcard is judged in context |
| Technology metadata | `Server`, `X-Powered-By`, HTML `<meta name="generator">`. No aggressive fingerprinting |

Every finding has a stable ID (for example `KAFKA-HDR-001`), the scanner name, a title, a
severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), a confidence (`HIGH`, `MEDIUM`, `LOW`),
a description, evidence and a recommendation. Severity is **preliminary triage, not proof of
exploitability**. Passive checks rarely produce `CRITICAL`.

## What it will never do

No exploitation, payload injection, brute force, credential collection, login automation,
form submission, crawling, directory brute-forcing, authentication bypass, session theft,
stealth, evasion, rate-limit bypass or automatic target changes.

## Install

KAFKA needs **Python 3.11 or newer** and works on Windows, macOS and Linux.

> KAFKA has not been published to PyPI. Install it from a source checkout or a built wheel as
> shown below. Do not install it in the same environment as the unrelated `kafka-python`
> package: both use the top-level module name `kafka`.

**Linux / macOS**

```bash
git clone https://github.com/NIKHILSAINI1801/kafka-web-scanner.git KAFKA && cd KAFKA
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
kafka doctor
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/NIKHILSAINI1801/kafka-web-scanner.git KAFKA; cd KAFKA
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
kafka doctor
```

If PowerShell blocks the activation script, run
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first (affects only that window).

## Usage

```text
kafka                              Command overview
kafka scan URL                     Confirm authorization, scan, write reports
kafka scan URL --output DIR        Choose the report directory (default: ./kafka-reports)
kafka scan URL --allow-private     Isolated-lab mode (loopback / private addresses)
kafka scan URL --i-am-authorized   Non-interactive: assert authorization, skip the prompt
kafka modules                      List the scanner modules
kafka history [--limit N]          Recent scans from the local history
kafka doctor                       Check your environment (makes no network requests)
kafka version                      Show the version
```

Example:

```bash
kafka scan https://example.com --output ./reports
```

KAFKA shows an authorization notice and asks `Do you own this website or have explicit
permission to assess it? [y/N]`. Only `y` or `yes` continues; anything else (including no
input) makes **no** network request.

Each scan writes three reports into the output directory:

* `kafka_<host>_<UTC timestamp>.html`: responsive, self-contained, no scripts or third-party assets
* `kafka_<host>_<UTC timestamp>.json`: machine-readable (`schema_version` `1.0`)
* `kafka_<host>_<UTC timestamp>.txt`: plain text

and records a summary row in the local history. Existing files are never overwritten.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed |
| 1 | Scan failed or was partial (network error, TLS failure, module error), or reports could not be written |
| 2 | Refused: invalid URL, authorization not given, or target outside the permitted scope |

### Where data is stored

| Data | Location |
|---|---|
| Reports | the `--output` directory (default `./kafka-reports`) |
| History database | Linux `~/.local/share/kafka/history.db`, macOS `~/Library/Application Support/KAFKA/history.db`, Windows `%LOCALAPPDATA%\KAFKA\history.db` (override the directory with `KAFKA_HOME`) |

KAFKA stores no response bodies, cookie values, credentials or URL query strings. Do not put
secrets in URL *paths* either: the path is shown in reports.

## Safety controls

* Only `http` and `https`; URLs with embedded credentials, malformed hosts or invalid ports are rejected.
* The host is resolved and **loopback, private, link-local, multicast, reserved, unspecified and other non-global addresses are blocked by default**.
  `--allow-private` lifts only the loopback/private/link-local block, for a lab you control;
  every other safeguard stays on, and multicast/unspecified/reserved addresses stay blocked.
* One `GET`. Connect and read timeouts, an overall deadline, and a strict streamed cap on response bytes (1 MiB).
* TLS certificate and host-name verification is always on. Redirects are never followed.
* Output derived from the remote server is sanitised before it reaches the terminal, reports or database.

See [docs/SECURITY.md](docs/SECURITY.md) for the full design, including the DNS
time-of-check/time-of-use limitation.

## Limitations

* One endpoint (one GET), not a whole site.
* A missing header is not automatically a vulnerability.
* CORS review is limited: KAFKA sends no `Origin` header, so dynamic allow-lists are not exercised.
* Technology metadata is self-reported and can be incomplete or spoofed.
* Successful HTTPS only means this client accepted the certificate for that connection. It is not a TLS audit.
* Environment proxy settings are ignored on purpose (so the validated address is the one contacted), which means KAFKA cannot be used from networks that *require* an HTTP proxy.
* Human review is required for every finding.

## Development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest -q
ruff check .
ruff format --check .
python -m build
```

More in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
and [CONTRIBUTING.md](CONTRIBUTING.md). A question-and-answer guide for presenting the project
is in [docs/VIVA_GUIDE.md](docs/VIVA_GUIDE.md).

## License

MIT. See [LICENSE](LICENSE). (Confirm this choice against your institution's rules.)
