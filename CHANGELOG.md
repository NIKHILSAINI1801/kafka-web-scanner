# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0]

First release.

### Added
- `kafka` command line interface (Typer + Rich): `scan`, `modules`, `history`, `doctor`,
  `version`, and a command overview when run without arguments.
- Strict URL validation (http/https only; credentials, malformed hosts and invalid ports rejected).
- Explicit authorization prompt before any network request, plus `--i-am-authorized` for
  non-interactive use.
- Scope enforcement: loopback, private, link-local, multicast, reserved, unspecified and other
  non-global addresses are blocked by default (including IPv4-mapped, 6to4 and NAT64 forms);
  `--allow-private` lab mode lifts only the loopback/private/link-local block.
- Bounded HTTP client: one GET, connect/read timeouts, overall deadline, streamed 1 MiB size cap,
  TLS verification always on, redirects never followed, proxies and environment CA settings
  ignored, connection pinned to a validated IP address (falls back to the next validated
  address only when a TCP connection cannot be established, so dual-stack hosts with an
  unreachable IPv6 route still work).
- Five passive modules: HTTPS/transport, security headers, cookies, CORS, technology metadata.
- Findings with stable IDs, severity, confidence, evidence and recommendations; risk summary.
- HTML, JSON (schema 1.0) and TXT reports with escaped output and safe file handling.
- Local SQLite scan history with automatic schema upgrades.
- Unit and local-server integration test-suite, GitHub Actions CI, packaging metadata.
