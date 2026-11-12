# Security design

This document describes the safety properties KAFKA enforces, how, and where they stop.
To report a vulnerability in KAFKA itself see [../SECURITY.md](../SECURITY.md).

## Intended use

KAFKA is for websites you own or are explicitly authorized to assess. It displays an
authorization notice and requires a typed `y`/`yes` (or `--i-am-authorized`) before any
network activity. The confirmation method is recorded in the report. This is a reminder and an
audit trail, not a technical control: KAFKA cannot verify that you really are authorized.

## Safety controls

| Control | How it is enforced | Tested in |
|---|---|---|
| http/https only; no URL credentials; valid host and port | `scope.validate_url` | `tests/unit/test_scope.py` |
| Authorization before network | `ui.ask_authorization`; DNS resolution happens only after it | `tests/unit/test_cli.py`, `tests/integration/test_local_scan.py` |
| Non-public destinations blocked | `scope.classify_address`, `scope.resolve_and_check` | `test_scope.py`, integration tests |
| `--allow-private` lifts nothing else | Only loopback/private/link-local/shared ranges are relaxed; multicast, unspecified and reserved stay blocked; timeouts, cap and TLS are unaffected | `test_scope.py` |
| One GET, no redirects, no retries | `http_client.fetch` (`allow_redirects=False`, `max_retries=0`). If a TCP connection cannot be established, the next *validated* address is tried; nothing has been sent at that point, and TLS errors or timeouts after connecting never cause another attempt | integration: request log shows exactly one GET; `tests/unit/test_http_client.py` |
| Timeouts | connect/read timeouts plus an overall deadline checked after every read | integration |
| Response size cap | streamed; never reads past 1 MiB; bodies are not decompressed | integration |
| TLS verification on | requests' `verify=True`; no option disables it | integration (self-signed and wrong-host certificates rejected) |
| No secrets stored | cookie values discarded at parse time; bodies not persisted; query strings replaced | unit and integration "canary" tests |
| Safe output | sanitised findings, Jinja2 auto-escaping, Rich `Text`, parameterised SQL | `test_reports.py`, `test_cli.py`, `test_database.py` |
| Safe file handling | sanitised names, exclusive create (`"x"` mode), no overwrite | `test_reports.py` |

## Address policy

All addresses a name resolves to must pass. By default these are blocked: loopback, private
(RFC 1918, ULA), link-local (including the cloud metadata address `169.254.169.254`),
multicast, reserved, unspecified and other non-global ranges such as `100.64.0.0/10`.
IPv6 forms that embed an IPv4 address (IPv4-mapped `::ffff:a.b.c.d`, 6to4 `2002::/16`, NAT64
`64:ff9b::/96`) are judged by the embedded IPv4 address too. Other transition mechanisms (for
example Teredo) are not specially handled.

Host names such as `127.1`, `2130706433` or `0x7f.0.0.1`, which different software
interprets differently, are rejected outright as ambiguous.

## DNS rebinding and time-of-check/time-of-use (TOCTOU)

Resolving a name, checking the address and then letting an HTTP library resolve the name
again is **not** a hardened SSRF defence: an attacker-controlled DNS server can answer the
check with a public address and the connection with an internal one (DNS rebinding).

What KAFKA does about it:

* It resolves **once**, validates every returned address, and then connects **directly to a
  validated IP address**. The HTTP stack never performs a second lookup, so the classic
  rebinding window between "check" and "connect" does not exist for the scan request.
* If the TCP connection to the first address cannot be established (for example a dual-stack
  host whose IPv6 route is unreachable from your network), KAFKA tries the next validated
  address, alternating IPv6 and IPv4, up to four attempts within the overall time limit. No
  HTTP request has been sent at that point. Once a connection exists, failures (TLS errors,
  timeouts, resets) are final and never cause another attempt.
* TLS still verifies the certificate against the original host name (SNI and verification use
  the host name, not the IP), and the `Host` header is the original host name.
* Redirects are never followed, so a redirect cannot steer the request to an internal address.
* Environment proxies are ignored (`trust_env` is off), so a proxy cannot re-resolve the name.

What it does not do, and why you should still not treat it as a hard boundary:

* `resolve_and_check` and `fetch` are separate functions. Code that resolves with KAFKA's
  helper and then fetches by name elsewhere gets none of the above.
* The check trusts the answer the operating-system resolver returns. Split-horizon DNS, NAT
  hairpinning or a path that maps a public address to an internal system cannot be detected.
* It is a client-side convenience that protects the person running the tool from scanning
  internal systems by accident. It is **not** designed as the SSRF boundary of a multi-tenant
  service. If you embed KAFKA's scanning in a server, add network-level egress controls.

## Data handling

* The response body exists only in memory, is capped at 1 MiB, and is used solely to read
  `<meta name="generator">`. It is never written to disk.
* `Set-Cookie` lines are parsed and the value is dropped immediately. Only names and
  attributes survive. Raw headers other than a short list of inspected ones are never shown.
* Redirect `Location` values are shown without credentials, query string or fragment.
* The scanned URL is stored and printed with the query string replaced by `<query omitted>`.
  The path is shown, so do not put secrets in URL paths.
* The history database is created with owner-only permissions where the platform supports it.
* Error messages are short and fixed-form. Verbose exception text is not printed.

## Untrusted output

Everything from the remote server is untrusted. A server can send control characters, terminal
escape sequences, Rich markup such as `[red]`, HTML, or SQL fragments. Defences, in layers:
(1) `Finding` and `ScanError` strip control/format characters and bound length; (2) Rich output
uses `Text` objects, never markup parsing; (3) the HTML report uses auto-escaping and has no
scripts; (4) SQL is parameterised; (5) file names are built from sanitised host names.

## Known limitations

* One endpoint, one request: absence of a finding is not evidence of security.
* CORS: no `Origin` header is sent, so dynamic origin reflection is not tested.
* A successful HTTPS connection is not a TLS audit.
* The authorization prompt cannot prove permission.
* Certificate trust uses the CA bundle shipped with the `certifi` package, not the operating
  system store, so a site that relies on a private CA will (correctly, for this tool) fail verification.
* Networks that require an HTTP proxy are not supported (see the DNS section).
