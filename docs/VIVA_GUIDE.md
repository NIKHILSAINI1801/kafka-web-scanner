# Viva guide

Short answers to questions an examiner is likely to ask. Be ready to demonstrate each claim.

## Purpose and scope

**What is KAFKA?** A passive, permission-based scanner that sends one GET request to a site
you are authorized to assess and reports configuration weaknesses (headers, cookies, CORS,
transport, technology disclosure) with evidence, severity, confidence and remediation.

**Why "passive"?** It only reads what the server volunteers in one normal response. It never
sends payloads, guesses credentials, submits forms or crawls, so it cannot damage the target
and stays inside what an authorized assessor would do first.

**Is it a vulnerability scanner or a pentest tool?** No. It reports *configuration
observations*. Severity is triage, not proof of exploitability.

## Safety design

**How do you make sure the user has permission?** The tool shows a notice and needs `y`/`yes`
before any network activity (including DNS). It records the method in the report. It cannot
verify permission, which is why the documentation is explicit about that.

**What is SSRF and how do you avoid scanning internal systems?** Server-side request forgery
makes a program contact internal addresses. KAFKA blocks loopback, private, link-local,
multicast, reserved and unspecified addresses by default, checking *every* address a name
resolves to, including IPv6 forms that hide an IPv4 address.

**What is DNS rebinding / TOCTOU?** A name can resolve to a public address when checked and an
internal one when used. KAFKA resolves once and connects to that exact IP (TLS still checks
the host name), and never follows redirects. This narrows the window; it is still documented
as not being a hardened boundary for server-side use (`docs/SECURITY.md`).

**What does `--allow-private` do?** Lets you scan a lab on loopback/private addresses. It does
not disable TLS verification, timeouts, the size cap, redirect blocking or authorization, and
multicast/unspecified/reserved addresses stay blocked.

**What if a site has IPv6 and IPv4 addresses and one is unreachable?** KAFKA validates all
of them and tries them in turn (alternating families), but only when the TCP connection cannot
be established, so no request has been sent yet. After connecting, nothing is retried, so there
is still exactly one GET. A Windows test run exposed this: `localhost` resolves to `::1` first.

**Why not follow redirects?** A redirect could lead to another host (maybe not yours, maybe
internal). Reporting it and stopping keeps the scan on the one URL you authorized.

**How is the response bounded?** Connect/read timeouts, an overall deadline checked after every
read (so a server dripping one byte at a time cannot stall it), and a hard 1 MiB cap on bytes
read, with no decompression. I found and fixed a flaw where the deadline was only checked per
16 KiB block; there is a regression test.

**Why is TLS verification never disabled?** A scanner that accepts any certificate could be
man-in-the-middled. There is deliberately no flag for it. Failed verification is reported.

## Findings

**Why is a missing header only LOW/MEDIUM and not HIGH?** Absence is context dependent (a JSON
API does not need `Referrer-Policy`). Confidence is lowered for non-HTML responses and
redirects. Passive checks almost never justify CRITICAL.

**Is a wildcard CORS origin a vulnerability?** Not by itself. `*` is normal for public
resources. It matters for private data. The finding says so and has LOW confidence. `*` with
credentials is invalid for browsers but signals misconfiguration. `null` with credentials is the
dangerous case.

**How do you protect cookie values?** `parse_set_cookie` discards the value immediately and the
data class has no value field. A test feeds canary values and asserts they never appear
in findings, reports, terminal output or the database.

**Does a successful HTTPS check mean the TLS is good?** No. It means this client accepted the
certificate for this connection. Protocol and cipher auditing needs a dedicated tool.

## Engineering

**Why Requests rather than HTTPX?** The specification allows either. Requests (urllib3) lets
me connect to a validated IP while verifying the certificate against the host name, and
`read1` for responsive deadline checks.

**How do you handle hostile server output?** Control characters are stripped when findings are
built; the terminal uses Rich `Text` (no markup parsing); HTML is auto-escaped with no
scripts; SQL is parameterised; file names are sanitised. Tests inject `<script>`, ANSI escapes
and Rich markup.

**How is the history database protected and upgraded?** Parameterised SQL only; no bodies or
secrets; owner-only file permissions where supported; a `schema_meta` table drives migrations
(the original table is upgraded in place by adding a `status` column).

**How are the tests organised?** Unit tests for each module, scope and report; integration
tests against a local HTTP/HTTPS server that records requests, proving: one GET, no redirect
follow, timeouts, size cap, TLS rejection, and "declined = no request".

## Limitations to volunteer

One endpoint only; absence of findings is not proof of security; CORS is not probed with an
`Origin` header; technology metadata can be spoofed; no TLS audit; DNS TOCTOU caveats; proxies
unsupported; the authorization prompt cannot prove permission; human review is required.
