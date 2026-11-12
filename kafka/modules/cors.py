"""CORS review based on the response headers of the single GET request.

No ``Origin`` header is sent, so servers that build their allow-list dynamically may not
reveal it. A wildcard origin is *context dependent*: it is normal for public, unauthenticated
resources and risky for anything that relies on credentials or network position.
"""

from __future__ import annotations

import re
from functools import partial

from kafka.models import Confidence, Finding, ResponseSnapshot, Severity
from kafka.util import clean_text

SCANNER = "cors"
_make = partial(Finding, scanner=SCANNER)
_ORIGIN = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/\s?#]+$")


def _evidence(origin: str | None, credentials: str | None) -> str:
    lines = [
        f"Access-Control-Allow-Origin: {clean_text(origin, max_length=200) if origin else '(not present)'}"
    ]
    if credentials is not None:
        lines.append(f"Access-Control-Allow-Credentials: {clean_text(credentials, max_length=40)}")
    return "\n".join(lines)


def scan(snap: ResponseSnapshot) -> list[Finding]:
    origin = snap.header("access-control-allow-origin")
    credentials = snap.header("access-control-allow-credentials")
    allows_credentials = credentials is not None and credentials.strip().lower() == "true"

    if origin is None:
        if credentials is not None:
            return [
                _make(
                    id="KAFKA-CORS-009",
                    title="Access-Control-Allow-Credentials sent without an allowed origin",
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    description=(
                        "A credentials header was present but no Access-Control-Allow-Origin. "
                        "The server may add the origin header only for requests that carry an "
                        "Origin header, which this scan does not send."
                    ),
                    evidence=_evidence(origin, credentials),
                    recommendation="Review the CORS configuration with an authorized, targeted test.",
                )
            ]
        return [
            _make(
                id="KAFKA-CORS-001",
                title="No CORS response headers observed",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                description=(
                    "No Access-Control-* headers were returned, so browsers apply the default "
                    "same-origin policy. Servers that answer CORS only for requests with an "
                    "Origin header would not show it here."
                ),
                evidence=_evidence(origin, credentials),
                recommendation="No action required for this observation.",
            )
        ]

    value = origin.strip()
    evidence = _evidence(origin, credentials)

    if "," in value or (value not in ("*", "null") and not _ORIGIN.match(value)):
        return [
            _make(
                id="KAFKA-CORS-008",
                title="Access-Control-Allow-Origin has an invalid value",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=(
                    "The header must contain exactly one origin (scheme://host[:port]), "
                    "'null' or '*'. Browsers ignore invalid values, so cross-origin access "
                    "may not work as intended."
                ),
                evidence=evidence,
                recommendation="Return a single, exact origin chosen from a server-side allow-list.",
            )
        ]

    if value == "*":
        if allows_credentials:
            return [
                _make(
                    id="KAFKA-CORS-003",
                    title="Wildcard CORS origin combined with Allow-Credentials: true",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=(
                        "Browsers refuse to send credentials to a wildcard origin, so this "
                        "combination does not work as written. It does suggest a "
                        "misconfigured CORS policy that may be 'fixed' later by reflecting "
                        "any origin, which would be risky."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Do not use '*' with credentials. Allow specific, trusted origins "
                        "from a server-side allow-list."
                    ),
                )
            ]
        return [
            _make(
                id="KAFKA-CORS-002",
                title="Wildcard CORS origin (Access-Control-Allow-Origin: *)",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description=(
                    "Any website may read this response from a browser. That is often "
                    "intentional for public, unauthenticated content or APIs, and "
                    "inappropriate for private data or resources reachable only from an "
                    "internal network. This depends on what the endpoint serves."
                ),
                evidence=evidence,
                recommendation=(
                    "Confirm the resource is meant to be public. Otherwise allow only "
                    "specific trusted origins."
                ),
            )
        ]

    if value == "null":
        if allows_credentials:
            return [
                _make(
                    id="KAFKA-CORS-005",
                    title="CORS allows the 'null' origin with credentials",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=(
                        "The 'null' origin can be produced by sandboxed frames and local "
                        "files, so allowing it together with credentials can let untrusted "
                        "pages make credentialed cross-origin requests."
                    ),
                    evidence=evidence,
                    recommendation="Never allow the 'null' origin; use exact trusted origins.",
                )
            ]
        return [
            _make(
                id="KAFKA-CORS-004",
                title="CORS allows the 'null' origin",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description=(
                    "The 'null' origin can be produced by sandboxed frames and local files, "
                    "so it is not a trustworthy allow-list entry."
                ),
                evidence=evidence,
                recommendation="Remove 'null' from the allow-list; use exact trusted origins.",
            )
        ]

    findings: list[Finding] = []
    if allows_credentials:
        findings.append(
            _make(
                id="KAFKA-CORS-006",
                title="CORS allows a specific origin with credentials",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                description=(
                    "A single origin is allowed to make credentialed requests. This is a "
                    "valid pattern; verify the origin is trusted and that it is not simply "
                    "echoed back from the request."
                ),
                evidence=evidence,
                recommendation="Keep the allow-list minimal and confirm origins are not reflected.",
            )
        )
    else:
        findings.append(
            _make(
                id="KAFKA-CORS-010",
                title="CORS allows a specific origin",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                description="A single, exact origin is allowed. No obvious problem observed.",
                evidence=evidence,
                recommendation="No action required for this observation.",
            )
        )
    vary_tokens = {token.strip().lower() for token in (snap.header("vary") or "").split(",")}
    if "origin" not in vary_tokens and "*" not in vary_tokens:
        findings.append(
            _make(
                id="KAFKA-CORS-007",
                title="Specific CORS origin without 'Vary: Origin'",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description=(
                    "If the allowed origin changes per request, caches need 'Vary: Origin' "
                    "to avoid serving one origin's CORS headers to another."
                ),
                evidence=f"Vary: {clean_text(snap.header('vary') or '(not present)', max_length=100)}",
                recommendation="Add 'Vary: Origin' when the response depends on the request origin.",
            )
        )
    return findings
