"""HTTPS / transport observation.

Reports whether the target URL used HTTP or HTTPS and describes redirects without
following them. This is an observation of one connection, not a TLS audit.
"""

from __future__ import annotations

from functools import partial
from urllib.parse import urljoin, urlsplit

from kafka.models import Confidence, Finding, ResponseSnapshot, Severity
from kafka.util import clean_text

SCANNER = "https"
_make = partial(Finding, scanner=SCANNER)


def _redirect_target(snap: ResponseSnapshot) -> tuple[str, str] | None:
    """Return ``(scheme, safe display text)`` for the redirect Location, if any."""
    location = snap.location
    if not snap.is_redirect or location is None:
        return None
    host = f"[{snap.hostname}]" if ":" in snap.hostname else snap.hostname
    base = f"{snap.scheme}://{host}:{snap.port}/"
    try:
        parts = urlsplit(urljoin(base, location.strip()))
        port = parts.port
    except ValueError:
        return None
    shown = f"{parts.scheme.lower()}://{parts.hostname or ''}"
    if port:
        shown += f":{port}"
    shown += parts.path
    if parts.query or parts.fragment:
        shown += " (query/fragment omitted)"
    return parts.scheme.lower(), clean_text(shown, max_length=200)


def scan(snap: ResponseSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    redirect = _redirect_target(snap)
    redirect_note = f"; redirects to {redirect[1]}" if redirect else ""

    if snap.scheme == "http":
        if redirect is not None and redirect[0] == "https":
            findings.append(
                _make(
                    id="KAFKA-TLS-002",
                    title="HTTP endpoint redirects to HTTPS (redirect not followed)",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=(
                        "The plain-HTTP URL answered with a redirect to HTTPS. The first "
                        "request still travels unencrypted, so a network attacker could "
                        "interfere before the redirect happens unless HSTS is in place."
                    ),
                    evidence=f"HTTP {snap.status_code}; Location: {redirect[1]}",
                    recommendation=(
                        "Keep the redirect, send Strict-Transport-Security from the HTTPS "
                        "site, and consider HSTS preloading once the site is HTTPS-only."
                    ),
                )
            )
        else:
            findings.append(
                _make(
                    id="KAFKA-TLS-001",
                    title="Page served over unencrypted HTTP",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        "The target URL uses http://, so traffic between the browser and the "
                        "server is neither encrypted nor integrity-protected. Credentials, "
                        "cookies and page content can be read or altered on the network."
                    ),
                    evidence=f"Scheme: http; HTTP {snap.status_code}{redirect_note}",
                    recommendation=(
                        "Serve the site over HTTPS with a valid certificate, redirect all HTTP "
                        "requests to HTTPS, then enable HSTS."
                    ),
                )
            )
    else:
        protocol = snap.tls_protocol or "not reported"
        findings.append(
            _make(
                id="KAFKA-TLS-003",
                title="HTTPS connection accepted with certificate verification",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=(
                    "This client completed a TLS connection and accepted the server "
                    "certificate for the host name. That is all this check shows; it is not "
                    "an audit of protocol versions, cipher suites or the certificate chain."
                ),
                evidence=(
                    f"Connected to {snap.hostname}:{snap.port}; certificate and host name "
                    f"verified; negotiated protocol: {protocol}"
                ),
                recommendation=(
                    "No action required for this observation. Use a dedicated TLS testing "
                    "tool for a full assessment."
                ),
            )
        )

    if redirect is not None:
        findings.append(
            _make(
                id="KAFKA-TLS-004",
                title="Response is a redirect (not followed)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=(
                    "KAFKA never follows redirects, so the headers and cookies of the "
                    "destination page were not examined."
                ),
                evidence=f"HTTP {snap.status_code}; Location: {redirect[1]}",
                recommendation=(
                    "If you are authorized to assess the destination, scan it as a separate target."
                ),
            )
        )
        if snap.scheme == "https" and redirect[0] == "http":
            findings.append(
                _make(
                    id="KAFKA-TLS-005",
                    title="HTTPS endpoint redirects to plain HTTP",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        "The HTTPS response sends visitors to an unencrypted HTTP URL, which "
                        "downgrades the connection."
                    ),
                    evidence=f"HTTP {snap.status_code}; Location: {redirect[1]}",
                    recommendation="Redirect to an https:// URL and enable HSTS.",
                )
            )
    return findings
