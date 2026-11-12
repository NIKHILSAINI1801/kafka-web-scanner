"""Technology metadata the server volunteers: Server, X-Powered-By and HTML generator.

Purely observational: no probing, no fingerprint databases. Everything here is
self-reported by the server and may be missing, generic or deliberately misleading.
"""

from __future__ import annotations

import codecs
import re
from functools import partial

from bs4 import BeautifulSoup, SoupStrainer

from kafka.models import Confidence, Finding, ResponseSnapshot, Severity
from kafka.util import clean_text

SCANNER = "technology"
_make = partial(Finding, scanner=SCANNER)
_VERSION = re.compile(r"\d+(?:\.\d+)+")
_SPOOF_NOTE = " This value is self-reported by the server and may be incomplete or spoofed."


def _generator(snap: ResponseSnapshot) -> str | None:
    """Read ``<meta name="generator">`` from the (capped, in-memory) HTML body."""
    if not snap.body or snap.content_encoding not in ("", "identity"):
        return None
    if snap.media_type and not snap.is_html:
        return None
    encoding = "utf-8"
    if snap.charset:
        try:
            encoding = codecs.lookup(snap.charset).name
        except LookupError:
            encoding = "utf-8"
    text = snap.body.decode(encoding, errors="replace")
    soup = BeautifulSoup(text, "html.parser", parse_only=SoupStrainer("meta"))
    for meta in soup.find_all("meta"):
        if str(meta.get("name", "")).strip().lower() == "generator":
            content = meta.get("content")
            if content:
                return clean_text(str(content), max_length=150)
    return None


def scan(snap: ResponseSnapshot) -> list[Finding]:
    findings: list[Finding] = []

    server = snap.header("server")
    if server:
        shown = clean_text(server, max_length=150)
        if _VERSION.search(shown):
            findings.append(
                _make(
                    id="KAFKA-TECH-001",
                    title="Server header discloses a software version",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description=(
                        "Version details help an attacker look up known weaknesses for that "
                        "exact release. Hiding them is hardening, not a fix for the "
                        "underlying software." + _SPOOF_NOTE
                    ),
                    evidence=f"Server: {shown}",
                    recommendation=(
                        "Remove version numbers from the Server header (for example "
                        "'server_tokens off' in nginx, 'ServerTokens Prod' in Apache) and keep "
                        "the software patched."
                    ),
                )
            )
        else:
            findings.append(
                _make(
                    id="KAFKA-TECH-002",
                    title="Server header present (no version disclosed)",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    description="The server names its software without a version." + _SPOOF_NOTE,
                    evidence=f"Server: {shown}",
                    recommendation="No action required for this observation.",
                )
            )

    powered_by = snap.header("x-powered-by")
    if powered_by:
        shown = clean_text(powered_by, max_length=150)
        has_version = bool(_VERSION.search(shown))
        findings.append(
            _make(
                id="KAFKA-TECH-003",
                title="X-Powered-By header discloses the application platform",
                severity=Severity.LOW if has_version else Severity.INFO,
                confidence=Confidence.MEDIUM,
                description=(
                    "This header reveals the framework or runtime behind the site"
                    + (", including a version" if has_version else "")
                    + "."
                    + _SPOOF_NOTE
                ),
                evidence=f"X-Powered-By: {shown}",
                recommendation="Disable the X-Powered-By header in the framework or proxy settings.",
            )
        )

    generator = _generator(snap)
    if generator:
        has_version = bool(_VERSION.search(generator))
        findings.append(
            _make(
                id="KAFKA-TECH-004",
                title="HTML generator meta tag discloses the publishing software",
                severity=Severity.LOW if has_version else Severity.INFO,
                confidence=Confidence.MEDIUM,
                description=(
                    'A <meta name="generator"> tag names the CMS or site builder'
                    + (" and its version" if has_version else "")
                    + "."
                    + _SPOOF_NOTE
                ),
                evidence=f'<meta name="generator" content="{generator}">',
                recommendation="Remove or genericise the generator meta tag and keep the software updated.",
            )
        )

    if not findings:
        findings.append(
            _make(
                id="KAFKA-TECH-005",
                title="No technology metadata observed",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                description=(
                    "No Server, X-Powered-By or generator metadata was observed in this "
                    "response. The technology in use may still be identifiable by other means."
                ),
                evidence="Server / X-Powered-By / generator: (not present)",
                recommendation="No action required for this observation.",
            )
        )
    return findings
