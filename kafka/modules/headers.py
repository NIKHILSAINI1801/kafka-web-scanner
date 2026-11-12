"""Security header checks: CSP, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy."""

from __future__ import annotations

import re
from functools import partial

from kafka.models import Confidence, Finding, ResponseSnapshot, Severity
from kafka.util import clean_text

SCANNER = "headers"
_make = partial(Finding, scanner=SCANNER)

HSTS_MIN_AGE = 15_552_000  # 180 days
HSTS_RECOMMENDED_AGE = 31_536_000  # 1 year
_REFERRER_VALUES = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
)
_WEAK_REFERRER = frozenset({"unsafe-url", "no-referrer-when-downgrade"})
_HASH_PREFIXES = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")


def _shown(value: str) -> str:
    return clean_text(value, max_length=600)


def _is_success(snap: ResponseSnapshot) -> bool:
    return 200 <= snap.status_code < 300


def _missing_confidence(snap: ResponseSnapshot) -> Confidence:
    return Confidence.MEDIUM if snap.is_html and _is_success(snap) else Confidence.LOW


def _context_note(snap: ResponseSnapshot) -> str:
    if snap.is_redirect:
        return " This response is a redirect, so the header may matter mainly on the final page."
    if not snap.is_html:
        kind = clean_text(snap.media_type, max_length=60) or "unknown"
        return f" The response is not HTML (content type: {kind}), so this may be less relevant."
    return ""


def _parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tokens[1:])
    return directives


def _csp_issues(directives: dict[str, list[str]]) -> list[str]:
    issues: list[str] = []
    script = (
        directives["script-src"] if "script-src" in directives else directives.get("default-src")
    )
    if script is None:
        issues.append("no script-src or default-src directive restricts script sources")
    else:
        tokens = [token.lower() for token in script]
        protected = any(token.startswith(_HASH_PREFIXES) for token in tokens)
        if "'unsafe-inline'" in tokens and not protected and "'strict-dynamic'" not in tokens:
            issues.append("'unsafe-inline' permits inline scripts")
        if "'unsafe-eval'" in tokens:
            issues.append("'unsafe-eval' permits string-to-code evaluation")
        if "*" in tokens or any(token in {"http:", "https:", "data:"} for token in tokens):
            issues.append("script sources include a wildcard or an entire scheme")
    if "object-src" not in directives and "default-src" not in directives:
        issues.append("object-src is not restricted")
    return issues


def _check_csp(snap: ResponseSnapshot) -> list[Finding]:
    enforced = snap.header("content-security-policy")
    report_only = snap.header("content-security-policy-report-only")
    if enforced is None and report_only is not None:
        return [
            _make(
                id="KAFKA-HDR-004",
                title="Content-Security-Policy is report-only",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description=(
                    "Only Content-Security-Policy-Report-Only was observed. It reports "
                    "violations but does not block anything."
                ),
                evidence=f"Content-Security-Policy-Report-Only: {_shown(report_only)}",
                recommendation=(
                    "After reviewing the reports, enforce the policy with the "
                    "Content-Security-Policy header."
                ),
            )
        ]
    if enforced is None:
        return [
            _make(
                id="KAFKA-HDR-001",
                title="Content-Security-Policy header not observed",
                severity=Severity.MEDIUM,
                confidence=_missing_confidence(snap),
                description=(
                    "No Content-Security-Policy header was present. CSP limits where scripts "
                    "and other resources may load from and reduces the impact of "
                    "cross-site scripting." + _context_note(snap)
                ),
                evidence="Content-Security-Policy: (not present)",
                recommendation=(
                    "Define a policy such as: Content-Security-Policy: default-src 'self'; "
                    "object-src 'none'; frame-ancestors 'self'. Test it in report-only mode "
                    "first."
                ),
            )
        ]
    issues = _csp_issues(_parse_csp(enforced))
    evidence = f"Content-Security-Policy: {_shown(enforced)}"
    if issues:
        return [
            _make(
                id="KAFKA-HDR-003",
                title="Content-Security-Policy contains weak directives",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description="The policy is present but weaker than it could be: "
                + "; ".join(issues)
                + ".",
                evidence=evidence,
                recommendation=(
                    "Tighten the policy: avoid 'unsafe-inline' and 'unsafe-eval' (use nonces "
                    "or hashes), avoid wildcard sources, and set object-src 'none'."
                ),
            )
        ]
    return [
        _make(
            id="KAFKA-HDR-002",
            title="Content-Security-Policy header present",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            description="A Content-Security-Policy header was observed. No obvious weakness found.",
            evidence=evidence,
            recommendation="Review the policy periodically; this check is not a full CSP audit.",
        )
    ]


def _check_xcto(snap: ResponseSnapshot) -> list[Finding]:
    value = snap.header("x-content-type-options")
    confidence = Confidence.MEDIUM if _is_success(snap) else Confidence.LOW
    if value is None:
        return [
            _make(
                id="KAFKA-HDR-010",
                title="X-Content-Type-Options header not observed",
                severity=Severity.LOW,
                confidence=confidence,
                description=(
                    "Without 'nosniff', some browsers may guess a different content type "
                    "than the server declared, which can turn uploads or misdeclared "
                    "resources into executable content."
                ),
                evidence="X-Content-Type-Options: (not present)",
                recommendation="Send the header: X-Content-Type-Options: nosniff",
            )
        ]
    tokens = {token.strip().lower() for token in value.split(",")}
    if tokens == {"nosniff"}:
        return [
            _make(
                id="KAFKA-HDR-011",
                title="X-Content-Type-Options set to nosniff",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description="MIME-type sniffing is disabled for this response.",
                evidence=f"X-Content-Type-Options: {_shown(value)}",
                recommendation="No action required.",
            )
        ]
    return [
        _make(
            id="KAFKA-HDR-012",
            title="X-Content-Type-Options has an unexpected value",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description="The only value browsers act on is 'nosniff'.",
            evidence=f"X-Content-Type-Options: {_shown(value)}",
            recommendation="Send exactly: X-Content-Type-Options: nosniff",
        )
    ]


def _check_hsts(snap: ResponseSnapshot) -> list[Finding]:
    value = snap.header("strict-transport-security")
    if snap.scheme != "https":
        return [
            _make(
                id="KAFKA-HDR-023",
                title="HSTS not evaluated (request used HTTP)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=(
                    "Browsers ignore Strict-Transport-Security received over plain HTTP, so "
                    "it is only meaningful on HTTPS responses."
                ),
                evidence=(
                    f"Strict-Transport-Security: {_shown(value)}"
                    if value
                    else "Request used http://; HSTS evaluation skipped."
                ),
                recommendation="Serve the site over HTTPS and send HSTS from those responses.",
            )
        ]
    if value is None:
        return [
            _make(
                id="KAFKA-HDR-020",
                title="Strict-Transport-Security (HSTS) header not observed",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    "The HTTPS response did not send HSTS, so browsers are not told to "
                    "refuse future plain-HTTP connections to this host."
                ),
                evidence="Strict-Transport-Security: (not present)",
                recommendation=(
                    "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains "
                    "(only after confirming all subdomains support HTTPS)."
                ),
            )
        ]
    match = re.search(r"max-age\s*=\s*\"?(\d+)\"?", value, re.IGNORECASE)
    max_age = int(match.group(1)) if match else None
    problem = None
    if max_age is None:
        problem = "no valid max-age directive"
    elif max_age == 0:
        problem = "max-age=0 switches HSTS off"
    elif max_age < HSTS_MIN_AGE:
        problem = f"max-age of {max_age} seconds is shorter than 180 days"
    if problem:
        return [
            _make(
                id="KAFKA-HDR-022",
                title="HSTS policy is weak or ineffective",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=f"The Strict-Transport-Security header is present but {problem}.",
                evidence=f"Strict-Transport-Security: {_shown(value)}",
                recommendation=(
                    f"Use max-age of at least {HSTS_RECOMMENDED_AGE} seconds (one year)."
                ),
            )
        ]
    return [
        _make(
            id="KAFKA-HDR-021",
            title="Strict-Transport-Security (HSTS) header present",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            description="HSTS is sent with a max-age of at least 180 days.",
            evidence=f"Strict-Transport-Security: {_shown(value)}",
            recommendation="No action required for this observation.",
        )
    ]


def _check_referrer(snap: ResponseSnapshot) -> list[Finding]:
    value = snap.header("referrer-policy")
    if value is None:
        return [
            _make(
                id="KAFKA-HDR-030",
                title="Referrer-Policy header not observed",
                severity=Severity.LOW,
                confidence=_missing_confidence(snap),
                description=(
                    "Without an explicit policy, browsers apply their own default, and older "
                    "browsers may send full URLs (including paths and query strings) to other "
                    "sites." + _context_note(snap)
                ),
                evidence="Referrer-Policy: (not present)",
                recommendation="Send: Referrer-Policy: strict-origin-when-cross-origin",
            )
        ]
    tokens = [token.strip().lower() for token in value.split(",") if token.strip()]
    recognised = [token for token in tokens if token in _REFERRER_VALUES]
    if not recognised:
        problem = "no recognised policy value"
    elif recognised[-1] in _WEAK_REFERRER:
        problem = f"'{recognised[-1]}' can leak full URLs to other sites"
    else:
        problem = None
    if problem:
        return [
            _make(
                id="KAFKA-HDR-032",
                title="Referrer-Policy is weak or unrecognised",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description=f"The Referrer-Policy header is present but {problem}.",
                evidence=f"Referrer-Policy: {_shown(value)}",
                recommendation="Use strict-origin-when-cross-origin or a stricter policy.",
            )
        ]
    return [
        _make(
            id="KAFKA-HDR-031",
            title="Referrer-Policy header present",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            description="An explicit referrer policy was observed.",
            evidence=f"Referrer-Policy: {_shown(value)}",
            recommendation="No action required.",
        )
    ]


def _check_permissions(snap: ResponseSnapshot) -> list[Finding]:
    value = snap.header("permissions-policy")
    if value is None:
        return [
            _make(
                id="KAFKA-HDR-040",
                title="Permissions-Policy header not observed",
                severity=Severity.INFO,
                confidence=_missing_confidence(snap),
                description=(
                    "Permissions-Policy lets a site switch off browser features (camera, "
                    "microphone, geolocation and so on) it does not use. Its absence is a "
                    "hardening opportunity rather than a flaw." + _context_note(snap)
                ),
                evidence="Permissions-Policy: (not present)",
                recommendation=(
                    "Consider: Permissions-Policy: camera=(), microphone=(), geolocation=() "
                    "for features the site never uses."
                ),
            )
        ]
    return [
        _make(
            id="KAFKA-HDR-041",
            title="Permissions-Policy header present",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            description="A Permissions-Policy header was observed.",
            evidence=f"Permissions-Policy: {_shown(value)}",
            recommendation="Review that the policy disables features the site does not need.",
        )
    ]


def scan(snap: ResponseSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for check in (_check_csp, _check_xcto, _check_hsts, _check_referrer, _check_permissions):
        findings.extend(check(snap))
    return findings
