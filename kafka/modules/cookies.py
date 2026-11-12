"""Cookie attribute checks: Secure, HttpOnly and SameSite.

Cookie *values* are discarded the instant a ``Set-Cookie`` line is parsed. They are never
stored, printed or put in a finding. Only cookie names and attribute flags are kept.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import partial

from kafka.models import Confidence, Finding, ResponseSnapshot, Severity
from kafka.util import clean_text

SCANNER = "cookies"
_make = partial(Finding, scanner=SCANNER)

MAX_LISTED = 10
MAX_NAME_LENGTH = 64
_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,256}$")
_SENSITIVE_NAME = re.compile(r"sess|(^|[_-])sid($|[_-])|token|auth|jwt|login", re.IGNORECASE)
_VALID_SAMESITE = frozenset({"strict", "lax", "none"})


@dataclass(frozen=True, slots=True)
class ParsedCookie:
    """Name and attribute flags of one cookie (there is deliberately no value field)."""

    name: str
    secure: bool
    http_only: bool
    same_site: str | None  # None: attribute absent; "": present without a value
    domain: str | None
    path: str | None

    @property
    def looks_sensitive(self) -> bool:
        return bool(_SENSITIVE_NAME.search(self.name))


def parse_set_cookie(header: str) -> ParsedCookie | None:
    """Parse one ``Set-Cookie`` line. Returns ``None`` if it is malformed."""
    parts = header.split(";")
    name, separator, _ = parts[0].partition("=")  # the value is discarded here
    name = name.strip()
    if not separator or not _TOKEN.match(name):
        return None
    secure = http_only = False
    same_site: str | None = None
    domain: str | None = None
    path: str | None = None
    for attribute in parts[1:]:
        key, _, value = attribute.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "secure":
            secure = True
        elif key == "httponly":
            http_only = True
        elif key == "samesite":
            same_site = value.lower()
        elif key == "domain":
            domain = value
        elif key == "path":
            path = value
    return ParsedCookie(
        name=clean_text(name, max_length=MAX_NAME_LENGTH),
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        domain=domain,
        path=path,
    )


def _names(cookies: list[ParsedCookie]) -> str:
    shown = ", ".join(cookie.name for cookie in cookies[:MAX_LISTED])
    extra = len(cookies) - MAX_LISTED
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def _yes_no(flag: bool) -> str:
    return "yes" if flag else "no"


def _prefix_violations(cookies: list[ParsedCookie]) -> list[ParsedCookie]:
    bad: list[ParsedCookie] = []
    for cookie in cookies:
        lowered = cookie.name.lower()
        if lowered.startswith("__host-") and (
            not cookie.secure or cookie.path != "/" or cookie.domain is not None
        ):
            bad.append(cookie)
        elif lowered.startswith("__secure-") and not cookie.secure:
            bad.append(cookie)
    return bad


def scan(snap: ResponseSnapshot) -> list[Finding]:
    raw_headers = snap.header_values("set-cookie")
    if not raw_headers:
        return [
            _make(
                id="KAFKA-CKE-001",
                title="No cookies set by this response",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=(
                    "The response contained no Set-Cookie header. Cookies may still be set by "
                    "other pages, after sign-in, or by scripts, which this scan does not visit."
                ),
                evidence="Set-Cookie: (not present)",
                recommendation="No action required for this observation.",
            )
        ]

    cookies: list[ParsedCookie] = []
    malformed = 0
    for header in raw_headers:
        parsed = parse_set_cookie(header)
        if parsed is None:
            malformed += 1
        else:
            cookies.append(parsed)

    total = len(cookies)
    findings: list[Finding] = []

    if cookies:
        lines = [
            f"{cookie.name}: Secure={_yes_no(cookie.secure)} HttpOnly={_yes_no(cookie.http_only)} "
            f"SameSite={cookie.same_site if cookie.same_site else 'not set'}"
            for cookie in cookies[:MAX_LISTED]
        ]
        if total > MAX_LISTED:
            lines.append(f"(+{total - MAX_LISTED} more)")
        findings.append(
            _make(
                id="KAFKA-CKE-009",
                title=f"{total} cookie(s) observed (names and attributes only)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=(
                    "Cookie attributes were inspected. Cookie values are never stored or "
                    "displayed by KAFKA."
                ),
                evidence="\n".join(lines),
                recommendation="Review that each cookie carries only the attributes it needs.",
            )
        )

    no_secure = [cookie for cookie in cookies if not cookie.secure]
    if no_secure:
        findings.append(
            _make(
                id="KAFKA-CKE-002",
                title="Cookie set without the Secure attribute",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    "Cookies without Secure may be sent over unencrypted HTTP connections, "
                    "where they can be read or tampered with."
                ),
                evidence=f"{len(no_secure)} of {total} lack Secure: {_names(no_secure)}",
                recommendation="Add the Secure attribute to every cookie on an HTTPS site.",
            )
        )

    no_http_only = [cookie for cookie in cookies if not cookie.http_only]
    if no_http_only:
        sensitive = any(cookie.looks_sensitive for cookie in no_http_only)
        findings.append(
            _make(
                id="KAFKA-CKE-003",
                title="Cookie set without the HttpOnly attribute",
                severity=Severity.MEDIUM if sensitive else Severity.LOW,
                confidence=Confidence.MEDIUM if sensitive else Confidence.LOW,
                description=(
                    "Cookies without HttpOnly are readable by page scripts, so a "
                    "cross-site scripting flaw could steal them. Some cookies are meant to be "
                    "script-readable; the severity is raised only when a name looks like a "
                    "session or authentication cookie (a heuristic)."
                ),
                evidence=f"{len(no_http_only)} of {total} lack HttpOnly: {_names(no_http_only)}",
                recommendation=(
                    "Add HttpOnly to session and authentication cookies that scripts do not need."
                ),
            )
        )

    no_same_site = [cookie for cookie in cookies if cookie.same_site is None]
    if no_same_site:
        findings.append(
            _make(
                id="KAFKA-CKE-004",
                title="Cookie set without the SameSite attribute",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description=(
                    "Without SameSite, behaviour depends on the browser default (modern "
                    "browsers treat it as Lax). An explicit value is clearer and safer."
                ),
                evidence=f"{len(no_same_site)} of {total} lack SameSite: {_names(no_same_site)}",
                recommendation="Set SameSite=Lax (or Strict) unless cross-site use is required.",
            )
        )

    none_without_secure = [
        cookie for cookie in cookies if cookie.same_site == "none" and not cookie.secure
    ]
    if none_without_secure:
        findings.append(
            _make(
                id="KAFKA-CKE-005",
                title="SameSite=None used without Secure",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    "Browsers reject SameSite=None cookies that are not marked Secure, and "
                    "the combination indicates a misconfiguration."
                ),
                evidence=f"Affected: {_names(none_without_secure)}",
                recommendation="Add Secure, or use SameSite=Lax/Strict if cross-site use is not needed.",
            )
        )

    bad_samesite = [
        cookie
        for cookie in cookies
        if cookie.same_site is not None and cookie.same_site not in _VALID_SAMESITE
    ]
    if bad_samesite:
        findings.append(
            _make(
                id="KAFKA-CKE-006",
                title="Cookie has an invalid SameSite value",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="SameSite must be Strict, Lax or None; browsers ignore other values.",
                evidence=f"Affected: {_names(bad_samesite)}",
                recommendation="Use SameSite=Strict, Lax or None (None requires Secure).",
            )
        )

    prefix_bad = _prefix_violations(cookies)
    if prefix_bad:
        findings.append(
            _make(
                id="KAFKA-CKE-007",
                title="Cookie name prefix requirements not met",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    "__Secure- cookies must be Secure. __Host- cookies must also have "
                    "Path=/ and no Domain attribute. Browsers reject cookies that violate this."
                ),
                evidence=f"Affected: {_names(prefix_bad)}",
                recommendation="Fix the attributes or remove the prefix.",
            )
        )

    if malformed:
        findings.append(
            _make(
                id="KAFKA-CKE-008",
                title="Malformed Set-Cookie header",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=(
                    "A Set-Cookie header could not be parsed (missing name or '=', or invalid "
                    "characters in the name). Browsers may ignore or mishandle it."
                ),
                evidence=f"{malformed} Set-Cookie header(s) could not be parsed (content not shown)",
                recommendation="Emit well-formed cookies: name=value followed by attributes.",
            )
        )
    return findings
