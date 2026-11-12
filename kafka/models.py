"""Core data models: findings, observed responses and scan results."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from kafka.util import clean_text

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_EVIDENCE_LENGTH = 1500


class Severity(StrEnum):
    """Preliminary triage level. Not proof of exploitability."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric weight: CRITICAL is 4 ... INFO is 0."""
        return len(SEVERITY_ORDER) - 1 - SEVERITY_ORDER.index(self)


SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


class Confidence(StrEnum):
    """How sure the check is that the observation is real and relevant."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


_FINDING_ID = re.compile(r"^KAFKA-[A-Z]{3,4}-\d{3}$")


@dataclass(frozen=True, slots=True)
class Finding:
    """One observation produced by a scanner module."""

    id: str
    scanner: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str
    recommendation: str

    def __post_init__(self) -> None:
        if not _FINDING_ID.match(self.id):
            raise ValueError(f"invalid finding id: {self.id!r}")
        object.__setattr__(self, "severity", Severity(self.severity))
        object.__setattr__(self, "confidence", Confidence(self.confidence))
        object.__setattr__(self, "scanner", clean_text(self.scanner, max_length=40))
        object.__setattr__(self, "title", clean_text(self.title, max_length=200))
        object.__setattr__(self, "description", clean_text(self.description, max_length=1500))
        object.__setattr__(
            self,
            "evidence",
            clean_text(self.evidence, max_length=MAX_EVIDENCE_LENGTH, keep_newlines=True),
        )
        object.__setattr__(self, "recommendation", clean_text(self.recommendation, max_length=1500))

    def to_dict(self) -> dict[str, str]:
        """JSON-serialisable representation with a stable key order."""
        return {
            "id": self.id,
            "scanner": self.scanner,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Rebuild a finding from :meth:`to_dict` output (e.g. from the history database)."""
        return cls(
            id=str(data["id"]),
            scanner=str(data["scanner"]),
            title=str(data["title"]),
            severity=Severity(data["severity"]),
            confidence=Confidence(data["confidence"]),
            description=str(data["description"]),
            evidence=str(data["evidence"]),
            recommendation=str(data["recommendation"]),
        )


@dataclass(frozen=True, slots=True)
class ScanError:
    """A problem that stopped or degraded a scan (never a stack trace)."""

    code: str
    message: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", clean_text(self.code, max_length=60))
        object.__setattr__(self, "message", clean_text(self.message, max_length=500))

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(slots=True)
class ResponseSnapshot:
    """What the single GET request returned. Held in memory only, never persisted.

    ``headers`` keeps every header line (so repeated ``Set-Cookie`` lines stay separate).
    ``body`` is capped by the HTTP client and used only for in-memory HTML metadata checks.
    """

    scheme: str
    hostname: str
    port: int
    status_code: int
    reason: str = ""
    http_version: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    body_truncated: bool = False
    elapsed_ms: int = 0
    resolved_ip: str = ""
    tls_verified: bool = False
    tls_protocol: str | None = None

    def header_values(self, name: str) -> list[str]:
        """All values of a header (case-insensitive), one entry per header line."""
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    def header(self, name: str) -> str | None:
        """Header value, with repeated lines joined by ``", "``; ``None`` if absent."""
        values = self.header_values(name)
        return ", ".join(values) if values else None

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").strip()

    @property
    def media_type(self) -> str:
        return self.content_type.split(";", 1)[0].strip().lower()

    @property
    def charset(self) -> str | None:
        match = re.search(r"charset\s*=\s*\"?([A-Za-z0-9_.:-]+)", self.content_type, re.I)
        return match.group(1) if match else None

    @property
    def is_html(self) -> bool:
        return self.media_type in {"text/html", "application/xhtml+xml"}

    @property
    def location(self) -> str | None:
        return self.header("location")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in REDIRECT_STATUSES and bool(self.location)

    @property
    def content_encoding(self) -> str:
        return (self.header("content-encoding") or "").strip().lower()


@dataclass
class ScanResult:
    """Everything known about one scan. Contains no response body and no secrets."""

    target: str
    tool_version: str
    started_at: datetime
    finished_at: datetime | None = None
    status: str = "completed"
    status_code: int | None = None
    http: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    modules_run: list[str] = field(default_factory=list)
    authorization: str = "interactive"
    lab_mode: bool = False
