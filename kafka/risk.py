"""Risk summary: severity counts, preliminary triage level and top recommendations."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from kafka.models import SEVERITY_ORDER, Confidence, Finding, Severity

_CONFIDENCE_RANK = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}

TRIAGE_TEXT = {
    Severity.CRITICAL: "Elevated: review the highest-severity findings first",
    Severity.HIGH: "Elevated: review the highest-severity findings first",
    Severity.MEDIUM: "Moderate: review recommended",
    Severity.LOW: "Low: hardening opportunities only",
    Severity.INFO: "Informational only: no actionable findings from this passive check",
}
NO_FINDINGS_TEXT = "No findings recorded"

# Text markers so severity never depends on colour alone.
GLYPHS = {
    Severity.CRITICAL: "[!!!!]",
    Severity.HIGH: "[!!!]",
    Severity.MEDIUM: "[!!]",
    Severity.LOW: "[!]",
    Severity.INFO: "[i]",
}


@dataclass(frozen=True)
class RiskSummary:
    """Aggregate view of findings. Preliminary triage, not a security score."""

    counts: dict[str, int]
    total: int
    highest: str | None
    triage: str

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "by_severity": dict(self.counts),
            "highest_severity": self.highest,
            "triage": self.triage,
        }


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Most severe first, then most confident, then by stable ID."""
    return sorted(
        findings,
        key=lambda f: (-f.severity.rank, -_CONFIDENCE_RANK[f.confidence], f.id),
    )


def summarize(findings: Iterable[Finding]) -> RiskSummary:
    """Count findings per severity and derive the triage level from the worst one."""
    items = list(findings)
    counts = {severity.value: 0 for severity in SEVERITY_ORDER}
    for finding in items:
        counts[finding.severity.value] += 1
    highest = next((s for s in SEVERITY_ORDER if counts[s.value] > 0), None)
    triage = TRIAGE_TEXT[highest] if highest is not None else NO_FINDINGS_TEXT
    return RiskSummary(
        counts=counts,
        total=len(items),
        highest=highest.value if highest else None,
        triage=triage,
    )


def top_recommendations(findings: Iterable[Finding], limit: int = 5) -> list[tuple[str, str]]:
    """Up to ``limit`` ``(finding id, recommendation)`` pairs from actionable findings."""
    actionable = [f for f in sort_findings(findings) if f.severity is not Severity.INFO]
    return [(f.id, f.recommendation) for f in actionable[:limit]]
