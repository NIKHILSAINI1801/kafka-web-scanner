"""Shared helpers for building response snapshots and findings in tests."""

from __future__ import annotations

from pathlib import Path

from kafka.models import ResponseSnapshot

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def make_snapshot(
    headers: dict[str, str] | list[tuple[str, str]] | None = None,
    *,
    scheme: str = "https",
    status: int = 200,
    body: bytes | str = b"",
    content_type: str | None = "text/html; charset=utf-8",
    **extra,
) -> ResponseSnapshot:
    """Build a snapshot. ``headers`` may be a dict or a list (to repeat header lines)."""
    lines = list(headers.items()) if isinstance(headers, dict) else list(headers or [])
    if content_type and not any(name.lower() == "content-type" for name, _ in lines):
        lines.insert(0, ("Content-Type", content_type))
    if isinstance(body, str):
        body = body.encode("utf-8")
    return ResponseSnapshot(
        scheme=scheme,
        hostname="example.test",
        port=443 if scheme == "https" else 80,
        status_code=status,
        reason="OK",
        headers=lines,
        body=body,
        tls_verified=scheme == "https",
        tls_protocol="TLSv1.3" if scheme == "https" else None,
        **extra,
    )


def ids(findings) -> set[str]:
    return {finding.id for finding in findings}


def by_id(findings, finding_id: str):
    matches = [finding for finding in findings if finding.id == finding_id]
    assert len(matches) == 1, f"expected exactly one {finding_id}, got {len(matches)}"
    return matches[0]


def make_finding(finding_id="KAFKA-HDR-001", severity="LOW", confidence="MEDIUM", **overrides):
    from kafka.models import Finding

    data = {
        "id": finding_id,
        "scanner": "headers",
        "title": f"Title {finding_id}",
        "severity": severity,
        "confidence": confidence,
        "description": "Description",
        "evidence": "Evidence",
        "recommendation": f"Recommendation for {finding_id}",
    }
    data.update(overrides)
    return Finding(**data)


def make_result(findings=None, **overrides):
    from datetime import UTC, datetime

    from kafka.models import ScanResult

    data = {
        "target": "https://example.test/",
        "tool_version": "1.0.0",
        "started_at": datetime(2026, 5, 6, 7, 8, 9, tzinfo=UTC),
        "finished_at": datetime(2026, 5, 6, 7, 8, 11, tzinfo=UTC),
        "status": "completed",
        "status_code": 200,
        "http": {"reason": "OK", "resolved_ip": "93.184.216.34", "tls_protocol": "TLSv1.3"},
        "findings": list(findings or []),
    }
    data.update(overrides)
    return ScanResult(**data)
