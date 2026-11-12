"""JSON report."""

from __future__ import annotations

import json
from typing import Any

from kafka import TOOL_NAME
from kafka.config import DISCLAIMER, JSON_SCHEMA_VERSION, LIMITATIONS
from kafka.models import ScanResult
from kafka.risk import sort_findings, summarize
from kafka.util import format_utc


def build_report_dict(result: ScanResult) -> dict[str, Any]:
    """Machine-readable report. Contains no response body, cookie values or secrets."""
    return {
        "schema_version": JSON_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": result.tool_version},
        "target": result.target,
        "started_at": format_utc(result.started_at),
        "finished_at": format_utc(result.finished_at) if result.finished_at else None,
        "status": result.status,
        "authorization": {
            "confirmed": True,
            "method": result.authorization,
            "lab_mode": result.lab_mode,
        },
        "http": result.http,
        "modules_run": list(result.modules_run),
        "summary": summarize(result.findings).to_dict(),
        "findings": [finding.to_dict() for finding in sort_findings(result.findings)],
        "errors": [error.to_dict() for error in result.errors],
        "warnings": list(result.warnings),
        "limitations": list(LIMITATIONS),
        "disclaimer": DISCLAIMER,
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(build_report_dict(result), indent=2, ensure_ascii=False) + "\n"
