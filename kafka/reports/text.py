"""Plain-text report."""

from __future__ import annotations

import textwrap

from kafka import TOOL_NAME
from kafka.config import DISCLAIMER, LIMITATIONS
from kafka.models import SEVERITY_ORDER, ScanResult
from kafka.risk import GLYPHS, sort_findings, summarize, top_recommendations
from kafka.util import format_utc

WIDTH = 88


def _wrap(text: str, indent: str = "    ") -> str:
    return textwrap.fill(text, width=WIDTH, initial_indent=indent, subsequent_indent=indent)


def render_text(result: ScanResult) -> str:
    summary = summarize(result.findings)
    rule = "=" * WIDTH
    lines = [
        f"{TOOL_NAME} SCAN REPORT",
        rule,
        f"Target:          {result.target}",
        f"Scan started:    {format_utc(result.started_at)} (UTC)",
        f"Scan finished:   {format_utc(result.finished_at) if result.finished_at else 'n/a'} (UTC)",
        f"Tool version:    {TOOL_NAME} {result.tool_version}",
        f"Scan status:     {result.status}",
        f"HTTP status:     {result.status_code if result.status_code is not None else 'n/a'}",
        f"Authorization:   confirmed ({result.authorization})"
        + ("; lab mode (--allow-private)" if result.lab_mode else ""),
    ]
    for label, key in (
        ("Resolved IP", "resolved_ip"),
        ("TLS protocol", "tls_protocol"),
        ("Bytes read", "response_bytes_read"),
    ):
        value = result.http.get(key)
        if value not in (None, ""):
            lines.append(f"{label + ':':<17}{value}")
    lines += ["", "SUMMARY", "-" * WIDTH]
    for severity in SEVERITY_ORDER:
        lines.append(
            f"  {GLYPHS[severity]:<7} {severity.value:<9} {summary.counts[severity.value]}"
        )
    lines.append(f"  Total findings: {summary.total}")
    lines.append(f"  Preliminary triage: {summary.triage}")

    recommendations = top_recommendations(result.findings)
    if recommendations:
        lines += ["", "PRIORITY RECOMMENDATIONS", "-" * WIDTH]
        for index, (finding_id, text) in enumerate(recommendations, start=1):
            lines.append(_wrap(f"{index}. [{finding_id}] {text}", indent="  "))

    lines += ["", "FINDINGS", "-" * WIDTH]
    if not result.findings:
        lines.append("  No findings were produced.")
    for finding in sort_findings(result.findings):
        lines += [
            "",
            f"{GLYPHS[finding.severity]} {finding.severity.value} | {finding.id} | "
            f"confidence: {finding.confidence.value} | module: {finding.scanner}",
            f"  {finding.title}",
            _wrap(f"Description: {finding.description}"),
            "    Evidence:",
        ]
        lines += [f"      {line}" for line in finding.evidence.splitlines() or [""]]
        lines.append(_wrap(f"Recommendation: {finding.recommendation}"))

    if result.errors or result.warnings:
        lines += ["", "SCAN NOTES", "-" * WIDTH]
        lines += [
            _wrap(f"Error [{error.code}]: {error.message}", indent="  ") for error in result.errors
        ]
        lines += [_wrap(f"Warning: {warning}", indent="  ") for warning in result.warnings]

    lines += ["", "LIMITATIONS", "-" * WIDTH]
    lines += [_wrap(f"- {item}", indent="  ") for item in LIMITATIONS]
    lines += ["", textwrap.fill(DISCLAIMER, width=WIDTH), ""]
    return "\n".join(lines)
