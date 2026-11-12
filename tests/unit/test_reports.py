import json

import pytest
from bs4 import BeautifulSoup

from kafka.config import DISCLAIMER
from kafka.models import Confidence, Finding, ScanError, Severity
from kafka.reports import (
    ReportError,
    build_report_dict,
    render_html,
    render_json,
    render_text,
    report_stem,
    write_reports,
)
from tests.helpers import make_finding, make_result

HOSTILE = '<script>alert("xss")</script><img src=x onerror=alert(1)>'


def _hostile_result():
    finding = Finding(
        id="KAFKA-TECH-001",
        scanner="technology",
        title=f"Title {HOSTILE}",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        description=f"Desc {HOSTILE}",
        evidence=f"Server: {HOSTILE}\nsecond line & <b>",
        recommendation=f"Fix {HOSTILE}",
    )
    return make_result(
        [finding, make_finding("KAFKA-HDR-001", "MEDIUM")],
        errors=[ScanError("module_failed", f"oops {HOSTILE}")],
        warnings=[f"warn {HOSTILE}"],
    )


def test_html_escapes_hostile_content_everywhere():
    html = render_html(_hostile_result())
    soup = BeautifulSoup(html, "html.parser")
    assert soup.find_all("script") == []
    assert soup.find("img") is None
    assert "<script" not in html.lower() and "<img" not in html.lower()
    assert "&lt;script&gt;" in html


def test_html_has_no_scripts_or_third_party_assets():
    html = render_html(make_result([make_finding()]))
    soup = BeautifulSoup(html, "html.parser")
    assert soup.find_all("script") == [] and soup.find_all("link") == []
    for tag in soup.find_all(["img", "iframe", "source", "audio", "video", "object", "embed"]):
        raise AssertionError(f"unexpected asset tag: {tag.name}")
    for tag in soup.find_all(True):
        for attribute in ("src", "href", "action"):
            value = tag.get(attribute)
            assert value is None or value.startswith("#"), (tag.name, attribute, value)
    assert "Content-Security-Policy" in html
    assert "@import" not in html and "url(" not in html


def test_html_is_responsive_and_complete():
    html = render_html(
        make_result(
            [make_finding("KAFKA-HDR-001", "MEDIUM"), make_finding("KAFKA-HDR-002", "INFO")]
        )
    )
    soup = BeautifulSoup(html, "html.parser")
    assert soup.find("meta", attrs={"name": "viewport"}) is not None
    assert soup.html.get("lang") == "en"
    assert soup.title.string and "example.test" in soup.title.string
    for needle in (
        "https://example.test/",
        "2026-05-06T07:08:09Z",
        "KAFKA 1.0.0",
        "completed",
        "200 OK",
        "KAFKA-HDR-001",
        "KAFKA-HDR-002",
        "MEDIUM",
        "Recommendation",
        "Evidence",
        DISCLAIMER[:40],
        "Limitations",
    ):
        assert needle in html, needle
    assert "prefers-color-scheme" in html and "max-width" in html


def test_html_shows_severity_as_text_not_only_colour():
    html = render_html(make_result([make_finding(severity="HIGH")]))
    assert "[!!!] HIGH" in html


def test_html_for_a_failed_scan_with_no_findings():
    result = make_result(
        [],
        status="failed",
        status_code=None,
        http={},
        errors=[ScanError("timeout", "The request timed out.")],
    )
    html = render_html(result)
    assert "No findings were produced." in html and "timeout" in html and "n/a" in html


def test_json_report_has_the_documented_structure():
    result = make_result(
        [make_finding("KAFKA-HDR-002", "LOW"), make_finding("KAFKA-HDR-001", "HIGH")],
        errors=[ScanError("module_failed", "x")],
        modules_run=["https"],
        lab_mode=True,
    )
    data = json.loads(render_json(result))
    assert data["schema_version"] == "1.0"
    assert data["tool"] == {"name": "KAFKA", "version": "1.0.0"}
    assert data["target"] == "https://example.test/"
    assert (
        data["started_at"] == "2026-05-06T07:08:09Z"
        and data["finished_at"] == "2026-05-06T07:08:11Z"
    )
    assert data["status"] == "completed"
    assert data["summary"]["by_severity"] == {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 0,
        "LOW": 1,
        "INFO": 0,
    }
    assert data["summary"]["total"] == 2 and data["summary"]["highest_severity"] == "HIGH"
    assert [f["id"] for f in data["findings"]] == ["KAFKA-HDR-001", "KAFKA-HDR-002"]
    assert data["errors"] == [{"code": "module_failed", "message": "x"}]
    assert data["authorization"] == {"confirmed": True, "method": "interactive", "lab_mode": True}
    assert set(data["findings"][0]) == {
        "id",
        "scanner",
        "title",
        "severity",
        "confidence",
        "description",
        "evidence",
        "recommendation",
    }
    assert data["limitations"] and data["disclaimer"]


def test_json_report_round_trips_hostile_text_safely():
    data = json.loads(render_json(_hostile_result()))
    hostile = next(f for f in data["findings"] if f["id"] == "KAFKA-TECH-001")
    assert HOSTILE in hostile["title"]  # data is preserved, just never interpreted


def test_json_report_contains_no_response_body_or_header_dump():
    keys = set(build_report_dict(make_result([make_finding()])))
    assert not {"body", "headers", "cookies", "response"} & keys


def test_text_report_contains_the_essentials():
    text = render_text(make_result([make_finding("KAFKA-HDR-001", "MEDIUM")], warnings=["careful"]))
    for needle in (
        "KAFKA SCAN REPORT",
        "https://example.test/",
        "2026-05-06T07:08:09Z",
        "KAFKA 1.0.0",
        "completed",
        "[!!] MEDIUM",
        "KAFKA-HDR-001",
        "Evidence",
        "Recommendation",
        "SUMMARY",
        "LIMITATIONS",
        "Warning: careful",
    ):
        assert needle in text, needle


def test_text_report_for_empty_result():
    assert "No findings were produced." in render_text(make_result([]))


# ---- file handling -------------------------------------------------------------------------


def test_report_stem_is_filesystem_safe():
    hostile = make_result(target="https://evil.test:8443/../../etc/passwd\\x")
    stem = report_stem(hostile)
    assert stem.startswith("kafka_") and stem.endswith("20260506T070809Z")
    for bad in ("/", "\\", "..", ":", " "):
        assert bad not in stem


def test_write_reports_creates_three_files_and_the_directory(tmp_path):
    out = tmp_path / "does" / "not" / "exist"
    paths = write_reports(make_result([make_finding()]), out)
    assert set(paths) == {"html", "json", "txt"}
    for kind, path in paths.items():
        assert path.parent == out and path.suffix == f".{kind}" and path.read_text(encoding="utf-8")
    json.loads(paths["json"].read_text(encoding="utf-8"))


def test_existing_report_files_are_never_overwritten(tmp_path):
    result = make_result([make_finding()])
    stem = report_stem(result)
    sentinel = tmp_path / f"{stem}.json"
    sentinel.write_text("PRECIOUS", encoding="utf-8")
    paths = write_reports(result, tmp_path)
    assert sentinel.read_text(encoding="utf-8") == "PRECIOUS"
    assert paths["json"].name == f"{stem}_1.json"


def test_output_path_that_is_a_file_is_rejected(tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("x")
    with pytest.raises(ReportError):
        write_reports(make_result(), target)
    with pytest.raises(ReportError):
        write_reports(make_result(), target / "sub")


def test_reports_handle_unicode(tmp_path):
    result = make_result(
        [make_finding(evidence="Server: caf\u00e9 \u2603")], target="https://xn--bcher-kva.example/"
    )
    paths = write_reports(result, tmp_path)
    assert "caf\u00e9 \u2603" in paths["html"].read_text(encoding="utf-8")
    assert "caf\u00e9 \u2603" in paths["txt"].read_text(encoding="utf-8")
