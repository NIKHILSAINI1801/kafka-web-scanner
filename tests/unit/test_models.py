import json

import pytest

from kafka.models import SEVERITY_ORDER, Confidence, Finding, ScanError, Severity
from tests.helpers import make_snapshot


def _finding(**overrides):
    data = {
        "id": "KAFKA-HDR-001",
        "scanner": "headers",
        "title": "Title",
        "severity": Severity.LOW,
        "confidence": Confidence.MEDIUM,
        "description": "Description",
        "evidence": "Evidence",
        "recommendation": "Do the thing",
    }
    data.update(overrides)
    return Finding(**data)


def test_severity_ranking_is_ordered_from_critical_to_info():
    assert [s.value for s in SEVERITY_ORDER] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    ranks = [s.rank for s in SEVERITY_ORDER]
    assert ranks == sorted(ranks, reverse=True)
    assert Severity.CRITICAL.rank > Severity.INFO.rank == 0


@pytest.mark.parametrize(
    "bad_id", ["", "HDR-001", "KAFKA-HDR-1", "kafka-hdr-001", "KAFKA-HDR-0011"]
)
def test_finding_rejects_malformed_ids(bad_id):
    with pytest.raises(ValueError):
        _finding(id=bad_id)


def test_finding_coerces_enums_from_strings():
    finding = _finding(severity="HIGH", confidence="LOW")
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.LOW


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        _finding(severity="SEVERE")


def test_finding_sanitises_all_text_fields():
    finding = _finding(
        title="T\x1b[31m\x00itle",
        description="D\u202eesc",
        evidence="line1\nli\x07ne2",
        recommendation="R\x00ec",
    )
    assert "\x1b" not in finding.title and "\x00" not in finding.title
    assert "\u202e" not in finding.description
    assert finding.evidence == "line1\nline2"
    assert "\x00" not in finding.recommendation


def test_finding_caps_evidence_length():
    assert len(_finding(evidence="x" * 100_000).evidence) <= 1500


def test_finding_round_trips_through_json():
    original = _finding(evidence="a\nb")
    restored = Finding.from_dict(json.loads(json.dumps(original.to_dict())))
    assert restored == original


def test_finding_to_dict_has_documented_keys():
    assert list(_finding().to_dict()) == [
        "id",
        "scanner",
        "title",
        "severity",
        "confidence",
        "description",
        "evidence",
        "recommendation",
    ]


def test_scan_error_is_sanitised():
    error = ScanError("code\x00", "message \x1b[0m ok")
    assert "\x00" not in error.code and "\x1b" not in error.message


def test_snapshot_header_lookup_is_case_insensitive_and_joins_repeats():
    snap = make_snapshot([("Set-Cookie", "a=1"), ("set-cookie", "b=2"), ("X-One", "v")])
    assert snap.header("SET-COOKIE") == "a=1, b=2"
    assert snap.header_values("set-cookie") == ["a=1", "b=2"]
    assert snap.header("missing") is None


def test_snapshot_content_type_helpers():
    snap = make_snapshot(content_type="Text/HTML; Charset=ISO-8859-1")
    assert snap.media_type == "text/html"
    assert snap.charset == "ISO-8859-1"
    assert snap.is_html
    assert not make_snapshot(content_type="application/json").is_html


def test_snapshot_redirect_detection_requires_location():
    assert make_snapshot({"Location": "/x"}, status=302).is_redirect
    assert not make_snapshot({}, status=302).is_redirect
    assert not make_snapshot({"Location": "/x"}, status=304).is_redirect
