from kafka.models import Severity
from kafka.risk import GLYPHS, NO_FINDINGS_TEXT, sort_findings, summarize, top_recommendations
from tests.helpers import make_finding


def test_counts_cover_every_severity_even_when_zero():
    summary = summarize([make_finding("KAFKA-HDR-001", "HIGH")])
    assert summary.counts == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    assert summary.total == 1 and summary.highest == "HIGH"


def test_empty_findings():
    summary = summarize([])
    assert summary.total == 0 and summary.highest is None
    assert summary.triage == NO_FINDINGS_TEXT


def test_triage_follows_the_worst_finding():
    assert summarize([make_finding(severity="INFO")]).triage.startswith("Informational")
    assert summarize([make_finding(severity="LOW")]).triage.startswith("Low")
    assert summarize(
        [make_finding(severity="MEDIUM"), make_finding("KAFKA-HDR-002", "LOW")]
    ).triage.startswith("Moderate")
    assert summarize([make_finding(severity="HIGH")]).triage.startswith("Elevated")
    assert summarize([make_finding(severity="CRITICAL")]).triage.startswith("Elevated")


def test_informational_triage_does_not_claim_the_site_is_secure():
    text = summarize([make_finding(severity="INFO")]).triage.lower()
    assert "secure" not in text and "safe" not in text


def test_sort_orders_by_severity_then_confidence_then_id():
    items = [
        make_finding("KAFKA-HDR-003", "LOW", "HIGH"),
        make_finding("KAFKA-HDR-002", "HIGH", "LOW"),
        make_finding("KAFKA-HDR-001", "LOW", "HIGH"),
        make_finding("KAFKA-HDR-004", "LOW", "LOW"),
        make_finding("KAFKA-HDR-005", "CRITICAL", "LOW"),
    ]
    assert [f.id for f in sort_findings(items)] == [
        "KAFKA-HDR-005",
        "KAFKA-HDR-002",
        "KAFKA-HDR-001",
        "KAFKA-HDR-003",
        "KAFKA-HDR-004",
    ]


def test_top_recommendations_skip_info_and_respect_limit():
    items = [make_finding(f"KAFKA-HDR-00{i}", "MEDIUM") for i in range(1, 8)]
    items.append(make_finding("KAFKA-HDR-099", "INFO"))
    recs = top_recommendations(items, limit=3)
    assert len(recs) == 3 and all(fid != "KAFKA-HDR-099" for fid, _ in recs)
    assert top_recommendations([make_finding(severity="INFO")]) == []


def test_every_severity_has_a_text_marker_so_colour_is_never_the_only_signal():
    assert set(GLYPHS) == set(Severity)
    assert len(set(GLYPHS.values())) == len(Severity)
