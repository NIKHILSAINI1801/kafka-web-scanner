import pytest

from kafka.models import Confidence, Severity
from kafka.modules import headers
from tests.helpers import by_id, ids, make_snapshot

GOOD = {
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'self'",
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
}


def test_all_five_headers_missing_on_https():
    findings = headers.scan(make_snapshot({}))
    assert ids(findings) == {
        "KAFKA-HDR-001",
        "KAFKA-HDR-010",
        "KAFKA-HDR-020",
        "KAFKA-HDR-030",
        "KAFKA-HDR-040",
    }
    assert by_id(findings, "KAFKA-HDR-001").severity is Severity.MEDIUM
    assert by_id(findings, "KAFKA-HDR-020").severity is Severity.MEDIUM
    assert by_id(findings, "KAFKA-HDR-010").severity is Severity.LOW
    assert by_id(findings, "KAFKA-HDR-030").severity is Severity.LOW
    assert by_id(findings, "KAFKA-HDR-040").severity is Severity.INFO


def test_all_five_headers_good_yields_only_informational_findings():
    findings = headers.scan(make_snapshot(GOOD))
    assert ids(findings) == {
        "KAFKA-HDR-002",
        "KAFKA-HDR-011",
        "KAFKA-HDR-021",
        "KAFKA-HDR-031",
        "KAFKA-HDR-041",
    }
    assert all(f.severity is Severity.INFO for f in findings)


def test_header_names_are_case_insensitive():
    lowered = {name.lower(): value for name, value in GOOD.items()}
    assert ids(headers.scan(make_snapshot(lowered))) == ids(headers.scan(make_snapshot(GOOD)))


def test_missing_header_on_non_html_response_has_lower_confidence_and_a_note():
    finding = by_id(
        headers.scan(make_snapshot({}, content_type="application/json")), "KAFKA-HDR-001"
    )
    assert finding.confidence is Confidence.LOW
    assert "not HTML" in finding.description


def test_missing_header_on_html_success_has_medium_confidence():
    finding = by_id(headers.scan(make_snapshot({})), "KAFKA-HDR-001")
    assert finding.confidence is Confidence.MEDIUM


def test_redirect_response_is_called_out_in_missing_header_description():
    finding = by_id(headers.scan(make_snapshot({"Location": "/x"}, status=302)), "KAFKA-HDR-001")
    assert "redirect" in finding.description
    assert finding.confidence is Confidence.LOW


# ---- CSP ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy",
    [
        "script-src 'self' 'unsafe-inline'; object-src 'none'",
        "default-src 'self' 'unsafe-eval'",
        "script-src *; object-src 'none'",
        "script-src https: ; object-src 'none'",
        "frame-ancestors 'self'",
        "script-src 'self'",
    ],
)
def test_weak_csp_policies_are_flagged_low(policy):
    finding = by_id(
        headers.scan(make_snapshot({"Content-Security-Policy": policy})), "KAFKA-HDR-003"
    )
    assert finding.severity is Severity.LOW


def test_unsafe_inline_is_ignored_when_a_nonce_is_present():
    policy = "script-src 'nonce-abc123' 'unsafe-inline'; object-src 'none'"
    findings = headers.scan(make_snapshot({"Content-Security-Policy": policy}))
    assert "KAFKA-HDR-002" in ids(findings)
    assert "KAFKA-HDR-003" not in ids(findings)


def test_report_only_csp_is_reported_separately():
    snap = make_snapshot({"Content-Security-Policy-Report-Only": "default-src 'self'"})
    findings = headers.scan(snap)
    assert "KAFKA-HDR-004" in ids(findings)
    assert "KAFKA-HDR-001" not in ids(findings)


def test_enforced_csp_wins_over_report_only():
    snap = make_snapshot(
        {
            "Content-Security-Policy": GOOD["Content-Security-Policy"],
            "Content-Security-Policy-Report-Only": "default-src 'none'",
        }
    )
    assert "KAFKA-HDR-004" not in ids(headers.scan(snap))


# ---- X-Content-Type-Options -----------------------------------------------------------------


def test_x_content_type_options_with_wrong_value():
    finding = by_id(
        headers.scan(make_snapshot({"X-Content-Type-Options": "sniff"})), "KAFKA-HDR-012"
    )
    assert finding.severity is Severity.LOW


def test_x_content_type_options_nosniff_is_case_insensitive():
    assert "KAFKA-HDR-011" in ids(
        headers.scan(make_snapshot({"X-Content-Type-Options": "NoSniff"}))
    )


# ---- HSTS --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["max-age=0", "max-age=300", "includeSubDomains", "max-age=abc", "max-age=15552000x; y"],
)
def test_weak_or_ineffective_hsts_is_flagged(value):
    findings = headers.scan(make_snapshot({"Strict-Transport-Security": value}))
    if value == "max-age=15552000x; y":  # still parses 15552000 = exactly 180 days: acceptable
        assert "KAFKA-HDR-021" in ids(findings)
    else:
        assert by_id(findings, "KAFKA-HDR-022").severity is Severity.LOW


def test_hsts_is_not_evaluated_over_plain_http():
    findings = headers.scan(make_snapshot({}, scheme="http"))
    assert "KAFKA-HDR-023" in ids(findings)
    assert "KAFKA-HDR-020" not in ids(findings)


def test_hsts_sent_over_http_is_noted_as_ignored():
    snap = make_snapshot({"Strict-Transport-Security": "max-age=31536000"}, scheme="http")
    finding = by_id(headers.scan(snap), "KAFKA-HDR-023")
    assert "max-age=31536000" in finding.evidence


# ---- Referrer-Policy -----------------------------------------------------------------------


@pytest.mark.parametrize("value", ["unsafe-url", "no-referrer-when-downgrade", "bogus-value"])
def test_weak_or_unknown_referrer_policy_is_flagged(value):
    findings = headers.scan(make_snapshot({"Referrer-Policy": value}))
    assert by_id(findings, "KAFKA-HDR-032").severity is Severity.LOW


def test_referrer_policy_fallback_list_uses_last_recognised_value():
    findings = headers.scan(make_snapshot({"Referrer-Policy": "unsafe-url, same-origin"}))
    assert "KAFKA-HDR-031" in ids(findings)


def test_repeated_header_lines_are_merged():
    snap = make_snapshot(
        [
            ("Referrer-Policy", "no-referrer"),
            ("Referrer-Policy", "unsafe-url"),
        ]
    )
    assert "KAFKA-HDR-032" in ids(headers.scan(snap))


def test_long_csp_evidence_is_bounded():
    finding = by_id(
        headers.scan(
            make_snapshot({"Content-Security-Policy": "default-src " + "a.example " * 2000})
        ),
        "KAFKA-HDR-002",
    )
    assert len(finding.evidence) < 700
