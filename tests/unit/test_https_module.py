from kafka.models import Severity
from kafka.modules import https
from tests.helpers import by_id, ids, make_snapshot


def test_plain_http_is_flagged_medium():
    findings = https.scan(make_snapshot(scheme="http"))
    finding = by_id(findings, "KAFKA-TLS-001")
    assert finding.severity is Severity.MEDIUM
    assert ids(findings) == {"KAFKA-TLS-001"}


def test_http_redirecting_to_https_is_low_and_not_followed():
    snap = make_snapshot({"Location": "https://example.test/home"}, scheme="http", status=301)
    findings = https.scan(snap)
    assert by_id(findings, "KAFKA-TLS-002").severity is Severity.LOW
    assert "KAFKA-TLS-001" not in ids(findings)
    assert "KAFKA-TLS-004" in ids(findings)


def test_http_with_relative_redirect_stays_on_http():
    findings = https.scan(make_snapshot({"Location": "/login"}, scheme="http", status=302))
    assert "KAFKA-TLS-001" in ids(findings)
    assert "KAFKA-TLS-002" not in ids(findings)


def test_http_redirecting_to_another_http_url_is_still_unencrypted():
    findings = https.scan(
        make_snapshot({"Location": "http://other.test/"}, scheme="http", status=302)
    )
    assert "KAFKA-TLS-001" in ids(findings)


def test_verified_https_is_informational_and_not_a_tls_audit():
    findings = https.scan(make_snapshot(scheme="https"))
    finding = by_id(findings, "KAFKA-TLS-003")
    assert finding.severity is Severity.INFO
    assert "TLSv1.3" in finding.evidence
    assert "not an audit" in finding.description
    assert ids(findings) == {"KAFKA-TLS-003"}


def test_https_to_http_redirect_is_a_downgrade():
    findings = https.scan(make_snapshot({"Location": "http://example.test/"}, status=302))
    assert by_id(findings, "KAFKA-TLS-005").severity is Severity.MEDIUM


def test_redirect_evidence_omits_query_fragment_and_credentials():
    snap = make_snapshot(
        {"Location": "https://user:hunter2@elsewhere.test/cb?token=SECRET123#frag"}, status=302
    )
    findings = https.scan(snap)
    blob = " ".join(f.evidence for f in findings)
    for leaked in ("SECRET123", "hunter2", "user:", "#frag", "token="):
        assert leaked not in blob
    assert "elsewhere.test/cb" in blob


def test_malformed_location_does_not_crash():
    findings = https.scan(make_snapshot({"Location": "http://[::1"}, status=302))
    assert "KAFKA-TLS-003" in ids(findings)
