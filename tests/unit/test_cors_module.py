from kafka.models import Severity
from kafka.modules import cors
from tests.helpers import by_id, ids, make_snapshot


def _scan(**headers):
    return cors.scan(make_snapshot({k.replace("_", "-"): v for k, v in headers.items()}))


def test_no_cors_headers():
    findings = _scan()
    assert ids(findings) == {"KAFKA-CORS-001"}
    assert findings[0].severity is Severity.INFO


def test_credentials_header_without_origin():
    assert ids(_scan(Access_Control_Allow_Credentials="true")) == {"KAFKA-CORS-009"}


def test_wildcard_is_context_dependent_not_automatically_serious():
    finding = by_id(_scan(Access_Control_Allow_Origin="*"), "KAFKA-CORS-002")
    assert finding.severity is Severity.LOW
    assert "intentional" in finding.description
    assert finding.confidence.value == "LOW"


def test_wildcard_with_credentials_is_medium():
    findings = _scan(Access_Control_Allow_Origin="*", Access_Control_Allow_Credentials="true")
    assert by_id(findings, "KAFKA-CORS-003").severity is Severity.MEDIUM
    assert "KAFKA-CORS-002" not in ids(findings)


def test_null_origin():
    assert (
        by_id(_scan(Access_Control_Allow_Origin="null"), "KAFKA-CORS-004").severity
        is Severity.MEDIUM
    )
    both = _scan(Access_Control_Allow_Origin="null", Access_Control_Allow_Credentials="true")
    assert by_id(both, "KAFKA-CORS-005").severity is Severity.HIGH


def test_specific_origin_without_vary_origin():
    findings = _scan(Access_Control_Allow_Origin="https://app.example.test")
    assert {"KAFKA-CORS-010", "KAFKA-CORS-007"} == ids(findings)


def test_specific_origin_with_vary_origin_is_fine():
    findings = _scan(
        Access_Control_Allow_Origin="https://app.example.test", Vary="Accept-Encoding, Origin"
    )
    assert ids(findings) == {"KAFKA-CORS-010"}


def test_specific_origin_with_credentials_is_informational():
    findings = _scan(
        Access_Control_Allow_Origin="https://app.example.test",
        Access_Control_Allow_Credentials="TRUE",
        Vary="Origin",
    )
    assert by_id(findings, "KAFKA-CORS-006").severity is Severity.INFO


def test_invalid_origin_values():
    for bad in (
        "https://a.test, https://b.test",
        "example.test",
        "https://a.test/path",
        "*.example.test",
    ):
        assert "KAFKA-CORS-008" in ids(_scan(Access_Control_Allow_Origin=bad)), bad


def test_no_cors_finding_is_ever_critical():
    for origin in ("*", "null", "https://a.test", "garbage"):
        for credentials in (None, "true"):
            headers = {"Access-Control-Allow-Origin": origin}
            if credentials:
                headers["Access-Control-Allow-Credentials"] = credentials
            assert all(
                f.severity is not Severity.CRITICAL for f in cors.scan(make_snapshot(headers))
            )
