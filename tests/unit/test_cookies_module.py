import json

import pytest

from kafka.models import Severity
from kafka.modules import cookies
from kafka.modules.cookies import parse_set_cookie
from tests.helpers import by_id, fixture_text, ids, make_snapshot


def _snap(*cookie_lines):
    return make_snapshot([("Set-Cookie", line) for line in cookie_lines])


def test_no_cookies_is_informational():
    findings = cookies.scan(make_snapshot({}))
    assert ids(findings) == {"KAFKA-CKE-001"}
    assert findings[0].severity is Severity.INFO


def test_well_configured_cookie_only_gets_the_summary():
    findings = cookies.scan(_snap("sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/"))
    assert ids(findings) == {"KAFKA-CKE-009"}


def test_missing_secure_httponly_samesite():
    findings = cookies.scan(_snap("theme=dark"))
    assert {"KAFKA-CKE-002", "KAFKA-CKE-003", "KAFKA-CKE-004", "KAFKA-CKE-009"} == ids(findings)
    assert by_id(findings, "KAFKA-CKE-002").severity is Severity.MEDIUM
    assert by_id(findings, "KAFKA-CKE-004").severity is Severity.LOW


def test_httponly_severity_rises_only_for_session_like_names():
    plain = by_id(cookies.scan(_snap("theme=dark; Secure; SameSite=Lax")), "KAFKA-CKE-003")
    session = by_id(cookies.scan(_snap("PHPSESSID=x; Secure; SameSite=Lax")), "KAFKA-CKE-003")
    assert plain.severity is Severity.LOW
    assert session.severity is Severity.MEDIUM


def test_attributes_are_case_insensitive():
    findings = cookies.scan(_snap("a=1; SECURE; httponly; samesite=LAX"))
    assert ids(findings) == {"KAFKA-CKE-009"}


def test_samesite_none_without_secure_is_medium():
    findings = cookies.scan(_snap("t=1; SameSite=None; HttpOnly"))
    assert by_id(findings, "KAFKA-CKE-005").severity is Severity.MEDIUM


def test_samesite_none_with_secure_is_accepted():
    findings = cookies.scan(_snap("t=1; SameSite=None; Secure; HttpOnly"))
    assert "KAFKA-CKE-005" not in ids(findings)


def test_invalid_samesite_value():
    assert "KAFKA-CKE-006" in ids(cookies.scan(_snap("t=1; SameSite=Bogus; Secure; HttpOnly")))
    assert "KAFKA-CKE-006" in ids(cookies.scan(_snap("t=1; SameSite; Secure; HttpOnly")))


def test_host_prefix_requirements():
    good = cookies.scan(_snap("__Host-id=1; Secure; Path=/; HttpOnly; SameSite=Lax"))
    assert "KAFKA-CKE-007" not in ids(good)
    for bad in (
        "__Host-id=1; Path=/",
        "__Host-id=1; Secure; Path=/app",
        "__Host-id=1; Secure; Path=/; Domain=example.test",
    ):
        assert "KAFKA-CKE-007" in ids(cookies.scan(_snap(bad))), bad


def test_secure_prefix_requires_secure():
    assert "KAFKA-CKE-007" in ids(cookies.scan(_snap("__Secure-x=1")))
    assert "KAFKA-CKE-007" not in ids(cookies.scan(_snap("__Secure-x=1; Secure")))


@pytest.mark.parametrize(
    "line", ["novalue", "=x; Secure", "bad name=1", "", ";;;", "na(me=1", "a b=c"]
)
def test_malformed_cookies_are_reported_without_crashing(line):
    findings = cookies.scan(_snap(line))
    assert "KAFKA-CKE-008" in ids(findings)
    assert "KAFKA-CKE-009" not in ids(findings)


def test_valid_and_malformed_cookies_together():
    findings = cookies.scan(_snap("ok=1; Secure; HttpOnly; SameSite=Lax", "garbage"))
    assert {"KAFKA-CKE-009", "KAFKA-CKE-008"} == ids(findings)


def test_cookie_values_never_appear_in_findings():
    canary = "SUPER-SECRET-TOKEN-VALUE"
    findings = cookies.scan(_snap(f"sessionid={canary}; Path=/", f"x={canary * 50}; Secure"))
    assert canary not in json.dumps([f.to_dict() for f in findings])


def test_fixture_file_values_never_leak():
    lines = [
        line
        for line in fixture_text("set_cookie_samples.txt").splitlines()
        if line and not line.startswith("#")
    ]
    findings = cookies.scan(_snap(*lines))
    blob = json.dumps([f.to_dict() for f in findings])
    assert "CANARY" not in blob
    assert {"KAFKA-CKE-002", "KAFKA-CKE-007", "KAFKA-CKE-008", "KAFKA-CKE-006"} <= ids(findings)


def test_many_cookies_are_summarised_not_dumped():
    findings = cookies.scan(_snap(*[f"c{i}=v" for i in range(25)]))
    evidence = by_id(findings, "KAFKA-CKE-002").evidence
    assert "(+15 more)" in evidence
    assert "c24" not in evidence


def test_parse_set_cookie_discards_the_value():
    parsed = parse_set_cookie("name=value; Secure; HttpOnly; SameSite=Lax; Domain=a.test; Path=/p")
    assert parsed is not None
    assert not hasattr(parsed, "value")
    assert "value" not in repr(parsed)
    assert (parsed.name, parsed.secure, parsed.http_only, parsed.same_site) == (
        "name",
        True,
        True,
        "lax",
    )
    assert (parsed.domain, parsed.path) == ("a.test", "/p")


def test_cookie_names_are_sanitised_and_capped():
    parsed = parse_set_cookie("n" * 200 + "=v")
    assert parsed is not None and len(parsed.name) <= 64
