import json

from kafka.models import Severity
from kafka.modules import technology
from tests.helpers import by_id, fixture_text, ids, make_snapshot


def test_server_with_version_is_low():
    finding = by_id(
        technology.scan(make_snapshot({"Server": "nginx/1.18.0 (Ubuntu)"})), "KAFKA-TECH-001"
    )
    assert finding.severity is Severity.LOW
    assert "nginx/1.18.0" in finding.evidence
    assert "spoofed" in finding.description


def test_server_without_version_is_informational():
    findings = technology.scan(make_snapshot({"Server": "cloudflare"}))
    assert by_id(findings, "KAFKA-TECH-002").severity is Severity.INFO


def test_x_powered_by():
    assert (
        by_id(
            technology.scan(make_snapshot({"X-Powered-By": "PHP/8.1.2"})), "KAFKA-TECH-003"
        ).severity
        is Severity.LOW
    )
    assert (
        by_id(
            technology.scan(make_snapshot({"X-Powered-By": "Express"})), "KAFKA-TECH-003"
        ).severity
        is Severity.INFO
    )


def test_generator_meta_tag_from_html_fixture():
    snap = make_snapshot({}, body=fixture_text("page_with_generator.html"))
    finding = by_id(technology.scan(snap), "KAFKA-TECH-004")
    assert "ExampleCMS 4.2.1" in finding.evidence
    assert finding.severity is Severity.LOW


def test_page_without_generator_yields_no_metadata_finding():
    snap = make_snapshot({}, body=fixture_text("page_plain.html"))
    assert ids(technology.scan(snap)) == {"KAFKA-TECH-005"}


def test_malformed_html_does_not_crash():
    snap = make_snapshot({}, body=fixture_text("page_malformed.html"))
    technology.scan(snap)  # must simply not raise


def test_body_is_ignored_for_non_html_and_compressed_responses():
    html = fixture_text("page_with_generator.html")
    assert "KAFKA-TECH-004" not in ids(
        technology.scan(make_snapshot({}, body=html, content_type="application/json"))
    )
    compressed = make_snapshot({"Content-Encoding": "gzip"}, body=html)
    assert "KAFKA-TECH-004" not in ids(technology.scan(compressed))


def test_declared_charset_is_honoured_and_bad_charset_tolerated():
    latin1 = "<meta name='generator' content='Caf\u00e9CMS 1.0'>".encode("latin-1")
    snap = make_snapshot({}, body=latin1, content_type="text/html; charset=iso-8859-1")
    assert "CaféCMS" in by_id(technology.scan(snap), "KAFKA-TECH-004").evidence
    odd = make_snapshot(
        {},
        body=b"<meta name='generator' content='X 1.0'>",
        content_type="text/html; charset=nonsense",
    )
    assert "KAFKA-TECH-004" in ids(technology.scan(odd))


def test_hostile_values_are_sanitised():
    snap = make_snapshot(
        {"Server": "evil/1.0 \x1b[31m\x00[bold]"},
        body="<meta name='generator' content='G\x07en 2.0 <script>x</script>'>",
    )
    blob = json.dumps([f.to_dict() for f in technology.scan(snap)])
    assert "\\u001b" not in blob and "\\u0000" not in blob and "\\u0007" not in blob


def test_nothing_observed():
    assert ids(technology.scan(make_snapshot({}))) == {"KAFKA-TECH-005"}


def test_generator_search_is_case_insensitive():
    snap = make_snapshot({}, body="<META NAME='GENERATOR' CONTENT='Site 9.9'>")
    assert "KAFKA-TECH-004" in ids(technology.scan(snap))
