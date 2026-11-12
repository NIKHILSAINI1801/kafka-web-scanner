"""End-to-end behaviour against a local test server (no external network is ever used)."""

import ipaddress
import json
import time
from functools import partial

from typer.testing import CliRunner

from kafka.config import HttpLimits, ScanConfig
from kafka.database import Database
from kafka.http_client import USER_AGENT, FetchError, fetch
from kafka.main import app
from kafka.scanner import run_scan
from kafka.scope import resolve_and_check, validate_url
from tests.helpers import ids

LAB = ScanConfig(allow_private=True)
SLOW_CONNECT = HttpLimits(connect_timeout=10.0, read_timeout=2.0, total_timeout=15.0)
runner = CliRunner()


def _scan(server, path="/", limits=None, **kwargs):
    config = ScanConfig(allow_private=True, limits=limits) if limits else LAB
    return run_scan(validate_url(server.url(path)), config, **kwargs)


# ---- request discipline ---------------------------------------------------------------------


def test_exactly_one_get_request_is_sent(server, limits):
    server.route("/", headers=[("Content-Type", "text/html")])
    result = _scan(server, limits=limits)
    assert result.status == "completed" and result.status_code == 200
    assert server.methods == ["GET"]
    assert len(server.requests) == 1


def test_no_other_http_methods_and_no_extra_paths_are_requested(server, limits):
    server.route("/", body=b"<a href='/admin'>admin</a><form action='/login' method='post'></form>")
    _scan(server, limits=limits)
    assert [(r.method, r.path) for r in server.requests] == [("GET", "/")]


def test_request_headers_are_minimal_and_identify_the_tool(server, limits):
    _scan(server, limits=limits)
    headers = server.requests[0].headers
    assert headers["user-agent"] == USER_AGENT and headers["user-agent"].startswith("KAFKA/")
    assert headers["accept-encoding"] == "identity"
    for forbidden in ("cookie", "authorization", "origin", "referer", "proxy-authorization"):
        assert forbidden not in headers
    assert headers["host"] == f"127.0.0.1:{server.port}"


def test_query_string_is_sent_to_the_server_but_not_reported(server, limits):
    result = _scan(server, "/search?q=hello&token=TOPSECRET", limits=limits)
    assert server.requests[0].path == "/search?q=hello&token=TOPSECRET"
    assert "TOPSECRET" not in result.target and "TOPSECRET" not in json.dumps(result.http)


def test_redirects_are_observed_but_never_followed(server, limits):
    server.route("/old", status=302, headers=[("Location", "/new?secret=abc")], body=b"")
    server.route("/new", body=b"followed!")
    result = _scan(server, "/old", limits=limits)
    assert result.status == "completed" and result.status_code == 302
    assert [r.path for r in server.requests] == ["/old"]
    assert "KAFKA-TLS-004" in ids(result.findings)
    assert "abc" not in " ".join(f.evidence for f in result.findings)


def test_redirect_to_other_host_is_not_contacted(server, limits):
    server.route("/", status=301, headers=[("Location", "http://192.0.2.1:9/never")], body=b"")
    result = _scan(server, limits=limits)
    assert result.status_code == 301 and len(server.requests) == 1


# ---- bounds -----------------------------------------------------------------------------------


def test_read_timeout_is_enforced(server):
    server.route("/", delay=1.5)
    limits = HttpLimits(connect_timeout=2, read_timeout=0.3, total_timeout=5)
    result = _scan(server, limits=limits)
    assert result.status == "failed" and result.errors[0].code == "timeout"
    assert result.findings == []


def test_overall_deadline_stops_slow_drip_responses(server):
    server.route("/", body=b"x" * 200, drip_interval=0.1, headers=[("Content-Type", "text/html")])
    limits = HttpLimits(
        connect_timeout=2, read_timeout=2, total_timeout=0.6, max_response_bytes=10_000
    )
    started = time.monotonic()
    result = _scan(server, limits=limits)
    elapsed = time.monotonic() - started
    assert result.status == "failed" and result.errors[0].code == "timeout"
    # The deadline is checked after every read, so a one-byte-at-a-time server cannot stall us
    # for long (it used to take ~20s when whole 16 KiB reads were blocked on).
    assert elapsed < 3.0, elapsed


def test_response_size_cap_is_strict(server):
    server.route("/", body=b"A" * 300_000, headers=[("Content-Type", "text/html")])
    target = validate_url(server.url())
    snapshot = fetch(
        target, resolve_and_check(target, allow_private=True), HttpLimits(max_response_bytes=10_000)
    )
    assert len(snapshot.body) == 10_000 and snapshot.body_truncated is True


def test_body_exactly_at_the_cap_is_not_flagged_truncated(server):
    server.route("/", body=b"B" * 5000)
    target = validate_url(server.url())
    snapshot = fetch(
        target, resolve_and_check(target, allow_private=True), HttpLimits(max_response_bytes=5000)
    )
    assert len(snapshot.body) == 5000 and snapshot.body_truncated is False


def test_truncated_scan_warns_and_still_completes(server):
    server.route("/", body=b"C" * 50_000, headers=[("Content-Type", "text/html")])
    result = _scan(
        server, limits=HttpLimits(max_response_bytes=1000, read_timeout=2, total_timeout=5)
    )
    assert result.status == "completed" and result.http["body_truncated"] is True
    assert result.http["response_bytes_read"] == 1000
    assert any("truncated" in w for w in result.warnings)


def test_chunked_responses_are_read_and_capped(server):
    html = b"<html><head><meta name='generator' content='Chunk 1.0'></head></html>"
    server.route("/", body=html, chunked=True, headers=[("Content-Type", "text/html")])
    target = validate_url(server.url())
    address = resolve_and_check(target, allow_private=True)
    assert fetch(target, address, HttpLimits()).body == html
    server.route("/", body=b"Z" * 400_000, chunked=True, headers=[("Content-Type", "text/html")])
    capped = fetch(target, address, HttpLimits(max_response_bytes=50_000))
    assert len(capped.body) == 50_000 and capped.body_truncated is True


def test_lying_content_length_cannot_exceed_the_cap(server):
    server.route(
        "/", body=b"D" * 20_000, declared_length=20_000, headers=[("Content-Type", "text/html")]
    )
    target = validate_url(server.url())
    snapshot = fetch(
        target, resolve_and_check(target, allow_private=True), HttpLimits(max_response_bytes=2048)
    )
    assert len(snapshot.body) <= 2048


def test_connection_refused_is_a_clean_failure(free_port, limits):
    result = run_scan(
        validate_url(f"http://127.0.0.1:{free_port}/"),
        ScanConfig(allow_private=True, limits=limits),
    )
    assert result.status == "failed" and result.errors[0].code == "connection_failed"
    assert "Traceback" not in result.errors[0].message


def test_compressed_responses_are_not_decoded(server, limits):
    server.route(
        "/",
        headers=[("Content-Encoding", "gzip"), ("Content-Type", "text/html")],
        body=b"\x1f\x8b not really gzip",
    )
    result = _scan(server, limits=limits)
    assert result.status == "completed"
    assert any("compressed" in w for w in result.warnings)


# ---- safeguards that stay on ---------------------------------------------------------------------


def test_loopback_is_blocked_by_default_and_no_request_is_made(server):
    result = run_scan(validate_url(server.url()))
    assert result.status == "blocked" and result.errors[0].code == "blocked_target"
    assert server.requests == []


def test_hostname_resolving_to_loopback_is_blocked_by_default(server):
    result = run_scan(validate_url(server.url(host="localhost")))
    assert result.status == "blocked" and server.requests == []


def test_lab_mode_works_with_a_hostname(server, limits):
    result = run_scan(
        validate_url(server.url(host="localhost")), ScanConfig(allow_private=True, limits=limits)
    )
    assert result.status == "completed"
    assert server.requests[0].headers["host"] == f"localhost:{server.port}"


# ---- findings built from real responses --------------------------------------------------------------


def test_real_headers_cookies_and_metadata_flow_into_findings(server, limits):
    server.route(
        "/",
        headers=[
            ("Content-Type", "text/html; charset=utf-8"),
            ("Server", "demo/2.4.1"),
            ("Set-Cookie", "sessionid=CANARY-ONE; Path=/"),
            ("Set-Cookie", "theme=CANARY-TWO; Secure; HttpOnly; SameSite=Lax"),
            ("Access-Control-Allow-Origin", "*"),
        ],
        body=b"<html><head><meta name='generator' content='DemoCMS 3.0'></head></html>",
    )
    result = _scan(server, limits=limits)
    found = ids(result.findings)
    assert {
        "KAFKA-TLS-001",
        "KAFKA-HDR-001",
        "KAFKA-CKE-002",
        "KAFKA-CORS-002",
        "KAFKA-TECH-001",
        "KAFKA-TECH-004",
    } <= found
    cookie_summary = next(f for f in result.findings if f.id == "KAFKA-CKE-009")
    assert "sessionid" in cookie_summary.evidence and "theme" in cookie_summary.evidence
    assert "CANARY" not in json.dumps([f.to_dict() for f in result.findings])


# ---- TLS --------------------------------------------------------------------------------------------


def test_self_signed_certificate_is_rejected(tls_server, limits):
    result = run_scan(
        validate_url(tls_server.url(host="localhost")),
        ScanConfig(allow_private=True, limits=limits),
    )
    assert result.status == "failed" and result.errors[0].code == "tls_verification_failed"
    assert "never disables" in result.errors[0].message
    assert result.findings == []


def test_trusted_certificate_is_accepted_and_sni_matches_the_hostname(tls_server, limits):
    fetcher = partial(fetch, ca_bundle=tls_server.cert_path)
    result = run_scan(
        validate_url(tls_server.url(host="localhost")),
        ScanConfig(allow_private=True, limits=limits),
        fetcher=fetcher,
    )
    assert result.status == "completed", result.errors
    assert "KAFKA-TLS-003" in ids(result.findings)
    assert result.http["tls_verified"] is True and str(result.http["tls_protocol"]).startswith(
        "TLS"
    )
    assert tls_server.requests[0].headers["host"] == f"localhost:{tls_server.port}"


def test_certificate_for_another_name_is_rejected_even_if_the_ca_is_trusted(
    wrong_name_tls_server, limits
):
    fetcher = partial(fetch, ca_bundle=wrong_name_tls_server.cert_path)
    result = run_scan(
        validate_url(wrong_name_tls_server.url(host="localhost")),
        ScanConfig(allow_private=True, limits=limits),
        fetcher=fetcher,
    )
    assert result.status == "failed" and result.errors[0].code == "tls_verification_failed"
    assert "mismatch" in result.errors[0].message.lower()


def test_tls_to_an_ip_literal_verifies_against_the_ip_san(tls_server, limits):
    fetcher = partial(fetch, ca_bundle=tls_server.cert_path)
    result = run_scan(
        validate_url(tls_server.url()),
        ScanConfig(allow_private=True, limits=limits),
        fetcher=fetcher,
    )
    assert result.status == "completed", result.errors


def test_plain_http_to_a_tls_port_fails_cleanly(tls_server, limits):
    result = run_scan(
        validate_url(f"http://127.0.0.1:{tls_server.port}/"),
        ScanConfig(allow_private=True, limits=limits),
    )
    assert result.status == "failed" and "Traceback" not in result.errors[0].message


def test_dual_stack_host_falls_back_when_the_first_address_does_not_connect(server, limits):
    """Windows resolves 'localhost' to ::1 first; the test server only listens on IPv4."""
    target = validate_url(server.url(host="localhost"))
    addresses = [ipaddress.ip_address("::1"), ipaddress.ip_address("127.0.0.1")]
    snapshot = fetch(target, addresses, limits)
    assert snapshot.status_code == 200 and snapshot.resolved_ip == "127.0.0.1"
    assert server.methods == ["GET"]  # still exactly one request


def test_connection_fallback_is_used_by_the_default_scan_path(server, limits):
    def resolver(target, allow_private=False):
        return [ipaddress.ip_address("::1"), ipaddress.ip_address("127.0.0.1")]

    result = run_scan(
        validate_url(server.url(host="localhost")),
        ScanConfig(allow_private=True, limits=limits),
        resolver=resolver,
    )
    assert result.status == "completed" and result.http["resolved_ip"] == "127.0.0.1"
    assert len(server.requests) == 1


def test_read_timeout_does_not_trigger_a_second_attempt(server):
    server.route("/", delay=1.5)
    target = validate_url(server.url())
    addresses = [ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")]
    limits = HttpLimits(connect_timeout=4, read_timeout=0.3, total_timeout=5)
    try:
        fetch(target, addresses, limits)
    except FetchError as exc:
        # A fallback to ::1 would have turned this into connection_failed.
        assert exc.code == "timeout"
    else:
        raise AssertionError("expected a timeout")
    assert len(server.requests) == 1


def test_every_address_failing_reports_the_last_connection_error(free_port):
    target = validate_url(f"http://127.0.0.1:{free_port}/")
    addresses = [ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")]
    try:
        fetch(target, addresses, SLOW_CONNECT)
    except FetchError as exc:
        assert exc.code == "connection_failed"
    else:
        raise AssertionError("expected FetchError")


def test_fetch_error_type_is_what_the_scanner_relies_on(free_port):
    target = validate_url(f"http://127.0.0.1:{free_port}/")
    try:
        fetch(target, resolve_and_check(target, allow_private=True), SLOW_CONNECT)
    except FetchError as exc:
        assert exc.code == "connection_failed"
    else:
        raise AssertionError("expected FetchError")


# ---- full CLI flow --------------------------------------------------------------------------------------


def test_cli_scan_creates_all_three_reports_and_history(server, tmp_path):
    server.route(
        "/",
        headers=[("Content-Type", "text/html"), ("Set-Cookie", "sessionid=CANARY-CLI; Path=/")],
    )
    out = tmp_path / "reports"
    result = runner.invoke(
        app, ["scan", server.url(), "--allow-private", "--output", str(out)], input="y\n"
    )
    assert result.exit_code == 0, result.output
    assert len(server.requests) == 1 and server.methods == ["GET"]
    files = {p.suffix: p for p in out.iterdir()}
    assert set(files) == {".html", ".json", ".txt"}
    data = json.loads(files[".json"].read_text(encoding="utf-8"))
    assert data["status"] == "completed" and data["http"]["status_code"] == 200
    assert data["authorization"]["lab_mode"] is True
    for path in list(out.iterdir()) + [Database().path]:
        content = path.read_bytes()
        assert b"CANARY-CLI" not in content, path
    assert "CANARY-CLI" not in result.output
    history = runner.invoke(app, ["history"])
    assert "completed" in history.output and str(server.port) in history.output


def test_cli_declined_authorization_sends_nothing(server, tmp_path):
    result = runner.invoke(
        app, ["scan", server.url(), "--allow-private", "-o", str(tmp_path / "r")], input="n\n"
    )
    assert result.exit_code == 2 and server.requests == []
    assert not (tmp_path / "r").exists()
    assert Database().count() == 0


def test_cli_blocks_private_targets_by_default_even_when_authorized(server, tmp_path):
    result = runner.invoke(
        app, ["scan", server.url(), "--i-am-authorized", "-o", str(tmp_path / "r")]
    )
    assert result.exit_code == 2 and "allow-private" in result.output
    assert server.requests == []


def test_cli_reports_unreachable_target_with_a_report_and_exit_1(free_port, tmp_path):
    out = tmp_path / "r"
    result = runner.invoke(
        app,
        [
            "scan",
            f"http://127.0.0.1:{free_port}/",
            "--allow-private",
            "--i-am-authorized",
            "-o",
            str(out),
        ],
    )
    assert result.exit_code == 1 and "connection_failed" in result.output
    data = json.loads(next(out.glob("*.json")).read_text(encoding="utf-8"))
    assert data["status"] == "failed" and data["errors"][0]["code"] == "connection_failed"
