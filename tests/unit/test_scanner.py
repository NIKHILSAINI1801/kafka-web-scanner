from kafka import scanner as scanner_module
from kafka.config import ScanConfig
from kafka.http_client import FetchError
from kafka.modules import MODULES, ModuleInfo
from kafka.scanner import TOTAL_STEPS, run_scan
from kafka.scope import ResolutionError, ScopeError, validate_url
from tests.helpers import ids, make_snapshot

TARGET = validate_url("https://example.test/")


def _ok_resolver(target, allow_private=False):
    return ["93.184.216.34"]


def _fetcher(snapshot):
    def fetch(target, address, limits):
        return snapshot

    return fetch


def test_successful_scan_runs_all_five_modules():
    snap = make_snapshot({"Server": "nginx/1.2.3"})
    result = run_scan(TARGET, resolver=_ok_resolver, fetcher=_fetcher(snap))
    assert result.status == "completed" and result.errors == []
    assert result.modules_run == [m.key for m in MODULES] and len(MODULES) == 5
    assert result.status_code == 200
    assert result.finished_at is not None and result.finished_at >= result.started_at
    prefixes = {f.id.split("-")[1] for f in result.findings}
    assert prefixes == {"TLS", "HDR", "CKE", "CORS", "TECH"}


def test_finding_ids_are_unique_within_a_scan():
    result = run_scan(TARGET, resolver=_ok_resolver, fetcher=_fetcher(make_snapshot({})))
    found = [f.id for f in result.findings]
    assert len(found) == len(set(found))


def test_findings_are_sorted_most_severe_first():
    result = run_scan(TARGET, resolver=_ok_resolver, fetcher=_fetcher(make_snapshot({})))
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_http_summary_contains_no_headers_or_body():
    snap = make_snapshot({"Set-Cookie": "a=SECRETVALUE"}, body=b"<html>BODYTEXT</html>")
    result = run_scan(TARGET, resolver=_ok_resolver, fetcher=_fetcher(snap))
    blob = repr(result.http) + repr(result.target)
    assert "SECRETVALUE" not in blob and "BODYTEXT" not in blob
    assert result.http["response_bytes_read"] == len(b"<html>BODYTEXT</html>")


def test_progress_callback_reports_every_step_in_order():
    seen = []
    run_scan(
        TARGET,
        resolver=_ok_resolver,
        fetcher=_fetcher(make_snapshot({})),
        progress=lambda m, s, t: seen.append((m, s, t)),
    )
    assert [step for _, step, _ in seen] == list(range(1, TOTAL_STEPS + 1))
    assert {total for _, _, total in seen} == {TOTAL_STEPS}


def test_scope_error_yields_blocked_status_and_no_request():
    def blocked(target, allow_private=False):
        raise ScopeError("Blocked: private address")

    def must_not_fetch(*args):
        raise AssertionError("network request attempted for a blocked target")

    result = run_scan(TARGET, resolver=blocked, fetcher=must_not_fetch)
    assert result.status == "blocked" and result.errors[0].code == "blocked_target"
    assert result.findings == [] and result.status_code is None


def test_dns_failure_yields_failed_status():
    def unresolvable(target, allow_private=False):
        raise ResolutionError("Could not resolve host name 'x'.")

    result = run_scan(TARGET, resolver=unresolvable, fetcher=_fetcher(make_snapshot({})))
    assert result.status == "failed" and result.errors[0].code == "dns_failure"


def test_fetch_error_codes_are_preserved():
    def failing(target, address, limits):
        raise FetchError("timeout", "The request timed out.")

    result = run_scan(TARGET, resolver=_ok_resolver, fetcher=failing)
    assert result.status == "failed" and result.errors[0].code == "timeout"
    assert result.finished_at is not None


def test_allow_private_flag_is_passed_to_the_resolver_and_recorded():
    seen = {}

    def resolver(target, allow_private=False):
        seen["allow_private"] = allow_private
        return ["127.0.0.1"]

    result = run_scan(
        TARGET,
        ScanConfig(allow_private=True),
        resolver=resolver,
        fetcher=_fetcher(make_snapshot({})),
    )
    assert seen["allow_private"] is True and result.lab_mode is True


def test_a_crashing_module_makes_the_scan_partial_but_keeps_other_results(monkeypatch):
    def boom(snapshot):
        raise RuntimeError("internal detail that must not leak: /home/secret/path")

    broken = ModuleInfo("broken", "Broken", "x", (), "KAFKA-TLS", boom)
    monkeypatch.setattr(scanner_module, "MODULES", (broken, *MODULES))
    result = run_scan(TARGET, resolver=_ok_resolver, fetcher=_fetcher(make_snapshot({})))
    assert result.status == "partial"
    assert result.errors[0].code == "module_failed" and "broken" in result.errors[0].message
    assert "RuntimeError" in result.errors[0].message
    assert "secret" not in result.errors[0].message  # no verbose exception text
    assert "broken" not in result.modules_run and "https" in result.modules_run
    assert "KAFKA-HDR-001" in ids(result.findings)


def test_truncation_and_compression_produce_warnings():
    snap = make_snapshot({"Content-Encoding": "gzip"}, body_truncated=True)
    result = run_scan(TARGET, ScanConfig(), resolver=_ok_resolver, fetcher=_fetcher(snap))
    text = " ".join(result.warnings)
    assert "truncated" in text and "compressed" in text


def test_no_passive_check_produces_critical_findings():
    worst = make_snapshot(
        {
            "Server": "Apache/1.3.0",
            "X-Powered-By": "PHP/4.0",
            "Set-Cookie": "sessionid=1",
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        },
        scheme="http",
    )
    result = run_scan(
        validate_url("http://example.test/"), resolver=_ok_resolver, fetcher=_fetcher(worst)
    )
    assert result.findings and all(f.severity.value != "CRITICAL" for f in result.findings)


def test_real_resolver_is_used_by_default_and_blocks_loopback():
    result = run_scan(validate_url("http://127.0.0.1:9/"))
    assert result.status == "blocked"
