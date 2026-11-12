import json

from typer.testing import CliRunner

import kafka.main as cli
from kafka import __version__
from kafka.database import Database, DatabaseError
from kafka.main import app
from kafka.models import ScanError
from tests.helpers import make_finding, make_result

runner = CliRunner()


def _forbid_scan(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("run_scan must not be reached")

    monkeypatch.setattr(cli, "run_scan", forbidden)


def _fake_scan(monkeypatch, result=None, calls=None):
    def fake(target, config=None, *, progress=None, authorization="interactive", **kwargs):
        if calls is not None:
            calls.append({"target": target, "config": config, "authorization": authorization})
        if progress:
            progress("Checking", 1, 1)
        produced = result or make_result(
            [make_finding("KAFKA-HDR-001", "MEDIUM")], target=target.display_url
        )
        produced.authorization = authorization  # the real run_scan records this
        return produced

    monkeypatch.setattr(cli, "run_scan", fake)


def test_no_arguments_shows_the_command_overview():
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    for needle in (
        "kafka scan URL",
        "kafka modules",
        "kafka history",
        "kafka doctor",
        "kafka version",
        "Authorized use only",
    ):
        assert needle in result.output


def test_help_works_and_lists_every_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("scan", "modules", "history", "doctor", "version"):
        assert command in result.output


def test_scan_help_documents_the_options():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    for option in ("--output", "--allow-private", "--i-am-authorized"):
        assert option in result.output


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0 and f"KAFKA {__version__}" in result.output


def test_modules_command_lists_all_five_modules():
    result = runner.invoke(app, ["modules"])
    assert result.exit_code == 0
    for needle in (
        "HTTPS / transport",
        "Security headers",
        "Cookies",
        "CORS",
        "Technology metadata",
    ):
        assert needle in result.output


def test_doctor_command_succeeds_in_a_healthy_environment():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0 and "Environment looks ready" in result.output


def test_history_command_when_empty():
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0 and "No scans recorded yet" in result.output


def test_history_command_lists_scans_and_respects_limit():
    db = Database()
    for index in range(3):
        db.add_scan(
            make_result([make_finding(severity="HIGH")], target=f"https://site{index}.test/")
        )
    full = runner.invoke(app, ["history"])
    assert all(f"site{i}.test" in full.output for i in range(3)) and "0/1/0/0/0" in full.output
    limited = runner.invoke(app, ["history", "--limit", "1"])
    assert "site2.test" in limited.output and "site0.test" not in limited.output


def test_history_rejects_out_of_range_limit():
    assert runner.invoke(app, ["history", "--limit", "0"]).exit_code != 0
    assert runner.invoke(app, ["history", "--limit", "9999"]).exit_code != 0


def test_history_reports_a_corrupt_database_cleanly(tmp_path):
    home = tmp_path / "kafka_home"
    home.mkdir()
    (home / "history.db").write_bytes(b"junk" * 200)
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 1 and "History unavailable" in result.output
    assert "Traceback" not in result.output


# ---- scan: validation and authorization ---------------------------------------------------------


def test_invalid_urls_are_rejected_before_any_prompt_or_network(monkeypatch):
    _forbid_scan(monkeypatch)
    for bad in (
        "ftp://example.com",
        "example.com",
        "http://user:pw@example.com/",
        "http://example.com:99999/",
    ):
        result = runner.invoke(app, ["scan", bad], input="y\n")
        assert result.exit_code == 2, bad
        assert "Invalid URL" in result.output and "Authorization required" not in result.output


def test_authorization_notice_is_shown_and_declining_prevents_the_scan(monkeypatch):
    _forbid_scan(monkeypatch)
    for answer in ("n\n", "\n", "no\n", "maybe\n", "yep\n", ""):
        result = runner.invoke(app, ["scan", "https://example.test/"], input=answer)
        assert result.exit_code == 2, repr(answer)
        assert (
            "Authorization required" in result.output
            and "no network request was made" in result.output
        )


def test_affirmative_answer_runs_the_scan_and_writes_reports(monkeypatch, tmp_path):
    calls = []
    _fake_scan(monkeypatch, calls=calls)
    out = tmp_path / "reports"
    result = runner.invoke(
        app, ["scan", "https://example.test/", "--output", str(out)], input="y\n"
    )
    assert result.exit_code == 0, result.output
    assert len(calls) == 1 and calls[0]["authorization"] == "interactive"
    assert calls[0]["config"].allow_private is False
    assert sorted(p.suffix for p in out.iterdir()) == [".html", ".json", ".txt"]
    assert "Reports written" in result.output and "KAFKA-HDR-001" in result.output
    assert "Severity summary" in result.output and "[!!] MEDIUM" in result.output
    assert Database().count() == 1


def test_yes_is_accepted_in_any_case(monkeypatch, tmp_path):
    _fake_scan(monkeypatch)
    assert (
        runner.invoke(
            app, ["scan", "https://example.test/", "-o", str(tmp_path)], input="YES\n"
        ).exit_code
        == 0
    )


def test_authorized_flag_skips_the_prompt_and_is_recorded(monkeypatch, tmp_path):
    calls = []
    _fake_scan(monkeypatch, calls=calls)
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["scan", "https://example.test/", "--i-am-authorized", "-o", str(out)]
    )
    assert result.exit_code == 0 and "Do you own this website" not in result.output
    assert calls[0]["authorization"] == "flag"
    data = json.loads(next(out.glob("*.json")).read_text(encoding="utf-8"))
    assert data["authorization"]["method"] == "flag"


def test_allow_private_shows_lab_warning_and_passes_config(monkeypatch, tmp_path):
    calls = []
    _fake_scan(monkeypatch, calls=calls)
    result = runner.invoke(
        app, ["scan", "http://127.0.0.1:8000/", "--allow-private", "-o", str(tmp_path)], input="y\n"
    )
    assert result.exit_code == 0 and "LAB MODE" in result.output
    assert calls[0]["config"].allow_private is True


def test_query_string_is_never_printed_or_stored(monkeypatch, tmp_path):
    _fake_scan(monkeypatch)
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["scan", "https://example.test/p?api_key=TOPSECRET", "-o", str(out)], input="y\n"
    )
    assert result.exit_code == 0 and "TOPSECRET" not in result.output
    assert all("TOPSECRET" not in f.read_text(encoding="utf-8") for f in out.iterdir())
    assert all("TOPSECRET" not in r.target for r in Database().recent())


# ---- scan: exit codes and degraded paths ---------------------------------------------------------


def test_blocked_scan_exits_2_and_is_explained(monkeypatch, tmp_path):
    _fake_scan(
        monkeypatch,
        make_result(
            [],
            status="blocked",
            status_code=None,
            http={},
            errors=[ScanError("blocked_target", "Blocked: loopback")],
        ),
    )
    result = runner.invoke(app, ["scan", "http://127.0.0.1/", "-o", str(tmp_path)], input="y\n")
    assert result.exit_code == 2 and "Blocked: loopback" in result.output


def test_failed_and_partial_scans_exit_1(monkeypatch, tmp_path):
    for status in ("failed", "partial"):
        _fake_scan(
            monkeypatch,
            make_result(
                [], status=status, status_code=None, http={}, errors=[ScanError("timeout", "slow")]
            ),
        )
        result = runner.invoke(
            app, ["scan", "https://example.test/", "-o", str(tmp_path)], input="y\n"
        )
        assert result.exit_code == 1, status
        assert next(tmp_path.glob("*.json")) is not None  # a report is still produced


def test_unwritable_output_directory_is_reported_not_crashed(monkeypatch, tmp_path):
    _fake_scan(monkeypatch)
    blocker = tmp_path / "afile"
    blocker.write_text("x")
    result = runner.invoke(app, ["scan", "https://example.test/", "-o", str(blocker)], input="y\n")
    assert result.exit_code == 1 and "Reports were not written" in result.output
    assert "Traceback" not in result.output and "KAFKA-HDR-001" in result.output


def test_history_failure_does_not_lose_the_scan_results(monkeypatch, tmp_path):
    _fake_scan(monkeypatch)

    class BrokenDatabase:
        def add_scan(self, result):
            raise DatabaseError("disk full")

    monkeypatch.setattr(cli, "Database", BrokenDatabase)
    result = runner.invoke(app, ["scan", "https://example.test/", "-o", str(tmp_path)], input="y\n")
    assert result.exit_code == 0 and "Scan history was not saved: disk full" in result.output


def test_remote_text_is_never_interpreted_as_rich_markup_or_escape_codes(monkeypatch, tmp_path):
    finding = make_finding(
        "KAFKA-TECH-001",
        "LOW",
        title="[red]boom[/red] [link=http://evil.test]click[/link]\x1b[31mred",
        evidence="x",
    )
    _fake_scan(monkeypatch, make_result([finding]))
    result = runner.invoke(app, ["scan", "https://example.test/", "-o", str(tmp_path)], input="y\n")
    assert result.exit_code == 0
    assert (
        "[red]boom[/red]" in result.output
        and "[link=http://evil.test]click[/link]" in result.output
    )
    assert "\x1b" not in result.output


# ---- unexpected failures ---------------------------------------------------------------------------


def test_unexpected_internal_errors_print_only_the_exception_type(monkeypatch, tmp_path):
    _fake_scan(monkeypatch)

    def explode(result, directory):
        raise RuntimeError("SECRET-DETAIL token=abc123")

    monkeypatch.setattr(cli, "write_reports", explode)
    result = runner.invoke(app, ["scan", "https://example.test/", "-o", str(tmp_path)], input="y\n")
    assert result.exit_code == 1
    assert "Unexpected error" in result.output and "RuntimeError" in result.output
    assert "SECRET-DETAIL" not in result.output and "Traceback" not in result.output


def test_debug_mode_lets_the_traceback_through(monkeypatch, tmp_path):
    _fake_scan(monkeypatch)
    monkeypatch.setenv("KAFKA_DEBUG", "1")

    def explode(result, directory):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "write_reports", explode)
    result = runner.invoke(app, ["scan", "https://example.test/", "-o", str(tmp_path)], input="y\n")
    assert isinstance(result.exception, RuntimeError)


def test_keyboard_interrupt_during_scan_is_handled(monkeypatch, tmp_path):
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_scan", interrupted)
    result = runner.invoke(app, ["scan", "https://example.test/", "-o", str(tmp_path)], input="y\n")
    assert result.exit_code == 130 and "cancelled" in result.output


def test_console_survives_a_legacy_code_page(monkeypatch):
    import io
    import sys

    from rich.text import Text

    from kafka import ui

    raw = io.BytesIO()
    legacy = io.TextIOWrapper(raw, encoding="cp1252", write_through=True)
    monkeypatch.setattr(sys, "stdout", legacy)
    console = ui.make_console()
    console.print(Text("caf\u00e9 \u65e5\u672c\u8a9e"))  # the CJK part cannot be encoded in cp1252
    assert b"caf" in raw.getvalue()
