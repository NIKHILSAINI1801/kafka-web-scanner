import importlib

from kafka import doctor
from kafka.doctor import FAIL, PASS, run_checks


def test_doctor_passes_in_a_healthy_environment():
    checks = run_checks()
    assert checks and all(check.status in {PASS, "WARN"} for check in checks)
    names = {check.name for check in checks}
    assert {
        "Python",
        "SQLite",
        "History directory",
        "History database",
        "CA certificate bundle",
    } <= names
    assert any(name.startswith("Dependency: typer") for name in names)


def test_doctor_reports_a_missing_dependency(monkeypatch):
    real = importlib.import_module

    def fake(name, *args, **kwargs):
        if name == "bs4":
            raise ImportError("simulated")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(doctor.importlib, "import_module", fake)
    checks = {c.name: c for c in run_checks()}
    assert checks["Dependency: beautifulsoup4"].status == FAIL


def test_doctor_never_creates_the_history_database(tmp_path):
    run_checks()
    assert not (tmp_path / "kafka_home" / "history.db").exists()


def test_doctor_notices_a_corrupt_history_database(tmp_path):
    home = tmp_path / "kafka_home"
    home.mkdir()
    (home / "history.db").write_bytes(b"garbage" * 100)
    checks = {c.name: c for c in run_checks()}
    assert checks["History database"].status == FAIL
