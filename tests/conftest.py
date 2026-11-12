"""Global fixtures: every test gets an isolated KAFKA_HOME and a wide, colourless console."""

import pytest


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("KAFKA_HOME", str(tmp_path / "kafka_home"))
    monkeypatch.setenv("COLUMNS", "220")
    monkeypatch.setenv("NO_COLOR", "1")
    return tmp_path
