"""Environment self-check for ``kafka doctor``. Never touches the network."""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import platform
import sqlite3
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path

from kafka import __version__
from kafka.config import data_dir, database_path

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

_DEPENDENCIES = (
    ("typer", "typer"),
    ("rich", "rich"),
    ("requests", "requests"),
    ("urllib3", "urllib3"),
    ("bs4", "beautifulsoup4"),
    ("jinja2", "Jinja2"),
)


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    detail: str


def _version_of(module_name: str, dist_name: str) -> str:
    try:
        return importlib.metadata.version(dist_name)
    except importlib.metadata.PackageNotFoundError:
        module = sys.modules.get(module_name)
        return str(getattr(module, "__version__", "version unknown"))


def _nearest_existing(path: Path) -> Path:
    current = path
    while not current.exists() and current != current.parent:
        current = current.parent
    return current


def _check_dependencies() -> list[DoctorCheck]:
    checks = []
    for module_name, dist_name in _DEPENDENCIES:
        try:
            importlib.import_module(module_name)
        except ImportError:
            checks.append(DoctorCheck(f"Dependency: {dist_name}", FAIL, "not installed"))
        else:
            checks.append(
                DoctorCheck(f"Dependency: {dist_name}", PASS, _version_of(module_name, dist_name))
            )
    return checks


def _check_history() -> DoctorCheck:
    path = database_path()
    if not path.exists():
        return DoctorCheck("History database", PASS, "none yet; created on the first scan")
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=2.0)
        try:
            result = conn.execute("PRAGMA quick_check").fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return DoctorCheck("History database", FAIL, "exists but cannot be read as SQLite")
    if result and result[0] == "ok":
        return DoctorCheck("History database", PASS, "readable; integrity check passed")
    return DoctorCheck("History database", FAIL, "integrity check failed")


def run_checks() -> list[DoctorCheck]:
    """Run every environment check and return the results."""
    checks = [
        DoctorCheck("KAFKA", PASS, f"version {__version__}"),
        DoctorCheck(
            "Python",
            PASS if sys.version_info >= (3, 11) else FAIL,
            f"{platform.python_version()} (3.11 or newer required)",
        ),
        DoctorCheck("Platform", PASS, f"{platform.system()} {platform.release()}"),
    ]
    checks += _check_dependencies()
    checks.append(DoctorCheck("SQLite", PASS, f"library {sqlite3.sqlite_version}"))

    try:
        from urllib3.util.ssl_ import create_urllib3_context

        minimum = create_urllib3_context().minimum_version
        checks.append(
            DoctorCheck(
                "TLS stack",
                PASS if minimum >= ssl.TLSVersion.TLSv1_2 else WARN,
                f"{ssl.OPENSSL_VERSION}; HTTP client minimum protocol {minimum.name}",
            )
        )
    except ImportError:
        checks.append(DoctorCheck("TLS stack", FAIL, "urllib3 is not installed"))
    try:
        import requests.certs

        bundle = Path(requests.certs.where())
        checks.append(
            DoctorCheck(
                "CA certificate bundle",
                PASS if bundle.is_file() else FAIL,
                "found" if bundle.is_file() else "bundle file is missing",
            )
        )
    except ImportError:
        checks.append(DoctorCheck("CA certificate bundle", FAIL, "requests is not installed"))

    directory = data_dir()
    anchor = _nearest_existing(directory)
    writable = os.access(anchor, os.W_OK)
    checks.append(
        DoctorCheck(
            "History directory",
            PASS if writable else FAIL,
            f"{directory} ({'writable' if writable else 'not writable'})",
        )
    )
    checks.append(_check_history())

    cwd_writable = os.access(Path.cwd(), os.W_OK)
    checks.append(
        DoctorCheck(
            "Report directory",
            PASS if cwd_writable else WARN,
            "current directory is writable; use --output to choose another"
            if cwd_writable
            else "current directory is not writable; use --output DIR",
        )
    )
    encoding = (sys.stdout.encoding or "unknown").lower()
    checks.append(
        DoctorCheck(
            "Terminal encoding",
            PASS if "utf" in encoding else WARN,
            encoding if "utf" in encoding else f"{encoding}: some characters may display poorly",
        )
    )
    return checks
