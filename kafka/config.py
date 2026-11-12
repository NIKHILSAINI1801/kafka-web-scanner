"""Configuration constants, safety limits and per-user storage locations."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

JSON_SCHEMA_VERSION = "1.0"
MAX_URL_LENGTH = 2048
DEFAULT_OUTPUT_DIR = Path("kafka-reports")

DISCLAIMER = (
    "KAFKA is an educational, passive configuration scanner. Severity ratings are preliminary "
    "triage, not proof of exploitability, and this report is not a security certification. "
    "Human review is required."
)

LIMITATIONS: tuple[str, ...] = (
    "Only one endpoint (a single GET request) is examined, not the whole site.",
    "A missing header is not automatically a vulnerability; context decides.",
    "CORS review is limited: no Origin header is sent, so dynamic allow-lists are not exercised.",
    "Technology metadata is self-reported by the server and can be incomplete or spoofed.",
    "A successful HTTPS connection only means this client accepted the certificate for this "
    "connection. It is not a TLS audit.",
    "Address checks have a time-of-check/time-of-use limitation; see docs/SECURITY.md.",
)


@dataclass(frozen=True)
class HttpLimits:
    """Hard bounds applied to the single outbound request."""

    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    total_timeout: float = 20.0
    max_response_bytes: int = 1_048_576


@dataclass(frozen=True)
class ScanConfig:
    """Options for one scan."""

    allow_private: bool = False
    limits: HttpLimits = field(default_factory=HttpLimits)


def data_dir() -> Path:
    """Per-user directory for scan history. ``KAFKA_HOME`` overrides the default."""
    override = os.environ.get("KAFKA_HOME")
    if override:
        return Path(override).expanduser()
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA")
        return (Path(base) if base else Path.home() / "AppData" / "Local") / "KAFKA"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "KAFKA"
    xdg = os.environ.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else Path.home() / ".local" / "share") / "kafka"


def database_path() -> Path:
    """Location of the SQLite history database."""
    return data_dir() / "history.db"
