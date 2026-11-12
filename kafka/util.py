"""Small text, time and filename helpers shared across KAFKA.

Everything that came from a remote server is untrusted. These helpers make that text safe
to put in terminals, reports and databases (no control characters, bounded length).
"""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime

_FILENAME_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def truncate(text: str, max_length: int) -> str:
    """Shorten ``text`` to ``max_length`` characters, marking the cut with ``...``."""
    if max_length < 4 or len(text) <= max_length:
        return text[:max_length] if max_length >= 0 else text
    return text[: max_length - 3] + "..."


def clean_text(value: object, max_length: int | None = None, *, keep_newlines: bool = False) -> str:
    """Return ``value`` as printable text.

    Removes control, format (e.g. bidirectional override), surrogate, private-use and
    unassigned characters so that remote data cannot inject terminal escape sequences or
    spoof the displayed text. Tabs and (optionally) newlines are normalised.
    """
    out: list[str] = []
    for ch in str(value):
        if ch == "\n" and keep_newlines:
            out.append(ch)
            continue
        if ch in "\t\r\n":
            out.append(" ")
            continue
        category = unicodedata.category(ch)
        if category in ("Zl", "Zp"):
            out.append(" ")
        elif category[0] == "C":
            continue
        else:
            out.append(ch)
    text = "".join(out)
    if max_length is not None:
        text = truncate(text, max_length)
    return text


def sanitize_filename(value: str, max_length: int = 80) -> str:
    """Reduce ``value`` to a safe, portable filename component (letters, digits, ``._-``)."""
    cleaned = _FILENAME_UNSAFE.sub("_", value).strip("._-")
    return cleaned[:max_length].rstrip("._-") or "target"


def utc_now() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(UTC)


def format_utc(moment: datetime) -> str:
    """ISO-8601 UTC timestamp with a trailing ``Z`` (second precision)."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
