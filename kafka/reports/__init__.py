"""Report generation (HTML, JSON, TXT) with safe file handling."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from kafka.models import ScanResult
from kafka.reports.html import render_html
from kafka.reports.json_report import build_report_dict, render_json
from kafka.reports.text import render_text
from kafka.util import sanitize_filename

__all__ = [
    "ReportError",
    "build_report_dict",
    "render_html",
    "render_json",
    "render_text",
    "report_stem",
    "write_reports",
]

_MAX_COLLISION_ATTEMPTS = 100


class ReportError(Exception):
    """Reports could not be written. The message is safe to show."""


def report_stem(result: ScanResult) -> str:
    """Safe base file name: ``kafka_<host>_<UTC timestamp>``."""
    host = urlsplit(result.target).netloc or result.target
    stamp = result.started_at.strftime("%Y%m%dT%H%M%SZ")
    return f"kafka_{sanitize_filename(host, max_length=60)}_{stamp}"


def _write_exclusive(directory: Path, stem: str, extension: str, content: str) -> Path:
    """Create a new file; never overwrite or follow a pre-existing path."""
    for attempt in range(_MAX_COLLISION_ATTEMPTS):
        suffix = "" if attempt == 0 else f"_{attempt}"
        path = directory / f"{stem}{suffix}.{extension}"
        try:
            with open(path, "x", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
        except FileExistsError:
            continue
        except OSError as exc:
            raise ReportError(
                f"Could not write {extension.upper()} report ({exc.strerror})."
            ) from exc
        return path
    raise ReportError("Could not find an unused report file name.")


def write_reports(result: ScanResult, output_dir: Path | str) -> dict[str, Path]:
    """Write HTML, JSON and TXT reports into ``output_dir`` and return their paths."""
    directory = Path(output_dir)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReportError(f"Could not create the output directory ({exc.strerror}).") from exc
    if not directory.is_dir():
        raise ReportError("The output path exists and is not a directory.")
    stem = report_stem(result)
    contents = {
        "html": render_html(result),
        "json": render_json(result),
        "txt": render_text(result),
    }
    return {ext: _write_exclusive(directory, stem, ext, text) for ext, text in contents.items()}
