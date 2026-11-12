"""Command line interface (Typer)."""

import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from kafka import TOOL_NAME, __version__, ui
from kafka.config import DEFAULT_OUTPUT_DIR, ScanConfig
from kafka.database import Database, DatabaseError
from kafka.doctor import FAIL, run_checks
from kafka.reports import ReportError, write_reports
from kafka.scanner import run_scan
from kafka.scope import URLValidationError, validate_url

EXIT_ERROR = 1
EXIT_REFUSED = 2

_HELP = (
    "KAFKA: a passive, permission-based website security configuration scanner. "
    "Scan only websites you own or are explicitly authorized to assess."
)

app = typer.Typer(
    name="kafka",
    help=_HELP,
    add_completion=False,
    no_args_is_help=False,
    rich_markup_mode=None,
    pretty_exceptions_show_locals=False,  # locals could contain remote data
)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """KAFKA: a passive, permission-based website security configuration scanner."""
    if ctx.invoked_subcommand is None:
        ui.print_dashboard(ui.make_console())


@app.command()
def scan(
    url: str = typer.Argument(
        ..., help="Target URL (http:// or https://) you are authorized to scan."
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Directory for the HTML, JSON and TXT reports (default: ./kafka-reports).",
    ),
    allow_private: bool = typer.Option(
        False,
        "--allow-private",
        help="Isolated-lab mode: allow loopback/private addresses. All other safeguards stay on.",
    ),
    i_am_authorized: bool = typer.Option(
        False,
        "--i-am-authorized",
        help="Non-interactive use: assert you are authorized to scan this target (skips the prompt).",
    ),
) -> None:
    """Confirm authorization, scan one URL (a single GET request) and write reports."""
    console = ui.make_console()
    try:
        _scan(console, url, output, allow_private, i_am_authorized)
    except (typer.Exit, typer.Abort):
        raise
    except KeyboardInterrupt:
        ui.print_error(console, "Interrupted", "The scan was cancelled.")
        raise typer.Exit(130) from None
    except Exception as exc:
        if os.environ.get("KAFKA_DEBUG"):
            raise
        ui.print_error(
            console,
            "Unexpected error",
            f"KAFKA hit an internal error ({type(exc).__name__}). Set KAFKA_DEBUG=1 and re-run "
            "to see the traceback when reporting a bug.",
        )
        raise typer.Exit(EXIT_ERROR) from None


def _scan(
    console: Console,
    url: str,
    output: Optional[Path],
    allow_private: bool,
    i_am_authorized: bool,
) -> None:
    try:
        target = validate_url(url)
    except URLValidationError as exc:
        ui.print_error(console, "Invalid URL", str(exc))
        raise typer.Exit(EXIT_REFUSED) from None

    ui.print_authorization_notice(console, target, allow_private)
    if not ui.ask_authorization(console, i_am_authorized):
        ui.print_error(
            console, "Not authorized", "No confirmation was given, so no network request was made."
        )
        raise typer.Exit(EXIT_REFUSED)

    config = ScanConfig(allow_private=allow_private)
    with ui.scan_progress(console) as progress:
        result = run_scan(
            target,
            config,
            progress=progress,
            authorization="flag" if i_am_authorized else "interactive",
        )

    notes: list[str] = []
    exit_code = 0
    if result.status == "blocked":
        exit_code = EXIT_REFUSED
    elif result.status != "completed":
        exit_code = EXIT_ERROR

    report_paths: dict[str, Path] = {}
    try:
        report_paths = write_reports(result, output or DEFAULT_OUTPUT_DIR)
    except ReportError as exc:
        notes.append(f"Reports were not written: {exc}")
        exit_code = exit_code or EXIT_ERROR
    try:
        Database().add_scan(result)
    except DatabaseError as exc:
        notes.append(f"Scan history was not saved: {exc}")

    ui.print_scan_summary(console, result, report_paths, notes)
    if exit_code:
        raise typer.Exit(exit_code)


@app.command()
def modules() -> None:
    """List the scanner modules and what each one checks."""
    ui.print_modules(ui.make_console())


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", min=1, max=200, help="Number of scans to show."),
) -> None:
    """Show recent scans from the local history."""
    console = ui.make_console()
    try:
        records = Database().recent(limit)
    except DatabaseError as exc:
        ui.print_error(console, "History unavailable", str(exc))
        raise typer.Exit(EXIT_ERROR) from None
    ui.print_history(console, records)


@app.command()
def doctor() -> None:
    """Check that the environment is ready (no network access)."""
    console = ui.make_console()
    checks = run_checks()
    ui.print_doctor(console, checks)
    if any(check.status == FAIL for check in checks):
        raise typer.Exit(EXIT_ERROR)


@app.command()
def version() -> None:
    """Show the KAFKA version."""
    typer.echo(f"{TOOL_NAME} {__version__}")


if __name__ == "__main__":
    app()
