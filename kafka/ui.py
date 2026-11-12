"""Terminal presentation with Rich.

Every piece of remote or user-supplied text is wrapped in ``Text`` (never parsed as Rich
markup), so a hostile header such as ``Server: [red]x`` cannot change the display.
Severity is always shown as a text label plus a text marker, never by colour alone.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

from kafka import __version__
from kafka.config import DISCLAIMER
from kafka.database import ScanRecord
from kafka.doctor import FAIL, PASS, DoctorCheck
from kafka.models import SEVERITY_ORDER, ScanResult, Severity
from kafka.modules import MODULES
from kafka.risk import GLYPHS, sort_findings, summarize, top_recommendations
from kafka.scanner import TOTAL_STEPS
from kafka.scope import ScanTarget
from kafka.util import clean_text

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim",
}
STATUS_STYLE = {"completed": "green", "partial": "yellow", "failed": "red", "blocked": "red"}
CHECK_STYLE = {PASS: "green", "WARN": "yellow", FAIL: "bold red"}


def _banner() -> str:
    letters = {
        "K": [" _  __", "| |/ /", "| ' / ", "| . \\ ", "|_|\\_\\"],
        "A": ["    _    ", "   / \\   ", "  / _ \\  ", " / ___ \\ ", "/_/   \\_\\"],
        "F": [" _____ ", "|  ___|", "| |_   ", "|  _|  ", "|_|    "],
    }
    rows = []
    for row in range(5):
        rows.append(
            "".join(letters[ch][row].ljust(len(max(letters[ch], key=len))) for ch in "KAFKA")
        )
    return "\n".join(rows)


def make_console() -> Console:
    """Console that never interprets data as markup or auto-highlights it.

    Characters the terminal's encoding cannot represent (for example from a hostile or
    non-Latin response on a legacy Windows code page) are replaced instead of raising.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
    return Console(highlight=False)


def severity_text(severity: Severity) -> Text:
    return Text(f"{GLYPHS[severity]} {severity.value}", style=SEVERITY_STYLE[severity])


def print_dashboard(console: Console) -> None:
    """Command overview shown when ``kafka`` is run without arguments."""
    header = Group(
        Text(_banner(), style="bold cyan"),
        Text(f"v{__version__}  Passive website security configuration scanner"),
        Text("Educational tool. One GET request, no exploitation, no crawling.", style="dim"),
    )
    console.print(Panel(header, box=box.ROUNDED, border_style="cyan"))

    table = Table(title="Commands", box=box.SIMPLE_HEAD, title_justify="left")
    table.add_column("Command", style="bold")
    table.add_column("What it does")
    for command, text in (
        ("kafka scan URL", "Confirm authorization, scan one URL, write HTML/JSON/TXT reports"),
        ("kafka scan URL --output DIR", "Choose the report directory (default: ./kafka-reports)"),
        ("kafka scan URL --allow-private", "Isolated-lab mode for loopback/private addresses"),
        ("kafka modules", "List the scanner modules and what they check"),
        ("kafka history", "Show recent scans from the local history"),
        ("kafka doctor", "Check that your environment is ready"),
        ("kafka version", "Show the version"),
    ):
        table.add_row(Text(command), Text(text))
    console.print(table)
    console.print(
        Panel(
            Text(
                "Scan only websites you own or have explicit permission to assess. "
                "Unauthorized scanning may be illegal.",
            ),
            title="Authorized use only",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )


def print_authorization_notice(console: Console, target: ScanTarget, allow_private: bool) -> None:
    lines = [
        Text("KAFKA will send ONE bounded HTTP(S) GET request to:"),
        Text(f"  {target.display_url}", style="bold"),
        Text(""),
        Text(
            "It does not follow redirects, log in, submit forms, crawl or exploit anything. "
            "You must own this website or have explicit permission to assess it."
        ),
    ]
    if allow_private:
        lines += [
            Text(""),
            Text(
                "LAB MODE (--allow-private): loopback/private addresses are allowed. Use this "
                "only on an isolated network you control. All other safeguards stay on.",
                style="bold yellow",
            ),
        ]
    console.print(
        Panel(Group(*lines), title="Authorization required", border_style="yellow", box=box.ROUNDED)
    )


def ask_authorization(console: Console, assume_yes: bool) -> bool:
    """Ask for an explicit yes. Anything else (including no input) means no."""
    if assume_yes:
        console.print(Text("Authorization asserted with --i-am-authorized."))
        return True
    prompt = Text("Do you own this website or have explicit permission to assess it? [y/N]: ")
    try:
        answer = console.input(prompt)
    except (EOFError, KeyboardInterrupt):
        console.print()
        return False
    return answer.strip().lower() in {"y", "yes"}


def print_error(console: Console, title: str, message: str) -> None:
    console.print(
        Panel(Text(clean_text(message)), title=title, border_style="red", box=box.ROUNDED)
    )


@contextmanager
def scan_progress(console: Console) -> Iterator[Callable[[str, int, int], None]]:
    """Progress bar for the scan; yields the callback to hand to ``run_scan``."""
    progress = Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    )
    with progress:
        task = progress.add_task("Starting", total=TOTAL_STEPS)

        def callback(message: str, step: int, total: int) -> None:
            progress.update(task, description=message, completed=step - 1, total=total)

        yield callback
        progress.update(task, description="Finished", completed=TOTAL_STEPS)


def print_scan_summary(
    console: Console,
    result: ScanResult,
    report_paths: dict[str, Path],
    notes: Sequence[str] = (),
) -> None:
    """Show the outcome of a scan in the terminal."""
    summary = summarize(result.findings)

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold")
    info.add_column()
    info.add_row("Target", Text(result.target))
    info.add_row("Status", Text(result.status, style=STATUS_STYLE.get(result.status, "")))
    if result.status_code is not None:
        info.add_row(
            "HTTP status", Text(f"{result.status_code} {result.http.get('reason', '')}".strip())
        )
    for label, key in (("Resolved IP", "resolved_ip"), ("TLS", "tls_protocol")):
        if result.http.get(key):
            info.add_row(label, Text(str(result.http[key])))
    console.print(Panel(info, title="Scan result", border_style="cyan", box=box.ROUNDED))

    for error in result.errors:
        print_error(console, f"Error: {error.code}", error.message)
    for warning in result.warnings:
        console.print(Text(f"Warning: {warning}", style="yellow"))

    if result.status in {"completed", "partial"}:
        counts = Table(title="Severity summary", box=box.SIMPLE_HEAD, title_justify="left")
        counts.add_column("Severity")
        counts.add_column("Count", justify="right")
        for severity in SEVERITY_ORDER:
            counts.add_row(severity_text(severity), Text(str(summary.counts[severity.value])))
        console.print(counts)
        console.print(Text(f"Preliminary triage: {summary.triage}", style="bold"))

        findings = Table(title="Findings", box=box.SIMPLE_HEAD, title_justify="left")
        findings.add_column("ID", no_wrap=True)
        findings.add_column("Severity", no_wrap=True)
        findings.add_column("Confidence", no_wrap=True)
        findings.add_column("Finding")
        for finding in sort_findings(result.findings):
            findings.add_row(
                Text(finding.id),
                severity_text(finding.severity),
                Text(finding.confidence.value),
                Text(finding.title),
            )
        console.print(findings)

        recommendations = top_recommendations(result.findings)
        if recommendations:
            console.print(Text("Top recommendations", style="bold"))
            for index, (finding_id, text) in enumerate(recommendations, start=1):
                console.print(Text(f"  {index}. [{finding_id}] {text}"))

    if report_paths:
        console.print(Text("Reports written:", style="bold"))
        for kind in ("html", "json", "txt"):
            if kind in report_paths:
                console.print(Text(f"  {kind.upper():<5} {report_paths[kind]}"))
    for note in notes:
        console.print(Text(note, style="yellow"))
    console.print(Text(DISCLAIMER, style="dim"))


def print_modules(console: Console) -> None:
    table = Table(title="Scanner modules (all passive)", box=box.SIMPLE_HEAD, title_justify="left")
    table.add_column("Key", style="bold", no_wrap=True)
    table.add_column("Module")
    table.add_column("What it checks")
    table.add_column("Finding IDs", no_wrap=True)
    for module in MODULES:
        table.add_row(
            Text(module.key),
            Text(module.name),
            Text(f"{module.description} ({', '.join(module.checks)})"),
            Text(f"{module.finding_prefix}-nnn"),
        )
    console.print(table)


def print_history(console: Console, records: Sequence[ScanRecord]) -> None:
    if not records:
        console.print(Text("No scans recorded yet. Run: kafka scan URL"))
        return
    table = Table(title="Recent scans", box=box.SIMPLE_HEAD, title_justify="left")
    table.add_column("ID", justify="right", no_wrap=True)
    table.add_column("Started (UTC)", no_wrap=True)
    table.add_column("Target")
    table.add_column("HTTP", justify="right", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("C/H/M/L/I", no_wrap=True)
    for record in records:
        if record.counts is None:
            counts = "unreadable"
        else:
            counts = "/".join(str(record.counts[s.value]) for s in SEVERITY_ORDER)
        table.add_row(
            Text(str(record.id)),
            Text(clean_text(record.started_at, max_length=25)),
            Text(clean_text(record.target, max_length=120)),
            Text(str(record.status_code) if record.status_code is not None else "-"),
            Text(
                clean_text(record.status, max_length=20), style=STATUS_STYLE.get(record.status, "")
            ),
            Text(counts),
        )
    console.print(table)
    console.print(Text("C/H/M/L/I = Critical/High/Medium/Low/Info finding counts.", style="dim"))


def print_doctor(console: Console, checks: Sequence[DoctorCheck]) -> None:
    table = Table(title="KAFKA environment check", box=box.SIMPLE_HEAD, title_justify="left")
    table.add_column("Check")
    table.add_column("Result", no_wrap=True)
    table.add_column("Details")
    for check in checks:
        table.add_row(
            Text(check.name),
            Text(check.status, style=CHECK_STYLE.get(check.status, "")),
            Text(clean_text(check.detail, max_length=200)),
        )
    console.print(table)
    failed = sum(1 for check in checks if check.status == FAIL)
    if failed:
        console.print(
            Text(f"{failed} check(s) failed. Fix them before scanning.", style="bold red")
        )
    else:
        console.print(Text("Environment looks ready.", style="green"))
