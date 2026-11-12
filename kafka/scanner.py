"""Scan orchestration: scope check, single bounded request, passive modules, risk summary."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence

from kafka import __version__
from kafka.config import ScanConfig
from kafka.http_client import FetchError, fetch
from kafka.models import ResponseSnapshot, ScanError, ScanResult
from kafka.modules import MODULES
from kafka.risk import sort_findings
from kafka.scope import (
    IPAddress,
    ResolutionError,
    ScanTarget,
    ScopeError,
    resolve_and_check,
)
from kafka.util import clean_text, utc_now

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, int, int], None]
ResolveFn = Callable[..., Sequence[IPAddress]]
FetchFn = Callable[..., ResponseSnapshot]

TOTAL_STEPS = 2 + len(MODULES)


def _http_summary(snapshot: ResponseSnapshot) -> dict[str, object]:
    """Non-sensitive facts about the response (no headers, no body)."""
    return {
        "scheme": snapshot.scheme,
        "status_code": snapshot.status_code,
        "reason": snapshot.reason,
        "http_version": snapshot.http_version,
        "content_type": clean_text(snapshot.content_type, max_length=100),
        "resolved_ip": snapshot.resolved_ip,
        "tls_verified": snapshot.tls_verified,
        "tls_protocol": snapshot.tls_protocol,
        "response_bytes_read": len(snapshot.body),
        "body_truncated": snapshot.body_truncated,
        "elapsed_ms": snapshot.elapsed_ms,
    }


def run_scan(
    target: ScanTarget,
    config: ScanConfig | None = None,
    *,
    progress: ProgressCallback | None = None,
    resolver: ResolveFn = resolve_and_check,
    fetcher: FetchFn = fetch,
    authorization: str = "interactive",
) -> ScanResult:
    """Run one complete passive scan and return its result.

    The caller must have obtained the user's authorization confirmation first. This
    function never raises for network or module problems; they are recorded in
    ``result.errors`` and reflected in ``result.status``:

    ``completed``, ``partial`` (a module failed), ``failed`` (no response obtained) or
    ``blocked`` (target outside the permitted scope).
    """
    config = config or ScanConfig()
    result = ScanResult(
        target=target.display_url,
        tool_version=__version__,
        started_at=utc_now(),
        authorization=authorization,
        lab_mode=config.allow_private,
    )
    step = 0

    def tick(message: str) -> None:
        nonlocal step
        step += 1
        if progress is not None:
            progress(message, step, TOTAL_STEPS)

    try:
        tick("Resolving host and checking scope")
        addresses = resolver(target, allow_private=config.allow_private)
        tick("Sending one bounded GET request")
        snapshot = fetcher(target, addresses, config.limits)
    except ScopeError as exc:
        result.status = "blocked"
        result.errors.append(ScanError("blocked_target", str(exc)))
    except ResolutionError as exc:
        result.status = "failed"
        result.errors.append(ScanError("dns_failure", str(exc)))
    except FetchError as exc:
        result.status = "failed"
        result.errors.append(ScanError(exc.code, exc.message))
    else:
        result.status_code = snapshot.status_code
        result.http = _http_summary(snapshot)
        if snapshot.body_truncated:
            result.warnings.append(
                f"Response body was truncated at {config.limits.max_response_bytes} bytes; "
                "HTML metadata checks only cover the captured part."
            )
        if snapshot.content_encoding not in ("", "identity"):
            result.warnings.append(
                "The response was compressed; the body was not decoded, so HTML metadata "
                "checks were skipped."
            )
        findings = []
        for module in MODULES:
            tick(f"Checking {module.name}")
            try:
                findings.extend(module.run(snapshot))
                result.modules_run.append(module.key)
            except Exception as exc:  # noqa: BLE001 - one module must not abort the scan
                logger.debug("module %s failed", module.key, exc_info=True)
                result.status = "partial"
                result.errors.append(
                    ScanError(
                        "module_failed", f"Module '{module.key}' failed ({type(exc).__name__})."
                    )
                )
        result.findings = sort_findings(findings)

    result.finished_at = utc_now()
    return result
