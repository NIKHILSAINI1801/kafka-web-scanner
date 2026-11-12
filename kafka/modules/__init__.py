"""Scanner modules and their registry.

Every module exposes ``scan(snapshot) -> list[Finding]`` and is purely passive: it only
inspects the single response that has already been fetched.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from kafka.models import Finding, ResponseSnapshot
from kafka.modules import cookies, cors, headers, https, technology


@dataclass(frozen=True)
class ModuleInfo:
    """Description of a scanner module for the ``modules`` command and reports."""

    key: str
    name: str
    description: str
    checks: tuple[str, ...]
    finding_prefix: str
    run: Callable[[ResponseSnapshot], list[Finding]]


MODULES: tuple[ModuleInfo, ...] = (
    ModuleInfo(
        key="https",
        name="HTTPS / transport",
        description="HTTP vs HTTPS, verified connection, redirects (never followed).",
        checks=("URL scheme", "verified TLS connection", "redirect target"),
        finding_prefix="KAFKA-TLS",
        run=https.scan,
    ),
    ModuleInfo(
        key="headers",
        name="Security headers",
        description="Presence and basic strength of five security response headers.",
        checks=(
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy",
        ),
        finding_prefix="KAFKA-HDR",
        run=headers.scan,
    ),
    ModuleInfo(
        key="cookies",
        name="Cookies",
        description="Cookie attributes. Values are never stored or printed.",
        checks=("Secure", "HttpOnly", "SameSite", "cookie prefixes"),
        finding_prefix="KAFKA-CKE",
        run=cookies.scan,
    ),
    ModuleInfo(
        key="cors",
        name="CORS",
        description="Cross-origin response headers; wildcard is judged in context.",
        checks=("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Vary"),
        finding_prefix="KAFKA-CORS",
        run=cors.scan,
    ),
    ModuleInfo(
        key="technology",
        name="Technology metadata",
        description="Self-reported technology details; no aggressive fingerprinting.",
        checks=("Server", "X-Powered-By", "HTML generator meta tag"),
        finding_prefix="KAFKA-TECH",
        run=technology.scan,
    ),
)

__all__ = ["MODULES", "ModuleInfo"]
