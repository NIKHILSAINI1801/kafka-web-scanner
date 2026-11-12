"""URL validation and network-scope enforcement.

``validate_url`` is purely offline. ``resolve_and_check`` performs the DNS lookup and applies
the address policy; callers must only invoke it after the user has confirmed authorization.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from kafka.config import MAX_URL_LENGTH
from kafka.util import clean_text

ALLOWED_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}

# Categories that are never scanned, even with --allow-private.
ALWAYS_BLOCKED = frozenset({"unspecified", "multicast", "reserved"})

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[..., list[Any]]

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_NAT64_PREFIX = bytes.fromhex("0064ff9b0000000000000000")


class URLValidationError(ValueError):
    """The supplied URL is not acceptable. Raised before any network activity."""


class ScopeError(Exception):
    """The destination is outside the permitted scope (for example a private address)."""


class ResolutionError(Exception):
    """The host name could not be resolved to an address."""


@dataclass(frozen=True)
class ScanTarget:
    """A validated, normalised target. Fragment and credentials never survive validation."""

    scheme: str
    hostname: str
    port: int
    path_query: str
    explicit_port: bool = False
    has_query: bool = False

    @property
    def is_ip_literal(self) -> bool:
        try:
            ipaddress.ip_address(self.hostname)
        except ValueError:
            return False
        return True

    @property
    def _host_text(self) -> str:
        return f"[{self.hostname}]" if ":" in self.hostname else self.hostname

    @property
    def host_header(self) -> str:
        """Value for the HTTP ``Host`` header (port omitted when it is the scheme default)."""
        if self.port == DEFAULT_PORTS[self.scheme]:
            return self._host_text
        return f"{self._host_text}:{self.port}"

    @property
    def display_url(self) -> str:
        """URL safe to print and store: the query string (possible tokens) is replaced."""
        port = f":{self.port}" if self.explicit_port else ""
        path = clean_text(self.path_query.split("?", 1)[0], max_length=200)
        suffix = "?<query omitted>" if self.has_query else ""
        return f"{self.scheme}://{self._host_text}{port}{path}{suffix}"


def _normalise_host(raw_host: str) -> str:
    if "%" in raw_host:
        raise URLValidationError("Zone identifiers in IPv6 addresses are not supported.")
    try:
        return str(ipaddress.ip_address(raw_host))
    except ValueError:
        pass
    host = raw_host.removesuffix(".")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise URLValidationError("The host name is malformed.") from exc
    if not _HOST_RE.match(ascii_host):
        raise URLValidationError("The host name is malformed.")
    last_label = ascii_host.rsplit(".", 1)[-1]
    if last_label.isdigit() or last_label.startswith("0x"):
        raise URLValidationError(
            "Ambiguous numeric host. Use a normal host name or a standard dotted-decimal IPv4 "
            "address."
        )
    return ascii_host


def validate_url(raw: str) -> ScanTarget:
    """Parse and validate a user-supplied URL without touching the network.

    Accepts only ``http`` and ``https``; rejects embedded credentials, malformed hosts,
    invalid ports, whitespace, control characters and backslashes.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise URLValidationError("The URL is empty.")
    url = raw.strip()
    if len(url) > MAX_URL_LENGTH:
        raise URLValidationError(f"The URL is longer than {MAX_URL_LENGTH} characters.")
    for ch in url:
        if ch == "\\" or ord(ch) <= 0x20 or unicodedata.category(ch).startswith("C"):
            raise URLValidationError(
                "The URL contains whitespace, control characters or backslashes."
            )
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise URLValidationError("The URL is malformed.") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        shown = clean_text(scheme, max_length=20) or "none"
        raise URLValidationError(
            f"Only http:// and https:// URLs are supported (scheme given: {shown}). "
            "Include the scheme, for example https://example.com."
        )
    if not parts.netloc:
        raise URLValidationError("The URL has no host.")
    if "@" in parts.netloc:
        raise URLValidationError("URLs containing credentials (user:password@host) are rejected.")
    try:
        port = parts.port
    except ValueError as exc:
        raise URLValidationError("The URL contains an invalid port.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise URLValidationError("The port must be between 1 and 65535.")
    if not parts.hostname:
        raise URLValidationError("The URL has no host.")

    hostname = _normalise_host(parts.hostname)
    path = parts.path or "/"
    return ScanTarget(
        scheme=scheme,
        hostname=hostname,
        port=port if port is not None else DEFAULT_PORTS[scheme],
        path_query=f"{path}?{parts.query}" if parts.query else path,
        explicit_port=port is not None,
        has_query=bool(parts.query),
    )


def _embedded_ipv4(ip: IPAddress) -> ipaddress.IPv4Address | None:
    if ip.version != 6:
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.packed[:12] == _NAT64_PREFIX:
        return ipaddress.IPv4Address(ip.packed[12:])
    return None


def _classify_single(ip: IPAddress) -> str | None:
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        return "private"
    if not ip.is_global:
        return "non-global"
    return None


def classify_address(ip: IPAddress) -> str | None:
    """Return why ``ip`` is out of scope (``"loopback"``, ``"private"``...), or ``None``.

    IPv6 forms that embed an IPv4 address (IPv4-mapped, 6to4, NAT64) are judged by the
    embedded IPv4 address as well, so they cannot be used to smuggle a private target past
    the check.
    """
    inner = _embedded_ipv4(ip)
    if inner is not None:
        inner_reason = classify_address(inner)
        if inner_reason is not None:
            return inner_reason
        if ip.version == 6 and ip.ipv4_mapped is not None:
            return None
    return _classify_single(ip)


def resolve_and_check(
    target: ScanTarget,
    *,
    allow_private: bool = False,
    resolver: Resolver = socket.getaddrinfo,
) -> list[IPAddress]:
    """Resolve the host and enforce the address policy; return the validated addresses.

    Every resolved address must be acceptable. By default loopback, private, link-local,
    multicast, reserved, unspecified and other non-global addresses are blocked.
    ``allow_private`` (lab mode) relaxes only loopback/private/link-local/shared ranges;
    unspecified, multicast and reserved addresses stay blocked.

    The returned addresses (in resolver order) are meant to be connected to directly, so the
    addresses that were checked are the addresses that are used. The HTTP client connects to
    the first and falls back to the next only if a TCP connection cannot be established. This
    narrows, but does not eliminate, the time-of-check/time-of-use window; see
    docs/SECURITY.md.
    """
    shown = clean_text(target.hostname, max_length=100)
    try:
        infos = resolver(target.hostname, target.port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise ResolutionError(f"Could not resolve host name '{shown}'.") from exc

    addresses: list[IPAddress] = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        except (ValueError, IndexError, TypeError):
            continue
        if ip not in addresses:
            addresses.append(ip)
    if not addresses:
        raise ResolutionError(f"Host name '{shown}' did not resolve to any address.")

    for ip in addresses:
        reason = classify_address(ip)
        if reason is None:
            continue
        if reason in ALWAYS_BLOCKED:
            raise ScopeError(
                f"Blocked: '{shown}' resolves to {ip} ({reason}). "
                "Addresses of this kind are never scanned."
            )
        if not allow_private:
            raise ScopeError(
                f"Blocked: '{shown}' resolves to {ip} ({reason} address). KAFKA scans only "
                "public addresses by default. If this is an isolated lab you control, "
                "use --allow-private."
            )
    return addresses
