"""Bounded, single-request HTTP client.

Safety properties enforced here:

* exactly one ``GET``; no redirects followed; no retries; no cookies sent;
* explicit connect/read timeouts plus an overall deadline (checked after every read, so the
  worst-case overshoot is one read timeout);
* a strict cap on the number of response-body bytes read (streamed, never decompressed);
* TLS certificate and host-name verification always on;
* environment proxy / CA settings ignored (``trust_env`` is off), so the address that was
  validated is the address that is contacted;
* the connection goes to the already-validated IP address, while the ``Host`` header and TLS
  server name still use the original host name.
"""

from __future__ import annotations

import ipaddress
import logging
import ssl
import time
from collections.abc import Sequence
from typing import Any

import requests
import urllib3
from requests.adapters import HTTPAdapter

from kafka import __version__
from kafka.config import HttpLimits
from kafka.models import ResponseSnapshot
from kafka.scope import IPAddress, ScanTarget
from kafka.util import clean_text

logger = logging.getLogger(__name__)

USER_AGENT = f"KAFKA/{__version__} (passive security configuration scanner; authorized use only)"
MAX_HEADER_VALUE_LENGTH = 8192
READ_CHUNK_SIZE = 16384
MAX_CONNECT_ATTEMPTS = 4


class FetchError(Exception):
    """The request could not be completed. ``message`` is safe to show to the user."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ConnectFailed(FetchError):
    """The TCP connection could not be established, so no HTTP request was sent.

    Only this kind of failure allows :func:`fetch` to try the next validated address.
    """


class _PinnedAdapter(HTTPAdapter):
    """Connect to a pre-validated IP while keeping TLS SNI/verification on the host name."""

    def __init__(self, server_hostname: str | None = None) -> None:
        self._server_hostname = server_hostname
        super().__init__(max_retries=0, pool_connections=1, pool_maxsize=1)

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any
    ) -> None:
        if self._server_hostname:
            pool_kwargs["server_hostname"] = self._server_hostname
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)


def _exception_chain(exc: BaseException) -> list[BaseException]:
    """Walk causes, contexts and wrapped exceptions (requests/urllib3 wrap TLS errors)."""
    seen: set[int] = set()
    pending: list[BaseException] = [exc]
    chain: list[BaseException] = []
    while pending:
        current = pending.pop(0)
        if id(current) in seen:
            continue
        seen.add(id(current))
        chain.append(current)
        for nxt in (current.__cause__, current.__context__, getattr(current, "reason", None)):
            if isinstance(nxt, BaseException):
                pending.append(nxt)
        pending.extend(arg for arg in current.args if isinstance(arg, BaseException))
    return chain


def _tls_failure(exc: BaseException) -> FetchError | None:
    """Translate TLS-related exceptions into a safe, specific error (or ``None``)."""
    chain = _exception_chain(exc)
    for item in chain:
        if isinstance(item, ssl.SSLCertVerificationError):
            reason = clean_text(item.verify_message or "certificate verification failed", 160)
            reason = reason.rstrip(".")
            return FetchError(
                "tls_verification_failed",
                f"TLS certificate verification failed: {reason}. "
                "KAFKA never disables certificate verification.",
            )
    for item in chain:
        if isinstance(item, ssl.SSLError | urllib3.exceptions.SSLError):
            return FetchError("tls_error", "The TLS handshake with the target failed.")
    return None


def _tls_protocol(response: requests.Response) -> str | None:
    try:
        sock = getattr(response.raw.connection, "sock", None)
        version = sock.version() if sock is not None and hasattr(sock, "version") else None
    except Exception:  # noqa: BLE001 - purely informational
        return None
    return clean_text(version, max_length=20) if version else None


def _header_lines(response: requests.Response) -> list[tuple[str, str]]:
    raw_headers = response.raw.headers
    iterator = raw_headers.iteritems() if hasattr(raw_headers, "iteritems") else raw_headers.items()
    return [(str(name), str(value)[:MAX_HEADER_VALUE_LENGTH]) for name, value in iterator]


def _fetch_from(
    target: ScanTarget,
    address: IPAddress,
    limits: HttpLimits,
    ca_bundle: str | None,
    deadline: float,
) -> ResponseSnapshot:
    """One connection attempt to one validated address, then (at most) one GET."""
    ip_text = address.compressed
    host_part = f"[{ip_text}]" if address.version == 6 else ip_text
    url = f"{target.scheme}://{host_part}:{target.port}{target.path_query}"
    server_hostname = (
        target.hostname if target.scheme == "https" and not target.is_ip_literal else None
    )
    headers = {
        "Host": target.host_header,
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
        "Accept-Encoding": "identity",
    }

    session = requests.Session()
    session.trust_env = False
    adapter = _PinnedAdapter(server_hostname)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    started = time.monotonic()
    try:
        with session.get(
            url,
            headers=headers,
            timeout=(limits.connect_timeout, limits.read_timeout),
            stream=True,
            allow_redirects=False,
            verify=ca_bundle or True,
        ) as response:
            tls_protocol = _tls_protocol(response) if target.scheme == "https" else None
            header_lines = _header_lines(response)
            body = bytearray()
            truncated = False
            # read1() returns as soon as *any* data has arrived, so the overall deadline is
            # checked after every network read. (A blocking read of a full chunk would let a
            # slow-drip server keep resetting the per-read timeout indefinitely.)
            read_some = getattr(response.raw, "read1", None)
            while True:
                if read_some is not None:
                    chunk = read_some(READ_CHUNK_SIZE, decode_content=False)
                else:  # pragma: no cover - urllib3 < 2.1 fallback with small reads
                    chunk = response.raw.read(256, decode_content=False)
                if not chunk:
                    break
                remaining = limits.max_response_bytes - len(body)
                if len(chunk) > remaining:
                    body.extend(chunk[:remaining])
                    truncated = True
                    break
                body.extend(chunk)
                if time.monotonic() > deadline:
                    raise FetchError("timeout", "The request exceeded the overall time limit.")
            status_code = response.status_code
            reason = clean_text(response.reason or "", max_length=100)
            version = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(response.raw.version, "HTTP")
    except FetchError:
        raise
    except requests.exceptions.ConnectTimeout as exc:
        raise ConnectFailed("timeout", "The connection to the target timed out.") from exc
    except requests.exceptions.Timeout as exc:
        raise FetchError("timeout", "The request timed out (read limit reached).") from exc
    except (
        requests.exceptions.RequestException,
        urllib3.exceptions.HTTPError,
        OSError,
    ) as exc:
        tls = _tls_failure(exc)
        if tls is not None:
            raise tls from exc
        chain = _exception_chain(exc)
        if isinstance(exc, requests.exceptions.ConnectionError) and any(
            isinstance(item, urllib3.exceptions.NewConnectionError) for item in chain
        ):
            raise ConnectFailed("connection_failed", "Could not connect to the target.") from exc
        if any(isinstance(item, TimeoutError) for item in chain) or isinstance(
            exc, urllib3.exceptions.ReadTimeoutError
        ):
            raise FetchError("timeout", "The request timed out.") from exc
        logger.debug("request failed", exc_info=True)
        if isinstance(exc, requests.exceptions.ConnectionError):
            raise FetchError("connection_failed", "Could not connect to the target.") from exc
        raise FetchError("http_error", f"The HTTP request failed ({type(exc).__name__}).") from exc
    finally:
        session.close()

    return ResponseSnapshot(
        scheme=target.scheme,
        hostname=target.hostname,
        port=target.port,
        status_code=status_code,
        reason=reason,
        http_version=version,
        headers=header_lines,
        body=bytes(body),
        body_truncated=truncated,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        resolved_ip=ip_text,
        tls_verified=target.scheme == "https",
        tls_protocol=tls_protocol,
    )


def _attempt_order(addresses: Sequence[IPAddress]) -> list[IPAddress]:
    """First address first, then alternate address families, capped at a few attempts.

    Alternating means a dual-stack host is tried over both IPv6 and IPv4 early, so an
    unreachable IPv6 route does not make a perfectly reachable site look down.
    """
    unique = list(dict.fromkeys(addresses))
    if not unique:
        return []
    first = unique[0]
    same = [a for a in unique[1:] if a.version == first.version]
    other = [a for a in unique[1:] if a.version != first.version]
    ordered = [first]
    while same or other:
        if other:
            ordered.append(other.pop(0))
        if same:
            ordered.append(same.pop(0))
    return ordered[:MAX_CONNECT_ATTEMPTS]


def fetch(
    target: ScanTarget,
    addresses: IPAddress | Sequence[IPAddress],
    limits: HttpLimits | None = None,
    *,
    ca_bundle: str | None = None,
) -> ResponseSnapshot:
    """Perform the single bounded GET and return what was observed.

    ``addresses`` are the already-validated addresses for the host. KAFKA connects to the
    first; only if the TCP connection itself cannot be established (so nothing has been sent)
    does it try the next one. TLS errors, read timeouts and HTTP errors never cause a second
    attempt, so at most one HTTP request is ever sent.

    ``ca_bundle`` exists only so the test-suite can trust a throw-away local certificate
    authority. The command line never exposes it, and verification is never disabled.
    """
    limits = limits or HttpLimits()
    if isinstance(addresses, ipaddress.IPv4Address | ipaddress.IPv6Address):
        candidates = [addresses]
    else:
        candidates = _attempt_order(list(addresses))
    if not candidates:
        raise FetchError("connection_failed", "There is no address to connect to.")

    deadline = time.monotonic() + limits.total_timeout
    last_error: FetchError | None = None
    for candidate in candidates:
        if last_error is not None and time.monotonic() >= deadline:
            break
        try:
            return _fetch_from(target, candidate, limits, ca_bundle, deadline)
        except ConnectFailed as exc:
            logger.debug("connection to %s failed (%s)", candidate, exc.code)
            last_error = exc
    raise last_error or FetchError("timeout", "The request exceeded the overall time limit.")
