"""A local HTTP(S) test server that records every request it receives."""

from __future__ import annotations

import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from kafka.config import HttpLimits
from tests.integration.certs import make_self_signed

DEFAULT_BODY = b"<!doctype html><html><head><title>t</title></head><body>hello</body></html>"
FAST = HttpLimits(
    connect_timeout=4.0, read_timeout=1.0, total_timeout=5.0, max_response_bytes=1_048_576
)


@dataclass
class Route:
    status: int = 200
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = DEFAULT_BODY
    delay: float = 0.0  # seconds to wait before responding
    drip_interval: float = 0.0  # if > 0, send the body one byte at a time
    declared_length: int | None = None
    chunked: bool = False  # send the body with Transfer-Encoding: chunked


@dataclass
class RecordedRequest:
    method: str
    path: str
    headers: dict[str, str]


class LocalServer:
    def __init__(self, tls: tuple[str, str] | None = None) -> None:
        self.requests: list[RecordedRequest] = []
        self.routes: dict[str, Route] = {}
        self.scheme = "https" if tls else "http"
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args) -> None:  # silence
                pass

            def _record(self) -> Route | None:
                owner.requests.append(
                    RecordedRequest(
                        self.command, self.path, {k.lower(): v for k, v in self.headers.items()}
                    )
                )
                if self.command != "GET":
                    self.send_response(405)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return None
                return owner.routes.get(self.path.split("?")[0]) or owner.routes.get("/") or Route()

            def do_GET(self) -> None:
                route = self._record()
                if route is None:
                    return
                if route.delay:
                    time.sleep(route.delay)
                length = (
                    route.declared_length if route.declared_length is not None else len(route.body)
                )
                try:
                    self.send_response(route.status)
                    for name, value in route.headers:
                        self.send_header(name, value)
                    if route.chunked:
                        self.send_header("Transfer-Encoding", "chunked")
                    else:
                        self.send_header("Content-Length", str(length))
                    self.end_headers()
                    if route.chunked:
                        for start in range(0, len(route.body), 4096):
                            part = route.body[start : start + 4096]
                            self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                        self.wfile.write(b"0\r\n\r\n")
                    elif route.drip_interval:
                        for byte in route.body:
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                            time.sleep(route.drip_interval)
                    else:
                        self.wfile.write(route.body)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                    pass

            def do_POST(self) -> None:
                self._record()

            do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = do_POST

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address) -> None:  # noqa: ARG002
                pass

        self.httpd = Server(("127.0.0.1", 0), Handler)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*tls)
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self._thread.start()

    def route(self, path: str = "/", **kwargs) -> Route:
        self.routes[path] = Route(**kwargs)
        return self.routes[path]

    def url(self, path: str = "/", host: str = "127.0.0.1") -> str:
        return f"{self.scheme}://{host}:{self.port}{path}"

    @property
    def methods(self) -> list[str]:
        return [request.method for request in self.requests]

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def limits():
    return FAST


@pytest.fixture
def server():
    srv = LocalServer()
    yield srv
    srv.close()


@pytest.fixture
def tls_material(tmp_path):
    cert, key = make_self_signed(tmp_path, ["localhost"], ["127.0.0.1"], "good")
    return cert, key


@pytest.fixture
def tls_server(tls_material):
    cert, key = tls_material
    srv = LocalServer(tls=(str(cert), str(key)))
    srv.cert_path = str(cert)
    yield srv
    srv.close()


@pytest.fixture
def wrong_name_tls_server(tmp_path):
    cert, key = make_self_signed(tmp_path, ["other.example"], [], "wrong")
    srv = LocalServer(tls=(str(cert), str(key)))
    srv.cert_path = str(cert)
    yield srv
    srv.close()


@pytest.fixture
def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
