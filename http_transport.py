from __future__ import annotations

import base64
from dataclasses import dataclass
import http.client
import ssl
import urllib.parse
import urllib.request

@dataclass(frozen=True, slots=True)
class HttpTarget:
    scheme: str
    host: str
    port: int

    @classmethod
    def parse(cls, value: str) -> HttpTarget:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target must be an absolute HTTP or HTTPS URL")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("target URL must not contain a path, query, or fragment")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return cls(parsed.scheme, parsed.hostname, port)

    @property
    def authority(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.authority}"

@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    path: str
    body: bytes | None = None
    boundary: bytes | None = None
    close: bool = False

    @classmethod
    def get(cls, path: str, close: bool = False) -> HttpRequest:
        return cls("GET", path, close=close)

    @classmethod
    def post(cls, path: str, body: bytes, boundary: bytes, close: bool = False) -> HttpRequest:
        return cls("POST", path, body, boundary, close)

@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    closes_connection: bool

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        return next((value for key, value in self.headers if key.lower() == lowered), None)

    def session_cookie(self) -> bytes:
        marker = "PHPSESSID="
        for name, value in self.headers:
            if name.lower() == "set-cookie" and marker in value:
                encoded = value.split(marker, 1)[1].split(";", 1)[0]
                return urllib.parse.unquote_to_bytes(encoded.replace("+", " "))
        return b""

class SharedReader:
    def __init__(self, stream: object):
        self.stream = stream

    def read(self, *args: object, **kwargs: object) -> bytes:
        return self.stream.read(*args, **kwargs)

    def readline(self, *args: object, **kwargs: object) -> bytes:
        return self.stream.readline(*args, **kwargs)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None

class SharedSocket:
    def __init__(self, reader: SharedReader):
        self.reader = reader

    def makefile(self, *_args: object, **_kwargs: object) -> SharedReader:
        return self.reader

class PersistentHttpClient:
    def __init__(self, target: HttpTarget, timeout: float, use_proxy: bool = True):
        self.target = target
        self.timeout = timeout
        self.use_proxy = use_proxy
        self.connection: http.client.HTTPConnection | None = None
        self.stream: object | None = None
        self.reader: SharedReader | None = None
        self.absolute_form = False
        self.closed_by_peer = False

    def __enter__(self) -> PersistentHttpClient:
        self.connection = self._create_connection()
        self.connection.connect()
        if self.connection.sock is None:
            raise ConnectionError("HTTP connection did not yield a socket")
        self.connection.sock.settimeout(self.timeout)
        self.stream = self.connection.sock.makefile("rb")
        self.reader = SharedReader(self.stream)
        return self

    def __exit__(self, *_args: object) -> None:
        if self.stream is not None:
            self.stream.close()
        if self.connection is not None:
            self.connection.close()

    def get(self, path: str, close: bool = False) -> HttpResponse:
        return self.pipeline((HttpRequest.get(path, close),))[0]

    def post(self, path: str, body: bytes, boundary: bytes, close: bool = False) -> HttpResponse:
        return self.pipeline((HttpRequest.post(path, body, boundary, close),))[0]

    def pipeline(self, requests: tuple[HttpRequest, ...]) -> tuple[HttpResponse, ...]:
        if self.connection is None or self.connection.sock is None or self.reader is None:
            raise RuntimeError("HTTP client is not connected")
        if self.closed_by_peer:
            raise ConnectionError("the previous response closed the persistent connection")
        if not requests:
            raise ValueError("pipeline must contain at least one request")
        frames = tuple(self._frame(request) for request in requests)
        self.connection.sock.sendall(b"".join(frames))
        responses = tuple(self._response() for _ in requests)
        self.closed_by_peer = responses[-1].closes_connection
        return responses

    def _frame(self, request: HttpRequest) -> bytes:
        if not request.path.startswith("/") or not request.path.isascii():
            raise ValueError("request path must be absolute and ASCII")
        target = self.target.origin + request.path if self.absolute_form else request.path
        headers = (
            f"{request.method} {target} HTTP/1.1\r\n"
            f"Host: {self.target.authority}\r\n"
            f"Connection: {'close' if request.close else 'keep-alive'}\r\n"
        )
        if request.body is None:
            if request.boundary is not None:
                raise ValueError("bodyless request cannot have a multipart boundary")
            return headers.encode("ascii") + b"\r\n"
        if request.boundary is None:
            raise ValueError("multipart boundary is required for a request body")
        entity_headers = (
            f"Content-Length: {len(request.body)}\r\n"
            f"Content-Type: multipart/form-data; boundary={request.boundary.decode('ascii')}\r\n\r\n"
        )
        return headers.encode("ascii") + entity_headers.encode("ascii") + request.body

    def _response(self) -> HttpResponse:
        if self.reader is None:
            raise RuntimeError("HTTP response reader is not available")
        source = http.client.HTTPResponse(SharedSocket(self.reader))
        source.begin()
        try:
            body = source.read()
        except http.client.IncompleteRead as error:
            body = error.partial
        return HttpResponse(source.status, source.reason, tuple(source.getheaders()), body, source.will_close)

    def _create_connection(self) -> http.client.HTTPConnection:
        proxy = self._proxy()
        if proxy is None:
            if self.target.scheme == "https":
                return http.client.HTTPSConnection(self.target.host, self.target.port, timeout=self.timeout, context=ssl.create_default_context())
            return http.client.HTTPConnection(self.target.host, self.target.port, timeout=self.timeout)
        if proxy.scheme != "http" or not proxy.hostname:
            raise ValueError("only HTTP proxy URLs are supported")
        port = proxy.port or 80
        if self.target.scheme == "https":
            connection = http.client.HTTPSConnection(proxy.hostname, port, timeout=self.timeout, context=ssl.create_default_context())
            connection.set_tunnel(self.target.host, self.target.port, self._proxy_headers(proxy))
            return connection
        self.absolute_form = True
        return http.client.HTTPConnection(proxy.hostname, port, timeout=self.timeout)

    def _proxy(self) -> urllib.parse.SplitResult | None:
        if not self.use_proxy or urllib.request.proxy_bypass(self.target.host):
            return None
        value = urllib.request.getproxies().get(self.target.scheme)
        return urllib.parse.urlsplit(value) if value else None

    @staticmethod
    def _proxy_headers(proxy: urllib.parse.SplitResult) -> dict[str, str]:
        if proxy.username is None:
            return {}
        username = urllib.parse.unquote(proxy.username)
        password = urllib.parse.unquote(proxy.password or "")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Proxy-Authorization": "Basic " + token}
