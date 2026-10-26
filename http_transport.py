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

class PersistentHttpClient:
    def __init__(self, target: HttpTarget, timeout: float, use_proxy: bool = True):
        self.target = target
        self.timeout = timeout
        self.use_proxy = use_proxy
        self.connection: http.client.HTTPConnection | None = None
        self.absolute_form = False
        self.closed_by_peer = False

    def __enter__(self) -> PersistentHttpClient:
        self.connection = self._create_connection()
        self.connection.connect()
        return self

    def __exit__(self, *_args: object) -> None:
        if self.connection is not None:
            self.connection.close()

    def get(self, path: str, close: bool = False) -> HttpResponse:
        return self.request("GET", path, None, None, close)

    def post(self, path: str, body: bytes, boundary: bytes, close: bool = False) -> HttpResponse:
        return self.request("POST", path, body, boundary, close)

    def request(self, method: str, path: str, body: bytes | None, boundary: bytes | None, close: bool) -> HttpResponse:
        if self.connection is None:
            raise RuntimeError("HTTP client is not connected")
        if self.closed_by_peer:
            raise ConnectionError("the previous response closed the persistent connection")
        if not path.startswith("/") or not path.isascii():
            raise ValueError("request path must be absolute and ASCII")
        target = self.target.origin + path if self.absolute_form else path
        self.connection.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
        self.connection.putheader("Host", self.target.authority)
        self.connection.putheader("Connection", "close" if close else "keep-alive")
        if body is not None:
            if boundary is None:
                raise ValueError("multipart boundary is required for a request body")
            self.connection.putheader("Content-Length", str(len(body)))
            self.connection.putheader("Content-Type", "multipart/form-data; boundary=" + boundary.decode("ascii"))
        self.connection.endheaders(body)
        source = self.connection.getresponse()
        try:
            response_body = source.read()
        except http.client.IncompleteRead as error:
            response_body = error.partial
        self.closed_by_peer = source.will_close
        return HttpResponse(source.status, source.reason, tuple(source.getheaders()), response_body, source.will_close)

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
