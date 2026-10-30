from __future__ import annotations

from dataclasses import dataclass
import http.client
import ssl
import urllib.parse

CHALLENGE_HOST = "old.stealmybitcoin.com"
CHALLENGE_PORT = 443
CHALLENGE_ORIGIN = f"https://{CHALLENGE_HOST}"
CHALLENGE_ENDPOINT = "/ping.php"
CHALLENGE_READINESS_PATH = "/php-version.php"


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
    def post(
        cls,
        path: str,
        body: bytes,
        boundary: bytes,
        close: bool = False,
    ) -> HttpRequest:
        return cls("POST", path, body, boundary, close)


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    closes_connection: bool

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
    """Direct TLS client locked to the authorized challenge host."""

    def __init__(self, timeout: float):
        self.timeout = timeout
        self.connection: http.client.HTTPSConnection | None = None
        self.stream: object | None = None
        self.reader: SharedReader | None = None
        self.closed_by_peer = False

    def __enter__(self) -> PersistentHttpClient:
        self.connection = http.client.HTTPSConnection(
            CHALLENGE_HOST,
            CHALLENGE_PORT,
            timeout=self.timeout,
            context=ssl.create_default_context(),
        )
        self.connection.connect()
        if self.connection.sock is None:
            raise ConnectionError("HTTPS connection did not yield a socket")
        self.connection.sock.settimeout(self.timeout)
        self.stream = self.connection.sock.makefile("rb")
        self.reader = SharedReader(self.stream)
        return self

    def __exit__(self, *_args: object) -> None:
        if self.stream is not None:
            self.stream.close()
        if self.connection is not None:
            self.connection.close()

    def pipeline(
        self,
        requests: tuple[HttpRequest, ...],
    ) -> tuple[HttpResponse, ...]:
        if self.connection is None or self.connection.sock is None or self.reader is None:
            raise RuntimeError("HTTPS client is not connected")
        if self.closed_by_peer:
            raise ConnectionError("the challenge closed the persistent connection")
        if not requests:
            raise ValueError("pipeline must contain at least one request")
        frames = tuple(self._frame(request) for request in requests)
        self.connection.sock.sendall(b"".join(frames))
        responses = tuple(self._response() for _ in requests)
        self.closed_by_peer = responses[-1].closes_connection
        return responses

    def _frame(self, request: HttpRequest) -> bytes:
        self._require_allowed_request(request)
        headers = (
            f"{request.method} {request.path} HTTP/1.1\r\n"
            f"Host: {CHALLENGE_HOST}\r\n"
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
            "Content-Type: multipart/form-data; boundary="
            f"{request.boundary.decode('ascii')}\r\n\r\n"
        )
        return headers.encode("ascii") + entity_headers.encode("ascii") + request.body

    @staticmethod
    def _require_allowed_request(request: HttpRequest) -> None:
        if not request.path.isascii() or any(
            ord(character) <= 0x20 or ord(character) == 0x7F
            for character in request.path
        ):
            raise ValueError("request path must be printable ASCII without spaces")
        parsed = urllib.parse.urlsplit(request.path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise ValueError("request path must be a relative challenge URL")
        if (
            request.method == "GET"
            and parsed.path == CHALLENGE_READINESS_PATH
            and not parsed.query
        ):
            return
        if request.method == "POST" and parsed.path == CHALLENGE_ENDPOINT:
            return
        raise ValueError("request is outside the authorized challenge paths")

    def _response(self) -> HttpResponse:
        if self.reader is None:
            raise RuntimeError("HTTPS response reader is not available")
        source = http.client.HTTPResponse(SharedSocket(self.reader))
        source.begin()
        try:
            body = source.read()
        except http.client.IncompleteRead as error:
            body = error.partial
        return HttpResponse(
            source.status,
            source.reason,
            tuple(source.getheaders()),
            body,
            source.will_close,
        )
