from __future__ import annotations

from dataclasses import dataclass
import socket
import subprocess
import time

from exploit_primitives import BOUNDARY

@dataclass(frozen=True, slots=True)
class HttpResponse:
    raw: bytes

    @property
    def status(self) -> str:
        return self.raw.split(b"\r\n", 1)[0].decode("latin1", "replace")

    @property
    def body(self) -> bytes:
        parts = self.raw.split(b"\r\n\r\n", 1)
        return parts[1] if len(parts) == 2 else b""

@dataclass(frozen=True, slots=True)
class PostOptions:
    path: str = "/ping.php"
    boundary: bytes = BOUNDARY
    timeout: float = 20

@dataclass(frozen=True, slots=True)
class DockerTarget:
    name: str

    def identity(self) -> str:
        command = ["docker", "inspect", "--format", "{{.Id}}|{{.Image}}", self.name]
        return subprocess.check_output(command, text=True).strip()

    def restart(self) -> None:
        command = ["docker", "restart", "--timeout", "0", self.name]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        time.sleep(0.1)

@dataclass(frozen=True, slots=True)
class LocalHttpClient:
    port: int

    def post(self, body: bytes, options: PostOptions = PostOptions()) -> HttpResponse:
        boundary = options.boundary.decode("ascii")
        headers = (
            f"POST {options.path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        )
        return HttpResponse(self._exchange(headers.encode("ascii") + body, options.timeout))

    def _exchange(self, request: bytes, timeout: float) -> bytes:
        chunks: list[bytes] = []
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(request)
            while chunk := _receive(connection):
                chunks.append(chunk)
        return b"".join(chunks)

    def probe(self, timeout: float = 1) -> bool:
        request = b"GET /php-version.php HTTP/1.0\r\nHost: localhost\r\n\r\n"
        try:
            response = self._exchange(request, timeout)
        except OSError:
            return False
        return response.startswith(b"HTTP/") and b"200 OK" in response

    def wait_until_ready(self, timeout: float = 10) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.probe():
                return
            time.sleep(0.05)
        raise RuntimeError(f"PHP server on 127.0.0.1:{self.port} did not become ready")

def _receive(connection: socket.socket) -> bytes:
    try:
        return connection.recv(65536)
    except ConnectionResetError:
        return b""
