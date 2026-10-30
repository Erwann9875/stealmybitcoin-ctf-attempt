from __future__ import annotations

import inspect
import io
import os
import unittest
from unittest import mock

import exploit_primitives as exploit
from exploit_chain import PayloadSet
from http_transport import (
    CHALLENGE_ENDPOINT,
    CHALLENGE_HOST,
    CHALLENGE_PORT,
    CHALLENGE_READINESS_PATH,
    HttpRequest,
    HttpResponse,
    PersistentHttpClient,
)
import remote_proof


def response(status: int = 200, body: bytes = b"") -> HttpResponse:
    return HttpResponse(status, "test", (), body, False)


class ScopeTests(unittest.TestCase):
    def test_transport_is_direct_and_fixed_even_with_proxy_environment(self) -> None:
        connection = mock.MagicMock()
        connection.sock = mock.MagicMock()
        connection.sock.makefile.return_value = io.BytesIO()
        context = object()
        proxy_environment = {
            "HTTP_PROXY": "http://127.0.0.1:1",
            "HTTPS_PROXY": "http://127.0.0.1:1",
        }
        with (
            mock.patch.dict(os.environ, proxy_environment),
            mock.patch(
                "http_transport.ssl.create_default_context",
                return_value=context,
            ),
            mock.patch(
                "http_transport.http.client.HTTPSConnection",
                return_value=connection,
            ) as factory,
        ):
            with PersistentHttpClient(12):
                pass
        factory.assert_called_once_with(
            CHALLENGE_HOST,
            CHALLENGE_PORT,
            timeout=12,
            context=context,
        )
        connection.set_tunnel.assert_not_called()

    def test_request_framing_accepts_only_challenge_paths(self) -> None:
        client = PersistentHttpClient(20)
        readiness = client._frame(HttpRequest.get(CHALLENGE_READINESS_PATH))
        self.assertTrue(
            readiness.startswith(b"GET /php-version.php HTTP/1.1\r\n")
        )
        self.assertIn(f"Host: {CHALLENGE_HOST}\r\n".encode(), readiness)
        client._frame(
            HttpRequest.post(
                CHALLENGE_ENDPOINT + "?q=v",
                b"body",
                b"C",
            )
        )

        invalid = (
            HttpRequest.get("/"),
            HttpRequest.get(CHALLENGE_READINESS_PATH + "?q=v"),
            HttpRequest.post("/other.php", b"x", b"C"),
            HttpRequest.post(
                CHALLENGE_ENDPOINT + "?x y",
                b"x",
                b"C",
            ),
            HttpRequest.post(
                CHALLENGE_ENDPOINT + "?x=1\r\nGET / HTTP/1.1",
                b"x",
                b"C",
            ),
            HttpRequest.post(
                CHALLENGE_ENDPOINT + "#fragment",
                b"x",
                b"C",
            ),
            HttpRequest.post(
                "https://example.com" + CHALLENGE_ENDPOINT,
                b"x",
                b"C",
            ),
        )
        for request in invalid:
            with self.subTest(path=request.path):
                with self.assertRaises(ValueError):
                    client._frame(request)

    def test_payload_command_and_calibration_are_fixed(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(exploit.fake_hash_table).parameters),
            ("address", "zif_system"),
        )
        self.assertEqual(
            tuple(inspect.signature(exploit.build_b2).parameters),
            ("address", "zif_system"),
        )
        table = exploit.fake_hash_table(0x100000, 0x200000)
        command = table[0x98 : 0x98 + len(exploit.PRINT_FLAG_COMMAND)]
        self.assertEqual(command, b"print-flag")

    def test_payload_sizes_remain_calibrated(self) -> None:
        payloads = PayloadSet.create()
        payloads.validate()
        self.assertEqual(
            [len(body) for _, body in payloads.items()],
            [305042, 1045243, 339678, 279369],
        )


class ValidationTests(unittest.TestCase):
    def test_callback_requires_one_new_exact_marker(self) -> None:
        earlier = (response(body=b"ordinary stage"),) * 5
        valid = response(
            body=b"prefix practice{challenge_already_won} suffix"
        )
        self.assertEqual(
            remote_proof.validate_callback(valid, earlier),
            remote_proof.EXPECTED_PRACTICE_FLAG,
        )

        invalid = (
            response(body=b"practice{different_marker}"),
            response(
                body=(
                    remote_proof.EXPECTED_PRACTICE_FLAG
                    + remote_proof.EXPECTED_PRACTICE_FLAG
                )
            ),
            response(status=500, body=remote_proof.EXPECTED_PRACTICE_FLAG),
        )
        for item in invalid:
            with self.assertRaises(remote_proof.RemoteProofError):
                remote_proof.validate_callback(item, earlier)

        contaminated = (response(body=remote_proof.EXPECTED_PRACTICE_FLAG),)
        with self.assertRaises(remote_proof.RemoteProofError):
            remote_proof.validate_callback(valid, contaminated)

    def test_availability_status_is_fatal(self) -> None:
        for status in remote_proof.UNAVAILABLE_STATUSES:
            with self.subTest(status=status):
                with self.assertRaises(remote_proof.FatalRemoteProofError):
                    remote_proof.require_available("test", response(status))

    def test_incomplete_leak_has_a_concise_failure(self) -> None:
        with self.assertRaisesRegex(
            remote_proof.RemoteProofError,
            "address leak could not be resolved",
        ):
            remote_proof.resolve_leak(b"")

    def test_fatal_failure_is_not_retried(self) -> None:
        payloads = mock.MagicMock()
        with mock.patch(
            "remote_proof.PayloadSet.create",
            return_value=payloads,
        ):
            runner = remote_proof.RemoteProofRunner(
                remote_proof.RemoteProofConfig(20)
            )
        runner.run_attempt = mock.MagicMock(
            side_effect=remote_proof.FatalRemoteProofError("stop")
        )
        with self.assertRaises(remote_proof.FatalRemoteProofError):
            runner.run()
        runner.run_attempt.assert_called_once_with()

    def test_unavailable_seed_stops_before_later_requests(self) -> None:
        payloads = mock.MagicMock()
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.pipeline.return_value = (response(503),)
        with (
            mock.patch(
                "remote_proof.PayloadSet.create",
                return_value=payloads,
            ),
            mock.patch(
                "remote_proof.PersistentHttpClient",
                return_value=client,
            ),
        ):
            runner = remote_proof.RemoteProofRunner(
                remote_proof.RemoteProofConfig(20)
            )
            with self.assertRaises(remote_proof.FatalRemoteProofError):
                runner.run_attempt()
        client.pipeline.assert_called_once()

    def test_configuration_exposes_only_timeout(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(remote_proof.RemoteProofConfig).parameters),
            ("timeout",),
        )


if __name__ == "__main__":
    unittest.main()
