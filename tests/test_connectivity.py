from __future__ import annotations

import subprocess
import unittest
from unittest.mock import Mock, patch

import requests

from ysu_net_watch.connectivity import (
    ConnectivityChecker,
    ConnectivityState,
    PingResult,
)


def response(
    status: int,
    *,
    url: str,
    location: str | None = None,
    body: str = "",
) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result.url = url
    result._content = body.encode()
    result._content_consumed = True
    result.encoding = "utf-8"
    if location is not None:
        result.headers["Location"] = location
    return result


class ConnectivityCheckerTests(unittest.TestCase):
    def test_stream_failure_is_unknown_and_response_is_closed(self) -> None:
        checker = ConnectivityChecker(
            probes=("http://www.msftconnecttest.com/connecttest.txt",),
        )
        checker._ping = Mock(return_value=PingResult(False, "test result"))
        reply = Mock(status_code=200)
        reply.iter_content.side_effect = requests.ConnectionError("read interrupted")
        checker.session.get = Mock(return_value=reply)
        result = checker.check()
        self.assertEqual(result.state, ConnectivityState.UNKNOWN)
        self.assertIn("ConnectionError", result.reason)
        reply.close.assert_called_once()

    def checker(self, ping_results: list[bool]) -> ConnectivityChecker:
        checker = ConnectivityChecker(probes=("http://probe.example/check",))
        checker._ping = Mock(
            return_value=PingResult(any(ping_results), "test result")
        )
        return checker

    @patch("ysu_net_watch.connectivity.subprocess.run")
    def test_three_pings_use_one_process(self, run: Mock) -> None:
        run.return_value = subprocess.CompletedProcess([], 0)
        checker = ConnectivityChecker(ping_count=3, probes=())

        result = checker.check()

        self.assertEqual(result.state, ConnectivityState.ONLINE)
        run.assert_called_once()
        self.assertIn("3", run.call_args.args[0])

    @patch("ysu_net_watch.connectivity.subprocess.run")
    def test_ping_timeout_is_in_diagnostic_reason(self, run: Mock) -> None:
        run.side_effect = subprocess.TimeoutExpired(["ping"], 8)
        checker = ConnectivityChecker(ping_count=3, ping_timeout=2, probes=())

        result = checker.check()

        self.assertEqual(result.state, ConnectivityState.UNKNOWN)
        self.assertIn("timeout after 8s", result.reason)

    @patch.dict(
        "os.environ",
        {
            "YSU_CAMPUS_USERNAME": "student",
            "ysu_campus_password": "secret",
        },
    )
    @patch("ysu_net_watch.connectivity.subprocess.run")
    def test_ping_child_environment_excludes_credentials(self, run: Mock) -> None:
        run.return_value = subprocess.CompletedProcess([], 0)

        ConnectivityChecker(probes=()).check()

        child_env = run.call_args.kwargs["env"]
        self.assertNotIn("YSU_CAMPUS_USERNAME", child_env)
        self.assertNotIn("ysu_campus_password", child_env)

    def test_any_successful_ping_is_online(self) -> None:
        checker = self.checker([False, True, False])
        checker.session.get = Mock()

        result = checker.check()

        self.assertEqual(result.state, ConnectivityState.ONLINE)
        checker.session.get.assert_not_called()

    def test_portal_redirect_is_captive(self) -> None:
        checker = self.checker([False, False, False])
        checker.session.get = Mock(
            return_value=response(
                302,
                url="http://probe.example/check",
                location="https://auth1.ysu.edu.cn/eportal/",
            )
        )

        result = checker.check()

        self.assertEqual(result.state, ConnectivityState.CAPTIVE)

    def test_attacker_suffix_is_not_portal(self) -> None:
        checker = self.checker([False, False, False])
        checker.session.get = Mock(
            return_value=response(
                302,
                url="http://probe.example/check",
                location="https://auth1.ysu.edu.cn.attacker.example/login",
            )
        )

        result = checker.check()

        self.assertEqual(result.state, ConnectivityState.UNKNOWN)

    def test_http_timeout_is_unknown(self) -> None:
        checker = self.checker([False, False, False])
        checker.session.get = Mock(side_effect=requests.Timeout())

        result = checker.check()

        self.assertEqual(result.state, ConnectivityState.UNKNOWN)

    def test_arbitrary_200_is_not_assumed_online(self) -> None:
        checker = self.checker([False, False, False])
        checker.session.get = Mock(
            return_value=response(
                200,
                url="http://probe.example/check",
                body="<html>portal login page</html>",
            )
        )

        result = checker.check()

        self.assertEqual(result.state, ConnectivityState.UNKNOWN)

    def test_known_msft_response_is_online(self) -> None:
        checker = ConnectivityChecker(
            probes=("http://www.msftconnecttest.com/connecttest.txt",)
        )
        checker._ping = Mock(return_value=PingResult(False, "test result"))
        checker.session.get = Mock(
            return_value=response(
                200,
                url="http://www.msftconnecttest.com/connecttest.txt",
                body="Microsoft Connect Test",
            )
        )

        result = checker.check()

        self.assertEqual(result.state, ConnectivityState.ONLINE)
        self.assertTrue(checker.session.get.call_args.kwargs["stream"])

    def test_oversized_msft_response_is_rejected(self) -> None:
        checker = ConnectivityChecker(
            probes=("http://www.msftconnecttest.com/connecttest.txt",)
        )
        checker._ping = Mock(return_value=PingResult(False, "test result"))
        checker.session.get = Mock(
            return_value=response(
                200,
                url="http://www.msftconnecttest.com/connecttest.txt",
                body="A" * 1025,
            )
        )

        result = checker.check()

        self.assertEqual(result.state, ConnectivityState.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
