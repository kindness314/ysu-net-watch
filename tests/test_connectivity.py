from __future__ import annotations

import unittest
from unittest.mock import Mock

import requests

from ysu_net_watch.connectivity import (
    ConnectivityChecker,
    ConnectivityState,
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
    result.encoding = "utf-8"
    if location is not None:
        result.headers["Location"] = location
    return result


class ConnectivityCheckerTests(unittest.TestCase):
    def checker(self, ping_results: list[bool]) -> ConnectivityChecker:
        checker = ConnectivityChecker(probes=("http://probe.example/check",))
        checker._ping_once = Mock(side_effect=ping_results)
        return checker

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
        checker._ping_once = Mock(side_effect=[False, False, False])
        checker.session.get = Mock(
            return_value=response(
                200,
                url="http://www.msftconnecttest.com/connecttest.txt",
                body="Microsoft Connect Test",
            )
        )

        result = checker.check()

        self.assertEqual(result.state, ConnectivityState.ONLINE)


if __name__ == "__main__":
    unittest.main()
