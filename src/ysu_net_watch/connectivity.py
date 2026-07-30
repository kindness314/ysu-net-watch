from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

import requests


PORTAL_HOSTS = {"auth.ysu.edu.cn", "auth1.ysu.edu.cn"}
DEFAULT_PROBES = (
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
)


class ConnectivityState(str, Enum):
    ONLINE = "online"
    CAPTIVE = "captive"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ConnectivityResult:
    state: ConnectivityState
    reason: str


class ConnectivityChecker:
    def __init__(
        self,
        ping_host: str = "baidu.com",
        ping_count: int = 3,
        ping_timeout: float = 2.0,
        probes: tuple[str, ...] = DEFAULT_PROBES,
        http_timeout: tuple[float, float] = (3.0, 8.0),
    ):
        self.ping_host = ping_host
        self.ping_count = ping_count
        self.ping_timeout = ping_timeout
        self.probes = probes
        self.http_timeout = http_timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": "YSU-Net-Watch/0.2.0"})

    def _ping_once(self) -> bool:
        timeout_ms = max(1, int(self.ping_timeout * 1000))
        if os.name == "nt":
            command = ["ping", "-n", "1", "-w", str(timeout_ms), self.ping_host]
        else:
            command = ["ping", "-c", "1", "-W", str(max(1, int(self.ping_timeout))), self.ping_host]
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.ping_timeout + 2,
                check=False,
            )
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def check(self) -> ConnectivityResult:
        ping_results = [self._ping_once() for _ in range(self.ping_count)]
        if any(ping_results):
            return ConnectivityResult(ConnectivityState.ONLINE, "at least one ping succeeded")

        saw_normal_http = False
        errors: list[str] = []
        for probe in self.probes:
            try:
                response = self.session.get(
                    probe, allow_redirects=False, timeout=self.http_timeout
                )
            except requests.RequestException as exc:
                errors.append(type(exc).__name__)
                continue

            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("Location", "")
                hostname = (urlparse(urljoin_safe(probe, location)).hostname or "").lower()
                if hostname in PORTAL_HOSTS:
                    return ConnectivityResult(
                        ConnectivityState.CAPTIVE,
                        f"all pings failed and HTTP was redirected to {hostname}",
                    )
            elif self._is_expected_online_response(probe, response):
                saw_normal_http = True

        if saw_normal_http:
            return ConnectivityResult(ConnectivityState.ONLINE, "HTTP probe returned normally")
        detail = ", ".join(errors) if errors else "no matching portal redirect"
        return ConnectivityResult(
            ConnectivityState.UNKNOWN,
            f"all pings failed but captive portal was not confirmed ({detail})",
        )

    @staticmethod
    def _is_expected_online_response(
        probe: str, response: requests.Response
    ) -> bool:
        """Only accept the documented response of a known connectivity probe."""
        host = (urlparse(probe).hostname or "").lower()
        path = urlparse(probe).path
        if host == "connectivitycheck.gstatic.com" and path == "/generate_204":
            return response.status_code == 204
        if host == "www.msftconnecttest.com" and path == "/connecttest.txt":
            return (
                response.status_code == 200
                and response.text.strip() == "Microsoft Connect Test"
            )
        # A custom probe is safe by default only when it uses the conventional
        # unambiguous 204 response. An arbitrary 200 could be a portal login page.
        return response.status_code == 204


def urljoin_safe(base: str, location: str) -> str:
    from urllib.parse import urljoin

    return urljoin(base, location)
