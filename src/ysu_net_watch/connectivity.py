from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

import requests

from .process import sanitized_child_environment, windows_system_executable


PORTAL_HOSTS = {"auth.ysu.edu.cn", "auth1.ysu.edu.cn"}
DEFAULT_PROBES = (
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
)
MAX_PROBE_BODY_BYTES = 1024


class ConnectivityState(str, Enum):
    ONLINE = "online"
    CAPTIVE = "captive"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ConnectivityResult:
    state: ConnectivityState
    reason: str


@dataclass(frozen=True)
class PingResult:
    online: bool
    detail: str


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
        self.session.headers.update({"User-Agent": "YSU-Net-Watch/0.3.0rc1"})

    @staticmethod
    def _windows_ping_path() -> str:
        return windows_system_executable("PING.EXE")

    @staticmethod
    def _return_code_detail(returncode: int) -> str:
        if returncode > 255:
            return f"exit {returncode} (0x{returncode & 0xFFFFFFFF:08X})"
        return f"exit {returncode}"

    def _ping(self) -> PingResult:
        timeout_ms = max(1, int(self.ping_timeout * 1000))
        count = max(1, int(self.ping_count))
        if os.name == "nt":
            command = [
                self._windows_ping_path(), "-n", str(count), "-w",
                str(timeout_ms), self.ping_host,
            ]
        else:
            command = [
                "ping", "-c", str(count), "-W",
                str(max(1, int(self.ping_timeout))), self.ping_host,
            ]
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=(self.ping_timeout * count) + 2,
                check=False,
                env=sanitized_child_environment(),
            )
            return PingResult(
                result.returncode == 0,
                self._return_code_detail(result.returncode),
            )
        except subprocess.TimeoutExpired:
            return PingResult(
                False, f"timeout after {(self.ping_timeout * count) + 2:g}s"
            )
        except OSError as exc:
            error_code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
            suffix = f" {error_code}" if error_code is not None else ""
            return PingResult(False, f"{type(exc).__name__}{suffix}")

    def check(self) -> ConnectivityResult:
        ping = self._ping()
        if ping.online:
            return ConnectivityResult(
                ConnectivityState.ONLINE, f"ping succeeded ({ping.detail})"
            )

        saw_normal_http = False
        errors: list[str] = []
        for probe in self.probes:
            try:
                response = self.session.get(
                    probe,
                    allow_redirects=False,
                    timeout=self.http_timeout,
                    stream=True,
                )
            except requests.RequestException as exc:
                errors.append(type(exc).__name__)
                continue

            try:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("Location", "")
                    hostname = (
                        urlparse(urljoin_safe(probe, location)).hostname or ""
                    ).lower()
                    if hostname in PORTAL_HOSTS:
                        return ConnectivityResult(
                            ConnectivityState.CAPTIVE,
                            f"ping failed ({ping.detail}) and HTTP was redirected to {hostname}",
                        )
                elif self._is_expected_online_response(probe, response):
                    saw_normal_http = True
            except requests.RequestException as exc:
                # Streaming can fail after the response headers were received.
                errors.append(type(exc).__name__)
            finally:
                response.close()

        if saw_normal_http:
            return ConnectivityResult(ConnectivityState.ONLINE, "HTTP probe returned normally")
        detail = ", ".join(errors) if errors else "no matching portal redirect"
        return ConnectivityResult(
            ConnectivityState.UNKNOWN,
            f"ping failed ({ping.detail}) but captive portal was not confirmed ({detail})",
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
                and ConnectivityChecker._limited_response_text(response)
                == "Microsoft Connect Test"
            )
        # A custom probe is safe by default only when it uses the conventional
        # unambiguous 204 response. An arbitrary 200 could be a portal login page.
        return response.status_code == 204

    @staticmethod
    def _limited_response_text(response: requests.Response) -> str | None:
        body = bytearray()
        for chunk in response.iter_content(chunk_size=256):
            if not chunk:
                continue
            if len(body) + len(chunk) > MAX_PROBE_BODY_BYTES:
                return None
            body.extend(chunk)
        encoding = response.encoding or "utf-8"
        return bytes(body).decode(encoding, errors="replace").strip()


def urljoin_safe(base: str, location: str) -> str:
    from urllib.parse import urljoin

    return urljoin(base, location)
