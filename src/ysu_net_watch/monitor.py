from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .connectivity import ConnectivityChecker, ConnectivityState
from .credentials import CredentialError, CredentialSource
from .portal import PortalClient, PortalError


EXIT_OK = 0
EXIT_MISSING_CREDENTIALS = 10
EXIT_AUTH_FAILED = 20
EXIT_PROTOCOL_CHANGED = 30
EXIT_WIFI_FAILED = 40


def sanitize_text(value: str, secrets: tuple[str, ...] = ()) -> str:
    clean = value
    for secret in secrets:
        if secret:
            clean = clean.replace(secret, "<REDACTED>")
    clean = re.sub(
        r"""(?ix)
        (["']?(?:ticket|token|sessionId|password|cookie|authorization)["']?)
        \s*[:=]\s*
        (["']?)[^&\s,"'}]+\2
        """,
        r"\1=<REDACTED>",
        clean,
    )
    clean = re.sub(
        r"(?i)(终端IP|clientIp|userIp)\s*[（(:：=]\s*"
        r"(?:\d{1,3}\.){3}\d{1,3}\)?",
        r"\1=<REDACTED>",
        clean,
    )
    clean = re.sub(
        r"(?i)(终端MAC|clientMac|userMac|mac)\s*[（(:：=]\s*"
        r"(?:[0-9a-f]{2}[:-]?){5}[0-9a-f]{2}\)?",
        r"\1=<REDACTED>",
        clean,
    )
    return clean[:500]


@dataclass(frozen=True)
class WatchSettings:
    mode: str
    service: str
    check_interval: float = 60.0
    confirmation_delay: float = 120.0
    retry_delays: tuple[float, ...] = (5.0, 10.0, 20.0, 40.0, 60.0)

    @property
    def max_attempts(self) -> int:
        return len(self.retry_delays)


class JsonEventLog:
    def __init__(self, path: Path, max_bytes: int = 1_000_000):
        self.path = path
        self.max_bytes = max_bytes
        self._lock = threading.Lock()

    @staticmethod
    def _sanitize(value: str, secrets: tuple[str, ...] = ()) -> str:
        return sanitize_text(value, secrets)

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        if self.max_bytes <= 0 or not self.path.exists():
            return
        if self.path.stat().st_size + incoming_bytes <= self.max_bytes:
            return
        backup = self.path.with_name(f"{self.path.name}.1")
        if backup.exists():
            backup.unlink()
        self.path.replace(backup)

    def write(self, event: str, *, secrets: tuple[str, ...] = (), **fields) -> None:
        record = {
            "time": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "event": event,
        }
        for key, value in fields.items():
            record[key] = self._sanitize(str(value), secrets) if isinstance(value, str) else value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        encoded_size = len((line + "\n").encode("utf-8"))
        with self._lock:
            self._rotate_if_needed(encoded_size)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


class Watcher:
    def __init__(
        self,
        settings: WatchSettings,
        checker: ConnectivityChecker,
        credentials: CredentialSource,
        portal_factory: Callable[[], PortalClient],
        event_log: JsonEventLog,
        stop_event: threading.Event | None = None,
        sleeper: Callable[[float], None] | None = None,
        reporter: Callable[[str], None] = print,
        expected_network: Callable[[], bool] | None = None,
    ):
        self.settings = settings
        self.checker = checker
        self.credentials = credentials
        self.portal_factory = portal_factory
        self.event_log = event_log
        self.stop_event = stop_event or threading.Event()
        self.sleeper = sleeper or self._interruptible_sleep
        self.reporter = reporter
        self.expected_network = expected_network or (lambda: True)

    def _interruptible_sleep(self, seconds: float) -> None:
        self.stop_event.wait(seconds)

    def _on_expected_network(self) -> bool:
        try:
            return bool(self.expected_network())
        except Exception as exc:
            self.event_log.write(
                "network_guard_failed",
                category=type(exc).__name__,
                reason=str(exc),
            )
            return False

    def _portal_confirms_offline(self) -> bool:
        """Confirm a failed public probe without ever loading credentials."""
        if not self._on_expected_network():
            self.event_log.write(
                "portal_confirmation_skipped",
                reason="current Wi-Fi is not the configured campus network",
            )
            self.reporter("当前已不在 iYanDa，不执行校园网认证。")
            return False
        try:
            status = self.portal_factory().status()
        except (PortalError, AttributeError) as exc:
            self.event_log.write(
                "portal_confirmation_failed",
                category=getattr(exc, "category", type(exc).__name__),
                reason=str(exc),
            )
            return False
        self.event_log.write(
            "portal_status_confirmation",
            online=status.online,
        )
        return not status.online

    def _is_confirmed_captive(self, result) -> bool:
        if result.state == ConnectivityState.CAPTIVE:
            return self._on_expected_network()
        if result.state == ConnectivityState.UNKNOWN:
            return self._portal_confirms_offline()
        return False

    def _authenticate(self) -> int:
        try:
            credential = self.credentials.get()
        except CredentialError as exc:
            self.event_log.write(
                "fatal",
                mode=self.settings.mode,
                category="missing_credentials",
                reason=str(exc),
            )
            self.reporter(f"缺少凭据：{exc}")
            return EXIT_MISSING_CREDENTIALS

        secrets = (credential.username, credential.password)
        for attempt in range(1, self.settings.max_attempts + 1):
            try:
                self.portal_factory().login(
                    credential.username, credential.password, self.settings.service
                )
                verification = self.checker.check()
                if verification.state != ConnectivityState.ONLINE:
                    raise PortalError(
                        "verification_failed",
                        "internet_probe",
                        verification.reason,
                    )
                self.event_log.write(
                    "authentication_succeeded",
                    mode=self.settings.mode,
                    service=self.settings.service,
                    attempt=attempt,
                    username=credential.masked_username,
                )
                self.reporter("认证成功，互联网连接已恢复。")
                return EXIT_OK
            except PortalError as exc:
                self.event_log.write(
                    "authentication_failed",
                    secrets=secrets,
                    mode=self.settings.mode,
                    service=self.settings.service,
                    attempt=attempt,
                    stage=exc.stage,
                    category=exc.category,
                    http_status=exc.http_status,
                    reason=str(exc),
                )
                safe_reason = sanitize_text(str(exc), secrets)
                self.reporter(
                    f"认证失败（{attempt}/{self.settings.max_attempts}）："
                    f"{safe_reason}"
                )
                if exc.category == "protocol_changed":
                    self.event_log.write(
                        "fatal",
                        mode=self.settings.mode,
                        service=self.settings.service,
                        attempts=attempt,
                        category="protocol_changed",
                        reason="authentication portal protocol changed",
                    )
                    return EXIT_PROTOCOL_CHANGED
                if attempt < self.settings.max_attempts:
                    self.sleeper(self.settings.retry_delays[attempt - 1])
                    if self.stop_event.is_set():
                        return EXIT_OK

        self.event_log.write(
            "fatal",
            mode=self.settings.mode,
            service=self.settings.service,
            attempts=self.settings.max_attempts,
            category="authentication_failed",
            reason="maximum authentication attempts reached",
        )
        return EXIT_AUTH_FAILED

    def run(self, once: bool = False, authenticate_on_start: bool = False) -> int:
        self.event_log.write(
            "watch_started", mode=self.settings.mode, service=self.settings.service
        )
        if authenticate_on_start:
            if not self._on_expected_network():
                self.event_log.write(
                    "startup_authentication_skipped",
                    mode=self.settings.mode,
                    reason="current Wi-Fi is not the configured campus network",
                )
                self.reporter("未确认当前连接 iYanDa，跳过首次认证。")
                authenticate_on_start = False
        if authenticate_on_start:
            self.event_log.write(
                "startup_authentication",
                mode=self.settings.mode,
                service=self.settings.service,
            )
            result_code = self._authenticate()
            if result_code != EXIT_OK:
                return result_code

        while not self.stop_event.is_set():
            result = self.checker.check()
            self.event_log.write("connectivity_check", state=result.state.value, reason=result.reason)

            if self._is_confirmed_captive(result):
                self.reporter(
                    f"检测到疑似认证掉线，"
                    f"{self.settings.confirmation_delay:g} 秒后复核。"
                )
                self.sleeper(self.settings.confirmation_delay)
                if self.stop_event.is_set():
                    break
                confirmation = self.checker.check()
                self.event_log.write(
                    "connectivity_confirmation",
                    state=confirmation.state.value,
                    reason=confirmation.reason,
                )
                if self._is_confirmed_captive(confirmation):
                    result_code = self._authenticate()
                    if result_code != EXIT_OK:
                        return result_code
                else:
                    self.reporter("复核时网络已恢复，不执行认证。")
            elif result.state == ConnectivityState.UNKNOWN:
                self.reporter(
                    "网络探测异常：Ping 失败，但校园网门户未确认掉线；稍后重试。"
                )

            if once:
                break
            self.sleeper(self.settings.check_interval)

        self.event_log.write("watch_stopped", mode=self.settings.mode)
        return EXIT_OK
