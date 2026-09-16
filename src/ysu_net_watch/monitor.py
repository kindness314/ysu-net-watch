from __future__ import annotations

import json
import math
import os
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
from .recovery import RecoveryState


EXIT_OK = 0
EXIT_MISSING_CREDENTIALS = 10
EXIT_AUTH_FAILED = 20
EXIT_NETWORK_UNCONFIRMED = 21
EXIT_PLANNED_PAUSE = 22
EXIT_CREDENTIAL_REJECTED = 23
EXIT_PROTOCOL_CHANGED = 30
EXIT_WIFI_FAILED = 40
EXIT_ACCOUNT_LIMIT = 24
EXIT_VERIFY_SKIPPED = 25
EXIT_IP_BLOCKED = 26
MAX_AUTH_ATTEMPTS = 5

EXIT_CODE_MESSAGES = {
    EXIT_OK: "正常结束或认证成功",
    EXIT_MISSING_CREDENTIALS: "缺少凭据或账号设置无效",
    EXIT_AUTH_FAILED: "暂时性认证失败达到最大次数",
    EXIT_NETWORK_UNCONFIRMED: "网络状态暂未确认，等待后续恢复",
    EXIT_PLANNED_PAUSE: "处于计划停网时段，等待定时恢复",
    EXIT_CREDENTIAL_REJECTED: "账号或密码被门户拒绝，已停止重试",
    EXIT_ACCOUNT_LIMIT: "账号在线设备数达到限制，已停止重试",
    EXIT_VERIFY_SKIPPED: "当前已有在线会话，未提交试验账号凭据",
    EXIT_IP_BLOCKED: "认证来源 IP 被门户冻结或封禁，已停止重试",
    EXIT_PROTOCOL_CHANGED: "认证门户协议发生变化，已停止提交",
    EXIT_WIFI_FAILED: "无法连接或配置指定 Wi-Fi",
}


def exit_code_text(code: int) -> str:
    """Return a stable Chinese explanation for a process exit code."""
    message = EXIT_CODE_MESSAGES.get(code, "未知退出状态")
    return f"退出码 {code}（{message}）"


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
        r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
        "<REDACTED-IP>",
        clean,
    )
    clean = re.sub(
        r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])"
        r"|(?<![0-9a-f])[0-9a-f]{12}(?![0-9a-f])",
        "<REDACTED-MAC>",
        clean,
    )
    clean = re.sub(
        r"(?i)(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])",
        "<REDACTED-EMAIL>",
        clean,
    )
    clean = re.sub(
        r"(?<!\d)1[3-9]\d{9}(?!\d)",
        "<REDACTED-PHONE>",
        clean,
    )
    # Portal/Wi-Fi diagnostics originate outside the process.  Strip terminal
    # control sequences and remaining C0/C1 controls before a message can be
    # printed or written to a log.  JSON encoding protects the log file's
    # syntax, but it does not protect an interactive terminal from ANSI/OSC
    # escape sequences (or newline injection).
    clean = re.sub(
        r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))",
        "",
        clean,
    )
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", clean)
    return clean[:500]


def default_log_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "YSUNetWatch" / "logs" / "ysu-net-watch.log"
    return Path.home() / ".ysu-net-watch" / "logs" / "ysu-net-watch.log"


@dataclass(frozen=True)
class WatchSettings:
    mode: str
    service: str
    check_interval: float = 60.0
    confirmation_delay: float = 120.0
    retry_delays: tuple[float, ...] = (5.0, 10.0, 20.0, 40.0, 60.0)
    verification_delays: tuple[float, ...] = (3.0, 5.0)

    def __post_init__(self) -> None:
        if not 1 <= len(self.retry_delays) <= MAX_AUTH_ATTEMPTS:
            raise ValueError(
                f"retry_delays must contain between 1 and {MAX_AUTH_ATTEMPTS} entries"
            )
        if any(
            not isinstance(delay, (int, float))
            or isinstance(delay, bool)
            or not math.isfinite(delay)
            or delay < 0
            for delay in (*self.retry_delays, *self.verification_delays)
        ):
            raise ValueError("authentication delays must be finite non-negative numbers")

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
            "pid": os.getpid(),
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


class ResilientEventLog:
    """Keep monitoring alive when the optional local audit log is unavailable."""

    def __init__(
        self,
        inner: JsonEventLog,
        reporter: Callable[[str], None] = print,
    ):
        self.inner = inner
        self.reporter = reporter
        self.last_error: OSError | None = None
        self._reported = False

    def write(self, event: str, *, secrets: tuple[str, ...] = (), **fields) -> None:
        try:
            self.inner.write(event, secrets=secrets, **fields)
            self.last_error = None
            self._reported = False
        except OSError as exc:
            self.last_error = exc
            if not self._reported:
                self._reported = True
                self.reporter(
                    f"日志暂不可写（{type(exc).__name__}），监听与认证继续运行。"
                )


class Watcher:
    def __init__(
        self,
        settings: WatchSettings,
        checker: ConnectivityChecker,
        credentials: CredentialSource,
        portal_factory: Callable[[], PortalClient],
        event_log: JsonEventLog | ResilientEventLog,
        stop_event: threading.Event | None = None,
        sleeper: Callable[[float], None] | None = None,
        reporter: Callable[[str], None] = print,
        expected_network: Callable[[], bool] | None = None,
        pause_reason: Callable[[], str | None] | None = None,
        on_resume: Callable[[], None] | None = None,
        force_switch: bool = False,
        profile_id: str | None = None,
    ):
        self.settings = settings
        self.checker = checker
        self.credentials = credentials
        self.portal_factory = portal_factory
        self.event_log = (
            event_log
            if isinstance(event_log, ResilientEventLog)
            else ResilientEventLog(event_log, reporter)
        )
        self.stop_event = stop_event or threading.Event()
        self.sleeper = sleeper or self._interruptible_sleep
        self.reporter = reporter
        self.expected_network = expected_network or (lambda: True)
        self._network_was_pending = False
        self.pause_reason = pause_reason or (lambda: None)
        self.on_resume = on_resume or (lambda: None)
        self._pause_message: str | None = None
        self._resume_pending = False
        self._switch_pending = force_switch
        self.profile_id = profile_id
        self.recovery = RecoveryState()
        self._last_failure: tuple[str, str, str] | None = None

    def _reset_recovery(self) -> None:
        self.recovery.reset()
        self._last_failure = None

    def _planned_pause(self) -> bool:
        reason = self.pause_reason()
        if not reason:
            return False
        if reason != self._pause_message:
            self._pause_message = reason
            self.event_log.write("planned_pause", reason=reason, profile_id=self.profile_id)
            self.reporter(reason)
        return True

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
        if self._planned_pause():
            return False
        if result.state == ConnectivityState.CAPTIVE:
            return self._on_expected_network()
        if result.state == ConnectivityState.UNKNOWN:
            return self._portal_confirms_offline()
        return False

    def _authentication_allowed(self) -> bool:
        return not self.stop_event.is_set() and not self._planned_pause() and self._on_expected_network()

    def _network_pending(self, reason: str, *, secrets=()) -> int:
        if self.stop_event.is_set():
            return EXIT_OK
        if self._planned_pause():
            return EXIT_PLANNED_PAUSE
        self._network_was_pending = True
        self.event_log.write(
            "network_pending", mode=self.settings.mode, service=self.settings.service,
            reason=reason, secrets=secrets,
        )
        self.reporter(
            f"网络待恢复，不累计认证失败：{sanitize_text(reason, secrets)}；继续监听。"
        )
        return EXIT_NETWORK_UNCONFIRMED

    def _verify_internet(self, portal, credential, attempt: int, submitted) -> int:
        secrets = (credential.username, credential.password)
        for delay in (0.0, *self.settings.verification_delays):
            if delay:
                self.sleeper(delay)
            if not self._authentication_allowed():
                return self._network_pending("认证已停止或当前已不在 iYanDa")
            verification = self.checker.check()
            if not self._authentication_allowed():
                return self._network_pending("认证已停止或当前已不在 iYanDa")
            self.event_log.write(
                "internet_verification", state=verification.state.value,
                reason=verification.reason, secrets=secrets,
            )
            if verification.state == ConnectivityState.ONLINE:
                self._reset_recovery()
                self._network_was_pending = False
                self.event_log.write(
                    "authentication_succeeded" if submitted is not False else "portal_already_online",
                    mode=self.settings.mode, service=self.settings.service,
                    attempt=attempt, profile_id=self.profile_id,
                )
                self.reporter(
                    "认证成功，互联网连接已恢复。"
                    if submitted is not False else "门户已在线，互联网连接正常。"
                )
                if self.profile_id and submitted is not False:
                    self.reporter("已提交所选账号，门户已在线；门户身份字段尚未独立核验。")
                return EXIT_OK

        # Public probes cannot tell whether the account was rejected. Only an
        # explicit offline portal state consumes another authentication attempt.
        try:
            status = portal.status()
        except PortalError as exc:
            if exc.category == "protocol_changed":
                raise
            if exc.category in {
                "ip_blocked", "account_locked", "credential_rejected",
                "account_device_limit",
            }:
                # An explicit account/source restriction in the portal status
                # response is terminal evidence, not a transient probe outage.
                raise
            return self._network_pending(
                f"外网未确认，门户复核 [{exc.stage}/{exc.category}]：{exc}",
                secrets=secrets,
            )
        if not status.online:
            raise PortalError(
                "verification_failed", "verify_login",
                "portal confirmed offline after authentication and recovery checks",
            )
        self._reset_recovery()
        return self._network_pending("门户已在线，但外网探测尚未通过", secrets=secrets)

    def _authenticate(self) -> int:
        secrets: tuple[str, ...] = ()
        while self.recovery.failures < self.settings.max_attempts:
            attempt = self.recovery.failures + 1
            if not self._authentication_allowed():
                return self._network_pending("认证已停止或当前已不在 iYanDa")
            # A changed Windows credential takes effect at the next attempt.
            try:
                credential = self.credentials.get()
            except CredentialError as exc:
                self.event_log.write(
                    "fatal", mode=self.settings.mode,
                    category="missing_credentials", reason=str(exc),
                )
                self.reporter(f"缺少凭据：{sanitize_text(str(exc))}")
                return EXIT_MISSING_CREDENTIALS
            secrets = (credential.username, credential.password)
            try:
                portal = self.portal_factory()
                if self._switch_pending:
                    submitted = portal.login(
                        credential.username, credential.password, self.settings.service,
                        force_switch=True,
                        recovery=self.recovery,
                    )
                else:
                    submitted = portal.login(
                        credential.username, credential.password, self.settings.service,
                        recovery=self.recovery,
                    )
                self._switch_pending = False
                self.event_log.write(
                    "portal_login_accepted" if submitted is not False else "portal_session_reused",
                    mode=self.settings.mode,
                    service=self.settings.service,
                    attempt=attempt,
                    profile_id=self.profile_id,
                )
                return self._verify_internet(portal, credential, attempt, submitted)
            except PortalError as exc:
                # A request can have started before 23:30 and completed after it.
                # Check the clock again before charging a failure or kicking/retrying.
                if self.stop_event.is_set():
                    return EXIT_OK
                if self._planned_pause():
                    return EXIT_PLANNED_PAUSE
                if exc.category in {"timeout", "network_error", "operation_cancelled"}:
                    return self._network_pending(
                        f"[{exc.stage}/{exc.category}]：{exc}", secrets=secrets,
                    )
                self.recovery.failures += 1
                self._last_failure = (exc.stage, exc.category, sanitize_text(str(exc), secrets))
                self.event_log.write(
                    "authentication_failed",
                    secrets=secrets,
                    mode=self.settings.mode,
                    service=self.settings.service,
                    attempt=attempt,
                    profile_id=self.profile_id,
                    stage=exc.stage,
                    category=exc.category,
                    http_status=exc.http_status,
                    reason=str(exc),
                )
                safe_reason = sanitize_text(str(exc), secrets)
                if exc.category in {
                    "ip_blocked", "credential_rejected", "account_locked",
                    "account_device_limit",
                }:
                    label = (
                        "认证来源 IP 已被门户冻结或封禁"
                        if exc.category == "ip_blocked"
                        else
                        "账号已被门户冻结或锁定"
                        if exc.category == "account_locked"
                        else "账号或密码被门户拒绝"
                        if exc.category == "credential_rejected"
                        else "账号在线设备数达到限制"
                    )
                    self.reporter(
                        f"{label}，已停止且不会重试："
                        f"[{exc.stage}/{exc.category}] {safe_reason}"
                    )
                    self.event_log.write(
                        "fatal",
                        mode=self.settings.mode,
                        service=self.settings.service,
                        attempts=attempt,
                        category=exc.category,
                        reason="portal rejected credentials or account state; retries disabled",
                    )
                    # A confirmed bad password, locked account, source-IP
                    # block, or device limit must never enter the ordinary
                    # retry/compensation path. The scheduler treats these
                    # outcomes as consumed for the day, so the same unsafe
                    # credentials/source is not submitted again at the
                    # configured compensation time.
                    return (
                        EXIT_ACCOUNT_LIMIT
                        if exc.category == "account_device_limit"
                        else EXIT_IP_BLOCKED
                        if exc.category == "ip_blocked"
                        else EXIT_CREDENTIAL_REJECTED
                    )
                if exc.category in {"protocol_changed", "unsafe_redirect"}:
                    self.reporter(
                        "认证安全检查未通过，已停止："
                        f"[{exc.stage}/{exc.category}] {safe_reason}"
                    )
                    self.event_log.write(
                        "fatal",
                        mode=self.settings.mode,
                        service=self.settings.service,
                        attempts=attempt,
                        category=exc.category,
                        reason="authentication portal protocol or redirect changed",
                    )
                    return EXIT_PROTOCOL_CHANGED
                self.reporter(
                    f"认证失败（{attempt}/{self.settings.max_attempts}）："
                    f"[{exc.stage}/{exc.category}] {safe_reason}"
                )
                if attempt < self.settings.max_attempts:
                    self.sleeper(self.settings.retry_delays[attempt - 1])
                    if self.stop_event.is_set():
                        return EXIT_OK

        self.event_log.write(
            "fatal",
            secrets=secrets,
            mode=self.settings.mode,
            service=self.settings.service,
            attempts=self.settings.max_attempts,
            profile_id=self.profile_id,
            category="authentication_failed",
            stage=self._last_failure[0] if self._last_failure else None,
            failure_category=self._last_failure[1] if self._last_failure else None,
            reason=self._last_failure[2] if self._last_failure else "maximum authentication attempts reached",
        )
        return EXIT_AUTH_FAILED

    def run(self, once: bool = False, authenticate_on_start: bool = False) -> int:
        self.event_log.write(
            "watch_started", mode=self.settings.mode, service=self.settings.service,
            profile_id=self.profile_id,
        )
        while not self.stop_event.is_set():
            if self._planned_pause():
                if once:
                    return EXIT_PLANNED_PAUSE
                self.sleeper(min(15.0, max(1.0, self.settings.check_interval)))
                continue
            if self._pause_message:
                self._pause_message = None
                self.reporter("计划停网时段结束，恢复监听。")
                self._resume_pending = True
            if self._resume_pending:
                try:
                    self.on_resume()
                except Exception as exc:
                    self.event_log.write("resume_network_failed", category=type(exc).__name__)
                    self.reporter("暂时无法恢复校园 Wi-Fi，稍后继续检测。")
                    if once:
                        return EXIT_NETWORK_UNCONFIRMED
                    self.sleeper(max(1.0, self.settings.check_interval))
                    continue
                self._resume_pending = False
                # The morning window is a new recovery episode, unlike a timeout.
                self._reset_recovery()
                authenticate_on_start = True
            if authenticate_on_start:
                authenticate_on_start = False
                if not self._on_expected_network():
                    self.event_log.write("startup_authentication_skipped", mode=self.settings.mode)
                    self.reporter("未确认当前连接 iYanDa，跳过首次认证。")
                else:
                    self.event_log.write("startup_authentication", mode=self.settings.mode,
                                         service=self.settings.service)
                    result_code = self._authenticate()
                    if result_code in {EXIT_NETWORK_UNCONFIRMED, EXIT_PLANNED_PAUSE} and once:
                        return result_code
                    if result_code not in {EXIT_OK, EXIT_NETWORK_UNCONFIRMED, EXIT_PLANNED_PAUSE}:
                        return result_code
                    if result_code == EXIT_PLANNED_PAUSE:
                        continue
            if self.stop_event.is_set():
                break
            result = self.checker.check()
            self.event_log.write("connectivity_check", state=result.state.value, reason=result.reason)
            if (result.state == ConnectivityState.ONLINE
                    and (self.recovery.failures or self.recovery.device_release_attempted)
                    and not self._switch_pending
                    and not self._planned_pause() and self._on_expected_network()):
                self._reset_recovery()
            if result.state == ConnectivityState.ONLINE and self._network_was_pending:
                self._network_was_pending = False
                self.event_log.write("internet_recovered", mode=self.settings.mode)
                self.reporter("互联网连接已恢复，继续监听。")

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
                    if result_code in {EXIT_NETWORK_UNCONFIRMED, EXIT_PLANNED_PAUSE} and once:
                        return result_code
                    if result_code not in {EXIT_OK, EXIT_NETWORK_UNCONFIRMED, EXIT_PLANNED_PAUSE}:
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
