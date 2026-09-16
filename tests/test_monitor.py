from __future__ import annotations

import json
import io
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from ysu_net_watch.connectivity import ConnectivityResult, ConnectivityState
from ysu_net_watch.credentials import Credential, CredentialError
from ysu_net_watch.monitor import (
    EXIT_ACCOUNT_LIMIT,
    EXIT_AUTH_FAILED,
    EXIT_CREDENTIAL_REJECTED,
    EXIT_IP_BLOCKED,
    EXIT_MISSING_CREDENTIALS,
    EXIT_NETWORK_UNCONFIRMED,
    EXIT_OK,
    EXIT_PROTOCOL_CHANGED,
    JsonEventLog,
    Watcher,
    WatchSettings,
)
from ysu_net_watch.portal import PortalError


def result(state: ConnectivityState) -> ConnectivityResult:
    return ConnectivityResult(state, f"test {state.value}")


class SequenceChecker:
    def __init__(self, *states: ConnectivityState):
        self.results = iter(result(state) for state in states)

    def check(self) -> ConnectivityResult:
        return next(self.results)


class StaticCredentials:
    def __init__(self, value: Credential | Exception):
        self.value = value
        self.calls = 0

    def get(self) -> Credential:
        self.calls += 1
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class PortalFactory:
    def __init__(self, failures: list[PortalError | None]):
        self.failures = iter(failures)
        self.calls = 0

    def __call__(self):
        factory = self

        class Client:
            def login(self, _username: str, _password: str, _service: str, **_kwargs) -> None:
                factory.calls += 1
                failure = next(factory.failures)
                if failure is not None:
                    raise failure

        return Client()


class OfflinePortalFactory:
    def __init__(self):
        self.status_calls = 0
        self.login_calls = 0

    def __call__(self):
        factory = self

        class Client:
            def status(self):
                factory.status_calls += 1
                return SimpleNamespace(online=False)

            def login(self, _username: str, _password: str, _service: str, **_kwargs) -> None:
                factory.login_calls += 1

        return Client()


class WatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.log_path = Path(self.tempdir.name) / "events.jsonl"
        self.settings = WatchSettings(
            mode="campus",
            service="校园网",
            check_interval=0,
            confirmation_delay=0,
            retry_delays=(0, 0, 0, 0, 0),
        )
        self.credential = Credential("student42", "super-secret")

    def test_auth_retry_budget_is_bounded_and_nonempty(self) -> None:
        with self.assertRaises(ValueError):
            WatchSettings("campus", "校园网", retry_delays=())
        with self.assertRaises(ValueError):
            WatchSettings("campus", "校园网", retry_delays=(0,) * 6)
        with self.assertRaises(ValueError):
            WatchSettings("campus", "校园网", retry_delays=(float("inf"),))

    def watcher(
        self,
        checker,
        credentials,
        portal_factory,
        *,
        expected_network=lambda: True,
    ) -> Watcher:
        return Watcher(
            settings=self.settings,
            checker=checker,
            credentials=credentials,
            portal_factory=portal_factory,
            event_log=JsonEventLog(self.log_path),
            stop_event=threading.Event(),
            sleeper=lambda _seconds: None,
            expected_network=expected_network,
        )

    def events(self) -> list[dict]:
        return [
            json.loads(line)
            for line in self.log_path.read_text(encoding="utf-8").splitlines()
        ]

    def test_recovery_during_confirmation_does_not_authenticate(self) -> None:
        credentials = StaticCredentials(self.credential)
        portal = PortalFactory([])
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.CAPTIVE, ConnectivityState.ONLINE),
            credentials,
            portal,
        )

        code = watcher.run(once=True)

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(credentials.calls, 0)
        self.assertEqual(portal.calls, 0)

    def test_log_permission_failure_is_reported_once_and_monitor_continues(self) -> None:
        event_log = Mock()
        event_log.write.side_effect = PermissionError("synthetic lock")
        reporter = Mock()
        watcher = Watcher(
            settings=self.settings,
            checker=SequenceChecker(ConnectivityState.ONLINE),
            credentials=StaticCredentials(self.credential),
            portal_factory=PortalFactory([]),
            event_log=event_log,
            stop_event=threading.Event(),
            sleeper=lambda _seconds: None,
            reporter=reporter,
        )
        self.assertEqual(watcher.run(once=True), EXIT_OK)
        warnings = [
            call.args[0] for call in reporter.call_args_list
            if "日志暂不可写" in call.args[0]
        ]
        self.assertEqual(len(warnings), 1)

    def test_log_warning_can_be_reported_again_after_write_recovers(self) -> None:
        event_log = Mock()
        event_log.write.side_effect = [
            PermissionError("first lock"),
            None,
            PermissionError("second lock"),
        ]
        reporter = Mock()
        watcher = Watcher(
            settings=self.settings,
            checker=SequenceChecker(ConnectivityState.ONLINE),
            credentials=StaticCredentials(self.credential),
            portal_factory=PortalFactory([]),
            event_log=event_log,
            reporter=reporter,
        )

        watcher.event_log.write("first")
        watcher.event_log.write("recovered")
        watcher.event_log.write("second")

        warnings = [
            call.args[0] for call in reporter.call_args_list
            if "日志暂不可写" in call.args[0]
        ]
        self.assertEqual(len(warnings), 2)

    def test_confirmed_captive_authenticates_once(self) -> None:
        credentials = StaticCredentials(self.credential)
        portal = PortalFactory([None])
        watcher = self.watcher(
            SequenceChecker(
                ConnectivityState.CAPTIVE,
                ConnectivityState.CAPTIVE,
                ConnectivityState.ONLINE,
            ),
            credentials,
            portal,
        )

        code = watcher.run(once=True)

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(credentials.calls, 1)
        self.assertEqual(portal.calls, 1)

    def test_unknown_public_probe_uses_portal_status_before_authentication(
        self,
    ) -> None:
        credentials = StaticCredentials(self.credential)
        portal = OfflinePortalFactory()
        watcher = self.watcher(
            SequenceChecker(
                ConnectivityState.UNKNOWN,
                ConnectivityState.UNKNOWN,
                ConnectivityState.ONLINE,
            ),
            credentials,
            portal,
        )

        code = watcher.run(once=True)

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(portal.status_calls, 2)
        self.assertEqual(portal.login_calls, 1)
        self.assertEqual(credentials.calls, 1)

    def test_unknown_probe_never_authenticates_after_leaving_iyanda(self) -> None:
        credentials = StaticCredentials(self.credential)
        portal = OfflinePortalFactory()
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.UNKNOWN),
            credentials,
            portal,
            expected_network=lambda: False,
        )

        code = watcher.run(once=True)

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(portal.status_calls, 0)
        self.assertEqual(portal.login_calls, 0)
        self.assertEqual(credentials.calls, 0)

    def test_five_transient_authentication_failures_exit_and_are_logged(self) -> None:
        failure = PortalError(
            "authentication_failed",
            "service_login",
            "student42 super-secret password=super-secret ticket=abc",
            200,
        )
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.CAPTIVE, ConnectivityState.CAPTIVE),
            StaticCredentials(self.credential),
            PortalFactory([failure, failure, failure, failure, failure]),
        )

        console = io.StringIO()
        with redirect_stdout(console):
            code = watcher.run(once=True)

        self.assertEqual(code, EXIT_AUTH_FAILED)
        events = self.events()
        failures = [event for event in events if event["event"] == "authentication_failed"]
        fatals = [event for event in events if event["event"] == "fatal"]
        self.assertEqual(len(failures), 5)
        self.assertEqual(len(fatals), 1)
        raw_log = self.log_path.read_text(encoding="utf-8")
        self.assertNotIn("student42", raw_log)
        self.assertNotIn("super-secret", raw_log)
        self.assertNotIn("ticket=abc", raw_log)
        self.assertNotIn("student42", console.getvalue())
        self.assertNotIn("super-secret", console.getvalue())
        self.assertNotIn("ticket=abc", console.getvalue())

    def test_credential_rejection_stops_after_first_attempt(self) -> None:
        portal = PortalFactory([
            PortalError("credential_rejected", "cas_login", "用户名或密码错误")
        ])
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.CAPTIVE, ConnectivityState.CAPTIVE),
            StaticCredentials(self.credential),
            portal,
        )

        code = watcher.run(once=True)

        self.assertEqual(code, EXIT_CREDENTIAL_REJECTED)
        self.assertEqual(portal.calls, 1)
        failures = [
            event for event in self.events()
            if event["event"] == "authentication_failed"
        ]
        fatals = [event for event in self.events() if event["event"] == "fatal"]
        self.assertEqual(len(failures), 1)
        self.assertEqual(fatals[-1]["category"], "credential_rejected")
        self.assertEqual(fatals[-1]["attempts"], 1)

    def test_locked_account_stops_after_first_attempt(self) -> None:
        portal = PortalFactory([
            PortalError("account_locked", "service_login", "账号已永久冻结")
        ])
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.CAPTIVE, ConnectivityState.CAPTIVE),
            StaticCredentials(self.credential),
            portal,
        )

        code = watcher.run(once=True)

        self.assertEqual(code, EXIT_CREDENTIAL_REJECTED)
        self.assertEqual(portal.calls, 1)
        fatals = [event for event in self.events() if event["event"] == "fatal"]
        self.assertEqual(fatals[-1]["category"], "account_locked")
        self.assertEqual(fatals[-1]["attempts"], 1)

    def test_device_count_limit_stops_without_retries(self) -> None:
        portal = PortalFactory([
            PortalError("account_device_limit", "service_login", "认证设备数量已达到上限")
        ])
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.CAPTIVE, ConnectivityState.CAPTIVE),
            StaticCredentials(self.credential),
            portal,
        )

        code = watcher.run(once=True)

        self.assertEqual(code, EXIT_ACCOUNT_LIMIT)
        self.assertEqual(portal.calls, 1)
        fatals = [event for event in self.events() if event["event"] == "fatal"]
        self.assertEqual(fatals[-1]["category"], "account_device_limit")

    def test_ip_freeze_stops_without_retries_with_distinct_exit_code(self) -> None:
        portal = PortalFactory([
            PortalError("ip_blocked", "service_login", "当前 IP 已被冻结"),
        ])
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.CAPTIVE, ConnectivityState.CAPTIVE),
            StaticCredentials(self.credential),
            portal,
        )

        code = watcher.run(once=True)

        self.assertEqual(code, EXIT_IP_BLOCKED)
        self.assertEqual(portal.calls, 1)
        fatals = [event for event in self.events() if event["event"] == "fatal"]
        self.assertEqual(fatals[-1]["category"], "ip_blocked")
        self.assertEqual(fatals[-1]["attempts"], 1)

    def test_missing_credentials_exits_without_portal(self) -> None:
        portal = PortalFactory([])
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.CAPTIVE, ConnectivityState.CAPTIVE),
            StaticCredentials(CredentialError("missing test credential")),
            portal,
        )

        code = watcher.run(once=True)

        self.assertEqual(code, EXIT_MISSING_CREDENTIALS)
        self.assertEqual(portal.calls, 0)

    def test_protocol_change_exits_immediately_with_30(self) -> None:
        portal = PortalFactory(
            [PortalError("protocol_changed", "cas_page", "missing flow key")]
        )
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.CAPTIVE, ConnectivityState.CAPTIVE),
            StaticCredentials(self.credential),
            portal,
        )

        code = watcher.run(once=True)

        self.assertEqual(code, EXIT_PROTOCOL_CHANGED)
        self.assertEqual(portal.calls, 1)

    def test_unsafe_redirect_exits_immediately_without_five_retries(self) -> None:
        portal = PortalFactory([
            PortalError(
                "unsafe_redirect",
                "portal_redirect",
                "unsafe destination (http://unexpected.example/portal)",
            )
        ])
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.CAPTIVE, ConnectivityState.CAPTIVE),
            StaticCredentials(self.credential),
            portal,
        )

        code = watcher.run(once=True)

        self.assertEqual(code, EXIT_PROTOCOL_CHANGED)
        self.assertEqual(portal.calls, 1)
        failures = [
            event for event in self.events()
            if event["event"] == "authentication_failed"
        ]
        self.assertEqual(len(failures), 1)

    def test_startup_authentication_skips_confirmation_delay(self) -> None:
        portal = PortalFactory([None])
        watcher = self.watcher(
            SequenceChecker(
                ConnectivityState.ONLINE,
                ConnectivityState.ONLINE,
            ),
            StaticCredentials(self.credential),
            portal,
        )

        code = watcher.run(once=True, authenticate_on_start=True)

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(portal.calls, 1)
        names = [event["event"] for event in self.events()]
        self.assertIn("startup_authentication", names)
        self.assertNotIn("connectivity_confirmation", names)

    def test_startup_authentication_requires_expected_wifi(self) -> None:
        portal = PortalFactory([])
        credentials = StaticCredentials(self.credential)
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.ONLINE),
            credentials,
            portal,
            expected_network=lambda: False,
        )

        code = watcher.run(once=True, authenticate_on_start=True)

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(credentials.calls, 0)
        self.assertEqual(portal.calls, 0)
        names = [event["event"] for event in self.events()]
        self.assertIn("startup_authentication_skipped", names)

    def test_online_portal_unknown_probes_do_not_count_as_auth_failures(self) -> None:
        portal = Mock()
        portal.login.return_value = True
        portal.status.return_value = SimpleNamespace(online=True)
        watcher = self.watcher(
            SequenceChecker(*([ConnectivityState.UNKNOWN] * 3)),
            StaticCredentials(self.credential), lambda: portal,
        )
        code = watcher.run(once=True, authenticate_on_start=True)
        self.assertEqual(code, EXIT_NETWORK_UNCONFIRMED)
        portal.login.assert_called_once()
        names = [event["event"] for event in self.events()]
        self.assertIn("network_pending", names)
        self.assertNotIn("authentication_failed", names)
        self.assertNotIn("authentication_succeeded", names)
        self.assertNotIn("fatal", names)

    def test_delayed_internet_recovers_without_resubmitting_login(self) -> None:
        portal = Mock()
        watcher = self.watcher(
            SequenceChecker(
                ConnectivityState.UNKNOWN, ConnectivityState.UNKNOWN,
                ConnectivityState.ONLINE, ConnectivityState.ONLINE,
            ),
            StaticCredentials(self.credential), lambda: portal,
        )
        self.assertEqual(watcher.run(once=True, authenticate_on_start=True), EXIT_OK)
        portal.login.assert_called_once()
        self.assertNotIn("authentication_failed", [e["event"] for e in self.events()])

    def test_continuous_watch_recovers_after_pending_without_another_login(self) -> None:
        portal = Mock()
        portal.status.return_value = SimpleNamespace(online=True)
        checker = SequenceChecker(
            *([ConnectivityState.UNKNOWN] * 3), ConnectivityState.ONLINE,
        )
        watcher = self.watcher(checker, StaticCredentials(self.credential), lambda: portal)
        messages = []
        def report(message):
            messages.append(message)
            if message == "互联网连接已恢复，继续监听。":
                watcher.stop_event.set()
        watcher.reporter = report
        self.assertEqual(watcher.run(authenticate_on_start=True), EXIT_OK)
        portal.login.assert_called_once()
        self.assertTrue(any("网络待恢复" in message for message in messages))

    def test_portal_transport_error_does_not_spend_five_attempts(self) -> None:
        portal = Mock()
        portal.login.side_effect = PortalError("timeout", "service_login", "timeout")
        watcher = self.watcher(
            SequenceChecker(), StaticCredentials(self.credential), lambda: portal,
        )
        self.assertEqual(
            watcher.run(once=True, authenticate_on_start=True), EXIT_NETWORK_UNCONFIRMED,
        )
        portal.login.assert_called_once()
        self.assertNotIn("authentication_failed", [e["event"] for e in self.events()])

    def test_failed_probe_and_failed_portal_recheck_remain_pending(self) -> None:
        portal = Mock()
        portal.status.side_effect = PortalError("network_error", "status", "unreachable")
        watcher = self.watcher(
            SequenceChecker(*([ConnectivityState.UNKNOWN] * 3)),
            StaticCredentials(self.credential), lambda: portal,
        )
        self.assertEqual(
            watcher.run(once=True, authenticate_on_start=True), EXIT_NETWORK_UNCONFIRMED,
        )
        self.assertNotIn("fatal", [e["event"] for e in self.events()])

    def test_portal_recheck_ip_freeze_is_terminal(self) -> None:
        portal = Mock()
        portal.login.return_value = True
        portal.status.side_effect = PortalError(
            "ip_blocked", "status", "登录来源 IP 已被冻结",
        )
        watcher = self.watcher(
            SequenceChecker(*([ConnectivityState.UNKNOWN] * 3)),
            StaticCredentials(self.credential), lambda: portal,
        )

        self.assertEqual(
            watcher.run(once=True, authenticate_on_start=True), EXIT_IP_BLOCKED,
        )
        portal.login.assert_called_once()
        fatal = next(e for e in self.events() if e["event"] == "fatal")
        self.assertEqual(fatal["category"], "ip_blocked")

    def test_portal_confirmed_offline_after_grace_still_stops_at_five(self) -> None:
        portal = Mock()
        portal.status.return_value = SimpleNamespace(online=False)
        watcher = self.watcher(
            SequenceChecker(*([ConnectivityState.CAPTIVE] * 15)),
            StaticCredentials(self.credential), lambda: portal,
        )
        self.assertEqual(watcher.run(once=True, authenticate_on_start=True), EXIT_AUTH_FAILED)
        self.assertEqual(portal.login.call_count, 5)
        fatal = next(e for e in self.events() if e["event"] == "fatal")
        self.assertEqual(fatal["stage"], "verify_login")
        self.assertIn("confirmed offline", fatal["reason"])

    def test_wifi_change_during_retry_prevents_remaining_attempts(self) -> None:
        network = {"campus": True}
        portal = Mock()
        portal.login.side_effect = PortalError("authentication_failed", "service_login", "rejected")
        source = StaticCredentials(self.credential)
        watcher = self.watcher(
            SequenceChecker(), source, lambda: portal,
            expected_network=lambda: network["campus"],
        )
        watcher.sleeper = lambda _: network.update(campus=False)
        self.assertEqual(
            watcher.run(once=True, authenticate_on_start=True), EXIT_NETWORK_UNCONFIRMED,
        )
        portal.login.assert_called_once()
        self.assertEqual(source.calls, 1)

    def test_changed_credential_is_read_on_next_attempt(self) -> None:
        source = StaticCredentials(self.credential)
        portal = Mock()
        portal.login.side_effect = [
            PortalError("authentication_failed", "service_login", "temporary rejection"), True,
        ]
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.ONLINE, ConnectivityState.ONLINE),
            source, lambda: portal,
        )
        watcher.sleeper = lambda _: setattr(source, "value", Credential("new-user", "new-secret"))
        self.assertEqual(watcher.run(once=True, authenticate_on_start=True), EXIT_OK)
        self.assertEqual(source.calls, 2)
        self.assertEqual(portal.login.call_args.args[:2], ("new-user", "new-secret"))
        self.assertNotIn("new-user", self.log_path.read_text(encoding="utf-8"))

    def test_stop_during_verification_does_not_report_success(self) -> None:
        portal = Mock()
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.UNKNOWN),
            StaticCredentials(self.credential), lambda: portal,
        )
        watcher.sleeper = lambda _: watcher.stop_event.set()
        self.assertEqual(watcher.run(once=True, authenticate_on_start=True), EXIT_OK)
        self.assertNotIn("authentication_succeeded", [e["event"] for e in self.events()])

    def test_existing_session_is_not_reported_as_new_account_login(self) -> None:
        portal = Mock()
        portal.login.return_value = False
        watcher = self.watcher(
            SequenceChecker(ConnectivityState.ONLINE, ConnectivityState.ONLINE),
            StaticCredentials(self.credential), lambda: portal,
        )
        self.assertEqual(watcher.run(once=True, authenticate_on_start=True), EXIT_OK)
        names = [e["event"] for e in self.events()]
        self.assertIn("portal_already_online", names)
        self.assertNotIn("authentication_succeeded", names)


if __name__ == "__main__":
    unittest.main()
