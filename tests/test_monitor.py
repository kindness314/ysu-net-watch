from __future__ import annotations

import json
import io
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from ysu_net_watch.connectivity import ConnectivityResult, ConnectivityState
from ysu_net_watch.credentials import Credential, CredentialError
from ysu_net_watch.monitor import (
    EXIT_AUTH_FAILED,
    EXIT_MISSING_CREDENTIALS,
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
            def login(self, _username: str, _password: str, _service: str) -> None:
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

            def login(self, _username: str, _password: str, _service: str) -> None:
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

    def test_five_failures_exit_and_are_logged(self) -> None:
        failure = PortalError(
            "credential_rejected",
            "cas_login",
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


if __name__ == "__main__":
    unittest.main()
