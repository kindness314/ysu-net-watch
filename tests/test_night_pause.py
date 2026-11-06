from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from ysu_net_watch.credentials import Credential
from ysu_net_watch.connectivity import ConnectivityResult, ConnectivityState
from ysu_net_watch.monitor import Watcher, WatchSettings, JsonEventLog
from ysu_net_watch.portal import PortalError
from ysu_net_watch.schedule import night_pause_until, night_pause_reason
from ysu_net_watch.settings import AppSettings


class NightWindowTests(unittest.TestCase):
    def test_cross_midnight_boundaries_and_weekends(self):
        settings = AppSettings()
        cases = (
            (datetime(2026, 9, 7, 23, 29, 59), False),
            (datetime(2026, 9, 7, 23, 30), True),
            (datetime(2026, 9, 8, 5, 59, 59), True),
            (datetime(2026, 9, 8, 6, 0), False),
            (datetime(2026, 9, 10, 23, 30), True),
            (datetime(2026, 9, 11, 2, 0), True),
            (datetime(2026, 9, 11, 6, 0), False),
            (datetime(2026, 9, 11, 23, 30), False),
            (datetime(2026, 9, 12, 2, 0), False),
            (datetime(2026, 9, 12, 23, 30), False),
            (datetime(2026, 9, 13, 2, 0), False),
            (datetime(2026, 9, 13, 23, 29, 59), False),
            (datetime(2026, 9, 13, 23, 30), True),
            (datetime(2026, 9, 14, 2, 0), True),
            (datetime(2026, 9, 14, 5, 59, 59), True),
            (datetime(2026, 9, 14, 6, 0), False),
        )
        for now, paused in cases:
            with self.subTest(now=now):
                self.assertEqual(night_pause_until(now, settings) is not None, paused)

    def test_disabled_default_timer_still_defines_recovery_time(self):
        settings = AppSettings()
        timers = list(settings.timers)
        timers[0] = replace(timers[0], enabled=False, time="07:15")
        settings = replace(settings, timers=tuple(timers))
        self.assertEqual(night_pause_until(datetime(2026, 9, 8, 6), settings),
                         datetime(2026, 9, 8, 7, 15))

    def test_night_protection_can_be_disabled(self):
        self.assertIsNone(night_pause_until(
            datetime(2026, 9, 8, 2), replace(AppSettings(), night_pause_enabled=False),
        ))

    def test_incident_sunday_to_monday_all_four_failure_times_are_paused(self):
        for now in (datetime(2026, 11, 1, 23, 41, 30), datetime(2026, 11, 1, 23, 46, 51),
                    datetime(2026, 11, 2, 0, 2, 10), datetime(2026, 11, 2, 0, 32, 30)):
            with self.subTest(now=now):
                self.assertEqual(night_pause_until(now, AppSettings()), datetime(2026, 11, 2, 6))

    def test_sunday_follows_custom_recovery_time_even_when_timer_disabled(self):
        settings = AppSettings()
        timers = (replace(settings.timers[0], enabled=False, time="07:15"), *settings.timers[1:])
        settings = replace(settings, timers=timers)
        self.assertEqual(night_pause_until(datetime(2026, 11, 2, 7, 14, 59), settings), datetime(2026, 11, 2, 7, 15))
        self.assertIsNone(night_pause_until(datetime(2026, 11, 2, 7, 15), settings))

    def test_sunday_respects_timezone_and_global_off_switch(self):
        zone = timezone(timedelta(hours=8))
        now = datetime(2026, 11, 1, 23, 30, tzinfo=zone)
        self.assertEqual(night_pause_until(now, AppSettings()), datetime(2026, 11, 2, 6, tzinfo=zone))
        self.assertIsNone(night_pause_until(now, replace(AppSettings(), night_pause_enabled=False)))


class NightWatcherTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.log = JsonEventLog(Path(directory.name) / "log")
        self.now = datetime(2026, 9, 7, 23, 30)
        self.portal = Mock()
        self.portal.login.return_value = True
        self.source = Mock(get=Mock(return_value=Credential("dummy", "dummy")))
        self.checker = Mock(check=Mock(return_value=ConnectivityResult(ConnectivityState.ONLINE, "test")))

    def watcher(self, **options):
        return Watcher(
            WatchSettings("broadband", "中国电信"),
            self.checker, self.source, lambda: self.portal, self.log,
            pause_reason=lambda: night_pause_reason(self.now, AppSettings()),
            reporter=Mock(), **options,
        )

    def test_night_start_never_reads_credentials_or_calls_network(self):
        watcher = self.watcher()
        self.assertEqual(watcher.run(once=True, authenticate_on_start=True), 22)
        self.source.get.assert_not_called()
        self.portal.login.assert_not_called()
        self.checker.check.assert_not_called()

    def test_sunday_night_never_reads_credentials_or_submits_authentication(self):
        self.now = datetime(2026, 11, 1, 23, 30)
        watcher = self.watcher()
        self.assertEqual(watcher.run(once=True, authenticate_on_start=True), 22)
        self.source.get.assert_not_called()
        self.portal.login.assert_not_called()
        self.checker.check.assert_not_called()
        self.assertEqual(watcher.recovery.failures, 0)

    def test_sunday_night_resumes_on_monday_without_restarting(self):
        self.now = datetime(2026, 11, 1, 23, 30)
        self.checker.check.side_effect = [
            ConnectivityResult(state, "test") for state in (
                ConnectivityState.CAPTIVE, ConnectivityState.CAPTIVE, ConnectivityState.ONLINE,
            )
        ]
        resume = Mock()
        watcher = self.watcher(on_resume=resume)
        watcher.sleeper = lambda _: setattr(self, "now", datetime(2026, 11, 2, 6))
        def report(message):
            if "认证成功" in message:
                watcher.stop_event.set()
        watcher.reporter = report
        self.assertEqual(watcher.run(authenticate_on_start=True), 0)
        resume.assert_called_once()
        self.portal.login.assert_called_once()

    def test_morning_recovers_automatically_without_restarting_program(self):
        self.checker.check.side_effect = [
            ConnectivityResult(state, "test") for state in (
                ConnectivityState.CAPTIVE, ConnectivityState.CAPTIVE, ConnectivityState.ONLINE,
            )
        ]
        resume = Mock()
        watcher = self.watcher(on_resume=resume)
        watcher.sleeper = lambda _: setattr(self, "now", datetime(2026, 9, 8, 6))
        def report(message):
            if "认证成功" in message:
                watcher.stop_event.set()
        watcher.reporter = report
        self.assertEqual(watcher.run(authenticate_on_start=True), 0)
        resume.assert_called_once()
        self.portal.login.assert_called_once()

    def test_response_crossing_2330_is_not_charged_as_auth_failure(self):
        self.now = datetime(2026, 9, 7, 23, 29)
        def login(*_, **_kwargs):
            self.now = datetime(2026, 9, 7, 23, 30)
            raise PortalError("authentication_failed", "service_login", "night restriction")
        self.portal.login.side_effect = login
        watcher = self.watcher()
        self.assertEqual(watcher.run(once=True, authenticate_on_start=True), 22)
        self.assertNotIn('"event":"authentication_failed"', self.log.path.read_text(encoding="utf-8"))
        self.assertNotIn('"event":"fatal"', self.log.path.read_text(encoding="utf-8"))

    def test_night_begins_during_retry_wait(self):
        self.now = datetime(2026, 9, 7, 23, 29)
        self.portal.login.side_effect = PortalError("authentication_failed", "service_login", "rejected")
        watcher = self.watcher(sleeper=lambda _: setattr(self, "now", datetime(2026, 9, 7, 23, 30)))
        self.assertEqual(watcher.run(once=True, authenticate_on_start=True), 22)
        self.portal.login.assert_called_once()
        self.assertNotIn('"event":"fatal"', self.log.path.read_text(encoding="utf-8"))

    def test_failed_wifi_resume_is_retried_before_reading_credentials(self):
        self.checker.check.side_effect = [
            ConnectivityResult(state, "test") for state in (
                ConnectivityState.CAPTIVE, ConnectivityState.CAPTIVE, ConnectivityState.ONLINE,
            )
        ]
        resume = Mock(side_effect=[OSError("temporary disconnect"), None])
        watcher = self.watcher(on_resume=resume)
        watcher.sleeper = lambda _: setattr(self, "now", datetime(2026, 9, 8, 6))
        def report(message):
            if "暂时无法恢复" in message:
                self.source.get.assert_not_called()
            if "认证成功" in message:
                watcher.stop_event.set()
        watcher.reporter = report
        self.assertEqual(watcher.run(authenticate_on_start=True), 0)
        self.assertEqual(resume.call_count, 2)
        self.source.get.assert_called_once()

    def test_morning_online_never_reads_credentials_or_queries_stale_portal(self):
        resume = Mock()
        protection = Mock()
        watcher = self.watcher(on_resume=resume, force_switch=True, protection=protection)
        self.portal.status.return_value = SimpleNamespace(online=False)

        def sleep(_):
            if self.now.hour == 23:
                self.now = datetime(2026, 9, 8, 6)
            else:
                watcher.stop_event.set()

        watcher.sleeper = sleep
        self.assertEqual(watcher.run(authenticate_on_start=True), 0)
        resume.assert_called_once()
        self.checker.check.assert_called_once()
        self.source.get.assert_not_called()
        self.assertFalse(self.portal.mock_calls)
        self.assertFalse(protection.mock_calls)
        self.assertFalse(watcher._switch_pending)

    def test_morning_confirmation_recovery_does_not_authenticate(self):
        watcher = self.watcher()
        self.checker.check.side_effect = [
            ConnectivityResult(state, "test") for state in (
                ConnectivityState.CAPTIVE, ConnectivityState.ONLINE,
            )
        ]

        def sleep(seconds):
            if self.now.hour == 23:
                self.now = datetime(2026, 9, 8, 6)
            elif seconds == watcher.settings.check_interval:
                watcher.stop_event.set()

        watcher.sleeper = sleep
        self.assertEqual(watcher.run(authenticate_on_start=True), 0)
        self.source.get.assert_not_called()
        self.portal.login.assert_not_called()
        self.assertEqual(self.checker.check.call_count, 2)

    def test_morning_unknown_with_portal_timeout_does_not_authenticate(self):
        watcher = self.watcher()
        self.checker.check.return_value = ConnectivityResult(ConnectivityState.UNKNOWN, "timeout")
        self.portal.status.side_effect = PortalError("timeout", "status", "timeout")

        def sleep(_):
            if self.now.hour == 23:
                self.now = datetime(2026, 9, 8, 6)
            else:
                watcher.stop_event.set()

        watcher.sleeper = sleep
        self.assertEqual(watcher.run(authenticate_on_start=True), 0)
        self.portal.status.assert_called_once()
        self.source.get.assert_not_called()
        self.portal.login.assert_not_called()
