from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime
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
            (datetime(2026, 9, 14, 2, 0), False),
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

    def test_morning_recovers_automatically_without_restarting_program(self):
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
