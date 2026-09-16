from __future__ import annotations

import threading
import unittest
from dataclasses import replace
from datetime import datetime
from unittest.mock import Mock, patch

from ysu_net_watch.cli import run_console
from ysu_net_watch.schedule import TimerSchedule, supervise_schedule
from ysu_net_watch.settings import AppSettings, legacy_profile_id
from ysu_net_watch.wifi import WifiConnectionInfo, WifiConnectionState, WifiError


class TimerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.config = AppSettings()
        self.six = datetime(2026, 9, 10, 6)
        self.eight = datetime(2026, 9, 10, 8)
        self.schedule = TimerSchedule()
        due = self.schedule.due_timers(self.six, self.config.timers, self.config.profiles)[0]
        self.run = self.schedule.mark_started(due, self.six.date())

    def due_retry(self, config):
        return self.schedule.due_timers(self.eight, config.timers, config.profiles)

    def rebound(self):
        timers = list(self.config.timers)
        timers[0] = replace(timers[0], service="telecom", profile_id=legacy_profile_id("telecom"))
        return replace(self.config, timers=tuple(timers))

    def test_old_failure_cannot_trigger_new_account(self):
        self.schedule.mark_finished(self.run, 20)
        self.assertEqual(self.due_retry(self.rebound()), [])

    def test_late_old_worker_cannot_fail_new_binding(self):
        config = self.rebound()
        self.schedule.sync(config.timers, config.profiles)
        self.schedule.mark_finished(self.run, 20)
        self.assertEqual(self.due_retry(config), [])

    def test_switch_away_and_back_still_invalidates_old_completion(self):
        changed = self.rebound()
        self.schedule.sync(changed.timers, changed.profiles)
        self.schedule.sync(self.config.timers, self.config.profiles)
        self.assertFalse(self.schedule.is_current(self.run))
        self.schedule.mark_finished(self.run, 20)
        self.assertEqual(self.due_retry(self.config), [])

    def test_credential_revision_invalidates_failure(self):
        self.schedule.mark_finished(self.run, 20)
        config = replace(self.config, profiles=tuple(
            replace(p, credential_revision=p.credential_revision + 1)
            if p.id == self.config.timers[0].profile_id else p for p in self.config.profiles
        ))
        self.assertEqual(self.due_retry(config), [])

    def test_rename_does_not_discard_valid_retry(self):
        self.schedule.mark_finished(self.run, 20)
        config = replace(self.config, profiles=tuple(replace(p, label=p.label + "x") for p in self.config.profiles))
        self.assertEqual([d.phase for d in self.due_retry(config)], ["retry"])

    def test_time_day_toggle_and_retry_edits_invalidate_old_run(self):
        for change in ({"time": "07:00"}, {"weekdays": (3,)}, {"enabled": False}, {"retry_time": "09:00"}):
            with self.subTest(change=change):
                self.setUp()
                timers = list(self.config.timers)
                timers[0] = replace(timers[0], **change)
                self.schedule.sync(tuple(timers), self.config.profiles)
                self.assertFalse(self.schedule.is_current(self.run))
                self.schedule.mark_finished(self.run, 20)
                self.assertEqual(self.schedule.primary_failed, {})

    def test_stale_start_token_cannot_start_after_rebinding(self):
        schedule = TimerSchedule()
        due = schedule.due_timers(self.six, self.config.timers, self.config.profiles)[0]
        changed = self.rebound()
        schedule.sync(changed.timers, changed.profiles)
        self.assertIsNone(schedule.mark_started(due, self.six.date()))

    def test_same_day_due_is_claimed_only_once(self):
        schedule = TimerSchedule()
        due = schedule.due_timers(self.six, self.config.timers, self.config.profiles)[0]
        self.assertIsNotNone(schedule.mark_started(due, self.six.date()))
        self.assertIsNone(schedule.mark_started(due, self.six.date()))

    def test_previous_day_completion_does_not_replace_new_day_result(self):
        tomorrow = datetime(2026, 9, 11, 6)
        due = self.schedule.due_timers(tomorrow, self.config.timers, self.config.profiles)[0]
        newer = self.schedule.mark_started(due, tomorrow.date())
        self.schedule.mark_finished(newer, 20)
        self.schedule.mark_finished(self.run, 20)
        self.assertEqual(self.schedule.primary_failed[0], tomorrow.date())


class SchedulerSupervisionTests(unittest.TestCase):
    def test_tick_and_error_reporting_exceptions_do_not_kill_service(self):
        stop = threading.Event()
        ticks = []
        def tick():
            ticks.append(True)
            if len(ticks) == 1:
                raise WifiError("synthetic timeout")
            stop.set()
        error = Mock(side_effect=OSError("synthetic unavailable log"))
        recovered = Mock()
        supervise_schedule(stop, tick, error, recovered, interval=0)
        self.assertEqual(len(ticks), 2)
        error.assert_called_once()
        recovered.assert_called_once()

    def test_stop_interrupts_retry_wait(self):
        stop = threading.Event()
        tick = Mock(side_effect=ValueError("synthetic config"))
        supervise_schedule(stop, tick, lambda _: stop.set(), Mock(), interval=60)
        tick.assert_called_once()

    def test_invalid_priority_timer_does_not_consume_next_valid_timer(self):
        config = AppSettings()
        timers = list(config.timers)
        timers[0] = replace(
            timers[0],
            profile_id="00000000-0000-0000-0000-000000000999",
        )
        timers[1] = replace(
            config.timers[0],
            enabled=True,
            time=config.timers[0].time,
        )
        config = replace(config, timers=tuple(timers))
        clock = [datetime(2026, 9, 10, 6)]
        started = threading.Event()
        errors = []

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock[0]

        def supervisor(stop, tick, on_error, _on_recovered):
            try:
                tick()
            except Exception as exc:
                errors.append(type(exc).__name__)
                on_error(exc)
            tick()
            stop.wait(2)

        def watch(args, *, external_stop_event, **_kwargs):
            self.assertEqual(args.profile, timers[1].profile_id)
            started.set()
            external_stop_event.wait(2)
            return 0

        def menu(_title, _options):
            self.assertTrue(started.wait(2))
            return 6

        with (
            patch("ysu_net_watch.cli.datetime", Clock),
            patch("ysu_net_watch.cli.load_settings", return_value=config),
            patch("ysu_net_watch.profiles.load_settings", return_value=config),
            patch("ysu_net_watch.cli.WifiConnector") as wifi,
            patch("ysu_net_watch.cli.JsonEventLog"),
            patch("ysu_net_watch.cli.supervise_schedule", side_effect=supervisor),
            patch("ysu_net_watch.cli.run_watch", side_effect=watch) as run_watch,
            patch("ysu_net_watch.cli.select_menu", side_effect=menu),
        ):
            wifi.return_value.connection_info.return_value = WifiConnectionInfo(
                WifiConnectionState.CONNECTED, "iYanDa",
            )
            self.assertEqual(run_console(schedule_state_path=None), 0)

        self.assertEqual(errors, ["CredentialError"])
        run_watch.assert_called_once()

    def test_real_console_survives_wifi_timeout_and_runs_eight_oclock_retry(self):
        config = AppSettings()
        clock = [datetime(2026, 9, 10, 6)]
        recovered = threading.Event()
        started = threading.Event()
        errors, titles = [], []
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock[0]
        def supervisor(stop, tick, on_error, on_recovered):
            def failed(exc):
                errors.append(type(exc).__name__)
                on_error(exc)
                clock[0] = datetime(2026, 9, 10, 8)
            def healthy():
                on_recovered()
                recovered.set()
            supervise_schedule(stop, tick, failed, healthy, interval=0.01)
        def watch(args, *, external_stop_event, **kwargs):
            self.assertEqual(args.profile, config.timers[0].profile_id)
            started.set()
            external_stop_event.wait(2)
            return 0
        def menu(title, options):
            self.assertTrue(started.wait(2))
            self.assertTrue(recovered.wait(2))
            titles.append(title())
            return 6
        with (
            patch("ysu_net_watch.cli.datetime", Clock),
            patch("ysu_net_watch.cli.load_settings", return_value=config),
            patch("ysu_net_watch.profiles.load_settings", return_value=config),
            patch("ysu_net_watch.cli.WifiConnector") as wifi,
            patch("ysu_net_watch.cli.JsonEventLog") as logs,
            patch("ysu_net_watch.cli.supervise_schedule", side_effect=supervisor),
            patch("ysu_net_watch.cli.run_watch", side_effect=watch) as run_watch,
            patch("ysu_net_watch.cli.select_menu", side_effect=menu),
        ):
            wifi.return_value.connection_info.side_effect = [
                WifiError("synthetic timeout"),
                WifiConnectionInfo(WifiConnectionState.CONNECTED, "iYanDa"),
            ]
            logs.return_value.write.side_effect = PermissionError("synthetic log locked")
            self.assertEqual(run_console(schedule_state_path=None), 0)
        self.assertEqual(errors, ["WifiError"])
        run_watch.assert_called_once()
        self.assertIn("定时调度：运行中", titles[0])
        self.assertNotIn("已停止（异常）", titles[0])

    def test_unknown_wifi_marks_primary_failed_and_runs_compensation(self):
        config = AppSettings()
        clock = [datetime(2026, 9, 10, 6)]
        started = threading.Event()
        titles = []
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock[0]
        def supervisor(stop, tick, _on_error, _on_recovered):
            tick()
            clock[0] = datetime(2026, 9, 10, 8)
            tick()
            stop.wait(2)
        def watch(_args, *, external_stop_event, **_kwargs):
            started.set()
            external_stop_event.wait(2)
            return 0
        def menu(title, _options):
            self.assertTrue(started.wait(2))
            titles.append(title())
            return 6
        with (
            patch("ysu_net_watch.cli.datetime", Clock),
            patch("ysu_net_watch.cli.load_settings", return_value=config),
            patch("ysu_net_watch.profiles.load_settings", return_value=config),
            patch("ysu_net_watch.cli.WifiConnector") as wifi,
            patch("ysu_net_watch.cli.JsonEventLog"),
            patch("ysu_net_watch.cli.supervise_schedule", side_effect=supervisor),
            patch("ysu_net_watch.cli.run_watch", side_effect=watch) as run_watch,
            patch("ysu_net_watch.cli.select_menu", side_effect=menu),
        ):
            wifi.return_value.connection_info.side_effect = [
                WifiConnectionInfo(WifiConnectionState.UNKNOWN, reason="query unavailable"),
                WifiConnectionInfo(WifiConnectionState.CONNECTED, "iYanDa"),
            ]
            self.assertEqual(run_console(schedule_state_path=None), 0)
        run_watch.assert_called_once()
        self.assertIn("定时器 1 补偿启动", titles[0])

    def test_one_watcher_reports_failure_to_every_attached_timer(self):
        timers = list(AppSettings().timers)
        timers[1] = replace(timers[0], time="07:00")
        config = replace(AppSettings(), timers=tuple(timers))
        clock = [datetime(2026, 9, 10, 6)]
        release_first = threading.Event()
        first_finished = threading.Event()
        second_started = threading.Event()
        calls = []
        titles = []
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock[0]
        def watch(_args, *, external_stop_event, **_kwargs):
            calls.append(clock[0])
            if len(calls) == 1:
                release_first.wait(2)
                first_finished.set()
                return 20
            second_started.set()
            external_stop_event.wait(2)
            return 0
        def supervisor(stop, tick, _on_error, _on_recovered):
            tick()  # timer 1 starts the shared watcher
            clock[0] = datetime(2026, 9, 10, 7)
            tick()  # timer 2 attaches to that watcher
            release_first.set()
            self.assertTrue(first_finished.wait(2))
            threading.Event().wait(0.05)
            clock[0] = datetime(2026, 9, 10, 8)
            tick()  # both failed; timer 1 wins the equal-time compensation
            stop.wait(2)
        def menu(title, _options):
            self.assertTrue(second_started.wait(2))
            titles.append(title())
            return 6
        with (
            patch("ysu_net_watch.cli.datetime", Clock),
            patch("ysu_net_watch.cli.load_settings", return_value=config),
            patch("ysu_net_watch.profiles.load_settings", return_value=config),
            patch("ysu_net_watch.cli.WifiConnector") as wifi,
            patch("ysu_net_watch.cli.JsonEventLog"),
            patch("ysu_net_watch.cli.supervise_schedule", side_effect=supervisor),
            patch("ysu_net_watch.cli.run_watch", side_effect=watch),
            patch("ysu_net_watch.cli.select_menu", side_effect=menu),
        ):
            wifi.return_value.connection_info.return_value = WifiConnectionInfo(
                WifiConnectionState.CONNECTED, "iYanDa",
            )
            self.assertEqual(run_console(schedule_state_path=None), 0)
        self.assertEqual(len(calls), 2)
        self.assertIn("定时器 1 补偿启动", titles[0])
