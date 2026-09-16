from __future__ import annotations

import json
import tempfile
import threading
import unittest
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from ysu_net_watch.cli import build_parser, run_console, run_login, run_watch
from ysu_net_watch.credentials import CredentialError
from ysu_net_watch.profiles import ProfileStore
from ysu_net_watch.schedule import TimerSchedule
from ysu_net_watch.settings import (
    AppSettings, legacy_profile_id, load_settings, save_settings, select_profile,
)
from ysu_net_watch.wifi import WifiConnectionInfo, WifiConnectionState


class TimerFollowTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "settings.json"
        patcher = patch("ysu_net_watch.settings.default_settings_path", return_value=self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = ProfileStore(self.path)
        self.telecom = legacy_profile_id("telecom")
        self.campus = legacy_profile_id("campus")

    def test_selection_persists_and_preserves_schedule_and_custom_timers(self):
        original = AppSettings()
        first = replace(original.timers[0], enabled=False, time="07:15",
                        weekdays=(1, 3), retry_time="09:20")
        config = replace(original, timers=(first, *original.timers[1:]))
        save_settings(config, self.path)
        for selected in (self.telecom, self.campus, self.telecom):
            self.store.remember_selection(selected)
            current = load_settings(self.path)
            self.assertEqual(current.last_selected_profile_id, selected)
            self.assertEqual(current.timers[0].profile_id, selected)
            self.assertEqual(current.timers[0].enabled, first.enabled)
            self.assertEqual(current.timers[0].time, first.time)
            self.assertEqual(current.timers[0].weekdays, first.weekdays)
            self.assertEqual(current.timers[0].retry_time, first.retry_time)
            self.assertEqual(current.timers[1:], config.timers[1:])
            self.assertEqual(current.default_profile_ids, config.default_profile_ids)
            self.assertEqual(current.mode, config.mode)
            self.assertEqual(current.service, config.service)
        self.assertEqual(current.timers[0].service, "telecom")

    def test_same_carrier_different_profile_follows_exact_id_without_credentials(self):
        config = AppSettings()
        other = replace(config.profiles[2], id="12000000-0000-0000-0000-000000000001",
                        label="Other Telecom", legacy=False)
        save_settings(replace(config, profiles=(*config.profiles, other)), self.path)
        with patch("ysu_net_watch.profiles.credential_source") as credentials:
            self.store.remember_selection(other.id)
        credentials.assert_not_called()
        self.assertEqual(load_settings(self.path).timers[0].profile_id, other.id)

    def test_old_config_migrates_from_common_account_not_stale_timer(self):
        raw = asdict(AppSettings(mode="broadband", service="telecom"))
        raw.pop("last_selected_profile_id")
        before = json.dumps(raw)
        self.path.write_text(before, encoding="utf-8")
        current = load_settings(self.path)
        self.assertEqual(current.timers[0].profile_id, self.telecom)
        self.assertEqual(current.timers[0].service, "telecom")
        self.assertEqual(self.path.read_text(encoding="utf-8"), before)
        save_settings(current, self.path)
        self.assertEqual(load_settings(self.path), current)
        self.assertEqual(
            self.path.with_suffix(".pre-timer-follow.json").read_text(encoding="utf-8"), before,
        )

    def test_explicit_missing_selection_never_falls_back_to_common_account(self):
        for selected in ("missing-profile", None):
            with self.subTest(selected=selected):
                save_settings(replace(AppSettings(), last_selected_profile_id=selected), self.path)
                current = load_settings(self.path)
                self.assertEqual(current.timers[0].profile_id, selected)
                with self.assertRaises(CredentialError):
                    self.store.get(current.timers[0].profile_id or "")

    def test_missing_migration_default_does_not_use_old_timer_account(self):
        raw = asdict(AppSettings(service="telecom", default_profile_ids={}))
        raw.pop("last_selected_profile_id")
        self.path.write_text(json.dumps(raw), encoding="utf-8")
        self.assertIsNone(load_settings(self.path).timers[0].profile_id)

    def test_invalid_selection_does_not_modify_settings(self):
        save_settings(AppSettings(), self.path)
        before = self.path.read_bytes()
        with self.assertRaises(CredentialError):
            self.store.remember_selection("missing")
        self.assertEqual(self.path.read_bytes(), before)

    def test_delete_remembered_profile_disables_timer_without_fallback(self):
        self.store.remember_selection(self.telecom)
        self.store.delete(self.telecom, disable_timers=True)
        current = load_settings(self.path)
        self.assertIsNone(current.last_selected_profile_id)
        self.assertIsNone(current.timers[0].profile_id)
        self.assertFalse(current.timers[0].enabled)
        self.store.remember_selection(self.campus)
        self.assertFalse(load_settings(self.path).timers[0].enabled)

    def test_primary_and_retry_use_same_remembered_target(self):
        config = self.store.remember_selection(self.telecom)
        schedule = TimerSchedule()
        six = datetime(2026, 9, 14, 6)
        primary = schedule.due_timers(six, config.timers, config.profiles)[0]
        self.assertEqual(primary.timer.profile_id, self.telecom)
        run = schedule.mark_started(primary, six.date())
        schedule.mark_finished(run, 20)
        retry = schedule.due_timers(datetime(2026, 9, 14, 8), config.timers, config.profiles)[0]
        self.assertEqual(retry.timer.profile_id, self.telecom)
        self.assertEqual(retry.timer.service, "telecom")
        self.assertEqual(retry.phase, "retry")

    def test_selection_change_cancels_old_retry_but_repeat_selection_preserves_it(self):
        config = self.store.remember_selection(self.telecom)
        schedule = TimerSchedule()
        six = datetime(2026, 9, 14, 6)
        due = schedule.due_timers(six, config.timers, config.profiles)[0]
        run = schedule.mark_started(due, six.date())
        schedule.mark_finished(run, 20)
        config = self.store.remember_selection(self.telecom)
        self.assertEqual(len(schedule.due_timers(datetime(2026, 9, 14, 8),
                                               config.timers, config.profiles)), 1)
        config = self.store.remember_selection(self.campus)
        schedule.sync(config.timers, config.profiles)
        schedule.mark_finished(run, 20)
        self.assertEqual(schedule.due_timers(datetime(2026, 9, 14, 8),
                                            config.timers, config.profiles), [])

    def test_manual_console_choice_is_remembered_even_if_authentication_fails(self):
        choices = iter([0, 6])
        started = threading.Event()
        def watch(args, **kwargs):
            self.assertFalse(kwargs["remember_selection"])
            started.set()
            return 20
        def menu(*args, **kwargs):
            choice = next(choices)
            if choice == 5:
                self.assertTrue(started.wait(2))
            return choice
        with patch("ysu_net_watch.cli.select_menu", side_effect=menu), patch(
            "ysu_net_watch.cli.run_watch", side_effect=watch
        ):
            self.assertEqual(run_console(enable_scheduler=False), 0)
        self.assertEqual(load_settings(self.path).last_selected_profile_id, self.campus)

    def test_failed_save_prevents_new_worker_from_starting(self):
        with patch("ysu_net_watch.cli.select_menu", side_effect=[0, 6]), patch(
            "ysu_net_watch.profiles.save_settings", side_effect=PermissionError()
        ), patch("ysu_net_watch.cli.run_watch") as watch:
            self.assertEqual(run_console(enable_scheduler=False), 0)
        watch.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_configure_common_account_also_updates_first_timer(self):
        with patch("ysu_net_watch.cli.select_menu", side_effect=[5, 0, 1, 1, 4, 6]):
            self.assertEqual(run_console(enable_scheduler=False), 0)
        current = load_settings(self.path)
        self.assertEqual(current.service, "telecom")
        self.assertEqual(current.timers[0].profile_id, self.telecom)

    def test_menu_cancel_and_custom_timer_binding_do_not_replace_selection(self):
        self.store.remember_selection(self.telecom)
        # Bind timer 2 to campus, then cancel timer 1's account picker.
        choices = [5, 1, 1, 3, 0, 6, 0, 3, 4, 6, 10, 4, 6]
        with patch("ysu_net_watch.cli.select_menu", side_effect=choices):
            self.assertEqual(run_console(enable_scheduler=False), 0)
        current = load_settings(self.path)
        self.assertEqual(current.last_selected_profile_id, self.telecom)
        self.assertEqual(current.timers[0].profile_id, self.telecom)
        self.assertEqual(current.timers[1].profile_id, self.campus)

    def test_first_timer_account_picker_updates_selection_and_reset_keeps_it(self):
        choices = [5, 1, 0, 3, 2, 5, 6, 10, 4, 6]
        with patch("ysu_net_watch.cli.select_menu", side_effect=choices):
            self.assertEqual(run_console(enable_scheduler=False), 0)
        current = load_settings(self.path)
        self.assertEqual(current.last_selected_profile_id, self.telecom)
        self.assertEqual(current.timers[0].profile_id, self.telecom)
        self.assertFalse(current.timers[0].enabled)
        self.assertEqual(current.timers[0].time, "06:00")
        self.assertIsNone(current.timers[0].retry_time)

    def test_cli_selection_is_remembered_at_night_without_network_calls(self):
        for command in ("login", "watch"):
            self.store.remember_selection(self.campus)
            args = build_parser().parse_args([command, "--profile", self.telecom])
            with patch("ysu_net_watch.cli.current_pause_reason", return_value="night"), patch(
                "ysu_net_watch.cli.WifiConnector"
            ) as wifi, patch("ysu_net_watch.cli.Watcher") as watcher:
                if command == "login":
                    self.assertEqual(run_login(args), 22)
                else:
                    watcher.return_value.run.return_value = 22
                    self.assertEqual(run_watch(args, install_signal_handlers=False), 22)
            wifi.return_value.connect.assert_not_called()
            self.assertEqual(load_settings(self.path).last_selected_profile_id, self.telecom)

    def test_env_only_login_does_not_create_a_persisted_timer_target(self):
        self.store.remember_selection(self.campus)
        args = build_parser().parse_args(
            ["login", "--mode", "broadband", "--service", "telecom", "--credential-source", "env"]
        )
        with patch("ysu_net_watch.cli.current_pause_reason", return_value="night"):
            self.assertEqual(run_login(args), 22)
        self.assertEqual(load_settings(self.path).last_selected_profile_id, self.campus)

    def test_scheduled_custom_timer_never_overwrites_remembered_selection(self):
        config = select_profile(AppSettings(), self.telecom)
        timers = list(config.timers)
        timers[1] = replace(timers[1], enabled=True, time="07:00",
                            profile_id=self.campus, mode="campus")
        save_settings(replace(config, timers=tuple(timers)), self.path)
        started = threading.Event()
        errors = []
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime(2026, 9, 14, 7)
        def supervisor(stop, tick, on_error, on_recovered):
            try:
                tick()
            except Exception as exc:
                errors.append(exc)
                started.set()
            stop.wait(2)
        def watch(args, **kwargs):
            self.assertEqual(args.profile, self.campus)
            self.assertFalse(kwargs["remember_selection"])
            started.set()
            kwargs["external_stop_event"].wait(2)
            return 0
        def menu(*args, **kwargs):
            self.assertTrue(started.wait(2))
            return 6
        with patch("ysu_net_watch.cli.datetime", Clock), patch(
            "ysu_net_watch.cli.supervise_schedule", side_effect=supervisor
        ), patch("ysu_net_watch.cli.WifiConnector") as wifi, patch(
            "ysu_net_watch.cli.run_watch", side_effect=watch
        ), patch("ysu_net_watch.cli.select_menu", side_effect=menu):
            wifi.return_value.connection_info.return_value = WifiConnectionInfo(
                WifiConnectionState.CONNECTED, "iYanDa",
            )
            self.assertEqual(run_console(schedule_state_path=None), 0)
        self.assertFalse(errors)
        self.assertEqual(load_settings(self.path).last_selected_profile_id, self.telecom)
        self.assertEqual(load_settings(self.path).timers[0].profile_id, self.telecom)

    def test_scheduled_watch_does_not_save_selection(self):
        args = build_parser().parse_args(["watch", "--profile", self.campus, "--no-auto-wifi"])
        self.store.remember_selection(self.telecom)
        before = self.path.read_bytes()
        with patch("ysu_net_watch.cli.Watcher"), patch("ysu_net_watch.cli.current_pause_reason",
                                                      return_value=None):
            run_watch(args, install_signal_handlers=False, remember_selection=False)
        self.assertEqual(self.path.read_bytes(), before)
