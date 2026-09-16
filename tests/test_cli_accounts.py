from __future__ import annotations

import io
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from contextlib import redirect_stdout

from ysu_net_watch.cli import (
    build_parser,
    main,
    run_account_verify,
    run_console,
    run_login,
    run_watch,
)
from ysu_net_watch.credentials import CredentialError
from ysu_net_watch.connectivity import ConnectivityState
from ysu_net_watch.instance import AlreadyRunningError
from ysu_net_watch.profiles import ProfileStore
from ysu_net_watch.settings import (
    AccountProfile, AppSettings, load_settings, legacy_profile_id, save_settings,
)
from ysu_net_watch.wifi import WifiConnectionState, WifiError
from ysu_net_watch.portal import PortalStatus, PortalError


class AccountCliTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "settings.json"
        for patcher in (
            patch("ysu_net_watch.settings.default_settings_path", return_value=self.path),
            patch("ysu_net_watch.cli.current_pause_reason", return_value=None),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_missing_target_credential_never_logs_out_old_account(self):
        args = build_parser().parse_args([
            "login", "--profile", legacy_profile_id("telecom"), "--no-auto-wifi",
        ])
        source = Mock()
        source.get.side_effect = CredentialError("missing")
        with patch("ysu_net_watch.cli.selected_credential_source", return_value=source), patch(
            "ysu_net_watch.cli.PortalClient"
        ) as portal:
            self.assertEqual(run_login(args), 10)
        portal.assert_not_called()

    def test_login_can_try_later_same_service_account_after_device_limit(self):
        first = AccountProfile(
            "00000000-0000-0000-0000-000000000001", "第一个联通", "broadband", "unicom",
        )
        second = AccountProfile(
            "00000000-0000-0000-0000-000000000002", "第二个联通", "broadband", "unicom",
        )
        other = AccountProfile(
            "00000000-0000-0000-0000-000000000003", "电信账号", "broadband", "telecom",
        )
        config = replace(
            AppSettings(),
            profiles=(first, second, other),
            default_profile_ids={"unicom": first.id, "telecom": other.id},
            last_selected_profile_id=first.id,
        )
        save_settings(config, self.path)
        args = build_parser().parse_args([
            "login", "--profile", first.id, "--no-auto-wifi", "--try-next-account",
        ])
        calls = []

        def fake_login(candidate_args, mode, service, profile, *, remember_selection):
            calls.append((candidate_args.profile, mode, service, remember_selection))
            return 24 if len(calls) == 1 else 0

        with patch("ysu_net_watch.cli._run_login_once", side_effect=fake_login), patch(
            "ysu_net_watch.cli.ProfileStore.remember_selection"
        ) as remember:
            self.assertEqual(run_login(args), 0)

        self.assertEqual([call[0] for call in calls], [first.id, second.id])
        self.assertEqual([call[2] for call in calls], ["中国联通", "中国联通"])
        self.assertTrue(calls[0][3])
        self.assertFalse(calls[1][3])
        remember.assert_called_once_with(second.id)

    def test_account_fallback_is_opt_in_and_parser_exposes_console_switch(self):
        login = build_parser().parse_args(["login", "--mode", "campus", "--try-next-account"])
        watch = build_parser().parse_args(["watch", "--mode", "campus", "--try-next-account"])
        console = build_parser().parse_args(["console", "--try-next-account"])
        self.assertTrue(login.try_next_account)
        self.assertTrue(watch.try_next_account)
        self.assertTrue(console.try_next_account)
        self.assertFalse(build_parser().parse_args(["login", "--mode", "campus"]).try_next_account)

    def test_account_verify_parser_is_one_shot_and_safe_by_default(self):
        args = build_parser().parse_args([
            "account", "verify", "--profile", legacy_profile_id("campus"),
            "--no-auto-wifi",
        ])
        self.assertEqual(args.account_command, "verify")
        self.assertFalse(args.force_switch)
        self.assertFalse(args.auto_wifi)

    def test_account_verify_does_not_submit_when_another_session_is_online(self):
        args = build_parser().parse_args([
            "account", "verify", "--profile", legacy_profile_id("campus"),
            "--no-auto-wifi",
        ])
        portal = Mock()
        portal.status.return_value = PortalStatus(True, {})
        source = Mock()
        output = io.StringIO()
        with (
            redirect_stdout(output),
            patch("ysu_net_watch.cli.PortalClient", return_value=portal),
            patch("ysu_net_watch.cli.selected_credential_source", return_value=source),
        ):
            self.assertEqual(run_account_verify(args), 25)
        source.get.assert_not_called()
        portal.login.assert_not_called()
        self.assertIn("未提交", output.getvalue())

    def test_account_verify_submits_once_without_device_kick_or_selection_change(self):
        args = build_parser().parse_args([
            "account", "verify", "--profile", legacy_profile_id("campus"),
            "--no-auto-wifi",
        ])
        portal = Mock()
        portal.status.return_value = PortalStatus(False, {})
        portal.login.return_value = True
        source = Mock()
        source.get.return_value = SimpleNamespace(username="dummy", password="secret")
        output = io.StringIO()
        with (
            redirect_stdout(output),
            patch("ysu_net_watch.cli.PortalClient", return_value=portal),
            patch("ysu_net_watch.cli.selected_credential_source", return_value=source),
            patch("ysu_net_watch.cli.ProfileStore.remember_selection") as remember,
        ):
            self.assertEqual(run_account_verify(args), 0)
        portal.login.assert_called_once_with(
            "dummy", "secret", "校园网", force_switch=False,
            allow_device_release=False, allow_workflow_retry=False,
        )
        remember.assert_not_called()
        self.assertIn("试验成功", output.getvalue())

    def test_account_verify_maps_device_limit_to_terminal_code(self):
        args = build_parser().parse_args([
            "account", "verify", "--profile", legacy_profile_id("campus"),
            "--no-auto-wifi",
        ])
        portal = Mock()
        portal.status.return_value = PortalStatus(False, {})
        portal.login.side_effect = PortalError(
            "account_device_limit", "service_login", "认证设备数量已达到上限",
        )
        source = Mock()
        source.get.return_value = SimpleNamespace(username="dummy", password="secret")
        with (
            patch("ysu_net_watch.cli.PortalClient", return_value=portal),
            patch("ysu_net_watch.cli.selected_credential_source", return_value=source),
        ):
            self.assertEqual(run_account_verify(args), 24)

    def test_night_protection_is_a_visible_direct_toggle_enabled_by_default(self):
        choices = iter([5, 2, 4, 6])
        menus = []

        def menu(title, options, **_kwargs):
            menus.append((title() if callable(title) else title, list(options)))
            return next(choices)

        with patch("ysu_net_watch.cli.select_menu", side_effect=menu):
            self.assertEqual(run_console(enable_scheduler=False), 0)

        self.assertTrue("夜间保护：开" in menus[1][1][2])
        self.assertFalse(load_settings(self.path).night_pause_enabled)

    def test_night_protection_can_be_enabled_again_from_the_same_toggle(self):
        save_settings(replace(AppSettings(), night_pause_enabled=False), self.path)
        choices = iter([5, 2, 4, 6])
        menus = []

        def menu(title, options, **_kwargs):
            menus.append((title() if callable(title) else title, list(options)))
            return next(choices)

        with patch("ysu_net_watch.cli.select_menu", side_effect=menu):
            self.assertEqual(run_console(enable_scheduler=False), 0)

        self.assertIn("夜间保护：关", menus[1][1][2])
        self.assertTrue(load_settings(self.path).night_pause_enabled)

    def test_watch_fallback_updates_actual_profile_after_device_limit(self):
        first = AccountProfile(
            "00000000-0000-0000-0000-000000000011", "第一个校园网", "campus", "unicom",
        )
        second = AccountProfile(
            "00000000-0000-0000-0000-000000000012", "第二个校园网", "campus", "unicom",
        )
        save_settings(
            replace(
                AppSettings(), profiles=(first, second),
                default_profile_ids={"campus": first.id},
                last_selected_profile_id=first.id,
            ),
            self.path,
        )
        args = build_parser().parse_args([
            "watch", "--profile", first.id, "--no-auto-wifi", "--once",
            "--try-next-account", "--log-file", str(self.path.with_suffix(".log")),
        ])
        changed = []
        with patch("ysu_net_watch.cli.Watcher") as watcher, patch(
            "ysu_net_watch.cli.selected_credential_source", return_value=Mock()
        ):
            watcher.return_value.run.side_effect = [24, 0]
            self.assertEqual(
                run_watch(
                    args,
                    install_signal_handlers=False,
                    profile_changed=lambda profile: changed.append(profile.id),
                ),
                0,
            )

        self.assertEqual(watcher.call_count, 2)
        self.assertEqual(
            [call.kwargs["profile_id"] for call in watcher.call_args_list],
            [first.id, second.id],
        )
        self.assertEqual(changed, [second.id])

    def test_night_watch_does_not_connect_wifi_or_load_credentials(self):
        args = build_parser().parse_args([
            "watch", "--profile", legacy_profile_id("telecom"), "--once",
            "--log-file", str(self.path.with_suffix(".log")),
        ])
        source = Mock()
        with (
            patch("ysu_net_watch.cli.current_pause_reason", return_value="计划停网"),
            patch("ysu_net_watch.cli.WifiConnector") as wifi,
            patch("ysu_net_watch.cli.selected_credential_source", return_value=source),
            patch("ysu_net_watch.cli.ConnectivityChecker") as checker,
            patch("ysu_net_watch.cli.PortalClient") as portal,
        ):
            self.assertEqual(run_watch(args, install_signal_handlers=False), 22)
        wifi.return_value.connect.assert_not_called()
        checker.return_value.check.assert_not_called()
        source.get.assert_not_called()
        portal.assert_not_called()

    def test_pre_stopped_watch_never_connects_wifi_or_checks_network(self):
        args = build_parser().parse_args([
            "watch", "--profile", legacy_profile_id("telecom"),
            "--log-file", str(self.path.with_suffix(".log")),
        ])
        stop = threading.Event()
        stop.set()
        with patch("ysu_net_watch.cli.WifiConnector") as wifi, patch(
            "ysu_net_watch.cli.ConnectivityChecker"
        ) as checker:
            self.assertEqual(
                run_watch(args, external_stop_event=stop, install_signal_handlers=False),
                0,
            )
        wifi.assert_not_called()
        checker.assert_not_called()

    def test_unknown_wifi_resume_raises_so_watcher_can_retry(self):
        args = build_parser().parse_args([
            "watch", "--profile", legacy_profile_id("telecom"),
            "--log-file", str(self.path.with_suffix(".log")),
        ])
        with patch("ysu_net_watch.cli.current_pause_reason", return_value="计划停网"), patch(
            "ysu_net_watch.cli.WifiConnector"
        ) as wifi, patch("ysu_net_watch.cli.Watcher") as watcher:
            run_watch(args, install_signal_handlers=False)
        resume = watcher.call_args.kwargs["on_resume"]
        wifi.return_value.connection_info.return_value = SimpleNamespace(
            state=WifiConnectionState.UNKNOWN,
            reason="query failed",
        )
        with self.assertRaisesRegex(WifiError, "query failed"):
            resume()
        wifi.return_value.connect.assert_not_called()

    def test_portal_request_guard_checks_stop_night_and_wifi(self):
        args = build_parser().parse_args([
            "watch", "--profile", legacy_profile_id("telecom"),
            "--log-file", str(self.path.with_suffix(".log")),
        ])
        stop = threading.Event()
        with (
            patch("ysu_net_watch.cli.WifiConnector") as wifi,
            patch("ysu_net_watch.cli.ConnectivityChecker") as checker,
            patch("ysu_net_watch.cli.Watcher") as watcher,
            patch("ysu_net_watch.cli.PortalClient") as portal,
        ):
            checker.return_value.check.return_value = SimpleNamespace(state=ConnectivityState.ONLINE, reason="test")
            wifi.return_value.connect.return_value = SimpleNamespace(ssid="iYanDa", profile_created=False)
            wifi.return_value.current_ssid.return_value = "iYanDa"
            run_watch(args, external_stop_event=stop, install_signal_handlers=False)
            factory = watcher.call_args.kwargs["portal_factory"]
            factory()
            allowed = portal.call_args.kwargs["operation_allowed"]
            self.assertTrue(allowed())
            wifi.return_value.current_ssid.return_value = "Phone hotspot"
            self.assertFalse(allowed())
            wifi.return_value.current_ssid.return_value = "iYanDa"
            with patch("ysu_net_watch.cli.current_pause_reason", return_value="计划停网"):
                self.assertFalse(allowed())
            stop.set()
            self.assertFalse(allowed())

    def test_mutating_commands_cannot_race_existing_watcher(self):
        for command in (
            ["login", "--profile", legacy_profile_id("telecom")],
            ["logout"],
            ["account", "delete", "--profile", legacy_profile_id("telecom")],
            ["credential", "set", "--mode", "broadband"],
        ):
            with self.subTest(command=command), patch(
                "ysu_net_watch.cli.SingleInstanceLock.__enter__", side_effect=AlreadyRunningError()
            ), patch("ysu_net_watch.cli.run_login") as login, patch("ysu_net_watch.cli.run_account") as account:
                self.assertEqual(main(command), 5)
                login.assert_not_called()
                account.assert_not_called()

    def test_account_list_is_readonly_even_when_watcher_is_running(self):
        output = io.StringIO()
        with redirect_stdout(output), patch("ysu_net_watch.cli.SingleInstanceLock") as lock, patch(
            "ysu_net_watch.credentials._win_api"
        ) as credentials:
            self.assertEqual(main(["account", "list"]), 0)
        lock.assert_not_called()
        credentials.assert_not_called()
        self.assertIn(legacy_profile_id("telecom"), output.getvalue())

    def test_menu_add_default_and_timer_binding_preserve_secret_privacy(self):
        # Main -> settings -> accounts -> add -> telecom -> new profile/default
        # -> timers -> timer 2 / bind new profile / enable -> exit.
        choices = [4, 4, 2, 4, 1, 6, 6, 5, 1, 1, 3, 4, 0, 6, 10, 4, 6]
        output = io.StringIO()
        with (
            redirect_stdout(output),
            patch("ysu_net_watch.cli.select_menu", side_effect=choices),
            patch("builtins.input", side_effect=["Work Telecom", "dummy-private-user"]),
            patch("ysu_net_watch.cli.getpass.getpass", return_value="dummy-private-password"),
            patch("ysu_net_watch.profiles.write_windows_credential") as write,
        ):
            self.assertEqual(run_console(enable_scheduler=False), 0)
        config = load_settings(self.path)
        profile = next(p for p in config.profiles if p.label == "Work Telecom")
        self.assertEqual(config.default_profile_ids["telecom"], profile.id)
        self.assertEqual(config.timers[1].profile_id, profile.id)
        self.assertTrue(config.timers[1].enabled)
        self.assertEqual(config.timers[1].service, "telecom")
        write.assert_called_once()
        self.assertNotIn("dummy-private", self.path.read_text(encoding="utf-8"))
        self.assertNotIn("dummy-private", output.getvalue())

    def test_late_report_from_stopped_account_does_not_replace_new_status(self):
        launched = []
        ready = threading.Event()
        titles = []
        def watch(_args, *, external_stop_event, reporter, **_kwargs):
            launched.append(True)
            if len(launched) == 1:
                external_stop_event.wait(2)
                reporter("OLD_ACCOUNT_LATE_STATUS")
            else:
                reporter("NEW_ACCOUNT_STATUS")
                ready.set()
                external_stop_event.wait(2)
            return 0
        selected = iter([0, 1, 6])
        def menu(title, _options, **_kwargs):
            choice = next(selected)
            if choice == 5:
                self.assertTrue(ready.wait(2))
            titles.append(title() if callable(title) else title)
            return choice
        with patch("ysu_net_watch.cli.select_menu", side_effect=menu), patch(
            "ysu_net_watch.cli.run_watch", side_effect=watch
        ):
            self.assertEqual(run_console(enable_scheduler=False), 0)
        self.assertNotIn("OLD_ACCOUNT_LATE_STATUS", "\n".join(titles))
        self.assertIn("NEW_ACCOUNT_STATUS", "\n".join(titles))
