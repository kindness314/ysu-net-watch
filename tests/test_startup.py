from __future__ import annotations

from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime
import io
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from ysu_net_watch.cli import (
    apply_console_wifi_options, build_parser, run_console, run_watch,
    scheduled_wifi_skip_reason, wait_for_startup_wifi,
)
from ysu_net_watch.connectivity import ConnectivityResult, ConnectivityState
from ysu_net_watch.settings import AppSettings, load_settings, save_settings, select_profile, legacy_profile_id
from ysu_net_watch.startup import RUN_KEY, RUN_NAME, StartupManager, startup_command
from ysu_net_watch.wifi import WifiConnectionInfo, WifiConnectionState


class RegistryStartupTests(unittest.TestCase):
    def test_frozen_command_quotes_executable_without_secrets(self):
        with patch("sys.frozen", True, create=True), patch("sys.executable", r"C:\Program Files\YSU Net Watch\watch.exe"):
            command = startup_command()
        self.assertEqual(command, '"C:\\Program Files\\YSU Net Watch\\watch.exe" console')
        self.assertNotIn("profile", command)
        self.assertNotIn("password", command)

    def test_source_command_uses_module_without_relying_on_working_directory(self):
        with patch("sys.frozen", False, create=True), patch("sys.executable", r"C:\YSU\.venv\Scripts\python.exe"):
            command = startup_command()
        self.assertEqual(command, r"C:\YSU\.venv\Scripts\python.exe -m ysu_net_watch console")

    def test_overlong_registration_is_rejected_before_registry_write(self):
        registry = Mock()
        with patch("sys.executable", "C:\\" + "a" * 261 + "\\watch.exe"):
            with self.assertRaisesRegex(ValueError, "路径过长"):
                StartupManager(registry).enable()
        registry.CreateKeyEx.assert_not_called()

    def test_registry_enable_and_disable_touch_only_our_current_user_value(self):
        registry = MagicMock()
        key = registry.CreateKeyEx.return_value.__enter__.return_value = Mock()
        key2 = registry.OpenKey.return_value.__enter__.return_value = Mock()
        with patch("ysu_net_watch.startup.startup_command", return_value=r"C:\YSU\watch.exe console"):
            manager = StartupManager(registry)
            manager.enable()
            manager.disable()
        registry.CreateKeyEx.assert_called_once_with(registry.HKEY_CURRENT_USER, RUN_KEY, 0, registry.KEY_SET_VALUE)
        registry.SetValueEx.assert_called_once_with(key, RUN_NAME, 0, registry.REG_SZ, r"C:\YSU\watch.exe console")
        registry.DeleteValue.assert_called_once_with(key2, RUN_NAME)
        registry.DeleteKey.assert_not_called()

    def test_disable_missing_value_is_idempotent(self):
        registry = Mock()
        registry.OpenKey.side_effect = FileNotFoundError
        StartupManager(registry).disable()
        registry.DeleteValue.assert_not_called()


class StartupAndNetworkTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "settings.json"
        pref = patch("ysu_net_watch.settings.default_settings_path", return_value=self.path)
        pref.start()
        self.addCleanup(pref.stop)
        pause = patch("ysu_net_watch.cli.current_pause_reason", return_value=None)
        pause.start()
        self.addCleanup(pause.stop)

    def config(self, **values):
        settings = replace(AppSettings(), **values)
        save_settings(settings, self.path)
        return settings

    def test_old_settings_keep_manual_start_and_hotspot_protection(self):
        self.assertFalse(load_settings(self.path).auto_watch_on_start)
        self.assertFalse(load_settings(self.path).auto_enable_wifi)
        self.assertEqual(load_settings(self.path).wifi_ssid, "iYanDa")
        self.assertEqual(load_settings(self.path).automatic_wifi_policy, "preserve")

    def test_preferences_round_trip_and_reject_invalid_automatic_fields(self):
        expected = self.config(auto_watch_on_start=True, auto_enable_wifi=True, wifi_ssid="Campus AP", automatic_wifi_policy="switch")
        self.assertEqual(load_settings(self.path), expected)
        good = json.loads(self.path.read_text(encoding="utf-8"))
        for field, value in (("auto_watch_on_start", "true"), ("wifi_ssid", "bad\x1bSSID"),
                             ("wifi_ssid", "校" * 11), ("automatic_wifi_policy", []), ("auto_enable_wifi", "true")):
            with self.subTest(field=field, value=value):
                payload = dict(good)
                payload[field] = value
                self.path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_settings(self.path)

    def test_network_policy_custom_target_and_unknown_state(self):
        hotspot = WifiConnectionInfo(WifiConnectionState.CONNECTED, "Phone")
        self.assertTrue(scheduled_wifi_skip_reason(hotspot, target_ssid="Campus AP"))
        self.assertEqual(scheduled_wifi_skip_reason(hotspot, target_ssid="Campus AP", allow_switch=True), "")
        self.assertTrue(scheduled_wifi_skip_reason(WifiConnectionInfo(WifiConnectionState.UNKNOWN), allow_switch=True))
        self.assertEqual(scheduled_wifi_skip_reason(WifiConnectionInfo(WifiConnectionState.CONNECTED, "Campus AP"), target_ssid="Campus AP"), "")

    def test_custom_network_never_creates_open_wifi_profile(self):
        args = build_parser().parse_args(["watch", "--mode", "campus"])
        apply_console_wifi_options(args, replace(AppSettings(), wifi_ssid="Campus AP"))
        self.assertEqual(args.wifi_ssid, "Campus AP")
        self.assertFalse(args.create_wifi_profile)

    def test_delayed_adapter_readiness_and_cancel_are_bounded(self):
        connector = Mock()
        connector.connection_info.side_effect = [WifiConnectionInfo(WifiConnectionState.UNKNOWN), WifiConnectionInfo(WifiConnectionState.DISCONNECTED)]
        stop = Mock()
        stop.is_set.return_value = False
        stop.wait.return_value = False
        self.assertEqual(wait_for_startup_wifi(connector, stop, Mock()).state, WifiConnectionState.DISCONNECTED)
        stop.wait.assert_called_once_with(15)
        connector.connection_info.side_effect = None
        connector.connection_info.return_value = WifiConnectionInfo(WifiConnectionState.UNKNOWN)
        connector.reset_mock()
        stop.wait.reset_mock()
        self.assertEqual(wait_for_startup_wifi(connector, stop, Mock()).state, WifiConnectionState.UNKNOWN)
        self.assertEqual(connector.connection_info.call_count, 12)
        self.assertEqual(stop.wait.call_count, 11)
        stop.is_set.return_value = True
        connector.reset_mock()
        wait_for_startup_wifi(connector, stop, Mock())
        connector.connection_info.assert_not_called()

    def test_console_start_uses_last_selected_account_once(self):
        settings = select_profile(replace(AppSettings(), auto_watch_on_start=True, wifi_ssid="Campus AP"), legacy_profile_id("telecom"))
        save_settings(settings, self.path)
        started = threading.Event()
        calls = []
        def watch(args, *, external_stop_event, **kwargs):
            calls.append(args)
            started.set()
            external_stop_event.wait(2)
            return 0
        def menu(*args, **kwargs):
            self.assertTrue(started.wait(2))
            return 6
        with patch("ysu_net_watch.cli.run_watch", side_effect=watch), patch("ysu_net_watch.cli.select_menu", side_effect=menu):
            self.assertEqual(run_console(enable_scheduler=False), 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].profile, legacy_profile_id("telecom"))
        self.assertEqual(calls[0].wifi_ssid, "Campus AP")
        self.assertTrue(calls[0].automatic_start)
        self.assertFalse(calls[0].create_wifi_profile)

    def test_console_default_off_does_not_start_network_or_register(self):
        self.config()
        with patch("ysu_net_watch.cli.run_watch") as watch, patch("ysu_net_watch.cli.StartupManager") as startup, patch("ysu_net_watch.cli.select_menu", return_value=6):
            self.assertEqual(run_console(enable_scheduler=False), 0)
        watch.assert_not_called()
        startup.assert_not_called()

    def test_startup_defers_to_due_timer_without_second_auth_cycle(self):
        self.config(auto_watch_on_start=True)
        started = threading.Event()
        def watch(args, **kwargs):
            self.assertTrue(args.automatic_start)
            started.set()
            return 23
        def supervisor(stop, tick, on_error, on_recovered):
            tick()
            self.assertTrue(started.wait(2))
            tick()
            stop.wait(2)
        def menu(*args, **kwargs):
            self.assertTrue(started.wait(2))
            return 6
        with patch("ysu_net_watch.cli.datetime") as clock, patch("ysu_net_watch.cli.WifiConnector") as wifi, patch("ysu_net_watch.cli.run_watch", side_effect=watch) as worker, patch("ysu_net_watch.cli.supervise_schedule", side_effect=supervisor), patch("ysu_net_watch.cli.select_menu", side_effect=menu):
            clock.now.return_value = datetime(2026, 10, 8, 6)
            wifi.return_value.connection_info.return_value = WifiConnectionInfo(WifiConnectionState.CONNECTED, "iYanDa")
            self.assertEqual(run_console(schedule_state_path=None), 0)
        worker.assert_called_once()

    def test_network_menu_save_and_cancel_do_not_start_authentication(self):
        self.config()
        with patch("ysu_net_watch.cli.StartupManager") as manager, patch("ysu_net_watch.cli.select_menu", side_effect=[5, 4, 2, 1, 5, 5, 6]), patch("builtins.input", return_value="Campus AP"), patch("ysu_net_watch.cli.run_watch") as watcher:
            manager.return_value.command.return_value = None
            self.assertEqual(run_console(enable_scheduler=False), 0)
        self.assertEqual(load_settings(self.path).wifi_ssid, "Campus AP")
        watcher.assert_not_called()
        with patch("ysu_net_watch.cli.StartupManager") as manager, patch("ysu_net_watch.cli.select_menu", side_effect=[5, 4, 2, 1, 5, 5, 6]), patch("builtins.input", return_value=""):
            manager.return_value.command.return_value = None
            self.assertEqual(run_console(enable_scheduler=False), 0)
        self.assertEqual(load_settings(self.path).wifi_ssid, "Campus AP")

    def test_menu_enables_startup_with_automatic_watch_and_rolls_back_on_error(self):
        for failure in (False, True):
            with self.subTest(failure=failure):
                self.config()
                with patch("ysu_net_watch.cli.StartupManager") as manager, patch("ysu_net_watch.cli.select_menu", side_effect=[5, 4, 0, 5, 5, 6]):
                    manager.return_value.command.return_value = None
                    if failure:
                        manager.return_value.enable.side_effect = PermissionError("denied")
                    self.assertEqual(run_console(enable_scheduler=False), 0)
                    manager.return_value.enable.assert_called_once()
                self.assertEqual(load_settings(self.path).auto_watch_on_start, not failure)

    def automatic_watch_args(self):
        args = build_parser().parse_args(["watch", "--profile", legacy_profile_id("unicom"), "--once", "--log-file", str(self.path.with_suffix(".log"))])
        args.automatic_start = True
        args.automatic_wifi_policy = "preserve"
        return args

    def test_menu_radio_setting_is_opt_in_without_changing_wifi_now(self):
        self.config()
        with patch("ysu_net_watch.cli.StartupManager") as manager, patch("ysu_net_watch.cli.select_menu", side_effect=[5, 4, 4, 5, 5, 6]), patch("ysu_net_watch.cli.WifiConnector") as wifi:
            manager.return_value.command.return_value = None
            self.assertEqual(run_console(enable_scheduler=False), 0)
        self.assertTrue(load_settings(self.path).auto_enable_wifi)
        wifi.assert_not_called()

    def test_enable_wifi_then_select_network_then_monitor_in_order(self):
        self.config()
        args = self.automatic_watch_args()
        args.auto_enable_wifi = True
        steps = []
        with patch("ysu_net_watch.cli.WifiConnector") as wifi, patch("ysu_net_watch.cli.ConnectivityChecker") as checker, patch("ysu_net_watch.cli.Watcher") as watcher, patch("ysu_net_watch.cli.selected_credential_source", return_value=Mock()):
            wifi.return_value.enable_radio.side_effect = lambda: steps.append("radio") or True
            wifi.return_value.connection_info.side_effect = lambda: steps.append("status") or WifiConnectionInfo(WifiConnectionState.DISCONNECTED)
            wifi.return_value.connect.side_effect = lambda: steps.append("connect") or SimpleNamespace(ssid="iYanDa", profile_created=False)
            checker.return_value.check.return_value = SimpleNamespace(state=ConnectivityState.ONLINE, reason="test")
            watcher.return_value.run.side_effect = lambda **kwargs: steps.append("monitor") or 0
            self.assertEqual(run_watch(args, install_signal_handlers=False), 0)
        self.assertEqual(steps, ["radio", "status", "connect", "monitor"])

    def test_radio_failure_never_connects_or_submits_credentials(self):
        from ysu_net_watch.wifi import WifiError
        self.config()
        args = self.automatic_watch_args()
        args.auto_enable_wifi = True
        with patch("ysu_net_watch.cli.WifiConnector") as wifi, patch("ysu_net_watch.cli.selected_credential_source") as source, patch("ysu_net_watch.cli.Watcher") as watcher:
            wifi.return_value.enable_radio.side_effect = WifiError("系统策略禁止控制无线开关")
            self.assertEqual(run_watch(args, install_signal_handlers=False), 40)
        wifi.return_value.connect.assert_not_called()
        source.assert_not_called()
        watcher.assert_not_called()

    def test_startup_on_hotspot_never_connects_reads_credentials_or_authenticates(self):
        self.config()
        with patch("ysu_net_watch.cli.WifiConnector") as wifi, patch("ysu_net_watch.cli.selected_credential_source") as source, patch("ysu_net_watch.cli.Watcher") as watcher:
            wifi.return_value.connection_info.return_value = WifiConnectionInfo(WifiConnectionState.CONNECTED, "Phone")
            self.assertEqual(run_watch(self.automatic_watch_args(), install_signal_handlers=False), 0)
        wifi.return_value.connect.assert_not_called()
        source.assert_not_called()
        watcher.assert_not_called()

    def test_startup_with_unknown_wifi_stops_without_submitting_credentials(self):
        self.config()
        with patch("ysu_net_watch.cli.wait_for_startup_wifi", return_value=WifiConnectionInfo(WifiConnectionState.UNKNOWN, reason="permission denied")), patch("ysu_net_watch.cli.WifiConnector") as wifi, patch("ysu_net_watch.cli.selected_credential_source") as source, patch("ysu_net_watch.cli.Watcher") as watcher:
            self.assertEqual(run_watch(self.automatic_watch_args(), install_signal_handlers=False), 40)
        wifi.return_value.connect.assert_not_called()
        source.assert_not_called()
        watcher.assert_not_called()

    def test_startup_at_night_keeps_protection_before_network_operations(self):
        self.config()
        args = self.automatic_watch_args()
        args.auto_enable_wifi = True
        source = Mock()
        with patch("ysu_net_watch.cli.current_pause_reason", return_value="计划停网"), patch("ysu_net_watch.cli.wait_for_startup_wifi") as wait, patch("ysu_net_watch.cli.WifiConnector") as wifi, patch("ysu_net_watch.cli.selected_credential_source", return_value=source), patch("ysu_net_watch.cli.Watcher") as watcher:
            watcher.return_value.run.return_value = 22
            self.assertEqual(run_watch(args, install_signal_handlers=False), 22)
        wait.assert_not_called()
        wifi.return_value.connect.assert_not_called()
        wifi.return_value.enable_radio.assert_not_called()
        source.get.assert_not_called()

    def test_console_logout_uses_configured_network(self):
        self.config(wifi_ssid="Campus AP")
        with patch("ysu_net_watch.cli.select_menu", side_effect=[3, 6]), patch("ysu_net_watch.cli.run_logout", return_value=0) as logout:
            self.assertEqual(run_console(enable_scheduler=False), 0)
        self.assertEqual(logout.call_args.args[0].wifi_ssid, "Campus AP")
        self.assertFalse(logout.call_args.args[0].create_wifi_profile)

    def test_startup_on_target_and_opt_in_switch_preserve_existing_online_session(self):
        self.config()
        for ssid, policy in (("iYanDa", "preserve"), ("Phone", "switch"), (None, "preserve")):
            with self.subTest(ssid=ssid, policy=policy):
                args = self.automatic_watch_args()
                args.automatic_wifi_policy = policy
                with patch("ysu_net_watch.cli.WifiConnector") as wifi, patch("ysu_net_watch.cli.ConnectivityChecker") as checker, patch("ysu_net_watch.cli.Watcher") as watcher, patch("ysu_net_watch.cli.selected_credential_source", return_value=Mock()):
                    wifi.return_value.connection_info.return_value = WifiConnectionInfo(WifiConnectionState.CONNECTED if ssid else WifiConnectionState.DISCONNECTED, ssid)
                    wifi.return_value.connect.return_value = SimpleNamespace(ssid="iYanDa", profile_created=False)
                    checker.return_value.check.return_value = SimpleNamespace(state=ConnectivityState.ONLINE, reason="test")
                    watcher.return_value.run.return_value = 0
                    self.assertEqual(run_watch(args, install_signal_handlers=False), 0)
                    wifi.return_value.connect.assert_called_once()
                    self.assertFalse(watcher.call_args.kwargs["force_switch"])
                    self.assertFalse(watcher.return_value.run.call_args.kwargs["authenticate_on_start"])

    def test_automatic_watch_online_skips_credentials_and_portal_even_if_portal_offline(self):
        self.config()
        args = self.automatic_watch_args()
        source = Mock()
        with patch("ysu_net_watch.cli.WifiConnector") as wifi, patch(
            "ysu_net_watch.cli.ConnectivityChecker"
        ) as checker, patch("ysu_net_watch.cli.selected_credential_source", return_value=source), patch(
            "ysu_net_watch.cli.PortalClient"
        ) as portal:
            wifi.return_value.connection_info.return_value = WifiConnectionInfo(WifiConnectionState.CONNECTED, "iYanDa")
            wifi.return_value.current_ssid.return_value = "iYanDa"
            wifi.return_value.connect.return_value = SimpleNamespace(ssid="iYanDa", profile_created=False)
            checker.return_value.check.return_value = ConnectivityResult(ConnectivityState.ONLINE, "test")
            portal.return_value.status.return_value = SimpleNamespace(online=False)
            self.assertEqual(run_watch(args, install_signal_handlers=False), 0)
        source.get.assert_not_called()
        portal.assert_not_called()

    def test_manual_watch_still_switches_accounts_when_internet_online(self):
        from ysu_net_watch.credentials import Credential
        self.config()
        args = self.automatic_watch_args()
        args.automatic_start = False
        source = Mock(get=Mock(return_value=Credential("dummy", "dummy")))
        with patch("ysu_net_watch.cli.WifiConnector") as wifi, patch(
            "ysu_net_watch.cli.ConnectivityChecker"
        ) as checker, patch("ysu_net_watch.cli.selected_credential_source", return_value=source), patch(
            "ysu_net_watch.cli.PortalClient"
        ) as portal, patch("ysu_net_watch.cli.AuthProtection"):
            wifi.return_value.connect.return_value = SimpleNamespace(ssid="iYanDa", profile_created=False)
            wifi.return_value.current_ssid.return_value = "iYanDa"
            checker.return_value.check.return_value = ConnectivityResult(ConnectivityState.ONLINE, "test")
            portal.return_value.login.return_value = True
            self.assertEqual(run_watch(args, install_signal_handlers=False), 0)
        source.get.assert_called_once()
        self.assertTrue(portal.return_value.login.call_args.kwargs["force_switch"])


if __name__ == "__main__":
    unittest.main()
