from __future__ import annotations

import io
import time
import unittest
import tempfile
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ysu_net_watch.cli import (
    APP_BANNER,
    build_parser,
    main,
    run_login,
    run_console,
    run_status,
    scheduled_skip_reason,
    scheduled_wifi_skip_reason,
    exit_code_text,
)
from ysu_net_watch.connectivity import ConnectivityState
from ysu_net_watch.instance import AlreadyRunningError
from ysu_net_watch.portal import PortalError
from ysu_net_watch.settings import AppSettings, legacy_profile_id, select_profile
from ysu_net_watch.wifi import WifiConnectionInfo, WifiConnectionState


class CliParserTests(unittest.TestCase):
    def test_status_error_is_sanitized(self) -> None:
        error = PortalError(
            "network_error",
            "status",
            "\x1b[2JsessionId=secret-session\nconnection failed",
        )
        with patch("ysu_net_watch.cli.PortalClient.status", side_effect=error), \
             patch("sys.stderr", new_callable=io.StringIO) as stderr:
            result = run_status()

        self.assertEqual(result, 1)
        output = stderr.getvalue()
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\nconnection", output)
        self.assertNotIn("secret-session", output)

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        settings_path = patch("ysu_net_watch.settings.default_settings_path",
                              return_value=Path(directory.name) / "settings.json")
        settings_path.start()
        self.addCleanup(settings_path.stop)
        pause = patch("ysu_net_watch.cli.current_pause_reason", return_value=None)
        pause.start()
        self.addCleanup(pause.stop)

    def test_login_timeout_has_network_exit_code(self) -> None:
        args = build_parser().parse_args([
            "login", "--mode", "broadband", "--service", "telecom", "--no-auto-wifi",
        ])
        portal = Mock()
        portal.login.side_effect = PortalError("timeout", "service_login", "timed out")
        source = Mock()
        source.get.return_value = SimpleNamespace(username="dummy", password="secret")
        with (
            patch("ysu_net_watch.cli.build_credential_source", return_value=source),
            patch("ysu_net_watch.cli.PortalClient", return_value=portal),
        ):
            self.assertEqual(run_login(args), 21)

    def test_login_password_rejection_has_terminal_exit_code(self) -> None:
        args = build_parser().parse_args([
            "login", "--mode", "broadband", "--service", "telecom", "--no-auto-wifi",
        ])
        portal = Mock()
        portal.login.side_effect = PortalError(
            "credential_rejected", "cas_login", "用户名或密码错误",
        )
        source = Mock()
        source.get.return_value = SimpleNamespace(username="dummy", password="secret")
        output = io.StringIO()
        with (
            redirect_stderr(output),
            patch("ysu_net_watch.cli.build_credential_source", return_value=source),
            patch("ysu_net_watch.cli.PortalClient", return_value=portal),
        ):
            self.assertEqual(run_login(args), 23)
        self.assertIn("退出码 23（账号或密码被门户拒绝，已停止重试）", output.getvalue())

    def test_login_ip_freeze_has_distinct_terminal_exit_code(self) -> None:
        args = build_parser().parse_args([
            "login", "--mode", "broadband", "--service", "telecom", "--no-auto-wifi",
        ])
        portal = Mock()
        portal.login.side_effect = PortalError(
            "ip_blocked", "service_login", "当前 IP 已被冻结",
        )
        source = Mock()
        source.get.return_value = SimpleNamespace(username="dummy", password="secret")
        output = io.StringIO()
        with (
            redirect_stderr(output),
            patch("ysu_net_watch.cli.build_credential_source", return_value=source),
            patch("ysu_net_watch.cli.PortalClient", return_value=portal),
        ):
            self.assertEqual(run_login(args), 26)
        self.assertIn("退出码 26（认证来源 IP 被门户冻结或封禁，已停止重试）", output.getvalue())

    def test_exit_code_text_explains_unknown_codes(self) -> None:
        self.assertEqual(
            exit_code_text(23),
            "退出码 23（账号或密码被门户拒绝，已停止重试）",
        )
        self.assertEqual(exit_code_text(999), "退出码 999（未知退出状态）")

    def test_schedule_skips_phone_hotspot(self) -> None:
        reason = scheduled_skip_reason("Phone Hotspot")
        self.assertIn("Phone Hotspot", reason)

    def test_schedule_does_not_skip_confirmed_iyanda(self) -> None:
        self.assertEqual(scheduled_skip_reason("iYanDa"), "")

    def test_schedule_prefers_not_to_switch_when_ssid_is_unknown_and_online(
        self,
    ) -> None:
        reason = scheduled_skip_reason(None, ConnectivityState.ONLINE)
        self.assertTrue(reason)

    def test_schedule_also_skips_when_ssid_and_network_are_unknown(self) -> None:
        reason = scheduled_skip_reason(None, ConnectivityState.UNKNOWN)
        self.assertTrue(reason)

    def test_schedule_connects_when_wifi_is_disconnected(self) -> None:
        reason = scheduled_wifi_skip_reason(
            WifiConnectionInfo(WifiConnectionState.DISCONNECTED)
        )
        self.assertEqual(reason, "")

    def test_schedule_skips_unknown_wifi_state(self) -> None:
        reason = scheduled_wifi_skip_reason(
            WifiConnectionInfo(WifiConnectionState.UNKNOWN)
        )
        self.assertTrue(reason)

    def test_watch_auto_connects_iyanda_by_default(self) -> None:
        args = build_parser().parse_args(["watch", "--mode", "campus"])

        self.assertTrue(args.auto_wifi)
        self.assertTrue(args.create_wifi_profile)
        self.assertEqual(args.wifi_ssid, "iYanDa")
        self.assertEqual(args.wifi_settle_delay, 5.0)

    def test_watch_can_disable_wifi_changes(self) -> None:
        args = build_parser().parse_args(
            ["watch", "--mode", "campus", "--no-auto-wifi"]
        )

        self.assertFalse(args.auto_wifi)

    def test_logout_has_wifi_options(self) -> None:
        args = build_parser().parse_args(["logout"])

        self.assertTrue(args.auto_wifi)
        self.assertEqual(args.wifi_ssid, "iYanDa")

    def test_no_arguments_open_console(self) -> None:
        with (
            patch("sys.argv", ["ysu-net-watch"]),
            patch("ysu_net_watch.cli.run_console", return_value=0) as console,
            patch("ysu_net_watch.cli.SingleInstanceLock"),
        ):
            code = main()

        self.assertEqual(code, 0)
        console.assert_called_once()

    def test_second_console_instance_exits_cleanly(self) -> None:
        with (
            patch("sys.argv", ["ysu-net-watch"]),
            patch(
                "ysu_net_watch.cli.SingleInstanceLock.__enter__",
                side_effect=AlreadyRunningError(),
            ),
            patch("ysu_net_watch.cli.run_console") as console,
        ):
            code = main()

        self.assertEqual(code, 5)
        console.assert_not_called()

    def test_console_can_logout_and_exit(self) -> None:
        output = io.StringIO()
        with (
            redirect_stdout(output),
            patch("builtins.input", side_effect=["4", "7"]),
            patch("ysu_net_watch.cli.run_logout", return_value=0) as logout,
        ):
            code = run_console(enable_scheduler=False)

        self.assertEqual(code, 0)
        logout.assert_called_once()
        self.assertIn(APP_BANNER, output.getvalue())
        self.assertIn("账号管理", output.getvalue())

    def test_main_menu_groups_daily_actions_before_account_and_settings(self) -> None:
        menus = []

        def menu(_title, options, **_kwargs):
            menus.append(list(options))
            return 6

        with patch("ysu_net_watch.cli.select_menu", side_effect=menu):
            self.assertEqual(run_console(enable_scheduler=False), 0)

        self.assertEqual(len(menus), 1)
        self.assertIn("监听校园网", menus[0][0])
        self.assertIn("默认宽带", menus[0][1])
        self.assertEqual(menus[0][2], "停止当前监听")
        self.assertEqual(menus[0][3], "当前认证账号下线")
        self.assertEqual(menus[0][4], "账号管理")
        self.assertEqual(menus[0][5], "修改常用/定时设置")
        self.assertEqual(menus[0][6], "退出程序")

    def test_console_saves_default_broadband_operator(self) -> None:
        with (
            patch(
                "builtins.input",
                side_effect=["6", "1", "2", "2", "5", "7"],
            ),
            patch(
                "ysu_net_watch.cli.load_settings",
                return_value=AppSettings(),
            ),
            patch("ysu_net_watch.cli.save_settings") as save,
        ):
            code = run_console(enable_scheduler=False)

        self.assertEqual(code, 0)
        save.assert_called_once_with(
            select_profile(AppSettings(
                mode="broadband",
                service="telecom",
            ), legacy_profile_id("telecom"))
        )

    def test_explicit_login_logs_out_before_switching_service(self) -> None:
        args = build_parser().parse_args(
            [
                "login",
                "--mode",
                "broadband",
                "--service",
                "unicom",
                "--no-auto-wifi",
            ]
        )
        portal = Mock()
        source = Mock()
        source.get.return_value = SimpleNamespace(
            username="student",
            password="secret",
        )
        with (
            patch("ysu_net_watch.cli.build_credential_source", return_value=source),
            patch("ysu_net_watch.cli.PortalClient", return_value=portal),
        ):
            code = run_login(args)

        self.assertEqual(code, 0)
        self.assertEqual(
            [call[0] for call in portal.method_calls],
            ["logout", "login"],
        )

    def test_console_can_enable_second_timer(self) -> None:
        initial = AppSettings()
        with (
            patch(
                "builtins.input",
                side_effect=["6", "2", "2", "1", "2", "7", "11", "5", "7"],
            ),
            patch("ysu_net_watch.cli.load_settings", return_value=initial),
            patch("ysu_net_watch.cli.save_settings") as save,
        ):
            code = run_console(enable_scheduler=False)

        self.assertEqual(code, 0)
        saved = save.call_args.args[0]
        self.assertTrue(saved.timers[1].enabled)
        self.assertEqual(len(saved.timers), 10)

    def test_empty_timer_time_returns_without_saving(self) -> None:
        initial = AppSettings()
        with (
            patch(
                "builtins.input",
                side_effect=["6", "2", "2", "2", "", "7", "11", "5", "7"],
            ),
            patch("ysu_net_watch.cli.load_settings", return_value=initial),
            patch("ysu_net_watch.cli.save_settings") as save,
        ):
            code = run_console(enable_scheduler=False)

        self.assertEqual(code, 0)
        save.assert_not_called()

    def test_stopping_worker_does_not_hold_status_lock_while_joining(
        self,
    ) -> None:
        def worker(
            _args,
            *,
            external_stop_event,
            install_signal_handlers,
            reporter,
            remember_selection,
        ):
            self.assertFalse(install_signal_handlers)
            self.assertFalse(remember_selection)
            external_stop_event.wait(2)
            reporter("监听线程已停止")
            return 0

        started = time.monotonic()
        with (
            patch("builtins.input", side_effect=["1", "3", "7"]),
            patch("ysu_net_watch.cli.run_logout", return_value=0),
            patch("ysu_net_watch.cli.run_watch", side_effect=worker),
        ):
            code = run_console(enable_scheduler=False)

        self.assertEqual(code, 0)
        self.assertLess(time.monotonic() - started, 3)


if __name__ == "__main__":
    unittest.main()
