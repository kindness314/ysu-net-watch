from __future__ import annotations

import io
import time
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ysu_net_watch.cli import (
    APP_BANNER,
    build_parser,
    main,
    run_login,
    run_console,
    scheduled_skip_reason,
    scheduled_wifi_skip_reason,
)
from ysu_net_watch.connectivity import ConnectivityState
from ysu_net_watch.settings import AppSettings
from ysu_net_watch.wifi import WifiConnectionInfo, WifiConnectionState


class CliParserTests(unittest.TestCase):
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
        ):
            code = main()

        self.assertEqual(code, 0)
        console.assert_called_once()

    def test_console_can_logout_and_exit(self) -> None:
        output = io.StringIO()
        with (
            redirect_stdout(output),
            patch("builtins.input", side_effect=["4", "6"]),
            patch("ysu_net_watch.cli.run_logout", return_value=0) as logout,
        ):
            code = run_console(enable_scheduler=False)

        self.assertEqual(code, 0)
        logout.assert_called_once()
        self.assertIn(APP_BANNER, output.getvalue())

    def test_console_saves_default_broadband_operator(self) -> None:
        with (
            patch(
                "builtins.input",
                side_effect=["3", "1", "2", "2", "3", "6"],
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
            AppSettings(
                mode="broadband",
                service="telecom",
            )
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
                side_effect=["3", "2", "2", "1", "7", "11", "3", "6"],
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
                side_effect=["3", "2", "2", "2", "", "7", "11", "3", "6"],
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
        ):
            self.assertFalse(install_signal_handlers)
            external_stop_event.wait(2)
            reporter("监听线程已停止")
            return 0

        started = time.monotonic()
        with (
            patch("builtins.input", side_effect=["1", "5", "6"]),
            patch("ysu_net_watch.cli.run_logout", return_value=0),
            patch("ysu_net_watch.cli.run_watch", side_effect=worker),
        ):
            code = run_console(enable_scheduler=False)

        self.assertEqual(code, 0)
        self.assertLess(time.monotonic() - started, 3)


if __name__ == "__main__":
    unittest.main()
