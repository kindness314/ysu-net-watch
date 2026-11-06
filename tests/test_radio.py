from __future__ import annotations

import base64
import subprocess
import unittest
from unittest.mock import Mock, patch

from ysu_net_watch.radio import WifiRadio
from ysu_net_watch.wifi import WifiError


class WifiRadioTests(unittest.TestCase):
    def setUp(self):
        platform = patch("ysu_net_watch.radio.os.name", "nt")
        platform.start()
        self.addCleanup(platform.stop)
        path = patch("ysu_net_watch.radio.windows_powershell_executable", return_value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        path.start()
        self.addCleanup(path.stop)

    def runner(self, status, returncode=0):
        return Mock(return_value=subprocess.CompletedProcess([], returncode, "YSU_WIFI_RADIO:" + status + "\r\n", ""))

    def test_already_on_is_confirmed_without_reporting_a_change(self):
        runner = self.runner("already_on")
        self.assertFalse(WifiRadio(runner=runner).ensure_on())
        runner.assert_called_once()
        self.assertEqual(runner.call_args.kwargs["timeout"], 40)

    def test_confirmed_radio_enable_and_no_credentials_in_child_environment(self):
        runner = self.runner("turned_on")
        with patch.dict("os.environ", {"YSU_CAMPUS_PASSWORD": "test-private-secret", "YSU_BROADBAND_USERNAME": "test-private-user"}):
            self.assertTrue(WifiRadio(runner=runner).ensure_on())
        env = runner.call_args.kwargs["env"]
        self.assertNotIn("YSU_CAMPUS_PASSWORD", env)
        self.assertNotIn("YSU_BROADBAND_USERNAME", env)
        script = base64.b64decode(runner.call_args.args[0][-1]).decode("utf-16-le")
        self.assertIn("$allowChange = $true", script)
        self.assertNotIn("test-private", script)

    def test_readonly_off_query_cannot_be_reported_as_enabled(self):
        runner = self.runner("off")
        self.assertEqual(WifiRadio(runner=runner).query(), "off")
        script = base64.b64decode(runner.call_args.args[0][-1]).decode("utf-16-le")
        self.assertIn("$allowChange = $false", script)
        with self.assertRaises(WifiError):
            WifiRadio(runner=runner).ensure_on()

    def test_permission_hardware_and_unconfirmed_results_stop_once(self):
        for status in ("access_DeniedByUser", "access_DeniedBySystem", "disabled", "no_radio", "not_confirmed", "unknown", "operation_failed"):
            with self.subTest(status=status):
                runner = self.runner(status, 1)
                with self.assertRaises(WifiError):
                    WifiRadio(runner=runner).ensure_on()
                runner.assert_called_once()

    def test_untrusted_or_ambiguous_output_never_reports_success(self):
        for output, code in (("YSU_WIFI_RADIO:turned_on\n", 1), ("unexpected\x1b[2J output", 0),
                             ("YSU_WIFI_RADIO:already_on\nYSU_WIFI_RADIO:turned_on\n", 0)):
            with self.subTest(output=output):
                runner = Mock(return_value=subprocess.CompletedProcess([], code, output, ""))
                with self.assertRaises(WifiError) as error:
                    WifiRadio(runner=runner).ensure_on()
                self.assertNotIn("\x1b", str(error.exception))

    def test_timeout_and_cancel_never_succeed_or_retry(self):
        runner = Mock(side_effect=subprocess.TimeoutExpired("powershell", 40))
        with self.assertRaisesRegex(WifiError, "超时"):
            WifiRadio(runner=runner).ensure_on()
        runner.assert_called_once()
        runner.reset_mock()
        with self.assertRaisesRegex(WifiError, "cancelled"):
            WifiRadio(runner=runner, operation_allowed=lambda: False).ensure_on()
        runner.assert_not_called()
