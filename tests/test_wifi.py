from __future__ import annotations

import os
import subprocess
import unittest
from unittest.mock import Mock, patch

from ysu_net_watch.wifi import (
    WifiConnectionState,
    WifiConnectResult,
    WifiConnector,
    WifiError,
)


def completed(returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, "", "")

def ssid_result(name: str) -> tuple[int, str]:
    return (
        0,
        "    State                  : connected\n"
        f"    SSID                   : {name}\n",
    )


class SequenceRunner:
    def __init__(self, *results: int | tuple[int, str]):
        self.results = iter(results)
        self.commands: list[list[str]] = []

    def __call__(self, command, **_kwargs):
        self.commands.append(command)
        value = next(self.results)
        if isinstance(value, tuple):
            return subprocess.CompletedProcess([], value[0], value[1], "")
        return completed(value)


class WifiConnectorTests(unittest.TestCase):
    def test_current_ssid_reads_connected_network(self) -> None:
        runner = Mock(
            return_value=subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    "    Name                   : Wi-Fi\n"
                    "    State                  : connected\n"
                    "    SSID                   : Phone Hotspot\n"
                    "    BSSID                  : 00:11:22:33:44:55\n"
                ),
                stderr="",
            )
        )

        ssid = WifiConnector(runner=runner).current_ssid()

        self.assertEqual(ssid, "Phone Hotspot")

    @patch("ysu_net_watch.wifi.os.name", "nt")
    def test_available_but_disconnected_wifi_is_distinguished(self) -> None:
        runner = Mock(
            return_value=subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    "    Name                   : Wi-Fi\n"
                    "    State                  : disconnected\n"
                ),
                stderr="",
            )
        )

        info = WifiConnector(runner=runner).connection_info()

        self.assertEqual(info.state, WifiConnectionState.DISCONNECTED)
        self.assertIsNone(info.ssid)

    @patch("ysu_net_watch.wifi.os.name", "nt")
    def test_missing_wireless_interface_is_unknown(self) -> None:
        runner = Mock(
            return_value=subprocess.CompletedProcess(
                [],
                0,
                stdout="There is no wireless interface on the system.\n",
                stderr="",
            )
        )

        info = WifiConnector(runner=runner).connection_info()

        self.assertEqual(info.state, WifiConnectionState.UNKNOWN)
    @patch("ysu_net_watch.wifi.os.name", "nt")
    def test_existing_profile_is_set_to_auto_and_connected(self) -> None:
        runner = SequenceRunner(0, 0, 0, ssid_result("iYanDa"))
        sleeps: list[float] = []
        connector = WifiConnector(
            "iYanDa",
            create_open_profile=False,
            runner=runner,
            sleeper=sleeps.append,
            settle_delay=3,
        )

        result = connector.connect()

        self.assertFalse(result.profile_created)
        self.assertEqual(runner.commands[1][:4], ["netsh", "wlan", "set", "profileparameter"])
        self.assertEqual(runner.commands[2][:3], ["netsh", "wlan", "connect"])
        self.assertEqual(sleeps, [1.0, 3])

    @patch("ysu_net_watch.wifi.os.name", "nt")
    def test_already_connected_target_is_reused_without_reconnecting(self) -> None:
        runner = SequenceRunner(ssid_result("iYanDa"))
        sleeps: list[float] = []
        connector = WifiConnector(
            "iYanDa",
            runner=runner,
            sleeper=sleeps.append,
            settle_delay=3,
        )

        result = connector.connect()

        self.assertEqual(result, WifiConnectResult("iYanDa", False))
        self.assertEqual(len(runner.commands), 1)
        self.assertEqual(sleeps, [3])

    @patch("ysu_net_watch.wifi.os.name", "nt")
    def test_missing_profile_creates_open_profile(self) -> None:
        runner = SequenceRunner(1, 0, 0, 0, 0, ssid_result("iYanDa"))
        connector = WifiConnector(
            "iYanDa", runner=runner, sleeper=lambda _seconds: None
        )

        result = connector.connect()

        self.assertTrue(result.profile_created)
        add_command = runner.commands[2]
        self.assertEqual(add_command[:4], ["netsh", "wlan", "add", "profile"])
        self.assertIn("user=current", add_command)

    @patch("ysu_net_watch.wifi.os.name", "nt")
    def test_incorrect_legacy_profile_is_removed_before_add(self) -> None:
        runner = SequenceRunner(
            1,
            (0, 'SSID name : "iYanda"'),
            0,
            0,
            0,
            0,
            ssid_result("iYanDa"),
        )
        connector = WifiConnector(
            "iYanDa", runner=runner, sleeper=lambda _seconds: None
        )

        connector.connect()

        self.assertEqual(
            runner.commands[2][:4], ["netsh", "wlan", "delete", "profile"]
        )
        self.assertEqual(
            runner.commands[3][:4], ["netsh", "wlan", "add", "profile"]
        )

    @patch("ysu_net_watch.wifi.os.name", "nt")
    def test_missing_profile_can_be_rejected(self) -> None:
        runner = SequenceRunner(0, 1)
        connector = WifiConnector(
            "iYanDa",
            create_open_profile=False,
            runner=runner,
            sleeper=lambda _seconds: None,
        )

        with self.assertRaises(WifiError):
            connector.connect()

        self.assertEqual(len(runner.commands), 2)

    @patch("ysu_net_watch.wifi.os.name", "nt")
    def test_transient_connect_failure_is_retried(self) -> None:
        runner = SequenceRunner(0, 0, 1, 0, ssid_result("iYanDa"))
        sleeps: list[float] = []
        connector = WifiConnector(
            "iYanDa",
            create_open_profile=False,
            runner=runner,
            sleeper=sleeps.append,
        )

        connector.connect()

        connect_commands = [
            command for command in runner.commands if command[:3] == ["netsh", "wlan", "connect"]
        ]
        self.assertEqual(len(connect_commands), 2)
        self.assertEqual(sleeps, [1.0, 2.0, 5.0])

    @patch("ysu_net_watch.wifi.os.name", "nt")
    def test_connect_request_is_rejected_when_target_ssid_never_appears(
        self,
    ) -> None:
        runner = SequenceRunner(
            0,
            0,
            0,
            *(ssid_result("Phone Hotspot") for _ in range(10)),
        )
        connector = WifiConnector(
            "iYanDa",
            create_open_profile=False,
            runner=runner,
            sleeper=lambda _seconds: None,
        )

        with self.assertRaisesRegex(WifiError, "target SSID was not confirmed"):
            connector.connect()

    @patch("ysu_net_watch.wifi.os.name", "nt")
    def test_netsh_failure_keeps_command_output(self) -> None:
        runner = Mock(
            side_effect=[
                subprocess.CompletedProcess(
                    [], 0, "", ""
                ),
                subprocess.CompletedProcess(
                    [], 1, "The profile was not found.", ""
                ),
            ]
        )
        connector = WifiConnector(
            "iYanDa",
            create_open_profile=False,
            runner=runner,
            sleeper=lambda _seconds: None,
        )

        with self.assertRaisesRegex(WifiError, "The profile was not found"):
            connector.connect()

    def test_invalid_ssid_is_rejected(self) -> None:
        with self.assertRaises(WifiError):
            WifiConnector("invalid\nssid")

    @unittest.skipIf(os.name == "nt", "non-Windows behavior test")
    def test_non_windows_is_rejected(self) -> None:
        with self.assertRaises(WifiError):
            WifiConnector("iYanDa").connect()


if __name__ == "__main__":
    unittest.main()
