from __future__ import annotations

import html
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable


class WifiError(RuntimeError):
    pass


@dataclass(frozen=True)
class WifiConnectResult:
    ssid: str
    profile_created: bool


class WifiConnectionState(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class WifiConnectionInfo:
    state: WifiConnectionState
    ssid: str | None = None


class WifiConnector:
    """Configure and connect a Windows WLAN profile without storing secrets."""

    def __init__(
        self,
        ssid: str = "iYanDa",
        *,
        create_open_profile: bool = True,
        settle_delay: float = 5.0,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        if not ssid or len(ssid) > 32 or any(char in ssid for char in "\r\n\0"):
            raise WifiError("Wi-Fi SSID must contain 1 to 32 valid characters")
        self.ssid = ssid
        self.create_open_profile = create_open_profile
        self.settle_delay = max(0.0, settle_delay)
        self.runner = runner
        self.sleeper = sleeper

    def _run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return self.runner(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WifiError("Windows Wi-Fi command could not be executed") from exc

    def connection_info(self) -> WifiConnectionInfo:
        if os.name != "nt":
            return WifiConnectionInfo(WifiConnectionState.UNKNOWN)
        result = self._run(["netsh", "wlan", "show", "interfaces"])
        if result.returncode != 0:
            return WifiConnectionInfo(WifiConnectionState.UNKNOWN)
        for line in result.stdout.splitlines():
            match = re.match(r"^\s*SSID\s*:\s*(.+?)\s*$", line)
            if match and not line.lstrip().startswith("BSSID"):
                return WifiConnectionInfo(
                    WifiConnectionState.CONNECTED,
                    match.group(1),
                )
        # A successful query with at least one interface but no SSID means the
        # adapter is available and currently disconnected. If no interface can
        # be identified, fail closed instead of assuming switching is safe.
        if re.search(r"(?im)^\s*(?:Name|名称)\s*:", result.stdout):
            return WifiConnectionInfo(WifiConnectionState.DISCONNECTED)
        return WifiConnectionInfo(WifiConnectionState.UNKNOWN)

    def current_ssid(self) -> str | None:
        return self.connection_info().ssid

    def _add_open_profile(self) -> None:
        escaped_ssid = html.escape(self.ssid, quote=False)
        profile = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{escaped_ssid}</name>
  <SSIDConfig>
    <SSID><name>{escaped_ssid}</name></SSID>
    <nonBroadcast>false</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <autoSwitch>false</autoSwitch>
  <MSM>
    <security>
      <authEncryption>
        <authentication>open</authentication>
        <encryption>none</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
    </security>
  </MSM>
</WLANProfile>
"""
        try:
            with tempfile.TemporaryDirectory(prefix="ysu-net-watch-") as directory:
                path = Path(directory) / "wifi-profile.xml"
                path.write_text(profile, encoding="utf-8")
                added = self._run(
                    ["netsh", "wlan", "add", "profile", f"filename={path}", "user=current"]
                )
        except OSError as exc:
            raise WifiError("Temporary Wi-Fi profile could not be created") from exc
        if added.returncode != 0:
            raise WifiError(
                f"Windows could not add the open Wi-Fi profile (exit {added.returncode})"
            )

    def _repair_legacy_iyanda_profile(self) -> None:
        if self.ssid != "iYanDa":
            return
        legacy = self._run(
            ["netsh", "wlan", "show", "profile", "name=iYanda"]
        )
        # Profile names are matched case-insensitively by netsh. Inspect the
        # quoted SSID value so a correct iYanDa profile is never removed.
        if legacy.returncode != 0 or '"iYanda"' not in legacy.stdout:
            return
        deleted = self._run(
            ["netsh", "wlan", "delete", "profile", "name=iYanda"]
        )
        if deleted.returncode != 0:
            raise WifiError(
                "Windows could not remove the obsolete iYanda Wi-Fi profile"
            )

    def connect(self) -> WifiConnectResult:
        if os.name != "nt":
            raise WifiError("automatic Wi-Fi connection is supported only on Windows")

        profile_created = False
        if self.create_open_profile:
            # Always update the current-user profile. This also repairs a profile
            # created with an incorrect case-sensitive SSID by an older release.
            self._repair_legacy_iyanda_profile()
            self._add_open_profile()
            profile_created = True

        auto = self._run(
            [
                "netsh",
                "wlan",
                "set",
                "profileparameter",
                f"name={self.ssid}",
                "connectionmode=auto",
            ]
        )
        if auto.returncode != 0:
            message = (
                f"Wi-Fi profile {self.ssid!r} does not exist or cannot be updated"
                if not self.create_open_profile
                else f"Windows could not enable automatic connection for {self.ssid!r}"
            )
            raise WifiError(message)

        # Windows may need a moment to apply a newly added/updated profile.
        self.sleeper(1.0)
        connected = None
        for attempt in range(3):
            connected = self._run(
                [
                    "netsh",
                    "wlan",
                    "connect",
                    f"name={self.ssid}",
                    f"ssid={self.ssid}",
                ]
            )
            if connected.returncode == 0:
                break
            if attempt < 2:
                self.sleeper(2.0)
        if connected is None or connected.returncode != 0:
            raise WifiError(
                f"Windows could not connect to Wi-Fi {self.ssid!r} "
                f"after 3 attempts (exit {connected.returncode if connected else 'unknown'})"
            )

        # `netsh wlan connect` only confirms that Windows accepted the
        # connection request. Poll the interface until the requested SSID is
        # actually active before reporting success or allowing authentication.
        observed_ssid: str | None = None
        for verification_attempt in range(10):
            observed_ssid = self.current_ssid()
            if (
                observed_ssid is not None
                and observed_ssid.casefold() == self.ssid.casefold()
            ):
                break
            if verification_attempt < 9:
                self.sleeper(1.0)
        else:
            detail = (
                f"; current Wi-Fi is {observed_ssid!r}"
                if observed_ssid
                else "; no connected Wi-Fi was detected"
            )
            raise WifiError(
                f"Windows accepted the connection request for {self.ssid!r}, "
                f"but the target SSID was not confirmed{detail}"
            )

        self.sleeper(self.settle_delay)
        return WifiConnectResult(self.ssid, profile_created)
