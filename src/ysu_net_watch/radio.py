from __future__ import annotations

import base64
import os
import re
import subprocess
from typing import Callable

from .process import sanitized_child_environment, windows_powershell_executable
from .wifi import WifiError


# The helper only changes Wi-Fi Off -> On. It neither toggles other radios nor
# changes adapter/flight-mode/privacy policy. ASCII result codes avoid locale
# parsing and prevent arbitrary PowerShell output from reaching the UI.
RADIO_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$allowChange = __ALLOW_CHANGE__
function Finish([string]$status, [int]$code = 0) {
    [Console]::WriteLine('YSU_WIFI_RADIO:' + $status)
    exit $code
}
try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $null = [Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime]
    $null = [Windows.Devices.Radios.RadioState,Windows.System.Devices,ContentType=WindowsRuntime]
    $null = [Windows.Devices.Radios.RadioAccessStatus,Windows.System.Devices,ContentType=WindowsRuntime]
    $asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and
        $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    } | Select-Object -First 1
    function AwaitRadio($operation, [Type]$resultType) {
        $task = $asTask.MakeGenericMethod($resultType).Invoke($null, @($operation))
        if (-not $task.Wait(10000)) { throw 'radio_task_timeout' }
        $task.GetAwaiter().GetResult()
    }
    $radios = @(AwaitRadio ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]]))
    $wifi = @($radios | Where-Object { $_.Kind.ToString() -eq 'WiFi' })
    if ($wifi.Count -eq 0) { Finish 'no_radio' 1 }
    if (@($wifi | Where-Object { $_.State.ToString() -eq 'On' }).Count -gt 0) {
        Finish 'already_on'
    }
    $candidate = $wifi | Where-Object { $_.State.ToString() -eq 'Off' } | Select-Object -First 1
    if ($null -eq $candidate) {
        if (@($wifi | Where-Object { $_.State.ToString() -eq 'Unknown' }).Count -gt 0) {
            Finish 'unknown' 1
        }
        Finish 'disabled' 1
    }
    if (-not $allowChange) { Finish 'off' }
    $access = AwaitRadio ([Windows.Devices.Radios.Radio]::RequestAccessAsync()) ([Windows.Devices.Radios.RadioAccessStatus])
    if ($access.ToString() -ne 'Allowed') { Finish ('access_' + $access.ToString()) 1 }
    $result = AwaitRadio ($candidate.SetStateAsync([Windows.Devices.Radios.RadioState]::On)) ([Windows.Devices.Radios.RadioAccessStatus])
    if ($result.ToString() -ne 'Allowed') { Finish ('access_' + $result.ToString()) 1 }
    for ($i = 0; $i -lt 15; $i++) {
        if ($candidate.State.ToString() -eq 'On') { Finish 'turned_on' }
        if ($candidate.State.ToString() -eq 'Disabled') { Finish 'disabled' 1 }
        Start-Sleep -Milliseconds 200
    }
    Finish 'not_confirmed' 1
} catch {
    Finish 'operation_failed' 1
}
"""

RADIO_ERRORS = {
    "no_radio": "未找到可控制的 Wi-Fi 无线设备；请检查网卡、驱动或系统禁用状态",
    "unknown": "Wi-Fi 无线设备尚未就绪，无法确认软件开关状态",
    "disabled": "Wi-Fi 被硬件开关、设备或系统策略禁用；请手动检查无线开关和飞行模式",
    "access_DeniedByUser": "Windows 未允许无线控制权限；请在系统设置中允许控制无线设备",
    "access_DeniedBySystem": "Windows 系统策略禁止控制无线开关；请检查系统权限或联系管理员",
    "access_Unspecified": "Windows 未明确授予无线控制权限，未尝试强行开启",
    "not_confirmed": "Windows 接受了 Wi-Fi 开启请求，但软件开关仍未确认打开",
    "operation_failed": "Windows 无线控制接口调用失败；请手动打开 Wi-Fi 并检查系统支持和权限",
}


class WifiRadio:
    def __init__(self, *, runner=subprocess.run, operation_allowed: Callable[[], bool] | None = None):
        self.runner = runner
        self.operation_allowed = operation_allowed or (lambda: True)

    def query(self, *, allow_change: bool = False) -> str:
        if os.name != "nt":
            raise WifiError("自动开启 Wi-Fi 软件开关仅支持 Windows")
        if not self.operation_allowed():
            raise WifiError("Wi-Fi operation was cancelled")
        script = RADIO_SCRIPT.replace("__ALLOW_CHANGE__", "$true" if allow_change else "$false")
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        try:
            result = self.runner(
                [windows_powershell_executable(), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                capture_output=True, text=True, errors="replace", timeout=40,
                check=False, env=sanitized_child_environment(),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise WifiError("自动开启 Wi-Fi 超时，已停止本次操作；请手动检查无线开关") from exc
        except OSError as exc:
            raise WifiError("无法执行 Windows 无线控制接口；请手动打开 Wi-Fi") from exc
        if not self.operation_allowed():
            raise WifiError("Wi-Fi operation was cancelled")
        matches = re.findall(r"(?m)^YSU_WIFI_RADIO:([A-Za-z_]+)\r?$", result.stdout or "")
        if len(matches) != 1:
            raise WifiError("Windows 无线控制结果无效，未确认开启 Wi-Fi")
        status = matches[0]
        successes = {"already_on", "turned_on"} if allow_change else {"already_on", "off"}
        if result.returncode == 0 and status in successes:
            return status
        raise WifiError(RADIO_ERRORS.get(status, "Windows 无线控制结果无效，未确认开启 Wi-Fi"))

    def ensure_on(self) -> bool:
        return self.query(allow_change=True) == "turned_on"
