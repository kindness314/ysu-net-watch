from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "YSUNetWatch"


def startup_command() -> str:
    executable = str(Path(sys.executable).resolve())
    arguments = [executable]
    if not getattr(sys, "frozen", False):
        arguments += ["-m", "ysu_net_watch"]
    arguments.append("console")
    command = subprocess.list2cmdline(arguments)
    if len(command) > 260:
        raise ValueError("程序路径过长，无法设置开机自启；请移到较短的固定路径")
    return command


class StartupManager:
    """Manage only this app's current-user logon entry; never store secrets."""

    def __init__(self, registry=None):
        if registry is None:
            if os.name != "nt":
                raise OSError("开机自启仅支持 Windows")
            import winreg
            registry = winreg
        self.registry = registry

    def command(self) -> str | None:
        registry = self.registry
        try:
            with registry.OpenKey(registry.HKEY_CURRENT_USER, RUN_KEY) as key:
                value, kind = registry.QueryValueEx(key, RUN_NAME)
        except FileNotFoundError:
            return None
        if kind != registry.REG_SZ or not isinstance(value, str):
            raise ValueError("本程序的自启项格式异常，请先关闭再重新开启")
        return value

    def enable(self) -> None:
        command = startup_command()
        registry = self.registry
        with registry.CreateKeyEx(
            registry.HKEY_CURRENT_USER, RUN_KEY, 0, registry.KEY_SET_VALUE,
        ) as key:
            registry.SetValueEx(key, RUN_NAME, 0, registry.REG_SZ, command)

    def disable(self) -> None:
        registry = self.registry
        try:
            with registry.OpenKey(
                registry.HKEY_CURRENT_USER, RUN_KEY, 0, registry.KEY_SET_VALUE,
            ) as key:
                registry.DeleteValue(key, RUN_NAME)
        except FileNotFoundError:
            pass
