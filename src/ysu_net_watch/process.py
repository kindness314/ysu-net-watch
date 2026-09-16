from __future__ import annotations

import os
from pathlib import Path


AUTH_ENV_NAMES = frozenset(
    {
        "ysu_campus_username",
        "ysu_campus_password",
        "ysu_broadband_username",
        "ysu_broadband_password",
    }
)


def sanitized_child_environment() -> dict[str, str]:
    """Return an inherited environment without authentication secrets."""
    return {
        key: value
        for key, value in os.environ.items()
        if key.casefold() not in AUTH_ENV_NAMES
    }


def windows_system_executable(filename: str) -> str:
    """Resolve a trusted executable from the real Windows system directory."""
    if os.name != "nt":
        return filename
    if Path(filename).name != filename or not filename.lower().endswith(".exe"):
        raise ValueError("system executable must be a plain .exe filename")

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel32.GetSystemDirectoryW.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if not length or length >= len(buffer):
        raise OSError(ctypes.get_last_error(), "Windows system directory is unavailable")

    executable = Path(buffer.value) / filename
    if not executable.is_file():
        raise FileNotFoundError(f"trusted Windows executable was not found: {executable}")
    return str(executable)
