from __future__ import annotations

import ctypes
import os
import sys
import time
from ctypes import wintypes
from typing import Callable


class _Coord(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


class _SmallRect(ctypes.Structure):
    _fields_ = [
        ("Left", ctypes.c_short),
        ("Top", ctypes.c_short),
        ("Right", ctypes.c_short),
        ("Bottom", ctypes.c_short),
    ]


class _ConsoleScreenBufferInfo(ctypes.Structure):
    _fields_ = [
        ("dwSize", _Coord),
        ("dwCursorPosition", _Coord),
        ("wAttributes", ctypes.c_ushort),
        ("srWindow", _SmallRect),
        ("dwMaximumWindowSize", _Coord),
    ]


def _windows_console_api():
    if os.name != "nt":
        return None, None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
    kernel32.GetStdHandle.restype = wintypes.HANDLE
    kernel32.GetConsoleScreenBufferInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ConsoleScreenBufferInfo),
    ]
    kernel32.GetConsoleScreenBufferInfo.restype = wintypes.BOOL
    kernel32.SetConsoleCursorPosition.argtypes = [wintypes.HANDLE, _Coord]
    kernel32.SetConsoleCursorPosition.restype = wintypes.BOOL
    return kernel32, kernel32.GetStdHandle(-11)


def _get_cursor_position() -> _Coord | None:
    kernel32, handle = _windows_console_api()
    if kernel32 is None or not handle:
        return None
    info = _ConsoleScreenBufferInfo()
    if not kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(info)):
        return None
    return _Coord(info.dwCursorPosition.X, info.dwCursorPosition.Y)


def _set_cursor_position(position: _Coord | None) -> bool:
    if position is None:
        return False
    kernel32, handle = _windows_console_api()
    if kernel32 is None or not handle:
        return False
    return bool(kernel32.SetConsoleCursorPosition(handle, position))


def _enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    kernel32, handle = _windows_console_api()
    if kernel32 is None or not handle:
        return
    kernel32.GetConsoleMode.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetConsoleMode.restype = wintypes.BOOL
    kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.SetConsoleMode.restype = wintypes.BOOL
    mode = ctypes.c_uint()
    if handle and kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)


def clear_console() -> None:
    """Clear only an interactive console; captured/non-interactive output is preserved."""
    if not sys.stdout.isatty():
        return
    _enable_windows_ansi()
    sys.stdout.write("\x1b[2J\x1b[H")
    sys.stdout.flush()


def _fallback_menu(title: str, options: list[str]) -> int | None:
    print(title)
    for index, option in enumerate(options, start=1):
        print(f"{index}. {option}")
    value = input(f"选择 [1-{len(options)}]: ").strip()
    if value.isdigit() and 1 <= int(value) <= len(options):
        return int(value) - 1
    return None


def select_menu(
    title: str | Callable[[], str],
    options: list[str],
    selected: int = 0,
) -> int | None:
    title_provider = title if callable(title) else lambda: title
    if (
        os.name != "nt"
        or not sys.stdin.isatty()
        or not sys.stdout.isatty()
    ):
        return _fallback_menu(title_provider(), options)

    import msvcrt

    _enable_windows_ansi()
    # Nested and long menus may make the Windows console scroll.  Starting every
    # menu from a freshly cleared viewport keeps the saved cursor origin valid
    # while arrow-key redraws take place.
    clear_console()
    selected = min(max(selected, 0), len(options) - 1)
    menu_origin = _get_cursor_position()
    previous_height = 0
    rendered_title = ""

    def render(move_up: bool) -> None:
        nonlocal previous_height, rendered_title
        rendered_title = title_provider()
        title_lines = rendered_title.splitlines() or [""]
        if move_up:
            if not _set_cursor_position(menu_origin):
                sys.stdout.write("\r\x1b[2K")
                sys.stdout.write(f"\x1b[{previous_height}F")
        for line in title_lines:
            sys.stdout.write(f"\x1b[2K{line}\n")
        for index, option in enumerate(options):
            if index == selected:
                line = f"\x1b[7m> {index + 1}. {option}\x1b[0m"
            else:
                line = f"  {index + 1}. {option}"
            sys.stdout.write(f"\x1b[2K{line}\n")
        sys.stdout.write(
            "\x1b[2K↑/↓ 移动，Enter 确认；> 是选择光标，● 是当前监听"
        )
        sys.stdout.flush()
        previous_height = len(title_lines) + len(options)

    render(False)
    while True:
        if callable(title):
            while not msvcrt.kbhit():
                time.sleep(0.1)
                if title_provider() != rendered_title:
                    render(True)
        key = msvcrt.getwch()
        if key in {"\x00", "\xe0"}:
            scan = msvcrt.getwch()
            if scan == "H":
                selected = (selected - 1) % len(options)
                render(True)
            elif scan == "P":
                selected = (selected + 1) % len(options)
                render(True)
        elif key in {"\r", "\n"}:
            sys.stdout.write("\r\x1b[2K\n")
            sys.stdout.flush()
            return selected
        elif key.isdigit() and 1 <= int(key) <= len(options):
            selected = int(key) - 1
            render(True)
            sys.stdout.write("\r\x1b[2K\n")
            sys.stdout.flush()
            return selected
        elif key == "\x1b":
            sys.stdout.write("\r\x1b[2K\n")
            sys.stdout.flush()
            return None
        elif key == "\x03":
            raise KeyboardInterrupt
