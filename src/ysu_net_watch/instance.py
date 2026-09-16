from __future__ import annotations

import os


class AlreadyRunningError(RuntimeError):
    pass


class SingleInstanceLock:
    """Keep one long-running watcher process per Windows machine."""

    def __init__(self, name: str = r"Global\kindness314.ysu-net-watch") -> None:
        self.name = name
        self._handle: int | None = None
        self._kernel32 = None

    def acquire(self) -> None:
        if os.name != "nt" or self._handle is not None:
            return

        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.CreateMutexW(None, False, self.name)
        if not handle:
            raise OSError(ctypes.get_last_error(), "Windows mutex could not be created")
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(handle)
            raise AlreadyRunningError("another ysu-net-watch process is already running")

        self._kernel32 = kernel32
        self._handle = handle

    def close(self) -> None:
        if self._handle is None:
            return
        if self._kernel32 is None:
            # Keep close() safe even if a partially initialized instance is
            # cleaned up after an API failure.
            self._handle = None
            return
        self._kernel32.CloseHandle(self._handle)
        self._handle = None
        self._kernel32 = None

    def __enter__(self) -> SingleInstanceLock:
        self.acquire()
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()
