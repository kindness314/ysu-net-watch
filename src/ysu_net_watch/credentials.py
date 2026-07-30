from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from dataclasses import dataclass
from typing import Protocol


class CredentialError(RuntimeError):
    pass


@dataclass(frozen=True)
class Credential:
    username: str
    password: str

    @property
    def masked_username(self) -> str:
        if len(self.username) <= 2:
            return "**"
        return "*" * (len(self.username) - 2) + self.username[-2:]


class CredentialSource(Protocol):
    def get(self) -> Credential:
        ...


ENV_NAMES = {
    "campus": ("YSU_CAMPUS_USERNAME", "YSU_CAMPUS_PASSWORD"),
    "broadband": ("YSU_BROADBAND_USERNAME", "YSU_BROADBAND_PASSWORD"),
}

WINDOWS_TARGETS = {
    "campus": "YSU-Net-Campus",
    "broadband": "YSU-Net-Broadband",
}


class EnvironmentCredentialSource:
    """Read environment credentials once, then remove them from this process."""

    def __init__(self, mode: str):
        self.username_name, self.password_name = ENV_NAMES[mode]
        self._cached: Credential | None = None

    def get(self) -> Credential:
        if self._cached is not None:
            return self._cached

        username = os.environ.get(self.username_name, "").strip()
        password = os.environ.get(self.password_name, "")
        if not username or not password:
            raise CredentialError(
                f"Missing {self.username_name} or {self.password_name}"
            )

        self._cached = Credential(username, password)
        os.environ.pop(self.username_name, None)
        os.environ.pop(self.password_name, None)
        return self._cached


if os.name == "nt":
    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class CREDENTIALW(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", wintypes.LPVOID),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    PCREDENTIALW = ctypes.POINTER(CREDENTIALW)


def _win_api():
    if os.name != "nt":
        raise CredentialError("Windows Credential Manager is only available on Windows")

    api = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(PCREDENTIALW)]
    api.CredReadW.restype = wintypes.BOOL
    api.CredWriteW.argtypes = [PCREDENTIALW, wintypes.DWORD]
    api.CredWriteW.restype = wintypes.BOOL
    api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    api.CredDeleteW.restype = wintypes.BOOL
    api.CredFree.argtypes = [wintypes.LPVOID]
    api.CredFree.restype = None
    return api


class WindowsCredentialSource:
    def __init__(self, mode: str):
        self.target = WINDOWS_TARGETS[mode]

    def get(self) -> Credential:
        api = _win_api()
        pointer = PCREDENTIALW()
        if not api.CredReadW(self.target, CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
            error = ctypes.get_last_error()
            raise CredentialError(
                f"Credential target {self.target!r} was not found (Windows error {error})"
            )

        try:
            item = pointer.contents
            blob = ctypes.string_at(item.CredentialBlob, item.CredentialBlobSize)
            password = blob.decode("utf-16-le")
            username = item.UserName or ""
            if not username or not password:
                raise CredentialError(f"Credential target {self.target!r} is incomplete")
            return Credential(username, password)
        finally:
            api.CredFree(pointer)


class FallbackCredentialSource:
    def __init__(self, *sources: CredentialSource):
        self.sources = sources

    def get(self) -> Credential:
        errors: list[str] = []
        for source in self.sources:
            try:
                return source.get()
            except CredentialError as exc:
                errors.append(str(exc))
        raise CredentialError("; ".join(errors))


def build_credential_source(mode: str, source: str) -> CredentialSource:
    if source == "env":
        return EnvironmentCredentialSource(mode)
    if source == "windows":
        return WindowsCredentialSource(mode)
    if os.name == "nt":
        return FallbackCredentialSource(
            WindowsCredentialSource(mode), EnvironmentCredentialSource(mode)
        )
    return EnvironmentCredentialSource(mode)


def write_windows_credential(mode: str, username: str, password: str) -> None:
    api = _win_api()
    target = WINDOWS_TARGETS[mode]
    encoded = password.encode("utf-16-le")
    blob = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
    item = CREDENTIALW()
    item.Type = CRED_TYPE_GENERIC
    item.TargetName = target
    item.Comment = "YSU network authentication"
    item.CredentialBlobSize = len(encoded)
    item.CredentialBlob = ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte))
    item.Persist = CRED_PERSIST_LOCAL_MACHINE
    item.UserName = username
    if not api.CredWriteW(ctypes.byref(item), 0):
        raise CredentialError(f"CredWrite failed with Windows error {ctypes.get_last_error()}")


def delete_windows_credential(mode: str) -> None:
    api = _win_api()
    target = WINDOWS_TARGETS[mode]
    if not api.CredDeleteW(target, CRED_TYPE_GENERIC, 0):
        error = ctypes.get_last_error()
        if error != 1168:
            raise CredentialError(f"CredDelete failed with Windows error {error}")
