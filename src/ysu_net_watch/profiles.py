from __future__ import annotations

import uuid
import warnings
from dataclasses import replace
from pathlib import Path

from .credentials import (
    CredentialError, WindowsCredentialSource,
    delete_windows_credential, write_windows_credential,
)
from .settings import (
    AccountProfile, AppSettings, MAX_PROFILES, SETTINGS_LOCK, VALID_MODES, VALID_SERVICES,
    legacy_profile_id, load_settings, save_settings, select_profile, service_key,
)


def validate_label(label: str) -> str:
    value = label.strip()
    if not value or len(value) > 40 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise CredentialError("别名应为 1～40 个可显示字符")
    return value


def credential_source(profile: AccountProfile) -> WindowsCredentialSource:
    if profile.legacy:
        if profile.id != legacy_profile_id(service_key(profile.mode, profile.service)):
            raise CredentialError("旧账号引用无效")
        return WindowsCredentialSource(profile.mode)
    return WindowsCredentialSource(
        profile.mode, profile_id=profile.id, revision=profile.credential_revision,
    )


class ProfileStore:
    """Store non-secret metadata; credential updates use copy-on-write revisions."""

    def __init__(self, path: Path | None = None):
        self.path = path

    def get(self, profile_id: str) -> AccountProfile:
        profile = next((p for p in load_settings(self.path).profiles if p.id == profile_id), None)
        if profile is None:
            raise CredentialError("账号档案不存在，请重新绑定账号")
        return profile

    def default(self, mode: str, service: str) -> AccountProfile:
        config = load_settings(self.path)
        key = service_key(mode, service)
        profile = self.get(config.default_profile_ids.get(key, ""))
        if service_key(profile.mode, profile.service) != key:
            raise CredentialError("常用账号与所选服务不匹配，请重新设置")
        return profile

    def _save_secret(self, profile: AccountProfile, username: str, password: str) -> None:
        if not username.strip() or not password:
            raise CredentialError("账号和密码不能为空")
        write_windows_credential(
            profile.mode, username.strip(), password,
            profile_id=profile.id, revision=profile.credential_revision,
        )

    @staticmethod
    def _delete_secret(profile: AccountProfile) -> None:
        if not profile.legacy:
            delete_windows_credential(
                profile.mode, profile_id=profile.id, revision=profile.credential_revision,
            )

    def create(self, label: str, mode: str, service: str, username: str, password: str) -> AccountProfile:
        if mode not in VALID_MODES or service not in VALID_SERVICES:
            raise CredentialError("认证服务无效")
        with SETTINGS_LOCK:
            config = load_settings(self.path)
            if len(config.profiles) >= MAX_PROFILES:
                raise CredentialError(f"最多保存 {MAX_PROFILES} 个账号档案")
            profile = AccountProfile(str(uuid.uuid4()), validate_label(label), mode, service)
            self._save_secret(profile, username, password)
            try:
                save_settings(replace(config, profiles=(*config.profiles, profile)), self.path)
            except Exception:
                self._delete_secret(profile)
                raise
            return profile

    def update_credentials(self, profile_id: str, username: str, password: str) -> AccountProfile:
        with SETTINGS_LOCK:
            config = load_settings(self.path)
            old = self.get(profile_id)
            updated = replace(old, credential_revision=old.credential_revision + 1, legacy=False)
            self._save_secret(updated, username, password)
            try:
                save_settings(replace(config, profiles=tuple(
                    updated if p.id == profile_id else p for p in config.profiles
                )), self.path)
            except Exception:
                self._delete_secret(updated)
                raise
            try:
                self._delete_secret(old)
            except CredentialError:
                # Committed metadata already points to the new credential. Never
                # roll it back because an obsolete secure item could not be removed.
                warnings.warn("新凭据已保存；旧版本凭据暂未清理", RuntimeWarning)
            return updated

    def rename(self, profile_id: str, label: str) -> None:
        with SETTINGS_LOCK:
            config = load_settings(self.path)
            self.get(profile_id)
            save_settings(replace(config, profiles=tuple(
                replace(p, label=validate_label(label)) if p.id == profile_id else p
                for p in config.profiles
            )), self.path)

    def set_default(self, profile_id: str) -> None:
        with SETTINGS_LOCK:
            config = load_settings(self.path)
            profile = self.get(profile_id)
            defaults = dict(config.default_profile_ids)
            defaults[service_key(profile.mode, profile.service)] = profile.id
            save_settings(select_profile(replace(
                config, default_profile_ids=defaults, mode=profile.mode, service=profile.service,
            ), profile.id), self.path)

    def remember_selection(self, profile_id: str) -> AppSettings:
        with SETTINGS_LOCK:
            config = load_settings(self.path)
            self.get(profile_id)
            updated = select_profile(config, profile_id)
            save_settings(updated, self.path)
            return updated

    def delete(self, profile_id: str, *, disable_timers: bool = False) -> None:
        with SETTINGS_LOCK:
            config = load_settings(self.path)
            profile = self.get(profile_id)
            if any(t.profile_id == profile_id for t in config.timers) and not disable_timers:
                raise CredentialError("账号被定时器引用，请先解除绑定或明确停用引用的定时器")
            updated = replace(
                config,
                last_selected_profile_id=(
                    None if config.last_selected_profile_id == profile_id
                    else config.last_selected_profile_id
                ),
                profiles=tuple(p for p in config.profiles if p.id != profile_id),
                default_profile_ids={k: v for k, v in config.default_profile_ids.items() if v != profile_id},
                timers=tuple(
                    replace(t, enabled=False, profile_id=None) if t.profile_id == profile_id else t
                    for t in config.timers
                ),
            )
            # Persist references first; a cleanup failure leaves an unused secure
            # item, never a configured account whose credential was already erased.
            save_settings(updated, self.path)
            try:
                self._delete_secret(profile)
            except CredentialError:
                warnings.warn("档案已删除；对应 Windows 凭据暂未清理", RuntimeWarning)


class ProfileCredentialSource:
    def __init__(self, profile_id: str, store: ProfileStore | None = None):
        self.profile_id = profile_id
        self.store = store or ProfileStore()

    def get(self):
        # Keep the metadata revision and Credential Manager read in one snapshot;
        # an update must not delete that revision between these two operations.
        with SETTINGS_LOCK:
            return credential_source(self.store.get(self.profile_id)).get()
