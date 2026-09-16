from __future__ import annotations

import json
import os
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path


VALID_MODES = {"campus", "broadband"}
VALID_SERVICES = {"unicom", "telecom", "mobile"}
MAX_TIMERS = 10
WEEKDAYS = (0, 1, 2, 3, 4)
ALL_DAYS = (0, 1, 2, 3, 4, 5, 6)
SETTINGS_LOCK = threading.RLock()
MAX_PROFILES = 20


def valid_profile_id(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def service_key(mode: str, service: str) -> str:
    return "campus" if mode == "campus" else service


def legacy_profile_id(key: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"ysu-net-watch/legacy/{key}"))


@dataclass(frozen=True)
class AccountProfile:
    id: str
    label: str
    mode: str
    service: str
    credential_revision: int = 1
    legacy: bool = False


def legacy_profiles() -> tuple[AccountProfile, ...]:
    names = {"campus": "旧校园网", "unicom": "旧宽带·联通",
             "telecom": "旧宽带·电信", "mobile": "旧宽带·移动"}
    return tuple(
        AccountProfile(legacy_profile_id(key), label,
                       "campus" if key == "campus" else "broadband",
                       "unicom" if key == "campus" else key, legacy=True)
        for key, label in names.items()
    )


def legacy_defaults() -> dict[str, str]:
    return {key: legacy_profile_id(key) for key in ("campus", "unicom", "telecom", "mobile")}


@dataclass(frozen=True)
class TimerSettings:
    enabled: bool = False
    time: str = "06:00"
    weekdays: tuple[int, ...] = WEEKDAYS
    mode: str = "broadband"
    service: str = "unicom"
    retry_time: str | None = None
    profile_id: str | None = None


def default_timers(
    mode: str = "broadband",
    service: str = "unicom",
    *,
    enabled: bool = True,
) -> tuple[TimerSettings, ...]:
    first = TimerSettings(
        enabled=enabled,
        time="06:00",
        weekdays=WEEKDAYS,
        mode=mode,
        service=service,
        retry_time="08:00",
        profile_id=legacy_profile_id(service_key(mode, service)),
    )
    return (first,) + tuple(TimerSettings() for _ in range(MAX_TIMERS - 1))


@dataclass(frozen=True)
class AppSettings:
    mode: str = "broadband"
    service: str = "unicom"
    timers: tuple[TimerSettings, ...] = default_timers()
    schema_version: int = 2
    profiles: tuple[AccountProfile, ...] = field(default_factory=legacy_profiles)
    default_profile_ids: dict[str, str] = field(default_factory=legacy_defaults)
    night_pause_enabled: bool = True
    # Only an opaque profile ID is remembered, never credentials.
    last_selected_profile_id: str | None = field(
        default_factory=lambda: legacy_profile_id("unicom"),
    )


def follow_last_selection(settings: AppSettings) -> AppSettings:
    """Timer 1 follows the remembered manual target; timers 2-10 stay fixed."""
    if not settings.timers:
        return settings
    profile = next(
        (p for p in settings.profiles if p.id == settings.last_selected_profile_id), None,
    )
    first = replace(settings.timers[0], profile_id=settings.last_selected_profile_id)
    if profile is not None:
        first = replace(first, mode=profile.mode, service=profile.service)
    # Missing/deleted references stay missing. Never pick another account.
    return replace(settings, timers=(first, *settings.timers[1:]))


def select_profile(settings: AppSettings, profile_id: str) -> AppSettings:
    if not any(p.id == profile_id for p in settings.profiles):
        raise ValueError("账号档案不存在，未改变定时器")
    return follow_last_selection(replace(settings, last_selected_profile_id=profile_id))


def default_settings_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "YSUNetWatch" / "settings.json"
    return Path.home() / ".ysu-net-watch" / "settings.json"


def load_settings(path: Path | None = None) -> AppSettings:
    target = path or default_settings_path()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return AppSettings()
    except (ValueError, TypeError) as exc:
        raise ValueError("设置文件损坏，已停止读取账号；请恢复设置备份") from exc
    if not isinstance(payload, dict):
        raise ValueError("设置格式无效，已停止读取账号")
    schema_version = payload.get("schema_version")
    if schema_version is not None and type(schema_version) is not int:
        raise ValueError("设置版本字段无效，已停止读取账号")
    if schema_version is not None and schema_version > 2:
        raise ValueError("设置由更新版本创建，请使用更新版本程序")
    mode = payload.get("mode")
    service = payload.get("service")
    if schema_version == 2 and (
        not isinstance(mode, str)
        or mode not in VALID_MODES
        or not isinstance(service, str)
        or service not in VALID_SERVICES
    ):
        raise ValueError("当前版本设置中的认证模式无效，已停止读取账号")
    valid_mode = mode if isinstance(mode, str) and mode in VALID_MODES else "broadband"
    valid_service = (
        service if isinstance(service, str) and service in VALID_SERVICES else "unicom"
    )
    raw_timers = payload.get("timers")
    if schema_version == 2 and (
        not isinstance(raw_timers, list)
        or not 1 <= len(raw_timers) <= MAX_TIMERS
        or any(not isinstance(raw, dict) for raw in raw_timers)
    ):
        raise ValueError("当前版本设置中的定时器格式无效，已停止读取账号")
    timers: list[TimerSettings] = []
    if isinstance(raw_timers, list):
        for index, raw in enumerate(raw_timers[:MAX_TIMERS]):
            if schema_version == 2:
                _validate_current_timer_payload(raw, index)
            timer = _parse_timer(raw)
            timers.append(timer)
    if not timers:
        legacy_enabled = payload.get("weekday_schedule")
        timers = list(
            default_timers(
                valid_mode,
                valid_service,
                enabled=legacy_enabled if isinstance(legacy_enabled, bool) else True,
            )
        )
    while len(timers) < MAX_TIMERS:
        timers.append(TimerSettings())
    if schema_version != 2:
        profiles = legacy_profiles()
        defaults = legacy_defaults()
        timers = [
            replace(timer, profile_id=legacy_profile_id(service_key(timer.mode, timer.service)))
            for timer in timers
        ]
    else:
        profiles_list = []
        seen = set()
        for raw in payload.get("profiles", []) if isinstance(payload.get("profiles"), list) else []:
            if not isinstance(raw, dict) or not valid_profile_id(raw.get("id")):
                continue
            raw_mode = raw.get("mode")
            raw_service = raw.get("service")
            if (
                raw["id"] in seen
                or not isinstance(raw_mode, str)
                or raw_mode not in VALID_MODES
                or not isinstance(raw_service, str)
                or raw_service not in VALID_SERVICES
            ):
                continue
            label = raw.get("label")
            revision = raw.get("credential_revision", 1)
            if (not isinstance(label, str) or not label.strip() or len(label) > 40
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in label)
                    or type(revision) is not int or not 1 <= revision <= 1_000_000):
                continue
            seen.add(raw["id"])
            profiles_list.append(AccountProfile(
                raw["id"], label, raw_mode, raw_service, revision,
                legacy=raw.get("legacy") is True,
            ))
        profiles = tuple(profiles_list[:MAX_PROFILES])
        raw_defaults = payload.get("default_profile_ids", {})
        defaults = {
            key: value for key, value in raw_defaults.items()
            if key in {"campus", *VALID_SERVICES} and isinstance(value, str)
        } if isinstance(raw_defaults, dict) else {}
    # Older versions did not remember manual selections. Migrate from the
    # explicitly configured common account, not timer 1's stale carrier.
    selected_id = payload.get(
        "last_selected_profile_id", defaults.get(service_key(valid_mode, valid_service)),
    )
    return follow_last_selection(AppSettings(
        mode=valid_mode,
        service=valid_service,
        timers=tuple(timers),
        profiles=profiles,
        default_profile_ids=defaults,
        night_pause_enabled=payload.get("night_pause_enabled", True) is not False,
        last_selected_profile_id=selected_id if isinstance(selected_id, str) else None,
    ))


def valid_time(value: object) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"\d{2}:\d{2}", value):
        return False
    hour, minute = (int(part) for part in value.split(":"))
    return 0 <= hour <= 23 and 0 <= minute <= 59


def _validate_current_timer_payload(value: object, index: int) -> None:
    number = index + 1
    if not isinstance(value, dict):
        raise ValueError(f"定时器 {number} 的设置格式无效")
    primary = value.get("time")
    retry = value.get("retry_time")
    weekdays = value.get("weekdays")
    mode = value.get("mode")
    service = value.get("service")
    profile_id = value.get("profile_id")
    if type(value.get("enabled")) is not bool:
        raise ValueError(f"定时器 {number} 的开关字段无效")
    if not valid_time(primary):
        raise ValueError(f"定时器 {number} 的执行时间无效")
    if (
        not isinstance(weekdays, list)
        or not weekdays
        or any(type(day) is not int or not 0 <= day <= 6 for day in weekdays)
        or len(set(weekdays)) != len(weekdays)
    ):
        raise ValueError(f"定时器 {number} 的执行日期无效")
    if not isinstance(mode, str) or mode not in VALID_MODES:
        raise ValueError(f"定时器 {number} 的认证模式无效")
    if not isinstance(service, str) or service not in VALID_SERVICES:
        raise ValueError(f"定时器 {number} 的运营商无效")
    if retry is not None and not valid_time(retry):
        raise ValueError(f"定时器 {number} 的补偿时间无效")
    if retry is not None and retry <= primary:
        raise ValueError(f"定时器 {number} 的补偿时间必须晚于执行时间")
    if profile_id is not None and not isinstance(profile_id, str):
        raise ValueError(f"定时器 {number} 的账号引用无效")


def validate_timer_settings(timer: TimerSettings, index: int) -> None:
    _validate_current_timer_payload(
        {
            "enabled": timer.enabled,
            "time": timer.time,
            "weekdays": (
                list(timer.weekdays)
                if isinstance(timer.weekdays, tuple)
                else timer.weekdays
            ),
            "mode": timer.mode,
            "service": timer.service,
            "retry_time": timer.retry_time,
            "profile_id": timer.profile_id,
        },
        index,
    )


def _parse_timer(value: object) -> TimerSettings:
    if not isinstance(value, dict):
        return TimerSettings()
    raw_days = value.get("weekdays")
    days = (
        tuple(
            sorted(
                {
                    day
                    for day in raw_days
                    if isinstance(day, int) and not isinstance(day, bool) and 0 <= day <= 6
                }
            )
        )
        if isinstance(raw_days, list)
        else WEEKDAYS
    )
    mode = value.get("mode")
    service = value.get("service")
    retry_time = value.get("retry_time")
    return TimerSettings(
        enabled=value.get("enabled") is True,
        time=value.get("time") if valid_time(value.get("time")) else "06:00",
        weekdays=days or WEEKDAYS,
        mode=mode if isinstance(mode, str) and mode in VALID_MODES else "broadband",
        service=(
            service
            if isinstance(service, str) and service in VALID_SERVICES
            else "unicom"
        ),
        retry_time=retry_time if valid_time(retry_time) else None,
        # Keep broken references visible; never redirect a timer to another account.
        profile_id=value.get("profile_id") if isinstance(value.get("profile_id"), str) else None,
    )


def save_settings(settings: AppSettings, path: Path | None = None) -> Path:
    settings = follow_last_selection(settings)
    if not 1 <= len(settings.timers) <= MAX_TIMERS:
        raise ValueError("定时器数量无效")
    for index, timer in enumerate(settings.timers):
        validate_timer_settings(timer, index)
    target = path or default_settings_path()
    with SETTINGS_LOCK:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raw = target.read_text(encoding="utf-8")
            previous = json.loads(raw)
            backup = target.with_suffix(".legacy-v1.json")
            if isinstance(previous, dict) and previous.get("schema_version") != 2 and not backup.exists():
                backup.write_text(raw, encoding="utf-8")
            if isinstance(previous, dict) and previous.get("schema_version") == 2 and "last_selected_profile_id" not in previous:
                backup = target.with_suffix(".pre-timer-follow.json")
                if not backup.exists():
                    backup.write_text(raw, encoding="utf-8")
        temporary = target.with_name(f"{target.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_text(
                json.dumps(asdict(settings), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    return target
