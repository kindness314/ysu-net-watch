from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path


VALID_MODES = {"campus", "broadband"}
VALID_SERVICES = {"unicom", "telecom", "mobile"}
MAX_TIMERS = 10
WEEKDAYS = (0, 1, 2, 3, 4)
ALL_DAYS = (0, 1, 2, 3, 4, 5, 6)


@dataclass(frozen=True)
class TimerSettings:
    enabled: bool = False
    time: str = "06:00"
    weekdays: tuple[int, ...] = WEEKDAYS
    mode: str = "broadband"
    service: str = "unicom"
    retry_time: str | None = None


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
    )
    return (first,) + tuple(TimerSettings() for _ in range(MAX_TIMERS - 1))


@dataclass(frozen=True)
class AppSettings:
    mode: str = "broadband"
    service: str = "unicom"
    timers: tuple[TimerSettings, ...] = default_timers()


def default_settings_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "YSUNetWatch" / "settings.json"
    return Path.home() / ".ysu-net-watch" / "settings.json"


def load_settings(path: Path | None = None) -> AppSettings:
    target = path or default_settings_path()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError, TypeError):
        return AppSettings()
    if not isinstance(payload, dict):
        return AppSettings()
    mode = payload.get("mode")
    service = payload.get("service")
    valid_mode = mode if mode in VALID_MODES else "broadband"
    valid_service = service if service in VALID_SERVICES else "unicom"
    raw_timers = payload.get("timers")
    timers: list[TimerSettings] = []
    if isinstance(raw_timers, list):
        for raw in raw_timers[:MAX_TIMERS]:
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
    return AppSettings(
        mode=valid_mode,
        service=valid_service,
        timers=tuple(timers),
    )


def valid_time(value: object) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"\d{2}:\d{2}", value):
        return False
    hour, minute = (int(part) for part in value.split(":"))
    return 0 <= hour <= 23 and 0 <= minute <= 59


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
        mode=mode if mode in VALID_MODES else "broadband",
        service=service if service in VALID_SERVICES else "unicom",
        retry_time=retry_time if valid_time(retry_time) else None,
    )


def save_settings(settings: AppSettings, path: Path | None = None) -> Path:
    target = path or default_settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(asdict(settings), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary.replace(target)
    return target
