from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, time
import hashlib
import json
import os
from pathlib import Path
import re
import threading
from typing import Callable
import uuid

from .settings import MAX_TIMERS, AccountProfile, AppSettings, TimerSettings


SCHEDULE_STATE_SCHEMA = 1
# These outcomes mean that retrying the same credentials or the same portal
# protocol later in the day is unsafe.  The numeric values mirror the public
# watcher exit codes while keeping this small scheduling module independent of
# the monitor implementation.
NON_RETRYABLE_EXIT_CODES = frozenset({23, 24, 26, 30})


def default_schedule_state_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "YSUNetWatch" / "schedule-state.json"
    return Path.home() / ".ysu-net-watch" / "schedule-state.json"


def _binding_fingerprint(timer: TimerSettings, credential_revision: int | None) -> str:
    payload = [
        timer.enabled,
        timer.time,
        list(timer.weekdays),
        timer.mode,
        timer.service,
        timer.retry_time,
        timer.profile_id,
        credential_revision,
    ]
    encoded = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _stored_date(value: object, field_name: str) -> date | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"定时状态字段 {field_name} 无效")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"定时状态字段 {field_name} 无效") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"定时状态字段 {field_name} 无效")
    return parsed


def night_pause_until(now: datetime, settings: AppSettings) -> datetime | None:
    """Mon–Thu 23:30 until the following day's timer 1 time, even if disabled."""
    if not settings.night_pause_enabled:
        return None
    hour, minute = map(int, settings.timers[0].time.split(":"))
    for origin in (now.date(), now.date() - timedelta(days=1)):
        if origin.weekday() not in (0, 1, 2, 3):
            continue
        start = datetime.combine(origin, time(23, 30), tzinfo=now.tzinfo)
        end = datetime.combine(origin + timedelta(days=1), time(hour, minute), tzinfo=now.tzinfo)
        if start <= now < end:
            return end
    return None


def night_pause_reason(now: datetime, settings: AppSettings) -> str | None:
    until = night_pause_until(now, settings)
    if until is None:
        return None
    return f"计划停网保护：暂停认证，{until:%m-%d %H:%M} 恢复（跟随定时器 1）"


@dataclass(frozen=True)
class DueTimer:
    index: int
    phase: str
    timer: TimerSettings
    generation: int
    caught_up: bool = False
    retry_window_missed: bool = False


@dataclass(frozen=True)
class TimerRun:
    index: int
    phase: str
    day: date
    generation: int


@dataclass
class TimerSchedule:
    state_path: Path | None = None
    primary_started: dict[int, date] = field(default_factory=dict)
    primary_failed: dict[int, date] = field(default_factory=dict)
    retry_started: dict[int, date] = field(default_factory=dict)
    _bindings: dict[int, tuple[TimerSettings, int | None]] = field(default_factory=dict)
    _fingerprints: dict[int, str] = field(default_factory=dict)
    _generations: dict[int, int] = field(default_factory=dict)
    _changed_bindings: set[int] = field(default_factory=set)
    _initialized: bool = False
    _state_dirty: bool = False
    _lock: object = field(default_factory=threading.RLock, repr=False, compare=False)

    def _load_state(self) -> None:
        if self.state_path is None:
            return
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self._state_dirty = True
            return
        except (ValueError, TypeError) as exc:
            raise ValueError(
                "定时状态文件损坏；为避免重复认证，定时调度已停止"
            ) from exc
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != SCHEDULE_STATE_SCHEMA
            or not isinstance(payload.get("timers"), dict)
        ):
            raise ValueError("定时状态格式无效；为避免重复认证，定时调度已停止")

        # The application has a fixed ten-slot timer table.  Reject oversized
        # state files before iterating them so a tampered local file cannot
        # consume unbounded memory/CPU or create phantom timer records.
        if len(payload["timers"]) > MAX_TIMERS:
            raise ValueError("定时状态中的任务记录过多")

        seen: set[int] = set()
        for raw_index, raw in payload["timers"].items():
            if (
                not isinstance(raw_index, str)
                or not raw_index.isdecimal()
                or not isinstance(raw, dict)
            ):
                raise ValueError("定时状态中的任务记录无效")
            index = int(raw_index)
            if not 0 <= index < MAX_TIMERS:
                raise ValueError("定时状态中的任务编号无效")
            if index in seen:
                raise ValueError("定时状态中存在重复任务记录")
            seen.add(index)
            if index not in self._fingerprints:
                self._state_dirty = True
                continue
            fingerprint = raw.get("fingerprint")
            pending_change = raw.get("pending_change", False)
            if (
                not isinstance(fingerprint, str)
                or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
                or type(pending_change) is not bool
            ):
                raise ValueError("定时状态中的任务指纹无效")
            if fingerprint != self._fingerprints[index]:
                if self._bindings[index][0].enabled:
                    self._changed_bindings.add(index)
                self._state_dirty = True
                continue
            if pending_change and self._bindings[index][0].enabled:
                self._changed_bindings.add(index)
            stored_dates = {
                key: _stored_date(raw.get(key), key)
                for key in (
                    "primary_started",
                    "primary_failed",
                    "retry_started",
                )
            }
            primary = stored_dates["primary_started"]
            if (
                stored_dates["primary_failed"] is not None
                and stored_dates["primary_failed"] != primary
            ) or (
                stored_dates["retry_started"] is not None
                and stored_dates["retry_started"] != primary
            ):
                raise ValueError("定时状态中的任务日期关系无效")
            for key, target in (
                ("primary_started", self.primary_started),
                ("primary_failed", self.primary_failed),
                ("retry_started", self.retry_started),
            ):
                if stored_dates[key] is not None:
                    target[index] = stored_dates[key]

        if seen != set(self._fingerprints):
            self._state_dirty = True

    def _save_state(self) -> None:
        if not self._state_dirty:
            return
        if self.state_path is None:
            self._state_dirty = False
            return
        payload = {
            "schema_version": SCHEDULE_STATE_SCHEMA,
            "timers": {
                str(index): {
                    "fingerprint": fingerprint,
                    "pending_change": index in self._changed_bindings,
                    "primary_started": (
                        self.primary_started[index].isoformat()
                        if index in self.primary_started else None
                    ),
                    "primary_failed": (
                        self.primary_failed[index].isoformat()
                        if index in self.primary_failed else None
                    ),
                    "retry_started": (
                        self.retry_started[index].isoformat()
                        if index in self.retry_started else None
                    ),
                }
                for index, fingerprint in sorted(self._fingerprints.items())
            },
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(
            f"{self.state_path.name}.{uuid.uuid4().hex}.tmp"
        )
        try:
            temporary.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            temporary.replace(self.state_path)
            self._state_dirty = False
        finally:
            temporary.unlink(missing_ok=True)

    def sync(
        self, timers: tuple[TimerSettings, ...], profiles: tuple[AccountProfile, ...] = (),
    ) -> None:
        revisions = {profile.id: profile.credential_revision for profile in profiles}
        bindings = {index: (timer, revisions.get(timer.profile_id)) for index, timer in enumerate(timers)}
        fingerprints = {
            index: _binding_fingerprint(timer, revisions.get(timer.profile_id))
            for index, timer in enumerate(timers)
        }
        with self._lock:
            if not self._initialized:
                self._bindings = bindings
                self._fingerprints = fingerprints
                self._generations = {index: 1 for index in bindings}
                self._load_state()
                self._initialized = True
                self._save_state()
                return
            for index in self._bindings.keys() | bindings.keys():
                if self._bindings.get(index) != bindings.get(index):
                    self._generations[index] = self._generations.get(index, 0) + 1
                    self.primary_started.pop(index, None)
                    self.primary_failed.pop(index, None)
                    self.retry_started.pop(index, None)
                    if index in bindings and bindings[index][0].enabled:
                        self._changed_bindings.add(index)
                    elif index not in bindings:
                        self._changed_bindings.discard(index)
                    self._state_dirty = True
            self._bindings = bindings
            self._fingerprints = fingerprints
            self._save_state()

    def is_current(self, run: TimerRun | DueTimer) -> bool:
        with self._lock:
            return (run.index in self._bindings
                    and self._generations.get(run.index) == run.generation)

    def due_timers(
        self,
        now: datetime,
        timers: tuple[TimerSettings, ...],
        profiles: tuple[AccountProfile, ...] = (),
    ) -> list[DueTimer]:
        with self._lock:
            self.sync(timers, profiles)
            today = now.date()
            current_time = now.strftime("%H:%M")
            due: list[DueTimer] = []
            for index, timer in enumerate(timers):
                if not timer.enabled or now.weekday() not in timer.weekdays:
                    continue
                if index in self._changed_bindings:
                    self._changed_bindings.discard(index)
                    if current_time > timer.time:
                        # Editing/rebinding an elapsed timer is not a request to
                        # run it immediately. Catch-up is for startup/resume.
                        self.primary_started[index] = today
                        self.retry_started[index] = today
                        self._state_dirty = True
                        self._save_state()
                        continue
                if current_time >= timer.time and self.primary_started.get(index) != today:
                    caught_up = current_time > timer.time
                    retry_window_missed = bool(
                        timer.retry_time and current_time >= timer.retry_time
                    )
                    due.append(DueTimer(
                        index, "primary", timer, self._generations[index],
                        caught_up=caught_up,
                        retry_window_missed=retry_window_missed,
                    ))
                    continue
                if (timer.retry_time is not None
                        and current_time >= timer.retry_time
                        and self.primary_failed.get(index) == today
                        and self.retry_started.get(index) != today):
                    due.append(DueTimer(
                        index, "retry", timer, self._generations[index],
                        caught_up=current_time > timer.retry_time,
                    ))
            # A task scheduled for this minute beats catch-up work. If several
            # tasks were missed during sleep, the most recent intended target
            # wins; equal times still use the lower timer number.
            def priority(item: DueTimer) -> tuple[int, int, int]:
                trigger = item.timer.time if item.phase == "primary" else item.timer.retry_time
                hour, minute = map(int, (trigger or "00:00").split(":"))
                return (1 if item.caught_up else 0, -(hour * 60 + minute), item.index)

            due.sort(key=priority)
            return due

    def mark_started(self, due: DueTimer, today: date) -> TimerRun | None:
        with self._lock:
            if not self.is_current(due):
                return None
            records = self.primary_started if due.phase == "primary" else self.retry_started
            if records.get(due.index) == today:
                return None
            records[due.index] = today
            if due.phase == "primary" and due.retry_window_missed:
                # A primary task caught up after its compensation time must not
                # immediately run a second full authentication cycle.
                self.retry_started[due.index] = today
            self._state_dirty = True
            self._save_state()
            return TimerRun(due.index, due.phase, today, due.generation)

    def mark_finished(self, run: TimerRun, exit_code: int) -> None:
        with self._lock:
            if (run.phase != "primary" or not self.is_current(run)
                    or self.primary_started.get(run.index) != run.day):
                return
            if exit_code == 0 or exit_code in NON_RETRYABLE_EXIT_CODES:
                if self.primary_failed.get(run.index) == run.day:
                    self.primary_failed.pop(run.index, None)
            else:
                self.primary_failed[run.index] = run.day
            self._state_dirty = True
            self._save_state()


def supervise_schedule(
    stop_event: threading.Event,
    tick: Callable[[], None],
    on_error: Callable[[Exception], None],
    on_recovered: Callable[[], None],
    interval: float = 15.0,
) -> None:
    """Keep the timer service alive across transient Wi-Fi/config/log failures."""
    failed = False
    while not stop_event.is_set():
        try:
            tick()
            if failed:
                on_recovered()
            failed = False
        except Exception as exc:
            failed = True
            # Failure reporting must not become another way to kill this service.
            try:
                on_error(exc)
            except Exception:
                pass
        stop_event.wait(interval)
