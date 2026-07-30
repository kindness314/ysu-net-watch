from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime

from .settings import TimerSettings


@dataclass(frozen=True)
class DueTimer:
    index: int
    phase: str
    timer: TimerSettings


@dataclass
class TimerSchedule:
    primary_started: dict[int, date] = field(default_factory=dict)
    primary_failed: dict[int, date] = field(default_factory=dict)
    retry_started: dict[int, date] = field(default_factory=dict)

    def due_timers(
        self,
        now: datetime,
        timers: tuple[TimerSettings, ...],
    ) -> list[DueTimer]:
        today = now.date()
        current_time = now.strftime("%H:%M")
        due: list[DueTimer] = []
        for index, timer in enumerate(timers):
            if not timer.enabled or now.weekday() not in timer.weekdays:
                continue
            if (
                current_time == timer.time
                and self.primary_started.get(index) != today
            ):
                due.append(DueTimer(index, "primary", timer))
                continue
            if (
                timer.retry_time == current_time
                and self.primary_failed.get(index) == today
                and self.retry_started.get(index) != today
            ):
                due.append(DueTimer(index, "retry", timer))
        return due

    def mark_started(self, index: int, phase: str, today: date) -> None:
        if phase == "primary":
            self.primary_started[index] = today
        elif phase == "retry":
            self.retry_started[index] = today

    def mark_finished(
        self,
        index: int,
        phase: str,
        today: date,
        exit_code: int,
    ) -> None:
        if phase != "primary":
            return
        if exit_code == 0:
            if self.primary_failed.get(index) == today:
                self.primary_failed.pop(index, None)
        else:
            self.primary_failed[index] = today
