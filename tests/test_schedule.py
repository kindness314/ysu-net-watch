from __future__ import annotations

import unittest
from datetime import datetime

from ysu_net_watch.schedule import TimerSchedule
from ysu_net_watch.settings import TimerSettings


class TimerScheduleTests(unittest.TestCase):
    def timer(self, **changes) -> TimerSettings:
        values = {
            "enabled": True,
            "time": "06:00",
            "weekdays": (0, 1, 2, 3, 4),
            "mode": "broadband",
            "service": "unicom",
            "retry_time": "08:00",
        }
        values.update(changes)
        return TimerSettings(**values)

    def test_primary_runs_once_at_exact_configured_time(self) -> None:
        now = datetime(2026, 7, 30, 6, 0)
        schedule = TimerSchedule()
        timers = (self.timer(),)
        due = schedule.due_timers(now, timers)
        self.assertEqual([(item.index, item.phase) for item in due], [(0, "primary")])
        schedule.mark_started(0, "primary", now.date())
        self.assertEqual(schedule.due_timers(now, timers), [])

    def test_failed_primary_retries_at_configured_time(self) -> None:
        six = datetime(2026, 7, 30, 6, 0)
        eight = datetime(2026, 7, 30, 8, 0)
        schedule = TimerSchedule()
        timers = (self.timer(),)
        schedule.mark_started(0, "primary", six.date())
        schedule.mark_finished(0, "primary", six.date(), 20)
        due = schedule.due_timers(eight, timers)
        self.assertEqual([(item.index, item.phase) for item in due], [(0, "retry")])

    def test_successful_primary_does_not_retry(self) -> None:
        six = datetime(2026, 7, 30, 6, 0)
        eight = datetime(2026, 7, 30, 8, 0)
        schedule = TimerSchedule()
        timers = (self.timer(),)
        schedule.mark_started(0, "primary", six.date())
        schedule.mark_finished(0, "primary", six.date(), 0)
        self.assertEqual(schedule.due_timers(eight, timers), [])

    def test_disabled_timer_never_runs(self) -> None:
        schedule = TimerSchedule()
        timer = self.timer(enabled=False)
        self.assertEqual(
            schedule.due_timers(datetime(2026, 7, 30, 6, 0), (timer,)),
            [],
        )

    def test_custom_days_and_missed_time(self) -> None:
        schedule = TimerSchedule()
        saturday_timer = self.timer(time="09:30", weekdays=(5,))
        self.assertEqual(
            len(
                schedule.due_timers(
                    datetime(2026, 8, 1, 9, 30),
                    (saturday_timer,),
                )
            ),
            1,
        )
        self.assertEqual(
            schedule.due_timers(
                datetime(2026, 8, 1, 9, 31),
                (saturday_timer,),
            ),
            [],
        )

    def test_up_to_ten_timers_can_be_due(self) -> None:
        schedule = TimerSchedule()
        timers = tuple(self.timer() for _ in range(10))
        due = schedule.due_timers(datetime(2026, 7, 30, 6, 0), timers)
        self.assertEqual(len(due), 10)


if __name__ == "__main__":
    unittest.main()
