from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from ysu_net_watch.schedule import TimerSchedule
from ysu_net_watch.settings import TimerSettings, default_timers, legacy_profiles


class TimerScheduleTests(unittest.TestCase):
    def test_state_rejects_more_than_ten_timer_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule-state.json"
            payload = {
                "schema_version": 1,
                "timers": {
                    str(index): {
                        "fingerprint": "0" * 64,
                        "pending_change": False,
                        "primary_started": None,
                        "primary_failed": None,
                        "retry_started": None,
                    }
                    for index in range(11)
                },
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            schedule = TimerSchedule(state_path=path)

            with self.assertRaisesRegex(ValueError, "记录过多"):
                schedule.sync(default_timers(), legacy_profiles())

    def test_state_rejects_out_of_range_timer_number(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule-state.json"
            payload = {
                "schema_version": 1,
                "timers": {
                    "10": {
                        "fingerprint": "0" * 64,
                        "pending_change": False,
                        "primary_started": None,
                        "primary_failed": None,
                        "retry_started": None,
                    },
                },
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            schedule = TimerSchedule(state_path=path)

            with self.assertRaisesRegex(ValueError, "编号无效"):
                schedule.sync(default_timers(), legacy_profiles())

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
        schedule.mark_started(due[0], now.date())
        self.assertEqual(schedule.due_timers(now, timers), [])

    def test_failed_primary_retries_at_configured_time(self) -> None:
        six = datetime(2026, 7, 30, 6, 0)
        eight = datetime(2026, 7, 30, 8, 0)
        schedule = TimerSchedule()
        timers = (self.timer(),)
        run = schedule.mark_started(schedule.due_timers(six, timers)[0], six.date())
        schedule.mark_finished(run, 20)
        due = schedule.due_timers(eight, timers)
        self.assertEqual([(item.index, item.phase) for item in due], [(0, "retry")])

    def test_successful_primary_does_not_retry(self) -> None:
        six = datetime(2026, 7, 30, 6, 0)
        eight = datetime(2026, 7, 30, 8, 0)
        schedule = TimerSchedule()
        timers = (self.timer(),)
        run = schedule.mark_started(schedule.due_timers(six, timers)[0], six.date())
        schedule.mark_finished(run, 0)
        self.assertEqual(schedule.due_timers(eight, timers), [])

    def test_terminal_credential_rejection_does_not_trigger_compensation(self) -> None:
        six = datetime(2026, 7, 30, 6, 0)
        eight = datetime(2026, 7, 30, 8, 0)
        schedule = TimerSchedule()
        timers = (self.timer(),)
        run = schedule.mark_started(schedule.due_timers(six, timers)[0], six.date())

        schedule.mark_finished(run, 23)

        self.assertEqual(schedule.due_timers(eight, timers), [])

    def test_protocol_change_does_not_trigger_compensation(self) -> None:
        six = datetime(2026, 7, 30, 6, 0)
        eight = datetime(2026, 7, 30, 8, 0)
        schedule = TimerSchedule()
        timers = (self.timer(),)
        run = schedule.mark_started(schedule.due_timers(six, timers)[0], six.date())

        schedule.mark_finished(run, 30)

        self.assertEqual(schedule.due_timers(eight, timers), [])

    def test_device_limit_does_not_trigger_compensation(self) -> None:
        six = datetime(2026, 7, 30, 6, 0)
        eight = datetime(2026, 7, 30, 8, 0)
        schedule = TimerSchedule()
        timers = (self.timer(),)
        run = schedule.mark_started(schedule.due_timers(six, timers)[0], six.date())

        schedule.mark_finished(run, 24)

        self.assertEqual(schedule.due_timers(eight, timers), [])

    def test_ip_freeze_does_not_trigger_compensation(self) -> None:
        six = datetime(2026, 7, 30, 6, 0)
        eight = datetime(2026, 7, 30, 8, 0)
        schedule = TimerSchedule()
        timers = (self.timer(),)
        run = schedule.mark_started(schedule.due_timers(six, timers)[0], six.date())

        schedule.mark_finished(run, 26)

        self.assertEqual(schedule.due_timers(eight, timers), [])

    def test_disabled_timer_never_runs(self) -> None:
        schedule = TimerSchedule()
        timer = self.timer(enabled=False)
        self.assertEqual(
            schedule.due_timers(datetime(2026, 7, 30, 6, 0), (timer,)),
            [],
        )

    def test_custom_day_catches_up_after_missed_minute(self) -> None:
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
            len(schedule.due_timers(
                datetime(2026, 8, 1, 9, 31),
                (saturday_timer,),
            )),
            1,
        )

    def test_failed_primary_catches_up_after_retry_minute(self) -> None:
        schedule = TimerSchedule()
        timer = self.timer()
        six = datetime(2026, 7, 30, 6)
        run = schedule.mark_started(
            schedule.due_timers(six, (timer,))[0], six.date(),
        )
        schedule.mark_finished(run, 20)
        due = schedule.due_timers(datetime(2026, 7, 30, 8, 17), (timer,))
        self.assertEqual([item.phase for item in due], ["retry"])

    def test_late_primary_after_retry_time_does_not_retry_immediately(self) -> None:
        schedule = TimerSchedule()
        timer = self.timer()
        ten = datetime(2026, 7, 30, 10)
        due = schedule.due_timers(ten, (timer,))[0]
        self.assertTrue(due.retry_window_missed)
        run = schedule.mark_started(due, ten.date())
        schedule.mark_finished(run, 20)
        self.assertEqual(schedule.due_timers(ten, (timer,)), [])

    def test_up_to_ten_timers_can_be_due(self) -> None:
        schedule = TimerSchedule()
        timers = tuple(self.timer() for _ in range(10))
        due = schedule.due_timers(datetime(2026, 7, 30, 6, 0), timers)
        self.assertEqual(len(due), 10)

    def test_started_primary_is_not_repeated_after_process_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule-state.json"
            timer = self.timer()
            noon = datetime(2026, 7, 30, 12)
            first = TimerSchedule(state_path=path)
            due = first.due_timers(noon, (timer,))
            first.mark_started(due[0], noon.date())

            restarted = TimerSchedule(state_path=path)
            self.assertEqual(restarted.due_timers(noon, (timer,)), [])
            state_text = path.read_text(encoding="utf-8").lower()

        self.assertNotIn("username", state_text)
        self.assertNotIn("password", state_text)

    def test_failed_primary_keeps_retry_eligibility_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule-state.json"
            timer = self.timer()
            six = datetime(2026, 7, 30, 6)
            first = TimerSchedule(state_path=path)
            run = first.mark_started(
                first.due_timers(six, (timer,))[0],
                six.date(),
            )
            first.mark_finished(run, 20)

            restarted = TimerSchedule(state_path=path)
            due = restarted.due_timers(
                datetime(2026, 7, 30, 8),
                (timer,),
            )

        self.assertEqual([item.phase for item in due], ["retry"])

    def test_elapsed_configuration_change_remains_suppressed_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule-state.json"
            original = self.timer(time="06:00")
            changed = self.timer(time="07:00")
            schedule = TimerSchedule(state_path=path)
            schedule.sync((original,))
            schedule.sync((changed,))

            restarted = TimerSchedule(state_path=path)
            nine = datetime(2026, 7, 30, 9)
            self.assertEqual(restarted.due_timers(nine, (changed,)), [])

            restarted_again = TimerSchedule(state_path=path)
            self.assertEqual(restarted_again.due_timers(nine, (changed,)), [])

    def test_corrupt_state_fails_closed_instead_of_repeating_timer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule-state.json"
            path.write_text(
                json.dumps({"schema_version": 1, "timers": []}),
                encoding="utf-8",
            )
            schedule = TimerSchedule(state_path=path)
            with self.assertRaisesRegex(ValueError, "避免重复认证"):
                schedule.due_timers(
                    datetime(2026, 7, 30, 6),
                    (self.timer(),),
                )

    def test_inconsistent_failure_state_cannot_trigger_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule-state.json"
            first = TimerSchedule(state_path=path)
            first.sync((self.timer(),))
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["timers"]["0"]["primary_failed"] = "2026-07-30"
            path.write_text(json.dumps(payload), encoding="utf-8")

            restarted = TimerSchedule(state_path=path)
            with self.assertRaisesRegex(ValueError, "日期关系无效"):
                restarted.due_timers(
                    datetime(2026, 7, 30, 8),
                    (self.timer(),),
                )


if __name__ == "__main__":
    unittest.main()
