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

    def test_device_protection_suppresses_compensation_but_temporary_cooldown_does_not(self) -> None:
        for code in (27, 28):
            with self.subTest(code=code):
                six = datetime(2026, 7, 30, 6, 0)
                eight = datetime(2026, 7, 30, 8, 0)
                schedule = TimerSchedule()
                timers = (self.timer(),)
                run = schedule.mark_started(schedule.due_timers(six, timers)[0], six.date())
                schedule.mark_finished(run, code)
                self.assertEqual(bool(schedule.due_timers(eight, timers)), code == 28)

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

    def test_new_primary_clears_previous_day_markers_before_restart(self) -> None:
        for previous_retry in (False, True):
            for finish_code in (None, 0, 20, 23):
                with self.subTest(previous_retry=previous_retry, finish_code=finish_code):
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / "schedule-state.json"
                        timers = (self.timer(),)
                        schedule = TimerSchedule(state_path=path)
                        old_day = datetime(2026, 9, 25, 6)
                        old_run = schedule.mark_started(
                            schedule.due_timers(old_day, timers)[0], old_day.date(),
                        )
                        schedule.mark_finished(old_run, 20)
                        if previous_retry:
                            eight = old_day.replace(hour=8)
                            schedule.mark_started(
                                schedule.due_timers(eight, timers)[0], eight.date(),
                            )
                        new_day = datetime(2026, 10, 2, 6)
                        new_run = schedule.mark_started(
                            schedule.due_timers(new_day, timers)[0], new_day.date(),
                        )
                        # A late result from the old worker must not restore it.
                        schedule.mark_finished(old_run, 20)
                        if finish_code is not None:
                            schedule.mark_finished(new_run, finish_code)
                        restarted = TimerSchedule(state_path=path)
                        self.assertEqual(restarted.due_timers(new_day, timers), [])
                        self.assertEqual(restarted.primary_started[0], new_day.date())
                        self.assertNotIn(0, restarted.retry_started)
                        due = restarted.due_timers(new_day.replace(hour=8), timers)
                        self.assertEqual([item.phase for item in due],
                                         ["retry"] if finish_code == 20 else [])

    def test_legacy_stale_markers_are_backed_up_without_repeating_primary(self) -> None:
        for stale_key in ("primary_failed", "retry_started", "both"):
            with self.subTest(stale_key=stale_key):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "schedule-state.json"
                    timers = (self.timer(),)
                    TimerSchedule(state_path=path).sync(timers)
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    record = payload["timers"]["0"]
                    record["primary_started"] = "2026-10-02"
                    for key in ("primary_failed", "retry_started"):
                        record[key] = "2026-09-25" if stale_key in (key, "both") else None
                    original = json.dumps(payload)
                    path.write_text(original, encoding="utf-8")
                    restarted = TimerSchedule(state_path=path)
                    self.assertEqual(restarted.due_timers(datetime(2026, 10, 2, 8), timers), [])
                    backups = list(path.parent.glob("schedule-state.json.pre-date-cleanup.*.bak"))
                    self.assertEqual(len(backups), 1)
                    self.assertEqual(backups[0].read_text(encoding="utf-8"), original)
                    migrated = json.loads(path.read_text(encoding="utf-8"))["timers"]["0"]
                    self.assertEqual(migrated["primary_started"], "2026-10-02")
                    self.assertIsNone(migrated["primary_failed"])
                    self.assertIsNone(migrated["retry_started"])
                    self.assertEqual(TimerSchedule(state_path=path).due_timers(
                        datetime(2026, 10, 2, 8), timers), [])
                    self.assertEqual(len(list(path.parent.glob("*.bak"))), 1)

    def test_migration_retains_current_day_failure_and_retry_eligibility(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule-state.json"
            timers = (self.timer(),)
            TimerSchedule(state_path=path).sync(timers)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["timers"]["0"].update(
                primary_started="2026-10-02", primary_failed="2026-10-02",
                retry_started="2026-09-25",
            )
            path.write_text(json.dumps(payload), encoding="utf-8")
            schedule = TimerSchedule(state_path=path)
            eight = datetime(2026, 10, 2, 8)
            due = schedule.due_timers(eight, timers)
            self.assertEqual([item.phase for item in due], ["retry"])
            schedule.mark_started(due[0], eight.date())
            self.assertEqual(TimerSchedule(state_path=path).due_timers(eight, timers), [])

    def test_previous_day_retry_token_cannot_overwrite_new_day_state(self) -> None:
        schedule = TimerSchedule()
        timers = (self.timer(),)
        old_day = datetime(2026, 9, 25, 6)
        old_run = schedule.mark_started(schedule.due_timers(old_day, timers)[0], old_day.date())
        schedule.mark_finished(old_run, 20)
        old_retry = schedule.due_timers(old_day.replace(hour=8), timers)[0]
        new_day = datetime(2026, 10, 2, 6)
        schedule.mark_started(schedule.due_timers(new_day, timers)[0], new_day.date())
        self.assertIsNone(schedule.mark_started(old_retry, old_day.date()))
        self.assertNotIn(0, schedule.retry_started)

    def test_future_secondary_date_blocks_migration_without_partial_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule-state.json"
            timers = (self.timer(), self.timer())
            TimerSchedule(state_path=path).sync(timers)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["timers"]["0"].update(
                primary_started="2026-10-02", primary_failed="2026-09-25",
            )
            payload["timers"]["1"].update(
                primary_started="2026-10-02", retry_started="2026-10-03",
            )
            original = json.dumps(payload)
            path.write_text(original, encoding="utf-8")
            schedule = TimerSchedule(state_path=path)
            with self.assertRaisesRegex(ValueError, "日期关系无效"):
                schedule.sync(timers)
            self.assertEqual(schedule.primary_started, {})
            self.assertEqual(schedule.primary_failed, {})
            self.assertEqual(path.read_text(encoding="utf-8"), original)
            self.assertEqual(list(path.parent.glob("*.bak")), [])

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
