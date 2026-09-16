from __future__ import annotations

import tempfile
import unittest
import json
from dataclasses import replace
from pathlib import Path

from ysu_net_watch.settings import (
    MAX_TIMERS,
    AppSettings,
    TimerSettings,
    load_settings,
    save_settings,
)


class SettingsTests(unittest.TestCase):
    def test_defaults_to_unicom_broadband(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings = load_settings(Path(directory) / "missing.json")
        self.assertEqual(settings, AppSettings())
        self.assertEqual(len(settings.timers), MAX_TIMERS)
        self.assertTrue(settings.timers[0].enabled)
        self.assertEqual(settings.timers[0].time, "06:00")
        self.assertEqual(settings.timers[0].retry_time, "08:00")
        self.assertTrue(settings.night_pause_enabled)

    def test_legacy_settings_default_night_protection_to_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-settings.json"
            path.write_text(json.dumps({"mode": "broadband", "service": "unicom"}), encoding="utf-8")
            settings = load_settings(path)
        self.assertTrue(settings.night_pause_enabled)

    def test_explicit_night_protection_off_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            save_settings(replace(AppSettings(), night_pause_enabled=False), path)
            settings = load_settings(path)
        self.assertFalse(settings.night_pause_enabled)

    def test_round_trip_contains_only_non_secret_preferences(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            timers = list(AppSettings().timers)
            timers[1] = TimerSettings(
                enabled=True,
                time="21:45",
                weekdays=(1, 3, 5),
                mode="campus",
                service="mobile",
            )
            expected = AppSettings(
                mode="campus",
                service="mobile",
                timers=tuple(timers),
            )
            save_settings(expected, path)
            text = path.read_text(encoding="utf-8")
            actual = load_settings(path)

        self.assertEqual(actual, expected)
        self.assertNotIn("username", text.lower())
        self.assertNotIn("password", text.lower())

    def test_legacy_schedule_is_migrated_to_first_timer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(
                json.dumps(
                    {
                        "mode": "campus",
                        "service": "telecom",
                        "weekday_schedule": False,
                    }
                ),
                encoding="utf-8",
            )
            settings = load_settings(path)

        self.assertEqual(len(settings.timers), MAX_TIMERS)
        self.assertFalse(settings.timers[0].enabled)
        self.assertEqual(settings.timers[0].mode, "campus")

    def test_invalid_timer_data_is_safely_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(
                json.dumps(
                    {
                        "timers": [
                            {
                                "enabled": True,
                                "time": "99:99",
                                "weekdays": [0, 9, True],
                                "mode": "invalid",
                                "service": "invalid",
                                "retry_time": "bad",
                            }
                        ]
                        * 12
                    }
                ),
                encoding="utf-8",
            )
            settings = load_settings(path)

        self.assertEqual(len(settings.timers), MAX_TIMERS)
        self.assertEqual(settings.timers[0].time, "06:00")
        self.assertEqual(settings.timers[0].weekdays, (0,))
        self.assertIsNone(settings.timers[0].retry_time)

    def test_string_schema_version_is_rejected_instead_of_legacy_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(
                json.dumps({"schema_version": "2", "mode": "broadband"}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "版本字段"):
                load_settings(path)

    def test_current_schema_rejects_unhashable_mode_without_type_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(
                json.dumps({
                    "schema_version": 2,
                    "mode": [],
                    "service": "unicom",
                    "timers": [{}],
                }),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError) as raised:
                load_settings(path)
        self.assertNotIsInstance(raised.exception, TypeError)

    def test_current_schema_rejects_invalid_inner_timer_instead_of_normalizing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            save_settings(AppSettings(), path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["timers"][0]["time"] = "not-a-time"
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "执行时间无效"):
                load_settings(path)

    def test_current_schema_rejects_invalid_weekday_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            save_settings(AppSettings(), path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["timers"][0]["weekdays"] = "weekdays"
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "执行日期无效"):
                load_settings(path)

    def test_save_rejects_compensation_not_later_than_primary(self) -> None:
        for retry_time in ("06:00", "05:59"):
            with self.subTest(retry_time=retry_time):
                timers = list(AppSettings().timers)
                timers[0] = replace(timers[0], retry_time=retry_time)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "settings.json"
                    with self.assertRaisesRegex(ValueError, "必须晚于执行时间"):
                        save_settings(
                            replace(AppSettings(), timers=tuple(timers)),
                            path,
                        )


if __name__ == "__main__":
    unittest.main()
