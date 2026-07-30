from __future__ import annotations

import tempfile
import unittest
import json
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


if __name__ == "__main__":
    unittest.main()
