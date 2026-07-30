from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ysu_net_watch.monitor import JsonEventLog, sanitize_text


class SanitizationTests(unittest.TestCase):
    def test_terminal_ip_and_mac_are_redacted(self) -> None:
        value = (
            "终端IP(10.53.29.172)，终端MAC（84:9e:56:77:1e:49） "
            "userIp=192.168.1.8 mac=849e56771e49"
        )

        clean = sanitize_text(value)

        self.assertNotIn("10.53.29.172", clean)
        self.assertNotIn("192.168.1.8", clean)
        self.assertNotIn("849e56771e49", clean)
        self.assertNotIn("84:9e:56:77:1e:49", clean)

    def test_secret_and_sensitive_fields_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            log = JsonEventLog(path)
            log.write(
                "test",
                secrets=("student42", "super-secret"),
                reason=(
                    'student42 super-secret ticket=abc '
                    '"sessionId":"session-value" Authorization=Bearer-value'
                ),
            )
            content = path.read_text(encoding="utf-8")

        for sensitive in (
            "student42",
            "super-secret",
            "ticket=abc",
            "session-value",
            "Bearer-value",
        ):
            self.assertNotIn(sensitive, content)
        self.assertIn("<REDACTED>", content)

    def test_log_rotates_at_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            log = JsonEventLog(path, max_bytes=120)
            log.write("first", reason="x" * 80)
            log.write("second", reason="y" * 80)

            self.assertTrue(path.exists())
            self.assertTrue(path.with_name("events.jsonl.1").exists())
            self.assertIn("second", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
