from __future__ import annotations

import os
import unittest
import uuid
from unittest.mock import patch

from ysu_net_watch.credentials import (
    CredentialError,
    EnvironmentCredentialSource,
    WindowsCredentialSource,
    delete_windows_credential,
    write_windows_credential,
)


class EnvironmentCredentialTests(unittest.TestCase):
    def test_environment_is_removed_and_value_is_cached(self) -> None:
        values = {
            "YSU_CAMPUS_USERNAME": "student42",
            "YSU_CAMPUS_PASSWORD": "test-password",
        }
        with patch.dict(os.environ, values, clear=False):
            source = EnvironmentCredentialSource("campus")
            first = source.get()
            self.assertNotIn("YSU_CAMPUS_USERNAME", os.environ)
            self.assertNotIn("YSU_CAMPUS_PASSWORD", os.environ)
            second = source.get()

        self.assertIs(first, second)
        self.assertEqual(first.username, "student42")
        self.assertEqual(first.password, "test-password")
        self.assertEqual(first.masked_username, "*******42")

    def test_missing_environment_raises(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(CredentialError):
                EnvironmentCredentialSource("campus").get()


@unittest.skipUnless(
    os.name == "nt" and os.environ.get("YSU_RUN_WINDOWS_CREDENTIAL_TEST") == "1",
    "set YSU_RUN_WINDOWS_CREDENTIAL_TEST=1 to run the Windows credential round trip",
)
class WindowsCredentialIntegrationTests(unittest.TestCase):
    def test_round_trip_uses_temporary_target(self) -> None:
        from ysu_net_watch import credentials

        mode = f"test-{uuid.uuid4()}"
        credentials.WINDOWS_TARGETS[mode] = f"YSU-Net-Watch-Test-{uuid.uuid4()}"
        try:
            write_windows_credential(mode, "unit-test-user", "unit-test-password")
            value = WindowsCredentialSource(mode).get()
            self.assertEqual(value.username, "unit-test-user")
            self.assertEqual(value.password, "unit-test-password")
        finally:
            try:
                delete_windows_credential(mode)
            finally:
                credentials.WINDOWS_TARGETS.pop(mode, None)


if __name__ == "__main__":
    unittest.main()
