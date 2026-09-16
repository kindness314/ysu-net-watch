from __future__ import annotations

import json
import tempfile
import unittest
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ysu_net_watch.credentials import Credential, CredentialError, profile_target
from ysu_net_watch.profiles import ProfileStore, ProfileCredentialSource
from ysu_net_watch.settings import AppSettings, load_settings, save_settings, legacy_profile_id


class ProfileTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "settings.json"
        self.store = ProfileStore(self.path)
        self.secrets = {}
        self.deletions = []

        def write(mode, username, password, *, profile_id, revision):
            self.secrets[(profile_id, revision)] = Credential(username, password)

        def delete(mode, *, profile_id, revision):
            self.deletions.append((profile_id, revision))
            self.secrets.pop((profile_id, revision), None)

        def source(mode, profile_id=None, revision=1):
            key = (profile_id, revision) if profile_id else ("legacy", mode)
            return SimpleNamespace(get=lambda: self.secrets[key])

        for target, effect in (
            ("ysu_net_watch.profiles.write_windows_credential", write),
            ("ysu_net_watch.profiles.delete_windows_credential", delete),
            ("ysu_net_watch.profiles.WindowsCredentialSource", source),
        ):
            patcher = patch(target, side_effect=effect)
            patcher.start()
            self.addCleanup(patcher.stop)

    def create(self, label="Telecom", service="telecom"):
        return self.store.create(label, "broadband", service, "dummy-user", "dummy-secret")

    def test_profiles_are_isolated_and_settings_have_no_credentials(self):
        first = self.create()
        second = self.create("Unicom", "unicom")
        self.store.update_credentials(first.id, "dummy-new-user", "dummy-new-secret")
        a = ProfileCredentialSource(first.id, self.store).get()
        b = ProfileCredentialSource(second.id, self.store).get()
        self.assertEqual(a.username, "dummy-new-user")
        self.assertEqual(b.username, "dummy-user")
        raw = self.path.read_text(encoding="utf-8")
        self.assertNotIn("dummy-user", raw)
        self.assertNotIn("dummy-secret", raw)
        self.assertNotIn("dummy-new-secret", raw)
        self.assertNotIn("password", raw)

    def test_rename_keeps_identity_and_credential(self):
        profile = self.create()
        self.store.rename(profile.id, "Renamed")
        self.assertEqual(self.store.get(profile.id).label, "Renamed")
        self.assertEqual(ProfileCredentialSource(profile.id, self.store).get().username, "dummy-user")

    def test_default_change_rebinds_first_timer_but_not_custom_timers(self):
        first = self.create()
        second = self.create("Other Telecom")
        config = load_settings(self.path)
        timers = list(config.timers)
        timers[1] = replace(timers[1], profile_id=first.id, service="telecom")
        save_settings(replace(config, timers=tuple(timers)), self.path)
        self.store.set_default(second.id)
        config = load_settings(self.path)
        self.assertEqual(config.timers[0].profile_id, second.id)
        self.assertEqual(config.last_selected_profile_id, second.id)
        self.assertEqual(config.timers[1].profile_id, first.id)
        self.assertEqual(config.default_profile_ids["telecom"], second.id)

    def test_referenced_delete_requires_explicit_disable(self):
        profile = self.create()
        config = load_settings(self.path)
        timers = list(config.timers)
        timers[0] = replace(timers[0], profile_id=profile.id)
        save_settings(replace(config, timers=tuple(timers), last_selected_profile_id=profile.id), self.path)
        with self.assertRaises(CredentialError):
            self.store.delete(profile.id)
        self.assertEqual(self.store.get(profile.id), profile)
        self.store.delete(profile.id, disable_timers=True)
        config = load_settings(self.path)
        self.assertFalse(config.timers[0].enabled)
        self.assertIsNone(config.timers[0].profile_id)
        with self.assertRaises(CredentialError):
            ProfileCredentialSource(profile.id, self.store).get()

    def test_create_failure_rolls_back_new_credential(self):
        with patch("ysu_net_watch.profiles.save_settings", side_effect=OSError("simulated")):
            with self.assertRaises(OSError):
                self.create()
        self.assertEqual(self.secrets, {})
        self.assertFalse(self.path.exists())

    def test_update_failure_keeps_original_credential_and_metadata(self):
        profile = self.create()
        before = self.path.read_bytes()
        with patch("ysu_net_watch.profiles.save_settings", side_effect=OSError("simulated")):
            with self.assertRaises(OSError):
                self.store.update_credentials(profile.id, "new", "new")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(ProfileCredentialSource(profile.id, self.store).get().username, "dummy-user")
        self.assertNotIn((profile.id, 2), self.secrets)

    def test_legacy_migration_is_idempotent_and_does_not_read_secrets(self):
        raw = json.dumps({"mode": "broadband", "service": "telecom", "weekday_schedule": True})
        self.path.write_text(raw, encoding="utf-8")
        first = load_settings(self.path)
        self.assertEqual(first, load_settings(self.path))
        self.assertEqual(first.timers[0].profile_id, legacy_profile_id("telecom"))
        self.assertEqual(self.secrets, {})
        save_settings(first, self.path)
        self.assertEqual(load_settings(self.path), first)
        self.assertEqual(self.path.with_suffix(".legacy-v1.json").read_text(encoding="utf-8"), raw)
        save_settings(first, self.path)
        self.assertEqual(len(load_settings(self.path).profiles), 4)

    def test_editing_one_legacy_profile_does_not_overwrite_shared_credential(self):
        self.secrets[("legacy", "broadband")] = Credential("old", "old-secret")
        telecom = legacy_profile_id("telecom")
        unicom = legacy_profile_id("unicom")
        self.store.update_credentials(telecom, "new", "new-secret")
        self.assertEqual(ProfileCredentialSource(telecom, self.store).get().username, "new")
        self.assertEqual(ProfileCredentialSource(unicom, self.store).get().username, "old")
        self.assertFalse(self.deletions)

    def test_invalid_default_never_falls_back_to_another_account(self):
        config = AppSettings()
        save_settings(replace(config, default_profile_ids={"telecom": "missing"}), self.path)
        with self.assertRaises(CredentialError):
            self.store.default("broadband", "telecom")

    def test_corrupt_settings_never_fall_back_to_legacy_accounts(self):
        self.path.write_text("{corrupt", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.store.default("broadband", "telecom")

    def test_credential_target_rejects_arbitrary_names(self):
        for value in ("YSU-Net-Campus", "../other", "", "abc"):
            with self.assertRaises(CredentialError):
                profile_target(value)

    def test_control_characters_are_rejected_in_labels(self):
        with self.assertRaises(CredentialError):
            self.create("bad\x1b[2J")

    def test_credential_revision_cannot_be_deleted_during_a_read(self):
        profile = self.create()
        reading = threading.Event()
        release = threading.Event()
        updated = threading.Event()
        values = []
        errors = []
        def read_secret():
            reading.set()
            if not release.wait(2):
                raise AssertionError("reader timed out")
            return self.secrets[(profile.id, 1)]
        def read():
            try:
                values.append(ProfileCredentialSource(profile.id, self.store).get())
            except Exception as exc:
                errors.append(exc)
        def update():
            try:
                self.store.update_credentials(profile.id, "new", "new")
                updated.set()
            except Exception as exc:
                errors.append(exc)
        with patch("ysu_net_watch.profiles.credential_source",
                   return_value=SimpleNamespace(get=read_secret)):
            reader = threading.Thread(target=read)
            writer = threading.Thread(target=update)
            reader.start()
            self.assertTrue(reading.wait(1))
            writer.start()
            try:
                self.assertFalse(updated.wait(0.05))
            finally:
                release.set()
                reader.join(2)
                writer.join(2)
        self.assertFalse(errors)
        self.assertTrue(updated.is_set())
        self.assertEqual(values[0].username, "dummy-user")
