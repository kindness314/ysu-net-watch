from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import requests

from ysu_net_watch.protection import AuthProtection, ProtectionError, RETRY_DELAYS
from ysu_net_watch.portal import PortalClient, PortalError, PortalStatus
from ysu_net_watch.monitor import WatchSettings, Watcher, EXIT_AUTH_PROTECTED, EXIT_AUTH_FAILED
from ysu_net_watch.credentials import Credential
from ysu_net_watch.cli import build_parser, run_login, run_protection


class ProtectionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "protection.json"
        self.now = 10000.0
        self.guard = AuthProtection(self.path, clock=lambda: self.now)

    def advance(self, seconds):
        self.now += seconds

    def client(self, *, success=False):
        client = PortalClient(protection=self.guard, sleeper=Mock(), reporter=Mock())
        self.addCleanup(client.session.close)
        client.status = Mock(return_value=PortalStatus(False, {}))
        client.redirect_to_portal = Mock(return_value={"sessionId": "dummy-session"})
        client.cas_login = Mock()
        client.service_selection = Mock()
        client.get_current_node = Mock(return_value={"currentNodePath": "dummy-node"})
        client.service_login = Mock(return_value={"code": 200, "data": {"authResult": "success"}})
        client.user_online = Mock(return_value={"online": success})
        return client

    def test_four_reservations_use_5_15_30_minute_delays_and_no_fifth(self):
        for index in range(4):
            self.assertEqual(self.guard.reserve(), index + 1)
            reloaded = AuthProtection(self.path, clock=lambda: self.now)
            with self.assertRaises(ProtectionError):
                reloaded.reserve()
            if index < 3:
                self.advance(RETRY_DELAYS[index])
        self.advance(86400 * 2)
        with self.assertRaisesRegex(ProtectionError, "四次"):
            AuthProtection(self.path, clock=lambda: self.now).reserve()

    def test_reservation_survives_lost_response_and_restart(self):
        self.guard.reserve()
        self.advance(300)
        restarted = AuthProtection(self.path, clock=lambda: self.now)
        self.assertEqual(restarted.reserve(), 2)

    def test_terminal_restrictions_do_not_expire_or_change_with_accounts(self):
        for category in ("mac_conflict", "mac_blocked", "ip_blocked", "account_locked", "credential_rejected", "rate_limited"):
            with self.subTest(category=category):
                self.guard.reset()
                self.advance(300)
                self.guard.reserve()
                self.guard.failed(category)
                self.advance(86400)
                with self.assertRaises(ProtectionError):
                    AuthProtection(self.path, clock=lambda: self.now).reserve()

    def test_success_and_explicit_reset_keep_minimum_five_minute_gap(self):
        self.guard.reserve()
        self.guard.succeeded()
        self.assertEqual(self.guard.status()["submissions"], 0)
        with self.assertRaises(ProtectionError):
            self.guard.reserve()
        self.guard.reset()
        with self.assertRaises(ProtectionError):
            self.guard.reserve()
        self.advance(300)
        self.assertEqual(self.guard.reserve(), 1)

    def test_success_cannot_clear_explicit_device_freeze(self):
        self.guard.failed("mac_blocked")
        self.guard.succeeded()
        with self.assertRaises(ProtectionError):
            self.guard.check()

    def test_clock_rollback_and_invalid_state_fail_closed(self):
        self.guard.reserve()
        self.now -= 1
        with self.assertRaises(ProtectionError):
            self.guard.check()
        with self.assertRaises(ProtectionError):
            self.guard.reset()
        for content in ('broken', '{}', '[]'):
            self.path.write_text(content, encoding="utf-8")
            with self.assertRaises(ProtectionError):
                self.guard.reserve()

    def test_all_state_fields_are_validated(self):
        self.guard.reserve()
        valid = json.loads(self.path.read_text(encoding="utf-8"))
        for key, value in (("blocked", []), ("submissions", True), ("submissions", 5),
                           ("next_allowed", float("inf")), ("updated", -1), ("schema", True)):
            with self.subTest(key=key, value=value):
                broken = dict(valid, **{key: value})
                self.path.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaises(ProtectionError):
                    self.guard.check()

    def test_save_failure_prevents_reservation_and_submission(self):
        with patch("ysu_net_watch.protection.os.replace", side_effect=OSError("test denial")):
            with self.assertRaises(ProtectionError):
                self.guard.reserve()
        self.assertFalse(self.path.exists())
        self.assertFalse(list(self.path.parent.glob("*.tmp")))

    def test_simultaneous_reservations_allow_only_one_workflow(self):
        results = []
        def submit():
            try:
                results.append(self.guard.reserve())
            except ProtectionError:
                results.append("blocked")
        workers = [threading.Thread(target=submit) for _ in range(5)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(5)
        self.assertEqual(results.count(1), 1)
        self.assertEqual(results.count("blocked"), 4)

    def test_real_screenshot_error_stops_before_kick_and_blocks_new_client(self):
        client = self.client()
        client.service_login.return_value = {
            "code": 200, "data": {"authResult": "failure", "message":
            "portal认证失败，运营商用户认证失败!失败原因[brac error: create session failed(mac collision)!]"},
        }
        client.replace_online_devices = Mock()
        with patch("requests.sessions.Session.request", side_effect=AssertionError("No real requests")):
            with self.assertRaises(PortalError) as raised:
                client.login("dummy-user", "dummy-password", "中国联通")
            self.assertEqual(raised.exception.category, "mac_conflict")
            client.cas_login.assert_called_once()
            client.replace_online_devices.assert_not_called()
            second = self.client()
            with self.assertRaises(PortalError) as stopped:
                second.login("different-dummy-user", "different-dummy-password", "中国电信", force_switch=True)
            self.assertEqual(stopped.exception.category, "authentication_protected")
            second.status.assert_not_called()
            second.cas_login.assert_not_called()
        saved = self.path.read_text(encoding="utf-8")
        self.assertNotIn("dummy-user", saved)
        self.assertNotIn("dummy-password", saved)

    def test_timeout_after_reserved_cas_cannot_submit_immediately_again(self):
        client = self.client()
        client.cas_login.side_effect = PortalError("timeout", "cas_login", "test timeout")
        with self.assertRaises(PortalError):
            client.login("dummy", "dummy", "校园网")
        self.assertEqual(self.guard.status()["submissions"], 1)
        with self.assertRaises(PortalError) as raised:
            self.client().login("dummy", "dummy", "校园网")
        self.assertEqual(raised.exception.category, "authentication_cooldown")

    def test_status_timeout_before_credentials_does_not_spend_submission(self):
        client = self.client()
        client.status.side_effect = PortalError("timeout", "status", "test timeout")
        with self.assertRaises(PortalError):
            client.login("dummy", "dummy", "校园网")
        self.assertEqual(self.guard.status()["submissions"], 0)

    def test_workflow_session_retry_cannot_hide_an_extra_credential_submission(self):
        client = self.client()
        client.get_current_node.side_effect = PortalError("workflow_state_missing", "workflow_node", "missing")
        with self.assertRaises(PortalError) as raised:
            client.login("dummy", "dummy", "校园网")
        self.assertEqual(raised.exception.category, "workflow_session_invalid")
        client.cas_login.assert_called_once()
        with self.assertRaises(ProtectionError):
            self.guard.reserve()

    def test_fourth_submission_can_succeed_but_a_fifth_failed_one_cannot(self):
        for delay in RETRY_DELAYS:
            self.guard.reserve()
            self.advance(delay)
        client = self.client(success=True)
        self.assertTrue(client.login("dummy", "dummy", "校园网"))
        self.assertEqual(self.guard.status()["submissions"], 0)
        self.assertIsNone(self.guard.status()["blocked"])

    def test_online_reuse_does_not_count_or_clear_a_previous_failure(self):
        self.guard.reserve()
        self.advance(300)
        client = self.client()
        client.status.return_value = PortalStatus(True, {})
        self.assertFalse(client.login("dummy", "dummy", "校园网"))
        self.assertEqual(self.guard.status()["submissions"], 1)
        client.cas_login.assert_not_called()

    def test_http_429_stops_and_is_not_misclassified_as_network_pending(self):
        client = self.client()
        response = requests.Response()
        response.status_code = 429
        client.session.request = Mock(return_value=response)
        with self.assertRaises(PortalError) as raised:
            client._request("GET", "https://auth1.ysu.edu.cn/", "status")
        self.assertEqual(raised.exception.category, "rate_limited")
        self.assertEqual(raised.exception.http_status, 429)

    def test_classifier_distinguishes_conflict_freeze_rate_and_normal_mac_validation(self):
        cases = {
            "brac error: create session failed(mac collision)!": "mac_conflict",
            "MAC地址已被冻结": "mac_blocked", "MAC address is blocked": "mac_blocked",
            "认证过于频繁，请稍后再试": "rate_limited", "Too many authentication attempts": "rate_limited",
            "MAC地址格式错误": "api_error", "MAC绑定不存在": "api_error",
            "machine is frozen": "api_error", "账号被冻结": "account_locked", "IP已被冻结": "ip_blocked",
            "账号被冻结，终端MAC(001122334455)": "account_locked",
            "设备已被冻结": "mac_blocked", "MAC(00:11:22:33:44:55)已被冻结": "mac_blocked",
            "MAC地址校验失败，输入被拒绝": "api_error",
        }
        for message, category in cases.items():
            with self.subTest(message=message):
                self.assertEqual(PortalClient._auth_message_category(message, default="api_error"), category)

    def test_cli_protection_reset_requires_explicit_confirmation(self):
        self.guard.failed("mac_conflict")
        with patch("ysu_net_watch.cli.AuthProtection", return_value=self.guard), patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(run_protection(build_parser().parse_args(["protection", "reset"])), 2)
            self.assertEqual(self.guard.status()["blocked"], "mac_conflict")
            self.assertEqual(run_protection(build_parser().parse_args(["protection", "reset", "--confirm"])), 0)
            self.assertIsNone(self.guard.status()["blocked"])

    def test_mac_restriction_prefixes_remain_supported_without_repetition(self):
        for message in (
            "设备已经被冻结", "MAC地址:已被:封禁", "MAC已被列入黑名单",
            "MAC已经被列入黑名单", "device has been blocked", "MAC was locked",
        ):
            with self.subTest(message=message):
                self.assertEqual(PortalClient._auth_message_category(message, default="api_error"), "mac_blocked")

    def test_repeated_untrusted_mac_prefix_does_not_backtrack_exponentially(self):
        # CodeQL's counterexample used overlapping repeated "已被" prefixes.
        # This is synthetic response text, not an authentication request.
        start = time.monotonic()
        for prefix in ("已被", "已经被", ":", "hasbeen"):
            message = "设备" + prefix * 20000 + "暂不可用"
            self.assertEqual(PortalClient._auth_message_category(message, default="api_error"), "api_error")
        self.assertLess(time.monotonic() - start, 2.0)

    def test_cli_manual_login_stops_before_wifi_and_credentials_when_blocked(self):
        self.guard.failed("mac_conflict")
        with patch("ysu_net_watch.cli.AuthProtection", return_value=self.guard), \
             patch("ysu_net_watch.cli.WifiConnector") as wifi, \
             patch("ysu_net_watch.cli.selected_credential_source") as creds, \
             patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(run_login(build_parser().parse_args(["login", "--mode", "campus"])), EXIT_AUTH_PROTECTED)
        wifi.assert_not_called()
        creds.assert_not_called()

    def test_default_watcher_policy_is_four_attempts_with_long_delays(self):
        settings = WatchSettings("campus", "校园网")
        self.assertEqual(settings.max_attempts, 4)
        self.assertEqual(settings.retry_delays[:3], RETRY_DELAYS)
        self.assertEqual(settings.confirmation_delay, 120)

    def test_monitor_stops_on_mac_conflict_without_sleep_or_extra_credentials(self):
        creds, portal, sleep = Mock(), Mock(), Mock()
        creds.get.return_value = Credential("dummy", "dummy")
        portal.login.side_effect = PortalError("mac_conflict", "service_login", "mac collision")
        watcher = Watcher(WatchSettings("campus", "校园网"), Mock(), creds,
                          lambda: portal, Mock(), sleeper=sleep, reporter=Mock(), protection=self.guard)
        self.assertEqual(watcher._authenticate(), EXIT_AUTH_PROTECTED)
        portal.login.assert_called_once()
        sleep.assert_not_called()
        self.assertEqual(self.guard.status()["blocked"], "mac_conflict")

    def test_full_monitor_four_rejections_stop_and_new_monitor_cannot_restart_budget(self):
        clients = []
        def factory():
            client = self.client()
            client.service_login.return_value = {"code": 200, "data": {"authResult": "failure", "message": "temporary rejection"}}
            clients.append(client)
            return client
        creds = Mock(get=Mock(return_value=Credential("dummy", "dummy")))
        waits = []
        def sleep(seconds):
            waits.append(seconds)
            self.advance(seconds)
        watcher = Watcher(WatchSettings("campus", "校园网"), Mock(), creds, factory,
                          Mock(), sleeper=sleep, reporter=Mock(), protection=self.guard)
        self.assertEqual(watcher._authenticate(), EXIT_AUTH_FAILED)
        self.assertEqual(sum(c.cas_login.call_count for c in clients), 4)
        self.assertEqual(waits, list(RETRY_DELAYS))
        fresh = Watcher(WatchSettings("campus", "校园网"), Mock(), creds, factory,
                        Mock(), sleeper=sleep, reporter=Mock(), protection=self.guard)
        self.advance(86400)
        self.assertEqual(fresh._authenticate(), EXIT_AUTH_PROTECTED)
        self.assertEqual(sum(c.cas_login.call_count for c in clients), 4)

    def test_portal_accepted_but_confirmed_offline_cannot_clear_persistent_budget(self):
        from ysu_net_watch.connectivity import ConnectivityState
        clients = []
        def factory():
            client = self.client(success=True)
            client.confirm_success = False
            clients.append(client)
            return client
        checker = Mock()
        checker.check.return_value = Mock(state=ConnectivityState.CAPTIVE, reason="offline test")
        watcher = Watcher(WatchSettings("campus", "校园网"), checker,
                          Mock(get=Mock(return_value=Credential("dummy", "dummy"))), factory,
                          Mock(), sleeper=self.advance, reporter=Mock(), protection=self.guard)
        self.assertEqual(watcher._authenticate(), EXIT_AUTH_FAILED)
        self.assertEqual(sum(c.cas_login.call_count for c in clients), 4)
        self.assertEqual(self.guard.status()["blocked"], "attempts_exhausted")

    def test_failed_final_submission_stays_blocked_without_waiting_for_a_response(self):
        for delay in RETRY_DELAYS:
            self.guard.reserve()
            self.advance(delay)
        client = self.client()
        client.cas_login.side_effect = PortalError("timeout", "cas_login", "lost fourth response")
        with self.assertRaises(PortalError):
            client.login("dummy", "dummy", "校园网")
        self.advance(86400)
        with self.assertRaises(ProtectionError):
            AuthProtection(self.path, clock=lambda: self.now).check()


if __name__ == "__main__":
    unittest.main()
