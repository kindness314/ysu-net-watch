from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from ysu_net_watch.connectivity import ConnectivityResult, ConnectivityState
from ysu_net_watch.credentials import Credential
from ysu_net_watch.monitor import Watcher, WatchSettings
from ysu_net_watch.portal import PortalClient, PortalError, PortalStatus
from ysu_net_watch.recovery import RecoveryState


class RecoveryTests(unittest.TestCase):
    def watcher(self, factory, checker=None):
        return Watcher(
            WatchSettings("broadband", "中国电信", retry_delays=(0,) * 5,
                          verification_delays=(), confirmation_delay=0, check_interval=0),
            checker or Mock(check=Mock(return_value=ConnectivityResult(ConnectivityState.ONLINE, "test"))),
            Mock(get=Mock(return_value=Credential("synthetic-user", "synthetic-password"))),
            factory, Mock(), sleeper=lambda _: None, reporter=Mock(),
        )

    def test_four_rejections_timeout_then_fifth_rejection_stops(self):
        rejected = PortalError("authentication_failed", "service_login", "synthetic rejection")
        portal = Mock()
        portal.login.side_effect = [rejected] * 4 + [PortalError("timeout", "status", "timeout"), rejected]
        watcher = self.watcher(lambda: portal)
        self.assertEqual(watcher._authenticate(), 21)
        self.assertEqual(watcher.recovery.failures, 4)
        self.assertEqual(watcher._authenticate(), 20)
        self.assertEqual(portal.login.call_count, 6)
        failures = [call.kwargs["attempt"] for call in watcher.event_log.inner.write.call_args_list
                    if call.args == ("authentication_failed",)]
        self.assertEqual(failures, [1, 2, 3, 4, 5])

    def test_continuous_monitor_does_not_reset_budget_between_checks(self):
        rejected = PortalError("authentication_failed", "service_login", "rejected")
        portal = Mock()
        portal.login.side_effect = [rejected] * 4 + [PortalError("timeout", "status", "timeout"), rejected]
        checker = Mock(check=Mock(return_value=ConnectivityResult(ConnectivityState.CAPTIVE, "test")))
        watcher = self.watcher(lambda: portal, checker)
        self.assertEqual(watcher.run(authenticate_on_start=True), 20)
        self.assertEqual(portal.login.call_count, 6)

    def test_transport_errors_do_not_consume_or_erase_budget(self):
        portal = Mock()
        watcher = self.watcher(lambda: portal)
        watcher.recovery.failures = 3
        for category in ("timeout", "network_error", "operation_cancelled"):
            portal.login.side_effect = PortalError(category, "status", "test")
            self.assertEqual(watcher._authenticate(), 21)
            self.assertEqual(watcher.recovery.failures, 3)

    def test_confirmed_online_resets_all_recovery_limits(self):
        portal = Mock(login=Mock(return_value=True))
        watcher = self.watcher(lambda: portal)
        watcher.recovery.failures = 4
        watcher.recovery.device_release_attempted = True
        watcher.recovery.workflow_session_retry_attempted = True
        self.assertEqual(watcher._authenticate(), 0)
        self.assertEqual(watcher.recovery, RecoveryState())

    def test_portal_online_but_public_network_pending_resets_auth_failures(self):
        portal = Mock(login=Mock(return_value=True), status=Mock(return_value=SimpleNamespace(online=True)))
        checker = Mock(check=Mock(return_value=ConnectivityResult(ConnectivityState.UNKNOWN, "test")))
        watcher = self.watcher(lambda: portal, checker)
        watcher.recovery.failures = 4
        self.assertEqual(watcher._authenticate(), 21)
        self.assertEqual(watcher.recovery.failures, 0)

    def test_hotspot_online_does_not_reset_campus_recovery(self):
        watcher = self.watcher(Mock())
        watcher.expected_network = lambda: False
        watcher.recovery.failures = 4
        watcher.recovery.device_release_attempted = True
        watcher.recovery.workflow_session_retry_attempted = True
        self.assertEqual(watcher.run(once=True), 0)
        self.assertEqual(watcher.recovery.failures, 4)
        self.assertTrue(watcher.recovery.device_release_attempted)
        self.assertTrue(watcher.recovery.workflow_session_retry_attempted)

    def test_planned_pause_preserves_budget_until_morning_episode(self):
        portal = Mock(login=Mock(return_value=True))
        watcher = self.watcher(lambda: portal)
        paused = [True]
        watcher.pause_reason = lambda: "planned night" if paused[0] else None
        watcher.recovery.failures = 4
        watcher.recovery.device_release_attempted = True
        watcher.recovery.workflow_session_retry_attempted = True
        self.assertEqual(watcher.run(once=True), 22)
        self.assertEqual(watcher.recovery.failures, 4)
        paused[0] = False
        def login(*args, **kwargs):
            self.assertEqual(kwargs["recovery"], RecoveryState())
            return True
        portal.login.side_effect = login
        self.assertEqual(watcher.run(once=True), 0)

    def occupied_portal(self, kick, compensation):
        portal = PortalClient(sleeper=lambda _: None, reporter=Mock(), verification_delays=())
        portal.status = Mock(return_value=PortalStatus(False, {}))
        portal.redirect_to_portal = Mock(return_value={"sessionId": "synthetic-session"})
        portal.get_current_node = Mock(return_value={"currentNodePath": "test-node"})
        portal.cas_login = Mock()
        portal.service_selection = Mock()
        portal.service_login = Mock(return_value={
            "code": 200, "data": {"authResult": "fail", "authMessage": "宽带账号已在线"},
        })
        portal.find_online_devices = Mock(return_value=[{"onlineUserUuid": "synthetic-device"}])
        portal.kick_online_devices = kick
        portal.manual_compensation_login = compensation
        portal.user_online = Mock(side_effect=[
            {"online": False, "message": "宽带账号已在线"},
            {"online": True},
        ])
        self.addCleanup(portal.session.close)
        return portal

    def test_device_kick_is_limited_across_all_login_retries(self):
        kick = Mock()
        compensation = Mock(side_effect=PortalError("authentication_failed", "compensate", "rejected"))
        watcher = self.watcher(lambda: self.occupied_portal(kick, compensation))
        self.assertEqual(watcher._authenticate(), 20)
        kick.assert_called_once()
        compensation.assert_called_once()

    def test_kick_timeout_is_not_reissued_after_unknown_result(self):
        kick = Mock(side_effect=PortalError("timeout", "kick_online_devices", "unknown result"))
        watcher = self.watcher(lambda: self.occupied_portal(kick, Mock()))
        self.assertEqual(watcher._authenticate(), 21)
        self.assertTrue(watcher.recovery.device_release_attempted)
        self.assertEqual(watcher._authenticate(), 20)
        kick.assert_called_once()

    def test_empty_device_list_does_not_claim_destructive_budget(self):
        kick = Mock()
        portal = self.occupied_portal(kick, Mock())
        portal.find_online_devices.return_value = []
        with self.assertRaises(PortalError):
            portal.replace_online_devices("synthetic-session")
        self.assertFalse(portal.recovery.device_release_attempted)
        kick.assert_not_called()

    def test_workflow_session_retry_can_only_be_claimed_once(self):
        recovery = RecoveryState()

        self.assertTrue(recovery.claim_workflow_session_retry())
        self.assertFalse(recovery.claim_workflow_session_retry())
        recovery.reset()
        self.assertTrue(recovery.claim_workflow_session_retry())
