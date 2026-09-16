from __future__ import annotations

import base64
import unittest
from unittest.mock import Mock, call

import requests

from ysu_net_watch.portal import (
    BASE_URL,
    PORTAL_HTTP_HOSTS,
    PORTAL_HTTPS_UPGRADES,
    PORTAL_REDIRECT_HOSTS,
    PortalClient,
    PortalError,
    PortalStatus,
)


def json_response(value, url: str = "https://auth1.ysu.edu.cn/api") -> requests.Response:
    response = requests.Response()
    response.status_code = 200
    response.url = url
    response._content = __import__("json").dumps(value).encode()
    response.headers["Content-Type"] = "application/json"
    return response


def html_response(value: str, url: str = "https://auth1.ysu.edu.cn/cas-sso/login") -> requests.Response:
    response = requests.Response()
    response.status_code = 200
    response.url = url
    response._content = value.encode("utf-8")
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    return response


class PortalClientTests(unittest.TestCase):
    def login_client(self) -> PortalClient:
        client = PortalClient(sleeper=Mock(), reporter=Mock())
        client.status = Mock(return_value=PortalStatus(False, {}))
        client.redirect_to_portal = Mock(return_value={"sessionId": "test-session"})
        client.get_current_node = Mock(return_value={"currentNodePath": "test-node"})
        client.cas_login = Mock()
        client.service_selection = Mock()
        client.service_login = Mock(return_value={
            "code": 200, "data": {"authResult": "success"},
        })
        client.user_online = Mock(return_value={"online": True})
        return client

    def test_delayed_online_status_is_polled_without_another_login(self) -> None:
        client = self.login_client()
        client.user_online.side_effect = [
            {"online": False}, {"online": False}, {"online": True},
        ]
        self.assertTrue(client.login("dummy", "secret", "中国电信"))
        client.cas_login.assert_called_once()
        client.service_login.assert_called_once()
        self.assertEqual(client.user_online.call_count, 3)
        self.assertEqual(client.sleeper.call_count, 2)

    def test_online_verification_is_bounded(self) -> None:
        client = self.login_client()
        client.user_online.return_value = {"online": False, "message": "still offline"}
        with self.assertRaises(PortalError) as raised:
            client.login("dummy", "secret", "中国电信")
        self.assertEqual(raised.exception.stage, "verify_login")
        self.assertEqual(client.user_online.call_count, 5)
        self.assertEqual(sum(c.args[0] for c in client.sleeper.call_args_list), 15)

    def test_service_rejection_preserves_business_code_and_message(self) -> None:
        client = self.login_client()
        client.service_login.return_value = {"code": 403, "message": "carrier rejected the request"}
        client.user_online.return_value = {"online": False}
        with self.assertRaises(PortalError) as raised:
            client.login("dummy", "secret", "中国电信")
        self.assertIn("403", str(raised.exception))
        self.assertIn("carrier rejected the request", str(raised.exception))

    def test_device_count_limit_is_terminal_before_device_kick(self) -> None:
        client = self.login_client()
        client.service_login.return_value = {
            "code": 200,
            "data": {
                "authResult": "fail",
                "authMessage": "认证设备数量已达到上限",
            },
        }
        client.replace_online_devices = Mock()

        with self.assertRaises(PortalError) as raised:
            client.login("dummy", "secret", "中国电信")

        self.assertEqual(raised.exception.category, "account_device_limit")
        client.replace_online_devices.assert_not_called()

    def test_device_count_limit_accepts_interpolated_portal_wording(self) -> None:
        self.assertTrue(
            PortalClient._account_device_limit("当前账号登录设备达到最大数量")
        )
        self.assertTrue(
            PortalClient._account_device_limit("maximum number of login devices exceeded")
        )
        self.assertFalse(PortalClient._account_device_limit("账号已经在线"))

    def test_login_checks_workflow_after_service_selection(self) -> None:
        client = self.login_client()
        events: list[str] = []
        client.redirect_to_portal.side_effect = lambda: (
            events.append("redirect") or {"sessionId": "test-session"}
        )
        client.get_current_node.side_effect = lambda _session_id: (
            events.append("node") or {"currentNodePath": "test-node"}
        )
        client.cas_login.side_effect = lambda *_args: events.append("cas")
        client.service_selection.side_effect = lambda _session_id: events.append("services")
        client.service_login.side_effect = lambda *_args: (
            events.append("service_login")
            or {"code": 200, "data": {"authResult": "success"}}
        )
        client.user_online.side_effect = lambda _session_id: (
            events.append("verify") or {"online": True}
        )

        self.assertTrue(client.login("dummy", "secret", "中国电信"))

        self.assertEqual(
            events,
            [
                "redirect",
                "cas",
                "services",
                "node",
                "service_login",
                "verify",
            ],
        )

    def test_service_error_is_accepted_when_portal_is_online(self) -> None:
        client = self.login_client()
        client.service_login.return_value = {
            "code": 400,
            "message": "temporary portal workflow response",
        }

        self.assertTrue(client.login("dummy", "secret", "中国电信"))

        client.service_login.assert_called_once()
        client.user_online.assert_called_once_with("test-session")
        self.assertTrue(any(
            "门户已确认在线" in call_.args[0]
            for call_ in client.reporter.call_args_list
        ))

    def test_service_timeout_is_accepted_when_portal_is_online(self) -> None:
        client = self.login_client()
        client.service_login.side_effect = PortalError(
            "timeout", "service_login", "unknown submission result",
        )

        self.assertTrue(client.login("dummy", "secret", "中国电信"))

        client.service_login.assert_called_once()
        client.user_online.assert_called_once_with("test-session")

    def test_service_selection_only_fetches_list(self) -> None:
        client = PortalClient()
        client._post_data = Mock(return_value={"services": []})

        result = client.service_selection("test-session")

        self.assertEqual(result, {"services": []})
        self.assertEqual(
            client._post_data.call_args_list,
            [call(
                "/eportal/network/serviceSelection",
                "service_selection",
                "test-session",
            )],
        )

    def test_service_login_does_not_advance_failed_or_unchecked_workflow(self) -> None:
        client = PortalClient()
        response = json_response(
            {"code": 200, "data": {"authResult": "success"}},
            "https://auth1.ysu.edu.cn/eportal/network/serviceLogin",
        )
        client._request_follow_safe = Mock(return_value=response)
        client.get_current_node = Mock(return_value={"currentNodePath": "online"})

        result = client.service_login("test-session", "中国电信")

        self.assertEqual(result["code"], 200)
        client.get_current_node.assert_not_called()

    def test_workflow_node_requires_current_path(self) -> None:
        client = PortalClient()
        client._post_data = Mock(return_value={"sessionId": "redacted"})

        with self.assertRaises(PortalError) as raised:
            client.get_current_node("test-session")

        self.assertEqual(raised.exception.category, "workflow_state_missing")
        self.assertEqual(raised.exception.stage, "workflow_node")

    def test_workflow_node_error_retries_one_fresh_session_then_stops(self) -> None:
        client = self.login_client()
        client.service_login.return_value = {
            "code": 400,
            "message": "登录失败，失败原因:workFlowNode is empty",
        }
        client.user_online.return_value = {"online": False}

        with self.assertRaises(PortalError) as raised:
            client.login("dummy", "secret", "中国电信")

        self.assertEqual(raised.exception.category, "protocol_changed")
        self.assertEqual(raised.exception.stage, "service_login")
        self.assertEqual(client.cas_login.call_count, 2)
        self.assertEqual(client.service_login.call_count, 2)
        self.assertTrue(client.recovery.workflow_session_retry_attempted)

    def test_workflow_node_error_can_recover_with_one_fresh_session(self) -> None:
        client = self.login_client()
        initial_http_session = client.session
        client.service_login.side_effect = [
            {
                "code": 400,
                "message": "登录失败，失败原因:workFlowNode is empty",
            },
            {"code": 200, "data": {"authResult": "success"}},
        ]
        client.user_online.side_effect = [
            *([{"online": False}] * 5),
            {"online": True},
        ]

        self.assertTrue(client.login("dummy", "secret", "中国电信"))

        self.assertEqual(client.cas_login.call_count, 2)
        self.assertEqual(client.service_login.call_count, 2)
        self.assertEqual(client.redirect_to_portal.call_count, 2)
        self.assertIsNot(client.session, initial_http_session)

    def test_missing_workflow_is_retried_before_service_login(self) -> None:
        client = self.login_client()
        client.get_current_node.side_effect = [
            PortalError(
                "workflow_state_missing",
                "workflow_node",
                "workflow node response has no currentNodePath",
            ),
            {"currentNodePath": "serviceSelection"},
        ]

        self.assertTrue(client.login("dummy", "secret", "中国电信"))

        self.assertEqual(client.cas_login.call_count, 2)
        self.assertEqual(client.service_selection.call_count, 2)
        client.service_login.assert_called_once()

    def test_workflow_node_error_does_not_retry_when_already_online(self) -> None:
        client = self.login_client()
        client.service_login.return_value = {
            "code": 400,
            "message": "登录失败，失败原因:workFlowNode is empty",
        }

        self.assertTrue(client.login("dummy", "secret", "中国电信"))

        client.cas_login.assert_called_once()
        client.service_login.assert_called_once()

    def test_workflow_error_survives_online_status_api_error(self) -> None:
        client = self.login_client()
        client.service_login.return_value = {
            "code": 400,
            "message": "登录失败，失败原因:workFlowNode is empty",
        }
        client.user_online.side_effect = PortalError(
            "api_error", "verify_login", "temporary status error",
        )

        with self.assertRaises(PortalError) as raised:
            client.login("dummy", "secret", "中国电信")

        self.assertEqual(raised.exception.category, "protocol_changed")
        self.assertEqual(client.service_login.call_count, 2)

    def test_service_login_locked_message_is_not_retried_as_generic_failure(self) -> None:
        client = self.login_client()
        client.replace_online_devices = Mock()
        client.service_login.return_value = {
            "code": 200,
            "data": {"authResult": "fail", "authMessage": "该账号已永久冻结"},
        }

        with self.assertRaises(PortalError) as raised:
            client.login("dummy", "secret", "中国电信")

        self.assertEqual(raised.exception.category, "account_locked")
        self.assertEqual(raised.exception.stage, "service_login")
        client.replace_online_devices.assert_not_called()
        client.user_online.assert_not_called()

    def test_service_login_explicit_password_rejection_is_non_retryable(self) -> None:
        client = self.login_client()
        client.service_login.return_value = {
            "code": 403,
            "message": "用户名或密码错误",
        }

        with self.assertRaises(PortalError) as raised:
            client.login("dummy", "secret", "中国电信")

        self.assertEqual(raised.exception.category, "credential_rejected")
        self.assertEqual(raised.exception.stage, "service_login")
        client.user_online.assert_not_called()

    def test_cas_generic_error_is_not_misclassified_as_bad_password(self) -> None:
        key = base64.b64encode(b"0123456789abcdef").decode("ascii")
        client = PortalClient()
        client._request_follow_safe = Mock(side_effect=[
            html_response(
                f'<p id="login-croypto">{key}</p>'
                '<p id="login-page-flowkey">test-execution</p>'
            ),
            html_response('<div id="errorMessage">系统繁忙，请稍后重试</div>'),
        ])

        with self.assertRaises(PortalError) as raised:
            client.cas_login("dummy", "secret", {"sessionId": "test-session"})

        self.assertEqual(raised.exception.category, "authentication_failed")

    def test_password_message_variants_are_classified_as_terminal(self) -> None:
        for message in (
            "帐号密码错误",
            "invalid username or password",
            "wrong password",
        ):
            with self.subTest(message=message):
                self.assertEqual(
                    PortalClient._auth_message_category(
                        message, default="authentication_failed",
                    ),
                    "credential_rejected",
                )

    def test_account_blocked_detection_is_narrow_and_case_insensitive(self) -> None:
        self.assertTrue(PortalClient._account_blocked("Account LOCKED by administrator"))
        self.assertTrue(PortalClient._account_blocked("密码错误次数过多，请稍后处理"))
        self.assertFalse(PortalClient._account_blocked("认证失败，请稍后重试"))

    def test_ip_blocked_detection_is_distinct_from_account_freeze(self) -> None:
        for message in (
            "当前IP已被冻结，请联系管理员",
            "登录 IP address is blocked",
            "source IP has been blacklisted",
            "客户端地址被限制登录",
            "IP_FROZEN",
        ):
            with self.subTest(message=message):
                self.assertTrue(PortalClient._ip_blocked(message))
                self.assertEqual(
                    PortalClient._auth_message_category(
                        message, default="authentication_failed",
                    ),
                    "ip_blocked",
                )
                self.assertFalse(PortalClient._account_blocked(message))

    def test_ip_blocked_detection_does_not_match_ordinary_ip_errors(self) -> None:
        for message in (
            "IP地址校验失败，请稍后重试",
            "当前登录IP为 10.0.0.2",
            "无法获取客户端IP",
            "shipping service is blocked",
        ):
            with self.subTest(message=message):
                self.assertFalse(PortalClient._ip_blocked(message))

    def test_account_freeze_requires_account_context(self) -> None:
        self.assertTrue(PortalClient._account_blocked("账号已冻结"))
        self.assertTrue(PortalClient._account_blocked("user account disabled"))
        self.assertFalse(PortalClient._account_blocked("IP已被冻结"))

    def test_service_login_uses_structured_error_code_when_message_is_generic(self) -> None:
        error = PortalClient()._service_login_error({
            "code": 200,
            "data": {
                "authResult": "fail",
                "authMessage": "请求被拒绝",
                "errorCode": "IP_FROZEN",
            },
        })

        self.assertIsNotNone(error)
        self.assertEqual(error.category, "ip_blocked")

    def test_cas_locked_message_has_distinct_category(self) -> None:
        key = base64.b64encode(b"0123456789abcdef").decode("ascii")
        client = PortalClient()
        client._request_follow_safe = Mock(side_effect=[
            html_response(
                f'<p id="login-croypto">{key}</p>'
                '<p id="login-page-flowkey">test-execution</p>'
            ),
            html_response('<div id="errorMessage">账号已永久冻结</div>'),
        ])

        with self.assertRaises(PortalError) as raised:
            client.cas_login("dummy", "secret", {"sessionId": "test-session"})

        self.assertEqual(raised.exception.category, "account_locked")
        self.assertEqual(raised.exception.stage, "cas_login")

    def test_cancelled_request_does_not_reach_http_session(self) -> None:
        client = PortalClient(operation_allowed=lambda: False)
        client.session.request = Mock()
        with self.assertRaises(PortalError) as raised:
            client._request("POST", f"{BASE_URL}/api", "test", json={"sessionId": "dummy"})
        self.assertEqual(raised.exception.category, "operation_cancelled")
        client.session.request.assert_not_called()

    def test_stop_during_device_release_wait_prevents_compensation(self) -> None:
        running = {"value": True}
        client = PortalClient(
            sleeper=lambda _: running.update(value=False),
            operation_allowed=lambda: running["value"], reporter=Mock(),
        )
        client.find_online_devices = Mock(return_value=[{"onlineUserUuid": "test-device"}])
        client.kick_online_devices = Mock()
        client.manual_compensation_login = Mock()
        with self.assertRaises(PortalError) as raised:
            client.replace_online_devices("test-session")
        self.assertEqual(raised.exception.category, "operation_cancelled")
        client.manual_compensation_login.assert_not_called()

    def test_device_replacement_is_not_repeated_during_online_polling(self) -> None:
        client = self.login_client()
        client.service_login.return_value = {
            "code": 200, "data": {"authResult": "fail", "authMessage": "宽带账号已在线"},
        }
        client.replace_online_devices = Mock(return_value=1)
        client.user_online.side_effect = [
            {"online": False, "message": "宽带账号已在线"}, {"online": True},
        ]
        self.assertTrue(client.login("dummy", "secret", "中国电信"))
        client.replace_online_devices.assert_called_once_with("test-session")

    def test_verification_does_not_release_other_devices(self) -> None:
        client = self.login_client()
        client.service_login.return_value = {
            "code": 200,
            "data": {"authResult": "fail", "authMessage": "宽带账号已在线"},
        }
        client.user_online.return_value = {"online": False, "message": "宽带账号已在线"}
        client.replace_online_devices = Mock()

        with self.assertRaises(PortalError) as raised:
            client.login(
                "dummy",
                "secret",
                "中国电信",
                allow_device_release=False,
            )

        self.assertEqual(raised.exception.category, "account_in_use")
        client.replace_online_devices.assert_not_called()

    def test_verification_does_not_treat_existing_online_session_as_success(self) -> None:
        client = self.login_client()
        client.service_login.return_value = {
            "code": 200,
            "data": {"authResult": "fail", "authMessage": "宽带账号已在线"},
        }
        client.user_online.return_value = {"online": True}
        client.replace_online_devices = Mock()

        with self.assertRaises(PortalError) as raised:
            client.login(
                "dummy",
                "secret",
                "中国电信",
                allow_device_release=False,
            )

        self.assertEqual(raised.exception.category, "account_in_use")
        client.replace_online_devices.assert_not_called()

    def test_delayed_logout_is_polled_before_switching(self) -> None:
        client = PortalClient(sleeper=Mock())
        client.status = Mock(side_effect=[
            PortalStatus(True, {"sessionId": "test-session"}),
            PortalStatus(True, {}), PortalStatus(False, {}),
        ])
        client.offline = Mock()
        self.assertTrue(client.logout())
        client.offline.assert_called_once_with("test-session")
        self.assertEqual(client.status.call_count, 3)

    def test_existing_session_is_distinguished_from_submitted_login(self) -> None:
        client = self.login_client()
        client.status.return_value = PortalStatus(True, {})
        self.assertFalse(client.login("dummy-new-user", "secret", "中国电信"))
        client.cas_login.assert_not_called()

    def test_profile_switch_logs_out_existing_session_before_new_login(self) -> None:
        client = self.login_client()
        client.status.return_value = PortalStatus(True, {})
        calls = []
        client.logout = Mock(side_effect=lambda: calls.append("logout"))
        client.cas_login.side_effect = lambda *_: calls.append("login")
        self.assertTrue(client.login("new-dummy", "secret", "中国电信", force_switch=True))
        self.assertEqual(calls, ["logout", "login"])

    def test_failed_logout_prevents_submitting_new_account(self) -> None:
        client = self.login_client()
        client.status.return_value = PortalStatus(True, {})
        client.logout = Mock(side_effect=PortalError("verification_failed", "logout", "still online"))
        with self.assertRaises(PortalError):
            client.login("new-dummy", "secret", "中国电信", force_switch=True)
        client.cas_login.assert_not_called()

    def test_data_response_rejects_non_object_json(self) -> None:
        with self.assertRaises(PortalError) as raised:
            PortalClient._data_response(json_response([]), "test")
        self.assertEqual(raised.exception.category, "protocol_changed")

    def test_data_response_rejects_non_200_code(self) -> None:
        with self.assertRaises(PortalError) as raised:
            PortalClient._data_response(
                json_response({"code": 401, "message": "rejected"}), "test"
            )
        self.assertEqual(raised.exception.category, "api_error")

    def test_data_response_classifies_structured_ip_freeze(self) -> None:
        with self.assertRaises(PortalError) as raised:
            PortalClient._data_response(
                json_response({
                    "code": 403,
                    "message": "请求被拒绝",
                    "errorCode": "IP_FROZEN",
                }),
                "service_login",
            )
        self.assertEqual(raised.exception.category, "ip_blocked")

    def test_encrypt_rejects_invalid_aes_key(self) -> None:
        invalid_key = base64.b64encode(b"too-short").decode()
        with self.assertRaises(PortalError) as raised:
            PortalClient._encrypt(invalid_key, "password")
        self.assertEqual(raised.exception.category, "protocol_changed")

    def test_safe_redirect_does_not_request_attacker_host(self) -> None:
        client = PortalClient()
        response = requests.Response()
        response.status_code = 307
        response.url = "https://auth1.ysu.edu.cn/cas-sso/login"
        response.headers["Location"] = "https://auth1.ysu.edu.cn.attacker.example/capture"
        client._request = Mock(return_value=response)

        with self.assertRaises(PortalError) as raised:
            client._request_follow_safe(
                "POST",
                "https://auth1.ysu.edu.cn/cas-sso/login",
                "test",
                data={"password": "encrypted"},
            )

        self.assertEqual(raised.exception.category, "unsafe_redirect")
        self.assertEqual(client._request.call_count, 1)

    def test_portal_bootstrap_allows_fixed_gateway_ip(self) -> None:
        client = PortalClient()
        redirect = requests.Response()
        redirect.status_code = 302
        redirect.url = "https://auth1.ysu.edu.cn/eportal/redirect.jsp?mode=history"
        redirect.headers["Location"] = "http://124.124.124.124/bootstrap"
        final = requests.Response()
        final.status_code = 200
        final.url = "http://124.124.124.124/bootstrap"
        client._request = Mock(side_effect=[redirect, final])

        response = client._request_follow_safe(
            "GET",
            redirect.url,
            "portal_redirect",
            allowed_hosts=PORTAL_REDIRECT_HOSTS,
            allowed_http_hosts=PORTAL_HTTP_HOSTS,
        )

        self.assertEqual(response.url, final.url)
        self.assertEqual(client._request.call_count, 2)

    def test_portal_bootstrap_upgrades_observed_auth_http_hop_locally(self) -> None:
        client = PortalClient()
        redirect = requests.Response()
        redirect.status_code = 302
        redirect.url = "https://auth1.ysu.edu.cn/eportal/redirect.jsp?mode=history"
        redirect.headers["Location"] = (
            "http://auth1.ysu.edu.cn/portal/portal-main?sessionId=test-session"
        )
        final = requests.Response()
        final.status_code = 200
        final.url = (
            "https://auth1.ysu.edu.cn/portal/portal-main?sessionId=test-session"
        )
        final._content = b""
        client._request = Mock(side_effect=[redirect, final])

        params = client.redirect_to_portal()

        requested_urls = [call.args[1] for call in client._request.call_args_list]
        self.assertEqual(params["sessionId"], "test-session")
        self.assertEqual(requested_urls, [redirect.url, final.url])
        self.assertFalse(any(url.startswith("http://") for url in requested_urls))

    def test_only_observed_auth_http_path_can_be_upgraded(self) -> None:
        client = PortalClient()
        redirect = requests.Response()
        redirect.status_code = 302
        redirect.url = "https://auth1.ysu.edu.cn/eportal/redirect.jsp?mode=history"
        redirect.headers["Location"] = "http://auth1.ysu.edu.cn/capture?secret=value"
        client._request = Mock(return_value=redirect)

        with self.assertRaises(PortalError) as raised:
            client._request_follow_safe(
                "GET",
                redirect.url,
                "portal_redirect",
                allowed_hosts=PORTAL_REDIRECT_HOSTS,
                allowed_http_hosts=PORTAL_HTTP_HOSTS,
                upgrade_http_destinations=PORTAL_HTTPS_UPGRADES,
            )

        self.assertEqual(raised.exception.category, "unsafe_redirect")
        self.assertNotIn("secret=value", str(raised.exception))
        client._request.assert_called_once()

    def test_safe_redirect_rejects_https_downgrade_for_auth_host(self) -> None:
        client = PortalClient()
        response = requests.Response()
        response.status_code = 307
        response.url = "https://auth1.ysu.edu.cn/api"
        response.headers["Location"] = "http://auth1.ysu.edu.cn/capture"
        client._request = Mock(return_value=response)

        with self.assertRaises(PortalError) as raised:
            client._request_follow_safe(
                "POST",
                response.url,
                "test",
                json={"sessionId": "secret-session"},
            )

        self.assertEqual(raised.exception.category, "unsafe_redirect")
        self.assertEqual(client._request.call_count, 1)

    def test_safe_redirect_rejects_nonstandard_port(self) -> None:
        client = PortalClient()

        with self.assertRaises(PortalError) as raised:
            client._request_follow_safe(
                "POST",
                "https://auth1.ysu.edu.cn:4443/api",
                "test",
                json={"sessionId": "secret-session"},
            )

        self.assertEqual(raised.exception.category, "unsafe_redirect")

    def test_logout_uses_online_session_and_verifies_offline(self) -> None:
        client = PortalClient()
        client.status = Mock(
            side_effect=[
                PortalStatus(
                    True,
                    {"portalOnlineUserInfo": {"sessionId": "test-session"}},
                ),
                PortalStatus(
                    False,
                    {"portalOnlineUserInfo": {"redirectUrl": "portal"}},
                ),
            ]
        )
        client.offline = Mock()

        changed = client.logout()

        self.assertTrue(changed)
        client.offline.assert_called_once_with("test-session")

    def test_logout_is_noop_when_already_offline(self) -> None:
        client = PortalClient()
        client.status = Mock(
            return_value=PortalStatus(
                False,
                {"portalOnlineUserInfo": {"redirectUrl": "portal"}},
            )
        )
        client.redirect_to_portal = Mock(return_value={"sessionId": "test-session"})
        client.user_online = Mock(return_value={"online": False})
        client.offline = Mock()

        changed = client.logout()

        self.assertFalse(changed)
        client.redirect_to_portal.assert_called_once_with()
        client.user_online.assert_called_once_with("test-session")
        client.offline.assert_not_called()

    def test_logout_rechecks_session_when_status_endpoint_says_offline(self) -> None:
        client = PortalClient()
        client.status = Mock(
            side_effect=[
                PortalStatus(
                    False,
                    {"portalOnlineUserInfo": {"redirectUrl": "portal"}},
                ),
                PortalStatus(
                    False,
                    {"portalOnlineUserInfo": {"redirectUrl": "portal"}},
                ),
            ]
        )
        client.redirect_to_portal = Mock(return_value={"sessionId": "test-session"})
        client.user_online = Mock(return_value={"online": True})
        client.offline = Mock()

        changed = client.logout()

        self.assertTrue(changed)
        client.redirect_to_portal.assert_called_once_with()
        client.user_online.assert_called_once_with("test-session")
        client.offline.assert_called_once_with("test-session")

    def test_broadband_occupation_does_not_kick_when_already_online(self) -> None:
        client = PortalClient()
        client.status = Mock(
            return_value=PortalStatus(
                False,
                {"portalOnlineUserInfo": {"redirectUrl": "portal"}},
            )
        )
        client.redirect_to_portal = Mock(return_value={"sessionId": "test-session"})
        client.get_current_node = Mock(return_value={"currentNodePath": "test-node"})
        client.cas_login = Mock()
        client.service_selection = Mock()
        client.service_login = Mock(
            return_value={
                "code": 200,
                "data": {
                    "authResult": "fail",
                    "authMessage": "宽带账号已在线",
                },
            }
        )
        client.replace_online_devices = Mock(return_value=1)
        client.user_online = Mock(return_value={"online": True})

        client.login("student", "secret", "中国联通")

        client.replace_online_devices.assert_not_called()
        client.user_online.assert_called_once_with("test-session")

    def test_verify_stage_online_limit_also_kicks_old_device(self) -> None:
        client = PortalClient()
        client.status = Mock(
            return_value=PortalStatus(
                False,
                {"portalOnlineUserInfo": {"redirectUrl": "portal"}},
            )
        )
        client.redirect_to_portal = Mock(return_value={"sessionId": "test-session"})
        client.get_current_node = Mock(return_value={"currentNodePath": "test-node"})
        client.cas_login = Mock()
        client.service_selection = Mock()
        client.service_login = Mock(
            return_value={
                "code": 200,
                "data": {"authResult": "success"},
            }
        )
        client.user_online = Mock(
            side_effect=[
                {
                    "online": False,
                    "message": "账号已达到同时在线用户数量上限",
                },
                {"online": True},
            ]
        )
        client.replace_online_devices = Mock(return_value=1)

        client.login("student", "secret", "中国联通")

        client.replace_online_devices.assert_called_once_with("test-session")
        self.assertEqual(client.user_online.call_count, 2)

    def test_unrelated_online_user_error_does_not_kick_devices(self) -> None:
        client = PortalClient()

        self.assertFalse(
            client._account_in_use("在线用户信息读取失败，请稍后重试")
        )

    def test_replace_online_devices_uses_portal_web_flow(self) -> None:
        client = PortalClient(sleeper=Mock())
        client.find_online_devices = Mock(
            return_value=[
                {"onlineUserUuid": "old-device-1"},
                {"onlineUserUuid": "old-device-2"},
            ]
        )
        client.kick_online_devices = Mock()
        client.manual_compensation_login = Mock()

        removed = client.replace_online_devices("test-session")

        self.assertEqual(removed, 2)
        client.kick_online_devices.assert_called_once_with(
            "test-session",
            ["old-device-1", "old-device-2"],
        )
        client.sleeper.assert_called_once_with(15)
        client.manual_compensation_login.assert_called_once_with("test-session")

    def test_find_online_devices_uses_verified_portal_endpoint(self) -> None:
        client = PortalClient()
        client._post_data = Mock(
            return_value={
                "onlineDevices": [{"onlineUserUuid": "old-device"}]
            }
        )

        devices = client.find_online_devices("test-session")

        self.assertEqual(devices, [{"onlineUserUuid": "old-device"}])
        client._post_data.assert_called_once_with(
            "/eportal/adaptor/devices/findDevice",
            "find_online_devices",
            "test-session",
        )

    def test_kick_online_devices_sends_only_verified_uuids(self) -> None:
        client = PortalClient()
        response = Mock()
        response.json.return_value = {"code": 200, "message": "ok"}
        client._request_follow_safe = Mock(return_value=response)

        client.kick_online_devices(
            "test-session", ["old-device-1", "old-device-2"]
        )

        client._request_follow_safe.assert_called_once_with(
            "POST",
            f"{BASE_URL}/eportal/adaptor/kick-offline/batch",
            "kick_online_devices",
            json={
                "sessionId": "test-session",
                "onlineUserUuids": ["old-device-1", "old-device-2"],
            },
        )

    def test_replace_online_devices_refuses_empty_identifier_list(self) -> None:
        client = PortalClient(sleeper=Mock())
        client.find_online_devices = Mock(return_value=[{"deviceName": "unknown"}])
        client.kick_online_devices = Mock()

        with self.assertRaises(PortalError) as raised:
            client.replace_online_devices("test-session")

        self.assertEqual(raised.exception.category, "account_in_use")
        client.kick_online_devices.assert_not_called()


if __name__ == "__main__":
    unittest.main()
