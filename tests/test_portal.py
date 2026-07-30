from __future__ import annotations

import base64
import unittest
from unittest.mock import Mock

import requests

from ysu_net_watch.portal import (
    BASE_URL,
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


class PortalClientTests(unittest.TestCase):
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
        )

        self.assertEqual(response.url, final.url)
        self.assertEqual(client._request.call_count, 2)

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
        client.offline = Mock()

        changed = client.logout()

        self.assertFalse(changed)
        client.offline.assert_not_called()

    def test_broadband_occupation_kicks_old_device_and_continues(self) -> None:
        client = PortalClient()
        client.status = Mock(
            return_value=PortalStatus(
                False,
                {"portalOnlineUserInfo": {"redirectUrl": "portal"}},
            )
        )
        client.redirect_to_portal = Mock(return_value={"sessionId": "test-session"})
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

        client.replace_online_devices.assert_called_once_with("test-session")
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
        client._request = Mock(return_value=response)

        client.kick_online_devices(
            "test-session", ["old-device-1", "old-device-2"]
        )

        client._request.assert_called_once_with(
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
