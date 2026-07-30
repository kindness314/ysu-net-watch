from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
# PyCryptodome deliberately provides the ``Crypto`` namespace. These imports
# are not the abandoned PyCrypto package that Bandit's B413 check targets.
from Crypto.Cipher import AES  # nosec B413
from Crypto.Util.Padding import pad  # nosec B413


AUTH_HOST = "auth1.ysu.edu.cn"
BASE_URL = f"https://{AUTH_HOST}"
CAS_REDIRECT_HOSTS = {AUTH_HOST, "cer.ysu.edu.cn"}
PORTAL_REDIRECT_HOSTS = {*CAS_REDIRECT_HOSTS, "124.124.124.124"}
PORTAL_HTTP_HOSTS = {"124.124.124.124"}


class PortalError(RuntimeError):
    def __init__(self, category: str, stage: str, message: str, http_status: int | None = None):
        super().__init__(message)
        self.category = category
        self.stage = stage
        self.http_status = http_status


@dataclass(frozen=True)
class PortalStatus:
    online: bool
    data: dict[str, Any]


class PortalClient:
    def __init__(
        self,
        timeout: tuple[float, float] = (5.0, 10.0),
        sleeper=time.sleep,
        reporter=print,
    ):
        self.timeout = timeout
        self.sleeper = sleeper
        self.reporter = reporter
        self.session = requests.Session()
        # Captive portal traffic must not be sent through a desktop proxy/VPN.
        self.session.trust_env = False
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
                )
            }
        )

    def _request(self, method: str, url: str, stage: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        # Redirects are opt-in so request bodies containing session identifiers
        # can never be forwarded before the destination has been validated.
        kwargs.setdefault("allow_redirects", False)
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.Timeout as exc:
            raise PortalError("timeout", stage, f"{stage} timed out") from exc
        except requests.RequestException as exc:
            status = exc.response.status_code if exc.response is not None else None
            raise PortalError("network_error", stage, f"{stage} request failed", status) from exc

    def _request_follow_safe(
        self,
        method: str,
        url: str,
        stage: str,
        *,
        allowed_hosts: set[str] | None = None,
        allowed_http_hosts: set[str] | None = None,
        **kwargs,
    ) -> requests.Response:
        """Follow redirects only after validating every destination host."""
        allowed_hosts = allowed_hosts or CAS_REDIRECT_HOSTS
        allowed_http_hosts = allowed_http_hosts or set()
        current_method = method.upper()
        current_url = url
        current_kwargs = dict(kwargs)
        current_kwargs["allow_redirects"] = False

        for _ in range(10):
            parsed_current = urlparse(current_url)
            try:
                port = parsed_current.port
            except ValueError as exc:
                raise PortalError(
                    "unsafe_redirect", stage, f"{stage} returned an invalid redirect port"
                ) from exc
            hostname = (parsed_current.hostname or "").lower()
            scheme = parsed_current.scheme.lower()
            permitted_scheme = scheme == "https" or (
                scheme == "http" and hostname in allowed_http_hosts
            )
            permitted_port = port is None or (
                scheme == "https" and port == 443
            ) or (
                scheme == "http" and port == 80
            )
            if (
                hostname not in allowed_hosts
                or not permitted_scheme
                or not permitted_port
                or parsed_current.username is not None
                or parsed_current.password is not None
            ):
                raise PortalError(
                    "unsafe_redirect",
                    stage,
                    f"{stage} attempted to use an unsafe destination",
                )

            response = self._request(
                current_method, current_url, stage, **current_kwargs
            )
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response

            location = response.headers.get("Location")
            if not location:
                raise PortalError(
                    "protocol_changed", stage, f"{stage} redirect had no Location"
                )
            target = urljoin(response.url, location)
            if response.status_code == 303 or (
                response.status_code in {301, 302} and current_method == "POST"
            ):
                current_method = "GET"
                current_kwargs.pop("data", None)
                current_kwargs.pop("json", None)
            current_url = target

        raise PortalError(
            "protocol_changed", stage, f"{stage} exceeded the redirect limit"
        )

    @staticmethod
    def _data_response(response: requests.Response, stage: str) -> Any:
        try:
            payload = response.json()
        except ValueError as exc:
            raise PortalError("protocol_changed", stage, f"{stage} returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise PortalError(
                "protocol_changed", stage, f"{stage} returned a non-object JSON value"
            )
        if payload.get("code") != 200:
            message = str(payload.get("message") or "portal API rejected the request")
            raise PortalError("api_error", stage, message, response.status_code)
        return payload.get("data")

    def get_online_user_info(self, session_id: str = "") -> dict[str, Any]:
        timestamp = int(time.time() * 1000)
        url = (
            f"{BASE_URL}/eportal/adaptor/getOnlineUserInfo"
            f"?sessionId={session_id}&{timestamp}&version=ysu-net-watch-0.2.0"
        )
        response = self._request_follow_safe("GET", url, "status")
        data = self._data_response(response, "status")
        if not isinstance(data, dict):
            raise PortalError("protocol_changed", "status", "status response has no data object")
        return data

    def status(self) -> PortalStatus:
        data = self.get_online_user_info()
        portal_info = data.get("portalOnlineUserInfo")
        if not isinstance(portal_info, dict):
            raise PortalError("protocol_changed", "status", "missing portalOnlineUserInfo")
        return PortalStatus(online=not bool(portal_info.get("redirectUrl")), data=data)

    def redirect_to_portal(self) -> dict[str, str]:
        response = self._request_follow_safe(
            "GET",
            f"{BASE_URL}/eportal/redirect.jsp?mode=history",
            "portal_redirect",
            allowed_hosts=PORTAL_REDIRECT_HOSTS,
            allowed_http_hosts=PORTAL_HTTP_HOSTS,
        )

        for _ in range(2):
            match = re.search(
                r"(?:window\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]",
                response.text,
                flags=re.IGNORECASE,
            )
            if not match:
                break
            target = urljoin(response.url, match.group(1))
            if (urlparse(target).hostname or "").lower() not in PORTAL_REDIRECT_HOSTS:
                raise PortalError("unsafe_redirect", "portal_redirect", "portal returned an unexpected host")
            response = self._request_follow_safe(
                "GET",
                target,
                "portal_redirect",
                allowed_hosts=PORTAL_REDIRECT_HOSTS,
                allowed_http_hosts=PORTAL_HTTP_HOSTS,
            )

        parsed = urlparse(response.url)
        if (parsed.hostname or "").lower() != AUTH_HOST or "portal-main" not in parsed.path:
            raise PortalError(
                "protocol_changed", "portal_redirect", "portal-main redirect was not reached"
            )
        params = {key: values[0] for key, values in parse_qs(parsed.query).items() if values}
        if not params.get("sessionId"):
            raise PortalError("protocol_changed", "portal_redirect", "portal sessionId is missing")
        return params

    @staticmethod
    def _encrypt(key_b64: str, plaintext: str) -> str:
        try:
            key = base64.b64decode(key_b64, validate=True)
            cipher = AES.new(key, AES.MODE_ECB)
        except (ValueError, TypeError) as exc:
            raise PortalError("protocol_changed", "cas_login", "invalid portal encryption key") from exc
        encrypted = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        return base64.b64encode(encrypted).decode("ascii")

    def cas_login(self, username: str, password: str, session_info: dict[str, str]) -> None:
        params = {
            "flowSessionId": session_info.get("sessionId", ""),
            "customPageId": session_info.get("customPageId", ""),
            "preview": "false",
            "appType": "normal",
            "language": "zh-CN",
            "mode": session_info.get("mode", ""),
            "timer": str(int(time.time() * 1000)),
            "nasIp": session_info.get("nasIp", ""),
            "userIp": session_info.get("userIp", ""),
            "ssid": session_info.get("ssid", ""),
        }
        login_url = f"{BASE_URL}/cas-sso/login?{urlencode(params)}"
        response = self._request_follow_safe("GET", login_url, "cas_page")
        soup = BeautifulSoup(response.text, "html.parser")
        key_element = soup.select_one("p#login-croypto")
        execution_element = soup.select_one("p#login-page-flowkey")
        if key_element is None or execution_element is None:
            raise PortalError(
                "protocol_changed", "cas_page", "CAS encryption or execution field is missing"
            )

        key = key_element.get_text(strip=True)
        execution = execution_element.get_text(strip=True)
        form = {
            "username": username,
            "type": "UsernamePassword",
            "_eventId": "submit",
            "geolocation": "",
            "execution": execution,
            "captcha_code": "",
            "croypto": key,
            "password": self._encrypt(key, password),
            "captcha_payload": self._encrypt(key, "{}"),
        }
        response = self._request_follow_safe(
            "POST",
            f"{login_url}&accept-language=zh-CN",
            "cas_login",
            data=form,
        )
        final_url = response.url
        if "auth-success" in final_url or "ticket=" in final_url:
            return

        error = BeautifulSoup(response.text, "html.parser").select_one("#errorMessage")
        if error is not None and error.get_text(strip=True):
            raise PortalError("credential_rejected", "cas_login", error.get_text(strip=True))
        raise PortalError("authentication_failed", "cas_login", "CAS login did not return a ticket")

    def _post_data(self, path: str, stage: str, session_id: str, **values) -> Any:
        payload = {"sessionId": session_id, **values}
        response = self._request_follow_safe(
            "POST", f"{BASE_URL}{path}", stage, json=payload
        )
        return self._data_response(response, stage)

    def service_selection(self, session_id: str) -> Any:
        return self._post_data(
            "/eportal/network/serviceSelection", "service_selection", session_id
        )

    def service_login(self, session_id: str, service: str) -> dict[str, Any]:
        response = self._request_follow_safe(
            "POST",
            f"{BASE_URL}/eportal/network/serviceLogin",
            "service_login",
            json={"sessionId": session_id, "service": service},
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise PortalError("protocol_changed", "service_login", "service login returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise PortalError("protocol_changed", "service_login", "service login response is invalid")
        return payload

    def user_online(self, session_id: str) -> dict[str, Any]:
        data = self._post_data("/eportal/network/userOnline", "verify_login", session_id)
        if not isinstance(data, dict):
            raise PortalError("protocol_changed", "verify_login", "online response is invalid")
        return data

    def offline(self, session_id: str) -> Any:
        return self._post_data(
            "/eportal/network/offline", "logout", session_id
        )

    def find_online_devices(self, session_id: str) -> list[dict[str, Any]]:
        data = self._post_data(
            "/eportal/adaptor/devices/findDevice",
            "find_online_devices",
            session_id,
        )
        if not isinstance(data, dict) or not isinstance(
            data.get("onlineDevices"), list
        ):
            raise PortalError(
                "protocol_changed",
                "find_online_devices",
                "online device response is invalid",
            )
        return [
            device for device in data["onlineDevices"] if isinstance(device, dict)
        ]

    def kick_online_devices(
        self, session_id: str, online_user_uuids: list[str]
    ) -> None:
        response = self._request_follow_safe(
            "POST",
            f"{BASE_URL}/eportal/adaptor/kick-offline/batch",
            "kick_online_devices",
            json={
                "sessionId": session_id,
                "onlineUserUuids": online_user_uuids,
            },
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise PortalError(
                "protocol_changed",
                "kick_online_devices",
                "device offline response is invalid",
            ) from exc
        if (
            not isinstance(payload, dict)
            or payload.get("code") != 200
            or str(payload.get("message", "")).upper() != "OK"
        ):
            message = (
                str(payload.get("message") or "device offline request failed")
                if isinstance(payload, dict)
                else "device offline response is invalid"
            )
            raise PortalError(
                "device_offline_failed",
                "kick_online_devices",
                message,
            )

    def manual_compensation_login(self, session_id: str) -> None:
        data = self._post_data(
            "/eportal/network/manualCompensationLogin",
            "manual_compensation_login",
            session_id,
        )
        if not data:
            raise PortalError(
                "authentication_failed",
                "manual_compensation_login",
                "manual compensation login was rejected",
            )

    def replace_online_devices(self, session_id: str) -> int:
        devices = self.find_online_devices(session_id)
        online_user_uuids = [
            value
            for device in devices
            if isinstance((value := device.get("onlineUserUuid")), str)
            and value
        ]
        # Refuse malformed or unreasonably large batches instead of sending
        # unverified identifiers to a destructive endpoint.
        if not online_user_uuids:
            raise PortalError(
                "account_in_use",
                "find_online_devices",
                "account is in use but no removable online device was returned",
            )
        if len(online_user_uuids) > 20:
            raise PortalError(
                "protocol_changed",
                "find_online_devices",
                "portal returned an unexpected number of online devices",
            )
        self.kick_online_devices(session_id, online_user_uuids)
        self.reporter(
            f"宽带账号被其他设备占用，已请求下线 "
            f"{len(online_user_uuids)} 个旧设备会话；15 秒后继续认证。"
        )
        # The official page enforces the same delay before continuing.
        self.sleeper(15)
        self.manual_compensation_login(session_id)
        return len(online_user_uuids)

    @staticmethod
    def _account_in_use(message: str) -> bool:
        markers = (
            "账号被占用",
            "宽带账号已在线",
            "账号已经在线",
            "并发用户数量上限",
            "并发数上限",
            "重复登录",
            "同时在线用户数量上限",
        )
        return any(marker in message for marker in markers)

    @staticmethod
    def _find_session_id(value: Any) -> str:
        if isinstance(value, dict):
            session_id = value.get("sessionId")
            if isinstance(session_id, str) and session_id:
                return session_id
            for child in value.values():
                found = PortalClient._find_session_id(child)
                if found:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = PortalClient._find_session_id(child)
                if found:
                    return found
        return ""

    def logout(self) -> bool:
        current = self.status()
        if not current.online:
            return False

        session_id = self._find_session_id(current.data)
        if not session_id:
            session_info = self.redirect_to_portal()
            session_id = session_info["sessionId"]

        self.offline(session_id)
        final = self.status()
        if final.online:
            raise PortalError(
                "verification_failed",
                "logout",
                "portal still reports the user as online after logout",
            )
        return True

    def login(self, username: str, password: str, service: str) -> None:
        status = self.status()
        if status.online:
            return

        session_info = self.redirect_to_portal()
        session_id = session_info["sessionId"]
        self.cas_login(username, password, session_info)
        self.service_selection(session_id)
        result = self.service_login(session_id, service)

        data = result.get("data") if result.get("code") == 200 else None
        if not isinstance(data, dict):
            raise PortalError("api_error", "service_login", "service login was rejected")
        auth_result = data.get("authResult")
        if auth_result != "success":
            message = str(data.get("authMessage") or f"unexpected result: {auth_result}")
            account_in_use = self._account_in_use(message)
            if account_in_use and service != "校园网":
                self.replace_online_devices(session_id)
            else:
                category = (
                    "account_in_use" if account_in_use else "authentication_failed"
                )
                raise PortalError(category, "service_login", message)

        online = self.user_online(session_id)
        if not online.get("online", False):
            message = str(
                online.get("message") or "portal reports that the user is offline"
            )
            if service != "校园网" and self._account_in_use(message):
                self.replace_online_devices(session_id)
                online = self.user_online(session_id)
            if online.get("online", False):
                return
            raise PortalError(
                "verification_failed",
                "verify_login",
                str(
                    online.get("message")
                    or "portal reports that the user is offline"
                ),
            )
