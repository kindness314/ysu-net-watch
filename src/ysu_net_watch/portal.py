from __future__ import annotations

from .recovery import RecoveryState

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
PORTAL_HTTPS_UPGRADES = {(AUTH_HOST, "/portal/portal-main")}


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
        operation_allowed=None,
        verification_delays: tuple[float, ...] = (2.0, 3.0, 5.0, 5.0),
    ):
        self.timeout = timeout
        self.sleeper = sleeper
        self.reporter = reporter
        self.operation_allowed = operation_allowed or (lambda: True)
        self.verification_delays = verification_delays
        self.recovery = RecoveryState()
        self.session = self._new_http_session()

    @staticmethod
    def _new_http_session() -> requests.Session:
        session = requests.Session()
        # Captive portal traffic must not be sent through a desktop proxy/VPN.
        session.trust_env = False
        session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
                )
            }
        )
        return session

    def _reset_http_session(self) -> None:
        self.session.close()
        self.session = self._new_http_session()

    def _require_active(self, stage: str) -> None:
        if not self.operation_allowed():
            raise PortalError(
                "operation_cancelled", stage, "authentication stopped or campus Wi-Fi changed"
            )

    def _request(self, method: str, url: str, stage: str, **kwargs) -> requests.Response:
        self._require_active(stage)
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
        upgrade_http_destinations: set[tuple[str, str]] | None = None,
        **kwargs,
    ) -> requests.Response:
        """Follow redirects only after validating every destination host."""
        allowed_hosts = allowed_hosts or CAS_REDIRECT_HOSTS
        allowed_http_hosts = allowed_http_hosts or set()
        upgrade_http_destinations = upgrade_http_destinations or set()
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
            if (
                current_method == "GET"
                and scheme == "http"
                and (hostname, parsed_current.path) in upgrade_http_destinations
                and (port is None or port == 80)
                and parsed_current.username is None
                and parsed_current.password is None
            ):
                # The YSU bootstrap currently emits an HTTP URL which only
                # responds with a 308 back to this exact HTTPS path. Skip the
                # clear-text round trip locally while preserving its query.
                parsed_current = parsed_current._replace(
                    scheme="https", netloc=hostname,
                )
                current_url = parsed_current.geturl()
                port = parsed_current.port
                scheme = "https"
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
                port_label = f":{port}" if port is not None else ""
                destination = (
                    f"{scheme or '<missing>'}://{hostname or '<missing>'}"
                    f"{port_label}{parsed_current.path or '/'}"
                )
                raise PortalError(
                    "unsafe_redirect",
                    stage,
                    f"{stage} attempted to use an unsafe destination ({destination})",
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

    @classmethod
    def _data_response(cls, response: requests.Response, stage: str) -> Any:
        try:
            payload = response.json()
        except ValueError as exc:
            raise PortalError("protocol_changed", stage, f"{stage} returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise PortalError(
                "protocol_changed", stage, f"{stage} returned a non-object JSON value"
        )
        if payload.get("code") != 200:
            nested = payload.get("data")
            message = cls._auth_response_text(
                payload,
                data=nested if isinstance(nested, dict) else None,
                fallback="portal API rejected the request",
            )
            category = cls._auth_message_category(message, default="api_error")
            raise PortalError(category, stage, message, response.status_code)
        return payload.get("data")

    def get_online_user_info(self, session_id: str = "") -> dict[str, Any]:
        timestamp = int(time.time() * 1000)
        url = (
            f"{BASE_URL}/eportal/adaptor/getOnlineUserInfo"
            f"?sessionId={session_id}&{timestamp}&version=ysu-net-watch-0.3.0rc1"
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
            upgrade_http_destinations=PORTAL_HTTPS_UPGRADES,
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
                upgrade_http_destinations=PORTAL_HTTPS_UPGRADES,
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
            message = error.get_text(strip=True)
            category = self._auth_message_category(
                message, default="authentication_failed",
            )
            raise PortalError(category, "cas_login", message)
        raise PortalError("authentication_failed", "cas_login", "CAS login did not return a ticket")

    def _post_data(self, path: str, stage: str, session_id: str, **values) -> Any:
        payload = {"sessionId": session_id, **values}
        response = self._request_follow_safe(
            "POST", f"{BASE_URL}{path}", stage, json=payload
        )
        return self._data_response(response, stage)

    def get_current_node(
        self, session_id: str, flow_key: str = "portal_auth"
    ) -> dict[str, Any]:
        data = self._post_data(
            "/eportal/workFlow/getCurrentNode",
            "workflow_node",
            session_id,
            flowKey=flow_key,
        )
        if not isinstance(data, dict):
            raise PortalError(
                "protocol_changed",
                "workflow_node",
                "workflow node response is invalid",
            )
        current_path = data.get("currentNodePath")
        if not isinstance(current_path, str) or not current_path.strip():
            raise PortalError(
                "workflow_state_missing",
                "workflow_node",
                "workflow node response has no currentNodePath",
            )
        return data

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
        self._require_active("find_online_devices")
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
        self._require_active("kick_online_devices")
        if not self.recovery.claim_device_release():
            raise PortalError(
                "account_in_use", "kick_online_devices",
                "本轮恢复已请求过旧设备下线，不重复踢设备；请检查占用状态",
            )
        self.kick_online_devices(session_id, online_user_uuids)
        self.reporter(
            f"宽带账号被其他设备占用，已请求下线 "
            f"{len(online_user_uuids)} 个旧设备会话；15 秒后继续认证。"
        )
        # The official page enforces the same delay before continuing.
        self.sleeper(15)
        self._require_active("manual_compensation_login")
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
    def _account_device_limit(message: str) -> bool:
        """Recognize explicit authentication-device capacity errors.

        Keep this narrower than ``_account_in_use``: an ordinary broadband
        session-occupancy response may still be recoverable by the verified
        device-release flow, while an explicit device-count limit must stop
        immediately and must not be retried with the same account.
        """
        normalized = message.casefold()
        markers = (
            "认证设备数量",
            "认证设备数",
            "认证终端数量",
            "认证终端数",
            "设备数量上限",
            "设备数上限",
            "设备数量已达到上限",
            "设备数已达到上限",
            "在线设备数量上限",
            "在线设备数上限",
            "在线设备数量已达到上限",
            "在线设备数已达到上限",
            "达到设备上限",
            "设备已达上限",
            "设备达到上限",
            "最大认证设备",
            "终端数量上限",
            "终端数上限",
            "终端数量已达到上限",
            "终端数已达到上限",
            "authentication device limit",
            "maximum authentication devices",
            "device count limit",
            "maximum number of devices",
            "maximum devices",
            "device limit",
        )
        if any(marker.casefold() in normalized for marker in markers):
            return True
        # Some portal versions interpolate the nouns and limit words in a
        # different order (for example, "登录设备达到最大数量").  Require a
        # device/terminal noun, an explicit capacity word, and an auth/count
        # context together so ordinary "account already online" messages do
        # not become terminal device-limit errors.
        device_context = any(word in normalized for word in ("设备", "终端", "device", "terminal"))
        capacity_context = any(word in normalized for word in (
            "上限", "最大", "限制", "超过", "已满", "limit", "maximum", "max", "exceed",
        ))
        auth_context = any(word in normalized for word in (
            "认证", "登录", "在线", "数量", "设备数", "terminal", "authentication", "login", "count",
        ))
        return device_context and capacity_context and auth_context

    @staticmethod
    def _normalized_auth_message(message: str) -> str:
        """Normalize portal messages without changing their meaning.

        Portal deployments mix ordinary and full-width Latin letters and often
        insert spaces around ``IP``. Removing whitespace here lets the
        classifiers recognize those harmless formatting differences while
        still requiring an explicit account/IP context below.
        """
        text = (
            str(message)
            .casefold()
            .replace("Ｉ", "i")
            .replace("Ｐ", "p")
            .replace("ｉ", "i")
            .replace("ｐ", "p")
        )
        return re.sub(r"\s+", "", text)

    @classmethod
    def _auth_response_text(
        cls,
        payload: dict[str, Any],
        *,
        data: dict[str, Any] | None = None,
        fallback: str,
    ) -> str:
        """Collect only human-readable auth error fields for classification.

        Some portal deployments put the wording in ``errorMsg`` and the
        machine-readable reason in ``errorCode`` rather than ``message`` or
        ``authMessage``.  Joining these small, known fields lets one classifier
        cover both forms without serializing arbitrary response JSON (which
        could contain session data).
        """
        values: list[str] = []
        seen: set[str] = set()
        for source in (payload, data):
            if not isinstance(source, dict):
                continue
            for key in (
                "message", "authMessage", "errorMessage", "errorMsg",
                "reason", "description", "errorCode", "authCode", "errCode",
            ):
                value = source.get(key)
                if value is None or isinstance(value, (dict, list, tuple, set)):
                    continue
                text = str(value).strip()
                if text and text not in seen:
                    seen.add(text)
                    values.append(text)
        return "；".join(values) if values else fallback

    @classmethod
    def _ip_blocked(cls, message: str) -> bool:
        """Recognize an explicit login-source IP freeze/block response.

        Do not classify every message mentioning an IP address as a freeze:
        redirects and ordinary address-validation errors also contain ``IP``.
        A terminal result needs both an IP/source context and a block/deny
        state phrase.
        """
        normalized = cls._normalized_auth_message(message)
        folded = (
            str(message)
            .casefold()
            .replace("Ｉ", "i")
            .replace("Ｐ", "p")
            .replace("ｉ", "i")
            .replace("ｐ", "p")
        )
        ip_context = bool(
            re.search(r"(?<![a-z0-9])ip(?:\s*address)?(?![a-z0-9])", folded)
        ) or any(
            marker in normalized
            for marker in (
                "来源地址", "来源ip", "客户端地址", "客户端ip", "登录地址",
                "登录ip", "源地址", "源ip", "sourceip", "clientip", "loginip",
                "ipblocked", "ipbanned", "ipfrozen", "iplocked",
                "iprestricted", "ipblacklisted",
            )
        )
        blocked_state = (
            "冻结" in normalized
            or "封禁" in normalized
            or "封锁" in normalized
            or "被封" in normalized
            or "锁定" in normalized
            or "受限" in normalized
            or "被限制" in normalized
            or "限制登录" in normalized
            or "禁止登录" in normalized
            or "不允许登录" in normalized
            or "禁止访问" in normalized
            or "访问被拒绝" in normalized
            or "拒绝访问" in normalized
            or "黑名单" in normalized
            or "blocked" in normalized
            or "banned" in normalized
            or "blacklisted" in normalized
            or "locked" in normalized
            or "frozen" in normalized
            or "restricted" in normalized
            or "denied" in normalized
        )
        return ip_context and blocked_state

    @classmethod
    def _account_blocked(cls, message: str) -> bool:
        """Recognize account states for which another login is unsafe.

        The account context is intentional. A broad check for ``冻结`` or
        ``锁定`` would mislabel an IP freeze as an account freeze and would
        show the wrong remediation to the user.
        """
        normalized = cls._normalized_auth_message(message)
        account_context = any(
            marker in normalized
            for marker in (
                "账号", "帐号", "账户", "用户", "学号", "account", "user",
                "studentid",
            )
        )
        blocked_state = any(
            marker in normalized
            for marker in (
                "冻结", "锁定", "封禁", "封锁", "停用", "受限", "被限制",
                "限制登录", "禁止登录", "禁止认证", "认证被禁止", "frozen", "locked",
                "disabled", "blocked", "banned", "blacklisted", "suspended",
            )
        )
        password_attempt_lock = any(
            marker in normalized
            for marker in (
                "密码错误次数过多",
                "密码错误过多",
                "passwordattemptsexceeded",
                "toomanyfailedpasswordattempts",
            )
        )
        return (account_context and blocked_state) or password_attempt_lock

    @staticmethod
    def _credentials_rejected(message: str) -> bool:
        """Recognize explicit credential rejection without broad error matching."""
        normalized = message.casefold()
        markers = (
            "用户名或密码",
            "用户名错误",
            "用户或密码",
            "用户密码错误",
            "账号或密码",
            "帐号或密码",
            "账户或密码",
            "账号密码错误",
            "帐号密码错误",
            "账户密码错误",
            "学号或密码",
            "学号密码错误",
            "账号不存在或密码",
            "帐号不存在或密码",
            "密码错误",
            "密码不正确",
            "口令错误",
            "凭据无效",
            "凭证无效",
            "invalid credentials",
            "invalid username or password",
            "invalid user name or password",
            "username or password",
            "invalid password",
            "incorrect password",
            "wrong password",
            "bad credentials",
        )
        return any(marker in normalized for marker in markers)

    @classmethod
    def _auth_message_category(cls, message: str, *, default: str) -> str:
        """Classify only explicit account/credential messages as terminal.

        Captive portals often put transient errors in the same HTML/JSON field as
        password errors.  Treating every non-success message as a bad password
        would hide a recoverable outage; treating an explicit password message as
        transient would repeatedly submit the same credentials.  Keep this
        classifier narrow and let the caller choose the fallback category.
        """
        # IP freezes must be checked before account freezes: both may contain
        # words such as “冻结/锁定”, but they require different remediation.
        if cls._ip_blocked(message):
            return "ip_blocked"
        if cls._account_blocked(message):
            return "account_locked"
        if cls._account_device_limit(message):
            return "account_device_limit"
        if cls._credentials_rejected(message):
            return "credential_rejected"
        if "workflownode is empty" in message.casefold():
            return "workflow_session_invalid"
        if cls._account_in_use(message):
            return "account_in_use"
        return default

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
        session_id = self._find_session_id(current.data)
        if not current.online:
            # The public status endpoint can report a redirect even while the
            # gateway still has this client online.  Establish a fresh,
            # read-only portal session and ask userOnline before deciding that
            # there is nothing to log out.  This never submits credentials.
            if not session_id:
                session_info = self.redirect_to_portal()
                session_id = session_info.get("sessionId", "")
            if not session_id:
                raise PortalError(
                    "protocol_changed",
                    "logout",
                    "portal did not return a session for logout verification",
                )
            online = self.user_online(session_id)
            if not online.get("online", False):
                return False

        if not session_id:
            session_info = self.redirect_to_portal()
            session_id = session_info.get("sessionId", "")
            if not session_id:
                raise PortalError(
                    "protocol_changed",
                    "logout",
                    "portal did not return a session for logout",
                )

        self.offline(session_id)
        for delay in (0.0, *self.verification_delays):
            if delay:
                self.sleeper(delay)
            self._require_active("logout")
            if not self.status().online:
                return True
        raise PortalError(
            "verification_failed",
            "logout",
            "portal still reports the user as online after logout verification",
        )

    def login(
        self, username: str, password: str, service: str, *,
        force_switch: bool = False,
        recovery: RecoveryState | None = None,
        allow_device_release: bool = True,
        allow_workflow_retry: bool = True,
    ) -> bool:
        """Return whether this call submitted a login, not just reused a session."""
        self.recovery = recovery if recovery is not None else RecoveryState()
        self._require_active("status")
        status = self.status()
        if status.online:
            if not force_switch:
                return False
            self.logout()

        while True:
            try:
                return self._login_with_new_portal_session(
                    username,
                    password,
                    service,
                    allow_device_release=allow_device_release,
                )
            except PortalError as exc:
                if exc.category != "workflow_session_invalid":
                    raise
                if not allow_workflow_retry:
                    raise PortalError(
                        "protocol_changed",
                        exc.stage,
                        str(exc),
                        exc.http_status,
                    ) from exc
                if not self.recovery.claim_workflow_session_retry():
                    raise PortalError(
                        "protocol_changed",
                        exc.stage,
                        str(exc),
                        exc.http_status,
                    ) from exc
                self._require_active("portal_redirect")
                self.reporter("门户工作流状态无效，正在使用全新会话重试一次。")
                self._reset_http_session()

    def _login_with_new_portal_session(
        self,
        username: str,
        password: str,
        service: str,
        *,
        allow_device_release: bool = True,
    ) -> bool:
        session_info = self.redirect_to_portal()
        session_id = session_info["sessionId"]
        self.cas_login(username, password, session_info)
        self.service_selection(session_id)

        # getCurrentNode is an observation endpoint used by the portal UI after
        # each operation.  It does not advance the workflow.  Check it here so
        # a missing node is caught before serviceLogin is submitted.
        try:
            self.get_current_node(session_id)
        except PortalError as exc:
            if exc.category == "workflow_state_missing":
                raise PortalError(
                    "workflow_session_invalid",
                    "workflow_node",
                    str(exc),
                    exc.http_status,
                ) from exc
            raise

        try:
            result = self.service_login(session_id, service)
            service_error = self._service_login_error(result)
        except PortalError as exc:
            if exc.category not in {"timeout", "network_error", "protocol_changed"}:
                raise
            service_error = exc

        if service_error is not None and service_error.category in {
            "ip_blocked", "account_locked", "credential_rejected",
            "account_device_limit",
        }:
            raise service_error

        replaced_devices = False
        last_online_message = "portal reports that the user is offline"
        # serviceLogin is known to return an error while the gateway is already
        # online.  Poll the read-only state before deciding whether another CAS
        # submission is necessary.
        for delay in (0.0, *self.verification_delays):
            if delay:
                self.sleeper(delay)
            self._require_active("verify_login")
            try:
                online = self.user_online(session_id)
            except PortalError as verify_error:
                if verify_error.category in {
                    "timeout", "network_error", "operation_cancelled",
                }:
                    raise
                if service_error is not None:
                    raise service_error from verify_error
                raise
            if online.get("online", False):
                if service_error is not None:
                    if (
                        service_error.category == "account_in_use"
                        and not allow_device_release
                    ):
                        # A verification run must not mistake another active
                        # broadband session for the account being tested.
                        raise service_error
                    self.reporter(
                        "服务登录接口返回异常，但门户已确认在线，按认证成功处理。"
                    )
                return True
            last_online_message = str(
                online.get("message") or "portal reports that the user is offline"
            )
            if self._account_device_limit(last_online_message):
                raise PortalError(
                    "account_device_limit", "verify_login", last_online_message,
                )
            if self._ip_blocked(last_online_message):
                raise PortalError(
                    "ip_blocked", "verify_login", last_online_message,
                )
            if self._account_blocked(last_online_message):
                raise PortalError(
                    "account_locked", "verify_login", last_online_message,
                )
            if self._credentials_rejected(last_online_message):
                raise PortalError(
                    "credential_rejected", "verify_login", last_online_message,
                )
            account_in_use = (
                service_error is not None
                and service_error.category == "account_in_use"
            ) or self._account_in_use(last_online_message)
            if (
                not replaced_devices
                and allow_device_release
                and service != "校园网"
                and account_in_use
            ):
                self.replace_online_devices(session_id)
                replaced_devices = True
                try:
                    online = self.user_online(session_id)
                except PortalError as verify_error:
                    if verify_error.category in {
                        "timeout", "network_error", "operation_cancelled",
                    }:
                        raise
                    if service_error is not None:
                        raise service_error from verify_error
                    raise
                if online.get("online", False):
                    return True
                last_online_message = str(
                    online.get("message")
                    or "portal reports that the user is offline"
                )

        if service_error is not None:
            if service_error.category == "workflow_session_invalid":
                raise service_error
            raise service_error
        if "workflownode is empty" in last_online_message.casefold():
            raise PortalError(
                "workflow_session_invalid",
                "verify_login",
                last_online_message,
            )
        raise PortalError(
            "verification_failed", "verify_login", last_online_message,
        )

    def _service_login_error(self, result: dict[str, Any]) -> PortalError | None:
        data = result.get("data")
        if not isinstance(data, dict):
            data = None
        if result.get("code") != 200 or data is None:
            message = self._auth_response_text(
                result, data=data, fallback="service login was rejected",
            )
            category = self._auth_message_category(message, default="api_error")
            return PortalError(
                category,
                "service_login",
                f"service login rejected (code={result.get('code')}): {message}",
            )

        auth_result = data.get("authResult")
        if auth_result == "success":
            return None
        message = self._auth_response_text(
            result,
            data=data,
            fallback=f"unexpected result: {auth_result}",
        )
        category = self._auth_message_category(
            message, default="authentication_failed",
        )
        return PortalError(category, "service_login", message)
