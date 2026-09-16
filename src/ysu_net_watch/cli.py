from __future__ import annotations

import argparse
import getpass
import re
import signal
import sys
import threading
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Callable

from .connectivity import ConnectivityChecker, ConnectivityState, DEFAULT_PROBES
from . import __version__
from .credentials import (
    CredentialError,
    build_credential_source,
    delete_windows_credential,
    write_windows_credential,
)
from .monitor import (
    EXIT_ACCOUNT_LIMIT,
    EXIT_CREDENTIAL_REJECTED,
    EXIT_IP_BLOCKED,
    EXIT_NETWORK_UNCONFIRMED,
    EXIT_PLANNED_PAUSE,
    EXIT_VERIFY_SKIPPED,
    EXIT_WIFI_FAILED,
    exit_code_text,
    JsonEventLog,
    ResilientEventLog,
    WatchSettings,
    Watcher,
    default_log_path,
    sanitize_text,
)
from .instance import AlreadyRunningError, SingleInstanceLock
from .portal import PortalClient, PortalError
from .schedule import (
    TimerRun,
    TimerSchedule,
    default_schedule_state_path,
    night_pause_reason,
    supervise_schedule,
)
from .profiles import ProfileStore, ProfileCredentialSource
from .settings import (
    ALL_DAYS,
    MAX_TIMERS,
    WEEKDAYS,
    AppSettings,
    AccountProfile,
    TimerSettings,
    load_settings,
    save_settings,
    follow_last_selection,
    select_profile,
    valid_time,
    service_key,
)
from .ui import select_menu
from .wifi import (
    WifiConnectionInfo,
    WifiConnectionState,
    WifiConnector,
    WifiError,
)


SERVICE_NAMES = {
    "campus": "校园网",
    "unicom": "中国联通",
    "telecom": "中国电信",
    "mobile": "中国移动",
}

APP_BANNER = r"""   __    _         __                 ___________
  / /__ (_)__  ___/ /__  ___ ___ ___ |_  <  / / /
 /  '_// / _ \/ _  / _ \/ -_|_-<(_-<_/_ </ /_  _/
/_/\_\/_/_//_/\_,_/_//_/\__/___/___/____/_/ /_/"""

DAY_NAMES = ("周一", "周二", "周三", "周四", "周五", "周六", "周日")


def scheduled_skip_reason(
    current_ssid: str | None,
    current_state: ConnectivityState | None = None,
) -> str:
    if current_ssid and current_ssid.casefold() != "iYanDa".casefold():
        return f"当前连接其他 Wi-Fi（{current_ssid}）"
    if current_ssid is None:
        return "无法确认当前 Wi-Fi 是否为 iYanDa"
    return ""


def scheduled_wifi_skip_reason(connection: WifiConnectionInfo) -> str:
    if connection.state == WifiConnectionState.CONNECTED:
        return scheduled_skip_reason(connection.ssid)
    if connection.state == WifiConnectionState.DISCONNECTED:
        return ""
    if connection.reason:
        return f"无法确认无线网卡或 Wi-Fi 连接状态：{connection.reason}"
    return "无法确认无线网卡或 Wi-Fi 连接状态"


def choose_mode(mode: str | None, service: str | None) -> tuple[str, str]:
    if mode is None:
        choice = select_menu("请选择监听模式：", ["校园网", "宽带"])
        mode = "broadband" if choice == 1 else "campus"

    if mode == "campus":
        return mode, "校园网"

    if service in {"unicom", "telecom", "mobile"}:
        return mode, SERVICE_NAMES[service]

    choice = select_menu(
        "请选择宽带运营商：",
        ["中国联通", "中国电信", "中国移动"],
    )
    selected = {0: "unicom", 1: "telecom", 2: "mobile"}.get(choice, "unicom")
    return mode, SERVICE_NAMES[selected]


def add_common_mode_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", help="使用指定账号档案 ID")
    parser.add_argument("--mode", choices=("campus", "broadband"))
    parser.add_argument("--service", choices=("unicom", "telecom", "mobile"))
    parser.add_argument(
        "--credential-source", choices=("auto", "windows", "env"), default="auto"
    )
    parser.add_argument(
        "--try-next-account",
        action="store_true",
        help="账号达到认证设备数限制时，按账号表顺序尝试下一个同服务账号",
    )


def add_wifi_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--wifi-ssid", default="iYanDa")
    parser.add_argument(
        "--no-auto-wifi",
        action="store_false",
        dest="auto_wifi",
        help="不自动配置或连接 Wi-Fi",
    )
    parser.add_argument(
        "--no-create-wifi-profile",
        action="store_false",
        dest="create_wifi_profile",
        help="指定 Wi-Fi 配置不存在时不创建开放网络配置",
    )
    parser.add_argument("--wifi-settle-delay", type=float, default=5.0)
    parser.set_defaults(auto_wifi=True, create_wifi_profile=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ysu-net-watch")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    watch = subparsers.add_parser("watch", help="持续监控并自动认证")
    add_common_mode_options(watch)
    add_wifi_options(watch)
    watch.add_argument("--check-interval", type=float, default=60.0)
    watch.add_argument("--confirmation-delay", type=float, default=120.0)
    watch.add_argument("--ping-host", default="baidu.com")
    watch.add_argument("--probe", action="append", default=[])
    watch.add_argument("--log-file", type=Path, default=default_log_path())
    watch.add_argument("--once", action="store_true", help="只执行一轮检测")

    login = subparsers.add_parser("login", help="立即执行一次认证")
    add_common_mode_options(login)
    add_wifi_options(login)

    logout = subparsers.add_parser("logout", help="让当前校园网认证账号下线")
    add_wifi_options(logout)

    console = subparsers.add_parser("console", help="打开常驻交互控制台")
    console.add_argument(
        "--try-next-account",
        action="store_true",
        help="定时或手动认证遇到设备数限制时，按账号表顺序尝试下一个同服务账号",
    )

    subparsers.add_parser("status", help="查询门户在线状态")

    credential = subparsers.add_parser("credential", help="管理 Windows 凭据")
    credential_sub = credential.add_subparsers(dest="credential_command", required=True)
    credential_set = credential_sub.add_parser("set")
    credential_set.add_argument("--mode", choices=("campus", "broadband"), required=True)
    credential_delete = credential_sub.add_parser("delete")
    credential_delete.add_argument("--mode", choices=("campus", "broadband"), required=True)
    account = subparsers.add_parser("account", help="管理多个独立账号档案")
    account_sub = account.add_subparsers(dest="account_command", required=True)
    account_sub.add_parser("list", help="列出账号别名与 ID，不读取密码")
    create = account_sub.add_parser("add", help="新增账号；密码隐藏输入")
    create.add_argument("--label", required=True)
    create.add_argument("--mode", choices=("campus", "broadband"), required=True)
    create.add_argument("--service", choices=("unicom", "telecom", "mobile"), default="unicom")
    verify = account_sub.add_parser(
        "verify", help="一次性验证指定账号状态，不启动持续监听"
    )
    verify.add_argument("--profile", required=True, help="账号档案 ID")
    verify.add_argument(
        "--force-switch",
        action="store_true",
        help="当前已有在线会话时，先下线它再验证指定账号",
    )
    add_wifi_options(verify)
    for name in ("update", "rename", "default", "delete"):
        sub = account_sub.add_parser(name)
        sub.add_argument("--profile", required=True)
        if name == "rename":
            sub.add_argument("--label", required=True)
        if name == "delete":
            sub.add_argument("--disable-timers", action="store_true",
                             help="明确停用所有引用此账号的定时器")
    return parser


def resolve_account(args) -> tuple[str, str, AccountProfile | None]:
    store = ProfileStore()
    if args.profile:
        if args.credential_source == "env":
            raise CredentialError("命名账号不使用环境变量回退，请更新该档案的凭据")
        profile = store.get(args.profile)
        if args.mode and args.mode != profile.mode:
            raise CredentialError("指定模式与账号档案不匹配")
        if args.service and service_key(profile.mode, args.service) != service_key(profile.mode, profile.service):
            raise CredentialError("指定运营商与账号档案不匹配")
        return profile.mode, SERVICE_NAMES[service_key(profile.mode, profile.service)], profile
    mode, service = choose_mode(args.mode, args.service)
    if args.credential_source == "env":
        return mode, service, None
    key = next(key for key, name in SERVICE_NAMES.items() if name == service)
    profile = store.default(mode, key)
    return mode, service, profile


def next_account_profiles(profile: AccountProfile) -> tuple[AccountProfile, ...]:
    """Return later same-service profiles in account-table order.

    Fallback deliberately does not wrap around to earlier entries: a single
    account is tried at most once per operation, and the order shown by
    ``account list`` is the order used for fallback.
    """
    config = load_settings()
    key = service_key(profile.mode, profile.service)
    try:
        position = next(index for index, item in enumerate(config.profiles) if item.id == profile.id)
    except StopIteration:
        return ()
    return tuple(
        item for item in config.profiles[position + 1:]
        if service_key(item.mode, item.service) == key
    )


def selected_credential_source(args, mode: str, profile: AccountProfile | None):
    if profile is not None and (args.profile or not profile.legacy):
        return ProfileCredentialSource(profile.id)
    return build_credential_source(mode, args.credential_source)


def current_pause_reason() -> str | None:
    return night_pause_reason(datetime.now(), load_settings())


def run_login(args: argparse.Namespace) -> int:
    try:
        mode, service, profile = resolve_account(args)
    except CredentialError as exc:
        print(f"账号配置错误：{exc}；{exit_code_text(10)}", file=sys.stderr)
        return 10
    code = _run_login_once(args, mode, service, profile, remember_selection=True)
    if code != EXIT_ACCOUNT_LIMIT or not getattr(args, "try_next_account", False):
        return code
    if profile is None:
        print("当前使用环境变量凭据，未启用账号表顺序回退。", file=sys.stderr)
        return code

    for candidate in next_account_profiles(profile):
        print(
            f"账号“{sanitize_text(profile.label)}”达到认证设备数限制，"
            f"按账号表顺序尝试“{sanitize_text(candidate.label)}”。"
        )
        candidate_args = argparse.Namespace(**vars(args))
        candidate_args.profile = candidate.id
        candidate_args.mode = None
        candidate_args.service = None
        candidate_args.credential_source = "auto"
        candidate_args.try_next_account = False
        candidate_code = _run_login_once(
            candidate_args,
            candidate.mode,
            SERVICE_NAMES[service_key(candidate.mode, candidate.service)],
            candidate,
            remember_selection=False,
        )
        if candidate_code != EXIT_ACCOUNT_LIMIT:
            if candidate_code == 0:
                ProfileStore().remember_selection(candidate.id)
            return candidate_code
        profile = candidate
    print("同服务账号均达到认证设备数限制，已停止认证。", file=sys.stderr)
    return EXIT_ACCOUNT_LIMIT


def _run_login_once(
    args: argparse.Namespace,
    mode: str,
    service: str,
    profile: AccountProfile | None,
    *,
    remember_selection: bool,
) -> int:
    if profile is not None and remember_selection:
        ProfileStore().remember_selection(profile.id)
    if reason := current_pause_reason():
        print(reason)
        return EXIT_PLANNED_PAUSE
    if args.auto_wifi:
        try:
            result = WifiConnector(
                args.wifi_ssid,
                create_open_profile=args.create_wifi_profile,
                settle_delay=max(0.0, args.wifi_settle_delay),
            ).connect()
            created = "（已更新开放网络配置）" if result.profile_created else ""
            print(f"已连接 Wi-Fi：{result.ssid}{created}")
        except WifiError as exc:
            print(
                f"Wi-Fi 连接失败：{sanitize_text(str(exc))}；{exit_code_text(EXIT_WIFI_FAILED)}",
                file=sys.stderr,
            )
            return EXIT_WIFI_FAILED
    source = selected_credential_source(args, mode, profile)
    credential = None
    try:
        if reason := current_pause_reason():
            print(reason)
            return EXIT_PLANNED_PAUSE
        credential = source.get()
        connector = WifiConnector(args.wifi_ssid, create_open_profile=False)
        portal = PortalClient(operation_allowed=lambda: (
            not current_pause_reason()
            and (connector.current_ssid() or "").casefold() == args.wifi_ssid.casefold()
        ))
        # `login()` intentionally returns when any service is already online.
        # Force an explicit CLI mode switch to take effect just like the
        # interactive console does.
        portal.logout()
        portal.login(credential.username, credential.password, service, force_switch=True)
    except CredentialError as exc:
        print(f"缺少凭据：{exc}；{exit_code_text(10)}", file=sys.stderr)
        return 10
    except PortalError as exc:
        if reason := current_pause_reason():
            print(reason)
            return EXIT_PLANNED_PAUSE
        secrets = (
            (credential.username, credential.password)
            if credential is not None
            else ()
        )
        network_unconfirmed = exc.category in {"timeout", "network_error", "operation_cancelled"}
        label = "网络暂未确认" if network_unconfirmed else "认证失败"
        code = (
            EXIT_NETWORK_UNCONFIRMED
            if network_unconfirmed
            else EXIT_IP_BLOCKED
            if exc.category == "ip_blocked"
            else EXIT_CREDENTIAL_REJECTED
            if exc.category in {"credential_rejected", "account_locked"}
            else EXIT_ACCOUNT_LIMIT
            if exc.category == "account_device_limit"
            else 30
            if exc.category == "protocol_changed"
            else 20
        )
        print(
            f"{label} [{exc.stage}/{exc.category}]："
            f"{sanitize_text(str(exc), secrets)}；{exit_code_text(code)}",
            file=sys.stderr,
        )
        if network_unconfirmed:
            return EXIT_NETWORK_UNCONFIRMED
        if exc.category == "ip_blocked":
            return EXIT_IP_BLOCKED
        if exc.category in {"credential_rejected", "account_locked"}:
            return EXIT_CREDENTIAL_REJECTED
        if exc.category == "account_device_limit":
            return EXIT_ACCOUNT_LIMIT
        return 20 if exc.category != "protocol_changed" else 30
    print("认证成功。")
    return 0


def run_status() -> int:
    try:
        status = PortalClient().status()
    except PortalError as exc:
        print(
            f"状态查询失败 [{exc.stage}/{exc.category}]：{sanitize_text(str(exc))}",
            file=sys.stderr,
        )
        return 1
    print("Online" if status.online else "Offline")
    return 0


def connect_wifi(args: argparse.Namespace, reporter=print) -> int:
    if not args.auto_wifi:
        return 0
    try:
        result = WifiConnector(
            args.wifi_ssid,
            create_open_profile=args.create_wifi_profile,
            settle_delay=max(0.0, args.wifi_settle_delay),
        ).connect()
        updated = "（已更新开放网络配置）" if result.profile_created else ""
        reporter(f"已连接 Wi-Fi：{result.ssid}{updated}")
        return 0
    except WifiError as exc:
        reporter(
            f"Wi-Fi 连接失败：{sanitize_text(str(exc))}；"
            f"{exit_code_text(EXIT_WIFI_FAILED)}"
        )
        return EXIT_WIFI_FAILED


def run_logout(args: argparse.Namespace, reporter=print) -> int:
    if reason := current_pause_reason():
        reporter(reason)
        return EXIT_PLANNED_PAUSE
    wifi_result = connect_wifi(args, reporter=reporter)
    if wifi_result:
        return wifi_result
    try:
        connector = WifiConnector(args.wifi_ssid, create_open_profile=False)
        changed = PortalClient(operation_allowed=lambda: (
            not current_pause_reason()
            and (connector.current_ssid() or "").casefold() == args.wifi_ssid.casefold()
        )).logout()
    except PortalError as exc:
        if reason := current_pause_reason():
            reporter(reason)
            return EXIT_PLANNED_PAUSE
        code = (
            EXIT_NETWORK_UNCONFIRMED
            if exc.category in {"timeout", "network_error", "operation_cancelled"}
            else 30
            if exc.category == "protocol_changed"
            else 20
        )
        reporter(
            f"下线失败 [{exc.stage}/{exc.category}]：{sanitize_text(str(exc))}；"
            f"{exit_code_text(code)}"
        )
        if exc.category in {"timeout", "network_error", "operation_cancelled"}:
            return EXIT_NETWORK_UNCONFIRMED
        return 30 if exc.category == "protocol_changed" else 20
    if changed:
        reporter("当前门户认证会话已下线。")
    else:
        reporter("门户未确认当前有在线认证会话，未发送下线请求；Wi-Fi 仍保持连接。")
    return 0


def run_watch(
    args: argparse.Namespace,
    *,
    external_stop_event: threading.Event | None = None,
    install_signal_handlers: bool = True,
    reporter=print,
    remember_selection: bool = True,
    profile_changed: Callable[[AccountProfile], None] | None = None,
) -> int:
    stop_event = external_stop_event or threading.Event()

    def stop(_signum, _frame):
        stop_event.set()

    if install_signal_handlers and threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, stop)
    if stop_event.is_set():
        return 0
    try:
        mode, service, profile = resolve_account(args)
    except CredentialError as exc:
        reporter(f"账号配置错误：{exc}；{exit_code_text(10)}")
        return 10
    if remember_selection and profile is not None:
        ProfileStore().remember_selection(profile.id)
    if stop_event.is_set():
        return 0
    settings = WatchSettings(
        mode=mode,
        service=service,
        check_interval=max(1.0, args.check_interval),
        confirmation_delay=max(0.0, args.confirmation_delay),
    )
    checker = ConnectivityChecker(
        ping_host=args.ping_host,
        probes=tuple(args.probe) if args.probe else DEFAULT_PROBES,
    )
    event_log = ResilientEventLog(JsonEventLog(args.log_file), reporter)
    authenticate_on_start = False
    wifi_connector = WifiConnector(
        args.wifi_ssid,
        create_open_profile=args.create_wifi_profile,
        settle_delay=max(0.0, args.wifi_settle_delay),
        sleeper=stop_event.wait,
        operation_allowed=lambda: not stop_event.is_set(),
    )
    paused = current_pause_reason()
    if args.auto_wifi and not paused:
        try:
            wifi = wifi_connector.connect()
            event_log.write(
                "wifi_connected",
                ssid=wifi.ssid,
                profile_created=wifi.profile_created,
            )
            created = "（已更新开放网络配置）" if wifi.profile_created else ""
            reporter(f"已连接 Wi-Fi：{wifi.ssid}{created}")
        except WifiError as exc:
            if stop_event.is_set():
                return 0
            event_log.write(
                "fatal",
                category="wifi_connection_failed",
                reason=str(exc),
            )
            reporter(
                f"Wi-Fi 连接失败：{sanitize_text(str(exc))}；"
                f"{exit_code_text(EXIT_WIFI_FAILED)}"
            )
            return EXIT_WIFI_FAILED

        if stop_event.is_set():
            return 0
        initial = checker.check()
        if stop_event.is_set():
            return 0
        event_log.write(
            "startup_connectivity_check",
            state=initial.state.value,
            reason=initial.reason,
        )
        authenticate_on_start = initial.state != ConnectivityState.ONLINE
        if authenticate_on_start:
            reporter("首次启动后外网不可用，立即尝试认证。")
    force_switch = bool(args.profile or getattr(args, "switch_on_start", False))
    authenticate_on_start = authenticate_on_start or force_switch or bool(paused)

    def expected_network() -> bool:
        return (wifi_connector.current_ssid() or "").casefold() == args.wifi_ssid.casefold()

    def operation_allowed() -> bool:
        if stop_event.is_set() or current_pause_reason():
            return False
        try:
            return expected_network()
        except WifiError:
            return False

    def on_resume() -> None:
        if not args.auto_wifi:
            return
        # A phone hotspot remains untouched when the planned outage ends.
        connection = wifi_connector.connection_info()
        if connection.state == WifiConnectionState.DISCONNECTED:
            wifi_connector.connect()
        elif connection.state == WifiConnectionState.UNKNOWN:
            raise WifiError(
                connection.reason or "Windows could not confirm the Wi-Fi state"
            )

    watcher = Watcher(
        settings=settings,
        checker=checker,
        credentials=selected_credential_source(args, mode, profile),
        portal_factory=lambda: PortalClient(
            reporter=reporter, sleeper=stop_event.wait, operation_allowed=operation_allowed,
        ),
        event_log=event_log,
        stop_event=stop_event,
        reporter=reporter,
        expected_network=expected_network,
        pause_reason=current_pause_reason,
        on_resume=on_resume,
        force_switch=force_switch,
        profile_id=profile.id if profile else None,
    )
    reporter(f"开始监听：{service}。")
    result = watcher.run(
        once=args.once, authenticate_on_start=authenticate_on_start
    )
    if (
        result != EXIT_ACCOUNT_LIMIT
        or not getattr(args, "try_next_account", False)
        or profile is None
    ):
        if (
            result == EXIT_ACCOUNT_LIMIT
            and getattr(args, "try_next_account", False)
            and profile is None
        ):
            reporter("当前使用环境变量凭据，未启用账号表顺序回退。")
        return result
    for candidate in next_account_profiles(profile):
        reporter(
            f"账号“{sanitize_text(profile.label)}”达到认证设备数限制，"
            f"按账号表顺序尝试“{sanitize_text(candidate.label)}”。"
        )
        if profile_changed is not None:
            profile_changed(candidate)
        candidate_args = argparse.Namespace(**vars(args))
        candidate_args.profile = candidate.id
        candidate_args.mode = None
        candidate_args.service = None
        candidate_args.credential_source = "auto"
        candidate_args.try_next_account = False
        result = run_watch(
            candidate_args,
            external_stop_event=stop_event,
            install_signal_handlers=False,
            reporter=reporter,
            remember_selection=False,
            profile_changed=profile_changed,
        )
        if result != EXIT_ACCOUNT_LIMIT:
            return result
        profile = candidate
    reporter("同服务账号均达到认证设备数限制，已停止认证。")
    return EXIT_ACCOUNT_LIMIT


_DEFAULT_SCHEDULE_STATE = object()


def run_console(
    *,
    enable_scheduler: bool = True,
    schedule_state_path: Path | None | object = _DEFAULT_SCHEDULE_STATE,
    try_next_account: bool = False,
) -> int:
    worker: threading.Thread | None = None
    worker_stop: threading.Event | None = None
    worker_result: list[int] = []
    worker_runs: dict[int, TimerRun] = {}
    operation_lock = threading.RLock()
    worker_control_lock = threading.RLock()
    scheduler_stop = threading.Event()
    resolved_schedule_state = (
        default_schedule_state_path()
        if enable_scheduler and schedule_state_path is _DEFAULT_SCHEDULE_STATE
        else schedule_state_path
    )
    schedule = TimerSchedule(
        state_path=(
            resolved_schedule_state
            if isinstance(resolved_schedule_state, Path)
            else None
        ),
    )
    scheduler_health = "运行中" if enable_scheduler else "已关闭"
    latest_status = "等待操作"
    recent_result = "暂无"
    pending_device_notice = ""
    active_mode: str | None = None
    active_service: str | None = None
    active_profile_id: str | None = None
    active_revision: int | None = None
    generation = 0
    account_store = ProfileStore()

    def update_status(message: str) -> None:
        nonlocal latest_status, recent_result, pending_device_notice
        with operation_lock:
            safe_message = sanitize_text(message)
            latest_status = safe_message
            if "已请求下线" in safe_message and "旧设备" in safe_message:
                pending_device_notice = safe_message
                recent_result = safe_message
            elif "认证成功" in safe_message:
                if pending_device_notice:
                    count_match = re.search(r"(\d+)\s*个旧设备", pending_device_notice)
                    count = count_match.group(1) if count_match else ""
                    recent_result = (
                        f"已下线 {count + ' 个' if count else ''}旧设备，并认证成功。"
                    )
                    pending_device_notice = ""
                else:
                    recent_result = safe_message
            elif any(word in safe_message for word in ("失败", "已跳过", "已结束", "已停止")):
                recent_result = safe_message

    def stop_worker() -> bool:
        nonlocal worker, worker_stop, active_mode, active_service
        nonlocal active_profile_id, active_revision, generation
        with worker_control_lock:
            with operation_lock:
                current_worker = worker
                current_stop = worker_stop
                generation += 1

            if current_worker is not None and current_worker.is_alive():
                update_status("正在停止当前监听……")
                if current_stop is None:
                    update_status("监听线程状态异常；未启动新的监听。")
                    return False
                current_stop.set()
                # Never wait for the worker while holding operation_lock:
                # its final reporter update also needs that lock.
                current_worker.join(timeout=20)
                if current_worker.is_alive():
                    update_status("监听线程未能在 20 秒内停止；未启动新的监听。")
                    return False

            with operation_lock:
                if worker is current_worker:
                    worker = None
                    worker_stop = None
                    worker_runs.clear()
                    active_mode = None
                    active_service = None
                    active_profile_id = None
                    active_revision = None
            return True

    def start_worker(
        mode: str,
        service: str | None = None,
        *,
        scheduled_run: TimerRun | None = None,
        profile_id: str | None = None,
    ) -> bool:
        nonlocal worker, worker_stop, active_mode, active_service
        nonlocal active_profile_id, active_revision
        with worker_control_lock:
            if scheduled_run is not None:
                config = load_settings()
                schedule.sync(config.timers, config.profiles)
                if not schedule.is_current(scheduled_run):
                    update_status("定时器配置已变更，取消旧任务。")
                    return False
            try:
                profile = account_store.get(profile_id) if profile_id else account_store.default(mode, service or "campus")
            except CredentialError as exc:
                update_status(f"无法切换账号：{exc}")
                return False
            if not stop_worker():
                return False
            if scheduled_run is None:
                try:
                    config = account_store.remember_selection(profile.id)
                    schedule.sync(config.timers, config.profiles)
                except (CredentialError, OSError, ValueError) as exc:
                    update_status(f"最近选择保存失败（{type(exc).__name__}）；未启动新监听。")
                    return False
                update_status(
                    f"默认定时器已跟随：{profile.label} · "
                    f"{SERVICE_NAMES[service_key(profile.mode, profile.service)]}"
                )
            # The worker reads the target credential before a forced logout.
            # At night it stays alive without logging out or submitting credentials.
            command = ["watch", "--profile", profile.id]
            if try_next_account:
                command.append("--try-next-account")
            watch_args = build_parser().parse_args(command)
            new_stop = threading.Event()
            token = generation

            def target() -> None:
                def profile_changed(candidate: AccountProfile) -> None:
                    nonlocal active_mode, active_service
                    nonlocal active_profile_id, active_revision
                    with operation_lock:
                        if token == generation:
                            active_mode = candidate.mode
                            active_service = (
                                candidate.service
                                if candidate.mode == "broadband" else None
                            )
                            active_profile_id = candidate.id
                            active_revision = candidate.credential_revision

                def report(message: str) -> None:
                    with operation_lock:
                        if token == generation:
                            update_status(message)
                try:
                    result = run_watch(
                        watch_args,
                        external_stop_event=new_stop,
                        install_signal_handlers=False,
                        reporter=report,
                        remember_selection=False,
                        profile_changed=profile_changed,
                    )
                except Exception as exc:
                    report(f"监听异常已停止：{type(exc).__name__}")
                    result = 30
                with operation_lock:
                    worker_result.append(result)

            new_worker = threading.Thread(
                target=target, name="ysu-network-watcher", daemon=True
            )
            with operation_lock:
                worker_stop = new_stop
                worker_result.clear()
                worker_runs.clear()
                if scheduled_run is not None:
                    worker_runs[scheduled_run.index] = scheduled_run
                worker = new_worker
                active_mode = profile.mode
                active_service = profile.service if profile.mode == "broadband" else None
                active_profile_id = profile.id
                active_revision = profile.credential_revision
                new_worker.start()
            return True

    def reap_worker() -> None:
        nonlocal worker, worker_stop, active_mode, active_service
        nonlocal active_profile_id, active_revision
        with worker_control_lock:
            with operation_lock:
                if worker is None or worker.is_alive() or not worker_result:
                    return
                code = worker_result[-1]
                finished_runs = tuple(worker_runs.values())
                worker = None
                worker_stop = None
                worker_runs.clear()
                active_mode = None
                active_service = None
                active_profile_id = None
                active_revision = None
            update_status(f"监听程序已结束：{exit_code_text(code)}")
            for finished_run in finished_runs:
                schedule.mark_finished(finished_run, code)

    def scheduler_log(event: str, **fields) -> None:
        try:
            JsonEventLog(default_log_path()).write(event, **fields)
        except OSError:
            # The UI remains the fallback when the log directory is unavailable.
            pass

    def finish_conflicts(conflicts, day) -> None:
        for conflict in conflicts:
            conflict_run = schedule.mark_started(conflict, day)
            if conflict_run is None:
                continue
            schedule.mark_finished(conflict_run, 0)
            scheduler_log(
                "timer_conflict_skipped",
                timer=conflict.index + 1,
                phase=conflict.phase,
                reason="a higher-priority due timer was accepted",
            )

    def scheduled_tick() -> None:
        with worker_control_lock:
            settings = load_settings()
            schedule.sync(settings.timers, settings.profiles)
            reap_worker()
            now = datetime.now()
            due = schedule.due_timers(now, settings.timers, settings.profiles)
            if not due:
                return
            selected = due[0]
            run = schedule.mark_started(selected, now.date())
            if run is None:
                return
        accepted = False
        try:
            if reason := night_pause_reason(now, settings):
                update_status(f"定时器 {selected.index + 1} 已跳过：{reason}")
                accepted = True
                schedule.mark_finished(run, 0)
                finish_conflicts(due[1:], now.date())
                return
            profile = account_store.get(selected.timer.profile_id or "")
            service = profile.service if profile.mode == "broadband" else None
            with worker_control_lock:
                current = load_settings()
                schedule.sync(current.timers, current.profiles)
                if not schedule.is_current(run):
                    return
                with operation_lock:
                    already_active = (
                        worker is not None and worker.is_alive()
                        and worker_stop is not None and not worker_stop.is_set()
                        and active_mode == profile.mode and active_profile_id == profile.id
                        and active_revision == profile.credential_revision
                    )
                    if already_active:
                        worker_runs[run.index] = run
            if already_active:
                update_status(f"定时器 {selected.index + 1}：目标模式已在监听。")
                accepted = True
                finish_conflicts(due[1:], now.date())
                return
            connector = WifiConnector("iYanDa", create_open_profile=False, settle_delay=0)
            connection = connector.connection_info()
            skip_reason = scheduled_wifi_skip_reason(connection)
            timer_name = f"定时器 {selected.index + 1}"
            phase_name = "补偿" if selected.phase == "retry" else "主任务"
            if skip_reason:
                unknown_wifi = connection.state == WifiConnectionState.UNKNOWN
                disposition = "失败" if unknown_wifi else "已跳过"
                update_status(f"{timer_name} {phase_name}{disposition}：{skip_reason}")
                scheduler_log("schedule_skipped", timer=selected.index + 1,
                              phase=selected.phase, reason=skip_reason)
                accepted = True
                schedule.mark_finished(
                    run, EXIT_WIFI_FAILED if unknown_wifi else 0,
                )
                return
            update_status(f"{timer_name} {phase_name}启动：{SERVICE_NAMES[service or 'campus']}")
            started = start_worker(
                profile.mode, service, scheduled_run=run, profile_id=profile.id,
            )
            if not started:
                schedule.mark_finished(run, EXIT_WIFI_FAILED)
                return
            accepted = True
            finish_conflicts(due[1:], now.date())
        except Exception as exc:
            # Record against the original run token, never the current slot binding.
            code = 10 if isinstance(exc, CredentialError) else (
                EXIT_WIFI_FAILED if isinstance(exc, WifiError) else 30
            )
            if not accepted:
                schedule.mark_finished(run, code)
            raise

    def scheduler_error(exc: Exception) -> None:
        nonlocal scheduler_health
        with operation_lock:
            scheduler_health = f"异常后等待重试（{type(exc).__name__}）"
        update_status(f"定时调度异常（{type(exc).__name__}），15 秒后继续检查；本次主任务失败可触发所设补偿。")
        scheduler_log("scheduler_error", category=type(exc).__name__, reason=str(exc))

    def scheduler_recovered() -> None:
        nonlocal scheduler_health
        with operation_lock:
            scheduler_health = "运行中"
        update_status("定时调度已恢复，继续检查后续任务。")

    def scheduled_loop() -> None:
        supervise_schedule(scheduler_stop, scheduled_tick, scheduler_error, scheduler_recovered)

    def save_console_settings(config: AppSettings):
        with worker_control_lock:
            config = follow_last_selection(config)
            path = save_settings(config)
            schedule.sync(config.timers, config.profiles)
            return path

    def configure_defaults() -> None:
        current = load_settings()
        print(
            f"当前默认：{SERVICE_NAMES[current.service if current.mode == 'broadband' else 'campus']}"
        )
        mode_choice = select_menu("请选择默认模式：", ["校园网", "宽带"])
        if mode_choice == 0:
            updated = replace(
                current,
                mode="campus",
            )
        elif mode_choice == 1:
            operator = select_menu(
                "请选择默认运营商：",
                ["中国联通", "中国电信", "中国移动"],
            )
            service = {
                0: "unicom",
                1: "telecom",
                2: "mobile",
            }.get(operator)
            if service is None:
                print("未保存：运营商选择无效。")
                return
            updated = replace(
                current,
                mode="broadband",
                service=service,
            )
        else:
            print("未保存：模式选择无效。")
            return
        eligible = [
            p for p in current.profiles
            if service_key(p.mode, p.service) == service_key(updated.mode, updated.service)
        ]
        if not eligible:
            print("该服务没有可用档案，请先在账号管理中添加。")
            return
        chosen = eligible[0] if len(eligible) == 1 else choose_profile(updated.mode, updated.service)
        if chosen is None:
            return
        defaults = dict(updated.default_profile_ids)
        defaults[service_key(chosen.mode, chosen.service)] = chosen.id
        updated = select_profile(replace(updated, default_profile_ids=defaults), chosen.id)
        path = save_console_settings(updated)
        print(f"常用设置已保存：{SERVICE_NAMES[updated.service if updated.mode == 'broadband' else 'campus']}")
        print("默认定时器 1 已跟随；自定义定时器 2～10 保持原绑定。")
        print(f"设置位置：{path}")

    def describe_days(days: tuple[int, ...]) -> str:
        if days == WEEKDAYS:
            return "工作日"
        if days == ALL_DAYS:
            return "每天"
        if days == (5, 6):
            return "周末"
        return "/".join(DAY_NAMES[day] for day in days)

    def describe_timer(
        index: int,
        timer: TimerSettings,
        *,
        include_index: bool = True,
    ) -> str:
        state = "开" if timer.enabled else "关"
        service = SERVICE_NAMES[
            timer.service if timer.mode == "broadband" else "campus"
        ]
        retry = f"，失败 {timer.retry_time} 补偿" if timer.retry_time else ""
        prefix = f"定时器 {index + 1}｜" if include_index else ""
        binding = "（跟随最近选择）" if index == 0 else "（固定账号）"
        return (
            f"{prefix}[{state}] {describe_days(timer.weekdays)} "
            f"{timer.time} {service} · {profile_label(timer.profile_id)}{binding}{retry}"
        )

    def profile_label(profile_id: str | None) -> str:
        return next((p.label for p in load_settings().profiles if p.id == profile_id), "未绑定/账号不存在")

    def profile_display(profile: AccountProfile, config: AppSettings | None = None) -> str:
        """Short, actionable account label used by account/profile pickers."""
        config = config or load_settings()
        key = service_key(profile.mode, profile.service)
        markers: list[str] = []
        if config.default_profile_ids.get(key) == profile.id:
            markers.append("常用")
        if active_profile_id == profile.id and worker is not None:
            markers.append("当前监听")
        marker = f" [{' / '.join(markers)}]" if markers else ""
        legacy = "（兼容旧凭据）" if profile.legacy else ""
        return f"{profile.label} · {SERVICE_NAMES[key]}{legacy}{marker}"

    def choose_profile(mode: str | None = None, service: str | None = None) -> AccountProfile | None:
        config = load_settings()
        profiles = [
            p for p in config.profiles
            if mode is None or service_key(p.mode, p.service) == service_key(mode, service or "campus")
        ]
        choices = [profile_display(p, config) for p in profiles]
        choice = select_menu("选择账号档案：", [*choices, "取消"])
        return profiles[choice] if choice is not None and choice < len(profiles) else None

    def account_secret() -> tuple[str, str] | None:
        username = input("学号/账号（直接 Enter 取消）: ").strip()
        if not username:
            return None
        password = getpass.getpass("密码（不显示字符；直接 Enter 取消）: ")
        return (username, password) if password else None

    def add_account() -> None:
        label = input("账号别名（请勿用完整学号/手机号；Enter 取消）: ").strip()
        if not label:
            return
        selection = select_menu("账号服务：", ["校园网", "中国联通", "中国电信", "中国移动", "取消"])
        if selection is None or selection >= 4:
            return
        mode = "campus" if selection == 0 else "broadband"
        service = {0: "unicom", 1: "unicom", 2: "telecom", 3: "mobile"}[selection]
        secret = account_secret()
        if secret is None:
            return
        with worker_control_lock:
            profile = account_store.create(label, mode, service, *secret)
        print(f"账号已保存：{profile.label}；可在账号管理中选择它进行修改、切换或设为常用。")

    def edit_account(profile_id: str) -> None:
        while True:
            try:
                profile = account_store.get(profile_id)
            except CredentialError:
                return
            choice = select_menu(
                "修改账号：" + profile_display(profile)
                + ("（更新凭据后将独立保存）" if profile.legacy else ""),
                ["切换到此账号并监听", "设为该服务常用账号", "修改别名",
                 "更新账号密码", "试验证账号状态（单次，不启动监听）",
                 "删除档案", "返回"],
            )
            if choice == 0:
                start_worker(profile.mode, profile.service, profile_id=profile.id)
                return
            if choice == 1:
                with worker_control_lock:
                    account_store.set_default(profile.id)
                    updated_config = load_settings()
                    schedule.sync(updated_config.timers, updated_config.profiles)
                print("常用账号已更新；默认定时器 1 已跟随，自定义定时器 2～10 保持原绑定。")
            elif choice == 2:
                label = input("新别名（Enter 取消）: ").strip()
                if label:
                    account_store.rename(profile.id, label)
                    print("账号别名已更新。")
            elif choice == 3:
                secret = account_secret()
                if secret:
                    with worker_control_lock:
                        account_store.update_credentials(profile.id, *secret)
                        updated_config = load_settings()
                        schedule.sync(updated_config.timers, updated_config.profiles)
                    print("凭据已更新。下一次认证读取新值；立即换号请选择切换并监听。")
            elif choice == 4:
                if worker is not None and worker.is_alive():
                    print("当前有监听正在运行，请先停止监听后再试验证账号。")
                    continue
                verify_args = build_parser().parse_args(
                    ["account", "verify", "--profile", profile.id]
                )
                result = run_account_verify(verify_args)
                if result == EXIT_VERIFY_SKIPPED:
                    follow_up = select_menu(
                        "当前已有在线会话：",
                        ["下线当前会话并继续试验证", "返回"],
                    )
                    if follow_up == 0:
                        verify_args.force_switch = True
                        run_account_verify(verify_args)
            elif choice == 5:
                config = load_settings()
                references = [str(i + 1) for i, t in enumerate(config.timers) if t.profile_id == profile.id]
                message = ("被定时器 " + "、".join(references) + " 引用。") if references else ""
                confirm = select_menu(message + "删除此档案？",
                                      ["取消", "停用引用定时器并删除" if references else "删除"])
                if confirm != 1:
                    continue
                with worker_control_lock:
                    if active_profile_id == profile.id and worker is not None:
                        print("此账号正在监听，请先停止监听或切换其他账号。")
                        continue
                    account_store.delete(profile.id, disable_timers=bool(references))
                    updated_config = load_settings()
                    schedule.sync(updated_config.timers, updated_config.profiles)
                print("档案已删除；兼容档案使用的旧共享凭据会保留。")
                return
            elif choice == 6 or choice is None:
                return

    def manage_accounts() -> None:
        while True:
            config = load_settings()
            profiles = config.profiles
            choice = select_menu(
                "账号管理：选择账号可直接修改，或添加新账号（最多 20 个档案）：",
                [f"修改：{profile_display(p, config)}" for p in profiles]
                + ["添加账号", "返回"],
            )
            if choice is None or choice == len(profiles) + 1:
                return
            try:
                if choice == len(profiles):
                    add_account()
                else:
                    edit_account(profiles[choice].id)
            except (CredentialError, OSError, ValueError) as exc:
                print(f"账号操作未完成：{type(exc).__name__}" if not isinstance(exc, CredentialError)
                      else f"账号操作未完成：{exc}")

    def configure_night_pause() -> None:
        config = load_settings()
        print(
            f"夜间保护在周一至周四 23:30 起生效，至次日 "
            f"{config.timers[0].time} 恢复；星期五恢复后至周一 23:30 不暂停。"
        )
        value = ask_time("夜间保护恢复时间（同时更新定时器 1 时间）", config.timers[0].time)
        if value is not None:
            timers = list(config.timers)
            timers[0] = replace(timers[0], time=value)
            save_console_settings(replace(config, timers=tuple(timers)))
            print(f"夜间保护恢复时间已保存：{value}。")

    def ask_time(prompt: str, current: str) -> str | None:
        value = input(
            f"{prompt}（HH:MM，当前 {current}；直接按 Enter 返回）: "
        ).strip()
        if not value:
            return None
        if valid_time(value):
            return value
        print("时间格式无效，应为 00:00 到 23:59。")
        return None

    def choose_days(current: tuple[int, ...]) -> tuple[int, ...] | None:
        choice = select_menu(
            f"当前执行日期：{describe_days(current)}",
            ["工作日", "每天", "周末", "自定义星期", "取消"],
        )
        if choice == 0:
            return WEEKDAYS
        if choice == 1:
            return ALL_DAYS
        if choice == 2:
            return (5, 6)
        if choice != 3:
            return None
        raw = input(
            "输入星期数字，用逗号分隔（1=周一，7=周日；直接按 Enter 返回）: "
        ).strip()
        if not raw:
            return None
        try:
            days = tuple(
                sorted(
                    {
                        int(part.strip()) - 1
                        for part in raw.split(",")
                        if part.strip()
                    }
                )
            )
        except ValueError:
            days = ()
        if not days or any(day < 0 or day > 6 for day in days):
            print("星期设置无效。")
            return None
        return days

    def choose_timer_mode(timer: TimerSettings) -> TimerSettings | None:
        mode_choice = select_menu("选择认证模式：", ["校园网", "宽带", "取消"])
        if mode_choice == 0:
            return replace(timer, mode="campus")
        if mode_choice != 1:
            return None
        operator = select_menu(
            "选择宽带运营商：",
            ["中国联通", "中国电信", "中国移动", "取消"],
        )
        service = {0: "unicom", 1: "telecom", 2: "mobile"}.get(operator)
        return replace(timer, mode="broadband", service=service) if service else None

    def edit_timer(index: int) -> None:
        while True:
            current = load_settings()
            timer = current.timers[index]
            choice = select_menu(
                f"编辑 {describe_timer(index, timer)}",
                [
                    "开启/关闭",
                    "修改执行时间",
                    "修改执行日期",
                    "修改最近选择（定时器 1 跟随）" if index == 0 else "绑定账号（同时选择服务）",
                    "设置/关闭失败补偿",
                    "重置时间并关闭（保留跟随）" if index == 0 else "恢复为空白关闭状态",
                    "返回",
                ],
            )
            updated = timer
            if choice == 0:
                if not timer.enabled and not any(p.id == timer.profile_id for p in current.profiles):
                    profile = choose_profile()
                    if profile is None:
                        continue
                    timer = replace(timer, profile_id=profile.id, mode=profile.mode, service=profile.service)
                updated = replace(timer, enabled=not timer.enabled)
            elif choice == 1:
                value = ask_time("执行时间", timer.time)
                if value is None:
                    continue
                if timer.retry_time is not None and value >= timer.retry_time:
                    print("执行时间必须早于补偿时间；如需跨日，请使用另一个定时器。")
                    continue
                updated = replace(timer, time=value)
            elif choice == 2:
                days = choose_days(timer.weekdays)
                if days is None:
                    continue
                updated = replace(timer, weekdays=days)
            elif choice == 3:
                selected = choose_profile()
                if selected is None:
                    continue
                updated = replace(timer, profile_id=selected.id, mode=selected.mode, service=selected.service)
            elif choice == 4:
                retry_choice = select_menu(
                    "失败补偿：",
                    ["关闭补偿", "设置补偿时间", "取消"],
                )
                if retry_choice == 0:
                    updated = replace(timer, retry_time=None)
                elif retry_choice == 1:
                    value = ask_time(
                        "补偿时间",
                        timer.retry_time or "08:00",
                    )
                    if value is None:
                        continue
                    if value <= timer.time:
                        print("补偿时间必须晚于执行时间；如需跨日，请使用另一个定时器。")
                        continue
                    updated = replace(timer, retry_time=value)
                else:
                    continue
            elif choice == 5:
                updated = TimerSettings()
            elif choice == 6 or choice is None:
                return
            else:
                continue
            timers = list(current.timers)
            timers[index] = updated
            updated_config = replace(current, timers=tuple(timers))
            if index == 0 and choice in {0, 3} and updated.profile_id != current.last_selected_profile_id:
                updated_config = select_profile(updated_config, updated.profile_id)
            save_console_settings(updated_config)

    def manage_timers() -> None:
        while True:
            current = load_settings()
            options = [
                describe_timer(index, timer, include_index=False)
                for index, timer in enumerate(current.timers)
            ]
            options.append("返回")
            choice = select_menu(
                "管理定时器（最多 10 个；相同时间以编号小者优先）：",
                options,
            )
            if choice is None or choice >= MAX_TIMERS:
                return
            edit_timer(choice)

    def configure_menu() -> None:
        while True:
            config = load_settings()
            choice = select_menu(
                "常用与定时设置：",
                [
                    "修改常用认证模式",
                    "管理 10 个定时器",
                    f"夜间保护：{'开' if config.night_pause_enabled else '关'}（按 Enter 切换）",
                    "修改夜间保护恢复时间",
                    "返回",
                ],
            )
            if choice == 0:
                configure_defaults()
            elif choice == 1:
                manage_timers()
            elif choice == 2:
                enabled = not config.night_pause_enabled
                save_console_settings(replace(config, night_pause_enabled=enabled))
                print(f"夜间保护已{'开启' if enabled else '关闭'}。")
            elif choice == 3:
                configure_night_pause()
            else:
                return

    scheduler_thread = None
    if enable_scheduler:
        scheduler_thread = threading.Thread(
            target=scheduled_loop,
            name="ysu-timer-scheduler",
            daemon=True,
        )
        scheduler_thread.start()

    try:
        while True:
            reap_worker()
            defaults = load_settings()
            default_name = SERVICE_NAMES[
                defaults.service if defaults.mode == "broadband" else "campus"
            ]
            enabled_timer_count = sum(
                1 for timer in defaults.timers if timer.enabled
            )

            def short_line(value: str, limit: int = 72) -> str:
                if len(value) <= limit:
                    return value
                head = max(24, (limit - 1) // 2)
                tail = limit - head - 1
                return value[:head] + "…" + value[-tail:]

            def menu_title() -> str:
                with operation_lock:
                    status_line = short_line(latest_status)
                    result_line = short_line(recent_result)
                    timer_health = scheduler_health
                    if enable_scheduler and scheduler_thread is not None and not scheduler_thread.is_alive():
                        timer_health = "已停止（异常），请重新启动程序"
                    if active_mode == "campus":
                        active_line = "校园网"
                    elif active_mode == "broadband" and active_service:
                        active_line = SERVICE_NAMES[active_service]
                    else:
                        active_line = "无"
                return (
                    f"{APP_BANNER}\n\n常用认证：{default_name}"
                    f" · {profile_label(defaults.default_profile_ids.get(service_key(defaults.mode, defaults.service)))}"
                    f"\n定时器：已启用 {enabled_timer_count}/{MAX_TIMERS}"
                    f"\n默认定时器跟随：{profile_label(defaults.last_selected_profile_id)}"
                    f"\n定时调度：{timer_health}"
                    f"\n监听目标：{active_line}"
                    + (f" · {profile_label(active_profile_id)}" if active_profile_id else "")
                    + f"\n夜间停网保护：{'开' if defaults.night_pause_enabled else '关'}"
                    f"\n最近结果：{result_line}"
                    f"\n运行状态：{status_line}\n请选择操作："
                )

            campus_mark = "  ● 当前监听" if active_mode == "campus" else ""
            broadband_mark = (
                "  ● 当前监听"
                if active_mode == "broadband"
                and active_service == defaults.service
                else ""
            )
            choice_index = select_menu(
                menu_title,
                [
                    f"切换到 iYanDa 并监听校园网{campus_mark}",
                    (
                        f"切换到 iYanDa 并监听默认宽带"
                        f"（{SERVICE_NAMES[defaults.service]}）{broadband_mark}"
                    ),
                    "停止当前监听",
                    "当前认证账号下线",
                    "账号管理",
                    "修改常用/定时设置",
                    "退出程序",
                ],
            )
            choice = str(choice_index + 1) if choice_index is not None else ""
            if choice == "1":
                start_worker("campus")
            elif choice == "2":
                start_worker("broadband", defaults.service)
            elif choice == "3":
                stop_worker()
                update_status("当前监听已停止。")
            elif choice == "4":
                with worker_control_lock:
                    if stop_worker():
                        run_logout(build_parser().parse_args(["logout"]), reporter=update_status)
            elif choice == "5":
                manage_accounts()
            elif choice == "6":
                configure_menu()
            elif choice == "7":
                scheduler_stop.set()
                stop_worker()
                return 0
            else:
                print("无效选择。")
    except (KeyboardInterrupt, EOFError):
        print("\n正在退出……")
        scheduler_stop.set()
        stop_worker()
        return 0


def run_credential(args: argparse.Namespace) -> int:
    try:
        if args.credential_command == "delete":
            delete_windows_credential(args.mode)
            print("凭据已删除。")
            return 0
        username = input("学号/账号: ").strip()
        password = getpass.getpass("密码: ")
        if not username or not password:
            raise CredentialError("用户名和密码不能为空")
        write_windows_credential(args.mode, username, password)
        print("凭据已写入 Windows 凭据管理器。")
        return 0
    except CredentialError as exc:
        print(f"凭据操作失败：{exc}", file=sys.stderr)
        return 1


def run_account_verify(args: argparse.Namespace, reporter=print) -> int:
    """Perform one guarded account-status verification.

    This deliberately is not a watcher and never uses the device replacement
    flow.  A currently online portal session is left untouched unless the user
    explicitly passes ``--force-switch``.
    """
    try:
        profile = ProfileStore().get(args.profile)
    except CredentialError as exc:
        reporter(f"账号试验失败：{exc}；{exit_code_text(10)}")
        return 10

    mode = profile.mode
    service = SERVICE_NAMES[service_key(profile.mode, profile.service)]
    if reason := current_pause_reason():
        reporter(f"账号试验已跳过：{reason}；{exit_code_text(EXIT_PLANNED_PAUSE)}")
        return EXIT_PLANNED_PAUSE

    wifi_result = connect_wifi(args, reporter=reporter)
    if wifi_result:
        return wifi_result

    connector = WifiConnector(args.wifi_ssid, create_open_profile=False)
    portal = PortalClient(
        reporter=reporter,
        operation_allowed=lambda: (
            not current_pause_reason()
            and (connector.current_ssid() or "").casefold() == args.wifi_ssid.casefold()
        ),
    )
    try:
        # Check this before reading the secret.  Without --force-switch a
        # different account could already be online, and submitting another
        # account would be both misleading and needlessly disruptive.
        current = portal.status()
        if current.online and not args.force_switch:
            reporter(
                f"当前门户已有在线会话，未提交账号“{sanitize_text(profile.label)}”的凭据。"
                f"如需切换后试验，请加 --force-switch；{exit_code_text(EXIT_VERIFY_SKIPPED)}"
            )
            return EXIT_VERIFY_SKIPPED

        credential = selected_credential_source(args, mode, profile).get()
        submitted = portal.login(
            credential.username,
            credential.password,
            service,
            force_switch=args.force_switch,
            allow_device_release=False,
            allow_workflow_retry=False,
        )
        if not submitted:
            # The status can change between the read-only precheck and login.
            reporter(
                f"当前门户已有在线会话，未提交账号“{sanitize_text(profile.label)}”的凭据。"
                f"如需切换后试验，请加 --force-switch；{exit_code_text(EXIT_VERIFY_SKIPPED)}"
            )
            return EXIT_VERIFY_SKIPPED
    except CredentialError as exc:
        reporter(f"账号试验缺少凭据：{exc}；{exit_code_text(10)}")
        return 10
    except PortalError as exc:
        if reason := current_pause_reason():
            reporter(f"账号试验已停止：{reason}；{exit_code_text(EXIT_PLANNED_PAUSE)}")
            return EXIT_PLANNED_PAUSE
        secrets = (credential.username, credential.password) if "credential" in locals() else ()
        if exc.category in {"timeout", "network_error", "operation_cancelled"}:
            code = EXIT_NETWORK_UNCONFIRMED
        elif exc.category == "ip_blocked":
            code = EXIT_IP_BLOCKED
        elif exc.category in {"credential_rejected", "account_locked"}:
            code = EXIT_CREDENTIAL_REJECTED
        elif exc.category == "account_device_limit":
            code = EXIT_ACCOUNT_LIMIT
        elif exc.category == "protocol_changed":
            code = 30
        else:
            code = 20
        reporter(
            f"账号试验失败 [{exc.stage}/{exc.category}]："
            f"{sanitize_text(str(exc), secrets)}；{exit_code_text(code)}"
        )
        if exc.category == "account_in_use":
            reporter("本次试验未踢下线其他设备；请确认旧设备会话或明确使用 --force-switch。")
        return code

    reporter(
        f"账号试验成功：账号“{sanitize_text(profile.label)}”的门户认证已确认在线；"
        "未启动持续监听，也未启用旧设备下线。"
    )
    return 0


def run_account(args: argparse.Namespace) -> int:
    store = ProfileStore()
    try:
        if args.account_command == "list":
            for profile in load_settings().profiles:
                print(f"{profile.id}  {profile.label}  "
                      f"{SERVICE_NAMES[service_key(profile.mode, profile.service)]}"
                      + ("  [兼容旧凭据]" if profile.legacy else ""))
            return 0
        if args.account_command == "verify":
            return run_account_verify(args)
        if args.account_command in {"add", "update"}:
            username = input("学号/账号（Enter 取消）: ").strip()
            if not username:
                return 0
            password = getpass.getpass("密码（隐藏输入；Enter 取消）: ")
            if not password:
                return 0
            if args.account_command == "add":
                profile = store.create(args.label, args.mode, args.service, username, password)
            else:
                profile = store.update_credentials(args.profile, username, password)
            print(f"账号已保存：{profile.label}  ID: {profile.id}")
        elif args.account_command == "rename":
            store.rename(args.profile, args.label)
        elif args.account_command == "default":
            store.set_default(args.profile)
        elif args.account_command == "delete":
            store.delete(args.profile, disable_timers=args.disable_timers)
            print("账号档案已删除。")
        return 0
    except (CredentialError, OSError, ValueError) as exc:
        print(f"账号操作失败：{exc}" if isinstance(exc, CredentialError)
              else f"账号设置保存失败：{type(exc).__name__}", file=sys.stderr)
        return 10


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list:
        command = "console"
        args = None
    elif args_list[0].startswith("-") and args_list[0] not in {"-h", "--help", "--version"}:
        args_list.insert(0, "watch")
        args = build_parser().parse_args(args_list)
        command = args.command
    else:
        args = build_parser().parse_args(args_list)
        command = args.command

    def dispatch() -> int:
        try:
            if command == "console":
                return run_console(
                    try_next_account=getattr(args, "try_next_account", False),
                )
            handlers = {"watch": run_watch, "login": run_login, "logout": run_logout,
                        "credential": run_credential, "account": run_account}
            if command == "status":
                return run_status()
            return handlers[command](args) if command in handlers else 2
        except (ValueError, OSError, CredentialError) as exc:
            print(
                f"启动或配置读取失败：{type(exc).__name__}。请检查设置文件、备份和权限；未切换到其他账号。",
                file=sys.stderr,
            )
            return 10

    readonly_account = command == "account" and args.account_command == "list"
    if command in {"watch", "console", "login", "logout", "credential", "account"} and not readonly_account:
        try:
            with SingleInstanceLock():
                return dispatch()
        except AlreadyRunningError:
            print(
                "ysu-net-watch 已在运行（检测到另一个进程）。"
                "请在已有窗口中切换或管理账号，或先退出该窗口。",
                file=sys.stderr,
            )
            return 5

    return dispatch()
