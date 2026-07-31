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

from .connectivity import ConnectivityChecker, ConnectivityState, DEFAULT_PROBES
from .credentials import (
    CredentialError,
    build_credential_source,
    delete_windows_credential,
    write_windows_credential,
)
from .monitor import (
    EXIT_WIFI_FAILED,
    JsonEventLog,
    WatchSettings,
    Watcher,
    default_log_path,
    sanitize_text,
)
from .portal import PortalClient, PortalError
from .schedule import TimerSchedule
from .settings import (
    ALL_DAYS,
    MAX_TIMERS,
    WEEKDAYS,
    AppSettings,
    TimerSettings,
    load_settings,
    save_settings,
    valid_time,
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
    parser.add_argument("--mode", choices=("campus", "broadband"))
    parser.add_argument("--service", choices=("unicom", "telecom", "mobile"))
    parser.add_argument(
        "--credential-source", choices=("auto", "windows", "env"), default="auto"
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

    subparsers.add_parser("console", help="打开常驻交互控制台")

    subparsers.add_parser("status", help="查询门户在线状态")

    credential = subparsers.add_parser("credential", help="管理 Windows 凭据")
    credential_sub = credential.add_subparsers(dest="credential_command", required=True)
    credential_set = credential_sub.add_parser("set")
    credential_set.add_argument("--mode", choices=("campus", "broadband"), required=True)
    credential_delete = credential_sub.add_parser("delete")
    credential_delete.add_argument("--mode", choices=("campus", "broadband"), required=True)
    return parser


def run_login(args: argparse.Namespace) -> int:
    mode, service = choose_mode(args.mode, args.service)
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
            print(f"Wi-Fi 连接失败：{exc}", file=sys.stderr)
            return EXIT_WIFI_FAILED
    source = build_credential_source(mode, args.credential_source)
    credential = None
    try:
        credential = source.get()
        portal = PortalClient()
        # `login()` intentionally returns when any service is already online.
        # Force an explicit CLI mode switch to take effect just like the
        # interactive console does.
        portal.logout()
        portal.login(credential.username, credential.password, service)
    except CredentialError as exc:
        print(f"缺少凭据：{exc}", file=sys.stderr)
        return 10
    except PortalError as exc:
        secrets = (
            (credential.username, credential.password)
            if credential is not None
            else ()
        )
        print(
            f"认证失败 [{exc.stage}/{exc.category}]："
            f"{sanitize_text(str(exc), secrets)}",
            file=sys.stderr,
        )
        return 20 if exc.category != "protocol_changed" else 30
    print("认证成功。")
    return 0


def run_status() -> int:
    try:
        status = PortalClient().status()
    except PortalError as exc:
        print(f"状态查询失败 [{exc.category}]：{exc}", file=sys.stderr)
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
        reporter(f"Wi-Fi 连接失败：{exc}")
        return EXIT_WIFI_FAILED


def run_logout(args: argparse.Namespace, reporter=print) -> int:
    wifi_result = connect_wifi(args, reporter=reporter)
    if wifi_result:
        return wifi_result
    try:
        changed = PortalClient().logout()
    except PortalError as exc:
        reporter(
            f"下线失败 [{exc.stage}/{exc.category}]：{sanitize_text(str(exc))}"
        )
        return 30 if exc.category == "protocol_changed" else 20
    if changed:
        reporter("当前校园网认证账号已下线。")
    else:
        reporter("当前已经处于下线状态。")
    return 0


def run_watch(
    args: argparse.Namespace,
    *,
    external_stop_event: threading.Event | None = None,
    install_signal_handlers: bool = True,
    reporter=print,
) -> int:
    mode, service = choose_mode(args.mode, args.service)
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
    event_log = JsonEventLog(args.log_file)
    authenticate_on_start = False
    if args.auto_wifi:
        try:
            wifi = WifiConnector(
                args.wifi_ssid,
                create_open_profile=args.create_wifi_profile,
                settle_delay=max(0.0, args.wifi_settle_delay),
            ).connect()
            event_log.write(
                "wifi_connected",
                ssid=wifi.ssid,
                profile_created=wifi.profile_created,
            )
            created = "（已更新开放网络配置）" if wifi.profile_created else ""
            reporter(f"已连接 Wi-Fi：{wifi.ssid}{created}")
        except WifiError as exc:
            event_log.write(
                "fatal",
                category="wifi_connection_failed",
                reason=str(exc),
            )
            reporter(f"Wi-Fi 连接失败：{exc}")
            return EXIT_WIFI_FAILED

        initial = checker.check()
        event_log.write(
            "startup_connectivity_check",
            state=initial.state.value,
            reason=initial.reason,
        )
        authenticate_on_start = initial.state != ConnectivityState.ONLINE
        if authenticate_on_start:
            reporter("首次启动后外网不可用，立即尝试认证。")

    stop_event = external_stop_event or threading.Event()

    def stop(_signum, _frame):
        stop_event.set()

    if install_signal_handlers and threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, stop)

    watcher = Watcher(
        settings=settings,
        checker=checker,
        credentials=build_credential_source(mode, args.credential_source),
        portal_factory=lambda: PortalClient(reporter=reporter),
        event_log=event_log,
        stop_event=stop_event,
        reporter=reporter,
        expected_network=lambda: (
            (
                WifiConnector(
                    args.wifi_ssid,
                    create_open_profile=False,
                    settle_delay=0,
                ).current_ssid()
                or ""
            ).casefold()
            == args.wifi_ssid.casefold()
        ),
    )
    reporter(f"开始监听：{service}。")
    return watcher.run(
        once=args.once, authenticate_on_start=authenticate_on_start
    )


def run_console(*, enable_scheduler: bool = True) -> int:
    worker: threading.Thread | None = None
    worker_stop: threading.Event | None = None
    worker_result: list[int] = []
    worker_slot: tuple[int, str, datetime] | None = None
    operation_lock = threading.RLock()
    worker_control_lock = threading.RLock()
    scheduler_stop = threading.Event()
    schedule = TimerSchedule()
    latest_status = "等待操作"
    recent_result = "暂无"
    pending_device_notice = ""
    active_mode: str | None = None
    active_service: str | None = None

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
            elif any(word in safe_message for word in ("失败", "已跳过", "已结束")):
                recent_result = safe_message

    def stop_worker() -> bool:
        nonlocal worker, worker_stop, worker_slot, active_mode, active_service
        with worker_control_lock:
            with operation_lock:
                current_worker = worker
                current_stop = worker_stop

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
                    worker_slot = None
                    active_mode = None
                    active_service = None
            return True

    def start_worker(
        mode: str,
        service: str | None = None,
        *,
        scheduled_timer_index: int | None = None,
        scheduled_phase: str = "primary",
        scheduled_at: datetime | None = None,
        quiet: bool = False,
    ) -> bool:
        nonlocal worker, worker_stop, worker_slot, active_mode, active_service
        with worker_control_lock:
            if not stop_worker():
                return False
            # Force the selected service to take effect instead of returning
            # early merely because another service is already online locally.
            logout_args = build_parser().parse_args(["logout"])
            action_reporter = update_status
            logout_code = run_logout(logout_args, reporter=action_reporter)
            if logout_code != 0:
                action_reporter(f"无法切换服务，下线步骤退出码：{logout_code}")
                return False

            command = ["watch", "--mode", mode]
            if service is not None:
                command.extend(["--service", service])
            watch_args = build_parser().parse_args(command)
            new_stop = threading.Event()
            new_slot = (
                (
                    scheduled_timer_index,
                    scheduled_phase,
                    scheduled_at or datetime.now(),
                )
                if scheduled_timer_index is not None
                else None
            )

            def target() -> None:
                result = run_watch(
                    watch_args,
                    external_stop_event=new_stop,
                    install_signal_handlers=False,
                    reporter=update_status,
                )
                with operation_lock:
                    worker_result.append(result)

            new_worker = threading.Thread(
                target=target, name="ysu-network-watcher", daemon=True
            )
            with operation_lock:
                worker_stop = new_stop
                worker_result.clear()
                worker_slot = new_slot
                worker = new_worker
                active_mode = mode
                active_service = service
                new_worker.start()
            return True

    def reap_worker() -> None:
        nonlocal worker, worker_stop, worker_slot, active_mode, active_service
        with worker_control_lock:
            with operation_lock:
                if worker is None or worker.is_alive() or not worker_result:
                    return
                code = worker_result[-1]
                finished_slot = worker_slot
                worker = None
                worker_stop = None
                worker_slot = None
                active_mode = None
                active_service = None
            update_status(f"监听程序已结束，退出码：{code}")
            if finished_slot is not None:
                timer_index, phase, started_at = finished_slot
                schedule.mark_finished(
                    timer_index,
                    phase,
                    started_at.date(),
                    code,
                )

    def scheduled_loop() -> None:
        while not scheduler_stop.is_set():
            reap_worker()
            now = datetime.now()
            settings = load_settings()
            due = schedule.due_timers(now, settings.timers)
            if due:
                selected = due[0]
                schedule.mark_started(selected.index, selected.phase, now.date())
                for conflict in due[1:]:
                    schedule.mark_started(
                        conflict.index,
                        conflict.phase,
                        now.date(),
                    )
                    JsonEventLog(default_log_path()).write(
                        "timer_conflict_skipped",
                        timer=conflict.index + 1,
                        phase=conflict.phase,
                        reason="another timer with the same time has priority",
                    )
                timer = selected.timer
                service = timer.service if timer.mode == "broadband" else None
                with operation_lock:
                    already_active = (
                        worker is not None
                        and worker.is_alive()
                        and active_mode == timer.mode
                        and (
                            timer.mode == "campus"
                            or active_service == timer.service
                        )
                    )
                if already_active:
                    update_status(
                        f"定时器 {selected.index + 1}：目标模式已在监听。"
                    )
                    schedule.mark_finished(
                        selected.index,
                        selected.phase,
                        now.date(),
                        0,
                    )
                    scheduler_stop.wait(15)
                    continue
                connector = WifiConnector(
                    "iYanDa", create_open_profile=False, settle_delay=0
                )
                connection = connector.connection_info()
                skip_reason = scheduled_wifi_skip_reason(connection)
                timer_name = f"定时器 {selected.index + 1}"
                phase_name = "补偿" if selected.phase == "retry" else "主任务"
                if skip_reason:
                    update_status(
                        f"{timer_name} {phase_name}已跳过：{skip_reason}"
                    )
                    JsonEventLog(default_log_path()).write(
                        "schedule_skipped",
                        timer=selected.index + 1,
                        phase=selected.phase,
                        reason=skip_reason,
                    )
                    schedule.mark_finished(
                        selected.index,
                        selected.phase,
                        now.date(),
                        0,
                    )
                    scheduler_stop.wait(15)
                    continue
                update_status(
                    f"{timer_name} {phase_name}启动："
                    f"{SERVICE_NAMES[service or 'campus']}"
                )
                if not start_worker(
                    timer.mode,
                    service,
                    scheduled_timer_index=selected.index,
                    scheduled_phase=selected.phase,
                    scheduled_at=now,
                    quiet=True,
                ):
                    schedule.mark_finished(
                        selected.index,
                        selected.phase,
                        now.date(),
                        EXIT_WIFI_FAILED,
                    )
            scheduler_stop.wait(15)

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
        path = save_settings(updated)
        print(f"常用设置已保存：{SERVICE_NAMES[updated.service if updated.mode == 'broadband' else 'campus']}")
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
        return (
            f"{prefix}[{state}] {describe_days(timer.weekdays)} "
            f"{timer.time} {service}{retry}"
        )

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
                    "修改认证模式",
                    "设置/关闭失败补偿",
                    "恢复为空白关闭状态",
                    "返回",
                ],
            )
            updated = timer
            if choice == 0:
                updated = replace(timer, enabled=not timer.enabled)
            elif choice == 1:
                value = ask_time("执行时间", timer.time)
                if value is None:
                    continue
                updated = replace(timer, time=value)
            elif choice == 2:
                days = choose_days(timer.weekdays)
                if days is None:
                    continue
                updated = replace(timer, weekdays=days)
            elif choice == 3:
                selected = choose_timer_mode(timer)
                if selected is None:
                    continue
                updated = selected
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
            save_settings(replace(current, timers=tuple(timers)))

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
            choice = select_menu(
                "常用与定时设置：",
                ["修改常用认证模式", "管理 10 个定时器", "返回"],
            )
            if choice == 0:
                configure_defaults()
            elif choice == 1:
                manage_timers()
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
                    if active_mode == "campus":
                        active_line = "校园网"
                    elif active_mode == "broadband" and active_service:
                        active_line = SERVICE_NAMES[active_service]
                    else:
                        active_line = "无"
                return (
                    f"{APP_BANNER}\n\n常用认证：{default_name}"
                    f"\n定时器：已启用 {enabled_timer_count}/{MAX_TIMERS}"
                    f"\n当前监听：{active_line}"
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
                    "修改常用/定时设置",
                    "当前认证账号下线",
                    "停止当前监听",
                    "退出程序",
                ],
            )
            choice = str(choice_index + 1) if choice_index is not None else ""
            if choice == "1":
                start_worker("campus")
            elif choice == "2":
                start_worker("broadband", defaults.service)
            elif choice == "3":
                configure_menu()
            elif choice == "4":
                stop_worker()
                run_logout(
                    build_parser().parse_args(["logout"]),
                    reporter=update_status,
                )
            elif choice == "5":
                stop_worker()
                update_status("当前监听已停止。")
            elif choice == "6":
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


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list:
        return run_console()
    elif args_list[0].startswith("-") and args_list[0] not in {"-h", "--help"}:
        args_list.insert(0, "watch")
    args = build_parser().parse_args(args_list)
    if args.command == "watch":
        return run_watch(args)
    if args.command == "login":
        return run_login(args)
    if args.command == "logout":
        return run_logout(args)
    if args.command == "console":
        return run_console()
    if args.command == "status":
        return run_status()
    if args.command == "credential":
        return run_credential(args)
    return 2
