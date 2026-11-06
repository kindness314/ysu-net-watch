"""Persistent, credential-free protection for one user's campus authenticator.

The CLI's SingleInstanceLock serializes processes; this lock serializes threads
and clients in that process. Reserve BEFORE starting a new credential workflow:
a lost response must not permit unlimited submissions after a restart.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import threading
import time
import uuid


MAX_SUBMISSIONS = 4
RETRY_DELAYS = (300.0, 900.0, 1800.0)
LOCK = threading.RLock()
TERMINAL_REASONS = {
    "mac_conflict": "运营商 MAC 会话冲突",
    "mac_blocked": "MAC/设备被冻结或封禁",
    "rate_limited": "认证过于频繁，门户要求停止",
    "ip_blocked": "认证来源 IP 被冻结或封禁",
    "credential_rejected": "账号或密码被拒绝",
    "account_locked": "账号被冻结或锁定",
    "protocol_changed": "门户协议异常",
    "unsafe_redirect": "认证跳转安全检查未通过",
    "attempts_exhausted": "已达到四次认证提交上限",
}


class ProtectionError(RuntimeError):
    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def default_protection_path() -> Path:
    root = os.environ.get("LOCALAPPDATA")
    return (Path(root) / "YSUNetWatch" if root else Path.home() / ".ysu-net-watch") / "auth-protection.json"


class AuthProtection:
    def __init__(self, path: Path | None = None, *, clock=time.time):
        self.path = path if path is not None else default_protection_path()
        self.clock = clock

    def _now(self) -> float:
        value = float(self.clock())
        if not math.isfinite(value) or value < 0:
            raise ProtectionError("protection_invalid", "系统时间无效，已停止认证提交")
        return value

    @staticmethod
    def _empty() -> dict:
        return {"schema": 1, "submissions": 0, "next_allowed": 0.0,
                "last_submission": 0.0, "updated": 0.0, "blocked": None}

    def _load(self) -> dict:
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return self._empty()
        except (OSError, ValueError) as exc:
            raise ProtectionError("protection_invalid", "认证保护状态不可读取，请检查备份和权限；未清零重试次数") from exc
        valid = (
            isinstance(state, dict) and set(state) == set(self._empty())
            and type(state.get("schema")) is int
            and state["schema"] == 1 and type(state.get("submissions")) is int
            and 0 <= state["submissions"] <= MAX_SUBMISSIONS
            and (state.get("blocked") is None or isinstance(state.get("blocked"), str)
                 and state["blocked"] in TERMINAL_REASONS)
            and all(type(state.get(key)) in (int, float)
                    and 0 <= state[key] <= 253402300799 and math.isfinite(state[key])
                    for key in ("next_allowed", "last_submission", "updated"))
        )
        if not valid:
            raise ProtectionError("protection_invalid", "认证保护状态格式无效，已停止提交；不会自动清零")
        return state

    def _save(self, state: dict) -> None:
        temporary = self.path.with_name(self.path.name + "." + uuid.uuid4().hex + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump(state, stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except OSError as exc:
            raise ProtectionError("protection_invalid", "认证保护状态无法安全保存，未继续提交认证") from exc
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _check(self, state: dict, now: float) -> None:
        if now < state["updated"]:
            raise ProtectionError("protection_invalid", "系统时间回退，请校正时间；认证保护未解除")
        if state["blocked"] or state["submissions"] >= MAX_SUBMISSIONS:
            reason = TERMINAL_REASONS.get(state["blocked"], TERMINAL_REASONS["attempts_exhausted"])
            raise ProtectionError("authentication_protected", f"认证保护：{reason}。已停止自动提交；请确认处理后手动解除")
        if now < state["next_allowed"]:
            remaining = math.ceil(state["next_allowed"] - now)
            raise ProtectionError("authentication_cooldown", f"认证冷却中，剩余 {remaining} 秒；重启、定时器或切换账号不能跳过")

    def check(self) -> None:
        with LOCK:
            self._check(self._load(), self._now())

    def reserve(self) -> int:
        with LOCK:
            state, now = self._load(), self._now()
            self._check(state, now)
            state["submissions"] += 1
            attempt = state["submissions"]
            state.update(last_submission=now, updated=now,
                         next_allowed=now + RETRY_DELAYS[min(attempt - 1, 2)])
            # The fourth reserved request may finish. No fifth request may start,
            # even if this process dies or that response never arrives.
            if attempt == MAX_SUBMISSIONS:
                state["blocked"] = "attempts_exhausted"
            self._save(state)
            return attempt

    def failed(self, category: str) -> None:
        with LOCK:
            state, now = self._load(), self._now()
            if now < state["updated"]:
                raise ProtectionError("protection_invalid", "系统时间回退，认证保护未解除")
            if category in TERMINAL_REASONS:
                state["blocked"] = category
            if state["submissions"]:
                delay = RETRY_DELAYS[min(state["submissions"] - 1, 2)]
                state["next_allowed"] = max(state["next_allowed"], now + delay)
            state["updated"] = now
            self._save(state)

    def succeeded(self) -> None:
        with LOCK:
            state, now = self._load(), self._now()
            if now < state["updated"]:
                raise ProtectionError("protection_invalid", "系统时间回退，认证保护未解除")
            # Success resets the failure episode, not the minimum submission gap.
            if state["blocked"] not in (None, "attempts_exhausted"):
                return
            state.update(submissions=0, blocked=None, updated=now,
                         next_allowed=max(now, state["last_submission"] + RETRY_DELAYS[0]))
            self._save(state)

    def status(self) -> dict:
        with LOCK:
            state, now = self._load(), self._now()
            return {"submissions": state["submissions"], "limit": MAX_SUBMISSIONS,
                    "blocked": state["blocked"],
                    "reason": TERMINAL_REASONS.get(state["blocked"], "未触发停止保护"),
                    "remaining_seconds": max(0, math.ceil(state["next_allowed"] - now))}

    def reset(self) -> None:
        with LOCK:
            state, now = self._load(), self._now()
            if now < state["updated"]:
                raise ProtectionError("protection_invalid", "请先校正系统时间，未解除认证保护")
            state.update(submissions=0, blocked=None, updated=now,
                         next_allowed=max(now, state["last_submission"] + RETRY_DELAYS[0]))
            self._save(state)
