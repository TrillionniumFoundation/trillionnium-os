#!/usr/bin/env python3
"""Finite mechanism-only supervisor for the owner-open Root Linux payload.

This process owns child process groups, bounded restart policy, status evidence
and emergency-stop handling. It never interprets a command, reconstructs a
semantic plan, or redispatches an accepted effect. Restarting a crashed carrier
starts only the carrier; durable call/job recovery remains the Host's explicit,
no-auto-redispatch protocol.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, field
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from typing import Any

SCHEMA = "org.trillionnium.owner-open.rootlinux-supervisor.v1"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_EVENT_BYTES = 16 * 1024 * 1024
MAX_CHILDREN = 16
NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")


class SupervisorError(RuntimeError):
    pass


class DuplicateMember(ValueError):
    pass


def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise DuplicateMember(f"duplicate key {key}")
        result[key] = value
    return result


def strict_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        actual = set(value) if isinstance(value, dict) else set()
        raise SupervisorError(
            f"{label} keys differ: missing={sorted(keys - actual)} extra={sorted(actual - keys)}"
        )
    return value


def absolute_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise SupervisorError(f"{label} must be an absolute NUL-free path")
    parsed = PurePosixPath(value)
    if ".." in parsed.parts or str(parsed) != value:
        raise SupervisorError(f"{label} is not canonical")
    return Path(value)


def bounded_number(value: Any, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SupervisorError(f"{label} must be numeric")
    result = float(value)
    if not minimum <= result <= maximum:
        raise SupervisorError(f"{label} is outside {minimum}..{maximum}")
    return result


def environment(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 128:
        raise SupervisorError(f"{label} must be a bounded object")
    result: dict[str, str] = {}
    for key, current in value.items():
        if not isinstance(key, str) or ENV_NAME.fullmatch(key) is None:
            raise SupervisorError(f"{label} contains an invalid environment name")
        if key == "ANDROID_SERIAL":
            raise SupervisorError("ANDROID_SERIAL is forbidden in the owner-open supervisor")
        if not isinstance(current, str) or "\x00" in current or len(current) > 16384:
            raise SupervisorError(f"{label}.{key} is malformed or oversized")
        result[key] = current
    return result


def stable_executable(path: Path, label: str) -> None:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_mode & 0o022
        or metadata.st_mode & 0o111 == 0
    ):
        raise SupervisorError(f"{label} is not one stable non-writable executable")


@dataclass(frozen=True)
class ChildConfig:
    name: str
    argv: tuple[str, ...]
    environment: dict[str, str]
    critical: bool
    restart_limit: int
    restart_window_seconds: float
    restart_backoff_seconds: float


@dataclass(frozen=True)
class Config:
    state_root: Path
    emergency_stop: Path
    status_path: Path
    event_log_path: Path
    poll_seconds: float
    shutdown_grace_seconds: float
    kill_grace_seconds: float
    environment: dict[str, str]
    children: tuple[ChildConfig, ...]


@dataclass
class ManagedChild:
    config: ChildConfig
    process: subprocess.Popen[bytes]
    restart_times: deque[float] = field(default_factory=deque)


def load_config(path: Path) -> Config:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > MAX_CONFIG_BYTES
        or metadata.st_mode & 0o022
    ):
        raise SupervisorError("supervisor config is not one bounded non-writable file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise SupervisorError("supervisor config changed while read")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise SupervisorError(f"invalid supervisor config: {error}") from error
    value = strict_object(
        value,
        {
            "schema",
            "state_root",
            "emergency_stop",
            "status_path",
            "event_log_path",
            "poll_seconds",
            "shutdown_grace_seconds",
            "kill_grace_seconds",
            "environment",
            "children",
            "automatic_effect_redispatch",
        },
        "supervisor config",
    )
    if value.get("schema") != SCHEMA:
        raise SupervisorError(f"supervisor config schema must be {SCHEMA}")
    if value.get("automatic_effect_redispatch") is not False:
        raise SupervisorError("automatic_effect_redispatch must be false")
    state_root = absolute_path(value.get("state_root"), "state_root")
    emergency_stop = absolute_path(value.get("emergency_stop"), "emergency_stop")
    status_path = absolute_path(value.get("status_path"), "status_path")
    event_log_path = absolute_path(value.get("event_log_path"), "event_log_path")
    for label, current in (
        ("emergency_stop", emergency_stop),
        ("status_path", status_path),
        ("event_log_path", event_log_path),
    ):
        try:
            current.relative_to(state_root)
        except ValueError as error:
            raise SupervisorError(f"{label} must remain below state_root") from error
    poll_seconds = bounded_number(value.get("poll_seconds"), "poll_seconds", 0.01, 1.0)
    shutdown_grace_seconds = bounded_number(
        value.get("shutdown_grace_seconds"), "shutdown_grace_seconds", 0.1, 30.0
    )
    kill_grace_seconds = bounded_number(
        value.get("kill_grace_seconds"), "kill_grace_seconds", 0.1, 30.0
    )
    base_environment = environment(value.get("environment"), "environment")
    children_value = value.get("children")
    if not isinstance(children_value, list) or not 1 <= len(children_value) <= MAX_CHILDREN:
        raise SupervisorError("children must contain 1..16 entries")
    children: list[ChildConfig] = []
    names: set[str] = set()
    for index, item in enumerate(children_value):
        item = strict_object(
            item,
            {
                "name",
                "argv",
                "environment",
                "critical",
                "restart_limit",
                "restart_window_seconds",
                "restart_backoff_seconds",
            },
            f"child[{index}]",
        )
        name = item.get("name")
        if not isinstance(name, str) or NAME.fullmatch(name) is None or name in names:
            raise SupervisorError(f"child[{index}].name is malformed or duplicated")
        names.add(name)
        argv_value = item.get("argv")
        if (
            not isinstance(argv_value, list)
            or not 1 <= len(argv_value) <= 128
            or any(not isinstance(argument, str) or "\x00" in argument or len(argument) > 16384 for argument in argv_value)
        ):
            raise SupervisorError(f"child[{index}].argv is malformed or oversized")
        executable = absolute_path(argv_value[0], f"child[{index}].argv[0]")
        stable_executable(executable, f"child {name} executable")
        child_environment = environment(item.get("environment"), f"child[{index}].environment")
        critical = item.get("critical")
        if not isinstance(critical, bool):
            raise SupervisorError(f"child[{index}].critical must be boolean")
        restart_limit = item.get("restart_limit")
        if (
            not isinstance(restart_limit, int)
            or isinstance(restart_limit, bool)
            or not 0 <= restart_limit <= 32
        ):
            raise SupervisorError(f"child[{index}].restart_limit must be in 0..32")
        restart_window = bounded_number(
            item.get("restart_window_seconds"),
            f"child[{index}].restart_window_seconds",
            1.0,
            3600.0,
        )
        restart_backoff = bounded_number(
            item.get("restart_backoff_seconds"),
            f"child[{index}].restart_backoff_seconds",
            0.0,
            60.0,
        )
        children.append(
            ChildConfig(
                name=name,
                argv=tuple(argv_value),
                environment=child_environment,
                critical=critical,
                restart_limit=restart_limit,
                restart_window_seconds=restart_window,
                restart_backoff_seconds=restart_backoff,
            )
        )
    if not any(child.critical for child in children):
        raise SupervisorError("at least one child must be critical")
    return Config(
        state_root=state_root,
        emergency_stop=emergency_stop,
        status_path=status_path,
        event_log_path=event_log_path,
        poll_seconds=poll_seconds,
        shutdown_grace_seconds=shutdown_grace_seconds,
        kill_grace_seconds=kill_grace_seconds,
        environment=base_environment,
        children=tuple(children),
    )


class Supervisor:
    def __init__(self, config: Config):
        self.config = config
        self.children: dict[str, ManagedChild] = {}
        self.stop_reason: str | None = None
        self.failure_reason: str | None = None

    def validate_state_root(self) -> None:
        metadata = self.config.state_root.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise SupervisorError("state_root must be a private owner-controlled directory")
        for path in (self.config.status_path.parent, self.config.event_log_path.parent):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            current = path.lstat()
            if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
                raise SupervisorError(f"state child path is unsafe: {path}")
            os.chmod(path, 0o700)

    def append_event(self, kind: str, **fields: Any) -> None:
        value = {
            "schema": "org.trillionnium.owner-open.rootlinux-supervisor-event.v1",
            "kind": kind,
            "monotonic_ns": time.monotonic_ns(),
            "automatic_effect_redispatch": False,
            **fields,
        }
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        descriptor = os.open(
            self.config.event_log_path,
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | os.O_CLOEXEC,
            0o600,
        )
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise SupervisorError("event log is not one regular file")
            if metadata.st_size + len(encoded) > MAX_EVENT_BYTES:
                raise SupervisorError("event log capacity exhausted")
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def write_status(self, state: str, reason: str | None = None) -> None:
        value = {
            "schema": "org.trillionnium.owner-open.rootlinux-supervisor-status.v1",
            "state": state,
            "reason": reason,
            "children": {
                name: {
                    "pid": managed.process.pid,
                    "running": managed.process.poll() is None,
                    "restart_count": len(managed.restart_times),
                }
                for name, managed in sorted(self.children.items())
            },
            "automatic_effect_redispatch": False,
            "updated_monotonic_ns": time.monotonic_ns(),
        }
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
        temporary = self.config.status_path.parent / (
            f".{self.config.status_path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.config.status_path)
        os.chmod(self.config.status_path, 0o600)

    def child_environment(self, child: ChildConfig) -> dict[str, str]:
        result = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
        result.update(self.config.environment)
        result.update(child.environment)
        result.pop("ANDROID_SERIAL", None)
        return result

    def spawn(self, child: ChildConfig, restart_times: deque[float] | None = None) -> ManagedChild:
        process = subprocess.Popen(
            list(child.argv),
            stdin=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            env=self.child_environment(child),
        )
        managed = ManagedChild(
            config=child,
            process=process,
            restart_times=restart_times if restart_times is not None else deque(),
        )
        self.children[child.name] = managed
        self.append_event("child_started", child=child.name, pid=process.pid)
        return managed

    @staticmethod
    def signal_group(managed: ManagedChild, current: int) -> None:
        if managed.process.poll() is not None:
            return
        try:
            os.killpg(managed.process.pid, current)
        except ProcessLookupError:
            pass

    def wait_groups(self, deadline: float) -> None:
        while time.monotonic() < deadline:
            if all(item.process.poll() is not None for item in self.children.values()):
                return
            time.sleep(min(self.config.poll_seconds, max(0.0, deadline - time.monotonic())))

    def shutdown(self) -> None:
        for managed in self.children.values():
            self.signal_group(managed, signal.SIGTERM)
        self.wait_groups(time.monotonic() + self.config.shutdown_grace_seconds)
        for managed in self.children.values():
            self.signal_group(managed, signal.SIGKILL)
        self.wait_groups(time.monotonic() + self.config.kill_grace_seconds)
        unreaped: list[str] = []
        for name, managed in self.children.items():
            try:
                managed.process.wait(timeout=0)
            except subprocess.TimeoutExpired:
                unreaped.append(name)
        if unreaped:
            raise SupervisorError(f"child process groups could not be reaped: {sorted(unreaped)}")

    def request_stop(self, reason: str) -> None:
        if self.stop_reason is None:
            self.stop_reason = reason

    def interruptible_sleep(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while self.stop_reason is None and time.monotonic() < deadline:
            if self.config.emergency_stop.exists():
                self.request_stop("emergency_stop")
                break
            time.sleep(min(self.config.poll_seconds, max(0.0, deadline - time.monotonic())))

    def run(self) -> int:
        self.validate_state_root()
        if self.config.emergency_stop.exists():
            self.append_event("startup_inhibited", reason="emergency_stop")
            self.write_status("inhibited", "emergency_stop")
            return 75
        previous_handlers: dict[int, Any] = {}
        for current in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            try:
                previous_handlers[current] = signal.getsignal(current)
                signal.signal(current, lambda signum, _frame: self.request_stop(f"signal:{signum}"))
            except ValueError:
                pass
        result = 0
        try:
            for child in self.config.children:
                self.spawn(child)
            self.append_event("supervisor_ready", child_count=len(self.children))
            self.write_status("running")
            while self.stop_reason is None and self.failure_reason is None:
                if self.config.emergency_stop.exists():
                    self.request_stop("emergency_stop")
                    break
                for name in sorted(self.children):
                    managed = self.children[name]
                    returncode = managed.process.poll()
                    if returncode is None:
                        continue
                    self.append_event("child_exited", child=name, returncode=returncode)
                    if not managed.config.critical:
                        del self.children[name]
                        break
                    now = time.monotonic()
                    window = managed.config.restart_window_seconds
                    while managed.restart_times and managed.restart_times[0] < now - window:
                        managed.restart_times.popleft()
                    if len(managed.restart_times) >= managed.config.restart_limit:
                        self.failure_reason = f"restart_budget_exhausted:{name}:{returncode}"
                        result = 70
                        break
                    managed.restart_times.append(now)
                    self.append_event(
                        "child_restart_scheduled",
                        child=name,
                        returncode=returncode,
                        restart_count=len(managed.restart_times),
                    )
                    self.interruptible_sleep(managed.config.restart_backoff_seconds)
                    if self.stop_reason is None:
                        self.spawn(managed.config, managed.restart_times)
                    break
                self.write_status("running")
                time.sleep(self.config.poll_seconds)
            reason = self.failure_reason or self.stop_reason or "supervisor_stopped"
            if reason == "emergency_stop":
                result = 75
            self.append_event("supervisor_stopping", reason=reason)
            self.write_status("stopping", reason)
        except Exception as error:
            result = 70
            self.failure_reason = f"supervisor_error:{type(error).__name__}:{error}"
            try:
                self.append_event("supervisor_error", error=self.failure_reason)
            except Exception:
                pass
        finally:
            try:
                self.shutdown()
            except Exception as error:
                result = 70
                self.failure_reason = f"cleanup_error:{type(error).__name__}:{error}"
            reason = self.failure_reason or self.stop_reason or "clean_stop"
            try:
                self.write_status("terminal", reason)
                self.append_event("supervisor_terminal", reason=reason, returncode=result)
            except Exception:
                result = 70
            for current, handler in previous_handlers.items():
                signal.signal(current, handler)
        return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--config", required=True, type=Path)
    result = parser.parse_args(argv)
    if not result.execute:
        parser.error("--execute is required")
    return result


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        config = load_config(args.config)
        return Supervisor(config).run()
    except (OSError, SupervisorError) as error:
        print(f"owner-open Root Linux supervisor HOLD: {error}", file=sys.stderr)
        return 70


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
