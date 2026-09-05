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
import fcntl
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
SESSION_FILE = ".supervisor-session.json"
SESSION_SCHEMA = "org.trillionnium.owner-open.rootlinux-supervisor-session.v1"
MAX_CHILDREN = 16
MAX_PATH_BYTES = 4096
MAX_PATH_COMPONENTS = 64
MAX_PROC_ENTRIES = 65536
MAX_PROC_STAT_BYTES = 8192
MAX_PROC_SCAN_SECONDS = 1.0
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
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise SupervisorError(f"{label} is not valid UTF-8") from error
    parsed = PurePosixPath(value)
    if len(encoded) > MAX_PATH_BYTES or len(parsed.parts) > MAX_PATH_COMPONENTS:
        raise SupervisorError(f"{label} exceeds the bounded path budget")
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


def write_all(descriptor: int, data: bytes) -> None:
    """Complete a finite regular-file write; never acknowledge a short write."""
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0 or written > len(remaining):
            raise SupervisorError("state write made no valid progress")
        remaining = remaining[written:]


def private_directory(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SupervisorError("state directory must be private and owner-controlled")


def open_directory_chain(path: Path) -> int:
    """Pin an absolute directory without following any symlink component."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def private_file(descriptor: int, label: str) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SupervisorError(f"{label} must be one private owner-controlled regular file")
    return metadata


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
    group_cleaned: bool = False


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
    outputs = (emergency_stop, status_path, event_log_path)
    reserved = state_root / SESSION_FILE
    if any(path == reserved or reserved in path.parents for path in outputs):
        raise SupervisorError("state outputs must not use the reserved supervisor session path")
    if any(path == state_root for path in outputs) or any(
        left == right or left in right.parents or right in left.parents
        for index, left in enumerate(outputs) for right in outputs[index + 1:]
    ):
        raise SupervisorError("state outputs and emergency inhibit must be distinct non-overlapping leaves")
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
        self._state_directories: dict[Path, int] = {}
        self._event_failed = False
        self._session_id: str | None = None
        self._session_identity: tuple[int, int] | None = None
        self._session_bytes: bytes | None = None
        self._session_ready = False
        self._terminal_recorded = False

    def close_state(self) -> None:
        """Release only this instance's descriptors and advisory directory lock."""
        for descriptor in self._state_directories.values():
            os.close(descriptor)
        self._state_directories.clear()

    def validate_state_root(self) -> None:
        if self._state_directories:
            self.assert_state_namespace()
            return
        try:
            root = open_directory_chain(self.config.state_root)
            self._state_directories[self.config.state_root] = root
            private_directory(root)
            try:
                fcntl.flock(root, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise SupervisorError("state_root is already owned or cannot be locked") from error
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            for path in (self.config.status_path, self.config.event_log_path, self.config.emergency_stop):
                current = self.config.state_root
                descriptor = root
                for part in path.parent.relative_to(self.config.state_root).parts:
                    current = current / part
                    if current not in self._state_directories:
                        try:
                            os.mkdir(part, 0o700, dir_fd=descriptor)
                        except FileExistsError:
                            pass
                        else:
                            os.fsync(descriptor)
                        child = os.open(part, flags, dir_fd=descriptor)
                        self._state_directories[current] = child
                        private_directory(child)
                    descriptor = self._state_directories[current]
            self.assert_state_namespace()
        except BaseException:
            self.close_state()
            raise

    def assert_state_namespace(self) -> None:
        """Reject replacement of a pinned directory, including inhibit parents.

        These checks do not defend against a malicious root/same-UID custodian.
        Retained dirfds, not the rechecked pathnames, are used for actual I/O.
        """
        if not self._state_directories:
            raise SupervisorError("state_root ownership has not been acquired")
        root = self.config.state_root
        current = open_directory_chain(root)
        try:
            pinned, observed = os.fstat(self._state_directories[root]), os.fstat(current)
            if (pinned.st_dev, pinned.st_ino) != (observed.st_dev, observed.st_ino):
                raise SupervisorError("state directory identity changed")
        finally:
            os.close(current)
        # Every intermediate parent is pinned. Check each edge once rather than
        # repeatedly traversing the whole prefix for every nested directory.
        for path, descriptor in self._state_directories.items():
            private_directory(descriptor)
            if path == root:
                continue
            observed = os.stat(
                path.name, dir_fd=self._state_directories[path.parent], follow_symlinks=False,
            )
            pinned = os.fstat(descriptor)
            if not stat.S_ISDIR(observed.st_mode) or (
                pinned.st_dev, pinned.st_ino
            ) != (observed.st_dev, observed.st_ino):
                raise SupervisorError("state directory identity changed")

    def state_parent(self, path: Path) -> int:
        self.assert_state_namespace()
        try:
            return self._state_directories[path.parent]
        except KeyError as error:
            raise SupervisorError("state output parent was not pinned") from error

    def assert_session_clear(self) -> None:
        """An absent process lock is not a receipt for an earlier session.

        Any retained marker (even empty, stale-looking, or a special file)
        requires offline reconciliation. Never inspect a stored PID to kill,
        adopt, or automatically remove another session's record.
        """
        parent = self.state_parent(self.config.state_root / SESSION_FILE)
        try:
            os.stat(SESSION_FILE, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise SupervisorError("prior supervisor session requires offline reconciliation")

    def begin_session(self) -> None:
        """Durably fence crash recovery before a new carrier may start."""
        if self._session_id is not None:
            raise SupervisorError("supervisor session admission was already attempted")
        parent = self.state_parent(self.config.state_root / SESSION_FILE)
        self._session_id = secrets.token_hex(16)
        self._session_bytes = json.dumps({
            "schema": SESSION_SCHEMA,
            "session_id": self._session_id,
            "supervisor_pid": os.getpid(),
            "pid_is_recovery_authority": False,
            "automatic_effect_redispatch": False,
            "cleanup_scope": "original_process_group_only",
            "recovery": "offline_reconciliation_required_if_retained",
        }, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        descriptor = os.open(
            SESSION_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=parent,
        )
        try:
            metadata = private_file(descriptor, "supervisor session")
            self._session_identity = (metadata.st_dev, metadata.st_ino)
            write_all(descriptor, self._session_bytes)
            os.fsync(descriptor)
            os.fsync(parent)
        finally:
            # Even a short/failed creation remains as a recovery fence. It is
            # not removed just because the creating process knows it failed.
            os.close(descriptor)
        self._session_ready = True

    def assert_session_owned(self) -> None:
        if not self._session_ready or self._session_bytes is None:
            raise SupervisorError("supervisor session admission is not durable")
        parent = self.state_parent(self.config.state_root / SESSION_FILE)
        descriptor = os.open(
            SESSION_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=parent,
        )
        try:
            metadata = private_file(descriptor, "supervisor session")
            if (metadata.st_dev, metadata.st_ino) != self._session_identity:
                raise SupervisorError("supervisor session identity changed")
            if metadata.st_size != len(self._session_bytes) or os.read(
                descriptor, len(self._session_bytes) + 1,
            ) != self._session_bytes:
                raise SupervisorError("supervisor session contents changed")
        finally:
            os.close(descriptor)

    def finish_session(self) -> None:
        if any(not child.group_cleaned for child in self.children.values()):
            raise SupervisorError("unconfirmed cleanup cannot release the supervisor session")
        if not self._terminal_recorded:
            raise SupervisorError("a durable terminal observation is required to release the session")
        self.assert_session_owned()
        parent = self.state_parent(self.config.state_root / SESSION_FILE)
        os.unlink(SESSION_FILE, dir_fd=parent)
        # If sync fails after unlink, removal is durability-unknown, not a
        # successful terminal operation. The caller must return failure.
        os.fsync(parent)
        self._session_ready = False

    def append_event(self, kind: str, **fields: Any) -> None:
        value = {
            "schema": "org.trillionnium.owner-open.rootlinux-supervisor-event.v1",
            "kind": kind,
            "session_id": self._session_id,
            "monotonic_ns": time.monotonic_ns(),
            "automatic_effect_redispatch": False,
            **fields,
        }
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        if self._event_failed:
            raise SupervisorError("event log is fenced after an I/O or integrity failure")
        parent = self.state_parent(self.config.event_log_path)
        descriptor = None
        try:
            descriptor = os.open(
                self.config.event_log_path.name,
                os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
                | os.O_CLOEXEC | os.O_NONBLOCK,
                0o600, dir_fd=parent,
            )
            metadata = private_file(descriptor, "event log")
            if metadata.st_size + len(encoded) > MAX_EVENT_BYTES:
                raise SupervisorError("event log capacity exhausted")
            if metadata.st_size and os.pread(descriptor, 1, metadata.st_size - 1) != b"\n":
                raise SupervisorError("event log has an unterminated tail; reconciliation required")
            write_all(descriptor, encoded)
            os.fsync(descriptor)
            # A new event file's name must survive independently of its bytes.
            os.fsync(parent)
        except BaseException:
            self._event_failed = True
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def write_status(self, state: str, reason: str | None = None) -> None:
        value = {
            "schema": "org.trillionnium.owner-open.rootlinux-supervisor-status.v1",
            "state": state,
            "session_id": self._session_id,
            "reason": reason,
            "children": {
                name: {
                    "pid": managed.process.pid,
                    "running": self.observe_exit(managed) is None,
                    "group_cleanup": "no_live_original_group_members_observed" if managed.group_cleaned else "pending",
                    "restart_count": len(managed.restart_times),
                }
                for name, managed in sorted(self.children.items())
            },
            "automatic_effect_redispatch": False,
            "updated_monotonic_ns": time.monotonic_ns(),
            "cleanup_scope": "original_process_group_only",
            "escaped_descendants_absence_proven": False,
        }
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
        parent = self.state_parent(self.config.status_path)
        temporary = f".{self.config.status_path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent,
        )
        replaced = False
        try:
            write_all(descriptor, raw)
            os.fsync(descriptor)
            os.replace(temporary, self.config.status_path.name, src_dir_fd=parent, dst_dir_fd=parent)
            replaced = True
            # Failure here means visible-but-durability-unknown, never success.
            os.fsync(parent)
        finally:
            os.close(descriptor)
            if not replaced:
                os.unlink(temporary, dir_fd=parent)

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
        if self._event_failed:
            raise SupervisorError("event log failure prohibits new carrier admission")
        if self.emergency_requested():
            raise SupervisorError("carrier admission is inhibited")
        if self._session_id is None:
            self.begin_session()
        self.assert_session_owned()
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
    def observe_exit(managed: ManagedChild) -> int | None:
        """Observe, but do not reap, the leader that pins the original PGID.

        No Popen.poll/wait is permitted before group cleanup. A retained zombie
        prevents reuse of its numeric PID while TERM/KILL are sent to the group.
        This supervisor must be the sole reaper of its direct children.
        """
        if managed.group_cleaned:
            return managed.process.returncode
        if managed.process.returncode is not None:
            raise SupervisorError("process-group anchor was reaped before cleanup")
        try:
            status = os.waitid(
                os.P_PID, managed.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except (OSError, AttributeError) as error:
            raise SupervisorError(f"cannot retain process-group anchor: {error}") from error
        if status is None:
            return None
        if status.si_code == os.CLD_EXITED:
            return status.si_status
        if status.si_code in (os.CLD_KILLED, os.CLD_DUMPED):
            return -status.si_status
        raise SupervisorError("unexpected non-exit process-group anchor status")

    @staticmethod
    def live_group_members(pgid: int) -> tuple[int, ...]:
        """Bounded procfs observation, not proof about escaped descendants.

        The installed environment must provide a complete same-namespace /proc
        view. Zombies cannot execute and do not count as live members; their
        actual reaping belongs to their parent or the installed init/subreaper.
        """
        found: list[int] = []
        anchor_seen = False
        deadline = time.monotonic() + MAX_PROC_SCAN_SECONDS
        try:
            with os.scandir("/proc") as entries:
                for count, entry in enumerate(entries, 1):
                    if count > MAX_PROC_ENTRIES or time.monotonic() >= deadline:
                        raise SupervisorError("process-group observation budget exhausted")
                    if not entry.name.isascii() or not entry.name.isdecimal():
                        continue
                    try:
                        with open(f"/proc/{entry.name}/stat", "rb") as current:
                            raw = current.read(MAX_PROC_STAT_BYTES + 1)
                    except (FileNotFoundError, ProcessLookupError):
                        continue  # An unrelated process may leave during scanning.
                    if len(raw) > MAX_PROC_STAT_BYTES:
                        raise SupervisorError("oversized procfs process stat")
                    # comm may contain whitespace and parentheses: split at its
                    # final closing parenthesis before indexing the numeric fields.
                    fields = raw.rsplit(b")", 1)[1].split()
                    group, session = int(fields[2]), int(fields[3])
                    if int(entry.name) == pgid:
                        if group != pgid or session != pgid:
                            raise SupervisorError("process-group anchor identity differs")
                        anchor_seen = True
                    if group == pgid and fields[0] not in (b"Z", b"X"):
                        if session != pgid:
                            raise SupervisorError("process-group session identity differs")
                        found.append(int(entry.name))
        except (OSError, ValueError, IndexError) as error:
            raise SupervisorError(f"process-group observation unavailable: {error}") from error
        if not anchor_seen:
            raise SupervisorError("retained process-group anchor is not observable")
        return tuple(sorted(found))

    @staticmethod
    def signal_group(managed: ManagedChild, current: int) -> None:
        if managed.group_cleaned:
            return
        Supervisor.observe_exit(managed)  # Never signal an already-reaped/reused PGID.
        try:
            os.killpg(managed.process.pid, current)
        except ProcessLookupError:
            pass
        except OSError as error:
            raise SupervisorError(f"cannot signal original process group: {error}") from error

    def wait_groups(self, deadline: float, children: list[ManagedChild] | None = None) -> bool:
        selected = list(self.children.values()) if children is None else children
        quiet_once = False
        while time.monotonic() < deadline:
            quiet = True
            for managed in selected:
                if managed.group_cleaned:
                    continue
                exited = self.observe_exit(managed) is not None
                live = self.live_group_members(managed.process.pid)
                quiet = quiet and exited and not live
            if quiet and quiet_once:
                return True
            quiet_once = quiet
            time.sleep(min(self.config.poll_seconds, 0.01, max(0.0, deadline - time.monotonic())))
        return False

    def cleanup_groups(self, children: list[ManagedChild]) -> None:
        pending = [child for child in children if not child.group_cleaned]
        if not pending:
            return
        errors: list[str] = []
        for managed in pending:
            try:
                self.signal_group(managed, signal.SIGTERM)
            except SupervisorError as error:
                errors.append(str(error))
        try:
            self.wait_groups(time.monotonic() + self.config.shutdown_grace_seconds, pending)
        except SupervisorError as error:
            errors.append(str(error))
        # Always escalate before reaping, even if TERM killed the leader or a
        # procfs read failed. Other still-pinned groups must also receive KILL.
        for managed in pending:
            try:
                self.signal_group(managed, signal.SIGKILL)
            except SupervisorError as error:
                errors.append(str(error))
        try:
            settled = self.wait_groups(time.monotonic() + self.config.kill_grace_seconds, pending)
        except SupervisorError as error:
            errors.append(str(error))
            settled = False
        if errors or not settled:
            raise SupervisorError(f"original process-group cleanup unconfirmed: {errors or ['deadline']}")
        for managed in pending:
            managed.process.wait(timeout=0)
            managed.group_cleaned = True
        # Finish reaping every settled anchor even if audit storage has failed.
        for managed in pending:
            self.append_event(
                "child_group_cleaned", child=managed.config.name,
                pgid=managed.process.pid, scope="original_process_group_only",
                escaped_descendants_absence_proven=False,
            )

    def shutdown(self) -> None:
        self.cleanup_groups(list(self.children.values()))

    def emergency_requested(self) -> bool:
        try:
            parent = self.state_parent(self.config.emergency_stop)
        except (OSError, SupervisorError):
            return True
        try:
            os.stat(self.config.emergency_stop.name, dir_fd=parent, follow_symlinks=False)
            return True  # Any marker, including a dangling symlink, inhibits.
        except FileNotFoundError:
            return False
        except (OSError, SupervisorError):
            return True  # An unreadable inhibit state is not permission to spawn.

    def request_stop(self, reason: str) -> None:
        if self.stop_reason is None:
            self.stop_reason = reason

    def interruptible_sleep(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while self.stop_reason is None and time.monotonic() < deadline:
            if self.emergency_requested():
                self.request_stop("emergency_stop")
                break
            time.sleep(min(self.config.poll_seconds, max(0.0, deadline - time.monotonic())))

    def run(self) -> int:
        if (
            not sys.platform.startswith("linux") or not callable(getattr(os, "waitid", None))
            or not hasattr(os, "WNOWAIT") or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
        ):
            raise SupervisorError("Linux waitid/WNOWAIT and exclusive default-SIGCHLD reaping are required")
        try:
            self.validate_state_root()
            self.assert_session_clear()
            result = self.run_owned()
            if result in (0, 75) and self._session_ready:
                self.finish_session()
            return result
        finally:
            self.close_state()

    def run_owned(self) -> int:
        if self.emergency_requested():
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
            self.begin_session()
            # Detect an unsafe/full/torn event log before the first carrier.
            # This is a supervisor observation, not durable job acceptance.
            self.append_event("supervisor_starting")
            for child in self.config.children:
                if self.emergency_requested():
                    self.request_stop("emergency_stop")
                if self.stop_reason is not None:
                    break
                self.spawn(child)
            self.append_event("supervisor_ready", child_count=len(self.children))
            self.write_status("running")
            while self.stop_reason is None and self.failure_reason is None:
                self.assert_session_owned()
                if self.emergency_requested():
                    self.request_stop("emergency_stop")
                    break
                for name in sorted(self.children):
                    managed = self.children[name]
                    returncode = self.observe_exit(managed)
                    if returncode is None:
                        continue
                    self.append_event("child_exited", child=name, returncode=returncode)
                    # Retire the old group before dropping a noncritical child,
                    # exhausting a budget, or replacing its managed-child slot.
                    self.cleanup_groups([managed])
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
                    if self.emergency_requested():
                        self.request_stop("emergency_stop")
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
                self._terminal_recorded = True
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
