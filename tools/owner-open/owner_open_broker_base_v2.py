"""Process, descriptor and delivery state for the owner-open broker v2."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import math
import os
import secrets
import signal
import socket
import subprocess
import threading
import time
from typing import Any

from owner_open_broker_audit import BrokerAuditJournal
from owner_open_broker_common import (
    BrokerError,
    canonical,
    finalize_descriptor,
    load_or_create_token,
    open_validated_executable,
    read_line,
    strict_json,
    validate_argv,
    validate_executable,
)
from owner_open_broker_mux import WeightedFairMux
from owner_open_broker_runtime import (
    BROKER_WRITE_TIMEOUT_SECONDS,
    Client,
    Request,
    write_all_bounded,
)

SCHEMA = "org.trillionnium.owner-open.connection-broker.v1"
WIRE = "org.trillionnium.owner-open.connection-broker-wire.v1"
DEFAULT_TIMEOUT_MS = 30_000
MAX_TIMEOUT_MS = 600_000
MAX_EXPECTED_KINDS = 32
TIMEOUT_SCAN_SECONDS = 0.01
DIRECT_ERROR_KINDS = frozenset({"host.error", "job.error"})

# Process-group cleanup is deliberately bounded.  A group signal is only
# issued after the leader generation, process-group and session identities
# captured at spawn are re-observed.  If that proof is unavailable, the exact
# ``Popen`` child handle may still be signalled safely, but a numeric PGID is
# never treated as authority by itself.
PROCESS_GROUP_SCAN_BUDGET_SECONDS = 0.5
UPSTREAM_TERMINATE_GRACE_SECONDS = 1.0
MAX_PROCESS_GROUP_SCAN_ENTRIES = 65_536


@dataclass(frozen=True)
class _ProcessIdentity:
    pid: int
    process_group: int
    session_id: int
    start_time_ticks: int
    boot_id_sha256: str


def _parse_proc_stat(stat_text: str, *, include_start_time: bool) -> tuple[int, int, int | None]:
    """Parse the bounded identity fields from Linux ``/proc/<pid>/stat``.

    The command name is parenthesized and may itself contain ``)``, therefore
    the final closing parenthesis is the only safe delimiter.  Kernel worker
    records can expose zero group/session values; callers that only inspect a
    group member treat those as non-userspace records rather than authority.
    """

    if len(stat_text) > 8 * 1024:
        raise BrokerError("proc stat record exceeds the bounded identity limit")
    command_end = stat_text.rfind(")")
    if command_end < 0:
        raise BrokerError("proc stat omitted command terminator")
    fields = stat_text[command_end + 1 :].split()
    try:
        process_group = int(fields[2], 10)
        session_id = int(fields[3], 10)
    except (IndexError, ValueError) as error:
        raise BrokerError("proc stat omitted a valid process group/session") from error
    start_time: int | None = None
    if include_start_time:
        try:
            start_time = int(fields[19], 10)
        except (IndexError, ValueError) as error:
            raise BrokerError("proc stat omitted a valid process start time") from error
        if start_time <= 0:
            raise BrokerError("proc stat process start time is zero")
    return process_group, session_id, start_time


def _read_proc_stat(pid: int, *, include_start_time: bool) -> tuple[int, int, int | None] | None:
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as stream:
            stat_text = stream.read()
    except FileNotFoundError:
        return None
    except UnicodeError as error:
        raise BrokerError("proc stat identity probe returned non-text data") from error
    except OSError as error:
        raise BrokerError(f"proc stat identity probe failed: {error}") from error
    return _parse_proc_stat(stat_text, include_start_time=include_start_time)


def _read_boot_id_sha256() -> str:
    try:
        with open(
            "/proc/sys/kernel/random/boot_id", "r", encoding="ascii"
        ) as stream:
            boot_id = stream.read().strip()
    except UnicodeError as error:
        raise BrokerError("kernel boot identity probe returned non-ASCII data") from error
    except OSError as error:
        raise BrokerError(f"kernel boot identity probe failed: {error}") from error
    valid = (
        len(boot_id) == 36
        and all(
            (byte == "-" if index in (8, 13, 18, 23) else byte in "0123456789abcdefABCDEF")
            for index, byte in enumerate(boot_id)
        )
    )
    if not valid:
        raise BrokerError("kernel boot identity is malformed")
    return hashlib.sha256(boot_id.encode("ascii")).hexdigest()


def _capture_process_identity(pid: int) -> _ProcessIdentity:
    observed = _read_proc_stat(pid, include_start_time=True)
    if observed is None:
        raise BrokerError("upstream exited before process identity capture")
    process_group, session_id, start_time = observed
    assert start_time is not None
    # ``start_new_session=True`` is part of the broker lifecycle contract.  A
    # different PGID/SID would make a later group signal broader than the
    # exact child we spawned, so fail closed before publication.
    if process_group != pid or session_id != pid:
        raise BrokerError("upstream did not enter its own process group/session")
    return _ProcessIdentity(
        pid=pid,
        process_group=process_group,
        session_id=session_id,
        start_time_ticks=start_time,
        boot_id_sha256=_read_boot_id_sha256(),
    )


def _observe_process_identity(pid: int) -> _ProcessIdentity | None:
    observed = _read_proc_stat(pid, include_start_time=True)
    if observed is None:
        return None
    process_group, session_id, start_time = observed
    assert start_time is not None
    return _ProcessIdentity(
        pid=pid,
        process_group=process_group,
        session_id=session_id,
        start_time_ticks=start_time,
        boot_id_sha256=_read_boot_id_sha256(),
    )


def _observe_process_group_member(pid: int) -> tuple[int, int] | None:
    observed = _read_proc_stat(pid, include_start_time=False)
    if observed is None:
        return None
    process_group, session_id, _ = observed
    if process_group <= 0 or session_id <= 0:
        # Kernel worker records are not userspace members of a session.
        return None
    return process_group, session_id


def _bound_group_has_member(identity: _ProcessIdentity) -> bool:
    deadline = time.monotonic() + PROCESS_GROUP_SCAN_BUDGET_SECONDS
    try:
        entries = os.scandir("/proc")
    except OSError as error:
        raise BrokerError(f"process-group member scan failed: {error}") from error
    try:
        with entries:
            for index, entry in enumerate(entries):
                if index >= MAX_PROCESS_GROUP_SCAN_ENTRIES or time.monotonic() >= deadline:
                    raise BrokerError("process-group member scan exceeded its bounded deadline")
                if not entry.name.isdecimal():
                    continue
                try:
                    pid = int(entry.name, 10)
                except ValueError:
                    continue
                if pid == identity.pid:
                    continue
                member = _observe_process_group_member(pid)
                if member == (identity.process_group, identity.session_id):
                    return True
    except BrokerError:
        raise
    except OSError as error:
        raise BrokerError(f"process-group member scan failed: {error}") from error
    return False


def _process_group_exists(process_group: int) -> bool:
    if process_group <= 0:
        raise BrokerError("invalid process group identity")
    try:
        os.kill(-process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as error:
        raise BrokerError(f"process-group probe failed: {error}") from error
    return True


def _identity_matches(expected: _ProcessIdentity, observed: _ProcessIdentity) -> bool:
    return expected == observed


def _ensure_bound_process_group(identity: _ProcessIdentity) -> bool:
    """Prove that the captured process group still names our child tree."""

    observed = _observe_process_identity(identity.pid)
    if observed is not None:
        if not _identity_matches(identity, observed):
            raise BrokerError("upstream process identity changed before group cleanup")
        return _process_group_exists(identity.process_group)
    if not _process_group_exists(identity.process_group):
        return False
    # Once the leader is gone, a surviving member in the same PGID *and* SID
    # is the only bounded proof available.  If no member is found, refusing a
    # signal avoids killing a recycled numeric process group.
    if not _bound_group_has_member(identity):
        raise BrokerError("upstream process-group identity cannot be proven after leader exit")
    return True


def _send_bound_process_group_signal(identity: _ProcessIdentity, sig: signal.Signals) -> bool:
    if not _ensure_bound_process_group(identity):
        return False
    try:
        # ``os.kill(-pgid, sig)`` is the process-group syscall.  The negative
        # PGID comes only from the identity proof above; never use a raw PID.
        os.kill(-identity.process_group, sig)
    except ProcessLookupError:
        return False
    except OSError as error:
        raise BrokerError(f"upstream process-group signal failed: {error}") from error
    return True


def _signal_exact_child(process: subprocess.Popen[bytes], sig: signal.Signals) -> None:
    """Signal the exact unreaped ``Popen`` child as a safe fallback."""

    try:
        if process.poll() is None:
            process.send_signal(sig)
    except (OSError, ProcessLookupError):
        pass


def terminate_upstream_bounded(
    process: subprocess.Popen[bytes],
    identity: _ProcessIdentity | None,
    *,
    grace_seconds: float = UPSTREAM_TERMINATE_GRACE_SECONDS,
) -> None:
    """Terminate/reap an upstream without trusting a recycled PID/PGID.

    Group signalling is attempted only while the captured identity can be
    revalidated.  On uncertainty we signal the exact ``Popen`` child (whose
    unreaped handle cannot refer to a recycled PID), then reap for a finite
    interval.  Descendants are intentionally left untouched when their group
    identity cannot be proven.
    """

    if (
        isinstance(grace_seconds, bool)
        or not isinstance(grace_seconds, (int, float))
        or not math.isfinite(grace_seconds)
        or grace_seconds < 0
    ):
        raise ValueError("upstream cleanup grace must be a finite non-negative number")
    grace = min(float(grace_seconds), 30.0)
    group_verified = False
    group_alive = False
    if identity is not None:
        try:
            group_alive = _ensure_bound_process_group(identity)
            group_verified = True
            if group_alive:
                _send_bound_process_group_signal(identity, signal.SIGTERM)
        except BrokerError:
            # Fail closed for the group; the exact child fallback below is
            # still safe and prevents a stuck leader from wedging shutdown.
            group_verified = False
    if not group_verified:
        _signal_exact_child(process, signal.SIGTERM)

    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if group_verified:
            assert identity is not None
            try:
                group_alive = _ensure_bound_process_group(identity)
            except BrokerError:
                group_verified = False
                break
            if not group_alive:
                break
        # Do not reap a verified leader during the grace window.  Its unreaped
        # PID cannot be recycled, so every subsequent /proc check remains tied
        # to the captured generation.  If the group proof is unavailable, the
        # exact child fallback is safe and polling it is the only way to stop
        # waiting early.
        if not group_verified and process.poll() is not None:
            break
        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))

    if group_verified and group_alive:
        assert identity is not None
        try:
            _send_bound_process_group_signal(identity, signal.SIGKILL)
        except BrokerError:
            pass
    _signal_exact_child(process, signal.SIGKILL)
    try:
        process.wait(timeout=max(1.0, grace + 1.0))
    except (OSError, subprocess.TimeoutExpired):
        # The caller is on a shutdown/error path; never turn a stubborn child
        # into an unbounded broker hang.  The process remains untrusted and no
        # further group signal is attempted.
        pass


class BrokerBase:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.token = load_or_create_token(args.token_file)
        self.token_epoch = hashlib.sha256(self.token.encode("ascii")).hexdigest()[:32]
        self.broker_epoch = secrets.token_hex(16)
        self.clients: dict[str, Client] = {}
        self.clients_lock = threading.Lock()
        self.request_slots = threading.BoundedSemaphore(args.max_pending_requests)
        self.mux = WeightedFairMux(
            max_pending=args.max_pending_requests,
            max_inflight=args.max_inflight_requests,
            max_retired=args.max_retired_requests,
            owner_weights=args.client_weights,
        )
        self.admission_lock = threading.Lock()
        self.sequence_lock = threading.Lock()
        # One transition lock orders pipe write -> durable forwarded record ->
        # terminal record.  It is never held while waiting for a Host result.
        self.transition_lock = threading.RLock()
        self.stopping = threading.Event()
        self.upstream_uncertain = threading.Event()
        self.unknown_lock = threading.Lock()
        self.upstream_stderr = bytearray()
        self.upstream_stderr_lock = threading.Lock()
        self.upstream_argv = [str(args.upstream), *args.upstream_arg]
        validate_argv(self.upstream_argv)
        self.upstream_identity = validate_executable(args.upstream, "--upstream")
        self.audit = BrokerAuditJournal(args.audit_file, broker_id=args.broker_id)
        self.next_upstream_seq = self.audit.next_upstream_seq
        self.upstream: subprocess.Popen[bytes] | None = None
        self.host_hello_ack: dict[str, Any] | None = None
        self.descriptor: dict[str, Any] | None = None
        self.listener: socket.socket | None = None
        self.socket_identity: tuple[int, int] | None = None
        self.socket_fd_identity: tuple[int, int] | None = None
        self.descriptor_identity: tuple[int, int] | None = None
        self.upstream_process_identity: _ProcessIdentity | None = None
        self.worker_threads: list[threading.Thread] = []

    def _start_upstream(self) -> None:
        # Keep the validated inode pinned through exec.  Re-validating the
        # pathname and then passing it directly to Popen leaves a replacement
        # or symlink-swap window between those two operations.  Linux's
        # proc-fd spelling resolves the descriptor inherited by the child, so
        # startup cannot be redirected to a different executable inode.
        descriptor, _identity = open_validated_executable(
            self.args.upstream,
            "--upstream",
            expected_identity=self.upstream_identity,
        )
        try:
            proc_fd_path = f"/proc/self/fd/{descriptor}"
            try:
                os.readlink(proc_fd_path)
            except OSError as error:
                raise BrokerError(
                    "validated upstream startup requires an available /proc/self/fd"
                ) from error
            upstream = subprocess.Popen(
                self.upstream_argv,
                executable=proc_fd_path,
                pass_fds=(descriptor,),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                bufsize=0,
            )
        finally:
            # The child receives its own copy via pass_fds; the broker need
            # not retain the validation descriptor after fork/exec setup.
            os.close(descriptor)
        self.upstream = upstream
        try:
            self.upstream_process_identity = _capture_process_identity(upstream.pid)
        except (BrokerError, OSError) as error:
            terminate_upstream_bounded(upstream, None)
            self.upstream = None
            raise BrokerError(f"upstream process identity capture failed: {error}") from error
        if upstream.stdin is None or upstream.stdout is None or upstream.stderr is None:
            terminate_upstream_bounded(upstream, self.upstream_process_identity)
            self.upstream = None
            self.upstream_process_identity = None
            raise BrokerError("upstream standard streams were not piped")
        stderr_thread = threading.Thread(
            target=self._drain_stderr,
            daemon=True,
            name="broker-upstream-stderr",
        )
        stderr_thread.start()
        self.worker_threads.append(stderr_thread)
        self.host_hello_ack = self._handshake()

    def _drain_stderr(self) -> None:
        upstream = self.upstream
        if upstream is None or upstream.stderr is None:
            return
        while not self.stopping.is_set():
            try:
                chunk = upstream.stderr.read(8192)
            except OSError:
                return
            if not chunk:
                return
            with self.upstream_stderr_lock:
                remaining = 1024 * 1024 - len(self.upstream_stderr)
                self.upstream_stderr.extend(chunk[: max(0, remaining)])

    def _handshake(self) -> dict[str, Any]:
        upstream = self.upstream
        if upstream is None or upstream.stdin is None or upstream.stdout is None:
            raise BrokerError("upstream is not available for handshake")
        request = {
            "kind": "hello",
            "seq": 0,
            "direction": "client_to_host",
            "payload": {
                "protocol": "trillionnium.agent.turn.v1",
                "protocol_version": 1,
            },
        }
        write_all_bounded(
            upstream.stdin,
            canonical(request) + b"\n",
            timeout_seconds=BROKER_WRITE_TIMEOUT_SECONDS,
            label="upstream hello",
        )
        raw = read_line(upstream.stdout, label="upstream hello")
        if raw is None:
            raise BrokerError("upstream exited before hello.ack")
        value = strict_json(raw, label="upstream hello")
        if not isinstance(value, dict) or value.get("kind") != "hello.ack":
            raise BrokerError("upstream first response is not hello.ack")
        return value

    def _build_descriptor(self) -> dict[str, Any]:
        if self.host_hello_ack is None:
            raise BrokerError("cannot build descriptor before Host handshake")
        return finalize_descriptor(
            {
                "schema": SCHEMA,
                "broker_id": self.args.broker_id,
                "broker_epoch": self.broker_epoch,
                "token_epoch": self.token_epoch,
                "socket_path": str(self.args.socket),
                "token_file": str(self.args.token_file),
                "audit_file": str(self.args.audit_file),
                "audit_status": "durable_fsync_hash_chain",
                "service_uid": os.geteuid(),
                "trust_domain": "same_euid_and_private_token_not_same_uid_process_isolation",
                "response_model": "broker_correlated_result_owner_with_broadcast_observation",
                "scheduler_version": 2,
                "scheduler": {
                    "kind": "bounded_weighted_round_robin",
                    "per_ordering_key_serialization": True,
                    # Identity is canonicalized by ordering_key_for_frame:
                    # known families require the complete immutable scope and
                    # reject partial/inconsistent aliases.  Operation and
                    # attachment ids are validated but do not split one job's
                    # serialization fence.
                    "ordering_key_identity": {
                        "scope": [
                            "session_id",
                            "profile_id",
                            "task_id",
                            "turn_id",
                            "turn_stream_id",
                        ],
                        "families": {
                            "job": ["job_id"],
                            "turn": ["turn_id"],
                            "call": ["call_id"],
                        },
                        "aliases": ["stream_id -> turn_stream_id"],
                        "partial_identity": "reject",
                    },
                    "late_result_isolation": "bounded_retired_upstream_sequence_tombstones",
                },
                "max_clients": self.args.max_clients,
                "client_queue_frames": self.args.client_queue_frames,
                "client_queue_bytes": self.args.client_queue_bytes,
                "max_pending_requests": self.args.max_pending_requests,
                "max_inflight_requests": self.args.max_inflight_requests,
                "max_retired_requests": self.args.max_retired_requests,
                "client_weights": self.args.client_weights,
                "request_audit_stages": [
                    "broker.accepted",
                    "broker.forwarded",
                    "broker.terminal",
                ],
                "upstream": self.upstream_identity,
                "upstream_argv_sha256": hashlib.sha256(
                    canonical(self.upstream_argv)
                ).hexdigest(),
                "host_hello_ack": self.host_hello_ack,
                "automatic_redispatch": False,
            }
        )

    def _owner(self, owner_id: str, value: dict[str, Any]) -> None:
        with self.clients_lock:
            client = self.clients.get(owner_id)
        if client is not None and not client.enqueue(value):
            self._remove_client(client)

    def _broadcast(self, value: dict[str, Any]) -> None:
        with self.clients_lock:
            clients = list(self.clients.items())
        dead = [client for _client_id, client in clients if not client.enqueue(value)]
        for client in dead:
            self._remove_client(client)

    def _remove_client(self, client: Client) -> bool:
        """Remove one exact client instance without evicting a replacement."""

        with self.clients_lock:
            if self.clients.get(client.client_id) is not client:
                return False
            self.clients.pop(client.client_id, None)
        client.close()
        return True

    def _remove(self, client_id: str) -> None:
        with self.clients_lock:
            client = self.clients.pop(client_id, None)
        if client:
            client.close()

    def _correlation_payload(self, request: Request) -> dict[str, Any]:
        return {
            "broker_epoch": self.broker_epoch,
            "broker_response_connection_id": request.owner_id,
            "broker_request_id": request.request_id,
            "broker_request_upstream_seq": request.upstream_seq,
            "broker_request_downstream_seq": request.client_seq,
            "broker_request_kind": request.frame["kind"],
            "broker_request_sha256": request.request_sha256,
            "broker_ordering_key": request.ordering_key,
        }

    def _result(self, request: Request, frame: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema": WIRE,
            "kind": "result",
            "request_id": request.request_id,
            **self._correlation_payload(request),
            "frame": frame,
            "automatic_redispatch": False,
        }

    @staticmethod
    def _error(request_id: str | None, code: str, message: str) -> dict[str, Any]:
        return {
            "schema": WIRE,
            "kind": "error",
            "request_id": request_id,
            "code": code,
            "message": message,
            "automatic_redispatch": False,
        }

    def _request_error(
        self,
        request: Request,
        code: str,
        message: str,
    ) -> dict[str, Any]:
        return {
            **self._error(request.request_id, code, message),
            **self._correlation_payload(request),
        }
