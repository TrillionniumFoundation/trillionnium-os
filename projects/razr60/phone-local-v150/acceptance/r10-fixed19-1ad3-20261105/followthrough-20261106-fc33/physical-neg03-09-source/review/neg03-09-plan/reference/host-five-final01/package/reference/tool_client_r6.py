#!/usr/bin/env python3
"""R6 rootfs client with exclusive transport phases and exact executor domain.
Real native shell.exec launches this process.
No request is automatically retried. A killed client closes its Unix socket;
the Android sidecar cancels and joins its one owned effect process group.
"""
import argparse, base64, errno, hashlib, json, os, re, socket, struct, sys, time
from pathlib import Path
PROTOCOL = "hepta_phone_local_v150"
DEFAULT_SOCKET_NAME = "hepta_phone_executor_v150_r6"
EXPECTED_SERVER_CONTEXT = "u:r:trillionnium_owner_open_phone_executor:s0"
EXPECTED_WORKER_CONTEXT = "u:r:trillionnium_owner_open_phone_worker:s0"
EXPECTED_EXECUTE_CALLER_CONTEXT = "u:r:trillionnium_owner_open_bootstrap:s0"
CLIENT_REVISION = 6
MAX_RESPONSE = 12 * 1024 * 1024
MAX_OUTPUT = 8 * 1024 * 1024
ALLOWED_SERVER_UIDS = (0,)

def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

class TransportTrace:
    """Exclusive durable phases. A phase is evidence, never retry authority."""
    def __init__(self, root, meta, socket_name):
        self.directory = root / (meta["action_id"] + ".transport-r6")
        self.directory.mkdir(mode=0o700, exist_ok=False)
        parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self.binding = {"schema": "hepta.client-transport-event.v150.r6",
            "client_revision": CLIENT_REVISION, "action_id": meta["action_id"],
            "command_sha256": meta["command_sha256"], "client_pid": os.getpid(),
            "client_source_sha256": meta["client_source_sha256"],
            "endpoint": socket_name, "automatic_replay": False}
        self.events = []
        self.previous = None
        self.progress = {}
        self.event("claim_durable_before_transport", {})

    def event(self, phase, progress):
        if len(self.events) >= 32:
            raise ValueError("transport_event_bound")
        self.progress = dict(progress)
        number = len(self.events)
        name = "%02d-%s.json" % (number, phase)
        value = {**self.binding, "sequence": number, "phase": phase,
                 "created_unix_ms": int(time.time() * 1000),
                 "monotonic_ns": time.monotonic_ns(),
                 "previous_event_sha256": self.previous,
                 "transport": self.progress}
        raw = _json_bytes(value)
        fd = os.open(self.directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        self.previous = hashlib.sha256(raw).hexdigest()
        self.events.append({"name": name, "sha256": self.previous, "bytes": len(raw)})

    def summary(self):
        return {"schema": "hepta.client-transport-trace.v150.r6",
                "directory": str(self.directory), "events": list(self.events),
                "last_event_sha256": self.previous, "transport": dict(self.progress),
                "automatic_replay": False}

def request(payload, socket_name=DEFAULT_SOCKET_NAME, timeout_s=70.0, trace=None):
    if socket_name != DEFAULT_SOCKET_NAME:
        raise ValueError("r6_endpoint_pin_mismatch_no_fallback")
    raw = _json_bytes(payload)
    if len(raw) > 262144:
        raise ValueError("request_size_limit")
    wire = struct.pack(">I", len(raw)) + raw
    deadline = time.monotonic() + timeout_s
    progress = {"operation": payload.get("op"), "phase": "prepared",
                "endpoint": socket_name, "payload_sha256": hashlib.sha256(raw).hexdigest(),
                "request_frame_sha256": hashlib.sha256(wire).hexdigest(),
                "request_frame_bytes": len(wire), "confirmed_send_bytes": 0,
                "confirmed_receive_bytes": 0, "response_body_bytes": None,
                "connected": False, "peer_identity_verified": False,
                "send_attempted": False, "request_frame_complete": False,
                "response_frame_complete": False, "automatic_replay": False}
    def mark(phase, **updates):
        progress.update(updates)
        progress["phase"] = phase
        if trace is not None:
            trace.event(phase, progress)
    def remaining(sock):
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("whole_transport_deadline")
        sock.settimeout(seconds)
    def recv_exact(sock, count):
        pieces = []
        while count:
            remaining(sock)
            part = sock.recv(count)
            if not part:
                raise ConnectionError("peer_closed_before_complete_response")
            pieces.append(part)
            count -= len(part)
            progress["confirmed_receive_bytes"] += len(part)
        return b"".join(pieces)
    try:
        mark("socket_create_attempt")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            mark("socket_created")
            remaining(sock)
            mark("connect_attempt")
            sock.connect("\0" + socket_name)
            mark("connected", connected=True)
            mark("peer_identity_query")
            peer_pid, peer_uid, peer_gid = struct.unpack(
                "3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            context = sock.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERSEC", 31), 256).rstrip(b"\0\n").decode("ascii")
            progress.update(peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid, peer_context=context)
            if peer_uid != 0 or peer_gid != 0 or context != EXPECTED_SERVER_CONTEXT:
                raise PermissionError(errno.EACCES, "r6_sidecar_peer_identity_denied_before_send")
            mark("peer_verified", peer_identity_verified=True)
            # This durable fence precedes the first send syscall. Any failure
            # from here onward is conservatively dispatch-possible, even if no
            # positive byte count is retained.
            mark("request_send_begin", send_attempted=True)
            view = memoryview(wire)
            while view:
                remaining(sock)
                count = sock.send(view)
                if count <= 0:
                    raise ConnectionError("request_send_incomplete")
                progress["confirmed_send_bytes"] += count
                view = view[count:]
            mark("request_sent", request_frame_complete=True)
            mark("response_header_begin")
            size = struct.unpack(">I", recv_exact(sock, 4))[0]
            if not 0 < size <= MAX_RESPONSE:
                raise ValueError("response_size_limit")
            mark("response_header_received", response_body_bytes=size)
            mark("response_body_begin")
            body = recv_exact(sock, size)
            mark("response_received", response_frame_complete=True,
                 response_body_sha256=hashlib.sha256(body).hexdigest())
            result = json.loads(body.decode("utf-8"))
            if (not isinstance(result, dict) or result.get("version") != 1
                    or result.get("protocol") != PROTOCOL):
                raise ValueError("response_protocol_mismatch")
            mark("response_validated")
        mark("transport_complete", request_may_have_reached_executor=bool(progress["send_attempted"]))
        return result
    except (OSError, ValueError, UnicodeError, ConnectionError) as exc:
        # Preserve the actual syscall/protocol phase and byte counters. No error
        # here grants replay, supplies a sidecar terminal, or claims business.
        failing_phase = progress["phase"]
        progress.update(error_type=type(exc).__name__, error=str(exc),
                        errno=getattr(exc, "errno", None), failed_phase=failing_phase,
                        request_may_have_reached_executor=bool(progress["send_attempted"]),
                        request_definitely_not_sent=not progress["send_attempted"])
        try:
            mark("transport_failure")
        except (OSError, ValueError) as phase_error:
            progress["phase_persistence_error"] = type(phase_error).__name__ + ":" + str(phase_error)
            if trace is not None:
                trace.progress = dict(progress)
        exc.hepta_transport = dict(progress)
        raise

def inspect(action_id, command_sha256="", include_output=False, socket_name=DEFAULT_SOCKET_NAME):
    return request({"version": 1, "op": "inspect", "action_id": action_id,
                    "command_sha256": command_sha256, "include_output": include_output},
                   socket_name, 10.0)

def _atomic(path, obj):
    data = _json_bytes(obj)
    temp = path.with_name(path.name + ".tmp." + str(os.getpid()))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass

def _emit_raw(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]

def _error(kind, action_id, receipt=None):
    record = {"client_error": kind, "action_id": action_id}
    if receipt is not None:
        record["receipt"] = receipt
    _emit_raw(2, b"\nHEPTA_PHONE_LOCAL " + _json_bytes(record) + b"\n")

def execute(command, action_id, timeout_ms=60000, socket_name=DEFAULT_SOCKET_NAME, receipt_dir=None):
    if not re.fullmatch(r"[0-9a-f]{32}", action_id):
        raise ValueError("invalid_action_id")
    raw = command.encode("utf-8")
    if not raw or len(raw) > 131072 or "\0" in command or not 1 <= timeout_ms <= 60000:
        raise ValueError("invalid_command_or_timeout")
    sha = hashlib.sha256(raw).hexdigest()
    root = Path(receipt_dir) if receipt_dir else Path(__file__).resolve().parent / "client-receipts"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink():
        raise ValueError("receipt_directory_is_symlink")
    claim = root / (action_id + ".claim.json")
    meta = {"version": 1, "action_id": action_id, "command_sha256": sha,
            "timeout_ms": timeout_ms, "state": "intent", "created_unix_ms": int(time.time()*1000),
            "client_revision": CLIENT_REVISION, "endpoint": socket_name,
            "client_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    try:
        fd = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        # Legacy claims belong to their original executor, never the new r6
        # namespace. No old claim is edited or retargeted to make a fresh call.
        original = json.loads(claim.read_bytes())
        if (original.get("action_id") != action_id or original.get("command_sha256") != sha
                or original.get("client_revision") != CLIENT_REVISION
                or original.get("endpoint") != DEFAULT_SOCKET_NAME):
            _error("duplicate_action_retained_original_executor_inspection_required", action_id,
                   {"can_redispatch": False, "claim_unchanged": True})
            return 76
        result = inspect(action_id, sha, False, socket_name)
        _atomic(root / (action_id + ".last-inspect.json"), result)
        _error("duplicate_action_inspect_only", action_id, result.get("receipt", result))
        return 76
    with os.fdopen(fd, "wb") as out:
        out.write(_json_bytes(meta));out.flush();os.fsync(out.fileno())
    dfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    payload = {"version": 1, "op": "execute", "action_id": action_id,
               "command_sha256": sha, "command": command, "timeout_ms": timeout_ms}
    trace = TransportTrace(root, meta, socket_name)
    try:
        result = request(payload, socket_name, timeout_ms / 1000 + 12, trace)
    except (OSError, ValueError, UnicodeError, ConnectionError) as exc:
        meta.update(state="indeterminate", error=type(exc).__name__ + ":" + str(exc),
                    can_redispatch=False, client_transport=trace.summary())
        _atomic(root / (action_id + ".result.json"), meta)
        _error("transport_indeterminate_no_retry", action_id, meta)
        return 71
    # Persist full returned receipt before interpretation, without raw user output duplication.
    saved = {k: v for k, v in result.items() if k not in ("stdout_b64", "stderr_b64")}
    saved["client_transport"] = trace.summary()
    _atomic(root / (action_id + ".result.json"), saved)
    r = result.get("receipt", {})
    if result.get("duplicate"):
        _error("duplicate_action_inspect_only", action_id, r);return 76
    if (r.get("action_id") != action_id or r.get("command_sha256") not in (None, sha) or
        (r.get("terminal") and r.get("command_sha256") != sha)):
        _error("response_action_binding_mismatch", action_id, r);return 70
    if not r.get("terminal"):
        _error("effect_not_terminal", action_id, r or result)
        return 77 if r.get("state") == "busy" else 75
    try:
        stdout = base64.b64decode(result["stdout_b64"], validate=True)
        stderr = base64.b64decode(result["stderr_b64"], validate=True)
        if (len(stdout) + len(stderr) > MAX_OUTPUT or
            len(stdout) != r["stdout_bytes"] or len(stderr) != r["stderr_bytes"] or
            hashlib.sha256(stdout).hexdigest() != r["stdout_sha256"] or
            hashlib.sha256(stderr).hexdigest() != r["stderr_sha256"]):
            raise ValueError("output_integrity_mismatch")
    except (KeyError, ValueError) as exc:
        _error("output_integrity_mismatch", action_id, r);return 70
    _emit_raw(1, stdout);_emit_raw(2, stderr)
    if (r.get("state") == "completed" and r.get("terminal") is True
            and r.get("executor_revision") == 6
            and r.get("executor_context") == EXPECTED_SERVER_CONTEXT
            and r.get("peer_context") == EXPECTED_EXECUTE_CALLER_CONTEXT
            and r.get("execution_credentials_scope") == "android_shell_uid2000"
            and r.get("required_execution_uid") == 2000 and r.get("required_execution_gid") == 2000
            and r.get("handshake_stage") == "worker_entry_after_exec_transition"
            and type(r.get("dispatch_count")) is int and r["dispatch_count"] == 1
            and type(r.get("pid")) is int and r["pid"] > 1 and r.get("pgid") == r["pid"]
            and r.get("waitpid_identity_lost") is False
            and r.get("effect_started") is True
            and r.get("process_group_established") is True
            and r.get("waitpid_joined") is True and r.get("process_group_absent") is True
            and r.get("execution_credentials_verified") is True
            and all(r.get(key) == 2000 for key in ("execution_uid", "execution_euid", "execution_gid", "execution_egid"))
            and r.get("supplementary_groups_cleared") is True
            and r.get("execution_supplementary_group_count") == 0
            and r.get("worker_domain_verified") is True
            and r.get("execution_context") == EXPECTED_WORKER_CONTEXT):
        code = r.get("exit_code")
        if type(code) is int and 0 <= code <= 255:
            return code
    _error("effect_terminal_failure", action_id, r)
    return {"timed_out": 72, "cancelled": 73, "output_limit_exceeded": 74}.get(r.get("state"), 75)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket-name", default=DEFAULT_SOCKET_NAME)
    subs = parser.add_subparsers(dest="operation", required=True)
    ex = subs.add_parser("execute")
    ex.add_argument("--action-id", required=True)
    ex.add_argument("--command-b64", required=True)
    ex.add_argument("--timeout-ms", type=int, default=60000)
    ex.add_argument("--receipt-dir")
    ins = subs.add_parser("inspect")
    ins.add_argument("--action-id", required=True)
    ins.add_argument("--command-sha256", default="")
    ins.add_argument("--include-output", action="store_true")
    subs.add_parser("health")
    args = parser.parse_args()
    try:
        if args.operation == "execute":
            command = base64.b64decode(args.command_b64, validate=True).decode("utf-8")
            return execute(command, args.action_id, args.timeout_ms, args.socket_name, args.receipt_dir)
        if args.operation == "inspect":
            result = inspect(args.action_id, args.command_sha256, args.include_output, args.socket_name)
        else:
            result = request({"version": 1, "op": "health"}, args.socket_name, 10)
        _emit_raw(1, _json_bytes(result) + b"\n")
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        _error(type(exc).__name__ + ":" + str(exc), getattr(args, "action_id", None), getattr(exc, "hepta_transport", None))
        return 70

if __name__ == "__main__":
    raise SystemExit(main())
