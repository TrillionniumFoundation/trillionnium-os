#!/usr/bin/env python3
"""Rootfs-only client. Real native shell.exec launches this process.
No request is automatically retried. A killed client closes its Unix socket;
the Android sidecar cancels and joins its one owned effect process group.
"""
import argparse, base64, hashlib, json, os, re, socket, struct, sys, time
from pathlib import Path
PROTOCOL = "hepta_phone_local_v150"
MAX_RESPONSE = 12 * 1024 * 1024
MAX_OUTPUT = 8 * 1024 * 1024
ALLOWED_SERVER_UIDS = (0, 2000)

def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

def _recv_exact(sock, count):
    chunks = []
    while count:
        part = sock.recv(count)
        if not part:
            raise ConnectionError("peer_closed_before_complete_response")
        chunks.append(part)
        count -= len(part)
    return b"".join(chunks)

def request(payload, socket_name=PROTOCOL, timeout_s=70.0):
    raw = _json_bytes(payload)
    if len(raw) > 262144:
        raise ValueError("request_size_limit")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout_s)
        sock.connect("\0" + socket_name)
        peer = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        peer_pid, peer_uid, peer_gid = struct.unpack("3i", peer)
        if peer_uid not in ALLOWED_SERVER_UIDS:
            raise PermissionError("sidecar_peer_uid_denied")
        sock.sendall(struct.pack(">I", len(raw)) + raw)
        size = struct.unpack(">I", _recv_exact(sock, 4))[0]
        if not 0 < size <= MAX_RESPONSE:
            raise ValueError("response_size_limit")
        result = json.loads(_recv_exact(sock, size).decode("utf-8"))
    if result.get("version") != 1 or result.get("protocol") != PROTOCOL:
        raise ValueError("response_protocol_mismatch")
    return result

def inspect(action_id, command_sha256="", include_output=False, socket_name=PROTOCOL):
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

def execute(command, action_id, timeout_ms=60000, socket_name=PROTOCOL, receipt_dir=None):
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
            "timeout_ms": timeout_ms, "state": "intent", "created_unix_ms": int(time.time()*1000)}
    try:
        fd = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
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
    try:
        result = request(payload, socket_name, timeout_ms / 1000 + 12)
    except (OSError, ValueError, UnicodeError, ConnectionError) as exc:
        meta.update(state="indeterminate", error=type(exc).__name__ + ":" + str(exc),
                    can_redispatch=False)
        _atomic(root / (action_id + ".result.json"), meta)
        _error("transport_indeterminate_no_retry", action_id, meta)
        return 71
    # Persist full returned receipt before interpretation, without raw user output duplication.
    saved = {k: v for k, v in result.items() if k not in ("stdout_b64", "stderr_b64")}
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
    if r.get("state") == "completed" and r.get("waitpid_joined") is True and r.get("process_group_absent") is True:
        code = r.get("exit_code")
        if isinstance(code, int) and 0 <= code <= 255:
            return code
    _error("effect_terminal_failure", action_id, r)
    return {"timed_out": 72, "cancelled": 73, "output_limit_exceeded": 74}.get(r.get("state"), 75)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket-name", default=PROTOCOL)
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
        _error(type(exc).__name__ + ":" + str(exc), getattr(args, "action_id", None))
        return 70

if __name__ == "__main__":
    raise SystemExit(main())
