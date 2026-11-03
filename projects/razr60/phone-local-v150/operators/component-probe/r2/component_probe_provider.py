#!/usr/bin/env python3
"""One-use native component probe; no model, UI automation, direct execution or replay.

The only emitted tool is a fixed printf nonce, admitted/executed by the existing
native shell.exec path. This provider performs only read-only executor health
and original-receipt inspection. Native turn.end and journal verification remain
an independent operator gate, not an assertion made by this process.
"""
import argparse
import base64
import fcntl
import hashlib
import types
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import time
import uuid

PROTOCOL = "trillionnium.owner-open.provider-jsonl.v1"
STATE = Path("/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6")
CLIENT = Path("/var/lib/trillionnium/owner-open/phone-local-v150/tool_client_r6.py")
CLIENT_SHA = "500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f"
PARENT_SHA = "8595f99cf8d0f39ec2a45f85f1250745c158ea504d2d0520cd83791f28bdb976"
WORKER_SHA = "49fb74f8798194c63d5e510c0ed81604d64a55e1df84822d9457ae4110cab6da"
POLICY_RULE_SHA = "7011fc8b0e4629a05bdd9739d168cdcba9b43044e54e0cdadb6da5f5bb876381"
PATCHED_POLICY_SHA = "67ee1d75606e42e8b95c91faa57f7a22a5070e177cd6cc82552308f3de2b25d0"
SOCKET = "hepta_phone_executor_v150_r6"
PARENT_CONTEXT = "u:r:trillionnium_owner_open_phone_executor:s0"
WORKER_CONTEXT = "u:r:trillionnium_owner_open_phone_worker:s0"
BOOTSTRAP_CONTEXT = "u:r:trillionnium_owner_open_bootstrap:s0"
MAGISK_CONTEXT = "u:r:magisk:s0"
JOURNAL = "/data/trillionnium/owner-open/state/phone-local-v150/executor-r6-component-01"
KEYS = ("session_id", "profile_id", "task_id", "turn_id", "turn_stream_id")
MAX_FRAME = 65536
SERVICE_SECONDS = 70
TURN_SECONDS = 25
TOOL_TIMEOUT_MS = 3000
NATIVE_TIMEOUT_MS = 15000
SCOPE = "native executor component only; zero model requests and zero business UI effects; HEPTA task-entry UI counted separately"

class Rejected(RuntimeError):
    pass

def require(ok, message):
    if not ok:
        raise Rejected(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()

def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Rejected("nonfinite_json")))
    require(isinstance(value, dict), "json_object_required")
    return value

def identifier(value, maximum=256):
    return isinstance(value, str) and 0 < len(value.encode()) <= maximum and "\0" not in value

def hex_string(value, length):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None

def owner_request(nonce):
    require(hex_string(nonce, 32), "nonce_shape")
    return ("执行一次手机本地执行器组件资格探针，标记 " + nonce +
            "。只通过原生工具通道输出该新标记一次；不调用模型，不操作任何 App，不重放旧动作。")

def fixed_command(nonce):
    require(hex_string(nonce, 32), "nonce_shape")
    return "printf '%s\\n' 'hepta_executor_component_" + nonce + "'"

def expected_output(nonce):
    return ("hepta_executor_component_" + nonce + "\n").encode("ascii")

def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def private_dir(path):
    require(path.is_absolute() and path.parent.resolve() == path.parent, "canonical_parent_required")
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "private_directory_identity")
    sync_dir(path.parent)

def create(path, value):
    raw = encode(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as out:
            out.write(raw)
            out.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    sync_dir(path.parent)
    return sha(raw)

def read_file(path, limit, expected=None):
    require(path.is_absolute() and path.parent.resolve() == path.parent, "canonical_file_parent")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.getuid() and not before.st_mode & 0o022
                and before.st_size <= limit, "file_identity_or_bound")
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    require(len(raw) <= limit and all(getattr(before, k) == getattr(after, k) for k in fields),
            "file_changed_or_oversized")
    raw = bytes(raw)
    require(expected is None or sha(raw) == expected, "file_sha256_mismatch")
    return raw

def validate_contract(c):
    names = {"schema", "nonce", "owner_request_sha256", "selected_session_id", "selected_profile_id",
             "executor_server_instance", "executor_journal", "endpoint", "client_sha256",
             "parent_sha256", "worker_sha256", "policy_rule_sha256", "patched_policy_sha256",
             "retirement_proof_sha256", "retirement_resolution_sha256", "provider_source_sha256",
             "expires_unix_ms", "scope"}
    require(set(c) == names and c["schema"] == "hepta.native-component-probe.contract.v150.r6.1",
            "contract_schema")
    require(hex_string(c["nonce"], 32) and hex_string(c["executor_server_instance"], 32), "contract_nonce_instance")
    require(c["owner_request_sha256"] == sha(owner_request(c["nonce"]).encode()), "contract_owner_bytes")
    require(identifier(c["selected_session_id"]) and identifier(c["selected_profile_id"]), "contract_selection")
    expected = {"executor_journal": JOURNAL, "endpoint": SOCKET, "client_sha256": CLIENT_SHA,
                "parent_sha256": PARENT_SHA, "worker_sha256": WORKER_SHA,
                "policy_rule_sha256": POLICY_RULE_SHA, "patched_policy_sha256": PATCHED_POLICY_SHA,
                "scope": SCOPE}
    require(all(c[k] == v for k, v in expected.items()), "contract_frozen_input_binding")
    require(all(hex_string(c[k], 64) for k in ("retirement_proof_sha256",
                "retirement_resolution_sha256", "provider_source_sha256")), "contract_proof_shape")
    require(type(c["expires_unix_ms"]) is int, "contract_expiry_type")
    return c

def verify_health(value, c):
    require(value.get("version") == 1 and value.get("protocol") == "hepta_phone_local_v150"
            and value.get("state") == "ready" and value.get("executor_revision") == 6
            and value.get("server_instance") == c["executor_server_instance"]
            and value.get("executor_context") == PARENT_CONTEXT
            and value.get("required_worker_context") == WORKER_CONTEXT
            and value.get("peer_context") == MAGISK_CONTEXT
            and value.get("execute_authorized") is False, "readonly_health_identity_or_recovery")
    # Magisk health authorization is deliberately not execution qualification.

def validate_start(value, c):
    require(set(value) == {"protocol", "seq", "kind", "turn"}, "start_envelope_shape")
    turn = value.get("turn")
    require(isinstance(turn, dict) and set(turn) == set(KEYS) | {"user_input"}, "turn_shape")
    require(all(identifier(turn.get(k)) for k in KEYS), "turn_scope")
    require(turn["session_id"] == c["selected_session_id"]
            and turn["profile_id"] == c["selected_profile_id"], "selected_session_profile_mismatch")
    require(turn["user_input"] == owner_request(c["nonce"])
            and sha(turn["user_input"].encode()) == c["owner_request_sha256"], "exact_owner_request_mismatch")
    require(int(time.time() * 1000) <= c["expires_unix_ms"], "contract_expired")
    scope = {k: turn[k] for k in KEYS}
    action = sha(encode({"scope": scope, "nonce": c["nonce"],
                         "owner_request_sha256": c["owner_request_sha256"]}))[:32]
    return scope, action

def native_output(value, call_id, expected):
    require(value.get("kind") == "tool.result" and value.get("call_id") == call_id
            and value.get("status") == "terminal", "native_result_not_terminal")
    terminal = value.get("terminal")
    require(isinstance(terminal, dict) and terminal.get("kind") == "exited"
            and type(terminal.get("exit_code")) is int and terminal["exit_code"] == 0
            and terminal.get("signal") is None and terminal.get("output_truncated") is False
            and terminal.get("error") is None,
            "native_exit_not_complete")
    rows = value.get("events")
    require(isinstance(rows, list) and 3 <= len(rows) <= 32, "native_event_bound")
    output = {"stdout": bytearray(), "stderr": bytearray()}
    kinds = []
    for number, row in enumerate(rows):
        require(isinstance(row, dict) and row.get("call_id") == call_id
                and row.get("tool") == "shell.exec" and type(row.get("seq")) is int
                and row["seq"] == number, "native_event_binding_sequence")
        event = row.get("event", {})
        kind = event.get("kind")
        kinds.append(kind)
        if kind == "output":
            stream = event.get("stream")
            require(stream in output and event.get("encoding") == "base64", "native_output_stream")
            raw = base64.b64decode(event["data"], validate=True)
            require(type(event.get("byte_count")) is int and event["byte_count"] == len(raw),
                    "native_output_byte_count")
            output[stream].extend(raw)
            require(sum(len(x) for x in output.values()) <= 4096, "native_output_bound")
        elif kind == "terminal":
            require(number == len(rows)-1 and event.get("terminal") == terminal, "native_terminal_event")
        elif kind == "started":
            require(type(event.get("pid")) is int and event["pid"] > 1, "native_started_pid")
        else:
            require(kind == "accepted", "native_unexpected_event")
    require(kinds[0] == "accepted" and kinds.count("accepted") == 1
            and kinds[1] == "started" and kinds.count("started") == 1
            and kinds[-1] == "terminal" and kinds.count("terminal") == 1, "native_lifecycle_order")
    require(bytes(output["stdout"]) == expected and not output["stderr"], "native_marker_not_exact")
    require(type(terminal.get("stdout_bytes")) is int and terminal["stdout_bytes"] == len(expected)
            and type(terminal.get("stderr_bytes")) is int and terminal["stderr_bytes"] == 0,
            "native_terminal_byte_count")
    registry = value.get("registry", {})
    require(registry.get("call_id") == call_id and registry.get("tool") == "shell.exec"
            and isinstance(registry.get("state"), str) and registry["state"].startswith("Terminal {")
            and registry.get("cancellation_requested") is False
            and registry.get("connection_lost") is False, "native_registry_not_confirmed")
    return {"stdout_sha256": sha(expected), "stdout_bytes": len(expected),
            "stderr_sha256": sha(b""), "stderr_bytes": 0, "native_exit_code": 0}

def verify_receipt(value, c, action_id, command_sha, expected):
    require(value.get("version") == 1 and value.get("protocol") == "hepta_phone_local_v150",
            "inspect_protocol")
    r = value.get("receipt", {})
    exact = {"action_id": action_id, "command_sha256": command_sha,
             "state": "completed", "terminal": True, "server_instance": c["executor_server_instance"],
             "executor_revision": 6, "executor_context": PARENT_CONTEXT, "peer_context": BOOTSTRAP_CONTEXT,
             "execution_credentials_scope": "android_shell_uid2000",
             "required_execution_uid": 2000, "required_execution_gid": 2000,
             "handshake_stage": "worker_entry_after_exec_transition",
             "execution_context": WORKER_CONTEXT, "stdout_sha256": sha(expected),
             "stderr_sha256": sha(b""), "stdout_bytes": len(expected), "stderr_bytes": 0}
    require(isinstance(r, dict) and all(r.get(k) == v and type(r.get(k)) is type(v) for k, v in exact.items()),
            "original_receipt_binding_or_terminal")
    for key in ("effect_started", "process_group_established", "waitpid_joined", "process_group_absent",
                "execution_credentials_verified", "supplementary_groups_cleared", "worker_domain_verified"):
        require(r.get(key) is True, "original_receipt_" + key)
    require(r.get("waitpid_identity_lost") is False, "original_receipt_identity_lost")
    for key in ("execution_uid", "execution_euid", "execution_gid", "execution_egid"):
        require(type(r.get(key)) is int and r[key] == 2000, "original_receipt_credentials")
    require(type(r.get("dispatch_count")) is int and r["dispatch_count"] == 1
            and type(r.get("execution_supplementary_group_count")) is int
            and r["execution_supplementary_group_count"] == 0
            and type(r.get("exit_code")) is int and r["exit_code"] == 0
            and type(r.get("pid")) is int and r["pid"] > 1
            and type(r.get("pgid")) is int and r["pid"] == r["pgid"], "original_receipt_execution_counts")
    return sha(encode(r))

class Session:
    def __init__(self, conn, state, run_dir, contract, client, stopped, service_deadline=None):
        self.conn, self.state, self.run_dir, self.c, self.client, self.stopped = conn, state, run_dir, contract, client, stopped
        self.in_seq = self.out_seq = 0
        self.partial = bytearray()
        self.total_in = 0
        self.action = self.call = self.scope = None
        self.dispatch_possible = False
        self.terminal = None
        self.inspection = None
        self.cancelled = False
        self.deadline = min(time.monotonic() + TURN_SECONDS,
                            service_deadline - 12 if service_deadline is not None else float('inf'))
        self.input_file = open(run_dir/"provider-in.jsonl", "xb", buffering=0)
        self.output_file = open(run_dir/"provider-out.jsonl", "xb", buffering=0)

    def record(self, name, value):
        return create(self.run_dir/name, value)

    def receive(self, expected, wait=True):
        while b"\n" not in self.partial:
            require(not self.stopped[0], "operator_stop")
            require(time.monotonic() < self.deadline, "probe_turn_deadline_no_retry")
            ready = select.select([self.conn], [], [], .05 if wait else 0)[0]
            if not ready:
                if wait:
                    continue
                return None
            chunk = self.conn.recv(min(16384, MAX_FRAME + 1 - len(self.partial)))
            require(bool(chunk), "native_transport_eof_no_retry")
            self.total_in += len(chunk)
            require(self.total_in <= 4*MAX_FRAME, "native_total_frame_bytes")
            self.partial.extend(chunk)
            require(len(self.partial) <= MAX_FRAME, "native_frame_bound")
        end = self.partial.index(10) + 1
        raw = bytes(self.partial[:end]); del self.partial[:end]
        self.input_file.write(raw); os.fsync(self.input_file.fileno())
        value = decode(raw)
        require(value.get("protocol") == PROTOCOL and type(value.get("seq")) is int
                and value["seq"] == self.in_seq and self.in_seq < 4, "native_protocol_sequence")
        self.in_seq += 1
        if value.get("kind") == "turn.cancel":
            self.cancelled = True
            raise Rejected("native_cancel_observed_no_redispatch")
        require(value.get("kind") == expected, "unexpected_native_frame")
        return value

    def emit(self, kind, **fields):
        require(self.terminal is None, "already_terminal")
        if kind == "tool.call":
            require(self.action is not None and not self.dispatch_possible
                    and not self.cancelled and not self.stopped[0], "one_dispatch_fence")
            self.record("dispatch-intent.json", {"state": "reserved_before_wire_result_may_be_unknown",
                        "scope": self.scope, "action_id": self.action, "call": fields["call"],
                        "command_sha256": sha(fixed_command(self.c["nonce"]).encode()),
                        "executor_instance": self.c["executor_server_instance"], "automatic_replay": False})
            self.dispatch_possible = True
        if kind in ("turn.complete", "turn.fail", "turn.cancelled"):
            self.terminal = kind
            self.record("provider-terminal-intent.json", {"kind": kind, "fields": fields,
                        "native_terminal_independently_verified": False})
        raw = encode({"protocol": PROTOCOL, "seq": self.out_seq, "kind": kind, **fields})
        require(len(raw) <= MAX_FRAME, "provider_frame_bound")
        self.output_file.write(raw); os.fsync(self.output_file.fileno())
        self.conn.settimeout(min(2.0, max(.01, self.deadline-time.monotonic())))
        self.conn.sendall(raw)
        self.out_seq += 1

    def inspect_original(self):
        if self.action is None or self.inspection is not None:
            return self.inspection
        try:
            value = self.client.inspect(self.action, sha(fixed_command(self.c["nonce"]).encode()), False)
            self.record("original-executor-inspection.json", value)
            self.inspection = value
        except Exception as error:
            self.record("original-executor-inspection-error.json",
                        {"error": type(error).__name__ + ":" + str(error),
                         "original_action_id": self.action, "automatic_replay": False})
            self.inspection = {"inspection_failed": True}
        return self.inspection

    def run(self):
        try:
            start = self.receive("turn.start")
            self.scope, self.action = validate_start(start, self.c)
            self.call = "component-" + self.c["nonce"]
            # Contract nonce persists across all identities and replacement streams.
            create(self.state/"claims"/(self.c["nonce"]+".json"),
                   {"scope": self.scope, "owner_request_sha256": self.c["owner_request_sha256"],
                    "action_id": self.action, "call_id": self.call,
                    "executor_server_instance": self.c["executor_server_instance"],
                    "run_dir": str(self.run_dir), "state": "accepted_never_replay"})
            self.record("accepted.json", {"scope": self.scope, "action_id": self.action,
                        "owner_request_sha256": self.c["owner_request_sha256"], "contract": self.c})
            read_file(CLIENT, 32768, CLIENT_SHA)
            # A buffered cancellation is processed before reserving the only dispatch.
            require(self.receive("no_additional_frame_before_dispatch", wait=False) is None, "extra_frame")
            argv = ["/usr/bin/python3", str(CLIENT), "execute", "--action-id", self.action,
                    "--command-b64", base64.b64encode(fixed_command(self.c["nonce"]).encode()).decode(),
                    "--timeout-ms", str(TOOL_TIMEOUT_MS), "--receipt-dir", str(self.state/"client-receipts")]
            call = {"call_id": self.call, "tool": "shell.exec", "argv": argv,
                    "timeout_ms": NATIVE_TIMEOUT_MS, **self.scope}
            self.emit("tool.call", call=call)
            result = self.receive("tool.result")
            self.record("native-tool-result.json", result)
            inspected = self.inspect_original()
            expected = expected_output(self.c["nonce"])
            native = native_output(result, self.call, expected)
            receipt_sha = verify_receipt(inspected, self.c, self.action,
                                        sha(fixed_command(self.c["nonce"]).encode()), expected)
            self.record("component-outcome.json", {"state": "component_postconditions_pass",
                        "scope": SCOPE, "identity": self.scope, "action_id": self.action,
                        "native_tool": native, "original_receipt_canonical_json_sha256": receipt_sha,
                        "model_requests": 0, "ui_business_actions": 0,
                        "native_turn_end_verified": False, "business_qualified": False})
            require(self.receive("no_additional_frame_before_terminal", wait=False) is None, "extra_frame")
            self.emit("turn.complete", summary="本地执行器组件探针通过；仅固定 stdout 标记，未进行模型或 App 业务验收。")
            return 0
        except Exception as error:
            if self.dispatch_possible:
                self.inspect_original()
            self.record("component-failure.json", {"error": type(error).__name__ + ":" + str(error),
                        "scope": self.scope, "action_id": self.action,
                        "dispatch_may_have_reached_native": self.dispatch_possible,
                        "automatic_replay": False, "native_turn_end_verified": False})
            if self.terminal is None:
                try:
                    kind = "turn.cancelled" if self.cancelled or self.stopped[0] else "turn.fail"
                    fields = ({"summary": "组件探针取消；只查原回执，不重发。"} if kind == "turn.cancelled"
                              else {"error": "component_probe_failed_no_retry:" + str(error)[:512]})
                    self.emit(kind, **fields)
                except Exception:
                    pass
            return 70
        finally:
            self.input_file.close(); self.output_file.close()
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.conn.close()

def ready_record(c, contract_sha, deadline, pid_start_ticks):
    require(type(pid_start_ticks) is int and pid_start_ticks > 0, "ready_process_start_ticks")
    return {"pid": os.getpid(), "pid_start_ticks": pid_start_ticks,
            "instance": uuid.uuid4().hex, "port": 18080, "scope": SCOPE,
            "nonce": c["nonce"], "owner_request_sha256": c["owner_request_sha256"],
            "provider_source_sha256": c["provider_source_sha256"],
            "contract_sha256": contract_sha, "accepting_one_session": True,
            "executor_server_instance": c["executor_server_instance"],
            "clock": "phone CLOCK_MONOTONIC",
            "ready_monotonic_ns": time.monotonic_ns(),
            "accept_deadline_monotonic_ns": int((deadline - 30) * 1000000000),
            "service_deadline_monotonic_ns": int(deadline * 1000000000),
            "readiness_scope": "transport_and_readonly_parent_identity_only"}


def serve(contract_path, contract_sha):
    os.umask(0o077)
    deadline = time.monotonic() + SERVICE_SECONDS
    require(os.getuid() == 0 and os.geteuid() == 0, "phone_rootlinux_root_required")
    for directory in (STATE, STATE/"contracts", STATE/"claims", STATE/"evidence", STATE/"client-receipts"):
        private_dir(directory)
    raw = read_file(contract_path, 16384, contract_sha)
    c = validate_contract(decode(raw))
    require(contract_path == STATE/"contracts"/(c["nonce"]+".json"), "fixed_contract_location")
    require(c["provider_source_sha256"] == sha(read_file(Path(__file__).absolute(), 65536)), "provider_source_pin")
    lock = os.open(STATE/"daemon.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    info = os.fstat(lock)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1, "daemon_lock_identity")
    create(STATE/("service-attempt-"+c["nonce"]+".json"),
           {"contract_sha256": contract_sha, "automatic_restart": False, "pid": os.getpid()})
    client_raw = read_file(CLIENT, 32768, CLIENT_SHA)
    client = types.ModuleType("pinned_probe_client_r6")
    client.__file__ = str(CLIENT)
    exec(compile(client_raw, str(CLIENT), "exec"), client.__dict__)
    health = client.request({"version": 1, "op": "health"}, timeout_s=10.0)
    create(STATE/("health-before-"+c["nonce"]+".json"), health)
    verify_health(health, c)
    stopped = [False]
    def stop(_number, _frame):
        stopped[0] = True
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, stop)
    accepted = False
    result = 78
    with socket.socket() as listener:
        # No SO_REUSEPORT and no other transport. Existing provider must be stopped.
        listener.bind(("127.0.0.1", 18080))
        listener.listen(1); listener.settimeout(.25)
        with open("/proc/self/stat", "rb") as proc_stat:
            process_stat = proc_stat.read(4097)
        require(len(process_stat) <= 4096, "ready_process_stat_bound")
        process_fields = process_stat.decode("utf-8").rsplit(")", 1)[1].split()
        require(len(process_fields) > 19, "ready_process_stat_shape")
        start_ticks = int(process_fields[19])
        create(STATE/("ready-"+c["nonce"]+".json"),
               ready_record(c, contract_sha, deadline, start_ticks))
        try:
            while not stopped[0] and time.monotonic() + 30 <= deadline:
                try:
                    conn, address = listener.accept()
                except socket.timeout:
                    continue
                require(address[0] == "127.0.0.1", "loopback_peer_required")
                accepted = True
                run_dir = STATE/"evidence"/(time.strftime("%Y%m%d-%H%M%S")+"-"+uuid.uuid4().hex)
                private_dir(run_dir)
                result = Session(conn, STATE, run_dir, c, client, stopped, deadline).run()
                break  # exactly one connection, including EOF/wrong-request/failure
        finally:
            create(STATE/("service-ended-"+c["nonce"]+".json"),
                   {"accepted_connection": accepted, "exit_code": result,
                    "automatic_restart": False, "native_terminal_verified": False,
                    "operator_must_retire_component_executor": True})
    os.close(lock)
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-sha256", required=True)
    args = parser.parse_args()
    require(hex_string(args.contract_sha256, 64), "contract_hash")
    try:
        return serve(args.contract.absolute(), args.contract_sha256)
    except Exception as error:
        print(encode({"state": "probe_service_failed", "error": type(error).__name__+":"+str(error),
                      "automatic_restart": False, "phone_business_qualified": False}).decode(), end="")
        return 78

if __name__ == "__main__":
    raise SystemExit(main())
