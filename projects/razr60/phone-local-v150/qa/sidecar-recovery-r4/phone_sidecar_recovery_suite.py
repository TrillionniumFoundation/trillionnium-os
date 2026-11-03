#!/usr/bin/env python3
"""Root-operated actual-phone sidecar r4 directed recovery suite.

PREPARE/REVIEW ONLY until invoked with --execute-new-suite inside the existing
GNU chroot. No ADB, no model, no native r5 task/tool ledger, no UI commands.
All synthetic shell writes are confined to one new HOSTSTATE/qa-<nonce>.
Never retry an execute request after an uncertain result. Inspect originals.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

PROTOCOL = "hepta_phone_local_v150"
HOSTSTATE = "/data/trillionnium/owner-open/state/phone-local-v150"
ROOTSTATE = Path("/var/lib/trillionnium/owner-open/phone-local-v150")
CLIENT = ROOTSTATE / "tool_client.py"
CLIENT_SHA = "b298ac86fdf57dd0c7dc5159febf114ed176398d32ea672c9abda4a6eb621539"
SIDECAR_SHA = "796f223a98553afc83eb875b3a89aa03f07d0d069a3fb5ab953f849a7f8e84c0"
CASES = ["disconnect_before_dispatch", "disconnect_after_started",
         "client_cancel_after_started", "executor_timeout_late_result",
         "duplicate_inspect_only"]
MAX_SUITE_SECONDS = 70.0
MAX_TOOL_MS = 3000
SCOPE = {
    "kind": "actual_phone_sidecar_component_directed_recovery",
    "original_installed_r4_client_and_sidecar_required": True,
    "native_r5_task_or_tool_ledger_used": False,
    "model_inference_used": False,
    "phone_ui_commands_used": False,
    "nineteen_item_business_protocol_completed": False,
    "automatic_effect_replay": False,
    "original_task_terminals_modified": False,
    "effects": "synthetic marker files inside one fresh qa directory only",
    "case1_exception": "incomplete request must remain not_found, no terminal is invented",
}

class SuiteError(RuntimeError):
    pass

class Deadline(SuiteError):
    pass

def require(ok, message):
    if not ok:
        raise SuiteError(message)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()

def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def exclusive_bytes(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(path.parent)
    return digest(raw)

def private_dir(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o700,
            "private root-owned directory required: " + str(path))
    require(path.resolve(strict=True) == path, "canonical directory required: " + str(path))

def safe_read(path, cap=262144):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == 0 and not (before.st_mode & 0o022)
                and 0 <= before.st_size <= cap, "unsafe/oversized original file: " + str(path))
        chunks = []
        remaining = cap + 1
        while remaining:
            block = os.read(fd, min(65536, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        raw = b"".join(chunks)
        after, named = os.fstat(fd), path.lstat()
        attrs = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(len(raw) == before.st_size and
                all(getattr(before, k) == getattr(after, k) == getattr(named, k) for k in attrs),
                "original file changed while read: " + str(path))
        return raw
    finally:
        os.close(fd)

def path_absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False

def proc_identity(pid):
    raw = Path("/proc/%d/stat" % pid).read_text()
    tail = raw.rsplit(") ", 1)[1].split()
    require(tail[0] != "Z", "sidecar is a zombie")
    return {"pid": pid, "pgrp": int(tail[2]), "session": int(tail[3]),
            "starttime": tail[19]}

class Suite:
    def __init__(self):
        self.started = time.monotonic()
        self.deadline = self.started + MAX_SUITE_SECONDS
        self.nonce = secrets.token_hex(12)
        self.root = ROOTSTATE / ("qa-" + self.nonce)
        self.host = HOSTSTATE + "/qa-" + self.nonce
        self.client = None
        self.peer = None
        self.server_instance = None
        self.sequence = 0
        self.rows = []
        self.sockets = []
        self.children = []
        self.late_checks = []
        self.active_case = None
        self.failure = None
        private_dir(ROOTSTATE)
        self.root.mkdir(mode=0o700)
        fsync_dir(ROOTSTATE)
        private_dir(self.root)
        (self.root / "client-receipts").mkdir(mode=0o700)
        fsync_dir(self.root)
        self.specs = []
        for index, name in enumerate(CASES, 1):
            action_id = secrets.token_hex(16)
            line = self.nonce + ":" + name + ":" + action_id + "\n"
            primary = "%02d-%s.marker" % (index, name)
            late = "%02d-%s.late" % (index, name)
            cmd = "set -eu; umask 077; printf %s " + shlex.quote(line) + " >> " + shlex.quote(self.host + "/" + primary)
            cmd += "; printf %s " + shlex.quote("started:" + action_id + "\n")
            if index in (2, 3, 4):
                cmd += "; /system/bin/sleep 2; printf %s " + shlex.quote(line) + " >> " + shlex.quote(self.host + "/" + late)
                cmd += "; printf %s " + shlex.quote("late-result:" + action_id + "\n")
            cmd += "; exit 0"
            timeout = 650 if index == 4 else MAX_TOOL_MS
            payload = {"version": 1, "op": "execute", "action_id": action_id,
                       "command_sha256": digest(cmd.encode()), "command": cmd,
                       "timeout_ms": timeout}
            self.specs.append({"name": name, "index": index, "action_id": action_id,
                               "line": line, "primary": primary, "late": late,
                               "payload": payload, "deadline_ms": timeout})
        require(len({s["action_id"] for s in self.specs}) == 5, "random identity collision")
        self.record("plan", {"schema": "hepta.phone-sidecar-recovery-plan.v150.1",
                            "scope": SCOPE, "nonce": self.nonce,
                            "rootfs_evidence": str(self.root), "android_evidence": self.host,
                            "client": str(CLIENT), "client_sha256": CLIENT_SHA,
                            "sidecar_sha256": SIDECAR_SHA, "suite_soft_bound_seconds": MAX_SUITE_SECONDS,
                            "outer_watchdog_recommendation": "timeout -s TERM -k 3s 85s /usr/bin/python3 -B SCRIPT --execute-new-suite",
                            "script_sha256": digest(Path(__file__).read_bytes()),
                            "cases": self.specs})
        print(json.dumps({"status": "new_suite_prepared", "nonce": self.nonce,
                          "rootfs_evidence": str(self.root), "android_evidence": self.host,
                          "scope": SCOPE}), flush=True)

    def remaining(self, cap=1.0):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise Deadline("suite 70-second execution budget exhausted")
        return min(cap, left)

    def record(self, label, value):
        self.sequence += 1
        path = self.root / ("%03d-%s.json" % (self.sequence, label))
        raw = encode(value)
        sha = exclusive_bytes(path, raw)
        return {"path": str(path), "sha256": sha, "bytes": len(raw)}

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sockets.append(sock)
        sock.settimeout(self.remaining(1.0))
        sock.connect("\0" + PROTOCOL)
        pid, uid, gid = struct.unpack("3i", sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        require(uid in (0, 2000), "sidecar peer UID differs")
        peer = {"pid": pid, "uid": uid, "gid": gid}
        if self.peer is not None:
            require(peer == self.peer, "sidecar peer changed during suite")
        return sock, peer

    def close_socket(self, sock):
        try:
            sock.close()
        finally:
            if sock in self.sockets:
                self.sockets.remove(sock)

    def request(self, payload):
        return self.client.request(payload, PROTOCOL, self.remaining(1.0))

    def health(self, label):
        reply = self.request({"version": 1, "op": "health"})
        self.record(label, reply)
        require(reply.get("state") == "ready", "sidecar not ready; do not dispatch or clear recovery gate")
        if self.server_instance is None:
            self.server_instance = reply.get("server_instance")
            require(isinstance(self.server_instance, str) and len(self.server_instance) == 32,
                    "server instance absent")
        require(reply.get("server_instance") == self.server_instance, "sidecar restarted during suite")
        return reply

    def inspect(self, spec, label, include=True):
        reply = self.request({"version": 1, "op": "inspect",
                              "action_id": spec["action_id"],
                              "command_sha256": spec["payload"]["command_sha256"],
                              "include_output": include})
        self.record(label, reply)
        r = reply.get("receipt", {})
        require(r.get("action_id") == spec["action_id"], "inspect action identity differs")
        if r.get("state") != "not_found":
            require(r.get("command_sha256") == spec["payload"]["command_sha256"],
                    "inspect original command hash differs")
        return reply

    def terminal(self, spec, expected_state, max_wait=7.0):
        until = time.monotonic() + max_wait
        while True:
            reply = self.inspect(spec, spec["name"] + "-original-inspect")
            r = reply["receipt"]
            if r.get("terminal") is True:
                require(r.get("state") == expected_state, "unexpected terminal state: " + str(r.get("state")))
                for key in ("effect_started", "process_group_established", "waitpid_joined",
                            "process_group_absent", "intent_parent_sync_complete"):
                    require(r.get(key) is True, "original terminal lacks " + key)
                require(r.get("dispatch_count") == 1 and r.get("can_redispatch") is False,
                        "original dispatch count/no-replay flag differs")
                require(r.get("server_instance") == self.server_instance, "terminal server instance differs")
                require(r.get("timeout_ms") == spec["deadline_ms"], "original timeout differs")
                for key in ("stdout", "stderr"):
                    raw = base64.b64decode(reply[key + "_b64"], validate=True)
                    require(len(raw) == r[key + "_bytes"] and digest(raw) == r[key + "_sha256"],
                            "original output integrity differs")
                    require(("late-result:" + spec["action_id"]).encode() not in raw,
                            "late output survived cancellation/timeout")
                self.marker(spec, 1)
                return reply
            require(time.monotonic() < until, "original action has no safe terminal; do not retry")
            time.sleep(min(0.04, self.remaining()))

    def marker(self, spec, count):
        path = self.root / spec["primary"]
        raw = b"" if path_absent(path) else safe_read(path, 4096)
        require(raw == spec["line"].encode() * count,
                "primary marker count/content differs for " + spec["name"])
        require(path_absent(self.root / spec["late"]), "late marker exists for " + spec["name"])
        return {"marker_path": str(path), "bytes": len(raw), "sha256": digest(raw),
                "expected_count": count, "observed_count": count, "late_marker_absent": True}

    def started_marker(self, spec):
        until = time.monotonic() + 1.5
        while True:
            reply = self.inspect(spec, spec["name"] + "-started-observation", False)
            r = reply["receipt"]
            present = not path_absent(self.root / spec["primary"])
            if present and r.get("effect_started") is True:
                require(r.get("terminal") is False and r.get("state") == "running",
                        "action already terminal before the planned cancellation")
                self.marker(spec, 1)
                self.late_checks.append((spec, time.monotonic() + 2.3))
                return reply
            require(r.get("terminal") is not True and time.monotonic() < until,
                    "could not observe running original action; no cancellation result invented")
            time.sleep(min(0.03, self.remaining()))

    def original_files(self, spec, label):
        source = ROOTSTATE / "sidecar" / "actions" / spec["action_id"]
        private_dir(source)
        evidence = {}
        for name in ("intent.json", "receipt.json", "stdout.bin", "stderr.bin"):
            raw = safe_read(source / name, 262144)
            dst = self.root / ("%s-%s-%s" % (spec["name"], label, name))
            sha = exclusive_bytes(dst, raw)
            evidence[name] = {"original_path": str(source / name), "copy_path": str(dst),
                              "sha256": sha, "bytes": len(raw)}
        receipt = json.loads(safe_read(source / "receipt.json"))
        require(receipt.get("terminal") is True and receipt.get("action_id") == spec["action_id"],
                "copied original receipt not terminal/bound")
        self.record(spec["name"] + "-" + label + "-journal", evidence)
        return evidence

    def client_spawn(self, spec, suffix):
        args = ["/usr/bin/python3", "-B", str(CLIENT), "execute",
                "--action-id", spec["action_id"], "--command-b64",
                base64.b64encode(spec["payload"]["command"].encode()).decode(),
                "--timeout-ms", str(spec["deadline_ms"]),
                "--receipt-dir", str(self.root / "client-receipts")]
        out_path = self.root / (spec["name"] + "-" + suffix + ".stdout.bin")
        err_path = self.root / (spec["name"] + "-" + suffix + ".stderr.bin")
        fds = [os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
               for path in (out_path, err_path)]
        try:
            child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=fds[0],
                                     stderr=fds[1], cwd=str(self.root), close_fds=True,
                                     env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                          "PYTHONDONTWRITEBYTECODE": "1"})
        finally:
            for fd in fds:
                os.close(fd)
        self.children.append(child)
        self.record(spec["name"] + "-" + suffix + "-client-start",
                    {"pid": child.pid, "argv": args, "stdout": str(out_path),
                     "stderr": str(err_path), "native_r5_tool_ledger": False})
        return child, out_path, err_path

    def client_wait(self, spec, spawned, expected_rc, suffix, seconds=8.0):
        child, out_path, err_path = spawned
        rc = child.wait(timeout=self.remaining(seconds))
        require(rc == expected_rc, "client exit differs for %s: %r" % (spec["name"], rc))
        row = {"pid": child.pid, "returncode": rc, "waitpid_joined": True}
        for key, path in (("stdout", out_path), ("stderr", err_path)):
            raw = safe_read(path, 262144)
            row[key] = {"path": str(path), "sha256": digest(raw), "bytes": len(raw)}
        self.record(spec["name"] + "-" + suffix + "-client-terminal", row)
        return row

    def run(self):
        require(os.getuid() == 0, "must run as root inside existing GNU chroot")
        require(sys.platform == "linux", "actual phone GNU chroot required")
        raw = safe_read(CLIENT, 32768)
        require(digest(raw) == CLIENT_SHA, "installed client differs from sealed r4 pin")
        sys.dont_write_bytecode = True
        spec = importlib.util.spec_from_file_location("installed_sidecar_client_for_qa", CLIENT)
        self.client = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.client)
        sock, self.peer = self.connect()
        raw_health = self.client._json_bytes({"version": 1, "op": "health"})
        sock.sendall(struct.pack(">I", len(raw_health)) + raw_health)
        size = struct.unpack(">I", self.client._recv_exact(sock, 4))[0]
        require(0 < size <= 8192, "initial health frame size differs")
        first_health = json.loads(self.client._recv_exact(sock, size))
        self.close_socket(sock)
        require(first_health.get("version") == 1 and first_health.get("protocol") == PROTOCOL
                and first_health.get("state") == "ready", "initial authenticated health not ready")
        self.server_instance = first_health.get("server_instance")
        require(isinstance(self.server_instance, str) and len(self.server_instance) == 32,
                "initial server instance absent")
        self.record("peer-pinning-health", first_health)
        before = proc_identity(self.peer["pid"])
        image = Path("/proc/%d/exe" % self.peer["pid"])
        h, count = hashlib.sha256(), 0
        with image.open("rb") as stream:
            while True:
                self.remaining()
                block = stream.read(1024 * 1024)
                if not block:
                    break
                h.update(block)
                count += len(block)
                require(count <= 16 * 1024 * 1024, "sidecar executable exceeds expected bound")
        require(h.hexdigest() == SIDECAR_SHA, "live sidecar executable is not sealed r4")
        require(before == proc_identity(self.peer["pid"]), "sidecar process identity changed while pinned")
        self.record("live-input-pins", {"client_sha256": digest(raw),
                                       "sidecar_sha256": h.hexdigest(), "sidecar_bytes": count,
                                       "peer": self.peer, "process_identity": before,
                                       "live_exe_link": os.readlink(image)})
        private_dir(ROOTSTATE / "sidecar" / "actions")
        self.health("initial-health")
        for item in self.specs:
            require(path_absent(ROOTSTATE / "sidecar" / "actions" / item["action_id"]),
                    "fresh action ID already exists; do not retry with a replacement ID")

        s = self.specs[0]
        self.active_case = s
        sock, _ = self.connect()
        raw = self.client._json_bytes(s["payload"])
        partial = struct.pack(">I", len(raw)) + raw[:-1]
        sock.sendall(partial)
        self.record(s["name"] + "-partial-transport",
                    {"declared_json_bytes": len(raw), "sent_json_bytes": len(raw)-1,
                     "sent_frame_sha256": digest(partial), "complete_request_sent": False})
        self.close_socket(sock)
        for n in (1, 2):
            reply = self.inspect(s, s["name"] + "-not-found-%d" % n, False)
            require(reply["receipt"].get("state") == "not_found" and
                    reply["receipt"].get("terminal") is False and
                    reply["receipt"].get("effect_started") is False,
                    "incomplete request reached an action")
            require(path_absent(ROOTSTATE / "sidecar" / "actions" / s["action_id"]),
                    "incomplete request created an original intent")
            self.marker(s, 0)
            if n == 1:
                time.sleep(min(0.15, self.remaining()))
        self.rows.append({"case": s["name"], "action_id": s["action_id"], "status": "PASS",
                          "expected_dispatches": 0, "original_state": "not_found",
                          "marker_count": 0, "terminal_requirement": "not_applicable_no_action_existed"})
        self.health("after-before-dispatch-health")

        s = self.specs[1]
        self.active_case = s
        sock, _ = self.connect()
        raw = self.client._json_bytes(s["payload"])
        sock.sendall(struct.pack(">I", len(raw)) + raw)
        self.record(s["name"] + "-one-execute-frame", {"action_id": s["action_id"], "execute_frames": 1})
        self.started_marker(s)
        self.close_socket(sock)
        reply = self.terminal(s, "cancelled")
        require(reply["receipt"].get("error") == "client_disconnected",
                "disconnect case cancelled for another reason")
        evidence = self.original_files(s, "terminal")
        self.rows.append({"case": s["name"], "action_id": s["action_id"], "status": "PASS",
                          "expected_dispatches": 1, "original_state": "cancelled",
                          "marker_count": 1, "original_files": evidence})
        self.health("after-disconnect-health")

        s = self.specs[2]
        self.active_case = s
        spawned = self.client_spawn(s, "original")
        self.started_marker(s)
        child = spawned[0]
        require(child.poll() is None, "client ended before planned SIGTERM")
        child.terminate()
        self.record(s["name"] + "-client-sigterm", {"pid": child.pid, "signal": "SIGTERM",
                                                  "after_original_effect_started_and_marker": True})
        self.client_wait(s, spawned, -signal.SIGTERM, "original", 2.0)
        reply = self.terminal(s, "cancelled")
        require(reply["receipt"].get("error") == "client_disconnected",
                "client cancellation case ended for another reason")
        evidence = self.original_files(s, "terminal")
        self.rows.append({"case": s["name"], "action_id": s["action_id"], "status": "PASS",
                          "expected_dispatches": 1, "original_state": "cancelled",
                          "marker_count": 1, "original_files": evidence})
        self.health("after-client-cancel-health")

        s = self.specs[3]
        self.active_case = s
        spawned = self.client_spawn(s, "original")
        self.client_wait(s, spawned, 72, "original")
        reply = self.terminal(s, "timed_out")
        require(reply["receipt"].get("error") == "timeout" and
                reply["receipt"].get("client_disconnected") is False,
                "executor timeout was not independently observed")
        self.late_checks.append((s, time.monotonic() + 2.3))
        evidence = self.original_files(s, "terminal")
        self.rows.append({"case": s["name"], "action_id": s["action_id"], "status": "PASS",
                          "expected_dispatches": 1, "original_state": "timed_out",
                          "marker_count": 1, "original_files": evidence})
        self.health("after-timeout-health")

        s = self.specs[4]
        self.active_case = s
        spawned = self.client_spawn(s, "original")
        self.client_wait(s, spawned, 0, "original")
        reply = self.terminal(s, "completed")
        before_files = self.original_files(s, "before-duplicate")
        # This second invocation MUST take the installed client's O_EXCL-claim
        # duplicate path, which sends INSPECT only. No second execute frame.
        duplicate = self.client_spawn(s, "duplicate-inspect-only")
        self.client_wait(s, duplicate, 76, "duplicate-inspect-only")
        duplicate_stderr = safe_read(duplicate[2], 262144)
        require(b"duplicate_action_inspect_only" in duplicate_stderr,
                "duplicate client did not report inspect-only")
        require(safe_read(duplicate[1], 262144) == b"", "duplicate echoed old output as fresh output")
        inspect_path = self.root / "client-receipts" / (s["action_id"] + ".last-inspect.json")
        retained = json.loads(safe_read(inspect_path))
        require(retained.get("receipt") == reply["receipt"], "duplicate inspection changed original terminal")
        self.terminal(s, "completed")
        after_files = self.original_files(s, "after-duplicate")
        require({k:v["sha256"] for k,v in before_files.items()} ==
                {k:v["sha256"] for k,v in after_files.items()},
                "duplicate changed original action files")
        self.rows.append({"case": s["name"], "action_id": s["action_id"], "status": "PASS",
                          "expected_dispatches": 1, "original_state": "completed",
                          "marker_count": 1, "duplicate_client_exit": 76,
                          "duplicate_protocol_operation": "inspect",
                          "original_files_unchanged": True,
                          "original_files": after_files})
        self.active_case = None

        # Observe beyond each killed command's originally scheduled late write.
        for item, due in self.late_checks:
            while time.monotonic() < due:
                time.sleep(min(0.1, due-time.monotonic(), self.remaining()))
            self.record(item["name"] + "-late-write-deadline-passed",
                        {"observation": self.marker(item, 1), "minimum_observation_margin_seconds": 2.3})
        for index, item in enumerate(self.specs):
            if index == 0:
                final = self.inspect(item, "final-before-dispatch-original", False)
                require(final["receipt"].get("state") == "not_found" and
                        path_absent(ROOTSTATE / "sidecar" / "actions" / item["action_id"]),
                        "incomplete request acquired a late intent")
                self.marker(item, 0)
            else:
                self.terminal(item, self.rows[index]["original_state"], 0.2)
                originals = self.rows[index]["original_files"]
                final_hashes = {name: digest(safe_read(Path(meta["original_path"])))
                                for name, meta in originals.items()}
                require(final_hashes == {name: meta["sha256"] for name, meta in originals.items()},
                        "late observation changed original journal for " + item["name"])
                self.record(item["name"] + "-final-journal-unchanged",
                            {"action_id": item["action_id"], "original_sha256": final_hashes,
                             "unchanged_after_late_deadlines": True})
        self.health("final-health")
        require(len(self.rows) == 5, "five independent cases did not complete")

    def cleanup(self):
        # No action is resent. Closing a fault socket or terminating this suite's
        # own client causes the server to cancel its existing owned tool group.
        for sock in list(self.sockets):
            self.close_socket(sock)
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=0.5)
        if self.failure and self.client is not None:
            end = time.monotonic() + 3.0
            for item in self.specs:
                if path_absent(ROOTSTATE / "sidecar" / "actions" / item["action_id"]):
                    continue
                try:
                    while time.monotonic() < end:
                        result = self.client.request({"version": 1, "op": "inspect",
                            "action_id": item["action_id"],
                            "command_sha256": item["payload"]["command_sha256"],
                            "include_output": False}, PROTOCOL, 0.5)
                        self.record(item["name"] + "-failure-cleanup-original-inspect", result)
                        if result.get("receipt", {}).get("terminal") is True:
                            break
                        time.sleep(0.03)
                except Exception as error:
                    self.record(item["name"] + "-failure-cleanup-unknown",
                                {"error_type": type(error).__name__, "error": str(error),
                                 "original_action_not_resent": True})

    def finish(self):
        files = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                raw = safe_read(path, 1048576)
                files.append({"path": str(path), "sha256": digest(raw), "bytes": len(raw)})
        manifest = {"schema": "hepta.phone-sidecar-recovery-evidence.v150.1",
                    "nonce": self.nonce, "files": files,
                    "immutable_original_copies": True, "no_files_deleted": True}
        manifest_raw = encode(manifest)
        manifest_path = self.root / "EVIDENCE-MANIFEST.json"
        manifest_sha = exclusive_bytes(manifest_path, manifest_raw)
        summary = {"schema": "hepta.phone-sidecar-recovery-summary.v150.1",
                   "status": "PASS" if self.failure is None and len(self.rows) == 5 else "FAIL_OR_INCOMPLETE",
                   "scope": SCOPE, "nonce": self.nonce, "cases": self.rows,
                   "failure": self.failure, "active_case_at_failure":
                        None if self.active_case is None else self.active_case["name"],
                   "elapsed_seconds": round(time.monotonic()-self.started, 3),
                   "rootfs_evidence": str(self.root), "android_evidence": self.host,
                   "manifest_path": str(manifest_path), "manifest_sha256": manifest_sha,
                   "client_sha256": CLIENT_SHA, "sidecar_sha256": SIDECAR_SHA,
                   "server_instance": self.server_instance,
                   "five_fresh_action_ids": [x["action_id"] for x in self.specs],
                   "executed_actions_expected_if_pass": 4,
                   "new_user_or_business_actions": 0,
                   "remaining_qualification": ["native r5 cancellation/disconnect chain",
                       "model + visual/Unicode business postconditions",
                       "fixed 19-item protocol", "real display-state qualification"]}
        raw = encode(summary)
        path = self.root / "SUMMARY.json"
        sha = exclusive_bytes(path, raw)
        exclusive_bytes(self.root / "SUMMARY.sha256",
                        (sha + "  SUMMARY.json\n").encode())
        print(json.dumps({"status": summary["status"], "summary": str(path),
                          "summary_sha256": sha, "evidence_manifest": str(manifest_path),
                          "evidence_manifest_sha256": manifest_sha,
                          "elapsed_seconds": summary["elapsed_seconds"],
                          "scope": SCOPE}), flush=True)
        return 0 if summary["status"] == "PASS" else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-new-suite", action="store_true",
                        help="root-only actual phone sidecar fault tests; never used during preparation")
    args = parser.parse_args()
    if not args.execute_new_suite:
        print(json.dumps({"status": "REVIEW_ONLY_NO_SOCKET_OR_FILES", "scope": SCOPE,
                          "cases": CASES, "max_tool_ms": MAX_TOOL_MS,
                          "suite_soft_bound_seconds": MAX_SUITE_SECONDS,
                          "client_sha256": CLIENT_SHA, "sidecar_sha256": SIDECAR_SHA}, indent=2))
        return 0
    require(os.getuid() == 0, "root GNU chroot required before creating any QA directory")
    os.umask(0o077)
    suite = None
    def abort(number, frame):
        raise Deadline("suite watchdog/signal: " + str(number))
    for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, abort)
    signal.setitimer(signal.ITIMER_REAL, MAX_SUITE_SECONDS)
    try:
        suite = Suite()
        suite.run()
    except BaseException as error:
        if suite is None:
            print(json.dumps({"status": "PRECHECK_FAILED_BEFORE_SUITE",
                              "error_type": type(error).__name__, "error": str(error)}), file=sys.stderr)
            return 2
        suite.failure = {"error_type": type(error).__name__, "error": str(error),
                         "no_execute_retry": True}
        suite.record("failure", suite.failure)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if suite is not None:
            try:
                suite.cleanup()
            except BaseException as error:
                suite.failure = suite.failure or {"error_type": type(error).__name__,
                                                  "error": str(error), "phase": "cleanup"}
    return suite.finish()

if __name__ == "__main__":
    raise SystemExit(main())
