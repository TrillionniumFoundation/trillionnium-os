#!/usr/bin/env python3
"""Read-only Hepta/Razr inventory, run only on an explicitly selected existing ADB server.

No installs, launches, input events, UI dumps, settings reads/writes, server resets,
model requests, app restarts, or task-prompt exports. Only a new private HOST output
directory is written. Missing evidence stays UNKNOWN. This is not an acceptance test.

The Adb connection contract and evidence utilities come from phone_acceptance.py.
Its command method uses the existing server's shell-v2 socket, bounds both streams,
and rejects commands outside its finite read-only allowlist. It does not invoke an
ADB client's implicit daemon-start or daemon-replacement paths.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import selectors
import shlex
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

# Local qualification dependencies execute from source, never cached pyc.
from types import ModuleType as _SourceModule
for _source_name in ('model_profiles', 'warm_receipts', 'qualification_scope', 'phone_acceptance'):
    _source_path = Path(__file__).resolve().with_name(_source_name + ".py")
    _source_raw = _source_path.read_bytes()
    _source_digest = __import__("hashlib").sha256(_source_raw).hexdigest()
    _source_previous = sys.modules.get(_source_name)
    _source_previous_digest = getattr(_source_previous, "__hepta_verified_source_sha256__", None)
    if _source_previous_digest is not None:
        if (Path(_source_previous.__file__).resolve() != _source_path
                or _source_previous_digest != _source_digest):
            raise ValueError("previous verified source dependency differs: " + _source_name)
        continue
    _source_module = _SourceModule(_source_name); _source_module.__file__ = str(_source_path)
    sys.modules[_source_name] = _source_module
    exec(compile(_source_raw, str(_source_path), "exec", dont_inherit=True), _source_module.__dict__)
    _source_module.__hepta_verified_source_sha256__ = _source_digest

import phone_acceptance as _acceptance
from model_profiles import PROFILES

Adb, DriverError = _acceptance.Adb, _acceptance.DriverError
digest, private_write, write_json, strict_json = (_acceptance.digest, _acceptance.private_write,
                                                 _acceptance.write_json, _acceptance.strict_json)
PACKAGE = _acceptance.PACKAGE
MAX_COMMANDS = 40
PROPERTIES = (
    "ro.product.manufacturer", "ro.product.model", "ro.product.device", "ro.soc.manufacturer",
    "ro.soc.model", "ro.board.platform", "ro.product.cpu.abilist", "ro.build.version.release",
    "ro.build.version.sdk", "ro.build.version.security_patch", "ro.build.fingerprint", "ro.serialno",
)
SESSION_KEYS = {
    "schema": '"hepta[.]local-session[.]v1"',
    "status": '"(pending|running|not_started|cancelled_before_start|model_reported_done|partial|failed|cancelled|blocked)"',
    "task_id": '(null|"[a-f0-9]{32}")',
    "pending": "(true|false)", "running": "(true|false)", "blocked": "(true|false)",
    "cleanup_known": "(true|false)", "app_uid": "[0-9]{1,10}",
    "updated_wall_ms": "[0-9]{1,16}", "external_model": "(true|false)",
    "automatic_resume": "(true|false)", "goal_independently_verified": "(true|false)",
    "model_reported_success": "(true|false)", "steps": "[0-9]{1,6}",
}
CONFIG_KEYS = {
    "schema": '"hepta[.]local-runtime[.]v[12]"', "compute": '"(npu|gpu)"',
    "model_profile": '"(' + "|".join(re.escape(name) for name in PROFILES) + ')"',
    "context_tokens": "(4096|8192)", "threads": "[1-8]",
}


def projection_script(relative, fields, size_limit):
    """Only fixed state/config paths and whitelisted scalar lines may leave the phone.

    The expected app writer uses pretty JSON. Other layouts/versions produce UNKNOWN;
    do not fall back to cat, jq installation, a prompt file, or a whole settings dump.
    Source hashes bracket the projection. This does not validate the full source JSON.
    """
    if relative not in ("files/control-session.json", "files/model/runtime-config.json"):
        raise DriverError("private inventory path is not allowlisted")
    parents = ["files"] + (["files/model"] if "/model/" in relative else [])
    checks = " || ".join("[ -L " + shlex.quote(p) + " ]" for p in parents + [relative])
    patterns = [r'^[[:space:]]*"' + k + r'"[[:space:]]*:[[:space:]]*' + v
                + r'[[:space:]]*,?[[:space:]]*$' for k, v in fields.items()]
    sed = ";".join("/" + p + "/p" for p in patterns)
    p = shlex.quote(relative)
    return ("if " + checks + "; then exit 41; fi; "
            "if [ ! -e " + p + " ]; then exit 40; fi; "
            "if [ ! -f " + p + " ]; then exit 41; fi; "
            "n=$(wc -c < " + p + ") || exit 42; "
            "case $n in ''|*[!0-9]*) exit 42;; esac; "
            "if [ \"$n\" -gt " + str(size_limit) + " ]; then exit 42; fi; "
            "printf 'SOURCE_SHA256_BEFORE '; sha256sum " + p + " || exit 43; "
            "printf 'SOURCE_METADATA '; stat -c '%s %u %a %h' " + p + " || exit 43; "
            "head -c " + str(size_limit) + " " + p + " | sed -n -E " + shlex.quote(sed) + "; "
            "printf 'SOURCE_SHA256_AFTER '; sha256sum " + p + " || exit 43")


SESSION_SCRIPT = projection_script("files/control-session.json", SESSION_KEYS, 32768)
CONFIG_SCRIPT = projection_script("files/model/runtime-config.json", CONFIG_KEYS, 4096)
INTERRUPTION_LATCH_PATH = "files/control-session.interrupted.json"
# Existence alone is authoritative; never inspect the latch's contents or require
# a regular nonempty JSON file. In particular a dangling symlink still blocks idle.
INTERRUPTION_LATCH_SCRIPT = (
    "if [ -e files/control-session.interrupted.json ] || [ -L files/control-session.interrupted.json ]; "
    "then printf 'present\\n'; exit 0; fi; "
    "if [ -L files ]; then exit 41; fi; "
    "if [ -e files ]; then if [ ! -d files ] || [ ! -r files ] || [ ! -x files ]; "
    "then exit 41; fi; fi; printf 'absent\\n'"
)


def base_commands():
    commands = {("getprop", p): 8192 for p in PROPERTIES}
    commands.update({
        ("getconf", "PAGESIZE"): 8192,
        ("cmd", "activity", "get-current-user"): 8192,
        ("cat", "/proc/meminfo"): 32768,
        ("cat", "/proc/pressure/memory"): 8192,
        ("dumpsys", "battery"): 32768,
        ("dumpsys", "thermalservice"): 131072,
        ("dumpsys", "package", PACKAGE): 524288,
        ("dumpsys", "meminfo", PACKAGE): 262144,
    })
    return commands


def user_commands(user_id):
    if type(user_id) is not int or not 0 <= user_id <= 21474:
        raise DriverError("invalid observed Android user")
    user = str(user_id)
    return {
        ("cmd", "package", "list", "packages", "--user", user, "-U", "--show-versioncode", PACKAGE): 65536,
        ("cmd", "package", "list", "packages", "--user", user, "-U", "--show-versioncode"): 524288,
        ("cmd", "package", "query-activities", "--brief", "--components", "--user", user,
         "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER"): 524288,
        ("cmd", "package", "path", "--user", user, PACKAGE): 32768,
        ("run-as", PACKAGE, "--user", user, "id", "-u"): 8192,
        ("run-as", PACKAGE, "--user", user, "sh", "-c", SESSION_SCRIPT): 32768,
        ("run-as", PACKAGE, "--user", user, "sh", "-c", CONFIG_SCRIPT): 8192,
        ("run-as", PACKAGE, "--user", user, "sh", "-c", INTERRUPTION_LATCH_SCRIPT): 8192,
    }


def _run_bounded(argv, timeout, limit):
    """Bound both host pipes. Only this process's adb client may be terminated.

    This never sends kill-server, a phone signal, a remote timeout command, or stdin.
    A stopped client means remote read completion is UNKNOWN, not successful.
    """
    started = time.time()
    deadline = time.monotonic() + timeout
    capture = {"stdout": bytearray(), "stderr": bytearray()}
    result = {"argv": argv, "started_wall_s": started, "exit_code": None,
              "client_timed_out": False, "output_truncated": False, "stdin_bytes": 0,
              "output_limit_bytes": limit, "client_terminated_reason": None}
    env = os.environ.copy()
    for key in ("ADB_SERVER_SOCKET", "ANDROID_ADB_SERVER_PORT", "ANDROID_ADB_SERVER_ADDRESS", "ADB_TRACE"):
        env.pop(key, None)
    process = None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env, start_new_session=True)
        with selectors.DefaultSelector() as poller:
            for name in capture:
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                poller.register(stream, selectors.EVENT_READ, name)
            while poller.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    result["client_timed_out"] = True
                    result["client_terminated_reason"] = "command_timeout"
                    break
                for key, _ in poller.select(min(left, 0.2)):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        poller.unregister(key.fileobj)
                        continue
                    room = limit - sum(len(v) for v in capture.values())
                    capture[key.data].extend(chunk[:room])
                    if len(chunk) > room:
                        result["output_truncated"] = True
                        result["client_terminated_reason"] = "output_limit"
                        break
                if result["client_terminated_reason"]:
                    break
            if not result["client_terminated_reason"]:
                try:
                    result["exit_code"] = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    result["client_timed_out"] = True
                    result["client_terminated_reason"] = "command_timeout"
    except OSError as error:
        result["host_error"] = type(error).__name__ + ": " + str(error)
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=0.2)
                    except subprocess.TimeoutExpired:
                        result["host_client_cleanup_unknown"] = True
            for name in capture:
                stream = getattr(process, name)
                if stream is not None:
                    stream.close()
        result["elapsed_s"] = time.time() - started
        result.update({name: bytes(data) for name, data in capture.items()})
    return result


def save_capture(stem, result):
    metadata = {k: v for k, v in result.items() if k not in ("stdout", "stderr")}
    for name in ("stdout", "stderr"):
        data = result.get(name, b"")
        private_write(stem.with_suffix("." + name + ".bin"), data)
        metadata[name + "_bytes"] = len(data)
        metadata[name + "_sha256"] = digest(data)
    write_json(stem.with_suffix(".json"), metadata)


class ReadOnlyAdb(Adb):
    def __init__(self, args, evidence=None):
        super().__init__(args, evidence)
        self.allowed_commands = base_commands()
        self.deadline = time.monotonic() + args.overall_timeout
        self.transport_lost = False
        self.host, self.port, self.serial = args.adb_host, args.adb_port, args.serial

    def allow_observed_user(self, user_id):
        self.allowed_commands.update(user_commands(user_id))

    def command(self, command, *, label="command", input_data=None, timeout=None, allowed=(0,), raw=False):
        command = tuple(command)
        if input_data is not None or command not in self.allowed_commands:
            raise DriverError("command or stdin outside read-only inventory allowlist")
        if self.sequence >= MAX_COMMANDS or self.transport_lost:
            raise DriverError("inventory command budget exhausted or selected transport lost")
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise DriverError("overall inventory deadline elapsed; no command sent")
        self.sequence += 1
        argv = self.base + ["shell", "-T", shlex.join(command)]
        result = _shell_v2_read(self.host, self.port, self.serial, command,
                                min(timeout or self.timeout, self.timeout, left), self.allowed_commands[command])
        result["equivalent_adb_argv_not_executed"] = argv
        if self.evidence is not None:
            safe_label = re.sub(r"[^a-zA-Z0-9_-]", "_", label)
            save_capture(self.evidence / "commands" / ("%05d-%s" % (self.sequence, safe_label)), result)
        if result.get("transport_error"):
            self.transport_lost = True
        if (result.get("host_error") or result["client_timed_out"] or result["output_truncated"]
                or result["exit_code"] not in allowed):
            reason = (result.get("client_terminated_reason") or result.get("host_error")
                      or "exit " + str(result["exit_code"]))
            raise DriverError(label + ": " + reason + "; observation UNKNOWN")
        return result["exit_code"], result["stdout"]


def _socket_read_exact(channel, length, deadline):
    chunks = bytearray()
    while len(chunks) < length:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("existing ADB socket deadline")
        channel.settimeout(left)
        data = channel.recv(length - len(chunks))
        if not data:
            raise DriverError("existing ADB socket closed before a complete response")
        chunks.extend(data)
    return bytes(chunks)


def _send_smart_service(channel, service, deadline):
    encoded = service.encode("utf-8")
    if len(encoded) > 65535:
        raise DriverError("ADB service request exceeds fixed protocol bound")
    channel.settimeout(max(0.001, deadline - time.monotonic()))
    channel.sendall(("%04x" % len(encoded)).encode("ascii") + encoded)
    status = _socket_read_exact(channel, 4, deadline)
    if status == b"FAIL":
        # Never follow an error with start-server, kill-server, a feature fallback,
        # another device, or a legacy shell lacking remote exit status.
        length = _socket_read_exact(channel, 4, deadline)
        if re.fullmatch(rb"[0-9a-fA-F]{4}", length):
            _socket_read_exact(channel, int(length, 16), deadline)
        raise DriverError("existing ADB server rejected the exact read-only service")
    if status != b"OKAY":
        raise DriverError("unexpected existing ADB service response")


def _shell_v2_read(host, port, serial, command, timeout, limit):
    """No ADB executable is used for phone reads, so no implicit daemon restart.

    shell-v2 packets are a one-byte stream ID plus a four-byte little-endian length.
    IDs 1/2 retain separate stdout/stderr; ID 3 carries the remote exit byte. Closing
    this socket after a cap/timeout only abandons a read; its completion stays UNKNOWN.
    """
    command = tuple(command)
    permitted = base_commands()
    # Also defend the low-level entry point. Only the fixed templates may include
    # a bounded numeric Android user; there is no generic shell-command facility.
    if "--user" in command:
        offset = command.index("--user")
        if offset + 1 < len(command) and re.fullmatch(r"[0-9]{1,5}", command[offset + 1]):
            permitted.update(user_commands(int(command[offset + 1])))
    if command not in permitted or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", serial):
        raise DriverError("read-only shell-v2 command/device is outside its allowlist")
    if not math.isfinite(timeout) or not 0 < timeout <= 30 or not 1 <= limit <= permitted[command]:
        raise DriverError("read-only shell-v2 timeout/output bound invalid")
    started = time.time()
    deadline = time.monotonic() + timeout
    streams = {1: bytearray(), 2: bytearray()}
    result = {"transport": "existing_adb_smart_socket_shell_v2", "adb_host": host, "adb_port": port,
              "serial": serial, "remote_command": list(command), "started_wall_s": started,
              "exit_code": None, "exit_code_source": "remote_shell_v2_exit_packet",
              "client_timed_out": False, "output_truncated": False, "stdin_bytes": 0,
              "output_limit_bytes": limit, "client_terminated_reason": None}
    try:
        with socket.create_connection((host, port), timeout=timeout) as channel:
            _send_smart_service(channel, "host:transport:" + serial, deadline)
            _send_smart_service(channel, "shell,v2,raw:" + shlex.join(command), deadline)
            channel.sendall(b"\x04\x00\x00\x00\x00")  # Close shell stdin; send no input data.
            while True:
                header = _socket_read_exact(channel, 5, deadline)
                stream, length = header[0], int.from_bytes(header[1:], "little")
                if stream == 3:
                    if length != 1:
                        raise DriverError("invalid shell-v2 remote exit packet")
                    result["exit_code"] = _socket_read_exact(channel, 1, deadline)[0]
                    break
                if stream not in streams:
                    raise DriverError("unexpected shell-v2 output stream")
                room = limit - sum(map(len, streams.values()))
                streams[stream].extend(_socket_read_exact(channel, min(length, room), deadline))
                if length > room:
                    result["output_truncated"] = True
                    result["client_terminated_reason"] = "output_limit"
                    break
    except (TimeoutError, socket.timeout):
        result["client_timed_out"] = True
        result["client_terminated_reason"] = "socket_timeout"
    except (OSError, DriverError) as error:
        result["host_error"] = type(error).__name__ + ": " + str(error)
        result["transport_error"] = True
    finally:
        result["stdout"], result["stderr"] = bytes(streams[1]), bytes(streams[2])
        result["elapsed_s"] = time.time() - started
    return result


def _smart_request(host, port, request, timeout):
    """Read an ALREADY listening ADB smart socket. Never invokes a server-start path."""
    if request not in ("host:version", "host:devices-l"):
        raise DriverError("non-read-only ADB smart-socket request")
    deadline = time.monotonic() + timeout
    with socket.create_connection((host, port), timeout=timeout) as channel:
        _send_smart_service(channel, request, deadline)
        size_text = _socket_read_exact(channel, 4, deadline)
        if not re.fullmatch(rb"[0-9a-fA-F]{4}", size_text):
            raise DriverError("invalid existing ADB payload length")
        return _socket_read_exact(channel, int(size_text, 16), deadline)


def socket_observation(args, directory, request, phase):
    started = time.time()
    stem = directory / "server" / (phase + "-" + request.replace(":", "-"))
    result = {"request": request, "adb_host": args.adb_host, "adb_port": args.adb_port,
              "started_wall_s": started, "stdout": b"", "stderr": b""}
    try:
        result["stdout"] = _smart_request(args.adb_host, args.adb_port, request, args.command_timeout)
        result["status"] = "OBSERVED"
        return result["stdout"]
    except (OSError, DriverError) as error:
        result["status"] = "UNKNOWN"
        result["error"] = type(error).__name__ + ": " + str(error)
        raise DriverError("existing ADB socket " + request + " unavailable; no server start/reset attempted") from error
    finally:
        result["elapsed_s"] = time.time() - started
        save_capture(stem, result)


def connected_device(data, serial):
    devices = []
    for line in data.decode("utf-8").splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 2:
            raise DriverError("malformed ADB connected-device record")
        row = {"serial": fields[0], "state": fields[1]}
        for field in fields[2:]:
            key, sep, value = field.partition(":")
            if sep and key in ("product", "model", "device", "transport_id"):
                if key in row:
                    raise DriverError("duplicate ADB device property")
                row[key] = value
        devices.append(row)
    matches = [row for row in devices if row["serial"] == serial]
    if len(matches) != 1 or matches[0]["state"] != "device":
        raise DriverError("explicit serial is not one uniquely online device on the existing server")
    return {"selected": matches[0], "connected_record_count": len(devices)}


def require_existing_adb_server(args, evidence_directory, phase="before"):
    """Reusable suite preflight. args supplies adb/adb_host/adb_port/serial/command_timeout.

    The directory must already be a private host evidence directory. This reads the
    existing smart socket and runs only local `adb version`; it never starts/resets a
    server or issues a phone command. Subsequent ordinary adb CLI calls retain their
    own version-check race; use ReadOnlyAdb for a read path without implicit restart.
    """
    validate_connection(args)
    directory = Path(evidence_directory)
    if not directory.is_dir() or directory.is_symlink() or directory.stat().st_mode & 0o077:
        raise DriverError("existing-server evidence directory must be private")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", phase):
        raise DriverError("invalid evidence phase")
    version = _run_bounded([str(Path(args.adb).expanduser()), "version"], args.command_timeout, 32768)
    save_capture(directory / "server" / (phase + "-host-adb-version"), version)
    parsed = re.search(rb"Android Debug Bridge version 1\.0\.(\d+)\b", version["stdout"])
    if version["exit_code"] != 0 or version["client_timed_out"] or version["output_truncated"] or not parsed:
        raise DriverError("host ADB protocol version not established; no phone command sent")
    server = socket_observation(args, directory, "host:version", phase)
    if not re.fullmatch(rb"[0-9a-fA-F]{4}", server) or int(server, 16) != int(parsed.group(1)):
        raise DriverError("existing ADB server/client protocol mismatch; refuse automatic replacement")
    connected = connected_device(socket_observation(args, directory, "host:devices-l", phase), args.serial)
    return {"server_protocol_hex": server.decode("ascii"), "local_client_protocol": int(parsed.group(1)),
            "connected": connected, "server_start_or_reset_requested": False}


def scalar(data):
    value = data.decode("utf-8").strip()
    if (not value or value.lower() in ("unknown", "null", "none", "n/a", "undefined", "(null)")
            or len(value) > 2048 or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise DriverError("missing or malformed scalar observation")
    return value


def integer(data, minimum=0, maximum=2**63 - 1):
    value = scalar(data)
    if not re.fullmatch(r"[0-9]+", value) or not minimum <= int(value) <= maximum:
        raise DriverError("invalid bounded integer observation")
    return int(value)


def parse_meminfo(data):
    known = ("MemTotal", "MemAvailable", "MemFree", "Buffers", "Cached", "SReclaimable", "Shmem", "SwapTotal", "SwapFree")
    values = {}
    for name, raw in re.findall(r"(?m)^([A-Za-z_()]+):\s+(\d+) kB\s*$", data.decode("ascii")):
        if name in known:
            if name in values:
                raise DriverError("duplicate kernel memory metric")
            values[name] = int(raw) * 1024
    total = values.get("MemTotal")
    if total is None or total <= 0:
        raise DriverError("kernel MemTotal missing or invalid")
    for key in ("MemFree", "MemAvailable"):
        if key in values and not 0 <= values[key] <= total:
            raise DriverError("inconsistent kernel " + key)
    if values.get("SwapFree", 0) > values.get("SwapTotal", 0):
        raise DriverError("inconsistent swap metrics")
    return {"kernel_source": "/proc/meminfo", "kernel_label_kB_means_bytes": 1024,
            "kernel_metrics_bytes": values, "kernel_memavailable_bytes": values.get("MemAvailable"),
            "kernel_memfree_bytes": values.get("MemFree"),
            "activity_manager_avail_mem_bytes": None, "activity_manager_avail_mem_status": "NOT_OBSERVED",
            "model_memory_budget_bytes": None, "swap_counted_as_ram": False,
            "memavailable_estimated_from_free_or_cache": False}


def parse_packages(data):
    found = {}
    for line in data.decode("utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"package:([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+|android)(.*)", line.strip())
        if not match:
            raise DriverError("malformed package-manager catalogue")
        package, suffix = match.groups()
        pairs = re.findall(r"\b(versionCode|uid):(\d+)\b", suffix)
        values = {k: int(v) for k, v in pairs}
        if len(pairs) != 2 or len(values) != 2 or package in found:
            raise DriverError("package UID/version missing, duplicate, or ambiguous")
        found[package] = {"package": package, "version_code": values["versionCode"], "uid": values["uid"]}
    return found


def section_lines(text, heading):
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == heading + ":":
            indent = len(line) - len(line.lstrip())
            found = []
            for value in lines[i + 1:]:
                if not value.strip():
                    continue
                if len(value) - len(value.lstrip()) <= indent:
                    break
                found.append(value.strip())
            return found
    return None


def parse_package_dump(data, user_id):
    text = data.decode("utf-8")
    header = re.search(r"(?m)^\s*Package \[" + re.escape(PACKAGE) + r"\] \([^\r\n]*\):\s*$", text)
    if not header:
        raise DriverError("exact installed target package absent from dumpsys")
    block = text[header.end():]
    other = re.search(r"(?m)^\s*Package \[", block)
    if other:
        block = block[:other.start()]
    def one(pattern):
        matches = re.findall(pattern, block, re.M)
        if len(matches) != 1:
            return None
        return matches[0]
    version = one(r"^\s*versionCode=(\d+)\b.*$")
    app_id = one(r"^\s*(?:userId|appId)=(\d+)\s*$")
    name = one(r"^\s*versionName=([^\r\n]+)$")
    user = one(r"^\s*User " + str(user_id) + r":([^\r\n]+)$")
    requested = section_lines(block, "requested permissions")
    permissions = None if requested is None else [x for x in requested if re.fullmatch(r"[A-Za-z0-9_.]+", x)]
    native = {}
    for kind in ("usesNativeLibraries", "usesOptionalNativeLibraries"):
        values = section_lines(block, kind)
        inline = one(r"^\s*" + kind + r":\s*\[([^\r\n]*)\]\s*$")
        if inline is not None:
            values = [x.strip() for x in inline.split(",") if x.strip()]
        if values is not None and any(not re.fullmatch(r"[A-Za-z0-9_.+-]+\.so", x) for x in values):
            raise DriverError("malformed native-library declaration")
        native[kind] = values
    grants = []
    for permission, granted in re.findall(r"(?m)^\s*([A-Za-z0-9_.]+): granted=(true|false)\b", block):
        grants.append({"permission": permission, "granted": granted == "true"})
    return {"package": PACKAGE, "version_code": int(version) if version else None,
            "version_name": name.strip() if name else None, "app_id": int(app_id) if app_id else None,
            "current_user_installed": bool(user and re.search(r"\binstalled=true\b", user)),
            "current_user_state_line": user, "requested_permissions": permissions,
            "permission_grant_lines": grants, "permission_grant_scope": "package dump; each user section retained in raw receipt",
            "internet_permission_declared": None if permissions is None else "android.permission.INTERNET" in permissions,
            "native_library_declarations": native,
            "native_library_declaration_status": "OBSERVED" if any(v is not None for v in native.values()) else "UNKNOWN",
            "native_library_dir": one(r"^\s*(?:legacyNativeLibraryDir|nativeLibraryDir)=([^\r\n]+)$"),
            "primary_cpu_abi": one(r"^\s*primaryCpuAbi=([^\r\n]+)$"),
            "binary_or_manifest_bytes_verified": False}


def parse_launchers(data):
    text = data.decode("utf-8").strip()
    if text == "No activities found":
        return []
    if not text:
        raise DriverError("empty launcher query does not establish an empty catalogue")
    found = []
    for line in text.splitlines():
        line = line.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]+/[A-Za-z0-9_.$]+", line):
            raise DriverError("unexpected launcher query format")
        found.append(line)
    if len(found) != len(set(found)):
        raise DriverError("duplicate launcher component")
    return sorted(found)


def parse_apk_paths(data):
    paths = []
    for line in data.decode("utf-8").splitlines():
        if not re.fullmatch(r"package:/[A-Za-z0-9_./=+@,~%-]+[.]apk", line):
            raise DriverError("invalid installed APK path record")
        path = line[len("package:"):]
        if ".." in path.split("/") or path in paths:
            raise DriverError("ambiguous installed APK path record")
        paths.append(path)
    if not paths:
        raise DriverError("no installed APK path observed")
    return {"paths": paths, "apk_bytes_read_or_verified": False}


def parse_battery(data):
    text = data.decode("utf-8")
    names = {"level": "level", "scale": "scale", "temperature": "temperature_deci_celsius",
             "voltage": "voltage_millivolts", "status": "android_status", "health": "android_health"}
    value = {"service_updates_stopped": "UPDATES STOPPED" in text}
    for key, output in names.items():
        found = re.findall(r"(?m)^\s*" + key + r":\s*(-?\d+)\s*$", text)
        value[output] = int(found[0]) if len(found) == 1 else None
    raw_temp = value["temperature_deci_celsius"]
    value["temperature_celsius"] = None if raw_temp is None else raw_temp / 10
    if value["level"] is None or value["scale"] is None or value["scale"] <= 0:
        raise DriverError("battery service metrics missing")
    value["battery_percentage"] = 100 * value["level"] / value["scale"]
    return value


def parse_thermal(data):
    text = data.decode("utf-8")
    found = re.findall(r"(?m)^\s*Thermal Status:\s*([0-6])\s*$", text)
    return {"thermal_status": int(found[0]) if len(found) == 1 else None,
            "thermal_status_observed": len(found) == 1,
            "sensor_details": "retained in bounded raw receipt; no temperature units guessed"}


def parse_app_memory(data):
    text = data.decode("utf-8")
    if re.search(r"No process found for:", text):
        return {"process_state": "NO_PROCESS_REPORTED", "processes": [], "app_started_for_measurement": False}
    blocks = re.split(r"(?=\*\* MEMINFO in pid \d+ \[)", text)
    records = []
    for block in blocks:
        match = re.match(r"\*\* MEMINFO in pid (\d+) \[(" + re.escape(PACKAGE) + r"(?::[A-Za-z0-9_.-]+)?)\] \*\*", block)
        if not match:
            continue
        def metric(label):
            values = re.findall(r"\b" + label + r":\s*(\d+)\b", block)
            return int(values[0]) * 1024 if len(values) == 1 else None
        records.append({"pid": int(match.group(1)), "process_name": match.group(2),
                        "pss_bytes": metric("TOTAL PSS"), "rss_bytes": metric("TOTAL RSS"),
                        "swap_pss_bytes": metric("TOTAL SWAP PSS")})
    return {"process_state": "OBSERVED" if records else "UNKNOWN", "processes": records,
            "scope": "only processes returned by dumpsys meminfo for this package; not whole model residency",
            "app_started_for_measurement": False, "pss_rss_summed_together": False}


def parse_projection(data, fields, expected_schema, expected_uid):
    text = data.decode("ascii")
    before = re.findall(r"(?m)^SOURCE_SHA256_BEFORE ([a-f0-9]{64})\s+[^\r\n]+$", text)
    after = re.findall(r"(?m)^SOURCE_SHA256_AFTER ([a-f0-9]{64})\s+[^\r\n]+$", text)
    meta = re.findall(r"(?m)^SOURCE_METADATA (\d+) (\d+) ([0-7]+) (\d+)$", text)
    if len(before) != 1 or before != after or len(meta) != 1:
        raise DriverError("private scalar projection changed during read or lacks source hashes")
    size, uid, mode, links = map(int, meta[0])
    if uid != expected_uid or mode != 600 or links != 1:
        raise DriverError("private state/config ownership or mode is not expected")
    value = {}
    for line in text.splitlines():
        if line.startswith("SOURCE_"):
            continue
        if not line.strip():
            continue
        item = strict_json(("{" + line.strip().removesuffix(",") + "}").encode("ascii"))
        if len(item) != 1:
            raise DriverError("invalid private scalar projection")
        key = next(iter(item))
        if key not in fields or key in value:
            raise DriverError("unexpected or duplicate private state/config field")
        encoded = json.dumps(item[key], separators=(",", ":"))
        if not re.fullmatch(fields[key], encoded):
            raise DriverError("private state/config scalar is outside its type/enum contract")
        value.update(item)
    schemas=("hepta.local-runtime.v1","hepta.local-runtime.v2") if fields is CONFIG_KEYS else (expected_schema,)
    if value.get("schema") not in schemas:
        raise DriverError("private state/config schema not observed")
    required = {"schema", "compute", "context_tokens", "threads"} if fields is CONFIG_KEYS else {"schema", "status", "running", "pending", "cleanup_known", "app_uid"}
    if fields is CONFIG_KEYS:
        if value.get("schema")=="hepta.local-runtime.v2":required.add("model_profile")
        elif "model_profile" in value:raise DriverError("legacy config cannot select a model_profile")
    if not required <= value.keys() or (fields is SESSION_KEYS and value["app_uid"] != expected_uid):
        raise DriverError("private state/config required identity or state missing")
    return {"status": "OBSERVED_PROJECTION", "values": value, "source_sha256": before[0], "source_size_bytes": size,
            "full_source_json_validated": False, "instruction_or_summary_exported": False,
            "inference_claims_independently_verified": False}


def parse_interruption_latch(data):
    value = scalar(data)
    if value not in ("present", "absent"):
        raise DriverError("interruption-latch presence is not established")
    return {"path": INTERRUPTION_LATCH_PATH, "presence": value.upper(), "contents_read": False,
            "existence_only": True, "symlink_empty_or_nonregular_also_counts_as_present": True}


def effective_session_state(observations):
    """A durable interruption latch outranks an old clean base-session receipt."""
    result = {"state": "UNKNOWN", "cleanup_known": None, "latch_presence": "UNKNOWN",
              "base_session_is_unverified_app_report": True, "independently_verified": False,
              "new_task_admission_granted": False, "interruption_latch_overrides_base": True}
    latch = observations.get("app-interruption-latch", {})
    if latch.get("status") != "OBSERVED":
        result["reason"] = "interruption latch was not observed; old base receipt cannot establish quiescence"
        return result
    presence = latch.get("value", {}).get("presence")
    result["latch_presence"] = presence if presence in ("PRESENT", "ABSENT") else "UNKNOWN"
    if presence == "PRESENT":
        result.update(state="INTERRUPTED", cleanup_known=False,
                      reason="fixed interruption latch exists; its contents and the old base receipt cannot override it")
        return result
    if presence != "ABSENT":
        result["reason"] = "interruption latch presence UNKNOWN"
        return result
    session = observations.get("app-session-state", {})
    value = session.get("value", {})
    if session.get("status") != "OBSERVED" or value.get("status") != "OBSERVED_PROJECTION":
        result["reason"] = "base session absent or unavailable; absence does not establish idle"
        return result
    claims = value.get("values", {})
    if claims.get("blocked") is True or claims.get("cleanup_known") is False:
        result.update(state="APP_REPORTED_BLOCKED", cleanup_known=False)
    elif claims.get("running") is True or claims.get("pending") is True:
        result.update(state="APP_REPORTED_ACTIVE", cleanup_known=claims.get("cleanup_known"))
    elif (claims.get("running") is False and claims.get("pending") is False
          and claims.get("blocked") is False and claims.get("cleanup_known") is True):
        result.update(state="APP_REPORTED_QUIESCENT", cleanup_known=True)
    else:
        result["reason"] = "base session lacks complete quiescence claims"
    return result


def planned_identity():
    manifest = Path(__file__).resolve().parents[1] / "AndroidManifest.xml"
    if not manifest.is_file() or manifest.stat().st_size > 131072:
        return {"status": "UNKNOWN", "observed_on_phone": False}
    data = manifest.read_bytes()
    root = ET.fromstring(data)
    ns = "{http://schemas.android.com/apk/res/android}"
    return {"source": str(manifest), "source_sha256": digest(data), "package": root.get("package"),
            "version_code": root.get(ns + "versionCode"), "version_name": root.get(ns + "versionName"),
            "planned_model_sha256": _acceptance.MODEL_SHA256, "observed_on_phone": False,
            "actual_model_bytes_verified": False}


def validate_connection(args):
    executable = Path(args.adb).expanduser()
    if not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise DriverError("--adb must name an existing absolute executable")
    if type(args.adb_port) is not int or not 1 <= args.adb_port <= 65535:
        raise DriverError("explicit valid --adb-port required")
    try:
        ipaddress.ip_address(args.adb_host)
    except ValueError as error:
        raise DriverError("--adb-host must be an explicit IP address; DNS probes are not performed") from error
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", args.serial):
        raise DriverError("explicit valid --serial required")
    if not math.isfinite(args.command_timeout) or not 0.1 <= args.command_timeout <= 30:
        raise DriverError("command timeout must be 0.1..30s")


def validate_args(args):
    validate_connection(args)
    if not math.isfinite(args.overall_timeout) or not 1 <= args.overall_timeout <= 600:
        raise DriverError("overall timeout must be 1..600s")
    directory = Path(args.output).expanduser()
    if not directory.is_absolute():
        raise DriverError("--output must be a new absolute host directory")
    if os.path.lexists(directory):
        raise FileExistsError("inventory refuses an existing output path before any device call")
    return directory


def run_inventory(args):
    import qualification_scope
    binding = qualification_scope.from_args(args)
    qualification_scope.need(binding is not None, "private device binding required before inventory")
    qualification_scope.require_device_target(args, binding)
    directory = validate_args(args)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    directory.chmod(0o700)
    report = {"schema": "hepta.read-only-phone-inventory.v1", "observation_status": "UNKNOWN",
              "started_wall_s": time.time(), "requested_connection": {"adb": args.adb, "host": args.adb_host,
              "port": args.adb_port, "serial": args.serial}, "target_package": PACKAGE,
              "evidence_directory": str(directory), "snapshot_atomic": False, "errors": [], "observations": {},
              "test_verdict": "NOT_RUN", "production_ready": "UNKNOWN", "model_inference_executed": False,
              "app_launched_or_stopped": False, "ui_dumped": False, "settings_read_or_changed": False,
              "task_prompts_exported": False, "adb_server_start_or_reset_requested": False,
              "actual_model_or_runtime_artifact_bytes_verified": False}
    observations = report["observations"]
    adb = None
    identity_missing = []
    try:
        report["planned_candidate_identity"] = planned_identity()
        preflight = require_existing_adb_server(args, directory)
        report["existing_server_preflight"] = preflight
        server = preflight["server_protocol_hex"].encode("ascii")
        connected = preflight["connected"]
        report["connected_device_before"] = connected
        adb = ReadOnlyAdb(args, directory)

        def observe(name, command, parser=scalar, allowed=(0,)):
            try:
                code, data = adb.command(command, label=name, allowed=allowed)
                if code == 40:
                    value = {"status": "ABSENT", "effective_setting": "UNKNOWN"}
                else:
                    value = parser(data)
                observations[name] = {"status": "OBSERVED", "value": value}
                return value
            except (DriverError, OSError, ValueError, UnicodeError, TypeError) as error:
                observations[name] = {"status": "UNKNOWN", "error": str(error)}
                report["errors"].append(name + ": " + str(error))
                return None

        properties = {}
        for prop in PROPERTIES:
            properties[prop] = observe("property-" + prop.replace(".", "-"), ["getprop", prop])
        report["observed_device_properties"] = properties
        page_size = observe("kernel-page-size", ["getconf", "PAGESIZE"], lambda b: integer(b, 4096, 65536))
        if page_size is not None and page_size not in (4096, 16384, 65536):
            identity_missing.append("unsupported or invalid page size")
        user = observe("android-user", ["cmd", "activity", "get-current-user"], lambda b: integer(b, 0, 21474))
        memory = observe("kernel-memory", ["cat", "/proc/meminfo"], parse_meminfo)
        observe("memory-pressure", ["cat", "/proc/pressure/memory"], lambda b: b.decode("ascii"))
        observe("battery", ["dumpsys", "battery"], parse_battery)
        thermal = observe("thermal", ["dumpsys", "thermalservice"], parse_thermal)
        if thermal is not None and not thermal["thermal_status_observed"]:
            report["errors"].append("thermal status unavailable in captured service output")
        target, details, app_uid = None, None, None
        if user is not None:
            adb.allow_observed_user(user)
            common = ["cmd", "package", "list", "packages", "--user", str(user), "-U", "--show-versioncode"]
            target_list = observe("target-package-list", common + [PACKAGE], parse_packages)
            target = (target_list or {}).get(PACKAGE)
            details = observe("target-package-details", ["dumpsys", "package", PACKAGE], lambda b: parse_package_dump(b, user))
            if details is not None and details["native_library_declaration_status"] == "UNKNOWN":
                report["errors"].append("installed native-library declarations unavailable in package dump; not inferred from host manifest")
            catalogue = observe("installed-packages", common, parse_packages)
            launchers = observe("launchable-components", ["cmd", "package", "query-activities", "--brief", "--components", "--user", str(user),
                                "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER"], parse_launchers)
            report["launchable_catalogue"] = None if launchers is None else [
                {"component": c, "package_metadata": (catalogue or {}).get(c.split("/")[0]), "label": None} for c in launchers]
            observe("installed-apk-paths", ["cmd", "package", "path", "--user", str(user), PACKAGE], parse_apk_paths)
            app_memory = observe("app-process-memory", ["dumpsys", "meminfo", PACKAGE], parse_app_memory)
            if app_memory is not None and app_memory["process_state"] == "UNKNOWN":
                report["errors"].append("app process memory snapshot is not parseable; raw receipt retained")
            if target and details and details["app_id"] is not None:
                expected_uid = user * 100000 + details["app_id"]
                if (target["uid"] == expected_uid and target["version_code"] == details["version_code"]
                        and details["version_name"] and details["current_user_installed"]):
                    app_uid = target["uid"]
                else:
                    identity_missing.append("installed package UID/version/user disagree")
            if app_uid is not None:
                run_as_uid = observe("app-sandbox-uid", ["run-as", PACKAGE, "--user", str(user), "id", "-u"], integer)
                if run_as_uid == app_uid:
                    observe("app-session-state", ["run-as", PACKAGE, "--user", str(user), "sh", "-c", SESSION_SCRIPT],
                            lambda b: parse_projection(b, SESSION_KEYS, "hepta.local-session.v1", app_uid), allowed=(0, 40))
                    # Observe the interruption marker after the base receipt. This
                    # preserves its higher authority without reading its contents.
                    observe("app-interruption-latch", ["run-as", PACKAGE, "--user", str(user), "sh", "-c", INTERRUPTION_LATCH_SCRIPT],
                            parse_interruption_latch)
                    observe("app-runtime-config", ["run-as", PACKAGE, "--user", str(user), "sh", "-c", CONFIG_SCRIPT],
                            lambda b: parse_projection(b, CONFIG_KEYS, "hepta.local-runtime.v1", app_uid), allowed=(0, 40))
                else:
                    report["errors"].append("app-private state/config unavailable for the observed package UID; no privilege change attempted")
            else:
                identity_missing.append("installed target package identity incomplete")
        else:
            identity_missing.append("current Android user unknown; no user-scoped queries sent")

        report["installed_app_identity"] = {"package_manager": target, "package_details": details,
                                              "actual_uid": app_uid, "observed_on_phone": app_uid is not None}
        planned = report["planned_candidate_identity"]
        report["installed_matches_planned_version"] = None if not details else (
            planned.get("package") == PACKAGE and str(details.get("version_code")) == planned.get("version_code")
            and details.get("version_name") == planned.get("version_name"))
        report["matching_version_does_not_verify_installed_bytes"] = True
        end_user = observe("android-user-after", ["cmd", "activity", "get-current-user"], lambda b: integer(b, 0, 21474))
        end_fingerprint = observe("build-fingerprint-after", ["getprop", "ro.build.fingerprint"])
        end_server = socket_observation(args, directory, "host:version", "after")
        end_connected = connected_device(socket_observation(args, directory, "host:devices-l", "after"), args.serial)
        report["connected_device_after"] = end_connected
        continuity = (end_server == server and end_connected["selected"] == connected["selected"]
                      and user is not None and end_user == user
                      and end_fingerprint is not None and end_fingerprint == properties.get("ro.build.fingerprint"))
        report["transport_user_build_stable_between_observations"] = continuity
        if not continuity:
            identity_missing.append("device transport/user/build continuity unknown or changed")
        for key in ("ro.product.model", "ro.product.device", "ro.soc.model", "ro.product.cpu.abilist",
                    "ro.build.version.release", "ro.build.version.sdk", "ro.build.fingerprint"):
            if properties.get(key) is None:
                identity_missing.append(key)
        sdk = properties.get("ro.build.version.sdk") or ""
        if not re.fullmatch(r"[1-9][0-9]{0,2}", sdk):
            identity_missing.append("invalid Android SDK identity")
        abi = properties.get("ro.product.cpu.abilist") or ""
        known_abis = {"arm64-v8a", "armeabi-v7a", "armeabi", "x86", "x86_64", "mips", "mips64", "riscv64"}
        if not abi or not set(abi.split(",")) <= known_abis or len(abi.split(",")) != len(set(abi.split(","))):
            identity_missing.append("invalid ABI list identity")
        if page_size is None:
            identity_missing.append("kernel page size UNKNOWN")
        if memory is None or memory.get("kernel_memavailable_bytes") is None:
            identity_missing.append("kernel MemTotal/MemAvailable incomplete")
        if app_uid is None:
            identity_missing.append("installed app UID/version UNKNOWN")
        report["identity_status"] = "UNKNOWN" if identity_missing else "OBSERVED"
        report["observation_status"] = "UNKNOWN" if identity_missing else "PARTIAL" if report["errors"] else "OBSERVED"
    except (DriverError, OSError, ValueError, UnicodeError, TypeError, ET.ParseError) as error:
        report["errors"].append(str(error))
        report["identity_status"] = "UNKNOWN"
    finally:
        report["effective_session_state"] = effective_session_state(observations)
        report["identity_missing_or_invalid"] = identity_missing
        report["finished_wall_s"] = time.time()
        report["remote_command_count"] = 0 if adb is None else adb.sequence
        report["remote_command_limit"] = MAX_COMMANDS
        report["existing_private_file_absence_is_not_effective_default_proof"] = True
        write_json(directory / "inventory.json", report)
        files = [{"path": str(p.relative_to(directory)), "bytes": p.stat().st_size, "sha256": digest(p.read_bytes())}
                 for p in sorted(directory.rglob("*")) if p.is_file() and p.name != "file-manifest.json"]
        write_json(directory / "file-manifest.json", {"schema": "hepta.inventory-file-manifest.v1", "files": files,
                   "manifest_self_hash_omitted": True, "phone_mutations": False})
    print(json.dumps({"observation_status": report["observation_status"], "identity_status": report.get("identity_status", "UNKNOWN"),
                      "test_verdict": "NOT_RUN", "production_ready": "UNKNOWN", "evidence_directory": str(directory),
                      "remote_command_count": report["remote_command_count"], "errors": report["errors"]}, ensure_ascii=False, indent=2))
    return 0 if report["observation_status"] == "OBSERVED" else 3


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    import qualification_scope
    qualification_scope.add_arguments(value)
    value.add_argument("--adb", required=True, help="exact existing absolute host ADB executable")
    value.add_argument("--adb-host", default="127.0.0.1", help="existing server IP; no hostname discovery")
    value.add_argument("--adb-port", required=True, type=int, help="exact existing server port; no implicit 5037")
    value.add_argument("--serial", required=True, help="exact online serial on that server")
    value.add_argument("--output", required=True, type=Path, help="new private absolute HOST evidence directory; parent must exist")
    value.add_argument("--command-timeout", type=float, default=10, help="bounded 0.1..30 seconds per command")
    value.add_argument("--overall-timeout", type=float, default=180, help="bounded 1..600 seconds for remote command collection")
    return value


def main(argv=None):
    return run_inventory(parser().parse_args(argv))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (DriverError, OSError, ValueError) as error:
        print(json.dumps({"inventory_error": str(error), "observation_status": "UNKNOWN",
                          "test_verdict": "NOT_RUN", "phone_actions_retried": False}, ensure_ascii=False), file=sys.stderr)
        sys.exit(2)
