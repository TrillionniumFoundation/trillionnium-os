#!/usr/bin/env python3
"""Real Codex decisions to owner-open JSONL; this process never executes tools.

The transport and executor remain separate. A persisted turn identity cannot be
reused after EOF, cancellation, timeout or a lost result. Credentials stay in the
existing host Codex login; no credentials are read by this adapter.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import select
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).parent))
from provider_openai_compatible import Adapter, ProviderError, PROTOCOL, MAX_LINE, decode, known_tool_result

SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "kind": {"type": "string", "enum": ["tool.call", "turn.complete"]},
        "call_id": {"type": "string"},
        "tool": {"type": "string", "enum": ["shell.exec", "adb.exec", "none"]},
        "command": {"type": "string"},
        "argv": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"},
    },
    "required": ["kind", "call_id", "tool", "command", "argv", "summary"],
}

def selected_tool_disable_notice(item):
    # This exact client startup diagnostic confirms the explicitly disabled
    # code-mode host. It is not an inference error or a tool invocation.
    return (item.get("type") == "error" and item.get("message") ==
            "Code Mode is unavailable because code-mode host is disabled. Code mode will fail closed; enable `features.code_mode_host` and install `codex-code-mode-host`.")

class CodexAdapter(Adapter):
    def __init__(self, args, source, sink, run_dir):
        super().__init__({"max_rounds": 8, "max_tool_calls": 16}, source, sink)
        self.args, self.run_dir, self.round = args, run_dir, 0
        self.frames = open(run_dir / "provider-out.jsonl", "a", buffering=1)
        self.inputs = open(run_dir / "provider-in.jsonl", "ab", buffering=0)
        self.claimed = False
        self.input_partial = bytearray()
        self.input_bytes = 0
        self.dispatched_calls = set()
        self.pending_call_id = None
        self.terminal = None

    def reader(self):
        # The serial host relay reads its socket in receive(), without a blocked
        # daemon reader or unbounded queue surviving a cancelled connection.
        return

    def atomic_record(self, path, value):
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
        temporary = path.with_suffix(path.suffix + ".new")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)

    def emit(self, kind, **fields):
        if self.terminal is not None:
            raise ProviderError("provider already persisted a terminal")
        raw = json.dumps({"protocol": PROTOCOL, "kind": kind,
                          "seq": self.out_seq, **fields}, ensure_ascii=False,
                         separators=(",", ":")) + "\n"
        if len(raw.encode()) > MAX_LINE:
            raise ProviderError("provider output exceeds frame bound")
        if kind == "tool.call":
            if not self.claimed:
                raise ProviderError("tool dispatch requires persisted accepted turn")
            call_id = fields["call"]["call_id"]
            if call_id in self.dispatched_calls:
                raise ProviderError("call identity already dispatched; no redispatch")
            self.dispatched_calls.add(call_id)
            self.pending_call_id = call_id
            signature = hashlib.sha256(json.dumps(fields["call"], sort_keys=True,
                                                  separators=(",", ":")).encode()).hexdigest()
            self.atomic_record(self.run_dir / f"dispatch-{self.tool_count:03d}.json",
                               {"call": fields["call"], "call_sha256": signature,
                                "state": "dispatch_intent_persisted; result may be unknown"})
        if kind in {"turn.complete", "turn.cancelled", "turn.fail"}:
            self.terminal = kind
            self.atomic_record(self.run_dir / "terminal.json",
                               {"kind": kind, "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "claimed": self.claimed, **fields})
        self.frames.write(raw)
        self.frames.flush()
        os.fsync(self.frames.fileno())
        super().emit(kind, **fields)

    def receive(self, expected=None, timeout=0.05):
        if self.session_deadline is not None and time.monotonic() >= self.session_deadline:
            raise ProviderError("Host session deadline expired; no redispatch")
        if b"\n" not in self.input_partial:
            fd = self.source.fileno()
            if not select.select([fd], [], [], timeout)[0]:
                return None
            raw = os.read(fd, min(65536, MAX_LINE + 1 - len(self.input_partial)))
            if not raw:
                raise ProviderError("Host transport closed; accepted outcome unknown; no redispatch")
            self.input_bytes += len(raw)
            if self.input_bytes > 16 * MAX_LINE:
                raise ProviderError("Host session exceeds byte bound")
            self.input_partial.extend(raw)
        if b"\n" not in self.input_partial:
            if len(self.input_partial) >= MAX_LINE:
                raise ProviderError("Host frame exceeds byte bound")
            return None
        end = self.input_partial.index(10) + 1
        if end > MAX_LINE:
            raise ProviderError("Host frame exceeds byte bound")
        raw = bytes(self.input_partial[:end])
        del self.input_partial[:end]
        value = decode(raw)
        if (value.get("protocol") != PROTOCOL or type(value.get("seq")) is not int
                or value["seq"] != self.in_seq or self.in_seq >= 128):
            raise ProviderError("Host protocol, sequence or frame count differs")
        self.in_seq += 1
        self.inputs.write(raw)
        os.fsync(self.inputs.fileno())
        if value.get("kind") == "turn.cancel":
            self.cancelled.set()
            return None
        if value.get("kind") != expected:
            raise ProviderError("Host sent an unexpected frame")
        if expected == "tool.result":
            if value.get("call_id") != self.pending_call_id:
                raise ProviderError("Host result identity differs; effect remains unknown")
            call_key = hashlib.sha256(self.pending_call_id.encode()).hexdigest()
            self.atomic_record(self.run_dir / f"result-{call_key}.json", value)
            if not known_tool_result(value):
                raise ProviderError("Host result is not confirmed completed; outcome unknown; no semantic redispatch")
            self.pending_call_id = None
        if value is not None and expected == "turn.start":
            turn = value.get("turn", {})
            names = ("session_id", "profile_id", "task_id", "turn_id", "turn_stream_id")
            if (not isinstance(turn, dict) or any(not isinstance(turn.get(n), str)
                    or not 0 < len(turn[n].encode()) <= 256 or "\0" in turn[n] for n in names)):
                raise ProviderError("turn identity missing")
            # A replacement stream is never a new semantic turn. Keep the
            # stream ID as evidence, but exclude it from accepted identity.
            identity = json.dumps([turn[n] for n in names[:-1]], separators=(",", ":")).encode()
            key = hashlib.sha256(identity).hexdigest()
            claim = self.args.evidence / "claims" / key
            try:
                fd = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                raise ProviderError("turn identity already accepted; outcome unknown; no redispatch")
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(json.dumps({"identity": {n:turn[n] for n in names},
                        "request_sha256": hashlib.sha256(str(turn.get("user_input", "")).encode()).hexdigest(),
                        "run_dir": str(self.run_dir), "state": "accepted_no_redispatch"}).encode())
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            parent = os.open(claim.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            self.claimed = True
        return value

    def completion(self, messages):
        self.round += 1
        prefix = self.run_dir / f"codex-{self.round:02d}"
        schema_path = prefix.with_suffix(".schema.json")
        answer_path = prefix.with_suffix(".answer.json")
        schema_path.write_text(json.dumps(SCHEMA))
        instruction = (
            "You are the sole semantic provider for an owner-open phone turn. "
            "You have no direct host/device tools. Return only the requested structured decision. "
            "Use tool.call to ask the separate Host executor to perform the owner's action. "
            "Preserve exact requested shell command or adb argv. Use one call at a time, with "
            "a unique call_id. For shell.exec argv must be empty; for adb.exec command must "
            "be empty. Do not fabricate results. Once a tool result is accepted, never repeat "
            "its effect for uncertainty, cancellation, transport loss or failure. For completion "
            "set tool=none, command='', argv=[], call_id='' and report the observed evidence. "
            "No filesystem reads, searches, tools, or unrelated actions. The following JSON "
            "is the actual turn transcript, including externally returned tool evidence:\n"
            + json.dumps(messages, ensure_ascii=False)
        )
        argv = [self.args.codex, "exec", "--json", "--ephemeral", "--ignore-user-config",
                "--skip-git-repo-check", "--sandbox", "read-only", "--model", self.args.model,
                "--output-schema", str(schema_path), "--output-last-message", str(answer_path),
                "-C", str(self.args.cwd), "-c", 'web_search="disabled"',
                "-c", 'model_reasoning_effort="low"', "-c", 'mcp_servers={}',
                "-c", 'suppress_unstable_features_warning=true',
                "--enable", "skip_host_skill_discovery"]
        for feature in ["shell_tool", "unified_exec", "unified_exec_tty", "shell_snapshot",
                        "code_mode", "code_mode_host", "code_mode_only", "code_mode_interrupt",
                        "apps", "plugins", "hooks", "remote_plugin", "browser_use",
                        "browser_use_external", "browser_use_full_cdp_access", "in_app_browser",
                        "computer_use", "multi_agent", "multi_agent_v2", "view_image", "image_generation",
                        "sleep_tool", "goals", "skill_search", "workspace_dependencies", "tool_suggest",
                        "auth_elicitation", "in_app_local_automation", "realtime_conversation",
                        "unbounded_connection_retries"]:
            argv += ["--disable", feature]
        argv += ["-"]
        # Redacted by construction: argv contains no token and no user text.
        prefix.with_suffix(".argv.json").write_text(json.dumps(argv))
        payload = instruction.encode()
        if len(payload) > 8 * MAX_LINE:
            raise ProviderError("Codex transcript exceeds request bound")
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
        streams = selectors.DefaultSelector()
        stdout, stderr = bytearray(), bytearray()
        event_partial, event_count = bytearray(), 0
        for pipe, name in [(process.stdout, "stdout"), (process.stderr, "stderr")]:
            os.set_blocking(pipe.fileno(), False)
            streams.register(pipe, selectors.EVENT_READ, name)
        os.set_blocking(process.stdin.fileno(), False)
        streams.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        sent = 0
        deadline = time.monotonic() + self.args.timeout
        try:
            while True:
                self.receive()
                if self.cancelled.is_set():
                    return None
                if time.monotonic() >= deadline:
                    raise ProviderError("Codex deadline expired; result unknown; no retry")
                if answer_path.exists() and answer_path.stat().st_size > MAX_LINE:
                    raise ProviderError("Codex structured decision exceeds file bound")
                for ready, _mask in streams.select(0.01):
                    pipe, name = ready.fileobj, ready.data
                    if name == "stdin":
                        try:
                            sent += os.write(pipe.fileno(), payload[sent:sent+65536])
                        except BrokenPipeError:
                            sent = len(payload)
                        if sent == len(payload):
                            streams.unregister(pipe)
                            pipe.close()
                    else:
                        chunk = os.read(pipe.fileno(), 65536)
                        if not chunk:
                            streams.unregister(pipe)
                            pipe.close()
                        else:
                            target, maximum = (stdout, 8 * MAX_LINE) if name == "stdout" else (stderr, MAX_LINE)
                            if len(target)+len(chunk) > maximum:
                                raise ProviderError("Codex output exceeded streaming byte bound")
                            target.extend(chunk)
                            if name == "stderr" and b'"invalid_request_error"' in stderr:
                                raise ProviderError("Codex backend rejected the request; no fallback or retry")
                            if name == "stdout":
                                event_partial.extend(chunk)
                                while b"\n" in event_partial:
                                    line, _, rest = event_partial.partition(b"\n")
                                    event_partial = bytearray(rest)
                                    event_count += 1
                                    if len(line) > MAX_LINE or event_count > 4096:
                                        raise ProviderError("Codex event framing exceeds bound")
                                    if not line.strip():
                                        continue
                                    event = decode(line)
                                    item = event.get("item", {})
                                    if event.get("type") in {"error", "turn.failed"}:
                                        raise ProviderError("Codex turn failed; no fallback or retry")
                                    if isinstance(item, dict) and item.get("type") is not None and item["type"] not in {"agent_message", "reasoning"} and not selected_tool_disable_notice(item):
                                        raise ProviderError("Codex emitted an error or unselected host tool; rejected")
                                if len(event_partial) > MAX_LINE:
                                    raise ProviderError("Codex event exceeds frame bound")
                if process.poll() is None or streams.get_map():
                    continue
                prefix.with_suffix(".events.jsonl").write_bytes(bytes(stdout))
                prefix.with_suffix(".stderr.txt").write_bytes(bytes(stderr))
                events = [decode(line) for line in stdout.splitlines() if line.strip()]
                if len(events) > 4096 or any(len(line)>MAX_LINE for line in stdout.splitlines()):
                    raise ProviderError("Codex event framing exceeds bound")
                if process.returncode or not any(x.get("type") == "turn.completed" for x in events):
                    raise ProviderError("Codex turn failed; no fallback or retry")
                allowed_items = {"agent_message", "reasoning"}
                if any(isinstance(x.get("item"), dict) and x["item"].get("type") not in allowed_items and not selected_tool_disable_notice(x["item"]) for x in events):
                    raise ProviderError("Codex used an unselected host tool; decision rejected")
                if not answer_path.exists() or answer_path.stat().st_size > 1024 * 1024:
                    raise ProviderError("Codex structured decision missing or oversized")
                decision = decode(answer_path.read_bytes())
                if set(decision) != set(SCHEMA["required"]):
                    raise ProviderError("Codex decision fields differ")
                if (any(not isinstance(decision[name], str) for name in ("kind", "call_id", "tool", "command", "summary"))
                        or not isinstance(decision["argv"], list)
                        or any(not isinstance(arg, str) for arg in decision["argv"])):
                    raise ProviderError("Codex decision value types differ")
                message = {"role": "assistant", "content": decision["summary"]}
                if decision["kind"] == "turn.complete":
                    if (decision["tool"] != "none" or decision["command"] or decision["argv"]
                            or decision["call_id"]):
                        raise ProviderError("completion contains tool effect fields")
                elif decision["kind"] == "tool.call":
                    if decision["tool"] == "shell.exec" and not decision["argv"]:
                        name, arguments = "shell_exec", {"command": decision["command"]}
                    elif decision["tool"] == "adb.exec" and not decision["command"]:
                        name, arguments = "adb_exec", {"argv": decision["argv"]}
                    else:
                        raise ProviderError("tool selection or argument fields differ")
                    message["tool_calls"] = [{"type": "function", "id": decision["call_id"],
                        "function": {"name": name, "arguments": json.dumps(arguments)}}]
                else:
                    raise ProviderError("Codex decision kind invalid")
                return {"choices": [{"message": message}]}
        finally:
            streams.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            for pipe in (process.stdin, process.stdout, process.stderr):
                if not pipe.closed:
                    pipe.close()
            prefix.with_suffix(".events.jsonl").write_bytes(bytes(stdout))
            prefix.with_suffix(".stderr.txt").write_bytes(bytes(stderr))
            prefix.with_suffix(".status.json").write_text(json.dumps({"returncode": process.returncode,
                "cancelled": self.cancelled.is_set(), "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
                "host_tools_disabled": True, "relay_no_relaunch_fallback_or_redispatch": True,
                "codex_transport_retries": "CLI defaults; relay stops on first reported error",
                "model": self.args.model, "codex": self.args.codex}))

def serve(args):
    os.umask(0o077)
    args.evidence, args.cwd = args.evidence.resolve(), args.cwd.resolve()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    (args.evidence / "claims").mkdir(mode=0o700, exist_ok=True)
    args.cwd.mkdir(mode=0o700, parents=True, exist_ok=True)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.port))
    listener.listen(1)
    listener.settimeout(1)
    shutdown = threading.Event()
    active = [None]
    def stop(_number, _frame):
        shutdown.set()
        if active[0] is not None:
            active[0].cancelled.set()
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, stop)
    print(json.dumps({"ready": True, "loopback_port": args.port, "model": args.model}), flush=True)
    while not shutdown.is_set():
        # Preserve every accepted identity. Stop accepting rather than deleting
        # claims or accumulating unlimited evidence across service restarts.
        total, files = 0, 0
        for directory, _dirs, names in os.walk(args.evidence):
            for name in names:
                total += (Path(directory) / name).stat().st_size
                files += 1
                if total > args.max_evidence_bytes - 256 * MAX_LINE or files > 65536:
                    raise ProviderError("persistent evidence capacity reached; operator rotation required")
        if sum(1 for path in args.evidence.iterdir() if path.is_dir()) >= 1024:
            raise ProviderError("persistent connection capacity reached; operator rotation required")
        available = os.statvfs(args.evidence)
        if available.f_bavail * available.f_frsize < 512 * MAX_LINE:
            raise ProviderError("free evidence capacity insufficient; no turn accepted")
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        if shutdown.is_set():
            connection.close()
            break
        connection.settimeout(10)
        run_dir = args.evidence / (time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(4).hex())
        run_dir.mkdir(mode=0o700)
        source, sink = connection.makefile("rb"), connection.makefile("w")
        adapter = CodexAdapter(args, source, sink, run_dir)
        active[0] = adapter
        try:
            adapter.run()
        except Exception as error:
            try:
                adapter.emit("turn.fail", error=str(error)[:1024])
            except Exception:
                pass
        finally:
            adapter.frames.close()
            adapter.inputs.close()
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            source.close()
            sink.close()
            connection.close()
            active[0] = None
    listener.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--codex", required=True,
                   help="Absolute executable path of the existing host Codex login entrypoint")
    p.add_argument("--model", required=True)
    p.add_argument("--port", type=int, default=18082)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--max-evidence-bytes", type=int, default=2 * 1024 * MAX_LINE)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--cwd", type=Path, required=True)
    args = p.parse_args()
    codex_path = Path(args.codex).expanduser()
    if not codex_path.is_absolute():
        p.error("--codex must be an absolute executable path")
    try:
        codex_path = codex_path.resolve(strict=True)
    except (OSError, RuntimeError):
        p.error("--codex does not resolve to an existing executable")
    if not codex_path.is_file() or not os.access(codex_path, os.X_OK):
        p.error("--codex must resolve to an executable regular file")
    args.codex = str(codex_path)
    if not 1 <= args.timeout <= 300 or not 1 <= args.port <= 65535 or not 512 * MAX_LINE <= args.max_evidence_bytes <= 16 * 1024 * MAX_LINE:
        p.error("timeout or loopback port exceeds service bound")
    serve(args)
