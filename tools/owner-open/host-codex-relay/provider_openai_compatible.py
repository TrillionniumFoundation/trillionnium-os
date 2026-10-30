#!/usr/bin/env python3
"""Owner-selected HTTP model to the bounded owner-open JSONL protocol.

This adapter does not execute tools, choose replacement operations, retry HTTP,
or redispatch an uncertain effect. The Host is the only tool executor. A local
proxy may terminate credentials on AI MAX; no API key is accepted by this file.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import select
import signal
import stat
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PROTOCOL = "trillionnium.owner-open.provider-jsonl.v1"
MAX_LINE = 1024 * 1024
MAX_RESPONSE = 8 * 1024 * 1024


class ProviderError(RuntimeError):
    pass


def unique_pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ProviderError("duplicate JSON member")
        result[key] = value
    return result


def decode(raw):
    def reject_constant(_value):
        raise ProviderError("non-finite JSON value")
    result = json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    if not isinstance(result, dict):
        raise ProviderError("JSON envelope must be an object")
    return result


def known_tool_result(value):
    """Recognize concrete fixture and native Host observations, not semantics.

    Existing/inhibited native calls can be known not to have started. Unknown,
    still accepted/started, and host errors cannot launch another model round.
    A known nonzero exit or invalid request remains evidence for the provider.
    """
    status = value.get("status")
    if not isinstance(status, str):
        return False
    if status in {"completed", "invalid_request"}:
        return True
    if status == "terminal":
        terminal = value.get("terminal")
        return (isinstance(terminal, dict) and isinstance(terminal.get("kind"), str) and terminal["kind"] in {
            "exited", "signaled", "timed_out", "client_cancelled",
            "resource_exhausted", "transport_unavailable", "spawn_failed", "io_error"})
    if status in {"existing", "inhibited"}:
        registry = value.get("registry")
        state = registry.get("state") if isinstance(registry, dict) else None
        return (isinstance(state, str) and (state.startswith("Terminal {")
                or state in {"CancelledBeforeSpawn", "ProvenNotStartedAfterDisconnect"}))
    return False


def load_config(path):
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_mode & 0o022 or not 0 < metadata.st_size <= 65536):
        raise ProviderError("provider config must be a bounded non-writable regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, 65537)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if ((metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ProviderError("provider config changed while read")
    value = decode(raw)
    required = {"schema", "endpoint", "model", "timeout_seconds", "max_rounds",
                "max_tool_calls", "max_tokens", "max_response_bytes"}
    if set(value) != required or value["schema"] != "org.trillionnium.owner-open.http-provider.v1":
        raise ProviderError("provider config schema or fields differ")
    endpoint = urllib.parse.urlsplit(value["endpoint"])
    if (endpoint.scheme not in {"http", "https"} or endpoint.username or endpoint.password
            or endpoint.query or endpoint.fragment or endpoint.path != "/v1/chat/completions"):
        raise ProviderError("provider endpoint is not an exact chat-completions endpoint")
    if endpoint.scheme == "http" and endpoint.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ProviderError("plaintext provider endpoint must be loopback")
    if not isinstance(value["model"], str) or not 0 < len(value["model"]) <= 256:
        raise ProviderError("model identity is missing or oversized")
    for key, maximum in [("timeout_seconds", 300), ("max_rounds", 64),
                         ("max_tool_calls", 128), ("max_tokens", 8192),
                         ("max_response_bytes", MAX_RESPONSE)]:
        if type(value[key]) is not int or not 1 <= value[key] <= maximum:
            raise ProviderError("provider resource limit is invalid")
    return value


TOOLS = [
    {"type": "function", "function": {
        "name": "shell_exec", "description": "Execute the exact owner-requested shell command through the Host.",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string"}, "cwd": {"type": "string"},
            "timeout_ms": {"type": "integer"}}, "required": ["command"],
            "additionalProperties": False}}},
    {"type": "function", "function": {
        "name": "adb_exec", "description": "Pass exact ordinary adb argument bytes to the Host; preserve target selection.",
        "parameters": {"type": "object", "properties": {
            "argv": {"type": "array", "items": {"type": "string"}},
            "timeout_ms": {"type": "integer"}}, "required": ["argv"],
            "additionalProperties": False}}},
]


def tool_call(value, seen):
    if not isinstance(value, dict) or value.get("type") != "function":
        raise ProviderError("model tool call is malformed")
    call_id = value.get("id")
    if (not isinstance(call_id, str) or not 0 < len(call_id) <= 256
            or "\0" in call_id or call_id in seen):
        raise ProviderError("model tool identity is missing, duplicate or invalid")
    function = value.get("function", {})
    names = {"shell_exec": "shell.exec", "adb_exec": "adb.exec"}
    if function.get("name") not in names or not isinstance(function.get("arguments"), str):
        raise ProviderError("model selected an unsupported tool")
    arguments = decode(function["arguments"])
    allowed = {"command", "cwd", "timeout_ms"} if function["name"] == "shell_exec" else {"argv", "timeout_ms"}
    if not set(arguments) <= allowed:
        raise ProviderError("model tool arguments have unknown fields")
    if function["name"] == "shell_exec":
        if not isinstance(arguments.get("command"), str) or not arguments["command"] or "\0" in arguments["command"]:
            raise ProviderError("shell command is missing or invalid")
        if "cwd" in arguments and (not isinstance(arguments["cwd"], str) or "\0" in arguments["cwd"]):
            raise ProviderError("shell cwd is invalid")
    elif (not isinstance(arguments.get("argv"), list) or not arguments["argv"]
          or len(arguments["argv"]) > 4096
          or any(not isinstance(item, str) or "\0" in item for item in arguments["argv"])):
        raise ProviderError("adb argv is invalid")
    if "timeout_ms" in arguments and (type(arguments["timeout_ms"]) is not int
            or not 1 <= arguments["timeout_ms"] <= 86400000):
        raise ProviderError("tool timeout is invalid")
    seen.add(call_id)
    return {"call_id": call_id, "tool": names[function["name"]], **arguments}


class Adapter:
    def __init__(self, config, source=None, sink=None):
        self.config = config
        self.source = source or sys.stdin.buffer
        self.sink = sink or sys.stdout
        self.inbox = queue.Queue(maxsize=2)
        self.cancelled = threading.Event()
        self.out_seq = 0
        self.in_seq = 0
        self.seen = set()
        self.tool_count = 0
        self.reader_stop = threading.Event()
        self.session_deadline = None

    def emit(self, kind, **fields):
        raw = json.dumps({"protocol": PROTOCOL, "kind": kind, "seq": self.out_seq, **fields},
                         ensure_ascii=False, separators=(",", ":"))
        if len(raw.encode()) > MAX_LINE:
            raise ProviderError("provider output exceeds frame bound")
        self.sink.write(raw + "\n")
        self.sink.flush()
        self.out_seq += 1

    def reader(self):
        try:
            fd, partial, total = self.source.fileno(), bytearray(), 0
            while not self.reader_stop.is_set():
                if not select.select([fd], [], [], 0.05)[0]:
                    continue
                raw = os.read(fd, min(65536, MAX_LINE + 1 - len(partial)))
                if not raw:
                    raise ProviderError("Host input ended before terminal")
                total += len(raw)
                if total > 16 * MAX_LINE:
                    raise ProviderError("Host session exceeds byte bound")
                partial.extend(raw)
                while b"\n" in partial:
                    end = partial.index(10) + 1
                    if end > MAX_LINE:
                        raise ProviderError("Host input exceeds frame bound")
                    value = decode(bytes(partial[:end]))
                    del partial[:end]
                    while not self.reader_stop.is_set():
                        try:
                            self.inbox.put(value, timeout=0.05)
                            break
                        except queue.Full:
                            continue
                if len(partial) >= MAX_LINE:
                    raise ProviderError("Host input exceeds frame bound")
        except Exception as error:
            while not self.reader_stop.is_set():
                try:
                    self.inbox.put(error, timeout=0.05)
                    break
                except queue.Full:
                    continue

    def receive(self, expected=None, timeout=0.05):
        if self.session_deadline is not None and time.monotonic() >= self.session_deadline:
            raise ProviderError("Host session deadline expired; no redispatch")
        try:
            value = self.inbox.get(timeout=timeout)
        except queue.Empty:
            return None
        if isinstance(value, Exception):
            raise ProviderError("Host transport closed or malformed")
        if (value.get("protocol") != PROTOCOL or type(value.get("seq")) is not int
                or value.get("seq") != self.in_seq):
            raise ProviderError("Host protocol or sequence differs")
        self.in_seq += 1
        if value.get("kind") == "turn.cancel":
            self.cancelled.set()
            return None
        if value.get("kind") != expected:
            raise ProviderError("Host sent an unexpected frame")
        return value

    def completion(self, messages):
        output = queue.Queue(maxsize=1)
        def work():
            try:
                body = json.dumps({"model": self.config["model"], "messages": messages,
                                   "tools": TOOLS, "tool_choice": "auto", "stream": False,
                                   "parallel_tool_calls": False, "max_tokens": self.config["max_tokens"]}).encode()
                if len(body) > MAX_RESPONSE:
                    raise ProviderError("model request exceeds byte bound")
                request = urllib.request.Request(self.config["endpoint"], body,
                                                 {"Content-Type": "application/json"})
                # No inherited proxy, redirects, authorization header, fallback or retry.
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, *args, **kwargs):
                        return None
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
                with opener.open(request, timeout=self.config["timeout_seconds"]) as response:
                    raw = response.read(self.config["max_response_bytes"] + 1)
                if len(raw) > self.config["max_response_bytes"]:
                    raise ProviderError("model response exceeds byte bound")
                output.put(decode(raw))
            except Exception:
                output.put(ProviderError("model HTTP request failed; no request or effect was retried"))
        threading.Thread(target=work, daemon=True).start()
        deadline = time.monotonic() + self.config["timeout_seconds"] + 1
        while not self.cancelled.is_set():
            self.receive()
            try:
                result = output.get_nowait()
                if isinstance(result, Exception):
                    raise result
                return result
            except queue.Empty:
                if time.monotonic() >= deadline:
                    raise ProviderError("model request deadline expired; result unknown")
        return None

    def run(self):
        self.session_deadline = time.monotonic() + self.config.get("max_duration_seconds", 300)
        thread = threading.Thread(target=self.reader, daemon=True)
        thread.start()
        try:
            return self._run()
        finally:
            self.reader_stop.set()
            thread.join(timeout=0.25)

    def _run(self):
        start = None
        while start is None and not self.cancelled.is_set():
            start = self.receive("turn.start")
        if self.cancelled.is_set():
            self.emit("turn.cancelled", summary="cancelled before model request")
            return
        turn = start.get("turn", {})
        user_input = turn.get("user_input")
        if not isinstance(user_input, str) or not 0 < len(user_input.encode()) <= MAX_LINE // 2:
            raise ProviderError("turn user input is missing or oversized")
        messages = [{"role": "system", "content":
            "You are the owner-selected semantic provider. Use the Host tools for requested actions. "
            "Preserve exact command and argument bytes. Treat uncertain tool results as unknown. "
            "Never repeat an effect to recover missing results. Report the observed result truthfully."},
            {"role": "user", "content": user_input}]
        for _ in range(self.config["max_rounds"]):
            result = self.completion(messages)
            if self.cancelled.is_set():
                break
            choices = result.get("choices")
            if not isinstance(choices, list) or len(choices) != 1:
                raise ProviderError("model choices are missing or ambiguous")
            message = choices[0].get("message", {})
            if not isinstance(message, dict) or message.get("role") != "assistant":
                raise ProviderError("model message is malformed")
            calls = message.get("tool_calls", [])
            content = message.get("content")
            if content is not None and not isinstance(content, str):
                raise ProviderError("model text is malformed")
            if content:
                self.emit("provider.event", event="model.message", text=content)
            if not isinstance(calls, list) or len(calls) > self.config["max_tool_calls"]:
                raise ProviderError("model tool call count exceeds bound")
            if not calls:
                self.emit("turn.complete", summary=content or "model completed without tool effects")
                return
            messages.append(message)
            for raw_call in calls:
                if self.cancelled.is_set():
                    break
                self.tool_count += 1
                if self.tool_count > self.config["max_tool_calls"]:
                    raise ProviderError("turn tool call count exceeds bound")
                call = tool_call(raw_call, self.seen)
                self.emit("tool.call", call=call)
                reply = None
                while reply is None and not self.cancelled.is_set():
                    reply = self.receive("tool.result")
                if self.cancelled.is_set():
                    break
                if reply.get("call_id") != call["call_id"]:
                    raise ProviderError("Host result identity differs; effect remains unknown")
                if not known_tool_result(reply):
                    raise ProviderError("Host result is not confirmed completed; outcome unknown; no semantic redispatch")
                messages.append({"role": "tool", "tool_call_id": call["call_id"],
                                 "content": json.dumps(reply, ensure_ascii=False, separators=(",", ":"))})
        if self.cancelled.is_set():
            self.emit("turn.cancelled", summary="cancelled; no further tool effects were dispatched")
            return
        raise ProviderError("model round limit reached; no automatic redispatch")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/etc/trillionnium/owner-open/provider-local-v1.json"))
    args = parser.parse_args()
    adapter = None
    try:
        adapter = Adapter(load_config(args.config))
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, lambda _number, _frame: adapter.cancelled.set())
        adapter.run()
        return 0
    except Exception as error:
        if adapter is None:
            adapter = Adapter({})
        adapter.emit("turn.fail", error=str(error)[:1024])
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
