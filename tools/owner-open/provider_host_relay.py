#!/usr/bin/python3
"""One-connection byte-preserving provider JSONL relay, without reconnection.

The host runs Codex and owns credentials. This phone-side adapter owns finite
transport only. A broken stream is unknown, never a reason to resend a turn or
tool result. The Root Linux Host remains the only effect executor.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import socket
import stat
import sys
import time

PROTOCOL = "trillionnium.owner-open.provider-jsonl.v1"
TERMINALS = {"turn.complete", "turn.cancelled", "turn.fail"}


class RelayError(RuntimeError):
    pass


def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise RelayError("duplicate JSON field")
        result[key] = value
    return result


def config(path):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_mode & 0o022 or not 0 < before.st_size <= 65536):
        raise RelayError("relay config is not a bounded non-writable file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, 65537)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise RelayError("relay config changed while read")
    value = json.loads(raw, object_pairs_hook=pairs)
    fields = {"schema", "host", "port", "connect_timeout_seconds", "idle_timeout_seconds",
              "max_duration_seconds", "max_line_bytes", "max_session_bytes"}
    if not isinstance(value, dict) or set(value) != fields:
        raise RelayError("relay config fields differ")
    if (value["schema"] != "org.trillionnium.owner-open.host-provider-relay.v1"
            or value["host"] != "127.0.0.1"):
        raise RelayError("relay endpoint must be explicit IPv4 loopback")
    bounds = {"port": 65535, "connect_timeout_seconds": 30, "idle_timeout_seconds": 600,
              "max_duration_seconds": 86400, "max_line_bytes": 1024 * 1024,
              "max_session_bytes": 256 * 1024 * 1024}
    if any(type(value[key]) is not int or not 1 <= value[key] <= limit
           for key, limit in bounds.items()):
        raise RelayError("relay resource limit is invalid")
    return value


class Lines:
    def __init__(self, maximum, direction):
        self.partial = bytearray()
        self.maximum = maximum
        self.direction = direction
        self.seq = 0
        self.terminal = False

    def feed(self, chunk):
        self.partial.extend(chunk)
        result = bytearray()
        while b"\n" in self.partial:
            end = self.partial.index(10) + 1
            if end > self.maximum:
                raise RelayError("provider line exceeds bound")
            raw = bytes(self.partial[:end])
            del self.partial[:end]
            value = json.loads(raw, object_pairs_hook=pairs)
            if (not isinstance(value, dict) or value.get("protocol") != PROTOCOL
                    or type(value.get("seq")) is not int or value["seq"] != self.seq
                    or not isinstance(value.get("kind"), str) or self.terminal):
                raise RelayError("provider protocol, sequence or terminal ordering differs")
            if self.direction == "to_codex" and self.seq == 0 and value["kind"] != "turn.start":
                raise RelayError("first Host frame must be turn.start")
            self.seq += 1
            if self.direction == "from_codex" and value["kind"] in TERMINALS:
                self.terminal = True
            result.extend(raw)  # Do not reserialize or rewrite accepted bytes.
        if len(self.partial) >= self.maximum:
            raise RelayError("unterminated provider line exceeds bound")
        return result


def relay(value, input_fd=0, output_fd=1):
    started = time.monotonic()
    deadline = started + value["max_duration_seconds"]
    idle = started + value["idle_timeout_seconds"]
    session_bytes = 0
    pending_to_codex = bytearray()
    pending_to_host = bytearray()
    lines_to_codex = Lines(value["max_line_bytes"], "to_codex")
    lines_to_host = Lines(value["max_line_bytes"], "from_codex")
    queue_bound = 2 * value["max_line_bytes"]
    previous_output_mode = os.get_blocking(output_fd)
    # Exactly one connect: no fallback endpoint, reconnect or semantic retry.
    with socket.create_connection((value["host"], value["port"]),
                                  timeout=value["connect_timeout_seconds"]) as peer:
        peer.setblocking(False)
        os.set_blocking(output_fd, False)
        try:
            while True:
                if lines_to_host.terminal and not pending_to_host:
                    return 0
                remaining = min(deadline, idle) - time.monotonic()
                if remaining <= 0:
                    raise RelayError("relay deadline expired; unobserved effects remain unknown")
                readers, writers = [], []
                if not lines_to_host.terminal and len(pending_to_codex) < queue_bound:
                    readers.append(input_fd)
                if not lines_to_host.terminal and len(pending_to_host) < queue_bound:
                    readers.append(peer)
                if pending_to_codex:
                    writers.append(peer)
                if pending_to_host:
                    writers.append(output_fd)
                readable, writable, _ = select.select(readers, writers, [], min(remaining, 0.1))
                if input_fd in readable:
                    chunk = os.read(input_fd, min(65536, queue_bound - len(pending_to_codex)))
                    if not chunk:
                        raise RelayError("Host input ended before a provider terminal")
                    session_bytes += len(chunk)
                    pending_to_codex.extend(lines_to_codex.feed(chunk))
                if peer in readable:
                    chunk = peer.recv(min(65536, queue_bound - len(pending_to_host)))
                    if not chunk:
                        raise RelayError("Codex host stream ended before terminal; no frame was resent")
                    session_bytes += len(chunk)
                    pending_to_host.extend(lines_to_host.feed(chunk))
                if session_bytes > value["max_session_bytes"]:
                    raise RelayError("relay session exceeds byte bound")
                if peer in writable:
                    count = peer.send(pending_to_codex)
                    if count <= 0:
                        raise RelayError("Codex host stream could not accept bytes")
                    del pending_to_codex[:count]
                if output_fd in writable:
                    count = os.write(output_fd, pending_to_host)
                    if count <= 0:
                        raise RelayError("Host stdout could not accept bytes")
                    del pending_to_host[:count]
                if readable or writable:
                    idle = time.monotonic() + value["idle_timeout_seconds"]
        finally:
            os.set_blocking(output_fd, previous_output_mode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path,
                        default=Path("/etc/trillionnium/owner-open/provider-host-relay-v1.json"))
    args = parser.parse_args()
    try:
        return relay(config(args.config))
    except Exception as error:
        # Do not invent a terminal after partially forwarded frames. EOF and
        # the nonzero exit are classified by the execution Host as uncertainty.
        print(f"owner-open provider relay stopped: {type(error).__name__}; no reconnect or redispatch",
              file=sys.stderr)
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
