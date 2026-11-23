"""Bounded, offline evidence checks for the independent phone lifecycle probe."""
from __future__ import annotations

import hashlib
import json
import re
import struct
import zlib

PACKAGE = "org.trillionnium.hepta.local"
SHA = re.compile(r"[a-f0-9]{64}\Z")
ID = re.compile(r"[a-f0-9]{32}\Z")
CLEAN = {"not_started", "cancelled_before_start", "model_reported_done", "partial", "failed", "cancelled"}
NOT_STARTED = {"not_started", "cancelled_before_start"}
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def pairs(items):
        value = {}
        for key, entry in items:
            if key in value:
                raise ValueError("duplicate JSON field: " + key)
            value[key] = entry
        return value
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON: " + value)))


def clean_session(value, uid, *, task_id=None, nonce_sha=None):
    """Matches frozen SessionRecovery's complete known-clean policy, not just running=false."""
    if not isinstance(value, dict) or type(uid) is not int or uid < 10000:
        raise ValueError("ordinary UID and complete prior session required")
    required = {"schema", "status", "state", "task_id", "origin", "instruction_sha256", "debug_nonce_sha256",
                "pending", "running", "blocked", "cleanup_known", "app_uid", "updated_wall_ms",
                "external_model", "automatic_resume"}
    if not required <= value.keys() or value["schema"] != "hepta.local-session.v1":
        raise ValueError("incomplete session schema")
    if type(value["app_uid"]) is not int or value["app_uid"] != uid:
        raise ValueError("session UID mismatch")
    if type(value["updated_wall_ms"]) is not int or value["updated_wall_ms"] <= 0 or not isinstance(value["state"], str):
        raise ValueError("session state/time invalid")
    if any(value[key] is not False for key in ("pending", "running", "blocked", "external_model", "automatic_resume")) or value["cleanup_known"] is not True:
        raise ValueError("session is active, blocked or cleanup is unknown")
    if value["status"] not in CLEAN:
        raise ValueError("session is not known clean terminal")
    for key, pattern in (("task_id", ID), ("instruction_sha256", SHA), ("debug_nonce_sha256", SHA)):
        if value[key] is not None and (not isinstance(value[key], str) or not pattern.fullmatch(value[key])):
            raise ValueError("invalid session identity: " + key)
    if not isinstance(value["origin"], str) or not 1 <= len(value["origin"]) <= 80 or "\0" in value["origin"] or value["instruction_sha256"] is None:
        raise ValueError("terminal reservation identity missing")
    if (value["status"] in NOT_STARTED) != (value["task_id"] is None):
        raise ValueError("task identity is inconsistent with terminal status")
    if value["origin"] == "private_debug_nonce" and value["debug_nonce_sha256"] is None:
        raise ValueError("private task nonce binding missing")
    if task_id is not None and value["task_id"] != task_id:
        raise ValueError("a different task owns the terminal session")
    if nonce_sha is not None and value["debug_nonce_sha256"] != nonce_sha:
        raise ValueError("a different nonce owns the terminal session")
    return value


def parse_proc(stat_before, status, cmdline, stat_after):
    def stat_row(data):
        text = data.decode("utf-8", "strict").strip()
        left, split = text.find(" ("), text.rfind(") ")
        if left < 1 or split <= left:
            raise ValueError("malformed proc stat")
        fields = text[split + 2:].split()
        if len(fields) < 20:
            raise ValueError("short proc stat")
        return {"pid": int(text[:left]), "ppid": int(fields[1]), "start_ticks": int(fields[19]),
                "state": fields[0], "cpu_ticks": int(fields[11]) + int(fields[12])}
    first, last = stat_row(stat_before), stat_row(stat_after)
    if any(first[k] != last[k] for k in ("pid", "ppid", "start_ticks")):
        raise ValueError("process identity changed while observed")
    uid_rows = re.findall(rb"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", status, re.M)
    if len(uid_rows) != 1 or len(set(uid_rows[0])) != 1 or not cmdline.endswith(b"\0"):
        raise ValueError("process UID/argv incomplete")
    argv = [s.decode("utf-8", "strict") for s in cmdline.rstrip(b"\0").split(b"\0")]
    if not argv or not argv[0] or last["state"] in {"Z", "X", "x"}:
        raise ValueError("process is no longer a live executable")
    return {**last, "uid": int(uid_rows[0][0]), "argv": argv}


def native_identity(process, parent, run_id, candidate, app_root, runner, model_file):
    if process["uid"] != parent["uid"] or process["ppid"] != parent["pid"] or parent["argv"] != [PACKAGE]:
        raise ValueError("worker does not descend from the ordinary Hepta App process")
    argv = process["argv"]
    if argv[0] != runner or len(argv[1:]) % 2:
        raise ValueError("worker runner/argv format mismatch")
    opts = {}
    for k, v in zip(argv[1::2], argv[2::2]):
        if not k.startswith("--") or k in opts:
            raise ValueError("duplicate or malformed native argv")
        opts[k] = v
    expected = {"--expected-parent-pid": str(parent["pid"]), "--request-id": run_id,
                "--model-profile": candidate.get("model_profile", "lfm3-1.7b-qad-q4_0"),
                "--mode": "llm", "--runtime": "llama_cpp", "--compute": candidate["compute"],
                "--ctx-size": str(candidate["context_tokens"]), "--threads": str(candidate["threads"]),
                "--model": app_root + "/files/model/" + model_file,
                "--prompt-file": app_root + "/files/runs/" + run_id + "/prompt.txt"}
    if any(opts.get(k) != v for k, v in expected.items()):
        raise ValueError("worker is not bound to the selected local request/profile")
    return True


def cancellation_receipt(receipt, result, session, binding, candidate, uid):
    clean_session(session, uid, task_id=binding["task_id"], nonce_sha=binding["nonce_sha256"])
    expected = {"schema": "hepta.local-model.receipt.v2", "package_name": PACKAGE,
                "run_id": binding["run_id"], "app_uid": uid, "app_pid": binding["parent"]["pid"],
                "expected_parent_pid": binding["parent"]["pid"], "runtime": "llama_cpp", "mode": "llm",
                "model_profile": candidate.get("model_profile", "lfm3-1.7b-qad-q4_0"),
                "model_sha256_verified": candidate["model_sha256"], "compute_requested": candidate["compute"],
                "context_tokens": candidate["context_tokens"], "process_started": True,
                "process_exit_observed": True, "cancel_requested": True, "timeout_observed": False,
                "inference_completed": False, "status": "cancelled", "fallback_allowed": False,
                "automatic_retry": False, "image_sent_to_model": False}
    if not isinstance(receipt, dict) or any(type(receipt.get(k)) is not type(v) or receipt.get(k) != v for k, v in expected.items()):
        raise ValueError("native cancellation receipt is not exact, clean, local and nonce-associated")
    if type(receipt.get("exit_code")) is not int or receipt["exit_code"] == 0 or receipt.get("runner_path") != binding["worker"]["argv"][0]:
        raise ValueError("native exit/runner evidence missing")
    native = receipt.get("native_receipt", {})
    if isinstance(native, dict) and (native.get("generation_complete") is True or native.get("worker_outcome") == "completed"):
        raise ValueError("native naturally completed before cancellation was attributable; inconclusive race")
    if result.get("task_id") != binding["task_id"] or result.get("status") != "cancelled" or result.get("cleanup_known") is not True or result.get("external_model") is not False or session.get("status") != "cancelled":
        raise ValueError("task/session did not publish a clean cancellation")
    return True


def png_extract(raw):
    """Keep a printable Android display warning separate; validate exact PNG chunks and CRCs."""
    offset = raw.find(PNG_MAGIC)
    if offset < 0 or offset > 4096 or len(raw) > 32 * 1024 * 1024:
        raise ValueError("screencap did not return a bounded PNG")
    prefix = raw[:offset]
    if prefix:
        warning = prefix.decode("utf-8", "strict")
        if any(ord(c) < 32 and c not in "\r\n\t" for c in warning) or not re.search(r"warning|display", warning, re.I):
            raise ValueError("unrecognized bytes before screenshot PNG")
    data, pos, header, compressed, ended = raw[offset:], 8, None, bytearray(), False
    while pos + 12 <= len(data):
        n = struct.unpack(">I", data[pos:pos + 4])[0]
        if n > 16 * 1024 * 1024 or pos + n + 12 > len(data):
            raise ValueError("invalid PNG chunk length")
        tag, payload = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + n]
        crc = struct.unpack(">I", data[pos + 8 + n:pos + 12 + n])[0]
        if zlib.crc32(tag + payload) & 0xffffffff != crc:
            raise ValueError("PNG chunk CRC mismatch")
        if pos == 8 and tag != b"IHDR":
            raise ValueError("PNG header must be first")
        if tag == b"IHDR":
            if header is not None or len(payload) != 13:
                raise ValueError("duplicate or malformed PNG header")
            header = struct.unpack(">IIBBBBB", payload)
        elif tag == b"IDAT":
            compressed.extend(payload)
        elif tag == b"IEND":
            if payload or pos + 12 != len(data):
                raise ValueError("trailing bytes after PNG")
            ended = True
            break
        pos += n + 12
    if not ended or not header or not compressed:
        raise ValueError("incomplete screenshot PNG")
    w, h, depth, color, compression, filtering, interlace = header
    if not (0 < w <= 8192 and 0 < h <= 8192 and w * h <= 24000000) or depth != 8 or color not in (2, 6) or (compression, filtering, interlace) != (0, 0, 0):
        raise ValueError("unsupported screenshot geometry/PNG format")
    return {"png": data, "warning": prefix.decode("utf-8"), "width": w, "height": h,
            "channels": 3 if color == 2 else 4, "compressed": bytes(compressed)}


def png_roi(image, rectangle):
    if not isinstance(rectangle, list) or len(rectangle) != 4 or any(type(x) is not int for x in rectangle):
        raise ValueError("observed Stop rectangle must be four integer pixel coordinates")
    x1, y1, x2, y2 = rectangle
    if not (0 <= x1 < x2 <= image["width"] and 0 <= y1 < y2 <= image["height"]):
        raise ValueError("observed Stop rectangle is outside screenshot")
    channels, width, height = image["channels"], image["width"], image["height"]
    stride, expected = width * channels, (width * channels + 1) * height
    decoder = zlib.decompressobj()
    raw = decoder.decompress(image["compressed"], expected + 1)
    if len(raw) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("screenshot PNG decompression length differs")
    previous, cropped = bytearray(stride), bytearray()
    for y in range(y2):
        offset = y * (stride + 1)
        kind, row = raw[offset], bytearray(raw[offset + 1:offset + 1 + stride])
        if kind > 4:
            raise ValueError("invalid PNG row filter")
        if kind:
            for x in range(stride):
                a, b, c = (row[x - channels] if x >= channels else 0), previous[x], (previous[x - channels] if x >= channels else 0)
                if kind == 1:
                    predictor = a
                elif kind == 2:
                    predictor = b
                elif kind == 3:
                    predictor = (a + b) // 2
                else:
                    p = a + b - c
                    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                    predictor = a if pa <= pb and pa <= pc else b if pb <= pc else c
                row[x] = (row[x] + predictor) & 255
        if y >= y1:
            cropped.extend(row[x1 * channels:x2 * channels])
        previous = row
    return sha(bytes(cropped))
