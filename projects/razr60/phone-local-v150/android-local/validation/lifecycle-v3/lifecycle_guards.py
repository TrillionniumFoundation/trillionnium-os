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


def top_focused_display(raw):
    """Parse one successful windows dump; duplicate/malformed labels are unknown."""
    text = raw.decode("utf-8", "strict")
    lines = [line.strip() for line in text.splitlines()
             if line.strip().startswith("mTopFocusedDisplayId")]
    if len(lines) != 1:
        raise ValueError("window dump lacks a unique top focused display label")
    match = re.fullmatch(r"mTopFocusedDisplayId=(0|[1-9][0-9]{0,4})", lines[0])
    if match is None or int(match[1]) > 65535:
        raise ValueError("window top focused display label is malformed")
    return int(match[1])


def display_focus(raw, logical_display_id):
    """Bind current focus to an explicit display block, never the first global line."""
    if type(logical_display_id) is not int or not 0 <= logical_display_id <= 65535:
        raise ValueError("explicit logical display ID required")
    lines = raw.decode("utf-8", "strict").splitlines()
    headers = [line.strip() for line in lines if line.strip().startswith("WINDOW MANAGER DISPLAY CONTENTS")]
    if headers != ["WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)"]:
        raise ValueError("unexpected display dump header")
    blocks = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("Display:"):
            match = re.fullmatch(r"Display: mDisplayId=(0|[1-9][0-9]{0,4})(?: \(organized\))?", stripped)
            if match is None or int(match[1]) > 65535:
                raise ValueError("display block header is malformed")
            blocks.append((int(match[1]), index))
    ids = [item[0] for item in blocks]
    if len(ids) != len(set(ids)) or logical_display_id not in ids:
        raise ValueError("requested display block is absent or duplicated")
    position = ids.index(logical_display_id)
    first = blocks[position][1] + 1
    last = blocks[position + 1][1] if position + 1 < len(blocks) else len(lines)
    focus = [line.strip() for line in lines[first:last] if line.strip().startswith("mCurrentFocus")]
    if len(focus) != 1:
        raise ValueError("requested display has missing or ambiguous current focus")
    if focus[0] == "mCurrentFocus=null":
        package = component = user = None
    else:
        match = re.fullmatch(r"mCurrentFocus=Window\{[0-9a-fA-F]+ u([0-9]+) "
                             r"([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)/([A-Za-z0-9_.$]+)\}", focus[0])
        if match is None:
            raise ValueError("requested display focus is not an exact app component")
        user, package, component = int(match[1]), match[2], match[3]
    return {"logical_display_id": logical_display_id, "focus_package": package,
            "focus_component": component, "focus_user": user, "focus_lines": focus,
            "observed_display_ids": ids}


def focus_observation(windows_before, displays, windows_after, logical_display_id):
    """Three retained observations, not an atomic focus or screen capture claim."""
    before, after = top_focused_display(windows_before), top_focused_display(windows_after)
    if before != logical_display_id or after != logical_display_id:
        raise ValueError("top focused display changed or differs from explicit input display")
    return {**display_focus(displays, logical_display_id), "top_focused_display": before,
            "top_display_before": before, "top_display_after": after,
            "windows_before_sha256": sha(windows_before), "displays_sha256": sha(displays),
            "windows_after_sha256": sha(windows_after), "atomic_snapshot_claimed": False}


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


def installed_library_inventory(package_dump):
    """Resolve only declarations for the already SHA-verified installed package."""
    text = package_dump.decode("utf-8", "strict")
    paths = re.findall(r"(?m)^[ \t]*codePath=([^\s]+)[ \t]*\r?$", text)
    abi = re.findall(r"(?m)^[ \t]*primaryCpuAbi=([^\s]+)[ \t]*\r?$", text)
    declarations = re.findall(r"(?m)^[ \t]*(legacyNativeLibraryDir|nativeLibraryDir)=([^\s]+)[ \t]*\r?$", text)
    labels = re.findall(r"(?m)^[ \t]*(codePath|primaryCpuAbi|legacyNativeLibraryDir|nativeLibraryDir)=", text)
    if (len(paths) != 1 or abi != ["arm64-v8a"] or not declarations or len(labels) != 2 + len(declarations)
            or len(set(labels)) != len(labels)):
        raise ValueError("unique installed code path, arm64 ABI and library declaration required")
    declared = {value for _, value in declarations}
    code = paths.pop()
    if not re.fullmatch(r"/data/app/(?:[A-Za-z0-9_+=~.-]+/)?" + re.escape(PACKAGE) + r"-[A-Za-z0-9_+=~.-]+", code):
        raise ValueError("code path is outside the selected package installation")
    if not declared <= {code + "/lib", code + "/lib/arm64"}:
        raise ValueError("native library declaration is outside the installed arm64 package")
    return {"code_path": code, "primary_abi": "arm64-v8a", "declared_library_directories": sorted(declared),
            "search_directory": min(declared, key=len), "expected_runner": code + "/lib/arm64/libhepta_local_runner.so"}


def runtime_path_binding(inventory, discovered, canonical_runner, app_root, resolved_roots, uid):
    """Aliases are admitted only after separate on-device readlink observations."""
    expected_runner = inventory["expected_runner"]
    rows = discovered.decode("utf-8", "strict").splitlines()
    if rows != [expected_runner] or canonical_runner.decode("utf-8", "strict").strip() != expected_runner:
        raise ValueError("one regular installed runner at the exact arm64 path must be observed")
    if type(uid) is not int or uid < 10000:
        raise ValueError("ordinary App UID required for private paths")
    user = uid // 100000
    allowed = {"/data/user/" + str(user) + "/" + PACKAGE}
    if user == 0:allowed.add("/data/data/" + PACKAGE)
    if app_root not in allowed or set(resolved_roots) != allowed:
        raise ValueError("private roots do not match the current App user")
    targets = set(resolved_roots.values())
    if len(targets) != 1 or not targets <= allowed:
        raise ValueError("private aliases were not observed resolving to the same App directory")
    return {"schema": "hepta.lifecycle-runtime-paths.v1", **inventory, "runner": expected_runner,
            "app_pwd": app_root, "canonical_app_root": targets.pop(), "private_roots": sorted(allowed),
            "readlink_observations": dict(resolved_roots), "app_uid": uid,
            "path_suffix_matching_used": False}


def native_identity(process, parent, run_id, candidate, app_root, runner, model_file, path_binding=None):
    if process["uid"] != parent["uid"] or process["ppid"] != parent["pid"] or parent["argv"] != [PACKAGE]:
        raise ValueError("worker does not descend from the ordinary Hepta App process")
    argv = process["argv"]
    if argv[0] != runner:
        raise ValueError("worker runner differs from the verified installed native path")
    if len(argv[1:]) % 2:
        raise ValueError("worker argv is not complete option/value pairs")
    opts = {}
    for k, v in zip(argv[1::2], argv[2::2]):
        if not k.startswith("--") or k in opts:
            raise ValueError("duplicate or malformed native argv")
        opts[k] = v
    roots = [app_root]
    if path_binding is not None:
        allowed_roots = {"/data/user/" + str(parent["uid"] // 100000) + "/" + PACKAGE}
        if parent["uid"] // 100000 == 0:allowed_roots.add("/data/data/" + PACKAGE)
        if (path_binding.get("schema") != "hepta.lifecycle-runtime-paths.v1" or path_binding.get("runner") != runner
                or path_binding.get("app_pwd") != app_root or path_binding.get("app_uid") != parent["uid"]
                or set(path_binding.get("private_roots", [])) != allowed_roots
                or path_binding.get("canonical_app_root") not in allowed_roots
                or set(path_binding.get("readlink_observations", {})) != set(path_binding.get("private_roots", []))
                or any(target != path_binding.get("canonical_app_root") for target in path_binding["readlink_observations"].values())):
            raise ValueError("verified runtime path binding differs from the selected App")
        roots = path_binding["private_roots"]
    matches = [root for root in roots if opts.get("--prompt-file") == root + "/files/runs/" + run_id + "/prompt.txt"]
    if len(matches) != 1:
        raise ValueError("prompt path is not an observed alias for this exact private request")
    private_root = matches[0]
    expected = {"--expected-parent-pid": str(parent["pid"]), "--request-id": run_id,
                "--model-profile": candidate.get("model_profile", "lfm3-1.7b-qad-q4_0"),
                "--mode": "llm", "--runtime": "llama_cpp", "--compute": candidate["compute"],
                "--ctx-size": str(candidate["context_tokens"]), "--threads": str(candidate["threads"]),
                "--model": private_root + "/files/model/" + model_file,
                "--prompt-file": private_root + "/files/runs/" + run_id + "/prompt.txt"}
    if path_binding is not None:
        for flag, name in (("--result-file", "native-result.json"), ("--text-file", "raw-text.txt"),
                           ("--system-file", "system.txt"), ("--grammar-file", "grammar.gbnf")):
            expected[flag] = private_root + "/files/runs/" + run_id + "/" + name
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


def stable_stop_roi(first, second, rectangle):
    """Require exact operator-selected pixels in both retained launch frames."""
    if any(first[k] != second[k] for k in ("width", "height", "channels")):
        raise ValueError("initial screenshots have different pixel geometry")
    roi = png_roi(second, rectangle)
    if png_roi(first, rectangle) != roi:
        raise ValueError("observed Stop region was not stable across initial retained frames; no click sent")
    return roi
