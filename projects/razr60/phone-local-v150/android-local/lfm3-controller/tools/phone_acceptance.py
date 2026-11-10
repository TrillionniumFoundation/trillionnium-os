#!/usr/bin/env python3
"""One-shot Hepta device acceptance driver. No installs, model probes, PID kills, or retries of tasks.

Device identifiers and ADB port are required arguments; no public default selects a phone or port 5037.
All phone interaction occurs only when an operator executes this script.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import struct
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from warm_receipts import APP_REQUEST, NATIVE_REQUEST, request_contract, session_contract, collection_verified
from model_profiles import DEFAULT_PROFILE, PROFILES

PACKAGE = "org.trillionnium.hepta.local"
COMPONENT = PACKAGE + "/.MainActivity"
MODEL_SHA256 = "43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452"
MODEL_FILE = "LFM3-1.7B-QAD-Q4_0.gguf"
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
SAFE_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,239}\Z")
TERMINAL = {"model_reported_done", "partial", "failed", "cancelled", "blocked"}
CONTROLLER_GRAMMAR_SCHEMAS = frozenset({
    "hepta.observed-action-gbnf.v1",
    "hepta.observed-action-gbnf.v2-reason-first",
    "hepta.observed-action-gbnf.v3-label-first",
})
LABEL_ACTION_SCHEMA = "hepta.observed-action-gbnf.v3-label-first"
LABEL_SCHEMA = "hepta.observed-target-labels.v1"
LABEL_ENCODING = "utf8-length-prefixed-be32-sorted-node-id.v1"


class DriverError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise DriverError("duplicate JSON key: " + key)
            value[key] = item
        return value
    def bad_constant(value):
        raise DriverError("non-finite JSON value: " + value)
    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad_constant)


def private_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def write_json(path, value):
    private_write(path, (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode())


class Adb:
    def __init__(self, args, evidence=None):
        executable = Path(args.adb).expanduser()
        if not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
            raise DriverError("--adb must be an existing absolute executable path")
        self.base = [str(executable), "-H", args.adb_host, "-P", str(args.adb_port), "-s", args.serial]
        self.timeout = args.command_timeout
        self.evidence, self.sequence = evidence, 0

    def command(self, command, *, label="command", input_data=None, timeout=None, allowed=(0,), raw=False):
        self.sequence += 1
        # Android shell v2 with no PTY preserves binary bytes, separated stderr, and remote exit status.
        # exec-out cannot supply the missing-file exit 40 contract used by app_bytes.
        argv = self.base + ["shell", "-T", shlex.join(command)]
        started = time.time()
        timed_out = False
        try:
            result = subprocess.run(argv, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=timeout or self.timeout, check=False)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            # subprocess.run terminates only its own host-side adb client. It does not kill a phone PID.
            code, stdout, stderr, timed_out = None, error.stdout or b"", error.stderr or b"", True
        if self.evidence:
            stem = self.evidence / "commands" / ("%05d-%s" % (self.sequence, re.sub(r"[^a-zA-Z0-9_-]", "_", label)))
            private_write(stem.with_suffix(".stdout.bin"), stdout)
            private_write(stem.with_suffix(".stderr.bin"), stderr)
            write_json(stem.with_suffix(".json"), {"argv": argv, "started_wall_s": started,
                "elapsed_s": time.time() - started, "exit_code": code, "client_timed_out": timed_out,
                "stdin_bytes": len(input_data or b""), "stdin_sha256": digest(input_data) if input_data is not None else None})
        if code not in allowed:
            raise DriverError("%s: %s; phone-side outcome may be unknown" % (label, "adb client timeout" if timed_out else "exit " + str(code)))
        return code, stdout

    def app_bytes(self, relative, *, optional=False):
        if not re.fullmatch(r"files/[A-Za-z0-9_./-]+", relative) or ".." in relative.split("/"):
            raise DriverError("unsafe app-relative path")
        script = "if [ -f {p} ] && [ ! -L {p} ]; then cat {p}; elif [ -e {p} ] || [ -L {p} ]; then exit 41; else exit 40; fi".format(p=shlex.quote(relative))
        code, data = self.command(["run-as", PACKAGE, "sh", "-c", script], label="read-app-file", raw=True,
                                  allowed=(0, 40) if optional else (0,))
        return None if code == 40 else data

    def app_json(self, relative, *, optional=True):
        data = self.app_bytes(relative, optional=optional)
        if data is None:
            return None
        value = strict_json(data)
        if not isinstance(value, dict):
            raise DriverError("JSON object required: " + relative)
        return value

    def list_children(self, relative, directories=False):
        script = "if [ -d {p} ]; then find {p} -mindepth 1 -maxdepth 1 -type {t}; else exit 40; fi".format(
            p=shlex.quote(relative), t="d" if directories else "f")
        code, output = self.command(["run-as", PACKAGE, "sh", "-c", script], label="list-app-files", raw=True, allowed=(0, 40))
        if code == 40:
            return []
        names = []
        for line in output.decode("utf-8").splitlines():
            if not line.startswith(relative + "/"):
                raise DriverError("unexpected find output")
            name = line[len(relative) + 1:]
            if not SAFE_FILE.fullmatch(name):
                raise DriverError("unsafe observed filename")
            names.append(name)
        return sorted(names)


def current_status(adb, task_id=None):
    value = {"package": PACKAGE, "trigger": adb.app_json("files/debug-trigger-result.json"),
             "session": adb.app_json("files/control-session.json")}
    candidate = task_id or ((value["session"] or {}).get("task_id"))
    if candidate is not None:
        if not isinstance(candidate, str) or not HEX32.fullmatch(candidate):
            raise DriverError("invalid observed task id")
        value["task_id"] = candidate
        value["result"] = adb.app_json("files/control-tasks/" + candidate + "/result.json")
    return value


def capture_ui(adb, directory, label):
    """Terminal-only UI observation; default UiAutomation may temporarily rebind services."""
    remote = "/data/local/tmp/hepta-observe-" + uuid.uuid4().hex + ".xml"
    try:
        adb.command(["uiautomator", "dump", remote], label=label + "-dump", timeout=30)
        _, data = adb.command(["cat", remote], label=label + "-read", raw=True)
        private_write(directory / (label + ".xml"), data)
        root = ET.fromstring(data)
        if root.tag != "hierarchy":
            raise DriverError("unexpected UI XML root")
        _, windows = adb.command(["dumpsys", "window", "windows"], label=label + "-focus")
        private_write(directory / (label + "-window.txt"), windows)
        focus_line = next((line.strip() for line in windows.decode("utf-8", "replace").splitlines()
                           if "mCurrentFocus=" in line), None)
        match = re.search(r"\bu\d+\s+([A-Za-z0-9_.]+)/", focus_line or "")
        return {"xml": root, "focus_line": focus_line, "focus_package": match.group(1) if match else None}
    finally:
        # Removing this UUID-named observer file is not a task action or application mutation.
        try:
            adb.command(["rm", "-f", remote], label=label + "-remove-own-temp")
        except DriverError:
            pass


def ui_predicates(ui, package, texts, contains=False):
    nodes = [n for n in ui["xml"].iter("node") if n.get("visible-to-user", "true") != "false"]
    packages = sorted({n.get("package") for n in nodes if n.get("package")})
    tests = []
    if package:
        # XML presence is required. An explicitly different focused window cannot be ignored.
        focused = ui["focus_package"]
        focus_ok = focused == package if ui["focus_line"] is not None else package in packages
        tests.append({"kind": "foreground_package", "expected": package,
                      "passed": package in packages and focus_ok, "xml_packages": packages,
                      "focus_line": ui["focus_line"], "focus_package": focused})
    for expected in texts:
        matches = []
        for node in nodes:
            if package and node.get("package") != package:
                continue
            for attribute in ("text", "content-desc"):
                actual = node.get(attribute, "")
                if (expected in actual) if contains else (expected == actual):
                    matches.append({"attribute": attribute, "actual": actual, "package": node.get("package"),
                                    "resource_id": node.get("resource-id"), "bounds": node.get("bounds")})
        tests.append({"kind": "visible_text", "expected": expected, "match": "contains" if contains else "exact",
                      "passed": bool(matches), "matches": matches})
    return {"checks": tests, "expectations_supplied": bool(tests), "all_passed": bool(tests) and all(t["passed"] for t in tests)}


def stop_button(ui):
    if ui["focus_package"] != PACKAGE:
        raise DriverError("Hepta is not the observed focused window; no stop click sent")
    found = []
    for node in ui["xml"].iter("node"):
        if node.get("package") == PACKAGE and node.get("text") == "停止" and node.get("enabled") == "true" and node.get("clickable") == "true" and node.get("visible-to-user", "true") != "false":
            bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
            if bounds:
                x1, y1, x2, y2 = map(int, bounds.groups())
                if 0 <= x1 < x2 <= 40000 and 0 <= y1 < y2 <= 40000:
                    found.append((x1, y1, x2, y2))
    if len(found) != 1:
        raise DriverError("no unique visible enabled Stop button; no stop click sent")
    return found[0]


def request_visible_stop(adb, directory, nonce_sha, task_id):
    # The stock uiautomator CLI may suppress Accessibility services while observing.
    # It cannot establish that pressing the normal UI Stop button caused cancellation.
    # An operator may use a visual screencap or a separately qualified non-suppressing
    # observer; this helper must not guess coordinates or change the app for teardown.
    session = adb.app_json("files/control-session.json") or {}
    own = (session.get("debug_nonce_sha256") == nonce_sha and session.get("task_id") == task_id
           and (session.get("running") is True or session.get("pending") is True))
    return {"attempted": False, "clicked": False, "matching_active_session": own,
            "manual_ui_stop_required": own, "cleanup_unknown": True,
            "reason": "No qualified non-suppressing Stop observer; no UI dump, launch or click sent while task active"}


def wait_terminal_quiescence(adb, nonce_sha, task_id, timeout=5):
    deadline = time.monotonic() + timeout
    while True:
        session = adb.app_json("files/control-session.json") or {}
        if (session.get("debug_nonce_sha256") == nonce_sha and session.get("task_id") == task_id
                and session.get("running") is False and session.get("pending") is False
                and session.get("cleanup_known") is True):
            return session
        if time.monotonic() >= deadline:
            raise DriverError("terminal receipt has no matching idle clean Session; UI observer not launched")
        time.sleep(0.2)


def prompt_binding(prompt, instruction, observation_ids):
    prefix = "UNTRUSTED_DATA\n"
    if not prompt.startswith(prefix):
        return False
    data, separator, owner = prompt[len(prefix):].partition("\nOWNER\n")
    if not separator or owner != instruction:
        return False
    try:
        parsed = strict_json(data.encode("utf-8"))
        return parsed.get("screen", {}).get("observation_id") in observation_ids
    except (ValueError, DriverError, AttributeError):
        return False


def native_budget_valid(native, expected_context, expected_model_profile="lfm3-1.7b-qad-q4_0"):
    from model_profiles import profile, LLAMA_COMMIT
    try: selected=profile(expected_model_profile)
    except ValueError: return False
    budget = native.get("prompt_budget")
    if not isinstance(budget, dict): return False
    size, generation = budget.get("formatted_utf8_bytes"), native.get("max_tokens")
    if type(size) is not int or size <= 0 or type(generation) is not int or not 1 <= generation <= 1024: return False
    if selected["exact"]:
        tokens=budget.get("prompt_tokens_exact")
        sdk_profile=native.get("profile")
        total=tokens+generation+256 if type(tokens) is int else -1
        return (native.get("model_profile")==expected_model_profile
            and native.get("model_sha256_verified")==selected["sha256"]
            and native.get("model_architecture")==selected["architecture"]
            and native.get("model_bytes_verified")==selected["bytes"] and native.get("model_metadata_unchanged") is True
            and native.get("chat_template_enable_thinking") is False and native.get("automatic_cpu_fallback") is False
            and budget.get("method")=="llama_tokenize_exact_same_input_ids"
            and budget.get("model_contract_sha256")==selected["sha256"]
            and budget.get("tokenizer_source_commit")==LLAMA_COMMIT
            and budget.get("checked") is True and budget.get("admitted") is True and budget.get("is_exact_token_count") is True
            and budget.get("add_special") is True and budget.get("parse_special") is True and budget.get("input_ids_passed_directly") is True
            and type(tokens) is int and 0<tokens<=expected_context and type(budget.get("input_ids_count")) is int and budget["input_ids_count"]==tokens
            and isinstance(sdk_profile,dict) and type(sdk_profile.get("prompt_tokens")) is int and sdk_profile["prompt_tokens"]==tokens
            and isinstance(budget.get("input_ids_sha256"),str) and re.fullmatch(r"[a-f0-9]{64}",budget["input_ids_sha256"]) is not None
            and budget.get("context_tokens")==expected_context and budget.get("generation_tokens")==generation
            and budget.get("reserved_tokens")==256 and type(budget.get("total_context_tokens")) is int
            and budget["total_context_tokens"]==total and total<=expected_context)
    return (budget.get("method") == "lfm3_rendered_utf8_bytes_upper_bound"
        and budget.get("model_contract_sha256") == MODEL_SHA256
        and budget.get("checked") is True and budget.get("admitted") is True
        and budget.get("is_exact_token_count") is False
        and budget.get("context_tokens") == expected_context and budget.get("generation_tokens") == generation
        and budget.get("bos_eos_upper") == 2 and budget.get("reserved_tokens") == 256
        and budget.get("total_context_upper") == size + 2 + generation + 256
        and size + 2 + generation + 256 <= expected_context)


def accelerator_log_evidence(log, compute):
    # This establishes positive tensor offload, not 100% operator coverage,
    # watts, or utilization. CPU fallback lines remain visible in the report.
    device = "HTP0" if compute == "npu" else "GPUOpenCL"
    # The pinned OpenCL backend's buffer label differs from the resolved device.
    buffer_device = "HTP0" if compute == "npu" else "OpenCL"
    # Accept complete native loader records, with the pinned GenieX log wrapper
    # when present. Quoted diagnostics or other text mentioning these words are
    # not loader evidence. Only SGR color escapes are removed for matching.
    prefix = (r"[ \t]*(?:\[(?:DEBUG| INFO)\][ \t]+"
        r"\[plugins/llama_cpp/src/plugin\.cpp:[0-9]+:ggml_to_geniex_log\][ \t]+)?"
        r"(?:load_tensors|llama_model_load):[ \t]*")
    layer_pattern = re.compile(prefix + r"offloaded[ \t]+([0-9]{1,9})(?:/([0-9]{1,9}))?"
        r"[ \t]+layers[ \t]+to[ \t]+GPU[ \t]*")
    buffer_pattern = re.compile(prefix + re.escape(buffer_device)
        + r"[ \t]+model[ \t]+buffer[ \t]+size[ \t]*=[ \t]*([0-9]+(?:\.[0-9]+)?)"
        r"[ \t]*(?:MiB|MB|GiB|bytes)[ \t]*")
    offloaded, buffer_lines, positive_buffer = [], [], False
    for original in log.split("\n"):
        line = re.sub(r"\x1b\[[0-9;]*m", "", original.removesuffix("\r"))
        if not line.isascii():
            continue
        match = layer_pattern.fullmatch(line)
        if match:
            count = int(match[1])
            if match[2] is None or 0 <= count <= int(match[2]) and int(match[2]) > 0:
                offloaded.append(count)
        match = buffer_pattern.fullmatch(line)
        if match:
            buffer_lines.append(original)
            # This is the captured buffer size, never another number on the line.
            positive_buffer |= any(digit in "123456789" for digit in match[1])
    return {"accelerator_offload_observed": bool(offloaded and max(offloaded) > 0 and positive_buffer),
        "device": device, "model_buffer_device": buffer_device,
        "offloaded_layers_observed": max(offloaded, default=0), "model_buffer_lines": buffer_lines,
        "fallback_lines": [line for line in log.splitlines() if "fallback" in line.lower() or "unsupported" in line.lower()],
        "full_operator_coverage_proven": False}


def target_label_binding_valid(receipt, native, prompt_bytes, raw_bytes):
    """Recompute the immutable pair receipt from the exact native prompt.

    Labels are compared as decoded strings, with no normalization, truncation,
    label lookup, or reasoning-based target substitution in this verifier.
    """
    if not isinstance(prompt_bytes, bytes) or not isinstance(raw_bytes, bytes):
        return False
    try:
        inputs = native.get("input_sha256")
        if (not isinstance(inputs, dict) or inputs.get("prompt") != digest(prompt_bytes)
                or receipt.get("prompt_sha256") != digest(prompt_bytes)):
            return False
        text = prompt_bytes.decode("utf-8")
        if not text.startswith("UNTRUSTED_DATA\n") or "\nOWNER\n" not in text:
            return False
        data = strict_json(text[len("UNTRUSTED_DATA\n"):].split("\nOWNER\n", 1)[0].encode("utf-8"))
        screen = data.get("screen")
        if not isinstance(screen, dict):
            return False
        observation, package = screen.get("observation_id"), screen.get("package")
        if (observation != receipt.get("grammar_observation_id")
                or package != receipt.get("grammar_current_package")):
            return False
        nodes = screen.get("nodes")
        if not isinstance(nodes, list) or len(nodes) > 200:
            return False
        labels = {}
        for row in nodes:
            if not isinstance(row, list) or len(row) != 4:
                return False
            node_id, label = row[:2]
            if (not isinstance(node_id, str) or re.fullmatch(r"n[0-9]{1,5}", node_id) is None
                    or node_id in labels or not isinstance(label, str)
                    or len(label.encode("utf-16-be")) // 2 > 37):
                return False
            # UTF-8 encoding also rejects isolated surrogate code points.
            label.encode("utf-8")
            labels[node_id] = label
        payload = bytearray()
        def field(value):
            encoded = value.encode("utf-8")
            payload.extend(struct.pack(">I", len(encoded)))
            payload.extend(encoded)
        for value in (LABEL_SCHEMA, LABEL_ENCODING, observation, package):
            field(value)
        payload.extend(struct.pack(">I", len(labels)))
        for node_id, label in sorted(labels.items()):
            field(node_id); field(label)
        expected = {"schema": LABEL_SCHEMA, "encoding": LABEL_ENCODING,
            "observation_id": observation, "package": package,
            "sha256": digest(payload), "pairs_count": len(labels)}
        contract = receipt.get("target_label_contract")
        if (not isinstance(contract, dict) or contract != expected
                or type(contract.get("pairs_count")) is not int):
            return False
        action = strict_json(raw_bytes)
        if not isinstance(action, dict):
            return False
        if action.get("action") in {"click", "type", "scroll"}:
            node_id, label = action.get("node_id"), action.get("node_label")
            keys = list(action)
            return (isinstance(node_id, str) and isinstance(label, str) and node_id in labels
                    and labels[node_id] == label and action.get("observation_id") == observation
                    and action.get("package") == package and keys.index("node_label") < keys.index("node_id"))
        return "node_id" not in action and "node_label" not in action
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, DriverError):
        return False


def controller_grammar_binding_valid(receipt, native, grammar_bytes, observation_packages,
        prompt_bytes=None, raw_bytes=None):
    """Known grammar schema plus the same native bytes and observed window identity.

    observation_packages is built only from real step-before/after observations,
    never from a model's action package or its receipt. Conflicting packages for
    one observation identity fail closed.
    """
    if not isinstance(receipt, dict) or not isinstance(native, dict) or not isinstance(grammar_bytes, bytes):
        return False
    schema = receipt.get("grammar_schema")
    if not isinstance(schema, str) or schema not in CONTROLLER_GRAMMAR_SCHEMAS:
        return False
    observation = receipt.get("grammar_observation_id")
    package = receipt.get("grammar_current_package")
    if (not isinstance(observation, str) or not HEX32.fullmatch(observation)
            or not isinstance(package, str) or not package or len(package) > 255
            or observation_packages.get(observation) != {package}):
        return False
    input_hashes = native.get("input_sha256")
    grammar_sha = digest(grammar_bytes)
    if not (isinstance(input_hashes, dict) and receipt.get("grammar_sha256") == grammar_sha
            and input_hashes.get("grammar") == grammar_sha):
        return False
    return schema != LABEL_ACTION_SCHEMA or target_label_binding_valid(receipt, native, prompt_bytes, raw_bytes)


def collect_evidence(adb, directory, task_id, instruction, baseline_runs, screenshots, expected_uid,
        expected_compute="npu", expected_context=4096, expected_model_profile="lfm3-1.7b-qad-q4_0"):
    from model_profiles import profile
    selected=profile(expected_model_profile)
    report = {"task_id": task_id, "associated_runs": [], "omitted_screenshots": [], "errors": [], "files": []}
    warm_records = {}
    observations, explicit_runs, observation_packages = set(), set(), {}
    if not task_id:
        return report
    task_path = "files/control-tasks/" + task_id
    try:
        names = adb.list_children(task_path)
    except Exception as error:
        report["errors"].append(str(error)); names = []
    for name in names:
        if name.endswith(".png") and not screenshots:
            report["omitted_screenshots"].append(name); continue
        if not (name.endswith(".json") or (screenshots and name.endswith(".png"))):
            continue
        try:
            data = adb.app_bytes(task_path + "/" + name)
            private_write(directory / "task" / name, data)
            report["files"].append({"path": "task/" + name, "bytes": len(data), "sha256": digest(data)})
            if name.endswith(".json"):
                value = strict_json(data)
                observation = value.get("observation_id")
                if isinstance(observation, str) and HEX32.fullmatch(observation):
                    observations.add(observation)
                    if re.fullmatch(r"step-[0-9]{2,}-(?:before|after)\.json", name):
                        package = value.get("package")
                        observation_packages.setdefault(observation, set()).add(package if isinstance(package, str) else None)
                run = value.get("run_id")
                if isinstance(run, str) and HEX32.fullmatch(run): explicit_runs.add(run)
        except Exception as error:
            report["errors"].append(name + ": " + str(error))
    try:
        candidates = set(adb.list_children("files/runs", directories=True)) - baseline_runs
    except Exception as error:
        report["errors"].append(str(error)); candidates = set()
    associated = set(explicit_runs)
    for run_id in sorted(candidates - associated):
        if not HEX32.fullmatch(run_id): continue
        try:
            prompt = adb.app_bytes("files/runs/" + run_id + "/prompt.txt", optional=True)
            if prompt is not None and prompt_binding(prompt.decode("utf-8"), instruction, observations): associated.add(run_id)
        except Exception as error:
            report["errors"].append("associate " + run_id + ": " + str(error))
    for run_id in sorted(associated):
        row = {"run_id": run_id, "association": "step_model_run_id" if run_id in explicit_runs else "exact_owner_and_observation_id", "files": []}
        receipt, native = {}, {}
        try:
            for name in adb.list_children("files/runs/" + run_id):
                if not (name.endswith((".json", ".txt", ".log", ".pending", ".gbnf")) or (screenshots and name == "image.bin")): continue
                data = adb.app_bytes("files/runs/" + run_id + "/" + name)
                target = "runs/" + run_id + "/" + name
                private_write(directory / target, data)
                row["files"].append({"path": target, "bytes": len(data), "sha256": digest(data)})
            app_file = directory / "runs" / run_id / "app-receipt.json"
            row["app_receipt_available"] = app_file.exists()
            if app_file.exists():
                receipt = strict_json(app_file.read_bytes())
                row.update({"run_id_binding_valid": receipt.get("run_id") == run_id,
                    "app_receipt_schema": receipt.get("schema"),
                    "process_exit_observed": receipt.get("process_exit_observed"), "exit_code": receipt.get("exit_code"),
                    "inference_completed": receipt.get("inference_completed"), "status": receipt.get("status"),
                    "app_identity_and_runtime_valid": (receipt.get("schema") in ("hepta.local-model.receipt.v2", APP_REQUEST)
                        and receipt.get("package_name") == PACKAGE and receipt.get("app_uid") == expected_uid
                        and expected_uid is not None and receipt.get("runtime") == "llama_cpp" and receipt.get("mode") == "llm"
                        and receipt.get("compute_requested") == expected_compute and receipt.get("context_tokens") == expected_context
                        and receipt.get("model_sha256_verified") == selected["sha256"] and receipt.get("image_sent_to_model") is False
                        and (not selected["exact"] or receipt.get("model_profile")==expected_model_profile)
                        and receipt.get("fallback_allowed") is False and receipt.get("native_context_budget_valid") is True
                        and receipt.get("grammar_constraint_enabled") is True and receipt.get("grammar_binding_valid") is True
                        and receipt.get("native_result_binding_valid") is True),
                    "app_uid": receipt.get("app_uid"), "package_name": receipt.get("package_name")})
            native_file = directory / "runs" / run_id / "native-result.json"
            raw_file = directory / "runs" / run_id / "raw-text.txt"
            row["native_output_binding_valid"] = False
            row["accelerator_runtime_valid"] = False
            row["accelerator_offload_observed"] = False
            row["controller_grammar_binding_valid"] = False
            if native_file.exists() and raw_file.exists():
                native = strict_json(native_file.read_bytes()); raw = raw_file.read_bytes(); raw.decode("utf-8")
                row["native_output_binding_valid"] = (native.get("schema") ==
                    (NATIVE_REQUEST if receipt.get("schema") == APP_REQUEST else "hepta.geniex-once.result.v1")
                    and native.get("request_id") == run_id and native.get("raw_text_sha256") == digest(raw)
                    and native.get("raw_text_bytes") == len(raw) and native.get("generation_complete") is True
                    and native.get("raw_text_truncated") is False and native.get("raw_text_utf8") is True
                    and "error" in native and native.get("error") is None)
                model_path = native.get("model_path")
                row["accelerator_runtime_valid"] = (native.get("runtime") == "llama_cpp" and native.get("mode") == "llm"
                    and native.get("compute_requested") == expected_compute
                    and native.get("device_resolved") == ("HTP0" if expected_compute == "npu" else "GPUOpenCL")
                    and "device_warning" in native and native.get("device_warning") is None
                    and type(native.get("n_gpu_layers_create")) is int and native["n_gpu_layers_create"] != 0
                    and native.get("n_ctx_create") == expected_context
                    and isinstance(model_path, str) and Path(model_path).name == selected["file"]
                    and app_file.exists() and model_path == receipt.get("model_path")
                    and native_budget_valid(native, expected_context, expected_model_profile))
                stderr_file = directory / "runs" / run_id / "stderr.log"
                log_evidence = accelerator_log_evidence(stderr_file.read_text(errors="replace") if stderr_file.exists() else "", expected_compute)
                row["accelerator_offload_observed"] = log_evidence["accelerator_offload_observed"]
                row["accelerator_log_evidence"] = log_evidence
                grammar_file=directory / "runs" / run_id / "grammar.gbnf"
                prompt_file=directory / "runs" / run_id / "prompt.txt"
                if grammar_file.is_file() and app_file.exists():
                    row["controller_grammar_binding_valid"] = controller_grammar_binding_valid(
                        receipt, native, grammar_file.read_bytes(), observation_packages,
                        prompt_file.read_bytes() if prompt_file.is_file() else None,raw)
                row["runtime_evidence"] = {k: native.get(k) for k in ("mode", "runtime", "compute_requested", "device_resolved", "device_warning", "n_ctx_create", "n_gpu_layers_create", "prompt_budget", "profile")}
            if receipt.get("schema") == APP_REQUEST:
                generation = receipt.get("worker_generation")
                row["worker_generation"] = generation
                row["request_sequence"] = receipt.get("request_sequence")
                row["task_request_binding_valid"] = request_contract(receipt, native, task_id)
                if isinstance(generation, str) and HEX32.fullmatch(generation):
                    warm_records.setdefault(generation, []).append((receipt, native))
        except Exception as error:
            report["errors"].append("collect " + run_id + ": " + str(error))
        report["associated_runs"].append(row)
    if warm_records:
        report["task_model_sessions"] = []
        final_file = directory / "task" / "result.json"
        final = strict_json(final_file.read_bytes()) if final_file.is_file() else {}
        for generation, records in sorted(warm_records.items()):
            session = {"worker_generation": generation, "binding_valid": False, "files": []}
            try:
                for name in ("app-session-receipt.json", "native-session-result.json", "stdout.log", "stderr.log"):
                    data = adb.app_bytes("files/runs/" + generation + "/" + name, optional=True)
                    if data is None:
                        continue
                    target = "runs/" + generation + "/" + name
                    private_write(directory / target, data)
                    session["files"].append({"path": target, "bytes": len(data), "sha256": digest(data)})
                app_file = directory / "runs" / generation / "app-session-receipt.json"
                native_file = directory / "runs" / generation / "native-session-result.json"
                if app_file.is_file() and native_file.is_file():
                    app, native = strict_json(app_file.read_bytes()), strict_json(native_file.read_bytes())
                    session["binding_valid"] = session_contract(app, native, digest(app_file.read_bytes()),
                        final, records, task_id, expected_uid)
                    session["process_exit_observed"] = app.get("process_exit_observed")
                    session["exit_code"] = app.get("exit_code")
                    session["requests_received"] = native.get("requests_received")
                    session["model_create_count"] = native.get("model_create_count")
                    session["model_reset_count"] = native.get("model_reset_count")
                stderr_file = directory / "runs" / generation / "stderr.log"
                logs = accelerator_log_evidence(stderr_file.read_text(errors="replace") if stderr_file.is_file() else "", expected_compute)
                for row in report["associated_runs"]:
                    if row.get("worker_generation") == generation:
                        row["accelerator_log_evidence"] = logs
                        row["accelerator_offload_observed"] = logs["accelerator_offload_observed"]
                        row["accelerator_log_scope"] = "same_owned_task_generation"
            except Exception as error:
                report["errors"].append("collect task worker " + generation + ": " + str(error))
            report["task_model_sessions"].append(session)
        report["task_model_sessions_valid"] = (len(report["task_model_sessions"]) == 1
            and all(session["binding_valid"] is True for session in report["task_model_sessions"]))
    write_json(directory / "collection.json", report)
    return report


def run_task(args):
    if not CASE_ID.fullmatch(args.case_id) or args.case_id in (".", ".."):
        raise DriverError("case ID must be a safe new directory name")
    instruction = args.instruction
    if not instruction.strip() or len(instruction.encode("utf-8")) > 1600 or any(s in instruction for s in ("\0", "<|", "<__image__>")):
        raise DriverError("instruction is empty, above 1600 UTF-8 bytes, or contains reserved markers")
    directory = args.evidence_root.expanduser().resolve() / args.case_id
    directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.mkdir(mode=0o700, exist_ok=False)  # A repeated case never overwrites evidence or submits another task.
    adb = Adb(args, directory)
    nonce = secrets.token_hex(32); nonce_sha = digest(nonce.encode()); task_id = None
    baseline_runs, final, trigger, session = set(), None, None, None
    report = {"schema": "hepta.host-acceptance.v1", "case_id": args.case_id, "package": PACKAGE,
        "instruction": instruction, "instruction_sha256": digest(instruction.encode()), "nonce_sha256": nonce_sha,
        "adb_host": args.adb_host, "adb_port": args.adb_port, "device_serial": args.serial,
        "launch_attempt_count": 0, "automatic_retry": False, "model_self_report_is_not_pass": True,
        "verdict": "fail", "timed_out": False, "setup_actions": [], "errors": []}
    try:
        _, app_uid = adb.command(["run-as", PACKAGE, "id", "-u"], label="app-uid")
        uid = int(app_uid.strip()); report["app_uid"] = uid
        if uid < 10000: raise DriverError("ordinary application UID required")
        prior = current_status(adb); write_json(directory / "status-before.json", prior)
        old = prior["session"] or {}
        if old.get("pending") is True or old.get("running") is True or old.get("blocked") is True or old.get("cleanup_known") is False:
            raise DriverError("existing session active or cleanup unknown; no new task submitted")
        baseline_runs = {r for r in adb.list_children("files/runs", directories=True) if HEX32.fullmatch(r)}
        if args.setup_home:
            adb.command(["input", "keyevent", "KEYCODE_HOME"], label="setup-home")
            report["setup_actions"].append({"action": "home", "classification": "test_precondition_not_model_action"})
        _, clock = adb.command(["date", "+%s"], label="phone-clock")
        now_ms = int(clock.strip()) * 1000
        request = {"schema": "hepta.private-debug-task.v1", "nonce": nonce, "instruction": instruction,
                   "created_wall_ms": now_ms, "expires_wall_ms": now_ms + 600000}
        request_bytes = (json.dumps(request, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        private_write(directory / "debug-request.json", request_bytes)
        # mksh noclobber opens a new regular file exclusively; an existing request is a conflict.
        script = "umask 077; if [ -e files/debug-task.json ] || [ -L files/debug-task.json ]; then exit 42; fi; set -C; cat > files/debug-task.json"
        adb.command(["run-as", PACKAGE, "sh", "-c", script], label="write-one-private-request", input_data=request_bytes)
        if adb.app_bytes("files/debug-task.json") != request_bytes:
            raise DriverError("request readback differs; no intent submitted")
        report["launch_attempt_count"] = 1
        try:
            adb.command(["am", "start", "-W", "-n", COMPONENT, "--ez", "auto_task", "true", "--es", "test_nonce", nonce], label="launch-once", timeout=30)
        except DriverError as error:
            report["errors"].append(str(error))  # Poll receipts to resolve uncertainty; never replay the Intent.
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            try:
                status = current_status(adb, task_id)
                if (status["trigger"] or {}).get("nonce_sha256") == nonce_sha:
                    trigger = status["trigger"]; write_json(directory / "trigger.json", trigger)
                    if trigger.get("accepted") is False:
                        report["trigger_rejected"] = True
                        raise DriverError("nonce-bound trigger rejected the task")
                candidate = status["session"] or {}
                if candidate.get("debug_nonce_sha256") == nonce_sha:
                    session = candidate; write_json(directory / "session.json", session)
                    new_id = candidate.get("task_id")
                    if new_id is not None:
                        if not isinstance(new_id, str) or not HEX32.fullmatch(new_id): raise DriverError("invalid nonce-bound task ID")
                        if task_id is not None and new_id != task_id: raise DriverError("nonce-bound task ID changed")
                        task_id = new_id
                        owner = adb.app_json("files/control-tasks/" + task_id + "/owner.json")
                        if owner is not None:
                            if owner.get("task_id") != task_id or owner.get("instruction") != instruction or owner.get("instruction_utf8_sha256") != report["instruction_sha256"]:
                                raise DriverError("task owner binding differs from the submitted instruction")
                            write_json(directory / "owner-binding.json", owner)
                        result = adb.app_json("files/control-tasks/" + task_id + "/result.json")
                        if result is not None:
                            if result.get("task_id") != task_id or result.get("status") not in TERMINAL: raise DriverError("invalid task terminal receipt")
                            final = result; break
                    elif candidate.get("status") in ("not_started", "cancelled_before_start", "blocked") and candidate.get("pending") is not True:
                        raise DriverError("nonce-bound session did not start: " + candidate.get("status", "unknown"))
            except DriverError as error:
                if any(term in str(error) for term in ("rejected the task", "binding differs", "task ID changed", "invalid nonce-bound", "did not start", "invalid task terminal")):
                    raise
                report["errors"].append(str(error))
            except (ValueError, UnicodeError) as error:
                report["errors"].append("incomplete/unreadable receipt: " + str(error))
            time.sleep(args.poll)
        if final is None:
            report["timed_out"] = True
            try:
                report["stop_request"] = request_visible_stop(adb, directory, nonce_sha, task_id)
            except Exception as error:
                report["stop_request"] = {"clicked": False, "error": str(error), "cleanup_unknown": True}
            stop_deadline = time.monotonic() + args.stop_grace
            while task_id and time.monotonic() < stop_deadline:
                try:
                    candidate = adb.app_json("files/control-tasks/" + task_id + "/result.json")
                    if candidate is not None and candidate.get("task_id") == task_id and candidate.get("status") in TERMINAL:
                        final = candidate; break
                except Exception as error:
                    report["errors"].append("stop collection: " + str(error))
                time.sleep(args.poll)
        report["task_id"] = task_id; report["task_result"] = final
        report["trigger_binding_verified"] = bool(trigger and trigger.get("accepted") is True and trigger.get("private_request_consumed") is True)
        report["owner_binding_verified"] = (directory / "owner-binding.json").is_file()
        if final is not None and not report["timed_out"] and final.get("cleanup_known") is True:
            observed_session = wait_terminal_quiescence(adb, nonce_sha, task_id)
            write_json(directory / "session-before-final-observer.json", observed_session)
            report["final_ui_observer_after_clean_idle_session"] = True
            ui = capture_ui(adb, directory, "ui-final")
            report["independent_ui"] = ui_predicates(ui, args.expected_package, args.expected_visible_text, args.text_match == "contains")
            predicates = report["independent_ui"]
            normal = final.get("status") == "model_reported_done" and final.get("cleanup_known") is True and final.get("external_model") is False
            if normal and report["trigger_binding_verified"] and report["owner_binding_verified"] and predicates["all_passed"]:
                report["verdict"] = "pass"
            elif normal and not predicates["expectations_supplied"]:
                report["verdict"] = "unverified"
        report["cleanup_unknown"] = final is None or final.get("cleanup_known") is not True
    except Exception as error:
        report["errors"].append(str(error)); report["task_id"] = task_id
        report["cleanup_unknown"] = report["launch_attempt_count"] > 0 and final is None and not report.get("trigger_rejected", False)
    finally:
        try:
            collection = collect_evidence(adb, directory, task_id, instruction, baseline_runs, args.include_screenshots, report.get("app_uid"), args.expected_compute, args.expected_context,getattr(args,"expected_model_profile","lfm3-1.7b-qad-q4_0"))
            report["collection"] = collection
            if collection["errors"] and report["verdict"] == "pass": report["verdict"] = "unverified"
            report["native_receipts_verified"] = collection_verified(collection)
            if report["verdict"] == "pass" and not report["native_receipts_verified"]:
                report["verdict"] = "unverified"
        except Exception as error:
            report["errors"].append("evidence collection: " + str(error))
            if report["verdict"] == "pass": report["verdict"] = "unverified"
        report["finished_host_wall_ms"] = int(time.time() * 1000)
        report["evidence_directory"] = str(directory)
        write_json(directory / "acceptance.json", report)
        manifest = [{"path": str(p.relative_to(directory)), "bytes": p.stat().st_size, "sha256": digest(p.read_bytes())}
                    for p in sorted(directory.rglob("*")) if p.is_file()]
        write_json(directory / "file-manifest.json", {"files": manifest, "screenshots_exported": args.include_screenshots})
    print(json.dumps({k: report.get(k) for k in ("case_id", "task_id", "verdict", "timed_out", "cleanup_unknown", "evidence_directory", "errors")}, ensure_ascii=False, indent=2))
    return 0 if report["verdict"] == "pass" else 3 if report["verdict"] == "unverified" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True, help="absolute host ADB executable")
    parser.add_argument("--adb-host", default="127.0.0.1")
    parser.add_argument("--adb-port", required=True, type=int, help="explicit existing ADB server port; never defaults to 5037")
    parser.add_argument("--serial", required=True, help="explicit selected device; no public default")
    parser.add_argument("--command-timeout", type=float, default=20)
    sub = parser.add_subparsers(dest="operation", required=True)
    run = sub.add_parser("run-task", help="submit one new task and independently verify its final UI")
    run.add_argument("--case-id", required=True); run.add_argument("--instruction", required=True)
    run.add_argument("--evidence-root", type=Path, required=True)
    run.add_argument("--expected-package"); run.add_argument("--expected-visible-text", action="append", default=[])
    run.add_argument("--expected-compute", choices=("npu", "gpu"), default="npu")
    run.add_argument("--expected-context", type=int, choices=(4096,8192), default=4096)
    run.add_argument("--expected-model-profile", choices=tuple(PROFILES), default=DEFAULT_PROFILE)
    run.add_argument("--text-match", choices=("exact", "contains"), default="exact")
    run.add_argument("--timeout", type=float, default=540); run.add_argument("--poll", type=float, default=2)
    run.add_argument("--stop-grace", type=float, default=25)
    run.add_argument("--setup-home", action="store_true"); run.add_argument("--include-screenshots", action="store_true")
    status = sub.add_parser("collect-status", help="read app receipts only; no launch, input, model request or UI mutation")
    status.add_argument("--task-id"); status.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.adb_port <= 65535 or args.command_timeout <= 0: parser.error("invalid explicit port or timeout")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.serial): parser.error("invalid device serial")
    if args.operation == "run-task":
        if not 0.2 <= args.poll <= 10 or not 1 <= args.timeout <= 3600 or not 0 <= args.stop_grace <= 120: parser.error("invalid polling/time bounds")
        if args.expected_package and args.expected_package != "android" and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", args.expected_package): parser.error("invalid expected package")
        if any(not text for text in args.expected_visible_text): parser.error("expected text cannot be empty")
        return run_task(args)
    if args.task_id and not HEX32.fullmatch(args.task_id): parser.error("invalid explicit task ID")
    evidence = None
    if args.output:
        evidence = args.output.expanduser().resolve(); evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    value = current_status(Adb(args, evidence), args.task_id)
    if evidence: write_json(evidence / "status.json", value)
    print(json.dumps(value, ensure_ascii=False, indent=2)); return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (DriverError, OSError, ValueError) as error:
        print(json.dumps({"driver_error": str(error), "task_automatically_retried": False}, ensure_ascii=False), file=sys.stderr)
        sys.exit(2)
