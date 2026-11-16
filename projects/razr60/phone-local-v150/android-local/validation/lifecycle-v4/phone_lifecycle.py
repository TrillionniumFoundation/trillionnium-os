#!/usr/bin/env python3
"""Independent, nonce-bound lifecycle validation. Only monitor/idle-restart contact a phone.

The monitor stays armed until an explicit host start-request. Active tasks are
observed with process records, app receipts, window state and screencap; never
UiAutomation. A Stop click requires a fresh operator-observed screenshot region.
No active-app kill, permission toggle, locking, retry or latch clearing exists.
"""
from __future__ import annotations

import argparse
import importlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import stat
import sys
import time

import lifecycle_guards as guard

DRIVERS = ("phone_acceptance.py", "phone_inventory.py", "phone_suite.py", "model_profiles.py")
SIDE_RECORDS = ("files/control-session.json.bak", "files/control-session.json.new",
                "files/control-session.interrupted.json", "files/debug-task.json")
GENERATE_ENTRY = re.compile(rb"\[plugins/llama_cpp/src/llm\.cpp:\d+:generate\]\s+prefix match:\s+past_prompt_tokens size:\s*\d+,\s*prompt_len:\s*\d+,\s*match_len:\s*\d+")


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()


def write(path, data, *, exclusive=False):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not isinstance(data, bytes):
        data = json_bytes(data)
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        temporary = None
    else:
        temporary = path.with_name(path.name + ".host-" + secrets.token_hex(8))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if temporary:
        if path.is_symlink():
            temporary.unlink()
            raise ValueError("host evidence path became a symlink")
        os.replace(temporary, path)


def safe_read(path, limit=2 * 1024 * 1024):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("bounded regular file required: " + str(path))
    return path.read_bytes()


def control_file(path):
    """Read only a private, single-link, same-user request; no symlink/duplicate-key ambiguity."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_nlink != 1 or not 0 < info.st_size <= 8192:
            raise ValueError("control request must be a private 0600 regular single-link file")
        data = stream.read(8193)
    if len(data) != info.st_size:
        raise ValueError("control request changed while read")
    value = guard.strict_json(data)
    if not isinstance(value, dict):
        raise ValueError("control request must be an object")
    return value


def load_drivers(root, plan):
    for item in plan["drivers"]:
        data = safe_read(root / item["path"])
        if len(data) != item["bytes"] or guard.sha(data) != item["sha256"]:
            raise ValueError("frozen driver changed: " + item["path"])
    if {row["path"] for row in plan["drivers"]} != set(DRIVERS):
        raise ValueError("unexpected lifecycle driver closure")
    if {p.name for p in root.iterdir() if p.is_file() and p.suffix == ".py"} != set(DRIVERS):
        raise ValueError("unlisted Python module in frozen lifecycle driver closure")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root))
    for name in ("phone_acceptance", "phone_suite", "phone_inventory", "model_profiles"):
        if name in sys.modules and Path(sys.modules[name].__file__).resolve().parent != root:
            raise ValueError("a different driver is already imported")
    return importlib.import_module("phone_acceptance"), importlib.import_module("phone_suite"), importlib.import_module("model_profiles")


def prepare(args):
    source = args.source_dir.expanduser().resolve(strict=True)
    manifest_raw = safe_read(source / "SOURCE-MANIFEST.json")
    manifest = guard.strict_json(manifest_raw)
    if manifest.get("schema") != "hepta.local-source.v3":
        raise ValueError("verified App source manifest required")
    members = {}
    for item in manifest["files"]:
        p = PurePosixPath(item["path"])
        if p.is_absolute() or ".." in p.parts or item["path"] in members:
            raise ValueError("invalid source closure")
        data = safe_read(source / item["path"])
        if guard.sha(data) != item["sha256"] or len(data) != item["bytes"]:
            raise ValueError("source differs: " + item["path"])
        members[item["path"]] = data
    candidate = guard.strict_json(safe_read(args.candidate))
    if candidate["version_code"] != manifest["version_code"]:
        raise ValueError("candidate and frozen source versions differ")
    instruction = safe_read(args.instruction_file, 1600).decode("utf-8")
    if not instruction.strip() or any(s in instruction for s in ("\0", "<|", "<__image__>")):
        raise ValueError("valid exact owner instruction required")
    out = args.output.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    drivers = out / "drivers"
    drivers.mkdir(mode=0o700)
    pin = []
    for name in DRIVERS:
        data = members["tools/" + name]
        write(drivers / name, data, exclusive=True)
        pin.append({"path": name, "bytes": len(data), "sha256": guard.sha(data)})
    plan = {"schema": "hepta.lifecycle-plan.v1", "candidate": candidate,
            "source_manifest_sha256": guard.sha(manifest_raw), "drivers": pin,
            "instruction": instruction, "instruction_sha256": guard.sha(instruction.encode()),
            "task_timeout_seconds": 600, "arm_timeout_seconds": 1800, "cleanup_grace_seconds": 60,
            "operator_request_max_age_seconds": 90, "idle_stability_seconds": 2,
            "restart_observation_seconds": 15, "automatic_retry": False,
            "tool_sha256": guard.sha(Path(__file__).read_bytes()),
            "guards_sha256": guard.sha(Path(guard.__file__).read_bytes())}
    acceptance, suite, _ = load_drivers(drivers, plan)
    case = {"case_id": "lifecycle-cancel", "instruction": instruction, "expected_package": "com.android.settings",
            "expected_visible_text": [], "text_match": "exact", "required_actions": [{"action": "open"}],
            "setup_home": False, "timeout_seconds": 600}
    suite.validate_plan({"schema": suite.SCHEMA, "suite_id": "lifecycle", "candidate": candidate, "cases": [case]}, require_runnable=True)
    write(out / "plan.json", plan, exclusive=True)
    print(json.dumps({"prepared": str(out), "plan_sha256": guard.sha((out / "plan.json").read_bytes()), "phone_contacted": False}))


def read_plan(path):
    path = path.expanduser().resolve(strict=True)
    raw = safe_read(path)
    plan = guard.strict_json(raw)
    if plan.get("schema") != "hepta.lifecycle-plan.v1" or plan.get("automatic_retry") is not False:
        raise ValueError("invalid lifecycle plan")
    if plan.get("tool_sha256") != guard.sha(Path(__file__).read_bytes()) or plan.get("guards_sha256") != guard.sha(Path(guard.__file__).read_bytes()):
        raise ValueError("lifecycle implementation differs; freeze a new explicit plan")
    if plan.get("instruction_sha256") != guard.sha(plan["instruction"].encode()):
        raise ValueError("frozen instruction hash differs")
    bounds = {"task_timeout_seconds": (1, 600), "arm_timeout_seconds": (1, 1800),
              "cleanup_grace_seconds": (1, 120), "operator_request_max_age_seconds": (1, 90),
              "idle_stability_seconds": (2, 10), "restart_observation_seconds": (15, 60)}
    for key, (low, high) in bounds.items():
        if type(plan.get(key)) is not int or not low <= plan[key] <= high:
            raise ValueError("invalid lifecycle time bound: " + key)
    return path, raw, plan


def uid_number(text):
    if text.isdecimal():
        return int(text)
    match = re.fullmatch(r"u(\d+)_a(\d+)", text)
    return int(match[1]) * 100000 + 10000 + int(match[2]) if match else None


class Probe:
    def __init__(self, args):
        self.args = args
        plan_path, raw, self.plan = read_plan(args.plan)
        self.out = args.output.expanduser().resolve()
        self.out.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.acceptance, self.suite, profiles = load_drivers(plan_path.parent / "drivers", self.plan)
        self.profile = profiles.profile(self.plan["candidate"].get("model_profile", profiles.DEFAULT_PROFILE))
        self.adb = self.acceptance.Adb(args, self.out)
        self.state = {"schema": "hepta.lifecycle-state.v1", "host_run_id": secrets.token_hex(16),
                      "plan_sha256": guard.sha(raw), "candidate": self.plan["candidate"], "phase": "created",
                      "phone_contacted": False, "launch_attempt_count": 0, "tap_attempt_count": 0,
                      "cleanup_known": None, "automatic_retry": False, "errors": [], "verdict": "unverified"}
        self.task_id = None
        self.nonce = secrets.token_hex(32)
        self.nonce_sha = guard.sha(self.nonce.encode())
        self.baseline_runs = set()
        self.uid = None
        write(self.out / "plan.json", raw, exclusive=True)

    def status(self, phase=None, **values):
        if phase:
            self.state["phase"] = phase
        self.state.update(values, updated_host_wall_ms=int(time.time() * 1000))
        write(self.out / "status.json", self.state)
        if phase:
            print(json.dumps({"event": phase, "directory": str(self.out), "host_run_id": self.state["host_run_id"]}), flush=True)

    def app_absent(self):
        script = "if [ ! -d files ] || [ ! -r files ] || [ ! -x files ] || [ -L files ]; then exit 41; fi; "
        for name in SIDE_RECORDS:
            p = shlex.quote(name)
            script += "if [ -e " + p + " ] || [ -L " + p + " ]; then printf '%s\\n' " + p + "; exit 42; fi; "
        self.adb.command(["run-as", guard.PACKAGE, "sh", "-c", script], label="known-idle-no-side-records")

    def processes(self):
        _, data = self.adb.command(["ps", "-A", "-o", "PID,PPID,UID,ARGS"], label="ordinary-app-process-inventory")
        rows = data.decode("utf-8", "strict").splitlines()
        if not rows or rows[0].split() != ["PID", "PPID", "UID", "ARGS"]:
            raise ValueError("unexpected process inventory columns")
        selected = []
        for row in rows[1:]:
            fields = row.split(None, 3)
            if len(fields) != 4:
                raise ValueError("incomplete process inventory row")
            uid = uid_number(fields[2])
            argv0 = fields[3].split(None, 1)[0]
            if uid == self.uid or argv0 == self.runner:
                if uid != self.uid:
                    raise ValueError("runner has a different UID")
                selected.append({"pid": int(fields[0]), "ppid": int(fields[1]), "uid": uid, "argv0": argv0})
        return selected

    def process(self, pid):
        if type(pid) is not int or not 1 <= pid <= 2 ** 31 - 1:
            raise ValueError("invalid observed process PID")
        marker = ("HEPTA_PROC_" + secrets.token_hex(16)).encode()
        root = "/proc/" + str(pid)
        script = "if [ ! -d " + root + " ]; then exit 40; fi; "
        for i, name in enumerate(("stat", "status", "cmdline", "stat")):
            if i:
                script += "printf '%s' " + shlex.quote(marker.decode()) + "; "
            script += "cat " + root + "/" + name + " || exit 41; "
        code, raw = self.adb.command(["sh", "-c", script], label="observe-owned-pid-" + str(pid), allowed=(0, 40, 41))
        if code == 41:
            code, raw = self.adb.command(["run-as", guard.PACKAGE, "sh", "-c", script], label="observe-owned-pid-as-app-" + str(pid), allowed=(0, 40, 41))
        if code == 40:
            return None
        if code != 0:
            raise ValueError("owned PID identity could not be read; absence is not proven")
        fields = raw.split(marker)
        if len(fields) != 4:
            raise ValueError("malformed process observation framing")
        try:
            value = guard.parse_proc(*fields)
            write(self.out / ("process-" + str(pid) + "-latest.json"), value)
            return value
        except ValueError as error:
            if "no longer a live" in str(error):
                return None
            raise

    def service_observation(self, label):
        _, data = self.adb.command(["dumpsys", "activity", "services", guard.PACKAGE], label=label)
        write(self.out / (label + ".txt"), data)
        text = data.decode("utf-8", "replace")
        component = guard.PACKAGE + "/.HeptaAccessibilityService"
        exact_component = component in text or guard.PACKAGE + "/" + guard.PACKAGE + ".HeptaAccessibilityService" in text
        process_lines = [line.strip() for line in text.splitlines() if "ProcessRecord{" in line and guard.PACKAGE + "/" in line]
        return {"exact_component_recorded": exact_component, "matching_process_record_lines": process_lines,
                "binding_proven_by_same_label": False, "operational_binding_requires_fresh_trigger_acceptance": True}

    def setup(self):
        self.state["phone_contacted"] = True
        self.state["existing_server"] = self.suite.require_existing_adb_server(self.args, self.out)
        self.state["preflight"] = self.suite.preflight(self.adb, self.plan["candidate"])
        _, data = self.adb.command(["run-as", guard.PACKAGE, "id", "-u"], label="ordinary-app-uid")
        self.uid = int(data.strip())
        if self.uid < 10000:
            raise ValueError("ordinary application UID required")
        _, data = self.adb.command(["run-as", guard.PACKAGE, "pwd"], label="app-private-root")
        self.app_root = data.decode("utf-8", "strict").strip()
        if not re.fullmatch(r"/data/(?:user/\d+|data)/org\.trillionnium\.hepta\.local", self.app_root):
            raise ValueError("unexpected app-private canonical root")
        _, data = self.adb.command(["dumpsys", "package", guard.PACKAGE], label="installed-native-library-location")
        inventory = guard.installed_library_inventory(data)
        _, discovered = self.adb.command(["find", inventory["search_directory"], "-mindepth", "1", "-maxdepth", "2",
            "-type", "f", "-name", "libhepta_local_runner.so"], label="installed-runner-discovery")
        _, canonical_runner = self.adb.command(["readlink", "-f", inventory["expected_runner"]], label="installed-runner-canonical-path")
        roots = {"/data/user/" + str(self.uid // 100000) + "/" + guard.PACKAGE}
        if self.uid // 100000 == 0:roots.add("/data/data/" + guard.PACKAGE)
        resolved = {}
        for index, path in enumerate(sorted(roots)):
            _, canonical = self.adb.command(["run-as", guard.PACKAGE, "readlink", "-f", path], label="app-private-canonical-root-" + str(index))
            resolved[path] = canonical.decode("utf-8", "strict").strip()
        self.path_binding = guard.runtime_path_binding(inventory, discovered, canonical_runner, self.app_root, resolved, self.uid)
        self.runner = self.path_binding["runner"]
        write(self.out / "runtime-path-binding.json", self.path_binding, exclusive=True)
        self.state["runtime_path_binding"] = self.path_binding
        self.state["app_uid"] = self.uid
        self.state["service_before"] = self.service_observation("accessibility-service-before")

    def idle(self, *, expected_task=None, expected_nonce=None):
        self.app_absent()
        raw = self.adb.app_bytes("files/control-session.json")
        session = guard.clean_session(guard.strict_json(raw), self.uid, task_id=expected_task, nonce_sha=expected_nonce)
        processes = self.processes()
        if any(row["argv0"].endswith("/libhepta_local_runner.so") for row in processes):
            raise ValueError("an app-owned native worker is still alive")
        self.app_absent()
        if self.adb.app_bytes("files/control-session.json") != raw:
            raise ValueError("terminal session changed during idle observation")
        return {"session": session, "session_sha256": guard.sha(raw), "processes": processes,
                "side_records_absent": True, "observed_host_wall_ms": int(time.time() * 1000)}

    def stable_idle(self, *, expected_task=None, expected_nonce=None, timeout=20):
        deadline = time.monotonic() + timeout
        last, stable_since, error = None, None, None
        while time.monotonic() < deadline:
            try:
                current = self.idle(expected_task=expected_task, expected_nonce=expected_nonce)
                key = current["session_sha256"]
                if last is not None and key == last["session_sha256"]:
                    if time.monotonic() - stable_since >= self.plan["idle_stability_seconds"]:
                        return current
                else:
                    stable_since = time.monotonic()
                last = current
            except Exception as caught:
                last, stable_since, error = None, None, str(caught)
            time.sleep(0.4)
        raise ValueError("no stable known-clean terminal session: " + str(error))

    def window(self, label):
        captures = []
        for suffix, section in (("top-before", "windows"), ("displays", "displays"), ("top-after", "windows")):
            _, data = self.adb.command(["dumpsys", "window", section], label=label + "-" + suffix)
            write(self.out / (label + "-" + suffix + ".txt"), data)
            captures.append(data)
        value = guard.focus_observation(*captures, self.args.logical_display_id)
        if value["focus_user"] is not None and value["focus_user"] != self.uid // 100000:
            raise ValueError("focused component belongs to a different Android user")
        write(self.out / (label + "-binding.json"), value)
        return value

    def screenshot(self, label):
        _, raw = self.adb.command(["screencap", "-p", "-d", self.args.physical_display_id], label=label, timeout=20, raw=True)
        write(self.out / (label + ".raw.bin"), raw)
        image = guard.png_extract(raw)
        write(self.out / (label + ".png"), image["png"])
        write(self.out / (label + "-warning.txt"), image["warning"].encode())
        if (image["width"], image["height"]) != (self.args.input_width, self.args.input_height):
            raise ValueError("screenshot geometry differs from explicitly observed input display mapping")
        return image

    def stop_preview(self, image):
        """Optional host-only, lossless top crop; complete PNG remains the sole click evidence."""
        metadata = {"schema": "hepta.lifecycle-preview.v1", "phone_contacted": False,
                    "source_png_sha256": guard.sha(image["png"]), "scaled": False,
                    "source_width": image["width"], "source_height": image["height"],
                    "coordinate_origin": [0, 0], "authorizes_tap": False}
        try:
            from PIL import Image
        except ImportError:
            metadata["available"] = False
            metadata["reason"] = "optional host Pillow module unavailable; use original PNG"
        else:
            height = min(1100, image["height"])
            with Image.open(io.BytesIO(image["png"])) as original:
                original.load()
                if original.size != (image["width"], image["height"]):
                    raise ValueError("host preview decoder dimensions differ from original PNG")
                preview = original.crop((0, 0, image["width"], height))
                data = io.BytesIO()
                preview.save(data, format="PNG")
            raw = data.getvalue()
            parsed = guard.png_extract(raw)
            region = [0, 0, image["width"], height]
            if guard.png_roi(image, region) != guard.png_roi(parsed, region):
                raise ValueError("host preview crop does not preserve exact source pixels")
            write(self.out / "stop-observation-top1100.png", raw)
            metadata.update(available=True, path="stop-observation-top1100.png", width=image["width"],
                            height=height, sha256=guard.sha(raw), bytes=len(raw), exact_pixels_verified=True)
        write(self.out / "stop-preview.json", metadata)
        return metadata

    def owned_status(self):
        current = self.acceptance.current_status(self.adb, self.task_id)
        trigger, session = current.get("trigger") or {}, current.get("session") or {}
        if trigger.get("nonce_sha256") == self.nonce_sha:
            write(self.out / "trigger.json", trigger)
            if trigger.get("accepted") is False:
                self.state["trigger_failure"] = trigger
                raise ValueError("nonce trigger rejected; setup/trigger failure, not model inference failure")
        if session.get("debug_nonce_sha256") != self.nonce_sha:
            return None
        if session.get("app_uid") != self.uid or session.get("instruction_sha256") != self.plan["instruction_sha256"] or session.get("origin") != "private_debug_nonce":
            raise ValueError("nonce session ownership differs")
        task = session.get("task_id")
        if task is not None:
            if not isinstance(task, str) or not guard.ID.fullmatch(task) or self.task_id is not None and task != self.task_id:
                raise ValueError("nonce task identity changed")
            self.task_id = task
            owner = self.adb.app_json("files/control-tasks/" + task + "/owner.json")
            if owner is not None:
                if owner.get("task_id") != task or owner.get("instruction") != self.plan["instruction"] or owner.get("instruction_utf8_sha256") != self.plan["instruction_sha256"]:
                    raise ValueError("task owner bytes differ")
                write(self.out / "owner-binding.json", owner)
        write(self.out / "session.json", session)
        self.state.update(task_id=self.task_id, nonce_sha256=self.nonce_sha)
        return {"session": session, "trigger": trigger, "result": current.get("result")}

    def live_native(self):
        owned = self.owned_status()
        if not owned or not self.task_id:
            return None
        session, trigger = owned["session"], owned["trigger"]
        if session.get("running") is not True or trigger.get("nonce_sha256") != self.nonce_sha or trigger.get("accepted") is not True or trigger.get("private_request_consumed") is not True:
            return None
        if not (self.out / "owner-binding.json").is_file():
            return None
        names = self.adb.list_children("files/control-tasks/" + self.task_id)
        observations = {}
        for name in sorted((n for n in names if re.fullmatch(r"step-\d\d-before.json", n)), reverse=True):
            value = self.adb.app_json("files/control-tasks/" + self.task_id + "/" + name, optional=False)
            observations[value["observation_id"]] = value
        current_runs = set(self.adb.list_children("files/runs", directories=True)) - self.baseline_runs
        for run_id in sorted(current_runs):
            if not guard.ID.fullmatch(run_id):
                continue
            remote = "files/runs/" + run_id + "/"
            if self.adb.app_json(remote + "app-receipt.json") is not None:
                continue
            prompt = self.adb.app_bytes(remote + "prompt.txt", optional=True)
            stderr = self.adb.app_bytes(remote + "stderr.log", optional=True)
            if prompt is None or stderr is None or not self.acceptance.prompt_binding(prompt.decode("utf-8"), self.plan["instruction"], set(observations)):
                continue
            boot = re.findall(rb"HEPTA_APPUID_BOOTSTRAP uid=(\d+) euid=(\d+) pid=(\d+) plugin=llama_cpp register_rc=0 runtime=([^\r\n]+)", stderr)
            parent_guard = re.findall(rb"HEPTA_PARENT_GUARD armed expected=(\d+) observed=(\d+) signal=SIGKILL", stderr)
            if len(boot) != 1 or len(parent_guard) != 1 or parent_guard[0][0] != parent_guard[0][1] or int(boot[0][0]) != self.uid or int(boot[0][1]) != self.uid:
                continue
            worker, parent = self.process(int(boot[0][2])), self.process(int(parent_guard[0][0]))
            if worker is None or parent is None:
                continue
            guard.native_identity(worker, parent, run_id, self.plan["candidate"], self.app_root, self.runner, self.profile["file"], self.path_binding)
            body = prompt.decode("utf-8")[len("UNTRUSTED_DATA\n"):].partition("\nOWNER\n")[0]
            screen = guard.strict_json(body)["screen"]
            write(self.out / "live-prompt.txt", prompt)
            write(self.out / "live-stderr.log", stderr)
            write(self.out / "live-observation.json", observations[screen["observation_id"]])
            return {"task_id": self.task_id, "nonce_sha256": self.nonce_sha, "run_id": run_id,
                    "worker": worker, "parent": parent, "prompt_sha256": guard.sha(prompt),
                    "observation_id": screen["observation_id"], "observation_package": screen["package"],
                    "live_phase_proven": "owned_local_native_worker_alive", "generation_token_phase_proven": False,
                    "runtime_path_binding_sha256": guard.sha(json_bytes(self.path_binding))}
        return None

    def same_live(self, binding):
        owned = self.owned_status()
        if not owned or owned["session"].get("running") is not True:
            raise ValueError("the observed cancellation task is no longer running")
        worker, parent = self.process(binding["worker"]["pid"]), self.process(binding["parent"]["pid"])
        for observed, expected in ((worker, binding["worker"]), (parent, binding["parent"])):
            if observed is None or any(observed[k] != expected[k] for k in ("pid", "ppid", "start_ticks", "uid", "argv")):
                raise ValueError("the exact originally observed worker/parent is no longer alive")
        return worker

    def action_members(self):
        root = "files/control-tasks/" + self.task_id
        return {name: guard.sha(self.adb.app_bytes(root + "/" + name))
                for name in self.adb.list_children(root) if re.fullmatch(r"step-\d\d-action.json", name)}

    def launch_once(self):
        self.baseline_runs = set(self.adb.list_children("files/runs", directories=True))
        _, clock = self.adb.command(["date", "+%s"], label="private-request-phone-clock")
        now = int(clock.strip()) * 1000
        request = {"schema": "hepta.private-debug-task.v1", "nonce": self.nonce, "instruction": self.plan["instruction"],
                   "created_wall_ms": now, "expires_wall_ms": now + 600000}
        data = json_bytes(request)
        write(self.out / "debug-request.json", data, exclusive=True)
        script = "umask 077; if [ -e files/debug-task.json ] || [ -L files/debug-task.json ]; then exit 42; fi; set -C; cat > files/debug-task.json"
        self.adb.command(["run-as", guard.PACKAGE, "sh", "-c", script], label="write-one-private-request", input_data=data)
        if self.adb.app_bytes("files/debug-task.json") != data:
            raise ValueError("private request readback differs; no Intent sent")
        self.status("launching-once", launch_attempt_count=1, nonce_sha256=self.nonce_sha, cleanup_known=False)
        try:
            self.adb.command(["am", "start", "-W", "-n", self.acceptance.COMPONENT, "--ez", "auto_task", "true", "--es", "test_nonce", self.nonce], label="launch-private-task-once", timeout=30)
        except Exception as error:
            self.state["errors"].append("Intent outcome uncertain; observing, never resending: " + str(error))

    def collect(self):
        if not self.task_id:
            return
        result = self.acceptance.collect_evidence(self.adb, self.out, self.task_id, self.plan["instruction"],
                  self.baseline_runs, False, self.uid, self.plan["candidate"]["compute"],
                  self.plan["candidate"]["context_tokens"], self.plan["candidate"].get("model_profile", "lfm3-1.7b-qad-q4_0"))
        write(self.out / "collection.json", result)


def request(args):
    root = args.run_dir.expanduser().resolve(strict=True)
    state = guard.strict_json(safe_read(root / "status.json"))
    if args.kind == "start":
        if state.get("phase") != "armed":
            raise ValueError("monitor is not armed")
        value = {"schema": "hepta.lifecycle-start-request.v1", "host_run_id": state["host_run_id"],
                 "challenge": state["challenge"], "plan_sha256": state["plan_sha256"]}
    else:
        if state.get("phase") != "awaiting-observed-stop" or args.point is None or args.rectangle is None:
            raise ValueError("awaiting screenshot plus explicitly observed Stop point/rectangle required")
        value = {"schema": "hepta.lifecycle-cancel-request.v1", "host_run_id": state["host_run_id"],
                 "challenge": state["challenge"], "task_id": state["task_id"], "nonce_sha256": state["nonce_sha256"],
                 "run_id": state["live_binding"]["run_id"], "worker_pid": state["live_binding"]["worker"]["pid"],
                 "worker_start_ticks": state["live_binding"]["worker"]["start_ticks"],
                 "screenshot_sha256": state["screenshot_sha256"], "observed_control": "停止",
                 "point": args.point, "rectangle": args.rectangle, "requested_host_wall_ms": int(time.time() * 1000)}
    write(root / (args.kind + "-request.json"), value, exclusive=True)
    print(json.dumps({"request_written": args.kind, "host_run_id": state["host_run_id"], "phone_contacted": False}))


def monitor(probe):
    challenge = secrets.token_hex(32)
    probe.status("armed", challenge=challenge,
                 start_request_template={"schema": "hepta.lifecycle-start-request.v1",
                    "host_run_id": probe.state["host_run_id"], "challenge": challenge,
                    "plan_sha256": probe.state["plan_sha256"]})
    end = time.monotonic() + probe.plan["arm_timeout_seconds"]
    while time.monotonic() < end:
        start = control_file(probe.out / "start-request.json")
        if start is not None:
            expected = {"schema": "hepta.lifecycle-start-request.v1", "host_run_id": probe.state["host_run_id"],
                        "challenge": challenge, "plan_sha256": probe.state["plan_sha256"]}
            if start != expected:
                raise ValueError("start request does not bind this armed run")
            write(probe.out / "accepted-start-request.json", start, exclusive=True)
            break
        time.sleep(0.2)
    else:
        raise ValueError("armed request expired; no phone contact")
    probe.status("preflight")
    probe.setup()
    prior = probe.stable_idle()
    write(probe.out / "known-idle-before.json", prior)
    _, displays = probe.adb.command(["dumpsys", "SurfaceFlinger", "--display-id"], label="observed-physical-display-inventory")
    write(probe.out / "physical-display-inventory.txt", displays)
    if not re.search(rb"(?<!\d)" + probe.args.physical_display_id.encode() + rb"(?!\d)", displays):
        raise ValueError("operator-supplied physical display ID is absent from observed inventory")
    probe.window("focus-parser-before-task-launch")
    probe.launch_once()
    deadline = time.monotonic() + probe.plan["task_timeout_seconds"]
    binding = None
    while time.monotonic() < deadline:
        binding = probe.live_native()
        if binding:
            break
        if probe.task_id:
            result = probe.adb.app_json("files/control-tasks/" + probe.task_id + "/result.json")
            if result is not None:
                raise ValueError("task completed before an active native cancellation opportunity; no click or retry")
        time.sleep(0.3)
    if binding is None:
        raise ValueError("no bound live native worker observed before deadline")
    background = probe.window("background-window")
    background_ok = background["focus_package"] is not None and background["focus_package"] != guard.PACKAGE
    probe.same_live(binding)
    write(probe.out / "live-binding.json", binding, exclusive=True)
    write(probe.out / "background-proof.json", {**background, "native_binding": binding,
        "hepta_background_observed": background_ok,
        "focus_matches_model_observation": background["focus_package"] == binding["observation_package"]}, exclusive=True)
    probe.status("showing-existing-task", live_binding=binding, hepta_background_observed=background_ok)
    probe.adb.command(["am", "start", "-W", "-n", probe.acceptance.COMPONENT], label="show-existing-task-no-auto-extras", timeout=30)
    # Android can report launch completion while the activity transition is still
    # drawn. Retain both full frames; the human-selected Stop ROI must later be
    # identical in both, and still match the fresh pre-tap frame.
    time.sleep(1.0)
    probe.same_live(binding)
    image_first = probe.screenshot("stop-observation-first")
    time.sleep(0.3)
    probe.same_live(binding)
    image = probe.screenshot("stop-observation")
    focus = probe.window("stop-observation-window")
    if focus["focus_package"] != guard.PACKAGE or focus["top_focused_display"] != probe.args.logical_display_id:
        raise ValueError("Hepta and the explicit input display are not uniquely focused")
    probe.same_live(binding)
    shot_at = int(time.time() * 1000)
    preview = probe.stop_preview(image)
    probe.same_live(binding)
    challenge = secrets.token_hex(32)
    probe.status("awaiting-observed-stop", challenge=challenge, screenshot="stop-observation.png",
                 screenshot_sha256=guard.sha(image["png"]), screenshot_host_wall_ms=shot_at,
                 logical_display_id=probe.args.logical_display_id, physical_display_id=probe.args.physical_display_id,
                 screenshot_width=image["width"], screenshot_height=image["height"],
                 initial_frame_sha256=guard.sha(image_first["png"]), preview=preview,
                 cancel_request_template={"schema": "hepta.lifecycle-cancel-request.v1",
                    "host_run_id": probe.state["host_run_id"], "challenge": challenge,
                    "task_id": probe.task_id, "nonce_sha256": probe.nonce_sha, "run_id": binding["run_id"],
                    "worker_pid": binding["worker"]["pid"], "worker_start_ticks": binding["worker"]["start_ticks"],
                    "screenshot_sha256": guard.sha(image["png"]), "observed_control": "停止",
                    "point": None, "rectangle": None, "requested_host_wall_ms": None})
    while time.monotonic() < deadline:
        stop = control_file(probe.out / "cancel-request.json")
        if stop is not None:
            break
        probe.same_live(binding)
        time.sleep(0.3)
    else:
        raise ValueError("visible cancellation request not received; no Stop click sent")
    expected = {"schema": "hepta.lifecycle-cancel-request.v1", "host_run_id": probe.state["host_run_id"],
                "challenge": challenge, "task_id": probe.task_id, "nonce_sha256": probe.nonce_sha,
                "run_id": binding["run_id"], "worker_pid": binding["worker"]["pid"],
                "worker_start_ticks": binding["worker"]["start_ticks"], "screenshot_sha256": guard.sha(image["png"]),
                "observed_control": "停止"}
    if set(stop) != set(expected) | {"point", "rectangle", "requested_host_wall_ms"} or any(type(stop.get(k)) is not type(v) or stop.get(k) != v for k, v in expected.items()):
        raise ValueError("operator Stop request is stale or binds a different task/worker/screenshot")
    now = int(time.time() * 1000)
    if type(stop["requested_host_wall_ms"]) is not int or not shot_at <= stop["requested_host_wall_ms"] <= now + 1000 or now - shot_at > probe.plan["operator_request_max_age_seconds"] * 1000:
        raise ValueError("operator-observed screenshot/request expired")
    point, rectangle = stop["point"], stop["rectangle"]
    roi = guard.stable_stop_roi(image_first, image, rectangle)
    if not isinstance(point, list) or len(point) != 2 or any(type(p) is not int for p in point) or not rectangle[0] < point[0] < rectangle[2] or not rectangle[1] < point[1] < rectangle[3]:
        raise ValueError("explicit observed tap point must be inside observed Stop rectangle")
    # The human can inspect Stop during native hash/create. Keep the exact owned
    # worker alive check, then wait for the pinned SDK's real generate entry so a
    # short token-generation window does not require another remote round trip.
    probe.status("awaiting-native-generate-entry", operator_cancel_request_validated=True)
    generate_line = None
    while time.monotonic() < deadline:
        probe.same_live(binding)
        live_stderr = probe.adb.app_bytes("files/runs/" + binding["run_id"] + "/stderr.log")
        matches = GENERATE_ENTRY.findall(live_stderr)
        if matches:
            generate_line = matches[-1].decode("utf-8")
            write(probe.out / "generate-entry-stderr.log", live_stderr, exclusive=True)
            break
        if int(time.time() * 1000) - shot_at > probe.plan["operator_request_max_age_seconds"] * 1000:
            raise ValueError("generate entry was not observed before screenshot expiry; no click sent")
        time.sleep(0.1)
    if generate_line is None:
        raise ValueError("real SDK generate entry not observed; no inference-cancel claim")
    fresh = probe.screenshot("immediately-before-stop")
    if guard.png_roi(fresh, rectangle) != roi:
        raise ValueError("observed Stop control pixels changed; no guessed click sent")
    focus = probe.window("immediately-before-stop-window")
    if focus["focus_package"] != guard.PACKAGE or focus["top_focused_display"] != probe.args.logical_display_id:
        raise ValueError("foreground/display changed before Stop click")
    probe.same_live(binding)
    actions_before = probe.action_members()
    runs_before = set(probe.adb.list_children("files/runs", directories=True))
    write(probe.out / "accepted-cancel-request.json", stop, exclusive=True)
    probe.status("stop-click-attempted-once", tap_attempt_count=1, stop_roi_sha256=roi,
                 original_worker_live_immediately_before_tap=True,
                 native_generate_entry_observed=True, native_generate_entry_line=generate_line)
    tap_ok = False
    try:
        probe.adb.command(["input", "-d", str(probe.args.logical_display_id), "tap", str(point[0]), str(point[1])], label="observed-visible-stop-single-tap")
        tap_ok = True
    except Exception as error:
        probe.state["errors"].append("tap transport outcome uncertain; no retry: " + str(error))
    probe.status("observing-owned-worker-exit", tap_command_completed=tap_ok)
    idle = probe.stable_idle(expected_task=probe.task_id, expected_nonce=probe.nonce_sha, timeout=probe.plan["cleanup_grace_seconds"])
    original = probe.process(binding["worker"]["pid"])
    exited = original is None or original["start_ticks"] != binding["worker"]["start_ticks"]
    parent = probe.process(binding["parent"]["pid"])
    parent_same = parent is not None and all(parent[k] == binding["parent"][k] for k in ("pid", "ppid", "start_ticks", "uid", "argv"))
    receipt = probe.adb.app_json("files/runs/" + binding["run_id"] + "/app-receipt.json", optional=False)
    result = probe.adb.app_json("files/control-tasks/" + probe.task_id + "/result.json", optional=False)
    guard.cancellation_receipt(receipt, result, idle["session"], binding, probe.plan["candidate"], probe.uid)
    unchanged_actions = probe.action_members() == actions_before
    unchanged_runs = set(probe.adb.list_children("files/runs", directories=True)) == runs_before
    write(probe.out / "known-idle-after-cancel.json", idle, exclusive=True)
    write(probe.out / "cancelled-native-receipt.json", receipt, exclusive=True)
    passed = tap_ok and exited and parent_same and unchanged_actions and unchanged_runs
    probe.status("cancel-complete", verdict="pass" if passed else "unverified", cleanup_known=True,
                 original_worker_exit_observed=exited, original_app_process_survived=parent_same,
                 no_new_dispatch_after_observed_stop=unchanged_actions, no_new_native_run_after_stop=unchanged_runs,
                 cancel_task_nonce_native_binding_valid=True,
                 local_model_path_and_hash_bound=True, internet_permission_declared=False,
                 device_offline_proven=False, generation_token_phase_proven=False,
                 background_case_verdict="pass" if background_ok else "unverified")


def membership(probe):
    return {name: probe.adb.list_children("files/" + name, directories=(name != "debug-consumed"))
            for name in ("runs", "control-tasks", "debug-consumed")}


def idle_restart(probe):
    """Restart only after complete stable idle evidence; never an active-task teardown."""
    probe.status("idle-restart-preflight")
    probe.setup()
    before = probe.stable_idle()
    processes = before["processes"]
    app_rows = [row for row in processes if row["argv0"] == guard.PACKAGE]
    if len(app_rows) != 1:
        raise ValueError("exactly one existing ordinary App process required for restart proof")
    original = probe.process(app_rows[0]["pid"])
    if original is None or original["uid"] != probe.uid or original["argv"] != [guard.PACKAGE]:
        raise ValueError("original idle App process identity unavailable")
    baseline = membership(probe)
    write(probe.out / "known-idle-before-restart.json", before, exclusive=True)
    write(probe.out / "membership-before-restart.json", baseline, exclusive=True)
    write(probe.out / "original-idle-app-process.json", original, exclusive=True)
    # The supervisor must own the phone exclusively for this bounded experiment.
    # A final same-shell hash/sidecar/worker guard precedes the ONLY force-stop.
    # No fallback path force-stops an active or unresolved session.
    gate = "set -e; "
    for p in SIDE_RECORDS:
        gate += "if [ -e " + shlex.quote(p) + " ] || [ -L " + shlex.quote(p) + " ]; then exit 42; fi; "
    gate += "test ! -L files/control-session.json; actual=$(sha256sum files/control-session.json); test \"${actual%% *}\" = " + shlex.quote(before["session_sha256"])
    ps_gate = "inventory=$(ps -A -o UID,ARGS); printf '%s\\n' \"$inventory\" | awk -v runner=" + shlex.quote(probe.runner) + " 'NR==1 {if ($1!=\"UID\" || $2!=\"ARGS\") exit 43; next} $2==runner {exit 44} END {if(NR<1) exit 43}'"
    command = "set -e; " + shlex.join(["run-as", guard.PACKAGE, "sh", "-c", gate]) + "; " + ps_gate + "; " + shlex.join(["am", "force-stop", guard.PACKAGE])
    probe.status("idle-stop-attempted-once", idle_stop_attempt_count=1, complete_idle_guard=before)
    probe.adb.command(["sh", "-c", command], label="guarded-known-idle-force-stop-once", timeout=30)
    end = time.monotonic() + 10
    old_gone = False
    while time.monotonic() < end:
        current = probe.process(original["pid"])
        if current is None or current["start_ticks"] != original["start_ticks"]:
            old_gone = True
            break
        time.sleep(0.3)
    if not old_gone:
        raise ValueError("idle original App process exit is unknown; no automatic retry")
    probe.status("starting-idle-ui-without-auto-extras", original_idle_app_exit_observed=True)
    probe.adb.command(["am", "start", "-W", "-n", probe.acceptance.COMPONENT], label="idle-restart-show-ui-no-auto-extras", timeout=30)
    end = time.monotonic() + probe.plan["restart_observation_seconds"]
    samples = []
    while time.monotonic() < end:
        after = probe.idle(expected_task=before["session"]["task_id"], expected_nonce=before["session"]["debug_nonce_sha256"])
        if after["session_sha256"] != before["session_sha256"] or membership(probe) != baseline:
            raise ValueError("idle restart changed task/run/nonce consumption or prior terminal session")
        rows = [r for r in after["processes"] if r["argv0"] == guard.PACKAGE]
        if len(rows) != 1:
            raise ValueError("new App process not uniquely established")
        new = probe.process(rows[0]["pid"])
        if new is None or new["uid"] != probe.uid or new["argv"] != [guard.PACKAGE] or (new["pid"], new["start_ticks"]) == (original["pid"], original["start_ticks"]):
            raise ValueError("actual App restart not established")
        samples.append({"session_sha256": after["session_sha256"], "new_pid": new["pid"],
                        "new_start_ticks": new["start_ticks"], "observed_host_wall_ms": after["observed_host_wall_ms"]})
        time.sleep(1)
    service = probe.service_observation("accessibility-service-after-restart")
    write(probe.out / "idle-restart-samples.json", samples, exclusive=True)
    probe.status("idle-restart-no-replay-observed", verdict="pass", cleanup_known=True,
                 original_idle_app_exit_observed=True, new_app_process_observed=True,
                 unchanged_prior_terminal_session=True, no_new_tasks_runs_or_consumed_nonces=True,
                 observation_seconds=probe.plan["restart_observation_seconds"],
                 service_after=service, accessibility_operational_after_restart="requires_fresh_task_evidence",
                 permission_or_service_configuration_modified=False, automatic_rebind_attempted=False)


def followup(args):
    """Evaluate a separately executed fresh task without submitting, resuming or replaying it."""
    before_raw = safe_read(args.prior_status)
    before = guard.strict_json(before_raw)
    root = args.case_dir.expanduser().resolve(strict=True)
    raw = safe_read(root / "acceptance.json")
    result = guard.strict_json(raw)
    if before.get("schema") != "hepta.lifecycle-state.v1" or before.get("verdict") != "pass" or before.get("cleanup_known") is not True:
        raise ValueError("a verified clean prior lifecycle outcome is required")
    if before.get("phase") == "cancel-complete":
        old_task, old_nonce = before["task_id"], before["nonce_sha256"]
    elif before.get("phase") == "idle-restart-no-replay-observed":
        session = before["complete_idle_guard"]["session"]
        old_task, old_nonce = session["task_id"], session["debug_nonce_sha256"]
    else:
        raise ValueError("prior lifecycle phase cannot be followed up")
    candidate = before["candidate"]
    basic = (result.get("schema") == "hepta.host-acceptance.v1" and result.get("launch_attempt_count") == 1
             and result.get("trigger_binding_verified") is True and result.get("owner_binding_verified") is True
             and isinstance(result.get("task_id"), str) and guard.ID.fullmatch(result["task_id"])
             and result["task_id"] != old_task and isinstance(result.get("nonce_sha256"), str)
             and guard.SHA.fullmatch(result["nonce_sha256"]) and result["nonce_sha256"] != old_nonce)
    trigger = guard.strict_json(safe_read(root / "trigger.json"))
    basic = bool(basic and trigger.get("nonce_sha256") == result.get("nonce_sha256") and trigger.get("accepted") is True
                 and trigger.get("private_request_consumed") is True and trigger.get("app_uid") == before["app_uid"])
    debug = guard.strict_json(safe_read(root / "debug-request.json"))
    owner = guard.strict_json(safe_read(root / "owner-binding.json"))
    basic = bool(basic and isinstance(debug.get("nonce"), str) and guard.SHA.fullmatch(debug["nonce"])
                 and guard.sha(debug["nonce"].encode()) == result.get("nonce_sha256")
                 and debug.get("instruction") == result.get("instruction") == owner.get("instruction")
                 and owner.get("task_id") == result.get("task_id")
                 and owner.get("instruction_utf8_sha256") == result.get("instruction_sha256")
                 and guard.sha(result["instruction"].encode()) == result.get("instruction_sha256"))
    observations = set()
    for file in (root / "task").glob("step-*-before.json"):
        observation = guard.strict_json(safe_read(file)).get("observation_id")
        if isinstance(observation, str) and guard.ID.fullmatch(observation):
            observations.add(observation)
    started, clean_exited = [], []
    for row in result.get("collection", {}).get("associated_runs", []):
        run = row.get("run_id")
        if not isinstance(run, str) or not guard.ID.fullmatch(run):
            raise ValueError("invalid follow-up run identity")
        receipt = guard.strict_json(safe_read(root / "runs" / run / "app-receipt.json"))
        expected = {"schema": "hepta.local-model.receipt.v2", "run_id": run, "package_name": guard.PACKAGE,
                    "app_uid": before["app_uid"], "process_started": True, "model_sha256_verified": candidate["model_sha256"],
                    "model_profile": candidate.get("model_profile", "lfm3-1.7b-qad-q4_0"), "compute_requested": candidate["compute"],
                    "context_tokens": candidate["context_tokens"], "runtime": "llama_cpp", "mode": "llm", "fallback_allowed": False}
        valid = all(type(receipt.get(k)) is type(v) and receipt.get(k) == v for k, v in expected.items())
        prompt = safe_read(root / "runs" / run / "prompt.txt").decode("utf-8")
        payload, separator, instruction = prompt.removeprefix("UNTRUSTED_DATA\n").partition("\nOWNER\n")
        bound_prompt = (prompt.startswith("UNTRUSTED_DATA\n") and separator and instruction == result.get("instruction")
                        and guard.strict_json(payload).get("screen", {}).get("observation_id") in observations
                        and receipt.get("prompt_sha256") == guard.sha(prompt.encode()))
        valid = bool(valid and bound_prompt and type(receipt.get("app_pid")) is int and receipt["app_pid"] > 1
                     and receipt.get("expected_parent_pid") == receipt["app_pid"])
        if valid:
            started.append(run)
            if receipt.get("process_exit_observed") is True:
                clean_exited.append(run)
    new_started = basic and bool(started)
    output = {"schema": "hepta.lifecycle-followup-review.v1", "phone_contacted": False,
              "prior_status_sha256": guard.sha(before_raw), "new_acceptance_sha256": guard.sha(raw),
              "different_task_and_nonce_verified": basic, "new_owned_native_runs_started": started,
              "new_owned_native_runs_with_observed_exit": clean_exited,
              "new_task_started_after_clean_prior_outcome": new_started,
              "accessibility_connected_gate_passed_by_real_trigger": basic,
              "new_task_native_generation_fully_verified": result.get("native_receipts_verified") is True,
              "new_task_goal_verdict_preserved": result.get("verdict"),
              "new_task_cleanup_unknown": result.get("cleanup_unknown"),
              "verdict": "pass" if new_started and result.get("cleanup_unknown") is False and len(clean_exited) == len(started) else "unverified",
              "full_phone_acceptance": "not_assessed"}
    write(args.output.expanduser().resolve(), output, exclusive=True)
    print(json.dumps(output, ensure_ascii=False))
    return 0 if output["verdict"] == "pass" else 3


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="operation", required=True)
    freezing = sub.add_parser("prepare", help="offline freeze; no phone contact")
    freezing.add_argument("--source-dir", type=Path, required=True)
    freezing.add_argument("--candidate", type=Path, required=True)
    freezing.add_argument("--instruction-file", type=Path, required=True)
    freezing.add_argument("--output", type=Path, required=True)
    requesting = sub.add_parser("request", help="write one local control request; no phone contact")
    requesting.add_argument("kind", choices=("start", "cancel"))
    requesting.add_argument("--run-dir", type=Path, required=True)
    requesting.add_argument("--point", nargs=2, type=int)
    requesting.add_argument("--rectangle", nargs=4, type=int)
    reviewing = sub.add_parser("followup", help="offline review of a separately run fresh task")
    reviewing.add_argument("--prior-status", type=Path, required=True)
    reviewing.add_argument("--case-dir", type=Path, required=True)
    reviewing.add_argument("--output", type=Path, required=True)
    for name in ("monitor", "idle-restart"):
        run = sub.add_parser(name)
        run.add_argument("--plan", type=Path, required=True)
        run.add_argument("--output", type=Path, required=True)
        run.add_argument("--adb", required=True)
        run.add_argument("--adb-host", default="127.0.0.1")
        run.add_argument("--adb-port", type=int, required=True)
        run.add_argument("--serial", required=True)
        run.add_argument("--command-timeout", type=float, default=15)
        if name == "monitor":
            run.add_argument("--physical-display-id", required=True, help="observed SurfaceFlinger physical display ID")
            run.add_argument("--logical-display-id", type=int, required=True, help="observed input logical display ID")
            run.add_argument("--input-width", type=int, required=True, help="observed logical input width, same pixel mapping as screenshot")
            run.add_argument("--input-height", type=int, required=True)
    return result


def main():
    args = parser().parse_args()
    if args.operation == "prepare":
        prepare(args)
        return 0
    if args.operation == "request":
        request(args)
        return 0
    if args.operation == "followup":
        return followup(args)
    if not 1 <= args.adb_port <= 65535 or not 1 <= args.command_timeout <= 120 or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.serial):
        raise ValueError("explicit valid device identity and command timeout required")
    if args.operation == "monitor" and (not re.fullmatch(r"\d{1,20}", args.physical_display_id) or not 0 <= args.logical_display_id <= 65535 or not 0 < args.input_width <= 8192 or not 0 < args.input_height <= 8192):
        raise ValueError("explicit observed display identity/geometry required")
    probe = Probe(args)
    try:
        monitor(probe) if args.operation == "monitor" else idle_restart(probe)
    except (Exception, KeyboardInterrupt) as error:
        probe.state["errors"].append(type(error).__name__ + ": " + str(error))
        probe.status("inconclusive-no-automatic-teardown", verdict="unverified",
                     manual_cleanup_may_be_required=probe.state.get("launch_attempt_count", 0) > 0 and probe.state.get("cleanup_known") is not True)
    finally:
        if args.operation == "monitor" and probe.state.get("phone_contacted"):
            try:
                probe.collect()
            except Exception as error:
                probe.state["errors"].append("collection: " + str(error))
                probe.state["verdict"] = "unverified"
        probe.status()
        write(probe.out / "lifecycle-result.json", probe.state, exclusive=True)
    return 0 if probe.state["verdict"] == "pass" else 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({"error": str(error), "automatic_retry": False}), file=sys.stderr)
        sys.exit(2)
