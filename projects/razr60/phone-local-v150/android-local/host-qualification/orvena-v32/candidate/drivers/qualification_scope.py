"""Fail-closed host evidence and transport for an explicitly scoped qualification.

This module performs no phone command and never grants a semantic PASS.  The
Android scope gate remains the authority immediately before actual dispatch.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct

SCHEMA = "hepta.orvena-scoped-host-binding.v2"
PACKAGE = "org.trillionnium.hepta.local"
PROFILE = "orvena-4b-q4_k_m"
MODEL_SHA = "c5d6df6e9a0828fa3068dfc6f6ca2ff6c4d950adc7e60e4b7202ece61595aa57"
MODEL_BYTES = 2783447904
SHA = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[0-9a-f]{32}\Z")
ROLES = {"settings": "com.android.settings", "search": "com.android.settings.intelligence",
         "calculator": "com.motorola.cn.calculator", "launcher": "com.motorola.launcher3"}
ORDINARY_INSTRUCTION = "打开系统设置，进入“应用”页面，停留在这个页面。"
ORDINARY_SHA = "13e2d90d46fe98e90e96758a3136ae9a1a866bc2874cd98b9c54e6328fe65d92"
ASSET_NAME = "assets/hepta-build-identity.json"


def verify_package(root, expected_sha):
    root = Path(root).resolve(strict=True)
    raw = read(root / "PACKAGE-MANIFEST.json")
    need(isinstance(expected_sha, str) and SHA.fullmatch(expected_sha) and sha(raw) == expected_sha,
         "reviewed helper package SHA differs")
    value = strict(raw)
    need(value.get("schema") == "hepta.orvena-v32-scoped-package.v1" and value.get("source_commit") ==
         "e07c6624b7309b0acf3fe10e31b0605a29e3e72d" and isinstance(value.get("files"), dict),
         "qualified host helper manifest differs")
    found = set()
    for path in root.rglob("*"):
        if "__pycache__" in path.parts or path == root / "PACKAGE-MANIFEST.json": continue
        if path.is_file() or path.is_symlink(): found.add(str(path.relative_to(root)))
    need(found == set(value["files"]), "host helper closure membership changed")
    for name, pin in value["files"].items():
        part = Path(name)
        need(not part.is_absolute() and ".." not in part.parts and (root / part).resolve().is_relative_to(root), "unsafe helper member")
        payload = read(root / part)
        need(isinstance(pin, dict) and set(pin) == {"sha256", "bytes"}
             and type(pin["bytes"]) is int and len(payload) == pin["bytes"] and sha(payload) == pin["sha256"],
             "host helper member changed: " + name)
    return value


def need(value, message):
    if not value:
        raise ValueError("qualification scope: " + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, "duplicate JSON key " + key)
            out[key] = value
        return out
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)))
    # Reject isolated surrogates and NUL, including escaped occurrences.
    def walk(item):
        if isinstance(item, str):
            item.encode("utf-8", "strict"); need("\0" not in item, "NUL in JSON string")
        elif isinstance(item, dict):
            for key, entry in item.items():
                walk(key); walk(entry)
        elif isinstance(item, list):
            for entry in item: walk(entry)
        elif isinstance(item, float):
            need(math.isfinite(item), "nonfinite JSON number")
    walk(value)
    return value


def equal(left, right):
    """JSON equality which never confuses true/false with 1/0."""
    if isinstance(left, dict) and isinstance(right, dict):
        return set(left) == set(right) and all(equal(left[k], right[k]) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(equal(a, b) for a, b in zip(left, right))
    if type(left) in (int, float) and type(right) in (int, float):
        return math.isfinite(left) and math.isfinite(right) and left == right
    return type(left) is type(right) and left == right


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def read(path, limit=8 << 20):
    path = Path(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
         "nonregular, linked or oversize host file: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    def identity(item):
        return (item.st_dev, item.st_ino, item.st_size, item.st_mode, item.st_nlink,
                item.st_mtime_ns, item.st_ctime_ns)
    need(identity(before) == identity(opened) == identity(after) == identity(path.lstat())
         and len(data) == before.st_size, "host file changed while reading")
    return data


def private_write(path, raw):
    path = Path(path); path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def positive_int(value, limit=(1 << 63) - 1):
    return type(value) is int and 0 < value <= limit


def f32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


def expected_sampler():
    # Same real C float values written by the v32 request-local producer.
    return dict(temperature=f32(.7), top_p=f32(.8), top_k=40, repetition_penalty=1,
                seed=42, min_p=f32(.05), presence_penalty=0, frequency_penalty=0)


def sampler_valid(value):
    return equal(value, expected_sampler())


def validate_scope(raw):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 16384, "scope byte bound")
    value = strict(raw)
    keys = {"schema", "enabled", "qualification_id", "build_identity_sha256",
            "runtime_config_sha256", "hepta_apk_sha256", "hepta_version_code", "launcher_component"}
    keys |= {role + "_" + suffix for role in ROLES
             for suffix in ("package", "uid", "version_code", "apk_set_sha256", "observation_sha256")}
    need(isinstance(value, dict) and set(value) == keys, "scope closed fields differ")
    need(value["schema"] == "hepta.qualification-scope.v1" and value["enabled"] is True,
         "scope disabled or schema differs")
    need(isinstance(value["qualification_id"], str)
         and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value["qualification_id"]), "qualification ID")
    need(positive_int(value["hepta_version_code"]), "scope version")
    for key in ("build_identity_sha256", "runtime_config_sha256", "hepta_apk_sha256"):
        need(isinstance(value[key], str) and SHA.fullmatch(value[key]), "invalid " + key)
    for role, package in ROLES.items():
        need(value[role + "_package"] == package, "unobserved role package " + role)
        uid = value[role + "_uid"]
        need(type(uid) is int and 0 <= uid <= (1 << 31) - 1, "role UID")
        need(positive_int(value[role + "_version_code"]), "role version")
        for suffix in ("apk_set_sha256", "observation_sha256"):
            digest = value[role + "_" + suffix]
            need(isinstance(digest, str) and SHA.fullmatch(digest), "role digest")
    home = value["launcher_component"]
    need(isinstance(home, str) and re.fullmatch(re.escape(ROLES["launcher"]) + r"/[A-Za-z0-9_.$]+", home),
         "explicit HOME component differs")
    need(not home.split("/", 1)[1].startswith("."), "HOME must use full PackageManager component name")
    return value


def validate_original_observation(raw, package):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 2 << 20, "observation byte bound")
    observation = strict(raw); window = observation.get("window")
    need(isinstance(observation, dict) and observation.get("package") == package
         and isinstance(observation.get("observation_id"), str) and ID.fullmatch(observation["observation_id"]),
         "original observation package/ID differs")
    need(isinstance(window, dict) and window.get("scope") == "active_root_only"
         and window.get("metadata_status") == "observed" and type(window.get("type")) is int
         and window["type"] == 1 and type(window.get("display_id")) is int and window["display_id"] == 0
         and type(window.get("window_id")) is int and window["window_id"] >= 0
         and type(observation.get("window_id")) is int and observation["window_id"] == window["window_id"],
         "original active application window identity unknown")
    return {"package": package, "sha256": sha(raw), "bytes": len(raw),
            "observation_id": observation["observation_id"], "window_id": window["window_id"]}


def apk_set_sha(rows):
    need(isinstance(rows, list) and rows, "APK rows missing")
    found = {}
    for row in rows:
        need(isinstance(row, dict) and set(row) == {"key", "sha256"}, "APK row fields")
        key, digest = row["key"], row["sha256"]
        need(isinstance(key, str) and (key == "base" or re.fullmatch(r"split:[A-Za-z0-9_.-]+", key)), "APK row key")
        need(key not in found and isinstance(digest, str) and SHA.fullmatch(digest), "duplicate APK row or invalid hash")
        found[key] = digest
    need("base" in found, "base APK row missing")
    return sha("".join(key + "\t" + found[key] + "\n" for key in sorted(found)).encode("utf-8"))


def validate_candidate(candidate):
    need(isinstance(candidate, dict) and set(candidate) == {"package", "apk_sha256", "version_code",
         "model_profile", "model_sha256", "compute", "context_tokens", "threads"}, "candidate fields")
    need(candidate["package"] == PACKAGE and candidate["version_code"] == 32 and type(candidate["version_code"]) is int
         and isinstance(candidate["apk_sha256"], str) and SHA.fullmatch(candidate["apk_sha256"]), "actual v32 APK required")
    need(candidate["model_profile"] == PROFILE and candidate["model_sha256"] == MODEL_SHA
         and candidate["compute"] in ("npu", "gpu") and type(candidate["context_tokens"]) is int
         and candidate["context_tokens"] == 8192 and type(candidate["threads"]) is int and candidate["threads"] == 4,
         "only explicit Orvena 8192/4 axis is qualified by this helper")


def validate_device_target(value):
    need(isinstance(value, dict) and set(value) == {"serial", "logical_display_id", "physical_display_id", "input_width", "input_height"},
         "explicit private device target required")
    need(isinstance(value["serial"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value["serial"]),
         "explicit target serial required")
    need(type(value["logical_display_id"]) is int and value["logical_display_id"] == 0
         and isinstance(value["physical_display_id"], str) and re.fullmatch(r"[0-9]{1,20}", value["physical_display_id"]),
         "explicit observed default display required")
    need(all(type(value[key]) is int and 1 <= value[key] <= 8192 for key in ("input_width", "input_height")),
         "explicit observed display dimensions required")
    return value


def require_device_target(args, binding, display=False):
    target = validate_device_target(binding.get("device_target"))
    need(getattr(args, "serial", None) == target["serial"], "selected serial differs from private binding")
    if display:
        need(all(getattr(args, key, None) == target[key] for key in
                 ("logical_display_id", "physical_display_id", "input_width", "input_height")),
             "selected display differs from private binding")
    return target


def load_binding(path, expected_sha):
    path = Path(path).resolve(strict=True)
    raw = read(path)
    need(isinstance(expected_sha, str) and SHA.fullmatch(expected_sha) and sha(raw) == expected_sha,
         "binding manifest SHA differs")
    value = strict(raw)
    need(isinstance(value, dict) and value.get("schema") == SCHEMA and value.get("phone_contacted") is False,
         "host binding schema differs")
    validate_device_target(value.get("device_target"))
    validate_candidate(value.get("candidate"))
    need(positive_int(value.get("app_uid"), (1 << 31) - 1) and value["app_uid"] >= 10000, "ordinary application UID required")
    files = value.get("files"); need(isinstance(files, dict), "binding files missing")
    required = {"qualification-scope.json", "build-identity.json", "runtime-config.json", "mac-build-receipt.json",
                "static-acceptance.json", "role-identities.json", "source-integration-manifest.json"} | {"observations/" + role + ".json" for role in ROLES}
    need(set(files) == required, "binding file closure differs")
    content = {}
    for name, pin in files.items():
        need(isinstance(pin, dict) and set(pin) == {"sha256", "bytes"}
             and type(pin["bytes"]) is int and pin["bytes"] >= 0, "file pin fields")
        payload = read(path.parent / name)
        need(len(payload) == pin["bytes"] and sha(payload) == pin["sha256"], "binding file changed: " + name)
        content[name] = payload
    scope = validate_scope(content["qualification-scope.json"])
    need(value.get("scope_sha256") == sha(content["qualification-scope.json"]), "scope digest differs")
    need(scope["hepta_apk_sha256"] == value["candidate"]["apk_sha256"]
         and scope["hepta_version_code"] == value["candidate"]["version_code"], "scope candidate differs")
    for field, name in (("build_identity_sha256", "build-identity.json"), ("runtime_config_sha256", "runtime-config.json")):
        need(scope[field] == sha(content[name]) == value.get(field), "bound " + field + " differs")
    asset = strict(content["build-identity.json"]); mac = strict(content["mac-build-receipt.json"])
    need(asset.get("schema") == "hepta.actual-build-inputs.v1" and type(asset.get("version_code")) is int
         and asset["version_code"] == 32 and isinstance(asset.get("source_inputs"), list)
         and asset["source_inputs"] and equal(asset["source_inputs"], mac.get("source_inputs")), "actual compiler input map differs")
    static = strict(content["static-acceptance.json"])
    need(static.get("schema") == "hepta.local-model.static-acceptance.v3" and static.get("package") == PACKAGE
         and static.get("version_code") == 32 and static.get("apk_sha256") == scope["hepta_apk_sha256"]
         and static.get("actual_build_identity_asset") == ASSET_NAME and static.get("actual_build_identity_sha256") == scope["build_identity_sha256"]
         and equal(static.get("permissions"), []), "exact APK static receipt differs")
    need(sha(content["source-integration-manifest.json"]) == value.get("complete_source_inventory_sha256"),
         "actual complete source integration receipt differs")
    integration = strict(content["source-integration-manifest.json"])
    need(integration.get("schema") == "hepta.independent-v32-source-integration.v1"
         and integration.get("source_commit") == value.get("source_commit") == "e07c6624b7309b0acf3fe10e31b0605a29e3e72d"
         and integration.get("source_tree") == "81955c2053ba24cab0783c9cb7636a49c0f186de"
         and integration.get("actual_source_assembly_verified") is True
         and integration.get("portable_inventory_sha256") == value.get("portable_source_inventory_sha256") ==
             "b9c1355c16658c354550aad818053e9e5d8bb12ce7150d7b861de109a1000b90"
         and type(integration.get("file_count")) is int and integration["file_count"] == 1194,
         "actual complete source identity differs")
    runtime = strict(content["runtime-config.json"])
    expected_runtime = {"schema": "hepta.local-runtime.v2", **{key: value["candidate"][key]
                        for key in ("model_profile", "compute", "context_tokens", "threads")}}
    need(equal(runtime, expected_runtime), "runtime configuration differs")
    need(sampler_valid(value.get("sampler_requested")), "v32 Orvena F32 requested sampler differs")
    for role, package in ROLES.items():
        proof = validate_original_observation(content["observations/" + role + ".json"], package)
        need(proof["sha256"] == scope[role + "_observation_sha256"], "role observation bytes differ")
    identities = strict(content["role-identities.json"])
    need(identities.get("schema") == "hepta.scope-installed-role-identities.v1"
         and identities.get("launcher_component") == scope["launcher_component"]
         and isinstance(identities.get("roles"), dict) and set(identities["roles"]) == set(ROLES),
         "bound role installation inventory differs")
    for role, package in ROLES.items():
        identity = identities["roles"][role]
        need(identity.get("package") == package and identity.get("enabled") is True
             and identity.get("stable_before_after") is True
             and type(identity.get("uid")) is int and identity["uid"] == scope[role + "_uid"]
             and type(identity.get("version_code")) is int and identity["version_code"] == scope[role + "_version_code"]
             and apk_set_sha(identity.get("apk_rows")) == identity.get("apk_set_sha256") == scope[role + "_apk_set_sha256"],
             "captured installed role differs: " + role)
    return {**value, "binding_sha256": expected_sha, "scope": scope, "runtime_config": runtime,
            "raw_files": content, "raw_binding": raw, "binding_path": str(path)}


def snapshot(binding, directory):
    directory = Path(directory); directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, raw in binding["raw_files"].items(): private_write(directory / name, raw)
    private_write(directory / "BINDING.json", binding["raw_binding"])
    return directory / "BINDING.json"


def review(directory, binding, task_id, instruction, collection):
    value = {"schema": "hepta.host-scoped-task-review.v1", "verified": False,
             "binding_sha256": binding["binding_sha256"], "scope_sha256": binding["scope_sha256"],
             "semantic_pass_granted": False, "errors": []}
    try:
        value["task_scope"] = task_evidence(directory, binding, task_id, instruction)
        value["native_sampler"] = sampled_native(directory, collection)
        value["verified"] = True
    except (ValueError, OSError, KeyError, TypeError) as error:
        value["errors"].append(str(error))
    return value


def from_args(args):
    path = getattr(args, "qualification_binding", None)
    digest = getattr(args, "qualification_binding_sha256", None)
    need((path is None) == (digest is None), "both qualification binding parameters required")
    return None if path is None else load_binding(path, digest)


def add_arguments(parser, required=True):
    parser.add_argument("--qualification-binding", type=Path, required=required)
    parser.add_argument("--qualification-binding-sha256", required=required)


def intent_extra(binding):
    need(isinstance(binding.get("scope_sha256"), str) and SHA.fullmatch(binding["scope_sha256"]), "expected scope SHA missing")
    return ["--es", "expected_scope_sha256", binding["scope_sha256"]]


def debug_intent(nonce, binding):
    need(isinstance(nonce, str) and SHA.fullmatch(nonce), "one-use nonce invalid")
    return ["am", "start", "-W", "-n", PACKAGE + "/.MainActivity", "--ez", "auto_task", "true",
            "--es", "test_nonce", nonce] + intent_extra(binding)


def ordinary_intent(instruction, binding):
    need(instruction == ORDINARY_INSTRUCTION and sha(instruction.encode()) == ORDINARY_SHA, "ordinary instruction changed")
    return ["am", "start", "-W", "--user", "0", "-a", "android.intent.action.MAIN", "-c",
            "android.intent.category.LAUNCHER", "-n", PACKAGE + "/.MainActivity", "--es", "task", instruction] + intent_extra(binding)


def fresh_files(adb, binding):
    for remote, local in (("files/qualification-scope.json", "qualification-scope.json"),
                          ("files/model/runtime-config.json", "runtime-config.json")):
        need(adb.app_bytes(remote) == binding["raw_files"][local], "fresh private file differs: " + remote)
    return {"scope_sha256": binding["scope_sha256"], "runtime_config_sha256": binding["runtime_config_sha256"]}


def session_binding(value, binding, allow_pending=False):
    need(isinstance(value, dict) and value.get("expected_scope_sha256") == binding["scope_sha256"]
         and "actual_scope_sha256" in value, "session scope expectation missing or changed")
    actual = value["actual_scope_sha256"]
    need(actual == binding["scope_sha256"] or (allow_pending and actual is None
         and value.get("status") in ("pending", "running")
         and (value.get("pending") is True or value.get("running") is True)),
         "session actual scope missing or changed")


def scope_evidence(value, binding, task_id, checked=False):
    need(isinstance(value, dict) and value.get("schema") == "hepta.qualification-task-scope.v1"
         and value.get("task_id") == task_id and value.get("expected_scope_sha256") == binding["scope_sha256"]
         and value.get("actual_scope_sha256") == binding["scope_sha256"]
         and value.get("restricted") is True and value.get("scope_loaded") is True
         and value.get("qualification_id") == binding["scope"]["qualification_id"]
         and value.get("build_identity_sha256") == binding["build_identity_sha256"]
         and value.get("runtime_config_sha256") == binding["runtime_config_sha256"]
         and value.get("scope_refused") is False and "refusal" in value and value["refusal"] is None,
         "task scope evidence missing, refused or changed")
    proof = value.get("last_check")
    need(isinstance(proof, dict), "scope dispatch proof absent")
    if not proof and not checked: return
    allowed = set(ROLES.values())
    need(proof.get("schema") == "hepta.qualification-scope-check.v1" and proof.get("restricted") is True
         and proof.get("allowed") is True and "reason" in proof and proof["reason"] is None
         and proof.get("fresh_root_package") in allowed and type(proof.get("fresh_root_window_id")) is int
         and proof["fresh_root_window_id"] >= 0 and type(proof.get("fresh_root_type")) is int
         and proof["fresh_root_type"] == 1 and type(proof.get("fresh_root_display_id")) is int
         and proof["fresh_root_display_id"] == 0 and proof.get("fresh_root_active") is True
         and proof.get("fresh_root_visible") is True, "fresh allowed active root proof differs")
    need(type(proof.get("node_required")) is bool, "node requirement unknown")
    if proof["node_required"]:
        need(proof.get("fresh_node_package") == proof["fresh_root_package"]
             and type(proof.get("fresh_node_window_id")) is int
             and proof["fresh_node_window_id"] == proof["fresh_root_window_id"], "fresh node scope differs")


def document_binding(value, binding, task_id, checked=False):
    need(isinstance(value, dict) and value.get("task_id") == task_id
         and value.get("expected_scope_sha256") == binding["scope_sha256"]
         and value.get("actual_scope_sha256") == binding["scope_sha256"], "owner/result scope identity differs")
    scope_evidence(value.get("qualification_scope"), binding, task_id, checked)


def task_evidence(directory, binding, task_id, instruction):
    """Supplemental admission gate only; native/goal/cleanup gates stay separate."""
    directory = Path(directory); task = directory / "task"
    need(isinstance(task_id, str) and ID.fullmatch(task_id), "task ID invalid")
    pins = {}
    def get(name):
        raw = read(task / name); pins[name] = sha(raw); return strict(raw)
    for local, expected in (("qualification-scope.json", "qualification-scope.json"),
                            ("build-identity.json", "build-identity.json"),
                            ("scope-runtime-config.json", "runtime-config.json")):
        raw = read(task / local)
        need(raw == binding["raw_files"][expected], "captured task bytes differ: " + local)
        pins[local] = sha(raw)
    owner, result, bound = get("owner.json"), get("result.json"), get("scope-binding.json")
    need(owner.get("instruction") == instruction and owner.get("instruction_utf8_sha256") == sha(instruction.encode()), "scope owner instruction differs")
    document_binding(owner, binding, task_id)
    document_binding(result, binding, task_id, True)
    scope_evidence(bound, binding, task_id)
    need(equal(owner["qualification_scope"], bound), "initial owner and captured scope receipt differ")
    observation_names = sorted(p.name for p in task.iterdir() if re.fullmatch(r"step-[0-9]{2,}-(before|after)\.json", p.name))
    action_names = sorted(p.name for p in task.iterdir() if re.fullmatch(r"step-[0-9]{2,}-action\.json", p.name))
    need(observation_names and action_names, "no complete scoped observation/action chain")
    observed_ids = set()
    for name in observation_names:
        observation = get(name); oid = observation.get("observation_id")
        need(isinstance(oid, str) and ID.fullmatch(oid), "observation ID malformed")
        scope_observation = get("scope-observation-" + oid + ".json")
        need(equal(scope_observation.get("observation"), observation), "scope observation was not the exact recorded frame")
        # requireScopeObservation validates the observed frame and does not
        # rewrite Gate.last_check, which deliberately still describes the last
        # dispatch (or {} before the first one).  Do not fabricate an "observe"
        # dispatch or confuse that prior proof with the new frame.
        proof = scope_observation.get("qualification_scope"); scope_evidence(proof, binding, task_id)
        need(observation.get("package") in set(ROLES.values()), "observed frame outside scope")
        validate_original_observation(encoded(observation), observation["package"])
        observed_ids.add(oid)
    for name in action_names:
        receipt = get(name); action = receipt.get("action"); proof = receipt.get("qualification_scope")
        stale = receipt.get("stale") is True and receipt.get("accepted") is False and receipt.get("dispatched") is False
        scope_evidence(proof, binding, task_id, not stale)
        need(isinstance(action, dict) and action.get("observation_id") in observed_ids, "action observation absent")
        need(proof.get("callback_lease_current") is True and proof.get("callback_cancelled") is False,
             "action callback lease retired or cancelled")
        if stale:
            continue  # No dispatch occurred; the existing native/action gate still binds its raw decision.
        check = proof["last_check"]
        need(check.get("action") == action.get("action") and check.get("target_package") == action.get("package"),
             "scope dispatch belongs to another action")
        node = action.get("action") in ("click", "type", "scroll")
        need(check["node_required"] is node, "node action lacks actual node scope proof")
        if action.get("action") == "open":
            need(action.get("package") in set(ROLES.values()), "open target outside scope")
        else:
            need(action.get("package") == check["fresh_root_package"], "action target differs from fresh root")
    need(result.get("final_observation_id") in observed_ids, "terminal observation not scoped")
    return {"schema": "hepta.host-task-scope-review.v1", "verified": True,
            "scope_sha256": binding["scope_sha256"], "binding_sha256": binding["binding_sha256"],
            "task_id": task_id, "file_sha256": pins, "semantic_pass_granted": False}


def sampled_native(directory, collection):
    runs = collection.get("associated_runs")
    need(isinstance(runs, list) and runs, "no actual native requests for sampler review")
    evidence = []
    for row in runs:
        run_id = row.get("run_id")
        need(isinstance(run_id, str) and ID.fullmatch(run_id), "invalid native request ID")
        raw = read(Path(directory) / "runs" / run_id / "native-result.json")
        receipt = strict(raw)
        need(sampler_valid(receipt.get("sampler_requested")), "actual native request has wrong F32 sampler")
        evidence.append({"run_id": run_id, "native_result_sha256": sha(raw), "sampler_requested": receipt["sampler_requested"]})
    return evidence


def downgrade(verdict, verified):
    need(verdict in ("pass", "fail", "unverified", "unknown", "not_run"), "verdict unknown")
    return "unverified" if verdict == "pass" and verified is not True else verdict
