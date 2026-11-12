#!/usr/bin/env python3
"""Prepared v54 acceptance: ordinary visible Start -> local notes.create -> bounded children.

No command runs merely by importing this module.  `prepare` only creates a new
harmless request on this host.  `preflight` takes the existing original operation
lock and performs read-only ADB observations.  `monitor` repeats that preflight,
then waits for the owner to press the existing Start button.  Its sole optional
input is one explicitly requested Start tap bound to the current screencap SHA.

No installation, configuration/scope/grant edits, nonce trigger, direct broker
client, target-app input, retry, guessed Stop, PID kill, or remote model is used.
The unchanged reviewed v36 driver supplies bounded readers/system observations;
the original identity helper supplies its fixed, read-only-opened exclusive lock
and guard_adb.  Pure chain replay is not phone qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
import time
from types import ModuleType
import zipfile

PACKAGE = "org.trillionnium.hepta.local"
NOTES = "com.motorola.stylus"
VERSION_CODE = 54
VERSION_NAME = "0.54.0-local-unified-observation"
SOURCE_HEAD = "824d73ed2e9dc57bc9ecfc6eff340b45cf1d81bd"
CANDIDATE_COMMIT = "79266ea9ac54e184b69088489f89b5e40fbc95da"
CANDIDATE_TREE = "ad7c0d73899cdaeced03df91bbed524d925fd547"
MANIFEST_SHA = "312140bc0cfd2bc617b32bc7821eaf49a24a4f524c5326c25e955081d4b8bd4f"
MAC_RECEIPT_SHA = "aabf68541b151a01463274add55d4c91d986f4d22ae153979e279217546eb9da"
DEX_SHA = "77b8e3dd6d727f713617c77ca258bc7dfac91fa86a368f4447ca8070da31ac90"
CERT_SHA = "202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5"
ASSEMBLER_SHA = "bb7cff1de735f0161fa91104e43a7a44287fa5d1d9cbf77801b75de617951268"
BASELINE_RECEIPT_SHA = "e96ba5683322ef8d113cb14fde7580d42441e360da2c0547c813d302dadc3d01"
MODEL_PROFILE = "lfm3-1.7b-qad-q4_0"
MODEL_SHA = "43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452"
OBSERVED_NOTES_APK = "0e1a52a937c04ec8df380bff3750ce4b345fa0d8d33683e5ae8aa08e70e94017"
REFERENCE = "provenance/background-v36-bff66-20261110/phone-tests/r2/background_calculator_acceptance.py"
IDENTITY = "provenance/background-v36-bff66-20261110/phone-tests/helpers/v35_identity.py"
PINS = {
    "v35_identity": (IDENTITY, "a4a751cf03956783e551f54b16dd37769f00d5b7cd2a0225b667becbc6e6d003"),
    "background_reference": (REFERENCE, "533c27c1d1ae400862b4322ff269aeb9557a1f113c539c253f8c7f9f091ff7af"),
    "warm_receipts": ("tools/warm_receipts.py", "d5ab468b1b3155195d24b771376581dd441fd59a20b71feda98af4074fcaa3d5"),
    "model_profiles": ("tools/model_profiles.py", "ee26ed1f2f2b2ffd5f14fbd526c6d3cbf05d7ed8d65c422df5e60a72fa0cfa3a"),
    "phone_acceptance": ("tools/phone_acceptance.py", "673a017689bff6d8a1972f6d3e64ff20803c0f00926265e2d0abc2cbe80371b9"),
    "build_identity": ("tools/build_identity.py", "7d5ad2641e9a3635fd04aa47ce3ea50a1a4f16b883a98b2ab407878eef36f6e6"),
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SELECTION = {"mode": "background", "allowed_packages": [NOTES], "bootstrap_package": NOTES,
    "bootstrap_source": "owner_selected_initial_app", "bootstrap_model_issued": False,
    "main_display_fallback": False, "home_allowed": False}


def need(value, message):
    if not value:
        raise RuntimeError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sha_text(value):
    return digest(value.encode("utf-8", errors="strict"))


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def bad(value):
        raise ValueError("nonfinite JSON: " + value)
    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs, parse_constant=bad)


def equal(left, right):
    """JSON equality with no Python bool/int aliasing, recursively."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(equal(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(equal(a, b) for a, b in zip(left, right))
    return left == right


def fields(value, expected, label):
    need(isinstance(value, dict), label + ": object required")
    for key, wanted in expected.items():
        need(key in value and equal(value[key], wanted), label + ": " + key + " differs")


def is_hex(value, pattern=HEX64):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def checked_file(path, maximum=16 << 20, allow_empty=False):
    path = Path(path)
    need(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)), "absolute non-symlink input required")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and (0 <= before.st_size if allow_empty else 0 < before.st_size)
             and before.st_size <= maximum, "invalid bounded regular input: " + str(path))
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(len(raw) == before.st_size and key(before) == key(after) == key(path.stat()), "input changed while read")
    return raw


def read_json(path):
    value = strict(checked_file(path))
    need(isinstance(value, dict), "JSON object required: " + str(path))
    return value


def write_new(path, value, binary=False):
    path = Path(path)
    need(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)), "unsafe output path")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = value if binary else (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def utf16_length(value):
    need(isinstance(value, str), "string required")
    return len(value.encode("utf-16-be", errors="strict")) // 2


def projected(value, limit=36):
    raw = value.encode("utf-16-be", errors="strict")
    if len(raw) <= limit * 2:
        return value
    end = limit * 2
    if 0xD800 <= int.from_bytes(raw[end - 2:end], "big") <= 0xDBFF:
        end -= 2
    return raw[:end].decode("utf-16-be") + "…"


def java_trim(value):
    return value.strip("".join(chr(n) for n in range(33)))


def label(node):
    text, description = node.get("text", ""), node.get("description", "")
    if java_trim(text):
        return text
    if java_trim(description):
        return description
    if node.get("child_text_truncated", False) or node.get("child_text_status", "not_applicable") != "derived":
        return ""
    return node.get("child_text", "")


def bounds(node):
    value = node.get("bounds")
    return (isinstance(value, list) and len(value) == 4 and all(type(x) is int for x in value)
            and value[0] >= 0 and value[1] >= 0 and value[2] > value[0] and value[3] > value[1])


def inside(node, outer):
    a, b = node["bounds"], outer["bounds"]
    return b[0] <= a[0] and b[1] <= a[1] and a[2] <= b[2] and a[3] <= b[3]


def domain_of(observation):
    window = observation.get("window", {})
    background = observation.get("background_session") or {}
    return {"display_id": window.get("display_id"), "generation": background.get("generation")}


def validate_domain(observation, domain, notes=True):
    need(is_hex(observation.get("observation_id"), HEX32), "observation identity invalid")
    need(type(domain.get("display_id")) is int and domain["display_id"] >= 0, "display identity invalid")
    need((domain["generation"] is None if domain["display_id"] == 0 else is_hex(domain.get("generation"), UUID)), "generation identity invalid")
    need(equal(domain_of(observation), domain), "observation display/generation changed")
    window = observation.get("window")
    fields(window, {"metadata_status": "observed", "type": 1, "display_id": domain["display_id"]}, "observed application window")
    need(type(observation.get("window_id")) is int and observation["window_id"] >= 0
         and equal(window.get("window_id"), observation["window_id"]), "window identity differs")
    need(type(observation.get("rotation")) is int and 0 <= observation["rotation"] <= 3, "rotation unavailable")
    need(is_hex(observation.get("observation_state_sha256")) and is_hex(observation.get("app_tree_sha256")), "tree/state hashes unavailable")
    if notes:
        need(observation.get("package") == NOTES, "observation left Notes")
    if domain["display_id"] > 0:
        fields(observation.get("background_session"), dict(SELECTION, generation=domain["generation"], display_id=domain["display_id"]), "background observation")
    else:
        need(observation.get("background_session") is None, "main-display fixture carries background lease")
    return observation


def validate_nodes(observation):
    need(observation.get("package") == NOTES and observation.get("nodes_truncated") is False, "complete Notes nodes required")
    nodes = observation.get("nodes")
    need(isinstance(nodes, list) and len(nodes) <= 200, "bounded node list required")
    ids = set()
    for node in nodes:
        need(isinstance(node, dict) and isinstance(node.get("id"), str)
             and re.fullmatch(r"n[0-9]{1,5}", node["id"]) and node["id"] not in ids, "duplicate/invalid node ID")
        ids.add(node["id"])
        for key in ("text", "description", "view_id", "package", "child_text"):
            utf16_length(node.get(key, ""))
        for key in ("editable", "clickable", "scrollable", "enabled", "password", "child_text_truncated", "child_text_sources_complete"):
            if key in node:
                need(type(node[key]) is bool, "node boolean type invalid")
    return nodes


def body_evidence(observation, body, installed):
    if observation.get("package") != NOTES:
        return {"matched": False, "missing": "not_notes"}
    validate_domain(observation, domain_of(observation))
    nodes = validate_nodes(observation)
    candidates = [n for n in nodes if n.get("package") == NOTES and n.get("enabled", True) and not n.get("password", False)]
    contexts = [n for n in candidates if not n.get("editable", False) and n.get("text", "") == "NoteEditor" and n.get("scrollable", False) and bounds(n)]
    editors = [n for n in candidates if n.get("editable", False)]
    if len(contexts) != 1 or len(editors) != 1 or not bounds(editors[0]) or not inside(editors[0], contexts[0]):
        return {"matched": False, "missing": "unique_editor_context_missing"}
    editor = editors[0]
    raw = editor.get("text", "")
    exact, forty = raw == body, raw == body + "\n" * 40
    need(utf16_length(body) > 0 and "\0" not in body, "owner body invalid")
    if not is_hex(editor.get("input_text_sha256")) or sha_text(raw) != editor["input_text_sha256"]:
        return {"matched": False, "missing": "complete_input_sha_mismatch"}
    if not exact and not (forty and equal(installed.get("apk_hashes"), {"base": OBSERVED_NOTES_APK})):
        return {"matched": False, "missing": "unsupported_body_or_notes_apk"}
    return {"matched": True, "raw_exact": exact, "persistent_bytes_verified": False,
        "node_id": editor["id"], "action_label": projected(label(editor)), "raw_text_sha256": sha_text(raw),
        "body_sha256": sha_text(body), "trailing_lf_count": len(raw) - len(raw.rstrip("\n")),
        "match_rule": "raw_exact" if exact else "body_plus_observed_40_lf", "missing": None}


def summary_source(node, body):
    """Port of NotesCompletionEvidence.summarySource; hashes bind real descendant provenance."""
    child = node.get("child_text", "")
    if not (node.get("view_id") == NOTES + ":id/note_item_content" and node.get("text", "") == ""
            and node.get("child_text_status") == "derived" and node.get("child_text_truncated") is False
            and node.get("child_text_source") == "visible_noninteractive_descendants.v2"
            and node.get("child_text_sources_complete") is True and label(node) == child
            and 0 < utf16_length(child) <= 96 and type(node.get("child_text_visited")) is int
            and 1 <= node["child_text_visited"] <= 16):
        return None
    sources, root = node.get("child_text_sources"), node.get("child_text_root_signature")
    if not (isinstance(sources, list) and 1 <= len(sources) <= 3 and is_hex(root) and is_hex(node.get("node_app_tree_sha256"))):
        return None
    paths, summaries = set(), []
    field = lambda value: str(utf16_length(value)) + ":" + value
    parts = ["visible_noninteractive_descendants.v2", "derived", child, "false", root, "true"]
    for source in sources:
        if not isinstance(source, dict):
            return None
        path, prop = source.get("descendant_path"), source.get("property")
        if not (isinstance(path, str) and re.fullmatch(r"(?:0|[1-9][0-9]?)(?:/(?:0|[1-9][0-9]?)){0,3}", path)
                and all(int(segment) < 16 for segment in path.split("/")) and path not in paths
                and prop in ("text", "description") and is_hex(source.get("text_sha256"))
                and is_hex(source.get("node_signature")) and isinstance(source.get("view_id"), str)):
            return None
        paths.add(path)
        parts.extend([path, prop, source["text_sha256"], source["node_signature"], source["view_id"]])
        if source["view_id"] == NOTES + ":id/note_summary":
            summaries.append(source)
    fingerprint = sha_text("".join(field(x) for x in parts))
    if sha_text(field(root) + field(fingerprint)) != node["node_app_tree_sha256"]:
        return None
    if len(summaries) != 1 or summaries[0]["property"] != "text" or summaries[0]["text_sha256"] != sha_text(body):
        return None
    return summaries[0]


def list_evidence(observation, body):
    if observation.get("package") != NOTES:
        return {"matched": False, "missing": "not_notes"}
    validate_domain(observation, domain_of(observation))
    nodes = validate_nodes(observation)
    if not 0 < utf16_length(body) < 95 or "\0" in body or body.endswith("…"):
        return {"matched": False, "missing": "body_not_complete_list_provable"}
    if any(n.get("editable", False) or n.get("text", "") == "NoteEditor" for n in nodes):
        return {"matched": False, "missing": "editor_present"}
    if any(n.get("package") == NOTES and n.get("view_id") == NOTES + ":id/no_note_text" and n.get("text", "") for n in nodes):
        return {"matched": False, "missing": "empty_list_notice"}
    usable = [n for n in nodes if n.get("package") == NOTES and n.get("enabled", True) and not n.get("password", False) and bounds(n)]
    titles = [n for n in usable if n.get("view_id") == NOTES + ":id/title_text" and n.get("text", "") == "所有笔记"]
    pagers = [n for n in usable if n.get("view_id") == NOTES + ":id/view_pager2" and n.get("scrollable", False)]
    if len(titles) != 1 or len(pagers) != 1:
        return {"matched": False, "missing": "unique_list_context_missing"}
    matches = []
    for node in usable:
        if node is titles[0] or node is pagers[0] or not node.get("clickable", False) or not inside(node, pagers[0]) or node.get("view_id") == NOTES + ":id/clickable_layout":
            continue
        own = body == node.get("text", "") == label(node)
        nonderived = not node.get("text", "") and body == label(node) and node.get("child_text_status") != "derived"
        source = summary_source(node, body)
        if own or nonderived or source is not None:
            matches.append((node, source, "bound_note_summary_accessibility_text" if source is not None else "exact_own_text" if own else "exact_nonderived_label"))
    if len(matches) != 1:
        return {"matched": False, "missing": "complete_body_list_item_is_not_unique" if len(matches) > 1 else "complete_body_list_item_missing"}
    node, source, rule = matches[0]
    return {"matched": True, "missing": None, "node_id": node["id"], "node_label": projected(label(node)), "match_rule": rule,
        "source_path": None if source is None else source["descendant_path"],
        "source_view_id": None if source is None else source["view_id"],
        "source_text_sha256": None if source is None else source["text_sha256"],
        "node_app_tree_sha256": node.get("node_app_tree_sha256"), "persistent_bytes_verified": False}


def mini(observation):
    domain = domain_of(observation)
    return {"observation_id": observation["observation_id"], "package": observation["package"],
        "window_id": observation["window_id"], "display_id": domain["display_id"], "background_generation": domain["generation"],
        "tree_sha256": observation["observation_state_sha256"], "rotation": observation["rotation"]}


def observed_files(directory):
    result = {}
    for path in sorted(Path(directory).glob("step-*.json")):
        value = read_json(path)
        if "nodes" not in value:
            continue
        oid = value.get("observation_id")
        need(is_hex(oid, HEX32), "invalid archived observation ID")
        need(oid not in result or equal(result[oid], value), "same observation ID has conflicting archived contents")
        result[oid] = value
    return result


def validate_notes_chain(directory, instruction, installed, expected_domain):
    """Pure replay of production JSON.  Never grants full phone qualification.

    Tests may pass display 0 host fixtures explicitly.  The phone entry point
    independently requires a fresh >0 background display and genuine native,
    process, lock, screenshot and installed-APK evidence.
    Invalid/missing evidence raises RuntimeError, ValueError/UnicodeError, or
    OSError.  The driver records all such failures as qualified=false.
    """
    directory = Path(directory)
    read = lambda name: read_json(directory / name)
    owner, result = read("owner.json"), read("result.json")
    task, owner_sha = owner.get("task_id"), sha_text(instruction)
    need(is_hex(task, HEX32) and directory.name in (task, "task"), "task directory identity differs")
    fields(owner, {"schema": "hepta.local-owner.v1", "instruction": instruction, "instruction_utf8_sha256": owner_sha,
        "external_model": False, "automatic_resume": False, "expected_scope_sha256": None, "actual_scope_sha256": None}, "owner")
    fields(installed, {"package": NOTES}, "installed Notes")
    need(type(installed.get("uid")) is int and 10000 <= installed["uid"] < 90000, "ordinary installed Notes UID required")
    apks = installed.get("apk_hashes")
    need(isinstance(apks, dict) and 1 <= len(apks) <= 128 and is_hex(apks.get("base"))
         and all(isinstance(k, str) and utf16_length(k) <= 300 and (k == "base" or k.startswith("split:") and len(k) > 6)
                 and is_hex(v) for k, v in apks.items()), "installed APK hashes invalid")
    fields(read("completion-installed-identity.json"), installed, "completion installed identity")
    contract = owner.get("completion_contract", {})
    fields(contract, {"schema": "hepta.task-completion.v1", "kind": "notes_save_list_reopen", "owner_sha256": owner_sha,
        "source": "immutable_owner_contract", "note_persistence_verification_policy": "save_list_reopen",
        "body_rewritten": False, "model_may_change_goal": False, "grants_tool_authority": False}, "immutable Notes contract")
    start, end = contract.get("body_source_start_utf16"), contract.get("body_source_end_utf16")
    need(type(start) is int and type(end) is int and 0 <= start < end <= utf16_length(instruction), "literal body span unavailable")
    body = instruction.encode("utf-16-be")[2 * start:2 * end].decode("utf-16-be", errors="strict")
    need(0 < utf16_length(body) < 95 and "\0" not in body, "complete short Notes body required")
    body_sha, recognition = sha_text(body), contract.get("recognition")
    need(isinstance(recognition, str) and recognition.startswith("hepta.notes-owner-intent.v1/"), "owner literal recognition missing")
    contract_sha = sha_text("hepta.task-completion.v1\n" + owner_sha + "\nnotes_save_list_reopen\n" + body_sha + "\n" + recognition)
    fields(contract, {"expected_body_sha256": body_sha, "contract_sha256": contract_sha}, "contract hashes")
    auth_sha = owner.get("task_authorization_sha256")
    need(is_hex(auth_sha), "owner authorization hash invalid")
    auth = owner.get("task_authorization", {})
    fields(auth, {"schema": "hepta.owner-task-authorization.v1", "instruction_sha256": owner_sha,
        "authorization_sha256": auth_sha}, "owner authorization")
    need(isinstance(auth.get("allowed_tools"), list) and {"notes.create", "back", "click"} <= set(auth["allowed_tools"]), "bounded children not authorized by original owner")
    observations = observed_files(directory)
    actions = [(p, read(p.name)) for p in sorted(directory.glob("step-*-action.json")) if re.fullmatch(r"step-[0-9]{2}-action.json", p.name)]
    need(1 <= len(actions) <= 20 and [int(p.name[5:7]) for p, _ in actions] == list(range(1, len(actions) + 1)), "model step sequence invalid")
    parents = [(p, a) for p, a in actions if a.get("action", {}).get("action") == "notes.create"]
    need(len(parents) == 1 and parents[0] == actions[-1], "exactly one final model notes.create parent required")
    parent_path, parent = parents[0]
    step, prefix = int(parent_path.name[5:7]), parent_path.name[:-len("-action.json")]
    decision, run = parent.get("action", {}), parent.get("model_run_id")
    need(is_hex(run, HEX32), "parent native run identity invalid")
    fields(parent, {"model_issued": True, "accepted": True, "dispatched": True, "stale": False,
        "task_authorization_sha256": auth_sha}, "real model parent action")
    fields(decision, {"action": "notes.create", "package": NOTES, "text": body}, "model parent Notes payload")
    before, created = read(prefix + "-before.json"), read(prefix + "-after.json")
    validate_domain(before, expected_domain, notes=False)
    validate_domain(created, expected_domain)
    need(decision.get("observation_id") == before["observation_id"], "parent action observation differs")
    models = [read(p.name) for p in directory.glob(prefix + "-model-*.json")]
    models = [m for m in models if m.get("run_id") == run]
    need(len(models) == 1, "parent model record missing/duplicated")
    model = models[0]
    fields(model, {"observation_id": before["observation_id"], "original_instruction_sha256": owner_sha}, "model owner observation")
    raw = strict(model.get("raw_text", "").encode("utf-8"))
    fields(raw, decision, "actual parent model raw JSON")
    for _, action in actions[:-1]:
        d = action.get("action", {})
        need(d.get("action") in ("find_app", "wait", "open") and (d.get("action") != "open" or d.get("package") == NOTES), "unrelated or additional write model action")
    prior_body, prior_list = body_evidence(before, body, installed), list_evidence(before, body)
    need(not prior_body["matched"] and not prior_list["matched"] and prior_list.get("missing") != "complete_body_list_item_is_not_unique", "preexisting visible test body cannot prove new creation")
    initial_body = body_evidence(created, body, installed)
    need(initial_body["matched"], "created full editor body missing")

    fixed = parent.get("fixed_intent", {})
    attempt_id = sha_text(task + "|1|notes.create|" + body_sha)
    stable_attempt = {"task_id": task, "model_run_id": run, "observation_id": before["observation_id"],
        "source_package": before["package"], "source_window_id": before["window_id"],
        "display_id": expected_domain["display_id"], "background_generation": expected_domain["generation"],
        "action": "notes.create", "payload_sha256": body_sha, "attempt_id": attempt_id, "attempt_ordinal": 1,
        "attempt_consumed": True, "automatic_retry_allowed": False}
    fields(fixed, dict(stable_attempt, schema="hepta.fixed-intent-result.v1", dispatch_attempted=True, api_accepted=True,
        result="launch_accepted", requested_outcome="draft_opened", goal_independently_verified=False,
        saved_or_search_results_verified=False), "fixed intent result")
    target = fixed.get("target", {})
    fields(target, {"source": "installed_package_manager", "action": "notes.create", "package": NOTES,
        "component": NOTES + "/com.motorola.stylus.note.text.TextNoteActivity", "target_uid": installed["uid"],
        "exported": True, "activity_enabled": True, "application_enabled": True,
        "declared_intent_filter_matched": True, "ordinary_caller_permission_checked": True}, "installed fixed target")
    need(isinstance(target.get("app_label"), str) and projected(target["app_label"], 48) == decision.get("app_label"), "parent app label differs")
    parent_app_uid = None
    if expected_domain["display_id"] > 0:
        parent_app_uid = (parent.get("background_session") or {}).get("app_uid")
        need(type(parent_app_uid) is int and 10000 <= parent_app_uid < 90000, "ordinary parent app UID missing")
        response = fixed.get("broker_response", {})
        fields(response, {"ok": True, "state": "ACTIVE", "dispatched": True, "operation": "notes.create",
            "generation": expected_domain["generation"], "display_id": expected_domain["display_id"]}, "fixed intent broker acknowledgement")
        need(is_hex(response.get("request_id"), UUID), "broker request identity invalid")
        fields(response.get("fixed_intent"), {"schema": "hepta.background-fixed-intent.v1", "request_id": response["request_id"],
            "generation": expected_domain["generation"], "display_id": expected_domain["display_id"],
            "action": "notes.create", "attempt_id": attempt_id, "payload_sha256": body_sha, "target": target,
            "ordinary_caller_uid": parent_app_uid, "attempt_consumed": True, "resolved_type": "text/plain"}, "broker ordinary-caller parent binding")
    journals = list(directory.glob("fixed-intent-*-attempt.json"))
    need(len(journals) == 1, "fixed intent attempts repeated")
    fields(read(journals[0].name), dict(stable_attempt, target=target, schema="hepta.fixed-intent-attempt.v1", stage="consumed_before_call"), "once-only launch journal")
    ledger = result.get("fixed_intent_attempts")
    need(isinstance(ledger, list) and len(ledger) == 1, "final fixed intent ledger repeated/missing")
    fields(ledger[0], dict(stable_attempt, target=target), "final fixed intent ledger")

    workflow_id = sha_text(task + "|" + run + "|" + attempt_id + "|" + contract_sha)
    grant_identity = {"workflow_id": workflow_id, "task_id": task, "parent_step": step, "parent_model_run_id": run,
        "parent_observation_id": before["observation_id"], "created_observation_id": created["observation_id"],
        "parent_fixed_intent_attempt_id": attempt_id, "owner_sha256": owner_sha, "contract_sha256": contract_sha,
        "task_authorization_sha256": auth_sha, "body_sha256": body_sha, "target_package": NOTES,
        "target_uid": installed["uid"], "target_apk_sha256": apks,
        "display_id": expected_domain["display_id"], "background_generation": expected_domain["generation"],
        "grants_tool_authority": False, "grant_consumed": True}
    need(len(list(directory.glob("step-*-notes-workflow-grant-consumed.json"))) == 1
         and len(list(directory.glob("step-*-notes-workflow-result.json"))) == 1, "multiple workflow grants/results")
    fields(read(prefix + "-notes-workflow-grant-consumed.json"), dict(grant_identity, schema="hepta.notes-create-workflow.v1", grant_retired=False), "consumed parent grant")
    workflow = read(prefix + "-notes-workflow-result.json")
    fields(workflow, dict(grant_identity, schema="hepta.notes-create-workflow.v1", grant_retired=True,
        actor_kind="tool_workflow", model_issued=False, fixed_intent_outcome_unchanged="draft_opened",
        workflow_verified=True, stop_reason=None, model_done_synthesized=False, persistent_storage_bytes_verified=False,
        accepted_as_completion_proof=True, native_model_done_synthesized=False), "retired verified workflow")
    children = workflow.get("children")
    need(isinstance(children, list) and 1 <= len(children) <= 3, "bounded children missing")
    n = len(children)
    expected_child_files = {prefix + "-tool-child-%02d-%s.json" % (i, suffix) for i in range(1, n + 1) for suffix in ("before", "action", "after", "proof")}
    need({p.name for p in directory.glob("step-*-tool-child-*.json")} == expected_child_files, "child files missing/extra/repeated")
    need({p.name for p in directory.glob("step-*-notes-workflow-child-*-planned.json")} ==
         {prefix + "-notes-workflow-child-%d-planned.json" % i for i in range(1, n + 1)}, "planned children missing/extra")
    observed_paths = sorted(directory.glob(prefix + "-notes-workflow-observation-*.json"))
    need({p.name for p in observed_paths} == {prefix + "-notes-workflow-observation-%d.json" % i for i in range(1, n + 3)}, "workflow observations missing/extra")
    fresh = [read(prefix + "-notes-workflow-observation-%d.json" % i) for i in range(1, n + 3)]
    for observation in fresh:
        validate_domain(observation, expected_domain)
    need(len({o["observation_id"] for o in [created, *fresh]}) == n + 3, "workflow observation reused")
    fields(workflow, {"initial": mini(created), "current": mini(fresh[-2]), "stable_readback": mini(fresh[-1]),
        "final_observation_id": fresh[-1]["observation_id"]}, "workflow observation chain")
    need(equal({k: v for k, v in mini(fresh[-2]).items() if k != "observation_id"},
               {k: v for k, v in mini(fresh[-1]).items() if k != "observation_id"}), "reopened readback not stable")
    readback_body = body_evidence(fresh[-1], body, installed)
    need(body_evidence(fresh[-2], body, installed)["matched"] and readback_body["matched"], "reopened/stable body missing")
    checks, list_match = [], None

    def authorization(action_row, action_name, child=False):
        value = action_row.get("task_authorization", {})
        fields(value, {"task_id": task, "instruction_sha256": owner_sha, "authorization_sha256": auth_sha,
            "callback_lease_current": True, "callback_cancelled": False, "retired": False, "refused": False}, "live owner callback")
        need(equal(value.get("allowed_tools"), auth["allowed_tools"]) and action_name in value["allowed_tools"], "owner tool permission changed")
        expected = {"task_id": task, "authorization_sha256": auth_sha, "model_run_id": run if child else action_row.get("model_run_id"),
            "action": action_name, "target_package": NOTES, "allowed": True}
        if child:
            expected.update(actor_kind="tool_child", model_issued=False, parent_model_run_id=run)
        fields(value.get("last_check"), expected, "owner last check")
        fields(action_row.get("qualification_scope"), {"task_id": task, "expected_scope_sha256": None,
            "actual_scope_sha256": None, "restricted": False, "scope_loaded": False, "scope_refused": False,
            "callback_lease_current": True, "callback_cancelled": False}, "scope callback")
        if expected_domain["display_id"] > 0:
            fields(action_row.get("background_session"), {"schema": "hepta.background-session.v1", "task_id": task,
                "app_uid": parent_app_uid, "owner_sha256": owner_sha, "selection": SELECTION, "state": "ACTIVE", "retired": False,
                "generation": expected_domain["generation"], "display_id": expected_domain["display_id"]}, "action background domain")
        else:
            need(action_row.get("background_session") is None, "fixture action background differs")

    authorization(parent, "notes.create")
    for i, final_record in enumerate(children, 1):
        child_prefix = prefix + "-tool-child-%02d" % i
        cb, ca = read(child_prefix + "-before.json"), read(child_prefix + "-after.json")
        need(equal(cb, fresh[i - 1]) and equal(ca, fresh[i]), "child before/after chain differs")
        child_action, proof = read(child_prefix + "-action.json"), read(child_prefix + "-proof.json")
        action_name = "click" if i == n else "back"
        current_list = list_evidence(cb, body)
        if action_name == "back":
            need(body_evidence(cb, body, installed)["matched"] and (body_evidence(ca, body, installed)["matched"] or list_evidence(ca, body)["matched"]), "Back left verified editor/list")
            node_id = node_label = None
        else:
            need(current_list["matched"] and body_evidence(ca, body, installed)["matched"], "same list item reopen chain missing")
            node_id, node_label, list_match = current_list["node_id"], current_list["node_label"], current_list
        child_id = sha_text(workflow_id + "|" + str(i) + "|" + action_name + "|" + cb["observation_id"] + "|" + (node_id or ""))
        child_identity = dict(grant_identity, schema="hepta.tool-child.v1", child_id=child_id, child_ordinal=i,
            actor_kind="tool_child", model_issued=False, action=action_name, observation_id=cb["observation_id"],
            node_id=node_id, node_label=node_label, automatic_retry_allowed=False)
        fields(read(prefix + "-notes-workflow-child-%d-planned.json" % i), dict(child_identity, grant_retired=False, service_entered=False), "planned once-only child")
        for name, record, retired in (("historical proof", proof, False), ("final workflow record", final_record, True)):
            fields(record, {"before": mini(cb), "after": mini(ca), "accepted": True, "dispatched": True,
                "stale": False, "live_lease_verified": True}, name)
            fields(record.get("child"), dict(child_identity, grant_retired=retired, service_entered=True), name + " child")
            fields(record.get("service_child_receipt"), dict(child_identity, grant_retired=False, service_entered=True), name + " live service proof")
        fields(child_action, {"schema": "hepta.tool-child.v1", "actor_kind": "tool_child", "model_issued": False,
            "parent_model_run_id": run, "parent_fixed_intent_attempt_id": attempt_id, "workflow_id": workflow_id,
            "child_id": child_id, "child_ordinal": i, "action_schema": "hepta.internal-tool-child.v1",
            "accepted": True, "dispatched": True, "stale": False}, "child action envelope")
        d = child_action.get("action", {})
        fields(d, {"action": action_name, "observation_id": cb["observation_id"], "package": NOTES}, "child actual action")
        need(d.get("node_id") == node_id and d.get("node_label") == node_label
             and all(key not in d for key in ("text", "query", "x", "y", "status", "summary")), "child has ungranted action payload")
        fields(child_action.get("tool_child"), dict(child_identity, grant_retired=False, service_entered=True), "child callback receipt")
        authorization(child_action, action_name, child=True)
        checks.append({"child_id": child_id, "ordinal": i, "action": action_name, "before": cb["observation_id"], "after": ca["observation_id"], "model_issued": False})

    fields(result, {"task_id": task, "status": "controller_verified_done", "steps": len(actions),
        "model_reported_success": False, "model_done_status": None, "model_done_summary": None,
        "completion_verified": True, "completion_actor": "controller/tool_workflow", "controller_completion_requested": True,
        "model_done_synthesized": False, "cleanup_known": True, "observation_read_worker_pending_at_terminal": False,
        "final_observation_id": fresh[-1]["observation_id"], "external_model": False, "automatic_replay": False,
        "goal_independently_verified": True, "task_authorization_sha256": auth_sha,
        "expected_scope_sha256": None, "actual_scope_sha256": None, "submit_attempts": []}, "terminal envelope")
    model_session = result.get("model_session", {})
    fields(model_session, {"task_id": task, "process_started": True, "process_exit_observed": True, "exit_code": 0, "receipt_valid": True}, "terminal native-session envelope")
    need(is_hex(model_session.get("worker_generation"), HEX32) and is_hex(model_session.get("app_receipt_sha256")), "native session receipt binding unavailable")
    fields(read("controller-completion-candidate.json"), {"schema": "hepta.controller-workflow-completion.v1", "task_id": task,
        "completion_actor": "controller/tool_workflow", "model_done_synthesized": False, "workflow_id": workflow_id,
        "parent_model_run_id": run, "parent_fixed_intent_attempt_id": attempt_id,
        "observation_id": fresh[-1]["observation_id"], "terminal_pending_native_identity_and_cleanup": True}, "completion candidate binding")
    completion = result.get("completion_evidence", {})
    fields(completion, {"schema": "hepta.task-completion.v1", "kind": "notes_save_list_reopen", "task_id": task,
        "owner_sha256": owner_sha, "contract_sha256": contract_sha, "contract": contract, "completion_verified": True,
        "source": "controller_observation_checks_not_model_claims", "missing": [], "notes_launch_observed": True,
        "editor_body_observed": True, "list_observed": True, "prior_visible_body_collision": False,
        "unobserved_prior_notes_known": False, "same_list_item_reopened": True, "reopen_actor_kind": "tool_child",
        "notes_create_workflow_verified": True, "notes_create_workflow_stop_reason": None,
        "current_surface": "verified_note_editor", "current_editor_body_matched": True,
        "persistent_storage_bytes_verified": False, "new_database_item_identity_verified": False,
        "grants_tool_authority": False, "current_body_evidence": readback_body,
        "display_id": expected_domain["display_id"], "background_generation": expected_domain["generation"],
        "observation_chain_verified": True, "terminal_binding_and_cleanup_verified": True,
        "completion_actor": "controller/tool_workflow", "model_done_synthesized": False,
        "controller_completion_requested": True, "controller_native_parent_session_bound": True}, "completion evidence")
    # The serialized final workflow repeats the in-process result before its two
    # controller archival-only annotations; stable evidence must still match.
    embedded = completion.get("notes_create_workflow", {})
    fields(workflow, embedded, "embedded workflow replay")
    return {"verified": True, "phone_qualified": False, "task_id": task, "parent_step": step,
        "parent_run_id": run, "workflow_id": workflow_id, "body_sha256": body_sha,
        "owner_sha256": owner_sha, "contract_sha256": contract_sha, "model_step_count": len(actions),
        "tool_children": checks, "initial_body": initial_body, "reopened_body": readback_body,
        "list_match": list_match, "final_observation_id": fresh[-1]["observation_id"],
        "observation_ids": sorted(observations), "persistent_storage_bytes_verified": False,
        "new_database_item_identity_verified": False, "object_capability_identity_independently_verified": False,
        "scope": "Replay of archived production observations and receipts; native/lock/system identity validated separately."}


def load_helpers(source):
    loaded = {}
    for name, (relative, pin) in PINS.items():
        need(name not in sys.modules, "preloaded helper refused: " + name)
        path = source / relative
        raw = checked_file(path)
        need(digest(raw) == pin, "helper differs from reviewed bytes: " + name)
        module = ModuleType(name)
        module.__file__, module.__package__ = str(path), ""
        sys.modules[name] = module
        exec(compile(raw, str(path), "exec"), module.__dict__)
        loaded[name] = module
    return loaded


def verify_source(source):
    raw = checked_file(source / "SOURCE-MANIFEST.json")
    need(digest(raw) == MANIFEST_SHA, "frozen v54 source manifest differs")
    manifest = strict(raw)
    fields(manifest, {"schema": "hepta.local-source.v3", "version_code": VERSION_CODE,
        "version_name": VERSION_NAME, "production_build_inputs_count": 186}, "source manifest")
    rows = manifest.get("files")
    need(isinstance(rows, list) and len(rows) == 1362, "source inventory incomplete")
    seen = {"SOURCE-MANIFEST.json"}
    for row in rows:
        path = row.get("path")
        need(isinstance(path, str) and path not in seen and PurePosixPath(path).as_posix() == path
             and not path.startswith("/") and all(part not in ("", ".", "..") for part in path.split("/")), "unsafe source member")
        seen.add(path)
        data = checked_file(source / path, allow_empty=True)
        need(type(row.get("bytes")) is int and len(data) == row["bytes"] and digest(data) == row.get("sha256"), "source member differs: " + path)
    # Source is frozen; tools must not create bytecode or generated files here.
    files = set()
    for path in source.rglob("*"):
        need(not path.is_symlink(), "linked source member")
        if path.is_file():
            files.add(str(path.relative_to(source)))
        else:
            need(path.is_dir(), "nonregular source member")
    need(files == seen, "unlisted/missing source member")
    return MANIFEST_SHA


def validate_config(raw):
    config = strict(raw)
    need(isinstance(config, dict), "config object required")
    schema = config.get("schema")
    expected = {"schema", "compute", "context_tokens", "threads"}
    if schema == "hepta.local-runtime.v2":
        expected.add("model_profile")
        need(config.get("model_profile") == MODEL_PROFILE, "current LFM3 profile required")
    else:
        need(schema == "hepta.local-runtime.v1", "unsupported config schema")
    need(set(config) == expected, "config keys differ from current production schema")
    fields(config, {"compute": "npu", "context_tokens": 8192, "threads": 4}, "current NPU configuration")
    return config


def verify_candidate(args, modules):
    raw = checked_file(args.assembly_result)
    need(digest(raw) == args.assembly_result_sha256, "reviewed assembly RESULT changed")
    assembly = strict(raw)
    fields(assembly, {"schema": "hepta.isolated-v54-assembly.v1", "all_pass": True,
        "source_head": SOURCE_HEAD, "candidate_source_commit": CANDIDATE_COMMIT, "candidate_source_tree": CANDIDATE_TREE,
        "source_manifest_sha256": MANIFEST_SHA, "actual_compiler_source_inputs": 186,
        "version_code": VERSION_CODE, "version_name": VERSION_NAME, "signer_certificate_sha256": CERT_SHA,
        "runner_sha256": ASSEMBLER_SHA, "native_baseline_signed_receipt_sha256": BASELINE_RECEIPT_SHA,
        "mac_build_receipt_sha256": MAC_RECEIPT_SHA, "signature_verified": True, "matches_previously_recorded_signer": True,
        "source_files_unchanged": True, "existing_key_bytes_and_metadata_unchanged": True,
        "cached_runtime_pins_unchanged": True, "native_libraries_identical_to_formal_v51": True,
        "actual_compiler_inputs_bound_to_signed_asset": True, "packaged_library_count": 17,
        "new_key_created": False, "android_compiled_on_mac": True}, "exact signed assembly proof")
    apk_path = Path(assembly.get("apk", ""))
    apk_raw = checked_file(apk_path, 256 << 20)
    need(type(assembly.get("apk_bytes")) is int and len(apk_raw) == assembly["apk_bytes"]
         and digest(apk_raw) == assembly.get("apk_sha256"), "signed candidate APK changed")
    mac_path = apk_path.parent / "mac-build-receipt.json"
    mac_raw = checked_file(mac_path)
    need(digest(mac_raw) == MAC_RECEIPT_SHA, "actual Mac compilation receipt changed")
    mac = strict(mac_raw)
    fields(mac, {"schema": "hepta.local-model.mac-build.v2", "source_head_from_ci": SOURCE_HEAD}, "Mac source head")
    need(len(mac.get("source_inputs", [])) == 186, "compiler input count differs")
    asset = modules["build_identity"].actual_build_identity(args.source, mac)
    pins = assembly.get("library_pins")
    need(isinstance(pins, dict) and len(pins) == 17 and all(is_hex(v) for v in pins.values()), "runtime library pins incomplete")
    with zipfile.ZipFile(io.BytesIO(apk_raw)) as packed:
        names = packed.namelist()
        need(len(names) == len(set(names)), "duplicate APK member")
        need(packed.read("assets/hepta-build-identity.json") == asset and digest(asset) == assembly.get("actual_build_identity_sha256"), "signed source identity asset differs")
        need(digest(packed.read("classes.dex")) == DEX_SHA, "signed exact Mac DEX differs")
        need({x for x in names if x.startswith("lib/")} == {"lib/arm64-v8a/" + name for name in pins}, "unexpected APK library set")
        for name, pin in pins.items():
            need(digest(packed.read("lib/arm64-v8a/" + name)) == pin, "signed runtime library differs")
    static = read_json(apk_path.parent / "control-v54-static/STATIC-ACCEPTANCE.json")
    need(digest(checked_file(apk_path.parent / "control-v54-static/STATIC-ACCEPTANCE.json")) == assembly.get("static_acceptance_sha256"), "static proof changed")
    fields(static, {"package": PACKAGE, "version_code": VERSION_CODE, "version_name": VERSION_NAME,
        "permissions": [], "apk_sha256": assembly["apk_sha256"], "actual_build_identity_sha256": digest(asset)}, "signed manifest/static scope")
    return assembly


def request_value(path):
    value = read_json(path)
    fields(value, {"schema": "hepta.background-notes-owner-request.v1", "target_package": NOTES,
        "external_model": False, "real_order": False}, "prepared harmless request")
    token = value.get("token")
    need(isinstance(token, str) and re.fullmatch(r"[0-9a-f]{16}", token), "unique request token invalid")
    body = "HEPTA测试-" + token
    instruction = "记一下：“" + body + "”"
    fields(value, {"body": body, "instruction": instruction, "body_sha256": sha_text(body),
        "instruction_sha256": sha_text(instruction)}, "unmodified prepared request")
    return value


def preflight(adb, ref, args, report, expected_config, assembly):
    hepta = ref.package_identity(adb, PACKAGE, "before-hepta")
    need(hepta["uid"] == args.expected_uid and 10000 <= args.expected_uid < 90000, "ordinary Hepta UID differs")
    need(len(hepta["apks"]) == 1 and hepta["apks"][0]["sha256"] == assembly["apk_sha256"], "installed exact signed v54 APK differs")
    version = ref.text(adb, ["dumpsys", "package", PACKAGE], "installed-hepta-version")
    need(re.search(r"\bversionCode=54\b", version) and re.search(r"\bversionName=" + re.escape(VERSION_NAME) + r"(?:\s|$)", version), "actual installed v54 manifest identity unavailable")
    need(ref.text(adb, ["run-as", PACKAGE, "id", "-u"], "run-as-uid").strip() == str(args.expected_uid), "private reader UID differs")
    notes = ref.package_identity(adb, NOTES, "before-notes")
    need(notes["uid"] == args.notes_uid and 10000 <= args.notes_uid < 90000, "Notes UID differs")
    need(len(notes["apks"]) == 1 and notes["apks"][0]["sha256"] == OBSERVED_NOTES_APK, "currently observed single-base Moto Notes build differs")
    report["installed_identity_before"] = {"hepta": hepta, "notes": notes}
    need(adb.app_bytes("files/model/runtime-config.json") == expected_config, "runtime config bytes differ")
    scope = adb.app_bytes("files/qualification-scope.json", optional=True)
    report["qualification_scope_present"] = scope is not None
    need(scope is None, "existing qualification scope blocks ordinary background UI; preserved unchanged")
    need(ref.text(adb, ["am", "get-current-user"], "current-user").strip() == "0", "Android user 0 required")
    enabled = ref.text(adb, ["settings", "get", "secure", "enabled_accessibility_services"], "enabled-accessibility").strip().split(":")
    service = PACKAGE + "/" + PACKAGE + ".HeptaAccessibilityService"
    expanded = [v.split("/", 1)[0] + "/" + (v.split("/", 1)[0] + v.split("/", 1)[1] if v.split("/", 1)[1].startswith(".") else v.split("/", 1)[1]) for v in enabled if "/" in v]
    need(service in expanded, "formal accessibility disabled; no settings changed")
    raw = ref.text(adb, ["dumpsys", "accessibility"], "accessibility-bound-state")
    bound = re.findall(r"\bBound services:\{(.*?)\}\s*Enabled services:\{", raw, re.S)
    need(any(re.search(re.escape(name) + r"(?=[,\]\s}])", part) for part in bound for name in (service, PACKAGE + "/.HeptaAccessibilityService")), "formal accessibility binding unreadable; no trigger sent")
    need(adb.app_bytes("files/background-session.active.json", optional=True) is None, "unreleased background journal blocks new task")
    baseline = ref.state(adb)
    need(not ref.active(baseline) and baseline.get("blocked") is not True, "existing task/recovery is not idle")
    need(not baseline or baseline.get("cleanup_known") is True, "old cleanup state unknown")
    need(adb.app_bytes("files/control-session.interrupted.json", optional=True) is None, "interruption latch requires normal owner recovery")
    # LocalModelEngine.WarmTask.directory() and request execution both place
    # their IDs directly under files/runs.  This set includes BOTH historical
    # request IDs and worker-generation directories; it is not a run-only set.
    run_directory_names = set(adb.list_children("files/runs", directories=True))
    tasks = set(adb.list_children("files/control-tasks", directories=True))
    sample = ref.system_snapshot(adb, args.out, 0, NOTES)
    need(not sample["errors"], "system baseline unsupported; inspect retained command outputs")
    need(PACKAGE + "/" in sample.get("main_focus", "") and sample.get("input_focused_display") == 0, "Hepta must already be visible on main display")
    need(not sample.get("target_task_displays"), "Notes already has a task; owner must close it normally before test")
    need(not any(d["name"].startswith("hepta-bg-") for d in sample["displays"].values()), "existing background display blocks test")
    need(not any(p["uid"] == args.expected_uid and "libhepta_local_runner.so" in p["args"] for p in sample["processes"]), "preexisting native worker blocks fresh task")
    screen_started = time.monotonic()
    _, screen = adb.command(["screencap", "-p"], label="prepared-main-screen", timeout=8, raw=True)
    screen_finished = time.monotonic()
    need(screen.startswith(b"\x89PNG\r\n\x1a\n") and len(screen) <= 16 << 20, "prepared screencap invalid")
    write_new(args.out / "prepared-main.png", screen, binary=True)
    report.update(preflight_pass=True, baseline_session=baseline, prepared_screen_sha256=digest(screen),
        prepared_screen_started_monotonic_s=screen_started, prepared_screen_finished_monotonic_s=screen_finished,
        preflight_scope="Read-only APK/config/accessibility/session/system observations; UI text/mode still verified against new owner after ordinary Start.")
    report["baseline_run_directory_names"] = sorted(run_directory_names)
    report["baseline_directory_scope"] = "All files/runs immediate directories, including request IDs and worker generations."
    return baseline, run_directory_names, tasks, [sample], hepta, notes, screen


def validate_display_release(cleanup, result, session, samples, task, generation, display_id, journal_absent):
    """Pure final cleanup gate used by monitor; app flags alone are insufficient."""
    need(is_hex(task, HEX32) and is_hex(generation, UUID) and type(display_id) is int and display_id > 0,
         "released background identity invalid")
    display_name = "hepta-bg-" + generation
    fields(cleanup, {"generation": generation, "task_id": task, "display_id": display_id,
        "state": "RELEASED", "cleanup_known": True, "retired": True,
        "broker_process_exit_observed": True, "broker_process_exit_code": 0}, "released broker process")
    fields(cleanup.get("last_broker_response"), {"generation": generation, "ok": True,
        "state": "RELEASED", "display_id": display_id}, "broker release response")
    fields(result, {"task_id": task, "cleanup_known": True, "observation_read_worker_pending_at_terminal": False}, "controller cleanup state")
    fields(session, {"task_id": task, "cleanup_known": True, "pending": False, "running": False,
        "blocked": False, "background_lease_unreleased": False}, "session cleanup state")
    fields(result.get("background_session"), {"task_id": task, "generation": generation,
        "display_id": display_id, "state": "RELEASED", "retired": True}, "final background lease")
    fields(result.get("background_cleanup"), {"task_id": task, "generation": generation,
        "display_id": display_id, "state": "RELEASED", "cleanup_known": True}, "terminal cleanup binding")
    need(journal_absent is True, "background journal remains or absence unknown")
    need(isinstance(samples, list) and len(samples) >= 2, "two post-terminal display samples required")
    for sample in samples[-2:]:
        need(isinstance(sample, dict) and sample.get("errors") == [] and isinstance(sample.get("displays"), dict)
             and 0 in sample["displays"] and isinstance(sample.get("task_display_ids"), list), "post-terminal system observation unavailable")
        need(display_id not in sample["displays"] and all(d.get("name") != display_name for d in sample["displays"].values())
             and display_id not in sample["task_display_ids"], "released display or its task remains in system observation")
    return {"verified": True, "background_display_system_absent": True, "journal_absent": True,
        "broker_exit_observed": True, "broker_exit_code": 0, "post_terminal_samples": 2,
        "scope": "Controller and broker receipts plus two observed system snapshots; not an atomic or continuous observation."}


def model_and_system_assessment(adb, modules, args, report, request, collection, samples, latest, baseline_run_directory_names, chain):
    ref, acceptance, receipts = (modules[k] for k in ("background_reference", "phone_acceptance", "warm_receipts"))
    directory = args.out / "evidence/task"
    read = lambda name: read_json(directory / name)
    owner, result, bootstrap, cleanup = [read(n) for n in ("owner.json", "result.json", "background-bootstrap.json", "background-cleanup.json")]
    task, uid = chain["task_id"], args.expected_uid
    generation, display_id = bootstrap.get("generation"), bootstrap.get("display_id")
    need(is_hex(generation, UUID) and type(display_id) is int and display_id > 0, "owned background display missing")
    display_name = "hepta-bg-" + generation
    fields(owner, {"background_request": SELECTION}, "owner selected Notes background scope")
    fields(latest, {"task_id": task, "origin": "user_button", "debug_nonce_sha256": None,
        "instruction_sha256": request["instruction_sha256"], "app_uid": uid,
        "cleanup_known": True, "pending": False, "running": False, "blocked": False,
        "external_model": False, "automatic_resume": False}, "ordinary Start final session")
    fields(bootstrap, {"task_id": task, "app_uid": uid, "owner_sha256": request["instruction_sha256"],
        "selection": SELECTION, "display_name": display_name, "bootstrap_dispatched": True, "bootstrap_model_issued": False}, "owner bootstrap")
    bound = read("background-binding.json")
    fields(bound, {"schema": "hepta.background-session.v1", "task_id": task, "generation": generation,
        "display_id": -1, "state": "INITIAL", "app_uid": uid, "owner_sha256": request["instruction_sha256"],
        "selection": SELECTION, "retired": False, "bootstrap_dispatched": False}, "initial pre-create task binding")
    observations = observed_files(directory)
    for oid, observation in observations.items():
        validate_domain(observation, {"display_id": display_id, "generation": generation})
        png = checked_file(directory / (oid + ".png"))
        need(png.startswith(b"\x89PNG\r\n\x1a\n") and digest(png) == observation.get("screen_sha256"), "archived screen hash differs")
    need(not collection.get("errors") and receipts.collection_verified(collection), "real native inference/session receipts not verified")
    rows = collection.get("associated_runs")
    need(isinstance(rows, list) and rows, "no associated real native model requests")
    associated, workers, pids = set(), set(), set()
    for row in rows:
        run = row.get("run_id")
        need(is_hex(run, HEX32) and run not in associated and run not in baseline_run_directory_names, "old/repeated native run referenced")
        associated.add(run)
        run_dir = args.out / "evidence/runs" / run
        receipt = read_json(run_dir / "app-receipt.json")
        prompt = checked_file(run_dir / "prompt.txt").decode("utf-8")
        need(acceptance.prompt_binding(prompt, request["instruction"], set(observations)), "native prompt not bound to exact owner/current observation")
        worker = receipt.get("worker_generation")
        need(is_hex(worker, HEX32) and worker not in baseline_run_directory_names, "old native worker session directory referenced")
        workers.add(worker)
        pid = receipt.get("worker_pid")
        need(type(pid) is int and pid > 0, "actual native worker PID unavailable")
        pids.add(pid)
    need(workers == {result["model_session"]["worker_generation"]}, "native requests do not share result session")
    model_artifacts = [read_json(p) for p in directory.glob("step-*-model-*.json")]
    need({m.get("run_id") for m in model_artifacts} == associated, "unmapped/extra native decisions")
    model_actions = [p for p in directory.glob("step-*-action.json") if re.fullmatch(r"step-[0-9]{2}-action.json", p.name)]
    for path in sorted(model_actions):
        action = read_json(path)
        decision = action.get("action", {})
        run = action.get("model_run_id")
        need(run in associated and action.get("model_issued") is True, "model action has no real native parent")
        raw = strict(checked_file(args.out / "evidence/runs" / run / "raw-text.txt"))
        fields(raw, decision, "native output/action binding")
        need(decision.get("observation_id") in observations and decision.get("action") in ("find_app", "wait", "open", "notes.create"), "unallowed model decision")
        need(action.get("stale") is False and action.get("accepted") is True, "model action rejected/stale")
        if decision.get("action") in ("open", "notes.create"):
            need(decision.get("package") == NOTES and action.get("dispatched") is True, "model wrote outside Notes")
        fields(action.get("background_session"), {"schema": "hepta.background-session.v1", "task_id": task,
            "app_uid": uid, "owner_sha256": request["instruction_sha256"], "selection": SELECTION,
            "state": "ACTIVE", "retired": False, "generation": generation, "display_id": display_id}, "model action display")
    need(chain["parent_run_id"] in associated, "real notes.create parent not inferred locally")
    observed_processes = [p for s in samples for p in s.get("processes", []) if p["pid"] in pids]
    model_uid_ok = all(any(p["pid"] == pid and p["uid"] == uid and "libhepta_local_runner.so" in p["args"] for p in observed_processes) for pid in pids) and all(p["uid"] == uid for p in observed_processes)
    clean = [s for s in samples if not s["errors"]]
    active = [s for s in clean if s.get("displays", {}).get(display_id, {}).get("name") == display_name]
    focus_ok = len(clean) == len(samples) and len(samples) >= 3 and all(s.get("main_focus") == samples[0].get("main_focus") and s.get("input_focused_display") == 0 for s in samples)
    isolated = bool(active) and any(s.get("target_task_displays") == [display_id] for s in active) and all(set(s.get("target_task_displays", [])) <= {display_id} for s in clean)
    broker = ref.broker_process_summary([p for s in active for p in s.get("processes", [])], generation, uid, NOTES)
    flags_ok = bool(active) and all(all(flag in s["displays"][display_id]["description"] for flag in
        ("FLAG_TRUSTED", "FLAG_OWN_FOCUS", "FLAG_STEAL_TOP_FOCUS_DISABLED")) and not any(flag in s["displays"][display_id]["description"]
        for flag in ("FLAG_SECURE", "FLAG_ALWAYS_UNLOCKED")) for s in active)
    fields(bootstrap.get("last_broker_response"), {"state": "ACTIVE", "generation": generation, "display_id": display_id,
        "width": 720, "height": 1280, "density": 240, "capture_secure": False, "always_unlocked": False, "ime_policy": "hide"}, "observed display policy")
    release = validate_display_release(cleanup, result, latest, samples, task, generation, display_id,
        adb.app_bytes("files/background-session.active.json", optional=True) is None)
    report["acceptance"] = {"ordinary_start_owner_bound": True, "local_native_parent_notes_create_verified": True,
        "native_request_and_session_cleanup_verified": True, "ordinary_uid_native_process_observed": model_uid_ok,
        "notes_chain": chain, "root_or_shell_broker_identity": broker, "sampled_main_focus_unchanged": focus_ok,
        "target_task_only_on_owned_display": isolated, "display_policy_readback_verified": flags_ok,
        "background_display_system_absent": release["background_display_system_absent"], "display_release": release,
        "broker_exit_observed": True, "broker_exit_code": 0,
        "journal_absent": True, "observer_pending_at_terminal_reported": result["observation_read_worker_pending_at_terminal"],
        "generation": generation, "display_id": display_id, "sample_count": len(samples), "active_display_samples": len(active),
        "main_screen_concurrent_canary_run": False, "main_screen_concurrency_qualified": False,
        "focus_claim_scope": "Idle main screen sampled points only; sequential dumps are non-atomic and cannot exclude transient interference.",
        "persistent_storage_bytes_verified": False, "new_database_item_identity_verified": False,
        "visual_screenshot_reviewed": False, "raw_xml_independently_verified": False,
        "hardware_execution_counters_independently_verified": False,
        "maximum_sample_start_gap_s": max((b["started_monotonic_s"] - a["started_monotonic_s"] for a, b in zip(samples, samples[1:])), default=None)}
    need(all((model_uid_ok, broker.get("verified") is True, focus_ok, isolated, flags_ok, release["verified"])), "native UID/display ownership/idle focus/system release checks incomplete")
    report["qualified"] = True


def execute(args, report):
    verify_source(args.source)
    modules = load_helpers(args.source)
    assembly = verify_candidate(args, modules)
    request = request_value(args.request)
    expected_config = checked_file(args.runtime_config, 4096)
    validate_config(expected_config)
    report.update(expected_apk_sha256=assembly["apk_sha256"], expected_app_uid=args.expected_uid,
        expected_notes_uid=args.notes_uid, source_head=SOURCE_HEAD, candidate_source_commit=CANDIDATE_COMMIT,
        candidate_source_tree=CANDIDATE_TREE, source_manifest_sha256=MANIFEST_SHA,
        assembly_result_sha256=args.assembly_result_sha256, runtime_config_sha256=digest(expected_config),
        model_profile=MODEL_PROFILE, expected_model_sha256=MODEL_SHA, compute="npu", context_tokens=8192, threads=4,
        instruction_sha256=request["instruction_sha256"], body_sha256=request["body_sha256"], helper_pins={k: v[1] for k, v in PINS.items()})
    identity, ref, acceptance = (modules[k] for k in ("v35_identity", "background_reference", "phone_acceptance"))
    # Exactly the reviewed existing O_RDONLY/no-create LOCK_EX|LOCK_NB lease.
    # Every device command remains protected by the helper's unchanged guard.
    with identity.operation_lock(report):
        adb = identity.guard_adb(acceptance.Adb(args, args.out))
        ref.bounded_private_reader(adb)
        baseline, baseline_run_directory_names, baseline_tasks, samples, hepta, notes, screen = preflight(adb, ref, args, report, expected_config, assembly)
        if args.mode == "preflight":
            report["preflight_only"] = True
            return
        marker = args.request.with_name(args.request.name + ".armed.json")
        need(not marker.exists() and not marker.is_symlink(), "this unique request was previously armed; prepare a new request instead of retrying")
        if args.start_tap:
            need(digest(screen) == args.prepared_screen_sha256, "current screenshot differs from explicitly reviewed Start proof")
        write_new(marker, {"schema": "hepta.once-only-owner-request-armed.v1", "request_sha256": digest(checked_file(args.request)),
            "instruction_sha256": request["instruction_sha256"], "out": str(args.out), "armed_wall_s": time.time()})
        # Durable trigger journal precedes the sole optional phone input.  If its
        # ADB outcome is unknown, never retry that tap or claim no task started.
        trigger = {"kind": "one_screenshot_bound_existing_start_tap" if args.start_tap else "owner_presses_existing_start",
            "auto_task": False, "coordinates": args.start_tap, "screen_sha256": digest(screen), "request_sha256": request["instruction_sha256"]}
        write_new(args.out / "ARMED.json", trigger)
        report["trigger"] = trigger
        if args.start_tap:
            need(report["prepared_screen_finished_monotonic_s"] - report["prepared_screen_started_monotonic_s"] <= 3
                 and time.monotonic() - report["prepared_screen_finished_monotonic_s"] <= 1,
                 "Start screencap/tap freshness window elapsed; no input sent and no automatic retry")
            report["ordinary_start_may_have_been_sent"] = True
            adb.command(["input", "-d", "0", "tap", str(args.start_tap[0]), str(args.start_tap[1])], label="existing-visible-hepta-start-button", timeout=3)
        else:
            report["ordinary_start_may_have_been_sent"] = True
            print("ARMED: press Hepta's existing 开始任务 once for the prepared request. Keep main screen idle and do not use another ADB operator.", flush=True)
        task, running_started, latest = None, None, baseline
        armed = time.monotonic()
        terminal = set(acceptance.TERMINAL) | {"controller_verified_done"}
        ended_normally = False
        while time.monotonic() - (running_started if running_started is not None else armed) < (args.timeout if task else args.start_window):
            samples.append(ref.system_snapshot(adb, args.out, len(samples), NOTES))
            latest = ref.state(adb)
            candidate = latest.get("task_id")
            if is_hex(candidate, HEX32) and candidate not in baseline_tasks and task is None:
                fields(latest, {"instruction_sha256": request["instruction_sha256"], "origin": "user_button", "debug_nonce_sha256": None}, "new ordinary owner task")
                task, running_started = candidate, time.monotonic()
                report["task_id"] = task
            if task is not None:
                need(candidate == task, "task identity replaced; no retries allowed")
                if not ref.active(latest) and latest.get("status") in terminal:
                    ended_normally = True
                    break
            else:
                need(candidate == baseline.get("task_id") or candidate is None, "preexisting/unrecognized task was resumed")
            time.sleep(args.interval)
        report["last_session"] = latest
        need(task is not None and ended_normally, "armed/task deadline or unknown terminal; use normal visible Stop if needed, no hidden cleanup attempted")
        for _ in range(2):
            time.sleep(args.interval)
            samples.append(ref.system_snapshot(adb, args.out, len(samples), NOTES))
        hepta_after, notes_after = ref.package_identity(adb, PACKAGE, "after-hepta"), ref.package_identity(adb, NOTES, "after-notes")
        report["installed_identity_after"] = {"hepta": hepta_after, "notes": notes_after}
        need(equal(hepta, hepta_after) and equal(notes, notes_after), "APK/UID changed during task")
        need(adb.app_bytes("files/model/runtime-config.json") == expected_config, "runtime config changed")
        need(adb.app_bytes("files/qualification-scope.json", optional=True) is None, "qualification scope appeared")
        latest = ref.state(adb)
        need(latest.get("task_id") == task and not ref.active(latest), "task replaced/restarted before evidence collection")
        collection = acceptance.collect_evidence(adb, args.out / "evidence", task, request["instruction"], baseline_run_directory_names,
            screenshots=True, expected_uid=args.expected_uid, expected_compute="npu", expected_context=8192, expected_model_profile=MODEL_PROFILE)
        report["collection"] = collection
        bootstrap = read_json(args.out / "evidence/task/background-bootstrap.json")
        domain = {"display_id": bootstrap.get("display_id"), "generation": bootstrap.get("generation")}
        need(type(domain["display_id"]) is int and domain["display_id"] > 0 and is_hex(domain["generation"], UUID), "no main-display fallback permitted")
        installed = {"package": NOTES, "uid": args.notes_uid, "apk_hashes": {"base": OBSERVED_NOTES_APK}}
        chain = validate_notes_chain(args.out / "evidence/task", request["instruction"], installed, domain)
        need(chain["task_id"] == task, "collected owner task differs from fresh ordinary Start")
        model_and_system_assessment(adb, modules, args, report, request, collection, samples, latest, baseline_run_directory_names, chain)
        need(equal(ref.state(adb), latest), "session changed during final evidence assessment")
        need(adb.app_bytes("files/model/runtime-config.json") == expected_config, "config changed during final evidence assessment")
        verify_source(args.source)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="mode", required=True)
    prepare = sub.add_parser("prepare", help="host only: create a unique harmless Notes request; no phone/lock access")
    prepare.add_argument("--out", type=Path, required=True, help="new absolute request JSON filename")
    for mode in ("preflight", "monitor"):
        q = sub.add_parser(mode, help="read-only fresh preflight" if mode == "preflight" else "fresh preflight then ordinary visible Start acceptance")
        q.add_argument("--source", type=Path, required=True, help="exact frozen controller source root")
        q.add_argument("--assembly-result", type=Path, required=True)
        q.add_argument("--assembly-result-sha256", required=True, help="actual completed v54 signed assembly RESULT SHA, not a placeholder")
        q.add_argument("--request", type=Path, required=True)
        q.add_argument("--runtime-config", type=Path, required=True, help="expected actual current config bytes; never written to phone")
        q.add_argument("--adb", required=True)
        q.add_argument("--adb-host", required=True)
        q.add_argument("--adb-port", type=int, required=True)
        q.add_argument("--serial", required=True)
        q.add_argument("--expected-uid", type=int, required=True)
        q.add_argument("--notes-uid", type=int, required=True)
        q.add_argument("--existing-su-authorized", action="store_true", required=True,
            help="operator confirms ordinary Hepta already has normal su authorization; no grant/probe is performed")
        q.add_argument("--command-timeout", type=int, default=8)
        q.add_argument("--out", type=Path, required=True, help="fresh absolute private result directory")
        if mode == "monitor":
            q.add_argument("--start-tap", type=int, nargs=2, metavar=("X", "Y"))
            q.add_argument("--prepared-screen-sha256", help="exact current screenshot explicitly visually reviewed for Start coordinates")
            q.add_argument("--start-window", type=int, default=90)
            q.add_argument("--timeout", type=int, default=560)
            q.add_argument("--interval", type=float, default=1.0)
    return p


def main():
    args = parser().parse_args()
    if args.mode == "prepare":
        token = secrets.token_hex(8)
        body = "HEPTA测试-" + token
        instruction = "记一下：“" + body + "”"
        write_new(args.out, {"schema": "hepta.background-notes-owner-request.v1", "target_package": NOTES,
            "token": token, "body": body, "instruction": instruction, "body_sha256": sha_text(body),
            "instruction_sha256": sha_text(instruction), "external_model": False, "real_order": False,
            "created_wall_s": time.time()})
        print(json.dumps({"prepared": str(args.out), "instruction": instruction, "phone_contacted": False}, ensure_ascii=False))
        return 0
    need(is_hex(args.assembly_result_sha256), "actual reviewed assembly-result SHA required")
    need(Path(args.adb).is_absolute() and Path(args.adb).is_file(), "absolute existing adb executable required")
    need(1 <= args.adb_port <= 65535 and 1 <= args.command_timeout <= 30, "bounded ADB configuration required")
    need(10000 <= args.expected_uid < 90000 and 10000 <= args.notes_uid < 90000, "ordinary package UIDs required")
    if args.mode == "monitor":
        need(1 <= args.start_window <= 120 and 540 <= args.timeout <= 600 and 0.25 <= args.interval <= 5, "bounded monitor timing required")
        if args.start_tap:
            need(is_hex(args.prepared_screen_sha256) and all(0 <= x <= 10000 for x in args.start_tap), "one Start tap needs explicit coordinates and reviewed screenshot SHA")
        else:
            need(args.prepared_screen_sha256 is None, "screenshot pin without a requested Start tap")
    need(args.out.is_absolute() and not args.out.exists() and all(not p.is_symlink() for p in (args.out, *args.out.parents)), "fresh absolute non-symlink output required")
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {"schema": "hepta.background-notes-acceptance.v1", "mode": args.mode, "qualified": False,
        "preflight_pass": False, "target_package": NOTES, "existing_su_authorization_operator_attested": True,
        "phone_installation_performed": False, "configuration_modified": False, "qualification_scope_modified": False,
        "magisk_policy_modified": False, "direct_broker_client_used": False, "external_model_invoked_by_driver": False,
        "private_nonce_trigger_used": False, "uiautomator_or_UiAutomation_used": False,
        "target_app_input_from_driver": False, "automatic_retry": False, "main_screen_concurrency_qualified": False,
        "started_wall_s": time.time()}
    try:
        execute(args, report)
    except BaseException as error:
        report.update(qualified=False, error_type=type(error).__name__, error=str(error))
        if report.get("ordinary_start_may_have_been_sent"):
            report.update(cleanup_status="UNKNOWN", manual_visible_stop_may_be_required=True)
    finally:
        report["ended_wall_s"] = time.time()
        write_new(args.out / "RESULT.json", report)
    ok = report["qualified"] if args.mode == "monitor" else report["preflight_pass"] and "error" not in report
    print(json.dumps({"qualified": report["qualified"], "preflight_pass": report["preflight_pass"],
        "error": report.get("error"), "result": str(args.out / "RESULT.json")}, ensure_ascii=False), flush=True)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
