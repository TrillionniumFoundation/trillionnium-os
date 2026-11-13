#!/usr/bin/env python3
"""Shared source-pinned support for the ordinary main58/helper6 Flight entry.

This module does not execute a model, business click, broker, shell tool or ADB
command at import time. Release inputs are actual immutable signed receipts.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import time
import xml.etree.ElementTree as ET

MAIN = "org.trillionnium.hepta.local"
HELPER = "org.trillionnium.hepta.webhelper"
NOTES = "com.motorola.stylus"
UI_PACKAGES = (NOTES, HELPER)
CERT = "202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5"
BASE_RUN_SHA = "0d1aa533221550cbc3b1568fd58f815c138fdaab6863281e71767629d492cfa4"
BASE_PREPARE_SHA = "3779eb4fc02dfd5aa5468e2ed4209631bab00fe9079950a5c875bfe96462f4f3"
UI_SHA = "b5483ad51dc3639a734d07169a7ad928f0ddf7ad2f5a46da4b3461abe8170c98"
R12_SHA = "d5a2caec2ad96b524d89651c0b4fbb63107678745dd4ccfa33368999fc0f817c"
HELPER_BUILD_SHA = "8dad8522b39d9fb017fdb869bfdf9c8081f14d445a314bb4555d84e11e49539d"
HELPER_SOURCE_SHA = "3a9cb424a258adfe71b821dadf6b6319bd228a3bf2d0bf190c9d6b139f6b1c8e"
PROTOCOL = HELPER + ".IWebEvidence.v4"
CALLBACK = HELPER + ".IWebEvidenceCallback.v4"
BINDING_SCHEMA = "hepta.web-helper.binding.v4"
RAW_SCHEMA = "hepta.web-helper.raw-evidence.v4"
CALLBACK_SCHEMA = "hepta.web-helper.callback.v4"
JOURNAL_SCHEMA = "hepta.web-helper.lease-journal.v4"
CLEANUP_KEYS = frozenset(("captures_retired", "stop_loading_called", "webview_destroyed",
                         "active_view_absent", "storage_clear_completed"))
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
OWNERS = {
    "flight": ("查一下2026年11月17日北京到上海的单程机票，1名成人",
               "868050b2cd0f02abb963559bbe60afcdfea9a0e2be5e62d06ba6f354f85ad2ee",
               "csair_public_flight"),
    "shopping": ("查一下小米AX3000T的官网售价",
                 "d2a8da63cc9cb9f6a9af55c498caacadaeec6d6eb1df7fb8e9ec263882d6e8b4",
                 "mi_public_product"),
}
IDENTITY_KEYS = frozenset(("package", "uid", "version_code", "apk_hashes",
                          "apk_set_sha256", "signer_sha256"))
BINDING_KEYS = frozenset(("schema", "initial_url", "goal_kind", "site_policy_id",
    "site_policy_sha256", "task_id", "controller_session_nonce", "owner",
    "owner_sha256", "contract_sha256", "authorization", "background",
    "controller_identity", "helper_identity", "storage_profile_name"))


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw if isinstance(raw, bytes) else raw.encode("utf-8")).hexdigest()


def strict(raw):
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, "duplicate JSON key")
            out[key] = value
        return out
    def bad(value):
        raise ValueError("non-finite JSON " + value)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad)


def same_json(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_json(v, right[k]) for k, v in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    return left == right


def canonical(value):
    """The exact pure WebEvidenceBinding encoder, including control characters."""
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        need(-(1 << 63) <= value < (1 << 63), "binding integer exceeds Java long")
        return str(value)
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        out = []
        for c in value:
            n = ord(c)
            out.append("\\" + c if c in ('"', "\\") else ("\\u%04x" % n if n < 0x20 else c))
        return '"' + "".join(out) + '"'
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        need(all(isinstance(k, str) for k in value), "binding key type")
        keys = sorted(value, key=lambda k: k.encode("utf-16-be", errors="strict"))
        return "{" + ",".join(canonical(k) + ":" + canonical(value[k]) for k in keys) + "}"
    raise RuntimeError("immutable binding contains unsupported scalar")


def stamp(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def exact(path, maximum=40 << 20, allow_empty=False):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts
         and all(not p.is_symlink() for p in (path, *path.parents)), "absolute non-link original input required")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and (0 <= before.st_size if allow_empty else 0 < before.st_size)
             and before.st_size <= maximum, "bounded regular original required")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    need(len(raw) == before.st_size and stamp(before) == stamp(after) == stamp(path.stat()),
         "input changed while read")
    return raw, stamp(before)


def pinned_module(path, expected, name):
    raw, identity = exact(path)
    need(sha(raw) == expected, "exact helper source differs: " + name)
    spec = importlib.util.spec_from_file_location(name, Path(path))
    value = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), "exec", dont_inherit=True), value.__dict__)
    need(exact(path) == (raw, identity), "helper changed during import")
    return value


def write_new(path, raw):
    path = Path(path)
    need(all(not p.is_symlink() for p in (path, *path.parents)), "output link rejected")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    need(exact(path, max(1, len(raw)), allow_empty=True)[0] == raw, "output readback differs")
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def plan_for(case):
    need(case == "flight", "this wire4 successor covers only the exact frozen Flight owner")
    owner, owner_sha, kind = OWNERS[case]
    need(sha(owner) == owner_sha, "frozen natural owner bytes differ")
    value = {"schema": "hepta.v58-public-web-test-plan.v1", "case": case,
             "instruction": owner, "instruction_sha256": owner_sha, "goal_kind": kind,
             "execution_mode": "background_only", "allowed_packages": [HELPER],
             "explicit_ui_selected_packages": list(UI_PACKAGES),
             "bootstrap_package": HELPER, "controller_version_code": 58, "helper_version_code": 6,
             "driver_business_actions": False, "model_required_for_page_actions": True}
    return value, encoded(value)


def read_ui_preferences(adb, expected_uid, label):
    """Fixed read-only SharedPreferences path. No write, repair, or app input."""
    relative = "shared_prefs/background-ui-choice-v1.xml"
    code, raw = adb.command(["run-as", MAIN, "sh", "-c",
        "test -d shared_prefs && test ! -L shared_prefs && "
        "test -f " + relative + " && test ! -L " + relative + " && "
        "test ! -e " + relative + ".bak && test ! -L " + relative + ".bak && echo PRESENT"],
        label=label + "-preference-path", raw=True)
    need(code == 0 and raw.strip() == b"PRESENT", "actual ordinary preference path unavailable")
    command = ["run-as", MAIN, "stat", "-c", "%d %i %u %s %h %f %Y %Z", relative]
    code, before = adb.command(command, label=label + "-preference-stat", raw=True)
    fields = before.decode("ascii", "strict").strip().split()
    need(code == 0 and len(fields) == 8
         and all(re.fullmatch(r"[0-9]+", fields[i]) for i in (0, 1, 2, 3, 4, 6, 7))
         and re.fullmatch(r"[0-9a-fA-F]+", fields[5]), "actual preference stat format differs")
    mode = int(fields[5], 16)
    need(int(fields[1]) > 0 and int(fields[2]) == expected_uid and int(fields[4]) == 1
         and stat.S_ISREG(mode)
         and 0 < int(fields[3]) <= 65536, "actual private preference UID/mode/link/size differs")
    code, value = adb.command(["run-as", MAIN, "head", "-c", "65537", relative],
        label=label + "-preference-read", raw=True)
    need(code == 0 and len(value) == int(fields[3]), "actual preference read length differs")
    code, after = adb.command(command, label=label + "-preference-stat-after", raw=True)
    need(code == 0 and after == before, "actual preference file changed while read")
    return value


def preference_choice(raw):
    """Parse actual saved UI choice bytes only; never grant a task or permission."""
    need(type(raw) is bytes and 0 < len(raw) <= 65536, 'bounded original SharedPreferences bytes required')
    text = raw.decode('utf-8', 'strict')
    need('<!DOCTYPE' not in text and '<!ENTITY' not in text, 'preference XML declarations unsupported')
    root = ET.fromstring(text)
    need(root.tag == 'map' and not root.attrib and not (root.text or '').strip(),
         'exact SharedPreferences map required')
    entries = {}
    for node in root:
        name = node.get('name')
        need(name in ('enabled', 'selection') and name not in entries
             and not list(node) and not (node.tail or '').strip(), 'exact unique UI preference fields required')
        entries[name] = node
    need(set(entries) == {'enabled', 'selection'}, 'mode and explicit selection must both be saved')
    enabled, selection = entries['enabled'], entries['selection']
    need(enabled.tag == 'boolean' and enabled.attrib == {'name': 'enabled', 'value': 'true'}
         and not (enabled.text or '').strip()
         and selection.tag == 'string' and selection.attrib == {'name': 'selection'}
         and isinstance(selection.text, str) and 0 < len(selection.text.encode('utf-8')) <= 8192,
         'actual persisted enabled mode and selection string required')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate preference selection key')
            result[key] = value
        return result
    def bad(value):
        raise RuntimeError('non-JSON preference number: ' + value)
    value = json.loads(selection.text, object_pairs_hook=pairs, parse_constant=bad)
    need(type(value) is dict and set(value) == {'schema', 'initial', 'packages'}
         and value['schema'] == 'hepta.background-ui-choice.v1'
         and value['initial'] in UI_PACKAGES and type(value['packages']) is list
         and len(value['packages']) == 2, 'actual saved dual selection shape differs')
    packages = []
    for row in value['packages']:
        need(type(row) is dict and set(row) == {'package', 'uid', 'signers'}
             and type(row['package']) is str and row['package'] in UI_PACKAGES
             and type(row['uid']) is int and 10000 <= row['uid'] < 90000
             and type(row['signers']) is list and 1 <= len(row['signers']) <= 4
             and all(type(h) is str and re.fullmatch(r'[0-9a-f]{64}', h) for h in row['signers'])
             and row['signers'] == sorted(set(row['signers'])), 'actual saved package UID/signers malformed')
        packages.append(row['package'])
    need(packages == list(UI_PACKAGES), 'actual saved UI set must be exactly Notes and helper')
    return value


def original_preference_bytes(preparation):
    original = preparation.get('ui_preferences_original')
    need(type(original) is dict and set(original) == {'file', 'bytes', 'sha256', 'raw_utf8'}
         and original['file'] == 'background-ui-choice-original.xml'
         and type(original['bytes']) is int and 0 < original['bytes'] <= 65536
         and type(original['raw_utf8']) is str and type(original['sha256']) is str
         and re.fullmatch(r'[0-9a-f]{64}', original['sha256']), 'exact original preference archive required')
    raw = original['raw_utf8'].encode('utf-8', 'strict')
    need(len(raw) == original['bytes'] and hashlib.sha256(raw).hexdigest() == original['sha256'],
         'embedded original preferences bytes/hash differ')
    preference_choice(raw)
    return raw


def background_choice_evidence(plan, preferences_raw, selected_labels, automatic_text, spinner_hidden):
    """Recompute a fixed natural OWNER's expected helper target within saved UI scope."""
    expected, unused_raw = plan_for(plan.get("case") if type(plan) is dict else None)
    need(same_json(plan, expected), "complete frozen natural Web plan required")
    saved = preference_choice(preferences_raw)
    need(type(selected_labels) is dict and set(selected_labels) == set(UI_PACKAGES)
         and all(type(value) is str and 0 < len(value.encode("utf-8")) <= 512
                 and not any(ord(c) < 32 for c in value) for value in selected_labels.values()),
         "both app labels must be archived from actual chooser rows")
    expected_text = "本次将自动使用：" + selected_labels[HELPER] + "。已保存的应用范围保持不变。"
    need(type(automatic_text) is str and automatic_text == expected_text
         and spinner_hidden is True, "actual helper automatic target and hidden Spinner required")
    recognition = {"flight": "natural_explicit_date_single_adult_flight_query.v1",
                   "shopping": "bounded_natural_official_product_price.v1"}[plan["case"]]
    return {"allowed_packages": list(UI_PACKAGES), "bootstrap_package": saved["initial"],
            "scope_count": 2, "automatic_target_text": automatic_text,
            "initial_spinner_hidden": True, "observed_app_labels": dict(selected_labels),
            "selection_source": "ordinary_visible_multi_choice_and_persisted_initial",
            "expected_effective_lease_packages": [HELPER], "effective_lease_already_verified": False,
            "expected_owner_task_selection": {
                "schema": "hepta.owner-task-app-selection.v1",
                "owner_sha256": plan["instruction_sha256"], "recognition": recognition,
                "original_ui_initial_package": saved["initial"],
                "original_ui_allowed_packages": list(UI_PACKAGES),
                "effective_initial_package": HELPER, "effective_allowed_packages": [HELPER],
                "effective_scope_within_selected_apps": True, "effective_scope_strictly_smaller": True,
                "initial_app_changed": saved["initial"] != HELPER,
                "package_from_model_or_screen": False, "grants_tool_authority": False,
                "changes_saved_preferences": False}}


def background_selection_from_preparation(plan, preparation):
    """Validate original UI/prefs only; the eventual runtime lease is separately collected."""
    need(type(preparation) is dict
         and preparation.get("schema") == "hepta.ordinary-background-web-ui-preparation.v1"
         and preparation.get("driver_revision") == "web-v58-helper6-natural-owner-automatic-target-r1"
         and preparation.get("prepared") is True and preparation.get("error") is None
         and preparation.get("task_started") is False and preparation.get("start_tapped") is False
         and preparation.get("target_app_operated") is False
         and preparation.get("permissions_changed") is False
         and preparation.get("existing_tasks_removed") is False
         and preparation.get("direct_broker_client_used") is False
         and preparation.get("ui_preferences_unchanged_from_before") is True
         and same_json(preparation.get("plan"), plan)
         and preparation.get("case") == plan["case"]
         and preparation.get("target_package") == HELPER
         and preparation.get("instruction") == plan["instruction"]
         and preparation.get("instruction_sha256") == plan["instruction_sha256"],
         "completed automatic ordinary Web preparation and original OWNER required")
    raw = original_preference_bytes(preparation)
    need(preparation.get("ui_preferences_before_sha256") == sha(raw),
         "original persisted UI preferences were not retained from before preparation")
    selection = preparation.get("background_selection")
    need(type(selection) is dict, "original automatic selection missing")
    expected = background_choice_evidence(plan, raw, selection.get("observed_app_labels"),
                                         selection.get("automatic_target_text"),
                                         selection.get("initial_spinner_hidden"))
    need(same_json(selection, expected), "recomputed automatic UI selection differs")
    return expected

def read_ref(ref, maximum):
    need(isinstance(ref, dict) and set(ref) == {"path", "bytes", "sha256"}
         and type(ref["bytes"]) is int and 0 < ref["bytes"] <= maximum
         and isinstance(ref["sha256"], str) and HEX64.fullmatch(ref["sha256"]),
         "exact artifact reference required")
    raw, identity = exact(Path(ref["path"]), maximum)
    need(len(raw) == ref["bytes"] and sha(raw) == ref["sha256"], "artifact bytes/SHA differ")
    return raw, identity


def load_release(path, expected_sha):
    need(isinstance(HELPER_BUILD_SHA, str) and HEX64.fullmatch(HELPER_BUILD_SHA)
         and isinstance(HELPER_SOURCE_SHA, str) and HEX64.fullmatch(HELPER_SOURCE_SHA),
         "actual helper6 build/source pins must be sealed before device admission")
    need(isinstance(expected_sha, str) and HEX64.fullmatch(expected_sha), "release manifest SHA required")
    raw, identity = exact(path, 65536)
    need(sha(raw) == expected_sha, "release manifest changed")
    value = strict(raw)
    need(set(value) == {"schema", "status", "controller", "helper"}
         and value["schema"] == "hepta.v58-web-entry-release.v1" and value["status"] == "sealed",
         "only a sealed actual release manifest can reach any device action")
    proof = {}
    retained = [(Path(path), raw, identity)]
    for role, package, version in (("controller", MAIN, 58), ("helper", HELPER, 6)):
        row = value[role]
        need(isinstance(row, dict) and set(row) == {"package", "uid", "version_code", "version_name",
             "apk", "signed_result", "source_inventory_sha256", "signer_certificate_sha256"},
             "complete exact release role required")
        need(row["package"] == package and type(row["uid"]) is int and 10000 <= row["uid"] < 90000
             and type(row["version_code"]) is int and row["version_code"] == version
             and row["signer_certificate_sha256"] == CERT
             and isinstance(row["source_inventory_sha256"], str) and HEX64.fullmatch(row["source_inventory_sha256"]),
             "released package/version/UID/signer differs")
        signed_raw, signed_id = read_ref(row["signed_result"], 1 << 20)
        signed = strict(signed_raw)
        need(signed.get("all_pass") is True and type(signed.get("exit_code")) is int and signed["exit_code"] == 0,
             "actual successful signed receipt required")
        for key in ("version_code", "version_name", "source_inventory_sha256", "signer_certificate_sha256"):
            need(same_json(signed.get(key), row[key]), "signed release field mismatch: " + key)
        need(signed.get("apk") == row["apk"]["path"]
             and type(signed.get("apk_bytes")) is int and signed["apk_bytes"] == row["apk"]["bytes"]
             and signed.get("apk_sha256") == row["apk"]["sha256"], "signed APK reference differs")
        apk_raw, apk_id = read_ref(row["apk"], 32 << 20 if role == "controller" else 2 << 20)
        if role == "controller":
            need(signed.get("schema") == "hepta.isolated-v58-assembly.v1"
                 and signed.get("permissions") == [HELPER + ".permission.BIND_EVIDENCE"]
                 and signed.get("source_files_unchanged") is True
                 and signed.get("native_recompiled_here") is False
                 and signed.get("actual_flight_results_provider_ready") is False
                 and isinstance(signed.get("pocket4_build_receipt_sha256"), str)
                 and HEX64.fullmatch(signed["pocket4_build_receipt_sha256"])
                 and isinstance(signed.get("source_commit"), str)
                 and re.fullmatch(r"[0-9a-f]{40}", signed["source_commit"]), "actual main58 source/permission receipt missing")
            layout = signed.get("resources_arsc_zip_layout", {})
            need(layout.get("compression_method") == 0 and layout.get("four_byte_aligned") is True,
                 "signed main resource layout missing")
        else:
            need(signed.get("schema") == "hepta.web-helper-formal-signed.v1"
                 and signed.get("package") == HELPER and signed.get("permissions") == ["android.permission.INTERNET"]
                 and signed.get("actual_unsigned_build_receipt_sha256") == HELPER_BUILD_SHA
                 and row["source_inventory_sha256"] == HELPER_SOURCE_SHA
                 and signed.get("protocol_descriptor") == PROTOCOL
                 and signed.get("callback_descriptor") == CALLBACK
                 and signed.get("all_compiled_members_unchanged") is True
                 and signed.get("all_inputs_unchanged") is True
                 and signed.get("resource_table_stored") is True
                 and type(signed.get("resource_table_data_offset_mod4")) is int
                 and signed["resource_table_data_offset_mod4"] == 0,
                 "actual helper6 protocol/source/permissions/layout missing")
        retained += [(Path(row["signed_result"]["path"]), signed_raw, signed_id),
                     (Path(row["apk"]["path"]), apk_raw, apk_id)]
        proof[role] = {"signed_result": row["signed_result"], "apk": row["apk"], "uid": row["uid"],
                       "version_code": version, "version_name": row["version_name"],
                       "source_inventory_sha256": row["source_inventory_sha256"], "signer_certificate_sha256": CERT}
    need(value["controller"]["uid"] != value["helper"]["uid"], "helper must have independent ordinary UID")
    return value, {"manifest_sha256": expected_sha, "roles": proof}, retained


def unchanged(retained):
    return all(exact(path, max(len(raw), 1), allow_empty=True) == (raw, identity)
               for path, raw, identity in retained)


def installed_matches(actual, role):
    need(actual["package"] == role["package"] and actual["uid"] == role["uid"]
         and len(actual["apks"]) == 1 and actual["apks"][0]["sha256"] == role["apk"]["sha256"],
         "current ordinary installed UID/APK differs from actual signed release")


def private_bytes(adb, package, relative, optional=False, maximum=16 << 20):
    """One read-only, length-framed original file read with before/after stat and SHA."""
    need(package in (MAIN, HELPER) and re.fullmatch(r"files/[A-Za-z0-9_./-]+", relative)
         and ".." not in relative.split("/") and type(maximum) is int and 0 < maximum <= 16 << 20,
         "fixed private-read scope")
    if package == HELPER:
        need(relative.startswith("files/web-evidence-v1/"), "helper reader is evidence-only")
    pieces = relative.split("/")
    paths = ["/".join(pieces[:i]) for i in range(1, len(pieces) + 1)]
    q = shlex.quote(relative)
    links = " || ".join("[ -L " + shlex.quote(p) + " ]" for p in paths)
    script = "\n".join((
        "if " + links + "; then exit 41; fi",
        "if [ ! -e " + q + " ]; then exit 40; fi",
        "if [ ! -f " + q + " ]; then exit 41; fi",
        "owner=$(id -u) || exit 42",
        "before=$(stat -c '%s %h %u %d %i %f %Y %Z' " + q + ") || exit 42",
        "set -- $before",
        "[ \"$#\" -eq 8 ] && [ \"$2\" = 1 ] && [ \"$3\" = \"$owner\" ] || exit 42",
        "case $1 in ''|*[!0-9]*) exit 42;; esac",
        "[ \"$1\" -le " + str(maximum) + " ] || exit 42",
        "before_hash=$(sha256sum " + q + ") || exit 42",
        "printf 'HEPTA_RAW_FILE_V1 %s\\n%s\\n' \"$before\" \"$before_hash\"",
        "head -c " + str(maximum + 1) + " " + q + " || exit 42",
        "after=$(stat -c '%s %h %u %d %i %f %Y %Z' " + q + ") || exit 42",
        "after_hash=$(sha256sum " + q + ") || exit 42",
        "printf '\\nHEPTA_RAW_FILE_END %s\\n%s\\n' \"$after\" \"$after_hash\"",
    ))
    code, framed = adb.command(["run-as", package, "sh", "-c", script], label="bounded-original-web-evidence",
                               allowed=(0, 40) if optional else (0,), raw=True)
    if code == 40:
        need(framed == b"", "absent private file returned bytes")
        return None
    need(len(framed) <= maximum + 4096, "private evidence framing exceeded budget")
    first_end = framed.find(b"\n")
    need(0 < first_end < 512, "private read stat frame missing")
    first = framed[:first_end].decode("ascii", errors="strict")
    match = re.fullmatch(r"HEPTA_RAW_FILE_V1 ([0-9]+) (1) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9a-fA-F]+) (-?[0-9]+) (-?[0-9]+)", first)
    need(match is not None and int(match.group(1)) <= maximum, "original private-file metadata differs")
    size = int(match.group(1))
    need(stat.S_ISREG(int(match.group(6), 16)), "private file mode is not regular")
    second_end = framed.find(b"\n", first_end + 1)
    need(first_end < second_end <= first_end + 1024, "private read hash frame missing")
    hash_line = framed[first_end + 1:second_end].decode("ascii", errors="strict")
    hashed = re.fullmatch(r"([0-9a-f]{64})[ \t]+" + re.escape(relative), hash_line)
    need(hashed is not None, "original private-file SHA line differs")
    body = framed[second_end + 1:second_end + 1 + size]
    ending = ("\nHEPTA_RAW_FILE_END " + first[len("HEPTA_RAW_FILE_V1 "):] + "\n" + hash_line + "\n").encode("ascii")
    need(len(body) == size and sha(body) == hashed.group(1)
         and framed[second_end + 1 + size:] == ending,
         "private-file original bytes or before/after identity changed")
    return body


def private_files(adb, package, relative, optional=False):
    need(package in (MAIN, HELPER) and re.fullmatch(r"files/[A-Za-z0-9_./-]+", relative)
         and ".." not in relative.split("/"), "fixed evidence directory")
    need((package == MAIN and (re.fullmatch(r"files/control-tasks/[0-9a-f]{32}", relative)
                              or re.fullmatch(r"files/runs/[0-9a-f]{32}", relative)))
         or (package == HELPER and relative == "files/web-evidence-v1"), "only task/run/helper evidence is enumerable")
    q = shlex.quote(relative)
    parents = ["/".join(relative.split("/")[:i]) for i in range(1, len(relative.split("/")) + 1)]
    links = " || ".join("[ -L " + shlex.quote(p) + " ]" for p in parents)
    script = ("if " + links + "; then exit 41; fi; if [ ! -e " + q + " ]; then exit 40; fi; "
              "if [ ! -d " + q + " ]; then exit 41; fi; "
              "links=$(find " + q + " -type l -print) || exit 42; [ -z \"$links\" ] || exit 41; "
              "find " + q + " -type f -print")
    code, raw = adb.command(["run-as", package, "sh", "-c", script], label="bounded-original-web-file-index",
                            allowed=(0, 40) if optional else (0,), raw=True)
    if code == 40:
        return []
    need(len(raw) <= 1 << 20, "bounded evidence filename index")
    rows = raw.decode("utf-8").splitlines()
    need(len(rows) <= 4096 and len(set(rows)) == len(rows), "bounded unique evidence file index")
    for row in rows:
        need(row.startswith(relative + "/") and re.fullmatch(r"files/[A-Za-z0-9_./-]+", row)
             and ".." not in row.split("/") and len(row.split("/")) <= 12, "unexpected private evidence filename")
    return sorted(rows)


def helper_idle(adb):
    raw = private_bytes(adb, HELPER, "files/web-evidence-v1/lease-journal.json", True, 65536)
    if raw is None:
        return {"journal_present": False, "formal_lease_recorded": False}
    value = strict(raw)
    need(value.get("schema") in ("hepta.web-helper.lease-journal.v2", JOURNAL_SCHEMA)
         and value.get("state") == "closed"
         and isinstance(value.get("cleanup"), dict) and set(value["cleanup"]) == CLEANUP_KEYS
         and all(value["cleanup"][k] is True for k in CLEANUP_KEYS),
         "helper original journal is not ordinary closed; explicit typed recovery is required")
    return {"journal_present": True, "journal_sha256": sha(raw), "state": value["state"],
            "cleanup": value["cleanup"], "raw": raw}


def collect_private_tree(adb, package, relative, out, budget, exclude=()):
    files = private_files(adb, package, relative)
    rows = []
    for name in files:
        if name in exclude:
            continue
        raw = private_bytes(adb, package, name)
        budget["files"] += 1
        budget["bytes"] += len(raw)
        need(budget["files"] <= 4096 and budget["bytes"] <= 128 << 20, "whole original collection budget exceeded")
        suffix = name[len(relative) + 1:]
        meta = write_new(out / suffix, raw)
        meta.update(package=package, device_path=name, relative_path=suffix)
        rows.append(meta)
    need(private_files(adb, package, relative) == files, "private file membership changed during collection")
    return rows


def runtime_identity(binding, role, installed):
    identity = binding[role + "_identity"]
    need(isinstance(identity, dict) and set(identity) == IDENTITY_KEYS, "exact runtime installed identity shape")
    need(identity["package"] == installed["package"] and type(identity["uid"]) is int
         and identity["uid"] == installed["uid"] and identity["signer_sha256"] == CERT,
         "runtime binding package/UID/signer differs")
    hashes = identity["apk_hashes"]
    need(isinstance(hashes, dict) and hashes == {"base": installed["apks"][0]["sha256"]}
         and identity["apk_set_sha256"] == sha("base\t" + installed["apks"][0]["sha256"] + "\n"),
         "runtime binding APK map/set differs from actual installed bytes")
    need(type(identity["version_code"]) is int and identity["version_code"] == (58 if role == "controller" else 6),
         "runtime peer version differs")


STORAGE_KEYS = frozenset(("schema", "library", "runtime_multi_profile", "runtime_delete_browsing_data",
    "profile_name", "profile_names_before", "profile_was_present_before", "profile_assigned_elapsed_ms",
    "webview_provider_package", "webview_provider_version", "webview_provider_version_code",
    "preload_clear", "first_load_dispatch_begin_elapsed_ms", "retirement_clear",
    "all_os_sockets_observed_closed", "whole_device_storage_erased", "business_verified", "first_url"))
PRELOAD_KEYS = frozenset(("started_elapsed_ms", "deadline_elapsed_ms", "initial_url", "callback_elapsed_ms",
    "callback_observed", "deadline_met", "cookies_present_after", "api"))
RETIRE_CLEAR_KEYS = frozenset(("started_elapsed_ms", "deadline_elapsed_ms", "callback_elapsed_ms",
    "callback_observed", "deadline_met", "cookies_present_after", "api", "attempt", "close_request_nonce", "actor"))
CALLBACK_KEYS = frozenset(("schema", "method", "request_nonce", "task_id", "controller_session_nonce",
    "status", "reason", "actual_helper_uid", "actual_display_id", "actual_window_id", "webview_instance",
    "navigation_epoch", "binding_sha256", "raw_length", "raw_sha256", "retired", "cleanup", "recovery"))
METHODS = {"attachLease": "hepta.web-helper.attach.v4", "captureEvidence": "hepta.web-helper.capture.v4",
           "closeLease": "hepta.web-helper.close.v4"}
COMMON_REQUEST = frozenset(("schema", "request_nonce", "task_id", "controller_session_nonce", "deadline_elapsed_ms"))
REQUEST_KEYS = {
    "attachLease": COMMON_REQUEST | {"owner", "owner_sha256", "contract_sha256", "authorization", "background",
                                     "controller_identity", "helper_identity"},
    "captureEvidence": COMMON_REQUEST | {"expected_webview_instance", "expected_navigation_epoch"},
    "closeLease": COMMON_REQUEST | {"reason"},
}
REQUEST_RECORD_KEYS = frozenset(("schema", "method", "request_json_utf8", "request_sha256",
    "binding_sha256", "before_remote_submission", "recorded_elapsed_ms"))
REPLY_RECORD_KEYS = frozenset(("schema", "method", "original_request_record_sha256", "callback_json_utf8",
    "callback_sha256", "callback_verification_passed", "binding_sha256", "raw_file", "raw_bytes",
    "raw_sha256", "recorded_elapsed_ms", "business_verified"))


def integer(value, message):
    need(type(value) is int and -(1 << 63) <= value < 1 << 63, message)
    return value


def require_storage_capture(binding, facts, started, ended):
    """Same recorded scalar/time predicates as the byte-identical v4 WebStorageEvidence source."""
    need(isinstance(facts, dict) and set(facts) == STORAGE_KEYS, "exact original capture storage fields required")
    profile = "hepta_v2_" + binding["controller_session_nonce"]
    need(binding["storage_profile_name"] == facts["profile_name"] == profile
         and facts["schema"] == "hepta.web-helper.storage-isolation.v1"
         and facts["library"] == "androidx.webkit:webkit:1.13.0"
         and facts["runtime_multi_profile"] is True and facts["runtime_delete_browsing_data"] is True,
         "same-profile actual storage feature provenance differs")
    need(facts["profile_was_present_before"] is False and facts["all_os_sockets_observed_closed"] is False
         and facts["whole_device_storage_erased"] is False and facts["business_verified"] is False,
         "storage proof overclaims scope or reuses a profile")
    names = facts["profile_names_before"]
    need(isinstance(names, list) and 0 < len(names) <= 128
         and all(isinstance(n, str) and len(n) <= 128 for n in names)
         and len(set(names)) == len(names) and profile not in names, "original fresh-profile enumeration differs")
    for key in ("webview_provider_package", "webview_provider_version"):
        need(isinstance(facts[key], str) and 0 < len(facts[key]) <= 200, "actual WebView provider missing")
    need(integer(facts["webview_provider_version_code"], "provider integer version") > 0, "provider version missing")
    clear = facts["preload_clear"]
    need(isinstance(clear, dict) and set(clear) == PRELOAD_KEYS
         and clear["api"] == "WebStorageCompat.deleteBrowsingData"
         and clear["callback_observed"] is True and clear["deadline_met"] is True
         and clear["cookies_present_after"] is False and clear["initial_url"] in (None, "", "about:blank"),
         "actual pre-load storage callback is incomplete")
    bg = binding["background"]
    created = integer(bg["created_elapsed_ms"], "lease creation time")
    expires = integer(bg["expires_elapsed_ms"], "lease expiry time")
    assigned = integer(facts["profile_assigned_elapsed_ms"], "profile assigned time")
    start = integer(clear["started_elapsed_ms"], "preload start")
    deadline = integer(clear["deadline_elapsed_ms"], "preload deadline")
    callback = integer(clear["callback_elapsed_ms"], "preload callback")
    dispatch = integer(facts["first_load_dispatch_begin_elapsed_ms"], "first load time")
    integer(started, "capture start"); integer(ended, "capture end")
    need(0 <= created <= assigned <= start <= callback <= dispatch <= deadline
         and start < deadline <= start + 3000 and dispatch <= started <= ended <= expires,
         "actual profile/clear/load/capture/lease order differs")
    need(facts["first_url"] == binding["initial_url"] and facts["retirement_clear"] is None,
         "capture storage facts are retired or from another initial page")
    return {"profile_name": profile, "preload_callback_elapsed_ms": callback,
            "capture_started_elapsed_ms": started, "capture_ended_elapsed_ms": ended,
            "actual_runtime_features_recorded": True}


def require_storage_closed(binding, original, facts, capture_ended, close_elapsed, requests):
    """Actual ProfileIsolation clear callback; does not claim profile deletion or OS socket closure."""
    need(isinstance(facts, dict) and set(facts) in (STORAGE_KEYS, STORAGE_KEYS | {"retirement_clear_history"}),
         "exact closed-profile storage fields required")
    for key in STORAGE_KEYS - {"retirement_clear"}:
        need(same_json(facts[key], original[key]), "original preload/provider/profile changed: " + key)
    clear = facts["retirement_clear"]
    need(isinstance(clear, dict) and set(clear) == RETIRE_CLEAR_KEYS
         and clear["api"] == "WebStorageCompat.deleteBrowsingData" and clear["callback_observed"] is True
         and clear["deadline_met"] is True and clear["cookies_present_after"] is False,
         "actual same-profile retirement callback incomplete")
    attempt = integer(clear["attempt"], "retirement attempt")
    need(1 <= attempt <= 129, "bounded actual retirement attempt required")
    history = facts.get("retirement_clear_history", [])
    need(isinstance(history, list) and len(history) == attempt - 1
         and len(history) <= 128 and all(isinstance(r, dict) for r in history),
         "retirement attempt history differs")
    start = integer(clear["started_elapsed_ms"], "retirement start")
    deadline = integer(clear["deadline_elapsed_ms"], "retirement deadline")
    callback = integer(clear["callback_elapsed_ms"], "retirement callback")
    integer(close_elapsed, "actual helper close record time")
    need(capture_ended <= start <= callback <= deadline <= start + 3000
         and start < deadline and callback <= close_elapsed, "actual retirement callback missed its own deadline")
    nonce = clear["close_request_nonce"]
    if nonce is None:
        need(clear["actor"] == "automatic_owned_retirement", "automatic close actor differs")
    else:
        need(isinstance(nonce, str) and HEX64.fullmatch(nonce) and nonce in requests
             and requests[nonce]["method"] == "closeLease"
             and clear["actor"] == "authenticated_controller_close", "clear was not authorized by this lease's original close")
        need(callback <= requests[nonce]["request"]["deadline_elapsed_ms"], "clear callback exceeded original close RPC")
    return {"profile_name": binding["storage_profile_name"], "retirement_attempt": attempt,
            "retirement_callback_elapsed_ms": callback, "retirement_deadline_elapsed_ms": deadline,
            "callback_within_deadline": True, "cookies_present_after": False,
            "profile_name_deleted": False, "all_os_sockets_observed_closed": False}



def require_flight_capture_v4(core, binding):
    """Replay the Flight-only full raw pair. This collector grants no page action."""
    keys = frozenset(("schema", "challenge", "binding", "helper_package", "helper_uid", "helper_pid",
        "display_id", "webview_instance", "actual_window_id", "webview_bounds_screen_pixels",
        "navigation_epoch", "committed_main_frame_url", "commit_elapsed_ms", "current_native_url",
        "native_url_source", "commit_source", "visual_request_id", "dom_raw_utf8", "dom_sha256",
        "observer_script_sha256", "started_elapsed_ms", "ended_elapsed_ms", "business_verified",
        "pixel_equality_claimed", "all_visible_semantics_verified", "truncated", "capture_geometry",
        "before_dom_raw_utf8", "before_dom_sha256", "dom_stability", "dom_stability_sha256",
        "raw_dom_equal", "comparison_scope", "observed_link_navigation"))
    need(type(core) is dict and set(core) == keys
         and core["schema"] == "hepta.owned-webview-origin-dom.v2"
         and binding["goal_kind"] == "csair_public_flight"
         and core["raw_dom_equal"] is True and core["comparison_scope"] == "full_raw_equality"
         and core["observed_link_navigation"] is None, "Flight requires the exact wire4 full raw scope")
    need(core["native_url_source"] == "android.webkit.WebView.getUrl"
         and core["commit_source"] == "android.webkit.WebViewClient.onPageCommitVisible"
         and core["observer_script_sha256"] == "05bb7c1e4e1929b961c42af1e5c0e01918bf6ff64f153132ca11c7d85873e705",
         "actual fixed observer/native URL provenance differs")
    need(all(core[k] is False for k in ("business_verified", "pixel_equality_claimed",
         "all_visible_semantics_verified", "truncated")), "wire4 capture scope differs")
    before, after = core["before_dom_raw_utf8"], core["dom_raw_utf8"]
    need(type(before) is str and type(after) is str and before == after
         and 0 < len(before.encode("utf-8")) <= 1 << 20
         and sha(before) == core["before_dom_sha256"] == core["dom_sha256"],
         "complete equal Flight DOM bytes and both hashes required")
    # The raw pair is identical. The exact full-scope proof contains only
    # integer counts, booleans, strings, nulls and path lists; the existing
    # binding canonicalizer is therefore also the exact DOM-proof encoder.
    dom = strict(after.encode("utf-8"))
    need(type(dom) is dict and dom["schema"] == "hepta.fixed-top-document-dom.v4"
         and dom["ready_state"] == "complete" and dom["truncated"] is False
         and dom["truncation_reasons"] == [] and dom["href"] == core["current_native_url"],
         "complete current wire4 DOM required")
    rows = dom["nodes"]
    need(type(rows) is list and 0 < len(rows) <= 1536
         and type(dom["visited"]) is int and dom["visited"] == len(rows), "complete wire4 DOM count")
    paths = []
    for row in rows:
        need(type(row) is dict and type(row.get("path")) is str
             and re.fullmatch(r"0(?:/[0-9]{1,5}){0,32}", row["path"])
             and row["path"] not in paths, "unique actual DOM path")
        path = row["path"]
        parent = path.rsplit("/", 1)[0] if "/" in path else None
        need("parent_path" in row and row["parent_path"] == parent, "actual DOM parent path differs")
        for key in ("tag", "id", "name", "role", "aria_label", "aria_hidden", "aria_modal",
                    "aria_selected", "aria_checked", "aria_pressed", "text", "item_type", "item_prop"):
            need(type(row.get(key)) is str and len(row[key].encode("utf-16-be")) // 2 <= 4096,
                 "bounded raw DOM string: " + key)
        for key in ("visible_in_viewport", "disabled", "hidden_attr", "inert_attr", "item_scope", "iframe_contents_read"):
            need(type(row.get(key)) is bool, "typed raw DOM flag: " + key)
        need(row["iframe_contents_read"] is False, "independent frame content is not observed")
        for key in ("href_raw", "href_resolved", "link_target", "value", "aria_disabled"):
            value = row[key]
            need(value is None or type(value) is str and len(value.encode("utf-16-be")) // 2 <= 4096,
                 "bounded nullable raw DOM string: " + key)
        rect = row["rect_css_pixels"]
        need(type(rect) is list and len(rect) == 4
             and all(type(v) in (int, float) and -100000000 <= v <= 100000000 for v in rect)
             and rect[0] <= rect[2] and rect[1] <= rect[3], "bounded original DOM rectangle")
        paths.append(path)
    need(all(p == "0" or p.rsplit("/", 1)[0] in paths for p in paths), "complete original DOM ancestry")
    proof = {"schema": "hepta.web-helper.dom-stability.v2", "dom_schema": "hepta.fixed-top-document-dom.v4",
        "site_policy_id": binding["site_policy_id"], "comparison_scope": "full_raw_equality", "raw_dom_equal": True,
        "before_dom_sha256": sha(before), "after_dom_sha256": sha(after),
        "before_dom_utf8_bytes": len(before.encode("utf-8")), "after_dom_utf8_bytes": len(after.encode("utf-8")),
        "both_complete_raw_dom_values_retained": True, "all_json_differences": [], "all_difference_count": 0,
        "outside_changed_rectangles": [], "region": None, "region_unavailable_reason": None,
        "target_predicate": "actual_dom_membership_for_full_raw", "eligible_action_dom_paths": paths,
        "eligible_paths_are_not_independent_action_authority": True, "scope_selected_by_compiled_task_policy": True,
        "caller_supplied_selector_allowed": False, "whole_page_raw_equal": True, "outside_visibility_inferred": False,
        "closed_shadow_contents_inspected": False, "whole_page_pixel_visibility_verified": False,
        "grants_action_authority": False, "business_verified": False}
    need(same_json(core["dom_stability"], proof) and len(canonical(proof).encode("utf-8")) <= 256 << 10
         and sha(canonical(proof)) == core["dom_stability_sha256"], "complete Flight stability proof differs")
    geometry = core["capture_geometry"]
    need(type(geometry) is dict and set(geometry) == {"schema", "samples", "native_samples_equal",
         "dom_equal_across_visual_callback", "dom_comparison_scope", "dom_stability_sha256", "ui_thread_bracket",
         "get_scale_is_deprecated_racy_observation", "css_to_screen_mapping_verified"}
         and geometry["schema"] == "hepta.webview-geometry-bracket.v2"
         and geometry["dom_equal_across_visual_callback"] is True
         and geometry["dom_comparison_scope"] == "full_raw_equality"
         and geometry["dom_stability_sha256"] == core["dom_stability_sha256"]
         and all(geometry[k] is True for k in ("native_samples_equal", "ui_thread_bracket",
                                               "get_scale_is_deprecated_racy_observation"))
         and geometry["css_to_screen_mapping_verified"] is False, "wire4 geometry/scope association differs")
    samples = geometry["samples"]
    phases = ("before_js1", "after_js1", "before_js2", "after_js2")
    need(type(samples) is list and len(samples) == 4, "four original native samples required")
    started = integer(core["started_elapsed_ms"], "capture start")
    ended = integer(core["ended_elapsed_ms"], "capture end")
    committed = integer(core["commit_elapsed_ms"], "page commit")
    need(binding["background"]["created_elapsed_ms"] <= committed <= started <= ended
         and ended - started <= 3000 and ended < binding["background"]["expires_elapsed_ms"],
         "commit/capture/lease bracket differs")
    previous = started
    for sample, phase in zip(samples, phases):
        need(type(sample) is dict and set(sample) == {"phase", "native"} and sample["phase"] == phase,
             "original native sample phase differs")
        native = sample["native"]
        need(type(native) is dict and native["display_id"] == core["display_id"]
             and native["actual_window_id"] == core["actual_window_id"]
             and native["bounds_screen_pixels"] == core["webview_bounds_screen_pixels"],
             "original native sample tuple differs")
        at = integer(native["sampled_elapsed_ms"], "native sample time")
        need(previous <= at <= ended, "original native sample bracket differs")
        previous = at
    return {"schema": "hepta.v58-flight-full-raw-pair-links.v1", "dom_schema": dom["schema"],
            "comparison_scope": "full_raw_equality", "raw_dom_equal": True,
            "before_dom_sha256": sha(before), "after_dom_sha256": sha(after),
            "dom_utf8_bytes": len(after.encode("utf-8")), "node_count": len(rows),
            "current_native_url": core["current_native_url"], "dom_stability_sha256": core["dom_stability_sha256"],
            "full_native_geometry_replayed_by_this_collector": False,
            "native_geometry_reference": "original verified main58 callback and retained four native samples",
            "grants_action_authority": False, "business_verified": False}


def original_capture_fd_index(directory, task):
    """Index retained exact FD bytes even when later semantic/cleanup validation fails."""
    web = directory / "task" / "web-helper"
    result = {"schema": "hepta.v58-original-capture-fd-index.v1", "task_id": task, "files": [],
              "index_is_capture_or_business_verdict": False, "business_verified": False}
    if not web.exists():
        result["web_journal_present"] = False
        return result
    result["web_journal_present"] = True
    paths = sorted(web.glob("raw-*.json"))
    need(len(paths) <= 1024, "bounded original FD index")
    for path in paths:
        raw = exact(path, 4 << 20)[0]
        row = {"relative_path": "task/web-helper/" + path.name, "bytes": len(raw), "sha256": sha(raw),
               "raw_original_retained": True, "independent_capture_validation_by_this_index": False,
               "business_verified": False}
        result["files"].append(row)
        try:
            match = re.fullmatch(r"raw-([0-9a-f]{64})\.json", path.name)
            need(match is not None, "raw FD filename shape")
            nonce = match.group(1)
            request_raw = exact(web / ("request-" + nonce + ".json"), 65536)[0]
            reply_raw = exact(web / ("reply-" + nonce + ".json"), 65536)[0]
            request, reply = strict(request_raw), strict(reply_raw)
            callback_raw = reply["callback_json_utf8"]
            need(type(callback_raw) is str and sha(callback_raw) == reply["callback_sha256"]
                 and reply["original_request_record_sha256"] == sha(request_raw)
                 and reply["raw_file"] == path.name and reply["raw_bytes"] == len(raw)
                 and reply["raw_sha256"] == sha(raw), "original FD/request/reply links differ")
            callback = strict(callback_raw.encode("utf-8"))
            need(callback["request_nonce"] == nonce and callback["task_id"] == task
                 and callback["raw_length"] == len(raw) and callback["raw_sha256"] == sha(raw)
                 and callback["method"] == request["method"] == reply["method"], "original callback links differ")
            row.update(request_nonce=nonce, method=request["method"], callback_status=callback["status"],
                       callback_verification_passed_as_recorded=reply["callback_verification_passed"],
                       request_record_sha256=sha(request_raw), reply_record_sha256=sha(reply_raw))
            value = strict(raw)
            row["raw_schema"] = value.get("schema")
            core = value.get("capture")
            if request["method"] == "captureEvidence" and type(core) is dict:
                row.update(capture_schema=core.get("schema"), challenge_as_recorded=core.get("challenge"),
                           current_native_url_as_recorded=core.get("current_native_url"),
                           comparison_scope_as_recorded=core.get("comparison_scope"),
                           raw_dom_equal_as_recorded=core.get("raw_dom_equal"),
                           webview_instance_as_recorded=core.get("webview_instance"),
                           navigation_epoch_as_recorded=core.get("navigation_epoch"))
                row["dom_fields"] = []
                for field, hash_field in (("before_dom_raw_utf8", "before_dom_sha256"), ("dom_raw_utf8", "dom_sha256")):
                    text = core.get(field)
                    need(type(text) is str and 0 < len(text.encode("utf-8")) <= 1 << 20,
                         "bounded complete embedded original DOM")
                    row["dom_fields"].append({"json_pointer": "/capture/" + field,
                        "bytes": len(text.encode("utf-8")), "sha256": sha(text),
                        "declared_sha256": core.get(hash_field), "declared_hash_matches": core.get(hash_field) == sha(text)})
        except Exception as error:
            row["interpretation_error"] = type(error).__name__ + ": " + str(error)
    result["raw_fd_file_count"] = len(result["files"])
    result["capture_method_file_count"] = sum(row.get("method") == "captureEvidence" for row in result["files"])
    return result


def original_web_summary(directory, task, plan, installed, helper_journal_raw, marker_absent):
    """Validate original journal links. This is not a business or SDK verifier."""
    web = directory / "task" / "web-helper"
    result = {"schema": "hepta.v58-original-web-lifecycle-links.v1", "task_id": task,
              "bound_capture_present": False, "ordinary_close_verified": False,
              "business_verified": False, "sdk_teardown_verified": False, "missing": []}
    if not (web / "BINDING.json").exists():
        result["missing"].append("original_Binding_missing")
        return result
    raw = exact(web / "BINDING.json", 16384)[0]
    binding = strict(raw)
    need(set(binding) == BINDING_KEYS and binding["schema"] == BINDING_SCHEMA
         and binding["task_id"] == task and binding["owner"] == plan["instruction"]
         and binding["owner_sha256"] == plan["instruction_sha256"] and binding["goal_kind"] == plan["goal_kind"],
         "original task OWNER/binding differs")
    binding_sha = sha(canonical(binding))
    runtime_identity(binding, "controller", installed["hepta"])
    runtime_identity(binding, "helper", installed["helper"])
    bg = binding["background"]
    need(type(bg["display_id"]) is int and bg["display_id"] > 0
         and bg["selected_packages"] == [HELPER] and isinstance(bg["generation"], str) and UUID.fullmatch(bg["generation"]),
         "original helper-only positive display lease differs")
    profile = binding["storage_profile_name"]
    need(isinstance(binding["controller_session_nonce"], str) and HEX64.fullmatch(binding["controller_session_nonce"])
         and profile == "hepta_v2_" + binding["controller_session_nonce"],
         "exact immutable per-lease storage profile required")
    result.update(binding_sha256=binding_sha, controller_session_nonce=binding["controller_session_nonce"],
                  profile_name=profile, generation=bg["generation"], display_id=bg["display_id"])
    captured, closed, requests, capture_facts = [], [], {}, []
    request_rows = list(web.glob("request-*.json"))
    need(len(request_rows) <= 1024, "bounded actual request journal")
    for request_path in request_rows:
        match = re.fullmatch(r"request-([0-9a-f]{64})\.json", request_path.name)
        need(match is not None, "original request filename shape")
        nonce = match.group(1)
        record_raw = exact(request_path, 65536)[0]
        record = strict(record_raw)
        need(set(record) == REQUEST_RECORD_KEYS and record["schema"] == "hepta.web-controller-request.v1"
             and record["before_remote_submission"] is True
             and record["binding_sha256"] == binding_sha, "original request-record binding differs")
        request_text = record["request_json_utf8"]
        need(isinstance(request_text, str) and 0 < len(request_text.encode("utf-8")) <= 16384
             and sha(request_text) == record["request_sha256"], "original request bytes/hash differ")
        request = strict(request_text.encode("utf-8"))
        method = record["method"]
        need(method in METHODS and set(request) == REQUEST_KEYS[method] and request["schema"] == METHODS[method]
             and request["task_id"] == task and request["controller_session_nonce"] == binding["controller_session_nonce"]
             and request["request_nonce"] == nonce, "original request tuple differs")
        if method == "attachLease":
            for key in REQUEST_KEYS["attachLease"] - COMMON_REQUEST:
                need(same_json(request[key], binding[key]), "original attach differs from immutable binding: " + key)
        sent = integer(record["recorded_elapsed_ms"], "request journal time")
        deadline = integer(request["deadline_elapsed_ms"], "request deadline")
        need(0 <= sent < deadline <= sent + 10000, "original request deadline bracket differs")
        requests[nonce] = {"method": method, "request": request, "sent_elapsed_ms": sent,
                           "record_raw_sha256": sha(record_raw)}
    for path in sorted(web.glob("reply-*.json")):
        match = re.fullmatch(r"reply-([0-9a-f]{64})\.json", path.name)
        need(match is not None, "reply filename shape")
        nonce = match.group(1)
        reply_raw = exact(path, 65536)[0]
        reply = strict(reply_raw)
        request_raw = exact(web / ("request-" + nonce + ".json"), 65536)[0]
        request_record = strict(request_raw)
        need(set(request_record) == REQUEST_RECORD_KEYS and set(reply) == REPLY_RECORD_KEYS
             and request_record["schema"] == "hepta.web-controller-request.v1"
             and reply["business_verified"] is False and type(reply["callback_verification_passed"]) is bool
             and request_record["before_remote_submission"] is True
             and reply["schema"] == "hepta.web-controller-reply.v1"
             and reply["original_request_record_sha256"] == sha(request_raw)
             and reply["binding_sha256"] == binding_sha
             and request_record["binding_sha256"] == binding_sha, "original RPC record chain differs")
        request_text = request_record["request_json_utf8"]
        cb_text = reply["callback_json_utf8"]
        need(isinstance(request_text, str) and isinstance(cb_text, str)
             and 0 < len(request_text.encode("utf-8")) <= 16384 and 0 < len(cb_text.encode("utf-8")) <= 16384
             and sha(request_text) == request_record["request_sha256"] and sha(cb_text) == reply["callback_sha256"],
             "original request/callback raw hash differs")
        request, cb = strict(request_text.encode()), strict(cb_text.encode())
        method = request_record["method"]
        need(method in METHODS and set(request) == REQUEST_KEYS[method] and request["schema"] == METHODS[method]
             and reply["method"] == cb["method"] == method and set(cb) == CALLBACK_KEYS,
             "exact original RPC schema/method differs")
        sent = integer(request_record["recorded_elapsed_ms"], "original request journal time")
        received = integer(reply["recorded_elapsed_ms"], "original reply journal time")
        deadline = integer(request["deadline_elapsed_ms"], "original request deadline")
        need(0 <= sent < deadline <= sent + 10000 and received >= sent, "original RPC time bracket differs")
        need(nonce in requests and requests[nonce]["method"] == method
             and same_json(requests[nonce]["request"], request)
             and requests[nonce]["record_raw_sha256"] == sha(request_raw), "original request index changed")
        requests[nonce]["recorded_reply_elapsed_ms"] = received
        for row in (request, cb):
            need(row["task_id"] == task and row["controller_session_nonce"] == binding["controller_session_nonce"]
                 and row["request_nonce"] == nonce, "original RPC tuple differs")
        need(cb["schema"] == CALLBACK_SCHEMA and cb["binding_sha256"] == binding_sha
             and type(cb["actual_helper_uid"]) is int and cb["actual_helper_uid"] == installed["helper"]["uid"]
             and type(cb["actual_display_id"]) is int and cb["actual_display_id"] == bg["display_id"],
             "original callback peer/display binding differs")
        if reply["callback_verification_passed"] is not True:
            continue
        need(received <= deadline, "verified reply journal completed after its original RPC deadline")
        if cb["status"] in ("captured", "closed"):
            need(type(cb["actual_window_id"]) is int and cb["actual_window_id"] >= 0
                 and isinstance(cb["webview_instance"], str) and UUID.fullmatch(cb["webview_instance"])
                 and type(cb["navigation_epoch"]) is int and cb["navigation_epoch"] >= 0
                 and type(cb["raw_length"]) is int, "typed callback window/instance/epoch/length required")
        if cb["status"] == "captured":
            need(method == "captureEvidence" and cb["retired"] is False
                 and cb["cleanup"] is None and cb["recovery"] is None,
                 "captured is not a current read-only capture reply")
            name = "raw-" + nonce + ".json"
            need(reply["raw_file"] == name and type(reply["raw_bytes"]) is int and 0 < reply["raw_bytes"] <= 4 << 20,
                 "original read-only FD reference missing")
            fd_raw = exact(web / name, 4 << 20)[0]
            need(len(fd_raw) == reply["raw_bytes"] == cb["raw_length"]
                 and sha(fd_raw) == reply["raw_sha256"] == cb["raw_sha256"], "original FD bytes/hash differ")
            capture = strict(fd_raw)
            need(capture["schema"] == RAW_SCHEMA and capture["binding_sha256"] == binding_sha
                 and same_json(capture["binding"], binding), "original capture binding differs")
            need(capture["request_json_utf8"] == request_text and capture["request_sha256"] == sha(request_text)
                 and same_json(capture["controller_identity"], binding["controller_identity"])
                 and same_json(capture["helper_identity"], binding["helper_identity"])
                 and capture["actor"] == "controller_evidence_capture" and capture["diagnostic_unbound"] is False
                 and capture["business_verified"] is False, "raw FD is not this authenticated request")
            core = capture["capture"]
            need(core["schema"] == "hepta.owned-webview-origin-dom.v2" and same_json(core["binding"], binding)
                 and core["challenge"] == nonce and core["helper_package"] == HELPER
                 and type(core["helper_uid"]) is int and core["helper_uid"] == installed["helper"]["uid"]
                 and type(core["display_id"]) is int and core["display_id"] == bg["display_id"]
                 and type(core["actual_window_id"]) is int and core["actual_window_id"] >= 0
                 and core["actual_window_id"] == cb["actual_window_id"] == capture["actual_window_id"]
                 and isinstance(core["webview_instance"], str) and UUID.fullmatch(core["webview_instance"])
                 and core["webview_instance"] == cb["webview_instance"]
                 and type(core["navigation_epoch"]) is int and core["navigation_epoch"] == cb["navigation_epoch"]
                 and type(core["helper_pid"]) is int and core["helper_pid"] > 0
                 and core["business_verified"] is False, "original core capture tuple differs")
            expected_instance, expected_epoch = request["expected_webview_instance"], request["expected_navigation_epoch"]
            need((expected_instance is None and expected_epoch is None)
                 or (isinstance(expected_instance, str) and expected_instance == core["webview_instance"]
                     and type(expected_epoch) is int and expected_epoch == core["navigation_epoch"]),
                 "original capture did not meet its exact navigation expectation")
            pair = require_flight_capture_v4(core, binding)
            storage = require_storage_capture(binding, capture["storage_isolation"],
                                              core["started_elapsed_ms"], core["ended_elapsed_ms"])
            need(sent <= core["started_elapsed_ms"] <= core["ended_elapsed_ms"] <= deadline,
                 "capture exceeded original RPC bracket")
            capture_facts.append({"storage": capture["storage_isolation"], "ended": core["ended_elapsed_ms"],
                                  "helper_pid": core["helper_pid"], "window_id": core["actual_window_id"],
                                  "webview_instance": core["webview_instance"], "navigation_epoch": core["navigation_epoch"]})
            captured.append({"nonce": nonce, "raw_sha256": sha(fd_raw), "raw_bytes": len(fd_raw),
                             "actual_window_id": core["actual_window_id"], "webview_instance": core["webview_instance"],
                             "navigation_epoch": core["navigation_epoch"], "storage": storage,
                             "raw_file": "task/web-helper/" + name, "flight_raw_pair": pair,
                             "raw_dom_json_pointers": ["/capture/before_dom_raw_utf8", "/capture/dom_raw_utf8"]})
        if cb["status"] == "closed":
            need(cb["method"] == "closeLease" and cb["retired"] is True
                 and cb["raw_length"] == 0 and type(cb["raw_length"]) is int
                 and cb["raw_sha256"] is None and reply["raw_file"] is None
                 and type(reply["raw_bytes"]) is int and reply["raw_bytes"] == 0
                 and reply["raw_sha256"] is None and cb["recovery"] is None
                 and isinstance(cb["cleanup"], dict) and set(cb["cleanup"]) == CLEANUP_KEYS
                 and all(cb["cleanup"][k] is True for k in CLEANUP_KEYS), "ordinary close requires actual five-method proof")
            closed.append((nonce, reply_raw, cb))
    result["captures"] = captured
    result["bound_capture_present"] = bool(captured)
    result["close_replies"] = len(closed)
    for path in sorted(web.glob("cleanup-*.json")):
        need(re.fullmatch(r"cleanup-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.json", path.name),
             "original cleanup filename shape")
        cleanup = strict(exact(path, 65536)[0])
        if cleanup.get("no_attach_request_prepared") is True:
            continue
        need(cleanup["schema"] == "hepta.web-controller-cleanup.v1" and cleanup["task_id"] == task
             and cleanup["binding_sha256"] == binding_sha, "cleanup record belongs to another lease")
        for nonce, reply_raw, cb in closed:
            if cleanup.get("request_nonce") != nonce:
                continue
            need(cleanup["retirement_verified"] is True and cleanup["recovered_retirement"] is False
                 and cleanup["unstarted_retirement"] is False and cleanup["old_cleanup_methods_upgraded"] is False
                 and cleanup["reply_file"] == "reply-" + nonce + ".json"
                 and cleanup["reply_sha256"] == sha(reply_raw), "ordinary cleanup-to-reply chain differs")
            need(helper_journal_raw is not None, "actual helper journal missing after ordinary close")
            helper = strict(helper_journal_raw)
            need(helper["schema"] == JOURNAL_SCHEMA and helper["state"] == "closed"
                 and helper["binding_sha256"] == binding_sha and same_json(helper["binding"], binding)
                 and same_json(helper["cleanup"], cb["cleanup"]) and marker_absent,
                 "actual helper journal/client marker do not confirm this same closed lease")
            need(capture_facts, "ordinary two-lease readiness requires an original bound capture")
            last_capture = max(capture_facts, key=lambda row: row["ended"])
            original_storage, capture_ended = last_capture["storage"], last_capture["ended"]
            need(type(helper["helper_pid"]) is int and helper["helper_pid"] == last_capture["helper_pid"]
                 and type(helper["window_id"]) is int and helper["window_id"] == cb["actual_window_id"] == last_capture["window_id"]
                 and helper["webview_instance"] == cb["webview_instance"] == last_capture["webview_instance"]
                 and type(helper["navigation_epoch"]) is int
                 and helper["navigation_epoch"] == cb["navigation_epoch"] >= last_capture["navigation_epoch"],
                 "closed helper journal does not preserve this captured native view identity")
            completed = integer(cleanup["completed_elapsed_ms"], "controller cleanup record time")
            close_received = requests[nonce]["recorded_reply_elapsed_ms"]
            need(completed >= close_received, "controller cleanup predates its original verified reply")
            close_matches, incomplete_originals = [], []
            for close_path in sorted((directory / "helper").glob("close-*.json")):
                need(re.fullmatch(r"close-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.json", close_path.name),
                     "original helper close filename shape")
                close_raw = exact(close_path, 2 << 20)[0]
                close = strict(close_raw)
                if close.get("schema") != "hepta.web-helper.close-evidence.v2" or close.get("binding_sha256") != binding_sha:
                    continue
                need(same_json(close.get("binding"), binding)
                     and close.get("os_socket_closure_verified") is False and close.get("business_verified") is False,
                     "helper close record overclaims or belongs to another lease")
                # retire() always writes its initial incomplete record before the real asynchronous clear.
                # Preserve it unchanged; only the later record matching the current closed journal supplies proof.
                if not same_json(close.get("cleanup"), cb["cleanup"]) or not same_json(
                        close.get("storage_isolation"), helper["storage_isolation"]):
                    incomplete_originals.append({"file": close_path.name, "bytes": len(close_raw),
                        "sha256": sha(close_raw), "used_as_completed_cleanup": False})
                    continue
                need(type(close["helper_pid"]) is int and close["helper_pid"] == helper["helper_pid"],
                     "helper close process differs from its own journal/capture")
                storage_proof = require_storage_closed(binding, original_storage, close["storage_isolation"],
                            capture_ended, close["elapsed_ms"], requests)
                need(close["elapsed_ms"] <= close_received <= completed,
                     "helper close record was not complete before the original closed reply and controller cleanup")
                close_matches.append({"file": close_path.name, "bytes": len(close_raw), "sha256": sha(close_raw),
                                      "storage": storage_proof})
            need(close_matches, "original same-profile helper storage callback record missing")
            result["ordinary_close_verified"] = True
            result["helper_close_records"] = close_matches
            result["preserved_incomplete_or_prior_clear_records"] = incomplete_originals
            result["cleanup_receipt_sha256"] = sha(exact(path, 65536)[0])
    if not captured:
        result["missing"].append("original_bound_capture_missing")
    if not result["ordinary_close_verified"]:
        result["missing"].append("same_profile_ordinary_close_or_marker_absence_missing")
    return result
