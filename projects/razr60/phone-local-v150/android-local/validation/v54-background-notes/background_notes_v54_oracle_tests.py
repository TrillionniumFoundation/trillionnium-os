#!/usr/bin/env python3
"""Offline adversarial checks of the dedicated Notes receipt replay oracle.

The positive input is an unmodified artifact produced by the actual v54 Java
controller with explicitly synthetic Android/native IO in strict-host CI.
Neither a passing fixture nor this test runner qualifies a phone or accelerator.
This runner never calls the harness monitor/main, ADB, an H host, or a network.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from unittest import mock


DEFAULT_CI_EVIDENCE_ROOT = Path(__file__).parent / "pr144-ci-evidence/strict-host-824d73ed"
POSITIVE_RELATIVE = "task-completion/notes-workflow-controller/scope-11366832051851667132/control-tasks/0c9bc919a576415fb2e7126a4f38c923"
LEGACY_POSITIVE_RELATIVE = "task-completion/notes-workflow-controller/scope-16055968249549152253/control-tasks/3720f75594d14c848ddeee7d630bb7da"
CI_ARTIFACT_SHA256 = "334cc14b2db745354e073360ed9321ed2e25940b7823c38142e0c57d6dea37a2"
WORKFLOW = "step-01-notes-workflow-result.json"
GRANT = "step-01-notes-workflow-grant-consumed.json"
PARENT = "step-01-action.json"
MODEL = "step-01-model-0.json"
ATTEMPT = "fixed-intent-01-attempt.json"
ZERO_SHA = "0" * 64
OTHER_ID = "f" * 32
OTHER_GENERATION = "ffffffff-ffff-ffff-ffff-ffffffffffff"
NOTES_PACKAGE = "com.motorola.stylus"
OBSERVED_NOTES_APK = "0e1a52a937c04ec8df380bff3750ce4b345fa0d8d33683e5ae8aa08e70e94017"
CHILD_TEXT_SOURCE = "visible_noninteractive_descendants.v2"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def fixture_manifest(directory):
    return [{"name": p.name, "bytes": p.stat().st_size, "sha256": sha(p.read_bytes())}
            for p in sorted(directory.iterdir()) if p.is_file()]


def utf16_count(value):
    return len(value.encode("utf-16-be")) // 2


def observed_label_projection(value):
    raw = value.encode("utf-16-be")
    if len(raw) <= 72:
        return value
    end = 72
    if 0xD800 <= int.from_bytes(raw[end - 2:end], "big") <= 0xDBFF:
        end -= 2
    return raw[:end].decode("utf-16-be") + "…"


def owner_body(directory):
    owner = read(directory / "owner.json")
    contract = owner["completion_contract"]
    raw = owner["instruction"].encode("utf-16-be")
    return raw[2 * contract["body_source_start_utf16"]:2 * contract["body_source_end_utf16"]].decode("utf-16-be")


def visit_dicts(value, transform):
    if isinstance(value, dict):
        transform(value)
        for child in tuple(value.values()):
            visit_dicts(child, transform)
    elif isinstance(value, list):
        for child in value:
            visit_dicts(child, transform)


def rewrite_records(directory, transform):
    for path in directory.glob("*.json"):
        record = read(path)
        visit_dicts(record, transform)
        write(path, record)


def rebind_child_text(node):
    """Independent encoding from ObservedChildText.java SOURCE/fingerprint/bind.

    These are explicit synthetic source identities. A matching hash is not a
    claim that any descendant was observed on a physical Android display.
    """
    field = lambda value: str(utf16_count(value)) + ":" + value
    root = node["child_text_root_signature"]
    parts = [CHILD_TEXT_SOURCE, node["child_text_status"], node["child_text"],
             str(node["child_text_truncated"]).lower(), root,
             str(node["child_text_sources_complete"]).lower()]
    for source in node["child_text_sources"]:
        parts.extend(source[key] for key in ("descendant_path", "property", "text_sha256", "node_signature", "view_id"))
    fingerprint = sha("".join(field(value) for value in parts).encode("utf-8"))
    node["node_app_tree_sha256"] = sha((field(root) + field(fingerprint)).encode("utf-8"))


def synthetic_forty_lf(directory, inputs):
    """Construct an allowed serialized branch; never an original phone sample."""
    body = owner_body(directory)
    raw_body = body + "\n" * 40
    body_sha = sha(body.encode("utf-8"))
    raw_sha = sha(raw_body.encode("utf-8"))
    old_apks = copy.deepcopy(inputs["installed"]["apk_hashes"])
    new_apks = {"base": OBSERVED_NOTES_APK}
    inputs["installed"]["apk_hashes"] = copy.deepcopy(new_apks)
    state_map, tree_map = {}, {}
    for path in directory.glob("*.json"):
        record = read(path)
        if "nodes" in record and any(n.get("editable") is True and n.get("text") == body for n in record["nodes"]):
            state = record["observation_state_sha256"]
            tree = record["app_tree_sha256"]
            state_map[state] = sha(("synthetic-40lf-state|" + state).encode())
            tree_map[tree] = sha(("synthetic-40lf-tree|" + tree).encode())
    def transform(record):
        for key in ("apk_hashes", "target_apk_sha256"):
            if record.get(key) == old_apks:
                record[key] = copy.deepcopy(new_apks)
        if "apk_set_sha256" in record and record.get("apk_hashes") == new_apks:
            record["apk_set_sha256"] = sha(("base\t" + OBSERVED_NOTES_APK + "\n").encode())
        if record.get("editable") is True and record.get("text") == body:
            record["text"] = raw_body
            record["input_text_sha256"] = raw_sha
        if record.get("body_sha256") == body_sha and "raw_exact" in record and "raw_text_sha256" in record:
            record.update(raw_exact=False, raw_text_sha256=raw_sha, trailing_lf_count=40,
                          action_label=observed_label_projection(raw_body), match_rule="body_plus_observed_40_lf")
        if "current_editor_raw_exact" in record:
            record["current_editor_raw_exact"] = False
        if "body_raw_exact" in record:
            record["body_raw_exact"] = False
        for key in ("observation_state_sha256", "tree_sha256"):
            if record.get(key) in state_map:
                record[key] = state_map[record[key]]
        if record.get("app_tree_sha256") in tree_map:
            record["app_tree_sha256"] = tree_map[record["app_tree_sha256"]]
    rewrite_records(directory, transform)


def synthetic_derived_summary(directory, inputs):
    """Replace the real-method fixture's own-text item with typed synthetic provenance."""
    body = owner_body(directory)
    source_observation = read(directory / "step-01-tool-child-02-before.json")
    target = source_observation["observation_id"]
    old_state, old_tree = source_observation["observation_state_sha256"], source_observation["app_tree_sha256"]
    new_state = sha(("synthetic-derived-state|" + old_state).encode())
    new_tree = sha(("synthetic-derived-tree|" + old_tree).encode())
    source = {"descendant_path": "0", "property": "text", "text_sha256": sha(body.encode("utf-8")),
              "node_signature": sha(b"synthetic-note-summary-node"), "view_id": NOTES_PACKAGE + ":id/note_summary"}
    sample_item = None
    def transform(record):
        nonlocal sample_item
        if record.get("observation_id") == target and "nodes" in record:
            item = next(n for n in record["nodes"] if n.get("clickable") is True and n.get("text") == body)
            item.update(text="", view_id=NOTES_PACKAGE + ":id/note_item_content", child_text=body,
                        child_text_source=CHILD_TEXT_SOURCE, child_text_status="derived", child_text_truncated=False,
                        child_text_sources_complete=True, child_text_visited=1,
                        child_text_root_signature=sha(b"synthetic-note-item-root"), child_text_sources=[copy.deepcopy(source)])
            rebind_child_text(item)
            sample_item = copy.deepcopy(item)
        if record.get("observation_id") == target:
            if "observation_state_sha256" in record:
                record["observation_state_sha256"] = new_state
            if "tree_sha256" in record:
                record["tree_sha256"] = new_state
            if "app_tree_sha256" in record:
                record["app_tree_sha256"] = new_tree
    rewrite_records(directory, transform)
    if sample_item is None:
        raise AssertionError("fixture lacks the expected complete list item")
    def summaries(record):
        if record.get("match_rule") == "exact_own_text" and record.get("node_id") == sample_item["id"]:
            record.update(match_rule="bound_note_summary_accessibility_text", source_path="0",
                          source_view_id=source["view_id"], source_text_sha256=source["text_sha256"],
                          node_app_tree_sha256=sample_item["node_app_tree_sha256"])
    rewrite_records(directory, summaries)


def synthetic_forty_lf_other_apk(directory, inputs):
    synthetic_forty_lf(directory, inputs)
    old_apks = copy.deepcopy(inputs["installed"]["apk_hashes"])
    wrong_apks = {"base": ZERO_SHA}
    inputs["installed"]["apk_hashes"] = copy.deepcopy(wrong_apks)
    def transform(record):
        for key in ("apk_hashes", "target_apk_sha256"):
            if record.get(key) == old_apks:
                record[key] = copy.deepcopy(wrong_apks)
        if "apk_set_sha256" in record and record.get("apk_hashes") == wrong_apks:
            record["apk_set_sha256"] = sha(("base\t" + ZERO_SHA + "\n").encode())
    rewrite_records(directory, transform)


def compose(*mutations):
    def mutate(directory, inputs):
        for mutation in mutations:
            mutation(directory, inputs)
    return mutate


def mutate_derived(edit, rebind=True):
    def mutate(directory, inputs):
        synthetic_derived_summary(directory, inputs)
        def transform(record):
            if record.get("view_id") == NOTES_PACKAGE + ":id/note_item_content" and record.get("child_text_status") == "derived":
                edit(record)
                if rebind:
                    rebind_child_text(record)
        rewrite_records(directory, transform)
    return mutate


def set_field(name, keys, value):
    def mutate(directory, inputs):
        path = directory / name
        record = read(path)
        cursor = record
        for key in keys[:-1]:
            cursor = cursor[key]
        cursor[keys[-1]] = copy.deepcopy(value)
        write(path, record)
    return mutate


def alter_json(name, edit):
    def mutate(directory, inputs):
        path = directory / name
        record = read(path)
        edit(record)
        write(path, record)
    return mutate


def remove_file(name):
    def mutate(directory, inputs):
        (directory / name).unlink()
    return mutate


def malformed_file(name, payload):
    def mutate(directory, inputs):
        (directory / name).write_bytes(payload)
    return mutate


def alter_observation(source_name, edit):
    """Change every full copy of one observation, preserving copy consistency.

    This prevents a semantic test from passing only because two saved copies of
    the same observation differ. Mini-summary bindings are intentionally left
    intact for body/list changes, which cannot be certified by a boolean flag.
    """
    def mutate(directory, inputs):
        observation_id = read(directory / source_name)["observation_id"]
        count = 0
        for path in directory.glob("*.json"):
            record = read(path)
            if isinstance(record, dict) and record.get("observation_id") == observation_id and "nodes" in record:
                edit(record)
                write(path, record)
                count += 1
        if count == 0:
            raise AssertionError("fixture observation was not found")
    return mutate


def edit_editor(edit):
    def update(observation):
        editors = [node for node in observation["nodes"] if node.get("editable") is True]
        if len(editors) != 1:
            raise AssertionError("fixture no longer has one editor")
        edit(editors[0], observation)
    return update


def alter_full_and_mini(source_name, full_key, mini_key, value):
    """Keep the stable readback's saved full/mini copies mutually consistent."""
    def mutate(directory, inputs):
        observation_id = read(directory / source_name)["observation_id"]
        def visit(record):
            if isinstance(record, dict):
                if record.get("observation_id") == observation_id:
                    if full_key in record:
                        record[full_key] = value
                    if mini_key in record:
                        record[mini_key] = value
                for child in record.values():
                    visit(child)
            elif isinstance(record, list):
                for child in record:
                    visit(child)
        for path in directory.glob("*.json"):
            record = read(path)
            visit(record)
            write(path, record)
    return mutate


def editor_suffix(suffix):
    def update(node, observation):
        node["text"] += suffix
        node["input_text_sha256"] = sha(node["text"].encode("utf-8"))
    return update


def duplicate_list_item(observation):
    original = next(node for node in observation["nodes"] if node.get("clickable") is True and node.get("text"))
    duplicate = copy.deepcopy(original)
    duplicate["id"] = "n199"
    observation["nodes"].append(duplicate)


def change_raw_model(directory, inputs):
    record = read(directory / MODEL)
    raw = json.loads(record["raw_text"])
    raw["text"] += "x"
    record["raw_text"] = json.dumps(raw, ensure_ascii=False)
    write(directory / MODEL, record)


def duplicate_attempt(directory, inputs):
    shutil.copyfile(directory / ATTEMPT, directory / "fixed-intent-02-attempt.json")


def symlinked_grant(directory, inputs):
    grant = directory / GRANT
    target = directory / "untrusted-alias-target.json"
    grant.rename(target)
    grant.symlink_to(target.name)


def foreign_owner_input(directory, inputs):
    inputs["instruction"] += "x"


def foreign_installed(directory, inputs):
    inputs["installed"]["uid"] += 1


def foreign_installed_hash(directory, inputs):
    inputs["installed"]["apk_hashes"]["base"] = ZERO_SHA


def foreign_domain(directory, inputs):
    inputs["expected_domain"] = {"display_id": 5, "generation": OTHER_GENERATION}


def select_cases():
    # Mutations are independently selected from the production authority,
    # observation, and lifecycle contracts, not from the verifier implementation.
    cases = [("positive_actual_controller_natural_owner", None, True),
             ("positive_synthetic_40lf_observed_apk", synthetic_forty_lf, True),
             ("positive_synthetic_derived_summary", synthetic_derived_summary, True),
             ("positive_synthetic_40lf_and_derived", compose(synthetic_forty_lf, synthetic_derived_summary), True)]
    cases += [(name, mutation, False) for name, mutation in [
        ("foreign_owner_argument", foreign_owner_input),
        ("owner_utf8_hash_changed", set_field("owner.json", ["instruction_utf8_sha256"], ZERO_SHA)),
        ("owner_body_span_changed", set_field("owner.json", ["completion_contract", "body_source_end_utf16"], 14)),
        ("owner_contract_hash_changed", set_field("owner.json", ["completion_contract", "contract_sha256"], ZERO_SHA)),
        ("owner_external_model_true", set_field("owner.json", ["external_model"], True)),
        ("foreign_installed_uid", foreign_installed),
        ("foreign_installed_apk", foreign_installed_hash),
        ("foreign_expected_display_and_generation", foreign_domain),
        ("parent_not_model_issued", set_field(PARENT, ["model_issued"], False)),
        ("parent_raw_model_payload_differs", change_raw_model),
        ("parent_stale", set_field(PARENT, ["stale"], True)),
        ("parent_not_dispatched", set_field(PARENT, ["dispatched"], False)),
        ("parent_missing_exact_attempt_journal", remove_file(ATTEMPT)),
        ("second_parent_attempt_journal", duplicate_attempt),
        ("attempt_allows_retry", set_field(ATTEMPT, ["automatic_retry_allowed"], True)),
        ("attempt_wrong_payload_sha", set_field(ATTEMPT, ["payload_sha256"], ZERO_SHA)),
        ("grant_not_consumed", set_field(GRANT, ["grant_consumed"], False)),
        ("grant_retired_before_work", set_field(GRANT, ["grant_retired"], True)),
        ("grant_missing_journal", remove_file(GRANT)),
        ("grant_symlink_alias", symlinked_grant),
        ("final_grant_not_retired", set_field(WORKFLOW, ["grant_retired"], False)),
        ("final_grant_claims_authority", set_field(WORKFLOW, ["grants_tool_authority"], True)),
        ("workflow_other_parent_run", set_field(WORKFLOW, ["parent_model_run_id"], OTHER_ID)),
        ("workflow_other_parent_attempt", set_field(WORKFLOW, ["parent_fixed_intent_attempt_id"], ZERO_SHA)),
        ("workflow_other_body", set_field(WORKFLOW, ["body_sha256"], ZERO_SHA)),
        ("workflow_other_display", set_field(WORKFLOW, ["display_id"], 5)),
        ("workflow_parent_step_boolean", set_field(WORKFLOW, ["parent_step"], True)),
        ("workflow_children_reordered", alter_json(WORKFLOW, lambda v: v["children"].reverse())),
        ("workflow_child_removed", alter_json(WORKFLOW, lambda v: v["children"].pop(0))),
        ("child_is_model_action", set_field("step-01-tool-child-01-action.json", ["model_issued"], True)),
        ("child_other_parent", set_field("step-01-tool-child-01-action.json", ["parent_model_run_id"], OTHER_ID)),
        ("child_wrong_actor", set_field("step-01-tool-child-01-action.json", ["actor_kind"], "model")),
        ("child_wrong_action_schema", set_field("step-01-tool-child-01-action.json", ["action_schema"], "hepta.action.v1")),
        ("child_live_lease_missing", set_field("step-01-tool-child-01-proof.json", ["live_lease_verified"], False)),
        ("child_cancelled_at_dispatch", set_field("step-01-tool-child-01-action.json", ["task_authorization", "callback_cancelled"], True)),
        ("child_accepted_false_dispatched_true", set_field("step-01-tool-child-01-action.json", ["accepted"], False)),
        ("child_stale_effect", set_field("step-01-tool-child-01-action.json", ["stale"], True)),
        ("child_planned_after_service_entry", set_field("step-01-notes-workflow-child-1-planned.json", ["service_entered"], True)),
        ("child_service_proof_retired", set_field("step-01-tool-child-01-proof.json", ["service_child_receipt", "grant_retired"], True)),
        ("child_planning_journal_missing", remove_file("step-01-notes-workflow-child-1-planned.json")),
        ("child_dispatch_receipt_missing", remove_file("step-01-tool-child-01-action.json")),
        ("child_before_missing", remove_file("step-01-tool-child-01-before.json")),
        ("child_after_missing", remove_file("step-01-tool-child-02-after.json")),
        ("child_proof_missing", remove_file("step-01-tool-child-02-proof.json")),
        ("initial_editor_body_changed", alter_observation("step-01-after.json", edit_editor(editor_suffix("x")))),
        ("readback_extra_space_not_trimmed", alter_observation("step-01-notes-workflow-observation-4.json", edit_editor(editor_suffix(" ")))),
        ("readback_39_lf_not_accepted", alter_observation("step-01-notes-workflow-observation-4.json", edit_editor(editor_suffix("\n" * 39)))),
        ("readback_40_lf_wrong_apk", alter_observation("step-01-notes-workflow-observation-4.json", edit_editor(editor_suffix("\n" * 40)))),
        ("readback_raw_sha_mismatch", alter_observation("step-01-notes-workflow-observation-4.json", edit_editor(lambda n, o: n.__setitem__("input_text_sha256", ZERO_SHA)))),
        ("readback_editor_disabled", alter_observation("step-01-notes-workflow-observation-4.json", edit_editor(lambda n, o: n.__setitem__("enabled", False)))),
        ("readback_editor_password", alter_observation("step-01-notes-workflow-observation-4.json", edit_editor(lambda n, o: n.__setitem__("password", True)))),
        ("readback_editor_outside_container", alter_observation("step-01-notes-workflow-observation-4.json", edit_editor(lambda n, o: n.__setitem__("bounds", [1100, 10, 1200, 150])))),
        ("readback_two_editors", alter_observation("step-01-notes-workflow-observation-4.json", edit_editor(lambda n, o: o["nodes"].append(dict(n, id="n199"))))),
        ("list_duplicate_matching_body", alter_observation("step-01-tool-child-02-before.json", duplicate_list_item)),
        ("list_truncated", alter_observation("step-01-tool-child-02-before.json", lambda o: o.__setitem__("nodes_truncated", True))),
        ("list_duplicate_node_id", alter_observation("step-01-tool-child-02-before.json", lambda o: o["nodes"][1].__setitem__("id", o["nodes"][0]["id"]))),
        ("list_title_missing", alter_observation("step-01-tool-child-02-before.json", lambda o: o.__setitem__("nodes", [n for n in o["nodes"] if not n.get("view_id", "").endswith(":id/title_text")]))),
        ("list_item_disabled", alter_observation("step-01-tool-child-02-before.json", lambda o: next(n for n in o["nodes"] if n.get("clickable") is True).__setitem__("enabled", False))),
        ("final_window_rotated", alter_observation("step-01-notes-workflow-observation-4.json", lambda o: o.__setitem__("rotation", 1))),
        ("final_observation_state_changed", alter_observation("step-01-notes-workflow-observation-4.json", lambda o: o.__setitem__("observation_state_sha256", ZERO_SHA))),
        ("stable_rotation_changed_in_all_matching_summaries", alter_full_and_mini("step-01-notes-workflow-observation-4.json", "rotation", "rotation", 1)),
        ("stable_tree_changed_in_all_matching_summaries", alter_full_and_mini("step-01-notes-workflow-observation-4.json", "observation_state_sha256", "tree_sha256", ZERO_SHA)),
        ("final_unobserved_window_metadata", alter_observation("step-01-notes-workflow-observation-4.json", lambda o: o["window"].__setitem__("metadata_status", "unavailable"))),
        ("final_wrong_window_type", alter_observation("step-01-notes-workflow-observation-4.json", lambda o: o["window"].__setitem__("type", 3))),
        ("controller_candidate_missing", remove_file("controller-completion-candidate.json")),
        ("controller_candidate_other_parent", set_field("controller-completion-candidate.json", ["parent_model_run_id"], OTHER_ID)),
        ("terminal_cancelled", set_field("result.json", ["status"], "cancelled")),
        ("terminal_unknown_cleanup", set_field("result.json", ["cleanup_known"], False)),
        ("terminal_no_completion_actor", set_field("result.json", ["completion_actor"], None)),
        ("terminal_goal_not_verified", set_field("result.json", ["goal_independently_verified"], False)),
        ("terminal_claims_synthetic_model_done", set_field("result.json", ["model_done_synthesized"], True)),
        ("terminal_parent_session_unbound", set_field("result.json", ["completion_evidence", "controller_native_parent_session_bound"], False)),
        ("terminal_observation_worker_pending", set_field("result.json", ["observation_read_worker_pending_at_terminal"], True)),
        ("terminal_native_exit_nonzero", set_field("result.json", ["model_session", "exit_code"], 9)),
        ("terminal_native_exit_unobserved", set_field("result.json", ["model_session", "process_exit_observed"], False)),
        ("synthetic_40lf_fully_rebound_wrong_apk", synthetic_forty_lf_other_apk),
        ("synthetic_derived_wrong_source_constant", mutate_derived(lambda n: n.__setitem__("child_text_source", "unobserved_source.v1"))),
        ("synthetic_derived_root_hash_mismatch", mutate_derived(lambda n: n.__setitem__("child_text_root_signature", ZERO_SHA), rebind=False)),
        ("synthetic_derived_node_binding_mismatch", mutate_derived(lambda n: n.__setitem__("node_app_tree_sha256", ZERO_SHA), rebind=False)),
        ("synthetic_derived_sources_incomplete", mutate_derived(lambda n: n.__setitem__("child_text_sources_complete", False))),
        ("synthetic_derived_label_truncated", mutate_derived(lambda n: n.__setitem__("child_text_truncated", True))),
        ("synthetic_derived_wrong_body_source_rebound", mutate_derived(lambda n: n["child_text_sources"][0].__setitem__("text_sha256", ZERO_SHA))),
        ("synthetic_derived_description_not_summary_text", mutate_derived(lambda n: n["child_text_sources"][0].__setitem__("property", "description"))),
        ("synthetic_derived_title_not_summary", mutate_derived(lambda n: n["child_text_sources"][0].__setitem__("view_id", NOTES_PACKAGE + ":id/note_title"))),
        ("synthetic_derived_noncanonical_path", mutate_derived(lambda n: n["child_text_sources"][0].__setitem__("descendant_path", "00"))),
        ("synthetic_derived_out_of_bound_path", mutate_derived(lambda n: n["child_text_sources"][0].__setitem__("descendant_path", "16"))),
        ("synthetic_derived_two_summary_sources", mutate_derived(lambda n: n["child_text_sources"].append(dict(n["child_text_sources"][0], descendant_path="1")))),
        ("synthetic_derived_boolean_visit_count", mutate_derived(lambda n: n.__setitem__("child_text_visited", True))),
        ("duplicate_json_key", malformed_file(GRANT, b'{"grant_consumed":true,"grant_consumed":false}')),
        ("nonfinite_json", malformed_file(GRANT, b'{"grant_consumed":true,"n":NaN}')),
    ]]
    return cases


def inputs_from(directory):
    owner = read(directory / "owner.json")
    installed = read(directory / "completion-installed-identity.json")
    return {"instruction": owner["instruction"],
            "installed": {k: copy.deepcopy(installed[k]) for k in ("package", "uid", "apk_hashes")},
            "expected_domain": {"display_id": 0, "generation": None}}


def execute_case(oracle, root, name, source, mutation, expected_verified):
    # The production collector binds the task to the directory basename. Keep
    # that identity unchanged while placing each mutation in its own parent.
    directory = root / name / source.name
    shutil.copytree(source, directory)
    inputs = inputs_from(directory)
    row = {"case": name, "expected_verified": expected_verified, "passed": False,
           "fixture_scope": "synthetic semantic mutation of production-method fake-IO fixture" if "synthetic" in name
                            else "unmodified production-method fake-IO fixture" if mutation is None
                            else "adversarial mutation of production-method fake-IO fixture"}
    try:
        if mutation:
            mutation(directory, inputs)
    except Exception as error:
        row.update(exception=type(error).__name__, reason=str(error)[:300],
                   failure="mutation fixture could not be constructed")
        return row
    try:
        result = oracle(directory, inputs["instruction"], inputs["installed"], inputs["expected_domain"])
        verified = isinstance(result, dict) and result.get("verified") is True
        row["returned_verified"] = verified
        row["passed"] = verified == expected_verified and (verified or isinstance(result, dict) and result.get("verified") is False)
        if not row["passed"]:
            row["failure"] = "oracle accepted a negative" if verified else "positive failed or invalid return contract"
    except (RuntimeError, ValueError, OSError) as error:
        row["rejected"] = True
        row["exception"] = type(error).__name__
        row["reason"] = str(error)[:300]
        row["passed"] = expected_verified is False
    except Exception as error:
        row["exception"] = type(error).__name__
        row["reason"] = str(error)[:300]
        row["failure"] = "unexpected exception in mutation or pure oracle"
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new absolute JSON report")
    parser.add_argument("--ci-evidence-root", type=Path, default=DEFAULT_CI_EVIDENCE_ROOT,
                        help="absolute extracted strict-host artifact root; never downloaded by this runner")
    parser.add_argument("--positive-fixture", type=Path,
                        help="optional explicit natural-OWNER task directory from production-controller fake-IO tests")
    parser.add_argument("--legacy-positive-fixture", type=Path,
                        help="optional explicit legacy-OWNER task directory, only with --include-legacy-owner")
    parser.add_argument("--ci-artifact-sha256", default=CI_ARTIFACT_SHA256,
                        help="provenance digest of the previously verified source ZIP; not re-downloaded or rehashed here")
    parser.add_argument("--include-legacy-owner", action="store_true")
    args = parser.parse_args()
    if not args.harness.is_absolute() or not args.harness.is_file() or args.harness.is_symlink():
        parser.error("--harness must be an existing absolute regular source path")
    if not args.output.is_absolute() or args.output.exists():
        parser.error("--output must be a new absolute path")
    if not args.ci_evidence_root.is_absolute():
        parser.error("--ci-evidence-root must be absolute")
    positive = args.positive_fixture or args.ci_evidence_root / POSITIVE_RELATIVE
    legacy = args.legacy_positive_fixture or args.ci_evidence_root / LEGACY_POSITIVE_RELATIVE
    for path in (positive, legacy) if args.include_legacy_owner else (positive,):
        if not path.is_absolute() or not path.is_dir() or any(p.is_symlink() for p in (path, *path.parents)):
            parser.error("fixture inputs must be existing absolute non-symlink directories")
    if len(args.ci_artifact_sha256) != 64 or any(c not in "0123456789abcdef" for c in args.ci_artifact_sha256):
        parser.error("--ci-artifact-sha256 must be a lowercase SHA256 provenance identifier")
    if args.legacy_positive_fixture and not args.include_legacy_owner:
        parser.error("--legacy-positive-fixture requires --include-legacy-owner")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    original_members = fixture_manifest(positive)
    source_bytes = args.harness.read_bytes()
    started = time.monotonic()
    rows = []
    def forbidden(*a, **kw):
        raise AssertionError("offline oracle tests must not launch subprocesses or network connections")
    with ExitStack() as guards:
        guards.enter_context(mock.patch.object(subprocess, "Popen", side_effect=forbidden))
        guards.enter_context(mock.patch.object(os, "system", side_effect=forbidden))
        guards.enter_context(mock.patch("socket.create_connection", side_effect=forbidden))
        spec = importlib.util.spec_from_file_location("hepta_notes_oracle_under_test", args.harness)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        oracle = getattr(module, "validate_notes_chain")
        with tempfile.TemporaryDirectory(prefix="hepta-notes-oracle-", dir=args.output.parent) as temp:
            root = Path(temp)
            for name, mutation, expected in select_cases():
                rows.append(execute_case(oracle, root, name, positive, mutation, expected))
            if args.include_legacy_owner:
                rows.append(execute_case(oracle, root, "positive_actual_controller_legacy_owner", legacy, None, True))
    unchanged = args.harness.read_bytes() == source_bytes and fixture_manifest(positive) == original_members
    report = {"schema": "hepta.background-notes-oracle-adversarial.v1", "all_pass": unchanged and all(x["passed"] for x in rows),
              "harness": str(args.harness), "harness_sha256": sha(source_bytes),
              "ci_artifact_sha256": args.ci_artifact_sha256, "artifact_checksum_reverified_this_run": False,
              "ci_evidence_root": str(args.ci_evidence_root), "fixture": str(positive), "fixture_members": original_members,
              "fixture_manifest_sha256": sha(json.dumps(original_members, sort_keys=True, separators=(",", ":")).encode()),
              "inputs_unchanged": unchanged, "case_count": len(rows), "passed_count": sum(x["passed"] for x in rows),
              "elapsed_seconds": round(time.monotonic() - started, 4), "cases": rows,
              "phone_tested": False, "accelerator_tested": False, "host_subprocesses_allowed": False,
              "scope": "Pure receipt replay only; positive fixtures contain synthetic Android/native IO and display 0. No phone qualification."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({k: report[k] for k in ("all_pass", "case_count", "passed_count", "inputs_unchanged", "harness_sha256", "phone_tested")}, sort_keys=True))
    for row in rows:
        if not row["passed"]:
            print(json.dumps(row, ensure_ascii=False, sort_keys=True))
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
