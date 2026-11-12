#!/usr/bin/env python3
"""Repeat the complete nine-field equality predicate on retained real context.

This does not rerun the 9-domain native/workflow replay or claim a new phone
result. Mutations are negative in-memory copies; all original bytes stay intact.
"""
import argparse
import ast
import copy
import json
from pathlib import Path

from offline_common import checked_read, need, strict_json, write_new_json

SOURCE_PIN = "4aa6e0f8db9229e1764d9ee79220ed8fa3eb7ddc3bd5526a857fd179870afe30"
COLLECTOR_PIN = "2d85991282f6a02834fcb492e8470ec7561a47fb9f524b750e319f7b1a3fae7d"
REPLAY_PIN = "eef5e79feb21965a52c4bdc35892842af3d5e74c578792deb4f4cdec73f12db2"
FIELDS = {"owner", "config_sha256", "display_id", "background_generation", "model_sha256", "body",
          "notes_identity", "expected_background_selection", "preparation_original_sha256"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    source = checked_read(args.root / "reviewed-v54-replay/main_user_inflight.py", SOURCE_PIN)
    report = strict_json(checked_read(args.root / "github-originals/original-phone-collector-result.json", COLLECTOR_PIN))
    replay = strict_json(checked_read(args.root / "github-originals/actual-independent-replay-result.json", REPLAY_PIN))
    tree = ast.parse(source)
    function = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "same_value"]
    need(len(function) == 1, "complete pinned equality predicate missing")
    verdict = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "verdict")
    comparisons = [node for node in ast.walk(verdict) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == "same_value"
                   and len(node.args) == 2 and isinstance(node.args[0], ast.Name)
                   and node.args[0].id == "context" and isinstance(node.args[1], ast.Dict)]
    need(len(comparisons) == 1 and {key.value for key in comparisons[0].args[1].keys} == FIELDS,
         "verdict no longer compares the complete nine-field context")
    need({a.arg for a in verdict.args.kwonlyargs} == {"expected_background_selection", "preparation_original_sha256"},
         "independently supplied context bindings missing")
    namespace = {"json": json}
    source_name = str(args.root / "reviewed-v54-replay/main_user_inflight.py") + ":same_value"
    exec(compile(ast.Module(body=function, type_ignores=[]), source_name, "exec"), namespace)
    same = namespace["same_value"]
    candidate = report["main_user"]["trigger_candidate"]
    actual = candidate["context"]
    expected = {"owner": report["instruction"], "config_sha256": report["runtime_config_sha256"],
                "display_id": replay["display_id"], "background_generation": replay["generation"],
                "model_sha256": report["expected_model_sha256"], "body": report["plan"]["body"],
                "notes_identity": report["installed_identity_before"]["notes"],
                "expected_background_selection": replay["actual_owner_task_selection"]["expected_selection"],
                "preparation_original_sha256": replay["actual_owner_task_selection"]["preparation_sha256"]}
    need(set(actual) == FIELDS and same(actual, expected), "retained real context/independently replayed identity differs")
    controls = []
    for field in sorted(FIELDS):
        value = copy.deepcopy(actual)
        value.pop(field)
        need(not same(value, expected), "missing field accepted: " + field)
        controls.append({"name": "missing_" + field, "rejected": True})
    mutations = [
        ("extra_context_field", lambda c: c.__setitem__("extra", True)),
        ("logical_display_zero", lambda c: c.__setitem__("display_id", 0)),
        ("boolean_display_id", lambda c: c.__setitem__("display_id", True)),
        ("wrong_generation", lambda c: c.__setitem__("background_generation", "00000000-0000-0000-0000-000000000000")),
        ("widened_selection", lambda c: c["expected_background_selection"]["allowed_packages"].append("com.android.settings")),
        ("wrong_preparation_sha", lambda c: c.__setitem__("preparation_original_sha256", "0" * 64)),
        ("wrong_model_sha", lambda c: c.__setitem__("model_sha256", "0" * 64)),
        ("changed_owner_instruction", lambda c: c.__setitem__("owner", c["owner"] + " changed")),
        ("changed_notes_body", lambda c: c.__setitem__("body", c["body"] + " changed")),
        ("wrong_notes_uid", lambda c: c["notes_identity"].__setitem__("uid", 0)),
    ]
    for name, mutate in mutations:
        value = copy.deepcopy(actual)
        mutate(value)
        need(not same(value, expected), "negative context accepted: " + name)
        controls.append({"name": name, "rejected": True})
    result = {"schema": "hepta.notes-v56-preparation-historical-context-controls.v1",
              "source_sha256": SOURCE_PIN, "original_collector_sha256": COLLECTOR_PIN,
              "historical_replay_sha256": REPLAY_PIN,
              "retained_real_nine_field_context_matches": True,
              "source_predicate_exact_nine_fields_confirmed": True,
              "negative_controls_rejected": len(controls), "negative_controls_total": len(controls),
              "controls": controls, "phone_actions": 0, "originals_modified": False,
              "entire_native_workflow_replay_reexecuted": False,
              "historical_machine_counts_reassigned": False, "v56_phone_qualified": False}
    print(write_new_json(args.out, result))


if __name__ == "__main__":
    main()
