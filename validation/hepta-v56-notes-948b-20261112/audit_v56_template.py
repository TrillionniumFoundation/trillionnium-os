#!/usr/bin/env python3
"""Offline review of the unsealed v56 derivative, never an APK/phone qualification.

The audit checks exact original and derived bytes, enumerates every function
change, verifies old predicates remain, and invokes only rejecting CLI paths.
A Python audit hook forbids subprocess, network and lock attempts during those
entry-point checks. No positive phone evidence is generated or rewritten.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import types

from offline_common import checked_read, need, sha256, strict_json, write_new_json
import seal_v56_notes as seal

STAGE_SHA = "5953f74931279890c5eea7aa7ff5d720cfac658e414e5d0d8b5f789b6646d5cb"
TEMPLATE_RESULT_SHA = "2e97b08c71d792e1bb137fa2cf57a14a912e6c4cebcfd8c07f5c52731391c1e8"
BEFORE_SHA = "89ec9ce9e68ea59ecce3ac13dd93c1efe3c1721fb3b1e8f3fa5c97339cc5cded"
AFTER_SHA = "64a9c5c2de0787ca9e8b118b7f5c47373434feb646ab108e5bea76c6955ae50f"
CONTEXT_FIELDS = {"owner", "config_sha256", "display_id", "background_generation", "model_sha256", "body",
                  "notes_identity", "expected_background_selection", "preparation_original_sha256"}
PROJECTION_FIELDS = {"mode", "generation", "display_id", "allowed_packages", "bootstrap_package",
                     "bootstrap_source", "bootstrap_model_issued", "home_allowed", "main_display_fallback"}


def functions(raw):
    tree = ast.parse(raw)
    found = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            found[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for method in node.body:
                if isinstance(method, ast.FunctionDef):
                    found[node.name + "." + method.name] = method
    return found


def structure(node):
    return ast.dump(node, include_attributes=False)


def literal_assignment(raw, name):
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    need(len(nodes) == 1, "unique module assignment missing: " + name)
    return ast.literal_eval(nodes[0].value)


def check_dictionary(node, variable):
    matches = [n.value for n in ast.walk(node) if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == variable for t in n.targets)
               and isinstance(n.value, ast.Dict)]
    need(len(matches) == 1, "unique check dictionary missing: " + variable)
    return {k.value: structure(v) for k, v in zip(matches[0].keys, matches[0].values)}


def load(raw, path, name):
    value = types.ModuleType(name)
    value.__file__ = str(path)
    sys.modules[name] = value
    exec(compile(raw, str(path), "exec"), value.__dict__)
    return value


def invocation(call, argv, expected):
    prior = sys.argv
    try:
        sys.argv = argv
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                call()
            except (RuntimeError, ValueError) as exc:
                need(str(exc) == expected, "rejected at an unexpected gate: " + str(exc))
                return {"rejected": True, "reason": str(exc)}
            else:
                raise AssertionError("unsealed entry point accepted")
    finally:
        sys.argv = prior


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--before", type=Path, required=True)
    p.add_argument("--after", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    sys.dont_write_bytecode = True
    root, stage = args.root, args.root / "source-stage-v56-r1"
    template = root / "v56-template-source-r2"
    record = strict_json(checked_read(template / "ADAPTATION-RESULT.json", TEMPLATE_RESULT_SHA))
    need(record["release_sealed"] is False and record["template_only"] is True
         and record["phone_execution_ready"] is False and record["actual_apk_byte_binding"] is None,
         "template was relabelled as a release")
    source_record = strict_json(checked_read(stage / "SOURCE-STAGE-RESULT.json", STAGE_SHA))
    originals = {r["file"]: checked_read(stage / "originals" / r["file"], r["sha256"])
                 for r in source_record["originals"]}
    reviewed = {r["file"]: checked_read(stage / "reviewed-v54-replay" / r["file"], r["sha256"])
                for r in source_record["reviewed_replay_sources"]}
    derived = {r["file"]: checked_read(template / r["file"], r["sha256"])
               for r in record["files"]}
    need(len(originals) == 14 and len(reviewed) == 3 and len(derived) == 16, "closure cardinality differs")
    for row in record["files"]:
        need(len(derived[row["file"]]) == row["bytes"], "derived length differs")
    for row in record["diffs"]:
        checked_read(template / "diffs" / (row["file"] + ".diff"), row["diff_sha256"])
    for row in record["production_source_reads"]:
        checked_read(root / "canonical-v56" / row["file"], row["sha256"])
    need(len(record["production_source_reads"]) == 9, "nine production source pins required")
    comparisons = [
        ("fixed_intent_v6_acceptance.py", originals["fixed_intent_v6_acceptance.py"], {"_V56SourceContext.__init__"}, set()),
        ("controller_workflow_evidence.py", reviewed["controller_workflow_evidence.py"], {"BoundDomain.__init__"}, set()),
        ("controller_idle_evidence.py", reviewed["controller_idle_evidence.py"], {"verify"}, set()),
        ("main_user_inflight.py", reviewed["main_user_inflight.py"], {"verdict"}, {"nondecorative_content_change"}),
        ("prepare_background_notes_v56_r1.py", originals["prepare_background_notes_v54_r1.py"], {"main"}, {"candidate_file"}),
        ("run_background_notes_v56_r1.py", originals["run_background_notes_v54_r1.py"],
         {"bind_local_inputs", "collect_and_assess", "parser", "main", "coexistence_verdict"}, set()),
    ]
    ast_rows = []
    for name, prior, allowed, added in comparisons:
        old = functions(seal.versioned(prior)); new = functions(derived[name])
        changed = {key for key in old.keys() & new.keys() if structure(old[key]) != structure(new[key])}
        need(changed == allowed and new.keys() - old.keys() == added and not old.keys() - new.keys(),
             "unreviewed function change or deletion: " + name)
        ast_rows.append({"file": name, "unchanged_after_version_label_rename": len(old) - len(changed),
                         "changed": sorted(changed), "added": sorted(added), "removed": []})
    for name in ("live_inflight_window.py", "moto_note_body_evidence_v51.py", "v35_identity.py"):
        need(derived[name] == originals[name], "unmodified critical helper differs: " + name)
    for name in ("model_profiles.py", "phone_acceptance.py", "phone_suite.py", "warm_receipts.py"):
        need(derived["compat-tools/" + name] == originals["tools/" + name], "compatibility helper bytes changed")
    need(derived["background_notes_plan.py"] == originals["background_notes_plan.py"].replace(b"v54", b"v56"),
         "narrow Notes plan contract changed beyond version labels")
    run_raw = derived["run_background_notes_v56_r1.py"]
    pins = literal_assignment(run_raw, "PINS")
    for name, pin in pins.items():
        path = name + ".py"
        raw = derived.get(path, derived.get("compat-tools/" + path))
        need(raw is not None and sha256(raw) == pin, "runtime helper pin mismatch: " + name)
    fixed_raw = derived["fixed_intent_v6_acceptance.py"]
    source_pins = literal_assignment(fixed_raw, "V56_SELECTION_SOURCES")
    source_pins["LocalTaskController.java"] = literal_assignment(fixed_raw, "V56_LTC_SHA")
    source_pins["NotesOwnerIntent.java"] = literal_assignment(fixed_raw, "V56_NOTES_OWNER_SHA")
    need(source_pins == seal.PRODUCTION, "source-aware binding does not pin all nine canonical producers")
    for name in ("V56_BUILD_SHA", "V56_COMMIT", "V56_INVENTORY", "V56_APK_SHA"):
        need(literal_assignment(fixed_raw, name) is None, "unknown signed identity filled in template")
    fixed_old = functions(seal.versioned(originals["fixed_intent_v6_acceptance.py"]))
    fixed_new = functions(fixed_raw)
    need(structure(fixed_old["v6_app_binding"]) == structure(fixed_new["v6_app_binding"]),
         "fixed entry keyset/source-aware extension altered")
    workflow = functions(derived["controller_workflow_evidence.py"])
    projected = [n.args[1] for n in ast.walk(workflow["BoundDomain.window"])
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_equal"
                 and len(n.args) == 2 and isinstance(n.args[0], ast.Name) and n.args[0].id == "bg"
                 and isinstance(n.args[1], ast.Dict)]
    need(len(projected) == 1 and {k.value for k in projected[0].keys} == PROJECTION_FIELDS,
         "exact canonical nine-field observation projection widened")
    main_old = functions(reviewed["main_user_inflight.py"])
    main_new = functions(derived["main_user_inflight.py"])
    old_checks = check_dictionary(main_old["verdict"], "checks")
    new_checks = check_dictionary(main_new["verdict"], "checks")
    need(len(old_checks) == 8 and len(new_checks) == 9
         and all(new_checks.get(k) == v for k, v in old_checks.items())
         and set(new_checks) - set(old_checks) == {"settings_non_decorative_content_changed"},
         "old main protocol conditions changed or new content gate absent")
    verdict = main_new["verdict"]
    contexts = [n.args[1] for n in ast.walk(verdict) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name) and n.func.id == "same_value" and len(n.args) == 2
                and isinstance(n.args[0], ast.Name) and n.args[0].id == "context" and isinstance(n.args[1], ast.Dict)]
    need(len(contexts) == 1 and {k.value for k in contexts[0].keys} == CONTEXT_FIELDS
         and {a.arg for a in verdict.args.kwonlyargs} == {"expected_background_selection", "preparation_original_sha256"}
         and all(v is None for v in verdict.args.kw_defaults), "complete independently bound context weakened")
    need(structure(main_old["same_value"]) == structure(main_new["same_value"]), "negative-controlled context predicate changed")
    reader = copy.deepcopy(functions(run_raw)["checked_file"])
    reader.name = "candidate_file"
    need(structure(reader) == structure(functions(derived["prepare_background_notes_v56_r1.py"])["candidate_file"]),
         "preparation input reader differs from exact pinned collector")
    for name in ("prepare_background_notes_v56_r1.py", "run_background_notes_v56_r1.py"):
        text = derived[name].decode()
        need('"same frozen candidate UID required"' in text and '"same frozen physical display required"' in text
             and '"same frozen runtime config required"' in text and '"sealed candidate bytes changed"' in text,
             "candidate identity is not bound before execution: " + name)
    # The actual archived scrollbar-only pair is a negative, never a new success.
    run = load(run_raw, template / "run_background_notes_v56_r1.py", "v56_offline_unsealed_collector")
    main_helper = load(derived["main_user_inflight.py"], template / "main_user_inflight.py", "v56_offline_main_content")
    before, after = checked_read(args.before, BEFORE_SHA), checked_read(args.after, AFTER_SHA)
    pixel_result = main_helper.nondecorative_content_change(run, before, after, [0, 130, 1224, 2920])
    need(pixel_result["interior_content_changed"] is False and pixel_result["semantic_scroll_verified"] is False,
         "actual scrollbar-only images were accepted")
    # No socket, subprocess, flock, OS command or spawn is allowed in these probes.
    forbidden = []
    def audit_event(event, values):
        if (event.startswith(("subprocess.", "socket.", "pty."))
                or event in {"os.system", "os.posix_spawn", "os.spawn", "os.fork", "fcntl.flock", "fcntl.lockf"}):
            forbidden.append(event)
            raise RuntimeError("offline audit forbids transport/lock event: " + event)
    sys.addaudithook(audit_event)
    out_paths = [root / "MUST-NOT-EXIST-unsealed-collector-r2", root / "MUST-NOT-EXIST-unsealed-prepare-r2",
                 root / "MUST-NOT-EXIST-missing-receipt-seal-r2"]
    need(all(not p.exists() for p in out_paths), "negative-probe output already exists")
    common = ["--test-mode", "background_only", "--adb", "/NO-TRANSPORT-ADB", "--adb-host", "NO-TRANSPORT",
              "--adb-port", "1", "--serial", "NO-TRANSPORT", "--apk-sha256", seal.OLD["apk"],
              "--expected-uid", "10481", "--main-physical-display-id", "4630947043778501779",
              "--runtime-config", str(root / "ABSENT-runtime.json"), "--plan", str(template / "notes-plan-v56-r1.json"),
              "--plan-sha256", sha256(derived["notes-plan-v56-r1.json"]), "--source-tools", str(template / "compat-tools")]
    collector_argv = [str(template / "run_background_notes_v56_r1.py"), *common,
        "--identity-helper", str(template / "v35_identity.py"), "--controller-source", str(root / "canonical-v56/src/org/trillionnium/hepta/local/LocalTaskController.java"),
        "--build-receipt", str(root / "ABSENT-build.json"), "--build-receipt-sha256", seal.OLD["build"],
        "--preparation", str(root / "ABSENT-preparation.json"), "--preparation-sha256", seal.OLD["build"],
        "--source-commit", seal.CANONICAL, "--target-package", "com.motorola.stylus", "--existing-su-authorized",
        "--out", str(out_paths[0])]
    negative = [{"name": "unsealed_collector_refuses_historical_uid_before_any_file_or_transport",
                 **invocation(run.main, collector_argv, "same frozen candidate UID required")}]
    prepare = load(derived["prepare_background_notes_v56_r1.py"], template / "prepare_background_notes_v56_r1.py", "v56_offline_unsealed_preparer")
    prepare_argv = [str(template / "prepare_background_notes_v56_r1.py"), *common,
        "--ui-helper", str(root / "ABSENT-ui.py"), "--background-driver", str(root / "ABSENT-r12.py"),
        "--r7-driver", str(root / "ABSENT-r7.py"), "--owner-root", str(root / "ABSENT-owner"),
        "--owner-start-ticks", "ABSENT", "--owner-boot-id", "ABSENT", "--owner-pid", "1", "--out", str(out_paths[1])]
    negative.append({"name": "unsealed_preparation_refuses_historical_apk_before_transport",
                     **invocation(prepare.main, prepare_argv, "actual final v56 APK identity is not sealed; no phone execution")})
    seal_argv = ["seal_v56_notes.py", "--root", str(root), "--candidate", str(root / "CANDIDATE-TEMPLATE-background-r1.json"),
        "--candidate-sha256", record["candidate_sha256"], "--plan", str(template / "notes-plan-v56-r1.json"),
        "--production-source-root", str(root / "canonical-v56"), "--out", str(out_paths[2])]
    negative.append({"name": "normal_seal_refuses_missing_actual_receipt_apk_inventory_runtime",
                     **invocation(seal.main, seal_argv, "actual receipt, APK, inventory and runtime config are mandatory to seal")})
    try:
        load(fixed_raw, template / "fixed_intent_v6_acceptance.py", "v56_offline_unsealed_fixed")._V56SourceContext(
            None, "/ABSENT-build", "/ABSENT-source", {}, "")
    except ValueError as exc:
        need(str(exc) == "actual final v56 signed identity is not sealed", "unsealed source context failed elsewhere")
        negative.append({"name": "unsealed_fixed_source_context_refuses_before_source_reads", "rejected": True, "reason": str(exc)})
    else:
        raise AssertionError("unsealed source context accepted")
    need(not forbidden and all(not p.exists() for p in out_paths), "negative probe reached output/transport/lock")
    result = {"schema": "hepta.notes-v56-offline-template-audit.v1", "all_scoped_checks_passed": True,
        "template_result_sha256": TEMPLATE_RESULT_SHA, "source_stage_sha256": STAGE_SHA,
        "original_collector_replay_files_rehashed": len(originals), "reviewed_v54_sources_rehashed": len(reviewed),
        "derived_template_files_rehashed": len(derived), "canonical_production_sources_rehashed": len(record["production_source_reads"]),
        "function_review": ast_rows, "unchanged_function_bodies_after_version_labels": sum(r["unchanged_after_version_label_rename"] for r in ast_rows),
        "reviewed_changed_function_bodies": sum(len(r["changed"]) for r in ast_rows),
        "old_main_check_predicates_unchanged": 8, "new_main_check_count": 9,
        "full_context_fields": sorted(CONTEXT_FIELDS), "background_projection_fields": sorted(PROJECTION_FIELDS),
        "fixed_native_keysets_unchanged": True, "warm_request_and_session_helper_byte_identical": True,
        "actual_scrollbar_only_original_pair_rejected": True, "actual_negative_pixel_result": pixel_result,
        "rejecting_entry_point_probes": negative, "rejecting_entry_point_probes_passed": len(negative),
        "transport_or_lock_attempts_observed": forbidden, "negative_probe_output_directories_created": 0,
        "new_phone_actions": 0, "full_native_workflow_replay_executed": False, "source_inventory_members_rehashed": False,
        "v56_phone_tested": False, "release_sealed": False, "phone_execution_ready": False,
        "positive_scroll_case_created": False, "effective_list_scroll_verified": False, "continuous_interactivity_verified": False,
        "actual_apk_receipt_and_fresh_uid_physical_display_preflight_pending": True}
    print(write_new_json(args.out, result))


if __name__ == "__main__":
    main()
