#!/usr/bin/env python3
"""Derive a reviewed v56 Notes verifier bundle from one exact candidate.

Normal mode requires the final candidate, its SHA, actual signed receipt, source
inventory and production source. --template-only emits deliberately unsealed
sources with None identities, so both normal CLI entry points refuse all APKs.
Neither mode imports or executes any phone driver.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import hashlib
import json
from pathlib import Path
import types

from offline_common import checked_file_hash, checked_read, exact_keys, need, sha256, strict_json, write_new_json
from preflight_v56 import CANDIDATE_KEYS, bind_artifacts, validate_candidate

CANONICAL = "5da3c83fe46edb2617934a92c06a10608accb68e"
LOCAL_FREEZE = "c2807a8093d064d2e158471788da9e98d4c4df94"
REPO_TREE = "e11aae799ecd27c7ccba0d1bfb65ee977c2e541e"
COMPONENT_TREE = "24e8d82d4befdab6f4f32ef7efeba7faad345a04"
SOURCE_MANIFEST = "a0835cd66f81f3c4c770b92256742b90188b0664c6a274c29086bae03d1c39ec"
STAGE_PIN = "5953f74931279890c5eea7aa7ff5d720cfac658e414e5d0d8b5f789b6646d5cb"
PLAN_SOURCE_PIN = "4bf77a52d012b4d5fe2fcfdcfea59649058c74d94202afcaacf0cb92e81c7bad"
MAIN_SOURCE_PIN = "ac8d0b871e783b0ce64416aecce707e910bcb151eadb2552fb1c71b0854cd6fd"
EXTRA_KEYS = {"published_source_commit", "local_frozen_source_commit", "repository_tree",
              "component_tree", "source_manifest_sha256", "plan_sha256"}
PRODUCTION = {
    "PhoneObservation.java": "9aeda02ab6fc541e9a8e04841093355c6055b590042f334b47fb55595ce5ca95",
    "BackgroundSession.java": "0045e81d6578a071de8dbdedd3c589afeb6025cf52d6c76fceb0e30e11e3dec6",
    "BackgroundTaskTarget.java": "e18294b0b18938636ed4112c0a5e82b2b70d76c5fb854a7fe25a876518fc73b7",
    "BackgroundUiPreferences.java": "a8bd7da61e46905e2e25dd064e6d04be73c26ba4b496b73fe4d8ef985ef29031",
    "MainActivity.java": "5bcc0da0a5cb73fa85062a450055eb3a9a9d31a467abf949e5d9335eb0d0e3f7",
    "TaskAuthorization.java": "9dbcabb1d4f505d581c2dc4b9fd772a4f7578344573c372e1831c84e2f82ecc8",
    "NotesOwnerIntent.java": "c3d8406e7d3bc6e513e0bad47d043f7d981cca82f5bbac095dce70aa84700e3f",
    "LocalTaskController.java": "c7639c1e0dbc3f476a280f16c3c8c835f78ea03bba254266de12b000e7fdd641",
    "HeptaAccessibilityService.java": "d5841f9a29a6a0218f765aa10ef4aef099ebb263bfe1e03bda1637e1e5f6a332",
}
OLD = {
    "commit": "42d3a0f447807659c0f78c8273edee01dd1b734f",
    "inventory": "8675c0c438cdf10f599c23a3a6305a5678fd59270f09b4f73a43f7a67bf2237d",
    "build": "eadc9dbb63b411015571a488377be6a8704c9f78415169a5164c8f13571f0f72",
    "apk": "0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a",
    "controller": "ee0430dcfc6709232387e77dc4f3843b0b2c25e84ebcff97a1b22d79a3c58919",
    "main_activity": "22e03ae02378cd05981faab93f70c2686de633b6bb7d35ab640ef358150c2aa5",
}


def replace(source, old, new, label, count=1):
    need(source.count(old) == count, "minimal patch cardinality differs: " + label)
    return source.replace(old, new)


def assignment(source, name, value):
    tree = ast.parse(source)
    nodes = [n for n in tree.body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    need(len(nodes) == 1, "single reviewed assignment required: " + name)
    lines = source.splitlines(True)
    node = nodes[0]
    before = "".join(lines[node.lineno - 1:node.end_lineno])
    return replace(source, before, name + " = " + repr(value) + "\n", "assignment " + name)


def versioned(raw):
    return raw.decode("utf-8").replace("v54", "v56").replace("V54", "V56")


def validate_release(candidate, build, runtime):
    exact_keys(candidate, set(CANDIDATE_KEYS) | EXTRA_KEYS, "complete v56 candidate")
    need(candidate["schema"] == "hepta.notes-v56-candidate.v2", "candidate v2 required")
    base = {k: candidate[k] for k in CANDIDATE_KEYS}
    base["schema"] = "hepta.notes-v56-candidate.v1"
    validate_candidate(base)
    need(candidate["published_source_commit"] == CANONICAL
         and candidate["local_frozen_source_commit"] == LOCAL_FREEZE
         and candidate["repository_tree"] == REPO_TREE
         and candidate["component_tree"] == COMPONENT_TREE
         and candidate["source_manifest_sha256"] == SOURCE_MANIFEST,
         "exact root-verified public/local frozen source identity required")
    need(candidate["source_commit"] in (CANONICAL, LOCAL_FREEZE),
         "actual compiler commit is not one of the independently tree-bound identities")
    bind_artifacts(base, build, runtime)
    # These are the union of the original collector, idle and source-aware gates.
    for key in ("source_commit_bound_after_exact_host_run", "existing_key_metadata_unchanged"):
        need(build.get(key) is True, "original signed source/key gate missing: " + key)
    need(type(build.get("exit_code")) is int and build["exit_code"] == 0
         and type(build.get("apk_bytes")) is int and build["apk_bytes"] > 0
         and build.get("new_key_created") is False, "original signed build outcome/key predicates missing")
    need(candidate["build_counts"]["actual_compiler_source_inputs"] == 211,
         "canonical production compiler input count differs")
    need(candidate["signer_proof_sha256"] == "97e3aba44ec7a303a935965c1d608692ac06007a33bb859fec481486c1a239fe",
         "original signer proof binding differs")


def render(original, reviewed, plan_source, main_source, candidate, candidate_sha, template):
    """All replacements are reviewable; no source input or old proof is mutated."""
    uid = None if template else candidate["device"]["expected_uid"]
    build_sha = None if template else candidate["build_receipt_sha256"]
    apk = None if template else candidate["apk_sha256"]
    commit = None if template else candidate["source_commit"]
    inventory = None if template else candidate["source_inventory_sha256"]
    schema = None if template else candidate["build_receipt_schema"]
    counts = None if template else candidate["build_counts"]
    runtime_sha = None if template else candidate["runtime_config_sha256"]
    physical = None if template else candidate["device"]["main_physical_display_id"]
    plan_sha = candidate["plan_sha256"]
    files = {
        "background_notes_plan.py": plan_source,
        "main_user_inflight.py": main_source,
        "live_inflight_window.py": original["live_inflight_window.py"],
        "moto_note_body_evidence_v51.py": original["moto_note_body_evidence_v51.py"],
        "v35_identity.py": original["v35_identity.py"],
        **{"compat-tools/" + name.split("/", 1)[1]: raw for name, raw in original.items()
           if name.startswith("tools/")},
    }
    fixed = versioned(original["fixed_intent_v6_acceptance.py"])
    for name, value in {
            "V56_BUILD_SHA": build_sha, "V56_LTC_SHA": PRODUCTION["LocalTaskController.java"],
            "V56_COMMIT": commit, "V56_INVENTORY": inventory, "V56_APK_SHA": apk,
            "V56_NOTES_OWNER_SHA": PRODUCTION["NotesOwnerIntent.java"],
            "V56_SELECTION_SOURCES": {n: h for n, h in PRODUCTION.items()
                                      if n not in ("LocalTaskController.java", "NotesOwnerIntent.java")}}.items():
        fixed = assignment(fixed, name, value)
    fixed = replace(fixed, 'build.get("schema") == "hepta.isolated-v56-assembly.v1"',
                    'build.get("schema") == ' + repr(schema), "actual build schema in source context")
    fixed = replace(fixed, 'build.get("version_code") == 54', 'build.get("version_code") == 56', "source context version")
    fixed = replace(fixed, 'and type(installed_identity["uid"]) is int and 10000 <= installed_identity["uid"] < 90000,',
                    'and type(installed_identity["uid"]) is int and installed_identity["uid"] == ' + repr(uid)
                    + ' and 10000 <= installed_identity["uid"] < 90000,', "same frozen installed UID")
    files["fixed_intent_v6_acceptance.py"] = fixed.encode()
    fixed_pin, plan_pin = sha256(files["fixed_intent_v6_acceptance.py"]), sha256(plan_source)

    workflow = versioned(reviewed["controller_workflow_evidence.py"])
    workflow = assignment(workflow, "FIXED_SHA", fixed_pin)
    workflow = assignment(workflow, "PLAN_SHA", plan_pin)
    workflow = replace(workflow, "self.bootstrap.get('app_uid') == 10481",
                       "self.bootstrap.get('app_uid') == " + repr(uid), "workflow actual UID")
    files["controller_workflow_evidence.py"] = workflow.encode()

    idle = versioned(reviewed["controller_idle_evidence.py"])
    idle = assignment(idle, "EXPECTED_V56_BUILD_SHA", build_sha)
    idle = assignment(idle, "EXPECTED_V56_APK_SHA", apk)
    idle = assignment(idle, "WORKFLOW_SHA", sha256(files["controller_workflow_evidence.py"]))
    idle = replace(idle, "expected_uid == 10481", "expected_uid == " + repr(uid), "idle actual UID")
    idle = replace(idle, "build.get('schema') == 'hepta.isolated-v56-assembly.v1'",
                   "build.get('schema') == " + repr(schema), "idle actual receipt schema")
    idle = replace(idle, "build['version_code'] == 54", "build['version_code'] == 56", "idle actual version")
    idle = replace(idle, "'version_code': 54", "'version_code': 56", "idle build metadata version")
    files["controller_idle_evidence.py"] = idle.encode()

    prepare = versioned(original["prepare_background_notes_v54_r1.py"])
    prepare = assignment(prepare, "EXPECTED_V56_APK_SHA", apk)
    prepare = assignment(prepare, "PLAN_HELPER_SHA", plan_pin)
    # Reuse the exact pinned collector's local bounded/stable reader; no new
    # transport or helper dependency is introduced into the preparation path.
    original_collector_text = original["run_background_notes_v54_r1.py"].decode()
    reader_node = next(n for n in ast.parse(original_collector_text).body
                       if isinstance(n, ast.FunctionDef) and n.name == "checked_file")
    reader_source = ast.get_source_segment(original_collector_text, reader_node)
    reader_source = reader_source.replace("def checked_file(", "def candidate_file(", 1)
    prepare = replace(prepare, "\ndef main():\n", "\n" + reader_source + "\n\n\ndef main():\n",
                      "pinned stable local input reader for candidate binding")
    start = prepare.index('    if args.test_mode == "background_only":\n')
    end = prepare.index('    need(re.fullmatch', start)
    old = prepare[start:end]
    admission = (
        '    need(args.plan == Path(__file__).absolute().with_name("notes-plan-v56-r1.json")\n'
        '         and args.plan_sha256 == ' + repr(plan_sha) + ',\n'
        '         "exact bundled v56 case plan required; no historical plan reuse")\n'
        '    need(args.expected_uid == ' + repr(uid) + ', "same frozen candidate UID required")\n'
        '    need(args.main_physical_display_id == ' + repr(physical) + ', "same frozen physical display required")\n'
        '    need(sha(candidate_file(args.runtime_config, 4096)) == ' + repr(runtime_sha)
        + ', "same frozen runtime config required")\n'
        '    need(sha(candidate_file(Path(__file__).absolute().with_name("RELEASE-CANDIDATE.json"), 65536))\n'
        '         == ' + repr(candidate_sha) + ', "sealed candidate bytes changed")\n')
    prepare = replace(prepare, old, admission, "exact new case admission in both modes")
    files["prepare_background_notes_v56_r1.py"] = prepare.encode()

    run = versioned(original["run_background_notes_v54_r1.py"])
    for name, value in {
            "EXPECTED_V56_SOURCE_COMMIT": commit, "EXPECTED_V56_SOURCE_INVENTORY": inventory,
            "EXPECTED_V56_BUILD_COUNTS": counts, "EXPECTED_V56_BUILD_SHA": build_sha,
            "EXPECTED_V56_APK_SHA": apk}.items():
        run = assignment(run, name, value)
    run = replace(run, 'build.get("schema") == "hepta.isolated-v56-assembly.v1"',
                  'build.get("schema") == ' + repr(schema), "collector actual receipt schema")
    run = replace(run, 'build.get("version_code") == 54', 'build.get("version_code") == 56', "collector actual version")
    run = replace(run, 'args.source_tools.parent / "src/org/trillionnium/hepta/local/LocalTaskController.java"',
                  "args.controller_source", "explicit actual production source path")
    run = replace(run, '    p.add_argument("--source-tools", type=Path, required=True)\n',
                  '    p.add_argument("--source-tools", type=Path, required=True,\n'
                  '        help="exact bundled compatibility tools, separate from production source")\n'
                  '    p.add_argument("--controller-source", type=Path, required=True,\n'
                  '        help="actual frozen v56 LocalTaskController.java with all source-bound siblings")\n',
                  "explicit source-path argument")
    run = replace(run,
        '    return MAIN_INFLIGHT.verdict(sys.modules[__name__], LIVE_INFLIGHT, args, report, samples, actions, by_file,\n'
        '        report.get("controller_workflow_proof") or {})',
        '    preparation_raw = checked_file(args.out / "PREPARATION-ORIGINAL.json", 2 << 20)\n'
        '    need(digest(preparation_raw) == args.preparation_sha256\n'
        '         and preparation_raw == checked_file(args.preparation, 2 << 20),\n'
        '         "actual preparation changed before independent main context binding")\n'
        '    plan_helper = sys.modules.get("background_notes_plan")\n'
        '    need(plan_helper is not None and digest(checked_file(Path(plan_helper.__file__))) == PINS["background_notes_plan"],\n'
        '         "exact plan helper required for main context binding")\n'
        '    expected_selection = plan_helper.background_selection_from_preparation(NOTES_PLAN, strict(preparation_raw))\n'
        '    return MAIN_INFLIGHT.verdict(sys.modules[__name__], LIVE_INFLIGHT, args, report, samples, actions, by_file,\n'
        '        report.get("controller_workflow_proof") or {},\n'
        '        expected_background_selection=expected_selection, preparation_original_sha256=digest(preparation_raw))',
        "independently bound complete nine-field live context")
    run = replace(run, '    args = parser().parse_args()\n',
                  '    args = parser().parse_args()\n'
                  '    need(args.expected_uid == ' + repr(uid) + ', "same frozen candidate UID required")\n'
                  '    need(args.main_physical_display_id == ' + repr(physical) + ', "same frozen physical display required")\n'
                  '    need(digest(checked_file(args.runtime_config, 4096)) == ' + repr(runtime_sha)
                  + ', "same frozen runtime config required")\n'
                  '    need(args.plan == Path(__file__).absolute().with_name("notes-plan-v56-r1.json")\n'
                  '         and args.plan_sha256 == ' + repr(plan_sha) + ', "exact new v56 case plan required")\n'
                  '    need(digest(checked_file(Path(__file__).absolute().with_name("RELEASE-CANDIDATE.json"), 65536))\n'
                  '         == ' + repr(candidate_sha) + ', "sealed candidate bytes changed")\n',
                  "same exact candidate and case before any phone action")
    tree = ast.parse(run)
    pins_node = next(n for n in tree.body if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == "PINS" for t in n.targets))
    pins = ast.literal_eval(pins_node.value)
    for name in ("background_notes_plan", "fixed_intent_v6_acceptance",
                 "prepare_background_notes_v56_r1", "main_user_inflight", "controller_workflow_evidence"):
        pins[name] = sha256(files[name + ".py"])
    run = assignment(run, "PINS", pins)
    files["run_background_notes_v56_r1.py"] = run.encode()
    for name, raw in files.items():
        compile(raw, name, "exec", dont_inherit=True)
    # No original security predicate body is removed by cardinality-free logic.
    return files


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--candidate-sha256", required=True)
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--production-source-root", type=Path, required=True)
    p.add_argument("--build-receipt", type=Path)
    p.add_argument("--apk", type=Path)
    p.add_argument("--source-inventory", type=Path)
    p.add_argument("--runtime-config", type=Path)
    p.add_argument("--template-only", action="store_true")
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    need(args.out.is_absolute() and not args.out.exists() and args.out.parent.is_dir()
         and all(not p.is_symlink() for p in args.out.parents), "new output directory required")
    candidate_raw = checked_read(args.candidate, args.candidate_sha256, 65536)
    candidate = strict_json(candidate_raw)
    stage = args.root / "source-stage-v56-r1"
    stage_record = strict_json(checked_read(stage / "SOURCE-STAGE-RESULT.json", STAGE_PIN))
    original = {r["file"]: checked_read(stage / "originals" / r["file"], r["sha256"])
                for r in stage_record["originals"]}
    reviewed = {r["file"]: checked_read(stage / "reviewed-v54-replay" / r["file"], r["sha256"])
                for r in stage_record["reviewed_replay_sources"]}
    plan_source = checked_read(stage / "identity-independent/background_notes_plan.py", PLAN_SOURCE_PIN)
    main_source = checked_read(stage / "identity-independent/main_user_inflight.py", MAIN_SOURCE_PIN)
    production_reads = []
    source_dir = args.production_source_root / "src/org/trillionnium/hepta/local"
    for name, pin in PRODUCTION.items():
        raw = checked_read(source_dir / name, pin)
        production_reads.append({"file": "src/org/trillionnium/hepta/local/" + name,
                                 "bytes": len(raw), "sha256": pin})
    need(type(candidate) is dict and type(candidate.get("plan_sha256")) is str, "exact plan binding required")
    plan_raw = checked_read(args.plan, candidate["plan_sha256"], 65536)
    plan_module = types.ModuleType("v56_plan_seal_validation")
    exec(compile(plan_source, "v56-plan-seal-validation", "exec"), plan_module.__dict__)
    actual_plan, actual_plan_raw = plan_module.load_plan(args.plan, candidate["plan_sha256"])
    need(actual_plan_raw == plan_raw and actual_plan["phone_tested"] is False, "fresh planned input required")
    build_raw = inventory_raw = runtime_raw = apk_read = None
    if args.template_only:
        need(candidate.get("release_sealed") is False and candidate.get("apk_sha256") is None
             and candidate.get("build_receipt_sha256") is None and candidate.get("source_commit") is None,
             "template identity must remain explicitly unknown")
    else:
        need(all(v is not None for v in (args.build_receipt, args.apk, args.source_inventory, args.runtime_config)),
             "actual receipt, APK, inventory and runtime config are mandatory to seal")
        exact_keys(candidate, set(CANDIDATE_KEYS) | EXTRA_KEYS, "complete v56 candidate")
        build_raw = checked_read(args.build_receipt, candidate["build_receipt_sha256"], 1 << 20)
        inventory_raw = checked_read(args.source_inventory, candidate["source_inventory_sha256"], 64 << 20)
        runtime_raw = checked_read(args.runtime_config, candidate["runtime_config_sha256"], 16384)
        build = strict_json(build_raw)
        validate_release(candidate, build, strict_json(runtime_raw))
        apk_read = checked_file_hash(args.apk, candidate["apk_sha256"], 512 << 20)
        need(apk_read["bytes"] == build["apk_bytes"], "actual signed APK length differs from receipt")
        profile_module = types.ModuleType("v56_exact_compat_model_profiles")
        exec(compile(original["tools/model_profiles.py"], "v56-exact-compat-model-profiles", "exec"), profile_module.__dict__)
        need(profile_module.profile(candidate["runtime"]["model_profile"])["sha256"]
             == candidate["runtime"]["model_sha256"], "candidate model hash differs from exact native profile")
    files = render(original, reviewed, plan_source, main_source, candidate,
                   args.candidate_sha256, args.template_only)
    files["notes-plan-v56-r1.json"] = plan_raw
    files["RELEASE-CANDIDATE.json"] = candidate_raw
    if not args.template_only:
        files["BUILD-RECEIPT-ORIGINAL.json"] = build_raw
        files["SOURCE-INVENTORY-ORIGINAL.json"] = inventory_raw
        files["RUNTIME-CONFIG-ORIGINAL.json"] = runtime_raw
    args.out.mkdir(mode=0o700)
    rows = []
    for name, raw in sorted(files.items()):
        target = args.out / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open("xb") as f:
            f.write(raw)
        need(target.read_bytes() == raw, "generated source readback differs")
        rows.append({"file": name, "bytes": len(raw), "sha256": sha256(raw)})
    diffs = []
    for name, raw in sorted(files.items()):
        prior_name = name.replace("_v56_r1.py", "_v54_r1.py")
        prior = original.get(prior_name) or reviewed.get(name)
        if prior is not None and prior != raw:
            diff = "".join(difflib.unified_diff(prior.decode().splitlines(True), raw.decode().splitlines(True),
                                               fromfile="original/" + prior_name, tofile="v56/" + name))
            diff_path = args.out / "diffs" / (name + ".diff")
            diff_path.parent.mkdir(exist_ok=True)
            with diff_path.open("xb") as f:
                f.write(diff.encode())
            diffs.append({"file": name, "original_sha256": sha256(prior), "derived_sha256": sha256(raw),
                          "diff_sha256": sha256(diff.encode())})
    result = {"schema": "hepta.notes-v56-source-adaptation-seal.v2",
              "release_sealed": not args.template_only, "template_only": args.template_only,
              "candidate_sha256": args.candidate_sha256, "canonical_public_commit": CANONICAL,
              "actual_compiler_commit": None if args.template_only else candidate["source_commit"],
              "production_source_reads": production_reads, "files": rows, "diffs": diffs,
              "actual_apk_byte_binding": apk_read,
              "complete_source_inventory_members_rehashed_here": False,
              "verification_tools_are_separate_from_production_tools": True,
              "original_native_auth_lease_workflow_checks_preserved": True,
              "additional_main_content_gate": True, "independent_semantic_review_required": True,
              "ordinary_prepare_external_prerequisites_still_required": True,
              "phone_actions": 0, "phone_tested": False, "phone_execution_ready": False,
              "next_gate": "Independent source/host-negative review, then root-controlled installation/preparation/Start under normal ownership"}
    print(write_new_json(args.out / "ADAPTATION-RESULT.json", result))


if __name__ == "__main__":
    main()
