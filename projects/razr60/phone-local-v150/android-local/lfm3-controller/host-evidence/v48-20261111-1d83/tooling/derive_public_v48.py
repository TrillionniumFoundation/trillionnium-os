#!/usr/bin/env python3
"""Prepare public-query adapters against an exact existing v48 core manifest.

No APK copy, host command, device contact or edit of the core adapter package.
Draft core inputs create only fail-closed device entry points; plan stays local.
"""
import argparse
import ast
import difflib
import hashlib
import json
from pathlib import Path
import re

BASE_MANIFEST_SHA = "2157694a475ff3997b623e190e4ca3be3df0b1687fb21188a76f40fc6a64cf7c"
SOURCE_COMMIT = '588e79570b87417dbbc754ecec1ca4fc5a0012ba'
SOURCE_INVENTORY_SHA = 'dd3c9eb9e42e1fbe2a02b9f058c1f526f51978cd4d511d5e53532284b12259f7'
PACKAGE_RECEIPT_SHA = 'ec4d454d4ca04da712a5af5c48c168704f09feb61ceb9df0177587f7eecd1c69'
SOURCE_PACKAGE_SHA = 'b7d4c5fa16045da007df88025cd3b5595dfdf22501ef5f00b401ef8d7b2f1f35'
BASE_FILES = ("public_query_v46_r1.py", "public_query_evidence_v46_r1.py", "fixed_intent_v6_acceptance.py")
INTEGRATED_PATHS = {"host-checks/task-completion/RESULT.json", "host-checks/task-completion/calculator-completion.stdout",
                    "host-checks/task-completion/notes-recovery.stdout", "host-checks/observation-pipeline/RESULT.json", "host-checks/observation-pipeline/tests.stdout"}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    need(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)), "absolute nonsymlink local input required")
    return path.read_bytes()


def once(text, old, new):
    need(text.count(old) == 1, "exact reviewed v46 anchor changed: " + old[:100])
    return text.replace(old, new)


def assign(text, name, value):
    found = [n for n in ast.parse(text).body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    need(len(found) == 1, "constant changed: " + name)
    node, lines = found[0], text.splitlines(keepends=True)
    return "".join(lines[:node.lineno-1]) + name + " = " + repr(value) + "\n" + "".join(lines[node.end_lineno:])


def core_binding(core, raw, expected_sha, expected_apk_sha=None, expected_assembly_sha=None):
    need(isinstance(expected_sha, str) and re.fullmatch(r"[0-9a-f]{64}", expected_sha) and sha(raw) == expected_sha,
         "explicit unchanged core manifest hash required")
    need(core.get("schema") == "hepta.phone-v48-preparation.v1" and core.get("build_identity", {}).get("version_code") == 48,
         "v48 core manifest required")
    status = core.get("status")
    need(status in ("draft_all_device_entries_disabled", "frozen_from_actual_build_artifacts"), "unknown core freeze status")
    frozen = status == "frozen_from_actual_build_artifacts"
    artifacts, identity = core["artifacts"], core["build_identity"]
    if frozen:
        need(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                 for value in (expected_apk_sha, expected_assembly_sha))
             and artifacts.get("apk_sha256") == expected_apk_sha
             and artifacts.get("build_receipt_sha256") == expected_assembly_sha,
             "explicit actual v48 APK/assembly hashes must match the unchanged frozen core")
        need(all(isinstance(artifacts.get(k), str) and re.fullmatch(r"[0-9a-f]{64}", artifacts[k]) for k in
                 ("apk_sha256", "build_receipt_sha256", "source_inventory_sha256", "package_receipt_sha256", "source_package_sha256", "assembly_script_sha256")),
             "complete actual core build artifact hashes required")
        need(identity.get("source_commit") == SOURCE_COMMIT and identity.get("source_inventory_sha256") == SOURCE_INVENTORY_SHA
             and artifacts["source_inventory_sha256"] == SOURCE_INVENTORY_SHA
             and artifacts["package_receipt_sha256"] == PACKAGE_RECEIPT_SHA and artifacts["source_package_sha256"] == SOURCE_PACKAGE_SHA
             and identity.get("source_file_count") == 515 and identity.get("actual_compiler_source_inputs") == 180,
             "core is not the reviewed actual v48 source package")
        integrated = core.get("integrated_evidence_sha256")
        need(isinstance(integrated, dict) and set(integrated) == INTEGRATED_PATHS
             and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in integrated.values()),
             "core five original observer/calculator/Notes-recovery gate byte bindings missing")
    else:
        need(expected_apk_sha is None and expected_assembly_sha is None, "draft forbids actual freeze identity arguments")
        need(all(v is None for v in artifacts.values()) and identity.get("source_commit") is None
             and identity.get("source_inventory_sha256") is None and core.get("integrated_evidence_sha256") is None,
             "draft must not carry invented frozen build identities or artifact hashes")
    return frozen


CONTROLLER_HELPER = '''def controller_completion_observation(terminal, session):
    """Report actual fields. This does not supply a missing web-results provider."""
    evidence = terminal.get("completion_evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    contract = evidence.get("contract")
    contract = contract if isinstance(contract, dict) else {}
    status = terminal.get("status")
    consistent = (status == session.get("status") and status in ("partial", "failed", "cancelled")
        and terminal.get("completion_verified") is False
        and terminal.get("goal_independently_verified") is False
        and evidence.get("terminal_binding_and_cleanup_verified") is False
        and contract.get("kind") == "web_search_results")
    return {"actual_terminal_status": status, "actual_session_status": session.get("status"),
        "actual_model_reported_success": terminal.get("model_reported_success"),
        "actual_model_done_status": terminal.get("model_done_status"), "actual_model_done_summary": terminal.get("model_done_summary"),
        "actual_completion_verified": terminal.get("completion_verified"),
        "actual_goal_independently_verified": terminal.get("goal_independently_verified"),
        "actual_terminal_binding_and_cleanup_verified": evidence.get("terminal_binding_and_cleanup_verified"),
        "actual_contract_kind": contract.get("kind"), "actual_missing": evidence.get("missing"),
        "consistent_unverified_web_terminal": consistent, "web_results_provider_available": False,
        "partial_or_unknown_promoted": False}


'''


INPUT_IDS_HELPER = '''def original_input_ids_bound(directory, collection, diagnostic):
    """Extra AND gate; never edits the original collection or binary diagnostic."""
    proof = {"verified": False, "scope": "complete collected task/run set and original binary bytes", "business_answer_verified": False}
    try:
        directory = Path(directory)
        raw_collection = (directory / "collection.json").read_bytes()
        raw_diagnostic = (directory / "input-ids-binary-collection.json").read_bytes()
        need(json.loads(raw_collection) == collection and json.loads(raw_diagnostic) == diagnostic, "saved original collection/diagnostic differs")
        need(diagnostic.get("schema") == "hepta.input-ids-binary-collection.v1"
             and diagnostic.get("all_associated_ids_bytes_verified") is True
             and diagnostic.get("original_collection_unchanged") is True
             and diagnostic.get("original_collection_sha256") == sha(raw_collection)
             and diagnostic.get("task_id") == collection.get("task_id")
             and isinstance(collection.get("task_id"), str) and re.fullmatch(r"[0-9a-f]{32}", collection["task_id"]), "exact original task/collection binding required")
        associated, rows = collection.get("associated_runs"), diagnostic.get("runs")
        need(isinstance(associated, list) and associated and isinstance(rows, list), "nonempty complete model run evidence required")
        expected = [row.get("run_id") for row in associated if isinstance(row, dict)]
        actual = [row.get("run_id") for row in rows if isinstance(row, dict)]
        need(len(expected) == len(associated) == len(set(expected)) and len(actual) == len(rows) == len(set(actual))
             and all(isinstance(run, str) and re.fullmatch(r"[0-9a-f]{32}", run) for run in expected)
             and set(actual) == set(expected), "binary diagnostic must cover every associated run exactly once")
        for row in rows:
            relative = "runs/" + row["run_id"] + "/formatted-input-ids.le32"
            need(row.get("path") == relative and row.get("available") is True
                 and row.get("actual_bytes_verified_against_native_receipt") is True, "original verified binary row required")
            path = directory / relative
            need(all(not part.is_symlink() for part in (path, *path.parents)), "binary path must not be a symlink")
            raw = path.read_bytes()
            need(0 < len(raw) <= 16 << 20 and len(raw) % 4 == 0 and type(row.get("bytes")) is int
                 and row["bytes"] == len(raw) and row.get("sha256") == sha(raw)
                 and type(row.get("decoded_count")) is int and row["decoded_count"] == len(raw) // 4,
                 "saved binary bytes/hash/count changed")
        proof.update(verified=True, task_id=collection["task_id"], original_collection_sha256=sha(raw_collection),
                     diagnostic_sha256=sha(raw_diagnostic), complete_run_ids=sorted(expected))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        proof["reason"] = str(error)
    return proof


'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", type=Path, required=True, help="exact original v46-phone-adapters or a copied three-file base plus its manifest")
    p.add_argument("--core-dir", type=Path, required=True, help="existing complete frozen v48 core, or explicit nonexecutable draft")
    p.add_argument("--core-manifest-sha256", required=True)
    p.add_argument("--apk-sha256", help="actual v48 signed APK hash; mandatory only for an already frozen actual core")
    p.add_argument("--assembly-receipt-sha256", help="actual original v48 assembly RESULT.json hash; mandatory only for an already frozen actual core")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    need(a.out.is_absolute() and not a.out.exists() and all(not x.is_symlink() for x in a.out.parents), "new absolute output directory required")
    base_raw = read(a.base / "MANIFEST.json")
    need(sha(base_raw) == BASE_MANIFEST_SHA, "reviewed original v46 manifest changed")
    rows = {x["name"]: x for x in json.loads(base_raw)["files"]}
    originals = {}
    for name in BASE_FILES:
        raw = read(a.base / name)
        need(sha(raw) == rows[name]["sha256"], "reviewed v46 query input changed: " + name)
        originals[name] = raw.decode("utf-8")
    core_raw = read(a.core_dir / "MANIFEST.json")
    core = json.loads(core_raw)
    frozen = core_binding(core, core_raw, a.core_manifest_sha256, a.apk_sha256, a.assembly_receipt_sha256)
    core_rows = {x["name"]: x for x in core["files"]}
    r7_raw = read(a.core_dir / "background_helpers_r7_v48.py")
    need(sha(r7_raw) == core_rows["background_helpers_r7_v48.py"]["sha256"], "actual core r7 bytes changed")
    extension_raw = read(a.core_dir / "fixed_intent_v6_acceptance.py")
    need(extension_raw == originals["fixed_intent_v6_acceptance.py"].encode()
         and sha(extension_raw) == core_rows["fixed_intent_v6_acceptance.py"]["sha256"], "core fixed-intent evidence helper differs")
    evidence = originals["public_query_evidence_v46_r1.py"].replace("v46", "v48").replace("V46", "V48")
    evidence = once(evidence, "public-query plans with observed click/back navigation and evidence-only checks.",
                    "public-query plans limited to web.search/scroll/wait/done and evidence-only checks.")
    evidence = assign(evidence, "TOOLS", ["done", "scroll", "wait", "web.search"])
    evidence = assign(evidence, "AUTH_PREVIEW", "已识别的工具权限：[打开网页查询, 滚动, 等待, 成功结束]。可随时停止或报告未完成；页面目标和其它语义条件仍需核对。")
    evidence = once(evidence, "本任务只允许点击、网页搜索、滚动、返回、等待和结束任务。", "本任务只允许网页搜索、滚动、等待和结束任务。")
    evidence = once(evidence, "可查看公开搜索结果及其公开详情，以核对实际信息和来源。", "仅查看本次公开搜索结果页面，通过滚动读取，不进入详情或其他应用页面。")
    evidence = once(evidence, "结束前须返回搜索结果页，并停留在实际结果可见的页面，不进入购买流程。", "结束时停留在本次搜索结果页面；若弹窗、登录或详情要求点击才能继续，应说明未完成。")
    evidence = once(evidence, '"public_details_allowed": True,', '"public_details_allowed": False, "public_search_results_only": True,')
    evidence = once(evidence, "最终页面确为本次公开搜索结果页；如曾进入公开详情，已返回结果页；未进入登录、预订、加购或付款流程", "最终页面确为本次公开搜索结果页；完整模型动作链仅含网页搜索、滚动、等待或结束，无点击、输入、提交、返回或应用打开")
    evidence = once(evidence, '"本次查询验收编号为" + test_id', '"本次查询验收编号为Hepta-v48-query-" + test_id')
    evidence = once(evidence, '"test_id": test_id, "case": case,', '"test_id": test_id, "marker": "Hepta-v48-query-" + test_id, "case": case,')
    evidence = once(evidence, 'def assess(args, plan, pa, receipts, binder, collection, session, final_ui, ext, installed):',
                    CONTROLLER_HELPER + INPUT_IDS_HELPER + 'def assess(args, plan, pa, receipts, binder, collection, session, final_ui, ext, installed):')
    evidence = once(evidence, '    machine = bool(owner_bound and authorization_bound and whole and not invalid and dispatch and current["results_evidence_present"] and clean)\n',
                    '    controller = controller_completion_observation(terminal, session)\n'
                    '    machine = bool(owner_bound and authorization_bound and whole and not invalid and dispatch and current["results_evidence_present"] and clean\n'
                    '        and controller["consistent_unverified_web_terminal"])\n')
    evidence = once(evidence, '"requested_business_answer_verified": False, "current_results_evidence": current, "machine_checks_passed": machine,',
                    '"requested_business_answer_verified": False, "current_results_evidence": current, "machine_checks_passed": machine,\n'
                    '            "controller_completion_observation": controller, "machine_checks_scope": "query evidence only; no goal completion promotion",')
    wrapper = originals["public_query_v46_r1.py"].replace("v46", "v48").replace("V46", "V48")
    wrapper = once(wrapper, "ordinary-Start public query wrapper: observed click/back and public detail review.",
                   "ordinary-Start public search-result reader: web.search/scroll/wait/done only.")
    wrapper = assign(assign(wrapper, "R7_SHA", sha(r7_raw)), "PUBLIC_EVIDENCE_SHA", sha(evidence.encode()))
    constants = {"FROZEN_BINDINGS_READY": frozen, "FROZEN_CORE_MANIFEST_SHA256": sha(core_raw),
                 "FROZEN_APK_SHA256": core["artifacts"].get("apk_sha256"), "FROZEN_SOURCE_COMMIT": core["build_identity"].get("source_commit"),
                 "FROZEN_ASSEMBLY_RECEIPT_SHA256": core["artifacts"].get("build_receipt_sha256")}
    wrapper = once(wrapper, "def need(", "".join(k + " = " + repr(v) + "\n" for k, v in constants.items()) + "\n\ndef need(")
    wrapper = once(wrapper, 'def device_stage(args, report):\n',
                   'def device_stage(args, report):\n'
                   '    need(FROZEN_BINDINGS_READY, "public v48 awaits actual frozen core; no owner or device access")\n'
                   '    need(args.apk_sha256 == FROZEN_APK_SHA256, "public query must use the same actual frozen v48 APK")\n'
                   '    need(args.core_manifest.is_absolute() and all(not p.is_symlink() for p in (args.core_manifest, *args.core_manifest.parents)), "exact core manifest path required")\n'
                   '    need(sha(args.core_manifest.read_bytes()) == FROZEN_CORE_MANIFEST_SHA256, "frozen core manifest changed")\n'
                   '    report["frozen_build_binding"] = {"core_manifest_sha256": FROZEN_CORE_MANIFEST_SHA256, "source_commit": FROZEN_SOURCE_COMMIT, "apk_sha256": FROZEN_APK_SHA256, "assembly_receipt_sha256": FROZEN_ASSEMBLY_RECEIPT_SHA256}\n')
    wrapper = once(wrapper, 'for name in ("plan", "out", "owner-root", "source-tools", "r7-driver", "runtime-config"):',
                   'for name in ("plan", "out", "owner-root", "source-tools", "r7-driver", "runtime-config", "core-manifest"):')
    wrapper = once(wrapper, '        report["machine_checks_passed"] = report["acceptance"]["machine_checks_passed"]\n',
                   '        report["acceptance"]["input_ids_original_binding"] = query_checks.original_input_ids_bound(args.out / "evidence", collection, report["input_ids_evidence"])\n'
                   '        report["acceptance"]["original_input_ids_bytes_verified"] = report["acceptance"]["input_ids_original_binding"]["verified"] is True\n'
                   '        report["acceptance"]["machine_checks_passed"] = bool(report["acceptance"]["machine_checks_passed"] and report["acceptance"]["original_input_ids_bytes_verified"])\n'
                   '        report["machine_checks_passed"] = report["acceptance"]["machine_checks_passed"]\n')
    a.out.mkdir(mode=0o700)
    (a.out / "originals").mkdir()
    (a.out / "CORE-MANIFEST.json").write_bytes(core_raw)
    entries, diffs = [], []
    for name, base_name, text in (("public_query_v48_r1.py", "public_query_v46_r1.py", wrapper),
                                  ("public_query_evidence_v48_r1.py", "public_query_evidence_v46_r1.py", evidence),
                                  ("fixed_intent_v6_acceptance.py", "fixed_intent_v6_acceptance.py", originals["fixed_intent_v6_acceptance.py"])):
        compile(text, name, "exec")
        raw = text.encode()
        (a.out / name).write_bytes(raw)
        (a.out / "originals" / base_name).write_text(originals[base_name])
        entries.append({"path": name, "bytes": len(raw), "sha256": sha(raw), "base": base_name, "base_sha256": rows[base_name]["sha256"]})
        diffs.append("".join(difflib.unified_diff(originals[base_name].splitlines(True), text.splitlines(True), fromfile="originals/" + base_name, tofile=name)))
    manifest = {"schema": "hepta.v48-public-query-adapters.v1", "status": "frozen_against_actual_core" if frozen else "draft_device_entry_disabled",
                "core_manifest_sha256": sha(core_raw), "core_source_commit": core["build_identity"].get("source_commit"),
                "actual_apk_sha256": core["artifacts"].get("apk_sha256"), "actual_assembly_receipt_sha256": core["artifacts"].get("build_receipt_sha256"),
                "core_r7_sha256": sha(r7_raw), "files": entries, "remote_executed": False, "phone_contacted": False,
                "integrated_evidence_sha256": core.get("integrated_evidence_sha256"),
                "actual_source_inventory_sha256": core["artifacts"].get("source_inventory_sha256"),
                "actual_package_receipt_sha256": core["artifacts"].get("package_receipt_sha256"),
                "actual_source_package_sha256": core["artifacts"].get("source_package_sha256"),
                "actual_assembly_script_sha256": core["artifacts"].get("assembly_script_sha256"),
                "core_package_modified": False, "qualified": False, "web_completion_provider_available": False,
                "original_input_ids_bytes_required": True, "business_answer_manual_review_required": True,
                "public_search_results_only": True, "public_details_allowed": False, "booking_cart_order_payment_allowed": False,
                "allowed_model_tools": ["done", "scroll", "wait", "web.search"],
                "navigation_semantics_hard_enforced_by_tool_whitelist": False,
                "flight_plan_fixture_date": "2026-11-17", "actual_user_itinerary_assumed": False}
    (a.out / "MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    (a.out / "ADAPTERS.diff").write_text("".join(diffs))
    print(json.dumps({"status": manifest["status"], "manifest_sha256": sha((a.out / "MANIFEST.json").read_bytes()), "core_package_modified": False, "phone_contacted": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()
