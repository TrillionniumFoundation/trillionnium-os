#!/usr/bin/env python3
"""Local mechanical v46-to-v48 driver preparation. No host or phone execution.

Without all actual build artifacts, every generated device entry refuses before
owner/ADB access. A draft hash is never presented as the new APK/build identity.
"""
import argparse
import ast
import difflib
import hashlib
import json
from pathlib import Path
import re

BASE_MANIFEST_SHA = "2157694a475ff3997b623e190e4ca3be3df0b1687fb21188a76f40fc6a64cf7c"
OLD_APK_SHA = "4b9378f4c244059e4521a23f351f1447e24736617d9a0dc6d1a14d59071298f5"
SIGNER = "202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5"
SIGNER_PROOF = "97e3aba44ec7a303a935965c1d608692ac06007a33bb859fec481486c1a239fe"
CALCULATOR_OWNER = "打开计算器，在当前主输入区计算 31 乘以 47，确认当前结果框显示计算结果后结束任务。"
BASE_FILES = (
    "background_helpers_r7_v46.py", "moto_note_legacy_v46_r2.py",
    "fixed_intent_v6_acceptance.py", "moto_note_body_evidence.py",
    "moto_note_v46_r1.py", "finalize_note_review_v46.py",
    "configure_local_profile_v46_helper_r1.py", "install_v46_idle_r1.py",
    "background_r12_v46.py", "prepare_background_v46_r1.py",
)
INTEGRATED_EVIDENCE = (
    "host-checks/task-completion/RESULT.json",
    "host-checks/task-completion/calculator-completion.stdout",
    "host-checks/task-completion/notes-recovery.stdout",
    "host-checks/observation-pipeline/RESULT.json",
    "host-checks/observation-pipeline/tests.stdout",
)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    need(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)), "absolute nonsymlink input required")
    return path.read_bytes()


def once(text, old, new):
    need(text.count(old) == 1, "exact v46 anchor changed: " + old[:100])
    return text.replace(old, new)


def assign(text, name, value):
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    need(len(nodes) == 1, "constant changed: " + name)
    node = nodes[0]
    lines = text.splitlines(keepends=True)
    return "".join(lines[:node.lineno-1]) + name + " = " + repr(value) + "\n" + "".join(lines[node.end_lineno:])


def package_contract(package, build, artifacts, archive_bytes):
    need(package.get("schema") == "hepta.v48-complete-build-package.v1"
         and package.get("source_git_blobs_verified") is True,
         "actual v48 complete-source package schema and Git-blob proof required")
    need(package.get("version_code") == 48 and package.get("source_commit") == build["source_commit"]
         and package.get("source_inventory_sha256") == build["source_inventory_sha256"]
         and package.get("source_file_count") == build["source_file_count"]
         and package.get("expected_compiler_source_inputs") == build["actual_compiler_source_inputs"]
         and package.get("archive_sha256") == artifacts["source_package_sha256"]
         and package.get("archive_bytes") == archive_bytes,
         "actual complete-source package does not match committed build source")


def integrated_evidence(receipt_path, build):
    """Read only five fixed original files relative to the actual build root."""
    need(build.get("integrated_observation_calculator_evidence_base") == "assembly_receipt_parent_parent",
         "actual integration evidence path base required")
    pins = build.get("integrated_observation_calculator_sha256")
    need(isinstance(pins, dict) and set(pins) == set(INTEGRATED_EVIDENCE)
         and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in pins.values()),
         "five fixed original integration evidence hashes required")
    nested = build.get("nested_phase_source_checks", {}).get("task-completion/calculator-completion.stdout", {})
    need(nested.get("evidence_relative_path") == "../host-checks/task-completion/calculator-completion.stdout"
         and nested.get("sha256") == pins[INTEGRATED_EVIDENCE[1]],
         "calculator nested stdout binding differs from original integration evidence")
    recovery = build.get("nested_phase_source_checks", {}).get("task-completion/notes-recovery.stdout", {})
    need(recovery.get("evidence_relative_path") == "../host-checks/task-completion/notes-recovery.stdout"
         and recovery.get("sha256") == pins["host-checks/task-completion/notes-recovery.stdout"],
         "Notes recovery nested stdout binding differs from original integration evidence")
    for relative in INTEGRATED_EVIDENCE:
        raw = read(receipt_path.parent.parent / relative)
        need(raw and digest(raw) == pins[relative], "actual original integrated evidence changed: " + relative)
    return dict(pins)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", type=Path, default=Path("/workspace/scratch/007f1dd9aa90/v46-phone-adapters"))
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--identity-helper", type=Path,
                   help="optional separate original v35_identity.py; default is under --base/background-prerequisites")
    for name in ("build-receipt", "source-inventory", "package-receipt", "source-package", "assembly-script", "apk"):
        p.add_argument("--" + name, type=Path)
    a = p.parse_args()
    need(a.out.is_absolute() and not a.out.exists(), "new absolute output directory required")
    base_raw = read(a.base / "MANIFEST.json")
    need(digest(base_raw) == BASE_MANIFEST_SHA, "original frozen v46 adapter manifest changed")
    base = json.loads(base_raw)
    originals = {}
    base_rows = {row["name"]: row for row in base["files"]}
    need(set(BASE_FILES) <= set(base_rows), "required frozen v46 driver rows missing")
    for name in BASE_FILES:
        raw = read(a.base / name)
        need(digest(raw) == base_rows[name]["sha256"], "v46 input changed: " + name)
        originals[name] = raw.decode("utf-8")
    # These helpers are reused exactly; unrelated tool changes require new review.
    for name in ("warm_receipts", "phone_acceptance", "phone_suite", "model_profiles"):
        need(digest(read(a.source / "tools" / (name + ".py"))) == base["source_pins"][name], "source tool changed: " + name)
    java_pin = digest(read(a.source / "src/org/trillionnium/hepta/local/ModelProfile.java"))
    need(java_pin == base["source_pins"]["ModelProfile.java"], "ModelProfile changed; review before repinning")
    artifact_names = ("build_receipt", "source_inventory", "package_receipt", "source_package", "assembly_script", "apk")
    present = [getattr(a, name) is not None for name in artifact_names]
    need(not any(present) or all(present), "supply all six actual build artifact paths together")
    frozen = all(present)
    identity = {"source_commit": None, "source_inventory_sha256": None, "version_code": 48,
                "source_file_count": None, "actual_compiler_source_inputs": None,
                "host_check_records": None, "host_input_count": None}
    artifacts = {name + "_sha256": None for name in artifact_names}
    build = None
    integration_pins = None
    if frozen:
        raws = {name: read(getattr(a, name)) for name in artifact_names}
        artifacts = {name + "_sha256": digest(raw) for name, raw in raws.items()}
        build, package = json.loads(raws["build_receipt"]), json.loads(raws["package_receipt"])
        need(build.get("all_pass") is True and build.get("version_code") == 48
             and all(build.get(k) is True for k in ("matches_previously_recorded_signer", "source_files_unchanged", "actual_compiler_inputs_bound_to_signed_asset")),
             "actual successful v48 assembly receipt required")
        need(build.get("signer_certificate_sha256") == SIGNER and build.get("signer_proof_sha256") == SIGNER_PROOF, "existing signer proof changed")
        need(re.fullmatch(r"[0-9a-f]{40}", build.get("source_commit", "")), "actual source commit required")
        need(build.get("source_inventory_sha256") == artifacts["source_inventory_sha256"]
             and build.get("apk_sha256") == artifacts["apk_sha256"] and build.get("apk_bytes") == len(raws["apk"])
             and build.get("runner_sha256") == artifacts["assembly_script_sha256"], "actual inventory/APK/assembly bytes do not match receipt")
        package_contract(package, build, artifacts, len(raws["source_package"]))
        for key in ("source_file_count", "actual_compiler_source_inputs", "host_check_records", "host_input_count"):
            need(type(build.get(key)) is int and build[key] >= base["build_identity"][key], "original build gate missing: " + key)
        integration_pins = integrated_evidence(a.build_receipt, build)
        rows = json.loads(raws["source_inventory"])
        need(isinstance(rows, list) and len(rows) == build["source_file_count"], "source inventory size differs")
        seen = set()
        for row in rows:
            need(isinstance(row, dict) and set(row) == {"path", "size", "sha256"}, "source inventory row shape differs")
            rel = Path(row["path"])
            need(not rel.is_absolute() and ".." not in rel.parts and str(rel) == row["path"] and row["path"] not in seen, "source inventory path invalid")
            seen.add(row["path"])
            raw = read(a.source / rel)
            need(len(raw) == row["size"] and digest(raw) == row["sha256"], "local source differs from built inventory: " + row["path"])
        need({"AndroidManifest.xml", "tools/model_profiles.py", "src/org/trillionnium/hepta/local/CalculatorCompletionEvidence.java"} <= seen, "v48 source inputs missing")
        identity = {key: build[key] for key in identity}
    a.out.mkdir(mode=0o700)
    (a.out / "originals").mkdir()
    entries, outputs, deltas = [], {}, []

    def emit(name, base_name, text):
        compile(text, name, "exec")
        raw = text.encode()
        (a.out / name).write_bytes(raw)
        (a.out / "originals" / base_name).write_text(originals[base_name])
        delta = "".join(difflib.unified_diff(originals[base_name].splitlines(True), text.splitlines(True), fromfile="originals/" + base_name, tofile=name))
        (a.out / (name + ".diff")).write_text(delta)
        entries.append({"name": name, "sha256": digest(raw), "base": base_name, "base_sha256": digest(originals[base_name].encode()), "bytes": len(raw)})
        outputs[name] = digest(raw)
        deltas.append(delta)
        return outputs[name]

    def version(text):
        return text.replace("v46", "v48").replace("V46", "V48")

    def guard(text, function, apk_arg):
        constants = "FROZEN_BINDINGS_READY = " + repr(frozen) + "\nFROZEN_APK_SHA256 = " + repr(artifacts["apk_sha256"]) + "\n"
        text = once(text, "def need(", constants + "\ndef need(")
        pattern = r"(^def " + re.escape(function) + r"\([^\n]+\):\n)"
        need(len(re.findall(pattern, text, re.M)) == 1, "device entry changed: " + function)
        return re.sub(pattern, lambda m: m.group(1) + '    need(FROZEN_BINDINGS_READY, "v48 awaits actual APK/package/assembly receipts; no device access")\n'
                      + '    need(args.' + apk_arg + ' == FROZEN_APK_SHA256, "actual frozen v48 APK differs")\n', text, flags=re.M)

    r7 = emit("background_helpers_r7_v48.py", "background_helpers_r7_v46.py", guard(originals["background_helpers_r7_v46.py"], "execute", "apk_sha256"))
    legacy_text = assign(originals["moto_note_legacy_v46_r2.py"], "R7_SHA", r7)
    legacy = emit("moto_note_legacy_v48_r2.py", "moto_note_legacy_v46_r2.py", guard(legacy_text, "device_stage", "apk_sha256"))
    for name in ("fixed_intent_v6_acceptance.py", "moto_note_body_evidence.py"):
        emit(name, name, originals[name])
    notes = guard(assign(version(originals["moto_note_v46_r1.py"]), "R7_SHA", r7), "device_stage", "apk_sha256")
    notes_pin = emit("moto_note_v48_r1.py", "moto_note_v46_r1.py", notes)
    emit("finalize_note_review_v48.py", "finalize_note_review_v46.py", version(originals["finalize_note_review_v46.py"]))
    profile = version(originals["configure_local_profile_v46_helper_r1.py"])
    for key, value in {"NOTES_SHA": legacy, "PROFILE_JAVA_SHA": java_pin, "SOURCE_COMMIT": identity["source_commit"],
                       "SOURCE_INVENTORY_SHA256": identity["source_inventory_sha256"], "VERSION_CODE": 48,
                       "BUILD_COUNTS": {k: identity[k] for k in ("source_file_count", "actual_compiler_source_inputs", "host_check_records", "host_input_count")}}.items():
        profile = assign(profile, key, value)
    profile_pin = emit("configure_local_profile_v48_helper_r1.py", "configure_local_profile_v46_helper_r1.py", guard(profile, "configure", "apk_sha256"))
    installer = version(originals["install_v46_idle_r1.py"])
    installer = once(installer, 'before["version_code"] == 45 and args.expected_version == 46', 'before["version_code"] == 46 and args.expected_version == 48')
    installer = once(installer, "exact v45 to v48", "exact v46 to v48")
    installer = once(installer, 'args.expected_version == 46, "this frozen installer', 'args.expected_version == 48, "this frozen installer')
    installer = once(installer, '    args = parser.parse_args()\n', '    args = parser.parse_args()\n    need(args.old_apk_sha256 == ' + repr(OLD_APK_SHA) + ', "expected installed v46 APK differs")\n')
    installer = assign(installer, "PROFILE_HELPER_SHA", profile_pin)
    emit("install_v48_idle_r1.py", "install_v46_idle_r1.py", guard(installer, "execute", "new_apk_sha256"))
    background = guard(version(originals["background_r12_v46.py"]), "execute", "apk_sha256")
    # Preserve every old predicate, and additionally require v48 controller proof.
    background = once(background, '        result.get("model_reported_success") is True, result.get("external_model") is False,\n',
                      '        result.get("model_reported_success") is True, result.get("external_model") is False,\n'
                      '        result.get("completion_verified") is True, result.get("goal_independently_verified") is True,\n'
                      '        result.get("completion_evidence", {}).get("terminal_binding_and_cleanup_verified") is True,\n'
                      '        result.get("completion_evidence", {}).get("contract", {}).get("kind") == "calculator_current_product",\n')
    background_pin = emit("background_r12_v48.py", "background_r12_v46.py", background)
    prepare = version(originals["prepare_background_v46_r1.py"])
    prepare = assign(assign(prepare, "UI_SHA", notes_pin), "R12_SHA", background_pin)
    emit("prepare_background_v48_r1.py", "prepare_background_v46_r1.py", guard(prepare, "execute", "apk_sha256"))
    identity_path = a.identity_helper or a.base / "background-prerequisites/v35_identity.py"
    identity_raw = read(identity_path)
    need(digest(identity_raw) == "a4a751cf03956783e551f54b16dd37769f00d5b7cd2a0225b667becbc6e6d003", "original operation lock helper changed")
    (a.out / "v35_identity.py").write_bytes(identity_raw)
    manifest = {"schema": "hepta.phone-v48-preparation.v1", "status": "frozen_from_actual_build_artifacts" if frozen else "draft_all_device_entries_disabled",
                "device_contacted": False, "remote_executed": False, "owner_511205_accessed_or_interrupted": False,
                "base_manifest_sha256": BASE_MANIFEST_SHA, "expected_previous_version": 46, "expected_previous_apk_sha256": OLD_APK_SHA,
                "build_identity": identity, "artifacts": artifacts, "files": entries,
                "integrated_evidence_sha256": integration_pins,
                "identity_helper_sha256": digest(identity_raw), "source_tools": str(a.source / "tools"),
                "calculator_owner": CALCULATOR_OWNER, "calculator_owner_sha256": digest(CALCULATOR_OWNER.encode()),
                "old_business_predicates_removed": False, "new_controller_calculator_proof_required": True,
                "qualified": False, "phone_tested": False, "runtime_config_sha256": None,
                "current_device_uid": None, "current_terminal_task_id": None}
    (a.out / "MANIFEST.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    (a.out / "ADAPTERS.diff").write_text("".join(deltas))
    print(json.dumps({"status": manifest["status"], "files": len(entries) + 1, "manifest_sha256": digest((a.out / "MANIFEST.json").read_bytes()), "phone_tested": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()
