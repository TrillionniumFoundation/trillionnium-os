"""Separate UI-Venus App worker packaging gate. No inference, downloading or phone access."""
import hashlib
import json
from pathlib import Path
import re

from verify_mobimind_runtime import _read_regular


def load_pins(source_root):
    root = Path(source_root)
    pins = json.loads((root / "native/ui-venus-runtime-pins.json").read_text())
    if pins.get("schema") != "hepta.ui-venus.app-worker-packaging.v1" or pins.get("geniex_release_member") is not False:
        raise RuntimeError("UI-Venus App worker provenance differs")
    if pins.get("worker_build_qualified") is not True:
        raise RuntimeError("UI-Venus ordinary-App worker has no qualified independent Android build pin")
    member = pins["worker"]
    if member.get("apk_name") != "libhepta_ui_venus_runner.so" or member.get("source_name") != member["apk_name"]:
        raise RuntimeError("UI-Venus worker filename differs")
    if type(member.get("bytes")) is not int or member["bytes"] <= 0 or not re.fullmatch(r"[0-9a-f]{64}", member.get("sha256", "")):
        raise RuntimeError("UI-Venus complete worker identity is missing")
    for field in ("build_receipt_sha256", "native_source_manifest_sha256", "source_generation_sha256",
                  "runtime_core_source_sha256", "build_helper_sha256", "source_boundary_sha256",
                  "baseline_app_source_generation_sha256"):
        if not isinstance(pins.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", pins[field]):
            raise RuntimeError("UI-Venus build provenance is incomplete: " + field)
    if not isinstance(member.get("needed"), list) or len(member["needed"]) != len(set(member["needed"])):
        raise RuntimeError("UI-Venus ELF dependencies are incomplete or duplicated")
    if member.get("runpath") != "$ORIGIN":
        raise RuntimeError("UI-Venus worker search path differs")
    java = (root / "src/org/trillionnium/hepta/local/UiVenusPins.java").read_text()
    if re.findall(r'\bWORKER\s*=\s*"([^"]+)"', java) != [member["apk_name"]] or \
       re.findall(r'\bWORKER_SHA\s*=\s*"([0-9a-f]{64})"', java) != [member["sha256"]] or \
       re.findall(r'\bWORKER_BYTES\s*=\s*(\d+)L', java) != [str(member["bytes"])]:
        raise RuntimeError("Java and packaging UI-Venus worker pins differ")
    if pins.get("model_profile") != "ui-venus2-9b-q4_0-f16-mmproj" or \
       re.findall(r'\bPROFILE\s*=\s*"([^"]+)"', java) != [pins["model_profile"]]:
        raise RuntimeError("UI-Venus explicit Q4_0 profile differs")
    bodies = re.findall(r'public static FilePin\[\] models\(\)\{return new FilePin\[\]\{(.*?)\};\}', java, re.S)
    if len(bodies) != 1:
        raise RuntimeError("UI-Venus model array is ambiguous")
    pattern = r'new FilePin\("([^"]+)",(\d+)L,"([0-9a-f]{64})"\)'
    rows = [{"name": name, "bytes": int(size), "sha256": sha} for name, size, sha in re.findall(pattern, bodies[0])]
    if rows != [pins.get("model"), pins.get("mmproj")] or re.sub(pattern, "", bodies[0]).strip(" \r\n\t,"):
        raise RuntimeError("UI-Venus Java and native model pair differ")
    sdk = json.loads((root / "provenance/ui-venus-app-r1/sdk-runtime-pins.json").read_text())
    if pins.get("sdk_source_commit") != sdk["sdk_commit"] or pins.get("llama_source_commit") != sdk["llama_commit"]:
        raise RuntimeError("UI-Venus SDK source identities differ")
    for pin in sdk["files"]:
        expression = r'new FilePin\("' + re.escape(pin["name"]) + r'",' + str(pin["bytes"]) + r'L,"' + pin["sha256"] + r'"\)'
        if len(re.findall(expression, java)) != 1:
            raise RuntimeError("UI-Venus Java fixed SDK closure differs: " + pin["name"])
    return pins


def verify_worker_dynamic(dynamic, member):
    tags = re.findall(r"\((RUNPATH|RPATH)\)", dynamic)
    paths = re.findall(r"\((RUNPATH|RPATH)\).*?\[([^]]*)\]", dynamic)
    if tags != ["RUNPATH"] or paths != [("RUNPATH", "$ORIGIN")]:
        raise RuntimeError("UI-Venus App worker requires only non-transitive $ORIGIN RUNPATH")
    needed = re.findall(r"\(NEEDED\).*?\[([^]]+)\]", dynamic)
    if needed != member["needed"]:
        raise RuntimeError("Actual UI-Venus App ELF dependency list differs")
    return {"worker_runpath": "$ORIGIN", "needed": needed, "runtime_maps_proven": False}



def verify_q4_0_source_scope(pins, receipt, generation, boundary, baseline, original_core, actual_core):
    """Validate the deliberately narrow model-identity delta, without execution."""
    common = {"profile": pins["model_profile"], "model": pins["model"], "mmproj": pins["mmproj"],
        "context_tokens": 8192, "max_tokens": 1024, "deadline_ms": 300000, "enable_thinking": True,
        "original_core_byte_unchanged": False, "only_model_identity_literals_changed": True,
        "runtime_core_source_sha256": pins["runtime_core_source_sha256"],
        "baseline_app_source_generation_sha256": pins["baseline_app_source_generation_sha256"],
        "original_shell_candidate_modified": False, "ordinary_app_qualified": False,
        "phone_contacted": False, "full_multimodal_token_admission_proven": False, "no_context_shift_proven": False}
    for document in (receipt, generation):
        if any(type(document.get(k)) is not type(v) or document[k] != v for k, v in common.items()):
            raise RuntimeError("Q4_0 native model, budget or source scope differs")
    if receipt.get("build_helper_sha256") != pins["build_helper_sha256"] or receipt.get("source_boundary") != boundary:
        raise RuntimeError("Q4_0 actual builder/boundary differs")
    expected = {"schema": "hepta.ui-venus.app-q4_0-native-boundary.v1", "passed": True,
        "baseline_source_generation_sha256": pins["baseline_app_source_generation_sha256"],
        "original_files": 19, "original_files_unchanged": 18,
        "original_files_changed": ["native/venus-runtime.inc"], "changed_literal_count": 4,
        "only_model_identity_literals_changed": True, "original_core_byte_unchanged": False,
        "worker_c_and_app_wrapper_bytes_unchanged": True, "same_directory_bootstrap_byte_unchanged": True,
        "entry_guard_bytes_unchanged": True, "phone_contact": False, "inference_run": False}
    if any(type(boundary.get(k)) is not type(v) or boundary[k] != v for k, v in expected.items()):
        raise RuntimeError("Q4_0 19-file/4-literal boundary differs")
    old_rows = {r["path"]: r for r in baseline["files"]}
    new_rows = {r["path"]: r for r in generation["files"]}
    if len(old_rows) != 19 or len(baseline["files"]) != 19 or len(new_rows) != 19 or len(generation["files"]) != 19 or set(old_rows) != set(new_rows):
        raise RuntimeError("Q4_0 original native membership differs")
    changed = [name for name in old_rows if old_rows[name] != new_rows[name]]
    if changed != ["native/venus-runtime.inc"]:
        raise RuntimeError("Q4_0 changed more than the runtime model literals")
    rows = boundary.get("files", [])
    if len(rows) != 19 or {r["path"] for r in rows} != set(new_rows):
        raise RuntimeError("Q4_0 boundary membership is incomplete or duplicated")
    for row in rows:
        name = row["path"]
        expected_row = dict(new_rows[name], original_sha256=old_rows[name]["sha256"],
                            unchanged_from_original_app=name != "native/venus-runtime.inc")
        if row != expected_row:
            raise RuntimeError("Q4_0 boundary row differs: " + name)
    replacements = [
        (b"ui-venus2-9b-q4_k_m-f16-mmproj", pins["model_profile"].encode()),
        (b"UI-Venus-2-9B-Q4_K_M.gguf", pins["model"]["name"].encode()),
        (b"5910782752", str(pins["model"]["bytes"]).encode()),
        (b"f2a8533b4adf7dc92d0731c39bd910438d229593f2e524b8f6e0e0e83fd1ec8d", pins["model"]["sha256"].encode())]
    expected_core = original_core
    for old, new in replacements:
        if expected_core.count(old) != 1:
            raise RuntimeError("Q4_0 baseline literal cardinality differs")
        expected_core = expected_core.replace(old, new)
    if expected_core != actual_core or hashlib.sha256(actual_core).hexdigest() != pins["runtime_core_source_sha256"]:
        raise RuntimeError("Q4_0 runtime contains a non-identity source change")


def verify_ui_venus_runtime(source_root, runtime_dir):
    root, runtime = Path(source_root), Path(runtime_dir)
    pins = load_pins(root)
    raw = _read_regular(runtime / "BUILD-RECEIPT.json", 131072)
    if hashlib.sha256(raw).hexdigest() != pins["build_receipt_sha256"]:
        raise RuntimeError("UI-Venus actual Android build receipt differs")
    if raw != _read_regular(root / "provenance/ui-venus-app-r1/NATIVE-BUILD-RECEIPT.json", 131072):
        raise RuntimeError("UI-Venus build receipt is not the preserved frozen provenance")
    receipt = json.loads(raw)
    if receipt.get("schema") != pins["build_receipt_schema"]:
        raise RuntimeError("UI-Venus Android build schema differs")
    source = root / "provenance/ui-venus-app-r1/native-worker"
    manifest = _read_regular(source / "DRAFT-MANIFEST.json", 131072)
    if hashlib.sha256(manifest).hexdigest() != pins["native_source_manifest_sha256"]:
        raise RuntimeError("UI-Venus independent wrapper source manifest differs")
    membership = json.loads(manifest)
    if membership.get("schema") != "hepta.ui-venus.app-native-source-manifest.v1":
        raise RuntimeError("UI-Venus independent source manifest schema differs")
    names=set()
    for row in membership["files"]:
        relative=Path(row["path"])
        if relative.is_absolute() or ".." in relative.parts or str(relative) in names:
            raise RuntimeError("UI-Venus wrapper source membership is unsafe or duplicated")
        names.add(str(relative));path=source/relative
        if path.resolve(strict=True)!=path:
            raise RuntimeError("UI-Venus wrapper source alias rejected")
        data=_read_regular(path,max(1,row["bytes"]))
        if len(data)!=row["bytes"] or hashlib.sha256(data).hexdigest()!=row["sha256"]:
            raise RuntimeError("UI-Venus wrapper source bytes differ: "+str(relative))
    generation=_read_regular(source/"SOURCE-GENERATION.json",131072)
    if hashlib.sha256(generation).hexdigest()!=pins["source_generation_sha256"]:
        raise RuntimeError("UI-Venus source-generation receipt differs")
    boundary_raw=_read_regular(source/"SOURCE-BOUNDARY.json",131072)
    if hashlib.sha256(boundary_raw).hexdigest()!=pins["source_boundary_sha256"]:
        raise RuntimeError("Q4_0 preserved native boundary differs")
    baseline_raw=_read_regular(source/"provenance/ORIGINAL-APP-SOURCE-GENERATION.json",131072)
    if hashlib.sha256(baseline_raw).hexdigest()!=pins["baseline_app_source_generation_sha256"]:
        raise RuntimeError("Q4_0 original App source generation differs")
    helper_raw=_read_regular(source/"tools/build_android.py",131072)
    if hashlib.sha256(helper_raw).hexdigest()!=pins["build_helper_sha256"]:
        raise RuntimeError("Q4_0 actual Android build helper differs")
    verify_q4_0_source_scope(pins,receipt,json.loads(generation),json.loads(boundary_raw),json.loads(baseline_raw),
        _read_regular(source/"provenance/ORIGINAL-APP-venus-runtime.inc",131072),
        _read_regular(source/"native/venus-runtime.inc",131072))
    expected={"sdk_source_commit":pins["sdk_source_commit"],"llama_source_commit":pins["llama_source_commit"],
              "source_generation_sha256":pins["source_generation_sha256"],"worker_source_sha256":pins["core_source_sha256"],
              "wrapper_source_sha256":pins["wrapper_source_sha256"],"entry_guard_sha256":pins["entry_guard_sha256"],
              "actual_ndk_revision":pins["actual_ndk_revision"],"original_core_byte_unchanged":False,
              "original_shell_candidate_modified":False,"android_executed":False,"model_inference_performed":False,
              "ordinary_app_qualified":False,"dispatcher_connected":False,"phone_contacted":False}
    if any(type(receipt.get(k)) is not type(v) or receipt[k]!=v for k,v in expected.items()):
        raise RuntimeError("UI-Venus actual Android build/source scope differs")
    member = pins["worker"]
    expected_worker={"name":member["source_name"],"bytes":member["bytes"],"sha256":member["sha256"],
                     "elf_machine":"AArch64","elf_type":"DYN-PIE","dt_needed":member["needed"],"runpath":["$ORIGIN"]}
    if receipt.get("worker")!=expected_worker:
        raise RuntimeError("UI-Venus built worker metadata differs from packaging identity")
    sdk=json.loads((root/"provenance/ui-venus-app-r1/sdk-runtime-pins.json").read_text())
    sdk_rows=[{k:row[k] for k in ("name","bytes","sha256")} for row in receipt["sdk_libraries"]]
    if sdk_rows!=sdk["files"]:
        raise RuntimeError("UI-Venus actual build did not verify the same twelve SDK members")
    path = runtime / member["source_name"]
    data = _read_regular(path, member["bytes"])
    if len(data) != member["bytes"] or hashlib.sha256(data).hexdigest() != member["sha256"]:
        raise RuntimeError("UI-Venus ordinary-App worker differs; the shell worker is not interchangeable")
    return {member["apk_name"]: {**member, "path": path,
             "provenance": "independent_ui_venus_app_android_build",
             "build_receipt_sha256": pins["build_receipt_sha256"]}}
