#!/usr/bin/env python3
"""Create one private v32/Orvena scope packet from actual build and role evidence.

Host files only. This script neither installs the scope nor contacts a phone.
Missing real APK/compiler/package inputs are errors, never template identities.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent / "drivers"))
from types import ModuleType
_scope_path = Path(__file__).resolve().parent / "drivers/qualification_scope.py"
_scope_raw = _scope_path.read_bytes()
scope = ModuleType("qualification_scope"); scope.__file__ = str(_scope_path)
sys.modules["qualification_scope"] = scope
exec(compile(_scope_raw, str(_scope_path), "exec", dont_inherit=True), scope.__dict__)

SOURCE_COMMIT = "e07c6624b7309b0acf3fe10e31b0605a29e3e72d"
BUILD_HELPER_SHA = "7d5ad2641e9a3635fd04aa47ce3ea50a1a4f16b883a98b2ab407878eef36f6e6"
EXPECTED_INVENTORY_SHA = "557d48bfa14b64d9cdb387e878f73253ca75d5fac07c9cf3e1f640a76c1e94b1"
PORTABLE_INVENTORY_SHA = "b9c1355c16658c354550aad818053e9e5d8bb12ce7150d7b861de109a1000b90"


def full_source_inventory(source, integration_raw):
    raw = scope.read(Path(__file__).resolve().parent / "reference/EXPECTED-FULL-V32-INVENTORY.json")
    scope.need(scope.sha(raw) == EXPECTED_INVENTORY_SHA, "qualified v32 complete inventory changed")
    expected = scope.strict(raw)
    scope.need(expected.get("portable_inventory_sha256") == PORTABLE_INVENTORY_SHA
               and len(expected.get("files", [])) == 1194, "qualified inventory membership differs")
    source = Path(source).resolve(strict=True)
    for row in expected["files"]:
        relative = Path(row["path"])
        scope.need(not relative.is_absolute() and ".." not in relative.parts, "unsafe compiler input path")
        path = source / relative
        scope.need(path.resolve(strict=True).is_relative_to(source), "input escapes complete source")
        data = scope.read(path, 32 << 20)
        git_blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        scope.need(len(data) == row["bytes"] and scope.sha(data) == row["sha256"] and git_blob == row["git_blob_sha"],
                   "actual complete source differs: " + row["path"])
    integration = scope.strict(integration_raw)
    scope.need(integration.get("schema") == "hepta.independent-v32-source-integration.v1"
               and integration.get("source_commit") == SOURCE_COMMIT
               and integration.get("source_tree") == "81955c2053ba24cab0783c9cb7636a49c0f186de"
               and integration.get("actual_source_assembly_verified") is True
               and type(integration.get("file_count")) is int and integration["file_count"] == 1194
               and integration.get("portable_inventory_sha256") == PORTABLE_INVENTORY_SHA
               and scope.equal(integration.get("files"), expected["files"]),
               "actual independent source integration receipt absent or differs")
    return PORTABLE_INVENTORY_SHA


def full_file_hash(path):
    path = Path(path); before = path.lstat()
    scope.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 512 << 20,
               "APK not a bounded regular file")
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""): digest.update(block)
        after = os.fstat(stream.fileno())
    def identity(s): return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    scope.need(identity(before) == identity(after) == identity(path.lstat()), "APK changed while hashing")
    return digest.hexdigest(), before.st_size


def actual_build(source, apk, mac_raw, static_raw):
    source = Path(source).resolve(strict=True)
    helper = source / "tools/build_identity.py"
    helper_raw = scope.read(helper)
    scope.need(scope.sha(helper_raw) == BUILD_HELPER_SHA, "actual build identity selector differs from qualified v32")
    module = ModuleType("hepta_v32_actual_build_selector"); module.__file__ = str(helper)
    sys.modules[module.__name__] = module
    exec(compile(helper_raw, str(helper), "exec", dont_inherit=True), module.__dict__)
    mac = scope.strict(mac_raw)
    asset = module.actual_build_identity(source, mac)
    value = scope.strict(asset)
    scope.need(value["version_code"] == 32, "complete compiler source is not version 32")
    expected = scope.strict(scope.read(Path(__file__).resolve().parent / "reference/EXPECTED-FULL-V32-INVENTORY.json"))
    known = {row["path"]: row["sha256"] for row in expected["files"]}
    scope.need(len(value["source_inputs"]) == 163 and all(known.get(row["path"]) == row["sha256"] for row in value["source_inputs"]),
               "compiler input was not part of the reviewed final source")
    apk_sha, apk_bytes = full_file_hash(apk)
    with zipfile.ZipFile(apk) as archive:
        rows = [item for item in archive.infolist() if item.filename == scope.ASSET_NAME]
        scope.need(len(rows) == 1 and 0 < rows[0].file_size <= 131072 and not rows[0].flag_bits & 1,
                   "APK asset absent, duplicated, encrypted or oversize")
        packaged = archive.read(rows[0])
    scope.need(packaged == asset, "signed APK build asset differs from actual complete compiler input map")
    receipt = scope.strict(static_raw)
    scope.need(receipt.get("schema") == "hepta.local-model.static-acceptance.v3"
               and receipt.get("apk_sha256") == apk_sha and receipt.get("apk_bytes") == apk_bytes
               and receipt.get("package") == scope.PACKAGE and type(receipt.get("version_code")) is int
               and receipt["version_code"] == 32 and receipt.get("actual_build_identity_asset") == scope.ASSET_NAME
               and receipt.get("actual_build_identity_sha256") == scope.sha(asset)
               and scope.equal(receipt.get("permissions"), []), "exact signed APK static acceptance differs")
    # No actual installation or signer-match claim is inferred from this host step.
    return asset, apk_sha, apk_bytes


def role_fields(raw, observations):
    value = scope.strict(raw)
    scope.need(isinstance(value, dict) and set(value) == {"schema", "launcher_component", "roles", "original_evidence"}
               and value["schema"] == "hepta.scope-installed-role-identities.v1", "role inventory schema")
    roles = value["roles"]
    scope.need(isinstance(roles, dict) and set(roles) == set(scope.ROLES), "all four exact roles required")
    evidence = value["original_evidence"]
    scope.need(isinstance(evidence, list) and evidence, "fresh original package identity evidence absent")
    for row in evidence:
        scope.need(isinstance(row, dict) and set(row) == {"path", "sha256"}, "identity original pin fields")
        source = scope.read(Path(row["path"]))
        scope.need(scope.sha(source) == row["sha256"], "fresh package original changed")
    fields = {"launcher_component": value["launcher_component"]}
    proofs = {}
    for role, package in scope.ROLES.items():
        entry = roles[role]
        scope.need(isinstance(entry, dict) and set(entry) == {"package", "uid", "version_code", "enabled",
                   "apk_rows", "apk_set_sha256", "stable_before_after"}, "installed role fields")
        scope.need(entry["package"] == package and entry["enabled"] is True and entry["stable_before_after"] is True,
                   "role package disabled, guessed or not stable")
        uid = entry["uid"]
        scope.need(type(uid) is int and 0 <= uid <= (1 << 31) - 1 and scope.positive_int(entry["version_code"]),
                   "role UID/version malformed")
        apk_set = scope.apk_set_sha(entry["apk_rows"])
        scope.need(apk_set == entry["apk_set_sha256"], "base APK hash is not an APK-set hash")
        original = scope.read(Path(observations) / (role + ".json"), 2 << 20)
        proof = scope.validate_original_observation(original, package)
        proofs[role] = original
        fields.update({role + "_package": package, role + "_uid": uid,
                       role + "_version_code": entry["version_code"], role + "_apk_set_sha256": apk_set,
                       role + "_observation_sha256": proof["sha256"]})
    return fields, proofs


def prepare(args):
    target = scope.validate_device_target({key: getattr(args, key) for key in
        ("serial", "logical_display_id", "physical_display_id", "input_width", "input_height")})
    integration_raw = scope.read(args.source_integration_manifest)
    portable = full_source_inventory(args.source, integration_raw)
    mac_raw = scope.read(args.mac_build_receipt)
    static_raw = scope.read(args.static_acceptance)
    asset, apk_sha, apk_bytes = actual_build(args.source, args.apk, mac_raw, static_raw)
    runtime_raw = scope.read(args.runtime_config, 4096); runtime = scope.strict(runtime_raw)
    candidate = {"package": scope.PACKAGE, "apk_sha256": apk_sha, "version_code": 32,
                 "model_profile": scope.PROFILE, "model_sha256": scope.MODEL_SHA,
                 "compute": args.compute, "context_tokens": 8192, "threads": 4}
    scope.validate_candidate(candidate)
    expected_runtime = {"schema": "hepta.local-runtime.v2", **{k: candidate[k]
                        for k in ("model_profile", "compute", "context_tokens", "threads")}}
    scope.need(scope.equal(runtime, expected_runtime), "explicit 8192/4 runtime bytes differ from chosen axis")
    scope.need(type(args.app_uid) is int and 10000 <= args.app_uid <= (1 << 31) - 1, "ordinary App UID required")
    roles_raw = scope.read(args.role_identities)
    roles, observations = role_fields(roles_raw, args.observations)
    value = {"schema": "hepta.qualification-scope.v1", "enabled": True,
             "qualification_id": args.qualification_id, "build_identity_sha256": scope.sha(asset),
             "runtime_config_sha256": scope.sha(runtime_raw), "hepta_apk_sha256": apk_sha,
             "hepta_version_code": 32, **roles}
    config_raw = scope.encoded(value); scope.validate_scope(config_raw)
    files = {"qualification-scope.json": config_raw, "build-identity.json": asset,
             "runtime-config.json": runtime_raw, "mac-build-receipt.json": mac_raw,
             "static-acceptance.json": static_raw, "role-identities.json": roles_raw,
             "source-integration-manifest.json": integration_raw,
             **{"observations/" + role + ".json": raw for role, raw in observations.items()}}
    binding = {"schema": scope.SCHEMA, "phone_contacted": False, "source_commit": SOURCE_COMMIT,
               "device_target": target,
               "source_directory": str(Path(args.source).resolve(strict=True)), "candidate": candidate,
               "complete_source_inventory_sha256": scope.sha(integration_raw), "portable_source_inventory_sha256": portable,
               "app_uid": args.app_uid, "scope_sha256": scope.sha(config_raw),
               "build_identity_sha256": scope.sha(asset), "runtime_config_sha256": scope.sha(runtime_raw),
               "actual_apk_bytes": apk_bytes, "sampler_requested": scope.expected_sampler(),
               "model_file": "Orvena-4B.Q4_K_M.gguf", "model_bytes": scope.MODEL_BYTES,
               "model_loaded_by_this_host_preparation": False, "installed_identity_proven_by_this_preparation": False,
               "source_identity_method": "actual complete source_inputs == Mac receipt == signed APK asset",
               "root_SOURCE_MANIFEST_used_as_current_source_identity": False,
               "files": {name: {"bytes": len(raw), "sha256": scope.sha(raw)} for name, raw in files.items()}}
    output = Path(args.output).resolve()
    scope.need(not output.exists(), "new output directory required")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, raw in files.items(): scope.private_write(output / name, raw)
    scope.private_write(output / "BINDING.json", scope.encoded(binding))
    binding_sha = scope.sha(scope.read(output / "BINDING.json"))
    scope.load_binding(output / "BINDING.json", binding_sha)
    print(json.dumps({"binding": str(output / "BINDING.json"), "binding_sha256": binding_sha,
                      "scope_sha256": binding["scope_sha256"], "candidate": candidate,
                      "phone_contacted": False, "scope_installed": False}, ensure_ascii=False, indent=2))


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True, help="complete final source, never the review subset")
    p.add_argument("--apk", type=Path, required=True)
    p.add_argument("--mac-build-receipt", type=Path, required=True)
    p.add_argument("--source-integration-manifest", type=Path, required=True)
    p.add_argument("--static-acceptance", type=Path, required=True)
    p.add_argument("--runtime-config", type=Path, required=True)
    p.add_argument("--role-identities", type=Path, required=True)
    p.add_argument("--observations", type=Path, required=True)
    p.add_argument("--app-uid", type=int, required=True)
    p.add_argument("--serial", required=True, help="exact operator-selected device; retained only in the private binding")
    p.add_argument("--logical-display-id", type=int, required=True)
    p.add_argument("--physical-display-id", required=True)
    p.add_argument("--input-width", type=int, required=True)
    p.add_argument("--input-height", type=int, required=True)
    p.add_argument("--compute", choices=("npu", "gpu"), required=True)
    p.add_argument("--qualification-id", required=True)
    p.add_argument("--output", type=Path, required=True)
    return p


if __name__ == "__main__":
    try:
        prepare(parser().parse_args())
    except (ValueError, OSError, KeyError, RuntimeError, zipfile.BadZipFile) as error:
        print(json.dumps({"error": str(error), "phone_contacted": False, "scope_installed": False}), file=sys.stderr)
        sys.exit(2)
