#!/usr/bin/env python3
"""Malformed runtime-config negative cases; no successful phone case is invented."""
import argparse
import ast
import copy
import hashlib
from pathlib import Path

from offline_common import checked_read, need, sha256, write_new_json
import preflight_v56 as preflight

SOURCE_SHA = "81447620dbc2a789bba8c22d561c768144f4d5619859b202d07cd83660a05dce"
SOURCE_BLOB = "eace1ef538bb6b491ce7c13aeb26567829367477"
SOURCE_URL = "https://github.com/TrillionniumFoundation/trillionnium-os/blob/5da3c83fe46edb2617934a92c06a10608accb68e/projects/razr60/phone-local-v150/android-local/lfm3-controller/src/org/trillionnium/hepta/local/LocalRuntimeConfig.java"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    source = checked_read(args.root / "canonical-v56/src/org/trillionnium/hepta/local/LocalRuntimeConfig.java", SOURCE_SHA)
    need(hashlib.sha1(b"blob " + str(len(source)).encode() + b"\0" + source).hexdigest() == SOURCE_BLOB,
         "canonical runtime source Git blob differs")
    preflight_raw = Path(preflight.__file__).read_bytes()
    tree = ast.parse(preflight_raw)
    binder = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "bind_artifacts")
    need(sum(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "validate_runtime_config"
             for n in ast.walk(binder)) == 1, "artifact binder does not enforce the strict config contract")
    sealer = ast.parse((args.root / "seal_v56_notes.py").read_bytes())
    release = next(n for n in sealer.body if isinstance(n, ast.FunctionDef) and n.name == "validate_release")
    need(sum(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "bind_artifacts"
             for n in ast.walk(release)) == 1, "normal release seal bypasses the exact config binder")
    # Only malformed variants are submitted. This is not an observed runtime,
    # installed device, signed candidate, or positive phone qualification.
    shape = {"schema": "hepta.local-runtime.v2", "model_profile": "lfm3-1.7b-qad-q4_0",
             "compute": "npu", "context_tokens": 8192, "threads": 4}
    cases = []
    for field in sorted(shape):
        value = dict(shape); value.pop(field)
        cases.append(("missing_" + field, value))
    for name, key, bad in [
            ("extra_field", "automatic_fallback", True),
            ("wrong_schema", "schema", "hepta.local-runtime.unknown"),
            ("legacy_schema_with_v2_fields", "schema", "hepta.local-runtime.v1"),
            ("threads_above_actual_constructor_limit", "threads", 9),
            ("threads_zero", "threads", 0),
            ("threads_boolean", "threads", True),
            ("context_boolean", "context_tokens", True),
            ("context_unreviewed", "context_tokens", 16384),
            ("profile_not_string", "model_profile", False),
            ("compute_cpu_fallback", "compute", "cpu")]:
        value = dict(shape); value[key] = bad; cases.append((name, value))
    legacy = copy.deepcopy(shape); legacy["schema"] = "hepta.local-runtime.v1"; legacy.pop("model_profile")
    cases.append(("legacy_four_field_config_not_inferred_as_v2", legacy))
    results = []
    for name, value in cases:
        try:
            preflight.validate_runtime_config(value)
        except ValueError as exc:
            results.append({"name": name, "rejected": True, "reason": str(exc)})
        else:
            raise AssertionError("malformed config accepted: " + name)
    record = {"schema": "hepta.notes-v56-runtime-contract-negative-controls.v1",
              "canonical_source": {"url": SOURCE_URL, "bytes": len(source), "sha256": SOURCE_SHA, "git_blob": SOURCE_BLOB},
              "preflight_source_sha256": sha256(preflight_raw),
              "seal_source_sha256": sha256((args.root / "seal_v56_notes.py").read_bytes()),
              "exact_runtime_config_keys": sorted(preflight.RUNTIME_CONFIG_KEYS),
              "required_schema": "hepta.local-runtime.v2", "actual_constructor_threads_range": [1, 8],
              "artifact_binder_and_normal_seal_call_strict_contract": True,
              "negative_controls_rejected": len(results), "negative_controls_total": len(results), "controls": results,
              "actual_fresh_device_runtime_received": False, "successful_runtime_or_phone_case_synthesized": False,
              "phone_actions": 0, "release_sealed": False, "phone_execution_ready": False}
    print(write_new_json(args.out, record))


if __name__ == "__main__":
    main()
