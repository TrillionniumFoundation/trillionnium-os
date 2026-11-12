#!/usr/bin/env python3
"""Offline v56 artifact byte binding. This is not a phone test or a launch gate.

Every candidate identity is an explicit, hash-pinned input. Unknown identities
are rejected. Success only permits further adapter review: it does not remove
the existing source-aware binder, preparation, native, or result checks.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from offline_common import COMMIT, checked_file_hash, checked_read, exact_keys, need, require_sha, strict_json, write_new_json

PACKAGE = "org.trillionnium.hepta.local"
NOTES = "com.motorola.stylus"
ORIGINAL_SIGNER = "202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5"
COUNT_KEYS = {"source_file_count", "actual_compiler_source_inputs", "host_check_records", "host_input_count", "packaged_library_count"}
CANDIDATE_KEYS = {"schema", "package", "version_code", "source_commit",
                  "source_inventory_sha256", "apk_sha256", "build_receipt_sha256", "build_receipt_schema",
                  "signer_certificate_sha256", "signer_proof_sha256", "build_counts",
                  "runtime_config_sha256", "runtime", "device"}
RUNTIME_KEYS = {"compute", "context_tokens", "threads", "model_profile", "model_sha256"}
RUNTIME_CONFIG_KEYS = {"schema", "model_profile", "compute", "context_tokens", "threads"}
DEVICE_KEYS = {"expected_uid", "target_package", "main_physical_display_id"}


def validate_candidate(candidate):
    exact_keys(candidate, CANDIDATE_KEYS, "candidate")
    need(candidate["schema"] == "hepta.notes-v56-candidate.v1", "candidate schema unsupported")
    need(candidate["package"] == PACKAGE, "Hepta package differs")
    need(type(candidate["version_code"]) is int and candidate["version_code"] == 56, "explicit v56 required")
    need(type(candidate["source_commit"]) is str and COMMIT.fullmatch(candidate["source_commit"]),
         "actual source commit required")
    for field in ("source_inventory_sha256", "apk_sha256", "build_receipt_sha256",
                  "signer_certificate_sha256", "signer_proof_sha256", "runtime_config_sha256"):
        require_sha(candidate[field], field)
    need(candidate["signer_certificate_sha256"] == ORIGINAL_SIGNER, "original installed signer required")
    need(type(candidate["build_receipt_schema"]) is str and 1 <= len(candidate["build_receipt_schema"]) <= 128,
         "reviewed build receipt schema required; no schema inference")
    exact_keys(candidate["build_counts"], COUNT_KEYS, "build counts")
    need(all(type(n) is int and 1 <= n <= 1000000 for n in candidate["build_counts"].values()),
         "positive exact integer build counts required")
    runtime = candidate["runtime"]
    exact_keys(runtime, RUNTIME_KEYS, "runtime")
    need(runtime["compute"] in ("npu", "gpu"), "phone GPU/NPU profile required")
    need(type(runtime["context_tokens"]) is int and runtime["context_tokens"] in (4096, 8192),
         "reviewed bounded context required")
    need(type(runtime["threads"]) is int and 1 <= runtime["threads"] <= 8, "explicit canonical 1..8 threads required")
    need(type(runtime["model_profile"]) is str and 1 <= len(runtime["model_profile"]) <= 128,
         "model profile required")
    require_sha(runtime["model_sha256"], "model hash")
    device = candidate["device"]
    exact_keys(device, DEVICE_KEYS, "device")
    need(type(device["expected_uid"]) is int and 10000 <= device["expected_uid"] < 90000,
         "actual ordinary package UID required")
    need(device["target_package"] == NOTES, "this artifact binding covers Moto Notes only")
    physical = device["main_physical_display_id"]
    need(type(physical) is str and physical.isascii() and physical.isdigit()
         and str(int(physical)) == physical and 0 < int(physical) < 1 << 64,
         "observed canonical main physical display ID required")


def validate_runtime_config(config):
    """Explicit-profile v2 case contract from canonical LocalRuntimeConfig.java.

    Production also reads a four-field legacy v1 config. This v56 qualification
    deliberately requires the actual five-field v2 profile; it never infers one.
    """
    exact_keys(config, RUNTIME_CONFIG_KEYS, "runtime config")
    need(config["schema"] == "hepta.local-runtime.v2", "explicit runtime v2 schema required")
    need(type(config["model_profile"]) is str and 1 <= len(config["model_profile"]) <= 128,
         "explicit runtime model profile required")
    need(config["compute"] in ("npu", "gpu"), "runtime compute differs")
    need(type(config["context_tokens"]) is int and config["context_tokens"] in (4096, 8192),
         "runtime context differs")
    need(type(config["threads"]) is int and 1 <= config["threads"] <= 8, "runtime threads must be 1..8")


def bind_artifacts(candidate, receipt, config):
    validate_candidate(candidate)
    need(type(receipt) is dict, "build receipt object required")
    for key in ("all_pass", "matches_previously_recorded_signer", "source_files_unchanged",
                "actual_compiler_inputs_bound_to_signed_asset"):
        need(receipt.get(key) is True, "existing signed build gate failed: " + key)
    fields = ("source_commit", "apk_sha256", "source_inventory_sha256", "version_code",
              "signer_certificate_sha256", "signer_proof_sha256")
    for key in fields:
        need(type(receipt.get(key)) is type(candidate[key]) and receipt[key] == candidate[key],
             "signed receipt identity differs: " + key)
    need(receipt.get("schema") == candidate["build_receipt_schema"], "signed receipt schema differs")
    for key, expected in candidate["build_counts"].items():
        need(type(receipt.get(key)) is int and receipt[key] == expected, "signed build count differs: " + key)
    validate_runtime_config(config)
    for key in ("compute", "context_tokens", "threads", "model_profile"):
        need(type(config.get(key)) is type(candidate["runtime"][key]) and config[key] == candidate["runtime"][key],
             "runtime configuration differs: " + key)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "build-receipt", "source-inventory", "apk", "runtime-config", "out"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--candidate-sha256", required=True)
    args = p.parse_args()
    result = {"schema": "hepta.notes-v56-offline-artifact-preflight.v1",
              "artifact_byte_binding_passed": False, "phone_execution_ready": False,
              "phone_operations": 0, "original_artifacts_modified": False,
              "full_phone_qualification": False}
    try:
        candidate_raw = checked_read(args.candidate, args.candidate_sha256, 65536)
        candidate = strict_json(candidate_raw)
        validate_candidate(candidate)
        receipt = strict_json(checked_read(args.build_receipt, candidate["build_receipt_sha256"], 8 << 20))
        inventory = checked_file_hash(args.source_inventory, candidate["source_inventory_sha256"], 64 << 20)
        apk = checked_file_hash(args.apk, candidate["apk_sha256"], 512 << 20)
        config = strict_json(checked_read(args.runtime_config, candidate["runtime_config_sha256"], 16384))
        bind_artifacts(candidate, receipt, config)
        result.update(artifact_byte_binding_passed=True, candidate_sha256=args.candidate_sha256,
                      candidate=candidate, source_inventory=inventory, apk=apk)
    except Exception as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    result["remaining_mandatory_gates"] = [
        "Review actual v56 receipt semantics and independently rehash its complete source inventory",
        "Retrieve and hash every original/replay helper; preserve source-aware binder and all negative controls",
        "Seal minimal v56 helper changes against exact final source/APK/compiler inputs",
        "Obtain normal owner release and fresh idle/cleanup/authority evidence before any phone operation",
        "Fresh v56 ordinary preparation and Start proof; no historical preparation reuse",
        "Fresh native model/tool-child/body/save-list-reopen/cleanup checks",
        "Fresh same-task main-display protocol plus independently reviewed semantic scroll evidence",
    ]
    record = write_new_json(args.out, result)
    print(record)
    return 0 if result["artifact_byte_binding_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
