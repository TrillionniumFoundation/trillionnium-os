#!/usr/bin/env python3
"""Bind the separate VLM runtime to one clean checkout and workflow attempt.

This is a producer/consumer transport check. It neither compiles an APK nor
executes an Android worker, signs, contacts a phone, or claims device acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from build_identity import source_inputs
from verify_mobimind_runtime import _read_regular
from verify_vlm_runtime import verify_vlm_runtime

TRANSFER_NAME = "CURRENT-CI-TRANSFER.json"
WORKFLOW_REL = ".github/workflows/hepta-local-android.yml"
CI_FILES = ("tools/vlm_ci_transfer.py", "tests/test_vlm_ci_transfer.py",
            "tests/test_vlm_runtime.py")


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "duplicate VLM transfer JSON member")
            value[key] = item
        return value
    def nonfinite(value):
        raise RuntimeError("nonfinite VLM transfer JSON value: " + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def binding(repo, source, runtime, source_head, repository, run_id, run_attempt):
    repo = Path(repo).resolve(strict=True)
    source = Path(source).resolve(strict=True)
    runtime = Path(runtime).resolve(strict=True)
    need(re.fullmatch(r"[0-9a-f]{40}", source_head), "exact checkout SHA required")
    need(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "repository identity required")
    need(re.fullmatch(r"[1-9][0-9]*", run_id) and re.fullmatch(r"[1-9][0-9]*", run_attempt),
         "positive workflow run and attempt required")
    need(source.is_relative_to(repo) and source != repo, "source must be within checkout")
    relative = source.relative_to(repo).as_posix()
    need(git(repo, "rev-parse", "--verify", "HEAD") == source_head, "checked-out source head differs")
    need(not git(repo, "status", "--porcelain=v1", "--untracked-files=all", "--", relative, WORKFLOW_REL),
         "VLM transfer requires a clean tracked source and workflow")
    workflow = repo / WORKFLOW_REL
    need(workflow.resolve(strict=True) == workflow, "workflow alias rejected")
    workflow_raw = _read_regular(workflow, 262144)
    rows = verify_vlm_runtime(source, runtime)
    member = rows["libhepta_local_vlm_runner.so"]
    receipt_raw = _read_regular(runtime / "BUILD-RECEIPT.json", 131072)
    receipt = strict_json(receipt_raw)
    reference = strict_json(_read_regular(source / "native/vlm-worker/provenance/ANDROID-BUILD-R4.json", 131072))
    for key in ("compiler_wrapper_sha256", "source_properties_sha256"):
        need(receipt.get(key) == reference[key], "VLM CI compiler identity differs: " + key)
    need(receipt.get("compiler_version", "").splitlines()[:1] == reference["compiler_version"].splitlines()[:1]
         and "Target: aarch64-unknown-linux-android30\n" in receipt.get("compiler_version", ""),
         "VLM CI compiler target/version differs")
    inputs = []
    for relative_ci in CI_FILES:
        path = source / relative_ci
        need(path.resolve(strict=True) == path, "CI input alias rejected")
        raw = _read_regular(path, 262144)
        inputs.append({"path": relative_ci, "bytes": len(raw), "sha256": sha(raw)})
    return {
        "schema": "hepta.vlm.ci-transfer.v1",
        "repository": repository, "source_head": source_head,
        "run_id": run_id, "run_attempt": run_attempt,
        "source_path": relative, "source_inputs": source_inputs(source),
        "workflow_path": WORKFLOW_REL, "workflow_sha256": sha(workflow_raw),
        "ci_inputs": inputs,
        "source_manifest_sha256": member["source_manifest_sha256"],
        "build_receipt_sha256": sha(receipt_raw),
        "worker": {key: member[key] for key in ("apk_name", "bytes", "sha256")},
        "compiler_wrapper_sha256": receipt["compiler_wrapper_sha256"],
        "source_properties_sha256": receipt["source_properties_sha256"],
        "device_qualification_claimed": False, "phone_contacted": False,
        "signing_performed": False, "model_inference_performed": False,
    }


def perform(mode, repo, source, runtime, source_head, repository, run_id, run_attempt):
    expected = binding(repo, source, runtime, source_head, repository, run_id, run_attempt)
    path = Path(runtime).resolve(strict=True) / TRANSFER_NAME
    if mode == "bind":
        raw = (json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    elif mode == "verify":
        actual = strict_json(_read_regular(path, 262144))
        need(json.dumps(actual, sort_keys=True, separators=(",", ":"), allow_nan=False)
             == json.dumps(expected, sort_keys=True, separators=(",", ":"), allow_nan=False),
             "VLM transfer source/workflow attempt/artifact identity differs")
    else:
        raise RuntimeError("unknown VLM transfer operation")
    return {"schema": "hepta.vlm.ci-transfer-verification.v1", "operation": mode,
            "verified": True, "transfer_sha256": sha(_read_regular(path, 262144)),
            "repository": repository, "source_head": source_head,
            "run_id": run_id, "run_attempt": run_attempt,
            "worker": expected["worker"], "build_receipt_sha256": expected["build_receipt_sha256"],
            "device_qualification_claimed": False, "phone_contacted": False,
            "model_inference_performed": False, "signing_performed": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("bind", "verify"))
    for option in ("repo-root", "source", "runtime"):
        parser.add_argument("--" + option, required=True, type=Path)
    for option in ("source-head", "repository", "run-id", "run-attempt"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args()
    print(json.dumps(perform(args.operation, args.repo_root, args.source, args.runtime,
                             args.source_head, args.repository, args.run_id, args.run_attempt), sort_keys=True))
