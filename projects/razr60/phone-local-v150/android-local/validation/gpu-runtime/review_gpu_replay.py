#!/usr/bin/env python3
"""Offline-only review of a retained model-only replay; old files and verdicts stay unchanged."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys

import gpu_log_validation as gpu


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("duplicate JSON field: " + key)
            obj[key] = value
        return obj
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid JSON constant")))


def read(path, limit=2 * 1024 * 1024):
    if path.is_symlink() or not path.is_file() or not 0 <= path.stat().st_size <= limit:
        raise ValueError("bounded regular input required: " + str(path))
    return path.read_bytes()


def load_source(source, expected_manifest_sha):
    raw = read(source / "SOURCE-MANIFEST.json")
    manifest = strict_json(raw)
    if sha(raw) != expected_manifest_sha or manifest.get("schema") != "hepta.local-source.v3":
        raise ValueError("source manifest is not the exact replay source")
    paths = set()
    for item in manifest["files"]:
        name = item["path"]
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or name in paths:
            raise ValueError("unsafe or duplicate source member")
        paths.add(name)
        data = read(source / name)
        if sha(data) != item["sha256"] or len(data) != item["bytes"]:
            raise ValueError("source member differs: " + name)
    driver_root = source / "tools"
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(driver_root))
    for name in ("phone_acceptance", "model_profiles"):
        if name in sys.modules and Path(sys.modules[name].__file__).resolve().parent != driver_root:
            raise ValueError("another driver version is already imported")
    return importlib.import_module("phone_acceptance"), importlib.import_module("model_profiles")


def review(replay, source):
    names = ("report.json", "native-result.json", "raw-text.txt", "stderr.log", "worker-exit.txt", "prompt.txt", "system.txt", "grammar.gbnf")
    payloads = {name: read(replay / name) for name in names}
    report, native = (strict_json(payloads[name]) for name in ("report.json", "native-result.json"))
    acceptance, profiles = load_source(source, report["source_manifest_sha256"])
    selected = profiles.profile(report["model_profile"])
    run = report.get("request_id")
    if report.get("schema") != "hepta.model-only-replay.v1" or not isinstance(run, str) or not re.fullmatch(r"[a-f0-9]{32}", run):
        raise ValueError("not a bound model-only replay")
    if report.get("model_only") is not True or type(report.get("phone_actions_dispatched")) is not int or report["phone_actions_dispatched"] != 0 or report.get("phone_goal_achieved") is not False:
        raise ValueError("replay unexpectedly claims phone action authorization")
    raw = payloads["raw-text.txt"]
    raw.decode("utf-8", "strict")
    expected = {"schema": "hepta.geniex-once.result.v1", "request_id": run,
                "model_profile": report["model_profile"], "model_sha256_verified": selected["sha256"],
                "model_bytes_verified": selected["bytes"], "model_architecture": selected["architecture"],
                "model_metadata_unchanged": True, "input_metadata_unchanged": True,
                "runtime": "llama_cpp", "mode": "llm", "compute_requested": "gpu", "device_resolved": "GPUOpenCL",
                "device_warning": None, "n_ctx_create": report["context_tokens"], "max_tokens": report["max_tokens"],
                "automatic_cpu_fallback": False, "automatic_retry": False, "generate_attempt_count": 1,
                "generation_complete": True, "worker_outcome": "completed", "worker_exit_status_planned": 0,
                "raw_text_sha256": sha(raw), "raw_text_bytes": len(raw), "raw_text_utf8": True,
                "raw_text_truncated": False, "chat_template_enable_thinking": False, "deadline_observed": False, "error": None}
    native_ok = all(k in native and type(native[k]) is type(value) and native[k] == value for k, value in expected.items())
    native_ok = native_ok and type(native.get("n_gpu_layers_create")) is int and native["n_gpu_layers_create"] != 0
    native_ok = native_ok and isinstance(native.get("model_path"), str) and native["model_path"].endswith("/org.trillionnium.hepta.local/files/model/" + selected["file"])
    native_ok = native_ok and report.get("compute") == "gpu" and report.get("model_sha256") == selected["sha256"]
    native_ok = native_ok and acceptance.native_budget_valid(native, report["context_tokens"], report["model_profile"])
    inputs = native.get("input_sha256", {})
    for field, filename in (("prompt", "prompt.txt"), ("system", "system.txt"), ("grammar", "grammar.gbnf")):
        native_ok = native_ok and inputs.get(field) == sha(payloads[filename]) == report.get(field + "_sha256")
    sdk = native.get("sdk_rc", {})
    native_ok = native_ok and all(type(sdk.get(k)) is int and sdk[k] == 0 for k in ("resolve", "set_log_level", "init", "create", "template", "generate", "destroy", "deinit"))
    exit_ok = (payloads["worker-exit.txt"] == (run + " 0\n").encode() and report.get("worker_started") is True
               and report.get("process_exit_observed") is True and report.get("cleanup_known") is True
               and type(report.get("worker_exit_code")) is int and report["worker_exit_code"] == 0)
    native_ok = bool(native_ok and exit_ok and report.get("native_identity_binding_valid") is True and report.get("errors") == [])
    stderr = payloads["stderr.log"].decode("utf-8", "strict")
    previous = acceptance.accelerator_log_evidence(stderr, "gpu")
    corrected = gpu.accelerator_log_evidence(stderr)
    completed = native_ok and corrected["accelerator_offload_observed"]
    return {"schema": "hepta.gpu-replay-offline-review.v1", "request_id": run,
            "phone_contacted": False, "source_manifest_sha256": report["source_manifest_sha256"],
            "model_profile": report["model_profile"], "original_verdict": report["verdict"],
            "original_files_preserved": True, "original_native_binding_claim": report.get("native_identity_binding_valid"),
            "native_binding_revalidated": native_ok, "host_owned_exit_revalidated": exit_ok,
            "old_gpu_predicate_reproduced": previous, "independent_gpu_evidence": corrected,
            "gpu_buffer_alias_false_negative_confirmed": bool(native_ok and not previous["accelerator_offload_observed"] and corrected["accelerator_offload_observed"]),
            "corrected_model_only_compute_verdict": "model_only_completed" if completed else "not_verified",
            "scored_decision_verdict_preserved": report.get("expected_decision_matched"),
            "phone_actions_dispatched": 0, "phone_goal_achieved": False, "full_phone_acceptance": "not_assessed",
            "device_offline_proven": False,
            "validation_module_sha256": sha(Path(gpu.__file__).read_bytes()),
            "review_driver_sha256": sha(Path(__file__).read_bytes()),
            "inputs": [{"path": name, "bytes": len(data), "sha256": sha(data)} for name, data in payloads.items()]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay-dir", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.exists():
        raise ValueError("use a new review output; no prior evidence is overwritten")
    result = review(args.replay_dir.expanduser().resolve(strict=True), args.source_dir.expanduser().resolve(strict=True))
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({k: result[k] for k in ("request_id", "original_verdict", "native_binding_revalidated",
        "gpu_buffer_alias_false_negative_confirmed", "corrected_model_only_compute_verdict", "phone_goal_achieved", "phone_contacted")}, ensure_ascii=False))
    return 0 if result["corrected_model_only_compute_verdict"] == "model_only_completed" else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"error": str(error), "phone_contacted": False}), file=sys.stderr)
        sys.exit(2)
