"""Narrow, explicit old-v1 to measured-stage R3 QAIRT configuration transform.

Pure data operations. No endpoint is called and no owner request, App catalogue,
native executor, or retained claim is replaced. Source/layout validation remains
the provider's separate runtime gate.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re

CORE_SHA = "06e65cbec4de0831e0010c02ff424e197a519f35b137344cb62ff92369abdb5d"
VLM_SHA = "773e23de3f892d2cd9c468e7b0af32e6c254af341d4ed0e7ef0eda95f6ee1d73"
COMPILER_SHA = "c230e076ae61c87a744c49b160a456c039d47441784ad3ccc2c6465bc67453a8"
PROFILE = "qairt-output-grammar-core-r2-vlm-r3-v1"
RUNTIME_MANIFEST_SHA = "cba2dba9d5b728cee9206af901493a987478babf0c072503972c4a1f2a2a6ca6"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def index_artifacts(artifacts):
    rows = artifacts["files"]
    result = {row["relative"]: row for row in rows}
    need(len(rows) == len(result) == 78, "selected model/runtime/binary inventory differs")
    need(len([key for key in result if key.startswith("runtime/lib/")]) == 52
         and len([key for key in result if key.startswith("model/")]) == 24
         and {key for key in result if key.startswith("bin/")} == {"bin/hepta-geniex-once", "bin/hepta-token-count"},
         "complete selected artifact families required")
    return result


def select_r3(old, base_sha256, artifacts, artifacts_sha256, compiler_raw):
    """Upgrade only the authorized backend/artifact fields; stage is bound later."""
    fields = {"schema", "base_provider_config_sha256", "model_id", "backend", "tokenizer_gnu_path",
              "tokenizer_config_gnu_path", "template_contract", "deployment_binding"}
    need(isinstance(old, dict) and set(old) == fields and old["schema"] == "hepta.provider-geniex-native.v1",
         "the preserved v1 static candidate is the required base")
    need(old["base_provider_config_sha256"] == base_sha256
         and old["model_id"] == "Qwen3-VL-4B-Instruct-QAIRT-w4a16-SM8750-v79", "base model/config differs")
    need(hashlib.sha256(compiler_raw).hexdigest() == COMPILER_SHA, "reviewed Python schema compiler differs")
    rows = index_artifacts(artifacts)
    need(artifacts["source_runtime_candidate_manifest_sha256"] == RUNTIME_MANIFEST_SHA,
         "selected real R3 runtime manifest missing")
    source = old["backend"]
    need(isinstance(source, dict) and set(source) == {"evidence_root", "stage_root", "android_stage_root", "worker_android",
         "worker_sha256", "model_android", "tokenizer_android", "plugin_path", "qairt_lib_path", "ld_library_path",
         "adsp_library_path", "artifact_manifest_sha256", "tokenizer_sha256", "counter_android", "counter_sha256",
         "tokenizer_library_android", "tokenizer_library_sha256", "max_worker_ms", "max_native_ms"},
         "preserved v1 backend fields differ")
    need(source["max_worker_ms"] == 55000 and type(source["max_worker_ms"]) is int
         and source["max_native_ms"] == 60000 and type(source["max_native_ms"]) is int,
         "old explicit process budgets differ")
    for field, relative in (("model_android", "model/genie_config.json"), ("tokenizer_android", "model/tokenizer.json")):
        need(source[field] == rows[relative]["target_android"], "read-only model must be reused without rebind")
    for field, relative in (("worker_sha256", "bin/hepta-geniex-once"), ("counter_sha256", "bin/hepta-token-count"),
                            ("tokenizer_sha256", "model/tokenizer.json"),
                            ("tokenizer_library_sha256", "runtime/lib/qairt/libgeniex-proc.so")):
        need(source[field] == rows[relative]["sha256"], "unchanged binary/tokenizer hash differs")
    plugin = str(PurePosixPath(rows["runtime/lib/libgeniex.so"]["target_android"]).parent)
    qairt = plugin + "/qairt"
    need(rows["runtime/lib/qairt/libgeniex_core.so"]["sha256"] == CORE_SHA
         and rows["runtime/lib/qairt/libgeniex_vlm.so"]["sha256"] == VLM_SHA,
         "explicit R3 library pins differ")
    for relative, row in rows.items():
        if relative.startswith("runtime/lib/"):
            need(row["target_android"] == plugin + relative[len("runtime/lib"):],
                 "runtime does not preserve the actual 52-file loader layout")
    value = copy.deepcopy(old)
    value["schema"] = "hepta.provider-geniex-native.v2"
    value["schema_compiler"] = {"kind": "reviewed_python_source", "sha256": COMPILER_SHA,
                                "subset": "hepta.mobile-schema-gbnf-subset.v1"}
    backend = value["backend"]
    backend.update(worker_android=rows["bin/hepta-geniex-once"]["target_android"],
        counter_android=rows["bin/hepta-token-count"]["target_android"], plugin_path=plugin,
        qairt_lib_path=qairt + "/htp-files",
        ld_library_path=":".join([plugin, plugin + "/llama_cpp", qairt, qairt + "/htp-files", "/system/lib64", "/vendor/lib64"]),
        adsp_library_path=qairt + "/htp-files;/vendor/lib/rfsa/adsp", artifact_manifest_sha256=artifacts_sha256,
        tokenizer_library_android=rows["runtime/lib/qairt/libgeniex-proc.so"]["target_android"],
        grammar_profile=PROFILE, core_android=qairt + "/libgeniex_core.so", core_sha256=CORE_SHA,
        vlm_android=qairt + "/libgeniex_vlm.so", vlm_sha256=VLM_SHA, schema_compiler_sha256=COMPILER_SHA)
    # Check the complete diff against the deliberate whitelist, not just fields
    # that happened to be assigned above.
    permitted = {"worker_android", "counter_android", "plugin_path", "qairt_lib_path", "ld_library_path",
                 "adsp_library_path", "artifact_manifest_sha256", "tokenizer_library_android",
                 "grammar_profile", "core_android", "core_sha256", "vlm_android", "vlm_sha256", "schema_compiler_sha256"}
    need(all(backend[key] == item for key, item in source.items() if key not in permitted), "unexpected backend semantic change")
    need(all(value[key] == old[key] for key in fields - {"schema", "backend"}), "owner/base/template/binding semantics changed")
    return value
