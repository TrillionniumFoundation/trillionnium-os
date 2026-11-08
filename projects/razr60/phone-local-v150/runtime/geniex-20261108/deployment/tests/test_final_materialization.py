#!/usr/bin/env python3
"""Actual code with synthetic metadata, never a phone/boot qualification."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import build_init_boot_candidate as boot
import final_config
import prepare_final_artifacts as artifacts
import inspect_init_boot as inventory


def selected_fixture():
    runtime = json.loads((HERE.parent / "grammar-vlm-r3/RUNTIME-CANDIDATE-MANIFEST.json").read_bytes())
    new_root = "/data/local/tmp/hepta-geniex-artifacts-" + "b" * 32
    old_root = "/data/local/tmp/hepta-geniex-artifacts-" + "a" * 32
    rows = [{"relative": "runtime/" + relative, "source_android": artifacts.R3_ANDROID_RUNTIME + "/" + relative,
             "target_android": new_root + "/runtime/" + relative, "sha256": digest,
             "bytes": 100, "mode": "0644", "copy_required": True} for relative, digest in runtime["candidate_files"].items()]
    for name in ["genie_config.json", "tokenizer.json"] + ["part-%02d.bin" % index for index in range(22)]:
        rows.append({"relative": "model/" + name, "source_android": old_root + "/model/" + name,
                     "target_android": old_root + "/model/" + name, "sha256": "3" * 64,
                     "bytes": 100, "mode": "0644", "copy_required": False})
    for name in ("hepta-geniex-once", "hepta-token-count"):
        rows.append({"relative": "bin/" + name, "source_android": old_root + "/bin/" + name,
                     "target_android": new_root + "/bin/" + name, "sha256": "4" * 64,
                     "bytes": 100, "mode": "0755", "copy_required": True})
    manifest = {"schema": "hepta.geniex-isolated-artifacts.v1", "instance": "b" * 32, "artifact_owner_uid": 0,
                "artifact_owner_gid": 0, "directory_mode": "0755", "context_tokens": 4096, "files": rows,
                "source_runtime_candidate_manifest_sha256": final_config.RUNTIME_MANIFEST_SHA}
    backend = {"evidence_root": "/old/evidence", "stage_root": "/old/stage", "android_stage_root": "/old/alias",
               "worker_android": old_root + "/bin/hepta-geniex-once", "worker_sha256": "4" * 64,
               "counter_android": old_root + "/bin/hepta-token-count", "counter_sha256": "4" * 64,
               "model_android": old_root + "/model/genie_config.json", "tokenizer_android": old_root + "/model/tokenizer.json",
               "tokenizer_sha256": "3" * 64, "plugin_path": old_root + "/runtime/lib",
               "qairt_lib_path": old_root + "/runtime/lib/qairt/htp-files", "ld_library_path": "old-loader-path",
               "adsp_library_path": "old-dsp-path", "artifact_manifest_sha256": "5" * 64,
               "tokenizer_library_android": old_root + "/runtime/lib/qairt/libgeniex-proc.so",
               "tokenizer_library_sha256": runtime["candidate_files"]["lib/qairt/libgeniex-proc.so"],
               "max_worker_ms": 55000, "max_native_ms": 60000}
    old = {"schema": "hepta.provider-geniex-native.v1", "base_provider_config_sha256": "1" * 64,
           "model_id": "Qwen3-VL-4B-Instruct-QAIRT-w4a16-SM8750-v79", "backend": backend,
           "tokenizer_gnu_path": "/old/tokenizer.json", "tokenizer_config_gnu_path": "/old/tokenizer_config.json",
           "template_contract": {"host_fixture_preserve_every_field": [1, "all original bytes remain bound"]},
           "deployment_binding": {"host_fixture_not_usable_as_inode_evidence": True}}
    compiler = (HERE.parent / "schema-grammar-python-r1/python_schema_grammar.py").read_bytes()
    return old, manifest, compiler


class FinalConfiguration(unittest.TestCase):
    def test_explicit_upgrade_preserves_base_template_stage_and_model_without_mutating_original(self):
        old, manifest, compiler = selected_fixture(); snapshot = copy.deepcopy(old)
        value = final_config.select_r3(old, "1" * 64, manifest, "2" * 64, compiler)
        self.assertEqual(old, snapshot)
        for key in ("base_provider_config_sha256", "model_id", "template_contract", "deployment_binding",
                    "tokenizer_gnu_path", "tokenizer_config_gnu_path"):
            self.assertEqual(value[key], old[key])
        for key in ("model_android", "tokenizer_android", "stage_root", "evidence_root", "max_worker_ms", "max_native_ms"):
            self.assertEqual(value["backend"][key], old["backend"][key])
        self.assertEqual(value["schema_compiler"]["sha256"], final_config.COMPILER_SHA)
        self.assertEqual(value["backend"]["grammar_profile"], final_config.PROFILE)

    def test_real_52_file_qairt_layout_is_preserved(self):
        old, manifest, compiler = selected_fixture()
        backend = final_config.select_r3(old, "1" * 64, manifest, "2" * 64, compiler)["backend"]
        plugin = backend["plugin_path"]
        self.assertEqual(backend["core_android"], plugin + "/qairt/libgeniex_core.so")
        self.assertEqual(backend["vlm_android"], plugin + "/qairt/libgeniex_vlm.so")
        self.assertEqual(backend["ld_library_path"].split(":"), [plugin, plugin + "/llama_cpp", plugin + "/qairt",
                         plugin + "/qairt/htp-files", "/system/lib64", "/vendor/lib64"])
        self.assertEqual(backend["tokenizer_library_android"], plugin + "/qairt/libgeniex-proc.so")

    def test_wrong_model_compiler_library_and_unexpected_old_fields_fail(self):
        old, manifest, compiler = selected_fixture()
        for kind in ("base", "model", "core", "compiler", "field", "count"):
            cfg, art, comp = copy.deepcopy(old), copy.deepcopy(manifest), compiler
            base = "1" * 64
            if kind == "base": base = "0" * 64
            elif kind == "model": cfg["backend"]["model_android"] = "/different/genie_config.json"
            elif kind == "core": next(row for row in art["files"] if row["relative"] == "runtime/lib/qairt/libgeniex_core.so")["sha256"] = "0" * 64
            elif kind == "compiler": comp += b"\n"
            elif kind == "field": cfg["backend"]["cpu_fallback"] = True
            elif kind == "count": art["files"].pop()
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                final_config.select_r3(cfg, base, art, "2" * 64, comp)

    def test_copy_renderer_reuses_model_and_only_writes_new_runtime_root(self):
        _, manifest, _ = selected_fixture()
        script = artifacts.copy_script(manifest)
        self.assertEqual(script.count("( set -C; /system/bin/cat "), 54)
        self.assertNotIn("> /data/local/tmp/hepta-geniex-artifacts-" + "a" * 32, script)
        self.assertNotIn("chcon", script)
        self.assertNotIn("ctl.start", script)
        self.assertNotIn("rm ", script)
        result = subprocess.run(["/bin/sh", "-n"], input=script.encode(), capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)


def record(name, data, mode, ino):
    name = name.encode() + b"\0"
    values = [ino, mode, 0, 0, 1, 1234567, len(data), 0, 0, 0, 0, len(name), 0]
    raw = b"070701" + b"".join(f"{value:08x}".encode() for value in values) + name
    raw += b"\0" * ((-len(raw)) % 4)
    return raw + data + b"\0" * ((-len(data)) % 4)


class CpioPreservation(unittest.TestCase):
    def fixture(self):
        return (record("overlay.d", b"", stat.S_IFDIR | 0o755, 1) +
                record("overlay.d/original.rc", b"ORIGINAL RC\n", stat.S_IFREG | 0o644, 2) +
                record("init", b"/system/bin/init", stat.S_IFLNK | 0o777, 3) +
                record("TRAILER!!!", b"", 0, 0) + b"\0" * 128)

    def test_one_new_rc_keeps_all_original_metadata_payloads_and_record_bytes(self):
        original = self.fixture(); entries, payloads, tail = inventory.cpio_inventory(original)
        name = "overlay.d/hepta-geniex-provider-" + "a" * 32 + ".rc"
        candidate, proof = boot.append_rc(original, name, b"service fixture /system/bin/true\n    disabled\n")
        new, new_payloads, _ = inventory.cpio_inventory(candidate)
        self.assertEqual(candidate[:tail["trailer_offset"]], original[:tail["trailer_offset"]])
        self.assertEqual(new[:-1], entries)
        self.assertEqual({key: new_payloads[key] for key in payloads}, payloads)
        self.assertEqual(new[-1]["mode"], stat.S_IFREG | 0o644)
        self.assertTrue(proof["original_records_preserved_byte_for_byte"])

    def test_duplicate_unsafe_or_binary_rc_is_rejected(self):
        original = self.fixture(); name = "overlay.d/hepta-geniex-provider-" + "a" * 32 + ".rc"
        candidate, _ = boot.append_rc(original, name, b"fixture\n")
        with self.assertRaises(ValueError): boot.append_rc(candidate, name, b"replacement\n")
        for bad_name, data in (("overlay.d/../init.rc", b"x"), (name, b"x\0y"), (name, b"x" * 16385)):
            with self.subTest(name=bad_name), self.assertRaises(ValueError):
                boot.append_rc(original, bad_name, data)

    def test_missing_overlay_directory_or_nonzero_trailer_is_rejected(self):
        name = "overlay.d/hepta-geniex-provider-" + "a" * 32 + ".rc"
        for cpio in (record("TRAILER!!!", b"", 0, 0), self.fixture() + b"bad"):
            with self.assertRaises(ValueError): boot.append_rc(cpio, name, b"fixture\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
