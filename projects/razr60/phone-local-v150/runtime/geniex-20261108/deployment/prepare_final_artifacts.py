#!/usr/bin/env python3
"""Prepare the small R3 runtime copy, reusing the verified read-only model.

Host-only: emits a new manifest and a fixed copy script. It never invokes ADB.
The generated script only creates its new artifact root, copies 52 libraries
and two frozen small programs, and verifies all 24 existing model files.
"""
from __future__ import annotations
import argparse
import copy
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess

import build_startup_bundle as bundle
import final_config
import staging

R3_ANDROID_RUNTIME = "/data/local/tmp/hepta-geniex-vlm-r3-20261108"


def prepare(previous, previous_sha256, instance, runtime_raw, core_raw, vlm_raw):
    staging.paths(instance)
    bundle.need(bundle.sha(runtime_raw) == final_config.RUNTIME_MANIFEST_SHA, "real R3 runtime manifest differs")
    runtime = bundle.strict(runtime_raw)
    old = final_config.index_artifacts(previous)
    bundle.need(bundle.sha(core_raw) == final_config.CORE_SHA and bundle.sha(vlm_raw) == final_config.VLM_SHA,
                "built R2-core/R3-VLM bytes differ")
    expected = runtime["candidate_files"]
    bundle.need(len(expected) == 52 and set(expected) == set(runtime["original_files"]), "runtime library set differs")
    new_root = "/data/local/tmp/hepta-geniex-artifacts-" + instance
    rows = []
    for relative, prior in old.items():
        row = copy.deepcopy(prior)
        if relative.startswith("model/"):
            # The old candidate was already copied into a new root-owned,
            # read-only tree in this session. Do not copy 4.6 GB again.
            row.update(source_android=prior["target_android"], copy_required=False)
        else:
            row.update(target_android=new_root + "/" + relative, copy_required=True)
            bundle.need(row["target_android"] != prior["target_android"], "fresh artifact identity required")
            if relative.startswith("runtime/"):
                key = relative[len("runtime/"):]
                bundle.need(prior["sha256"] == runtime["original_files"][key], "preserved original library pin differs")
                row.update(source_android=R3_ANDROID_RUNTIME + "/" + key, sha256=expected[key])
                if key == "lib/qairt/libgeniex_core.so":
                    row["bytes"] = len(core_raw)
                elif key == "lib/qairt/libgeniex_vlm.so":
                    row["bytes"] = len(vlm_raw)
            else:
                row["source_android"] = prior["target_android"]
        rows.append(row)
    result = copy.deepcopy(previous)
    result.update(instance=instance, files=rows, source_static_manifest_sha256=previous_sha256,
                  source_runtime_candidate_manifest_sha256=final_config.RUNTIME_MANIFEST_SHA,
                  model_files_reused_without_copy=24, copied_runtime_and_binary_files=54,
                  production_domain_qualified=False, prompt_decision_qualified=False)
    bundle.artifact_contract(result)
    return result


def copy_script(value):
    rows = bundle.artifact_contract(value)
    root = "/data/local/tmp/hepta-geniex-artifacts-" + value["instance"]
    need_copy = [row for row in rows if row["copy_required"] is True]
    bundle.need(len(need_copy) == 54 and len(rows) == 78, "exact copy/reuse inventory required")
    lines = ["#!/system/bin/sh", "set -eu", "umask 077", *staging.stopped_guards(),
             '[ "$(/system/bin/readlink /proc/self/ns/mnt)" = "$(/system/bin/readlink /proc/1/ns/mnt)" ]',
             '[ ! -e ' + root + ' ]', '[ ! -L ' + root + ' ]',
             '/system/bin/mkdir ' + root, '/system/bin/chown 0:0 ' + root, '/system/bin/chmod 0755 ' + root]
    directories = set()
    for row in need_copy:
        parent = PurePosixPath(row["target_android"]).parent
        while str(parent) != root:
            bundle.need(str(parent).startswith(root + "/"), "copy target escaped new root")
            directories.add(str(parent)); parent = parent.parent
    for directory in sorted(directories, key=lambda path: (path.count("/"), path)):
        lines += ["/system/bin/mkdir " + shlex.quote(directory), "/system/bin/chown 0:0 " + shlex.quote(directory),
                  "/system/bin/chmod 0755 " + shlex.quote(directory)]
    for row in rows:
        source, target = row["source_android"], row["target_android"]
        for path in {source, target} if row["copy_required"] is False else {source}:
            q = shlex.quote(path)
            lines += ["[ -f " + q + " ]", "[ ! -L " + q + " ]",
                      '[ "$(/system/bin/readlink -f ' + q + ')" = ' + q + ' ]',
                      '[ "$(/system/bin/stat -c %s ' + q + ')" = ' + str(row["bytes"]) + ' ]',
                      staging.hash_guard(path, row["sha256"])]
        if row["copy_required"]:
            bundle.need(target.startswith(root + "/"), "copy target is not new artifact")
            lines += ["[ ! -e " + shlex.quote(target) + " ]", "[ ! -L " + shlex.quote(target) + " ]",
                      "( set -C; /system/bin/cat " + shlex.quote(source) + " > " + shlex.quote(target) + " )",
                      "/system/bin/chown 0:0 " + shlex.quote(target),
                      "/system/bin/chmod " + row["mode"] + " " + shlex.quote(target)]
        lines += [staging.hash_guard(target, row["sha256"]),
                  '[ "$(/system/bin/stat -c %u:%g:%a:%s ' + shlex.quote(target) + ')" = ' +
                  shlex.quote("0:0:" + row["mode"].lstrip("0") + ":" + str(row["bytes"])) + ' ]']
    lines += ["/system/bin/sync", *staging.stopped_guards(),
              "/system/bin/stat -c 'ARTIFACT_ROOT %d:%i:%u:%g:%a' " + root,
              "printf 'COPIED_FILES 54\\nREUSED_MODEL_FILES 24\\nALL_FILE_SHA256_VERIFIED 78\\n'",
              "# No type/driver/mount change, service start, stop removal, or model execution."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    for name in ("previous_manifest", "runtime_manifest", "core", "vlm", "out"):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    parser.add_argument("--previous-manifest-sha256", required=True)
    parser.add_argument("--instance", required=True)
    args = parser.parse_args()
    raw = bundle.raw_file(args.previous_manifest, 1024 * 1024)
    bundle.need(bundle.sha(raw) == args.previous_manifest_sha256, "preserved artifact manifest differs")
    value = prepare(bundle.strict(raw), bundle.sha(raw), args.instance, bundle.raw_file(args.runtime_manifest),
                    bundle.raw_file(args.core), bundle.raw_file(args.vlm))
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    manifest = bundle.encode(value)
    bundle.write_new(args.out / "ARTIFACT-MANIFEST.json", manifest)
    script = copy_script(value)
    bundle.write_new(args.out / "copy-new-runtime-reuse-model.sh", script)
    subprocess.run(["/bin/sh", "-n", str(args.out / "copy-new-runtime-reuse-model.sh")], check=True)
    bundle.write_new(args.out / "PREPARE-RESULT.json", bundle.encode({"schema": "hepta.geniex-static-copy-plan.v1",
        "status": "PREPARED_NOT_EXECUTED", "instance": args.instance, "manifest_sha256": bundle.sha(manifest),
        "copy_script_sha256": bundle.sha(script.encode()),
        "copy_bytes": sum(row["bytes"] for row in value["files"] if row["copy_required"]),
        "reuse_bytes": sum(row["bytes"] for row in value["files"] if not row["copy_required"]),
        "phone_operations": 0, "owner_stop_changed": False, "original_claims_changed": False}))


if __name__ == "__main__":
    main()
