#!/usr/bin/env python3
"""Materialize a complete private startup bundle after real staging identity.

Host-only builder. It does not access ADB, flash, mount, start a service, clear a
stop, or select a model. A missing final source/config/build/identity fails; no
placeholder service or fabricated inode is emitted. The resulting early rc is
an additional member for the pinned original ramdisk, never a replacement rc.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess

import staging
import final_config

HERE = Path(__file__).resolve().parent
ROOTFS_SHA = "5b17d4e356525e02ebd9354e74b4a5334678837ccc5a1895b3507eaa01264cda"
ROOTFS_MANIFEST_SHA = "e54a2adf831c6cbf4d8f482e5ef574c39fbb6dcd598554ba29d8a36c6d91cf3b"
PYTHON_SHA = "f7ad87c414fc6a5126571b2ecca19351119ac10e54d0539de6a0a9300d81087f"
NATIVE_POLICY_SHA = "30f3963d10aa4c4eea70c31c8f80278490be3c16986fb029853b5bc217a4b6f8"
TOKENIZER_SHA = "be75606093db2094d7cd20f3c2f385c212750648bd6ea4fb2bf507a6a4c55506"
TOKENIZER_CONFIG_SHA = "766dff8c4aaa85ebdd16131cd5b5f2976ce93a1ae510ef9c362d42ae7eb64158"
ENTRY_BUILD_MANIFEST_SHA = "dd8e700204acb92a3dfe6781eea69d20c2595983461e2bcbc7b54db1e45b2f42"
ENTRY_BINARY_SHA = "2d27ec9d9ecdddda8f8180e89d6759d327e41072cc65acc88b2e4d242b1c5caa"


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def raw_file(path, limit=16 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
         "canonical host input path required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
             "bounded regular host input required")
        parts, size = [], 0
        while size <= limit:
            part = os.read(fd, min(65536, limit + 1 - size))
            if not part:
                break
            parts.append(part); size += len(part)
        after, named = os.fstat(fd), path.lstat()
        fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_uid", "st_gid", "st_nlink", "st_mtime_ns", "st_ctime_ns")
        need(size == before.st_size and all(getattr(before, key) == getattr(after, key) == getattr(named, key)
                                           for key in fields), "input changed while reading")
        return b"".join(parts)
    finally:
        os.close(fd)


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "duplicate JSON field")
            value[key] = item
        return value
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def write_new(path, raw, mode=0o600):
    if isinstance(raw, str):
        raw = raw.encode()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        # The bundle contains distinct private data, public module data, and
        # executable entries. Caller umask must not silently collapse 0755.
        os.fchmod(stream.fileno(), mode)
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"bytes": len(raw), "sha256": sha(raw)}


def python_pin(raw):
    need(sha(raw) == ROOTFS_MANIFEST_SHA, "different immutable rootfs manifest requires a new review")
    value = strict(raw)
    need(value["image_sha256"] == ROOTFS_SHA, "rootfs image identity differs")
    rows = [row for row in value["entries"] if row.get("destination") == "/usr/bin/python3"]
    need(len(rows) == 1, "one interpreter member required")
    row = rows[0]
    need(row.get("bytes") == 7843560 and row.get("sha256") == PYTHON_SHA and row.get("mode") == "0555"
         and row.get("uid") == row.get("gid") == 0 and row.get("elf", {}).get("machine") == "AArch64",
         "interpreter does not match the verified immutable payload")
    return {"bytes": row["bytes"], "sha256": row["sha256"]}


def artifact_contract(value):
    need(isinstance(value, dict) and value.get("schema") == "hepta.geniex-isolated-artifacts.v1"
         and type(value.get("artifact_owner_uid")) is int and type(value.get("artifact_owner_gid")) is int
         and value.get("artifact_owner_uid") == value.get("artifact_owner_gid") == 0
         and value.get("directory_mode") == "0755" and type(value.get("context_tokens")) is int
         and value.get("context_tokens") == 4096,
         "reviewed root-owned read-only artifact manifest required")
    rows, names = value.get("files"), set()
    need(isinstance(rows, list) and 20 <= len(rows) <= 256, "complete model/runtime file set required")
    for row in rows:
        need(isinstance(row, dict), "artifact row must be an object")
        path = row.get("target_android")
        need(isinstance(path, str) and re.fullmatch(r"/data/local/tmp/hepta-geniex-artifacts-[0-9a-f]{32}/[A-Za-z0-9_./+,-]+", path)
             and str(PurePosixPath(path)) == path and ".." not in PurePosixPath(path).parts
             and path not in names, "artifact target is not a new canonical candidate path")
        names.add(path)
        need(type(row.get("bytes")) is int and row["bytes"] > 0
             and isinstance(row.get("sha256"), str) and re.fullmatch("[0-9a-f]{64}", row["sha256"])
             and row.get("mode") in {"0644", "0755"}, "artifact metadata differs")
        if row["mode"] == "0755":
            need(PurePosixPath(path).name in {"hepta-geniex-once", "hepta-token-count"}, "unreviewed artifact executable")
    return rows


def label_artifacts_script(rows):
    """Type only the new candidate paths after exact immutable bytes/modes."""
    directories = set()
    lines = ["#!/system/bin/sh", "set -eu", "umask 077", '[ "$(/system/bin/id -u)" = 0 ]',
             '[ "$(/system/bin/getenforce)" = Enforcing ]']
    for row in rows:
        path = row["target_android"]
        root = PurePosixPath("/".join(path.split("/")[:5]))
        parent = PurePosixPath(path).parent
        while parent != root.parent:
            directories.add(str(parent)); parent = parent.parent
        target = shlex.quote(path)
        lines += ['[ ! -L ' + target + ' ]',
                  '[ "$(/system/bin/readlink -f ' + target + ')" = ' + target + ' ]',
                  '[ "$(/system/bin/stat -c %u:%g:%a:%s ' + target + ')" = ' +
                  shlex.quote('0:0:' + row["mode"].lstrip("0") + ':' + str(row["bytes"])) + ' ]',
                  staging.hash_guard(path, row["sha256"])]
        name = PurePosixPath(path).name
        kind = ("runtime_exec" if row["mode"] == "0755" else
                "library_file" if name.endswith(".so") or ".so." in name else "data_file")
        lines.append('/system/bin/chcon u:object_r:trillionnium_owner_open_geniex_' + kind + ':s0 ' + target)
    for directory in sorted(directories, key=lambda path: (path.count("/"), path)):
        quoted = shlex.quote(directory)
        lines += ['[ ! -L ' + quoted + ' ]', '[ "$(/system/bin/stat -c %u:%g:%a ' + quoted + ')" = 0:0:755 ]',
                  '/system/bin/chcon u:object_r:trillionnium_owner_open_geniex_artifact_dir:s0 ' + quoted]
    return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser()
    for name in ("source", "source_manifest", "base_config", "geniex_config", "artifacts_manifest", "tokenizer", "tokenizer_config",
                 "stage_observation", "rootfs_image_manifest", "entry_binary", "entry_build_manifest", "native_policy", "out"):
        p.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    p.add_argument("--mode", choices=("serve", "preflight_only"), required=True)
    p.add_argument("--expected-geniex-config-sha256", required=True)
    p.add_argument("--expected-source-manifest-sha256", required=True)
    args = p.parse_args()
    need(args.out.is_absolute() and not args.out.exists(), "new private output directory required")
    observation_raw = raw_file(args.stage_observation, 65536)
    observation = strict(observation_raw); locations = staging.observation_contract(observation)
    instance = observation["instance"]
    rootfs_raw = raw_file(args.rootfs_image_manifest)
    interpreter = python_pin(rootfs_raw)
    binary = raw_file(args.entry_binary)
    build_raw = raw_file(args.entry_build_manifest, 131072); build = strict(build_raw)
    need(sha(build_raw) == ENTRY_BUILD_MANIFEST_SHA and sha(binary) == ENTRY_BINARY_SHA,
         "reviewed Android entry build identity differs")
    c_source = raw_file(HERE / "provider_entry.cpp")
    c_rows = [row for row in build["source_files"] if row["path"] == "provider_entry.cpp"]
    need(build.get("host_fixture_defined") is False and build.get("api") == 28 and len(c_rows) == 1
         and c_rows[0]["sha256"] == sha(c_source) and c_rows[0]["bytes"] == len(c_source)
         and build["binary"]["sha256"] == sha(binary) and build["binary"]["bytes"] == len(binary),
         "native entry is not the actual production build of this source")
    policy_raw = raw_file(args.native_policy, 131072)
    need(sha(policy_raw) == NATIVE_POLICY_SHA, "original r9 native policy pin differs")
    artifacts_raw = raw_file(args.artifacts_manifest, 1024 * 1024)
    rows = artifact_contract(strict(artifacts_raw))
    template_raw = raw_file(args.geniex_config, 131072)
    need(sha(template_raw) == args.expected_geniex_config_sha256, "preserved private base config SHA differs")
    original_config = strict(template_raw)
    base_raw = raw_file(args.base_config, 131072)
    tokenizer, tokcfg = raw_file(args.tokenizer), raw_file(args.tokenizer_config, 65536)
    need(sha(tokenizer) == TOKENIZER_SHA and sha(tokcfg) == TOKENIZER_CONFIG_SHA, "selected model tokenizer differs")
    source = args.source.resolve(strict=True)
    need(source == args.source and source.is_dir(), "canonical private source required")
    source_raw = {path.name: raw_file(path, 8 * 1024 * 1024) for path in sorted(source.glob("*.py"))}
    need(10 <= len(source_raw) <= 56 and {"daily_phone_local.py", "native_backend.py", "provider_bridge.py", "schema_grammar.py", "startup_health.py"}
         <= set(source_raw), "complete final private provider source required")
    for name, raw in source_raw.items():
        need(re.fullmatch(r"[a-z][a-z0-9_]*\.py", name), "source basename differs")
        ast.parse(raw, filename=name)
    source_manifest_raw = raw_file(args.source_manifest, 131072)
    need(sha(source_manifest_raw) == args.expected_source_manifest_sha256,
         "reviewed private source manifest differs")
    source_manifest = strict(source_manifest_raw)
    need(source_manifest.get("schema") == "hepta.geniex-provider-overlay.v1"
         and source_manifest.get("candidate_sha256") == {name: sha(raw) for name, raw in source_raw.items()}
         and source_manifest.get("old_cpu_receipt_branch_modified") is False
         and source_manifest.get("old_claims_modified") is False
         and source_manifest.get("legacy_completion_recovered_exactly") is True,
         "qualified private source set or preserved original branch differs")
    daily = ast.parse(source_raw["daily_phone_local.py"])
    parents = [node for node in daily.body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == "PARENTS" for target in node.targets)]
    need(len(parents) == 1, "daily source pin map missing")
    parent_pins = ast.literal_eval(parents[0].value)
    need(isinstance(parent_pins, dict)
         and all(name not in source_raw or digest == sha(source_raw[name]) for name, digest in parent_pins.items()),
         "daily import pins do not match copied source")
    config = final_config.select_r3(original_config, sha(base_raw), strict(artifacts_raw), sha(artifacts_raw),
                                     source_raw["schema_grammar.py"])
    # Artifact selection above uses the reviewed R3 layout. Only new measured
    # staging and private tokenizer locations are rebound here. Native endpoint,
    # base-config semantics, process deadlines and original claims remain.
    config["backend"]["evidence_root"] = locations["gnu"] + "/model-evidence"
    config["backend"]["stage_root"] = locations["gnu"] + "/stage"
    config["backend"]["android_stage_root"] = locations["alias"]
    config["deployment_binding"] = {"schema": "hepta.geniex-shared-mount.v1", "instance": instance,
        "execution_uid": 2000, "execution_gid": 2000, "new_dedicated_mount": True, "old_state_permissions_changed": False,
        "gnu_path": locations["gnu"] + "/stage", "android_path": locations["alias"],
        "st_dev": observation["source"]["st_dev"], "st_ino": observation["source"]["st_ino"]}
    config["tokenizer_gnu_path"] = locations["gnu"] + "/tokenizer/tokenizer.json"
    config["tokenizer_config_gnu_path"] = locations["gnu"] + "/tokenizer/tokenizer_config.json"
    config_raw = encode(config)
    args.out.mkdir(mode=0o700)
    payload = args.out / "payload"; payload.mkdir(mode=0o700)
    pins = {}
    for name, raw in source_raw.items():
        pins["source/" + name] = write_new(payload / "source" / name, raw)
    for name, raw in (("local-config-base.json", base_raw), ("geniex-config.json", config_raw),
                      ("ARTIFACT-MANIFEST.json", artifacts_raw), ("startup/provider_entry.py", raw_file(HERE / "provider_entry.py"))):
        pins[name] = write_new(payload / name, raw)
    write_new(payload / "tokenizer/tokenizer.json", tokenizer)
    write_new(payload / "tokenizer/tokenizer_config.json", tokcfg)
    launch = {"schema": "hepta.geniex-provider-start.v1", "instance": instance, "mode": args.mode,
              "source_sha256": {name: sha(raw) for name, raw in source_raw.items()},
              "base_config_sha256": sha(base_raw), "geniex_config_sha256": sha(config_raw),
              "retained_claims_sha256": staging.CLAIMS_SHA,
              "stage": {key: observation["source"][key] for key in ("st_dev", "st_ino")}}
    launch_raw = encode(launch)
    pins["startup/provider-start.json"] = write_new(payload / "startup/provider-start.json", launch_raw)
    plan = {"schema": "hepta.init-owned-geniex-provider.v1", "instance": instance, "rootfs_python": interpreter,
            "files": pins, "stage": launch["stage"], "retained_claims_sha256": staging.CLAIMS_SHA,
            "launch_config_sha256": sha(launch_raw)}
    plan_raw = encode(plan)
    write_new(payload / "startup/entry-plan.json", plan_raw)
    for name, text in (("bind-stage.sh", staging.bind_script(observation)),
                       ("unbind-empty-stage.sh", staging.unbind_script(observation)),
                       ("label-new-artifacts.sh", label_artifacts_script(rows))):
        write_new(payload / "startup" / name, text)
        subprocess.run(["/bin/sh", "-n", str(payload / "startup" / name)], check=True)
    rc_name = "overlay.d/hepta-geniex-provider-" + instance + ".rc"
    rc = staging.service_rc(instance, sha(plan_raw)); write_new(args.out / "early-ramdisk" / rc_name, rc, 0o644)
    module = args.out / "module-root"
    module_id = "trillionnium_hepta_geniex_provider_" + instance[:16]
    write_new(module / "module.prop", f"id={module_id}\nname=Hepta reviewed phone-local NPU entry\nversion=20261108-candidate\nversionCode=1\nauthor=Trillionnium\ndescription=Disabled init service; explicit reviewed activation only\n", 0o644)
    write_new(module / "system/system_ext/bin/trillionnium-hepta-geniex-provider-entry", binary, 0o755)
    policy = policy_raw.rstrip() + b"\n\n" + staging.policy_fragment().encode() + b"\n" + staging.artifact_policy_fragment().encode()
    write_new(module / "sepolicy.rule", policy, 0o644)
    post_fs = ("#!/system/bin/sh\nset -eu\numask 077\nMODDIR=${0%/*}\n"
               "entry=$MODDIR/system/system_ext/bin/trillionnium-hepta-geniex-provider-entry\n"
               '[ "$(/system/bin/sha256sum "$entry" | /system/bin/cut -d\' \' -f1)" = ' + sha(binary) + ' ]\n'
               "/system/bin/chown 0:0 \"$entry\"\n/system/bin/chmod 0755 \"$entry\"\n"
               "/system/bin/chcon u:object_r:trillionnium_owner_open_bootstrap_exec:s0 \"$entry\"\n"
               "# No stage relabel here: original init post-fs-data restorecon must finish first.\n"
               "# No service start, owner-stop removal, model launch, or old module enable.\n")
    write_new(module / "post-fs-data.sh", post_fs, 0o755)
    subprocess.run(["/bin/sh", "-n", str(module / "post-fs-data.sh")], check=True)
    # Magisk merges these directories into existing system paths. Private
    # bundle defaults (0700) must never become /system_ext/bin metadata.
    module.chmod(0o755)
    for directory in module.rglob("*"):
        if directory.is_dir():
            need(not directory.is_symlink(), "module directory is not regular")
            directory.chmod(0o755)
    report = {"schema": "hepta.init-provider-startup-bundle.v1", "instance": instance,
              "status": "MATERIALIZED_NOT_INSTALLED_OR_ACTIVATED", "mode": args.mode,
              "candidate_android": locations["native"], "candidate_gnu": locations["gnu"],
              "native_service": locations["service"], "module_id": module_id, "early_rc_member": rc_name,
              "entry_plan_sha256": sha(plan_raw), "launch_config_sha256": sha(launch_raw),
              "input_geniex_template_sha256": sha(template_raw), "effective_geniex_config_sha256": sha(config_raw),
              "stage_observation_sha256": sha(observation_raw), "native_base_policy_sha256": sha(policy_raw),
              "private_source_manifest_sha256": sha(source_manifest_raw),
              "combined_policy_sha256": sha(policy), "entry_binary_sha256": sha(binary),
              "entry_build_manifest_sha256": sha(build_raw), "rootfs_manifest_sha256": sha(rootfs_raw),
              "native_npu_qualified": False, "app_operations_qualified": False,
              "one_attempt_per_candidate_per_boot": True, "same_boot_automatic_restart": False,
              "original_claims_changed": False, "owner_stop_changed": False,
              "files": []}
    for path in sorted(args.out.rglob("*")):
        if path.is_file():
            raw = path.read_bytes(); report["files"].append({"path": str(path.relative_to(args.out)),
                "bytes": len(raw), "sha256": sha(raw), "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}"})
    write_new(args.out / "BUNDLE-MANIFEST.json", encode(report))
    print(json.dumps({"manifest": str(args.out / "BUNDLE-MANIFEST.json"), "sha256": sha(encode(report)),
                      "entry_plan_sha256": sha(plan_raw), "service": locations["service"]}))


if __name__ == "__main__":
    main()
