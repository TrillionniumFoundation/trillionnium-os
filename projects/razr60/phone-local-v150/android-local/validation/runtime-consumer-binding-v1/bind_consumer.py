#!/usr/bin/env python3
"""Bind an unchanged frozen runtime producer to an independently verified consumer.

The original MNN v8 and UI-Venus v1 producers/verifiers stay unchanged. Their
complete pinned source is a separate checkout; the candidate App is verified
against its own exact Git head and manifest, never admitted as the producer.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

COMPONENT = "projects/razr60/phone-local-v150/android-local/lfm3-controller"
VALIDATION = "projects/razr60/phone-local-v150/android-local/validation"
PRODUCER_HEAD = "cc4a7035760383a126e4510002139d88667e0b97"
PRODUCER_MANIFEST = "f4af9855da4e62a2eeaa1cc8d734082c6c31d17f95d001b58b412dbd7604978a"
REBUILD = VALIDATION + "/mobimind-runtime-rebuild-v8/rebuild_exact_runtime.py"
MNN_BINDER = VALIDATION + "/mobimind-ci-host-split-v8/verify_ci_runtime_bundle.py"
QUALIFIER = VALIDATION + "/mobimind-ci-host-split-v8/qualify_macos_compiler.py"
UI_BUILDER = VALIDATION + "/ui-venus-runtime-rebuild-v1/rebuild_and_verify.py"
SELF = VALIDATION + "/runtime-consumer-binding-v1/bind_consumer.py"
WORKFLOW = ".github/workflows/hepta-local-android.yml"
LEGACY_HELPERS = (REBUILD, MNN_BINDER, QUALIFIER, UI_BUILDER,
                  VALIDATION + "/ui-venus-runtime-rebuild-v1/test_rebuild_and_verify.py")
CONTRACT_FILES = (
    "native/mobimind-runtime-pins.json",
    "native/ui-venus-runtime-pins.json",
    "src/org/trillionnium/hepta/local/MobiMindPins.java",
    "src/org/trillionnium/hepta/local/UiVenusPins.java",
    "tools/verify_mobimind_runtime.py",
    "tools/verify_ui_venus_runtime.py",
    "tools/fetch_pinned_runtime.py",
    "provenance/mobimind-worker-r4-build.json",
)
CONTRACT_PREFIXES = ("provenance/mobimind-worker-r4/", "provenance/ui-venus-app-r1/")
BINDING = "CURRENT-CONSUMER-SOURCE.json"
INNER = "producer"
MAX_SOURCE_FILE = 64 * 1024 * 1024


def require(value, message):
    if value is not True:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def read(path, maximum=MAX_SOURCE_FILE):
    path = Path(path)
    require(path.resolve(strict=True) == path.absolute(), "symlink or noncanonical file: " + str(path))
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
                "bounded single-link regular file required")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    identity = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_nlink, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    require(len(raw) == before.st_size and identity(before) == identity(after) == identity(path.lstat()),
            "file changed during read")
    return raw


def obj(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def git(root, *args):
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(root), *map(str, args)],
        capture_output=True, timeout=30,
        env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C", "LANG": "C",
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"},
    )
    require(result.returncode == 0, "git identity lookup failed: " + result.stderr.decode("utf-8", "replace")[:500])
    return result.stdout


def entries(root, head, prefix):
    raw = git(root, "ls-tree", "-r", "-z", "--full-tree", head, "--", prefix)
    result = {}
    for row in raw.split(b"\0"):
        if not row:
            continue
        meta, name = row.split(b"\t", 1)
        mode, kind, sha = meta.decode("ascii").split()
        path = name.decode("utf-8")
        require(kind == "blob" and mode in ("100644", "100755"), "nonregular Git source member")
        require(path not in result, "duplicate Git source path")
        result[path] = {"mode": mode, "git_blob": sha}
    require(bool(result), "Git source prefix is empty")
    return result


def verify_git_file(root, name, expected):
    path = root / name
    raw = read(path)
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()
    require(blob == expected["git_blob"], "working source differs from exact Git head: " + name)
    executable = bool(path.stat().st_mode & 0o111)
    require(executable == (expected["mode"] == "100755"), "working source mode differs: " + name)
    return {"bytes": len(raw), "sha256": digest(raw), **expected}


def verify_source(root, head, component=COMPONENT):
    """Read every source byte, check both its manifest and exact Git object."""
    require(re.fullmatch("[0-9a-f]{40}", head) is not None, "exact source head required")
    root = Path(root).resolve(strict=True)
    require(Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve() == root,
            "repository root identity differs")
    require(git(root, "rev-parse", "HEAD").decode().strip() == head, "checkout is not the required source head")
    source = root / component
    manifest_raw = read(source / "SOURCE-MANIFEST.json", 4 * 1024 * 1024)
    manifest = obj(manifest_raw)
    require(type(manifest) is dict and manifest.get("schema") == "hepta.local-source.v3"
            and type(manifest.get("files")) is list, "complete source manifest required")
    tracked = entries(root, head, component)
    rows = {}
    for item in manifest["files"]:
        require(type(item) is dict and type(item.get("path")) is str, "invalid manifest row")
        name = item["path"]
        rel = PurePosixPath(name)
        require(name and not rel.is_absolute() and ".." not in rel.parts and str(rel) == name
                and name != "SOURCE-MANIFEST.json" and name not in rows, "unsafe or duplicate manifest path")
        require(type(item.get("bytes")) is int and item["bytes"] >= 0
                and re.fullmatch("[0-9a-f]{64}", str(item.get("sha256"))) is not None,
                "invalid manifest byte identity")
        rows[name] = item
    require(set(tracked) == {component + "/" + name for name in rows} | {component + "/SOURCE-MANIFEST.json"},
            "manifest does not enumerate the complete Git component")
    actual = set()
    for path in source.rglob("*"):
        rel = path.relative_to(source)
        if rel.parts[0] in ("out", ".git", "keys") or ("__pycache__" in rel.parts and path.suffix == ".pyc"):
            continue
        require(not path.is_symlink(), "source symlink rejected")
        if path.is_file():
            actual.add(str(rel))
    require(actual == set(rows) | {"SOURCE-MANIFEST.json"}, "unlisted or missing source member")
    inventory = {}
    for name, pin in tracked.items():
        relative = name[len(component) + 1:]
        item = verify_git_file(root, name, pin)
        if relative != "SOURCE-MANIFEST.json":
            require(item["bytes"] == rows[relative]["bytes"] and item["sha256"] == rows[relative]["sha256"],
                    "source manifest hash differs: " + relative)
        inventory[relative] = item
    require(read(source / "SOURCE-MANIFEST.json", 4 * 1024 * 1024) == manifest_raw,
            "source manifest changed during verification")
    require(git(root, "rev-parse", "HEAD").decode().strip() == head, "source head moved during verification")
    identity = {
        "head": head,
        "component_tree": git(root, "rev-parse", head + ":" + component).decode().strip(),
        "source_manifest_sha256": digest(manifest_raw),
        "source_files": len(inventory),
        "complete_inventory_sha256": digest(canonical(inventory)),
    }
    return identity, inventory


def match_contracts(producer, consumer):
    selected = set(CONTRACT_FILES)
    for prefix in CONTRACT_PREFIXES:
        old = {name for name in producer if name.startswith(prefix)}
        new = {name for name in consumer if name.startswith(prefix)}
        require(bool(old) and old == new, "runtime source closure membership differs: " + prefix)
        selected.update(old)
    result = []
    for name in sorted(selected):
        require(name in producer and name in consumer and producer[name] == consumer[name],
                "consumer runtime contract differs from fixed producer: " + name)
        result.append({"path": name, **producer[name]})
    return result


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def verify_pair(consumer_root, producer_root, head):
    consumer_id, consumer_files = verify_source(consumer_root, head)
    producer_id, producer_files = verify_source(producer_root, PRODUCER_HEAD)
    require(producer_id["source_manifest_sha256"] == PRODUCER_MANIFEST, "fixed producer manifest differs")
    contracts = match_contracts(producer_files, consumer_files)
    helpers = []
    for name in LEGACY_HELPERS:
        current = verify_git_file(consumer_root, name, entries(consumer_root, head, name)[name])
        frozen = verify_git_file(producer_root, name, entries(producer_root, PRODUCER_HEAD, name)[name])
        require(current == frozen, "original producer or verifier changed: " + name)
        helpers.append({"path": name, **current})
    for name in (SELF, WORKFLOW):
        verify_git_file(consumer_root, name, entries(consumer_root, head, name)[name])
    return {"consumer": consumer_id, "producer": producer_id,
            "runtime_contract_files": contracts, "unchanged_original_helpers": helpers}


def check_runtime(kind, consumer_root, inner):
    source = consumer_root / COMPONENT
    # UI verifier imports this exact already-verified MNN verifier by module name.
    mnn = load(source / "tools/verify_mobimind_runtime.py", "verify_mobimind_runtime")
    if kind == "mnn":
        records = mnn.verify_mobimind_runtime(source, inner / "runtime")
    else:
        ui = load(source / "tools/verify_ui_venus_runtime.py", "verified_consumer_ui_venus")
        records = ui.verify_ui_venus_runtime(source, inner / "runtime")
    rows = []
    for name, record in sorted(records.items()):
        rows.append({"apk_name": name, "source_name": record["source_name"],
                     "bytes": record["bytes"], "sha256": record["sha256"],
                     "build_receipt_sha256": record["build_receipt_sha256"]})
    return rows


def original_argv(args, consumer_root, producer_root, inner):
    common = ["--app-source", str(producer_root / COMPONENT), "--bundle", str(inner),
              "--source-head", args.source_head, "--run-id", args.run_id, "--run-attempt", args.run_attempt]
    if args.kind == "mnn":
        command = [sys.executable, "-B", str(consumer_root / MNN_BINDER), args.operation,
                   "--rebuild-helper", str(consumer_root / REBUILD), *common]
    else:
        command = [sys.executable, "-B", str(consumer_root / UI_BUILDER),
                   "build" if args.operation == "bind" else "verify",
                   "--compiler-qualifier", str(consumer_root / QUALIFIER), *common]
        if args.operation == "bind":
            require(args.ndk is not None and args.sdk_libs is not None, "UI build needs original NDK and SDK")
            command.extend(["--ndk", str(args.ndk), "--sdk-libs", str(args.sdk_libs)])
    if args.operation == "bind":
        require(args.compiler_identity is not None, "producer compiler identity required")
        command.extend(["--compiler-identity", str(args.compiler_identity)])
    else:
        require(args.ndk is None and args.sdk_libs is None and args.compiler_identity is None,
                "consumer must use only transferred original producer evidence")
    return command


def write_new(path, raw):
    with Path(path).open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def execute(args):
    require(re.fullmatch("[0-9a-f]{40}", args.source_head) is not None, "exact consumer head required")
    for value in (args.run_id, args.run_attempt):
        require(re.fullmatch("[1-9][0-9]*", value) is not None, "exact workflow run and attempt required")
    consumer_root = Path(args.consumer_root).resolve(strict=True)
    producer_root = Path(args.producer_root).resolve(strict=True)
    require(consumer_root != producer_root, "producer needs an independent checkout")
    pair = verify_pair(consumer_root, producer_root, args.source_head)
    if args.operation == "check-sources":
        print(json.dumps({"schema": "hepta.ci.runtime-source-pair.v1", **pair,
                          "phone_contacted": False, "runtime_rebuilt": False}, sort_keys=True))
        return 0
    require(args.kind in ("mnn", "ui") and args.bundle is not None, "runtime kind and bundle required")
    outer = Path(args.bundle).absolute()
    require(not outer.is_symlink(), "bundle symlink rejected")
    inner = outer / INNER
    if args.operation == "verify":
        require(outer.is_dir() and {p.name for p in outer.iterdir()} == {INNER, BINDING},
                "transferred consumer bundle membership differs")
    elif args.kind == "ui":
        require(not outer.exists(), "new independent UI consumer bundle required")
        outer.mkdir(parents=True)
    else:
        require(outer.is_dir() and {p.name for p in outer.iterdir()} == {INNER},
                "MNN source binding requires only the new original producer directory")
    command = original_argv(args, consumer_root, producer_root, inner)
    result = subprocess.run(command, capture_output=True, timeout=900,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    # Preserve original diagnostics without concatenating JSON documents on stdout.
    sys.stderr.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    require(result.returncode == 0, "unchanged original runtime build/verification failed")
    # Re-read the complete consumer and producer after the original operation.
    require(verify_pair(consumer_root, producer_root, args.source_head) == pair,
            "source pair changed during original runtime operation")
    runtime = check_runtime(args.kind, consumer_root, inner)
    original = obj(read(inner / "CURRENT-CI-SOURCE.json", 1024 * 1024))
    require(original.get("source_head_sha") == args.source_head
            and original.get("github_run_id") == args.run_id
            and original.get("github_run_attempt") == args.run_attempt
            and original.get("app_source_manifest_sha256") == PRODUCER_MANIFEST,
            "original runtime binding belongs to another consumer/run/producer")
    binding = {
        "schema": "hepta.ci.consumer-runtime-binding.v1", "kind": args.kind,
        "source_head_sha": args.source_head, "github_run_id": args.run_id,
        "github_run_attempt": args.run_attempt, **pair, "runtime_files": runtime,
        "original_runtime_binding_sha256": digest(read(inner / "CURRENT-CI-SOURCE.json")),
        "original_new_build_receipt_sha256": digest(read(inner / "NEW-BUILD-RECEIPT.json")),
        "original_compiler_identity_sha256": digest(read(inner / "COMPILER-IDENTITY.json")),
        "whole_runtime_verified_against_consumer": True,
        "frozen_producer_is_current_app_source": False,
        "consumer_android_build_proven": False, "phone_contacted": False,
    }
    require(verify_pair(consumer_root, producer_root, args.source_head) == pair,
            "source pair changed before consumer admission")
    encoded = canonical(binding) + b"\n"
    if args.operation == "bind":
        write_new(outer / BINDING, encoded)
    else:
        require(read(outer / BINDING, 4 * 1024 * 1024) == encoded,
                "consumer runtime binding is stale, modified, or for a different source/run")
    print(json.dumps({"operation": args.operation, "kind": args.kind,
                      "consumer_runtime_binding_sha256": digest(encoded),
                      "source_head_sha": args.source_head, "producer_head_sha": PRODUCER_HEAD,
                      "whole_runtime_verified_against_consumer": True,
                      "consumer_android_build_proven": False, "phone_contacted": False}))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("check-sources", "bind", "verify"))
    parser.add_argument("--kind", choices=("mnn", "ui"))
    parser.add_argument("--consumer-root", type=Path, required=True)
    parser.add_argument("--producer-root", type=Path, required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--compiler-identity", type=Path)
    parser.add_argument("--ndk", type=Path)
    parser.add_argument("--sdk-libs", type=Path)
    return execute(parser.parse_args())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"state": "rejected", "consumer_android_build_proven": False,
                          "phone_contacted": False, "error": type(error).__name__ + ": " + str(error)}))
        raise SystemExit(2)
