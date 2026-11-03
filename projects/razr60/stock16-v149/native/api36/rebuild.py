#!/usr/bin/env python3
"""Rebuild the three API36 native control programs without device access.

The recipes use the captured AOSP headers and stock16 shared libraries. --root-map
can relocate external dependency trees. Inputs are read only; every output is
created beneath a new --out directory. No produced executable is run.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import time

HERE = Path(__file__).resolve().parent
MEMORY = 8 * 1024**3
ALLOWED = {
    "prebuilts/clang/host/linux-x86/clang-r584948b/bin/clang++",
    "prebuilts/clang/host/linux-x86/clang-r584948b/bin/llvm-strip",
    "/usr/bin/readelf",
}

def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024**2), b""):
            h.update(chunk)
    return h.hexdigest()

def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()

def limits() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY, MEMORY))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--root-map", type=Path,
                    help="JSON map from recorded absolute directory prefixes to relocated directories")
    args = ap.parse_args()
    conf_path = HERE / "recipes.json"
    conf = json.loads(conf_path.read_text())
    remap = json.loads(args.root_map.read_text()) if args.root_map else {}
    assert isinstance(remap, dict) and all(Path(k).is_absolute() and Path(v).is_absolute()
                                          for k, v in remap.items())
    def relocate(value: str) -> str:
        for old in sorted(remap, key=len, reverse=True):
            if value == old or value.startswith(old.rstrip("/") + "/"):
                return remap[old].rstrip("/") + value[len(old):]
        return value
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    for d in ("logs", "work", "source"):
        (out / d).mkdir()
    source_pins = {}
    for p in sorted((HERE / "source").iterdir()):
        assert p.is_file() and not p.is_symlink(), str(p)
        before = sha(p)
        shutil.copyfile(p, out / "source" / p.name)
        assert sha(out / "source" / p.name) == before
        source_pins[p.name] = {"sha256": before, "bytes": p.stat().st_size}
    receipt = {
        "schema": "razr60-native-api36-fresh-rebuild-v1",
        "started_utc": utc(), "script_sha256": sha(Path(__file__)),
        "recipes_sha256": sha(conf_path), "source_pins": source_pins,
        "commands": [], "modules": [], "phone_operations": 0,
        "target_program_executions": 0, "network_namespace": "isolated",
        "qualification": "API36 retarget using retained AOSP17 headers and stock16 link libraries",
        "compiler_success": False, "all_binaries_match_installed": False,
    }
    def save() -> None:
        (out / "NATIVE-REBUILD-RECEIPT.json").write_text(
            json.dumps(receipt, indent=2) + "\n")
    def verify(item):
        name, expected = item
        p = Path(relocate(name))
        if not p.is_file():
            raise RuntimeError("Missing pinned dependency: " + str(p))
        observed = {"sha256": sha(p), "bytes": p.stat().st_size}
        if observed != expected:
            raise RuntimeError("Dependency pin mismatch: " + str(p))
        return name, observed
    try:
        if hasattr(os, "sched_setaffinity"):
            os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:4])
        os.nice(5)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            observed = dict(pool.map(verify, conf["external_dependency_pins"].items()))
        receipt["external_dependency_count"] = len(observed)
        receipt["external_dependency_pins_sha256"] = hashlib.sha256(
            json.dumps(observed, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        for recipe in conf["recipes"]:
            names = {"bootstrap": "owner_open_bootstrap.cpp",
                     "ingress": "owner_open_ingress_proxy.cpp",
                     "emergency-stop": "owner_open_emergency_stop.cpp"}
            assert source_pins[names[recipe["component"]]]["sha256"] == recipe["source_sha256"]
            folder = out / "work" / recipe["variant"]
            folder.mkdir(exist_ok=True)
            rsp = folder / (recipe["module"] + ".new.rsp")
            shutil.copyfile(HERE / recipe["response_file"], rsp)
            for recorded in recipe["commands"]:
                argv = list(recorded["argv"])
                assert argv[0] == "/usr/bin/bwrap" and "--unshare-all" in argv
                marker = argv.index("--")
                assert argv[marker + 1] in ALLOWED
                for i, word in enumerate(list(argv[:marker])):
                    if word == "--ro-bind":
                        source, target = argv[i + 1], argv[i + 2]
                        if source == conf["source_root_mount"]:
                            argv[i + 1] = str(out / "source")
                        elif source == conf["bootstrap_override_mount"]:
                            argv[i + 1] = str(out / "source/owner_open_bootstrap.cpp")
                        else:
                            argv[i + 1] = relocate(source)
                    elif word == "--bind":
                        assert argv[i + 2] == "/work", "Unexpected writable mount"
                        argv[i + 1] = str(out / "work")
                label = recorded["label"]
                start = time.monotonic()
                with (out / "logs" / (label + ".stdout")).open("xb") as so, \
                        (out / "logs" / (label + ".stderr")).open("xb") as se:
                    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                                         start_new_session=True, preexec_fn=limits)
                    try:
                        rc = p.wait(timeout=120)
                    except BaseException:
                        os.killpg(p.pid, signal.SIGKILL)
                        p.wait(timeout=5)
                        raise
                row = {"label": label, "returncode": rc,
                       "elapsed_seconds": time.monotonic() - start,
                       "argv": argv}
                receipt["commands"].append(row)
                save()
                print(json.dumps({"label": label, "returncode": rc}), flush=True)
                if rc:
                    raise RuntimeError(label + " failed; see logs")
            binary = folder / recipe["module"]
            observed_binary = {"sha256": sha(binary), "bytes": binary.stat().st_size}
            match = observed_binary == recipe["expected_installed_binary"]
            receipt["modules"].append({"component": recipe["component"],
                                       "binary": str(binary), "observed": observed_binary,
                                       "expected_installed": recipe["expected_installed_binary"],
                                       "matches_installed": match})
        receipt["compiler_success"] = len(receipt["modules"]) == 3
        receipt["all_binaries_match_installed"] = all(
            m["matches_installed"] for m in receipt["modules"])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            after = dict(pool.map(verify, conf["external_dependency_pins"].items()))
        receipt["external_dependencies_unchanged"] = after == observed
        receipt["source_unchanged"] = all(
            sha(HERE / "source" / name) == v["sha256"] for name, v in source_pins.items())
    except BaseException as exc:
        receipt["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        receipt["finished_utc"] = utc()
        receipt["pass"] = (receipt["compiler_success"]
                           and receipt["all_binaries_match_installed"]
                           and receipt.get("external_dependencies_unchanged", False)
                           and receipt.get("source_unchanged", False))
        save()
    print(json.dumps({"receipt": str(out / "NATIVE-REBUILD-RECEIPT.json"),
                      "pass": receipt["pass"], "error": receipt.get("error"),
                      "modules": receipt["modules"]}), flush=True)
    return 0 if receipt["pass"] else 1

if __name__ == "__main__":
    raise SystemExit(main())

