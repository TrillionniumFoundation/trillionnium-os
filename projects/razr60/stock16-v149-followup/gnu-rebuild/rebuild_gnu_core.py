#!/usr/bin/env python3
"""Fresh GNU core build using the frozen build recipe and measured local inputs.

Execute in a fresh owned directory under a read-only-root, network-isolated
bubblewrap sandbox. No phone/service access and no dependency downloads. The
existing build recipe supplies the compiler/link commands; this driver relocates
its source/output/toolchain and replaces only its historical post-build probes.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import uuid

HISTORICAL_SCRIPT_SHA = "54846b00dd7452b1b9da30fa56bf55cad1ec647075fc6e2342e3a50beed021ff"
HISTORICAL_INPUTS_SHA = "f18f5c440de9dd33348a9fde2bd2699fbcbaf5d0707e1b11715598262ad28c2b"
RUNTIME_MANIFEST_SHA = "0bb197a636625d6edf2a82f8cf27fdc76ccea8a0c8a04b5fb254be446b7b06c7"
INSTALLED_CORE_SHA = "7046846404871ceffe1cc3241fc6aa2da6c281eb8832595dc26b283e307b4031"
CORE_SOURCE_SHA = "070bb8e6bd56e065f56e7eaa2ebc6ab9e0bd0dde1050942f3b8ab5136823fc26"
LOCK_SHA = "2a9c12114e6844a97fad887717350572c62d124090f639c939f2a380a6e37da3"


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024**2), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory(root):
    return {str(p.relative_to(root)): {"bytes": p.stat().st_size, "sha256": sha(p)}
            for p in sorted(root.rglob("*")) if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--historical-builder", type=Path, required=True)
    parser.add_argument("--historical-inputs", type=Path, required=True)
    parser.add_argument("--rust-toolchain", type=Path, required=True)
    parser.add_argument("--runtime-libs", type=Path, required=True)
    a = parser.parse_args()
    source = a.source.resolve(strict=True)
    out = a.out.resolve()
    if out.exists():
        parser.error("output must not exist")
    builder = a.historical_builder.resolve(strict=True)
    historical_inputs = a.historical_inputs.resolve(strict=True)
    rust = a.rust_toolchain.resolve(strict=True)
    libs_input = a.runtime_libs.resolve(strict=True)
    assert sha(builder) == HISTORICAL_SCRIPT_SHA
    assert sha(historical_inputs) == HISTORICAL_INPUTS_SHA
    assert sha(libs_input / "manifest.json") == RUNTIME_MANIFEST_SHA
    assert sha(source / "Cargo.lock") == LOCK_SHA
    assert sha(source / "apps/trillionnium-owner-open-host/src/bin/r5_control_host_v4/process.rs") == CORE_SOURCE_SHA
    original = json.loads(historical_inputs.read_text())
    runtime = json.loads((libs_input / "manifest.json").read_text())
    for name, expected in runtime["files"].items():
        assert sha(libs_input / name) == expected["sha256"]
    source_before = inventory(source)
    script = builder.read_text()
    marker = "libs=BASE/'actual-bookworm-public-libs'"
    assert script.count(marker) == 1
    prefix = script.split(marker, 1)[0]
    replacements = {
        "BASE=pathlib.Path(__file__).resolve().parent": "BASE=pathlib.Path(" + repr(str(out.parent)) + ")",
        "SOURCE=BASE/'proposed-4b687742'": "SOURCE=pathlib.Path(" + repr(str(source)) + ")",
        "ROOT=BASE/'gnu-actual239-r1'": "ROOT=pathlib.Path(" + repr(str(out)) + ")",
        "rustsys=pathlib.Path(subprocess.check_output(['rustc','--print','sysroot'],text=True).strip()).resolve()":
            "rustsys=pathlib.Path(" + repr(str(rust)) + ")",
    }
    for old, new in replacements.items():
        assert prefix.count(old) == 1, old
        prefix = prefix.replace(old, new)
    report = {"schema": "razr60-gnu-core-independent-rebuild-v149.1",
              "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "driver_sha256": sha(Path(__file__)), "historical_recipe_sha256": HISTORICAL_SCRIPT_SHA,
              "historical_tool_inputs_sha256": HISTORICAL_INPUTS_SHA,
              "source_baseline_commit": "4b687742fca939bc32122857f21067ec28d30a23",
              "source_file_count": len(source_before), "source_pins": source_before,
              "phone_operations": 0, "service_changes": 0, "global_installs": 0,
              "dependency_downloads": 0, "full_rootfs_rebuild": False,
              "compile_pass": False, "qemu_fixture_pass": False, "pass": False,
              "network_namespace": "isolated by caller", "QEMU_checks": [],
              "pass_gate": "Compile, exact historical input identities, runtime ABI, three QEMU fixtures, source unchanged; installed binary identity reported separately",
              "limits": {"virtual_memory_bytes": 8 * 1024**3, "cargo_jobs": 4,
                         "cargo_timeout_seconds": 180, "qemu_probe_timeout_seconds": 15}}
    namespace = {"__file__": str(builder), "__name__": "frozen_gnu_recipe"}
    try:
        os.nice(10)
        resource.setrlimit(resource.RLIMIT_AS, (8 * 1024**3, 8 * 1024**3))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if hasattr(os, "sched_setaffinity"):
            os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:4])
            report["limits"]["cpu_affinity_count"] = len(os.sched_getaffinity(0))
        exec(compile(prefix, str(builder), "exec"), namespace)
        fresh_inputs = json.loads((out / "tool-inputs.json").read_text())
        report["historical_gnu_inputs_match"] = fresh_inputs["private_GNU_inputs"] == original["private_GNU_inputs"]
        report["historical_target_std_match"] = fresh_inputs["private_target_std"] == original["private_target_std"]
        old_tools = {Path(name).name: value for name, value in original["tools"].items()
                     if Path(name).name != "target-linker.sh"}
        new_tools = {Path(name).name: value for name, value in fresh_inputs["tools"].items()
                     if Path(name).name != "target-linker.sh"}
        report["historical_host_tools_match"] = new_tools == old_tools
        report["fresh_tool_inputs_sha256"] = sha(out / "tool-inputs.json")
        binary = namespace["binary"]
        binary_sha = sha(binary)
        report.update(compile_pass=True,
                      binary={"path": str(binary), "bytes": binary.stat().st_size, "sha256": binary_sha},
                      expected_installed_core_sha256=INSTALLED_CORE_SHA,
                      binary_matches_installed=(binary_sha == INSTALLED_CORE_SHA),
                      build_steps=namespace["records"])
        assert report["historical_gnu_inputs_match"], "Historical GNU input tree changed"
        assert report["historical_target_std_match"], "Historical Rust target std changed"
        assert report["historical_host_tools_match"], "Historical host compiler tools changed"
        libs = out / "actual-public-libs"
        shutil.copytree(libs_input, libs)
        for name, expected in runtime["files"].items():
            assert sha(libs / name) == expected["sha256"]
        actual = {Path(name).name: libs / name for name in runtime["files"]}
        provided = {}
        for name, path in actual.items():
            value = subprocess.check_output(["/usr/bin/aarch64-linux-gnu-readelf", "-V", str(path)], text=True)
            definitions = value.split("Version definition section", 1)[1].split("Version needs section", 1)[0]
            provided[name] = set(re.findall(r"Name: (\S+)", definitions))
        text = namespace["text"]
        needed = re.findall(r"Shared library: \[([^]]+)\]", text)
        needs = {}
        current = None
        for line in text.split("Version needs section", 1)[1].splitlines():
            found = re.search(r"File: (\S+)\s+Cnt:", line)
            if found:
                current = found[1]
                needs[current] = set()
            found = re.search(r"Name: (\S+)", line)
            if found and current:
                needs[current].add(found[1])
        assert set(needed) <= actual.keys()
        assert all(name in provided and versions <= provided[name] for name, versions in needs.items())
        glibc = max(tuple(map(int, v[6:].split("."))) for versions in needs.values() for v in versions
                    if re.fullmatch(r"GLIBC_[0-9.]+", v))
        assert glibc <= (2, 39)
        report.update(runtime_manifest_sha256=RUNTIME_MANIFEST_SHA, runtime_files_verified=len(runtime["files"]),
                      runtime_unique_sonames=len(actual),
                      needed=needed, version_needs={k: sorted(v) for k, v in needs.items()},
                      maximum_needed_GLIBC=".".join(map(str, glibc)), all_runtime_version_needs_satisfied=True)
        loader = libs / "lib/ld-linux-aarch64.so.1"
        loader.chmod(0o700)  # Only the new owned fixture copy; original modes stay untouched.
        command = ["/usr/bin/qemu-aarch64-static", str(loader), "--library-path",
                   str(libs / "usr/lib/aarch64-linux-gnu"), str(binary)]
        def probe(label, argv, data=None):
            p = subprocess.run(argv, input=data, capture_output=True, timeout=15)
            (out / (label + ".stdout")).write_bytes(p.stdout)
            (out / (label + ".stderr")).write_bytes(p.stderr)
            report["QEMU_checks"].append({"label": label, "argv": argv, "rc": p.returncode,
                "stdout_sha256": hashlib.sha256(p.stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(p.stderr).hexdigest()})
            return p
        help_result = probe("fresh-QEMU-help", command + ["--help"])
        assert help_result.returncode == 0 and b"usage:" in help_result.stdout.lower() and not help_result.stderr
        nonce = uuid.uuid4().hex
        scope = {"session_id": "source-proof-" + nonce, "profile_id": "owner-open",
                 "task_id": "fixture-" + nonce, "turn_id": "turn-" + nonce}
        scope["turn_stream_id"] = "r5-stream-" + hashlib.sha256(json.dumps(
            {"schema": "trillionnium.owner-open.turn-stream.v1", **scope},
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        for ordinal, kind in [(1, "turn.cancel"), (2, "tool.cancel")]:
            payload = dict(scope)
            if kind == "tool.cancel":
                payload["call_id"] = "call-" + nonce
            request = {"kind": kind, "seq": ordinal, "direction": "client_to_host", "payload": payload,
                       "broker_request_id": nonce + ":" + kind, "broker_request_sha256": "a" * 64,
                       "broker_request_upstream_seq": 19 + ordinal}
            p = probe("fresh-QEMU-inactive-" + kind, command + ["--provider", "/bin/true"],
                      (json.dumps(request) + "\n").encode())
            assert p.returncode == 0 and not p.stderr
            frames = [json.loads(line) for line in p.stdout.splitlines()]
            assert len(frames) == 1 and frames[0]["kind"] == "host.error"
            assert frames[0]["payload"]["code"] == "no_active_turn"
            assert frames[0]["broker_request_id"] == request["broker_request_id"]
            assert frames[0]["broker_request_upstream_seq"] == 19 + ordinal
            assert frames[0]["payload"]["cancel_requested"] is False
        report["qemu_fixture_pass"] = True
        assert sha(binary) == binary_sha
        report["source_unchanged"] = inventory(source) == source_before
        assert report["source_unchanged"]
        report["pass"] = True
    except BaseException as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
        report["build_steps"] = namespace.get("records", [])
        report["source_unchanged"] = inventory(source) == source_before
    finally:
        out.mkdir(parents=True, exist_ok=True)
        report["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        (out / "FRESH-GNU-REBUILD-RECEIPT.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k not in {"source_pins", "build_steps"}}), flush=True)
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
