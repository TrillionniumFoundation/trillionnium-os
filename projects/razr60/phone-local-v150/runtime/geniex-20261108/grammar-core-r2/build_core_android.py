#!/usr/bin/env python3
"""Build only the reviewed QAIRT core against the unchanged official processor.

Read a pinned build request on stdin. This script has no ADB or phone operation.
The original source, review patches, unstripped result, and all logs are retained.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    os.umask(0o077)
    req = json.load(sys.stdin)
    root = Path(req["workdir"])
    root.mkdir(mode=0o700, exist_ok=False)
    for name in ("logs", "review", "inputs", "reference", "artifacts", "abi"):
        (root / name).mkdir()
    (root / "BUILD-REQUEST.json").write_text(json.dumps(req, indent=2) + "\n")
    env = dict(os.environ)
    ndk = Path(req["ndk"])
    env["ANDROID_NDK_ROOT"] = str(ndk)
    toolbin = ndk / "toolchains/llvm/prebuilt/darwin-x86_64/bin"
    cmake = "/opt/homebrew/bin/cmake"
    steps = []

    def run(label, argv, timeout=180, cwd=None):
        started = time.monotonic()
        with (root / "logs" / (label + ".stdout")).open("wb") as out, \
                (root / "logs" / (label + ".stderr")).open("wb") as err:
            p = subprocess.run(argv, cwd=cwd, env=env, stdout=out, stderr=err,
                               timeout=timeout)
        item = {"stage": label, "argv": [str(x) for x in argv],
                "returncode": p.returncode,
                "seconds": round(time.monotonic() - started, 3)}
        steps.append(item)
        (root / "STEPS.json").write_text(json.dumps(steps, indent=2) + "\n")
        print(json.dumps({k: item[k] for k in ("stage", "returncode", "seconds")}), flush=True)
        if p.returncode:
            raise RuntimeError(label + " failed; see retained log")
        return (root / "logs" / (label + ".stdout")).read_text(errors="replace")

    scp = ["/usr/bin/scp", "-p", "-o", "BatchMode=yes", "-o",
           "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes"]
    archive = root / "core-r2-fixed-inputs.tar.gz"
    run("copy-fixed-inputs", scp + ["hepta-pocket4:" + req["inputs"]["archive"], str(archive)])
    assert archive.stat().st_size == req["inputs"]["archive_bytes"]
    assert sha(archive) == req["inputs"]["archive_sha256"]
    seen = set()
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        assert sum(m.size for m in members) < 100_000_000
        for m in members:
            rel = PurePosixPath(m.name)
            assert m.isfile() and not rel.is_absolute() and ".." not in rel.parts
            assert str(rel) not in seen
            seen.add(str(rel))
            target = root / "inputs" / str(rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = tf.extractfile(m)
            assert stream is not None
            data = stream.read()
            assert len(data) == m.size
            target.write_bytes(data)
    source_manifest = root / "inputs/INPUTS-MANIFEST.json"
    assert sha(source_manifest) == req["inputs"]["manifest_sha256"]
    inputs = json.loads(source_manifest.read_text())
    for row in inputs["files"]:
        if row["input"] in ("qairt", "proc"):
            path = root / "inputs" / row["input"] / row["path"]
        elif row["input"] == "sdk":
            path = root / "inputs/arm64-android-llvm.cmake"
        else:
            path = root / "inputs" / row["path"]
        assert path.stat().st_size == row["bytes"] and sha(path) == row["sha256"]
    for row in req["review_files"]:
        data = row["content"].encode()
        assert len(data) == row["bytes"]
        assert hashlib.sha256(data).hexdigest() == row["sha256"]
        path = root / "review" / row["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    refroot = req["baseline_path"]
    for row in req["baseline"]["libraries"]:
        name = Path(row["file"]).name + ".symbols.json"
        path = root / "reference" / name
        run("copy-" + name, scp + ["hepta-pocket4:" + refroot + "/" + name, str(path)])
        assert sha(path) == row["symbols_file_sha256"]
    (root / "reference/ABI-BASELINE.json").write_text(json.dumps(req["baseline"], indent=2) + "\n")
    (root / "reference/ABI-DYNAMIC-CORRECTION.json").write_text(json.dumps(req["baseline_dynamic"], indent=2) + "\n")
    original_dynamic = root / "reference/libgeniex_core.so.dynamic.stdout"
    run("copy-original-core-dynamic", scp + ["hepta-pocket4:" + refroot + "/libgeniex_core.so.dynamic.stdout", str(original_dynamic)])
    assert sha(original_dynamic) == req["baseline_dynamic"]["libraries"][0]["raw_dynamic_sha256"]

    source = root / "qairt-patched"
    shutil.copytree(root / "inputs/qairt", source)
    run("init-isolated-patched-source", ["/usr/bin/git", "init", str(source)])
    pm = json.loads((root / "review/review-r2/PATCH-MANIFEST.json").read_text())
    for row in pm["patches"]:
        assert sha(source / row["target"]) == row["upstream_sha256"]
        patch = root / "review/review-r2" / row["file"]
        assert sha(patch) == row["sha256"]
        run("check-" + row["file"], ["/usr/bin/git", "apply", "--check", str(patch)], cwd=source)
        run("apply-" + row["file"], ["/usr/bin/git", "apply", str(patch)], cwd=source)
        assert sha(source / row["target"]) == row["patched_source_sha256"]

    compiler = run("compiler-version", [str(toolbin / "clang++"), "--version"])
    cmake_version = run("cmake-version", [cmake, "--version"])
    ndk_properties = (ndk / "source.properties").read_text()
    proc = root / "inputs/proc"
    deps = ";".join(str(proc / "third-party" / part / "include")
                    for part in ("xtl", "xtensor", "xtensor-io", "xtensor-blas"))
    build = root / "build"
    configure = [cmake, "-S", str(source), "-B", str(build), "-G", "Unix Makefiles",
                 "-DCMAKE_MAKE_PROGRAM=/usr/bin/make",
                 "-DCMAKE_TOOLCHAIN_FILE=" + str(root / "inputs/arm64-android-llvm.cmake"),
                 "-DANDROID_ABI=arm64-v8a", "-DANDROID_PLATFORM=android-31",
                 "-DANDROID_STL=c++_static", "-DCMAKE_BUILD_TYPE=Release",
                 "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                 "-DCMAKE_SHARED_LINKER_FLAGS=-Wl,-rpath,$ORIGIN",
                 "-DCMAKE_CXX_STANDARD_LIBRARIES=-llog -ldl -latomic -lm",
                 "-DGENIEX_BUILD_VLM=OFF", "-DGENIEX_BUILD_AUDIO=OFF",
                 "-DGENIEX_BUILD_OCR=OFF", "-DGENIEX_BUILD_EXAMPLES=OFF",
                 "-DGENIEX_BUILD_TESTS=OFF", "-DGENIEX_DEBUG=OFF",
                 "-DGENIEX_SKIP_HTP_RUNTIME_COPY=ON",
                 "-DGENIEX_PROC_PREBUILT_LIBRARY=" + str(root / "inputs/prebuilt/libgeniex-proc.so"),
                 "-DGENIEX_PROC_PREBUILT_INCLUDE_DIR=" + str(proc / "include"),
                 "-DGENIEX_PROC_PUBLIC_DEPENDENCY_INCLUDE_DIRS=" + deps]
    run("cmake-configure", configure)
    run("cmake-build-core", [cmake, "--build", str(build), "--target", "geniex_core", "--parallel", "4"], timeout=900)
    built = build / "bin/libgeniex_core.so"
    assert built.is_file()
    final = root / "artifacts/libgeniex_core.so"
    shutil.copyfile(built, final)
    run("strip-candidate", [str(toolbin / "llvm-strip"), "--strip-unneeded", str(final)])
    readelf = str(toolbin / "llvm-readelf")
    raw = {}
    for label, opts in (("header", ["-h"]), ("dynamic", ["-d"]),
                        ("dynsym", ["--dyn-syms"]), ("versions", ["--version-info"]),
                        ("comment", ["-p", ".comment"])):
        raw[label] = run("candidate-" + label, [readelf, "-W", *opts, str(final)])
        (root / "abi" / (label + ".txt")).write_text(raw[label])
    symbols = []
    for line in raw["dynsym"].splitlines():
        p = line.split()
        if len(p) >= 8 and p[0].rstrip(":").isdigit():
            symbols.append(dict(name=p[7], type=p[3], binding=p[4], visibility=p[5], section=p[6]))
    (root / "abi/candidate-symbols.json").write_text(json.dumps(symbols, indent=2) + "\n")
    old = json.loads((root / "reference/libgeniex_core.so.symbols.json").read_text())
    old_defined = {x["name"] for x in old if x["section"] != "UND"}
    new_defined = {x["name"] for x in symbols if x["section"] != "UND"}
    old_undefined = {x["name"] for x in old if x["section"] == "UND"}
    new_undefined = {x["name"] for x in symbols if x["section"] == "UND"}
    consumer_needs = set()
    for name in ("libgeniex-proc.so", "libgeniex_vlm.so", "libgeniex_plugin.so"):
        consumer_needs.update(x["name"] for x in json.loads((root / "reference" / (name + ".symbols.json")).read_text()) if x["section"] == "UND")
    required = consumer_needs & old_defined
    dyn = raw["dynamic"]
    comparison = {"schema": "hepta.qairt-core-abi-comparison.v1",
                  "status": "BUILD_CANDIDATE_REQUIRES_REVIEW_AND_PHONE_TESTS",
                  "phone_accessed": False,
                  "original_core_sha256": req["baseline"]["libraries"][0]["sha256"],
                  "candidate_core_sha256": sha(final),
                  "soname": re.findall(r"\(SONAME\).*?\[(.*?)\]", dyn),
                  "needed": re.findall(r"\(NEEDED\).*?\[(.*?)\]", dyn),
                  "runpath": re.findall(r"\((?:RUNPATH|RPATH)\).*?\[(.*?)\]", dyn),
                  "original_runpath": re.findall(r"\((?:RUNPATH|RPATH)\).*?\[(.*?)\]", original_dynamic.read_text()),
                  "defined_symbols_original": len(old_defined), "defined_symbols_candidate": len(new_defined),
                  "missing_original_definitions": sorted(old_defined - new_defined),
                  "new_definitions": sorted(new_defined - old_defined),
                  "missing_known_consumer_requirements": sorted(required - new_defined),
                  "known_consumer_requirements": sorted(required),
                  "new_undefined_symbols": sorted(new_undefined - old_undefined),
                  "removed_undefined_symbols": sorted(old_undefined - new_undefined)}
    (root / "abi/ABI-COMPARISON.json").write_text(json.dumps(comparison, indent=2) + "\n")
    report = {"schema": "hepta.qairt-core-android-build.v1", "status": comparison["status"],
              "phone_accessed": False, "model_qnn_processor_worker_modified": False,
              "source_inputs_manifest_sha256": sha(source_manifest),
              "review_patch_manifest_sha256": sha(root / "review/review-r2/PATCH-MANIFEST.json"),
              "ndk_directory": str(ndk), "ndk_source_properties": ndk_properties,
              "compiler": compiler, "cmake": cmake_version,
              "toolchain_source_sha256": sha(root / "inputs/arm64-android-llvm.cmake"),
              "configure_argv": configure, "build_parallelism": 4,
              "android_stl": "c++_static", "android_api": 31,
              "system_link_libraries": ["log", "dl", "atomic", "m"],
              "unstripped_bytes": built.stat().st_size, "unstripped_sha256": sha(built),
              "candidate_bytes": final.stat().st_size, "candidate_sha256": sha(final),
              "abi_comparison_sha256": sha(root / "abi/ABI-COMPARISON.json"),
              "compile_commands_sha256": sha(build / "compile_commands.json"),
              "cmake_cache_sha256": sha(build / "CMakeCache.txt"),
              "processor_sha256_unchanged": sha(root / "inputs/prebuilt/libgeniex-proc.so"),
              "build_steps": steps}
    (root / "BUILD-MANIFEST.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"stage": "ready_for_abi_review", "workdir": str(root),
                      "candidate": str(final), "candidate_bytes": final.stat().st_size,
                      "candidate_sha256": sha(final), "manifest_sha256": sha(root / "BUILD-MANIFEST.json"),
                      "missing_known_consumer_requirements": comparison["missing_known_consumer_requirements"],
                      "missing_original_definition_count": len(comparison["missing_original_definitions"]),
                      "needed": comparison["needed"], "soname": comparison["soname"]}), flush=True)


if __name__ == "__main__":
    main()
