#!/usr/bin/env python3
"""Offline NDK build. Requires the already SHA-verified official Android library.

No downloads, device commands, APK changes or phone inference are performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess

PIN = "d000b46697a43bfae6181f280240ddeff08ef25049902f42d54b35c519ec7764"
ap = argparse.ArgumentParser()
ap.add_argument("--ndk-root", required=True, type=Path)
ap.add_argument("--runtime", required=True, type=Path)
ap.add_argument("--out", required=True, type=Path)
args = ap.parse_args()
root = Path(__file__).resolve().parent
runtime = args.runtime.resolve(strict=True)
if runtime.stat().st_size != 22758512 or hashlib.sha256(runtime.read_bytes()).hexdigest() != PIN:
    raise SystemExit("official Android ARM64 runtime checksum/size mismatch")
if args.out.exists() or args.out.is_symlink():
    raise SystemExit("output must be a new directory")
args.out.mkdir(parents=True)
out = args.out.resolve()
tag = "darwin-x86_64" if platform.system() == "Darwin" else "linux-x86_64"
tools = args.ndk_root.resolve(strict=True) / "toolchains/llvm/prebuilt" / tag / "bin"
clang = tools / "aarch64-linux-android30-clang"
if not clang.is_file():
    raise SystemExit("cached NDK API30 compiler unavailable")
copied = out / "liblitert-lm.so"
shutil.copyfile(runtime, copied)
commands = []

def run(command):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True, timeout=180)
    commands.append({"argv":[str(x) for x in command], "exit_code":result.returncode,
                     "stdout":result.stdout, "stderr":result.stderr})
    if result.returncode:
        (out / "BUILD-FAILURE.json").write_text(json.dumps(commands, indent=2)+"\n")
        raise SystemExit("compile/link failed; see BUILD-FAILURE.json")
    return result.stdout

flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIE", "-pthread",
    "-DYYJSON_DISABLE_NON_STANDARD=1", "-DYYJSON_READER_DEPTH_LIMIT=32", "-DYYJSON_WRITER_DEPTH_LIMIT=40",
    "-I"+str(root/"vendor/litert"), "-I"+str(root/"vendor/litert/c"), "-I"+str(root/"vendor/yyjson")]
run([clang, *flags, "-c", root/"runner.c", "-o", out/"runner.o"])
run([clang, *flags, "-c", root/"vendor/yyjson/yyjson.c", "-o", out/"yyjson.o"])
program = out/"libhepta_litert_runner.so"
run([clang, "-fPIE", "-pie", "-pthread", out/"runner.o", out/"yyjson.o", "-L"+str(out),
     "-llitert-lm", "-Wl,--no-undefined", "-Wl,-rpath,$ORIGIN", "-Wl,-z,max-page-size=16384",
     "-ldl", "-lm", "-o", program])
shutil.copyfile(program, out/"hepta_litert_runner")
(out/"hepta_litert_runner").chmod(0o755)
program.chmod(0o755)
elf = run([tools/"llvm-readelf", "-h", "-l", "-d", "-n", program])
if "AArch64" not in elf or "liblitert-lm.so" not in elf or "INTERP" not in elf:
    raise SystemExit("linked output is not the expected Android ARM64 executable")
source_files = [p for p in root.rglob("*") if p.is_file() and "build" not in p.relative_to(root).parts]
report = {"schema":"hepta.litert-runner-android-link.v1", "android_execution":False,
    "model_inference":False, "gpu_or_npu_execution_verified":False,
    "source_root":str(root), "ndk_root":str(args.ndk_root),
    "compiler_version":run([clang,"--version"]),
    "ndk_source_properties":(args.ndk_root/"source.properties").read_text(),
    "runtime_sha256":PIN, "sources":{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files},
    "commands":commands, "elf":elf,
    "products":{p.name:{"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
                for p in [program,out/"hepta_litert_runner",copied]}}
(out/"BUILD-RESULT.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({"result":str(out/"BUILD-RESULT.json"),"products":report["products"],"android_execution":False}))
