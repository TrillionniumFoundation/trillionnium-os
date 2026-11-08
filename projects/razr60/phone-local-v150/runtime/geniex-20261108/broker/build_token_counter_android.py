#!/usr/bin/env python3
"""Rebuild the pinned Bionic token counter into a new directory; never deploys it."""
from pathlib import Path
import argparse
import hashlib
import json
import platform
import subprocess
import time

SOURCE_SHA = "59fc52b4cc23db15093c072b3514ccf5b11e2d8ccbfaf920d2db5e3f24c7f132"
HEADER_SHA = "2575b68c8efc882d5713491dce71a0290ce9c33f8389c183555b105a7432967b"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ndk", type=Path, required=True, help="Existing Android NDK r28b (28.1.13356709)")
    ap.add_argument("--output", type=Path, required=True, help="New, absent build directory")
    ap.add_argument("--host-tag", choices=["darwin-x86_64", "linux-x86_64"])
    args = ap.parse_args()
    source_root = Path(__file__).resolve().parent
    source, header = source_root / "token_count.c", source_root / "vendor/tokenizers_c.h"
    if digest(source) != SOURCE_SHA or digest(header) != HEADER_SHA:
        ap.error("Source or official header differs from the frozen, reviewed pins")
    ndk = args.ndk.resolve()
    properties = (ndk / "source.properties").read_text()
    if "Pkg.Revision = 28.1.13356709" not in properties:
        ap.error("This build pin requires the actual r28b revision, irrespective of directory name")
    host_tag = args.host_tag or ("darwin-x86_64" if platform.system() == "Darwin" else "linux-x86_64")
    tools = ndk / "toolchains/llvm/prebuilt" / host_tag / "bin"
    compiler = tools / "aarch64-linux-android28-clang"
    if not compiler.is_file():
        ap.error("Existing API 28 AArch64 compiler is missing")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    for subdir in ["source/vendor", "artifacts", "logs"]:
        (out / subdir).mkdir(parents=True)
    copied_source = out / "source/token_count.c"
    copied_source.write_bytes(source.read_bytes())
    (out / "source/vendor/tokenizers_c.h").write_bytes(header.read_bytes())
    binary = out / "artifacts/hepta-token-count"
    command = [str(compiler), "-std=c11", "-O2", "-fPIE", "-pie", "-Wall", "-Wextra",
               "-Wpedantic", "-Werror", "-ffunction-sections", "-fdata-sections",
               "-Wl,--gc-sections", "-Wl,-z,relro,-z,now", str(copied_source), "-ldl", "-o", str(binary)]
    version = subprocess.run([str(compiler), "--version"], capture_output=True, check=True, timeout=20).stdout.decode()
    started = time.monotonic()
    compiled = subprocess.run(command, capture_output=True, timeout=60)
    elapsed = time.monotonic() - started
    (out / "logs/compile.stdout").write_bytes(compiled.stdout)
    (out / "logs/compile.stderr").write_bytes(compiled.stderr)
    compiled.check_returncode()
    before_strip = digest(binary)
    strip_command = [str(tools / "llvm-strip"), "--strip-unneeded", str(binary)]
    subprocess.run(strip_command, check=True, timeout=20)
    elf = subprocess.run([str(tools / "llvm-readelf"), "-h", "-d", str(binary)],
                         capture_output=True, check=True, timeout=20).stdout.decode()
    (out / "logs/elf.txt").write_text(elf)
    manifest = {"schema": "hepta.token-counter-android-build.v1", "candidate_only": True,
                "source_sha256": SOURCE_SHA, "header_sha256": HEADER_SHA,
                "ndk_source_properties": properties, "compiler_version": version,
                "command": command, "strip_command": strip_command, "elapsed_seconds": elapsed,
                "binary": {"path": str(binary), "bytes": binary.stat().st_size,
                           "sha256": digest(binary), "prestrip_sha256": before_strip},
                "elf": elf, "phone_validated": False, "production_receipt": False}
    (out / "BUILD-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
