#!/usr/bin/env python3
"""Build the isolated v0.10.0 single-request Android worker; never deploy it."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import time

WORKER_SHA256 = "07cd434bea9d1214acef499a69ed204ecef879a6ac05c82f24d062160e2efb3e"
HEADER_SHA256 = "c5d441ee290c5ec83f01ec1af9a7c16cdd8c740b522b78c23ed667062fc21e40"
LIB_SHA256 = "99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--geniex-package", type=Path, required=True,
                        help="Extracted official geniex-bench-android-arm64-v0.10.0 directory")
    parser.add_argument("--output", type=Path, required=True, help="New build directory")
    args = parser.parse_args()
    source_root = Path(__file__).resolve().parent
    source = source_root / "worker.c"
    header = source_root / "vendor/geniex.h"
    library = args.geniex_package.resolve() / "lib/libgeniex.so"
    for path, expected in ((source, WORKER_SHA256), (header, HEADER_SHA256), (library, LIB_SHA256)):
        actual = digest(path)
        if actual != expected:
            raise SystemExit("Pinned build input differs: %s (%s)" % (path, actual))
    ndk = args.ndk.resolve()
    compilers = sorted((ndk / "toolchains/llvm/prebuilt").glob("*/bin/aarch64-linux-android28-clang"))
    if len(compilers) != 1:
        raise SystemExit("Expected exactly one Android 28 AArch64 compiler in the NDK")
    compiler = compilers[0]
    tool_bin = compiler.parent
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    binary = out / "hepta-geniex-once"
    command = [
        str(compiler), "-std=c11", "-O2", "-fPIE", "-pie",
        "-Wall", "-Wextra", "-Wpedantic", "-Werror",
        "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
        "-Wl,-z,relro,-z,now", "-isystem", str(header.parent),
        str(source), "-L", str(library.parent), "-lgeniex", "-lm",
        "-o", str(binary),
    ]
    manifest = {
        "status": "candidate build in progress",
        "production_ready": False,
        "worker_sha256": WORKER_SHA256,
        "header_sha256": HEADER_SHA256,
        "libgeniex_sha256": LIB_SHA256,
        "geniex_tag": "v0.10.0",
        "geniex_commit": "071f609995470bdb0e0769ab964754adfaab7e47",
        "llama_cpp_commit": "19cce6919992fdffd92e0ac152caaf1e2b8f254e",
        "ndk_source_properties": (ndk / "source.properties").read_text(),
        "command": command,
        "power_mode": "sustained_high_performance",
        "api_level": 28,
    }
    started = time.monotonic()
    try:
        version = subprocess.run([str(compiler), "--version"], capture_output=True, check=True, timeout=15)
        manifest["compiler_version"] = version.stdout.decode("utf-8", errors="replace")
        result = subprocess.run(command, capture_output=True, timeout=120)
        (out / "compile.stdout").write_bytes(result.stdout)
        (out / "compile.stderr").write_bytes(result.stderr)
        manifest["compiler_exit"] = result.returncode
        result.check_returncode()
        manifest["before_strip_sha256"] = digest(binary)
        strip = [str(tool_bin / "llvm-strip"), "--strip-unneeded", str(binary)]
        subprocess.run(strip, check=True, timeout=15)
        elf = subprocess.run([str(tool_bin / "llvm-readelf"), "-h", "-d", str(binary)],
                             capture_output=True, check=True, timeout=15)
        (out / "elf.txt").write_bytes(elf.stdout)
        manifest.update(
            status="Android candidate built; no device execution performed by this script",
            binary_sha256=digest(binary), binary_bytes=binary.stat().st_size,
            strip_command=strip,
        )
    finally:
        manifest["elapsed_seconds"] = time.monotonic() - started
        (out / "BUILD-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
