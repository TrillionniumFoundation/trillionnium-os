#!/usr/bin/env python3
"""Read-only active init_boot backup through an explicitly selected ADB transport.

No partition write, reboot, service control, model request, or UI command exists
in this tool. A failed or interrupted transfer remains as its original .part.
The operator must reconcile that directory instead of silently repeating it.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def exclusive(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-stop-sha256", required=True)
    parser.add_argument("--expected-claims-sha256", required=True)
    args = parser.parse_args()
    need(args.adb.is_absolute() and args.adb.is_file(), "explicit adb required")
    # The selected host transport may be an operator-installed symlink. Keep
    # using that exact argv while recording its resolved executable identity.
    adb_real = args.adb.resolve(strict=True)
    need(adb_real.is_file() and os.access(args.adb, os.X_OK), "selected adb is not executable")
    need(1 <= args.port <= 65535 and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.serial), "transport identity invalid")
    for digest in (args.expected_stop_sha256, args.expected_claims_sha256):
        need(re.fullmatch("[0-9a-f]{64}", digest), "preservation pin missing")
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    adb = [str(args.adb), "-P", str(args.port), "-s", args.serial]
    rows = []

    def read_command(name, command):
        start = time.monotonic()
        result = subprocess.run(adb + ["shell", "-T", shlex.join(["/product/bin/su", "-c", command])],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        for kind, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            exclusive(args.out / (name + "." + kind + ".raw"), raw)
        rows.append({"name": name, "returncode": result.returncode, "elapsed": time.monotonic() - start,
                     "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                     "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
        need(result.returncode == 0, "read-only command failed; retain original transfer state")
        return result.stdout.decode("utf-8", errors="strict")

    def baseline(name):
        command = "\n".join([
            "set -eu", "getprop ro.boot.slot_suffix", "getprop init.svc.trillionnium_owner_open_bootstrap",
            "sha256sum /data/trillionnium/owner-open/state/emergency-stop",
            "sha256sum /data/trillionnium/owner-open/state/phone-local-v150/retained-claims.json"])
        lines = read_command(name, command).splitlines()
        need(len(lines) == 4 and re.fullmatch(r"_[ab]", lines[0]) and lines[1] == "stopped", "active slot/service state differs")
        need(lines[2].split()[0] == args.expected_stop_sha256 and lines[3].split()[0] == args.expected_claims_sha256,
             "stop or claims changed")
        return lines[0]

    def transfer(name, source, expected_size, expected_sha):
        partial = args.out / (name + ".part")
        start = time.monotonic()
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            result = subprocess.run(adb + ["exec-out", shlex.join(["/product/bin/su", "-c", "cat " + shlex.quote(source)])],
                                    stdout=stream, stderr=subprocess.PIPE, timeout=60)
            stream.flush(); os.fsync(stream.fileno())
        exclusive(args.out / (name + ".stderr.raw"), result.stderr)
        observed_size, observed_sha = partial.stat().st_size, sha_file(partial)
        row = {"name": name, "returncode": result.returncode, "elapsed": time.monotonic() - start,
               "bytes": observed_size, "sha256": observed_sha, "expected_bytes": expected_size,
               "expected_sha256": expected_sha}
        rows.append(row)
        need(result.returncode == 0 and observed_size == expected_size and observed_sha == expected_sha,
             "original read is incomplete or differs; do not retry blindly")
        destination = args.out / name
        need(not destination.exists(), "backup already exists")
        partial.rename(destination)
        directory = os.open(args.out, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return row

    result = {"schema": "hepta.active-init-boot-readonly-backup.v1", "partition_written": False,
              "services_started": False, "phone_rebooted": False, "rows": rows,
              "adb": {"selected_path": str(args.adb), "resolved_path": str(adb_real),
                      "sha256": sha_file(adb_real)}}
    try:
        slot = baseline("baseline-before")
        image = "/dev/block/by-name/init_boot" + slot
        command = "\n".join(["set -eu", "readlink -f " + image,
            "/data/adb/magisk/busybox blockdev --getsize64 " + image, "sha256sum " + image,
            "stat -c %s /data/adb/magisk/magiskboot", "sha256sum /data/adb/magisk/magiskboot",
            "/data/adb/magisk/magisk -V"])
        lines = read_command("immutable-input-metadata", command).splitlines()
        need(len(lines) == 6 and lines[0].startswith("/dev/block/") and lines[5] == "31100", "observed Magisk/partition differs")
        image_size, tool_size = int(lines[1]), int(lines[3])
        need(1024 * 1024 <= image_size <= 128 * 1024 * 1024 and 65536 <= tool_size <= 8 * 1024 * 1024,
             "unexpected bounded image/tool size")
        image_sha, tool_sha = lines[2].split()[0], lines[4].split()[0]
        need(re.fullmatch("[0-9a-f]{64}", image_sha) and re.fullmatch("[0-9a-f]{64}", tool_sha), "remote SHA missing")
        result.update(active_slot=slot, input_partition=image, real_partition=lines[0], magisk_version_code=31100)
        result["image"] = transfer("active-init_boot" + slot + ".img", image, image_size, image_sha)
        result["magiskboot"] = transfer("phone-magiskboot", "/data/adb/magisk/magiskboot", tool_size, tool_sha)
        need(baseline("baseline-after") == slot, "active slot changed during backup")
        # Local-host inventory only; the Android tool is not executed here.
        result["host_tools"] = {name: shutil.which(name) for name in ("qemu-aarch64", "qemu-aarch64-static", "readelf", "cpio")}
        result["status"] = "VERIFIED_READONLY_BACKUP_NO_UNPACK_OR_FLASH"
    except Exception as error:
        result.update(status="FAILED_RETAIN_ORIGINAL_PARTIAL_STATE", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        raw = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
        exclusive(args.out / "RESULT.json", raw)
        print(json.dumps({"status": result["status"], "result_path": str(args.out / "RESULT.json"),
                          "result_sha256": hashlib.sha256(raw).hexdigest()}), flush=True)


if __name__ == "__main__":
    main()
