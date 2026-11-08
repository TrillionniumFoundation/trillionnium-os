#!/usr/bin/env python3
"""Use pinned on-device magiskboot on a fresh ordinary-file working copy only.

No flash, block-device write, reboot, mount, policy change, service action or UI
operation is available. Preserve every failure and never reuse the work path.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

IMAGE_SHA = "ff159c91e06c34b0611ed5b071575dded3955e62f263fb5fec7d96b42c19436f"
MAGISKBOOT_SHA = "97e9ec75731103d31c9e1effca7a50c6444309ce8f78c2ec27e9fe721da4bb54"
STOP_SHA = "ff6401f96ef8d2206e61e9fdf6d75d1dd11fe25f5696d7f6996b6647023fdb07"
CLAIMS_SHA = "7feecc970e6499cd1735e5b0bf2c68386c669462a89a76d84f5bfc8b2225dd8c"
ROOTFS_MANIFEST = "/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.image-manifest.json"


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def new_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def python_members(value):
    result = []
    def walk(node, path):
        if isinstance(node, dict):
            if any(isinstance(item, str) and item.lstrip("/") in {"usr/bin/python3", "usr/bin/python3.11", "usr/bin/python3.12", "usr/bin/python3.13"}
                   for item in node.values()) or any(str(key).lstrip("/") == "usr/bin/python3" for key in node):
                result.append({"json_path": path, "entry": node})
            else:
                for key, item in node.items():
                    walk(item, path + "/" + str(key))
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, path + "/" + str(index))
    walk(value, "")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--instance", required=True)
    args = parser.parse_args()
    need(args.adb.is_absolute() and args.adb.is_file() and 1 <= args.port <= 65535, "explicit transport required")
    need(re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.serial) and re.fullmatch("[0-9a-f]{32}", args.instance), "transport/instance invalid")
    original = args.image.read_bytes()
    need(len(original) == 8388608 and sha(original) == IMAGE_SHA, "not the verified original backup")
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    work = "/data/local/tmp/hepta-init-boot-review-" + args.instance
    adb = [str(args.adb), "-P", str(args.port), "-s", args.serial]
    rows = []

    def invoke(name, command, *, binary_input=None, timeout=30, exec_out=False):
        argv = adb + (["exec-out"] if exec_out else ["shell", "-T"]) + [shlex.join(["/product/bin/su", "-c", command])]
        started = time.monotonic()
        try:
            run = subprocess.run(argv, input=binary_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            row = {"name": name, "elapsed": time.monotonic() - started, "timed_out": True, "returncode": None}
            for key, raw in (("stdout", error.stdout or b""), ("stderr", error.stderr or b"")):
                new_file(args.out / (name + "." + key + ".raw"), raw)
                row[key] = {"bytes": len(raw), "sha256": sha(raw)}
            rows.append(row)
            raise RuntimeError("command timeout; retain this exact ordinary-file work directory") from error
        row = {"name": name, "elapsed": time.monotonic() - started, "returncode": run.returncode, "timed_out": False}
        for key, raw in (("stdout", run.stdout), ("stderr", run.stderr)):
            new_file(args.out / (name + "." + key + ".raw"), raw)
            row[key] = {"bytes": len(raw), "sha256": sha(raw)}
        rows.append(row)
        need(run.returncode == 0, "ordinary-file operation failed; no automatic retry")
        return run.stdout

    def baseline(name):
        raw = invoke(name, "\n".join(["set -eu", "getprop ro.boot.slot_suffix",
            "getprop init.svc.trillionnium_owner_open_bootstrap",
            "sha256sum /data/trillionnium/owner-open/state/emergency-stop",
            "sha256sum /data/trillionnium/owner-open/state/phone-local-v150/retained-claims.json",
            "sha256sum /data/adb/magisk/magiskboot"]))
        lines = raw.decode().splitlines()
        need(len(lines) == 5 and lines[:2] == ["_a", "stopped"] and
             [line.split()[0] for line in lines[2:]] == [STOP_SHA, CLAIMS_SHA, MAGISKBOOT_SHA], "preservation baseline differs")
        return sha(raw)

    result = {"schema": "hepta.magiskboot-ordinary-file-roundtrip.v1", "instance": args.instance,
              "phone_work_dir": work, "original_image_sha256": IMAGE_SHA, "tool_sha256": MAGISKBOOT_SHA,
              "partition_written": False, "services_started": False, "phone_rebooted": False,
              "phone_ui_actions": 0, "rows": rows}
    try:
        before = baseline("baseline-before")
        raw = invoke("rootfs-image-manifest", "cat " + shlex.quote(ROOTFS_MANIFEST), exec_out=True)
        need(0 < len(raw) <= 2 * 1024 * 1024, "rootfs manifest size differs")
        result["rootfs_manifest"] = {"bytes": len(raw), "sha256": sha(raw), "python_members": python_members(json.loads(raw))}
        need(result["rootfs_manifest"]["python_members"], "Python member metadata not found")
        invoke("create-fresh-work", "set -eu; umask 077; mkdir " + shlex.quote(work) + "; chmod 0700 " + shlex.quote(work))
        invoke("write-ordinary-input", "set -eu; set -C; umask 077; cat > " + shlex.quote(work + "/original.img"),
               binary_input=original, timeout=60)
        raw = invoke("verify-working-input", "sha256sum " + shlex.quote(work + "/original.img"))
        need(raw.decode().split()[0] == IMAGE_SHA, "ordinary working copy differs")
        invoke("magiskboot-unpack", "cd " + shlex.quote(work) + " && /data/adb/magisk/magiskboot unpack -h original.img", timeout=45)
        raw = invoke("read-original-cpio", "cat " + shlex.quote(work + "/ramdisk.cpio"), exec_out=True)
        need(0 < len(raw) <= 64 * 1024 * 1024, "cpio output size differs")
        result["unpacked_cpio"] = {"bytes": len(raw), "sha256": sha(raw)}
        invoke("magiskboot-unchanged-repack", "cd " + shlex.quote(work) + " && /data/adb/magisk/magiskboot repack original.img unchanged-repack.img", timeout=45)
        raw = invoke("read-unchanged-repack", "cat " + shlex.quote(work + "/unchanged-repack.img"), exec_out=True)
        need(4096 <= len(raw) <= 128 * 1024 * 1024 and raw[:8] == b"ANDROID!", "roundtrip output size/magic differs")
        result["unchanged_repack"] = {"bytes": len(raw), "sha256": sha(raw), "bit_exact_original": sha(raw) == IMAGE_SHA}
        raw = invoke("verify-original-after", "sha256sum " + shlex.quote(work + "/original.img") +
                     " /dev/block/by-name/init_boot_a")
        need([line.split()[0] for line in raw.decode().splitlines()] == [IMAGE_SHA, IMAGE_SHA], "original image/partition changed")
        need(baseline("baseline-after") == before, "baseline changed during ordinary-file review")
        result["status"] = "ORDINARY_FILE_ROUNDTRIP_COMPLETED_NOT_INSTALLED"
    except Exception as error:
        result.update(status="FAILED_RETAIN_ORDINARY_FILE_WORK_STATE", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        raw = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
        new_file(args.out / "RESULT.json", raw)
        print(json.dumps({"status": result["status"], "result": str(args.out / "RESULT.json"), "sha256": sha(raw)}), flush=True)


if __name__ == "__main__":
    main()
