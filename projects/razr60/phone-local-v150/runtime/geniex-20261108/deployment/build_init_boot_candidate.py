#!/usr/bin/env python3
"""Append one reviewed rc, repack only ordinary files with pinned magiskboot.

No block-device write, bootloader command, reboot, service start, policy load,
or stop removal is implemented. The original block is read after repacking to
verify preservation. A partial failure retains this instance for inspection.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time

import build_startup_bundle as bundle
import inspect_init_boot as inventory
import phone_magisk_roundtrip as original

ORIGINAL_CPIO_SHA = "8171c6c6ac63ba1dcafe51fbbef4fa15474a1f93e3b4a0786c84fd4e11b2b5d1"
ORIGINAL_RC_SHA = "a2f43dc3a9fe8db8d47dcaf6a1c435b8a53232dfce378593ab8830fec49275ca"


def append_rc(cpio, name, raw):
    """Preserve every original CPIO record byte, including its metadata."""
    bundle.need(re.fullmatch(r"overlay\.d/hepta-geniex-provider-[0-9a-f]{32}\.rc", name), "unselected new rc member")
    bundle.need(isinstance(raw, bytes) and 0 < len(raw) <= 16384 and b"\0" not in raw, "bounded text rc required")
    raw.decode("utf-8", errors="strict")
    entries, payloads, trailer = inventory.cpio_inventory(cpio)
    bundle.need(name not in payloads, "new rc already exists")
    directories = [entry for entry in entries if entry["name"] == "overlay.d"]
    bundle.need(len(directories) == 1 and stat.S_ISDIR(directories[0]["mode"]), "existing overlay.d directory required")
    ino = max(entry["ino"] for entry in entries) + 1
    bundle.need(0 < ino < 0xffffffff, "new cpio inode exceeds header")
    name_raw = name.encode() + b"\0"
    values = [ino, stat.S_IFREG | 0o644, 0, 0, 1, 0, len(raw), 0, 0, 0, 0, len(name_raw), 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in values)
    record = header + name_raw
    record += b"\0" * ((-len(record)) % 4)
    record += raw + b"\0" * ((-len(raw)) % 4)
    offset = trailer["trailer_offset"]
    result = cpio[:offset] + record + cpio[offset:]
    after, after_payloads, _ = inventory.cpio_inventory(result)
    bundle.need(after[:-1] == entries and len(after) == len(entries) + 1
                and all(after_payloads[key] == value for key, value in payloads.items())
                and after[-1]["name"] == name and after_payloads[name] == raw,
                "an original cpio member changed")
    return result, {"original_members": len(entries), "candidate_members": len(after),
                    "original_records_preserved_byte_for_byte": True,
                    "new_member": after[-1], "original_cpio_sha256": bundle.sha(cpio),
                    "candidate_cpio_sha256": bundle.sha(result)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--original-image", type=Path, required=True)
    parser.add_argument("--startup-bundle", type=Path, required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    bundle.need(args.adb.is_absolute() and args.adb.is_file() and 1 <= args.port <= 65535
                and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.serial), "explicit selected transport required")
    source = bundle.raw_file(args.original_image)
    bundle.need(len(source) == 8388608 and bundle.sha(source) == original.IMAGE_SHA, "verified original image required")
    before, cpio, payloads = inventory.inspect(source)
    bundle.need(before["cpio_sha256"] == ORIGINAL_CPIO_SHA and len(before["members"]) == 33
                and bundle.sha(payloads["overlay.d/trillionnium-hepta.rc"]) == ORIGINAL_RC_SHA,
                "original ramdisk differs from reviewed active backup")
    manifest_raw = bundle.raw_file(args.startup_bundle / "BUNDLE-MANIFEST.json", 1024 * 1024)
    bundle.need(bundle.sha(manifest_raw) == args.bundle_sha256, "startup bundle differs")
    manifest = bundle.strict(manifest_raw)
    bundle.need(manifest["schema"] == "hepta.init-provider-startup-bundle.v1" and manifest["mode"] == "serve"
                and manifest["status"] == "MATERIALIZED_NOT_INSTALLED_OR_ACTIVATED", "selected serve bundle required")
    instance = manifest["instance"]
    bundle.need(re.fullmatch("[0-9a-f]{32}", instance), "complete startup identity required")
    name = "overlay.d/hepta-geniex-provider-" + instance + ".rc"
    bundle.need(manifest["early_rc_member"] == name, "rc identity differs")
    rc = bundle.raw_file(args.startup_bundle / "early-ramdisk" / name, 16384)
    expected_rc = bundle.staging.service_rc(instance, manifest["entry_plan_sha256"]).encode()
    bundle.need(rc == expected_rc, "rc does not match the selected plan")
    modified, delta = append_rc(cpio, name, rc)
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    bundle.write_new(args.out / "reviewed-added-ramdisk.cpio", modified)
    bundle.write_new(args.out / "CPIO-DELTA.json", bundle.encode(delta))
    work = "/data/local/tmp/hepta-init-boot-candidate-" + instance
    adb = [str(args.adb), "-P", str(args.port), "-s", args.serial]
    rows = []
    result = {"schema": "hepta.init-boot-candidate-review.v1", "instance": instance,
              "startup_bundle_sha256": args.bundle_sha256, "original_image_sha256": original.IMAGE_SHA,
              "magiskboot_sha256": original.MAGISKBOOT_SHA, "cpio_delta": delta, "rows": rows,
              "partition_written": False, "services_started": False, "phone_rebooted": False,
              "policy_loaded": False, "phone_ui_actions": 0, "boot_tested": False}

    def run(label, command, raw=None, maximum=45, binary=False):
        argv = adb + (["exec-out"] if binary else ["shell", "-T"]) + [shlex.join(["/product/bin/su", "-c", command])]
        started = time.monotonic()
        try:
            process = subprocess.run(argv, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=maximum)
            output, error, code, timed_out = process.stdout, process.stderr, process.returncode, False
        except subprocess.TimeoutExpired as exception:
            output, error, code, timed_out = exception.stdout or b"", exception.stderr or b"", None, True
        row = {"name": label, "returncode": code, "timed_out": timed_out, "seconds": time.monotonic() - started}
        for key, data in (("stdout", output), ("stderr", error)):
            bundle.write_new(args.out / (label + "." + key + ".raw"), data)
            row[key] = {"bytes": len(data), "sha256": bundle.sha(data)}
        rows.append(row)
        bundle.need(code == 0 and not timed_out, "ordinary-file step failed; retain and reconcile this instance")
        return output

    def baseline(label):
        raw = run(label, "\n".join(["set -eu", "getprop ro.boot.slot_suffix", "getprop init.svc.trillionnium_owner_open_bootstrap",
            "sha256sum /data/trillionnium/owner-open/state/emergency-stop",
            "sha256sum /data/trillionnium/owner-open/state/phone-local-v150/retained-claims.json",
            "sha256sum /data/adb/magisk/magiskboot"]))
        lines = raw.decode().splitlines()
        bundle.need(len(lines) == 5 and lines[:2] == ["_a", "stopped"]
                    and [line.split()[0] for line in lines[2:]] == [original.STOP_SHA, original.CLAIMS_SHA, original.MAGISKBOOT_SHA],
                    "preservation baseline differs")
        return bundle.sha(raw)

    try:
        baseline_sha = baseline("baseline-before")
        run("create-ordinary-work", "set -eu; umask 077; mkdir " + shlex.quote(work) + "; chmod 0700 " + shlex.quote(work))
        for name, raw in (("original.img", source), ("reviewed-added-ramdisk.cpio", modified)):
            run("write-" + name, "set -eu; set -C; umask 077; cat > " + shlex.quote(work + "/" + name), raw, 60)
        run("unpack-original", "cd " + shlex.quote(work) + " && /data/adb/magisk/magiskboot unpack -h original.img")
        observed = run("original-cpio", "cat " + shlex.quote(work + "/ramdisk.cpio"), binary=True)
        bundle.need(observed == cpio, "magiskboot original cpio differs from independent inventory")
        install = "\n".join(["set -eu", "cd " + shlex.quote(work),
            bundle.staging.hash_guard(work + "/reviewed-added-ramdisk.cpio", bundle.sha(modified)),
            "[ ! -e original-ramdisk.cpio ]", "mv ramdisk.cpio original-ramdisk.cpio",
            "[ ! -e ramdisk.cpio ]", "cp reviewed-added-ramdisk.cpio ramdisk.cpio",
            "[ ! -e candidate-init_boot.img ]", "/data/adb/magisk/magiskboot repack original.img candidate-init_boot.img"])
        run("repack-new-rc", "/system/bin/sh -s", install.encode(), 60)
        candidate = run("candidate-image", "cat " + shlex.quote(work + "/candidate-init_boot.img"), binary=True, maximum=60)
        after, candidate_cpio, _ = inventory.inspect(candidate)
        bundle.need(candidate_cpio == modified and len(candidate) == len(source)
                    and after["header"]["kernel_bytes"] == 0, "repacked candidate differs from reviewed cpio/image extent")
        raw = run("verify-original-after", "sha256sum " + shlex.quote(work + "/original.img") + " /dev/block/by-name/init_boot_a")
        bundle.need([line.split()[0] for line in raw.decode().splitlines()] == [original.IMAGE_SHA, original.IMAGE_SHA],
                    "original image or active partition changed")
        bundle.need(baseline("baseline-after") == baseline_sha, "stop/claims/tool changed during review")
        bundle.write_new(args.out / "candidate-init_boot.img", candidate)
        bundle.write_new(args.out / "CANDIDATE-INVENTORY.json", bundle.encode(after))
        result.update(status="ORDINARY_FILE_CANDIDATE_VERIFIED_NOT_FLASHED", candidate_bytes=len(candidate),
                      candidate_sha256=bundle.sha(candidate), original_partition_unchanged=True,
                      original_cpio_members_preserved=True, added_member_count=1)
    except Exception as error:
        result.update(status="FAILED_RETAIN_ORDINARY_FILE_STATE", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        raw = bundle.encode(result); bundle.write_new(args.out / "RESULT.json", raw)
        print(json.dumps({"result": str(args.out / "RESULT.json"), "sha256": bundle.sha(raw), "status": result["status"]}), flush=True)


if __name__ == "__main__":
    main()
