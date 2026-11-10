"""Verify the separate, already-built MNN runtime without altering any binary.

These are not GenieX release members. The exact prior Android build receipt,
source pins and three unchanged ELF payloads form their own provenance.
ELF dependency and installed-APK member checks are completed by the assembler.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat


def verify_worker_linker_policy(dynamic):
    """Verify real readelf output for the fixed worker's non-global search path.

    Both private shared objects are direct dependencies of this PIE. A single
    non-transitive $ORIGIN RUNPATH can find them without putting the complete
    application or vendor directory ahead of the platform dependency search.
    This static check does not establish actual Android dlopen resolution.
    """
    paths = re.findall(r"\((RUNPATH|RPATH)\).*?\[([^]]*)\]", dynamic)
    tags = re.findall(r"\((RUNPATH|RPATH)\)", dynamic)
    if tags != ["RUNPATH"] or paths != [("RUNPATH", "$ORIGIN")]:
        raise RuntimeError("MNN worker requires exactly one non-transitive $ORIGIN RUNPATH and no RPATH")
    needed = re.findall(r"\(NEEDED\).*?\[([^]]+)\]", dynamic)
    private = ["libMNN.so", "libc++_shared.so"]
    if any(needed.count(name) != 1 for name in private):
        raise RuntimeError("MNN worker must directly need each pinned private library exactly once")
    return {"policy": "origin-runpath-platform-defaults.v1", "worker_runpath": "$ORIGIN",
            "worker_rpath": None, "private_direct_dependencies": private,
            "global_ld_library_path_required": False, "runtime_resolution_proven": False}


def _read_regular(path, maximum):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise RuntimeError("MNN runtime member must be a bounded regular file: " + str(path))
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        current = os.lstat(path)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mode,
                              value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
    if len(data) != before.st_size or identity(before) != identity(after) or identity(before) != identity(current):
        raise RuntimeError("MNN runtime member changed during verification: " + str(path))
    return data


def _verify_payload(path, pin):
    data = _read_regular(path, pin["bytes"])
    if len(data) != pin["bytes"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
        raise RuntimeError("MNN runtime payload differs from its independent pin: " + str(path))
    return data


def load_pins(source_root):
    root = Path(source_root)
    pins = json.loads((root / "native/mobimind-runtime-pins.json").read_text())
    if pins.get("schema") != "hepta.mobimind.packaging-pins.v1" or pins.get("geniex_release_members") is not False:
        raise RuntimeError("MNN packaging provenance schema differs")
    members = pins["libraries"]
    expected = {"libhepta_mobimind_runner.so", "libMNN.so", "libc++_shared.so"}
    if len(members) != 3 or {item["apk_name"] for item in members} != expected:
        raise RuntimeError("MNN packaging membership differs")
    for item in members:
        if any(Path(item[key]).name != item[key] for key in ("source_name", "apk_name")):
            raise RuntimeError("MNN runtime member must be a single filename")
        if type(item["bytes"]) is not int or item["bytes"] <= 0 or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise RuntimeError("Invalid MNN member identity")
    java = (root / "src/org/trillionnium/hepta/local/MobiMindPins.java").read_text()
    by_name = {item["apk_name"]: item for item in members}
    if re.findall(r'\bWORKER\s*=\s*"([^"]+)"', java) != ["libhepta_mobimind_runner.so"]:
        raise RuntimeError("Java MNN runner filename differs from the APK member")
    for key, name in (("WORKER", "libhepta_mobimind_runner.so"), ("MNN", "libMNN.so"), ("CXX", "libc++_shared.so")):
        if re.findall(r'\b' + key + r'_SHA\s*=\s*"([0-9a-f]{64})"', java) != [by_name[name]["sha256"]]:
            raise RuntimeError("Java and packaging MNN hashes differ: " + key)
        if re.findall(r'\b' + key + r'_BYTES\s*=\s*(\d+)L', java) != [str(by_name[name]["bytes"])]:
            raise RuntimeError("Java and packaging MNN sizes differ: " + key)
    return pins


def verify_mobimind_runtime(source_root, runtime_dir):
    root, runtime = Path(source_root), Path(runtime_dir)
    pins = load_pins(root)
    receipt_bytes = _read_regular(runtime / "BUILD-RECEIPT.json", 65536)
    if hashlib.sha256(receipt_bytes).hexdigest() != pins["build_receipt_sha256"]:
        raise RuntimeError("MNN prior Android build receipt pin differs")
    preserved = _read_regular(root / "provenance/mobimind-worker-r4-build.json", 65536)
    if preserved != receipt_bytes:
        raise RuntimeError("MNN build receipt differs from frozen source provenance")
    worker_manifest = _read_regular(root / "provenance/mobimind-worker-r4/SOURCE-MANIFEST.json", 65536)
    if hashlib.sha256(worker_manifest).hexdigest() != pins["worker_source_manifest_sha256"]:
        raise RuntimeError("MNN worker source manifest differs")
    receipt = json.loads(receipt_bytes)
    fields = {"schema": "hepta.mobimind.android-worker-build.v2", "source_commit": pins["mnn_source_commit"],
              "worker_revision": pins["worker_revision"], "probe_archive_sha256": pins["worker_source_archive_sha256"],
              "probe_source_manifest_sha256": pins["worker_source_manifest_sha256"], "worker_rebuilt": True,
              "http_resource_support": False}
    if any(type(receipt.get(key)) is not type(value) or receipt[key] != value for key, value in fields.items()):
        raise RuntimeError("MNN original Android build identity differs")
    actual = {row["name"]: row for row in receipt["libraries"]}
    if len(receipt["libraries"]) != 3 or set(actual) != {row["source_name"] for row in pins["libraries"]}:
        raise RuntimeError("MNN original build membership differs")
    result = {}
    for pin in pins["libraries"]:
        record = actual[pin["source_name"]]
        if any(record[key] != pin[key] for key in ("bytes", "sha256", "needed")):
            raise RuntimeError("MNN member provenance differs: " + pin["source_name"])
        path = runtime / pin["source_name"]
        _verify_payload(path, pin)
        result[pin["apk_name"]] = {**pin, "path": path,
                                  "provenance": "pinned_mobimind_r4_android_build",
                                  "build_receipt_sha256": pins["build_receipt_sha256"]}
    return result
