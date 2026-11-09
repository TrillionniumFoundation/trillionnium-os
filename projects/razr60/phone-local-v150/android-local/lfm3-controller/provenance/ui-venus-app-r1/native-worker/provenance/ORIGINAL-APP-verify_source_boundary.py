#!/usr/bin/env python3
"""Read-only source/provenance comparison. No compilation or remote commands."""
import hashlib
import json
import re
from pathlib import Path


def contains_serial_literal(text):
    """Reject bounded mixed uppercase/digit identifier literals, not a device list."""
    return re.search(r"\b(?=[A-Z0-9]{8,20}\b)(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*[0-9])[A-Z0-9]+\b", text) is not None


def digest(path):
    data = path.read_bytes()
    return len(data), hashlib.sha256(data).hexdigest()


def main():
    here = Path(__file__).resolve().parent
    record = json.loads((here / "provenance/SHELL-NATIVE-SOURCES.json").read_text())
    rows = []
    for item in record["files"]:
        path = here / item["file"]
        size, sha = digest(path)
        same = (size, sha) == (item["bytes"], item["sha256"])
        allowed_change = item["file"] == "native/probe-worker.c"
        if same == allowed_change:
            raise ValueError("unexpected source boundary: " + item["file"])
        rows.append({"file": item["file"], "bytes": size, "sha256": sha,
                     "unchanged_from_shell": same})
    files = {p.relative_to(here).as_posix() for p in (here / "native").rglob("*") if p.is_file()}
    expected = {i["file"] for i in record["files"]} | {"native/app-entry-guard.h"}
    if files != expected:
        raise ValueError("unexpected native source set")
    changed = (here / "native/probe-worker.c").read_text()
    boundary = (here / "native/app-entry-guard.h").read_text()
    original_path = here / "provenance/SHELL-probe-worker.c"
    original = original_path.read_text()
    original_pin = next(i for i in record["files"] if i["file"] == "native/probe-worker.c")
    if digest(original_path) != (original_pin["bytes"], original_pin["sha256"]):
        raise ValueError("original bootstrap comparison source differs")
    marker = "#define main venus_worker_main"
    if original.count(marker) != 1 or changed.count(marker) != 1 or original.split(marker)[0] != changed.split(marker)[0]:
        raise ValueError("same-directory bootstrap was changed")
    if "getuid()!=2000" in changed or "geteuid()!=2000" in changed:
        raise ValueError("shell inference gate remains")
    for text in (changed, boundary):
        if "10481" in text or contains_serial_literal(text):
            raise ValueError("phone-specific identity in portable App entry")
    if 'hepta_arm_parent_death_guard(expected)' not in changed:
        raise ValueError("parent-death guard missing")
    size, sha = digest(here / "native/app-entry-guard.h")
    rows.append({"file": "native/app-entry-guard.h", "bytes": size, "sha256": sha,
                 "new_app_boundary_file": True})
    print(json.dumps({"schema": "hepta.ui-venus.app-source-boundary.v1", "passed": True,
                      "original_files": len(record["files"]), "original_files_unchanged": 17,
                      "original_files_changed": ["native/probe-worker.c"],
                      "new_native_files": ["native/app-entry-guard.h"], "files": rows,
                      "same_directory_bootstrap_byte_unchanged": True,
                      "compiled": False, "phone_contact": False, "inference_run": False},
                     indent=2))


if __name__ == "__main__":
    main()
