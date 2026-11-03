#!/usr/bin/env python3
"""Prepare the complete frozen GNU source tree plus four measured overlays.

Reads a local Git object database; never fetches or modifies the checkout.
Writes only a new output directory. This prepares source, not GNU/rootfs build
qualification. Requires Python 3.11+ for Cargo workspace TOML inspection.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tomllib

HERE = Path(__file__).resolve().parent
BASELINE = "4b687742fca939bc32122857f21067ec28d30a23"
OVERLAYS = {
    "apps/trillionnium-owner-open-host/src/bin/r5_control_host_v4/process.rs": (
        "270ae2206d092bc590b1f241d9f77eee21fc941445a76511369b5f58b81bd93e",
        "070bb8e6bd56e065f56e7eaa2ebc6ab9e0bd0dde1050942f3b8ab5136823fc26"),
    "tools/owner-open/owner_open_broker_admission_v2.py": (
        "74c801798fce3817cbd0853d88bbbe25d32e7442d229f736aceeefe2aa721927",
        "76131b9d99e8b51affea4680e79c00236992a48d13f20ddf8541a539e6995d15"),
    "tools/tests/test_owner_open_inspect_observation_lane.py": (
        None, "1a11e65e27e5eb805e8337912eb45f3673d9e6fc0a452ae516d992d26b11ac97"),
    "apps/trillionnium-owner-open-host/tests/r5_late_cancel_known_terminal.rs": (
        None, "9b136958e9060d09166c467e59342cf231d19108a2d06b7e26f046af7826e435"),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    checkout = args.checkout.resolve(strict=True)
    out = args.out.resolve()
    if out.exists():
        parser.error("output must not exist")
    def git(*argv):
        return subprocess.check_output(["git", "-C", str(checkout), *argv], text=True).strip()
    if git("rev-parse", "--verify", BASELINE + "^{commit}") != BASELINE:
        parser.error("the exact frozen commit is unavailable")
    tree = git("rev-parse", BASELINE + "^{tree}")
    for rel, (_, expected) in OVERLAYS.items():
        if sha(HERE / "frozen-intake-v142/gnu-core-proposed" / rel) != expected:
            parser.error("overlay hash mismatch: " + rel)
    out.mkdir(parents=True, exist_ok=False)
    archive = out / "frozen-baseline.tar"
    subprocess.run(["git", "-C", str(checkout), "archive", "--format=tar", "--output", str(archive), BASELINE], check=True)
    workspace = out / "workspace"
    workspace.mkdir()
    extracted = 0
    with tarfile.open(archive, "r:") as source:
        members = source.getmembers()
        seen = set()
        for member in members:
            rel = PurePosixPath(member.name)
            if rel.is_absolute() or ".." in rel.parts or ".git" in rel.parts or member.name in seen:
                raise ValueError("unsafe/duplicate archive path: " + member.name)
            if not (member.isdir() or member.isfile()):
                raise ValueError("source archive contains a link or special file: " + member.name)
            seen.add(member.name)
        for member in members:
            destination = workspace / member.name
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as src, destination.open("xb") as dst:
                    shutil.copyfileobj(src, dst)
                destination.chmod(0o755 if member.mode & 0o111 else 0o644)
                extracted += 1
    frozen = json.loads((HERE / "frozen-intake-v142/gnu-core-provenance/frozen-source-manifest.json").read_text())
    if frozen["source_commit"] != BASELINE:
        raise ValueError("frozen source manifest commit mismatch")
    for rel, expected in frozen["files"].items():
        if sha(workspace / rel) != expected:
            raise ValueError("frozen baseline file mismatch: " + rel)
    for rel, (before, after) in OVERLAYS.items():
        target = workspace / rel
        if before is None:
            if target.exists():
                raise ValueError("new overlay unexpectedly exists upstream: " + rel)
        elif sha(target) != before:
            raise ValueError("overlay baseline hash mismatch: " + rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((HERE / "frozen-intake-v142/gnu-core-proposed" / rel).read_bytes())
        if sha(target) != after:
            raise ValueError("written overlay hash mismatch: " + rel)
    cargo = tomllib.loads((workspace / "Cargo.toml").read_text())
    members = cargo["workspace"]["members"]
    missing = [member for member in members if not (workspace / member / "Cargo.toml").is_file()]
    if missing:
        raise ValueError("incomplete Cargo workspace members: " + repr(missing))
    receipt = {"schema": "razr60-complete-frozen-backend-source-v1",
               "utc": dt.datetime.now(dt.timezone.utc).isoformat(), "commit": BASELINE,
               "git_tree": tree, "archive_sha256": sha(archive), "extracted_files": extracted,
               "checked_baseline_manifest_files": len(frozen["files"]), "workspace_members": members,
               "overlays": [{"path": rel, "before": before, "after": after}
                            for rel, (before, after) in OVERLAYS.items()],
               "source_closed": True, "fresh_gnu_build": False, "fresh_rootfs_build": False,
               "network_operations": 0, "phone_operations": 0}
    (out / "SOURCE-PREPARE-RECEIPT.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
