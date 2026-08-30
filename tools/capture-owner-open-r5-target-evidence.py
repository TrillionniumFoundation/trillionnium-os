#!/usr/bin/env python3
"""Run one fixed target-owned R5 harness and emit a capture-only bundle."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from typing import Any

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from owner_open_r5_capture_trust import (  # noqa: E402
    assert_harness_identity,
    environment_statement,
    harness_environment,
    require_fixed_target_file,
    validate_capture_chain,
)
from owner_open_r5_evidence_bundle import (  # noqa: E402
    ARTIFACT_INDEX_SCHEMA,
    EvidenceError,
    KIND_POLICIES,
    OBSERVATIONS_SCHEMA,
    REPOSITORY,
    read_json_object,
    sha256_file,
    validate_target_attestation,
)

ROOT = Path("/opt/owner-open-r5")
ATTESTATION_ROOT = Path("/etc/owner-open-r5/attestations")
HARNESS_ROOT = ROOT / "harnesses"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode(
        "utf-8"
    ) + b"\n"
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise EvidenceError("JSON write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run_harness(
    harness: Path,
    *,
    raw_dir: Path,
    index: Path,
    observations: Path,
    kind: str,
    source_commit: str,
    source_tree: str,
    timeout: float,
) -> dict[str, Any]:
    environment = harness_environment(
        kind=kind,
        source_commit=source_commit,
        source_tree=source_tree,
        raw_dir=raw_dir,
        artifact_index=index,
        observations=observations,
    )
    argv = [
        str(harness),
        "--raw-dir",
        str(raw_dir),
        "--artifact-index",
        str(index),
        "--observations",
        str(observations),
        "--source-commit",
        source_commit,
        "--source-tree",
        source_tree,
    ]
    started = utc_now()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
        close_fds=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate(timeout=5)
        raise EvidenceError(f"target harness timed out after {timeout}s") from error
    finished = utc_now()
    if len(stdout) + len(stderr) > 64 * 1024 * 1024:
        raise EvidenceError("target harness stdout/stderr exceeded 64 MiB")
    (raw_dir / "harness-stdout.bin").write_bytes(stdout)
    (raw_dir / "harness-stderr.bin").write_bytes(stderr)
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace")[-4096:]
        raise EvidenceError(f"target harness failed with {process.returncode}: {detail}")
    return {
        "argv": argv,
        "returncode": process.returncode,
        "started_at": utc_text(started),
        "finished_at": utc_text(finished),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
        "environment": environment_statement(environment),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", required=True, choices=sorted(KIND_POLICIES))
    parser.add_argument("--gap-id", action="append", required=True)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--claim-ceiling", required=True)
    parser.add_argument("--producer-login", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--workflow-run-id", required=True, type=int)
    parser.add_argument("--workflow-run-attempt", required=True, type=int)
    parser.add_argument("--job", required=True)
    parser.add_argument("--timeout", type=float, default=3600.0)
    parser.add_argument("--retention-days", type=int, default=30)
    parser.add_argument("--negative-claim", action="append", required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        policy = KIND_POLICIES[args.kind]
        if not set(args.gap_id) <= set(policy["allowed_gaps"]):
            raise EvidenceError("requested gap IDs exceed the selected kind policy")
        if args.timeout < 1 or args.timeout > 12 * 3600:
            raise EvidenceError("capture timeout is outside 1..43200 seconds")
        if args.retention_days < 1 or args.retention_days > 90:
            raise EvidenceError("retention-days is outside 1..90")
        bundle_dir = args.bundle_dir.resolve(strict=False)
        if bundle_dir.exists() or bundle_dir.is_symlink():
            raise EvidenceError("bundle-dir must be a new path")
        if not bundle_dir.parent.is_dir() or bundle_dir.parent.is_symlink():
            raise EvidenceError("bundle-dir parent must be an existing real directory")
        bundle_dir.mkdir(mode=0o700)
        raw_dir = bundle_dir / "raw"
        raw_dir.mkdir(mode=0o700)
        index = bundle_dir / "artifact-index.json"
        observations_path = bundle_dir / "observations.json"

        harness = HARNESS_ROOT / args.kind
        attestation = ATTESTATION_ROOT / f"{args.kind}.json"
        harness_identity = require_fixed_target_file(
            harness, executable=True, require_root_owner=True
        )
        attestation_identity = require_fixed_target_file(
            attestation, executable=False, require_root_owner=True
        )
        provisional = {
            "source_commit": args.source_commit,
            "source_tree": args.source_tree,
            "evidence_level": policy["level"],
        }
        started = utc_now()
        attestation_value = validate_target_attestation(
            attestation, manifest=provisional, at_time=started
        )
        assert_harness_identity(
            harness_identity, attestation_value.get("harness"), kind=args.kind
        )
        run = run_harness(
            harness,
            raw_dir=raw_dir,
            index=index,
            observations=observations_path,
            kind=args.kind,
            source_commit=args.source_commit,
            source_tree=args.source_tree,
            timeout=args.timeout,
        )

        artifact_index = read_json_object(index)
        if artifact_index.get("schema") != ARTIFACT_INDEX_SCHEMA:
            raise EvidenceError("harness artifact index schema is unsupported")
        entries = artifact_index.get("artifacts")
        if not isinstance(entries, list):
            raise EvidenceError("harness artifact index artifacts must be a list")
        entries.extend(
            [
                {"path": "raw/harness-stdout.bin", "role": "harness_stdout"},
                {"path": "raw/harness-stderr.bin", "role": "harness_stderr"},
                {"path": "raw/capture-driver.json", "role": "capture_driver"},
            ]
        )
        driver = {
            "schema": "org.trillionnium.owner-open-r5.capture-driver.v1",
            "repository": REPOSITORY,
            "kind": args.kind,
            "source_commit": args.source_commit,
            "source_tree": args.source_tree,
            "synthetic": False,
            "harness": harness_identity,
            "target_attestation": attestation_identity,
            "run": run,
            "automatic_redispatch": False,
        }
        atomic_json(raw_dir / "capture-driver.json", driver)
        atomic_json(index, artifact_index)

        observations = read_json_object(observations_path)
        if observations.get("schema") != OBSERVATIONS_SCHEMA:
            raise EvidenceError("harness observations schema is unsupported")
        if observations.get("kind") != args.kind:
            raise EvidenceError("harness observations kind differs from selected kind")
        observations["capture_driver_sha256"] = sha256_file(
            raw_dir / "capture-driver.json"
        )[1]
        atomic_json(observations_path, observations)

        finished = utc_now()
        expires = finished + timedelta(days=args.retention_days)
        finalizer = TOOLS / "finalize-owner-open-r5-evidence-bundle.py"
        finalizer_argv = [
            sys.executable,
            str(finalizer),
            "--bundle-dir",
            str(bundle_dir),
            "--target-attestation",
            str(attestation),
            "--kind",
            args.kind,
            "--evidence-level",
            str(policy["level"]),
            "--branch",
            args.branch,
            "--source-commit",
            args.source_commit,
            "--source-tree",
            args.source_tree,
            "--claim-ceiling",
            args.claim_ceiling,
            "--producer-login",
            args.producer_login,
            "--workflow",
            args.workflow,
            "--workflow-run-id",
            str(args.workflow_run_id),
            "--workflow-run-attempt",
            str(args.workflow_run_attempt),
            "--job",
            args.job,
            "--started-at",
            utc_text(started),
            "--finished-at",
            utc_text(finished),
            "--artifact-expires-at",
            utc_text(expires),
            "--immutable-location",
            f"github-actions-run:{args.workflow_run_id}:artifact-pending",
            "--reproduction",
            f"dispatch {args.workflow} at {args.source_commit} on the fixed {args.kind} target lane",
        ]
        for gap_id in args.gap_id:
            finalizer_argv.extend(["--gap-id", gap_id])
        for claim in args.negative_claim:
            finalizer_argv.extend(["--negative-claim", claim])
        completed = subprocess.run(
            finalizer_argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        if completed.returncode != 0:
            raise EvidenceError(
                "capture finalization failed: " + completed.stderr[-4096:]
            )
        validate_capture_chain(bundle_dir / "manifest.json")
    except (EvidenceError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(completed.stdout, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
