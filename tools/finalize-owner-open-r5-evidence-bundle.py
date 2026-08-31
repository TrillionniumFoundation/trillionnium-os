#!/usr/bin/env python3
"""Finalize a capture-only or independently reviewed Owner-Open R5 bundle."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import sys
from typing import Any

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from owner_open_r5_evidence_bundle import (  # noqa: E402
    ARTIFACT_INDEX_SCHEMA,
    BUNDLE_SCHEMA,
    EvidenceError,
    KIND_POLICIES,
    OBSERVATIONS_SCHEMA,
    PLAN_REVISION,
    REPOSITORY,
    canonical_json_bytes,
    enumerate_bundle_files,
    read_json_object,
    read_regular_bytes,
    require_valid_bundle,
    safe_relative_path,
    sha256_file,
)


def atomic_write(path: Path, raw: bytes, mode: int = 0o644) -> None:
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise EvidenceError(f"write made no progress for {path}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def require_real_directory(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise EvidenceError("bundle-dir must be an absolute real directory")
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError("bundle-dir is not a directory")
    return path


def copy_stable(source: Path, destination: Path) -> None:
    source = source.resolve(strict=True)
    if source == destination.resolve(strict=False):
        return
    raw = read_regular_bytes(source, maximum=4 * 1024 * 1024, label=str(source))
    if destination.exists() or destination.is_symlink():
        raise EvidenceError(f"destination already exists: {destination}")
    atomic_write(destination, raw)


def artifact_entries(
    bundle_root: Path,
    *,
    index_path: str,
    observations_path: str,
    attestation_path: str,
    review_path: str | None,
    release_path: str | None,
) -> list[dict[str, Any]]:
    index_file = bundle_root / index_path
    index = read_json_object(index_file)
    if index.get("schema") != ARTIFACT_INDEX_SCHEMA:
        raise EvidenceError("artifact index schema is unsupported")
    raw_entries = index.get("artifacts")
    if not isinstance(raw_entries, list):
        raise EvidenceError("artifact index artifacts must be a list")

    special: dict[str, str] = {
        index_path: "artifact_index",
        observations_path: "observation_summary",
        attestation_path: "target_attestation",
    }
    if review_path is not None:
        special[review_path] = "review_attestation"
    if release_path is not None:
        special[release_path] = "release_authorization"

    roles: dict[str, str] = dict(special)
    for position, item in enumerate(raw_entries):
        label = f"artifact-index.artifacts[{position}]"
        if not isinstance(item, dict):
            raise EvidenceError(f"{label} must be an object")
        relative = safe_relative_path(item.get("path"), label=f"{label}.path")
        role = item.get("role")
        if not isinstance(role, str) or not role.strip():
            raise EvidenceError(f"{label}.role is required")
        if relative in roles:
            raise EvidenceError(f"artifact index duplicates special or prior path: {relative}")
        roles[relative] = role

    observed = {
        path.relative_to(bundle_root).as_posix()
        for path in enumerate_bundle_files(bundle_root, exclude={"manifest.json"})
    }
    if observed != set(roles):
        raise EvidenceError(
            "artifact index does not close bundle files; undeclared="
            + repr(sorted(observed - set(roles)))
            + " absent="
            + repr(sorted(set(roles) - observed))
        )

    result: list[dict[str, Any]] = []
    for relative in sorted(roles):
        size, digest = sha256_file(bundle_root / relative)
        result.append(
            {
                "path": relative,
                "role": roles[relative],
                "bytes": size,
                "sha256": digest,
            }
        )
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--artifact-index", default="artifact-index.json")
    parser.add_argument("--observations", default="observations.json")
    parser.add_argument("--target-attestation", required=True, type=Path)
    parser.add_argument("--target-attestation-name", default="target-attestation.json")
    parser.add_argument("--review-attestation", type=Path)
    parser.add_argument("--review-attestation-name", default="review-attestation.json")
    parser.add_argument("--release-authorization", type=Path)
    parser.add_argument(
        "--release-authorization-name", default="release-authorization.json"
    )
    parser.add_argument("--replace-existing-capture", action="store_true")
    parser.add_argument("--promotable", action="store_true")
    parser.add_argument("--kind", required=True, choices=sorted(KIND_POLICIES))
    parser.add_argument("--gap-id", action="append", required=True)
    parser.add_argument("--evidence-level", required=True, choices=sorted({p['level'] for p in KIND_POLICIES.values()}))
    parser.add_argument("--branch", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--claim-ceiling", required=True)
    parser.add_argument("--producer-login", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--workflow-run-id", required=True, type=int)
    parser.add_argument("--workflow-run-attempt", required=True, type=int)
    parser.add_argument("--job", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--finished-at", required=True)
    parser.add_argument("--negative-claim", action="append", required=True)
    parser.add_argument("--artifact-expires-at", required=True)
    parser.add_argument("--immutable-location", required=True)
    parser.add_argument("--reproduction", required=True)
    parser.add_argument("--environment-available", action=argparse.BooleanOptionalAction, default=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    manifest_path: Path | None = None
    try:
        bundle_root = require_real_directory(args.bundle_dir.resolve())
        manifest_path = bundle_root / "manifest.json"
        previous: dict[str, tuple[int, str, str]] = {}
        if manifest_path.exists() or manifest_path.is_symlink():
            if not args.replace_existing_capture:
                raise EvidenceError("manifest.json already exists")
            facts = require_valid_bundle(manifest_path, require_promotable=False)
            if facts.get("promotable") is not False:
                raise EvidenceError("only a capture-only manifest may be replaced")
            old = read_json_object(manifest_path)
            previous = {
                str(item["path"]): (int(item["bytes"]), str(item["sha256"]), str(item["role"]))
                for item in old.get("artifacts", [])
                if isinstance(item, dict)
            }
            manifest_path.unlink()

        index_path = safe_relative_path(args.artifact_index, label="artifact-index")
        observations_path = safe_relative_path(args.observations, label="observations")
        attestation_name = safe_relative_path(
            args.target_attestation_name, label="target-attestation-name"
        )
        review_name: str | None = None
        release_name: str | None = None

        copy_stable(args.target_attestation, bundle_root / attestation_name)
        if args.promotable:
            if args.review_attestation is None:
                raise EvidenceError("--promotable requires --review-attestation")
            review_name = safe_relative_path(
                args.review_attestation_name, label="review-attestation-name"
            )
            copy_stable(args.review_attestation, bundle_root / review_name)
        elif args.review_attestation is not None:
            raise EvidenceError("capture-only finalization must not receive review attestation")

        if args.kind == "signed_public_release":
            if args.release_authorization is None:
                raise EvidenceError(
                    "signed_public_release requires --release-authorization"
                )
            release_name = safe_relative_path(
                args.release_authorization_name,
                label="release-authorization-name",
            )
            copy_stable(args.release_authorization, bundle_root / release_name)
        elif args.release_authorization is not None:
            raise EvidenceError(
                "release authorization is accepted only for signed_public_release"
            )

        observations = read_json_object(bundle_root / observations_path)
        if observations.get("schema") != OBSERVATIONS_SCHEMA:
            raise EvidenceError("observations schema is unsupported")
        if observations.get("kind") != args.kind:
            raise EvidenceError("observations kind differs from --kind")

        artifacts = artifact_entries(
            bundle_root,
            index_path=index_path,
            observations_path=observations_path,
            attestation_path=attestation_name,
            review_path=review_name,
            release_path=release_name,
        )
        if previous:
            current = {
                str(item["path"]): (int(item["bytes"]), str(item["sha256"]), str(item["role"]))
                for item in artifacts
            }
            for relative, identity in previous.items():
                if relative == review_name or relative == release_name:
                    continue
                if current.get(relative) != identity:
                    raise EvidenceError(
                        f"capture artifact changed during promotion: {relative}"
                    )

        review: dict[str, Any]
        if args.promotable:
            review_document = read_json_object(bundle_root / str(review_name))
            review = {
                "approved": True,
                "attestation_path": review_name,
                "reviewer": review_document.get("reviewer"),
                "review_id": review_document.get("review_id"),
                "reviewed_at": review_document.get("reviewed_at"),
            }
        else:
            review = {
                "approved": False,
                "attestation_path": None,
                "reviewer": None,
                "review_id": None,
                "reviewed_at": None,
            }

        manifest: dict[str, Any] = {
            "schema": BUNDLE_SCHEMA,
            "plan_revision": PLAN_REVISION,
            "repository": REPOSITORY,
            "branch": args.branch,
            "source_commit": args.source_commit,
            "source_tree": args.source_tree,
            "evidence_level": args.evidence_level,
            "kind": args.kind,
            "gap_ids": args.gap_id,
            "result": "pass",
            "synthetic": False,
            "promotable": args.promotable,
            "automatic_redispatch": False,
            "started_at": args.started_at,
            "finished_at": args.finished_at,
            "claim_ceiling": args.claim_ceiling,
            "negative_claims": args.negative_claim,
            "producer": {
                "login": args.producer_login,
                "workflow": args.workflow,
                "workflow_run_id": args.workflow_run_id,
                "workflow_run_attempt": args.workflow_run_attempt,
                "job": args.job,
            },
            "retention": {
                "artifact_expires_at": args.artifact_expires_at,
                "immutable_location": args.immutable_location,
                "reproduction": args.reproduction,
                "environment_available": args.environment_available,
            },
            "target_attestation_path": attestation_name,
            "review": review,
            "release_authorization_path": release_name,
            "observations": observations,
            "artifacts": artifacts,
        }
        raw = json.dumps(
            manifest, ensure_ascii=False, indent=2, sort_keys=True
        ).encode("utf-8") + b"\n"
        atomic_write(manifest_path, raw)
        facts = require_valid_bundle(
            manifest_path, require_promotable=args.promotable
        )
    except (EvidenceError, OSError, ValueError) as error:
        if manifest_path is not None and manifest_path.exists():
            manifest_path.unlink(missing_ok=True)
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(json.dumps(facts, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
