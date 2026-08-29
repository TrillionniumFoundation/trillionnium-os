#!/usr/bin/env python3
"""Apply one reviewed external evidence bundle to the canonical R5 gap truth."""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import sys
from typing import Any

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from owner_open_r5_evidence_bundle import (  # noqa: E402
    EvidenceError,
    LEVELS,
    require_valid_bundle,
    safe_relative_path,
)

GAPS_PATH = Path("docs/status/owner-open-r5-gap-closure.json")
STATUS_PATH = Path("docs/status/owner-open-r5-status.json")

NEGATIVE_CLAIMS = {
    "R5-GAP-GOVERNANCE-001": "protected-main governance and independent exact-head integration approval",
    "R5-GAP-PROCESS-LIFECYCLE-001": "installed target process lifecycle and descendant cleanup",
    "R5-GAP-STREAM-RECOVERY-001": "installed target stream pause, cursor resume and no-redispatch recovery",
    "R5-GAP-JOURNAL-CONVERGENCE-001": "destructive journal ENOSPC, corruption and power-loss convergence",
    "R5-GAP-BROKER-CORRELATION-001": "installed multi-client Broker correlation and audit durability",
    "R5-GAP-PRODUCT-ENTRYPOINT-001": "clean target-files product entrypoint inclusion",
    "R5-GAP-INSTALLED-CODEX-001": "installed authenticated Codex same-turn qualification",
    "R5-GAP-ROOTLINUX-PLACEMENT-001": "target Root Linux UID, namespace, cgroup and service placement",
    "R5-GAP-ANDROID-GRAPH-001": "clean Android image and target-files qualification",
    "R5-GAP-PHYSICAL-ADB-001": "authorized physical ordinary ADB effect qualification",
    "R5-GAP-FAULT-MATRIX-001": "full destructive crash, storage, USB, reboot and power-loss qualification",
    "R5-GAP-RELEASE-001": "cryptographically verified and independently human-authorized public release",
}

STATUS_BY_LEVEL = {
    "L0": "SOURCE_IMPLEMENTED",
    "L1": "HOST_TESTED",
    "L2": "HOST_TESTED",
    "L3": "IMAGE_INCLUDED",
    "L4": "DEVICE_OBSERVED",
    "L5": "FAULT_TESTED",
    "L6": "RELEASE_QUALIFIED",
}


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must contain one object")
    return value


def atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o644,
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
    os.replace(temporary, path)


def gap_verifier_module() -> Any:
    path = TOOLS / "verify-owner-open-r5-gap-evidence.py"
    spec = importlib.util.spec_from_file_location("owner_open_r5_gap_verifier", path)
    if spec is None or spec.loader is None:
        raise EvidenceError("cannot load R5 gap verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def is_external(gap: dict[str, Any]) -> bool:
    value = gap.get("requires_external_evidence")
    if isinstance(value, bool):
        return value
    level = gap.get("exit_evidence_level")
    return level in LEVELS and LEVELS[str(level)] >= LEVELS["L2"]


def evidence_entry(
    *, bundle_relative: str, facts: dict[str, Any]
) -> dict[str, Any]:
    return {
        "level": facts["evidence_level"],
        "source_commit": facts["source_commit"],
        "source_tree": facts["source_tree"],
        "evidence_sha256": facts["manifest_sha256"],
        "kind": facts["kind"],
        "reviewer": facts["reviewer"],
        "synthetic": False,
        "bundle_path": bundle_relative,
    }


def highest_closed_level(
    package_gap_ids: list[str], gaps_by_id: dict[str, dict[str, Any]]
) -> str:
    ranks = [
        LEVELS[str(gaps_by_id[identifier]["exit_evidence_level"])]
        for identifier in package_gap_ids
        if identifier in gaps_by_id
        and gaps_by_id[identifier].get("status") == "CLOSED"
        and gaps_by_id[identifier].get("exit_evidence_level") in LEVELS
    ]
    rank = max(ranks, default=LEVELS["L1"])
    return f"L{rank}"


def update_status(
    status: dict[str, Any], gaps: dict[str, Any], promoted: set[str]
) -> None:
    entries = [item for item in gaps["gaps"] if isinstance(item, dict)]
    gaps_by_id = {str(item["id"]): item for item in entries}
    all_closed = bool(entries) and all(item.get("status") == "CLOSED" for item in entries)
    release_closed = gaps_by_id.get("R5-GAP-RELEASE-001", {}).get("status") == "CLOSED"
    status["zero_gap"] = all_closed
    status["public_release"] = release_closed
    status["automatic_redispatch"] = False
    status["updated_at"] = datetime.now(timezone.utc).date().isoformat()

    for field in (
        "open_repository_gaps",
        "external_evidence_holds",
        "source_closed_pending_evidence",
    ):
        value = status.get(field)
        if isinstance(value, list):
            status[field] = [
                item
                for item in value
                if not isinstance(item, dict)
                or str(item.get("id")) not in promoted
            ]

    for package in status.get("work_packages", []):
        if not isinstance(package, dict):
            continue
        original = package.get("open_gap_ids")
        if not isinstance(original, list):
            continue
        package_ids = [str(item) for item in original]
        package["open_gap_ids"] = [
            identifier
            for identifier in package_ids
            if gaps_by_id.get(identifier, {}).get("status") != "CLOSED"
        ]
        package["complete"] = not package["open_gap_ids"]
        level = highest_closed_level(package_ids, gaps_by_id)
        package["latest_evidence_level"] = level
        package["status"] = STATUS_BY_LEVEL[level]

    remaining = [item for item in entries if item.get("status") != "CLOSED"]
    status["critical_path_next"] = [
        f"{item['id']}: {item.get('summary', 'collect declared exit evidence')}"
        for item in remaining
    ]
    status["not_claimed"] = [
        NEGATIVE_CLAIMS.get(str(item["id"]), str(item.get("summary", item["id"])))
        for item in remaining
    ]
    counts: dict[str, int] = {}
    for item in entries:
        state = str(item.get("status"))
        counts[state] = counts.get(state, 0) + 1
    status["product_claim"] = (
        "Owner-Open R5 evidence state: "
        + ", ".join(f"{key}={counts[key]}" for key in sorted(counts))
        + f"; zero_gap={str(all_closed).lower()}; public_release={str(release_closed).lower()}."
    )
    if all_closed:
        status["claim_ceiling"] = "ZERO_GAP_RELEASE_QUALIFIED_AND_HUMAN_AUTHORIZED"
    current = status.get("current_candidate")
    if isinstance(current, dict):
        current["exact_head_validation_pending"] = True
        current["promotion_commit_requires_new_exact_head_ci"] = True


def apply_promotion(
    root: Path, manifest_path: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    root = root.resolve()
    manifest_path = manifest_path.resolve(strict=True)
    try:
        bundle_relative = manifest_path.relative_to(root).as_posix()
    except ValueError as error:
        raise EvidenceError("bundle manifest must be inside the repository root") from error
    bundle_relative = safe_relative_path(bundle_relative, label="bundle manifest path")
    if not bundle_relative.startswith("evidence/owner-open-r5/"):
        raise EvidenceError("bundle manifest must be below evidence/owner-open-r5/")
    facts = require_valid_bundle(manifest_path, require_promotable=True)

    gaps = deepcopy(load_object(root / GAPS_PATH))
    status = deepcopy(load_object(root / STATUS_PATH))
    entries = gaps.get("gaps")
    if not isinstance(entries, list):
        raise EvidenceError("gap register gaps must be a list")
    by_id = {
        str(item.get("id")): item for item in entries if isinstance(item, dict)
    }
    promoted: set[str] = set()
    entry = evidence_entry(bundle_relative=bundle_relative, facts=facts)
    for gap_id in facts["gap_ids"]:
        gap = by_id.get(str(gap_id))
        if not isinstance(gap, dict):
            raise EvidenceError(f"bundle references unknown gap: {gap_id}")
        if not is_external(gap):
            raise EvidenceError(f"bundle cannot promote source-only gap: {gap_id}")
        if gap.get("status") == "OPEN":
            raise EvidenceError(f"source work is still OPEN for {gap_id}")
        source = gap.get("source_evidence")
        if not isinstance(source, dict):
            raise EvidenceError(f"{gap_id} has no exact source evidence")
        if (
            source.get("commit") != facts["source_commit"]
            or source.get("tree") != facts["source_tree"]
        ):
            raise EvidenceError(f"{gap_id} source evidence differs from bundle")
        exit_level = str(gap.get("exit_evidence_level"))
        if exit_level not in LEVELS or LEVELS[facts["evidence_level"]] < LEVELS[exit_level]:
            raise EvidenceError(f"bundle evidence level is below {gap_id} exit")
        existing = gap.get("evidence")
        if existing is None:
            evidence = []
        elif isinstance(existing, list):
            evidence = list(existing)
        else:
            raise EvidenceError(f"{gap_id}.evidence is not a list")
        if entry not in evidence:
            evidence.append(dict(entry))
        gap["evidence"] = evidence
        gap["status"] = "CLOSED"
        for field in ("remaining_evidence", "required_material", "required_authority"):
            gap.pop(field, None)
        promoted.add(str(gap_id))

    release_promoted = "R5-GAP-RELEASE-001" in promoted
    if release_promoted:
        not_closed = {
            identifier
            for identifier, gap in by_id.items()
            if identifier != "R5-GAP-RELEASE-001" and gap.get("status") != "CLOSED"
        }
        if not_closed:
            raise EvidenceError(
                "release evidence cannot promote before all prior gaps close: "
                + ", ".join(sorted(not_closed))
            )

    all_closed = all(
        isinstance(item, dict) and item.get("status") == "CLOSED" for item in entries
    )
    gaps.setdefault("generated_policy", {})["automatic_redispatch"] = False
    gaps["generated_policy"]["public_release"] = release_promoted or (
        by_id.get("R5-GAP-RELEASE-001", {}).get("status") == "CLOSED"
    )
    update_status(status, gaps, promoted)
    if status["zero_gap"] is not all_closed:
        raise EvidenceError("derived zero-gap state is inconsistent")

    verifier = gap_verifier_module()
    report = verifier.verify_values(root, gaps, status)
    if not report.ok:
        raise EvidenceError("promotion would fail canonical verification: " + "; ".join(report.errors))
    return gaps, status, {
        "promoted_gap_ids": sorted(promoted),
        "bundle_path": bundle_relative,
        "bundle_sha256": facts["manifest_sha256"],
        "zero_gap": status["zero_gap"],
        "public_release": status["public_release"],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--bundle-manifest", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    manifest = (
        args.bundle_manifest
        if args.bundle_manifest.is_absolute()
        else root / args.bundle_manifest
    )
    try:
        gaps, status, summary = apply_promotion(root, manifest)
        if args.apply:
            atomic_json(root / GAPS_PATH, gaps)
            atomic_json(root / STATUS_PATH, status)
    except (EvidenceError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    summary["applied"] = bool(args.apply)
    if args.json or True:
        print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
