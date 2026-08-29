#!/usr/bin/env python3
"""One-time, self-removing migration for the permanent Owner-Open R5 evidence program.

The migration does not close a gap.  It installs fail-closed bundle validation,
source binding, capture-only target workflows and review tooling, then removes
all temporary write-capable executors including itself.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import stat
import textwrap

ROOT = Path(__file__).resolve().parents[2]


def emit(path: str, raw: str, *, executable: bool = False) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(raw).lstrip("\n"), encoding="utf-8")
    target.chmod(0o755 if executable else 0o644)


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement anchor, observed {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_between(path: str, start: str, end: str, replacement: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    left = text.find(start)
    if left < 0:
        raise SystemExit(f"{path}: start marker absent: {start!r}")
    right = text.find(end, left + len(start))
    if right < 0:
        raise SystemExit(f"{path}: end marker absent: {end!r}")
    target.write_text(text[:left] + replacement + text[right:], encoding="utf-8")


def apply_existing_external_semantics() -> None:
    verifier = ROOT / "tools/verify-owner-open-r5-gap-evidence.py"
    if "def requires_external_evidence(" in verifier.read_text(encoding="utf-8"):
        return
    workflow = ROOT / ".github/workflows/owner-open-r5-external-closure-semantics-executor.yml"
    if not workflow.is_file():
        raise SystemExit("external-closure semantics source is absent")
    source = workflow.read_text(encoding="utf-8")
    marker = "          python3 - <<'PY'\n"
    start = source.find(marker)
    end = source.find("\n          PY\n", start + len(marker))
    if start < 0 or end < 0:
        raise SystemExit("cannot extract reviewed external-closure semantics migration")
    raw = source[start + len(marker):end]
    script = "\n".join(
        line[10:] if line.startswith("          ") else line
        for line in raw.splitlines()
    )
    exec(compile(script, str(workflow) + "#migration", "exec"), {})


EVIDENCE_BUNDLE = r'''
#!/usr/bin/env python3
"""Validate one recursively bound Owner-Open R5 external evidence bundle."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

SCHEMA = "org.trillionnium.owner-open-r5.evidence-bundle.v1"
ATTESTATION_SCHEMA = "org.trillionnium.owner-open-r5.target-attestation.v1"
RELEASE_SCHEMA = "org.trillionnium.owner-open-r5.release-authorization.v1"
PLAN_REVISION = "2026-08-29-r6"
REPOSITORY = "TrillionniumFoundation/trillionnium-os"
LEVELS = {f"L{i}": i for i in range(7)}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
DERIVED_FILES = {"validation-report.json", "SHA256SUMS"}
MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"OPENAI_API_KEY\s*="),
    re.compile(rb"GITHUB_TOKEN\s*="),
)


class BundleError(ValueError):
    pass


class DuplicateMember(ValueError):
    pass


def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMember(f"duplicate key: {key}")
        result[key] = value
    return result


def read_object(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateMember) as error:
        raise BundleError(f"invalid strict JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise BundleError(f"{path} must contain one JSON object")
    return value, raw


def parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise BundleError(f"{label} must be a non-empty RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise BundleError(f"{label} is not RFC3339: {error}") from error
    if parsed.tzinfo is None:
        raise BundleError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def require_login(value: Any, label: str) -> str:
    if not isinstance(value, str) or LOGIN.fullmatch(value) is None:
        raise BundleError(f"{label} is not a GitHub-login-shaped identity")
    lowered = value.lower()
    if lowered == "github-actions" or lowered.endswith("[bot]") or lowered.endswith("-bot"):
        raise BundleError(f"{label} must be a human identity")
    return value


def require_strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and bool(item.strip()) for item in value
    ):
        raise BundleError(f"{label} must be a non-empty string list")
    return list(value)


def stable_file(path: Path, root: Path) -> os.stat_result:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise BundleError(f"file escapes evidence root: {path}") from error
    cursor = resolved
    while cursor != root.resolve():
        if cursor.is_symlink():
            raise BundleError(f"symlink component is forbidden: {cursor}")
        cursor = cursor.parent
    metadata = resolved.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise BundleError(f"evidence member is not a single-link regular file: {path}")
    if metadata.st_size < 0 or metadata.st_size > MAX_FILE_BYTES:
        raise BundleError(f"evidence member exceeds the byte bound: {path}")
    return metadata


def digest_file(path: Path) -> tuple[int, str, bool]:
    digest = hashlib.sha256()
    total = 0
    secret = False
    overlap = b""
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            scan = overlap + chunk
            if any(pattern.search(scan) for pattern in SECRET_PATTERNS):
                secret = True
            overlap = scan[-256:]
    return total, digest.hexdigest(), secret


def safe_relative(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise BundleError(f"{label} is not a portable relative path")
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BundleError(f"{label} is not a safe relative path")
    return path


def validate_bundle(
    root: Path,
    manifest_path: Path,
    *,
    gap_register_path: Path | None = None,
    require_current_attestation: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    manifest_path = manifest_path if manifest_path.is_absolute() else root / manifest_path
    stable_file(manifest_path, root)
    manifest, manifest_raw = read_object(manifest_path)
    bundle_root = manifest_path.parent.resolve(strict=True)

    if manifest.get("schema") != SCHEMA:
        raise BundleError("unsupported evidence-bundle schema")
    if manifest.get("plan_revision") != PLAN_REVISION:
        raise BundleError("evidence bundle is not bound to active R5 r6")
    if manifest.get("repository") != REPOSITORY:
        raise BundleError("repository identity drifted")
    if manifest.get("result") != "pass":
        raise BundleError("only a passing bundle can be promoted")
    if manifest.get("automatic_redispatch") is not False:
        raise BundleError("automatic_redispatch must be false")
    if manifest.get("synthetic") is not False:
        raise BundleError("synthetic must be false")
    level = manifest.get("level")
    if level not in LEVELS or level == "L0":
        raise BundleError("bundle level must be L1-L6")
    kind = manifest.get("kind")
    if not isinstance(kind, str) or not kind.strip():
        raise BundleError("bundle kind is missing")
    gap_ids = require_strings(manifest.get("gap_ids"), "gap_ids")
    if len(gap_ids) != len(set(gap_ids)):
        raise BundleError("gap_ids contains duplicates")
    source_commit = manifest.get("source_commit")
    source_tree = manifest.get("source_tree")
    if not isinstance(source_commit, str) or HEX40.fullmatch(source_commit) is None:
        raise BundleError("source_commit must be lowercase 40-hex")
    if not isinstance(source_tree, str) or HEX40.fullmatch(source_tree) is None:
        raise BundleError("source_tree must be lowercase 40-hex")

    workflow = manifest.get("workflow")
    if not isinstance(workflow, dict):
        raise BundleError("workflow identity must be an object")
    for field in ("run_id", "run_attempt", "job_id"):
        value = workflow.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise BundleError(f"workflow.{field} must be positive")
    if not isinstance(workflow.get("name"), str) or not workflow["name"].strip():
        raise BundleError("workflow.name is missing")
    started = parse_time(workflow.get("started_at"), "workflow.started_at")
    completed = parse_time(workflow.get("completed_at"), "workflow.completed_at")
    if completed < started:
        raise BundleError("workflow completed before it started")

    producer = manifest.get("producer")
    if not isinstance(producer, dict):
        raise BundleError("producer must be an object")
    producer_login = require_login(producer.get("login"), "producer.login")

    attestation = manifest.get("target_attestation")
    if not isinstance(attestation, dict) or attestation.get("schema") != ATTESTATION_SCHEMA:
        raise BundleError("target_attestation schema is invalid")
    if attestation.get("authorized") is not True or attestation.get("synthetic") is not False:
        raise BundleError("target attestation must be authorized and non-synthetic")
    if attestation.get("source_commit") != source_commit or attestation.get("source_tree") != source_tree:
        raise BundleError("target attestation source identity differs")
    for field in ("environment_id", "environment_class", "controller", "harness_path"):
        if not isinstance(attestation.get(field), str) or not attestation[field].strip():
            raise BundleError(f"target_attestation.{field} is missing")
    operator = require_login(attestation.get("operator"), "target_attestation.operator")
    harness_sha = attestation.get("harness_sha256")
    if not isinstance(harness_sha, str) or HEX64.fullmatch(harness_sha) is None:
        raise BundleError("target_attestation.harness_sha256 must be lowercase 64-hex")
    labels = require_strings(attestation.get("runner_labels"), "target_attestation.runner_labels")
    issued = parse_time(attestation.get("issued_at"), "target_attestation.issued_at")
    expires = parse_time(attestation.get("expires_at"), "target_attestation.expires_at")
    if not (issued <= started <= completed <= expires):
        raise BundleError("capture timestamps fall outside target-attestation validity")
    if require_current_attestation:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if not (issued <= current <= expires):
            raise BundleError("target attestation is not currently valid")

    review = manifest.get("review")
    if not isinstance(review, dict):
        raise BundleError("review must be an object")
    reviewer = require_login(review.get("reviewer"), "review.reviewer")
    if review.get("approved") is not True or review.get("independent") is not True:
        raise BundleError("review must be approved and independently controlled")
    reviewed = parse_time(review.get("reviewed_at"), "review.reviewed_at")
    if reviewed < completed or reviewed > expires:
        raise BundleError("review is outside the capture/attestation interval")
    if reviewer in {producer_login, operator}:
        raise BundleError("reviewer must differ from producer and target operator")
    require_strings(review.get("scope"), "review.scope")

    require_strings(manifest.get("observations"), "observations")
    require_strings(manifest.get("negative_claims"), "negative_claims")

    if level == "L6":
        release = manifest.get("release_authorization")
        if not isinstance(release, dict) or release.get("schema") != RELEASE_SCHEMA:
            raise BundleError("L6 requires a release authorization")
        if release.get("public_release") is not True:
            raise BundleError("L6 release authorization must set public_release=true")
        authorization_id = release.get("authorization_id")
        if not isinstance(authorization_id, str) or not authorization_id.strip():
            raise BundleError("release authorization_id is missing")
        authorizer = require_login(release.get("authorizer"), "release_authorization.authorizer")
        if authorizer in {producer_login, operator, reviewer}:
            raise BundleError("L6 authorizer must be independent of capture and review")
        authorized_at = parse_time(release.get("authorized_at"), "release_authorization.authorized_at")
        if authorized_at < reviewed:
            raise BundleError("release authorization predates evidence review")
        if release.get("source_commit") != source_commit or release.get("source_tree") != source_tree:
            raise BundleError("release authorization source identity differs")
    elif manifest.get("release_authorization") not in (None, {}):
        raise BundleError("non-L6 bundle must not carry public-release authorization")

    raw_files = manifest.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise BundleError("files must be a non-empty list")
    declared: set[str] = set()
    total_bytes = 0
    roles: set[str] = set()
    for index, item in enumerate(raw_files):
        label = f"files[{index}]"
        if not isinstance(item, dict):
            raise BundleError(f"{label} must be an object")
        relative = safe_relative(item.get("path"), f"{label}.path")
        name = relative.as_posix()
        if name in declared:
            raise BundleError(f"duplicate evidence path: {name}")
        declared.add(name)
        role = item.get("role")
        if not isinstance(role, str) or not role.strip():
            raise BundleError(f"{label}.role is missing")
        roles.add(role)
        expected_bytes = item.get("bytes")
        expected_sha = item.get("sha256")
        if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool) or expected_bytes < 0:
            raise BundleError(f"{label}.bytes is invalid")
        if not isinstance(expected_sha, str) or HEX64.fullmatch(expected_sha) is None:
            raise BundleError(f"{label}.sha256 is invalid")
        path = bundle_root / relative
        metadata = stable_file(path, bundle_root)
        actual_bytes, actual_sha, secret = digest_file(path)
        if metadata.st_size != actual_bytes or expected_bytes != actual_bytes or expected_sha != actual_sha:
            raise BundleError(f"evidence identity mismatch: {name}")
        if secret:
            raise BundleError(f"credential/private-key shape detected in evidence: {name}")
        total_bytes += actual_bytes
        if total_bytes > MAX_TOTAL_BYTES:
            raise BundleError("bundle exceeds the total byte bound")

    actual: set[str] = set()
    for path in bundle_root.rglob("*"):
        if path.is_symlink():
            raise BundleError(f"symlink is forbidden in bundle: {path}")
        if path.is_file():
            relative = path.relative_to(bundle_root).as_posix()
            if relative == manifest_path.name or relative in DERIVED_FILES:
                continue
            stable_file(path, bundle_root)
            actual.add(relative)
    if actual != declared:
        raise BundleError(
            "bundle file closure differs: missing="
            + ",".join(sorted(declared - actual))
            + " extra="
            + ",".join(sorted(actual - declared))
        )
    if "raw_capture" not in roles:
        raise BundleError("bundle has no raw_capture file role")

    if gap_register_path is not None:
        register, _raw = read_object(gap_register_path)
        if register.get("revision") != PLAN_REVISION:
            raise BundleError("gap register revision differs")
        entries = register.get("gaps")
        if not isinstance(entries, list):
            raise BundleError("gap register has no gaps list")
        by_id = {item.get("id"): item for item in entries if isinstance(item, dict)}
        for gap_id in gap_ids:
            gap = by_id.get(gap_id)
            if not isinstance(gap, dict):
                raise BundleError(f"bundle references unknown gap: {gap_id}")
            exit_level = gap.get("exit_evidence_level")
            if exit_level not in LEVELS or LEVELS[str(level)] < LEVELS[str(exit_level)]:
                raise BundleError(f"bundle level is below {gap_id} exit level")
            source = gap.get("source_evidence")
            if not isinstance(source, dict):
                raise BundleError(f"{gap_id} has no source evidence")
            if source.get("commit") != source_commit or source.get("tree") != source_tree:
                raise BundleError(f"bundle source differs from {gap_id} source evidence")

    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    return {
        "ok": True,
        "schema": SCHEMA,
        "manifest": str(manifest_path.relative_to(root)),
        "manifest_sha256": manifest_sha,
        "level": level,
        "kind": kind,
        "gap_ids": gap_ids,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "reviewer": reviewer,
        "operator": operator,
        "producer": producer_login,
        "runner_labels": labels,
        "file_count": len(declared),
        "total_bytes": total_bytes,
        "release_authorized": level == "L6",
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--gap-register", type=Path, default=Path("docs/status/owner-open-r5-gap-closure.json"))
    parser.add_argument("--require-current-attestation", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    try:
        report = validate_bundle(
            root,
            args.manifest,
            gap_register_path=root / args.gap_register,
            require_current_attestation=args.require_current_attestation,
        )
    except (OSError, BundleError) as error:
        report = {"ok": False, "errors": [str(error)]}
    raw = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output if args.output.is_absolute() else root / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(raw, encoding="utf-8")
    if args.json or not args.output:
        print(raw, end="")
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
'''

PROMOTION_TOOL = r'''
#!/usr/bin/env python3
"""Atomically prepare or apply a reviewed Owner-Open R5 evidence promotion."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Any

HEX40 = re.compile(r"^[0-9a-f]{40}$")


class PromotionError(ValueError):
    pass


def load_validator(root: Path):
    path = root / "tools/owner-open/owner_open_r5_evidence_bundle.py"
    spec = importlib.util.spec_from_file_location("owner_open_r5_evidence_bundle", path)
    if spec is None or spec.loader is None:
        raise PromotionError("cannot load evidence-bundle validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PromotionError(f"{path} must contain one JSON object")
    return value


def atomic(path: Path, raw: bytes) -> None:
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def promote(root: Path, manifest_path: Path, *, apply: bool) -> dict[str, Any]:
    root = root.resolve()
    manifest_path = manifest_path if manifest_path.is_absolute() else root / manifest_path
    try:
        relative_manifest = manifest_path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as error:
        raise PromotionError("manifest must be inside the repository") from error
    if relative_manifest.parts[:2] != ("evidence", "owner-open-r5"):
        raise PromotionError("promotable evidence must be committed under evidence/owner-open-r5")
    gaps_path = root / "docs/status/owner-open-r5-gap-closure.json"
    status_path = root / "docs/status/owner-open-r5-status.json"
    validator = load_validator(root)
    report = validator.validate_bundle(root, manifest_path, gap_register_path=gaps_path)
    gaps = read_object(gaps_path)
    status = read_object(status_path)
    entries = gaps.get("gaps")
    if not isinstance(entries, list):
        raise PromotionError("gap register has no gaps list")
    by_id = {item.get("id"): item for item in entries if isinstance(item, dict)}
    manifest = read_object(manifest_path)
    closed: list[str] = []
    evidence = {
        "level": report["level"],
        "source_commit": report["source_commit"],
        "source_tree": report["source_tree"],
        "evidence_sha256": report["manifest_sha256"],
        "kind": report["kind"],
        "reviewer": report["reviewer"],
        "synthetic": False,
        "bundle_manifest": relative_manifest.as_posix(),
    }
    for identifier in report["gap_ids"]:
        gap = by_id.get(identifier)
        if not isinstance(gap, dict):
            raise PromotionError(f"unknown gap: {identifier}")
        if gap.get("status") == "OPEN":
            raise PromotionError(f"source-open gap cannot be externally promoted: {identifier}")
        source = gap.get("source_evidence")
        if not isinstance(source, dict):
            raise PromotionError(f"gap has no source evidence: {identifier}")
        if source.get("commit") != report["source_commit"] or source.get("tree") != report["source_tree"]:
            raise PromotionError(f"source evidence differs for {identifier}")
        existing = gap.get("evidence")
        if gap.get("status") == "CLOSED":
            if not isinstance(existing, list) or evidence not in existing:
                raise PromotionError(f"closed gap is bound to different evidence: {identifier}")
            continue
        gap["status"] = "CLOSED"
        gap["evidence"] = [evidence]
        for field in ("remaining_evidence", "required_material", "required_authority"):
            gap.pop(field, None)
        closed.append(identifier)

    all_closed = bool(entries) and all(
        isinstance(item, dict) and item.get("status") == "CLOSED" for item in entries
    )
    release_closed = by_id.get("R5-GAP-RELEASE-001", {}).get("status") == "CLOSED"
    gaps.setdefault("generated_policy", {})["automatic_redispatch"] = False
    gaps["generated_policy"]["public_release"] = release_closed
    status["zero_gap"] = all_closed
    status["public_release"] = release_closed
    status["automatic_redispatch"] = False
    for field in ("open_repository_gaps", "external_evidence_holds", "source_closed_pending_evidence"):
        value = status.get(field)
        if isinstance(value, list):
            status[field] = [
                item for item in value
                if not isinstance(item, dict) or item.get("id") not in set(closed)
            ]
    for package in status.get("work_packages", []):
        if not isinstance(package, dict):
            continue
        open_ids = package.get("open_gap_ids")
        if isinstance(open_ids, list):
            package["open_gap_ids"] = [item for item in open_ids if item not in set(closed)]
            package["complete"] = not package["open_gap_ids"]
    if all_closed:
        status["critical_path_next"] = ["independent final closeout review and protected integration"]
        status["not_claimed"] = []
        status["claim_ceiling"] = "ZERO_GAP_EVIDENCE_BOUND_RELEASE_QUALIFIED"
        status["product_claim"] = (
            "All Owner-Open R5 gaps are bound to reviewed source and target evidence; "
            "public release is authorized by the independently reviewed L6 bundle."
        )

    gaps_raw = (json.dumps(gaps, indent=2, ensure_ascii=False) + "\n").encode()
    status_raw = (json.dumps(status, indent=2, ensure_ascii=False) + "\n").encode()
    if apply:
        original_gaps = gaps_path.read_bytes()
        original_status = status_path.read_bytes()
        try:
            atomic(gaps_path, gaps_raw)
            atomic(status_path, status_raw)
        except Exception:
            atomic(gaps_path, original_gaps)
            atomic(status_path, original_status)
            raise
    return {
        "ok": True,
        "applied": apply,
        "manifest": relative_manifest.as_posix(),
        "manifest_sha256": report["manifest_sha256"],
        "closed_gap_ids": closed,
        "all_closed": all_closed,
        "zero_gap": all_closed,
        "public_release": release_closed,
        "automatic_redispatch": False,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        report = promote(args.root.resolve(), args.manifest, apply=args.apply)
    except (OSError, json.JSONDecodeError, PromotionError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    raw = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        target = args.output if args.output.is_absolute() else args.root.resolve() / args.output
        target.write_text(raw, encoding="utf-8")
    print(raw, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
'''

BIND_TOOL = r'''
#!/usr/bin/env python3
"""Bind all R5 source evidence to one exact successful binder workflow run."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def object_at(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def bind(
    root: Path,
    *,
    branch: str,
    commit: str,
    tree: str,
    run_id: int,
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    if not branch or HEX40.fullmatch(commit) is None or HEX40.fullmatch(tree) is None or run_id <= 0:
        raise ValueError("invalid exact-source identity")
    if len(artifacts) < 3:
        raise ValueError("binder requires graph, Rust and aggregate artifacts")
    for artifact in artifacts:
        if not isinstance(artifact.get("id"), int) or artifact["id"] <= 0:
            raise ValueError("artifact id must be positive")
        if not isinstance(artifact.get("name"), str) or not artifact["name"]:
            raise ValueError("artifact name is missing")
        digest = artifact.get("digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:") or HEX64.fullmatch(digest[7:]) is None:
            raise ValueError("artifact digest is malformed")
    evidence = {
        "level": "L1",
        "branch": branch,
        "commit": commit,
        "tree": tree,
        "workflow_run_id": run_id,
        "successful_jobs": [
            "L1 exact-source graph, documentation, broker and MCP closure",
            "L1 exact-source Rust 1.93 closure",
            "L1 exact-source aggregate binder",
        ],
        "artifacts": artifacts,
    }
    gaps_path = root / "docs/status/owner-open-r5-gap-closure.json"
    status_path = root / "docs/status/owner-open-r5-status.json"
    gaps = object_at(gaps_path)
    status = object_at(status_path)
    entries = gaps.get("gaps")
    if not isinstance(entries, list) or not entries:
        raise ValueError("gap register has no gaps")
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("gap entry is malformed")
        item["source_evidence"] = evidence
    candidate = {
        "branch": branch,
        "state": "EXACT_SOURCE_HEAD_L1_PASSED",
        "evidence_level": "L1",
        "validated_source_commit": commit,
        "validated_source_tree": tree,
        "workflow_run_id": run_id,
        "checked_in_promotion_requires_new_exact_head_ci": True,
    }
    gaps["documentation_candidate"] = candidate
    status["current_candidate"] = {
        "branch": branch,
        "status": "HOST_TESTED",
        "latest_evidence_level": "L1",
        "exact_head_validation_pending": False,
        "must_not_inherit_baseline_l1": False,
        "validated_source_commit": commit,
        "validated_source_tree": tree,
        "workflow_run_id": run_id,
        "promotion_commit_requires_new_exact_head_ci": False,
        "scope": status.get("current_candidate", {}).get("scope", []),
    }
    status["known_exact_candidate"] = {
        "status": "HOST_TESTED",
        "evidence_level": "L1",
        "branch": branch,
        "commit": commit,
        "tree": tree,
        "workflow_run_id": run_id,
        "successful_jobs": evidence["successful_jobs"],
        "artifacts": artifacts,
        "claim_ceiling": "EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX",
    }
    status["product_claim"] = (
        f"Exact source commit {commit} and tree {tree} passed the permanent L1 "
        "exact-source binder. Higher-level target, device, fault, governance and "
        "release claims remain controlled by their evidence bundles."
    )
    status["claim_ceiling"] = "EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX"
    status["automatic_redispatch"] = False
    gaps_path.write_text(json.dumps(gaps, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    status_path.write_text(json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    evidence_path = root / "docs/status/owner-open-r5-source-closure-evidence-latest.md"
    evidence_path.write_text(
        "# Owner-Open R5 exact-source closure\n\n"
        f"- branch: `{branch}`\n- commit: `{commit}`\n- tree: `{tree}`\n"
        f"- workflow run: `{run_id}`\n- evidence level: `L1`\n"
        "- claim ceiling: `EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX`\n\n"
        "This source closure does not establish L2-L6 target evidence.\n",
        encoding="utf-8",
    )
    status["source_evidence_document"] = "docs/status/owner-open-r5-source-closure-evidence-latest.md"
    status_path.write_text(json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"ok": True, "commit": commit, "tree": tree, "run_id": run_id, "gap_count": len(entries)}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--branch", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--artifacts", required=True, type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        artifacts = json.loads(args.artifacts.read_text(encoding="utf-8"))
        if not isinstance(artifacts, list):
            raise ValueError("artifacts input must be a list")
        report = bind(root, branch=args.branch, commit=args.commit, tree=args.tree, run_id=args.run_id, artifacts=artifacts)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
'''

WORKFLOW_IDENTITY = r'''
#!/usr/bin/env python3
"""Reject ambiguous PR merge-SHA evidence and temporary write executors."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

ALLOWED_WRITE = {"owner-open-r5-exact-source-binder-v4.yml"}
FORBIDDEN_NAME_PARTS = ("one-shot", "promotion-executor", "semantics-executor")


def verify(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    checked: list[str] = []
    directory = root / ".github/workflows"
    for path in sorted(directory.glob("owner-open-r5*.yml")):
        text = path.read_text(encoding="utf-8")
        checked.append(path.name)
        if any(value in path.name for value in FORBIDDEN_NAME_PARTS):
            errors.append(f"temporary executor remains tracked: {path.name}")
        if re.search(r"(?m)^\s*contents:\s*write\s*$", text) and path.name not in ALLOWED_WRITE:
            errors.append(f"unexpected contents:write workflow: {path.name}")
        if re.search(r"(?m)^\s{2}pull_request\s*:", text):
            if re.search(r"\$\{\{\s*github\.sha\s*\}\}", text):
                errors.append(f"raw PR merge github.sha identity remains: {path.name}")
            lines = text.splitlines()
            for index, line in enumerate(lines):
                if re.match(r"^\s*- uses: actions/checkout@v4\s*$", line):
                    indent = len(line) - len(line.lstrip())
                    block: list[str] = []
                    for following in lines[index + 1:]:
                        stripped = following.strip()
                        following_indent = len(following) - len(following.lstrip())
                        if stripped and following_indent <= indent and stripped.startswith("-"):
                            break
                        if stripped and following_indent < indent:
                            break
                        block.append(following)
                    joined = "\n".join(block)
                    if not any(token in joined for token in (
                        "github.event.pull_request.head.sha",
                        "env.EXPECTED_SHA",
                        "inputs.source_commit",
                    )):
                        errors.append(f"PR checkout is not exact-head-bound: {path.name}:{index + 1}")
    return {"ok": not errors, "errors": errors, "workflows": checked}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = verify(args.root.resolve())
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for error in report["errors"]:
            print(f"ERROR: {error}", file=sys.stderr)
        if report["ok"]:
            print("owner-open R5 workflow identity verified")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
'''

TEST_BUNDLE = r'''
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BUNDLE_SCRIPT = ROOT / "tools/owner-open/owner_open_r5_evidence_bundle.py"
PROMOTION_SCRIPT = ROOT / "tools/owner-open/promote_owner_open_r5_evidence.py"

def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

bundle = load("owner_open_r5_evidence_bundle_test", BUNDLE_SCRIPT)
promotion = load("promote_owner_open_r5_evidence_test", PROMOTION_SCRIPT)


class EvidenceBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "docs/status").mkdir(parents=True)
        (self.root / "tools/owner-open").mkdir(parents=True)
        (self.root / "tools/owner-open/owner_open_r5_evidence_bundle.py").write_bytes(BUNDLE_SCRIPT.read_bytes())
        self.source = {"level": "L1", "branch": "feature", "commit": "a" * 40, "tree": "b" * 40, "workflow_run_id": 1, "successful_jobs": ["graph"], "artifacts": [{"id": 1, "name": "source", "digest": "sha256:" + "c" * 64}]}
        self.gaps = {"schema": "org.trillionnium.owner-open-r5.gap-closure.v1", "revision": bundle.PLAN_REVISION, "generated_policy": {"automatic_redispatch": False, "public_release": False}, "priority_order": ["GAP-L2"], "gaps": [{"id": "GAP-L2", "status": "SOURCE_CLOSED_PENDING_EVIDENCE", "issue": 1, "summary": "target", "exit_evidence_level": "L2", "acceptance": ["target passes"], "source_evidence": self.source, "remaining_evidence": ["target"]}]}
        self.status = {"active_plan_revision": bundle.PLAN_REVISION, "zero_gap": False, "public_release": False, "automatic_redispatch": False, "work_packages": [], "not_claimed": ["target"], "critical_path_next": ["target"]}
        self.write_machine()
        self.bundle_dir = self.root / "evidence/owner-open-r5/l2-test"
        self.bundle_dir.mkdir(parents=True)
        self.raw = self.bundle_dir / "raw.log"
        self.raw.write_bytes(b"real-target-observation\n")
        self.manifest = self.bundle_dir / "manifest.json"
        self.write_manifest()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_machine(self) -> None:
        (self.root / "docs/status/owner-open-r5-gap-closure.json").write_text(json.dumps(self.gaps, indent=2) + "\n")
        (self.root / "docs/status/owner-open-r5-status.json").write_text(json.dumps(self.status, indent=2) + "\n")

    def write_manifest(self, **changes) -> None:
        raw = self.raw.read_bytes()
        value = {
            "schema": bundle.SCHEMA,
            "plan_revision": bundle.PLAN_REVISION,
            "kind": "installed_root_linux_process_matrix",
            "gap_ids": ["GAP-L2"],
            "level": "L2",
            "result": "pass",
            "repository": bundle.REPOSITORY,
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "workflow": {"run_id": 12, "run_attempt": 1, "job_id": 34, "name": "L2 target", "started_at": "2026-08-30T00:10:00Z", "completed_at": "2026-08-30T00:20:00Z"},
            "producer": {"login": "capture-producer", "role": "capture"},
            "target_attestation": {"schema": bundle.ATTESTATION_SCHEMA, "environment_id": "rootlinux-01", "environment_class": "installed_root_linux", "controller": "target-owner", "operator": "target-operator", "issued_at": "2026-08-30T00:00:00Z", "expires_at": "2026-08-30T02:00:00Z", "source_commit": "a" * 40, "source_tree": "b" * 40, "synthetic": False, "authorized": True, "harness_path": "/opt/owner-open-r5/harnesses/l2-rootlinux", "harness_sha256": "d" * 64, "runner_labels": ["self-hosted", "owner-open-r5-l2-rootlinux"]},
            "observations": ["installed process matrix passed"],
            "files": [{"path": "raw.log", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "role": "raw_capture"}],
            "negative_claims": ["does not claim Android image"],
            "automatic_redispatch": False,
            "synthetic": False,
            "review": {"reviewer": "independent-reviewer", "reviewed_at": "2026-08-30T00:30:00Z", "approved": True, "independent": True, "scope": ["raw logs", "source identity"]},
        }
        value.update(changes)
        self.manifest.write_text(json.dumps(value, indent=2) + "\n")

    def validate(self):
        return bundle.validate_bundle(self.root, self.manifest, gap_register_path=self.root / "docs/status/owner-open-r5-gap-closure.json")

    def test_valid_bundle(self) -> None:
        report = self.validate()
        self.assertTrue(report["ok"])
        self.assertEqual(report["gap_ids"], ["GAP-L2"])

    def test_raw_tamper_fails(self) -> None:
        self.raw.write_bytes(b"tampered\n")
        with self.assertRaises(bundle.BundleError):
            self.validate()

    def test_undeclared_file_fails(self) -> None:
        (self.bundle_dir / "extra.log").write_text("extra")
        with self.assertRaises(bundle.BundleError):
            self.validate()

    def test_secret_shape_fails(self) -> None:
        self.raw.write_bytes(b"OPENAI_API_KEY=secret-secret-secret\n")
        self.write_manifest()
        with self.assertRaises(bundle.BundleError):
            self.validate()

    def test_reviewer_must_be_independent(self) -> None:
        value = json.loads(self.manifest.read_text())
        value["review"]["reviewer"] = "target-operator"
        self.manifest.write_text(json.dumps(value))
        with self.assertRaises(bundle.BundleError):
            self.validate()

    def test_l6_requires_fourth_party_authorization(self) -> None:
        self.gaps["gaps"][0]["exit_evidence_level"] = "L6"
        self.write_machine()
        self.write_manifest(level="L6")
        with self.assertRaises(bundle.BundleError):
            self.validate()

    def test_promotion_closes_only_bound_gap(self) -> None:
        report = promotion.promote(self.root, self.manifest, apply=True)
        self.assertTrue(report["all_closed"])
        gaps = json.loads((self.root / "docs/status/owner-open-r5-gap-closure.json").read_text())
        status = json.loads((self.root / "docs/status/owner-open-r5-status.json").read_text())
        self.assertEqual(gaps["gaps"][0]["status"], "CLOSED")
        self.assertTrue(status["zero_gap"])
        self.assertFalse(status["public_release"])


if __name__ == "__main__":
    unittest.main()
'''

TEST_BIND = r'''
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "owner-open/bind_owner_open_r5_source_evidence.py"
spec = importlib.util.spec_from_file_location("bind_owner_open_r5_source_evidence_test", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class BindSourceEvidenceTest(unittest.TestCase):
    def test_bind_updates_every_gap_without_closing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "docs/status").mkdir(parents=True)
            gaps = {"gaps": [{"id": "A", "status": "OPEN"}, {"id": "B", "status": "EXTERNAL_HOLD"}]}
            status = {"current_candidate": {}, "automatic_redispatch": False}
            (root / "docs/status/owner-open-r5-gap-closure.json").write_text(json.dumps(gaps))
            (root / "docs/status/owner-open-r5-status.json").write_text(json.dumps(status))
            artifacts = [{"id": i, "name": f"artifact-{i}", "digest": "sha256:" + str(i) * 64} for i in (1, 2, 3)]
            report = module.bind(root, branch="feature", commit="a" * 40, tree="b" * 40, run_id=7, artifacts=artifacts)
            self.assertTrue(report["ok"])
            value = json.loads((root / "docs/status/owner-open-r5-gap-closure.json").read_text())
            self.assertEqual([item["status"] for item in value["gaps"]], ["OPEN", "EXTERNAL_HOLD"])
            self.assertTrue(all(item["source_evidence"]["commit"] == "a" * 40 for item in value["gaps"]))

if __name__ == "__main__":
    unittest.main()
'''

TEST_WORKFLOW_IDENTITY = r'''
from __future__ import annotations
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "owner-open/verify_owner_open_r5_workflow_identity.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_r5_workflow_identity_test", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class WorkflowIdentityTest(unittest.TestCase):
    def test_good_exact_head_workflow_passes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / ".github/workflows"
            path.mkdir(parents=True)
            (path / "owner-open-r5-good.yml").write_text("on:\n  pull_request:\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha || github.sha }}\n")
            self.assertTrue(module.verify(root)["ok"])

    def test_raw_merge_sha_and_write_executor_fail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / ".github/workflows"
            path.mkdir(parents=True)
            (path / "owner-open-r5-one-shot.yml").write_text("on:\n  pull_request:\npermissions:\n  contents: write\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo '${{ github.sha }}'\n")
            report = module.verify(root)
            self.assertFalse(report["ok"])
            self.assertGreaterEqual(len(report["errors"]), 3)

if __name__ == "__main__":
    unittest.main()
'''


def capture_workflow(level: str, title: str, label: str, environment: str, harness: str, gaps: list[str]) -> str:
    gap_text = " ".join(gaps)
    return f'''
name: {level} owner-open R5 {title} capture

on:
  workflow_dispatch:
    inputs:
      source_commit:
        description: Exact L1-qualified source commit
        required: true
        type: string
      source_tree:
        description: Exact L1-qualified source tree
        required: true
        type: string

permissions:
  contents: read

concurrency:
  group: owner-open-r5-{level.lower()}-{label}-${{{{ inputs.source_commit }}}}
  cancel-in-progress: false

jobs:
  capture:
    name: {level} independently controlled target capture
    runs-on: [self-hosted, linux, {label}]
    environment: {environment}
    timeout-minutes: 180
    env:
      EXPECTED_SOURCE_COMMIT: ${{{{ inputs.source_commit }}}}
      EXPECTED_SOURCE_TREE: ${{{{ inputs.source_tree }}}}
      AUTOMATIC_REDISPATCH: "false"
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          ref: ${{{{ inputs.source_commit }}}}
          persist-credentials: false
      - name: Assert exact qualified source
        shell: bash
        run: |
          set -euo pipefail
          test "$(git rev-parse HEAD)" = "$EXPECTED_SOURCE_COMMIT"
          test "$(git rev-parse HEAD^{{tree}})" = "$EXPECTED_SOURCE_TREE"
          test -z "$(git status --porcelain --untracked-files=no)"
      - name: Execute target-owned harness
        shell: bash
        run: |
          set -euo pipefail
          test "$AUTOMATIC_REDISPATCH" = false
          test -f /etc/owner-open-r5/target-attestation.json
          test -x {harness}
          output="$RUNNER_TEMP/owner-open-r5-{level.lower()}-$GITHUB_RUN_ID"
          test ! -e "$output"
          mkdir -m 0700 "$output"
          {harness} \\
            --source-root "$GITHUB_WORKSPACE" \\
            --source-commit "$EXPECTED_SOURCE_COMMIT" \\
            --source-tree "$EXPECTED_SOURCE_TREE" \\
            --attestation /etc/owner-open-r5/target-attestation.json \\
            --gap-ids {gap_text} \\
            --output "$output"
          python3 tools/owner-open/owner_open_r5_evidence_bundle.py \\
            --manifest "$output/manifest.json" \\
            --require-current-attestation \\
            --output "$output/validation-report.json"
          (cd "$output" && sha256sum manifest.json validation-report.json > SHA256SUMS)
      - uses: actions/upload-artifact@v4
        with:
          name: owner-open-r5-{level.lower()}-${{{{ inputs.source_commit }}}}-${{{{ github.run_id }}}}
          path: ${{{{ runner.temp }}}}/owner-open-r5-{level.lower()}-${{{{ github.run_id }}}}/
          if-no-files-found: error
          retention-days: 30
'''


BINDER_WORKFLOW = r'''
name: L1 owner-open R5 exact-source binder v4

on:
  push:
    branches:
      - codex/owner-open-r5-gap-closure-20260829
    paths:
      - "Cargo.toml"
      - "Cargo.lock"
      - "apps/**"
      - "crates/**"
      - "tools/**"
      - "docs/contracts/**"
      - "docs/protocols/**"
      - "docs/architecture/**"
      - "docs/operations/**"
      - "docs/qualification/**"
      - "docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md"
      - ".github/workflows/**"
      - ".github/CODEOWNERS"

permissions:
  contents: write
  actions: read

concurrency:
  group: owner-open-r5-exact-source-binder-${{ github.ref }}
  cancel-in-progress: true

env:
  SOURCE_SHA: ${{ github.sha }}
  SOURCE_BRANCH: codex/owner-open-r5-gap-closure-20260829

jobs:
  graph:
    name: L1 exact-source graph, docs, broker and MCP closure
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    outputs:
      artifact_id: ${{ steps.upload.outputs.artifact-id }}
      artifact_digest: ${{ steps.upload.outputs.artifact-digest }}
      artifact_name: owner-open-r5-l1-binder-graph-${{ github.sha }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          ref: ${{ github.sha }}
          persist-credentials: false
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - name: Execute exact-source Python closure
        env:
          OWNER_OPEN_R5_BINDING_SOURCE_SHA: ${{ github.sha }}
          PYTHONWARNINGS: error::ResourceWarning
        run: |
          set -euo pipefail
          test "$(git rev-parse HEAD)" = "$SOURCE_SHA"
          python3 -m compileall -q tools
          python3 tools/generate-owner-open-types.py --check
          python3 tools/verify-owner-open-r5.py --json | tee verify-r5.json
          python3 tools/verify-owner-open-r5-gap-evidence.py --json | tee verify-gap.json
          python3 tools/owner-open/verify_owner_open_r5_workflow_identity.py --json | tee verify-workflows.json
          python3 -m unittest \
            tools.tests.test_verify_owner_open_r5 \
            tools.tests.test_verify_owner_open_r5_gap_closure \
            tools.tests.test_verify_owner_open_r5_gap_evidence \
            tools.tests.test_generate_owner_open_r5_resume_packet \
            tools.tests.test_owner_open_r5_evidence_bundle \
            tools.tests.test_bind_owner_open_r5_source_evidence \
            tools.tests.test_verify_owner_open_r5_workflow_identity \
            tools.tests.test_codex_owner_open_mcp \
            tools.tests.test_codex_mcp_qualification_lifecycle \
            -v 2>&1 | tee binder-tests.log
          python3 -m unittest discover -s tools/tests -p 'test_*broker*.py' -v 2>&1 | tee binder-broker-tests.log
          test -z "$(git status --porcelain --untracked-files=no)"
      - id: upload
        uses: actions/upload-artifact@v4
        with:
          name: owner-open-r5-l1-binder-graph-${{ github.sha }}
          path: |
            verify-r5.json
            verify-gap.json
            verify-workflows.json
            binder-tests.log
            binder-broker-tests.log
          if-no-files-found: error
          retention-days: 30

  rust:
    name: L1 exact-source Rust 1.93 closure
    runs-on: ubuntu-24.04
    timeout-minutes: 75
    outputs:
      artifact_id: ${{ steps.upload.outputs.artifact-id }}
      artifact_digest: ${{ steps.upload.outputs.artifact-digest }}
      artifact_name: owner-open-r5-l1-binder-rust-${{ github.sha }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          ref: ${{ github.sha }}
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@1.93.0
        with:
          components: rustfmt, clippy
      - name: Execute exact-source Rust closure
        run: |
          set -euo pipefail
          test "$(git rev-parse HEAD)" = "$SOURCE_SHA"
          cp Cargo.lock reviewed-Cargo.lock
          cargo metadata --locked --format-version 1 > cargo-metadata.json
          cargo fmt --all -- --check
          cargo test --locked --all-targets 2>&1 | tee cargo-test.log
          cargo clippy --locked --all-targets -- -D warnings 2>&1 | tee cargo-clippy.log
          cmp --silent Cargo.lock reviewed-Cargo.lock
          git diff --exit-code -- Cargo.lock
          test -z "$(git status --porcelain --untracked-files=no)"
      - id: upload
        uses: actions/upload-artifact@v4
        with:
          name: owner-open-r5-l1-binder-rust-${{ github.sha }}
          path: |
            Cargo.lock
            reviewed-Cargo.lock
            cargo-metadata.json
            cargo-test.log
            cargo-clippy.log
          if-no-files-found: error
          retention-days: 30

  bind:
    name: Bind exact-source evidence without target promotion
    needs: [graph, rust]
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          ref: ${{ github.sha }}
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - name: Generate aggregate candidate
        run: |
          set -euo pipefail
          tree="$(git rev-parse HEAD^{tree})"
          python3 tools/owner-open/generate_owner_open_l1_candidate.py \
            --repository "$GITHUB_REPOSITORY" \
            --source-head-sha "$SOURCE_SHA" \
            --source-head-ref "$SOURCE_BRANCH" \
            --workflow-trigger-sha "$SOURCE_SHA" \
            --pull-request-base-sha "" \
            --event-name push \
            --workflow-name "L1 owner-open R5 exact-source binder v4" \
            --workflow-run-id "$GITHUB_RUN_ID" \
            --workflow-run-attempt "$GITHUB_RUN_ATTEMPT" \
            --output binder-candidate.json
          test "$(python3 -c 'import json; print(json.load(open("binder-candidate.json"))["tree_sha"])')" = "$tree"
      - id: candidate_upload
        uses: actions/upload-artifact@v4
        with:
          name: owner-open-r5-l1-binder-candidate-${{ github.sha }}
          path: binder-candidate.json
          if-no-files-found: error
          retention-days: 30
      - name: Bind exact-source artifact identities
        env:
          GRAPH_ID: ${{ needs.graph.outputs.artifact_id }}
          GRAPH_DIGEST: ${{ needs.graph.outputs.artifact_digest }}
          GRAPH_NAME: ${{ needs.graph.outputs.artifact_name }}
          RUST_ID: ${{ needs.rust.outputs.artifact_id }}
          RUST_DIGEST: ${{ needs.rust.outputs.artifact_digest }}
          RUST_NAME: ${{ needs.rust.outputs.artifact_name }}
          CANDIDATE_ID: ${{ steps.candidate_upload.outputs.artifact-id }}
          CANDIDATE_DIGEST: ${{ steps.candidate_upload.outputs.artifact-digest }}
          CANDIDATE_NAME: owner-open-r5-l1-binder-candidate-${{ github.sha }}
        run: |
          set -euo pipefail
          tree="$(git rev-parse HEAD^{tree})"
          python3 - <<'PY'
          import json, os
          values = []
          for prefix in ("GRAPH", "RUST", "CANDIDATE"):
              values.append({
                  "id": int(os.environ[prefix + "_ID"]),
                  "name": os.environ[prefix + "_NAME"],
                  "digest": os.environ[prefix + "_DIGEST"],
              })
          open("binder-artifacts.json", "w").write(json.dumps(values, indent=2) + "\n")
          PY
          python3 tools/owner-open/bind_owner_open_r5_source_evidence.py \
            --branch "$SOURCE_BRANCH" \
            --commit "$SOURCE_SHA" \
            --tree "$tree" \
            --run-id "$GITHUB_RUN_ID" \
            --artifacts binder-artifacts.json
          unset OWNER_OPEN_R5_BINDING_SOURCE_SHA
          python3 tools/verify-owner-open-r5.py --json > /tmp/verify-r5.json
          python3 tools/verify-owner-open-r5-gap-evidence.py --json > /tmp/verify-gap.json
          python3 tools/owner-open/verify_owner_open_r5_workflow_identity.py --json > /tmp/verify-workflows.json
          git diff --check
      - name: Commit status-only source binding with compare-and-swap
        run: |
          set -euo pipefail
          remote="$(git ls-remote origin refs/heads/$SOURCE_BRANCH | awk '{print $1}')"
          test "$remote" = "$SOURCE_SHA"
          git config user.name github-actions[bot]
          git config user.email 41898282+github-actions[bot]@users.noreply.github.com
          git add docs/status/owner-open-r5-gap-closure.json docs/status/owner-open-r5-status.json docs/status/owner-open-r5-source-closure-evidence-latest.md
          test -n "$(git diff --cached --name-only)"
          test -z "$(git diff --cached --name-only | grep -v '^docs/status/' || true)"
          git diff --cached --check
          git commit -m "docs(r5): bind exact-source evidence for $SOURCE_SHA"
          git push origin HEAD:$SOURCE_BRANCH
'''

REVIEW_WORKFLOW = r'''
name: Owner-open R5 evidence bundle and promotion review

on:
  pull_request:
    paths:
      - "evidence/owner-open-r5/**"
      - "docs/status/owner-open-r5-gap-closure.json"
      - "docs/status/owner-open-r5-status.json"
      - "tools/owner-open/owner_open_r5_evidence_bundle.py"
      - "tools/owner-open/promote_owner_open_r5_evidence.py"
      - ".github/workflows/owner-open-r5-*-capture.yml"
      - ".github/workflows/owner-open-r5-evidence-review.yml"
  pull_request_review:
    types: [submitted, dismissed]

permissions:
  contents: read
  pull-requests: read

jobs:
  verify:
    if: github.event_name == 'pull_request' || github.event.pull_request != null
    runs-on: ubuntu-24.04
    timeout-minutes: 25
    env:
      EXPECTED_SHA: ${{ github.event.pull_request.head.sha }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - name: Verify bundles, machine truth and exact-head review boundary
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"
          python3 -m unittest tools.tests.test_owner_open_r5_evidence_bundle -v
          python3 tools/verify-owner-open-r5.py --json > verify-r5.json
          python3 tools/verify-owner-open-r5-gap-evidence.py --json > verify-gap.json
          python3 tools/owner-open/verify_owner_open_r5_workflow_identity.py --json > verify-workflows.json
          python3 - <<'PY'
          import json, os, subprocess
          base = os.environ["GITHUB_BASE_REF"]
          head = os.environ["EXPECTED_SHA"]
          changed = subprocess.check_output(["git", "diff", "--name-only", f"origin/{base}...{head}"], text=True).splitlines()
          sensitive = any(path.startswith("evidence/owner-open-r5/") for path in changed)
          if not sensitive:
              raise SystemExit(0)
          event = json.load(open(os.environ["GITHUB_EVENT_PATH"]))
          pr = event["pull_request"]
          author = pr["user"]["login"]
          repo = os.environ["GITHUB_REPOSITORY"]
          number = pr["number"]
          raw = subprocess.check_output(["gh", "api", f"repos/{repo}/pulls/{number}/reviews", "--paginate"], text=True)
          reviews = json.loads(raw)
          latest = {}
          for review in reviews:
              latest[review["user"]["login"]] = review
          approved = [review for login, review in latest.items() if login != author and not login.endswith("[bot]") and review.get("state") == "APPROVED" and review.get("commit_id") == head]
          if not approved:
              raise SystemExit("external evidence requires a non-author, non-bot APPROVED review anchored to the exact PR head")
          PY
      - uses: actions/upload-artifact@v4
        with:
          name: owner-open-r5-evidence-review-${{ github.event.pull_request.head.sha }}
          path: verify-*.json
          if-no-files-found: error
          retention-days: 30
'''

RUNBOOK = r'''
# Owner-Open R5 evidence bundle and target-capture runbook

Status: **ACTIVE — capture and promotion mechanics only; no target is inferred to exist**  
Plan revision: `2026-08-29-r6`

## Boundary

A source workflow can close only L1 source work. L2–L6 require an independently
controlled target, a target-owned attestation and harness, raw observations, a
recursive evidence bundle, independent review, and a separate promotion commit.
Capture workflows use `contents: read`; artifact upload is never promotion.

## Fixed target paths

Each target runner must provide:

```text
/etc/owner-open-r5/target-attestation.json
/opt/owner-open-r5/harnesses/<lane>
```

The attestation is non-synthetic, time bounded, source commit/tree bound and
names the environment controller, operator, harness digest and runner labels.
The harness writes a new private bundle directory containing `manifest.json`
and every raw file declared by that manifest.

## Permanent lanes

| Level | Runner label | Harness | Gap family |
|---|---|---|---|
| L1 governance | `owner-open-r5-governance` | `governance` | branch protection and exact-head independent review |
| L2 | `owner-open-r5-l2-rootlinux` | `l2-rootlinux` | installed Codex, Root Linux, process, flow and Broker |
| L3 | `owner-open-r5-l3-android` | `l3-android` | clean target-files, product entrypoint, init and SELinux |
| L4 | `owner-open-r5-l4-physical` | `l4-physical` | authorized physical ordinary ADB and visible effects |
| L5 | `owner-open-r5-l5-destructive` | `l5-destructive` | crash, ENOSPC, corruption, USB, reboot and power loss |
| L6 | `owner-open-r5-l6-release` | `l6-release` | signatures, AVB, OTA, rollback, custody and human authorization |

## Validation and promotion

```text
python3 tools/owner-open/owner_open_r5_evidence_bundle.py \
  --manifest evidence/owner-open-r5/<bundle>/manifest.json \
  --json

python3 tools/owner-open/promote_owner_open_r5_evidence.py \
  --manifest evidence/owner-open-r5/<bundle>/manifest.json
```

The second command is dry-run by default. `--apply` updates only the canonical
gap register and status. The resulting branch must pass the permanent evidence
review workflow and receive a non-author, non-bot approval on its exact head.
L6 additionally requires a fourth, independent human release authorizer.

## No-redispatch rule

Every attestation, manifest, promotion record and resulting status retains:

```text
automatic_redispatch=false
```

Unknown post-effect outcomes are reconciled; they are never blindly repeated.
'''

TARGET_TEMPLATE = {
    "schema": "org.trillionnium.owner-open-r5.target-attestation.v1",
    "environment_id": "UNSET",
    "environment_class": "UNSET",
    "controller": "UNSET",
    "operator": "UNSET",
    "issued_at": "1970-01-01T00:00:00Z",
    "expires_at": "1970-01-01T00:00:00Z",
    "source_commit": "0" * 40,
    "source_tree": "0" * 40,
    "synthetic": True,
    "authorized": False,
    "harness_path": "/opt/owner-open-r5/harnesses/UNSET",
    "harness_sha256": "0" * 64,
    "runner_labels": ["UNSET"],
}

BUNDLE_TEMPLATE = {
    "schema": "org.trillionnium.owner-open-r5.evidence-bundle.v1",
    "plan_revision": "2026-08-29-r6",
    "kind": "UNSET",
    "gap_ids": ["UNSET"],
    "level": "L0",
    "result": "hold",
    "repository": "TrillionniumFoundation/trillionnium-os",
    "source_commit": "0" * 40,
    "source_tree": "0" * 40,
    "workflow": {"run_id": 0, "run_attempt": 0, "job_id": 0, "name": "UNSET", "started_at": "1970-01-01T00:00:00Z", "completed_at": "1970-01-01T00:00:00Z"},
    "producer": {"login": "UNSET", "role": "UNSET"},
    "target_attestation": TARGET_TEMPLATE,
    "observations": ["UNSET"],
    "files": [],
    "negative_claims": ["template is not evidence"],
    "automatic_redispatch": False,
    "synthetic": True,
    "review": {"reviewer": "UNSET", "reviewed_at": "1970-01-01T00:00:00Z", "approved": False, "independent": False, "scope": ["UNSET"]},
}

READINESS = {
    "schema": "org.trillionnium.owner-open-r5.target-readiness.v1",
    "plan_revision": "2026-08-29-r6",
    "source_of_truth": "environment and runner administration plus target-local attestation",
    "automatic_redispatch": False,
    "environments": [
        {"level": level, "environment": environment, "runner_label": label, "attestation_path": "/etc/owner-open-r5/target-attestation.json", "harness_path": harness, "environment_exists": False, "runner_ready": False, "attestation_validated": False, "harness_validated": False, "capture_ready": False}
        for level, environment, label, harness in [
            ("L1", "owner-open-r5-governance", "owner-open-r5-governance", "/opt/owner-open-r5/harnesses/governance"),
            ("L2", "owner-open-r5-l2-rootlinux", "owner-open-r5-l2-rootlinux", "/opt/owner-open-r5/harnesses/l2-rootlinux"),
            ("L3", "owner-open-r5-l3-android", "owner-open-r5-l3-android", "/opt/owner-open-r5/harnesses/l3-android"),
            ("L4", "owner-open-r5-l4-physical", "owner-open-r5-l4-physical", "/opt/owner-open-r5/harnesses/l4-physical"),
            ("L5", "owner-open-r5-l5-destructive", "owner-open-r5-l5-destructive", "/opt/owner-open-r5/harnesses/l5-destructive"),
            ("L6", "owner-open-r5-l6-release", "owner-open-r5-l6-release", "/opt/owner-open-r5/harnesses/l6-release"),
        ]
    ],
}


def harden_gap_verifier() -> None:
    path = "tools/verify-owner-open-r5-gap-evidence.py"
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    for import_line in ("import hashlib\n", "import importlib.util\n", "import os\n", "import subprocess\n"):
        if import_line not in text:
            text = text.replace("import argparse\n", "import argparse\n" + import_line, 1)
    target.write_text(text, encoding="utf-8")

    replacement = r'''def exact_source_evidence(root: Path, value: Any, label: str, report: Report) -> None:
    report.check(isinstance(value, dict), f"{label} source_evidence must be an object")
    if not isinstance(value, dict):
        return
    report.check(value.get("level") == "L1", f"{label} source evidence level must be L1")
    report.check(isinstance(value.get("branch"), str) and bool(value.get("branch")), f"{label} source evidence branch is missing")
    commit = value.get("commit")
    tree = value.get("tree")
    report.check(isinstance(commit, str) and HEX40.fullmatch(commit) is not None, f"{label} source evidence commit must be lowercase 40-hex")
    report.check(isinstance(tree, str) and HEX40.fullmatch(tree) is not None, f"{label} source evidence tree must be lowercase 40-hex")
    report.check(isinstance(value.get("workflow_run_id"), int) and not isinstance(value.get("workflow_run_id"), bool) and value["workflow_run_id"] > 0, f"{label} source evidence workflow_run_id must be positive")
    report.check(nonempty_strings(value.get("successful_jobs")), f"{label} source evidence must name successful jobs")
    artifacts = value.get("artifacts")
    report.check(isinstance(artifacts, list) and bool(artifacts), f"{label} source evidence must bind at least one artifact")
    if isinstance(artifacts, list):
        for index, artifact in enumerate(artifacts):
            artifact_label = f"{label} source_evidence.artifacts[{index}]"
            report.check(isinstance(artifact, dict), f"{artifact_label} must be an object")
            if not isinstance(artifact, dict):
                continue
            report.check(isinstance(artifact.get("id"), int) and not isinstance(artifact.get("id"), bool) and artifact["id"] > 0, f"{artifact_label}.id must be positive")
            report.check(isinstance(artifact.get("name"), str) and bool(artifact.get("name")), f"{artifact_label}.name is missing")
            digest = artifact.get("digest")
            report.check(isinstance(digest, str) and digest.startswith("sha256:") and HEX64.fullmatch(digest.removeprefix("sha256:")) is not None, f"{artifact_label}.digest must be sha256:<64 lowercase hex>")
    git = root / ".git"
    if git.exists() and isinstance(commit, str) and HEX40.fullmatch(commit):
        try:
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True, timeout=10).strip()
            transition = os.environ.get("OWNER_OPEN_R5_BINDING_SOURCE_SHA")
            if transition == head:
                return
            subprocess.run(["git", "merge-base", "--is-ancestor", commit, head], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            changed = subprocess.check_output(["git", "diff", "--name-only", f"{commit}..{head}"], cwd=root, text=True, timeout=10).splitlines()
            forbidden = [name for name in changed if not (name.startswith("docs/status/") or name.startswith("evidence/owner-open-r5/"))]
            report.check(not forbidden, f"{label} source evidence is stale after source changes: {', '.join(forbidden[:8])}")
        except (OSError, subprocess.SubprocessError):
            report.check(False, f"{label} source evidence commit is not an ancestor of current HEAD")


def _bundle_validator(root: Path):
    path = root / "tools/owner-open/owner_open_r5_evidence_bundle.py"
    spec = importlib.util.spec_from_file_location("owner_open_r5_evidence_bundle_gap", path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load evidence-bundle validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def environment_evidence(root: Path, value: Any, source: Any, label: str, exit_level: str, report: Report) -> None:
    report.check(isinstance(value, list) and bool(value), f"{label} evidence must be a non-empty list")
    if not isinstance(value, list):
        report.check(False, f"{label} has no evidence at or above exit level {exit_level}")
        return
    exit_rank = LEVELS[exit_level]
    observed_ranks: list[int] = []
    for index, item in enumerate(value):
        item_label = f"{label} evidence[{index}]"
        report.check(isinstance(item, dict), f"{item_label} must be an object")
        if not isinstance(item, dict):
            continue
        level = item.get("level")
        report.check(level in LEVELS, f"{item_label}.level is invalid")
        if level in LEVELS:
            observed_ranks.append(LEVELS[level])
        for field in ("source_commit", "source_tree"):
            raw = item.get(field)
            report.check(isinstance(raw, str) and HEX40.fullmatch(raw) is not None, f"{item_label}.{field} must be lowercase 40-hex")
        digest = item.get("evidence_sha256")
        report.check(isinstance(digest, str) and HEX64.fullmatch(digest) is not None, f"{item_label}.evidence_sha256 must be lowercase 64-hex")
        report.check(isinstance(item.get("kind"), str) and bool(item.get("kind")), f"{item_label}.kind is missing")
        report.check(isinstance(item.get("reviewer"), str) and bool(item.get("reviewer")), f"{item_label}.reviewer is missing")
        report.check(item.get("synthetic") is False, f"{item_label} must explicitly declare synthetic=false")
        manifest_value = item.get("bundle_manifest")
        report.check(isinstance(manifest_value, str) and manifest_value.startswith("evidence/owner-open-r5/"), f"{item_label}.bundle_manifest must be under evidence/owner-open-r5")
        if not isinstance(manifest_value, str):
            continue
        try:
            module = _bundle_validator(root)
            bundle = module.validate_bundle(root, root / manifest_value, gap_register_path=root / GAPS)
        except Exception as error:
            report.check(False, f"{item_label} bundle validation failed: {error}")
            continue
        report.check(bundle.get("manifest_sha256") == digest, f"{item_label} manifest digest differs")
        report.check(bundle.get("level") == level, f"{item_label} bundle level differs")
        report.check(bundle.get("kind") == item.get("kind"), f"{item_label} bundle kind differs")
        report.check(bundle.get("reviewer") == item.get("reviewer"), f"{item_label} bundle reviewer differs")
        report.check(label in bundle.get("gap_ids", []), f"{item_label} bundle does not cover the gap")
        report.check(bundle.get("source_commit") == item.get("source_commit"), f"{item_label} bundle source commit differs")
        report.check(bundle.get("source_tree") == item.get("source_tree"), f"{item_label} bundle source tree differs")
        if isinstance(source, dict):
            report.check(item.get("source_commit") == source.get("commit") and item.get("source_tree") == source.get("tree"), f"{item_label} does not bind the gap source evidence")
    report.check(any(rank >= exit_rank for rank in observed_ranks), f"{label} has no evidence at or above exit level {exit_level}")


'''
    replace_between(path, "def exact_source_evidence(", "def verify(", replacement + "def verify(")
    text = target.read_text(encoding="utf-8")
    text = text.replace("exact_source_evidence(gap.get(\"source_evidence\"), identifier, report)", "exact_source_evidence(root, gap.get(\"source_evidence\"), identifier, report)")
    text = text.replace("exact_source_evidence(gap[\"source_evidence\"], identifier, report)", "exact_source_evidence(root, gap[\"source_evidence\"], identifier, report)")
    old = '''        elif state == "CLOSED" and exit_level in LEVELS:\n            exact_source_evidence(root, gap.get("source_evidence"), identifier, report)\n            if external_required:\n                environment_evidence(gap.get("evidence"), identifier, exit_level, report)\n            else:\n'''
    new = '''        elif state == "CLOSED" and exit_level in LEVELS:\n            source_evidence = gap.get("source_evidence")\n            exact_source_evidence(root, source_evidence, identifier, report)\n            if external_required:\n                environment_evidence(root, gap.get("evidence"), source_evidence, identifier, exit_level, report)\n            else:\n'''
    if old not in text:
        raise SystemExit("gap verifier CLOSED block drifted")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_gap_evidence_tests() -> None:
    emit("tools/tests/test_verify_owner_open_r5_gap_evidence.py", r'''
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-r5-gap-evidence.py"
BUNDLE = Path(__file__).resolve().parents[1] / "owner-open/owner_open_r5_evidence_bundle.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_r5_gap_evidence", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

SOURCE = {"level": "L1", "branch": "feature/gap", "commit": "a" * 40, "tree": "b" * 40, "workflow_run_id": 123, "successful_jobs": ["python", "rust"], "artifacts": [{"id": 456, "name": "l1-candidate", "digest": "sha256:" + "c" * 64}]}

class GapEvidenceVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "docs/status").mkdir(parents=True)
        (self.root / "tools/owner-open").mkdir(parents=True)
        shutil.copy2(BUNDLE, self.root / "tools/owner-open/owner_open_r5_evidence_bundle.py")
        self.status = {"active_plan_revision": module.EXPECTED_REVISION, "zero_gap": False, "public_release": False, "automatic_redispatch": False}
        self.gaps = {"schema": module.EXPECTED_SCHEMA, "revision": module.EXPECTED_REVISION, "generated_policy": {"automatic_redispatch": False, "public_release": False}, "priority_order": ["SOURCE-L1", "SOURCE-L2", "EXTERNAL-L4"], "gaps": [
            {"id": "SOURCE-L1", "status": "OPEN", "issue": 1, "summary": "source gap", "exit_evidence_level": "L1", "acceptance": ["source passes"]},
            {"id": "SOURCE-L2", "status": "OPEN", "issue": 2, "summary": "installed gap", "exit_evidence_level": "L2", "acceptance": ["installed passes"]},
            {"id": "EXTERNAL-L4", "status": "EXTERNAL_HOLD", "issue": 3, "summary": "device gap", "exit_evidence_level": "L4", "required_material": ["authorized device"], "acceptance": ["physical pass"]},
        ]}
        self.write()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self) -> None:
        (self.root / module.STATUS).write_text(json.dumps(self.status, indent=2) + "\n")
        (self.root / module.GAPS).write_text(json.dumps(self.gaps, indent=2) + "\n")

    def verify(self):
        self.write()
        return module.verify(self.root)

    def bundle_evidence(self, gap_id: str, level: str) -> dict:
        directory = self.root / f"evidence/owner-open-r5/{gap_id.lower()}"
        directory.mkdir(parents=True)
        raw = directory / "raw.log"
        raw.write_bytes(b"physical-observation\n")
        payload = raw.read_bytes()
        manifest = {"schema": "org.trillionnium.owner-open-r5.evidence-bundle.v1", "plan_revision": module.EXPECTED_REVISION, "kind": "real_target_evidence", "gap_ids": [gap_id], "level": level, "result": "pass", "repository": "TrillionniumFoundation/trillionnium-os", "source_commit": "a" * 40, "source_tree": "b" * 40, "workflow": {"run_id": 1, "run_attempt": 1, "job_id": 1, "name": "target", "started_at": "2026-08-30T00:10:00Z", "completed_at": "2026-08-30T00:20:00Z"}, "producer": {"login": "producer-user", "role": "capture"}, "target_attestation": {"schema": "org.trillionnium.owner-open-r5.target-attestation.v1", "environment_id": "target", "environment_class": "target", "controller": "owner", "operator": "operator-user", "issued_at": "2026-08-30T00:00:00Z", "expires_at": "2026-08-30T02:00:00Z", "source_commit": "a" * 40, "source_tree": "b" * 40, "synthetic": False, "authorized": True, "harness_path": "/opt/owner-open-r5/harnesses/test", "harness_sha256": "d" * 64, "runner_labels": ["self-hosted", "target"]}, "observations": ["target passed"], "files": [{"path": "raw.log", "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest(), "role": "raw_capture"}], "negative_claims": ["no broader claim"], "automatic_redispatch": False, "synthetic": False, "review": {"reviewer": "reviewer-user", "reviewed_at": "2026-08-30T00:30:00Z", "approved": True, "independent": True, "scope": ["all raw evidence"]}}
        manifest_path = directory / "manifest.json"
        raw_manifest = json.dumps(manifest, indent=2).encode() + b"\n"
        manifest_path.write_bytes(raw_manifest)
        return {"level": level, "source_commit": "a" * 40, "source_tree": "b" * 40, "evidence_sha256": hashlib.sha256(raw_manifest).hexdigest(), "kind": "real_target_evidence", "reviewer": "reviewer-user", "synthetic": False, "bundle_manifest": manifest_path.relative_to(self.root).as_posix()}

    def test_open_and_explicit_external_hold_pass(self) -> None:
        self.assertEqual(self.verify().errors, [])

    def test_l1_source_gap_closes_only_with_source_evidence(self) -> None:
        gap = self.gaps["gaps"][0]
        gap.update(status="CLOSED", source_evidence=dict(SOURCE))
        self.assertEqual(self.verify().errors, [])
        del gap["source_evidence"]
        self.assertTrue(any("source_evidence" in value for value in self.verify().errors))

    def test_l2_source_complete_remains_pending(self) -> None:
        gap = self.gaps["gaps"][1]
        gap.update(status="SOURCE_CLOSED_PENDING_EVIDENCE", source_evidence=dict(SOURCE), remaining_evidence=["installed target"])
        self.assertEqual(self.verify().errors, [])

    def test_source_only_cannot_close_l2(self) -> None:
        gap = self.gaps["gaps"][1]
        gap.update(status="CLOSED", source_evidence=dict(SOURCE))
        self.assertTrue(self.verify().errors)

    def test_recursive_real_environment_evidence_closes(self) -> None:
        gap = self.gaps["gaps"][1]
        gap.update(status="CLOSED", source_evidence=dict(SOURCE))
        self.write()
        gap["evidence"] = [self.bundle_evidence("SOURCE-L2", "L2")]
        self.assertEqual(self.verify().errors, [])

    def test_tampered_raw_evidence_fails(self) -> None:
        gap = self.gaps["gaps"][1]
        gap.update(status="CLOSED", source_evidence=dict(SOURCE))
        self.write()
        evidence = self.bundle_evidence("SOURCE-L2", "L2")
        gap["evidence"] = [evidence]
        (self.root / evidence["bundle_manifest"]).parent.joinpath("raw.log").write_text("tampered")
        self.assertTrue(any("bundle validation failed" in value for value in self.verify().errors))

    def test_zero_gap_requires_every_gap_closed(self) -> None:
        self.status["zero_gap"] = True
        self.assertTrue(any("every gap is CLOSED" in value for value in self.verify().errors))

    def test_priority_order_drift_fails(self) -> None:
        self.gaps["priority_order"].reverse()
        self.assertTrue(any("priority_order" in value for value in self.verify().errors))

if __name__ == "__main__":
    unittest.main()
''')


def patch_workflows() -> None:
    directory = ROOT / ".github/workflows"
    for path in sorted(directory.glob("owner-open-r5*.yml")):
        if path.name == "owner-open-r5-evidence-hardening-migration-v4.yml":
            continue
        text = path.read_text(encoding="utf-8")
        has_pr = re.search(r"(?m)^\s{2}pull_request\s*:", text) is not None
        if has_pr:
            text = text.replace("${{ github.sha }}", "${{ github.event.pull_request.head.sha || github.sha }}")
            lines = text.splitlines()
            output: list[str] = []
            index = 0
            while index < len(lines):
                line = lines[index]
                output.append(line)
                if re.match(r"^\s*- uses: actions/checkout@v4\s*$", line):
                    indent = len(line) - len(line.lstrip())
                    block_end = index + 1
                    while block_end < len(lines):
                        stripped = lines[block_end].strip()
                        current_indent = len(lines[block_end]) - len(lines[block_end].lstrip())
                        if stripped and current_indent <= indent and (stripped.startswith("-") or not lines[block_end].startswith(" " * (indent + 1))):
                            break
                        block_end += 1
                    block = lines[index + 1:block_end]
                    joined = "\n".join(block)
                    if not any(token in joined for token in ("github.event.pull_request.head.sha", "env.EXPECTED_SHA", "inputs.source_commit")):
                        with_index = next((i for i, value in enumerate(block) if value.strip() == "with:"), None)
                        if with_index is None:
                            output.extend([" " * (indent + 2) + "with:", " " * (indent + 4) + "ref: ${{ github.event.pull_request.head.sha || github.sha }}"])
                            output.extend(block)
                        else:
                            output.extend(block[:with_index + 1])
                            output.append(" " * (indent + 4) + "ref: ${{ github.event.pull_request.head.sha || github.sha }}")
                            output.extend(block[with_index + 1:])
                        index = block_end
                        continue
                index += 1
            text = "\n".join(output) + ("\n" if path.read_text(encoding="utf-8").endswith("\n") else "")
        path.write_text(text, encoding="utf-8")

    tool_loop = directory / "owner-open-r5-tool-loop.yml"
    text = tool_loop.read_text(encoding="utf-8")
    text = text.replace('assert facts.get("zero_gap") is False, facts', 'assert isinstance(facts.get("zero_gap"), bool), facts')
    text = text.replace('assert gap.get("facts", {}).get("zero_gap") is False, gap', 'assert gap.get("facts", {}).get("zero_gap") is facts.get("zero_gap"), gap')
    anchor = "            tools.tests.test_generate_owner_open_l1_candidate \\\n            -v"
    addition = "            tools.tests.test_generate_owner_open_l1_candidate \\\n            tools.tests.test_owner_open_r5_evidence_bundle \\\n            tools.tests.test_bind_owner_open_r5_source_evidence \\\n            tools.tests.test_verify_owner_open_r5_workflow_identity \\\n            -v"
    if anchor in text:
        text = text.replace(anchor, addition, 1)
    identity_anchor = "          python3 tools/verify-owner-open-r5-gap-evidence.py --json | tee owner-open-r5-gap-evidence.json\n"
    if "verify_owner_open_r5_workflow_identity.py --json" not in text and identity_anchor in text:
        text = text.replace(identity_anchor, identity_anchor + "          python3 tools/owner-open/verify_owner_open_r5_workflow_identity.py --json | tee owner-open-r5-workflow-identity.json\n", 1)
    tool_loop.write_text(text, encoding="utf-8")


def append_docs() -> None:
    plan = ROOT / "docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md"
    text = plan.read_text(encoding="utf-8")
    marker = "## Permanent external evidence program (v4)"
    if marker not in text:
        text += "\n\n" + marker + "\n\n" + (
            "All L1 source identities are now bound by the permanent exact-source binder. "
            "L1 governance and L2-L6 promotion require a recursively hashed bundle under "
            "`evidence/owner-open-r5/`, a target-local attestation, target-owned harness, "
            "independent human review and the canonical promotion tool. Capture workflows "
            "are read-only and cannot edit machine truth. L6 additionally requires an "
            "independent human release authorization.\n"
        )
        plan.write_text(text, encoding="utf-8")
    start = ROOT / "docs/OWNER_OPEN_R5_START_HERE.md"
    text = start.read_text(encoding="utf-8")
    marker = "## Permanent target-evidence entry"
    if marker not in text:
        text += "\n\n" + marker + "\n\nRead `operations/owner-open-r5-evidence-bundle-and-target-capture.md` before any L1-governance or L2-L6 promotion. Artifact upload alone is never gap closure.\n"
        start.write_text(text, encoding="utf-8")


def codeowners() -> None:
    path = ROOT / ".github/CODEOWNERS"
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    marker = "# Owner-Open R5 independent review boundary"
    if marker not in text:
        if text and not text.endswith("\n"):
            text += "\n"
        text += textwrap.dedent('''
        # Owner-Open R5 independent review boundary
        /.github/workflows/ @ProfHepta
        /docs/status/owner-open-r5-* @ProfHepta
        /evidence/owner-open-r5/ @ProfHepta
        /tools/owner-open/owner_open_r5_evidence_bundle.py @ProfHepta
        /tools/owner-open/promote_owner_open_r5_evidence.py @ProfHepta
        ''').lstrip("\n")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def main() -> None:
    apply_existing_external_semantics()
    emit("tools/owner-open/owner_open_r5_evidence_bundle.py", EVIDENCE_BUNDLE, executable=True)
    emit("tools/owner-open/promote_owner_open_r5_evidence.py", PROMOTION_TOOL, executable=True)
    emit("tools/owner-open/bind_owner_open_r5_source_evidence.py", BIND_TOOL, executable=True)
    emit("tools/owner-open/verify_owner_open_r5_workflow_identity.py", WORKFLOW_IDENTITY, executable=True)
    emit("tools/tests/test_owner_open_r5_evidence_bundle.py", TEST_BUNDLE)
    emit("tools/tests/test_bind_owner_open_r5_source_evidence.py", TEST_BIND)
    emit("tools/tests/test_verify_owner_open_r5_workflow_identity.py", TEST_WORKFLOW_IDENTITY)
    emit("docs/operations/owner-open-r5-evidence-bundle-and-target-capture.md", RUNBOOK)
    emit("docs/contracts/owner-open-r5-target-attestation-v1.template.json", json.dumps(TARGET_TEMPLATE, indent=2) + "\n")
    emit("docs/contracts/owner-open-r5-evidence-bundle-v1.template.json", json.dumps(BUNDLE_TEMPLATE, indent=2) + "\n")
    emit("docs/status/owner-open-r5-target-readiness.json", json.dumps(READINESS, indent=2) + "\n")
    emit(".github/workflows/owner-open-r5-exact-source-binder-v4.yml", BINDER_WORKFLOW)
    emit(".github/workflows/owner-open-r5-evidence-review.yml", REVIEW_WORKFLOW)
    lanes = [
        ("L1", "governance", "owner-open-r5-governance", "owner-open-r5-governance", "/opt/owner-open-r5/harnesses/governance", ["R5-GAP-GOVERNANCE-001"]),
        ("L2", "installed Root Linux", "owner-open-r5-l2-rootlinux", "owner-open-r5-l2-rootlinux", "/opt/owner-open-r5/harnesses/l2-rootlinux", ["R5-GAP-PROCESS-LIFECYCLE-001", "R5-GAP-STREAM-RECOVERY-001", "R5-GAP-BROKER-CORRELATION-001", "R5-GAP-INSTALLED-CODEX-001", "R5-GAP-ROOTLINUX-PLACEMENT-001"]),
        ("L3", "clean Android image", "owner-open-r5-l3-android", "owner-open-r5-l3-android", "/opt/owner-open-r5/harnesses/l3-android", ["R5-GAP-PRODUCT-ENTRYPOINT-001", "R5-GAP-ANDROID-GRAPH-001"]),
        ("L4", "physical device normal path", "owner-open-r5-l4-physical", "owner-open-r5-l4-physical", "/opt/owner-open-r5/harnesses/l4-physical", ["R5-GAP-PHYSICAL-ADB-001"]),
        ("L5", "destructive fault matrix", "owner-open-r5-l5-destructive", "owner-open-r5-l5-destructive", "/opt/owner-open-r5/harnesses/l5-destructive", ["R5-GAP-JOURNAL-CONVERGENCE-001", "R5-GAP-FAULT-MATRIX-001"]),
        ("L6", "signed public release", "owner-open-r5-l6-release", "owner-open-r5-l6-release", "/opt/owner-open-r5/harnesses/l6-release", ["R5-GAP-RELEASE-001"]),
    ]
    for level, title, label, environment, harness, gaps in lanes:
        emit(f".github/workflows/owner-open-r5-{level.lower()}-{label.removeprefix('owner-open-r5-')}-capture.yml", capture_workflow(level, title, label, environment, harness, gaps))
    harden_gap_verifier()
    replace_gap_evidence_tests()
    patch_workflows()
    append_docs()
    codeowners()
    for path in (
        ".github/workflows/owner-open-r5-external-closure-semantics-executor.yml",
        ".github/workflows/owner-open-r5-gap-promotion-one-shot.yml",
        ".github/workflows/owner-open-r5-gap-promotion-executor-v2.yml",
        ".github/workflows/owner-open-r5-evidence-hardening-migration-v4.yml",
        "tools/owner-open/apply_r5_evidence_hardening_v4.py",
    ):
        target = ROOT / path
        if target.exists():
            target.unlink()


if __name__ == "__main__":
    main()
