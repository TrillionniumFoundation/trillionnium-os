#!/usr/bin/env python3
"Fail-closed semantic compatibility and one-shot change-review admission."
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import unicodedata
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CATALOG = "docs/machine/module-contract-catalog.v1.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
REVIEW_PACKET_PATH = re.compile(
    r"^docs/reviews/module-contracts/([0-9a-f]{64})[.]json$"
)
REVIEW_PACKET_SCHEMA = "org.trillionnium.module-contract-migration-review-packet.v1"
REVIEW_PACKET_MAX_BYTES = 65536
REVIEW_AUTHORITY = "GITHUB_PROTECTED_EXACT_HEAD_REVIEW_REQUIRED"
CLAIM_CEILING = "L1_EXECUTABLE_CONTRACT_SOURCE_ONLY_NO_TARGET_OR_RELEASE_AUTHORITY"
AUTHORIZED_MIGRATION_REVIEWERS = frozenset({"Franksudoman", "Tomasrgbsf"})
CHANGE_REVIEW_CLASSES = {"NO_CHANGE", "BREAKING_MIGRATION"}
CHANGE_REVIEW_CONTRACTS = {"api", "state", "errors"}
CHANGE_REVIEW_FAMILIES = {
    "required", "type", "enum", "default", "identity", "ordering",
    "state", "error", "other",
}
IDENTITY_FIELDS = {"schema", "module_id", "operation_id", "request_digest"}
ORDERING_FIELDS = {
    "ordering_key", "host_epoch", "writer_epoch", "fencing_token",
    "durable_sequence", "monotonic_ns",
}


def finite_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError(f"nonfinite JSON number: {raw}")
    return value


def load(raw: bytes, label: str) -> Any:
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"{label}: duplicate member {key}")
            out[key] = value
        return out

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"{label}: nonfinite {value}")
        ),
        parse_float=finite_float,
    )


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_packet(value: Any) -> bytes:
    return canonical(value) + b"\n"


def stable_file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def read_review_packet(
    root: Path,
    relative: Any,
    expected_sha256: Any,
    label: str,
) -> bytes:
    if not isinstance(relative, str):
        raise ValueError(f"{label}: review packet path is not text")
    match = REVIEW_PACKET_PATH.fullmatch(relative)
    if match is None:
        raise ValueError(f"{label}: review packet path is not canonical")
    path_digest = match.group(1)
    if expected_sha256 != path_digest:
        raise ValueError(f"{label}: review packet path and digest differ")

    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"{label}: review packet path is unsafe")
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required_flags) or not hasattr(os, "pread"):
        raise ValueError(f"{label}: review packet safe acquisition is unavailable")
    if (
        os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise ValueError(f"{label}: descriptor-relative review packet acquisition is unavailable")

    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    directory_descriptors: list[int] = []
    descriptor: int | None = None
    try:
        directory_descriptors.append(os.open(root, directory_flags))
        for part in pure.parts[:-1]:
            directory_descriptors.append(
                os.open(part, directory_flags, dir_fd=directory_descriptors[-1])
            )
        parent_descriptor = directory_descriptors[-1]
        leaf = pure.parts[-1]
        descriptor = os.open(leaf, file_flags, dir_fd=parent_descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > REVIEW_PACKET_MAX_BYTES
        ):
            raise ValueError(f"{label}: review packet is not one bounded regular file")
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(
                descriptor,
                min(65536, before.st_size - offset),
                offset,
            )
            if not chunk:
                raise ValueError(f"{label}: review packet short read")
            chunks.append(chunk)
            offset += len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        current = os.stat(leaf, dir_fd=parent_descriptor, follow_symlinks=False)
    except ValueError:
        raise
    except OSError as error:
        raise ValueError(f"{label}: review packet descriptor acquisition failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for directory_descriptor in reversed(directory_descriptors):
            os.close(directory_descriptor)

    if (
        len(raw) != before.st_size
        or len(raw) > REVIEW_PACKET_MAX_BYTES
        or stable_file_identity(after) != stable_file_identity(before)
        or stable_file_identity(current) != stable_file_identity(before)
    ):
        raise ValueError(f"{label}: review packet changed while being read")
    if sha256_bytes(raw) != expected_sha256:
        raise ValueError(f"{label}: review packet digest differs")
    return raw


def validate_review_packet(
    packet: Any,
    label: str,
    review: dict[str, Any],
    migration_sha256: str,
    rollback_sha256: str,
) -> None:
    expected = {
        "schema",
        "module_id",
        "contracts",
        "families",
        "base_catalog_sha256",
        "base_contract_sha256",
        "target_contract_sha256",
        "migration_review_sha256",
        "rollback_review_sha256",
        "reviewer",
        "review_authority",
        "approval_asserted",
        "automatic_redispatch",
        "claim_ceiling",
        "public_release",
    }
    if not isinstance(packet, dict) or set(packet) != expected:
        raise ValueError(f"{label}: review packet keys differ")
    if packet.get("schema") != REVIEW_PACKET_SCHEMA:
        raise ValueError(f"{label}: review packet schema differs")
    if packet.get("module_id") != label:
        raise ValueError(f"{label}: review packet module differs")
    for field in (
        "contracts",
        "families",
        "base_catalog_sha256",
        "base_contract_sha256",
        "target_contract_sha256",
    ):
        if packet.get(field) != review.get(field):
            raise ValueError(f"{label}: review packet {field} differs")
    if packet.get("migration_review_sha256") != migration_sha256:
        raise ValueError(f"{label}: review packet migration digest differs")
    if packet.get("rollback_review_sha256") != rollback_sha256:
        raise ValueError(f"{label}: review packet rollback digest differs")
    reviewer = packet.get("reviewer")
    if not valid_text(reviewer, 64) or reviewer not in AUTHORIZED_MIGRATION_REVIEWERS:
        raise ValueError(f"{label}: review packet reviewer is unauthorized")
    if packet.get("review_authority") != REVIEW_AUTHORITY:
        raise ValueError(f"{label}: review packet authority differs")
    if packet.get("approval_asserted") is not False:
        raise ValueError(f"{label}: source packet cannot assert independent approval")
    if packet.get("automatic_redispatch") is not False:
        raise ValueError(f"{label}: review packet enables redispatch")
    if packet.get("claim_ceiling") != CLAIM_CEILING:
        raise ValueError(f"{label}: review packet claim ceiling differs")
    if packet.get("public_release") is not False:
        raise ValueError(f"{label}: review packet authorizes release")
    if review.get("reviewer") != reviewer:
        raise ValueError(f"{label}: change review reviewer differs from packet")
    if review.get("review_authority") != REVIEW_AUTHORITY:
        raise ValueError(f"{label}: change review authority differs from packet")
    if review.get("approval_asserted") is not False:
        raise ValueError(f"{label}: change review cannot assert independent approval")


def valid_text(value: Any, maximum: int) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= maximum and not any(
        unicodedata.category(char) == "Cc" for char in value
    )


def git(args: list[str], label: str, *, root: Path = ROOT) -> bytes:
    result = subprocess.run(
        ["git", "--no-replace-objects", *args],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(f"{label}: git returned {result.returncode}: {detail}")
    return result.stdout


def resolve_commit(ref: str, *, root: Path = ROOT) -> str:
    if not isinstance(ref, str) or not ref or "\x00" in ref or "\n" in ref:
        raise ValueError("base ref is malformed")
    raw = git(
        ["rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
        "resolve base ref",
        root=root,
    )
    values = raw.decode("ascii", "strict").splitlines()
    if len(values) != 1 or SHA40.fullmatch(values[0]) is None:
        raise ValueError("base ref did not resolve to one exact commit")
    commit = values[0]
    git(
        ["merge-base", "--is-ancestor", commit, "HEAD"],
        "verify base ancestry",
        root=root,
    )
    return commit


def show(
    commit: str,
    path: str,
    *,
    allow_absent: bool = False,
    root: Path = ROOT,
) -> bytes | None:
    if SHA40.fullmatch(commit) is None:
        raise ValueError("show requires an exact commit")
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or "\n" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise ValueError(f"unsafe tree path: {path!r}")

    listing = git(
        ["ls-tree", "-z", "--full-tree", commit, "--", path],
        f"inspect {path} in verified base",
        root=root,
    )
    entries = [entry for entry in listing.split(b"\0") if entry]
    if not entries:
        if allow_absent:
            return None
        raise ValueError(f"verified base path is absent: {path}")
    if len(entries) != 1:
        raise ValueError(f"verified base path is ambiguous: {path}")

    metadata, separator, encoded_name = entries[0].partition(b"\t")
    if not separator:
        raise ValueError(f"malformed ls-tree result for {path}")
    try:
        mode, kind, object_id = metadata.decode("ascii", "strict").split(" ")
        observed_name = encoded_name.decode("utf-8", "strict")
    except (UnicodeError, ValueError) as error:
        raise ValueError(f"malformed ls-tree identity for {path}") from error
    if (
        observed_name != path
        or kind != "blob"
        or mode not in {"100644", "100755"}
        or SHA40.fullmatch(object_id) is None
    ):
        raise ValueError(f"verified base object is not one regular tracked file: {path}")
    return git(["cat-file", "blob", object_id], f"read verified base file {path}", root=root)


NON_SEMANTIC = {
    "$schema", "$id", "title", "description", "examples",
    "x-trillionnium-binding",
}
NAMED_SCHEMA_MAPS = {
    "$defs", "definitions", "properties", "patternProperties",
    "dependentSchemas",
}
SCHEMA_SINGLE = {
    "additionalProperties", "unevaluatedProperties", "propertyNames",
    "contains", "contentSchema", "if", "then", "else", "not",
    "unevaluatedItems",
}
SCHEMA_ARRAYS = {"allOf", "anyOf", "oneOf", "prefixItems"}


def normalized_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalized_data(item)
            for key, item in sorted(value.items())
        }
    if isinstance(value, list):
        return [normalized_data(item) for item in value]
    return value


def fingerprint(value: Any) -> Any:
    "Remove annotations only where the dictionary is a JSON Schema object."
    if isinstance(value, bool):
        return value
    if not isinstance(value, dict):
        return normalized_data(value)

    result = {}
    for key, item in sorted(value.items()):
        if key in NON_SEMANTIC:
            continue
        if key in NAMED_SCHEMA_MAPS and isinstance(item, dict):
            result[key] = {
                name: fingerprint(child)
                for name, child in sorted(item.items())
            }
        elif key == "dependencies" and isinstance(item, dict):
            result[key] = {
                name: (
                    fingerprint(child)
                    if isinstance(child, (dict, bool))
                    else normalized_data(child)
                )
                for name, child in sorted(item.items())
            }
        elif key in SCHEMA_SINGLE and isinstance(item, (dict, bool)):
            result[key] = fingerprint(item)
        elif key == "items":
            if isinstance(item, list):
                result[key] = [fingerprint(child) for child in item]
            elif isinstance(item, (dict, bool)):
                result[key] = fingerprint(item)
            else:
                result[key] = normalized_data(item)
        elif key in SCHEMA_ARRAYS and isinstance(item, list):
            result[key] = [fingerprint(child) for child in item]
        else:
            result[key] = normalized_data(item)
    return result


def semantic_change_families(old: Any, new: Any, kind: str) -> list[str]:
    old = fingerprint(old)
    new = fingerprint(new)
    families: set[str] = set()

    def mark(path: tuple[str, ...]) -> None:
        before = set(families)
        leaf = path[-1] if path else ""
        if leaf == "required" or "required" in path:
            families.add("required")
        if leaf == "type":
            families.add("type")
        if leaf == "enum":
            families.add("enum")
        if leaf == "default":
            families.add("default")
        if any(part in IDENTITY_FIELDS for part in path):
            families.add("identity")
        if any(part in ORDERING_FIELDS for part in path):
            families.add("ordering")
        if kind == "state":
            families.add("state")
        if kind == "errors":
            families.add("error")
        if families == before:
            families.add("other")

    def walk(left: Any, right: Any, path: tuple[str, ...]) -> None:
        if left == right:
            return
        if isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                if key not in left or key not in right:
                    mark(path + (key,))
                else:
                    walk(left[key], right[key], path + (key,))
            return
        if isinstance(left, list) and isinstance(right, list):
            if path and path[-1] in {"required", "enum"}:
                mark(path)
                return
            for index in range(max(len(left), len(right))):
                if index >= len(left) or index >= len(right):
                    mark(path + (str(index),))
                else:
                    walk(left[index], right[index], path + (str(index),))
            return
        mark(path)

    walk(old, new, ())
    return sorted(families)


def validate_change_review(
    compatibility: Any,
    label: str,
    *,
    root: Path,
) -> dict[str, Any]:
    if not isinstance(compatibility, dict):
        raise ValueError(f"{label}: compatibility metadata is not an object")
    if compatibility.get("introduction_review_class") != "INITIAL_V1":
        raise ValueError(f"{label}: introduction provenance differs")
    migration = compatibility.get("migration_review")
    rollback = compatibility.get("rollback_review")
    if not isinstance(migration, dict) or not migration:
        raise ValueError(f"{label}: migration metadata is missing")
    if not isinstance(rollback, dict) or not rollback or rollback.get("fail_closed") is not True:
        raise ValueError(f"{label}: rollback metadata is not fail-closed")

    migration_sha256 = sha256_bytes(canonical(migration))
    rollback_sha256 = sha256_bytes(canonical(rollback))
    review = compatibility.get("change_review")
    expected = {
        "class",
        "contracts",
        "families",
        "review_packet",
        "review_packet_sha256",
        "reviewer",
        "review_authority",
        "approval_asserted",
        "migration_review_sha256",
        "rollback_review_sha256",
        "base_catalog_sha256",
        "base_contract_sha256",
        "target_contract_sha256",
    }
    if not isinstance(review, dict) or set(review) != expected:
        raise ValueError(f"{label}: change review keys differ")
    review_class = review.get("class")
    if review_class not in CHANGE_REVIEW_CLASSES:
        raise ValueError(f"{label}: change review class is unknown")
    contracts = review.get("contracts")
    families = review.get("families")
    if (
        not isinstance(contracts, list)
        or contracts != sorted(set(contracts))
        or not set(contracts) <= CHANGE_REVIEW_CONTRACTS
    ):
        raise ValueError(f"{label}: change review contract scope is malformed")
    if (
        not isinstance(families, list)
        or families != sorted(set(families))
        or not set(families) <= CHANGE_REVIEW_FAMILIES
    ):
        raise ValueError(f"{label}: change review families are malformed")
    if review.get("migration_review_sha256") != migration_sha256:
        raise ValueError(f"{label}: migration metadata digest differs")
    if review.get("rollback_review_sha256") != rollback_sha256:
        raise ValueError(f"{label}: rollback metadata digest differs")
    if review.get("approval_asserted") is not False:
        raise ValueError(f"{label}: source metadata cannot assert independent approval")

    if review_class == "NO_CHANGE":
        if contracts or families:
            raise ValueError(f"{label}: NO_CHANGE carries a change scope")
        if not (
            review.get("review_packet") is None
            and review.get("review_packet_sha256") is None
            and review.get("reviewer") is None
            and review.get("review_authority") is None
            and review.get("base_catalog_sha256") is None
            and review.get("base_contract_sha256") == {}
            and review.get("target_contract_sha256") == {}
        ):
            raise ValueError(f"{label}: NO_CHANGE carries reusable review authority")
    else:
        if not contracts or not families:
            raise ValueError(f"{label}: breaking review has no exact scope")
        if not isinstance(review.get("base_catalog_sha256"), str) or SHA64.fullmatch(
            review["base_catalog_sha256"]
        ) is None:
            raise ValueError(f"{label}: base catalog digest is invalid")
        for field in ("base_contract_sha256", "target_contract_sha256"):
            values = review.get(field)
            if not isinstance(values, dict) or set(values) != set(contracts):
                raise ValueError(f"{label}: {field} scope differs")
            if not all(
                isinstance(value, str) and SHA64.fullmatch(value)
                for value in values.values()
            ):
                raise ValueError(f"{label}: {field} digest is invalid")
        packet_raw = read_review_packet(
            root,
            review.get("review_packet"),
            review.get("review_packet_sha256"),
            label,
        )
        packet = load(packet_raw, f"{label} review packet")
        if packet_raw != canonical_packet(packet):
            raise ValueError(f"{label}: review packet is not canonical")
        validate_review_packet(
            packet,
            label,
            review,
            migration_sha256,
            rollback_sha256,
        )
    return review



def evaluate(root: Path, base_ref: str) -> dict[str, Any]:
    current = load((root / CATALOG).read_bytes(), CATALOG)
    base_commit = resolve_commit(base_ref, root=root)
    old_raw = show(base_commit, CATALOG, allow_absent=True, root=root)
    if old_raw is None:
        for module in current["modules"]:
            compatibility = load(
                (root / module["artifacts"]["compatibility"]).read_bytes(),
                module["module_id"],
            )
            review = validate_change_review(compatibility, module["module_id"], root=root)
            if review["class"] != "NO_CHANGE":
                raise ValueError("initial introduction carries a reusable change class")
        return {
            "base_commit": base_commit,
            "modules": current["module_count"],
            "public_release": False,
            "result": "PASS_INITIAL_V1",
        }

    old = load(old_raw, CATALOG)
    old_by = {item["module_id"]: item for item in old["modules"]}
    current_by = {item["module_id"]: item for item in current["modules"]}
    if set(old_by) != set(current_by):
        raise ValueError("module set changed without a separately reviewed catalog migration")

    changed: list[str] = []
    for module_id in sorted(current_by):
        current_record = current_by[module_id]
        old_record = old_by[module_id]
        compatibility = load(
            (root / current_record["artifacts"]["compatibility"]).read_bytes(),
            module_id,
        )
        old_compatibility_raw = show(
            base_commit, old_record["artifacts"]["compatibility"], root=root
        )
        old_compatibility = load(old_compatibility_raw, f"base {module_id}")
        review = validate_change_review(compatibility, module_id, root=root)
        validate_change_review(old_compatibility, f"base {module_id}", root=root)
        if compatibility["introduction_review_class"] != old_compatibility[
            "introduction_review_class"
        ]:
            raise ValueError(f"{module_id}: introduction provenance changed")

        changed_kinds: list[str] = []
        detected_families: set[str] = set()
        old_contract_raw: dict[str, bytes] = {}
        new_contract_raw: dict[str, bytes] = {}
        for kind in ("api", "state", "errors"):
            new_path = current_record["artifacts"][kind]
            old_path = old_record["artifacts"][kind]
            old_schema_raw = show(base_commit, old_path, root=root)
            new_schema_raw = (root / new_path).read_bytes()
            old_contract_raw[kind] = old_schema_raw
            new_contract_raw[kind] = new_schema_raw
            old_schema = load(old_schema_raw, old_path)
            new_schema = load(new_schema_raw, new_path)
            if fingerprint(old_schema) != fingerprint(new_schema):
                changed_kinds.append(kind)
                detected_families.update(
                    semantic_change_families(old_schema, new_schema, kind)
                )
                changed.append(f"{module_id}:{kind}")

        if not changed_kinds:
            if review["class"] != "NO_CHANGE":
                raise ValueError(f"{module_id}: stale breaking review was not reset")
            continue

        if review["class"] != "BREAKING_MIGRATION":
            raise ValueError(
                f"{module_id}: semantic schema drift lacks BREAKING_MIGRATION review"
            )
        if review["contracts"] != sorted(changed_kinds):
            raise ValueError(f"{module_id}: reviewed contract scope differs from detected drift")
        if review["families"] != sorted(detected_families):
            raise ValueError(f"{module_id}: reviewed change families differ from detected drift")
        if review["base_catalog_sha256"] != sha256_bytes(old_raw):
            raise ValueError(f"{module_id}: review does not bind the base catalog")
        for kind in changed_kinds:
            if review["base_contract_sha256"][kind] != sha256_bytes(
                old_contract_raw[kind]
            ):
                raise ValueError(f"{module_id}: review does not bind base {kind}")
            if review["target_contract_sha256"][kind] != sha256_bytes(
                new_contract_raw[kind]
            ):
                raise ValueError(f"{module_id}: review does not bind target {kind}")

    return {
        "base_commit": base_commit,
        "public_release": False,
        "result": "PASS",
        "semantic_changes": changed,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-ref", required=True)
    args = parser.parse_args()
    print(json.dumps(evaluate(ROOT, args.base_ref), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        print(f"module-contract compatibility failed: {error}", file=sys.stderr)
        raise SystemExit(2)
