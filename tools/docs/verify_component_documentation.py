#!/usr/bin/env python3
"""Verify component-local documentation for the complete root Cargo workspace.

This gate closes repository inventory/documentation defects only.  It does not
promote installed-target, Android-image, device, fault or release evidence.
"""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any


LIFECYCLE_KEYS = {
    "schema",
    "program_revision",
    "authority",
    "rule",
    "non_product_members",
}
LIFECYCLE_ENTRY_KEYS = {"path", "classification", "replacement", "reason"}


class VerificationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise VerificationError(f"non-finite JSON number {value}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise VerificationError(f"cannot read strict JSON {path}: {error}") from error
    require(isinstance(value, dict), f"{path} root must be an object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    require(
        actual == expected,
        f"{label} key drift; missing={sorted(expected-actual)}, "
        f"extra={sorted(actual-expected)}",
    )


def text(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and bool(value.strip()),
        f"{label} must be non-empty text",
    )
    require("\x00" not in value, f"{label} contains NUL")
    return value


def strings(value: Any, label: str, *, empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    require(empty or bool(value), f"{label} must not be empty")
    result = [text(item, f"{label}[{index}]") for index, item in enumerate(value)]
    duplicates = [item for item, count in Counter(result).items() if count > 1]
    require(not duplicates, f"{label} duplicates: {duplicates}")
    return result


def normalized_path(root: Path, value: Any, label: str) -> tuple[str, Path]:
    raw = text(value, label)
    pure = PurePosixPath(raw)
    require(not pure.is_absolute(), f"{label} must be relative")
    require(raw == pure.as_posix() and "\\" not in raw, f"{label} is not normalized")
    require("." not in pure.parts and ".." not in pure.parts, f"{label} traverses")
    candidate = root.joinpath(*pure.parts)
    resolved = candidate.resolve(strict=False)
    require(resolved.is_relative_to(root.resolve()), f"{label} escapes repository")
    cursor = candidate
    while cursor != root and cursor.exists():
        require(not cursor.is_symlink(), f"{label} traverses symlink {cursor}")
        cursor = cursor.parent
    return raw, candidate


def parse_workspace(root: Path) -> tuple[list[str], list[str]]:
    try:
        cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"Cargo.toml cannot be parsed: {error}") from error
    workspace = cargo.get("workspace")
    require(isinstance(workspace, dict), "Cargo.toml [workspace] is missing")
    members = strings(workspace.get("members"), "workspace.members")
    defaults = strings(workspace.get("default-members"), "workspace.default-members")
    require(set(defaults) <= set(members), "default-members are not workspace members")
    return members, defaults


def package_name(manifest: Path, label: str) -> str:
    try:
        value = tomllib.loads(manifest.read_text(encoding="utf-8"))
        package = value["package"]["name"]
    except (OSError, UnicodeError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        raise VerificationError(f"{label} package manifest cannot be parsed: {error}") from error
    return text(package, f"{label}.package.name")


def verify(root: Path) -> None:
    root = root.resolve()
    members, defaults = parse_workspace(root)
    catalog = load_json(root / "docs/machine/module-catalog.v1.json")
    catalog_defaults = strings(
        catalog.get("default_source_closure"),
        "module-catalog.default_source_closure",
    )
    require(
        defaults == catalog_defaults,
        "Cargo default-members drift from module catalog default_source_closure",
    )

    lifecycle = load_json(root / "governance/component-lifecycle.v1.json")
    exact_keys(lifecycle, LIFECYCLE_KEYS, "component lifecycle")
    require(
        lifecycle["schema"] == "org.trillionnium.component-lifecycle.v1",
        "unsupported component lifecycle schema",
    )
    require(
        lifecycle["authority"] == "docs/machine/module-catalog.v1.json",
        "component lifecycle authority drifted",
    )
    text(lifecycle["program_revision"], "component lifecycle program_revision")
    text(lifecycle["rule"], "component lifecycle rule")

    entries = lifecycle["non_product_members"]
    require(isinstance(entries, list), "non_product_members must be an array")
    non_product: list[str] = []
    member_set = set(members)
    default_set = set(defaults)
    for index, entry in enumerate(entries):
        require(
            isinstance(entry, dict),
            f"non_product_members[{index}] must be an object",
        )
        exact_keys(entry, LIFECYCLE_ENTRY_KEYS, f"non_product_members[{index}]")
        path, _ = normalized_path(
            root, entry["path"], f"non_product_members[{index}].path"
        )
        non_product.append(path)
        require(path in member_set, f"lifecycle path is not a workspace member: {path}")
        require(path not in default_set, f"default member is classified non-product: {path}")
        classification = text(entry["classification"], f"{path}.classification")
        require(
            classification.startswith("sealed_"),
            f"non-product classification is not sealed: {path}",
        )
        reason = text(entry["reason"], f"{path}.reason")
        require(len(reason) >= 32, f"non-product reason is too short: {path}")
        for replacement in strings(entry["replacement"], f"{path}.replacement", empty=True):
            _, target = normalized_path(root, replacement, f"{path}.replacement")
            require(target.exists(), f"replacement path does not exist: {replacement}")

    expected_non_product = [member for member in members if member not in default_set]
    require(
        non_product == expected_non_product,
        "component lifecycle must exactly follow the non-default workspace member order",
    )

    seen_packages: list[str] = []
    for index, member in enumerate(members):
        member_text, directory = normalized_path(
            root, member, f"workspace.members[{index}]"
        )
        require(directory.is_dir(), f"workspace member directory missing: {member_text}")
        manifest = directory / "Cargo.toml"
        require(
            manifest.is_file() and not manifest.is_symlink(),
            f"workspace member manifest missing: {member_text}",
        )
        package = package_name(manifest, member_text)
        seen_packages.append(package)

        readme = directory / "README.md"
        require(
            readme.is_file() and not readme.is_symlink(),
            f"workspace member README missing: {member_text}",
        )
        raw = readme.read_bytes()
        require(len(raw) >= 256, f"workspace member README truncated: {member_text}")
        require(len(raw) <= 1 << 20, f"workspace member README is unbounded: {member_text}")
        try:
            prose = raw.decode("utf-8")
        except UnicodeError as error:
            raise VerificationError(
                f"workspace member README is not UTF-8: {member_text}: {error}"
            ) from error
        require(
            package in prose,
            f"workspace member README does not identify package {package}: {member_text}",
        )

    duplicates = [
        package for package, count in Counter(seen_packages).items() if count > 1
    ]
    require(not duplicates, f"duplicate workspace package names: {duplicates}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    args = parser.parse_args(argv)
    try:
        verify(args.root)
    except VerificationError as error:
        print(f"component documentation verification failed: {error}", file=sys.stderr)
        return 1
    print("component documentation verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
