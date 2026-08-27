#!/usr/bin/env python3
"""Load and apply the closed production-retirement policy.

The Android Messenger checks are deliberately scoped to the two Trillionnium
application roots.  Android framework and unrelated application uses of
``android.os.Messenger`` are not retirement findings.

The vendor scope distinguishes reachable production sources from the one
bootstrap file that performs negative cleanup of legacy archive members.  A
cleanup-only path is not an executable product edge and is never exempted from
the module, partition, or staged-root absence checks.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Iterable, Mapping


REPOSITORY = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = REPOSITORY / "packaging/production-retirement-policy-v1.json"
POLICY_SCHEMA = "org.trillionnium.production-retirement-policy.v1"
RETIRED_PROVIDER_SCOPE = "open" + "claw_android"
TOP_LEVEL_KEYS = {
    "schema",
    "android_app_source",
    "android_vendor",
    RETIRED_PROVIDER_SCOPE,
    "model_artifacts",
    "mobian",
}
SCOPE_KEYS = {
    "android_app_source": {
        "roots",
        "class_identifiers",
        "manifest_identifiers",
        "module_identifiers",
        "protocol_identifiers",
        "messenger_constructs",
        "relative_paths",
    },
    "android_vendor": {
        "roots",
        "product_graph_files",
        "source_marker_files",
        "negative_cleanup_files",
        "retired_source_paths",
        "retired_modules",
        "retired_partition_paths",
        "retired_content_markers",
    },
    RETIRED_PROVIDER_SCOPE: {"provider_tokens", "explicitly_non_denied_tokens"},
    "model_artifacts": {"weight_extensions", "native_module_basenames"},
    "mobian": {
        "retired_binary_packages",
        "retired_paths",
        "retired_content_markers",
    },
}


class RetirementPolicyError(RuntimeError):
    """The policy or a checked tree violates the closed contract."""


def _reject_duplicate_key(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RetirementPolicyError(f"duplicate policy key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> None:
    raise RetirementPolicyError(f"non-finite policy number: {value}")


def _string_list(value: Any, dotted: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise RetirementPolicyError(f"{dotted} must be a nonempty unique string list")
    return tuple(value)


def _safe_relative(value: str, dotted: str) -> None:
    path = PurePosixPath(value)
    if (
        "\x00" in value
        or path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or path.as_posix() != value
    ):
        raise RetirementPolicyError(f"{dotted} contains an unsafe relative path: {value}")


def load_policy(path: Path | None = None) -> dict[str, Any]:
    policy_path = DEFAULT_POLICY_PATH if path is None else Path(path)
    try:
        value = json.loads(
            policy_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_key,
            parse_constant=_reject_nonfinite_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RetirementPolicyError(f"cannot read retirement policy: {error}") from error
    if not isinstance(value, dict) or set(value) != TOP_LEVEL_KEYS:
        raise RetirementPolicyError("retirement policy top level is not closed")
    if value["schema"] != POLICY_SCHEMA:
        raise RetirementPolicyError("unexpected retirement policy schema")
    for scope, expected_keys in SCOPE_KEYS.items():
        section = value[scope]
        if not isinstance(section, dict) or set(section) != expected_keys:
            raise RetirementPolicyError(f"retirement policy scope is not closed: {scope}")
        for field in expected_keys:
            section[field] = list(_string_list(section[field], f"{scope}.{field}"))

    android = value["android_app_source"]
    for field in ("roots", "relative_paths"):
        for item in android[field]:
            _safe_relative(item, f"android_app_source.{field}")

    vendor = value["android_vendor"]
    for field in (
        "roots",
        "product_graph_files",
        "source_marker_files",
        "negative_cleanup_files",
        "retired_source_paths",
        "retired_partition_paths",
    ):
        for item in vendor[field]:
            _safe_relative(item, f"android_vendor.{field}")
    if not set(vendor["product_graph_files"]) <= set(vendor["source_marker_files"]):
        raise RetirementPolicyError(
            "android_vendor product graph files must be source-marker scoped"
        )
    if set(vendor["negative_cleanup_files"]) & set(vendor["source_marker_files"]):
        raise RetirementPolicyError(
            "android_vendor negative cleanup files cannot be marker-scanned"
        )
    if set(vendor["negative_cleanup_files"]) & set(vendor["retired_source_paths"]):
        raise RetirementPolicyError(
            "android_vendor negative cleanup files cannot be retired source paths"
        )
    for module in vendor["retired_modules"]:
        if not all(character.isalnum() or character in "._+-" for character in module):
            raise RetirementPolicyError(f"invalid retired Android module: {module}")
    for marker in vendor["retired_content_markers"]:
        if "\x00" in marker or "\n" in marker or "\r" in marker:
            raise RetirementPolicyError(f"invalid retired vendor marker: {marker!r}")

    retired_provider = value[RETIRED_PROVIDER_SCOPE]
    for field in ("provider_tokens", "explicitly_non_denied_tokens"):
        for token in retired_provider[field]:
            if (
                not token.isascii()
                or token != token.casefold()
                or not token.replace("-", "").isalnum()
            ):
                raise RetirementPolicyError(f"invalid retired Provider token: {token}")
    if set(retired_provider["provider_tokens"]) & set(
        retired_provider["explicitly_non_denied_tokens"]
    ):
        raise RetirementPolicyError(
            "denied and explicitly allowed retired Provider tokens overlap"
        )

    artifacts = value["model_artifacts"]
    for extension in artifacts["weight_extensions"]:
        if (
            not extension.startswith(".")
            or extension != extension.casefold()
            or not extension[1:].isalnum()
        ):
            raise RetirementPolicyError(f"invalid model weight extension: {extension}")
    for basename in artifacts["native_module_basenames"]:
        if PurePosixPath(basename).name != basename:
            raise RetirementPolicyError(f"invalid native module basename: {basename}")

    mobian = value["mobian"]
    for item in mobian["retired_paths"]:
        _safe_relative(item, "mobian.retired_paths")
    if any(marker != marker.casefold() for marker in mobian["retired_content_markers"]):
        raise RetirementPolicyError("Mobian content markers must be case-folded")

    return value


def policy_list(policy: Mapping[str, Any], scope: str, field: str) -> tuple[str, ...]:
    if scope not in SCOPE_KEYS or field not in SCOPE_KEYS[scope]:
        raise RetirementPolicyError(f"unknown policy list: {scope}.{field}")
    value = policy[scope][field]
    return _string_list(value, f"{scope}.{field}")


def retired_model_artifact_reason(
    path: str | PurePosixPath, policy: Mapping[str, Any]
) -> str | None:
    normalized = PurePosixPath(path).as_posix()
    basename = PurePosixPath(normalized).name.casefold()
    artifacts = policy["model_artifacts"]
    if any(normalized.casefold().endswith(extension) for extension in artifacts["weight_extensions"]):
        return "model weight extension"
    if basename in {item.casefold() for item in artifacts["native_module_basenames"]}:
        return "retired local-model native module"
    return None


def mobian_path_is_retired(path: str | PurePosixPath, policy: Mapping[str, Any]) -> bool:
    normalized = PurePosixPath(path).as_posix().removeprefix("./").rstrip("/")
    return normalized in set(policy["mobian"]["retired_paths"])


def android_source_violations(
    source_root: Path,
    policy: Mapping[str, Any],
    *,
    require_all_roots: bool = True,
) -> list[str]:
    """Return scoped findings beneath Trillionnium AiShell/Authority only."""

    findings: list[str] = []
    android = policy["android_app_source"]
    content_markers = tuple(
        marker.encode("utf-8")
        for field in (
            "class_identifiers",
            "manifest_identifiers",
            "module_identifiers",
            "protocol_identifiers",
            "messenger_constructs",
        )
        for marker in android[field]
    )
    retired_relative_paths = set(android["relative_paths"])
    for configured_root in android["roots"]:
        app_root = source_root / configured_root
        if not app_root.exists() and not app_root.is_symlink():
            if require_all_roots:
                findings.append(f"{configured_root}: required scoped app root is absent")
            continue
        if app_root.is_symlink() or not app_root.is_dir():
            findings.append(f"{configured_root}: scoped app root is not a real directory")
            continue
        for current, directories, files in os.walk(app_root, followlinks=False):
            current_path = Path(current)
            for name in list(directories):
                candidate = current_path / name
                if candidate.is_symlink():
                    findings.append(
                        f"{candidate.relative_to(source_root).as_posix()}: symlink in scoped app root"
                    )
                    directories.remove(name)
            for name in files:
                candidate = current_path / name
                relative_app = candidate.relative_to(app_root).as_posix()
                relative_tree = candidate.relative_to(source_root).as_posix()
                if candidate.is_symlink() or not candidate.is_file():
                    findings.append(f"{relative_tree}: non-regular scoped source entry")
                    continue
                if relative_app in retired_relative_paths:
                    findings.append(f"{relative_tree}: retired local-model source path")
                try:
                    content = candidate.read_bytes()
                except OSError as error:
                    findings.append(f"{relative_tree}: unreadable scoped source: {error}")
                    continue
                matched = next((item for item in content_markers if item in content), None)
                if matched is not None:
                    findings.append(
                        f"{relative_tree}: retired identifier {matched.decode('utf-8')!r}"
                    )
    return findings


def _vendor_roots(
    source_root: Path,
    policy: Mapping[str, Any],
    *,
    require_all_roots: bool,
) -> tuple[list[tuple[str, Path]], list[str]]:
    roots: list[tuple[str, Path]] = []
    findings: list[str] = []
    for configured_root in policy["android_vendor"]["roots"]:
        vendor_root = source_root / configured_root
        if not vendor_root.exists() and not vendor_root.is_symlink():
            if require_all_roots:
                findings.append(f"{configured_root}: required vendor root is absent")
            continue
        if vendor_root.is_symlink() or not vendor_root.is_dir():
            findings.append(f"{configured_root}: vendor root is not a real directory")
            continue
        roots.append((configured_root, vendor_root))
    return roots, findings


def _scoped_regular_file(
    vendor_root: Path,
    relative: str,
    label: str,
    findings: list[str],
) -> Path | None:
    current = vendor_root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            findings.append(f"{label}: symlink in scoped vendor path")
            return None
    if not current.is_file():
        findings.append(f"{label}: required regular file is absent")
        return None
    return current


def _make_product_modules(content: str) -> set[str]:
    modules: set[str] = set()
    lines = content.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index].split("#", 1)[0].strip()
        match = re.match(r"^PRODUCT_PACKAGES(?:_DEBUG)?\s*\+=\s*(.*)$", line)
        if match is None:
            index += 1
            continue
        payload = match.group(1).strip()
        while payload.endswith("\\"):
            payload = payload[:-1].rstrip()
            index += 1
            if index >= len(lines):
                break
            continuation = lines[index].split("#", 1)[0].strip()
            payload = f"{payload} {continuation}".strip()
        modules.update(token for token in payload.split() if token != "\\")
        index += 1
    return modules


def _blueprint_modules(content: str) -> set[str]:
    return set(
        re.findall(r'(?m)^\s*name\s*:\s*"([^"\n]+)"\s*,\s*(?://.*)?$', content)
    )


def _vendor_product_graph_violations_for_roots(
    roots: Iterable[tuple[str, Path]], policy: Mapping[str, Any]
) -> list[str]:
    findings: list[str] = []
    vendor = policy["android_vendor"]
    retired_modules = set(vendor["retired_modules"])
    for configured_root, vendor_root in roots:
        for relative in vendor["product_graph_files"]:
            label = f"{configured_root}/{relative}"
            graph = _scoped_regular_file(vendor_root, relative, label, findings)
            if graph is None:
                continue
            try:
                content = graph.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                findings.append(f"{label}: unreadable product graph: {error}")
                continue
            if graph.name == "Android.bp":
                modules = _blueprint_modules(content)
            elif graph.suffix == ".mk":
                modules = _make_product_modules(content)
            else:
                findings.append(f"{label}: unsupported product graph format")
                continue
            for module in sorted(retired_modules & modules):
                findings.append(f"{label}: retired product module {module}")
    return findings


def android_vendor_product_graph_violations(
    source_root: Path,
    policy: Mapping[str, Any],
    *,
    require_all_roots: bool = True,
) -> list[str]:
    roots, findings = _vendor_roots(
        source_root, policy, require_all_roots=require_all_roots
    )
    findings.extend(_vendor_product_graph_violations_for_roots(roots, policy))
    return findings


def android_vendor_source_violations(
    source_root: Path,
    policy: Mapping[str, Any],
    *,
    require_all_roots: bool = True,
) -> list[str]:
    """Return retired vendor source, marker, and product-graph findings."""

    roots, findings = _vendor_roots(
        source_root, policy, require_all_roots=require_all_roots
    )
    vendor = policy["android_vendor"]
    markers = tuple(marker.encode("utf-8") for marker in vendor["retired_content_markers"])
    for configured_root, vendor_root in roots:
        for relative in vendor["retired_source_paths"]:
            candidate = vendor_root / relative
            if os.path.lexists(candidate):
                findings.append(f"{configured_root}/{relative}: retired vendor source path")
        for relative in vendor["negative_cleanup_files"]:
            _scoped_regular_file(
                vendor_root,
                relative,
                f"{configured_root}/{relative}",
                findings,
            )
        for relative in vendor["source_marker_files"]:
            label = f"{configured_root}/{relative}"
            candidate = _scoped_regular_file(vendor_root, relative, label, findings)
            if candidate is None:
                continue
            try:
                content = candidate.read_bytes()
            except OSError as error:
                findings.append(f"{label}: unreadable vendor source: {error}")
                continue
            matched = next((marker for marker in markers if marker in content), None)
            if matched is not None:
                findings.append(
                    f"{label}: retired vendor marker {matched.decode('utf-8')!r}"
                )
    findings.extend(_vendor_product_graph_violations_for_roots(roots, policy))
    return findings


def staged_root_violations(
    staged_root: Path, policy: Mapping[str, Any]
) -> list[str]:
    """Return retired target-files/product-root members found in a fresh stage."""

    if staged_root.is_symlink() or not staged_root.is_dir():
        return [f"{staged_root}: staged root is not a real directory"]
    findings: list[str] = []
    for relative in policy["android_vendor"]["retired_partition_paths"]:
        path = PurePosixPath(relative)
        variants = {path.as_posix()}
        if path.parts:
            variants.add(
                PurePosixPath(path.parts[0].casefold(), *path.parts[1:]).as_posix()
            )
        for variant in sorted(variants):
            candidate = staged_root / variant
            if os.path.lexists(candidate):
                findings.append(f"{variant}: retired staged-root path")
    return findings


def _print_lines(values: Iterable[str]) -> None:
    for value in values:
        print(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate")
    get_parser = subparsers.add_parser("get")
    get_parser.add_argument("scope", choices=sorted(SCOPE_KEYS))
    get_parser.add_argument("field")
    scan_parser = subparsers.add_parser("scan-android-source")
    scan_parser.add_argument("source_root", type=Path)
    scan_parser.add_argument("--allow-missing-roots", action="store_true")
    vendor_parser = subparsers.add_parser("scan-android-vendor-source")
    vendor_parser.add_argument("source_root", type=Path)
    vendor_parser.add_argument("--allow-missing-roots", action="store_true")
    graph_parser = subparsers.add_parser("scan-android-product-graph")
    graph_parser.add_argument("source_root", type=Path)
    graph_parser.add_argument("--allow-missing-roots", action="store_true")
    staged_parser = subparsers.add_parser("scan-staged-root")
    staged_parser.add_argument("staged_root", type=Path)
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy)
        if args.command == "get":
            _print_lines(policy_list(policy, args.scope, args.field))
        elif args.command == "scan-android-source":
            findings = android_source_violations(
                args.source_root,
                policy,
                require_all_roots=not args.allow_missing_roots,
            )
            if findings:
                _print_lines(findings)
                return 1
        elif args.command == "scan-android-vendor-source":
            findings = android_vendor_source_violations(
                args.source_root,
                policy,
                require_all_roots=not args.allow_missing_roots,
            )
            if findings:
                _print_lines(findings)
                return 1
        elif args.command == "scan-android-product-graph":
            findings = android_vendor_product_graph_violations(
                args.source_root,
                policy,
                require_all_roots=not args.allow_missing_roots,
            )
            if findings:
                _print_lines(findings)
                return 1
        elif args.command == "scan-staged-root":
            findings = staged_root_violations(args.staged_root, policy)
            if findings:
                _print_lines(findings)
                return 1
    except RetirementPolicyError as error:
        print(f"production-retirement-policy: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
