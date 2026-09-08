#!/usr/bin/env python3
"""Verify repository-wide links, authority references and product profiles."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
SCAN_ROOTS = ("docs", "apps", "crates", "tools", "packaging", "android-integration")
PROFILE_PATH = "docs/machine/product-profile-catalog.v1.json"
LIFECYCLE_PATH = "governance/component-lifecycle.v1.json"
CAPABILITY_BEGIN = "<!-- PROFILE_CAPABILITIES_BEGIN -->"
CAPABILITY_END = "<!-- PROFILE_CAPABILITIES_END -->"
CAPABILITY_RE = re.compile(r"^- `([a-z][a-z0-9]*(?:[.-][a-z0-9]+)+)`$")
MARKDOWN_LINK_RE = re.compile(
    r"(?<!!)\[[^\]\n]+\]\(\s*(?:<([^>\n]+)>|([^\s)]+))(?:\s+['\"][^\n]*['\"])?\s*\)"
)
AUTHORITY_PHRASE_RE = re.compile(
    r"\b(?:canonical (?:plan|document|status|source)|authoritative (?:plan|document|status|source)|"
    r"source of truth|current (?:plan|status|state|authority))\b",
    re.IGNORECASE,
)
URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
PROFILE_KEYS = {
    "schema", "program_revision", "default_profile", "semantic_contract",
    "component_lifecycle", "profiles",
}
PROFILE_ENTRY_KEYS = {
    "id", "status", "default", "activation_allowed", "claim_ceiling",
    "selected_modules", "selected_cargo_components", "selected_implementation_paths",
    "offered_capabilities", "retained_components", "blocked_capabilities",
    "evidence_requirements",
}
CAPABILITY_KEYS = {"id", "owner_module", "implementation_paths"}
BLOCKED_CAPABILITY_KEYS = {"id", "reason"}


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise VerificationError(f"non-finite JSON number {value}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=reject_nonfinite,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, VerificationError) as error:
        raise VerificationError(f"cannot load strict JSON {path}: {error}") from error
    require(isinstance(value, dict), f"{path} root must be an object")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    require(
        actual == expected,
        f"{label} keys drift; missing={sorted(expected-actual)}, extra={sorted(actual-expected)}",
    )


def text(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{label} must be non-empty text")
    require("\x00" not in value, f"{label} contains NUL")
    return value


def string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    require(isinstance(value, list), f"{label} must be an array")
    if not allow_empty:
        require(bool(value), f"{label} must not be empty")
    result = [text(item, f"{label}[{index}]") for index, item in enumerate(value)]
    duplicates = sorted(item for item, count in Counter(result).items() if count > 1)
    require(not duplicates, f"{label} contains duplicates: {duplicates}")
    return result


def normalized_repository_path(root: Path, value: Any, label: str) -> tuple[str, Path]:
    raw = text(value, label)
    require("\\" not in raw and "%" not in raw, f"{label} uses ambiguous encoding")
    pure = PurePosixPath(raw)
    require(not pure.is_absolute(), f"{label} must be repository-relative")
    require("" not in pure.parts and "." not in pure.parts and ".." not in pure.parts,
            f"{label} is not normalized")
    candidate = root.joinpath(*pure.parts)
    cursor = root
    for part in pure.parts:
        cursor /= part
        require(not cursor.is_symlink(), f"{label} traverses symlink {cursor}")
    resolved = candidate.resolve(strict=False)
    require(resolved.is_relative_to(root), f"{label} escapes repository")
    return pure.as_posix(), candidate


def visible_markdown(source: str) -> list[str]:
    """Return prose lines while excluding fenced/indented code and HTML comments."""
    lines: list[str] = []
    marker: str | None = None
    marker_len = 0
    in_comment = False
    for raw in source.splitlines():
        line = raw
        if in_comment:
            if "-->" in line:
                line = line.split("-->", 1)[1]
                in_comment = False
            else:
                continue
        while "<!--" in line:
            before, after = line.split("<!--", 1)
            if "-->" in after:
                after = after.split("-->", 1)[1]
                line = before + after
            else:
                line = before
                in_comment = True
                break
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if marker is None:
            match = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
            if match:
                marker = match.group(1)[0]
                marker_len = len(match.group(1))
                continue
            if indent >= 4:
                continue
            # Inline code cannot contain a Markdown link that should carry authority.
            line = re.sub(r"(`+)(?:(?!\1).)*\1", "", line)
            lines.append(line)
        else:
            close = re.match(rf"^ {{0,3}}{re.escape(marker)}{{{marker_len},}}\s*$", line)
            if close:
                marker = None
                marker_len = 0
    require(marker is None, "unterminated fenced code block in Markdown input")
    require(not in_comment, "unterminated HTML comment in Markdown input")
    return lines


def markdown_files(root: Path) -> Iterable[Path]:
    for directory in SCAN_ROOTS:
        base = root / directory
        require(base.is_dir() and not base.is_symlink(), f"scan root missing or unsafe: {directory}")
        for path in sorted(base.rglob("*.md")):
            require(not path.is_symlink(), f"Markdown source is a symlink: {path.relative_to(root)}")
            yield path


def resolve_markdown_target(root: Path, source: Path, target: str, label: str) -> str | None:
    target = target.strip()
    if not target or target.startswith("#"):
        return source.relative_to(root).as_posix()
    require("\\" not in target and "%" not in target and "\x00" not in target,
            f"{label} uses ambiguous target encoding")
    require(not URL_SCHEME_RE.match(target) and not target.startswith("//"),
            f"{label} called local resolver for an external target")
    path_text = target.split("#", 1)[0].split("?", 1)[0]
    require(bool(path_text), f"{label} has an empty local path")
    pure = PurePosixPath(path_text)
    require(not pure.is_absolute(), f"{label} must be repository-relative")
    cursor = source.parent
    for part in pure.parts:
        if part in ("", "."):
            continue
        if part == "..":
            cursor = cursor.parent
        else:
            cursor /= part
        require(cursor.resolve(strict=False).is_relative_to(root), f"{label} escapes repository")
        require(not cursor.is_symlink(), f"{label} traverses symlink {cursor}")
    resolved = cursor.resolve(strict=False)
    require(resolved.is_relative_to(root), f"{label} escapes repository")
    require(cursor.exists(), f"{label} target does not exist: {target}")
    return resolved.relative_to(root).as_posix()


def semantic_capabilities(root: Path) -> list[str]:
    source = (root / "docs/PRODUCT_SEMANTICS.md").read_text(encoding="utf-8")
    require(source.count(CAPABILITY_BEGIN) == 1 and source.count(CAPABILITY_END) == 1,
            "PRODUCT_SEMANTICS capability marker cardinality drift")
    block = source.split(CAPABILITY_BEGIN, 1)[1].split(CAPABILITY_END, 1)[0]
    values: list[str] = []
    for raw in block.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = CAPABILITY_RE.fullmatch(line)
        require(match is not None, f"invalid capability declaration: {line}")
        values.append(match.group(1))
    require(bool(values) and len(values) == len(set(values)),
            "semantic capability declarations must be unique and non-empty")
    return values


def path_covers(owner: str, selected: str) -> bool:
    return owner == selected or owner.startswith(selected + "/") or selected.startswith(owner + "/")


def verify_profiles(root: Path) -> dict[str, Any]:
    catalog = load_json(root / PROFILE_PATH)
    exact_keys(catalog, PROFILE_KEYS, "product profile catalog")
    require(catalog["schema"] == "org.trillionnium.product-profile-catalog.v1",
            "unsupported product profile schema")
    text(catalog["program_revision"], "profile program_revision")
    semantic_path, semantic_file = normalized_repository_path(root, catalog["semantic_contract"], "semantic_contract")
    lifecycle_path, lifecycle_file = normalized_repository_path(root, catalog["component_lifecycle"], "component_lifecycle")
    require(semantic_path == "docs/PRODUCT_SEMANTICS.md" and semantic_file.is_file(),
            "semantic contract must bind docs/PRODUCT_SEMANTICS.md")
    require(lifecycle_path == LIFECYCLE_PATH and lifecycle_file.is_file(),
            "component lifecycle binding drift")

    modules = load_json(root / "docs/machine/module-catalog.v1.json")
    module_map = {text(item.get("id"), "module id"): item for item in modules.get("modules", [])}
    require(len(module_map) == len(modules.get("modules", [])), "module catalog repeats an id")
    default_components = string_list(modules.get("default_source_closure"), "module default_source_closure")
    lifecycle = load_json(lifecycle_file)
    retained = string_list(
        [item.get("path") for item in lifecycle.get("non_product_members", [])],
        "lifecycle retained components",
    )

    profiles = catalog["profiles"]
    require(isinstance(profiles, list) and bool(profiles), "profiles must be a non-empty array")
    ids: list[str] = []
    default_ids: list[str] = []
    active_offered: list[str] = []
    retained_projection: list[str] = []
    for index, raw in enumerate(profiles):
        require(isinstance(raw, dict), f"profiles[{index}] must be an object")
        exact_keys(raw, PROFILE_ENTRY_KEYS, f"profiles[{index}]")
        profile_id = text(raw["id"], f"profiles[{index}].id")
        require(re.fullmatch(r"[a-z][a-z0-9-]{2,63}", profile_id) is not None,
                f"invalid profile id: {profile_id}")
        ids.append(profile_id)
        require(raw["status"] in {"ACTIVE_DEFAULT", "SEALED_OPTIONAL"},
                f"{profile_id} status is unsupported")
        require(isinstance(raw["default"], bool) and isinstance(raw["activation_allowed"], bool),
                f"{profile_id} boolean flags are malformed")
        if raw["default"]:
            default_ids.append(profile_id)
        text(raw["claim_ceiling"], f"{profile_id}.claim_ceiling")
        selected_modules = string_list(raw["selected_modules"], f"{profile_id}.selected_modules", allow_empty=True)
        selected_cargo = string_list(raw["selected_cargo_components"], f"{profile_id}.selected_cargo_components", allow_empty=True)
        selected_paths = string_list(raw["selected_implementation_paths"], f"{profile_id}.selected_implementation_paths", allow_empty=True)
        retained_components = string_list(raw["retained_components"], f"{profile_id}.retained_components", allow_empty=True)
        string_list(raw["evidence_requirements"], f"{profile_id}.evidence_requirements")
        for path_index, path in enumerate(selected_paths + retained_components):
            _, candidate = normalized_repository_path(root, path, f"{profile_id}.path[{path_index}]")
            require(candidate.exists(), f"{profile_id} path does not exist: {path}")
        for module_id in selected_modules:
            require(module_id in module_map, f"{profile_id} selects unknown module {module_id}")
            for owner_path in string_list(module_map[module_id].get("paths"), f"{module_id}.paths"):
                require(any(path_covers(owner_path, selected) for selected in selected_paths),
                        f"{profile_id} selects {module_id} without implementation path {owner_path}")

        capabilities = raw["offered_capabilities"]
        require(isinstance(capabilities, list), f"{profile_id}.offered_capabilities must be an array")
        capability_ids: list[str] = []
        for cap_index, capability in enumerate(capabilities):
            require(isinstance(capability, dict), f"{profile_id}.offered_capabilities[{cap_index}] must be an object")
            exact_keys(capability, CAPABILITY_KEYS, f"{profile_id}.offered_capabilities[{cap_index}]")
            capability_id = text(capability["id"], f"{profile_id}.capability.id")
            require(CAPABILITY_RE.fullmatch(f"- `{capability_id}`") is not None,
                    f"invalid capability id: {capability_id}")
            capability_ids.append(capability_id)
            owner_module = text(capability["owner_module"], f"{capability_id}.owner_module")
            require(owner_module in selected_modules,
                    f"{profile_id} capability {capability_id} owner is not selected")
            implementation_paths = string_list(
                capability["implementation_paths"], f"{capability_id}.implementation_paths"
            )
            for implementation in implementation_paths:
                _, candidate = normalized_repository_path(root, implementation, f"{capability_id}.implementation")
                require(candidate.exists(), f"{capability_id} implementation path does not exist")
                require(any(path_covers(implementation, selected) for selected in selected_paths),
                        f"{capability_id} implementation is outside selected graph: {implementation}")
        require(len(capability_ids) == len(set(capability_ids)),
                f"{profile_id} repeats a capability")

        blocked = raw["blocked_capabilities"]
        require(isinstance(blocked, list), f"{profile_id}.blocked_capabilities must be an array")
        blocked_ids: list[str] = []
        for blocked_index, item in enumerate(blocked):
            require(isinstance(item, dict), f"{profile_id}.blocked_capabilities[{blocked_index}] must be an object")
            exact_keys(item, BLOCKED_CAPABILITY_KEYS, f"{profile_id}.blocked_capabilities[{blocked_index}]")
            blocked_ids.append(text(item["id"], f"{profile_id}.blocked_capability.id"))
            text(item["reason"], f"{profile_id}.blocked_capability.reason")
        require(len(blocked_ids) == len(set(blocked_ids)), f"{profile_id} repeats a blocked capability")
        require(not set(blocked_ids) & set(capability_ids),
                f"{profile_id} both offers and blocks a capability")

        if raw["status"] == "ACTIVE_DEFAULT":
            require(raw["default"] and raw["activation_allowed"],
                    "ACTIVE_DEFAULT profile must be default and activatable")
            require(selected_cargo == default_components,
                    "active profile Cargo graph differs from module default_source_closure")
            require(not set(selected_cargo) & set(retained),
                    "active profile selects a sealed lifecycle component")
            require(not retained_components and not blocked,
                    "active profile cannot retain sealed components or blocked capability claims")
            active_offered = capability_ids
        else:
            require(not raw["default"] and not raw["activation_allowed"],
                    "SEALED_OPTIONAL profile cannot be default or activatable")
            require(not selected_modules and not selected_cargo and not selected_paths and not capabilities,
                    "sealed optional profile cannot select or offer active product behavior")
            require(bool(retained_components) and bool(blocked),
                    "sealed optional profile must enumerate retained components and blockers")
            retained_projection.extend(retained_components)

    require(len(ids) == len(set(ids)), "product profile ids are not unique")
    require(default_ids == [catalog["default_profile"]],
            "exactly one default profile must match default_profile")
    require(sorted(retained_projection) == sorted(retained),
            "sealed profile retained-component projection differs from component lifecycle")
    require(active_offered == semantic_capabilities(root),
            "PRODUCT_SEMANTICS current capabilities differ from active profile")
    return catalog


def verify_markdown(root: Path, profile_catalog: dict[str, Any]) -> tuple[int, int]:
    docset = load_json(root / "docs/machine/doc-set.v1.json")
    forbidden_paths = string_list(docset.get("forbidden_paths"), "doc-set.forbidden_paths")
    forbidden_markers = string_list(docset.get("forbidden_content_markers"), "doc-set.forbidden_content_markers")
    authority_targets = set(string_list(docset.get("authority_order"), "doc-set.authority_order"))
    authority_targets.update({PROFILE_PATH, LIFECYCLE_PATH, "docs/generated/CURRENT_STATE.md"})
    link_count = 0
    file_count = 0
    for path in markdown_files(root):
        file_count += 1
        relative = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8")
        lines = visible_markdown(source)
        visible = "\n".join(lines)
        if relative != "docs/machine/doc-set.v1.json":
            for marker in forbidden_markers:
                require(marker not in visible,
                        f"forbidden legacy marker {marker!r} appears in {relative}")
        for line_number, line in enumerate(lines, start=1):
            local_targets: list[str] = []
            for match in MARKDOWN_LINK_RE.finditer(line):
                target = match.group(1) or match.group(2)
                if URL_SCHEME_RE.match(target) or target.startswith("//"):
                    continue
                resolved = resolve_markdown_target(
                    root, path, target, f"{relative}: visible line {line_number} Markdown link"
                )
                assert resolved is not None
                link_count += 1
                local_targets.append(resolved)
                for forbidden in forbidden_paths:
                    require(
                        resolved != forbidden and not resolved.startswith(forbidden.rstrip("/") + "/"),
                        f"{relative}: link targets forbidden authority path {resolved}",
                    )
            if AUTHORITY_PHRASE_RE.search(line) and local_targets:
                for target in local_targets:
                    permitted = (
                        target in authority_targets
                        or target.startswith("docs/machine/")
                        or target.startswith("docs/modules/")
                        or target.startswith("docs/generated/")
                        or target.startswith("schemas/")
                    )
                    require(permitted,
                            f"{relative}: authority phrase points to unregistered target {target}")
    return file_count, link_count


def verify(root: Path = ROOT) -> dict[str, int]:
    root = root.resolve()
    catalog = verify_profiles(root)
    files, links = verify_markdown(root, catalog)
    return {"profiles": len(catalog["profiles"]), "markdown_files": files, "local_links": links}


def main() -> int:
    try:
        report = verify()
    except (VerificationError, OSError, UnicodeError, KeyError, TypeError) as error:
        print(f"repository authority verification failed: {error}", file=sys.stderr)
        return 1
    print(
        "repository authority verification passed: "
        f"profiles={report['profiles']} markdown_files={report['markdown_files']} "
        f"local_links={report['local_links']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
