#!/usr/bin/env python3
"""Verify component-local documentation for the complete root Cargo workspace.

This gate closes repository inventory/documentation defects only. It does not
promote installed-target, Android-image, device, fault or release evidence.
"""
from __future__ import annotations

import argparse
import json
import re
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
MODULE_ID = re.compile(r"^MOD-[A-Z0-9][A-Z0-9-]{0,126}$")
MODULE_CONTRACT_PATH = re.compile(
    r"^docs/modules/(MOD-[A-Z0-9][A-Z0-9-]{0,126})\.md$"
)
MARKDOWN_LINK = re.compile(
    r"(?<!!)(?<!\\)\[[^\]\n]*\]\(\s*(?:<(?P<angle>[^<>\n]+)>|"
    r"(?P<plain>[^()\s]+))\s*\)"
)
FENCE_OPEN = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,})(?P<info>.*)$")
SHELL_FENCE_LANGUAGES = {"sh", "bash", "shell", "zsh", "console"}


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
    cursor = candidate
    while cursor != root:
        require(not cursor.is_symlink(), f"{label} traverses symlink {cursor}")
        cursor = cursor.parent

    resolved = candidate.resolve(strict=False)
    require(resolved.is_relative_to(root), f"{label} escapes repository")
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


def strip_html_comments(source: str, label: str) -> str:
    """Remove HTML comments while preserving line and byte positions."""
    characters = list(source)
    cursor = 0
    while True:
        start = source.find("<!--", cursor)
        if start < 0:
            break
        end = source.find("-->", start + 4)
        require(end >= 0, f"{label} has an unterminated HTML comment")
        for index in range(start, end + 3):
            if characters[index] not in "\r\n":
                characters[index] = " "
        cursor = end + 3
    return "".join(characters)


def _find_exact_backtick_run(line: str, marker: str, start: int = 0) -> int:
    """Find a maximal backtick run whose length exactly matches marker."""
    cursor = start
    marker_length = len(marker)
    while cursor < len(line):
        candidate = line.find(marker, cursor)
        if candidate < 0:
            return -1
        run_start = candidate
        while run_start > 0 and line[run_start - 1] == "`":
            run_start -= 1
        run_end = candidate + marker_length
        while run_end < len(line) and line[run_end] == "`":
            run_end += 1
        if candidate == run_start and run_end - run_start == marker_length:
            return candidate
        cursor = run_end
    return -1


def strip_inline_code(line: str, open_marker: str | None) -> tuple[str, str | None]:
    """Hide inline code spans, retaining an exact marker across physical lines."""
    characters = list(line)
    cursor = 0
    marker = open_marker

    if marker is not None:
        close = _find_exact_backtick_run(line, marker)
        span_end = len(line) if close < 0 else close + len(marker)
        for index in range(span_end):
            characters[index] = " "
        if close < 0:
            return "".join(characters), marker
        cursor = span_end
        marker = None

    while cursor < len(line):
        if line[cursor] != "`":
            cursor += 1
            continue
        run_end = cursor
        while run_end < len(line) and line[run_end] == "`":
            run_end += 1
        marker = line[cursor:run_end]
        close = _find_exact_backtick_run(line, marker, run_end)
        span_end = len(line) if close < 0 else close + len(marker)
        for index in range(cursor, span_end):
            characters[index] = " "
        if close < 0:
            return "".join(characters), marker
        cursor = span_end
        marker = None
    return "".join(characters), None

def indentation_columns(line: str) -> int:
    """Return CommonMark-style leading indentation columns with tab stops."""
    columns = 0
    for character in line:
        if character == " ":
            columns += 1
        elif character == "\t":
            columns += 4 - columns % 4
        else:
            break
    return columns


def markdown_surfaces(prose: str, label: str, *, preserve_inline: bool = False) -> tuple[str, set[str], str]:
    """Return rendered prose, exact shell-fence lines, and comment-free source."""
    source = strip_html_comments(prose, label)
    visible_lines: list[str] = []
    shell_lines: set[str] = set()
    marker_character: str | None = None
    marker_length = 0
    language = ""
    inline_marker: str | None = None

    for line in source.splitlines():
        lowered = line.lstrip().lower()
        if marker_character is None:
            # Accepted Markdown subset: no raw HTML block openers outside
            # fenced code. This deliberately rejects every element tag,
            # processing instruction, declaration and CDATA opener at the start
            # of a physical line, including custom tags and closing tags. We do
            # not approximate CommonMark's seven HTML-block termination rules.
            # Complete HTML comments were removed above; ordinary inline HTML
            # after prose and autolinks remain supported.
            require(
                re.match(r"^<(?:/?[a-z][a-z0-9-]*(?:\s|/|>|$)|!|\?)", lowered) is None,
                f"{label} contains an unsupported raw HTML block; use fenced examples or plain Markdown",
            )
            if inline_marker is not None:
                visible, inline_marker = strip_inline_code(line, inline_marker)
                visible_lines.append(visible)
                continue

            match = FENCE_OPEN.fullmatch(line)
            if match is not None:
                marker = match.group("marker")
                marker_character = marker[0]
                marker_length = len(marker)
                info = match.group("info").strip()
                language = info.split(None, 1)[0].lower() if info else ""
                continue

            # Four-column indentation is Markdown code, including mixed tabs.
            if indentation_columns(line) >= 4:
                continue
            visible, inline_marker = strip_inline_code(line, None)
            visible_lines.append(line if preserve_inline and inline_marker is None else visible)
            continue

        stripped = line.lstrip(" \t")
        indentation = indentation_columns(line)
        run_length = 0
        while run_length < len(stripped) and stripped[run_length] == marker_character:
            run_length += 1
        if (
            indentation <= 3
            and run_length >= marker_length
            and not stripped[run_length:].strip()
        ):
            marker_character = None
            marker_length = 0
            language = ""
            continue
        if language in SHELL_FENCE_LANGUAGES:
            shell_lines.add(line.strip())

    require(marker_character is None, f"{label} has an unterminated fenced code block")
    return "\n".join(visible_lines), shell_lines, source


def module_contract_links(root: Path, readme: Path, visible_prose: str) -> set[str]:
    """Resolve visible Markdown module links to exact repository contract files."""
    links: set[str] = set()
    for line_number, line in enumerate(visible_prose.splitlines(), start=1):
        for match in MARKDOWN_LINK.finditer(line):
            target = match.group("angle") or match.group("plain")
            if "MOD-" not in target and "MOD-" not in match.group(0):
                continue
            label = f"{readme}: line {line_number} module contract link"
            require("\\" not in target, f"{label} uses a backslash")
            require("%" not in target, f"{label} uses percent-encoding")
            require("?" not in target and "#" not in target, f"{label} has query or fragment")
            require("://" not in target, f"{label} is not repository-local")
            pure = PurePosixPath(target)
            require(not pure.is_absolute(), f"{label} must be relative")

            cursor = readme.parent
            for part in pure.parts:
                if part in ("", "."):
                    continue
                if part == "..":
                    cursor = cursor.parent
                else:
                    cursor /= part
                    require(not cursor.is_symlink(), f"{label} traverses symlink {cursor}")
                require(cursor.is_relative_to(root), f"{label} escapes repository")
            candidate = cursor.resolve(strict=False)
            require(candidate.is_relative_to(root), f"{label} escapes repository")
            relative = candidate.relative_to(root).as_posix()
            require(
                MODULE_CONTRACT_PATH.fullmatch(relative) is not None,
                f"{label} does not resolve to a canonical docs/modules/MOD-*.md file: {target}",
            )

            cursor = root
            for part in PurePosixPath(relative).parts:
                cursor /= part
                require(not cursor.is_symlink(), f"{label} traverses symlink {cursor}")
            require(candidate.is_file(), f"{label} target does not exist: {relative}")
            links.add(relative)
    return links


def module_contracts(
    root: Path,
    catalog: dict[str, Any],
    members: list[str],
) -> tuple[set[str], dict[str, list[str]]]:
    modules = catalog.get("modules")
    require(
        isinstance(modules, list) and bool(modules),
        "module-catalog.modules must be a non-empty array",
    )

    member_parts = {member: PurePosixPath(member) for member in members}
    physical: dict[str, set[str]] = {member: set() for member in members}
    valid_contracts: set[str] = set()
    seen_ids: set[str] = set()

    for index, module in enumerate(modules):
        require(isinstance(module, dict), f"module-catalog.modules[{index}] must be an object")
        module_id = text(module.get("id"), f"module-catalog.modules[{index}].id")
        require(MODULE_ID.fullmatch(module_id) is not None, f"invalid module id: {module_id}")
        require(module_id not in seen_ids, f"duplicate module id: {module_id}")
        seen_ids.add(module_id)

        contract_text = f"docs/modules/{module_id}.md"
        _, contract = normalized_path(root, contract_text, f"{module_id}.contract")
        require(
            contract.is_file() and not contract.is_symlink(),
            f"module contract missing: {contract_text}",
        )
        valid_contracts.add(contract_text)

        for path_index, raw_path in enumerate(strings(module.get("paths"), f"{module_id}.paths")):
            module_path_text, source_path = normalized_path(
                root,
                raw_path,
                f"{module_id}.paths[{path_index}]",
            )
            require(source_path.exists(), f"{module_id} source ownership path does not exist: {module_path_text}")
            module_path = PurePosixPath(module_path_text)
            for member, member_path in member_parts.items():
                if module_path == member_path or member_path in module_path.parents:
                    physical[member].add(contract_text)

    return valid_contracts, {
        member: sorted(contracts) for member, contracts in physical.items()
    }


def dependency_projection(
    root: Path,
    catalog: dict[str, Any],
    members: list[str],
    defaults: list[str],
    physical_contracts: dict[str, list[str]],
    *,
    workspace_root: Path | None = None,
) -> dict[str, list[str]]:
    """Validate every declared local Cargo edge, including optional/target/dev edges.

    Manifests are parsed as data without build execution or network access. This
    conservative declaration graph is not a resolved target/feature graph. A
    multi-module composition component declares each external edge on at least
    one owner; no per-Rust-file dependency is inferred from Cargo metadata.
    """
    workspace_root = root if workspace_root is None else workspace_root
    workspace = tomllib.loads((workspace_root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    inherited = workspace.get("dependencies", {})
    by_path = {(root / member).resolve(): member for member in members}
    selected = set(defaults)
    module_by_id = {module["id"]: module for module in catalog["modules"]}
    owners = {
        member: {PurePosixPath(contract).stem for contract in physical_contracts[member]}
        for member in members
    }
    result: dict[str, list[str]] = {}
    for member in defaults:
        require(bool(owners[member]), f"active workspace member has no module contract mapping: {member}")
        manifest = tomllib.loads((root / member / "Cargo.toml").read_text(encoding="utf-8"))
        tables = [("package", manifest)]
        targets = manifest.get("target", {})
        require(isinstance(targets, dict), f"{member}.target must be a table")
        tables.extend((f"target.{name}", value) for name, value in targets.items())
        local_edges: set[str] = set()
        for scope, table in tables:
            require(isinstance(table, dict), f"{member}.{scope} must be a table")
            for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
                dependencies = table.get(kind, {})
                require(isinstance(dependencies, dict), f"{member}.{kind} must be a table")
                for alias, specification in dependencies.items():
                    if not isinstance(specification, dict):
                        continue
                    origin = root / member
                    if specification.get("workspace") is True:
                        require(alias in inherited, f"{member} inherits unknown dependency {alias}")
                        specification = inherited[alias]
                        origin = workspace_root
                    if not isinstance(specification, dict) or "path" not in specification:
                        continue
                    local = specification["path"]
                    require(isinstance(local, str) and local and not Path(local).is_absolute(),
                            f"{member} local dependency {alias} has an unsafe path")
                    lexical = origin / local
                    for candidate in (lexical, *lexical.parents):
                        require(not candidate.is_symlink(), f"{member} dependency {alias} traverses symlink")
                        if candidate == root:
                            break
                    target = lexical.resolve()
                    require(target.is_relative_to(root), f"{member} dependency {alias} escapes repository")
                    require(target in by_path, f"{member} local dependency {alias} is outside declared workspace")
                    target_member = by_path[target]
                    require(target_member in selected,
                            f"{member} dependency {alias} enters sealed non-product component {target_member}")
                    require(bool(owners[target_member]), f"local dependency has no module owner: {target_member}")
                    expected_package = specification.get("package", alias)
                    actual_package = package_name(target / "Cargo.toml", target_member)
                    require(expected_package == actual_package,
                            f"{member} dependency alias {alias} disagrees with target package {actual_package}")
                    local_edges.add(target_member)
                    for target_module in owners[target_member] - owners[member]:
                        require(any(target_module in module_by_id[owner].get("dependencies", [])
                                    for owner in owners[member]),
                                f"undeclared module dependency: {member} -> {target_member} ({target_module})")
        result[member] = sorted(local_edges)
    return result



def verify_source_coverage(root: Path, catalog: dict[str, Any], source_roots: list[str]) -> None:
    """Reverse-check source files in the explicitly selected component/support trees."""
    owned = [(module["id"], root / path) for module in catalog["modules"] for path in module["paths"]]
    suffixes = {".rs", ".py", ".sh", ".bp", ".mk", ".rc", ".te"}
    for relative in source_roots:
        directory = root / relative
        require(directory.is_dir(), f"source inventory root missing: {relative}")
        for path in sorted(directory.rglob("*")):
            if "target" in path.relative_to(directory).parts or "__pycache__" in path.parts:
                continue
            if not path.is_file() or path.suffix not in suffixes:
                continue
            name = path.relative_to(root).as_posix()
            normalized_path(root, name, "source inventory file")
            matches = {module for module, parent in owned if path == parent or path.is_relative_to(parent)}
            require(len(matches) == 1, f"source file needs exactly one module owner: {name}; owners={sorted(matches)}")

def verify_planned_workspace(root: Path, catalog: dict[str, Any]) -> None:
    planned_paths = [path for module in catalog["modules"] for path in module["paths"]
                     if path.startswith("planned/")]
    if not planned_paths:
        return
    workspace_root = root / "planned"
    manifest = workspace_root / "Cargo.toml"
    require(manifest.is_file() and not manifest.is_symlink(), "planned workspace manifest missing or symlinked")
    workspace = tomllib.loads(manifest.read_text(encoding="utf-8"))["workspace"]
    members = ["planned/" + member for member in strings(workspace.get("members"), "planned.members")]
    for member in members:
        normalized_path(root, member, "planned member")
    _, physical = module_contracts(root, catalog, members)
    for member in members:
        directory = root / member
        readme = directory / "README.md"
        require(readme.is_file() and not readme.is_symlink(), f"planned component README missing: {member}")
        raw = readme.read_bytes()
        require(256 <= len(raw) <= 1 << 20, f"planned component README size invalid: {member}")
        visible, shell_lines, _ = markdown_surfaces(raw.decode("utf-8"), member)
        package = package_name(directory / "Cargo.toml", member)
        command = f"cargo test --locked --manifest-path planned/Cargo.toml -p {package} --all-targets"
        require(command in shell_lines, f"planned component missing exact local test command: {member}")
        require(bool(physical[member]), f"planned component has no module owner: {member}")
        linked = module_contract_links(root, readme, visible)
        require(set(physical[member]) <= linked, f"planned component missing module contract link: {member}")
    dependency_projection(root, catalog, members, members, physical, workspace_root=workspace_root)
    verify_source_coverage(root, catalog, members)


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
    valid_contracts, physical_contracts_by_member = module_contracts(
        root, catalog, members
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
    readme_errors: list[str] = []
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

        try:
            visible_prose, shell_lines, comment_free_source = markdown_surfaces(
                prose,
                f"workspace member README {member_text}",
            )
        except VerificationError as error:
            readme_errors.append(str(error))
            visible_prose, shell_lines, comment_free_source = "", set(), ""

        if package not in comment_free_source:
            readme_errors.append(
                f"workspace member README does not identify package {package}: {member_text}"
            )

        command = f"cargo test --locked -p {package} --all-targets"
        if command not in shell_lines:
            readme_errors.append(
                "workspace member README missing exact local test command "
                f"{command!r} in a visible shell code block: {member_text}"
            )

        if member_text in default_set:
            try:
                linked_contracts = sorted(
                    module_contract_links(root, readme, visible_prose)
                )
            except VerificationError as error:
                readme_errors.append(str(error))
                linked_contracts = []
            physical_contracts = physical_contracts_by_member[member_text]
            for contract in physical_contracts:
                if contract not in linked_contracts:
                    readme_errors.append(
                        "active workspace member README missing module contract link "
                        f"{contract}: {member_text}"
                    )
            if not physical_contracts:
                readme_errors.append(
                    f"active workspace member has no module contract mapping: {member_text}"
                )
            unknown_contracts = [
                contract
                for contract in linked_contracts
                if contract not in valid_contracts
            ]
            if unknown_contracts:
                readme_errors.append(
                    "active workspace member README has unknown module contract links "
                    f"{unknown_contracts}: {member_text}"
                )

    duplicates = [
        package for package, count in Counter(seen_packages).items() if count > 1
    ]
    require(not duplicates, f"duplicate workspace package names: {duplicates}")
    require(
        not readme_errors,
        "component README contract violations:\n- " + "\n- ".join(readme_errors),
    )

    dependency_projection(root, catalog, members, defaults, physical_contracts_by_member)
    verify_source_coverage(root, catalog, defaults)
    support_roots = [
        "tools/owner-open", "tools/evidence", "tools/build", "packaging/root-linux",
        "packaging/owner-open-adb", "android-integration/working-tree/vendor/trillionnium/owner-open",
    ]
    # Small fixtures may contain no support components; a real catalog path in
    # one of these trees makes that tree part of the source inventory.
    selected_support = [directory for directory in support_roots if any(
        path == directory or path.startswith(directory + "/")
        for module in catalog["modules"] for path in module["paths"])]
    verify_source_coverage(root, catalog, selected_support)
    verify_planned_workspace(root, catalog)


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
    except (VerificationError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"component documentation verification failed: {error}", file=sys.stderr)
        return 1
    print("component documentation verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
