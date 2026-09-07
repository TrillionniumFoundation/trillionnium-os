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
FENCE_OPEN = re.compile(r"^[ \t]{0,3}(?P<marker>`{3,}|~{3,})(?P<info>.*)$")
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


def strip_inline_code(line: str) -> str:
    """Hide inline code spans so examples cannot satisfy visible-link checks."""
    characters = list(line)
    cursor = 0
    while cursor < len(line):
        if line[cursor] != "`":
            cursor += 1
            continue
        run_end = cursor
        while run_end < len(line) and line[run_end] == "`":
            run_end += 1
        marker = line[cursor:run_end]
        close = line.find(marker, run_end)
        span_end = len(line) if close < 0 else close + len(marker)
        for index in range(cursor, span_end):
            characters[index] = " "
        cursor = span_end
    return "".join(characters)


def markdown_surfaces(prose: str, label: str) -> tuple[str, set[str], str]:
    """Return rendered prose, exact shell-fence lines, and comment-free source."""
    source = strip_html_comments(prose, label)
    visible_lines: list[str] = []
    shell_lines: set[str] = set()
    marker_character: str | None = None
    marker_length = 0
    language = ""
    html_code_block: str | None = None

    for line in source.splitlines():
        lowered = line.lstrip().lower()
        if html_code_block is not None:
            if f"</{html_code_block}>" in lowered:
                html_code_block = None
            continue

        if marker_character is None:
            opened_html_block = False
            for tag in ("pre", "code", "script", "style"):
                if re.match(rf"^<{tag}(?:\s|>)", lowered):
                    if f"</{tag}>" not in lowered:
                        html_code_block = tag
                    opened_html_block = True
                    break
            if opened_html_block:
                continue

            match = FENCE_OPEN.fullmatch(line)
            if match is not None:
                marker = match.group("marker")
                marker_character = marker[0]
                marker_length = len(marker)
                info = match.group("info").strip()
                language = info.split(None, 1)[0].lower() if info else ""
                continue

            # Four-space and tab-indented blocks are Markdown code, not links.
            if line.startswith("\t") or len(line) - len(line.lstrip(" ")) >= 4:
                continue
            visible_lines.append(strip_inline_code(line))
            continue

        stripped = line.lstrip(" \t")
        indentation = len(line) - len(stripped)
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
    require(html_code_block is None, f"{label} has an unterminated HTML code block")
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
            module_path_text, _ = normalized_path(
                root,
                raw_path,
                f"{module_id}.paths[{path_index}]",
            )
            module_path = PurePosixPath(module_path_text)
            for member, member_path in member_parts.items():
                if module_path == member_path or member_path in module_path.parents:
                    physical[member].add(contract_text)

    return valid_contracts, {
        member: sorted(contracts) for member, contracts in physical.items()
    }


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
            if not (physical_contracts or linked_contracts):
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
