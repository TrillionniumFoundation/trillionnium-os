#!/usr/bin/env python3
"""Verify repository-wide links, authority references and product profiles.

The verifier deliberately uses a closed, dependency-free Markdown policy. Every
repository Markdown file outside explicitly ephemeral build directories is
visited exactly once. Supported links are inline links/images, full/collapsed/
shortcut references, angle autolinks and HTML href/src attributes. Unsupported
or unresolved link-shaped syntax fails closed instead of becoming invisible to
an authority check.
"""
from __future__ import annotations

from collections import Counter
import html
from html.parser import HTMLParser
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
MARKDOWN_EXCLUDED_DIRECTORIES = frozenset({
    ".git", "target", ".venv", "venv", "__pycache__", ".pytest_cache",
})
PROFILE_PATH = "docs/machine/product-profile-catalog.v1.json"
LIFECYCLE_PATH = "governance/component-lifecycle.v1.json"
CAPABILITY_BEGIN = "<!-- PROFILE_CAPABILITIES_BEGIN -->"
CAPABILITY_END = "<!-- PROFILE_CAPABILITIES_END -->"
CAPABILITY_RE = re.compile(r"^- `([a-z][a-z0-9]*(?:[.-][a-z0-9]+)+)`$")
AUTHORITY_PHRASE_RE = re.compile(
    r"\b(?:canonical (?:plan|document|status|source)|authoritative (?:plan|document|status|source)|"
    r"source of truth|current (?:plan|status|state|authority))\b",
    re.IGNORECASE,
)
DECLARATIVE_AUTHORITY_RE = re.compile(
    r"(?:\bcanonical (?:plan|document|status|source)\b\s+(?:for\b|is\b)|"
    r"\bauthoritative (?:plan|document|status|source)\b\s+(?:for\b|is\b)|"
    r"\bsource of truth\b\s*(?:is\b|:)|"
    r"\bcurrent authority\b\s*(?:is\b|:))",
    re.IGNORECASE,
)
URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
REFERENCE_DEFINITION_RE = re.compile(
    r"^ {0,3}\[([^\]\n]+)\]:[ \t]*(?:<([^>\n]+)>|([^\s]+))"
    r"(?:[ \t]+(?:\"[^\"\n]*\"|'[^'\n]*'|\([^\)\n]*\)))?[ \t]*$"
)
INLINE_LINK_RE = re.compile(
    r"!?\[([^\[\]]+)\]\([ \t\r\n]*(?:<([^<>\n]+)>|([^\s\)]+))"
    r"(?:[ \t\r\n]+(?:\"[^\"\n]*\"|'[^'\n]*'|\([^\)\n]*\)))?[ \t\r\n]*\)",
    re.MULTILINE,
)
REFERENCE_LINK_RE = re.compile(r"!?\[([^\[\]]+)\]\[([^\[\]]*)\]", re.MULTILINE)
BRACKET_RE = re.compile(r"!?\[([^\[\]]+)\]", re.MULTILINE)
ANGLE_TARGET_RE = re.compile(r"<([^<>\s]+)>")
HTML_TAG_NAME_RE = re.compile(r"</?([A-Za-z][A-Za-z0-9:-]*)")
HTML_BLOCK_BOUNDARY_TAGS = frozenset({
    "address", "article", "aside", "blockquote", "br", "dd", "div", "dl",
    "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1",
    "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main",
    "nav", "ol", "p", "pre", "section", "table", "tbody", "td",
    "tfoot", "th", "thead", "tr", "ul",
})
BARE_AUTHORITY_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.+/-])((?:(?:\.{1,2}/)+)?(?:(?:docs|governance|schemas|apps|crates|tools|packaging|"
    r"android-integration|evidence|foundations|planned|platform|profile)/"
    r"[A-Za-z0-9_.+@~/-]+|README\.md|SECURITY\.md|CONTRIBUTING\.md|"
    r"TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN\.md)(?:#[A-Za-z0-9_.:+-]+)?)"
)
PROFILE_KEYS = {
    "schema", "program_revision", "default_profile", "semantic_contract",
    "component_lifecycle", "profiles",
}
PROFILE_ENTRY_KEYS = {
    "id", "status", "default", "activation_allowed", "claim_ceiling",
    "selected_modules", "selected_cargo_components", "selected_implementation_paths",
    "offered_capabilities", "retained_components", "blocked_capabilities",
    "evidence_requirements", "deferred_dependencies",
}
CAPABILITY_KEYS = {"id", "owner_module", "implementation_paths"}
BLOCKED_CAPABILITY_KEYS = {"id", "reason"}
DEFERRED_DEPENDENCY_KEYS = {
    "source_module", "dependency_module", "classification", "blocking_gap", "reason",
}


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


def _strip_html_comments(line: str, in_comment: bool) -> tuple[str, bool]:
    output = ""
    remaining = line
    while True:
        if in_comment:
            end = remaining.find("-->")
            if end < 0:
                return output, True
            remaining = remaining[end + 3:]
            in_comment = False
        start = remaining.find("<!--")
        if start < 0:
            return output + remaining, in_comment
        output += remaining[:start]
        remaining = remaining[start + 4:]
        in_comment = True


def _strip_inline_code(line: str) -> str:
    chars = list(line)
    index = 0
    while index < len(chars):
        if chars[index] != "`":
            index += 1
            continue
        end_run = index
        while end_run < len(chars) and chars[end_run] == "`":
            end_run += 1
        marker = "`" * (end_run - index)
        closing = line.find(marker, end_run)
        if closing < 0:
            index = end_run
            continue
        for position in range(index, closing + len(marker)):
            chars[position] = " "
        index = closing + len(marker)
    return "".join(chars)


def visible_markdown(source: str) -> list[tuple[int, str]]:
    """Return visible prose with source line numbers.

    Fenced code, true top-level indented code and HTML comments are excluded.
    Four-space list continuations remain visible; this is the authority-bearing
    case that the previous line-oriented filter incorrectly discarded.
    """
    lines: list[tuple[int, str]] = []
    fence_character: str | None = None
    fence_length = 0
    in_comment = False
    list_content_indent: int | None = None
    for line_number, raw in enumerate(source.splitlines(), start=1):
        line, in_comment = _strip_html_comments(raw, in_comment)
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if fence_character is None:
            opening = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
            if opening:
                marker = opening.group(1)
                if marker[0] == "`":
                    require("`" not in opening.group(2),
                            "backtick fence info string contains a backtick")
                fence_character = marker[0]
                fence_length = len(marker)
                continue
        else:
            closing = re.match(
                rf"^ {{0,3}}{re.escape(fence_character)}{{{fence_length},}}[ \t]*$",
                line,
            )
            if closing:
                fence_character = None
                fence_length = 0
            continue

        if not line.strip():
            lines.append((line_number, ""))
            continue
        item = re.match(r"^( {0,3})(?:[-+*]|\d{1,9}[.)])([ \t]+)", line)
        if item:
            list_content_indent = item.end()
        elif list_content_indent is not None and indent < list_content_indent:
            list_content_indent = None
        if indent >= 4 and (list_content_indent is None or indent < list_content_indent):
            continue
        lines.append((line_number, _strip_inline_code(line)))
    require(fence_character is None, "unterminated fenced code block in Markdown input")
    require(not in_comment, "unterminated HTML comment in Markdown input")
    return lines


def _filesystem_markdown_inventory(root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in root.rglob("*.md"):
        relative_parts = path.relative_to(root).parts
        if any(part in MARKDOWN_EXCLUDED_DIRECTORIES for part in relative_parts):
            continue
        relative = path.relative_to(root).as_posix()
        require(relative not in result, f"Markdown inventory repeats {relative}")
        require(path.is_file() and not path.is_symlink(),
                f"Markdown source is not a regular non-symlink file: {relative}")
        result[relative] = path
    return result


def _tracked_markdown_inventory(root: Path) -> set[str] | None:
    if not (root / ".git").exists():
        return None
    completed = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(root), "ls-files", "-z", "--", "*.md"],
        check=False,
        capture_output=True,
        timeout=30,
    )
    require(completed.returncode == 0,
            f"cannot enumerate tracked Markdown: {completed.stderr.decode(errors='replace').strip()}")
    tracked: set[str] = set()
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise VerificationError(f"tracked Markdown path is not UTF-8: {error}") from error
        require(relative not in tracked, f"tracked Markdown inventory repeats {relative}")
        tracked.add(relative)
    return tracked


def markdown_files(root: Path) -> Iterable[Path]:
    filesystem = _filesystem_markdown_inventory(root)
    tracked = _tracked_markdown_inventory(root)
    if tracked is not None:
        require(
            set(filesystem) == tracked,
            "closed Markdown inventory differs from tracked source; "
            f"untracked={sorted(set(filesystem)-tracked)}, missing={sorted(tracked-set(filesystem))}",
        )
    for relative in sorted(filesystem):
        yield filesystem[relative]


def resolve_markdown_target(root: Path, source: Path, target: str, label: str) -> str:
    target = html.unescape(target.strip())
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


def resolve_bare_repository_target(root: Path, target: str, label: str) -> str:
    target = target.split("#", 1)[0]
    normalized, candidate = normalized_repository_path(root, target, label)
    require(candidate.exists(), f"{label} target does not exist: {target}")
    return normalized


def normalize_reference_label(value: str) -> str:
    return re.sub(r"[ \t\r\n]+", " ", value.strip()).casefold()


def _reference_definitions(
    visible_lines: list[tuple[int, str]], relative: str,
) -> tuple[dict[str, str], set[int]]:
    definitions: dict[str, str] = {}
    definition_lines: set[int] = set()
    for line_number, line in visible_lines:
        match = REFERENCE_DEFINITION_RE.fullmatch(line)
        if not match:
            continue
        name = normalize_reference_label(match.group(1))
        require(name and name not in definitions,
                f"{relative}: duplicate or empty reference definition {name!r}")
        definitions[name] = match.group(2) or match.group(3)
        definition_lines.add(line_number)
    return definitions, definition_lines


def _paragraphs(
    visible_lines: list[tuple[int, str]], definition_lines: set[int],
) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    buffer: list[str] = []
    start = 1
    for line_number, line in visible_lines:
        if line_number in definition_lines:
            continue
        if not line.strip():
            if buffer:
                result.append((start, "\n".join(buffer)))
                buffer = []
            continue
        if not buffer:
            start = line_number
        buffer.append(line)
    if buffer:
        result.append((start, "\n".join(buffer)))
    return result


def _mask_ranges(source: str, ranges: list[tuple[int, int]]) -> str:
    chars = list(source)
    for start, end in ranges:
        for index in range(start, end):
            chars[index] = " "
    return "".join(chars)


def _is_angle_target(candidate: str) -> bool:
    """Return whether ``<candidate>`` is a supported Markdown autolink.

    A self-closing HTML tag such as ``<br/>`` is deliberately not classified
    as a repository-path autolink merely because it contains ``/``.
    """
    candidate = html.unescape(candidate)
    if URL_SCHEME_RE.match(candidate) or candidate.startswith("//"):
        return True
    if re.fullmatch(r"/?[A-Za-z][A-Za-z0-9:-]*/?", candidate):
        return False
    return "/" in candidate


def _angle_target_ranges(source: str) -> set[tuple[int, int]]:
    return {
        match.span()
        for match in ANGLE_TARGET_RE.finditer(source)
        if _is_angle_target(match.group(1))
    }


class _SingleHtmlTagParser(HTMLParser):
    """Parse one bounded HTML tag and retain exact href/src attributes."""

    def __init__(self, label: str) -> None:
        super().__init__(convert_charrefs=True)
        self.label = label
        self.events = 0
        self.tag_name: str | None = None
        self.targets: list[str] = []

    def _record(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.events += 1
        require(self.events == 1, f"{self.label}: HTML fragment contains multiple tags")
        self.tag_name = tag.casefold()
        names = [name.casefold() for name, _ in attrs]
        duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
        require(not duplicates, f"{self.label}: duplicate HTML attributes {duplicates}")
        for (name, value), normalized_name in zip(attrs, names):
            del name
            if normalized_name not in {"href", "src"}:
                continue
            require(value is not None and bool(value.strip()),
                    f"{self.label}: empty HTML {normalized_name} target")
            self.targets.append(value)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._record(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._record(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        self.events += 1
        require(self.events == 1, f"{self.label}: HTML fragment contains multiple tags")
        self.tag_name = tag.casefold()

    def handle_data(self, data: str) -> None:
        require(not data.strip(), f"{self.label}: malformed HTML tag fragment")


def _html_tags(source: str, label: str) -> list[tuple[int, int, str, list[str]]]:
    """Return structurally bounded HTML tags and every exact href/src target.

    The scanner respects quotes while locating ``>``.  Attribute names are
    then parsed by :class:`HTMLParser`, so ``data-href`` and text containing
    ``href=`` cannot masquerade as the real destination. Duplicate attributes
    fail closed instead of relying on browser-dependent first/last semantics.
    """
    angle_ranges = _angle_target_ranges(source)
    result: list[tuple[int, int, str, list[str]]] = []
    index = 0
    while index < len(source):
        start = source.find("<", index)
        if start < 0:
            break
        angle = next((span for span in angle_ranges if span[0] == start), None)
        if angle is not None:
            index = angle[1]
            continue
        name_match = HTML_TAG_NAME_RE.match(source, start)
        if name_match is None:
            index = start + 1
            continue
        quote: str | None = None
        cursor = name_match.end()
        while cursor < len(source):
            character = source[cursor]
            if quote is None and character in {"\"", "'"}:
                quote = character
            elif quote is not None and character == quote:
                quote = None
            elif quote is None and character == ">":
                break
            cursor += 1
        require(cursor < len(source), f"{label}: unterminated HTML tag")
        end = cursor + 1
        fragment = source[start:end]
        parser = _SingleHtmlTagParser(f"{label}: HTML tag at offset {start}")
        try:
            parser.feed(fragment)
            parser.close()
        except VerificationError:
            raise
        except Exception as error:  # HTMLParser can surface malformed entity errors.
            raise VerificationError(f"{label}: malformed HTML tag: {error}") from error
        require(parser.events == 1 and parser.tag_name == name_match.group(1).casefold(),
                f"{label}: malformed or ambiguously parsed HTML tag")
        result.append((start, end, parser.tag_name, parser.targets))
        index = end
    return result


def _semantic_without_html(value: str, label: str) -> str:
    tags = _html_tags(value, label)
    if not tags:
        return value
    output: list[str] = []
    cursor = 0
    for start, end, tag_name, _ in tags:
        output.append(value[cursor:start])
        if tag_name in HTML_BLOCK_BOUNDARY_TAGS:
            output.append(" ")
        cursor = end
    output.append(value[cursor:])
    return "".join(output)


def markdown_targets(
    paragraph: str,
    *,
    definitions: dict[str, str],
    label: str,
) -> list[tuple[str, str]]:
    """Return (target, syntax) for every supported link in one paragraph."""
    targets: list[tuple[str, str]] = []
    consumed: list[tuple[int, int]] = []
    for match in INLINE_LINK_RE.finditer(paragraph):
        targets.append((match.group(2) or match.group(3), "inline Markdown link"))
        consumed.append(match.span())
    masked = _mask_ranges(paragraph, consumed)

    reference_ranges: list[tuple[int, int]] = []
    for match in REFERENCE_LINK_RE.finditer(masked):
        name = normalize_reference_label(match.group(2) or match.group(1))
        require(name in definitions, f"{label}: unresolved reference link {name!r}")
        targets.append((definitions[name], "reference Markdown link"))
        reference_ranges.append(match.span())
    masked = _mask_ranges(masked, reference_ranges)

    shortcut_ranges: list[tuple[int, int]] = []
    for match in BRACKET_RE.finditer(masked):
        name = normalize_reference_label(match.group(1))
        if name in definitions:
            targets.append((definitions[name], "shortcut Markdown link"))
            shortcut_ranges.append(match.span())
    masked = _mask_ranges(masked, shortcut_ranges)

    html_ranges: list[tuple[int, int]] = []
    for start, end, _, html_targets in _html_tags(masked, label):
        html_ranges.append((start, end))
        for target in html_targets:
            targets.append((target, "HTML href/src target"))
    consumed.extend(html_ranges)

    for match in ANGLE_TARGET_RE.finditer(_mask_ranges(paragraph, consumed)):
        candidate = html.unescape(match.group(1))
        if _is_angle_target(candidate):
            targets.append((candidate, "angle autolink"))

    # Any remaining explicit inline/reference delimiter is link-shaped syntax
    # outside the closed parser and therefore cannot silently evade validation.
    residual = _mask_ranges(masked, consumed)
    require(re.search(r"\]\s*\(", residual) is None,
            f"{label}: unsupported inline-link syntax")
    require(re.search(r"\]\s*\[", residual) is None,
            f"{label}: unsupported reference-link syntax")
    return targets


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


def path_is_within(child: str, parent: str) -> bool:
    return child == parent or child.startswith(parent.rstrip("/") + "/")


def paths_overlap(left: str, right: str) -> bool:
    return path_is_within(left, right) or path_is_within(right, left)


def verify_profile_dependencies(
    root: Path,
    profile: dict[str, Any],
    module_map: dict[str, dict[str, Any]],
    module_paths: dict[str, list[str]],
    selected_paths: list[str],
) -> None:
    """Check the selected source graph, never mint installed/runtime authority.

    A missing target may be deferred only as a named planned-only edge with an
    unresolved target-qualification gap owned by its selected source module.
    There is no wildcard, optional runtime dependency, or fallback behavior.
    """
    profile_id = profile["id"]
    selected = set(profile["selected_modules"])
    edges: set[tuple[str, str]] = set()
    for source in sorted(selected):
        for target in string_list(
            module_map[source].get("dependencies"), f"{source}.dependencies", allow_empty=True
        ):
            require(target in module_map, f"{source} has unknown dependency {target}")
            require(target != source, f"{source} has a self dependency")
            edges.add((source, target))
    missing = {(source, target) for source, target in edges if target not in selected}
    deferred = profile["deferred_dependencies"]
    require(isinstance(deferred, list), f"{profile_id}.deferred_dependencies must be an array")
    require(len(deferred) <= len(edges), f"{profile_id} has too many deferred dependencies")
    gap_catalog = load_json(root / "docs/machine/gap-register.v2.json")
    gap_items = gap_catalog.get("gaps")
    require(isinstance(gap_items, list), "gap register must contain a gaps array")
    gaps: dict[str, dict[str, Any]] = {}
    for gap in gap_items:
        require(isinstance(gap, dict), "gap entry must be an object")
        gap_id = text(gap.get("id"), "gap id")
        require(gap_id not in gaps, "gap register repeats an id")
        gaps[gap_id] = gap
    observed: set[tuple[str, str]] = set()
    for index, entry in enumerate(deferred):
        label = f"{profile_id}.deferred_dependencies[{index}]"
        require(isinstance(entry, dict), f"{label} must be an object")
        exact_keys(entry, DEFERRED_DEPENDENCY_KEYS, label)
        source = text(entry["source_module"], f"{label}.source_module")
        target = text(entry["dependency_module"], f"{label}.dependency_module")
        edge = (source, target)
        require(edge not in observed, f"{label} duplicates a deferred edge")
        require(edge in missing, f"{label} is not a missing selected-source dependency")
        require(entry["classification"] == "PLANNED_ONLY", f"{label} classification must be PLANNED_ONLY")
        maturity = module_map[target].get("maturity")
        require(isinstance(maturity, str) and maturity.startswith("PLANNED_"),
                f"{label} cannot defer a non-planned module")
        require(all(path.startswith("planned/") for path in module_paths[target]),
                f"{label} planned module has a non-planned source path")
        require(not any(paths_overlap(path, planned) for path in selected_paths
                        for planned in module_paths[target]),
                f"{label} planned source is already selected")
        gap_id = text(entry["blocking_gap"], f"{label}.blocking_gap")
        require(gap_id in gaps, f"{label} references an unknown blocking gap")
        gap = gaps[gap_id]
        require(gap.get("status") in {"OPEN", "SOURCE_CLOSED_PENDING_EVIDENCE", "EXTERNAL_HOLD"},
                f"{label} blocking gap is not unresolved")
        require(gap.get("exit_level") in {"L2", "L3", "L4", "L5", "L6"},
                f"{label} blocking gap is not target qualification")
        owners = string_list(gap.get("modules"), f"{gap_id}.modules")
        require(source in owners, f"{label} blocking gap does not cover the source module")
        reason = text(entry["reason"], f"{label}.reason")
        try:
            reason_bytes = reason.encode("utf-8", "strict")
        except UnicodeError as error:
            raise VerificationError(f"{label} reason is not valid UTF-8") from error
        require(len(reason_bytes) <= 1024
                and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in reason),
                f"{label} reason exceeds bounded single-line text")
        observed.add(edge)
    require(observed == missing,
            f"{profile_id} undeclared missing dependencies: {sorted(missing-observed)}")


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
    module_items = modules.get("modules", [])
    require(isinstance(module_items, list) and module_items, "module catalog has no modules")
    module_map = {text(item.get("id"), "module id"): item for item in module_items}
    require(len(module_map) == len(module_items), "module catalog repeats an id")
    module_paths: dict[str, list[str]] = {}
    for module_id, item in module_map.items():
        paths: list[str] = []
        for index, raw_path in enumerate(string_list(item.get("paths"), f"{module_id}.paths")):
            normalized, candidate = normalized_repository_path(
                root, raw_path, f"{module_id}.paths[{index}]"
            )
            require(candidate.exists(), f"{module_id} path does not exist: {normalized}")
            paths.append(normalized)
        module_paths[module_id] = paths

    default_components = string_list(modules.get("default_source_closure"), "module default_source_closure")
    default_components = [
        normalized_repository_path(root, value, "module default_source_closure")[0]
        for value in default_components
    ]
    lifecycle = load_json(lifecycle_file)
    retained = string_list(
        [item.get("path") for item in lifecycle.get("non_product_members", [])],
        "lifecycle retained components",
    )
    retained = [
        normalized_repository_path(root, value, "lifecycle retained component")[0]
        for value in retained
    ]

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
        selected_cargo_raw = string_list(raw["selected_cargo_components"], f"{profile_id}.selected_cargo_components", allow_empty=True)
        selected_paths_raw = string_list(raw["selected_implementation_paths"], f"{profile_id}.selected_implementation_paths", allow_empty=True)
        retained_raw = string_list(raw["retained_components"], f"{profile_id}.retained_components", allow_empty=True)
        string_list(raw["evidence_requirements"], f"{profile_id}.evidence_requirements")

        selected_cargo: list[str] = []
        for path_index, value in enumerate(selected_cargo_raw):
            normalized, candidate = normalized_repository_path(root, value, f"{profile_id}.selected_cargo[{path_index}]")
            require(candidate.exists(), f"{profile_id} Cargo path does not exist: {normalized}")
            selected_cargo.append(normalized)
        selected_paths: list[str] = []
        for path_index, value in enumerate(selected_paths_raw):
            normalized, candidate = normalized_repository_path(root, value, f"{profile_id}.selected_path[{path_index}]")
            require(candidate.exists(), f"{profile_id} path does not exist: {normalized}")
            selected_paths.append(normalized)
        retained_components: list[str] = []
        for path_index, value in enumerate(retained_raw):
            normalized, candidate = normalized_repository_path(root, value, f"{profile_id}.retained[{path_index}]")
            require(candidate.exists(), f"{profile_id} retained path does not exist: {normalized}")
            retained_components.append(normalized)

        for selected in selected_paths:
            require(not any(paths_overlap(selected, sealed) for sealed in retained),
                    f"{profile_id} selected path overlaps sealed lifecycle component: {selected}")
        require(set(selected_cargo).issubset(set(selected_paths)),
                f"{profile_id} selected implementation graph omits a selected Cargo component")

        for module_id in selected_modules:
            require(module_id in module_map, f"{profile_id} selects unknown module {module_id}")
        allowed_selected_roots = set(selected_cargo)
        for module_id in selected_modules:
            allowed_selected_roots.update(module_paths[module_id])
        for selected in selected_paths:
            require(selected in allowed_selected_roots,
                    f"{profile_id} selected path is not an exact component or module root: {selected}")
        for module_id in selected_modules:
            for owner_path in module_paths[module_id]:
                covered = owner_path in selected_paths or any(
                    cargo in selected_paths and path_is_within(owner_path, cargo)
                    for cargo in selected_cargo
                )
                require(covered,
                        f"{profile_id} selects {module_id} without complete path {owner_path}")

        verify_profile_dependencies(root, raw, module_map, module_paths, selected_paths)

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
            implementations = string_list(
                capability["implementation_paths"], f"{capability_id}.implementation_paths"
            )
            normalized_implementations: list[str] = []
            for implementation_index, implementation in enumerate(implementations):
                normalized, candidate = normalized_repository_path(
                    root, implementation, f"{capability_id}.implementation[{implementation_index}]"
                )
                require(candidate.exists(), f"{capability_id} implementation path does not exist")
                require(any(path_is_within(normalized, selected) for selected in selected_paths),
                        f"{capability_id} implementation is outside selected graph: {normalized}")
                require(not any(paths_overlap(normalized, sealed) for sealed in retained),
                        f"{capability_id} implementation overlaps sealed lifecycle path: {normalized}")
                owners = {
                    candidate_module
                    for candidate_module in selected_modules
                    if any(path_is_within(normalized, owner_path)
                           for owner_path in module_paths[candidate_module])
                }
                require(owners == {owner_module},
                        f"{capability_id} implementation ownership differs: "
                        f"declared={owner_module}, observed={sorted(owners)}")
                normalized_implementations.append(normalized)
            require(len(normalized_implementations) == len(set(normalized_implementations)),
                    f"{capability_id} repeats an implementation path")
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


def _semantic_visible_text(paragraph: str) -> str:
    """Normalize rendered prose for authority-phrase classification.

    Target extraction still uses the original paragraph. Semantic matching uses
    rendered link labels rather than Markdown destinations so permitted link
    syntax cannot split a visible authority phrase. Inline HTML tags preserve
    text adjacency (``Canoni<b>cal</b>`` renders as ``Canonical``); block and
    line-break tags retain a whitespace boundary. Entities and emphasis normalize.
    """
    value = INLINE_LINK_RE.sub(lambda match: match.group(1), paragraph)
    value = REFERENCE_LINK_RE.sub(lambda match: match.group(1), value)
    value = BRACKET_RE.sub(lambda match: match.group(1), value)
    value = _semantic_without_html(value, "semantic authority text")
    value = html.unescape(value)
    value = value.translate(str.maketrans("", "", "*_~"))
    return re.sub(r"\s+", " ", value).strip()


def _registered_authority(target: str, authority_targets: set[str]) -> bool:
    # Authority is granted only to exact registered file identities. Directory
    # roots remain ordinary navigation targets and never confer authority.
    return target in authority_targets


def verify_markdown(root: Path, profile_catalog: dict[str, Any]) -> tuple[int, int]:
    del profile_catalog  # The profile is verified independently; no hidden scan roots come from it.
    docset = load_json(root / "docs/machine/doc-set.v1.json")
    forbidden_paths = string_list(docset.get("forbidden_paths"), "doc-set.forbidden_paths")
    forbidden_markers = string_list(docset.get("forbidden_content_markers"), "doc-set.forbidden_content_markers")
    authority_order = string_list(docset.get("authority_order"), "doc-set.authority_order")
    required_files = string_list(docset.get("required_files"), "doc-set.required_files")
    authority_targets: set[str] = set()
    for index, value in enumerate(authority_order + required_files + [LIFECYCLE_PATH]):
        normalized, candidate = normalized_repository_path(
            root, value, f"registered authority[{index}]"
        )
        require(candidate.exists(), f"registered authority does not exist: {normalized}")
        authority_targets.add(normalized)
    link_count = 0
    files = list(markdown_files(root))
    require(len(files) == len({path.relative_to(root).as_posix() for path in files}),
            "Markdown inventory is not one-to-one")
    for path in files:
        relative = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8")
        visible_lines = visible_markdown(source)
        visible = "\n".join(line for _, line in visible_lines)
        for marker in forbidden_markers:
            require(marker not in visible,
                    f"forbidden legacy marker {marker!r} appears in {relative}")
        definitions, definition_lines = _reference_definitions(visible_lines, relative)
        for paragraph_line, paragraph in _paragraphs(visible_lines, definition_lines):
            targets = markdown_targets(
                paragraph,
                definitions=definitions,
                label=f"{relative}: paragraph at visible line {paragraph_line}",
            )
            semantic_paragraph = _semantic_visible_text(paragraph)
            authority_phrase = AUTHORITY_PHRASE_RE.search(semantic_paragraph) is not None
            if authority_phrase:
                for match in BARE_AUTHORITY_PATH_RE.finditer(paragraph):
                    targets.append((match.group(1).rstrip(".,;:!?"), "bare authority path"))
            resolved_targets: list[tuple[str, str]] = []
            external_targets: list[tuple[str, str]] = []
            seen: set[tuple[str, str]] = set()
            for target, syntax in targets:
                item = (target, syntax)
                if item in seen:
                    continue
                seen.add(item)
                normalized_target = html.unescape(target.strip())
                if URL_SCHEME_RE.match(normalized_target) or normalized_target.startswith("//"):
                    external_targets.append((normalized_target, syntax))
                    continue
                if syntax == "bare authority path" and not normalized_target.startswith(("./", "../")):
                    resolved = resolve_bare_repository_target(
                        root, normalized_target,
                        f"{relative}: visible line {paragraph_line} {syntax}",
                    )
                else:
                    resolved = resolve_markdown_target(
                        root, path, normalized_target,
                        f"{relative}: visible line {paragraph_line} {syntax}",
                    )
                link_count += 1
                resolved_targets.append((resolved, syntax))
                for forbidden in forbidden_paths:
                    require(
                        resolved != forbidden and not resolved.startswith(forbidden.rstrip("/") + "/"),
                        f"{relative}: link targets forbidden authority path {resolved}",
                    )
            if authority_phrase:
                if external_targets:
                    raise VerificationError(
                        f"{relative}: authority phrase points to external target "
                        f"{external_targets[0][0]}"
                    )
                for target, _ in resolved_targets:
                    require(_registered_authority(target, authority_targets),
                            f"{relative}: authority phrase points to unregistered target {target}")
                if DECLARATIVE_AUTHORITY_RE.search(semantic_paragraph) and not resolved_targets:
                    require(_registered_authority(relative, authority_targets),
                            f"{relative}: unregistered document makes an unbound authority declaration")
    return len(files), link_count


def verify(root: Path = ROOT) -> dict[str, int]:
    root = root.resolve()
    catalog = verify_profiles(root)
    files, links = verify_markdown(root, catalog)
    return {"profiles": len(catalog["profiles"]), "markdown_files": files, "local_links": links}


def main() -> int:
    try:
        report = verify()
    except (VerificationError, OSError, UnicodeError, KeyError, TypeError, subprocess.SubprocessError) as error:
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
