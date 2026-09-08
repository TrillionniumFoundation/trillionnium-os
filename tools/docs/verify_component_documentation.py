#!/usr/bin/env python3
"""Stable CLI facade for the component-documentation verifier.

The reviewed core remains byte-identical.  This facade adds one deliberately
smaller accepted-subset rule: outside fenced examples, a raw HTML block opener
is rejected after both physical-line container markers and any continuation
indentation.  That fail-closed rule prevents list-item continuation state from
making a literal Markdown-looking link or shell fence count as rendered
content.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any


CORE_PATH = Path(__file__).with_name("_verify_component_documentation_core.py")
SPEC = importlib.util.spec_from_file_location(
    "_verify_component_documentation_core", CORE_PATH
)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery
    raise RuntimeError(f"cannot load component verifier core: {CORE_PATH}")
CORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORE)

_ORIGINAL_MARKDOWN_SURFACES = CORE.markdown_surfaces


def _reject_indented_raw_html(prose: str, label: str) -> None:
    """Reject raw block HTML at any continuation indentation outside fences."""
    source = CORE.strip_html_comments(prose, label)
    marker_character: str | None = None
    marker_length = 0

    for line_number, line in enumerate(source.splitlines(), start=1):
        if marker_character is None:
            remainder = CORE.strip_markdown_container_prefix(line).lstrip(" \t")
            if CORE.RAW_HTML_BLOCK_OPEN.match(remainder):
                raise CORE.VerificationError(
                    f"{label}: line {line_number} raw HTML block opener is forbidden"
                )

            match = CORE.FENCE_OPEN.fullmatch(line)
            if match is not None:
                marker = match.group("marker")
                marker_character = marker[0]
                marker_length = len(marker)
            continue

        stripped = line.lstrip(" \t")
        run_length = 0
        while (
            run_length < len(stripped)
            and stripped[run_length] == marker_character
        ):
            run_length += 1
        if (
            CORE.indentation_columns(line) <= 3
            and run_length >= marker_length
            and not stripped[run_length:].strip()
        ):
            marker_character = None
            marker_length = 0


def markdown_surfaces(prose: str, label: str) -> tuple[str, set[str], str]:
    _reject_indented_raw_html(prose, label)
    return _ORIGINAL_MARKDOWN_SURFACES(prose, label)


# The core's verify()/main() resolve markdown_surfaces in the core module.
CORE.markdown_surfaces = markdown_surfaces

# Preserve the established public import surface used by focused tests and
# external source tooling.  The hardened function above intentionally wins.
for _name in dir(CORE):
    if not _name.startswith("__") and _name != "markdown_surfaces":
        globals()[_name] = getattr(CORE, _name)


if __name__ == "__main__":
    raise SystemExit(CORE.main())
