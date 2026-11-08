#!/usr/bin/env python3
"""Build an unadopted function fragment and patch from one pinned R10 source.

This tool only reads/writes files below this offline candidate directory.  It
does not import the runtime, alter the frozen source, or run an admission.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
from pathlib import Path


BASE = Path(__file__).resolve().parents[1]
ORIGINAL = BASE / "originals/late_boundary.r10.original.py"
EXPECTED = {
    "bytes": 259866,
    "sha256": "f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7",
}

OLD_BLOCK = """    C.need(all(a == b or not (a in b.parents or b in a.parents) for a in paths for b in paths),
           'inventory roots overlap')
    C.need(all(p in entries and entries[p].get('kind') in ('directory', 'absent') for p in roots),
           'inventory root is absent or not a directory')
    root_parts = frozenset(p.parts for p in paths)
    root_depths = frozenset(len(parts) for parts in root_parts)
"""

NEW_BLOCK = """    root_parts = frozenset(p.parts for p in paths)
    root_depths = frozenset(len(parts) for parts in root_parts)
    C.need(all(parts[:depth] not in root_parts
               for parts in root_parts for depth in root_depths if depth < len(parts)),
           'inventory roots overlap')
    C.need(all(p in entries and entries[p].get('kind') in ('directory', 'absent') for p in roots),
           'inventory root is absent or not a directory')
"""


def descriptor(data: bytes) -> dict:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def function(source: str) -> tuple[ast.FunctionDef, str]:
    matches = [node for node in ast.parse(source).body
               if isinstance(node, ast.FunctionDef) and node.name == "inventory_value"]
    if len(matches) != 1:
        raise ValueError("exactly one original inventory_value is required")
    node = matches[0]
    return node, "\n".join(source.splitlines()[node.lineno - 1:node.end_lineno]) + "\n"


def build() -> dict:
    original_raw = ORIGINAL.read_bytes()
    if descriptor(original_raw) != EXPECTED:
        raise ValueError("original R10 source bytes differ")
    source = original_raw.decode("utf-8")
    original_node, original_function = function(source)
    if source.count(OLD_BLOCK) != 1 or original_function.count(OLD_BLOCK) != 1:
        raise ValueError("the single original topology block differs")
    derived_source = source.replace(OLD_BLOCK, NEW_BLOCK, 1)
    derived_node, derived_function = function(derived_source)
    # Undo the one declared transformation: every other source byte must match.
    if derived_source.replace(NEW_BLOCK, OLD_BLOCK, 1).encode("utf-8") != original_raw:
        raise ValueError("candidate changed bytes outside the declared topology block")
    candidate_dir = BASE / "candidate"
    candidate_dir.mkdir(exist_ok=True)
    fragment = (
        '"""Unadopted pure function fragment; it has no runtime entry point.\n\n'
        'Bind the same reviewed C, Path, stat, and re objects when integrating.\n'
        'No historical source or result identity is reassigned by this file.\n'
        '"""\n\n' + derived_function
    ).encode("utf-8")
    fragment_path = candidate_dir / "inventory_value.py"
    fragment_path.write_bytes(fragment)
    patch = "".join(difflib.unified_diff(
        source.splitlines(keepends=True), derived_source.splitlines(keepends=True),
        fromfile="a/runtime/source/late_boundary.py",
        tofile="b/runtime/source/late_boundary.py", n=5,
    )).encode("utf-8")
    patch_path = candidate_dir / "late_boundary.inventory_value.patch"
    patch_path.write_bytes(patch)
    report = {
        "schema": "hepta.offline.inventory-topology-candidate.v1",
        "state": "UNADOPTED_PURE_FUNCTION_CANDIDATE",
        "original_source": {"path": "originals/late_boundary.r10.original.py", **EXPECTED},
        "original_function": {"line": original_node.lineno,
                              **descriptor(original_function.encode("utf-8"))},
        "candidate_function": {"line_in_derived_source": derived_node.lineno,
                               **descriptor(derived_function.encode("utf-8"))},
        "candidate_fragment": {"path": str(fragment_path.relative_to(BASE)), **descriptor(fragment)},
        "patch": {"path": str(patch_path.relative_to(BASE)), **descriptor(patch)},
        "derived_full_source_if_applied": descriptor(derived_source.encode("utf-8")),
        "change": "Only root non-overlap uses strict Path.parts prefixes; existing sets move before this guard.",
        "other_source_bytes_unchanged": True,
        "validation_result_cache": False,
        "historical_sources_changed": False,
        "runtime_admission": False,
        "native_case_credit": 0,
        "whole_stage_budget_verified": False,
    }
    (BASE / "CANDIDATE-MANIFEST.json").write_text(
        json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return report


if __name__ == "__main__":
    print(json.dumps(build(), ensure_ascii=False, sort_keys=True, indent=2))
