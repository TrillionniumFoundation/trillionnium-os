#!/usr/bin/env python3
"""Create separate, unadopted derived validators; never edit historical sources."""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
from pathlib import Path

from build_candidate import OLD_BLOCK, NEW_BLOCK

BASE = Path(__file__).resolve().parents[1]
SCOPE_OLD = """    for path in after['entries']:
        if any(Path(path)==Path(root)or Path(root)in Path(path).parents for root in old['roots']):
            need(path in old['entries'],'no new child added below any old retained root')
"""
SCOPE_NEW = """    _topology_old_root_parts=frozenset(Path(root).parts for root in old['roots'])
    _topology_old_root_depths=frozenset(len(parts) for parts in _topology_old_root_parts)
    for path in after['entries']:
        _topology_entry_parts=Path(path).parts
        if any(_topology_entry_parts[:depth] in _topology_old_root_parts
               for depth in _topology_old_root_depths if depth<=len(_topology_entry_parts)):
            need(path in old['entries'],'no new child added below any old retained root')
"""

SPECS = [
    {"id": "source-parent-inventory", "path": "originals/source_parent_late_boundary_r4.original.py",
     "bytes": 153138, "sha256": "27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4",
     "function": "inventory_value", "old": OLD_BLOCK, "new": NEW_BLOCK,
     "fragment": "source_parent_inventory_value.py"},
    {"id": "retained-r8-scope", "path": "originals/retained_r8_scope.original.py",
     "bytes": 21865, "sha256": "937a34f4ba752e14bb78b1566c672e89b2e26502392d8d2a3561a52ceb88af38",
     "function": "verify_complete_scope", "old": SCOPE_OLD, "new": SCOPE_NEW,
     "fragment": "retained_r8_verify_complete_scope.py"},
]


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def extract(source, name):
    nodes = [n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(nodes) != 1:
        raise ValueError("exactly one original function is required")
    node = nodes[0]
    return "\n".join(source.splitlines()[node.lineno - 1:node.end_lineno]) + "\n", node


def build():
    destination = BASE / "candidate/derived"
    destination.mkdir(parents=True, exist_ok=True)
    rows = []
    for spec in SPECS:
        raw = (BASE / spec["path"]).read_bytes()
        if pin(raw) != {k: spec[k] for k in ("bytes", "sha256")}:
            raise ValueError("historical source pin differs: " + spec["id"])
        source = raw.decode("utf-8")
        original, node = extract(source, spec["function"])
        if original.count(spec["old"]) != 1:
            raise ValueError("one exact pure topology replacement site is required")
        if spec["id"] == "retained-r8-scope" and "_topology_" in source:
            raise ValueError("candidate local names collide with historical source")
        derived = original.replace(spec["old"], spec["new"], 1)
        if derived.replace(spec["new"], spec["old"], 1) != original:
            raise ValueError("whole-byte inverse failed")
        full = source.replace(original, derived, 1)
        if full.replace(derived, original, 1) != source:
            raise ValueError("source outside the function changed")
        fragment = ('"""Unadopted derived pure function; bind new provenance before use.\n'
                    'Historical publisher and historical reader identities remain distinct.\n'
                    'No production selector or runtime admission is provided.\n"""\n\n' + derived).encode()
        path = destination / spec["fragment"]
        path.write_bytes(fragment)
        patch = "".join(difflib.unified_diff(source.splitlines(True), full.splitlines(True),
                            fromfile="a/" + spec["id"] + ".py",
                            tofile="b/" + spec["id"] + ".py", n=5)).encode()
        patch_path = destination / (spec["id"] + ".patch")
        patch_path.write_bytes(patch)
        rows.append({"id": spec["id"], "original_source": {"path": spec["path"], **pin(raw)},
                     "original_function": {"name": spec["function"], "line": node.lineno,
                                           **pin(original.encode())},
                     "derived_function": pin(derived.encode()),
                     "fragment": {"path": str(path.relative_to(BASE)), **pin(fragment)},
                     "patch": {"path": str(patch_path.relative_to(BASE)), **pin(patch)},
                     "derived_complete_source_if_composed": pin(full.encode()),
                     "whole_byte_inverse_verified": True,
                     "historical_source_bytes_changed": False,
                     "historical_reader_function_replaced_in_runtime": False,
                     "original_module_provenance_reassigned": False,
                     "validation_result_cache": False,
                     "production_selector_implemented": False})
    result = {"schema": "hepta.offline.derived-topology-fragments.v1",
              "state": "UNADOPTED_DERIVED_FUNCTION_CANDIDATES", "functions": rows,
              "runtime_admission": False, "native_case_credit": 0,
              "whole_stage_budget_verified": False}
    (BASE / "DERIVED-CANDIDATE-MANIFEST.json").write_text(
        json.dumps(result, sort_keys=True, ensure_ascii=False, indent=2) + "\n")
    return result


if __name__ == "__main__":
    print(json.dumps(build(), sort_keys=True, ensure_ascii=False, indent=2))
