#!/usr/bin/env python3
"""Recompute unadopted selector identities without editing any frozen source.

Prints a deterministic manifest.  An optional output must be a new file.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import types


BASE = Path(__file__).resolve().parents[1]
SOURCES = {
    "r7-reader": "originals/verify_retained_preaccept_r7.original.py",
    "r8-reader": "originals/verify_retained_staged_r8.original.py",
    "r8-scope": "originals/retained_r8_scope.original.py",
    "r9-reader": "originals/verify_retained_transport_r9.original.py",
    "r9-scope": "originals/retained_r9_scope.original.py",
}


def load(raw, label):
    module = types.ModuleType(label)
    module.__file__ = "<offline-manifest-" + label + ">"
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    return module


def build():
    selector_path = "candidate/derived/reader_selector.py"
    loader_path = "candidate/derived/bound_selector_loader.py"
    raw = (BASE / selector_path).read_bytes()
    loader_raw = (BASE / loader_path).read_bytes()
    loader = load(loader_raw, "bound-selector-loader")
    # Check the separate source pin before compiling the selector for extraction.
    import hashlib
    if {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} != loader.SELECTOR_PIN:
        raise ValueError("actual selector implementation differs from independent loader pin")
    module = load(raw, "reader-selector")
    inventory = module.function_source((BASE / "candidate/inventory_value.py").read_bytes(), "inventory_value")
    scope = module.function_source((BASE / "candidate/derived/retained_r8_verify_complete_scope.py").read_bytes(),
                                   "verify_complete_scope")
    selector = loader.make_selector(selector_source=raw, implementation_source=raw,
                                   inventory_function=inventory, scope_function=scope)
    for kind, path in SOURCES.items():
        getattr(selector, kind.replace("-", "_"))((BASE / path).read_bytes())
    result = selector.receipt()
    result.update({"schema": "hepta.UNADOPTED.reader-selector-candidate.v1",
        "state": "OFFLINE_TESTED_NOT_PRODUCTION_ADOPTED",
        "selector_source": {"path": selector_path, **module.pin(raw)},
        "bound_loader_source": {"path": loader_path, **module.pin(loader_raw)},
        "constructor_source_and_receipt_binding": "exact independently pinned compiled bytes equal declared implementation bytes",
        "original_sources": [{"kind": kind, "path": path, **module.PINS[kind]} for kind, path in SOURCES.items()],
        "original_inventory_sources": module.INVENTORY_SOURCES,
        "original_inventory_function": module.ORIGINAL_INVENTORY_FUNCTION,
        "derived_inventory_function": module.DERIVED_INVENTORY_FUNCTION,
        "original_scope_function": module.ORIGINAL_SCOPE_FUNCTION,
        "derived_scope_function": module.DERIVED_SCOPE_FUNCTION,
        "nested_r7_r8_r9_inventory_validation_selected_explicitly": True,
        "historical_response_is_data_projection": True,
        "new_code_provenance_is_separate": True,
        "source_parent_full_boundary_composed": False,
        "new_runtime_policy_or_freeze_provided": False})
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw = json.dumps(build(), sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        if args.output.exists():
            raise ValueError("manifest output already exists; preserve the prior artifact")
        args.output.write_text(raw)
    print(raw, end="")
