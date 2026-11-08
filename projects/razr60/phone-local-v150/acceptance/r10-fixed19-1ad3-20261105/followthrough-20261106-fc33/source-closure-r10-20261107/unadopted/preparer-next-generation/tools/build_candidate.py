#!/usr/bin/env python3
"""Rebuild inert source and review metadata. --check is read-only; no runtime use."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("unbound_preparer_binding", ROOT / "candidate/preparer_binding.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def build():
    original = (ROOT / "originals/prepare_native_bound_components_r10_fc33.original.py").read_bytes()
    derived, receipt = module.derive_unbound_preparer(original)
    receipt["deriver_source"] = module.pin((ROOT / "candidate/preparer_binding.py").read_bytes())
    receipt["builder_source"] = module.pin(Path(__file__).read_bytes())
    products = {
        "candidate/prepare_next_generation_UNBOUND.py": derived,
        "FUTURE-BINDING-UNBOUND.json": module.encoded(module.binding_template()),
        "PREPARER-CANDIDATE-MANIFEST.json": (json.dumps(receipt, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode(),
    }
    return products


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify the deterministic products without writing")
    args = parser.parse_args()
    products = build()
    for name, raw in products.items():
        target = ROOT / name
        if args.check:
            if target.read_bytes() != raw:
                raise SystemExit("deterministic product differs: " + name)
        elif target.exists():
            if target.read_bytes() != raw:
                raise SystemExit("refusing to overwrite a different candidate product: " + name)
        else:
            with target.open("xb") as output:
                output.write(raw)
    print(json.dumps({"state": "PASS_INERT_SOURCE_REBUILD_ONLY", "check_only": args.check,
                      "files": {name: module.pin(raw) for name, raw in products.items()},
                      "runtime_admission": False, "production_adopted": False}, sort_keys=True))
