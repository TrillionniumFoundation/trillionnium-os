#!/usr/bin/env python3
"""Fail-closed semantic compatibility check for generated module contracts."""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATALOG = "docs/machine/module-contract-catalog.v1.json"


def load(raw, label):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"{label}: duplicate member {key}")
            out[key] = value
        return out
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"{label}: nonfinite {value}")),
    )


def show(ref, path):
    result = subprocess.run(
        ["git", "--no-replace-objects", "show", f"{ref}:{path}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        timeout=30,
    )
    return result.stdout if result.returncode == 0 else None


NON_SEMANTIC = {"$schema", "$id", "title", "description", "examples", "x-trillionnium-binding"}


def fingerprint(value):
    if isinstance(value, dict):
        return {
            key: fingerprint(item)
            for key, item in sorted(value.items())
            if key not in NON_SEMANTIC
        }
    if isinstance(value, list):
        return [fingerprint(item) for item in value]
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-ref", required=True)
    args = parser.parse_args()
    current = load((ROOT / CATALOG).read_bytes(), CATALOG)
    old_raw = show(args.base_ref, CATALOG)
    if old_raw is None:
        for module in current["modules"]:
            compatibility = load(
                (ROOT / module["artifacts"]["compatibility"]).read_bytes(),
                module["module_id"],
            )
            if compatibility.get("change_review_class") != "INITIAL_V1":
                raise SystemExit("initial contract lacks INITIAL_V1 review class")
        print(json.dumps({"result":"PASS_INITIAL_V1","modules":current["module_count"],"public_release":False},sort_keys=True))
        return 0
    old = load(old_raw, CATALOG)
    old_by = {item["module_id"]: item for item in old["modules"]}
    current_by = {item["module_id"]: item for item in current["modules"]}
    if set(old_by) != set(current_by):
        raise SystemExit("module set changed without a separately reviewed catalog migration")
    changed = []
    for module_id in sorted(current_by):
        for kind in ("api", "state", "errors"):
            new_path = current_by[module_id]["artifacts"][kind]
            old_path = old_by[module_id]["artifacts"][kind]
            old_schema_raw = show(args.base_ref, old_path)
            if old_schema_raw is None:
                raise SystemExit(f"base schema missing: {module_id}/{kind}")
            if fingerprint(load(old_schema_raw, old_path)) != fingerprint(load((ROOT / new_path).read_bytes(), new_path)):
                changed.append(f"{module_id}:{kind}")
        compatibility = load(
            (ROOT / current_by[module_id]["artifacts"]["compatibility"]).read_bytes(),
            module_id,
        )
        if any(item.startswith(module_id + ":") for item in changed) and compatibility.get("change_review_class") == "NO_CHANGE":
            raise SystemExit(f"semantic schema drift lacks migration/rollback review class: {module_id}")
    print(json.dumps({"result":"PASS","semantic_changes":changed,"public_release":False},sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"module-contract compatibility failed: {error}", file=sys.stderr)
        raise SystemExit(2)
