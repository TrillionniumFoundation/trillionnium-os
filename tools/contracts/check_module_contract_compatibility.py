#!/usr/bin/env python3
"""Fail-closed semantic compatibility check for generated module contracts."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CATALOG = "docs/machine/module-contract-catalog.v1.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def finite_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError(f"nonfinite JSON number: {raw}")
    return value


def load(raw: bytes, label: str) -> Any:
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
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"{label}: nonfinite {value}")
        ),
        parse_float=finite_float,
    )


def git(args: list[str], label: str, *, root: Path = ROOT) -> bytes:
    result = subprocess.run(
        ["git", "--no-replace-objects", *args],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(f"{label}: git returned {result.returncode}: {detail}")
    return result.stdout


def resolve_commit(ref: str, *, root: Path = ROOT) -> str:
    if not isinstance(ref, str) or not ref or "\x00" in ref or "\n" in ref:
        raise ValueError("base ref is malformed")
    raw = git(
        ["rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
        "resolve base ref",
        root=root,
    )
    values = raw.decode("ascii", "strict").splitlines()
    if len(values) != 1 or SHA40.fullmatch(values[0]) is None:
        raise ValueError("base ref did not resolve to one exact commit")
    commit = values[0]
    git(
        ["merge-base", "--is-ancestor", commit, "HEAD"],
        "verify base ancestry",
        root=root,
    )
    return commit


def show(
    commit: str,
    path: str,
    *,
    allow_absent: bool = False,
    root: Path = ROOT,
) -> bytes | None:
    if SHA40.fullmatch(commit) is None:
        raise ValueError("show requires an exact commit")
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or "\n" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise ValueError(f"unsafe tree path: {path!r}")

    listing = git(
        ["ls-tree", "-z", "--full-tree", commit, "--", path],
        f"inspect {path} in verified base",
        root=root,
    )
    entries = [entry for entry in listing.split(b"\0") if entry]
    if not entries:
        if allow_absent:
            return None
        raise ValueError(f"verified base path is absent: {path}")
    if len(entries) != 1:
        raise ValueError(f"verified base path is ambiguous: {path}")

    metadata, separator, encoded_name = entries[0].partition(b"\t")
    if not separator:
        raise ValueError(f"malformed ls-tree result for {path}")
    try:
        mode, kind, object_id = metadata.decode("ascii", "strict").split(" ")
        observed_name = encoded_name.decode("utf-8", "strict")
    except (UnicodeError, ValueError) as error:
        raise ValueError(f"malformed ls-tree identity for {path}") from error
    if (
        observed_name != path
        or kind != "blob"
        or mode not in {"100644", "100755"}
        or SHA40.fullmatch(object_id) is None
    ):
        raise ValueError(f"verified base object is not one regular tracked file: {path}")
    return git(["cat-file", "blob", object_id], f"read verified base file {path}", root=root)


NON_SEMANTIC = {
    "$schema",
    "$id",
    "title",
    "description",
    "examples",
    "x-trillionnium-binding",
}
NAMED_SCHEMA_MAPS = {
    "$defs",
    "definitions",
    "properties",
    "patternProperties",
    "dependentSchemas",
}
SCHEMA_SINGLE = {
    "additionalProperties",
    "unevaluatedProperties",
    "propertyNames",
    "contains",
    "contentSchema",
    "if",
    "then",
    "else",
    "not",
    "unevaluatedItems",
}
SCHEMA_ARRAYS = {"allOf", "anyOf", "oneOf", "prefixItems"}


def normalized_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalized_data(item)
            for key, item in sorted(value.items())
        }
    if isinstance(value, list):
        return [normalized_data(item) for item in value]
    return value


def fingerprint(value: Any) -> Any:
    """Remove annotations only where the dictionary is a JSON Schema object."""
    if isinstance(value, bool):
        return value
    if not isinstance(value, dict):
        return normalized_data(value)

    result = {}
    for key, item in sorted(value.items()):
        if key in NON_SEMANTIC:
            continue
        if key in NAMED_SCHEMA_MAPS and isinstance(item, dict):
            # Keys here are application property/definition names. They are
            # semantic even when they happen to be called "title" or "$id".
            result[key] = {
                name: fingerprint(child)
                for name, child in sorted(item.items())
            }
        elif key == "dependencies" and isinstance(item, dict):
            result[key] = {
                name: (
                    fingerprint(child)
                    if isinstance(child, (dict, bool))
                    else normalized_data(child)
                )
                for name, child in sorted(item.items())
            }
        elif key in SCHEMA_SINGLE and isinstance(item, (dict, bool)):
            result[key] = fingerprint(item)
        elif key == "items":
            if isinstance(item, list):
                result[key] = [fingerprint(child) for child in item]
            elif isinstance(item, (dict, bool)):
                result[key] = fingerprint(item)
            else:
                result[key] = normalized_data(item)
        elif key in SCHEMA_ARRAYS and isinstance(item, list):
            result[key] = [fingerprint(child) for child in item]
        else:
            # Values of const/enum/default-like or unknown extension keywords
            # are data, not automatically nested schemas. Preserve them.
            result[key] = normalized_data(item)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-ref", required=True)
    args = parser.parse_args()

    current = load((ROOT / CATALOG).read_bytes(), CATALOG)
    base_commit = resolve_commit(args.base_ref)
    old_raw = show(base_commit, CATALOG, allow_absent=True)
    if old_raw is None:
        for module in current["modules"]:
            compatibility = load(
                (ROOT / module["artifacts"]["compatibility"]).read_bytes(),
                module["module_id"],
            )
            if compatibility.get("change_review_class") != "INITIAL_V1":
                raise SystemExit("initial contract lacks INITIAL_V1 review class")
        print(
            json.dumps(
                {
                    "base_commit": base_commit,
                    "modules": current["module_count"],
                    "public_release": False,
                    "result": "PASS_INITIAL_V1",
                },
                sort_keys=True,
            )
        )
        return 0

    old = load(old_raw, CATALOG)
    old_by = {item["module_id"]: item for item in old["modules"]}
    current_by = {item["module_id"]: item for item in current["modules"]}
    if set(old_by) != set(current_by):
        raise SystemExit(
            "module set changed without a separately reviewed catalog migration"
        )

    changed = []
    for module_id in sorted(current_by):
        for kind in ("api", "state", "errors"):
            new_path = current_by[module_id]["artifacts"][kind]
            old_path = old_by[module_id]["artifacts"][kind]
            old_schema_raw = show(base_commit, old_path)
            if fingerprint(load(old_schema_raw, old_path)) != fingerprint(
                load((ROOT / new_path).read_bytes(), new_path)
            ):
                changed.append(f"{module_id}:{kind}")
        compatibility = load(
            (ROOT / current_by[module_id]["artifacts"]["compatibility"]).read_bytes(),
            module_id,
        )
        if (
            any(item.startswith(module_id + ":") for item in changed)
            and compatibility.get("change_review_class") == "NO_CHANGE"
        ):
            raise SystemExit(
                "semantic schema drift lacks migration/rollback review class: "
                f"{module_id}"
            )

    print(
        json.dumps(
            {
                "base_commit": base_commit,
                "public_release": False,
                "result": "PASS",
                "semantic_changes": changed,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        print(f"module-contract compatibility failed: {error}", file=sys.stderr)
        raise SystemExit(2)
