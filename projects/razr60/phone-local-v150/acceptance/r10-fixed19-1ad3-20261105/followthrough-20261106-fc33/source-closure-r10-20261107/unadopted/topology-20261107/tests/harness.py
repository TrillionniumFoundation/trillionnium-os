"""Offline loaders for the exact original and the unadopted pure fragment."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types
import zlib


BASE = Path(__file__).resolve().parents[1]
SOURCE_PIN = {"bytes": 259866,
              "sha256": "f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7"}
COMMON_PIN = {"bytes": 19138,
              "sha256": "1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab"}


def pin(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


def exact_bytes(path, expected):
    raw = path.read_bytes()
    if pin(raw) != expected:
        raise AssertionError("offline source/fixture pin differs: " + str(path))
    return raw


def function_ast(raw, name):
    nodes = [n for n in ast.parse(raw).body
             if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(nodes) != 1:
        raise AssertionError("one exact function required: " + name)
    return nodes[0]


def original_common():
    raw = exact_bytes(BASE / "originals/component_common.r10.original.py", COMMON_PIN)
    tree = ast.parse(raw)
    needed = [n for n in tree.body if
              (isinstance(n, ast.FunctionDef) and n.name == "need") or
              (isinstance(n, ast.Assign) and len(n.targets) == 1 and
               isinstance(n.targets[0], ast.Name) and n.targets[0].id == "HASH")]
    if len(needed) != 2:
        raise AssertionError("the exact original need and HASH definitions are required")
    namespace = {"re": re}
    exec(compile(ast.Module(body=needed, type_ignores=[]),
                 "<pinned-common-pure-fragment>", "exec"), namespace)
    return types.SimpleNamespace(need=namespace["need"], HASH=namespace["HASH"])


def load_inventory(raw, label):
    node = function_ast(raw, "inventory_value")
    namespace = {"C": original_common(), "Path": Path, "re": re, "stat": stat}
    # No runtime module is imported or executed.  Only this pure function's AST
    # is compiled, with the original pure assertion and hash-pattern definitions.
    exec(compile(ast.Module(body=[node], type_ignores=[]), label, "exec"), namespace)
    return namespace["inventory_value"]


def implementations():
    original_raw = exact_bytes(BASE / "originals/late_boundary.r10.original.py", SOURCE_PIN)
    manifest = json.loads((BASE / "CANDIDATE-MANIFEST.json").read_text())
    row = manifest["candidate_fragment"]
    candidate_raw = exact_bytes(BASE / row["path"], {k: row[k] for k in ("bytes", "sha256")})
    return (load_inventory(original_raw, "<pinned-R10-inventory_value>"),
            load_inventory(candidate_raw, "<unadopted-prefix-inventory_value>"))


def fixtures():
    if os.environ.get("HEPTA_TOPOLOGY_SYNTHETIC_ONLY") == "1":
        return []
    manifest = json.loads((BASE / "fixtures/MANIFEST.json").read_text())
    result = []
    for row in manifest["fixtures"]:
        compressed = exact_bytes(BASE / row["path"], {
            "bytes": row["compressed_bytes"], "sha256": row["compressed_sha256"]})
        z = zlib.decompressobj()
        raw = z.decompress(compressed, row["bytes"] + 1)
        if not z.eof or z.unused_data or z.unconsumed_tail or pin(raw) != {
                k: row[k] for k in ("bytes", "sha256")}:
            raise AssertionError("exact complete fixture decompression required")
        value = json.loads(raw)
        if len(value["roots"]) != row["roots"] or len(value["entries"]) != row["entries"]:
            raise AssertionError("fixture cardinalities differ")
        result.append((row, value))
    return result


def outcome(function, value):
    # A fresh copy also checks that neither implementation mutates the input.
    trial = copy.deepcopy(value)
    before = copy.deepcopy(trial)
    try:
        output = function(trial)
    except Exception as error:
        result = {"accepted": False, "exception_type": type(error).__name__,
                  "message": str(error)}
    else:
        result = {"accepted": True, "output": output}
    if trial != before:
        raise AssertionError("a pure validator mutated its input")
    return result


def directory_inventory(roots):
    entries = {root: {"kind": "directory", "metadata":
                     [1, index + 1, stat.S_IFDIR | 0o700, 0, 0, 2, 0, 0, 0],
                     "names": []} for index, root in enumerate(roots)}
    return {"schema": "hepta.native-guard.complete-inventory.v1", "roots": list(roots),
            "entries": entries, "file_bytes_hashed": 0, "elapsed_seconds": 0.0,
            "inventory_is_closure_or_retirement": False}


def file_inventory(sizes=(1, 7), root="/scope"):
    value = directory_inventory([root])
    names = ["file-%02d" % index for index in range(len(sizes))]
    value["entries"][root]["names"] = names
    for index, (name, size) in enumerate(zip(names, sizes)):
        value["entries"][root + "/" + name] = {
            "kind": "file", "metadata":
            [1, index + 2, stat.S_IFREG | 0o600, 0, 0, 1, size, 0, 0],
            "bytes": size, "sha256": "ab" * 32}
    value["file_bytes_hashed"] = sum(sizes)
    return value
