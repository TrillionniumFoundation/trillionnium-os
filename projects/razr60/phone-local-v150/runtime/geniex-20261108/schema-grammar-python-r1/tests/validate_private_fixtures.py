#!/usr/bin/env python3
"""CPU-only pocket4 oracle job; private fixture values never leave that host.

No phone or inference access. Immutable input schema bytes are checked against
the existing manifest; only independent output files are created. This is a
semantic fixture check, not evidence that a phone action has happened.
"""
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

BASE = Path("/home/alex/razr60-local-model-v150/offline-gpu-integration-20261108/schema-grammar-python-r1-host")
MANIFEST = Path("/home/alex/razr60-local-model-v150/offline-gpu-integration-20261108/private-provider-candidate/geniex-native-r5/catalogue-prompt-fixtures/MANIFEST.json")
MANIFEST_SHA = "8a32dc4b8e1ab1567c2253b2e25e22cd9090322fc8b31b7127e49a8b946a66f0"
SOURCE_SHA = "c230e076ae61c87a744c49b160a456c039d47441784ad3ccc2c6465bc67453a8"
EXE_SHA = "02e822631e002b2d210cc6b6eea57937c0961d114cfc01e278c06a61a56ad03f"
GZIP_SHA = "8fb0ee606d51348ec09d39560ffb8b1a44a32626c7d1e7dd7dee909e9d32896a"
HELPER_SHA = "2230701186c5757fe518da5d0a3f2df82ebd339efdd9fda1b5f25e7a289b25d9"
RECOGNIZER_SHA = "a9317c9eb2e7461e9b4656a8541791e7f13ca9b60e9c0296d2d4ac94970ab1c3"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, reason):
    if not value:
        raise ValueError(reason)


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).replace("\x7f", r"\u007f").encode()


def read(path, maximum, expected):
    need(path.is_absolute() and path.resolve(strict=True) == path, "input canonical path differs")
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= maximum, "input identity/size differs")
    raw = path.read_bytes()
    after = path.lstat()
    need(all(getattr(st, k) == getattr(after, k) for k in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")),
         "input changed")
    need(sha(raw) == expected, "input SHA differs")
    return raw


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
    finally:
        os.close(fd)
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def load(name, filename, expected):
    path = BASE / filename
    raw = read(path, 131072, expected)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Compile the already verified bytes, avoiding an unchecked .pyc/import.
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def sample(node):
    if "const" in node:
        return node["const"]
    if "enum" in node:
        return node["enum"][0]
    kind = node["type"]
    if kind == "object":
        return {key: sample(child) for key, child in node["properties"].items()}
    if kind == "array":
        return [sample(child) for child in node["prefixItems"]]
    if kind == "integer":
        return node["minimum"]
    if "pattern" in node:
        return "org.fixture:id/value" if ":id/" in node["pattern"] else "org.fixture"
    return "x" * node.get("minLength", 0)


def accepts(value, node):
    if "oneOf" in node:
        return sum(accepts(value, part) for part in node["oneOf"]) == 1
    if "const" in node and (type(value) is not type(node["const"]) or value != node["const"]):
        return False
    if "enum" in node and not any(type(value) is type(x) and value == x for x in node["enum"]):
        return False
    kind = node.get("type")
    if kind is None:
        return True
    if type(value) is not {"string": str, "integer": int, "object": dict, "array": list}[kind]:
        return False
    if kind == "object":
        return set(value) == set(node["properties"]) and set(node["required"]) <= set(value) and \
            all(accepts(value[k], child) for k, child in node["properties"].items())
    if kind == "array":
        return len(value) == len(node["prefixItems"]) == node["minItems"] == node["maxItems"] and \
            all(accepts(v, child) for v, child in zip(value, node["prefixItems"]))
    if kind == "integer":
        return node["minimum"] <= value <= node["maximum"]
    return node.get("minLength", 0) <= len(value) <= node.get("maxLength", len(value)) and \
        ("pattern" not in node or re.fullmatch(node["pattern"], value) is not None)


def mutations(node, value):
    if node.get("type") == "object":
        for key, child in node["properties"].items():
            missing = copy.deepcopy(value); del missing[key]
            yield missing
            for changed in mutations(child, value[key]):
                result = copy.deepcopy(value); result[key] = changed
                yield result
        result = copy.deepcopy(value); result["unexpected"] = 0
        yield result
    elif "enum" in node:
        yield from node["enum"]
        yield "not_in_the_current_registered_enum"
    elif "const" in node:
        yield "different_constant"
    elif node.get("type") == "array":
        yield []
        yield value + [0]
        for index, child in enumerate(node["prefixItems"]):
            for changed in mutations(child, value[index]):
                result = copy.deepcopy(value); result[index] = changed
                yield result
    elif node.get("type") == "integer":
        yield from [node["minimum"] - 1, node["minimum"], node["maximum"], node["maximum"] + 1, True, 0.0]
    elif node.get("type") == "string" and "pattern" not in node:
        maximum = node["maxLength"]
        yield from ["", "中🙂", "quote\"slash\\newline\n", "x" * maximum, "x" * (maximum + 1)]


def main():
    os.umask(0o077)
    BASE.chmod(0o700)
    archive = read(BASE / "host-static.gz", 1145215, GZIP_SHA)
    raw = gzip.decompress(archive)
    need(len(raw) == 3166104 and sha(raw) == EXE_SHA, "reference executable differs")
    executable = BASE / "hepta-schema-gbnf"
    write(executable, raw)
    executable.chmod(0o700)
    python = load("reviewed_python", "python_schema_grammar.py", SOURCE_SHA)
    reference = load("reference_cpp", "reference_convert_schema.py", HELPER_SHA)
    recognizer = load("independent_recognizer", "gbnf_recognizer.py", RECOGNIZER_SHA)
    elf = reference.static_elf_contract(raw)
    original = read(MANIFEST, 65536, MANIFEST_SHA)
    manifest = json.loads(original)
    need(len(manifest["cases"]) == 2, "two original cases required")
    out = BASE / "actual-r9-fixtures"
    out.mkdir(mode=0o700, exist_ok=False)
    results = []
    for index, row in enumerate(manifest["cases"], 1):
        source = row["files"]["model-schema.json"]
        path = Path(source["path"])
        need(path.is_relative_to(MANIFEST.parent), "schema outside pinned fixture")
        schema_bytes = read(path, 65536, source["sha256"])
        need(len(schema_bytes) == source["bytes"], "manifest schema bytes differ")
        schema = json.loads(schema_bytes)
        started = time.monotonic()
        grammar, proof = python.convert_schema(schema_bytes, compiler_source_sha256=SOURCE_SHA)
        conversion_seconds = time.monotonic() - started
        oracle, oracle_proof = reference.convert_schema(schema_bytes, executable=executable, executable_sha256=EXE_SHA)
        ours, other = recognizer.Recognizer(grammar), recognizer.Recognizer(oracle)
        counts = {"valid": 0, "invalid": 0}
        for branch in schema["oneOf"]:
            example = sample(branch)
            for value in [example, *mutations(branch, example)]:
                expected = accepts(value, schema)
                serialized = encode(value)
                need(ours.accepts(serialized) == expected and other.accepts(serialized) == expected,
                     "independent schema/GBNF differential mismatch")
                counts["valid" if expected else "invalid"] += 1
        prefix = "case-%02d" % index
        saved = {"grammar": write(out / (prefix + ".gbnf"), grammar),
                 "conversion": write(out / (prefix + "-conversion.json"), encode(proof)),
                 "oracle_grammar": write(out / (prefix + "-oracle.gbnf"), oracle),
                 "oracle_conversion": write(out / (prefix + "-oracle-conversion.json"), encode(oracle_proof))}
        results.append({"index": index, "source_schema": {"path": str(path), "bytes": len(schema_bytes), "sha256": sha(schema_bytes)},
                        "branches": len(schema["oneOf"]), "counts": counts, "python_conversion_seconds": conversion_seconds,
                        "files": saved, "pass": True})
    report = {"schema": "hepta.actual-r9-schema-python-oracle.v1", "all_pass": True,
              "source_manifest_sha256": MANIFEST_SHA, "compiler_source_sha256": SOURCE_SHA,
              "reference_executable_sha256": EXE_SHA, "reference_elf": elf, "cases": results,
              "scope": "original_r9_generated_host_semantic_fixtures_not_phone_actions",
              "model_requests": 0, "phone_accessed": False, "proc_grammar_parser_tested": False,
              "private_schema_bytes_left_pocket4": False}
    write(out / "RESULT.json", encode(report))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
