#!/usr/bin/env python3
"""Add observational hooks to exactly the qualified MNN checkout.

This does not alter model math, sampling, or backend selection. The linked probe
uses the hooks to reject a global OpenCL -> CPU fallback and oversized prompts.
"""
import argparse
import hashlib
import json
from pathlib import Path

REVISION = "bce7456ce60b5e51b4d3b357f303515860353d8c"
FILES = {
    "express/Executor.cpp": "79fd37b7111e91201efcbca12aa61f287d6ffe7d05a95cc7e9b215a6990cda05",
    "source/core/Pipeline.cpp": "f7cd899354b062e55f19643a3b88becfcf4a33983f57b249362a4d72ded2cfa2",
    "transformers/llm/engine/src/llm.cpp": "30fafe27c266787512fd6a0a18811f7c7aeaed4b0215d185599e8e50777cf0b8",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def transform(name, source):
    if name == "express/Executor.cpp":
        declaration = 'extern "C" __attribute__((weak)) void hepta_mnn_runtime(int, int);\n'
        old = "    auto type      = Schedule::getAppropriateType(config);"
        new = old + "\n    if (hepta_mnn_runtime) hepta_mnn_runtime((int)config.type, (int)type);"
        expected = 1
    elif name == "source/core/Pipeline.cpp":
        declaration = 'extern "C" __attribute__((weak)) void hepta_mnn_observe(const char*, const char*, int, int);\n'
        old = "auto code = cmd.execution->onExecute(cmd.workInputs, cmd.workOutputs);"
        new = old + '\n                if (hepta_mnn_observe) hepta_mnn_observe(\n                    cmd.op ? EnumNameOpType(cmd.op->type()) : "unknown",\n                    (cmd.op && cmd.op->name()) ? cmd.op->name()->c_str() : "",\n                    cmd.execution->backend() ? (int)cmd.execution->backend()->type() : -1, (int)code);'
        expected = 3
    else:
        declaration = '#include <cstddef>\nextern "C" __attribute__((weak)) void hepta_mnn_input_ids(const int*, std::size_t);\n'
        old = "    std::vector<int> input_ids = tokenizer_encode(multimodal_input_copy);"
        new = old + "\n    if (hepta_mnn_input_ids) hepta_mnn_input_ids(input_ids.data(), input_ids.size());"
        expected = 1
    if source.count(old) != expected:
        raise ValueError(f"hook location mismatch: {name}")
    return "// HEPTA_MODEL_ONLY_OBSERVATION_HOOKS_R1\n" + declaration + source.replace(old, new)


def apply(root, originals=None):
    changes = []
    for name, pin in FILES.items():
        path = root / name
        raw = path.read_bytes()
        if originals is not None:
            original = (originals / Path(name).name).read_bytes()
        elif raw.startswith(b"// HEPTA_MODEL_ONLY_OBSERVATION_HOOKS_R1\n"):
            backup = root / ".hepta-probe-originals" / name
            original = backup.read_bytes()
        else:
            original = raw
        if digest(original) != pin:
            raise ValueError(f"upstream pin mismatch: {name}")
        patched = transform(name, original.decode("utf-8")).encode("utf-8")
        if raw not in (original, patched):
            raise ValueError(f"modified source rejected: {name}")
        changes.append((path, original, patched))
    # Validate every file before mutating any file.
    for path, original, patched in changes:
        backup = root / ".hepta-probe-originals" / path.relative_to(root)
        backup.parent.mkdir(parents=True, exist_ok=True)
        if backup.exists() and backup.read_bytes() != original:
            raise ValueError(f"original backup mismatch: {path}")
        backup.write_bytes(original)
        path.write_bytes(patched)
    return {str(path.relative_to(root)): {"upstream_sha256": digest(original),
            "patched_sha256": digest(patched)} for path, original, patched in changes}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    report = {"mnn_revision": REVISION, "files": apply(args.source.resolve())}
    print(json.dumps(report, sort_keys=True, indent=2))
