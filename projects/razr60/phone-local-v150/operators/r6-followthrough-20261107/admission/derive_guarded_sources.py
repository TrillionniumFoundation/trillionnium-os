#!/usr/bin/env python3
"""Create a new, local source-only guard candidate from exact retained sources.

This tool never edits its inputs, patches a live Mac file, starts a child, uses
the network, creates a native nonce, or creates a new runtime task. The output
directory must not exist. No accepted disposition or deployment is produced.
"""
import argparse
import ast
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT_NAME = "run_component_root_once.py"
PREPARER_NAME = "prepare_native_bound_components_r6_fc33_successor02.py"
INPUTS = {
    ROOT_NAME: (78567, "53c2e7c26c960d76ac5d3201420d33f13fb06c241d30d40fc7b2b7577e690257"),
    PREPARER_NAME: (20902, "ff7f83db52bd067ffd6c41ebfd734a5414245c6e48224266da35fd2c37b9f77c"),
    "original_attempt_admission.py": (10422, "e268d050959228423003717a63e57106d608cd763d5d977b3f376982e8e9da0b"),
    "ORIGINAL-ATTEMPTS.json": (2943, "331e135d43cbe8dc8fa4136ff2b1af40a2fb2fab1e83ed71533e2d29df3dde70"),
    "current_check.py": (3887, "b0015fb4455bf87c97e99a206c65235456cc9e7a8e9986fa9fbe2719d8bb1a59"),
}
OUTPUTS = {'run_component_root_once.py': {'bytes': 79408, 'sha256': '66324bd333190b2dbfc62a4ef6badc1f4e6829ff3bba6f551e39eacaeb53c3be'}, 'prepare_native_bound_components_r6_fc33_successor02.py': {'bytes': 21567, 'sha256': 'df4d2a40d2df631cc598b6b79b6b6a095a3350287ad3925b62a6b9072d75751f'}, 'original_attempt_admission.py': {'bytes': 10422, 'sha256': 'e268d050959228423003717a63e57106d608cd763d5d977b3f376982e8e9da0b'}, 'ORIGINAL-ATTEMPTS.json': {'bytes': 2943, 'sha256': '331e135d43cbe8dc8fa4136ff2b1af40a2fb2fab1e83ed71533e2d29df3dde70'}, 'current_check.py': {'bytes': 3887, 'sha256': 'b0015fb4455bf87c97e99a206c65235456cc9e7a8e9986fa9fbe2719d8bb1a59'}}
ROOT_STAGES = (
    "coordinator.validate_plan",
    "coordinator.output_reservation",
    "coordinator.dispatch",
    "coordinator.main",
)
PREPARER_STAGES = (
    "preparer.selected_context",
    "preparer.before_nonce_and_reservation",
    "preparer.main",
)
GUARD_FUNCTION = "require_original_attempt_admission"


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def exact_input(name, raw):
    size, digest = INPUTS[name]
    need(type(raw) is bytes and len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
         "unreviewed baseline/input: " + name)


def stable_read(path):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path, "canonical source input required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= 1048576, "bounded single-link source required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(1048577)
        after, named = os.fstat(fd), path.lstat()
        keys = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                "st_size", "st_mtime_ns", "st_ctime_ns")
        need(len(raw) == before.st_size and all(
            getattr(before, k) == getattr(after, k) == getattr(named, k) for k in keys),
            "source changed while reading")
        return raw
    finally:
        os.close(fd)


def replace_once(raw, old, new):
    need(raw.count(old) == 1, "exact unique source insertion anchor required")
    return raw.replace(old, new, 1)


def root_loader():
    size, digest = INPUTS["original_attempt_admission.py"]
    return ("def require_original_attempt_admission(stage):\n"
            "    # New source-only hold; this does not grant an old original a terminal.\n"
            "    path=HERE/'original_attempt_admission.py'\n"
            "    raw=read(path,65536)\n"
            f"    need(len(raw)=={size} and sha(raw)=='{digest}',\n"
            "         'exact reviewed original-attempt guard source required')\n"
            "    guard=types.ModuleType('reviewed_original_attempt_admission')\n"
            "    guard.__file__=str(path)\n"
            "    exec(compile(raw,str(path),'exec'),guard.__dict__)\n"
            "    guard.require_successor_admission(stage=stage)\n\n\n").encode()


def preparer_loader():
    size, digest = INPUTS["original_attempt_admission.py"]
    return ("def require_original_attempt_admission(stage):\n"
            "    # Exact sidecar source, before helper loading/reservation/nonce generation.\n"
            "    path=Path(__file__).absolute().with_name('original_attempt_admission.py')\n"
            f"    row={{'path':str(path),'bytes':{size},'sha256':'{digest}'}}\n"
            "    raw=initial(row)\n"
            "    guard=module(raw,'reviewed_original_attempt_admission',path)\n"
            "    guard.require_successor_admission(stage=stage)\n\n\n").encode()


def root_candidate(raw):
    exact_input(ROOT_NAME, raw)
    need(GUARD_FUNCTION.encode() not in raw, "guard name must be new")
    raw = replace_once(raw, b"def validate_current_prior(p,previous,runtime,manifest):\n",
                       root_loader() + b"def validate_current_prior(p,previous,runtime,manifest):\n")
    for before, after in (
        (b"def validate_plan(raw):\n", b"def validate_plan(raw):\n    require_original_attempt_admission('coordinator.validate_plan')\n"),
        (b"    def __init__(self,plan,raw):\n", b"    def __init__(self,plan,raw):\n        require_original_attempt_admission('coordinator.output_reservation')\n"),
        (b"    def run(self):\n", b"    def run(self):\n        require_original_attempt_admission('coordinator.dispatch')\n"),
        (b"    a.add_argument('--execute-root-chain-once',action='store_true');v=a.parse_args()\n",
         b"    a.add_argument('--execute-root-chain-once',action='store_true');v=a.parse_args()\n    require_original_attempt_admission('coordinator.main')\n"),
    ):
        raw = replace_once(raw, before, after)
    return raw


def preparer_candidate(raw):
    exact_input(PREPARER_NAME, raw)
    need(GUARD_FUNCTION.encode() not in raw, "guard name must be new")
    raw = replace_once(raw, b"def selected_context(h,o,args):\n",
                       preparer_loader() + b"def selected_context(h,o,args):\n")
    for before, after in (
        (b"def selected_context(h,o,args):\n", b"def selected_context(h,o,args):\n    require_original_attempt_admission('preparer.selected_context')\n"),
        (b"def create(h,o,c,source,source_raw,preview):\n", b"def create(h,o,c,source,source_raw,preview):\n    require_original_attempt_admission('preparer.before_nonce_and_reservation')\n"),
        (b"    ap.add_argument('--create-host-plan-once',action='store_true');args=ap.parse_args()\n",
         b"    ap.add_argument('--create-host-plan-once',action='store_true');args=ap.parse_args()\n    require_original_attempt_admission('preparer.main')\n"),
    ):
        raw = replace_once(raw, before, after)
    return raw


def function_original(raw, name):
    tree = ast.parse(raw)
    rows = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    need(len(rows) == 1, "one original function required: " + name)
    lines = raw.splitlines(keepends=True)
    return b"".join(lines[rows[0].lineno - 1:rows[0].end_lineno])


def verify_only_guard_additions(before, after, stages):
    old_tree, tree = ast.parse(before), ast.parse(after)
    found = []
    definitions = []

    class RemoveNewGuard(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            if node.name == GUARD_FUNCTION:
                definitions.append(node)
                return None
            return self.generic_visit(node)

        def visit_Expr(self, node):
            call = node.value
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == GUARD_FUNCTION:
                need(len(call.args) == 1 and isinstance(call.args[0], ast.Constant)
                     and type(call.args[0].value) is str and not call.keywords,
                     "only the reviewed constant-stage guard call may be added")
                found.append(call.args[0].value)
                return None
            return self.generic_visit(node)

    stripped = RemoveNewGuard().visit(copy.deepcopy(tree))
    need(len(definitions) == 1 and sorted(found) == sorted(stages), "exact new guard definition/calls required")
    need(ast.dump(old_tree, include_attributes=False) == ast.dump(stripped, include_attributes=False),
         "existing program AST changed beyond the new guard")
    compile(after, "source_only_guard_candidate", "exec")
    return {"existing_program_ast_unchanged_after_removing_guard": True,
            "new_guard_definitions": 1, "new_entry_guards": found}


def derive(inputs):
    need(set(inputs) == set(INPUTS), "complete exact source/input set required")
    for name, raw in inputs.items():
        exact_input(name, raw)
    root = root_candidate(inputs[ROOT_NAME])
    preparer = preparer_candidate(inputs[PREPARER_NAME])
    checks = {
        "coordinator": verify_only_guard_additions(inputs[ROOT_NAME], root, ROOT_STAGES),
        "preparer": verify_only_guard_additions(inputs[PREPARER_NAME], preparer, PREPARER_STAGES),
    }
    old_prior = function_original(inputs[ROOT_NAME], "validate_current_prior")
    need(function_original(root, "validate_current_prior") == old_prior,
         "existing validate_current_prior must remain byte-identical")
    checks["validate_current_prior"] = {**pin(old_prior), "byte_identical": True}
    outputs = dict(inputs)
    outputs[ROOT_NAME], outputs[PREPARER_NAME] = root, preparer
    need(set(outputs) == set(OUTPUTS), "reviewed output pin set missing")
    for name, raw in outputs.items():
        need(pin(raw) == OUTPUTS[name], "derived output differs from reviewed target: " + name)
    return outputs, checks


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    base = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-source", type=Path, default=base / "reference" / ROOT_NAME)
    parser.add_argument("--preparer-source", type=Path, default=base / "reference" / PREPARER_NAME)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    paths = {name: base / name for name in INPUTS}
    paths[ROOT_NAME], paths[PREPARER_NAME] = args.root_source, args.preparer_source
    originals = {name: stable_read(path) for name, path in paths.items()}
    outputs, checks = derive(originals)
    out = args.out.absolute()
    need(out.parent.resolve(strict=True) == out.parent, "canonical output parent required")
    # All source validation/compilation precedes the only directory creation.
    out.mkdir(mode=0o700)
    for name, raw in outputs.items():
        write_new(out / name, raw)
    changes = out / "changes"
    changes.mkdir(mode=0o700)
    for name in (ROOT_NAME, PREPARER_NAME):
        patch = "".join(difflib.unified_diff(originals[name].decode().splitlines(keepends=True),
                                           outputs[name].decode().splitlines(keepends=True),
                                           fromfile="reference/" + name, tofile=name))
        write_new(changes / (name + ".patch"), patch.encode())
    manifest = {
        "schema": "hepta.r6.original-attempt-guard-source-derivation.v1",
        "state": "SOURCE_ONLY_BLOCKED_ORIGINAL_BOUND02_NO_DEPLOYMENT",
        "inputs": {name: pin(raw) for name, raw in originals.items()},
        "outputs": {name: pin(raw) for name, raw in outputs.items()},
        "derivation_source": pin(stable_read(Path(__file__))),
        "checks": checks,
        "actual_mac_preparer_used": True,
        "old_frozen_files_modified": False,
        "original_outcome_rewritten": False,
        "automatic_disposition_or_override_supported": False,
        "source_package_refreeze_still_required": True,
        "new_runtime_combination": None,
        "live_guard_enforcement_proven": False,
        "phone_calls": 0,
        "native_nonce_generations": 0,
        "runtime_dispatches": 0,
        "component_qualified": False,
        "full19_qualified": False,
    }
    write_new(out / "SOURCE-DERIVATION.json", encoded(manifest))
    print(encoded({"state": manifest["state"], "outputs": manifest["outputs"], "checks": checks}).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
