#!/usr/bin/env python3
"""Build a separate reviewed provider source candidate; never launch/deploy it.

Run this on pocket4 for a private r9 source base. It copies existing bindings
only within the newly named local candidate directory and emits its manifest
there. Private code, config and proof are never uploaded by this script.
"""
from __future__ import annotations
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import shutil


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def one(nodes, predicate, description):
    values = [node for node in nodes if predicate(node)]
    if len(values) != 1:
        raise ValueError("ambiguous or missing " + description)
    return values[0]


def target_assignment(node, name):
    return isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == name for x in node.targets)


def function(tree, klass, name):
    cls = one(tree.body, lambda n: isinstance(n, ast.ClassDef) and n.name == klass, klass)
    return one(cls.body, lambda n: isinstance(n, ast.FunctionDef) and n.name == name, klass + "." + name)


def provider_overlay(source):
    tree = ast.parse(source)
    method = function(tree, "PhoneLocalAdapter", "completion")
    original = copy.deepcopy(method)
    body_assignment = one(method.body, lambda n: target_assignment(n, "body"), "model request construction")
    slot_before = one(method.body, lambda n: target_assignment(n, "before") and isinstance(n.value, ast.Call)
                      and isinstance(n.value.func, ast.Name) and n.value.func.id == "inspect_single_slot", "legacy CPU slot observation")
    request_try = one(method.body, lambda n: isinstance(n, ast.Try)
                      and any(target_assignment(x, "result") for x in n.body), "legacy response try")
    result_assignment = one(request_try.body, lambda n: target_assignment(n, "result"), "parsed legacy result")
    tail = copy.deepcopy(request_try.body[request_try.body.index(result_assignment) + 1:])
    if not tail or not isinstance(tail[-1], ast.Return):
        raise ValueError("common typed-decision tail changed")
    forbidden = {"process", "streams", "output", "receipt", "response_path", "receipt_path"}
    if any(isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in forbidden
           for statement in tail for node in ast.walk(statement)):
        raise ValueError("common decision tail depends on HTTP-only state")
    presentation = ast.parse("body = geniex_prepare_body(self, body)").body[0]
    method.body.insert(method.body.index(body_assignment) + 1, presentation)
    branch = ast.parse("if getattr(self.args, 'geniex_backend', None) is not None:\n"
                       "    result = geniex_complete(self, body, prefix, request_id)\n"
                       "    if result is None:\n        return None\n").body[0]
    branch.body.extend(tail)
    method.body.insert(method.body.index(slot_before), branch)
    # Verify that removing only the explicit new presentation/branch recreates
    # the exact original method AST, including every private r9 ledger guard.
    reduced = copy.deepcopy(method)
    reduced.body = [node for node in reduced.body if node is not None]
    del reduced.body[method.body.index(branch)]
    del reduced.body[method.body.index(presentation)]
    if ast.dump(reduced, include_attributes=False) != ast.dump(original, include_attributes=False):
        raise ValueError("legacy completion AST changed")
    tree.body.insert(1, ast.parse("from provider_bridge import prepare_body as geniex_prepare_body, complete as geniex_complete").body[0])
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n", {"legacy_completion_ast_sha256": digest(ast.dump(original, include_attributes=False).encode()),
                                     "legacy_completion_recovered_exactly": True,
                                     "common_decision_tail_ast_sha256": digest(ast.dump(ast.Module(body=tail, type_ignores=[]), include_attributes=False).encode())}


def daily_overlay(source, file_hashes):
    tree = ast.parse(source)
    main = one(tree.body, lambda n: isinstance(n, ast.FunctionDef) and n.name == "main", "daily main")
    parse = one(main.body, lambda n: target_assignment(n, "args") and isinstance(n.value, ast.Call)
                and isinstance(n.value.func, ast.Attribute) and n.value.func.attr == "parse_args", "argument parsing")
    main.body.insert(main.body.index(parse), ast.parse("p.add_argument('--geniex-config', type=Path)").body[0])
    cleanup_options = [node for node in main.body if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "add_argument" and node.value.args
        and isinstance(node.value.args[0], ast.Constant) and node.value.args[0].value == "--slot-cleanup-binding"]
    if cleanup_options:
        if len(cleanup_options) != 1:
            raise ValueError("ambiguous CPU cleanup selector")
        # The deployed r9 launch always supplies a real CPU-instance binding.
        # The new backend must neither require nor consume a fictional one.
        # Explicitly preserve that launch requirement for selected CPU mode.
        for keyword in cleanup_options[0].value.keywords:
            if keyword.arg == "required":
                keyword.value = ast.Constant(False)
        main.body[main.body.index(parse)+1:main.body.index(parse)+1] = ast.parse(
            "if args.geniex_config is None and args.slot_cleanup_binding is None:\n"
            "    p.error('--slot-cleanup-binding is required for the CPU backend')\n"
            "if args.geniex_config is not None and args.slot_cleanup_binding is not None:\n"
            "    p.error('GenieX uses native process receipts; a CPU cleanup binding is not applicable')\n").body
    model = one(main.body, lambda n: isinstance(n, ast.Assign) and any(isinstance(t, ast.Attribute)
                and isinstance(t.value, ast.Name) and t.value.id == "args" and t.attr == "model" for t in n.targets), "model selection")
    main.body.insert(main.body.index(model), ast.parse("if args.geniex_config is not None:\n"
         "    from provider_bridge import configure as configure_geniex\n"
         "    configure_geniex(args, args.geniex_config)\n").body[0])
    parents = one(tree.body, lambda n: target_assignment(n, "PARENTS"), "source pins")
    values = ast.literal_eval(parents.value)
    values.update(file_hashes)
    parents.value = ast.parse(repr(values), mode="eval").body
    # Ready metadata explicitly identifies the selected backend/config; old
    # CPU readiness remains exactly phone_local_http when no new selector exists.
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for index, key in enumerate(node.keys):
                if (isinstance(key, ast.Constant) and key.value == "backend" and isinstance(node.values[index], ast.Constant)
                        and node.values[index].value == "phone_local_http"):
                    node.values[index] = ast.parse("'geniex_qairt_isolated_process' if getattr(args, 'geniex_backend', None) is not None else 'phone_local_http'", mode="eval").body
                    node.keys.extend([ast.Constant("geniex_config_sha256"), ast.Constant("geniex_effective_config_sha256")])
                    node.values.extend([ast.parse("getattr(args, 'geniex_config_sha256', None)", mode="eval").body,
                                        ast.parse("getattr(args, 'geniex_effective_config_sha256', None)", mode="eval").body])
                    break
    # New atomic evidence names are explicit; old temporary-name grammar remains.
    expected = one(tree.body, lambda n: target_assignment(n, "_EXPECTED_EVIDENCE_TEMP"), "evidence temporary allowlist")
    pattern = ast.literal_eval(expected.value.args[0])
    if not pattern.endswith(r")\Z"):
        raise ValueError("unexpected temporary grammar shape")
    expected.value.args[0] = ast.Constant(pattern[:-3] + r"|local-[0-9]{2}\.(?:geniex-budget|geniex-receipt)\.json\.new)\Z")
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n"


def ledger_profile_overlay(source):
    """Add one named budget; retain every original ledger/proof operation."""
    tree = ast.parse(source)
    init = function(tree, "LedgerPrefix", "__init__")
    rounds = one(init.body, lambda node: target_assignment(node, "rounds"), "private ledger round profiles")
    original = ast.literal_eval(rounds.value)
    if original != {"fixed19-v150-r7": 8, "daily-local-24-v1": 25}:
        raise ValueError("unreviewed private ledger budget profile map")
    rounds.value = ast.parse(repr({**original, "daily-qairt-4096-process60-v1": 25}), mode="eval").body
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n"


def build(base: Path, out: Path):
    base = base.resolve(strict=True)
    if out.exists() or not out.is_absolute():
        raise ValueError("new absolute candidate directory required")
    out.mkdir(mode=0o700)
    source = out / "source"
    source.mkdir(mode=0o700)
    for item in base.glob("*.py"):
        if item.is_symlink() or not item.is_file():
            raise ValueError("source file is not a regular pinned Python file")
        shutil.copyfile(item, source / item.name)
    here = Path(__file__).resolve().parent
    for name in ("native_backend.py", "prompt_budget.py", "provider_bridge.py"):
        shutil.copyfile(here / name, source / name)
    before = {p.name: digest(p.read_bytes()) for p in base.glob("*.py")}
    new_provider, evidence = provider_overlay((base / "provider_phone_local.py").read_text())
    (source / "provider_phone_local.py").write_text(new_provider)
    changed = ["native_backend.py", "prompt_budget.py", "provider_bridge.py", "provider_phone_local.py"]
    if (base / "ledger_round_evidence.py").is_file():
        (source / "ledger_round_evidence.py").write_text(ledger_profile_overlay((base / "ledger_round_evidence.py").read_text()))
        changed.append("ledger_round_evidence.py")
    pins = {name: digest((source / name).read_bytes()) for name in changed}
    new_daily = daily_overlay((base / "daily_phone_local.py").read_text(), pins)
    (source / "daily_phone_local.py").write_text(new_daily)
    for path in source.glob("*.py"):
        compile(path.read_bytes(), str(path), "exec")
    after = {p.name: digest(p.read_bytes()) for p in source.glob("*.py")}
    manifest = {"schema": "hepta.geniex-provider-overlay.v1", "base_source_directory": str(base),
                "candidate_source_directory": str(source), "base_sha256": before, "candidate_sha256": after,
                "selection": "daily_phone_local.py --geniex-config <private reviewed config>",
                "candidate_only": True, "deployed": False, "old_cpu_receipt_branch_modified": False,
                "old_claims_modified": False, **evidence}
    (out / "OVERLAY-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.base_source, args.out)
    print(json.dumps({"candidate_only": True, "source": result["candidate_source_directory"],
                      "legacy_completion_recovered_exactly": result["legacy_completion_recovered_exactly"]}))
