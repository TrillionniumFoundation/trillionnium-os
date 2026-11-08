"""Pure, unadopted preparation scaffolding; no execution capability is enabled.

The future-binding format is a review format. Byte/shape checks do not attest
controller completion, fresh absence, admission semantics, or production use.
The generated preparer rejects before its first import, independent of input.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import PurePosixPath
import re

ORIGINAL_PREPARER = {
    "bytes": 27261,
    "sha256": "8e4bb7e8034dd09fde1cb93867f38f59f1487a6e06e4504eb8c201ee1df27b10",
}
OLD_FREEZE = {
    "bytes": 1613295,
    "sha256": "651b4dd0f4f1c32b1928d58480e1adc3f2fcf104884db44b4eac52a0c625ba6d",
}
OLD_FREEZER = {
    "bytes": 32010,
    "sha256": "7db072079c16ca6485d3ea6083eec5adf1054ebe0e6850d6eabf352745603b36",
}
OLD_CONTROLLER = {
    "bytes": 8823,
    "sha256": "d7a4f0aaa6bfd2852ba5395db3296a0b50abfb16fb6fba7c8661d05d422ad881",
}
OLD_FROZEN_ROOT = (
    "/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/"
    "stock16-hepta-local-model-Root-v150-r1/"
    "native-guard-r10-r1-operator-fc33-native-v3-r10"
)
OLD_GENERATION_LABELS = frozenset((
    "root-r10-neg01-fc33-r10-bound01", "root-r10-neg02-fc33-r10-bound01",
))
# The first seven are source-pinned in the original helper. The final label's
# output directory was observed to exist on the Mac before this candidate.
KNOWN_CONSUMED_LABELS = frozenset((
    "root-r10-neg01-1ad3-01", "root-r10-neg01-20261105-08",
    "root-r10-neg01-20261105-09", "root-r10-neg01-7c907661-01",
    "root-r10-neg01-7c907661-diag01", "root-r10-neg01-7c907661-diag02",
    "root-r10-neg01-7c907661-sides01", "root-r10-neg01-fc33-r10-bound01",
))
ADMISSION_NAMES = (
    "build_fence_plan", "verify_retained_preaccept", "verify_retained_staged_r8",
    "verify_retained_transport_r9", "bound02_disposition", "admission_entry",
)
SLOTS = ("FROZEN", "LABELS", "BOOT", "FROZEN_INPUTS", "ADMISSION_SOURCE_PINS")
SCHEMA = "hepta.UNADOPTED.future-preparer-binding.v1"
REQUIRED_ROLES = (
    "actual_freeze", "actual_freezer_source", "actual_controller",
    "retained_r10_failed_original", "new_original_attempt_admission",
    "new_admission_policy_source", "unused_NEG01_observation", "unused_NEG02_observation",
)
PENDING_EXECUTABLE_SEMANTICS = (
    "new complete freeze/controller verifier with actual source and terminal bindings",
    "new admission-policy implementation validating the retained R10 failure without promotion",
    "new full admission dependency closure including that R10 disposition implementation",
    "new live namespace/boot/profile/CAS/freshness and sole-reservation checks",
    "new predecessor, consumed-nonce and generation-specific constants bound to actual originals",
    "reviewed integration of new source-parent result envelopes into the actual runtime",
)
GUARD_REASON = "UNBOUND_NEXT_GENERATION_PREPARER_NO_SOURCE_READ_NONCE_WRITE_OR_PHONE"
GUARD_PREFIX = (
    '"""UNADOPTED next-generation preparer scaffold; all execution is disabled.\n'
    'The retained reviewed logic below is inert. Filling JSON slots cannot enable it.\n'
    'A new executable contract and actual original evidence remain required.\n"""\n'
    'raise RuntimeError("' + GUARD_REASON + '")\n'
    '# Byte-preserved reviewed function bodies follow; generation slots are None.\n'
).encode("utf-8")


class BindingError(ValueError):
    pass


class UnboundPreparerError(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise BindingError(reason)


def pin(raw):
    need(type(raw) is bytes, "exact immutable bytes required")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def bad_constant(value):
        raise BindingError("non-finite JSON constant: " + value)
    need(type(raw) is bytes, "original JSON bytes required")
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                      parse_constant=bad_constant)


def binding_template():
    return {
        "schema": SCHEMA, "state": "UNBOUND", "source_origin": dict(ORIGINAL_PREPARER),
        "originals": {name: None for name in REQUIRED_ROLES},
        "admission_sources": {name: None for name in ADMISSION_NAMES},
        "labels": {"NEG-01": None, "NEG-02": None},
        "runtime_admission": False, "production_adopted": False,
    }


def _descriptor(row):
    need(type(row) is dict and set(row) == {"path", "bytes", "sha256"},
         "complete exact original descriptor required")
    path = row["path"]
    need(type(path) is str and "\x00" not in path and path.startswith("/") and not path.startswith("//")
         and str(PurePosixPath(path)) == path and ".." not in PurePosixPath(path).parts,
         "canonical absolute original path required")
    need(type(row["bytes"]) is int and 0 < row["bytes"] <= 32 * 1024 * 1024
         and type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"]),
         "bounded exact original byte identity required")
    return row


def validate_binding_structure(binding, originals):
    """Check already supplied in-memory originals; never open a path or execute.

    A successful result is structural review only. This function does not
    validate successful controller terminal semantics or R10 admission policy.
    The unconditional execution guard is not controlled by this result.
    """
    need(type(binding) is dict and set(binding) == set(binding_template()),
         "exact future-binding review fields required")
    need(binding["schema"] == SCHEMA and binding["source_origin"] == ORIGINAL_PREPARER
         and binding["runtime_admission"] is False and binding["production_adopted"] is False,
         "source origin or non-admission claim ceiling differs")
    need(binding["state"] == "ORIGINALS_SUPPLIED_FOR_REVIEW",
         "UNBOUND: actual new originals have not been supplied")
    need(type(binding["originals"]) is dict and set(binding["originals"]) == set(REQUIRED_ROLES),
         "all freeze/controller/R10/admission/absence original roles required")
    need(type(binding["admission_sources"]) is dict
         and set(binding["admission_sources"]) == set(ADMISSION_NAMES),
         "all six inherited admission source roles required; future R10 policy is additional")
    need(type(binding["labels"]) is dict and set(binding["labels"]) == {"NEG-01", "NEG-02"},
         "two explicit future case labels required")
    for label in binding["labels"].values():
        need(type(label) is str and re.fullmatch("[a-z0-9][a-z0-9-]{5,35}", label),
             "explicit canonical future label required")
        need(label not in KNOWN_CONSUMED_LABELS, "known consumed label cannot be reused")
        need(label not in OLD_GENERATION_LABELS, "old-generation label cannot become the new generation")
    need(len(set(binding["labels"].values())) == 2, "future case labels must be distinct")
    rows = dict(binding["originals"])
    rows.update({"admission/" + key: value for key, value in binding["admission_sources"].items()})
    for role, row in rows.items():
        _descriptor(row)
        need(not (row["path"] == OLD_FROZEN_ROOT or row["path"].startswith(OLD_FROZEN_ROOT + "/")),
             "frozen R10 namespace cannot be reinterpreted as a new original")
        forbidden = {"actual_freeze": OLD_FREEZE, "actual_freezer_source": OLD_FREEZER,
                     "actual_controller": OLD_CONTROLLER}.get(role)
        if forbidden:
            need({k: row[k] for k in ("bytes", "sha256")} != forbidden,
                 "old R10 " + role + " cannot be reused")
    need(type(originals) is dict and set(originals) == set(rows),
         "every declared original must have supplied bytes; no implicit source reads")
    for role, row in rows.items():
        need(pin(originals[role]) == {k: row[k] for k in ("bytes", "sha256")},
             "original bytes differ: " + role)
    freeze = strict_json(originals["actual_freeze"])
    need(type(freeze) is dict and freeze.get("schema") == "hepta.fc33.native-bound.actual-host-freeze.v1"
         and freeze.get("state") == "FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED"
         and freeze.get("source") == rows["actual_freezer_source"],
         "new source-only freeze structure and freezer source binding required")
    need(all(type(freeze.get(k)) is int and freeze[k] == 0
             for k in ("phone_calls", "native_submissions", "new_nonces"))
         and all(freeze.get(k) is False for k in ("full19_qualified", "production_ready", "automatic_retry"))
         and freeze.get("rollback_admission_is_separate_required_gate") is True,
         "source freeze cannot supply runtime, retry, release or rollback admission")
    need(type(freeze.get("files")) is dict, "freeze member table required for six-source linkage")
    for name in ADMISSION_NAMES:
        need(freeze["files"].get("dependencies/admission/" + name + ".py")
             == binding["admission_sources"][name], "six-source freeze linkage differs: " + name)
    # Even a structurally complete original set is NOT an executable admission.
    # R10 failure semantics and controller/freshness verification need new code.
    return {
        "schema": "hepta.UNADOPTED.preparer-binding-structural-review.v1",
        "state": "STRUCTURAL_REVIEW_ONLY_EXECUTION_DISABLED",
        "binding": pin(encoded(binding)), "checked_original_roles": sorted(rows),
        "actual_controller_semantics_verified": False, "retained_R10_failure_semantics_verified": False,
        "namespace_absence_or_freshness_verified": False, "complete_freeze_verified": False,
        "runtime_admission": False, "production_adopted": False, "execution_enabled": False,
        "pending_executable_semantics": list(PENDING_EXECUTABLE_SEMANTICS),
    }


def prepare(*args, **kwargs):
    """Deliberately disabled, even if a caller supplies a completed review draft."""
    raise UnboundPreparerError(GUARD_REASON)


def derive_unbound_preparer(original):
    """Return a deterministic inert derivative and a whole-byte inverse receipt."""
    need(pin(original) == ORIGINAL_PREPARER, "exact reviewed 27261-byte preparer required")
    text = original.decode("utf-8", "strict")
    lines = text.splitlines(keepends=True)
    tree = ast.parse(text)
    changed = []
    derived = original
    for name in SLOTS:
        nodes = [n for n in tree.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
        need(len(nodes) == 1, "one explicit generation slot required: " + name)
        node = nodes[0]
        old = "".join(lines[node.lineno - 1:node.end_lineno]).encode()
        new = (name + " = None  # UNBOUND: future actual originals and new semantics required\n").encode()
        need(derived.count(old) == 1 and new not in derived, "unique whole-byte slot: " + name)
        derived = derived.replace(old, new, 1)
        changed.append((name, old, new))
    derived = GUARD_PREFIX + derived
    reverse = derived[len(GUARD_PREFIX):]
    for name, old, new in reversed(changed):
        need(reverse.count(new) == 1, "unique inverse generation slot: " + name)
        reverse = reverse.replace(new, old, 1)
    need(reverse == original, "whole-byte inverse must recover the exact original")
    parsed = ast.parse(derived)
    executable = [n for n in parsed.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                                               and isinstance(n.value.value, str))]
    need(isinstance(executable[0], ast.Raise), "unconditional guard before every import or source operation")
    before = {n.name: ast.dump(n, include_attributes=False) for n in tree.body
              if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    after = {n.name: ast.dump(n, include_attributes=False) for n in parsed.body
             if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    need(before == after, "every reviewed function/class body must remain unchanged")
    compile(derived, "<UNADOPTED-unbound-preparer>", "exec")
    return derived, {
        "schema": "hepta.UNADOPTED.preparer-derivation.v1", "state": "INERT_UNBOUND_SOURCE_ONLY",
        "original": pin(original), "derived": pin(derived), "whole_byte_inverse_verified": True,
        "retained_function_class_bodies": len(before), "all_retained_function_class_bodies_unchanged": True,
        "unbound_slots": [{"name": name, "old": pin(old), "new": pin(new)} for name, old, new in changed],
        "unconditional_guard_before_import": True, "future_binding_schema": SCHEMA,
        "binding_cannot_enable_execution": True, "runtime_admission": False, "production_adopted": False,
        "new_nonce_generations": 0, "phone_calls": 0, "runtime_execution_performed": False,
        "pending_executable_semantics": list(PENDING_EXECUTABLE_SEMANTICS),
    }
