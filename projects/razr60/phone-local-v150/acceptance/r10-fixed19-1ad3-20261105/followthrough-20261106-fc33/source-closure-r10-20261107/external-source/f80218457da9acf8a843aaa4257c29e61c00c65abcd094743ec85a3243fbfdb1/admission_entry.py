"""Stage-aware adapter for the reviewed Root, preparer and sender derivation.

The freezer binds RESOLUTION exactly once after genuine disposition evidence
exists. Dynamic fresh observations are explicit operator inputs in the plan.
Neither preview nor a stage string grants permission to create a nonce/output.
"""
import hashlib
import os
from pathlib import Path
import stat

import bound02_disposition as D

# A source-only candidate is deliberately unbound, not an accepted receipt.
# The derivation records any later replacement together with its exact bytes.
RESOLUTION = {'bytes': 10367, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/bound02-disposition-20261107-01/DISPOSITION-INPUTS.json', 'sha256': '7957589edeb1a0c4fef7764b27ecd31880898310c1e5b466b64c2c981445826b'}
RETAINED_PREACCEPT = {'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-preaccept-r7-failed01/RETENTION-INPUTS.json', 'bytes': 423, 'sha256': '0878279ffce3ecf3e541063ab8ce845950b904e0d46b9a81f6c2bf451bec4b29'}
RETAINED_FAILED_STAGED = {'bytes': 422, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/retained-staged-r8-failed01-ast02/RETENTION-INPUTS.json', 'sha256': 'b005ba692ea1f31e93858628eb9ae64c936c83193c632002eafa1dfb84f7f7f0'}
PREFLIGHT_STAGES = frozenset(("root-main", "root-validate-plan", "preparer-main", "preparer-selected-context", "sender-preview"))
EXECUTION_STAGES = frozenset(D.FIXED_STAGES)
STAT_KEYS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


def read_pinned(row):
    D.descriptor(row)
    p = Path(row["path"])
    D.need(p.is_absolute() and ".." not in p.parts and p.resolve(strict=True) == p, "canonical admission original path")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        D.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row["bytes"], "admission original inode/type/size")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(row["bytes"] + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    stamp = lambda s: tuple(getattr(s, k) for k in STAT_KEYS)
    D.need(stamp(before) == stamp(after) == stamp(p.lstat()), "admission original changed while reading")
    D.need(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"], "admission original exact byte pin")
    return raw


def read_live_fence(expected):
    """Pure local read; compatible with the unchanged preparer audit hook."""
    p = Path(expected["path"])
    D.need(expected["host"] == "mac" and p.is_absolute() and p.resolve(strict=True) == p,
           "actual local original entry fence required")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        D.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
               and before.st_size == expected["payload_bytes"], "live fence type/link/size differs")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(expected["payload_bytes"] + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    stamp = lambda s: tuple(getattr(s, k) for k in STAT_KEYS)
    D.need(stamp(before) == stamp(after) == stamp(p.lstat()), "live fence changed during exact local read")
    return raw, {key: getattr(before, key) for key in STAT_KEYS}


def require_original_admission(stage, plan_context=None):
    D.need(stage in PREFLIGHT_STAGES | EXECUTION_STAGES, "unreviewed admission stage")
    D.need(type(RESOLUTION) is dict and type(RETAINED_PREACCEPT) is dict and type(RETAINED_FAILED_STAGED) is dict,
           "UNBOUND_EXACT_ORIGINAL_DISPOSITIONS_NO_NONCE_OUTPUT_OR_DISPATCH")
    if stage in PREFLIGHT_STAGES:
        D.need(plan_context is None, "preflight is not a current execution receipt")
        result = D.verify_disposition(RESOLUTION, read_pinned=read_pinned)
        retained = D.verify_retained_preaccept(RETAINED_PREACCEPT, read_pinned=read_pinned)
        staged = D.verify_retained_failed_staged(RETAINED_FAILED_STAGED, retained=retained, read_pinned=read_pinned)
        return {"state": "DISPOSITION_PREFLIGHT_ONLY", "stage": stage,
                "resolution_sha256": RESOLUTION["sha256"], "original_terminal": result["original_terminal"],
                "retained_preaccept_sha256": RETAINED_PREACCEPT["sha256"],
                "retained_original_native_terminal": retained["native_terminal"],
                "retained_failed_staged_sha256": RETAINED_FAILED_STAGED["sha256"],
                "retained_failed_staged_native_terminal": staged["native_terminal"],
                "execution_authorized": False, "nonce_creation_authorized": False}
    D.need(type(plan_context) is dict, "actual mutation stage requires complete current context")
    D.exact(plan_context, ("admission_input", "execution_context"), "guard adapter context")
    value = D.document(plan_context["admission_input"], read_pinned)
    D.exact(value, ("schema", "resolution", "retained_preaccept", "retained_failed_staged", "fresh_observation"), "one explicit admission operator input")
    D.need(value["schema"] == D.OPERATOR_SCHEMA and D.same(value["resolution"], RESOLUTION)
           and D.same(value["retained_preaccept"], RETAINED_PREACCEPT)
           and D.same(value["retained_failed_staged"], RETAINED_FAILED_STAGED),
           "operator input changed fixed original dispositions")
    context = plan_context["execution_context"]
    D.need(context.get("stage") == stage, "caller stage/context mismatch")
    return D.fresh_admission(context, RESOLUTION, value["fresh_observation"],
                             retained_preaccept_descriptor=RETAINED_PREACCEPT,
                             retained_failed_staged_descriptor=RETAINED_FAILED_STAGED, read_pinned=read_pinned,
                             read_live_fence=read_live_fence)


def root_context(plan, stage):
    """Called only after the existing full validate_plan succeeds."""
    D.need(stage in ("root-before-init", "root-before-run"), "Root context stage")
    context = {
        "schema": D.CONTEXT_SCHEMA, "stage": stage,
        "candidate": {k: plan[k] for k in ("package", "source_package", "shared_materials", "artifacts", "policy_adoption", "live_policy_sha256")},
        "case_id": plan["case_id"], "label": plan["label"], "nonce": plan["nonce"],
        "out": plan["out"], "request_directory": str(Path(plan["request"]["path"]).parent),
        "previous": plan["previous"], "prior_boundary_descriptor": plan["prior_boundary_descriptor"],
        "prior_boundary_original": plan["prior_boundary_original"], "request": plan["request"], "boot_id": plan["boot_id"],
        "session_id": plan["session_id"], "profile_id": plan["profile_id"],
    }
    return {"admission_input": plan["original_attempt_admission"], "execution_context": context}


def preparation_context(selected):
    """No nonce draw or output reservation is performed by this adapter."""
    p = selected["parent"]
    updates = selected["updates"]
    context = {
        "schema": D.CONTEXT_SCHEMA, "stage": "prepare-before-create",
        "candidate": {k: updates[k] for k in ("package", "source_package", "shared_materials", "artifacts", "policy_adoption", "live_policy_sha256")},
        "case_id": selected["case_id"], "label": selected["selected_label"], "nonce": None,
        "out": str(selected["out"]), "request_directory": str(selected["directory"]),
        "previous": selected["actual_previous"], "prior_boundary_descriptor": updates["prior_boundary_descriptor"],
        "prior_boundary_original": updates["prior_boundary_original"], "request": None, "boot_id": p["boot_id"],
        "session_id": p["session_id"], "profile_id": p["profile_id"],
    }
    return {"admission_input": updates["original_attempt_admission"], "execution_context": context}


def sender_context(plan, *, label, request_descriptor, package_descriptor, contract):
    D.need(label == plan["label"] and D.same(request_descriptor, plan["request"])
           and D.same(package_descriptor, plan["package"]) and contract["nonce"] == plan["nonce"]
           and contract["owner_request_sha256"] == plan["request"]["sha256"], "actual sender/request/contract differs from current plan")
    row = root_context(plan, "root-before-run")
    row["execution_context"]["stage"] = "sender-before-execute"
    return row
