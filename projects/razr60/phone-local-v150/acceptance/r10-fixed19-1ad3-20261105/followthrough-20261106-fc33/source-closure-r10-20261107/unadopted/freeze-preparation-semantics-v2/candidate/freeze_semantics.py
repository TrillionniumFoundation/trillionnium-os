"""Pure source-freeze/controller semantics; never an execution grant.

Inputs are explicit immutable original bytes and supplied full9 observations.
Their consistency is checked, but this module does not authenticate the provider
or make an observation fresh. No paths are opened, nonces drawn or plans written.
The membership source plan is independently bound by the caller's contract;
FREEZE-RESULT cannot select its own verification membership.
"""
from __future__ import annotations

import ast
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
import stat
import types

MAX_FREEZE_BYTES = 32 * 1024 * 1024
FULL9 = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
         "st_size", "st_mtime_ns", "st_ctime_ns")
MANIFESTS = (("runtime/MANIFEST.json", "runtime_manifest", 38),
             ("root-chain/SOURCE-MANIFEST.json", "root_chain_manifest", 3),
             ("shared/SHARED-MATERIALS.json", "shared_materials", 17))
ADMISSION_NAMES = ("build_fence_plan", "verify_retained_preaccept", "verify_retained_staged_r8",
                   "verify_retained_transport_r9", "bound02_disposition", "admission_entry")
OLD_FREEZE_SHA = "651b4dd0f4f1c32b1928d58480e1adc3f2fcf104884db44b4eac52a0c625ba6d"
OLD_FREEZER_SHA = "7db072079c16ca6485d3ea6083eec5adf1054ebe0e6850d6eabf352745603b36"
OLD_CONTROLLER_SHA = "d7a4f0aaa6bfd2852ba5395db3296a0b50abfb16fb6fba7c8661d05d422ad881"
OLD_FREEZE_ROOT = "/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-fc33-native-v3-r10"
OLD_IDEMPOTENCY_KEY = "fc33-native-bound-runtime-r10-freeze-once01"
OLD_LABELS = frozenset(("root-r10-neg01-fc33-r10-bound01", "root-r10-neg02-fc33-r10-bound01"))
R10_READER = {"bytes": 35444, "sha256": "bb9809c6767d4822d1ceab7eb82e2d2386eab0af87592cedb971edc07e092901"}
R10_LOADER = {"bytes": 793, "sha256": "646368153a161538903e5bf23f1109d72c3d9a60f84dc79df163427e615429a6"}
CONTRACT_SCHEMA = "hepta.UNADOPTED.source-freeze-originals-contract.v1"
PLAN_SCHEMA = "hepta.UNADOPTED.source-freeze-complete-membership.v1"
CLAIM_CEILING = {"runtime_admission": False, "production_adopted": False,
                 "fresh_execution_eligible": False, "nonce_creation_authorized": False,
                 "reservation_authorized": False, "phone_calls_authorized": False,
                 "current_native_case_credit": 0}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def exact(value, keys, reason):
    need(type(value) is dict and set(value) == set(keys), reason)


def pin(raw):
    need(type(raw) is bytes, "exact immutable original bytes required")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def same(left, right):
    """JSON structure identity preserves booleans, integers and floats."""
    return encoded(left) == encoded(right)


def strict(raw):
    need(type(raw) is bytes and len(raw) <= MAX_FREEZE_BYTES, "bounded immutable JSON original required")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def bad(value):
        raise ValueError("nonfinite JSON value: " + value)
    def finite(value):
        result = float(value)
        need(math.isfinite(result), "nonfinite JSON number")
        return result
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                      parse_constant=bad, parse_float=finite)


def path(value, absolute=True):
    need(type(value) is str and value and "\x00" not in value
         and not value.startswith("//"), "nonempty canonical path required")
    p = PurePosixPath(value)
    need(p.is_absolute() is absolute and str(p) == value and ".." not in p.parts
         and (absolute or value != "."), "canonical path without traversal required")
    return p


def descriptor(value):
    exact(value, ("path", "bytes", "sha256"), "exact path/bytes/hash descriptor required")
    path(value["path"])
    need(value["path"] != "/", "file original cannot denote the filesystem root")
    need(type(value["bytes"]) is int and 0 <= value["bytes"] <= MAX_FREEZE_BYTES
         and type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]),
         "bounded exact byte identity required")
    return value


def full9(value, *, kind, size=None, private=False):
    need(type(value) is list and len(value) == 9 and all(type(x) is int and x >= 0 for x in value),
         "nine exact integer metadata fields required")
    need(value[1] > 0 and value[5] > 0, "valid inode and link count required")
    if kind == "file":
        need(stat.S_ISREG(value[2]) and value[5] == 1 and value[6] == size,
             "single-link regular file with exact size required")
        if private:
            need(stat.S_IMODE(value[2]) == 0o600, "private frozen file mode required")
    else:
        need(kind == "directory" and stat.S_ISDIR(value[2]) and stat.S_IMODE(value[2]) == 0o700,
             "private frozen directory mode required")
    return value


def check_source(implementation_source):
    need(type(implementation_source) is bytes
         and implementation_source == globals().get("__bound_source_bytes__"),
         "declared implementation must equal actual bound compiled bytes")


def mcp_value(envelope):
    need(type(envelope) is dict and envelope.get("isError") is False
         and type(envelope.get("content")) is list and len(envelope["content"]) == 1,
         "complete original controller text envelope required")
    text = envelope["content"][0]
    need(type(text) is dict and text.get("type") == "text" and type(text.get("text")) is str,
         "one original text content required")
    return strict(text["text"].encode("utf-8"))


def verify_controller(carrier_raw, freeze, freeze_row, expected_request):
    """Check the original four-record controller and both complete streams.

    This is the old preparer's full terminal/byte-count check with the generation
    request bound externally, plus strict scalar types and no implicit reads.
    """
    carrier = strict(carrier_raw)
    exact(carrier, ("schema", "request", "start", "status", "read"), "all four controller originals required")
    need(carrier["schema"] == "hepta.fc33.actual-runtime-freeze-controller-originals.v1",
         "exact source-freeze controller carrier required")
    request = carrier["request"]
    exact(expected_request, ("host", "executable", "args", "idempotency_key"), "exact reviewed controller request required")
    need(expected_request["host"] == "mac" and expected_request["executable"] == "/usr/bin/python3"
         and expected_request["args"] == [freeze["source"]["path"], "--freeze-reviewed-host-runtime", freeze["source"]["sha256"]]
         and type(expected_request["idempotency_key"]) is str and bool(expected_request["idempotency_key"]),
         "controller request must select the exact freezer source once")
    need(type(request) is dict and all(request.get(k) == v for k, v in expected_request.items()),
         "original controller request differs from reviewed request")
    start, status, read = (mcp_value(carrier[name]) for name in ("start", "status", "read"))
    job = start["job"]
    need(start.get("reused") is False and type(job) is dict
         and all(job.get(k) == v for k, v in expected_request.items())
         and job.get("launch_error") is None and job.get("launch_state") == "launched"
         and type(job.get("id")) is str and bool(job["id"])
         and job["id"] == status.get("job_id") == read.get("job_id"),
         "same fresh original launch and terminal identity required")
    need(status.get("state") == "succeeded" and type(status.get("exit_code")) is int and status["exit_code"] == 0
         and all(status.get(k) is False for k in ("cancelled", "timed_out", "automatic_retry"))
         and all(status.get(k) is True for k in ("output_complete", "output_durable", "terminal_publication_confirmed")),
         "complete successful durable original freeze terminal required")
    streams = {}
    for name in ("stdout", "stderr"):
        row = read[name]; log = status["log_bytes"][name]
        need(type(row["bytes_hex"]) is str and re.fullmatch("(?:[0-9a-f]{2})*", row["bytes_hex"]) is not None,
             "canonical full controller output hex required")
        raw = bytes.fromhex(row["bytes_hex"]); n = len(raw)
        values = (row["offset"], row["next_offset"], row["size"], log["seen"], log["stored"])
        need(all(type(x) is int for x in values) and values == (0, n, n, n, n)
             and row["eof"] is True and status["log_truncated"][name] is False
             and status["log_synced"][name] is True and status["log_errors"][name] is None,
             "complete durable controller stream with exact counts required")
        streams[name] = raw
    need(streams["stderr"] == b"" and streams["stdout"].endswith(b"\n"),
         "successful newline-terminated controller output and empty stderr required")
    summary = strict(streams["stdout"])
    need(type(summary) is dict and summary.get("state") == freeze["state"]
         and same(summary.get("freeze"), freeze_row)
         and all(same(summary.get(k), freeze[k]) for k in ("runtime_manifest", "root_chain_manifest", "combination"))
         and type(summary.get("complete_directory_bytes")) is int
         and summary["complete_directory_bytes"] == freeze["complete_directory_bytes"]
         and type(summary.get("phone_calls")) is int and summary["phone_calls"] == 0
         and summary.get("full19_qualified") is False,
         "complete controller stdout must bind the exact final tuple and accounting")
    return {"job_id": job["id"], "exit_code": 0, "controller_original": pin(carrier_raw),
            "stdout": pin(streams["stdout"]), "stderr": pin(streams["stderr"]),
            "both_streams_eof": True, "automatic_retry": False}


def validate_contract(contract_raw, plan_raw):
    c, p = strict(contract_raw), strict(plan_raw)
    exact(c, ("schema", "state", "frozen_root", "freeze", "controller", "freezer", "membership_plan", "controller_request"),
          "exact source-freeze originals contract required")
    need(c["schema"] == CONTRACT_SCHEMA and c["state"] == "ORIGINALS_SUPPLIED_FOR_OFFLINE_VERIFICATION",
         "UNBOUND: actual original descriptors have not been supplied")
    root = path(c["frozen_root"])
    need(str(root) != "/", "dedicated frozen root required")
    for role in ("freeze", "controller", "freezer", "membership_plan"):
        descriptor(c[role])
        if role != "freeze":
            need(path(c[role]["path"]) != root and root not in path(c[role]["path"]).parents,
                 "external source/controller/membership originals must stay outside frozen output")
    need(c["freeze"]["path"] == str(root / "FREEZE-RESULT.json")
         and pin(plan_raw) == {k: c["membership_plan"][k] for k in ("bytes", "sha256")},
         "freeze namespace and independently bound membership-plan bytes required")
    exact(p, ("schema", "frozen_root", "source", "files", "actual_input_files", "expected_history", "actual_policy", "actual_adoption"),
          "complete external membership source plan required")
    need(p["schema"] == PLAN_SCHEMA and p["frozen_root"] == c["frozen_root"] and same(p["source"], c["freezer"]),
         "one exact planned source and namespace required")
    need(type(p["files"]) is dict and 0 < len(p["files"]) <= 254
         and type(p["actual_input_files"]) is dict and 0 < len(p["actual_input_files"]) <= 4096,
         "bounded complete planned members and external inputs required")
    required = {name for name, _, _ in MANIFESTS} | {
        "FREEZER-SOURCE.original.py", "HOST-VALIDATION.json", "COMBINATION.json",
        "SOURCE-PARENT-RECORDS.json", "root-chain/source/run_component_root_once.py",
        "dependencies/DEPENDENCIES.json"}
    required |= {"dependencies/admission/" + name + ".py" for name in ADMISSION_NAMES}
    need(required <= set(p["files"]), "complete source-freeze roles and six inherited admission sources required")
    for name, row in p["files"].items():
        rel = path(name, False); descriptor(row)
        need(name not in ("FREEZE-RESULT.json", "DERIVATION.json") and row["path"] == str(root / rel),
             "exact planned member namespace required")
    member_names = set(p["files"]) | {"FREEZE-RESULT.json", "DERIVATION.json"}
    need(all(not any(str(parent) in member_names for parent in path(name, False).parents)
             for name in member_names), "file member cannot also be a parent directory")
    for name, row in p["actual_input_files"].items():
        exact(row, ("path", "bytes", "sha256", "metadata"), "exact source input including full9 required")
        descriptor({k: row[k] for k in ("path", "bytes", "sha256")})
        need(name == row["path"], "source input key must equal exact path")
        need(path(name) != root and root not in path(name).parents,
             "external source inputs cannot hide unknown frozen output members")
        full9(row["metadata"], kind="file", size=row["bytes"])
    exact(p["expected_history"], ("historical_failed_count", "source_parent_count"), "explicit inherited history cardinality required")
    need(type(p["expected_history"]["historical_failed_count"]) is int
         and p["expected_history"]["historical_failed_count"] >= 9
         and type(p["expected_history"]["source_parent_count"]) is int and p["expected_history"]["source_parent_count"] == 1,
         "inherited historical closure must not be reduced")
    descriptor(p["actual_adoption"])
    # The existing policy is a byte identity; its host path is an input member.
    exact(p["actual_policy"], ("bytes", "sha256"), "exact policy byte identity required")
    need(type(p["actual_policy"]["bytes"]) is int and p["actual_policy"]["bytes"] > 0
         and type(p["actual_policy"]["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", p["actual_policy"]["sha256"]),
         "valid exact policy identity required")
    need(p["actual_adoption"]["path"] in p["actual_input_files"]
         and same({k: p["actual_input_files"][p["actual_adoption"]["path"]][k] for k in ("path", "bytes", "sha256")}, p["actual_adoption"])
         and any(same({k: row[k] for k in ("bytes", "sha256")}, p["actual_policy"]) for row in p["actual_input_files"].values()),
         "actual policy and adoption must be complete bound input originals")
    return c, p


def expected_rows(c, p):
    rows = {}
    def add(row):
        descriptor(row)
        old = rows.get(row["path"])
        need(old is None or old == row, "one path cannot denote conflicting originals")
        rows[row["path"]] = row
    for role in ("freeze", "controller", "freezer", "membership_plan"):
        add(c[role])
    add({"path": str(path(c["frozen_root"]) / "DERIVATION.json"), **{k: c["freeze"][k] for k in ("bytes", "sha256")}})
    for row in p["files"].values():
        add(row)
    for row in p["actual_input_files"].values():
        add({k: row[k] for k in ("path", "bytes", "sha256")})
    return rows


def verify_observations(c, p, rows, observations):
    exact(observations, ("files", "directories"), "explicit supplied file and tree observations required")
    need(type(observations["files"]) is dict and set(observations["files"]) == set(rows),
         "complete supplied full9 observation membership required")
    root = path(c["frozen_root"])
    for name, row in rows.items():
        seen = observations["files"][name]
        exact(seen, ("before", "after", "named"), "full9 file read bookends required")
        private = name == str(root) or root in path(name).parents
        for value in seen.values():
            full9(value, kind="file", size=row["bytes"], private=private)
        need(seen["before"] == seen["after"] == seen["named"], "file full9 read bookend differs")
        if name in p["actual_input_files"]:
            need(seen["before"] == p["actual_input_files"][name]["metadata"], "original input generation differs")
    members = set(p["files"]) | {"FREEZE-RESULT.json", "DERIVATION.json"}
    dirs = {str(root): set()}
    for member in members:
        parts = path(member, False).parts
        parent = root
        for name in parts[:-1]:
            dirs.setdefault(str(parent), set()).add(name)
            parent /= name; dirs.setdefault(str(parent), set())
        dirs[str(parent)].add(parts[-1])
    need(len(dirs) <= 129 and type(observations["directories"]) is dict
         and set(observations["directories"]) == set(dirs), "complete bounded frozen directory census required")
    for name, children in dirs.items():
        seen = observations["directories"][name]
        exact(seen, ("before", "after", "names_before", "names_after"), "directory identity and names bookends required")
        full9(seen["before"], kind="directory"); full9(seen["after"], kind="directory")
        need(all(type(seen[key]) is list and all(type(value) is str for value in seen[key])
                 for key in ("names_before", "names_after")), "directory names require exact string lists")
        need(seen["before"] == seen["after"]
             and seen["names_before"] == seen["names_after"] == sorted(children),
             "frozen directory generation or complete membership differs")
    return {"files": len(rows), "directories": len(dirs),
            "supplied_full9_and_census_consistency_checked": True,
            "observation_provider_implementation_attested": False, "observations_proven_live": False}


def verify_freeze_bundle(contract_raw, membership_plan_raw, originals, observations, *, implementation_source):
    check_source(implementation_source)
    c, p = validate_contract(contract_raw, membership_plan_raw)
    rows = expected_rows(c, p)
    need(type(originals) is dict and set(originals) == set(rows), "complete exact independently planned original membership required")
    for name, row in rows.items():
        need(pin(originals[name]) == {k: row[k] for k in ("bytes", "sha256")}, "original bytes differ: " + name)
    need(originals[c["membership_plan"]["path"]] == membership_plan_raw, "actual membership-plan original differs")
    observation = verify_observations(c, p, rows, observations)
    raw = originals[c["freeze"]["path"]]; f = strict(raw)
    need(type(f) is dict and f.get("schema") == "hepta.fc33.native-bound.actual-host-freeze.v1"
         and f.get("state") == "FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED"
         and same(f.get("source"), c["freezer"]) and f.get("output") == c["frozen_root"],
         "actual source-only freeze source and output identity required")
    need(all(type(f.get(k)) is int and f[k] == 0 for k in ("phone_calls", "native_submissions", "new_nonces"))
         and all(f.get(k) is False for k in ("full19_qualified", "production_ready", "automatic_retry"))
         and all(f.get(k) is True for k in ("rollback_admission_is_separate_required_gate", "all_inputs_bookended_before_publication",
                                          "all_output_files_read_back", "terminal_record_is_last")),
         "source freeze cannot promote qualification, retry or rollback admission")
    need(same(f.get("files"), p["files"]) and same(f.get("actual_input_files"), p["actual_input_files"])
         and same(f.get("actual_policy"), p["actual_policy"]) and same(f.get("actual_adoption"), p["actual_adoption"]),
         "freeze cannot alter independently bound membership, inputs, policy or adoption")
    files = {name: originals[row["path"]] for name, row in p["files"].items()}
    need(files["FREEZER-SOURCE.original.py"] == originals[c["freezer"]["path"]]
         and originals[str(path(c["frozen_root"]) / "DERIVATION.json")] == raw,
         "executed source and both terminal-copy original bytes must match")
    counts = (f.get("result_bytes"), f.get("terminal_copies"), f.get("payload_bytes"),
              f.get("complete_directory_bytes"), f.get("maximum_complete_directory_bytes"))
    need(all(type(x) is int for x in counts) and counts[0] == len(raw) and counts[1] == 2
         and counts[2] == sum(map(len, files.values())) and counts[3] == counts[2] + 2 * len(raw)
         and counts[4] == MAX_FREEZE_BYTES and 0 < counts[3] <= MAX_FREEZE_BYTES,
         "complete frozen payload and two terminal copies must satisfy exact 32MiB accounting")
    for name, key, count in MANIFESTS:
        manifest = strict(files[name]); members = manifest["files"]
        need(same(f[key], p["files"][name]) and type(members) is list and len(members) == count,
             "exact frozen manifest cardinality required: " + name)
        seen = set()
        for member in members:
            need(type(member) is dict and {"path", "bytes", "sha256"} <= set(member), "complete manifest member identity required")
            rel = path(member["path"], False); full = str(path(name, False).parent / rel)
            need(full not in seen and full in files, "unique complete manifest member required")
            seen.add(full)
            need(type(member["bytes"]) is int and pin(files[full]) == {k: member[k] for k in ("bytes", "sha256")},
                 "actual manifest member source bytes differ")
        folder = str(path(name, False).parent) + "/"
        actual_members = {item for item in files if item.startswith(folder)}
        need(actual_members == seen | {name}, "exact frozen family subtree membership required: " + name)
    checks = strict(files["HOST-VALIDATION.json"])
    need(same(f.get("checks"), checks) and checks.get("source_parent_current_credit") is False
         and checks.get("fresh_phone_admission_required") is True
         and all(type(checks.get(k)) is int and checks[k] == v for k, v in p["expected_history"].items()),
         "exact complete historical context without inherited current credit required")
    need(same(f.get("combination"), p["files"]["COMBINATION.json"]), "exact frozen combination original required")
    need(same(f.get("dependencies"), p["files"]["dependencies/DEPENDENCIES.json"]),
         "exact complete frozen dependency manifest original required")
    package, root = strict(files["runtime/MANIFEST.json"]), strict(files["root-chain/SOURCE-MANIFEST.json"])
    need(package.get("current_combination_sha256") == root.get("current_combination_sha256") == f["combination"]["sha256"]
         and same(package.get("source_parent_records"), strict(files["SOURCE-PARENT-RECORDS.json"])),
         "one exact package/root/combination/source-parent tuple required")
    tree = ast.parse(files["root-chain/source/run_component_root_once.py"])
    values = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "PKG" for target in n.targets)]
    need(values == [f["runtime_manifest"]["sha256"]], "single exact root package constant required")
    controller = verify_controller(originals[c["controller"]["path"]], f, c["freeze"], c["controller_request"])
    return {"schema": "hepta.UNADOPTED.verified-source-freeze-semantics.v1",
            "state": "SOURCE_FREEZE_AND_CONTROLLER_SEMANTICS_CHECKED_NO_EXECUTION_GRANT",
            "implementation": pin(implementation_source), "contract": pin(contract_raw),
            "membership_plan": pin(membership_plan_raw), "freeze": dict(c["freeze"]), "freezer": dict(c["freezer"]),
            "controller": dict(c["controller"]), "controller_result": controller,
            "frozen_root": c["frozen_root"], "complete_directory_bytes": counts[3],
            "frozen_member_count_including_terminal_copies": len(files) + 2,
            "external_input_count": len(p["actual_input_files"]), "manifest_member_counts": [38, 3, 17],
            "runtime_manifest": f["runtime_manifest"], "root_chain_manifest": f["root_chain_manifest"],
            "shared_materials": f["shared_materials"], "combination": f["combination"],
            "dependency_manifest": f["dependencies"],
            "source_parent_records": package["source_parent_records"],
            "actual_policy": f["actual_policy"], "actual_adoption": f["actual_adoption"],
            "inherited_admission_source_originals": {name: p["files"]["dependencies/admission/" + name + ".py"] for name in ADMISSION_NAMES},
            "runtime_import_dependency_semantics_reverified": False,
            "observations": observation, "membership_plan_review_authority_verified": False,
            "source_build_reproducibility_verified": False, "whole_stage_budget_verified": False,
            "formal_BUILD_release_sealed": False, "source_freezer_executed_by_this_verifier": False,
            **CLAIM_CEILING}


def require_new_generation(contract_raw, membership_plan_raw, labels, consumed_labels):
    """Reject old actual R10 binding before any original-byte provider is called."""
    c, _ = validate_contract(contract_raw, membership_plan_raw)
    need(c["frozen_root"] != OLD_FREEZE_ROOT and not c["frozen_root"].startswith(OLD_FREEZE_ROOT + "/")
         and c["freeze"]["sha256"] != OLD_FREEZE_SHA and c["freezer"]["sha256"] != OLD_FREEZER_SHA
         and c["controller"]["sha256"] != OLD_CONTROLLER_SHA
         and c["controller_request"]["idempotency_key"] != OLD_IDEMPOTENCY_KEY,
         "old R10 freeze, source, controller and namespace cannot become a new generation")
    exact(labels, ("NEG-01", "NEG-02"), "two explicit new case labels required")
    need(type(consumed_labels) is list and all(type(x) is str for x in consumed_labels),
         "explicit consumed-label ledger projection required")
    need(len(set(labels.values())) == 2, "new labels must be distinct")
    for label in labels.values():
        need(type(label) is str and re.fullmatch("[a-z0-9][a-z0-9-]{5,35}", label)
             and label not in OLD_LABELS and label not in consumed_labels,
             "old, consumed or invalid case label cannot be reused")
    return c


def verify_new_freeze_with_provider(contract_raw, membership_plan_raw, labels, consumed_labels, *, read_observed, implementation_source):
    """Guard first, then explicit file observations twice; provider is not attested.

    read_observed receives only a copied exact descriptor and returns original
    bytes plus file full9 before/after/named. Directory observations are excluded
    here deliberately: a complete tree observation must be supplied to the core.
    This function returns material for that core, never a verification receipt.
    """
    check_source(implementation_source)
    c = require_new_generation(contract_raw, membership_plan_raw, labels, consumed_labels)
    _, p = validate_contract(contract_raw, membership_plan_raw)
    need(callable(read_observed), "explicit bound original provider required")
    rows = expected_rows(c, p); before = {}
    for name in sorted(rows):
        observed = read_observed(dict(rows[name]))
        exact(observed, ("raw", "before", "after", "named"), "explicit immutable bytes and full9 bookends required")
        need(pin(observed["raw"]) == {k: rows[name][k] for k in ("bytes", "sha256")}, "first original read differs")
        for value in (observed["before"], observed["after"], observed["named"]):
            full9(value, kind="file", size=rows[name]["bytes"])
        need(observed["before"] == observed["after"] == observed["named"], "first observed full9 differs")
        # Copy mutable metadata immediately; a provider cannot retroactively edit
        # the accepted bookend through a shared list alias.
        before[name] = {"raw": observed["raw"], **{k: list(observed[k]) for k in ("before", "after", "named")}}
    for name in sorted(rows):
        observed = read_observed(dict(rows[name]))
        exact(observed, ("raw", "before", "after", "named"), "complete second original observation required")
        need(pin(observed["raw"]) == pin(before[name]["raw"]) and observed["raw"] == before[name]["raw"],
             "second original bytes differ")
        for key in ("before", "after", "named"):
            full9(observed[key], kind="file", size=rows[name]["bytes"])
            need(observed[key] == before[name][key], "second original full9 differs")
    return {"schema": "hepta.UNADOPTED.source-freeze-provider-material.v1", "material": before,
            "implementation": pin(implementation_source), "contract": pin(contract_raw),
            "membership_plan": pin(membership_plan_raw),
            "provider_calls": len(rows) * 2, "complete_tree_observation_supplied": False,
            "provider_implementation_attested": False, **CLAIM_CEILING}


def verify_retained_r10_context(expectation_raw, originals, *, reader_source, loader_source, implementation_source):
    """Actually execute the fixed independently bound retained-failure reader."""
    check_source(implementation_source)
    need(pin(reader_source) == R10_READER and pin(loader_source) == R10_LOADER,
         "exact sealed R10 reader and byte-bound loader required")
    module = types.ModuleType("UNADOPTED_freeze_R10_loader")
    exec(compile(loader_source, "<exact-retained-R10-loader>", "exec"), module.__dict__)
    reader = module.load(reader_source)
    value = reader.verify_retained_r10_failure(expectation_raw, originals, implementation_source=reader_source)
    need(value["implementation"] == R10_READER
         and all(value[key] is None for key in ("original_phone_terminal", "original_phone_stage_producer_terminal",
                                               "original_phone_stage_writes", "global_unknown_effect_count"))
         and all(value[key] is False for key in ("retirement_accepted", "fresh_execution_eligible", "nonce_creation_authorized",
                                                "production_adopted", "original_replay_allowed", "original_lease_refreshed"))
         and value["original_nonce_consumed"] is True and type(value["native_case_credit"]) is int
         and value["native_case_credit"] == 0, "R10 retained history cannot promote unknowns or execution eligibility")
    return {"schema": "hepta.UNADOPTED.preparation-retained-R10-context.v1",
            "implementation": pin(implementation_source), "retained_reader_source": dict(R10_READER),
            "retained_loader_source": dict(R10_LOADER),
            "verified_retained_R10": value, "R6_R7_R8_R9_chain_verification_replaced": False,
            "complete_current_phone_scope_and_fence_disposition_supplied": False,
            "budget_seconds_not_refreshed": value["original_phone_stage_budget_seconds"], **CLAIM_CEILING}
