"""Verify the exact retained R10 host failure without creating admission.

Only caller-supplied immutable bytes are parsed. This module never extracts an
archive to disk, executes retained Python, observes the phone, or changes a
nonce/fence/lease. A valid result is a retained-failure fact record, not a
retirement or fresh-execution permission. Use bound_loader for source identity.
"""
import ast
import hashlib
import io
import json
import math
from pathlib import PurePosixPath
import re
import stat
import tarfile

SCHEMA = "hepta.UNADOPTED.r10-retained-host-failure-verification.v1"
STATE = "EXACT_R10_HOST_FAILURE_VERIFIED_PHONE_OUTCOME_UNKNOWN"
EXPECTATION_PIN = {"bytes": 3722, "sha256": "ab8eef23aefa5c57f9fd9b14ec35bf01bc7160ef77e639c2a72e001649cdc42f"}
LABEL = "root-r10-neg01-fc33-r10-bound01"
NONCE = "4e5480a8952443bd18fa603b81f8efe9"
JOB = "1a1b7ef6a3a-12894-cbf"
BOOT = "f8019f83-20a7-4f18-bea1-51c980621e4d"
SESSION = "session-ee897738-8fc2-4d3e-a916-5fe368b340ef"
BASE = "/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1"
OUT = BASE + "/native-guard-root-chains-r10-r1/" + LABEL
INPUT = BASE + "/native-guard-root-inputs-r10-r1/" + LABEL
OPERATOR = BASE + "/native-guard-r10-r1-operator-fc33-native-v3-r10"
WORKER = "/Users/qianqi/.local/state/hepta-runtime-mac-worker/jobs/" + JOB
PHASES = ("prepare-material", "host-stage-material", "phone-push-material", "phone-copy-material",
          "phone-push-stage-source", "phone-copy-stage-source", "phone-stage")
META_KEYS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
PACKAGE_PIN = {"bytes": 87655, "sha256": "94e945e55f4cda2c9d2c4bd473f6fdb8ec6eca425610db4fd59af1814f5fca02"}
SOURCE_PIN = {"bytes": 74044, "sha256": "43bbc6ac86758d31ed03d55a5cac0e24db5a021b161d2161a4f52a58980d8da2"}
PLAN_PIN = {"bytes": 5194, "sha256": "523aa7ce5eb64732ca40fcfba7d78fc30c93689b6acc0c25620ed2972b4d5366"}
REQUEST_PIN = {"bytes": 317, "sha256": "0801bcc799572e5a0eae481bbebf40246566a5ae0eb705d12f7906573bd3878f"}
LEASE_PIN = {"bytes": 2508, "sha256": "979ad88b23a579bcdfb1ec928b04b52f6f50d5a71ff69a6e86026186f74974ed"}
STAGE_PIN = {"bytes": 19085, "sha256": "74ff4865d2021e42ae5022d606cfe5732d924e8038d00c3a99b89ebcd4c77d72"}
ARCHIVE_PIN = {"bytes": 851713, "sha256": "e3e6a071a4374fc379b51018fc36826511193f60d46cfad2cbe15240ae9d4c57"}
MAX_RAW = 32 * 1024 * 1024


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def pin(raw):
    need(type(raw) is bytes, "exact immutable bytes required")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def exact(value, keys, reason):
    need(type(value) is dict and set(value) == set(keys), reason)


def strict(raw):
    need(type(raw) is bytes and len(raw) <= MAX_RAW, "bounded JSON bytes required")
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, "duplicate JSON key")
            out[key] = value
        return out
    def bad(value):
        raise ValueError("non-finite JSON constant")
    def finite(value):
        number = float(value)
        need(math.isfinite(number), "non-finite JSON number")
        return number
    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                      parse_constant=bad, parse_float=finite)


def canonical_path(value, absolute):
    need(type(value) is str and value and "\x00" not in value and "\\" not in value,
         "canonical nonempty POSIX path")
    p = PurePosixPath(value)
    need(p.is_absolute() is absolute and str(p) == value and not value.startswith("//")
         and all(x not in ("", ".", "..") for x in value.split("/")[1 if absolute else 0:]),
         "canonical POSIX path without traversal")
    return p


def descriptor(value):
    exact(value, ("path", "bytes", "sha256"), "exact original descriptor")
    canonical_path(value["path"], True)
    need(type(value["bytes"]) is int and 0 <= value["bytes"] <= MAX_RAW
         and type(value["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", value["sha256"]),
         "bounded original size/hash")
    return value


def full9(value, kind, size=None):
    need(type(value) is list and len(value) == 9 and all(type(x) is int and x >= 0 for x in value),
         "nine exact metadata integers required")
    if kind == "file":
        need(stat.S_ISREG(value[2]) and value[5] == 1 and (size is None or value[6] == size),
             "regular single-link file metadata and exact size required")
    else:
        need(kind == "directory" and stat.S_ISDIR(value[2]), "directory metadata required")
    return value


def verify_inventory(index, inputs):
    """Validate every original path, metadata tuple and parent/name edge."""
    need(index["schema"] == "hepta.r10.failed-host-original-index.v1"
         and inputs["schema"] == "hepta.r10.failed-host-export-inputs.v1", "exact retained export schemas")
    roots = inputs["roots"]
    need(type(roots) is list and len(roots) == 5, "all five fixed retained roots required")
    expected_roots = {"root": OUT, "plan": INPUT, "root-source": OPERATOR + "/root-chain/source/run_component_root_once.py",
                      "root-manifest": OPERATOR + "/root-chain/SOURCE-MANIFEST.json",
                      "runtime-manifest": OPERATOR + "/runtime/MANIFEST.json"}
    need(all(type(r) is dict and set(r) == {"alias", "path"} for r in roots)
         and len({r["alias"] for r in roots}) == 5
         and {r["alias"]: r["path"] for r in roots} == expected_roots, "exact retained root identities")
    census = index["complete_census"]
    exact(census, ("entries", "entry_count", "file_count", "file_bytes"), "complete original census fields")
    entries = census["entries"]
    need(type(entries) is dict and len(entries) == census["entry_count"] == 141,
         "all 141 retained census entries required")
    need(all(type(entry) is dict for entry in entries.values()), "ordinary original census entry objects")
    need(type(census["entry_count"]) is int and type(census["file_count"]) is int
         and type(census["file_bytes"]) is int, "census counts are integers, not booleans")
    children = {p: [] for p, e in entries.items() if e.get("kind") == "directory"}
    file_paths = set()
    for path, entry in entries.items():
        p = canonical_path(path, True)
        kind = entry.get("kind")
        exact(entry, ("alias", "kind", "metadata", "path", "relative") + (("children",) if kind == "directory" else ()),
              "exact retained census entry")
        need(entry["path"] == path and entry["alias"] in expected_roots, "original census alias/path")
        anchor = expected_roots[entry["alias"]]
        need(path == anchor or path.startswith(anchor + "/"), "original root containment")
        rel = "" if path == anchor else path[len(anchor) + 1:]
        need(entry["relative"] == rel, "original relative path binding")
        full9(entry["metadata"], kind)
        if path != anchor:
            parent = str(p.parent)
            need(parent in children, "every nonroot original has its original directory parent")
            children[parent].append(p.name)
        if kind == "file":
            file_paths.add(path)
    need(set(expected_roots.values()) <= set(entries), "every retained root is present")
    for path, names in children.items():
        need(entries[path]["children"] == sorted(names) and len(names) == len(set(names)),
             "complete original directory child-name bookends")
    files = index["files"]
    need(type(files) is list and len(files) == census["file_count"] == 125, "all 125 retained files required")
    by_path = {}
    members = set()
    for row in files:
        exact(row, ("archive_member", "bytes", "metadata", "path", "sha256"), "exact retained file row")
        descriptor({k: row[k] for k in ("path", "bytes", "sha256")})
        name = row["archive_member"]
        canonical_path(name, False)
        need(name.startswith("originals/") and name not in members and row["path"] not in by_path,
             "unique retained member and source path")
        need(row["path"] in file_paths, "file row must belong to complete original census")
        entry = entries[row["path"]]
        expected_name = "originals/" + entry["alias"] + "/" + (entry["relative"] or PurePosixPath(row["path"]).name)
        need(name == expected_name and row["metadata"] == entry["metadata"], "archive name and original full9 binding")
        full9(row["metadata"], "file", row["bytes"])
        by_path[row["path"]] = row
        members.add(name)
    need(set(by_path) == file_paths and sum(r["bytes"] for r in files) == census["file_bytes"] == 13283382,
         "complete original file set and byte count")
    for path, known in inputs["known_pins"].items():
        need(path in by_path and all(by_path[path].get(k) == v for k, v in known.items()), "prior-known original pin differs")
    for path, digest in inputs["known_sha256_without_prior_size"].items():
        need(path in by_path and by_path[path]["sha256"] == digest, "prior-known digest differs")
    return by_path


def verify_archive(archive_raw, index_raw, index, by_path):
    """Read the complete bounded tar in memory; never call extract/extractall."""
    need(type(archive_raw) is bytes and len(archive_raw) <= 8 * 1024 * 1024, "bounded retained archive")
    rows = {v["archive_member"]: v for v in by_path.values()}
    expected_names = set(rows) | {"EVIDENCE-INDEX.json"}
    got = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:gz") as archive:
        for member in archive:
            canonical_path(member.name, False)
            need(member.isfile() and not member.issym() and not member.islnk()
                 and member.name in expected_names and member.name not in got, "exact regular unique archive member")
            expected = pin(index_raw) if member.name == "EVIDENCE-INDEX.json" else {k: rows[member.name][k] for k in ("bytes", "sha256")}
            need(type(member.size) is int and member.size == expected["bytes"], "archive member declared size")
            total += member.size
            need(total <= 13283382 + len(index_raw), "bounded complete uncompressed archive")
            stream = archive.extractfile(member)
            need(stream is not None, "regular member stream required")
            raw = stream.read(expected["bytes"] + 1)
            need(pin(raw) == expected, "complete original archive member bytes differ")
            got[member.name] = raw
    need(set(got) == expected_names and len(got) == 126 and got["EVIDENCE-INDEX.json"] == index_raw,
         "complete archive including identical embedded original index")
    return {path: got[row["archive_member"]] for path, row in by_path.items()}


def verify_controller(originals, plan):
    m = strict(originals["controller_metadata"])
    req = strict(originals["worker_request"])
    terminal = strict(originals["worker_exit"])
    witness = strict(originals["worker_exit_witness"])
    launch = strict(originals["worker_launch"])
    started = strict(originals["worker_started"])
    argv = ["-I", "-B", OPERATOR + "/root-chain/source/run_component_root_once.py", "--plan", INPUT + "/ROOT-PLAN.json",
            "--plan-sha256", PLAN_PIN["sha256"], "--execute-root-chain-once"]
    need(m["id"] == req["job_id"] == terminal["job_id"] == witness["job_id"] == started["job_id"] == JOB,
         "original controller/worker job identity")
    need(m["host"] == "mac" and m["idempotency_key"] == LABEL and m["launch_state"] == "launched"
         and m["launch_error"] is None and m["args"] == req["args"] == argv
         and m["executable"] == req["executable"] == "/usr/bin/python3"
         and m["remote_job_dir"] == req["job_dir"] == WORKER, "original executable, argv, namespace and launch")
    need(m["request_digest"] == req["request_digest"] == req["request_fingerprint"]
         == "b6c1451b85783736a6fafb19b0400a14b3f3c2b3a46cd15c6f2c892fad07b357", "exact original durable request digest")
    need(req["launch_nonce"] == terminal["launch_nonce"] == witness["launch_nonce"] == started["launch_nonce"]
         == "be4deee3f860b563147bb0109bffd61a", "same original durable launch nonce")
    need(type(terminal["exit_code"]) is int and terminal["exit_code"] == 1
         and terminal["cancelled"] is False and terminal["timed_out"] is False
         and terminal["output_complete"] is True and terminal["output_durable"] is True,
         "original outer failed terminal, not an outer timeout or cancellation")
    need(type(terminal["terminal_publication_protocol"]) is int and type(witness["terminal_publication_protocol"]) is int
         and terminal["terminal_publication_protocol"] == witness["terminal_publication_protocol"] == 1
         and witness["exit_sha256"] == pin(originals["worker_exit"])["sha256"], "original terminal publication witness")
    for stream in ("stdout", "stderr"):
        size = len(originals["worker_" + stream])
        counts = terminal["log_bytes"][stream]
        need(type(counts) is dict and set(counts) == {"seen", "stored"}
             and all(type(counts[k]) is int for k in ("seen", "stored"))
             and counts == {"seen": size, "stored": size}
             and terminal["log_errors"][stream] is None and terminal["log_synced"][stream] is True
             and terminal["log_truncated"][stream] is False, "complete original worker log")
    need(type(launch["launcher_pid"]) is int and type(started["supervisor_pid"]) is int
         and all(type(value) is int for value in (m["created_unix_ms"], started["at_unix_ms"], terminal["at_unix_ms"]))
         and launch["backend"] == "detached" and launch["launcher_pid"] == started["supervisor_pid"]
         and 0 < m["created_unix_ms"] <= started["at_unix_ms"] <= terminal["at_unix_ms"],
         "original launch/start/terminal order")
    need(plan["label"] == LABEL and plan["nonce"] == NONCE, "actual failed plan identity")
    return {"job_id": JOB, "request_digest": m["request_digest"], "exit_code": 1,
            "original_terminal": pin(originals["worker_exit"]), "original_terminal_witness": pin(originals["worker_exit_witness"]),
            "output_complete": True, "output_durable": True, "outer_timed_out": False,
            "created_unix_ms": m["created_unix_ms"], "terminal_at_unix_ms": terminal["at_unix_ms"]}


def verify_material_transfers(files):
    """Verify the four retained push/copy payloads, not a zero-write claim."""
    results = []
    for suffix, expected, ending in (("material", ARCHIVE_PIN, ".tar.gz"), ("stage-source", STAGE_PIN, ".stage.py")):
        pushed = strict(files[OUT + "/phone-push-" + suffix + "/stdout.original"])
        copied = strict(files[OUT + "/phone-copy-" + suffix + "/stdout.original"])
        for kind, value in (("push", pushed), ("copy", copied)):
            wrapper = value["wrapper"]
            need(type(value["actor_rc"]) is int and value["actor_rc"] == 0
                 and wrapper["schema"] == "hepta.phone-local.operator-result.v150.1"
                 and wrapper["label"] == "ng-" + NONCE + "-" + kind + "-" + suffix
                 and wrapper["model_decision"] is False and wrapper["native_task_result"] is False,
                 "actual original material actor result")
        push = pushed["wrapper"]
        source = "/data/local/tmp/hepta-phone-local-v150-r1/hepta-native-guard-" + LABEL + ending
        target = "/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-staging-r10-r1/" + LABEL + ending
        need(push["status"] == "pushed_and_hash_verified" and type(push["bytes"]) is int
             and {k: push[k] for k in ("bytes", "sha256")} == expected
             and type(push["readback"]["rc"]) is int and push["readback"]["rc"] == 0
             and push["readback"]["stderr"] == ""
             and push["readback"]["stdout"] == expected["sha256"] + "  " + source + "\n" + str(expected["bytes"]) + "\n",
             "original material push exact byte/hash readback")
        copy = copied["wrapper"]
        need(copy["status"] == "command_exited" and type(copy["phone"]["rc"]) is int
             and copy["phone"]["rc"] == 0 and copy["phone"]["stderr"] == "", "original material copy command outcome")
        row = strict(copy["phone"]["stdout"].encode("utf-8"))
        need(row["state"] == "EXACT_INPUT_COPIED_CREATE_ONLY" and row["source"] == "/proc/1/root" + source
             and type(row["effects"]) is int and row["effects"] == 0
             and row["target"]["path"] == target and {k: row["target"][k] for k in ("bytes", "sha256")} == expected,
             "original material create-only target bytes")
        full9(row["source_metadata"], "file", expected["bytes"])
        full9(row["target"]["metadata"], "file", expected["bytes"])
        results.append({"role": suffix, "bytes": expected["bytes"], "sha256": expected["sha256"],
                        "original_target": target, "original_target_metadata": row["target"]["metadata"]})
    return results


def verify_failure_semantics(files, by_path):
    doc = lambda relative: strict(files[OUT + "/" + relative])
    plan = doc("ROOT-PLAN.original.json")
    failure = doc("ROOT-FAILURE.json")
    need(pin(files[OUT + "/ROOT-PLAN.original.json"]) == PLAN_PIN
         and files[OUT + "/ROOT-PLAN.original.json"] == files[INPUT + "/ROOT-PLAN.json"], "same exact original and reserved plan bytes")
    need(plan["schema"] == "hepta.native-guard.root-chain-plan.v1" and plan["label"] == LABEL
         and plan["nonce"] == NONCE and plan["case_id"] == "NEG-01" and plan["boot_id"] == BOOT
         and plan["session_id"] == SESSION and plan["profile_id"] == "owner-open" and plan["out"] == OUT,
         "fixed R10 failed plan tuple")
    for role, expected, path in (("package", PACKAGE_PIN, OPERATOR + "/runtime/MANIFEST.json"),
                                 ("source_package", SOURCE_PIN, OPERATOR + "/root-chain/SOURCE-MANIFEST.json"),
                                 ("request", REQUEST_PIN, INPUT + "/REQUEST.txt")):
        need(plan[role] == {"path": path, **expected} and pin(files[path]) == expected, "original plan role differs: " + role)
    package = strict(files[OPERATOR + "/runtime/MANIFEST.json"])
    package_root = OUT + "/material/tree/package/"
    declared = package["files"]
    need(type(package["runtime_file_count"]) is int and package["runtime_file_count"] == len(declared) == 38,
         "all 38 original material package members declared")
    declared_paths = set()
    for row in declared:
        exact(row, ("path", "bytes", "sha256"), "original material package member descriptor")
        canonical_path(row["path"], False)
        need(type(row["bytes"]) is int and row["path"] not in declared_paths,
             "unique typed original package member")
        declared_paths.add(row["path"])
        need(package_root + row["path"] in files
             and pin(files[package_root + row["path"]]) == {k: row[k] for k in ("bytes", "sha256")},
             "original material package member bytes")
    need({p[len(package_root):] for p in files if p.startswith(package_root)} == declared_paths | {"MANIFEST.json"}
         and files[package_root + "MANIFEST.json"] == files[OPERATOR + "/runtime/MANIFEST.json"],
         "complete original material package and identical manifest copy")
    source_manifest = strict(files[OPERATOR + "/root-chain/SOURCE-MANIFEST.json"])
    root_source = [r for r in source_manifest["files"] if r.get("path") == "source/run_component_root_once.py"]
    need(len(root_source) == 1 and pin(files[OPERATOR + "/root-chain/source/run_component_root_once.py"])
         == {k: root_source[0][k] for k in ("bytes", "sha256")}, "actual original controller program source pin")
    request = files[INPUT + "/REQUEST.txt"]
    need(request.count(NONCE.encode()) == 1, "one original nonce in actual owner request")
    need(failure["state"] == "FAILED_OR_UNKNOWN_ORIGINALS_PRESERVED_NO_AUTOMATIC_CONTINUATION"
         and failure["error_type"] == "ValueError" and failure["detail"] == "phone actor unknown/nonzero; inspect original without replay",
         "original failure cause and terminal state")
    for key in ("automatic_retry", "new_identity_retry", "send_again", "business_qualified", "component_qualified"):
        need(failure[key] is False, "original failure must not promote " + key)
    for key in ("model_requests", "policy_changes", "signals_sent_by_coordinator"):
        need(type(failure[key]) is int and failure[key] == 0, "original coordinator count: " + key)
    need(failure["root_fixture_attempts"] == [] and failure["host_cleanup"] == {"host_children": [], "stream_cleanup_errors": []},
         "original coordinator-only cleanup facts")
    need(type(failure["steps"]) is list and tuple(x["phase"] for x in failure["steps"]) == PHASES,
         "exact seven phases ending at phone-stage")
    for phase, retained in zip(PHASES, failure["steps"]):
        result = doc(phase + "/RESULT.json")
        capture = doc(phase + "/OUTPUT-CAPTURE.json")
        intent = doc(phase + "/INTENT.json")
        child = doc(phase + "/CHILD.json")
        need(result == retained and result["state"] == "ORIGINAL_HOST_CHILD_JOINED"
             and type(result["returncode"]) is int and result["returncode"] == 0
             and result["automatic_retry"] is False, "exact joined original phase result")
        need(type(intent["maximum_starts"]) is int and type(child["maximum_starts"]) is int
             and intent["phase"] == capture["phase"] == result["phase"] == phase
             and intent["maximum_starts"] == child["maximum_starts"] == 1
             and intent["automatic_retry"] is False and intent["signals_on_timeout"] is False,
             "original phase once-only intent")
        need(type(result["pid"]) is int and result["pid"] > 0 and result["pid"] == capture["pid"] == child["pid"],
             "same original host phase PID")
        intent_sha = pin(files[OUT + "/" + phase + "/INTENT.json"])["sha256"]
        need(capture["source_intent_sha256"] == child["source_intent_sha256"] == intent_sha,
             "original phase intent/source binding")
        need(capture["schema"] == "hepta.native-guard.host-output-capture.v1" and capture["error"] is None
             and capture["stdout_eof"] is True and capture["stderr_eof"] is True
             and capture["worker_started"] is True and capture["worker_joined"] is True
             and capture["child_wait_returned"] is True and type(capture["child_returncode"]) is int
             and capture["child_returncode"] == 0 and capture["prefix_only_or_unknown"] is False
             and capture["remote_terminal_or_cleanup_proven"] is False
             and type(capture["signals_sent"]) is int and capture["signals_sent"] == 0
             and capture["persist_errors"] == [] and capture["pipe_close_errors"] == [],
             "complete host capture does not prove remote terminal or cleanup")
        for stream in ("stdout", "stderr"):
            path = OUT + "/" + phase + "/" + stream + ".original"
            expected = pin(files[path])
            need(type(result[stream]["bytes"]) is int and type(capture["captured"][stream]["bytes"]) is int
                 and result[stream] == {"path": path, **expected} and capture["captured"][stream] == expected,
                 "same original phase stream bytes")
            row = capture["files"][stream]
            need(type(row["bytes"]) is int and row["path"] == path and {k: row[k] for k in ("bytes", "sha256")} == expected
                 and row["original_created_inode_bound"] is True and set(row["metadata"]) == set(META_KEYS)
                 and [row["metadata"][k] for k in META_KEYS] == by_path[path]["metadata"],
                 "actual captured stream original full9")
            full9([row["metadata"][k] for k in META_KEYS], "file", expected["bytes"])
    material_transfers = verify_material_transfers(files)
    wrapped = doc("phone-stage/stdout.original")
    wrapper = wrapped["wrapper"]
    need(type(wrapped["actor_rc"]) is int and wrapped["actor_rc"] == 1
         and wrapper["schema"] == "hepta.phone-local.operator-result.v150.1"
         and wrapper["label"] == "ng-" + NONCE + "-stage"
         and wrapper["status"] == "failed_or_unknown_no_retry" and wrapper["error"] == "TimeoutError"
         and wrapper["automatic_replay"] is False and wrapper["model_decision"] is False
         and wrapper["native_task_result"] is False and wrapper["elapsed_seconds"] == 90.29949793312699,
         "original inner actor timeout, not phone success")
    need(wrapped["wrapper_sha256"] == "9ff0070e4bb97d91fa3028c09ff8334a9512dff5755a477c5d91e4f0c672f589",
         "original separately reported operator wrapper pin")
    lease_raw = files[OUT + "/material/tree/LEASE.json"]
    lease = strict(lease_raw)
    need(pin(lease_raw) == LEASE_PIN and lease["label"] == LABEL and lease["nonce"] == NONCE
         and lease["boot_id"] == BOOT and lease["case_id"] == "NEG-01"
         and lease["owner_request_sha256"] == REQUEST_PIN["sha256"]
         and lease["package_sha256"] == PACKAGE_PIN["sha256"], "original unchanged lease tuple")
    need(pin(files[OUT + "/material/component-inputs.tar.gz"]) == ARCHIVE_PIN
         and pin(files[OUT + "/material/tree/package/source/stage_component.py"]) == STAGE_PIN,
         "exact historical stage and stage-input archive")
    chain = doc("CHAIN-INTENT.json")
    need(chain["label"] == LABEL and chain["nonce"] == NONCE and chain["case_id"] == "NEG-01"
         and chain["lease_expires_unix_ms"] == lease["expires_unix_ms"]
         and chain["automatic_lease_extension"] is False and chain["automatic_retry"] is False,
         "original lease expiry retained without extension")
    # Parse a literal data assignment only; do not execute historical operator code.
    tree = ast.parse(files[OUT + "/phone-stage/stdin.original"])
    reqs = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
            and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "req"]
    need(len(reqs) == 1 and reqs[0]["kind"] == "shell" and reqs[0]["root"] is True
         and type(reqs[0]["timeout_seconds"]) is int and reqs[0]["timeout_seconds"] == 90,
         "unchanged original phone-stage 90-second budget")
    need(ARCHIVE_PIN["sha256"] in reqs[0]["command"] and LEASE_PIN["sha256"] in reqs[0]["command"]
         and PACKAGE_PIN["sha256"] in reqs[0]["command"] and "--execute-private-stage-once" in reqs[0]["command"],
         "actual original stage invocation binds original archive, lease and package")
    return {"plan": plan, "phase_count": len(PHASES), "historical_phone_operator_phases": 5,
            "material_transfers": material_transfers,
            "actor_rc": 1, "actor_status": wrapper["status"], "actor_error": wrapper["error"],
            "actor_elapsed_seconds": wrapper["elapsed_seconds"], "original_phone_stage_budget_seconds": 90,
            "original_lease_expires_unix_ms": lease["expires_unix_ms"]}


def verify_retained_r10_failure(expectation_raw, originals, *, implementation_source):
    """Return complete host-retention facts; never authorize fresh execution."""
    need(type(implementation_source) is bytes and implementation_source == globals().get("__bound_source_bytes__"),
         "declared implementation must equal bound compiled source bytes")
    need(pin(expectation_raw) == EXPECTATION_PIN, "one exact reviewed original-role manifest required")
    expected = strict(expectation_raw)
    need(expected["schema"] == "hepta.UNADOPTED.r10-failure-exact-originals.v1", "exact role-manifest schema")
    roles = expected["roles"]
    need(type(originals) is dict and set(originals) == set(roles), "all and only exact original roles required")
    for role, row in roles.items():
        descriptor(row)
        need(pin(originals[role]) == {k: row[k] for k in ("bytes", "sha256")}, "exact original bytes differ: " + role)
    index = strict(originals["retained_index"])
    inputs = strict(originals["retained_inputs"])
    exported = strict(originals["export_result"])
    for value in (index, inputs, exported):
        need(value["label"] == LABEL and value["nonce"] == NONCE and value["original_root_job"] == JOB
             and value["host"] == "mac" and value["retirement_accepted"] is False
             and type(value["native_case_credit"]) is int and value["native_case_credit"] == 0
             and value["global_unknown_effect_count"] is None and value["automatic_retry"] is False,
             "same retained R10 identity with unknown outcome and no promotion")
    need(index["original_failure_unknowns_preserved"] is True and index["all_files_read_twice_with_full9_bookends"] is True
         and index["all_three_censuses_equal"] is True and index["source"] == pin(originals["collector_source"])
         and index["inputs"] == pin(originals["retained_inputs"]), "original collector/index/input binding")
    need(exported["state"] == "COMPLETE_HOST_ORIGINALS_EXPORTED_NOT_RETIRED_OR_QUALIFIED"
         and exported["all_archive_members_hash_verified"] is True and exported["all_original_files_hash_verified_twice"] is True
         and exported["full9_and_complete_census_final_equal"] is True
         and all(type(exported[k]) is int for k in ("input_root_count", "input_entry_count", "input_file_count", "input_file_bytes"))
         and exported["input_root_count"] == 5 and exported["input_entry_count"] == 141
         and exported["input_file_count"] == 125 and exported["input_file_bytes"] == 13283382,
         "complete retained host export, not disposition")
    for key, role in (("archive", "retained_archive"), ("index", "retained_index"),
                      ("inputs", "retained_inputs"), ("source", "collector_source")):
        need(all(exported[key][k] == roles[role][k] for k in ("path", "bytes", "sha256")), "export role binding: " + role)
        full9(exported[key]["metadata"], "file", roles[role]["bytes"])
    for key in ("phone_stage_producer_terminal", "phone_stage_retirement", "phone_stage_terminal", "phone_stage_writes"):
        need(inputs[key] is None, "original unknown must stay null: " + key)
    need(inputs["original_nonce_consumed"] is True and inputs["new_nonce_authorized"] is False,
         "consumed original identity must not be made fresh")
    by_path = verify_inventory(index, inputs)
    files = verify_archive(originals["retained_archive"], originals["retained_index"], index, by_path)
    failure = verify_failure_semantics(files, by_path)
    controller = verify_controller(originals, failure["plan"])
    return {"schema": SCHEMA, "state": STATE, "implementation": pin(implementation_source),
            "expectation_source": pin(expectation_raw), "label": LABEL, "nonce": NONCE, "boot_id": BOOT,
            "case_id": "NEG-01", "profile_id": "owner-open", "session_id": SESSION,
            "original_plan": PLAN_PIN.copy(), "original_package": PACKAGE_PIN.copy(),
            "original_source_package": SOURCE_PIN.copy(), "original_request": REQUEST_PIN.copy(),
            "original_lease": LEASE_PIN.copy(), "original_stage": STAGE_PIN.copy(),
            "retained_archive": pin(originals["retained_archive"]), "retained_index": pin(originals["retained_index"]),
            "original_roles_verified": sorted(roles), "retained_root_count": 5, "retained_entry_count": 141,
            "retained_file_count": 125, "retained_file_bytes": 13283382, "archive_members_verified": 126,
            "original_material_runtime_files_verified": 38, "original_root_driver_source_pin_verified": True,
            "all_external_runtime_dependencies_reverified": False,
            "all_retained_member_bytes_and_original_metadata_relations_verified": True,
            "original_host_controller": controller,
            "original_host_phase_count": failure["phase_count"], "historical_phone_operator_phases": 5,
            "original_material_transfers": failure["material_transfers"],
            "material_copy_zero_effects_field_is_not_a_zero_file_writes_claim": True,
            "separate_operator_wrapper_original_bytes_verified": False,
            "original_actor_rc": 1, "original_actor_status": failure["actor_status"],
            "original_actor_error": failure["actor_error"], "original_actor_elapsed_seconds": failure["actor_elapsed_seconds"],
            "original_phone_stage_budget_seconds": 90, "original_lease_expires_unix_ms": failure["original_lease_expires_unix_ms"],
            "original_phone_terminal": None, "original_phone_stage_producer_terminal": None,
            "original_phone_stage_writes": None, "global_unknown_effect_count": None,
            "remote_terminal_or_cleanup_proven": False, "historical_failure_callsite": None,
            "original_nonce_consumed": True, "original_replay_allowed": False, "original_lease_refreshed": False,
            "complete_current_phone_scope_verified": False, "live_original_metadata_observed_by_this_function": False,
            "retirement_accepted": False, "fresh_execution_eligible": False, "standalone_execution_authorized": False,
            "nonce_creation_authorized": False, "component_qualified": False, "business_qualified": False,
            "native_case_credit": 0, "production_adopted": False,
            "reader_effects": {"file_reads": 0, "file_writes": 0, "phone_calls": 0, "native_submissions": 0,
                               "subprocesses": 0, "signals": 0, "new_nonces": 0},
            "scope_limit": "Complete exact retained host archive and controller terminal only. A new admitted full phone preservation, producer/namespace fences, predecessor and source adoption remain separate."}


def verify_with_reader(expectation_raw, *, read_pinned, implementation_source):
    """Optional explicit original-byte provider, checked before and after core.

    The provider's implementation/live metadata is not attested by this API.
    Production must bind its own real full9 reader; a fixture provider stays a
    fixture. This wrapper still has no effects except invoking that provider.
    """
    need(type(implementation_source) is bytes and implementation_source == globals().get("__bound_source_bytes__"),
         "declared implementation must equal bound compiled source bytes before callback")
    need(callable(read_pinned), "explicit original-byte provider required")
    need(pin(expectation_raw) == EXPECTATION_PIN, "exact original-role manifest before callback")
    roles = strict(expectation_raw)["roles"]
    originals = {role: read_pinned(dict(roles[role])) for role in sorted(roles)}
    result = verify_retained_r10_failure(expectation_raw, originals, implementation_source=implementation_source)
    for role in sorted(roles):
        after = read_pinned(dict(roles[role]))
        need(pin(after) == pin(originals[role]) and after == originals[role],
             "original byte provider changed across complete verification: " + role)
    return {"schema": "hepta.UNADOPTED.r10-retained-host-failure-readback.v1", "verified_failure": result,
            "provider_calls": 2 * len(roles), "byte_bookends_equal": True,
            "provider_implementation_or_live_metadata_attested": False,
            "runtime_admission": False, "production_adopted": False}
