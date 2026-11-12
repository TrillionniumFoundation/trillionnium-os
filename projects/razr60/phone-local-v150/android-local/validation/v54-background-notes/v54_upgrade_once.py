#!/usr/bin/env python3
"""Prepared, single-attempt original-signer v51 -> v54 upgrade; no IO on import.

Only the explicit ``install-once`` CLI can contact a device. It reuses the
reviewed harness's source/candidate verifiers and original fixed kernel lease.
The only device mutation is one ``adb install -r``. A durable consumed-attempt
receipt prevents replay, including after an ambiguous client outcome. This is
an installer, not background-agent or Notes qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from types import ModuleType

sys.dont_write_bytecode = True
HARNESS_SHA = "604f72e2654b777adc4a2a5b079dfcf455873f42681ee780a597994b2fbd86ae"
BASELINE_SHA = "e34775cd587ae1a68a04805dbdd42efd9a389cae21b11c83558d3a1306ec4313"
BASELINE_UID = 10481
BASELINE_VERSION = 51
BASELINE_VERSION_NAME = "0.51.0-local-notes-workflow"
BASELINE_RECEIPT_PATH = "/home/alex/hepta-local-007f-20261111/v51-build-r2/assembly-r1/RESULT.json"
PACKAGE = "org.trillionnium.hepta.local"
LOCK_PATH = "/home/alex/.local/state/hepta/razr-operation.lock"
LOCK_INODE = 58890228  # Existing original lock observed twice by the parent task.
ATTEMPT_PATH = "/home/alex/.local/state/hepta/razr-v54-upgrade-attempt.json"
RUNTIME_CONFIG = "files/model/runtime-config.json"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
WORKERS = ("libhepta_local_runner.so", "libhepta_mobimind_runner.so",
           "libhepta_ui_venus_runner.so", "org.trillionnium.hepta.background.BackgroundDisplayBroker")
SESSIONS = ("control-session.json", "mobi-probe-session.json", "ui-venus-probe-session.json",
            "background-permission-session.json")
BARRIERS = ("control-session.interrupted.json", "mobi-probe-interrupted.json",
            "ui-venus-probe-interrupted.json", "background-permission-interrupted.json",
            "background-session.active.json", "qualification-scope.json")


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked_file(path, maximum=16 << 20):
    """Bootstrap reader used before the pinned harness is executable."""
    path = Path(path)
    need(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)),
         "absolute non-symlink input required")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, "invalid bounded regular input")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(len(raw) == before.st_size and key(before) == key(after) == key(path.stat()), "input changed while read")
    return raw


def load_harness(path):
    raw = checked_file(path, 1 << 20)
    need(sha(raw) == HARNESS_SHA, "acceptance harness differs from the final reviewed SHA")
    module = ModuleType("_reviewed_v54_upgrade_harness")
    module.__file__, module.__package__ = str(path), ""
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def executable(path):
    raw = checked_file(path, 256 << 20)
    need(os.access(path, os.X_OK), "executable permission unavailable: " + str(path))
    return {"path": str(path), "sha256": sha(raw), "bytes": len(raw)}


def host_check(h, args, label, argv):
    """Host-only SDK inspection; no shell interpolation or device command."""
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    need(len(result.stdout) <= 2 << 20 and len(result.stderr) <= 2 << 20, "SDK output exceeded bound")
    h.write_new(args.out / (label + ".stdout.bin"), result.stdout, binary=True)
    h.write_new(args.out / (label + ".stderr.bin"), result.stderr, binary=True)
    h.write_new(args.out / (label + ".json"), {"argv": argv, "exit_code": result.returncode})
    need(result.returncode == 0, "host SDK verification failed: " + label)
    return result.stdout.decode("utf-8", errors="strict")


def verify_host(args, h, report):
    """All concrete assembly checks finish before any lock or ADB contact."""
    for name in ("assembly_result_sha256", "apk_sha256", "certificate_sha256", "dex_sha256", "runtime_config_sha256"):
        need(isinstance(getattr(args, name), str) and HEX64.fullmatch(getattr(args, name)), "explicit SHA required: " + name)
    need(type(args.apk_bytes) is int and 0 < args.apk_bytes <= 256 << 20, "explicit actual APK size required")
    need(args.certificate_sha256 == h.CERT_SHA and args.dex_sha256 == h.DEX_SHA, "reviewed signer/DEX differs")
    h.verify_source(args.source)
    modules = h.load_helpers(args.source)
    assembly = h.verify_candidate(args, modules)
    need(Path(assembly["apk"]) == args.apk and assembly["apk_sha256"] == args.apk_sha256
         and assembly["apk_bytes"] == args.apk_bytes, "explicit APK inputs differ from signed assembly proof")
    candidate = checked_file(args.apk, 256 << 20)
    need(sha(candidate) == args.apk_sha256 and len(candidate) == args.apk_bytes, "candidate changed after assembly verification")
    config = checked_file(args.runtime_config, 65536)
    need(sha(config) == args.runtime_config_sha256, "explicit runtime-config bytes differ")
    h.validate_config(config)
    staged = args.out / "candidate.apk"
    h.write_new(staged, candidate, binary=True)
    staged.chmod(0o400)
    report["host_tools"] = {name: executable(getattr(args, name)) for name in ("apksigner", "aapt2", "adb")}
    sig = host_check(h, args, "actual-apk-signature", [str(args.apksigner), "verify", "--verbose", "--print-certs", str(staged)])
    certs = re.findall(r"^Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F]{64})\s*$", sig, re.M)
    need(len(certs) == 1 and certs[0].lower() == h.CERT_SHA, "actual APK does not have the sole original signer")
    badging = host_check(h, args, "actual-apk-badging", [str(args.aapt2), "dump", "badging", str(staged)])
    package = re.findall(r"^package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'", badging, re.M)
    need(package == [(PACKAGE, str(h.VERSION_CODE), h.VERSION_NAME)], "actual packaged version/package differs")
    permissions = host_check(h, args, "actual-apk-permissions", [str(args.aapt2), "dump", "permissions", str(staged)])
    need(permissions.splitlines() == ["package: " + PACKAGE], "actual APK requests unexpected permissions")
    need(sha(checked_file(staged, 256 << 20)) == args.apk_sha256, "staged APK changed during SDK verification")
    report["host_verified"] = {"assembly_result_sha256": args.assembly_result_sha256,
        "apk_sha256": args.apk_sha256, "apk_bytes": args.apk_bytes, "signer_certificate_sha256": h.CERT_SHA,
        "dex_sha256": h.DEX_SHA, "version_code": h.VERSION_CODE, "version_name": h.VERSION_NAME,
        "library_count": 17, "source_manifest_sha256": h.MANIFEST_SHA,
        "runtime_config_sha256": args.runtime_config_sha256, "harness_sha256": HARNESS_SHA}
    return modules, staged, config


def integer(value, minimum=0, maximum=(1 << 63) - 1):
    return type(value) is int and minimum <= value <= maximum


def hex_value(value, length=64):
    return isinstance(value, str) and (HEX64 if length == 64 else HEX32).fullmatch(value) is not None


def text_value(value, maximum=80):
    return isinstance(value, str) and 0 < len(value.encode("utf-16-be")) // 2 <= maximum and "\0" not in value


def control_idle(h, value):
    h.fields(value, {"schema": "hepta.local-session.v1", "app_uid": BASELINE_UID,
        "pending": False, "running": False, "blocked": False, "cleanup_known": True,
        "external_model": False, "automatic_resume": False, "background_lease_unreleased": False}, "control terminal")
    need(integer(value.get("updated_wall_ms"), 1) and isinstance(value.get("state"), str), "invalid control terminal metadata")
    for key, length in (("task_id", 32), ("instruction_sha256", 64), ("debug_nonce_sha256", 64)):
        need(key in value and (value[key] is None or hex_value(value[key], length)), "invalid control identity: " + key)
    status = value.get("status")
    need(status in {"not_started", "cancelled_before_start", "model_reported_done", "controller_verified_done",
                    "partial", "failed", "cancelled"}, "unknown or administratively recovered control status refused")
    need(hex_value(value["instruction_sha256"]) and text_value(value.get("origin")), "control reservation identity missing")
    need((value["task_id"] is None) if status in {"not_started", "cancelled_before_start"}
         else hex_value(value["task_id"], 32), "control terminal task binding differs")
    if value["origin"] == "private_debug_nonce":
        need(hex_value(value["debug_nonce_sha256"]), "debug terminal nonce binding missing")


def diagnostic_idle(h, value, family):
    h.fields(value, {"schema": "hepta." + family + ".diagnostic-session.v1", "app_uid": BASELINE_UID,
        "pending": False, "running": False, "actions_executed": False, "external_model_used": False,
        "automatic_resume": False, "cleanup_known": True}, "diagnostic terminal")
    need(integer(value.get("updated_wall_ms"), 1) and hex_value(value.get("nonce_sha256"))
         and hex_value(value.get("owner_sha256")) and hex_value(value.get("request_id"), 32), "diagnostic identity unavailable")
    started, status = value.get("process_started"), value.get("status")
    need(type(started) is bool and type(value.get("native_binding_valid")) is bool, "diagnostic exit metadata malformed")
    early = {"preflight_failed", "cancelled_before_start", "submission_failed"}
    if started:
        need(value.get("process_exit_observed") is True and integer(value.get("exit_code"), 0, 255)
             and status in {"completed", "native_failed", "cancelled", "cancel_race", "timed_out"}, "diagnostic process exit unresolved")
        need(status != "cancelled" or value["exit_code"] != 0, "diagnostic cancellation exit ambiguous")
    else:
        need(value.get("process_exit_observed") is False and value.get("exit_code") is None and status in early,
             "diagnostic pre-launch state unresolved")
    need(value["native_binding_valid"] is (status == "completed"), "diagnostic native binding differs")
    need(status != "completed" or (started and value["exit_code"] == 0), "diagnostic completed without clean exit")


def permission_idle(h, value, read):
    """Read archived reservation/terminal receipt only; never run its command."""
    h.fields(value, {"schema": "hepta.background-permission-preparation.v1", "source": "visible_owner_button",
        "package_name": PACKAGE, "app_uid": BASELINE_UID, "installed_uid": BASELINE_UID,
        "command": ["su", "-c", "/system/bin/id -u"], "timeout_ms": 60000, "phase": "terminal",
        "automatic_retry": False, "automatic_resume": False, "permanent_authorization_proven": False,
        "display_created": False, "broker_started": False, "task_started": False, "model_started": False,
        "policy_database_modified": False, "cleanup_known": True, "terminal_receipt_published": True}, "permission terminal")
    need(hex_value(value.get("request_id"), 32) and hex_value(value.get("result_sha256"))
         and integer(value.get("app_pid"), 1, (1 << 31) - 1) and integer(value.get("boot_count"), -1, (1 << 31) - 1)
         and integer(value.get("started_elapsed_ms"), 0, (1 << 63) - 60001)
         and integer(value.get("deadline_elapsed_ms"))
         and value["deadline_elapsed_ms"] == value["started_elapsed_ms"] + 60000, "permission reservation identity malformed")
    started, status = value.get("process_started"), value.get("status")
    need(type(started) is bool and type(value.get("permission_verified")) is bool, "permission process state unknown")
    if not started:
        need(value.get("process_exit_observed") is False and value.get("exit_code") is None
             and value["permission_verified"] is False and status in {"not_started", "cancelled_before_start", "timed_out_before_start"},
             "permission request did not reach a clean terminal")
    else:
        need(value.get("process_exit_observed") is True and integer(value.get("exit_code"), 0, 255), "permission process exit unresolved")
        if value["permission_verified"]:
            h.fields(value, {"status": "verified", "exit_code": 0, "cancel_requested": False, "timed_out": False,
                "termination_requested": False, "forced_termination": False, "stdout_complete": True, "stderr_complete": True,
                "stdout_read_failed": False, "stderr_read_failed": False, "stdout_overflow": False, "stderr_overflow": False}, "permission completed probe")
            need(integer(value.get("stdout_bytes"), 1, 2) and hex_value(value.get("stderr_sha256"))
                 and value.get("stdout_sha256") == sha(b"0" if value["stdout_bytes"] == 1 else b"0\n"), "permission output receipt malformed")
        else:
            need(status in {"cancelled", "timed_out", "output_unverified", "not_authorized", "cleanup_unknown", "late_process_exit"},
                 "unknown permission terminal status")
    name = value.get("result_file")
    need(name in {"result.json", "late-exit.json"}, "permission terminal file differs")
    raw = read("files/background-permission-runs/" + value["request_id"] + "/" + name, optional=False)
    need(sha(raw) == value["result_sha256"], "permission archived terminal hash differs")
    expected = {k: v for k, v in value.items() if k not in {"result_sha256", "result_file"}}
    need(h.equal(h.strict(raw), expected), "permission archived terminal differs from journal")


def idle_private(adb, h, ref):
    raw = ref.text(adb, ["run-as", PACKAGE, "find", "files", "-mindepth", "1", "-maxdepth", "1", "-print"], "private-top-level")
    lines = raw.splitlines()
    need(len(raw.encode()) <= 65536 and len(lines) <= 256 and len(lines) == len(set(lines))
         and all(re.fullmatch(r"files/[A-Za-z0-9_.-]+", s) for s in lines), "private file enumeration malformed/oversized")
    names = {s[6:] for s in lines}
    forbidden = {name + suffix for name in BARRIERS for suffix in ("", ".bak", ".new")}
    forbidden.update(name + suffix for name in SESSIONS for suffix in (".bak", ".new"))
    need(not names.intersection(forbidden) and not any(n.startswith("control-session.recovery-pending-") for n in names),
         "background/qualification/interruption/recovery/uncommitted journal present; unchanged")
    snapshots = {}

    def read(path, *, optional=True):
        data = adb.app_bytes(path, optional=optional)
        need(data is None or 0 < len(data) <= 65536, "private journal empty or oversized")
        snapshots[path] = None if data is None else sha(data)
        return data

    for name in SESSIONS:
        value = read("files/" + name)
        need((value is not None) == (name in names), "private session appeared/disappeared during enumeration")
        if value is None:
            continue
        obj = h.strict(value)
        need(isinstance(obj, dict), "private session must be a JSON object")
        if name == SESSIONS[0]:
            control_idle(h, obj)
        elif name == SESSIONS[3]:
            permission_idle(h, obj, read)
        else:
            diagnostic_idle(h, obj, "mobimind" if name == SESSIONS[1] else "ui-venus")
    for suffix in (".bak", ".new"):
        need(read(RUNTIME_CONFIG + suffix) is None, "runtime config has an uncommitted sidecar")
    return snapshots


def installed(adb, ref, h, label):
    value = ref.package_identity(adb, PACKAGE, label)
    dump = ref.text(adb, ["dumpsys", "package", PACKAGE], label + "-version")
    versions = set(re.findall(r"\bversionCode=(\d+)\b", dump))
    names = set(re.findall(r"\bversionName=(\S+)", dump))
    need(len(versions) == 1 and len(names) == 1, "installed manifest identity unavailable/ambiguous")
    value.update(version_code=int(next(iter(versions))), version_name=next(iter(names)))
    return value


def private_identity(adb, ref, label):
    need(ref.text(adb, ["run-as", PACKAGE, "id", "-u"], label + "-private-uid").strip() == str(BASELINE_UID),
         "private app UID changed or is unreadable")
    need(ref.text(adb, ["am", "get-current-user"], label + "-android-user").strip() == "0", "Android user 0 required")


def identity_matches(value, expected_sha, version, version_name=None):
    return (isinstance(value, dict) and value.get("package") == PACKAGE and type(value.get("uid")) is int
        and value["uid"] == BASELINE_UID and type(value.get("version_code")) is int and value["version_code"] == version
        and isinstance(value.get("apks"), list) and len(value["apks"]) == 1
        and value["apks"][0].get("sha256") == expected_sha
        and (version_name is None or value.get("version_name") == version_name))


def preflight(adb, ref, h, args, expected_config, index):
    identity = installed(adb, ref, h, "before-" + str(index))
    need(identity_matches(identity, BASELINE_SHA, BASELINE_VERSION, BASELINE_VERSION_NAME),
         "device no longer equals exact formal v51 APK / UID10481; concurrent or unknown version preserved")
    private_identity(adb, ref, "before-" + str(index))
    config = adb.app_bytes(RUNTIME_CONFIG)
    need(config == expected_config, "installed runtime config differs from exact approved baseline bytes")
    journals = idle_private(adb, h, ref)
    system = ref.system_snapshot(adb, args.out, index, PACKAGE)
    need(system.get("errors") == [], "system process/display observation incomplete")
    need(isinstance(system.get("displays"), dict) and 0 in system["displays"] and isinstance(system.get("processes"), list),
         "system idle evidence missing")
    need(not any("hepta" in d.get("name", "").lower() for d in system["displays"].values()), "Hepta background display remains live")
    need(not any(any(token in p.get("args", "") for token in WORKERS) for p in system["processes"]),
         "local native runner or background broker remains live")
    return {"identity": identity, "runtime_config_sha256": sha(config), "private_journal_hashes": journals,
            "system_sample_index": index, "system_idle_observed": True}


def claim_attempt(identity, h, args, report):
    """A consumed-attempt journal, not a lock; only written under original lease."""
    identity.require_operation_lock("before_durable_single_attempt_receipt")
    path = Path(ATTEMPT_PATH)
    need(not os.path.lexists(path), "v54 attempt already consumed; inspect actual state, never replay installer")
    need(path.parent == Path(identity.OPERATION_LOCK_PATH).parent
         and all(not p.is_symlink() for p in (path, *path.parents)), "unexpected attempt receipt directory")
    info = path.parent.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
         "attempt receipt parent must be existing owned non-writable-by-others directory")
    value = {"schema": "hepta.v54-upgrade-attempt-consumed.v1", "created_wall_ns": time.time_ns(),
        "apk_sha256": args.apk_sha256, "assembly_result_sha256": args.assembly_result_sha256,
        "baseline_apk_sha256": BASELINE_SHA, "baseline_uid": BASELINE_UID,
        "harness_sha256": HARNESS_SHA, "evidence_directory": str(args.out),
        "may_have_submitted_install": True, "automatic_retry": False}
    identity.write_new(path, identity.encoded(value))  # Original helper fsyncs file AND parent.
    report["attempt_receipt"] = {"path": str(path), "sha256": sha(identity.encoded(value)), "consumed": True}


def install_once(adb, identity, h, args, staged, report, run=subprocess.run):
    need(sha(checked_file(staged, 256 << 20)) == args.apk_sha256, "staged APK changed before sole install")
    need(sha(checked_file(Path(args.adb), 256 << 20)) == report["host_tools"]["adb"]["sha256"], "ADB executable changed")
    claim_attempt(identity, h, args, report)
    argv = adb.base + ["install", "-r", str(staged)]
    result = {"argv": argv, "attempts": 0, "automatic_retry": False, "client_exit_code": None,
              "client_timed_out": False, "outcome_unknown": True, "started_wall_ns": time.time_ns()}
    report["install"] = result
    try:
        identity.require_operation_lock("immediately_before_sole_adb_install_r")
        result["attempts"] = 1
        completed = run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=args.install_timeout, check=False)
        stdout, stderr = completed.stdout, completed.stderr
        result.update(client_exit_code=completed.returncode, client_success=completed.returncode == 0
                      and stdout.decode("utf-8", errors="replace").splitlines().count("Success") == 1)
        result["outcome_unknown"] = not result["client_success"]
    except (Exception, KeyboardInterrupt) as error:
        stdout, stderr = getattr(error, "stdout", None) or b"", getattr(error, "stderr", None) or b""
        result.update(client_timed_out=isinstance(error, subprocess.TimeoutExpired), client_success=False,
                      error=type(error).__name__ + ": " + str(error))
    result.update(ended_wall_ns=time.time_ns(), stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
    # Evidence publication errors must not suppress the one read-only outcome observation.
    try:
        h.write_new(args.out / "install.stdout.bin", stdout, binary=True)
        h.write_new(args.out / "install.stderr.bin", stderr, binary=True)
    except Exception as error:
        result["evidence_write_error"] = type(error).__name__ + ": " + str(error)
    return result


def execute_phone(args, h, modules, staged, expected_config, report, *, run=subprocess.run):
    identity, ref, acceptance = (modules[name] for name in ("v35_identity", "background_reference", "phone_acceptance"))
    need(identity.OPERATION_LOCK_PATH == LOCK_PATH, "original fixed operation lock differs")
    report.update(all_pass=False, phone_qualified=False, background_agent_qualified=False, install_attempted=False)
    with identity.operation_lock(report):
        held_inode = report["operation_lock"].get("held_inode")
        need(type(held_inode) is int and held_inode == LOCK_INODE,
             "acquired lock inode differs from this session's observed original; no phone contact")
        need(not os.path.lexists(ATTEMPT_PATH), "previous v54 attempt consumed; no phone contact or replay")
        adb = identity.guard_adb(acceptance.Adb(args, evidence=args.out))
        ref.bounded_private_reader(adb)
        first = preflight(adb, ref, h, args, expected_config, 0)
        report["preflight_first"] = first
        final = preflight(adb, ref, h, args, expected_config, 1)
        report["preflight_immediately_before_install"] = final
        need(first["identity"] == final["identity"] and first["private_journal_hashes"] == final["private_journal_hashes"],
             "device identity or session journals changed during preflight; preserved unchanged")
        result = install_once(adb, identity, h, args, staged, report, run=run)
        report["install_attempted"] = result["attempts"] == 1
        # Always reconcile once after a submission attempt, including timeout/error.
        try:
            actual = installed(adb, ref, h, "after-sole-install")
            report["installed_identity_after"] = actual
            report["target_v54_observed"] = identity_matches(actual, args.apk_sha256, h.VERSION_CODE, h.VERSION_NAME)
            report["known_v51_still_observed"] = identity_matches(actual, BASELINE_SHA, BASELINE_VERSION, BASELINE_VERSION_NAME)
            private_identity(adb, ref, "after-sole-install")
            config = adb.app_bytes(RUNTIME_CONFIG)
            report["config_after"] = {"sha256": sha(config), "same_exact_bytes": config == expected_config}
            need(report["target_v54_observed"] and config == expected_config, "post-install APK/version/UID/config differs or outcome is unresolved")
            report["private_journal_hashes_after"] = idle_private(adb, h, ref)
            report["postconditions_verified"] = True
        except (Exception, KeyboardInterrupt) as error:
            report["reconciliation_error"] = type(error).__name__ + ": " + str(error)
            report["postconditions_verified"] = False
        report["installation_confirmed"] = (result.get("client_success") is True
            and "evidence_write_error" not in result and report.get("postconditions_verified") is True)
    lock = report.get("operation_lock", {})
    report["all_pass"] = (report.get("installation_confirmed") is True and lock.get("released") is True
                          and lock.get("continuity_verified") is True)
    return report


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=["install-once"])
    for name in ("harness", "source", "assembly-result", "apk", "runtime-config", "apksigner", "aapt2", "adb", "out"):
        p.add_argument("--" + name, required=True, type=Path)
    for name in ("assembly-result-sha256", "apk-sha256", "certificate-sha256", "dex-sha256", "runtime-config-sha256"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--apk-bytes", required=True, type=int)
    p.add_argument("--adb-host", required=True)
    p.add_argument("--adb-port", required=True, type=int)
    p.add_argument("--serial", required=True)
    p.add_argument("--command-timeout", type=float, default=8)
    p.add_argument("--install-timeout", type=float, default=180)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    need(0 < args.command_timeout <= 30 and 0 < args.install_timeout <= 300, "bounded command timeouts required")
    need(1 <= args.adb_port <= 65535 and re.fullmatch(r"[A-Za-z0-9_.:-]+", args.adb_host)
         and re.fullmatch(r"[A-Za-z0-9_.:-]+", args.serial), "explicit unambiguous ADB endpoint required")
    need(args.out.is_absolute() and all(not p.is_symlink() for p in (args.out, *args.out.parents)), "absolute safe output path required")
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    h = load_harness(args.harness)
    report = {"schema": "hepta.original-signer-v54-upgrade.v1", "prepared_only": False,
        "all_pass": False, "phone_qualified": False, "background_agent_qualified": False,
        "harness_sha256": HARNESS_SHA, "script_sha256": sha(checked_file(Path(__file__).absolute(), 1 << 20)),
        "baseline_apk_sha256": BASELINE_SHA, "baseline_uid": BASELINE_UID, "automatic_retry": False,
        "prior_baseline_receipt": {"path": BASELINE_RECEIPT_PATH, "sha256": h.BASELINE_RECEIPT_SHA,
            "scope": "Previously verified formal assembly; this run separately rereads actual installed APK identity."},
        "no_app_launch_requested": True, "no_settings_or_model_config_write_requested": True,
        "operation_lock_boundary": "Cooperative host operators only; UI/uncooperative operators are not frozen atomically."}
    try:
        modules, staged, config = verify_host(args, h, report)
        execute_phone(args, h, modules, staged, config, report)
    except (Exception, KeyboardInterrupt) as error:
        report.update(all_pass=False, error=type(error).__name__ + ": " + str(error))
    h.write_new(args.out / "RESULT.json", report)
    print(json.dumps({"all_pass": report["all_pass"], "phone_qualified": False,
        "result": str(args.out / "RESULT.json"), "install_attempted": report.get("install_attempted", False)}, sort_keys=True))
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
