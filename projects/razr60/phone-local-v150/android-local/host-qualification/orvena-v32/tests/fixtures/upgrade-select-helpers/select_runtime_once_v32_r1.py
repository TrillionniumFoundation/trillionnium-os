#!/usr/bin/env python3
"""Plan, or explicitly perform, one idle Hepta v32 runtime-config replacement.

Default mode is HOST ONLY. --execute requires an operator-owned exclusive idle
window. It never starts a task/inference, changes network settings, installs,
retries a mutation, rolls back, or clears a recovery barrier. The explicit
--restore-observed-accessibility option restores only the exact original service
list after config publication, for this phone's pinned force-stop side effects.
The ordinary MAIN launch is the only launch. candidate.json is written only after
verified configuration readback; it is not model-load or phone-task qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import uuid

import v32_identity as identity
V32_IDENTITY = identity

PACKAGE = "org.trillionnium.hepta.local"
APK_SHA = None  # Set only by the verified actual v32 bundle.
UID = 10481
TARGET = "files/model/runtime-config.json"
SCOPE_FILE = "qualification-scope.json"
JOURNALS = ("control-session.json", "mobi-probe-session.json", "ui-venus-probe-session.json")
LATCHES = ("control-session.interrupted.json", "mobi-probe-interrupted.json", "ui-venus-probe-interrupted.json")
PENDING = ("debug-task.json", "mobi-probe-request.json", "ui-venus-probe-request.json")
PREFS = ("enabled_accessibility_services", "accessibility_enabled")
ORIGINAL_SERVICES_SHA = "e57178be14eae0a4c7f161b07c0abb652231dbfc7fce1a0a67bdd3e6dc0dedc7"
STOPPED_SERVICES = (
    b"org.trillionnium.hepta.localprobe/.HeptaAccessibilityService:com.motorola.actioncore/.screenhelper.TalkBackService\n",
    b"org.trillionnium.hepta.localprobe/.HeptaAccessibilityService:com.motorola.actioncore/.screenhelper.TalkBackService:com.motorola.actioncore/com.motorola.actioncore.screenhelper.TalkBackService\n",
)
HEX = re.compile(r"[0-9a-f]{64}\Z")
WORKERS = re.compile(rb"libhepta_[A-Za-z0-9_.-]*(?:runner|worker)[A-Za-z0-9_.-]*[.]so|hepta-mobimind-probe|hepta-geniex-once|geniex[-_]bench|llama-(?:bench|cli)")
HELPERS = ("phone_acceptance", "phone_inventory", "model_profiles", "warm_receipts")
CONTRACTS = ("LocalRuntimeConfig", "LocalModelEngine", "SessionRecovery", "MobiMindSessionContract", "UiVenusSessionContract", "WarmProcessSession")


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict(data):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "duplicate JSON key: " + key)
            value[key] = item
        return value
    def bad(value):
        raise ValueError("non-finite JSON: " + value)
    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()


def write_new(path, data):
    """Create-only private evidence, including fsync of its directory entry."""
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def load_source(args):
    global APK_SHA
    modules, pins, proof = identity.load_bundle(args)
    APK_SHA = args.apk_sha256
    return modules, pins, proof


def config_for(args, profiles):
    profile = profiles.profile(args.profile)
    need(args.compute in ("npu", "gpu"), "compute must be npu or gpu")
    need(not (args.compute == "npu" and "q4_k_m" in args.profile and args.profile not in ("orvena-4b-q4_k_m", "nanbeige4.2-3b-q4_k_m")), "this Q4_K_M profile has not been admitted for NPU testing")
    # These two closed Q4_K_M profiles have source support in the pinned
    # runtime. Admission permits an experimental test, not model qualification.
    need(type(args.context_tokens) is int and args.context_tokens in (4096, 8192) and type(args.threads) is int and 1 <= args.threads <= 8,
         "runtime parameters outside v32 contract")
    config = {"schema": "hepta.local-runtime.v2", "model_profile": args.profile,
              "compute": args.compute, "context_tokens": args.context_tokens, "threads": args.threads}
    return config, profile


def clean_journal(value, kind):
    """Closed subset of the pinned v32 recovery contracts; acknowledged-idle is refused."""
    if value is None:
        return True
    if not isinstance(value, dict) or type(value.get("app_uid")) is not int or value["app_uid"] != UID:
        return False
    if type(value.get("updated_wall_ms")) is not int or value["updated_wall_ms"] <= 0:
        return False
    if value.get("cleanup_known") is not True or any(value.get(k) is not False for k in ("pending", "running", "automatic_resume")):
        return False
    def hx(key, length):
        return isinstance(value.get(key), str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value[key]) is not None
    if kind == 0:
        if value.get("schema") != "hepta.local-session.v1" or value.get("blocked") is not False or value.get("external_model") is not False:
            return False
        if not isinstance(value.get("state"), str) or not isinstance(value.get("origin"), str) or not 0 < len(value["origin"]) <= 80:
            return False
        if not hx("instruction_sha256", 64) or "debug_nonce_sha256" not in value:
            return False
        if value["debug_nonce_sha256"] is not None and not hx("debug_nonce_sha256", 64):
            return False
        if value["origin"] == "private_debug_nonce" and not hx("debug_nonce_sha256", 64):
            return False
        if value.get("status") in ("not_started", "cancelled_before_start"):
            return "task_id" in value and value["task_id"] is None
        return value.get("status") in ("model_reported_done", "partial", "failed", "cancelled") and hx("task_id", 32)
    if value.get("schema") != ("hepta.mobimind.diagnostic-session.v1" if kind == 1 else "hepta.ui-venus.diagnostic-session.v1"):
        return False
    if any(value.get(k) is not False for k in ("actions_executed", "external_model_used")):
        return False
    if not hx("nonce_sha256", 64) or not hx("owner_sha256", 64) or not hx("request_id", 32):
        return False
    status, code = value.get("status"), value.get("exit_code")
    no_start = ("preflight_failed", "cancelled_before_start", "submission_failed")
    if status not in (*no_start, "completed", "native_failed", "cancelled", "cancel_race", "timed_out"):
        return False
    if value.get("process_started") is True:
        if value.get("process_exit_observed") is not True or type(code) is not int or not 0 <= code <= 255 or status in no_start:
            return False
        if status == "cancelled" and code == 0:
            return False
    elif value.get("process_started") is not False or value.get("process_exit_observed") is not False or "exit_code" not in value or code is not None or status not in no_start:
        return False
    return (value.get("process_started") is True and code == 0 and value.get("native_binding_valid") is True
            if status == "completed" else value.get("native_binding_valid") is False)


ROOT_GUARD = ("set -eu; test -d files; test ! -L files; test -d files/model; test ! -L files/model; "
              "hepta_root=$(pwd -P); case \"$hepta_root\" in /data/user/0/" + PACKAGE + "|/data/data/" + PACKAGE + ") ;; *) exit 41;; esac; "
              "test \"$(readlink -f files/model)\" = \"$hepta_root/files/model\"; ")
BARRIERS = " ".join("if [ -e files/{0} ] || [ -L files/{0} ]; then exit 41; fi;".format(name)
                    for name in (*LATCHES, *PENDING, *(j + s for j in JOURNALS for s in (".bak", ".new"))))
BARRIERS += ' for p in files/control-session.recovery-pending-*.record; do if [ -e "$p" ] || [ -L "$p" ]; then exit 41; fi; done; '
BARRIERS += " ".join("if [ -e files/{0}{1} ] || [ -L files/{0}{1} ]; then exit 41; fi;".format(SCOPE_FILE, suffix) for suffix in (".bak", ".new"))
BARRIERS += ' if [ -e files/instrumentation-fixtures/ACTIVE.json ] || [ -L files/instrumentation-fixtures/ACTIVE.json ]; then exit 41; fi; '
MAIN = ["am", "start", "-W", "--user", "0", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", "-n", PACKAGE + "/.MainActivity"]


def stat_guard(path, size):
    need(re.fullmatch(r"files/model/[A-Za-z0-9_.-]+", path) is not None, "unsafe private file")
    p = shlex.quote(path)
    return ("test -f {p}; test ! -L {p}; test \"$(stat -c '%u %a %h %s' {p})\" = '{uid} 600 1 {size}'; ").format(p=p, uid=UID, size=size)


def hash_guard(path, expected):
    need(HEX.fullmatch(expected), "invalid expected file SHA")
    return "test \"$(sha256sum " + shlex.quote(path) + " | cut -d ' ' -f 1)\" = '" + expected + "'; "


def replace_script(temp, before_raw, after_raw, journal_raw):
    script = ROOT_GUARD + BARRIERS
    for name, raw in journal_raw.items():
        p = "files/" + name
        if raw is None:
            script += "test ! -e {p}; test ! -L {p}; ".format(p=shlex.quote(p))
        else:
            script += "test -f {p}; test ! -L {p}; ".format(p=shlex.quote(p)) + hash_guard(p, sha(raw))
    script += stat_guard(TARGET, len(before_raw)) + hash_guard(TARGET, sha(before_raw))
    script += stat_guard(temp, len(after_raw)) + hash_guard(temp, sha(after_raw))
    script += "mv -f " + shlex.quote(temp) + " " + shlex.quote(TARGET) + "; "
    script += "test ! -e {p}; test ! -L {p}; ".format(p=shlex.quote(temp))
    return script + stat_guard(TARGET, len(after_raw)) + hash_guard(TARGET, sha(after_raw)) + "printf 'REPLACED\\n'"


def mutate(adb, output, label, words, data=None):
    # Intent is durable BEFORE a command can change phone state. No inferred false
    # outcome is written if command issuance, response, or verification is unknown.
    intent = {"operation": label, "argv": words, "stdin_sha256": None if data is None else sha(data),
              "started_wall_ms": int(time.time() * 1000), "outcome": "unknown_until_separate_verification"}
    write_new(output / (label + ".intent.json"), encoded(intent))
    code, response = adb.command(words, label=label, input_data=data)
    write_new(output / (label + ".returned.json"), encoded({"exit_code": code, "stdout_sha256": sha(response),
              "remote_exit_observed": True, "postcondition_verified": False}))
    return response


def observed_stop_preferences(original, observed, restore_enabled):
    """Accept only the exact baseline or the two actually observed stop states."""
    need(set(original) == set(PREFS) and set(observed) == set(PREFS), "unexpected preference keys")
    if not restore_enabled:
        need(observed == original, "accessibility preference changed; explicit observed restoration not enabled")
        return
    need(sha(original["enabled_accessibility_services"]) == ORIGINAL_SERVICES_SHA
         and original["accessibility_enabled"] == b"1\n", "restoration is only authorized for the pinned original four-service state")
    need(observed["accessibility_enabled"] == original["accessibility_enabled"]
         and observed["enabled_accessibility_services"] in (original["enabled_accessibility_services"], *STOPPED_SERVICES),
         "accessibility state differs from every explicitly observed force-stop side effect")


def restore_services_script(observed, original):
    observed_stop_preferences(original, observed, True)
    script = "set -eu; "
    for name in PREFS:
        script += "test \"$(settings --user 0 get secure {n})\" = {v}; ".format(
            n=name, v=shlex.quote(observed[name].decode("ascii").rstrip("\n")))
    # accessibility_enabled remains exactly 1; only the changed service list is written.
    return script + "settings --user 0 put secure enabled_accessibility_services " + shlex.quote(
        original["enabled_accessibility_services"].decode("ascii").rstrip("\n"))


def verify_host_apk_permissions(args, output):
    """Bind the frozen assembler's no-permissions rule to the exact installed APK hash.

    A missing dumpsys section stays UNKNOWN. This independent host APK inspection
    supplies the declaration evidence; it never changes the original observation.
    """
    apk = Path(args.apk).expanduser()
    aapt2 = Path(args.aapt2).expanduser()
    need(apk.is_absolute() and apk.is_file() and not apk.is_symlink(), "explicit regular host APK required")
    need(aapt2.is_absolute() and aapt2.is_file() and os.access(aapt2, os.X_OK), "explicit host aapt2 executable required")
    before = apk.stat()
    digest = hashlib.sha256()
    with apk.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 << 20), b""):
            digest.update(chunk)
    need(digest.hexdigest() == APK_SHA, "host APK is not the exact frozen installed candidate")
    captures = {}
    for label, words in (("badging", ["dump", "badging", str(apk)]),
                         ("permissions", ["dump", "permissions", str(apk)]),
                         ("manifest", ["dump", "xmltree", str(apk), "--file", "AndroidManifest.xml"])):
        argv = [str(aapt2)] + words
        result = subprocess.run(argv, capture_output=True, timeout=30, check=False)
        write_new(output / ("host-apk-" + label + ".stdout.txt"), result.stdout)
        write_new(output / ("host-apk-" + label + ".stderr.txt"), result.stderr)
        write_new(output / ("host-apk-" + label + ".command.json"), encoded({"argv": argv, "exit_code": result.returncode}))
        need(result.returncode == 0, "aapt2 failed; APK permission declaration stays unknown")
        captures[label] = result.stdout.decode("utf-8", "strict")
    badging = re.findall(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'", captures["badging"], re.MULTILINE)
    need(badging == [(PACKAGE, str(identity.VERSION_CODE), identity.VERSION_NAME)]
         and "native-code: 'arm64-v8a'" in captures["badging"], "actual APK package/version/ABI differs")
    # Same no-uses-permission / no-INTERNET rule as pinned assemble_pocket4.py.
    # Require the actual package header so empty/truncated tool output is not proof.
    need(captures["permissions"].splitlines() == ["package: " + PACKAGE], "APK does not have the exact permission-free declaration")
    need("E: manifest" in captures["manifest"] and "android.permission.INTERNET" not in captures["manifest"],
         "APK manifest unavailable or declares INTERNET")
    after = apk.stat()
    need(tuple(getattr(before, k) for k in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))
         == tuple(getattr(after, k) for k in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")),
         "host APK changed during permission verification")
    return {"host_apk": str(apk), "apk_sha256": digest.hexdigest(), "apk_bytes": before.st_size,
            "method": "aapt2 dump permissions + xmltree on full-SHA-bound host APK; pinned assembler rule",
            "version_code": identity.VERSION_CODE, "version_name": identity.VERSION_NAME,
            "badging_stdout_sha256": sha(captures["badging"].encode()),
            "permissions_stdout_sha256": sha(captures["permissions"].encode()),
            "manifest_stdout_sha256": sha(captures["manifest"].encode()),
            "internet_permission_declared": False, "requested_permissions": []}


def execute(args, output, modules, config, profile, report):
    acceptance, inventory, _ = modules
    need(args.exclusive_idle_window, "--execute requires an operator-owned --exclusive-idle-window")
    inventory.validate_connection(args)
    adb = acceptance.Adb(args, output)
    def command(words, label, **kwargs):
        return adb.command(words, label=label, **kwargs)[1]
    def app(script, label, **kwargs):
        return command(["run-as", PACKAGE, "--user", "0", "sh", "-c", script], label, **kwargs)
    def prefs(label):
        return {name: command(["settings", "--user", "0", "get", "secure", name], label + "-" + name) for name in PREFS}
    def identity(label):
        need(command(["am", "get-current-user"], label + "-user").strip() == b"0", "current user is not 0")
        need(command(["getprop", "ro.soc.model"], label + "-soc").strip() == b"SM8750", "unexpected phone SoC")
        need(app("id -u", label + "-uid").strip() == str(UID).encode(), "app UID differs")
        paths = command(["pm", "path", PACKAGE], label + "-apk-path")
        match = re.fullmatch(rb"package:(/data/app/[^\s]+/base[.]apk)\r?\n", paths)
        need(match, "unique installed base APK required")
        apk = match.group(1).decode()
        need(command(["sha256sum", apk], label + "-apk-sha", timeout=60).decode().split()[0] == APK_SHA, "APK differs from exact v32")
        package_raw = command(["dumpsys", "package", PACKAGE], label + "-package")
        details = inventory.parse_package_dump(package_raw, 0)
        write_new(output / (label + "-package-parsed.json"), encoded(details))
        need(details["version_code"] == 32 and details["version_name"] == V32_IDENTITY.VERSION_NAME and details["app_id"] == UID and details["current_user_installed"],
             "installed package identity differs")
        need(details["internet_permission_declared"] is not True and b"android.permission.INTERNET" not in package_raw,
             "installed package contradicts permission-free APK")
        proof = report["host_apk_permission_evidence"]
        need(proof["apk_sha256"] == APK_SHA and proof["internet_permission_declared"] is False,
             "independent exact-APK permission evidence missing")
        report.setdefault("dumpsys_permission_observations", {})[label] = {
            "requested_permissions": details["requested_permissions"],
            "internet_permission_declared": details["internet_permission_declared"], "raw_sha256": sha(package_raw)}
        return {"package": PACKAGE, "apk_sha256": APK_SHA, "version_code": 32, "uid": UID, "apk_path": apk}
    def no_workers(label):
        data = command(["ps", "-A", "-o", "PID,PPID,UID,NAME,ARGS"], label + "-processes")
        need(data.startswith(b"PID") or re.match(rb"\s+PID", data), "process list header missing")
        need(not WORKERS.search(data), "native inference/diagnostic worker present")
    def idle(label, expected_config_sha):
        app(ROOT_GUARD + BARRIERS, label + "-barriers")
        values = {}
        for kind, name in enumerate(JOURNALS):
            data = adb.app_bytes("files/" + name, optional=True)
            need(clean_journal(None if data is None else strict(data), kind), "not a known clean journal: " + name)
            values[name] = data
        scope_raw = adb.app_bytes("files/" + SCOPE_FILE, optional=True)
        need(scope_raw is None or len(scope_raw) <= 16384, "scope file exceeds bounded preservation contract")
        values[SCOPE_FILE] = scope_raw
        data = adb.app_bytes(TARGET)
        need(sha(data) == expected_config_sha, "runtime config changed unexpectedly")
        app(stat_guard(TARGET, len(data)), label + "-config-metadata")
        no_workers(label)
        app(ROOT_GUARD + BARRIERS, label + "-barriers-after")
        return values, data
    def app_stopped(label):
        code, data = adb.command(["pidof", PACKAGE], label=label, allowed=(0, 1))
        need(code == 1 and not data.strip(), "app restarted or remains alive; no second force-stop is allowed")
        no_workers(label)
    report["server_before"] = inventory.require_existing_adb_server(args, output, "before")
    report["phone_contacted"] = True
    report["identity_before"] = identity("before")
    first, old_raw = idle("idle-first", args.config_sha256)
    old_prefs = prefs("before")
    observed_stop_preferences(old_prefs, old_prefs, args.restore_observed_accessibility)
    model_path = "files/model/" + profile["file"]
    model_guard = ROOT_GUARD + stat_guard(model_path, profile["bytes"])
    before_stat = app(model_guard + "stat -c '%i %s %Y %Z' " + shlex.quote(model_path), "model-metadata-before")
    actual_model_sha = app("sha256sum " + shlex.quote(model_path), "model-full-sha", timeout=180).decode().split()[0]
    need(actual_model_sha == profile["sha256"], "selected model full SHA differs")
    need(app(model_guard + "stat -c '%i %s %Y %Z' " + shlex.quote(model_path), "model-metadata-after") == before_stat,
         "model changed during full SHA verification")
    second, old_again = idle("idle-second", args.config_sha256)
    need((first, old_raw) == (second, old_again) and prefs("stable") == old_prefs, "idle/config/accessibility observations not stable")
    write_new(output / "old-runtime-config.json", old_raw)
    for name, raw in old_prefs.items():
        write_new(output / ("old-a11y-" + name + ".txt"), raw)
    for name, raw in first.items():
        if raw is not None:
            write_new(output / ("old-" + name), raw)
    report["model_full_sha_verified"] = actual_model_sha
    report["stable_idle_before_mutation"] = True
    new_raw = encoded(config)
    temp = "files/model/.runtime-select-" + uuid.uuid4().hex + ".tmp"
    report["temporary_path"] = temp
    report["server_before_mutation"] = inventory.require_existing_adb_server(args, output, "mutation")
    V32_IDENTITY.recheck_bundle(args, report.pop("_source_pins"), report["host_build_identity"])
    # No remote command is repeated: a timeout/nonzero return exits to RESULT.
    mutate(adb, output, "01-force-stop", ["am", "force-stop", "--user", "0", PACKAGE])
    app_stopped("after-stop")
    need(idle("stopped-idle", args.config_sha256) == (first, old_raw), "force-stop changed journal/config; stop without repair")
    stopped_prefs = prefs("stopped")
    observed_stop_preferences(old_prefs, stopped_prefs, args.restore_observed_accessibility)
    report["observed_accessibility_after_stop"] = {k: v.decode() for k, v in stopped_prefs.items()}
    create = ROOT_GUARD + BARRIERS + stat_guard(TARGET, len(old_raw)) + hash_guard(TARGET, sha(old_raw))
    create += "set -C; umask 077; test ! -e {t}; test ! -L {t}; cat > {t}; chmod 600 {t}; ".format(t=shlex.quote(temp))
    create += stat_guard(temp, len(new_raw)) + hash_guard(temp, sha(new_raw))
    mutate(adb, output, "02-create-private-temp", ["run-as", PACKAGE, "--user", "0", "sh", "-c", create], new_raw)
    app_stopped("before-replace")
    before_replace_prefs = prefs("before-replace")
    observed_stop_preferences(old_prefs, before_replace_prefs, args.restore_observed_accessibility)
    report["observed_accessibility_before_replace"] = {k: v.decode() for k, v in before_replace_prefs.items()}
    response = mutate(adb, output, "03-atomic-replace", ["run-as", PACKAGE, "--user", "0", "sh", "-c",
                      replace_script(temp, old_raw, new_raw, first)])
    need(response == b"REPLACED\n", "replacement completion marker missing")
    need(idle("replaced-idle", sha(new_raw)) == (first, new_raw), "replacement readback/journals differ")
    report["configuration_replacement_verified"] = True
    write_new(output / "replacement-verified.json", encoded({"config_sha256": sha(new_raw), "old_config_sha256": sha(old_raw)}))
    app_stopped("before-main")
    before_restore_prefs = prefs("before-restore")
    observed_stop_preferences(old_prefs, before_restore_prefs, args.restore_observed_accessibility)
    report["observed_accessibility_before_restore"] = {k: v.decode() for k, v in before_restore_prefs.items()}
    if before_restore_prefs != old_prefs:
        # Config is already verified and the App was still stopped. Restoring the
        # service may now start the App; it must not be force-stopped again.
        mutate(adb, output, "04-restore-original-service-pref", ["sh", "-c", restore_services_script(before_restore_prefs, old_prefs)])
        need(prefs("restored") == old_prefs, "original accessibility preference restoration not verified; no retry")
        report["observed_accessibility_restoration_verified"] = True
    launch = mutate(adb, output, "05-normal-main", MAIN)
    need(re.search(rb"(?m)^Status: ok\s*$", launch) is not None, "ordinary MAIN launch not acknowledged")
    pid_bytes = command(["pidof", PACKAGE], "after-main-pid")
    need(re.fullmatch(rb"[1-9][0-9]*\r?\n", pid_bytes), "one normal app process was not observed")
    report["observed_app_pid_after_main"] = int(pid_bytes)
    report["identity_after"] = identity("after")
    need(report["identity_after"] == report["identity_before"], "installed identity changed")
    need(idle("after-main-idle", sha(new_raw)) == (first, new_raw), "ordinary launch changed journal/config or started native work")
    need(prefs("after") == old_prefs, "accessibility preferences changed; no automatic repair")
    need(app(model_guard + "stat -c '%i %s %Y %Z' " + shlex.quote(model_path), "model-metadata-final") == before_stat,
         "selected model metadata changed after verification")
    report["server_after"] = inventory.require_existing_adb_server(args, output, "after")
    write_new(output / "runtime-config.json", new_raw)
    write_new(output / "candidate.json", encoded({"package": PACKAGE, "apk_sha256": APK_SHA, "version_code": 32,
              "uid": UID, "config_sha256": sha(new_raw),
              **V32_IDENTITY.report_fields(report["host_build_identity"]),
              "model_sha256": actual_model_sha, **{key: config[key] for key in ("model_profile", "compute", "context_tokens", "threads")}}))
    report.update(status="configuration_verified", final_configuration_sha256=sha(new_raw),
                  ordinary_launch_verified=True, final_accessibility_preferences_equal_original=True,
                  journals_unchanged=True, qualification_scope_file_unchanged=True,
                  final_no_native_worker_observed=True, permission_free_host_apk_bound_to_installed_bytes=True,
                  same_signing_certificate_verified=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    identity.add_arguments(p)
    p.add_argument("--profile", required=True)
    p.add_argument("--compute", choices=("npu", "gpu"), required=True)
    p.add_argument("--context-tokens", type=int, default=8192)
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--config-sha256", required=True, help="fresh expected CURRENT raw config SHA")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--exclusive-idle-window", action="store_true")
    p.add_argument("--restore-observed-accessibility", action="store_true")
    p.add_argument("--adb")
    p.add_argument("--adb-host")
    p.add_argument("--adb-port", type=int)
    p.add_argument("--serial")
    p.add_argument("--command-timeout", type=float, default=25)
    args = p.parse_args()
    need(args.source.is_absolute() and args.output.is_absolute(), "source/output must be absolute host paths")
    need(HEX.fullmatch(args.config_sha256), "fresh current config SHA required")
    if args.execute:
        need(all((args.adb, args.adb_host, args.adb_port, args.serial, args.exclusive_idle_window)),
             "explicit connection and exclusive idle window required")
    output = args.output
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    need(not output.is_symlink() and not output.stat().st_mode & 0o077, "private fresh output required")
    report = {"schema": "hepta.select-runtime-once.v3-observed-accessibility", "status": "host_validation_pending",
              "started_wall_ms": int(time.time() * 1000), "phone_contacted": False,
              "script_sha256": sha(Path(__file__).read_bytes()), "expected_version_code": 32,
              "expected_apk_sha256": args.apk_sha256, "expected_uid": UID,
              "old_config_sha256_expected": args.config_sha256, "automatic_retry": False,
              "rollback_attempted": False, "model_or_task_started_by_script": False,
              "restore_observed_accessibility_authorized": args.restore_observed_accessibility,
              "model_load_qualified": None, "task_goal_verified": None, "accessibility_connection_verified": None,
              "execution_boundary": "operator-exclusive idle window; no App inference slot reservation",
              "adb_boundary": "existing-server preflight plus pinned acceptance Adb; CLI retains server-version race",
              "replacement_boundary": "guarded same-directory rename; assumes exclusive operator window, not a concurrent-writer atomic CAS"}
    write_new(output / "REQUEST.json", encoded({key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}))
    try:
        modules, pins, proof = load_source(args)
        report.update(identity.report_fields(proof))
        report["host_build_identity"] = proof
        config, profile = config_for(args, modules[2])
        report.update(selected_config=config, selected_model=profile)
        report["host_signature"] = identity.verify_signature(args.apk, args.apk_sha256, args.apksigner, output, "host-new-signature")
        proof["host_signature_independently_verified"] = True
        report["host_apk_permission_evidence"] = verify_host_apk_permissions(args, output)
        write_new(output / "proposed-runtime-config.json", encoded(config))
        report["status"] = "planned"
        write_new(output / "PLAN.json", encoded(report))
        if args.execute:
            report["status"] = "execution_in_progress"
            report["_source_pins"] = pins
            execute(args, output, modules, config, profile, report)
    except (Exception, KeyboardInterrupt) as error:
        report.update(status="stopped", error=type(error).__name__ + ": " + str(error),
                      unverified_mutation_outcomes="unknown; inspect per-operation intent, return and independent readback",
                      temporary_files="retained if created; no cleanup/rollback attempted")
    finally:
        report.pop("_source_pins", None)
        report["finished_wall_ms"] = int(time.time() * 1000)
        write_new(output / "RESULT.json", encoded(report))
        print(json.dumps({key: report.get(key) for key in ("status", "phone_contacted", "selected_config", "error", "final_configuration_sha256")}, ensure_ascii=False))
    return 0 if report["status"] in ("planned", "configuration_verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
