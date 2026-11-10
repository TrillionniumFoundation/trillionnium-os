#!/usr/bin/env python3
"""Plan, or explicitly perform, one v30 -> v32 upgrade in an exclusive idle window.

Default mode is HOST ONLY. Execution performs one adb install -r -t and one
ordinary MAIN launch. It never starts a model/task, changes config/accessibility/
network settings, force-stops, retries, rolls back, imports models, or clears a
barrier. Android's package-replacement lifecycle may itself restart the App.
A candidate is published only after actual identity/config/model/readback checks.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
from types import SimpleNamespace

import v32_identity as identity
V32_IDENTITY = identity

SELECTOR_SHA = "3fb80f4bf8ebd153d2d448415f9f1512a29a209697f1468545df069532a40721"
OLD_APK_SHA = "a8c4be595fbd89d79bc1c7693b9f3c7d2b86ac9980fadc324dc10a5718d3c593"
NEW_APK_SHA = None  # Set only after actual v32 bundle validation.
CONFIG_SHA = None  # Fresh current configuration SHA must be supplied explicitly.
CERT_SHA = "202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5"
VERSION_NAME = identity.VERSION_NAME


def load(args):
    global NEW_APK_SHA, CONFIG_SHA
    selector = Path(__file__).resolve().parent / "select_runtime_once_v32_r1.py"
    raw, _ = identity.regular(selector, 131072)
    identity.need(identity.sha(raw) == SELECTOR_SHA, "selector is not the frozen v32 helper")
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("frozen_v32_upgrade_selector", selector)
    b = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(selector), "exec"), b.__dict__)
    modules, pins, proof = b.load_source(args)
    NEW_APK_SHA, CONFIG_SHA = args.apk_sha256, args.config_sha256
    return b, modules, pins, proof


def file_identity(b, path, digest):
    b.need(path.is_absolute() and path.is_file() and not path.is_symlink(), "regular absolute host APK required")
    before = path.stat()
    actual = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 << 20), b""):
            actual.update(chunk)
    b.need(actual.hexdigest() == digest, "host APK full SHA differs")
    return tuple(getattr(before, k) for k in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))


def host_apks(args, output, b):
    receipts = {}
    for label, path, digest in (("old", args.old_apk, OLD_APK_SHA), ("new", args.apk, NEW_APK_SHA)):
        receipts[label] = identity.verify_signature(path, digest, args.apksigner, output, "host-" + label + "-signature")
    receipts["new_permission_evidence"] = b.verify_host_apk_permissions(args, output)
    return receipts


def install_once(args, output, b, adb, report):
    argv = adb.base + ["install", "-r", "-t", str(Path(args.apk).expanduser())]
    b.write_new(output / "01-install.intent.json", b.encoded({
        "argv": argv, "started_wall_ms": int(time.time() * 1000), "timeout_s": 120,
        "outcome": "unknown_until_return_and_independent_readback", "automatic_retry": False}))
    report["install_invocation_attempted"] = True
    try:
        result = subprocess.run(argv, capture_output=True, timeout=120, check=False)
    except subprocess.TimeoutExpired as error:
        b.write_new(output / "01-install.stdout.bin", error.stdout or b"")
        b.write_new(output / "01-install.stderr.bin", error.stderr or b"")
        b.write_new(output / "01-install.returned.json", b.encoded({
            "exit_code": None, "client_timed_out": True, "phone_outcome": "unknown"}))
        raise RuntimeError("install client timed out; outcome unknown, no retry") from error
    b.write_new(output / "01-install.stdout.bin", result.stdout)
    b.write_new(output / "01-install.stderr.bin", result.stderr)
    b.write_new(output / "01-install.returned.json", b.encoded({
        "exit_code": result.returncode, "client_timed_out": False,
        "stdout_sha256": b.sha(result.stdout), "stderr_sha256": b.sha(result.stderr),
        "installed_identity_verified": False}))
    b.need(result.returncode == 0 and re.search(rb"(?m)^Success\r?$", result.stdout),
           "single install did not acknowledge Success; no retry")
    report["install_success_acknowledged"] = True


def execute(args, output, loaded, report):
    b, modules, pins, proof = loaded
    acceptance, inventory, profiles = modules
    b.need(args.exclusive_idle_window, "execution requires operator-owned --exclusive-idle-window")
    inventory.validate_connection(args)
    adb = acceptance.Adb(args, output)
    report["server_before"] = inventory.require_existing_adb_server(args, output, "before")
    report["phone_contacted"] = True

    def command(words, label, **kwargs):
        return adb.command(words, label=label, **kwargs)[1]

    def app(script, label, **kwargs):
        return command(["run-as", b.PACKAGE, "--user", "0", "sh", "-c", script], label, **kwargs)

    def no_workers(label):
        data = command(["ps", "-A", "-o", "PID,PPID,UID,NAME,ARGS"], label + "-workers")
        b.need(re.match(rb"\s*PID\b", data), "process list header unavailable")
        b.need(not b.WORKERS.search(data), "native inference/diagnostic worker present")

    def identity(label, expected_sha, version):
        b.need(command(["am", "get-current-user"], label + "-user").strip() == b"0", "current user differs")
        b.need(command(["getprop", "ro.soc.model"], label + "-soc").strip() == b"SM8750", "phone SoC differs")
        b.need(app("id -u", label + "-uid").strip() == str(b.UID).encode(), "app UID differs")
        paths = command(["pm", "path", b.PACKAGE], label + "-apk-path")
        match = re.fullmatch(rb"package:(/data/app/[^\s]+/base[.]apk)\r?\n", paths)
        b.need(match, "unique installed base APK required")
        apk_path = match.group(1).decode()
        actual = command(["sha256sum", apk_path], label + "-apk-sha", timeout=60).decode().split()
        b.need(actual and actual[0] == expected_sha, "installed full APK SHA differs")
        raw = command(["dumpsys", "package", b.PACKAGE], label + "-package")
        details = inventory.parse_package_dump(raw, 0)
        b.write_new(output / (label + "-package-parsed.json"), b.encoded(details))
        b.need(details["version_code"] == version and details["app_id"] == b.UID
               and details["current_user_installed"], "installed version/UID/user differs")
        b.need(details["internet_permission_declared"] is not True and b"android.permission.INTERNET" not in raw,
               "installed package contradicts permission-free source")
        if version == 32:
            b.need(details["version_name"] == VERSION_NAME, "installed v32 versionName differs")
            proof = report["host_apks"]["new_permission_evidence"]
            b.need(proof["apk_sha256"] == actual[0] and proof["internet_permission_declared"] is False,
                   "independent exact-APK permission evidence absent")
        report.setdefault("dumpsys_permission_observations", {})[label] = {
            "requested_permissions": details["requested_permissions"],
            "internet_permission_declared": details["internet_permission_declared"], "raw_sha256": b.sha(raw)}
        return {"package": b.PACKAGE, "uid": b.UID, "version_code": version,
                "version_name": details["version_name"], "apk_sha256": actual[0], "apk_path": apk_path}

    def snapshot(label):
        app(b.ROOT_GUARD + b.BARRIERS, label + "-barriers")
        journals = {}
        for kind, name in enumerate(b.JOURNALS):
            raw = adb.app_bytes("files/" + name, optional=True)
            b.need(b.clean_journal(None if raw is None else b.strict(raw), kind), "not a known clean journal: " + name)
            journals[name] = raw
            if raw is not None:
                b.write_new(output / (label + "-" + name), raw)
        scope_raw = adb.app_bytes("files/" + b.SCOPE_FILE, optional=True)
        b.need(scope_raw is None or len(scope_raw) <= 16384, "scope preservation byte bound")
        journals[b.SCOPE_FILE] = scope_raw
        if scope_raw is not None:
            b.write_new(output / (label + "-" + b.SCOPE_FILE), scope_raw)
        config_raw = adb.app_bytes(b.TARGET)
        b.need(b.sha(config_raw) == CONFIG_SHA, "current runtime config differs")
        app(b.stat_guard(b.TARGET, len(config_raw)), label + "-config-metadata")
        b.write_new(output / (label + "-runtime-config.json"), config_raw)
        prefs = {}
        for name in b.PREFS:
            raw = command(["settings", "--user", "0", "get", "secure", name], label + "-" + name)
            prefs[name] = raw
            b.write_new(output / (label + "-" + name + ".txt"), raw)
        no_workers(label)
        app(b.ROOT_GUARD + b.BARRIERS, label + "-barriers-after")
        return journals, config_raw, prefs

    report["identity_before"] = identity("before", OLD_APK_SHA, 30)
    before = snapshot("before-one")
    config = b.strict(before[1])
    b.need(isinstance(config, dict), "runtime config must be an object")
    canonical, profile = b.config_for(SimpleNamespace(
        profile=config.get("model_profile"), compute=config.get("compute"),
        context_tokens=config.get("context_tokens"), threads=config.get("threads")), profiles)
    b.need(config == canonical, "current config has noncanonical schema/fields")
    model_path = "files/model/" + profile["file"]
    model_guard = b.ROOT_GUARD + b.stat_guard(model_path, profile["bytes"])
    model_stat = app(model_guard + "stat -c '%i %s %Y %Z' " + shlex.quote(model_path), "model-metadata-before")
    model_sha = app("sha256sum " + shlex.quote(model_path), "model-full-sha", timeout=180).decode().split()
    b.need(model_sha and model_sha[0] == profile["sha256"], "actual selected model full SHA differs")
    b.need(app(model_guard + "stat -c '%i %s %Y %Z' " + shlex.quote(model_path), "model-metadata-after") == model_stat,
           "selected model changed during full hash")
    b.need(snapshot("before-two") == before, "idle journals/config/accessibility observations not stable")
    report["stable_idle_before_install"] = True
    report["actual_model_sha256_before_install"] = model_sha[0]
    report["selected_config_observed"] = config
    report["server_before_install"] = inventory.require_existing_adb_server(args, output, "install")
    # Recheck host file identity after phone preflight, before the only install.
    for label, path, digest in (("old", Path(args.old_apk).expanduser(), OLD_APK_SHA),
                                ("new", Path(args.apk).expanduser(), NEW_APK_SHA)):
        b.need(list(file_identity(b, path, digest)) == report["host_apks"][label]["stat"],
               "host APK changed before install")
    V32_IDENTITY.recheck_bundle(args, pins, proof)
    install_once(args, output, b, adb, report)

    report["identity_after_install"] = identity("installed", NEW_APK_SHA, 32)
    b.need(snapshot("installed") == before, "install changed journal/config/accessibility; no repair attempted")
    report["install_readback_verified"] = True
    b.write_new(output / "install-verified.json", b.encoded({
        "identity": report["identity_after_install"], "config_sha256": CONFIG_SHA,
        "journals_and_accessibility_bytes_preserved": True}))
    launch = b.mutate(adb, output, "02-normal-main", b.MAIN)
    b.need(re.search(rb"(?m)^Status: ok\s*$", launch), "ordinary MAIN launch not acknowledged")
    pid_raw = command(["pidof", b.PACKAGE], "after-main-pid")
    b.need(re.fullmatch(rb"[1-9][0-9]*\r?\n", pid_raw), "one ordinary App process not observed")
    report["app_pid_after_main"] = int(pid_raw)
    report["identity_after_main"] = identity("after-main", NEW_APK_SHA, 32)
    b.need(report["identity_after_main"] == report["identity_after_install"], "identity changed after ordinary MAIN")
    final = snapshot("after-main")
    b.need(final == before, "ordinary MAIN changed journal/config/accessibility or started work")
    b.need(app(model_guard + "stat -c '%i %s %Y %Z' " + shlex.quote(model_path), "model-metadata-final") == model_stat,
           "selected model metadata changed after full verification")
    report["server_after"] = inventory.require_existing_adb_server(args, output, "after")
    for name, words in (("display-ids", ["dumpsys", "SurfaceFlinger", "--display-id"]),
                        ("wm-size", ["wm", "size"])):
        b.write_new(output / (name + ".txt"), command(words, "after-main-" + name))
    # Both files are derived only from verified actual readback. No config rewrite.
    runtime_path, candidate_path = output / "runtime-config.json", output / "candidate.json"
    b.write_new(runtime_path, final[1])
    observed_config = b.strict(final[1])
    b.write_new(candidate_path, b.encoded({
        "package": b.PACKAGE, "apk_sha256": report["identity_after_main"]["apk_sha256"],
        "version_code": report["identity_after_main"]["version_code"], "uid": b.UID,
        "model_sha256": model_sha[0], "config_sha256": b.sha(final[1]),
        **V32_IDENTITY.report_fields(proof),
        **{key: observed_config[key] for key in ("model_profile", "compute", "context_tokens", "threads")}}))
    report.update(status="upgrade_verified", candidate_path=str(candidate_path), runtime_config_path=str(runtime_path),
                  final_configuration_sha256=b.sha(final[1]), ordinary_launch_verified=True,
                  final_accessibility_preferences_equal_original=True, journals_unchanged=True,
                  qualification_scope_file_unchanged=True,
                  final_no_native_worker_observed=True, selected_model_metadata_unchanged=True,
                  permission_free_host_apk_bound_to_installed_bytes=True, same_signing_certificate_verified=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    identity.add_arguments(p)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--old-apk", type=Path, required=True, help="retained exact signed v30 APK")
    p.add_argument("--config-sha256", required=True, help="fresh expected CURRENT raw config SHA")
    p.add_argument("--adb")
    p.add_argument("--adb-host")
    p.add_argument("--adb-port", type=int)
    p.add_argument("--serial")
    p.add_argument("--command-timeout", type=float, default=25)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--exclusive-idle-window", action="store_true")
    args = p.parse_args()
    identity.need(args.source.is_absolute() and args.output.is_absolute(), "source/output must be absolute host paths")
    identity.need(identity.HEX.fullmatch(args.config_sha256), "fresh current config SHA required")
    if args.execute:
        identity.need(all((args.adb, args.adb_host, args.adb_port, args.serial, args.exclusive_idle_window)),
                      "explicit connection and exclusive idle window required")
    output = args.output
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    identity.need(not output.is_symlink() and not output.stat().st_mode & 0o077, "private fresh output required")
    report = {"schema": "hepta.upgrade-v32-once.v1", "status": "host_validation_pending",
              "started_wall_ms": int(time.time() * 1000), "phone_contacted": False,
              "script_sha256": identity.sha(Path(__file__).read_bytes()), "selector_sha256": SELECTOR_SHA,
              "old_apk_sha256": OLD_APK_SHA, "new_apk_sha256": args.apk_sha256,
              "expected_config_sha256": args.config_sha256, "expected_uid": 10481,
              "install_invocation_attempted": False, "automatic_retry": False, "rollback_attempted": False,
              "model_or_task_started_by_script": False, "configuration_rewrite_attempted": False,
              "accessibility_restore_attempted": False, "network_setting_change_attempted": False,
              "model_load_qualified": None, "task_goal_verified": None, "accessibility_connection_verified": None,
              "execution_boundary": "operator-exclusive idle window; no App inference-slot reservation",
              "adb_boundary": "existing-server preflight plus pinned acceptance Adb; CLI retains server-version race"}
    identity.write_new(output / "REQUEST.json", identity.encoded({key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}))
    try:
        loaded = load(args)
        b, modules, pins, proof = loaded
        report.update(identity.report_fields(proof))
        report["host_build_identity"] = proof
        report["host_apks"] = host_apks(args, output, b)
        proof["host_signature_independently_verified"] = True
        report["status"] = "planned"
        identity.write_new(output / "PLAN.json", identity.encoded(report))
        if args.execute:
            report["status"] = "execution_in_progress"
            execute(args, output, loaded, report)
    except (Exception, KeyboardInterrupt) as error:
        report.update(status="stopped", error=type(error).__name__ + ": " + str(error),
                      unverified_mutation_outcomes="unknown; inspect durable intent/return and independent readback")
    finally:
        report["finished_wall_ms"] = int(time.time() * 1000)
        identity.write_new(output / "RESULT.json", identity.encoded(report))
        print(json.dumps({key: report.get(key) for key in ("status", "phone_contacted", "candidate_path", "runtime_config_path", "error")}, ensure_ascii=False))
    return 0 if report["status"] in ("planned", "upgrade_verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
