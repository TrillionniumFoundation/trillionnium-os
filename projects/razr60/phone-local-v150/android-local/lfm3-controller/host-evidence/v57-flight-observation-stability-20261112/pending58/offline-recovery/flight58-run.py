#!/usr/bin/env python3
"""One ordinary root-reviewed Start for a main58/helper6 background Web task.

This driver holds the existing operation_lock and sends no webpage input. The
local model alone may dispatch the current native AX capabilities. All native,
task, page/FD and cleanup files are preserved as originals; business and SDK
health are not assigned by this collector. There is no automatic Start/Stop retry.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

PKG = PACKAGE = "org.trillionnium.hepta.local"
HELPER = "org.trillionnium.hepta.webhelper"
SUPPORT_SHA = "ffc943520d277e4235f9e07eb6469881e7f0554878e675834318a6d3c86560e1"
TERMINAL_V53 = frozenset(("model_reported_done", "partial", "failed", "cancelled", "blocked", "controller_verified_done"))
START_CAPTURE_MAX_AGE_SECONDS = 10.0
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
support = None
RELEASE = RELEASE_INPUTS = PREVIOUS = PLAN = PREPARATION = None
INSTRUCTION = None
PINS = {}

def need(ok, message):
    if not ok:
        raise RuntimeError(message)

def module(path, expected, name):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts
         and all(not p.is_symlink() for p in (path, *path.parents)), "exact absolute helper path required")
    def stamp(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 8 << 20,
             "bounded regular helper source required")
        raw = stream.read((8 << 20) + 1)
        after = os.fstat(stream.fileno())
    need(len(raw) == before.st_size and stamp(before) == stamp(after) == stamp(path.stat())
         and hashlib.sha256(raw).hexdigest() == expected, "frozen helper differs: " + name)
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), "exec", dont_inherit=True), value.__dict__)
    need(stamp(path.stat()) == stamp(before) and path.read_bytes() == raw, "helper changed during import")
    return value



def require_native_idle(sample):
    need(not sample["errors"], "complete numeric process/display snapshot required")
    blockers = [p for p in sample["processes"]
                if "libhepta_local_runner.so" in p["args"]
                or "org.trillionnium.hepta.background.BackgroundDisplayBroker" in p["args"]]
    need(not blockers, "an existing native worker or broker still requires ordinary recovery")

def original_file(path):
    raw = support.exact(path, 16 << 20)[0]
    return support.strict(raw)

def collect_original_web(adb, args, report, samples, latest, baseline_runs):
    task = report["task_id"]
    budget = {"files": 0, "bytes": 0}
    task_rows = support.collect_private_tree(adb, PKG, "files/control-tasks/" + task,
                                             args.out / "evidence" / "task", budget)
    capture_index = support.original_capture_fd_index(args.out / "evidence", task)
    capture_index_raw = support.encoded(capture_index)
    report["capture_raw_index"] = support.write_new(args.out / "CAPTURE-RAW-INDEX.json", capture_index_raw)
    report["original_raw_fd_files"] = len(capture_index["files"])
    report["capture_index_is_business_verdict"] = False
    new_runs = sorted(set(adb.list_children("files/runs", directories=True)) - baseline_runs)
    need(len(new_runs) <= 64 and all(HEX32.fullmatch(r) for r in new_runs), "bounded original model run index")
    run_rows = []
    for run_id in new_runs:
        run_rows.extend(support.collect_private_tree(adb, PKG, "files/runs/" + run_id,
                         args.out / "evidence" / "runs" / run_id, budget))
    helper_rows = support.collect_private_tree(adb, HELPER, "files/web-evidence-v1",
                                               args.out / "evidence" / "helper", budget)
    markers = {}
    for marker in ("qualification-scope.json", "web-helper.active.json", "background-session.active.json",
                   "control-session.interrupted.json", "background-permission-interrupted.json"):
        data = adb.app_bytes("files/" + marker, optional=True)
        markers[marker] = data is not None
        if data is not None:
            write_new(args.out / "evidence" / "remaining-markers" / marker, data, binary=True)
    helper_raw = support.private_bytes(adb, HELPER, "files/web-evidence-v1/lease-journal.json", True, 65536)
    report["helper_journal_after_sha256"] = None if helper_raw is None else support.sha(helper_raw)
    if helper_raw is not None:
        write_new(args.out / "helper-journal-after.json", helper_raw, binary=True)
    report["markers_present_after"] = markers
    lifecycle = {"ordinary_close_verified": False, "bound_capture_present": False, "business_verified": False}
    try:
        lifecycle = support.original_web_summary(args.out / "evidence", task, PLAN,
                     report["installed_identity_after"], helper_raw, not markers["web-helper.active.json"])
    except Exception as error:
        lifecycle["error"] = type(error).__name__ + ": " + str(error)
    report["web_lifecycle"] = lifecycle
    system_clean = True
    try:
        for sample in samples[-2:]:
            require_native_idle(sample)
            need(not sample["target_task_displays"]
                 and not any(d["name"].startswith("hepta-bg-") for d in sample["displays"].values()),
                 "actual helper task/display still present")
    except Exception as error:
        system_clean = False
        report["remaining_system_resources"] = str(error)
    final_raw = support.private_bytes(adb, PKG, "files/control-session.json", False, 2 << 20)
    final = support.strict(final_raw)
    need(support.same_json(final, latest) and not active(final), "terminal task changed during original collection")
    write_new(args.out / "controller-session-after.json", final_raw, binary=True)
    report["controller_session_after_sha256"] = support.sha(final_raw)
    need(support.private_bytes(adb, HELPER, "files/web-evidence-v1/lease-journal.json", True, 65536) == helper_raw,
         "helper journal changed during original collection")
    for marker, present in markers.items():
        need((adb.app_bytes("files/" + marker, optional=True) is not None) is present,
             "cleanup marker presence changed during original collection")
    report.update(collection_complete=True, system_resources_absent=system_clean,
        original_model_run_directories=new_runs, native_input_or_model_outputs_synthesized=False,
        raw_original_evidence_bytes=budget["bytes"], raw_original_evidence_files=budget["files"])
    report["ready_for_next_lease"] = (final.get("cleanup_known") is True and not any(markers.values())
        and system_clean and lifecycle.get("ordinary_close_verified") is True
        and lifecycle.get("bound_capture_present") is True)
    report["two_lease_profiles_checked"] = False
    if PREVIOUS is not None and report["ready_for_next_lease"]:
        previous = PREVIOUS["web_lifecycle"]
        need(previous["profile_name"] != lifecycle["profile_name"]
             and previous["controller_session_nonce"] != lifecycle["controller_session_nonce"]
             and PREVIOUS["task_id"] != task, "second lease must use a fresh task/session/profile")
        report["two_lease_profiles_checked"] = True
        report["prior_lease_result_sha256"] = args.previous_lease_sha256
        report["prior_lease_profile"] = previous["profile_name"]
    collection = {"schema": "hepta.original-web-task-file-index.v2", "task_id": task,
                  "task_files": task_rows, "model_run_files": run_rows, "helper_files": helper_rows,
                  "raw_bytes": budget["bytes"], "file_count": budget["files"],
                  "collection_is_business_verdict": False, "capture_raw_index": report["capture_raw_index"],
                  "claim_scope": "Original task/model runs plus helper FD/profile journals; sequential file reads, not an atomic device snapshot."}
    write_new(args.out / "COLLECTION.json", collection)
    report["collection"] = {"path": str(args.out / "COLLECTION.json"),
                            "sha256": support.sha(support.exact(args.out / "COLLECTION.json", 2 << 20)[0])}

def execute(args, report):
    identity = load_pinned("v35_identity", args.identity_helper)
    receipts = load_pinned("warm_receipts", args.source_tools / "warm_receipts.py")
    profiles = load_pinned("model_profiles", args.source_tools / "model_profiles.py")
    acceptance = load_pinned("phone_acceptance", args.source_tools / "phone_acceptance.py")
    expected_config = checked_file(args.runtime_config, 4096)
    config = strict(expected_config)
    need(isinstance(config, dict) and config.get("compute") in ("gpu", "npu"), "GPU/NPU config required")
    selected = profiles.profile(config.get("model_profile"))
    need(type(config.get("context_tokens")) is int and config["context_tokens"] in (4096, 8192), "unsupported context")
    report.update(runtime_config_sha256=digest(expected_config), model_profile=config["model_profile"],
        expected_model_sha256=selected["sha256"], compute=config["compute"], helper_pins=PINS)
    reviewed_png = reviewed_windows = None
    if args.start_tap:
        reviewed_png = checked_file(args.prepared_screen, 16 << 20)
        reviewed_windows_raw = checked_file(args.prepared_window_dump, 8 << 20)
        need(digest(reviewed_png) == args.prepared_screen_sha256, "reviewed original screenshot file hash differs")
        need(digest(reviewed_windows_raw) == args.prepared_window_dump_sha256, "reviewed window dump file hash differs")
        reviewed_windows = reviewed_windows_raw.decode("utf-8", errors="strict")
        # Preserve original operator-reviewed input bytes, never a re-encoded crop.
        write_new(args.out / "reviewed-main.png", reviewed_png, binary=True)
        write_new(args.out / "reviewed-window-displays.txt", reviewed_windows_raw, binary=True)
    with identity.operation_lock(report):
        adb = identity.guard_adb(acceptance.Adb(args, args.out))
        bounded_private_reader(adb)
        # All file reads and observations below pass the same still-held readonly lock fd.
        hepta_before = package_identity(adb, PACKAGE, "before-hepta")
        need(hepta_before["uid"] == args.expected_uid and 10000 <= args.expected_uid < 90000, "ordinary APK UID differs")
        need(len(hepta_before["apks"]) == 1 and hepta_before["apks"][0]["sha256"] == args.apk_sha256, "installed exact APK differs")
        need(text(adb, ["run-as", PACKAGE, "id", "-u"], "run-as-uid").strip() == str(args.expected_uid), "private reader UID differs")
        target_before = package_identity(adb, args.target_package, "before-notes")
        report["installed_identity_before"] = {"hepta": hepta_before, "helper": target_before}
        support.installed_matches(hepta_before, RELEASE["controller"])
        support.installed_matches(target_before, RELEASE["helper"])
        need(text(adb, ["run-as", HELPER, "id", "-u"], "helper-private-uid").strip() == str(RELEASE["helper"]["uid"]),
             "actual helper private-reader UID differs")
        preferences_raw = support.original_preference_bytes(PREPARATION)
        need(support.read_ui_preferences(adb, args.expected_uid, "prestart-ordinary-choice") == preferences_raw,
             "saved explicit app preferences differ from reviewed preparation")
        write_new(args.out / "background-ui-choice-before.xml", preferences_raw, binary=True)
        report["ui_preferences_before_sha256"] = support.sha(preferences_raw)
        report["background_selection_from_preparation"] = support.background_selection_from_preparation(PLAN, PREPARATION)
        before_helper = support.helper_idle(adb)
        before_helper_raw = before_helper.pop("raw", None)
        report["helper_idle_before"] = before_helper
        if before_helper_raw is not None:
            write_new(args.out / "helper-journal-before.json", before_helper_raw, binary=True)
        if PREVIOUS is not None:
            need(before_helper.get("journal_sha256") == PREVIOUS["helper_journal_after_sha256"],
                 "previous exact closed helper journal changed before next lease")

        need(adb.app_bytes("files/model/runtime-config.json") == expected_config, "runtime config bytes differ")
        scope = adb.app_bytes("files/qualification-scope.json", optional=True)
        report["qualification_scope_present"] = scope is not None
        if scope is not None:
            report["qualification_scope_sha256"] = digest(scope)
            raise RuntimeError("existing qualification scope blocks background UI; preserved unchanged")
        need(text(adb, ["am", "get-current-user"], "current-android-user").strip() == "0", "only current Android user 0 is covered")
        enabled = text(adb, ["settings", "get", "secure", "enabled_accessibility_services"], "enabled-accessibility").strip().split(":")
        expected_service = PACKAGE + "/" + PACKAGE + ".HeptaAccessibilityService"
        expanded = [value.split("/", 1)[0] + "/" + (value.split("/", 1)[0] + value.split("/", 1)[1]
            if value.split("/", 1)[1].startswith(".") else value.split("/", 1)[1]) for value in enabled if "/" in value]
        report["formal_hepta_accessibility_enabled"] = expected_service in expanded
        need(report["formal_hepta_accessibility_enabled"], "formal Hepta accessibility service is disabled; no settings changed")
        accessibility = text(adb, ["dumpsys", "accessibility"], "accessibility-bound-state")
        services = text(adb, ["dumpsys", "activity", "services", PACKAGE + "/.HeptaAccessibilityService"], "formal-service-binding")
        report["formal_service_binding"] = formal_service_binding(services, args.expected_uid)
        report["component_named_in_accessibility_bound_table"] = formal_accessibility_bound(accessibility)
        report["formal_hepta_accessibility_bound"] = report["formal_service_binding"]["verified"]
        need(report["formal_hepta_accessibility_bound"], "formal Hepta service binding not independently readable; no UI trigger sent")
        need(adb.app_bytes("files/background-session.active.json", optional=True) is None, "unreleased background journal blocks new task")
        need(adb.app_bytes("files/web-helper.active.json", optional=True) is None, "unresolved official-web helper journal blocks new public Web task")
        for marker in ("control-session.interrupted.json", "background-permission-interrupted.json"):
            need(adb.app_bytes("files/" + marker, optional=True) is None, "unresolved prior latch blocks Web task")
        baseline = state(adb)
        need(not active(baseline) and baseline.get("blocked") is not True, "existing task/recovery is not idle")
        need(not baseline or baseline.get("cleanup_known") is True, "old cleanup state unknown")
        need(adb.app_bytes("files/control-session.interrupted.json", optional=True) is None, "interruption latch requires normal owner recovery")
        baseline_runs = set(adb.list_children("files/runs", directories=True))
        baseline_tasks = set(adb.list_children("files/control-tasks", directories=True))
        samples = [system_snapshot(adb, args.out, 0, args.target_package)]
        report["baseline_session"] = baseline
        need(not samples[0]["errors"], "system baseline could not be parsed; inspect retained raw commands")
        require_native_idle(samples[0])
        need(PACKAGE + "/" in samples[0].get("main_focus", "") and samples[0].get("input_focused_display") == 0,
             "Hepta must already be visible on main display")
        need(not samples[0].get("target_task_displays"), "public Web already has a task; close it normally before a new test")
        need(not any(x["name"].startswith("hepta-bg-") for x in samples[0]["displays"].values()), "existing Hepta display blocks new test")
        mapping_dump = text(adb, ["dumpsys", "display"], "prestart-logical-display-mapping")
        physical_dump = text(adb, ["dumpsys", "SurfaceFlinger", "--display-id"], "prestart-physical-display-mapping")
        write_new(args.out / "prestart-display-mapping.txt", mapping_dump.encode("utf-8"), binary=True)
        write_new(args.out / "prestart-physical-displays.txt", physical_dump.encode("utf-8"), binary=True)
        mapping = main_physical_display_mapping(mapping_dump, physical_dump, args.main_physical_display_id)
        report["main_physical_display_mapping"] = mapping
        # No UiAutomation is used here or during the task. Re-read the formal
        # binding after the long identity/baseline preflight and before any Start.
        prestart_accessibility = text(adb, ["dumpsys", "accessibility"], "prestart-accessibility-bound-state")
        prestart_services = text(adb, ["dumpsys", "activity", "services", PACKAGE + "/.HeptaAccessibilityService"], "prestart-formal-service-binding")
        report["prestart_formal_service_binding"] = formal_service_binding(prestart_services, args.expected_uid)
        report["component_named_in_prestart_accessibility_bound_table"] = formal_accessibility_bound(prestart_accessibility)
        report["formal_hepta_accessibility_bound_before_start"] = report["prestart_formal_service_binding"]["verified"]
        need(report["formal_hepta_accessibility_bound_before_start"], "formal Hepta service unbound before Start; no UI trigger sent")
        current_windows = None
        if args.start_tap:
            current_windows = text(adb, ["dumpsys", "window", "displays"], "prestart-window-insets")
            write_new(args.out / "prestart-window-displays.txt", current_windows.encode("utf-8"), binary=True)
        capture_started = time.monotonic()
        _, screen = adb.command(["screencap", "-p", "-d", args.main_physical_display_id], label="prepared-main-screen", raw=True, timeout=8)
        capture_ended = time.monotonic()
        with png_rgba(screen) as captured:
            need(list(captured.size) == mapping["screen_size"], "physical screenshot dimensions differ from logical main display")
        write_new(args.out / "prepared-main.png", screen, binary=True)
        report["prepared_screen_sha256"] = digest(screen)
        if args.start_tap:
            proof = compare_start_content(reviewed_png, screen, reviewed_windows, current_windows, args.start_tap)
            proof.update(capture_started_monotonic_s=capture_started, capture_ended_monotonic_s=capture_ended,
                maximum_capture_start_to_tap_seconds=START_CAPTURE_MAX_AGE_SECONDS)
            report["start_pixel_proof"] = proof
            need(proof["current_geometry"]["main_focus"] == samples[0]["main_focus"], "main focus changed before Start")
            need(proof["pixels_equal"], "application content differs from reviewed screenshot; no Start tap sent")
            proof["capture_start_to_tap_seconds"] = time.monotonic() - capture_started
            need(proof["capture_start_to_tap_seconds"] <= START_CAPTURE_MAX_AGE_SECONDS,
                 "fresh Start screenshot expired before tap; no retry sent")
            x, y = args.start_tap
            # No public Web input, HOME, target launch, shell calculation or direct broker IPC.
            report["start_attempted"] = True
            report["input_outcome_unknown"] = True
            report["trigger"] = {"kind": "one_exact_application_content_bound_start_tap",
                                 "coordinates": [x, y], "auto_task": False, "command_completed": False}
            adb.command(["input", "-d", "0", "tap", str(x), str(y)], label="existing-visible-hepta-start-button", timeout=3)
            report["trigger"]["command_completed"] = True
            report["input_outcome_unknown"] = False
        armed = time.monotonic()
        running_started = None
        task = None
        latest = baseline
        report["main_user"] = {"phase": "hepta", "attempted": False, "host_actions": [],
            "actor": "no_main_user_coexistence_actions_requested", "model_issued": False, "task_action": False}
        while time.monotonic() - (running_started or armed) < (args.timeout if task else args.start_window):
            samples.append(system_snapshot(adb, args.out, len(samples), args.target_package, phase=report["main_user"]["phase"]))
            latest = state(adb)
            candidate = latest.get("task_id")
            fresh = isinstance(candidate, str) and HEX32.fullmatch(candidate) and candidate not in baseline_tasks
            if fresh and task is None:
                need(latest.get("instruction_sha256") == digest(INSTRUCTION.encode()) and latest.get("origin") == "user_button"
                    and latest.get("debug_nonce_sha256") is None, "new task is not the exact visible-owner public Web request")
                task, running_started = candidate, time.monotonic()
                report["task_id"] = task
            if task:
                need(candidate == task, "task identity changed; no retry permitted")
                if not active(latest) and latest.get("status") in TERMINAL_V53:
                    break
            time.sleep(args.interval)
        report["last_session"] = latest
        need(task is not None, "no fresh background task started in armed window")
        if active(latest):
            report["manual_visible_stop_required"] = True
            raise RuntimeError("task deadline reached; no guessed Stop, PID kill or cleanup success claim; use existing visible Stop")
        # Two complete post-terminal system observations; app flags alone cannot prove display release.
        for _ in range(2):
            time.sleep(args.interval)
            samples.append(system_snapshot(adb, args.out, len(samples), args.target_package, phase=report["main_user"]["phase"]))
        hepta_after = package_identity(adb, PACKAGE, "after-hepta")
        target_after = package_identity(adb, args.target_package, "after-notes")
        report["installed_identity_after"] = {"hepta": hepta_after, "helper": target_after}
        need(hepta_after == hepta_before and target_after == target_before, "APK/UID identity changed during test")
        need(adb.app_bytes("files/model/runtime-config.json") == expected_config, "runtime config changed during test")
        need(adb.app_bytes("files/qualification-scope.json", optional=True) is None, "scope appeared during test")
        collect_original_web(adb, args, report, samples, latest, baseline_runs)
        after_preferences = support.read_ui_preferences(adb, args.expected_uid, "postcollection-ordinary-choice")
        write_new(args.out / "background-ui-choice-after.xml", after_preferences, binary=True)
        report["ui_preferences_after_sha256"] = support.sha(after_preferences)
        need(after_preferences == preferences_raw, "saved UI preferences changed during task or collection")
        report["ui_preferences_unchanged"] = True
        need(adb.app_bytes("files/model/runtime-config.json") == expected_config,
             "runtime config changed during original collection")
        need(support.unchanged(RELEASE_INPUTS), "sealed release original files changed")


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--case", choices=("flight",), required=True)
    p.add_argument("--lease-number", type=int, choices=(1, 2), required=True)
    for field in ("base-runner", "identity-helper", "source-tools", "runtime-config", "release-manifest",
                  "preparation", "review", "prepared-screen", "prepared-window-dump", "out"):
        p.add_argument("--" + field, type=Path, required=True)
    for field in ("release-manifest-sha256", "preparation-sha256", "review-sha256",
                  "prepared-screen-sha256", "prepared-window-dump-sha256",
                  "adb", "adb-host", "serial", "main-physical-display-id"):
        p.add_argument("--" + field, required=True)
    p.add_argument("--adb-port", type=int, required=True)
    p.add_argument("--start-tap", type=int, nargs=2, required=True)
    p.add_argument("--previous-lease", type=Path)
    p.add_argument("--previous-lease-sha256")
    p.add_argument("--existing-su-authorized", action="store_true", required=True)
    p.add_argument("--start-window", type=int, default=90)
    p.add_argument("--timeout", type=int, default=560)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--command-timeout", type=int, default=8)
    return p

def main():
    global support, RELEASE, RELEASE_INPUTS, PREVIOUS, PLAN, PREPARATION, INSTRUCTION, PINS
    args = parser().parse_args()
    sys.dont_write_bytecode = True
    support_path = Path(__file__).absolute().with_name("web_entry_support.py")
    support = module(support_path, SUPPORT_SHA, "v58_web_entry_support")
    RELEASE, release_proof, RELEASE_INPUTS = support.load_release(args.release_manifest, args.release_manifest_sha256)
    PLAN, plan_raw = support.plan_for(args.case)
    INSTRUCTION = PLAN["instruction"]
    base = support.pinned_module(args.base_runner, support.BASE_RUN_SHA, "frozen53_web_readers_no_main")
    base.MAIN_INFLIGHT = base.load_pinned("main_user_inflight", args.base_runner.with_name("main_user_inflight.py"))
    for name in ("need", "digest", "strict", "checked_file", "write_new", "load_pinned", "text",
                 "bounded_private_reader", "package_identity", "png_rgba", "main_physical_display_mapping",
                 "compare_start_content", "formal_accessibility_bound", "formal_service_binding",
                 "system_snapshot", "state", "active"):
        globals()[name] = getattr(base, name)
    PINS = {k: base.PINS[k] for k in ("v35_identity", "warm_receipts", "model_profiles", "phone_acceptance", "main_user_inflight")}
    args.apk_sha256 = RELEASE["controller"]["apk"]["sha256"]
    args.expected_uid = RELEASE["controller"]["uid"]
    args.target_package = HELPER
    args.test_mode = "background_only"
    need(all(HEX64.fullmatch(getattr(args, f)) for f in
         ("release_manifest_sha256", "preparation_sha256", "review_sha256",
          "prepared_screen_sha256", "prepared_window_dump_sha256")), "exact original argument digests required")
    preparation_raw = support.exact(args.preparation, 2 << 20)[0]
    need(support.sha(preparation_raw) == args.preparation_sha256, "original preparation changed")
    preparation = support.strict(preparation_raw)
    support.background_selection_from_preparation(PLAN, preparation)
    PREPARATION = preparation
    need(preparation.get("schema") == "hepta.ordinary-background-web-ui-preparation.v1"
         and preparation.get("prepared") is True and preparation.get("error") is None
         and preparation.get("task_started") is False
         and preparation.get("start_tapped") is False and preparation.get("case") == args.case
         and preparation.get("instruction") == INSTRUCTION
         and preparation.get("instruction_sha256") == PLAN["instruction_sha256"]
         and preparation.get("release", {}).get("manifest_sha256") == args.release_manifest_sha256
         and preparation.get("background_selection", {}).get("allowed_packages") == list(support.UI_PACKAGES)
         and preparation["background_selection"]["bootstrap_package"] in support.UI_PACKAGES
         and preparation["background_selection"]["expected_effective_lease_packages"] == [HELPER]
         and preparation.get("start_point") == args.start_tap,
         "exact explicit Notes/helper ordinary preparation required")
    prepared = preparation["background_web_reviewed_start_arguments"]
    need(prepared["target_package"] == HELPER and prepared["start_tap"] == args.start_tap
         and prepared["prepared_screen"] == str(args.prepared_screen)
         and prepared["prepared_screen_sha256"] == args.prepared_screen_sha256
         and prepared["prepared_window_dump"] == str(args.prepared_window_dump)
         and prepared["prepared_window_dump_sha256"] == args.prepared_window_dump_sha256,
         "reviewed Start original artifact linkage differs")
    review_raw = support.exact(args.review, 65536)[0]
    need(support.sha(review_raw) == args.review_sha256, "root review bytes changed")
    review = support.strict(review_raw)
    need(set(review) == {"schema", "preparation_sha256", "case", "instruction_sha256", "release_manifest_sha256",
         "prepared_screen_sha256", "prepared_window_dump_sha256", "start_point", "start_bounds",
         "selected_packages", "actual_whole_frame_visual_review_completed", "one_ordinary_start_authorized",
         "phone_action_issued_by_review"}
         and review["schema"] == "hepta.root-reviewed-web-start.v1"
         and review["preparation_sha256"] == args.preparation_sha256 and review["case"] == args.case
         and review["instruction_sha256"] == PLAN["instruction_sha256"]
         and review["release_manifest_sha256"] == args.release_manifest_sha256
         and review["prepared_screen_sha256"] == args.prepared_screen_sha256
         and review["prepared_window_dump_sha256"] == args.prepared_window_dump_sha256
         and review["start_point"] == args.start_tap and review["start_bounds"] == preparation["start_bounds"]
         and review["selected_packages"] == list(support.UI_PACKAGES)
         and review["actual_whole_frame_visual_review_completed"] is True
         and review["one_ordinary_start_authorized"] is True and review["phone_action_issued_by_review"] is False,
         "actual root visual review and one ordinary Start authorization required")
    if args.lease_number == 1:
        need(args.previous_lease is None and args.previous_lease_sha256 is None, "first lease cannot borrow a prior success")
    else:
        need(args.previous_lease is not None and isinstance(args.previous_lease_sha256, str)
             and HEX64.fullmatch(args.previous_lease_sha256), "second lease requires exact first original")
        prior_raw = support.exact(args.previous_lease, 2 << 20)[0]
        need(support.sha(prior_raw) == args.previous_lease_sha256, "prior lease result changed")
        PREVIOUS = support.strict(prior_raw)
        need(PREVIOUS.get("schema") == "hepta.v58-background-web-observation.v1"
             and PREVIOUS.get("lease_number") == 1 and PREVIOUS.get("error") is None
             and PREVIOUS.get("collection_complete") is True
             and PREVIOUS.get("ready_for_next_lease") is True
             and PREVIOUS.get("release", {}).get("manifest_sha256") == args.release_manifest_sha256
             and PREVIOUS.get("web_lifecycle", {}).get("ordinary_close_verified") is True
             and PREVIOUS["web_lifecycle"].get("bound_capture_present") is True,
             "first same-release lease must have original bound capture and ordinary closed profile")
    need(1 <= args.adb_port <= 65535 and 1 <= args.command_timeout <= 30 and 1 <= args.start_window <= 120
         and 540 <= args.timeout <= 600 and 0.25 <= args.interval <= 5
         and all(0 <= n <= 10000 for n in args.start_tap)
         and re.fullmatch(r"[1-9][0-9]{0,19}", args.main_physical_display_id)
         and int(args.main_physical_display_id) < 1 << 64, "bounded actual connection/display/Start arguments required")
    need(args.out.is_absolute() and not args.out.exists()
         and all(not p.is_symlink() for p in (args.out, *args.out.parents)), "fresh output root required")
    args.out.mkdir(mode=0o700)
    report = {"schema": "hepta.v58-background-web-observation.v1", "driver_revision": "web-helper6-natural-owner-automatic-target-two-lease-r1",
        "qualified": False, "business_verified": False, "sdk_teardown_verified": False,
        "case": args.case, "lease_number": args.lease_number, "instruction": INSTRUCTION,
        "instruction_sha256": PLAN["instruction_sha256"], "plan": PLAN, "plan_sha256": support.sha(plan_raw),
        "release": release_proof, "preparation_sha256": args.preparation_sha256, "review_sha256": args.review_sha256,
        "source_readers_sha256": support.BASE_RUN_SHA, "support_sha256": SUPPORT_SHA,
        "target_package": HELPER, "existing_su_authorization_operator_attested": True,
        "direct_broker_client_used": False, "private_nonce_trigger_used": False,
        "uiautomator_or_UiAutomation_used": False, "driver_webpage_actions": [],
        "model_required_for_page_actions": True, "automatic_retry": False,
        "collection_complete": False, "ready_for_next_lease": False,
        "start_attempted": False, "input_outcome_unknown": False,
        "started_wall_s": time.time()}
    try:
        execute(args, report)
    except BaseException as error:
        report["collection_complete"] = False
        report["ready_for_next_lease"] = False
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        try:
            need(support.unchanged(RELEASE_INPUTS), "sealed release artifacts changed")
            report["release_artifacts_unchanged"] = True
        except Exception as error:
            report["release_artifacts_unchanged"] = False
            report["collection_complete"] = False
            report["ready_for_next_lease"] = False
            report["release_artifact_error"] = type(error).__name__ + ": " + str(error)
        report["ended_wall_s"] = time.time()
        support.write_new(args.out / "RESULT.json", support.encoded(report))
    print(json.dumps({"collection_complete": report["collection_complete"],
                      "ready_for_next_lease": report["ready_for_next_lease"],
                      "task_id": report.get("task_id"), "error": report.get("error"),
                      "result": str(args.out / "RESULT.json"), "business_verified": False}, ensure_ascii=False), flush=True)
    return 0 if report["collection_complete"] and report.get("error") is None else 2

if __name__ == "__main__":
    raise SystemExit(main())
