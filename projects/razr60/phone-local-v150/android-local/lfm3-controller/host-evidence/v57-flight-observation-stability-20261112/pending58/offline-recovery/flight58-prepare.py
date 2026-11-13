#!/usr/bin/env python3
"""Prepare ordinary main58 UI for one natural public-Web model task.

Run only as the existing cooperative owner child. This explicitly selects the
released helper6 and existing Notes packages, then prefills one natural OWNER. It never taps
Start, controls a page, changes the model, grants permissions or invokes a broker.
Root reviews the original full PNG before a separate once-Start runner.
"""
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

PKG = "org.trillionnium.hepta.local"
TARGET = "org.trillionnium.hepta.webhelper"
NOTES = "com.motorola.stylus"
SELECTED_UI_PACKAGES = (NOTES, TARGET)
UI_SHA = 'b5483ad51dc3639a734d07169a7ad928f0ddf7ad2f5a46da4b3461abe8170c98'
R12_SHA = 'd5a2caec2ad96b524d89651c0b4fbb63107678745dd4ccfa33368999fc0f817c'
MODE = "background_only"
SUPPORT_SHA = "ffc943520d277e4235f9e07eb6469881e7f0554878e675834318a6d3c86560e1"


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


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


def recent_task_report(raw):
    """Conservative report of exact-package references; never removes a task."""
    header = "ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)"
    recognized = len(re.findall(r"^" + re.escape(header) + r"[ \t]*$", raw, re.M)) == 1
    pattern = re.compile(r"(?<![A-Za-z0-9_.])" + re.escape(TARGET) + r"(?![A-Za-z0-9_.])")
    matches = [{"line": index, "text": line} for index, line in enumerate(raw.splitlines(), 1) if pattern.search(line)]
    return {"schema": "hepta.background-preparation-recents.v1", "dump_sha256": sha(raw.encode()),
            "recognized_header": recognized, "target_references": matches,
            "target_reference_present": bool(matches), "task_removal_attempted": False,
            "scope": "exact-package references in the complete observed recents dump; any match blocks readiness"}


def scope_button(ui):
    matches = []
    for node in ui["xml"].iter("node"):
        if node.get("package") != PKG or node.get("enabled") != "true":
            continue
        label = node.get("text", "")
        if label == "选择后台应用范围":
            matches.append((node, 0))
        else:
            match = re.fullmatch(r"后台范围：([1-6]) 个应用（更改）", label)
            if match:
                matches.append((node, int(match.group(1))))
    need(len(matches) <= 1, "background scope button ambiguous")
    return matches[0] if matches else None


def visible_in(helper, node, viewport):
    if node.get("visible-to-user") == "false":
        return False
    try:
        l, t, r, b = helper.bounds(node)
    except RuntimeError:
        return False
    return viewport[0] <= l < r <= viewport[2] and viewport[1] <= t < b <= viewport[3]


def choice_rows(ui, helper):
    helper.exact_node(ui, "本次后台可操作应用（最多 6 个）")
    lists = [n for n in ui["xml"].iter("node") if n.get("package") == PKG and n.get("class") == "android.widget.ListView"]
    need(len(lists) == 1, "one observed background app list required")
    viewport = helper.bounds(lists[0])
    rows = {}
    for n in lists[0].iter("node"):
        match = re.fullmatch(r".+ · ([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)", n.get("text", ""))
        if not match or n.get("package") != PKG or not visible_in(helper, n, viewport):
            continue
        need(n.get("checkable") == "true" and n.get("checked") in ("true", "false")
             and n.get("enabled") == "true", "observed app row is not an enabled checkbox")
        package = match.group(1)
        need(package not in rows, "duplicate visible app package")
        rows[package] = n
    need(rows, "no supported visible background app choices")
    return lists[0], rows


def automatic_target_observation(ui, helper, expected_text):
    """Read one visible actual automatic target; never choose an initial app."""
    spinners = [n for n in ui["xml"].iter("node") if n.get("package") == PKG
                and n.get("class") == "android.widget.Spinner"]
    need(not spinners, "recognized natural Web OWNER must hide the initial-app Spinner")
    automatic = [n for n in ui["xml"].iter("node") if n.get("package") == PKG
                 and n.get("class") == "android.widget.TextView"
                 and n.get("text", "").startswith("本次将自动使用：")]
    need(len(automatic) <= 1 and (not automatic or automatic[0].get("text") == expected_text),
         "actual automatic target label is ambiguous or differs from the observed helper label")
    if automatic and visible_in(helper, automatic[0], helper.bounds(helper.outer_scroll(ui))):
        return automatic[0]
    return None


def execute(args, report):
    sys.dont_write_bytecode = True
    uihelper = module(args.ui_helper, UI_SHA, "frozen_v46_ui_prepare")
    background = module(args.background_driver, R12_SHA, "frozen_r12_readers")
    support = module(Path(__file__).absolute().with_name("web_entry_support.py"), SUPPORT_SHA, "frozen_v58_web_entry_support")
    release, release_proof, retained = support.load_release(args.release_manifest, args.release_manifest_sha256)
    need(args.expected_uid == release["controller"]["uid"] and args.apk_sha256 == release["controller"]["apk"]["sha256"],
         "explicit current controller identity differs from sealed actual55 release")
    plan, plan_raw = support.plan_for(args.case)
    report.update(release=release_proof, case=args.case)
    instruction = plan["instruction"]
    report.update(plan=plan, plan_sha256=sha(plan_raw), target_package=TARGET)
    report.update(instruction=instruction, instruction_sha256=sha(instruction.encode()),
                  ui_helper_sha256=UI_SHA, background_driver_sha256=R12_SHA)
    check_owner, owner_fd = uihelper.owner_guard(args)
    try:
        # Use only the pinned ordinary UI/readers; no Notes business binder is installed.
        r7 = module(args.r7_driver, uihelper.R7_SHA, "frozen_r7_web_preparation_readers")
        receipts = r7.load_pinned("warm_receipts", args.source_tools / "warm_receipts.py")
        profiles = r7.load_pinned("model_profiles", args.source_tools / "model_profiles.py")
        pa = r7.load_pinned("phone_acceptance", args.source_tools / "phone_acceptance.py")
        config_raw = r7.checked_file(args.runtime_config, 4096)
        config = r7.strict(config_raw)
        profiles.profile(config["model_profile"])
        need(config.get("schema") == "hepta.local-runtime.v2" and config.get("compute") in ("npu", "gpu")
             and config.get("context_tokens") in (4096, 8192), "reviewed local accelerator config required")
        report.update(runtime_config_sha256=sha(config_raw), runtime_config=config, helper_pins=r7.PINS)

        class GuardedAdb(pa.Adb):
            def command(self, *values, **options):
                check_owner()
                result = super().command(*values, **options)
                check_owner()
                return result

        adb = GuardedAdb(args, args.out)
        r7.bounded_private_reader(adb)
        text = lambda cmd, label: r7.text(adb, cmd, label, timeout=args.command_timeout)
        hepta = r7.package_identity(adb, PKG, "hepta-before")
        web_helper = r7.package_identity(adb, TARGET, "web_helper-before")
        notes_identity = r7.package_identity(adb, NOTES, "notes-before")
        report["installed_identity_before"] = {"hepta": hepta, "helper": web_helper, "notes": notes_identity}
        support.installed_matches(hepta, release["controller"])
        support.installed_matches(web_helper, release["helper"])
        need(text(["run-as", TARGET, "id", "-u"], "helper-private-reader-uid").strip() == str(release["helper"]["uid"]), "helper private-reader UID differs")
        helper_idle = support.helper_idle(adb)
        helper_idle.pop("raw", None)
        report["helper_idle_before"] = helper_idle
        need(hepta["uid"] == args.expected_uid and len(hepta["apks"]) == 1 and hepta["apks"][0]["sha256"] == args.apk_sha256, "exact installed Hepta/UID differs")
        need(text(["run-as", PKG, "id", "-u"], "private-reader-uid").strip() == str(args.expected_uid), "private reader UID differs")
        need(text(["am", "get-current-user"], "current-user").strip() == "0", "only Android user 0 covered")
        need(adb.app_bytes("files/model/runtime-config.json") == config_raw, "runtime configuration differs")
        baseline = adb.app_json("files/control-session.json") or {}
        need(not r7.active(baseline) and not baseline.get("blocked") and (not baseline or baseline.get("cleanup_known") is True), "task/recovery is not clean idle")
        for name in ("qualification-scope.json", "background-session.active.json", "control-session.interrupted.json", "background-permission-interrupted.json", "web-helper.active.json"):
            need(adb.app_bytes("files/" + name, optional=True) is None, "existing state requires ordinary owner handling: " + name)
        report["baseline_session"] = baseline
        baseline_runs = set(adb.list_children("files/runs", directories=True))
        baseline_tasks = set(adb.list_children("files/control-tasks", directories=True))
        task_dump = text(["dumpsys", "activity", "activities"], "before-target-tasks")
        recents = text(["dumpsys", "activity", "recents"], "before-target-recents")
        displays = text(["cmd", "display", "get-displays"], "before-displays")
        r7.write_new(args.out / "before-activity-tasks.txt", task_dump.encode(), binary=True)
        r7.write_new(args.out / "before-recents.txt", recents.encode(), binary=True)
        r7.write_new(args.out / "before-displays.txt", displays.encode(), binary=True)
        report["target_task_inventory"] = background.activity_task_inventory(task_dump, TARGET)
        report["target_recents"] = recent_task_report(recents)
        report["displays_before"] = background.parse_displays(displays)
        blockers = []
        if report["target_task_inventory"]["target_tasks"]:
            blockers.append("official Web helper has an existing live Task on the recorded display(s); handle it through ordinary UI")
        if not report["target_recents"]["recognized_header"]:
            blockers.append("Recents enumeration format is not recognized; inspect the retained complete dump")
        if report["target_recents"]["target_reference_present"]:
            blockers.append("official Web helper appears in Recents; handle it through ordinary UI")
        if any(v["name"].startswith("hepta-bg-") for v in report["displays_before"].values()):
            blockers.append("An existing Hepta background display requires ordinary owner handling")
        report["blockers"] = blockers
        need(not blockers, "; ".join(blockers))
        before_preferences = support.read_ui_preferences(adb, args.expected_uid, "before-ordinary-choice")
        support.preference_choice(before_preferences)
        r7.write_new(args.out / "background-ui-choice-before.xml", before_preferences, binary=True)
        report["ui_preferences_before_sha256"] = sha(before_preferences)
        report["ui_actions"] = []

        def capture(label):
            current = adb.app_json("files/control-session.json") or {}
            need(current.get("task_id") == baseline.get("task_id") and not r7.active(current) and not current.get("blocked"), "session changed; do not use UiAutomation")
            return uihelper.capture_ui(adb, args.out, r7, pa, label)

        def tap(node, reason):
            need(node.get("text") not in ("开始任务", "停止", "清理上一次后台空间", "核验后台执行权限", "确认中断并开始新会话"), "control is outside preparation scope")
            point = uihelper.point(node)
            adb.command(["input", "-d", "0", "tap", *map(str, point)], label=reason)
            report["ui_actions"].append({"action": reason, "text": node.get("text"), "bounds": uihelper.bounds(node), "point": point})

        def swipe(scroll, reason):
            need(scroll.get("scrollable") == "true", "observed container is not scrollable")
            box = uihelper.bounds(scroll)
            x, height = (box[0] + box[2]) // 2, box[3] - box[1]
            coords = [x, box[1] + height * 3 // 4, x, box[1] + height // 3]
            adb.command(["input", "-d", "0", "swipe", *map(str, coords), "350"], label=reason)
            report["ui_actions"].append({"action": reason, "observed_bounds": box, "coordinates": coords})

        adb.command(["am", "start", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", "-n", PKG + "/.MainActivity", "--es", "task", instruction], label="ordinary-hepta-main-prefill-only")
        ui = capture("prefilled")
        uihelper.exact_node(ui, instruction)
        mode = uihelper.exact_node(ui, "在后台空间操作")
        need(mode.get("checked") in ("true", "false"), "background checkbox state unknown")
        if mode.get("checked") == "false":
            tap(mode, "ordinary-background-mode-toggle")
        ui = capture("background-selected")
        uihelper.exact_node(ui, instruction)
        need(uihelper.exact_node(ui, "在后台空间操作").get("checked") == "true", "background mode not selected")
        windows = text(["dumpsys", "window", "displays"], "before-hide-ime")
        main_windows = r7.display_blocks(windows, r"^\s*Display: mDisplayId=(\d+)\b[^\n]*$")[0]
        if re.search(r"InsetsSource[^\n]* type=ime [^\n]* visible=true\b", main_windows):
            adb.command(["input", "-d", "0", "keyevent", "KEYCODE_BACK"], label="hide-observed-hepta-ime")
            report["ui_actions"].append({"action": "hide_observed_ime"})
        for index in range(4):
            ui = capture("unfocus-%02d" % index)
            field = uihelper.exact_node(ui, instruction)
            need(field.get("class") == "android.widget.EditText", "original task field differs")
            if field.get("focused") == "false":
                break
            need(field.get("focused") == "true" and index < 3, "task cursor remains focused")
            adb.command(["input", "-d", "0", "keyevent", "KEYCODE_TAB"], label="normal-unfocus-task-field")
        need(uihelper.exact_node(ui, "在后台空间操作").get("checked") == "true", "background mode changed")
        report["owner_and_mode_verified_before_scroll"] = True
        for index in range(7):
            ui = capture("scope-viewport-%02d" % index)
            scroll = uihelper.outer_scroll(ui)
            choice = scope_button(ui)
            if choice and visible_in(uihelper, choice[0], uihelper.bounds(scroll)):
                button, original_count = choice
                break
            need(index < 6, "scope selector not exposed by bounded ordinary scrolling")
            swipe(scroll, "scroll-hepta-to-background-scope")
        tap(button, "open-background-app-choices")
        wanted = set(SELECTED_UI_PACKAGES)
        original_seen, selected, added, prior_page, pending_toggle = set(), set(), set(), None, None
        selected_labels = {}
        for index in range(40):
            ui = capture("app-choices-%02d" % index)
            scroll, rows = choice_rows(ui, uihelper)
            if pending_toggle is not None:
                package, expected_checked = pending_toggle
                need(package in rows and rows[package].get("checked") == expected_checked,
                     "ordinary checkbox tap did not produce the required observed state")
                pending_toggle = None
            changed = False
            for package, row in rows.items():
                checked = row.get("checked") == "true"
                if checked and package not in original_seen and package not in added:
                    need(len(original_seen) < original_count,
                         "selected checkbox count differs from original visible scope count")
                    original_seen.add(package)
                if checked and package not in wanted:
                    tap(row, "unselect-other-background-app")
                    pending_toggle = (package, "false")
                    changed = True
                    break
                if package in wanted:
                    label = row.get("text", "")[:-(len(package) + 3)]
                    need(label and (package not in selected_labels or selected_labels[package] == label),
                         "observed selected-app label changed during ordinary choice")
                    selected_labels[package] = label
                    if checked:
                        selected.add(package)
                    else:
                        need(package not in selected and package not in added,
                             "a confirmed explicit selection changed; no input retry permitted")
                        tap(row, "select-explicit-notes-or-web-helper")
                        added.add(package)
                        pending_toggle = (package, "true")
                        changed = True
                        break
            if changed:
                prior_page = None
                continue
            if selected == wanted and len(original_seen) == original_count:
                tap(uihelper.exact_node(ui, "使用所选应用"), "confirm-notes-and-web-helper-scope")
                break
            signature = tuple((p, n.get("checked")) for p, n in rows.items())
            need(index < 39 and signature != prior_page,
                 "explicit Notes/helper or previous selections not found in bounded observed choices")
            prior_page = signature
            swipe(scroll, "scroll-background-app-choices")
        else:
            raise RuntimeError("background selection did not settle")
        ui = capture("notes-and-web-helper-selected")
        uihelper.exact_node(ui, "后台范围：2 个应用（更改）")
        need(set(selected_labels) == wanted, "both selected app labels must come from actual chooser rows")
        expected_auto = "本次将自动使用：" + selected_labels[TARGET] + "。已保存的应用范围保持不变。"
        for index in range(7):
            automatic = automatic_target_observation(ui, uihelper, expected_auto)
            if automatic is not None:
                break
            need(index < 6, "actual automatic helper target message was not exposed")
            swipe(uihelper.outer_scroll(ui), "scroll-hepta-automatic-target-into-view")
            ui = capture("automatic-target-%02d" % index)
        preferences_raw = support.read_ui_preferences(adb, args.expected_uid, "ordinary-choice-saved")
        need(preferences_raw == before_preferences, "ordinary dual app confirmation changed saved preferences")
        report["ui_preferences_unchanged_from_before"] = True
        r7.write_new(args.out / "background-ui-choice-original.xml", preferences_raw, binary=True)
        report["ui_preferences_original"] = {"file": "background-ui-choice-original.xml",
            "bytes": len(preferences_raw), "sha256": sha(preferences_raw),
            "raw_utf8": preferences_raw.decode("utf-8", "strict")}
        report["background_selection"] = support.background_choice_evidence(
            plan, preferences_raw, selected_labels, automatic.get("text"), True)
        for index in range(7):
            ui = capture("start-viewport-%02d" % index)
            scroll = uihelper.outer_scroll(ui)
            start = uihelper.visible_start(ui, uihelper.bounds(scroll))
            if start is not None:
                report.update(start_point=uihelper.point(start), start_bounds=uihelper.bounds(start), final_ui_label="start-viewport-%02d" % index)
                break
            need(index < 6, "Start not exposed by bounded ordinary scrolling")
            swipe(scroll, "scroll-hepta-start-into-view")
        # Last UiAutomation capture has finished. Only read binding/geometry/PNG
        # below, so the formal service can rebind before r12's separate run.
        binding = {"verified": False}
        for index in range(10):
            services = text(["dumpsys", "activity", "services", PKG + "/.HeptaAccessibilityService"], "formal-service-rebind")
            try:
                binding = r7.formal_service_binding(services, args.expected_uid)
                break
            except RuntimeError:
                time.sleep(1)
        need(binding.get("verified") is True, "formal accessibility service did not rebind; no setting/grant attempted")
        report["formal_service_binding"] = binding
        display = text(["dumpsys", "display"], "logical-display-mapping")
        physical = text(["dumpsys", "SurfaceFlinger", "--display-id"], "physical-display-mapping")
        mapping = r7.main_physical_display_mapping(display, physical, args.main_physical_display_id)
        windows = text(["dumpsys", "window", "displays"], "prepared-window-displays")
        screen = adb.command(["screencap", "-p", "-d", args.main_physical_display_id], label="prepared-original-main-png", raw=True)[1]
        r7.write_new(args.out / "prepared-window.txt", windows.encode(), binary=True)
        r7.write_new(args.out / "prepared-main.png", screen, binary=True)
        with r7.png_rgba(screen) as image:
            need(list(image.size) == mapping["screen_size"], "main screenshot dimensions differ")
            geometry = r7.system_bar_content_geometry(windows, image.size)
            after = text(["dumpsys", "window", "displays"], "prepared-window-after")
            need(r7.system_bar_content_geometry(after, image.size) == geometry, "main geometry changed during screenshot")
        r7.write_new(args.out / "prepared-window-after.txt", after.encode(), binary=True)
        l, t, r, b = geometry["content_rect"]
        x, y = report["start_point"]
        need(l <= x < r and t <= y < b, "Start point is outside observed app content")
        current = adb.app_json("files/control-session.json") or {}
        need(current == baseline and not r7.active(current), "task state changed during preparation")
        need(set(adb.list_children("files/runs", directories=True)) == baseline_runs
             and set(adb.list_children("files/control-tasks", directories=True)) == baseline_tasks, "preparation created a task or model run")
        need(adb.app_bytes("files/model/runtime-config.json") == config_raw, "runtime configuration changed")
        need(r7.package_identity(adb, PKG, "hepta-after") == hepta
             and r7.package_identity(adb, TARGET, "web_helper-after") == web_helper
             and r7.package_identity(adb, NOTES, "notes-after") == notes_identity, "installed package identity changed")
        need(support.read_ui_preferences(adb, args.expected_uid, "prepared-choice-unchanged") == preferences_raw,
             "ordinary saved app preferences changed during preparation")
        report.update(prepared=True, main_display_mapping=mapping, prepared_geometry=geometry,
            prepared_screen_sha256=sha(screen), prepared_window_sha256=sha(windows.encode()),
            background_web_reviewed_start_arguments={"test_mode": args.test_mode, "target_package": TARGET, "start_tap": report["start_point"],
                "prepared_screen": str(args.out / "prepared-main.png"), "prepared_screen_sha256": sha(screen),
                "prepared_window_dump": str(args.out / "prepared-window.txt"), "prepared_window_dump_sha256": sha(windows.encode())},
            ordinary_owner_lock_handoff_required=True,
            handoff="Normally close the existing owner before the independent Web runner acquires the original operation_lock")
    finally:
        try:
            need(support.unchanged(retained), "sealed release artifacts changed during preparation")
        finally:
            os.close(owner_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-mode", choices=[MODE], required=True)
    for name in ("ui-helper", "background-driver", "r7-driver", "source-tools", "owner-root", "runtime-config", "release-manifest", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("owner-start-ticks", "owner-boot-id", "adb", "adb-host", "serial", "apk-sha256", "main-physical-display-id", "release-manifest-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("owner-pid", "adb-port", "expected-uid"):
        parser.add_argument("--" + name, type=int, required=True)
    parser.add_argument("--command-timeout", type=int, default=12)
    parser.add_argument("--case", choices=("flight",), required=True)
    args = parser.parse_args()
    need(re.fullmatch(r"[0-9a-f]{64}", args.apk_sha256) and 10000 <= args.expected_uid < 90000
         and 1 <= args.adb_port <= 65535 and 1 <= args.command_timeout <= 30, "exact bounded device arguments required")
    need(args.out.is_absolute() and not args.out.exists() and all(not p.is_symlink() for p in args.out.parents), "new absolute output directory required")
    args.out.mkdir(parents=False, mode=0o700)
    report = {"schema": "hepta.ordinary-background-web-ui-preparation.v1", "driver_revision": "web-v58-helper6-natural-owner-automatic-target-r1",
        "test_mode": args.test_mode, "prepared": False, "task_started": False, "start_tapped": False,
        "target_app_operated": False, "existing_tasks_removed": False, "direct_broker_client_used": False,
        "permissions_changed": False, "r12_operation_lock_acquired_or_bypassed": False,
        "expected_apk_sha256": args.apk_sha256, "expected_uid": args.expected_uid,
        "started_wall_s": time.time()}
    try:
        execute(args, report)
    except Exception as error:
        report["prepared"] = False
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        report["ended_wall_s"] = time.time()
        (args.out / "RESULT.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"prepared": report["prepared"], "error": report.get("error"), "blockers": report.get("blockers"), "result": str(args.out / "RESULT.json")}, ensure_ascii=False))
    return 0 if report["prepared"] and report.get("error") is None else 2


if __name__ == "__main__":
    raise SystemExit(main())
