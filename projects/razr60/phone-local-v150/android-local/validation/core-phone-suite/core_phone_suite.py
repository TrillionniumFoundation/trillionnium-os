#!/usr/bin/env python3
"""Freeze and run concrete phone goals with pinned, model-aware base drivers.

Only `run` contacts a phone. `freeze`, `validate`, and `evaluate` are offline.
The app's original nonce/native/offload/action gates remain mandatory.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
from pathlib import Path
import re
import sys
import time

import core_assertions as checks

SCHEMA = "hepta.phone-core-suite.v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def unique(items):
        value = {}
        for key, entry in items:
            if key in value:
                raise ValueError("duplicate JSON field " + key)
            value[key] = entry
        return value
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid JSON constant " + value)))


def driver_files(path):
    root = Path(path).resolve(strict=True)
    paths = sorted(p for p in root.iterdir() if p.suffix in {".py", ".json"})
    if not 3 <= len(paths) <= 100:
        raise ValueError("unexpected driver directory membership")
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise ValueError("driver inputs must be regular files")
    content = {p.name: p.read_bytes() for p in paths}
    if sum(map(len, content.values())) > 8 * 1024 * 1024 or any(len(b) > 2 * 1024 * 1024 for b in content.values()):
        raise ValueError("driver source closure exceeds bound")
    if not {"phone_suite.py", "phone_acceptance.py", "phone_inventory.py"} <= content.keys():
        raise ValueError("the original three acceptance drivers are required")
    pin = {"source_directory": str(root), "files": [{"path": name, "bytes": len(data), "sha256": sha(data)}
           for name, data in content.items()]}
    return pin, content


def verify_driver_pin(pin, directory=None):
    if not isinstance(pin, dict) or set(pin) != {"source_directory", "files"}:
        raise ValueError("invalid driver pin")
    path = Path(directory or pin["source_directory"])
    observed, content = driver_files(path)
    if observed["files"] != pin["files"]:
        raise ValueError("driver files changed from the frozen plan")
    return path.resolve(), content


def load_drivers(pin, directory=None):
    path, _ = verify_driver_pin(pin, directory)
    sys.path.insert(0, str(path))
    for name in ("phone_acceptance", "phone_inventory", "phone_suite"):
        if name in sys.modules and Path(sys.modules[name].__file__).resolve().parent != path:
            raise ValueError("another version of the base driver is already loaded")
    acceptance = importlib.import_module("phone_acceptance")
    suite = importlib.import_module("phone_suite")
    for module in (acceptance, suite):
        if Path(module.__file__).resolve().parent != path:
            raise ValueError("base driver import came from an unexpected directory")
    return suite, acceptance


def templates():
    settings, search, calculator = checks.SETTINGS, checks.SEARCH, checks.CALCULATOR
    def case(case_id, instruction, package, texts, actions, assertion, setup_home=True):
        return {"case_id": case_id, "instruction": instruction, "expected_package": package,
                "expected_visible_text": texts, "text_match": "exact", "required_actions": actions,
                "setup_home": setup_home, "timeout_seconds": 540, "assertion": assertion}
    def action(kind, package=None):
        return {"action": kind, **({"package": package} if package else {})}
    return [
        case("core-settings-home-01", "打开系统设置，停留在设置首页。", settings, ["设置", "搜索设置"],
             [action("open", settings)], "settings_home"),
        case("core-settings-apps-01", "打开系统设置，进入“应用”页面，停留在这个页面。", settings, ["特殊应用权限", "应用管理"],
             [action("open", settings), action("click", settings)], "apps_management"),
        case("core-calculator-keypad-01", "打开计算器，清除当前输入，使用计算器按键计算23乘以19，按等号并保留结果。不要直接输入答案。", calculator, ["437"],
             [action("open", calculator), *[action("click", calculator) for _ in range(7)]], "calculator_keypad"),
        case("core-settings-chinese-search-01", "打开系统设置，在搜索框输入“蓝牙”，停留在搜索结果页面。", search, ["蓝牙"],
             [action("open", settings), action("type", search)], "chinese_search"),
        case("core-search-return-home-01", "请使用系统返回操作back，从当前设置搜索页逐级返回系统设置首页，最后停留在设置首页。此项只测试系统返回操作，不使用点击界面返回箭头替代，不修改任何设置。", settings, ["设置", "搜索设置"],
             [action("back", search)], "search_return_home", False),
        case("core-settings-home-settings-01", "依次完成：打开系统设置，回到桌面，再次打开系统设置并停留在设置首页。不要修改设置。", settings, ["设置", "搜索设置"],
             [action("open", settings), action("home"), action("open", settings)], "ordered_navigation"),
        case("core-cross-app-01", "依次打开系统设置、计算器，再次打开系统设置并停留在设置首页。不修改设置，不进行计算。", settings, ["设置", "搜索设置"],
             [action("open", settings), action("open", calculator), action("open", settings)], "cross_app"),
        case("core-settings-scroll-01", "打开系统设置，回到设置首页，向下滚动设置列表至少一次并停留在滚动后的列表。不修改任何设置。", settings, [],
             [action("open", settings), action("scroll", settings)], "scroll"),
        case("core-find-calculator-01", "请先使用本机应用查找工具find_app搜索“计算器”，再从查找结果打开计算器。不进行计算。", calculator, [],
             [action("open", calculator)], "find_app"),
    ]


def base_plan(plan, suite):
    return {"schema": suite.SCHEMA, "suite_id": plan["suite_id"], "candidate": plan["candidate"],
            "cases": [{k: v for k, v in c.items() if k != "assertion"} for c in plan["cases"]]}


def validate_plan(plan, suite, runnable=False):
    if not isinstance(plan, dict) or set(plan) != {"schema", "suite_id", "candidate", "drivers", "cases"} or plan["schema"] != SCHEMA:
        raise ValueError("invalid core plan schema or fields")
    if not isinstance(plan["cases"], list) or not plan["cases"]:
        raise ValueError("explicit cases required")
    for case in plan["cases"]:
        if not isinstance(case, dict) or case.get("assertion") not in checks.KINDS:
            raise ValueError("unknown goal-specific assertion")
    result = suite.validate_plan(base_plan(plan, suite), require_runnable=runnable)
    return {**result, "schema": SCHEMA, "goal_specific_assertions": [c["assertion"] for c in plan["cases"]],
            "driver_closure_pinned": True}


def evaluate_one(directory, case, suite, acceptance):
    raw = (directory / "acceptance.json").read_bytes()
    evidence = acceptance.strict_json(raw)
    owner_sha = acceptance.digest(case["instruction"].encode("utf-8"))
    if evidence.get("case_id") != case["case_id"] or evidence.get("instruction_sha256") != owner_sha or evidence.get("instruction") != case["instruction"]:
        raise acceptance.DriverError("case receipt does not bind the exact frozen instruction")
    if type(evidence.get("launch_attempt_count")) is not int or evidence["launch_attempt_count"] not in (0, 1):
        raise acceptance.DriverError("invalid launch count")
    verdict = evidence.get("verdict")
    if verdict not in {"pass", "fail", "unverified"}:
        raise acceptance.DriverError("invalid underlying case verdict")
    sequence = suite.action_sequence(directory, case["required_actions"], owner_sha)
    extra = checks.evaluate_case(directory, case, suite, acceptance)
    if verdict == "pass":
        if not sequence["evidence_complete"] or not extra["evidence_complete"]:
            verdict = "unverified"
        elif not sequence["passed"] or not extra["all_passed"]:
            verdict = "fail"
    extra_bytes = (json.dumps(extra, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    acceptance.private_write(directory / "core-checks.json", extra_bytes)
    return {"verdict": verdict, "task_id": evidence.get("task_id"),
            "launch_attempt_count": evidence["launch_attempt_count"], "acceptance_sha256": sha(raw),
            "original_case_verdict": evidence["verdict"], "action_sequence": sequence,
            "goal_specific_checks": extra, "core_checks_sha256": sha(extra_bytes),
            "cleanup_unknown": evidence.get("cleanup_unknown") is not False}


def persist(root, report, suite, acceptance):
    suite.summarize(report)
    report["full_phone_acceptance"] = "not_assessed"
    report["core_functional_acceptance"] = report["suite_verdict"]
    acceptance.write_json(root / "suite-result.json", report)


def run(args, plan, raw):
    # Verify/copy immutable base code before importing it or contacting ADB.
    _, content = verify_driver_pin(plan["drivers"])
    root = args.output.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    snapshot = root / "drivers"
    snapshot.mkdir(mode=0o700)
    for name, data in content.items():
        (snapshot / name).write_bytes(data)
    suite, acceptance = load_drivers(plan["drivers"], snapshot)
    validate_plan(plan, suite, runnable=True)
    acceptance.private_write(root / "plan.json", raw)
    acceptance.write_json(root / "base-plan.json", base_plan(plan, suite))
    report = {"schema": "hepta.phone-core-suite-result.v1", "suite_id": plan["suite_id"],
              "plan_sha256": sha(raw), "candidate": plan["candidate"], "drivers": plan["drivers"],
              "core_driver_sha256": sha(Path(__file__).read_bytes()), "core_assertions_sha256": sha(Path(checks.__file__).read_bytes()),
              "automatic_retry": False, "device_serial": args.serial, "adb_port": args.adb_port,
              "cases": [{"case_id": c["case_id"], "verdict": "not_run", "launch_attempt_count": 0} for c in plan["cases"]],
              "errors": [], "started_host_wall_ms": int(time.time() * 1000)}
    persist(root, report, suite, acceptance)
    try:
        report["existing_server"] = suite.require_existing_adb_server(args, root)
        report["preflight"] = suite.preflight(acceptance.Adb(args, root / "preflight"), plan["candidate"])
        persist(root, report, suite, acceptance)
        for index, case in enumerate(plan["cases"]):
            row = report["cases"][index]
            row["existing_server"] = suite.require_existing_adb_server(args, root, phase="case-%03d" % index)
            row["preflight"] = suite.preflight(acceptance.Adb(args, root / ("preflight-%03d" % index)), plan["candidate"])
            row.update(verdict="unknown", launch_attempt_count=None)
            persist(root, report, suite, acceptance)
            started = time.monotonic()
            print(json.dumps({"event": "case_start", "case_id": case["case_id"], "assertion": case["assertion"]}), flush=True)
            try:
                code = acceptance.run_task(suite.case_args(args, case, plan["candidate"], root))
                row.update(evaluate_one(root / "cases" / case["case_id"], case, suite, acceptance),
                           driver_exit_code=code, elapsed_host_s=time.monotonic() - started)
                print(json.dumps({"event": "case_complete", "case_id": case["case_id"], "verdict": row["verdict"],
                                  "launch_attempt_count": row["launch_attempt_count"], "cleanup_unknown": row["cleanup_unknown"]}), flush=True)
                if row["cleanup_unknown"]:
                    report["errors"].append("cleanup unknown; no following case submitted")
                    break
            except (Exception, KeyboardInterrupt) as error:
                row.update(verdict="unknown", error=str(error), elapsed_host_s=time.monotonic() - started)
                report["errors"].append("case outcome unresolved; no replay or following task")
                break
            finally:
                persist(root, report, suite, acceptance)
    except (Exception, KeyboardInterrupt) as error:
        report["errors"].append(str(error))
    finally:
        report["finished_host_wall_ms"] = int(time.time() * 1000)
        persist(root, report, suite, acceptance)
    print(json.dumps({k: report[k] for k in ("suite_id", "suite_verdict", "counts", "actual_launches", "errors")}, ensure_ascii=False, indent=2), flush=True)
    return 0 if report["suite_verdict"] == "pass" else 2


def evaluate(root):
    root = root.resolve(strict=True)
    raw = (root / "plan.json").read_bytes()
    plan = strict_json(raw)
    report = strict_json((root / "suite-result.json").read_bytes())
    if report.get("plan_sha256") != sha(raw) or report.get("candidate") != plan.get("candidate"):
        raise ValueError("retained result and frozen plan differ")
    suite, acceptance = load_drivers(plan["drivers"], root / "drivers")
    validate_plan(plan, suite, runnable=True)
    if [r.get("case_id") for r in report["cases"]] != [c["case_id"] for c in plan["cases"]]:
        raise ValueError("retained case membership differs from plan")
    for case, row in zip(plan["cases"], report["cases"]):
        directory = root / "cases" / case["case_id"]
        if row["verdict"] == "not_run" or not (directory / "acceptance.json").is_file():
            continue
        try:
            row.update(evaluate_one(directory, case, suite, acceptance))
        except Exception as error:
            if row["verdict"] != "fail":
                row["verdict"] = "unverified"
            row["reevaluation_error"] = str(error)
    report["offline_reevaluation"] = {"phone_contacted": False, "wall_ms": int(time.time() * 1000),
                                      "core_driver_sha256": sha(Path(__file__).read_bytes()),
                                      "core_assertions_sha256": sha(Path(checks.__file__).read_bytes())}
    suite.summarize(report)
    report["core_functional_acceptance"] = report["suite_verdict"]
    acceptance.write_json(root / "offline-reevaluation.json", report)
    print(json.dumps({k: report[k] for k in ("suite_id", "suite_verdict", "counts", "actual_launches")}, ensure_ascii=False, indent=2))
    return 0 if report["suite_verdict"] == "pass" else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    freeze = sub.add_parser("freeze", help="freeze exact candidate, driver code and concrete case subset; offline")
    freeze.add_argument("--drivers", type=Path, required=True)
    freeze.add_argument("--candidate", type=Path, required=True)
    freeze.add_argument("--suite-id", required=True)
    freeze.add_argument("--case", action="append", choices=[c["case_id"] for c in templates()])
    freeze.add_argument("--output", type=Path, required=True)
    validate = sub.add_parser("validate", help="validate the frozen plan and driver source; offline")
    validate.add_argument("plan", type=Path)
    running = sub.add_parser("run", help="execute the explicit frozen cases once; the only device-contacting command")
    running.add_argument("plan", type=Path)
    running.add_argument("--adb", required=True)
    running.add_argument("--adb-host", default="127.0.0.1")
    running.add_argument("--adb-port", type=int, required=True)
    running.add_argument("--serial", required=True)
    running.add_argument("--output", type=Path, required=True)
    running.add_argument("--command-timeout", type=float, default=20)
    offline = sub.add_parser("evaluate", help="re-evaluate retained evidence without replay or device contact")
    offline.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.operation == "freeze":
        if args.output.exists():
            raise ValueError("plan output already exists; choose a new explicit identity")
        pin, _ = driver_files(args.drivers)
        plan = {"schema": SCHEMA, "suite_id": args.suite_id, "candidate": strict_json(args.candidate.read_bytes()),
                "drivers": pin, "cases": [c for c in templates() if not args.case or c["case_id"] in args.case]}
        suite, acceptance = load_drivers(pin)
        result = validate_plan(plan, suite, runnable=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("xb") as stream:
            stream.write((json.dumps(plan, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        args.output.chmod(0o600)
        print(json.dumps({**result, "plan": str(args.output.resolve()), "plan_sha256": sha(args.output.read_bytes())}, ensure_ascii=False, indent=2))
        return 0
    if args.operation == "evaluate":
        return evaluate(args.output)
    raw = args.plan.read_bytes()
    plan = strict_json(raw)
    if args.operation == "validate":
        suite, _ = load_drivers(plan["drivers"])
        print(json.dumps(validate_plan(plan, suite, runnable=True), ensure_ascii=False, indent=2))
        return 0
    if not 1 <= args.adb_port <= 65535 or not 1 <= args.command_timeout <= 120 or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.serial):
        parser.error("invalid explicit device identity or command timeout")
    return run(args, plan, raw)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps({"error": str(error), "automatic_retry": False}), file=sys.stderr)
        sys.exit(2)
