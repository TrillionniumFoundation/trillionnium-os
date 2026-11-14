"""Additional phone-goal checks over the original driver's retained evidence.

This module never contacts a device or supplies an action. A pass requires the
original nonce/runtime/native-output gates plus these goal-specific predicates.
"""
from __future__ import annotations

import re
from pathlib import Path
import xml.etree.ElementTree as ET

SETTINGS = "com.android.settings"
SEARCH = "com.android.settings.intelligence"
CALCULATOR = "com.motorola.cn.calculator"
SEARCH_FIELD = "android:id/search_src_text"
KINDS = {"settings_home", "apps_management", "calculator_keypad", "chinese_search",
         "search_return_home", "ordered_navigation", "cross_app", "scroll", "find_app"}


def _node(event, capability):
    matches = [n for n in event["before"].get("nodes", [])
               if isinstance(n, dict) and n.get("id") == event["action"].get("node_id")]
    if len(matches) != 1:
        raise ValueError("selected node is not unique in the action's before observation")
    node = matches[0]
    if node.get(capability) is not True or node.get("enabled", True) is not True or node.get("password", False) is not False:
        raise ValueError("selected node does not have the observed permitted capability")
    return node


def _prompt(directory, event, instruction, acceptance):
    path = directory / "runs" / event["model_run_id"] / "prompt.txt"
    if path.is_symlink():
        raise ValueError("model prompt is a symlink")
    raw = path.read_bytes()
    if len(raw) > 131072:
        raise ValueError("model prompt exceeds evidence bound")
    text = raw.decode("utf-8", "strict")
    if not acceptance.prompt_binding(text, instruction, {event["before"]["observation_id"]}):
        raise ValueError("model prompt does not bind this owner and observation")
    payload, _, _ = text[len("UNTRUSTED_DATA\n"):].partition("\nOWNER\n")
    data = acceptance.strict_json(payload.encode("utf-8"))
    if data.get("screen", {}).get("package") != event["before"].get("package"):
        raise ValueError("model prompt and observed package differ")
    return data


def bound_events(directory, instruction, suite, acceptance):
    """Include only independently bound dispatched effects or read-only find_app."""
    directory = Path(directory)
    events, errors, bindings, seen = [], [], [], set()
    paths = sorted((directory / "task").glob("step-*-action.json"))
    if len(paths) > 100:
        return [], ["too many action receipts"], []
    for path in paths:
        try:
            if not re.fullmatch(r"step-[0-9]{2}-action\.json", path.name):
                raise ValueError("invalid action receipt filename")
            receipt = suite._evidence_object(path)
            if receipt.get("accepted") is not True:
                continue
            action = receipt.get("action")
            if not isinstance(action, dict):
                raise ValueError("accepted action has no decision object")
            kind = action.get("action")
            if kind not in suite.EFFECTS | {"find_app"}:
                continue
            read_only = kind == "find_app"
            if receipt.get("stale") is not False or receipt.get("dispatched") is not (not read_only):
                raise ValueError("accepted effect/read outcome has contradictory dispatch state")
            if read_only and (receipt.get("read_only") is not True or receipt.get("effect") != "launcher_catalogue_read"):
                raise ValueError("find_app is not recorded as a read-only catalogue lookup")
            before = suite._evidence_object(path.with_name(path.name.replace("-action", "-before")))
            after = suite._evidence_object(path.with_name(path.name.replace("-action", "-after")))
            for observation in (before, after):
                if not isinstance(observation.get("observation_id"), str) or not acceptance.HEX32.fullmatch(observation["observation_id"]):
                    raise ValueError("invalid observation identity")
            if action.get("observation_id") != before["observation_id"]:
                raise ValueError("action uses a different before observation")
            if kind != "open" and action.get("package") != before.get("package"):
                raise ValueError("action does not target its observed package")
            binding = suite.model_action_binding(directory, path, receipt, before,
                                                 acceptance.digest(instruction.encode("utf-8")))
            bindings.append(binding)
            if not binding["verified"]:
                raise ValueError(binding.get("reason", "unbound model output"))
            run_id = binding["model_run_id"]
            if run_id in seen:
                raise ValueError("one model output was reused for multiple actions or reads")
            seen.add(run_id)
            event = {"step": int(path.name[5:7]), "source": str(path.relative_to(directory)),
                     "action": action, "before": before, "after": after,
                     "model_run_id": run_id, "model_binding": binding}
            prompt = _prompt(directory, event, instruction, acceptance)
            event["prompt"] = prompt
            if kind in {"click", "type", "scroll"}:
                capability = {"click": "clickable", "type": "editable", "scroll": "scrollable"}[kind]
                event["node"] = _node(event, capability)
                projected = [n for n in prompt.get("screen", {}).get("nodes", [])
                             if isinstance(n, list) and len(n) == 4 and n[0] == action.get("node_id")]
                letter = {"click": "c", "type": "t", "scroll": "s"}[kind]
                if len(projected) != 1 or not isinstance(projected[0][3], str) or letter not in projected[0][3]:
                    raise ValueError("selected node capability was absent from actual native model input")
            if kind == "open":
                apps = prompt.get("apps", [])
                if not any(isinstance(p, list) and len(p) == 2 and p[0] == action.get("package") for p in apps):
                    raise ValueError("opened package was absent from actual native model input")
            events.append(event)
        except (OSError, ValueError, TypeError, KeyError, AttributeError, acceptance.DriverError) as error:
            errors.append(str(path.relative_to(directory)) + ": " + str(error))
    return events, errors, bindings


def final_ui(directory, acceptance):
    path = Path(directory) / "ui-final.xml"
    if path.is_symlink():
        raise ValueError("final UI XML is a symlink")
    raw = path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("final UI XML exceeds evidence bound")
    root = ET.fromstring(raw)
    if root.tag != "hierarchy":
        raise ValueError("final UI is not a hierarchy")
    window = Path(directory) / "ui-final-window.txt"
    if window.is_symlink():
        raise ValueError("final focused-window evidence is a symlink")
    line = next((x.strip() for x in window.read_text().splitlines() if "mCurrentFocus=" in x), None)
    match = re.search(r"\bu\d+\s+([A-Za-z0-9_.]+)/", line or "")
    return {"xml": root, "focus_line": line, "focus_package": match.group(1) if match else None}


def _labels(node):
    return [str(node.get(k, "")).strip() for k in ("text", "description", "child_text") if node.get(k)]


def _key(node):
    aliases = {"清除": "clear", "清空": "clear", "AC": "clear", "C": "clear", "Clear": "clear",
               "乘": "multiply", "乘以": "multiply", "×": "multiply", "*": "multiply", "x": "multiply", "X": "multiply",
               "Multiply": "multiply", "multiply": "multiply", "等于": "equals", "=": "equals", "Equals": "equals", "equals": "equals",
               "+": "plus", "加": "plus", "-": "minus", "−": "minus", "减": "minus",
               "÷": "divide", "/": "divide", "除": "divide", ".": "decimal", "%": "percent"}
    found = set()
    for label in _labels(node):
        if label in aliases:
            found.add(aliases[label])
        elif re.fullmatch(r"[0-9]", label):
            found.add(label)
        else:
            match = re.fullmatch(r"(?:数字|digit|number)\s*([0-9])", label, re.IGNORECASE)
            if match:
                found.add(match.group(1))
    if len(found) > 1:
        raise ValueError("calculator key text and accessibility label disagree")
    return next(iter(found), None)


def _text_set(observation):
    return {(str(n.get("view_id", "")), str(n.get("text") or n.get("description") or "").strip())
            for n in observation.get("nodes", []) if isinstance(n, dict)
            and (n.get("text") or n.get("description"))
            and not re.fullmatch(r"[\d\s:.,%/+-]+(?:\s*[ap]m)?", str(n.get("text") or n.get("description") or ""), re.IGNORECASE)}


def evaluate_case(directory, case, suite, acceptance):
    directory = Path(directory)
    checks, errors = [], []
    events, event_errors, bindings = bound_events(directory, case["instruction"], suite, acceptance)
    errors.extend(event_errors)

    def check(kind, passed, **detail):
        checks.append({"kind": kind, "passed": bool(passed), **detail})

    try:
        ui = final_ui(directory, acceptance)
        final = acceptance.ui_predicates(ui, case["expected_package"], case["expected_visible_text"], case["text_match"] == "contains")
        check("independent_final_ui", final["all_passed"], evidence=final)
        nodes = [n.attrib for n in ui["xml"].iter("node") if n.get("visible-to-user", "true") != "false"]
        kind = case["assertion"]
        if kind in {"settings_home", "search_return_home"}:
            titles = {n.get("text", "") for n in nodes if n.get("package") == SETTINGS}
            descriptions = {n.get("content-desc", "") for n in nodes if n.get("package") == SETTINGS}
            check("settings_home_title_and_search_entry", "设置" in titles | descriptions and "搜索设置" in titles | descriptions)
        if kind == "apps_management":
            clicks = [e["step"] for e in events if e["action"]["action"] == "click"
                      and e["before"].get("package") == SETTINGS
                      and set(_labels(e.get("node", {}))) & {"应用", "应用管理", "Apps", "App management"}]
            check("model_clicked_observed_apps_entry", bool(clicks), steps=clicks)
        if kind == "calculator_keypad":
            calculator_events = [e for e in events if e["before"].get("package") == CALCULATOR]
            typed = [e["step"] for e in calculator_events if e["action"]["action"] == "type"]
            key_events = []
            for event in calculator_events:
                if event["action"]["action"] == "click":
                    label = _key(event.get("node", {}))
                    if label is not None:
                        key_events.append({"step": event["step"], "key": label, "node_id": event["action"]["node_id"]})
            last_clear = max((i for i, e in enumerate(key_events) if e["key"] == "clear"), default=-1)
            wanted = ["2", "3", "multiply", "1", "9", "equals"]
            actual = [e["key"] for e in key_events[last_clear + 1:]]
            check("calculator_no_type_shortcut", not typed, type_steps=typed)
            check("calculator_fresh_clear_then_exact_keypad_sequence", last_clear >= 0 and actual == wanted,
                  expected=wanted, observed_keys=key_events)
            expression = []
            for event in calculator_events:
                for observation in (event["before"], event["after"]):
                    if observation.get("package") != CALCULATOR:
                        continue
                    for node in observation.get("nodes", []):
                        value = re.sub(r"\s+", "", str(node.get("text", "")))
                        if re.fullmatch(r"\(?23[×*xX]19\)?(?:=437(?:\.0+)?)?", value):
                            expression.append({"observation_id": observation["observation_id"], "node_id": node.get("id"), "text": node.get("text")})
            check("calculator_entered_expression_visible", bool(expression), evidence=expression)
            results = [n for n in nodes if n.get("package") == CALCULATOR
                       and "EditText" not in n.get("class", "") and "history" not in n.get("resource-id", "").lower()
                       and any(re.fullmatch(r"=?\s*437(?:\.0+)?", n.get(a, "").strip()) for a in ("text", "content-desc"))]
            check("calculator_final_result_visible", bool(results), evidence=results)
        if kind == "chinese_search":
            typed = []
            for event in events:
                if (event["action"]["action"] == "type" and event["action"].get("text") == "蓝牙"
                        and event["before"].get("package") == SEARCH and event.get("node", {}).get("view_id") == SEARCH_FIELD):
                    readback = [n for n in event["after"].get("nodes", [])
                                if n.get("view_id") == SEARCH_FIELD and n.get("text") == "蓝牙" and n.get("editable") is True]
                    if event["after"].get("package") == SEARCH and len(readback) == 1:
                        typed.append(event["step"])
            fields = [n for n in nodes if n.get("package") == SEARCH and n.get("resource-id") == SEARCH_FIELD and n.get("text") == "蓝牙"]
            results = [n for n in nodes if n.get("package") == SEARCH and n.get("resource-id") != SEARCH_FIELD
                       and "EditText" not in n.get("class", "") and "蓝牙" in n.get("text", "")]
            check("model_typed_exact_chinese_into_observed_search_field", bool(typed), steps=typed)
            check("independent_search_field_exact_value", len(fields) == 1, evidence=fields)
            check("independent_non_input_search_result_visible", bool(results), evidence=results)
        if kind == "search_return_home":
            returned = [e["step"] for e in events if e["action"]["action"] == "back"
                        and e["before"].get("package") == SEARCH and e["after"].get("package") == SETTINGS]
            check("model_back_from_observed_search_to_settings", bool(returned), steps=returned)
        if kind == "scroll":
            changed = []
            for event in events:
                if event["action"]["action"] != "scroll" or event["before"].get("package") != SETTINGS:
                    continue
                before, after = event["before"], event["after"]
                fixed = after.get("package") == SETTINGS and all(before.get(k) == after.get(k) for k in ("rotation", "screen_width", "screen_height"))
                old, new = _text_set(before), _text_set(after)
                if fixed and old and new and old != new:
                    changed.append({"step": event["step"], "removed": sorted(old - new), "added": sorted(new - old)})
            check("model_scroll_changed_visible_settings_content", bool(changed), evidence=changed)
        if kind == "find_app":
            discoveries = []
            owner = suite._evidence_object(directory / "task" / "owner.json")
            initial = suite._evidence_object(directory / "task" / "initial-app-catalogue.json")
            for event in events:
                if event["action"]["action"] != "find_app":
                    continue
                receipt = suite._evidence_object(directory / "task" / ("step-%02d-find-app.json" % event["step"]))
                expected = {"schema": "hepta.local-app-discovery.v1", "task_id": owner.get("task_id"),
                            "request_observation_id": event["before"]["observation_id"], "model_run_id": event["model_run_id"],
                            "original_instruction_sha256": acceptance.digest(case["instruction"].encode("utf-8")),
                            "query": event["action"].get("query"), "offset": event["action"].get("offset"),
                            "model_issued": True, "read_only": True, "dispatched": False,
                            "catalogue_sha256": initial.get("catalogue_sha256")}
                if any(type(receipt.get(k)) is not type(v) or receipt.get(k) != v for k, v in expected.items()):
                    raise ValueError("find_app result does not bind its exact model request and catalogue")
                apps = receipt.get("apps")
                if not isinstance(apps, list) or receipt.get("returned") != len(apps):
                    raise ValueError("invalid find_app result membership")
                returned = any(isinstance(app, dict) and app.get("package") == CALCULATOR for app in apps)
                opens = [e["step"] for e in events if e["step"] > event["step"] and e["action"]["action"] == "open"
                         and e["action"].get("package") == CALCULATOR and e["after"].get("package") == CALCULATOR
                         and e["prompt"].get("app_search", {}).get("query") == receipt.get("query")
                         and e["prompt"].get("app_search", {}).get("offset") == receipt.get("offset")]
                if returned and receipt.get("query") == "计算器" and opens:
                    discoveries.append({"find_step": event["step"], "open_steps": opens,
                                        "catalogue_sha256": receipt["catalogue_sha256"]})
            check("model_find_app_then_open_returned_target", bool(discoveries), evidence=discoveries)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ET.ParseError, acceptance.DriverError) as error:
        errors.append(str(error))
    return {"schema": "hepta.phone-core-checks.v1", "case_id": case["case_id"], "assertion": case["assertion"],
            "all_passed": bool(checks) and all(c["passed"] for c in checks) and not errors,
            "evidence_complete": not errors, "errors": errors, "checks": checks, "model_action_bindings": bindings,
            "observed_bound_event_count": len(events), "phone_contacted": False}
