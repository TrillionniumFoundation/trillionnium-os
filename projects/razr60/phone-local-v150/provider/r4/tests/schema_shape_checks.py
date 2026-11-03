#!/usr/bin/env python3
"""Offline schema/guard checks. No model, phone, shell or sidecar operations."""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "source"))
import provider_phone_local as local
from health_contracts import final_only_schema, validate_decision as validate_health
from provider_openai_compatible import ProviderError

def valid(value, schema):
    """Independent validator for only the explicit JSON Schema subset used here."""
    if "oneOf" in schema:
        return sum(valid(value, branch) for branch in schema["oneOf"]) == 1
    if "const" in schema and value != schema["const"]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            return False
        properties = schema.get("properties", {})
        if not all(name in value for name in schema.get("required", [])):
            return False
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            return False
        return all(valid(item, properties[name]) for name, item in value.items() if name in properties)
    if kind == "string":
        return (isinstance(value, str) and len(value) <= schema.get("maxLength", len(value))
                and ("pattern" not in schema or re.search(schema["pattern"], value) is not None))
    if kind == "array":
        if not isinstance(value, list) or not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            return False
        prefix = schema.get("prefixItems", [])
        if not all(valid(item, prefix[index]) for index, item in enumerate(value[:len(prefix)])):
            return False
        return "items" not in schema or all(valid(item, schema["items"]) for item in value[len(prefix):])
    if kind is not None:
        raise AssertionError("test validator encountered an unreviewed schema type")
    return True

def put(path, value):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path":str(path.relative_to(ROOT)), "bytes":len(raw),
            "sha256":hashlib.sha256(raw).hexdigest()}

def method_dump(path, name):
    tree = ast.parse(path.read_bytes())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "PhoneLocalAdapter")
    return ast.dump(next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == name),
                    include_attributes=False)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(mode=0o700)
    fixtures = args.out / "schema-inputs"
    fixtures.mkdir(mode=0o700)
    checks = []
    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append(name)
    for path in (ROOT / "source").glob("*.py"):
        ast.parse(path.read_bytes(), feature_version=(3,12))
    check("all_runtime_sources_python3_12_syntax", True)
    parent = ROOT.parent / "provider-r3"
    for name in ("receive", "emit", "_decision", "_inspect_pending"):
        check(name+"_guard_unchanged", method_dump(parent/"source/provider_phone_local.py",name) ==
              method_dump(ROOT/"source/provider_phone_local.py",name))
    parent_seal = json.loads((parent/"SOURCE-SEAL-v150-r3.json").read_bytes())
    for pin in parent_seal["production_files"]:
        if Path(pin["path"]).name in {"provider_phone_local.py", "daily_phone_local.py"}:
            continue
        check(Path(pin["path"]).name+"_unchanged",
              hashlib.sha256((ROOT/pin["path"]).read_bytes()).hexdigest() == pin["sha256"])
    config = json.loads((ROOT/"local-config.phone.production.json").read_bytes())
    apps = config["approved_apps"]
    call = "r01_" + secrets.token_hex(8)
    phone = SimpleNamespace(latest=None, visual_read_constraints=[], calls={}, verified_facts={})
    schema = local.business_decision_schema(call, 1, phone, apps)
    check("top_level_union_only", set(schema) == {"oneOf"})
    for branch in schema["oneOf"]:
        check("closed_branch_"+str(len(checks)), branch["additionalProperties"] is False and
              set(branch["required"]) == set(branch["properties"]) == set(local.SCHEMA["required"]))
    def decision(tool, argv, command="", status="in_progress", call_id=call):
        return {"kind":"tool.call", "call_id":call_id, "tool":tool, "command":command,
                "argv":argv, "summary":"", "task_status":status}
    for alias in apps:
        check("exact_alias_"+alias, valid(decision("phone.open_app",[alias]),schema))
    check("historical_bad_open_shape_rejected",
          not valid(decision("phone.open_app",["HEPTA视觉挑战"],"org.trillionnium.hepta.controlprobe"),schema))
    check("unregistered_label_rejected",
          not valid(decision("phone.open_app",["HEPTA视觉挑战"]),schema))
    check("package_not_treated_as_alias",
          not valid(decision("phone.open_app",["org.trillionnium.hepta.controlprobe"]),schema))
    check("nonempty_open_command_rejected",
          not valid(decision("phone.open_app",["视觉挑战"],"ignored"),schema))
    check("wrong_call_id_rejected",
          not valid(decision("phone.open_app",["视觉挑战"],call_id="r01_"+secrets.token_hex(8)),schema))
    check("screenshot_argv_exact", valid(decision("phone.screenshot",["0"]),schema)
          and not valid(decision("phone.screenshot",[]),schema)
          and not valid(decision("phone.screenshot",["1"]),schema))
    check("return_empty_argv", valid(decision("phone.return_hepta",[]),schema)
          and not valid(decision("phone.return_hepta",["0"]),schema))
    package = "org.trillionnium.hepta.controlprobe"
    view = package + ":id/unicode_input"
    texts = ["independent first text", "中文 🦉\n\"quoted\" 'literal' $HOME ; &"]
    check("input_text_not_answer_forced", all(valid(decision("phone.input_text",[package,view,""],text),schema)
                                             for text in texts))
    check("input_exact_three_string_arguments",
          not valid(decision("phone.input_text",[package,view],"text"),schema)
          and not valid(decision("phone.input_text",[package,view,"", "extra"],"text"),schema)
          and not valid(decision("phone.input_text",[package,view,0],"text"),schema))
    check("package_and_resource_id_shapes", not valid(decision("phone.input_text",["bad",view,""],"t"),schema)
          and not valid(decision("phone.input_text",[package,"bad",""],"t"),schema))
    for count in range(1,6):
        check("read_"+str(count)+"_views", valid(decision("phone.read_text",
              [package]+[package+":id/view_"+str(i) for i in range(count)]),schema))
    check("read_range_bound", not valid(decision("phone.read_text",[package]),schema)
          and not valid(decision("phone.read_text",[package]+[view]*6),schema))
    check("no_tap_without_current_image", not any(
          row["properties"]["tool"].get("const")=="phone.tap" for row in schema["oneOf"]))
    call3 = "r03_"+secrets.token_hex(8)
    image_call = "r02_"+secrets.token_hex(8)
    phone.latest = {"attached_round":3,"call_id":image_call,"received_monotonic":time.monotonic()}
    current = local.business_decision_schema(call3,3,phone,apps)
    for coordinate in ("0","1","999","1000"):
        check("normalized_coordinate_"+coordinate, valid(decision("phone.tap",
              [image_call,coordinate,coordinate],call_id=call3),current))
    for coordinate in ("-1","00","01","1001","1.0","1e2"," 1"):
        check("coordinate_rejected_"+coordinate, not valid(decision("phone.tap",
              [image_call,coordinate,"1"],call_id=call3),current))
    check("screenshot_id_is_bound", not valid(decision("phone.tap",["old","1","2"],call_id=call3),current))
    phone.latest["attached_round"] = 2
    stale = local.business_decision_schema(call3,3,phone,apps)
    check("wrong_round_image_not_admitted", not valid(decision("phone.tap",[image_call,"1","2"],call_id=call3),stale))
    phone.latest.update(attached_round=3,received_monotonic=time.monotonic()-121)
    expired = local.business_decision_schema(call3,3,phone,apps)
    check("expired_image_not_admitted", not valid(decision("phone.tap",[image_call,"1","2"],call_id=call3),expired))
    phone.latest["received_monotonic"] = time.monotonic()
    phone.visual_read_constraints=[{"kind":"visual_receipt_matches_challenge","package":package}]
    phone.calls={"prior":{"semantic_tool":"phone.tap"}}
    used = local.business_decision_schema(call3,3,phone,apps)
    check("visual_second_selection_not_admitted", not valid(decision("phone.tap",[image_call,"1","2"],call_id=call3),used))
    final = local.business_decision_schema("r08_"+secrets.token_hex(8),8,phone,apps)
    final_value = {"kind":"turn.complete","tool":"none","call_id":"","command":"","argv":[],
                   "summary":"independently chosen summary","task_status":"partial"}
    check("round8_final_only", valid(final_value,final) and len(final["oneOf"])==1
          and not valid(decision("phone.screenshot",["0"]),final))
    health = final_only_schema(local.SCHEMA)
    check("health_summary_not_forced", set(health["properties"]["summary"])=={"type","maxLength"})
    check("health_zero_tool_schema", not valid(decision("phone.open_app",["视觉挑战"]),health))
    nonce = secrets.token_hex(16)
    health_value = dict(final_value, task_status="completed", summary=nonce)
    validate_health({"nonce":nonce},health_value)
    try:
        validate_health({"nonce":nonce},dict(health_value,summary="different"))
    except ProviderError:
        wrong_nonce_rejected = True
    else:
        wrong_nonce_rejected = False
    check("health_independent_nonce_validation_unchanged", wrong_nonce_rejected)
    phone.calls = {}
    phone.verified_facts = {}
    phone.latest["received_monotonic"] = time.monotonic()
    visual_before = local.business_decision_schema(call3,3,phone,apps)
    choices_before = {item["properties"]["tool"]["const"] for item in visual_before["oneOf"]}
    check("visual_before_selection_hides_observe_and_read",
          not {"phone.observe","phone.read_text"}.intersection(choices_before))
    check("visual_branch_gate_does_not_choose_task_action",
          {"none","phone.open_app","phone.screenshot","phone.tap"}.issubset(choices_before))
    phone.verified_facts = {"verified":{"kind":"visual_tap_executed","package":package}}
    phone.calls = {"used":{"semantic_tool":"phone.tap"}}
    visual_after = local.business_decision_schema(call3,3,phone,apps)
    choices_after = {item["properties"]["tool"]["const"] for item in visual_after["oneOf"]}
    check("verified_visual_selection_allows_public_readback",
          {"phone.observe","phone.read_text"}.issubset(choices_after))
    check("visual_used_selection_stays_unavailable",
          "phone.tap" not in choices_after)
    pins = []
    for name,value in (("before-image.json",schema),("current-image.json",current),
                       ("round8-final.json",final),("health-final-only.json",health),
                       ("visual-before-selection.json",visual_before),("visual-after-selection.json",visual_after)):
        pins.append(put(fixtures/name,value))
    result = {"status":"PASS","checks":checks,"assertions":len(checks),
              "schema_fixtures":pins, "schema_validator":"Independent test-only validator for explicit const/enum/object/string/array/oneOf subset",
              "pinned_cpp_grammar_conversion":"Separate required evidence; this report alone is not converter proof",
              "phone_calls":0,"model_requests":0,"sidecar_calls":0,"production_parent_modified":False}
    pin = put(args.out/"RESULT.json",result)
    print(json.dumps({"result":pin,"assertions":len(checks),"status":"PASS",
                      "schema_fixtures":pins,"phone_calls":0,"model_requests":0},separators=(",",":")))

if __name__ == "__main__":
    main()
