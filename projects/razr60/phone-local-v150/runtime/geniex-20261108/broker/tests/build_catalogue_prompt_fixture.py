#!/usr/bin/env python3
"""Generate two private model-input fixtures with an actual launcher catalogue.

Calls the selected provider's real compose_local_messages (24576-byte bound)
and compact_provider_body. Does not run a model, native command, phone action,
provider service, or receipt validator. History is synthetic and must never be
treated as actual device evidence. The two expected decisions are checked only
after real model output is obtained by a separate qualified test runner.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import struct
import sys
import time
import types
import uuid

BROKER = Path(__file__).resolve().parents[1]
SOURCE_FILENAMES = ("provider_phone_local.py", "phone_local_tools.py", "phone_observation_tools.py",
                    "prompt_budget.py", "provider_bridge.py", "native_backend.py")
# These public synthetic inputs/regions are already defined by the project's
# tools/phone_qairt_acceptance.py. No target location enters the model prompt.
IMAGE_EXPECTATIONS = {
    "3884af3cf4b76e45a6cd8a38084423241863079b48fa2b1fc437069b89591459": [84, 260, 684, 490],
    "2e08fa22606640ad6da655e406eeb801cfb7cb297f0e276f19efb7348d37c4a6": [84, 980, 684, 1210],
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def require(value, message):
    if not value:
        raise ValueError(message)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def read(path, maximum):
    require(path.is_absolute() and path.resolve(strict=True) == path and path.is_file(), "canonical input file required")
    raw = path.read_bytes()
    require(0 < len(raw) <= maximum, "fixture source exceeds its explicit bound")
    return raw


def private_directory(path):
    path.mkdir(mode=0o700, exist_ok=False)
    path.chmod(0o700)


def save(directory, name, raw):
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
    finally:
        os.close(fd)
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def catalogue(raw):
    value = strict_json(raw)
    require(value.get("schema") == "hepta.local-launcher-catalog.v1"
            and isinstance(value.get("entries"), list) and 1 <= len(value["entries"]) <= 64,
            "expected bounded hepta.local-launcher-catalog.v1 entries")
    apps = {}
    for entry in value["entries"]:
        require(isinstance(entry, dict) and entry.get("enabled") is True and entry.get("exported") is True,
                "fixture catalogue must contain only enabled exported launcher entries")
        label, component, package = (entry.get(k) for k in ("label", "component", "package"))
        require(isinstance(label, str) and label and "\0" not in label and label not in apps
                and isinstance(component, str) and "/" in component and component.split("/")[0] == package,
                "ambiguous or inconsistent catalogue entry")
        apps[label] = {"component": component, "label": label}
    return apps


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "catalogue", "image", "out"):
        ap.add_argument("--" + name, type=Path, required=True)
    ap.add_argument("--target-alias", required=True)
    ap.add_argument("--owner", required=True)
    ap.add_argument("--schema-grammar", action="store_true")
    ap.add_argument("--grammar-profile", help="Explicit reviewed profile; --schema-grammar retains R2 semantics")
    args = ap.parse_args()
    source = args.source.resolve(strict=True)
    require(source.is_dir(), "provider source directory required")
    require(args.out.is_absolute() and args.out.parent.resolve(strict=True) == args.out.parent and not args.out.exists(),
            "new absolute private output directory required")
    cat_raw = read(args.catalogue, 262144)
    apps = catalogue(cat_raw)
    require(args.target_alias in apps and args.target_alias.casefold() in args.owner.casefold(),
            "target must exactly match a registered alias named in the owner request")
    owner_raw = args.owner.encode("utf-8", errors="strict")
    require(owner_raw and b"\0" not in owner_raw and len(owner_raw) <= 65536, "owner UTF-8 bytes invalid or oversized")
    image_raw = read(args.image, 196608)
    image_sha = sha(image_raw)
    require(image_sha in IMAGE_EXPECTATIONS and image_raw[:8] == b"\x89PNG\r\n\x1a\n", "use an existing qualified synthetic r2 PNG")
    width, height = struct.unpack(">II", image_raw[16:24])
    require((width, height) == (768, 1536), "qualified synthetic image dimensions differ")

    sys.path[:0] = [str(source), str(BROKER)]
    provider = importlib.import_module("provider_phone_local")
    prompt_budget = importlib.import_module("prompt_budget")
    backend = importlib.import_module("native_backend")
    require(not (args.schema_grammar and args.grammar_profile is not None),
            "select either --schema-grammar or --grammar-profile")
    grammar_profile = backend.GRAMMAR_PROFILE if args.schema_grammar else args.grammar_profile
    allowed_profiles = getattr(backend, "GRAMMAR_PROFILES", frozenset((backend.GRAMMAR_PROFILE,)))
    require(grammar_profile is None or grammar_profile in allowed_profiles,
            "unknown output grammar profile")
    grammar_module = None
    compiler_sha = None
    if grammar_profile is not None:
        grammar_module = importlib.import_module("schema_grammar")
        require(Path(grammar_module.__file__) == source / "schema_grammar.py", "compiler outside selected provider source")
        compiler_sha = sha(read(source / "schema_grammar.py", 65536))
    provider.validate_apps(apps)
    # In-memory harness configuration mirrors the explicit new selector. It
    # does not edit provider source or bypass the original composition limit.
    profile = {"name": backend.PROFILE["name"], "max_tool_calls": 24, "max_rounds": 25,
               "max_duration_seconds": 300, "max_inference_seconds": 55,
               "max_turn_image_bytes": 24 * 196608}
    require(provider.OPERATION_PROFILES.get(profile["name"]) in (None, profile), "conflicting operation profile")
    provider.OPERATION_PROFILES[profile["name"]] = profile
    private_directory(args.out)
    run_id = uuid.uuid4().hex
    ids = {i: "r%02d_%s" % (i, uuid.uuid4().hex[:16]) for i in range(1, 5)}
    target = apps[args.target_alias]
    package, component = target["component"].split("/")[0], target["component"]
    source_pins = {}
    for name in SOURCE_FILENAMES:
        path = source / name
        if not path.exists():
            path = BROKER / name
        source_pins[name] = {"path": str(path), "sha256": sha(path.read_bytes())}
    if grammar_module is not None:
        helper = source / "schema_grammar.py"
        source_pins[helper.name] = {"path": str(helper), "sha256": sha(helper.read_bytes())}
    manifest = {"schema": "hepta.catalogue-model-prompt-fixture.v1", "fixture_id": run_id,
                "scope": "host_semantic_fixture_not_phone_evidence", "phone_actions_executed": 0,
                "model_inference_executed": False, "native_receipts_validated": False,
                "catalogue_sha256": sha(cat_raw), "registered_entries": len(apps), "source_pins": source_pins,
                "owner_sha256": sha(owner_raw), "owner_utf8_bytes": len(owner_raw),
                "target_alias": args.target_alias, "image_sha256": image_sha,
                "image_ground_truth_source": "tools/phone_qairt_acceptance.py public synthetic FIXTURES",
                "image_ground_truth_excluded_from_prompt": True, "source_compose_max_prompt_bytes": 24576,
                "operation_profile": profile, "cases": [], "all_inputs_generated": False}
    manifest.update(grammar_profile=grammar_profile,
                    schema_compiler_sha256=compiler_sha,
                    grammar_model_enforcement_tested=False)
    save(args.out, "owner.txt", owner_raw)
    messages = [{"role": "user", "content": args.owner}]
    calls, facts = {}, {}

    def append(tool, summary, fields, observation):
        cid = ids[len(calls) + 1]
        calls[cid] = {"call_id": cid, "semantic_tool": tool, **fields}
        messages.append({"role": "assistant", "content": summary, "tool_calls": [{"id": cid}]})
        messages.append({"role": "tool", "tool_call_id": cid, "content": json.dumps({
            "terminal": {"kind": "exited", "exit_code": 0, "output_truncated": False}, **observation}, ensure_ascii=False)})
        return cid

    def emit(name, with_image):
        directory = args.out / name
        private_directory(directory)
        rnd = len(calls) + 1
        phone = types.SimpleNamespace(verified_facts=facts, visual_read_constraints=[], calls=calls,
            latest={"attached_round": rnd, "call_id": ids[3], "received_monotonic": time.monotonic()} if with_image else None,
            open_app_allowed=lambda value: not calls or value != component)
        # Actual r9 adds the existing replay-exclusion projection. These are
        # synthetic prior opens, not a substitute for a real ledger decision.
        schema_extra = {}
        if hasattr(provider, "open_replay_exclusions"):
            schema_extra["excluded_open_aliases"] = [args.target_alias] if calls else []
        legacy = provider.business_decision_schema(ids[rnd], rnd, phone, apps, profile, **schema_extra)
        model_schema = provider.mobile_use_schema(legacy)
        scope = {"allowed_call_id": ids[rnd], "round": rnd, "tools_remaining": profile["max_rounds"] - rnd,
                 "operation_profile": profile, "context_tokens": 4096, "max_prompt_bytes": 24576,
                 "prompt_bytes_are_not_token_count": True,
                 "approved_apps": {key: {**item, "package": item["component"].split("/")[0]} for key, item in apps.items()},
                 "prior_action_inspections_no_old_text": [], "postconditions": None}
        if schema_extra:
            scope["reserved_open_aliases_not_repeatable"] = schema_extra["excluded_open_aliases"]
        parts = [{"type": "image_url", "image_url": {"url": "data:image/png;base64," + base64.b64encode(image_raw).decode()}}] if with_image else []
        case = {"name": name, "scope": "host_semantic_fixture_not_phone_evidence", "round": rnd,
                "allowed_call_id": ids[rnd], "owner_sha256": sha(owner_raw), "image_present": with_image,
                "synthetic_prior_actions": len(calls), "model_result": None, "phone_actions_executed": 0, "files": {}}
        for filename, obj in (("legacy-schema.json", legacy), ("model-schema.json", model_schema),
                              ("synthetic-prepared-messages.json", messages), ("synthetic-call-records.json", calls)):
            case["files"][filename] = save(directory, filename, encode(obj))
        try:
            # Real provider gate. A failure here remains a recorded failure;
            # never raise its limit or bypass it to get a compacted body.
            original_messages = provider.compose_local_messages(messages, messages, phone, scope, parts, 24576,
                decision_schema=model_schema, profile=profile)
            body = {"model": "Qwen3-VL-4B-Instruct-QAIRT-w4a16-SM8750-v79", "messages": original_messages,
                    "stream": False, "temperature": 0, "max_tokens": 256,
                    "response_format": {"type": "json_schema", "json_schema": {
                        "name": "hepta_mobile_use_action", "strict": True, "schema": model_schema}}}
            compact = prompt_budget.compact_provider_body(body, grammar_enabled=grammar_module is not None)
            before, after = [strict_json(item["messages"][1]["content"].encode()) for item in (body, compact)]
            require(compact["response_format"] == body["response_format"] and compact["messages"][2] == body["messages"][2],
                    "owner/image/authoritative schema changed in projection")
            require(all(before[k] == after[k] for k in ("transcript", "postconditions", "observation_status", "owner_request_utf8_sha256")),
                    "semantic history or observation changed in projection")
            prompt = ("VERIFIED_CONTEXT_JSON\n" + compact["messages"][1]["content"] + "\nOWNER_INSTRUCTION\n").encode() + owner_raw
            system = compact["messages"][0]["content"].encode()
            require(prompt.endswith(owner_raw), "exact final owner bytes missing")
            if grammar_module is not None:
                grammar, conversion = grammar_module.convert_schema(encode(model_schema),
                    compiler_source_sha256=compiler_sha)
                require(conversion["root_schema_kind"] == "mobile_use"
                        and conversion["original_schema_sha256"] == case["files"]["model-schema.json"]["sha256"],
                        "converter did not bind the original current model schema")
                case["files"]["grammar.gbnf"] = save(directory, "grammar.gbnf", grammar)
                case["files"]["schema-conversion.json"] = save(directory, "schema-conversion.json", encode(conversion))
                case["grammar_bytes"] = len(grammar)
            for filename, raw in (("system.txt", system), ("prompt.txt", prompt),
                                  ("original-body.json", encode(body)), ("body.json", encode(compact))):
                case["files"][filename] = save(directory, filename, raw)
            if with_image:
                case["files"]["current.png"] = save(directory, "current.png", image_raw)
            case.update(status="INPUTS_GENERATED_NOT_MODEL_TESTED", text_utf8_bytes=len(prompt) + len(system),
                        preprojection_text_utf8_bytes=sum(len(original_messages[i]["content"].encode()) for i in (0, 1)) + len(owner_raw),
                        transcript_utf8_bytes=len(encode(after["transcript"])),
                        actual_token_count=None, semantic_preservation_assertions=True,
                        expected={"action": "click", "screenshot_id": ids[3], "coordinate_space": [0, 1000],
                                  "target_bbox_pixels": IMAGE_EXPECTATIONS[image_sha], "image_size": [width, height]}
                        if with_image else {"action": "open", "text": args.target_alias})
        except Exception as error:
            case.update(status="INPUT_COMPOSITION_FAILED", error_type=type(error).__name__, error=str(error))
        case_file = save(directory, "CASE.json", encode(case))
        manifest["cases"].append({**case, "case_manifest": case_file})

    emit("01-first-open", False)
    first = append("phone.open_app", "打开" + target["label"], {"alias": args.target_alias, "package": package},
        {"_hepta_verified_local_observation": {"kind": "app_open", "package": package, "component": component, "display_id": 0}})
    facts[first] = {"kind": "app_open", "package": package}
    nodes = []
    for index, text in enumerate(("Interface", "Ready")):
        nodes.append({"resource-id": package + ":id/fixture_neutral_%d" % index, "text": text,
            "content-desc": "", "enabled": "true", "focused": "false", "clickable": "false", "focusable": "false",
            "scrollable": "false", "bounds": "[%d,%d][%d,%d]" % (index, index, index + 1, index + 1),
            "class": "android.widget.TextView"})
    observed = append("phone.observe", "查看当前界面", {"package": package},
        {"_hepta_verified_local_observation": {"kind": "ui_nodes", "package": package, "component": component,
         "display_id": 0, "nodes": nodes}})
    facts[observed] = {"kind": "ui_nodes", "package": package}
    append("phone.screenshot", "观察当前截图", {}, {"_hepta_image_observation": {"call_id": ids[3],
        "encoded_size": [width, height], "original_width": width, "original_height": height, "rotation": 0,
        "logical_display_id": 0, "observed_page": {"package": package, "component": component},
        "image_attached_in_this_completion": True, "stale_for_actions": False}})
    emit("02-after-three-actions-click", True)
    manifest["all_inputs_generated"] = all(row["status"] == "INPUTS_GENERATED_NOT_MODEL_TESTED" for row in manifest["cases"])
    saved = save(args.out, "MANIFEST.json", encode(manifest))
    print(json.dumps({"manifest": saved, "all_inputs_generated": manifest["all_inputs_generated"],
                      "registered_entries": len(apps), "case_statuses": {x["name"]: x["status"] for x in manifest["cases"]},
                      "phone_actions_executed": 0, "model_inference_executed": False}, ensure_ascii=False))
    return 0 if manifest["all_inputs_generated"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
