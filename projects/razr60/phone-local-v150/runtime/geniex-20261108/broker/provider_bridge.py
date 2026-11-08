"""Explicit opt-in bridge for a generated r9 provider candidate.

The overlay inserts this bridge around the existing model transport only. Its
original r9 ledger-prefix construction and exact typed decision parser remain
the authority. It never emits a native phone action itself.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import time

import native_backend as backend
from prompt_budget import NativeTokenizerBudget, QWEN_TOKENIZER_SHA, QWEN_TOKENIZER_CONFIG_SHA, compact_provider_body


def _read_artifact(path, expected, limit):
    path = Path(path)
    backend.require(path.is_absolute() and path.resolve(strict=True) == path, "noncanonical configured artifact")
    raw = path.read_bytes()
    backend.require(0 < len(raw) <= limit and backend.sha(raw) == expected, "configured artifact size/hash differs")
    return raw


def configure(args, path):
    """Called only by --geniex-config, before serving any connection.

    This does not start a model, native executor, bootstrap, mount, or service.
    Missing configured directories/mounts fail before the provider listens.
    """
    import provider_phone_local as provider
    raw = backend.read_private(Path(path), os.getuid(), 131072)
    value = backend.strict_json(raw)
    required = {"schema", "base_provider_config_sha256", "model_id", "backend", "tokenizer_gnu_path",
                "tokenizer_config_gnu_path", "template_contract", "deployment_binding"}
    grammar_selected = isinstance(value, dict) and value.get("schema") == "hepta.provider-geniex-native.v2"
    if grammar_selected:
        required.add("schema_compiler")
    backend.require(isinstance(value, dict) and set(value) == required
                    and value["schema"] in {"hepta.provider-geniex-native.v1", "hepta.provider-geniex-native.v2"},
                    "GenieX provider config differs")
    backend.require(value["base_provider_config_sha256"] == args.local_config_sha256,
                    "base provider config differs; no silent reassignment of its native executor/claims")
    backend.require(value["model_id"] == "Qwen3-VL-4B-Instruct-QAIRT-w4a16-SM8750-v79",
                    "unselected QAIRT model identity")
    binding = value["deployment_binding"]
    backend.require(isinstance(binding, dict) and binding.get("schema") == "hepta.geniex-shared-mount.v1"
                    and binding.get("execution_uid") == 2000 and binding.get("execution_gid") == 2000
                    and binding.get("new_dedicated_mount") is True and binding.get("old_state_permissions_changed") is False
                    and backend.hex_string(binding.get("instance"), 32), "explicit shared staging binding absent")
    fields = {field.name for field in dataclasses.fields(backend.BackendConfig)}
    vlm_fields = {"vlm_android", "vlm_sha256"}
    grammar_fields = {"grammar_profile", "core_android", "core_sha256", "schema_compiler_sha256"} | vlm_fields
    backend.require(isinstance(value["backend"], dict)
                    and (set(value["backend"]) in (fields, fields - vlm_fields)
                         or (not grammar_selected and set(value["backend"]) == fields - grammar_fields)),
                    "GenieX backend config fields differ")
    params = dict(value["backend"])
    params["evidence_root"] = Path(params["evidence_root"])
    params["stage_root"] = Path(params["stage_root"])
    config = backend.BackendConfig(**params)
    backend.require((config.grammar_profile in backend.GRAMMAR_PROFILES) if grammar_selected
                    else all(getattr(config, field) is None for field in grammar_fields),
                    "explicit config version/output grammar selection differs")
    backend.require(config.tokenizer_sha256 == QWEN_TOKENIZER_SHA,
                    "QAIRT bundle tokenizer is not the selected verified artifact")
    backend.require(binding.get("gnu_path") == str(config.stage_root)
                    and binding.get("android_path") == config.android_stage_root, "staging mount paths differ")
    info = config.stage_root.stat()
    backend.require(type(binding.get("st_dev")) is int and type(binding.get("st_ino")) is int
                    and info.st_dev == binding["st_dev"] and info.st_ino == binding["st_ino"], "shared mount identity differs")
    model = backend.NativeBackend(config)
    compiler = None
    if grammar_selected:
        import schema_grammar
        compiler_value = value["schema_compiler"]
        backend.require(isinstance(compiler_value, dict) and set(compiler_value) == {"kind", "sha256", "subset"}
                        and compiler_value["kind"] == backend.GRAMMAR_COMPILER_KIND
                        and compiler_value["subset"] == backend.GRAMMAR_SUBSET
                        and compiler_value["sha256"] == config.schema_compiler_sha256,
                        "schema compiler/profile binding differs")
        compiler_source = Path(__file__).with_name("schema_grammar.py")
        backend.require(Path(schema_grammar.__file__) == compiler_source, "schema compiler module is outside pinned provider source")
        _read_artifact(str(compiler_source), compiler_value["sha256"], 65536)
        compiler = {**compiler_value, "convert": schema_grammar.convert_schema}
    counter = NativeTokenizerBudget(_read_artifact(value["tokenizer_gnu_path"], QWEN_TOKENIZER_SHA, 16 * 1024 * 1024),
        expected_tokenizer_sha256=QWEN_TOKENIZER_SHA,
        tokenizer_config_raw=_read_artifact(value["tokenizer_config_gnu_path"], QWEN_TOKENIZER_CONFIG_SHA, 65536),
        expected_tokenizer_config_sha256=QWEN_TOKENIZER_CONFIG_SHA, template_contract=value["template_contract"],
        grammar_profile=config.grammar_profile, schema_compiler_sha256=config.schema_compiler_sha256)
    # Add an explicit new profile. Existing fixed19 and ordinary CPU definitions
    # are preserved byte-for-byte and continue to select their old transport.
    profile = {"name": backend.PROFILE["name"], "max_tool_calls": 24, "max_rounds": 25,
               "max_duration_seconds": 300, "max_inference_seconds": 55, "max_turn_image_bytes": 24 * 196608}
    old = provider.OPERATION_PROFILES.get(profile["name"])
    backend.require(old is None or old == profile, "conflicting GenieX operation profile")
    provider.OPERATION_PROFILES[profile["name"]] = profile
    args.local_config = dict(args.local_config)
    args.local_config.update(model=value["model_id"], operation_profile=profile["name"], context_tokens=4096, max_tokens=256,
                             service_manifest_sha256=config.artifact_manifest_sha256)
    args.geniex_backend = {"runner": model, "counter": counter, "config_path": Path(path), "config_sha256": backend.sha(raw),
                           "base_config_sha256": args.local_config_sha256, "active_gate": None, "schema_compiler": compiler}
    args.geniex_effective_config_sha256 = backend.sha(backend.canonical_json(args.local_config))
    args.geniex_config_sha256 = backend.sha(raw)
    return args


def prepare_body(adapter, body):
    if getattr(adapter.args, "geniex_backend", None) is None:
        return body
    value = compact_provider_body(body,
        grammar_enabled=adapter.args.geniex_backend["runner"].config.grammar_profile in backend.GRAMMAR_PROFILES)
    value["model"] = adapter.local_config["model"]
    value["max_tokens"] = 256
    return value


def complete(adapter, body, prefix, request_id):
    from model_health import ModelFailure
    selected = adapter.args.geniex_backend
    backend.require(backend.sha(backend.read_private(selected["config_path"], os.getuid(), 131072)) == selected["config_sha256"],
                    "GenieX config changed; service restart/review required")
    backend.require(backend.sha(backend.read_private(adapter.args.config, os.getuid(), 65536)) == selected["base_config_sha256"],
                    "base provider/native configuration changed")
    messages = body["messages"]
    backend.require(messages[0].get("role") == "system" and isinstance(messages[0].get("content"), str), "explicit system prompt missing")
    system = messages[0]["content"].encode()
    image = None
    if len(messages) == 2 and isinstance(messages[1].get("content"), str):
        prompt = messages[1]["content"].encode()
    else:
        backend.require(len(messages) == 3 and isinstance(messages[1].get("content"), str)
                        and isinstance(messages[2].get("content"), list), "bounded model messages differ")
        parts = messages[2]["content"]
        texts = [part["text"] for part in parts if part.get("type") == "text"]
        images = [part["image_url"]["url"] for part in parts if part.get("type") == "image_url"]
        backend.require(len(texts) == 1 and len(images) <= 1 and len(texts) + len(images) == len(parts), "only one exact owner text/current image permitted")
        # Metadata remains explicitly data. The owner bytes remain an intact
        # final segment; no API has a message-history cache in this worker.
        prompt = ("VERIFIED_CONTEXT_JSON\n" + messages[1]["content"] + "\nOWNER_INSTRUCTION\n").encode() + texts[0].encode()
        if images:
            header, encoded = images[0].split(",", 1)
            backend.require(header in {"data:image/png;base64", "data:image/jpeg;base64"}, "unsupported current image encoding")
            image = base64.b64decode(encoded, validate=True)
            backend.require(base64.b64encode(image).decode() == encoded, "noncanonical image encoding")
    owner_evidence = backend.strict_json(backend.read_private(adapter.run_dir / "accepted-owner-request.json", os.getuid(), 1024 * 1024))
    exact_owner = base64.b64decode(owner_evidence["request_utf8_b64"], validate=True)
    backend.require(prompt.endswith(exact_owner), "model prompt lost the exact final owner-request bytes")
    # Original QAIRT stays grammar-disabled. The explicit patched-core profile
    # converts the unchanged current schema outside the model input context.
    # The original r9 JSON/schema/typed/observation tail still validates output.
    grammar, conversion = None, None
    compiler = selected.get("schema_compiler")
    if compiler is not None:
        schema = body.get("response_format", {}).get("json_schema", {}).get("schema")
        backend.require(isinstance(schema, dict), "current original output schema missing")
        schema_raw = backend.canonical_json(schema)
        grammar, conversion = compiler["convert"](schema_raw, compiler_source_sha256=compiler["sha256"])
        backend.require(conversion.get("original_schema_sha256") == backend.sha(schema_raw)
                        and conversion.get("canonical_schema_sha256") == backend.sha(schema_raw)
                        and conversion.get("root_schema_kind") == ("health_final_only" if len(messages) == 2 else "mobile_use"),
                        "converter lost the exact current schema")
    budget = selected["counter"].budget(prompt=prompt, system=system, grammar=grammar, image=image,
                                        schema_conversion=conversion)
    adapter.atomic_record(prefix.with_suffix(".geniex-budget.json"), budget)
    identity = adapter.accepted_identity
    key = backend.sha(json.dumps([identity[name] for name in ("session_id", "profile_id", "task_id", "turn_id")], separators=(",", ":")).encode())
    owner = adapter.run_dir / "accepted-owner-request.json"
    claim = Path(adapter.args.evidence) / "claims" / key
    gate = backend.CancelGate()
    selected["active_gate"] = gate
    task_deadline_hit = False
    owner_transport_error = None
    def poll():
        nonlocal task_deadline_hit, owner_transport_error
        expired = adapter.session_deadline is not None and time.monotonic() >= adapter.session_deadline
        if not expired and owner_transport_error is None:
            try:
                adapter.receive(timeout=0)
            except Exception as error:
                # The base adapter raises before reading once its deadline is
                # reached. Translate that into a cancellation fence first so
                # original native cleanup can still be joined and recorded.
                expired = adapter.session_deadline is not None and time.monotonic() >= adapter.session_deadline
                if not expired:
                    owner_transport_error = error
        expired = expired or (adapter.session_deadline is not None and time.monotonic() >= adapter.session_deadline)
        task_deadline_hit = task_deadline_hit or expired
        if adapter.cancelled.is_set() or adapter.shutdown.is_set() or expired or owner_transport_error is not None:
            gate.cancel()
    # r9's existing DailyAdapter wrapper records model-health success/failure.
    adapter.health_attempt = adapter.args.model_health.begin()
    try:
        remaining = (adapter.session_deadline - time.monotonic()) if adapter.session_deadline is not None else 300
        if remaining < selected["runner"].config.max_native_ms / 1000 + 12 + 6:
            raise ModelFailure("model_timeout", {"known_not_dispatched": True,
                "reason": "insufficient task deadline for complete native supervision"})
        answer = selected["runner"].run(request_id=request_id, prompt=prompt, system=system, grammar=grammar, image=image,
            owner_path=owner, owner_claim_path=claim, budget=budget, gate=gate, on_poll=poll)
        adapter.atomic_record(prefix.with_suffix(".geniex-receipt.json"), answer["receipt"])
        if not answer["receipt"]["cleanup_confirmed"]:
            adapter.shutdown.set()
        poll()
        if task_deadline_hit:
            raise ModelFailure("model_timeout", answer["receipt"])
        if owner_transport_error is not None:
            raise owner_transport_error
        if gate.cancelled or adapter.cancelled.is_set():
            return None
        if answer["receipt"]["cleanup_confirmed"] and answer["receipt"]["state"] == "timed_out":
            raise ModelFailure("model_timeout", answer["receipt"])
        if not answer["receipt"]["model_result_usable"]:
            raise ModelFailure("unknown_model_failure", answer["receipt"])
        # The original r9 common tail will validate this one assistant content,
        # normalize against its unchanged current schema and apply typed guards.
        return {"model": adapter.local_config["model"], "choices": [{"message": {
            "role": "assistant", "content": answer["text"]}}]}
    finally:
        selected["active_gate"] = None

