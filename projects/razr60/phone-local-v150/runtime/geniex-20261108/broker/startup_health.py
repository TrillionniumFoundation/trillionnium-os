"""One fixed NPU health request before the init-owned provider may listen.

This is not a user turn or an App task. It shares the ordinary backend's native
supervision, evidence lock, unresolved-intent scan and receipt validators, but
uses an independently typed init/startup binding. No input/command/action may be
supplied by a model or UI, and a health failure cannot be retried automatically.
"""
from __future__ import annotations
import dataclasses
import os
from pathlib import Path
import re
import signal
import threading
import time
import types

import native_backend as b

STATE = Path("/var/lib/trillionnium/owner-open")
CAPS = (1 << 0) | (1 << 1) | (1 << 5) | (1 << 18)
SYSTEM = (b"This is the fixed Hepta startup inference health check. No phone or App operation is allowed. "
          b"Return one JSON object with kind=turn.complete, call_id='', tool=none, command='', argv=[], "
          b"task_status=completed. Set summary to only the decimal answer to the question.")
PROMPT = b"HEPTA_STARTUP_HEALTH_V1\nWhat is 6 times 7?"


def health_schema():
    constants = {"kind": "turn.complete", "call_id": "", "tool": "none", "command": "", "task_status": "completed"}
    properties = {key: {"type": "string", "const": value} for key, value in constants.items()}
    properties["argv"] = {"type": "array", "items": {"type": "string"}, "minItems": 0, "maxItems": 0}
    # The answer is intentionally not a const, enum, pattern or grammar literal.
    properties["summary"] = {"type": "string", "maxLength": 1024}
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def kernel_identity(policy):
    status = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, sep, value = line.partition(":")
        if sep:
            status[key] = value.strip()
    context = Path("/proc/self/attr/current").read_text().rstrip("\n\0")
    result = {"pid": os.getpid(), "ppid": os.getppid(), "context": context,
              "effective_capabilities": int(status["CapEff"], 16), "permitted_capabilities": int(status["CapPrm"], 16)}
    b.require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == policy.server_uid,
              "startup process credentials differ")
    if policy.production:
        b.require(policy == b.ANDROID_POLICY and result["ppid"] == 1 and context == policy.caller_context
                  and result["effective_capabilities"] == result["permitted_capabilities"] == CAPS,
                  "startup request is not the real init-owned bootstrap process")
    return result


def startup_binding(runner, candidate):
    candidate = Path(candidate)
    b.private_dir(candidate, os.getuid())
    match = re.fullmatch("geniex-candidate-([0-9a-f]{32})", candidate.name)
    b.require(match is not None, "startup candidate identity differs")
    instance = match[1]
    if runner.policy.production:
        b.require(candidate == STATE / "phone-local-v150" / candidate.name, "startup candidate is outside original state view")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    b.require(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", boot), "kernel boot identity differs")
    identity = kernel_identity(runner.policy)
    directory = candidate / "startup-evidence"
    raw = {}
    for key, path in (("entry", directory / ("entry-" + boot + ".json")),
                      ("post", directory / ("post-exec-" + boot + ".json")),
                      ("plan", candidate / "startup/entry-plan.json"),
                      ("launch", candidate / "startup/provider-start.json"),
                      ("config", candidate / "geniex-config.json")):
        raw[key] = b.read_private(path, os.getuid(), 131072)
    entry, post, plan, launch, config = [b.strict_json(raw[key]) for key in ("entry", "post", "plan", "launch", "config")]
    b.require(plan.get("schema") == "hepta.init-owned-geniex-provider.v1"
              and launch.get("schema") == "hepta.geniex-provider-start.v1" and launch.get("mode") == "serve",
              "startup plan/launch mode differs")
    b.require(entry.get("schema") == "hepta.geniex-provider-entry-intent.v1"
              and entry.get("instance") == post.get("instance") == launch.get("instance") == instance
              and entry.get("state") == "validated_exec_intent_not_ready"
              and entry.get("automatic_request_replay") is False and entry.get("native_execution_qualified") is False,
              "original init entry intent differs")
    for key, observed in identity.items():
        b.require(type(entry.get(key)) is type(observed) and entry[key] == observed, "startup process no longer matches init intent")
    b.require(post.get("schema") == "hepta.geniex-provider-post-exec-preflight.v1" and post.get("mode") == "serve"
              and post.get("boot_id") == boot and post.get("entry_intent_sha256") == b.sha(raw["entry"])
              and post.get("entry_plan_sha256") == entry.get("entry_plan_sha256") == b.sha(raw["plan"])
              and post.get("launch_config_sha256") == plan.get("launch_config_sha256") == b.sha(raw["launch"])
              and launch.get("geniex_config_sha256") == b.sha(raw["config"])
              and post.get("stage") == entry.get("stage") == plan.get("stage") == launch.get("stage")
              and post.get("model_executed") is False and post.get("phone_action_executed") is False
              and post.get("model_or_app_qualified") is False
              and post.get("state") == "identity_and_health_verified_provider_listen_not_yet_proved",
              "post-exec/config proof is not bound to this original entry")
    post_identity = post.get("identity", {})
    b.require(type(post_identity.get("pid")) is int and post_identity["pid"] == identity["pid"]
              and post_identity.get("context") == identity["context"]
              and all(isinstance(post_identity.get(key), str) and re.fullmatch("[0-9a-fA-F]{16}", post_identity[key])
                      and int(post_identity[key], 16) == identity[target]
                      for key, target in (("CapEff", "effective_capabilities"), ("CapPrm", "permitted_capabilities"))),
              "post-exec kernel identity differs")
    params = dataclasses.asdict(runner.config)
    params.update(evidence_root=str(runner.config.evidence_root), stage_root=str(runner.config.stage_root))
    b.require(config.get("backend") == params and runner.config.evidence_root == candidate / "model-evidence"
              and runner.config.stage_root == candidate / "stage", "startup request is not using the selected backend/config")
    health = post.get("native_health", {})
    b.require(health.get("protocol") == b.PROTOCOL and type(health.get("executor_revision")) is int
              and health["executor_revision"] == 6 and health.get("state") == "ready"
              and health.get("execute_authorized") is True and b.hex_string(health.get("server_instance"), 32),
              "post-exec native health is not ready")
    proof = {"schema": "hepta.init-startup-inference-binding.v1", "instance": instance, "boot_id": boot,
             "pid": identity["pid"], "ppid": identity["ppid"], "context": identity["context"],
             "entry_intent_sha256": b.sha(raw["entry"]), "post_exec_sha256": b.sha(raw["post"]),
             "entry_plan_sha256": b.sha(raw["plan"]), "launch_config_sha256": b.sha(raw["launch"]),
             "geniex_config_sha256": b.sha(raw["config"]), "native_server_instance": health["server_instance"],
             "proof_environment": "android_init" if runner.policy.production else "host_fixture",
             "user_turn_created": False, "phone_action_authorized": False}
    return {"request_kind": "startup_health", "startup_binding": proof}


def prepare_request(runner, candidate, counter, compiler):
    binding = startup_binding(runner, candidate)
    b.require(runner.config.grammar_profile == b.GRAMMAR_R3_PROFILE and isinstance(compiler, dict)
              and compiler.get("sha256") == runner.config.schema_compiler_sha256
              and callable(compiler.get("convert")), "startup requires the reviewed R3 grammar/compiler")
    schema = b.canonical_json(health_schema())
    grammar, conversion = compiler["convert"](schema, compiler_source_sha256=compiler["sha256"])
    b.require(conversion.get("root_schema_kind") == "health_final_only"
              and conversion.get("original_schema_sha256") == conversion.get("canonical_schema_sha256") == b.sha(schema),
              "startup grammar no longer represents the fixed answer-independent health schema")
    budget = counter.budget(prompt=PROMPT, system=SYSTEM, grammar=grammar, image=None, schema_conversion=conversion)
    proof = binding["startup_binding"]
    request_id = b.sha(b.canonical_json(["hepta-startup-health-v1", proof["instance"], proof["boot_id"],
                                         proof["entry_plan_sha256"], proof["geniex_config_sha256"]]))[:32]
    return {"request_id": request_id, "grammar": grammar, "budget": budget, "binding": binding}


def validate_answer(runner, prepared, answer):
    b.require(isinstance(answer, dict) and set(answer) == {"receipt", "text"}, "startup backend result differs")
    receipt = answer["receipt"]
    b.require(isinstance(receipt, dict) and receipt.get("schema") == "hepta.geniex-startup-process-receipt.v1"
              and receipt.get("request_kind") == "startup_health" and receipt.get("request_id") == prepared["request_id"]
              and receipt.get("startup_binding_sha256") == b.sha(b.canonical_json(prepared["binding"]["startup_binding"]))
              and receipt.get("state") == "completed" and receipt.get("cleanup_confirmed") is True
              and receipt.get("model_result_usable") is True and receipt.get("native_action_authorized") is False
              and receipt.get("automatic_retry") is False and receipt.get("can_redispatch") is False
              and receipt.get("proof_type") == "native_r6_waitpid_process_group.v1"
              and receipt.get("proof_environment") == ("android_native" if runner.policy.production else "host_fixture"),
              "startup inference lacks a complete original native/worker receipt")
    directory = runner.config.evidence_root / prepared["request_id"]
    terminal_raw = b.read_private(directory / "terminal.json", os.getuid(), 131072)
    raw = b.read_private(directory / "generated.bin", os.getuid(), b.MAX_RAW_TEXT)
    b.require(terminal_raw == b.canonical_json(receipt) and receipt.get("text_sha") == b.sha(raw)
              and isinstance(answer["text"], str) and answer["text"].encode() == raw,
              "startup result is not the original durable text/receipt")
    decision = b.strict_json(raw)
    expected = {"kind": "turn.complete", "call_id": "", "tool": "none", "command": "", "argv": [],
                "task_status": "completed", "summary": "42"}
    b.require(decision == expected, "startup 42 semantic check failed; no repair, retry or action")
    return {"request_id": prepared["request_id"], "startup_binding_sha256": receipt["startup_binding_sha256"],
            "model_receipt_sha256": b.sha(terminal_raw), "generated_sha256": b.sha(raw),
            "cleanup_confirmed": True, "answer_42_verified": True,
            "native_uid2000_npu_qualified": runner.policy.production, "app_operations_qualified": False}


def run_prelisten(source, candidate, *, no_stop):
    """Called by the same init-owned interpreter; never opens a provider port."""
    import provider_bridge
    from provider_phone_local import load_local_config
    source, candidate = Path(source), Path(candidate)
    b.require(Path(__file__).resolve() == source / "startup_health.py", "startup helper is outside pinned source")
    args = types.SimpleNamespace(config=candidate / "local-config-base.json")
    args.local_config, args.local_config_sha256 = load_local_config(args.config)
    provider_bridge.configure(args, candidate / "geniex-config.json")
    selected = args.geniex_backend
    runner, counter, compiler = selected["runner"], selected["counter"], selected["schema_compiler"]
    b.require(runner.policy.production, "the actual startup entry cannot select host fixtures")
    prepared = prepare_request(runner, candidate, counter, compiler)
    boot = prepared["binding"]["startup_binding"]["boot_id"]
    directory = candidate / "startup-evidence"
    intent = {"schema": "hepta.fixed-startup-health-intent.v1", "request_id": prepared["request_id"],
              "binding": prepared["binding"], "input_sha256": {"prompt": b.sha(PROMPT), "system": b.sha(SYSTEM),
                  "grammar": b.sha(prepared["grammar"]), "image": None}, "budget": prepared["budget"],
              "user_turn_created": False, "phone_action_authorized": False, "automatic_retry": False}
    b.exclusive(directory / ("npu-health-intent-" + boot + ".json"), b.canonical_json(intent))
    gate = b.CancelGate()
    interrupted = threading.Event()
    handlers = {}
    installed_handlers = []
    deadline = time.monotonic() + runner.config.max_native_ms / 1000
    result = {"schema": "hepta.fixed-startup-health-result.v1", "request_id": prepared["request_id"],
              "intent_sha256": b.sha(b.canonical_json(intent)), "state": "not_completed", "listen_authorized": False,
              "listener_ready": False,
              "user_turn_created": False, "app_operations_qualified": False, "automatic_retry": False}
    def on_signal(_number, _frame):
        interrupted.set(); gate.cancel()
    def restore_handlers():
        # Successful handoff must not retain a handler that merely records a
        # signal. Once restored, a new SIGTERM terminates the process normally.
        for number in installed_handlers:
            signal.signal(number, handlers[number])
        installed_handlers.clear()
    def poll():
        try:
            no_stop()
        except Exception:
            interrupted.set(); gate.cancel()
        if interrupted.is_set() or time.monotonic() >= deadline:
            gate.cancel()
    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous = signal.getsignal(number)
            b.require(previous is signal.SIG_DFL
                      or number == signal.SIGINT and previous is signal.default_int_handler,
                      "startup inherited a signal handler that may swallow shutdown")
            handlers[number] = previous
        for number in handlers:
            signal.signal(number, on_signal); installed_handlers.append(number)
        poll()
        answer = runner.run_startup_health(candidate=candidate, counter=counter, compiler=compiler, gate=gate, on_poll=poll)
        poll()
        b.require(not gate.cancelled, "startup cancellation/deadline won; provider must not listen")
        proof = validate_answer(runner, prepared, answer)
        no_stop()
        # A signal may arrive while validating/publishing the model result,
        # after the first cancellation check above. Restore terminating handlers
        # before the final sticky check, so there is no later swallowed-signal
        # window between this function and daily's own lifecycle setup.
        restore_handlers()
        poll()
        b.require(not interrupted.is_set() and not gate.cancelled,
                  "startup cancellation/deadline won before handoff; provider must not listen")
        result.update(state="model_health_passed_handoff_authorized_not_listening", listen_authorized=True, **proof)
    except BaseException as error:
        result.update(state="failed_no_listen", listen_authorized=False, error_type=type(error).__name__, error=str(error),
                      native_uid2000_npu_qualified=False)
        raise
    finally:
        restore_handlers()
        b.exclusive(directory / ("npu-health-result-" + boot + ".json"), b.canonical_json(result))
    return result
