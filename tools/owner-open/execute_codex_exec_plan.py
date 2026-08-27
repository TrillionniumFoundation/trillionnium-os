#!/usr/bin/env python3
"""Execute one validated owner-open Codex exec-prefix plan.

Execution is explicit. The adapter revalidates the plan hash and executable
identity, requires an explicit prompt transport and delegates only process/JSONL
mechanics to `jsonl_provider_runtime`. It does not interpret provider event
semantics; an embedding Host may supply an event handler.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Callable


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

PREFIX = importlib.import_module("build_codex_exec_prefix")
PROBE = importlib.import_module("probe_codex_cli")
RUNTIME = importlib.import_module("jsonl_provider_runtime")

PLAN_SCHEMA = "org.trillionnium.owner-open.codex-exec-prefix.v1"
EVENT_LOG_SCHEMA = "org.trillionnium.owner-open.provider-event-log.v1"
TERMINAL_SCHEMA = "org.trillionnium.owner-open.provider-execution-terminal.v1"
MAX_PLAN_BYTES = 4 * 1024 * 1024
MAX_PROMPT_BYTES = 256 * 1024


class ExecutionPlanError(ValueError):
    pass


class _DuplicateMember(ValueError):
    pass


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateMember(f"duplicate key {key}")
        value[key] = item
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_private_json(path: Path, *, label: str, maximum: int) -> tuple[dict[str, Any], bytes]:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or metadata.st_nlink != 1
        or metadata.st_size == 0
        or metadata.st_size > maximum
        or metadata.st_mode & 0o077
    ):
        raise ExecutionPlanError(
            f"{label} must be one non-empty private regular file within its byte bound"
        )
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise ExecutionPlanError(f"{label} changed while being read")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs)
    except (UnicodeDecodeError, _DuplicateMember, json.JSONDecodeError) as error:
        raise ExecutionPlanError(f"invalid {label} JSON: {error}") from error
    if not isinstance(value, dict):
        raise ExecutionPlanError(f"{label} must contain a JSON object")
    return value, raw


def validate_plan(path: Path) -> dict[str, Any]:
    plan, _raw = load_private_json(path, label="exec prefix plan", maximum=MAX_PLAN_BYTES)
    if plan.get("schema") != PLAN_SCHEMA:
        raise ExecutionPlanError(f"plan schema must be {PLAN_SCHEMA}")
    supplied_hash = plan.get("plan_sha256")
    PREFIX.lower_sha256(supplied_hash, "plan_sha256")
    preimage = dict(plan)
    del preimage["plan_sha256"]
    canonical = json.dumps(
        preimage, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if sha256_bytes(canonical) != supplied_hash:
        raise ExecutionPlanError("exec prefix plan SHA-256 does not bind its canonical preimage")

    claims = plan.get("claims")
    expected_claims = {
        "generated_only": True,
        "codex_executed": False,
        "credentials_opened": False,
        "provider_contacted": False,
        "model_invoked": False,
        "json_transport_executed": False,
        "owner_open_mode_executed": False,
        "host_integrated": False,
        "same_turn_tool_effect": False,
        "release_evidence": False,
    }
    if claims != expected_claims:
        raise ExecutionPlanError("exec prefix plan contains promoted or incomplete claims")
    if plan.get("claim_ceiling") != "EXEC_PREFIX_GENERATED_NOT_EXECUTED":
        raise ExecutionPlanError("exec prefix plan has an incompatible claim ceiling")
    if plan.get("prompt_delivery") != "unselected_requires_W1_2_adapter_test":
        raise ExecutionPlanError("exec prefix plan prompt-delivery boundary changed")

    argv = plan.get("argv_prefix")
    if (
        not isinstance(argv, list)
        or len(argv) < 4
        or any(not isinstance(item, str) for item in argv)
        or argv[1] != "exec"
        or argv[2] != "--json"
    ):
        raise ExecutionPlanError("exec prefix plan argv shape is invalid")
    executable_path = Path(plan.get("executable_path", ""))
    if not executable_path.is_absolute() or str(executable_path) != argv[0]:
        raise ExecutionPlanError("exec prefix executable path is not exact and absolute")
    measured = PROBE.inspect_executable(executable_path)
    if measured["sha256"] != plan.get("executable_sha256"):
        raise ExecutionPlanError("Codex executable no longer matches the planned digest")
    return plan


def load_prompt(path: Path) -> bytes:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_PROMPT_BYTES
        or metadata.st_mode & 0o077
    ):
        raise ExecutionPlanError("prompt must be one private bounded regular file")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise ExecutionPlanError("prompt changed while being read")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ExecutionPlanError("prompt is not UTF-8") from error
    return raw


def build_invocation(
    plan: dict[str, Any], prompt: bytes, prompt_mode: str
) -> tuple[list[str], bytes, str]:
    argv = list(plan["argv_prefix"])
    if prompt_mode == "argv-final":
        if b"\x00" in prompt:
            raise ExecutionPlanError("argv prompt contains NUL")
        argv.append(prompt.decode("utf-8"))
        return argv, b"", "keep-open"
    if prompt_mode == "stdin-close":
        return argv, prompt, "close-after-initial"
    if prompt_mode == "stdin-keep":
        return argv, prompt, "keep-open"
    raise ExecutionPlanError(f"unsupported prompt mode: {prompt_mode}")


def event_record(event: Any, plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": EVENT_LOG_SCHEMA,
        "plan_sha256": plan["plan_sha256"],
        "config_generation": plan["config_generation"],
        "seq": event.seq,
        "elapsed_ms": event.elapsed_ms,
        "raw_line_sha256": sha256_bytes(event.raw),
        "raw_line_base64": base64.b64encode(event.raw).decode("ascii"),
        "provider_event": event.value,
        "normalized_host_event": None,
        "same_turn_tool_effect_proven": False,
    }


def terminal_record(
    terminal: Any,
    plan: dict[str, Any],
    *,
    prompt: bytes,
    prompt_mode: str,
    provider_kind: str,
    environment_mode: str,
) -> dict[str, Any]:
    return {
        "schema": TERMINAL_SCHEMA,
        "plan_sha256": plan["plan_sha256"],
        "probe_report_sha256": plan["probe_report_sha256"],
        "executable_sha256": plan["executable_sha256"],
        "config_generation": plan["config_generation"],
        "selected_access_policy": plan["selected_access_policy"],
        "provider_kind": provider_kind,
        "prompt_mode": prompt_mode,
        "prompt_sha256": sha256_bytes(prompt),
        "prompt_bytes": len(prompt),
        "environment_mode": environment_mode,
        "kind": terminal.kind,
        "exit_code": terminal.exit_code,
        "signal": terminal.signal,
        "event_count": terminal.event_count,
        "stdout_bytes": terminal.stdout_bytes,
        "stderr_bytes": len(terminal.stderr),
        "stderr_base64": base64.b64encode(terminal.stderr).decode("ascii"),
        "outbound_bytes": terminal.outbound_bytes,
        "elapsed_ms": terminal.elapsed_ms,
        "error": terminal.error,
        "success": terminal.success,
        "claims": {
            "validated_plan_executed": True,
            "fixture_provider": provider_kind == "fixture",
            "installed_codex_requested": provider_kind == "codex",
            "provider_contact_proven": False,
            "model_invocation_proven": False,
            "codex_event_compatibility_proven": False,
            "host_integrated": False,
            "same_turn_tool_effect": False,
            "physical_device_effect": False,
            "release_evidence": False,
        },
        "claim_ceiling": "VALIDATED_PROVIDER_PROCESS_EXECUTION_ONLY",
    }


def atomic_write_json(path: Path, value: Any, *, jsonl: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}"
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            if jsonl:
                for item in value:
                    handle.write(
                        json.dumps(
                            item,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
            else:
                handle.write(
                    json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
                    + "\n"
                )
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def execute_plan(
    plan_path: Path,
    prompt_path: Path,
    *,
    prompt_mode: str,
    provider_kind: str,
    environment_mode: str,
    event_handler: Callable[[Any], bytes | str | None] | None = None,
    limits: Any | None = None,
    cancellation: Any | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if provider_kind not in {"fixture", "codex"}:
        raise ExecutionPlanError("provider_kind must be fixture or codex")
    if environment_mode not in {"inherit", "empty"}:
        raise ExecutionPlanError("environment_mode must be inherit or empty")
    plan = validate_plan(plan_path)
    prompt = load_prompt(prompt_path)
    argv, initial_stdin, stdin_policy = build_invocation(plan, prompt, prompt_mode)
    records: list[dict[str, Any]] = []

    def sink(event: Any) -> None:
        records.append(event_record(event, plan))

    terminal = RUNTIME.run_provider(
        argv,
        initial_stdin=initial_stdin,
        stdin_policy=stdin_policy,
        event_handler=event_handler,
        event_sink=sink,
        limits=limits,
        cancellation=cancellation,
        environment=None if environment_mode == "inherit" else {},
    )
    return records, terminal_record(
        terminal,
        plan,
        prompt=prompt,
        prompt_mode=prompt_mode,
        provider_kind=provider_kind,
        environment_mode=environment_mode,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--prompt-file", required=True, type=Path)
    parser.add_argument(
        "--prompt-mode", required=True, choices=["argv-final", "stdin-close", "stdin-keep"]
    )
    parser.add_argument("--provider-kind", required=True, choices=["fixture", "codex"])
    parser.add_argument("--environment-mode", required=True, choices=["inherit", "empty"])
    parser.add_argument("--events-output", required=True, type=Path)
    parser.add_argument("--terminal-output", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    arguments = parse_args(argv)
    if not arguments.execute:
        print("HOLD: --execute is required to start the validated provider plan", file=sys.stderr)
        return 64
    try:
        records, terminal = execute_plan(
            arguments.plan,
            arguments.prompt_file,
            prompt_mode=arguments.prompt_mode,
            provider_kind=arguments.provider_kind,
            environment_mode=arguments.environment_mode,
            limits=RUNTIME.ProcessLimits(timeout_seconds=arguments.timeout_seconds),
        )
        atomic_write_json(arguments.events_output, records, jsonl=True)
        atomic_write_json(arguments.terminal_output, terminal)
    except (OSError, ExecutionPlanError, RUNTIME.ProviderRuntimeError) as error:
        print(f"HOLD: {error}", file=sys.stderr)
        return 1
    print(
        "PASS_VALIDATED_PROVIDER_PROCESS_EXECUTION_ONLY "
        f"terminal={terminal['kind']} events={terminal['event_count']}"
    )
    return 0 if terminal["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
