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
import secrets
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
MAX_RECEIPT_BYTES = 64 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_PATH_PARTS = 64


class ExecutionPlanError(ValueError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_path(path: Path) -> Path:
    path = Path(path).absolute()
    if (not path.name or ".." in path.parts or path.anchor != "/"
            or len(path.parts) > MAX_PATH_PARTS
            or len(os.fsencode(path)) > MAX_PATH_BYTES or "\x00" in str(path)):
        raise ExecutionPlanError("file path is not canonical or exceeds its bound")
    return path


def _open_parent(path: Path, *, create: bool = False) -> int:
    """Pin a directory by no-follow traversal; never resolve symlink aliases."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for part in path.parent.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                else:
                    os.fsync(descriptor)
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _private_regular(metadata: os.stat_result, label: str) -> None:
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_mode & 0o7077):
        raise ExecutionPlanError(f"{label} must be one private bounded regular file")


def _version(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_mode,
            metadata.st_uid, metadata.st_nlink)


def _read_private_bytes(path: Path, maximum: int, label: str) -> bytes:
    path = _canonical_path(path)
    parent = descriptor = None
    try:
        parent = _open_parent(path)
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW
                             | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        _private_regular(before, label)
        if before.st_size > maximum:
            raise ExecutionPlanError(f"{label} exceeds its byte bound")
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (len(raw) > maximum or len(raw) != before.st_size
                or _version(before) != _version(after)
                or _version(after) != _version(named)):
            raise ExecutionPlanError(f"{label} changed while being read or exceeds its bound")
        return bytes(raw)
    except OSError as error:
        raise ExecutionPlanError(f"{label} must be one private bounded regular file: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def load_private_json(path: Path, *, label: str, maximum: int) -> tuple[dict[str, Any], bytes]:
    raw = _read_private_bytes(path, maximum, label)
    try:
        value = RUNTIME.decode_strict_event(raw)
    except RUNTIME.ProviderRuntimeError as error:
        raise ExecutionPlanError(f"invalid {label} JSON: {error}") from error
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
        preimage, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
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
    if (not isinstance(claims, dict) or set(claims) != set(expected_claims)
            or any(claims[key] is not value for key, value in expected_claims.items())):
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
    raw = _read_private_bytes(path, MAX_PROMPT_BYTES, "prompt")
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
        "process_cleanup": {
            "scope": "original_process_group_only",
            "confirmed": terminal.cleanup_confirmed,
            "leader_reaped": terminal.leader_reaped,
            "diagnostic_pid": terminal.process_id,
            "pid_is_recovery_authority": False,
            "escaped_descendants_absence_proven": False,
            "automatic_redispatch": False,
        },
        "claims": {
            "validated_plan_executed": terminal.process_id is not None,
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


class _ReceiptTarget:
    """An owned private temporary file under a retained output parent.

    Preflight is not a storage reservation or durable-before-effect journal.
    The two CLI outputs remain separately committed files, not one transaction.
    """
    def __init__(self, path: Path, *, require_new: bool = False):
        self.path = _canonical_path(path)
        self.parent = self.descriptor = None
        self.temporary = ".provider-receipt-" + secrets.token_hex(16) + ".tmp"
        self.identity = None
        self.published = False
        self.attempted = False
        self.written = 0
        try:
            self.parent = _open_parent(self.path, create=True)
            self._check_parent()
            self.prior = self._target_version()
            if require_new and self.prior is not None:
                raise ExecutionPlanError("CLI receipt targets must be new; preserve existing evidence")
            self.descriptor = os.open(
                self.temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.parent,
            )
            current = os.fstat(self.descriptor)
            self.identity = (current.st_dev, current.st_ino)
            # A restrictive umask can remove owner access, never add group access.
            os.fchmod(self.descriptor, 0o600)
            os.fsync(self.descriptor)
            os.fsync(self.parent)
        except BaseException:
            self.close()
            raise

    def _check_parent(self) -> None:
        pinned = os.fstat(self.parent)
        if pinned.st_uid not in {0, os.geteuid()} or pinned.st_mode & 0o7077:
            raise ExecutionPlanError("receipt parent must be private and owner-controlled")
        current = _open_parent(self.path)
        try:
            observed = os.fstat(current)
            if (pinned.st_dev, pinned.st_ino) != (observed.st_dev, observed.st_ino):
                raise ExecutionPlanError("receipt parent identity changed")
        finally:
            os.close(current)

    def _target_version(self) -> tuple[int, ...] | None:
        try:
            current = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        _private_regular(current, "receipt target")
        return _version(current)

    def _owned_temporary(self) -> bool:
        if self.parent is None or self.identity is None:
            return False
        try:
            current = os.stat(self.temporary, dir_fd=self.parent, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return (current.st_dev, current.st_ino) == self.identity

    def _write(self, text: str) -> None:
        raw = text.encode("utf-8")
        if self.written + len(raw) > MAX_RECEIPT_BYTES:
            raise ExecutionPlanError("receipt exceeds its serialized byte bound")
        remaining = memoryview(raw)
        while remaining:
            count = os.write(self.descriptor, remaining)
            if count <= 0 or count > len(remaining):
                raise ExecutionPlanError("receipt write made no valid progress")
            remaining = remaining[count:]
        self.written += len(raw)

    def publish(self, value: Any, *, jsonl: bool = False) -> None:
        if self.attempted or self.descriptor is None:
            raise ExecutionPlanError("receipt publication is single-attempt; no implicit retry")
        self.attempted = True
        encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True,
                                   allow_nan=False, indent=None if jsonl else 2,
                                   separators=(",", ":") if jsonl else None)
        for item in value if jsonl else (value,):
            for chunk in encoder.iterencode(item):
                self._write(chunk)
            self._write("\n")
        os.fsync(self.descriptor)
        self._check_parent()
        if self._target_version() != self.prior:
            raise ExecutionPlanError("receipt target changed after preflight")
        if not self._owned_temporary():
            raise ExecutionPlanError("receipt temporary identity changed")
        _private_regular(os.fstat(self.descriptor), "receipt temporary")
        os.replace(self.temporary, self.path.name,
                   src_dir_fd=self.parent, dst_dir_fd=self.parent)
        self.published = True
        # Failure after replacement is visible-but-durability-unknown, not rollback.
        os.fsync(self.parent)

    def close(self) -> None:
        try:
            if not self.published and self._owned_temporary():
                os.unlink(self.temporary, dir_fd=self.parent)
        finally:
            try:
                if self.descriptor is not None:
                    os.close(self.descriptor)
            finally:
                self.descriptor = None
                if self.parent is not None:
                    os.close(self.parent)
                self.parent = None

    def __enter__(self):
        return self

    def __exit__(self, *_exception):
        self.close()


def atomic_write_json(path: Path, value: Any, *, jsonl: bool = False) -> None:
    with _ReceiptTarget(path) as target:
        target.publish(value, jsonl=jsonl)


def _validate_output_paths(inputs: tuple[Path, ...], outputs: tuple[Path, ...]) -> None:
    sources = tuple(_canonical_path(path) for path in inputs)
    destinations = tuple(_canonical_path(path) for path in outputs)
    for index, path in enumerate(destinations):
        for other in sources + destinations[:index]:
            if path == other or path in other.parents or other in path.parents:
                raise ExecutionPlanError("input and receipt paths must be distinct non-overlapping leaves")


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
    phase = "pre_execution"
    try:
        _validate_output_paths((arguments.plan, arguments.prompt_file),
                               (arguments.events_output, arguments.terminal_output))
        with _ReceiptTarget(arguments.events_output, require_new=True) as events_target, \
                _ReceiptTarget(arguments.terminal_output, require_new=True) as terminal_target:
            phase = "execution_outcome_may_be_unknown"
            records, terminal = execute_plan(
                arguments.plan,
                arguments.prompt_file,
                prompt_mode=arguments.prompt_mode,
                provider_kind=arguments.provider_kind,
                environment_mode=arguments.environment_mode,
                limits=RUNTIME.ProcessLimits(timeout_seconds=arguments.timeout_seconds),
            )
            phase = "receipt_publication_after_execution"
            events_target.publish(records, jsonl=True)
            terminal_target.publish(terminal)
    except (OSError, ValueError, RecursionError) as error:
        print(f"HOLD phase={phase}: {str(error)[:1024]}; automatic_retry=false", file=sys.stderr)
        return 1
    result = "PASS" if terminal["success"] else "FAIL"
    print(
        f"{result}_VALIDATED_PROVIDER_PROCESS_EXECUTION_ONLY "
        f"terminal={terminal['kind']} events={terminal['event_count']}"
    )
    return 0 if terminal["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
