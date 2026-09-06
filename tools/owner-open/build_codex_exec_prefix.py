#!/usr/bin/env python3
"""Build an auditable, unexecuted Codex exec argv prefix from a probe report.

This generator never launches Codex, opens credentials, appends user input or
claims that advertised options function at runtime. It binds one owner policy
to one exact probe-report digest and executable digest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


PROBE_SCHEMA = "org.trillionnium.owner-open.codex-cli-probe.v1"
PLAN_SCHEMA = "org.trillionnium.owner-open.codex-exec-prefix.v1"
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_ID_BYTES = 256
MAX_MODEL_BYTES = 256
ACCESS_POLICIES = {
    "auto-owner-open",
    "bypass-approvals-and-sandbox",
    "danger-full-access",
}


class PrefixError(ValueError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def lower_sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PrefixError(f"{label} must be a lowercase SHA-256")
    return value


def bounded_string(value: Any, label: str, maximum: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise PrefixError(f"{label} must be a string")
    encoded = value.encode("utf-8")
    if (
        (not allow_empty and not value)
        or len(encoded) > maximum
        or "\x00" in value
        or value != value.strip()
    ):
        raise PrefixError(f"{label} is empty, oversized or malformed")
    return value


def option_present(text: str, option: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9_-]){re.escape(option)}(?![A-Za-z0-9_-])", text) is not None


def load_probe(path: Path) -> tuple[dict[str, Any], str]:
    metadata = path.lstat()
    if not path.is_file() or path.is_symlink() or metadata.st_size == 0:
        raise PrefixError("probe report must be a real non-empty regular file")
    if metadata.st_size > MAX_REPORT_BYTES:
        raise PrefixError("probe report exceeds the byte bound")
    if metadata.st_mode & 0o022:
        raise PrefixError("probe report is group/world writable")
    raw = path.read_bytes()
    if len(raw) != metadata.st_size:
        raise PrefixError("probe report changed while being read")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PrefixError(f"invalid probe report JSON: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != PROBE_SCHEMA:
        raise PrefixError(f"probe report schema must be {PROBE_SCHEMA}")
    return value, sha256_bytes(raw)


def require_help_only_claims(probe: dict[str, Any]) -> None:
    claims = probe.get("claims")
    if not isinstance(claims, dict) or claims.get("help_only") is not True:
        raise PrefixError("probe report is not a help-only observation")
    required_false = {
        "credentials_opened_by_probe",
        "provider_contacted",
        "model_invoked",
        "exec_turn_started",
        "mcp_server_started",
        "owner_open_flags_verified_by_execution",
        "integrated_host",
        "same_turn_tool_effect",
        "release_evidence",
    }
    missing = [field for field in sorted(required_false) if claims.get(field) is not False]
    if missing:
        raise PrefixError(f"probe report contains promoted or missing non-claims: {missing}")
    if probe.get("claim_ceiling") != "INSTALLED_CLI_HELP_OBSERVATION_ONLY":
        raise PrefixError("probe report claim ceiling is incompatible")


def exec_help_text(probe: dict[str, Any]) -> str:
    probes = probe.get("probes")
    if not isinstance(probes, dict):
        raise PrefixError("probe report has no probe records")
    value = probes.get("exec_help")
    if not isinstance(value, dict):
        raise PrefixError("probe report has no exec help record")
    stdout = value.get("stdout")
    stderr = value.get("stderr")
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        raise PrefixError("exec help output is malformed")
    if sha256_bytes(stdout.encode("utf-8")) != value.get("stdout_sha256"):
        raise PrefixError("exec help stdout digest does not match report bytes")
    if sha256_bytes(stderr.encode("utf-8")) != value.get("stderr_sha256"):
        raise PrefixError("exec help stderr digest does not match report bytes")
    return stdout + "\n" + stderr


def observed_capabilities(probe: dict[str, Any]) -> dict[str, bool]:
    value = probe.get("capabilities")
    if not isinstance(value, dict):
        raise PrefixError("probe report has no capability observations")
    required = {
        "exec_subcommand_observed",
        "json_event_flag_observed",
        "sandbox_long_flag_observed",
        "sandbox_short_flag_observed",
        "danger_full_access_value_observed",
        "bypass_approvals_and_sandbox_flag_observed",
        "model_flag_observed",
        "config_override_flag_observed",
    }
    if any(not isinstance(value.get(field), bool) for field in required):
        raise PrefixError("probe capability observations are incomplete or malformed")
    return {field: value[field] for field in required}


def choose_access_mode(policy: str, capabilities: dict[str, bool], help_text: str) -> tuple[str, list[str]]:
    if policy not in ACCESS_POLICIES:
        raise PrefixError(f"unsupported access policy: {policy}")

    bypass = capabilities["bypass_approvals_and_sandbox_flag_observed"] and option_present(
        help_text, "--dangerously-bypass-approvals-and-sandbox"
    )
    sandbox_option = None
    if (
        capabilities["danger_full_access_value_observed"]
        and "danger-full-access" in help_text
    ):
        if capabilities["sandbox_long_flag_observed"] and option_present(
            help_text, "--sandbox"
        ):
            sandbox_option = "--sandbox"
        elif capabilities["sandbox_short_flag_observed"] and option_present(help_text, "-s"):
            sandbox_option = "-s"

    selected = policy
    if policy == "auto-owner-open":
        if bypass:
            selected = "bypass-approvals-and-sandbox"
        elif sandbox_option is not None:
            selected = "danger-full-access"
        else:
            raise PrefixError("no observed owner-open access mode is available")

    if selected == "bypass-approvals-and-sandbox":
        if not bypass:
            raise PrefixError("requested bypass option was not observed in this executable help")
        return selected, ["--dangerously-bypass-approvals-and-sandbox"]
    if selected == "danger-full-access":
        if sandbox_option is None:
            raise PrefixError("requested danger-full-access mode was not observed in this executable help")
        return selected, [sandbox_option, "danger-full-access"]
    raise AssertionError(selected)


def choose_json_option(capabilities: dict[str, bool], help_text: str) -> str:
    if not capabilities["exec_subcommand_observed"]:
        raise PrefixError("Codex exec subcommand was not observed")
    if not capabilities["json_event_flag_observed"] or not option_present(help_text, "--json"):
        raise PrefixError("Codex exec JSON event option was not observed")
    return "--json"


def choose_model_option(model: str | None, capabilities: dict[str, bool], help_text: str) -> list[str]:
    if model is None:
        return []
    model = bounded_string(model, "model", MAX_MODEL_BYTES)
    if not capabilities["model_flag_observed"]:
        raise PrefixError("model override requested but no model option was observed")
    if option_present(help_text, "--model"):
        return ["--model", model]
    if option_present(help_text, "-m"):
        return ["-m", model]
    raise PrefixError("model capability bit is not bound to an observed option token")


def build_plan(
    probe_path: Path,
    *,
    expected_executable_sha256: str,
    access_policy: str,
    config_generation: str,
    model: str | None = None,
) -> dict[str, Any]:
    probe, report_sha256 = load_probe(probe_path)
    require_help_only_claims(probe)
    expected_executable_sha256 = lower_sha256(
        expected_executable_sha256, "expected executable SHA-256"
    )
    config_generation = bounded_string(
        config_generation, "config_generation", MAX_ID_BYTES
    )
    executable = probe.get("executable")
    if not isinstance(executable, dict):
        raise PrefixError("probe report has no executable identity")
    executable_path = bounded_string(
        executable.get("path"), "probe executable path", 16 * 1024
    )
    executable_sha256 = lower_sha256(
        executable.get("sha256"), "probe executable SHA-256"
    )
    if executable_sha256 != expected_executable_sha256:
        raise PrefixError("expected executable digest does not match the probe report")

    capabilities = observed_capabilities(probe)
    help_text = exec_help_text(probe)
    json_option = choose_json_option(capabilities, help_text)
    selected_policy, access_arguments = choose_access_mode(
        access_policy, capabilities, help_text
    )
    model_arguments = choose_model_option(model, capabilities, help_text)

    argv_prefix = [
        executable_path,
        "exec",
        json_option,
        *access_arguments,
        *model_arguments,
    ]
    preimage = {
        "schema": PLAN_SCHEMA,
        "probe_report_sha256": report_sha256,
        "executable_path": executable_path,
        "executable_sha256": executable_sha256,
        "config_generation": config_generation,
        "requested_access_policy": access_policy,
        "selected_access_policy": selected_policy,
        "argv_prefix": argv_prefix,
        "prompt_delivery": "unselected_requires_W1_2_adapter_test",
        "capabilities": capabilities,
        "claims": {
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
        },
        "claim_ceiling": "EXEC_PREFIX_GENERATED_NOT_EXECUTED",
    }
    canonical = json.dumps(
        preimage, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {**preimage, "plan_sha256": sha256_bytes(canonical)}


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}"
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            handle.write(encoded)
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--expected-executable-sha256", required=True)
    parser.add_argument("--access-policy", required=True, choices=sorted(ACCESS_POLICIES))
    parser.add_argument("--config-generation", required=True)
    parser.add_argument("--model")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    arguments = parse_args(argv)
    try:
        plan = build_plan(
            arguments.probe,
            expected_executable_sha256=arguments.expected_executable_sha256,
            access_policy=arguments.access_policy,
            config_generation=arguments.config_generation,
            model=arguments.model,
        )
        if arguments.output:
            atomic_write(arguments.output, plan)
    except (OSError, PrefixError) as error:
        response = {"schema": PLAN_SCHEMA, "ok": False, "error": str(error)}
        if arguments.json:
            print(json.dumps(response, sort_keys=True))
        else:
            print(f"HOLD: {error}", file=sys.stderr)
        return 1
    if arguments.json or not arguments.output:
        print(json.dumps({"ok": True, **plan}, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(
            "PASS_PREFIX_GENERATED_NOT_EXECUTED "
            f"plan_sha256={plan['plan_sha256']} policy={plan['selected_access_policy']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
