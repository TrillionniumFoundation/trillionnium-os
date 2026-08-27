#!/usr/bin/env python3
"""Generate Direct Agent Host ABI bindings from the closed JSON contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/direct-agent-host-abi-v1.json"
RUST_OUTPUT = ROOT / "src/direct_agent_host_abi.rs"

CONTRACT_SCHEMA = "org.trillionnium.direct-agent-host.abi-contract.v1"
ABI_SCHEMA = "org.trillionnium.direct-agent-host.abi.v1"
TASK_LIFECYCLE_SCHEMA = "org.trillionnium.direct-agent-host.task-lifecycle.v1"
DIRECT_RESULT_SCHEMA = "org.trillionnium.direct-agent-host.direct-result.v1"
DIRECT_RECEIPT_SCHEMA = "trillionnium.agent-direct-receipt.v2"
TOP_LEVEL_FIELDS = {
    "contract_schema",
    "abi_schema",
    "task_lifecycle_schema",
    "direct_result_schema",
    "direct_receipt_schema",
    "carriers",
    "shared_lifecycle_methods",
    "task_states",
    "terminal_task_states",
    "direct_outcomes",
    "direct_result_fields",
    "direct_commitment_fields",
    "effect_authority",
}
CARRIER_FIELDS = {
    "protocol",
    "socket",
    "socket_namespace",
    "trust_domain",
    "wire_methods",
    "declares_direct_turn_method",
    "implementation_status",
    "runtime_ready",
}
EXPECTED_CARRIERS = {
    "builtin_android": {
        "protocol": "trillionnium.direct-agent-host.uds.v1",
        "socket": "trillionnium-direct-agent-host-v1",
        "socket_namespace": "android_abstract",
        "trust_domain": "android_aishell_peercred_peersec",
        "wire_methods": {
            "health": "health",
            "run_direct_turn": "plan",
            "cancel_task": "cancel",
        },
        "declares_direct_turn_method": True,
        "implementation_status": "source_contract_only_materialization_hold",
        "runtime_ready": False,
    },
    "kernel_agent_api": {
        "protocol": "trillionnium.agent-api.uds.v2",
        "socket": "/run/trillionnium/agent-api-v2.sock",
        "socket_namespace": "root_linux_filesystem",
        "trust_domain": "kernel_peercred_peersec_channel_binding",
        "wire_methods": {
            "health": "health",
            "create_task": "create_task",
            "cancel_task": "cancel_task",
        },
        "declares_direct_turn_method": False,
        "implementation_status": "lifecycle_carrier_only_no_direct_turn",
        "runtime_ready": False,
    },
}
SHARED_LIFECYCLE_METHODS = ("health", "create_task", "cancel_task")
TASK_STATES = (
    "created",
    "running",
    "waiting_for_approval",
    "indeterminate",
    "completed",
    "failed",
    "cancelled",
)
TERMINAL_TASK_STATES = ("indeterminate", "completed", "failed", "cancelled")
DIRECT_OUTCOMES = ("completed", "indeterminate", "refused", "no_action")
DIRECT_RESULT_FIELDS = (
    "direct_agent_host_abi",
    "direct_agent_host_abi_sha256",
    "direct_result_schema",
    "task_id",
    "direct_execution_receipt_id",
    "direct_execution_receipt_sha256",
    "direct_receipt_commitment",
    "plan_id",
    "approval_id",
    "action",
    "summary",
    "model",
    "provider_id",
    "provider",
    "provider_output_sha256",
    "agent_id",
    "agent_manifest_sha256",
    "agent_executable_sha256",
    "runtime_lifecycle_binding_sha256",
    "request_payload_sha256",
    "workflow_id_sha256",
    "direct_evidence_sha256",
    "direct_call_evidence",
    "direct_outcome",
    "direct_refusal_reason",
    "direct_refusal_sha256",
    "execution_mode",
    "requires_approval",
    "execution_available",
    "execution_completed",
    "network_scope",
    "tool_invocation_owned_by_agent",
    "tool_backend_owned_by_os",
    "daemon_is_effect_executor",
    "contract_confers_effect_authority",
    "model_invoked_tools",
    "model_executed_tools",
    "direct_tool_call_events",
    "completed_direct_tool_calls",
    "direct_tool_names",
    "plan_submitted_for_execution",
    "authority_called",
    "plan_latency_ms",
    "egress_grant_consumed",
)
DIRECT_COMMITMENT_FIELDS = (
    "schema",
    "direct_agent_host_abi",
    "direct_agent_host_abi_sha256",
    "direct_result_schema",
    "request_id_sha256",
    "request_payload_sha256",
    "subject_uid",
    "subject_selinux_domain_sha256",
    "provider_id",
    "workflow_id_sha256",
    "task_id",
    "agent_id",
    "agent_manifest_sha256",
    "agent_executable_sha256",
    "runtime_lifecycle_binding_sha256",
    "runtime_provider",
    "model",
    "summary_sha256",
    "provider_output_sha256",
    "direct_evidence_sha256",
    "direct_call_evidence",
    "direct_outcome",
    "direct_refusal_sha256",
    "direct_tool_call_events",
    "completed_direct_tool_calls",
    "direct_tool_names",
    "shell_exec_authorization_sha256",
    "shell_exec_direct_binding_sha256",
    "p01_daemon_build_binding_sha256",
)
EFFECT_AUTHORITY = {
    "tool_invocation_owned_by_agent": True,
    "tool_backend_owned_by_os": True,
    "daemon_is_effect_executor": False,
    "contract_confers_effect_authority": False,
}
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")


def reject_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def load_contract(path: Path) -> tuple[dict[str, object], bytes, str]:
    raw = path.read_bytes()
    try:
        contract = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_object,
            parse_float=lambda value: (_ for _ in ()).throw(
                ValueError(f"floating-point number denied: {value}")
            ),
            parse_constant=reject_nonstandard_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
        raise SystemExit(f"invalid Direct Agent Host ABI contract: {error}") from error
    if not isinstance(contract, dict) or set(contract) != TOP_LEVEL_FIELDS:
        raise SystemExit("Direct Agent Host ABI contract does not use the closed field schema")
    expected_scalars = {
        "contract_schema": CONTRACT_SCHEMA,
        "abi_schema": ABI_SCHEMA,
        "task_lifecycle_schema": TASK_LIFECYCLE_SCHEMA,
        "direct_result_schema": DIRECT_RESULT_SCHEMA,
        "direct_receipt_schema": DIRECT_RECEIPT_SCHEMA,
    }
    for field, expected in expected_scalars.items():
        if contract[field] != expected:
            raise SystemExit(f"unexpected Direct Agent Host ABI {field}")
    carriers = contract["carriers"]
    if not isinstance(carriers, dict) or set(carriers) != set(EXPECTED_CARRIERS):
        raise SystemExit("Direct Agent Host ABI carriers are not closed")
    for name, expected in EXPECTED_CARRIERS.items():
        actual = carriers[name]
        if not isinstance(actual, dict) or set(actual) != CARRIER_FIELDS or actual != expected:
            raise SystemExit(f"Direct Agent Host ABI carrier drift: {name}")
    exact_sequences = {
        "shared_lifecycle_methods": SHARED_LIFECYCLE_METHODS,
        "task_states": TASK_STATES,
        "terminal_task_states": TERMINAL_TASK_STATES,
        "direct_outcomes": DIRECT_OUTCOMES,
        "direct_result_fields": DIRECT_RESULT_FIELDS,
        "direct_commitment_fields": DIRECT_COMMITMENT_FIELDS,
    }
    for field, expected in exact_sequences.items():
        actual = contract[field]
        if not isinstance(actual, list) or tuple(actual) != expected or len(set(actual)) != len(actual):
            raise SystemExit(f"Direct Agent Host ABI sequence drift: {field}")
    if contract["effect_authority"] != EFFECT_AUTHORITY:
        raise SystemExit("Direct Agent Host ABI effect authority widened")
    if "tool_execution_owned_by_os" in DIRECT_RESULT_FIELDS:
        raise SystemExit("ambiguous tool ownership field must remain retired")
    if any(retired in raw for retired in (b"os-ui-authority", b"ui_authority")):
        raise SystemExit("retired Authority carrier naming reappeared in Host ABI")
    digest = hashlib.sha256(raw).hexdigest()
    if LOWER_SHA256.fullmatch(digest) is None:
        raise SystemExit("Direct Agent Host ABI digest generation failed")
    return contract, raw, digest


def rust_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def rust_slice(values: list[str]) -> str:
    return ", ".join(rust_string(value) for value in values)


def render_rust(contract: dict[str, object], digest: str) -> str:
    builtin = contract["carriers"]["builtin_android"]
    generic = contract["carriers"]["kernel_agent_api"]
    effect = contract["effect_authority"]
    return f'''// @generated by tools/generate-direct-agent-host-abi.py; do not edit.

pub const CONTRACT_SCHEMA: &str = {rust_string(contract['contract_schema'])};
pub const CONTRACT_SHA256: &str = {rust_string(digest)};
pub const ABI_SCHEMA: &str = {rust_string(contract['abi_schema'])};
pub const TASK_LIFECYCLE_SCHEMA: &str = {rust_string(contract['task_lifecycle_schema'])};
pub const DIRECT_RESULT_SCHEMA: &str = {rust_string(contract['direct_result_schema'])};
pub const DIRECT_RECEIPT_SCHEMA: &str = {rust_string(contract['direct_receipt_schema'])};

pub const BUILTIN_ANDROID_PROTOCOL: &str = {rust_string(builtin['protocol'])};
pub const BUILTIN_ANDROID_SOCKET: &str = {rust_string(builtin['socket'])};
pub const BUILTIN_ANDROID_TRUST_DOMAIN: &str = {rust_string(builtin['trust_domain'])};
pub const BUILTIN_WIRE_METHOD_HEALTH: &str = {rust_string(builtin['wire_methods']['health'])};
pub const BUILTIN_WIRE_METHOD_RUN_DIRECT_TURN: &str = {rust_string(builtin['wire_methods']['run_direct_turn'])};
pub const BUILTIN_WIRE_METHOD_CANCEL_TASK: &str = {rust_string(builtin['wire_methods']['cancel_task'])};

pub const KERNEL_AGENT_API_PROTOCOL: &str = {rust_string(generic['protocol'])};
pub const KERNEL_AGENT_API_SOCKET: &str = {rust_string(generic['socket'])};
pub const KERNEL_AGENT_API_TRUST_DOMAIN: &str = {rust_string(generic['trust_domain'])};
pub const KERNEL_WIRE_METHOD_HEALTH: &str = {rust_string(generic['wire_methods']['health'])};
pub const KERNEL_WIRE_METHOD_CREATE_TASK: &str = {rust_string(generic['wire_methods']['create_task'])};
pub const KERNEL_WIRE_METHOD_CANCEL_TASK: &str = {rust_string(generic['wire_methods']['cancel_task'])};

pub const SHARED_LIFECYCLE_METHODS: &[&str] = &[{rust_slice(contract['shared_lifecycle_methods'])}];
pub const TASK_STATES: &[&str] = &[{rust_slice(contract['task_states'])}];
pub const TERMINAL_TASK_STATES: &[&str] = &[{rust_slice(contract['terminal_task_states'])}];
pub const DIRECT_OUTCOMES: &[&str] = &[{rust_slice(contract['direct_outcomes'])}];
pub const DIRECT_RESULT_FIELDS: &[&str] = &[{rust_slice(contract['direct_result_fields'])}];
pub const DIRECT_COMMITMENT_FIELDS: &[&str] = &[{rust_slice(contract['direct_commitment_fields'])}];

pub const TOOL_INVOCATION_OWNED_BY_AGENT: bool = {str(effect['tool_invocation_owned_by_agent']).lower()};
pub const TOOL_BACKEND_OWNED_BY_OS: bool = {str(effect['tool_backend_owned_by_os']).lower()};
pub const DAEMON_IS_EFFECT_EXECUTOR: bool = {str(effect['daemon_is_effect_executor']).lower()};
pub const CONTRACT_CONFERS_EFFECT_AUTHORITY: bool = {str(effect['contract_confers_effect_authority']).lower()};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectOutcome {{
    Completed,
    Indeterminate,
    Refused,
    NoAction,
}}

impl DirectOutcome {{
    pub const fn as_str(self) -> &'static str {{
        match self {{
            Self::Completed => "completed",
            Self::Indeterminate => "indeterminate",
            Self::Refused => "refused",
            Self::NoAction => "no_action",
        }}
    }}
}}

pub fn bind_direct_result_contract(result: &mut serde_json::Map<String, serde_json::Value>) {{
    result.insert("direct_agent_host_abi".to_string(), serde_json::json!(ABI_SCHEMA));
    result.insert(
        "direct_agent_host_abi_sha256".to_string(),
        serde_json::json!(CONTRACT_SHA256),
    );
    result.insert(
        "direct_result_schema".to_string(),
        serde_json::json!(DIRECT_RESULT_SCHEMA),
    );
    result.insert(
        "tool_invocation_owned_by_agent".to_string(),
        serde_json::json!(TOOL_INVOCATION_OWNED_BY_AGENT),
    );
    result.insert(
        "tool_backend_owned_by_os".to_string(),
        serde_json::json!(TOOL_BACKEND_OWNED_BY_OS),
    );
    result.insert(
        "daemon_is_effect_executor".to_string(),
        serde_json::json!(DAEMON_IS_EFFECT_EXECUTOR),
    );
    result.insert(
        "contract_confers_effect_authority".to_string(),
        serde_json::json!(CONTRACT_CONFERS_EFFECT_AUTHORITY),
    );
}}

pub fn health_contract() -> serde_json::Value {{
    serde_json::json!({{
        "abi_schema": ABI_SCHEMA,
        "abi_contract_sha256": CONTRACT_SHA256,
        "task_lifecycle_schema": TASK_LIFECYCLE_SCHEMA,
        "direct_result_schema": DIRECT_RESULT_SCHEMA,
        "direct_receipt_schema": DIRECT_RECEIPT_SCHEMA,
        "shared_lifecycle_methods": SHARED_LIFECYCLE_METHODS,
        "task_states": TASK_STATES,
        "terminal_task_states": TERMINAL_TASK_STATES,
        "direct_outcomes": DIRECT_OUTCOMES,
        "carriers": {{
            "builtin_android": {{
                "protocol": BUILTIN_ANDROID_PROTOCOL,
                "trust_domain": BUILTIN_ANDROID_TRUST_DOMAIN,
                "declares_direct_turn_method": {str(builtin['declares_direct_turn_method']).lower()},
                "implementation_status": {rust_string(builtin['implementation_status'])},
                "runtime_ready": {str(builtin['runtime_ready']).lower()},
            }},
            "kernel_agent_api": {{
                "protocol": KERNEL_AGENT_API_PROTOCOL,
                "trust_domain": KERNEL_AGENT_API_TRUST_DOMAIN,
                "declares_direct_turn_method": {str(generic['declares_direct_turn_method']).lower()},
                "implementation_status": {rust_string(generic['implementation_status'])},
                "runtime_ready": {str(generic['runtime_ready']).lower()},
            }},
        }},
        "tool_invocation_owned_by_agent": TOOL_INVOCATION_OWNED_BY_AGENT,
        "tool_backend_owned_by_os": TOOL_BACKEND_OWNED_BY_OS,
        "daemon_is_effect_executor": DAEMON_IS_EFFECT_EXECUTOR,
        "contract_confers_effect_authority": CONTRACT_CONFERS_EFFECT_AUTHORITY,
    }})
}}

#[cfg(test)]
mod tests {{
    use super::*;
    use crate::TaskStatus;

    #[test]
    fn generated_contract_hash_is_exact() {{
        assert_eq!(
            crate::sha256_bytes(include_bytes!("../contracts/direct-agent-host-abi-v1.json")),
            CONTRACT_SHA256
        );
    }}

    #[test]
    fn task_lifecycle_matches_the_shared_os_type() {{
        let states = [
            TaskStatus::Created,
            TaskStatus::Running,
            TaskStatus::WaitingForApproval,
            TaskStatus::Indeterminate,
            TaskStatus::Completed,
            TaskStatus::Failed,
            TaskStatus::Cancelled,
        ]
        .into_iter()
        .map(|status| {{
            serde_json::to_value(status)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        }})
        .collect::<Vec<_>>();
        assert_eq!(states, TASK_STATES);
    }}

    #[test]
    fn direct_outcomes_and_result_fields_are_closed() {{
        assert_eq!(
            [
                DirectOutcome::Completed,
                DirectOutcome::Indeterminate,
                DirectOutcome::Refused,
                DirectOutcome::NoAction,
            ]
            .map(DirectOutcome::as_str),
            DIRECT_OUTCOMES
        );
        assert!(!DIRECT_RESULT_FIELDS.contains(&"tool_execution_owned_by_os"));
        assert!(DIRECT_RESULT_FIELDS.contains(&"tool_backend_owned_by_os"));
        assert!(DIRECT_RESULT_FIELDS.contains(&"contract_confers_effect_authority"));
        let mut result = serde_json::Map::new();
        bind_direct_result_contract(&mut result);
        assert_eq!(result.len(), 7);
        assert_eq!(result["direct_agent_host_abi"], ABI_SCHEMA);
        assert_eq!(result["direct_agent_host_abi_sha256"], CONTRACT_SHA256);
        assert_eq!(result["contract_confers_effect_authority"], false);
    }}

    #[test]
    fn health_contract_is_shared_and_confers_no_effect_authority() {{
        let health = health_contract();
        assert_eq!(health["abi_schema"], ABI_SCHEMA);
        assert_eq!(health["abi_contract_sha256"], CONTRACT_SHA256);
        assert_eq!(health["shared_lifecycle_methods"], serde_json::json!(SHARED_LIFECYCLE_METHODS));
        assert_eq!(health["tool_invocation_owned_by_agent"], true);
        assert_eq!(health["tool_backend_owned_by_os"], true);
        assert_eq!(health["daemon_is_effect_executor"], false);
        assert_eq!(health["contract_confers_effect_authority"], false);
        assert_eq!(health["carriers"]["builtin_android"]["declares_direct_turn_method"], true);
        assert_eq!(health["carriers"]["builtin_android"]["runtime_ready"], false);
        assert_eq!(
            health["carriers"]["builtin_android"]["implementation_status"],
            "source_contract_only_materialization_hold"
        );
        assert_eq!(health["carriers"]["kernel_agent_api"]["runtime_ready"], false);
        assert_ne!(BUILTIN_ANDROID_TRUST_DOMAIN, KERNEL_AGENT_API_TRUST_DOMAIN);
    }}
}}
'''


def java_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def java_array(values: list[str]) -> str:
    return ",\n            ".join(java_string(value) for value in values)


def render_java(contract: dict[str, object], digest: str) -> str:
    builtin = contract["carriers"]["builtin_android"]
    effect = contract["effect_authority"]
    return f'''// @generated by trillionnium-os-types/tools/generate-direct-agent-host-abi.py; do not edit.
package org.trillionnium.aishell;

final class DirectAgentHostAbi {{
    static final String CONTRACT_SHA256 = {java_string(digest)};
    static final String ABI_SCHEMA = {java_string(contract['abi_schema'])};
    static final String TASK_LIFECYCLE_SCHEMA = {java_string(contract['task_lifecycle_schema'])};
    static final String DIRECT_RESULT_SCHEMA = {java_string(contract['direct_result_schema'])};
    static final String DIRECT_RECEIPT_SCHEMA = {java_string(contract['direct_receipt_schema'])};
    static final String BUILTIN_PROTOCOL = {java_string(builtin['protocol'])};
    static final String BUILTIN_SOCKET = {java_string(builtin['socket'])};
    static final String BUILTIN_WIRE_METHOD_RUN_DIRECT_TURN = {java_string(builtin['wire_methods']['run_direct_turn'])};
    static final boolean TOOL_INVOCATION_OWNED_BY_AGENT = {str(effect['tool_invocation_owned_by_agent']).lower()};
    static final boolean TOOL_BACKEND_OWNED_BY_OS = {str(effect['tool_backend_owned_by_os']).lower()};
    static final boolean DAEMON_IS_EFFECT_EXECUTOR = {str(effect['daemon_is_effect_executor']).lower()};
    static final boolean CONTRACT_CONFERS_EFFECT_AUTHORITY = {str(effect['contract_confers_effect_authority']).lower()};

    private static final String[] DIRECT_RESULT_FIELDS = {{
            {java_array(contract['direct_result_fields'])}
    }};
    private static final String[] DIRECT_COMMITMENT_FIELDS = {{
            {java_array(contract['direct_commitment_fields'])}
    }};

    private DirectAgentHostAbi() {{}}

    static String[] directResultFields() {{
        return DIRECT_RESULT_FIELDS.clone();
    }}

    static String[] directCommitmentFields() {{
        return DIRECT_COMMITMENT_FIELDS.clone();
    }}
}}
'''


def semantic_rust(source: str) -> str:
    output: list[str] = []
    index = 0
    state = "normal"
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "normal":
            if char.isspace():
                index += 1
                continue
            if char == "/" and following == "/":
                state = "line_comment"
                index += 2
                continue
            if char == "/" and following == "*":
                state = "block_comment"
                index += 2
                continue
            if char == '"':
                state = "string"
            output.append(char)
        elif state == "line_comment":
            if char == "\n":
                state = "normal"
        elif state == "block_comment":
            if char == "*" and following == "/":
                state = "normal"
                index += 1
        else:
            output.append(char)
            if char == "\\" and following:
                output.append(following)
                index += 1
            elif char == '"':
                state = "normal"
        index += 1
    if state != "normal":
        raise SystemExit("generated Rust source ended inside a token")
    return re.sub(r",(?=[]})])", "", "".join(output))


def check_or_write(
    path: Path,
    expected: bytes,
    check: bool,
    description: str,
    semantic_compare: bool = False,
) -> None:
    if check:
        if not path.is_file():
            raise SystemExit(f"generated {description} is stale: {path}")
        actual = path.read_bytes()
        matches = actual == expected
        if semantic_compare and not matches:
            matches = semantic_rust(actual.decode("utf-8")) == semantic_rust(
                expected.decode("utf-8")
            )
        if not matches:
            raise SystemExit(f"generated {description} is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(expected)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--rust-output", type=Path, default=RUST_OUTPUT)
    parser.add_argument("--java-output", type=Path)
    parser.add_argument("--mirror-output", type=Path, action="append", default=[])
    args = parser.parse_args()

    contract, raw, digest = load_contract(args.contract)
    check_or_write(
        args.rust_output,
        render_rust(contract, digest).encode("utf-8"),
        args.check,
        "Rust Direct Agent Host ABI",
        semantic_compare=True,
    )
    if args.java_output is not None:
        check_or_write(
            args.java_output,
            render_java(contract, digest).encode("utf-8"),
            args.check,
            "Java Direct Agent Host ABI",
        )
    for mirror in args.mirror_output:
        check_or_write(mirror, raw, args.check, "Direct Agent Host ABI contract mirror")


if __name__ == "__main__":
    main()
