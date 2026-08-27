#!/usr/bin/env python3
"""Generate the closed root task-registration bindings for capability leases."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts/capability-lease-root-registration-v1.json"
RUST_OUTPUT = ROOT / "src/capability_lease_root_registration.rs"

CONTRACT_SCHEMA = "org.trillionnium.capabilitylease.root-registration.contract.v1"
TASK_REGISTRATION_SCHEMA = "org.trillionnium.capabilitylease.root-task-registration.v1"
SOURCE_STATUS = "source_only_no_transport_no_runtime_no_effect_authority_v1"
FIXED = {
    "registration_binding_domain": "trillionnium.capability-lease-root-registration.v1",
    "kind": "TASK_CONTEXT",
    "adapter_id": "system_api",
    "action_id": "open_uri",
    "subject_user_id": 0,
    "opaque_task_context_token_prefix": "task-context-",
}
AUTHORITY = {
    "transport_available": False,
    "runtime_consumer_available": False,
    "confers_effect_authority": False,
}
BINDING_FIELDS = (
    "domain",
    "kind",
    "peer",
    "boot_id_sha256",
    "publisher_epoch",
    "root_journal_genesis_sha256",
    "epoch_proof_sha256",
    "publisher_sequence",
    "adapter",
    "action",
    "subject_user",
    "opaque_token_sha256",
    "request_id",
    "canonical_request_sha256",
    "workflow_id",
    "task_id",
    "authenticated_task_binding_sha256",
    "root_direct_binding_sha256",
)
PAYLOAD_FIELDS = (
    "schema",
    "provider_id",
    "agent_id",
    "replay_namespace",
    "boot_id_sha256",
    "publisher_epoch",
    "publisher_sequence",
    "root_journal_genesis_sha256",
    "epoch_proof_sha256",
    "opaque_task_context_token",
    "prepare_request_id",
    "prepare_canonical_request_sha256",
    "workflow_id",
    "task_id",
    "authenticated_task_binding_sha256",
    "root_direct_binding_sha256",
    "registration_binding_sha256",
)
ENCODING = {
    "digest": "sha256",
    "field_frame": (
        "u32be(name_byte_length) || name_ascii || "
        "u32be(value_byte_length) || value"
    ),
    "string_values": "utf8",
    "integer_values": "i64be",
    "binding_fields": list(BINDING_FIELDS),
    "payload_fields": list(PAYLOAD_FIELDS),
}
VALIDATION = {
    "digest": "lower_hex_64_nonzero",
    "publisher_epoch": "lower_hex_32_nonzero",
    "publisher_sequence": "1..9223372036854775807",
    "request_id": "ascii_[A-Za-z0-9._:-]+_max_128_bytes",
    "workflow_id": "req-[0-9a-f]{32}",
    "task_id": "ascii_[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
    "opaque_task_context_token": "task-context-[0-9a-f]{64}_nonzero_suffix",
}
TOP_LEVEL_FIELDS = {
    "contract_schema",
    "task_registration_schema",
    "source_status",
    "fixed",
    "authority",
    "encoding",
    "validation",
    "golden",
}
GOLDEN_FIELDS = {
    "provider_id",
    "agent_id",
    "replay_namespace",
    "boot_id_sha256",
    "publisher_epoch",
    "publisher_sequence",
    "root_journal_genesis_sha256",
    "epoch_proof_sha256",
    "opaque_task_context_token",
    "prepare_request_id",
    "prepare_canonical_request_sha256",
    "workflow_id",
    "task_id",
    "authenticated_task_binding_sha256",
    "root_direct_binding_sha256",
    "opaque_token_sha256",
    "registration_binding_sha256",
}


def exact_fields(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise SystemExit(f"{label} fields are not closed")
    return value


def reject_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def load_strict_json(raw: bytes) -> object:
    try:
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicate_object,
            parse_constant=reject_nonstandard_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"invalid root-registration contract: {error}") from error


def valid_nonzero_hex(value: object, width: int) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(f"[0-9a-f]{{{width}}}", value) is not None
        and value != "0" * width
    )


def valid_request_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value.encode("ascii", errors="ignore")) <= 128
        and value.isascii()
        and re.fullmatch(r"[A-Za-z0-9._:-]+", value) is not None
    )


def valid_task_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value.encode("utf-8")) <= 128
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None
    )


def framed(name: str, value: bytes) -> bytes:
    encoded_name = name.encode("ascii")
    return (
        struct.pack(">I", len(encoded_name))
        + encoded_name
        + struct.pack(">I", len(value))
        + value
    )


def derive_golden(contract: dict[str, object]) -> tuple[str, str]:
    golden = contract["golden"]
    opaque_sha256 = hashlib.sha256(
        golden["opaque_task_context_token"].encode("ascii")
    ).hexdigest()
    values: dict[str, bytes] = {
        "domain": FIXED["registration_binding_domain"].encode("utf-8"),
        "kind": FIXED["kind"].encode("utf-8"),
        "peer": golden["replay_namespace"].encode("utf-8"),
        "boot_id_sha256": golden["boot_id_sha256"].encode("utf-8"),
        "publisher_epoch": golden["publisher_epoch"].encode("utf-8"),
        "root_journal_genesis_sha256": golden[
            "root_journal_genesis_sha256"
        ].encode("utf-8"),
        "epoch_proof_sha256": golden["epoch_proof_sha256"].encode("utf-8"),
        "publisher_sequence": struct.pack(">q", golden["publisher_sequence"]),
        "adapter": FIXED["adapter_id"].encode("utf-8"),
        "action": FIXED["action_id"].encode("utf-8"),
        "subject_user": struct.pack(">q", FIXED["subject_user_id"]),
        "opaque_token_sha256": opaque_sha256.encode("utf-8"),
        "request_id": golden["prepare_request_id"].encode("utf-8"),
        "canonical_request_sha256": golden[
            "prepare_canonical_request_sha256"
        ].encode("utf-8"),
        "workflow_id": golden["workflow_id"].encode("utf-8"),
        "task_id": golden["task_id"].encode("utf-8"),
        "authenticated_task_binding_sha256": golden[
            "authenticated_task_binding_sha256"
        ].encode("utf-8"),
        "root_direct_binding_sha256": golden["root_direct_binding_sha256"].encode(
            "utf-8"
        ),
    }
    digest = hashlib.sha256()
    for field in BINDING_FIELDS:
        digest.update(framed(field, values[field]))
    return opaque_sha256, digest.hexdigest()


def load_contract(path: Path) -> tuple[dict[str, object], bytes, str]:
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise SystemExit("contract must end with one newline")
    contract = load_strict_json(raw)
    exact_fields(contract, TOP_LEVEL_FIELDS, "contract")
    if contract["contract_schema"] != CONTRACT_SCHEMA:
        raise SystemExit("unexpected root-registration contract schema")
    if contract["task_registration_schema"] != TASK_REGISTRATION_SCHEMA:
        raise SystemExit("unexpected root task-registration schema")
    if contract["source_status"] != SOURCE_STATUS:
        raise SystemExit("root registration must remain source-only")
    if exact_fields(contract["fixed"], set(FIXED), "fixed") != FIXED:
        raise SystemExit("fixed root-registration values drifted")
    if exact_fields(contract["authority"], set(AUTHORITY), "authority") != AUTHORITY:
        raise SystemExit("root registration unexpectedly grants authority")
    if exact_fields(contract["encoding"], set(ENCODING), "encoding") != ENCODING:
        raise SystemExit("root-registration encoding drifted")
    if exact_fields(contract["validation"], set(VALIDATION), "validation") != VALIDATION:
        raise SystemExit("root-registration validation drifted")
    golden = exact_fields(contract["golden"], GOLDEN_FIELDS, "golden")
    if (
        golden["provider_id"] != "openai-codex"
        or golden["agent_id"] != "agent-codex-direct-v1"
        or golden["replay_namespace"] != "agent-codex-v1"
        or not valid_nonzero_hex(golden["boot_id_sha256"], 64)
        or not valid_nonzero_hex(golden["publisher_epoch"], 32)
        or not isinstance(golden["publisher_sequence"], int)
        or not 1 <= golden["publisher_sequence"] <= 2**63 - 1
        or not valid_nonzero_hex(golden["root_journal_genesis_sha256"], 64)
        or not valid_nonzero_hex(golden["epoch_proof_sha256"], 64)
        or not valid_request_id(golden["prepare_request_id"])
        or not valid_nonzero_hex(golden["prepare_canonical_request_sha256"], 64)
        or re.fullmatch(r"req-[0-9a-f]{32}", golden["workflow_id"]) is None
        or not valid_task_id(golden["task_id"])
        or not valid_nonzero_hex(golden["authenticated_task_binding_sha256"], 64)
        or not valid_nonzero_hex(golden["root_direct_binding_sha256"], 64)
        or re.fullmatch(r"task-context-[0-9a-f]{64}", golden["opaque_task_context_token"])
        is None
        or golden["opaque_task_context_token"].endswith("0" * 64)
    ):
        raise SystemExit("golden root task registration is malformed")
    opaque_sha256, registration_sha256 = derive_golden(contract)
    if golden["opaque_token_sha256"] != opaque_sha256:
        raise SystemExit("golden opaque-token digest does not match")
    if golden["registration_binding_sha256"] != registration_sha256:
        raise SystemExit("golden root-registration binding does not match")
    return contract, raw, hashlib.sha256(raw).hexdigest()


def rust_strings(values: tuple[str, ...]) -> str:
    return "\n".join(f'    {json.dumps(value)},' for value in values)


def render_rust(contract: dict[str, object], digest: str) -> str:
    golden = contract["golden"]
    template = r'''// @generated by tools/generate-capability-lease-root-registration.py; do not edit.

use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_principal_registry;
use crate::capability_lease_agent_binding::{
    CAPABILITY_LEASE_OPEN_URI_ACTION_KIND, resolve_system_api_open_uri_agent_binding,
};
use crate::direct_operation::{DirectOperationAdapter, DirectOperationBindingInbox};
use crate::sha256_bytes;

pub const CONTRACT_SCHEMA: &str = "@CONTRACT_SCHEMA@";
pub const CONTRACT_SHA256: &str = "@CONTRACT_SHA256@";
pub const TASK_REGISTRATION_SCHEMA: &str = "@TASK_REGISTRATION_SCHEMA@";
pub const SOURCE_STATUS: &str = "@SOURCE_STATUS@";
pub const REGISTRATION_BINDING_DOMAIN: &str = "@REGISTRATION_BINDING_DOMAIN@";
pub const TASK_CONTEXT_KIND: &str = "@TASK_CONTEXT_KIND@";
pub const ADAPTER_ID: &str = "@ADAPTER_ID@";
pub const ACTION_ID: &str = "@ACTION_ID@";
pub const SUBJECT_USER_ID: u64 = @SUBJECT_USER_ID@;
pub const OPAQUE_TASK_CONTEXT_TOKEN_PREFIX: &str = "@TOKEN_PREFIX@";
pub const TRANSPORT_AVAILABLE: bool = false;
pub const RUNTIME_CONSUMER_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

pub const BINDING_FIELDS: &[&str] = &[
@BINDING_FIELDS@
];
pub const PAYLOAD_FIELDS: &[&str] = &[
@PAYLOAD_FIELDS@
];

pub const GOLDEN_OPAQUE_TOKEN_SHA256: &str = "@GOLDEN_OPAQUE_TOKEN_SHA256@";
pub const GOLDEN_REGISTRATION_BINDING_SHA256: &str =
    "@GOLDEN_REGISTRATION_BINDING_SHA256@";

pub type CapabilityLeaseRootRegistrationResult<T> =
    Result<T, CapabilityLeaseRootRegistrationError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityLeaseRootRegistrationError(&'static str);

impl CapabilityLeaseRootRegistrationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for CapabilityLeaseRootRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for CapabilityLeaseRootRegistrationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeaseRootPublisherEvidenceV1 {
    pub boot_id_sha256: String,
    pub publisher_epoch: String,
    pub publisher_sequence: u64,
    pub root_journal_genesis_sha256: String,
    pub epoch_proof_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeaseRootTaskContextV1 {
    pub opaque_task_context_token: String,
    pub prepare_request_id: String,
    pub prepare_canonical_request_sha256: String,
    pub workflow_id: String,
    pub task_id: String,
    pub authenticated_task_binding_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeaseRootTaskRegistrationV1 {
    pub schema: String,
    pub provider_id: String,
    pub agent_id: String,
    pub replay_namespace: String,
    pub boot_id_sha256: String,
    pub publisher_epoch: String,
    pub publisher_sequence: u64,
    pub root_journal_genesis_sha256: String,
    pub epoch_proof_sha256: String,
    pub opaque_task_context_token: String,
    pub prepare_request_id: String,
    pub prepare_canonical_request_sha256: String,
    pub workflow_id: String,
    pub task_id: String,
    pub authenticated_task_binding_sha256: String,
    pub root_direct_binding_sha256: String,
    pub registration_binding_sha256: String,
}

impl CapabilityLeaseRootTaskRegistrationV1 {
    pub fn derive(
        provider_id: String,
        agent_id: String,
        replay_namespace: String,
        publisher: CapabilityLeaseRootPublisherEvidenceV1,
        task: CapabilityLeaseRootTaskContextV1,
        root_direct_binding_sha256: String,
    ) -> CapabilityLeaseRootRegistrationResult<Self> {
        let mut value = Self {
            schema: TASK_REGISTRATION_SCHEMA.to_string(),
            provider_id,
            agent_id,
            replay_namespace,
            boot_id_sha256: publisher.boot_id_sha256,
            publisher_epoch: publisher.publisher_epoch,
            publisher_sequence: publisher.publisher_sequence,
            root_journal_genesis_sha256: publisher.root_journal_genesis_sha256,
            epoch_proof_sha256: publisher.epoch_proof_sha256,
            opaque_task_context_token: task.opaque_task_context_token,
            prepare_request_id: task.prepare_request_id,
            prepare_canonical_request_sha256: task.prepare_canonical_request_sha256,
            workflow_id: task.workflow_id,
            task_id: task.task_id,
            authenticated_task_binding_sha256: task.authenticated_task_binding_sha256,
            root_direct_binding_sha256,
            registration_binding_sha256: String::new(),
        };
        value.validate_preimage()?;
        value.registration_binding_sha256 = value.expected_binding_sha256()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> CapabilityLeaseRootRegistrationResult<()> {
        self.validate_preimage()?;
        if !valid_nonzero_lower_hex(&self.registration_binding_sha256, 64)
            || self.expected_binding_sha256()? != self.registration_binding_sha256
        {
            return Err(denied("capability_lease_root_registration_binding_denied"));
        }
        Ok(())
    }

    pub fn validate_for_inbox(
        &self,
        inbox: &DirectOperationBindingInbox,
    ) -> CapabilityLeaseRootRegistrationResult<()> {
        self.validate()?;
        inbox
            .validate()
            .map_err(|_| denied("capability_lease_root_registration_inbox_denied"))?;
        if self.provider_id != inbox.binding.stable_seed.provider_id
            || self.agent_id != inbox.binding.stable_seed.agent_id
            || self.task_id != inbox.binding.stable_seed.task_id
            || self.root_direct_binding_sha256 != inbox.binding_sha256
            || self.workflow_id_sha256() != inbox.binding.workflow_id_sha256
        {
            return Err(denied("capability_lease_root_registration_inbox_denied"));
        }
        Ok(())
    }

    pub fn binding_sha256(&self) -> CapabilityLeaseRootRegistrationResult<String> {
        self.validate()?;
        Ok(self.registration_binding_sha256.clone())
    }

    pub fn opaque_token_sha256(&self) -> CapabilityLeaseRootRegistrationResult<String> {
        if !valid_task_context_token(&self.opaque_task_context_token) {
            return Err(denied("capability_lease_root_registration_task_denied"));
        }
        Ok(sha256_bytes(self.opaque_task_context_token.as_bytes()))
    }

    fn workflow_id_sha256(&self) -> String {
        sha256_bytes(self.workflow_id.as_bytes())
    }

    fn validate_preimage(&self) -> CapabilityLeaseRootRegistrationResult<()> {
        if self.schema != TASK_REGISTRATION_SCHEMA {
            return Err(denied("capability_lease_root_registration_schema_denied"));
        }
        let principal = agent_principal_registry::from_provider_agent_pair(
            &self.provider_id,
            &self.agent_id,
        )
        .ok_or_else(|| denied("capability_lease_root_registration_descriptor_denied"))?;
        if self.replay_namespace != principal.replay_namespace {
            return Err(denied("capability_lease_root_registration_descriptor_denied"));
        }
        if !valid_nonzero_lower_hex(&self.boot_id_sha256, 64)
            || !valid_nonzero_lower_hex(&self.publisher_epoch, 32)
            || self.publisher_sequence == 0
            || self.publisher_sequence > i64::MAX as u64
            || !valid_nonzero_lower_hex(&self.root_journal_genesis_sha256, 64)
            || !valid_nonzero_lower_hex(&self.epoch_proof_sha256, 64)
        {
            return Err(denied("capability_lease_root_registration_publisher_denied"));
        }
        if !valid_task_context_token(&self.opaque_task_context_token)
            || !valid_request_id(&self.prepare_request_id)
            || !valid_nonzero_lower_hex(&self.prepare_canonical_request_sha256, 64)
            || !valid_workflow_id(&self.workflow_id)
            || !valid_task_id(&self.task_id)
            || !valid_nonzero_lower_hex(&self.authenticated_task_binding_sha256, 64)
            || !valid_nonzero_lower_hex(&self.root_direct_binding_sha256, 64)
        {
            return Err(denied("capability_lease_root_registration_task_denied"));
        }
        Ok(())
    }

    fn expected_binding_sha256(&self) -> CapabilityLeaseRootRegistrationResult<String> {
        self.validate_preimage()?;
        let mut hasher = Sha256::new();
        hash_string_field(&mut hasher, "domain", REGISTRATION_BINDING_DOMAIN)?;
        hash_string_field(&mut hasher, "kind", TASK_CONTEXT_KIND)?;
        hash_string_field(&mut hasher, "peer", &self.replay_namespace)?;
        hash_string_field(&mut hasher, "boot_id_sha256", &self.boot_id_sha256)?;
        hash_string_field(&mut hasher, "publisher_epoch", &self.publisher_epoch)?;
        hash_string_field(
            &mut hasher,
            "root_journal_genesis_sha256",
            &self.root_journal_genesis_sha256,
        )?;
        hash_string_field(&mut hasher, "epoch_proof_sha256", &self.epoch_proof_sha256)?;
        hash_u64_field(&mut hasher, "publisher_sequence", self.publisher_sequence)?;
        hash_string_field(&mut hasher, "adapter", ADAPTER_ID)?;
        hash_string_field(&mut hasher, "action", ACTION_ID)?;
        hash_u64_field(&mut hasher, "subject_user", SUBJECT_USER_ID)?;
        hash_string_field(
            &mut hasher,
            "opaque_token_sha256",
            &self.opaque_token_sha256()?,
        )?;
        hash_string_field(&mut hasher, "request_id", &self.prepare_request_id)?;
        hash_string_field(
            &mut hasher,
            "canonical_request_sha256",
            &self.prepare_canonical_request_sha256,
        )?;
        hash_string_field(&mut hasher, "workflow_id", &self.workflow_id)?;
        hash_string_field(&mut hasher, "task_id", &self.task_id)?;
        hash_string_field(
            &mut hasher,
            "authenticated_task_binding_sha256",
            &self.authenticated_task_binding_sha256,
        )?;
        hash_string_field(
            &mut hasher,
            "root_direct_binding_sha256",
            &self.root_direct_binding_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

pub fn derive_system_api_open_uri_root_task_registration(
    inbox: &DirectOperationBindingInbox,
    publisher: CapabilityLeaseRootPublisherEvidenceV1,
    task: CapabilityLeaseRootTaskContextV1,
) -> CapabilityLeaseRootRegistrationResult<CapabilityLeaseRootTaskRegistrationV1> {
    let agent = resolve_system_api_open_uri_agent_binding(
        inbox,
        &task.workflow_id,
        &task.task_id,
        &inbox.binding.stable_seed.provider_id,
        DirectOperationAdapter::SystemApi,
        CAPABILITY_LEASE_OPEN_URI_ACTION_KIND,
    )
    .map_err(|_| denied("capability_lease_root_registration_inbox_denied"))?;
    let principal = agent_principal_registry::from_provider_agent_pair(
        &agent.provider_id,
        &agent.agent_id,
    )
    .ok_or_else(|| denied("capability_lease_root_registration_descriptor_denied"))?;
    let registration = CapabilityLeaseRootTaskRegistrationV1::derive(
        agent.provider_id,
        agent.agent_id,
        principal.replay_namespace.to_string(),
        publisher,
        task,
        inbox.binding_sha256.clone(),
    )?;
    registration.validate_for_inbox(inbox)?;
    Ok(registration)
}

fn hash_string_field(
    hasher: &mut Sha256,
    name: &str,
    value: &str,
) -> CapabilityLeaseRootRegistrationResult<()> {
    hash_bytes_field(hasher, name, value.as_bytes())
}

fn hash_u64_field(
    hasher: &mut Sha256,
    name: &str,
    value: u64,
) -> CapabilityLeaseRootRegistrationResult<()> {
    hash_bytes_field(hasher, name, &value.to_be_bytes())
}

fn hash_bytes_field(
    hasher: &mut Sha256,
    name: &str,
    value: &[u8],
) -> CapabilityLeaseRootRegistrationResult<()> {
    let name_length = u32::try_from(name.len())
        .map_err(|_| denied("capability_lease_root_registration_binding_denied"))?;
    let value_length = u32::try_from(value.len())
        .map_err(|_| denied("capability_lease_root_registration_binding_denied"))?;
    hasher.update(name_length.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(value_length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn valid_nonzero_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(valid_ascii_identifier_byte)
}

fn valid_workflow_id(value: &str) -> bool {
    value
        .strip_prefix("req-")
        .is_some_and(|suffix| valid_lower_hex(suffix, 32))
}

fn valid_task_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.len() <= 128
        && bytes.all(valid_ascii_identifier_byte)
}

fn valid_task_context_token(value: &str) -> bool {
    value
        .strip_prefix(OPAQUE_TASK_CONTEXT_TOKEN_PREFIX)
        .is_some_and(|suffix| valid_nonzero_lower_hex(suffix, 64))
}

fn valid_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_ascii_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
}

fn lower_hex(value: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}

const fn denied(code: &'static str) -> CapabilityLeaseRootRegistrationError {
    CapabilityLeaseRootRegistrationError(code)
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::agent_descriptor_registry::{AgentDescriptor, CODEX};
    use crate::direct_operation::{
        BINDING_INBOX_SCHEMA, BINDING_SCHEMA, DirectOperationBinding,
        DirectOperationProviderAttempt, DirectOperationStableSeed, STABLE_SEED_SCHEMA,
    };

    const GOLDEN_BOOT: &str = "@GOLDEN_BOOT@";
    const GOLDEN_EPOCH: &str = "@GOLDEN_EPOCH@";
    const GOLDEN_ROOT_GENESIS: &str = "@GOLDEN_ROOT_GENESIS@";
    const GOLDEN_EPOCH_PROOF: &str = "@GOLDEN_EPOCH_PROOF@";
    const GOLDEN_TASK_TOKEN: &str = "@GOLDEN_TASK_TOKEN@";
    const GOLDEN_PREPARE_REQUEST: &str = "@GOLDEN_PREPARE_REQUEST@";
    const GOLDEN_PREPARE_CANONICAL: &str = "@GOLDEN_PREPARE_CANONICAL@";
    const GOLDEN_WORKFLOW: &str = "@GOLDEN_WORKFLOW@";
    const GOLDEN_TASK: &str = "@GOLDEN_TASK@";
    const GOLDEN_TASK_BINDING: &str = "@GOLDEN_TASK_BINDING@";
    const GOLDEN_ROOT_DIRECT_BINDING: &str = "@GOLDEN_ROOT_DIRECT_BINDING@";

    fn publisher() -> CapabilityLeaseRootPublisherEvidenceV1 {
        CapabilityLeaseRootPublisherEvidenceV1 {
            boot_id_sha256: GOLDEN_BOOT.to_string(),
            publisher_epoch: GOLDEN_EPOCH.to_string(),
            publisher_sequence: @GOLDEN_SEQUENCE@,
            root_journal_genesis_sha256: GOLDEN_ROOT_GENESIS.to_string(),
            epoch_proof_sha256: GOLDEN_EPOCH_PROOF.to_string(),
        }
    }

    fn task() -> CapabilityLeaseRootTaskContextV1 {
        CapabilityLeaseRootTaskContextV1 {
            opaque_task_context_token: GOLDEN_TASK_TOKEN.to_string(),
            prepare_request_id: GOLDEN_PREPARE_REQUEST.to_string(),
            prepare_canonical_request_sha256: GOLDEN_PREPARE_CANONICAL.to_string(),
            workflow_id: GOLDEN_WORKFLOW.to_string(),
            task_id: GOLDEN_TASK.to_string(),
            authenticated_task_binding_sha256: GOLDEN_TASK_BINDING.to_string(),
        }
    }

    fn golden_registration() -> CapabilityLeaseRootTaskRegistrationV1 {
        CapabilityLeaseRootTaskRegistrationV1::derive(
            CODEX.provider_id.to_string(),
            CODEX.agent_id.to_string(),
            CODEX.replay_namespace.to_string(),
            publisher(),
            task(),
            GOLDEN_ROOT_DIRECT_BINDING.to_string(),
        )
        .unwrap()
    }

    fn fixture_inbox(descriptor: &AgentDescriptor) -> DirectOperationBindingInbox {
        let stable_seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: descriptor.provider_id.to_string(),
            agent_id: descriptor.agent_id.to_string(),
            task_id: GOLDEN_TASK.to_string(),
            provider_invocation_id_sha256: sha256_bytes(b"lease-provider-invocation"),
            provider_session_id_sha256: sha256_bytes(b"lease-provider-session"),
            subject_uid: 10_123,
            subject_selinux_domain_sha256: sha256_bytes(b"lease-aishell-domain"),
        };
        let invocation_id = stable_seed.invocation_id().unwrap();
        let binding = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            stable_seed,
            invocation_id,
            workflow_id_sha256: sha256_bytes(GOLDEN_WORKFLOW.as_bytes()),
            agent_identity_key_sha256: descriptor.identity_key_sha256.to_string(),
            agent_executable_sha256: descriptor.identity_key_sha256.to_string(),
            authorized_adapter_set: crate::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(
                sha256_bytes(b"lease-runtime-lifecycle"),
                1,
                sha256_bytes(b"lease-daemon-attempt-context"),
            )
            .unwrap(),
        };
        let binding_sha256 = binding.digest_sha256().unwrap();
        DirectOperationBindingInbox {
            schema: BINDING_INBOX_SCHEMA.to_string(),
            binding,
            binding_sha256,
        }
    }

    fn assert_code<T>(expected: &'static str, result: CapabilityLeaseRootRegistrationResult<T>) {
        match result {
            Ok(_) => panic!("expected root task-registration rejection"),
            Err(error) => assert_eq!(error.code(), expected),
        }
    }

    #[test]
    fn generated_contract_hash_and_closed_status_are_exact() {
        assert_eq!(
            sha256_bytes(include_bytes!(
                "../contracts/capability-lease-root-registration-v1.json"
            )),
            CONTRACT_SHA256
        );
        assert_eq!(BINDING_FIELDS.len(), 18);
        assert_eq!(PAYLOAD_FIELDS.len(), 17);
        assert!(!TRANSPORT_AVAILABLE);
        assert!(!RUNTIME_CONSUMER_AVAILABLE);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    }

    #[test]
    fn cross_language_golden_binding_is_byte_exact() {
        let registration = golden_registration();
        assert_eq!(
            registration.opaque_token_sha256().unwrap(),
            GOLDEN_OPAQUE_TOKEN_SHA256
        );
        assert_eq!(
            registration.binding_sha256().unwrap(),
            GOLDEN_REGISTRATION_BINDING_SHA256
        );
        let value = serde_json::to_value(&registration).unwrap();
        let fields = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(fields, PAYLOAD_FIELDS.iter().copied().collect());
    }

    #[test]
    fn direct_inbox_producer_binds_codex_without_authority() {
        for descriptor in [&CODEX] {
            let inbox = fixture_inbox(descriptor);
            let registration = derive_system_api_open_uri_root_task_registration(
                &inbox,
                publisher(),
                task(),
            )
            .unwrap();
            assert_eq!(registration.provider_id, descriptor.provider_id);
            assert_eq!(registration.agent_id, descriptor.agent_id);
            assert_eq!(registration.replay_namespace, descriptor.replay_namespace);
            assert_eq!(registration.root_direct_binding_sha256, inbox.binding_sha256);
            registration.validate_for_inbox(&inbox).unwrap();
        }
    }

    #[test]
    fn retained_payload_rejects_descriptor_publisher_task_and_binding_drift() {
        let valid = golden_registration();

        let mut descriptor = valid.clone();
        descriptor.replay_namespace = "unregistered-replay-namespace".to_string();
        assert_code(
            "capability_lease_root_registration_descriptor_denied",
            descriptor.validate(),
        );

        let mut publisher = valid.clone();
        publisher.publisher_sequence = 0;
        assert_code(
            "capability_lease_root_registration_publisher_denied",
            publisher.validate(),
        );

        let mut task = valid.clone();
        task.opaque_task_context_token = format!("{}{}", OPAQUE_TASK_CONTEXT_TOKEN_PREFIX, "0".repeat(64));
        assert_code(
            "capability_lease_root_registration_task_denied",
            task.validate(),
        );

        let mut binding = valid;
        binding.registration_binding_sha256 = sha256_bytes(b"drifted-registration");
        assert_code(
            "capability_lease_root_registration_binding_denied",
            binding.validate(),
        );
    }

    #[test]
    fn direct_inbox_producer_rejects_workflow_task_and_binding_drift() {
        let inbox = fixture_inbox(&CODEX);

        let mut workflow = task();
        workflow.workflow_id = "req-fedcba9876543210fedcba9876543210".to_string();
        assert_code(
            "capability_lease_root_registration_inbox_denied",
            derive_system_api_open_uri_root_task_registration(&inbox, publisher(), workflow),
        );

        let mut task_id = task();
        task_id.task_id = "task.other".to_string();
        assert_code(
            "capability_lease_root_registration_inbox_denied",
            derive_system_api_open_uri_root_task_registration(&inbox, publisher(), task_id),
        );

        let registration = derive_system_api_open_uri_root_task_registration(
            &inbox,
            publisher(),
            task(),
        )
        .unwrap();
        let mut other = fixture_inbox(&CODEX);
        other.binding.stable_seed.agent_id = "unregistered-agent".to_string();
        assert_code(
            "capability_lease_root_registration_inbox_denied",
            registration.validate_for_inbox(&other),
        );
    }

    #[test]
    fn serde_rejects_unknown_payload_fields() {
        let mut value = serde_json::to_value(golden_registration()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("effect_authority".to_string(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<CapabilityLeaseRootTaskRegistrationV1>(value).is_err()
        );
    }
}
'''
    replacements = {
        "@CONTRACT_SCHEMA@": CONTRACT_SCHEMA,
        "@CONTRACT_SHA256@": digest,
        "@TASK_REGISTRATION_SCHEMA@": TASK_REGISTRATION_SCHEMA,
        "@SOURCE_STATUS@": SOURCE_STATUS,
        "@REGISTRATION_BINDING_DOMAIN@": FIXED["registration_binding_domain"],
        "@TASK_CONTEXT_KIND@": FIXED["kind"],
        "@ADAPTER_ID@": FIXED["adapter_id"],
        "@ACTION_ID@": FIXED["action_id"],
        "@SUBJECT_USER_ID@": str(FIXED["subject_user_id"]),
        "@TOKEN_PREFIX@": FIXED["opaque_task_context_token_prefix"],
        "@BINDING_FIELDS@": rust_strings(BINDING_FIELDS),
        "@PAYLOAD_FIELDS@": rust_strings(PAYLOAD_FIELDS),
        "@GOLDEN_OPAQUE_TOKEN_SHA256@": golden["opaque_token_sha256"],
        "@GOLDEN_REGISTRATION_BINDING_SHA256@": golden[
            "registration_binding_sha256"
        ],
        "@GOLDEN_BOOT@": golden["boot_id_sha256"],
        "@GOLDEN_EPOCH@": golden["publisher_epoch"],
        "@GOLDEN_ROOT_GENESIS@": golden["root_journal_genesis_sha256"],
        "@GOLDEN_EPOCH_PROOF@": golden["epoch_proof_sha256"],
        "@GOLDEN_TASK_TOKEN@": golden["opaque_task_context_token"],
        "@GOLDEN_PREPARE_REQUEST@": golden["prepare_request_id"],
        "@GOLDEN_PREPARE_CANONICAL@": golden[
            "prepare_canonical_request_sha256"
        ],
        "@GOLDEN_WORKFLOW@": golden["workflow_id"],
        "@GOLDEN_TASK@": golden["task_id"],
        "@GOLDEN_TASK_BINDING@": golden["authenticated_task_binding_sha256"],
        "@GOLDEN_ROOT_DIRECT_BINDING@": golden["root_direct_binding_sha256"],
        "@GOLDEN_SEQUENCE@": str(golden["publisher_sequence"]),
    }
    for marker, value in replacements.items():
        template = template.replace(marker, value)
    if re.search(r"@[A-Z_]+@", template):
        raise SystemExit("unexpanded Rust root-registration template marker")
    return template


def java_strings(values: tuple[str, ...]) -> str:
    return ",\n            ".join(json.dumps(value) for value in values)


def render_java(contract: dict[str, object], digest: str) -> str:
    golden = contract["golden"]
    return f'''/*
 * SPDX-License-Identifier: Apache-2.0
 */

// @generated by trillionnium-os-types/tools/generate-capability-lease-root-registration.py; do not edit.
package org.trillionnium.platform.internal;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Closed constants shared by root task registration and the durable token registry. */
final class CapabilityLeaseTokenBindingV1 {{
    static final String CONTRACT_SCHEMA = {json.dumps(CONTRACT_SCHEMA)};
    static final String CONTRACT_SHA256 = {json.dumps(digest)};
    static final String TASK_REGISTRATION_SCHEMA = {json.dumps(TASK_REGISTRATION_SCHEMA)};
    static final String SOURCE_STATUS = {json.dumps(SOURCE_STATUS)};
    static final String REGISTRATION_BINDING_DOMAIN =
            {json.dumps(FIXED['registration_binding_domain'])};
    static final String TASK_CONTEXT_KIND = {json.dumps(FIXED['kind'])};
    static final String ADAPTER_ID = {json.dumps(FIXED['adapter_id'])};
    static final String ACTION_ID = {json.dumps(FIXED['action_id'])};
    static final int SUBJECT_USER_ID = {FIXED['subject_user_id']};
    static final String OPAQUE_TASK_CONTEXT_TOKEN_PREFIX =
            {json.dumps(FIXED['opaque_task_context_token_prefix'])};
    static final boolean TRANSPORT_AVAILABLE = false;
    static final boolean RUNTIME_CONSUMER_AVAILABLE = false;
    static final boolean CONFERS_EFFECT_AUTHORITY = false;
    static final String GOLDEN_OPAQUE_TOKEN_SHA256 =
            {json.dumps(golden['opaque_token_sha256'])};
    static final String GOLDEN_REGISTRATION_BINDING_SHA256 =
            {json.dumps(golden['registration_binding_sha256'])};

    private static final String[] REGISTRATION_BINDING_FIELDS = {{
            {java_strings(BINDING_FIELDS)}
    }};
    private static final String[] REGISTRATION_PAYLOAD_FIELDS = {{
            {java_strings(PAYLOAD_FIELDS)}
    }};

    static String deriveTaskRegistrationBinding(String replayNamespace,
            String bootIdSha256, String publisherEpoch,
            String rootJournalGenesisSha256, String epochProofSha256,
            long publisherSequence, String opaqueTaskContextToken,
            String prepareRequestId, String prepareCanonicalRequestSha256,
            String workflowId, String taskId, String authenticatedTaskBindingSha256,
            String rootDirectBindingSha256) {{
        if (replayNamespace == null || bootIdSha256 == null || publisherEpoch == null
                || rootJournalGenesisSha256 == null || epochProofSha256 == null
                || publisherSequence <= 0 || opaqueTaskContextToken == null
                || prepareRequestId == null || prepareCanonicalRequestSha256 == null
                || workflowId == null || taskId == null
                || authenticatedTaskBindingSha256 == null
                || rootDirectBindingSha256 == null) {{
            throw new SecurityException("invalid task registration binding");
        }}
        MessageDigest digest = newSha256();
        hashStringField(digest, "domain", REGISTRATION_BINDING_DOMAIN);
        hashStringField(digest, "kind", TASK_CONTEXT_KIND);
        hashStringField(digest, "peer", replayNamespace);
        hashStringField(digest, "boot_id_sha256", bootIdSha256);
        hashStringField(digest, "publisher_epoch", publisherEpoch);
        hashStringField(digest, "root_journal_genesis_sha256",
                rootJournalGenesisSha256);
        hashStringField(digest, "epoch_proof_sha256", epochProofSha256);
        hashLongField(digest, "publisher_sequence", publisherSequence);
        hashStringField(digest, "adapter", ADAPTER_ID);
        hashStringField(digest, "action", ACTION_ID);
        hashLongField(digest, "subject_user", SUBJECT_USER_ID);
        hashStringField(digest, "opaque_token_sha256", lowerHex(newSha256().digest(
                opaqueTaskContextToken.getBytes(StandardCharsets.US_ASCII))));
        hashStringField(digest, "request_id", prepareRequestId);
        hashStringField(digest, "canonical_request_sha256",
                prepareCanonicalRequestSha256);
        hashStringField(digest, "workflow_id", workflowId);
        hashStringField(digest, "task_id", taskId);
        hashStringField(digest, "authenticated_task_binding_sha256",
                authenticatedTaskBindingSha256);
        hashStringField(digest, "root_direct_binding_sha256",
                rootDirectBindingSha256);
        return lowerHex(digest.digest());
    }}

    private static void hashStringField(MessageDigest digest, String name, String value) {{
        hashBytesField(digest, name, value.getBytes(StandardCharsets.UTF_8));
    }}

    private static void hashLongField(MessageDigest digest, String name, long value) {{
        hashBytesField(digest, name, ByteBuffer.allocate(Long.BYTES).putLong(value).array());
    }}

    private static void hashBytesField(MessageDigest digest, String name, byte[] value) {{
        byte[] encodedName = name.getBytes(StandardCharsets.US_ASCII);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(encodedName.length).array());
        digest.update(encodedName);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array());
        digest.update(value);
    }}

    private static MessageDigest newSha256() {{
        try {{
            return MessageDigest.getInstance("SHA-256");
        }} catch (NoSuchAlgorithmException impossible) {{
            throw new AssertionError("SHA-256 unavailable", impossible);
        }}
    }}

    private static String lowerHex(byte[] value) {{
        char[] alphabet = "0123456789abcdef".toCharArray();
        char[] encoded = new char[value.length * 2];
        for (int index = 0; index < value.length; index++) {{
            int item = value[index] & 0xff;
            encoded[index * 2] = alphabet[item >>> 4];
            encoded[index * 2 + 1] = alphabet[item & 0x0f];
        }}
        return new String(encoded);
    }}

    private CapabilityLeaseTokenBindingV1() {{}}

    static String[] registrationBindingFields() {{
        return REGISTRATION_BINDING_FIELDS.clone();
    }}

    static String[] registrationPayloadFields() {{
        return REGISTRATION_PAYLOAD_FIELDS.clone();
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
        "Rust capability-lease root registration",
        semantic_compare=True,
    )
    if args.java_output is not None:
        check_or_write(
            args.java_output,
            render_java(contract, digest).encode("utf-8"),
            args.check,
            "Java capability-lease root registration",
        )
    for mirror in args.mirror_output:
        check_or_write(
            mirror,
            raw,
            args.check,
            "capability-lease root-registration contract mirror",
        )


if __name__ == "__main__":
    main()
