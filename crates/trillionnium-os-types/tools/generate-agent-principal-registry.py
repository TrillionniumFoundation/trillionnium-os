#!/usr/bin/env python3
"""Generate the identity-digest-independent stable Agent principal registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "agent-principal-registry-v2.json"
CANONICAL_OPERATION_CONTRACT = (
    ROOT.parent
    / "trillionnium-agent-direct-tools/contracts/canonical-operation-binding-v1.json"
)
OUTPUT = ROOT / "src" / "agent_principal_registry.rs"
PRODUCTION_RUST_ROOT = ROOT.parents[1]
DESCRIPTOR_REGISTRY_OUTPUT = ROOT / "src" / "agent_descriptor_registry.rs"
DESCRIPTOR_CONTRACT = ROOT / "contracts" / "agent-descriptor-registry-v1.json"
CONTRACT_SCHEMA = "org.trillionnium.agent-principal-registry.contract.v2"
REGISTRY_SCHEMA = "org.trillionnium.agent-principal-registry.v2"
PRINCIPAL_SCHEMA = "org.trillionnium.agent-stable-principal.v1"
DESCRIPTOR_CONTRACT_SCHEMA = "org.trillionnium.agent-descriptor-registry.contract.v1"
DESCRIPTOR_REGISTRY_SCHEMA = "org.trillionnium.agent-descriptor-registry.v1"
DESCRIPTOR_SCHEMA = "org.trillionnium.agent-descriptor.v1"
MATERIALIZATION_STATUS = "hold_same_crate_counterfactual_build_required"
TOP_LEVEL_FIELDS = {
    "contract_schema",
    "registry_schema",
    "principal_schema",
    "materialization_status",
    "same_crate_counterfactual_build_required",
    "endpoints",
    "principals",
}
DESCRIPTOR_TOP_LEVEL_FIELDS = {
    "contract_schema",
    "registry_schema",
    "descriptor_schema",
    "endpoints",
    "descriptors",
}
ENDPOINT_FIELDS = {
    "symbol",
    "tool_selinux_domain",
    "operation_replay_sync_selinux_domain",
}
PRINCIPAL_FIELDS = {
    "symbol",
    "provider_id",
    "agent_id",
    "replay_namespace",
    "uid",
    "gid",
    "agent_selinux_domain",
    "runtime_adapter",
}
DESCRIPTOR_FIELDS = PRINCIPAL_FIELDS | {"identity_key_sha256"}
SYMBOL = re.compile(r"[A-Z][A-Z0-9_]*")
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
STABLE_ATOM = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
SELINUX_DOMAIN = re.compile(r"u:r:[a-z0-9_]+:s0")
REQUIRED_ENDPOINT_SYMBOLS = ("SYSTEM_API", "ACCESSIBILITY")
REQUIRED_PRINCIPAL_SYMBOLS = ("CODEX",)


def rust_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def require_exact_fields(value: dict, fields: set[str], description: str) -> None:
    if set(value) != fields:
        raise SystemExit(f"{description} does not use the closed field schema")


def reject_duplicate_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def load_strict_json(raw: bytes, description: str) -> object:
    try:
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicate_object,
            parse_constant=reject_nonstandard_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
        raise SystemExit(f"invalid {description}: {error}") from error


def require_string_pattern(
    value: dict, field: str, pattern: re.Pattern[str], description: str
) -> str:
    field_value = value[field]
    if not isinstance(field_value, str) or pattern.fullmatch(field_value) is None:
        raise SystemExit(f"{description} has an invalid {field}")
    return field_value


def validate_endpoints(endpoints: object, description: str) -> set[str]:
    if not isinstance(endpoints, list) or len(endpoints) != len(
        REQUIRED_ENDPOINT_SYMBOLS
    ):
        raise SystemExit(f"{description} endpoint allowlist is not the closed product set")
    endpoint_domains: set[str] = set()
    for index, endpoint in enumerate(endpoints):
        if not isinstance(endpoint, dict):
            raise SystemExit(f"{description} endpoint {index} must be a JSON object")
        require_exact_fields(
            endpoint,
            ENDPOINT_FIELDS,
            f"{description} endpoint {index}",
        )
        endpoint_description = f"{description} endpoint {index}"
        if endpoint["symbol"] != REQUIRED_ENDPOINT_SYMBOLS[index]:
            raise SystemExit(
                f"{endpoint_description} is not the required product endpoint"
            )
        require_string_pattern(endpoint, "symbol", SYMBOL, endpoint_description)
        for field in (
            "tool_selinux_domain",
            "operation_replay_sync_selinux_domain",
        ):
            domain = require_string_pattern(
                endpoint,
                field,
                SELINUX_DOMAIN,
                endpoint_description,
            )
            if domain in endpoint_domains:
                raise SystemExit(f"{endpoint_description} duplicates a SELinux domain")
            endpoint_domains.add(domain)
    return endpoint_domains


def load_and_validate(path: Path) -> tuple[dict, str, str, str]:
    raw = path.read_bytes()
    contract = load_strict_json(raw, "stable Agent principal contract")
    if not isinstance(contract, dict):
        raise SystemExit("stable Agent principal contract must be a JSON object")
    require_exact_fields(contract, TOP_LEVEL_FIELDS, "stable Agent principal contract")
    if contract["contract_schema"] != CONTRACT_SCHEMA:
        raise SystemExit("unexpected stable Agent principal contract schema")
    if contract["registry_schema"] != REGISTRY_SCHEMA:
        raise SystemExit("unexpected stable Agent principal registry schema")
    if contract["principal_schema"] != PRINCIPAL_SCHEMA:
        raise SystemExit("unexpected stable Agent principal field schema")
    if contract["materialization_status"] != MATERIALIZATION_STATUS:
        raise SystemExit("stable Agent principal materialization status is not fail-closed")
    if contract["same_crate_counterfactual_build_required"] is not True:
        raise SystemExit("stable Agent principal counterfactual build gate is not required")

    endpoint_domains = validate_endpoints(
        contract["endpoints"],
        "stable Agent principal contract",
    )

    principals = contract["principals"]
    if not isinstance(principals, list) or len(principals) != len(
        REQUIRED_PRINCIPAL_SYMBOLS
    ):
        raise SystemExit("stable Agent principal allowlist is not the Codex-only set")

    unique_fields = {
        "symbol": set(),
        "provider_id": set(),
        "agent_id": set(),
        "replay_namespace": set(),
        "uid": set(),
        "gid": set(),
        "agent_selinux_domain": set(),
    }
    for index, principal in enumerate(principals):
        if not isinstance(principal, dict):
            raise SystemExit(f"principal {index} must be a JSON object")
        require_exact_fields(principal, PRINCIPAL_FIELDS, f"principal {index}")
        if principal["symbol"] != REQUIRED_PRINCIPAL_SYMBOLS[index]:
            raise SystemExit(f"principal {index} is not the required Codex principal")
        principal_description = f"principal {index}"
        require_string_pattern(principal, "symbol", SYMBOL, principal_description)
        require_string_pattern(principal, "provider_id", STABLE_ATOM, principal_description)
        agent_id = require_string_pattern(
            principal,
            "agent_id",
            STABLE_ATOM,
            principal_description,
        )
        if not agent_id.startswith("agent-"):
            raise SystemExit(f"principal {index} agent_id is not OS-scoped")
        require_string_pattern(
            principal,
            "replay_namespace",
            STABLE_ATOM,
            principal_description,
        )
        require_string_pattern(
            principal,
            "runtime_adapter",
            STABLE_ATOM,
            principal_description,
        )
        agent_domain = require_string_pattern(
            principal,
            "agent_selinux_domain",
            SELINUX_DOMAIN,
            principal_description,
        )
        if agent_domain in endpoint_domains:
            raise SystemExit(
                f"principal {index} aliases a tool or replay-control endpoint domain"
            )
        for numeric in ("uid", "gid"):
            value = principal[numeric]
            if type(value) is not int or value <= 0 or value > 0x7FFF_FFFF:
                raise SystemExit(f"principal {index} has an invalid {numeric}")
        for field, seen in unique_fields.items():
            if principal[field] in seen:
                raise SystemExit(f"principal {index} duplicates {field}")
            seen.add(principal[field])

    canonical_endpoints = [
        {
            "symbol": endpoint["symbol"],
            "tool_selinux_domain": endpoint["tool_selinux_domain"],
            "operation_replay_sync_selinux_domain": endpoint[
                "operation_replay_sync_selinux_domain"
            ],
        }
        for endpoint in contract["endpoints"]
    ]
    canonical_principals = [
        {
            "schema": contract["principal_schema"],
            "provider_id": principal["provider_id"],
            "agent_id": principal["agent_id"],
            "replay_namespace": principal["replay_namespace"],
            "uid": principal["uid"],
            "gid": principal["gid"],
            "agent_selinux_domain": principal["agent_selinux_domain"],
            "runtime_adapter": principal["runtime_adapter"],
        }
        for principal in principals
    ]
    canonical_json = json.dumps(
        {
            "schema": contract["registry_schema"],
            "endpoints": canonical_endpoints,
            "principals": canonical_principals,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )
    contract_sha256 = hashlib.sha256(raw).hexdigest()
    canonical_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return contract, contract_sha256, canonical_json, canonical_sha256


def validate_descriptor_contract_compatibility(
    path: Path,
    stable_contract: dict,
) -> None:
    descriptor_contract = load_strict_json(
        path.read_bytes(),
        "v1 AgentDescriptor compatibility contract",
    )
    if not isinstance(descriptor_contract, dict):
        raise SystemExit("v1 AgentDescriptor compatibility contract must be a JSON object")
    require_exact_fields(
        descriptor_contract,
        DESCRIPTOR_TOP_LEVEL_FIELDS,
        "v1 AgentDescriptor compatibility contract",
    )
    if descriptor_contract["contract_schema"] != DESCRIPTOR_CONTRACT_SCHEMA:
        raise SystemExit("unexpected v1 AgentDescriptor contract schema")
    if descriptor_contract["registry_schema"] != DESCRIPTOR_REGISTRY_SCHEMA:
        raise SystemExit("unexpected v1 AgentDescriptor registry schema")
    if descriptor_contract["descriptor_schema"] != DESCRIPTOR_SCHEMA:
        raise SystemExit("unexpected v1 AgentDescriptor field schema")
    validate_endpoints(
        descriptor_contract["endpoints"],
        "v1 AgentDescriptor compatibility contract",
    )
    if descriptor_contract["endpoints"] != stable_contract["endpoints"]:
        raise SystemExit("v1 AgentDescriptor endpoints drifted from stable registry v2")

    descriptors = descriptor_contract["descriptors"]
    if not isinstance(descriptors, list) or len(descriptors) != len(
        REQUIRED_PRINCIPAL_SYMBOLS
    ):
        raise SystemExit("v1 AgentDescriptor allowlist is not the Codex-only set")
    for index, (descriptor, principal) in enumerate(
        zip(descriptors, stable_contract["principals"], strict=True)
    ):
        if not isinstance(descriptor, dict):
            raise SystemExit(f"v1 descriptor {index} must be a JSON object")
        require_exact_fields(descriptor, DESCRIPTOR_FIELDS, f"v1 descriptor {index}")
        descriptor_description = f"v1 descriptor {index}"
        if descriptor["symbol"] != REQUIRED_PRINCIPAL_SYMBOLS[index]:
            raise SystemExit(
                f"{descriptor_description} is not the required Codex descriptor"
            )
        require_string_pattern(descriptor, "symbol", SYMBOL, descriptor_description)
        require_string_pattern(
            descriptor,
            "provider_id",
            STABLE_ATOM,
            descriptor_description,
        )
        agent_id = require_string_pattern(
            descriptor,
            "agent_id",
            STABLE_ATOM,
            descriptor_description,
        )
        if not agent_id.startswith("agent-"):
            raise SystemExit(f"{descriptor_description} agent_id is not OS-scoped")
        require_string_pattern(
            descriptor,
            "replay_namespace",
            STABLE_ATOM,
            descriptor_description,
        )
        require_string_pattern(
            descriptor,
            "agent_selinux_domain",
            SELINUX_DOMAIN,
            descriptor_description,
        )
        require_string_pattern(
            descriptor,
            "runtime_adapter",
            STABLE_ATOM,
            descriptor_description,
        )
        identity_digest = require_string_pattern(
            descriptor,
            "identity_key_sha256",
            LOWER_SHA256,
            descriptor_description,
        )
        if identity_digest == "0" * 64:
            raise SystemExit(f"{descriptor_description} has a zero identity key digest")
        for numeric in ("uid", "gid"):
            value = descriptor[numeric]
            if type(value) is not int or value <= 0 or value > 0x7FFF_FFFF:
                raise SystemExit(f"{descriptor_description} has an invalid {numeric}")
        descriptor_projection = {
            field: descriptor[field]
            for field in PRINCIPAL_FIELDS
        }
        if descriptor_projection != principal:
            raise SystemExit(
                f"v1 descriptor {index} stable fields drifted from stable registry v2"
            )


def validate_no_production_principal_mirrors(
    contract: dict,
    source_root: Path,
    generated_output: Path,
    descriptor_registry_output: Path,
) -> None:
    stable_string_fields = (
        "provider_id",
        "agent_id",
        "replay_namespace",
        "agent_selinux_domain",
        "runtime_adapter",
    )
    identities = {
        principal[field]
        for principal in contract["principals"]
        for field in stable_string_fields
    }
    numeric_identities = {
        rendered
        for principal in contract["principals"]
        for field in ("uid", "gid")
        for rendered in (str(principal[field]), f"{principal[field]:_}")
    }
    excluded = {
        generated_output.resolve(),
        descriptor_registry_output.resolve(),
    }
    violations: list[str] = []
    for path in source_root.rglob("*.rs"):
        if path.resolve() in excluded or "target" in path.relative_to(source_root).parts:
            continue
        if "tests" in path.relative_to(source_root).parts:
            continue
        source = path.read_text(encoding="utf-8")
        production_source = re.split(
            r"(?m)^#\[cfg\(test\)\]\r?\n(?:#\[[^\r\n]+\]\r?\n)*mod tests \{",
            source,
            maxsplit=1,
        )[0]
        mirrored = sorted(
            identity for identity in identities if identity in production_source
        )
        mirrored.extend(
            sorted(
                identity
                for identity in numeric_identities
                if re.search(
                    rf"(?<![0-9_]){re.escape(identity)}(?![0-9_])",
                    production_source,
                )
            )
        )
        if mirrored:
            violations.append(f"{path}: {', '.join(mirrored)}")
    if violations:
        raise SystemExit(
            "production Rust mirrors generated stable Agent principal fields:\n"
            + "\n".join(violations)
        )


def render(
    contract_path: Path,
    descriptor_contract_path: Path,
    canonical_operation_contract: Path,
    production_rust_root: Path,
    output: Path,
    descriptor_registry_output: Path,
) -> str:
    contract, contract_sha256, canonical_json, canonical_sha256 = load_and_validate(
        contract_path
    )
    validate_descriptor_contract_compatibility(descriptor_contract_path, contract)
    validate_no_production_principal_mirrors(
        contract,
        production_rust_root,
        output,
        descriptor_registry_output,
    )
    operation_contract = load_strict_json(
        canonical_operation_contract.read_bytes(),
        "canonical operation contract",
    )
    expected_namespaces = {
        principal["symbol"].lower(): principal["replay_namespace"]
        for principal in contract["principals"]
    }
    if not isinstance(operation_contract, dict) or operation_contract.get(
        "agents"
    ) != expected_namespaces:
        raise SystemExit(
            "canonical operation replay namespaces drifted from stable Agent principals"
        )

    endpoint_constants = []
    for endpoint in contract["endpoints"]:
        endpoint_constants.append(
            f'''pub const {endpoint['symbol']}_ENDPOINT: AgentEndpointDescriptor = AgentEndpointDescriptor {{
    symbol: {rust_string(endpoint['symbol'])},
    tool_selinux_domain: {rust_string(endpoint['tool_selinux_domain'])},
    operation_replay_sync_selinux_domain: {rust_string(endpoint['operation_replay_sync_selinux_domain'])},
}};'''
        )
    endpoint_symbols = ", ".join(
        "&" + endpoint["symbol"] + "_ENDPOINT"
        for endpoint in contract["endpoints"]
    )
    constants = []
    for principal in contract["principals"]:
        constants.append(
            f'''pub const {principal['symbol']}_STABLE_PRINCIPAL: AgentStablePrincipal = AgentStablePrincipal {{
    provider_id: {rust_string(principal['provider_id'])},
    agent_id: {rust_string(principal['agent_id'])},
    replay_namespace: {rust_string(principal['replay_namespace'])},
    uid: {principal['uid']},
    gid: {principal['gid']},
    agent_selinux_domain: {rust_string(principal['agent_selinux_domain'])},
    runtime_adapter: {rust_string(principal['runtime_adapter'])},
}};'''
        )
    symbols = ", ".join(
        "&" + principal["symbol"] + "_STABLE_PRINCIPAL"
        for principal in contract["principals"]
    )
    namespace_assertions = "\n".join(
        f'''        assert_eq!(operation["agents"][{rust_string(principal['symbol'].lower())}], {principal['symbol']}_STABLE_PRINCIPAL.replay_namespace);'''
        for principal in contract["principals"]
    )

    return f'''// @generated by tools/generate-agent-principal-registry.py; do not edit.

pub const CONTRACT_SCHEMA: &str = {rust_string(contract['contract_schema'])};
pub const CONTRACT_SHA256: &str = {rust_string(contract_sha256)};
pub const REGISTRY_SCHEMA: &str = {rust_string(contract['registry_schema'])};
pub const STABLE_PRINCIPAL_SCHEMA: &str = {rust_string(contract['principal_schema'])};
pub const MATERIALIZATION_STATUS: &str = {rust_string(contract['materialization_status'])};
pub const SAME_CRATE_COUNTERFACTUAL_BUILD_REQUIRED: bool = {str(contract['same_crate_counterfactual_build_required']).lower()};
pub const STABLE_PRINCIPAL_CANONICAL_JSON: &str = {rust_string(canonical_json)};
pub const STABLE_PRINCIPAL_CANONICAL_SHA256: &str = {rust_string(canonical_sha256)};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentEndpointDescriptor {{
    pub symbol: &'static str,
    pub tool_selinux_domain: &'static str,
    pub operation_replay_sync_selinux_domain: &'static str,
}}

{chr(10).join(endpoint_constants)}

pub const PRODUCT_ENDPOINT_ALLOWLIST: &[&AgentEndpointDescriptor] = &[{endpoint_symbols}];

pub fn endpoint_from_symbol(symbol: &str) -> Option<&'static AgentEndpointDescriptor> {{
    PRODUCT_ENDPOINT_ALLOWLIST
        .iter()
        .copied()
        .find(|endpoint| endpoint.symbol == symbol)
}}

pub fn endpoint_from_tool_selinux_domain(
    selinux_domain: &str,
) -> Option<&'static AgentEndpointDescriptor> {{
    PRODUCT_ENDPOINT_ALLOWLIST
        .iter()
        .copied()
        .find(|endpoint| endpoint.tool_selinux_domain == selinux_domain)
}}

pub fn endpoint_from_operation_replay_sync_selinux_domain(
    selinux_domain: &str,
) -> Option<&'static AgentEndpointDescriptor> {{
    PRODUCT_ENDPOINT_ALLOWLIST
        .iter()
        .copied()
        .find(|endpoint| endpoint.operation_replay_sync_selinux_domain == selinux_domain)
}}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentStablePrincipal {{
    pub provider_id: &'static str,
    pub agent_id: &'static str,
    pub replay_namespace: &'static str,
    pub uid: u32,
    pub gid: u32,
    pub agent_selinux_domain: &'static str,
    pub runtime_adapter: &'static str,
}}

impl AgentStablePrincipal {{
    /// Match only stable, kernel-authenticated registration fields. The
    /// executable/launcher digest and dynamic readiness state are deliberately
    /// outside this stable-principal projection and remain separate gates.
    pub fn matches_registration_fields(&self, registration: &crate::AgentRegistration) -> bool {{
        registration.agent_id == self.agent_id
            && registration.adapter == self.runtime_adapter
            && registration.peer_uid == self.uid
            && registration.peer_gid == self.gid
            && registration.selinux_domain == self.agent_selinux_domain
    }}
}}

{chr(10).join(constants)}

pub const PRODUCT_ALLOWLIST: &[&AgentStablePrincipal] = &[{symbols}];

pub fn from_provider_id(provider_id: &str) -> Option<&'static AgentStablePrincipal> {{
    PRODUCT_ALLOWLIST
        .iter()
        .copied()
        .find(|principal| principal.provider_id == provider_id)
}}

pub fn from_agent_id(agent_id: &str) -> Option<&'static AgentStablePrincipal> {{
    PRODUCT_ALLOWLIST
        .iter()
        .copied()
        .find(|principal| principal.agent_id == agent_id)
}}

pub fn from_replay_namespace(replay_namespace: &str) -> Option<&'static AgentStablePrincipal> {{
    PRODUCT_ALLOWLIST
        .iter()
        .copied()
        .find(|principal| principal.replay_namespace == replay_namespace)
}}

pub fn from_provider_agent_pair(
    provider_id: &str,
    agent_id: &str,
) -> Option<&'static AgentStablePrincipal> {{
    from_provider_id(provider_id).filter(|principal| principal.agent_id == agent_id)
}}

pub fn from_uid_gid(uid: u32, gid: u32) -> Option<&'static AgentStablePrincipal> {{
    PRODUCT_ALLOWLIST
        .iter()
        .copied()
        .find(|principal| principal.uid == uid && principal.gid == gid)
}}

pub fn from_registration_fields(
    registration: &crate::AgentRegistration,
) -> Option<&'static AgentStablePrincipal> {{
    from_agent_id(&registration.agent_id)
        .filter(|principal| principal.matches_registration_fields(registration))
}}

#[cfg(test)]
mod tests {{
    use super::*;
    use crate::{{AgentHealth, AgentNetworkPolicy, AgentRegistration}};

    fn registration(principal: &AgentStablePrincipal) -> AgentRegistration {{
        AgentRegistration {{
            api_version: crate::AGENT_API_VERSION.to_string(),
            agent_id: principal.agent_id.to_string(),
            adapter: principal.runtime_adapter.to_string(),
            adapter_version: "stable-principal-test".to_string(),
            identity_key_sha256: "f".repeat(64),
            peer_uid: principal.uid,
            peer_gid: principal.gid,
            selinux_domain: principal.agent_selinux_domain.to_string(),
            network_policy: AgentNetworkPolicy::Deny,
            enabled: false,
            health: AgentHealth::Offline,
            registered_at_unix_ms: 1,
            updated_at_unix_ms: 1,
        }}
    }}

    #[test]
    fn generated_contract_and_canonical_principal_hashes_are_exact() {{
        assert_eq!(
            crate::sha256_bytes(include_bytes!(
                "../contracts/agent-principal-registry-v2.json"
            )),
            CONTRACT_SHA256
        );
        assert_eq!(
            crate::sha256_bytes(STABLE_PRINCIPAL_CANONICAL_JSON.as_bytes()),
            STABLE_PRINCIPAL_CANONICAL_SHA256
        );
        assert_eq!(
            STABLE_PRINCIPAL_CANONICAL_SHA256,
            {rust_string(canonical_sha256)}
        );
        assert_eq!(
            MATERIALIZATION_STATUS,
            "hold_same_crate_counterfactual_build_required"
        );
        const {{
            assert!(SAME_CRATE_COUNTERFACTUAL_BUILD_REQUIRED);
        }}
    }}

    #[test]
    fn generated_principals_match_the_canonical_registry() {{
        let registry: serde_json::Value = serde_json::from_str(STABLE_PRINCIPAL_CANONICAL_JSON)
        .expect("generated stable principal JSON");
        assert_eq!(registry["schema"], REGISTRY_SCHEMA);
        let endpoints = registry["endpoints"]
            .as_array()
            .expect("generated endpoint array");
        assert_eq!(endpoints.len(), PRODUCT_ENDPOINT_ALLOWLIST.len());
        for (actual, expected) in endpoints.iter().zip(PRODUCT_ENDPOINT_ALLOWLIST) {{
            let actual = actual.as_object().expect("generated endpoint object");
            assert_eq!(actual.len(), 3);
            assert_eq!(actual["symbol"], expected.symbol);
            assert_eq!(actual["tool_selinux_domain"], expected.tool_selinux_domain);
            assert_eq!(
                actual["operation_replay_sync_selinux_domain"],
                expected.operation_replay_sync_selinux_domain
            );
        }}
        let principals = registry["principals"]
            .as_array()
            .expect("generated stable principal array");
        assert_eq!(principals.len(), PRODUCT_ALLOWLIST.len());
        for (actual, expected) in principals
            .iter()
            .zip(PRODUCT_ALLOWLIST)
        {{
            let actual = actual.as_object().expect("generated stable principal object");
            assert_eq!(actual.len(), 8);
            assert_eq!(actual["schema"], STABLE_PRINCIPAL_SCHEMA);
            assert_eq!(actual["provider_id"], expected.provider_id);
            assert_eq!(actual["agent_id"], expected.agent_id);
            assert_eq!(actual["replay_namespace"], expected.replay_namespace);
            assert_eq!(actual["uid"], expected.uid);
            assert_eq!(actual["gid"], expected.gid);
            assert_eq!(actual["agent_selinux_domain"], expected.agent_selinux_domain);
            assert_eq!(actual["runtime_adapter"], expected.runtime_adapter);
            assert!(actual.get("identity_key_sha256").is_none());
        }}
    }}

    #[test]
    fn stable_principal_matches_v1_descriptor_non_identity_fields() {{
        let stable = CODEX_STABLE_PRINCIPAL;
        let exact = crate::agent_descriptor_registry::CODEX;
        assert_eq!(stable.provider_id, exact.provider_id);
        assert_eq!(stable.agent_id, exact.agent_id);
        assert_eq!(stable.replay_namespace, exact.replay_namespace);
        assert_eq!(stable.uid, exact.uid);
        assert_eq!(stable.gid, exact.gid);
        assert_eq!(stable.agent_selinux_domain, exact.agent_selinux_domain);
        assert_eq!(stable.runtime_adapter, exact.runtime_adapter);
        assert_eq!(
            SYSTEM_API_ENDPOINT.tool_selinux_domain,
            crate::agent_descriptor_registry::SYSTEM_API_ENDPOINT.tool_selinux_domain
        );
        assert_eq!(
            SYSTEM_API_ENDPOINT.operation_replay_sync_selinux_domain,
            crate::agent_descriptor_registry::SYSTEM_API_ENDPOINT
                .operation_replay_sync_selinux_domain
        );
        assert_eq!(
            ACCESSIBILITY_ENDPOINT.tool_selinux_domain,
            crate::agent_descriptor_registry::ACCESSIBILITY_ENDPOINT.tool_selinux_domain
        );
        assert_eq!(
            ACCESSIBILITY_ENDPOINT.operation_replay_sync_selinux_domain,
            crate::agent_descriptor_registry::ACCESSIBILITY_ENDPOINT
                .operation_replay_sync_selinux_domain
        );
    }}

    #[test]
    fn generated_endpoint_domains_are_closed_disjoint_and_lookup_bound() {{
        assert_eq!(PRODUCT_ENDPOINT_ALLOWLIST.len(), 2);
        assert_eq!(
            endpoint_from_symbol("SYSTEM_API"),
            Some(&SYSTEM_API_ENDPOINT)
        );
        assert_eq!(
            endpoint_from_tool_selinux_domain(ACCESSIBILITY_ENDPOINT.tool_selinux_domain),
            Some(&ACCESSIBILITY_ENDPOINT)
        );
        assert_eq!(
            endpoint_from_operation_replay_sync_selinux_domain(
                SYSTEM_API_ENDPOINT.operation_replay_sync_selinux_domain
            ),
            Some(&SYSTEM_API_ENDPOINT)
        );
        assert_ne!(
            SYSTEM_API_ENDPOINT.tool_selinux_domain,
            SYSTEM_API_ENDPOINT.operation_replay_sync_selinux_domain
        );
        assert_ne!(
            SYSTEM_API_ENDPOINT.tool_selinux_domain,
            ACCESSIBILITY_ENDPOINT.tool_selinux_domain
        );
        assert_eq!(endpoint_from_symbol("MODEL_AUTHORED"), None);
    }}

    #[test]
    fn stable_principal_lookups_are_closed_and_pair_bound() {{
        assert_eq!(
            PRODUCT_ALLOWLIST,
            &[&CODEX_STABLE_PRINCIPAL]
        );
        assert_eq!(
            from_provider_id(CODEX_STABLE_PRINCIPAL.provider_id),
            Some(&CODEX_STABLE_PRINCIPAL)
        );
        assert_eq!(
            from_agent_id(CODEX_STABLE_PRINCIPAL.agent_id),
            Some(&CODEX_STABLE_PRINCIPAL)
        );
        assert_eq!(
            from_replay_namespace(CODEX_STABLE_PRINCIPAL.replay_namespace),
            Some(&CODEX_STABLE_PRINCIPAL)
        );
        assert_eq!(
            from_uid_gid(CODEX_STABLE_PRINCIPAL.uid, CODEX_STABLE_PRINCIPAL.gid),
            Some(&CODEX_STABLE_PRINCIPAL)
        );
        assert_eq!(
            from_provider_agent_pair(
                CODEX_STABLE_PRINCIPAL.provider_id,
                "agent-retired-v1"
            ),
            None
        );
        assert_eq!(from_provider_id("model-authored-provider"), None);
    }}

    #[test]
    fn registration_lookup_ignores_rotating_digest_and_dynamic_state_only() {{
        let mut registration = registration(&CODEX_STABLE_PRINCIPAL);
        assert_eq!(
            from_registration_fields(&registration),
            Some(&CODEX_STABLE_PRINCIPAL)
        );
        registration.identity_key_sha256 = "a".repeat(64);
        registration.enabled = true;
        registration.health = AgentHealth::Ready;
        assert_eq!(
            from_registration_fields(&registration),
            Some(&CODEX_STABLE_PRINCIPAL)
        );
        registration.peer_uid += 1;
        assert_eq!(from_registration_fields(&registration), None);
    }}

    #[test]
    fn canonical_operation_namespaces_match_the_stable_principals() {{
        let operation: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../trillionnium-agent-direct-tools/contracts/canonical-operation-binding-v1.json"
        ))
        .expect("canonical operation contract");
{namespace_assertions}
    }}
}}
'''


def semantic_rust(source: str) -> str:
    output: list[str] = []
    index = 0
    state = "normal"
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "normal":
            if char.isspace():
                index += 1
                continue
            if char == "/" and next_char == "/":
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
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
            if char == "*" and next_char == "/":
                state = "normal"
                index += 1
        else:
            output.append(char)
            if char == "\\" and next_char:
                output.append(next_char)
                index += 1
            elif state == "string" and char == '"':
                state = "normal"
        index += 1
    if state != "normal":
        raise SystemExit("generated Rust source ended inside a token")
    return "".join(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument(
        "--descriptor-contract",
        type=Path,
        default=DESCRIPTOR_CONTRACT,
    )
    parser.add_argument(
        "--canonical-operation-contract",
        type=Path,
        default=CANONICAL_OPERATION_CONTRACT,
    )
    parser.add_argument("--production-rust-root", type=Path, default=PRODUCTION_RUST_ROOT)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument(
        "--descriptor-registry-output",
        type=Path,
        default=DESCRIPTOR_REGISTRY_OUTPUT,
    )
    args = parser.parse_args()
    expected = render(
        args.contract,
        args.descriptor_contract,
        args.canonical_operation_contract,
        args.production_rust_root,
        args.output,
        args.descriptor_registry_output,
    )
    if args.check:
        if not args.output.exists() or semantic_rust(
            args.output.read_text(encoding="utf-8")
        ) != semantic_rust(expected):
            raise SystemExit(f"generated stable Agent principal registry is stale: {args.output}")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(expected, encoding="utf-8")


if __name__ == "__main__":
    main()
