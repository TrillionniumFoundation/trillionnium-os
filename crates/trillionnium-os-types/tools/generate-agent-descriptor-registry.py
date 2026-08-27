#!/usr/bin/env python3
"""Generate the Rust AgentDescriptor registry from its closed JSON contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "agent-descriptor-registry-v1.json"
CANONICAL_OPERATION_CONTRACT = (
    ROOT.parent
    / "trillionnium-agent-direct-tools/contracts/canonical-operation-binding-v1.json"
)
OUTPUT = ROOT / "src" / "agent_descriptor_registry.rs"
PRODUCTION_RUST_ROOT = ROOT.parents[1]
CONTRACT_SCHEMA = "org.trillionnium.agent-descriptor-registry.contract.v1"
REGISTRY_SCHEMA = "org.trillionnium.agent-descriptor-registry.v1"
DESCRIPTOR_SCHEMA = "org.trillionnium.agent-descriptor.v1"
TOP_LEVEL_FIELDS = {
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
DESCRIPTOR_FIELDS = {
    "symbol",
    "provider_id",
    "agent_id",
    "identity_key_sha256",
    "replay_namespace",
    "uid",
    "gid",
    "agent_selinux_domain",
    "runtime_adapter",
}
SYMBOL = re.compile(r"[A-Z][A-Z0-9_]*")
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
STABLE_ATOM = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
SELINUX_DOMAIN = re.compile(r"u:r:[a-z0-9_]+:s0")
REQUIRED_ENDPOINT_SYMBOLS = ("SYSTEM_API", "ACCESSIBILITY")
REQUIRED_DESCRIPTOR_SYMBOLS = ("CODEX",)


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


def load_and_validate(path: Path) -> tuple[dict, str, str, str]:
    raw = path.read_bytes()
    contract = load_strict_json(raw, "AgentDescriptor contract")
    if not isinstance(contract, dict):
        raise SystemExit("AgentDescriptor contract must be a JSON object")
    require_exact_fields(contract, TOP_LEVEL_FIELDS, "AgentDescriptor contract")
    if contract["contract_schema"] != CONTRACT_SCHEMA:
        raise SystemExit("unexpected AgentDescriptor contract schema")
    if contract["registry_schema"] != REGISTRY_SCHEMA:
        raise SystemExit("unexpected AgentDescriptor registry schema")
    if contract["descriptor_schema"] != DESCRIPTOR_SCHEMA:
        raise SystemExit("unexpected AgentDescriptor field schema")
    endpoints = contract["endpoints"]
    if not isinstance(endpoints, list) or len(endpoints) != len(REQUIRED_ENDPOINT_SYMBOLS):
        raise SystemExit("AgentDescriptor endpoint allowlist is not the closed product set")
    endpoint_domains: set[str] = set()
    for index, endpoint in enumerate(endpoints):
        if not isinstance(endpoint, dict):
            raise SystemExit(f"endpoint {index} must be a JSON object")
        require_exact_fields(endpoint, ENDPOINT_FIELDS, f"endpoint {index}")
        if endpoint["symbol"] != REQUIRED_ENDPOINT_SYMBOLS[index]:
            raise SystemExit(f"endpoint {index} is not the required product endpoint")
        for field in (
            "tool_selinux_domain",
            "operation_replay_sync_selinux_domain",
        ):
            domain = endpoint[field]
            if not isinstance(domain, str) or SELINUX_DOMAIN.fullmatch(domain) is None:
                raise SystemExit(f"endpoint {index} has an invalid {field}")
            if domain in endpoint_domains:
                raise SystemExit(f"endpoint {index} duplicates a SELinux domain")
            endpoint_domains.add(domain)
    descriptors = contract["descriptors"]
    if not isinstance(descriptors, list) or len(descriptors) != len(
        REQUIRED_DESCRIPTOR_SYMBOLS
    ):
        raise SystemExit("AgentDescriptor product allowlist is not the Codex-only set")

    unique_fields = {
        "symbol": set(),
        "provider_id": set(),
        "agent_id": set(),
        "identity_key_sha256": set(),
        "replay_namespace": set(),
        "uid": set(),
        "gid": set(),
        "agent_selinux_domain": set(),
    }
    for index, descriptor in enumerate(descriptors):
        if not isinstance(descriptor, dict):
            raise SystemExit(f"descriptor {index} must be a JSON object")
        require_exact_fields(descriptor, DESCRIPTOR_FIELDS, f"descriptor {index}")
        if descriptor["symbol"] != REQUIRED_DESCRIPTOR_SYMBOLS[index]:
            raise SystemExit(f"descriptor {index} is not the required Codex product descriptor")
        if SYMBOL.fullmatch(descriptor["symbol"]) is None:
            raise SystemExit(f"descriptor {index} has an invalid symbol")
        if STABLE_ATOM.fullmatch(descriptor["provider_id"]) is None:
            raise SystemExit(f"descriptor {index} has an invalid provider_id")
        if STABLE_ATOM.fullmatch(descriptor["agent_id"]) is None:
            raise SystemExit(f"descriptor {index} has an invalid agent_id")
        if not descriptor["agent_id"].startswith("agent-"):
            raise SystemExit(f"descriptor {index} agent_id is not OS-scoped")
        if LOWER_SHA256.fullmatch(descriptor["identity_key_sha256"]) is None:
            raise SystemExit(f"descriptor {index} has an invalid identity key digest")
        if descriptor["identity_key_sha256"] == "0" * 64:
            raise SystemExit(f"descriptor {index} has a zero identity key digest")
        if STABLE_ATOM.fullmatch(descriptor["replay_namespace"]) is None:
            raise SystemExit(f"descriptor {index} has an invalid replay namespace")
        if STABLE_ATOM.fullmatch(descriptor["runtime_adapter"]) is None:
            raise SystemExit(f"descriptor {index} has an invalid runtime adapter")
        if SELINUX_DOMAIN.fullmatch(descriptor["agent_selinux_domain"]) is None:
            raise SystemExit(f"descriptor {index} has an invalid SELinux domain")
        if descriptor["agent_selinux_domain"] in endpoint_domains:
            raise SystemExit(
                f"descriptor {index} aliases a tool or replay-control endpoint domain"
            )
        for numeric in ("uid", "gid"):
            value = descriptor[numeric]
            if type(value) is not int or value <= 0 or value > 0x7FFF_FFFF:
                raise SystemExit(f"descriptor {index} has an invalid {numeric}")
        for field, seen in unique_fields.items():
            if descriptor[field] in seen:
                raise SystemExit(f"descriptor {index} duplicates {field}")
            seen.add(descriptor[field])

    canonical_descriptors = []
    for descriptor in descriptors:
        canonical_descriptors.append(
            {
                "schema": contract["descriptor_schema"],
                "provider_id": descriptor["provider_id"],
                "agent_id": descriptor["agent_id"],
                "identity_key_sha256": descriptor["identity_key_sha256"],
                "replay_namespace": descriptor["replay_namespace"],
                "uid": descriptor["uid"],
                "gid": descriptor["gid"],
                "agent_selinux_domain": descriptor["agent_selinux_domain"],
                "runtime_adapter": descriptor["runtime_adapter"],
            }
        )
    canonical_json = json.dumps(
        {
            "schema": contract["registry_schema"],
            "descriptors": canonical_descriptors,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )
    contract_sha256 = hashlib.sha256(raw).hexdigest()
    canonical_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return contract, contract_sha256, canonical_json, canonical_sha256


def validate_no_production_identity_mirrors(
    contract: dict, source_root: Path, generated_output: Path
) -> None:
    identity_fields = (
        "provider_id",
        "agent_id",
        "identity_key_sha256",
        "replay_namespace",
        "agent_selinux_domain",
        "runtime_adapter",
    )
    identities = {
        descriptor[field]
        for descriptor in contract["descriptors"]
        for field in identity_fields
    }
    numeric_identities = {
        rendered
        for descriptor in contract["descriptors"]
        for field in ("uid", "gid")
        for rendered in (str(descriptor[field]), f"{descriptor[field]:_}")
    }
    violations: list[str] = []
    for path in source_root.rglob("*.rs"):
        if path.resolve() == generated_output.resolve() or "target" in path.relative_to(
            source_root
        ).parts:
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
            "production Rust mirrors generated AgentDescriptor identity:\n"
            + "\n".join(violations)
        )


def render(
    contract_path: Path,
    canonical_operation_contract: Path,
    production_rust_root: Path,
    output: Path,
) -> str:
    contract, contract_sha256, canonical_json, canonical_sha256 = load_and_validate(
        contract_path
    )
    validate_no_production_identity_mirrors(contract, production_rust_root, output)
    operation_contract = load_strict_json(
        canonical_operation_contract.read_bytes(),
        "canonical operation contract",
    )
    expected_namespaces = {
        descriptor["symbol"].lower(): descriptor["replay_namespace"]
        for descriptor in contract["descriptors"]
    }
    if operation_contract.get("agents") != expected_namespaces:
        raise SystemExit("canonical operation replay namespaces drifted from AgentDescriptor")
    endpoint_constants = []
    for endpoint in contract["endpoints"]:
        endpoint_constants.append(
            f'''pub const {endpoint['symbol']}_ENDPOINT: AgentEndpointDescriptor = AgentEndpointDescriptor {{
    symbol: {rust_string(endpoint['symbol'])},
    tool_selinux_domain: {rust_string(endpoint['tool_selinux_domain'])},
    operation_replay_sync_selinux_domain: {rust_string(endpoint['operation_replay_sync_selinux_domain'])},
}};'''
        )
    constants = []
    for descriptor in contract["descriptors"]:
        constants.append(
            f'''pub const {descriptor['symbol']}: AgentDescriptor = AgentDescriptor {{
    provider_id: {rust_string(descriptor['provider_id'])},
    agent_id: {rust_string(descriptor['agent_id'])},
    identity_key_sha256: {rust_string(descriptor['identity_key_sha256'])},
    replay_namespace: {rust_string(descriptor['replay_namespace'])},
    uid: {descriptor['uid']},
    gid: {descriptor['gid']},
    agent_selinux_domain: {rust_string(descriptor['agent_selinux_domain'])},
    runtime_adapter: {rust_string(descriptor['runtime_adapter'])},
}};'''
        )
    symbols = ", ".join("&" + descriptor["symbol"] for descriptor in contract["descriptors"])
    endpoint_symbols = ", ".join(
        "&" + endpoint["symbol"] + "_ENDPOINT" for endpoint in contract["endpoints"]
    )
    namespace_assertions = "\n".join(
        f'''        assert_eq!(operation["agents"][{rust_string(descriptor['symbol'].lower())}], {descriptor['symbol']}.replay_namespace);'''
        for descriptor in contract["descriptors"]
    )
    return f'''// @generated by tools/generate-agent-descriptor-registry.py; do not edit.

pub const CONTRACT_SCHEMA: &str = {rust_string(contract['contract_schema'])};
pub const CONTRACT_SHA256: &str = {rust_string(contract_sha256)};
pub const REGISTRY_SCHEMA: &str = {rust_string(contract['registry_schema'])};
pub const DESCRIPTOR_SCHEMA: &str = {rust_string(contract['descriptor_schema'])};
pub const CANONICAL_REGISTRY_JSON: &str = {rust_string(canonical_json)};
pub const CANONICAL_REGISTRY_SHA256: &str = {rust_string(canonical_sha256)};

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
pub struct AgentDescriptor {{
    pub provider_id: &'static str,
    pub agent_id: &'static str,
    pub identity_key_sha256: &'static str,
    pub replay_namespace: &'static str,
    pub uid: u32,
    pub gid: u32,
    pub agent_selinux_domain: &'static str,
    pub runtime_adapter: &'static str,
}}

impl AgentDescriptor {{
    pub fn matches_registration(&self, registration: &crate::AgentRegistration) -> bool {{
        registration.agent_id == self.agent_id
            && registration.adapter == self.runtime_adapter
            && registration.identity_key_sha256 == self.identity_key_sha256
            && registration.peer_uid == self.uid
            && registration.peer_gid == self.gid
            && registration.selinux_domain == self.agent_selinux_domain
    }}
}}

{chr(10).join(constants)}

pub const PRODUCT_ALLOWLIST: &[&AgentDescriptor] = &[{symbols}];

pub fn from_provider_id(provider_id: &str) -> Option<&'static AgentDescriptor> {{
    PRODUCT_ALLOWLIST
        .iter()
        .copied()
        .find(|descriptor| descriptor.provider_id == provider_id)
}}

pub fn from_agent_id(agent_id: &str) -> Option<&'static AgentDescriptor> {{
    PRODUCT_ALLOWLIST
        .iter()
        .copied()
        .find(|descriptor| descriptor.agent_id == agent_id)
}}

pub fn from_replay_namespace(replay_namespace: &str) -> Option<&'static AgentDescriptor> {{
    PRODUCT_ALLOWLIST
        .iter()
        .copied()
        .find(|descriptor| descriptor.replay_namespace == replay_namespace)
}}

pub fn from_provider_agent_pair(
    provider_id: &str,
    agent_id: &str,
) -> Option<&'static AgentDescriptor> {{
    from_provider_id(provider_id).filter(|descriptor| descriptor.agent_id == agent_id)
}}

pub fn from_uid_gid(uid: u32, gid: u32) -> Option<&'static AgentDescriptor> {{
    PRODUCT_ALLOWLIST
        .iter()
        .copied()
        .find(|descriptor| descriptor.uid == uid && descriptor.gid == gid)
}}

pub fn from_registration(
    registration: &crate::AgentRegistration,
) -> Option<&'static AgentDescriptor> {{
    from_agent_id(&registration.agent_id)
        .filter(|descriptor| descriptor.matches_registration(registration))
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn generated_contract_and_canonical_registry_hashes_are_exact() {{
        assert_eq!(
            crate::sha256_bytes(include_bytes!("../contracts/agent-descriptor-registry-v1.json")),
            CONTRACT_SHA256
        );
        assert_eq!(
            crate::sha256_bytes(CANONICAL_REGISTRY_JSON.as_bytes()),
            CANONICAL_REGISTRY_SHA256
        );
        assert_eq!(
            CANONICAL_REGISTRY_SHA256,
            {rust_string(canonical_sha256)}
        );
    }}

    #[test]
    fn generated_descriptors_match_the_canonical_registry() {{
        let registry: serde_json::Value =
            serde_json::from_str(CANONICAL_REGISTRY_JSON).expect("generated registry JSON");
        assert_eq!(registry["schema"], REGISTRY_SCHEMA);
        let descriptors = registry["descriptors"]
            .as_array()
            .expect("generated descriptor array");
        assert_eq!(descriptors.len(), PRODUCT_ALLOWLIST.len());
        for (actual, expected) in descriptors.iter().zip(PRODUCT_ALLOWLIST) {{
            let actual = actual.as_object().expect("generated descriptor object");
            assert_eq!(actual.len(), 9);
            assert_eq!(actual["schema"], DESCRIPTOR_SCHEMA);
            assert_eq!(actual["provider_id"], expected.provider_id);
            assert_eq!(actual["agent_id"], expected.agent_id);
            assert_eq!(actual["identity_key_sha256"], expected.identity_key_sha256);
            assert_eq!(actual["replay_namespace"], expected.replay_namespace);
            assert_eq!(actual["uid"], expected.uid);
            assert_eq!(actual["gid"], expected.gid);
            assert_eq!(actual["agent_selinux_domain"], expected.agent_selinux_domain);
            assert_eq!(actual["runtime_adapter"], expected.runtime_adapter);
        }}
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
    fn canonical_operation_namespaces_match_the_generated_descriptors() {{
        let operation: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../trillionnium-agent-direct-tools/contracts/canonical-operation-binding-v1.json"
        ))
        .expect("canonical operation contract");
{namespace_assertions}
    }}

    #[test]
    fn product_identity_lookups_are_closed_and_pair_bound() {{
        assert_eq!(PRODUCT_ALLOWLIST, &[&CODEX]);
        assert_eq!(from_provider_id(CODEX.provider_id), Some(&CODEX));
        assert_eq!(from_agent_id(CODEX.agent_id), Some(&CODEX));
        assert_eq!(
            from_replay_namespace(CODEX.replay_namespace),
            Some(&CODEX)
        );
        assert_eq!(from_uid_gid(CODEX.uid, CODEX.gid), Some(&CODEX));
        assert_eq!(
            from_provider_agent_pair(CODEX.provider_id, "agent-retired-v1"),
            None
        );
        assert_eq!(from_provider_id("model-authored-provider"), None);
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
        "--canonical-operation-contract",
        type=Path,
        default=CANONICAL_OPERATION_CONTRACT,
    )
    parser.add_argument("--production-rust-root", type=Path, default=PRODUCTION_RUST_ROOT)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    expected = render(
        args.contract,
        args.canonical_operation_contract,
        args.production_rust_root,
        args.output,
    )
    if args.check:
        if not args.output.exists() or semantic_rust(
            args.output.read_text(encoding="utf-8")
        ) != semantic_rust(expected):
            raise SystemExit(f"generated AgentDescriptor registry is stale: {args.output}")
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(expected, encoding="utf-8")


if __name__ == "__main__":
    main()
