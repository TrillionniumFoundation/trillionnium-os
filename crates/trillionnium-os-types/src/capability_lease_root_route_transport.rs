use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_descriptor_registry;

pub const CONTRACT_SCHEMA: &str =
    "org.trillionnium.capabilitylease.root-route-transport.contract.v1";
pub const CONTRACT_SHA256: &str =
    "176fc01d3a666fe98e2d9209a411a10fae030b69c480c7ef520dc7ca233a68ac";
pub const REQUEST_SCHEMA: &str = "org.trillionnium.capabilitylease.root-route-request.v1";
pub const RESPONSE_SCHEMA: &str = "org.trillionnium.capabilitylease.root-route-response.v1";
pub const PROTOCOL: &str = "trillionnium.capability-lease-root-route.uds.v1";
pub const OPERATION: &str = "run_root_publisher_once";
pub const REQUEST_BINDING_DOMAIN: &str = "trillionnium.capability-lease-root-route-request.v1";
pub const RESPONSE_BINDING_DOMAIN: &str = "trillionnium.capability-lease-root-route-response.v1";
pub const SOCKET_NAME: &str = "trillionnium_capability_lease_root_route";
pub const CLIENT_UID: u32 = 1000;
pub const CLIENT_GID: u32 = 1000;
pub const CLIENT_SELINUX_DOMAIN: &str = "u:r:system_server:s0";
pub const SERVER_UID: u32 = 0;
pub const SERVER_GID: u32 = 0;
pub const SERVER_SELINUX_DOMAIN: &str = "u:r:trillionnium_agentd:s0";
pub const MAXIMUM_PAYLOAD_BYTES: usize = 4096;
pub const PUBLIC_BROKER_PROTOCOL_EXTENDED: bool = false;
pub const PRIVATE_LISTENER_AVAILABLE: bool = false;
pub const PRIVATE_CONNECTOR_AVAILABLE: bool = false;
pub const BROKER_MAIN_ROUTE_WIRED: bool = false;
pub const COORDINATOR_ROUTE_ADAPTER_WIRED: bool = false;
pub const CONFERS_ACK_AUTHORITY: bool = false;
pub const CONFERS_LEASE_TRUST: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

pub type RootRouteTransportResult<T> = Result<T, RootRouteTransportError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootRouteTransportError(&'static str);

impl RootRouteTransportError {
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for RootRouteTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for RootRouteTransportError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeaseRootRouteRequestV1 {
    pub agent_id: String,
    pub boot_id_sha256: String,
    pub contract_sha256: String,
    pub operation: String,
    pub protocol: String,
    pub provider_id: String,
    pub registration_binding_sha256: String,
    pub replay_namespace: String,
    pub request_binding_sha256: String,
    pub schema: String,
}

impl CapabilityLeaseRootRouteRequestV1 {
    pub fn derive(
        provider_id: String,
        agent_id: String,
        replay_namespace: String,
        boot_id_sha256: String,
        registration_binding_sha256: String,
    ) -> RootRouteTransportResult<Self> {
        let mut request = Self {
            agent_id,
            boot_id_sha256,
            contract_sha256: CONTRACT_SHA256.to_string(),
            operation: OPERATION.to_string(),
            protocol: PROTOCOL.to_string(),
            provider_id,
            registration_binding_sha256,
            replay_namespace,
            request_binding_sha256: String::new(),
            schema: REQUEST_SCHEMA.to_string(),
        };
        request.request_binding_sha256 = request.expected_binding()?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> RootRouteTransportResult<()> {
        let descriptor =
            agent_descriptor_registry::from_provider_agent_pair(&self.provider_id, &self.agent_id)
                .filter(|descriptor| descriptor.replay_namespace == self.replay_namespace)
                .ok_or_else(|| denied("capability_lease_root_route_request_identity_denied"))?;
        if descriptor.provider_id != self.provider_id
            || self.schema != REQUEST_SCHEMA
            || self.contract_sha256 != CONTRACT_SHA256
            || self.protocol != PROTOCOL
            || self.operation != OPERATION
            || !valid_digest(&self.boot_id_sha256)
            || !valid_digest(&self.registration_binding_sha256)
            || !valid_digest(&self.request_binding_sha256)
            || self.expected_binding()? != self.request_binding_sha256
        {
            return Err(denied("capability_lease_root_route_request_denied"));
        }
        Ok(())
    }

    pub fn encode_frame(&self) -> RootRouteTransportResult<Vec<u8>> {
        encode_frame(self, "capability_lease_root_route_request_frame_denied")
    }

    pub fn decode_frame(frame: &[u8]) -> RootRouteTransportResult<Self> {
        let request: Self =
            decode_frame(frame, "capability_lease_root_route_request_frame_denied")?;
        request.validate()?;
        Ok(request)
    }

    fn expected_binding(&self) -> RootRouteTransportResult<String> {
        let mut hasher = Sha256::new();
        hash_string(&mut hasher, "domain", REQUEST_BINDING_DOMAIN)?;
        hash_string(&mut hasher, "schema", &self.schema)?;
        hash_string(&mut hasher, "contract_sha256", &self.contract_sha256)?;
        hash_string(&mut hasher, "protocol", &self.protocol)?;
        hash_string(&mut hasher, "operation", &self.operation)?;
        hash_u64(&mut hasher, "client_uid", CLIENT_UID.into())?;
        hash_u64(&mut hasher, "client_gid", CLIENT_GID.into())?;
        hash_string(&mut hasher, "client_selinux_domain", CLIENT_SELINUX_DOMAIN)?;
        hash_u64(&mut hasher, "server_uid", SERVER_UID.into())?;
        hash_u64(&mut hasher, "server_gid", SERVER_GID.into())?;
        hash_string(&mut hasher, "server_selinux_domain", SERVER_SELINUX_DOMAIN)?;
        hash_string(&mut hasher, "provider_id", &self.provider_id)?;
        hash_string(&mut hasher, "agent_id", &self.agent_id)?;
        hash_string(&mut hasher, "replay_namespace", &self.replay_namespace)?;
        hash_string(&mut hasher, "boot_id_sha256", &self.boot_id_sha256)?;
        hash_string(
            &mut hasher,
            "registration_binding_sha256",
            &self.registration_binding_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityLeaseRootRouteCompletionV1 {
    pub publication_binding_sha256: String,
    pub registration_binding_sha256: String,
    pub token_record_sha256: String,
    pub root_record_sha256: String,
    pub root_record_proof_sha256: String,
    pub ack_binding_sha256: String,
    pub authentication_binding_sha256: String,
}

impl CapabilityLeaseRootRouteCompletionV1 {
    pub fn validate(&self) -> RootRouteTransportResult<()> {
        if [
            &self.publication_binding_sha256,
            &self.registration_binding_sha256,
            &self.token_record_sha256,
            &self.root_record_sha256,
            &self.root_record_proof_sha256,
            &self.ack_binding_sha256,
            &self.authentication_binding_sha256,
        ]
        .into_iter()
        .all(|value| valid_digest(value))
        {
            Ok(())
        } else {
            Err(denied("capability_lease_root_route_completion_denied"))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeaseRootRouteResponseV1 {
    pub ack_binding_sha256: String,
    pub authentication_binding_sha256: String,
    pub contract_sha256: String,
    pub operation: String,
    pub protocol: String,
    pub publication_binding_sha256: String,
    pub registration_binding_sha256: String,
    pub request_binding_sha256: String,
    pub response_binding_sha256: String,
    pub root_record_proof_sha256: String,
    pub root_record_sha256: String,
    pub schema: String,
    pub token_record_sha256: String,
}

impl CapabilityLeaseRootRouteResponseV1 {
    pub fn derive(
        request: &CapabilityLeaseRootRouteRequestV1,
        completion: CapabilityLeaseRootRouteCompletionV1,
    ) -> RootRouteTransportResult<Self> {
        request.validate()?;
        completion.validate()?;
        if completion.registration_binding_sha256 != request.registration_binding_sha256 {
            return Err(denied(
                "capability_lease_root_route_response_registration_denied",
            ));
        }
        let mut response = Self {
            ack_binding_sha256: completion.ack_binding_sha256,
            authentication_binding_sha256: completion.authentication_binding_sha256,
            contract_sha256: CONTRACT_SHA256.to_string(),
            operation: OPERATION.to_string(),
            protocol: PROTOCOL.to_string(),
            publication_binding_sha256: completion.publication_binding_sha256,
            registration_binding_sha256: completion.registration_binding_sha256,
            request_binding_sha256: request.request_binding_sha256.clone(),
            response_binding_sha256: String::new(),
            root_record_proof_sha256: completion.root_record_proof_sha256,
            root_record_sha256: completion.root_record_sha256,
            schema: RESPONSE_SCHEMA.to_string(),
            token_record_sha256: completion.token_record_sha256,
        };
        response.response_binding_sha256 = response.expected_binding()?;
        response.validate_for(request)?;
        Ok(response)
    }

    pub fn validate_for(
        &self,
        request: &CapabilityLeaseRootRouteRequestV1,
    ) -> RootRouteTransportResult<()> {
        request.validate()?;
        if self.schema != RESPONSE_SCHEMA
            || self.contract_sha256 != CONTRACT_SHA256
            || self.protocol != PROTOCOL
            || self.operation != OPERATION
            || self.request_binding_sha256 != request.request_binding_sha256
            || self.registration_binding_sha256 != request.registration_binding_sha256
            || ![
                &self.publication_binding_sha256,
                &self.registration_binding_sha256,
                &self.token_record_sha256,
                &self.root_record_sha256,
                &self.root_record_proof_sha256,
                &self.ack_binding_sha256,
                &self.authentication_binding_sha256,
                &self.request_binding_sha256,
                &self.response_binding_sha256,
            ]
            .into_iter()
            .all(|value| valid_digest(value))
            || self.expected_binding()? != self.response_binding_sha256
        {
            return Err(denied("capability_lease_root_route_response_denied"));
        }
        Ok(())
    }

    pub fn encode_frame(&self) -> RootRouteTransportResult<Vec<u8>> {
        encode_frame(self, "capability_lease_root_route_response_frame_denied")
    }

    pub fn decode_frame_for(
        frame: &[u8],
        request: &CapabilityLeaseRootRouteRequestV1,
    ) -> RootRouteTransportResult<Self> {
        let response: Self =
            decode_frame(frame, "capability_lease_root_route_response_frame_denied")?;
        response.validate_for(request)?;
        Ok(response)
    }

    fn expected_binding(&self) -> RootRouteTransportResult<String> {
        let mut hasher = Sha256::new();
        hash_string(&mut hasher, "domain", RESPONSE_BINDING_DOMAIN)?;
        hash_string(&mut hasher, "schema", &self.schema)?;
        hash_string(&mut hasher, "contract_sha256", &self.contract_sha256)?;
        hash_string(&mut hasher, "protocol", &self.protocol)?;
        hash_string(&mut hasher, "operation", &self.operation)?;
        for (name, value) in [
            ("request_binding_sha256", &self.request_binding_sha256),
            (
                "publication_binding_sha256",
                &self.publication_binding_sha256,
            ),
            (
                "registration_binding_sha256",
                &self.registration_binding_sha256,
            ),
            ("token_record_sha256", &self.token_record_sha256),
            ("root_record_sha256", &self.root_record_sha256),
            ("root_record_proof_sha256", &self.root_record_proof_sha256),
            ("ack_binding_sha256", &self.ack_binding_sha256),
            (
                "authentication_binding_sha256",
                &self.authentication_binding_sha256,
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }
}

fn encode_frame<T: Serialize>(
    value: &T,
    denial: &'static str,
) -> RootRouteTransportResult<Vec<u8>> {
    let payload = serde_json::to_vec(value).map_err(|_| denied(denial))?;
    if payload.is_empty() || payload.len() > MAXIMUM_PAYLOAD_BYTES {
        return Err(denied(denial));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn decode_frame<T: for<'de> Deserialize<'de> + Serialize>(
    frame: &[u8],
    denial: &'static str,
) -> RootRouteTransportResult<T> {
    if frame.len() < 5 {
        return Err(denied(denial));
    }
    let length = u32::from_be_bytes(frame[..4].try_into().expect("fixed prefix")) as usize;
    if length == 0 || length > MAXIMUM_PAYLOAD_BYTES || frame.len() != length + 4 {
        return Err(denied(denial));
    }
    let value = serde_json::from_slice(&frame[4..]).map_err(|_| denied(denial))?;
    if serde_json::to_vec(&value).map_err(|_| denied(denial))? != frame[4..] {
        return Err(denied(denial));
    }
    Ok(value)
}

fn hash_string(hasher: &mut Sha256, name: &str, value: &str) -> RootRouteTransportResult<()> {
    let name_length = u32::try_from(name.len())
        .map_err(|_| denied("capability_lease_root_route_binding_denied"))?;
    let value_length = u32::try_from(value.len())
        .map_err(|_| denied("capability_lease_root_route_binding_denied"))?;
    hasher.update(name_length.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(value_length.to_be_bytes());
    hasher.update(value.as_bytes());
    Ok(())
}

fn hash_u64(hasher: &mut Sha256, name: &str, value: u64) -> RootRouteTransportResult<()> {
    let name_length = u32::try_from(name.len())
        .map_err(|_| denied("capability_lease_root_route_binding_denied"))?;
    hasher.update(name_length.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(8_u32.to_be_bytes());
    hasher.update(value.to_be_bytes());
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !value.bytes().all(|byte| byte == b'0')
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const fn denied(code: &'static str) -> RootRouteTransportError {
    RootRouteTransportError(code)
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    fn request() -> CapabilityLeaseRootRouteRequestV1 {
        CapabilityLeaseRootRouteRequestV1::derive(
            "openai-codex".to_string(),
            "agent-codex-direct-v1".to_string(),
            "agent-codex-v1".to_string(),
            "1".repeat(64),
            "2".repeat(64),
        )
        .unwrap()
    }

    fn completion() -> CapabilityLeaseRootRouteCompletionV1 {
        CapabilityLeaseRootRouteCompletionV1 {
            publication_binding_sha256: "3".repeat(64),
            registration_binding_sha256: "2".repeat(64),
            token_record_sha256: "4".repeat(64),
            root_record_sha256: "5".repeat(64),
            root_record_proof_sha256: "6".repeat(64),
            ack_binding_sha256: "7".repeat(64),
            authentication_binding_sha256: "8".repeat(64),
        }
    }

    #[test]
    fn request_and_response_round_trip_canonical_frames() {
        let request = request();
        assert_eq!(
            request.request_binding_sha256,
            "f083a31c618555ab14298b9ec11b8f2d25d0af310a368a230c3d9d87f036ee73"
        );
        assert_eq!(
            CapabilityLeaseRootRouteRequestV1::decode_frame(&request.encode_frame().unwrap())
                .unwrap(),
            request
        );
        let response = CapabilityLeaseRootRouteResponseV1::derive(&request, completion()).unwrap();
        assert_eq!(
            response.response_binding_sha256,
            "88022a64a733e543fd389e9c666a497916d13012073359a620d0a70e362748a8"
        );
        assert_eq!(
            CapabilityLeaseRootRouteResponseV1::decode_frame_for(
                &response.encode_frame().unwrap(),
                &request,
            )
            .unwrap(),
            response
        );
    }

    #[test]
    fn duplicate_trailing_identity_and_commitment_drift_fail_closed() {
        let request = request();
        let duplicate = format!(
            "{{\"agent_id\":\"{}\",\"agent_id\":\"{}\"}}",
            request.agent_id, request.agent_id
        );
        let mut duplicate_frame = (duplicate.len() as u32).to_be_bytes().to_vec();
        duplicate_frame.extend_from_slice(duplicate.as_bytes());
        assert!(CapabilityLeaseRootRouteRequestV1::decode_frame(&duplicate_frame).is_err());
        let mut trailing = request.encode_frame().unwrap();
        trailing.push(0);
        assert!(CapabilityLeaseRootRouteRequestV1::decode_frame(&trailing).is_err());
        let mut wrong_identity = request.clone();
        wrong_identity.replay_namespace = "unregistered-replay-namespace".to_string();
        assert!(wrong_identity.validate().is_err());
        let mut wrong_response =
            CapabilityLeaseRootRouteResponseV1::derive(&request, completion()).unwrap();
        wrong_response.ack_binding_sha256 = "9".repeat(64);
        assert!(wrong_response.validate_for(&request).is_err());
    }

    #[test]
    fn contract_hash_and_all_authority_flags_are_closed() {
        assert_eq!(
            crate::sha256_bytes(include_bytes!(
                "../contracts/capability-lease-root-route-transport-v1.json"
            )),
            CONTRACT_SHA256
        );
        assert!(!PUBLIC_BROKER_PROTOCOL_EXTENDED);
        assert!(!PRIVATE_LISTENER_AVAILABLE);
        assert!(!PRIVATE_CONNECTOR_AVAILABLE);
        assert!(!BROKER_MAIN_ROUTE_WIRED);
        assert!(!COORDINATOR_ROUTE_ADAPTER_WIRED);
        assert!(!CONFERS_ACK_AUTHORITY);
        assert!(!CONFERS_LEASE_TRUST);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    }
}
