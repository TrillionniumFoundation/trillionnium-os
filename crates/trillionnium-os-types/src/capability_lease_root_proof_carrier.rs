use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capability_lease_root_authenticator::CapabilityLeaseRootPublisherAuthenticationV1;

pub const CONTRACT_SCHEMA: &str = "org.trillionnium.capabilitylease.root-proof-carrier.contract.v1";
pub const CONTRACT_SHA256: &str =
    "30dd53fc52e139dee108d6eb51ea5958e8c43a7fb45f496b47f145b0f68d2a35";
pub const DELIVERY_SCHEMA: &str = "org.trillionnium.capabilitylease.root-proof-delivery.v1";
pub const PROTOCOL: &str = "trillionnium.capability-lease-root-proof.uds.v1";
pub const OPERATION: &str = "deliver_root_publisher_authentication";
pub const BINDING_DOMAIN: &str = "trillionnium.capability-lease-root-proof-delivery.v1";
pub const SOCKET_NAME: &str = "trillionnium_capability_lease_root_proof";
pub const BROKER_UID: u32 = 0;
pub const BROKER_GID: u32 = 0;
pub const BROKER_SELINUX_DOMAIN: &str = "u:r:trillionnium_agentd:s0";
pub const SERVER_UID: u32 = 1000;
pub const SERVER_GID: u32 = 1000;
pub const SERVER_SELINUX_DOMAIN: &str = "u:r:system_server:s0";
pub const MAXIMUM_PAYLOAD_BYTES: usize = 8192;
pub const BROKER_PUBLISHER_WIRED: bool = false;
pub const LISTENER_WIRED: bool = false;
pub const RUNTIME_CONSUMER_AVAILABLE: bool = false;
pub const CONFERS_ACK_AUTHORITY: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

pub type ProofCarrierResult<T> = Result<T, ProofCarrierError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProofCarrierError(&'static str);

impl ProofCarrierError {
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ProofCarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for ProofCarrierError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeaseRootProofDeliveryV1 {
    pub schema: String,
    pub contract_sha256: String,
    pub protocol: String,
    pub operation: String,
    pub broker_uid: u32,
    pub broker_gid: u32,
    pub broker_selinux_domain: String,
    pub server_uid: u32,
    pub server_gid: u32,
    pub server_selinux_domain: String,
    pub authentication: CapabilityLeaseRootPublisherAuthenticationV1,
    pub delivery_binding_sha256: String,
}

impl CapabilityLeaseRootProofDeliveryV1 {
    pub fn derive(
        authentication: CapabilityLeaseRootPublisherAuthenticationV1,
    ) -> ProofCarrierResult<Self> {
        authentication
            .validate_closed()
            .map_err(|_| denied("capability_lease_root_proof_authentication_denied"))?;
        let mut delivery = Self {
            schema: DELIVERY_SCHEMA.to_string(),
            contract_sha256: CONTRACT_SHA256.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: OPERATION.to_string(),
            broker_uid: BROKER_UID,
            broker_gid: BROKER_GID,
            broker_selinux_domain: BROKER_SELINUX_DOMAIN.to_string(),
            server_uid: SERVER_UID,
            server_gid: SERVER_GID,
            server_selinux_domain: SERVER_SELINUX_DOMAIN.to_string(),
            authentication,
            delivery_binding_sha256: String::new(),
        };
        delivery.delivery_binding_sha256 = delivery.expected_binding()?;
        delivery.validate()?;
        Ok(delivery)
    }

    pub fn validate(&self) -> ProofCarrierResult<()> {
        self.authentication
            .validate_closed()
            .map_err(|_| denied("capability_lease_root_proof_authentication_denied"))?;
        if self.schema != DELIVERY_SCHEMA
            || self.contract_sha256 != CONTRACT_SHA256
            || self.protocol != PROTOCOL
            || self.operation != OPERATION
            || self.broker_uid != BROKER_UID
            || self.broker_gid != BROKER_GID
            || self.broker_selinux_domain != BROKER_SELINUX_DOMAIN
            || self.server_uid != SERVER_UID
            || self.server_gid != SERVER_GID
            || self.server_selinux_domain != SERVER_SELINUX_DOMAIN
            || !valid_digest(&self.delivery_binding_sha256)
            || self.expected_binding()? != self.delivery_binding_sha256
        {
            return Err(denied("capability_lease_root_proof_delivery_denied"));
        }
        Ok(())
    }

    pub fn encode_frame(&self) -> ProofCarrierResult<Vec<u8>> {
        self.validate()?;
        let payload = serde_json::to_vec(self)
            .map_err(|_| denied("capability_lease_root_proof_json_denied"))?;
        if payload.is_empty() || payload.len() > MAXIMUM_PAYLOAD_BYTES {
            return Err(denied("capability_lease_root_proof_frame_denied"));
        }
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    pub fn decode_frame(frame: &[u8]) -> ProofCarrierResult<Self> {
        if frame.len() < 5 {
            return Err(denied("capability_lease_root_proof_frame_denied"));
        }
        let length = u32::from_be_bytes(frame[..4].try_into().expect("fixed prefix")) as usize;
        if length == 0 || length > MAXIMUM_PAYLOAD_BYTES || frame.len() != length + 4 {
            return Err(denied("capability_lease_root_proof_frame_denied"));
        }
        let delivery: Self = serde_json::from_slice(&frame[4..])
            .map_err(|_| denied("capability_lease_root_proof_json_denied"))?;
        let canonical = serde_json::to_vec(&delivery)
            .map_err(|_| denied("capability_lease_root_proof_json_denied"))?;
        if canonical != frame[4..] {
            return Err(denied("capability_lease_root_proof_json_denied"));
        }
        delivery.validate()?;
        Ok(delivery)
    }

    fn expected_binding(&self) -> ProofCarrierResult<String> {
        let mut hasher = Sha256::new();
        hash_string(&mut hasher, "domain", BINDING_DOMAIN)?;
        hash_string(&mut hasher, "schema", &self.schema)?;
        hash_string(&mut hasher, "contract_sha256", &self.contract_sha256)?;
        hash_string(&mut hasher, "protocol", &self.protocol)?;
        hash_string(&mut hasher, "operation", &self.operation)?;
        hash_u64(&mut hasher, "broker_uid", self.broker_uid.into())?;
        hash_u64(&mut hasher, "broker_gid", self.broker_gid.into())?;
        hash_string(
            &mut hasher,
            "broker_selinux_domain",
            &self.broker_selinux_domain,
        )?;
        hash_u64(&mut hasher, "server_uid", self.server_uid.into())?;
        hash_u64(&mut hasher, "server_gid", self.server_gid.into())?;
        hash_string(
            &mut hasher,
            "server_selinux_domain",
            &self.server_selinux_domain,
        )?;
        hash_string(
            &mut hasher,
            "authentication_binding_sha256",
            &self.authentication.authentication_binding_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

fn hash_string(hasher: &mut Sha256, name: &str, value: &str) -> ProofCarrierResult<()> {
    hash_bytes(hasher, name, value.as_bytes())
}

fn hash_u64(hasher: &mut Sha256, name: &str, value: u64) -> ProofCarrierResult<()> {
    hash_bytes(hasher, name, &value.to_be_bytes())
}

fn hash_bytes(hasher: &mut Sha256, name: &str, value: &[u8]) -> ProofCarrierResult<()> {
    let name_length = u32::try_from(name.len())
        .map_err(|_| denied("capability_lease_root_proof_binding_denied"))?;
    let value_length = u32::try_from(value.len())
        .map_err(|_| denied("capability_lease_root_proof_binding_denied"))?;
    hasher.update(name_length.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(value_length.to_be_bytes());
    hasher.update(value);
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

const fn denied(code: &'static str) -> ProofCarrierError {
    ProofCarrierError(code)
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;
    use crate::capability_lease_root_authenticator;

    fn authentication() -> CapabilityLeaseRootPublisherAuthenticationV1 {
        CapabilityLeaseRootPublisherAuthenticationV1 {
            authentication_schema: capability_lease_root_authenticator::AUTHENTICATION_SCHEMA
                .to_string(),
            root_authenticator_contract_sha256:
                capability_lease_root_authenticator::CONTRACT_SHA256.to_string(),
            root_publication_contract_sha256:
                crate::capability_lease_root_publication::CONTRACT_SHA256.to_string(),
            root_publisher_launch_contract_sha256:
                crate::capability_lease_root_publisher_launch::CONTRACT_SHA256.to_string(),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            replay_namespace: "agent-codex-v1".to_string(),
            boot_id_sha256: "1".repeat(64),
            publisher_pid: 42,
            publisher_start_time_ticks: 99,
            publisher_uid: 5901,
            publisher_gid: 5901,
            publisher_selinux_domain:
                crate::capability_lease_root_publisher_launch::PUBLISHER_SELINUX_DOMAIN.to_string(),
            publisher_executable_identity:
                crate::capability_lease_root_publisher_launch::PUBLISHER_EXECUTABLE_IDENTITY
                    .to_string(),
            publisher_executable_sha256: "7".repeat(64),
            pidfd_identity_sha256: "a".repeat(64),
            publication_binding_sha256:
                "14aa78a5bd303ca3cda70906298062a7ad4963005398ca456673899f2294a10d".to_string(),
            registration_binding_sha256:
                "ac4ff17cb0f22710e90a0d34f5caae7805582162a50ad2ca3c7dc15797f31603".to_string(),
            publisher_epoch: "e".repeat(32),
            publisher_sequence: 1,
            root_journal_genesis_sha256: "2".repeat(64),
            epoch_proof_sha256: "3".repeat(64),
            root_record_sha256: "8".repeat(64),
            root_record_proof_sha256: "9".repeat(64),
            authentication_binding_sha256:
                "b6cb97987f06f48d4f0f53af2ae2957213bf7272119ddce6075236aa11d0c65b".to_string(),
        }
    }

    #[test]
    fn exact_delivery_round_trips_one_canonical_frame() {
        let delivery = CapabilityLeaseRootProofDeliveryV1::derive(authentication()).unwrap();
        let frame = delivery.encode_frame().unwrap();
        assert_eq!(
            CapabilityLeaseRootProofDeliveryV1::decode_frame(&frame).unwrap(),
            delivery
        );
    }

    #[test]
    fn trailing_duplicate_and_identity_drift_fail_closed() {
        let delivery = CapabilityLeaseRootProofDeliveryV1::derive(authentication()).unwrap();
        let mut trailing = delivery.encode_frame().unwrap();
        trailing.push(0);
        assert!(CapabilityLeaseRootProofDeliveryV1::decode_frame(&trailing).is_err());
        let mut drifted = delivery.clone();
        drifted.server_uid += 1;
        assert!(drifted.validate().is_err());
        let duplicate = format!(
            "{{\"schema\":\"{}\",\"schema\":\"{}\"}}",
            DELIVERY_SCHEMA, DELIVERY_SCHEMA
        );
        let mut frame = (duplicate.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(duplicate.as_bytes());
        assert!(CapabilityLeaseRootProofDeliveryV1::decode_frame(&frame).is_err());
    }

    #[test]
    fn contract_hash_and_authority_are_closed() {
        assert_eq!(
            crate::sha256_bytes(include_bytes!(
                "../contracts/capability-lease-root-proof-carrier-v1.json"
            )),
            CONTRACT_SHA256
        );
        assert!(!BROKER_PUBLISHER_WIRED);
        assert!(!LISTENER_WIRED);
        assert!(!RUNTIME_CONSUMER_AVAILABLE);
        assert!(!CONFERS_ACK_AUTHORITY);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    }
}
