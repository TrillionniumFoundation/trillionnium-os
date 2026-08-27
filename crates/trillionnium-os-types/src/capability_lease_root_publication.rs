use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_principal_registry;
use crate::capability_lease_root_registration::{self, CapabilityLeaseRootTaskRegistrationV1};

pub const CONTRACT_SCHEMA: &str = "org.trillionnium.capabilitylease.root-publication.contract.v1";
pub const CONTRACT_SHA256: &str =
    "2a23182e8778f51086ab66f93dd39a51b0fc56f5b5a62947e7fd340e736e1a74";
pub const TASK_PUBLICATION_SCHEMA: &str =
    "org.trillionnium.capabilitylease.root-task-publication.v1";
pub const TASK_PUBLICATION_ACK_SCHEMA: &str =
    "org.trillionnium.capabilitylease.root-task-publication-ack.v1";
pub const SOURCE_STATUS: &str = "source_only_no_listener_no_runtime_no_effect_authority_v1";
pub const PROTOCOL: &str = "trillionnium.capability-lease-root-publication.uds.v1";
pub const OPERATION: &str = "register_task";
pub const TRANSPORT_ROLE: &str = "system_api_replay_sync";
pub const TRANSPORT_SELINUX_DOMAIN: &str = "u:r:trillionnium_agent_system_api_replay_sync:s0";
pub const TRANSPORT_EXECUTABLE_IDENTITY: &str =
    "system_ext/bin/trillionnium-system-api-replay-sync";
pub const PUBLICATION_BINDING_DOMAIN: &str = "trillionnium.capability-lease-root-publication.v1";
pub const ACK_BINDING_DOMAIN: &str = "trillionnium.capability-lease-root-publication-ack.v1";
pub const MAXIMUM_PAYLOAD_BYTES: usize = 8192;
pub const LISTENER_AVAILABLE: bool = false;
pub const RUNTIME_CONSUMER_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

pub type CapabilityLeaseRootPublicationResult<T> = Result<T, CapabilityLeaseRootPublicationError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityLeaseRootPublicationError(&'static str);

impl CapabilityLeaseRootPublicationError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for CapabilityLeaseRootPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for CapabilityLeaseRootPublicationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeaseRootPublisherTransportPeerV1 {
    pub role: String,
    pub uid: u32,
    pub gid: u32,
    pub selinux_domain: String,
    pub executable_identity: String,
    pub executable_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeaseRootTaskPublicationV1 {
    pub schema: String,
    pub publication_contract_sha256: String,
    pub root_registration_contract_sha256: String,
    pub protocol: String,
    pub operation: String,
    pub transport_peer: CapabilityLeaseRootPublisherTransportPeerV1,
    pub registration: CapabilityLeaseRootTaskRegistrationV1,
    pub root_record_sha256: String,
    pub root_record_proof_sha256: String,
    pub publication_binding_sha256: String,
}

impl CapabilityLeaseRootTaskPublicationV1 {
    pub fn derive(
        transport_peer: CapabilityLeaseRootPublisherTransportPeerV1,
        registration: CapabilityLeaseRootTaskRegistrationV1,
        root_record_sha256: String,
        root_record_proof_sha256: String,
    ) -> CapabilityLeaseRootPublicationResult<Self> {
        let mut publication = Self {
            schema: TASK_PUBLICATION_SCHEMA.to_string(),
            publication_contract_sha256: CONTRACT_SHA256.to_string(),
            root_registration_contract_sha256: capability_lease_root_registration::CONTRACT_SHA256
                .to_string(),
            protocol: PROTOCOL.to_string(),
            operation: OPERATION.to_string(),
            transport_peer,
            registration,
            root_record_sha256,
            root_record_proof_sha256,
            publication_binding_sha256: String::new(),
        };
        publication.validate_preimage()?;
        publication.publication_binding_sha256 = publication.expected_binding_sha256()?;
        publication.validate()?;
        Ok(publication)
    }

    pub fn validate(&self) -> CapabilityLeaseRootPublicationResult<()> {
        self.validate_preimage()?;
        if !valid_digest(&self.publication_binding_sha256)
            || self.expected_binding_sha256()? != self.publication_binding_sha256
        {
            return Err(denied("capability_lease_root_publication_binding_denied"));
        }
        Ok(())
    }

    pub fn encode_frame(&self) -> CapabilityLeaseRootPublicationResult<Vec<u8>> {
        self.validate()?;
        encode_frame(self)
    }

    pub fn decode_frame(frame: &[u8]) -> CapabilityLeaseRootPublicationResult<Self> {
        let publication: Self = decode_frame(frame)?;
        publication.validate()?;
        Ok(publication)
    }

    fn validate_preimage(&self) -> CapabilityLeaseRootPublicationResult<()> {
        if self.schema != TASK_PUBLICATION_SCHEMA
            || self.publication_contract_sha256 != CONTRACT_SHA256
            || self.root_registration_contract_sha256
                != capability_lease_root_registration::CONTRACT_SHA256
            || self.protocol != PROTOCOL
            || self.operation != OPERATION
        {
            return Err(denied("capability_lease_root_publication_contract_denied"));
        }
        self.registration
            .validate()
            .map_err(|_| denied("capability_lease_root_publication_registration_denied"))?;
        let principal = agent_principal_registry::from_provider_agent_pair(
            &self.registration.provider_id,
            &self.registration.agent_id,
        )
        .ok_or_else(|| denied("capability_lease_root_publication_subject_denied"))?;
        if self.registration.replay_namespace != principal.replay_namespace
            || self.transport_peer.role != TRANSPORT_ROLE
            || self.transport_peer.uid != principal.uid
            || self.transport_peer.gid != principal.gid
            || self.transport_peer.selinux_domain != TRANSPORT_SELINUX_DOMAIN
            || self.transport_peer.executable_identity != TRANSPORT_EXECUTABLE_IDENTITY
            || !valid_digest(&self.transport_peer.executable_sha256)
        {
            return Err(denied("capability_lease_root_publication_transport_denied"));
        }
        if !valid_digest(&self.root_record_sha256) || !valid_digest(&self.root_record_proof_sha256)
        {
            return Err(denied("capability_lease_root_publication_record_denied"));
        }
        Ok(())
    }

    fn expected_binding_sha256(&self) -> CapabilityLeaseRootPublicationResult<String> {
        self.validate_preimage()?;
        let mut hasher = Sha256::new();
        hash_string(&mut hasher, "domain", PUBLICATION_BINDING_DOMAIN)?;
        hash_string(&mut hasher, "publication_schema", TASK_PUBLICATION_SCHEMA)?;
        hash_string(&mut hasher, "publication_contract_sha256", CONTRACT_SHA256)?;
        hash_string(
            &mut hasher,
            "root_registration_contract_sha256",
            capability_lease_root_registration::CONTRACT_SHA256,
        )?;
        hash_string(&mut hasher, "protocol", PROTOCOL)?;
        hash_string(&mut hasher, "operation", OPERATION)?;
        hash_string(&mut hasher, "provider_id", &self.registration.provider_id)?;
        hash_string(&mut hasher, "agent_id", &self.registration.agent_id)?;
        hash_string(
            &mut hasher,
            "replay_namespace",
            &self.registration.replay_namespace,
        )?;
        hash_u64(
            &mut hasher,
            "transport_peer_uid",
            self.transport_peer.uid.into(),
        )?;
        hash_u64(
            &mut hasher,
            "transport_peer_gid",
            self.transport_peer.gid.into(),
        )?;
        hash_string(
            &mut hasher,
            "transport_peer_selinux_domain",
            &self.transport_peer.selinux_domain,
        )?;
        hash_string(
            &mut hasher,
            "transport_executable_sha256",
            &self.transport_peer.executable_sha256,
        )?;
        hash_string(
            &mut hasher,
            "boot_id_sha256",
            &self.registration.boot_id_sha256,
        )?;
        hash_string(
            &mut hasher,
            "publisher_epoch",
            &self.registration.publisher_epoch,
        )?;
        hash_u64(
            &mut hasher,
            "publisher_sequence",
            self.registration.publisher_sequence,
        )?;
        hash_string(
            &mut hasher,
            "root_journal_genesis_sha256",
            &self.registration.root_journal_genesis_sha256,
        )?;
        hash_string(
            &mut hasher,
            "epoch_proof_sha256",
            &self.registration.epoch_proof_sha256,
        )?;
        hash_string(&mut hasher, "root_record_sha256", &self.root_record_sha256)?;
        hash_string(
            &mut hasher,
            "root_record_proof_sha256",
            &self.root_record_proof_sha256,
        )?;
        hash_string(
            &mut hasher,
            "registration_binding_sha256",
            &self.registration.registration_binding_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeaseRootTaskPublicationAckV1 {
    pub schema: String,
    pub publication_binding_sha256: String,
    pub registration_binding_sha256: String,
    pub token_record_sha256: String,
    pub publisher_epoch: String,
    pub publisher_sequence: u64,
    pub root_record_sha256: String,
    pub root_record_proof_sha256: String,
    pub ack_binding_sha256: String,
}

impl CapabilityLeaseRootTaskPublicationAckV1 {
    pub fn derive(
        publication: &CapabilityLeaseRootTaskPublicationV1,
        token_record_sha256: String,
    ) -> CapabilityLeaseRootPublicationResult<Self> {
        publication.validate()?;
        let mut ack = Self {
            schema: TASK_PUBLICATION_ACK_SCHEMA.to_string(),
            publication_binding_sha256: publication.publication_binding_sha256.clone(),
            registration_binding_sha256: publication
                .registration
                .registration_binding_sha256
                .clone(),
            token_record_sha256,
            publisher_epoch: publication.registration.publisher_epoch.clone(),
            publisher_sequence: publication.registration.publisher_sequence,
            root_record_sha256: publication.root_record_sha256.clone(),
            root_record_proof_sha256: publication.root_record_proof_sha256.clone(),
            ack_binding_sha256: String::new(),
        };
        ack.validate_preimage()?;
        ack.ack_binding_sha256 = ack.expected_binding_sha256()?;
        ack.validate()?;
        Ok(ack)
    }

    pub fn validate(&self) -> CapabilityLeaseRootPublicationResult<()> {
        self.validate_preimage()?;
        if !valid_digest(&self.ack_binding_sha256)
            || self.expected_binding_sha256()? != self.ack_binding_sha256
        {
            return Err(denied(
                "capability_lease_root_publication_ack_binding_denied",
            ));
        }
        Ok(())
    }

    pub fn encode_frame(&self) -> CapabilityLeaseRootPublicationResult<Vec<u8>> {
        self.validate()?;
        encode_frame(self)
    }

    pub fn decode_frame(frame: &[u8]) -> CapabilityLeaseRootPublicationResult<Self> {
        let ack: Self = decode_frame(frame)?;
        ack.validate()?;
        Ok(ack)
    }

    fn validate_preimage(&self) -> CapabilityLeaseRootPublicationResult<()> {
        if self.schema != TASK_PUBLICATION_ACK_SCHEMA
            || !valid_digest(&self.publication_binding_sha256)
            || !valid_digest(&self.registration_binding_sha256)
            || !valid_digest(&self.token_record_sha256)
            || !valid_epoch(&self.publisher_epoch)
            || self.publisher_sequence == 0
            || self.publisher_sequence > i64::MAX as u64
            || !valid_digest(&self.root_record_sha256)
            || !valid_digest(&self.root_record_proof_sha256)
        {
            return Err(denied("capability_lease_root_publication_ack_denied"));
        }
        Ok(())
    }

    fn expected_binding_sha256(&self) -> CapabilityLeaseRootPublicationResult<String> {
        self.validate_preimage()?;
        let mut hasher = Sha256::new();
        hash_string(&mut hasher, "domain", ACK_BINDING_DOMAIN)?;
        hash_string(
            &mut hasher,
            "publication_binding_sha256",
            &self.publication_binding_sha256,
        )?;
        hash_string(
            &mut hasher,
            "registration_binding_sha256",
            &self.registration_binding_sha256,
        )?;
        hash_string(
            &mut hasher,
            "token_record_sha256",
            &self.token_record_sha256,
        )?;
        hash_string(&mut hasher, "publisher_epoch", &self.publisher_epoch)?;
        hash_u64(&mut hasher, "publisher_sequence", self.publisher_sequence)?;
        hash_string(&mut hasher, "root_record_sha256", &self.root_record_sha256)?;
        hash_string(
            &mut hasher,
            "root_record_proof_sha256",
            &self.root_record_proof_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

fn encode_frame<T: Serialize>(value: &T) -> CapabilityLeaseRootPublicationResult<Vec<u8>> {
    let canonical_value = serde_json::to_value(value)
        .map_err(|_| denied("capability_lease_root_publication_json_denied"))?;
    let payload = serde_json::to_vec(&canonical_value)
        .map_err(|_| denied("capability_lease_root_publication_json_denied"))?;
    if payload.is_empty() || payload.len() > MAXIMUM_PAYLOAD_BYTES {
        return Err(denied("capability_lease_root_publication_frame_denied"));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| denied("capability_lease_root_publication_frame_denied"))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn decode_frame<T: DeserializeOwned + Serialize>(
    frame: &[u8],
) -> CapabilityLeaseRootPublicationResult<T> {
    if frame.len() < 5 {
        return Err(denied("capability_lease_root_publication_frame_denied"));
    }
    let length = u32::from_be_bytes(frame[..4].try_into().expect("fixed frame prefix")) as usize;
    if length == 0 || length > MAXIMUM_PAYLOAD_BYTES || frame.len() != length + 4 {
        return Err(denied("capability_lease_root_publication_frame_denied"));
    }
    let payload = &frame[4..];
    let value: T = serde_json::from_slice(payload)
        .map_err(|_| denied("capability_lease_root_publication_json_denied"))?;
    let canonical_value = serde_json::to_value(&value)
        .map_err(|_| denied("capability_lease_root_publication_json_denied"))?;
    let canonical = serde_json::to_vec(&canonical_value)
        .map_err(|_| denied("capability_lease_root_publication_json_denied"))?;
    if canonical != payload {
        return Err(denied("capability_lease_root_publication_json_denied"));
    }
    Ok(value)
}

fn hash_string(
    hasher: &mut Sha256,
    name: &str,
    value: &str,
) -> CapabilityLeaseRootPublicationResult<()> {
    hash_bytes(hasher, name, value.as_bytes())
}

fn hash_u64(
    hasher: &mut Sha256,
    name: &str,
    value: u64,
) -> CapabilityLeaseRootPublicationResult<()> {
    hash_bytes(hasher, name, &value.to_be_bytes())
}

fn hash_bytes(
    hasher: &mut Sha256,
    name: &str,
    value: &[u8],
) -> CapabilityLeaseRootPublicationResult<()> {
    let name_length = u32::try_from(name.len())
        .map_err(|_| denied("capability_lease_root_publication_binding_denied"))?;
    let value_length = u32::try_from(value.len())
        .map_err(|_| denied("capability_lease_root_publication_binding_denied"))?;
    hasher.update(name_length.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(value_length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    valid_nonzero_lower_hex(value, 64)
}

fn valid_epoch(value: &str) -> bool {
    valid_nonzero_lower_hex(value, 32)
}

fn valid_nonzero_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
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

const fn denied(code: &'static str) -> CapabilityLeaseRootPublicationError {
    CapabilityLeaseRootPublicationError(code)
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;
    use crate::agent_descriptor_registry::CODEX;
    use crate::capability_lease_root_registration::{
        CapabilityLeaseRootPublisherEvidenceV1, CapabilityLeaseRootTaskContextV1,
        CapabilityLeaseRootTaskRegistrationV1,
    };
    use crate::sha256_bytes;

    fn registration() -> CapabilityLeaseRootTaskRegistrationV1 {
        CapabilityLeaseRootTaskRegistrationV1::derive(
            CODEX.provider_id.to_string(),
            CODEX.agent_id.to_string(),
            CODEX.replay_namespace.to_string(),
            CapabilityLeaseRootPublisherEvidenceV1 {
                boot_id_sha256: "1".repeat(64),
                publisher_epoch: "8".repeat(32),
                publisher_sequence: 10,
                root_journal_genesis_sha256: "a".repeat(64),
                epoch_proof_sha256: "b".repeat(64),
            },
            CapabilityLeaseRootTaskContextV1 {
                opaque_task_context_token: format!("task-context-{}", "2".repeat(64)),
                prepare_request_id: "prepare-token-registry".to_string(),
                prepare_canonical_request_sha256: "9".repeat(64),
                workflow_id: format!("req-{}", "4".repeat(32)),
                task_id: "task.token-registry".to_string(),
                authenticated_task_binding_sha256: "5".repeat(64),
            },
            "6".repeat(64),
        )
        .unwrap()
    }

    fn publication() -> CapabilityLeaseRootTaskPublicationV1 {
        CapabilityLeaseRootTaskPublicationV1::derive(
            CapabilityLeaseRootPublisherTransportPeerV1 {
                role: TRANSPORT_ROLE.to_string(),
                uid: CODEX.uid,
                gid: CODEX.gid,
                selinux_domain: TRANSPORT_SELINUX_DOMAIN.to_string(),
                executable_identity: TRANSPORT_EXECUTABLE_IDENTITY.to_string(),
                executable_sha256: "c".repeat(64),
            },
            registration(),
            "d".repeat(64),
            "e".repeat(64),
        )
        .unwrap()
    }

    #[test]
    fn contract_hash_and_authority_are_closed() {
        assert_eq!(
            sha256_bytes(include_bytes!(
                "../contracts/capability-lease-root-publication-v1.json"
            )),
            CONTRACT_SHA256
        );
        assert!(!LISTENER_AVAILABLE);
        assert!(!RUNTIME_CONSUMER_AVAILABLE);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    }

    #[test]
    fn publication_and_ack_round_trip_canonical_frames() {
        let publication = publication();
        assert_eq!(
            publication.publication_binding_sha256,
            "ac58fc6425bc0989b97fa936787de7fa388a7e9bbb7e247001a3c75d5b6bae5e"
        );
        let frame = publication.encode_frame().unwrap();
        assert_eq!(
            CapabilityLeaseRootTaskPublicationV1::decode_frame(&frame).unwrap(),
            publication
        );
        let ack =
            CapabilityLeaseRootTaskPublicationAckV1::derive(&publication, "f".repeat(64)).unwrap();
        assert_eq!(
            ack.ack_binding_sha256,
            "e0768cd4c80f4fdc013f8e3b125388a038da5597f7c8173c7fbeab8a8463b304"
        );
        let ack_frame = ack.encode_frame().unwrap();
        assert_eq!(
            CapabilityLeaseRootTaskPublicationAckV1::decode_frame(&ack_frame).unwrap(),
            ack
        );
    }

    #[test]
    fn framing_and_transport_drift_fail_closed() {
        let publication = publication();
        let mut frame = publication.encode_frame().unwrap();
        frame.push(b' ');
        assert_eq!(
            CapabilityLeaseRootTaskPublicationV1::decode_frame(&frame)
                .unwrap_err()
                .code(),
            "capability_lease_root_publication_frame_denied"
        );

        let mut drifted = publication;
        drifted.transport_peer.selinux_domain = "u:r:trillionnium_codex_agent:s0".to_string();
        assert_eq!(
            drifted.validate().unwrap_err().code(),
            "capability_lease_root_publication_transport_denied"
        );
    }

    #[test]
    fn duplicate_or_noncanonical_json_fails_closed() {
        let publication = publication();
        let canonical = serde_json::to_string(&publication).unwrap();
        let duplicate =
            canonical.replacen("{\"schema\":", "{\"schema\":\"duplicate\",\"schema\":", 1);
        let mut frame = Vec::new();
        frame.extend_from_slice(&(duplicate.len() as u32).to_be_bytes());
        frame.extend_from_slice(duplicate.as_bytes());
        assert_eq!(
            CapabilityLeaseRootTaskPublicationV1::decode_frame(&frame)
                .unwrap_err()
                .code(),
            "capability_lease_root_publication_json_denied"
        );
    }
}
