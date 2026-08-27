use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capability_lease_root_publication::{self, CapabilityLeaseRootTaskPublicationV1};
use crate::capability_lease_root_publisher_launch;

pub const CONTRACT_SCHEMA: &str = "org.trillionnium.capabilitylease.root-authenticator.contract.v1";
pub const CONTRACT_SHA256: &str =
    "eadb86b31c7927c5b16cda4d94553db8cc534584fa30b05c76338e69e26630c3";
pub const AUTHENTICATION_SCHEMA: &str =
    "org.trillionnium.capabilitylease.root-publisher-authentication.v1";
pub const AUTHENTICATION_BINDING_DOMAIN: &str =
    "trillionnium.capability-lease-root-publisher-authentication.v1";
pub const SOURCE_STATUS: &str = "source_only_no_live_authority_no_product_constructor_v1";
pub const LINUX_KERNEL_BACKEND_AVAILABLE: bool = false;
pub const BROKER_ROUTE_AVAILABLE: bool = false;
pub const PRODUCT_CONSTRUCTOR_AVAILABLE: bool = false;
pub const LISTENER_WIRED: bool = false;
pub const RUNTIME_CONSUMER_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

pub type RootAuthenticatorResult<T> = Result<T, RootAuthenticatorError>;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RootAuthenticatorError(&'static str);

impl RootAuthenticatorError {
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for RootAuthenticatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for RootAuthenticatorError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherKernelIdentityV1 {
    pub pid: u32,
    pub start_time_ticks: u64,
    pub uid: u32,
    pub gid: u32,
    pub selinux_domain: String,
    pub executable_identity: String,
    pub executable_sha256: String,
    pub pidfd_identity_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeaseRootPublisherAuthenticationV1 {
    pub authentication_schema: String,
    pub root_authenticator_contract_sha256: String,
    pub root_publication_contract_sha256: String,
    pub root_publisher_launch_contract_sha256: String,
    pub provider_id: String,
    pub agent_id: String,
    pub replay_namespace: String,
    pub boot_id_sha256: String,
    pub publisher_pid: u32,
    pub publisher_start_time_ticks: u64,
    pub publisher_uid: u32,
    pub publisher_gid: u32,
    pub publisher_selinux_domain: String,
    pub publisher_executable_identity: String,
    pub publisher_executable_sha256: String,
    pub pidfd_identity_sha256: String,
    pub publication_binding_sha256: String,
    pub registration_binding_sha256: String,
    pub publisher_epoch: String,
    pub publisher_sequence: u64,
    pub root_journal_genesis_sha256: String,
    pub epoch_proof_sha256: String,
    pub root_record_sha256: String,
    pub root_record_proof_sha256: String,
    pub authentication_binding_sha256: String,
}

impl CapabilityLeaseRootPublisherAuthenticationV1 {
    pub fn derive(
        publication: &CapabilityLeaseRootTaskPublicationV1,
        kernel: PublisherKernelIdentityV1,
    ) -> RootAuthenticatorResult<Self> {
        publication
            .validate()
            .map_err(|_| denied("capability_lease_root_authenticator_publication_denied"))?;
        if kernel.pid == 0
            || kernel.start_time_ticks == 0
            || kernel.uid != publication.transport_peer.uid
            || kernel.gid != publication.transport_peer.gid
            || kernel.selinux_domain != publication.transport_peer.selinux_domain
            || kernel.executable_identity != publication.transport_peer.executable_identity
            || kernel.executable_sha256 != publication.transport_peer.executable_sha256
            || !valid_digest(&kernel.pidfd_identity_sha256)
        {
            return Err(denied(
                "capability_lease_root_authenticator_kernel_identity_denied",
            ));
        }
        let registration = &publication.registration;
        let mut authentication = Self {
            authentication_schema: AUTHENTICATION_SCHEMA.to_string(),
            root_authenticator_contract_sha256: CONTRACT_SHA256.to_string(),
            root_publication_contract_sha256: capability_lease_root_publication::CONTRACT_SHA256
                .to_string(),
            root_publisher_launch_contract_sha256:
                capability_lease_root_publisher_launch::CONTRACT_SHA256.to_string(),
            provider_id: registration.provider_id.clone(),
            agent_id: registration.agent_id.clone(),
            replay_namespace: registration.replay_namespace.clone(),
            boot_id_sha256: registration.boot_id_sha256.clone(),
            publisher_pid: kernel.pid,
            publisher_start_time_ticks: kernel.start_time_ticks,
            publisher_uid: kernel.uid,
            publisher_gid: kernel.gid,
            publisher_selinux_domain: kernel.selinux_domain,
            publisher_executable_identity: kernel.executable_identity,
            publisher_executable_sha256: kernel.executable_sha256,
            pidfd_identity_sha256: kernel.pidfd_identity_sha256,
            publication_binding_sha256: publication.publication_binding_sha256.clone(),
            registration_binding_sha256: registration.registration_binding_sha256.clone(),
            publisher_epoch: registration.publisher_epoch.clone(),
            publisher_sequence: registration.publisher_sequence,
            root_journal_genesis_sha256: registration.root_journal_genesis_sha256.clone(),
            epoch_proof_sha256: registration.epoch_proof_sha256.clone(),
            root_record_sha256: publication.root_record_sha256.clone(),
            root_record_proof_sha256: publication.root_record_proof_sha256.clone(),
            authentication_binding_sha256: String::new(),
        };
        authentication.authentication_binding_sha256 = authentication.expected_binding()?;
        authentication.validate_against(publication)?;
        Ok(authentication)
    }

    pub fn validate_against(
        &self,
        publication: &CapabilityLeaseRootTaskPublicationV1,
    ) -> RootAuthenticatorResult<()> {
        self.validate_closed()?;
        publication
            .validate()
            .map_err(|_| denied("capability_lease_root_authenticator_publication_denied"))?;
        let registration = &publication.registration;
        if self.provider_id != registration.provider_id
            || self.agent_id != registration.agent_id
            || self.replay_namespace != registration.replay_namespace
            || self.boot_id_sha256 != registration.boot_id_sha256
            || self.publisher_uid != publication.transport_peer.uid
            || self.publisher_gid != publication.transport_peer.gid
            || self.publisher_selinux_domain != publication.transport_peer.selinux_domain
            || self.publisher_executable_identity != publication.transport_peer.executable_identity
            || self.publisher_executable_sha256 != publication.transport_peer.executable_sha256
            || self.publication_binding_sha256 != publication.publication_binding_sha256
            || self.registration_binding_sha256 != registration.registration_binding_sha256
            || self.publisher_epoch != registration.publisher_epoch
            || self.publisher_sequence != registration.publisher_sequence
            || self.root_journal_genesis_sha256 != registration.root_journal_genesis_sha256
            || self.epoch_proof_sha256 != registration.epoch_proof_sha256
            || self.root_record_sha256 != publication.root_record_sha256
            || self.root_record_proof_sha256 != publication.root_record_proof_sha256
        {
            return Err(denied("capability_lease_root_authenticator_binding_denied"));
        }
        Ok(())
    }

    pub fn validate_closed(&self) -> RootAuthenticatorResult<()> {
        if self.authentication_schema != AUTHENTICATION_SCHEMA
            || self.root_authenticator_contract_sha256 != CONTRACT_SHA256
            || self.root_publication_contract_sha256
                != capability_lease_root_publication::CONTRACT_SHA256
            || self.root_publisher_launch_contract_sha256
                != capability_lease_root_publisher_launch::CONTRACT_SHA256
            || self.provider_id.is_empty()
            || self.agent_id.is_empty()
            || self.replay_namespace.is_empty()
            || !valid_digest(&self.boot_id_sha256)
            || self.publisher_pid == 0
            || self.publisher_start_time_ticks == 0
            || self.publisher_uid == 0
            || self.publisher_gid == 0
            || self.publisher_selinux_domain
                != capability_lease_root_publisher_launch::PUBLISHER_SELINUX_DOMAIN
            || self.publisher_executable_identity
                != capability_lease_root_publisher_launch::PUBLISHER_EXECUTABLE_IDENTITY
            || !valid_digest(&self.publisher_executable_sha256)
            || !valid_digest(&self.pidfd_identity_sha256)
            || !valid_digest(&self.publication_binding_sha256)
            || !valid_digest(&self.registration_binding_sha256)
            || self.publisher_epoch.len() != 32
            || !self
                .publisher_epoch
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.publisher_sequence == 0
            || !valid_digest(&self.root_journal_genesis_sha256)
            || !valid_digest(&self.epoch_proof_sha256)
            || !valid_digest(&self.root_record_sha256)
            || !valid_digest(&self.root_record_proof_sha256)
            || !valid_digest(&self.authentication_binding_sha256)
            || self.expected_binding()? != self.authentication_binding_sha256
        {
            return Err(denied("capability_lease_root_authenticator_binding_denied"));
        }
        Ok(())
    }

    fn expected_binding(&self) -> RootAuthenticatorResult<String> {
        let mut hasher = Sha256::new();
        hash_string(&mut hasher, "domain", AUTHENTICATION_BINDING_DOMAIN)?;
        hash_string(
            &mut hasher,
            "authentication_schema",
            &self.authentication_schema,
        )?;
        hash_string(
            &mut hasher,
            "root_authenticator_contract_sha256",
            &self.root_authenticator_contract_sha256,
        )?;
        hash_string(
            &mut hasher,
            "root_publication_contract_sha256",
            &self.root_publication_contract_sha256,
        )?;
        hash_string(
            &mut hasher,
            "root_publisher_launch_contract_sha256",
            &self.root_publisher_launch_contract_sha256,
        )?;
        hash_string(&mut hasher, "provider_id", &self.provider_id)?;
        hash_string(&mut hasher, "agent_id", &self.agent_id)?;
        hash_string(&mut hasher, "replay_namespace", &self.replay_namespace)?;
        hash_string(&mut hasher, "boot_id_sha256", &self.boot_id_sha256)?;
        hash_u64(&mut hasher, "publisher_pid", self.publisher_pid.into())?;
        hash_u64(
            &mut hasher,
            "publisher_start_time_ticks",
            self.publisher_start_time_ticks,
        )?;
        hash_u64(&mut hasher, "publisher_uid", self.publisher_uid.into())?;
        hash_u64(&mut hasher, "publisher_gid", self.publisher_gid.into())?;
        hash_string(
            &mut hasher,
            "publisher_selinux_domain",
            &self.publisher_selinux_domain,
        )?;
        hash_string(
            &mut hasher,
            "publisher_executable_identity",
            &self.publisher_executable_identity,
        )?;
        hash_string(
            &mut hasher,
            "publisher_executable_sha256",
            &self.publisher_executable_sha256,
        )?;
        hash_string(
            &mut hasher,
            "pidfd_identity_sha256",
            &self.pidfd_identity_sha256,
        )?;
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
        hash_string(&mut hasher, "publisher_epoch", &self.publisher_epoch)?;
        hash_u64(&mut hasher, "publisher_sequence", self.publisher_sequence)?;
        hash_string(
            &mut hasher,
            "root_journal_genesis_sha256",
            &self.root_journal_genesis_sha256,
        )?;
        hash_string(&mut hasher, "epoch_proof_sha256", &self.epoch_proof_sha256)?;
        hash_string(&mut hasher, "root_record_sha256", &self.root_record_sha256)?;
        hash_string(
            &mut hasher,
            "root_record_proof_sha256",
            &self.root_record_proof_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

fn hash_string(hasher: &mut Sha256, name: &str, value: &str) -> RootAuthenticatorResult<()> {
    hash_bytes(hasher, name, value.as_bytes())
}

fn hash_u64(hasher: &mut Sha256, name: &str, value: u64) -> RootAuthenticatorResult<()> {
    hash_bytes(hasher, name, &value.to_be_bytes())
}

fn hash_bytes(hasher: &mut Sha256, name: &str, value: &[u8]) -> RootAuthenticatorResult<()> {
    let name_length = u32::try_from(name.len())
        .map_err(|_| denied("capability_lease_root_authenticator_binding_denied"))?;
    let value_length = u32::try_from(value.len())
        .map_err(|_| denied("capability_lease_root_authenticator_binding_denied"))?;
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
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

const fn denied(code: &'static str) -> RootAuthenticatorError {
    RootAuthenticatorError(code)
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;
    use crate::agent_descriptor_registry::CODEX;
    use crate::capability_lease_root_publication::CapabilityLeaseRootPublisherTransportPeerV1;
    use crate::capability_lease_root_registration::{
        CapabilityLeaseRootPublisherEvidenceV1, CapabilityLeaseRootTaskContextV1,
        CapabilityLeaseRootTaskRegistrationV1,
    };

    fn publication() -> CapabilityLeaseRootTaskPublicationV1 {
        let registration = CapabilityLeaseRootTaskRegistrationV1::derive(
            CODEX.provider_id.to_string(),
            CODEX.agent_id.to_string(),
            CODEX.replay_namespace.to_string(),
            CapabilityLeaseRootPublisherEvidenceV1 {
                boot_id_sha256: "1".repeat(64),
                publisher_epoch: "e".repeat(32),
                publisher_sequence: 1,
                root_journal_genesis_sha256: "2".repeat(64),
                epoch_proof_sha256: "3".repeat(64),
            },
            CapabilityLeaseRootTaskContextV1 {
                opaque_task_context_token: format!("task-context-{}", "2".repeat(64)),
                prepare_request_id: "prepare-token-registry".to_string(),
                prepare_canonical_request_sha256: "4".repeat(64),
                workflow_id: format!("req-{}", "4".repeat(32)),
                task_id: "task.token-registry".to_string(),
                authenticated_task_binding_sha256: "5".repeat(64),
            },
            "6".repeat(64),
        )
        .unwrap();
        CapabilityLeaseRootTaskPublicationV1::derive(
            CapabilityLeaseRootPublisherTransportPeerV1 {
                role: capability_lease_root_publication::TRANSPORT_ROLE.to_string(),
                uid: CODEX.uid,
                gid: CODEX.gid,
                selinux_domain: capability_lease_root_publication::TRANSPORT_SELINUX_DOMAIN
                    .to_string(),
                executable_identity:
                    capability_lease_root_publication::TRANSPORT_EXECUTABLE_IDENTITY.to_string(),
                executable_sha256: "7".repeat(64),
            },
            registration,
            "8".repeat(64),
            "9".repeat(64),
        )
        .unwrap()
    }

    fn kernel() -> PublisherKernelIdentityV1 {
        PublisherKernelIdentityV1 {
            pid: 42,
            start_time_ticks: 99,
            uid: CODEX.uid,
            gid: CODEX.gid,
            selinux_domain: capability_lease_root_publication::TRANSPORT_SELINUX_DOMAIN.to_string(),
            executable_identity: capability_lease_root_publication::TRANSPORT_EXECUTABLE_IDENTITY
                .to_string(),
            executable_sha256: "7".repeat(64),
            pidfd_identity_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn exact_kernel_and_publication_derive_stable_authentication() {
        let publication = publication();
        let authentication =
            CapabilityLeaseRootPublisherAuthenticationV1::derive(&publication, kernel()).unwrap();
        authentication.validate_against(&publication).unwrap();
        assert_eq!(
            authentication.authentication_binding_sha256,
            "b6cb97987f06f48d4f0f53af2ae2957213bf7272119ddce6075236aa11d0c65b"
        );
    }

    #[test]
    fn every_kernel_identity_drift_fails_closed() {
        let publication = publication();
        let mut altered = kernel();
        altered.start_time_ticks += 1;
        let authentication =
            CapabilityLeaseRootPublisherAuthenticationV1::derive(&publication, altered).unwrap();
        let mut drifted = authentication.clone();
        drifted.publisher_pid += 1;
        assert!(drifted.validate_against(&publication).is_err());
        let mut wrong = kernel();
        wrong.uid += 1;
        assert!(CapabilityLeaseRootPublisherAuthenticationV1::derive(&publication, wrong).is_err());
    }

    #[test]
    fn contract_hash_and_authority_are_closed() {
        assert_eq!(
            crate::sha256_bytes(include_bytes!(
                "../contracts/capability-lease-root-authenticator-v1.json"
            )),
            CONTRACT_SHA256
        );
        assert!(!LINUX_KERNEL_BACKEND_AVAILABLE);
        assert!(!BROKER_ROUTE_AVAILABLE);
        assert!(!PRODUCT_CONSTRUCTOR_AVAILABLE);
        assert!(!LISTENER_WIRED);
        assert!(!RUNTIME_CONSUMER_AVAILABLE);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    }
}
