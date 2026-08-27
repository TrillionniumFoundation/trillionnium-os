//! Source-only broker-owned provider launch custody.
//!
//! This module deliberately does not use the older measured-exec controller's
//! `RunningPidfdAtomicMeasuredExec`: that controller resumes immediately after
//! its ptrace exec stop.  A provider launch instead has to remain stopped after
//! the final runtime exec and hardening ceremony while the daemon prepares the
//! exact prompt, proxy, schema, and invocation-state resources.
//!
//! The affine values below never cross the broker socket.  The live protocol,
//! `BrokerCore`, `main`, provider adapters, and product flags do not construct
//! them.  Their only producers are test-only injected custody seams.  Raw
//! digests and serializable lifecycle records are expectations, not authority.
//! `ProviderLeafAbortRequest` survives here only as a correlation record for
//! the explicitly legacy childless lifecycle state machine. It cannot mint a
//! topology-v2 proof; v2 topology/reservation authority is represented
//! separately by `ProviderSubtreeReservationEvidenceV2` and its affine
//! custody.

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_os_types::agent_descriptor_registry;
#[cfg(feature = "p0-launch-package-device-conformance")]
use trillionnium_os_types::provider_post_exec_containment::P0ConformanceProvisionedRuntimePolicyIdentityV2;
use trillionnium_os_types::provider_post_exec_containment::{
    ProviderPostExecContainmentConsumerExpectation, ProviderRuntimeExecTopologyV1,
    ProviderSubtreeReservationEvidenceV2, ProvisionedProviderRuntimePolicyV2,
    ValidatedProviderPostExecContainmentChainBinding,
};
use trillionnium_privilege_broker_protocol::{
    Digest, FixedBytes32, Provider, ProviderLeafAbortRequest,
};

/// The broker-owned affine launch typestate is implemented as a source
/// foundation and has injected fault coverage.
pub(crate) const SOURCE_FINAL_EXEC_HELD_LAUNCH_TYPESTATE_IMPLEMENTED: bool = true;
/// The complete validated post-exec chain can be retained inside broker-owned
/// held-child custody without minting a product authority.
pub(crate) const SOURCE_POST_EXEC_FULL_CHAIN_COMPOSITION_IMPLEMENTED: bool = true;
/// The retained legacy lifecycle correlation record is not topology-v2
/// authority and is never accepted in place of exact subtree reservation
/// custody.
pub(crate) const LEGACY_PROVIDER_LEAF_REQUEST_CONFERS_TOPOLOGY_V2_AUTHORITY: bool = false;
/// No production Linux custody producer exists.
pub(crate) const PRODUCT_LAUNCH_CUSTODY_PRODUCER_AVAILABLE: bool = false;
/// The draft broker protocol does not carry this custody.
pub(crate) const PRODUCT_LAUNCH_PROTOCOL_WIRED: bool = false;
/// The daemon and built-in provider adapters do not consume this custody.
pub(crate) const PRODUCT_PROVIDER_RUNTIME_WIRED: bool = false;
/// This source foundation alone never authorizes an OS tool effect.
pub(crate) const CONFERS_EFFECT_AUTHORITY: bool = false;

/// Exact identities authenticated before the final runtime may be released.
///
/// This is structural expectation data, not an authority.  In particular, the
/// serializable `ProviderLeafAbortRequest` is only the old childless-
/// lifecycle correlation key; it neither describes the v2 subtree nor
/// contains the provider invocation or provider session identity. The
/// identity-key digest names the registered launcher executable, while the
/// separate manifest digest names the exact validated immutable source
/// AgentManifest bytes retained by provisioning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProviderLaunchBinding {
    provider: Provider,
    runtime_exec_topology: ProviderRuntimeExecTopologyV1,
    agent_identity_key_sha256: Digest,
    agent_manifest_sha256: Digest,
    provider_invocation_id_sha256: Digest,
    provider_session_id_sha256: Digest,
    boot_id_sha256: Digest,
    /// Runtime policy generation is an independent broker/store identity.
    policy_generation_sha256: Digest,
    /// Provision epoch is the immutable provisioned-policy identity bound by
    /// the complete os-types chain; it is never inferred from policy generation.
    provision_epoch_sha256: Digest,
    policy_anchor_sha256: Digest,
    final_runtime_executable_sha256: Digest,
    final_runtime_closure_sha256: Digest,
    post_exec_seccomp_filter_sha256: Digest,
    final_evidence_sha256: Digest,
    expected_uid: u32,
    expected_gid: u32,
    expected_selinux_domain_sha256: Digest,
    fixed_cgroup_inventory_sha256: Digest,
    cgroup_directory_ancestry_sha256: Digest,
    provider_runtime_leaf_binding_sha256: Digest,
    provider_subtree_empty_proof_sha256: Digest,
    leaf_request: ProviderLeafAbortRequest,
    tgid: u32,
    starttime_ticks: u64,
    pidfd_identity_sha256: Digest,
    fixed_leaf_fd_identity_sha256: Digest,
    exec_event_identity_sha256: Digest,
    hardening_event_identity_sha256: Digest,
    stdin_fd_identity_sha256: Digest,
    stdout_fd_identity_sha256: Digest,
    stderr_fd_identity_sha256: Digest,
}

/// Kernel/broker observation made while the exact final runtime remains held.
///
/// The associated `Child` owned by [`ProviderLaunchCustodyOps`] must retain the
/// pidfd, ptrace/event stream, fixed-leaf handle, and stdio handles represented
/// here. `final_evidence_sha256` must be derived by that same OS-owned
/// held-child observation ceremony after credential, SELinux, leaf, exec, and
/// hardening verification; it must never be echoed from the launch plan. This
/// record cannot substitute for those handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FinalExecHeldObservation {
    provider: Provider,
    runtime_exec_topology: ProviderRuntimeExecTopologyV1,
    tgid: u32,
    starttime_ticks: u64,
    pidfd_identity_sha256: Digest,
    fixed_leaf_fd_identity_sha256: Digest,
    final_runtime_executable_sha256: Digest,
    final_runtime_closure_sha256: Digest,
    post_exec_seccomp_filter_sha256: Digest,
    final_evidence_sha256: Digest,
    provision_epoch_sha256: Digest,
    observed_uid: u32,
    observed_gid: u32,
    observed_selinux_domain_sha256: Digest,
    fixed_cgroup_inventory_sha256: Digest,
    cgroup_directory_ancestry_sha256: Digest,
    provider_runtime_leaf_binding_sha256: Digest,
    provider_subtree_empty_proof_sha256: Digest,
    exec_event_identity_sha256: Digest,
    hardening_event_identity_sha256: Digest,
    stdin_fd_identity_sha256: Digest,
    stdout_fd_identity_sha256: Digest,
    stderr_fd_identity_sha256: Digest,
    task_stopped: bool,
    pidfd_not_exited: bool,
    later_exec_count: u64,
}

impl ProviderLaunchBinding {
    fn validate_shape(&self) -> bool {
        let distinct_bound_digests = [
            self.agent_identity_key_sha256,
            self.agent_manifest_sha256,
            self.provider_invocation_id_sha256,
            self.provider_session_id_sha256,
            self.boot_id_sha256,
            self.policy_generation_sha256,
            self.provision_epoch_sha256,
            self.policy_anchor_sha256,
            self.final_runtime_closure_sha256,
            self.post_exec_seccomp_filter_sha256,
            self.final_evidence_sha256,
            self.expected_selinux_domain_sha256,
            self.fixed_cgroup_inventory_sha256,
            self.cgroup_directory_ancestry_sha256,
            self.provider_runtime_leaf_binding_sha256,
            self.provider_subtree_empty_proof_sha256,
            Digest::new(self.leaf_request.operation_id.value()),
            Digest::new(self.leaf_request.reservation_id.value()),
            self.leaf_request.lifecycle_digest,
            self.pidfd_identity_sha256,
            self.fixed_leaf_fd_identity_sha256,
            self.exec_event_identity_sha256,
            self.hardening_event_identity_sha256,
            self.stdin_fd_identity_sha256,
            self.stdout_fd_identity_sha256,
            self.stderr_fd_identity_sha256,
        ];
        self.provider == self.leaf_request.provider
            && topology_matches_provider_and_executables(
                self.provider,
                self.runtime_exec_topology,
                self.agent_identity_key_sha256,
                self.final_runtime_executable_sha256,
                &distinct_bound_digests,
            )
            && self.tgid > 1
            && self.starttime_ticks != 0
            && self.expected_uid != 0
            && self.expected_gid != 0
            && self.leaf_request.operation_id.value() != self.leaf_request.reservation_id.value()
            && all_digests_distinct(&distinct_bound_digests)
    }

    fn matches_final_exec_held(&self, observation: &FinalExecHeldObservation) -> bool {
        self.validate_shape()
            && self.provider == observation.provider
            && self.runtime_exec_topology == observation.runtime_exec_topology
            && self.tgid == observation.tgid
            && self.starttime_ticks == observation.starttime_ticks
            && self.pidfd_identity_sha256 == observation.pidfd_identity_sha256
            && self.fixed_leaf_fd_identity_sha256 == observation.fixed_leaf_fd_identity_sha256
            && self.final_runtime_executable_sha256 == observation.final_runtime_executable_sha256
            && self.final_runtime_closure_sha256 == observation.final_runtime_closure_sha256
            && self.post_exec_seccomp_filter_sha256 == observation.post_exec_seccomp_filter_sha256
            && self.final_evidence_sha256 == observation.final_evidence_sha256
            && self.provision_epoch_sha256 == observation.provision_epoch_sha256
            && self.expected_uid == observation.observed_uid
            && self.expected_gid == observation.observed_gid
            && self.expected_selinux_domain_sha256 == observation.observed_selinux_domain_sha256
            && self.fixed_cgroup_inventory_sha256 == observation.fixed_cgroup_inventory_sha256
            && self.cgroup_directory_ancestry_sha256 == observation.cgroup_directory_ancestry_sha256
            && self.provider_runtime_leaf_binding_sha256
                == observation.provider_runtime_leaf_binding_sha256
            && self.provider_subtree_empty_proof_sha256
                == observation.provider_subtree_empty_proof_sha256
            && self.exec_event_identity_sha256 == observation.exec_event_identity_sha256
            && self.hardening_event_identity_sha256 == observation.hardening_event_identity_sha256
            && self.stdin_fd_identity_sha256 == observation.stdin_fd_identity_sha256
            && self.stdout_fd_identity_sha256 == observation.stdout_fd_identity_sha256
            && self.stderr_fd_identity_sha256 == observation.stderr_fd_identity_sha256
            && observation.task_stopped
            && observation.pidfd_not_exited
            && observation.later_exec_count == 0
    }

    fn matches_complete_post_exec_chain(
        &self,
        expected: &ProviderPostExecContainmentConsumerExpectation<'_>,
    ) -> bool {
        let descriptor = match self.provider {
            Provider::Codex => &agent_descriptor_registry::CODEX,
        };
        self.validate_shape()
            && descriptor.provider_id == expected.provider_id
            && descriptor.agent_id == expected.agent_id
            && self.runtime_exec_topology == expected.runtime_exec_topology
            && digest_matches_hex(
                self.agent_identity_key_sha256,
                expected.agent_identity_key_sha256,
            )
            && digest_matches_hex(self.agent_manifest_sha256, expected.agent_manifest_sha256)
            && digest_matches_hex(
                self.provider_invocation_id_sha256,
                expected.provider_invocation_id_sha256,
            )
            && digest_matches_hex(
                self.provider_session_id_sha256,
                expected.provider_session_id_sha256,
            )
            && digest_matches_hex(self.boot_id_sha256, expected.boot_id_sha256)
            && digest_matches_hex(self.provision_epoch_sha256, expected.provision_epoch_sha256)
            && digest_matches_hex(self.policy_anchor_sha256, expected.policy_anchor_sha256)
            && digest_matches_hex(
                self.final_runtime_executable_sha256,
                expected.final_runtime_executable_sha256,
            )
            && digest_matches_hex(
                self.final_runtime_closure_sha256,
                expected.final_runtime_closure_sha256,
            )
            && digest_matches_hex(
                self.post_exec_seccomp_filter_sha256,
                expected.post_exec_seccomp_filter_sha256,
            )
            && digest_matches_hex(
                self.final_evidence_sha256,
                expected.final_exec_evidence_sha256,
            )
            && self.expected_uid == expected.expected_uid
            && self.expected_gid == expected.expected_gid
            && sha256_bytes_matches_digest(
                expected.expected_selinux_domain.as_bytes(),
                self.expected_selinux_domain_sha256,
            )
            && digest_matches_hex(
                self.fixed_cgroup_inventory_sha256,
                expected.fixed_cgroup_inventory_sha256,
            )
            && digest_matches_hex(
                self.cgroup_directory_ancestry_sha256,
                expected.cgroup_directory_ancestry_sha256,
            )
            && digest_matches_hex(
                self.provider_runtime_leaf_binding_sha256,
                expected.provider_runtime_leaf_binding_sha256,
            )
            && digest_matches_hex(
                self.provider_subtree_empty_proof_sha256,
                expected.provider_subtree_empty_proof_sha256,
            )
            && self.leaf_request.provider == self.provider
            && self.leaf_request.broker_leaf_generation.value()
                == expected.broker_subtree_generation
            && fixed_bytes_match_hex(
                self.leaf_request.operation_id.value().as_bytes(),
                expected.lifecycle_operation_id_sha256,
            )
            && fixed_bytes_match_hex(
                self.leaf_request.reservation_id.value().as_bytes(),
                expected.lifecycle_reservation_id_sha256,
            )
            && digest_matches_hex(
                self.leaf_request.lifecycle_digest,
                expected.provider_subtree_lifecycle_sha256,
            )
            && self.tgid == expected.provider_pid
            && self.starttime_ticks == expected.provider_start_time_ticks
            && digest_matches_hex(
                self.pidfd_identity_sha256,
                expected.provider_pidfd_identity_sha256,
            )
            && digest_matches_hex(
                self.exec_event_identity_sha256,
                expected.final_exec_event_identity_sha256,
            )
            && digest_matches_hex(
                self.hardening_event_identity_sha256,
                expected.hardening_event_identity_sha256,
            )
    }

    fn canonical_sha256(&self) -> Result<Digest, ProviderLaunchCustodyError> {
        let mut hasher = Sha256::new();
        hasher.update(b"org.trillionnium.provider-launch-binding.v1\0");
        hash_provider(&mut hasher, self.provider);
        hash_runtime_exec_topology(&mut hasher, self.runtime_exec_topology);
        for digest in [
            self.agent_identity_key_sha256,
            self.agent_manifest_sha256,
            self.provider_invocation_id_sha256,
            self.provider_session_id_sha256,
            self.boot_id_sha256,
            self.policy_generation_sha256,
            self.provision_epoch_sha256,
            self.policy_anchor_sha256,
            self.final_runtime_executable_sha256,
            self.final_runtime_closure_sha256,
            self.post_exec_seccomp_filter_sha256,
            self.final_evidence_sha256,
            self.expected_selinux_domain_sha256,
            self.fixed_cgroup_inventory_sha256,
            self.cgroup_directory_ancestry_sha256,
            self.provider_runtime_leaf_binding_sha256,
            self.provider_subtree_empty_proof_sha256,
        ] {
            hash_digest(&mut hasher, digest);
        }
        hasher.update(self.expected_uid.to_be_bytes());
        hasher.update(self.expected_gid.to_be_bytes());
        hash_leaf_request(&mut hasher, self.leaf_request);
        hasher.update(self.tgid.to_be_bytes());
        hasher.update(self.starttime_ticks.to_be_bytes());
        for digest in [
            self.pidfd_identity_sha256,
            self.fixed_leaf_fd_identity_sha256,
            self.exec_event_identity_sha256,
            self.hardening_event_identity_sha256,
            self.stdin_fd_identity_sha256,
            self.stdout_fd_identity_sha256,
            self.stderr_fd_identity_sha256,
        ] {
            hash_digest(&mut hasher, digest);
        }
        finish_digest(hasher)
    }
}

/// Opaque authenticated launch-plan custody.
///
/// Fields are private, the type is affine and non-Serde, and production has no
/// constructor.  Canonical hashing only detects drift after authentication; it
/// does not authenticate caller-provided records.
#[must_use = "authenticated launch-plan custody must be consumed or discarded"]
pub(crate) struct AuthenticatedProviderLaunchPlan {
    binding: ProviderLaunchBinding,
    binding_sha256: Digest,
}

impl AuthenticatedProviderLaunchPlan {
    fn validate(&self) -> bool {
        self.binding.validate_shape()
            && self
                .binding
                .canonical_sha256()
                .is_ok_and(|expected| expected == self.binding_sha256)
    }

    #[cfg(test)]
    fn for_test(binding: ProviderLaunchBinding) -> Self {
        let binding_sha256 = binding.canonical_sha256().unwrap();
        Self {
            binding,
            binding_sha256,
        }
    }
}

/// Broker-private custody of one authenticated provisioned policy and the
/// exact immutable source AgentManifest bytes named by that policy.
///
/// This source tranche deliberately has no product constructor. A future
/// provisioner must create it from rollback-resistant policy storage and
/// retained source-manifest custody, never from a runtime-mutated
/// `AgentRegistration`.
#[must_use = "authenticated provisioned policy custody must be consumed"]
pub(crate) struct AuthenticatedProvisionedProviderPolicyCustody {
    policy: ProvisionedProviderRuntimePolicyV2,
    source_agent_manifest_bytes: Box<[u8]>,
}

impl AuthenticatedProvisionedProviderPolicyCustody {
    fn validates_exact_chain(
        &self,
        expected: &ProviderPostExecContainmentConsumerExpectation<'_>,
    ) -> bool {
        self.policy.validate().is_ok()
            && self
                .policy
                .canonical_sha256()
                .is_ok_and(|sha256| sha256 == expected.policy_anchor_sha256)
            && self.policy.provider_id() == expected.provider_id
            && self.policy.agent_id() == expected.agent_id
            && self.policy.runtime_exec_topology() == expected.runtime_exec_topology
            && self.policy.agent_identity_key_sha256() == expected.agent_identity_key_sha256
            && self.policy.agent_manifest_sha256() == expected.agent_manifest_sha256
            && sha256_bytes_matches_hex(
                &self.source_agent_manifest_bytes,
                expected.agent_manifest_sha256,
            )
    }

    #[cfg(test)]
    fn for_test(
        policy: ProvisionedProviderRuntimePolicyV2,
        source_agent_manifest_bytes: impl Into<Box<[u8]>>,
    ) -> Self {
        Self {
            policy,
            source_agent_manifest_bytes: source_agent_manifest_bytes.into(),
        }
    }
}

/// Broker-private custody of the exact reserved provider subtree consumed by one
/// post-exec composition.
///
/// The record remains data; its authority comes from this affine custody,
/// whose product constructor is intentionally absent.
#[must_use = "exact provider subtree reservation custody must be consumed"]
pub(crate) struct ExactProviderSubtreeReservationCustody {
    reservation: ProviderSubtreeReservationEvidenceV2,
}

impl ExactProviderSubtreeReservationCustody {
    fn validates_exact_chain(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
        expected: &ProviderPostExecContainmentConsumerExpectation<'_>,
    ) -> bool {
        self.reservation.validate_for(policy).is_ok()
            && self
                .reservation
                .canonical_sha256(policy)
                .is_ok_and(|sha256| sha256 == expected.reservation_evidence_sha256)
    }

    #[cfg(test)]
    fn for_test(reservation: ProviderSubtreeReservationEvidenceV2) -> Self {
        Self { reservation }
    }
}

/// Exact resources prepared only after final-exec-held custody exists.
///
/// Repeated launch/process fields prevent a commitment for another invocation
/// from being accepted merely because a caller copied one aggregate digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProviderResourceCommitmentBinding {
    provider: Provider,
    runtime_exec_topology: ProviderRuntimeExecTopologyV1,
    agent_identity_key_sha256: Digest,
    agent_manifest_sha256: Digest,
    provider_invocation_id_sha256: Digest,
    provider_session_id_sha256: Digest,
    boot_id_sha256: Digest,
    policy_generation_sha256: Digest,
    provision_epoch_sha256: Digest,
    policy_anchor_sha256: Digest,
    final_runtime_executable_sha256: Digest,
    final_runtime_closure_sha256: Digest,
    post_exec_seccomp_filter_sha256: Digest,
    final_evidence_sha256: Digest,
    expected_uid: u32,
    expected_gid: u32,
    expected_selinux_domain_sha256: Digest,
    fixed_cgroup_inventory_sha256: Digest,
    cgroup_directory_ancestry_sha256: Digest,
    provider_runtime_leaf_binding_sha256: Digest,
    provider_subtree_empty_proof_sha256: Digest,
    leaf_request: ProviderLeafAbortRequest,
    tgid: u32,
    starttime_ticks: u64,
    pidfd_identity_sha256: Digest,
    fixed_leaf_fd_identity_sha256: Digest,
    exec_event_identity_sha256: Digest,
    hardening_event_identity_sha256: Digest,
    stdin_fd_identity_sha256: Digest,
    stdout_fd_identity_sha256: Digest,
    stderr_fd_identity_sha256: Digest,
    resource_inventory_sha256: Digest,
    prompt_fd_identity_sha256: Digest,
    schema_fd_identity_sha256: Digest,
    egress_proxy_identity_sha256: Digest,
    invocation_state_dir_identity_sha256: Digest,
}

impl ProviderResourceCommitmentBinding {
    fn validate_shape(&self) -> bool {
        let distinct_bound_digests = [
            self.agent_identity_key_sha256,
            self.agent_manifest_sha256,
            self.provider_invocation_id_sha256,
            self.provider_session_id_sha256,
            self.boot_id_sha256,
            self.policy_generation_sha256,
            self.provision_epoch_sha256,
            self.policy_anchor_sha256,
            self.final_runtime_closure_sha256,
            self.post_exec_seccomp_filter_sha256,
            self.final_evidence_sha256,
            self.expected_selinux_domain_sha256,
            self.fixed_cgroup_inventory_sha256,
            self.cgroup_directory_ancestry_sha256,
            self.provider_runtime_leaf_binding_sha256,
            self.provider_subtree_empty_proof_sha256,
            Digest::new(self.leaf_request.operation_id.value()),
            Digest::new(self.leaf_request.reservation_id.value()),
            self.leaf_request.lifecycle_digest,
            self.pidfd_identity_sha256,
            self.fixed_leaf_fd_identity_sha256,
            self.exec_event_identity_sha256,
            self.hardening_event_identity_sha256,
            self.stdin_fd_identity_sha256,
            self.stdout_fd_identity_sha256,
            self.stderr_fd_identity_sha256,
        ];
        self.provider == self.leaf_request.provider
            && topology_matches_provider_and_executables(
                self.provider,
                self.runtime_exec_topology,
                self.agent_identity_key_sha256,
                self.final_runtime_executable_sha256,
                &distinct_bound_digests,
            )
            && self.tgid > 1
            && self.starttime_ticks != 0
            && self.expected_uid != 0
            && self.expected_gid != 0
            && self.leaf_request.operation_id.value() != self.leaf_request.reservation_id.value()
            && all_digests_distinct(&distinct_bound_digests)
            && all_digests_distinct(&[
                self.resource_inventory_sha256,
                self.prompt_fd_identity_sha256,
                self.schema_fd_identity_sha256,
                self.egress_proxy_identity_sha256,
                self.invocation_state_dir_identity_sha256,
            ])
    }

    fn matches_launch(&self, launch: &ProviderLaunchBinding) -> bool {
        self.validate_shape()
            && self.provider == launch.provider
            && self.runtime_exec_topology == launch.runtime_exec_topology
            && self.agent_identity_key_sha256 == launch.agent_identity_key_sha256
            && self.agent_manifest_sha256 == launch.agent_manifest_sha256
            && self.provider_invocation_id_sha256 == launch.provider_invocation_id_sha256
            && self.provider_session_id_sha256 == launch.provider_session_id_sha256
            && self.boot_id_sha256 == launch.boot_id_sha256
            && self.policy_generation_sha256 == launch.policy_generation_sha256
            && self.provision_epoch_sha256 == launch.provision_epoch_sha256
            && self.policy_anchor_sha256 == launch.policy_anchor_sha256
            && self.final_runtime_executable_sha256 == launch.final_runtime_executable_sha256
            && self.final_runtime_closure_sha256 == launch.final_runtime_closure_sha256
            && self.post_exec_seccomp_filter_sha256 == launch.post_exec_seccomp_filter_sha256
            && self.final_evidence_sha256 == launch.final_evidence_sha256
            && self.expected_uid == launch.expected_uid
            && self.expected_gid == launch.expected_gid
            && self.expected_selinux_domain_sha256 == launch.expected_selinux_domain_sha256
            && self.fixed_cgroup_inventory_sha256 == launch.fixed_cgroup_inventory_sha256
            && self.cgroup_directory_ancestry_sha256 == launch.cgroup_directory_ancestry_sha256
            && self.provider_runtime_leaf_binding_sha256
                == launch.provider_runtime_leaf_binding_sha256
            && self.provider_subtree_empty_proof_sha256
                == launch.provider_subtree_empty_proof_sha256
            && self.leaf_request == launch.leaf_request
            && self.tgid == launch.tgid
            && self.starttime_ticks == launch.starttime_ticks
            && self.pidfd_identity_sha256 == launch.pidfd_identity_sha256
            && self.fixed_leaf_fd_identity_sha256 == launch.fixed_leaf_fd_identity_sha256
            && self.exec_event_identity_sha256 == launch.exec_event_identity_sha256
            && self.hardening_event_identity_sha256 == launch.hardening_event_identity_sha256
            && self.stdin_fd_identity_sha256 == launch.stdin_fd_identity_sha256
            && self.stdout_fd_identity_sha256 == launch.stdout_fd_identity_sha256
            && self.stderr_fd_identity_sha256 == launch.stderr_fd_identity_sha256
    }

    fn canonical_sha256(&self) -> Result<Digest, ProviderLaunchCustodyError> {
        let mut hasher = Sha256::new();
        hasher.update(b"org.trillionnium.provider-resource-commitment.v1\0");
        hash_provider(&mut hasher, self.provider);
        hash_runtime_exec_topology(&mut hasher, self.runtime_exec_topology);
        for digest in [
            self.agent_identity_key_sha256,
            self.agent_manifest_sha256,
            self.provider_invocation_id_sha256,
            self.provider_session_id_sha256,
            self.boot_id_sha256,
            self.policy_generation_sha256,
            self.provision_epoch_sha256,
            self.policy_anchor_sha256,
            self.final_runtime_executable_sha256,
            self.final_runtime_closure_sha256,
            self.post_exec_seccomp_filter_sha256,
            self.final_evidence_sha256,
            self.expected_selinux_domain_sha256,
            self.fixed_cgroup_inventory_sha256,
            self.cgroup_directory_ancestry_sha256,
            self.provider_runtime_leaf_binding_sha256,
            self.provider_subtree_empty_proof_sha256,
        ] {
            hash_digest(&mut hasher, digest);
        }
        hasher.update(self.expected_uid.to_be_bytes());
        hasher.update(self.expected_gid.to_be_bytes());
        hash_leaf_request(&mut hasher, self.leaf_request);
        hasher.update(self.tgid.to_be_bytes());
        hasher.update(self.starttime_ticks.to_be_bytes());
        for digest in [
            self.pidfd_identity_sha256,
            self.fixed_leaf_fd_identity_sha256,
            self.exec_event_identity_sha256,
            self.hardening_event_identity_sha256,
            self.stdin_fd_identity_sha256,
            self.stdout_fd_identity_sha256,
            self.stderr_fd_identity_sha256,
            self.resource_inventory_sha256,
            self.prompt_fd_identity_sha256,
            self.schema_fd_identity_sha256,
            self.egress_proxy_identity_sha256,
            self.invocation_state_dir_identity_sha256,
        ] {
            hash_digest(&mut hasher, digest);
        }
        finish_digest(hasher)
    }
}

/// Affine authenticated resource custody. `Resources` owns the actual retained
/// handles; the digest binding alone cannot construct this value.
#[must_use = "authenticated provider resources must be consumed by exact release"]
pub(crate) struct AuthenticatedProviderResourceCommitmentCustody<Resources: ProviderResourceCustody>
{
    binding: ProviderResourceCommitmentBinding,
    binding_sha256: Digest,
    resources: Option<Resources>,
}

/// Retained resource handle custody must independently report the exact
/// commitment authenticated when those handles were opened. A raw resource
/// inventory record cannot implement the private constructor that encloses
/// this value.
pub(crate) trait ProviderResourceCustody {
    fn authenticated_commitment_sha256(&self) -> Digest;
}

impl<Resources: ProviderResourceCustody> AuthenticatedProviderResourceCommitmentCustody<Resources> {
    fn validate(&self) -> bool {
        self.binding.validate_shape()
            && self
                .binding
                .canonical_sha256()
                .is_ok_and(|expected| expected == self.binding_sha256)
            && self.resources.as_ref().is_some_and(|resources| {
                resources.authenticated_commitment_sha256() == self.binding_sha256
            })
    }

    #[cfg(test)]
    fn for_test(binding: ProviderResourceCommitmentBinding, resources: Resources) -> Self {
        let binding_sha256 = binding.canonical_sha256().unwrap();
        Self {
            binding,
            binding_sha256,
            resources: Some(resources),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitmentClaimOutcome {
    Accepted,
    ReplayDenied,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FinalExecReleaseReceipt {
    launch_binding_sha256: Digest,
    resource_commitment_sha256: Digest,
    provider: Provider,
    runtime_exec_topology: ProviderRuntimeExecTopologyV1,
    agent_identity_key_sha256: Digest,
    agent_manifest_sha256: Digest,
    provider_invocation_id_sha256: Digest,
    provider_session_id_sha256: Digest,
    tgid: u32,
    starttime_ticks: u64,
    pidfd_identity_sha256: Digest,
    resume_event_identity_sha256: Digest,
    receipt_sha256: Digest,
}

impl FinalExecReleaseReceipt {
    fn new(
        launch: &ProviderLaunchBinding,
        launch_binding_sha256: Digest,
        resource_commitment_sha256: Digest,
        resume_event_identity_sha256: Digest,
    ) -> Result<Self, ProviderLaunchCustodyError> {
        let mut receipt = Self {
            launch_binding_sha256,
            resource_commitment_sha256,
            provider: launch.provider,
            runtime_exec_topology: launch.runtime_exec_topology,
            agent_identity_key_sha256: launch.agent_identity_key_sha256,
            agent_manifest_sha256: launch.agent_manifest_sha256,
            provider_invocation_id_sha256: launch.provider_invocation_id_sha256,
            provider_session_id_sha256: launch.provider_session_id_sha256,
            tgid: launch.tgid,
            starttime_ticks: launch.starttime_ticks,
            pidfd_identity_sha256: launch.pidfd_identity_sha256,
            resume_event_identity_sha256,
            receipt_sha256: resume_event_identity_sha256,
        };
        receipt.receipt_sha256 = receipt.canonical_sha256()?;
        Ok(receipt)
    }

    fn matches(
        &self,
        launch: &ProviderLaunchBinding,
        launch_binding_sha256: Digest,
        resource_commitment_sha256: Digest,
    ) -> bool {
        self.launch_binding_sha256 == launch_binding_sha256
            && self.resource_commitment_sha256 == resource_commitment_sha256
            && self.provider == launch.provider
            && self.runtime_exec_topology == launch.runtime_exec_topology
            && self.agent_identity_key_sha256 == launch.agent_identity_key_sha256
            && self.agent_manifest_sha256 == launch.agent_manifest_sha256
            && self.provider_invocation_id_sha256 == launch.provider_invocation_id_sha256
            && self.provider_session_id_sha256 == launch.provider_session_id_sha256
            && self.tgid == launch.tgid
            && self.starttime_ticks == launch.starttime_ticks
            && self.pidfd_identity_sha256 == launch.pidfd_identity_sha256
            && all_digests_distinct(&[
                self.launch_binding_sha256,
                self.resource_commitment_sha256,
                self.agent_identity_key_sha256,
                self.agent_manifest_sha256,
                self.provider_invocation_id_sha256,
                self.provider_session_id_sha256,
                self.pidfd_identity_sha256,
                self.resume_event_identity_sha256,
                launch.fixed_leaf_fd_identity_sha256,
                launch.exec_event_identity_sha256,
                launch.hardening_event_identity_sha256,
            ])
            && self
                .canonical_sha256()
                .is_ok_and(|expected| expected == self.receipt_sha256)
    }

    fn canonical_sha256(&self) -> Result<Digest, ProviderLaunchCustodyError> {
        let mut hasher = Sha256::new();
        hasher.update(b"org.trillionnium.provider-final-exec-release-receipt.v1\0");
        hash_digest(&mut hasher, self.launch_binding_sha256);
        hash_digest(&mut hasher, self.resource_commitment_sha256);
        hash_provider(&mut hasher, self.provider);
        hash_runtime_exec_topology(&mut hasher, self.runtime_exec_topology);
        hash_digest(&mut hasher, self.agent_identity_key_sha256);
        hash_digest(&mut hasher, self.agent_manifest_sha256);
        hash_digest(&mut hasher, self.provider_invocation_id_sha256);
        hash_digest(&mut hasher, self.provider_session_id_sha256);
        hasher.update(self.tgid.to_be_bytes());
        hasher.update(self.starttime_ticks.to_be_bytes());
        hash_digest(&mut hasher, self.pidfd_identity_sha256);
        hash_digest(&mut hasher, self.resume_event_identity_sha256);
        finish_digest(hasher)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FinalExecReleaseOutcome {
    Released {
        receipt: Box<FinalExecReleaseReceipt>,
    },
    Denied,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailStopCleanupOutcome {
    ProvedKilledReapedAndDrained,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PermanentHoldReason {
    AuthenticatedLaunchPlanInvalid,
    FinalExecObservationLost,
    FinalExecObservationIdentityDrift,
    PostExecAuthorityBindingDrift,
    PostExecAuthorityClaimLost,
    PostExecAuthorityReplay,
    ResourceCommitmentBindingDrift,
    ResourceCommitmentReplay,
    CommitmentClaimLost,
    ReleaseStateIndeterminate,
    ReleaseReceiptInvalid,
    CleanupProofMissing,
}

/// Injectable broker-owned operations.
///
/// `Child` must own the exact pidfd, process start identity, ptrace/event
/// stream, fixed-leaf custody, and stdio handles.  Both `Self` and `Child` are
/// moved into each typestate so Drop never depends on a borrowed external
/// cleanup object.
pub(crate) trait ProviderLaunchCustodyOps {
    type Child;

    fn observe_final_exec_held(
        &mut self,
        child: &Self::Child,
    ) -> Result<FinalExecHeldObservation, ProviderLaunchCustodyError>;

    fn claim_post_exec_authority_binding(&mut self, claim_sha256: Digest)
    -> CommitmentClaimOutcome;

    fn claim_resource_commitment(&mut self, claim_sha256: Digest) -> CommitmentClaimOutcome;

    fn release_final_exec(
        &mut self,
        child: &mut Self::Child,
        launch: &ProviderLaunchBinding,
        launch_binding_sha256: Digest,
        resource_commitment_sha256: Digest,
        commitment: &ProviderResourceCommitmentBinding,
    ) -> FinalExecReleaseOutcome;

    fn fail_stop_exact_child_and_drain(
        &mut self,
        binding: &ProviderLaunchBinding,
        child: Self::Child,
    ) -> FailStopCleanupOutcome;

    fn record_permanent_hold(&mut self, binding_sha256: Digest, reason: PermanentHoldReason);
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ProviderLaunchCustodyError {
    #[error("authenticated provider launch plan is unavailable or inconsistent")]
    LaunchPlanInvalid,
    #[error("final-exec-held observation is unavailable")]
    FinalExecObservationUnavailable,
    #[error("final-exec-held identity drifted")]
    FinalExecIdentityMismatch,
    #[error("validated post-exec chain does not bind the authenticated held child")]
    PostExecAuthorityBindingMismatch,
    #[error("post-exec authority binding claim was already consumed")]
    PostExecAuthorityReplay,
    #[error("post-exec authority binding claim outcome is unknown")]
    PostExecAuthorityClaimUnknown,
    #[error("authenticated resource commitment is unavailable or inconsistent")]
    ResourceCommitmentInvalid,
    #[error("resource commitment does not bind the held launch")]
    ResourceCommitmentMismatch,
    #[error("resource commitment claim was already consumed")]
    ResourceCommitmentReplay,
    #[error("resource commitment claim outcome is unknown")]
    ResourceCommitmentClaimUnknown,
    #[error("final-exec release was denied")]
    FinalExecReleaseDenied,
    #[error("final-exec release outcome is unknown")]
    FinalExecReleaseUnknown,
    #[error("final-exec release receipt does not bind the exact held launch")]
    FinalExecReleaseReceiptMismatch,
    #[error("fail-stop cleanup outcome is unknown")]
    FailStopCleanupUnknown,
    #[error("owned launch custody was internally unavailable")]
    OwnedCustodyUnavailable,
    #[error("canonical custody digest could not be constructed")]
    DigestConstructionFailed,
}

/// Unwind-safe owner of the exact child and its cleanup implementation.
///
/// The guard stays intact while observation, claim, and release callbacks run.
/// If any callback unwinds, this value is still on the stack and its Drop path
/// fail-stops the exact child.
struct OwnedProviderInvocationCustody<Ops: ProviderLaunchCustodyOps> {
    binding: ProviderLaunchBinding,
    binding_sha256: Digest,
    ops: Option<Ops>,
    child: Option<Ops::Child>,
    pending_permanent_reason: Option<PermanentHoldReason>,
}

impl<Ops: ProviderLaunchCustodyOps> OwnedProviderInvocationCustody<Ops> {
    fn new(
        binding: ProviderLaunchBinding,
        binding_sha256: Digest,
        ops: Ops,
        child: Ops::Child,
    ) -> Self {
        Self {
            binding,
            binding_sha256,
            ops: Some(ops),
            child: Some(child),
            pending_permanent_reason: None,
        }
    }

    fn parts_mut(&mut self) -> Result<(&mut Ops, &mut Ops::Child), ProviderLaunchCustodyError> {
        match (self.ops.as_mut(), self.child.as_mut()) {
            (Some(ops), Some(child)) => Ok((ops, child)),
            _ => Err(ProviderLaunchCustodyError::OwnedCustodyUnavailable),
        }
    }

    fn ops_mut(&mut self) -> Result<&mut Ops, ProviderLaunchCustodyError> {
        self.ops
            .as_mut()
            .ok_or(ProviderLaunchCustodyError::OwnedCustodyUnavailable)
    }

    fn fail_stop(
        mut self,
        permanent_reason: Option<PermanentHoldReason>,
        original_error: ProviderLaunchCustodyError,
    ) -> ProviderLaunchCustodyError {
        if permanent_reason.is_some() {
            self.pending_permanent_reason = permanent_reason;
        }
        self.cleanup_now(original_error)
    }

    fn arm_permanent_hold(&mut self, reason: PermanentHoldReason) {
        self.pending_permanent_reason = Some(reason);
    }

    fn disarm_permanent_hold(&mut self) {
        self.pending_permanent_reason = None;
    }

    fn cleanup_now(
        &mut self,
        original_error: ProviderLaunchCustodyError,
    ) -> ProviderLaunchCustodyError {
        let (Some(mut ops), Some(child)) = (self.ops.take(), self.child.take()) else {
            return ProviderLaunchCustodyError::OwnedCustodyUnavailable;
        };
        match ops.fail_stop_exact_child_and_drain(&self.binding, child) {
            FailStopCleanupOutcome::ProvedKilledReapedAndDrained => {
                if let Some(reason) = self.pending_permanent_reason.take() {
                    ops.record_permanent_hold(self.binding_sha256, reason);
                }
                original_error
            }
            FailStopCleanupOutcome::Unknown => {
                ops.record_permanent_hold(
                    self.binding_sha256,
                    PermanentHoldReason::CleanupProofMissing,
                );
                ProviderLaunchCustodyError::FailStopCleanupUnknown
            }
        }
    }

    #[cfg(test)]
    fn into_adopted_parts_for_test(mut self) -> (Ops, Ops::Child) {
        (self.ops.take().unwrap(), self.child.take().unwrap())
    }
}

impl<Ops: ProviderLaunchCustodyOps> Drop for OwnedProviderInvocationCustody<Ops> {
    fn drop(&mut self) {
        if self.ops.is_some() && self.child.is_some() {
            let _ = self.cleanup_now(ProviderLaunchCustodyError::FinalExecReleaseDenied);
        }
    }
}

/// Exact final-runtime child retained at the post-hardening stop.
#[must_use = "dropping held provider custody kills, reaps, and drains the exact child"]
pub(crate) struct FinalExecHeldProviderInvocation<Ops: ProviderLaunchCustodyOps> {
    custody: OwnedProviderInvocationCustody<Ops>,
}

/// Broker-private affine custody of one validated complete post-exec chain.
///
/// This value owns the authenticated policy and exact source AgentManifest,
/// the exact provider-subtree reservation, and the still-held child. It has no
/// release, activation, serialization, raw-parts, listener, backend, or effect
/// surface. Dropping it fail-stops the child through the retained launch
/// custody.
#[must_use = "dropping full-chain custody fail-stops the exact held child"]
pub(crate) struct BrokerPostExecFullChainCustody<Ops: ProviderLaunchCustodyOps> {
    chain: ValidatedProviderPostExecContainmentChainBinding,
    _policy: AuthenticatedProvisionedProviderPolicyCustody,
    _reservation: ExactProviderSubtreeReservationCustody,
    held: FinalExecHeldProviderInvocation<Ops>,
}

/// Construct held custody only from a non-forgeable authenticated plan and an
/// owned exact child.  Every error after child ownership arrives is fail-stop.
pub(crate) fn prepare_final_exec_held_provider_invocation<Ops: ProviderLaunchCustodyOps>(
    plan: AuthenticatedProviderLaunchPlan,
    ops: Ops,
    child: Ops::Child,
) -> Result<FinalExecHeldProviderInvocation<Ops>, ProviderLaunchCustodyError> {
    let binding = plan.binding;
    let binding_sha256 = plan.binding_sha256;
    let mut custody = OwnedProviderInvocationCustody::new(binding, binding_sha256, ops, child);
    if !plan.validate() {
        return Err(custody.fail_stop(
            Some(PermanentHoldReason::AuthenticatedLaunchPlanInvalid),
            ProviderLaunchCustodyError::LaunchPlanInvalid,
        ));
    }

    custody.arm_permanent_hold(PermanentHoldReason::FinalExecObservationLost);
    let observation = match custody.parts_mut() {
        Ok((ops, child)) => ops.observe_final_exec_held(child),
        Err(error) => return Err(error),
    };
    let observation = match observation {
        Ok(observation) => observation,
        Err(_) => {
            return Err(custody.fail_stop(
                Some(PermanentHoldReason::FinalExecObservationLost),
                ProviderLaunchCustodyError::FinalExecObservationUnavailable,
            ));
        }
    };
    if !binding.matches_final_exec_held(&observation) {
        return Err(custody.fail_stop(
            Some(PermanentHoldReason::FinalExecObservationIdentityDrift),
            ProviderLaunchCustodyError::FinalExecIdentityMismatch,
        ));
    }
    custody.disarm_permanent_hold();

    Ok(FinalExecHeldProviderInvocation { custody })
}

/// Consume every authenticated input into one exact held-child composition.
///
/// The complete-chain record is validated by `trillionnium-os-types`; this
/// broker only checks that its private authenticated custodies and held child
/// bind that exact chain, then claims the chain digest once. No authority is
/// minted and the child remains stopped.
pub(crate) fn compose_broker_post_exec_full_chain<Ops: ProviderLaunchCustodyOps>(
    policy_custody: AuthenticatedProvisionedProviderPolicyCustody,
    reservation_custody: ExactProviderSubtreeReservationCustody,
    chain: ValidatedProviderPostExecContainmentChainBinding,
    held: FinalExecHeldProviderInvocation<Ops>,
) -> Result<BrokerPostExecFullChainCustody<Ops>, ProviderLaunchCustodyError> {
    let expected = chain.consumer_expectation();
    if !policy_custody.validates_exact_chain(&expected)
        || !reservation_custody.validates_exact_chain(&policy_custody.policy, &expected)
        || !held
            .custody
            .binding
            .matches_complete_post_exec_chain(&expected)
    {
        return Err(held.custody.fail_stop(
            Some(PermanentHoldReason::PostExecAuthorityBindingDrift),
            ProviderLaunchCustodyError::PostExecAuthorityBindingMismatch,
        ));
    }
    let Some(claim_sha256) = digest_from_lower_hex(chain.binding_sha256()) else {
        return Err(held
            .custody
            .fail_stop(None, ProviderLaunchCustodyError::DigestConstructionFailed));
    };

    let mut custody = held.custody;
    custody.arm_permanent_hold(PermanentHoldReason::PostExecAuthorityClaimLost);
    let claim_outcome = match custody.ops_mut() {
        Ok(ops) => ops.claim_post_exec_authority_binding(claim_sha256),
        Err(error) => return Err(error),
    };
    match claim_outcome {
        CommitmentClaimOutcome::Accepted => custody.disarm_permanent_hold(),
        CommitmentClaimOutcome::ReplayDenied => {
            return Err(custody.fail_stop(
                Some(PermanentHoldReason::PostExecAuthorityReplay),
                ProviderLaunchCustodyError::PostExecAuthorityReplay,
            ));
        }
        CommitmentClaimOutcome::Unknown => {
            return Err(custody.fail_stop(
                Some(PermanentHoldReason::PostExecAuthorityClaimLost),
                ProviderLaunchCustodyError::PostExecAuthorityClaimUnknown,
            ));
        }
    }

    Ok(BrokerPostExecFullChainCustody {
        chain,
        _policy: policy_custody,
        _reservation: reservation_custody,
        held: FinalExecHeldProviderInvocation { custody },
    })
}

impl<Ops: ProviderLaunchCustodyOps> BrokerPostExecFullChainCustody<Ops> {
    /// Borrow the complete validated runtime-policy identity retained by this
    /// affine custody. The policy cannot outlive this value, and the held
    /// child, pidfd, cgroup, reservation and stdio handles never leave it.
    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn p0_conformance_runtime_policy_identity(
        &self,
    ) -> Option<P0ConformanceProvisionedRuntimePolicyIdentityV2<'_>> {
        self._policy
            .policy
            .p0_conformance_runtime_policy_identity()
            .ok()
    }

    #[cfg(test)]
    fn binding_sha256(&self) -> &str {
        self.chain.binding_sha256()
    }

    #[cfg(test)]
    fn child_is_still_held_for_test(&self) -> bool {
        self.held.custody.child.is_some()
    }
}

impl<Ops: ProviderLaunchCustodyOps> FinalExecHeldProviderInvocation<Ops> {
    /// The only source-level release transition. Both launch custody and the
    /// authenticated resource commitment are consumed.
    pub(crate) fn release<Resources: ProviderResourceCustody>(
        self,
        mut commitment: AuthenticatedProviderResourceCommitmentCustody<Resources>,
    ) -> Result<ReleasedProviderInvocation<Ops, Resources>, ProviderLaunchCustodyError> {
        let mut custody = self.custody;

        if !commitment.validate() {
            return Err(custody.fail_stop(
                Some(PermanentHoldReason::ResourceCommitmentBindingDrift),
                ProviderLaunchCustodyError::ResourceCommitmentInvalid,
            ));
        }
        if !commitment.binding.matches_launch(&custody.binding) {
            return Err(custody.fail_stop(
                Some(PermanentHoldReason::ResourceCommitmentBindingDrift),
                ProviderLaunchCustodyError::ResourceCommitmentMismatch,
            ));
        }
        custody.arm_permanent_hold(PermanentHoldReason::CommitmentClaimLost);
        let claim_outcome = match custody.ops_mut() {
            Ok(ops) => ops.claim_resource_commitment(commitment.binding_sha256),
            Err(error) => return Err(error),
        };
        match claim_outcome {
            CommitmentClaimOutcome::Accepted => custody.disarm_permanent_hold(),
            CommitmentClaimOutcome::ReplayDenied => {
                return Err(custody.fail_stop(
                    Some(PermanentHoldReason::ResourceCommitmentReplay),
                    ProviderLaunchCustodyError::ResourceCommitmentReplay,
                ));
            }
            CommitmentClaimOutcome::Unknown => {
                return Err(custody.fail_stop(
                    Some(PermanentHoldReason::CommitmentClaimLost),
                    ProviderLaunchCustodyError::ResourceCommitmentClaimUnknown,
                ));
            }
        }

        let binding = custody.binding;
        let binding_sha256 = custody.binding_sha256;
        custody.arm_permanent_hold(PermanentHoldReason::ReleaseStateIndeterminate);
        let release_outcome = match custody.parts_mut() {
            Ok((ops, child)) => ops.release_final_exec(
                child,
                &binding,
                binding_sha256,
                commitment.binding_sha256,
                &commitment.binding,
            ),
            Err(error) => return Err(error),
        };
        let release_receipt = match release_outcome {
            FinalExecReleaseOutcome::Released { receipt } => receipt,
            FinalExecReleaseOutcome::Denied => {
                custody.disarm_permanent_hold();
                return Err(
                    custody.fail_stop(None, ProviderLaunchCustodyError::FinalExecReleaseDenied)
                );
            }
            FinalExecReleaseOutcome::Unknown => {
                return Err(custody.fail_stop(
                    Some(PermanentHoldReason::ReleaseStateIndeterminate),
                    ProviderLaunchCustodyError::FinalExecReleaseUnknown,
                ));
            }
        };
        if !release_receipt.matches(
            &custody.binding,
            custody.binding_sha256,
            commitment.binding_sha256,
        ) {
            return Err(custody.fail_stop(
                Some(PermanentHoldReason::ReleaseReceiptInvalid),
                ProviderLaunchCustodyError::FinalExecReleaseReceiptMismatch,
            ));
        }
        custody.disarm_permanent_hold();

        let Some(resources) = commitment.resources.take() else {
            return Err(custody.fail_stop(
                Some(PermanentHoldReason::ReleaseStateIndeterminate),
                ProviderLaunchCustodyError::OwnedCustodyUnavailable,
            ));
        };
        Ok(ReleasedProviderInvocation {
            custody,
            resource_commitment_sha256: commitment.binding_sha256,
            release_receipt_sha256: release_receipt.receipt_sha256,
            resources: Some(resources),
        })
    }
}

/// Positive release typestate. It still retains all process and resource
/// custody until a later product lifecycle atomically adopts it.
#[must_use = "released provider custody must be atomically adopted or fail-stopped"]
pub(crate) struct ReleasedProviderInvocation<
    Ops: ProviderLaunchCustodyOps,
    Resources: ProviderResourceCustody,
> {
    custody: OwnedProviderInvocationCustody<Ops>,
    resource_commitment_sha256: Digest,
    release_receipt_sha256: Digest,
    resources: Option<Resources>,
}

impl<Ops: ProviderLaunchCustodyOps, Resources: ProviderResourceCustody>
    ReleasedProviderInvocation<Ops, Resources>
{
    #[cfg(test)]
    fn binding_sha256(&self) -> Digest {
        self.custody.binding_sha256
    }

    #[cfg(test)]
    fn resource_commitment_sha256(&self) -> Digest {
        self.resource_commitment_sha256
    }

    #[cfg(test)]
    fn release_receipt_sha256(&self) -> Digest {
        self.release_receipt_sha256
    }

    #[cfg(test)]
    fn into_adopted_parts_for_test(mut self) -> (Ops, Ops::Child, Resources) {
        let resources = self.resources.take().unwrap();
        let (ops, child) = self.custody.into_adopted_parts_for_test();
        (ops, child, resources)
    }
}

fn hash_provider(hasher: &mut Sha256, provider: Provider) {
    hasher.update([match provider {
        Provider::Codex => 1,
    }]);
}

fn hash_runtime_exec_topology(hasher: &mut Sha256, topology: ProviderRuntimeExecTopologyV1) {
    hasher.update([match topology {
        ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => 1,
        ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => 2,
    }]);
}

const fn required_runtime_exec_topology(provider: Provider) -> ProviderRuntimeExecTopologyV1 {
    match provider {
        Provider::Codex => ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime,
    }
}

fn topology_matches_provider_and_executables(
    provider: Provider,
    topology: ProviderRuntimeExecTopologyV1,
    launcher_executable_sha256: Digest,
    final_runtime_executable_sha256: Digest,
    distinct_bound_digests: &[Digest],
) -> bool {
    if topology != required_runtime_exec_topology(provider) {
        return false;
    }
    match topology {
        ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => {
            launcher_executable_sha256 == final_runtime_executable_sha256
        }
        ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => {
            launcher_executable_sha256 != final_runtime_executable_sha256
                && !distinct_bound_digests.contains(&final_runtime_executable_sha256)
        }
    }
}

fn hash_digest(hasher: &mut Sha256, digest: Digest) {
    hasher.update(digest.value().as_bytes());
}

fn hash_leaf_request(hasher: &mut Sha256, request: ProviderLeafAbortRequest) {
    hash_provider(hasher, request.provider);
    hasher.update(request.broker_leaf_generation.value().to_be_bytes());
    hasher.update(request.operation_id.value().as_bytes());
    hasher.update(request.reservation_id.value().as_bytes());
    hash_digest(hasher, request.lifecycle_digest);
}

fn all_digests_distinct(digests: &[Digest]) -> bool {
    digests
        .iter()
        .enumerate()
        .all(|(index, digest)| !digests[..index].contains(digest))
}

fn sha256_bytes_matches_hex(bytes: &[u8], expected: &str) -> bool {
    let sha256: [u8; 32] = Sha256::digest(bytes).into();
    fixed_bytes_match_hex(&sha256, expected)
}

fn sha256_bytes_matches_digest(bytes: &[u8], expected: Digest) -> bool {
    let sha256: [u8; 32] = Sha256::digest(bytes).into();
    sha256 == *expected.value().as_bytes()
}

fn digest_matches_hex(digest: Digest, expected: &str) -> bool {
    fixed_bytes_match_hex(digest.value().as_bytes(), expected)
}

fn fixed_bytes_match_hex(bytes: &[u8; 32], expected: &str) -> bool {
    let expected = expected.as_bytes();
    expected.len() == 64
        && bytes.iter().enumerate().all(|(index, byte)| {
            let offset = index * 2;
            decode_hex_byte(expected[offset], expected[offset + 1]) == Some(*byte)
        })
}

fn digest_from_lower_hex(value: &str) -> Option<Digest> {
    let value = value.as_bytes();
    if value.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = decode_hex_byte(value[offset], value[offset + 1])?;
    }
    FixedBytes32::new(bytes).map(Digest::new).ok()
}

fn decode_hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(decode_hex_nibble(high)? << 4 | decode_hex_nibble(low)?)
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn finish_digest(hasher: Sha256) -> Result<Digest, ProviderLaunchCustodyError> {
    let bytes: [u8; 32] = hasher.finalize().into();
    FixedBytes32::new(bytes)
        .map(Digest::new)
        .map_err(|_| ProviderLaunchCustodyError::DigestConstructionFailed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::rc::Rc;
    use trillionnium_os_types::direct_operation::{
        ProviderCgroupResourcePolicyV1, ProviderCgroupTopologyV2,
    };
    use trillionnium_os_types::provider_post_exec_containment::{
        FINAL_EXEC_EVIDENCE_V2_SCHEMA, FINAL_RUNTIME_EXEC_SEQUENCE, LAUNCH_INTENT_V2_SCHEMA,
        PROTOCOL, PROVIDER_SUBTREE_RESERVATION_EVIDENCE_V2_SCHEMA, PROVISIONED_POLICY_V2_SCHEMA,
        ProviderPostExecContainmentFinalExecEvidenceV2, ProviderPostExecContainmentLaunchIntentV2,
        ProviderPostExecContainmentSpawnHeldEvidenceV2, SPAWN_HELD_EVIDENCE_V2_SCHEMA,
    };
    use trillionnium_privilege_broker_protocol::{
        BrokerLeafGeneration, LifecycleOperationId, LifecycleReservationId,
    };

    #[derive(Default)]
    struct FakeState {
        observe_calls: usize,
        post_exec_claim_calls: usize,
        claim_calls: usize,
        release_calls: usize,
        cleanup_calls: usize,
        cleaned_children: Vec<u64>,
        permanent_holds: Vec<(Digest, PermanentHoldReason)>,
        seen_post_exec_authority_claims: HashSet<[u8; 32]>,
        seen_claims: HashSet<[u8; 32]>,
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[derive(Clone)]
    pub(crate) struct P0CleanupProbe {
        state: Rc<RefCell<FakeState>>,
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    impl P0CleanupProbe {
        pub(crate) fn cleanup_calls(&self) -> usize {
            self.state.borrow().cleanup_calls
        }

        pub(crate) fn release_calls(&self) -> usize {
            self.state.borrow().release_calls
        }
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum P0FullChainPolicyDriftForTest {
        PolicyAuthority,
        PolicyStore,
        SystemImage,
        AvbChain,
        BootId,
        ProvisioningManifest,
        ProvisionEpoch,
        FixedCgroupInventory,
        CgroupDirectoryAncestry,
        ProviderRuntimeLeafBinding,
        ProviderCgroupPolicy,
        ExecEventAuthority,
        Argv,
        Environment,
        CompiledSelinuxAndImage,
        SystemApiToolAndImage,
        AccessibilityToolAndImage,
    }

    pub(crate) struct FakeChild {
        identity: u64,
    }

    struct FakeResources {
        identity: u64,
        authenticated_commitment_sha256: Digest,
    }

    impl ProviderResourceCustody for FakeResources {
        fn authenticated_commitment_sha256(&self) -> Digest {
            self.authenticated_commitment_sha256
        }
    }

    #[derive(Clone, Copy)]
    enum FakeReleaseMode {
        Exact,
        ReceiptMismatch,
        Denied,
        Unknown,
    }

    pub(crate) struct FakeOps {
        state: Rc<RefCell<FakeState>>,
        observation: Result<FinalExecHeldObservation, ProviderLaunchCustodyError>,
        release_mode: FakeReleaseMode,
        cleanup_outcome: FailStopCleanupOutcome,
        claim_unknown: bool,
        post_exec_claim_unknown: bool,
        panic_observe: bool,
        panic_post_exec_claim: bool,
        panic_claim: bool,
        panic_release: bool,
    }

    impl ProviderLaunchCustodyOps for FakeOps {
        type Child = FakeChild;

        fn observe_final_exec_held(
            &mut self,
            _child: &Self::Child,
        ) -> Result<FinalExecHeldObservation, ProviderLaunchCustodyError> {
            self.state.borrow_mut().observe_calls += 1;
            assert!(!self.panic_observe, "injected observe panic");
            self.observation
        }

        fn claim_post_exec_authority_binding(
            &mut self,
            claim_sha256: Digest,
        ) -> CommitmentClaimOutcome {
            self.state.borrow_mut().post_exec_claim_calls += 1;
            assert!(
                !self.panic_post_exec_claim,
                "injected post-exec claim panic"
            );
            let mut state = self.state.borrow_mut();
            if self.post_exec_claim_unknown {
                return CommitmentClaimOutcome::Unknown;
            }
            if state
                .seen_post_exec_authority_claims
                .insert(*claim_sha256.value().as_bytes())
            {
                CommitmentClaimOutcome::Accepted
            } else {
                CommitmentClaimOutcome::ReplayDenied
            }
        }

        fn claim_resource_commitment(&mut self, claim_sha256: Digest) -> CommitmentClaimOutcome {
            self.state.borrow_mut().claim_calls += 1;
            assert!(!self.panic_claim, "injected claim panic");
            let mut state = self.state.borrow_mut();
            if self.claim_unknown {
                return CommitmentClaimOutcome::Unknown;
            }
            if state.seen_claims.insert(*claim_sha256.value().as_bytes()) {
                CommitmentClaimOutcome::Accepted
            } else {
                CommitmentClaimOutcome::ReplayDenied
            }
        }

        fn release_final_exec(
            &mut self,
            _child: &mut Self::Child,
            launch: &ProviderLaunchBinding,
            launch_binding_sha256: Digest,
            resource_commitment_sha256: Digest,
            _commitment: &ProviderResourceCommitmentBinding,
        ) -> FinalExecReleaseOutcome {
            self.state.borrow_mut().release_calls += 1;
            assert!(!self.panic_release, "injected release panic");
            match self.release_mode {
                FakeReleaseMode::Exact => FinalExecReleaseOutcome::Released {
                    receipt: Box::new(
                        FinalExecReleaseReceipt::new(
                            launch,
                            launch_binding_sha256,
                            resource_commitment_sha256,
                            digest(240),
                        )
                        .unwrap(),
                    ),
                },
                FakeReleaseMode::ReceiptMismatch => {
                    let mut receipt = FinalExecReleaseReceipt::new(
                        launch,
                        launch_binding_sha256,
                        resource_commitment_sha256,
                        digest(240),
                    )
                    .unwrap();
                    receipt.provider_session_id_sha256 = digest(239);
                    receipt.receipt_sha256 = receipt.canonical_sha256().unwrap();
                    FinalExecReleaseOutcome::Released {
                        receipt: Box::new(receipt),
                    }
                }
                FakeReleaseMode::Denied => FinalExecReleaseOutcome::Denied,
                FakeReleaseMode::Unknown => FinalExecReleaseOutcome::Unknown,
            }
        }

        fn fail_stop_exact_child_and_drain(
            &mut self,
            _binding: &ProviderLaunchBinding,
            child: Self::Child,
        ) -> FailStopCleanupOutcome {
            let mut state = self.state.borrow_mut();
            state.cleanup_calls += 1;
            state.cleaned_children.push(child.identity);
            self.cleanup_outcome
        }

        fn record_permanent_hold(&mut self, binding_sha256: Digest, reason: PermanentHoldReason) {
            self.state
                .borrow_mut()
                .permanent_holds
                .push((binding_sha256, reason));
        }
    }

    fn digest(value: u8) -> Digest {
        Digest::new(FixedBytes32::new([value; 32]).unwrap())
    }

    fn leaf_request(provider: Provider, seed: u8) -> ProviderLeafAbortRequest {
        ProviderLeafAbortRequest {
            provider,
            broker_leaf_generation: BrokerLeafGeneration::new(u64::from(seed) + 1).unwrap(),
            operation_id: LifecycleOperationId::new(
                FixedBytes32::new([seed.wrapping_add(1); 32]).unwrap(),
            ),
            reservation_id: LifecycleReservationId::new(
                FixedBytes32::new([seed.wrapping_add(2); 32]).unwrap(),
            ),
            lifecycle_digest: digest(seed.wrapping_add(3)),
        }
    }

    const fn opposite_runtime_exec_topology(
        topology: ProviderRuntimeExecTopologyV1,
    ) -> ProviderRuntimeExecTopologyV1 {
        match topology {
            ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => {
                ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime
            }
            ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => {
                ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage
            }
        }
    }

    fn binding(provider: Provider, seed: u8) -> ProviderLaunchBinding {
        let descriptor = match provider {
            Provider::Codex => &agent_descriptor_registry::CODEX,
        };
        let runtime_exec_topology = required_runtime_exec_topology(provider);
        let agent_identity_key_sha256 = digest(seed.wrapping_add(1));
        let final_runtime_executable_sha256 = match runtime_exec_topology {
            ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => agent_identity_key_sha256,
            ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => digest(seed.wrapping_add(8)),
        };
        ProviderLaunchBinding {
            provider,
            runtime_exec_topology,
            agent_identity_key_sha256,
            agent_manifest_sha256: digest(seed.wrapping_add(2)),
            provider_invocation_id_sha256: digest(seed.wrapping_add(3)),
            provider_session_id_sha256: digest(seed.wrapping_add(4)),
            boot_id_sha256: digest(seed.wrapping_add(5)),
            policy_generation_sha256: digest(seed.wrapping_add(6)),
            provision_epoch_sha256: digest(seed.wrapping_add(18)),
            policy_anchor_sha256: digest(seed.wrapping_add(7)),
            final_runtime_executable_sha256,
            final_runtime_closure_sha256: digest(seed.wrapping_add(9)),
            post_exec_seccomp_filter_sha256: digest(seed.wrapping_add(24)),
            final_evidence_sha256: digest(seed.wrapping_add(10)),
            expected_uid: descriptor.uid,
            expected_gid: descriptor.gid,
            expected_selinux_domain_sha256: digest(seed.wrapping_add(19)),
            fixed_cgroup_inventory_sha256: digest(seed.wrapping_add(20)),
            cgroup_directory_ancestry_sha256: digest(seed.wrapping_add(21)),
            provider_runtime_leaf_binding_sha256: digest(seed.wrapping_add(22)),
            provider_subtree_empty_proof_sha256: digest(seed.wrapping_add(23)),
            leaf_request: leaf_request(provider, seed.wrapping_add(30)),
            tgid: u32::from(seed) + 400,
            starttime_ticks: u64::from(seed) + 9_000,
            pidfd_identity_sha256: digest(seed.wrapping_add(11)),
            fixed_leaf_fd_identity_sha256: digest(seed.wrapping_add(12)),
            exec_event_identity_sha256: digest(seed.wrapping_add(13)),
            hardening_event_identity_sha256: digest(seed.wrapping_add(14)),
            stdin_fd_identity_sha256: digest(seed.wrapping_add(15)),
            stdout_fd_identity_sha256: digest(seed.wrapping_add(16)),
            stderr_fd_identity_sha256: digest(seed.wrapping_add(17)),
        }
    }

    fn observation(binding: &ProviderLaunchBinding) -> FinalExecHeldObservation {
        FinalExecHeldObservation {
            provider: binding.provider,
            runtime_exec_topology: binding.runtime_exec_topology,
            tgid: binding.tgid,
            starttime_ticks: binding.starttime_ticks,
            pidfd_identity_sha256: binding.pidfd_identity_sha256,
            fixed_leaf_fd_identity_sha256: binding.fixed_leaf_fd_identity_sha256,
            final_runtime_executable_sha256: binding.final_runtime_executable_sha256,
            final_runtime_closure_sha256: binding.final_runtime_closure_sha256,
            post_exec_seccomp_filter_sha256: binding.post_exec_seccomp_filter_sha256,
            final_evidence_sha256: binding.final_evidence_sha256,
            provision_epoch_sha256: binding.provision_epoch_sha256,
            observed_uid: binding.expected_uid,
            observed_gid: binding.expected_gid,
            observed_selinux_domain_sha256: binding.expected_selinux_domain_sha256,
            fixed_cgroup_inventory_sha256: binding.fixed_cgroup_inventory_sha256,
            cgroup_directory_ancestry_sha256: binding.cgroup_directory_ancestry_sha256,
            provider_runtime_leaf_binding_sha256: binding.provider_runtime_leaf_binding_sha256,
            provider_subtree_empty_proof_sha256: binding.provider_subtree_empty_proof_sha256,
            exec_event_identity_sha256: binding.exec_event_identity_sha256,
            hardening_event_identity_sha256: binding.hardening_event_identity_sha256,
            stdin_fd_identity_sha256: binding.stdin_fd_identity_sha256,
            stdout_fd_identity_sha256: binding.stdout_fd_identity_sha256,
            stderr_fd_identity_sha256: binding.stderr_fd_identity_sha256,
            task_stopped: true,
            pidfd_not_exited: true,
            later_exec_count: 0,
        }
    }

    fn commitment(launch: &ProviderLaunchBinding, seed: u8) -> ProviderResourceCommitmentBinding {
        ProviderResourceCommitmentBinding {
            provider: launch.provider,
            runtime_exec_topology: launch.runtime_exec_topology,
            agent_identity_key_sha256: launch.agent_identity_key_sha256,
            agent_manifest_sha256: launch.agent_manifest_sha256,
            provider_invocation_id_sha256: launch.provider_invocation_id_sha256,
            provider_session_id_sha256: launch.provider_session_id_sha256,
            boot_id_sha256: launch.boot_id_sha256,
            policy_generation_sha256: launch.policy_generation_sha256,
            provision_epoch_sha256: launch.provision_epoch_sha256,
            policy_anchor_sha256: launch.policy_anchor_sha256,
            final_runtime_executable_sha256: launch.final_runtime_executable_sha256,
            final_runtime_closure_sha256: launch.final_runtime_closure_sha256,
            post_exec_seccomp_filter_sha256: launch.post_exec_seccomp_filter_sha256,
            final_evidence_sha256: launch.final_evidence_sha256,
            expected_uid: launch.expected_uid,
            expected_gid: launch.expected_gid,
            expected_selinux_domain_sha256: launch.expected_selinux_domain_sha256,
            fixed_cgroup_inventory_sha256: launch.fixed_cgroup_inventory_sha256,
            cgroup_directory_ancestry_sha256: launch.cgroup_directory_ancestry_sha256,
            provider_runtime_leaf_binding_sha256: launch.provider_runtime_leaf_binding_sha256,
            provider_subtree_empty_proof_sha256: launch.provider_subtree_empty_proof_sha256,
            leaf_request: launch.leaf_request,
            tgid: launch.tgid,
            starttime_ticks: launch.starttime_ticks,
            pidfd_identity_sha256: launch.pidfd_identity_sha256,
            fixed_leaf_fd_identity_sha256: launch.fixed_leaf_fd_identity_sha256,
            exec_event_identity_sha256: launch.exec_event_identity_sha256,
            hardening_event_identity_sha256: launch.hardening_event_identity_sha256,
            stdin_fd_identity_sha256: launch.stdin_fd_identity_sha256,
            stdout_fd_identity_sha256: launch.stdout_fd_identity_sha256,
            stderr_fd_identity_sha256: launch.stderr_fd_identity_sha256,
            resource_inventory_sha256: digest(seed.wrapping_add(1)),
            prompt_fd_identity_sha256: digest(seed.wrapping_add(2)),
            schema_fd_identity_sha256: digest(seed.wrapping_add(3)),
            egress_proxy_identity_sha256: digest(seed.wrapping_add(4)),
            invocation_state_dir_identity_sha256: digest(seed.wrapping_add(5)),
        }
    }

    fn ops(state: Rc<RefCell<FakeState>>, observation: FinalExecHeldObservation) -> FakeOps {
        FakeOps {
            state,
            observation: Ok(observation),
            release_mode: FakeReleaseMode::Exact,
            cleanup_outcome: FailStopCleanupOutcome::ProvedKilledReapedAndDrained,
            claim_unknown: false,
            post_exec_claim_unknown: false,
            panic_observe: false,
            panic_post_exec_claim: false,
            panic_claim: false,
            panic_release: false,
        }
    }

    fn authenticated_commitment(
        binding: ProviderResourceCommitmentBinding,
        resource_identity: u64,
    ) -> AuthenticatedProviderResourceCommitmentCustody<FakeResources> {
        let authenticated_commitment_sha256 = binding.canonical_sha256().unwrap();
        AuthenticatedProviderResourceCommitmentCustody::for_test(
            binding,
            FakeResources {
                identity: resource_identity,
                authenticated_commitment_sha256,
            },
        )
    }

    fn held(
        binding: ProviderLaunchBinding,
        state: Rc<RefCell<FakeState>>,
        child_identity: u64,
    ) -> FinalExecHeldProviderInvocation<FakeOps> {
        prepare_final_exec_held_provider_invocation(
            AuthenticatedProviderLaunchPlan::for_test(binding),
            ops(state, observation(&binding)),
            FakeChild {
                identity: child_identity,
            },
        )
        .unwrap()
    }

    struct PostExecFixture {
        source_manifest_bytes: Vec<u8>,
        policy: ProvisionedProviderRuntimePolicyV2,
        reservation: ProviderSubtreeReservationEvidenceV2,
        intent: ProviderPostExecContainmentLaunchIntentV2,
        spawn: ProviderPostExecContainmentSpawnHeldEvidenceV2,
        final_evidence: ProviderPostExecContainmentFinalExecEvidenceV2,
    }

    impl PostExecFixture {
        #[allow(clippy::too_many_lines)]
        fn new(provider: Provider, seed: &str) -> Self {
            let descriptor = match provider {
                Provider::Codex => &agent_descriptor_registry::CODEX,
            };
            let cgroup_leaf = match provider {
                Provider::Codex => {
                    trillionnium_os_types::direct_operation::CODEX_PROVIDER_RUNTIME_CGROUP_PATH
                }
            };
            let runtime_exec_topology = required_runtime_exec_topology(provider);
            let cgroup_topology =
                ProviderCgroupTopologyV2::fixed_for(descriptor.provider_id).unwrap();
            let cgroup_resource_policy = ProviderCgroupResourcePolicyV1::provisioned(
                descriptor.provider_id,
                128,
                1024 * 1024 * 1024,
                200_000,
                100_000,
            )
            .unwrap();
            let runtime_exec_topology_name = match runtime_exec_topology {
                ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => {
                    "single_final_runtime_image"
                }
                ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => {
                    "launcher_then_final_runtime"
                }
            };
            let final_runtime_executable_sha256 = match runtime_exec_topology {
                ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => {
                    descriptor.identity_key_sha256.to_owned()
                }
                ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => {
                    test_sha256_seed(seed, "final-exe")
                }
            };
            let source_manifest_bytes = format!("{seed}-exact-source-agent-manifest").into_bytes();
            let agent_manifest_sha256 = test_sha256(&source_manifest_bytes);
            let mut policy_json = serde_json::json!({
                "schema": PROVISIONED_POLICY_V2_SCHEMA,
                "protocol": PROTOCOL,
                "provider_id": descriptor.provider_id,
                "agent_id": descriptor.agent_id,
                "runtime_exec_topology": runtime_exec_topology_name,
                "agent_identity_key_sha256": descriptor.identity_key_sha256,
                "agent_manifest_sha256": agent_manifest_sha256,
                "policy_authority_identity_sha256": test_sha256_seed(seed, "authority"),
                "policy_store_instance_sha256": test_sha256_seed(seed, "store"),
                "system_image_sha256": test_sha256_seed(seed, "system-image"),
                "avb_chain_sha256": test_sha256_seed(seed, "avb"),
                "boot_id_sha256": test_sha256_seed(seed, "boot"),
                "provisioning_manifest_sha256": test_sha256_seed(seed, "provisioning-manifest"),
                "provision_epoch_sha256": test_sha256_seed(seed, "provision-epoch"),
                "provisioned_launcher_executable_sha256": descriptor.identity_key_sha256,
                "provisioned_final_runtime_executable_sha256": final_runtime_executable_sha256.clone(),
                "provisioned_final_runtime_closure_sha256": test_sha256_seed(seed, "final-closure"),
                "expected_uid": descriptor.uid,
                "expected_gid": descriptor.gid,
                "expected_selinux_domain": descriptor.agent_selinux_domain,
                "expected_provider_runtime_cgroup_leaf": cgroup_leaf,
                "expected_provider_cgroup_topology": serde_json::to_value(&cgroup_topology).unwrap(),
                "expected_provider_cgroup_resource_policy": serde_json::to_value(&cgroup_resource_policy).unwrap(),
                "fixed_cgroup_inventory_sha256": test_sha256_seed(seed, "inventory"),
                "cgroup_directory_ancestry_sha256": test_sha256_seed(seed, "ancestry"),
                "provider_runtime_leaf_binding_sha256": test_sha256_seed(seed, "leaf-binding"),
                "provider_cgroup_policy_sha256": cgroup_resource_policy.policy_sha256.clone(),
                "expected_exec_event_authority": "privilege_broker_ptrace_exec_stop",
                "expected_post_exec_seccomp_filter_sha256": test_sha256_seed(seed, "seccomp-filter"),
                "permitted_argv_sha256": test_sha256_seed(seed, "argv"),
                "permitted_environment_sha256": test_sha256_seed(seed, "environment"),
                "permitted_fd_table_sha256": test_sha256_seed(seed, "fd-table"),
                "permitted_supplementary_groups_sha256": test_sha256_seed(seed, "groups"),
                "permitted_descendant_closure_sha256": test_sha256_seed(seed, "descendants"),
                "policy_anchor_sha256": test_sha256_seed(seed, "placeholder-policy")
            });
            let provisional_policy: ProvisionedProviderRuntimePolicyV2 =
                deserialize_record(&policy_json);
            let policy_anchor = provisional_policy.canonical_sha256().unwrap();
            policy_json["policy_anchor_sha256"] = serde_json::json!(policy_anchor);
            let policy: ProvisionedProviderRuntimePolicyV2 = deserialize_record(&policy_json);

            let invocation = test_sha256_seed(seed, "invocation");
            let lifecycle = test_sha256_seed(seed, "lifecycle");
            let operation = test_sha256_seed(seed, "operation");
            let reservation_id = test_sha256_seed(seed, "reservation-id");
            let mut reservation_json = serde_json::json!({
                "schema": PROVIDER_SUBTREE_RESERVATION_EVIDENCE_V2_SCHEMA,
                "protocol": PROTOCOL,
                "policy_anchor_sha256": policy_anchor,
                "provider_id": descriptor.provider_id,
                "agent_id": descriptor.agent_id,
                "provider_invocation_id_sha256": invocation,
                "fixed_cgroup_inventory_sha256": test_sha256_seed(seed, "inventory"),
                "cgroup_directory_ancestry_sha256": test_sha256_seed(seed, "ancestry"),
                "provider_runtime_leaf_binding_sha256": test_sha256_seed(seed, "leaf-binding"),
                "provider_subtree_lifecycle_sha256": lifecycle,
                "lifecycle_operation_id_sha256": operation,
                "lifecycle_reservation_id_sha256": reservation_id,
                "broker_subtree_generation": 41,
                "provider_subtree_empty_proof_sha256": test_sha256_seed(seed, "empty-proof"),
                "reservation_nonce": test_sha256_seed(seed, "reservation-nonce"),
                "reservation_evidence_sha256": test_sha256_seed(seed, "placeholder-reservation")
            });
            let provisional_reservation: ProviderSubtreeReservationEvidenceV2 =
                deserialize_record(&reservation_json);
            let reservation_sha256 = provisional_reservation.canonical_sha256(&policy).unwrap();
            reservation_json["reservation_evidence_sha256"] = serde_json::json!(reservation_sha256);
            let reservation: ProviderSubtreeReservationEvidenceV2 =
                deserialize_record(&reservation_json);

            let session = test_sha256_seed(seed, "session");
            let mut intent_json = serde_json::json!({
                "schema": LAUNCH_INTENT_V2_SCHEMA,
                "protocol": PROTOCOL,
                "policy_anchor_sha256": policy_anchor,
                "reservation_evidence_sha256": reservation_sha256,
                "provider_id": descriptor.provider_id,
                "agent_id": descriptor.agent_id,
                "provider_invocation_id_sha256": invocation,
                "provider_session_id_sha256": session,
                "daemon_challenge": test_sha256_seed(seed, "daemon-challenge"),
                "daemon_request_nonce": test_sha256_seed(seed, "daemon-request"),
                "launch_intent_sha256": test_sha256_seed(seed, "placeholder-intent")
            });
            let provisional_intent: ProviderPostExecContainmentLaunchIntentV2 =
                deserialize_record(&intent_json);
            let intent_sha256 = provisional_intent
                .canonical_sha256(&policy, &reservation)
                .unwrap();
            intent_json["launch_intent_sha256"] = serde_json::json!(intent_sha256);
            let intent: ProviderPostExecContainmentLaunchIntentV2 =
                deserialize_record(&intent_json);

            let boot = test_sha256_seed(seed, "boot");
            let pidfd = test_sha256_seed(seed, "pidfd");
            let pid_namespace = test_sha256_seed(seed, "pid-namespace");
            let cgroup_namespace = test_sha256_seed(seed, "cgroup-namespace");
            let event_stream = test_sha256_seed(seed, "event-stream");
            let launcher_exec = test_sha256_seed(seed, "launcher-exec");
            let mut spawn_json = serde_json::json!({
                "schema": SPAWN_HELD_EVIDENCE_V2_SCHEMA,
                "protocol": PROTOCOL,
                "phase": "spawn_held",
                "policy_anchor_sha256": policy_anchor,
                "reservation_evidence_sha256": reservation_sha256,
                "launch_intent_sha256": intent_sha256,
                "provider_id": descriptor.provider_id,
                "agent_id": descriptor.agent_id,
                "provider_invocation_id_sha256": invocation,
                "provider_session_id_sha256": session,
                "boot_id_sha256": boot,
                "provider_pid": 4242,
                "provider_start_time_ticks": 90001,
                "provider_pidfd_identity_sha256": pidfd,
                "pid_namespace_identity_sha256": pid_namespace,
                "cgroup_namespace_identity_sha256": cgroup_namespace,
                "expected_provider_runtime_cgroup_leaf": cgroup_leaf,
                "observed_provider_runtime_cgroup_leaf_identity_sha256": test_sha256_seed(seed, "leaf-binding"),
                "fixed_cgroup_inventory_sha256": test_sha256_seed(seed, "inventory"),
                "cgroup_directory_ancestry_sha256": test_sha256_seed(seed, "ancestry"),
                "provider_runtime_leaf_binding_sha256": test_sha256_seed(seed, "leaf-binding"),
                "provider_subtree_lifecycle_sha256": lifecycle,
                "lifecycle_operation_id_sha256": operation,
                "lifecycle_reservation_id_sha256": reservation_id,
                "broker_subtree_generation": 41,
                "provider_subtree_empty_proof_sha256": test_sha256_seed(seed, "empty-proof"),
                "observed_launcher_executable_sha256": descriptor.identity_key_sha256,
                "observed_uid": descriptor.uid,
                "observed_gid": descriptor.gid,
                "observed_selinux_domain": descriptor.agent_selinux_domain,
                "exec_event_authority": "privilege_broker_ptrace_exec_stop",
                "exec_event_stream_identity_sha256": event_stream,
                "spawn_stop_event_identity_sha256": test_sha256_seed(seed, "spawn-stop"),
                "launcher_exec_event_identity_sha256": launcher_exec.clone(),
                "broker_spawn_nonce": test_sha256_seed(seed, "spawn-nonce"),
                "spawn_held_evidence_sha256": test_sha256_seed(seed, "placeholder-spawn")
            });
            let provisional_spawn: ProviderPostExecContainmentSpawnHeldEvidenceV2 =
                deserialize_record(&spawn_json);
            let spawn_sha256 = provisional_spawn
                .canonical_sha256(&policy, &reservation, &intent)
                .unwrap();
            spawn_json["spawn_held_evidence_sha256"] = serde_json::json!(spawn_sha256);
            let spawn: ProviderPostExecContainmentSpawnHeldEvidenceV2 =
                deserialize_record(&spawn_json);

            let final_exec = match runtime_exec_topology {
                ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => launcher_exec.clone(),
                ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => {
                    test_sha256_seed(seed, "final-exec")
                }
            };
            let hardening_stop = test_sha256_seed(seed, "hardening-stop");
            let hardening = test_sha256_seed(seed, "hardening");
            let mut final_json = serde_json::json!({
                "schema": FINAL_EXEC_EVIDENCE_V2_SCHEMA,
                "protocol": PROTOCOL,
                "phase": "final_exec_verified_held",
                "policy_anchor_sha256": policy_anchor,
                "reservation_evidence_sha256": reservation_sha256,
                "launch_intent_sha256": intent_sha256,
                "spawn_held_evidence_sha256": spawn_sha256,
                "provider_id": descriptor.provider_id,
                "agent_id": descriptor.agent_id,
                "provider_invocation_id_sha256": invocation,
                "provider_session_id_sha256": session,
                "boot_id_sha256": boot,
                "provider_pid": 4242,
                "provider_start_time_ticks": 90001,
                "provider_pidfd_identity_sha256": pidfd,
                "pid_namespace_identity_sha256": pid_namespace,
                "cgroup_namespace_identity_sha256": cgroup_namespace,
                "expected_provider_runtime_cgroup_leaf": cgroup_leaf,
                "expected_provider_cgroup_topology_sha256": cgroup_topology.topology_sha256,
                "observed_provider_cgroup_resource_policy": serde_json::to_value(&cgroup_resource_policy).unwrap(),
                "observed_provider_runtime_cgroup_leaf_identity_sha256": test_sha256_seed(seed, "leaf-binding"),
                "fixed_cgroup_inventory_sha256": test_sha256_seed(seed, "inventory"),
                "cgroup_directory_ancestry_sha256": test_sha256_seed(seed, "ancestry"),
                "provider_runtime_leaf_binding_sha256": test_sha256_seed(seed, "leaf-binding"),
                "provider_subtree_lifecycle_sha256": lifecycle,
                "lifecycle_operation_id_sha256": operation,
                "lifecycle_reservation_id_sha256": reservation_id,
                "broker_subtree_generation": 41,
                "provider_subtree_empty_proof_sha256": test_sha256_seed(seed, "empty-proof"),
                "observed_final_runtime_executable_sha256": final_runtime_executable_sha256,
                "observed_final_runtime_closure_sha256": test_sha256_seed(seed, "final-closure"),
                "observed_uid": descriptor.uid,
                "observed_gid": descriptor.gid,
                "observed_selinux_domain": descriptor.agent_selinux_domain,
                "exec_event_authority": "privilege_broker_ptrace_exec_stop",
                "exec_event_stream_identity_sha256": event_stream
            });
            let final_hardening_json = serde_json::json!({
                "final_exec_event_identity_sha256": final_exec,
                "hardening_stop_event_identity_sha256": hardening_stop,
                "hardening_event_identity_sha256": hardening,
                "final_exec_sequence": FINAL_RUNTIME_EXEC_SEQUENCE,
                "post_verification_exec_event_count": 0,
                "post_exec_dumpable": 0,
                "post_exec_no_new_privs": 1,
                "post_exec_seccomp_mode": 2,
                "observed_post_exec_seccomp_filter_sha256": test_sha256_seed(seed, "seccomp-filter"),
                "effective_capabilities": 0,
                "permitted_capabilities": 0,
                "inheritable_capabilities": 0,
                "ambient_capabilities": 0,
                "bounding_capabilities": 0,
                "supplementary_groups": [],
                "observed_supplementary_groups_sha256": test_sha256_seed(seed, "groups"),
                "observed_argv_sha256": test_sha256_seed(seed, "argv"),
                "observed_environment_sha256": test_sha256_seed(seed, "environment"),
                "observed_fd_table_sha256": test_sha256_seed(seed, "fd-table"),
                "observed_descendant_closure_sha256": test_sha256_seed(seed, "descendants"),
                "prompt_access_count": 0,
                "broker_access_count": 0,
                "invocation_tmp_access_count": 0,
                "child_spawn_count": 0,
                "tool_access_count": 0,
                "broker_hardening_nonce": test_sha256_seed(seed, "hardening-nonce"),
                "broker_verification_nonce": test_sha256_seed(seed, "verification-nonce"),
                "os_observation_sha256": test_sha256_seed(seed, "os-observation"),
                "final_exec_evidence_sha256": test_sha256_seed(seed, "placeholder-final")
            });
            let final_cgroup_json = serde_json::json!({
                "provider_subtree_process_count": 0,
                "provider_subtree_descendant_count": 3,
                "provider_subtree_dying_descendant_count": 0,
                "provider_subtree_max_descendants": 3,
                "provider_subtree_max_depth": 1,
                "runtime_leaf_process_count": 1,
                "runtime_leaf_descendant_count": 0,
                "runtime_leaf_dying_descendant_count": 0,
                "runtime_leaf_max_descendants": 0,
                "runtime_leaf_max_depth": 0,
                "system_api_leaf_process_count": 0,
                "system_api_leaf_descendant_count": 0,
                "system_api_leaf_dying_descendant_count": 0,
                "system_api_leaf_max_descendants": 0,
                "system_api_leaf_max_depth": 0,
                "accessibility_leaf_process_count": 0,
                "accessibility_leaf_descendant_count": 0,
                "accessibility_leaf_dying_descendant_count": 0,
                "accessibility_leaf_max_descendants": 0,
                "accessibility_leaf_max_depth": 0
            });
            final_json
                .as_object_mut()
                .unwrap()
                .extend(final_hardening_json.as_object().unwrap().clone());
            final_json
                .as_object_mut()
                .unwrap()
                .extend(final_cgroup_json.as_object().unwrap().clone());
            let provisional_final: ProviderPostExecContainmentFinalExecEvidenceV2 =
                deserialize_record(&final_json);
            let final_sha256 = provisional_final
                .canonical_sha256(&policy, &reservation, &intent, &spawn)
                .unwrap();
            final_json["final_exec_evidence_sha256"] = serde_json::json!(final_sha256);
            let final_evidence: ProviderPostExecContainmentFinalExecEvidenceV2 =
                deserialize_record(&final_json);

            Self {
                source_manifest_bytes,
                policy,
                reservation,
                intent,
                spawn,
                final_evidence,
            }
        }

        /// Produce another independently valid complete chain whose retained
        /// policy differs in one reviewed identity dimension. Artifact-pin
        /// dimensions also rotate their causally bound image, AVB chain and
        /// provisioning manifest. Every dependent record is re-bound and
        /// rehashed, so a rejection by the P0 admission is a cross-custody join
        /// rejection rather than an invalid-chain shortcut.
        #[cfg(feature = "p0-launch-package-device-conformance")]
        fn with_p0_policy_drift(mut self, drift: P0FullChainPolicyDriftForTest) -> Self {
            let label = format!("p0-policy-drift-{drift:?}");
            let replacement = test_sha256_seed(&label, "replacement");
            let replacement_avb = test_sha256_seed(&label, "replacement-avb");
            let replacement_manifest = test_sha256_seed(&label, "replacement-manifest");
            let placeholder = test_sha256_seed(&label, "placeholder");

            let mut policy_json = serde_json::to_value(&self.policy).unwrap();
            match drift {
                P0FullChainPolicyDriftForTest::PolicyAuthority => {
                    policy_json["policy_authority_identity_sha256"] =
                        serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::PolicyStore => {
                    policy_json["policy_store_instance_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::SystemImage => {
                    policy_json["system_image_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::AvbChain => {
                    policy_json["avb_chain_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::BootId => {
                    policy_json["boot_id_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::ProvisioningManifest => {
                    policy_json["provisioning_manifest_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::ProvisionEpoch => {
                    policy_json["provision_epoch_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::FixedCgroupInventory => {
                    policy_json["fixed_cgroup_inventory_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::CgroupDirectoryAncestry => {
                    policy_json["cgroup_directory_ancestry_sha256"] =
                        serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::ProviderRuntimeLeafBinding => {
                    policy_json["provider_runtime_leaf_binding_sha256"] =
                        serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::ProviderCgroupPolicy => {
                    let provider_id = policy_json["provider_id"]
                        .as_str()
                        .expect("fixture provider id");
                    let replacement_policy = ProviderCgroupResourcePolicyV1::provisioned(
                        provider_id,
                        129,
                        1024 * 1024 * 1024,
                        200_000,
                        100_000,
                    )
                    .unwrap();
                    policy_json["expected_provider_cgroup_resource_policy"] =
                        serde_json::to_value(&replacement_policy).unwrap();
                    policy_json["provider_cgroup_policy_sha256"] =
                        serde_json::json!(replacement_policy.policy_sha256);
                }
                P0FullChainPolicyDriftForTest::ExecEventAuthority => {
                    policy_json["expected_exec_event_authority"] =
                        serde_json::json!("privilege_broker_seccomp_exec_notification");
                }
                P0FullChainPolicyDriftForTest::Argv => {
                    policy_json["permitted_argv_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::Environment => {
                    policy_json["permitted_environment_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::CompiledSelinuxAndImage
                | P0FullChainPolicyDriftForTest::SystemApiToolAndImage
                | P0FullChainPolicyDriftForTest::AccessibilityToolAndImage => {
                    policy_json["system_image_sha256"] = serde_json::json!(replacement);
                    policy_json["avb_chain_sha256"] = serde_json::json!(replacement_avb);
                    policy_json["provisioning_manifest_sha256"] =
                        serde_json::json!(replacement_manifest);
                }
            }
            policy_json["policy_anchor_sha256"] = serde_json::json!(placeholder);
            let provisional_policy: ProvisionedProviderRuntimePolicyV2 =
                deserialize_record(&policy_json);
            let policy_anchor = provisional_policy.canonical_sha256().unwrap();
            policy_json["policy_anchor_sha256"] = serde_json::json!(policy_anchor);
            let policy: ProvisionedProviderRuntimePolicyV2 = deserialize_record(&policy_json);

            let mut reservation_json = serde_json::to_value(&self.reservation).unwrap();
            reservation_json["policy_anchor_sha256"] = serde_json::json!(policy_anchor);
            match drift {
                P0FullChainPolicyDriftForTest::FixedCgroupInventory => {
                    reservation_json["fixed_cgroup_inventory_sha256"] =
                        serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::CgroupDirectoryAncestry => {
                    reservation_json["cgroup_directory_ancestry_sha256"] =
                        serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::ProviderRuntimeLeafBinding => {
                    reservation_json["provider_runtime_leaf_binding_sha256"] =
                        serde_json::json!(replacement);
                }
                _ => {}
            }
            reservation_json["reservation_evidence_sha256"] = serde_json::json!(placeholder);
            let provisional_reservation: ProviderSubtreeReservationEvidenceV2 =
                deserialize_record(&reservation_json);
            let reservation_sha256 = provisional_reservation.canonical_sha256(&policy).unwrap();
            reservation_json["reservation_evidence_sha256"] = serde_json::json!(reservation_sha256);
            let reservation: ProviderSubtreeReservationEvidenceV2 =
                deserialize_record(&reservation_json);

            let mut intent_json = serde_json::to_value(&self.intent).unwrap();
            intent_json["policy_anchor_sha256"] = serde_json::json!(policy_anchor);
            intent_json["reservation_evidence_sha256"] = serde_json::json!(reservation_sha256);
            intent_json["launch_intent_sha256"] = serde_json::json!(placeholder);
            let provisional_intent: ProviderPostExecContainmentLaunchIntentV2 =
                deserialize_record(&intent_json);
            let intent_sha256 = provisional_intent
                .canonical_sha256(&policy, &reservation)
                .unwrap();
            intent_json["launch_intent_sha256"] = serde_json::json!(intent_sha256);
            let intent: ProviderPostExecContainmentLaunchIntentV2 =
                deserialize_record(&intent_json);

            let mut spawn_json = serde_json::to_value(&self.spawn).unwrap();
            spawn_json["policy_anchor_sha256"] = serde_json::json!(policy_anchor);
            spawn_json["reservation_evidence_sha256"] = serde_json::json!(reservation_sha256);
            spawn_json["launch_intent_sha256"] = serde_json::json!(intent_sha256);
            match drift {
                P0FullChainPolicyDriftForTest::BootId => {
                    spawn_json["boot_id_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::FixedCgroupInventory => {
                    spawn_json["fixed_cgroup_inventory_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::CgroupDirectoryAncestry => {
                    spawn_json["cgroup_directory_ancestry_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::ProviderRuntimeLeafBinding => {
                    spawn_json["provider_runtime_leaf_binding_sha256"] =
                        serde_json::json!(replacement);
                    spawn_json["observed_provider_runtime_cgroup_leaf_identity_sha256"] =
                        serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::ExecEventAuthority => {
                    spawn_json["exec_event_authority"] =
                        serde_json::json!("privilege_broker_seccomp_exec_notification");
                }
                _ => {}
            }
            spawn_json["spawn_held_evidence_sha256"] = serde_json::json!(placeholder);
            let provisional_spawn: ProviderPostExecContainmentSpawnHeldEvidenceV2 =
                deserialize_record(&spawn_json);
            let spawn_sha256 = provisional_spawn
                .canonical_sha256(&policy, &reservation, &intent)
                .unwrap();
            spawn_json["spawn_held_evidence_sha256"] = serde_json::json!(spawn_sha256);
            let spawn: ProviderPostExecContainmentSpawnHeldEvidenceV2 =
                deserialize_record(&spawn_json);

            let mut final_json = serde_json::to_value(&self.final_evidence).unwrap();
            final_json["policy_anchor_sha256"] = serde_json::json!(policy_anchor);
            final_json["reservation_evidence_sha256"] = serde_json::json!(reservation_sha256);
            final_json["launch_intent_sha256"] = serde_json::json!(intent_sha256);
            final_json["spawn_held_evidence_sha256"] = serde_json::json!(spawn_sha256);
            match drift {
                P0FullChainPolicyDriftForTest::BootId => {
                    final_json["boot_id_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::FixedCgroupInventory => {
                    final_json["fixed_cgroup_inventory_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::CgroupDirectoryAncestry => {
                    final_json["cgroup_directory_ancestry_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::ProviderRuntimeLeafBinding => {
                    final_json["provider_runtime_leaf_binding_sha256"] =
                        serde_json::json!(replacement);
                    final_json["observed_provider_runtime_cgroup_leaf_identity_sha256"] =
                        serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::ExecEventAuthority => {
                    final_json["exec_event_authority"] =
                        serde_json::json!("privilege_broker_seccomp_exec_notification");
                }
                P0FullChainPolicyDriftForTest::Argv => {
                    final_json["observed_argv_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::Environment => {
                    final_json["observed_environment_sha256"] = serde_json::json!(replacement);
                }
                P0FullChainPolicyDriftForTest::ProviderCgroupPolicy => {
                    final_json["observed_provider_cgroup_resource_policy"] =
                        policy_json["expected_provider_cgroup_resource_policy"].clone();
                }
                _ => {}
            }
            final_json["final_exec_evidence_sha256"] = serde_json::json!(placeholder);
            let provisional_final: ProviderPostExecContainmentFinalExecEvidenceV2 =
                deserialize_record(&final_json);
            let final_sha256 = provisional_final
                .canonical_sha256(&policy, &reservation, &intent, &spawn)
                .unwrap();
            final_json["final_exec_evidence_sha256"] = serde_json::json!(final_sha256);
            let final_evidence: ProviderPostExecContainmentFinalExecEvidenceV2 =
                deserialize_record(&final_json);

            self.policy = policy;
            self.reservation = reservation;
            self.intent = intent;
            self.spawn = spawn;
            self.final_evidence = final_evidence;
            self
        }

        fn validated_chain(&self) -> ValidatedProviderPostExecContainmentChainBinding {
            ValidatedProviderPostExecContainmentChainBinding::validate_complete_chain(
                &self.policy,
                &self.reservation,
                &self.intent,
                &self.spawn,
                &self.final_evidence,
            )
            .unwrap()
        }

        fn launch_binding(&self, provider: Provider, extra_seed: u8) -> ProviderLaunchBinding {
            let chain = self.validated_chain();
            let expected = chain.consumer_expectation();
            ProviderLaunchBinding {
                provider,
                runtime_exec_topology: expected.runtime_exec_topology,
                agent_identity_key_sha256: digest_from_lower_hex(
                    expected.agent_identity_key_sha256,
                )
                .unwrap(),
                agent_manifest_sha256: digest_from_lower_hex(expected.agent_manifest_sha256)
                    .unwrap(),
                provider_invocation_id_sha256: digest_from_lower_hex(
                    expected.provider_invocation_id_sha256,
                )
                .unwrap(),
                provider_session_id_sha256: digest_from_lower_hex(
                    expected.provider_session_id_sha256,
                )
                .unwrap(),
                boot_id_sha256: digest_from_lower_hex(expected.boot_id_sha256).unwrap(),
                policy_generation_sha256: digest(extra_seed),
                provision_epoch_sha256: digest_from_lower_hex(expected.provision_epoch_sha256)
                    .unwrap(),
                policy_anchor_sha256: digest_from_lower_hex(expected.policy_anchor_sha256).unwrap(),
                final_runtime_executable_sha256: digest_from_lower_hex(
                    expected.final_runtime_executable_sha256,
                )
                .unwrap(),
                final_runtime_closure_sha256: digest_from_lower_hex(
                    expected.final_runtime_closure_sha256,
                )
                .unwrap(),
                post_exec_seccomp_filter_sha256: digest_from_lower_hex(
                    expected.post_exec_seccomp_filter_sha256,
                )
                .unwrap(),
                final_evidence_sha256: digest_from_lower_hex(expected.final_exec_evidence_sha256)
                    .unwrap(),
                expected_uid: expected.expected_uid,
                expected_gid: expected.expected_gid,
                expected_selinux_domain_sha256: Digest::new(
                    FixedBytes32::new(Sha256::digest(expected.expected_selinux_domain).into())
                        .unwrap(),
                ),
                fixed_cgroup_inventory_sha256: digest_from_lower_hex(
                    expected.fixed_cgroup_inventory_sha256,
                )
                .unwrap(),
                cgroup_directory_ancestry_sha256: digest_from_lower_hex(
                    expected.cgroup_directory_ancestry_sha256,
                )
                .unwrap(),
                provider_runtime_leaf_binding_sha256: digest_from_lower_hex(
                    expected.provider_runtime_leaf_binding_sha256,
                )
                .unwrap(),
                provider_subtree_empty_proof_sha256: digest_from_lower_hex(
                    expected.provider_subtree_empty_proof_sha256,
                )
                .unwrap(),
                leaf_request: ProviderLeafAbortRequest {
                    provider,
                    broker_leaf_generation: BrokerLeafGeneration::new(
                        expected.broker_subtree_generation,
                    )
                    .unwrap(),
                    operation_id: LifecycleOperationId::new(fixed_bytes_from_lower_hex(
                        expected.lifecycle_operation_id_sha256,
                    )),
                    reservation_id: LifecycleReservationId::new(fixed_bytes_from_lower_hex(
                        expected.lifecycle_reservation_id_sha256,
                    )),
                    lifecycle_digest: digest_from_lower_hex(
                        expected.provider_subtree_lifecycle_sha256,
                    )
                    .unwrap(),
                },
                tgid: expected.provider_pid,
                starttime_ticks: expected.provider_start_time_ticks,
                pidfd_identity_sha256: digest_from_lower_hex(
                    expected.provider_pidfd_identity_sha256,
                )
                .unwrap(),
                fixed_leaf_fd_identity_sha256: digest(extra_seed.wrapping_add(1)),
                exec_event_identity_sha256: digest_from_lower_hex(
                    expected.final_exec_event_identity_sha256,
                )
                .unwrap(),
                hardening_event_identity_sha256: digest_from_lower_hex(
                    expected.hardening_event_identity_sha256,
                )
                .unwrap(),
                stdin_fd_identity_sha256: digest(extra_seed.wrapping_add(2)),
                stdout_fd_identity_sha256: digest(extra_seed.wrapping_add(3)),
                stderr_fd_identity_sha256: digest(extra_seed.wrapping_add(4)),
            }
        }

        fn policy_custody(&self) -> AuthenticatedProvisionedProviderPolicyCustody {
            AuthenticatedProvisionedProviderPolicyCustody::for_test(
                self.policy.clone(),
                self.source_manifest_bytes.clone(),
            )
        }

        fn reservation_custody(&self) -> ExactProviderSubtreeReservationCustody {
            ExactProviderSubtreeReservationCustody::for_test(self.reservation.clone())
        }
    }

    fn deserialize_record<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> T {
        serde_json::from_value(value.clone()).unwrap()
    }

    fn test_sha256_seed(seed: &str, label: &str) -> String {
        test_sha256(format!("{seed}-{label}").as_bytes())
    }

    fn test_sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn p0_full_chain_and_descriptor_for_test(
        provider: Provider,
        variant: trillionnium_os_types::p0_launch_package_device_conformance::P0ConformanceProductVariant,
    ) -> (
        BrokerPostExecFullChainCustody<FakeOps>,
        trillionnium_os_types::p0_launch_package_device_conformance::P0LaunchPackageConformanceBuildDescriptorV2,
    ){
        let (full_chain, descriptor, _probe) =
            p0_full_chain_fixture_for_test(provider, variant, None);
        (full_chain, descriptor)
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn p0_full_chain_descriptor_and_probe_for_test(
        provider: Provider,
        variant: trillionnium_os_types::p0_launch_package_device_conformance::P0ConformanceProductVariant,
    ) -> (
        BrokerPostExecFullChainCustody<FakeOps>,
        trillionnium_os_types::p0_launch_package_device_conformance::P0LaunchPackageConformanceBuildDescriptorV2,
        P0CleanupProbe,
    ){
        p0_full_chain_fixture_for_test(provider, variant, None)
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn p0_full_chain_with_policy_drift_for_test(
        provider: Provider,
        variant: trillionnium_os_types::p0_launch_package_device_conformance::P0ConformanceProductVariant,
        drift: P0FullChainPolicyDriftForTest,
    ) -> (
        BrokerPostExecFullChainCustody<FakeOps>,
        trillionnium_os_types::p0_launch_package_device_conformance::P0LaunchPackageConformanceBuildDescriptorV2,
        P0CleanupProbe,
    ){
        p0_full_chain_fixture_for_test(provider, variant, Some(drift))
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    fn p0_full_chain_fixture_for_test(
        provider: Provider,
        variant: trillionnium_os_types::p0_launch_package_device_conformance::P0ConformanceProductVariant,
        drift: Option<P0FullChainPolicyDriftForTest>,
    ) -> (
        BrokerPostExecFullChainCustody<FakeOps>,
        trillionnium_os_types::p0_launch_package_device_conformance::P0LaunchPackageConformanceBuildDescriptorV2,
        P0CleanupProbe,
    ){
        use trillionnium_os_types::agent_direct_permission_model::{
            DIRECT_AGENT_TOOL_NAMES, PERMISSION_MODEL_SHA256,
        };
        use trillionnium_os_types::p0_launch_package_device_conformance::{
            BUILD_DESCRIPTOR_SCHEMA, BUILD_DESCRIPTOR_STATUS,
            P0LaunchPackageConformanceBuildBodyV2, P0LaunchPackageConformanceBuildDescriptorV2,
            REQUIRED_CAPABILITY_POLICY, REQUIRED_DESCENDANT_POLICY, REQUIRED_FD_POLICY,
            REQUIRED_GROUP_POLICY, TARGET_ACTION, TARGET_ANDROID_USER, TARGET_PACKAGE,
        };

        let provider_name = match provider {
            Provider::Codex => "codex",
        };
        let seed = format!("p0-{provider_name}-{}", variant.as_str());
        let fixture = match drift {
            Some(drift) => PostExecFixture::new(provider, &seed).with_p0_policy_drift(drift),
            None => PostExecFixture::new(provider, &seed),
        };
        let chain = fixture.validated_chain();
        let expected = chain.consumer_expectation();
        let policy_identity = fixture
            .policy
            .p0_conformance_runtime_policy_identity()
            .unwrap();
        let registry = match provider {
            Provider::Codex => &agent_descriptor_registry::CODEX,
        };
        let system_api_tool_sha256 = match drift {
            Some(P0FullChainPolicyDriftForTest::SystemApiToolAndImage) => {
                test_sha256_seed(&seed, "drifted-system-api-tool")
            }
            _ => test_sha256_seed(&seed, "system-api-tool"),
        };
        let accessibility_tool_sha256 = match drift {
            Some(P0FullChainPolicyDriftForTest::AccessibilityToolAndImage) => {
                test_sha256_seed(&seed, "drifted-accessibility-tool")
            }
            _ => test_sha256_seed(&seed, "accessibility-tool"),
        };
        let compiled_selinux_policy_sha256 = match drift {
            Some(P0FullChainPolicyDriftForTest::CompiledSelinuxAndImage) => {
                test_sha256_seed(&seed, "drifted-compiled-selinux")
            }
            _ => test_sha256_seed(&seed, "compiled-selinux"),
        };
        let descriptor = P0LaunchPackageConformanceBuildDescriptorV2::from_source_body(
            P0LaunchPackageConformanceBuildBodyV2 {
                schema: BUILD_DESCRIPTOR_SCHEMA.to_string(),
                status: BUILD_DESCRIPTOR_STATUS.to_string(),
                provider_id: expected.provider_id.to_string(),
                agent_id: expected.agent_id.to_string(),
                identity_key_sha256: expected.agent_identity_key_sha256.to_string(),
                runtime_adapter: registry.runtime_adapter.to_string(),
                uid: expected.expected_uid,
                gid: expected.expected_gid,
                agent_selinux_domain: expected.expected_selinux_domain.to_string(),
                product_variant: variant,
                runtime_exec_topology: expected.runtime_exec_topology,
                permission_model_sha256: PERMISSION_MODEL_SHA256.to_string(),
                direct_tool_names: [
                    DIRECT_AGENT_TOOL_NAMES[0].to_string(),
                    DIRECT_AGENT_TOOL_NAMES[1].to_string(),
                ],
                action: TARGET_ACTION.to_string(),
                package: TARGET_PACKAGE.to_string(),
                android_user: TARGET_ANDROID_USER,
                agent_manifest_sha256: expected.agent_manifest_sha256.to_string(),
                launcher_executable_sha256: expected.launcher_executable_sha256.to_string(),
                final_runtime_executable_sha256: expected
                    .final_runtime_executable_sha256
                    .to_string(),
                final_runtime_closure_sha256: expected.final_runtime_closure_sha256.to_string(),
                system_api_tool_sha256,
                accessibility_tool_sha256,
                compiled_selinux_policy_sha256,
                cgroup_policy_sha256: policy_identity.provider_cgroup_policy_sha256().to_string(),
                seccomp_filter_sha256: expected.post_exec_seccomp_filter_sha256.to_string(),
                fd_table_sha256: policy_identity.permitted_fd_table_sha256().to_string(),
                supplementary_groups_policy_sha256: policy_identity
                    .permitted_supplementary_groups_sha256()
                    .to_string(),
                descendant_policy_sha256: policy_identity
                    .permitted_descendant_closure_sha256()
                    .to_string(),
                expected_provider_runtime_cgroup_leaf: match provider {
                    Provider::Codex => {
                        trillionnium_os_types::direct_operation::CODEX_PROVIDER_RUNTIME_CGROUP_PATH
                    }
                }
                .to_string(),
                permitted_fd_numbers: [0, 1, 2],
                supplementary_groups: Vec::new(),
                fd_policy: REQUIRED_FD_POLICY.to_string(),
                supplementary_group_policy: REQUIRED_GROUP_POLICY.to_string(),
                capability_policy: REQUIRED_CAPABILITY_POLICY.to_string(),
                descendant_policy: REQUIRED_DESCENDANT_POLICY.to_string(),
                required_no_new_privileges: 1,
                required_dumpable: 0,
                required_seccomp_mode: 2,
                outer_owned_cgroup_supervisor: true,
                zero_survivors_required_before_durable_ack: true,
                local_command_fallback: false,
                product_effect_authority: false,
            },
        )
        .unwrap();
        let launch = fixture.launch_binding(
            provider,
            match provider {
                Provider::Codex => 200,
            },
        );
        let state = Rc::new(RefCell::new(FakeState::default()));
        let probe = P0CleanupProbe {
            state: Rc::clone(&state),
        };
        let full_chain = compose_broker_post_exec_full_chain(
            fixture.policy_custody(),
            fixture.reservation_custody(),
            chain,
            held(launch, state, 1),
        )
        .unwrap();
        assert!(
            full_chain
                .p0_conformance_runtime_policy_identity()
                .is_some()
        );
        (full_chain, descriptor, probe)
    }

    fn fixed_bytes_from_lower_hex(value: &str) -> FixedBytes32 {
        digest_from_lower_hex(value).unwrap().value()
    }

    #[test]
    fn unknown_or_unwound_full_chain_claim_preserves_permanent_hold_and_cleanup() {
        let fixture = PostExecFixture::new(Provider::Codex, "composition-fault");
        let launch = fixture.launch_binding(Provider::Codex, 190);

        let unknown_state = Rc::new(RefCell::new(FakeState::default()));
        let mut unknown_ops = ops(Rc::clone(&unknown_state), observation(&launch));
        unknown_ops.post_exec_claim_unknown = true;
        let unknown_held = prepare_final_exec_held_provider_invocation(
            AuthenticatedProviderLaunchPlan::for_test(launch),
            unknown_ops,
            FakeChild { identity: 111 },
        )
        .unwrap();
        let unknown = compose_broker_post_exec_full_chain(
            fixture.policy_custody(),
            fixture.reservation_custody(),
            fixture.validated_chain(),
            unknown_held,
        );
        assert_eq!(
            unknown.err(),
            Some(ProviderLaunchCustodyError::PostExecAuthorityClaimUnknown)
        );
        {
            let state = unknown_state.borrow();
            assert_eq!(state.post_exec_claim_calls, 1);
            assert_eq!(state.cleanup_calls, 1);
            assert_eq!(state.release_calls, 0);
            assert_eq!(
                state.permanent_holds,
                vec![(
                    launch.canonical_sha256().unwrap(),
                    PermanentHoldReason::PostExecAuthorityClaimLost
                )]
            );
        }

        let panic_state = Rc::new(RefCell::new(FakeState::default()));
        let mut panic_ops = ops(Rc::clone(&panic_state), observation(&launch));
        panic_ops.panic_post_exec_claim = true;
        let panic_held = prepare_final_exec_held_provider_invocation(
            AuthenticatedProviderLaunchPlan::for_test(launch),
            panic_ops,
            FakeChild { identity: 112 },
        )
        .unwrap();
        let claim_panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = compose_broker_post_exec_full_chain(
                fixture.policy_custody(),
                fixture.reservation_custody(),
                fixture.validated_chain(),
                panic_held,
            );
        }));
        assert!(claim_panic.is_err());
        let state = panic_state.borrow();
        assert_eq!(state.post_exec_claim_calls, 1);
        assert_eq!(state.cleanup_calls, 1);
        assert_eq!(state.release_calls, 0);
        assert_eq!(
            state.permanent_holds,
            vec![(
                launch.canonical_sha256().unwrap(),
                PermanentHoldReason::PostExecAuthorityClaimLost
            )]
        );
    }

    #[test]
    fn every_resource_identity_is_committed_but_raw_digest_is_not_release_authority() {
        type Drift = Box<dyn Fn(&mut ProviderResourceCommitmentBinding)>;
        let launch = binding(Provider::Codex, 100);
        let drifts: Vec<Drift> = vec![
            Box::new(|value| value.resource_inventory_sha256 = digest(211)),
            Box::new(|value| value.prompt_fd_identity_sha256 = digest(212)),
            Box::new(|value| value.schema_fd_identity_sha256 = digest(213)),
            Box::new(|value| value.egress_proxy_identity_sha256 = digest(214)),
            Box::new(|value| value.invocation_state_dir_identity_sha256 = digest(215)),
        ];
        let expected = commitment(&launch, 130);
        let expected_sha256 = expected.canonical_sha256().unwrap();
        for drift in drifts {
            let mut changed = expected;
            drift(&mut changed);
            assert_ne!(changed.canonical_sha256().unwrap(), expected_sha256);
        }

        let source = include_str!("provider_launch_custody.rs");
        assert!(!source.contains(concat!("impl Serialize for ", "AuthenticatedProvider")));
        assert!(!source.contains(concat!("impl Clone for ", "AuthenticatedProvider")));
        assert!(!source.contains(concat!("pub fn ", "from_records")));
        assert!(!source.contains(concat!("pub fn ", "from_digest")));
        for type_name in [
            "AuthenticatedProviderLaunchPlan",
            "AuthenticatedProvisionedProviderPolicyCustody",
            "ExactProviderSubtreeReservationCustody",
            "AuthenticatedProviderResourceCommitmentCustody",
            "OwnedProviderInvocationCustody",
            "FinalExecHeldProviderInvocation",
            "BrokerPostExecFullChainCustody",
            "ReleasedProviderInvocation",
        ] {
            let declaration = source
                .find(&format!("struct {type_name}"))
                .expect("affine custody declaration must remain in this module");
            let header_start = source[..declaration]
                .rfind("\n\n")
                .map_or(0, |offset| offset + 2);
            assert!(
                !source[header_start..declaration].contains("#[derive"),
                "{type_name} must not acquire derived cloning or serialization"
            );
        }
    }

    #[test]
    fn mismatched_or_event_reused_release_receipts_fail_closed() {
        let launch = binding(Provider::Codex, 38);
        let state = Rc::new(RefCell::new(FakeState::default()));
        let mut fake_ops = ops(Rc::clone(&state), observation(&launch));
        fake_ops.release_mode = FakeReleaseMode::ReceiptMismatch;
        let result = prepare_final_exec_held_provider_invocation(
            AuthenticatedProviderLaunchPlan::for_test(launch),
            fake_ops,
            FakeChild { identity: 18 },
        )
        .unwrap()
        .release(authenticated_commitment(commitment(&launch, 142), 19));
        assert_eq!(
            result.err(),
            Some(ProviderLaunchCustodyError::FinalExecReleaseReceiptMismatch)
        );
        let state = state.borrow();
        assert_eq!(state.release_calls, 1);
        assert_eq!(state.cleanup_calls, 1);
        assert_eq!(
            state.permanent_holds,
            vec![(
                launch.canonical_sha256().unwrap(),
                PermanentHoldReason::ReleaseReceiptInvalid
            )]
        );
        drop(state);

        let launch_sha256 = launch.canonical_sha256().unwrap();
        let commitment_sha256 = commitment(&launch, 142).canonical_sha256().unwrap();
        for reused_event in [
            launch.exec_event_identity_sha256,
            launch.hardening_event_identity_sha256,
        ] {
            let mut receipt = FinalExecReleaseReceipt::new(
                &launch,
                launch_sha256,
                commitment_sha256,
                digest(240),
            )
            .unwrap();
            receipt.resume_event_identity_sha256 = reused_event;
            receipt.receipt_sha256 = receipt.canonical_sha256().unwrap();
            assert!(!receipt.matches(&launch, launch_sha256, commitment_sha256));
        }
    }

    #[test]
    fn drop_before_release_and_drop_after_release_fail_stop_once() {
        let launch = binding(Provider::Codex, 35);

        let held_state = Rc::new(RefCell::new(FakeState::default()));
        drop(held(launch, Rc::clone(&held_state), 11));
        assert_eq!(held_state.borrow().cleanup_calls, 1);
        assert_eq!(held_state.borrow().cleaned_children, vec![11]);

        let released_state = Rc::new(RefCell::new(FakeState::default()));
        let released = held(launch, Rc::clone(&released_state), 12)
            .release(authenticated_commitment(commitment(&launch, 140), 13))
            .unwrap();
        drop(released);
        let state = released_state.borrow();
        assert_eq!(state.release_calls, 1);
        assert_eq!(state.cleanup_calls, 1);
        assert_eq!(state.cleaned_children, vec![12]);
    }

    #[test]
    fn replayed_commitment_claim_never_releases_a_second_child() {
        let launch = binding(Provider::Codex, 55);
        let shared_state = Rc::new(RefCell::new(FakeState::default()));

        let first = held(launch, Rc::clone(&shared_state), 31)
            .release(authenticated_commitment(commitment(&launch, 160), 32))
            .unwrap();
        let _ = first.into_adopted_parts_for_test();

        let second = held(launch, Rc::clone(&shared_state), 33)
            .release(authenticated_commitment(commitment(&launch, 160), 34));
        assert_eq!(
            second.err(),
            Some(ProviderLaunchCustodyError::ResourceCommitmentReplay)
        );
        let state = shared_state.borrow();
        assert_eq!(state.claim_calls, 2);
        assert_eq!(state.release_calls, 1);
        assert_eq!(state.cleanup_calls, 1);
        assert_eq!(state.cleaned_children, vec![33]);
        assert_eq!(
            state.permanent_holds,
            vec![(
                launch.canonical_sha256().unwrap(),
                PermanentHoldReason::ResourceCommitmentReplay
            )]
        );
    }

    #[test]
    fn source_foundation_is_inert_and_confers_no_product_authority() {
        const {
            assert!(SOURCE_FINAL_EXEC_HELD_LAUNCH_TYPESTATE_IMPLEMENTED);
            assert!(SOURCE_POST_EXEC_FULL_CHAIN_COMPOSITION_IMPLEMENTED);
            assert!(!LEGACY_PROVIDER_LEAF_REQUEST_CONFERS_TOPOLOGY_V2_AUTHORITY);
            assert!(!PRODUCT_LAUNCH_CUSTODY_PRODUCER_AVAILABLE);
            assert!(!PRODUCT_LAUNCH_PROTOCOL_WIRED);
            assert!(!PRODUCT_PROVIDER_RUNTIME_WIRED);
            assert!(!CONFERS_EFFECT_AUTHORITY);
        }

        let source = include_str!("provider_launch_custody.rs");
        let main_source = include_str!("main.rs");
        let live_protocol_source =
            include_str!("../../../crates/trillionnium-privilege-broker-protocol/src/lib.rs");
        assert!(!source.contains(concat!("impl serde::", "Serialize")));
        assert!(!source.contains(concat!("Broker", "Core::")));
        assert!(!source.contains(concat!("std::os::unix::", "net")));
        assert!(!main_source.contains("prepare_final_exec_held_provider_invocation"));
        assert!(!main_source.contains("FinalExecHeldProviderInvocation"));
        assert!(!main_source.contains("compose_broker_post_exec_full_chain"));
        assert!(!main_source.contains("BrokerPostExecFullChainCustody"));
        assert!(!live_protocol_source.contains("FinalExecHeldProviderInvocation"));
        assert!(!live_protocol_source.contains("ReleaseFinalExecHeldProvider"));
        assert!(!live_protocol_source.contains("BrokerPostExecFullChainCustody"));
        assert!(!live_protocol_source.contains("PostExecAuthorityBinding"));
    }
}
