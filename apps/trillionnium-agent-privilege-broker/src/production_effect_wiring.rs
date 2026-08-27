//! Affine composition gate for one future production Direct effect route.
//!
//! The live broker already authenticates one daemon peer, but none of the
//! later authorities required for a phone effect are product-constructible.
//! This module makes that boundary explicit in one ordered type-state:
//!
//! authenticated broker session -> fixed-cgroup custody -> durable allocation
//! -> Android epoch activation -> Android replay ACK -> outer receipt publish.
//!
//! Only the first value is constructed by the live [`crate::BrokerCore`].  The
//! later proof values have private fields and no production constructors. A
//! future verifier must construct each proof directly from retained OS
//! custody; serialised records, digests, model input, environment variables,
//! or caller-selected paths cannot advance this state machine. Consequently
//! The current fixed-cgroup proof is the legacy childless-provider shape: it
//! neither retains the topology-v2 parent plus three child-leaf inventory nor
//! binds the broker subtree reservation independently from daemon attempt
//! generation. It cannot mint a topology-v2 custody proof. Consequently this
//! source checkpoint cannot authorize an effect and does not change the
//! draft-v2 wire protocol's `backend_not_installed` response.

use std::marker::PhantomData;

use thiserror::Error;
use trillionnium_os_types::direct_operation::DirectOperationAdapter;
use trillionnium_privilege_broker_protocol::{Digest, Provider, SessionBinding};

pub(crate) const SOURCE_ORDERED_PRODUCTION_EFFECT_TYPESTATE_IMPLEMENTED: bool = true;
pub(crate) const LIVE_AUTHENTICATED_BROKER_SESSION_RETAINED: bool = true;
pub(crate) const FIXED_CGROUP_CUSTODY_LEGACY_CHILDLESS_TOPOLOGY: bool = true;
pub(crate) const FIXED_CGROUP_CUSTODY_TOPOLOGY_V2_PROOF_AVAILABLE: bool = false;
pub(crate) const PRODUCT_FIXED_CGROUP_PROVENANCE_AVAILABLE: bool = false;
pub(crate) const PRODUCT_ALLOCATION_DELIVERY_AVAILABLE: bool = false;
pub(crate) const PRODUCT_ANDROID_EPOCH_ACTIVATION_AVAILABLE: bool = false;
pub(crate) const PRODUCT_ANDROID_REPLAY_ACK_AVAILABLE: bool = false;
pub(crate) const PRODUCT_OUTER_RECEIPT_PUBLISHER_AVAILABLE: bool = false;
pub(crate) const PRODUCT_EFFECT_WIRING_AVAILABLE: bool = false;
pub(crate) const CONFERS_EFFECT_AUTHORITY: bool = false;

/// Exact promotion inputs still absent from the product graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionPromotionGate {
    AndroidInitFixedCgroupProvenance,
    CompiledSelinuxPolicyIdentity,
    DurableAllocationDeliveryTransport,
    ExternalRollbackHighWater,
    AndroidEpochActivationLauncher,
    AndroidReplayAckLauncher,
    DurableOuterReceiptPublisher,
}

pub(crate) const MISSING_PRODUCT_PROMOTION_GATES: &[ProductionPromotionGate] = &[
    ProductionPromotionGate::AndroidInitFixedCgroupProvenance,
    ProductionPromotionGate::CompiledSelinuxPolicyIdentity,
    ProductionPromotionGate::DurableAllocationDeliveryTransport,
    ProductionPromotionGate::ExternalRollbackHighWater,
    ProductionPromotionGate::AndroidEpochActivationLauncher,
    ProductionPromotionGate::AndroidReplayAckLauncher,
    ProductionPromotionGate::DurableOuterReceiptPublisher,
];

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum ProductionEffectWiringError {
    #[error("production effect route identity drift at {0}")]
    IdentityDrift(&'static str),
    #[error("production effect proof reuses a digest across independent custody domains")]
    DigestDomainCollision,
    #[error("production allocation journal sequence is invalid")]
    InvalidAllocationSequence,
    #[error("Android operation epoch is invalid")]
    InvalidOperationEpoch,
    #[error("Android replay ACK watermark does not cover the durable allocation")]
    ReplayAckWatermarkRollback,
    #[error("outer receipt publication does not cover the authenticated replay ACK")]
    OuterReceiptWatermarkMismatch,
    #[error("product promotion gate remains unavailable: {0:?}")]
    PromotionGateUnavailable(ProductionPromotionGate),
}

/// The product remains fail-closed even when a source test reaches the final
/// type-state. Completion evidence is not permission to perform another
/// effect, and it cannot remove any of these external promotion gates.
pub(crate) fn require_product_promotion() -> Result<(), ProductionEffectWiringError> {
    Err(ProductionEffectWiringError::PromotionGateUnavailable(
        MISSING_PRODUCT_PROMOTION_GATES[0],
    ))
}

/// One authenticated broker session retained after the exact peer policy,
/// measured executable, `SO_PEERCRED`, `SO_PEERSEC`, start-time and challenge
/// binding have all been checked by the live broker core.
///
/// This value is affine and never crosses the wire. The constructor is called
/// only from `BrokerCore::new`; it does not accept a peer identity from a
/// request frame.
#[must_use = "an authenticated production session must remain in broker custody"]
#[derive(Debug)]
pub(crate) struct AuthenticatedBrokerSession {
    session_binding: SessionBinding,
    peer_binding: Digest,
}

impl AuthenticatedBrokerSession {
    pub(super) const fn from_authenticated_broker_core(
        session_binding: SessionBinding,
        peer_binding: Digest,
    ) -> Self {
        Self {
            session_binding,
            peer_binding,
        }
    }

    /// Begin one provider/adapter route only after a future fixed-cgroup
    /// verifier supplies non-serialisable Android-init and SELinux custody.
    pub(crate) fn bind_fixed_cgroup(
        self,
        proof: VerifiedFixedCgroupCustody,
    ) -> Result<ProductionEffectWiring<FixedCgroupCustodied>, ProductionEffectWiringError> {
        if proof.route.session_binding != self.session_binding {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "fixed_cgroup_session_binding",
            ));
        }
        if proof.route.broker_peer_binding != self.peer_binding {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "fixed_cgroup_peer_binding",
            ));
        }
        proof.validate()?;
        Ok(ProductionEffectWiring {
            session_binding: self.session_binding,
            peer_binding: self.peer_binding,
            route: proof.route,
            fixed_cgroup_custody_sha256: proof.custody_sha256,
            allocation: None,
            epoch: None,
            replay_ack: None,
            outer_publication: None,
            _state: PhantomData,
        })
    }
}

/// Closed identity shared by every proof in one effect route.
///
/// It is intentionally not serialisable. A raw binding digest is never a
/// capability; it appears here only inside proof values produced by future
/// retained-custody verifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectEffectRouteIdentity {
    session_binding: SessionBinding,
    broker_peer_binding: Digest,
    provider: Provider,
    adapter: DirectOperationAdapter,
    direct_binding_sha256: Digest,
    provider_attempt_sha256: Digest,
}

/// Sealed result of the legacy fixed provider-leaf reservation plus
/// Android-init and compiled SELinux provenance verification.
///
/// There is deliberately no production constructor. The existing fixed FD
/// opener and durable reservation store retain only the two old childless
/// provider parents; they neither prove the exact topology-v2 child inventory
/// nor init origin, mount and PID namespaces, labels/xattrs, or compiled-policy
/// identity.
#[must_use = "fixed-cgroup custody must be consumed by the allocation route"]
pub(crate) struct VerifiedFixedCgroupCustody {
    route: DirectEffectRouteIdentity,
    boot_id_sha256: Digest,
    leaf_fd_identity_sha256: Digest,
    empty_proof_sha256: Digest,
    reservation_sha256: Digest,
    android_init_provenance_sha256: Digest,
    compiled_selinux_policy_sha256: Digest,
    custody_sha256: Digest,
}

impl VerifiedFixedCgroupCustody {
    fn validate(&self) -> Result<(), ProductionEffectWiringError> {
        require_distinct(&[
            self.route.direct_binding_sha256,
            self.route.provider_attempt_sha256,
            self.boot_id_sha256,
            self.leaf_fd_identity_sha256,
            self.empty_proof_sha256,
            self.reservation_sha256,
            self.android_init_provenance_sha256,
            self.compiled_selinux_policy_sha256,
            self.custody_sha256,
        ])
    }

    #[cfg(test)]
    fn for_test(route: DirectEffectRouteIdentity, digests: [Digest; 7]) -> Self {
        let [boot, leaf, empty, reservation, init, selinux, custody] = digests;
        Self {
            route,
            boot_id_sha256: boot,
            leaf_fd_identity_sha256: leaf,
            empty_proof_sha256: empty,
            reservation_sha256: reservation,
            android_init_provenance_sha256: init,
            compiled_selinux_policy_sha256: selinux,
            custody_sha256: custody,
        }
    }
}

/// Sealed result of the daemon-owned v2 delivery/PREPARED/commit transaction.
///
/// The proof binds the authenticated daemon transport and rollback high-water
/// in addition to the data-only delivery/envelope/receipt hashes. There is no
/// production constructor until that transport and high-water backend exist.
#[must_use = "a durable allocation proof must be consumed by epoch activation"]
pub(crate) struct VerifiedAllocationDelivery {
    route: DirectEffectRouteIdentity,
    os_tool_call_id_sha256: Digest,
    delivery_sha256: Digest,
    envelope_sha256: Digest,
    prepared_ack_sha256: Digest,
    allocation_record_sha256: Digest,
    commit_receipt_sha256: Digest,
    daemon_transport_peer_sha256: Digest,
    rollback_high_water_sha256: Digest,
    journal_sequence: u64,
    adapter_effect_ordinal: u64,
}

impl VerifiedAllocationDelivery {
    fn validate(&self) -> Result<(), ProductionEffectWiringError> {
        if self.journal_sequence == 0 {
            return Err(ProductionEffectWiringError::InvalidAllocationSequence);
        }
        require_distinct(&[
            self.route.direct_binding_sha256,
            self.route.provider_attempt_sha256,
            self.os_tool_call_id_sha256,
            self.delivery_sha256,
            self.envelope_sha256,
            self.prepared_ack_sha256,
            self.allocation_record_sha256,
            self.commit_receipt_sha256,
            self.daemon_transport_peer_sha256,
            self.rollback_high_water_sha256,
        ])
    }

    #[cfg(test)]
    fn for_test(
        route: DirectEffectRouteIdentity,
        digests: [Digest; 8],
        journal_sequence: u64,
        adapter_effect_ordinal: u64,
    ) -> Self {
        let [
            tool_call,
            delivery,
            envelope,
            prepared,
            record,
            receipt,
            peer,
            high_water,
        ] = digests;
        Self {
            route,
            os_tool_call_id_sha256: tool_call,
            delivery_sha256: delivery,
            envelope_sha256: envelope,
            prepared_ack_sha256: prepared,
            allocation_record_sha256: record,
            commit_receipt_sha256: receipt,
            daemon_transport_peer_sha256: peer,
            rollback_high_water_sha256: high_water,
            journal_sequence,
            adapter_effect_ordinal,
        }
    }
}

/// Sealed result of activating the exact Android backend epoch against an
/// external rollback-resistant expectation.
#[must_use = "epoch activation must be consumed by replay acknowledgement"]
pub(crate) struct VerifiedAndroidEpochActivation {
    route: DirectEffectRouteIdentity,
    operation_epoch: [u8; 16],
    allocation_commit_receipt_sha256: Digest,
    activation_authority_sha256: Digest,
    external_high_water_sha256: Digest,
    android_peer_identity_sha256: Digest,
}

impl VerifiedAndroidEpochActivation {
    fn validate(&self) -> Result<(), ProductionEffectWiringError> {
        if self.operation_epoch == [0; 16] {
            return Err(ProductionEffectWiringError::InvalidOperationEpoch);
        }
        require_distinct(&[
            self.route.direct_binding_sha256,
            self.route.provider_attempt_sha256,
            self.allocation_commit_receipt_sha256,
            self.activation_authority_sha256,
            self.external_high_water_sha256,
            self.android_peer_identity_sha256,
        ])
    }

    #[cfg(test)]
    fn for_test(
        route: DirectEffectRouteIdentity,
        operation_epoch: [u8; 16],
        digests: [Digest; 4],
    ) -> Self {
        let [commit_receipt, authority, high_water, peer] = digests;
        Self {
            route,
            operation_epoch,
            allocation_commit_receipt_sha256: commit_receipt,
            activation_authority_sha256: authority,
            external_high_water_sha256: high_water,
            android_peer_identity_sha256: peer,
        }
    }
}

/// Sealed result of one exact Android replay ACK exchange.
#[must_use = "Android replay acknowledgement must be consumed by outer publication"]
pub(crate) struct VerifiedAndroidReplayAck {
    route: DirectEffectRouteIdentity,
    operation_epoch: [u8; 16],
    activation_authority_sha256: Digest,
    external_high_water_sha256: Digest,
    acknowledged_through_sequence: u64,
    acknowledgement_sha256: Digest,
    authenticated_ack_chain_sha256: Digest,
    android_peer_identity_sha256: Digest,
}

impl VerifiedAndroidReplayAck {
    fn validate(&self) -> Result<(), ProductionEffectWiringError> {
        if self.operation_epoch == [0; 16] || self.acknowledged_through_sequence == 0 {
            return Err(ProductionEffectWiringError::InvalidOperationEpoch);
        }
        require_distinct(&[
            self.route.direct_binding_sha256,
            self.route.provider_attempt_sha256,
            self.activation_authority_sha256,
            self.external_high_water_sha256,
            self.acknowledgement_sha256,
            self.authenticated_ack_chain_sha256,
            self.android_peer_identity_sha256,
        ])
    }

    #[cfg(test)]
    fn for_test(
        route: DirectEffectRouteIdentity,
        operation_epoch: [u8; 16],
        acknowledged_through_sequence: u64,
        digests: [Digest; 5],
    ) -> Self {
        let [activation, high_water, acknowledgement, chain, peer] = digests;
        Self {
            route,
            operation_epoch,
            activation_authority_sha256: activation,
            external_high_water_sha256: high_water,
            acknowledged_through_sequence,
            acknowledgement_sha256: acknowledgement,
            authenticated_ack_chain_sha256: chain,
            android_peer_identity_sha256: peer,
        }
    }
}

/// Sealed result of durably publishing one v2 outer receipt and its exact
/// adapter acknowledgement chain.
#[must_use = "outer publication must be consumed into completion evidence"]
pub(crate) struct VerifiedOuterReceiptPublication {
    route: DirectEffectRouteIdentity,
    operation_epoch: [u8; 16],
    acknowledged_through_sequence: u64,
    external_high_water_sha256: Digest,
    android_acknowledgement_sha256: Digest,
    authenticated_ack_chain_sha256: Digest,
    android_peer_identity_sha256: Digest,
    outer_receipt_sha256: Digest,
    outer_ack_sha256: Digest,
    publication_record_sha256: Digest,
    root_publisher_identity_sha256: Digest,
}

impl VerifiedOuterReceiptPublication {
    fn validate(&self) -> Result<(), ProductionEffectWiringError> {
        if self.operation_epoch == [0; 16] || self.acknowledged_through_sequence == 0 {
            return Err(ProductionEffectWiringError::OuterReceiptWatermarkMismatch);
        }
        require_distinct(&[
            self.route.direct_binding_sha256,
            self.route.provider_attempt_sha256,
            self.external_high_water_sha256,
            self.android_acknowledgement_sha256,
            self.authenticated_ack_chain_sha256,
            self.android_peer_identity_sha256,
            self.outer_receipt_sha256,
            self.outer_ack_sha256,
            self.publication_record_sha256,
            self.root_publisher_identity_sha256,
        ])
    }

    #[cfg(test)]
    fn for_test(
        route: DirectEffectRouteIdentity,
        operation_epoch: [u8; 16],
        acknowledged_through_sequence: u64,
        digests: [Digest; 8],
    ) -> Self {
        let [
            high_water,
            android_acknowledgement,
            ack_chain,
            android_peer,
            receipt,
            outer_ack,
            record,
            publisher,
        ] = digests;
        Self {
            route,
            operation_epoch,
            acknowledged_through_sequence,
            external_high_water_sha256: high_water,
            android_acknowledgement_sha256: android_acknowledgement,
            authenticated_ack_chain_sha256: ack_chain,
            android_peer_identity_sha256: android_peer,
            outer_receipt_sha256: receipt,
            outer_ack_sha256: outer_ack,
            publication_record_sha256: record,
            root_publisher_identity_sha256: publisher,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AllocationState {
    journal_sequence: u64,
    adapter_effect_ordinal: u64,
    commit_receipt_sha256: Digest,
    rollback_high_water_sha256: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EpochState {
    operation_epoch: [u8; 16],
    activation_authority_sha256: Digest,
    external_high_water_sha256: Digest,
    android_peer_identity_sha256: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplayAckState {
    operation_epoch: [u8; 16],
    external_high_water_sha256: Digest,
    acknowledged_through_sequence: u64,
    acknowledgement_sha256: Digest,
    authenticated_ack_chain_sha256: Digest,
    android_peer_identity_sha256: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OuterPublicationState {
    outer_receipt_sha256: Digest,
    outer_ack_sha256: Digest,
    publication_record_sha256: Digest,
    root_publisher_identity_sha256: Digest,
}

pub(crate) struct FixedCgroupCustodied;
pub(crate) struct AllocationCommitted;
pub(crate) struct AndroidEpochActivated;
pub(crate) struct AndroidReplayAcknowledged;
pub(crate) struct OuterReceiptPublished;

/// One ordered, affine production wiring attempt.
#[must_use = "dropping an incomplete production wiring attempt cannot authorize an effect"]
pub(crate) struct ProductionEffectWiring<State> {
    session_binding: SessionBinding,
    peer_binding: Digest,
    route: DirectEffectRouteIdentity,
    fixed_cgroup_custody_sha256: Digest,
    allocation: Option<AllocationState>,
    epoch: Option<EpochState>,
    replay_ack: Option<ReplayAckState>,
    outer_publication: Option<OuterPublicationState>,
    _state: PhantomData<State>,
}

impl ProductionEffectWiring<FixedCgroupCustodied> {
    pub(crate) fn commit_allocation(
        self,
        proof: VerifiedAllocationDelivery,
    ) -> Result<ProductionEffectWiring<AllocationCommitted>, ProductionEffectWiringError> {
        require_route(self.route, proof.route, "allocation_delivery")?;
        proof.validate()?;
        Ok(self.advance(
            Some(AllocationState {
                journal_sequence: proof.journal_sequence,
                adapter_effect_ordinal: proof.adapter_effect_ordinal,
                commit_receipt_sha256: proof.commit_receipt_sha256,
                rollback_high_water_sha256: proof.rollback_high_water_sha256,
            }),
            None,
            None,
            None,
        ))
    }
}

impl ProductionEffectWiring<AllocationCommitted> {
    pub(crate) fn activate_android_epoch(
        self,
        proof: VerifiedAndroidEpochActivation,
    ) -> Result<ProductionEffectWiring<AndroidEpochActivated>, ProductionEffectWiringError> {
        require_route(self.route, proof.route, "android_epoch_activation")?;
        proof.validate()?;
        let allocation = self.allocation.expect("type-state retains allocation");
        if proof.allocation_commit_receipt_sha256 != allocation.commit_receipt_sha256 {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "android_epoch_allocation_commit_receipt",
            ));
        }
        if proof.external_high_water_sha256 != allocation.rollback_high_water_sha256 {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "android_epoch_external_high_water",
            ));
        }
        Ok(self.advance(
            Some(allocation),
            Some(EpochState {
                operation_epoch: proof.operation_epoch,
                activation_authority_sha256: proof.activation_authority_sha256,
                external_high_water_sha256: proof.external_high_water_sha256,
                android_peer_identity_sha256: proof.android_peer_identity_sha256,
            }),
            None,
            None,
        ))
    }
}

impl ProductionEffectWiring<AndroidEpochActivated> {
    pub(crate) fn acknowledge_android_replay(
        self,
        proof: VerifiedAndroidReplayAck,
    ) -> Result<ProductionEffectWiring<AndroidReplayAcknowledged>, ProductionEffectWiringError>
    {
        require_route(self.route, proof.route, "android_replay_ack")?;
        proof.validate()?;
        let allocation = self.allocation.expect("type-state retains allocation");
        let epoch = self.epoch.expect("type-state retains activated epoch");
        if proof.operation_epoch != epoch.operation_epoch {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "android_replay_ack_epoch",
            ));
        }
        if proof.activation_authority_sha256 != epoch.activation_authority_sha256 {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "android_replay_ack_activation_authority",
            ));
        }
        if proof.external_high_water_sha256 != epoch.external_high_water_sha256 {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "android_replay_ack_external_high_water",
            ));
        }
        if proof.android_peer_identity_sha256 != epoch.android_peer_identity_sha256 {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "android_replay_ack_android_peer",
            ));
        }
        if proof.acknowledged_through_sequence < allocation.journal_sequence {
            return Err(ProductionEffectWiringError::ReplayAckWatermarkRollback);
        }
        Ok(self.advance(
            Some(allocation),
            Some(epoch),
            Some(ReplayAckState {
                operation_epoch: proof.operation_epoch,
                external_high_water_sha256: proof.external_high_water_sha256,
                acknowledged_through_sequence: proof.acknowledged_through_sequence,
                acknowledgement_sha256: proof.acknowledgement_sha256,
                authenticated_ack_chain_sha256: proof.authenticated_ack_chain_sha256,
                android_peer_identity_sha256: proof.android_peer_identity_sha256,
            }),
            None,
        ))
    }
}

impl ProductionEffectWiring<AndroidReplayAcknowledged> {
    pub(crate) fn publish_outer_receipt(
        self,
        proof: VerifiedOuterReceiptPublication,
    ) -> Result<ProductionEffectWiring<OuterReceiptPublished>, ProductionEffectWiringError> {
        require_route(self.route, proof.route, "outer_receipt_publication")?;
        proof.validate()?;
        let replay_ack = self.replay_ack.expect("type-state retains replay ACK");
        if proof.acknowledged_through_sequence != replay_ack.acknowledged_through_sequence {
            return Err(ProductionEffectWiringError::OuterReceiptWatermarkMismatch);
        }
        if proof.operation_epoch != replay_ack.operation_epoch {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "outer_receipt_operation_epoch",
            ));
        }
        if proof.external_high_water_sha256 != replay_ack.external_high_water_sha256 {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "outer_receipt_external_high_water",
            ));
        }
        if proof.android_acknowledgement_sha256 != replay_ack.acknowledgement_sha256 {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "outer_receipt_android_acknowledgement",
            ));
        }
        if proof.authenticated_ack_chain_sha256 != replay_ack.authenticated_ack_chain_sha256 {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "outer_receipt_authenticated_ack_chain",
            ));
        }
        if proof.android_peer_identity_sha256 != replay_ack.android_peer_identity_sha256 {
            return Err(ProductionEffectWiringError::IdentityDrift(
                "outer_receipt_android_peer",
            ));
        }
        let allocation = self.allocation;
        let epoch = self.epoch;
        Ok(self.advance(
            allocation,
            epoch,
            Some(replay_ack),
            Some(OuterPublicationState {
                outer_receipt_sha256: proof.outer_receipt_sha256,
                outer_ack_sha256: proof.outer_ack_sha256,
                publication_record_sha256: proof.publication_record_sha256,
                root_publisher_identity_sha256: proof.root_publisher_identity_sha256,
            }),
        ))
    }
}

impl ProductionEffectWiring<OuterReceiptPublished> {
    /// Consume the final type-state into evidence suitable for a future
    /// lifecycle adopter. This value records completion only; the global
    /// product promotion gate still returns HOLD.
    pub(crate) fn into_completion_evidence(self) -> ProductionEffectCompletionEvidence {
        ProductionEffectCompletionEvidence {
            session_binding: self.session_binding,
            peer_binding: self.peer_binding,
            provider: self.route.provider,
            adapter: self.route.adapter,
            direct_binding_sha256: self.route.direct_binding_sha256,
            provider_attempt_sha256: self.route.provider_attempt_sha256,
            fixed_cgroup_custody_sha256: self.fixed_cgroup_custody_sha256,
            allocation: self.allocation.expect("type-state retains allocation"),
            epoch: self.epoch.expect("type-state retains activated epoch"),
            replay_ack: self.replay_ack.expect("type-state retains replay ACK"),
            outer_publication: self
                .outer_publication
                .expect("type-state retains outer publication"),
        }
    }
}

impl<State> ProductionEffectWiring<State> {
    fn advance<Next>(
        self,
        allocation: Option<AllocationState>,
        epoch: Option<EpochState>,
        replay_ack: Option<ReplayAckState>,
        outer_publication: Option<OuterPublicationState>,
    ) -> ProductionEffectWiring<Next> {
        ProductionEffectWiring {
            session_binding: self.session_binding,
            peer_binding: self.peer_binding,
            route: self.route,
            fixed_cgroup_custody_sha256: self.fixed_cgroup_custody_sha256,
            allocation,
            epoch,
            replay_ack,
            outer_publication,
            _state: PhantomData,
        }
    }
}

/// Complete ordered evidence retained for a future lifecycle adopter.
///
/// It is neither serialisable nor cloneable and deliberately exposes no
/// execute, resume, socket, FD, path, PID, or acknowledgement method.
#[must_use = "completion evidence must remain in the future lifecycle adopter's custody"]
pub(crate) struct ProductionEffectCompletionEvidence {
    session_binding: SessionBinding,
    peer_binding: Digest,
    provider: Provider,
    adapter: DirectOperationAdapter,
    direct_binding_sha256: Digest,
    provider_attempt_sha256: Digest,
    fixed_cgroup_custody_sha256: Digest,
    allocation: AllocationState,
    epoch: EpochState,
    replay_ack: ReplayAckState,
    outer_publication: OuterPublicationState,
}

fn require_route(
    expected: DirectEffectRouteIdentity,
    observed: DirectEffectRouteIdentity,
    stage: &'static str,
) -> Result<(), ProductionEffectWiringError> {
    if expected != observed {
        return Err(ProductionEffectWiringError::IdentityDrift(stage));
    }
    Ok(())
}

fn require_distinct(values: &[Digest]) -> Result<(), ProductionEffectWiringError> {
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(ProductionEffectWiringError::DigestDomainCollision);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trillionnium_privilege_broker_protocol::FixedBytes32;

    const _: () = {
        assert!(SOURCE_ORDERED_PRODUCTION_EFFECT_TYPESTATE_IMPLEMENTED);
        assert!(LIVE_AUTHENTICATED_BROKER_SESSION_RETAINED);
        assert!(FIXED_CGROUP_CUSTODY_LEGACY_CHILDLESS_TOPOLOGY);
        assert!(!FIXED_CGROUP_CUSTODY_TOPOLOGY_V2_PROOF_AVAILABLE);
        assert!(!PRODUCT_FIXED_CGROUP_PROVENANCE_AVAILABLE);
        assert!(!PRODUCT_ALLOCATION_DELIVERY_AVAILABLE);
        assert!(!PRODUCT_ANDROID_EPOCH_ACTIVATION_AVAILABLE);
        assert!(!PRODUCT_ANDROID_REPLAY_ACK_AVAILABLE);
        assert!(!PRODUCT_OUTER_RECEIPT_PUBLISHER_AVAILABLE);
        assert!(!PRODUCT_EFFECT_WIRING_AVAILABLE);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    };

    fn digest(seed: u8) -> Digest {
        Digest::new(FixedBytes32::new([seed; 32]).unwrap())
    }

    fn session(seed: u8) -> AuthenticatedBrokerSession {
        AuthenticatedBrokerSession::from_authenticated_broker_core(
            SessionBinding::new(FixedBytes32::new([seed; 32]).unwrap()),
            digest(seed + 1),
        )
    }

    fn route(
        session_seed: u8,
        provider: Provider,
        adapter: DirectOperationAdapter,
    ) -> DirectEffectRouteIdentity {
        DirectEffectRouteIdentity {
            session_binding: SessionBinding::new(FixedBytes32::new([session_seed; 32]).unwrap()),
            broker_peer_binding: digest(session_seed + 1),
            provider,
            adapter,
            direct_binding_sha256: digest(3),
            provider_attempt_sha256: digest(4),
        }
    }

    fn cgroup(route: DirectEffectRouteIdentity) -> VerifiedFixedCgroupCustody {
        VerifiedFixedCgroupCustody::for_test(
            route,
            [
                digest(5),
                digest(6),
                digest(7),
                digest(8),
                digest(9),
                digest(10),
                digest(11),
            ],
        )
    }

    fn allocation(route: DirectEffectRouteIdentity, sequence: u64) -> VerifiedAllocationDelivery {
        VerifiedAllocationDelivery::for_test(
            route,
            [
                digest(12),
                digest(13),
                digest(14),
                digest(15),
                digest(16),
                digest(17),
                digest(18),
                digest(19),
            ],
            sequence,
            0,
        )
    }

    fn epoch(route: DirectEffectRouteIdentity, value: u8) -> VerifiedAndroidEpochActivation {
        VerifiedAndroidEpochActivation::for_test(
            route,
            [value; 16],
            [digest(17), digest(20), digest(19), digest(22)],
        )
    }

    fn replay(
        route: DirectEffectRouteIdentity,
        epoch: u8,
        through: u64,
    ) -> VerifiedAndroidReplayAck {
        VerifiedAndroidReplayAck::for_test(
            route,
            [epoch; 16],
            through,
            [digest(20), digest(19), digest(23), digest(24), digest(22)],
        )
    }

    fn outer(route: DirectEffectRouteIdentity, through: u64) -> VerifiedOuterReceiptPublication {
        VerifiedOuterReceiptPublication::for_test(
            route,
            [31; 16],
            through,
            [
                digest(19),
                digest(23),
                digest(24),
                digest(22),
                digest(26),
                digest(27),
                digest(28),
                digest(29),
            ],
        )
    }

    fn through_replay(
        route: DirectEffectRouteIdentity,
        sequence: u64,
        through: u64,
    ) -> ProductionEffectWiring<AndroidReplayAcknowledged> {
        through_epoch(route, sequence, 31)
            .acknowledge_android_replay(replay(route, 31, through))
            .unwrap()
    }

    fn through_allocation(
        route: DirectEffectRouteIdentity,
        sequence: u64,
    ) -> ProductionEffectWiring<AllocationCommitted> {
        AuthenticatedBrokerSession::from_authenticated_broker_core(
            route.session_binding,
            route.broker_peer_binding,
        )
        .bind_fixed_cgroup(cgroup(route))
        .unwrap()
        .commit_allocation(allocation(route, sequence))
        .unwrap()
    }

    fn through_epoch(
        route: DirectEffectRouteIdentity,
        sequence: u64,
        epoch_value: u8,
    ) -> ProductionEffectWiring<AndroidEpochActivated> {
        through_allocation(route, sequence)
            .activate_android_epoch(epoch(route, epoch_value))
            .unwrap()
    }

    #[test]
    fn exact_ordered_chain_reaches_completion_without_promoting_product() {
        let route = route(1, Provider::Codex, DirectOperationAdapter::SystemApi);
        let completed = through_replay(route, 7, 9)
            .publish_outer_receipt(outer(route, 9))
            .unwrap()
            .into_completion_evidence();

        assert_eq!(completed.provider, Provider::Codex);
        assert_eq!(completed.adapter, DirectOperationAdapter::SystemApi);
        assert_eq!(completed.allocation.journal_sequence, 7);
        assert_eq!(completed.allocation.adapter_effect_ordinal, 0);
        assert_eq!(completed.epoch.operation_epoch, [31; 16]);
        assert_eq!(completed.replay_ack.acknowledged_through_sequence, 9);
        assert_eq!(completed.outer_publication.outer_receipt_sha256, digest(26));
        assert!(matches!(
            require_product_promotion(),
            Err(ProductionEffectWiringError::PromotionGateUnavailable(
                ProductionPromotionGate::AndroidInitFixedCgroupProvenance
            ))
        ));
    }

    #[test]
    fn every_cross_stage_binding_or_adapter_drift_fails_closed() {
        let codex_system = route(32, Provider::Codex, DirectOperationAdapter::SystemApi);
        let mut other_binding = codex_system;
        other_binding.direct_binding_sha256 = digest(99);
        let codex_accessibility = route(32, Provider::Codex, DirectOperationAdapter::Accessibility);

        let cgroup_bound = session(32).bind_fixed_cgroup(cgroup(codex_system)).unwrap();
        assert_eq!(
            cgroup_bound
                .commit_allocation(allocation(other_binding, 1))
                .err(),
            Some(ProductionEffectWiringError::IdentityDrift(
                "allocation_delivery"
            ))
        );

        let allocated = session(32)
            .bind_fixed_cgroup(cgroup(codex_system))
            .unwrap()
            .commit_allocation(allocation(codex_system, 1))
            .unwrap();
        assert_eq!(
            allocated
                .activate_android_epoch(epoch(codex_accessibility, 1))
                .err(),
            Some(ProductionEffectWiringError::IdentityDrift(
                "android_epoch_activation"
            ))
        );

        let epoch_active = session(32)
            .bind_fixed_cgroup(cgroup(codex_system))
            .unwrap()
            .commit_allocation(allocation(codex_system, 1))
            .unwrap()
            .activate_android_epoch(epoch(codex_system, 1))
            .unwrap();
        assert_eq!(
            epoch_active
                .acknowledge_android_replay(replay(other_binding, 1, 1))
                .err(),
            Some(ProductionEffectWiringError::IdentityDrift(
                "android_replay_ack"
            ))
        );

        assert_eq!(
            through_replay(codex_system, 1, 1)
                .publish_outer_receipt(outer(codex_accessibility, 1))
                .err(),
            Some(ProductionEffectWiringError::IdentityDrift(
                "outer_receipt_publication"
            ))
        );
    }

    #[test]
    fn replay_and_outer_watermarks_cannot_roll_back_or_skip() {
        let route = route(35, Provider::Codex, DirectOperationAdapter::Accessibility);
        let epoch_active = session(35)
            .bind_fixed_cgroup(cgroup(route))
            .unwrap()
            .commit_allocation(allocation(route, 8))
            .unwrap()
            .activate_android_epoch(epoch(route, 2))
            .unwrap();
        assert_eq!(
            epoch_active
                .acknowledge_android_replay(replay(route, 2, 7))
                .err(),
            Some(ProductionEffectWiringError::ReplayAckWatermarkRollback)
        );

        assert_eq!(
            through_replay(route, 8, 10)
                .publish_outer_receipt(outer(route, 11))
                .err(),
            Some(ProductionEffectWiringError::OuterReceiptWatermarkMismatch)
        );
    }

    #[test]
    fn session_and_every_cross_stage_custody_value_are_exactly_bound() {
        let route = route(50, Provider::Codex, DirectOperationAdapter::SystemApi);
        assert_eq!(
            session(51).bind_fixed_cgroup(cgroup(route)).err(),
            Some(ProductionEffectWiringError::IdentityDrift(
                "fixed_cgroup_session_binding"
            ))
        );

        let mut peer_drift = route;
        peer_drift.broker_peer_binding = digest(52);
        assert_eq!(
            session(50).bind_fixed_cgroup(cgroup(peer_drift)).err(),
            Some(ProductionEffectWiringError::IdentityDrift(
                "fixed_cgroup_peer_binding"
            ))
        );

        let mut cross_session_route = route;
        cross_session_route.session_binding =
            SessionBinding::new(FixedBytes32::new([51; 32]).unwrap());
        cross_session_route.broker_peer_binding = digest(52);
        assert_eq!(
            session(50)
                .bind_fixed_cgroup(cgroup(route))
                .unwrap()
                .commit_allocation(allocation(cross_session_route, 7))
                .err(),
            Some(ProductionEffectWiringError::IdentityDrift(
                "allocation_delivery"
            ))
        );

        let mut wrong_epoch_commit = epoch(route, 31);
        wrong_epoch_commit.allocation_commit_receipt_sha256 = digest(30);
        assert_eq!(
            through_allocation(route, 7)
                .activate_android_epoch(wrong_epoch_commit)
                .err(),
            Some(ProductionEffectWiringError::IdentityDrift(
                "android_epoch_allocation_commit_receipt"
            ))
        );

        let mut wrong_epoch_high_water = epoch(route, 31);
        wrong_epoch_high_water.external_high_water_sha256 = digest(30);
        assert_eq!(
            through_allocation(route, 7)
                .activate_android_epoch(wrong_epoch_high_water)
                .err(),
            Some(ProductionEffectWiringError::IdentityDrift(
                "android_epoch_external_high_water"
            ))
        );

        for (stage, mutate) in [
            ("android_replay_ack_activation_authority", 0_u8),
            ("android_replay_ack_external_high_water", 1_u8),
            ("android_replay_ack_android_peer", 2_u8),
        ] {
            let mut proof = replay(route, 31, 7);
            match mutate {
                0 => proof.activation_authority_sha256 = digest(30),
                1 => proof.external_high_water_sha256 = digest(30),
                2 => proof.android_peer_identity_sha256 = digest(30),
                _ => unreachable!(),
            }
            assert_eq!(
                through_epoch(route, 7, 31)
                    .acknowledge_android_replay(proof)
                    .err(),
                Some(ProductionEffectWiringError::IdentityDrift(stage))
            );
        }

        for (stage, mutate) in [
            ("outer_receipt_operation_epoch", 0_u8),
            ("outer_receipt_external_high_water", 1_u8),
            ("outer_receipt_android_acknowledgement", 2_u8),
            ("outer_receipt_authenticated_ack_chain", 3_u8),
            ("outer_receipt_android_peer", 4_u8),
        ] {
            let mut proof = outer(route, 7);
            match mutate {
                0 => proof.operation_epoch = [30; 16],
                1 => proof.external_high_water_sha256 = digest(30),
                2 => proof.android_acknowledgement_sha256 = digest(30),
                3 => proof.authenticated_ack_chain_sha256 = digest(30),
                4 => proof.android_peer_identity_sha256 = digest(30),
                _ => unreachable!(),
            }
            assert_eq!(
                through_replay(route, 7, 7)
                    .publish_outer_receipt(proof)
                    .err(),
                Some(ProductionEffectWiringError::IdentityDrift(stage))
            );
        }
    }

    #[test]
    fn reused_placeholder_digest_is_not_accepted_as_cross_domain_proof() {
        let route = route(41, Provider::Codex, DirectOperationAdapter::SystemApi);
        let repeated = digest(40);
        let proof = VerifiedFixedCgroupCustody::for_test(route, [repeated; 7]);
        assert_eq!(
            session(41).bind_fixed_cgroup(proof).err(),
            Some(ProductionEffectWiringError::DigestDomainCollision)
        );
    }

    #[test]
    fn product_flags_and_promotion_inventory_remain_explicitly_closed() {
        assert_eq!(MISSING_PRODUCT_PROMOTION_GATES.len(), 7);
    }
}
