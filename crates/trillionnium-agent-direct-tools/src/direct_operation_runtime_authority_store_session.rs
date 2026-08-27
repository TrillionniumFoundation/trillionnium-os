//! Opaque same-store core for the future operation runtime authority.
//!
//! This module deliberately has no product constructor, transport, listener,
//! or effect-authorizing output. Its production backend is uninhabited. The
//! in-memory backend exists only in tests so the first-use state machine and
//! the atomic first-use/restart handoffs can be exercised without promoting
//! bare mutation-CAS ABI records into authority.

use std::convert::Infallible;

#[cfg(test)]
use trillionnium_os_types::agent_principal_registry::CODEX_STABLE_PRINCIPAL;
use trillionnium_os_types::direct_operation_runtime_authority_mutation_cas as cas;

enum AuthorityStoreBackend {
    Product(Infallible),
    #[cfg(test)]
    Test(TestAuthorityStore),
}

/// An authority-store session before the store has accepted a first-use
/// candidate. There is intentionally no product constructor.
pub(crate) struct UnprovisionedAuthorityStoreSession {
    backend: AuthorityStoreBackend,
}

/// Same-store continuation after the authority issued the candidate nonce.
pub(crate) struct CandidateAuthorityStoreSession {
    backend: AuthorityStoreBackend,
    anchor: cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    candidate: cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1,
}

/// Same-store continuation after the authority durably accepted PREPARED.
pub(crate) struct PreparedAuthorityStoreSession {
    backend: AuthorityStoreBackend,
    anchor: cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    candidate: cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1,
    prepared: cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1,
}

/// Move-only proof that one store atomically persisted and read back the full
/// first-use lineage and the exact generation-one empty snapshot.
///
/// The backend is retained inside the capability. A consumer can therefore
/// perform a fresh observation only against the store that minted it; no API
/// accepts a replacement backend.
pub(crate) struct SealedFirstUseGenesisCommit {
    backend: AuthorityStoreBackend,
    lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    committed_head: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
}

/// Only this post-OBSERVE typestate may eventually be consumed by the
/// mutation-CAS client. Keeping it distinct prevents an unobserved COMMIT
/// result from being mistaken for an active generation-one session.
pub(crate) struct FreshlyObservedFirstUseGenesis {
    backend: AuthorityStoreBackend,
    lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    committed_head: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
}

/// One replay decision prepared by the same authority store that owns the
/// first-use lineage and the current mutation head. The embedded backend is
/// move-only; bare lineage/head/snapshot records cannot construct this type.
pub(crate) struct PreparedReplayAuthorityStoreSession {
    backend: AuthorityStoreBackend,
    lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    committed_head: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
}

/// Replay authority after a second exact observation made after the local
/// journal open. This is the only replay typestate accepted by the mutation
/// CAS client.
pub(crate) struct FreshlyObservedReplayAuthorityStore {
    backend: AuthorityStoreBackend,
    lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    committed_head: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
}

/// Affine same-store backend after an exact first-use or replay observation
/// has been consumed.
///
/// `session_seed_committed_head` is read exactly once by the mutation client
/// while constructing its initial committed typestate. Mutation calls never
/// compare live state with that frozen seed: every verb validates its request
/// against the current record held by the same embedded store.
pub(crate) struct ActiveAuthorityStoreSession {
    backend: AuthorityStoreBackend,
    first_use_lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    session_seed_committed_head: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
}

/// Test-only persistent authority service handle. Cloning this handle models
/// reconnecting to the same external store after an adapter process restart;
/// it is not itself an active mutation session.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestReplayAuthorityStore {
    backend: TestAuthorityStore,
    lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityStoreSessionError {
    BackendUnavailable,
    PolicyMismatch,
    StateMismatch,
    InvalidRecord,
    OutcomeUnknown,
    FreshObservationMismatch,
}

pub(crate) type StoreResult<T> = Result<T, AuthorityStoreSessionError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityStoreMutationCallFailure {
    NotApplied,
    Denied,
    OutcomeUnknown,
}

pub(crate) type MutationStoreCall<T> = Result<T, AuthorityStoreMutationCallFailure>;

impl UnprovisionedAuthorityStoreSession {
    pub(crate) fn issue_candidate(
        self,
        _anchor: cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    ) -> StoreResult<CandidateAuthorityStoreSession> {
        match self.backend {
            AuthorityStoreBackend::Product(never) => match never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                let candidate = store.issue_candidate_and_read(&_anchor)?;
                Ok(CandidateAuthorityStoreSession {
                    backend: AuthorityStoreBackend::Test(store),
                    anchor: _anchor,
                    candidate,
                })
            }
        }
    }
}

impl CandidateAuthorityStoreSession {
    pub(crate) fn candidate(&self) -> &cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1 {
        &self.candidate
    }

    pub(crate) fn prepare(
        self,
        anchor: &cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
        candidate: &cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1,
    ) -> StoreResult<PreparedAuthorityStoreSession> {
        if anchor != &self.anchor || candidate != &self.candidate {
            return Err(AuthorityStoreSessionError::StateMismatch);
        }
        match self.backend {
            AuthorityStoreBackend::Product(never) => match never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                let prepared = store.prepare_and_read(anchor, candidate)?;
                Ok(PreparedAuthorityStoreSession {
                    backend: AuthorityStoreBackend::Test(store),
                    anchor: self.anchor,
                    candidate: self.candidate,
                    prepared,
                })
            }
        }
    }
}

impl PreparedAuthorityStoreSession {
    pub(crate) fn prepared(&self) -> &cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1 {
        &self.prepared
    }

    pub(crate) fn commit(
        self,
        anchor: &cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
        candidate: &cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1,
        prepared: &cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1,
        _durable_commit_evidence_sha256: String,
    ) -> StoreResult<SealedFirstUseGenesisCommit> {
        if anchor != &self.anchor || candidate != &self.candidate || prepared != &self.prepared {
            return Err(AuthorityStoreSessionError::StateMismatch);
        }
        match self.backend {
            AuthorityStoreBackend::Product(never) => match never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                let stored = store.commit_and_mint(
                    anchor,
                    candidate,
                    prepared,
                    _durable_commit_evidence_sha256,
                )?;
                validate_exact_genesis_record(&stored)?;
                Ok(SealedFirstUseGenesisCommit {
                    backend: AuthorityStoreBackend::Test(store),
                    lineage: stored.lineage,
                    committed_head: stored.committed_head,
                    snapshot: stored.snapshot,
                })
            }
        }
    }
}

impl SealedFirstUseGenesisCommit {
    /// Consume the one-shot capability and compare it with a fresh observation
    /// from its embedded backend. An advanced, forked, pending, or substituted
    /// store is rejected; the caller cannot supply a different backend.
    pub(crate) fn into_freshly_observed(self) -> StoreResult<FreshlyObservedFirstUseGenesis> {
        match self.backend {
            AuthorityStoreBackend::Product(never) => match never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                let observed = store.observe_committed()?;
                observed.lineage.validate().map_err(invalid_record)?;
                observed
                    .committed_head
                    .validate(&observed.lineage)
                    .map_err(invalid_record)?;
                observed
                    .snapshot
                    .validate(&observed.lineage)
                    .map_err(invalid_record)?;
                if observed.lineage != self.lineage
                    || observed.committed_head != self.committed_head
                    || observed.snapshot != self.snapshot
                    || observed.snapshot.prepared_slot
                        != cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty
                {
                    return Err(AuthorityStoreSessionError::FreshObservationMismatch);
                }
                Ok(FreshlyObservedFirstUseGenesis {
                    backend: AuthorityStoreBackend::Test(store),
                    lineage: self.lineage,
                    committed_head: self.committed_head,
                    snapshot: self.snapshot,
                })
            }
        }
    }

    pub(crate) fn lineage(&self) -> &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1 {
        &self.lineage
    }

    pub(crate) fn committed_head(&self) -> &cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
        &self.committed_head
    }

    pub(crate) fn snapshot(&self) -> &cas::DirectOperationRuntimeAuthoritySnapshotV1 {
        &self.snapshot
    }

    #[cfg(test)]
    pub(crate) fn replay_authority_store_for_test(&self) -> TestReplayAuthorityStore {
        let backend = match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => store.clone(),
        };
        TestReplayAuthorityStore {
            backend,
            lineage: self.lineage.clone(),
        }
    }
}

impl FreshlyObservedFirstUseGenesis {
    pub(crate) fn lineage(&self) -> &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1 {
        &self.lineage
    }

    pub(crate) fn committed_head(&self) -> &cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
        &self.committed_head
    }

    pub(crate) fn snapshot(&self) -> &cas::DirectOperationRuntimeAuthoritySnapshotV1 {
        &self.snapshot
    }

    /// Consume the fresh genesis observation into the long-lived same-store
    /// backend. The final locked comparison happens during the move, so a
    /// caller cannot detach the backend from the records it observed.
    pub(crate) fn into_active_mutation_store(self) -> StoreResult<ActiveAuthorityStoreSession> {
        let Self {
            backend,
            lineage: _lineage,
            committed_head: _committed_head,
            snapshot: _snapshot,
        } = self;
        match backend {
            AuthorityStoreBackend::Product(never) => match never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                {
                    let state = store
                        .state
                        .lock()
                        .map_err(|_| AuthorityStoreSessionError::BackendUnavailable)?;
                    let TestAuthorityStorePhase::Committed {
                        record,
                        capability_minted,
                    } = &state.phase
                    else {
                        return Err(AuthorityStoreSessionError::StateMismatch);
                    };
                    validate_exact_genesis_record(record)?;
                    if !*capability_minted
                        || record.lineage != _lineage
                        || record.committed_head != _committed_head
                        || record.snapshot != _snapshot
                        || state.mutation_pending.is_some()
                        || state.mutation_reconcile_required_transaction.is_some()
                    {
                        return Err(AuthorityStoreSessionError::FreshObservationMismatch);
                    }
                }
                Ok(ActiveAuthorityStoreSession {
                    backend: AuthorityStoreBackend::Test(store),
                    first_use_lineage: _lineage,
                    session_seed_committed_head: _committed_head,
                })
            }
        }
    }
}

#[cfg(test)]
impl TestReplayAuthorityStore {
    /// Seal one current store observation into the replay decision. The
    /// decision will re-observe this exact state after the local runtime open.
    pub(crate) fn prepare(self) -> StoreResult<PreparedReplayAuthorityStoreSession> {
        let record = self.backend.observe_committed()?;
        validate_committed_store_record(&record)?;
        if record.lineage != self.lineage {
            return Err(AuthorityStoreSessionError::FreshObservationMismatch);
        }
        Ok(PreparedReplayAuthorityStoreSession {
            backend: AuthorityStoreBackend::Test(self.backend),
            lineage: record.lineage,
            committed_head: record.committed_head,
            snapshot: record.snapshot,
        })
    }
}

impl PreparedReplayAuthorityStoreSession {
    pub(crate) fn lineage(&self) -> &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1 {
        &self.lineage
    }

    pub(crate) fn committed_head(&self) -> &cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
        &self.committed_head
    }

    pub(crate) fn snapshot(&self) -> &cas::DirectOperationRuntimeAuthoritySnapshotV1 {
        &self.snapshot
    }

    /// Re-observe the same store after local pathname custody was opened and
    /// compare the complete lineage/head/snapshot before releasing authority.
    pub(crate) fn into_freshly_observed(self) -> StoreResult<FreshlyObservedReplayAuthorityStore> {
        let Self {
            backend,
            lineage: _lineage,
            committed_head: _committed_head,
            snapshot: _snapshot,
        } = self;
        match backend {
            AuthorityStoreBackend::Product(never) => match never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                let observed = store.observe_committed()?;
                validate_committed_store_record(&observed)?;
                if observed.lineage != _lineage
                    || observed.committed_head != _committed_head
                    || observed.snapshot != _snapshot
                {
                    return Err(AuthorityStoreSessionError::FreshObservationMismatch);
                }
                Ok(FreshlyObservedReplayAuthorityStore {
                    backend: AuthorityStoreBackend::Test(store),
                    lineage: _lineage,
                    committed_head: _committed_head,
                    snapshot: _snapshot,
                })
            }
        }
    }
}

impl FreshlyObservedReplayAuthorityStore {
    pub(crate) fn lineage(&self) -> &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1 {
        &self.lineage
    }

    pub(crate) fn committed_head(&self) -> &cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
        &self.committed_head
    }

    pub(crate) fn snapshot(&self) -> &cas::DirectOperationRuntimeAuthoritySnapshotV1 {
        &self.snapshot
    }

    pub(crate) fn into_active_mutation_store(self) -> StoreResult<ActiveAuthorityStoreSession> {
        let Self {
            backend,
            lineage: _lineage,
            committed_head: _committed_head,
            snapshot: _snapshot,
        } = self;
        match backend {
            AuthorityStoreBackend::Product(never) => match never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                let observed = store.observe_committed()?;
                validate_committed_store_record(&observed)?;
                if observed.lineage != _lineage
                    || observed.committed_head != _committed_head
                    || observed.snapshot != _snapshot
                {
                    return Err(AuthorityStoreSessionError::FreshObservationMismatch);
                }
                Ok(ActiveAuthorityStoreSession {
                    backend: AuthorityStoreBackend::Test(store),
                    first_use_lineage: _lineage,
                    session_seed_committed_head: _committed_head,
                })
            }
        }
    }
}

impl ActiveAuthorityStoreSession {
    pub(crate) fn first_use_lineage(
        &self,
    ) -> &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1 {
        &self.first_use_lineage
    }

    pub(crate) fn session_seed_committed_head(
        &self,
    ) -> &cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
        &self.session_seed_committed_head
    }

    pub(crate) fn mutation_request_nonce(
        &self,
        _phase: &'static str,
        _binding_sha256: &str,
    ) -> MutationStoreCall<String> {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                store.mutation_request_nonce(_phase, _binding_sha256, &self.first_use_lineage)
            }
        }
    }

    pub(crate) fn prepare_mutation_head(
        &self,
        _request: &cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
    ) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityPrepareReceiptV1> {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                store.prepare_mutation_head(&self.first_use_lineage, _request)
            }
        }
    }

    pub(crate) fn commit_mutation_head(
        &self,
        _request: &cas::DirectOperationRuntimeAuthorityCommitRequestV1,
    ) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityCommitReceiptV1> {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                store.commit_mutation_head(&self.first_use_lineage, _request)
            }
        }
    }

    pub(crate) fn observe_mutation_head(
        &self,
        _request: &cas::DirectOperationRuntimeAuthorityObserveRequestV1,
    ) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityObserveResponseV1> {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                store.observe_mutation_head(&self.first_use_lineage, _request)
            }
        }
    }

    pub(crate) fn reconcile_mutation_head(
        &self,
        _request: &cas::DirectOperationRuntimeAuthorityReconcileRequestV1,
    ) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityReconcileResponseV1> {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => {
                store.reconcile_mutation_head(&self.first_use_lineage, _request)
            }
        }
    }

    /// Confirm a restart observation in which the durable local sidecar names
    /// a mutation that the same store already committed. The caller supplies
    /// the deterministic prepared record, never a reconstructed predecessor
    /// committed head; the store independently binds it to its live successor
    /// before clearing any exact commit-unknown recovery marker.
    pub(crate) fn confirm_replayed_committed_mutation(
        &self,
        _intent: &cas::DirectOperationRuntimeAuthorityMutationIntentV1,
        _prepared: &cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
    ) -> MutationStoreCall<()> {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            #[cfg(test)]
            AuthorityStoreBackend::Test(store) => store.confirm_replayed_committed_mutation(
                &self.first_use_lineage,
                &self.session_seed_committed_head,
                _intent,
                _prepared,
            ),
        }
    }
}

fn validate_exact_genesis_record(record: &CommittedStoreRecord) -> StoreResult<()> {
    validate_committed_store_record(record)?;
    let expected_ancestry = cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Genesis {
        first_use_committed_result_binding_sha256: record
            .lineage
            .committed_result_binding
            .first_use_committed_result_binding_sha256
            .clone(),
    };
    if record.committed_head.mutation_generation != 1
        || record.committed_head.journal_version != record.lineage.anchor.genesis_journal_version
        || record.committed_head.ancestry != expected_ancestry
        || record.snapshot.prepared_slot
            != cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty
    {
        return Err(AuthorityStoreSessionError::InvalidRecord);
    }
    Ok(())
}

fn validate_committed_store_record(record: &CommittedStoreRecord) -> StoreResult<()> {
    record.lineage.validate().map_err(invalid_record)?;
    record
        .committed_head
        .validate(&record.lineage)
        .map_err(invalid_record)?;
    record
        .snapshot
        .validate(&record.lineage)
        .map_err(invalid_record)?;
    if record.snapshot.committed_head != record.committed_head {
        return Err(AuthorityStoreSessionError::InvalidRecord);
    }
    Ok(())
}

fn invalid_record<T>(_error: T) -> AuthorityStoreSessionError {
    AuthorityStoreSessionError::InvalidRecord
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CommittedStoreRecord {
    lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    committed_head: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
}

#[cfg(test)]
#[derive(Clone)]
struct TestAuthorityStore {
    state: std::sync::Arc<std::sync::Mutex<TestAuthorityStoreState>>,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TestAuthorityStorePolicy {
    authority_identity_sha256: String,
    provision_epoch_sha256: String,
    provider_id: String,
    agent_id: String,
    adapter: trillionnium_os_types::direct_operation::DirectOperationAdapter,
    state_directory_identity_sha256: String,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TestAuthorityStoreFault {
    CommitUnknownBeforeApply,
    CommitUnknownAfterApply,
    MutationObserveDenied,
    MutationObserveOutcomeUnknown,
    MutationPrepareDenied,
    MutationPrepareNotApplied,
    MutationPrepareUnknownBeforeApply,
    MutationPrepareUnknownAfterApply,
    MutationPrepareForkedReceipt,
    MutationCommitNotApplied,
    MutationCommitDenied,
    MutationCommitUnknownBeforeApply,
    MutationCommitUnknownAfterApply,
    MutationCommitForkedReceipt,
    MutationReconcileDenied,
    MutationReconcileOutcomeUnknown,
    MutationReconcileForkedPreparedHead,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TestAuthorityStoreMutationPhase {
    Nonce(&'static str, String),
    Observe(String, String),
    Prepare(String, String),
    PrepareApplied(String),
    Commit(String, String),
    CommitApplied(String),
    Reconcile(cas::DirectOperationRuntimeAuthorityReconcileCauseV1),
}

#[cfg(test)]
#[derive(Clone)]
struct TestMutationPrepareExchange {
    request: cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
    receipt: cas::DirectOperationRuntimeAuthorityPrepareReceiptV1,
}

#[cfg(test)]
#[derive(Clone)]
struct TestPendingMutation {
    intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    prepared_head: cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
    exchanges: Vec<TestMutationPrepareExchange>,
}

#[cfg(test)]
#[derive(Clone)]
enum TestAuthorityStorePhase {
    Unprovisioned,
    Candidate {
        anchor: Box<cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1>,
        candidate: Box<cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1>,
    },
    Prepared {
        anchor: Box<cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1>,
        candidate: Box<cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1>,
        prepared: Box<cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1>,
    },
    Committed {
        record: Box<CommittedStoreRecord>,
        capability_minted: bool,
    },
}

#[cfg(test)]
struct TestAuthorityStoreState {
    policy: TestAuthorityStorePolicy,
    authority_store_instance_sha256: String,
    phase: TestAuthorityStorePhase,
    nonce_counter: u64,
    faults: std::collections::VecDeque<TestAuthorityStoreFault>,
    mutation_pending: Option<TestPendingMutation>,
    mutation_reconcile_required_transaction: Option<String>,
    mutation_transcript: Vec<TestAuthorityStoreMutationPhase>,
}

#[cfg(test)]
impl TestAuthorityStorePolicy {
    const FIXED_POLICY_SEED: &'static str =
        "trillionnium.test.operation-runtime-authority-policy.v1";

    pub(crate) fn fixed_codex_system_api(
        state_directory_identity_sha256: String,
    ) -> StoreResult<Self> {
        if !valid_nonzero_sha256(&state_directory_identity_sha256) {
            return Err(AuthorityStoreSessionError::InvalidRecord);
        }
        Ok(Self {
            authority_identity_sha256: trillionnium_os_types::sha256_bytes(
                format!("{}:authority", Self::FIXED_POLICY_SEED).as_bytes(),
            ),
            provision_epoch_sha256: trillionnium_os_types::sha256_bytes(
                format!("{}:provision-epoch", Self::FIXED_POLICY_SEED).as_bytes(),
            ),
            provider_id: CODEX_STABLE_PRINCIPAL.provider_id.to_string(),
            agent_id: CODEX_STABLE_PRINCIPAL.agent_id.to_string(),
            adapter: trillionnium_os_types::direct_operation::DirectOperationAdapter::SystemApi,
            state_directory_identity_sha256,
        })
    }
}

#[cfg(test)]
impl UnprovisionedAuthorityStoreSession {
    pub(crate) fn for_test(
        policy: TestAuthorityStorePolicy,
        store_instance_discriminator: &str,
    ) -> StoreResult<Self> {
        use std::sync::{Arc, Mutex};

        if store_instance_discriminator.is_empty() {
            return Err(AuthorityStoreSessionError::InvalidRecord);
        }
        let authority_store_instance_sha256 = trillionnium_os_types::sha256_bytes(
            format!(
                "{}:store:{}:{store_instance_discriminator}",
                TestAuthorityStorePolicy::FIXED_POLICY_SEED,
                policy.authority_identity_sha256,
            )
            .as_bytes(),
        );
        Ok(Self {
            backend: AuthorityStoreBackend::Test(TestAuthorityStore {
                state: Arc::new(Mutex::new(TestAuthorityStoreState {
                    policy,
                    authority_store_instance_sha256,
                    phase: TestAuthorityStorePhase::Unprovisioned,
                    nonce_counter: 0,
                    faults: std::collections::VecDeque::new(),
                    mutation_pending: None,
                    mutation_reconcile_required_transaction: None,
                    mutation_transcript: Vec::new(),
                })),
            }),
        })
    }

    pub(crate) fn test_authority_identity_sha256(&self) -> String {
        self.test_store_state()
            .expect("test authority store")
            .policy
            .authority_identity_sha256
            .clone()
    }

    pub(crate) fn test_authority_store_instance_sha256(&self) -> String {
        self.test_store_state()
            .expect("test authority store")
            .authority_store_instance_sha256
            .clone()
    }

    pub(crate) fn test_provision_epoch_sha256(&self) -> String {
        self.test_store_state()
            .expect("test authority store")
            .policy
            .provision_epoch_sha256
            .clone()
    }

    fn test_store_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, TestAuthorityStoreState>, AuthorityStoreSessionError>
    {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => store
                .state
                .lock()
                .map_err(|_| AuthorityStoreSessionError::BackendUnavailable),
        }
    }
}

#[cfg(test)]
impl CandidateAuthorityStoreSession {
    pub(crate) fn queue_fault(&self, fault: TestAuthorityStoreFault) {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => store
                .state
                .lock()
                .expect("test authority store poisoned")
                .faults
                .push_back(fault),
        }
    }
}

#[cfg(test)]
impl PreparedAuthorityStoreSession {
    pub(crate) fn queue_fault(&self, fault: TestAuthorityStoreFault) {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => store
                .state
                .lock()
                .expect("test authority store poisoned")
                .faults
                .push_back(fault),
        }
    }
}

#[cfg(test)]
impl SealedFirstUseGenesisCommit {
    fn mutate_store_for_test(&self, mutate: impl FnOnce(&mut CommittedStoreRecord)) {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => {
                let mut state = store.state.lock().expect("test authority store poisoned");
                let TestAuthorityStorePhase::Committed { record, .. } = &mut state.phase else {
                    panic!("test store is not committed");
                };
                mutate(record.as_mut());
            }
        }
    }
}

#[cfg(test)]
impl FreshlyObservedFirstUseGenesis {
    fn mutate_store_for_test(&self, mutate: impl FnOnce(&mut CommittedStoreRecord)) {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => {
                let mut state = store.state.lock().expect("test authority store poisoned");
                let TestAuthorityStorePhase::Committed { record, .. } = &mut state.phase else {
                    panic!("test store is not committed");
                };
                mutate(record.as_mut());
            }
        }
    }

    pub(crate) fn test_nonce_counter(&self) -> u64 {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => {
                store
                    .state
                    .lock()
                    .expect("test authority store poisoned")
                    .nonce_counter
            }
        }
    }

    pub(crate) fn set_test_nonce_counter(&self, value: u64) {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => {
                store
                    .state
                    .lock()
                    .expect("test authority store poisoned")
                    .nonce_counter = value;
            }
        }
    }

    pub(crate) fn test_observe_transcript(&self) -> Vec<(String, String)> {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => store
                .state
                .lock()
                .expect("test authority store poisoned")
                .mutation_transcript
                .iter()
                .filter_map(|phase| match phase {
                    TestAuthorityStoreMutationPhase::Observe(session, request) => {
                        Some((session.clone(), request.clone()))
                    }
                    _ => None,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
impl ActiveAuthorityStoreSession {
    pub(crate) fn queue_fault(&self, fault: TestAuthorityStoreFault) {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => store
                .state
                .lock()
                .expect("test authority store poisoned")
                .faults
                .push_back(fault),
        }
    }

    pub(crate) fn test_nonce_counter(&self) -> u64 {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => {
                store
                    .state
                    .lock()
                    .expect("test authority store poisoned")
                    .nonce_counter
            }
        }
    }

    pub(crate) fn test_observe_transcript(&self) -> Vec<(String, String)> {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => store
                .state
                .lock()
                .expect("test authority store poisoned")
                .mutation_transcript
                .iter()
                .filter_map(|phase| match phase {
                    TestAuthorityStoreMutationPhase::Observe(session, request) => {
                        Some((session.clone(), request.clone()))
                    }
                    _ => None,
                })
                .collect(),
        }
    }

    pub(crate) fn test_mutation_transcript(&self) -> Vec<TestAuthorityStoreMutationPhase> {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => store
                .state
                .lock()
                .expect("test authority store poisoned")
                .mutation_transcript
                .clone(),
        }
    }

    pub(crate) fn test_has_pending(&self) -> bool {
        match &self.backend {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => store
                .state
                .lock()
                .expect("test authority store poisoned")
                .mutation_pending
                .is_some(),
        }
    }
}

#[cfg(test)]
impl TestAuthorityStore {
    fn issue_candidate_and_read(
        &self,
        anchor: &cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    ) -> StoreResult<cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityStoreSessionError::BackendUnavailable)?;
        if !matches!(state.phase, TestAuthorityStorePhase::Unprovisioned)
            || anchor.validate().is_err()
            || !state.matches_anchor_policy(anchor)
        {
            return Err(AuthorityStoreSessionError::PolicyMismatch);
        }
        let nonce = state.next_nonce("first-use-candidate", &anchor.first_use_anchor_sha256)?;
        let mut candidate = cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1 {
            schema: cas::FIRST_USE_CANDIDATE_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            proposed_genesis_journal_version_sha256: anchor
                .genesis_journal_version
                .journal_version_sha256
                .clone(),
            candidate_nonce_sha256: nonce,
            first_use_candidate_sha256: String::new(),
        };
        candidate.first_use_candidate_sha256 =
            candidate.canonical_sha256().map_err(invalid_record)?;
        candidate.validate_for(anchor).map_err(invalid_record)?;
        state.phase = TestAuthorityStorePhase::Candidate {
            anchor: Box::new(anchor.clone()),
            candidate: Box::new(candidate.clone()),
        };
        Ok(candidate)
    }

    fn prepare_and_read(
        &self,
        anchor: &cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
        candidate: &cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1,
    ) -> StoreResult<cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityStoreSessionError::BackendUnavailable)?;
        let exact = matches!(
            &state.phase,
            TestAuthorityStorePhase::Candidate {
                anchor: stored_anchor,
                candidate: stored_candidate,
            } if stored_anchor.as_ref() == anchor && stored_candidate.as_ref() == candidate
        );
        if !exact || candidate.validate_for(anchor).is_err() {
            return Err(AuthorityStoreSessionError::StateMismatch);
        }
        let nonce = state.next_nonce("first-use-prepare", &candidate.first_use_candidate_sha256)?;
        let mut prepared = cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1 {
            schema: cas::FIRST_USE_PREPARED_HEAD_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            first_use_candidate_sha256: candidate.first_use_candidate_sha256.clone(),
            prepared_genesis_journal_version_sha256: anchor
                .genesis_journal_version
                .journal_version_sha256
                .clone(),
            prepared_sentinel_identity_sha256: anchor.sentinel_identity_sha256.clone(),
            prepared_sentinel_bytes_sha256: anchor.sentinel_bytes_sha256.clone(),
            prepare_nonce_sha256: nonce,
            first_use_prepared_head_sha256: String::new(),
        };
        prepared.first_use_prepared_head_sha256 =
            prepared.canonical_sha256().map_err(invalid_record)?;
        prepared
            .validate_for(anchor, candidate)
            .map_err(invalid_record)?;
        state.phase = TestAuthorityStorePhase::Prepared {
            anchor: Box::new(anchor.clone()),
            candidate: Box::new(candidate.clone()),
            prepared: Box::new(prepared.clone()),
        };
        Ok(prepared)
    }

    fn commit_and_mint(
        &self,
        anchor: &cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
        candidate: &cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1,
        prepared: &cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1,
        durable_commit_evidence_sha256: String,
    ) -> StoreResult<CommittedStoreRecord> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityStoreSessionError::BackendUnavailable)?;
        let exact = matches!(
            &state.phase,
            TestAuthorityStorePhase::Prepared {
                anchor: stored_anchor,
                candidate: stored_candidate,
                prepared: stored_prepared,
            } if stored_anchor.as_ref() == anchor
                && stored_candidate.as_ref() == candidate
                && stored_prepared.as_ref() == prepared
        );
        if !exact
            || prepared.validate_for(anchor, candidate).is_err()
            || !valid_nonzero_sha256(&durable_commit_evidence_sha256)
        {
            return Err(AuthorityStoreSessionError::StateMismatch);
        }
        if state.take_fault(TestAuthorityStoreFault::CommitUnknownBeforeApply) {
            return Err(AuthorityStoreSessionError::OutcomeUnknown);
        }
        let record = build_committed_record(
            &mut state,
            anchor,
            candidate,
            prepared,
            durable_commit_evidence_sha256,
        )?;
        state.phase = TestAuthorityStorePhase::Committed {
            record: Box::new(record.clone()),
            capability_minted: false,
        };
        if state.take_fault(TestAuthorityStoreFault::CommitUnknownAfterApply) {
            let TestAuthorityStorePhase::Committed {
                capability_minted, ..
            } = &mut state.phase
            else {
                return Err(AuthorityStoreSessionError::OutcomeUnknown);
            };
            // Burn the only mint ticket: commit-unknown recovery must use a
            // future authenticated reconciliation path, never raw readback.
            *capability_minted = true;
            return Err(AuthorityStoreSessionError::OutcomeUnknown);
        }
        let TestAuthorityStorePhase::Committed {
            record: readback,
            capability_minted,
        } = &mut state.phase
        else {
            return Err(AuthorityStoreSessionError::OutcomeUnknown);
        };
        if *capability_minted
            || readback.lineage != record.lineage
            || readback.committed_head != record.committed_head
            || readback.snapshot != record.snapshot
        {
            return Err(AuthorityStoreSessionError::OutcomeUnknown);
        }
        validate_exact_genesis_record(readback)?;
        *capability_minted = true;
        Ok((**readback).clone())
    }

    fn observe_committed(&self) -> StoreResult<CommittedStoreRecord> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuthorityStoreSessionError::BackendUnavailable)?;
        match &state.phase {
            TestAuthorityStorePhase::Committed { record, .. } => Ok((**record).clone()),
            _ => Err(AuthorityStoreSessionError::StateMismatch),
        }
    }

    fn mutation_request_nonce(
        &self,
        phase: &'static str,
        binding_sha256: &str,
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    ) -> MutationStoreCall<String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityStoreMutationCallFailure::OutcomeUnknown)?;
        validate_test_mutation_state(&state, lineage)?;
        if !matches!(
            phase,
            "prepare" | "commit" | "observe-session" | "observe" | "reconcile"
        ) || !valid_nonzero_sha256(binding_sha256)
        {
            return Err(AuthorityStoreMutationCallFailure::Denied);
        }
        let nonce = state
            .next_nonce(phase, binding_sha256)
            .map_err(|_| AuthorityStoreMutationCallFailure::Denied)?;
        state
            .mutation_transcript
            .push(TestAuthorityStoreMutationPhase::Nonce(phase, nonce.clone()));
        Ok(nonce)
    }

    fn prepare_mutation_head(
        &self,
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
    ) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityPrepareReceiptV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityStoreMutationCallFailure::OutcomeUnknown)?;
        let record = validate_test_mutation_state(&state, lineage)?;
        if request.validate(lineage).is_err()
            || request.current_committed_head != record.committed_head
            || state
                .mutation_reconcile_required_transaction
                .as_deref()
                .is_some_and(|transaction| {
                    transaction != request.mutation_transaction_sha256.as_str()
                })
            || state
                .mutation_pending
                .as_ref()
                .is_some_and(|pending| pending.intent != request.mutation_intent)
        {
            return Err(AuthorityStoreMutationCallFailure::Denied);
        }
        state
            .mutation_transcript
            .push(TestAuthorityStoreMutationPhase::Prepare(
                request.mutation_transaction_sha256.clone(),
                request.request_nonce_sha256.clone(),
            ));
        if state.take_fault(TestAuthorityStoreFault::MutationPrepareDenied) {
            return Err(AuthorityStoreMutationCallFailure::Denied);
        }
        if state.take_fault(TestAuthorityStoreFault::MutationPrepareNotApplied) {
            return Err(AuthorityStoreMutationCallFailure::NotApplied);
        }
        if state.take_fault(TestAuthorityStoreFault::MutationPrepareUnknownBeforeApply) {
            state.mutation_reconcile_required_transaction =
                Some(request.mutation_transaction_sha256.clone());
            return Err(AuthorityStoreMutationCallFailure::OutcomeUnknown);
        }

        let prepared_head = match &state.mutation_pending {
            Some(pending) => pending.prepared_head.clone(),
            None => make_mutation_prepared_head(
                lineage,
                &record.committed_head,
                &request.mutation_intent,
            )?,
        };
        let receipt = make_mutation_prepare_receipt(lineage, request, prepared_head.clone())?;
        let applied = if let Some(pending) = &mut state.mutation_pending {
            pending.exchanges.push(TestMutationPrepareExchange {
                request: request.clone(),
                receipt: receipt.clone(),
            });
            false
        } else {
            state.mutation_pending = Some(TestPendingMutation {
                intent: request.mutation_intent.clone(),
                prepared_head: prepared_head.clone(),
                exchanges: vec![TestMutationPrepareExchange {
                    request: request.clone(),
                    receipt: receipt.clone(),
                }],
            });
            true
        };
        if applied {
            let snapshot = make_mutation_snapshot(
                lineage,
                &record.committed_head,
                cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                    prepared_head: prepared_head.clone(),
                },
            )?;
            install_mutation_record(&mut state, record.lineage, record.committed_head, snapshot);
            state
                .mutation_transcript
                .push(TestAuthorityStoreMutationPhase::PrepareApplied(
                    prepared_head.prepared_head_sha256.clone(),
                ));
        }
        if state.take_fault(TestAuthorityStoreFault::MutationPrepareUnknownAfterApply) {
            state.mutation_reconcile_required_transaction =
                Some(request.mutation_transaction_sha256.clone());
            return Err(AuthorityStoreMutationCallFailure::OutcomeUnknown);
        }
        if state.take_fault(TestAuthorityStoreFault::MutationPrepareForkedReceipt) {
            state.mutation_reconcile_required_transaction =
                Some(request.mutation_transaction_sha256.clone());
            return make_forked_mutation_prepare_receipt(receipt);
        }
        Ok(receipt)
    }

    fn commit_mutation_head(
        &self,
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &cas::DirectOperationRuntimeAuthorityCommitRequestV1,
    ) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityCommitReceiptV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityStoreMutationCallFailure::OutcomeUnknown)?;
        let record = validate_test_mutation_state(&state, lineage)?;
        let pending = state
            .mutation_pending
            .clone()
            .ok_or(AuthorityStoreMutationCallFailure::Denied)?;
        let exchange = pending
            .exchanges
            .iter()
            .find(|exchange| {
                exchange.request.request_sha256 == request.prepare_request_sha256
                    && exchange.receipt.receipt_sha256 == request.prepare_receipt_sha256
            })
            .cloned()
            .ok_or(AuthorityStoreMutationCallFailure::Denied)?;
        if request
            .validate_for(lineage, &exchange.request, &exchange.receipt)
            .is_err()
            || request.mutation_transaction_sha256 != pending.intent.mutation_intent_sha256
            || state
                .mutation_reconcile_required_transaction
                .as_deref()
                .is_some_and(|transaction| {
                    transaction != request.mutation_transaction_sha256.as_str()
                })
        {
            return Err(AuthorityStoreMutationCallFailure::Denied);
        }
        state
            .mutation_transcript
            .push(TestAuthorityStoreMutationPhase::Commit(
                request.mutation_transaction_sha256.clone(),
                request.request_nonce_sha256.clone(),
            ));
        if state.take_fault(TestAuthorityStoreFault::MutationCommitNotApplied) {
            return Err(AuthorityStoreMutationCallFailure::NotApplied);
        }
        if state.take_fault(TestAuthorityStoreFault::MutationCommitDenied) {
            return Err(AuthorityStoreMutationCallFailure::Denied);
        }
        if state.take_fault(TestAuthorityStoreFault::MutationCommitUnknownBeforeApply) {
            state.mutation_reconcile_required_transaction =
                Some(request.mutation_transaction_sha256.clone());
            return Err(AuthorityStoreMutationCallFailure::OutcomeUnknown);
        }
        if state.take_fault(TestAuthorityStoreFault::MutationCommitForkedReceipt) {
            state.mutation_reconcile_required_transaction =
                Some(request.mutation_transaction_sha256.clone());
            return make_forked_mutation_commit_receipt(
                lineage,
                &record.committed_head,
                &pending.prepared_head,
                request,
            );
        }

        let successor =
            make_mutation_successor(lineage, &record.committed_head, &pending.prepared_head)?;
        let receipt = make_mutation_commit_receipt(request, successor.clone())?;
        receipt
            .validate_for(
                lineage,
                &record.committed_head,
                &exchange.request,
                &exchange.receipt,
                request,
            )
            .map_err(mutation_denied)?;
        let snapshot = make_mutation_snapshot(
            lineage,
            &successor,
            cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
        )?;
        install_mutation_record(&mut state, record.lineage, successor.clone(), snapshot);
        state.mutation_pending = None;
        state.mutation_reconcile_required_transaction = None;
        state
            .mutation_transcript
            .push(TestAuthorityStoreMutationPhase::CommitApplied(
                successor.committed_head_sha256,
            ));
        if state.take_fault(TestAuthorityStoreFault::MutationCommitUnknownAfterApply) {
            state.mutation_reconcile_required_transaction =
                Some(request.mutation_transaction_sha256.clone());
            return Err(AuthorityStoreMutationCallFailure::OutcomeUnknown);
        }
        Ok(receipt)
    }

    fn observe_mutation_head(
        &self,
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &cas::DirectOperationRuntimeAuthorityObserveRequestV1,
    ) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityObserveResponseV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityStoreMutationCallFailure::OutcomeUnknown)?;
        let record = validate_test_mutation_state(&state, lineage)?;
        if request
            .validate_for(lineage, &record.committed_head)
            .is_err()
        {
            return Err(AuthorityStoreMutationCallFailure::Denied);
        }
        state
            .mutation_transcript
            .push(TestAuthorityStoreMutationPhase::Observe(
                request.observation_session_sha256.clone(),
                request.request_nonce_sha256.clone(),
            ));
        if state.take_fault(TestAuthorityStoreFault::MutationObserveDenied) {
            return Err(AuthorityStoreMutationCallFailure::Denied);
        }
        if state.take_fault(TestAuthorityStoreFault::MutationObserveOutcomeUnknown) {
            return Err(AuthorityStoreMutationCallFailure::OutcomeUnknown);
        }
        let response = make_mutation_observe_response(request, record.snapshot)?;
        response
            .validate_for(lineage, request, &record.committed_head)
            .map_err(mutation_denied)?;
        Ok(response)
    }

    fn reconcile_mutation_head(
        &self,
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &cas::DirectOperationRuntimeAuthorityReconcileRequestV1,
    ) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityReconcileResponseV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityStoreMutationCallFailure::OutcomeUnknown)?;
        let record = validate_test_mutation_state(&state, lineage)?;
        let exact_transaction = request.mutation_transaction_sha256.as_str();
        let exact_no_mutation_probe = state.mutation_pending.is_none()
            && record.snapshot.prepared_slot
                == cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty
            && request.cause
                == cas::DirectOperationRuntimeAuthorityReconcileCauseV1::PrepareResponseUnknown
            && request.prepared_knowledge
                == cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Unknown
            && state
                .mutation_reconcile_required_transaction
                .as_deref()
                .is_none_or(|transaction| transaction == exact_transaction);
        let exact_recovery_transaction = state.mutation_reconcile_required_transaction.as_deref()
            == Some(exact_transaction)
            || state
                .mutation_pending
                .as_ref()
                .map(|pending| pending.intent.mutation_intent_sha256.as_str())
                == Some(exact_transaction)
            || exact_no_mutation_probe;
        if request.validate(lineage).is_err() || !exact_recovery_transaction {
            return Err(AuthorityStoreMutationCallFailure::Denied);
        }
        state
            .mutation_transcript
            .push(TestAuthorityStoreMutationPhase::Reconcile(request.cause));
        if state.take_fault(TestAuthorityStoreFault::MutationReconcileDenied) {
            return Err(AuthorityStoreMutationCallFailure::Denied);
        }
        if state.take_fault(TestAuthorityStoreFault::MutationReconcileOutcomeUnknown) {
            return Err(AuthorityStoreMutationCallFailure::OutcomeUnknown);
        }
        let mut prepared_slot = record.snapshot.prepared_slot;
        if state.take_fault(TestAuthorityStoreFault::MutationReconcileForkedPreparedHead) {
            let cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending { prepared_head } =
                &mut prepared_slot
            else {
                return Err(AuthorityStoreMutationCallFailure::Denied);
            };
            prepared_head.proposed_journal_version =
                make_forked_mutation_journal_version("reconcile")?;
            prepared_head.prepared_head_sha256 =
                prepared_head.canonical_sha256().map_err(mutation_denied)?;
        }
        let snapshot = make_mutation_snapshot(lineage, &record.committed_head, prepared_slot)?;
        let response = make_mutation_reconcile_response(request, snapshot)?;
        let disposition = response
            .disposition_for(lineage, request)
            .map_err(mutation_denied)?;
        if matches!(
            disposition,
            cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::NoMutation
                | cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::Committed
        ) {
            state.mutation_reconcile_required_transaction = None;
        }
        Ok(response)
    }

    fn confirm_replayed_committed_mutation(
        &self,
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        successor: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
        intent: &cas::DirectOperationRuntimeAuthorityMutationIntentV1,
        prepared: &cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
    ) -> MutationStoreCall<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityStoreMutationCallFailure::OutcomeUnknown)?;
        let record = validate_test_mutation_state(&state, lineage)?;
        validate_replayed_committed_successor(lineage, successor, intent, prepared)?;
        if record.committed_head != *successor
            || record.snapshot.committed_head != *successor
            || record.snapshot.prepared_slot
                != cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty
            || state.mutation_pending.is_some()
            || state
                .mutation_reconcile_required_transaction
                .as_deref()
                .is_some_and(|transaction| transaction != intent.mutation_intent_sha256)
        {
            return Err(AuthorityStoreMutationCallFailure::Denied);
        }
        state.mutation_reconcile_required_transaction = None;
        Ok(())
    }

    fn advance_for_test(
        &self,
        prepared: &cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
        successor: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
        snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
    ) -> StoreResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityStoreSessionError::BackendUnavailable)?;
        let previous = match &state.phase {
            TestAuthorityStorePhase::Committed { record, .. } => (**record).clone(),
            _ => return Err(AuthorityStoreSessionError::StateMismatch),
        };
        successor
            .validate_successor(&previous.lineage, &previous.committed_head, prepared)
            .map_err(invalid_record)?;
        snapshot
            .validate(&previous.lineage)
            .map_err(invalid_record)?;
        if snapshot.committed_head != successor
            || snapshot.prepared_slot != cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty
        {
            return Err(AuthorityStoreSessionError::InvalidRecord);
        }
        state.phase = TestAuthorityStorePhase::Committed {
            record: Box::new(CommittedStoreRecord {
                lineage: previous.lineage,
                committed_head: successor,
                snapshot,
            }),
            capability_minted: true,
        };
        state.mutation_pending = None;
        state.mutation_reconcile_required_transaction = None;
        Ok(())
    }
}

#[cfg(test)]
fn validate_replayed_committed_successor(
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    successor: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    intent: &cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    prepared: &cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
) -> MutationStoreCall<()> {
    lineage.validate().map_err(mutation_denied)?;
    successor.validate(lineage).map_err(mutation_denied)?;
    intent
        .expected_journal_version
        .validate()
        .map_err(mutation_denied)?;
    intent
        .observed_current_journal_version
        .validate()
        .map_err(mutation_denied)?;
    intent
        .proposed_journal_version
        .validate()
        .map_err(mutation_denied)?;
    let to_mutation_generation = intent
        .from_mutation_generation
        .checked_add(1)
        .ok_or(AuthorityStoreMutationCallFailure::Denied)?;
    if intent.schema != cas::MUTATION_INTENT_V1_SCHEMA
        || intent.protocol != cas::PROTOCOL
        || intent.authority_store_instance_sha256 != lineage.anchor.authority_store_instance_sha256
        || intent.first_use_lineage_sha256 != lineage.first_use_lineage_sha256
        || intent.from_mutation_generation == 0
        || intent.to_mutation_generation != to_mutation_generation
        || intent.to_mutation_generation != successor.mutation_generation
        || intent.expected_journal_version != intent.observed_current_journal_version
        || intent.proposed_journal_version != successor.journal_version
        || intent.proposed_journal_version.journal_identity_sha256
            == intent.expected_journal_version.journal_identity_sha256
        || intent.proposed_journal_version.journal_bytes_sha256
            == intent.expected_journal_version.journal_bytes_sha256
        || !valid_nonzero_sha256(&intent.from_committed_head_sha256)
        || !valid_nonzero_sha256(&intent.mutation_nonce_sha256)
        || !valid_nonzero_sha256(&intent.mutation_intent_sha256)
        || intent.canonical_sha256().map_err(mutation_denied)? != intent.mutation_intent_sha256
    {
        return Err(AuthorityStoreMutationCallFailure::Denied);
    }
    let mut expected_prepared = cas::DirectOperationRuntimeAuthorityPreparedHeadV1 {
        schema: cas::PREPARED_HEAD_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        authority_identity_sha256: lineage.anchor.authority_identity_sha256.clone(),
        authority_store_instance_sha256: lineage.anchor.authority_store_instance_sha256.clone(),
        first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
        from_committed_head_sha256: intent.from_committed_head_sha256.clone(),
        from_mutation_generation: intent.from_mutation_generation,
        to_mutation_generation: intent.to_mutation_generation,
        mutation_intent_sha256: intent.mutation_intent_sha256.clone(),
        expected_journal_version: intent.expected_journal_version.clone(),
        proposed_journal_version: intent.proposed_journal_version.clone(),
        prepared_head_sha256: String::new(),
    };
    expected_prepared.prepared_head_sha256 = expected_prepared
        .canonical_sha256()
        .map_err(mutation_denied)?;
    let expected_ancestry = cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Successor {
        predecessor_committed_head_sha256: intent.from_committed_head_sha256.clone(),
        prepared_head_sha256: expected_prepared.prepared_head_sha256.clone(),
    };
    if prepared != &expected_prepared || successor.ancestry != expected_ancestry {
        return Err(AuthorityStoreMutationCallFailure::Denied);
    }
    Ok(())
}

#[cfg(test)]
impl TestAuthorityStoreState {
    fn matches_anchor_policy(
        &self,
        anchor: &cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    ) -> bool {
        anchor.authority_identity_sha256 == self.policy.authority_identity_sha256
            && anchor.authority_store_instance_sha256 == self.authority_store_instance_sha256
            && anchor.provision_epoch_sha256 == self.policy.provision_epoch_sha256
            && anchor.provider_id == self.policy.provider_id
            && anchor.agent_id == self.policy.agent_id
            && anchor.adapter == self.policy.adapter
            && anchor.state_directory_identity_sha256 == self.policy.state_directory_identity_sha256
    }

    fn next_nonce(&mut self, phase: &str, binding: &str) -> StoreResult<String> {
        self.nonce_counter = self
            .nonce_counter
            .checked_add(1)
            .ok_or(AuthorityStoreSessionError::StateMismatch)?;
        Ok(trillionnium_os_types::sha256_bytes(
            format!(
                "trillionnium.test.operation-runtime-authority-store-nonce.v1:{}:{phase}:{}:{binding}",
                self.authority_store_instance_sha256,
                self.nonce_counter,
            )
            .as_bytes(),
        ))
    }

    fn take_fault(&mut self, expected: TestAuthorityStoreFault) -> bool {
        if self.faults.front() == Some(&expected) {
            self.faults.pop_front();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
fn validate_test_mutation_state(
    state: &TestAuthorityStoreState,
    expected_lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
) -> MutationStoreCall<CommittedStoreRecord> {
    let TestAuthorityStorePhase::Committed {
        record,
        capability_minted,
    } = &state.phase
    else {
        return Err(AuthorityStoreMutationCallFailure::Denied);
    };
    if !*capability_minted || record.lineage != *expected_lineage {
        return Err(AuthorityStoreMutationCallFailure::Denied);
    }
    validate_committed_store_record(record)
        .map_err(|_| AuthorityStoreMutationCallFailure::Denied)?;
    match (&state.mutation_pending, &record.snapshot.prepared_slot) {
        (None, cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty) => {}
        (
            Some(pending),
            cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending { prepared_head },
        ) if pending.prepared_head == *prepared_head
            && pending
                .intent
                .validate_for(expected_lineage, &record.committed_head)
                .is_ok()
            && pending
                .prepared_head
                .validate_for_intent(expected_lineage, &record.committed_head, &pending.intent)
                .is_ok() => {}
        _ => return Err(AuthorityStoreMutationCallFailure::Denied),
    }
    Ok((**record).clone())
}

#[cfg(test)]
fn install_mutation_record(
    state: &mut TestAuthorityStoreState,
    lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    committed_head: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
) {
    state.phase = TestAuthorityStorePhase::Committed {
        record: Box::new(CommittedStoreRecord {
            lineage,
            committed_head,
            snapshot,
        }),
        capability_minted: true,
    };
}

#[cfg(test)]
fn mutation_denied<T>(_error: T) -> AuthorityStoreMutationCallFailure {
    AuthorityStoreMutationCallFailure::Denied
}

#[cfg(test)]
fn make_mutation_prepared_head(
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    intent: &cas::DirectOperationRuntimeAuthorityMutationIntentV1,
) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityPreparedHeadV1> {
    let mut prepared = cas::DirectOperationRuntimeAuthorityPreparedHeadV1 {
        schema: cas::PREPARED_HEAD_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        authority_identity_sha256: lineage.anchor.authority_identity_sha256.clone(),
        authority_store_instance_sha256: lineage.anchor.authority_store_instance_sha256.clone(),
        first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
        from_committed_head_sha256: current.committed_head_sha256.clone(),
        from_mutation_generation: current.mutation_generation,
        to_mutation_generation: intent.to_mutation_generation,
        mutation_intent_sha256: intent.mutation_intent_sha256.clone(),
        expected_journal_version: intent.expected_journal_version.clone(),
        proposed_journal_version: intent.proposed_journal_version.clone(),
        prepared_head_sha256: String::new(),
    };
    prepared.prepared_head_sha256 = prepared.canonical_sha256().map_err(mutation_denied)?;
    prepared
        .validate_for_intent(lineage, current, intent)
        .map_err(mutation_denied)?;
    Ok(prepared)
}

#[cfg(test)]
fn make_mutation_prepare_receipt(
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    request: &cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
    prepared_head: cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityPrepareReceiptV1> {
    let mut receipt = cas::DirectOperationRuntimeAuthorityPrepareReceiptV1 {
        schema: cas::PREPARE_RECEIPT_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        operation: cas::PREPARE_OPERATION.to_string(),
        request_sha256: request.request_sha256.clone(),
        prepared_head,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt.canonical_sha256().map_err(mutation_denied)?;
    receipt
        .validate_for(lineage, request)
        .map_err(mutation_denied)?;
    Ok(receipt)
}

#[cfg(test)]
fn make_forked_mutation_prepare_receipt(
    mut receipt: cas::DirectOperationRuntimeAuthorityPrepareReceiptV1,
) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityPrepareReceiptV1> {
    receipt.prepared_head.proposed_journal_version =
        make_forked_mutation_journal_version("prepare")?;
    receipt.prepared_head.prepared_head_sha256 = receipt
        .prepared_head
        .canonical_sha256()
        .map_err(mutation_denied)?;
    receipt.receipt_sha256 = receipt.canonical_sha256().map_err(mutation_denied)?;
    Ok(receipt)
}

#[cfg(test)]
fn make_mutation_successor(
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    prepared: &cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityCommittedHeadV1> {
    let mut head = cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
        schema: cas::COMMITTED_HEAD_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        authority_identity_sha256: lineage.anchor.authority_identity_sha256.clone(),
        authority_store_instance_sha256: lineage.anchor.authority_store_instance_sha256.clone(),
        first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
        provider_id: lineage.anchor.provider_id.clone(),
        agent_id: lineage.anchor.agent_id.clone(),
        adapter: lineage.anchor.adapter,
        journal_epoch: lineage.anchor.journal_epoch.clone(),
        state_directory_identity_sha256: lineage.anchor.state_directory_identity_sha256.clone(),
        mutation_generation: prepared.to_mutation_generation,
        journal_version: prepared.proposed_journal_version.clone(),
        ancestry: cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Successor {
            predecessor_committed_head_sha256: current.committed_head_sha256.clone(),
            prepared_head_sha256: prepared.prepared_head_sha256.clone(),
        },
        committed_head_sha256: String::new(),
    };
    head.committed_head_sha256 = head.canonical_sha256().map_err(mutation_denied)?;
    head.validate_successor(lineage, current, prepared)
        .map_err(mutation_denied)?;
    Ok(head)
}

#[cfg(test)]
fn make_mutation_commit_receipt(
    request: &cas::DirectOperationRuntimeAuthorityCommitRequestV1,
    committed_head: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityCommitReceiptV1> {
    let mut receipt = cas::DirectOperationRuntimeAuthorityCommitReceiptV1 {
        schema: cas::COMMIT_RECEIPT_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        operation: cas::COMMIT_OPERATION.to_string(),
        request_sha256: request.request_sha256.clone(),
        committed_head,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt.canonical_sha256().map_err(mutation_denied)?;
    Ok(receipt)
}

#[cfg(test)]
fn make_forked_mutation_commit_receipt(
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    prepared: &cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
    request: &cas::DirectOperationRuntimeAuthorityCommitRequestV1,
) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityCommitReceiptV1> {
    let mut head = make_mutation_successor(lineage, current, prepared)?;
    head.journal_version = make_forked_mutation_journal_version("commit")?;
    head.committed_head_sha256 = head.canonical_sha256().map_err(mutation_denied)?;
    make_mutation_commit_receipt(request, head)
}

#[cfg(test)]
fn make_forked_mutation_journal_version(
    phase: &str,
) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityJournalVersionV1> {
    let mut version = cas::DirectOperationRuntimeAuthorityJournalVersionV1 {
        schema: cas::JOURNAL_VERSION_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        journal_identity_sha256: trillionnium_os_types::sha256_bytes(
            format!("same-store:{phase}:forked-journal-identity").as_bytes(),
        ),
        journal_bytes_sha256: trillionnium_os_types::sha256_bytes(
            format!("same-store:{phase}:forked-journal-bytes").as_bytes(),
        ),
        journal_version_sha256: String::new(),
    };
    version.journal_version_sha256 = version.canonical_sha256().map_err(mutation_denied)?;
    version.validate().map_err(mutation_denied)?;
    Ok(version)
}

#[cfg(test)]
fn make_mutation_snapshot(
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    committed_head: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    prepared_slot: cas::DirectOperationRuntimeAuthorityPreparedSlotV1,
) -> MutationStoreCall<cas::DirectOperationRuntimeAuthoritySnapshotV1> {
    let mut snapshot = cas::DirectOperationRuntimeAuthoritySnapshotV1 {
        schema: cas::AUTHORITY_SNAPSHOT_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
        committed_head: committed_head.clone(),
        prepared_slot,
        snapshot_sha256: String::new(),
    };
    snapshot.snapshot_sha256 = snapshot.canonical_sha256().map_err(mutation_denied)?;
    snapshot.validate(lineage).map_err(mutation_denied)?;
    Ok(snapshot)
}

#[cfg(test)]
fn make_mutation_observe_response(
    request: &cas::DirectOperationRuntimeAuthorityObserveRequestV1,
    snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityObserveResponseV1> {
    let mut response = cas::DirectOperationRuntimeAuthorityObserveResponseV1 {
        schema: cas::OBSERVE_RESPONSE_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        operation: cas::OBSERVE_OPERATION.to_string(),
        request_sha256: request.request_sha256.clone(),
        snapshot,
        response_sha256: String::new(),
    };
    response.response_sha256 = response.canonical_sha256().map_err(mutation_denied)?;
    Ok(response)
}

#[cfg(test)]
fn make_mutation_reconcile_response(
    request: &cas::DirectOperationRuntimeAuthorityReconcileRequestV1,
    snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
) -> MutationStoreCall<cas::DirectOperationRuntimeAuthorityReconcileResponseV1> {
    let mut response = cas::DirectOperationRuntimeAuthorityReconcileResponseV1 {
        schema: cas::RECONCILE_RESPONSE_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        operation: cas::RECONCILE_OPERATION.to_string(),
        request_sha256: request.request_sha256.clone(),
        snapshot,
        response_sha256: String::new(),
    };
    response.response_sha256 = response.canonical_sha256().map_err(mutation_denied)?;
    Ok(response)
}

#[cfg(test)]
fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

#[cfg(test)]
fn build_committed_record(
    state: &mut TestAuthorityStoreState,
    anchor: &cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    candidate: &cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1,
    prepared: &cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1,
    durable_commit_evidence_sha256: String,
) -> StoreResult<CommittedStoreRecord> {
    let mut first_use_committed_head =
        cas::DirectOperationRuntimeAuthorityFirstUseCommittedHeadV1 {
            schema: cas::FIRST_USE_COMMITTED_HEAD_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            first_use_candidate_sha256: candidate.first_use_candidate_sha256.clone(),
            first_use_prepared_head_sha256: prepared.first_use_prepared_head_sha256.clone(),
            committed_genesis_journal_version: anchor.genesis_journal_version.clone(),
            committed_sentinel_identity_sha256: anchor.sentinel_identity_sha256.clone(),
            committed_sentinel_bytes_sha256: anchor.sentinel_bytes_sha256.clone(),
            durable_commit_evidence_sha256,
            first_use_committed_head_sha256: String::new(),
        };
    first_use_committed_head.first_use_committed_head_sha256 = first_use_committed_head
        .canonical_sha256()
        .map_err(invalid_record)?;
    first_use_committed_head
        .validate_for(anchor, candidate, prepared)
        .map_err(invalid_record)?;

    let result_receipt_sha256 = state.next_nonce(
        "first-use-commit-result",
        &first_use_committed_head.first_use_committed_head_sha256,
    )?;
    let mut result = cas::DirectOperationRuntimeAuthorityFirstUseCommittedResultBindingV1 {
        schema: cas::FIRST_USE_COMMITTED_RESULT_BINDING_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
        first_use_candidate_sha256: candidate.first_use_candidate_sha256.clone(),
        first_use_prepared_head_sha256: prepared.first_use_prepared_head_sha256.clone(),
        first_use_committed_head_sha256: first_use_committed_head
            .first_use_committed_head_sha256
            .clone(),
        committed_genesis_journal_version_sha256: anchor
            .genesis_journal_version
            .journal_version_sha256
            .clone(),
        committed_sentinel_identity_sha256: anchor.sentinel_identity_sha256.clone(),
        committed_sentinel_bytes_sha256: anchor.sentinel_bytes_sha256.clone(),
        durable_commit_evidence_sha256: first_use_committed_head
            .durable_commit_evidence_sha256
            .clone(),
        result_receipt_sha256,
        first_use_committed_result_binding_sha256: String::new(),
    };
    result.first_use_committed_result_binding_sha256 =
        result.canonical_sha256().map_err(invalid_record)?;
    result
        .validate_for(anchor, candidate, prepared, &first_use_committed_head)
        .map_err(invalid_record)?;

    let mut lineage = cas::DirectOperationRuntimeAuthorityFirstUseLineageV1 {
        schema: cas::FIRST_USE_LINEAGE_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        anchor: anchor.clone(),
        candidate: candidate.clone(),
        prepared_head: prepared.clone(),
        committed_head: first_use_committed_head,
        committed_result_binding: result,
        first_use_lineage_sha256: String::new(),
    };
    lineage.first_use_lineage_sha256 = lineage.canonical_sha256().map_err(invalid_record)?;
    lineage.validate().map_err(invalid_record)?;

    let mut committed_head = cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
        schema: cas::COMMITTED_HEAD_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        authority_identity_sha256: anchor.authority_identity_sha256.clone(),
        authority_store_instance_sha256: anchor.authority_store_instance_sha256.clone(),
        first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
        provider_id: anchor.provider_id.clone(),
        agent_id: anchor.agent_id.clone(),
        adapter: anchor.adapter,
        journal_epoch: anchor.journal_epoch.clone(),
        state_directory_identity_sha256: anchor.state_directory_identity_sha256.clone(),
        mutation_generation: 1,
        journal_version: anchor.genesis_journal_version.clone(),
        ancestry: cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Genesis {
            first_use_committed_result_binding_sha256: lineage
                .committed_result_binding
                .first_use_committed_result_binding_sha256
                .clone(),
        },
        committed_head_sha256: String::new(),
    };
    committed_head.committed_head_sha256 =
        committed_head.canonical_sha256().map_err(invalid_record)?;
    committed_head.validate(&lineage).map_err(invalid_record)?;

    let mut snapshot = cas::DirectOperationRuntimeAuthoritySnapshotV1 {
        schema: cas::AUTHORITY_SNAPSHOT_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
        committed_head: committed_head.clone(),
        prepared_slot: cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
        snapshot_sha256: String::new(),
    };
    snapshot.snapshot_sha256 = snapshot.canonical_sha256().map_err(invalid_record)?;
    snapshot.validate(&lineage).map_err(invalid_record)?;

    let record = CommittedStoreRecord {
        lineage,
        committed_head,
        snapshot,
    };
    validate_exact_genesis_record(&record)?;
    Ok(record)
}

#[cfg(test)]
pub(crate) fn fresh_genesis_for_test(label: &str) -> StoreResult<FreshlyObservedFirstUseGenesis> {
    use trillionnium_os_types::direct_operation::DirectOperationAdapter;

    if label.is_empty() {
        return Err(AuthorityStoreSessionError::InvalidRecord);
    }
    let digest =
        |suffix: &str| trillionnium_os_types::sha256_bytes(format!("{label}:{suffix}").as_bytes());
    let policy = TestAuthorityStorePolicy::fixed_codex_system_api(digest("state-directory"))?;
    let session = UnprovisionedAuthorityStoreSession::for_test(policy, label)?;
    let mut journal_version = cas::DirectOperationRuntimeAuthorityJournalVersionV1 {
        schema: cas::JOURNAL_VERSION_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        journal_identity_sha256: digest("genesis-journal-identity"),
        journal_bytes_sha256: digest("genesis-journal-bytes"),
        journal_version_sha256: String::new(),
    };
    journal_version.journal_version_sha256 =
        journal_version.canonical_sha256().map_err(invalid_record)?;
    journal_version.validate().map_err(invalid_record)?;
    let mut anchor = cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1 {
        schema: cas::FIRST_USE_ANCHOR_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        authority_identity_sha256: session.test_authority_identity_sha256(),
        authority_store_instance_sha256: session.test_authority_store_instance_sha256(),
        provision_epoch_sha256: session.test_provision_epoch_sha256(),
        provider_id: CODEX_STABLE_PRINCIPAL.provider_id.to_string(),
        agent_id: CODEX_STABLE_PRINCIPAL.agent_id.to_string(),
        adapter: DirectOperationAdapter::SystemApi,
        journal_epoch: "12".repeat(16),
        state_directory_identity_sha256: digest("state-directory"),
        genesis_journal_version: journal_version,
        immutable_sentinel_schema: cas::FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA.to_string(),
        immutable_sentinel_embeds_prepared_head: false,
        sentinel_identity_sha256: digest("sentinel-identity"),
        sentinel_bytes_sha256: String::new(),
        first_use_anchor_sha256: String::new(),
    };
    anchor.sentinel_bytes_sha256 = anchor
        .canonical_immutable_sentinel_bytes_sha256()
        .map_err(invalid_record)?;
    anchor.first_use_anchor_sha256 = anchor.canonical_sha256().map_err(invalid_record)?;
    anchor.validate().map_err(invalid_record)?;

    let candidate = session.issue_candidate(anchor.clone())?;
    let candidate_record = candidate.candidate().clone();
    let prepared = candidate.prepare(&anchor, &candidate_record)?;
    let prepared_record = prepared.prepared().clone();
    prepared
        .commit(
            &anchor,
            &candidate_record,
            &prepared_record,
            digest("durable-first-use-commit"),
        )?
        .into_freshly_observed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use trillionnium_os_types::direct_operation::DirectOperationAdapter;

    const PROVIDER: &str = "openai-codex";
    const AGENT: &str = "agent-codex-direct-v1";

    fn digest(label: &str) -> String {
        trillionnium_os_types::sha256_bytes(label.as_bytes())
    }

    fn policy(label: &str) -> TestAuthorityStorePolicy {
        TestAuthorityStorePolicy::fixed_codex_system_api(digest(&format!(
            "{label}:state-directory"
        )))
        .unwrap()
    }

    fn unprovisioned_and_anchor(
        label: &str,
    ) -> (
        UnprovisionedAuthorityStoreSession,
        cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    ) {
        let session = UnprovisionedAuthorityStoreSession::for_test(policy(label), label).unwrap();
        let mut journal_version = cas::DirectOperationRuntimeAuthorityJournalVersionV1 {
            schema: cas::JOURNAL_VERSION_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            journal_identity_sha256: digest(&format!("{label}:journal-identity")),
            journal_bytes_sha256: digest(&format!("{label}:journal-bytes")),
            journal_version_sha256: String::new(),
        };
        journal_version.journal_version_sha256 = journal_version.canonical_sha256().unwrap();
        journal_version.validate().unwrap();
        let mut anchor = cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1 {
            schema: cas::FIRST_USE_ANCHOR_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            authority_identity_sha256: session.test_authority_identity_sha256(),
            authority_store_instance_sha256: session.test_authority_store_instance_sha256(),
            provision_epoch_sha256: session.test_provision_epoch_sha256(),
            provider_id: PROVIDER.to_string(),
            agent_id: AGENT.to_string(),
            adapter: DirectOperationAdapter::SystemApi,
            journal_epoch: "12".repeat(16),
            state_directory_identity_sha256: digest(&format!("{label}:state-directory")),
            genesis_journal_version: journal_version,
            immutable_sentinel_schema: cas::FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA.to_string(),
            immutable_sentinel_embeds_prepared_head: false,
            sentinel_identity_sha256: digest(&format!("{label}:sentinel-identity")),
            sentinel_bytes_sha256: digest("temporary-sentinel-bytes"),
            first_use_anchor_sha256: String::new(),
        };
        anchor.sentinel_bytes_sha256 = anchor.canonical_immutable_sentinel_bytes_sha256().unwrap();
        anchor.first_use_anchor_sha256 = anchor.canonical_sha256().unwrap();
        anchor.validate().unwrap();
        (session, anchor)
    }

    fn prepared(
        label: &str,
    ) -> (
        cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
        cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1,
        cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1,
        PreparedAuthorityStoreSession,
    ) {
        let (session, anchor) = unprovisioned_and_anchor(label);
        let candidate_session = session.issue_candidate(anchor.clone()).unwrap();
        let candidate = candidate_session.candidate().clone();
        let prepared_session = candidate_session.prepare(&anchor, &candidate).unwrap();
        let prepared = prepared_session.prepared().clone();
        (anchor, candidate, prepared, prepared_session)
    }

    fn committed(label: &str) -> SealedFirstUseGenesisCommit {
        let (anchor, candidate, prepared, session) = prepared(label);
        session
            .commit(
                &anchor,
                &candidate,
                &prepared,
                digest(&format!("{label}:durable-local-commit")),
            )
            .unwrap()
    }

    #[test]
    fn atomic_commit_mints_only_exact_generation_one_empty_snapshot() {
        let capability = committed("exact-genesis");
        validate_exact_genesis_record(&CommittedStoreRecord {
            lineage: capability.lineage.clone(),
            committed_head: capability.committed_head.clone(),
            snapshot: capability.snapshot.clone(),
        })
        .unwrap();
        assert_eq!(capability.committed_head.mutation_generation, 1);
        assert_eq!(
            capability.snapshot.prepared_slot,
            cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty
        );
        let observed = capability.into_freshly_observed().unwrap();
        assert_eq!(observed.committed_head().mutation_generation, 1);
        assert_eq!(
            observed.committed_head().journal_version,
            observed.lineage().anchor.genesis_journal_version
        );
        observed.snapshot().validate(observed.lineage()).unwrap();
    }

    #[test]
    fn cross_store_backend_substitution_is_rejected() {
        let first = committed("store-a");
        let second = committed("store-b");
        let SealedFirstUseGenesisCommit {
            backend: _backend_a,
            lineage,
            committed_head,
            snapshot,
        } = first;
        let SealedFirstUseGenesisCommit {
            backend: backend_b, ..
        } = second;
        let substituted = SealedFirstUseGenesisCommit {
            backend: backend_b,
            lineage,
            committed_head,
            snapshot,
        };
        assert!(matches!(
            substituted.into_freshly_observed(),
            Err(AuthorityStoreSessionError::FreshObservationMismatch)
        ));
    }

    #[test]
    fn same_authority_different_store_and_cross_stage_substitution_are_rejected() {
        let (store_a, anchor_a) = unprovisioned_and_anchor("cross-candidate-a");
        let (store_b, _anchor_b) = unprovisioned_and_anchor("cross-candidate-b");
        assert_eq!(
            store_a.test_authority_identity_sha256(),
            store_b.test_authority_identity_sha256()
        );
        assert_ne!(
            store_a.test_authority_store_instance_sha256(),
            store_b.test_authority_store_instance_sha256()
        );
        let candidate_a = store_a.issue_candidate(anchor_a.clone()).unwrap();
        let raw_candidate_a = candidate_a.candidate.clone();
        let forged_candidate_stage = CandidateAuthorityStoreSession {
            backend: store_b.backend,
            anchor: anchor_a.clone(),
            candidate: raw_candidate_a.clone(),
        };
        assert!(matches!(
            forged_candidate_stage.prepare(&anchor_a, &raw_candidate_a),
            Err(AuthorityStoreSessionError::StateMismatch)
        ));

        let (store_a, anchor_a) = unprovisioned_and_anchor("cross-prepared-a");
        let candidate_a = store_a.issue_candidate(anchor_a.clone()).unwrap();
        let raw_candidate_a = candidate_a.candidate.clone();
        let prepared_a = candidate_a.prepare(&anchor_a, &raw_candidate_a).unwrap();
        let raw_prepared_a = prepared_a.prepared.clone();
        let (store_b, anchor_b) = unprovisioned_and_anchor("cross-prepared-b");
        let candidate_b = store_b.issue_candidate(anchor_b.clone()).unwrap();
        let raw_candidate_b = candidate_b.candidate.clone();
        let prepared_b = candidate_b.prepare(&anchor_b, &raw_candidate_b).unwrap();
        let forged_prepared_stage = PreparedAuthorityStoreSession {
            backend: prepared_b.backend,
            anchor: anchor_a.clone(),
            candidate: raw_candidate_a.clone(),
            prepared: raw_prepared_a.clone(),
        };
        assert!(matches!(
            forged_prepared_stage.commit(
                &anchor_a,
                &raw_candidate_a,
                &raw_prepared_a,
                digest("cross-prepared-durable"),
            ),
            Err(AuthorityStoreSessionError::StateMismatch)
        ));

        let (store_b, _anchor_b) = unprovisioned_and_anchor("cross-policy-root-b");
        assert!(matches!(
            store_b.issue_candidate(anchor_a),
            Err(AuthorityStoreSessionError::PolicyMismatch)
        ));
    }

    #[test]
    fn commit_outcome_unknown_never_returns_a_capability() {
        for fault in [
            TestAuthorityStoreFault::CommitUnknownBeforeApply,
            TestAuthorityStoreFault::CommitUnknownAfterApply,
        ] {
            let label = format!("unknown-{fault:?}");
            let (anchor, candidate, prepared, session) = prepared(&label);
            let store = match &session.backend {
                AuthorityStoreBackend::Product(never) => match *never {},
                AuthorityStoreBackend::Test(store) => store.clone(),
            };
            session.queue_fault(fault);
            assert!(matches!(
                session.commit(
                    &anchor,
                    &candidate,
                    &prepared,
                    digest(&format!("{label}:durable")),
                ),
                Err(AuthorityStoreSessionError::OutcomeUnknown)
            ));
            let state = store.state.lock().unwrap();
            match (&state.phase, fault) {
                (
                    TestAuthorityStorePhase::Prepared { .. },
                    TestAuthorityStoreFault::CommitUnknownBeforeApply,
                ) => {}
                (
                    TestAuthorityStorePhase::Committed {
                        capability_minted: true,
                        ..
                    },
                    TestAuthorityStoreFault::CommitUnknownAfterApply,
                ) => {}
                _ => panic!("commit-unknown returned or retained a mint ticket"),
            }
        }
    }

    #[test]
    fn fresh_observation_rejects_valid_advanced_or_pending_store() {
        for pending in [false, true] {
            let capability = committed(if pending {
                "fresh-valid-pending"
            } else {
                "fresh-valid-successor"
            });
            capability.mutate_store_for_test(|record| {
                let prepared = test_runtime_prepared_head(&record.lineage, &record.committed_head);
                if pending {
                    record.snapshot.prepared_slot =
                        cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                            prepared_head: prepared,
                        };
                } else {
                    record.committed_head =
                        test_runtime_successor(&record.lineage, &record.committed_head, &prepared);
                    record.snapshot.committed_head = record.committed_head.clone();
                }
                record.snapshot.snapshot_sha256 = record.snapshot.canonical_sha256().unwrap();
                record.snapshot.validate(&record.lineage).unwrap();
            });
            assert!(capability.into_freshly_observed().is_err());
        }
    }

    #[test]
    fn gen_zero_two_successor_binding_field_and_pending_tamper_cannot_mint() {
        for drift in 0..6 {
            let capability = committed(&format!("mint-tamper-{drift}"));
            let mut record = CommittedStoreRecord {
                lineage: capability.lineage.clone(),
                committed_head: capability.committed_head.clone(),
                snapshot: capability.snapshot.clone(),
            };
            match drift {
                0 => record.committed_head.mutation_generation = 0,
                1 => record.committed_head.mutation_generation = 2,
                2 => {
                    record.committed_head.ancestry =
                        cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Successor {
                            predecessor_committed_head_sha256: digest("tamper-predecessor"),
                            prepared_head_sha256: digest("tamper-prepared"),
                        }
                }
                3 => {
                    record.committed_head.ancestry =
                        cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Genesis {
                            first_use_committed_result_binding_sha256: digest(
                                "tamper-result-binding",
                            ),
                        }
                }
                4 => {
                    record.committed_head.authority_store_instance_sha256 =
                        digest("tamper-store-field")
                }
                5 => {
                    record.snapshot.prepared_slot =
                        cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                            prepared_head: test_runtime_prepared_head(
                                &record.lineage,
                                &record.committed_head,
                            ),
                        }
                }
                _ => unreachable!(),
            }
            if let Ok(hash) = record.committed_head.canonical_sha256() {
                record.committed_head.committed_head_sha256 = hash;
            }
            record.snapshot.committed_head = record.committed_head.clone();
            if let Ok(hash) = record.snapshot.canonical_sha256() {
                record.snapshot.snapshot_sha256 = hash;
            }
            assert!(
                validate_exact_genesis_record(&record).is_err(),
                "tamper drift {drift} entered the mint path"
            );
        }
    }

    #[test]
    fn activation_rejects_every_post_observation_store_drift_before_rpc() {
        for drift in 0..7 {
            let fresh = committed(&format!("post-observation-drift-{drift}"))
                .into_freshly_observed()
                .unwrap();
            let store = match &fresh.backend {
                AuthorityStoreBackend::Product(never) => match *never {},
                AuthorityStoreBackend::Test(store) => store.clone(),
            };
            let nonce_before = store.state.lock().unwrap().nonce_counter;
            fresh.mutate_store_for_test(|record| {
                match drift {
                    0 => record.committed_head.mutation_generation = 0,
                    1 => record.committed_head.mutation_generation = 2,
                    2 => {
                        record.committed_head.ancestry =
                            cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Genesis {
                                first_use_committed_result_binding_sha256: digest(
                                    "post-observation-wrong-result-binding",
                                ),
                            }
                    }
                    3 => {
                        record.committed_head.ancestry =
                            cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Successor {
                                predecessor_committed_head_sha256: digest(
                                    "post-observation-predecessor",
                                ),
                                prepared_head_sha256: digest("post-observation-prepared"),
                            }
                    }
                    4 => {
                        let mut mismatched = record.committed_head.clone();
                        mismatched.mutation_generation = 2;
                        record.snapshot.committed_head = mismatched;
                    }
                    5 => {
                        record.snapshot.prepared_slot =
                            cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                                prepared_head: test_runtime_prepared_head(
                                    &record.lineage,
                                    &record.committed_head,
                                ),
                            }
                    }
                    6 => {
                        record.lineage.anchor.authority_store_instance_sha256 =
                            digest("post-observation-substituted-store");
                    }
                    _ => unreachable!(),
                }
                if let Ok(hash) = record.committed_head.canonical_sha256() {
                    record.committed_head.committed_head_sha256 = hash;
                }
                if drift != 4 {
                    record.snapshot.committed_head = record.committed_head.clone();
                }
                if let Ok(hash) = record.snapshot.canonical_sha256() {
                    record.snapshot.snapshot_sha256 = hash;
                }
            });
            assert!(
                crate::direct_operation_runtime_authority_mutation_cas_client::activate_same_store(
                    fresh
                )
                .is_err(),
                "post-observation drift {drift} activated"
            );
            let state = store.state.lock().unwrap();
            assert_eq!(state.nonce_counter, nonce_before);
            assert!(state.mutation_transcript.is_empty());
        }
    }

    #[test]
    fn activation_rejects_post_observation_backend_substitution_before_rpc() {
        let first = committed("post-observation-backend-a")
            .into_freshly_observed()
            .unwrap();
        let second = committed("post-observation-backend-b")
            .into_freshly_observed()
            .unwrap();
        let FreshlyObservedFirstUseGenesis {
            backend: _backend_a,
            lineage,
            committed_head,
            snapshot,
        } = first;
        let FreshlyObservedFirstUseGenesis {
            backend: backend_b, ..
        } = second;
        let store_b = match &backend_b {
            AuthorityStoreBackend::Product(never) => match *never {},
            AuthorityStoreBackend::Test(store) => store.clone(),
        };
        let nonce_before = store_b.state.lock().unwrap().nonce_counter;
        let substituted = FreshlyObservedFirstUseGenesis {
            backend: backend_b,
            lineage,
            committed_head,
            snapshot,
        };
        assert!(
            crate::direct_operation_runtime_authority_mutation_cas_client::activate_same_store(
                substituted
            )
            .is_err()
        );
        let state = store_b.state.lock().unwrap();
        assert_eq!(state.nonce_counter, nonce_before);
        assert!(state.mutation_transcript.is_empty());
    }

    #[test]
    fn capability_surface_is_affine_and_product_backend_is_uninhabited() {
        let source = include_str!("direct_operation_runtime_authority_store_session.rs");
        for name in [
            "SealedFirstUseGenesisCommit",
            "FreshlyObservedFirstUseGenesis",
        ] {
            let declaration = format!("pub(crate) struct {name}");
            let start = source.find(&declaration).unwrap();
            let preceding = &source[start.saturating_sub(192)..start];
            assert!(
                !preceding.contains("#[derive"),
                "{name} gained a derived capability trait"
            );
        }
        for forbidden in [
            concat!("impl Clone for Sealed", "FirstUseGenesisCommit"),
            concat!(
                "#[derive(Clone)]\npub(crate) struct Sealed",
                "FirstUseGenesisCommit"
            ),
            concat!("impl Clone for Freshly", "ObservedFirstUseGenesis"),
            concat!(
                "#[derive(Clone)]\npub(crate) struct Freshly",
                "ObservedFirstUseGenesis"
            ),
            concat!("derive(Clone", ", Serialize"),
            concat!("impl Default for Sealed", "FirstUseGenesisCommit"),
            concat!("pub fn new", "_product"),
            concat!("pub(crate) fn from_", "lineage"),
            concat!("pub(crate) fn from_", "snapshot"),
            concat!("fn into_", "parts"),
            concat!("SealedOperationRuntime", "AuthorityStore"),
        ] {
            assert!(!source.contains(forbidden), "{forbidden}");
        }
        assert!(source.contains("Product(Infallible)"));
        const {
            assert!(!cas::AUTHORITY_BACKEND_PRODUCT_AVAILABLE);
            assert!(!cas::MUTATION_CAS_PRODUCT_AVAILABLE);
            assert!(!cas::CONFERS_FIRST_USE_AUTHORITY);
            assert!(!cas::CONFERS_REPLAY_AUTHORITY);
            assert!(!cas::CONFERS_EFFECT_AUTHORITY);
        }
    }

    fn test_runtime_prepared_head(
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) -> cas::DirectOperationRuntimeAuthorityPreparedHeadV1 {
        let proposed_journal_version = test_journal_version(
            &format!(
                "{}:successor-journal-identity",
                current.committed_head_sha256
            ),
            &format!("{}:successor-journal-bytes", current.committed_head_sha256),
        );
        let mut intent = cas::DirectOperationRuntimeAuthorityMutationIntentV1 {
            schema: cas::MUTATION_INTENT_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            authority_store_instance_sha256: current.authority_store_instance_sha256.clone(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            from_committed_head_sha256: current.committed_head_sha256.clone(),
            from_mutation_generation: current.mutation_generation,
            mutation_kind: cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            expected_journal_version: current.journal_version.clone(),
            observed_current_journal_version: current.journal_version.clone(),
            to_mutation_generation: current.mutation_generation.checked_add(1).unwrap(),
            proposed_journal_version,
            mutation_nonce_sha256: digest("pending-mutation-nonce"),
            mutation_intent_sha256: String::new(),
        };
        intent.mutation_intent_sha256 = intent.canonical_sha256().unwrap();
        intent.validate_for(lineage, current).unwrap();
        let mut prepared = cas::DirectOperationRuntimeAuthorityPreparedHeadV1 {
            schema: cas::PREPARED_HEAD_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            authority_identity_sha256: current.authority_identity_sha256.clone(),
            authority_store_instance_sha256: current.authority_store_instance_sha256.clone(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            from_committed_head_sha256: current.committed_head_sha256.clone(),
            from_mutation_generation: current.mutation_generation,
            to_mutation_generation: intent.to_mutation_generation,
            mutation_intent_sha256: intent.mutation_intent_sha256.clone(),
            expected_journal_version: intent.expected_journal_version.clone(),
            proposed_journal_version: intent.proposed_journal_version.clone(),
            prepared_head_sha256: String::new(),
        };
        prepared.prepared_head_sha256 = prepared.canonical_sha256().unwrap();
        prepared
            .validate_for_intent(lineage, current, &intent)
            .unwrap();
        prepared
    }

    fn test_runtime_successor(
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
        prepared: &cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
    ) -> cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
        let mut successor = cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
            schema: cas::COMMITTED_HEAD_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            authority_identity_sha256: current.authority_identity_sha256.clone(),
            authority_store_instance_sha256: current.authority_store_instance_sha256.clone(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            provider_id: current.provider_id.clone(),
            agent_id: current.agent_id.clone(),
            adapter: current.adapter,
            journal_epoch: current.journal_epoch.clone(),
            state_directory_identity_sha256: current.state_directory_identity_sha256.clone(),
            mutation_generation: prepared.to_mutation_generation,
            journal_version: prepared.proposed_journal_version.clone(),
            ancestry: cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Successor {
                predecessor_committed_head_sha256: current.committed_head_sha256.clone(),
                prepared_head_sha256: prepared.prepared_head_sha256.clone(),
            },
            committed_head_sha256: String::new(),
        };
        successor.committed_head_sha256 = successor.canonical_sha256().unwrap();
        successor
            .validate_successor(lineage, current, prepared)
            .unwrap();
        successor
    }

    fn test_journal_version(
        identity_label: &str,
        bytes_label: &str,
    ) -> cas::DirectOperationRuntimeAuthorityJournalVersionV1 {
        let mut version = cas::DirectOperationRuntimeAuthorityJournalVersionV1 {
            schema: cas::JOURNAL_VERSION_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            journal_identity_sha256: digest(identity_label),
            journal_bytes_sha256: digest(bytes_label),
            journal_version_sha256: String::new(),
        };
        version.journal_version_sha256 = version.canonical_sha256().unwrap();
        version.validate().unwrap();
        version
    }
}
