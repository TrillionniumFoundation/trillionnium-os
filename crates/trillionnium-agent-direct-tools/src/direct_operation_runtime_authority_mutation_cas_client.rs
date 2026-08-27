//! Source-only sealed client for the independent operation-journal mutation
//! CAS authority.
//!
//! There is deliberately no product backend constructor or transport in this
//! module. Non-test continuations consume whole affine first-use or replay
//! observations minted by the same-store state machine; bare ABI records
//! cannot select or reconstruct its backend. That affine handoff becomes the
//! active backend for every mutation verb.

use trillionnium_os_types::direct_operation_runtime_authority_mutation_cas as cas;

use crate::direct_operation_runtime_authority_store_session::{
    ActiveAuthorityStoreSession, AuthorityStoreMutationCallFailure, FreshlyObservedFirstUseGenesis,
    FreshlyObservedReplayAuthorityStore,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendCallFailure {
    /// The request was provably not admitted and may be retried with a fresh
    /// request nonce while retaining the immutable mutation transaction.
    NotApplied,
    /// The authority denied the exact request. The caller must reopen.
    Denied,
    /// The request might have changed authority state.
    OutcomeUnknown,
}

type BackendCall<T> = Result<T, BackendCallFailure>;

fn map_same_store_failure(failure: AuthorityStoreMutationCallFailure) -> BackendCallFailure {
    match failure {
        AuthorityStoreMutationCallFailure::NotApplied => BackendCallFailure::NotApplied,
        AuthorityStoreMutationCallFailure::Denied => BackendCallFailure::Denied,
        AuthorityStoreMutationCallFailure::OutcomeUnknown => BackendCallFailure::OutcomeUnknown,
    }
}

/// Private authority RPC surface. The product source has no implementation.
/// The in-memory test authority implements the complete protocol; the
/// non-product same-store continuation delegates every verb to one store.
trait MutationCasAuthorityBackend {
    fn issue_nonce(&self, phase: &'static str, binding_sha256: &str) -> BackendCall<String>;
    fn prepare_call(
        &self,
        request: &cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
    ) -> BackendCall<cas::DirectOperationRuntimeAuthorityPrepareReceiptV1>;
    fn commit_call(
        &self,
        request: &cas::DirectOperationRuntimeAuthorityCommitRequestV1,
    ) -> BackendCall<cas::DirectOperationRuntimeAuthorityCommitReceiptV1>;
    fn observe_call(
        &self,
        request: &cas::DirectOperationRuntimeAuthorityObserveRequestV1,
    ) -> BackendCall<cas::DirectOperationRuntimeAuthorityObserveResponseV1>;
    fn reconcile_call(
        &self,
        request: &cas::DirectOperationRuntimeAuthorityReconcileRequestV1,
    ) -> BackendCall<cas::DirectOperationRuntimeAuthorityReconcileResponseV1>;
}

enum SealedMutationCasBackend {
    Product(std::convert::Infallible),
    /// Affine same-store continuation minted only after an exact first-use or
    /// replay observation. It is deliberately not cloneable.
    SameStore(Box<ActiveAuthorityStoreSession>),
    #[cfg(test)]
    Test(TestMutationCasAuthority),
}

impl SealedMutationCasBackend {
    fn next_mutation_nonce(
        &self,
        _phase: &'static str,
        _binding_sha256: &str,
    ) -> BackendCall<String> {
        match self {
            Self::Product(never) => match *never {},
            Self::SameStore(authority) => authority
                .mutation_request_nonce(_phase, _binding_sha256)
                .map_err(map_same_store_failure),
            #[cfg(test)]
            Self::Test(authority) => authority.issue_nonce(_phase, _binding_sha256),
        }
    }

    fn next_observe_nonce(&self, phase: &'static str, binding_sha256: &str) -> BackendCall<String> {
        match self {
            Self::Product(never) => match *never {},
            Self::SameStore(authority) => authority
                .mutation_request_nonce(phase, binding_sha256)
                .map_err(map_same_store_failure),
            #[cfg(test)]
            Self::Test(authority) => authority.issue_nonce(phase, binding_sha256),
        }
    }

    fn prepare(
        &self,
        _request: &cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
    ) -> BackendCall<cas::DirectOperationRuntimeAuthorityPrepareReceiptV1> {
        match self {
            Self::Product(never) => match *never {},
            Self::SameStore(authority) => authority
                .prepare_mutation_head(_request)
                .map_err(map_same_store_failure),
            #[cfg(test)]
            Self::Test(authority) => authority.prepare_call(_request),
        }
    }

    fn commit(
        &self,
        _request: &cas::DirectOperationRuntimeAuthorityCommitRequestV1,
    ) -> BackendCall<cas::DirectOperationRuntimeAuthorityCommitReceiptV1> {
        match self {
            Self::Product(never) => match *never {},
            Self::SameStore(authority) => authority
                .commit_mutation_head(_request)
                .map_err(map_same_store_failure),
            #[cfg(test)]
            Self::Test(authority) => authority.commit_call(_request),
        }
    }

    fn observe(
        &self,
        _request: &cas::DirectOperationRuntimeAuthorityObserveRequestV1,
    ) -> BackendCall<cas::DirectOperationRuntimeAuthorityObserveResponseV1> {
        match self {
            Self::Product(never) => match *never {},
            Self::SameStore(authority) => authority
                .observe_mutation_head(_request)
                .map_err(map_same_store_failure),
            #[cfg(test)]
            Self::Test(authority) => authority.observe_call(_request),
        }
    }

    fn reconcile(
        &self,
        _request: &cas::DirectOperationRuntimeAuthorityReconcileRequestV1,
    ) -> BackendCall<cas::DirectOperationRuntimeAuthorityReconcileResponseV1> {
        match self {
            Self::Product(never) => match *never {},
            Self::SameStore(authority) => authority
                .reconcile_mutation_head(_request)
                .map_err(map_same_store_failure),
            #[cfg(test)]
            Self::Test(authority) => authority.reconcile_call(_request),
        }
    }

    fn confirm_replayed_committed_mutation(
        &self,
        _intent: &cas::DirectOperationRuntimeAuthorityMutationIntentV1,
        _prepared: &cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
    ) -> BackendCall<()> {
        match self {
            Self::Product(never) => match *never {},
            Self::SameStore(authority) => authority
                .confirm_replayed_committed_mutation(_intent, _prepared)
                .map_err(map_same_store_failure),
            #[cfg(test)]
            Self::Test(_) => Err(BackendCallFailure::Denied),
        }
    }
}

enum SealedWriterLockWitnessSource {
    Product(std::convert::Infallible),
    Journal,
    #[cfg(test)]
    Test,
}

/// Private proof that the journal owner already holds the exact writer lock
/// for the mutation transaction being opened. The only non-test constructor
/// requires the unforgeable `operation_journal` module seal and binds the
/// digest derived from its live `JournalLock` guard.
pub(crate) struct SealedWriterLockWitness {
    writer_lock_identity_sha256: String,
    source: SealedWriterLockWitnessSource,
}

impl SealedWriterLockWitness {
    fn into_identity(self) -> String {
        let Self {
            writer_lock_identity_sha256: _writer_lock_identity_sha256,
            source,
        } = self;
        match source {
            SealedWriterLockWitnessSource::Product(never) => match never {},
            SealedWriterLockWitnessSource::Journal => _writer_lock_identity_sha256,
            #[cfg(test)]
            SealedWriterLockWitnessSource::Test => _writer_lock_identity_sha256,
        }
    }

    pub(crate) fn from_journal(
        _seal: &crate::operation_journal::MutationCasJournalSeal,
        writer_lock_identity_sha256: String,
    ) -> Self {
        Self {
            writer_lock_identity_sha256,
            source: SealedWriterLockWitnessSource::Journal,
        }
    }

    #[cfg(test)]
    fn for_test(writer_lock_identity_sha256: String) -> Self {
        assert!(
            writer_lock_identity_sha256.len() == 64
                && !writer_lock_identity_sha256.bytes().all(|byte| byte == b'0')
                && writer_lock_identity_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        Self {
            writer_lock_identity_sha256,
            source: SealedWriterLockWitnessSource::Test,
        }
    }
}

enum SealedDurableStagedMutationProofSource {
    Product(std::convert::Infallible),
    Journal,
    #[cfg(test)]
    Test,
}

/// Sealed proof that both the exact proposed journal candidate and its
/// transaction sidecar are already durable under the live writer lock. The
/// only non-test constructor requires the journal module seal and receives
/// fd/inode/fsync observations from the retained local stage.
pub(crate) struct SealedDurableStagedMutationProof {
    staged_candidate_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    transaction_sidecar_identity_sha256: String,
    transaction_sidecar_bytes_sha256: String,
    sidecar_first_use_lineage_sha256: String,
    sidecar_from_committed_head_sha256: String,
    sidecar_mutation_transaction_sha256: String,
    sidecar_mutation_kind: cas::DirectOperationRuntimeAuthorityMutationKindV1,
    sidecar_current_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    sidecar_proposed_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    sidecar_writer_lock_identity_sha256: String,
    source: SealedDurableStagedMutationProofSource,
}

struct DurableStagedMutationBinding {
    staged_candidate_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    transaction_sidecar_identity_sha256: String,
    transaction_sidecar_bytes_sha256: String,
    sidecar_first_use_lineage_sha256: String,
    sidecar_from_committed_head_sha256: String,
    sidecar_mutation_transaction_sha256: String,
    sidecar_mutation_kind: cas::DirectOperationRuntimeAuthorityMutationKindV1,
    sidecar_current_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    sidecar_proposed_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    sidecar_writer_lock_identity_sha256: String,
}

impl SealedDurableStagedMutationProof {
    fn into_binding(self) -> DurableStagedMutationBinding {
        match self {
            Self {
                source: SealedDurableStagedMutationProofSource::Product(never),
                ..
            } => match never {},
            Self {
                staged_candidate_journal_version,
                transaction_sidecar_identity_sha256,
                transaction_sidecar_bytes_sha256,
                sidecar_first_use_lineage_sha256,
                sidecar_from_committed_head_sha256,
                sidecar_mutation_transaction_sha256,
                sidecar_mutation_kind,
                sidecar_current_journal_version,
                sidecar_proposed_journal_version,
                sidecar_writer_lock_identity_sha256,
                source: SealedDurableStagedMutationProofSource::Journal,
            } => DurableStagedMutationBinding {
                staged_candidate_journal_version,
                transaction_sidecar_identity_sha256,
                transaction_sidecar_bytes_sha256,
                sidecar_first_use_lineage_sha256,
                sidecar_from_committed_head_sha256,
                sidecar_mutation_transaction_sha256,
                sidecar_mutation_kind,
                sidecar_current_journal_version,
                sidecar_proposed_journal_version,
                sidecar_writer_lock_identity_sha256,
            },
            #[cfg(test)]
            Self {
                staged_candidate_journal_version,
                transaction_sidecar_identity_sha256,
                transaction_sidecar_bytes_sha256,
                sidecar_first_use_lineage_sha256,
                sidecar_from_committed_head_sha256,
                sidecar_mutation_transaction_sha256,
                sidecar_mutation_kind,
                sidecar_current_journal_version,
                sidecar_proposed_journal_version,
                sidecar_writer_lock_identity_sha256,
                source: SealedDurableStagedMutationProofSource::Test,
            } => DurableStagedMutationBinding {
                staged_candidate_journal_version,
                transaction_sidecar_identity_sha256,
                transaction_sidecar_bytes_sha256,
                sidecar_first_use_lineage_sha256,
                sidecar_from_committed_head_sha256,
                sidecar_mutation_transaction_sha256,
                sidecar_mutation_kind,
                sidecar_current_journal_version,
                sidecar_proposed_journal_version,
                sidecar_writer_lock_identity_sha256,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_journal(
        _seal: &crate::operation_journal::MutationCasJournalSeal,
        staged_candidate_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        transaction_sidecar_identity_sha256: String,
        transaction_sidecar_bytes_sha256: String,
        sidecar_first_use_lineage_sha256: String,
        sidecar_from_committed_head_sha256: String,
        sidecar_mutation_transaction_sha256: String,
        sidecar_mutation_kind: cas::DirectOperationRuntimeAuthorityMutationKindV1,
        sidecar_current_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        sidecar_proposed_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        sidecar_writer_lock_identity_sha256: String,
    ) -> Self {
        Self {
            staged_candidate_journal_version,
            transaction_sidecar_identity_sha256,
            transaction_sidecar_bytes_sha256,
            sidecar_first_use_lineage_sha256,
            sidecar_from_committed_head_sha256,
            sidecar_mutation_transaction_sha256,
            sidecar_mutation_kind,
            sidecar_current_journal_version,
            sidecar_proposed_journal_version,
            sidecar_writer_lock_identity_sha256,
            source: SealedDurableStagedMutationProofSource::Journal,
        }
    }

    #[cfg(test)]
    fn for_test(plan: &PlannedMutationCasSession) -> Self {
        Self {
            staged_candidate_journal_version: plan.intent.proposed_journal_version.clone(),
            transaction_sidecar_identity_sha256: trillionnium_os_types::sha256_bytes(
                b"test-mutation-sidecar-identity",
            ),
            transaction_sidecar_bytes_sha256: trillionnium_os_types::sha256_bytes(
                b"test-mutation-sidecar-bytes",
            ),
            sidecar_first_use_lineage_sha256: plan.session.lineage.first_use_lineage_sha256.clone(),
            sidecar_from_committed_head_sha256: plan.session.current.committed_head_sha256.clone(),
            sidecar_mutation_transaction_sha256: plan.intent.mutation_intent_sha256.clone(),
            sidecar_mutation_kind: plan.intent.mutation_kind,
            sidecar_current_journal_version: plan.intent.observed_current_journal_version.clone(),
            sidecar_proposed_journal_version: plan.intent.proposed_journal_version.clone(),
            sidecar_writer_lock_identity_sha256: plan.writer_lock_identity_sha256.clone(),
            source: SealedDurableStagedMutationProofSource::Test,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MutationCasFailStopReason {
    InvalidLocalInput,
    ObserveDenied,
    ObserveOutcomeUnknown,
    PrepareNotApplied,
    PrepareDenied,
    PrepareOutcomeUnknown,
    InvalidPrepareReceipt,
    LocalPublicationUncertain,
    CommitNotApplied,
    CommitDenied,
    CommitOutcomeUnknown,
    InvalidCommitReceipt,
}

enum RecoveryState {
    None {
        writer_lock_identity_sha256: Option<String>,
    },
    Uncertain {
        cause: cas::DirectOperationRuntimeAuthorityReconcileCauseV1,
        intent: Box<cas::DirectOperationRuntimeAuthorityMutationIntentV1>,
        prepared_knowledge: Box<cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1>,
        /// Once an exact local writer-lock identity has participated in
        /// publication or reconciliation, every later recovery attempt for
        /// this durable mutation transaction must use that same identity.
        writer_lock_identity_sha256: Option<String>,
    },
}

/// A usable session always owns an authority backend, a validated first-use
/// lineage, and one mandatory committed head. None of these can be synthesized
/// from a local observation.
pub(crate) struct SealedCommittedMutationCasSession {
    backend: SealedMutationCasBackend,
    lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    current: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MutationCasActivationError {
    InvalidGenesis,
    SameStoreMismatch,
}

/// Consume the whole freshly-observed same-store capability. Bare lineage,
/// head, or snapshot records can never call this constructor, and the backend
/// remains embedded in the affine session.
pub(crate) fn activate_same_store(
    authority: FreshlyObservedFirstUseGenesis,
) -> Result<SealedCommittedMutationCasSession, MutationCasActivationError> {
    let lineage = authority.lineage().clone();
    let current = authority.committed_head().clone();
    let snapshot = authority.snapshot().clone();
    lineage
        .validate()
        .map_err(|_| MutationCasActivationError::InvalidGenesis)?;
    current
        .validate(&lineage)
        .map_err(|_| MutationCasActivationError::InvalidGenesis)?;
    snapshot
        .validate(&lineage)
        .map_err(|_| MutationCasActivationError::InvalidGenesis)?;
    let expected_ancestry = cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Genesis {
        first_use_committed_result_binding_sha256: lineage
            .committed_result_binding
            .first_use_committed_result_binding_sha256
            .clone(),
    };
    if current.mutation_generation != 1
        || current.journal_version != lineage.anchor.genesis_journal_version
        || current.ancestry != expected_ancestry
        || snapshot.committed_head != current
        || snapshot.prepared_slot != cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty
    {
        return Err(MutationCasActivationError::InvalidGenesis);
    }
    let authority = authority
        .into_active_mutation_store()
        .map_err(|_| MutationCasActivationError::SameStoreMismatch)?;
    if authority.first_use_lineage() != &lineage
        || authority.session_seed_committed_head() != &current
    {
        return Err(MutationCasActivationError::SameStoreMismatch);
    }
    Ok(SealedCommittedMutationCasSession {
        backend: SealedMutationCasBackend::SameStore(Box::new(authority)),
        lineage,
        current,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplayMutationCasActivationError {
    InvalidReplayObservation,
    SameStoreMismatch,
    LocalJournalMismatch,
    PendingMutationRequiresReconciliation,
}

enum SealedReplayJournalLayout {
    Clean,
    Staged {
        intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
        staged_candidate_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        writer_lock_identity_sha256: String,
    },
    Published {
        intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
        writer_lock_identity_sha256: String,
    },
}

/// Exact local restart layout sealed by `operation_journal` while its retained
/// writer lock and private file descriptors are still live.
pub(crate) struct SealedReplayJournalState {
    named_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    layout: SealedReplayJournalLayout,
}

impl SealedReplayJournalState {
    pub(crate) fn clean(
        _seal: &crate::operation_journal::MutationCasJournalSeal,
        named_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    ) -> Self {
        Self {
            named_journal_version,
            layout: SealedReplayJournalLayout::Clean,
        }
    }

    pub(crate) fn staged(
        _seal: &crate::operation_journal::MutationCasJournalSeal,
        named_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        staged_candidate_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
        writer_lock_identity_sha256: String,
    ) -> Self {
        Self {
            named_journal_version,
            layout: SealedReplayJournalLayout::Staged {
                intent,
                staged_candidate_journal_version,
                writer_lock_identity_sha256,
            },
        }
    }

    pub(crate) fn published(
        _seal: &crate::operation_journal::MutationCasJournalSeal,
        named_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
        writer_lock_identity_sha256: String,
    ) -> Self {
        Self {
            named_journal_version,
            layout: SealedReplayJournalLayout::Published {
                intent,
                writer_lock_identity_sha256,
            },
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum ReplayMutationCasActivation {
    Current(SealedCommittedMutationCasSession),
    Reconcile(
        FailStoppedMutationCasSession,
        SealedLocalReconcileObservations,
    ),
    Cleanup(ReconciledCommittedMutationCasSession),
}

/// Consume a fresh replay observation from the same embedded store. A clean
/// replay can activate only when the externally observed committed head names
/// the exact journal inode/bytes opened under retained local custody.
pub(crate) fn activate_same_store_replay(
    authority: FreshlyObservedReplayAuthorityStore,
    local: SealedReplayJournalState,
) -> Result<ReplayMutationCasActivation, ReplayMutationCasActivationError> {
    let lineage = authority.lineage().clone();
    let current = authority.committed_head().clone();
    let snapshot = authority.snapshot().clone();
    lineage
        .validate()
        .map_err(|_| ReplayMutationCasActivationError::InvalidReplayObservation)?;
    current
        .validate(&lineage)
        .map_err(|_| ReplayMutationCasActivationError::InvalidReplayObservation)?;
    snapshot
        .validate(&lineage)
        .map_err(|_| ReplayMutationCasActivationError::InvalidReplayObservation)?;
    local
        .named_journal_version
        .validate()
        .map_err(|_| ReplayMutationCasActivationError::LocalJournalMismatch)?;
    if snapshot.committed_head != current {
        return Err(ReplayMutationCasActivationError::InvalidReplayObservation);
    }
    let authority = authority
        .into_active_mutation_store()
        .map_err(|_| ReplayMutationCasActivationError::SameStoreMismatch)?;
    if authority.first_use_lineage() != &lineage
        || authority.session_seed_committed_head() != &current
    {
        return Err(ReplayMutationCasActivationError::SameStoreMismatch);
    }
    let session = SealedCommittedMutationCasSession {
        backend: SealedMutationCasBackend::SameStore(Box::new(authority)),
        lineage,
        current,
    };
    activate_replay_local_state(session, snapshot, local)
}

fn activate_replay_local_state(
    session: SealedCommittedMutationCasSession,
    snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
    local: SealedReplayJournalState,
) -> Result<ReplayMutationCasActivation, ReplayMutationCasActivationError> {
    let SealedReplayJournalState {
        named_journal_version,
        layout,
    } = local;
    match (layout, snapshot.prepared_slot) {
        (
            SealedReplayJournalLayout::Clean,
            cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
        ) if named_journal_version == session.current.journal_version => {
            Ok(ReplayMutationCasActivation::Current(session))
        }
        (
            SealedReplayJournalLayout::Clean,
            cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending { .. },
        ) => Err(ReplayMutationCasActivationError::PendingMutationRequiresReconciliation),
        (
            SealedReplayJournalLayout::Staged {
                intent,
                staged_candidate_journal_version,
                writer_lock_identity_sha256,
            },
            prepared_slot,
        ) => {
            if !valid_nonzero_sha256(&writer_lock_identity_sha256)
                || named_journal_version != session.current.journal_version
                || named_journal_version != intent.observed_current_journal_version
                || staged_candidate_journal_version != intent.proposed_journal_version
                || intent
                    .validate_for(&session.lineage, &session.current)
                    .is_err()
            {
                return Err(ReplayMutationCasActivationError::LocalJournalMismatch);
            }
            let (cause, prepared_knowledge) = match prepared_slot {
                cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty => (
                    cas::DirectOperationRuntimeAuthorityReconcileCauseV1::PrepareResponseUnknown,
                    cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Unknown,
                ),
                cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending { prepared_head } => {
                    if prepared_head
                        .validate_for_intent(&session.lineage, &session.current, &intent)
                        .is_err()
                    {
                        return Err(ReplayMutationCasActivationError::InvalidReplayObservation);
                    }
                    (
                        cas::DirectOperationRuntimeAuthorityReconcileCauseV1::RestartWithPrepared,
                        cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                            prepared_head,
                        },
                    )
                }
            };
            let observations = SealedLocalReconcileObservations {
                writer_lock_identity_sha256: writer_lock_identity_sha256.clone(),
                named_journal: LocalEntryObservation::Present(named_journal_version),
                staged_candidate: LocalEntryObservation::Present(staged_candidate_journal_version),
                _source: SealedLocalObservationSource::Journal,
            };
            let failed = session.fail_stopped(
                MutationCasFailStopReason::LocalPublicationUncertain,
                uncertain_recovery(
                    cause,
                    intent,
                    prepared_knowledge,
                    writer_lock_identity_sha256,
                ),
            );
            Ok(ReplayMutationCasActivation::Reconcile(failed, observations))
        }
        (
            SealedReplayJournalLayout::Published {
                intent,
                writer_lock_identity_sha256,
            },
            cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending { prepared_head },
        ) => {
            if !valid_nonzero_sha256(&writer_lock_identity_sha256)
                || named_journal_version != intent.proposed_journal_version
                || intent
                    .validate_for(&session.lineage, &session.current)
                    .is_err()
                || prepared_head
                    .validate_for_intent(&session.lineage, &session.current, &intent)
                    .is_err()
            {
                return Err(ReplayMutationCasActivationError::LocalJournalMismatch);
            }
            let observations = SealedLocalReconcileObservations {
                writer_lock_identity_sha256: writer_lock_identity_sha256.clone(),
                named_journal: LocalEntryObservation::Present(named_journal_version),
                staged_candidate: LocalEntryObservation::Missing,
                _source: SealedLocalObservationSource::Journal,
            };
            let failed = session.fail_stopped(
                MutationCasFailStopReason::LocalPublicationUncertain,
                uncertain_recovery(
                    cas::DirectOperationRuntimeAuthorityReconcileCauseV1::LocalPublicationUnknown,
                    intent,
                    cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                        prepared_head,
                    },
                    writer_lock_identity_sha256,
                ),
            );
            Ok(ReplayMutationCasActivation::Reconcile(failed, observations))
        }
        (
            SealedReplayJournalLayout::Published {
                intent,
                writer_lock_identity_sha256,
            },
            cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
        ) => {
            if !valid_nonzero_sha256(&writer_lock_identity_sha256)
                || named_journal_version != session.current.journal_version
                || named_journal_version != intent.proposed_journal_version
            {
                return Err(ReplayMutationCasActivationError::LocalJournalMismatch);
            }
            let prepared_head = replay_prepared_head_for_committed_successor(&session, &intent)?;
            session
                .backend
                .confirm_replayed_committed_mutation(&intent, &prepared_head)
                .map_err(|_| ReplayMutationCasActivationError::SameStoreMismatch)?;
            Ok(ReplayMutationCasActivation::Cleanup(
                ReconciledCommittedMutationCasSession {
                    expected_named_journal_version: named_journal_version,
                    session,
                    intent,
                    prepared_knowledge:
                        cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                            prepared_head,
                        },
                    writer_lock_identity_sha256,
                },
            ))
        }
        _ => Err(ReplayMutationCasActivationError::LocalJournalMismatch),
    }
}

/// Validate an already-committed replay successor without inventing its
/// predecessor record. The durable sidecar carries the immutable intent, and
/// the externally observed successor carries both predecessor and prepared
/// hashes in its ancestry. Reconstructing the deterministic prepared record
/// is safe; reconstructing a missing committed predecessor is deliberately
/// forbidden.
fn replay_prepared_head_for_committed_successor(
    session: &SealedCommittedMutationCasSession,
    intent: &cas::DirectOperationRuntimeAuthorityMutationIntentV1,
) -> Result<cas::DirectOperationRuntimeAuthorityPreparedHeadV1, ReplayMutationCasActivationError> {
    intent
        .expected_journal_version
        .validate()
        .map_err(|_| ReplayMutationCasActivationError::LocalJournalMismatch)?;
    intent
        .observed_current_journal_version
        .validate()
        .map_err(|_| ReplayMutationCasActivationError::LocalJournalMismatch)?;
    intent
        .proposed_journal_version
        .validate()
        .map_err(|_| ReplayMutationCasActivationError::LocalJournalMismatch)?;
    let expected_generation = intent
        .from_mutation_generation
        .checked_add(1)
        .ok_or(ReplayMutationCasActivationError::LocalJournalMismatch)?;
    if intent.schema != cas::MUTATION_INTENT_V1_SCHEMA
        || intent.protocol != cas::PROTOCOL
        || intent.authority_store_instance_sha256
            != session.lineage.anchor.authority_store_instance_sha256
        || intent.first_use_lineage_sha256 != session.lineage.first_use_lineage_sha256
        || intent.from_mutation_generation == 0
        || intent.to_mutation_generation != expected_generation
        || intent.to_mutation_generation != session.current.mutation_generation
        || intent.expected_journal_version != intent.observed_current_journal_version
        || intent.proposed_journal_version != session.current.journal_version
        || intent.proposed_journal_version.journal_identity_sha256
            == intent.expected_journal_version.journal_identity_sha256
        || intent.proposed_journal_version.journal_bytes_sha256
            == intent.expected_journal_version.journal_bytes_sha256
        || !valid_nonzero_sha256(&intent.from_committed_head_sha256)
        || !valid_nonzero_sha256(&intent.mutation_nonce_sha256)
        || !valid_nonzero_sha256(&intent.mutation_intent_sha256)
        || intent
            .canonical_sha256()
            .map_err(|_| ReplayMutationCasActivationError::LocalJournalMismatch)?
            != intent.mutation_intent_sha256
    {
        return Err(ReplayMutationCasActivationError::LocalJournalMismatch);
    }
    let mut prepared_head = cas::DirectOperationRuntimeAuthorityPreparedHeadV1 {
        schema: cas::PREPARED_HEAD_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        authority_identity_sha256: session.lineage.anchor.authority_identity_sha256.clone(),
        authority_store_instance_sha256: session
            .lineage
            .anchor
            .authority_store_instance_sha256
            .clone(),
        first_use_lineage_sha256: session.lineage.first_use_lineage_sha256.clone(),
        from_committed_head_sha256: intent.from_committed_head_sha256.clone(),
        from_mutation_generation: intent.from_mutation_generation,
        to_mutation_generation: intent.to_mutation_generation,
        mutation_intent_sha256: intent.mutation_intent_sha256.clone(),
        expected_journal_version: intent.expected_journal_version.clone(),
        proposed_journal_version: intent.proposed_journal_version.clone(),
        prepared_head_sha256: String::new(),
    };
    prepared_head.prepared_head_sha256 = prepared_head
        .canonical_sha256()
        .map_err(|_| ReplayMutationCasActivationError::LocalJournalMismatch)?;
    let expected_ancestry = cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Successor {
        predecessor_committed_head_sha256: intent.from_committed_head_sha256.clone(),
        prepared_head_sha256: prepared_head.prepared_head_sha256.clone(),
    };
    if session.current.ancestry != expected_ancestry {
        return Err(ReplayMutationCasActivationError::InvalidReplayObservation);
    }
    Ok(prepared_head)
}

/// Pure local mutation plan. This type deliberately has no PREPARE method:
/// the only continuation is binding an exact sealed durable-stage proof.
pub(crate) struct PlannedMutationCasSession {
    session: SealedCommittedMutationCasSession,
    intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    writer_lock_identity_sha256: String,
}

/// A PREPARE-capable session exists only after exact staged candidate and
/// sidecar durability have been sealed and bound to the immutable plan.
pub(crate) struct StagedMutationCasSession {
    session: SealedCommittedMutationCasSession,
    intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    writer_lock_identity_sha256: String,
}

pub(crate) struct RetryablePrepareMutationCasSession {
    session: SealedCommittedMutationCasSession,
    intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    previous_request_nonce_sha256: String,
    writer_lock_identity_sha256: String,
}

pub(crate) struct PreparedMutationCasSession {
    session: SealedCommittedMutationCasSession,
    prepare_request: cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
    prepare_receipt: cas::DirectOperationRuntimeAuthorityPrepareReceiptV1,
    writer_lock_identity_sha256: String,
}

pub(crate) struct LocallyPublishedMutationCasSession {
    prepared: PreparedMutationCasSession,
    local_publication: cas::DirectOperationRuntimeAuthorityLocalPublicationV1,
}

pub(crate) struct FailStoppedMutationCasSession {
    backend: SealedMutationCasBackend,
    lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    current: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    reason: MutationCasFailStopReason,
    recovery: RecoveryState,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum ObserveTransition {
    Current(SealedCommittedMutationCasSession),
    FailStopped(FailStoppedMutationCasSession),
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum PlanTransition {
    Planned(PlannedMutationCasSession),
    FailStopped(FailStoppedMutationCasSession),
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum DurableStageTransition {
    Staged(StagedMutationCasSession),
    FailStopped(FailStoppedMutationCasSession),
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum PrepareTransition {
    Prepared(PreparedMutationCasSession),
    Retryable(RetryablePrepareMutationCasSession),
    FailStopped(FailStoppedMutationCasSession),
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum LocalPublicationTransition {
    Published(LocallyPublishedMutationCasSession),
    FailStopped(FailStoppedMutationCasSession),
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum CommitTransition {
    Committed(ReconciledCommittedMutationCasSession),
    FailStopped(FailStoppedMutationCasSession),
}

/// A reconciled pending mutation is still bound to the original immutable
/// intent and the exact authority-observed prepared head. The only executable
/// continuation is a fresh PREPARE exchange for that same transaction.
pub(crate) struct ReconciledPreparedMutationCasSession {
    session: SealedCommittedMutationCasSession,
    intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    prepared_head: cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
    writer_lock_identity_sha256: String,
    recovery_cause: cas::DirectOperationRuntimeAuthorityReconcileCauseV1,
}

/// A terminal authority classification, including a valid direct COMMIT
/// receipt, is not yet a usable committed session. The journal owner must
/// first prove the exact named version, staged-name cleanup, and writer-lock
/// continuity; reopening then performs a fresh authority OBSERVE.
pub(crate) struct ReconciledCommittedMutationCasSession {
    session: SealedCommittedMutationCasSession,
    intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    prepared_knowledge: cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1,
    writer_lock_identity_sha256: String,
    expected_named_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum ReconcileTransition {
    NoMutation(ReconciledCommittedMutationCasSession),
    ResumeExactPreparedPublication(ReconciledPreparedMutationCasSession),
    RetryExactCommit(ReconciledPreparedMutationCasSession),
    Committed(ReconciledCommittedMutationCasSession),
    Hold(ReopenRequired),
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum ReprepareTransition {
    Prepared(PreparedMutationCasSession),
    FailStopped(FailStoppedMutationCasSession),
    Hold(ReopenRequired),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReopenRequired {
    reason: MutationCasFailStopReason,
}

impl ReopenRequired {
    #[cfg(test)]
    fn reason(&self) -> MutationCasFailStopReason {
        self.reason
    }
}

impl SealedCommittedMutationCasSession {
    pub(crate) fn committed_head_sha256(&self) -> &str {
        &self.current.committed_head_sha256
    }

    #[cfg(test)]
    pub(crate) fn queue_same_store_fault_for_test(
        &self,
        fault: crate::direct_operation_runtime_authority_store_session::TestAuthorityStoreFault,
    ) -> bool {
        match &self.backend {
            SealedMutationCasBackend::Product(never) => match *never {},
            SealedMutationCasBackend::SameStore(authority) => {
                authority.queue_fault(fault);
                true
            }
            SealedMutationCasBackend::Test(_) => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn mutation_generation_for_test(&self) -> u64 {
        self.current.mutation_generation
    }

    #[cfg(test)]
    pub(crate) fn same_store_observation_snapshot_for_test(
        &self,
    ) -> Option<(u64, Vec<(String, String)>)> {
        match &self.backend {
            SealedMutationCasBackend::Product(never) => match *never {},
            SealedMutationCasBackend::SameStore(authority) => Some((
                authority.test_nonce_counter(),
                authority.test_observe_transcript(),
            )),
            SealedMutationCasBackend::Test(_) => None,
        }
    }

    pub(crate) fn validate_current(
        self,
        observed_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    ) -> ObserveTransition {
        self.validate_current_with_writer_lock(observed_journal_version, None)
    }

    fn validate_current_with_writer_lock(
        self,
        observed_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        writer_lock_identity_sha256: Option<String>,
    ) -> ObserveTransition {
        if observed_journal_version != self.current.journal_version {
            return ObserveTransition::FailStopped(self.fail_stopped(
                MutationCasFailStopReason::InvalidLocalInput,
                no_recovery(writer_lock_identity_sha256),
            ));
        }
        let request = match build_observe_request(
            &self.backend,
            &self.lineage,
            &self.current,
            observed_journal_version,
        ) {
            Ok(request) => request,
            Err(()) => {
                return ObserveTransition::FailStopped(self.fail_stopped(
                    MutationCasFailStopReason::InvalidLocalInput,
                    no_recovery(writer_lock_identity_sha256),
                ));
            }
        };
        match self.backend.observe(&request) {
            Ok(response)
                if response
                    .validate_for(&self.lineage, &request, &self.current)
                    .is_ok() =>
            {
                ObserveTransition::Current(self)
            }
            Ok(_) | Err(BackendCallFailure::Denied | BackendCallFailure::NotApplied) => {
                ObserveTransition::FailStopped(self.fail_stopped(
                    MutationCasFailStopReason::ObserveDenied,
                    no_recovery(writer_lock_identity_sha256),
                ))
            }
            Err(BackendCallFailure::OutcomeUnknown) => {
                ObserveTransition::FailStopped(self.fail_stopped(
                    MutationCasFailStopReason::ObserveOutcomeUnknown,
                    no_recovery(writer_lock_identity_sha256),
                ))
            }
        }
    }

    /// Build and validate the immutable mutation intent without issuing a
    /// backend nonce or performing any authority RPC.
    pub(crate) fn plan_prepare(
        self,
        writer_lock: SealedWriterLockWitness,
        mutation_kind: cas::DirectOperationRuntimeAuthorityMutationKindV1,
        observed_current_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        proposed_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        mutation_nonce_sha256: String,
    ) -> PlanTransition {
        let writer_lock_identity_sha256 = writer_lock.into_identity();
        let intent = match build_mutation_intent(
            &self.lineage,
            &self.current,
            mutation_kind,
            observed_current_journal_version,
            proposed_journal_version,
            mutation_nonce_sha256,
        ) {
            Ok(intent) => intent,
            Err(()) => {
                return PlanTransition::FailStopped(self.fail_stopped(
                    MutationCasFailStopReason::InvalidLocalInput,
                    no_recovery(Some(writer_lock_identity_sha256)),
                ));
            }
        };
        PlanTransition::Planned(PlannedMutationCasSession {
            session: self,
            intent,
            writer_lock_identity_sha256,
        })
    }

    fn fail_stopped(
        self,
        reason: MutationCasFailStopReason,
        recovery: RecoveryState,
    ) -> FailStoppedMutationCasSession {
        FailStoppedMutationCasSession {
            backend: self.backend,
            lineage: self.lineage,
            current: self.current,
            reason,
            recovery,
        }
    }

    #[cfg(test)]
    fn current(&self) -> &cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
        &self.current
    }
}

impl PlannedMutationCasSession {
    pub(crate) fn journal_stage_records(
        &self,
        _seal: &crate::operation_journal::MutationCasJournalSeal,
    ) -> (
        cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
        cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    ) {
        (
            self.session.lineage.clone(),
            self.session.current.clone(),
            self.intent.clone(),
        )
    }

    /// Bind fd-derived durable staged-candidate and transaction-sidecar facts
    /// to every authority-relevant field before a PREPARE nonce can be issued.
    pub(crate) fn bind_durable_stage(
        self,
        proof: SealedDurableStagedMutationProof,
    ) -> DurableStageTransition {
        let binding = proof.into_binding();
        let exact = binding.staged_candidate_journal_version
            == self.intent.proposed_journal_version
            && valid_nonzero_sha256(&binding.transaction_sidecar_identity_sha256)
            && valid_nonzero_sha256(&binding.transaction_sidecar_bytes_sha256)
            && binding.sidecar_first_use_lineage_sha256
                == self.session.lineage.first_use_lineage_sha256
            && binding.sidecar_from_committed_head_sha256
                == self.session.current.committed_head_sha256
            && binding.sidecar_mutation_transaction_sha256 == self.intent.mutation_intent_sha256
            && binding.sidecar_mutation_kind == self.intent.mutation_kind
            && binding.sidecar_current_journal_version
                == self.intent.observed_current_journal_version
            && binding.sidecar_proposed_journal_version == self.intent.proposed_journal_version
            && binding.sidecar_writer_lock_identity_sha256 == self.writer_lock_identity_sha256;
        if !exact {
            return DurableStageTransition::FailStopped(self.session.fail_stopped(
                MutationCasFailStopReason::InvalidLocalInput,
                no_recovery(Some(self.writer_lock_identity_sha256)),
            ));
        }
        DurableStageTransition::Staged(StagedMutationCasSession {
            session: self.session,
            intent: self.intent,
            writer_lock_identity_sha256: self.writer_lock_identity_sha256,
        })
    }

    #[cfg(test)]
    fn transaction_sha256(&self) -> &str {
        &self.intent.mutation_intent_sha256
    }
}

impl StagedMutationCasSession {
    /// The only initial PREPARE entry point. Construction of this typestate
    /// proves the exact candidate and sidecar were durable first.
    pub(crate) fn send_prepare(self) -> PrepareTransition {
        let Self {
            session,
            intent,
            writer_lock_identity_sha256,
        } = self;
        let request = match build_prepare_request(
            &session.backend,
            &session.lineage,
            &session.current,
            &intent,
        ) {
            Ok(request) => request,
            Err(()) => {
                return PrepareTransition::FailStopped(session.fail_stopped(
                    MutationCasFailStopReason::InvalidLocalInput,
                    no_recovery(Some(writer_lock_identity_sha256)),
                ));
            }
        };
        match session.backend.prepare(&request) {
            Ok(receipt) if receipt.validate_for(&session.lineage, &request).is_ok() => {
                PrepareTransition::Prepared(PreparedMutationCasSession {
                    session,
                    prepare_request: request,
                    prepare_receipt: receipt,
                    writer_lock_identity_sha256,
                })
            }
            Ok(_) => PrepareTransition::FailStopped(session.fail_stopped(
                MutationCasFailStopReason::InvalidPrepareReceipt,
                uncertain_recovery(
                    cas::DirectOperationRuntimeAuthorityReconcileCauseV1::PrepareResponseUnknown,
                    intent,
                    cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Unknown,
                    writer_lock_identity_sha256,
                ),
            )),
            Err(BackendCallFailure::NotApplied) => {
                PrepareTransition::Retryable(RetryablePrepareMutationCasSession {
                    session,
                    intent,
                    previous_request_nonce_sha256: request.request_nonce_sha256,
                    writer_lock_identity_sha256,
                })
            }
            Err(BackendCallFailure::Denied) => {
                PrepareTransition::FailStopped(session.fail_stopped(
                    MutationCasFailStopReason::PrepareDenied,
                    no_recovery(Some(writer_lock_identity_sha256)),
                ))
            }
            Err(BackendCallFailure::OutcomeUnknown) => {
                PrepareTransition::FailStopped(session.fail_stopped(
                    MutationCasFailStopReason::PrepareOutcomeUnknown,
                    uncertain_recovery(
                        cas::DirectOperationRuntimeAuthorityReconcileCauseV1::PrepareResponseUnknown,
                        intent,
                        cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Unknown,
                        writer_lock_identity_sha256,
                    ),
                ))
            }
        }
    }
}

impl RetryablePrepareMutationCasSession {
    pub(crate) fn retry(self) -> PrepareTransition {
        let Self {
            session,
            intent,
            previous_request_nonce_sha256: _,
            writer_lock_identity_sha256,
        } = self;
        let observed = intent.observed_current_journal_version.clone();
        match session
            .validate_current_with_writer_lock(observed, Some(writer_lock_identity_sha256.clone()))
        {
            ObserveTransition::Current(current) => StagedMutationCasSession {
                session: current,
                intent,
                writer_lock_identity_sha256,
            }
            .send_prepare(),
            ObserveTransition::FailStopped(failed) => PrepareTransition::FailStopped(failed),
        }
    }

    /// A `NotApplied` PREPARE result is an explicit non-admission proof. The
    /// journal may remove its still-local durable stage, but this affine
    /// session remains fail-stopped so callers must reopen instead of silently
    /// reusing a transaction whose request nonce has already been exposed.
    pub(crate) fn abandon_not_applied(self) -> FailStoppedMutationCasSession {
        let Self {
            session,
            intent: _,
            previous_request_nonce_sha256: _,
            writer_lock_identity_sha256,
        } = self;
        session.fail_stopped(
            MutationCasFailStopReason::PrepareNotApplied,
            no_recovery(Some(writer_lock_identity_sha256)),
        )
    }

    #[cfg(test)]
    fn transaction_sha256(&self) -> &str {
        &self.intent.mutation_intent_sha256
    }

    #[cfg(test)]
    fn previous_request_nonce_sha256(&self) -> &str {
        &self.previous_request_nonce_sha256
    }
}

impl PreparedMutationCasSession {
    pub(crate) fn bind_journal_publication(
        self,
        _seal: &crate::operation_journal::MutationCasJournalSeal,
        named_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    ) -> LocalPublicationTransition {
        let mut publication = cas::DirectOperationRuntimeAuthorityLocalPublicationV1 {
            schema: cas::LOCAL_PUBLICATION_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            first_use_lineage_sha256: self.session.lineage.first_use_lineage_sha256.clone(),
            prepared_head_sha256: self
                .prepare_receipt
                .prepared_head
                .prepared_head_sha256
                .clone(),
            mutation_generation: self.prepare_receipt.prepared_head.to_mutation_generation,
            state_directory_identity_sha256: self
                .session
                .lineage
                .anchor
                .state_directory_identity_sha256
                .clone(),
            writer_lock_identity_sha256: self.writer_lock_identity_sha256.clone(),
            named_journal_version,
            local_publication_sha256: String::new(),
        };
        let Ok(digest) = publication.canonical_sha256() else {
            return LocalPublicationTransition::FailStopped(self.fail_stopped(
                MutationCasFailStopReason::LocalPublicationUncertain,
                cas::DirectOperationRuntimeAuthorityReconcileCauseV1::LocalPublicationUnknown,
            ));
        };
        publication.local_publication_sha256 = digest;
        self.bind_local_publication(publication)
    }

    pub(crate) fn bind_local_publication(
        self,
        local_publication: cas::DirectOperationRuntimeAuthorityLocalPublicationV1,
    ) -> LocalPublicationTransition {
        if local_publication
            .validate_for(&self.session.lineage, &self.prepare_receipt.prepared_head)
            .is_err()
            || self.writer_lock_identity_sha256.as_str()
                != local_publication.writer_lock_identity_sha256.as_str()
        {
            return LocalPublicationTransition::FailStopped(self.fail_stopped(
                MutationCasFailStopReason::LocalPublicationUncertain,
                cas::DirectOperationRuntimeAuthorityReconcileCauseV1::LocalPublicationUnknown,
            ));
        }
        LocalPublicationTransition::Published(LocallyPublishedMutationCasSession {
            prepared: self,
            local_publication,
        })
    }

    /// The authority PREPARE is known to be durable, the exact staged
    /// candidate is still present, and the named journal is known not to have
    /// been replaced. Reconciliation must classify this separately from an
    /// uncertain post-rename publication.
    pub(crate) fn staged_publication_interrupted(self) -> FailStoppedMutationCasSession {
        self.fail_stopped(
            MutationCasFailStopReason::LocalPublicationUncertain,
            cas::DirectOperationRuntimeAuthorityReconcileCauseV1::RestartWithPrepared,
        )
    }

    pub(crate) fn local_publication_uncertain(self) -> FailStoppedMutationCasSession {
        self.fail_stopped(
            MutationCasFailStopReason::LocalPublicationUncertain,
            cas::DirectOperationRuntimeAuthorityReconcileCauseV1::LocalPublicationUnknown,
        )
    }

    fn fail_stopped(
        self,
        reason: MutationCasFailStopReason,
        cause: cas::DirectOperationRuntimeAuthorityReconcileCauseV1,
    ) -> FailStoppedMutationCasSession {
        let recovery = uncertain_recovery(
            cause,
            self.prepare_request.mutation_intent.clone(),
            cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                prepared_head: self.prepare_receipt.prepared_head.clone(),
            },
            self.writer_lock_identity_sha256.clone(),
        );
        self.session.fail_stopped(reason, recovery)
    }

    #[cfg(test)]
    fn transaction_sha256(&self) -> &str {
        &self.prepare_request.mutation_transaction_sha256
    }

    #[cfg(test)]
    fn prepared_head(&self) -> &cas::DirectOperationRuntimeAuthorityPreparedHeadV1 {
        &self.prepare_receipt.prepared_head
    }
}

impl LocallyPublishedMutationCasSession {
    pub(crate) fn commit(self) -> CommitTransition {
        let request = match build_commit_request(
            &self.prepared.session.backend,
            &self.prepared.session.lineage,
            &self.prepared.prepare_request,
            &self.prepared.prepare_receipt,
            self.local_publication.clone(),
        ) {
            Ok(request) => request,
            Err(()) => {
                return CommitTransition::FailStopped(self.fail_stopped(
                    MutationCasFailStopReason::InvalidLocalInput,
                    cas::DirectOperationRuntimeAuthorityReconcileCauseV1::LocalPublicationUnknown,
                ));
            }
        };
        match self.prepared.session.backend.commit(&request) {
            Ok(receipt)
                if receipt
                    .validate_for(
                        &self.prepared.session.lineage,
                        &self.prepared.session.current,
                        &self.prepared.prepare_request,
                        &self.prepared.prepare_receipt,
                        &request,
                    )
                    .is_ok() =>
            {
                let committed_head = receipt.committed_head;
                let expected_named_journal_version = committed_head.journal_version.clone();
                let intent = self.prepared.prepare_request.mutation_intent.clone();
                let prepared_head = self.prepared.prepare_receipt.prepared_head.clone();
                let writer_lock_identity_sha256 =
                    self.local_publication.writer_lock_identity_sha256.clone();
                CommitTransition::Committed(ReconciledCommittedMutationCasSession {
                    session: SealedCommittedMutationCasSession {
                        backend: self.prepared.session.backend,
                        lineage: self.prepared.session.lineage,
                        current: committed_head,
                    },
                    intent,
                    prepared_knowledge:
                        cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                            prepared_head,
                        },
                    writer_lock_identity_sha256,
                    expected_named_journal_version,
                })
            }
            Ok(_) => CommitTransition::FailStopped(self.fail_stopped(
                MutationCasFailStopReason::InvalidCommitReceipt,
                cas::DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown,
            )),
            Err(BackendCallFailure::NotApplied) => {
                CommitTransition::FailStopped(self.fail_stopped(
                    MutationCasFailStopReason::CommitNotApplied,
                    cas::DirectOperationRuntimeAuthorityReconcileCauseV1::LocalPublicationUnknown,
                ))
            }
            Err(BackendCallFailure::Denied) => CommitTransition::FailStopped(
                self.fail_stopped_without_recovery(MutationCasFailStopReason::CommitDenied),
            ),
            Err(BackendCallFailure::OutcomeUnknown) => {
                CommitTransition::FailStopped(self.fail_stopped(
                    MutationCasFailStopReason::CommitOutcomeUnknown,
                    cas::DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown,
                ))
            }
        }
    }

    fn fail_stopped(
        self,
        reason: MutationCasFailStopReason,
        cause: cas::DirectOperationRuntimeAuthorityReconcileCauseV1,
    ) -> FailStoppedMutationCasSession {
        let recovery = uncertain_recovery(
            cause,
            self.prepared.prepare_request.mutation_intent.clone(),
            cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                prepared_head: self.prepared.prepare_receipt.prepared_head.clone(),
            },
            self.local_publication.writer_lock_identity_sha256.clone(),
        );
        self.prepared.session.fail_stopped(reason, recovery)
    }

    fn fail_stopped_without_recovery(
        self,
        reason: MutationCasFailStopReason,
    ) -> FailStoppedMutationCasSession {
        let writer_lock_identity_sha256 =
            self.local_publication.writer_lock_identity_sha256.clone();
        self.prepared
            .session
            .fail_stopped(reason, no_recovery(Some(writer_lock_identity_sha256)))
    }
}

impl ReconciledPreparedMutationCasSession {
    /// Reacquire a receipt for the exact pending mutation. A new request nonce
    /// is mandatory, while the durable mutation transaction and prepared head
    /// must remain byte-for-byte identical.
    pub(crate) fn reprepare(self) -> ReprepareTransition {
        let request = match build_prepare_request(
            &self.session.backend,
            &self.session.lineage,
            &self.session.current,
            &self.intent,
        ) {
            Ok(request) => request,
            Err(()) => {
                return ReprepareTransition::Hold(ReopenRequired {
                    reason: MutationCasFailStopReason::InvalidLocalInput,
                });
            }
        };
        let response = self.session.backend.prepare(&request);
        match response {
            Ok(receipt)
                if receipt
                    .validate_for(&self.session.lineage, &request)
                    .is_ok()
                    && receipt.prepared_head == self.prepared_head =>
            {
                let Self {
                    session,
                    intent: _,
                    prepared_head: _,
                    writer_lock_identity_sha256,
                    recovery_cause: _,
                } = self;
                ReprepareTransition::Prepared(PreparedMutationCasSession {
                    session,
                    prepare_request: request,
                    prepare_receipt: receipt,
                    writer_lock_identity_sha256,
                })
            }
            Ok(_) => {
                self.fail_stopped_after_reprepare(MutationCasFailStopReason::InvalidPrepareReceipt)
            }
            Err(BackendCallFailure::NotApplied) => {
                self.fail_stopped_after_reprepare(MutationCasFailStopReason::PrepareNotApplied)
            }
            Err(BackendCallFailure::Denied) => ReprepareTransition::Hold(ReopenRequired {
                reason: MutationCasFailStopReason::PrepareDenied,
            }),
            Err(BackendCallFailure::OutcomeUnknown) => {
                self.fail_stopped_after_reprepare(MutationCasFailStopReason::PrepareOutcomeUnknown)
            }
        }
    }

    // The non-test backend is intentionally uninhabited, so rustc sees the
    // enum wrapping below as unreachable outside tests. Keeping the wrapper is
    // required for the source-only typestate and its in-memory authority.
    #[allow(unreachable_code)]
    fn fail_stopped_after_reprepare(
        self,
        reason: MutationCasFailStopReason,
    ) -> ReprepareTransition {
        let recovery = uncertain_recovery(
            self.recovery_cause,
            self.intent,
            cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                prepared_head: self.prepared_head,
            },
            self.writer_lock_identity_sha256,
        );
        ReprepareTransition::FailStopped(self.session.fail_stopped(reason, recovery))
    }

    #[cfg(test)]
    fn transaction_sha256(&self) -> &str {
        &self.intent.mutation_intent_sha256
    }

    #[cfg(test)]
    fn prepared_head(&self) -> &cas::DirectOperationRuntimeAuthorityPreparedHeadV1 {
        &self.prepared_head
    }
}

impl ReconciledCommittedMutationCasSession {
    /// Complete the local half of a terminal reconciliation, then perform a
    /// fresh external OBSERVE before exposing a usable committed session.
    pub(crate) fn reopen_after_local_cleanup(
        self,
        observations: SealedLocalReconcileObservations,
    ) -> ObserveTransition {
        let Self {
            session,
            intent: _,
            prepared_knowledge: _,
            writer_lock_identity_sha256,
            expected_named_journal_version,
        } = self;
        let SealedLocalReconcileObservations {
            writer_lock_identity_sha256: observed_writer_lock,
            named_journal,
            staged_candidate,
            _source: _,
        } = observations;
        let named_is_exact = matches!(
            named_journal,
            LocalEntryObservation::Present(version)
                if version == expected_named_journal_version
        );
        if observed_writer_lock != writer_lock_identity_sha256
            || !named_is_exact
            || !matches!(staged_candidate, LocalEntryObservation::Missing)
        {
            return ObserveTransition::FailStopped(session.fail_stopped(
                MutationCasFailStopReason::InvalidLocalInput,
                no_recovery(Some(writer_lock_identity_sha256)),
            ));
        }
        session.validate_current_with_writer_lock(
            expected_named_journal_version,
            Some(writer_lock_identity_sha256),
        )
    }

    #[cfg(test)]
    fn transaction_sha256(&self) -> &str {
        &self.intent.mutation_intent_sha256
    }

    #[cfg(test)]
    fn prepared_knowledge(&self) -> &cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1 {
        &self.prepared_knowledge
    }
}

fn uncertain_recovery(
    cause: cas::DirectOperationRuntimeAuthorityReconcileCauseV1,
    intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    prepared_knowledge: cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1,
    writer_lock_identity_sha256: String,
) -> RecoveryState {
    RecoveryState::Uncertain {
        cause,
        intent: Box::new(intent),
        prepared_knowledge: Box::new(prepared_knowledge),
        writer_lock_identity_sha256: Some(writer_lock_identity_sha256),
    }
}

fn no_recovery(writer_lock_identity_sha256: Option<String>) -> RecoveryState {
    RecoveryState::None {
        writer_lock_identity_sha256,
    }
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && !value.bytes().all(|byte| byte == b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

enum LocalEntryObservation {
    Present(cas::DirectOperationRuntimeAuthorityJournalVersionV1),
    Missing,
}

enum SealedLocalObservationSource {
    Journal,
    #[cfg(test)]
    Test,
}

/// These are sealed local facts, not authority. Only the independent backend
/// response can classify a reconciliation outcome.
pub(crate) struct SealedLocalReconcileObservations {
    writer_lock_identity_sha256: String,
    named_journal: LocalEntryObservation,
    staged_candidate: LocalEntryObservation,
    _source: SealedLocalObservationSource,
}

impl SealedLocalReconcileObservations {
    pub(crate) fn after_journal_cleanup(
        _seal: &crate::operation_journal::MutationCasJournalSeal,
        writer_lock_identity_sha256: String,
        named_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    ) -> Self {
        Self {
            writer_lock_identity_sha256,
            named_journal: LocalEntryObservation::Present(named_journal_version),
            staged_candidate: LocalEntryObservation::Missing,
            _source: SealedLocalObservationSource::Journal,
        }
    }
}

impl FailStoppedMutationCasSession {
    pub(crate) fn durable_stage_must_be_retained(&self) -> bool {
        matches!(self.recovery, RecoveryState::Uncertain { .. })
    }

    pub(crate) fn reconcile(
        self,
        observations: SealedLocalReconcileObservations,
    ) -> ReconcileTransition {
        let RecoveryState::Uncertain {
            cause,
            intent,
            prepared_knowledge,
            writer_lock_identity_sha256: sealed_writer_lock_identity_sha256,
        } = self.recovery
        else {
            return ReconcileTransition::Hold(ReopenRequired {
                reason: self.reason,
            });
        };
        let intent = *intent;
        let prepared_knowledge = *prepared_knowledge;
        let Some(writer_lock_identity_sha256) = sealed_writer_lock_identity_sha256 else {
            return ReconcileTransition::Hold(ReopenRequired {
                reason: self.reason,
            });
        };
        if writer_lock_identity_sha256.as_str() != observations.writer_lock_identity_sha256.as_str()
        {
            return ReconcileTransition::Hold(ReopenRequired {
                reason: self.reason,
            });
        };
        let request = match build_reconcile_request(
            &self.backend,
            &self.lineage,
            &self.current,
            intent.clone(),
            prepared_knowledge.clone(),
            cause,
            observations,
        ) {
            Ok(request) => request,
            Err(()) => {
                return ReconcileTransition::Hold(ReopenRequired {
                    reason: self.reason,
                });
            }
        };
        let response = match self.backend.reconcile(&request) {
            Ok(response) => response,
            Err(_) => {
                return ReconcileTransition::Hold(ReopenRequired {
                    reason: self.reason,
                });
            }
        };
        let disposition = match response.disposition_for(&self.lineage, &request) {
            Ok(disposition) => disposition,
            Err(_) => {
                return ReconcileTransition::Hold(ReopenRequired {
                    reason: self.reason,
                });
            }
        };
        let session = SealedCommittedMutationCasSession {
            backend: self.backend,
            lineage: self.lineage,
            current: self.current,
        };
        match disposition {
            cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::NoMutation => {
                let expected_named_journal_version = session.current.journal_version.clone();
                ReconcileTransition::NoMutation(ReconciledCommittedMutationCasSession {
                    session,
                    intent,
                    prepared_knowledge,
                    writer_lock_identity_sha256,
                    expected_named_journal_version,
                })
            }
            cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::ResumeExactPreparedPublication
            | cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::RetryExactCommit => {
                let cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                    prepared_head,
                } = response.snapshot.prepared_slot
                else {
                    return ReconcileTransition::Hold(ReopenRequired {
                        reason: self.reason,
                    });
                };
                if prepared_head
                    .validate_for_intent(&session.lineage, &session.current, &intent)
                    .is_err()
                    || matches!(
                        &prepared_knowledge,
                        cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                            prepared_head: known,
                        } if known != &prepared_head
                    )
                {
                    return ReconcileTransition::Hold(ReopenRequired {
                        reason: self.reason,
                    });
                }
                let continuation = ReconciledPreparedMutationCasSession {
                    session,
                    intent,
                    prepared_head,
                    writer_lock_identity_sha256,
                    recovery_cause: match disposition {
                        cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::ResumeExactPreparedPublication => {
                            cas::DirectOperationRuntimeAuthorityReconcileCauseV1::RestartWithPrepared
                        }
                        cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::RetryExactCommit => {
                            cas::DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown
                        }
                        _ => unreachable!("matched pending reconciliation disposition"),
                    },
                };
                match disposition {
                    cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::ResumeExactPreparedPublication => {
                        ReconcileTransition::ResumeExactPreparedPublication(continuation)
                    }
                    cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::RetryExactCommit => {
                        ReconcileTransition::RetryExactCommit(continuation)
                    }
                    _ => unreachable!("matched pending reconciliation disposition"),
                }
            }
            cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::Committed => {
                let successor = response.snapshot.committed_head;
                let cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                    prepared_head,
                } = prepared_knowledge
                else {
                    return ReconcileTransition::Hold(ReopenRequired {
                        reason: self.reason,
                    });
                };
                if successor
                    .validate_successor(&session.lineage, &session.current, &prepared_head)
                    .is_err()
                {
                    return ReconcileTransition::Hold(ReopenRequired {
                        reason: self.reason,
                    });
                }
                let expected_named_journal_version = successor.journal_version.clone();
                ReconcileTransition::Committed(ReconciledCommittedMutationCasSession {
                    session: SealedCommittedMutationCasSession {
                        backend: session.backend,
                        lineage: session.lineage,
                        current: successor,
                    },
                    intent,
                    prepared_knowledge:
                        cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                            prepared_head,
                        },
                    writer_lock_identity_sha256,
                    expected_named_journal_version,
                })
            }
        }
    }

    #[cfg(test)]
    fn reason(&self) -> MutationCasFailStopReason {
        self.reason
    }
}

fn build_mutation_intent(
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    mutation_kind: cas::DirectOperationRuntimeAuthorityMutationKindV1,
    observed_current_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    proposed_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    mutation_nonce_sha256: String,
) -> Result<cas::DirectOperationRuntimeAuthorityMutationIntentV1, ()> {
    let to_mutation_generation = current.mutation_generation.checked_add(1).ok_or(())?;
    let mut intent = cas::DirectOperationRuntimeAuthorityMutationIntentV1 {
        schema: cas::MUTATION_INTENT_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        authority_store_instance_sha256: lineage.anchor.authority_store_instance_sha256.clone(),
        first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
        from_committed_head_sha256: current.committed_head_sha256.clone(),
        from_mutation_generation: current.mutation_generation,
        mutation_kind,
        expected_journal_version: current.journal_version.clone(),
        observed_current_journal_version,
        to_mutation_generation,
        proposed_journal_version,
        mutation_nonce_sha256,
        mutation_intent_sha256: String::new(),
    };
    intent.mutation_intent_sha256 = intent.canonical_sha256().map_err(|_| ())?;
    intent.validate_for(lineage, current).map_err(|_| ())?;
    Ok(intent)
}

fn build_prepare_request(
    backend: &SealedMutationCasBackend,
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    intent: &cas::DirectOperationRuntimeAuthorityMutationIntentV1,
) -> Result<cas::DirectOperationRuntimeAuthorityPrepareRequestV1, ()> {
    let mut request = cas::DirectOperationRuntimeAuthorityPrepareRequestV1 {
        schema: cas::PREPARE_REQUEST_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        operation: cas::PREPARE_OPERATION.to_string(),
        mutation_transaction_sha256: intent.mutation_intent_sha256.clone(),
        request_nonce_sha256: backend
            .next_mutation_nonce("prepare", &intent.mutation_intent_sha256)
            .map_err(|_| ())?,
        current_committed_head: current.clone(),
        mutation_intent: intent.clone(),
        request_sha256: String::new(),
    };
    request.request_sha256 = request.canonical_sha256().map_err(|_| ())?;
    request.validate(lineage).map_err(|_| ())?;
    Ok(request)
}

fn build_commit_request(
    backend: &SealedMutationCasBackend,
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    prepare: &cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
    receipt: &cas::DirectOperationRuntimeAuthorityPrepareReceiptV1,
    local_publication: cas::DirectOperationRuntimeAuthorityLocalPublicationV1,
) -> Result<cas::DirectOperationRuntimeAuthorityCommitRequestV1, ()> {
    let mut request = cas::DirectOperationRuntimeAuthorityCommitRequestV1 {
        schema: cas::COMMIT_REQUEST_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        operation: cas::COMMIT_OPERATION.to_string(),
        mutation_transaction_sha256: prepare.mutation_transaction_sha256.clone(),
        request_nonce_sha256: backend
            .next_mutation_nonce("commit", &prepare.mutation_transaction_sha256)
            .map_err(|_| ())?,
        prepare_request_sha256: prepare.request_sha256.clone(),
        prepare_receipt_sha256: receipt.receipt_sha256.clone(),
        prepared_head_sha256: receipt.prepared_head.prepared_head_sha256.clone(),
        local_publication,
        request_sha256: String::new(),
    };
    request.request_sha256 = request.canonical_sha256().map_err(|_| ())?;
    request
        .validate_for(lineage, prepare, receipt)
        .map_err(|_| ())?;
    Ok(request)
}

fn build_observe_request(
    backend: &SealedMutationCasBackend,
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    observed_journal_version: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
) -> Result<cas::DirectOperationRuntimeAuthorityObserveRequestV1, ()> {
    let session_sha256 = backend
        .next_observe_nonce("observe-session", &current.committed_head_sha256)
        .map_err(|_| ())?;
    let mut request = cas::DirectOperationRuntimeAuthorityObserveRequestV1 {
        schema: cas::OBSERVE_REQUEST_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        operation: cas::OBSERVE_OPERATION.to_string(),
        observation_session_sha256: session_sha256,
        request_nonce_sha256: backend
            .next_observe_nonce("observe", &current.committed_head_sha256)
            .map_err(|_| ())?,
        expected_committed_head_sha256: current.committed_head_sha256.clone(),
        observed_journal_version,
        request_sha256: String::new(),
    };
    request.request_sha256 = request.canonical_sha256().map_err(|_| ())?;
    request.validate_for(lineage, current).map_err(|_| ())?;
    Ok(request)
}

#[allow(clippy::too_many_arguments)]
fn build_reconcile_request(
    backend: &SealedMutationCasBackend,
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    prepared_knowledge: cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1,
    cause: cas::DirectOperationRuntimeAuthorityReconcileCauseV1,
    observations: SealedLocalReconcileObservations,
) -> Result<cas::DirectOperationRuntimeAuthorityReconcileRequestV1, ()> {
    let request_nonce_sha256 = backend
        .next_mutation_nonce("reconcile", &intent.mutation_intent_sha256)
        .map_err(|_| ())?;
    let named_journal = build_local_observation(
        cas::DirectOperationRuntimeAuthorityLocalEntryRoleV1::NamedJournal,
        observations.named_journal,
        &observations.writer_lock_identity_sha256,
        lineage,
        current,
        &intent,
        cause,
        &request_nonce_sha256,
    )?;
    let staged_candidate = build_local_observation(
        cas::DirectOperationRuntimeAuthorityLocalEntryRoleV1::StagedCandidate,
        observations.staged_candidate,
        &observations.writer_lock_identity_sha256,
        lineage,
        current,
        &intent,
        cause,
        &request_nonce_sha256,
    )?;
    let mut request = cas::DirectOperationRuntimeAuthorityReconcileRequestV1 {
        schema: cas::RECONCILE_REQUEST_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        operation: cas::RECONCILE_OPERATION.to_string(),
        mutation_transaction_sha256: intent.mutation_intent_sha256.clone(),
        request_nonce_sha256,
        cause,
        expected_committed_head: current.clone(),
        mutation_intent: intent,
        prepared_knowledge,
        observed_named_journal: named_journal,
        observed_staged_candidate: staged_candidate,
        request_sha256: String::new(),
    };
    request.request_sha256 = request.canonical_sha256().map_err(|_| ())?;
    request.validate(lineage).map_err(|_| ())?;
    Ok(request)
}

#[allow(clippy::too_many_arguments)]
fn build_local_observation(
    role: cas::DirectOperationRuntimeAuthorityLocalEntryRoleV1,
    entry: LocalEntryObservation,
    writer_lock_identity_sha256: &str,
    lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    intent: &cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    cause: cas::DirectOperationRuntimeAuthorityReconcileCauseV1,
    request_nonce_sha256: &str,
) -> Result<cas::DirectOperationRuntimeAuthorityLocalObservationV1, ()> {
    let entry_domain = match role {
        cas::DirectOperationRuntimeAuthorityLocalEntryRoleV1::NamedJournal => {
            cas::NAMED_JOURNAL_ENTRY_DOMAIN
        }
        cas::DirectOperationRuntimeAuthorityLocalEntryRoleV1::StagedCandidate => {
            cas::STAGED_CANDIDATE_ENTRY_DOMAIN
        }
    };
    let mut context = cas::DirectOperationRuntimeAuthorityLocalObservationContextV1 {
        schema: cas::LOCAL_OBSERVATION_CONTEXT_V1_SCHEMA.to_string(),
        protocol: cas::PROTOCOL.to_string(),
        role,
        entry_domain: entry_domain.to_string(),
        entry_binding_sha256: String::new(),
        state_directory_identity_sha256: lineage.anchor.state_directory_identity_sha256.clone(),
        writer_lock_identity_sha256: writer_lock_identity_sha256.to_string(),
        first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
        mutation_transaction_sha256: intent.mutation_intent_sha256.clone(),
        request_nonce_sha256: request_nonce_sha256.to_string(),
        mutation_intent_sha256: intent.mutation_intent_sha256.clone(),
        expected_committed_head_sha256: current.committed_head_sha256.clone(),
        expected_journal_version_sha256: current.journal_version.journal_version_sha256.clone(),
        proposed_journal_version_sha256: intent
            .proposed_journal_version
            .journal_version_sha256
            .clone(),
        reconcile_cause: cause,
        context_sha256: String::new(),
    };
    context.entry_binding_sha256 = context.canonical_entry_binding_sha256().map_err(|_| ())?;
    context.context_sha256 = context.canonical_sha256().map_err(|_| ())?;
    let mut observation = match entry {
        LocalEntryObservation::Present(journal_version) => {
            cas::DirectOperationRuntimeAuthorityLocalObservationV1::Present {
                context,
                journal_version,
                observation_sha256: String::new(),
            }
        }
        LocalEntryObservation::Missing => {
            cas::DirectOperationRuntimeAuthorityLocalObservationV1::Missing {
                context,
                name_absent: true,
                observation_sha256: String::new(),
            }
        }
    };
    let digest = observation.canonical_sha256().map_err(|_| ())?;
    match &mut observation {
        cas::DirectOperationRuntimeAuthorityLocalObservationV1::Present {
            observation_sha256,
            ..
        }
        | cas::DirectOperationRuntimeAuthorityLocalObservationV1::Missing {
            observation_sha256,
            ..
        } => *observation_sha256 = digest,
    }
    Ok(observation)
}

#[cfg(test)]
mod test_authority {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use trillionnium_os_types::sha256_bytes;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum TestFault {
        ObserveDenied,
        ObserveOutcomeUnknown,
        PrepareDenied,
        PrepareNotApplied,
        PrepareUnknownBeforeApply,
        PrepareUnknownAfterApply,
        PrepareForkedReceipt,
        CommitNotApplied,
        CommitDenied,
        CommitUnknownBeforeApply,
        CommitUnknownAfterApply,
        CommitForkedReceipt,
        ReconcileDenied,
        ReconcileForkedPreparedHead,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(super) enum TestPhase {
        Nonce(&'static str, String),
        Observe(String),
        Prepare(String, String),
        PrepareApplied(String),
        Commit(String, String),
        CommitApplied(String),
        Reconcile(cas::DirectOperationRuntimeAuthorityReconcileCauseV1),
    }

    #[derive(Clone)]
    struct PrepareExchange {
        request: cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
        receipt: cas::DirectOperationRuntimeAuthorityPrepareReceiptV1,
    }

    #[derive(Clone)]
    struct PendingMutation {
        intent: cas::DirectOperationRuntimeAuthorityMutationIntentV1,
        prepared_head: cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
        exchanges: Vec<PrepareExchange>,
    }

    struct TestAuthorityState {
        lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
        pending: Option<PendingMutation>,
        reconcile_required_transaction: Option<String>,
        faults: VecDeque<TestFault>,
        nonce_counter: u64,
        transcript: Vec<TestPhase>,
    }

    #[derive(Clone)]
    pub(super) struct TestMutationCasAuthority {
        state: Arc<Mutex<TestAuthorityState>>,
    }

    impl TestMutationCasAuthority {
        pub(super) fn new(
            lineage: cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
            current: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
        ) -> Self {
            lineage.validate().unwrap();
            current.validate(&lineage).unwrap();
            Self {
                state: Arc::new(Mutex::new(TestAuthorityState {
                    lineage,
                    current,
                    pending: None,
                    reconcile_required_transaction: None,
                    faults: VecDeque::new(),
                    nonce_counter: 0,
                    transcript: Vec::new(),
                })),
            }
        }

        pub(super) fn open(&self) -> Result<SealedCommittedMutationCasSession, &'static str> {
            let state = self.state.lock().unwrap();
            if state.pending.is_some() || state.reconcile_required_transaction.is_some() {
                return Err("test_authority_reconcile_required");
            }
            state.lineage.validate().map_err(|_| "invalid_lineage")?;
            state
                .current
                .validate(&state.lineage)
                .map_err(|_| "invalid_head")?;
            Ok(SealedCommittedMutationCasSession {
                backend: SealedMutationCasBackend::Test(self.clone()),
                lineage: state.lineage.clone(),
                current: state.current.clone(),
            })
        }

        pub(super) fn queue_fault(&self, fault: TestFault) {
            self.state.lock().unwrap().faults.push_back(fault);
        }

        pub(super) fn transcript(&self) -> Vec<TestPhase> {
            self.state.lock().unwrap().transcript.clone()
        }

        pub(super) fn has_pending(&self) -> bool {
            self.state.lock().unwrap().pending.is_some()
        }

        fn take_fault(state: &mut TestAuthorityState, expected: TestFault) -> bool {
            if state.faults.front() == Some(&expected) {
                state.faults.pop_front();
                true
            } else {
                false
            }
        }

        pub(super) fn next_nonce(&self, phase: &'static str, binding_sha256: &str) -> String {
            let mut state = self.state.lock().unwrap();
            state.nonce_counter += 1;
            let nonce = sha256_bytes(
                format!("{phase}:{}:{binding_sha256}", state.nonce_counter).as_bytes(),
            );
            state
                .transcript
                .push(TestPhase::Nonce(phase, nonce.clone()));
            nonce
        }

        pub(super) fn prepare(
            &self,
            request: &cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
        ) -> BackendCall<cas::DirectOperationRuntimeAuthorityPrepareReceiptV1> {
            let mut state = self.state.lock().unwrap();
            if request.validate(&state.lineage).is_err()
                || request.current_committed_head != state.current
            {
                return Err(BackendCallFailure::Denied);
            }
            state.transcript.push(TestPhase::Prepare(
                request.mutation_transaction_sha256.clone(),
                request.request_nonce_sha256.clone(),
            ));
            if Self::take_fault(&mut state, TestFault::PrepareDenied) {
                return Err(BackendCallFailure::Denied);
            }
            if Self::take_fault(&mut state, TestFault::PrepareNotApplied) {
                return Err(BackendCallFailure::NotApplied);
            }
            if Self::take_fault(&mut state, TestFault::PrepareUnknownBeforeApply) {
                state.reconcile_required_transaction =
                    Some(request.mutation_transaction_sha256.clone());
                return Err(BackendCallFailure::OutcomeUnknown);
            }

            let prepared_head = if let Some(pending) = &state.pending {
                if pending.intent != request.mutation_intent {
                    return Err(BackendCallFailure::Denied);
                }
                pending.prepared_head.clone()
            } else {
                make_prepared_head(&state.lineage, &state.current, &request.mutation_intent)
            };
            let receipt = make_prepare_receipt(&state.lineage, request, prepared_head.clone());
            if let Some(pending) = &mut state.pending {
                pending.exchanges.push(PrepareExchange {
                    request: request.clone(),
                    receipt: receipt.clone(),
                });
            } else {
                state.pending = Some(PendingMutation {
                    intent: request.mutation_intent.clone(),
                    prepared_head: prepared_head.clone(),
                    exchanges: vec![PrepareExchange {
                        request: request.clone(),
                        receipt: receipt.clone(),
                    }],
                });
                state.transcript.push(TestPhase::PrepareApplied(
                    prepared_head.prepared_head_sha256.clone(),
                ));
            }
            if Self::take_fault(&mut state, TestFault::PrepareUnknownAfterApply) {
                state.reconcile_required_transaction =
                    Some(request.mutation_transaction_sha256.clone());
                return Err(BackendCallFailure::OutcomeUnknown);
            }
            if Self::take_fault(&mut state, TestFault::PrepareForkedReceipt) {
                let mut forked = receipt;
                forked.prepared_head.proposed_journal_version = super::tests::journal_version(
                    "forked-prepare-journal-identity",
                    "forked-prepare-journal-bytes",
                );
                forked.prepared_head.prepared_head_sha256 = forked
                    .prepared_head
                    .canonical_sha256()
                    .map_err(|_| BackendCallFailure::Denied)?;
                forked.receipt_sha256 = forked
                    .canonical_sha256()
                    .map_err(|_| BackendCallFailure::Denied)?;
                return Ok(forked);
            }
            Ok(receipt)
        }

        pub(super) fn commit(
            &self,
            request: &cas::DirectOperationRuntimeAuthorityCommitRequestV1,
        ) -> BackendCall<cas::DirectOperationRuntimeAuthorityCommitReceiptV1> {
            let mut state = self.state.lock().unwrap();
            let Some(pending) = state.pending.clone() else {
                return Err(BackendCallFailure::Denied);
            };
            let Some(exchange) = pending.exchanges.iter().find(|exchange| {
                exchange.request.request_sha256 == request.prepare_request_sha256
                    && exchange.receipt.receipt_sha256 == request.prepare_receipt_sha256
            }) else {
                return Err(BackendCallFailure::Denied);
            };
            if request
                .validate_for(&state.lineage, &exchange.request, &exchange.receipt)
                .is_err()
            {
                return Err(BackendCallFailure::Denied);
            }
            state.transcript.push(TestPhase::Commit(
                request.mutation_transaction_sha256.clone(),
                request.request_nonce_sha256.clone(),
            ));
            if Self::take_fault(&mut state, TestFault::CommitNotApplied) {
                return Err(BackendCallFailure::NotApplied);
            }
            if Self::take_fault(&mut state, TestFault::CommitDenied) {
                return Err(BackendCallFailure::Denied);
            }
            if Self::take_fault(&mut state, TestFault::CommitUnknownBeforeApply) {
                state.reconcile_required_transaction =
                    Some(request.mutation_transaction_sha256.clone());
                return Err(BackendCallFailure::OutcomeUnknown);
            }
            if Self::take_fault(&mut state, TestFault::CommitForkedReceipt) {
                state.reconcile_required_transaction =
                    Some(request.mutation_transaction_sha256.clone());
                return Ok(make_forked_commit_receipt(
                    &state.lineage,
                    &state.current,
                    &pending.prepared_head,
                    request,
                ));
            }
            let successor = make_successor(&state.lineage, &state.current, &pending.prepared_head);
            let receipt = make_commit_receipt(request, successor.clone());
            state.current = successor.clone();
            state.pending = None;
            state.reconcile_required_transaction = None;
            state.transcript.push(TestPhase::CommitApplied(
                successor.committed_head_sha256.clone(),
            ));
            if Self::take_fault(&mut state, TestFault::CommitUnknownAfterApply) {
                state.reconcile_required_transaction =
                    Some(request.mutation_transaction_sha256.clone());
                return Err(BackendCallFailure::OutcomeUnknown);
            }
            Ok(receipt)
        }

        pub(super) fn observe(
            &self,
            request: &cas::DirectOperationRuntimeAuthorityObserveRequestV1,
        ) -> BackendCall<cas::DirectOperationRuntimeAuthorityObserveResponseV1> {
            let mut state = self.state.lock().unwrap();
            if request
                .validate_for(&state.lineage, &state.current)
                .is_err()
            {
                return Err(BackendCallFailure::Denied);
            }
            state
                .transcript
                .push(TestPhase::Observe(request.request_nonce_sha256.clone()));
            if Self::take_fault(&mut state, TestFault::ObserveDenied) {
                return Err(BackendCallFailure::Denied);
            }
            if Self::take_fault(&mut state, TestFault::ObserveOutcomeUnknown) {
                return Err(BackendCallFailure::OutcomeUnknown);
            }
            let prepared_slot = match &state.pending {
                Some(pending) => cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                    prepared_head: pending.prepared_head.clone(),
                },
                None => cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
            };
            let snapshot = make_snapshot(&state.lineage, &state.current, prepared_slot);
            Ok(make_observe_response(request, snapshot))
        }

        pub(super) fn reconcile(
            &self,
            request: &cas::DirectOperationRuntimeAuthorityReconcileRequestV1,
        ) -> BackendCall<cas::DirectOperationRuntimeAuthorityReconcileResponseV1> {
            let mut state = self.state.lock().unwrap();
            if request.validate(&state.lineage).is_err()
                || state.reconcile_required_transaction.as_deref()
                    != Some(request.mutation_transaction_sha256.as_str())
                    && state
                        .pending
                        .as_ref()
                        .map(|pending| pending.intent.mutation_intent_sha256.as_str())
                        != Some(request.mutation_transaction_sha256.as_str())
            {
                return Err(BackendCallFailure::Denied);
            }
            state.transcript.push(TestPhase::Reconcile(request.cause));
            if Self::take_fault(&mut state, TestFault::ReconcileDenied) {
                return Err(BackendCallFailure::Denied);
            }
            let mut prepared_slot = match &state.pending {
                Some(pending) => cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                    prepared_head: pending.prepared_head.clone(),
                },
                None => cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
            };
            if Self::take_fault(&mut state, TestFault::ReconcileForkedPreparedHead) {
                let cas::DirectOperationRuntimeAuthorityPreparedSlotV1::Pending { prepared_head } =
                    &mut prepared_slot
                else {
                    return Err(BackendCallFailure::Denied);
                };
                prepared_head.proposed_journal_version = super::tests::journal_version(
                    "forked-reconcile-journal-identity",
                    "forked-reconcile-journal-bytes",
                );
                prepared_head.prepared_head_sha256 = prepared_head
                    .canonical_sha256()
                    .map_err(|_| BackendCallFailure::Denied)?;
            }
            let snapshot = make_snapshot(&state.lineage, &state.current, prepared_slot);
            let response = make_reconcile_response(request, snapshot);
            let disposition = response
                .disposition_for(&state.lineage, request)
                .map_err(|_| BackendCallFailure::Denied)?;
            if matches!(
                disposition,
                cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::NoMutation
                    | cas::DirectOperationRuntimeAuthorityReconcileDispositionV1::Committed
            ) {
                state.reconcile_required_transaction = None;
            }
            Ok(response)
        }
    }

    impl MutationCasAuthorityBackend for TestMutationCasAuthority {
        fn issue_nonce(&self, phase: &'static str, binding_sha256: &str) -> BackendCall<String> {
            Ok(Self::next_nonce(self, phase, binding_sha256))
        }

        fn prepare_call(
            &self,
            request: &cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
        ) -> BackendCall<cas::DirectOperationRuntimeAuthorityPrepareReceiptV1> {
            Self::prepare(self, request)
        }

        fn commit_call(
            &self,
            request: &cas::DirectOperationRuntimeAuthorityCommitRequestV1,
        ) -> BackendCall<cas::DirectOperationRuntimeAuthorityCommitReceiptV1> {
            Self::commit(self, request)
        }

        fn observe_call(
            &self,
            request: &cas::DirectOperationRuntimeAuthorityObserveRequestV1,
        ) -> BackendCall<cas::DirectOperationRuntimeAuthorityObserveResponseV1> {
            Self::observe(self, request)
        }

        fn reconcile_call(
            &self,
            request: &cas::DirectOperationRuntimeAuthorityReconcileRequestV1,
        ) -> BackendCall<cas::DirectOperationRuntimeAuthorityReconcileResponseV1> {
            Self::reconcile(self, request)
        }
    }

    fn make_prepared_head(
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
        intent: &cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    ) -> cas::DirectOperationRuntimeAuthorityPreparedHeadV1 {
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
        prepared.prepared_head_sha256 = prepared.canonical_sha256().unwrap();
        prepared
    }

    fn make_prepare_receipt(
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &cas::DirectOperationRuntimeAuthorityPrepareRequestV1,
        prepared_head: cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
    ) -> cas::DirectOperationRuntimeAuthorityPrepareReceiptV1 {
        let mut receipt = cas::DirectOperationRuntimeAuthorityPrepareReceiptV1 {
            schema: cas::PREPARE_RECEIPT_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            operation: cas::PREPARE_OPERATION.to_string(),
            request_sha256: request.request_sha256.clone(),
            prepared_head,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt.canonical_sha256().unwrap();
        receipt.validate_for(lineage, request).unwrap();
        receipt
    }

    fn make_successor(
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
        prepared: &cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
    ) -> cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
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
        head.committed_head_sha256 = head.canonical_sha256().unwrap();
        head.validate_successor(lineage, current, prepared).unwrap();
        head
    }

    fn make_commit_receipt(
        request: &cas::DirectOperationRuntimeAuthorityCommitRequestV1,
        committed_head: cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) -> cas::DirectOperationRuntimeAuthorityCommitReceiptV1 {
        let mut receipt = cas::DirectOperationRuntimeAuthorityCommitReceiptV1 {
            schema: cas::COMMIT_RECEIPT_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            operation: cas::COMMIT_OPERATION.to_string(),
            request_sha256: request.request_sha256.clone(),
            committed_head,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt.canonical_sha256().unwrap();
        receipt
    }

    fn make_forked_commit_receipt(
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
        prepared: &cas::DirectOperationRuntimeAuthorityPreparedHeadV1,
        request: &cas::DirectOperationRuntimeAuthorityCommitRequestV1,
    ) -> cas::DirectOperationRuntimeAuthorityCommitReceiptV1 {
        let mut head = make_successor(lineage, current, prepared);
        head.journal_version =
            super::tests::journal_version("forked-journal-identity", "forked-journal-bytes");
        head.committed_head_sha256 = head.canonical_sha256().unwrap();
        make_commit_receipt(request, head)
    }

    fn make_snapshot(
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        committed_head: &cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
        prepared_slot: cas::DirectOperationRuntimeAuthorityPreparedSlotV1,
    ) -> cas::DirectOperationRuntimeAuthoritySnapshotV1 {
        let mut snapshot = cas::DirectOperationRuntimeAuthoritySnapshotV1 {
            schema: cas::AUTHORITY_SNAPSHOT_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            committed_head: committed_head.clone(),
            prepared_slot,
            snapshot_sha256: String::new(),
        };
        snapshot.snapshot_sha256 = snapshot.canonical_sha256().unwrap();
        snapshot
    }

    fn make_observe_response(
        request: &cas::DirectOperationRuntimeAuthorityObserveRequestV1,
        snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
    ) -> cas::DirectOperationRuntimeAuthorityObserveResponseV1 {
        let mut response = cas::DirectOperationRuntimeAuthorityObserveResponseV1 {
            schema: cas::OBSERVE_RESPONSE_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            operation: cas::OBSERVE_OPERATION.to_string(),
            request_sha256: request.request_sha256.clone(),
            snapshot,
            response_sha256: String::new(),
        };
        response.response_sha256 = response.canonical_sha256().unwrap();
        response
    }

    fn make_reconcile_response(
        request: &cas::DirectOperationRuntimeAuthorityReconcileRequestV1,
        snapshot: cas::DirectOperationRuntimeAuthoritySnapshotV1,
    ) -> cas::DirectOperationRuntimeAuthorityReconcileResponseV1 {
        let mut response = cas::DirectOperationRuntimeAuthorityReconcileResponseV1 {
            schema: cas::RECONCILE_RESPONSE_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            operation: cas::RECONCILE_OPERATION.to_string(),
            request_sha256: request.request_sha256.clone(),
            snapshot,
            response_sha256: String::new(),
        };
        response.response_sha256 = response.canonical_sha256().unwrap();
        response
    }
}

#[cfg(test)]
use test_authority::TestMutationCasAuthority;

#[cfg(test)]
mod tests {
    use super::test_authority::{TestFault, TestPhase};
    use super::*;
    use crate::direct_operation_runtime_authority_store_session::{
        TestAuthorityStoreFault, TestAuthorityStoreMutationPhase,
    };
    use trillionnium_os_types::direct_operation::DirectOperationAdapter;
    use trillionnium_os_types::sha256_bytes;

    fn digest(label: &str) -> String {
        sha256_bytes(label.as_bytes())
    }

    pub(super) fn journal_version(
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

    fn lineage() -> cas::DirectOperationRuntimeAuthorityFirstUseLineageV1 {
        let mut anchor = cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1 {
            schema: cas::FIRST_USE_ANCHOR_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            authority_identity_sha256: digest("authority"),
            authority_store_instance_sha256: digest("authority-store"),
            provision_epoch_sha256: digest("provision-epoch"),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            adapter: DirectOperationAdapter::SystemApi,
            journal_epoch: "01".repeat(16),
            state_directory_identity_sha256: digest("state-directory"),
            genesis_journal_version: journal_version(
                "genesis-journal-identity",
                "genesis-journal-bytes",
            ),
            immutable_sentinel_schema: cas::FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA.to_string(),
            immutable_sentinel_embeds_prepared_head: false,
            sentinel_identity_sha256: digest("sentinel-identity"),
            sentinel_bytes_sha256: String::new(),
            first_use_anchor_sha256: String::new(),
        };
        anchor.sentinel_bytes_sha256 = anchor.canonical_immutable_sentinel_bytes_sha256().unwrap();
        anchor.first_use_anchor_sha256 = anchor.canonical_sha256().unwrap();

        let mut candidate = cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1 {
            schema: cas::FIRST_USE_CANDIDATE_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            proposed_genesis_journal_version_sha256: anchor
                .genesis_journal_version
                .journal_version_sha256
                .clone(),
            candidate_nonce_sha256: digest("first-use-candidate-nonce"),
            first_use_candidate_sha256: String::new(),
        };
        candidate.first_use_candidate_sha256 = candidate.canonical_sha256().unwrap();

        let mut prepared_head = cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1 {
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
            prepare_nonce_sha256: digest("first-use-prepare-nonce"),
            first_use_prepared_head_sha256: String::new(),
        };
        prepared_head.first_use_prepared_head_sha256 = prepared_head.canonical_sha256().unwrap();

        let mut committed_head = cas::DirectOperationRuntimeAuthorityFirstUseCommittedHeadV1 {
            schema: cas::FIRST_USE_COMMITTED_HEAD_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            first_use_candidate_sha256: candidate.first_use_candidate_sha256.clone(),
            first_use_prepared_head_sha256: prepared_head.first_use_prepared_head_sha256.clone(),
            committed_genesis_journal_version: anchor.genesis_journal_version.clone(),
            committed_sentinel_identity_sha256: anchor.sentinel_identity_sha256.clone(),
            committed_sentinel_bytes_sha256: anchor.sentinel_bytes_sha256.clone(),
            durable_commit_evidence_sha256: digest("first-use-durable-commit-evidence"),
            first_use_committed_head_sha256: String::new(),
        };
        committed_head.first_use_committed_head_sha256 = committed_head.canonical_sha256().unwrap();

        let mut result = cas::DirectOperationRuntimeAuthorityFirstUseCommittedResultBindingV1 {
            schema: cas::FIRST_USE_COMMITTED_RESULT_BINDING_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            first_use_candidate_sha256: candidate.first_use_candidate_sha256.clone(),
            first_use_prepared_head_sha256: prepared_head.first_use_prepared_head_sha256.clone(),
            first_use_committed_head_sha256: committed_head.first_use_committed_head_sha256.clone(),
            committed_genesis_journal_version_sha256: anchor
                .genesis_journal_version
                .journal_version_sha256
                .clone(),
            committed_sentinel_identity_sha256: anchor.sentinel_identity_sha256.clone(),
            committed_sentinel_bytes_sha256: anchor.sentinel_bytes_sha256.clone(),
            durable_commit_evidence_sha256: committed_head.durable_commit_evidence_sha256.clone(),
            result_receipt_sha256: digest("first-use-result-receipt"),
            first_use_committed_result_binding_sha256: String::new(),
        };
        result.first_use_committed_result_binding_sha256 = result.canonical_sha256().unwrap();

        let mut lineage = cas::DirectOperationRuntimeAuthorityFirstUseLineageV1 {
            schema: cas::FIRST_USE_LINEAGE_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            anchor,
            candidate,
            prepared_head,
            committed_head,
            committed_result_binding: result,
            first_use_lineage_sha256: String::new(),
        };
        lineage.first_use_lineage_sha256 = lineage.canonical_sha256().unwrap();
        lineage.validate().unwrap();
        lineage
    }

    fn genesis(
        lineage: &cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    ) -> cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
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
            mutation_generation: 1,
            journal_version: lineage.anchor.genesis_journal_version.clone(),
            ancestry: cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Genesis {
                first_use_committed_result_binding_sha256: lineage
                    .committed_result_binding
                    .first_use_committed_result_binding_sha256
                    .clone(),
            },
            committed_head_sha256: String::new(),
        };
        head.committed_head_sha256 = head.canonical_sha256().unwrap();
        head.validate(lineage).unwrap();
        head
    }

    fn authority() -> TestMutationCasAuthority {
        let lineage = lineage();
        let current = genesis(&lineage);
        TestMutationCasAuthority::new(lineage, current)
    }

    fn writer_lock_witness() -> SealedWriterLockWitness {
        writer_lock_witness_for("writer-lock")
    }

    fn writer_lock_witness_for(label: &str) -> SealedWriterLockWitness {
        SealedWriterLockWitness::for_test(digest(label))
    }

    fn plan_prepare_for_test(
        session: SealedCommittedMutationCasSession,
        writer_lock: SealedWriterLockWitness,
        kind: cas::DirectOperationRuntimeAuthorityMutationKindV1,
        current: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        proposed: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        mutation_nonce_sha256: String,
    ) -> PlannedMutationCasSession {
        match session.plan_prepare(writer_lock, kind, current, proposed, mutation_nonce_sha256) {
            PlanTransition::Planned(plan) => plan,
            PlanTransition::FailStopped(_) => panic!("mutation plan must be valid"),
        }
    }

    fn stage_plan_for_test(plan: PlannedMutationCasSession) -> StagedMutationCasSession {
        let proof = SealedDurableStagedMutationProof::for_test(&plan);
        match plan.bind_durable_stage(proof) {
            DurableStageTransition::Staged(staged) => staged,
            DurableStageTransition::FailStopped(_) => panic!("durable stage must bind"),
        }
    }

    fn send_initial_prepare_for_test(
        session: SealedCommittedMutationCasSession,
        writer_lock: SealedWriterLockWitness,
        kind: cas::DirectOperationRuntimeAuthorityMutationKindV1,
        current: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        proposed: cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        mutation_nonce_sha256: String,
    ) -> PrepareTransition {
        stage_plan_for_test(plan_prepare_for_test(
            session,
            writer_lock,
            kind,
            current,
            proposed,
            mutation_nonce_sha256,
        ))
        .send_prepare()
    }

    fn prepare(
        session: SealedCommittedMutationCasSession,
        kind: cas::DirectOperationRuntimeAuthorityMutationKindV1,
        suffix: &str,
    ) -> PreparedMutationCasSession {
        let current = session.current().journal_version.clone();
        match send_initial_prepare_for_test(
            session,
            writer_lock_witness(),
            kind,
            current,
            journal_version(
                &format!("proposed-identity-{suffix}"),
                &format!("proposed-bytes-{suffix}"),
            ),
            digest(&format!("mutation-nonce-{suffix}")),
        ) {
            PrepareTransition::Prepared(prepared) => prepared,
            _ => panic!("prepare must succeed"),
        }
    }

    fn publication(
        prepared: &PreparedMutationCasSession,
    ) -> cas::DirectOperationRuntimeAuthorityLocalPublicationV1 {
        publication_with_writer_lock(prepared, digest("writer-lock"))
    }

    fn publication_with_writer_lock(
        prepared: &PreparedMutationCasSession,
        writer_lock_identity_sha256: String,
    ) -> cas::DirectOperationRuntimeAuthorityLocalPublicationV1 {
        let mut publication = cas::DirectOperationRuntimeAuthorityLocalPublicationV1 {
            schema: cas::LOCAL_PUBLICATION_V1_SCHEMA.to_string(),
            protocol: cas::PROTOCOL.to_string(),
            first_use_lineage_sha256: prepared.session.lineage.first_use_lineage_sha256.clone(),
            prepared_head_sha256: prepared
                .prepare_receipt
                .prepared_head
                .prepared_head_sha256
                .clone(),
            mutation_generation: prepared
                .prepare_receipt
                .prepared_head
                .to_mutation_generation,
            state_directory_identity_sha256: prepared
                .session
                .lineage
                .anchor
                .state_directory_identity_sha256
                .clone(),
            writer_lock_identity_sha256,
            named_journal_version: prepared
                .prepare_receipt
                .prepared_head
                .proposed_journal_version
                .clone(),
            local_publication_sha256: String::new(),
        };
        publication.local_publication_sha256 = publication.canonical_sha256().unwrap();
        publication
    }

    fn publish(prepared: PreparedMutationCasSession) -> LocallyPublishedMutationCasSession {
        let evidence = publication(&prepared);
        match prepared.bind_local_publication(evidence) {
            LocalPublicationTransition::Published(published) => published,
            _ => panic!("publication must bind"),
        }
    }

    fn commit_to_terminal(
        published: LocallyPublishedMutationCasSession,
    ) -> ReconciledCommittedMutationCasSession {
        match published.commit() {
            CommitTransition::Committed(terminal) => terminal,
            CommitTransition::FailStopped(_) => panic!("commit must succeed"),
        }
    }

    fn commit_and_reopen(
        published: LocallyPublishedMutationCasSession,
    ) -> SealedCommittedMutationCasSession {
        let proposed = published
            .prepared
            .prepare_receipt
            .prepared_head
            .proposed_journal_version
            .clone();
        let writer_lock_identity_sha256 = published
            .local_publication
            .writer_lock_identity_sha256
            .clone();
        match commit_to_terminal(published).reopen_after_local_cleanup(facts_with_writer_lock(
            writer_lock_identity_sha256,
            LocalEntryObservation::Present(proposed),
            LocalEntryObservation::Missing,
        )) {
            ObserveTransition::Current(session) => session,
            ObserveTransition::FailStopped(_) => {
                panic!("exact cleanup and fresh OBSERVE must reopen")
            }
        }
    }

    fn publish_with_writer_lock(
        prepared: PreparedMutationCasSession,
        writer_lock_identity_sha256: String,
    ) -> LocallyPublishedMutationCasSession {
        let evidence = publication_with_writer_lock(&prepared, writer_lock_identity_sha256);
        match prepared.bind_local_publication(evidence) {
            LocalPublicationTransition::Published(published) => published,
            _ => panic!("publication must bind"),
        }
    }

    fn facts(
        named: LocalEntryObservation,
        staged: LocalEntryObservation,
    ) -> SealedLocalReconcileObservations {
        facts_with_writer_lock(digest("writer-lock"), named, staged)
    }

    fn facts_with_writer_lock(
        writer_lock_identity_sha256: String,
        named: LocalEntryObservation,
        staged: LocalEntryObservation,
    ) -> SealedLocalReconcileObservations {
        SealedLocalReconcileObservations {
            writer_lock_identity_sha256,
            named_journal: named,
            staged_candidate: staged,
            _source: SealedLocalObservationSource::Test,
        }
    }

    fn resume_after_unknown_prepare(
        authority: &TestMutationCasAuthority,
        suffix: &str,
    ) -> ReconciledPreparedMutationCasSession {
        authority.queue_fault(TestFault::PrepareUnknownAfterApply);
        let session = authority.open().unwrap();
        let old = session.current().journal_version.clone();
        let proposed = journal_version(
            &format!("resume-helper-identity-{suffix}"),
            &format!("resume-helper-bytes-{suffix}"),
        );
        let failed = match send_initial_prepare_for_test(
            session,
            writer_lock_witness(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            old.clone(),
            proposed.clone(),
            digest(&format!("resume-helper-nonce-{suffix}")),
        ) {
            PrepareTransition::FailStopped(failed) => failed,
            _ => panic!("prepare must become uncertain after apply"),
        };
        match failed.reconcile(facts(
            LocalEntryObservation::Present(old),
            LocalEntryObservation::Present(proposed),
        )) {
            ReconcileTransition::ResumeExactPreparedPublication(continuation) => continuation,
            _ => panic!("exact pending mutation must resume"),
        }
    }

    #[test]
    fn mutation_plan_is_rpc_free_and_prepare_requires_staged_typestate() {
        let authority = authority();
        let session = authority.open().unwrap();
        let current = session.current().journal_version.clone();
        let plan = plan_prepare_for_test(
            session,
            writer_lock_witness(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            current,
            journal_version("plan-stage-identity", "plan-stage-bytes"),
            digest("plan-stage-mutation-nonce"),
        );
        assert!(!plan.transaction_sha256().is_empty());
        assert!(
            authority.transcript().is_empty(),
            "planning must not issue a nonce or call the backend"
        );

        let proof = SealedDurableStagedMutationProof::for_test(&plan);
        let staged = match plan.bind_durable_stage(proof) {
            DurableStageTransition::Staged(staged) => staged,
            DurableStageTransition::FailStopped(_) => panic!("exact durable stage must bind"),
        };
        assert!(
            authority.transcript().is_empty(),
            "binding durable local facts must remain backend-free"
        );
        assert!(matches!(
            staged.send_prepare(),
            PrepareTransition::Prepared(_)
        ));
        assert!(
            authority
                .transcript()
                .iter()
                .any(|phase| matches!(phase, TestPhase::Prepare(_, _)))
        );

        let source = include_str!("direct_operation_runtime_authority_mutation_cas_client.rs");
        let planned_impl = source
            .split("impl PlannedMutationCasSession {")
            .nth(1)
            .unwrap()
            .split("impl StagedMutationCasSession {")
            .next()
            .unwrap();
        assert!(planned_impl.contains("bind_durable_stage"));
        assert!(
            !planned_impl.contains("send_prepare"),
            "an unstaged plan must have no PREPARE-capable method"
        );
    }

    #[test]
    fn durable_stage_field_or_lock_drift_fails_before_prepare_rpc() {
        for case in 0..10 {
            let authority = authority();
            let session = authority.open().unwrap();
            let current = session.current().journal_version.clone();
            let plan = plan_prepare_for_test(
                session,
                writer_lock_witness(),
                cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
                current,
                journal_version(
                    &format!("stage-drift-proposed-identity-{case}"),
                    &format!("stage-drift-proposed-bytes-{case}"),
                ),
                digest(&format!("stage-drift-mutation-nonce-{case}")),
            );
            let mut proof = SealedDurableStagedMutationProof::for_test(&plan);
            match case {
                0 => {
                    proof.staged_candidate_journal_version =
                        journal_version("wrong-staged-identity", "wrong-staged-bytes");
                }
                1 => {
                    proof.transaction_sidecar_identity_sha256 = "0".repeat(64);
                }
                2 => {
                    proof.transaction_sidecar_bytes_sha256 = "0".repeat(64);
                }
                3 => {
                    proof.sidecar_first_use_lineage_sha256 = digest("wrong-first-use-lineage");
                }
                4 => {
                    proof.sidecar_from_committed_head_sha256 = digest("wrong-committed-head");
                }
                5 => {
                    proof.sidecar_mutation_transaction_sha256 =
                        digest("wrong-mutation-transaction");
                }
                6 => {
                    proof.sidecar_mutation_kind =
                        cas::DirectOperationRuntimeAuthorityMutationKindV1::AcknowledgeOuterV2;
                }
                7 => {
                    proof.sidecar_current_journal_version =
                        journal_version("wrong-current-identity", "wrong-current-bytes");
                }
                8 => {
                    proof.sidecar_proposed_journal_version =
                        journal_version("wrong-proposed-identity", "wrong-proposed-bytes");
                }
                9 => {
                    proof.sidecar_writer_lock_identity_sha256 = digest("wrong-writer-lock");
                }
                _ => unreachable!("fixed stage-drift matrix"),
            }
            let failed = match plan.bind_durable_stage(proof) {
                DurableStageTransition::FailStopped(failed) => failed,
                DurableStageTransition::Staged(_) => {
                    panic!("drifted durable stage must never become PREPARE-capable")
                }
            };
            assert_eq!(
                failed.reason(),
                MutationCasFailStopReason::InvalidLocalInput
            );
            match &failed.recovery {
                RecoveryState::None {
                    writer_lock_identity_sha256: Some(writer_lock),
                } => assert_eq!(writer_lock, &digest("writer-lock")),
                _ => panic!("stage drift must retain the planned writer-lock lineage"),
            }
            assert!(
                authority.transcript().is_empty(),
                "stage drift must fail before nonce issuance or PREPARE RPC"
            );
        }
    }

    #[test]
    fn all_four_mutation_kinds_commit_exact_successors() {
        for (index, kind) in [
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            cas::DirectOperationRuntimeAuthorityMutationKindV1::PersistPreparedTransportAck,
            cas::DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult,
            cas::DirectOperationRuntimeAuthorityMutationKindV1::AcknowledgeOuterV2,
        ]
        .into_iter()
        .enumerate()
        {
            let authority = authority();
            let prepared = prepare(authority.open().unwrap(), kind, &index.to_string());
            let transaction = prepared.transaction_sha256().to_string();
            let committed = commit_and_reopen(publish(prepared));
            assert_eq!(committed.current().mutation_generation, 2);
            assert_eq!(
                committed.current().journal_version,
                journal_version(
                    &format!("proposed-identity-{index}"),
                    &format!("proposed-bytes-{index}")
                )
            );
            assert!(authority.transcript().iter().any(
                |phase| matches!(phase, TestPhase::Prepare(value, _) if value == &transaction)
            ));
        }
    }

    #[test]
    fn direct_commit_terminal_requires_exact_local_cleanup() {
        for case in 0..4 {
            let authority = authority();
            let prepared = prepare(
                authority.open().unwrap(),
                cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
                &format!("direct-cleanup-drift-{case}"),
            );
            let old = prepared.prepared_head().expected_journal_version.clone();
            let proposed = prepared.prepared_head().proposed_journal_version.clone();
            let terminal = commit_to_terminal(publish(prepared));
            assert!(!terminal.transaction_sha256().is_empty());
            assert!(matches!(
                terminal.prepared_knowledge(),
                cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known { .. }
            ));
            let observe_count_before = authority
                .transcript()
                .iter()
                .filter(|phase| matches!(phase, TestPhase::Observe(_)))
                .count();
            let observations = match case {
                0 => facts(
                    LocalEntryObservation::Present(old),
                    LocalEntryObservation::Missing,
                ),
                1 => facts(
                    LocalEntryObservation::Missing,
                    LocalEntryObservation::Missing,
                ),
                2 => facts(
                    LocalEntryObservation::Present(proposed.clone()),
                    LocalEntryObservation::Present(proposed),
                ),
                3 => facts_with_writer_lock(
                    digest("different-writer-lock"),
                    LocalEntryObservation::Present(proposed),
                    LocalEntryObservation::Missing,
                ),
                _ => unreachable!("fixed cleanup-drift matrix"),
            };
            let failed = match terminal.reopen_after_local_cleanup(observations) {
                ObserveTransition::FailStopped(failed) => failed,
                ObserveTransition::Current(_) => {
                    panic!("inexact direct-commit cleanup must never expose Current")
                }
            };
            assert_eq!(
                failed.reason(),
                MutationCasFailStopReason::InvalidLocalInput
            );
            match &failed.recovery {
                RecoveryState::None {
                    writer_lock_identity_sha256: Some(writer_lock),
                } => assert_eq!(writer_lock, &digest("writer-lock")),
                _ => panic!("cleanup drift must retain the expected writer-lock lineage"),
            }
            assert_eq!(
                authority
                    .transcript()
                    .iter()
                    .filter(|phase| matches!(phase, TestPhase::Observe(_)))
                    .count(),
                observe_count_before,
                "local cleanup drift must fail before contacting authority"
            );
        }
    }

    #[test]
    fn direct_commit_cleanup_never_reopens_after_observe_failure() {
        for (index, (fault, reason)) in [
            (
                TestFault::ObserveDenied,
                MutationCasFailStopReason::ObserveDenied,
            ),
            (
                TestFault::ObserveOutcomeUnknown,
                MutationCasFailStopReason::ObserveOutcomeUnknown,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let authority = authority();
            let prepared = prepare(
                authority.open().unwrap(),
                cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
                &format!("direct-cleanup-observe-{index}"),
            );
            let proposed = prepared.prepared_head().proposed_journal_version.clone();
            let terminal = commit_to_terminal(publish(prepared));
            authority.queue_fault(fault);
            let failed = match terminal.reopen_after_local_cleanup(facts(
                LocalEntryObservation::Present(proposed),
                LocalEntryObservation::Missing,
            )) {
                ObserveTransition::FailStopped(failed) => failed,
                ObserveTransition::Current(_) => {
                    panic!("failed direct-commit OBSERVE must never expose Current")
                }
            };
            assert_eq!(failed.reason(), reason);
            match &failed.recovery {
                RecoveryState::None {
                    writer_lock_identity_sha256: Some(writer_lock),
                } => assert_eq!(writer_lock, &digest("writer-lock")),
                _ => panic!("direct-commit OBSERVE failure must retain writer-lock lineage"),
            }
            let terminal_phases: Vec<_> = authority
                .transcript()
                .iter()
                .filter_map(|phase| match phase {
                    TestPhase::CommitApplied(_) => Some("commit_applied"),
                    TestPhase::Observe(_) => Some("observe"),
                    _ => None,
                })
                .collect();
            assert_eq!(terminal_phases, ["commit_applied", "observe"]);
        }
    }

    #[test]
    fn exact_phase_transcript_and_nonce_retry_keep_one_transaction() {
        let authority = authority();
        authority.queue_fault(TestFault::PrepareNotApplied);
        let session = authority.open().unwrap();
        let current = session.current().journal_version.clone();
        let retry = match send_initial_prepare_for_test(
            session,
            writer_lock_witness(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            current,
            journal_version("retry-proposed-identity", "retry-proposed-bytes"),
            digest("retry-mutation-nonce"),
        ) {
            PrepareTransition::Retryable(retry) => retry,
            _ => panic!("first call must be provably not applied"),
        };
        let transaction = retry.transaction_sha256().to_string();
        let first_nonce = retry.previous_request_nonce_sha256().to_string();
        let prepared = match retry.retry() {
            PrepareTransition::Prepared(prepared) => prepared,
            _ => panic!("retry must prepare"),
        };
        assert_eq!(prepared.transaction_sha256(), transaction);
        let attempts: Vec<_> = authority
            .transcript()
            .into_iter()
            .filter_map(|phase| match phase {
                TestPhase::Prepare(transaction, nonce) => Some((transaction, nonce)),
                _ => None,
            })
            .collect();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].0, attempts[1].0);
        assert_eq!(attempts[0].0, transaction);
        assert_eq!(attempts[0].1, first_nonce);
        assert_ne!(attempts[0].1, attempts[1].1);
        let _committed = commit_and_reopen(publish(prepared));
        let phase_names: Vec<_> = authority
            .transcript()
            .iter()
            .filter_map(|phase| match phase {
                TestPhase::Observe(_) => Some("observe"),
                TestPhase::Prepare(_, _) => Some("prepare"),
                TestPhase::PrepareApplied(_) => Some("prepare_applied"),
                TestPhase::Commit(_, _) => Some("commit"),
                TestPhase::CommitApplied(_) => Some("commit_applied"),
                _ => None,
            })
            .collect();
        assert_eq!(
            phase_names,
            [
                "prepare",
                "observe",
                "prepare",
                "prepare_applied",
                "commit",
                "commit_applied",
                "observe"
            ]
        );
    }

    #[test]
    fn observe_requires_exact_current_and_empty_prepared_slot() {
        let authority = authority();
        let session = authority.open().unwrap();
        let observed = session.current().journal_version.clone();
        let observer = match session.validate_current(observed) {
            ObserveTransition::Current(session) => session,
            _ => panic!("exact empty observation must pass"),
        };
        let mutator = authority.open().unwrap();
        let _prepared = prepare(
            mutator,
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            "observe-pending",
        );
        assert!(authority.has_pending());
        let observed = observer.current().journal_version.clone();
        let failed = match observer.validate_current(observed) {
            ObserveTransition::FailStopped(failed) => failed,
            _ => panic!("a pending prepared slot must fail observation"),
        };
        assert_eq!(failed.reason(), MutationCasFailStopReason::ObserveDenied);
        assert!(authority.open().is_err());
    }

    #[test]
    fn prepare_unknown_before_apply_reconciles_to_original_committed_session() {
        let authority = authority();
        authority.queue_fault(TestFault::PrepareUnknownBeforeApply);
        let session = authority.open().unwrap();
        let old = session.current().journal_version.clone();
        let proposed = journal_version("unknown-before-identity", "unknown-before-bytes");
        let failed = match send_initial_prepare_for_test(
            session,
            writer_lock_witness(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            old.clone(),
            proposed.clone(),
            digest("unknown-before-nonce"),
        ) {
            PrepareTransition::FailStopped(failed) => failed,
            _ => panic!("prepare outcome must be unknown"),
        };
        assert_eq!(
            failed.reason(),
            MutationCasFailStopReason::PrepareOutcomeUnknown
        );
        assert!(authority.open().is_err());
        let terminal = match failed.reconcile(facts(
            LocalEntryObservation::Present(old.clone()),
            LocalEntryObservation::Present(proposed.clone()),
        )) {
            ReconcileTransition::NoMutation(terminal) => terminal,
            _ => panic!("exact before-apply snapshot must return the original session"),
        };
        assert_eq!(
            terminal.prepared_knowledge(),
            &cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Unknown
        );
        let reopened = match terminal.reopen_after_local_cleanup(facts(
            LocalEntryObservation::Present(old.clone()),
            LocalEntryObservation::Missing,
        )) {
            ObserveTransition::Current(session) => session,
            _ => panic!("exact cleanup plus fresh observe must reopen"),
        };
        assert_eq!(reopened.current().journal_version, old);
        assert_eq!(reopened.current().mutation_generation, 1);
        assert!(authority.open().is_ok());
    }

    #[test]
    fn prepare_unknown_after_apply_reprepares_exact_pending_with_fresh_nonce() {
        let authority = authority();
        authority.queue_fault(TestFault::PrepareUnknownAfterApply);
        let session = authority.open().unwrap();
        let old = session.current().journal_version.clone();
        let proposed = journal_version("resume-identity", "resume-bytes");
        let failed = match send_initial_prepare_for_test(
            session,
            writer_lock_witness(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            old.clone(),
            proposed.clone(),
            digest("resume-nonce"),
        ) {
            PrepareTransition::FailStopped(failed) => failed,
            _ => panic!("prepare response must be unknown"),
        };
        let (first_transaction, first_nonce) = authority
            .transcript()
            .iter()
            .find_map(|phase| match phase {
                TestPhase::Prepare(transaction, nonce) => {
                    Some((transaction.clone(), nonce.clone()))
                }
                _ => None,
            })
            .unwrap();
        let continuation = match failed.reconcile(facts(
            LocalEntryObservation::Present(old),
            LocalEntryObservation::Present(proposed),
        )) {
            ReconcileTransition::ResumeExactPreparedPublication(continuation) => continuation,
            _ => panic!("exact after-apply snapshot must resume the pending publication"),
        };
        assert_eq!(continuation.transaction_sha256(), first_transaction);
        let exact_prepared_head = continuation.prepared_head().clone();
        let prepared = match continuation.reprepare() {
            ReprepareTransition::Prepared(prepared) => prepared,
            _ => panic!("exact pending mutation must reprepare"),
        };
        assert_eq!(prepared.transaction_sha256(), first_transaction);
        assert_eq!(prepared.prepared_head(), &exact_prepared_head);
        let prepare_attempts: Vec<_> = authority
            .transcript()
            .iter()
            .filter_map(|phase| match phase {
                TestPhase::Prepare(transaction, nonce) => {
                    Some((transaction.clone(), nonce.clone()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(prepare_attempts.len(), 2);
        assert_eq!(prepare_attempts[0].0, prepare_attempts[1].0);
        assert_eq!(prepare_attempts[0].0, first_transaction);
        assert_eq!(prepare_attempts[0].1, first_nonce);
        assert_ne!(prepare_attempts[0].1, prepare_attempts[1].1);
        let committed = commit_and_reopen(publish(prepared));
        assert_eq!(committed.current().mutation_generation, 2);
        assert!(authority.open().is_ok());
    }

    #[test]
    fn known_prepared_staged_candidate_resumes_before_named_publication() {
        let authority = authority();
        let prepared = prepare(
            authority.open().unwrap(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::PersistPreparedTransportAck,
            "staged-before-rename",
        );
        let old = prepared
            .prepare_receipt
            .prepared_head
            .expected_journal_version
            .clone();
        let proposed = prepared.prepared_head().proposed_journal_version.clone();
        let failed = prepared.staged_publication_interrupted();
        let continuation = match failed.reconcile(facts(
            LocalEntryObservation::Present(old),
            LocalEntryObservation::Present(proposed),
        )) {
            ReconcileTransition::ResumeExactPreparedPublication(continuation) => continuation,
            _ => panic!("known staged candidate must resume exact publication"),
        };
        let expected = continuation.prepared_head().clone();
        let reprepared = match continuation.reprepare() {
            ReprepareTransition::Prepared(prepared) => prepared,
            _ => panic!("known staged candidate must reprepare"),
        };
        assert_eq!(reprepared.prepared_head(), &expected);
        let committed = commit_and_reopen(publish(reprepared));
        assert_eq!(committed.current().mutation_generation, 2);
    }

    #[test]
    fn locally_published_pending_reprepares_then_retries_exact_commit() {
        let authority = authority();
        let prepared = prepare(
            authority.open().unwrap(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult,
            "retry-commit",
        );
        let proposed = prepared.prepared_head().proposed_journal_version.clone();
        let failed = prepared.local_publication_uncertain();
        let continuation = match failed.reconcile(facts(
            LocalEntryObservation::Present(proposed),
            LocalEntryObservation::Missing,
        )) {
            ReconcileTransition::RetryExactCommit(continuation) => continuation,
            _ => panic!("exact locally published mutation must retry commit"),
        };
        let transaction = continuation.transaction_sha256().to_string();
        let reprepared = match continuation.reprepare() {
            ReprepareTransition::Prepared(prepared) => prepared,
            _ => panic!("exact commit retry must reacquire a receipt"),
        };
        assert_eq!(reprepared.transaction_sha256(), transaction);
        let committed = commit_and_reopen(publish(reprepared));
        assert_eq!(committed.current().mutation_generation, 2);
    }

    #[test]
    fn commit_unknown_after_apply_returns_exact_successor_session() {
        let authority = authority();
        let prepared = prepare(
            authority.open().unwrap(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::AcknowledgeOuterV2,
            "commit-after",
        );
        let proposed = prepared.prepared_head().proposed_journal_version.clone();
        authority.queue_fault(TestFault::CommitUnknownAfterApply);
        let failed = match publish(prepared).commit() {
            CommitTransition::FailStopped(failed) => failed,
            _ => panic!("commit response must be unknown"),
        };
        let terminal = match failed.reconcile(facts(
            LocalEntryObservation::Present(proposed.clone()),
            LocalEntryObservation::Missing,
        )) {
            ReconcileTransition::Committed(terminal) => terminal,
            _ => panic!("after-apply snapshot must return the exact successor"),
        };
        let transaction = terminal.transaction_sha256().to_string();
        assert!(!transaction.is_empty());
        assert!(matches!(
            terminal.prepared_knowledge(),
            cas::DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known { .. }
        ));
        let committed = match terminal.reopen_after_local_cleanup(facts(
            LocalEntryObservation::Present(proposed),
            LocalEntryObservation::Missing,
        )) {
            ObserveTransition::Current(session) => session,
            _ => panic!("terminal successor needs exact cleanup plus fresh observe"),
        };
        assert_eq!(committed.current().mutation_generation, 2);
        assert_eq!(authority.open().unwrap().current().mutation_generation, 2);
    }

    #[test]
    fn commit_not_applied_retries_exactly_while_denial_stays_closed() {
        let retry_authority = authority();
        let retry_prepared = prepare(
            retry_authority.open().unwrap(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult,
            "commit-not-applied",
        );
        let proposed = retry_prepared
            .prepared_head()
            .proposed_journal_version
            .clone();
        retry_authority.queue_fault(TestFault::CommitNotApplied);
        let retry_failed = match publish(retry_prepared).commit() {
            CommitTransition::FailStopped(failed) => failed,
            _ => panic!("provably unapplied commit must fail-stop for exact retry"),
        };
        assert_eq!(
            retry_failed.reason(),
            MutationCasFailStopReason::CommitNotApplied
        );
        assert!(
            retry_authority
                .transcript()
                .iter()
                .all(|phase| !matches!(phase, TestPhase::CommitApplied(_)))
        );
        let continuation = match retry_failed.reconcile(facts(
            LocalEntryObservation::Present(proposed),
            LocalEntryObservation::Missing,
        )) {
            ReconcileTransition::RetryExactCommit(continuation) => continuation,
            _ => panic!("provably unapplied commit must retain exact retry authority"),
        };
        let reprepared = match continuation.reprepare() {
            ReprepareTransition::Prepared(prepared) => prepared,
            _ => panic!("commit retry must reprepare"),
        };
        let committed = commit_and_reopen(publish(reprepared));
        assert_eq!(committed.current().mutation_generation, 2);

        let denied_authority = authority();
        let denied_prepared = prepare(
            denied_authority.open().unwrap(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult,
            "commit-denied",
        );
        let denied_proposed = denied_prepared
            .prepared_head()
            .proposed_journal_version
            .clone();
        denied_authority.queue_fault(TestFault::CommitDenied);
        let denied = match publish(denied_prepared).commit() {
            CommitTransition::FailStopped(failed) => failed,
            _ => panic!("denied commit must fail-stop"),
        };
        assert_eq!(denied.reason(), MutationCasFailStopReason::CommitDenied);
        let denied_hold = match denied.reconcile(facts(
            LocalEntryObservation::Present(denied_proposed),
            LocalEntryObservation::Missing,
        )) {
            ReconcileTransition::Hold(hold) => hold,
            _ => panic!("denied commit must remain closed"),
        };
        assert_eq!(
            denied_hold.reason(),
            MutationCasFailStopReason::CommitDenied
        );
        assert!(denied_authority.open().is_err());
    }

    #[test]
    fn commit_unknown_before_apply_reprepares_exact_pending_and_commits() {
        let authority = authority();
        let prepared = prepare(
            authority.open().unwrap(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::AcknowledgeOuterV2,
            "commit-before",
        );
        let proposed = prepared.prepared_head().proposed_journal_version.clone();
        authority.queue_fault(TestFault::CommitUnknownBeforeApply);
        let failed = match publish(prepared).commit() {
            CommitTransition::FailStopped(failed) => failed,
            _ => panic!("commit response must be unknown"),
        };
        let continuation = match failed.reconcile(facts(
            LocalEntryObservation::Present(proposed),
            LocalEntryObservation::Missing,
        )) {
            ReconcileTransition::RetryExactCommit(continuation) => continuation,
            _ => panic!("exact pending snapshot must retry the same commit"),
        };
        let transaction = continuation.transaction_sha256().to_string();
        let reprepared = match continuation.reprepare() {
            ReprepareTransition::Prepared(prepared) => prepared,
            _ => panic!("exact pending commit must reprepare"),
        };
        assert_eq!(reprepared.transaction_sha256(), transaction);
        let committed = commit_and_reopen(publish(reprepared));
        assert_eq!(committed.current().mutation_generation, 2);
    }

    #[test]
    fn stale_session_and_forked_commit_receipt_fail_closed() {
        let stale_authority = authority();
        let stale = stale_authority.open().unwrap();
        let active = stale_authority.open().unwrap();
        let committed = commit_and_reopen(publish(prepare(
            active,
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            "advance",
        )));
        assert_eq!(committed.current().mutation_generation, 2);
        let stale_version = stale.current().journal_version.clone();
        let stale = match stale.validate_current(stale_version.clone()) {
            ObserveTransition::FailStopped(failed) => failed,
            _ => panic!("stale authority head must fail"),
        };
        assert_eq!(stale.reason(), MutationCasFailStopReason::ObserveDenied);
        let stale_hold = match stale.reconcile(facts(
            LocalEntryObservation::Present(stale_version),
            LocalEntryObservation::Missing,
        )) {
            ReconcileTransition::Hold(hold) => hold,
            _ => panic!("stale session must not gain a continuation"),
        };
        assert_eq!(
            stale_hold.reason(),
            MutationCasFailStopReason::ObserveDenied
        );

        let fork_authority = authority();
        let prepared = prepare(
            fork_authority.open().unwrap(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            "fork",
        );
        fork_authority.queue_fault(TestFault::CommitForkedReceipt);
        let failed = match publish(prepared).commit() {
            CommitTransition::FailStopped(failed) => failed,
            _ => panic!("forked receipt must fail"),
        };
        assert_eq!(
            failed.reason(),
            MutationCasFailStopReason::InvalidCommitReceipt
        );
        let proposed = match &failed.recovery {
            RecoveryState::Uncertain { intent, .. } => intent.proposed_journal_version.clone(),
            RecoveryState::None { .. } => {
                panic!("invalid receipt must require reconciliation")
            }
        };
        fork_authority.queue_fault(TestFault::ReconcileForkedPreparedHead);
        let fork_hold = match failed.reconcile(facts(
            LocalEntryObservation::Present(proposed),
            LocalEntryObservation::Missing,
        )) {
            ReconcileTransition::Hold(hold) => hold,
            _ => panic!("forked prepared snapshot must remain closed"),
        };
        assert_eq!(
            fork_hold.reason(),
            MutationCasFailStopReason::InvalidCommitReceipt
        );
        assert!(fork_authority.open().is_err());
    }

    #[test]
    fn reconcile_denial_and_inexact_terminal_cleanup_hold_closed() {
        let denied_authority = authority();
        denied_authority.queue_fault(TestFault::PrepareUnknownAfterApply);
        let session = denied_authority.open().unwrap();
        let old = session.current().journal_version.clone();
        let proposed = journal_version("denied-reconcile-identity", "denied-reconcile-bytes");
        let failed = match send_initial_prepare_for_test(
            session,
            writer_lock_witness(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            old.clone(),
            proposed.clone(),
            digest("denied-reconcile-nonce"),
        ) {
            PrepareTransition::FailStopped(failed) => failed,
            _ => panic!("prepare must become uncertain"),
        };
        denied_authority.queue_fault(TestFault::ReconcileDenied);
        let hold = match failed.reconcile(facts(
            LocalEntryObservation::Present(old),
            LocalEntryObservation::Present(proposed),
        )) {
            ReconcileTransition::Hold(hold) => hold,
            _ => panic!("reconcile denial must hold"),
        };
        assert_eq!(
            hold.reason(),
            MutationCasFailStopReason::PrepareOutcomeUnknown
        );

        let cleanup_authority = authority();
        cleanup_authority.queue_fault(TestFault::PrepareUnknownBeforeApply);
        let session = cleanup_authority.open().unwrap();
        let old = session.current().journal_version.clone();
        let proposed = journal_version("cleanup-identity", "cleanup-bytes");
        let failed = match send_initial_prepare_for_test(
            session,
            writer_lock_witness(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            old.clone(),
            proposed.clone(),
            digest("cleanup-nonce"),
        ) {
            PrepareTransition::FailStopped(failed) => failed,
            _ => panic!("prepare must become uncertain"),
        };
        let terminal = match failed.reconcile(facts(
            LocalEntryObservation::Present(old.clone()),
            LocalEntryObservation::Present(proposed.clone()),
        )) {
            ReconcileTransition::NoMutation(terminal) => terminal,
            _ => panic!("before-apply reconcile must classify no mutation"),
        };
        let failed_cleanup = match terminal.reopen_after_local_cleanup(facts(
            LocalEntryObservation::Present(old),
            LocalEntryObservation::Present(proposed),
        )) {
            ObserveTransition::FailStopped(failed) => failed,
            _ => panic!("staged candidate still present must block reopen"),
        };
        assert_eq!(
            failed_cleanup.reason(),
            MutationCasFailStopReason::InvalidLocalInput
        );
    }

    #[test]
    fn terminal_cleanup_never_reopens_after_observe_failure() {
        for (index, (fault, reason)) in [
            (
                TestFault::ObserveDenied,
                MutationCasFailStopReason::ObserveDenied,
            ),
            (
                TestFault::ObserveOutcomeUnknown,
                MutationCasFailStopReason::ObserveOutcomeUnknown,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let authority = authority();
            authority.queue_fault(TestFault::PrepareUnknownBeforeApply);
            let session = authority.open().unwrap();
            let old = session.current().journal_version.clone();
            let proposed = journal_version(
                &format!("terminal-observe-identity-{index}"),
                &format!("terminal-observe-bytes-{index}"),
            );
            let failed = match send_initial_prepare_for_test(
                session,
                writer_lock_witness(),
                cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
                old.clone(),
                proposed.clone(),
                digest(&format!("terminal-observe-nonce-{index}")),
            ) {
                PrepareTransition::FailStopped(failed) => failed,
                _ => panic!("prepare must become uncertain before apply"),
            };
            let terminal = match failed.reconcile(facts(
                LocalEntryObservation::Present(old.clone()),
                LocalEntryObservation::Present(proposed),
            )) {
                ReconcileTransition::NoMutation(terminal) => terminal,
                _ => panic!("before-apply reconcile must classify no mutation"),
            };
            authority.queue_fault(fault);
            let failed = match terminal.reopen_after_local_cleanup(facts(
                LocalEntryObservation::Present(old),
                LocalEntryObservation::Missing,
            )) {
                ObserveTransition::FailStopped(failed) => failed,
                ObserveTransition::Current(_) => {
                    panic!("failed terminal OBSERVE must never expose Current")
                }
            };
            assert_eq!(failed.reason(), reason);
            match &failed.recovery {
                RecoveryState::None {
                    writer_lock_identity_sha256: Some(writer_lock),
                } => assert_eq!(writer_lock, &digest("writer-lock")),
                _ => panic!("terminal OBSERVE failure must retain writer-lock lineage"),
            }
        }
    }

    #[test]
    fn reprepare_failures_reconcile_exact_pending_while_denial_holds() {
        let not_applied_authority = authority();
        let continuation = resume_after_unknown_prepare(&not_applied_authority, "not-applied");
        let old = continuation.session.current().journal_version.clone();
        let proposed = continuation.intent.proposed_journal_version.clone();
        not_applied_authority.queue_fault(TestFault::PrepareNotApplied);
        let failed = match continuation.reprepare() {
            ReprepareTransition::FailStopped(failed) => failed,
            _ => panic!("provably unapplied reprepare must not expose a prepared session"),
        };
        assert_eq!(
            failed.reason(),
            MutationCasFailStopReason::PrepareNotApplied
        );
        let continuation = match failed.reconcile(facts(
            LocalEntryObservation::Present(old),
            LocalEntryObservation::Present(proposed),
        )) {
            ReconcileTransition::ResumeExactPreparedPublication(continuation) => continuation,
            _ => panic!("provably unapplied reprepare must retain exact pending recovery"),
        };
        assert!(matches!(
            continuation.reprepare(),
            ReprepareTransition::Prepared(_)
        ));
        assert!(not_applied_authority.has_pending());

        let forked_authority = authority();
        let continuation = resume_after_unknown_prepare(&forked_authority, "forked-receipt");
        let old = continuation.session.current().journal_version.clone();
        let proposed = continuation.intent.proposed_journal_version.clone();
        forked_authority.queue_fault(TestFault::PrepareForkedReceipt);
        let failed = match continuation.reprepare() {
            ReprepareTransition::FailStopped(failed) => failed,
            _ => panic!("forked reprepare receipt must not expose a prepared session"),
        };
        assert_eq!(
            failed.reason(),
            MutationCasFailStopReason::InvalidPrepareReceipt
        );
        assert!(matches!(
            failed.reconcile(facts(
                LocalEntryObservation::Present(old),
                LocalEntryObservation::Present(proposed),
            )),
            ReconcileTransition::ResumeExactPreparedPublication(_)
        ));
        assert!(forked_authority.has_pending());

        let denied_authority = authority();
        let continuation = resume_after_unknown_prepare(&denied_authority, "denied");
        denied_authority.queue_fault(TestFault::PrepareDenied);
        let hold = match continuation.reprepare() {
            ReprepareTransition::Hold(hold) => hold,
            _ => panic!("authority denial must be terminal"),
        };
        assert_eq!(hold.reason(), MutationCasFailStopReason::PrepareDenied);
    }

    #[test]
    fn writer_lock_lineage_survives_reprepare_failure_and_rejects_drift() {
        let drift_authority = authority();
        let continuation = resume_after_unknown_prepare(&drift_authority, "lock-drift");
        let old = continuation.session.current().journal_version.clone();
        let proposed = continuation.intent.proposed_journal_version.clone();
        drift_authority.queue_fault(TestFault::PrepareUnknownAfterApply);
        let failed = match continuation.reprepare() {
            ReprepareTransition::FailStopped(failed) => failed,
            _ => panic!("unknown reprepare must retain exact recovery state"),
        };
        assert_eq!(
            failed.reason(),
            MutationCasFailStopReason::PrepareOutcomeUnknown
        );
        let reconcile_count_before = drift_authority
            .transcript()
            .iter()
            .filter(|phase| matches!(phase, TestPhase::Reconcile(_)))
            .count();
        let hold = match failed.reconcile(facts_with_writer_lock(
            digest("writer-lock-b"),
            LocalEntryObservation::Present(old),
            LocalEntryObservation::Present(proposed),
        )) {
            ReconcileTransition::Hold(hold) => hold,
            _ => panic!("writer-lock drift must hold before contacting authority"),
        };
        assert_eq!(
            hold.reason(),
            MutationCasFailStopReason::PrepareOutcomeUnknown
        );
        assert_eq!(
            drift_authority
                .transcript()
                .iter()
                .filter(|phase| matches!(phase, TestPhase::Reconcile(_)))
                .count(),
            reconcile_count_before
        );

        let exact_authority = authority();
        let continuation = resume_after_unknown_prepare(&exact_authority, "lock-exact");
        let old = continuation.session.current().journal_version.clone();
        let proposed = continuation.intent.proposed_journal_version.clone();
        exact_authority.queue_fault(TestFault::PrepareUnknownAfterApply);
        let failed = match continuation.reprepare() {
            ReprepareTransition::FailStopped(failed) => failed,
            _ => panic!("unknown reprepare must fail-stop"),
        };
        assert!(matches!(
            failed.reconcile(facts(
                LocalEntryObservation::Present(old),
                LocalEntryObservation::Present(proposed),
            )),
            ReconcileTransition::ResumeExactPreparedPublication(_)
        ));
    }

    #[test]
    fn staged_and_bind_failure_paths_reject_writer_lock_drift_before_backend() {
        let staged_authority = authority();
        let staged = prepare(
            staged_authority.open().unwrap(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::PersistPreparedTransportAck,
            "staged-lock-drift",
        );
        let old = staged.prepared_head().expected_journal_version.clone();
        let proposed = staged.prepared_head().proposed_journal_version.clone();
        let failed = staged.staged_publication_interrupted();
        let reconcile_count_before = staged_authority
            .transcript()
            .iter()
            .filter(|phase| matches!(phase, TestPhase::Reconcile(_)))
            .count();
        assert!(matches!(
            failed.reconcile(facts_with_writer_lock(
                digest("writer-lock-b"),
                LocalEntryObservation::Present(old),
                LocalEntryObservation::Present(proposed),
            )),
            ReconcileTransition::Hold(_)
        ));
        assert_eq!(
            staged_authority
                .transcript()
                .iter()
                .filter(|phase| matches!(phase, TestPhase::Reconcile(_)))
                .count(),
            reconcile_count_before
        );

        let bind_authority = authority();
        let prepared = prepare(
            bind_authority.open().unwrap(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult,
            "bind-lock-drift",
        );
        let proposed = prepared.prepared_head().proposed_journal_version.clone();
        let mismatched_publication =
            publication_with_writer_lock(&prepared, digest("writer-lock-b"));
        let failed = match prepared.bind_local_publication(mismatched_publication) {
            LocalPublicationTransition::FailStopped(failed) => failed,
            LocalPublicationTransition::Published(_) => {
                panic!("writer-lock mismatch must fail-stop before commit")
            }
        };
        let reconcile_count_before = bind_authority
            .transcript()
            .iter()
            .filter(|phase| matches!(phase, TestPhase::Reconcile(_)))
            .count();
        assert!(matches!(
            failed.reconcile(facts_with_writer_lock(
                digest("writer-lock-b"),
                LocalEntryObservation::Present(proposed),
                LocalEntryObservation::Missing,
            )),
            ReconcileTransition::Hold(_)
        ));
        assert_eq!(
            bind_authority
                .transcript()
                .iter()
                .filter(|phase| matches!(phase, TestPhase::Reconcile(_)))
                .count(),
            reconcile_count_before
        );
    }

    #[test]
    fn initial_publication_writer_lock_is_sticky_across_commit_unknown() {
        let drift_authority = authority();
        let prepared = prepare(
            drift_authority.open().unwrap(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult,
            "initial-lock-drift",
        );
        let proposed = prepared.prepared_head().proposed_journal_version.clone();
        drift_authority.queue_fault(TestFault::CommitUnknownBeforeApply);
        let failed = match publish_with_writer_lock(prepared, digest("writer-lock")).commit() {
            CommitTransition::FailStopped(failed) => failed,
            _ => panic!("commit response must be unknown"),
        };
        let reconcile_count_before = drift_authority
            .transcript()
            .iter()
            .filter(|phase| matches!(phase, TestPhase::Reconcile(_)))
            .count();
        assert!(matches!(
            failed.reconcile(facts_with_writer_lock(
                digest("writer-lock-b"),
                LocalEntryObservation::Present(proposed),
                LocalEntryObservation::Missing,
            )),
            ReconcileTransition::Hold(_)
        ));
        assert_eq!(
            drift_authority
                .transcript()
                .iter()
                .filter(|phase| matches!(phase, TestPhase::Reconcile(_)))
                .count(),
            reconcile_count_before
        );

        let exact_authority = authority();
        let prepared = prepare(
            exact_authority.open().unwrap(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult,
            "initial-lock-exact",
        );
        let proposed = prepared.prepared_head().proposed_journal_version.clone();
        exact_authority.queue_fault(TestFault::CommitUnknownBeforeApply);
        let failed = match publish_with_writer_lock(prepared, digest("writer-lock")).commit() {
            CommitTransition::FailStopped(failed) => failed,
            _ => panic!("commit response must be unknown"),
        };
        assert!(matches!(
            failed.reconcile(facts(
                LocalEntryObservation::Present(proposed),
                LocalEntryObservation::Missing,
            )),
            ReconcileTransition::RetryExactCommit(_)
        ));
    }

    #[test]
    fn same_store_runs_all_four_mutation_kinds_continuously_from_generation_one_to_five() {
        let fresh =
            crate::direct_operation_runtime_authority_store_session::fresh_genesis_for_test(
                "same-store-continuous-mutations",
            )
            .unwrap();
        let lineage_sha256 = fresh.lineage().first_use_lineage_sha256.clone();
        let mut session = activate_same_store(fresh).unwrap();
        assert_eq!(session.current().mutation_generation, 1);

        for (index, kind) in [
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            cas::DirectOperationRuntimeAuthorityMutationKindV1::PersistPreparedTransportAck,
            cas::DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult,
            cas::DirectOperationRuntimeAuthorityMutationKindV1::AcknowledgeOuterV2,
        ]
        .into_iter()
        .enumerate()
        {
            let suffix = format!("same-store-continuous-{index}");
            let prepared = prepare(session, kind, &suffix);
            let proposed = prepared.prepared_head().proposed_journal_version.clone();
            session = commit_and_reopen(publish(prepared));
            assert_eq!(session.current().mutation_generation, index as u64 + 2);
            assert_eq!(session.current().journal_version, proposed);
            assert_eq!(session.lineage.first_use_lineage_sha256, lineage_sha256);
        }

        let transcript = match &session.backend {
            SealedMutationCasBackend::Product(never) => match *never {},
            SealedMutationCasBackend::SameStore(authority) => {
                assert!(!authority.test_has_pending());
                authority.test_mutation_transcript()
            }
            SealedMutationCasBackend::Test(_) => panic!("expected same-store backend"),
        };
        assert_eq!(
            transcript
                .iter()
                .filter(|phase| matches!(phase, TestAuthorityStoreMutationPhase::PrepareApplied(_)))
                .count(),
            4
        );
        assert_eq!(
            transcript
                .iter()
                .filter(|phase| matches!(phase, TestAuthorityStoreMutationPhase::CommitApplied(_)))
                .count(),
            4
        );
        assert_eq!(
            transcript
                .iter()
                .filter(|phase| matches!(phase, TestAuthorityStoreMutationPhase::Observe(_, _)))
                .count(),
            4
        );

        let source = include_str!("direct_operation_runtime_authority_mutation_cas_client.rs");
        assert!(source.contains("SameStore(Box<ActiveAuthorityStoreSession>)"));
        assert!(!source.contains("#[derive(Clone)]\nenum SealedMutationCasBackend"));
        assert!(!source.contains(concat!("fn from_", "lineage")));
        assert!(!source.contains(concat!("fn from_", "snapshot")));
        assert!(!source.contains(concat!("fn into_", "parts")));
    }

    #[test]
    fn same_store_unknown_after_apply_reconciles_pending_then_committed() {
        let fresh =
            crate::direct_operation_runtime_authority_store_session::fresh_genesis_for_test(
                "same-store-unknown-after-apply",
            )
            .unwrap();
        let session = activate_same_store(fresh).unwrap();
        let old = session.current().journal_version.clone();
        let proposed = journal_version(
            "same-store-unknown-proposed-identity",
            "same-store-unknown-proposed-bytes",
        );
        match &session.backend {
            SealedMutationCasBackend::Product(never) => match *never {},
            SealedMutationCasBackend::SameStore(authority) => {
                authority.queue_fault(TestAuthorityStoreFault::MutationPrepareUnknownAfterApply)
            }
            SealedMutationCasBackend::Test(_) => panic!("expected same-store backend"),
        }
        let failed = match send_initial_prepare_for_test(
            session,
            writer_lock_witness(),
            cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            old.clone(),
            proposed.clone(),
            digest("same-store-unknown-mutation-nonce"),
        ) {
            PrepareTransition::FailStopped(failed) => failed,
            _ => panic!("PREPARE response must be unknown after applying"),
        };
        let continuation = match failed.reconcile(facts(
            LocalEntryObservation::Present(old),
            LocalEntryObservation::Present(proposed.clone()),
        )) {
            ReconcileTransition::ResumeExactPreparedPublication(continuation) => continuation,
            _ => panic!("same-store pending head must resume exact publication"),
        };
        let prepared = match continuation.reprepare() {
            ReprepareTransition::Prepared(prepared) => prepared,
            _ => panic!("same-store pending head must accept exact re-PREPARE"),
        };
        match &prepared.session.backend {
            SealedMutationCasBackend::Product(never) => match *never {},
            SealedMutationCasBackend::SameStore(authority) => {
                authority.queue_fault(TestAuthorityStoreFault::MutationCommitUnknownAfterApply)
            }
            SealedMutationCasBackend::Test(_) => panic!("expected same-store backend"),
        }
        let failed = match publish(prepared).commit() {
            CommitTransition::FailStopped(failed) => failed,
            _ => panic!("COMMIT response must be unknown after applying"),
        };
        let terminal = match failed.reconcile(facts(
            LocalEntryObservation::Present(proposed.clone()),
            LocalEntryObservation::Missing,
        )) {
            ReconcileTransition::Committed(terminal) => terminal,
            _ => panic!("same-store successor must reconcile as committed"),
        };
        let session = match terminal.reopen_after_local_cleanup(facts(
            LocalEntryObservation::Present(proposed),
            LocalEntryObservation::Missing,
        )) {
            ObserveTransition::Current(session) => session,
            ObserveTransition::FailStopped(_) => {
                panic!("same-store successor must pass cleanup OBSERVE")
            }
        };
        assert_eq!(session.current().mutation_generation, 2);
        let transcript = match &session.backend {
            SealedMutationCasBackend::Product(never) => match *never {},
            SealedMutationCasBackend::SameStore(authority) => {
                assert!(!authority.test_has_pending());
                authority.test_mutation_transcript()
            }
            SealedMutationCasBackend::Test(_) => panic!("expected same-store backend"),
        };
        assert!(transcript.iter().any(|phase| matches!(
            phase,
            TestAuthorityStoreMutationPhase::Reconcile(
                cas::DirectOperationRuntimeAuthorityReconcileCauseV1::PrepareResponseUnknown
            )
        )));
        assert!(transcript.iter().any(|phase| matches!(
            phase,
            TestAuthorityStoreMutationPhase::Reconcile(
                cas::DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown
            )
        )));
    }

    #[test]
    fn same_store_nonce_overflow_fails_before_observe_rpc() {
        let fresh =
            crate::direct_operation_runtime_authority_store_session::fresh_genesis_for_test(
                "same-store-nonce-overflow",
            )
            .unwrap();
        fresh.set_test_nonce_counter(u64::MAX);
        let session = activate_same_store(fresh).unwrap();
        let current_version = session.current().journal_version.clone();
        let failed = match session.validate_current(current_version) {
            ObserveTransition::Current(_) => panic!("overflow minted an OBSERVE"),
            ObserveTransition::FailStopped(failed) => failed,
        };
        assert_eq!(
            failed.reason(),
            MutationCasFailStopReason::InvalidLocalInput
        );
        match &failed.backend {
            SealedMutationCasBackend::Product(never) => match *never {},
            SealedMutationCasBackend::SameStore(authority) => {
                assert_eq!(authority.test_nonce_counter(), u64::MAX);
                assert!(authority.test_observe_transcript().is_empty());
            }
            SealedMutationCasBackend::Test(_) => panic!("expected same-store backend"),
        }
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn product_surface_is_closed_and_all_activation_flags_remain_false() {
        assert!(cas::SOURCE_DATA_ABI_IMPLEMENTED);
        assert!(!cas::AUTHORITY_BACKEND_PRODUCT_AVAILABLE);
        assert!(!cas::ADAPTER_CLIENT_PRODUCT_WIRED);
        assert!(!cas::DAEMON_LISTENER_PRODUCT_WIRED);
        assert!(!cas::PREPARE_PRODUCT_AVAILABLE);
        assert!(!cas::COMMIT_PRODUCT_AVAILABLE);
        assert!(!cas::OBSERVE_PRODUCT_AVAILABLE);
        assert!(!cas::RECONCILE_PRODUCT_AVAILABLE);
        assert!(!cas::MUTATION_CAS_PRODUCT_AVAILABLE);
        assert!(!cas::CONFERS_FIRST_USE_AUTHORITY);
        assert!(!cas::CONFERS_REPLAY_AUTHORITY);
        assert!(!cas::CONFERS_EFFECT_AUTHORITY);

        let source = include_str!("direct_operation_runtime_authority_mutation_cas_client.rs");
        let product = source
            .split("#[cfg(test)]\nmod test_authority")
            .next()
            .unwrap();
        for forbidden in [
            "std::os::unix::net",
            "UnixListener",
            "UnixStream",
            "TcpStream",
            "std::env",
            "File::open",
            "PathBuf",
            "connect(",
            "bind(",
        ] {
            assert!(
                !product.contains(forbidden),
                "forbidden product source: {forbidden}"
            );
        }
        assert!(product.contains("enum SealedMutationCasBackend"));
        assert!(product.contains("Product(std::convert::Infallible)"));
        assert!(product.contains("#[cfg(test)]\n    Test(TestMutationCasAuthority)"));
        let session_declaration = product
            .find("pub(crate) struct SealedCommittedMutationCasSession")
            .expect("sealed committed session declaration");
        let declaration_prefix =
            &product[session_declaration.saturating_sub(192)..session_declaration];
        assert!(
            !declaration_prefix.contains("#[derive"),
            "the sealed committed session must remain affine and opaque"
        );
        for forbidden in [
            "impl Clone for SealedCommittedMutationCasSession",
            "impl Debug for SealedCommittedMutationCasSession",
            "impl fmt::Debug for SealedCommittedMutationCasSession",
            "impl std::fmt::Debug for SealedCommittedMutationCasSession",
            "impl Default for SealedCommittedMutationCasSession",
            "impl Serialize for SealedCommittedMutationCasSession",
            "impl serde::Serialize for SealedCommittedMutationCasSession",
            "impl Deserialize for SealedCommittedMutationCasSession",
            "impl serde::Deserialize for SealedCommittedMutationCasSession",
            "from_lineage",
            "from_head",
            "from_snapshot",
            "into_parts",
            "new(lineage",
        ] {
            assert!(
                !product.contains(forbidden),
                "sealed session exposes forbidden reconstruction or trait surface: {forbidden}"
            );
        }
        assert!(product.contains("enum SealedDurableStagedMutationProofSource"));
        assert!(product.contains("pub(crate) struct SealedDurableStagedMutationProof"));
        assert!(
            product.contains(
                "#[cfg(test)]\n    fn for_test(plan: &PlannedMutationCasSession) -> Self"
            )
        );
        assert!(!product.contains("fn for_product"));
        assert!(!product.contains("pub(crate) fn for_test"));
        assert!(!product.contains("send_prepare_rpc"));

        let library = include_str!("lib.rs");
        assert_eq!(
            library
                .matches("mod direct_operation_runtime_authority_mutation_cas_client;")
                .count(),
            1
        );
        assert!(
            !library.contains("pub mod direct_operation_runtime_authority_mutation_cas_client;")
        );
        assert!(
            !library
                .contains("pub(crate) mod direct_operation_runtime_authority_mutation_cas_client;")
        );
    }
}
