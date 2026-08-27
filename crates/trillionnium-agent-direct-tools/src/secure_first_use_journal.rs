//! Secure first-use journal publication and one-shot runtime-open foundation.
//!
//! Absence of `operations.json` is never authority to mint an epoch. Staging
//! consumes a sealed external `UNPROVISIONED` capability whose production
//! constructor does not exist. Under one retained OFD writer lease, the exact
//! v4 genesis journal and the mutation-CAS ABI's immutable sentinel v2 are
//! written to distinct temporary inodes, fsynced, read back and made durable
//! in the parent directory. Only then may a canonical first-use Candidate be
//! exposed to a future external PREPARE exchange. The sentinel bytes contain
//! neither the Candidate nor a PREPARED head, so this order is acyclic.
//!
//! The already-staged journal and sentinel are later published with
//! `RENAME_NOREPLACE`, each followed by a directory fsync and exact readback.
//! Runtime authority is returned only after the OS Types Anchor -> Candidate
//! -> PREPARED -> COMMITTED -> result -> Lineage chain validates against those
//! exact local inodes and bytes.
//!
//! A retained non-blocking Linux OFD write lease serializes cooperating
//! ceremonies. Any journal/sentinel partial state or commit-unknown result is
//! a permanent HOLD at this layer. There is no lock fallback, repair, replace,
//! deletion-as-first-use or test initializer fallback. The operation journal
//! can consume the final sealed capability for exactly one first runtime open.
//! That handoff consumes the same store's sealed COMMIT, performs a fresh
//! generation-one OBSERVE, activates an affine mutation-CAS session, and then
//! revalidates local custody a third time before either handle may escape. No
//! product constructor, authority backend, transport, listener, or effect
//! activation exists yet.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
#[cfg(test)]
use std::path::Path;

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_os_types::agent_principal_registry;
use trillionnium_os_types::direct_operation::DirectOperationAdapter;
use trillionnium_os_types::direct_operation_runtime_authority_mutation_cas as mutation_cas;

use crate::direct_operation_runtime_authority_mutation_cas_client::{
    SealedCommittedMutationCasSession, activate_same_store,
};
#[cfg(test)]
use crate::direct_operation_runtime_authority_store_session::TestAuthorityStorePolicy;
#[cfg(test)]
use crate::direct_operation_runtime_authority_store_session::TestReplayAuthorityStore;
use crate::direct_operation_runtime_authority_store_session::{
    CandidateAuthorityStoreSession, FreshlyObservedReplayAuthorityStore,
    PreparedAuthorityStoreSession, PreparedReplayAuthorityStoreSession,
    SealedFirstUseGenesisCommit, UnprovisionedAuthorityStoreSession,
};
use crate::operation_journal::{CanonicalJournalGenesis, OperationJournalError, Sha256Digest};

pub(crate) const SECURE_FIRST_USE_JOURNAL_FOUNDATION_ENABLED: bool = false;

const JOURNAL_NAME: &CStr = c"operations.json";
const SENTINEL_NAME: &CStr = c"operations.first-use-committed.json";
const LOCK_NAME: &CStr = c".operations.first-use.lock";
const JOURNAL_TEMP_NAME: &CStr = c".operations.first-use-genesis.staged";
const SENTINEL_TEMP_NAME: &CStr = c".operations.first-use-immutable-sentinel.staged";
const MAX_SENTINEL_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
}

impl FileIdentity {
    fn from_file(file: &File, expected_size: Option<u64>) -> Result<Self, FirstUseError> {
        let metadata = file.metadata()?;
        let identity = Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.len(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            nlink: metadata.nlink(),
        };
        if !metadata.is_file()
            || identity.ino == 0
            || identity.nlink != 1
            || identity.mode & 0o7777 != 0o600
            || identity.uid != unsafe { libc::geteuid() }
            || identity.gid != unsafe { libc::getegid() }
            || expected_size.is_some_and(|size| identity.size != size)
        {
            return Err(FirstUseError::LocalIdentityAmbiguous);
        }
        Ok(identity)
    }

    fn directory(file: &File) -> Result<Self, FirstUseError> {
        let metadata = file.metadata()?;
        let identity = Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.len(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            nlink: metadata.nlink(),
        };
        if !metadata.is_dir()
            || identity.ino == 0
            || identity.nlink == 0
            || identity.mode & 0o7777 != 0o700
        {
            return Err(FirstUseError::LocalIdentityAmbiguous);
        }
        Ok(identity)
    }
}

/// One-shot proof that an independent rollback-resistant authority currently
/// holds this exact directory/Agent/adapter at UNPROVISIONED.  There is no
/// production constructor in this source batch.
pub(crate) struct VerifiedUnprovisionedAuthority {
    directory: File,
    directory_identity: FileIdentity,
    provider_id: String,
    agent_id: String,
    adapter: DirectOperationAdapter,
    authority_identity_sha256: Sha256Digest,
    authority_store_instance_sha256: Sha256Digest,
    provision_epoch_sha256: Sha256Digest,
    authority_store_session: UnprovisionedAuthorityStoreSession,
}

impl VerifiedUnprovisionedAuthority {
    #[cfg(test)]
    pub(crate) fn for_test(
        directory: &Path,
        agent_id: &str,
        adapter_id: &str,
    ) -> Result<Self, FirstUseError> {
        let principal = agent_principal_registry::from_agent_id(agent_id)
            .ok_or(FirstUseError::AuthorityMismatch)?;
        let adapter = direct_operation_adapter(adapter_id)?;
        if principal != &agent_principal_registry::CODEX_STABLE_PRINCIPAL
            || adapter != DirectOperationAdapter::SystemApi
        {
            return Err(FirstUseError::AuthorityMismatch);
        }
        let file = File::open(directory)?;
        let directory_identity = FileIdentity::directory(&file)?;
        let state_directory_identity_sha256 =
            identity_digest(b"state-directory", directory_identity).to_hex();
        let policy = TestAuthorityStorePolicy::fixed_codex_system_api(
            state_directory_identity_sha256.clone(),
        )
        .map_err(|_| FirstUseError::AuthorityMismatch)?;
        let authority_store_session =
            UnprovisionedAuthorityStoreSession::for_test(policy, &state_directory_identity_sha256)
                .map_err(|_| FirstUseError::AuthorityMismatch)?;
        Ok(Self {
            directory: file,
            directory_identity,
            provider_id: principal.provider_id.to_string(),
            agent_id: agent_id.to_string(),
            adapter,
            authority_identity_sha256: digest_from_hex(
                &authority_store_session.test_authority_identity_sha256(),
            )?,
            authority_store_instance_sha256: digest_from_hex(
                &authority_store_session.test_authority_store_instance_sha256(),
            )?,
            provision_epoch_sha256: digest_from_hex(
                &authority_store_session.test_provision_epoch_sha256(),
            )?,
            authority_store_session,
        })
    }
}

pub(crate) struct StagedFirstUseLocal {
    directory: File,
    directory_identity: FileIdentity,
    lock: File,
    journal_temporary_name: CString,
    journal_temporary_file: File,
    journal_temporary_identity: FileIdentity,
    sentinel_temporary_name: CString,
    sentinel_temporary_file: File,
    sentinel_temporary_identity: FileIdentity,
    sentinel_bytes: Vec<u8>,
    genesis: CanonicalJournalGenesis,
    anchor: mutation_cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    candidate: mutation_cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1,
}

pub(crate) struct StagedFirstUseJournal {
    local: StagedFirstUseLocal,
    authority_store_session: CandidateAuthorityStoreSession,
}

impl std::ops::Deref for StagedFirstUseJournal {
    type Target = StagedFirstUseLocal;

    fn deref(&self) -> &Self::Target {
        &self.local
    }
}

impl StagedFirstUseJournal {
    pub(crate) fn candidate(
        &self,
    ) -> &mutation_cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1 {
        &self.candidate
    }
}

/// External PREPARED response bound to the exact already-fsynced candidate.
/// Production verification/transport is intentionally absent.
pub(crate) struct VerifiedPreparedAuthority {
    local: StagedFirstUseLocal,
    prepared_head: mutation_cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1,
    authority_store_session: PreparedAuthorityStoreSession,
}

impl std::ops::Deref for VerifiedPreparedAuthority {
    type Target = StagedFirstUseLocal;

    fn deref(&self) -> &Self::Target {
        &self.local
    }
}

impl std::ops::DerefMut for VerifiedPreparedAuthority {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.local
    }
}

impl VerifiedPreparedAuthority {
    #[cfg(test)]
    pub(crate) fn for_test(staged: StagedFirstUseJournal) -> Result<Self, FirstUseError> {
        let StagedFirstUseJournal {
            local,
            authority_store_session,
        } = staged;
        let authority_store_session = authority_store_session
            .prepare(&local.anchor, &local.candidate)
            .map_err(|_| FirstUseError::AuthorityMismatch)?;
        let prepared_head = authority_store_session.prepared().clone();
        Ok(Self {
            local,
            prepared_head,
            authority_store_session,
        })
    }
}

pub(crate) struct PublishedFirstUseLocal {
    directory: File,
    directory_identity: FileIdentity,
    lock: File,
    journal_file: File,
    journal_identity: FileIdentity,
    journal_bytes_sha256: Sha256Digest,
    sentinel_file: File,
    sentinel_identity: FileIdentity,
    sentinel_bytes_sha256: Sha256Digest,
    anchor: mutation_cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    candidate: mutation_cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1,
    prepared_head: mutation_cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1,
}

pub(crate) struct LocallyCommittedFirstUseJournal {
    local: PublishedFirstUseLocal,
    authority_store_session: PreparedAuthorityStoreSession,
}

impl std::ops::Deref for LocallyCommittedFirstUseJournal {
    type Target = PublishedFirstUseLocal;

    fn deref(&self) -> &Self::Target {
        &self.local
    }
}

/// External COMMITTED response. It is distinct from PREPARED and binds the
/// exact local sentinel that was published last.
pub(crate) struct VerifiedCommittedAuthority {
    local: PublishedFirstUseLocal,
    lineage: mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    genesis_commit: SealedFirstUseGenesisCommit,
}

impl std::ops::Deref for VerifiedCommittedAuthority {
    type Target = PublishedFirstUseLocal;

    fn deref(&self) -> &Self::Target {
        &self.local
    }
}

impl std::ops::DerefMut for VerifiedCommittedAuthority {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.local
    }
}

impl VerifiedCommittedAuthority {
    #[cfg(test)]
    pub(crate) fn for_test(local: LocallyCommittedFirstUseJournal) -> Result<Self, FirstUseError> {
        let LocallyCommittedFirstUseJournal {
            local,
            authority_store_session,
        } = local;
        let durable_commit_evidence_sha256 = durable_local_commit_evidence_digest(
            local.directory_identity,
            local.journal_identity,
            local.journal_bytes_sha256,
            local.sentinel_identity,
            local.sentinel_bytes_sha256,
        )
        .to_hex();
        let genesis_commit = authority_store_session
            .commit(
                &local.anchor,
                &local.candidate,
                &local.prepared_head,
                durable_commit_evidence_sha256,
            )
            .map_err(|_| FirstUseError::AuthorityMismatch)?;
        let lineage = genesis_commit.lineage().clone();
        Ok(Self {
            local,
            lineage,
            genesis_commit,
        })
    }
}

/// Final sealed capability for exactly one trusted journal open. The
/// capability retains the exact local inodes and external COMMITTED result so
/// a caller cannot detach the authority result from the bytes it approved.
///
/// No production constructor or authority transport exists. The normal
/// product adapter entry point therefore remains an explicit pre-effect HOLD.
pub(crate) struct RetainedFirstUseRuntimeCustody {
    directory: File,
    directory_identity: FileIdentity,
    /// Keep the original ceremony lease and authenticated inode descriptors
    /// alive until this one-shot capability is consumed by the runtime open.
    lock: File,
    journal_file: File,
    journal_identity: FileIdentity,
    journal_bytes_sha256: Sha256Digest,
    sentinel_file: File,
    sentinel_identity: FileIdentity,
    candidate_sha256: Sha256Digest,
    sentinel_bytes_sha256: Sha256Digest,
    directory_identity_sha256: Sha256Digest,
    authority_identity_sha256: Sha256Digest,
    provision_epoch_sha256: Sha256Digest,
    agent_id: String,
    adapter_id: String,
    journal_epoch: String,
    prepared_head_sha256: Sha256Digest,
    committed_head_sha256: Sha256Digest,
    committed_result_binding_sha256: Sha256Digest,
    authority_lineage: mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
}

pub(crate) struct VerifiedFirstUseJournal {
    custody: RetainedFirstUseRuntimeCustody,
    genesis_commit: SealedFirstUseGenesisCommit,
}

impl std::ops::Deref for VerifiedFirstUseJournal {
    type Target = RetainedFirstUseRuntimeCustody;

    fn deref(&self) -> &Self::Target {
        &self.custody
    }
}

#[cfg(test)]
impl std::ops::DerefMut for VerifiedFirstUseJournal {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.custody
    }
}

impl VerifiedFirstUseJournal {
    /// Consume this capability around the actual `OperationJournal` open.
    ///
    /// The closure is deliberately nested between two exact checks of the
    /// retained ceremony lock and retained journal/sentinel descriptors. An
    /// opened journal is dropped inside this method if any fixed name, inode,
    /// bytes, or lock changes during the open; no handle can escape on that
    /// path.
    pub(crate) fn consume_for_runtime_open<T, E>(
        self,
        _consumer: crate::operation_journal::OperationJournalRuntimeOpenConsumerToken,
        trusted_directory: &File,
        agent_id: &str,
        adapter_id: &str,
        open: impl FnOnce(&Self) -> Result<T, E>,
    ) -> Result<Result<(T, SealedCommittedMutationCasSession), E>, FirstUseError> {
        self.validate_for_runtime_open(trusted_directory, agent_id, adapter_id)?;
        inject_custody_race(CustodyRacePoint::PrecheckComplete);
        let opened = match open(&self) {
            Ok(opened) => opened,
            Err(error) => return Ok(Err(error)),
        };
        inject_custody_race(CustodyRacePoint::OpenComplete);
        self.validate_for_runtime_open(trusted_directory, agent_id, adapter_id)?;

        let Self {
            custody,
            genesis_commit,
        } = self;
        let fresh = genesis_commit
            .into_freshly_observed()
            .map_err(|_| FirstUseError::AuthorityMismatch)?;
        inject_custody_race(CustodyRacePoint::FreshObservationComplete);
        let session = activate_same_store(fresh).map_err(|_| FirstUseError::AuthorityMismatch)?;
        inject_custody_race(CustodyRacePoint::ActivationComplete);
        custody.validate_for_runtime_open(trusted_directory, agent_id, adapter_id)?;
        Ok(Ok((opened, session)))
    }

    /// Recheck the exact committed first-use result against the already-open
    /// trusted state directory. This remains private so every runtime consumer
    /// must use the two-phase method above rather than split validation from
    /// the pathname-based journal open.
    fn validate_for_runtime_open(
        &self,
        trusted_directory: &File,
        agent_id: &str,
        adapter_id: &str,
    ) -> Result<(), FirstUseError> {
        self.custody
            .validate_for_runtime_open(trusted_directory, agent_id, adapter_id)
    }

    pub(crate) fn journal_epoch(&self) -> &str {
        &self.custody.journal_epoch
    }

    pub(crate) const fn journal_bytes_sha256(&self) -> Sha256Digest {
        self.custody.journal_bytes_sha256
    }

    pub(crate) const fn journal_file_identity(&self) -> (u64, u64) {
        (
            self.custody.journal_identity.dev,
            self.custody.journal_identity.ino,
        )
    }

    pub(crate) const fn operation_epoch_authority_sha256(&self) -> Sha256Digest {
        self.custody.committed_result_binding_sha256
    }

    fn export_replay_lineage(&self) -> FirstUseReplayLineage {
        self.custody.export_replay_lineage()
    }

    /// Export only the immutable digest lineage required by a future external
    /// replay authority. This is not an activation bearer: constructing a
    /// [`VerifiedJournalReplayAuthority`] still requires an unavailable
    /// rollback-resistant external decision over the exact current journal.
    #[cfg(not(test))]
    #[allow(dead_code)]
    pub(crate) fn replay_lineage(&self) -> FirstUseReplayLineage {
        self.export_replay_lineage()
    }

    /// Test ceremonies provision a store-owned copy once. Replay callers
    /// receive this sealed fixture, not editable historical lineage fields.
    #[cfg(test)]
    pub(crate) fn replay_lineage(&self) -> TestJournalReplayAuthorityStore {
        TestJournalReplayAuthorityStore {
            first_use_lineage: self.export_replay_lineage(),
            authority_store: self.genesis_commit.replay_authority_store_for_test(),
        }
    }
}

impl RetainedFirstUseRuntimeCustody {
    fn validate_for_runtime_open(
        &self,
        trusted_directory: &File,
        agent_id: &str,
        adapter_id: &str,
    ) -> Result<(), FirstUseError> {
        revalidate_lock(&self.directory, &self.lock)?;
        let adapter = direct_operation_adapter(adapter_id)?;
        if FileIdentity::directory(&self.directory)? != self.directory_identity
            || FileIdentity::directory(trusted_directory)? != self.directory_identity
            || self.agent_id != agent_id
            || self.adapter_id != adapter_id
            || identity_digest(b"state-directory", self.directory_identity)
                != self.directory_identity_sha256
            || validate_authority_lineage_for_local(
                &self.authority_lineage,
                self.directory_identity,
                self.journal_identity,
                self.journal_bytes_sha256,
                self.sentinel_identity,
                self.sentinel_bytes_sha256,
                agent_id,
                adapter,
                &self.journal_epoch,
            )
            .is_err()
            || digest_from_hex(&self.authority_lineage.candidate.first_use_candidate_sha256)?
                != self.candidate_sha256
            || digest_from_hex(
                &self
                    .authority_lineage
                    .prepared_head
                    .first_use_prepared_head_sha256,
            )? != self.prepared_head_sha256
            || digest_from_hex(
                &self
                    .authority_lineage
                    .committed_head
                    .first_use_committed_head_sha256,
            )? != self.committed_head_sha256
            || digest_from_hex(
                &self
                    .authority_lineage
                    .committed_result_binding
                    .first_use_committed_result_binding_sha256,
            )? != self.committed_result_binding_sha256
            || digest_from_hex(&self.authority_lineage.anchor.authority_identity_sha256)?
                != self.authority_identity_sha256
            || digest_from_hex(&self.authority_lineage.anchor.provision_epoch_sha256)?
                != self.provision_epoch_sha256
        {
            return Err(FirstUseError::AuthorityMismatch);
        }
        let mut journal = self.journal_file.try_clone()?;
        let journal_bytes = readback_retained_named_file(
            &self.directory,
            JOURNAL_NAME,
            &mut journal,
            self.journal_identity,
            self.journal_bytes_sha256,
        )?;
        CanonicalJournalGenesis::validate_exact(
            &journal_bytes,
            &self.agent_id,
            &self.adapter_id,
            &self.journal_epoch,
            self.journal_bytes_sha256,
        )?;

        let mut sentinel = self.sentinel_file.try_clone()?;
        let sentinel_bytes = readback_retained_named_file(
            &self.directory,
            SENTINEL_NAME,
            &mut sentinel,
            self.sentinel_identity,
            self.sentinel_bytes_sha256,
        )?;
        if self
            .authority_lineage
            .anchor
            .canonical_immutable_sentinel_bytes()
            .map_err(|_| FirstUseError::AuthorityMismatch)?
            != sentinel_bytes
        {
            return Err(FirstUseError::LocalIdentityAmbiguous);
        }
        ensure_named_identity(&self.directory, JOURNAL_NAME, self.journal_identity)?;
        ensure_named_identity(&self.directory, SENTINEL_NAME, self.sentinel_identity)?;
        revalidate_lock(&self.directory, &self.lock)?;
        Ok(())
    }

    fn export_replay_lineage(&self) -> FirstUseReplayLineage {
        FirstUseReplayLineage {
            directory_identity: self.directory_identity,
            genesis_journal_identity: self.journal_identity,
            genesis_journal_bytes_sha256: self.journal_bytes_sha256,
            sentinel_identity: self.sentinel_identity,
            sentinel_bytes_sha256: self.sentinel_bytes_sha256,
            directory_identity_sha256: self.directory_identity_sha256,
            authority_identity_sha256: self.authority_identity_sha256,
            provision_epoch_sha256: self.provision_epoch_sha256,
            candidate_sha256: self.candidate_sha256,
            prepared_head_sha256: self.prepared_head_sha256,
            committed_head_sha256: self.committed_head_sha256,
            committed_result_binding_sha256: self.committed_result_binding_sha256,
            authority_lineage: self.authority_lineage.clone(),
        }
    }
}

/// Immutable first-use ancestry retained by the rollback-resistant authority.
/// These digests do not authorize a replay by themselves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FirstUseReplayLineage {
    directory_identity: FileIdentity,
    genesis_journal_identity: FileIdentity,
    genesis_journal_bytes_sha256: Sha256Digest,
    sentinel_identity: FileIdentity,
    sentinel_bytes_sha256: Sha256Digest,
    directory_identity_sha256: Sha256Digest,
    authority_identity_sha256: Sha256Digest,
    provision_epoch_sha256: Sha256Digest,
    candidate_sha256: Sha256Digest,
    prepared_head_sha256: Sha256Digest,
    committed_head_sha256: Sha256Digest,
    committed_result_binding_sha256: Sha256Digest,
    authority_lineage: mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
}

/// Test-only stand-in for rollback-resistant authority storage. The original
/// first-use ancestry is provisioned from the sealed COMMITTED capability and
/// retained inside the fixture; replay callers provide only current local
/// facts and cannot substitute a recomputed historical lineage.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestJournalReplayAuthorityStore {
    first_use_lineage: FirstUseReplayLineage,
    authority_store: TestReplayAuthorityStore,
}

/// One-shot external authority for reopening an already-provisioned journal.
///
/// The authority binds the exact current journal inode and bytes to the
/// immutable first-use sentinel ancestry plus an external monotonic high-water
/// and replay head. Local journal validity, a matching epoch, or a caller-
/// supplied counter can never construct this type. Product transport and
/// verification constructors remain deliberately absent.
#[allow(dead_code)]
pub(crate) struct VerifiedJournalReplayAuthority {
    directory: File,
    directory_identity: FileIdentity,
    /// Exact files authenticated when the external replay decision was
    /// constructed. Runtime consumption reuses these descriptors and never
    /// reopens either fixed name.
    journal_file: File,
    current_journal_identity: FileIdentity,
    current_journal_bytes_sha256: Sha256Digest,
    sentinel_file: File,
    sentinel_identity: FileIdentity,
    sentinel_bytes_sha256: Sha256Digest,
    agent_id: String,
    adapter_id: String,
    journal_epoch: String,
    first_use_lineage: FirstUseReplayLineage,
    replay_authority_identity_sha256: Sha256Digest,
    replay_high_water: u64,
    replay_head_sha256: Sha256Digest,
    replay_result_binding_sha256: Sha256Digest,
    authority_committed_head_sha256: Sha256Digest,
    authority_snapshot_sha256: Sha256Digest,
    authority_mutation_generation: u64,
    authority_store: Option<PreparedReplayAuthorityStoreSession>,
}

impl VerifiedJournalReplayAuthority {
    /// Test-only stand-in for a daemon-to-adapter sealed external replay
    /// decision. It observes exact local bytes against store-owned immutable
    /// first-use history and a non-zero external high-water.
    #[cfg(test)]
    pub(crate) fn for_test(
        directory: &Path,
        agent_id: &str,
        adapter_id: &str,
        journal_epoch: &str,
        authority_store: TestJournalReplayAuthorityStore,
        replay_high_water: u64,
    ) -> Result<Self, FirstUseError> {
        let TestJournalReplayAuthorityStore {
            first_use_lineage,
            authority_store,
        } = authority_store;
        if replay_high_water == 0 || !valid_journal_epoch(journal_epoch) {
            return Err(FirstUseError::AuthorityMismatch);
        }
        let authority_store = authority_store
            .prepare()
            .map_err(|_| FirstUseError::AuthorityMismatch)?;
        if authority_store.lineage() != &first_use_lineage.authority_lineage {
            return Err(FirstUseError::AuthorityMismatch);
        }
        let authority_committed_head_sha256 =
            digest_from_hex(&authority_store.committed_head().committed_head_sha256)?;
        let authority_snapshot_sha256 =
            digest_from_hex(&authority_store.snapshot().snapshot_sha256)?;
        let authority_mutation_generation = authority_store.committed_head().mutation_generation;
        let adapter = direct_operation_adapter(adapter_id)?;
        let directory = File::open(directory)?;
        let directory_identity = FileIdentity::directory(&directory)?;
        if !same_directory_custody(directory_identity, first_use_lineage.directory_identity)
            || identity_digest(b"state-directory", first_use_lineage.directory_identity)
                != first_use_lineage.directory_identity_sha256
            || validate_authority_lineage_for_local(
                &first_use_lineage.authority_lineage,
                first_use_lineage.directory_identity,
                first_use_lineage.genesis_journal_identity,
                first_use_lineage.genesis_journal_bytes_sha256,
                first_use_lineage.sentinel_identity,
                first_use_lineage.sentinel_bytes_sha256,
                agent_id,
                adapter,
                journal_epoch,
            )
            .is_err()
        {
            return Err(FirstUseError::AuthorityMismatch);
        }

        let mut journal = open_private_file(&directory, JOURNAL_NAME)?;
        let current_journal_identity = FileIdentity::from_file(&journal, None)?;
        if current_journal_identity.size == 0
            || current_journal_identity.size > crate::operation_journal::MAX_JOURNAL_BYTES as u64
        {
            return Err(FirstUseError::LocalIdentityAmbiguous);
        }
        ensure_named_identity(&directory, JOURNAL_NAME, current_journal_identity)?;
        let current_journal_bytes =
            read_exact_fd(&mut journal, current_journal_identity.size as usize)?;
        let current_journal_bytes_sha256 = Sha256Digest::of_bytes(&current_journal_bytes);
        let _current_journal_bytes = readback_retained_named_file(
            &directory,
            JOURNAL_NAME,
            &mut journal,
            current_journal_identity,
            current_journal_bytes_sha256,
        )?;

        let mut sentinel = open_private_file(&directory, SENTINEL_NAME)?;
        let sentinel_identity = FileIdentity::from_file(&sentinel, None)?;
        if sentinel_identity.size == 0 || sentinel_identity.size > MAX_SENTINEL_BYTES as u64 {
            return Err(FirstUseError::LocalIdentityAmbiguous);
        }
        ensure_named_identity(&directory, SENTINEL_NAME, sentinel_identity)?;
        let sentinel_bytes = read_exact_fd(&mut sentinel, sentinel_identity.size as usize)?;
        let sentinel_bytes_sha256 = Sha256Digest::of_bytes(&sentinel_bytes);
        let sentinel_bytes = readback_retained_named_file(
            &directory,
            SENTINEL_NAME,
            &mut sentinel,
            sentinel_identity,
            sentinel_bytes_sha256,
        )?;
        validate_replay_sentinel(
            &sentinel_bytes,
            sentinel_identity,
            sentinel_bytes_sha256,
            directory_identity,
            agent_id,
            adapter_id,
            journal_epoch,
            &first_use_lineage,
        )?;
        ensure_named_identity(&directory, JOURNAL_NAME, current_journal_identity)?;
        ensure_named_identity(&directory, SENTINEL_NAME, sentinel_identity)?;

        let replay_authority_identity_sha256 =
            Sha256Digest::of_bytes(b"test-journal-replay-high-water-authority");
        let replay_head_sha256 = replay_head_digest(
            first_use_lineage.committed_head_sha256,
            current_journal_bytes_sha256,
            replay_authority_identity_sha256,
            replay_high_water,
            authority_committed_head_sha256,
            authority_snapshot_sha256,
            authority_mutation_generation,
        );
        let replay_result_binding_sha256 = replay_result_binding_digest(
            agent_id,
            adapter_id,
            journal_epoch,
            identity_digest(b"state-directory", directory_identity),
            identity_digest(b"current-journal", current_journal_identity),
            current_journal_bytes_sha256,
            sentinel_bytes_sha256,
            first_use_lineage.committed_result_binding_sha256,
            replay_authority_identity_sha256,
            replay_high_water,
            replay_head_sha256,
            authority_committed_head_sha256,
            authority_snapshot_sha256,
            authority_mutation_generation,
        );
        Ok(Self {
            directory,
            directory_identity,
            journal_file: journal,
            current_journal_identity,
            current_journal_bytes_sha256,
            sentinel_file: sentinel,
            sentinel_identity,
            sentinel_bytes_sha256,
            agent_id: agent_id.to_string(),
            adapter_id: adapter_id.to_string(),
            journal_epoch: journal_epoch.to_string(),
            first_use_lineage,
            replay_authority_identity_sha256,
            replay_high_water,
            replay_head_sha256,
            replay_result_binding_sha256,
            authority_committed_head_sha256,
            authority_snapshot_sha256,
            authority_mutation_generation,
            authority_store: Some(authority_store),
        })
    }

    /// Consume the replay decision around the actual pathname-based journal
    /// open. The exact descriptors authenticated by the authority constructor
    /// remain alive through both checks, so replacement during the open cannot
    /// yield a live handle.
    pub(crate) fn consume_for_runtime_open<T>(
        mut self,
        _consumer: crate::operation_journal::OperationJournalRuntimeOpenConsumerToken,
        trusted_directory: &File,
        agent_id: &str,
        adapter_id: &str,
        open: impl FnOnce(&Self) -> T,
    ) -> Result<(T, FreshlyObservedReplayAuthorityStore), FirstUseError> {
        self.validate_for_runtime_open(trusted_directory, agent_id, adapter_id)?;
        inject_custody_race(CustodyRacePoint::PrecheckComplete);
        let opened = open(&self);
        inject_custody_race(CustodyRacePoint::OpenComplete);
        self.validate_for_runtime_open(trusted_directory, agent_id, adapter_id)?;
        let authority_store = self
            .authority_store
            .take()
            .ok_or(FirstUseError::AuthorityMismatch)?
            .into_freshly_observed()
            .map_err(|_| FirstUseError::AuthorityMismatch)?;
        if digest_from_hex(&authority_store.committed_head().committed_head_sha256)?
            != self.authority_committed_head_sha256
            || digest_from_hex(&authority_store.snapshot().snapshot_sha256)?
                != self.authority_snapshot_sha256
            || authority_store.committed_head().mutation_generation
                != self.authority_mutation_generation
        {
            return Err(FirstUseError::AuthorityMismatch);
        }
        self.validate_for_runtime_open(trusted_directory, agent_id, adapter_id)?;
        Ok((opened, authority_store))
    }

    fn validate_for_runtime_open(
        &self,
        trusted_directory: &File,
        agent_id: &str,
        adapter_id: &str,
    ) -> Result<(), FirstUseError> {
        let observed_directory = FileIdentity::directory(&self.directory)?;
        let trusted_directory = FileIdentity::directory(trusted_directory)?;
        let adapter = direct_operation_adapter(adapter_id)?;
        if !same_directory_custody(observed_directory, self.directory_identity)
            || !same_directory_custody(trusted_directory, self.directory_identity)
            || self.agent_id != agent_id
            || self.adapter_id != adapter_id
            || !valid_journal_epoch(&self.journal_epoch)
            || self.replay_high_water == 0
            || !same_directory_custody(
                self.directory_identity,
                self.first_use_lineage.directory_identity,
            )
            || identity_digest(
                b"state-directory",
                self.first_use_lineage.directory_identity,
            ) != self.first_use_lineage.directory_identity_sha256
            || validate_authority_lineage_for_local(
                &self.first_use_lineage.authority_lineage,
                self.first_use_lineage.directory_identity,
                self.first_use_lineage.genesis_journal_identity,
                self.first_use_lineage.genesis_journal_bytes_sha256,
                self.first_use_lineage.sentinel_identity,
                self.first_use_lineage.sentinel_bytes_sha256,
                agent_id,
                adapter,
                &self.journal_epoch,
            )
            .is_err()
            || replay_head_digest(
                self.first_use_lineage.committed_head_sha256,
                self.current_journal_bytes_sha256,
                self.replay_authority_identity_sha256,
                self.replay_high_water,
                self.authority_committed_head_sha256,
                self.authority_snapshot_sha256,
                self.authority_mutation_generation,
            ) != self.replay_head_sha256
            || replay_result_binding_digest(
                &self.agent_id,
                &self.adapter_id,
                &self.journal_epoch,
                identity_digest(b"state-directory", self.directory_identity),
                identity_digest(b"current-journal", self.current_journal_identity),
                self.current_journal_bytes_sha256,
                self.sentinel_bytes_sha256,
                self.first_use_lineage.committed_result_binding_sha256,
                self.replay_authority_identity_sha256,
                self.replay_high_water,
                self.replay_head_sha256,
                self.authority_committed_head_sha256,
                self.authority_snapshot_sha256,
                self.authority_mutation_generation,
            ) != self.replay_result_binding_sha256
            || self.authority_store.as_ref().is_some_and(|authority| {
                authority.committed_head().committed_head_sha256
                    != self.authority_committed_head_sha256.to_hex()
                    || authority.snapshot().snapshot_sha256
                        != self.authority_snapshot_sha256.to_hex()
                    || authority.committed_head().mutation_generation
                        != self.authority_mutation_generation
            })
        {
            return Err(FirstUseError::AuthorityMismatch);
        }

        let mut journal = self.journal_file.try_clone()?;
        let _journal_bytes = readback_retained_named_file(
            &self.directory,
            JOURNAL_NAME,
            &mut journal,
            self.current_journal_identity,
            self.current_journal_bytes_sha256,
        )?;
        let mut sentinel = self.sentinel_file.try_clone()?;
        let sentinel_bytes = readback_retained_named_file(
            &self.directory,
            SENTINEL_NAME,
            &mut sentinel,
            self.sentinel_identity,
            self.sentinel_bytes_sha256,
        )?;
        validate_replay_sentinel(
            &sentinel_bytes,
            self.sentinel_identity,
            self.sentinel_bytes_sha256,
            self.directory_identity,
            &self.agent_id,
            &self.adapter_id,
            &self.journal_epoch,
            &self.first_use_lineage,
        )?;
        ensure_named_identity(&self.directory, JOURNAL_NAME, self.current_journal_identity)?;
        ensure_named_identity(&self.directory, SENTINEL_NAME, self.sentinel_identity)
    }

    pub(crate) fn journal_epoch(&self) -> &str {
        &self.journal_epoch
    }

    pub(crate) const fn journal_bytes_sha256(&self) -> Sha256Digest {
        self.current_journal_bytes_sha256
    }

    pub(crate) const fn journal_file_identity(&self) -> (u64, u64) {
        (
            self.current_journal_identity.dev,
            self.current_journal_identity.ino,
        )
    }

    pub(crate) const fn operation_epoch_authority_sha256(&self) -> Sha256Digest {
        self.first_use_lineage.committed_result_binding_sha256
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_replay_sentinel(
    sentinel_bytes: &[u8],
    sentinel_identity: FileIdentity,
    sentinel_bytes_sha256: Sha256Digest,
    directory_identity: FileIdentity,
    agent_id: &str,
    adapter_id: &str,
    journal_epoch: &str,
    lineage: &FirstUseReplayLineage,
) -> Result<(), FirstUseError> {
    let adapter = direct_operation_adapter(adapter_id)?;
    if sentinel_identity != lineage.sentinel_identity
        || sentinel_bytes_sha256 != lineage.sentinel_bytes_sha256
        || !same_directory_custody(directory_identity, lineage.directory_identity)
        || validate_authority_lineage_for_local(
            &lineage.authority_lineage,
            lineage.directory_identity,
            lineage.genesis_journal_identity,
            lineage.genesis_journal_bytes_sha256,
            lineage.sentinel_identity,
            lineage.sentinel_bytes_sha256,
            agent_id,
            adapter,
            journal_epoch,
        )
        .is_err()
        || digest_from_hex(
            &lineage
                .authority_lineage
                .candidate
                .first_use_candidate_sha256,
        )? != lineage.candidate_sha256
        || digest_from_hex(
            &lineage
                .authority_lineage
                .prepared_head
                .first_use_prepared_head_sha256,
        )? != lineage.prepared_head_sha256
        || digest_from_hex(
            &lineage
                .authority_lineage
                .committed_head
                .first_use_committed_head_sha256,
        )? != lineage.committed_head_sha256
        || digest_from_hex(
            &lineage
                .authority_lineage
                .committed_result_binding
                .first_use_committed_result_binding_sha256,
        )? != lineage.committed_result_binding_sha256
        || digest_from_hex(
            &lineage
                .authority_lineage
                .anchor
                .state_directory_identity_sha256,
        )? != lineage.directory_identity_sha256
        || digest_from_hex(&lineage.authority_lineage.anchor.authority_identity_sha256)?
            != lineage.authority_identity_sha256
        || digest_from_hex(&lineage.authority_lineage.anchor.provision_epoch_sha256)?
            != lineage.provision_epoch_sha256
    {
        return Err(FirstUseError::AuthorityMismatch);
    }
    if lineage
        .authority_lineage
        .anchor
        .canonical_immutable_sentinel_bytes()
        .map_err(|_| FirstUseError::AuthorityMismatch)?
        != sentinel_bytes
    {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    Ok(())
}

fn replay_head_digest(
    first_use_committed_head: Sha256Digest,
    current_journal: Sha256Digest,
    replay_authority: Sha256Digest,
    replay_high_water: u64,
    authority_committed_head: Sha256Digest,
    authority_snapshot: Sha256Digest,
    authority_mutation_generation: u64,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.agent-operation-journal-replay-head.v1\0");
    for value in [
        first_use_committed_head,
        current_journal,
        replay_authority,
        authority_committed_head,
        authority_snapshot,
    ] {
        hasher.update(value.as_bytes());
    }
    hasher.update(replay_high_water.to_be_bytes());
    hasher.update(authority_mutation_generation.to_be_bytes());
    Sha256Digest::of_bytes(&hasher.finalize())
}

#[allow(clippy::too_many_arguments)]
fn replay_result_binding_digest(
    agent_id: &str,
    adapter_id: &str,
    journal_epoch: &str,
    directory_identity: Sha256Digest,
    current_journal_identity: Sha256Digest,
    current_journal: Sha256Digest,
    sentinel: Sha256Digest,
    first_use_committed_result: Sha256Digest,
    replay_authority: Sha256Digest,
    replay_high_water: u64,
    replay_head: Sha256Digest,
    authority_committed_head: Sha256Digest,
    authority_snapshot: Sha256Digest,
    authority_mutation_generation: u64,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.agent-operation-journal-replay-result.v1\0");
    for value in [
        agent_id.as_bytes(),
        adapter_id.as_bytes(),
        journal_epoch.as_bytes(),
    ] {
        hasher.update((value.len() as u32).to_be_bytes());
        hasher.update(value);
    }
    for value in [
        directory_identity,
        current_journal_identity,
        current_journal,
        sentinel,
        first_use_committed_result,
        replay_authority,
        authority_committed_head,
        authority_snapshot,
    ] {
        hasher.update(value.as_bytes());
    }
    hasher.update(replay_high_water.to_be_bytes());
    hasher.update(authority_mutation_generation.to_be_bytes());
    hasher.update(replay_head.as_bytes());
    Sha256Digest::of_bytes(&hasher.finalize())
}

fn same_directory_custody(left: FileIdentity, right: FileIdentity) -> bool {
    left.dev == right.dev
        && left.ino == right.ino
        && left.mode == right.mode
        && left.uid == right.uid
        && left.gid == right.gid
        && left.nlink == right.nlink
}

fn valid_journal_epoch(value: &str) -> bool {
    value.len() == 32
        && value != "00000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Error)]
pub(crate) enum FirstUseError {
    #[error("first-use local state is present, partial, replaced, or ambiguous")]
    LocalIdentityAmbiguous,
    #[error("first-use external authority does not bind the exact candidate")]
    AuthorityMismatch,
    #[error("first-use local publication outcome is commit-unknown")]
    LocalCommitUnknown,
    #[error("first-use journal encoding is invalid: {0}")]
    Journal(#[from] OperationJournalError),
    #[error("first-use journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    JournalTempFsync,
    SentinelTempFsync,
    PreStageDirectoryFsync,
    JournalRename,
    JournalDirectoryFsync,
    SentinelRename,
    SentinelDirectoryFsync,
}

#[cfg(test)]
thread_local! {
    static NEXT_FAULT: std::cell::Cell<Option<FaultPoint>> = const { std::cell::Cell::new(None) };
}

/// Stage and durably read back exact genesis bytes. The sealed UNPROVISIONED
/// authority is consumed here; local absence alone cannot call this function.
pub(crate) fn stage_secure_first_use(
    authority: VerifiedUnprovisionedAuthority,
) -> Result<StagedFirstUseJournal, FirstUseError> {
    let VerifiedUnprovisionedAuthority {
        directory,
        directory_identity,
        provider_id,
        agent_id,
        adapter,
        authority_identity_sha256,
        authority_store_instance_sha256,
        provision_epoch_sha256,
        authority_store_session,
    } = authority;
    if FileIdentity::directory(&directory)? != directory_identity
        || directory_identity.uid != unsafe { libc::geteuid() }
        || directory_identity.gid != unsafe { libc::getegid() }
        || agent_principal_registry::from_provider_agent_pair(&provider_id, &agent_id).is_none()
    {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    require_absent(&directory, JOURNAL_NAME)?;
    require_absent(&directory, SENTINEL_NAME)?;
    let lock = acquire_lock(&directory)?;
    require_absent(&directory, JOURNAL_NAME)?;
    require_absent(&directory, SENTINEL_NAME)?;

    let adapter_id = adapter.adapter_id();
    let genesis = CanonicalJournalGenesis::new(&agent_id, adapter_id)?;
    let (journal_temporary_name, mut journal_temporary_file) =
        create_fixed_temp(&directory, JOURNAL_TEMP_NAME)?;
    journal_temporary_file.write_all(genesis.bytes())?;
    inject_fault(FaultPoint::JournalTempFsync)?;
    journal_temporary_file.sync_all()?;
    let journal_temporary_identity =
        FileIdentity::from_file(&journal_temporary_file, Some(genesis.bytes().len() as u64))?;
    ensure_named_identity(
        &directory,
        &journal_temporary_name,
        journal_temporary_identity,
    )?;
    if read_exact_fd(&mut journal_temporary_file, genesis.bytes().len())? != genesis.bytes() {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }

    let directory_identity_sha256 = identity_digest(b"state-directory", directory_identity);
    let genesis_journal_version =
        canonical_journal_version(journal_temporary_identity, genesis.bytes_sha256())?;
    let mut anchor = mutation_cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1 {
        schema: mutation_cas::FIRST_USE_ANCHOR_V1_SCHEMA.to_string(),
        protocol: mutation_cas::PROTOCOL.to_string(),
        authority_identity_sha256: authority_identity_sha256.to_hex(),
        authority_store_instance_sha256: authority_store_instance_sha256.to_hex(),
        provision_epoch_sha256: provision_epoch_sha256.to_hex(),
        provider_id,
        agent_id,
        adapter,
        journal_epoch: genesis.epoch().to_string(),
        state_directory_identity_sha256: directory_identity_sha256.to_hex(),
        genesis_journal_version,
        immutable_sentinel_schema: mutation_cas::FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA.to_string(),
        immutable_sentinel_embeds_prepared_head: false,
        // Neither field participates in the immutable sentinel encoding.
        // They are filled only after that sentinel has its final inode.
        sentinel_identity_sha256: String::new(),
        sentinel_bytes_sha256: String::new(),
        first_use_anchor_sha256: String::new(),
    };
    let sentinel_bytes = anchor
        .canonical_immutable_sentinel_bytes()
        .map_err(|_| FirstUseError::AuthorityMismatch)?;
    if sentinel_bytes.is_empty() || sentinel_bytes.len() > MAX_SENTINEL_BYTES {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    let (sentinel_temporary_name, mut sentinel_temporary_file) =
        create_fixed_temp(&directory, SENTINEL_TEMP_NAME)?;
    sentinel_temporary_file.write_all(&sentinel_bytes)?;
    inject_fault(FaultPoint::SentinelTempFsync)?;
    sentinel_temporary_file.sync_all()?;
    let sentinel_temporary_identity =
        FileIdentity::from_file(&sentinel_temporary_file, Some(sentinel_bytes.len() as u64))?;
    ensure_named_identity(
        &directory,
        &sentinel_temporary_name,
        sentinel_temporary_identity,
    )?;
    if read_exact_fd(&mut sentinel_temporary_file, sentinel_bytes.len())? != sentinel_bytes {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }

    anchor.sentinel_identity_sha256 =
        identity_digest(b"first-use-immutable-sentinel", sentinel_temporary_identity).to_hex();
    anchor.sentinel_bytes_sha256 = Sha256Digest::of_bytes(&sentinel_bytes).to_hex();
    anchor.first_use_anchor_sha256 = anchor
        .canonical_sha256()
        .map_err(|_| FirstUseError::AuthorityMismatch)?;
    anchor
        .validate()
        .map_err(|_| FirstUseError::AuthorityMismatch)?;

    // One parent-directory fsync covers both already-fsynced temporary
    // directory entries. Candidate construction happens strictly afterwards.
    inject_fault(FaultPoint::PreStageDirectoryFsync)?;
    directory.sync_all()?;
    revalidate_lock(&directory, &lock)?;
    if FileIdentity::directory(&directory)? != directory_identity {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    ensure_named_identity(
        &directory,
        &journal_temporary_name,
        journal_temporary_identity,
    )?;
    ensure_named_identity(
        &directory,
        &sentinel_temporary_name,
        sentinel_temporary_identity,
    )?;
    require_absent(&directory, JOURNAL_NAME)?;
    require_absent(&directory, SENTINEL_NAME)?;

    let authority_store_session = authority_store_session
        .issue_candidate(anchor.clone())
        .map_err(|_| FirstUseError::AuthorityMismatch)?;
    let candidate = authority_store_session.candidate().clone();

    Ok(StagedFirstUseJournal {
        local: StagedFirstUseLocal {
            directory,
            directory_identity,
            lock,
            journal_temporary_name,
            journal_temporary_file,
            journal_temporary_identity,
            sentinel_temporary_name,
            sentinel_temporary_file,
            sentinel_temporary_identity,
            sentinel_bytes,
            genesis,
            anchor,
            candidate,
        },
        authority_store_session,
    })
}

/// Publish the two already-durable temporary inodes without rebuilding either
/// candidate. Any failure after the first rename is commit-unknown.
pub(crate) fn publish_prepared_first_use(
    staged: VerifiedPreparedAuthority,
) -> Result<LocallyCommittedFirstUseJournal, FirstUseError> {
    let VerifiedPreparedAuthority {
        mut local,
        prepared_head,
        authority_store_session,
    } = staged;
    if local.anchor.validate().is_err()
        || local.candidate.validate_for(&local.anchor).is_err()
        || prepared_head
            .validate_for(&local.anchor, &local.candidate)
            .is_err()
    {
        return Err(FirstUseError::AuthorityMismatch);
    }
    if FileIdentity::directory(&local.directory)? != local.directory_identity
        || FileIdentity::from_file(
            &local.journal_temporary_file,
            Some(local.genesis.bytes().len() as u64),
        )? != local.journal_temporary_identity
        || FileIdentity::from_file(
            &local.sentinel_temporary_file,
            Some(local.sentinel_bytes.len() as u64),
        )? != local.sentinel_temporary_identity
        || read_exact_fd(
            &mut local.journal_temporary_file,
            local.genesis.bytes().len(),
        )? != local.genesis.bytes()
        || read_exact_fd(
            &mut local.sentinel_temporary_file,
            local.sentinel_bytes.len(),
        )? != local.sentinel_bytes
        || local
            .anchor
            .canonical_immutable_sentinel_bytes()
            .map_err(|_| FirstUseError::AuthorityMismatch)?
            != local.sentinel_bytes
    {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    revalidate_lock(&local.directory, &local.lock)?;
    ensure_named_identity(
        &local.directory,
        &local.journal_temporary_name,
        local.journal_temporary_identity,
    )?;
    ensure_named_identity(
        &local.directory,
        &local.sentinel_temporary_name,
        local.sentinel_temporary_identity,
    )?;
    require_absent(&local.directory, JOURNAL_NAME)?;
    require_absent(&local.directory, SENTINEL_NAME)?;

    inject_fault(FaultPoint::JournalRename)?;
    rename_noreplace(
        &local.directory,
        &local.journal_temporary_name,
        JOURNAL_NAME,
    )
    .map_err(|_| FirstUseError::LocalCommitUnknown)?;
    finish_prepared_publication(local, prepared_head, authority_store_session)
        .map_err(|_| FirstUseError::LocalCommitUnknown)
}

/// Everything in this helper runs after the journal rename may have committed.
/// Its concrete error must never invite first-use retry; the caller collapses
/// every outcome other than a complete local commit to `LocalCommitUnknown`.
fn finish_prepared_publication(
    mut staged: StagedFirstUseLocal,
    prepared_head: mutation_cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1,
    authority_store_session: PreparedAuthorityStoreSession,
) -> Result<LocallyCommittedFirstUseJournal, FirstUseError> {
    inject_fault(FaultPoint::JournalDirectoryFsync)?;
    staged.directory.sync_all()?;
    revalidate_lock(&staged.directory, &staged.lock)?;
    let journal_identity = staged.journal_temporary_identity;
    let journal_bytes = readback_retained_named_file(
        &staged.directory,
        JOURNAL_NAME,
        &mut staged.journal_temporary_file,
        journal_identity,
        staged.genesis.bytes_sha256(),
    )?;
    if journal_bytes != staged.genesis.bytes() {
        return Err(FirstUseError::LocalCommitUnknown);
    }
    ensure_named_identity(
        &staged.directory,
        &staged.sentinel_temporary_name,
        staged.sentinel_temporary_identity,
    )?;
    if read_exact_fd(
        &mut staged.sentinel_temporary_file,
        staged.sentinel_bytes.len(),
    )? != staged.sentinel_bytes
    {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    ensure_named_identity(&staged.directory, JOURNAL_NAME, journal_identity)?;
    revalidate_lock(&staged.directory, &staged.lock)?;
    require_absent(&staged.directory, SENTINEL_NAME)?;
    inject_fault(FaultPoint::SentinelRename)?;
    rename_noreplace(
        &staged.directory,
        &staged.sentinel_temporary_name,
        SENTINEL_NAME,
    )?;
    inject_fault(FaultPoint::SentinelDirectoryFsync)?;
    staged.directory.sync_all()?;
    revalidate_lock(&staged.directory, &staged.lock)?;
    let sentinel_identity = staged.sentinel_temporary_identity;
    let sentinel_bytes_sha256 = Sha256Digest::of_bytes(&staged.sentinel_bytes);
    let sentinel_bytes = readback_retained_named_file(
        &staged.directory,
        SENTINEL_NAME,
        &mut staged.sentinel_temporary_file,
        sentinel_identity,
        sentinel_bytes_sha256,
    )?;
    if sentinel_bytes != staged.sentinel_bytes {
        return Err(FirstUseError::LocalCommitUnknown);
    }
    ensure_named_identity(&staged.directory, JOURNAL_NAME, journal_identity)?;
    ensure_named_identity(&staged.directory, SENTINEL_NAME, sentinel_identity)?;
    revalidate_lock(&staged.directory, &staged.lock)?;
    Ok(LocallyCommittedFirstUseJournal {
        local: PublishedFirstUseLocal {
            directory: staged.directory,
            directory_identity: staged.directory_identity,
            lock: staged.lock,
            journal_file: staged.journal_temporary_file,
            journal_identity,
            journal_bytes_sha256: staged.genesis.bytes_sha256(),
            sentinel_file: staged.sentinel_temporary_file,
            sentinel_identity,
            sentinel_bytes_sha256,
            anchor: staged.anchor,
            candidate: staged.candidate,
            prepared_head,
        },
        authority_store_session,
    })
}

/// Consume the external COMMITTED response and recheck both published local
/// inodes before returning a sealed runtime capability.
pub(crate) fn finalize_committed_first_use(
    committed: VerifiedCommittedAuthority,
) -> Result<VerifiedFirstUseJournal, FirstUseError> {
    let VerifiedCommittedAuthority {
        mut local,
        lineage,
        genesis_commit,
    } = committed;
    // The exact staged OFD lease must still be named before any external
    // COMMITTED result or local pathname is trusted.
    revalidate_lock(&local.directory, &local.lock)?;
    if FileIdentity::directory(&local.directory)? != local.directory_identity {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    let journal_bytes = readback_retained_named_file(
        &local.directory,
        JOURNAL_NAME,
        &mut local.journal_file,
        local.journal_identity,
        local.journal_bytes_sha256,
    )?;
    CanonicalJournalGenesis::validate_exact(
        &journal_bytes,
        &local.anchor.agent_id,
        local.anchor.adapter.adapter_id(),
        &local.anchor.journal_epoch,
        local.journal_bytes_sha256,
    )?;
    let sentinel_bytes = readback_retained_named_file(
        &local.directory,
        SENTINEL_NAME,
        &mut local.sentinel_file,
        local.sentinel_identity,
        local.sentinel_bytes_sha256,
    )?;
    if local
        .anchor
        .canonical_immutable_sentinel_bytes()
        .map_err(|_| FirstUseError::AuthorityMismatch)?
        != sentinel_bytes
    {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    ensure_named_identity(&local.directory, JOURNAL_NAME, local.journal_identity)?;
    ensure_named_identity(&local.directory, SENTINEL_NAME, local.sentinel_identity)?;
    revalidate_lock(&local.directory, &local.lock)?;

    if lineage.validate().is_err()
        || genesis_commit.lineage() != &lineage
        || lineage.anchor != local.anchor
        || lineage.candidate != local.candidate
        || lineage.prepared_head != local.prepared_head
        || lineage
            .committed_head
            .validate_for(&local.anchor, &local.candidate, &local.prepared_head)
            .is_err()
        || lineage
            .committed_result_binding
            .validate_for(
                &local.anchor,
                &local.candidate,
                &local.prepared_head,
                &lineage.committed_head,
            )
            .is_err()
        || validate_authority_lineage_for_local(
            &lineage,
            local.directory_identity,
            local.journal_identity,
            local.journal_bytes_sha256,
            local.sentinel_identity,
            local.sentinel_bytes_sha256,
            &local.anchor.agent_id,
            local.anchor.adapter,
            &local.anchor.journal_epoch,
        )
        .is_err()
    {
        return Err(FirstUseError::AuthorityMismatch);
    }

    // Authority validation may be non-local and arbitrarily delayed. Re-read
    // the retained descriptors after it completes so an in-place same-size
    // write cannot detach the returned capability from the exact bytes bound
    // by COMMITTED.
    inject_custody_race(CustodyRacePoint::LineageValidated);
    let journal_bytes = readback_retained_named_file(
        &local.directory,
        JOURNAL_NAME,
        &mut local.journal_file,
        local.journal_identity,
        local.journal_bytes_sha256,
    )?;
    CanonicalJournalGenesis::validate_exact(
        &journal_bytes,
        &local.anchor.agent_id,
        local.anchor.adapter.adapter_id(),
        &local.anchor.journal_epoch,
        local.journal_bytes_sha256,
    )?;
    let sentinel_bytes = readback_retained_named_file(
        &local.directory,
        SENTINEL_NAME,
        &mut local.sentinel_file,
        local.sentinel_identity,
        local.sentinel_bytes_sha256,
    )?;
    if local
        .anchor
        .canonical_immutable_sentinel_bytes()
        .map_err(|_| FirstUseError::AuthorityMismatch)?
        != sentinel_bytes
    {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    ensure_named_identity(&local.directory, JOURNAL_NAME, local.journal_identity)?;
    ensure_named_identity(&local.directory, SENTINEL_NAME, local.sentinel_identity)?;
    revalidate_lock(&local.directory, &local.lock)?;

    let candidate_sha256 = digest_from_hex(&lineage.candidate.first_use_candidate_sha256)?;
    let prepared_head_sha256 =
        digest_from_hex(&lineage.prepared_head.first_use_prepared_head_sha256)?;
    let committed_head_sha256 =
        digest_from_hex(&lineage.committed_head.first_use_committed_head_sha256)?;
    let committed_result_binding_sha256 = digest_from_hex(
        &lineage
            .committed_result_binding
            .first_use_committed_result_binding_sha256,
    )?;
    let directory_identity_sha256 =
        digest_from_hex(&lineage.anchor.state_directory_identity_sha256)?;
    let authority_identity_sha256 = digest_from_hex(&lineage.anchor.authority_identity_sha256)?;
    let provision_epoch_sha256 = digest_from_hex(&lineage.anchor.provision_epoch_sha256)?;
    let agent_id = lineage.anchor.agent_id.clone();
    let adapter_id = lineage.anchor.adapter.adapter_id().to_string();
    let journal_epoch = lineage.anchor.journal_epoch.clone();
    Ok(VerifiedFirstUseJournal {
        custody: RetainedFirstUseRuntimeCustody {
            directory: local.directory,
            directory_identity: local.directory_identity,
            lock: local.lock,
            journal_file: local.journal_file,
            journal_identity: local.journal_identity,
            journal_bytes_sha256: local.journal_bytes_sha256,
            sentinel_file: local.sentinel_file,
            sentinel_identity: local.sentinel_identity,
            candidate_sha256,
            sentinel_bytes_sha256: local.sentinel_bytes_sha256,
            directory_identity_sha256,
            authority_identity_sha256,
            provision_epoch_sha256,
            agent_id,
            adapter_id,
            journal_epoch,
            prepared_head_sha256,
            committed_head_sha256,
            committed_result_binding_sha256,
            authority_lineage: lineage,
        },
        genesis_commit,
    })
}

fn direct_operation_adapter(value: &str) -> Result<DirectOperationAdapter, FirstUseError> {
    match value {
        "system_api" => Ok(DirectOperationAdapter::SystemApi),
        "accessibility" => Ok(DirectOperationAdapter::Accessibility),
        _ => Err(FirstUseError::AuthorityMismatch),
    }
}

fn canonical_journal_version(
    identity: FileIdentity,
    bytes_sha256: Sha256Digest,
) -> Result<mutation_cas::DirectOperationRuntimeAuthorityJournalVersionV1, FirstUseError> {
    let mut version = mutation_cas::DirectOperationRuntimeAuthorityJournalVersionV1 {
        schema: mutation_cas::JOURNAL_VERSION_V1_SCHEMA.to_string(),
        protocol: mutation_cas::PROTOCOL.to_string(),
        journal_identity_sha256: identity_digest(b"genesis-journal", identity).to_hex(),
        journal_bytes_sha256: bytes_sha256.to_hex(),
        journal_version_sha256: String::new(),
    };
    version.journal_version_sha256 = version
        .canonical_sha256()
        .map_err(|_| FirstUseError::AuthorityMismatch)?;
    version
        .validate()
        .map_err(|_| FirstUseError::AuthorityMismatch)?;
    Ok(version)
}

#[allow(clippy::too_many_arguments)]
fn validate_authority_lineage_for_local(
    lineage: &mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    directory_identity: FileIdentity,
    genesis_journal_identity: FileIdentity,
    genesis_journal_bytes_sha256: Sha256Digest,
    sentinel_identity: FileIdentity,
    sentinel_bytes_sha256: Sha256Digest,
    agent_id: &str,
    adapter: DirectOperationAdapter,
    journal_epoch: &str,
) -> Result<(), FirstUseError> {
    lineage
        .anchor
        .validate()
        .map_err(|_| FirstUseError::AuthorityMismatch)?;
    lineage
        .candidate
        .validate_for(&lineage.anchor)
        .map_err(|_| FirstUseError::AuthorityMismatch)?;
    lineage
        .prepared_head
        .validate_for(&lineage.anchor, &lineage.candidate)
        .map_err(|_| FirstUseError::AuthorityMismatch)?;
    lineage
        .committed_head
        .validate_for(&lineage.anchor, &lineage.candidate, &lineage.prepared_head)
        .map_err(|_| FirstUseError::AuthorityMismatch)?;
    lineage
        .committed_result_binding
        .validate_for(
            &lineage.anchor,
            &lineage.candidate,
            &lineage.prepared_head,
            &lineage.committed_head,
        )
        .map_err(|_| FirstUseError::AuthorityMismatch)?;
    lineage
        .validate()
        .map_err(|_| FirstUseError::AuthorityMismatch)?;

    if lineage.anchor.agent_id != agent_id
        || lineage.anchor.adapter != adapter
        || lineage.anchor.journal_epoch != journal_epoch
        || lineage.anchor.state_directory_identity_sha256
            != identity_digest(b"state-directory", directory_identity).to_hex()
        || lineage
            .anchor
            .genesis_journal_version
            .journal_identity_sha256
            != identity_digest(b"genesis-journal", genesis_journal_identity).to_hex()
        || lineage.anchor.genesis_journal_version.journal_bytes_sha256
            != genesis_journal_bytes_sha256.to_hex()
        || lineage.anchor.sentinel_identity_sha256
            != identity_digest(b"first-use-immutable-sentinel", sentinel_identity).to_hex()
        || lineage.anchor.sentinel_bytes_sha256 != sentinel_bytes_sha256.to_hex()
        || lineage.committed_head.durable_commit_evidence_sha256
            != durable_local_commit_evidence_digest(
                directory_identity,
                genesis_journal_identity,
                genesis_journal_bytes_sha256,
                sentinel_identity,
                sentinel_bytes_sha256,
            )
            .to_hex()
    {
        return Err(FirstUseError::AuthorityMismatch);
    }
    Ok(())
}

fn digest_from_hex(value: &str) -> Result<Sha256Digest, FirstUseError> {
    Sha256Digest::from_hex(value).map_err(FirstUseError::Journal)
}

fn durable_local_commit_evidence_digest(
    directory_identity: FileIdentity,
    journal_identity: FileIdentity,
    journal_bytes_sha256: Sha256Digest,
    sentinel_identity: FileIdentity,
    sentinel_bytes_sha256: Sha256Digest,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.agent-first-use-local-durable-commit-evidence.v1\0");
    for value in [
        identity_digest(b"state-directory", directory_identity),
        identity_digest(b"genesis-journal", journal_identity),
        journal_bytes_sha256,
        identity_digest(b"first-use-immutable-sentinel", sentinel_identity),
        sentinel_bytes_sha256,
    ] {
        hasher.update(value.as_bytes());
    }
    Sha256Digest::of_bytes(&hasher.finalize())
}

#[cfg(test)]
fn test_authority_digest(domain: &[u8], predecessor: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.agent-first-use-test-authority.v1\0");
    hasher.update((domain.len() as u32).to_be_bytes());
    hasher.update(domain);
    hasher.update((predecessor.len() as u32).to_be_bytes());
    hasher.update(predecessor.as_bytes());
    Sha256Digest::of_bytes(&hasher.finalize()).to_hex()
}

fn identity_digest(domain: &[u8], identity: FileIdentity) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.agent-operation-journal-first-use-identity.v1\0");
    hasher.update((domain.len() as u32).to_be_bytes());
    hasher.update(domain);
    hasher.update(identity.dev.to_be_bytes());
    hasher.update(identity.ino.to_be_bytes());
    hasher.update(identity.mode.to_be_bytes());
    hasher.update(identity.uid.to_be_bytes());
    hasher.update(identity.gid.to_be_bytes());
    hasher.update(identity.nlink.to_be_bytes());
    Sha256Digest::of_bytes(&hasher.finalize())
}

fn acquire_lock(directory: &File) -> Result<File, FirstUseError> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            LOCK_NAME.as_ptr(),
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600,
        )
    };
    let (file, created) = if fd >= 0 {
        (unsafe { File::from_raw_fd(fd) }, true)
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                LOCK_NAME.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        (unsafe { File::from_raw_fd(fd) }, false)
    };
    let identity = FileIdentity::from_file(&file, Some(0))?;
    ensure_named_identity(directory, LOCK_NAME, identity)?;
    if created {
        file.sync_all()?;
        directory.sync_all()?;
    }
    acquire_ofd_write_lock(&file)?;
    ensure_named_identity(directory, LOCK_NAME, identity)?;
    Ok(file)
}

fn acquire_ofd_write_lock(file: &File) -> Result<(), FirstUseError> {
    let mut lock = libc::flock {
        l_type: libc::F_WRLCK as _,
        l_whence: libc::SEEK_SET as _,
        l_start: 0,
        l_len: 1,
        l_pid: 0,
    };
    loop {
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &mut lock) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        // Busy, unsupported, and every unreviewed kernel outcome are all HOLD.
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
}

fn revalidate_lock(directory: &File, lock: &File) -> Result<(), FirstUseError> {
    let identity = FileIdentity::from_file(lock, Some(0))?;
    ensure_named_identity(directory, LOCK_NAME, identity)
}

fn create_fixed_temp(directory: &File, name: &CStr) -> Result<(CString, File), FirstUseError> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(FirstUseError::LocalIdentityAmbiguous)
        } else {
            Err(error.into())
        };
    }
    let file = unsafe { File::from_raw_fd(fd) };
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok((name.to_owned(), file))
}

fn rename_noreplace(directory: &File, from: &CStr, to: &CStr) -> Result<(), FirstUseError> {
    if crate::linux_syscall::renameat2_noreplace(
        directory.as_raw_fd(),
        from,
        directory.as_raw_fd(),
        to,
    ) != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn require_absent(directory: &File, name: &CStr) -> Result<(), FirstUseError> {
    if stat_entry(directory, name)?.is_some() {
        Err(FirstUseError::LocalIdentityAmbiguous)
    } else {
        Ok(())
    }
}

fn ensure_named_identity(
    directory: &File,
    name: &CStr,
    expected: FileIdentity,
) -> Result<(), FirstUseError> {
    if stat_entry(directory, name)? == Some(expected) {
        Ok(())
    } else {
        Err(FirstUseError::LocalIdentityAmbiguous)
    }
}

// Linux libc exposes `nlink_t` as `u64` on x86-64 and `u32` on AArch64.
// Widen the product-architecture value while retaining the exact host value.
#[allow(clippy::useless_conversion)]
fn normalized_nlink(value: libc::nlink_t) -> u64 {
    u64::from(value)
}

fn stat_entry(directory: &File, name: &CStr) -> Result<Option<FileIdentity>, FirstUseError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error.into());
    }
    let stat = unsafe { stat.assume_init() };
    let size = u64::try_from(stat.st_size).map_err(|_| FirstUseError::LocalIdentityAmbiguous)?;
    Ok(Some(FileIdentity {
        dev: stat.st_dev,
        ino: stat.st_ino,
        size,
        mode: stat.st_mode,
        uid: stat.st_uid,
        gid: stat.st_gid,
        nlink: normalized_nlink(stat.st_nlink),
    }))
}

fn open_private_file(directory: &File, name: &CStr) -> Result<File, FirstUseError> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

/// Open the exact inode previously authenticated by the external authority.
///
/// A pathname-only `fstatat` followed by `openat` leaves a replacement window:
/// an Agent that owns its private state directory could substitute a different
/// same-byte inode between those calls. The content digest would still match,
/// but the capability would no longer have consumed the inode it names. Check
/// the opened descriptor itself, then recheck that the fixed name still points
/// to that descriptor before any bytes are accepted.
fn open_exact_private_file(
    directory: &File,
    name: &CStr,
    expected: FileIdentity,
) -> Result<File, FirstUseError> {
    let file = open_private_file(directory, name)?;
    if FileIdentity::from_file(&file, Some(expected.size))? != expected {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    ensure_named_identity(directory, name, expected)?;
    Ok(file)
}

/// Revalidate and read an already-authenticated descriptor while proving the
/// fixed name still denotes that exact inode before and after the read. This
/// deliberately performs no pathname open, closing the check-to-open window.
fn readback_retained_named_file(
    directory: &File,
    name: &CStr,
    file: &mut File,
    expected_identity: FileIdentity,
    expected_bytes_sha256: Sha256Digest,
) -> Result<Vec<u8>, FirstUseError> {
    if FileIdentity::from_file(file, Some(expected_identity.size))? != expected_identity {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    ensure_named_identity(directory, name, expected_identity)?;
    let bytes = read_exact_fd(file, expected_identity.size as usize)?;
    if FileIdentity::from_file(file, Some(expected_identity.size))? != expected_identity
        || Sha256Digest::of_bytes(&bytes) != expected_bytes_sha256
    {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    ensure_named_identity(directory, name, expected_identity)?;
    Ok(bytes)
}

fn read_exact_fd(file: &mut File, expected: usize) -> Result<Vec<u8>, FirstUseError> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(expected);
    file.take(expected as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != expected {
        return Err(FirstUseError::LocalIdentityAmbiguous);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CustodyRacePoint {
    PrecheckComplete,
    OpenComplete,
    FreshObservationComplete,
    ActivationComplete,
    LineageValidated,
}

#[cfg(test)]
type CustodyRaceHook = (CustodyRacePoint, Box<dyn FnOnce()>);

#[cfg(test)]
thread_local! {
    static CUSTODY_RACE_HOOK: std::cell::RefCell<Option<CustodyRaceHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn install_custody_race_hook(point: CustodyRacePoint, hook: impl FnOnce() + 'static) {
    CUSTODY_RACE_HOOK.with(|slot| {
        let previous = slot.borrow_mut().replace((point, Box::new(hook)));
        assert!(previous.is_none(), "custody race hook already installed");
    });
}

#[cfg(test)]
fn inject_custody_race(point: CustodyRacePoint) {
    let hook = CUSTODY_RACE_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(installed_point, _)| *installed_point == point)
        {
            slot.take().map(|(_, hook)| hook)
        } else {
            None
        }
    });
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn inject_custody_race(_point: CustodyRacePoint) {}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
fn inject_fault(point: FaultPoint) -> Result<(), FirstUseError> {
    if NEXT_FAULT.with(|slot| slot.get() == Some(point)) {
        NEXT_FAULT.with(|slot| slot.set(None));
        Err(FirstUseError::Io(std::io::Error::other(format!(
            "injected first-use fault: {point:?}"
        ))))
    } else {
        Ok(())
    }
}

#[cfg(not(test))]
fn inject_fault(_point: FaultPoint) -> Result<(), FirstUseError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs::{self, OpenOptions};
    use std::io::SeekFrom;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    const AGENT: &str = "agent-codex-direct-v1";
    const ADAPTER: &str = "system_api";

    fn runtime_open_consumer() -> crate::operation_journal::OperationJournalRuntimeOpenConsumerToken
    {
        crate::operation_journal::operation_journal_runtime_open_consumer_for_test()
    }

    fn fixture() -> TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn authority(directory: &TempDir) -> VerifiedUnprovisionedAuthority {
        VerifiedUnprovisionedAuthority::for_test(directory.path(), AGENT, ADAPTER).unwrap()
    }

    fn completed_first_use(directory: &TempDir) -> VerifiedFirstUseJournal {
        let staged = stage_secure_first_use(authority(directory)).unwrap();
        let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
        let local = publish_prepared_first_use(prepared).unwrap();
        let committed = VerifiedCommittedAuthority::for_test(local).unwrap();
        finalize_committed_first_use(committed).unwrap()
    }

    fn locally_committed_first_use(directory: &TempDir) -> VerifiedCommittedAuthority {
        let staged = stage_secure_first_use(authority(directory)).unwrap();
        let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
        let local = publish_prepared_first_use(prepared).unwrap();
        VerifiedCommittedAuthority::for_test(local).unwrap()
    }

    fn path_for_temporary(directory: &TempDir, name: &CStr) -> std::path::PathBuf {
        directory.path().join(name.to_str().unwrap())
    }

    fn replace_with_same_bytes(path: &Path) {
        let replacement = path.with_file_name(".custody-race-replacement");
        fs::write(&replacement, fs::read(path).unwrap()).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(replacement, path).unwrap();
    }

    fn overwrite_first_byte_in_place(path: &Path) {
        let first = fs::read(path).unwrap()[0];
        let mut file = OpenOptions::new().write(true).open(path).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&[first ^ 1]).unwrap();
        file.sync_all().unwrap();
    }

    fn actual_runtime_open(
        directory: &TempDir,
        journal_epoch: &str,
        operation_epoch_authority_sha256: Sha256Digest,
        journal_bytes_sha256: Sha256Digest,
        journal_identity: (u64, u64),
    ) -> crate::operation_journal::JournalResult<crate::operation_journal::OperationJournal> {
        crate::operation_journal::OperationJournal::open_exact_runtime_authority_for_test(
            &directory.path().join("operations.json"),
            File::open(directory.path()).unwrap(),
            AGENT,
            ADAPTER,
            journal_epoch,
            operation_epoch_authority_sha256,
            journal_bytes_sha256,
            journal_identity.0,
            journal_identity.1,
        )
    }

    fn rehash_all_first_use_descendants(
        lineage: &mut mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    ) {
        lineage.anchor.sentinel_bytes_sha256 = lineage
            .anchor
            .canonical_immutable_sentinel_bytes_sha256()
            .unwrap();
        lineage.anchor.first_use_anchor_sha256 = lineage.anchor.canonical_sha256().unwrap();

        lineage.candidate.first_use_anchor_sha256 = lineage.anchor.first_use_anchor_sha256.clone();
        lineage.candidate.proposed_genesis_journal_version_sha256 = lineage
            .anchor
            .genesis_journal_version
            .journal_version_sha256
            .clone();
        lineage.candidate.first_use_candidate_sha256 =
            lineage.candidate.canonical_sha256().unwrap();

        lineage.prepared_head.first_use_anchor_sha256 =
            lineage.anchor.first_use_anchor_sha256.clone();
        lineage.prepared_head.first_use_candidate_sha256 =
            lineage.candidate.first_use_candidate_sha256.clone();
        lineage
            .prepared_head
            .prepared_genesis_journal_version_sha256 = lineage
            .anchor
            .genesis_journal_version
            .journal_version_sha256
            .clone();
        lineage.prepared_head.prepared_sentinel_identity_sha256 =
            lineage.anchor.sentinel_identity_sha256.clone();
        lineage.prepared_head.prepared_sentinel_bytes_sha256 =
            lineage.anchor.sentinel_bytes_sha256.clone();
        lineage.prepared_head.first_use_prepared_head_sha256 =
            lineage.prepared_head.canonical_sha256().unwrap();

        lineage.committed_head.first_use_anchor_sha256 =
            lineage.anchor.first_use_anchor_sha256.clone();
        lineage.committed_head.first_use_candidate_sha256 =
            lineage.candidate.first_use_candidate_sha256.clone();
        lineage.committed_head.first_use_prepared_head_sha256 =
            lineage.prepared_head.first_use_prepared_head_sha256.clone();
        lineage.committed_head.committed_genesis_journal_version =
            lineage.anchor.genesis_journal_version.clone();
        lineage.committed_head.committed_sentinel_identity_sha256 =
            lineage.anchor.sentinel_identity_sha256.clone();
        lineage.committed_head.committed_sentinel_bytes_sha256 =
            lineage.anchor.sentinel_bytes_sha256.clone();
        lineage.committed_head.first_use_committed_head_sha256 =
            lineage.committed_head.canonical_sha256().unwrap();

        let result = &mut lineage.committed_result_binding;
        result.first_use_anchor_sha256 = lineage.anchor.first_use_anchor_sha256.clone();
        result.first_use_candidate_sha256 = lineage.candidate.first_use_candidate_sha256.clone();
        result.first_use_prepared_head_sha256 =
            lineage.prepared_head.first_use_prepared_head_sha256.clone();
        result.first_use_committed_head_sha256 = lineage
            .committed_head
            .first_use_committed_head_sha256
            .clone();
        result.committed_genesis_journal_version_sha256 = lineage
            .anchor
            .genesis_journal_version
            .journal_version_sha256
            .clone();
        result.committed_sentinel_identity_sha256 = lineage.anchor.sentinel_identity_sha256.clone();
        result.committed_sentinel_bytes_sha256 = lineage.anchor.sentinel_bytes_sha256.clone();
        result.durable_commit_evidence_sha256 = lineage
            .committed_head
            .durable_commit_evidence_sha256
            .clone();
        result.first_use_committed_result_binding_sha256 = result.canonical_sha256().unwrap();

        lineage.first_use_lineage_sha256 = lineage.canonical_sha256().unwrap();
        lineage.validate().unwrap();
    }

    #[test]
    fn linux_nlink_identity_normalization_is_lossless() {
        fn widened<T: Into<u64>>(value: T) -> u64 {
            value.into()
        }

        let value = libc::nlink_t::MAX;
        assert_eq!(normalized_nlink(value), widened(value));
    }

    #[test]
    fn exact_private_open_rejects_same_byte_inode_after_path_precheck() {
        let directory = fixture();
        let journal_path = directory.path().join("operations.json");
        let bytes = b"same authenticated bytes\n";
        fs::write(&journal_path, bytes).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        let directory_fd = File::open(directory.path()).unwrap();
        let original = open_private_file(&directory_fd, JOURNAL_NAME).unwrap();
        let expected = FileIdentity::from_file(&original, Some(bytes.len() as u64)).unwrap();

        // Model the exact fstatat(name) -> openat(name) race: the pathname
        // precheck succeeds for the authenticated inode, then a same-byte
        // replacement becomes the inode returned by the later open.
        ensure_named_identity(&directory_fd, JOURNAL_NAME, expected).unwrap();
        let replacement = directory.path().join("operations.replacement");
        fs::write(&replacement, bytes).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &journal_path).unwrap();

        assert!(matches!(
            open_exact_private_file(&directory_fd, JOURNAL_NAME, expected),
            Err(FirstUseError::LocalIdentityAmbiguous)
        ));
    }

    #[test]
    fn both_candidates_are_pre_staged_before_prepare_and_published_exactly() {
        let directory = fixture();
        let staged = stage_secure_first_use(authority(&directory)).unwrap();
        assert!(!directory.path().join("operations.json").exists());
        assert!(
            !directory
                .path()
                .join("operations.first-use-committed.json")
                .exists()
        );
        assert_eq!(staged.anchor.agent_id, AGENT);
        assert_eq!(staged.anchor.adapter.adapter_id(), ADAPTER);
        assert_eq!(
            fs::read(path_for_temporary(
                &directory,
                &staged.journal_temporary_name
            ))
            .unwrap(),
            staged.genesis.bytes()
        );
        assert_eq!(
            fs::read(path_for_temporary(
                &directory,
                &staged.sentinel_temporary_name
            ))
            .unwrap(),
            staged.anchor.canonical_immutable_sentinel_bytes().unwrap()
        );
        staged.anchor.validate().unwrap();
        staged.candidate().validate_for(&staged.anchor).unwrap();
        let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
        prepared
            .prepared_head
            .validate_for(&prepared.anchor, &prepared.candidate)
            .unwrap();
        let local = publish_prepared_first_use(prepared).unwrap();
        assert!(directory.path().join("operations.json").is_file());
        assert!(
            directory
                .path()
                .join("operations.first-use-committed.json")
                .is_file()
        );
        let committed = VerifiedCommittedAuthority::for_test(local).unwrap();
        let verified = finalize_committed_first_use(committed).unwrap();
        assert_ne!(verified.candidate_sha256, verified.sentinel_bytes_sha256);
        assert_ne!(verified.committed_head_sha256, verified.candidate_sha256);
        verified.authority_lineage.validate().unwrap();
        assert!(!std::hint::black_box(
            SECURE_FIRST_USE_JOURNAL_FOUNDATION_ENABLED
        ));
    }

    #[test]
    fn canonical_abi_sentinel_is_acyclic_and_unchanged_by_prepare() {
        let directory = fixture();
        let staged = stage_secure_first_use(authority(&directory)).unwrap();
        let canonical_before = staged.anchor.canonical_immutable_sentinel_bytes().unwrap();
        assert!(
            canonical_before
                .starts_with(mutation_cas::FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA.as_bytes())
        );
        assert!(
            !canonical_before
                .windows(b"candidate".len())
                .any(|window| window == b"candidate")
        );
        assert!(
            canonical_before
                .windows(b"prepared_head_embedded".len())
                .any(|window| window == b"prepared_head_embedded")
        );
        assert_eq!(
            Sha256Digest::of_bytes(&canonical_before).to_hex(),
            staged.anchor.sentinel_bytes_sha256
        );

        let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
        let prepared_digest = prepared
            .prepared_head
            .first_use_prepared_head_sha256
            .clone();
        assert_eq!(
            prepared
                .anchor
                .canonical_immutable_sentinel_bytes()
                .unwrap(),
            canonical_before
        );
        assert!(
            !canonical_before
                .windows(prepared_digest.len())
                .any(|window| window == prepared_digest.as_bytes())
        );

        let local = publish_prepared_first_use(prepared).unwrap();
        assert_eq!(
            fs::read(directory.path().join("operations.first-use-committed.json")).unwrap(),
            canonical_before
        );
        let committed = VerifiedCommittedAuthority::for_test(local).unwrap();
        let verified = finalize_committed_first_use(committed).unwrap();
        verified.authority_lineage.validate().unwrap();
    }

    #[test]
    fn journal_directory_commit_unknown_never_publishes_authority() {
        let directory = fixture();
        let staged = stage_secure_first_use(authority(&directory)).unwrap();
        let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
        NEXT_FAULT.with(|slot| slot.set(Some(FaultPoint::JournalDirectoryFsync)));
        assert!(matches!(
            publish_prepared_first_use(prepared),
            Err(FirstUseError::LocalCommitUnknown)
        ));
        assert!(directory.path().join("operations.json").exists());
        assert!(
            !directory
                .path()
                .join("operations.first-use-committed.json")
                .exists()
        );
        assert!(matches!(
            stage_secure_first_use(authority(&directory)),
            Err(FirstUseError::LocalIdentityAmbiguous)
        ));
    }

    #[test]
    fn every_publication_fault_fails_without_runtime_authority() {
        for point in [
            FaultPoint::JournalRename,
            FaultPoint::JournalDirectoryFsync,
            FaultPoint::SentinelRename,
            FaultPoint::SentinelDirectoryFsync,
        ] {
            let directory = fixture();
            let staged = stage_secure_first_use(authority(&directory)).unwrap();
            let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
            NEXT_FAULT.with(|slot| slot.set(Some(point)));
            let error = match publish_prepared_first_use(prepared) {
                Ok(_) => panic!("fault unexpectedly returned runtime authority"),
                Err(error) => error,
            };
            if point == FaultPoint::JournalRename {
                assert!(matches!(error, FirstUseError::Io(_)));
            } else {
                assert!(matches!(error, FirstUseError::LocalCommitUnknown));
            }
            assert!(NEXT_FAULT.with(|slot| slot.get()).is_none());
        }
    }

    #[test]
    fn candidate_is_not_exposed_until_file_and_directory_are_durable() {
        for point in [
            FaultPoint::JournalTempFsync,
            FaultPoint::SentinelTempFsync,
            FaultPoint::PreStageDirectoryFsync,
        ] {
            let directory = fixture();
            NEXT_FAULT.with(|slot| slot.set(Some(point)));
            assert!(matches!(
                stage_secure_first_use(authority(&directory)),
                Err(FirstUseError::Io(_))
            ));
            assert!(!directory.path().join("operations.json").exists());
            assert!(
                !directory
                    .path()
                    .join("operations.first-use-committed.json")
                    .exists()
            );
            assert!(matches!(
                stage_secure_first_use(authority(&directory)),
                Err(FirstUseError::LocalIdentityAmbiguous)
            ));
            assert!(NEXT_FAULT.with(|slot| slot.get()).is_none());
        }
    }

    #[test]
    fn preexisting_regular_symlink_or_partial_state_never_initializes() {
        for attack in 0..3 {
            let directory = fixture();
            match attack {
                0 => fs::write(directory.path().join("operations.json"), b"attacker").unwrap(),
                1 => {
                    let target = directory.path().join("target");
                    fs::write(&target, b"attacker").unwrap();
                    symlink(target, directory.path().join("operations.json")).unwrap();
                }
                2 => fs::write(
                    directory.path().join("operations.first-use-committed.json"),
                    b"attacker",
                )
                .unwrap(),
                _ => unreachable!(),
            }
            assert!(matches!(
                stage_secure_first_use(authority(&directory)),
                Err(FirstUseError::LocalIdentityAmbiguous)
            ));
        }
    }

    #[test]
    fn ofd_lease_is_exclusive_and_untrusted_lock_files_are_never_normalized() {
        let directory = fixture();
        let staged = stage_secure_first_use(authority(&directory)).unwrap();
        assert!(matches!(
            stage_secure_first_use(authority(&directory)),
            Err(FirstUseError::LocalIdentityAmbiguous)
        ));
        drop(staged);

        let directory = fixture();
        let lock_path = directory.path().join(".operations.first-use.lock");
        fs::write(&lock_path, b"").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(stage_secure_first_use(authority(&directory)).is_err());
        assert_eq!(
            fs::metadata(&lock_path).unwrap().permissions().mode() & 0o7777,
            0o644
        );

        let directory = fixture();
        let source = directory.path().join("attacker-lock");
        fs::write(&source, b"").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&source, directory.path().join(".operations.first-use.lock")).unwrap();
        assert!(stage_secure_first_use(authority(&directory)).is_err());

        let directory = fixture();
        let staged = stage_secure_first_use(authority(&directory)).unwrap();
        let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
        let lock_path = directory.path().join(".operations.first-use.lock");
        fs::remove_file(&lock_path).unwrap();
        fs::write(&lock_path, b"").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            publish_prepared_first_use(prepared),
            Err(FirstUseError::LocalIdentityAmbiguous)
        ));
        assert!(!directory.path().join("operations.json").exists());
    }

    #[test]
    fn publication_and_verified_capability_retain_the_original_ofd_lock() {
        let directory = fixture();
        let committed = locally_committed_first_use(&directory);
        let original_lock_identity = FileIdentity::from_file(&committed.lock, Some(0)).unwrap();
        let directory_fd = File::open(directory.path()).unwrap();
        assert!(
            acquire_lock(&directory_fd).is_err(),
            "local COMMITTED typestate must retain the ceremony OFD lease"
        );

        let verified = finalize_committed_first_use(committed).unwrap();
        assert_eq!(
            FileIdentity::from_file(&verified.lock, Some(0)).unwrap(),
            original_lock_identity
        );
        assert!(
            acquire_lock(&directory_fd).is_err(),
            "verified capability must take over the same OFD lease"
        );
        drop(verified);

        let reacquired = acquire_lock(&directory_fd).unwrap();
        assert_eq!(
            FileIdentity::from_file(&reacquired, Some(0)).unwrap(),
            original_lock_identity
        );
    }

    #[test]
    fn finalize_rejects_replaced_lock_even_when_lock_b_is_held() {
        let directory = fixture();
        let committed = locally_committed_first_use(&directory);
        let lock_a_identity = FileIdentity::from_file(&committed.lock, Some(0)).unwrap();
        let lock_path = directory.path().join(".operations.first-use.lock");
        fs::remove_file(&lock_path).unwrap();
        fs::write(&lock_path, b"").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        let directory_fd = File::open(directory.path()).unwrap();
        let lock_b = acquire_lock(&directory_fd).unwrap();
        assert_ne!(
            FileIdentity::from_file(&lock_b, Some(0)).unwrap(),
            lock_a_identity
        );

        assert!(matches!(
            finalize_committed_first_use(committed),
            Err(FirstUseError::LocalIdentityAmbiguous)
        ));
        drop(lock_b);
    }

    #[test]
    fn finalize_rejects_post_publication_inode_replacement_unlink_or_relink() {
        for attack in 0..4 {
            let directory = fixture();
            let committed = locally_committed_first_use(&directory);
            let replace_journal = attack % 2 == 0;
            let target = if replace_journal {
                directory.path().join("operations.json")
            } else {
                directory.path().join("operations.first-use-committed.json")
            };
            if attack < 2 {
                let replacement = directory.path().join("same-byte-replacement");
                fs::write(&replacement, fs::read(&target).unwrap()).unwrap();
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
                fs::rename(&replacement, &target).unwrap();
            } else {
                fs::remove_file(&target).unwrap();
            }

            assert!(matches!(
                finalize_committed_first_use(committed),
                Err(FirstUseError::LocalIdentityAmbiguous)
            ));
        }
    }

    #[test]
    fn restart_layouts_never_remint_first_use() {
        for phase in 0..4 {
            let directory = fixture();
            match phase {
                0 => {
                    let staged = stage_secure_first_use(authority(&directory)).unwrap();
                    let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
                    drop(prepared);
                }
                1 => {
                    let staged = stage_secure_first_use(authority(&directory)).unwrap();
                    let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
                    NEXT_FAULT.with(|slot| slot.set(Some(FaultPoint::SentinelRename)));
                    assert!(matches!(
                        publish_prepared_first_use(prepared),
                        Err(FirstUseError::LocalCommitUnknown)
                    ));
                }
                2 => {
                    let staged = stage_secure_first_use(authority(&directory)).unwrap();
                    let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
                    let local = publish_prepared_first_use(prepared).unwrap();
                    drop(local);
                }
                3 => {
                    let committed = locally_committed_first_use(&directory);
                    drop(committed);
                }
                _ => unreachable!("fixed restart-layout matrix"),
            }
            assert!(matches!(
                stage_secure_first_use(authority(&directory)),
                Err(FirstUseError::LocalIdentityAmbiguous)
            ));
        }
    }

    #[test]
    fn staged_journal_or_sentinel_inode_replacement_is_rejected_before_publication() {
        for replace_sentinel in [false, true] {
            let directory = fixture();
            let staged = stage_secure_first_use(authority(&directory)).unwrap();
            let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
            let target_name = if replace_sentinel {
                &prepared.sentinel_temporary_name
            } else {
                &prepared.journal_temporary_name
            };
            let target = path_for_temporary(&directory, target_name);
            let replacement = directory.path().join("attacker-replacement");
            fs::write(&replacement, fs::read(&target).unwrap()).unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(&replacement, &target).unwrap();

            assert!(matches!(
                publish_prepared_first_use(prepared),
                Err(FirstUseError::LocalIdentityAmbiguous)
            ));
            assert!(!directory.path().join("operations.json").exists());
            assert!(
                !directory
                    .path()
                    .join("operations.first-use-committed.json")
                    .exists()
            );
        }
    }

    #[test]
    fn identity_domains_and_foreign_prepared_chain_cannot_cross_bind() {
        let directory = fixture();
        let staged = stage_secure_first_use(authority(&directory)).unwrap();
        assert_ne!(
            identity_digest(b"state-directory", staged.directory_identity),
            identity_digest(b"genesis-journal", staged.directory_identity)
        );
        assert_ne!(
            identity_digest(b"genesis-journal", staged.journal_temporary_identity),
            identity_digest(
                b"first-use-immutable-sentinel",
                staged.journal_temporary_identity
            )
        );

        let foreign_directory = fixture();
        let foreign_authority =
            VerifiedUnprovisionedAuthority::for_test(foreign_directory.path(), AGENT, ADAPTER)
                .unwrap();
        let foreign_staged = stage_secure_first_use(foreign_authority).unwrap();
        let foreign_prepared = VerifiedPreparedAuthority::for_test(foreign_staged).unwrap();
        let mut prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
        prepared.prepared_head = foreign_prepared.prepared_head;
        assert!(matches!(
            publish_prepared_first_use(prepared),
            Err(FirstUseError::AuthorityMismatch)
        ));
        assert!(!directory.path().join("operations.json").exists());
    }

    #[test]
    fn prepared_or_committed_authority_substitution_is_rejected() {
        let directory = fixture();
        let staged = stage_secure_first_use(authority(&directory)).unwrap();
        let mut prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
        prepared.prepared_head.first_use_candidate_sha256 =
            Sha256Digest::of_bytes(b"wrong-candidate").to_hex();
        assert!(matches!(
            publish_prepared_first_use(prepared),
            Err(FirstUseError::AuthorityMismatch)
        ));

        let directory = fixture();
        let staged = stage_secure_first_use(authority(&directory)).unwrap();
        let mut prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
        prepared.prepared_head.first_use_prepared_head_sha256 =
            prepared.candidate.first_use_candidate_sha256.clone();
        assert!(matches!(
            publish_prepared_first_use(prepared),
            Err(FirstUseError::AuthorityMismatch)
        ));
        assert!(!directory.path().join("operations.json").exists());

        let directory = fixture();
        let staged = stage_secure_first_use(authority(&directory)).unwrap();
        let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
        let local = publish_prepared_first_use(prepared).unwrap();
        let mut committed = VerifiedCommittedAuthority::for_test(local).unwrap();
        committed.lineage.anchor.sentinel_bytes_sha256 =
            Sha256Digest::of_bytes(b"wrong-sentinel").to_hex();
        assert!(matches!(
            finalize_committed_first_use(committed),
            Err(FirstUseError::AuthorityMismatch)
        ));
    }

    #[test]
    fn recomputed_lineage_cannot_forge_local_durable_commit_evidence() {
        let directory = fixture();
        let mut committed = locally_committed_first_use(&directory);
        committed
            .lineage
            .committed_head
            .durable_commit_evidence_sha256 =
            Sha256Digest::of_bytes(b"caller-authored-durable-commit-evidence").to_hex();
        rehash_all_first_use_descendants(&mut committed.lineage);
        committed.lineage.validate().unwrap();

        assert!(
            validate_authority_lineage_for_local(
                &committed.lineage,
                committed.directory_identity,
                committed.journal_identity,
                committed.journal_bytes_sha256,
                committed.sentinel_identity,
                committed.sentinel_bytes_sha256,
                &committed.anchor.agent_id,
                committed.anchor.adapter,
                &committed.anchor.journal_epoch,
            )
            .is_err()
        );
        assert!(matches!(
            finalize_committed_first_use(committed),
            Err(FirstUseError::AuthorityMismatch)
        ));
    }

    #[test]
    fn finalize_postcheck_rejects_equal_length_in_place_byte_drift() {
        for target in [JOURNAL_NAME, SENTINEL_NAME] {
            let directory = fixture();
            let committed = locally_committed_first_use(&directory);
            let target = path_for_temporary(&directory, target);
            install_custody_race_hook(CustodyRacePoint::LineageValidated, move || {
                overwrite_first_byte_in_place(&target)
            });
            assert!(matches!(
                finalize_committed_first_use(committed),
                Err(FirstUseError::LocalIdentityAmbiguous)
            ));
        }
    }

    #[test]
    fn fully_rehashed_foreign_lineage_cannot_replace_exact_local_custody() {
        for drift in 0..3 {
            let directory = fixture();
            let staged = stage_secure_first_use(authority(&directory)).unwrap();
            let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
            let local = publish_prepared_first_use(prepared).unwrap();
            let mut committed = VerifiedCommittedAuthority::for_test(local).unwrap();
            match drift {
                0 => {
                    committed.lineage.anchor.authority_store_instance_sha256 =
                        Sha256Digest::of_bytes(b"foreign-authority-store").to_hex();
                }
                1 => {
                    committed.lineage.anchor.state_directory_identity_sha256 =
                        Sha256Digest::of_bytes(b"foreign-state-directory").to_hex();
                }
                2 => {
                    committed.lineage.anchor.adapter = DirectOperationAdapter::Accessibility;
                }
                _ => unreachable!(),
            }
            rehash_all_first_use_descendants(&mut committed.lineage);
            committed.lineage.validate().unwrap();
            assert!(matches!(
                finalize_committed_first_use(committed),
                Err(FirstUseError::AuthorityMismatch)
            ));
        }
    }

    #[test]
    fn replacement_epoch_and_authority_lineage_drift_fail_closed() {
        let directory = fixture();
        let verified = completed_first_use(&directory);
        let trusted_directory = File::open(directory.path()).unwrap();
        verified
            .validate_for_runtime_open(&trusted_directory, AGENT, ADAPTER)
            .unwrap();
        let sentinel_path = directory.path().join("operations.first-use-committed.json");
        let replacement_path = directory.path().join("replacement-sentinel");
        fs::write(&replacement_path, fs::read(&sentinel_path).unwrap()).unwrap();
        fs::set_permissions(&replacement_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement_path, &sentinel_path).unwrap();
        assert!(matches!(
            verified.validate_for_runtime_open(&trusted_directory, AGENT, ADAPTER),
            Err(FirstUseError::LocalIdentityAmbiguous)
        ));

        let directory = fixture();
        let verified = completed_first_use(&directory);
        let lineage = verified.replay_lineage();
        let epoch = verified.journal_epoch().to_string();
        VerifiedJournalReplayAuthority::for_test(
            directory.path(),
            AGENT,
            ADAPTER,
            &epoch,
            lineage.clone(),
            1,
        )
        .unwrap();
        let wrong_epoch = if epoch == "f".repeat(32) {
            "e".repeat(32)
        } else {
            "f".repeat(32)
        };
        assert!(matches!(
            VerifiedJournalReplayAuthority::for_test(
                directory.path(),
                AGENT,
                ADAPTER,
                &wrong_epoch,
                lineage.clone(),
                1,
            ),
            Err(FirstUseError::AuthorityMismatch)
        ));

        for drift in 0..5 {
            let mut drifted = lineage.clone();
            match drift {
                0 => {
                    drifted.first_use_lineage.candidate_sha256 =
                        Sha256Digest::of_bytes(b"drifted-first-use-candidate")
                }
                1 => {
                    drifted.first_use_lineage.prepared_head_sha256 =
                        Sha256Digest::of_bytes(b"drifted-first-use-prepared-head")
                }
                2 => {
                    drifted.first_use_lineage.committed_head_sha256 =
                        Sha256Digest::of_bytes(b"drifted-first-use-committed-head")
                }
                3 => {
                    drifted.first_use_lineage.committed_result_binding_sha256 =
                        Sha256Digest::of_bytes(b"drifted-first-use-result-binding")
                }
                4 => {
                    drifted.first_use_lineage.provision_epoch_sha256 =
                        Sha256Digest::of_bytes(b"drifted-first-use-provision-epoch")
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                VerifiedJournalReplayAuthority::for_test(
                    directory.path(),
                    AGENT,
                    ADAPTER,
                    &epoch,
                    drifted,
                    1,
                ),
                Err(FirstUseError::AuthorityMismatch)
            ));
        }
    }

    #[test]
    fn store_owned_replay_history_rejects_recomputed_sentinel_and_descendants() {
        let directory = fixture();
        let verified = completed_first_use(&directory);
        let authority_store = verified.replay_lineage();
        let epoch = verified.journal_epoch().to_string();
        drop(verified);

        let mut forged_history = authority_store.first_use_lineage.clone();
        forged_history
            .authority_lineage
            .anchor
            .authority_store_instance_sha256 =
            Sha256Digest::of_bytes(b"attacker-recomputed-authority-store").to_hex();
        let forged_sentinel_bytes = forged_history
            .authority_lineage
            .anchor
            .canonical_immutable_sentinel_bytes()
            .unwrap();
        let replacement = directory.path().join("forged-sentinel-replacement");
        fs::write(&replacement, &forged_sentinel_bytes).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        let replacement_file = File::open(&replacement).unwrap();
        let replacement_identity =
            FileIdentity::from_file(&replacement_file, Some(forged_sentinel_bytes.len() as u64))
                .unwrap();
        let replacement_bytes_sha256 = Sha256Digest::of_bytes(&forged_sentinel_bytes);
        forged_history
            .authority_lineage
            .anchor
            .sentinel_identity_sha256 =
            identity_digest(b"first-use-immutable-sentinel", replacement_identity).to_hex();
        forged_history
            .authority_lineage
            .anchor
            .sentinel_bytes_sha256 = replacement_bytes_sha256.to_hex();
        forged_history
            .authority_lineage
            .committed_head
            .durable_commit_evidence_sha256 = durable_local_commit_evidence_digest(
            forged_history.directory_identity,
            forged_history.genesis_journal_identity,
            forged_history.genesis_journal_bytes_sha256,
            replacement_identity,
            replacement_bytes_sha256,
        )
        .to_hex();
        rehash_all_first_use_descendants(&mut forged_history.authority_lineage);
        forged_history.sentinel_identity = replacement_identity;
        forged_history.sentinel_bytes_sha256 = replacement_bytes_sha256;
        forged_history.candidate_sha256 = digest_from_hex(
            &forged_history
                .authority_lineage
                .candidate
                .first_use_candidate_sha256,
        )
        .unwrap();
        forged_history.prepared_head_sha256 = digest_from_hex(
            &forged_history
                .authority_lineage
                .prepared_head
                .first_use_prepared_head_sha256,
        )
        .unwrap();
        forged_history.committed_head_sha256 = digest_from_hex(
            &forged_history
                .authority_lineage
                .committed_head
                .first_use_committed_head_sha256,
        )
        .unwrap();
        forged_history.committed_result_binding_sha256 = digest_from_hex(
            &forged_history
                .authority_lineage
                .committed_result_binding
                .first_use_committed_result_binding_sha256,
        )
        .unwrap();
        validate_authority_lineage_for_local(
            &forged_history.authority_lineage,
            forged_history.directory_identity,
            forged_history.genesis_journal_identity,
            forged_history.genesis_journal_bytes_sha256,
            forged_history.sentinel_identity,
            forged_history.sentinel_bytes_sha256,
            AGENT,
            DirectOperationAdapter::SystemApi,
            &epoch,
        )
        .unwrap();

        fs::rename(
            &replacement,
            directory.path().join("operations.first-use-committed.json"),
        )
        .unwrap();
        assert!(matches!(
            VerifiedJournalReplayAuthority::for_test(
                directory.path(),
                AGENT,
                ADAPTER,
                &epoch,
                authority_store,
                1,
            ),
            Err(FirstUseError::LocalIdentityAmbiguous | FirstUseError::AuthorityMismatch)
        ));
    }

    #[test]
    fn sealed_runtime_capability_binds_the_exact_external_committed_head() {
        let directory = fixture();
        let staged = stage_secure_first_use(authority(&directory)).unwrap();
        let prepared = VerifiedPreparedAuthority::for_test(staged).unwrap();
        let local = publish_prepared_first_use(prepared).unwrap();
        let committed = VerifiedCommittedAuthority::for_test(local).unwrap();
        let mut verified = finalize_committed_first_use(committed).unwrap();
        let trusted_directory = File::open(directory.path()).unwrap();
        verified
            .validate_for_runtime_open(&trusted_directory, AGENT, ADAPTER)
            .unwrap();

        verified.committed_head_sha256 =
            Sha256Digest::of_bytes(b"substituted-external-committed-head");
        assert!(matches!(
            verified.validate_for_runtime_open(&trusted_directory, AGENT, ADAPTER),
            Err(FirstUseError::AuthorityMismatch)
        ));
    }

    #[test]
    fn first_use_actual_open_cannot_escape_postcheck_replacement() {
        for target in [JOURNAL_NAME, SENTINEL_NAME, LOCK_NAME] {
            let directory = fixture();
            let authority = completed_first_use(&directory);
            let trusted_directory = File::open(directory.path()).unwrap();
            let original_journal = fs::read(directory.path().join("operations.json")).unwrap();
            let target = path_for_temporary(&directory, target);
            install_custody_race_hook(CustodyRacePoint::OpenComplete, move || {
                replace_with_same_bytes(&target)
            });
            let actual_open_completed = Cell::new(false);
            let result = authority.consume_for_runtime_open(
                runtime_open_consumer(),
                &trusted_directory,
                AGENT,
                ADAPTER,
                |authority| {
                    let opened = actual_runtime_open(
                        &directory,
                        authority.journal_epoch(),
                        authority.operation_epoch_authority_sha256(),
                        authority.journal_bytes_sha256(),
                        authority.journal_file_identity(),
                    );
                    actual_open_completed.set(opened.is_ok());
                    opened
                },
            );
            assert!(actual_open_completed.get());
            assert!(matches!(result, Err(FirstUseError::LocalIdentityAmbiguous)));
            assert_eq!(
                fs::read(directory.path().join("operations.json")).unwrap(),
                original_journal
            );
        }
    }

    #[test]
    fn first_use_handoff_returns_opened_journal_and_same_store_session() {
        let directory = fixture();
        let authority = completed_first_use(&directory);
        let trusted_directory = File::open(directory.path()).unwrap();
        let result = authority.consume_for_runtime_open(
            runtime_open_consumer(),
            &trusted_directory,
            AGENT,
            ADAPTER,
            |authority| {
                actual_runtime_open(
                    &directory,
                    authority.journal_epoch(),
                    authority.operation_epoch_authority_sha256(),
                    authority.journal_bytes_sha256(),
                    authority.journal_file_identity(),
                )
            },
        );
        let Ok(Ok((journal, mutation_cas_session))) = result else {
            panic!("same-store first-use handoff failed");
        };
        assert!(
            !journal.has_mutation_cas_session_for_test(),
            "the exact local open is not allowed to self-mint or retain a CAS session"
        );
        assert!(
            journal
                .mutation_cas_observation_snapshot_for_test()
                .is_none(),
            "the exact local open has no same-store authority backend"
        );
        drop(mutation_cas_session);
        drop(journal);
        assert!(
            acquire_lock(&trusted_directory).is_ok(),
            "ceremony OFD lease escaped the completed handoff"
        );
    }

    #[test]
    fn local_open_error_is_preserved_and_never_activates() {
        let directory = fixture();
        let authority = completed_first_use(&directory);
        let trusted_directory = File::open(directory.path()).unwrap();
        let result = authority.consume_for_runtime_open(
            runtime_open_consumer(),
            &trusted_directory,
            AGENT,
            ADAPTER,
            |_authority| Err::<(), _>("local-open-failed"),
        );
        assert!(matches!(result, Ok(Err("local-open-failed"))));
        assert!(
            acquire_lock(&trusted_directory).is_ok(),
            "failed local open retained first-use custody"
        );
    }

    #[test]
    fn activation_window_drift_drops_opened_value_and_session_inside_consumer() {
        use std::rc::Rc;

        struct DropProbe(Rc<Cell<bool>>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        for target in [JOURNAL_NAME, SENTINEL_NAME, LOCK_NAME] {
            let directory = fixture();
            let authority = completed_first_use(&directory);
            let trusted_directory = File::open(directory.path()).unwrap();
            let target_path = path_for_temporary(&directory, target);
            let state_path = directory.path().to_path_buf();
            install_custody_race_hook(CustodyRacePoint::ActivationComplete, move || {
                let directory_fd = File::open(&state_path).unwrap();
                assert!(
                    acquire_lock(&directory_fd).is_err(),
                    "ceremony OFD lease died before activation completed"
                );
                replace_with_same_bytes(&target_path);
            });
            let dropped = Rc::new(Cell::new(false));
            let result = authority.consume_for_runtime_open(
                runtime_open_consumer(),
                &trusted_directory,
                AGENT,
                ADAPTER,
                |_authority| Ok::<_, ()>(DropProbe(Rc::clone(&dropped))),
            );
            assert!(matches!(result, Err(FirstUseError::LocalIdentityAmbiguous)));
            assert!(
                dropped.get(),
                "opened value escaped a failed final custody check"
            );
        }
    }

    #[test]
    fn replay_capability_retains_constructed_inode_and_byte_custody() {
        for (target, replace) in [
            (JOURNAL_NAME, true),
            (SENTINEL_NAME, true),
            (JOURNAL_NAME, false),
            (SENTINEL_NAME, false),
        ] {
            let directory = fixture();
            let first_use = completed_first_use(&directory);
            let authority_store = first_use.replay_lineage();
            let epoch = first_use.journal_epoch().to_string();
            drop(first_use);
            let replay = VerifiedJournalReplayAuthority::for_test(
                directory.path(),
                AGENT,
                ADAPTER,
                &epoch,
                authority_store,
                1,
            )
            .unwrap();
            let target = path_for_temporary(&directory, target);
            if replace {
                replace_with_same_bytes(&target);
            } else {
                overwrite_first_byte_in_place(&target);
            }
            let trusted_directory = File::open(directory.path()).unwrap();
            assert!(matches!(
                replay.validate_for_runtime_open(&trusted_directory, AGENT, ADAPTER),
                Err(FirstUseError::LocalIdentityAmbiguous)
            ));
        }
    }

    #[test]
    fn replay_actual_open_cannot_escape_postcheck_replacement() {
        for target in [JOURNAL_NAME, SENTINEL_NAME] {
            let directory = fixture();
            let first_use = completed_first_use(&directory);
            let authority_store = first_use.replay_lineage();
            let epoch = first_use.journal_epoch().to_string();
            drop(first_use);
            let replay = VerifiedJournalReplayAuthority::for_test(
                directory.path(),
                AGENT,
                ADAPTER,
                &epoch,
                authority_store,
                1,
            )
            .unwrap();
            let trusted_directory = File::open(directory.path()).unwrap();
            let original_journal = fs::read(directory.path().join("operations.json")).unwrap();
            let target = path_for_temporary(&directory, target);
            install_custody_race_hook(CustodyRacePoint::OpenComplete, move || {
                replace_with_same_bytes(&target)
            });
            let actual_open_completed = Cell::new(false);
            let result = replay.consume_for_runtime_open(
                runtime_open_consumer(),
                &trusted_directory,
                AGENT,
                ADAPTER,
                |authority| {
                    let opened = actual_runtime_open(
                        &directory,
                        authority.journal_epoch(),
                        authority.operation_epoch_authority_sha256(),
                        authority.journal_bytes_sha256(),
                        authority.journal_file_identity(),
                    );
                    actual_open_completed.set(opened.is_ok());
                    opened
                },
            );
            assert!(actual_open_completed.get());
            assert!(matches!(result, Err(FirstUseError::LocalIdentityAmbiguous)));
            assert_eq!(
                fs::read(directory.path().join("operations.json")).unwrap(),
                original_journal
            );
        }
    }

    #[test]
    fn foundation_has_no_adapter_or_product_authority_route() {
        assert!(!std::hint::black_box(
            SECURE_FIRST_USE_JOURNAL_FOUNDATION_ENABLED
        ));
        assert!(std::hint::black_box(
            mutation_cas::SOURCE_DATA_ABI_IMPLEMENTED
        ));
        for product_flag in [
            mutation_cas::AUTHORITY_BACKEND_PRODUCT_AVAILABLE,
            mutation_cas::ADAPTER_CLIENT_PRODUCT_WIRED,
            mutation_cas::DAEMON_LISTENER_PRODUCT_WIRED,
            mutation_cas::PREPARE_PRODUCT_AVAILABLE,
            mutation_cas::COMMIT_PRODUCT_AVAILABLE,
            mutation_cas::OBSERVE_PRODUCT_AVAILABLE,
            mutation_cas::RECONCILE_PRODUCT_AVAILABLE,
            mutation_cas::MUTATION_CAS_PRODUCT_AVAILABLE,
            mutation_cas::CONFERS_FIRST_USE_AUTHORITY,
            mutation_cas::CONFERS_REPLAY_AUTHORITY,
            mutation_cas::CONFERS_EFFECT_AUTHORITY,
        ] {
            assert!(!product_flag);
        }
        for live_source in [
            include_str!("system_api.rs"),
            include_str!("accessibility.rs"),
            include_str!("journaled_call.rs"),
            include_str!("bin/system_api.rs"),
            include_str!("bin/accessibility.rs"),
        ] {
            assert!(!live_source.contains("stage_secure_first_use"));
            assert!(!live_source.contains("VerifiedFirstUseJournal"));
            assert!(!live_source.contains("operations.first-use-committed.json"));
        }

        let module_source = include_str!("secure_first_use_journal.rs");
        for forbidden in [
            ["pub(crate) fn new_", "unprovisioned"].concat(),
            ["pub(crate) fn verify_", "prepared"].concat(),
            ["pub(crate) fn verify_", "committed"].concat(),
            ["DirectOperationRuntimeAuthority", "CommittedHeadV1"].concat(),
        ] {
            assert!(!module_source.contains(&forbidden));
        }
        assert!(
            module_source.contains("authority_mutation_generation"),
            "replay/high-water decisions must bind the exact same-store mutation generation"
        );

        let journal_source = include_str!("operation_journal.rs");
        assert!(journal_source.contains("open_trusted_after_first_use"));
        assert!(journal_source.contains("consume_for_runtime_open"));
        assert!(journal_source.contains("required_initial_state_sha256"));
        assert!(journal_source.contains("pinned_epoch"));

        let context_source = include_str!("trusted_context.rs");
        let product_open = context_source
            .split_once("pub fn open_operation_journal(")
            .unwrap()
            .1
            .split_once("#[cfg(test)]")
            .unwrap()
            .0;
        assert!(product_open.contains("FirstUseAuthorityUnavailable"));
        assert!(!product_open.contains("open_trusted_after_first_use"));
    }
}
