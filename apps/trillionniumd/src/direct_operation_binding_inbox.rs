//! Root-owned direct-operation binding inbox publication.
//!
//! The daemon publisher hot path derives all identity from the already
//! verified request/binding and publishes the canonical envelope only to the
//! exact adapter leaves authorized by Binding V3. The current constructor is
//! fixed to the first P0 profile `[system_api]`; Accessibility is not
//! published or synthesized. Paths, providers,
//! Agents, subjects, and attempt identity are never selected by a model or by
//! environment variables. Any commit-unknown result is an error and callers
//! must not spawn the provider. A provider-specific lifecycle lock plus the
//! dedicated-UID drain keeps a live invocation's hidden inbox from being
//! replaced until supervised descendant cleanup is complete.
//!
//! Adapter intake exists only behind the explicitly inert
//! `trusted-context-hotpath` build feature; default/product tools do not consume
//! this inbox. An in-process lock plus `/proc` UID drain cannot prove across a
//! daemon crash that no fork/exit chain retained the old context. Kernel-owned
//! cgroup/PID-namespace descendant custody, secure first-use tool journals, and
//! outer effect ACK consumption therefore remain HOLD. No binding value enters
//! model input, MCP JSON, environment, or argv, and no sensitive tool is enabled.

use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::NonZeroU64;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard, TryLockError};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use trillionnium_os_types::agent_principal_registry::{self, CODEX_STABLE_PRINCIPAL as CODEX};
use trillionnium_os_types::direct_operation::{
    BINDING_INBOX_SCHEMA, BINDING_SCHEMA, DirectOperationBinding, DirectOperationBindingInbox,
    DirectOperationProviderAttempt, DirectOperationStableSeed, STABLE_SEED_SCHEMA,
};
use trillionnium_os_types::{
    AgentRegistration, sha256_bytes, sha256_json, validate_agent_registration,
};
use trillionnium_tool_runtime::supervised_codex::{
    PlanningRequest, RuntimeLifecycleBinding, preflight_dedicated_uid,
};

// trillionniumd runs after `trillionnium-root-linux-run` has entered the Root
// Linux chroot. Android init owns `/data/trillionnium/agent-tools` and bind
// mounts that host source at `/var/lib/trillionnium/agent-tools` inside this
// namespace; Android-host paths are therefore neither valid nor accepted here.
const PRODUCT_INBOX_ROOT: &str = "/var/lib/trillionnium/agent-tools/inbox";
const BINDING_FILE_NAME: &CStr = c"current-invocation.json";
const BINDING_FILE_MODE: u32 = 0o440;
const INBOX_LEAF_MODE: u32 = 0o750;
const MAX_BINDING_BYTES: usize = 32 * 1024;
const ROOT_UID: u32 = 0;
#[cfg(test)]
const CODEX_UID_GID: u32 = CODEX.uid;
const CODEX_PROVIDER_ID: &str = CODEX.provider_id;
const CODEX_FINAL_RUNTIME_SHA256: &str = env!("TRILLIONNIUM_P01_CODEX_RUNTIME_SHA256");
#[cfg(test)]
const CODEX_AGENT_ID: &str = CODEX.agent_id;
const ATTEMPT_CONTEXT_SCHEMA: &str = "trillionnium.direct-operation-daemon-attempt-context.v1";
const WORKFLOW_ID_PREFIX: &str = "req-";
const WORKFLOW_ID_HEX_BYTES: usize = 32;
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// The inbox names are fixed per provider rather than per invocation. Hold the
// matching provider lock from the first pre-publication UID drain until the
// supervised provider has completed and its observed descendants are gone.
// This serializes same-daemon requests but is deliberately not treated as
// cross-daemon crash custody; default/product adapters do not consume the inbox.
static CODEX_DIRECT_LIFECYCLE_LOCK: Mutex<()> = Mutex::new(());
#[cfg(test)]
static PUBLISHER_TEST_SERIAL_LOCK: Mutex<()> = Mutex::new(());

/// Query presented to the future root-owned durable attempt journal.
///
/// It contains no raw intent, context, URI, request body, credential, nonce, or
/// backend result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableProviderAttemptQuery {
    pub provider_id: String,
    pub agent_id: String,
    pub task_id: String,
    pub runtime_lifecycle_binding_sha256: String,
}

/// Sealed OS-authored identity projection for Binding V3 publication.
///
/// The workflow plaintext is accepted only long enough to validate and hash
/// its exact `req-<32lowerhex>` shape. Agent identity comes from the typed OS
/// registration and the executable digest comes from the daemon's measured
/// dispatch identity. None of this projection enters the provider request,
/// model input, MCP schema, environment, or argv.
///
/// The current built-in registration aliases its identity-key digest to the
/// measured executable digest. Keeping both named commitments is not evidence
/// of an independent signed launcher authority; that promotion gate remains
/// HOLD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectOperationOsIdentity {
    agent_id: String,
    agent_peer_uid: u32,
    agent_peer_gid: u32,
    workflow_id_sha256: String,
    agent_identity_key_sha256: String,
    agent_executable_sha256: String,
}

impl DirectOperationOsIdentity {
    pub(crate) fn from_registered_agent(
        workflow_id: &str,
        registration: &AgentRegistration,
        measured_agent_executable_sha256: &str,
    ) -> Result<Self> {
        if !exact_workflow_id(workflow_id)
            || !validate_agent_registration(registration).valid
            || crate::builtin_provider_identity::from_registration_with_active_launcher(
                registration,
                measured_agent_executable_sha256,
            )
            .is_none()
            || !is_nonzero_lower_sha256(measured_agent_executable_sha256)
            || registration.identity_key_sha256 != measured_agent_executable_sha256
        {
            bail!("direct_operation_os_identity_source_denied");
        }
        let workflow_id_sha256 = sha256_bytes(workflow_id.as_bytes());
        if !is_nonzero_lower_sha256(&workflow_id_sha256) {
            bail!("direct_operation_workflow_identity_digest_denied");
        }
        Ok(Self {
            agent_id: registration.agent_id.clone(),
            agent_peer_uid: registration.peer_uid,
            agent_peer_gid: registration.peer_gid,
            workflow_id_sha256,
            agent_identity_key_sha256: registration.identity_key_sha256.clone(),
            agent_executable_sha256: measured_agent_executable_sha256.to_string(),
        })
    }

    fn validate_for(
        &self,
        request: &PlanningRequest,
        runtime_binding: &RuntimeLifecycleBinding,
    ) -> Result<()> {
        let claims = &request.capability.claims;
        if self.agent_id != runtime_binding.agent_id
            || self.agent_id != claims.agent_id
            || self.agent_peer_uid != runtime_binding.agent_peer_uid
            || self.agent_peer_uid != claims.agent_peer_uid
            || self.agent_peer_gid != runtime_binding.agent_peer_gid
            || self.agent_peer_gid != claims.agent_peer_gid
            || self.workflow_id_sha256 != claims.workflow_id_sha256
            || self.agent_identity_key_sha256 != self.agent_executable_sha256
            || self.agent_executable_sha256 != runtime_binding.agent_executable_sha256
            || self.agent_executable_sha256 != claims.agent_executable_sha256
            || !is_nonzero_lower_sha256(&self.workflow_id_sha256)
            || !is_nonzero_lower_sha256(&self.agent_identity_key_sha256)
            || !is_nonzero_lower_sha256(&self.agent_executable_sha256)
        {
            bail!("direct_operation_os_identity_binding_mismatch");
        }
        Ok(())
    }
}

/// Closed projection that a durable attempt journal must return.
///
/// `durable_record_sha256` commits the journal record that owns the generation;
/// it is not a caller nonce.  The constructor validates shape, while the source
/// implementation remains responsible for proving the record was durably read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableProviderAttemptRecord {
    runtime_lifecycle_binding_sha256: String,
    attempt_generation: NonZeroU64,
    durable_record_sha256: String,
    egress_grant_id_sha256: String,
    egress_journal_binding_sha256: String,
}

impl DurableProviderAttemptRecord {
    pub(crate) fn from_durable_journal_record(
        runtime_lifecycle_binding_sha256: String,
        attempt_generation: u64,
        durable_record_sha256: String,
        egress_grant_id_sha256: String,
        egress_journal_binding_sha256: String,
    ) -> Result<Self> {
        if !is_lower_sha256(&runtime_lifecycle_binding_sha256)
            || !is_lower_sha256(&durable_record_sha256)
            || !is_nonzero_lower_sha256(&egress_grant_id_sha256)
            || !is_nonzero_lower_sha256(&egress_journal_binding_sha256)
        {
            bail!("direct_operation_attempt_journal_digest_denied");
        }
        let attempt_generation = NonZeroU64::new(attempt_generation)
            .context("direct_operation_attempt_generation_must_be_nonzero")?;
        Ok(Self {
            runtime_lifecycle_binding_sha256,
            attempt_generation,
            durable_record_sha256,
            egress_grant_id_sha256,
            egress_journal_binding_sha256,
        })
    }

    #[cfg(test)]
    fn for_test(
        runtime_lifecycle_binding_sha256: String,
        attempt_generation: u64,
        durable_record_sha256: String,
    ) -> Result<Self> {
        Self::from_durable_journal_record(
            runtime_lifecycle_binding_sha256,
            attempt_generation,
            durable_record_sha256,
            sha256_bytes(b"fixture-egress-grant-id"),
            sha256_bytes(b"fixture-egress-journal-binding"),
        )
    }

    fn validate_for(&self, query: &DurableProviderAttemptQuery) -> Result<()> {
        if self.runtime_lifecycle_binding_sha256 != query.runtime_lifecycle_binding_sha256
            || !is_lower_sha256(&self.durable_record_sha256)
        {
            bail!("direct_operation_attempt_journal_binding_mismatch");
        }
        Ok(())
    }
}

/// Integration point for the root-owned monotonic attempt-generation journal.
/// There is deliberately no environment-backed implementation.
pub(crate) trait DurableProviderAttemptSource {
    fn load_durable_attempt(
        &self,
        query: &DurableProviderAttemptQuery,
    ) -> Result<DurableProviderAttemptRecord>;
}

/// Daemon-local audit projection of the exact hidden inbox publication. These
/// values are never passed to children. Only the unpromoted hotpath feature and
/// conformance code consume the canonical root-owned envelope from its fixed
/// SELinux-only path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectOperationLaunchExpectation {
    pub binding_sha256: String,
    pub invocation_id: String,
    pub task_id: String,
    pub delivery_provider_attempt_id: String,
}

#[derive(Debug)]
pub(crate) struct DirectOperationInboxPublication {
    pub binding: DirectOperationBinding,
    pub launch: DirectOperationLaunchExpectation,
    custody_seed: Option<DirectOperationInboxCustodySeed>,
    // The caller retains this until supervised descendant cleanup completes.
    _lifecycle_guard: Option<DirectOperationLifecycleGuard>,
    #[cfg(test)]
    _test_serial_guard: Option<MutexGuard<'static, ()>>,
}

#[derive(Debug)]
pub(crate) struct DirectOperationInboxCustodySeed {
    pub(crate) binding_inbox: DirectOperationBindingInbox,
    pub(crate) binding_inbox_bytes_sha256: String,
    pub(crate) egress_grant_id_sha256: String,
    pub(crate) egress_journal_binding_sha256: String,
    pub(crate) allocation_egress_cas_sha256: String,
    pub(crate) parent_directory_identity_sha256: String,
    pub(crate) published_file_identity_sha256: String,
    pub(crate) parent_directory_fsync_proof_sha256: String,
}

#[derive(Debug)]
struct DirectOperationAttemptCustodyIdentity {
    egress_grant_id_sha256: String,
    egress_journal_binding_sha256: String,
    allocation_egress_cas_sha256: String,
}

#[derive(Debug)]
struct DurableLeafPublicationEvidence {
    parent_directory_identity_sha256: String,
    published_file_identity_sha256: String,
    parent_directory_fsync_proof_sha256: String,
}

impl DirectOperationInboxPublication {
    #[cfg(any(test, feature = "p0-launch-package-device-conformance"))]
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn take_custody_seed(&mut self) -> Result<DirectOperationInboxCustodySeed> {
        self.custody_seed
            .take()
            .context("direct_operation_inbox_custody_seed_already_consumed")
    }
}

#[derive(Debug)]
struct DirectOperationLifecycleGuard {
    _guard: MutexGuard<'static, ()>,
}

impl DirectOperationLifecycleGuard {
    fn try_acquire(provider: &ProviderSpecification) -> Result<Self> {
        let lock = match provider.provider_id {
            CODEX_PROVIDER_ID => &CODEX_DIRECT_LIFECYCLE_LOCK,
            _ => bail!("direct_operation_lifecycle_provider_denied"),
        };
        match lock.try_lock() {
            Ok(guard) => Ok(Self { _guard: guard }),
            Err(TryLockError::WouldBlock) => {
                bail!("direct_operation_lifecycle_busy_dispatch_denied")
            }
            Err(TryLockError::Poisoned(_)) => {
                bail!("direct_operation_lifecycle_lock_poisoned")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderSpecification {
    provider_id: &'static str,
    agent_id: &'static str,
    product_directory: &'static str,
    agent_uid: u32,
    agent_gid: u32,
}

#[derive(Debug)]
pub(crate) struct DirectOperationLifecycleReservation {
    provider: ProviderSpecification,
    guard: DirectOperationLifecycleGuard,
}

impl ProviderSpecification {
    fn from_verified_request(
        request: &PlanningRequest,
        runtime_binding: &RuntimeLifecycleBinding,
    ) -> Result<Self> {
        let rederived =
            RuntimeLifecycleBinding::from_verified_request(request, CODEX_FINAL_RUNTIME_SHA256)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if &rederived != runtime_binding {
            bail!("direct_operation_runtime_binding_not_rederived_from_verified_request");
        }
        if request.task_id != request.capability.claims.task_id {
            bail!("direct_operation_request_task_binding_mismatch");
        }
        Self::from_runtime(runtime_binding)
    }

    fn from_runtime(binding: &RuntimeLifecycleBinding) -> Result<Self> {
        let descriptor = agent_principal_registry::from_provider_agent_pair(
            &binding.provider_id,
            &binding.agent_id,
        )
        .ok_or_else(|| anyhow::anyhow!("direct_operation_provider_agent_identity_denied"))?;
        let product_directory = match descriptor.provider_id {
            CODEX_PROVIDER_ID => "codex",
            _ => bail!("direct_operation_provider_agent_identity_denied"),
        };
        let specification = Self {
            provider_id: descriptor.provider_id,
            agent_id: descriptor.agent_id,
            product_directory,
            agent_uid: descriptor.uid,
            agent_gid: descriptor.gid,
        };
        if binding.agent_peer_uid != specification.agent_uid
            || binding.agent_peer_gid != specification.agent_gid
        {
            bail!("direct_operation_provider_uid_gid_denied");
        }
        Ok(specification)
    }
}

#[derive(Debug, Clone)]
struct InboxLeafSpecification {
    path: PathBuf,
    owner_uid: u32,
    group_gid: u32,
    trusted_non_root_ancestor_uid: Option<u32>,
}

impl InboxLeafSpecification {
    fn product(provider: &ProviderSpecification, adapter_directory: &str) -> Self {
        Self {
            path: Path::new(PRODUCT_INBOX_ROOT)
                .join(provider.product_directory)
                .join(adapter_directory),
            owner_uid: ROOT_UID,
            group_gid: provider.agent_gid,
            trusted_non_root_ancestor_uid: None,
        }
    }
}

#[derive(Debug, Clone)]
struct PublisherLayout {
    daemon_uid: u32,
    override_leaf: Option<InboxLeafSpecification>,
}

impl PublisherLayout {
    fn product() -> Self {
        Self {
            daemon_uid: ROOT_UID,
            override_leaf: None,
        }
    }

    fn p0_system_api_leaf(&self, provider: &ProviderSpecification) -> InboxLeafSpecification {
        self.override_leaf
            .clone()
            .unwrap_or_else(|| InboxLeafSpecification::product(provider, "system-api"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishFaultPoint {
    BeforeFirstRename,
    AfterFirstRenameBeforeDirectoryFsync,
    AfterDirectoryFsync,
}

/// Fixed product publisher.  No constructor accepts a product path, provider,
/// Agent, UID/GID, or attempt value from environment/model material.
pub(crate) struct DirectOperationBindingInboxPublisher {
    layout: PublisherLayout,
    fault: Option<PublishFaultPoint>,
}

impl DirectOperationBindingInboxPublisher {
    #[must_use]
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn product() -> Self {
        Self {
            layout: PublisherLayout::product(),
            fault: None,
        }
    }

    /// Reserve the fixed provider lifecycle before durable attempt allocation.
    /// Contention and poison fail closed immediately; callers never wait while
    /// holding or consuming a new attempt generation.
    pub(crate) fn reserve_verified(
        &self,
        request: &PlanningRequest,
        runtime_binding: &RuntimeLifecycleBinding,
    ) -> Result<DirectOperationLifecycleReservation> {
        if unsafe { libc::geteuid() } != self.layout.daemon_uid {
            bail!("direct_operation_binding_publisher_requires_configured_daemon_uid");
        }
        let provider = ProviderSpecification::from_verified_request(request, runtime_binding)?;
        let guard = DirectOperationLifecycleGuard::try_acquire(&provider)?;
        Ok(DirectOperationLifecycleReservation { provider, guard })
    }

    /// Build and durably publish one Binding V3 to its sole P0 System API inbox
    /// under an already held request-bound reservation. Any error is a
    /// provider-spawn denial, including errors after rename.
    pub(crate) fn publish_reserved<S: DurableProviderAttemptSource>(
        &self,
        reservation: DirectOperationLifecycleReservation,
        request: &PlanningRequest,
        runtime_binding: &RuntimeLifecycleBinding,
        os_identity: &DirectOperationOsIdentity,
        attempt_source: &S,
    ) -> Result<DirectOperationInboxPublication> {
        if unsafe { libc::geteuid() } != self.layout.daemon_uid {
            bail!("direct_operation_binding_publisher_requires_configured_daemon_uid");
        }
        let requested_provider =
            ProviderSpecification::from_verified_request(request, runtime_binding)?;
        if requested_provider != reservation.provider {
            bail!("direct_operation_lifecycle_reservation_provider_mismatch");
        }
        let lifecycle_guard = reservation.guard;
        let (provider, envelope, encoded, mut publication, custody_identity) =
            build_binding_envelope(request, runtime_binding, os_identity, attempt_source)?;
        if provider != requested_provider {
            bail!("direct_operation_lifecycle_reservation_provider_mismatch");
        }
        if self.layout.override_leaf.is_none()
            && preflight_dedicated_uid(Some(provider.agent_uid)).map_err(anyhow::Error::msg)?
                != Some(true)
        {
            bail!("direct_operation_dedicated_uid_preflight_denied");
        }
        envelope
            .binding
            .authorized_adapter_set
            .validate_p0_system_api()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let leaf = self.layout.p0_system_api_leaf(&provider);
        let opened = open_inbox_leaf(&leaf)?;
        let mut staged = StagedInboxEntry::stage(opened, leaf, &encoded)?;

        self.fail_at(PublishFaultPoint::BeforeFirstRename)?;
        staged.rename_into_place()?;
        self.fail_at(PublishFaultPoint::AfterFirstRenameBeforeDirectoryFsync)?;
        let leaf_evidence = staged.sync_and_validate(&encoded)?;
        self.fail_at(PublishFaultPoint::AfterDirectoryFsync)?;

        // Re-walk the immutable configured paths and prove they still resolve
        // to the exact directory inodes used by renameat.
        staged.prove_configured_path_stable()?;
        envelope
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        publication.custody_seed = Some(DirectOperationInboxCustodySeed {
            binding_inbox: envelope,
            binding_inbox_bytes_sha256: sha256_bytes(&encoded),
            egress_grant_id_sha256: custody_identity.egress_grant_id_sha256,
            egress_journal_binding_sha256: custody_identity.egress_journal_binding_sha256,
            allocation_egress_cas_sha256: custody_identity.allocation_egress_cas_sha256,
            parent_directory_identity_sha256: leaf_evidence.parent_directory_identity_sha256,
            published_file_identity_sha256: leaf_evidence.published_file_identity_sha256,
            parent_directory_fsync_proof_sha256: leaf_evidence.parent_directory_fsync_proof_sha256,
        });
        publication._lifecycle_guard = Some(lifecycle_guard);
        Ok(publication)
    }

    #[cfg(test)]
    fn publish_verified<S: DurableProviderAttemptSource>(
        &self,
        request: &PlanningRequest,
        runtime_binding: &RuntimeLifecycleBinding,
        os_identity: &DirectOperationOsIdentity,
        attempt_source: &S,
    ) -> Result<DirectOperationInboxPublication> {
        let test_serial_guard = PUBLISHER_TEST_SERIAL_LOCK.lock().unwrap();
        let reservation = self.reserve_verified(request, runtime_binding)?;
        let mut publication = self.publish_reserved(
            reservation,
            request,
            runtime_binding,
            os_identity,
            attempt_source,
        )?;
        publication._test_serial_guard = Some(test_serial_guard);
        Ok(publication)
    }

    fn fail_at(&self, point: PublishFaultPoint) -> Result<()> {
        if self.fault == Some(point) {
            bail!("injected_direct_operation_binding_publish_failure:{point:?}");
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(leaf: PathBuf) -> Self {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        Self {
            layout: PublisherLayout {
                daemon_uid: uid,
                override_leaf: Some(InboxLeafSpecification {
                    path: leaf,
                    owner_uid: uid,
                    group_gid: gid,
                    trusted_non_root_ancestor_uid: Some(uid),
                }),
            },
            fault: None,
        }
    }

    #[cfg(test)]
    fn with_fault(mut self, point: PublishFaultPoint) -> Self {
        self.fault = Some(point);
        self
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DaemonAttemptContextCommitment<'a> {
    schema: &'a str,
    provider_id: &'a str,
    agent_id: &'a str,
    task_id: &'a str,
    runtime_lifecycle_binding_sha256: &'a str,
    attempt_generation: u64,
    durable_record_sha256: &'a str,
}

/// Rebuild the daemon-authored commitment that binds one durable provider
/// attempt to the exact egress-journal record which allocated it.  Keep this
/// projection in one place: the inbox publisher and later read-only custody
/// snapshots must never drift into two attempt-context hash algorithms.
pub(crate) fn daemon_attempt_context_sha256(
    provider_id: &str,
    agent_id: &str,
    task_id: &str,
    runtime_lifecycle_binding_sha256: &str,
    attempt_generation: u64,
    durable_record_sha256: &str,
) -> Result<String> {
    if agent_principal_registry::from_provider_agent_pair(provider_id, agent_id).is_none()
        || task_id.is_empty()
        || task_id.len() > 128
        || task_id.chars().any(char::is_control)
        || !is_lower_sha256(runtime_lifecycle_binding_sha256)
        || attempt_generation == 0
        || !is_lower_sha256(durable_record_sha256)
    {
        bail!("direct_operation_daemon_attempt_context_shape_denied");
    }
    let attempt_context = DaemonAttemptContextCommitment {
        schema: ATTEMPT_CONTEXT_SCHEMA,
        provider_id,
        agent_id,
        task_id,
        runtime_lifecycle_binding_sha256,
        attempt_generation,
        durable_record_sha256,
    };
    Ok(sha256_json(&serde_json::to_value(attempt_context)?))
}

fn build_binding_envelope<S: DurableProviderAttemptSource>(
    request: &PlanningRequest,
    runtime_binding: &RuntimeLifecycleBinding,
    os_identity: &DirectOperationOsIdentity,
    attempt_source: &S,
) -> Result<(
    ProviderSpecification,
    DirectOperationBindingInbox,
    Vec<u8>,
    DirectOperationInboxPublication,
    DirectOperationAttemptCustodyIdentity,
)> {
    let claims = &request.capability.claims;
    let provider = ProviderSpecification::from_verified_request(request, runtime_binding)?;
    os_identity.validate_for(request, runtime_binding)?;
    let runtime_lifecycle_binding_sha256 = runtime_binding
        .digest_sha256()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let query = DurableProviderAttemptQuery {
        provider_id: provider.provider_id.to_string(),
        agent_id: provider.agent_id.to_string(),
        task_id: request.task_id.clone(),
        runtime_lifecycle_binding_sha256: runtime_lifecycle_binding_sha256.clone(),
    };
    let durable_attempt = attempt_source.load_durable_attempt(&query)?;
    durable_attempt.validate_for(&query)?;
    let attempt_generation = durable_attempt.attempt_generation.get();
    let daemon_attempt_context_sha256 = daemon_attempt_context_sha256(
        provider.provider_id,
        provider.agent_id,
        &request.task_id,
        &runtime_lifecycle_binding_sha256,
        attempt_generation,
        &durable_attempt.durable_record_sha256,
    )?;
    let attempt = DirectOperationProviderAttempt::derive(
        runtime_lifecycle_binding_sha256,
        attempt_generation,
        daemon_attempt_context_sha256,
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let stable_seed = DirectOperationStableSeed {
        schema: STABLE_SEED_SCHEMA.to_string(),
        provider_id: provider.provider_id.to_string(),
        agent_id: provider.agent_id.to_string(),
        task_id: request.task_id.clone(),
        provider_invocation_id_sha256: runtime_binding.provider_invocation_id_sha256.clone(),
        provider_session_id_sha256: runtime_binding.provider_session_id_sha256.clone(),
        subject_uid: claims.subject_uid,
        subject_selinux_domain_sha256: claims.subject_selinux_domain_sha256.clone(),
    };
    let invocation_id = stable_seed
        .invocation_id()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let binding = DirectOperationBinding {
        schema: BINDING_SCHEMA.to_string(),
        stable_seed,
        invocation_id: invocation_id.clone(),
        workflow_id_sha256: os_identity.workflow_id_sha256.clone(),
        agent_identity_key_sha256: os_identity.agent_identity_key_sha256.clone(),
        agent_executable_sha256: os_identity.agent_executable_sha256.clone(),
        authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
        attempt,
    };
    let binding_sha256 = binding
        .digest_sha256()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let envelope = DirectOperationBindingInbox {
        schema: BINDING_INBOX_SCHEMA.to_string(),
        binding: binding.clone(),
        binding_sha256: binding_sha256.clone(),
    };
    envelope
        .validate()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let mut encoded = serde_json::to_vec(&envelope)?;
    encoded.push(b'\n');
    if encoded.len() > MAX_BINDING_BYTES || encoded[..encoded.len() - 1].contains(&b'\n') {
        bail!("direct_operation_binding_canonical_encoding_boundary_denied");
    }
    let launch = DirectOperationLaunchExpectation {
        binding_sha256,
        invocation_id,
        task_id: request.task_id.clone(),
        delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
    };
    let publication = DirectOperationInboxPublication {
        binding: binding.clone(),
        launch,
        custody_seed: None,
        _lifecycle_guard: None,
        #[cfg(test)]
        _test_serial_guard: None,
    };
    let custody_identity = DirectOperationAttemptCustodyIdentity {
        egress_grant_id_sha256: durable_attempt.egress_grant_id_sha256,
        egress_journal_binding_sha256: durable_attempt.egress_journal_binding_sha256,
        allocation_egress_cas_sha256: durable_attempt.durable_record_sha256,
    };
    Ok((provider, envelope, encoded, publication, custody_identity))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct EntryIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl EntryIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
            len: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    fn same_inode(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }
}

struct OpenInboxLeaf {
    directory: File,
    identity: EntryIdentity,
}

fn open_inbox_leaf(specification: &InboxLeafSpecification) -> Result<OpenInboxLeaf> {
    if !specification.path.is_absolute() {
        bail!("direct_operation_inbox_path_not_absolute");
    }
    let mut components = Vec::new();
    for component in specification.path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => components.push(secure_component(value)?),
            _ => bail!("direct_operation_inbox_path_component_denied"),
        }
    }
    if components.is_empty() {
        bail!("direct_operation_inbox_path_cannot_be_root");
    }
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    validate_trusted_ancestor(&directory, specification)
        .context("direct_operation_inbox_root_ancestor_denied")?;
    for (index, component) in components.iter().enumerate() {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("direct_operation_inbox_component_open_denied");
        }
        let next = unsafe { File::from_raw_fd(fd) };
        if index + 1 == components.len() {
            validate_inbox_leaf(&next, specification).with_context(|| {
                format!(
                    "direct_operation_inbox_leaf_denied:{}",
                    specification.path.display()
                )
            })?;
        } else {
            validate_trusted_ancestor(&next, specification).with_context(|| {
                format!(
                    "direct_operation_inbox_ancestor_denied:{}",
                    component.to_string_lossy()
                )
            })?;
        }
        directory = next;
    }
    let identity = EntryIdentity::from_metadata(&directory.metadata()?);
    Ok(OpenInboxLeaf {
        directory,
        identity,
    })
}

fn secure_component(component: &OsStr) -> Result<CString> {
    let bytes = component.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        bail!("direct_operation_inbox_component_denied");
    }
    CString::new(bytes).context("direct_operation_inbox_component_contains_nul")
}

fn validate_trusted_ancestor(
    directory: &File,
    specification: &InboxLeafSpecification,
) -> Result<()> {
    let metadata = directory.metadata()?;
    let owner_allowed = metadata.uid() == ROOT_UID
        || specification
            .trusted_non_root_ancestor_uid
            .is_some_and(|uid| metadata.uid() == uid);
    if !metadata.is_dir() || !owner_allowed || metadata.mode() & 0o022 != 0 || metadata.nlink() == 0
    {
        bail!(
            "direct_operation_inbox_ancestor_identity_denied:uid={}:mode={:o}:nlink={}:trusted_non_root={:?}",
            metadata.uid(),
            metadata.mode() & 0o7777,
            metadata.nlink(),
            specification.trusted_non_root_ancestor_uid
        );
    }
    Ok(())
}

fn validate_inbox_leaf(directory: &File, specification: &InboxLeafSpecification) -> Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != specification.owner_uid
        || metadata.gid() != specification.group_gid
        || metadata.mode() & 0o7777 != INBOX_LEAF_MODE
        || metadata.nlink() == 0
    {
        bail!("direct_operation_inbox_leaf_identity_denied");
    }
    Ok(())
}

fn entry_identity_at(directory: &File, name: &CStr) -> Result<Option<EntryIdentity>> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            // O_PATH inspects corrupt/special entries without opening a FIFO,
            // device, or socket for I/O.  The validated regular file is opened
            // normally only when its bytes must be read after publication.
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).context("direct_operation_inbox_entry_open_denied");
    }
    let file = unsafe { File::from_raw_fd(fd) };
    Ok(Some(EntryIdentity::from_metadata(&file.metadata()?)))
}

fn validate_binding_entry_identity(
    identity: &EntryIdentity,
    specification: &InboxLeafSpecification,
    expected_len: Option<usize>,
) -> Result<()> {
    if identity.mode & libc::S_IFMT != libc::S_IFREG
        || identity.uid != specification.owner_uid
        || identity.gid != specification.group_gid
        || identity.mode & 0o7777 != BINDING_FILE_MODE
        || identity.nlink != 1
        || identity.len > MAX_BINDING_BYTES as u64
        || expected_len.is_some_and(|length| identity.len != length as u64)
    {
        bail!("direct_operation_binding_file_identity_denied");
    }
    Ok(())
}

struct StagedInboxEntry {
    leaf: OpenInboxLeaf,
    specification: InboxLeafSpecification,
    temporary_name: CString,
    temporary_identity: EntryIdentity,
    destination_baseline: Option<EntryIdentity>,
    renamed: bool,
}

impl StagedInboxEntry {
    fn stage(
        leaf: OpenInboxLeaf,
        specification: InboxLeafSpecification,
        bytes: &[u8],
    ) -> Result<Self> {
        let destination_baseline = entry_identity_at(&leaf.directory, BINDING_FILE_NAME)?;
        if let Some(identity) = &destination_baseline {
            validate_binding_entry_identity(identity, &specification, None)?;
        }
        let temporary_name = temporary_name()?;
        let fd = unsafe {
            libc::openat(
                leaf.directory.as_raw_fd(),
                temporary_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("direct_operation_binding_temp_create_failed");
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let staged = (|| -> Result<EntryIdentity> {
            let initial = file.metadata()?;
            // Keep the staged name daemon-private while bytes are written.
            // Group readability is granted only after complete readback and
            // immediately before the atomic rename.
            if !initial.is_file()
                || initial.uid() != specification.owner_uid
                || initial.mode() & 0o077 != 0
                || initial.nlink() != 1
            {
                bail!("direct_operation_binding_initial_temp_identity_denied");
            }
            file.write_all(bytes)?;
            file.sync_all()?;
            file.seek(SeekFrom::Start(0))?;
            let mut observed = Vec::with_capacity(bytes.len());
            Read::by_ref(&mut file)
                .take(bytes.len() as u64 + 1)
                .read_to_end(&mut observed)?;
            if observed != bytes {
                bail!("direct_operation_binding_temp_readback_mismatch");
            }
            let identity_needs_chown = initial.uid() != specification.owner_uid
                || initial.gid() != specification.group_gid;
            if identity_needs_chown
                && unsafe {
                    libc::fchown(
                        file.as_raw_fd(),
                        specification.owner_uid,
                        specification.group_gid,
                    )
                } != 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("direct_operation_binding_temp_chown_failed");
            }
            if unsafe { libc::fchmod(file.as_raw_fd(), BINDING_FILE_MODE as libc::mode_t) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("direct_operation_binding_temp_chmod_failed");
            }
            file.sync_all()?;
            let identity = EntryIdentity::from_metadata(&file.metadata()?);
            validate_binding_entry_identity(&identity, &specification, Some(bytes.len()))?;
            Ok(identity)
        })();
        let temporary_identity = match staged {
            Ok(identity) => identity,
            Err(error) => {
                unsafe {
                    libc::unlinkat(leaf.directory.as_raw_fd(), temporary_name.as_ptr(), 0);
                }
                return Err(error);
            }
        };
        Ok(Self {
            leaf,
            specification,
            temporary_name,
            temporary_identity,
            destination_baseline,
            renamed: false,
        })
    }

    fn rename_into_place(&mut self) -> Result<()> {
        validate_inbox_leaf(&self.leaf.directory, &self.specification)?;
        let current = entry_identity_at(&self.leaf.directory, BINDING_FILE_NAME)?;
        if current != self.destination_baseline {
            bail!("direct_operation_binding_destination_changed_before_rename");
        }
        if unsafe {
            libc::renameat(
                self.leaf.directory.as_raw_fd(),
                self.temporary_name.as_ptr(),
                self.leaf.directory.as_raw_fd(),
                BINDING_FILE_NAME.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("direct_operation_binding_atomic_rename_failed");
        }
        self.renamed = true;
        Ok(())
    }

    fn sync_and_validate(&self, bytes: &[u8]) -> Result<DurableLeafPublicationEvidence> {
        self.leaf
            .directory
            .sync_all()
            .context("direct_operation_binding_parent_fsync_commit_unknown")?;
        let identity = entry_identity_at(&self.leaf.directory, BINDING_FILE_NAME)?
            .context("direct_operation_binding_disappeared_after_rename")?;
        // rename updates ctime while preserving the staged inode.
        if !identity.same_inode(&self.temporary_identity) {
            bail!("direct_operation_binding_published_inode_changed");
        }
        validate_binding_entry_identity(&identity, &self.specification, Some(bytes.len()))?;
        let fd = unsafe {
            libc::openat(
                self.leaf.directory.as_raw_fd(),
                BINDING_FILE_NAME.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("direct_operation_binding_published_open_failed");
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let opened_identity = EntryIdentity::from_metadata(&file.metadata()?);
        if opened_identity != identity {
            bail!("direct_operation_binding_changed_during_published_open");
        }
        let mut observed = Vec::with_capacity(bytes.len());
        file.take(bytes.len() as u64 + 1)
            .read_to_end(&mut observed)?;
        if observed != bytes {
            bail!("direct_operation_binding_published_bytes_changed");
        }
        let parent_identity = EntryIdentity::from_metadata(&self.leaf.directory.metadata()?);
        let parent_directory_identity_sha256 = sha256_bytes(&serde_json::to_vec(&parent_identity)?);
        let published_file_identity_sha256 = sha256_bytes(&serde_json::to_vec(&identity)?);
        let parent_directory_fsync_proof_sha256 = sha256_bytes(&serde_json::to_vec(&(
            "trillionnium.direct-operation-binding-parent-fsync-proof.v1",
            &parent_directory_identity_sha256,
            &published_file_identity_sha256,
            sha256_bytes(bytes),
        ))?);
        Ok(DurableLeafPublicationEvidence {
            parent_directory_identity_sha256,
            published_file_identity_sha256,
            parent_directory_fsync_proof_sha256,
        })
    }

    fn prove_configured_path_stable(&self) -> Result<()> {
        let reopened = open_inbox_leaf(&self.specification)?;
        // Publishing updates directory timestamps, but not its identity.
        if !reopened.identity.same_inode(&self.leaf.identity) {
            bail!("direct_operation_inbox_leaf_path_changed_during_publish");
        }
        Ok(())
    }
}

impl Drop for StagedInboxEntry {
    fn drop(&mut self) {
        if !self.renamed {
            unsafe {
                libc::unlinkat(
                    self.leaf.directory.as_raw_fd(),
                    self.temporary_name.as_ptr(),
                    0,
                );
            }
        }
    }
}

fn temporary_name() -> Result<CString> {
    let mut random = [0u8; 16];
    fill_kernel_random(&mut random)?;
    CString::new(
        format!(
            ".current-invocation.json.tmp-{}-{}",
            std::process::id(),
            sha256_bytes(&random)
        )
        .into_bytes(),
    )
    .context("direct_operation_binding_temp_name_invalid")
}

fn fill_kernel_random(bytes: &mut [u8]) -> Result<()> {
    let mut filled = 0usize;
    while filled < bytes.len() {
        let result = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if result > 0 {
            filled += usize::try_from(result)?;
            continue;
        }
        if result == 0 {
            bail!("direct_operation_binding_getrandom_returned_eof");
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("direct_operation_binding_getrandom_failed");
        }
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_nonzero_lower_sha256(value: &str) -> bool {
    is_lower_sha256(value) && value != ZERO_SHA256
}

fn exact_workflow_id(value: &str) -> bool {
    value
        .strip_prefix(WORKFLOW_ID_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == WORKFLOW_ID_HEX_BYTES
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt, symlink};

    use serde_json::Value;
    use tempfile::TempDir;
    use trillionnium_os_types::{AGENT_API_VERSION, AgentHealth, AgentNetworkPolicy};
    use trillionnium_tool_runtime::supervised_codex::{
        CapabilityClaims, PrivacyClass, ProvenanceContext, SignedCapabilityToken,
    };

    use super::*;

    #[derive(Clone)]
    struct FixtureAttemptSource {
        generation: u64,
        runtime_digest_override: Option<String>,
        record_digest: String,
    }

    impl DurableProviderAttemptSource for FixtureAttemptSource {
        fn load_durable_attempt(
            &self,
            query: &DurableProviderAttemptQuery,
        ) -> Result<DurableProviderAttemptRecord> {
            DurableProviderAttemptRecord::for_test(
                self.runtime_digest_override
                    .clone()
                    .unwrap_or_else(|| query.runtime_lifecycle_binding_sha256.clone()),
                self.generation,
                self.record_digest.clone(),
            )
        }
    }

    struct CountingAttemptSource {
        calls: Cell<usize>,
    }

    impl DurableProviderAttemptSource for CountingAttemptSource {
        fn load_durable_attempt(
            &self,
            query: &DurableProviderAttemptQuery,
        ) -> Result<DurableProviderAttemptRecord> {
            self.calls.set(self.calls.get() + 1);
            DurableProviderAttemptRecord::for_test(
                query.runtime_lifecycle_binding_sha256.clone(),
                1,
                digest(b"counted-durable-attempt-record"),
            )
        }
    }

    struct Fixture {
        _root: TempDir,
        system_api: PathBuf,
        accessibility: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
            // The workspace source tree is intentionally group-writable for
            // collaboration. Place security fixtures in its trusted,
            // non-group-writable parent so ancestor validation exercises the
            // success path rather than short-circuiting every test at that
            // unrelated mode bit.
            let fixture_parent = manifest.ancestors().nth(4).unwrap();
            let root = tempfile::Builder::new()
                .prefix(".direct-binding-publisher-test-")
                .tempdir_in(fixture_parent)
                .unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let provider = root.path().join("inbox/codex");
            let system_api = provider.join("system-api");
            let accessibility = provider.join("accessibility");
            fs::create_dir_all(&system_api).unwrap();
            fs::create_dir_all(&accessibility).unwrap();
            for directory in [root.path().join("inbox"), provider.clone()] {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o750)).unwrap();
            }
            for directory in [&system_api, &accessibility] {
                fs::set_permissions(directory, fs::Permissions::from_mode(INBOX_LEAF_MODE))
                    .unwrap();
            }
            Self {
                _root: root,
                system_api,
                accessibility,
            }
        }

        fn publisher(&self) -> DirectOperationBindingInboxPublisher {
            DirectOperationBindingInboxPublisher::for_test(self.system_api.clone())
        }

        fn files(&self) -> [PathBuf; 2] {
            [
                self.system_api.join(BINDING_FILE_NAME.to_str().unwrap()),
                self.accessibility.join(BINDING_FILE_NAME.to_str().unwrap()),
            ]
        }
    }

    fn digest(label: &[u8]) -> String {
        sha256_bytes(label)
    }

    const FIXTURE_WORKFLOW_ID: &str = "req-0123456789abcdef0123456789abcdef";

    fn request(provider_id: &str, agent_id: &str, uid_gid: u32) -> PlanningRequest {
        let captured = 1_000_000;
        let context = ProvenanceContext {
            source_id: "fixture-source".to_string(),
            source_kind: "android_fixture".to_string(),
            captured_at_unix_ms: captured,
            freshness_ttl_ms: 60_000,
            privacy_class: PrivacyClass::LocalPrivate,
            content: "fixture".to_string(),
        };
        let intent = "fixture intent".to_string();
        let descriptor = agent_principal_registry::from_agent_id(agent_id);
        let claims = CapabilityClaims {
            token_id: "cap-fixture".to_string(),
            task_id: "task-binding-fixture".to_string(),
            provider_id: provider_id.to_string(),
            agent_id: agent_id.to_string(),
            agent_peer_uid: uid_gid,
            agent_peer_gid: uid_gid,
            agent_selinux_domain_sha256: descriptor
                .map(|descriptor| sha256_bytes(descriptor.agent_selinux_domain.as_bytes()))
                .unwrap_or_else(|| digest(b"agent-domain")),
            agent_executable_sha256: descriptor
                .and_then(crate::builtin_provider_identity::active_launcher_identity)
                .map(str::to_string)
                .unwrap_or_else(|| digest(b"agent-executable")),
            agent_manifest_sha256: digest(b"agent-manifest"),
            subject_uid: 10_123,
            subject_selinux_domain_sha256: digest(b"subject-domain"),
            subject_user_id: 0,
            boot_id_sha256: digest(b"boot"),
            workflow_id_sha256: digest(FIXTURE_WORKFLOW_ID.as_bytes()),
            provider_invocation_id_sha256: digest(b"provider-invocation"),
            provider_session_id_sha256: digest(b"provider-session"),
            context_id_sha256: digest(b"context-id"),
            context_kind: context.source_kind.clone(),
            context_captured_at_ms: captured,
            context_expires_at_ms: captured + 60_000,
            context_sha256: digest(context.content.as_bytes()),
            source_id_sha256: digest(context.source_id.as_bytes()),
            privacy_class: "local_private".to_string(),
            content_bytes: context.content.len() as u64,
            intent_sha256: digest(intent.as_bytes()),
            intent_bytes: intent.len() as u64,
            allowed_actions: Vec::new(),
            allowed_actions_sha256: sha256_bytes(b"[]"),
            prompt_contract: "fixture-contract".to_string(),
            prompt_contract_version: 1,
            egress_grant_id: "egress-fixture".to_string(),
            consent_challenge_sha256: digest(b"challenge"),
            consent_receipt_id: digest(b"receipt"),
            journal_binding_sha256: digest(b"journal-binding"),
            teardown_nonce_sha256: digest(b"teardown"),
            issued_at_unix_ms: captured + 1,
            expires_at_unix_ms: captured + 60_000,
            network_approved: true,
            egress_endpoint: "chatgpt.com:443".to_string(),
            egress_upload_byte_limit: 1024,
            egress_download_byte_limit: 1024,
            egress_expires_at_unix_ms: captured + 59_000,
            nonce: "nonce-fixture".to_string(),
        };
        PlanningRequest {
            task_id: claims.task_id.clone(),
            intent,
            contexts: vec![context],
            capability: SignedCapabilityToken {
                claims,
                signature_sha256: digest(b"signature"),
            },
        }
    }

    fn codex_request_and_binding() -> (PlanningRequest, RuntimeLifecycleBinding) {
        let request = request(CODEX_PROVIDER_ID, CODEX_AGENT_ID, CODEX_UID_GID);
        let binding =
            RuntimeLifecycleBinding::from_verified_request(&request, CODEX_FINAL_RUNTIME_SHA256)
                .unwrap();
        (request, binding)
    }

    fn registration(request: &PlanningRequest) -> AgentRegistration {
        let claims = &request.capability.claims;
        let descriptor = agent_principal_registry::from_agent_id(&claims.agent_id).unwrap();
        AgentRegistration {
            api_version: AGENT_API_VERSION.to_string(),
            agent_id: claims.agent_id.clone(),
            adapter: descriptor.runtime_adapter.to_string(),
            adapter_version: "1".to_string(),
            identity_key_sha256: claims.agent_executable_sha256.clone(),
            peer_uid: claims.agent_peer_uid,
            peer_gid: claims.agent_peer_gid,
            selinux_domain: descriptor.agent_selinux_domain.to_string(),
            network_policy: AgentNetworkPolicy::Deny,
            enabled: true,
            health: AgentHealth::Ready,
            registered_at_unix_ms: 1,
            updated_at_unix_ms: 1,
        }
    }

    fn os_identity_for(request: &PlanningRequest, workflow_id: &str) -> DirectOperationOsIdentity {
        let claims = &request.capability.claims;
        let registration = registration(request);
        DirectOperationOsIdentity::from_registered_agent(
            workflow_id,
            &registration,
            &claims.agent_executable_sha256,
        )
        .unwrap()
    }

    fn os_identity(request: &PlanningRequest) -> DirectOperationOsIdentity {
        os_identity_for(request, FIXTURE_WORKFLOW_ID)
    }

    fn build_fixture_envelope<S: DurableProviderAttemptSource>(
        request: &PlanningRequest,
        binding: &RuntimeLifecycleBinding,
        source: &S,
    ) -> Result<(
        ProviderSpecification,
        DirectOperationBindingInbox,
        Vec<u8>,
        DirectOperationInboxPublication,
        DirectOperationAttemptCustodyIdentity,
    )> {
        build_binding_envelope(request, binding, &os_identity(request), source)
    }

    fn source(generation: u64) -> FixtureAttemptSource {
        FixtureAttemptSource {
            generation,
            runtime_digest_override: None,
            record_digest: digest(b"durable-attempt-record"),
        }
    }

    fn read_envelope(path: &Path) -> (Vec<u8>, DirectOperationBindingInbox) {
        let bytes = fs::read(path).unwrap();
        let envelope = serde_json::from_slice::<DirectOperationBindingInbox>(&bytes).unwrap();
        (bytes, envelope)
    }

    #[test]
    fn publishes_one_canonical_system_api_inbox_and_no_accessibility_inbox() {
        let fixture = Fixture::new();
        let (request, binding) = codex_request_and_binding();
        let mut publication = fixture
            .publisher()
            .publish_verified(&request, &binding, &os_identity(&request), &source(7))
            .unwrap();
        let files = fixture.files();
        let (first_bytes, first) = read_envelope(&files[0]);
        assert!(!files[1].exists());
        assert_eq!(first.binding, publication.binding);
        assert_eq!(
            first.binding.workflow_id_sha256,
            sha256_bytes(FIXTURE_WORKFLOW_ID.as_bytes())
        );
        assert_eq!(
            first.binding.agent_identity_key_sha256,
            request.capability.claims.agent_executable_sha256
        );
        assert_eq!(
            first.binding.agent_executable_sha256,
            binding.agent_executable_sha256
        );
        assert_eq!(first.binding_sha256, publication.launch.binding_sha256);
        assert_eq!(
            first.binding.invocation_id,
            publication.launch.invocation_id
        );
        assert_eq!(
            first.binding.attempt.delivery_provider_attempt_id,
            publication.launch.delivery_provider_attempt_id
        );
        let mut canonical = serde_json::to_vec(&first).unwrap();
        canonical.push(b'\n');
        assert_eq!(first_bytes, canonical);
        assert_eq!(first_bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
        let custody_seed = publication.take_custody_seed().unwrap();
        assert_eq!(custody_seed.binding_inbox, first);
        assert_eq!(
            custody_seed.binding_inbox_bytes_sha256,
            sha256_bytes(&first_bytes)
        );
        assert_eq!(
            custody_seed.allocation_egress_cas_sha256,
            digest(b"durable-attempt-record")
        );
        assert_eq!(
            custody_seed.egress_grant_id_sha256,
            sha256_bytes(b"fixture-egress-grant-id")
        );
        assert_eq!(
            custody_seed.egress_journal_binding_sha256,
            sha256_bytes(b"fixture-egress-journal-binding")
        );
        assert!(is_nonzero_lower_sha256(
            &custody_seed.parent_directory_identity_sha256
        ));
        assert!(is_nonzero_lower_sha256(
            &custody_seed.published_file_identity_sha256
        ));
        assert!(is_nonzero_lower_sha256(
            &custody_seed.parent_directory_fsync_proof_sha256
        ));
        assert!(publication.take_custody_seed().is_err());

        assert!(CODEX_DIRECT_LIFECYCLE_LOCK.try_lock().is_err());
        drop(publication);
        assert!(CODEX_DIRECT_LIFECYCLE_LOCK.try_lock().is_ok());

        let replacement = fixture
            .publisher()
            .publish_verified(&request, &binding, &os_identity(&request), &source(8))
            .unwrap();
        let (replaced_first_bytes, replaced_first) = read_envelope(&files[0]);
        assert_ne!(first_bytes, replaced_first_bytes);
        assert!(!files[1].exists());
        assert_eq!(
            replaced_first.binding_sha256,
            replacement.launch.binding_sha256
        );
        let metadata = fs::metadata(&files[0]).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.gid(), unsafe { libc::getegid() });
        assert_eq!(metadata.mode() & 0o7777, BINDING_FILE_MODE);
        assert_eq!(metadata.nlink(), 1);
    }

    #[test]
    fn lifecycle_contention_fails_before_attempt_load_or_inbox_mutation() {
        let _test_serial_guard = PUBLISHER_TEST_SERIAL_LOCK.lock().unwrap();
        let fixture = Fixture::new();
        let publisher = fixture.publisher();
        let (request, binding) = codex_request_and_binding();
        let reservation = publisher.reserve_verified(&request, &binding).unwrap();
        let attempt_source = CountingAttemptSource {
            calls: Cell::new(0),
        };
        let files = fixture.files();
        assert!(files.iter().all(|path| !path.exists()));

        let error = publisher.reserve_verified(&request, &binding).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("direct_operation_lifecycle_busy_dispatch_denied")
        );
        assert_eq!(attempt_source.calls.get(), 0);
        assert!(files.iter().all(|path| !path.exists()));
        drop(reservation);
    }

    #[test]
    fn generation_changes_attempt_but_not_stable_invocation() {
        let (request, binding) = codex_request_and_binding();
        let first = build_fixture_envelope(&request, &binding, &source(7))
            .unwrap()
            .1;
        let second = build_fixture_envelope(&request, &binding, &source(8))
            .unwrap()
            .1;
        assert_eq!(first.binding.invocation_id, second.binding.invocation_id);
        assert_ne!(
            first.binding.attempt.delivery_provider_attempt_id,
            second.binding.attempt.delivery_provider_attempt_id
        );
        assert_ne!(first.binding_sha256, second.binding_sha256);
    }

    #[test]
    fn exact_retry_keeps_v3_binding_and_canonical_inbox_stable() {
        let (request, binding) = codex_request_and_binding();
        let first = build_fixture_envelope(&request, &binding, &source(7)).unwrap();
        let second = build_fixture_envelope(&request, &binding, &source(7)).unwrap();
        assert_eq!(first.1, second.1);
        assert_eq!(first.2, second.2);
        assert_eq!(first.3.binding, second.3.binding);
        assert_eq!(first.3.launch, second.3.launch);
    }

    #[test]
    fn os_identity_source_requires_exact_workflow_registration_and_measurement() {
        let (request, binding) = codex_request_and_binding();
        let registration = registration(&request);
        let executable = request.capability.claims.agent_executable_sha256.as_str();
        let identity = DirectOperationOsIdentity::from_registered_agent(
            FIXTURE_WORKFLOW_ID,
            &registration,
            executable,
        )
        .unwrap();
        build_binding_envelope(&request, &binding, &identity, &source(1)).unwrap();

        for malformed in [
            "workflow-0123456789abcdef0123456789abcdef",
            "req-0123456789abcdef0123456789abcde",
            "req-0123456789ABCDEF0123456789ABCDEF",
            "req-0123456789abcdef0123456789abcdef0",
        ] {
            assert!(
                DirectOperationOsIdentity::from_registered_agent(
                    malformed,
                    &registration,
                    executable,
                )
                .is_err()
            );
        }

        for malformed in [ZERO_SHA256.to_string(), "A".repeat(64), "a".repeat(63)] {
            let mut changed = registration.clone();
            changed.identity_key_sha256 = malformed;
            assert!(
                DirectOperationOsIdentity::from_registered_agent(
                    FIXTURE_WORKFLOW_ID,
                    &changed,
                    executable,
                )
                .is_err()
            );
        }
        assert!(
            DirectOperationOsIdentity::from_registered_agent(
                FIXTURE_WORKFLOW_ID,
                &registration,
                &digest(b"different-executable"),
            )
            .is_err()
        );
    }

    #[test]
    fn signed_claim_or_runtime_identity_drift_is_denied_before_attempt_load() {
        let (request, binding) = codex_request_and_binding();
        let identity = os_identity(&request);
        let counting = CountingAttemptSource {
            calls: Cell::new(0),
        };

        let mut workflow_drift = identity.clone();
        workflow_drift.workflow_id_sha256 = digest(b"other-workflow");
        assert!(build_binding_envelope(&request, &binding, &workflow_drift, &counting).is_err());

        let mut registration_drift = identity.clone();
        registration_drift.agent_identity_key_sha256 = digest(b"other-registration");
        assert!(
            build_binding_envelope(&request, &binding, &registration_drift, &counting).is_err()
        );

        let mut executable_drift = identity;
        executable_drift.agent_executable_sha256 = digest(b"other-executable");
        assert!(build_binding_envelope(&request, &binding, &executable_drift, &counting).is_err());
        assert_eq!(counting.calls.get(), 0);
    }

    #[test]
    fn missing_zero_or_cross_lifecycle_attempt_generation_fails_closed() {
        let (request, binding) = codex_request_and_binding();
        assert!(build_fixture_envelope(&request, &binding, &source(0)).is_err());
        let cross = FixtureAttemptSource {
            generation: 1,
            runtime_digest_override: Some(digest(b"other-runtime")),
            record_digest: digest(b"durable-attempt-record"),
        };
        assert!(build_fixture_envelope(&request, &binding, &cross).is_err());
    }

    #[test]
    fn request_runtime_provider_agent_and_uid_mismatches_are_denied() {
        let (codex_request, binding) = codex_request_and_binding();
        let mut changed = binding.clone();
        changed.provider_session_id_sha256 = digest(b"changed-session");
        assert!(build_fixture_envelope(&codex_request, &changed, &source(1)).is_err());

        let mut task_changed = codex_request.clone();
        task_changed.task_id = "task-other".to_string();
        assert!(build_fixture_envelope(&task_changed, &binding, &source(1)).is_err());

        let bad_agent = request(CODEX_PROVIDER_ID, "unregistered-agent", CODEX_UID_GID);
        let bad_agent_binding =
            RuntimeLifecycleBinding::from_verified_request(&bad_agent, CODEX_FINAL_RUNTIME_SHA256)
                .unwrap();
        let codex_identity = os_identity(&codex_request);
        assert!(
            build_binding_envelope(&bad_agent, &bad_agent_binding, &codex_identity, &source(1),)
                .is_err()
        );

        let bad_uid = request(CODEX_PROVIDER_ID, CODEX_AGENT_ID, CODEX_UID_GID + 1);
        let bad_uid_binding =
            RuntimeLifecycleBinding::from_verified_request(&bad_uid, CODEX_FINAL_RUNTIME_SHA256)
                .unwrap();
        assert!(
            build_binding_envelope(&bad_uid, &bad_uid_binding, &codex_identity, &source(1),)
                .is_err()
        );
    }

    #[test]
    fn malicious_leaf_destination_and_hardlink_are_denied_without_publication() {
        let (request, binding) = codex_request_and_binding();

        let symlink_fixture = Fixture::new();
        let symlink_target = symlink_fixture._root.path().join("outside");
        fs::write(&symlink_target, b"outside").unwrap();
        symlink(
            &symlink_target,
            symlink_fixture.system_api.join("current-invocation.json"),
        )
        .unwrap();
        assert!(
            symlink_fixture
                .publisher()
                .publish_verified(&request, &binding, &os_identity(&request), &source(1))
                .is_err()
        );
        assert_eq!(fs::read(symlink_target).unwrap(), b"outside");
        assert!(!symlink_fixture.files()[1].exists());

        let hardlink_fixture = Fixture::new();
        let first = hardlink_fixture.files()[0].clone();
        fs::write(&first, b"old").unwrap();
        fs::set_permissions(&first, fs::Permissions::from_mode(BINDING_FILE_MODE)).unwrap();
        fs::hard_link(&first, hardlink_fixture._root.path().join("alias")).unwrap();
        assert!(
            hardlink_fixture
                .publisher()
                .publish_verified(&request, &binding, &os_identity(&request), &source(1))
                .is_err()
        );
        assert_eq!(fs::read(first).unwrap(), b"old");
    }

    #[test]
    fn non_regular_or_wrong_mode_destination_is_denied_without_blocking_or_replacement() {
        let (request, binding) = codex_request_and_binding();

        let fifo_fixture = Fixture::new();
        let fifo = fifo_fixture.files()[0].clone();
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(fifo_name.as_ptr(), BINDING_FILE_MODE as libc::mode_t) },
            0
        );
        assert!(
            fifo_fixture
                .publisher()
                .publish_verified(&request, &binding, &os_identity(&request), &source(1))
                .is_err()
        );
        assert!(fs::symlink_metadata(fifo).unwrap().file_type().is_fifo());

        let mode_fixture = Fixture::new();
        let wrong_mode = mode_fixture.files()[0].clone();
        fs::write(&wrong_mode, b"old").unwrap();
        fs::set_permissions(&wrong_mode, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            mode_fixture
                .publisher()
                .publish_verified(&request, &binding, &os_identity(&request), &source(1))
                .is_err()
        );
        assert_eq!(fs::read(wrong_mode).unwrap(), b"old");
    }

    #[test]
    fn symlink_leaf_and_wrong_leaf_mode_fail_closed() {
        let (request, binding) = codex_request_and_binding();
        let fixture = Fixture::new();
        let substitute = fixture._root.path().join("substitute");
        fs::create_dir(&substitute).unwrap();
        fs::set_permissions(&substitute, fs::Permissions::from_mode(INBOX_LEAF_MODE)).unwrap();
        fs::remove_dir(&fixture.system_api).unwrap();
        symlink(&substitute, &fixture.system_api).unwrap();
        assert!(
            fixture
                .publisher()
                .publish_verified(&request, &binding, &os_identity(&request), &source(1))
                .is_err()
        );

        let fixture = Fixture::new();
        fs::set_permissions(&fixture.system_api, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(
            fixture
                .publisher()
                .publish_verified(&request, &binding, &os_identity(&request), &source(1))
                .is_err()
        );
    }

    #[test]
    fn precommit_fault_leaves_old_inboxes_and_cleans_owned_temporaries() {
        let fixture = Fixture::new();
        let (request, binding) = codex_request_and_binding();
        let files = fixture.files();
        fs::write(&files[0], b"old").unwrap();
        fs::set_permissions(&files[0], fs::Permissions::from_mode(BINDING_FILE_MODE)).unwrap();
        let publisher = fixture
            .publisher()
            .with_fault(PublishFaultPoint::BeforeFirstRename);
        assert!(
            publisher
                .publish_verified(&request, &binding, &os_identity(&request), &source(1))
                .is_err()
        );
        let entries = fs::read_dir(&fixture.system_api)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, [OsStr::new("current-invocation.json")]);
        assert_eq!(fs::read(&files[0]).unwrap(), b"old");
        assert_eq!(fs::read_dir(&fixture.accessibility).unwrap().count(), 0);
    }

    #[test]
    fn p0_publication_never_writes_accessibility_leaf() {
        let fixture = Fixture::new();
        let (request, binding) = codex_request_and_binding();
        fs::write(fixture.accessibility.join("sentinel"), b"untouched").unwrap();
        let publication = fixture
            .publisher()
            .publish_verified(&request, &binding, &os_identity(&request), &source(1))
            .unwrap();
        let files = fixture.files();
        assert!(files[0].is_file());
        assert!(!files[1].exists());
        assert_eq!(
            fs::read(fixture.accessibility.join("sentinel")).unwrap(),
            b"untouched"
        );
        assert_eq!(fs::read_dir(&fixture.accessibility).unwrap().count(), 1);
        drop(publication);
    }

    #[test]
    fn post_rename_commit_unknown_fault_is_always_an_error() {
        let (request, binding) = codex_request_and_binding();
        for point in [
            PublishFaultPoint::AfterFirstRenameBeforeDirectoryFsync,
            PublishFaultPoint::AfterDirectoryFsync,
        ] {
            let fixture = Fixture::new();
            assert!(
                fixture
                    .publisher()
                    .with_fault(point)
                    .publish_verified(&request, &binding, &os_identity(&request), &source(1))
                    .is_err()
            );
        }
    }

    #[test]
    fn product_paths_are_fixed_to_the_chroot_visible_bind_target() {
        for (provider, directory, gid) in [(
            ProviderSpecification {
                provider_id: CODEX_PROVIDER_ID,
                agent_id: CODEX_AGENT_ID,
                product_directory: "codex",
                agent_uid: CODEX.uid,
                agent_gid: CODEX.gid,
            },
            "codex",
            CODEX_UID_GID,
        )] {
            let leaf = PublisherLayout::product().p0_system_api_leaf(&provider);
            assert_eq!(
                leaf.path,
                Path::new("/var/lib/trillionnium/agent-tools/inbox")
                    .join(directory)
                    .join("system-api")
            );
            assert_eq!(leaf.owner_uid, ROOT_UID);
            assert_eq!(leaf.group_gid, gid);
            assert!(!leaf.path.starts_with("/data/trillionnium"));
        }
    }

    #[test]
    fn lifecycle_try_reservation_and_uid_drain_precede_product_inbox_mutation() {
        let source = include_str!("direct_operation_binding_inbox.rs");
        let reserve = source
            .split_once("pub(crate) fn reserve_verified")
            .unwrap()
            .1
            .split_once("pub(crate) fn publish_reserved")
            .unwrap()
            .0;
        assert!(reserve.contains("DirectOperationLifecycleGuard::try_acquire"));
        let publish = source
            .split_once("pub(crate) fn publish_reserved")
            .unwrap()
            .1
            .split_once("#[cfg(test)]\n    fn publish_verified")
            .unwrap()
            .0;
        assert!(!publish.contains("DirectOperationLifecycleGuard::try_acquire"));
        let verify_provider = publish.find("provider != reservation.provider").unwrap();
        let build = publish.find("build_binding_envelope").unwrap();
        let drain = publish.find("preflight_dedicated_uid").unwrap();
        let open = publish.find("open_inbox_leaf").unwrap();
        let attach_guard = publish
            .find("publication._lifecycle_guard = Some(lifecycle_guard)")
            .unwrap();
        assert!(verify_provider < build);
        assert!(build < drain);
        assert!(drain < open);
        assert!(open < attach_guard);
    }

    #[test]
    fn encoded_envelope_contains_no_raw_request_or_environment_path_material() {
        let (mut request, _) = codex_request_and_binding();
        request.intent = "TOP_SECRET_INTENT".to_string();
        request.contexts[0].content = "TOP_SECRET_CONTEXT".to_string();
        let binding =
            RuntimeLifecycleBinding::from_verified_request(&request, CODEX_FINAL_RUNTIME_SHA256)
                .unwrap();
        let encoded = build_fixture_envelope(&request, &binding, &source(1))
            .unwrap()
            .2;
        let rendered = String::from_utf8(encoded).unwrap();
        assert!(!rendered.contains("TOP_SECRET_INTENT"));
        assert!(!rendered.contains("TOP_SECRET_CONTEXT"));
        assert!(!rendered.contains(PRODUCT_INBOX_ROOT));
        let parsed: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(
            parsed["schema"],
            Value::String(BINDING_INBOX_SCHEMA.to_string())
        );
        let binding = parsed["binding"].as_object().unwrap();
        assert_eq!(binding.len(), 8);
        assert_eq!(
            binding["authorized_adapter_set"],
            serde_json::json!({
                "schema": trillionnium_os_types::direct_operation::AUTHORIZED_ADAPTER_SET_V3_SCHEMA,
                "authorized_adapters": ["system_api"],
                "authorized_adapters_sha256": trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api()
                    .authorized_adapters_sha256,
            })
        );
        for field in [
            "workflow_id_sha256",
            "agent_identity_key_sha256",
            "agent_executable_sha256",
            "authorized_adapter_set",
        ] {
            assert!(binding.contains_key(field));
            assert!(
                !binding["stable_seed"]
                    .as_object()
                    .unwrap()
                    .contains_key(field)
            );
            assert!(!binding["attempt"].as_object().unwrap().contains_key(field));
        }
    }
}
