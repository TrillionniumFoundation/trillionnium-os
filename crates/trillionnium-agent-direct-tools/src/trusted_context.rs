//! Trusted, read-only invocation binding intake for direct adapters.
//!
//! Product paths are derived exclusively from the effective UID and the
//! compile-time adapter kind. Model arguments and environment variables cannot
//! select a provider, identity, journal path, inbox path, or binding. The
//! daemon-written inbox and adapter-written journal are deliberately separate
//! custody domains.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[cfg(any(test, feature = "production-durable-hotpath"))]
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_os_types::agent_principal_registry::{
    self, ACCESSIBILITY_ENDPOINT, CODEX_STABLE_PRINCIPAL, SYSTEM_API_ENDPOINT,
};
#[cfg(feature = "production-durable-hotpath")]
use trillionnium_os_types::direct_operation::DirectOperationKernelLaunchCustodyV3;
use trillionnium_os_types::direct_operation::{
    DirectOperationAdapter, DirectOperationBinding, DirectOperationBindingInbox,
    DirectOperationOuterAckInboxV3,
};
#[cfg(any(test, feature = "production-durable-hotpath"))]
use trillionnium_os_types::direct_operation::{
    DirectOperationToolCallAllocationRequestV3, DirectOperationToolCallDeliveryV3,
    DirectOperationToolCallEnvelopeV3, DirectOperationUncorrelatedToolCallAllocationRequestV3,
};

#[cfg(test)]
const CODEX_UID: u32 = CODEX_STABLE_PRINCIPAL.uid;
#[cfg(test)]
const CODEX_GID: u32 = CODEX_STABLE_PRINCIPAL.gid;
#[cfg(test)]
const CODEX_PROVIDER_ID: &str = CODEX_STABLE_PRINCIPAL.provider_id;
#[cfg(test)]
const CODEX_AGENT_ID: &str = CODEX_STABLE_PRINCIPAL.agent_id;
const SYSTEM_API_DOMAIN: &str = SYSTEM_API_ENDPOINT.tool_selinux_domain;
const ACCESSIBILITY_DOMAIN: &str = ACCESSIBILITY_ENDPOINT.tool_selinux_domain;
const SYSTEM_API_OPERATION_REPLAY_SYNC_DOMAIN: &str =
    SYSTEM_API_ENDPOINT.operation_replay_sync_selinux_domain;
const ACCESSIBILITY_OPERATION_REPLAY_SYNC_DOMAIN: &str =
    ACCESSIBILITY_ENDPOINT.operation_replay_sync_selinux_domain;
const SYSTEM_API_OPERATION_REPLAY_SYNC_BINARY: &str =
    "/system_ext/bin/trillionnium-system-api-operation-replay-sync";
const ACCESSIBILITY_OPERATION_REPLAY_SYNC_BINARY: &str =
    "/system_ext/bin/trillionnium-accessibility-operation-replay-sync";
#[cfg(feature = "device-launch-package-conformance")]
const SYSTEM_API_DEVICE_CONFORMANCE_REPLAY_SYNC_BINARY: &str =
    "/usr/local/bin/trillionnium-system-api-device-conformance-replay-sync";
const PRODUCT_STATE_ROOT: &str = "/var/lib/trillionnium/agent-tools/state";
const PRODUCT_INBOX_ROOT: &str = "/var/lib/trillionnium/agent-tools/inbox";
const JOURNAL_FILE_NAME: &str = "operations.json";
#[cfg(feature = "device-launch-package-conformance")]
const DEVICE_CONFORMANCE_JOURNAL_FILE_NAME: &str = "p01-launch-package-operations.json";
#[cfg(feature = "production-durable-hotpath")]
const KERNEL_LAUNCH_CUSTODY_V3_FILE_NAME: &CStr = c"kernel-launch-custody-v3.json";
const OUTER_ACK_V3_FILE_NAME: &CStr = c"pending-outer-ack-v3.json";
const MAX_BINDING_BYTES: u64 = 32 * 1024;
#[cfg(feature = "production-durable-hotpath")]
const MAX_KERNEL_LAUNCH_CUSTODY_BYTES: u64 = 32 * 1024;
const MAX_OUTER_ACK_BYTES: u64 = 256 * 1024;
#[cfg(any(test, feature = "production-durable-hotpath"))]
const MAX_PROC_CGROUP_BYTES: u64 = 4 * 1024;
#[cfg(feature = "production-durable-hotpath")]
const MAX_PROC_IDENTITY_BYTES: u64 = 4 * 1024;
#[cfg(feature = "production-durable-hotpath")]
const MAX_ADAPTER_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const PROC_SUPER_MAGIC: u64 = 0x0000_9fa0;

pub type TrustedContextResult<T> = Result<T, TrustedContextError>;

#[derive(Debug, Error)]
pub enum TrustedContextError {
    #[error("trusted adapter identity is invalid: {0}")]
    Identity(&'static str),
    #[error("trusted adapter path is invalid: {0}")]
    Path(&'static str),
    #[error("trusted adapter inbox is corrupt: {0}")]
    Corrupt(String),
    #[error("trusted adapter binding digest does not match the fixed launch expectation")]
    BindingDigestMismatch,
    #[error("trusted adapter kernel launch custody is unavailable: {0}")]
    KernelCustody(String),
    #[error(
        "OS-owned per-logical-call allocation authority is unavailable; product tool effect held"
    )]
    ToolCallAllocationUnavailable,
    #[error(
        "daemon-sealed operation replay-sync launch challenge and rollback authority are unavailable; helper held"
    )]
    ReplaySyncLaunchAuthorityUnavailable,
    #[error(
        "pending outer ACK requires the dedicated endpoint operation replay-sync helper; tool effect held"
    )]
    PendingOuterAckRequiresReplaySync,
    #[error("trusted adapter I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("trusted adapter binding JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Source-level boundary for the future daemon/root logical-call allocator.
/// The adapter supplies only an authenticated binding and canonical digest;
/// the authority chooses the token and contiguous ordinal. Product binaries do
/// not accept an implementation from arguments, environment, plugins, or the
/// Agent process. The V3 uncorrelated allocation request explicitly declares
/// that durable
/// upstream retry correlation is absent; implementations in this source seam
/// are test fixtures only. The daemon now has a separate durable V3 delivery
/// contract/ledger, but Codex MCP does not currently carry its
/// root-authored delivery envelope through an authenticated adapter transport.
/// Until that transport and external rollback high-water exist, this V3 seam
/// remains deliberately unconstructible in product and canonical content is
/// never used to guess retry identity.
#[cfg(any(test, feature = "production-durable-hotpath"))]
#[allow(dead_code)]
pub(crate) trait ToolCallAllocationAuthority {
    fn allocate(
        &mut self,
        request: &DirectOperationUncorrelatedToolCallAllocationRequestV3,
    ) -> TrustedContextResult<DirectOperationToolCallEnvelopeV3>;
}

/// Closed adapter-side contract for the daemon-owned durable V3 logical-call
/// allocator. The exact daemon delivery is authenticated before canonical
/// content exists; the adapter later supplies only that delivery plus the
/// canonical digest. Equal content under a new delivery remains a new call,
/// while an exact delivery retry must recover the same envelope.
///
/// This trait is injectable only for source tests today. The product has no
/// root-authenticated daemon transport or rollback-high-water constructor.
#[cfg(any(test, feature = "production-durable-hotpath"))]
#[allow(dead_code)]
pub(crate) trait ToolCallAllocationAuthorityV3 {
    fn allocate(
        &mut self,
        delivery: &DirectOperationToolCallDeliveryV3,
        request: &DirectOperationToolCallAllocationRequestV3,
    ) -> TrustedContextResult<DirectOperationToolCallEnvelopeV3>;
}

/// Sealed adapter-side proof that the delivery crossed the future fixed
/// daemon transport under OS peer/cgroup/SELinux custody. Raw JSON or a
/// provider/model-supplied delivery cannot construct this type.
#[cfg(any(test, feature = "production-durable-hotpath"))]
#[allow(dead_code)]
pub(crate) struct VerifiedDaemonToolCallDelivery {
    delivery: DirectOperationToolCallDeliveryV3,
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
impl VerifiedDaemonToolCallDelivery {
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn for_test(
        delivery: DirectOperationToolCallDeliveryV3,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> TrustedContextResult<Self> {
        delivery
            .validate_for(binding, binding_sha256, adapter)
            .map_err(|error| TrustedContextError::Corrupt(error.to_string()))?;
        Ok(Self { delivery })
    }
}

/// Construct and validate one typed per-call allocation through an injected
/// authority. This is testable source plumbing for the future OS transport;
/// the current product has no constructible authority and uses the explicit
/// HOLD in [`TrustedAdapterContext::allocate_product_tool_call`].
#[cfg(any(test, feature = "production-durable-hotpath"))]
#[allow(dead_code)]
pub(crate) fn allocate_tool_call_with_authority(
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    canonical_request: &[u8],
    authority: &mut impl ToolCallAllocationAuthority,
) -> TrustedContextResult<DirectOperationToolCallEnvelopeV3> {
    let request =
        tool_call_allocation_request(binding, binding_sha256, adapter, canonical_request)?;
    let envelope = authority.allocate(&request)?;
    envelope
        .validate_for(
            binding,
            binding_sha256,
            adapter,
            &request.canonical_request_sha256,
        )
        .and_then(|()| envelope.validate_for_allocation_request(&request))
        .map_err(|error| TrustedContextError::Corrupt(error.to_string()))?;
    Ok(envelope)
}

/// Validate one daemon-issued logical delivery, derive its V3 allocation
/// request from canonical adapter bytes, and require an exact V3 envelope.
/// Neither a model/provider call ID nor canonical content can select the
/// durable identity at this boundary.
#[cfg(any(test, feature = "production-durable-hotpath"))]
#[allow(dead_code)]
pub(crate) fn allocate_tool_call_with_daemon_delivery_authority(
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    verified_delivery: &VerifiedDaemonToolCallDelivery,
    canonical_request: &[u8],
    authority: &mut impl ToolCallAllocationAuthorityV3,
) -> TrustedContextResult<DirectOperationToolCallEnvelopeV3> {
    let delivery = &verified_delivery.delivery;
    delivery
        .validate_for(binding, binding_sha256, adapter)
        .map_err(|error| TrustedContextError::Corrupt(error.to_string()))?;
    let request = DirectOperationToolCallAllocationRequestV3::derive(
        delivery,
        binding,
        binding_sha256,
        adapter,
        lower_hex(&Sha256::digest(canonical_request)),
    )
    .map_err(|error| TrustedContextError::Corrupt(error.to_string()))?;
    let envelope = authority.allocate(delivery, &request)?;
    envelope
        .validate_for(
            binding,
            binding_sha256,
            adapter,
            &request.canonical_request_sha256,
        )
        .and_then(|()| envelope.validate_for_allocation_request_v3(&request))
        .map_err(|error| TrustedContextError::Corrupt(error.to_string()))?;
    Ok(envelope)
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
fn tool_call_allocation_request(
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    canonical_request: &[u8],
) -> TrustedContextResult<DirectOperationUncorrelatedToolCallAllocationRequestV3> {
    DirectOperationUncorrelatedToolCallAllocationRequestV3::derive(
        binding,
        binding_sha256,
        adapter,
        lower_hex(&Sha256::digest(canonical_request)),
    )
    .map_err(|error| TrustedContextError::Corrupt(error.to_string()))
}

/// No safe constructor exists. A future product route must replace this with a
/// broker-authenticated V3 delivery transport; retaining an uninhabited
/// authority type prevents a zero-sized local "approval" object from silently
/// enabling effects in the meantime. Capability-lease replay-sync is not an
/// Android operation-epoch activation or tool-call allocation authority.
#[cfg(feature = "production-durable-hotpath")]
#[allow(dead_code)]
struct ProductToolCallAllocationAuthority {
    _unconstructible: std::convert::Infallible,
}

/// A separate uninhabited capability keeps the new V3 source seam from being
/// mistaken for a locally constructible product transport.
#[cfg(feature = "production-durable-hotpath")]
#[allow(dead_code)]
struct ProductDaemonDeliveryAllocationAuthority {
    _unconstructible: std::convert::Infallible,
}

#[derive(Debug)]
pub struct TrustedAdapterContext {
    adapter: DirectOperationAdapter,
    provider_id: &'static str,
    agent_id: &'static str,
    delivery_provider_attempt_id: String,
    binding_sha256: String,
    #[cfg(feature = "device-launch-package-conformance")]
    binding_inbox_bytes_sha256: String,
    binding: DirectOperationBinding,
    journal_path: PathBuf,
    // Keep the exact validated state-directory inode alive for the entire
    // context lifetime. Product ancestors are root-owned and non-writable by
    // the Agent, so the fixed pathname cannot be retargeted by that Agent.
    _state_directory: File,
    _inbox_directory: File,
    inbox_file_owner_uid: u32,
    inbox_file_owner_gid: u32,
    inbox_file_mode: u32,
    #[cfg(feature = "production-durable-hotpath")]
    kernel_launch_custody: Option<DirectOperationKernelLaunchCustodyV3>,
}

/// Endpoint-specific replay/ACK custody for the measured one-shot helper.
///
/// Construction is possible only from the current process's fixed provider
/// UID/GID four-tuple, the endpoint's dedicated operation replay-sync SELinux
/// domain, and its fixed system_ext executable. The ordinary adapter tool
/// domain is deliberately rejected. No model field, environment variable,
/// command payload, or CLI selector chooses any of these values.
pub struct TrustedReplaySyncContext {
    inner: TrustedAdapterContext,
    operation_replay_sync_selinux_domain: &'static str,
    executable_path: &'static str,
}

/// Affine proof that the measured daemon authorized one replay-sync command.
///
/// The fields are private and the type is deliberately neither `Clone` nor
/// `Copy`. Product code can obtain it only from
/// [`TrustedReplaySyncContext::require_product_launch_authority`], which stays
/// fail-closed until the daemon-sealed launch challenge and rollback-resistant
/// journal replay capability are implemented. ACK preparation consumes this
/// proof and retains it through Android echo and local compaction, preventing
/// a later stage from substituting a different trusted context.
pub(crate) struct AuthorizedReplaySyncContext<'a> {
    context: &'a TrustedReplaySyncContext,
    launch_challenge_sha256: String,
}

impl<'a> AuthorizedReplaySyncContext<'a> {
    #[must_use]
    pub(crate) const fn context(&self) -> &'a TrustedReplaySyncContext {
        self.context
    }

    #[must_use]
    pub(crate) fn launch_challenge_sha256(&self) -> &str {
        &self.launch_challenge_sha256
    }

    /// Phase A has no rollback-resistant replay authority, even after the
    /// launch-authority type barrier. Keeping journal opening on this affine
    /// proof prevents an ordinary parsed context from reaching the journal.
    pub(crate) fn open_replay_sync_operation_journal(
        &self,
    ) -> crate::operation_journal::JournalResult<crate::operation_journal::OperationJournal> {
        Err(crate::operation_journal::OperationJournalError::ReplayAuthorityUnavailable)
    }
}

impl TrustedReplaySyncContext {
    pub fn open_current_product(adapter: DirectOperationAdapter) -> TrustedContextResult<Self> {
        let identity = current_process_identity();
        let domain = current_selinux_domain()?;
        let (specification, expected_domain, executable_path) =
            replay_sync_product_specification(identity, &domain, adapter)?;
        validate_current_executable_path(executable_path)?;
        let inner = TrustedAdapterContext::open_with_specification(specification, None)?;
        Ok(Self {
            inner,
            operation_replay_sync_selinux_domain: expected_domain,
            executable_path,
        })
    }

    /// Open the fixed System API replay-sync identity for the separately
    /// packaged userdebug-only launch-package lane.  This deliberately skips
    /// product kernel-custody activation, but retains the same provider
    /// UID/GID, endpoint replay-sync SELinux domain, root-owned inbox, and
    /// exact executable checks as the product replay helper.
    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn open_current_device_conformance_system_api() -> TrustedContextResult<Self> {
        let adapter = DirectOperationAdapter::SystemApi;
        let identity = current_process_identity();
        let domain = current_selinux_domain()?;
        let (specification, expected_domain, _product_executable_path) =
            replay_sync_product_specification(identity, &domain, adapter)?;
        validate_current_executable_path(SYSTEM_API_DEVICE_CONFORMANCE_REPLAY_SYNC_BINARY)?;
        let inner = TrustedAdapterContext::open_with_specification(specification, None)?;
        Ok(Self {
            inner,
            operation_replay_sync_selinux_domain: expected_domain,
            executable_path: SYSTEM_API_DEVICE_CONFORMANCE_REPLAY_SYNC_BINARY,
        })
    }

    #[must_use]
    pub const fn adapter(&self) -> DirectOperationAdapter {
        self.inner.adapter
    }

    #[must_use]
    pub const fn provider_id(&self) -> &'static str {
        self.inner.provider_id
    }

    #[must_use]
    pub const fn agent_id(&self) -> &'static str {
        self.inner.agent_id
    }

    #[must_use]
    pub fn binding(&self) -> &DirectOperationBinding {
        &self.inner.binding
    }

    #[must_use]
    pub fn binding_sha256(&self) -> &str {
        &self.inner.binding_sha256
    }

    #[cfg(feature = "device-launch-package-conformance")]
    #[must_use]
    pub(crate) fn binding_inbox_bytes_sha256(&self) -> &str {
        &self.inner.binding_inbox_bytes_sha256
    }

    #[must_use]
    pub fn invocation_id(&self) -> &str {
        &self.inner.binding.invocation_id
    }

    #[must_use]
    pub fn delivery_provider_attempt_id(&self) -> &str {
        &self.inner.delivery_provider_attempt_id
    }

    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.inner.journal_path
    }

    #[must_use]
    pub const fn operation_replay_sync_selinux_domain(&self) -> &'static str {
        self.operation_replay_sync_selinux_domain
    }

    #[must_use]
    pub const fn executable_path(&self) -> &'static str {
        self.executable_path
    }

    pub(crate) fn pending_outer_ack_v3(
        &self,
    ) -> TrustedContextResult<Option<DirectOperationOuterAckInboxV3>> {
        self.inner.read_pending_outer_ack_v3()
    }

    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn pending_outer_ack_v3_for_device_conformance(
        &self,
    ) -> TrustedContextResult<Option<DirectOperationOuterAckInboxV3>> {
        self.inner.read_pending_outer_ack_v3()
    }

    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn open_device_conformance_operation_journal(
        &self,
    ) -> crate::operation_journal::JournalResult<crate::operation_journal::OperationJournal> {
        crate::operation_journal::OperationJournal::open_device_conformance_replay_sync(&self.inner)
    }

    #[cfg(test)]
    pub(crate) fn clone_state_directory(&self) -> std::io::Result<File> {
        self.inner._state_directory.try_clone()
    }

    #[cfg(test)]
    pub(crate) fn open_operation_journal_without_replay_for_test(
        &self,
    ) -> crate::operation_journal::JournalResult<crate::operation_journal::OperationJournal> {
        crate::operation_journal::OperationJournal::open_replay_sync_without_authority_for_test(
            self,
        )
    }

    /// Phase A deliberately has no product constructor for the daemon-sealed
    /// launch challenge or rollback-resistant journal replay capability.
    /// Parsing a valid command from FD 3 must never mint either authority.
    pub(crate) fn require_product_launch_authority(
        &self,
        binding_sha256: &str,
        launch_challenge_sha256: &str,
    ) -> TrustedContextResult<AuthorizedReplaySyncContext<'_>> {
        if binding_sha256 != self.binding_sha256() {
            return Err(TrustedContextError::BindingDigestMismatch);
        }
        if !is_lower_sha256(launch_challenge_sha256)
            || launch_challenge_sha256.bytes().all(|byte| byte == b'0')
        {
            return Err(TrustedContextError::Identity(
                "replay-sync launch challenge must be non-zero lowercase SHA-256",
            ));
        }
        Err(TrustedContextError::ReplaySyncLaunchAuthorityUnavailable)
    }

    #[cfg(test)]
    fn authorize_replay_sync_for_test(
        &self,
        launch_challenge_sha256: &str,
    ) -> TrustedContextResult<AuthorizedReplaySyncContext<'_>> {
        if !is_lower_sha256(launch_challenge_sha256)
            || launch_challenge_sha256.bytes().all(|byte| byte == b'0')
        {
            return Err(TrustedContextError::Identity(
                "replay-sync launch challenge must be non-zero lowercase SHA-256",
            ));
        }
        Ok(AuthorizedReplaySyncContext {
            context: self,
            launch_challenge_sha256: launch_challenge_sha256.to_string(),
        })
    }

    #[cfg(test)]
    fn open_for_test(
        adapter: DirectOperationAdapter,
        provider_id: &'static str,
        agent_id: &'static str,
        state_directory: PathBuf,
        inbox_directory: PathBuf,
        expectation: LaunchExpectation<'_>,
    ) -> TrustedContextResult<Self> {
        let identity = current_process_identity();
        let uid = identity.effective_uid;
        let gid = identity.effective_gid;
        let (domain, executable_path) = operation_replay_sync_identity(adapter);
        let inner = TrustedAdapterContext::open_with_specification(
            ContextSpecification {
                adapter,
                provider_id,
                agent_id,
                state_directory,
                inbox_directory,
                state_owner_uid: uid,
                state_owner_gid: gid,
                state_mode: 0o700,
                inbox_owner_uid: uid,
                inbox_owner_gid: gid,
                inbox_mode: 0o700,
                binding_owner_uid: uid,
                binding_owner_gid: gid,
                binding_mode: 0o600,
                require_root_owned_ancestors: false,
            },
            Some(expectation),
        )?;
        Ok(Self {
            inner,
            operation_replay_sync_selinux_domain: domain,
            executable_path,
        })
    }
}

impl TrustedAdapterContext {
    /// Consume the same fixed root-authored invocation inbox as the product
    /// adapter without claiming product kernel-custody or authority wiring.
    /// This constructor exists only in the separately packaged userdebug-only
    /// launch-package conformance binary.
    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn open_current_device_conformance(
        adapter: DirectOperationAdapter,
    ) -> TrustedContextResult<Self> {
        let identity = current_process_identity();
        let domain = current_selinux_domain()?;
        let specification = product_specification(identity, &domain, adapter)?;
        Self::open_with_specification(specification, None)
    }

    /// Consume the current fixed, root-authored inbox without accepting any
    /// caller-selected comparison value. Production durable builds also
    /// require the exact root-authored kernel launch-custody envelope and live
    /// membership in the fixed provider cgroup. Missing broker/init custody is
    /// therefore a pre-effect runtime HOLD, never an unjournaled fallback.
    pub fn open_current_product(adapter: DirectOperationAdapter) -> TrustedContextResult<Self> {
        let identity = current_process_identity();
        let domain = current_selinux_domain()?;
        let specification = product_specification(identity, &domain, adapter)?;
        let mut context = Self::open_with_specification(specification, None)?;
        context.activate_product_kernel_custody()?;
        Ok(context)
    }

    /// Open the fixed product state and inbox paths. Missing provisioning is a
    /// hard error; there is no environment or unjournaled fallback.
    pub fn open_product(
        adapter: DirectOperationAdapter,
        expected_binding_sha256: &str,
        expected_invocation_id: &str,
        expected_task_id: &str,
        expected_delivery_provider_attempt_id: &str,
    ) -> TrustedContextResult<Self> {
        let identity = current_process_identity();
        let domain = current_selinux_domain()?;
        let specification = product_specification(identity, &domain, adapter)?;
        let mut context = Self::open_with_specification(
            specification,
            Some(LaunchExpectation {
                binding_sha256: expected_binding_sha256,
                invocation_id: expected_invocation_id,
                task_id: expected_task_id,
                delivery_provider_attempt_id: expected_delivery_provider_attempt_id,
            }),
        )?;
        context.activate_product_kernel_custody()?;
        Ok(context)
    }

    #[must_use]
    pub const fn adapter(&self) -> DirectOperationAdapter {
        self.adapter
    }

    #[must_use]
    pub const fn provider_id(&self) -> &'static str {
        self.provider_id
    }

    #[must_use]
    pub const fn agent_id(&self) -> &'static str {
        self.agent_id
    }

    #[must_use]
    pub fn invocation_id(&self) -> &str {
        &self.binding.invocation_id
    }

    #[must_use]
    pub fn delivery_provider_attempt_id(&self) -> &str {
        &self.delivery_provider_attempt_id
    }

    #[must_use]
    pub fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }

    #[must_use]
    pub fn binding(&self) -> &DirectOperationBinding {
        &self.binding
    }

    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn device_conformance_journal_path(&self) -> PathBuf {
        self.journal_path
            .with_file_name(DEVICE_CONFORMANCE_JOURNAL_FILE_NAME)
    }

    // Used only by the source-complete first-use consumer. Product adapters
    // cannot reach that consumer until a trusted authority transport exists.
    #[allow(dead_code)]
    pub(crate) fn clone_state_directory(&self) -> std::io::Result<File> {
        self._state_directory.try_clone()
    }

    /// The normal product entry point cannot activate from local journal bytes
    /// alone. A future daemon transport must deliver the sealed external
    /// first-use COMMITTED capability (or a distinct replay/high-water
    /// capability) through the dedicated typed seam.
    pub fn open_operation_journal(
        &self,
    ) -> crate::operation_journal::JournalResult<crate::operation_journal::OperationJournal> {
        Err(crate::operation_journal::OperationJournalError::FirstUseAuthorityUnavailable)
    }

    /// Source-complete restart seam for an already-provisioned journal. The
    /// sealed replay capability must come from a rollback-resistant external
    /// authority and is consumed by the open. Ordinary product paths cannot
    /// construct it and continue to fail closed in `open_operation_journal`.
    #[allow(dead_code)]
    pub(crate) fn open_operation_journal_after_replay(
        &self,
        authority: crate::secure_first_use_journal::VerifiedJournalReplayAuthority,
    ) -> crate::operation_journal::JournalResult<crate::operation_journal::OperationJournal> {
        crate::operation_journal::OperationJournal::open_trusted_after_replay(self, authority)
    }

    #[cfg(test)]
    pub(crate) fn open_operation_journal_without_first_use_for_test(
        &self,
    ) -> crate::operation_journal::JournalResult<crate::operation_journal::OperationJournal> {
        crate::operation_journal::OperationJournal::open_trusted_without_first_use_for_test(self)
    }

    /// Request one new or retry-stable logical call identity only after the
    /// request is canonicalized. There is deliberately no fixed-file fallback:
    /// a launch-scoped file could be reused by a long-lived MCP adapter and
    /// cannot distinguish two deliberate identical actions. Until the live
    /// root/daemon allocator transport exists, product calls stop here before
    /// journal mutation, backend connection, or effect.
    #[cfg(feature = "production-durable-hotpath")]
    #[allow(dead_code)]
    pub(crate) fn allocate_product_tool_call(
        &self,
        canonical_request: &[u8],
    ) -> TrustedContextResult<DirectOperationToolCallEnvelopeV3> {
        let _request = tool_call_allocation_request(
            &self.binding,
            &self.binding_sha256,
            self.adapter,
            canonical_request,
        )?;
        Err(TrustedContextError::ToolCallAllocationUnavailable)
    }

    /// Revalidate this process's live membership in the selected kernel-owned
    /// adapter child leaf immediately before any product effect. The
    /// root-authored proof is permanently bound to the already frozen
    /// invocation/attempt/adapter context.
    pub(crate) fn require_product_effect_custody(&self) -> TrustedContextResult<()> {
        #[cfg(feature = "production-durable-hotpath")]
        {
            let custody = self.kernel_launch_custody.as_ref().ok_or_else(|| {
                TrustedContextError::KernelCustody(
                    "kernel launch custody envelope was not admitted".to_string(),
                )
            })?;
            custody
                .validate_for(&self.binding, &self.binding_sha256, self.adapter)
                .map_err(|error| TrustedContextError::KernelCustody(error.to_string()))?;
            validate_live_launch_identity(custody, self.provider_id, self.adapter)
        }
        #[cfg(not(feature = "production-durable-hotpath"))]
        {
            Err(TrustedContextError::KernelCustody(
                "production durable effect custody is not compiled".to_string(),
            ))
        }
    }

    #[cfg(feature = "production-durable-hotpath")]
    pub(crate) fn kernel_launch_custody_for_direct_transport(
        &self,
    ) -> TrustedContextResult<&DirectOperationKernelLaunchCustodyV3> {
        self.require_product_effect_custody()?;
        self.kernel_launch_custody.as_ref().ok_or_else(|| {
            TrustedContextError::KernelCustody(
                "kernel launch custody envelope was not admitted".to_string(),
            )
        })
    }

    /// Stop the ordinary tool hotpath before opening or mutating its journal
    /// whenever the fixed root inbox contains a pending V3 acknowledgement.
    /// Only the endpoint-specific replay-sync context may perform Android ACK
    /// followed by local reclamation.
    pub(crate) fn require_no_pending_outer_ack_v3(&self) -> TrustedContextResult<()> {
        if self.read_pending_outer_ack_v3()?.is_some() {
            return Err(TrustedContextError::PendingOuterAckRequiresReplaySync);
        }
        Ok(())
    }

    /// Read and authenticate the fixed root-owned outer-ACK inbox without
    /// mutating the local journal.  The conformance lane needs this split so
    /// the Android replay ACK and local compaction can be crash-reconciled.
    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn pending_outer_ack_v3_for_device_conformance(
        &self,
    ) -> TrustedContextResult<Option<DirectOperationOuterAckInboxV3>> {
        self.read_pending_outer_ack_v3()
    }

    fn read_pending_outer_ack_v3(
        &self,
    ) -> TrustedContextResult<Option<DirectOperationOuterAckInboxV3>> {
        let directory = SecureDirectory {
            file: self._inbox_directory.try_clone()?,
        };
        let Some(bytes) = directory.read_optional_closed_file(
            OUTER_ACK_V3_FILE_NAME,
            self.inbox_file_owner_uid,
            self.inbox_file_owner_gid,
            self.inbox_file_mode,
            MAX_OUTER_ACK_BYTES,
        )?
        else {
            return Ok(None);
        };
        let inbox: DirectOperationOuterAckInboxV3 = serde_json::from_slice(&bytes)?;
        inbox
            .validate()
            .map_err(|error| TrustedContextError::Corrupt(error.to_string()))?;
        let mut canonical = serde_json::to_vec(&inbox)?;
        canonical.push(b'\n');
        if canonical != bytes {
            return Err(TrustedContextError::Corrupt(
                "outer ACK v3 inbox is not exact canonical one-line JSON".to_string(),
            ));
        }
        let acknowledgement = &inbox.acknowledgement;
        if acknowledgement.binding_sha256 != self.binding_sha256
            || acknowledgement.invocation_id != self.binding.invocation_id
            || acknowledgement.delivery_provider_attempt_id != self.delivery_provider_attempt_id
            || acknowledgement.provider_id != self.provider_id
            || acknowledgement.agent_id != self.agent_id
            || acknowledgement.adapter != self.adapter
        {
            return Err(TrustedContextError::Corrupt(
                "outer ACK v3 does not match the frozen delivery context".to_string(),
            ));
        }
        Ok(Some(inbox))
    }

    fn activate_product_kernel_custody(&mut self) -> TrustedContextResult<()> {
        #[cfg(feature = "production-durable-hotpath")]
        {
            let directory = SecureDirectory {
                file: self._inbox_directory.try_clone()?,
            };
            let bytes = directory.read_closed_file(
                KERNEL_LAUNCH_CUSTODY_V3_FILE_NAME,
                self.inbox_file_owner_uid,
                self.inbox_file_owner_gid,
                self.inbox_file_mode,
                MAX_KERNEL_LAUNCH_CUSTODY_BYTES,
            )?;
            let custody: DirectOperationKernelLaunchCustodyV3 = serde_json::from_slice(&bytes)?;
            custody
                .validate_for(&self.binding, &self.binding_sha256, self.adapter)
                .map_err(|error| TrustedContextError::KernelCustody(error.to_string()))?;
            let mut canonical = serde_json::to_vec(&custody)?;
            canonical.push(b'\n');
            if canonical != bytes {
                return Err(TrustedContextError::KernelCustody(
                    "kernel launch custody is not exact canonical one-line JSON".to_string(),
                ));
            }
            validate_live_launch_identity(&custody, self.provider_id, self.adapter)?;
            self.kernel_launch_custody = Some(custody);
        }
        Ok(())
    }

    fn open_with_specification(
        specification: ContextSpecification,
        expectation: Option<LaunchExpectation<'_>>,
    ) -> TrustedContextResult<Self> {
        if expectation.is_some_and(|value| !is_lower_sha256(value.binding_sha256)) {
            return Err(TrustedContextError::Identity(
                "expected binding digest must be lowercase SHA-256",
            ));
        }
        let state = SecureDirectory::open(
            &specification.state_directory,
            specification.state_owner_uid,
            specification.state_owner_gid,
            specification.state_mode,
            specification.require_root_owned_ancestors,
        )?;
        let inbox = SecureDirectory::open(
            &specification.inbox_directory,
            specification.inbox_owner_uid,
            specification.inbox_owner_gid,
            specification.inbox_mode,
            specification.require_root_owned_ancestors,
        )?;
        let inbox_value = inbox.read_closed_file(
            c"current-invocation.json",
            specification.binding_owner_uid,
            specification.binding_owner_gid,
            specification.binding_mode,
            MAX_BINDING_BYTES,
        )?;
        let envelope: DirectOperationBindingInbox = serde_json::from_slice(&inbox_value)?;
        envelope
            .validate()
            .map_err(|error| TrustedContextError::Corrupt(error.to_string()))?;
        if !envelope
            .binding
            .authorized_adapter_set
            .authorizes(specification.adapter)
        {
            return Err(TrustedContextError::Identity(
                "binding does not authorize this fixed adapter",
            ));
        }
        let mut canonical = serde_json::to_vec(&envelope)?;
        canonical.push(b'\n');
        if canonical != inbox_value {
            return Err(TrustedContextError::Corrupt(
                "binding inbox is not exact canonical one-line JSON".to_string(),
            ));
        }
        if let Some(expectation) = expectation {
            if envelope.binding_sha256 != expectation.binding_sha256 {
                return Err(TrustedContextError::BindingDigestMismatch);
            }
            // Explicit comparisons remain available for conformance callers.
            // The unpromoted hotpath feature can omit them and consume the
            // SELinux-hidden inbox without exposing these values to the Agent;
            // product activation still requires kernel descendant custody.
            if envelope.binding.invocation_id != expectation.invocation_id
                || envelope.binding.stable_seed.task_id != expectation.task_id
                || envelope.binding.attempt.delivery_provider_attempt_id
                    != expectation.delivery_provider_attempt_id
            {
                return Err(TrustedContextError::Identity(
                    "binding does not match the fixed launch invocation, task, or attempt",
                ));
            }
        }
        if envelope.binding.stable_seed.provider_id != specification.provider_id
            || envelope.binding.stable_seed.agent_id != specification.agent_id
        {
            return Err(TrustedContextError::Identity(
                "binding provider or Agent differs from the fixed product identity",
            ));
        }
        let journal_path = specification.state_directory.join(JOURNAL_FILE_NAME);
        #[cfg(feature = "device-launch-package-conformance")]
        let binding_inbox_bytes_sha256 = trillionnium_os_types::sha256_bytes(&inbox_value);
        Ok(Self {
            adapter: specification.adapter,
            provider_id: specification.provider_id,
            agent_id: specification.agent_id,
            delivery_provider_attempt_id: envelope
                .binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            binding_sha256: envelope.binding_sha256,
            #[cfg(feature = "device-launch-package-conformance")]
            binding_inbox_bytes_sha256,
            binding: envelope.binding,
            journal_path,
            _state_directory: state.file,
            _inbox_directory: inbox.file,
            inbox_file_owner_uid: specification.binding_owner_uid,
            inbox_file_owner_gid: specification.binding_owner_gid,
            inbox_file_mode: specification.binding_mode,
            #[cfg(feature = "production-durable-hotpath")]
            kernel_launch_custody: None,
        })
    }

    #[cfg(test)]
    fn open_for_test(
        adapter: DirectOperationAdapter,
        provider_id: &'static str,
        agent_id: &'static str,
        state_directory: PathBuf,
        inbox_directory: PathBuf,
        expectation: LaunchExpectation<'_>,
    ) -> TrustedContextResult<Self> {
        let identity = current_process_identity();
        let uid = identity.effective_uid;
        let gid = identity.effective_gid;
        Self::open_with_specification(
            ContextSpecification {
                adapter,
                provider_id,
                agent_id,
                state_directory,
                inbox_directory,
                state_owner_uid: uid,
                state_owner_gid: gid,
                state_mode: 0o700,
                inbox_owner_uid: uid,
                inbox_owner_gid: gid,
                inbox_mode: 0o700,
                binding_owner_uid: uid,
                binding_owner_gid: gid,
                binding_mode: 0o600,
                require_root_owned_ancestors: false,
            },
            Some(expectation),
        )
    }

    #[cfg(test)]
    fn open_current_for_test(
        adapter: DirectOperationAdapter,
        provider_id: &'static str,
        agent_id: &'static str,
        state_directory: PathBuf,
        inbox_directory: PathBuf,
    ) -> TrustedContextResult<Self> {
        let identity = current_process_identity();
        let uid = identity.effective_uid;
        let gid = identity.effective_gid;
        Self::open_with_specification(
            ContextSpecification {
                adapter,
                provider_id,
                agent_id,
                state_directory,
                inbox_directory,
                state_owner_uid: uid,
                state_owner_gid: gid,
                state_mode: 0o700,
                inbox_owner_uid: uid,
                inbox_owner_gid: gid,
                inbox_mode: 0o700,
                binding_owner_uid: uid,
                binding_owner_gid: gid,
                binding_mode: 0o600,
                require_root_owned_ancestors: false,
            },
            None,
        )
    }
}

struct ContextSpecification {
    adapter: DirectOperationAdapter,
    provider_id: &'static str,
    agent_id: &'static str,
    state_directory: PathBuf,
    inbox_directory: PathBuf,
    state_owner_uid: u32,
    state_owner_gid: u32,
    state_mode: u32,
    inbox_owner_uid: u32,
    inbox_owner_gid: u32,
    inbox_mode: u32,
    binding_owner_uid: u32,
    binding_owner_gid: u32,
    binding_mode: u32,
    require_root_owned_ancestors: bool,
}

#[derive(Clone, Copy)]
struct LaunchExpectation<'a> {
    binding_sha256: &'a str,
    invocation_id: &'a str,
    task_id: &'a str,
    delivery_provider_attempt_id: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessIdentity {
    real_uid: u32,
    effective_uid: u32,
    real_gid: u32,
    effective_gid: u32,
}

fn product_specification(
    identity: ProcessIdentity,
    domain: &str,
    adapter: DirectOperationAdapter,
) -> TrustedContextResult<ContextSpecification> {
    let expected_domain = match adapter {
        DirectOperationAdapter::SystemApi => SYSTEM_API_DOMAIN,
        DirectOperationAdapter::Accessibility => ACCESSIBILITY_DOMAIN,
    };
    product_specification_for_domain(identity, domain, adapter, expected_domain)
}

fn replay_sync_product_specification(
    identity: ProcessIdentity,
    domain: &str,
    adapter: DirectOperationAdapter,
) -> TrustedContextResult<(ContextSpecification, &'static str, &'static str)> {
    let (expected_domain, executable_path) = operation_replay_sync_identity(adapter);
    let specification =
        product_specification_for_domain(identity, domain, adapter, expected_domain)?;
    Ok((specification, expected_domain, executable_path))
}

fn operation_replay_sync_identity(adapter: DirectOperationAdapter) -> (&'static str, &'static str) {
    match adapter {
        DirectOperationAdapter::SystemApi => (
            SYSTEM_API_OPERATION_REPLAY_SYNC_DOMAIN,
            SYSTEM_API_OPERATION_REPLAY_SYNC_BINARY,
        ),
        DirectOperationAdapter::Accessibility => (
            ACCESSIBILITY_OPERATION_REPLAY_SYNC_DOMAIN,
            ACCESSIBILITY_OPERATION_REPLAY_SYNC_BINARY,
        ),
    }
}

fn product_specification_for_domain(
    identity: ProcessIdentity,
    domain: &str,
    adapter: DirectOperationAdapter,
    expected_domain: &'static str,
) -> TrustedContextResult<ContextSpecification> {
    if identity.real_uid != identity.effective_uid || identity.real_gid != identity.effective_gid {
        return Err(TrustedContextError::Identity(
            "real/effective UID/GID four-tuple is not one fixed direct Agent principal",
        ));
    }
    let principal = agent_principal_registry::from_uid_gid(identity.real_uid, identity.real_gid)
        .filter(|principal| **principal == CODEX_STABLE_PRINCIPAL)
        .ok_or(TrustedContextError::Identity(
            "real/effective UID/GID four-tuple is not one fixed direct Agent principal",
        ))?;
    let (provider_directory, provider_id, agent_id, uid, gid) = (
        "codex",
        principal.provider_id,
        principal.agent_id,
        principal.uid,
        principal.gid,
    );
    let adapter_directory = match adapter {
        DirectOperationAdapter::SystemApi => "system-api",
        DirectOperationAdapter::Accessibility => "accessibility",
    };
    if domain != expected_domain {
        return Err(TrustedContextError::Identity(
            "process SELinux domain does not match the fixed adapter",
        ));
    }
    Ok(ContextSpecification {
        adapter,
        provider_id,
        agent_id,
        state_directory: Path::new(PRODUCT_STATE_ROOT)
            .join(provider_directory)
            .join(adapter_directory),
        inbox_directory: Path::new(PRODUCT_INBOX_ROOT)
            .join(provider_directory)
            .join(adapter_directory),
        state_owner_uid: uid,
        state_owner_gid: gid,
        state_mode: 0o700,
        inbox_owner_uid: 0,
        inbox_owner_gid: gid,
        inbox_mode: 0o750,
        binding_owner_uid: 0,
        binding_owner_gid: gid,
        binding_mode: 0o440,
        require_root_owned_ancestors: true,
    })
}

fn validate_current_executable_path(expected: &str) -> TrustedContextResult<()> {
    let actual = std::fs::read_link("/proc/self/exe")?;
    validate_executable_path(&actual, expected)
}

fn validate_executable_path(actual: &Path, expected: &str) -> TrustedContextResult<()> {
    if actual != Path::new(expected) {
        return Err(TrustedContextError::Identity(
            "process executable is not the fixed operation replay-sync entrypoint",
        ));
    }
    Ok(())
}

struct SecureDirectory {
    file: File,
}

impl SecureDirectory {
    fn open(
        path: &Path,
        uid: u32,
        gid: u32,
        mode: u32,
        require_root_owned_ancestors: bool,
    ) -> TrustedContextResult<Self> {
        if !path.is_absolute() {
            return Err(TrustedContextError::Path("directory must be absolute"));
        }
        let root_fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut directory = unsafe { File::from_raw_fd(root_fd) };
        validate_directory_inode(&directory, 0, 0, None, require_root_owned_ancestors)?;
        let components = path
            .components()
            .filter_map(|component| match component {
                Component::RootDir => None,
                Component::Normal(component) => Some(Ok(component)),
                _ => Some(Err(TrustedContextError::Path(
                    "directory contains a non-normal component",
                ))),
            })
            .collect::<TrustedContextResult<Vec<_>>>()?;
        if components.is_empty() {
            return Err(TrustedContextError::Path(
                "directory path must name a leaf below root",
            ));
        }
        for (index, component) in components.iter().enumerate() {
            let name = checked_component(component)?;
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let next = unsafe { File::from_raw_fd(fd) };
            let metadata = next.metadata()?;
            let stat = stat_entry(&directory, &name)?.ok_or(TrustedContextError::Path(
                "directory entry disappeared during validation",
            ))?;
            if stat.st_dev != metadata.dev()
                || stat.st_ino != metadata.ino()
                || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
                || stat.st_nlink == 0
            {
                return Err(TrustedContextError::Path(
                    "directory entry does not match the validated inode",
                ));
            }
            let is_final = index + 1 == components.len();
            if is_final {
                validate_directory_inode(&next, uid, gid, Some(mode), false)?;
            } else {
                validate_directory_inode(&next, 0, 0, None, require_root_owned_ancestors)?;
            }
            directory = next;
        }
        Ok(Self { file: directory })
    }

    fn read_closed_file(
        &self,
        name: &CStr,
        uid: u32,
        gid: u32,
        mode: u32,
        maximum_bytes: u64,
    ) -> TrustedContextResult<Vec<u8>> {
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.gid() != gid
            || metadata.mode() & 0o7777 != mode
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > maximum_bytes
        {
            return Err(TrustedContextError::Corrupt(
                "inbox file ownership, mode, type, link count, or size is invalid".to_string(),
            ));
        }
        let stat = stat_entry(&self.file, name)?
            .ok_or_else(|| TrustedContextError::Corrupt("inbox file disappeared".to_string()))?;
        if stat.st_dev != metadata.dev()
            || stat.st_ino != metadata.ino()
            || stat.st_uid != uid
            || stat.st_gid != gid
            || stat.st_nlink != 1
            || stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_mode & 0o7777 != mode
        {
            return Err(TrustedContextError::Corrupt(
                "inbox directory entry changed during validation".to_string(),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.by_ref()
            .take(maximum_bytes + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum_bytes
            || bytes.last() != Some(&b'\n')
            || bytes[..bytes.len().saturating_sub(1)].contains(&b'\n')
        {
            return Err(TrustedContextError::Corrupt(
                "inbox file is not one bounded newline-terminated frame".to_string(),
            ));
        }
        let after = file.metadata()?;
        let after_entry = stat_entry(&self.file, name)?.ok_or_else(|| {
            TrustedContextError::Corrupt("inbox file disappeared after read".to_string())
        })?;
        if after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.len() != metadata.len()
            || after.mtime() != metadata.mtime()
            || after.mtime_nsec() != metadata.mtime_nsec()
            || after.ctime() != metadata.ctime()
            || after.ctime_nsec() != metadata.ctime_nsec()
            || after_entry.st_dev != metadata.dev()
            || after_entry.st_ino != metadata.ino()
        {
            return Err(TrustedContextError::Corrupt(
                "inbox file or directory entry changed while it was read".to_string(),
            ));
        }
        Ok(bytes)
    }

    fn read_optional_closed_file(
        &self,
        name: &CStr,
        uid: u32,
        gid: u32,
        mode: u32,
        maximum_bytes: u64,
    ) -> TrustedContextResult<Option<Vec<u8>>> {
        if stat_entry(&self.file, name)?.is_none() {
            return Ok(None);
        }
        match self.read_closed_file(name, uid, gid, mode, maximum_bytes) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(TrustedContextError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

fn validate_directory_inode(
    directory: &File,
    uid: u32,
    gid: u32,
    exact_mode: Option<u32>,
    require_root_owned_nonwritable: bool,
) -> TrustedContextResult<()> {
    let metadata = directory.metadata()?;
    let exact_identity_matches = exact_mode.is_none_or(|mode| {
        metadata.uid() == uid && metadata.gid() == gid && metadata.mode() & 0o7777 == mode
    });
    let root_ancestor_matches =
        !require_root_owned_nonwritable || (metadata.uid() == 0 && metadata.mode() & 0o022 == 0);
    if !metadata.is_dir()
        || metadata.nlink() == 0
        || !exact_identity_matches
        || !root_ancestor_matches
    {
        return Err(TrustedContextError::Path(
            "directory ownership, mode, type, link state, or root custody is invalid",
        ));
    }
    Ok(())
}

fn checked_component(value: &OsStr) -> TrustedContextResult<CString> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 || bytes == b"." || bytes == b".." {
        return Err(TrustedContextError::Path("path component is invalid"));
    }
    CString::new(bytes).map_err(|_| TrustedContextError::Path("path component contains NUL"))
}

fn stat_entry(parent: &File, name: &CStr) -> TrustedContextResult<Option<libc::stat>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(Some(unsafe { stat.assume_init() }));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(error.into())
    }
}

pub(crate) fn current_selinux_domain() -> TrustedContextResult<String> {
    let fd = unsafe {
        libc::open(
            c"/proc/self/attr/current".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fd is one fresh successful open result and ownership transfers
    // exactly once into File.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: filesystem points to writable storage for one statfs value.
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fstatfs succeeded and initialized the complete value.
    if unsafe { filesystem.assume_init() }.f_type as u64 != PROC_SUPER_MAGIC {
        return Err(TrustedContextError::Identity(
            "process SELinux domain file is not on procfs",
        ));
    }
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() == 0 {
        return Err(TrustedContextError::Identity(
            "process SELinux domain inode is malformed",
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref().take(257).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() > 256
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.nlink() != after.nlink()
    {
        return Err(TrustedContextError::Identity(
            "process SELinux domain changed or exceeded its bound",
        ));
    }
    while matches!(bytes.last(), Some(b'\n' | 0)) {
        bytes.pop();
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| TrustedContextError::Identity("process SELinux domain is not UTF-8"))?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(TrustedContextError::Identity(
            "process SELinux domain is malformed",
        ));
    }
    Ok(value)
}

fn current_process_identity() -> ProcessIdentity {
    ProcessIdentity {
        real_uid: unsafe { libc::getuid() },
        effective_uid: unsafe { libc::geteuid() },
        real_gid: unsafe { libc::getgid() },
        effective_gid: unsafe { libc::getegid() },
    }
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
pub(crate) fn read_current_unified_cgroup() -> TrustedContextResult<String> {
    let fd = unsafe {
        libc::open(
            c"/proc/self/cgroup".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(TrustedContextError::KernelCustody(format!(
            "could not open fixed procfs cgroup membership: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(TrustedContextError::KernelCustody(format!(
            "could not authenticate procfs cgroup membership: {}",
            std::io::Error::last_os_error()
        )));
    }
    let filesystem = unsafe { filesystem.assume_init() };
    if filesystem.f_type as u64 != PROC_SUPER_MAGIC {
        return Err(TrustedContextError::KernelCustody(
            "fixed cgroup membership file is not on procfs".to_string(),
        ));
    }
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() == 0 || before.len() > MAX_PROC_CGROUP_BYTES {
        return Err(TrustedContextError::KernelCustody(
            "procfs cgroup membership inode is malformed".to_string(),
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_PROC_CGROUP_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.is_empty()
        || bytes.len() as u64 > MAX_PROC_CGROUP_BYTES
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.nlink() != after.nlink()
        || bytes.contains(&0)
    {
        return Err(TrustedContextError::KernelCustody(
            "procfs cgroup membership changed or exceeded its bound".to_string(),
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        TrustedContextError::KernelCustody(
            "procfs cgroup membership is not valid UTF-8".to_string(),
        )
    })
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
pub(crate) fn require_fixed_adapter_cgroup(
    provider_id: &str,
    adapter: DirectOperationAdapter,
    membership: &str,
) -> TrustedContextResult<String> {
    let expected =
        trillionnium_os_types::direct_operation::fixed_adapter_cgroup_path(provider_id, adapter)
            .map_err(|error| TrustedContextError::KernelCustody(error.to_string()))?;
    let mut unified = None;
    for line in membership.lines() {
        if line.is_empty() {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 3
            || fields[0].is_empty()
            || fields[2].is_empty()
            || fields
                .iter()
                .any(|field| field.bytes().any(|byte| byte.is_ascii_control()))
        {
            return Err(TrustedContextError::KernelCustody(
                "procfs cgroup membership contains a malformed record".to_string(),
            ));
        }
        if fields[0] == "0" && fields[1].is_empty() && unified.replace(fields[2]).is_some() {
            return Err(TrustedContextError::KernelCustody(
                "procfs reports more than one unified cgroup membership".to_string(),
            ));
        }
    }
    if unified != Some(expected.as_str()) {
        return Err(TrustedContextError::KernelCustody(format!(
            "process is not in fixed provider/adapter cgroup leaf {expected}"
        )));
    }
    Ok(expected)
}

#[cfg(feature = "production-durable-hotpath")]
fn validate_live_launch_identity(
    custody: &DirectOperationKernelLaunchCustodyV3,
    provider_id: &str,
    adapter: DirectOperationAdapter,
) -> TrustedContextResult<()> {
    let pid = unsafe { libc::getpid() };
    let pid = u32::try_from(pid).map_err(|_| {
        TrustedContextError::KernelCustody("adapter PID is not a positive u32".to_string())
    })?;
    let boot_id = read_fixed_proc_file(c"/proc/sys/kernel/random/boot_id", 64)?;
    let boot_id = boot_id.strip_suffix(b"\n").unwrap_or(&boot_id);
    if boot_id.len() != 36
        || boot_id
            .iter()
            .any(|byte| !byte.is_ascii_hexdigit() && *byte != b'-')
    {
        return Err(TrustedContextError::KernelCustody(
            "kernel boot ID is malformed".to_string(),
        ));
    }
    let boot_id_sha256 = lower_hex(&Sha256::digest(boot_id));
    let stat = read_fixed_proc_file(c"/proc/self/stat", MAX_PROC_IDENTITY_BYTES)?;
    let stat = std::str::from_utf8(&stat)
        .map_err(|_| TrustedContextError::KernelCustody("process stat is not UTF-8".to_string()))?;
    let close = stat.rfind(')').ok_or_else(|| {
        TrustedContextError::KernelCustody("process stat lacks comm terminator".to_string())
    })?;
    let start_time_ticks = stat[close + 1..]
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| {
            TrustedContextError::KernelCustody("process stat lacks starttime".to_string())
        })?
        .parse::<u64>()
        .map_err(|_| {
            TrustedContextError::KernelCustody("process starttime is malformed".to_string())
        })?;
    let executable_sha256 = hash_current_executable()?;
    let cgroup =
        require_fixed_adapter_cgroup(provider_id, adapter, &read_current_unified_cgroup()?)?;
    if custody.boot_id_sha256 != boot_id_sha256
        || custody.adapter_pid != pid
        || custody.adapter_start_time_ticks != start_time_ticks
        || custody.adapter_executable_sha256 != executable_sha256
        || custody.unified_cgroup_path != cgroup
        || custody.adapter_binary_kind
            != trillionnium_os_types::direct_operation::adapter_binary_kind(adapter)
    {
        return Err(TrustedContextError::KernelCustody(
            "kernel launch custody anti-replay identity does not match this process".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "production-durable-hotpath")]
fn read_fixed_proc_file(path: &CStr, maximum: u64) -> TrustedContextResult<Vec<u8>> {
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(TrustedContextError::KernelCustody(format!(
            "could not open fixed proc identity: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0
        || unsafe { filesystem.assume_init() }.f_type as u64 != PROC_SUPER_MAGIC
    {
        return Err(TrustedContextError::KernelCustody(
            "fixed process identity is not on procfs".to_string(),
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref().take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > maximum || bytes.contains(&0) {
        return Err(TrustedContextError::KernelCustody(
            "fixed process identity is empty or oversized".to_string(),
        ));
    }
    Ok(bytes)
}

#[cfg(feature = "production-durable-hotpath")]
fn hash_current_executable() -> TrustedContextResult<String> {
    let mut file = File::open("/proc/self/exe")?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.len() == 0
        || before.len() > MAX_ADAPTER_EXECUTABLE_BYTES
        || before.uid() != 0
        || before.gid() != 0
        || before.mode() & 0o7777 != 0o755
        || before.nlink() != 1
    {
        return Err(TrustedContextError::KernelCustody(
            "current adapter executable is not one bounded root:root mode-0755 regular inode"
                .to_string(),
        ));
    }
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied = copied.checked_add(count as u64).ok_or_else(|| {
            TrustedContextError::KernelCustody("adapter size overflow".to_string())
        })?;
        if copied > MAX_ADAPTER_EXECUTABLE_BYTES {
            return Err(TrustedContextError::KernelCustody(
                "current adapter executable exceeded its bound".to_string(),
            ));
        }
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if copied != before.len()
        || !after.is_file()
        || after.nlink() != 1
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(TrustedContextError::KernelCustody(
            "current adapter executable inode identity or timestamps changed while hashing"
                .to_string(),
        ));
    }
    Ok(lower_hex(&hasher.finalize()))
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::TempDir;
    use trillionnium_os_types::direct_operation::{
        BINDING_INBOX_SCHEMA, BINDING_SCHEMA, DirectOperationJournalEvidenceSnapshotV1,
        DirectOperationOuterAckChainStepV3, DirectOperationOuterAckInboxV3,
        DirectOperationOuterAckV3, DirectOperationProviderAttempt, DirectOperationStableSeed,
        OUTER_ACK_INBOX_V3_SCHEMA, OUTER_ACK_V3_SCHEMA, STABLE_SEED_SCHEMA,
    };
    #[cfg(feature = "production-durable-hotpath")]
    use trillionnium_os_types::direct_operation::{
        DirectOperationToolCallAllocationRequestV3, DirectOperationToolCallDeliveryV3,
        DirectOperationToolCallEnvelopeV3, DirectOperationUncorrelatedToolCallAllocationRequestV3,
        OS_TOOL_CALL_ID_PREFIX, TOOL_CALL_ENVELOPE_V3_SCHEMA,
    };

    use super::*;
    use crate::BackendCompletion;

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    const fn product_identity(uid: u32, gid: u32) -> ProcessIdentity {
        ProcessIdentity {
            real_uid: uid,
            effective_uid: uid,
            real_gid: gid,
            effective_gid: gid,
        }
    }

    #[test]
    fn production_cgroup_membership_is_fixed_for_codex_and_fail_closed() {
        require_fixed_adapter_cgroup(
            CODEX_PROVIDER_ID,
            DirectOperationAdapter::SystemApi,
            "0::/trillionnium/agents/codex/system-api\n",
        )
        .unwrap();
        for (provider, adapter, membership) in [
            (
                CODEX_PROVIDER_ID,
                DirectOperationAdapter::SystemApi,
                "0::/trillionnium/agents/unregistered/system-api\n",
            ),
            (
                CODEX_PROVIDER_ID,
                DirectOperationAdapter::SystemApi,
                "0::/trillionnium/agents/codex/system-api/child\n",
            ),
            (
                CODEX_PROVIDER_ID,
                DirectOperationAdapter::SystemApi,
                "0::/trillionnium/agents/codex/system-api\n0::/trillionnium/agents/codex/system-api\n",
            ),
            (
                CODEX_PROVIDER_ID,
                DirectOperationAdapter::Accessibility,
                "0::/trillionnium/agents/codex/system-api\n",
            ),
            (
                "caller-selected-provider",
                DirectOperationAdapter::SystemApi,
                "0::/trillionnium/agents/codex/system-api\n",
            ),
        ] {
            assert!(require_fixed_adapter_cgroup(provider, adapter, membership).is_err());
        }
    }

    #[test]
    fn product_effect_custody_never_defaults_to_success_without_authority() {
        let fixture = Fixture::new();
        let context = fixture.open().unwrap();
        assert!(matches!(
            context.require_product_effect_custody(),
            Err(TrustedContextError::KernelCustody(_))
        ));
        assert!(!context.journal_path().exists());
    }

    #[cfg(feature = "production-durable-hotpath")]
    #[test]
    fn production_missing_or_partial_kernel_custody_never_admits_effect_authority() {
        let fixture = Fixture::new();
        let mut context = fixture.open().unwrap();
        let journal_path = fixture.state.join(JOURNAL_FILE_NAME);
        assert!(!journal_path.exists());
        assert!(matches!(
            context.require_product_effect_custody(),
            Err(TrustedContextError::KernelCustody(_))
        ));
        assert!(context.activate_product_kernel_custody().is_err());
        assert!(!journal_path.exists());

        let custody_path = fixture.inbox.join(
            KERNEL_LAUNCH_CUSTODY_V3_FILE_NAME
                .to_str()
                .expect("fixed custody name is UTF-8"),
        );
        fs::write(&custody_path, b"{}\n").unwrap();
        fs::set_permissions(&custody_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(context.activate_product_kernel_custody().is_err());
        assert!(matches!(
            context.require_product_effect_custody(),
            Err(TrustedContextError::KernelCustody(_))
        ));
        assert!(!journal_path.exists());
    }

    #[cfg(feature = "production-durable-hotpath")]
    #[test]
    fn product_tool_call_is_per_canonicalized_call_and_has_no_launch_file_fallback() {
        let fixture = Fixture::new();
        let context = fixture.open().unwrap();
        assert!(matches!(
            context.allocate_product_tool_call(b"same-semantic-action"),
            Err(TrustedContextError::ToolCallAllocationUnavailable)
        ));

        let canonical_request = b"same-semantic-action";
        let mut authority = FixtureToolCallAuthority { next_ordinal: 0 };
        let first = allocate_tool_call_with_authority(
            &fixture.binding.binding,
            &fixture.binding.binding_sha256,
            DirectOperationAdapter::SystemApi,
            canonical_request,
            &mut authority,
        )
        .unwrap();
        let second = allocate_tool_call_with_authority(
            &fixture.binding.binding,
            &fixture.binding.binding_sha256,
            DirectOperationAdapter::SystemApi,
            canonical_request,
            &mut authority,
        )
        .unwrap();
        assert_eq!(first.adapter_effect_ordinal, 0);
        assert_eq!(second.adapter_effect_ordinal, 1);
        assert_ne!(first.os_tool_call_id, second.os_tool_call_id);
        assert_eq!(
            first.canonical_request_sha256,
            second.canonical_request_sha256
        );
    }

    #[cfg(feature = "production-durable-hotpath")]
    #[test]
    fn daemon_delivery_v3_seam_distinguishes_new_equal_calls_and_replays_exact_retry() {
        let fixture = Fixture::new();
        let binding = &fixture.binding.binding;
        let binding_sha256 = &fixture.binding.binding_sha256;
        let first_delivery = DirectOperationToolCallDeliveryV3::derive(
            binding,
            binding_sha256,
            DirectOperationAdapter::SystemApi,
            format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('d')),
            0,
        )
        .unwrap();
        let second_delivery = DirectOperationToolCallDeliveryV3::derive(
            binding,
            binding_sha256,
            DirectOperationAdapter::SystemApi,
            format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('e')),
            1,
        )
        .unwrap();
        let first_verified = VerifiedDaemonToolCallDelivery::for_test(
            first_delivery.clone(),
            binding,
            binding_sha256,
            DirectOperationAdapter::SystemApi,
        )
        .unwrap();
        let second_verified = VerifiedDaemonToolCallDelivery::for_test(
            second_delivery,
            binding,
            binding_sha256,
            DirectOperationAdapter::SystemApi,
        )
        .unwrap();
        let canonical = b"same-semantic-action";
        let mut authority = FixtureToolCallAuthorityV3::default();

        let first = allocate_tool_call_with_daemon_delivery_authority(
            binding,
            binding_sha256,
            DirectOperationAdapter::SystemApi,
            &first_verified,
            canonical,
            &mut authority,
        )
        .unwrap();
        let second = allocate_tool_call_with_daemon_delivery_authority(
            binding,
            binding_sha256,
            DirectOperationAdapter::SystemApi,
            &second_verified,
            canonical,
            &mut authority,
        )
        .unwrap();
        let retry = allocate_tool_call_with_daemon_delivery_authority(
            binding,
            binding_sha256,
            DirectOperationAdapter::SystemApi,
            &first_verified,
            canonical,
            &mut authority,
        )
        .unwrap();

        assert_ne!(first.os_tool_call_id, second.os_tool_call_id);
        assert_eq!(
            first.canonical_request_sha256,
            second.canonical_request_sha256
        );
        assert_eq!(retry, first);
        assert_eq!(authority.new_allocations, 2);
        assert_eq!(authority.requests, 3);

        let mut drifted = first_delivery;
        drifted.adapter_effect_ordinal = 1;
        drifted.delivery_sha256 = drifted.digest_sha256().unwrap();
        let drifted = VerifiedDaemonToolCallDelivery::for_test(
            drifted,
            binding,
            binding_sha256,
            DirectOperationAdapter::SystemApi,
        )
        .unwrap();
        assert!(
            allocate_tool_call_with_daemon_delivery_authority(
                binding,
                binding_sha256,
                DirectOperationAdapter::SystemApi,
                &drifted,
                canonical,
                &mut authority,
            )
            .is_err()
        );
        assert_eq!(authority.requests, 4);
        assert_eq!(authority.new_allocations, 2);
    }

    #[cfg(feature = "production-durable-hotpath")]
    struct FixtureToolCallAuthority {
        next_ordinal: u64,
    }

    #[cfg(feature = "production-durable-hotpath")]
    impl ToolCallAllocationAuthority for FixtureToolCallAuthority {
        fn allocate(
            &mut self,
            request: &DirectOperationUncorrelatedToolCallAllocationRequestV3,
        ) -> TrustedContextResult<DirectOperationToolCallEnvelopeV3> {
            let ordinal = self.next_ordinal;
            self.next_ordinal += 1;
            let token_character = char::from_digit((ordinal + 10) as u32, 16).unwrap();
            let mut envelope = DirectOperationToolCallEnvelopeV3 {
                schema: TOOL_CALL_ENVELOPE_V3_SCHEMA.to_string(),
                binding_sha256: request.binding_sha256.clone(),
                invocation_id: request.invocation_id.clone(),
                delivery_provider_attempt_id: request.delivery_provider_attempt_id.clone(),
                provider_id: request.provider_id.clone(),
                agent_id: request.agent_id.clone(),
                adapter: request.adapter,
                os_tool_call_id: format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest(token_character)),
                adapter_effect_ordinal: ordinal,
                canonical_request_sha256: request.canonical_request_sha256.clone(),
                envelope_sha256: String::new(),
            };
            envelope.envelope_sha256 = envelope
                .digest_sha256()
                .map_err(|error| TrustedContextError::Corrupt(error.to_string()))?;
            Ok(envelope)
        }
    }

    #[cfg(feature = "production-durable-hotpath")]
    #[derive(Default)]
    struct FixtureToolCallAuthorityV3 {
        envelopes: std::collections::HashMap<String, (String, DirectOperationToolCallEnvelopeV3)>,
        requests: usize,
        new_allocations: usize,
    }

    #[cfg(feature = "production-durable-hotpath")]
    impl ToolCallAllocationAuthorityV3 for FixtureToolCallAuthorityV3 {
        fn allocate(
            &mut self,
            delivery: &DirectOperationToolCallDeliveryV3,
            request: &DirectOperationToolCallAllocationRequestV3,
        ) -> TrustedContextResult<DirectOperationToolCallEnvelopeV3> {
            self.requests += 1;
            if delivery.delivery_sha256 != request.delivery_sha256
                || delivery.os_tool_call_id != request.os_tool_call_id
                || delivery.adapter_effect_ordinal != request.adapter_effect_ordinal
                || request
                    .digest_sha256()
                    .map_err(|error| TrustedContextError::Corrupt(error.to_string()))?
                    != request.request_sha256
            {
                return Err(TrustedContextError::Corrupt(
                    "fixture V3 request does not bind the daemon delivery".to_string(),
                ));
            }
            if let Some((canonical, envelope)) = self.envelopes.get(&delivery.os_tool_call_id) {
                if canonical != &request.canonical_request_sha256 {
                    return Err(TrustedContextError::Corrupt(
                        "fixture V3 retry changed canonical content".to_string(),
                    ));
                }
                return Ok(envelope.clone());
            }
            let mut envelope = DirectOperationToolCallEnvelopeV3 {
                schema: TOOL_CALL_ENVELOPE_V3_SCHEMA.to_string(),
                binding_sha256: request.binding_sha256.clone(),
                invocation_id: request.invocation_id.clone(),
                delivery_provider_attempt_id: request.delivery_provider_attempt_id.clone(),
                provider_id: request.provider_id.clone(),
                agent_id: request.agent_id.clone(),
                adapter: request.adapter,
                os_tool_call_id: request.os_tool_call_id.clone(),
                adapter_effect_ordinal: request.adapter_effect_ordinal,
                canonical_request_sha256: request.canonical_request_sha256.clone(),
                envelope_sha256: String::new(),
            };
            envelope.envelope_sha256 = envelope
                .digest_sha256()
                .map_err(|error| TrustedContextError::Corrupt(error.to_string()))?;
            self.envelopes.insert(
                delivery.os_tool_call_id.clone(),
                (request.canonical_request_sha256.clone(), envelope.clone()),
            );
            self.new_allocations += 1;
            Ok(envelope)
        }
    }

    fn inbox() -> DirectOperationBindingInbox {
        let seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: CODEX_PROVIDER_ID.to_string(),
            agent_id: CODEX_AGENT_ID.to_string(),
            task_id: "task-trusted-context".to_string(),
            provider_invocation_id_sha256: digest('1'),
            provider_session_id_sha256: digest('2'),
            subject_uid: 10_100,
            subject_selinux_domain_sha256: digest('3'),
        };
        let binding = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            invocation_id: seed.invocation_id().unwrap(),
            stable_seed: seed,
            workflow_id_sha256: digest('6'),
            agent_identity_key_sha256: digest('7'),
            agent_executable_sha256: digest('8'),
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(digest('5'), 1, digest('4')).unwrap(),
        };
        DirectOperationBindingInbox {
            schema: BINDING_INBOX_SCHEMA.to_string(),
            binding_sha256: binding.digest_sha256().unwrap(),
            binding,
        }
    }

    fn outer_ack_inbox_v3(
        binding: &DirectOperationBinding,
        snapshot: DirectOperationJournalEvidenceSnapshotV1,
    ) -> DirectOperationOuterAckInboxV3 {
        let mut acknowledgement = DirectOperationOuterAckV3 {
            schema: OUTER_ACK_V3_SCHEMA.to_string(),
            binding_sha256: binding.digest_sha256().unwrap(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter: DirectOperationAdapter::SystemApi,
            authorized_adapter_set_sha256: binding.authorized_adapter_set.digest_sha256().unwrap(),
            outer_receipt_sha256: digest('a'),
            journal_evidence_snapshot: snapshot,
            journal_evidence_snapshot_sha256: String::new(),
        };
        acknowledgement.journal_evidence_snapshot_sha256 = acknowledgement
            .journal_evidence_snapshot
            .digest_sha256()
            .unwrap();
        let acknowledgement_sha256 = acknowledgement.digest_sha256().unwrap();
        let chain_step = DirectOperationOuterAckChainStepV3::derive(
            acknowledgement.adapter,
            acknowledgement
                .journal_evidence_snapshot
                .journal_epoch
                .clone(),
            acknowledgement
                .journal_evidence_snapshot
                .previous_ack_watermark,
            acknowledgement
                .journal_evidence_snapshot
                .last_journal_sequence,
            acknowledgement_sha256.clone(),
            acknowledgement
                .journal_evidence_snapshot
                .previous_ack_chain_sha256
                .clone(),
        )
        .unwrap();
        let chain_step_sha256 = chain_step.digest_sha256().unwrap();
        let inbox = DirectOperationOuterAckInboxV3 {
            schema: OUTER_ACK_INBOX_V3_SCHEMA.to_string(),
            acknowledgement,
            acknowledgement_sha256,
            chain_step,
            chain_step_sha256,
        };
        inbox.validate().unwrap();
        inbox
    }

    struct Fixture {
        _root: TempDir,
        state: PathBuf,
        inbox: PathBuf,
        binding_path: PathBuf,
        binding: DirectOperationBindingInbox,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let state = root.path().join("state");
            let inbox_directory = root.path().join("inbox");
            fs::create_dir(&state).unwrap();
            fs::create_dir(&inbox_directory).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&inbox_directory, fs::Permissions::from_mode(0o700)).unwrap();
            let binding = inbox();
            let binding_path = inbox_directory.join("current-invocation.json");
            let mut encoded = serde_json::to_vec(&binding).unwrap();
            encoded.push(b'\n');
            fs::write(&binding_path, encoded).unwrap();
            fs::set_permissions(&binding_path, fs::Permissions::from_mode(0o600)).unwrap();
            Self {
                _root: root,
                state,
                inbox: inbox_directory,
                binding_path,
                binding,
            }
        }

        fn open(&self) -> TrustedContextResult<TrustedAdapterContext> {
            TrustedAdapterContext::open_for_test(
                DirectOperationAdapter::SystemApi,
                CODEX_PROVIDER_ID,
                CODEX_AGENT_ID,
                self.state.clone(),
                self.inbox.clone(),
                self.expectation(),
            )
        }

        fn open_replay_sync(&self) -> TrustedContextResult<TrustedReplaySyncContext> {
            TrustedReplaySyncContext::open_for_test(
                DirectOperationAdapter::SystemApi,
                CODEX_PROVIDER_ID,
                CODEX_AGENT_ID,
                self.state.clone(),
                self.inbox.clone(),
                self.expectation(),
            )
        }

        fn expectation(&self) -> LaunchExpectation<'_> {
            LaunchExpectation {
                binding_sha256: &self.binding.binding_sha256,
                invocation_id: &self.binding.binding.invocation_id,
                task_id: &self.binding.binding.stable_seed.task_id,
                delivery_provider_attempt_id: &self
                    .binding
                    .binding
                    .attempt
                    .delivery_provider_attempt_id,
            }
        }
    }

    fn complete_first_use_for_test(
        context: &TrustedAdapterContext,
        state_directory: &Path,
    ) -> crate::secure_first_use_journal::VerifiedFirstUseJournal {
        let unprovisioned =
            crate::secure_first_use_journal::VerifiedUnprovisionedAuthority::for_test(
                state_directory,
                context.agent_id(),
                context.adapter().adapter_id(),
            )
            .unwrap();
        let staged =
            crate::secure_first_use_journal::stage_secure_first_use(unprovisioned).unwrap();
        let prepared =
            crate::secure_first_use_journal::VerifiedPreparedAuthority::for_test(staged).unwrap();
        let local = crate::secure_first_use_journal::publish_prepared_first_use(prepared).unwrap();
        let committed =
            crate::secure_first_use_journal::VerifiedCommittedAuthority::for_test(local).unwrap();
        crate::secure_first_use_journal::finalize_committed_first_use(committed).unwrap()
    }

    #[test]
    fn externally_committed_first_use_result_binds_the_first_runtime_open_and_epoch() {
        let fixture = Fixture::new();
        let context = fixture.open().unwrap();
        let authority = complete_first_use_for_test(&context, &fixture.state);
        let expected_epoch = authority.journal_epoch().to_string();
        let mut journal = crate::operation_journal::OperationJournal::open_trusted_after_first_use(
            &context, authority,
        )
        .unwrap();
        assert!(journal.has_mutation_cas_session_for_test());
        let prepared = journal
            .begin_effect_with_identity(
                &format!("tool-call:{}", digest('c')),
                0,
                b"first-runtime-open-after-external-commit",
            )
            .unwrap()
            .into_prepared();
        assert_eq!(prepared.epoch, expected_epoch);
        let mut envelope =
            trillionnium_os_types::direct_operation::DirectOperationToolCallEnvelopeV3 {
                schema: trillionnium_os_types::direct_operation::TOOL_CALL_ENVELOPE_V3_SCHEMA
                    .to_string(),
                binding_sha256: context.binding_sha256().to_string(),
                invocation_id: context.invocation_id().to_string(),
                delivery_provider_attempt_id: context.delivery_provider_attempt_id().to_string(),
                provider_id: context.provider_id().to_string(),
                agent_id: context.agent_id().to_string(),
                adapter: context.adapter(),
                os_tool_call_id: prepared.os_tool_call_id.clone(),
                adapter_effect_ordinal: prepared.adapter_effect_ordinal,
                canonical_request_sha256: prepared.canonical_request_sha256.to_hex(),
                envelope_sha256: String::new(),
            };
        envelope.envelope_sha256 = envelope.digest_sha256().unwrap();
        let prepared_ack = journal
            .prepared_transport_ack(&envelope, &prepared)
            .unwrap();
        assert_eq!(prepared_ack.journal_epoch, expected_epoch);
        assert_eq!(prepared_ack.journal_sequence, prepared.journal_sequence);
        assert_ne!(
            prepared_ack.operation_epoch_authority_sha256,
            "0".repeat(64)
        );

        // The epoch remains pinned for the entire handle. Replacing the named
        // journal with a separately valid journal carrying another epoch is a
        // HOLD, not a new first use.
        let replacement_root = tempfile::tempdir().unwrap();
        fs::set_permissions(replacement_root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let replacement_path = replacement_root.path().join(JOURNAL_FILE_NAME);
        let replacement = crate::operation_journal::OperationJournal::open(
            &replacement_path,
            context.agent_id(),
            context.adapter().adapter_id(),
            context.invocation_id(),
            context.delivery_provider_attempt_id(),
        )
        .unwrap();
        assert!(!replacement.has_mutation_cas_session_for_test());
        assert!(
            replacement
                .mutation_cas_observation_snapshot_for_test()
                .is_none()
        );
        drop(replacement);
        fs::copy(&replacement_path, context.journal_path()).unwrap();
        assert!(matches!(
            journal.recovery_plan(),
            Err(crate::operation_journal::OperationJournalError::FirstUseEpochMismatch)
        ));
    }

    #[test]
    fn replay_sync_missing_external_authority_cannot_report_no_operations() {
        let fixture = Fixture::new();
        let adapter_context = fixture.open().unwrap();
        let authority = complete_first_use_for_test(&adapter_context, &fixture.state);
        let journal = crate::operation_journal::OperationJournal::open_trusted_after_first_use(
            &adapter_context,
            authority,
        )
        .unwrap();
        drop(journal);

        let replay_context = fixture.open_replay_sync().unwrap();
        let mut journal = replay_context
            .open_operation_journal_without_replay_for_test()
            .unwrap();
        let test_launch_authority = replay_context
            .authorize_replay_sync_for_test(&digest('f'))
            .unwrap();
        assert!(matches!(
            journal.terminal_disposition(test_launch_authority),
            Err(crate::operation_journal::OperationJournalError::MutationAuthorityUnavailable)
        ));
        assert!(matches!(
            replay_context
                .require_product_launch_authority(replay_context.binding_sha256(), &digest('f')),
            Err(TrustedContextError::ReplaySyncLaunchAuthorityUnavailable)
        ));
    }

    #[cfg(feature = "device-launch-package-conformance")]
    #[test]
    fn conformance_replay_sync_never_initializes_missing_state_or_follows_ack_links() {
        let fixture = Fixture::new();
        let replay_context = fixture.open_replay_sync().unwrap();
        let journal_path = fixture.state.join(DEVICE_CONFORMANCE_JOURNAL_FILE_NAME);
        assert!(!journal_path.exists());
        assert!(matches!(
            replay_context.open_device_conformance_operation_journal(),
            Err(crate::operation_journal::OperationJournalError::MissingTrustedJournal)
        ));
        assert!(!journal_path.exists());

        let ack_path = fixture.inbox.join("pending-outer-ack-v3.json");
        symlink(&fixture.binding_path, &ack_path).unwrap();
        assert!(
            replay_context
                .pending_outer_ack_v3_for_device_conformance()
                .is_err()
        );
        fs::remove_file(&ack_path).unwrap();

        fs::write(&ack_path, b"{}\n").unwrap();
        fs::set_permissions(&ack_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            replay_context
                .pending_outer_ack_v3_for_device_conformance()
                .is_err()
        );
    }

    #[test]
    fn replay_sync_authoritative_dispositions_compact_and_reopen_idempotently() {
        use trillionnium_os_types::direct_operation::DirectOperationAdapterTerminalStateV1;

        let fixture = Fixture::new();
        let adapter_context = fixture.open().unwrap();
        let replay_context = fixture.open_replay_sync().unwrap();
        let first_use = complete_first_use_for_test(&adapter_context, &fixture.state);
        let replay_store = first_use.replay_lineage();
        let epoch = first_use.journal_epoch().to_string();
        let mut journal = crate::operation_journal::OperationJournal::open_trusted_after_first_use(
            &adapter_context,
            first_use,
        )
        .unwrap();

        let empty = journal
            .terminal_disposition(
                replay_context
                    .authorize_replay_sync_for_test(&digest('f'))
                    .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            empty.terminal_disposition.terminal_state,
            DirectOperationAdapterTerminalStateV1::NoOperations { .. }
        ));

        let prepared = journal
            .begin_effect_with_identity(
                &format!("tool-call:{}", digest('b')),
                0,
                b"replay-sync-positive-terminal-effect",
            )
            .unwrap()
            .into_prepared();
        let held = journal
            .terminal_disposition(
                replay_context
                    .authorize_replay_sync_for_test(&digest('f'))
                    .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            held.terminal_disposition.terminal_state,
            DirectOperationAdapterTerminalStateV1::HeldIndeterminate { .. }
        ));

        let mut envelope =
            trillionnium_os_types::direct_operation::DirectOperationToolCallEnvelopeV3 {
                schema: trillionnium_os_types::direct_operation::TOOL_CALL_ENVELOPE_V3_SCHEMA
                    .to_string(),
                binding_sha256: adapter_context.binding_sha256().to_string(),
                invocation_id: adapter_context.invocation_id().to_string(),
                delivery_provider_attempt_id: adapter_context
                    .delivery_provider_attempt_id()
                    .to_string(),
                provider_id: adapter_context.provider_id().to_string(),
                agent_id: adapter_context.agent_id().to_string(),
                adapter: adapter_context.adapter(),
                os_tool_call_id: prepared.os_tool_call_id.clone(),
                adapter_effect_ordinal: prepared.adapter_effect_ordinal,
                canonical_request_sha256: prepared.canonical_request_sha256.to_hex(),
                envelope_sha256: String::new(),
            };
        envelope.envelope_sha256 = envelope.digest_sha256().unwrap();
        journal
            .prepared_transport_ack(&envelope, &prepared)
            .unwrap();
        let response = serde_json::to_vec(&serde_json::json!({
            "protocol": crate::system_api::PROTOCOL,
            "request_id": prepared.request_id,
            "ok": true,
        }))
        .unwrap();
        journal
            .record_result(&prepared, &response, BackendCompletion::Response)
            .unwrap();

        let ackable = journal
            .terminal_disposition(
                replay_context
                    .authorize_replay_sync_for_test(&digest('f'))
                    .unwrap(),
            )
            .unwrap();
        let snapshot = match ackable.terminal_disposition.terminal_state {
            DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot,
            } => journal_evidence_snapshot,
            other => panic!("expected ackable replay disposition, got {other:?}"),
        };
        let inbox = outer_ack_inbox_v3(adapter_context.binding(), snapshot);
        let ack_intent = inbox.operation_replay_sync_ack_intent_sha256().unwrap();
        let prepared_ack = journal
            .prepare_outer_ack_for_replay_sync(
                replay_context
                    .authorize_replay_sync_for_test(&digest('f'))
                    .unwrap(),
                &inbox,
                &ack_intent,
            )
            .unwrap();
        let android_ack =
            crate::android_operation_replay_ack::VerifiedOperationReplayAck::for_replay_sync_test(
                &prepared_ack,
            )
            .unwrap();
        let first_confirmation = journal
            .apply_outer_ack_and_confirm(prepared_ack, &android_ack)
            .unwrap();
        first_confirmation.validate().unwrap();
        assert!(journal.recovery_plan().unwrap().is_none());
        drop(journal);

        let replay = crate::secure_first_use_journal::VerifiedJournalReplayAuthority::for_test(
            &fixture.state,
            adapter_context.agent_id(),
            adapter_context.adapter().adapter_id(),
            &epoch,
            replay_store,
            1,
        )
        .unwrap();
        let mut reopened = adapter_context
            .open_operation_journal_after_replay(replay)
            .unwrap();
        let prepared_retry = reopened
            .prepare_outer_ack_for_replay_sync(
                replay_context
                    .authorize_replay_sync_for_test(&digest('f'))
                    .unwrap(),
                &inbox,
                &ack_intent,
            )
            .unwrap();
        let android_retry =
            crate::android_operation_replay_ack::VerifiedOperationReplayAck::for_replay_sync_test(
                &prepared_retry,
            )
            .unwrap();
        let retry_confirmation = reopened
            .apply_outer_ack_and_confirm(prepared_retry, &android_retry)
            .unwrap();
        assert_eq!(retry_confirmation, first_confirmation);
        assert!(reopened.recovery_plan().unwrap().is_none());
    }

    #[test]
    fn first_use_journal_advances_same_store_cas_through_all_four_mutation_choke_points() {
        let fixture = Fixture::new();
        let context = fixture.open().unwrap();
        let authority = complete_first_use_for_test(&context, &fixture.state);
        let mut journal = crate::operation_journal::OperationJournal::open_trusted_after_first_use(
            &context, authority,
        )
        .unwrap();
        let authority_snapshot = journal
            .mutation_cas_observation_snapshot_for_test()
            .expect("first-use journal owns its same-store CAS session");
        assert!(
            authority_snapshot.1.is_empty(),
            "journal retention must not issue a mutation OBSERVE"
        );
        assert_eq!(journal.mutation_cas_generation_for_test(), Some(1));
        assert!(!format!("{journal:?}").contains("mutation_cas"));

        let prepared = journal
            .begin_effect_with_identity(
                &format!("tool-call:{}", digest('b')),
                0,
                b"retain-same-store-session-through-four-mutations",
            )
            .unwrap()
            .into_prepared();
        assert!(journal.has_mutation_cas_session_for_test());
        assert_eq!(journal.mutation_cas_generation_for_test(), Some(2));
        let after_begin = journal
            .mutation_cas_observation_snapshot_for_test()
            .unwrap();
        assert!(after_begin.0 > authority_snapshot.0);
        assert_eq!(after_begin.1.len(), 2);

        let mut envelope =
            trillionnium_os_types::direct_operation::DirectOperationToolCallEnvelopeV3 {
                schema: trillionnium_os_types::direct_operation::TOOL_CALL_ENVELOPE_V3_SCHEMA
                    .to_string(),
                binding_sha256: context.binding_sha256().to_string(),
                invocation_id: context.invocation_id().to_string(),
                delivery_provider_attempt_id: context.delivery_provider_attempt_id().to_string(),
                provider_id: context.provider_id().to_string(),
                agent_id: context.agent_id().to_string(),
                adapter: context.adapter(),
                os_tool_call_id: prepared.os_tool_call_id.clone(),
                adapter_effect_ordinal: prepared.adapter_effect_ordinal,
                canonical_request_sha256: prepared.canonical_request_sha256.to_hex(),
                envelope_sha256: String::new(),
            };
        envelope.envelope_sha256 = envelope.digest_sha256().unwrap();
        journal
            .prepared_transport_ack(&envelope, &prepared)
            .unwrap();
        assert!(journal.has_mutation_cas_session_for_test());
        assert_eq!(journal.mutation_cas_generation_for_test(), Some(3));
        let after_prepared_ack = journal
            .mutation_cas_observation_snapshot_for_test()
            .unwrap();
        assert!(after_prepared_ack.0 > after_begin.0);
        assert_eq!(after_prepared_ack.1.len(), 4);

        let response = serde_json::to_vec(&serde_json::json!({
            "protocol": crate::system_api::PROTOCOL,
            "request_id": prepared.request_id,
            "ok": true,
        }))
        .unwrap();
        journal
            .record_result(&prepared, &response, BackendCompletion::Response)
            .unwrap();
        assert!(journal.has_mutation_cas_session_for_test());
        assert_eq!(journal.mutation_cas_generation_for_test(), Some(4));
        let after_result = journal
            .mutation_cas_observation_snapshot_for_test()
            .unwrap();
        assert!(after_result.0 > after_prepared_ack.0);
        assert_eq!(after_result.1.len(), 6);

        let inbox = outer_ack_inbox_v3(context.binding(), journal.evidence_snapshot().unwrap());
        journal
            .acknowledge_outer_v3_for_test(context.binding(), context.binding_sha256(), &inbox)
            .unwrap();
        assert!(journal.has_mutation_cas_session_for_test());
        assert_eq!(journal.mutation_cas_generation_for_test(), Some(5));
        let after_outer_ack = journal
            .mutation_cas_observation_snapshot_for_test()
            .unwrap();
        assert!(after_outer_ack.0 > after_result.0);
        assert_eq!(after_outer_ack.1.len(), 8);
    }

    #[test]
    fn mutation_cas_fault_boundaries_cleanup_before_prepare_and_retain_after_prepare() {
        use crate::operation_journal::{
            MutationCasFaultForTest, OperationJournalError, fail_next_mutation_cas_for_test,
        };

        for (
            fault,
            named_changes,
            staged_candidate_remains,
            sidecar_remains,
            recovered_generation,
            next_effect_ordinal,
        ) in [
            (
                MutationCasFaultForTest::SidecarFsyncBeforePrepare,
                false,
                false,
                false,
                1,
                0,
            ),
            (
                MutationCasFaultForTest::PublicationRenameAfterPrepare,
                false,
                true,
                true,
                2,
                1,
            ),
            (
                MutationCasFaultForTest::PublicationParentFsyncAfterRename,
                true,
                false,
                true,
                2,
                1,
            ),
            (
                MutationCasFaultForTest::CleanupParentFsyncAfterCommit,
                true,
                false,
                false,
                2,
                1,
            ),
        ] {
            let fixture = Fixture::new();
            let context = fixture.open().unwrap();
            let authority = complete_first_use_for_test(&context, &fixture.state);
            let replay_store = authority.replay_lineage();
            let epoch = authority.journal_epoch().to_string();
            let mut journal =
                crate::operation_journal::OperationJournal::open_trusted_after_first_use(
                    &context, authority,
                )
                .unwrap();
            let named_before = fs::read(context.journal_path()).unwrap();

            fail_next_mutation_cas_for_test(fault);
            let result = journal.begin_effect_with_identity(
                &format!("tool-call:{}", digest('9')),
                0,
                b"mutation-cas-fault-boundary",
            );
            assert!(result.is_err());
            assert!(journal.is_fail_stopped());
            assert!(!journal.has_mutation_cas_session_for_test());
            assert!(matches!(
                journal.recovery_plan(),
                Err(OperationJournalError::ReopenRequired)
            ));

            let named_after = fs::read(context.journal_path()).unwrap();
            assert_eq!(named_after != named_before, named_changes);
            let private_names = fs::read_dir(&fixture.state)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                private_names
                    .iter()
                    .any(|name| name.starts_with(".operation-journal-staged-candidate-")),
                staged_candidate_remains
            );
            assert_eq!(
                private_names
                    .iter()
                    .any(|name| name.starts_with(".operation-journal-mutation-sidecar-")),
                sidecar_remains
            );
            drop(journal);

            let replay = crate::secure_first_use_journal::VerifiedJournalReplayAuthority::for_test(
                &fixture.state,
                context.agent_id(),
                context.adapter().adapter_id(),
                &epoch,
                replay_store,
                1,
            )
            .unwrap();
            let mut reopened = context.open_operation_journal_after_replay(replay).unwrap();
            assert!(reopened.has_mutation_cas_session_for_test());
            assert_eq!(
                reopened.mutation_cas_generation_for_test(),
                Some(recovered_generation)
            );
            let private_names = fs::read_dir(&fixture.state)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(
                !private_names.iter().any(|name| {
                    name.starts_with(".operation-journal-staged-candidate-")
                        || name.starts_with(".operation-journal-mutation-sidecar-")
                }),
                "successful replay must clean the exact retained transaction artifacts"
            );
            let recovered = reopened
                .begin_effect_with_identity(
                    &format!("tool-call:{}", digest('9')),
                    0,
                    b"mutation-cas-fault-boundary",
                )
                .unwrap()
                .into_prepared();
            let generation_after_recovered_begin =
                recovered_generation + u64::from(next_effect_ordinal == 0);
            assert_eq!(
                reopened.mutation_cas_generation_for_test(),
                Some(generation_after_recovered_begin)
            );
            let response = serde_json::to_vec(&serde_json::json!({
                "protocol": crate::system_api::PROTOCOL,
                "request_id": recovered.request_id,
                "ok": true,
            }))
            .unwrap();
            reopened
                .record_result(&recovered, &response, BackendCompletion::Response)
                .unwrap();
            assert_eq!(
                reopened.mutation_cas_generation_for_test(),
                Some(generation_after_recovered_begin + 1)
            );
        }
    }

    #[test]
    fn replay_reconciles_prepare_unknown_and_confirms_commit_unknown_after_apply() {
        use crate::direct_operation_runtime_authority_store_session::TestAuthorityStoreFault;

        for (fault, recovered_generation, staged_candidate_remains) in [
            (
                TestAuthorityStoreFault::MutationPrepareUnknownBeforeApply,
                1,
                true,
            ),
            (
                TestAuthorityStoreFault::MutationCommitUnknownAfterApply,
                2,
                false,
            ),
        ] {
            let fixture = Fixture::new();
            let context = fixture.open().unwrap();
            let authority = complete_first_use_for_test(&context, &fixture.state);
            let replay_store = authority.replay_lineage();
            let epoch = authority.journal_epoch().to_string();
            let mut journal =
                crate::operation_journal::OperationJournal::open_trusted_after_first_use(
                    &context, authority,
                )
                .unwrap();
            journal.queue_mutation_store_fault_for_test(fault);
            assert!(
                journal
                    .begin_effect_with_identity(
                        &format!("tool-call:{}", digest('b')),
                        0,
                        b"same-store-response-loss-restart",
                    )
                    .is_err()
            );
            assert!(journal.is_fail_stopped());
            let private_names = fs::read_dir(&fixture.state)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                private_names
                    .iter()
                    .any(|name| name.starts_with(".operation-journal-staged-candidate-")),
                staged_candidate_remains
            );
            assert!(
                private_names
                    .iter()
                    .any(|name| name.starts_with(".operation-journal-mutation-sidecar-"))
            );
            drop(journal);

            let replay = crate::secure_first_use_journal::VerifiedJournalReplayAuthority::for_test(
                &fixture.state,
                context.agent_id(),
                context.adapter().adapter_id(),
                &epoch,
                replay_store,
                1,
            )
            .unwrap();
            let mut reopened = context.open_operation_journal_after_replay(replay).unwrap();
            assert_eq!(
                reopened.mutation_cas_generation_for_test(),
                Some(recovered_generation)
            );
            let recovered = reopened
                .begin_effect_with_identity(
                    &format!("tool-call:{}", digest('b')),
                    0,
                    b"same-store-response-loss-restart",
                )
                .unwrap()
                .into_prepared();
            let generation_after_begin =
                recovered_generation + u64::from(recovered_generation == 1);
            assert_eq!(
                reopened.mutation_cas_generation_for_test(),
                Some(generation_after_begin)
            );
            let response = serde_json::to_vec(&serde_json::json!({
                "protocol": crate::system_api::PROTOCOL,
                "request_id": recovered.request_id,
                "ok": true,
            }))
            .unwrap();
            reopened
                .record_result(&recovered, &response, BackendCompletion::Response)
                .unwrap();
            assert_eq!(
                reopened.mutation_cas_generation_for_test(),
                Some(generation_after_begin + 1)
            );
        }
    }

    #[test]
    fn first_use_capability_rejects_journal_or_sentinel_drift_before_runtime_open() {
        for target in [JOURNAL_FILE_NAME, "operations.first-use-committed.json"] {
            let fixture = Fixture::new();
            let context = fixture.open().unwrap();
            let authority = complete_first_use_for_test(&context, &fixture.state);
            fs::write(fixture.state.join(target), b"drift\n").unwrap();
            assert!(matches!(
                crate::operation_journal::OperationJournal::open_trusted_after_first_use(
                    &context, authority,
                ),
                Err(crate::operation_journal::OperationJournalError::FirstUseAuthority(_))
            ));
        }
    }

    #[test]
    fn sealed_replay_authority_reopens_current_epoch_and_replays_terminal_bytes() {
        let fixture = Fixture::new();
        let context = fixture.open().unwrap();
        let first_use = complete_first_use_for_test(&context, &fixture.state);
        let lineage = first_use.replay_lineage();
        let epoch = first_use.journal_epoch().to_string();
        let tool_call_id = format!("tool-call:{}", digest('d'));
        let mut journal = crate::operation_journal::OperationJournal::open_trusted_after_first_use(
            &context, first_use,
        )
        .unwrap();
        let prepared = journal
            .begin_effect_with_identity(&tool_call_id, 0, b"restart-replay-terminal-result")
            .unwrap()
            .into_prepared();
        let mut envelope =
            trillionnium_os_types::direct_operation::DirectOperationToolCallEnvelopeV3 {
                schema: trillionnium_os_types::direct_operation::TOOL_CALL_ENVELOPE_V3_SCHEMA
                    .to_string(),
                binding_sha256: context.binding_sha256().to_string(),
                invocation_id: context.invocation_id().to_string(),
                delivery_provider_attempt_id: context.delivery_provider_attempt_id().to_string(),
                provider_id: context.provider_id().to_string(),
                agent_id: context.agent_id().to_string(),
                adapter: context.adapter(),
                os_tool_call_id: prepared.os_tool_call_id.clone(),
                adapter_effect_ordinal: prepared.adapter_effect_ordinal,
                canonical_request_sha256: prepared.canonical_request_sha256.to_hex(),
                envelope_sha256: String::new(),
            };
        envelope.envelope_sha256 = envelope.digest_sha256().unwrap();
        let prepared_ack = journal
            .prepared_transport_ack(&envelope, &prepared)
            .unwrap();
        let response = serde_json::to_vec(&serde_json::json!({
            "protocol": crate::system_api::PROTOCOL,
            "request_id": prepared.request_id,
            "ok": true,
        }))
        .unwrap();
        journal
            .record_result(&prepared, &response, BackendCompletion::Response)
            .unwrap();
        drop(journal);

        let replay = crate::secure_first_use_journal::VerifiedJournalReplayAuthority::for_test(
            &fixture.state,
            context.agent_id(),
            context.adapter().adapter_id(),
            &epoch,
            lineage,
            1,
        )
        .unwrap();
        let mut reopened = context.open_operation_journal_after_replay(replay).unwrap();
        assert!(reopened.has_mutation_cas_session_for_test());
        assert_eq!(reopened.mutation_cas_generation_for_test(), Some(4));
        assert!(
            reopened
                .mutation_cas_observation_snapshot_for_test()
                .is_some()
        );
        let recovered = reopened
            .begin_effect_with_identity(&tool_call_id, 0, b"restart-replay-terminal-result")
            .unwrap()
            .into_prepared();
        let replayed_prepared_ack = reopened
            .prepared_transport_ack(&envelope, &recovered)
            .unwrap();
        assert_eq!(recovered.epoch, epoch);
        assert_eq!(replayed_prepared_ack, prepared_ack);
        assert_eq!(
            reopened.replay_terminal_result(&recovered).unwrap(),
            Some(response)
        );
    }

    #[test]
    fn sealed_replay_authority_reproduces_the_exact_unresolved_prepared_ack() {
        let fixture = Fixture::new();
        let context = fixture.open().unwrap();
        let first_use = complete_first_use_for_test(&context, &fixture.state);
        let lineage = first_use.replay_lineage();
        let epoch = first_use.journal_epoch().to_string();
        let tool_call_id = format!("tool-call:{}", digest('1'));
        let canonical = b"restart-replay-unresolved-prepared";
        let mut journal = crate::operation_journal::OperationJournal::open_trusted_after_first_use(
            &context, first_use,
        )
        .unwrap();
        let prepared = journal
            .begin_effect_with_identity(&tool_call_id, 0, canonical)
            .unwrap()
            .into_prepared();
        let mut envelope =
            trillionnium_os_types::direct_operation::DirectOperationToolCallEnvelopeV3 {
                schema: trillionnium_os_types::direct_operation::TOOL_CALL_ENVELOPE_V3_SCHEMA
                    .to_string(),
                binding_sha256: context.binding_sha256().to_string(),
                invocation_id: context.invocation_id().to_string(),
                delivery_provider_attempt_id: context.delivery_provider_attempt_id().to_string(),
                provider_id: context.provider_id().to_string(),
                agent_id: context.agent_id().to_string(),
                adapter: context.adapter(),
                os_tool_call_id: prepared.os_tool_call_id.clone(),
                adapter_effect_ordinal: prepared.adapter_effect_ordinal,
                canonical_request_sha256: prepared.canonical_request_sha256.to_hex(),
                envelope_sha256: String::new(),
            };
        envelope.envelope_sha256 = envelope.digest_sha256().unwrap();
        let before_restart = journal
            .prepared_transport_ack(&envelope, &prepared)
            .unwrap();
        drop(journal);

        let replay = crate::secure_first_use_journal::VerifiedJournalReplayAuthority::for_test(
            &fixture.state,
            context.agent_id(),
            context.adapter().adapter_id(),
            &epoch,
            lineage,
            1,
        )
        .unwrap();
        let mut reopened = context.open_operation_journal_after_replay(replay).unwrap();
        let recovered = reopened
            .begin_effect_with_identity(&tool_call_id, 0, canonical)
            .unwrap()
            .into_prepared();
        let after_restart = reopened
            .prepared_transport_ack(&envelope, &recovered)
            .unwrap();

        assert_eq!(recovered, prepared);
        assert_eq!(after_restart, before_restart);
    }

    #[test]
    fn replay_open_restores_same_store_mutation_session_for_a_new_journal_version() {
        let fixture = Fixture::new();
        let context = fixture.open().unwrap();
        let first_use = complete_first_use_for_test(&context, &fixture.state);
        let lineage = first_use.replay_lineage();
        let epoch = first_use.journal_epoch().to_string();
        let mut journal = crate::operation_journal::OperationJournal::open_trusted_after_first_use(
            &context, first_use,
        )
        .unwrap();
        let prepared = journal
            .begin_effect_with_identity(
                &format!("tool-call:{}", digest('7')),
                0,
                b"complete-before-replay-mutation-hold",
            )
            .unwrap()
            .into_prepared();
        let response = serde_json::to_vec(&serde_json::json!({
            "protocol": crate::system_api::PROTOCOL,
            "request_id": prepared.request_id,
            "ok": true,
        }))
        .unwrap();
        journal
            .record_result(&prepared, &response, BackendCompletion::Response)
            .unwrap();
        drop(journal);

        let replay = crate::secure_first_use_journal::VerifiedJournalReplayAuthority::for_test(
            &fixture.state,
            context.agent_id(),
            context.adapter().adapter_id(),
            &epoch,
            lineage,
            1,
        )
        .unwrap();
        let mut reopened = context.open_operation_journal_after_replay(replay).unwrap();
        assert!(reopened.has_mutation_cas_session_for_test());
        assert_eq!(reopened.mutation_cas_generation_for_test(), Some(3));
        let named_before = fs::read(context.journal_path()).unwrap();
        reopened
            .begin_effect_with_identity(
                &format!("tool-call:{}", digest('8')),
                1,
                b"new-mutation-after-replay-uses-same-store",
            )
            .unwrap();
        assert!(!reopened.is_fail_stopped());
        assert_eq!(reopened.mutation_cas_generation_for_test(), Some(4));
        assert_ne!(fs::read(context.journal_path()).unwrap(), named_before);
    }

    #[test]
    fn replay_authority_rejects_same_bytes_replacement_and_valid_snapshot_rollback() {
        for rollback_to_genesis in [false, true] {
            let fixture = Fixture::new();
            let context = fixture.open().unwrap();
            let first_use = complete_first_use_for_test(&context, &fixture.state);
            let lineage = first_use.replay_lineage();
            let epoch = first_use.journal_epoch().to_string();
            let genesis = fs::read(context.journal_path()).unwrap();
            let mut journal =
                crate::operation_journal::OperationJournal::open_trusted_after_first_use(
                    &context, first_use,
                )
                .unwrap();
            journal
                .begin_effect_with_identity(
                    &format!("tool-call:{}", digest('e')),
                    0,
                    b"newer-state-before-replay-authority",
                )
                .unwrap();
            drop(journal);
            let replay = crate::secure_first_use_journal::VerifiedJournalReplayAuthority::for_test(
                &fixture.state,
                context.agent_id(),
                context.adapter().adapter_id(),
                &epoch,
                lineage,
                2,
            )
            .unwrap();

            let replacement = fixture.state.join("operations.replacement");
            let replacement_bytes = if rollback_to_genesis {
                genesis.clone()
            } else {
                fs::read(context.journal_path()).unwrap()
            };
            fs::write(&replacement, replacement_bytes).unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(&replacement, context.journal_path()).unwrap();

            assert!(matches!(
                context.open_operation_journal_after_replay(replay),
                Err(crate::operation_journal::OperationJournalError::ReplayAuthority(_))
            ));
        }
    }

    #[test]
    fn replay_authority_rejects_sentinel_replacement_and_epoch_drift() {
        for drift_epoch in [false, true] {
            let fixture = Fixture::new();
            let context = fixture.open().unwrap();
            let first_use = complete_first_use_for_test(&context, &fixture.state);
            let lineage = first_use.replay_lineage();
            let epoch = first_use.journal_epoch().to_string();
            let mut journal =
                crate::operation_journal::OperationJournal::open_trusted_after_first_use(
                    &context, first_use,
                )
                .unwrap();
            journal
                .begin_effect_with_identity(
                    &format!("tool-call:{}", digest('f')),
                    0,
                    b"replay-sentinel-or-epoch-negative",
                )
                .unwrap();
            drop(journal);

            let requested_epoch = if drift_epoch {
                "0".repeat(32)
            } else {
                epoch.clone()
            };
            let replay = crate::secure_first_use_journal::VerifiedJournalReplayAuthority::for_test(
                &fixture.state,
                context.agent_id(),
                context.adapter().adapter_id(),
                &requested_epoch,
                lineage,
                3,
            );
            if drift_epoch {
                assert!(replay.is_err());
                continue;
            }
            let replay = replay.unwrap();
            let sentinel_path = fixture.state.join("operations.first-use-committed.json");
            let replacement = fixture.state.join("sentinel.replacement");
            fs::write(&replacement, fs::read(&sentinel_path).unwrap()).unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(&replacement, &sentinel_path).unwrap();
            assert!(matches!(
                context.open_operation_journal_after_replay(replay),
                Err(crate::operation_journal::OperationJournalError::ReplayAuthority(_))
            ));
        }
    }

    #[test]
    fn fixed_test_context_reads_exact_binding_and_separates_journal_path() {
        let fixture = Fixture::new();
        let delivery_attempt_b = fixture
            .binding
            .binding
            .attempt
            .delivery_provider_attempt_id
            .clone();
        let allocating_attempt_a =
            DirectOperationProviderAttempt::derive(digest('a'), 2, digest('b'))
                .unwrap()
                .delivery_provider_attempt_id;
        assert_ne!(delivery_attempt_b, allocating_attempt_a);
        let context = fixture.open().unwrap();
        assert_eq!(context.provider_id(), CODEX_PROVIDER_ID);
        assert_eq!(context.agent_id(), CODEX_AGENT_ID);
        assert_eq!(context.binding_sha256(), fixture.binding.binding_sha256);
        assert_eq!(context.delivery_provider_attempt_id(), delivery_attempt_b);
        assert_eq!(
            context.invocation_id(),
            fixture.binding.binding.invocation_id
        );
        assert_eq!(
            context.journal_path(),
            fixture.state.join(JOURNAL_FILE_NAME)
        );
        assert_ne!(context.journal_path(), fixture.binding_path);
        assert!(matches!(
            context.open_operation_journal(),
            Err(crate::operation_journal::OperationJournalError::FirstUseAuthorityUnavailable)
        ));
        assert!(!context.journal_path().exists());
    }

    #[test]
    fn hidden_current_context_requires_no_model_launch_parameters() {
        let fixture = Fixture::new();
        let context = TrustedAdapterContext::open_current_for_test(
            DirectOperationAdapter::SystemApi,
            CODEX_PROVIDER_ID,
            CODEX_AGENT_ID,
            fixture.state.clone(),
            fixture.inbox.clone(),
        )
        .unwrap();
        assert_eq!(context.binding(), &fixture.binding.binding);
        assert_eq!(context.binding_sha256(), fixture.binding.binding_sha256);
    }

    #[test]
    fn consumed_hidden_context_is_frozen_against_later_path_replacement() {
        let fixture = Fixture::new();
        let context = TrustedAdapterContext::open_current_for_test(
            DirectOperationAdapter::SystemApi,
            CODEX_PROVIDER_ID,
            CODEX_AGENT_ID,
            fixture.state.clone(),
            fixture.inbox.clone(),
        )
        .unwrap();
        let frozen = context.binding().clone();
        let mut replacement = inbox();
        replacement.binding.attempt =
            DirectOperationProviderAttempt::derive(digest('5'), 2, digest('4')).unwrap();
        replacement.binding_sha256 = replacement.binding.digest_sha256().unwrap();
        let mut encoded = serde_json::to_vec(&replacement).unwrap();
        encoded.push(b'\n');
        fs::write(&fixture.binding_path, encoded).unwrap();
        fs::set_permissions(&fixture.binding_path, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(context.binding(), &frozen);
        assert_ne!(context.binding(), &replacement.binding);
    }

    #[test]
    fn production_hidden_context_is_explicit_and_uses_no_launch_arguments() {
        for source in [
            include_str!("bin/system_api.rs"),
            include_str!("bin/accessibility.rs"),
        ] {
            assert!(source.contains("TrustedAdapterContext::open_current_product"));
            assert!(source.contains("call_semantic_trusted"));
            assert!(source.contains("raw backend-wire mode is non-product"));
            assert!(source.contains("feature = \"production-durable-hotpath\""));
            for forbidden in [
                "expected_binding_sha256",
                "expected_invocation_id",
                "expected_task_id",
                "expected_delivery_provider_attempt_id",
                "workflow_id_sha256",
                "agent_identity_key_sha256",
                "agent_executable_sha256",
            ] {
                assert!(!source.contains(forbidden));
            }
        }
        for schema in [
            crate::system_api::mcp_tool().input_schema,
            crate::accessibility::mcp_tool().input_schema,
        ] {
            let rendered = serde_json::to_string(&schema).unwrap();
            for forbidden in [
                "workflow_id_sha256",
                "agent_identity_key_sha256",
                "agent_executable_sha256",
            ] {
                assert!(!rendered.contains(forbidden));
            }
        }
        let build = include_str!("../tools/build-root-linux-arm64.sh");
        assert!(build.contains("--no-default-features"));
        assert!(build.contains("--locked"));
        assert!(build.contains("--offline"));
        assert!(build.contains("-p trillionniumd"));
        assert!(
            build.contains("--features trillionnium-agent-direct-tools/production-durable-hotpath")
        );
    }

    #[test]
    fn root_linux_build_is_source_fixed_to_the_bookworm_abi_and_closed_elf_contract() {
        let build = include_str!("../tools/build-root-linux-arm64.sh");
        for required in [
            "readonly MAX_GLIBC=\"2.36\"",
            "TRILLIONNIUM_AARCH64_LINUX_GNU_SYSROOT is required",
            "an explicit private CARGO_HOME is required",
            "an explicit fresh CARGO_TARGET_DIR is required",
            "TRILLIONNIUM_ROOT_LINUX_HOST_TOOLS_DIRECTORY is required",
            "TRILLIONNIUM_ROOT_LINUX_HOST_LINKER is required",
            "TRILLIONNIUM_ROOT_LINUX_HOST_AR is required",
            "TRILLIONNIUM_ROOT_LINUX_PRIVATE_TOOLCHAIN_ROOT is required",
            "readonly SOURCE_FIXED_CARGO_HOME_MANIFEST_SHA256=",
            "readonly SOURCE_FIXED_PRIVATE_TOOLCHAIN_MANIFEST_SHA256=",
            "readonly SOURCE_FIXED_SYSROOT_LIBGCC_S_SHA256=",
            "readonly SOURCE_FIXED_SYSROOT_LIBM_SHA256=",
            "caller-supplied Cargo-home digests are forbidden; the closure is source-fixed",
            "caller-supplied private-toolchain digests are forbidden; the closure is source-fixed",
            "Cargo-home closure digest does not match the source-fixed digest",
            "private-toolchain closure digest does not match the source-fixed digest",
            "private toolchain mount is not read-only",
            "private-toolchain read-only proof requires the fixed runtime uid 1000",
            "readonly ACTUAL_HOST_BASH=\"$(\"$HOST_REALPATH\" -e \"/proc/$$/exe\")\"",
            "[[ \"$ACTUAL_HOST_BASH\" == \"$FIXED_HOST_BASH\" ]]",
            "[[ \"/proc/$$/exe\" -ef \"$FIXED_HOST_BASH\" ]]",
            "actual_interpreter_sha256=%s",
            "\"$HOST_ENV\" -i",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
            "LIBSQLITE3_SYS_USE_PKG_CONFIG=0",
            "build_contract=path-closed-cache-toolchain-content-pinned-measured-host-tcb hermetic=false",
            "host_userspace_rootfs_content_addressed_external_lane_required=true",
            "Cargo-home closure changed during the build",
            "private-toolchain closure changed during the build",
            "prebuild_postbuild_equal=true",
            "runtime_readonly_mount=true",
            "eight_private_leaf_digests_source_fixed=true",
            "remap destination contains a source build path",
            "artifact leaks build path $forbidden_path",
            "symlink_escape_gate=true",
            "EXPECTED_DIRECT_NEEDED=$'libgcc_s.so.1\\nlibc.so.6'",
            "EXPECTED_DAEMON_NEEDED=$'libgcc_s.so.1\\nlibm.so.6\\nlibc.so.6'",
            "trillionnium-system-api-replay-sync",
            "trillionnium-system-api-operation-replay-sync",
            "trillionnium-accessibility-operation-replay-sync",
            "built operation replay-sync helper is missing",
            "-Wl,--as-needed",
            "-Wl,--build-id=sha1",
            "-Wl,-z,relro,-z,now",
            "artifact lacks BIND_NOW or PIE",
            "artifact contains forbidden $forbidden",
            "artifact has a missing or executable GNU_STACK",
            "artifact requires GLIBC_$maximum, newer than GLIBC_$MAX_GLIBC",
        ] {
            assert!(build.contains(required), "missing build gate: {required}");
        }
        for forbidden in [
            "curl ",
            "wget ",
            "apt-get ",
            "dpkg -i",
            "package_current_rootfs",
        ] {
            assert!(
                !build.contains(forbidden),
                "root build must not fetch, install or refresh: {forbidden}"
            );
        }

        let cargo_home_manifest =
            include_str!("../tools/canonical-root-linux-cargo-home-manifest.sh");
        for required in [
            "trillionnium.root-linux.cargo-home.canonical-manifest.v2",
            "Cargo-home symlink escapes the closure",
            "Cargo-home closure crosses a filesystem boundary",
            "Cargo-home closure contains a multiply linked file",
            "Cargo-home closure contains a write-enabled entry",
            "find -P . -mindepth 0 \\( -type f -o -type d \\) -perm /222 -print -quit",
            "sha256sum -b -z --",
            "readlink -z --",
        ] {
            assert!(
                cargo_home_manifest.contains(required),
                "missing Cargo-home closure gate: {required}"
            );
        }
        assert!(!cargo_home_manifest.contains("-perm /022"));

        let private_toolchain_manifest =
            include_str!("../tools/canonical-root-linux-toolchain-manifest.sh");
        for required in [
            "trillionnium.root-linux.private-toolchain.canonical-manifest.v1",
            "unsupported private-toolchain entry",
            "regular-file-sha256",
            "sha256sum -b -z --",
            "symlink-targets",
            "readlink -z --",
            "Runtime immutability is a",
            "separate read-only-mount gate",
        ] {
            assert!(
                private_toolchain_manifest.contains(required),
                "missing private-toolchain content gate: {required}"
            );
        }

        let bookworm_builder =
            include_str!("../tools/root-linux-bookworm-builder-candidate-v1.json");
        for required in [
            "\"schema\": \"trillionnium.root-linux.bookworm-builder-candidate.v1\"",
            "\"local_builder_image_index_digest\": \"sha256:a736afffbcc4bb1c8350cc5c6f9dbaba5b973aa2c1f7e152731af8602916a8ed\"",
            "\"local_builder_linux_amd64_manifest_digest\": \"sha256:f45df717ed9d4926691b7906ed5beef6823d308cc1bc093c879ea8a314042130\"",
            "\"local_builder_config_digest\": \"sha256:20b9970bd3914c6304b499b6e4651a8711d5f41eda600b0e2e2b1a628c737449\"",
            "\"source_fixed_cargo_home_manifest_sha256\": \"711d39583b0004485a9e226442f1476a203a32601fac061198c9d6f933520b63\"",
            "\"source_fixed_private_toolchain_manifest_sha256\": \"8ee268e616feb4d5d9cb07ba363d4966c88bfb915d2d0147014cbed6d45a05d2\"",
            "\"sysroot_libm\": \"3c4cb3be0b974edf05f023f85ab15107fb5afc2687163593d0d4cf8e80c17b39\"",
            "\"private_toolchain_readonly_bind_required\": true",
            "\"host_userspace_rootfs_content_addressed\": true",
            "\"host_kernel_pinned\": false",
            "\"registry_and_image_provenance_independently_approved\": false",
            "\"private_toolchain_origin_independently_approved\": false",
            "\"production_builder_approvals_observed\": 0",
            "\"production_builder_approvals_required\": 2",
            "\"rollback_resistant_epoch_high_water_present\": false",
            "\"production_builder_approved\": false",
            "\"rootfs_refresh_authorized\": false",
            "\"production_payload_refresh_performed\": false",
        ] {
            assert!(
                bookworm_builder.contains(required),
                "missing Bookworm builder HOLD: {required}"
            );
        }
    }

    #[test]
    fn hotpath_only_library_has_no_production_call_bypass() {
        for source in [
            include_str!("system_api.rs"),
            include_str!("accessibility.rs"),
        ] {
            assert!(
                source.contains("#[cfg(any(test, feature = \"development-compatibility-lane\"))]"),
                "ephemeral backend calls must require the explicit development lane"
            );
            assert!(
                !source.contains("not(feature = \"trusted-context-hotpath\")"),
                "absence of the trusted hotpath must not compile an effect fallback"
            );
            let trusted = source
                .split_once("pub fn call_trusted(")
                .unwrap()
                .1
                .split_once("pub(crate) fn call_as(")
                .unwrap()
                .0;
            assert!(trusted.contains("current_agent_identity()?"));
            assert!(trusted.contains("trusted_preflight(request, agent)?"));
            let custody = trusted
                .find("require_product_effect_custody()")
                .expect("product custody must be checked");
            let journal = trusted
                .find("open_operation_journal()")
                .expect("durable journal must be opened");
            if source.contains("trusted Accessibility snapshot requires a separate") {
                let read_only_classification = trusted
                    .find("requires_durable_operation_sequence()")
                    .expect("Accessibility must classify read-only snapshots");
                assert!(
                    read_only_classification < custody,
                    "read-only snapshots must HOLD before product custody or journal state"
                );
            }
            assert!(custody < journal);
            assert!(trusted.contains("open_operation_journal()"));
            assert!(
                trusted.contains(
                    "call_allowed_journaled(path, request, agent, context, &mut journal)"
                )
            );
            assert!(!trusted.contains("call_as(path, request, agent)"));
            assert!(!trusted.contains("call(path, request)"));
        }
    }

    #[test]
    fn fixed_v3_ack_inbox_is_never_consumed_by_the_tool_context() {
        let fixture = Fixture::new();
        let context = fixture.open().unwrap();
        let initialized = crate::operation_journal::OperationJournal::open(
            context.journal_path(),
            context.agent_id(),
            context.adapter().adapter_id(),
            context.invocation_id(),
            context.delivery_provider_attempt_id(),
        )
        .unwrap();
        assert!(!initialized.has_mutation_cas_session_for_test());
        assert!(
            initialized
                .mutation_cas_observation_snapshot_for_test()
                .is_none()
        );
        drop(initialized);
        let mut journal = context
            .open_operation_journal_without_first_use_for_test()
            .unwrap();
        assert!(!journal.has_mutation_cas_session_for_test());
        assert!(
            journal
                .mutation_cas_observation_snapshot_for_test()
                .is_none()
        );
        let prepared = journal
            .begin_next_effect(b"trusted-context-v3-ack-effect")
            .unwrap()
            .into_prepared();
        let response = serde_json::to_vec(&serde_json::json!({
            "protocol": crate::system_api::PROTOCOL,
            "request_id": prepared.request_id,
            "ok": true,
        }))
        .unwrap();
        journal
            .record_result(&prepared, &response, BackendCompletion::Response)
            .unwrap();
        let snapshot = journal.evidence_snapshot().unwrap();
        let inbox = outer_ack_inbox_v3(&fixture.binding.binding, snapshot);
        let ack_path = fixture.inbox.join("pending-outer-ack-v3.json");
        for version in 1..=2 {
            let mut old = inbox.clone();
            old.schema = format!("trillionnium.direct-operation-outer-ack-inbox.v{version}");
            old.acknowledgement.schema =
                format!("trillionnium.direct-operation-outer-ack.v{version}");
            let mut old_encoded = serde_json::to_vec(&old).unwrap();
            old_encoded.push(b'\n');
            fs::write(&ack_path, old_encoded).unwrap();
            fs::set_permissions(&ack_path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                context.require_no_pending_outer_ack_v3(),
                Err(TrustedContextError::Corrupt(_))
            ));
            assert!(journal.recovery_plan().unwrap().is_some());
        }
        let mut encoded = serde_json::to_vec(&inbox).unwrap();
        encoded.push(b'\n');
        fs::write(&ack_path, &encoded).unwrap();

        fs::set_permissions(&ack_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(context.require_no_pending_outer_ack_v3().is_err());
        assert!(journal.recovery_plan().unwrap().is_some());

        fs::set_permissions(&ack_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            context.require_no_pending_outer_ack_v3(),
            Err(TrustedContextError::PendingOuterAckRequiresReplaySync)
        ));
        assert!(journal.recovery_plan().unwrap().is_some());
        assert!(matches!(
            context.require_no_pending_outer_ack_v3(),
            Err(TrustedContextError::PendingOuterAckRequiresReplaySync)
        ));
        assert!(journal.recovery_plan().unwrap().is_some());
    }

    #[test]
    fn journal_open_retains_the_exact_validated_state_directory_inode() {
        let fixture = Fixture::new();
        let context = fixture.open().unwrap();
        let displaced = fixture._root.path().join("displaced-state");
        fs::rename(&fixture.state, &displaced).unwrap();
        fs::create_dir(&fixture.state).unwrap();
        fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(
            context.open_operation_journal_without_first_use_for_test(),
            Err(crate::operation_journal::OperationJournalError::IdentityMismatch)
        ));
    }

    #[test]
    fn product_matrix_is_fixed_by_codex_uid_gid_and_adapter_domain() {
        for (uid, gid, provider_dir, provider_id, agent_id) in [(
            CODEX_UID,
            CODEX_GID,
            "codex",
            CODEX_PROVIDER_ID,
            CODEX_AGENT_ID,
        )] {
            for (adapter, adapter_dir, domain) in [
                (
                    DirectOperationAdapter::SystemApi,
                    "system-api",
                    SYSTEM_API_DOMAIN,
                ),
                (
                    DirectOperationAdapter::Accessibility,
                    "accessibility",
                    ACCESSIBILITY_DOMAIN,
                ),
            ] {
                let value =
                    product_specification(product_identity(uid, gid), domain, adapter).unwrap();
                assert_eq!(value.provider_id, provider_id);
                assert_eq!(value.agent_id, agent_id);
                assert_eq!(
                    value.state_directory,
                    Path::new(PRODUCT_STATE_ROOT)
                        .join(provider_dir)
                        .join(adapter_dir)
                );
                assert_eq!(
                    value.inbox_directory,
                    Path::new(PRODUCT_INBOX_ROOT)
                        .join(provider_dir)
                        .join(adapter_dir)
                );
            }
        }
        assert!(
            product_specification(
                product_identity(CODEX_UID, CODEX_GID + 1),
                SYSTEM_API_DOMAIN,
                DirectOperationAdapter::SystemApi
            )
            .is_err()
        );
        assert!(
            product_specification(
                product_identity(CODEX_UID, CODEX_GID),
                ACCESSIBILITY_DOMAIN,
                DirectOperationAdapter::SystemApi
            )
            .is_err()
        );

        for mismatched in [
            ProcessIdentity {
                real_uid: CODEX_UID + 1,
                ..product_identity(CODEX_UID, CODEX_GID)
            },
            ProcessIdentity {
                effective_uid: CODEX_UID + 1,
                ..product_identity(CODEX_UID, CODEX_GID)
            },
            ProcessIdentity {
                real_gid: CODEX_GID + 1,
                ..product_identity(CODEX_UID, CODEX_GID)
            },
            ProcessIdentity {
                effective_gid: CODEX_GID + 1,
                ..product_identity(CODEX_UID, CODEX_GID)
            },
        ] {
            assert!(
                product_specification(
                    mismatched,
                    SYSTEM_API_DOMAIN,
                    DirectOperationAdapter::SystemApi,
                )
                .is_err()
            );
        }

        for (adapter, operation_domain, tool_domain, binary) in [
            (
                DirectOperationAdapter::SystemApi,
                SYSTEM_API_OPERATION_REPLAY_SYNC_DOMAIN,
                SYSTEM_API_DOMAIN,
                SYSTEM_API_OPERATION_REPLAY_SYNC_BINARY,
            ),
            (
                DirectOperationAdapter::Accessibility,
                ACCESSIBILITY_OPERATION_REPLAY_SYNC_DOMAIN,
                ACCESSIBILITY_DOMAIN,
                ACCESSIBILITY_OPERATION_REPLAY_SYNC_BINARY,
            ),
        ] {
            let (specification, admitted_domain, admitted_binary) =
                replay_sync_product_specification(
                    product_identity(CODEX_UID, CODEX_GID),
                    operation_domain,
                    adapter,
                )
                .unwrap();
            assert_eq!(specification.provider_id, CODEX_PROVIDER_ID);
            assert_eq!(admitted_domain, operation_domain);
            assert_eq!(admitted_binary, binary);
            assert!(
                replay_sync_product_specification(
                    product_identity(CODEX_UID, CODEX_GID),
                    tool_domain,
                    adapter,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn product_replay_sync_entrypoints_remain_fixed_in_system_ext() {
        assert_eq!(
            SYSTEM_API_OPERATION_REPLAY_SYNC_BINARY,
            "/system_ext/bin/trillionnium-system-api-operation-replay-sync"
        );
        assert_eq!(
            ACCESSIBILITY_OPERATION_REPLAY_SYNC_BINARY,
            "/system_ext/bin/trillionnium-accessibility-operation-replay-sync"
        );
    }

    #[cfg(feature = "device-launch-package-conformance")]
    #[test]
    fn device_conformance_replay_sync_admits_only_the_canonical_chroot_entrypoint() {
        const FORMER_SYSTEM_EXT_ALIAS: &str =
            "/system_ext/bin/trillionnium-system-api-device-conformance-replay-sync";

        assert_eq!(
            SYSTEM_API_DEVICE_CONFORMANCE_REPLAY_SYNC_BINARY,
            "/usr/local/bin/trillionnium-system-api-device-conformance-replay-sync"
        );
        assert!(
            validate_executable_path(
                Path::new(SYSTEM_API_DEVICE_CONFORMANCE_REPLAY_SYNC_BINARY),
                SYSTEM_API_DEVICE_CONFORMANCE_REPLAY_SYNC_BINARY,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_executable_path(
                Path::new(FORMER_SYSTEM_EXT_ALIAS),
                SYSTEM_API_DEVICE_CONFORMANCE_REPLAY_SYNC_BINARY,
            ),
            Err(TrustedContextError::Identity(
                "process executable is not the fixed operation replay-sync entrypoint"
            ))
        ));
    }

    #[test]
    fn digest_provider_and_agent_forgery_fail_closed() {
        let fixture = Fixture::new();
        assert!(matches!(
            TrustedAdapterContext::open_for_test(
                DirectOperationAdapter::SystemApi,
                CODEX_PROVIDER_ID,
                CODEX_AGENT_ID,
                fixture.state.clone(),
                fixture.inbox.clone(),
                LaunchExpectation {
                    binding_sha256: &digest('f'),
                    ..fixture.expectation()
                },
            ),
            Err(TrustedContextError::BindingDigestMismatch)
        ));
        assert!(
            TrustedAdapterContext::open_for_test(
                DirectOperationAdapter::SystemApi,
                "unregistered-provider",
                "unregistered-agent",
                fixture.state.clone(),
                fixture.inbox.clone(),
                fixture.expectation(),
            )
            .is_err()
        );
    }

    #[test]
    fn symlink_hardlink_mode_and_noncanonical_inbox_are_rejected() {
        {
            let fixture = Fixture::new();
            let real = fixture.inbox.join("real.json");
            fs::rename(&fixture.binding_path, &real).unwrap();
            symlink(&real, &fixture.binding_path).unwrap();
            assert!(fixture.open().is_err());
        }
        {
            let fixture = Fixture::new();
            fs::hard_link(&fixture.binding_path, fixture.inbox.join("second-link")).unwrap();
            assert!(fixture.open().is_err());
        }
        {
            let fixture = Fixture::new();
            fs::set_permissions(&fixture.binding_path, fs::Permissions::from_mode(0o640)).unwrap();
            assert!(fixture.open().is_err());
        }
        {
            let fixture = Fixture::new();
            fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o750)).unwrap();
            assert!(fixture.open().is_err());
        }
        {
            let fixture = Fixture::new();
            let real_inbox = fixture._root.path().join("real-inbox");
            fs::rename(&fixture.inbox, &real_inbox).unwrap();
            symlink(&real_inbox, &fixture.inbox).unwrap();
            assert!(fixture.open().is_err());
        }
        {
            let fixture = Fixture::new();
            let mut pretty = serde_json::to_vec_pretty(&fixture.binding).unwrap();
            pretty.push(b'\n');
            fs::write(&fixture.binding_path, pretty).unwrap();
            fs::set_permissions(&fixture.binding_path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(fixture.open().is_err());
        }
    }

    #[test]
    fn unknown_or_raw_model_fields_never_enter_the_binding_inbox() {
        let fixture = Fixture::new();
        let mut value = serde_json::to_value(&fixture.binding).unwrap();
        value["binding"]["request_id"] = serde_json::json!("model-controlled");
        value["binding"]["journal_path"] = serde_json::json!("/tmp/attacker");
        value["binding"]["uri"] = serde_json::json!("content://private");
        value["binding"]["text"] = serde_json::json!("private input");
        value["binding"]["result"] = serde_json::json!({"private": true});
        value["binding"]["risk"] = serde_json::json!({"tier": "model-authored"});
        let mut encoded = serde_json::to_vec(&value).unwrap();
        encoded.push(b'\n');
        fs::write(&fixture.binding_path, encoded).unwrap();
        fs::set_permissions(&fixture.binding_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(fixture.open().is_err());
    }

    #[test]
    fn stale_and_cross_task_launch_selection_fail_closed() {
        let fixture = Fixture::new();
        let binding = &fixture.binding.binding;
        for (digest, invocation, task, attempt) in [
            (
                digest('f'),
                binding.invocation_id.as_str(),
                binding.stable_seed.task_id.as_str(),
                binding.attempt.delivery_provider_attempt_id.as_str(),
            ),
            (
                fixture.binding.binding_sha256.clone(),
                "inv:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                binding.stable_seed.task_id.as_str(),
                binding.attempt.delivery_provider_attempt_id.as_str(),
            ),
            (
                fixture.binding.binding_sha256.clone(),
                binding.invocation_id.as_str(),
                "task-other",
                binding.attempt.delivery_provider_attempt_id.as_str(),
            ),
            (
                fixture.binding.binding_sha256.clone(),
                binding.invocation_id.as_str(),
                binding.stable_seed.task_id.as_str(),
                "attempt:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        ] {
            assert!(
                TrustedAdapterContext::open_for_test(
                    DirectOperationAdapter::SystemApi,
                    CODEX_PROVIDER_ID,
                    CODEX_AGENT_ID,
                    fixture.state.clone(),
                    fixture.inbox.clone(),
                    LaunchExpectation {
                        binding_sha256: &digest,
                        invocation_id: invocation,
                        task_id: task,
                        delivery_provider_attempt_id: attempt,
                    },
                )
                .is_err()
            );
        }
    }
}
