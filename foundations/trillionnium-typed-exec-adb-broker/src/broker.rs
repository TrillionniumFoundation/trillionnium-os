//! Crate-private broker state machine and userdebug conformance admission.
//!
//! The only executable seam is a sealed read-only action enum used by tests.
//! There is no public backend trait, authority constructor, listener, process
//! launcher, or product ledger implementation.

#![allow(dead_code)] // Deliberately unexported until a reviewed OS listener owns it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::protocol::{
    BrokerBindingIdentityV1, CATALOG_SHA256, ExecutionDescriptorV1, ProtocolError,
    TypedBrokerOperationV1, TypedBrokerOutcomeV1, TypedBrokerRequestV1, TypedBrokerResponseV1,
    principal, sha256_bytes, sha256_json, valid_nonzero_sha256,
};

const LISTENER_ADDRESS: &str = "@trillionnium_typed_broker_userdebug_v1";
const CATALOG_ARTIFACT_PATH: &str = "/system_ext/etc/trillionnium/typed-broker/catalog.v1.json";
const BROKER_ARTIFACT_PATH: &str = "/system_ext/bin/trillionnium-typed-broker-userdebug";
const REPLAY_SNAPSHOT_SCHEMA: &str = "trillionnium.typed-broker-replay-snapshot.v1";
const SYSTEM_API_GAP_PROOF_SCHEMA: &str = "trillionnium.typed-broker-system-api-gap-proof.v1";
const SYSTEM_API_GAP_PROOF_DOMAIN: &str =
    "trillionnium.typed-broker-system-api-gap-proof-digest.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuildVariantV1 {
    User,
    Userdebug,
    Eng,
    Recovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerObservationSourceV1 {
    SoPeercredSoPeersecPidfd,
    CallerClaim,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CgroupObservationSourceV1 {
    PidfdBoundProcCgroup,
    CallerClaim,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SocketTypeV1 {
    UnixSeqpacket,
    UnixStream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArtifactObservationSourceV1 {
    Openat2NoSymlinkFstatSha256,
    PathStringOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KernelPeerEvidenceV1 {
    source: PeerObservationSourceV1,
    pid: u32,
    start_time_ticks: u64,
    uid: u32,
    gid: u32,
    selinux_domain: String,
    cgroup_source: CgroupObservationSourceV1,
    cgroup_leaf: String,
    executable_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ListenerFdEvidenceV1 {
    address: String,
    fd: i32,
    socket_type: SocketTypeV1,
    cloexec: bool,
    passcred: bool,
    peercred_observed: bool,
    peersec_observed: bool,
    scm_rights_accepted: bool,
    unexpected_inherited_fd_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactFdEvidenceV1 {
    source: ArtifactObservationSourceV1,
    path: String,
    fd: i32,
    cloexec: bool,
    read_only: bool,
    nofollow: bool,
    regular_file: bool,
    device: u64,
    inode: u64,
    link_count: u64,
    mode: u32,
    sha256: String,
}

impl ArtifactFdEvidenceV1 {
    fn validates_for(&self, expected_path: &str, expected_sha256: &str) -> bool {
        self.source == ArtifactObservationSourceV1::Openat2NoSymlinkFstatSha256
            && self.path == expected_path
            && self.fd >= 3
            && self.cloexec
            && self.read_only
            && self.nofollow
            && self.regular_file
            && self.device != 0
            && self.inode != 0
            && self.link_count == 1
            && self.mode & 0o022 == 0
            && valid_nonzero_sha256(&self.sha256)
            && self.sha256 == expected_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutionProfileEvidenceV1 {
    cgroup_profile: String,
    cgroup_attached_before_exec: bool,
    seccomp_profile: String,
    seccomp_loaded_before_exec: bool,
    no_new_privs: bool,
    ambient_capabilities_empty: bool,
    stdin_closed: bool,
    stdout_pipe_cloexec: bool,
    stderr_pipe_cloexec: bool,
    descendant_policy_enforced: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SystemApiGapProofV1 {
    schema: String,
    proof_scope: String,
    request_sha256: String,
    direct_binding_sha256: String,
    operation_id: TypedBrokerOperationV1,
    proof_sha256: String,
}

impl SystemApiGapProofV1 {
    fn derive(request: &TypedBrokerRequestV1) -> Self {
        let mut proof = Self {
            schema: SYSTEM_API_GAP_PROOF_SCHEMA.to_string(),
            proof_scope: "userdebug_transport_conformance_fixture_not_product_fallback".to_string(),
            request_sha256: request.request_sha256.clone(),
            direct_binding_sha256: request.direct_binding_sha256.clone(),
            operation_id: request.operation_id,
            proof_sha256: String::new(),
        };
        proof.proof_sha256 = proof.expected_sha256();
        proof
    }

    fn expected_sha256(&self) -> String {
        sha256_json(&json!({
            "domain": SYSTEM_API_GAP_PROOF_DOMAIN,
            "schema": self.schema,
            "proof_scope": self.proof_scope,
            "request_sha256": self.request_sha256,
            "direct_binding_sha256": self.direct_binding_sha256,
            "operation_id": self.operation_id,
        }))
    }

    fn validates_for(&self, request: &TypedBrokerRequestV1) -> bool {
        self.schema == SYSTEM_API_GAP_PROOF_SCHEMA
            && self.proof_scope == "userdebug_transport_conformance_fixture_not_product_fallback"
            && self.request_sha256 == request.request_sha256
            && self.direct_binding_sha256 == request.direct_binding_sha256
            && self.operation_id == request.operation_id
            && valid_nonzero_sha256(&self.proof_sha256)
            && self.proof_sha256 == self.expected_sha256()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UserdebugAdmissionEvidenceV1 {
    build_variant: BuildVariantV1,
    peer: KernelPeerEvidenceV1,
    listener: ListenerFdEvidenceV1,
    catalog_artifact: ArtifactFdEvidenceV1,
    broker_artifact: ArtifactFdEvidenceV1,
    executor_artifact: ArtifactFdEvidenceV1,
    profile: ExecutionProfileEvidenceV1,
    system_api_gap_proof: SystemApiGapProofV1,
}

/// Provisioned values are intentionally private and have no non-test
/// constructor. A future product implementation must acquire them from signed,
/// AVB-bound state rather than accepting caller JSON.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProvisionedUserdebugPolicyV1 {
    broker_artifact_sha256: String,
    exec_fingerprint_artifact_sha256: String,
}

#[derive(Clone, Copy, Debug)]
struct VerifiedUserdebugAdmissionV1<'a> {
    request: &'a TypedBrokerRequestV1,
}

fn admit_userdebug<'a>(
    binding: &BrokerBindingIdentityV1,
    request: &'a TypedBrokerRequestV1,
    evidence: &UserdebugAdmissionEvidenceV1,
    policy: &ProvisionedUserdebugPolicyV1,
) -> Result<VerifiedUserdebugAdmissionV1<'a>, AdmissionError> {
    request.validate_identity_for(binding)?;
    if evidence.build_variant != BuildVariantV1::Userdebug {
        return Err(AdmissionError::ProductVariantDenied);
    }
    if request.operation_id != TypedBrokerOperationV1::ExecInspectBuildFingerprintUserdebugV1 {
        return Err(AdmissionError::TypedAdbBackendUnavailableHold);
    }
    let descriptor = principal(&binding.provider_id, &binding.agent_id)
        .ok_or(AdmissionError::PeerIdentityDenied)?;
    if evidence.peer.source != PeerObservationSourceV1::SoPeercredSoPeersecPidfd
        || evidence.peer.cgroup_source != CgroupObservationSourceV1::PidfdBoundProcCgroup
        || evidence.peer.pid == 0
        || evidence.peer.start_time_ticks == 0
        || evidence.peer.uid != descriptor.uid
        || evidence.peer.gid != descriptor.gid
        || evidence.peer.selinux_domain != descriptor.selinux_domain
        || evidence.peer.cgroup_leaf != descriptor.cgroup_leaf
        || evidence.peer.executable_sha256 != binding.agent_executable_sha256
    {
        return Err(AdmissionError::PeerIdentityDenied);
    }
    if evidence.listener.address != LISTENER_ADDRESS
        || evidence.listener.fd < 3
        || evidence.listener.socket_type != SocketTypeV1::UnixSeqpacket
        || !evidence.listener.cloexec
        || !evidence.listener.passcred
        || !evidence.listener.peercred_observed
        || !evidence.listener.peersec_observed
        || evidence.listener.scm_rights_accepted
        || evidence.listener.unexpected_inherited_fd_count != 0
    {
        return Err(AdmissionError::ListenerFdBoundaryDenied);
    }
    let executor_path = match request.operation_id.definition().descriptor {
        ExecutionDescriptorV1::Exec { executable, .. } => executable,
        ExecutionDescriptorV1::Adb { .. } => {
            return Err(AdmissionError::TypedAdbBackendUnavailableHold);
        }
    };
    if !evidence
        .catalog_artifact
        .validates_for(CATALOG_ARTIFACT_PATH, CATALOG_SHA256)
        || !evidence
            .broker_artifact
            .validates_for(BROKER_ARTIFACT_PATH, &policy.broker_artifact_sha256)
        || !evidence
            .executor_artifact
            .validates_for(executor_path, &policy.exec_fingerprint_artifact_sha256)
        || evidence.catalog_artifact.fd == evidence.listener.fd
        || evidence.broker_artifact.fd == evidence.listener.fd
        || evidence.executor_artifact.fd == evidence.listener.fd
        || evidence.catalog_artifact.fd == evidence.broker_artifact.fd
        || evidence.catalog_artifact.fd == evidence.executor_artifact.fd
        || evidence.broker_artifact.fd == evidence.executor_artifact.fd
    {
        return Err(AdmissionError::ArtifactFdBoundaryDenied);
    }
    let execution = request.operation_id.definition().descriptor;
    if evidence.profile.cgroup_profile != execution.cgroup_profile()
        || !evidence.profile.cgroup_attached_before_exec
        || evidence.profile.seccomp_profile != execution.seccomp_profile()
        || !evidence.profile.seccomp_loaded_before_exec
        || !evidence.profile.no_new_privs
        || !evidence.profile.ambient_capabilities_empty
        || !evidence.profile.stdin_closed
        || !evidence.profile.stdout_pipe_cloexec
        || !evidence.profile.stderr_pipe_cloexec
        || !evidence.profile.descendant_policy_enforced
    {
        return Err(AdmissionError::ExecutionProfileDenied);
    }
    if !evidence.system_api_gap_proof.validates_for(request) {
        return Err(AdmissionError::SystemApiPreferenceProofDenied);
    }
    Ok(VerifiedUserdebugAdmissionV1 { request })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub(super) enum AdmissionError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("only the explicit userdebug conformance variant is admissible")]
    ProductVariantDenied,
    #[error("kernel peer identity, SELinux, or cgroup evidence is denied")]
    PeerIdentityDenied,
    #[error("listener file-descriptor boundary is denied")]
    ListenerFdBoundaryDenied,
    #[error("catalog, broker, or executor artifact boundary is denied")]
    ArtifactFdBoundaryDenied,
    #[error("cgroup, seccomp, capabilities, or stdio profile is denied")]
    ExecutionProfileDenied,
    #[error("System API preference/gap proof is denied")]
    SystemApiPreferenceProofDenied,
    #[error("typed ADB live backend and key custody are unavailable")]
    TypedAdbBackendUnavailableHold,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SealedReadOnlyActionV1 {
    InspectBuildFingerprint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BackendLimitsV1 {
    deadline_ms: u64,
    stdout_limit_bytes: usize,
    stderr_limit_bytes: usize,
    total_output_limit_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendObservationKindV1 {
    Exited,
    TimedOut,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BackendObservationV1 {
    kind: BackendObservationKindV1,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    elapsed_ms: u64,
}

/// Private and sealed inside this standalone crate. A model/plugin cannot
/// implement it and cannot supply an executable or argument vector.
trait ReadOnlyUserdebugBackendV1 {
    fn execute(
        &mut self,
        action: SealedReadOnlyActionV1,
        limits: BackendLimitsV1,
    ) -> BackendObservationV1;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedReplayRecordV1 {
    pub(super) request: TypedBrokerRequestV1,
    pub(super) request_wire_sha256: String,
}

impl PreparedReplayRecordV1 {
    pub(super) fn derive(request: &TypedBrokerRequestV1) -> Result<Self, BrokerError> {
        let request_wire_sha256 = sha256_bytes(&request.canonical_wire_bytes()?);
        let value = Self {
            request: request.clone(),
            request_wire_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    pub(super) fn validate(&self) -> Result<(), BrokerError> {
        if self.request.expected_request_sha256()? != self.request.request_sha256
            || self.request_wire_sha256 != sha256_bytes(&self.request.canonical_wire_bytes()?)
        {
            return Err(BrokerError::ReplaySnapshotInvalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TerminalReplayRecordV1 {
    pub(super) prepared: PreparedReplayRecordV1,
    pub(super) response: TypedBrokerResponseV1,
    pub(super) response_wire: Vec<u8>,
    pub(super) response_wire_sha256: String,
}

impl TerminalReplayRecordV1 {
    pub(super) fn derive(
        prepared: PreparedReplayRecordV1,
        response: TypedBrokerResponseV1,
    ) -> Result<Self, BrokerError> {
        let response_wire = response.canonical_wire_bytes(&prepared.request)?;
        let response_wire_sha256 = sha256_bytes(&response_wire);
        let value = Self {
            prepared,
            response,
            response_wire,
            response_wire_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    pub(super) fn validate(&self) -> Result<(), BrokerError> {
        self.prepared.validate()?;
        self.response.validate_for(&self.prepared.request)?;
        if self.response_wire != self.response.canonical_wire_bytes(&self.prepared.request)?
            || self.response_wire_sha256 != sha256_bytes(&self.response_wire)
        {
            return Err(BrokerError::ReplaySnapshotInvalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ReplayRecordV1 {
    Prepared { record: Box<PreparedReplayRecordV1> },
    Terminal { record: Box<TerminalReplayRecordV1> },
}

impl ReplayRecordV1 {
    pub(super) fn prepared(&self) -> &PreparedReplayRecordV1 {
        match self {
            Self::Prepared { record } => record,
            Self::Terminal { record } => &record.prepared,
        }
    }

    pub(super) fn validate(&self) -> Result<(), BrokerError> {
        match self {
            Self::Prepared { record } => record.validate(),
            Self::Terminal { record } => record.validate(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaySnapshotV1 {
    schema: String,
    records: BTreeMap<String, ReplayRecordV1>,
}

pub(super) trait ReplayLedgerV1 {
    fn lookup(&self, operation_identity_sha256: &str) -> Option<ReplayRecordV1>;
    fn prepare(&mut self, prepared: PreparedReplayRecordV1) -> Result<(), BrokerError>;
    fn commit(&mut self, terminal: TerminalReplayRecordV1) -> Result<(), BrokerError>;
}

#[derive(Clone, Debug, Default)]
struct MemoryReplayLedgerV1 {
    records: BTreeMap<String, ReplayRecordV1>,
    fail_next_prepare: bool,
    fail_next_commit: bool,
}

impl MemoryReplayLedgerV1 {
    fn snapshot_bytes(&self) -> Result<Vec<u8>, BrokerError> {
        for (identity, record) in &self.records {
            record.validate()?;
            if identity != &record.prepared().request.operation_identity_sha256 {
                return Err(BrokerError::ReplaySnapshotInvalid);
            }
        }
        serde_json::to_vec(&ReplaySnapshotV1 {
            schema: REPLAY_SNAPSHOT_SCHEMA.to_string(),
            records: self.records.clone(),
        })
        .map_err(|_| BrokerError::ReplaySnapshotInvalid)
    }

    fn restore(bytes: &[u8]) -> Result<Self, BrokerError> {
        let snapshot: ReplaySnapshotV1 =
            serde_json::from_slice(bytes).map_err(|_| BrokerError::ReplaySnapshotInvalid)?;
        if snapshot.schema != REPLAY_SNAPSHOT_SCHEMA {
            return Err(BrokerError::ReplaySnapshotInvalid);
        }
        let value = Self {
            records: snapshot.records,
            fail_next_prepare: false,
            fail_next_commit: false,
        };
        value.snapshot_bytes()?;
        Ok(value)
    }
}

impl ReplayLedgerV1 for MemoryReplayLedgerV1 {
    fn lookup(&self, operation_identity_sha256: &str) -> Option<ReplayRecordV1> {
        self.records.get(operation_identity_sha256).cloned()
    }

    fn prepare(&mut self, prepared: PreparedReplayRecordV1) -> Result<(), BrokerError> {
        if self.fail_next_prepare {
            self.fail_next_prepare = false;
            return Err(BrokerError::PreparePersistenceFailedHold);
        }
        let key = prepared.request.operation_identity_sha256.clone();
        if self.records.contains_key(&key) {
            return Err(BrokerError::OperationIdentityConflict);
        }
        self.records.insert(
            key,
            ReplayRecordV1::Prepared {
                record: Box::new(prepared),
            },
        );
        Ok(())
    }

    fn commit(&mut self, terminal: TerminalReplayRecordV1) -> Result<(), BrokerError> {
        if self.fail_next_commit {
            self.fail_next_commit = false;
            return Err(BrokerError::TerminalPersistenceFailedHold);
        }
        let key = terminal.prepared.request.operation_identity_sha256.clone();
        match self.records.get(&key) {
            Some(ReplayRecordV1::Prepared { record }) if record.as_ref() == &terminal.prepared => {}
            _ => return Err(BrokerError::OperationIdentityConflict),
        }
        self.records.insert(
            key,
            ReplayRecordV1::Terminal {
                record: Box::new(terminal),
            },
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BrokerDispatchV1 {
    response: TypedBrokerResponseV1,
    exact_wire_response: Vec<u8>,
    replayed: bool,
}

struct BrokerCoreV1<L, B> {
    ledger: L,
    backend: B,
}

impl<L, B> BrokerCoreV1<L, B>
where
    L: ReplayLedgerV1,
    B: ReadOnlyUserdebugBackendV1,
{
    fn dispatch_userdebug(
        &mut self,
        binding: &BrokerBindingIdentityV1,
        request: &TypedBrokerRequestV1,
        evidence: &UserdebugAdmissionEvidenceV1,
        policy: &ProvisionedUserdebugPolicyV1,
        now_boot_ms: u64,
    ) -> Result<BrokerDispatchV1, BrokerError> {
        let admission = admit_userdebug(binding, request, evidence, policy)?;
        debug_assert_eq!(admission.request.request_sha256, request.request_sha256);
        if let Some(existing) = self.ledger.lookup(&request.operation_identity_sha256) {
            if existing.prepared().request.request_sha256 != request.request_sha256 {
                return Err(BrokerError::OperationIdentityConflict);
            }
            return match existing {
                ReplayRecordV1::Prepared { .. } => Err(BrokerError::PreparedIndeterminateHold),
                ReplayRecordV1::Terminal { record } => {
                    record.validate()?;
                    let record = *record;
                    Ok(BrokerDispatchV1 {
                        response: record.response,
                        exact_wire_response: record.response_wire,
                        replayed: true,
                    })
                }
            };
        }

        request.validate_first_delivery_for(binding, now_boot_ms)?;
        let prepared = PreparedReplayRecordV1::derive(request)?;
        self.ledger.prepare(prepared.clone())?;

        let controls = request.operation_id.definition().descriptor.controls();
        let limits = BackendLimitsV1 {
            deadline_ms: request.absolute_deadline_boot_ms - now_boot_ms,
            stdout_limit_bytes: controls.stdout_limit_bytes,
            stderr_limit_bytes: controls.stderr_limit_bytes,
            total_output_limit_bytes: controls.total_output_limit_bytes,
        };
        let observation = self
            .backend
            .execute(SealedReadOnlyActionV1::InspectBuildFingerprint, limits);
        let response = response_from_observation(request, limits, observation)?;
        let terminal = TerminalReplayRecordV1::derive(prepared, response.clone())?;
        let exact_wire_response = terminal.response_wire.clone();
        self.ledger.commit(terminal)?;
        Ok(BrokerDispatchV1 {
            response,
            exact_wire_response,
            replayed: false,
        })
    }
}

fn response_from_observation(
    request: &TypedBrokerRequestV1,
    limits: BackendLimitsV1,
    observation: BackendObservationV1,
) -> Result<TypedBrokerResponseV1, BrokerError> {
    let stdout_bytes = observation.stdout.len();
    let stderr_bytes = observation.stderr.len();
    let output_exceeded = stdout_bytes > limits.stdout_limit_bytes
        || stderr_bytes > limits.stderr_limit_bytes
        || stdout_bytes.saturating_add(stderr_bytes) > limits.total_output_limit_bytes;
    let deadline_exceeded = observation.elapsed_ms >= limits.deadline_ms;
    let (outcome, exit_code, stdout, stderr) = if output_exceeded {
        (
            TypedBrokerOutcomeV1::OutputLimitIndeterminate,
            None,
            String::new(),
            String::new(),
        )
    } else if deadline_exceeded || observation.kind == BackendObservationKindV1::TimedOut {
        (
            TypedBrokerOutcomeV1::TimedOutIndeterminate,
            None,
            observation.stdout,
            observation.stderr,
        )
    } else {
        match observation.kind {
            BackendObservationKindV1::Exited => match observation.exit_code {
                Some(0) => (
                    TypedBrokerOutcomeV1::Completed,
                    Some(0),
                    observation.stdout,
                    observation.stderr,
                ),
                Some(code) => (
                    TypedBrokerOutcomeV1::CommandFailed,
                    Some(code),
                    observation.stdout,
                    observation.stderr,
                ),
                None => (
                    TypedBrokerOutcomeV1::BackendIndeterminate,
                    None,
                    observation.stdout,
                    observation.stderr,
                ),
            },
            BackendObservationKindV1::TimedOut => unreachable!("handled above"),
            BackendObservationKindV1::Indeterminate => (
                TypedBrokerOutcomeV1::BackendIndeterminate,
                None,
                observation.stdout,
                observation.stderr,
            ),
        }
    };
    Ok(TypedBrokerResponseV1::terminal(
        request,
        outcome,
        exit_code,
        stdout,
        stderr,
        observation.elapsed_ms,
    )?)
}

#[derive(Debug, Error)]
pub(super) enum BrokerError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Admission(#[from] AdmissionError),
    #[error("operation identity was reused with different request bytes")]
    OperationIdentityConflict,
    #[error("a PREPARED operation has no terminal record; blind retry is forbidden")]
    PreparedIndeterminateHold,
    #[error("PREPARED could not be persisted; backend was not called")]
    PreparePersistenceFailedHold,
    #[error("terminal result could not be persisted; return is held and retry is forbidden")]
    TerminalPersistenceFailedHold,
    #[error("standalone replay snapshot is invalid")]
    ReplaySnapshotInvalid,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::durable::DurableReplayLedgerV1;
    use crate::protocol::{BINDING_IDENTITY_SCHEMA, CODEX, TypedBrokerOperationV1, sha256_bytes};

    static NEXT_DURABLE_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct DurableTestDirectory {
        path: std::path::PathBuf,
    }

    impl DurableTestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DURABLE_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "trillionnium-typed-broker-integration-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create durable integration directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("set durable integration directory mode");
            Self { path }
        }
    }

    impl Drop for DurableTestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[derive(Clone, Debug)]
    struct FakeBackend {
        calls: usize,
        observation: BackendObservationV1,
        last_action: Option<SealedReadOnlyActionV1>,
        last_limits: Option<BackendLimitsV1>,
    }

    impl ReadOnlyUserdebugBackendV1 for FakeBackend {
        fn execute(
            &mut self,
            action: SealedReadOnlyActionV1,
            limits: BackendLimitsV1,
        ) -> BackendObservationV1 {
            self.calls += 1;
            self.last_action = Some(action);
            self.last_limits = Some(limits);
            self.observation.clone()
        }
    }

    fn digest(seed: &str) -> String {
        sha256_bytes(seed.as_bytes())
    }

    fn binding() -> BrokerBindingIdentityV1 {
        BrokerBindingIdentityV1 {
            schema: BINDING_IDENTITY_SCHEMA.to_string(),
            provider_id: CODEX.provider_id.to_string(),
            agent_id: CODEX.agent_id.to_string(),
            direct_binding_sha256: digest("binding"),
            invocation_id: format!("inv:{}", digest("invocation")),
            delivery_provider_attempt_id: format!("attempt:{}", digest("attempt")),
            agent_executable_sha256: digest("agent-executable"),
        }
    }

    fn request(binding: &BrokerBindingIdentityV1) -> TypedBrokerRequestV1 {
        TypedBrokerRequestV1::derive(
            binding,
            7,
            TypedBrokerOperationV1::ExecInspectBuildFingerprintUserdebugV1,
            15_000,
        )
        .expect("request")
    }

    fn artifact(path: &str, fd: i32, sha256: String) -> ArtifactFdEvidenceV1 {
        ArtifactFdEvidenceV1 {
            source: ArtifactObservationSourceV1::Openat2NoSymlinkFstatSha256,
            path: path.to_string(),
            fd,
            cloexec: true,
            read_only: true,
            nofollow: true,
            regular_file: true,
            device: 1,
            inode: fd as u64 + 100,
            link_count: 1,
            mode: 0o555,
            sha256,
        }
    }

    fn policy() -> ProvisionedUserdebugPolicyV1 {
        ProvisionedUserdebugPolicyV1 {
            broker_artifact_sha256: digest("broker-artifact"),
            exec_fingerprint_artifact_sha256: digest("getprop-artifact"),
        }
    }

    fn evidence(
        binding: &BrokerBindingIdentityV1,
        request: &TypedBrokerRequestV1,
    ) -> UserdebugAdmissionEvidenceV1 {
        let policy = policy();
        UserdebugAdmissionEvidenceV1 {
            build_variant: BuildVariantV1::Userdebug,
            peer: KernelPeerEvidenceV1 {
                source: PeerObservationSourceV1::SoPeercredSoPeersecPidfd,
                pid: 41,
                start_time_ticks: 90,
                uid: CODEX.uid,
                gid: CODEX.gid,
                selinux_domain: CODEX.selinux_domain.to_string(),
                cgroup_source: CgroupObservationSourceV1::PidfdBoundProcCgroup,
                cgroup_leaf: CODEX.cgroup_leaf.to_string(),
                executable_sha256: binding.agent_executable_sha256.clone(),
            },
            listener: ListenerFdEvidenceV1 {
                address: LISTENER_ADDRESS.to_string(),
                fd: 7,
                socket_type: SocketTypeV1::UnixSeqpacket,
                cloexec: true,
                passcred: true,
                peercred_observed: true,
                peersec_observed: true,
                scm_rights_accepted: false,
                unexpected_inherited_fd_count: 0,
            },
            catalog_artifact: artifact(CATALOG_ARTIFACT_PATH, 8, CATALOG_SHA256.to_string()),
            broker_artifact: artifact(BROKER_ARTIFACT_PATH, 9, policy.broker_artifact_sha256),
            executor_artifact: artifact(
                "/system/bin/getprop",
                10,
                policy.exec_fingerprint_artifact_sha256,
            ),
            profile: ExecutionProfileEvidenceV1 {
                cgroup_profile: request
                    .operation_id
                    .definition()
                    .descriptor
                    .cgroup_profile()
                    .to_string(),
                cgroup_attached_before_exec: true,
                seccomp_profile: request
                    .operation_id
                    .definition()
                    .descriptor
                    .seccomp_profile()
                    .to_string(),
                seccomp_loaded_before_exec: true,
                no_new_privs: true,
                ambient_capabilities_empty: true,
                stdin_closed: true,
                stdout_pipe_cloexec: true,
                stderr_pipe_cloexec: true,
                descendant_policy_enforced: true,
            },
            system_api_gap_proof: SystemApiGapProofV1::derive(request),
        }
    }

    fn completed_backend() -> FakeBackend {
        FakeBackend {
            calls: 0,
            observation: BackendObservationV1 {
                kind: BackendObservationKindV1::Exited,
                exit_code: Some(0),
                stdout: "trillionnium/fogos/userdebug\n".to_string(),
                stderr: String::new(),
                elapsed_ms: 4,
            },
            last_action: None,
            last_limits: None,
        }
    }

    #[test]
    fn complete_read_only_fixture_prepares_commits_and_returns_bounded_response() {
        let binding = binding();
        let request = request(&binding);
        let base_evidence = evidence(&binding, &request);
        let mut broker = BrokerCoreV1 {
            ledger: MemoryReplayLedgerV1::default(),
            backend: completed_backend(),
        };
        let dispatch = broker
            .dispatch_userdebug(&binding, &request, &base_evidence, &policy(), 10_001)
            .expect("dispatch");
        assert!(!dispatch.replayed);
        assert_eq!(dispatch.response.outcome, TypedBrokerOutcomeV1::Completed);
        assert_eq!(broker.backend.calls, 1);
        assert_eq!(
            broker.backend.last_action,
            Some(SealedReadOnlyActionV1::InspectBuildFingerprint)
        );
        assert_eq!(broker.backend.last_limits.unwrap().deadline_ms, 4_999);
        assert_eq!(
            dispatch.exact_wire_response,
            dispatch.response.canonical_wire_bytes(&request).unwrap()
        );
        assert!(matches!(
            broker.ledger.lookup(&request.operation_identity_sha256),
            Some(ReplayRecordV1::Terminal { .. })
        ));
    }

    #[test]
    fn terminal_snapshot_restarts_and_replays_exact_bytes_after_deadline() {
        let binding = binding();
        let request = request(&binding);
        let evidence = evidence(&binding, &request);
        let mut first = BrokerCoreV1 {
            ledger: MemoryReplayLedgerV1::default(),
            backend: completed_backend(),
        };
        let original = first
            .dispatch_userdebug(&binding, &request, &evidence, &policy(), 10_001)
            .expect("first dispatch");
        let snapshot = first.ledger.snapshot_bytes().expect("snapshot");
        let mut restarted = BrokerCoreV1 {
            ledger: MemoryReplayLedgerV1::restore(&snapshot).expect("restore"),
            backend: completed_backend(),
        };
        let replay = restarted
            .dispatch_userdebug(&binding, &request, &evidence, &policy(), 99_000)
            .expect("replay after deadline");
        assert!(replay.replayed);
        assert_eq!(replay.response, original.response);
        assert_eq!(replay.exact_wire_response, original.exact_wire_response);
        assert_eq!(restarted.backend.calls, 0);
    }

    #[test]
    fn durable_broker_response_loss_restarts_and_replays_without_backend() {
        let directory = DurableTestDirectory::new();
        let binding = binding();
        let request = request(&binding);
        let evidence = evidence(&binding, &request);
        let original = {
            let mut first = BrokerCoreV1 {
                ledger: DurableReplayLedgerV1::open(&directory.path).expect("open durable ledger"),
                backend: completed_backend(),
            };
            let dispatch = first
                .dispatch_userdebug(&binding, &request, &evidence, &policy(), 10_001)
                .expect("durable first dispatch");
            assert_eq!(first.backend.calls, 1);
            dispatch
        };

        let mut restarted = BrokerCoreV1 {
            ledger: DurableReplayLedgerV1::open(&directory.path).expect("reopen durable ledger"),
            backend: completed_backend(),
        };
        let replay = restarted
            .dispatch_userdebug(&binding, &request, &evidence, &policy(), 99_000)
            .expect("replay response after delivery loss");
        assert!(replay.replayed);
        assert_eq!(replay.response, original.response);
        assert_eq!(replay.exact_wire_response, original.exact_wire_response);
        assert_eq!(restarted.backend.calls, 0);
    }

    #[test]
    fn prepared_restart_is_indeterminate_and_never_blindly_retries() {
        let binding = binding();
        let request = request(&binding);
        let evidence = evidence(&binding, &request);
        let mut ledger = MemoryReplayLedgerV1::default();
        ledger
            .prepare(PreparedReplayRecordV1::derive(&request).unwrap())
            .unwrap();
        let snapshot = ledger.snapshot_bytes().unwrap();
        let mut broker = BrokerCoreV1 {
            ledger: MemoryReplayLedgerV1::restore(&snapshot).unwrap(),
            backend: completed_backend(),
        };
        assert!(matches!(
            broker.dispatch_userdebug(&binding, &request, &evidence, &policy(), 10_001),
            Err(BrokerError::PreparedIndeterminateHold)
        ));
        assert_eq!(broker.backend.calls, 0);
    }

    #[test]
    fn reused_operation_identity_with_different_request_is_denied() {
        let binding = binding();
        let request = request(&binding);
        let original_evidence = evidence(&binding, &request);
        let mut broker = BrokerCoreV1 {
            ledger: MemoryReplayLedgerV1::default(),
            backend: completed_backend(),
        };
        broker
            .dispatch_userdebug(&binding, &request, &original_evidence, &policy(), 10_001)
            .unwrap();
        let mut conflict = request.clone();
        conflict.absolute_deadline_boot_ms += 1;
        conflict.request_sha256 = conflict.expected_request_sha256().unwrap();
        let conflict_evidence = evidence(&binding, &conflict);
        assert!(matches!(
            broker.dispatch_userdebug(&binding, &conflict, &conflict_evidence, &policy(), 10_002),
            Err(BrokerError::OperationIdentityConflict)
        ));
        assert_eq!(broker.backend.calls, 1);
    }

    #[test]
    fn prepare_failure_prevents_backend_and_commit_failure_leaves_hold() {
        let binding = binding();
        let request = request(&binding);
        let evidence = evidence(&binding, &request);
        let mut prepare_failure = BrokerCoreV1 {
            ledger: MemoryReplayLedgerV1 {
                fail_next_prepare: true,
                ..MemoryReplayLedgerV1::default()
            },
            backend: completed_backend(),
        };
        assert!(matches!(
            prepare_failure.dispatch_userdebug(&binding, &request, &evidence, &policy(), 10_001),
            Err(BrokerError::PreparePersistenceFailedHold)
        ));
        assert_eq!(prepare_failure.backend.calls, 0);

        let mut commit_failure = BrokerCoreV1 {
            ledger: MemoryReplayLedgerV1 {
                fail_next_commit: true,
                ..MemoryReplayLedgerV1::default()
            },
            backend: completed_backend(),
        };
        assert!(matches!(
            commit_failure.dispatch_userdebug(&binding, &request, &evidence, &policy(), 10_001),
            Err(BrokerError::TerminalPersistenceFailedHold)
        ));
        assert_eq!(commit_failure.backend.calls, 1);
        assert!(matches!(
            commit_failure.dispatch_userdebug(&binding, &request, &evidence, &policy(), 10_001),
            Err(BrokerError::PreparedIndeterminateHold)
        ));
        assert_eq!(commit_failure.backend.calls, 1);
    }

    #[test]
    fn timeout_and_output_overflow_are_terminal_indeterminate_without_retry() {
        let binding = binding();
        for observation in [
            BackendObservationV1 {
                kind: BackendObservationKindV1::TimedOut,
                exit_code: None,
                stdout: String::new(),
                stderr: "deadline".to_string(),
                elapsed_ms: 4_999,
            },
            BackendObservationV1 {
                kind: BackendObservationKindV1::Exited,
                exit_code: Some(0),
                stdout: "x".repeat(8_193),
                stderr: String::new(),
                elapsed_ms: 2,
            },
        ] {
            let mut request = request(&binding);
            request.operation_ordinal += observation.elapsed_ms + 1;
            request.operation_identity_sha256 =
                crate::protocol::operation_identity_sha256(&binding, request.operation_ordinal);
            request.request_sha256 = request.expected_request_sha256().unwrap();
            let evidence = evidence(&binding, &request);
            let mut broker = BrokerCoreV1 {
                ledger: MemoryReplayLedgerV1::default(),
                backend: FakeBackend {
                    calls: 0,
                    observation,
                    last_action: None,
                    last_limits: None,
                },
            };
            let first = broker
                .dispatch_userdebug(&binding, &request, &evidence, &policy(), 10_001)
                .unwrap();
            assert!(matches!(
                first.response.outcome,
                TypedBrokerOutcomeV1::TimedOutIndeterminate
                    | TypedBrokerOutcomeV1::OutputLimitIndeterminate
            ));
            let replay = broker
                .dispatch_userdebug(&binding, &request, &evidence, &policy(), 99_000)
                .unwrap();
            assert!(replay.replayed);
            assert_eq!(replay.exact_wire_response, first.exact_wire_response);
            assert_eq!(broker.backend.calls, 1);
        }
    }

    #[test]
    fn every_kernel_selinux_cgroup_fd_artifact_and_profile_boundary_is_checked() {
        let binding = binding();
        let request = request(&binding);
        let base = evidence(&binding, &request);
        admit_userdebug(&binding, &request, &base, &policy()).expect("base admission");

        let mut value = base.clone();
        value.peer.uid += 1;
        assert!(matches!(
            admit_userdebug(&binding, &request, &value, &policy()),
            Err(AdmissionError::PeerIdentityDenied)
        ));
        let mut value = base.clone();
        value.peer.selinux_domain = "u:r:untrusted_app:s0".to_string();
        assert!(matches!(
            admit_userdebug(&binding, &request, &value, &policy()),
            Err(AdmissionError::PeerIdentityDenied)
        ));
        let mut value = base.clone();
        value.peer.cgroup_source = CgroupObservationSourceV1::CallerClaim;
        assert!(matches!(
            admit_userdebug(&binding, &request, &value, &policy()),
            Err(AdmissionError::PeerIdentityDenied)
        ));
        let mut value = base.clone();
        value.listener.cloexec = false;
        assert!(matches!(
            admit_userdebug(&binding, &request, &value, &policy()),
            Err(AdmissionError::ListenerFdBoundaryDenied)
        ));
        let mut value = base.clone();
        value.listener.scm_rights_accepted = true;
        assert!(matches!(
            admit_userdebug(&binding, &request, &value, &policy()),
            Err(AdmissionError::ListenerFdBoundaryDenied)
        ));
        let mut value = base.clone();
        value.executor_artifact.sha256 = digest("wrong-executor");
        assert!(matches!(
            admit_userdebug(&binding, &request, &value, &policy()),
            Err(AdmissionError::ArtifactFdBoundaryDenied)
        ));
        let mut value = base.clone();
        value.catalog_artifact.source = ArtifactObservationSourceV1::PathStringOnly;
        assert!(matches!(
            admit_userdebug(&binding, &request, &value, &policy()),
            Err(AdmissionError::ArtifactFdBoundaryDenied)
        ));
        let mut value = base.clone();
        value.profile.seccomp_loaded_before_exec = false;
        assert!(matches!(
            admit_userdebug(&binding, &request, &value, &policy()),
            Err(AdmissionError::ExecutionProfileDenied)
        ));
        let mut value = base;
        value.system_api_gap_proof.proof_sha256 = digest("forged-gap-proof");
        assert!(matches!(
            admit_userdebug(&binding, &request, &value, &policy()),
            Err(AdmissionError::SystemApiPreferenceProofDenied)
        ));
    }

    #[test]
    fn non_userdebug_and_typed_adb_have_no_authority_or_backend() {
        let binding = binding();
        let request = request(&binding);
        for variant in [
            BuildVariantV1::User,
            BuildVariantV1::Eng,
            BuildVariantV1::Recovery,
        ] {
            let mut evidence = evidence(&binding, &request);
            evidence.build_variant = variant;
            assert!(matches!(
                admit_userdebug(&binding, &request, &evidence, &policy()),
                Err(AdmissionError::ProductVariantDenied)
            ));
        }

        let adb = TypedBrokerRequestV1::derive(
            &binding,
            8,
            TypedBrokerOperationV1::AdbInspectPackageSettingsUserdebugV1,
            15_000,
        )
        .unwrap();
        let evidence = evidence(&binding, &adb);
        assert!(matches!(
            admit_userdebug(&binding, &adb, &evidence, &policy()),
            Err(AdmissionError::TypedAdbBackendUnavailableHold)
        ));
        assert!(crate::require_product_authority().is_err());
        assert!(crate::require_userdebug_typed_adb_backend().is_err());
    }

    #[test]
    fn caller_claim_and_stream_socket_variants_are_never_admitted() {
        let binding = binding();
        let request = request(&binding);
        let mut caller_claim_evidence = evidence(&binding, &request);
        caller_claim_evidence.peer.source = PeerObservationSourceV1::CallerClaim;
        assert!(matches!(
            admit_userdebug(&binding, &request, &caller_claim_evidence, &policy()),
            Err(AdmissionError::PeerIdentityDenied)
        ));
        let mut stream_evidence = evidence(&binding, &request);
        stream_evidence.listener.socket_type = SocketTypeV1::UnixStream;
        assert!(matches!(
            admit_userdebug(&binding, &request, &stream_evidence, &policy()),
            Err(AdmissionError::ListenerFdBoundaryDenied)
        ));
    }
}
