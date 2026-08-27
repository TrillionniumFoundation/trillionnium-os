//! Affine measured-launch custody for one operation replay-sync helper.
//!
//! This layer owns semantic/type-state validation. The sibling Linux backend
//! owns syscalls. Neither is reachable from daemon `main`, and the product
//! launcher constructor requires an authority type with no constructor in this
//! source slice.

use anyhow::{Context as _, Result, anyhow, bail};
use trillionnium_os_types::agent_principal_registry::{
    ACCESSIBILITY_ENDPOINT, SYSTEM_API_ENDPOINT, from_provider_agent_pair,
};
#[cfg(feature = "p0-launch-package-device-conformance")]
use trillionnium_os_types::direct_operation::DirectOperationP0ReplaySyncAckConfirmationV1;
use trillionnium_os_types::direct_operation::{
    DirectOperationAdapter, DirectOperationReplaySyncAckConfirmationV3,
    DirectOperationReplaySyncCommandV3, OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA,
    fixed_adapter_cgroup_path,
};
use trillionnium_os_types::sha256_bytes;

#[cfg(feature = "p0-launch-package-device-conformance")]
use super::P0BindingPublicationGuarded;
use super::{
    CompletedOperationReplaySyncLaunch, DirectOperationExecutionAuthorityEvidenceV1,
    DirectOperationReplaySyncLaunchReceiptV3, PreparedOperationReplaySyncLaunch,
    REPLAY_SYNC_LAUNCH_RECEIPT_SCHEMA, VerifiedAndroidBackendAckConfirmationProof,
};

pub(super) const SOURCE_STATUS: &str =
    "p0_userdebug_measured_operation_replay_sync_launcher_product_authority_held_v2";
pub(super) const RETAINED_AGENTD_CAPABILITY_MASK: u64 = 0x00e1;
pub(super) const REQUIRED_AGENTD_SECUREBITS: u32 = 0x00c3;
pub(super) const MAX_REPLAY_SYNC_PAYLOAD_BYTES: usize = 64 * 1024;
const REPLAY_SYNC_FRAME_MAGIC: [u8; 8] = *b"TROPSY01";
const REPLAY_SYNC_FRAME_VERSION: u8 = 1;
const REPLAY_SYNC_FRAME_HEADER_BYTES: usize = 16;
const APPLY_ACK_RESPONSE_OPCODE: u8 = 0x82;
#[cfg(not(feature = "p0-launch-package-device-conformance"))]
const SYSTEM_API_OPERATION_REPLAY_SYNC_BINARY: &str =
    "/system_ext/bin/trillionnium-system-api-operation-replay-sync";
#[cfg(feature = "p0-launch-package-device-conformance")]
const SYSTEM_API_OPERATION_REPLAY_SYNC_BINARY: &str =
    "/usr/local/bin/trillionnium-system-api-device-conformance-replay-sync";
const ACCESSIBILITY_OPERATION_REPLAY_SYNC_BINARY: &str =
    "/system_ext/bin/trillionnium-accessibility-operation-replay-sync";

/// Exact packaging/Verified-Boot admission for one fixed adapter executable.
/// All fields originate outside this source-only bridge.  There is no public
/// or crate-visible constructor in this checkpoint.
#[derive(Clone, Debug)]
pub(super) struct OperationReplaySyncProductAdmission {
    pub(super) adapter: DirectOperationAdapter,
    pub(super) executable_sha256: String,
    pub(super) product_descriptor_sha256: String,
    pub(super) signed_product_measurement_sha256: String,
    pub(super) avb_partition_digest_sha256: String,
    pub(super) fsverity_digest_sha256: String,
}

/// Future packaging/SELinux/device admission capability. It intentionally has
/// no constructor in this checkpoint.
#[must_use = "operation replay-sync launcher authority must be consumed"]
pub(crate) struct VerifiedOperationReplaySyncLauncherAuthority {
    system_api: OperationReplaySyncProductAdmission,
    accessibility: OperationReplaySyncProductAdmission,
}

impl VerifiedOperationReplaySyncLauncherAuthority {
    pub(super) fn into_admissions(self) -> Result<[OperationReplaySyncProductAdmission; 2]> {
        if self.system_api.adapter != DirectOperationAdapter::SystemApi
            || self.accessibility.adapter != DirectOperationAdapter::Accessibility
        {
            bail!("direct_operation_replay_sync_product_adapter_set_denied");
        }
        Ok([self.system_api, self.accessibility])
    }
}

#[derive(Debug)]
pub(super) struct OperationReplaySyncLaunchSpec {
    pub(super) provider_id: String,
    pub(super) agent_id: String,
    pub(super) adapter: DirectOperationAdapter,
    pub(super) binding_sha256: String,
    pub(super) daemon_ack_intent_sha256: String,
    pub(super) operation_replay_sync_ack_intent_sha256: String,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) executable_path: &'static str,
    pub(super) selinux_domain: &'static str,
    pub(super) unified_cgroup_path: String,
    pub(super) authority_evidence: DirectOperationExecutionAuthorityEvidenceV1,
    pub(super) launch_id_sha256: String,
    pub(super) launch_challenge_sha256: String,
    pub(super) command_frame: Vec<u8>,
    pub(super) command_frame_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VerifiedDaemonCapabilityCustody {
    pub(super) effective: u64,
    pub(super) permitted: u64,
    pub(super) bounding: u64,
    pub(super) inheritable: u64,
    pub(super) ambient: u64,
    pub(super) securebits: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MeasuredOperationReplaySyncExecutable {
    pub(super) fixed_path: String,
    pub(super) executable_sha256: String,
    pub(super) executable_file_identity_sha256: String,
    pub(super) same_fd_for_execveat: bool,
    pub(super) read_only_mount: bool,
    pub(super) regular_single_link: bool,
    pub(super) root_owned_nonwritable: bool,
    pub(super) elf_image: bool,
    pub(super) static_aarch64_elf64: bool,
    pub(super) pt_interp_absent: bool,
    pub(super) pt_dynamic_absent: bool,
    pub(super) wx_segment_absent: bool,
    pub(super) executable_stack_absent: bool,
    pub(super) setid_bits_absent: bool,
    pub(super) file_capabilities_absent: bool,
    pub(super) expected_hash_authority_matched: bool,
    pub(super) fsverity_measurement_matched: bool,
    pub(super) authority_evidence: DirectOperationExecutionAuthorityEvidenceV1,
    pub(super) fsverity_digest_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VerifiedOperationReplaySyncExec {
    pub(super) pid: u32,
    pub(super) start_time_ticks: u64,
    pub(super) pidfd_identity_sha256: String,
    pub(super) cgroup_identity_sha256: String,
    pub(super) pidfd_returned_by_clone3: bool,
    pub(super) clone_into_fixed_cgroup: bool,
    pub(super) ptrace_exec_stop_observed: bool,
    pub(super) start_time_stable_after_exec: bool,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) selinux_domain: String,
    pub(super) unified_cgroup_path: String,
    pub(super) executable_path: String,
    pub(super) executable_sha256: String,
    pub(super) command_fd3_only: bool,
    pub(super) response_fd4_only: bool,
    pub(super) other_fds_closed: bool,
    pub(super) environment_empty: bool,
    pub(super) arguments_empty: bool,
    pub(super) pdeathsig_sigkill: bool,
    pub(super) no_new_privs: bool,
    pub(super) dumpable_disabled: bool,
    pub(super) capabilities_empty: bool,
    pub(super) descendants_forbidden: bool,
    pub(super) tracer_parent_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExactHelperConfirmation {
    pub(super) confirmation: ReplaySyncAckConfirmation,
    pub(super) response_frame_sha256: String,
    pub(super) exact_eof: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ReplaySyncAckConfirmation {
    Product(DirectOperationReplaySyncAckConfirmationV3),
    #[cfg(feature = "p0-launch-package-device-conformance")]
    P0(DirectOperationP0ReplaySyncAckConfirmationV1),
}

impl ReplaySyncAckConfirmation {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Product(value) => value.validate().map_err(|error| anyhow!(error.to_string())),
            #[cfg(feature = "p0-launch-package-device-conformance")]
            Self::P0(value) => value.validate().map_err(|error| anyhow!(error.to_string())),
        }
    }

    fn ack_intent_sha256(&self) -> &str {
        match self {
            Self::Product(value) => &value.ack_intent_sha256,
            #[cfg(feature = "p0-launch-package-device-conformance")]
            Self::P0(value) => &value.ack_intent_sha256,
        }
    }

    fn acknowledgement_sha256(&self) -> &str {
        match self {
            Self::Product(value) => &value.acknowledgement_sha256,
            #[cfg(feature = "p0-launch-package-device-conformance")]
            Self::P0(value) => &value.acknowledgement_sha256,
        }
    }

    fn authenticated_ack_chain_sha256(&self) -> &str {
        match self {
            Self::Product(value) => &value.authenticated_ack_chain_sha256,
            #[cfg(feature = "p0-launch-package-device-conformance")]
            Self::P0(value) => &value.authenticated_ack_chain_sha256,
        }
    }

    fn compacted_ack_watermark(&self) -> u64 {
        match self {
            Self::Product(value) => value.compacted_ack_watermark,
            #[cfg(feature = "p0-launch-package-device-conformance")]
            Self::P0(value) => value.compacted_ack_watermark,
        }
    }

    fn digest_sha256(&self) -> Result<String> {
        match self {
            Self::Product(value) => value
                .digest_sha256()
                .map_err(|error| anyhow!(error.to_string())),
            #[cfg(feature = "p0-launch-package-device-conformance")]
            Self::P0(value) => value
                .digest_sha256()
                .map_err(|error| anyhow!(error.to_string())),
        }
    }
}

pub(super) trait OperationReplaySyncLaunchOps {
    type Child;

    fn verify_daemon_capabilities(&mut self) -> Result<VerifiedDaemonCapabilityCustody>;
    fn measure_fixed_executable(
        &mut self,
        spec: &OperationReplaySyncLaunchSpec,
    ) -> Result<MeasuredOperationReplaySyncExecutable>;
    fn spawn_stopped(
        &mut self,
        spec: &OperationReplaySyncLaunchSpec,
        executable: &MeasuredOperationReplaySyncExecutable,
    ) -> Result<Self::Child>;
    fn verify_post_exec(
        &mut self,
        child: &mut Self::Child,
    ) -> Result<VerifiedOperationReplaySyncExec>;
    fn release_command(&mut self, child: &mut Self::Child) -> Result<()>;
    fn resume(&mut self, child: &mut Self::Child) -> Result<()>;
    fn collect_exact_confirmation(
        &mut self,
        child: &mut Self::Child,
        spec: &OperationReplaySyncLaunchSpec,
    ) -> Result<ExactHelperConfirmation>;
    fn verify_successful_exit_and_reap(&mut self, child: &mut Self::Child) -> Result<()>;
    fn kill_and_reap(&mut self, child: Self::Child) -> Result<()>;
}

/// Fixed launcher shell. The only non-test constructor consumes an authority
/// which is presently uninhabited.
pub(crate) struct FixedOperationReplaySyncLauncher {
    ops: super::linux_operation_replay_sync_launcher::ConcreteLinuxOperationReplaySyncLaunchOps,
}

impl FixedOperationReplaySyncLauncher {
    pub(crate) fn from_verified_product_authority(
        authority: VerifiedOperationReplaySyncLauncherAuthority,
    ) -> Result<Self> {
        Ok(Self {
            ops: super::linux_operation_replay_sync_launcher::ConcreteLinuxOperationReplaySyncLaunchOps::from_verified_product_authority(authority)?,
        })
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn from_p0_userdebug_conformance() -> Result<Self> {
        Ok(Self {
            ops: super::linux_operation_replay_sync_launcher::ConcreteLinuxOperationReplaySyncLaunchOps::from_p0_userdebug_conformance()?,
        })
    }

    pub(crate) fn launch(
        &mut self,
        prepared: PreparedOperationReplaySyncLaunch,
    ) -> Result<CompletedOperationReplaySyncLaunch> {
        launch_with_ops(prepared, &mut self.ops)
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn launch_p0(
        &mut self,
        guarded: P0BindingPublicationGuarded<PreparedOperationReplaySyncLaunch>,
    ) -> Result<P0BindingPublicationGuarded<CompletedOperationReplaySyncLaunch>> {
        launch_p0_with_ops(guarded, &mut self.ops)
    }
}

pub(super) struct ConfirmationProofToken {
    launch_receipt: DirectOperationReplaySyncLaunchReceiptV3,
}

impl ConfirmationProofToken {
    pub(super) fn into_launch_receipt(self) -> DirectOperationReplaySyncLaunchReceiptV3 {
        self.launch_receipt
    }
}

pub(super) fn launch_with_ops<O: OperationReplaySyncLaunchOps>(
    prepared: PreparedOperationReplaySyncLaunch,
    ops: &mut O,
) -> Result<CompletedOperationReplaySyncLaunch> {
    prepared._single_flight_lease.revalidate_retained()?;
    let spec = derive_spec(&prepared)?;
    let capabilities = ops.verify_daemon_capabilities()?;
    require_exact_daemon_capabilities(&capabilities)?;
    let executable = ops.measure_fixed_executable(&spec)?;
    require_exact_executable(&spec, &executable)?;
    let mut child = ops.spawn_stopped(&spec, &executable)?;
    let verified = match ops.verify_post_exec(&mut child) {
        Ok(value) => value,
        Err(error) => return cleanup(ops, child, error),
    };
    if let Err(error) = require_exact_post_exec(&spec, &executable, &verified) {
        return cleanup(ops, child, error);
    }
    if let Err(error) = prepared._single_flight_lease.revalidate_retained() {
        return cleanup(ops, child, error);
    }
    // Command bytes are withheld until the semantic layer has accepted every
    // measured kernel fact.  The syscall backend cannot release them merely by
    // returning a forged or incomplete process snapshot.
    if let Err(error) = ops.release_command(&mut child) {
        return cleanup(ops, child, error);
    }
    if let Err(error) = ops.resume(&mut child) {
        return cleanup(ops, child, error);
    }
    let exact = match ops.collect_exact_confirmation(&mut child, &spec) {
        Ok(value) => value,
        Err(error) => return cleanup(ops, child, error),
    };
    if let Err(error) = validate_confirmation(&prepared, &exact) {
        return cleanup(ops, child, error);
    }
    if let Err(error) = ops.verify_successful_exit_and_reap(&mut child) {
        return cleanup(ops, child, error);
    }
    prepared._single_flight_lease.revalidate_retained()?;

    let launch_receipt = build_launch_receipt(&prepared, &spec, &executable, &verified, &exact)?;
    let verified_proof =
        VerifiedAndroidBackendAckConfirmationProof::from_measured_replay_sync_launcher(
            &prepared,
            ConfirmationProofToken { launch_receipt },
        )?;
    Ok(CompletedOperationReplaySyncLaunch {
        custody_head: prepared.custody_head,
        binding_sha256: prepared.binding_sha256,
        adapter: prepared.adapter,
        verified: verified_proof,
        _single_flight_lease: prepared._single_flight_lease,
    })
}

#[cfg(feature = "p0-launch-package-device-conformance")]
pub(super) fn launch_p0_with_ops<O: OperationReplaySyncLaunchOps>(
    guarded: P0BindingPublicationGuarded<PreparedOperationReplaySyncLaunch>,
    ops: &mut O,
) -> Result<P0BindingPublicationGuarded<CompletedOperationReplaySyncLaunch>> {
    let (publication, prepared) = guarded.into_parts();
    publication.validate_for_phase(
        &prepared.custody_head,
        &prepared.binding_sha256,
        prepared.adapter,
    )?;
    let completed = launch_with_ops(prepared, ops)?;
    publication.validate_for_phase(
        &completed.custody_head,
        &completed.binding_sha256,
        completed.adapter,
    )?;
    Ok(P0BindingPublicationGuarded::new(publication, completed))
}

fn derive_spec(
    prepared: &PreparedOperationReplaySyncLaunch,
) -> Result<OperationReplaySyncLaunchSpec> {
    prepared
        .inbox
        .validate()
        .map_err(|error| anyhow!(error.to_string()))?;
    let descriptor = from_provider_agent_pair(&prepared.provider_id, &prepared.agent_id)
        .context("direct_operation_replay_sync_descriptor_denied")?;
    let acknowledgement = &prepared.inbox.acknowledgement;
    if acknowledgement.provider_id != prepared.provider_id
        || acknowledgement.agent_id != prepared.agent_id
        || acknowledgement.adapter != prepared.adapter
        || acknowledgement.binding_sha256 != prepared.binding_sha256
        || prepared.outer_ack_inbox_publication.adapter != prepared.adapter
        || prepared.outer_ack_inbox_publication.binding_sha256 != prepared.binding_sha256
        || prepared.outer_ack_inbox_publication.ack_intent_sha256 != prepared.ack_intent_sha256
        || prepared.outer_ack_inbox_publication.acknowledgement_sha256
            != prepared.inbox.acknowledgement_sha256
        || prepared
            .outer_ack_inbox_publication
            .authenticated_ack_chain_sha256
            != prepared.inbox.chain_step.authenticated_ack_chain_sha256
    {
        bail!("direct_operation_replay_sync_prepared_identity_denied");
    }
    let expected_sync_intent = prepared
        .inbox
        .operation_replay_sync_ack_intent_sha256()
        .map_err(|error| anyhow!(error.to_string()))?;
    if expected_sync_intent != prepared.operation_replay_sync_ack_intent_sha256 {
        bail!("direct_operation_replay_sync_intent_digest_domain_drift");
    }
    let (executable_path, selinux_domain) = match prepared.adapter {
        DirectOperationAdapter::SystemApi => (
            SYSTEM_API_OPERATION_REPLAY_SYNC_BINARY,
            SYSTEM_API_ENDPOINT.operation_replay_sync_selinux_domain,
        ),
        DirectOperationAdapter::Accessibility => (
            ACCESSIBILITY_OPERATION_REPLAY_SYNC_BINARY,
            ACCESSIBILITY_ENDPOINT.operation_replay_sync_selinux_domain,
        ),
    };
    let unified_cgroup_path = fixed_adapter_cgroup_path(&prepared.provider_id, prepared.adapter)
        .map_err(|error| anyhow!(error.to_string()))?;
    if !valid_digest(&prepared.launch_id_sha256) || !valid_digest(&prepared.launch_challenge_sha256)
    {
        bail!("direct_operation_replay_sync_launch_identity_denied");
    }
    let launch_challenge_sha256 = prepared.launch_challenge_sha256.clone();
    let command = DirectOperationReplaySyncCommandV3::ApplyAck {
        schema: OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA.to_string(),
        binding_sha256: prepared.binding_sha256.clone(),
        ack_intent_sha256: prepared.operation_replay_sync_ack_intent_sha256.clone(),
        launch_challenge_sha256: launch_challenge_sha256.clone(),
        p0_sealed_authority: {
            #[cfg(feature = "p0-launch-package-device-conformance")]
            {
                prepared.p0_sealed_authority.clone().map(Box::new)
            }
            #[cfg(not(feature = "p0-launch-package-device-conformance"))]
            {
                None
            }
        },
    };
    #[cfg(feature = "p0-launch-package-device-conformance")]
    if prepared.p0_sealed_authority.is_some() {
        command
            .validate_p0_daemon_custody_lane()
            .map_err(|error| anyhow!(error.to_string()))?;
    } else {
        command
            .validate_product_lane()
            .map_err(|error| anyhow!(error.to_string()))?;
    }
    #[cfg(not(feature = "p0-launch-package-device-conformance"))]
    command
        .validate_product_lane()
        .map_err(|error| anyhow!(error.to_string()))?;
    let command_frame = encode_command_frame(&command)?;
    let command_frame_sha256 = sha256_bytes(&command_frame);
    Ok(OperationReplaySyncLaunchSpec {
        provider_id: prepared.provider_id.clone(),
        agent_id: prepared.agent_id.clone(),
        adapter: prepared.adapter,
        binding_sha256: prepared.binding_sha256.clone(),
        daemon_ack_intent_sha256: prepared.ack_intent_sha256.clone(),
        operation_replay_sync_ack_intent_sha256: prepared
            .operation_replay_sync_ack_intent_sha256
            .clone(),
        uid: descriptor.uid,
        gid: descriptor.gid,
        executable_path,
        selinux_domain,
        unified_cgroup_path,
        authority_evidence: prepared
            .outer_ack_inbox_publication
            .publisher_provenance
            .authority_evidence
            .clone(),
        launch_id_sha256: prepared.launch_id_sha256.clone(),
        launch_challenge_sha256,
        command_frame,
        command_frame_sha256,
    })
}

fn encode_command_frame(command: &DirectOperationReplaySyncCommandV3) -> Result<Vec<u8>> {
    let payload = command
        .canonical_json()
        .map_err(|_| anyhow!("direct_operation_replay_sync_command_json_denied"))?;
    if payload.is_empty() || payload.len() > MAX_REPLAY_SYNC_PAYLOAD_BYTES {
        bail!("direct_operation_replay_sync_command_payload_size_denied");
    }
    let payload_len = u32::try_from(payload.len())
        .context("direct_operation_replay_sync_command_payload_length_overflow")?;
    let mut frame = Vec::with_capacity(REPLAY_SYNC_FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&REPLAY_SYNC_FRAME_MAGIC);
    frame.push(REPLAY_SYNC_FRAME_VERSION);
    frame.push(command.opcode());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub(super) fn decode_ack_confirmation_response_frame(
    bytes: &[u8],
) -> Result<ReplaySyncAckConfirmation> {
    if bytes.len() < REPLAY_SYNC_FRAME_HEADER_BYTES
        || bytes[..8] != REPLAY_SYNC_FRAME_MAGIC
        || bytes[8] != REPLAY_SYNC_FRAME_VERSION
        || bytes[9] != APPLY_ACK_RESPONSE_OPCODE
        || bytes[10..12] != [0, 0]
    {
        bail!("direct_operation_replay_sync_confirmation_frame_header_denied");
    }
    let payload_len =
        u32::from_be_bytes(bytes[12..16].try_into().expect("fixed replay-sync header")) as usize;
    if payload_len == 0
        || payload_len > MAX_REPLAY_SYNC_PAYLOAD_BYTES
        || bytes.len() != REPLAY_SYNC_FRAME_HEADER_BYTES + payload_len
    {
        bail!("direct_operation_replay_sync_confirmation_frame_length_denied");
    }
    let payload = &bytes[REPLAY_SYNC_FRAME_HEADER_BYTES..];
    #[cfg(feature = "p0-launch-package-device-conformance")]
    if let Ok(value) = DirectOperationP0ReplaySyncAckConfirmationV1::from_canonical_json(payload) {
        return Ok(ReplaySyncAckConfirmation::P0(value));
    }
    DirectOperationReplaySyncAckConfirmationV3::from_canonical_json(payload)
        .map(ReplaySyncAckConfirmation::Product)
        .map_err(|_| anyhow!("direct_operation_replay_sync_confirmation_json_denied"))
}

fn require_exact_daemon_capabilities(value: &VerifiedDaemonCapabilityCustody) -> Result<()> {
    if value.effective != RETAINED_AGENTD_CAPABILITY_MASK
        || value.permitted != RETAINED_AGENTD_CAPABILITY_MASK
        || value.bounding != 0
        || value.inheritable != 0
        || value.ambient != 0
        || value.securebits != REQUIRED_AGENTD_SECUREBITS
    {
        bail!("direct_operation_replay_sync_agentd_capability_set_denied");
    }
    Ok(())
}

fn require_exact_executable(
    spec: &OperationReplaySyncLaunchSpec,
    value: &MeasuredOperationReplaySyncExecutable,
) -> Result<()> {
    if value.fixed_path != spec.executable_path
        || !valid_digest(&value.executable_sha256)
        || !valid_digest(&value.executable_file_identity_sha256)
        || !value.same_fd_for_execveat
        || !value.read_only_mount
        || !value.regular_single_link
        || !value.root_owned_nonwritable
        || !value.elf_image
        || !value.static_aarch64_elf64
        || !value.pt_interp_absent
        || !value.pt_dynamic_absent
        || !value.wx_segment_absent
        || !value.executable_stack_absent
        || !value.setid_bits_absent
        || !value.file_capabilities_absent
        || !value.expected_hash_authority_matched
        || match &value.authority_evidence {
            DirectOperationExecutionAuthorityEvidenceV1::SignedProduct { .. } => {
                !value.fsverity_measurement_matched
            }
            DirectOperationExecutionAuthorityEvidenceV1::P0UserdebugConformance { .. } => {
                value.fsverity_measurement_matched
            }
        }
        || value.authority_evidence != spec.authority_evidence
        || value.authority_evidence.validate().is_err()
        || !value
            .authority_evidence
            .valid_component_integrity(&value.fsverity_digest_sha256)
    {
        bail!("direct_operation_replay_sync_executable_measurement_denied");
    }
    Ok(())
}

fn require_exact_post_exec(
    spec: &OperationReplaySyncLaunchSpec,
    executable: &MeasuredOperationReplaySyncExecutable,
    value: &VerifiedOperationReplaySyncExec,
) -> Result<()> {
    if value.pid == 0
        || value.start_time_ticks == 0
        || !valid_digest(&value.pidfd_identity_sha256)
        || !valid_digest(&value.cgroup_identity_sha256)
        || !value.pidfd_returned_by_clone3
        || !value.clone_into_fixed_cgroup
        || !value.ptrace_exec_stop_observed
        || !value.start_time_stable_after_exec
        || value.uid != spec.uid
        || value.gid != spec.gid
        || value.selinux_domain != spec.selinux_domain
        || value.unified_cgroup_path != spec.unified_cgroup_path
        || value.executable_path != spec.executable_path
        || value.executable_sha256 != executable.executable_sha256
        || !value.command_fd3_only
        || !value.response_fd4_only
        || !value.other_fds_closed
        || !value.environment_empty
        || !value.arguments_empty
        || !value.pdeathsig_sigkill
        || !value.no_new_privs
        || !value.dumpable_disabled
        || !value.capabilities_empty
        || !value.descendants_forbidden
        || !value.tracer_parent_verified
    {
        bail!("direct_operation_replay_sync_post_exec_custody_denied");
    }
    Ok(())
}

pub(super) fn validate_confirmation(
    prepared: &PreparedOperationReplaySyncLaunch,
    exact: &ExactHelperConfirmation,
) -> Result<()> {
    exact.confirmation.validate()?;
    let acknowledgement = &prepared.inbox.acknowledgement;
    if !exact.exact_eof
        || !valid_digest(&exact.response_frame_sha256)
        || exact.confirmation.ack_intent_sha256()
            != prepared.operation_replay_sync_ack_intent_sha256
        || exact.confirmation.acknowledgement_sha256() != prepared.inbox.acknowledgement_sha256
        || exact.confirmation.authenticated_ack_chain_sha256()
            != prepared.inbox.chain_step.authenticated_ack_chain_sha256
        || exact.confirmation.compacted_ack_watermark()
            != acknowledgement
                .journal_evidence_snapshot
                .last_journal_sequence
    {
        bail!("direct_operation_replay_sync_helper_confirmation_denied");
    }
    #[cfg(feature = "p0-launch-package-device-conformance")]
    match (&prepared.p0_sealed_authority, &exact.confirmation) {
        (Some(authority), ReplaySyncAckConfirmation::P0(value))
            if value.daemon_custody_committed_head_sha256
                == authority.committed_custody_head_sha256
                && value.daemon_high_water_observation_sha256
                    == authority.daemon_high_water_observation_sha256
                && value.daemon_binding_publication_identity_sha256
                    == authority.daemon_binding_publication_identity_sha256
                && value.sealed_authority_sha256 == authority.sealed_authority_sha256 => {}
        (None, ReplaySyncAckConfirmation::Product(_)) => {}
        _ => bail!("direct_operation_replay_sync_confirmation_lane_substitution_denied"),
    }
    #[cfg(not(feature = "p0-launch-package-device-conformance"))]
    if !matches!(exact.confirmation, ReplaySyncAckConfirmation::Product(_)) {
        bail!("direct_operation_replay_sync_confirmation_lane_substitution_denied");
    }
    Ok(())
}

fn build_launch_receipt(
    _prepared: &PreparedOperationReplaySyncLaunch,
    spec: &OperationReplaySyncLaunchSpec,
    executable: &MeasuredOperationReplaySyncExecutable,
    verified: &VerifiedOperationReplaySyncExec,
    exact: &ExactHelperConfirmation,
) -> Result<DirectOperationReplaySyncLaunchReceiptV3> {
    let confirmation_sha256 = exact.confirmation.digest_sha256()?;
    Ok(DirectOperationReplaySyncLaunchReceiptV3 {
        schema: REPLAY_SYNC_LAUNCH_RECEIPT_SCHEMA.to_string(),
        adapter: spec.adapter,
        binding_sha256: spec.binding_sha256.clone(),
        launch_id_sha256: spec.launch_id_sha256.clone(),
        launch_challenge_sha256: spec.launch_challenge_sha256.clone(),
        operation_replay_sync_ack_intent_sha256: spec
            .operation_replay_sync_ack_intent_sha256
            .clone(),
        authority_evidence: executable.authority_evidence.clone(),
        fsverity_digest_sha256: executable.fsverity_digest_sha256.clone(),
        executable_sha256: executable.executable_sha256.clone(),
        executable_file_identity_sha256: executable.executable_file_identity_sha256.clone(),
        executable_static_aarch64_elf64: executable.static_aarch64_elf64,
        pid: verified.pid,
        start_time_ticks: verified.start_time_ticks,
        pidfd_identity_sha256: verified.pidfd_identity_sha256.clone(),
        cgroup_identity_sha256: verified.cgroup_identity_sha256.clone(),
        uid: verified.uid,
        gid: verified.gid,
        selinux_domain: verified.selinux_domain.clone(),
        command_frame_sha256: spec.command_frame_sha256.clone(),
        response_frame_sha256: exact.response_frame_sha256.clone(),
        confirmation_sha256,
        tracer_parent_verified: verified.tracer_parent_verified,
        pdeathsig_sigkill_verified: verified.pdeathsig_sigkill,
        exact_process_surface_verified: verified.command_fd3_only
            && verified.response_fd4_only
            && verified.other_fds_closed
            && verified.environment_empty
            && verified.arguments_empty
            && verified.no_new_privs
            && verified.dumpable_disabled
            && verified.capabilities_empty
            && verified.descendants_forbidden,
    })
}

fn cleanup<O: OperationReplaySyncLaunchOps, T>(
    ops: &mut O,
    child: O::Child,
    original: anyhow::Error,
) -> Result<T> {
    if let Err(cleanup) = ops.kill_and_reap(child) {
        return Err(anyhow!(
            "{original:#}; direct_operation_replay_sync_cleanup_ambiguous: {cleanup:#}"
        ));
    }
    Err(original)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !value.bytes().all(|byte| byte == b'0')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn product_admission(adapter: DirectOperationAdapter) -> OperationReplaySyncProductAdmission {
        let digest = |label: &str| sha256_bytes(label.as_bytes());
        OperationReplaySyncProductAdmission {
            adapter,
            executable_sha256: digest("test-replay-sync-executable"),
            product_descriptor_sha256: digest("test-replay-sync-product-descriptor"),
            signed_product_measurement_sha256: digest("test-replay-sync-signed-product"),
            avb_partition_digest_sha256: digest("test-replay-sync-avb"),
            fsverity_digest_sha256: digest("test-replay-sync-fsverity"),
        }
    }

    #[test]
    fn source_keeps_product_authority_uninhabited_and_caps_minimal() {
        let source = include_str!("operation_replay_sync_launcher.rs");
        assert_eq!(RETAINED_AGENTD_CAPABILITY_MASK, 0x00e1);
        assert!(!source.contains(concat!("CAP_SYS_", "ADMIN")));
        assert!(!source.contains(concat!("CAP_SYS_", "PTRACE")));
        assert!(!source.contains(concat!("pub fn for_", "path")));
        assert!(!source.contains(concat!("pub fn with_", "uid")));
        assert_eq!(
            SOURCE_STATUS,
            "p0_userdebug_measured_operation_replay_sync_launcher_product_authority_held_v2"
        );
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_userdebug_launcher_constructor_is_distinct_from_product_authority() {
        FixedOperationReplaySyncLauncher::from_p0_userdebug_conformance().unwrap();
    }

    #[test]
    fn daemon_capability_contract_matches_hardened_agentd_exactly() {
        let exact = VerifiedDaemonCapabilityCustody {
            effective: RETAINED_AGENTD_CAPABILITY_MASK,
            permitted: RETAINED_AGENTD_CAPABILITY_MASK,
            bounding: 0,
            inheritable: 0,
            ambient: 0,
            securebits: REQUIRED_AGENTD_SECUREBITS,
        };
        require_exact_daemon_capabilities(&exact).unwrap();
        let mut drift = exact.clone();
        drift.bounding = RETAINED_AGENTD_CAPABILITY_MASK;
        assert!(require_exact_daemon_capabilities(&drift).is_err());
        let mut drift = exact.clone();
        drift.securebits &= !0x2;
        assert!(require_exact_daemon_capabilities(&drift).is_err());
    }

    #[test]
    fn product_authority_requires_one_exact_admission_per_fixed_adapter() {
        let exact = VerifiedOperationReplaySyncLauncherAuthority {
            system_api: product_admission(DirectOperationAdapter::SystemApi),
            accessibility: product_admission(DirectOperationAdapter::Accessibility),
        };
        assert!(exact.into_admissions().is_ok());

        let duplicate = VerifiedOperationReplaySyncLauncherAuthority {
            system_api: product_admission(DirectOperationAdapter::SystemApi),
            accessibility: product_admission(DirectOperationAdapter::SystemApi),
        };
        assert!(duplicate.into_admissions().is_err());
        let swapped = VerifiedOperationReplaySyncLauncherAuthority {
            system_api: product_admission(DirectOperationAdapter::Accessibility),
            accessibility: product_admission(DirectOperationAdapter::SystemApi),
        };
        assert!(swapped.into_admissions().is_err());
    }
}
