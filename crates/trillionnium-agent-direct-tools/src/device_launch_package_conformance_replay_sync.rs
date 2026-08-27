//! Fixed-FD userdebug-only runtime intake for P0-2 launch-package replay.
//!
//! This module describes the affine transaction required to reconcile the
//! fixed `p01-launch-package-operations.json` journal: authenticate complete
//! delivery/allocation bindings and the durable outer receipt, ACTIVATE the
//! fixed Android System API replay endpoint, ACK before local compaction, and
//! publish/read back a post-compaction confirmation.  It also models the two
//! restart windows: ACK response loss and compaction-before-confirmation.
//!
//! The public helper now consumes the production replay-sync fixed FD 3/4
//! framing, authenticates its fixed replay role, reads the root-owned binding
//! and ACK inbox, and observes the retained conformance journal.  It validates
//! the complete locally available ACK evidence before requesting any Android
//! action. The measured daemon now hands the full allocation/receipt/custody
//! preimage through that same fixed descriptor only after post-exec custody is
//! verified. The helper cross-checks it against its independently opened
//! root-owned inbox before ACTIVATE, ACK and local compaction.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use trillionnium_os_types::agent_principal_registry::{self, CODEX_STABLE_PRINCIPAL};
use trillionnium_os_types::direct_operation::{
    DirectOperationAdapter, DirectOperationBinding, DirectOperationJournalEvidenceSnapshotV1,
    DirectOperationOuterAckInboxV3, DirectOperationOuterEvidence, DirectOperationOuterOutcome,
    DirectOperationOuterReceiptV3, DirectOperationP0ReplaySyncAckConfirmationV1,
    DirectOperationP0ReplaySyncSealedAuthorityV1, DirectOperationReplaySyncCommandV3,
    P0_REPLAY_SYNC_ACK_CONFIRMATION_LANE, P0_REPLAY_SYNC_ACK_CONFIRMATION_V1_SCHEMA,
};

use crate::operation_journal::{
    DeviceConformanceJournalObservation, DeviceConformanceReplayState, OperationJournal,
};
use crate::operation_replay_sync::FixedOneShotTransport;
use crate::trusted_context::TrustedReplaySyncContext;
use crate::{DirectToolError, Result};

pub const JOURNAL_FILE_NAME: &str = "p01-launch-package-operations.json";
pub const CONFIRMATION_FILE_NAME: &str = "p01-launch-package-replay-confirmation-v1.json";
pub const CONFIRMATION_SCHEMA: &str = "org.trillionnium.p0-2.launch-package-replay-confirmation.v1";
pub const SOURCE_STATUS: &str = "p0_userdebug_sealed_authority_activate_ack_compact_v4";

const LANE: &str = "non_product_userdebug_only";
const CONFIRMATION_STATUS: &str = "held_non_authorizing_transition_model";
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const CONFORMANCE_FIXED_FD_INTAKE_WIRED: bool = true;
const CONFORMANCE_TRUSTED_CONTEXT_INTAKE_WIRED: bool = true;
const CONFORMANCE_LOCAL_JOURNAL_OBSERVATION_WIRED: bool = true;
const P0_USERDEBUG_DAEMON_SEALED_AUTHORITY_WIRED: bool = true;
const PRODUCT_EXTERNAL_ROLLBACK_AUTHORITY_WIRED: bool = false;
const PRODUCT_ROOT_PUBLICATION_AUTHORITY_WIRED: bool = false;
const PRODUCT_EFFECT_AUTHORITY_WIRED: bool = false;
const PRODUCT_MUTATION_CAS_AUTHORITY_WIRED: bool = false;
const COMPILED_BUILD_VARIANT: Option<&str> =
    option_env!("TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT");
const _: () = {
    assert!(CONFORMANCE_FIXED_FD_INTAKE_WIRED);
    assert!(CONFORMANCE_TRUSTED_CONTEXT_INTAKE_WIRED);
    assert!(CONFORMANCE_LOCAL_JOURNAL_OBSERVATION_WIRED);
    assert!(P0_USERDEBUG_DAEMON_SEALED_AUTHORITY_WIRED);
    assert!(!PRODUCT_EXTERNAL_ROLLBACK_AUTHORITY_WIRED);
    assert!(!PRODUCT_ROOT_PUBLICATION_AUTHORITY_WIRED);
    assert!(!PRODUCT_EFFECT_AUTHORITY_WIRED);
    assert!(!PRODUCT_MUTATION_CAS_AUTHORITY_WIRED);
};

/// Fixed helper entry point for the non-product userdebug-only P0 lane.
pub fn run_system_api_replay_sync() -> Result<()> {
    let _compiled_artifact_identity =
        crate::device_launch_package_conformance::compiled_build_variant_evidence();
    require_compiled_non_product_build_variant(COMPILED_BUILD_VARIANT)?;
    let mut intake = ValidatedRuntimeIntake::open()?;
    validate_sealed_replay_authority(&mut intake)?;
    complete_runtime_replay(intake)
}

fn require_compiled_non_product_build_variant(value: Option<&str>) -> Result<&str> {
    match value {
        Some("userdebug") => Ok("userdebug"),
        _ => Err(hold(
            "P0-2 replay-sync helper lacks an embedded userdebug-only build identity",
        )),
    }
}

fn validate_p0_system_api_binding(binding: &DirectOperationBinding) -> Result<()> {
    binding
        .authorized_adapter_set
        .validate_p0_system_api()
        .map_err(|_| hold("P0-2 binding adapter policy is not exactly System API"))
}

/// Fully validated material that is available inside the endpoint helper
/// without trusting caller paths or self-reported root evidence.  Keeping the
/// transport alive also keeps the already validated response pipe distinct
/// from FD 3 until the run either reaches a durable confirmation or HOLDs.
struct ValidatedRuntimeIntake {
    transport: FixedOneShotTransport,
    context: TrustedReplaySyncContext,
    inbox: DirectOperationOuterAckInboxV3,
    authority: DirectOperationP0ReplaySyncSealedAuthorityV1,
    journal: OperationJournal,
    local_journal: DeviceConformanceJournalObservation,
    local_position: LocalReplayPosition,
    launch_challenge_sha256: String,
    ack_intent_sha256: String,
}

impl ValidatedRuntimeIntake {
    fn open() -> Result<Self> {
        let transport = FixedOneShotTransport::open()
            .map_err(|error| hold(&format!("P0-2 fixed replay-sync FD intake failed: {error}")))?;
        transport
            .command()
            .validate_p0_daemon_custody_lane()
            .map_err(|_| hold("P0-2 fixed command is not the sealed daemon-custody lane"))?;
        let (binding_sha256, ack_intent_sha256, launch_challenge_sha256, authority) =
            match transport.command() {
                DirectOperationReplaySyncCommandV3::ApplyAck {
                    binding_sha256,
                    ack_intent_sha256,
                    launch_challenge_sha256,
                    p0_sealed_authority,
                    ..
                } => (
                    binding_sha256.clone(),
                    ack_intent_sha256.clone(),
                    launch_challenge_sha256.clone(),
                    p0_sealed_authority
                        .as_deref()
                        .cloned()
                        .ok_or_else(|| hold("P0-2 fixed command lacks sealed replay authority"))?,
                ),
                DirectOperationReplaySyncCommandV3::ObserveDisposition { .. } => {
                    return Err(hold(
                        "P0-2 conformance replay-sync accepts only the fixed ApplyAck command",
                    ));
                }
            };

        let context = TrustedReplaySyncContext::open_current_device_conformance_system_api()
            .map_err(|error| hold(&format!("P0-2 trusted replay context failed: {error}")))?;
        validate_p0_system_api_binding(context.binding())?;
        if binding_sha256 != context.binding_sha256()
            || !valid_nonzero_sha256(&launch_challenge_sha256)
        {
            return Err(hold(
                "P0-2 fixed command does not match the trusted binding/challenge identity",
            ));
        }
        let inbox = context
            .pending_outer_ack_v3_for_device_conformance()
            .map_err(|error| hold(&format!("P0-2 fixed ACK inbox failed: {error}")))?
            .ok_or_else(|| hold("P0-2 fixed root-owned outer ACK v3 inbox is absent"))?;
        let expected_ack_intent = inbox
            .operation_replay_sync_ack_intent_sha256()
            .map_err(|_| hold("P0-2 fixed ACK intent is invalid"))?;
        if ack_intent_sha256 != expected_ack_intent {
            return Err(hold(
                "P0-2 fixed FD command ACK intent does not match the root-owned inbox",
            ));
        }
        authority
            .validate_for(
                &inbox,
                &binding_sha256,
                &ack_intent_sha256,
                &launch_challenge_sha256,
            )
            .map_err(|_| hold("P0-2 sealed replay authority does not match the fixed intake"))?;
        if authority.delivery_binding != *context.binding()
            || authority.binding_inbox_bytes_sha256 != context.binding_inbox_bytes_sha256()
        {
            return Err(hold(
                "P0-2 sealed replay authority differs from the independently opened root binding inbox",
            ));
        }

        let mut journal = context
            .open_device_conformance_operation_journal()
            .map_err(|error| hold(&format!("P0-2 fixed conformance journal failed: {error}")))?;
        let local = journal
            .device_conformance_journal_observation()
            .map_err(|error| hold(&format!("P0-2 local journal observation failed: {error}")))?;
        let local_position = validate_runtime_local_ack(&context, &inbox, &local)?;

        Ok(Self {
            transport,
            context,
            inbox,
            authority,
            journal,
            local_journal: local,
            local_position,
            launch_challenge_sha256,
            ack_intent_sha256,
        })
    }
}

fn validate_runtime_local_ack(
    context: &TrustedReplaySyncContext,
    inbox: &DirectOperationOuterAckInboxV3,
    local: &DeviceConformanceJournalObservation,
) -> Result<LocalReplayPosition> {
    validate_p0_system_api_binding(context.binding())?;
    inbox
        .validate()
        .map_err(|_| hold("P0-2 fixed outer ACK v3 is invalid"))?;
    let acknowledgement = &inbox.acknowledgement;
    if acknowledgement.binding_sha256 != context.binding_sha256()
        || acknowledgement.invocation_id != context.invocation_id()
        || acknowledgement.delivery_provider_attempt_id != context.delivery_provider_attempt_id()
        || acknowledgement.provider_id != context.provider_id()
        || acknowledgement.agent_id != context.agent_id()
        || acknowledgement.adapter != DirectOperationAdapter::SystemApi
    {
        return Err(hold(
            "P0-2 fixed outer ACK differs from the trusted replay context",
        ));
    }
    let snapshot = &acknowledgement.journal_evidence_snapshot;
    validate_fixed_launch_evidence(context.provider_id(), context.agent_id(), snapshot)?;
    let (before, after) = replay_states_from_inbox(inbox)?;
    let position = if local.replay_state == before {
        if local.evidence_snapshot.as_ref() != Some(snapshot)
            || local.journal_payload_sha256 != snapshot.journal_payload_sha256
        {
            return Err(hold(
                "P0-2 retained journal is not the exact authenticated pre-ACK snapshot",
            ));
        }
        LocalReplayPosition::BeforeAck
    } else if local.replay_state == after && local.evidence_snapshot.is_none() {
        LocalReplayPosition::AfterAck
    } else {
        return Err(hold(
            "P0-2 local journal is neither the exact pre-ACK nor post-ACK state",
        ));
    };
    require_nonzero_sha256(
        &local.journal_file_identity_sha256,
        "P0-2 retained journal inode identity is invalid",
    )?;
    Ok(position)
}

fn validate_sealed_replay_authority(intake: &mut ValidatedRuntimeIntake) -> Result<()> {
    // Recheck all independent local facts immediately before the first
    // Android request. Fixed-FD bytes alone never override a changed root
    // inbox or retained journal inode.
    let current_local = intake
        .journal
        .device_conformance_journal_observation()
        .map_err(|error| {
            hold(&format!(
                "P0-2 journal revalidation failed before daemon-sealed handoff: {error}"
            ))
        })?;
    let current_position =
        validate_runtime_local_ack(&intake.context, &intake.inbox, &current_local)?;
    if current_local != intake.local_journal || current_position != intake.local_position {
        return Err(hold(
            "P0-2 retained journal changed before daemon-sealed handoff",
        ));
    }
    if intake.ack_intent_sha256
        != intake
            .inbox
            .operation_replay_sync_ack_intent_sha256()
            .map_err(|_| hold("P0-2 ACK intent changed before daemon-sealed handoff"))?
        || intake.context.binding_sha256() != intake.inbox.acknowledgement.binding_sha256
        || !valid_nonzero_sha256(&intake.launch_challenge_sha256)
        || intake.authority.delivery_binding != *intake.context.binding()
        || intake.authority.binding_inbox_bytes_sha256
            != intake.context.binding_inbox_bytes_sha256()
    {
        return Err(hold(
            "P0-2 fixed intake changed before daemon-sealed handoff",
        ));
    }
    intake
        .authority
        .validate_for(
            &intake.inbox,
            intake.context.binding_sha256(),
            &intake.ack_intent_sha256,
            &intake.launch_challenge_sha256,
        )
        .map_err(|_| hold("P0-2 sealed replay authority changed before ACTIVATE"))?;
    Ok(())
}

fn complete_runtime_replay(mut intake: ValidatedRuntimeIntake) -> Result<()> {
    let pending = match intake.local_position {
        LocalReplayPosition::BeforeAck => Some(&intake.inbox),
        LocalReplayPosition::AfterAck => None,
    };
    let activation =
        crate::android_operation_replay_control::activate_system_api_for_device_conformance_replay_sync(
            &intake.local_journal.replay_state,
            pending,
            &intake.context,
        )?;
    let android_ack = if activation.android_ack_already_applied() {
        crate::android_operation_replay_ack::recover_system_api_ack_for_device_conformance(
            &intake.inbox,
            activation,
        )
    } else {
        crate::android_operation_replay_ack::acknowledge_system_api_for_device_conformance(
            &intake.inbox,
        )
    }
    .map_err(|error| {
        hold(&format!(
            "P0-2 Android ACK failed or response was lost: {error}"
        ))
    })?;
    let android_ack_echo_sha256 = android_ack.echo_sha256();
    let post = intake
        .journal
        .apply_device_conformance_outer_ack_and_observe(
            &intake.authority.delivery_binding,
            &intake.authority.allocation_binding,
            &intake.authority.outer_receipt,
            &intake.inbox,
            &android_ack,
        )
        .map_err(|error| hold(&format!("P0-2 journal compaction failed: {error}")))?;
    let confirmation = DirectOperationP0ReplaySyncAckConfirmationV1 {
        schema: P0_REPLAY_SYNC_ACK_CONFIRMATION_V1_SCHEMA.to_string(),
        lane: P0_REPLAY_SYNC_ACK_CONFIRMATION_LANE.to_string(),
        ack_intent_sha256: intake.ack_intent_sha256,
        android_ack_echo_sha256,
        acknowledgement_sha256: intake.inbox.acknowledgement_sha256.clone(),
        authenticated_ack_chain_sha256: intake
            .inbox
            .chain_step
            .authenticated_ack_chain_sha256
            .clone(),
        compacted_ack_watermark: post.replay_state.acknowledged_through,
        post_compaction_journal_sha256: post.journal_payload_sha256,
        journal_file_identity_sha256: post.journal_file_identity_sha256,
        daemon_custody_committed_head_sha256: intake.authority.committed_custody_head_sha256,
        daemon_high_water_observation_sha256: intake.authority.daemon_high_water_observation_sha256,
        daemon_binding_publication_identity_sha256: intake
            .authority
            .daemon_binding_publication_identity_sha256,
        sealed_authority_sha256: intake.authority.sealed_authority_sha256,
    };
    confirmation
        .validate()
        .map_err(|_| hold("P0-2 replay confirmation is invalid"))?;
    let payload = confirmation
        .canonical_json()
        .map_err(|_| hold("P0-2 replay confirmation is not canonical"))?;
    intake
        .transport
        .write_response(0x82, &payload)
        .map_err(|error| hold(&format!("P0-2 fixed confirmation response failed: {error}")))
}

#[derive(Debug, PartialEq, Eq)]
struct BoundConformanceLaunchIdentity {
    provider_id: String,
    agent_id: String,
    invocation_id: String,
    delivery_provider_attempt_id: String,
    allocating_provider_attempt_id: String,
    delivery_binding_sha256: String,
    allocation_binding_sha256: String,
    outer_receipt_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalReplayPosition {
    BeforeAck,
    AfterAck,
}

#[derive(Debug, PartialEq, Eq)]
struct ConformanceAckIntent {
    ack_intent_sha256: String,
    acknowledgement_sha256: String,
    authenticated_ack_chain_sha256: String,
    before_journal_sha256: String,
    canonical_request_sha256: String,
    backend_request_id_sha256: String,
    backend_result_sha256: String,
    before: DeviceConformanceReplayState,
    after: DeviceConformanceReplayState,
}

fn fixed_agent_identity(
    provider_id: &str,
    agent_id: &str,
) -> Result<crate::risk_guard::AgentIdentity> {
    if agent_principal_registry::from_provider_agent_pair(provider_id, agent_id)
        == Some(&CODEX_STABLE_PRINCIPAL)
    {
        Ok(crate::risk_guard::AgentIdentity::Codex)
    } else {
        Err(hold(
            "P0-2 conformance replay provider/agent is not one exact stable-principal pair",
        ))
    }
}

fn fixed_launch_package_request() -> crate::system_api::SystemApiRequest {
    crate::system_api::SystemApiRequest::LaunchPackage {
        protocol: crate::system_api::PROTOCOL.to_string(),
        request_id: "p0-2-canonical-request-not-a-runtime-id".to_string(),
        package: crate::device_launch_package_conformance::TARGET_PACKAGE.to_string(),
        user: 0,
    }
}

fn canonical_system_api_request_sha256(
    agent: crate::risk_guard::AgentIdentity,
    request: &crate::system_api::SystemApiRequest,
) -> Result<String> {
    let bytes = crate::canonical_operation::system_api_request(agent, request)?;
    Ok(lower_hex(&Sha256::digest(bytes)))
}

fn fixed_launch_package_request_sha256(provider_id: &str, agent_id: &str) -> Result<String> {
    canonical_system_api_request_sha256(
        fixed_agent_identity(provider_id, agent_id)?,
        &fixed_launch_package_request(),
    )
}

fn validate_fixed_launch_evidence<'a>(
    provider_id: &str,
    agent_id: &str,
    snapshot: &'a DirectOperationJournalEvidenceSnapshotV1,
) -> Result<&'a DirectOperationOuterEvidence> {
    snapshot
        .validate()
        .map_err(|_| hold("P0-2 launch-package evidence snapshot is invalid"))?;
    if snapshot.provider_id != provider_id || snapshot.agent_id != agent_id {
        return Err(hold(
            "P0-2 launch-package evidence does not match the trusted registry identity",
        ));
    }
    let [evidence] = snapshot.evidence.as_slice() else {
        return Err(hold(
            "P0-2 launch-package evidence is not exactly one System API effect",
        ));
    };
    let expected_request_sha256 = fixed_launch_package_request_sha256(provider_id, agent_id)?;
    if evidence.allocating_provider_attempt_id != snapshot.allocating_provider_attempt_id
        || evidence.adapter_effect_ordinal != 0
        || evidence.journal_sequence != 1
        || evidence.tool != crate::device_launch_package_conformance::TOOL_NAME
        || evidence.canonical_request_sha256 != expected_request_sha256
        || !valid_nonzero_sha256(&evidence.backend_request_id_sha256)
        || !valid_nonzero_sha256(&evidence.backend_result_sha256)
        || evidence.outcome != DirectOperationOuterOutcome::Success
        || evidence.backend_error_code.is_some()
    {
        return Err(hold(
            "P0-2 ACK evidence is not the exact successful launch_package(com.android.settings) user-0 effect",
        ));
    }
    Ok(evidence)
}

fn replay_states_from_inbox(
    inbox: &DirectOperationOuterAckInboxV3,
) -> Result<(DeviceConformanceReplayState, DeviceConformanceReplayState)> {
    inbox
        .validate()
        .map_err(|_| hold("P0-2 outer ACK is invalid while deriving replay states"))?;
    let snapshot = &inbox.acknowledgement.journal_evidence_snapshot;
    if snapshot.previous_ack_watermark != 0
        || snapshot.previous_ack_chain_sha256 != ZERO_SHA256
        || snapshot.journal_allocation_count != 1
        || snapshot.journal_evidence_count != 1
        || snapshot.first_journal_sequence != 1
        || snapshot.last_journal_sequence != 1
    {
        return Err(hold(
            "P0-2 outer ACK is not the fixed one-operation replay transition",
        ));
    }
    let before = DeviceConformanceReplayState {
        epoch: snapshot.journal_epoch.clone(),
        acknowledged_through: 0,
        next_sequence: 2,
        highest_retained_sequence: 1,
        operation_epoch_exhausted: false,
        authenticated_ack_sha256: ZERO_SHA256.to_string(),
        authenticated_ack_chain_sha256: ZERO_SHA256.to_string(),
    };
    let after = DeviceConformanceReplayState {
        epoch: snapshot.journal_epoch.clone(),
        acknowledged_through: 1,
        next_sequence: 2,
        highest_retained_sequence: 0,
        operation_epoch_exhausted: false,
        authenticated_ack_sha256: inbox.acknowledgement_sha256.clone(),
        authenticated_ack_chain_sha256: inbox.chain_step.authenticated_ack_chain_sha256.clone(),
    };
    validate_replay_state(&before)?;
    validate_replay_state(&after)?;
    Ok((before, after))
}

impl ConformanceAckIntent {
    fn derive(
        inbox: &DirectOperationOuterAckInboxV3,
        delivery_binding: &DirectOperationBinding,
        allocation_binding: &DirectOperationBinding,
        receipt: &DirectOperationOuterReceiptV3,
    ) -> Result<Self> {
        validate_p0_system_api_binding(delivery_binding)?;
        validate_p0_system_api_binding(allocation_binding)?;
        receipt
            .authorized_adapter_set
            .validate_p0_system_api()
            .map_err(|_| hold("P0-2 outer receipt adapter policy is not exactly System API"))?;
        inbox
            .validate_for_bindings_and_receipt(delivery_binding, allocation_binding, receipt)
            .map_err(|_| hold("P0-2 outer ACK does not match both bindings and outer receipt"))?;
        let acknowledgement = &inbox.acknowledgement;
        let snapshot = &acknowledgement.journal_evidence_snapshot;
        if acknowledgement.adapter != DirectOperationAdapter::SystemApi
            || snapshot.adapter != DirectOperationAdapter::SystemApi
            || snapshot.previous_ack_watermark != 0
            || snapshot.previous_ack_chain_sha256 != ZERO_SHA256
            || snapshot.journal_allocation_count != 1
            || snapshot.journal_evidence_count != 1
            || snapshot.evidence.len() != 1
            || snapshot.first_journal_sequence != 1
            || snapshot.last_journal_sequence != 1
        {
            return Err(hold(
                "P0-2 ACK is not the fixed one-operation System API conformance successor",
            ));
        }
        let evidence = validate_fixed_launch_evidence(
            &acknowledgement.provider_id,
            &acknowledgement.agent_id,
            snapshot,
        )?;
        let (before, after) = replay_states_from_inbox(inbox)?;
        Ok(Self {
            ack_intent_sha256: inbox
                .operation_replay_sync_ack_intent_sha256()
                .map_err(|_| hold("P0-2 ACK intent digest is invalid"))?,
            acknowledgement_sha256: inbox.acknowledgement_sha256.clone(),
            authenticated_ack_chain_sha256: inbox.chain_step.authenticated_ack_chain_sha256.clone(),
            before_journal_sha256: snapshot.journal_payload_sha256.clone(),
            canonical_request_sha256: evidence.canonical_request_sha256.clone(),
            backend_request_id_sha256: evidence.backend_request_id_sha256.clone(),
            backend_result_sha256: evidence.backend_result_sha256.clone(),
            before,
            after,
        })
    }

    fn classify(&self, state: &DeviceConformanceReplayState) -> Result<LocalReplayPosition> {
        if *state == self.before {
            Ok(LocalReplayPosition::BeforeAck)
        } else if *state == self.after {
            Ok(LocalReplayPosition::AfterAck)
        } else {
            Err(hold(
                "P0-2 replay state is neither exact pre-ACK nor exact post-ACK state",
            ))
        }
    }
}

/// Private journal observation.  Structural fields alone are not proof: no
/// non-test constructor exists.  A future constructor must be inside the fixed
/// journal reader and bind its retained FD plus external committed head.
#[derive(Debug, PartialEq, Eq)]
struct SealedLocalJournalProof {
    state: DeviceConformanceReplayState,
    journal_payload_sha256: String,
    journal_file_identity_sha256: String,
    committed_head_sha256: String,
    external_high_water_sha256: String,
    root_publication_identity_sha256: String,
    proof_sha256: String,
}

impl SealedLocalJournalProof {
    fn validate(&self) -> Result<()> {
        validate_replay_state(&self.state)?;
        for value in [
            &self.journal_payload_sha256,
            &self.journal_file_identity_sha256,
            &self.committed_head_sha256,
            &self.external_high_water_sha256,
            &self.root_publication_identity_sha256,
        ] {
            require_nonzero_sha256(value, "P0-2 sealed journal identity is invalid")?;
        }
        let expected = local_journal_proof_sha256(
            &self.state,
            &self.journal_payload_sha256,
            &self.journal_file_identity_sha256,
            &self.committed_head_sha256,
            &self.external_high_water_sha256,
            &self.root_publication_identity_sha256,
        );
        if self.proof_sha256 != expected {
            return Err(hold("P0-2 sealed journal observation digest changed"));
        }
        Ok(())
    }

    #[cfg(test)]
    fn for_test(material: TestLocalJournalMaterial) -> Result<Self> {
        let proof_sha256 = local_journal_proof_sha256(
            &material.state,
            &material.journal_payload_sha256,
            &material.journal_file_identity_sha256,
            &material.committed_head_sha256,
            &material.external_high_water_sha256,
            &material.root_publication_identity_sha256,
        );
        let value = Self {
            state: material.state,
            journal_payload_sha256: material.journal_payload_sha256,
            journal_file_identity_sha256: material.journal_file_identity_sha256,
            committed_head_sha256: material.committed_head_sha256,
            external_high_water_sha256: material.external_high_water_sha256,
            root_publication_identity_sha256: material.root_publication_identity_sha256,
            proof_sha256,
        };
        value.validate()?;
        Ok(value)
    }
}

struct ConformanceReplaySessionCore {
    trusted_identity: BoundConformanceLaunchIdentity,
    delivery_binding: DirectOperationBinding,
    allocation_binding: DirectOperationBinding,
    outer_receipt: DirectOperationOuterReceiptV3,
    inbox: DirectOperationOuterAckInboxV3,
    intent: ConformanceAckIntent,
}

impl ConformanceReplaySessionCore {
    fn validate(&self) -> Result<()> {
        validate_p0_system_api_binding(&self.delivery_binding)?;
        validate_p0_system_api_binding(&self.allocation_binding)?;
        self.outer_receipt
            .authorized_adapter_set
            .validate_p0_system_api()
            .map_err(|_| hold("P0-2 outer receipt adapter policy is not exactly System API"))?;
        self.inbox
            .validate_for_bindings_and_receipt(
                &self.delivery_binding,
                &self.allocation_binding,
                &self.outer_receipt,
            )
            .map_err(|_| hold("P0-2 prepared session binding/receipt validation failed"))?;
        let snapshot = &self.inbox.acknowledgement.journal_evidence_snapshot;
        let evidence = validate_fixed_launch_evidence(
            &self.trusted_identity.provider_id,
            &self.trusted_identity.agent_id,
            snapshot,
        )?;
        let expected = BoundConformanceLaunchIdentity {
            provider_id: self.delivery_binding.stable_seed.provider_id.clone(),
            agent_id: self.delivery_binding.stable_seed.agent_id.clone(),
            invocation_id: self.delivery_binding.invocation_id.clone(),
            delivery_provider_attempt_id: self
                .delivery_binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            allocating_provider_attempt_id: self
                .allocation_binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            delivery_binding_sha256: self
                .delivery_binding
                .digest_sha256()
                .map_err(|_| hold("P0-2 delivery binding digest is invalid"))?,
            allocation_binding_sha256: self
                .allocation_binding
                .digest_sha256()
                .map_err(|_| hold("P0-2 allocation binding digest is invalid"))?,
            outer_receipt_sha256: self
                .outer_receipt
                .digest_sha256()
                .map_err(|_| hold("P0-2 outer receipt digest is invalid"))?,
        };
        if self.trusted_identity != expected
            || snapshot.allocating_provider_attempt_id
                != self.trusted_identity.allocating_provider_attempt_id
            || snapshot.allocation_binding_sha256 != self.trusted_identity.allocation_binding_sha256
            || self.inbox.acknowledgement.outer_receipt_sha256
                != self.trusted_identity.outer_receipt_sha256
            || self.intent.ack_intent_sha256
                != self
                    .inbox
                    .operation_replay_sync_ack_intent_sha256()
                    .map_err(|_| hold("P0-2 prepared ACK intent changed"))?
            || self.intent.acknowledgement_sha256 != self.inbox.acknowledgement_sha256
            || self.intent.authenticated_ack_chain_sha256
                != self.inbox.chain_step.authenticated_ack_chain_sha256
            || self.intent.before_journal_sha256 != snapshot.journal_payload_sha256
            || self.intent.canonical_request_sha256 != evidence.canonical_request_sha256
            || self.intent.backend_request_id_sha256 != evidence.backend_request_id_sha256
            || self.intent.backend_result_sha256 != evidence.backend_result_sha256
        {
            return Err(hold(
                "P0-2 prepared session trusted provider/agent/invocation/attempt identity changed",
            ));
        }
        Ok(())
    }

    fn identity_sha256(&self) -> String {
        let mut hasher = domain_hasher(b"trillionnium.p0-2.prepared-session-identity.v1");
        for (name, value) in [
            (
                b"provider_id".as_slice(),
                self.trusted_identity.provider_id.as_bytes(),
            ),
            (
                b"agent_id".as_slice(),
                self.trusted_identity.agent_id.as_bytes(),
            ),
            (
                b"invocation_id".as_slice(),
                self.trusted_identity.invocation_id.as_bytes(),
            ),
            (
                b"delivery_attempt".as_slice(),
                self.trusted_identity
                    .delivery_provider_attempt_id
                    .as_bytes(),
            ),
            (
                b"allocation_attempt".as_slice(),
                self.trusted_identity
                    .allocating_provider_attempt_id
                    .as_bytes(),
            ),
            (
                b"delivery_binding".as_slice(),
                self.trusted_identity.delivery_binding_sha256.as_bytes(),
            ),
            (
                b"allocation_binding".as_slice(),
                self.trusted_identity.allocation_binding_sha256.as_bytes(),
            ),
            (
                b"outer_receipt".as_slice(),
                self.trusted_identity.outer_receipt_sha256.as_bytes(),
            ),
            (
                b"ack_intent".as_slice(),
                self.intent.ack_intent_sha256.as_bytes(),
            ),
            (
                b"canonical_request".as_slice(),
                self.intent.canonical_request_sha256.as_bytes(),
            ),
            (
                b"backend_request_id".as_slice(),
                self.intent.backend_request_id_sha256.as_bytes(),
            ),
            (
                b"backend_result".as_slice(),
                self.intent.backend_result_sha256.as_bytes(),
            ),
        ] {
            hash_field(&mut hasher, name, value);
        }
        lower_hex(&hasher.finalize())
    }
}

/// Affine transaction start.  It is intentionally neither `Clone` nor public.
/// There is no production constructor.
struct PreparedConformanceReplaySession {
    core: ConformanceReplaySessionCore,
    local: SealedLocalJournalProof,
}

impl PreparedConformanceReplaySession {
    fn validate(&self) -> Result<LocalReplayPosition> {
        self.core.validate()?;
        self.local.validate()?;
        let position = self.core.intent.classify(&self.local.state)?;
        if position == LocalReplayPosition::BeforeAck
            && self.local.journal_payload_sha256 != self.core.intent.before_journal_sha256
        {
            return Err(hold(
                "P0-2 local terminal journal differs from the authenticated outer snapshot",
            ));
        }
        Ok(position)
    }

    #[cfg(test)]
    fn prepare_for_test(
        trusted_identity: BoundConformanceLaunchIdentity,
        delivery_binding: DirectOperationBinding,
        allocation_binding: DirectOperationBinding,
        outer_receipt: DirectOperationOuterReceiptV3,
        inbox: DirectOperationOuterAckInboxV3,
        local: SealedLocalJournalProof,
    ) -> Result<Self> {
        let intent = ConformanceAckIntent::derive(
            &inbox,
            &delivery_binding,
            &allocation_binding,
            &outer_receipt,
        )?;
        let value = Self {
            core: ConformanceReplaySessionCore {
                trusted_identity,
                delivery_binding,
                allocation_binding,
                outer_receipt,
                inbox,
                intent,
            },
            local,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivateExpectation {
    PendingAckCrashWindow,
    ExactAfterAck,
}

impl ActivateExpectation {
    const fn tag(self) -> &'static [u8] {
        match self {
            Self::PendingAckCrashWindow => b"pending_ack_crash_window",
            Self::ExactAfterAck => b"exact_after_ack",
        }
    }
}

/// Opaque ACTIVATE proof.  A future non-test constructor belongs beside the
/// fixed ACTIVATE codec after exact response-frame and peer verification.
struct SealedActivateProof {
    expectation: ActivateExpectation,
    observed: DeviceConformanceReplayState,
    response_identity_sha256: String,
    proof_sha256: String,
}

impl SealedActivateProof {
    fn validate_for(&self, core: &ConformanceReplaySessionCore) -> Result<()> {
        validate_replay_state(&self.observed)?;
        require_nonzero_sha256(
            &self.response_identity_sha256,
            "P0-2 ACTIVATE response identity is invalid",
        )?;
        let expected = activate_proof_sha256(
            core,
            self.expectation,
            &self.observed,
            &self.response_identity_sha256,
        );
        if self.proof_sha256 != expected {
            return Err(hold(
                "P0-2 ACTIVATE proof does not match the prepared session",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn for_test(
        session: &PreparedConformanceReplaySession,
        expectation: ActivateExpectation,
        observed: DeviceConformanceReplayState,
        response_identity_sha256: String,
    ) -> Result<Self> {
        let proof_sha256 = activate_proof_sha256(
            &session.core,
            expectation,
            &observed,
            &response_identity_sha256,
        );
        let value = Self {
            expectation,
            observed,
            response_identity_sha256,
            proof_sha256,
        };
        value.validate_for(&session.core)?;
        Ok(value)
    }
}

struct ActivatedBeforeAckSession {
    prepared: PreparedConformanceReplaySession,
    activate: SealedActivateProof,
}

/// Opaque exact ACK echo proof.  It is not a naked digest.  A future runtime
/// producer must wrap the existing fixed-codec `VerifiedOperationReplayAck`;
/// only the test producer exists today.
struct SealedAndroidAckEchoProof {
    response_identity_sha256: String,
    proof_sha256: String,
}

impl SealedAndroidAckEchoProof {
    fn validate_for(&self, activated: &ActivatedBeforeAckSession) -> Result<()> {
        require_nonzero_sha256(
            &self.response_identity_sha256,
            "P0-2 Android ACK echo identity is invalid",
        )?;
        let expected = ack_echo_proof_sha256(
            &activated.prepared.core,
            &activated.activate.proof_sha256,
            &self.response_identity_sha256,
        );
        if self.proof_sha256 != expected {
            return Err(hold("P0-2 Android ACK echo proof changed"));
        }
        Ok(())
    }

    #[cfg(test)]
    fn for_test(
        activated: &ActivatedBeforeAckSession,
        response_identity_sha256: String,
    ) -> Result<Self> {
        let proof_sha256 = ack_echo_proof_sha256(
            &activated.prepared.core,
            &activated.activate.proof_sha256,
            &response_identity_sha256,
        );
        let value = Self {
            response_identity_sha256,
            proof_sha256,
        };
        value.validate_for(activated)?;
        Ok(value)
    }
}

struct SealedAckResponseLostProof {
    attempt_identity_sha256: String,
    proof_sha256: String,
}

impl SealedAckResponseLostProof {
    fn validate_for(&self, activated: &ActivatedBeforeAckSession) -> Result<()> {
        require_nonzero_sha256(
            &self.attempt_identity_sha256,
            "P0-2 uncertain ACK attempt identity is invalid",
        )?;
        let expected = ack_response_lost_proof_sha256(
            &activated.prepared.core,
            &activated.activate.proof_sha256,
            &self.attempt_identity_sha256,
        );
        if self.proof_sha256 != expected {
            return Err(hold("P0-2 uncertain ACK attempt proof changed"));
        }
        Ok(())
    }

    #[cfg(test)]
    fn for_test(
        activated: &ActivatedBeforeAckSession,
        attempt_identity_sha256: String,
    ) -> Result<Self> {
        let proof_sha256 = ack_response_lost_proof_sha256(
            &activated.prepared.core,
            &activated.activate.proof_sha256,
            &attempt_identity_sha256,
        );
        let value = Self {
            attempt_identity_sha256,
            proof_sha256,
        };
        value.validate_for(activated)?;
        Ok(value)
    }
}

enum AndroidAckExchange {
    Echoed(SealedAndroidAckEchoProof),
    ResponseLost(SealedAckResponseLostProof),
}

enum ResolvedAndroidAck {
    Echoed {
        activate: SealedActivateProof,
        ack: SealedAndroidAckEchoProof,
    },
    ActivateRecoveredAfterResponseLoss(SealedActivateProof),
    ActivateRecoveredAfterCompaction(SealedActivateProof),
}

impl ResolvedAndroidAck {
    fn validate_for(&self, core: &ConformanceReplaySessionCore) -> Result<()> {
        match self {
            Self::Echoed { activate, ack } => {
                activate.validate_for(core)?;
                if activate.expectation != ActivateExpectation::PendingAckCrashWindow
                    || core.intent.classify(&activate.observed)? != LocalReplayPosition::BeforeAck
                {
                    return Err(hold("P0-2 ACK echo has the wrong ACTIVATE predecessor"));
                }
                require_nonzero_sha256(
                    &ack.response_identity_sha256,
                    "P0-2 ACK echo response identity is invalid",
                )?;
                if ack.proof_sha256
                    != ack_echo_proof_sha256(
                        core,
                        &activate.proof_sha256,
                        &ack.response_identity_sha256,
                    )
                {
                    return Err(hold("P0-2 ACK echo proof is not exact"));
                }
            }
            Self::ActivateRecoveredAfterResponseLoss(proof) => {
                proof.validate_for(core)?;
                if proof.expectation != ActivateExpectation::PendingAckCrashWindow
                    || core.intent.classify(&proof.observed)? != LocalReplayPosition::AfterAck
                {
                    return Err(hold(
                        "P0-2 response-loss recovery ACTIVATE proof is not exact",
                    ));
                }
            }
            Self::ActivateRecoveredAfterCompaction(proof) => {
                proof.validate_for(core)?;
                if proof.expectation != ActivateExpectation::ExactAfterAck
                    || core.intent.classify(&proof.observed)? != LocalReplayPosition::AfterAck
                {
                    return Err(hold("P0-2 post-compaction ACTIVATE proof is not exact"));
                }
            }
        }
        Ok(())
    }

    fn proof_sha256(&self) -> &str {
        match self {
            Self::Echoed { ack, .. } => &ack.proof_sha256,
            Self::ActivateRecoveredAfterResponseLoss(proof)
            | Self::ActivateRecoveredAfterCompaction(proof) => &proof.proof_sha256,
        }
    }

    fn record(&self) -> AndroidAckResolutionRecord {
        match self {
            Self::Echoed { activate, ack } => AndroidAckResolutionRecord::Echoed {
                activation_response_identity_sha256: activate.response_identity_sha256.clone(),
                activation_proof_sha256: activate.proof_sha256.clone(),
                ack_response_identity_sha256: ack.response_identity_sha256.clone(),
                ack_proof_sha256: ack.proof_sha256.clone(),
            },
            Self::ActivateRecoveredAfterResponseLoss(proof) => {
                AndroidAckResolutionRecord::ActivateRecoveredAfterResponseLoss {
                    activation_response_identity_sha256: proof.response_identity_sha256.clone(),
                    activation_proof_sha256: proof.proof_sha256.clone(),
                }
            }
            Self::ActivateRecoveredAfterCompaction(proof) => {
                AndroidAckResolutionRecord::ActivateRecoveredAfterCompaction {
                    activation_response_identity_sha256: proof.response_identity_sha256.clone(),
                    activation_proof_sha256: proof.proof_sha256.clone(),
                }
            }
        }
    }
}

/// Sealed result of journal compaction plus exact reopen/readback and external
/// high-water/root-publication observation.
struct SealedCompactionProof {
    post: SealedLocalJournalProof,
    authorization_proof_sha256: String,
    proof_sha256: String,
}

impl SealedCompactionProof {
    fn validate_for(
        &self,
        core: &ConformanceReplaySessionCore,
        resolution: &ResolvedAndroidAck,
    ) -> Result<()> {
        resolution.validate_for(core)?;
        self.post.validate()?;
        if core.intent.classify(&self.post.state)? != LocalReplayPosition::AfterAck
            || self.authorization_proof_sha256 != resolution.proof_sha256()
            || self.proof_sha256
                != compaction_proof_sha256(
                    core,
                    &self.authorization_proof_sha256,
                    &self.post.proof_sha256,
                )
        {
            return Err(hold("P0-2 compaction proof is not the exact ACK successor"));
        }
        Ok(())
    }

    #[cfg(test)]
    fn for_test(
        session: &PreparedConformanceReplaySession,
        resolution: &ResolvedAndroidAck,
        post: SealedLocalJournalProof,
    ) -> Result<Self> {
        let authorization_proof_sha256 = resolution.proof_sha256().to_string();
        let proof_sha256 = compaction_proof_sha256(
            &session.core,
            &authorization_proof_sha256,
            &post.proof_sha256,
        );
        let value = Self {
            post,
            authorization_proof_sha256,
            proof_sha256,
        };
        value.validate_for(&session.core, resolution)?;
        Ok(value)
    }
}

struct CompactedConformanceReplaySession {
    core: ConformanceReplaySessionCore,
    resolution: ResolvedAndroidAck,
    compaction: SealedCompactionProof,
}

impl CompactedConformanceReplaySession {
    fn from_effect(
        prepared: PreparedConformanceReplaySession,
        resolution: ResolvedAndroidAck,
        compaction: SealedCompactionProof,
    ) -> Result<Self> {
        prepared.validate()?;
        resolution.validate_for(&prepared.core)?;
        compaction.validate_for(&prepared.core, &resolution)?;
        Ok(Self {
            core: prepared.core,
            resolution,
            compaction,
        })
    }

    fn adopt_existing(
        prepared: PreparedConformanceReplaySession,
        resolution: ResolvedAndroidAck,
    ) -> Result<Self> {
        if prepared.validate()? != LocalReplayPosition::AfterAck {
            return Err(hold("P0-2 cannot adopt a non-compacted local journal"));
        }
        resolution.validate_for(&prepared.core)?;
        let authorization_proof_sha256 = resolution.proof_sha256().to_string();
        let proof_sha256 = compaction_proof_sha256(
            &prepared.core,
            &authorization_proof_sha256,
            &prepared.local.proof_sha256,
        );
        let compaction = SealedCompactionProof {
            post: prepared.local,
            authorization_proof_sha256,
            proof_sha256,
        };
        compaction.validate_for(&prepared.core, &resolution)?;
        Ok(Self {
            core: prepared.core,
            resolution,
            compaction,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AndroidAckResolutionRecord {
    Echoed {
        activation_response_identity_sha256: String,
        activation_proof_sha256: String,
        ack_response_identity_sha256: String,
        ack_proof_sha256: String,
    },
    ActivateRecoveredAfterResponseLoss {
        activation_response_identity_sha256: String,
        activation_proof_sha256: String,
    },
    ActivateRecoveredAfterCompaction {
        activation_response_identity_sha256: String,
        activation_proof_sha256: String,
    },
}

impl AndroidAckResolutionRecord {
    fn validate_for(&self, core: &ConformanceReplaySessionCore) -> Result<&str> {
        match self {
            Self::Echoed {
                activation_response_identity_sha256,
                activation_proof_sha256,
                ack_response_identity_sha256,
                ack_proof_sha256,
            } => {
                let expected_activation = activate_proof_sha256(
                    core,
                    ActivateExpectation::PendingAckCrashWindow,
                    &core.intent.before,
                    activation_response_identity_sha256,
                );
                let expected_ack =
                    ack_echo_proof_sha256(core, &expected_activation, ack_response_identity_sha256);
                if activation_proof_sha256 != &expected_activation
                    || ack_proof_sha256 != &expected_ack
                {
                    return Err(hold("P0-2 echoed resolution proof is not exact"));
                }
                Ok(ack_proof_sha256)
            }
            Self::ActivateRecoveredAfterResponseLoss {
                activation_response_identity_sha256,
                activation_proof_sha256,
            } => {
                let expected = activate_proof_sha256(
                    core,
                    ActivateExpectation::PendingAckCrashWindow,
                    &core.intent.after,
                    activation_response_identity_sha256,
                );
                if activation_proof_sha256 != &expected {
                    return Err(hold("P0-2 response-loss resolution proof is not exact"));
                }
                Ok(activation_proof_sha256)
            }
            Self::ActivateRecoveredAfterCompaction {
                activation_response_identity_sha256,
                activation_proof_sha256,
            } => {
                let expected = activate_proof_sha256(
                    core,
                    ActivateExpectation::ExactAfterAck,
                    &core.intent.after,
                    activation_response_identity_sha256,
                );
                if activation_proof_sha256 != &expected {
                    return Err(hold("P0-2 post-compaction resolution proof is not exact"));
                }
                Ok(activation_proof_sha256)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceConformanceReplayConfirmationV1 {
    schema: String,
    lane: String,
    status: String,
    journal_file_name: String,
    provider_id: String,
    agent_id: String,
    invocation_id: String,
    delivery_provider_attempt_id: String,
    allocating_provider_attempt_id: String,
    delivery_binding_sha256: String,
    allocation_binding_sha256: String,
    outer_receipt_sha256: String,
    semantic_tool: String,
    semantic_action: String,
    target_package: String,
    android_user: u32,
    canonical_request_sha256: String,
    backend_request_id_sha256: String,
    backend_result_sha256: String,
    backend_outcome: DirectOperationOuterOutcome,
    journal_epoch: String,
    ack_intent_sha256: String,
    acknowledgement_sha256: String,
    authenticated_ack_chain_sha256: String,
    android_ack_resolution: AndroidAckResolutionRecord,
    compacted_ack_watermark: u64,
    post_compaction_state_sha256: String,
    post_compaction_journal_sha256: String,
    journal_file_identity_sha256: String,
    committed_head_sha256: String,
    external_high_water_sha256: String,
    root_publication_identity_sha256: String,
    compaction_proof_sha256: String,
    product_effect_authority: bool,
    product_mutation_cas_authority: bool,
    durable_device_evidence: bool,
}

impl DeviceConformanceReplayConfirmationV1 {
    fn from_compacted(session: &CompactedConformanceReplaySession) -> Result<Self> {
        session
            .compaction
            .validate_for(&session.core, &session.resolution)?;
        let identity = &session.core.trusted_identity;
        let post = &session.compaction.post;
        let value = Self {
            schema: CONFIRMATION_SCHEMA.to_string(),
            lane: LANE.to_string(),
            status: CONFIRMATION_STATUS.to_string(),
            journal_file_name: JOURNAL_FILE_NAME.to_string(),
            provider_id: identity.provider_id.clone(),
            agent_id: identity.agent_id.clone(),
            invocation_id: identity.invocation_id.clone(),
            delivery_provider_attempt_id: identity.delivery_provider_attempt_id.clone(),
            allocating_provider_attempt_id: identity.allocating_provider_attempt_id.clone(),
            delivery_binding_sha256: identity.delivery_binding_sha256.clone(),
            allocation_binding_sha256: identity.allocation_binding_sha256.clone(),
            outer_receipt_sha256: identity.outer_receipt_sha256.clone(),
            semantic_tool: crate::device_launch_package_conformance::TOOL_NAME.to_string(),
            semantic_action: crate::device_launch_package_conformance::SEMANTIC_ACTION.to_string(),
            target_package: crate::device_launch_package_conformance::TARGET_PACKAGE.to_string(),
            android_user: 0,
            canonical_request_sha256: session.core.intent.canonical_request_sha256.clone(),
            backend_request_id_sha256: session.core.intent.backend_request_id_sha256.clone(),
            backend_result_sha256: session.core.intent.backend_result_sha256.clone(),
            backend_outcome: DirectOperationOuterOutcome::Success,
            journal_epoch: post.state.epoch.clone(),
            ack_intent_sha256: session.core.intent.ack_intent_sha256.clone(),
            acknowledgement_sha256: session.core.intent.acknowledgement_sha256.clone(),
            authenticated_ack_chain_sha256: session
                .core
                .intent
                .authenticated_ack_chain_sha256
                .clone(),
            android_ack_resolution: session.resolution.record(),
            compacted_ack_watermark: post.state.acknowledged_through,
            post_compaction_state_sha256: replay_state_sha256(&post.state),
            post_compaction_journal_sha256: post.journal_payload_sha256.clone(),
            journal_file_identity_sha256: post.journal_file_identity_sha256.clone(),
            committed_head_sha256: post.committed_head_sha256.clone(),
            external_high_water_sha256: post.external_high_water_sha256.clone(),
            root_publication_identity_sha256: post.root_publication_identity_sha256.clone(),
            compaction_proof_sha256: session.compaction.proof_sha256.clone(),
            product_effect_authority: false,
            product_mutation_cas_authority: false,
            durable_device_evidence: false,
        };
        value.validate_for_core_and_post(&session.core, post)?;
        Ok(value)
    }

    fn validate_for_prepared_after(
        &self,
        session: &PreparedConformanceReplaySession,
    ) -> Result<()> {
        if session.validate()? != LocalReplayPosition::AfterAck {
            return Err(hold(
                "P0-2 confirmation requires an exact compacted local state",
            ));
        }
        self.validate_for_core_and_post(&session.core, &session.local)
    }

    fn validate_for_core_and_post(
        &self,
        core: &ConformanceReplaySessionCore,
        post: &SealedLocalJournalProof,
    ) -> Result<()> {
        core.validate()?;
        post.validate()?;
        if core.intent.classify(&post.state)? != LocalReplayPosition::AfterAck {
            return Err(hold("P0-2 confirmation post-state is not compacted"));
        }
        let resolution_proof = self.android_ack_resolution.validate_for(core)?;
        let expected_compaction =
            compaction_proof_sha256(core, resolution_proof, &post.proof_sha256);
        let identity = &core.trusted_identity;
        if self.schema != CONFIRMATION_SCHEMA
            || self.lane != LANE
            || self.status != CONFIRMATION_STATUS
            || self.journal_file_name != JOURNAL_FILE_NAME
            || self.provider_id != identity.provider_id
            || self.agent_id != identity.agent_id
            || self.invocation_id != identity.invocation_id
            || self.delivery_provider_attempt_id != identity.delivery_provider_attempt_id
            || self.allocating_provider_attempt_id != identity.allocating_provider_attempt_id
            || self.delivery_binding_sha256 != identity.delivery_binding_sha256
            || self.allocation_binding_sha256 != identity.allocation_binding_sha256
            || self.outer_receipt_sha256 != identity.outer_receipt_sha256
            || self.semantic_tool != crate::device_launch_package_conformance::TOOL_NAME
            || self.semantic_action != crate::device_launch_package_conformance::SEMANTIC_ACTION
            || self.target_package != crate::device_launch_package_conformance::TARGET_PACKAGE
            || self.android_user != 0
            || self.canonical_request_sha256 != core.intent.canonical_request_sha256
            || self.backend_request_id_sha256 != core.intent.backend_request_id_sha256
            || self.backend_result_sha256 != core.intent.backend_result_sha256
            || self.backend_outcome != DirectOperationOuterOutcome::Success
            || self.journal_epoch != post.state.epoch
            || self.ack_intent_sha256 != core.intent.ack_intent_sha256
            || self.acknowledgement_sha256 != core.intent.acknowledgement_sha256
            || self.authenticated_ack_chain_sha256 != core.intent.authenticated_ack_chain_sha256
            || self.compacted_ack_watermark != post.state.acknowledged_through
            || self.post_compaction_state_sha256 != replay_state_sha256(&post.state)
            || self.post_compaction_journal_sha256 != post.journal_payload_sha256
            || self.journal_file_identity_sha256 != post.journal_file_identity_sha256
            || self.committed_head_sha256 != post.committed_head_sha256
            || self.external_high_water_sha256 != post.external_high_water_sha256
            || self.root_publication_identity_sha256 != post.root_publication_identity_sha256
            || self.compaction_proof_sha256 != expected_compaction
            || self.product_effect_authority
            || self.product_mutation_cas_authority
            || self.durable_device_evidence
        {
            return Err(hold(
                "P0-2 held confirmation does not match exact custody and rollback identities",
            ));
        }
        Ok(())
    }

    fn canonical_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(DirectToolError::from)
    }

    fn from_canonical_json(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > crate::MAX_REQUEST_BYTES {
            return Err(hold("P0-2 confirmation byte length is invalid"));
        }
        let value: Self = serde_json::from_slice(bytes)?;
        if value.canonical_json()?.as_slice() != bytes {
            return Err(hold("P0-2 confirmation JSON is not canonical"));
        }
        Ok(value)
    }
}

/// Opaque fixed-file readback proof.  A future producer must retain the opened
/// confirmation inode through byte validation and directory durability checks.
struct SealedConfirmationReadbackProof {
    canonical_json: Vec<u8>,
    publication_identity_sha256: String,
    proof_sha256: String,
}

impl SealedConfirmationReadbackProof {
    fn validate_for(&self, core: &ConformanceReplaySessionCore) -> Result<()> {
        require_nonzero_sha256(
            &self.publication_identity_sha256,
            "P0-2 confirmation publication identity is invalid",
        )?;
        let expected = confirmation_readback_proof_sha256(
            core,
            &self.canonical_json,
            &self.publication_identity_sha256,
        );
        if self.proof_sha256 != expected {
            return Err(hold("P0-2 confirmation readback proof changed"));
        }
        Ok(())
    }

    #[cfg(test)]
    fn for_test(
        session: &PreparedConformanceReplaySession,
        canonical_json: Vec<u8>,
        publication_identity_sha256: String,
    ) -> Result<Self> {
        let proof_sha256 = confirmation_readback_proof_sha256(
            &session.core,
            &canonical_json,
            &publication_identity_sha256,
        );
        let value = Self {
            canonical_json,
            publication_identity_sha256,
            proof_sha256,
        };
        value.validate_for(&session.core)?;
        Ok(value)
    }
}

enum ReconcileOutcome {
    Confirmed(Box<DeviceConformanceReplayConfirmationV1>),
    RetryAfterAckResponseLoss,
}

/// No production implementation exists.  Each return type is opaque and has
/// only a test producer; future implementations must live beside the fixed
/// codecs/journal/root store and consume daemon-issued affine custody.
trait ConformanceReplayEffects {
    fn read_durable_confirmation(
        &mut self,
        session: &PreparedConformanceReplaySession,
    ) -> Result<Option<SealedConfirmationReadbackProof>>;

    fn activate_exact(
        &mut self,
        session: &PreparedConformanceReplaySession,
        expectation: ActivateExpectation,
    ) -> Result<SealedActivateProof>;

    fn publish_android_ack(
        &mut self,
        activated: &ActivatedBeforeAckSession,
    ) -> Result<AndroidAckExchange>;

    fn compact_local_after_android_ack(
        &mut self,
        session: &PreparedConformanceReplaySession,
        resolution: &ResolvedAndroidAck,
    ) -> Result<SealedCompactionProof>;

    fn publish_durable_confirmation(
        &mut self,
        session: &PreparedConformanceReplaySession,
        canonical_json: &[u8],
    ) -> Result<SealedConfirmationReadbackProof>;
}

enum ActivationDecision {
    Before(ActivatedBeforeAckSession),
    Resolved {
        prepared: PreparedConformanceReplaySession,
        resolution: ResolvedAndroidAck,
    },
}

fn activate_prepared<E: ConformanceReplayEffects>(
    prepared: PreparedConformanceReplaySession,
    effects: &mut E,
) -> Result<ActivationDecision> {
    let local_position = prepared.validate()?;
    let expectation = match local_position {
        LocalReplayPosition::BeforeAck => ActivateExpectation::PendingAckCrashWindow,
        LocalReplayPosition::AfterAck => ActivateExpectation::ExactAfterAck,
    };
    let proof = effects.activate_exact(&prepared, expectation)?;
    proof.validate_for(&prepared.core)?;
    if proof.expectation != expectation {
        return Err(hold("P0-2 ACTIVATE proof used the wrong expectation"));
    }
    let android_position = prepared.core.intent.classify(&proof.observed)?;
    match (local_position, android_position) {
        (LocalReplayPosition::BeforeAck, LocalReplayPosition::BeforeAck) => {
            Ok(ActivationDecision::Before(ActivatedBeforeAckSession {
                prepared,
                activate: proof,
            }))
        }
        (LocalReplayPosition::BeforeAck, LocalReplayPosition::AfterAck) => {
            Ok(ActivationDecision::Resolved {
                prepared,
                resolution: ResolvedAndroidAck::ActivateRecoveredAfterResponseLoss(proof),
            })
        }
        (LocalReplayPosition::AfterAck, LocalReplayPosition::AfterAck) => {
            Ok(ActivationDecision::Resolved {
                prepared,
                resolution: ResolvedAndroidAck::ActivateRecoveredAfterCompaction(proof),
            })
        }
        (LocalReplayPosition::AfterAck, LocalReplayPosition::BeforeAck) => Err(hold(
            "P0-2 Android replay state rolled behind the compacted local journal",
        )),
    }
}

/// Consume one prepared session through the affine transition chain.  It
/// accepts no caller-populated state, digest, inbox, binding, or receipt.
fn reconcile<E: ConformanceReplayEffects>(
    prepared: PreparedConformanceReplaySession,
    effects: &mut E,
) -> Result<ReconcileOutcome> {
    prepared.validate()?;
    if let Some(readback) = effects.read_durable_confirmation(&prepared)? {
        if prepared.validate()? != LocalReplayPosition::AfterAck {
            return Err(hold(
                "P0-2 confirmation exists while the local journal is not compacted",
            ));
        }
        // A completed file is never sufficient by itself.  Re-ACTIVATE and
        // require the exact post-ACK Android state before replaying it.
        let activate = effects.activate_exact(&prepared, ActivateExpectation::ExactAfterAck)?;
        activate.validate_for(&prepared.core)?;
        if activate.expectation != ActivateExpectation::ExactAfterAck
            || prepared.core.intent.classify(&activate.observed)? != LocalReplayPosition::AfterAck
        {
            return Err(hold(
                "P0-2 completed confirmation restart lacks exact post-ACK ACTIVATE proof",
            ));
        }
        readback.validate_for(&prepared.core)?;
        let confirmation =
            DeviceConformanceReplayConfirmationV1::from_canonical_json(&readback.canonical_json)?;
        confirmation.validate_for_prepared_after(&prepared)?;
        return Ok(ReconcileOutcome::Confirmed(Box::new(confirmation)));
    }

    let compacted = match activate_prepared(prepared, effects)? {
        ActivationDecision::Before(activated) => {
            let exchange = effects.publish_android_ack(&activated)?;
            let resolution = match exchange {
                AndroidAckExchange::Echoed(proof) => {
                    proof.validate_for(&activated)?;
                    ResolvedAndroidAck::Echoed {
                        activate: activated.activate,
                        ack: proof,
                    }
                }
                AndroidAckExchange::ResponseLost(proof) => {
                    proof.validate_for(&activated)?;
                    return Ok(ReconcileOutcome::RetryAfterAckResponseLoss);
                }
            };
            resolution.validate_for(&activated.prepared.core)?;
            let proof =
                effects.compact_local_after_android_ack(&activated.prepared, &resolution)?;
            CompactedConformanceReplaySession::from_effect(activated.prepared, resolution, proof)?
        }
        ActivationDecision::Resolved {
            prepared,
            resolution,
        } => match resolution {
            ResolvedAndroidAck::ActivateRecoveredAfterResponseLoss(_) => {
                let proof = effects.compact_local_after_android_ack(&prepared, &resolution)?;
                CompactedConformanceReplaySession::from_effect(prepared, resolution, proof)?
            }
            ResolvedAndroidAck::ActivateRecoveredAfterCompaction(_) => {
                CompactedConformanceReplaySession::adopt_existing(prepared, resolution)?
            }
            ResolvedAndroidAck::Echoed { .. } => {
                unreachable!("activation cannot synthesize ACK echo")
            }
        },
    };

    let confirmation = DeviceConformanceReplayConfirmationV1::from_compacted(&compacted)?;
    let canonical = confirmation.canonical_json()?;
    // The effects interface takes the still-complete identity via a temporary
    // prepared view only in tests; production has no implementation.
    let prepared_view = PreparedConformanceReplaySession {
        core: compacted.core,
        local: compacted.compaction.post,
    };
    let readback = effects.publish_durable_confirmation(&prepared_view, &canonical)?;
    readback.validate_for(&prepared_view.core)?;
    if readback.canonical_json != canonical {
        return Err(hold(
            "P0-2 confirmation readback differs from the published canonical bytes",
        ));
    }
    let reopened =
        DeviceConformanceReplayConfirmationV1::from_canonical_json(&readback.canonical_json)?;
    reopened.validate_for_prepared_after(&prepared_view)?;
    Ok(ReconcileOutcome::Confirmed(Box::new(reopened)))
}

fn validate_replay_state(state: &DeviceConformanceReplayState) -> Result<()> {
    if state.epoch.len() != 32
        || state.epoch == "00000000000000000000000000000000"
        || !state
            .epoch
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || state.next_sequence == 0
        || (state.highest_retained_sequence != 0
            && state.highest_retained_sequence <= state.acknowledged_through)
    {
        return Err(hold("P0-2 replay state shape is invalid"));
    }
    let ack_zero = state.authenticated_ack_sha256 == ZERO_SHA256;
    let chain_zero = state.authenticated_ack_chain_sha256 == ZERO_SHA256;
    let ack_identity_valid = if state.acknowledged_through == 0 {
        ack_zero && chain_zero
    } else {
        valid_nonzero_sha256(&state.authenticated_ack_sha256)
            && valid_nonzero_sha256(&state.authenticated_ack_chain_sha256)
    };
    if !ack_identity_valid {
        return Err(hold("P0-2 replay ACK identity is invalid"));
    }
    let highest = state
        .acknowledged_through
        .max(state.highest_retained_sequence);
    if highest == i64::MAX as u64 {
        if !state.operation_epoch_exhausted || state.next_sequence != highest {
            return Err(hold("P0-2 replay exhaustion state is invalid"));
        }
    } else if state.operation_epoch_exhausted || state.next_sequence != highest + 1 {
        return Err(hold("P0-2 replay next sequence is invalid"));
    }
    Ok(())
}

fn local_journal_proof_sha256(
    state: &DeviceConformanceReplayState,
    journal_payload_sha256: &str,
    journal_file_identity_sha256: &str,
    committed_head_sha256: &str,
    external_high_water_sha256: &str,
    root_publication_identity_sha256: &str,
) -> String {
    let mut hasher = domain_hasher(b"trillionnium.p0-2.sealed-local-journal-proof.v1");
    for (name, value) in [
        (b"state".as_slice(), replay_state_sha256(state).as_bytes()),
        (b"payload".as_slice(), journal_payload_sha256.as_bytes()),
        (
            b"file_identity".as_slice(),
            journal_file_identity_sha256.as_bytes(),
        ),
        (
            b"committed_head".as_slice(),
            committed_head_sha256.as_bytes(),
        ),
        (
            b"external_high_water".as_slice(),
            external_high_water_sha256.as_bytes(),
        ),
        (
            b"root_publication_identity".as_slice(),
            root_publication_identity_sha256.as_bytes(),
        ),
    ] {
        hash_field(&mut hasher, name, value);
    }
    lower_hex(&hasher.finalize())
}

fn activate_proof_sha256(
    core: &ConformanceReplaySessionCore,
    expectation: ActivateExpectation,
    observed: &DeviceConformanceReplayState,
    response_identity_sha256: &str,
) -> String {
    let mut hasher = domain_hasher(b"trillionnium.p0-2.sealed-activate-proof.v1");
    hash_field(&mut hasher, b"session", core.identity_sha256().as_bytes());
    hash_field(&mut hasher, b"expectation", expectation.tag());
    hash_field(
        &mut hasher,
        b"observed_state",
        replay_state_sha256(observed).as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"response_identity",
        response_identity_sha256.as_bytes(),
    );
    lower_hex(&hasher.finalize())
}

fn ack_echo_proof_sha256(
    core: &ConformanceReplaySessionCore,
    activation_proof_sha256: &str,
    response_identity_sha256: &str,
) -> String {
    let mut hasher = domain_hasher(b"trillionnium.p0-2.sealed-android-ack-echo-proof.v1");
    hash_field(&mut hasher, b"session", core.identity_sha256().as_bytes());
    hash_field(
        &mut hasher,
        b"ack_intent",
        core.intent.ack_intent_sha256.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"activation_proof",
        activation_proof_sha256.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"response_identity",
        response_identity_sha256.as_bytes(),
    );
    lower_hex(&hasher.finalize())
}

fn ack_response_lost_proof_sha256(
    core: &ConformanceReplaySessionCore,
    activation_proof_sha256: &str,
    attempt_identity_sha256: &str,
) -> String {
    let mut hasher = domain_hasher(b"trillionnium.p0-2.sealed-ack-response-lost-proof.v1");
    hash_field(&mut hasher, b"session", core.identity_sha256().as_bytes());
    hash_field(
        &mut hasher,
        b"ack_intent",
        core.intent.ack_intent_sha256.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"activation_proof",
        activation_proof_sha256.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"attempt_identity",
        attempt_identity_sha256.as_bytes(),
    );
    lower_hex(&hasher.finalize())
}

fn compaction_proof_sha256(
    core: &ConformanceReplaySessionCore,
    authorization_proof_sha256: &str,
    post_journal_proof_sha256: &str,
) -> String {
    let mut hasher = domain_hasher(b"trillionnium.p0-2.sealed-compaction-proof.v1");
    hash_field(&mut hasher, b"session", core.identity_sha256().as_bytes());
    hash_field(
        &mut hasher,
        b"authorization_proof",
        authorization_proof_sha256.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"post_journal_proof",
        post_journal_proof_sha256.as_bytes(),
    );
    lower_hex(&hasher.finalize())
}

fn confirmation_readback_proof_sha256(
    core: &ConformanceReplaySessionCore,
    canonical_json: &[u8],
    publication_identity_sha256: &str,
) -> String {
    let mut hasher = domain_hasher(b"trillionnium.p0-2.sealed-confirmation-readback-proof.v1");
    hash_field(&mut hasher, b"session", core.identity_sha256().as_bytes());
    hash_field(&mut hasher, b"canonical_json", canonical_json);
    hash_field(
        &mut hasher,
        b"publication_identity",
        publication_identity_sha256.as_bytes(),
    );
    lower_hex(&hasher.finalize())
}

fn replay_state_sha256(state: &DeviceConformanceReplayState) -> String {
    let mut hasher = domain_hasher(b"trillionnium.p0-2.device-conformance-replay-state.v1");
    hash_field(&mut hasher, b"epoch", state.epoch.as_bytes());
    hash_field(
        &mut hasher,
        b"acknowledged_through",
        &state.acknowledged_through.to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        b"next_sequence",
        &state.next_sequence.to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        b"highest_retained_sequence",
        &state.highest_retained_sequence.to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        b"operation_epoch_exhausted",
        &[u8::from(state.operation_epoch_exhausted)],
    );
    hash_field(
        &mut hasher,
        b"authenticated_ack_sha256",
        state.authenticated_ack_sha256.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"authenticated_ack_chain_sha256",
        state.authenticated_ack_chain_sha256.as_bytes(),
    );
    lower_hex(&hasher.finalize())
}

fn domain_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"domain", domain);
    hasher
}

fn hash_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn require_nonzero_sha256(value: &str, message: &'static str) -> Result<()> {
    if valid_nonzero_sha256(value) {
        Ok(())
    } else {
        Err(hold(message))
    }
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hold(message: &str) -> DirectToolError {
    DirectToolError::BackendUnavailable(message.to_string())
}

#[cfg(test)]
#[derive(Clone)]
struct TestLocalJournalMaterial {
    state: DeviceConformanceReplayState,
    journal_payload_sha256: String,
    journal_file_identity_sha256: String,
    committed_head_sha256: String,
    external_high_water_sha256: String,
    root_publication_identity_sha256: String,
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::TempDir;
    use trillionnium_os_types::direct_operation::{
        ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA, BINDING_SCHEMA,
        DirectOperationAdapterTerminalDispositionV1, DirectOperationAdapterTerminalStateV1,
        DirectOperationJournalEvidenceSnapshotV1, DirectOperationOuterAckChainStepV3,
        DirectOperationOuterAckV3, DirectOperationProviderAttempt, DirectOperationStableSeed,
        JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA, OUTER_ACK_INBOX_V3_SCHEMA, OUTER_ACK_V3_SCHEMA,
        OUTER_RECEIPT_V3_SCHEMA, STABLE_SEED_SCHEMA,
    };

    use super::*;

    const EPOCH: &str = "0123456789abcdef0123456789abcdef";
    const AFTER_JOURNAL: &str = "6666666666666666666666666666666666666666666666666666666666666666";
    const ACTIVATE_BEFORE_RESPONSE: &str =
        "7777777777777777777777777777777777777777777777777777777777777777";
    const ACTIVATE_AFTER_RESPONSE: &str =
        "8888888888888888888888888888888888888888888888888888888888888888";
    const ACK_RESPONSE: &str = "9999999999999999999999999999999999999999999999999999999999999999";
    const ACK_ATTEMPT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CONFIRMATION_PUBLICATION: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn digest(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn stable_seed(
        provider_id: &str,
        agent_id: &str,
        subject_uid: u32,
    ) -> DirectOperationStableSeed {
        DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: provider_id.to_string(),
            agent_id: agent_id.to_string(),
            task_id: "task-p0-2-replay-model".to_string(),
            provider_invocation_id_sha256: digest('1'),
            provider_session_id_sha256: digest('2'),
            subject_uid,
            subject_selinux_domain_sha256: digest('3'),
        }
    }

    fn binding(
        seed: &DirectOperationStableSeed,
        attempt: char,
        ordinal: u64,
    ) -> DirectOperationBinding {
        let value = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            stable_seed: seed.clone(),
            invocation_id: seed.invocation_id().unwrap(),
            workflow_id_sha256: digest('4'),
            agent_identity_key_sha256: digest('5'),
            agent_executable_sha256: digest('6'),
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(digest(attempt), ordinal, digest('7'))
                .unwrap(),
        };
        value.validate().unwrap();
        value
    }

    #[derive(Clone)]
    struct TestMaterial {
        delivery: DirectOperationBinding,
        allocation: DirectOperationBinding,
        receipt: DirectOperationOuterReceiptV3,
        inbox: DirectOperationOuterAckInboxV3,
        before: TestLocalJournalMaterial,
        after: TestLocalJournalMaterial,
    }

    impl TestMaterial {
        fn new() -> Self {
            Self::new_for_registry_pair(
                CODEX_STABLE_PRINCIPAL.provider_id,
                CODEX_STABLE_PRINCIPAL.agent_id,
                CODEX_STABLE_PRINCIPAL.uid,
            )
        }

        fn new_for_registry_pair(provider_id: &str, agent_id: &str, subject_uid: u32) -> Self {
            let seed = stable_seed(provider_id, agent_id, subject_uid);
            let allocation = binding(&seed, '8', 1);
            let delivery = binding(&seed, '9', 2);
            let evidence = vec![DirectOperationOuterEvidence {
                allocating_provider_attempt_id: allocation
                    .attempt
                    .delivery_provider_attempt_id
                    .clone(),
                adapter_effect_ordinal: 0,
                journal_sequence: 1,
                tool: DirectOperationAdapter::SystemApi.tool_name().to_string(),
                canonical_request_sha256: fixed_launch_package_request_sha256(
                    &allocation.stable_seed.provider_id,
                    &allocation.stable_seed.agent_id,
                )
                .unwrap(),
                backend_request_id_sha256: digest('b'),
                backend_result_sha256: digest('c'),
                outcome: DirectOperationOuterOutcome::Success,
                backend_error_code: None,
            }];
            let mut snapshot = DirectOperationJournalEvidenceSnapshotV1 {
                schema: JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA.to_string(),
                allocation_binding_sha256: allocation.digest_sha256().unwrap(),
                invocation_id: allocation.invocation_id.clone(),
                provider_id: allocation.stable_seed.provider_id.clone(),
                agent_id: allocation.stable_seed.agent_id.clone(),
                allocating_provider_attempt_id: allocation
                    .attempt
                    .delivery_provider_attempt_id
                    .clone(),
                adapter: DirectOperationAdapter::SystemApi,
                journal_epoch: EPOCH.to_string(),
                journal_payload_sha256: digest('d'),
                previous_ack_watermark: 0,
                previous_ack_chain_sha256: ZERO_SHA256.to_string(),
                journal_allocation_count: 1,
                journal_evidence_count: 1,
                first_journal_sequence: 1,
                last_journal_sequence: 1,
                evidence,
                evidence_sha256: String::new(),
            };
            snapshot.evidence_sha256 = snapshot.evidence_digest_sha256().unwrap();
            snapshot.validate().unwrap();
            let system = DirectOperationAdapterTerminalDispositionV1 {
                schema: ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA.to_string(),
                binding_sha256: delivery.digest_sha256().unwrap(),
                invocation_id: delivery.invocation_id.clone(),
                delivery_provider_attempt_id: delivery.attempt.delivery_provider_attempt_id.clone(),
                provider_id: delivery.stable_seed.provider_id.clone(),
                agent_id: delivery.stable_seed.agent_id.clone(),
                adapter: DirectOperationAdapter::SystemApi,
                terminal_state: DirectOperationAdapterTerminalStateV1::Ackable {
                    journal_evidence_snapshot: snapshot.clone(),
                },
            };
            let mut receipt = DirectOperationOuterReceiptV3 {
                schema: OUTER_RECEIPT_V3_SCHEMA.to_string(),
                binding_sha256: delivery.digest_sha256().unwrap(),
                invocation_id: delivery.invocation_id.clone(),
                delivery_provider_attempt_id: delivery.attempt.delivery_provider_attempt_id.clone(),
                provider_id: delivery.stable_seed.provider_id.clone(),
                agent_id: delivery.stable_seed.agent_id.clone(),
                direct_execution_receipt_sha256: digest('1'),
                ui_replay_completion_proof_sha256: digest('2'),
                ui_replay_semantic_sha256: digest('3'),
                terminal_egress_cas_sha256: digest('4'),
                runtime_evidence_sha256: digest('5'),
                provider_teardown_completion_ack_sha256: digest('6'),
                authorized_adapter_set: delivery.authorized_adapter_set.clone(),
                adapter_terminal_dispositions: vec![system],
                adapter_terminal_dispositions_sha256: String::new(),
            };
            receipt.adapter_terminal_dispositions_sha256 =
                receipt.adapter_dispositions_digest_sha256().unwrap();
            receipt.validate().unwrap();
            let acknowledgement = DirectOperationOuterAckV3 {
                schema: OUTER_ACK_V3_SCHEMA.to_string(),
                binding_sha256: delivery.digest_sha256().unwrap(),
                invocation_id: delivery.invocation_id.clone(),
                delivery_provider_attempt_id: delivery.attempt.delivery_provider_attempt_id.clone(),
                provider_id: delivery.stable_seed.provider_id.clone(),
                agent_id: delivery.stable_seed.agent_id.clone(),
                adapter: DirectOperationAdapter::SystemApi,
                authorized_adapter_set_sha256: delivery
                    .authorized_adapter_set
                    .digest_sha256()
                    .unwrap(),
                outer_receipt_sha256: receipt.digest_sha256().unwrap(),
                journal_evidence_snapshot: snapshot.clone(),
                journal_evidence_snapshot_sha256: snapshot.digest_sha256().unwrap(),
            };
            acknowledgement.validate().unwrap();
            let acknowledgement_sha256 = acknowledgement.digest_sha256().unwrap();
            let chain_step = DirectOperationOuterAckChainStepV3::derive(
                DirectOperationAdapter::SystemApi,
                EPOCH.to_string(),
                0,
                1,
                acknowledgement_sha256.clone(),
                ZERO_SHA256.to_string(),
            )
            .unwrap();
            let inbox = DirectOperationOuterAckInboxV3 {
                schema: OUTER_ACK_INBOX_V3_SCHEMA.to_string(),
                acknowledgement,
                acknowledgement_sha256,
                chain_step_sha256: chain_step.digest_sha256().unwrap(),
                chain_step,
            };
            inbox
                .validate_for_bindings_and_receipt(&delivery, &allocation, &receipt)
                .unwrap();
            let intent =
                ConformanceAckIntent::derive(&inbox, &delivery, &allocation, &receipt).unwrap();
            let before = TestLocalJournalMaterial {
                state: intent.before,
                journal_payload_sha256: snapshot.journal_payload_sha256,
                journal_file_identity_sha256: digest('1'),
                committed_head_sha256: digest('2'),
                external_high_water_sha256: digest('3'),
                root_publication_identity_sha256: digest('4'),
            };
            let after = TestLocalJournalMaterial {
                state: intent.after,
                journal_payload_sha256: AFTER_JOURNAL.to_string(),
                journal_file_identity_sha256: digest('5'),
                committed_head_sha256: digest('6'),
                external_high_water_sha256: digest('7'),
                root_publication_identity_sha256: digest('8'),
            };
            Self {
                delivery,
                allocation,
                receipt,
                inbox,
                before,
                after,
            }
        }

        fn trusted_identity(&self) -> BoundConformanceLaunchIdentity {
            BoundConformanceLaunchIdentity {
                provider_id: self.delivery.stable_seed.provider_id.clone(),
                agent_id: self.delivery.stable_seed.agent_id.clone(),
                invocation_id: self.delivery.invocation_id.clone(),
                delivery_provider_attempt_id: self
                    .delivery
                    .attempt
                    .delivery_provider_attempt_id
                    .clone(),
                allocating_provider_attempt_id: self
                    .allocation
                    .attempt
                    .delivery_provider_attempt_id
                    .clone(),
                delivery_binding_sha256: self.delivery.digest_sha256().unwrap(),
                allocation_binding_sha256: self.allocation.digest_sha256().unwrap(),
                outer_receipt_sha256: self.receipt.digest_sha256().unwrap(),
            }
        }

        fn prepare(
            &self,
            local: &TestLocalJournalMaterial,
        ) -> Result<PreparedConformanceReplaySession> {
            PreparedConformanceReplaySession::prepare_for_test(
                self.trusted_identity(),
                self.delivery.clone(),
                self.allocation.clone(),
                self.receipt.clone(),
                self.inbox.clone(),
                SealedLocalJournalProof::for_test(local.clone())?,
            )
        }
    }

    #[derive(Clone, Copy)]
    enum NextAck {
        Echoed,
        LostApplied,
        LostNotApplied,
    }

    struct FakeEffects {
        material: TestMaterial,
        directory: TempDir,
        local: TestLocalJournalMaterial,
        android: DeviceConformanceReplayState,
        next_ack: NextAck,
        fail_next_confirmation_publish: bool,
        ack_intents: Vec<String>,
        events: Vec<&'static str>,
    }

    impl FakeEffects {
        fn new() -> Self {
            let material = TestMaterial::new();
            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                local: material.before.clone(),
                android: material.before.state.clone(),
                material,
                directory,
                next_ack: NextAck::Echoed,
                fail_next_confirmation_publish: false,
                ack_intents: Vec::new(),
                events: Vec::new(),
            }
        }

        fn prepare(&self) -> Result<PreparedConformanceReplaySession> {
            self.material.prepare(&self.local)
        }

        fn confirmation_path(&self) -> std::path::PathBuf {
            self.directory.path().join(CONFIRMATION_FILE_NAME)
        }

        fn write_confirmation_bytes(&self, bytes: &[u8]) {
            fs::write(self.confirmation_path(), bytes).unwrap();
            OpenOptions::new()
                .read(true)
                .open(self.directory.path())
                .unwrap()
                .sync_all()
                .unwrap();
        }

        fn clear_events(&mut self) {
            self.events.clear();
        }
    }

    impl ConformanceReplayEffects for FakeEffects {
        fn read_durable_confirmation(
            &mut self,
            session: &PreparedConformanceReplaySession,
        ) -> Result<Option<SealedConfirmationReadbackProof>> {
            self.events.push("read_confirmation");
            let bytes = match fs::read(self.confirmation_path()) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            Ok(Some(SealedConfirmationReadbackProof::for_test(
                session,
                bytes,
                CONFIRMATION_PUBLICATION.to_string(),
            )?))
        }

        fn activate_exact(
            &mut self,
            session: &PreparedConformanceReplaySession,
            expectation: ActivateExpectation,
        ) -> Result<SealedActivateProof> {
            self.events.push("activate");
            let response_identity = if self.android == session.core.intent.before {
                ACTIVATE_BEFORE_RESPONSE
            } else {
                ACTIVATE_AFTER_RESPONSE
            };
            SealedActivateProof::for_test(
                session,
                expectation,
                self.android.clone(),
                response_identity.to_string(),
            )
        }

        fn publish_android_ack(
            &mut self,
            activated: &ActivatedBeforeAckSession,
        ) -> Result<AndroidAckExchange> {
            self.events.push("android_ack");
            self.ack_intents
                .push(activated.prepared.core.intent.ack_intent_sha256.clone());
            match std::mem::replace(&mut self.next_ack, NextAck::Echoed) {
                NextAck::Echoed => {
                    self.android = activated.prepared.core.intent.after.clone();
                    Ok(AndroidAckExchange::Echoed(
                        SealedAndroidAckEchoProof::for_test(activated, ACK_RESPONSE.to_string())?,
                    ))
                }
                NextAck::LostApplied => {
                    self.android = activated.prepared.core.intent.after.clone();
                    Ok(AndroidAckExchange::ResponseLost(
                        SealedAckResponseLostProof::for_test(activated, ACK_ATTEMPT.to_string())?,
                    ))
                }
                NextAck::LostNotApplied => Ok(AndroidAckExchange::ResponseLost(
                    SealedAckResponseLostProof::for_test(activated, ACK_ATTEMPT.to_string())?,
                )),
            }
        }

        fn compact_local_after_android_ack(
            &mut self,
            session: &PreparedConformanceReplaySession,
            resolution: &ResolvedAndroidAck,
        ) -> Result<SealedCompactionProof> {
            self.events.push("compact");
            self.local = self.material.after.clone();
            SealedCompactionProof::for_test(
                session,
                resolution,
                SealedLocalJournalProof::for_test(self.local.clone())?,
            )
        }

        fn publish_durable_confirmation(
            &mut self,
            session: &PreparedConformanceReplaySession,
            canonical_json: &[u8],
        ) -> Result<SealedConfirmationReadbackProof> {
            self.events.push("publish_confirmation");
            if std::mem::take(&mut self.fail_next_confirmation_publish) {
                return Err(hold("injected confirmation publication crash"));
            }
            let temporary = self.directory.path().join("confirmation.pending");
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(canonical_json)?;
            file.sync_all()?;
            fs::rename(&temporary, self.confirmation_path())?;
            OpenOptions::new()
                .read(true)
                .open(self.directory.path())?
                .sync_all()?;
            self.events.push("confirmation_readback");
            let bytes = fs::read(self.confirmation_path())?;
            SealedConfirmationReadbackProof::for_test(
                session,
                bytes,
                CONFIRMATION_PUBLICATION.to_string(),
            )
        }
    }

    fn run(effects: &mut FakeEffects) -> Result<ReconcileOutcome> {
        let prepared = effects.prepare()?;
        reconcile(prepared, effects)
    }

    #[test]
    fn fresh_ack_uses_sealed_proofs_before_compaction_and_readback() {
        let mut effects = FakeEffects::new();
        let ReconcileOutcome::Confirmed(confirmation) = run(&mut effects).unwrap() else {
            panic!("expected confirmation");
        };
        assert_eq!(effects.local.state, effects.material.after.state);
        assert_eq!(effects.ack_intents.len(), 1);
        assert!(matches!(
            confirmation.android_ack_resolution,
            AndroidAckResolutionRecord::Echoed { .. }
        ));
        assert_eq!(
            effects.events,
            [
                "read_confirmation",
                "activate",
                "android_ack",
                "compact",
                "publish_confirmation",
                "confirmation_readback",
            ]
        );
    }

    #[test]
    fn response_loss_applied_recovers_by_activate_without_second_ack() {
        let mut effects = FakeEffects::new();
        effects.next_ack = NextAck::LostApplied;
        assert!(matches!(
            run(&mut effects).unwrap(),
            ReconcileOutcome::RetryAfterAckResponseLoss
        ));
        assert_eq!(effects.local.state, effects.material.before.state);
        assert_eq!(effects.android, effects.material.after.state);
        effects.clear_events();
        let ReconcileOutcome::Confirmed(confirmation) = run(&mut effects).unwrap() else {
            panic!("restart did not confirm");
        };
        assert_eq!(effects.ack_intents.len(), 1);
        assert!(matches!(
            confirmation.android_ack_resolution,
            AndroidAckResolutionRecord::ActivateRecoveredAfterResponseLoss { .. }
        ));
        assert_eq!(
            effects.events,
            [
                "read_confirmation",
                "activate",
                "compact",
                "publish_confirmation",
                "confirmation_readback",
            ]
        );
    }

    #[test]
    fn response_loss_not_applied_retries_only_the_same_ack_intent() {
        let mut effects = FakeEffects::new();
        effects.next_ack = NextAck::LostNotApplied;
        assert!(matches!(
            run(&mut effects).unwrap(),
            ReconcileOutcome::RetryAfterAckResponseLoss
        ));
        assert_eq!(effects.android, effects.material.before.state);
        let exact = effects.ack_intents[0].clone();
        effects.clear_events();
        assert!(matches!(
            run(&mut effects).unwrap(),
            ReconcileOutcome::Confirmed(_)
        ));
        assert_eq!(effects.ack_intents, [exact.clone(), exact]);
        assert_eq!(
            effects.events,
            [
                "read_confirmation",
                "activate",
                "android_ack",
                "compact",
                "publish_confirmation",
                "confirmation_readback",
            ]
        );
    }

    #[test]
    fn compacted_crash_reconfirms_but_completed_fast_path_reactivates() {
        let mut effects = FakeEffects::new();
        effects.fail_next_confirmation_publish = true;
        assert!(run(&mut effects).is_err());
        assert_eq!(effects.local.state, effects.material.after.state);
        assert_eq!(effects.ack_intents.len(), 1);
        effects.clear_events();
        let first = run(&mut effects).unwrap();
        assert_eq!(effects.ack_intents.len(), 1);
        effects.clear_events();
        let replay = run(&mut effects).unwrap();
        assert!(
            matches!((&first, &replay), (ReconcileOutcome::Confirmed(a), ReconcileOutcome::Confirmed(b)) if a == b)
        );
        assert_eq!(effects.events, ["read_confirmation", "activate"]);
    }

    #[test]
    fn third_android_state_and_local_after_android_before_hold() {
        let mut third = FakeEffects::new();
        third.android.epoch = "11111111111111111111111111111111".to_string();
        assert!(run(&mut third).is_err());
        assert_eq!(third.events, ["read_confirmation", "activate"]);

        let mut rollback = FakeEffects::new();
        rollback.local = rollback.material.after.clone();
        rollback.android = rollback.material.before.state.clone();
        assert!(run(&mut rollback).is_err());
        assert_eq!(rollback.events, ["read_confirmation", "activate"]);
    }

    #[test]
    fn prepared_session_rejects_wrong_trusted_identity_binding_and_receipt() {
        let material = TestMaterial::new();
        let local = SealedLocalJournalProof::for_test(material.before.clone()).unwrap();
        let mut identity = material.trusted_identity();
        identity.provider_id = "unregistered-provider".to_string();
        assert!(
            PreparedConformanceReplaySession::prepare_for_test(
                identity,
                material.delivery.clone(),
                material.allocation.clone(),
                material.receipt.clone(),
                material.inbox.clone(),
                local,
            )
            .is_err()
        );

        for field in [
            "agent",
            "invocation",
            "delivery_attempt",
            "allocation_attempt",
            "receipt",
        ] {
            let mut identity = material.trusted_identity();
            match field {
                "agent" => identity.agent_id = "unregistered-agent".to_string(),
                "invocation" => identity.invocation_id = format!("inv:{}", digest('f')),
                "delivery_attempt" => {
                    identity.delivery_provider_attempt_id = format!("attempt:{}", digest('e'))
                }
                "allocation_attempt" => {
                    identity.allocating_provider_attempt_id = format!("attempt:{}", digest('d'))
                }
                "receipt" => identity.outer_receipt_sha256 = digest('c'),
                _ => unreachable!(),
            }
            assert!(
                PreparedConformanceReplaySession::prepare_for_test(
                    identity,
                    material.delivery.clone(),
                    material.allocation.clone(),
                    material.receipt.clone(),
                    material.inbox.clone(),
                    SealedLocalJournalProof::for_test(material.before.clone()).unwrap(),
                )
                .is_err()
            );
        }

        assert!(
            PreparedConformanceReplaySession::prepare_for_test(
                material.trusted_identity(),
                material.delivery.clone(),
                material.delivery.clone(),
                material.receipt.clone(),
                material.inbox.clone(),
                SealedLocalJournalProof::for_test(material.before.clone()).unwrap(),
            )
            .is_err()
        );

        let mut wrong_receipt = material.receipt.clone();
        wrong_receipt.runtime_evidence_sha256 = digest('f');
        assert!(wrong_receipt.validate().is_ok());
        assert!(
            PreparedConformanceReplaySession::prepare_for_test(
                material.trusted_identity(),
                material.delivery.clone(),
                material.allocation.clone(),
                wrong_receipt,
                material.inbox.clone(),
                SealedLocalJournalProof::for_test(material.before).unwrap(),
            )
            .is_err()
        );
    }

    fn canonical_request_sha256_for_test(request: &crate::system_api::SystemApiRequest) -> String {
        canonical_system_api_request_sha256(crate::risk_guard::AgentIdentity::Codex, request)
            .unwrap()
    }

    fn assert_request_identity_rejected(request_sha256: String) {
        let material = TestMaterial::new();
        let mut snapshot = material
            .inbox
            .acknowledgement
            .journal_evidence_snapshot
            .clone();
        snapshot.evidence[0].canonical_request_sha256 = request_sha256;
        snapshot.evidence_sha256 = snapshot.evidence_digest_sha256().unwrap();
        assert!(snapshot.validate().is_ok());
        assert!(
            validate_fixed_launch_evidence(
                CODEX_STABLE_PRINCIPAL.provider_id,
                CODEX_STABLE_PRINCIPAL.agent_id,
                &snapshot,
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_ack_evidence_rejects_wrong_package_user_action_request_and_outcome() {
        assert_request_identity_rejected(canonical_request_sha256_for_test(
            &crate::system_api::SystemApiRequest::LaunchPackage {
                protocol: crate::system_api::PROTOCOL.to_string(),
                request_id: "ignored-for-canonical-identity".to_string(),
                package: "com.android.contacts".to_string(),
                user: 0,
            },
        ));
        assert_request_identity_rejected(canonical_request_sha256_for_test(
            &crate::system_api::SystemApiRequest::LaunchPackage {
                protocol: crate::system_api::PROTOCOL.to_string(),
                request_id: "ignored-for-canonical-identity".to_string(),
                package: crate::device_launch_package_conformance::TARGET_PACKAGE.to_string(),
                user: 10,
            },
        ));
        assert_request_identity_rejected(canonical_request_sha256_for_test(
            &crate::system_api::SystemApiRequest::OpenUri {
                protocol: crate::system_api::PROTOCOL.to_string(),
                request_id: "ignored-for-canonical-identity".to_string(),
                uri: "package:com.android.settings".to_string(),
                user: 0,
            },
        ));
        assert_request_identity_rejected(digest('a'));

        let material = TestMaterial::new();
        let mut snapshot = material
            .inbox
            .acknowledgement
            .journal_evidence_snapshot
            .clone();
        snapshot.evidence[0].outcome = DirectOperationOuterOutcome::BackendError;
        snapshot.evidence[0].backend_error_code = Some("backend_rejected".to_string());
        snapshot.evidence_sha256 = snapshot.evidence_digest_sha256().unwrap();
        assert!(snapshot.validate().is_ok());
        assert!(
            validate_fixed_launch_evidence(
                CODEX_STABLE_PRINCIPAL.provider_id,
                CODEX_STABLE_PRINCIPAL.agent_id,
                &snapshot,
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_ack_evidence_accepts_only_the_stable_registry_pair() {
        assert_eq!(
            fixed_agent_identity(
                CODEX_STABLE_PRINCIPAL.provider_id,
                CODEX_STABLE_PRINCIPAL.agent_id,
            )
            .unwrap(),
            crate::risk_guard::AgentIdentity::Codex
        );
        for principal in [&CODEX_STABLE_PRINCIPAL] {
            let material = TestMaterial::new_for_registry_pair(
                principal.provider_id,
                principal.agent_id,
                principal.uid,
            );
            assert!(material.prepare(&material.before).is_ok());
        }
        for (provider, agent) in [
            (CODEX_STABLE_PRINCIPAL.provider_id, "unregistered-agent"),
            ("unregistered-provider", CODEX_STABLE_PRINCIPAL.agent_id),
            ("openai-unknown", CODEX_STABLE_PRINCIPAL.agent_id),
            (CODEX_STABLE_PRINCIPAL.provider_id, "agent-unknown"),
        ] {
            assert!(fixed_agent_identity(provider, agent).is_err());
        }
    }

    fn completed_effects() -> FakeEffects {
        let mut effects = FakeEffects::new();
        assert!(matches!(
            run(&mut effects).unwrap(),
            ReconcileOutcome::Confirmed(_)
        ));
        effects.clear_events();
        effects
    }

    #[test]
    fn corrupt_old_epoch_and_wrong_resolution_confirmations_hold_after_activate() {
        let mut corrupt = completed_effects();
        corrupt.write_confirmation_bytes(b"not-json");
        assert!(run(&mut corrupt).is_err());
        assert_eq!(corrupt.events, ["read_confirmation", "activate"]);

        let mut old_epoch = completed_effects();
        let bytes = fs::read(old_epoch.confirmation_path()).unwrap();
        let mut confirmation =
            DeviceConformanceReplayConfirmationV1::from_canonical_json(&bytes).unwrap();
        confirmation.journal_epoch = "11111111111111111111111111111111".to_string();
        old_epoch.write_confirmation_bytes(&confirmation.canonical_json().unwrap());
        assert!(run(&mut old_epoch).is_err());
        assert_eq!(old_epoch.events, ["read_confirmation", "activate"]);

        let mut wrong_resolution = completed_effects();
        let bytes = fs::read(wrong_resolution.confirmation_path()).unwrap();
        let mut confirmation =
            DeviceConformanceReplayConfirmationV1::from_canonical_json(&bytes).unwrap();
        if let AndroidAckResolutionRecord::Echoed {
            activation_response_identity_sha256,
            activation_proof_sha256,
            ..
        } = confirmation.android_ack_resolution
        {
            confirmation.android_ack_resolution =
                AndroidAckResolutionRecord::ActivateRecoveredAfterResponseLoss {
                    activation_response_identity_sha256,
                    activation_proof_sha256,
                };
        } else {
            panic!("expected echoed fixture");
        }
        wrong_resolution.write_confirmation_bytes(&confirmation.canonical_json().unwrap());
        assert!(run(&mut wrong_resolution).is_err());
        assert_eq!(wrong_resolution.events, ["read_confirmation", "activate"]);
    }

    #[test]
    fn rollback_file_head_high_water_and_root_publication_identities_hold() {
        for field in ["file", "head", "high_water", "root_publication"] {
            let mut effects = completed_effects();
            let bytes = fs::read(effects.confirmation_path()).unwrap();
            let mut confirmation =
                DeviceConformanceReplayConfirmationV1::from_canonical_json(&bytes).unwrap();
            match field {
                "file" => confirmation.journal_file_identity_sha256 = digest('1'),
                "head" => confirmation.committed_head_sha256 = digest('2'),
                "high_water" => confirmation.external_high_water_sha256 = digest('3'),
                "root_publication" => confirmation.root_publication_identity_sha256 = digest('4'),
                _ => unreachable!(),
            }
            effects.write_confirmation_bytes(&confirmation.canonical_json().unwrap());
            assert!(run(&mut effects).is_err(), "rollback field {field} passed");
            assert_eq!(effects.events, ["read_confirmation", "activate"]);
        }
    }

    #[test]
    fn public_entry_requires_measured_fd_sealed_authority_before_p0_success_path() {
        assert_eq!(
            SOURCE_STATUS,
            "p0_userdebug_sealed_authority_activate_ack_compact_v4"
        );

        let source = include_str!("device_launch_package_conformance_replay_sync.rs");
        for wired_gate in [
            "const CONFORMANCE_FIXED_FD_INTAKE_WIRED: bool = true;",
            "const CONFORMANCE_TRUSTED_CONTEXT_INTAKE_WIRED: bool = true;",
            "const CONFORMANCE_LOCAL_JOURNAL_OBSERVATION_WIRED: bool = true;",
        ] {
            assert!(source.contains(wired_gate));
        }
        assert!(source.contains("const P0_USERDEBUG_DAEMON_SEALED_AUTHORITY_WIRED: bool = true;"));
        for held_gate in [
            "const PRODUCT_EXTERNAL_ROLLBACK_AUTHORITY_WIRED: bool = false;",
            "const PRODUCT_ROOT_PUBLICATION_AUTHORITY_WIRED: bool = false;",
            "const PRODUCT_EFFECT_AUTHORITY_WIRED: bool = false;",
            "const PRODUCT_MUTATION_CAS_AUTHORITY_WIRED: bool = false;",
        ] {
            assert!(source.contains(held_gate));
        }
        let entry = source
            .split_once("pub fn run_system_api_replay_sync()")
            .unwrap()
            .1
            .split_once("fn require_compiled_non_product_build_variant")
            .unwrap()
            .0;
        let variant = entry
            .find("require_compiled_non_product_build_variant")
            .unwrap();
        let intake = entry.find("ValidatedRuntimeIntake::open").unwrap();
        let sealed = entry.find("validate_sealed_replay_authority").unwrap();
        let completion = entry.find("complete_runtime_replay").unwrap();
        assert!(variant < intake && intake < sealed && sealed < completion);

        let intake_body = source
            .split_once("impl ValidatedRuntimeIntake")
            .unwrap()
            .1
            .split_once("fn validate_runtime_local_ack")
            .unwrap()
            .0;
        let fixed_fd = intake_body.find("FixedOneShotTransport::open").unwrap();
        let p0_lane = intake_body.find("validate_p0_daemon_custody_lane").unwrap();
        let context = intake_body
            .find("open_current_device_conformance_system_api")
            .unwrap();
        let inbox = intake_body
            .find("pending_outer_ack_v3_for_device_conformance")
            .unwrap();
        let journal = intake_body
            .find("open_device_conformance_operation_journal")
            .unwrap();
        let observation = intake_body
            .find("device_conformance_journal_observation")
            .unwrap();
        let local_validation = intake_body.find("validate_runtime_local_ack").unwrap();
        let sealed_from_fd = intake_body.find("p0_sealed_authority").unwrap();
        let independent_inbox_digest = intake_body
            .find("context.binding_inbox_bytes_sha256")
            .unwrap();
        assert!(
            fixed_fd < p0_lane
                && p0_lane < context
                && context < inbox
                && sealed_from_fd < independent_inbox_digest
                && inbox < journal
                && journal < observation
                && observation < local_validation
        );
        assert!(!intake_body.contains("open_from_command"));
        assert!(!intake_body.contains("open_from_bytes"));

        let authority_body = source
            .split_once("fn validate_sealed_replay_authority(")
            .unwrap()
            .1
            .split_once("fn complete_runtime_replay(")
            .unwrap()
            .0;
        for retained_revalidation in [
            "device_conformance_journal_observation",
            "validate_runtime_local_ack",
            "current_local != intake.local_journal",
            "current_position != intake.local_position",
        ] {
            assert!(authority_body.contains(retained_revalidation));
        }
        assert!(!authority_body.contains("activate_system_api_for_device_conformance"));

        let completion_body = source
            .split_once("fn complete_runtime_replay(")
            .unwrap()
            .1
            .split_once("#[derive(Debug, PartialEq, Eq)]")
            .unwrap()
            .0;
        for required in [
            "activate_system_api_for_device_conformance",
            "acknowledge_system_api_for_device_conformance",
            "recover_system_api_ack_for_device_conformance",
            "apply_device_conformance_outer_ack_and_observe",
            "DirectOperationP0ReplaySyncAckConfirmationV1",
            "write_response",
        ] {
            assert!(completion_body.contains(required));
        }
        assert!(!completion_body.contains("mutation_cas_committed_head_sha256"));
        assert!(completion_body.contains("daemon_custody_committed_head_sha256"));

        let binary = include_str!("bin/system_api_device_conformance_replay_sync.rs");
        let measured_stop = binary.find("enter_measured_parent_stop").unwrap();
        let runtime = binary.find("run_system_api_replay_sync").unwrap();
        assert!(measured_stop < runtime);

        let tests_marker = source.find("#[cfg(test)]\nmod tests").unwrap();
        let before_tests = &source[..tests_marker];
        assert!(!before_tests.contains("impl ConformanceReplayEffects for"));
        assert!(!before_tests.contains("pub fn reconcile<"));
        assert!(!before_tests.contains("pub(crate) fn reconcile<"));
        assert!(before_tests.contains("fn reconcile<E: ConformanceReplayEffects>"));
        let test_impl = ["impl ConformanceReplayEffects", " for FakeEffects"].concat();
        assert_eq!(source.matches(&test_impl).count(), 1);
        assert!(source.find(&test_impl).unwrap() > tests_marker);
        assert_eq!(before_tests.matches("fn prepare_for_test").count(), 1);
        assert!(before_tests.contains("#[cfg(test)]\n    fn prepare_for_test("));
        assert!(before_tests.contains("validate_for_bindings_and_receipt"));
        assert!(before_tests.contains("struct PreparedConformanceReplaySession"));
    }

    #[test]
    fn compile_time_variant_gate_accepts_only_userdebug() {
        assert_eq!(
            require_compiled_non_product_build_variant(Some("userdebug")).unwrap(),
            "userdebug"
        );
        for rejected in [None, Some("user"), Some("eng"), Some("recovery"), Some("")] {
            assert!(require_compiled_non_product_build_variant(rejected).is_err());
        }
    }

    #[test]
    fn p0_replay_sync_independently_rejects_the_reserved_dual_adapter_profile() {
        let seed = stable_seed(
            CODEX_STABLE_PRINCIPAL.provider_id,
            CODEX_STABLE_PRINCIPAL.agent_id,
            CODEX_STABLE_PRINCIPAL.uid,
        );
        let mut candidate = binding(&seed, '8', 1);
        candidate.authorized_adapter_set = trillionnium_os_types::direct_operation::
            DirectOperationAuthorizedAdapterSetV3::future_system_api_and_accessibility();
        assert!(
            candidate
                .authorized_adapter_set
                .authorizes(DirectOperationAdapter::SystemApi)
        );
        assert!(validate_p0_system_api_binding(&candidate).is_err());
    }

    #[test]
    fn journal_filename_matches_existing_conformance_open_path() {
        let trusted_context = include_str!("trusted_context.rs");
        assert!(trusted_context.contains(&format!(
            "const DEVICE_CONFORMANCE_JOURNAL_FILE_NAME: &str = \"{JOURNAL_FILE_NAME}\";"
        )));
        assert_ne!(JOURNAL_FILE_NAME, "operations.json");
    }
}
