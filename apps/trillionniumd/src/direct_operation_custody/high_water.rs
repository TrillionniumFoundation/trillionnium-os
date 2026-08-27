//! Durable rollback-resistant high-water for daemon Direct-operation custody.
//!
//! Product use has one compile-time-fixed root-owned store, one separate
//! root-owned client transaction journal, and one distinct fixed Unix socket.
//! The socket inode, root peer credentials, and exact SELinux domain are
//! authenticated. No path, generation, digest, record, or boolean supplied by
//! a caller can construct a verified capability.
//!
//! Every authority operation is two-phase on the wire. Before an operation is
//! sent, an immutable intent is fsynced below `active/<operation-id>/`. The
//! authority must durably apply and record the exact response with
//! `response_confirmed=false` before sending it. The client validates and
//! fsyncs a response receipt, then sends a digest-bound `ConfirmResponse`.
//! Only an exact authority confirmation ACK lets the client atomically move
//! the entire operation directory, no-replace, from `active` to `resolved`.
//! Nothing is retired by unlinking.
//!
//! On restart an intent without a response is retried with the exact stable
//! operation ID. An authority that had already applied it must durably HOLD;
//! an authority that never saw it may process it once. A durable response
//! receipt can safely re-confirm an exact pending/already-resolved authority
//! operation. Corruption, rollback, ambiguous live errors, or inexact state
//! publishes a local permanent-HOLD marker. Thus response loss cannot be
//! converted into fresh authority merely because local and external heads
//! happen to compare equal.
//!
//! The high-level order remains `reconcile -> observe -> prepare -> local
//! durable commit -> authority commit -> reconcile`. This module creates no
//! publisher, launcher, Android, provider, or effect authority, and product
//! `main` has no call site.

use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trillionnium_os_types::direct_operation_custody_high_water::{
    DirectOperationCustodyHead, DirectOperationCustodyHighWaterClientFrameV1,
    DirectOperationCustodyHighWaterDisposition, DirectOperationCustodyHighWaterOperation,
    DirectOperationCustodyHighWaterRequestV1,
    DirectOperationCustodyHighWaterResponseConfirmationAckV1,
    DirectOperationCustodyHighWaterResponseConfirmationV1,
    DirectOperationCustodyHighWaterResponseV1, DirectOperationCustodyHighWaterRouteV1,
    DirectOperationCustodyHighWaterServerFrameV1, transition_sha256,
};

use super::{
    FileIdentity, SecureParent, open_directory, open_existing_secure_parent_path,
    openat_create_new, read_named_file, secure_open_parent, set_exact_mode,
};

pub(super) const FIXED_PRODUCT_CUSTODY_STORE_PATH: &str =
    "/var/lib/trillionnium/direct-operation-custody/custody-v1.json";
pub(super) const FIXED_CLIENT_JOURNAL_ROOT: &str =
    "/var/lib/trillionnium/direct-operation-custody/high-water-client-v2";
pub(super) const FIXED_AUTHORITY_SOCKET_PATH: &str =
    "/run/trillionnium/direct-operation-custody-high-water-v2.sock";
const FIXED_AUTHORITY_UID: u32 = 0;
const FIXED_AUTHORITY_GID: u32 = 0;
const FIXED_AUTHORITY_SOCKET_MODE: u32 = 0o600;
const FIXED_AUTHORITY_SELINUX_DOMAIN: &str =
    "u:r:trillionnium_direct_operation_custody_high_water:s0";
const FIXED_AUTHORITY_IDENTITY_SHA256: &str =
    "1b6a5712e17d79f896a915ba02b5b44a743db3700fb753e8f14f7f625b7e4a40";
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_JOURNAL_RECORD_BYTES: usize = 256 * 1024;
const MAX_RESOLVED_OPERATIONS: usize = 4096;
const CALL_TIMEOUT: Duration = Duration::from_secs(5);
const ACTIVE_DIRECTORY_NAME: &CStr = c"active";
const RESOLVED_DIRECTORY_NAME: &CStr = c"resolved";
const INTENT_FILE_NAME: &CStr = c"intent-v2.json";
const RESPONSE_FILE_NAME: &CStr = c"response-v2.json";
const CONFIRMATION_ACK_FILE_NAME: &CStr = c"confirmation-ack-v2.json";
const INTENT_SCHEMA: &str = "trillionnium.direct-operation-custody-client-intent.v2";
const RESPONSE_RECEIPT_SCHEMA: &str =
    "trillionnium.direct-operation-custody-client-response-receipt.v2";
const CONFIRMATION_ACK_RECEIPT_SCHEMA: &str =
    "trillionnium.direct-operation-custody-client-confirmation-ack-receipt.v2";
const PERMANENT_HOLD_SCHEMA: &str =
    "trillionnium.direct-operation-custody-client-permanent-hold.v2";
const INTENT_DOMAIN: &[u8] = b"trillionnium.direct-operation-custody-client-intent.v2";
const RESPONSE_RECEIPT_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-custody-client-response-receipt.v2";
const CONFIRMATION_ACK_RECEIPT_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-custody-client-confirmation-ack-receipt.v2";
const PERMANENT_HOLD_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-custody-client-permanent-hold.v2";

pub(super) fn product_route() -> Result<DirectOperationCustodyHighWaterRouteV1> {
    DirectOperationCustodyHighWaterRouteV1::derive(
        sha256_bytes(FIXED_PRODUCT_CUSTODY_STORE_PATH.as_bytes()),
        sha256_bytes(FIXED_CLIENT_JOURNAL_ROOT.as_bytes()),
        sha256_bytes(FIXED_AUTHORITY_SOCKET_PATH.as_bytes()),
        sha256_bytes(FIXED_AUTHORITY_SELINUX_DOMAIN.as_bytes()),
    )
    .map_err(|error| anyhow!(error))
}

trait AuthorityTransport: Send {
    /// Return only after the exact operation response has itself been durably
    /// receipted and explicitly confirmed by the authority.
    fn exchange(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
    ) -> Result<DirectOperationCustodyHighWaterResponseV1>;
}

trait WireTransport: Send {
    fn operation(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
    ) -> Result<DirectOperationCustodyHighWaterResponseV1>;

    fn confirm_response(
        &mut self,
        confirmation: &DirectOperationCustodyHighWaterResponseConfirmationV1,
    ) -> Result<DirectOperationCustodyHighWaterResponseConfirmationAckV1>;
}

#[must_use = "verified custody high-water must be consumed by the store"]
pub(super) struct VerifiedDirectOperationCustodyHighWater {
    transport: Box<dyn AuthorityTransport>,
    route: DirectOperationCustodyHighWaterRouteV1,
    committed_head: DirectOperationCustodyHead,
}

#[must_use = "prepared custody high-water must be resolved exactly"]
pub(super) struct PreparedDirectOperationCustodyHighWater {
    transport: Box<dyn AuthorityTransport>,
    route: DirectOperationCustodyHighWaterRouteV1,
    from_head: DirectOperationCustodyHead,
    to_head: DirectOperationCustodyHead,
    transition_sha256: String,
}

#[must_use = "committed custody high-water must be reconciled before reuse"]
pub(super) struct CommittedDirectOperationCustodyHighWater {
    transport: Box<dyn AuthorityTransport>,
    route: DirectOperationCustodyHighWaterRouteV1,
    committed_head: DirectOperationCustodyHead,
}

impl VerifiedDirectOperationCustodyHighWater {
    pub(super) fn connect_product(local_head: DirectOperationCustodyHead) -> Result<Self> {
        let transport = DurableAuthorityTransport::connect_product()?;
        establish(Box::new(transport), product_route()?, local_head)
    }

    pub(super) fn route(&self) -> &DirectOperationCustodyHighWaterRouteV1 {
        &self.route
    }

    pub(super) fn committed_head(&self) -> &DirectOperationCustodyHead {
        &self.committed_head
    }

    /// Re-observe the external authority immediately before deriving a local
    /// capability that can cross an effect boundary.  Comparing the cached
    /// head alone is not freshness evidence.
    pub(super) fn observe_fresh_exact(
        &mut self,
        local_head: &DirectOperationCustodyHead,
    ) -> Result<()> {
        if local_head != &self.committed_head {
            bail!("direct_operation_custody_high_water_fresh_observe_local_drift_denied");
        }
        let observed = request_exact(
            self.transport.as_mut(),
            DirectOperationCustodyHighWaterOperation::Observe,
            &self.route,
            local_head,
            None,
            None,
        )?;
        if observed.committed_head != *local_head {
            bail!("direct_operation_custody_high_water_fresh_observe_external_drift_denied");
        }
        Ok(())
    }

    pub(super) fn prepare(
        mut self,
        to_head: DirectOperationCustodyHead,
    ) -> Result<PreparedDirectOperationCustodyHighWater> {
        to_head.validate().map_err(|error| anyhow!(error))?;
        let observed = request_exact(
            self.transport.as_mut(),
            DirectOperationCustodyHighWaterOperation::Observe,
            &self.route,
            &self.committed_head,
            None,
            None,
        )?;
        if observed.committed_head != self.committed_head {
            bail!("direct_operation_custody_high_water_observe_drift_denied");
        }
        let expected_generation = self
            .committed_head
            .generation
            .checked_add(1)
            .context("direct_operation_custody_high_water_generation_overflow")?;
        if to_head.generation != expected_generation {
            bail!("direct_operation_custody_high_water_successor_generation_denied");
        }
        let transition = transition_sha256(&self.route, &self.committed_head, &to_head);
        request_exact(
            self.transport.as_mut(),
            DirectOperationCustodyHighWaterOperation::Prepare,
            &self.route,
            &self.committed_head,
            Some(to_head.clone()),
            Some(transition.clone()),
        )?;
        Ok(PreparedDirectOperationCustodyHighWater {
            transport: self.transport,
            route: self.route,
            from_head: self.committed_head,
            to_head,
            transition_sha256: transition,
        })
    }
}

impl PreparedDirectOperationCustodyHighWater {
    pub(super) fn commit(
        mut self,
        durable_local_head: &DirectOperationCustodyHead,
    ) -> Result<CommittedDirectOperationCustodyHighWater> {
        if durable_local_head != &self.to_head {
            bail!("direct_operation_custody_high_water_local_durability_mismatch");
        }
        request_exact(
            self.transport.as_mut(),
            DirectOperationCustodyHighWaterOperation::Commit,
            &self.route,
            &self.to_head,
            Some(self.to_head.clone()),
            Some(self.transition_sha256.clone()),
        )?;
        Ok(CommittedDirectOperationCustodyHighWater {
            transport: self.transport,
            route: self.route,
            committed_head: self.to_head,
        })
    }

    pub(super) fn reconcile_known_local(
        self,
        local_head: DirectOperationCustodyHead,
    ) -> Result<VerifiedDirectOperationCustodyHighWater> {
        if local_head != self.from_head && local_head != self.to_head {
            bail!("direct_operation_custody_high_water_reconcile_local_fork_denied");
        }
        establish(self.transport, self.route, local_head)
    }
}

impl CommittedDirectOperationCustodyHighWater {
    pub(super) fn reconcile(
        self,
        local_head: &DirectOperationCustodyHead,
    ) -> Result<VerifiedDirectOperationCustodyHighWater> {
        if local_head != &self.committed_head {
            bail!("direct_operation_custody_high_water_post_commit_local_drift_denied");
        }
        establish(self.transport, self.route, local_head.clone())
    }
}

fn establish(
    mut transport: Box<dyn AuthorityTransport>,
    route: DirectOperationCustodyHighWaterRouteV1,
    local_head: DirectOperationCustodyHead,
) -> Result<VerifiedDirectOperationCustodyHighWater> {
    route.validate().map_err(|error| anyhow!(error))?;
    local_head.validate().map_err(|error| anyhow!(error))?;
    request_exact(
        transport.as_mut(),
        DirectOperationCustodyHighWaterOperation::Reconcile,
        &route,
        &local_head,
        None,
        None,
    )?;
    request_exact(
        transport.as_mut(),
        DirectOperationCustodyHighWaterOperation::Observe,
        &route,
        &local_head,
        None,
        None,
    )?;
    Ok(VerifiedDirectOperationCustodyHighWater {
        transport,
        route,
        committed_head: local_head,
    })
}

fn request_exact(
    transport: &mut dyn AuthorityTransport,
    operation: DirectOperationCustodyHighWaterOperation,
    route: &DirectOperationCustodyHighWaterRouteV1,
    current_head: &DirectOperationCustodyHead,
    proposed_head: Option<DirectOperationCustodyHead>,
    transition_sha256: Option<String>,
) -> Result<DirectOperationCustodyHighWaterResponseV1> {
    let request = DirectOperationCustodyHighWaterRequestV1::build(
        operation,
        route.clone(),
        current_head.clone(),
        proposed_head,
        transition_sha256,
        fresh_nonce_sha256()?,
    )
    .map_err(|error| anyhow!(error))?;
    let response = transport
        .exchange(&request)
        .context("direct_operation_custody_high_water_authority_outcome_unknown_permanent_hold")?;
    response
        .validate_binding_for(&request, FIXED_AUTHORITY_IDENTITY_SHA256)
        .map_err(|error| anyhow!(error))?;
    response.require_success().map_err(|error| anyhow!(error))?;
    Ok(response)
}

struct DurableAuthorityTransport<W: WireTransport> {
    wire: W,
    journal: ClientAttemptJournal,
}

#[derive(Debug)]
struct ExactConfirmationRetryRequired;

impl fmt::Display for ExactConfirmationRetryRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("direct_operation_custody_high_water_exact_confirmation_retry_required")
    }
}

impl std::error::Error for ExactConfirmationRetryRequired {}

fn is_exact_confirmation_retry_required(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ExactConfirmationRetryRequired>()
        .is_some()
}

impl DurableAuthorityTransport<FixedPathWireTransport> {
    fn connect_product() -> Result<Self> {
        let journal =
            ClientAttemptJournal::open(Path::new(FIXED_CLIENT_JOURNAL_ROOT), FIXED_AUTHORITY_UID)?;
        let wire = FixedPathWireTransport::connect()?;
        let mut transport = Self { wire, journal };
        transport.recover_active()?;
        Ok(transport)
    }
}

impl<W: WireTransport> DurableAuthorityTransport<W> {
    #[cfg(test)]
    fn connect_for_test(wire: W, journal_path: &Path, owner_uid: u32) -> Result<Self> {
        let journal = ClientAttemptJournal::open(journal_path, owner_uid)?;
        let mut transport = Self { wire, journal };
        transport.recover_active()?;
        Ok(transport)
    }

    #[cfg(test)]
    fn connect_for_test_with_capacity(
        wire: W,
        journal_path: &Path,
        owner_uid: u32,
        resolved_capacity: usize,
    ) -> Result<Self> {
        let journal =
            ClientAttemptJournal::open_with_capacity(journal_path, owner_uid, resolved_capacity)?;
        let mut transport = Self { wire, journal };
        transport.recover_active()?;
        Ok(transport)
    }

    fn recover_active(&mut self) -> Result<()> {
        self.journal.require_not_held()?;
        let active = match self.journal.load_active() {
            Ok(active) => active,
            Err(error) => {
                self.journal.mark_permanent_hold(
                    None,
                    &format!("startup_active_journal_damage:{error:#}"),
                )?;
                return Err(error).context(
                    "direct_operation_custody_high_water_active_journal_damage_permanent_hold",
                );
            }
        };
        let Some(active) = active else {
            return Ok(());
        };
        if active.confirmation_ack_receipt.is_some() {
            if let Err(error) = self
                .journal
                .resolve(&active.intent.request.operation_id_sha256)
            {
                self.journal.mark_permanent_hold(
                    Some(&active.intent.request.operation_id_sha256),
                    &format!("startup_confirmed_retirement_unknown:{error:#}"),
                )?;
                return Err(error).context(
                    "direct_operation_custody_high_water_confirmed_retirement_permanent_hold",
                );
            }
            return Ok(());
        }
        let result = if let Some(receipt) = active.response_receipt.as_ref() {
            self.confirm_receipted_response(&active.intent.request, receipt)
                .map(|_| ())
        } else {
            self.complete_started_operation(&active.intent.request)
                .map(|_| ())
        };
        if let Err(error) = result {
            if is_exact_confirmation_retry_required(&error) {
                return Err(error).context(
                    "direct_operation_custody_high_water_exact_confirmation_reconnect_required",
                );
            }
            self.journal.mark_permanent_hold(
                Some(&active.intent.request.operation_id_sha256),
                &format!("startup_recovery:{error:#}"),
            )?;
            return Err(error).context(
                "direct_operation_custody_high_water_active_attempt_recovery_permanent_hold",
            );
        }
        Ok(())
    }

    fn complete_started_operation(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
    ) -> Result<DirectOperationCustodyHighWaterResponseV1> {
        let response = self.wire.operation(request)?;
        response
            .validate_binding_for(request, FIXED_AUTHORITY_IDENTITY_SHA256)
            .map_err(|error| anyhow!(error))?;
        if response.disposition == DirectOperationCustodyHighWaterDisposition::PermanentHold {
            self.journal.mark_permanent_hold(
                Some(&request.operation_id_sha256),
                "authority_returned_permanent_hold",
            )?;
            bail!("direct_operation_custody_high_water_authority_permanent_hold");
        }
        let receipt = self.journal.persist_response(request, &response)?;
        self.confirm_receipted_response(request, &receipt)?;
        Ok(response)
    }

    fn confirm_receipted_response(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
        receipt: &ClientResponseReceiptV2,
    ) -> Result<DirectOperationCustodyHighWaterResponseConfirmationAckV1> {
        receipt.validate_for(request)?;
        let confirmation = DirectOperationCustodyHighWaterResponseConfirmationV1::derive(
            request,
            &receipt.response,
            receipt.receipt_sha256.clone(),
        )
        .map_err(|error| anyhow!(error))?;
        let acknowledgement = self.wire.confirm_response(&confirmation).map_err(|error| {
            // Once the exact response receipt is durable, resending this exact
            // confirmation is idempotent against either pending or resolved
            // authority state.  A transport I/O outcome is therefore a retry
            // boundary, not a reason to mint a generic local permanent HOLD.
            if error
                .chain()
                .any(|cause| cause.downcast_ref::<std::io::Error>().is_some())
            {
                anyhow!(ExactConfirmationRetryRequired).context(error)
            } else {
                error
            }
        })?;
        acknowledgement
            .validate_for(&confirmation, FIXED_AUTHORITY_IDENTITY_SHA256)
            .map_err(|error| anyhow!(error))?;
        self.journal
            .persist_confirmation_ack(request, receipt, &confirmation, &acknowledgement)?;
        self.journal.resolve(&request.operation_id_sha256)?;
        Ok(acknowledgement)
    }

    /// Test-only abrupt-process-death boundary. Unlike `exchange`, this does
    /// not translate a transport error into a live-process HOLD: the caller
    /// must immediately drop the transport, exactly as a killed process would.
    #[cfg(test)]
    fn crash_test_after_operation_without_response_receipt(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
    ) -> Result<()> {
        request.validate().map_err(|error| anyhow!(error))?;
        self.journal.begin(request)?;
        let _ = self.wire.operation(request)?;
        Ok(())
    }

    /// Test-only abrupt-process-death boundary after the response receipt is
    /// durable but before the confirmation is sent.
    #[cfg(test)]
    fn crash_test_after_response_receipt(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
    ) -> Result<()> {
        request.validate().map_err(|error| anyhow!(error))?;
        self.journal.begin(request)?;
        let response = self.wire.operation(request)?;
        response
            .validate_binding_for(request, FIXED_AUTHORITY_IDENTITY_SHA256)
            .map_err(|error| anyhow!(error))?;
        self.journal.persist_response(request, &response)?;
        Ok(())
    }

    /// Test-only abrupt-process-death boundary after the authority has
    /// durably resolved an exact confirmation but before the client records
    /// the confirmation acknowledgement.
    #[cfg(test)]
    fn crash_test_after_confirmation_ack_without_receipt(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
    ) -> Result<()> {
        request.validate().map_err(|error| anyhow!(error))?;
        self.journal.begin(request)?;
        let response = self.wire.operation(request)?;
        response
            .validate_binding_for(request, FIXED_AUTHORITY_IDENTITY_SHA256)
            .map_err(|error| anyhow!(error))?;
        let receipt = self.journal.persist_response(request, &response)?;
        let confirmation = DirectOperationCustodyHighWaterResponseConfirmationV1::derive(
            request,
            &response,
            receipt.receipt_sha256.clone(),
        )
        .map_err(|error| anyhow!(error))?;
        let _ = self.wire.confirm_response(&confirmation)?;
        Ok(())
    }
}

impl<W: WireTransport> AuthorityTransport for DurableAuthorityTransport<W> {
    fn exchange(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
    ) -> Result<DirectOperationCustodyHighWaterResponseV1> {
        request.validate().map_err(|error| anyhow!(error))?;
        self.journal.require_not_held()?;
        self.journal.begin(request)?;
        let result = self.complete_started_operation(request);
        if let Err(error) = &result
            && !is_exact_confirmation_retry_required(error)
        {
            self.journal.mark_permanent_hold(
                Some(&request.operation_id_sha256),
                &format!("live_exchange:{error:#}"),
            )?;
        }
        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClientAttemptIntentV2 {
    schema: String,
    operation_id_sha256: String,
    request: DirectOperationCustodyHighWaterRequestV1,
    request_bytes_sha256: String,
    intent_sha256: String,
}

impl ClientAttemptIntentV2 {
    fn derive(request: &DirectOperationCustodyHighWaterRequestV1) -> Result<Self> {
        request.validate().map_err(|error| anyhow!(error))?;
        let mut intent = Self {
            schema: INTENT_SCHEMA.to_string(),
            operation_id_sha256: request.operation_id_sha256.clone(),
            request: request.clone(),
            request_bytes_sha256: sha256_bytes(&serde_json::to_vec(request)?),
            intent_sha256: String::new(),
        };
        intent.intent_sha256 = intent.expected_sha256()?;
        intent.validate()?;
        Ok(intent)
    }

    fn validate(&self) -> Result<()> {
        self.request.validate().map_err(|error| anyhow!(error))?;
        if self.schema != INTENT_SCHEMA
            || self.operation_id_sha256 != self.request.operation_id_sha256
            || self.request_bytes_sha256 != sha256_bytes(&serde_json::to_vec(&self.request)?)
            || self.intent_sha256 != self.expected_sha256()?
        {
            bail!("direct_operation_custody_client_intent_denied");
        }
        Ok(())
    }

    fn expected_sha256(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            operation_id_sha256: &'a str,
            request: &'a DirectOperationCustodyHighWaterRequestV1,
            request_bytes_sha256: &'a str,
        }
        domain_digest(
            INTENT_DOMAIN,
            &Preimage {
                schema: &self.schema,
                operation_id_sha256: &self.operation_id_sha256,
                request: &self.request,
                request_bytes_sha256: &self.request_bytes_sha256,
            },
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClientResponseReceiptV2 {
    schema: String,
    operation_id_sha256: String,
    request_sha256: String,
    response: DirectOperationCustodyHighWaterResponseV1,
    response_bytes_sha256: String,
    receipt_sha256: String,
}

impl ClientResponseReceiptV2 {
    fn derive(
        request: &DirectOperationCustodyHighWaterRequestV1,
        response: &DirectOperationCustodyHighWaterResponseV1,
    ) -> Result<Self> {
        response
            .validate_binding_for(request, FIXED_AUTHORITY_IDENTITY_SHA256)
            .map_err(|error| anyhow!(error))?;
        response.require_success().map_err(|error| anyhow!(error))?;
        let mut receipt = Self {
            schema: RESPONSE_RECEIPT_SCHEMA.to_string(),
            operation_id_sha256: request.operation_id_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            response: response.clone(),
            response_bytes_sha256: sha256_bytes(&serde_json::to_vec(response)?),
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt.expected_sha256()?;
        receipt.validate_for(request)?;
        Ok(receipt)
    }

    fn validate_for(&self, request: &DirectOperationCustodyHighWaterRequestV1) -> Result<()> {
        self.response
            .validate_binding_for(request, FIXED_AUTHORITY_IDENTITY_SHA256)
            .map_err(|error| anyhow!(error))?;
        self.response
            .require_success()
            .map_err(|error| anyhow!(error))?;
        if self.schema != RESPONSE_RECEIPT_SCHEMA
            || self.operation_id_sha256 != request.operation_id_sha256
            || self.request_sha256 != request.request_sha256
            || self.response_bytes_sha256 != sha256_bytes(&serde_json::to_vec(&self.response)?)
            || self.receipt_sha256 != self.expected_sha256()?
        {
            bail!("direct_operation_custody_client_response_receipt_denied");
        }
        Ok(())
    }

    fn expected_sha256(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            operation_id_sha256: &'a str,
            request_sha256: &'a str,
            response: &'a DirectOperationCustodyHighWaterResponseV1,
            response_bytes_sha256: &'a str,
        }
        domain_digest(
            RESPONSE_RECEIPT_DOMAIN,
            &Preimage {
                schema: &self.schema,
                operation_id_sha256: &self.operation_id_sha256,
                request_sha256: &self.request_sha256,
                response: &self.response,
                response_bytes_sha256: &self.response_bytes_sha256,
            },
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClientConfirmationAckReceiptV2 {
    schema: String,
    operation_id_sha256: String,
    request_sha256: String,
    response_receipt_sha256: String,
    confirmation: DirectOperationCustodyHighWaterResponseConfirmationV1,
    acknowledgement: DirectOperationCustodyHighWaterResponseConfirmationAckV1,
    acknowledgement_bytes_sha256: String,
    receipt_sha256: String,
}

impl ClientConfirmationAckReceiptV2 {
    fn derive(
        request: &DirectOperationCustodyHighWaterRequestV1,
        response_receipt: &ClientResponseReceiptV2,
        confirmation: &DirectOperationCustodyHighWaterResponseConfirmationV1,
        acknowledgement: &DirectOperationCustodyHighWaterResponseConfirmationAckV1,
    ) -> Result<Self> {
        response_receipt.validate_for(request)?;
        acknowledgement
            .validate_for(confirmation, FIXED_AUTHORITY_IDENTITY_SHA256)
            .map_err(|error| anyhow!(error))?;
        let mut receipt = Self {
            schema: CONFIRMATION_ACK_RECEIPT_SCHEMA.to_string(),
            operation_id_sha256: request.operation_id_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            response_receipt_sha256: response_receipt.receipt_sha256.clone(),
            confirmation: confirmation.clone(),
            acknowledgement: acknowledgement.clone(),
            acknowledgement_bytes_sha256: sha256_bytes(&serde_json::to_vec(acknowledgement)?),
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt.expected_sha256()?;
        receipt.validate_for(request, response_receipt)?;
        Ok(receipt)
    }

    fn validate_for(
        &self,
        request: &DirectOperationCustodyHighWaterRequestV1,
        response_receipt: &ClientResponseReceiptV2,
    ) -> Result<()> {
        response_receipt.validate_for(request)?;
        self.confirmation
            .validate()
            .map_err(|error| anyhow!(error))?;
        self.acknowledgement
            .validate_for(&self.confirmation, FIXED_AUTHORITY_IDENTITY_SHA256)
            .map_err(|error| anyhow!(error))?;
        if self.schema != CONFIRMATION_ACK_RECEIPT_SCHEMA
            || self.operation_id_sha256 != request.operation_id_sha256
            || self.request_sha256 != request.request_sha256
            || self.response_receipt_sha256 != response_receipt.receipt_sha256
            || self.confirmation.client_response_receipt_sha256 != response_receipt.receipt_sha256
            || self.confirmation.response_sha256 != response_receipt.response.response_sha256
            || self.acknowledgement_bytes_sha256
                != sha256_bytes(&serde_json::to_vec(&self.acknowledgement)?)
            || self.receipt_sha256 != self.expected_sha256()?
        {
            bail!("direct_operation_custody_client_confirmation_ack_receipt_denied");
        }
        Ok(())
    }

    fn expected_sha256(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            operation_id_sha256: &'a str,
            request_sha256: &'a str,
            response_receipt_sha256: &'a str,
            confirmation: &'a DirectOperationCustodyHighWaterResponseConfirmationV1,
            acknowledgement: &'a DirectOperationCustodyHighWaterResponseConfirmationAckV1,
            acknowledgement_bytes_sha256: &'a str,
        }
        domain_digest(
            CONFIRMATION_ACK_RECEIPT_DOMAIN,
            &Preimage {
                schema: &self.schema,
                operation_id_sha256: &self.operation_id_sha256,
                request_sha256: &self.request_sha256,
                response_receipt_sha256: &self.response_receipt_sha256,
                confirmation: &self.confirmation,
                acknowledgement: &self.acknowledgement,
                acknowledgement_bytes_sha256: &self.acknowledgement_bytes_sha256,
            },
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClientPermanentHoldV2 {
    schema: String,
    journal_root_path_sha256: String,
    journal_root_identity_sha256: String,
    operation_id_sha256: Option<String>,
    reason_sha256: String,
    hold_sha256: String,
}

impl ClientPermanentHoldV2 {
    fn derive(
        journal_root_path_sha256: String,
        journal_root_identity_sha256: String,
        operation_id_sha256: Option<&str>,
        reason: &str,
    ) -> Result<Self> {
        if operation_id_sha256.is_some_and(|value| !valid_nonzero_sha256(value)) {
            bail!("direct_operation_custody_client_hold_operation_id_denied");
        }
        let mut hold = Self {
            schema: PERMANENT_HOLD_SCHEMA.to_string(),
            journal_root_path_sha256,
            journal_root_identity_sha256,
            operation_id_sha256: operation_id_sha256.map(str::to_string),
            reason_sha256: sha256_bytes(reason.as_bytes()),
            hold_sha256: String::new(),
        };
        hold.hold_sha256 = hold.expected_sha256()?;
        hold.validate()?;
        Ok(hold)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != PERMANENT_HOLD_SCHEMA
            || !valid_nonzero_sha256(&self.journal_root_path_sha256)
            || !valid_nonzero_sha256(&self.journal_root_identity_sha256)
            || self
                .operation_id_sha256
                .as_deref()
                .is_some_and(|value| !valid_nonzero_sha256(value))
            || !valid_nonzero_sha256(&self.reason_sha256)
            || self.hold_sha256 != self.expected_sha256()?
        {
            bail!("direct_operation_custody_client_permanent_hold_record_denied");
        }
        Ok(())
    }

    fn expected_sha256(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            journal_root_path_sha256: &'a str,
            journal_root_identity_sha256: &'a str,
            operation_id_sha256: &'a Option<String>,
            reason_sha256: &'a str,
        }
        domain_digest(
            PERMANENT_HOLD_DOMAIN,
            &Preimage {
                schema: &self.schema,
                journal_root_path_sha256: &self.journal_root_path_sha256,
                journal_root_identity_sha256: &self.journal_root_identity_sha256,
                operation_id_sha256: &self.operation_id_sha256,
                reason_sha256: &self.reason_sha256,
            },
        )
    }
}

struct ActiveClientAttempt {
    intent: ClientAttemptIntentV2,
    response_receipt: Option<ClientResponseReceiptV2>,
    confirmation_ack_receipt: Option<ClientConfirmationAckReceiptV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct JournalFileIdentity {
    mount_id: u64,
    file: FileIdentity,
}

impl JournalFileIdentity {
    fn from_file(file: &File) -> Result<Self> {
        let mut statx = std::mem::MaybeUninit::<libc::statx>::zeroed();
        let result = unsafe {
            libc::statx(
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
                statx.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("direct_operation_custody_client_journal_statx_failed");
        }
        let statx = unsafe { statx.assume_init() };
        if statx.stx_mask & libc::STATX_MNT_ID == 0 {
            bail!("direct_operation_custody_client_journal_mount_identity_unavailable");
        }
        Ok(Self {
            mount_id: statx.stx_mnt_id,
            file: FileIdentity::from_metadata(&file.metadata()?),
        })
    }

    fn digest_sha256(&self) -> Result<String> {
        domain_digest(
            b"trillionnium.direct-operation-custody-client-journal-inode.v2",
            self,
        )
    }

    fn same_directory_custody(&self, other: &Self) -> bool {
        self.mount_id == other.mount_id
            && self.file.dev == other.file.dev
            && self.file.ino == other.file.ino
            && self.file.uid == other.file.uid
            && self.file.gid == other.file.gid
            && self.file.mode == other.file.mode
    }
}

struct RetainedActiveOperation {
    operation_id_sha256: String,
    directory: File,
    identity: JournalFileIdentity,
}

struct ClientAttemptJournal {
    root_parent: SecureParent,
    root_name: CString,
    external_hold_name: CString,
    root: File,
    root_identity: JournalFileIdentity,
    active: File,
    active_identity: JournalFileIdentity,
    resolved: File,
    resolved_identity: JournalFileIdentity,
    retained_active_operation: Option<RetainedActiveOperation>,
    owner_uid: u32,
    root_path: PathBuf,
    resolved_capacity: usize,
    #[cfg(test)]
    hold_pre_return_barrier: Option<Box<dyn Fn() + Send + Sync>>,
}

fn revalidate_journal_root_parent(parent: &SecureParent, owner_uid: u32) -> Result<()> {
    let metadata = parent.directory.metadata()?;
    let current = FileIdentity::from_metadata(&metadata);
    if !current.same_directory_custody(&parent.identity)
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.nlink() == 0
    {
        bail!("direct_operation_custody_client_journal_parent_identity_changed");
    }
    let named = open_existing_secure_parent_path(&parent.path, owner_uid)?;
    if !FileIdentity::from_metadata(&named.metadata()?).same_directory_custody(&parent.identity) {
        bail!("direct_operation_custody_client_journal_parent_path_rebound");
    }
    Ok(())
}

impl ClientAttemptJournal {
    fn open(root_path: &Path, owner_uid: u32) -> Result<Self> {
        Self::open_with_capacity(root_path, owner_uid, MAX_RESOLVED_OPERATIONS)
    }

    fn open_with_capacity(
        root_path: &Path,
        owner_uid: u32,
        resolved_capacity: usize,
    ) -> Result<Self> {
        if resolved_capacity == 0 || resolved_capacity > MAX_RESOLVED_OPERATIONS {
            bail!("direct_operation_custody_client_journal_capacity_denied");
        }
        let (root_parent, root_name) = secure_open_parent(root_path, owner_uid)?;
        create_private_directory(&root_parent.directory, &root_name)?;
        root_parent.directory.sync_all()?;
        revalidate_journal_root_parent(&root_parent, owner_uid)?;
        let root = open_directory(root_parent.directory.as_raw_fd(), &root_name)?;
        validate_private_directory(&root, owner_uid)?;
        if unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("direct_operation_custody_client_journal_lock_unavailable");
        }
        create_private_directory(&root, ACTIVE_DIRECTORY_NAME)?;
        create_private_directory(&root, RESOLVED_DIRECTORY_NAME)?;
        let active = open_directory(root.as_raw_fd(), ACTIVE_DIRECTORY_NAME)?;
        let resolved = open_directory(root.as_raw_fd(), RESOLVED_DIRECTORY_NAME)?;
        validate_private_directory(&active, owner_uid)?;
        validate_private_directory(&resolved, owner_uid)?;
        root.sync_all()?;
        root_parent.directory.sync_all()?;
        let root_path_sha256 = sha256_bytes(root_path.as_os_str().as_encoded_bytes());
        let external_hold_name = CString::new(format!(
            ".direct-operation-custody-hold-{}.json",
            &root_path_sha256[..24]
        ))?;
        let mut journal = Self {
            root_parent,
            root_name,
            external_hold_name,
            root_identity: JournalFileIdentity::from_file(&root)?,
            root,
            active_identity: JournalFileIdentity::from_file(&active)?,
            active,
            resolved_identity: JournalFileIdentity::from_file(&resolved)?,
            resolved,
            retained_active_operation: None,
            owner_uid,
            root_path: root_path.to_path_buf(),
            resolved_capacity,
            #[cfg(test)]
            hold_pre_return_barrier: None,
        };
        journal.revalidate()?;
        if let Err(error) = journal.validate_complete_namespace() {
            journal.mark_permanent_hold(None, &format!("startup_journal_damage:{error:#}"))?;
            return Err(error)
                .context("direct_operation_custody_client_journal_damage_permanent_hold");
        }
        Ok(journal)
    }

    fn revalidate(&self) -> Result<()> {
        revalidate_journal_root_parent(&self.root_parent, self.owner_uid)?;
        validate_private_directory(&self.root, self.owner_uid)?;
        validate_private_directory(&self.active, self.owner_uid)?;
        validate_private_directory(&self.resolved, self.owner_uid)?;
        if !JournalFileIdentity::from_file(&self.root)?.same_directory_custody(&self.root_identity)
        {
            bail!("direct_operation_custody_client_journal_root_identity_drift");
        }
        let reopened = open_directory(self.root.as_raw_fd(), c".")?;
        if !JournalFileIdentity::from_file(&reopened)?.same_directory_custody(&self.root_identity) {
            bail!("direct_operation_custody_client_journal_root_reopen_drift");
        }
        let named = open_directory(self.root_parent.directory.as_raw_fd(), &self.root_name)?;
        if !JournalFileIdentity::from_file(&named)?.same_directory_custody(&self.root_identity) {
            bail!("direct_operation_custody_client_journal_root_path_rebound");
        }
        let named_active = open_directory(named.as_raw_fd(), ACTIVE_DIRECTORY_NAME)?;
        if !JournalFileIdentity::from_file(&named_active)?
            .same_directory_custody(&self.active_identity)
        {
            bail!("direct_operation_custody_client_journal_active_path_rebound");
        }
        let named_resolved = open_directory(named.as_raw_fd(), RESOLVED_DIRECTORY_NAME)?;
        if !JournalFileIdentity::from_file(&named_resolved)?
            .same_directory_custody(&self.resolved_identity)
        {
            bail!("direct_operation_custody_client_journal_resolved_path_rebound");
        }
        if unsafe { libc::flock(self.root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("direct_operation_custody_client_journal_lock_lost");
        }
        Ok(())
    }

    fn validate_namespace(&self) -> Result<()> {
        self.revalidate()?;
        let root_names = list_directory_names(&self.root)?;
        for name in &root_names {
            if name != "active" && name != "resolved" {
                bail!("direct_operation_custody_client_journal_unexpected_root_entry");
            }
        }
        let active_names = list_directory_names(&self.active)?;
        if active_names.len() > 1 {
            bail!("direct_operation_custody_client_journal_multiple_active_attempts");
        }
        for name in &active_names {
            require_operation_leaf(name)?;
        }
        let resolved_names = list_directory_names(&self.resolved)?;
        if resolved_names.len() > self.resolved_capacity {
            bail!("direct_operation_custody_client_journal_resolved_capacity_exhausted");
        }
        for name in &resolved_names {
            require_operation_leaf(name)?;
        }
        Ok(())
    }

    fn validate_complete_namespace(&mut self) -> Result<()> {
        self.validate_namespace()?;
        for name in list_directory_names(&self.resolved)? {
            require_operation_leaf(&name)?;
            let operation_name = CString::new(name.as_bytes())?;
            let operation = open_directory(self.resolved.as_raw_fd(), &operation_name)?;
            self.validate_operation_records(&operation, &name, true)?;
        }
        if let Some(active) = list_directory_names(&self.active)?.first() {
            require_operation_leaf(active)?;
            let operation_name = CString::new(active.as_bytes())?;
            let operation = open_directory(self.active.as_raw_fd(), &operation_name)?;
            self.validate_operation_records(&operation, active, false)?;
            self.retained_active_operation = Some(RetainedActiveOperation {
                operation_id_sha256: active.clone(),
                identity: JournalFileIdentity::from_file(&operation)?,
                directory: operation,
            });
        }
        Ok(())
    }

    fn require_not_held(&self) -> Result<()> {
        self.validate_namespace()?;
        if let Some(bytes) = read_named_file(
            &self.root_parent.directory,
            &self.external_hold_name,
            self.owner_uid,
            MAX_JOURNAL_RECORD_BYTES,
        )? {
            let hold: ClientPermanentHoldV2 = decode_canonical(&bytes)?;
            hold.validate()?;
            if hold.journal_root_path_sha256
                != sha256_bytes(self.root_path.as_os_str().as_encoded_bytes())
            {
                bail!("direct_operation_custody_client_journal_hold_route_drift");
            }
            bail!("direct_operation_custody_client_journal_permanent_hold");
        }
        Ok(())
    }

    fn begin(&mut self, request: &DirectOperationCustodyHighWaterRequestV1) -> Result<()> {
        self.require_not_held()?;
        if !list_directory_names(&self.active)?.is_empty() {
            bail!("direct_operation_custody_client_journal_active_attempt_exists");
        }
        let operation_name = operation_name(&request.operation_id_sha256)?;
        if stat_directory_at(&self.resolved, &operation_name)?.is_some() {
            bail!("direct_operation_custody_client_journal_operation_replay_denied");
        }
        if list_directory_names(&self.resolved)?.len() >= self.resolved_capacity {
            bail!("direct_operation_custody_client_journal_capacity_pre_authority_hold");
        }
        create_private_directory(&self.active, &operation_name)?;
        self.active.sync_all()?;
        let operation = open_directory(self.active.as_raw_fd(), &operation_name)?;
        validate_private_directory(&operation, self.owner_uid)?;
        let operation_identity = JournalFileIdentity::from_file(&operation)?;
        let intent = ClientAttemptIntentV2::derive(request)?;
        write_record_noreplace(&operation, INTENT_FILE_NAME, &intent, self.owner_uid)?;
        operation.sync_all()?;
        self.active.sync_all()?;
        self.retained_active_operation = Some(RetainedActiveOperation {
            operation_id_sha256: request.operation_id_sha256.clone(),
            directory: operation,
            identity: operation_identity,
        });
        self.revalidate_active_operation(&request.operation_id_sha256)
    }

    fn persist_response(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
        response: &DirectOperationCustodyHighWaterResponseV1,
    ) -> Result<ClientResponseReceiptV2> {
        self.revalidate_active_operation(&request.operation_id_sha256)?;
        let operation = &self
            .retained_active_operation
            .as_ref()
            .expect("revalidation retains active operation")
            .directory;
        let receipt = ClientResponseReceiptV2::derive(request, response)?;
        write_record_noreplace(operation, RESPONSE_FILE_NAME, &receipt, self.owner_uid)?;
        operation.sync_all()?;
        self.active.sync_all()?;
        self.revalidate_active_operation(&request.operation_id_sha256)?;
        Ok(receipt)
    }

    fn persist_confirmation_ack(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
        response_receipt: &ClientResponseReceiptV2,
        confirmation: &DirectOperationCustodyHighWaterResponseConfirmationV1,
        acknowledgement: &DirectOperationCustodyHighWaterResponseConfirmationAckV1,
    ) -> Result<ClientConfirmationAckReceiptV2> {
        self.revalidate_active_operation(&request.operation_id_sha256)?;
        let operation = &self
            .retained_active_operation
            .as_ref()
            .expect("revalidation retains active operation")
            .directory;
        let receipt = ClientConfirmationAckReceiptV2::derive(
            request,
            response_receipt,
            confirmation,
            acknowledgement,
        )?;
        write_record_noreplace(
            operation,
            CONFIRMATION_ACK_FILE_NAME,
            &receipt,
            self.owner_uid,
        )?;
        operation.sync_all()?;
        self.active.sync_all()?;
        self.revalidate_active_operation(&request.operation_id_sha256)?;
        Ok(receipt)
    }

    fn resolve(&mut self, operation_id_sha256: &str) -> Result<()> {
        self.revalidate_active_operation(operation_id_sha256)?;
        let operation_name = operation_name(operation_id_sha256)?;
        if list_directory_names(&self.resolved)?.len() >= self.resolved_capacity {
            bail!("direct_operation_custody_client_journal_capacity_before_resolve_hold");
        }
        let active_identity = stat_directory_at(&self.active, &operation_name)?
            .context("direct_operation_custody_client_journal_active_attempt_missing")?;
        if stat_directory_at(&self.resolved, &operation_name)?.is_some() {
            bail!("direct_operation_custody_client_journal_resolved_name_conflict");
        }
        let operation = &self
            .retained_active_operation
            .as_ref()
            .expect("revalidation retains active operation")
            .directory;
        if FileIdentity::from_metadata(&operation.metadata()?) != active_identity {
            bail!("direct_operation_custody_client_journal_active_inode_drift");
        }
        self.validate_operation_records(operation, operation_id_sha256, true)?;
        operation.sync_all()?;
        renameat2_noreplace(
            self.active.as_raw_fd(),
            &operation_name,
            self.resolved.as_raw_fd(),
            &operation_name,
        )?;
        self.active.sync_all()?;
        self.resolved.sync_all()?;
        if stat_directory_at(&self.active, &operation_name)?.is_some() {
            bail!("direct_operation_custody_client_journal_active_retirement_failed");
        }
        let resolved = open_directory(self.resolved.as_raw_fd(), &operation_name)?;
        if FileIdentity::from_metadata(&resolved.metadata()?) != active_identity {
            bail!("direct_operation_custody_client_journal_resolved_inode_drift");
        }
        if JournalFileIdentity::from_file(&resolved)?
            != self
                .retained_active_operation
                .as_ref()
                .expect("retained operation remains live through rename")
                .identity
        {
            bail!("direct_operation_custody_client_journal_resolved_mount_inode_drift");
        }
        self.validate_operation_records(&resolved, operation_id_sha256, true)?;
        self.revalidate()?;
        self.retained_active_operation = None;
        self.validate_namespace()
    }

    fn mark_permanent_hold(&self, operation_id_sha256: Option<&str>, reason: &str) -> Result<()> {
        revalidate_journal_root_parent(&self.root_parent, self.owner_uid)?;
        let hold = ClientPermanentHoldV2::derive(
            sha256_bytes(self.root_path.as_os_str().as_encoded_bytes()),
            self.root_identity.digest_sha256()?,
            operation_id_sha256,
            reason,
        )?;
        let bytes = encode_canonical(&hold)?;
        match read_named_file(
            &self.root_parent.directory,
            &self.external_hold_name,
            self.owner_uid,
            MAX_JOURNAL_RECORD_BYTES,
        )? {
            Some(existing) => {
                let existing: ClientPermanentHoldV2 = decode_canonical(&existing)?;
                existing.validate()?;
            }
            None => {
                write_bytes_noreplace(
                    &self.root_parent.directory,
                    &self.external_hold_name,
                    &bytes,
                    self.owner_uid,
                )?;
                self.root_parent.directory.sync_all()?;
            }
        }
        revalidate_journal_root_parent(&self.root_parent, self.owner_uid)?;
        let installed = read_named_file(
            &self.root_parent.directory,
            &self.external_hold_name,
            self.owner_uid,
            MAX_JOURNAL_RECORD_BYTES,
        )?
        .context("direct_operation_custody_client_external_hold_missing_after_publish")?;
        let installed: ClientPermanentHoldV2 = decode_canonical(&installed)?;
        installed.validate()?;
        if installed.journal_root_path_sha256
            != sha256_bytes(self.root_path.as_os_str().as_encoded_bytes())
        {
            bail!("direct_operation_custody_client_external_hold_route_drift");
        }
        #[cfg(test)]
        if let Some(barrier) = &self.hold_pre_return_barrier {
            barrier();
        }
        self.revalidate()
            .context("direct_operation_custody_client_external_hold_final_rebind_denied")?;
        Ok(())
    }

    fn load_active(&mut self) -> Result<Option<ActiveClientAttempt>> {
        self.require_not_held()?;
        let names = list_directory_names(&self.active)?;
        let Some(name) = names.first() else {
            return Ok(None);
        };
        require_operation_leaf(name)?;
        let operation_name = CString::new(name.as_bytes())?;
        let operation = open_directory(self.active.as_raw_fd(), &operation_name)?;
        let active = self.validate_operation_records(&operation, name, false)?;
        self.retained_active_operation = Some(RetainedActiveOperation {
            operation_id_sha256: name.clone(),
            identity: JournalFileIdentity::from_file(&operation)?,
            directory: operation,
        });
        Ok(Some(active))
    }

    fn validate_operation_records(
        &self,
        operation: &File,
        operation_id_sha256: &str,
        require_confirmation: bool,
    ) -> Result<ActiveClientAttempt> {
        validate_private_directory(operation, self.owner_uid)?;
        let names = list_directory_names(operation)?;
        for name in &names {
            if name != "intent-v2.json"
                && name != "response-v2.json"
                && name != "confirmation-ack-v2.json"
            {
                bail!("direct_operation_custody_client_journal_unexpected_attempt_entry");
            }
        }
        let intent_bytes = read_named_file(
            operation,
            INTENT_FILE_NAME,
            self.owner_uid,
            MAX_JOURNAL_RECORD_BYTES,
        )?
        .context("direct_operation_custody_client_journal_intent_missing")?;
        let intent: ClientAttemptIntentV2 = decode_canonical(&intent_bytes)?;
        intent.validate()?;
        if intent.operation_id_sha256 != operation_id_sha256 {
            bail!("direct_operation_custody_client_journal_operation_name_drift");
        }
        let response_receipt = read_named_file(
            operation,
            RESPONSE_FILE_NAME,
            self.owner_uid,
            MAX_JOURNAL_RECORD_BYTES,
        )?
        .map(|bytes| decode_canonical::<ClientResponseReceiptV2>(&bytes))
        .transpose()?;
        if let Some(receipt) = &response_receipt {
            receipt.validate_for(&intent.request)?;
        }
        let confirmation_ack_receipt = read_named_file(
            operation,
            CONFIRMATION_ACK_FILE_NAME,
            self.owner_uid,
            MAX_JOURNAL_RECORD_BYTES,
        )?
        .map(|bytes| decode_canonical::<ClientConfirmationAckReceiptV2>(&bytes))
        .transpose()?;
        if let Some(receipt) = &confirmation_ack_receipt {
            let response = response_receipt
                .as_ref()
                .context("direct_operation_custody_client_journal_confirmation_without_response")?;
            receipt.validate_for(&intent.request, response)?;
        }
        if require_confirmation && confirmation_ack_receipt.is_none() {
            bail!("direct_operation_custody_client_journal_resolve_before_confirmation");
        }
        Ok(ActiveClientAttempt {
            intent,
            response_receipt,
            confirmation_ack_receipt,
        })
    }

    fn revalidate_active_operation(&self, operation_id_sha256: &str) -> Result<()> {
        self.revalidate()?;
        let operation_name = operation_name(operation_id_sha256)?;
        let retained = self
            .retained_active_operation
            .as_ref()
            .context("direct_operation_custody_client_journal_active_handle_missing")?;
        if retained.operation_id_sha256 != operation_id_sha256
            || JournalFileIdentity::from_file(&retained.directory)? != retained.identity
        {
            bail!("direct_operation_custody_client_journal_active_handle_drift");
        }
        let operation = open_directory(self.active.as_raw_fd(), &operation_name)?;
        validate_private_directory(&operation, self.owner_uid)?;
        if JournalFileIdentity::from_file(&operation)? != retained.identity {
            bail!("direct_operation_custody_client_journal_active_name_rebound");
        }
        Ok(())
    }
}

fn create_private_directory(parent: &File, name: &CStr) -> Result<()> {
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error).context("direct_operation_custody_client_journal_mkdirat_failed");
        }
    }
    let directory = open_directory(parent.as_raw_fd(), name)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.nlink() == 0
    {
        bail!("direct_operation_custody_client_journal_directory_mode_denied");
    }
    Ok(())
}

fn validate_private_directory(directory: &File, owner_uid: u32) -> Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.nlink() == 0
    {
        bail!("direct_operation_custody_client_journal_private_directory_denied");
    }
    Ok(())
}

fn list_directory_names(directory: &File) -> Result<Vec<String>> {
    // `dup` would share the directory stream offset with the retained fd and
    // could make a later namespace validation observe a false empty set.
    // Re-open `.` to obtain an independent open file description instead.
    let reopened = open_directory(directory.as_raw_fd(), c".")?;
    let reopened_fd = reopened.into_raw_fd();
    let stream = unsafe { libc::fdopendir(reopened_fd) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(reopened_fd) };
        return Err(error).context("direct_operation_custody_client_journal_fdopendir_failed");
    }
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let errno = unsafe { *libc::__errno_location() };
            unsafe { libc::closedir(stream) };
            if errno != 0 {
                return Err(std::io::Error::from_raw_os_error(errno))
                    .context("direct_operation_custody_client_journal_readdir_failed");
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let name = std::str::from_utf8(name.to_bytes())
            .context("direct_operation_custody_client_journal_name_not_utf8")?;
        names.push(name.to_string());
    }
    names.sort();
    Ok(names)
}

fn write_record_noreplace<T: Serialize>(
    directory: &File,
    name: &CStr,
    value: &T,
    owner_uid: u32,
) -> Result<()> {
    write_bytes_noreplace(directory, name, &encode_canonical(value)?, owner_uid)
}

fn write_bytes_noreplace(
    directory: &File,
    name: &CStr,
    bytes: &[u8],
    owner_uid: u32,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_RECORD_BYTES {
        bail!("direct_operation_custody_client_journal_record_size_denied");
    }
    let mut file = openat_create_new(directory.as_raw_fd(), name, 0o600)?;
    set_exact_mode(&file, 0o600)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let created_identity = JournalFileIdentity::from_file(&file)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != bytes.len() as u64
    {
        bail!("direct_operation_custody_client_journal_record_identity_denied");
    }
    read_named_file_exact_identity(directory, name, owner_uid, bytes, &created_identity)?;
    directory.sync_all()?;
    read_named_file_exact_identity(directory, name, owner_uid, bytes, &created_identity)?;
    Ok(())
}

fn read_named_file_exact_identity(
    directory: &File,
    name: &CStr,
    owner_uid: u32,
    expected_bytes: &[u8],
    expected_identity: &JournalFileIdentity,
) -> Result<()> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_client_journal_named_record_open_failed");
    }
    let mut named = unsafe { File::from_raw_fd(fd) };
    let metadata = named.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != expected_bytes.len() as u64
        || JournalFileIdentity::from_file(&named)? != *expected_identity
    {
        bail!("direct_operation_custody_client_journal_named_record_inode_drift");
    }
    let mut readback = Vec::new();
    Read::by_ref(&mut named)
        .take(MAX_JOURNAL_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut readback)?;
    if readback != expected_bytes || JournalFileIdentity::from_file(&named)? != *expected_identity {
        bail!("direct_operation_custody_client_journal_record_readback_mismatch");
    }
    let reopened_fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if reopened_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_client_journal_named_record_reopen_failed");
    }
    let reopened = unsafe { File::from_raw_fd(reopened_fd) };
    if JournalFileIdentity::from_file(&reopened)? != *expected_identity {
        bail!("direct_operation_custody_client_journal_named_record_rebound");
    }
    Ok(())
}

fn encode_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_JOURNAL_RECORD_BYTES {
        bail!("direct_operation_custody_client_journal_record_size_denied");
    }
    Ok(bytes)
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_RECORD_BYTES {
        bail!("direct_operation_custody_client_journal_record_size_denied");
    }
    let value: T = serde_json::from_slice(bytes)
        .context("direct_operation_custody_client_journal_record_json_denied")?;
    if encode_canonical(&value)? != bytes {
        bail!("direct_operation_custody_client_journal_record_noncanonical");
    }
    Ok(value)
}

fn operation_name(operation_id_sha256: &str) -> Result<CString> {
    require_operation_leaf(operation_id_sha256)?;
    CString::new(operation_id_sha256)
        .context("direct_operation_custody_client_journal_operation_name_contains_nul")
}

fn require_operation_leaf(name: &str) -> Result<()> {
    if !valid_nonzero_sha256(name) {
        bail!("direct_operation_custody_client_journal_operation_name_denied");
    }
    Ok(())
}

fn stat_directory_at(parent: &File, name: &CStr) -> Result<Option<FileIdentity>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
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
        return Err(error).context("direct_operation_custody_client_journal_fstatat_failed");
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        bail!("direct_operation_custody_client_journal_operation_not_directory");
    }
    Ok(Some(FileIdentity::from_stat(&stat)))
}

fn renameat2_noreplace(
    old_parent: RawFd,
    old_name: &CStr,
    new_parent: RawFd,
    new_name: &CStr,
) -> Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_parent,
            old_name.as_ptr(),
            new_parent,
            new_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_client_journal_rename_noreplace_failed");
    }
    Ok(())
}

struct FixedPathWireTransport {
    stream: UnixStream,
    socket_identity: SocketIdentity,
    peer_pid: libc::pid_t,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SocketIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
}

impl SocketIdentity {
    fn fixed_path() -> Result<Self> {
        let metadata = fs::symlink_metadata(FIXED_AUTHORITY_SOCKET_PATH)
            .context("direct_operation_custody_high_water_fixed_socket_metadata_denied")?;
        let identity = Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
        };
        if !metadata.file_type().is_socket()
            || metadata.uid() != FIXED_AUTHORITY_UID
            || metadata.gid() != FIXED_AUTHORITY_GID
            || metadata.permissions().mode() & 0o7777 != FIXED_AUTHORITY_SOCKET_MODE
            || metadata.nlink() != 1
        {
            bail!("direct_operation_custody_high_water_fixed_socket_identity_denied");
        }
        Ok(identity)
    }
}

impl FixedPathWireTransport {
    fn connect() -> Result<Self> {
        let before = SocketIdentity::fixed_path()?;
        let stream = UnixStream::connect(FIXED_AUTHORITY_SOCKET_PATH)
            .context("direct_operation_custody_high_water_fixed_socket_connect_denied")?;
        stream.set_read_timeout(Some(CALL_TIMEOUT))?;
        stream.set_write_timeout(Some(CALL_TIMEOUT))?;
        require_cloexec(&stream)?;
        let after = SocketIdentity::fixed_path()?;
        if before != after {
            bail!("direct_operation_custody_high_water_fixed_socket_replaced_during_connect");
        }
        let credentials = peer_credentials(&stream)?;
        if credentials.uid != FIXED_AUTHORITY_UID
            || credentials.gid != FIXED_AUTHORITY_GID
            || credentials.pid <= 0
            || peer_security_context(&stream)? != FIXED_AUTHORITY_SELINUX_DOMAIN
        {
            bail!("direct_operation_custody_high_water_peer_identity_denied");
        }
        Ok(Self {
            stream,
            socket_identity: before,
            peer_pid: credentials.pid,
        })
    }

    fn revalidate(&self) -> Result<()> {
        require_cloexec(&self.stream)?;
        if SocketIdentity::fixed_path()? != self.socket_identity {
            bail!("direct_operation_custody_high_water_fixed_socket_replaced");
        }
        let credentials = peer_credentials(&self.stream)?;
        if credentials.uid != FIXED_AUTHORITY_UID
            || credentials.gid != FIXED_AUTHORITY_GID
            || credentials.pid != self.peer_pid
            || peer_security_context(&self.stream)? != FIXED_AUTHORITY_SELINUX_DOMAIN
        {
            bail!("direct_operation_custody_high_water_peer_identity_changed");
        }
        Ok(())
    }

    fn exchange_frame(
        &mut self,
        frame: DirectOperationCustodyHighWaterClientFrameV1,
    ) -> Result<DirectOperationCustodyHighWaterServerFrameV1> {
        self.revalidate()?;
        let bytes = serde_json::to_vec(&frame)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            bail!("direct_operation_custody_high_water_request_frame_denied");
        }
        self.stream
            .write_all(&u32::try_from(bytes.len())?.to_be_bytes())
            .and_then(|()| self.stream.write_all(&bytes))
            .and_then(|()| self.stream.flush())
            .context("direct_operation_custody_high_water_request_outcome_unknown")?;
        let mut prefix = [0u8; 4];
        self.stream
            .read_exact(&mut prefix)
            .context("direct_operation_custody_high_water_response_outcome_unknown")?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            bail!("direct_operation_custody_high_water_response_frame_denied");
        }
        let mut response_bytes = vec![0u8; length];
        self.stream
            .read_exact(&mut response_bytes)
            .context("direct_operation_custody_high_water_response_outcome_unknown")?;
        self.revalidate()?;
        let response: DirectOperationCustodyHighWaterServerFrameV1 =
            serde_json::from_slice(&response_bytes)
                .context("direct_operation_custody_high_water_response_json_denied")?;
        if serde_json::to_vec(&response)? != response_bytes {
            bail!("direct_operation_custody_high_water_response_noncanonical_denied");
        }
        Ok(response)
    }
}

impl WireTransport for FixedPathWireTransport {
    fn operation(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
    ) -> Result<DirectOperationCustodyHighWaterResponseV1> {
        match self.exchange_frame(DirectOperationCustodyHighWaterClientFrameV1::Operation(
            request.clone(),
        ))? {
            DirectOperationCustodyHighWaterServerFrameV1::OperationResponse(response) => {
                Ok(response)
            }
            _ => bail!("direct_operation_custody_high_water_operation_response_kind_denied"),
        }
    }

    fn confirm_response(
        &mut self,
        confirmation: &DirectOperationCustodyHighWaterResponseConfirmationV1,
    ) -> Result<DirectOperationCustodyHighWaterResponseConfirmationAckV1> {
        match self.exchange_frame(
            DirectOperationCustodyHighWaterClientFrameV1::ConfirmResponse(confirmation.clone()),
        )? {
            DirectOperationCustodyHighWaterServerFrameV1::ConfirmResponseAck(response) => {
                Ok(response)
            }
            _ => bail!("direct_operation_custody_high_water_confirmation_response_kind_denied"),
        }
    }
}

fn require_cloexec(stream: &UnixStream) -> Result<()> {
    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_high_water_socket_fcntl_denied");
    }
    if flags & libc::FD_CLOEXEC == 0 {
        bail!("direct_operation_custody_high_water_socket_cloexec_denied");
    }
    Ok(())
}

fn peer_credentials(stream: &UnixStream) -> Result<libc::ucred> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast::<libc::c_void>(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_high_water_SO_PEERCRED_denied");
    }
    Ok(unsafe { credentials.assume_init() })
}

fn peer_security_context(stream: &UnixStream) -> Result<String> {
    let mut buffer = [0u8; 256];
    let mut length = buffer.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            &mut length,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_high_water_SO_PEERSEC_denied");
    }
    let length = length as usize;
    if length == 0 || length > buffer.len() {
        bail!("direct_operation_custody_high_water_SO_PEERSEC_malformed");
    }
    let context = &buffer[..length];
    let context = context.strip_suffix(&[0]).unwrap_or(context);
    let context = std::str::from_utf8(context)
        .context("direct_operation_custody_high_water_SO_PEERSEC_not_utf8")?;
    if context.is_empty() || context.as_bytes().contains(&0) {
        bail!("direct_operation_custody_high_water_SO_PEERSEC_malformed");
    }
    Ok(context.to_string())
}

fn fresh_nonce_sha256() -> Result<String> {
    let mut nonce = [0u8; 32];
    let result =
        unsafe { libc::getrandom(nonce.as_mut_ptr().cast::<libc::c_void>(), nonce.len(), 0) };
    if result != nonce.len() as isize || nonce.iter().all(|byte| *byte == 0) {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_high_water_kernel_nonce_unavailable");
    }
    Ok(sha256_bytes(&nonce))
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"domain", domain);
    hash_field(&mut hasher, b"value", &bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value != trillionnium_os_types::direct_operation_custody_high_water::DIRECT_OPERATION_CUSTODY_ZERO_SHA256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestAuthorityFault {
    OutcomeUnknownBeforeApply(DirectOperationCustodyHighWaterOperation),
    OutcomeUnknownAfterApply(DirectOperationCustodyHighWaterOperation),
}

#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestDirectOperationCustodyHighWaterAuthority {
    state: std::sync::Arc<std::sync::Mutex<TestAuthorityState>>,
}

#[cfg(test)]
#[derive(Clone)]
struct TestPendingTransition {
    from: DirectOperationCustodyHead,
    to: DirectOperationCustodyHead,
    transition_sha256: String,
}

#[cfg(test)]
struct TestAuthorityState {
    route: DirectOperationCustodyHighWaterRouteV1,
    committed: DirectOperationCustodyHead,
    pending: Option<TestPendingTransition>,
    permanent_hold: bool,
    fault: Option<TestAuthorityFault>,
    operations: Vec<DirectOperationCustodyHighWaterOperation>,
}

#[cfg(test)]
impl TestDirectOperationCustodyHighWaterAuthority {
    pub(super) fn new(committed: DirectOperationCustodyHead) -> Self {
        Self {
            state: std::sync::Arc::new(std::sync::Mutex::new(TestAuthorityState {
                route: product_route().expect("fixed route validates"),
                committed,
                pending: None,
                permanent_hold: false,
                fault: None,
                operations: Vec::new(),
            })),
        }
    }

    pub(super) fn connect(
        &self,
        local_head: DirectOperationCustodyHead,
    ) -> Result<VerifiedDirectOperationCustodyHighWater> {
        establish(Box::new(self.clone()), product_route()?, local_head)
    }

    pub(super) fn connect_foreign_route(
        &self,
        local_head: DirectOperationCustodyHead,
    ) -> Result<VerifiedDirectOperationCustodyHighWater> {
        let route = DirectOperationCustodyHighWaterRouteV1::derive(
            sha256_bytes(FIXED_PRODUCT_CUSTODY_STORE_PATH.as_bytes()),
            sha256_bytes(FIXED_CLIENT_JOURNAL_ROOT.as_bytes()),
            sha256_bytes(b"/run/trillionnium/direct-operation-tool-call-high-water-v1.sock"),
            sha256_bytes(b"u:r:trillionnium_direct_operation_high_water:s0"),
        )
        .map_err(|error| anyhow!(error))?;
        establish(Box::new(self.clone()), route, local_head)
    }

    pub(super) fn inject_fault(&self, fault: TestAuthorityFault) {
        self.state.lock().unwrap().fault = Some(fault);
    }

    pub(super) fn committed_head(&self) -> DirectOperationCustodyHead {
        self.state.lock().unwrap().committed.clone()
    }

    pub(super) fn is_permanent_hold(&self) -> bool {
        self.state.lock().unwrap().permanent_hold
    }

    pub(super) fn operation_count(
        &self,
        operation: DirectOperationCustodyHighWaterOperation,
    ) -> usize {
        self.state
            .lock()
            .unwrap()
            .operations
            .iter()
            .filter(|candidate| **candidate == operation)
            .count()
    }
}

#[cfg(test)]
impl AuthorityTransport for TestDirectOperationCustodyHighWaterAuthority {
    fn exchange(
        &mut self,
        request: &DirectOperationCustodyHighWaterRequestV1,
    ) -> Result<DirectOperationCustodyHighWaterResponseV1> {
        request.validate().map_err(|error| anyhow!(error))?;
        let mut state = self.state.lock().unwrap();
        state.operations.push(request.operation);
        if request.route != state.route {
            state.permanent_hold = true;
        }
        if state.permanent_hold {
            return test_response(
                request,
                DirectOperationCustodyHighWaterDisposition::PermanentHold,
                state.committed.clone(),
                request.transition_sha256.clone(),
            );
        }
        let fault_matches = state.fault.as_ref().is_some_and(|fault| match fault {
            TestAuthorityFault::OutcomeUnknownBeforeApply(operation)
            | TestAuthorityFault::OutcomeUnknownAfterApply(operation) => {
                *operation == request.operation
            }
        });
        let fault = if fault_matches {
            state.fault.take()
        } else {
            None
        };
        if matches!(
            fault,
            Some(TestAuthorityFault::OutcomeUnknownBeforeApply(_))
        ) {
            state.permanent_hold = true;
            bail!("test_custody_high_water_outcome_unknown_before_apply");
        }
        let response = apply_test_operation(&mut state, request)?;
        if matches!(fault, Some(TestAuthorityFault::OutcomeUnknownAfterApply(_))) {
            state.permanent_hold = true;
            bail!("test_custody_high_water_outcome_unknown_after_apply");
        }
        Ok(response)
    }
}

#[cfg(test)]
fn apply_test_operation(
    state: &mut TestAuthorityState,
    request: &DirectOperationCustodyHighWaterRequestV1,
) -> Result<DirectOperationCustodyHighWaterResponseV1> {
    let (disposition, transition) = match request.operation {
        DirectOperationCustodyHighWaterOperation::Reconcile => {
            if let Some(pending) = state.pending.clone() {
                if request.current_head == pending.from {
                    state.pending = None;
                } else if request.current_head == pending.to {
                    state.committed = pending.to;
                    state.pending = None;
                } else {
                    state.permanent_hold = true;
                }
            } else if request.current_head != state.committed {
                state.permanent_hold = true;
            }
            (
                DirectOperationCustodyHighWaterDisposition::ReconciledExact,
                None,
            )
        }
        DirectOperationCustodyHighWaterOperation::Observe => {
            if state.pending.is_some() || request.current_head != state.committed {
                state.permanent_hold = true;
            }
            (
                DirectOperationCustodyHighWaterDisposition::ObservedExact,
                None,
            )
        }
        DirectOperationCustodyHighWaterOperation::Prepare => {
            let proposed = request.proposed_head.clone().expect("validated prepare");
            let transition = request
                .transition_sha256
                .clone()
                .expect("validated transition");
            let candidate = TestPendingTransition {
                from: request.current_head.clone(),
                to: proposed,
                transition_sha256: transition.clone(),
            };
            if request.current_head != state.committed
                || state.pending.as_ref().is_some_and(|pending| {
                    pending.from != candidate.from
                        || pending.to != candidate.to
                        || pending.transition_sha256 != candidate.transition_sha256
                })
            {
                state.permanent_hold = true;
            } else {
                state.pending = Some(candidate);
            }
            (
                DirectOperationCustodyHighWaterDisposition::PreparedExact,
                Some(transition),
            )
        }
        DirectOperationCustodyHighWaterOperation::Commit => {
            let transition = request
                .transition_sha256
                .clone()
                .expect("validated transition");
            let exact = state.pending.as_ref().is_some_and(|pending| {
                pending.to == request.current_head
                    && pending.transition_sha256 == transition
                    && pending.from == state.committed
            });
            if exact {
                state.committed = request.current_head.clone();
                state.pending = None;
            } else {
                state.permanent_hold = true;
            }
            (
                DirectOperationCustodyHighWaterDisposition::CommittedExact,
                Some(transition),
            )
        }
    };
    test_response(
        request,
        if state.permanent_hold {
            DirectOperationCustodyHighWaterDisposition::PermanentHold
        } else {
            disposition
        },
        state.committed.clone(),
        if state.permanent_hold {
            request.transition_sha256.clone()
        } else {
            transition
        },
    )
}

#[cfg(test)]
fn test_response(
    request: &DirectOperationCustodyHighWaterRequestV1,
    disposition: DirectOperationCustodyHighWaterDisposition,
    committed_head: DirectOperationCustodyHead,
    transition_sha256: Option<String>,
) -> Result<DirectOperationCustodyHighWaterResponseV1> {
    use trillionnium_os_types::direct_operation_custody_high_water::{
        DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL,
        DIRECT_OPERATION_CUSTODY_HIGH_WATER_RESPONSE_SCHEMA,
    };
    let mut response = DirectOperationCustodyHighWaterResponseV1 {
        schema: DIRECT_OPERATION_CUSTODY_HIGH_WATER_RESPONSE_SCHEMA.to_string(),
        protocol: DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL.to_string(),
        operation: request.operation,
        disposition,
        authority_identity_sha256: FIXED_AUTHORITY_IDENTITY_SHA256.to_string(),
        route_sha256: request.route.route_sha256.clone(),
        operation_id_sha256: request.operation_id_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        committed_head,
        transition_sha256,
        response_sha256: String::new(),
    };
    response.seal();
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use tempfile::TempDir;
    use trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHighWaterConfirmationDisposition;

    // This is a real Unix-socket authority whose complete semantic state is
    // reloaded from an fsynced on-disk record after server restart.  It proves
    // crash persistence and protocol ordering only.  The record and its
    // revision/hash share one rollback domain, so this is deliberately not
    // rollback-freshness evidence and is never a product authority.
    const TEST_AUTHORITY_STATE_SCHEMA: &str =
        "trillionnium.direct-operation-custody-test-authority-state.v2";
    const TEST_AUTHORITY_STATE_DOMAIN: &[u8] =
        b"trillionnium.direct-operation-custody-test-authority-state.v2";
    const TEST_AUTHORITY_STATE_FILE: &str = "authority-state-v2.json";
    const TEST_AUTHORITY_NEXT_FILE: &str = "authority-state-v2.next";
    const TEST_AUTHORITY_RESOLVED_LIMIT: usize = 512;

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DurableTestPendingTransition {
        from: DirectOperationCustodyHead,
        to: DirectOperationCustodyHead,
        transition_sha256: String,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DurableTestPendingExchange {
        request: DirectOperationCustodyHighWaterRequestV1,
        response: DirectOperationCustodyHighWaterResponseV1,
        response_confirmed: bool,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DurableTestResolvedExchange {
        request: DirectOperationCustodyHighWaterRequestV1,
        response: DirectOperationCustodyHighWaterResponseV1,
        confirmation: DirectOperationCustodyHighWaterResponseConfirmationV1,
        acknowledgement: DirectOperationCustodyHighWaterResponseConfirmationAckV1,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DurableTestAuthorityState {
        schema: String,
        revision: u64,
        route: DirectOperationCustodyHighWaterRouteV1,
        committed: DirectOperationCustodyHead,
        pending_transition: Option<DurableTestPendingTransition>,
        pending_exchange: Option<DurableTestPendingExchange>,
        resolved: Vec<DurableTestResolvedExchange>,
        permanent_hold: bool,
        state_sha256: String,
    }

    impl DurableTestAuthorityState {
        fn initial(committed: DirectOperationCustodyHead) -> Result<Self> {
            let mut state = Self {
                schema: TEST_AUTHORITY_STATE_SCHEMA.to_string(),
                revision: 0,
                route: product_route()?,
                committed,
                pending_transition: None,
                pending_exchange: None,
                resolved: Vec::new(),
                permanent_hold: false,
                state_sha256: String::new(),
            };
            state.seal()?;
            state.validate()?;
            Ok(state)
        }

        fn validate(&self) -> Result<()> {
            self.route.validate().map_err(|error| anyhow!(error))?;
            self.committed.validate().map_err(|error| anyhow!(error))?;
            if self.schema != TEST_AUTHORITY_STATE_SCHEMA
                || self.resolved.len() > TEST_AUTHORITY_RESOLVED_LIMIT
                || self.state_sha256 != self.expected_sha256()?
            {
                bail!("test_durable_authority_state_denied");
            }
            if let Some(pending) = &self.pending_transition {
                pending.from.validate().map_err(|error| anyhow!(error))?;
                pending.to.validate().map_err(|error| anyhow!(error))?;
                if pending.to.generation
                    != pending
                        .from
                        .generation
                        .checked_add(1)
                        .context("test_durable_authority_pending_transition_generation_overflow")?
                    || pending.transition_sha256
                        != transition_sha256(&self.route, &pending.from, &pending.to)
                {
                    bail!("test_durable_authority_pending_transition_denied");
                }
            }
            if let Some(exchange) = &self.pending_exchange {
                exchange
                    .request
                    .validate()
                    .map_err(|error| anyhow!(error))?;
                exchange
                    .response
                    .validate_binding_for(&exchange.request, FIXED_AUTHORITY_IDENTITY_SHA256)
                    .map_err(|error| anyhow!(error))?;
                exchange
                    .response
                    .require_success()
                    .map_err(|error| anyhow!(error))?;
                if exchange.response_confirmed {
                    bail!("test_durable_authority_pending_exchange_confirmed_denied");
                }
            }
            for exchange in &self.resolved {
                exchange
                    .request
                    .validate()
                    .map_err(|error| anyhow!(error))?;
                exchange
                    .response
                    .validate_binding_for(&exchange.request, FIXED_AUTHORITY_IDENTITY_SHA256)
                    .map_err(|error| anyhow!(error))?;
                exchange
                    .confirmation
                    .validate()
                    .map_err(|error| anyhow!(error))?;
                exchange
                    .acknowledgement
                    .validate_for(&exchange.confirmation, FIXED_AUTHORITY_IDENTITY_SHA256)
                    .map_err(|error| anyhow!(error))?;
                if exchange.confirmation.operation_id_sha256 != exchange.request.operation_id_sha256
                    || exchange.confirmation.request_sha256 != exchange.request.request_sha256
                    || exchange.confirmation.response_sha256 != exchange.response.response_sha256
                {
                    bail!("test_durable_authority_resolved_exchange_denied");
                }
            }
            Ok(())
        }

        fn seal(&mut self) -> Result<()> {
            self.state_sha256 = self.expected_sha256()?;
            Ok(())
        }

        fn expected_sha256(&self) -> Result<String> {
            #[derive(Serialize)]
            struct Preimage<'a> {
                schema: &'a str,
                revision: u64,
                route: &'a DirectOperationCustodyHighWaterRouteV1,
                committed: &'a DirectOperationCustodyHead,
                pending_transition: &'a Option<DurableTestPendingTransition>,
                pending_exchange: &'a Option<DurableTestPendingExchange>,
                resolved: &'a Vec<DurableTestResolvedExchange>,
                permanent_hold: bool,
            }
            domain_digest(
                TEST_AUTHORITY_STATE_DOMAIN,
                &Preimage {
                    schema: &self.schema,
                    revision: self.revision,
                    route: &self.route,
                    committed: &self.committed,
                    pending_transition: &self.pending_transition,
                    pending_exchange: &self.pending_exchange,
                    resolved: &self.resolved,
                    permanent_hold: self.permanent_hold,
                },
            )
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DurableTestAuthorityFault {
        DropOperation(DirectOperationCustodyHighWaterOperation),
        TruncatedOperationFrame(DirectOperationCustodyHighWaterOperation),
        FullOperationResponseBeforeClientRead(DirectOperationCustodyHighWaterOperation),
        ConfirmationAckLost,
    }

    struct DurableTestAuthorityControl {
        fault: Mutex<Option<DurableTestAuthorityFault>>,
        persisted_barrier_reached: AtomicBool,
        release_barrier: AtomicBool,
    }

    impl DurableTestAuthorityControl {
        fn new() -> Self {
            Self {
                fault: Mutex::new(None),
                persisted_barrier_reached: AtomicBool::new(false),
                release_barrier: AtomicBool::new(false),
            }
        }

        fn arm(&self, fault: DurableTestAuthorityFault) {
            *self.fault.lock().unwrap() = Some(fault);
            self.persisted_barrier_reached
                .store(false, Ordering::SeqCst);
            self.release_barrier.store(false, Ordering::SeqCst);
        }

        fn take_matching_operation(
            &self,
            operation: DirectOperationCustodyHighWaterOperation,
        ) -> Option<DurableTestAuthorityFault> {
            let mut fault = self.fault.lock().unwrap();
            if fault.as_ref().is_some_and(|candidate| {
                matches!(
                    candidate,
                    DurableTestAuthorityFault::DropOperation(target)
                        | DurableTestAuthorityFault::TruncatedOperationFrame(target)
                        | DurableTestAuthorityFault::FullOperationResponseBeforeClientRead(target)
                        if *target == operation
                )
            }) {
                fault.take()
            } else {
                None
            }
        }

        fn take_confirmation(&self) -> Option<DurableTestAuthorityFault> {
            let mut fault = self.fault.lock().unwrap();
            if matches!(
                fault.as_ref(),
                Some(DurableTestAuthorityFault::ConfirmationAckLost)
            ) {
                fault.take()
            } else {
                None
            }
        }

        fn cross_persisted_barrier(&self) {
            self.persisted_barrier_reached.store(true, Ordering::SeqCst);
            while !self.release_barrier.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(1));
            }
        }

        fn wait_until_persisted(&self) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !self.persisted_barrier_reached.load(Ordering::SeqCst) {
                assert!(
                    Instant::now() < deadline,
                    "authority persist barrier timed out"
                );
                thread::sleep(Duration::from_millis(1));
            }
        }

        fn release(&self) {
            self.release_barrier.store(true, Ordering::SeqCst);
        }
    }

    fn durable_test_authority_state_path(root: &Path) -> PathBuf {
        root.join(TEST_AUTHORITY_STATE_FILE)
    }

    fn persist_durable_test_authority_state(
        root: &Path,
        state: &mut DurableTestAuthorityState,
    ) -> Result<()> {
        state.revision = state
            .revision
            .checked_add(1)
            .context("test_durable_authority_revision_overflow")?;
        state.seal()?;
        state.validate()?;
        let bytes = encode_canonical(state)?;
        let next = root.join(TEST_AUTHORITY_NEXT_FILE);
        let final_path = durable_test_authority_state_path(root);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&next)
            .context("test_durable_authority_next_create_failed")?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() != bytes.len() as u64
        {
            bail!("test_durable_authority_next_identity_denied");
        }
        fs::rename(&next, &final_path)
            .context("test_durable_authority_state_atomic_replace_failed")?;
        File::open(root)?.sync_all()?;
        let readback = fs::read(&final_path)?;
        if readback != bytes {
            bail!("test_durable_authority_state_readback_mismatch");
        }
        Ok(())
    }

    fn load_durable_test_authority_state(root: &Path) -> Result<DurableTestAuthorityState> {
        if root.join(TEST_AUTHORITY_NEXT_FILE).exists() {
            bail!("test_durable_authority_incomplete_state_publish_permanent_hold");
        }
        let bytes = fs::read(durable_test_authority_state_path(root))?;
        let state: DurableTestAuthorityState = decode_canonical(&bytes)?;
        state.validate()?;
        Ok(state)
    }

    fn initialise_durable_test_authority(
        root: &Path,
        committed: DirectOperationCustodyHead,
    ) -> Result<()> {
        fs::create_dir(root)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        let mut state = DurableTestAuthorityState::initial(committed)?;
        persist_durable_test_authority_state(root, &mut state)
    }

    fn durable_test_hold_response(
        request: &DirectOperationCustodyHighWaterRequestV1,
        committed: DirectOperationCustodyHead,
    ) -> Result<DirectOperationCustodyHighWaterResponseV1> {
        test_response(
            request,
            DirectOperationCustodyHighWaterDisposition::PermanentHold,
            committed,
            request.transition_sha256.clone(),
        )
    }

    fn apply_durable_test_operation(
        state: &mut DurableTestAuthorityState,
        request: &DirectOperationCustodyHighWaterRequestV1,
    ) -> Result<DirectOperationCustodyHighWaterResponseV1> {
        request.validate().map_err(|error| anyhow!(error))?;
        if request.route != state.route
            || state.pending_exchange.is_some()
            || state
                .resolved
                .iter()
                .any(|resolved| resolved.request.operation_id_sha256 == request.operation_id_sha256)
        {
            state.permanent_hold = true;
        }
        if state.permanent_hold {
            return durable_test_hold_response(request, state.committed.clone());
        }

        let (disposition, response_transition) = match request.operation {
            DirectOperationCustodyHighWaterOperation::Reconcile => {
                if let Some(pending) = state.pending_transition.clone() {
                    if request.current_head == pending.from {
                        state.pending_transition = None;
                    } else if request.current_head == pending.to {
                        state.committed = pending.to;
                        state.pending_transition = None;
                    } else {
                        state.permanent_hold = true;
                    }
                } else if request.current_head != state.committed {
                    state.permanent_hold = true;
                }
                (
                    DirectOperationCustodyHighWaterDisposition::ReconciledExact,
                    None,
                )
            }
            DirectOperationCustodyHighWaterOperation::Observe => {
                if state.pending_transition.is_some() || request.current_head != state.committed {
                    state.permanent_hold = true;
                }
                (
                    DirectOperationCustodyHighWaterDisposition::ObservedExact,
                    None,
                )
            }
            DirectOperationCustodyHighWaterOperation::Prepare => {
                let to = request
                    .proposed_head
                    .clone()
                    .context("test_durable_authority_prepare_head_missing")?;
                let transition = request
                    .transition_sha256
                    .clone()
                    .context("test_durable_authority_prepare_transition_missing")?;
                let pending = DurableTestPendingTransition {
                    from: request.current_head.clone(),
                    to,
                    transition_sha256: transition.clone(),
                };
                if request.current_head != state.committed
                    || state
                        .pending_transition
                        .as_ref()
                        .is_some_and(|existing| existing != &pending)
                {
                    state.permanent_hold = true;
                } else {
                    state.pending_transition = Some(pending);
                }
                (
                    DirectOperationCustodyHighWaterDisposition::PreparedExact,
                    Some(transition),
                )
            }
            DirectOperationCustodyHighWaterOperation::Commit => {
                let transition = request
                    .transition_sha256
                    .clone()
                    .context("test_durable_authority_commit_transition_missing")?;
                let exact = state.pending_transition.as_ref().is_some_and(|pending| {
                    pending.from == state.committed
                        && pending.to == request.current_head
                        && pending.transition_sha256 == transition
                });
                if exact {
                    state.committed = request.current_head.clone();
                    state.pending_transition = None;
                } else {
                    state.permanent_hold = true;
                }
                (
                    DirectOperationCustodyHighWaterDisposition::CommittedExact,
                    Some(transition),
                )
            }
        };
        if state.permanent_hold {
            return durable_test_hold_response(request, state.committed.clone());
        }
        test_response(
            request,
            disposition,
            state.committed.clone(),
            response_transition,
        )
    }

    fn durable_test_process_operation(
        root: &Path,
        request: DirectOperationCustodyHighWaterRequestV1,
    ) -> Result<DirectOperationCustodyHighWaterResponseV1> {
        let mut state = load_durable_test_authority_state(root)?;
        let response = apply_durable_test_operation(&mut state, &request)?;
        if !state.permanent_hold {
            state.pending_exchange = Some(DurableTestPendingExchange {
                request,
                response: response.clone(),
                response_confirmed: false,
            });
        }
        persist_durable_test_authority_state(root, &mut state)?;
        Ok(response)
    }

    fn durable_test_confirmation_ack(
        confirmation: &DirectOperationCustodyHighWaterResponseConfirmationV1,
        disposition: DirectOperationCustodyHighWaterConfirmationDisposition,
    ) -> DirectOperationCustodyHighWaterResponseConfirmationAckV1 {
        use trillionnium_os_types::direct_operation_custody_high_water::{
            DIRECT_OPERATION_CUSTODY_HIGH_WATER_CONFIRMATION_ACK_SCHEMA,
            DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL,
        };
        let mut acknowledgement = DirectOperationCustodyHighWaterResponseConfirmationAckV1 {
            schema: DIRECT_OPERATION_CUSTODY_HIGH_WATER_CONFIRMATION_ACK_SCHEMA.to_string(),
            protocol: DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL.to_string(),
            disposition,
            authority_identity_sha256: FIXED_AUTHORITY_IDENTITY_SHA256.to_string(),
            route_sha256: confirmation.route_sha256.clone(),
            operation_id_sha256: confirmation.operation_id_sha256.clone(),
            request_sha256: confirmation.request_sha256.clone(),
            response_sha256: confirmation.response_sha256.clone(),
            client_response_receipt_sha256: confirmation.client_response_receipt_sha256.clone(),
            confirmation_sha256: confirmation.confirmation_sha256.clone(),
            confirmation_ack_sha256: String::new(),
        };
        acknowledgement.seal();
        acknowledgement
    }

    fn durable_test_process_confirmation(
        root: &Path,
        confirmation: DirectOperationCustodyHighWaterResponseConfirmationV1,
    ) -> Result<DirectOperationCustodyHighWaterResponseConfirmationAckV1> {
        confirmation.validate().map_err(|error| anyhow!(error))?;
        let mut state = load_durable_test_authority_state(root)?;
        if let Some(resolved) = state
            .resolved
            .iter()
            .find(|resolved| resolved.confirmation == confirmation)
        {
            return Ok(resolved.acknowledgement.clone());
        }
        let exact_pending = state.pending_exchange.as_ref().is_some_and(|pending| {
            pending.request.operation == confirmation.operation
                && pending.request.route.route_sha256 == confirmation.route_sha256
                && pending.request.operation_id_sha256 == confirmation.operation_id_sha256
                && pending.request.request_sha256 == confirmation.request_sha256
                && pending.response.response_sha256 == confirmation.response_sha256
        });
        if state.permanent_hold || !exact_pending {
            state.permanent_hold = true;
            let acknowledgement = durable_test_confirmation_ack(
                &confirmation,
                DirectOperationCustodyHighWaterConfirmationDisposition::PermanentHold,
            );
            persist_durable_test_authority_state(root, &mut state)?;
            return Ok(acknowledgement);
        }
        let pending = state
            .pending_exchange
            .take()
            .context("test_durable_authority_exact_pending_disappeared")?;
        let acknowledgement = durable_test_confirmation_ack(
            &confirmation,
            DirectOperationCustodyHighWaterConfirmationDisposition::ResponseConfirmedExact,
        );
        state.resolved.push(DurableTestResolvedExchange {
            request: pending.request,
            response: pending.response,
            confirmation,
            acknowledgement: acknowledgement.clone(),
        });
        persist_durable_test_authority_state(root, &mut state)?;
        Ok(acknowledgement)
    }

    enum TestServerRead {
        Frame(Box<DirectOperationCustodyHighWaterClientFrameV1>),
        Timeout,
        Eof,
    }

    fn read_test_client_frame(stream: &mut UnixStream) -> Result<TestServerRead> {
        let mut prefix = [0u8; 4];
        match stream.read_exact(&mut prefix) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(TestServerRead::Timeout);
            }
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(TestServerRead::Eof);
            }
            Err(error) => return Err(error.into()),
        }
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            bail!("test_durable_authority_request_frame_size_denied");
        }
        let mut bytes = vec![0u8; length];
        stream.read_exact(&mut bytes)?;
        let frame: DirectOperationCustodyHighWaterClientFrameV1 = serde_json::from_slice(&bytes)?;
        if serde_json::to_vec(&frame)? != bytes {
            bail!("test_durable_authority_request_frame_noncanonical");
        }
        Ok(TestServerRead::Frame(Box::new(frame)))
    }

    fn write_test_server_frame(
        stream: &mut UnixStream,
        frame: &DirectOperationCustodyHighWaterServerFrameV1,
        truncate: bool,
    ) -> Result<()> {
        let bytes = serde_json::to_vec(frame)?;
        stream.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
        if truncate {
            stream.write_all(&bytes[..bytes.len() / 2])?;
        } else {
            stream.write_all(&bytes)?;
        }
        stream.flush()?;
        Ok(())
    }

    fn serve_durable_test_connection(
        mut stream: UnixStream,
        authority_root: &Path,
        control: &DurableTestAuthorityControl,
        stop: &AtomicBool,
    ) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_millis(50)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        while !stop.load(Ordering::SeqCst) {
            let frame = match read_test_client_frame(&mut stream)? {
                TestServerRead::Timeout => continue,
                TestServerRead::Eof => return Ok(()),
                TestServerRead::Frame(frame) => *frame,
            };
            match frame {
                DirectOperationCustodyHighWaterClientFrameV1::Operation(request) => {
                    let operation = request.operation;
                    let response = durable_test_process_operation(authority_root, request)?;
                    if let Some(fault) = control.take_matching_operation(operation) {
                        match fault {
                            DurableTestAuthorityFault::DropOperation(_) => {
                                control.cross_persisted_barrier();
                                return Ok(());
                            }
                            DurableTestAuthorityFault::TruncatedOperationFrame(_) => {
                                control.cross_persisted_barrier();
                                write_test_server_frame(
                                    &mut stream,
                                    &DirectOperationCustodyHighWaterServerFrameV1::OperationResponse(
                                        response,
                                    ),
                                    true,
                                )?;
                                return Ok(());
                            }
                            DurableTestAuthorityFault::FullOperationResponseBeforeClientRead(_) => {
                                write_test_server_frame(
                                    &mut stream,
                                    &DirectOperationCustodyHighWaterServerFrameV1::OperationResponse(
                                        response,
                                    ),
                                    false,
                                )?;
                                // This barrier is deliberately after the full
                                // response frame has reached the Unix socket,
                                // while the test client remains alive but has
                                // not issued its first read.
                                control.cross_persisted_barrier();
                                return Ok(());
                            }
                            DurableTestAuthorityFault::ConfirmationAckLost => {
                                unreachable!("operation matcher excludes confirmation fault")
                            }
                        }
                    }
                    write_test_server_frame(
                        &mut stream,
                        &DirectOperationCustodyHighWaterServerFrameV1::OperationResponse(response),
                        false,
                    )?;
                }
                DirectOperationCustodyHighWaterClientFrameV1::ConfirmResponse(confirmation) => {
                    let acknowledgement =
                        durable_test_process_confirmation(authority_root, confirmation)?;
                    if control.take_confirmation().is_some() {
                        control.cross_persisted_barrier();
                        return Ok(());
                    }
                    write_test_server_frame(
                        &mut stream,
                        &DirectOperationCustodyHighWaterServerFrameV1::ConfirmResponseAck(
                            acknowledgement,
                        ),
                        false,
                    )?;
                }
            }
        }
        Ok(())
    }

    struct DurableTestAuthorityServer {
        socket_path: PathBuf,
        control: Arc<DurableTestAuthorityControl>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<Result<()>>>,
    }

    impl DurableTestAuthorityServer {
        fn start(authority_root: &Path, socket_path: &Path) -> Result<Self> {
            load_durable_test_authority_state(authority_root)?;
            if socket_path.exists() {
                fs::remove_file(socket_path)?;
            }
            let listener = UnixListener::bind(socket_path)?;
            fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
            listener.set_nonblocking(true)?;
            let authority_root = authority_root.to_path_buf();
            let socket_path_owned = socket_path.to_path_buf();
            let control = Arc::new(DurableTestAuthorityControl::new());
            let thread_control = Arc::clone(&control);
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let thread = thread::spawn(move || -> Result<()> {
                while !thread_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            serve_durable_test_connection(
                                stream,
                                &authority_root,
                                &thread_control,
                                &thread_stop,
                            )?;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Ok(())
            });
            Ok(Self {
                socket_path: socket_path_owned,
                control,
                stop,
                thread: Some(thread),
            })
        }

        fn arm(&self, fault: DurableTestAuthorityFault) {
            self.control.arm(fault);
        }

        fn wait_until_persisted(&self) {
            self.control.wait_until_persisted();
        }

        fn release(&self) {
            self.control.release();
        }

        fn shutdown(mut self) -> Result<()> {
            self.stop.store(true, Ordering::SeqCst);
            let _ = UnixStream::connect(&self.socket_path);
            if let Some(thread) = self.thread.take() {
                thread
                    .join()
                    .map_err(|_| anyhow!("test_durable_authority_thread_panicked"))??;
            }
            if self.socket_path.exists() {
                fs::remove_file(&self.socket_path)?;
            }
            Ok(())
        }
    }

    impl Drop for DurableTestAuthorityServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = UnixStream::connect(&self.socket_path);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            let _ = fs::remove_file(&self.socket_path);
        }
    }

    struct TestSocketWireTransport {
        stream: UnixStream,
    }

    impl TestSocketWireTransport {
        fn connect(socket_path: &Path) -> Result<Self> {
            let stream = UnixStream::connect(socket_path)?;
            // These are deadlock guards, not protocol deadlines.  The tests
            // deliberately perform many fsync-heavy authorities in parallel,
            // so a two-second wall-clock cutoff is too small on a loaded host.
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(10)))?;
            Ok(Self { stream })
        }

        fn exchange_frame(
            &mut self,
            frame: DirectOperationCustodyHighWaterClientFrameV1,
        ) -> Result<DirectOperationCustodyHighWaterServerFrameV1> {
            let bytes = serde_json::to_vec(&frame)?;
            self.stream
                .write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
            self.stream.write_all(&bytes)?;
            self.stream.flush()?;
            let mut prefix = [0u8; 4];
            self.stream.read_exact(&mut prefix)?;
            let length = u32::from_be_bytes(prefix) as usize;
            if length == 0 || length > MAX_FRAME_BYTES {
                bail!("test_durable_client_response_frame_size_denied");
            }
            let mut response = vec![0u8; length];
            self.stream.read_exact(&mut response)?;
            let frame: DirectOperationCustodyHighWaterServerFrameV1 =
                serde_json::from_slice(&response)?;
            if serde_json::to_vec(&frame)? != response {
                bail!("test_durable_client_response_frame_noncanonical");
            }
            Ok(frame)
        }

        fn send_operation_without_read(
            &mut self,
            request: &DirectOperationCustodyHighWaterRequestV1,
        ) -> Result<()> {
            let frame = DirectOperationCustodyHighWaterClientFrameV1::Operation(request.clone());
            let bytes = serde_json::to_vec(&frame)?;
            self.stream
                .write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
            self.stream.write_all(&bytes)?;
            self.stream.flush()?;
            Ok(())
        }
    }

    impl WireTransport for TestSocketWireTransport {
        fn operation(
            &mut self,
            request: &DirectOperationCustodyHighWaterRequestV1,
        ) -> Result<DirectOperationCustodyHighWaterResponseV1> {
            match self.exchange_frame(DirectOperationCustodyHighWaterClientFrameV1::Operation(
                request.clone(),
            ))? {
                DirectOperationCustodyHighWaterServerFrameV1::OperationResponse(response) => {
                    Ok(response)
                }
                _ => bail!("test_durable_client_operation_frame_kind_denied"),
            }
        }

        fn confirm_response(
            &mut self,
            confirmation: &DirectOperationCustodyHighWaterResponseConfirmationV1,
        ) -> Result<DirectOperationCustodyHighWaterResponseConfirmationAckV1> {
            match self.exchange_frame(
                DirectOperationCustodyHighWaterClientFrameV1::ConfirmResponse(confirmation.clone()),
            )? {
                DirectOperationCustodyHighWaterServerFrameV1::ConfirmResponseAck(response) => {
                    Ok(response)
                }
                _ => bail!("test_durable_client_confirmation_frame_kind_denied"),
            }
        }
    }

    struct DurableSocketFixture {
        _temporary: TempDir,
        authority_root: PathBuf,
        client_journal_root: PathBuf,
        socket_path: PathBuf,
    }

    impl DurableSocketFixture {
        fn new(committed: DirectOperationCustodyHead) -> Self {
            let temporary = TempDir::new().unwrap();
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let authority_root = temporary.path().join("authority");
            let client_journal_root = temporary.path().join("client-journal");
            let socket_path = temporary.path().join("authority.sock");
            initialise_durable_test_authority(&authority_root, committed).unwrap();
            fs::create_dir(&client_journal_root).unwrap();
            fs::set_permissions(&client_journal_root, fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                _temporary: temporary,
                authority_root,
                client_journal_root,
                socket_path,
            }
        }

        fn start_server(&self) -> DurableTestAuthorityServer {
            DurableTestAuthorityServer::start(&self.authority_root, &self.socket_path).unwrap()
        }

        fn connect(&self) -> Result<DurableAuthorityTransport<TestSocketWireTransport>> {
            let wire = TestSocketWireTransport::connect(&self.socket_path)?;
            DurableAuthorityTransport::connect_for_test(wire, &self.client_journal_root, unsafe {
                libc::geteuid()
            })
        }

        fn connect_with_capacity(
            &self,
            resolved_capacity: usize,
        ) -> Result<DurableAuthorityTransport<TestSocketWireTransport>> {
            let wire = TestSocketWireTransport::connect(&self.socket_path)?;
            DurableAuthorityTransport::connect_for_test_with_capacity(
                wire,
                &self.client_journal_root,
                unsafe { libc::geteuid() },
                resolved_capacity,
            )
        }

        fn state(&self) -> DurableTestAuthorityState {
            load_durable_test_authority_state(&self.authority_root).unwrap()
        }

        fn client_hold_exists(&self) -> bool {
            let root_path_sha256 =
                sha256_bytes(self.client_journal_root.as_os_str().as_encoded_bytes());
            self.client_journal_root
                .parent()
                .unwrap()
                .join(format!(
                    ".direct-operation-custody-hold-{}.json",
                    &root_path_sha256[..24]
                ))
                .is_file()
        }

        fn active_operation_path(&self) -> PathBuf {
            let mut entries = fs::read_dir(self.client_journal_root.join("active"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            assert_eq!(entries.len(), 1);
            entries.pop().unwrap()
        }

        fn only_resolved_operation_path(&self) -> PathBuf {
            let mut entries = fs::read_dir(self.client_journal_root.join("resolved"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            assert_eq!(entries.len(), 1);
            entries.pop().unwrap()
        }
    }

    fn request(
        operation: DirectOperationCustodyHighWaterOperation,
        current: DirectOperationCustodyHead,
        proposed: Option<DirectOperationCustodyHead>,
        transition: Option<String>,
        nonce_label: &str,
    ) -> DirectOperationCustodyHighWaterRequestV1 {
        DirectOperationCustodyHighWaterRequestV1::build(
            operation,
            product_route().unwrap(),
            current,
            proposed,
            transition,
            digest(nonce_label),
        )
        .unwrap()
    }

    fn operation_request(
        operation: DirectOperationCustodyHighWaterOperation,
        initial: &DirectOperationCustodyHead,
        successor: &DirectOperationCustodyHead,
        nonce_label: &str,
    ) -> DirectOperationCustodyHighWaterRequestV1 {
        let transition = transition_sha256(&product_route().unwrap(), initial, successor);
        match operation {
            DirectOperationCustodyHighWaterOperation::Reconcile
            | DirectOperationCustodyHighWaterOperation::Observe => {
                request(operation, initial.clone(), None, None, nonce_label)
            }
            DirectOperationCustodyHighWaterOperation::Prepare => request(
                operation,
                initial.clone(),
                Some(successor.clone()),
                Some(transition),
                nonce_label,
            ),
            DirectOperationCustodyHighWaterOperation::Commit => request(
                operation,
                successor.clone(),
                Some(successor.clone()),
                Some(transition),
                nonce_label,
            ),
        }
    }

    fn confirm_prepare_for_commit(
        transport: &mut DurableAuthorityTransport<TestSocketWireTransport>,
        initial: &DirectOperationCustodyHead,
        successor: &DirectOperationCustodyHead,
        nonce_label: &str,
    ) {
        let prepare = operation_request(
            DirectOperationCustodyHighWaterOperation::Prepare,
            initial,
            successor,
            nonce_label,
        );
        AuthorityTransport::exchange(transport, &prepare).unwrap();
    }

    fn digest(label: &str) -> String {
        sha256_bytes(label.as_bytes())
    }

    fn head(generation: u64, label: &str) -> DirectOperationCustodyHead {
        DirectOperationCustodyHead::new(
            generation,
            if generation == 0 {
                trillionnium_os_types::direct_operation_custody_high_water::DIRECT_OPERATION_CUSTODY_ZERO_SHA256.to_string()
            } else {
                digest(label)
            },
        )
        .unwrap()
    }

    #[test]
    fn durable_socket_unreceipted_response_loss_holds_every_operation_after_restart() {
        for operation in [
            DirectOperationCustodyHighWaterOperation::Reconcile,
            DirectOperationCustodyHighWaterOperation::Observe,
            DirectOperationCustodyHighWaterOperation::Prepare,
            DirectOperationCustodyHighWaterOperation::Commit,
        ] {
            let initial = head(0, "unused");
            let successor = head(1, "successor");
            let fixture = DurableSocketFixture::new(initial.clone());
            let server = fixture.start_server();
            let mut transport = fixture.connect().unwrap();
            if operation == DirectOperationCustodyHighWaterOperation::Commit {
                confirm_prepare_for_commit(
                    &mut transport,
                    &initial,
                    &successor,
                    "prepare-before-commit-loss",
                );
            }
            let request = operation_request(
                operation,
                &initial,
                &successor,
                &format!("{operation:?}-loss"),
            );
            server.arm(DurableTestAuthorityFault::DropOperation(operation));
            let operation_id = request.operation_id_sha256.clone();
            let worker = thread::spawn(move || {
                transport.crash_test_after_operation_without_response_receipt(&request)
            });
            server.wait_until_persisted();
            let persisted = fixture.state();
            assert_eq!(
                persisted
                    .pending_exchange
                    .as_ref()
                    .unwrap()
                    .request
                    .operation_id_sha256,
                operation_id
            );
            assert!(!persisted.permanent_hold);
            server.release();
            assert!(worker.join().unwrap().is_err());
            server.shutdown().unwrap();

            let restarted = fixture.start_server();
            let reconnect = fixture.connect();
            assert!(
                reconnect.is_err(),
                "{operation:?} unexpectedly recovered; active={:?}; state={:?}",
                fs::read_dir(fixture.client_journal_root.join("active"))
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<Vec<_>>(),
                fixture.state()
            );
            let held = fixture.state();
            assert!(held.permanent_hold);
            assert!(fixture.client_hold_exists());
            restarted.shutdown().unwrap();
        }
    }

    #[test]
    fn durable_socket_confirmation_ack_loss_recovers_only_from_exact_receipt_and_resolved_state() {
        let initial = head(0, "unused");
        let successor = head(1, "unused-successor");
        let fixture = DurableSocketFixture::new(initial.clone());
        let server = fixture.start_server();
        let mut transport = fixture.connect().unwrap();
        let request = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "confirmation-ack-loss",
        );
        let operation_id = request.operation_id_sha256.clone();
        server.arm(DurableTestAuthorityFault::ConfirmationAckLost);
        let worker = thread::spawn(move || {
            transport.crash_test_after_confirmation_ack_without_receipt(&request)
        });
        server.wait_until_persisted();
        let persisted = fixture.state();
        assert!(persisted.pending_exchange.is_none());
        assert_eq!(persisted.resolved.len(), 1);
        assert_eq!(
            persisted.resolved[0].request.operation_id_sha256,
            operation_id
        );
        server.release();
        assert!(worker.join().unwrap().is_err());
        server.shutdown().unwrap();

        let restarted = fixture.start_server();
        let recovered = fixture.connect().unwrap();
        drop(recovered);
        assert!(!fixture.state().permanent_hold);
        assert!(!fixture.client_hold_exists());
        let active = fs::read_dir(fixture.client_journal_root.join("active"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert!(active.is_empty(), "active after exact recovery: {active:?}");
        assert_eq!(
            fs::read_dir(fixture.client_journal_root.join("resolved"))
                .unwrap()
                .count(),
            1
        );
        restarted.shutdown().unwrap();
    }

    #[test]
    fn durable_socket_live_confirmation_ack_io_loss_preserves_exact_retry_without_local_hold() {
        let initial = head(0, "unused");
        let successor = head(1, "unused-successor");
        let fixture = DurableSocketFixture::new(initial.clone());
        let server = fixture.start_server();
        let mut transport = fixture.connect().unwrap();
        let request = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "live-confirmation-ack-loss",
        );
        server.arm(DurableTestAuthorityFault::ConfirmationAckLost);
        let worker = thread::spawn(move || AuthorityTransport::exchange(&mut transport, &request));
        server.wait_until_persisted();
        assert_eq!(fixture.state().resolved.len(), 1);
        server.release();
        let error = worker.join().unwrap().unwrap_err();
        assert!(is_exact_confirmation_retry_required(&error));
        assert!(!fixture.client_hold_exists());
        server.shutdown().unwrap();

        let restarted = fixture.start_server();
        let recovered = fixture.connect().unwrap();
        drop(recovered);
        assert!(!fixture.client_hold_exists());
        assert!(
            fs::read_dir(fixture.client_journal_root.join("active"))
                .unwrap()
                .next()
                .is_none()
        );
        restarted.shutdown().unwrap();
    }

    #[test]
    fn resolved_capacity_is_reserved_before_any_authority_io() {
        let initial = head(0, "unused");
        let successor = head(1, "unused-successor");
        let fixture = DurableSocketFixture::new(initial.clone());
        let server = fixture.start_server();
        let mut transport = fixture.connect_with_capacity(1).unwrap();
        let first = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "capacity-first",
        );
        AuthorityTransport::exchange(&mut transport, &first).unwrap();
        let before = fixture.state();
        assert_eq!(before.resolved.len(), 1);
        let second = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "capacity-second",
        );
        let error = AuthorityTransport::exchange(&mut transport, &second).unwrap_err();
        assert!(error.to_string().contains("capacity_pre_authority_hold"));
        assert_eq!(fixture.state(), before);
        assert!(!fixture.client_hold_exists());
        server.shutdown().unwrap();
    }

    #[test]
    fn journal_root_child_and_operation_rebinds_fail_and_hold_outside_detached_root() {
        let initial = head(0, "unused");
        let successor = head(1, "unused-successor");

        let root_fixture = DurableSocketFixture::new(initial.clone());
        let root_server = root_fixture.start_server();
        let mut root_transport = root_fixture.connect().unwrap();
        let root_request = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "root-rebind",
        );
        root_transport
            .crash_test_after_response_receipt(&root_request)
            .unwrap();
        let detached_root = root_fixture
            .client_journal_root
            .with_file_name("client-journal.detached");
        fs::rename(&root_fixture.client_journal_root, &detached_root).unwrap();
        fs::create_dir(&root_fixture.client_journal_root).unwrap();
        fs::set_permissions(
            &root_fixture.client_journal_root,
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(root_transport.journal.revalidate().is_err());
        assert!(
            root_transport
                .journal
                .mark_permanent_hold(Some(&root_request.operation_id_sha256), "root_rebound")
                .is_err()
        );
        assert!(root_fixture.client_hold_exists());
        drop(root_transport);
        root_server.shutdown().unwrap();

        let child_fixture = DurableSocketFixture::new(initial.clone());
        let child_server = child_fixture.start_server();
        let mut child_transport = child_fixture.connect().unwrap();
        let child_request = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "active-rebind",
        );
        child_transport
            .crash_test_after_response_receipt(&child_request)
            .unwrap();
        let active = child_fixture.client_journal_root.join("active");
        fs::rename(
            &active,
            child_fixture.client_journal_root.join("active.detached"),
        )
        .unwrap();
        fs::create_dir(&active).unwrap();
        fs::set_permissions(&active, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(child_transport.journal.revalidate().is_err());
        assert!(
            child_transport
                .journal
                .mark_permanent_hold(Some(&child_request.operation_id_sha256), "active_rebound")
                .is_err()
        );
        assert!(child_fixture.client_hold_exists());
        drop(child_transport);
        child_server.shutdown().unwrap();

        let operation_fixture = DurableSocketFixture::new(initial);
        let operation_server = operation_fixture.start_server();
        let mut operation_transport = operation_fixture.connect().unwrap();
        let operation_request = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &head(0, "unused"),
            &successor,
            "operation-rebind",
        );
        operation_transport
            .crash_test_after_response_receipt(&operation_request)
            .unwrap();
        let operation_path = operation_fixture.active_operation_path();
        let detached_operation = operation_path.with_file_name("detached-operation");
        fs::rename(&operation_path, &detached_operation).unwrap();
        fs::create_dir(&operation_path).unwrap();
        fs::set_permissions(&operation_path, fs::Permissions::from_mode(0o700)).unwrap();
        for entry in fs::read_dir(&detached_operation).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), operation_path.join(entry.file_name())).unwrap();
        }
        assert!(
            operation_transport
                .journal
                .revalidate_active_operation(&operation_request.operation_id_sha256)
                .is_err()
        );
        drop(operation_transport);
        operation_server.shutdown().unwrap();
    }

    #[test]
    fn permanent_hold_final_rebind_barrier_rejects_parent_and_root_name_swaps() {
        let owner_uid = unsafe { libc::geteuid() };

        let root_temporary = TempDir::new().unwrap();
        fs::set_permissions(root_temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root_parent = root_temporary.path().join("root-parent");
        fs::create_dir(&root_parent).unwrap();
        fs::set_permissions(&root_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root_path = root_parent.join("client-journal");
        let mut root_journal = ClientAttemptJournal::open(&root_path, owner_uid).unwrap();
        let root_hold_name = root_journal
            .external_hold_name
            .to_str()
            .unwrap()
            .to_string();
        let root_reached = Arc::new(Barrier::new(2));
        let root_release = Arc::new(Barrier::new(2));
        root_journal.hold_pre_return_barrier = Some(Box::new({
            let reached = Arc::clone(&root_reached);
            let release = Arc::clone(&root_release);
            move || {
                reached.wait();
                release.wait();
            }
        }));
        let root_worker = thread::spawn(move || {
            let result = root_journal.mark_permanent_hold(None, "root_pre_return_rebind");
            (result, root_journal)
        });
        root_reached.wait();
        let root_hold_path = root_parent.join(&root_hold_name);
        assert!(root_hold_path.exists());
        let detached_root = root_parent.join("client-journal.detached");
        fs::rename(&root_path, &detached_root).unwrap();
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        root_release.wait();
        let (root_result, _) = root_worker.join().unwrap();
        assert!(format!("{:#}", root_result.unwrap_err()).contains("root_path_rebound"));
        assert!(root_hold_path.exists());

        let parent_temporary = TempDir::new().unwrap();
        fs::set_permissions(parent_temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let parent_path = parent_temporary.path().join("journal-parent");
        fs::create_dir(&parent_path).unwrap();
        fs::set_permissions(&parent_path, fs::Permissions::from_mode(0o700)).unwrap();
        let journal_path = parent_path.join("client-journal");
        let mut parent_journal = ClientAttemptJournal::open(&journal_path, owner_uid).unwrap();
        let parent_hold_name = parent_journal
            .external_hold_name
            .to_str()
            .unwrap()
            .to_string();
        let parent_reached = Arc::new(Barrier::new(2));
        let parent_release = Arc::new(Barrier::new(2));
        parent_journal.hold_pre_return_barrier = Some(Box::new({
            let reached = Arc::clone(&parent_reached);
            let release = Arc::clone(&parent_release);
            move || {
                reached.wait();
                release.wait();
            }
        }));
        let parent_worker = thread::spawn(move || {
            let result = parent_journal.mark_permanent_hold(None, "parent_pre_return_rebind");
            (result, parent_journal)
        });
        parent_reached.wait();
        assert!(parent_path.join(&parent_hold_name).exists());
        let detached_parent = parent_temporary.path().join("journal-parent.detached");
        fs::rename(&parent_path, &detached_parent).unwrap();
        fs::create_dir(&parent_path).unwrap();
        fs::set_permissions(&parent_path, fs::Permissions::from_mode(0o700)).unwrap();
        parent_release.wait();
        let (parent_result, _) = parent_worker.join().unwrap();
        assert!(format!("{:#}", parent_result.unwrap_err()).contains("parent_path_rebound"));
        assert!(detached_parent.join(parent_hold_name).exists());
    }

    #[test]
    fn durable_socket_fully_written_but_unreceipted_response_has_no_delivery_oracle() {
        let initial = head(0, "unused");
        let successor = head(1, "unused-successor");
        let fixture = DurableSocketFixture::new(initial.clone());
        let server = fixture.start_server();
        let mut transport = fixture.connect().unwrap();
        let request = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "fully-written-response-before-client-crash",
        );
        transport
            .crash_test_after_operation_without_response_receipt(&request)
            .unwrap();
        drop(transport);
        assert!(fixture.state().pending_exchange.is_some());
        server.shutdown().unwrap();

        let restarted = fixture.start_server();
        assert!(fixture.connect().is_err());
        assert!(fixture.state().permanent_hold);
        assert!(fixture.client_hold_exists());
        restarted.shutdown().unwrap();
    }

    #[test]
    fn durable_socket_full_response_before_first_client_read_holds_after_both_restarts() {
        let initial = head(0, "unused");
        let successor = head(1, "unused-successor");
        let fixture = DurableSocketFixture::new(initial.clone());
        let server = fixture.start_server();
        let mut transport = fixture.connect().unwrap();
        let request = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "full-response-before-first-read",
        );
        server.arm(
            DurableTestAuthorityFault::FullOperationResponseBeforeClientRead(
                DirectOperationCustodyHighWaterOperation::Observe,
            ),
        );
        let release_client = Arc::new(AtomicBool::new(false));
        let client_release = Arc::clone(&release_client);
        let worker = thread::spawn(move || -> Result<()> {
            transport.journal.begin(&request)?;
            transport.wire.send_operation_without_read(&request)?;
            while !client_release.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(1));
            }
            // Drop without ever reading a response prefix or payload.
            drop(transport);
            Ok(())
        });
        server.wait_until_persisted();
        assert!(fixture.state().pending_exchange.is_some());
        release_client.store(true, Ordering::SeqCst);
        worker.join().unwrap().unwrap();
        server.release();
        server.shutdown().unwrap();

        let restarted = fixture.start_server();
        assert!(fixture.connect().is_err());
        assert!(fixture.state().permanent_hold);
        assert!(fixture.client_hold_exists());
        restarted.shutdown().unwrap();
    }

    #[test]
    fn durable_socket_truncated_response_and_client_journal_damage_fail_closed() {
        let initial = head(0, "unused");
        let successor = head(1, "unused-successor");

        let truncated = DurableSocketFixture::new(initial.clone());
        let truncated_server = truncated.start_server();
        let mut transport = truncated.connect().unwrap();
        let truncated_request = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "truncated-response",
        );
        truncated_server.arm(DurableTestAuthorityFault::TruncatedOperationFrame(
            DirectOperationCustodyHighWaterOperation::Observe,
        ));
        let worker =
            thread::spawn(move || AuthorityTransport::exchange(&mut transport, &truncated_request));
        truncated_server.wait_until_persisted();
        assert!(truncated.state().pending_exchange.is_some());
        truncated_server.release();
        assert!(worker.join().unwrap().is_err());
        assert!(truncated.client_hold_exists());
        truncated_server.shutdown().unwrap();

        let corrupt_receipt = DurableSocketFixture::new(initial.clone());
        let corrupt_receipt_server = corrupt_receipt.start_server();
        let mut transport = corrupt_receipt.connect().unwrap();
        let receipt_request = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "corrupt-response-receipt",
        );
        transport
            .crash_test_after_response_receipt(&receipt_request)
            .unwrap();
        drop(transport);
        let response_path = corrupt_receipt
            .active_operation_path()
            .join("response-v2.json");
        fs::write(&response_path, b"{}\n").unwrap();
        File::open(&response_path).unwrap().sync_all().unwrap();
        assert!(corrupt_receipt.connect().is_err());
        assert!(corrupt_receipt.client_hold_exists());
        corrupt_receipt_server.shutdown().unwrap();

        let rolled_back_receipt = DurableSocketFixture::new(initial.clone());
        let rolled_back_server = rolled_back_receipt.start_server();
        let mut transport = rolled_back_receipt.connect().unwrap();
        let rollback_request = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "rolled-back-response-receipt",
        );
        transport
            .crash_test_after_response_receipt(&rollback_request)
            .unwrap();
        drop(transport);
        fs::remove_file(
            rolled_back_receipt
                .active_operation_path()
                .join("response-v2.json"),
        )
        .unwrap();
        File::open(rolled_back_receipt.client_journal_root.join("active"))
            .unwrap()
            .sync_all()
            .unwrap();
        assert!(rolled_back_receipt.connect().is_err());
        assert!(rolled_back_receipt.client_hold_exists());
        assert!(rolled_back_receipt.state().permanent_hold);
        rolled_back_server.shutdown().unwrap();

        let corrupt_archive = DurableSocketFixture::new(initial.clone());
        let corrupt_archive_server = corrupt_archive.start_server();
        let mut transport = corrupt_archive.connect().unwrap();
        let archived_request = operation_request(
            DirectOperationCustodyHighWaterOperation::Observe,
            &initial,
            &successor,
            "corrupt-resolved-archive",
        );
        AuthorityTransport::exchange(&mut transport, &archived_request).unwrap();
        drop(transport);
        let ack_path = corrupt_archive
            .only_resolved_operation_path()
            .join("confirmation-ack-v2.json");
        fs::write(&ack_path, b"{}\n").unwrap();
        File::open(&ack_path).unwrap().sync_all().unwrap();
        assert!(corrupt_archive.connect().is_err());
        assert!(corrupt_archive.client_hold_exists());
        corrupt_archive_server.shutdown().unwrap();
    }

    #[test]
    fn durable_socket_full_transition_and_authority_state_restart_are_exact() {
        let initial = head(0, "unused");
        let successor = head(1, "successor");
        let fixture = DurableSocketFixture::new(initial.clone());
        let server = fixture.start_server();
        let transport = fixture.connect().unwrap();
        let verified = establish(
            Box::new(transport),
            product_route().unwrap(),
            initial.clone(),
        )
        .unwrap();
        let verified = verified
            .prepare(successor.clone())
            .unwrap()
            .commit(&successor)
            .unwrap()
            .reconcile(&successor)
            .unwrap();
        assert_eq!(verified.committed_head(), &successor);
        drop(verified);
        assert_eq!(fixture.state().committed, successor);
        server.shutdown().unwrap();

        let restarted = fixture.start_server();
        let transport = fixture.connect().unwrap();
        let _verified = establish(
            Box::new(transport),
            product_route().unwrap(),
            successor.clone(),
        )
        .unwrap();
        restarted.shutdown().unwrap();

        let rollback = DurableSocketFixture::new(successor);
        let rollback_server = rollback.start_server();
        let transport = rollback.connect().unwrap();
        assert!(establish(Box::new(transport), product_route().unwrap(), initial).is_err());
        assert!(rollback.state().permanent_hold);
        assert!(rollback.client_hold_exists());
        rollback_server.shutdown().unwrap();
    }

    #[test]
    fn durable_authority_corrupt_or_incomplete_state_never_restarts() {
        let fixture = DurableSocketFixture::new(head(0, "unused"));
        fs::write(
            durable_test_authority_state_path(&fixture.authority_root),
            b"{}\n",
        )
        .unwrap();
        assert!(
            DurableTestAuthorityServer::start(&fixture.authority_root, &fixture.socket_path)
                .is_err()
        );

        let fixture = DurableSocketFixture::new(head(0, "unused"));
        fs::write(
            fixture.authority_root.join(TEST_AUTHORITY_NEXT_FILE),
            b"partial",
        )
        .unwrap();
        assert!(
            DurableTestAuthorityServer::start(&fixture.authority_root, &fixture.socket_path)
                .is_err()
        );
    }

    #[test]
    fn semantic_typestate_reconciles_prepare_and_commit_crash_boundaries() {
        let initial = head(0, "unused");
        let successor = head(1, "successor");
        let authority = TestDirectOperationCustodyHighWaterAuthority::new(initial.clone());
        let prepared = authority
            .connect(initial.clone())
            .unwrap()
            .prepare(successor.clone())
            .unwrap();
        drop(prepared);
        assert_eq!(
            authority.connect(initial.clone()).unwrap().committed_head(),
            &initial
        );

        let authority = TestDirectOperationCustodyHighWaterAuthority::new(initial.clone());
        let prepared = authority
            .connect(initial.clone())
            .unwrap()
            .prepare(successor.clone())
            .unwrap();
        drop(prepared);
        assert_eq!(
            authority
                .connect(successor.clone())
                .unwrap()
                .committed_head(),
            &successor
        );

        let authority = TestDirectOperationCustodyHighWaterAuthority::new(initial.clone());
        let committed = authority
            .connect(initial)
            .unwrap()
            .prepare(successor.clone())
            .unwrap()
            .commit(&successor)
            .unwrap();
        drop(committed);
        assert_eq!(
            authority
                .connect(successor.clone())
                .unwrap()
                .committed_head(),
            &successor
        );
    }

    #[test]
    fn rollback_cross_domain_and_unknown_results_permanently_hold() {
        let initial = head(0, "unused");
        let committed = head(2, "committed");
        let authority = TestDirectOperationCustodyHighWaterAuthority::new(committed);
        assert!(authority.connect(head(1, "rollback")).is_err());
        assert!(authority.is_permanent_hold());

        let authority = TestDirectOperationCustodyHighWaterAuthority::new(initial.clone());
        assert!(authority.connect_foreign_route(initial.clone()).is_err());
        assert!(authority.is_permanent_hold());

        for (operation, after_apply) in [
            (DirectOperationCustodyHighWaterOperation::Reconcile, false),
            (DirectOperationCustodyHighWaterOperation::Reconcile, true),
            (DirectOperationCustodyHighWaterOperation::Observe, false),
            (DirectOperationCustodyHighWaterOperation::Observe, true),
            (DirectOperationCustodyHighWaterOperation::Prepare, false),
            (DirectOperationCustodyHighWaterOperation::Prepare, true),
            (DirectOperationCustodyHighWaterOperation::Commit, false),
            (DirectOperationCustodyHighWaterOperation::Commit, true),
        ] {
            let authority = TestDirectOperationCustodyHighWaterAuthority::new(initial.clone());
            if matches!(
                operation,
                DirectOperationCustodyHighWaterOperation::Reconcile
                    | DirectOperationCustodyHighWaterOperation::Observe
            ) {
                authority.inject_fault(if after_apply {
                    TestAuthorityFault::OutcomeUnknownAfterApply(operation)
                } else {
                    TestAuthorityFault::OutcomeUnknownBeforeApply(operation)
                });
                assert!(authority.connect(initial.clone()).is_err());
            } else {
                let verified = authority.connect(initial.clone()).unwrap();
                let successor = head(1, "successor");
                if operation == DirectOperationCustodyHighWaterOperation::Prepare {
                    authority.inject_fault(if after_apply {
                        TestAuthorityFault::OutcomeUnknownAfterApply(operation)
                    } else {
                        TestAuthorityFault::OutcomeUnknownBeforeApply(operation)
                    });
                    assert!(verified.prepare(successor).is_err());
                } else {
                    let prepared = verified.prepare(successor.clone()).unwrap();
                    authority.inject_fault(if after_apply {
                        TestAuthorityFault::OutcomeUnknownAfterApply(operation)
                    } else {
                        TestAuthorityFault::OutcomeUnknownBeforeApply(operation)
                    });
                    assert!(prepared.commit(&successor).is_err());
                }
            }
            assert!(authority.is_permanent_hold());
        }
    }

    #[test]
    fn journal_is_append_only_no_replace_and_route_is_distinct() {
        assert_eq!(
            FIXED_AUTHORITY_SOCKET_PATH,
            "/run/trillionnium/direct-operation-custody-high-water-v2.sock"
        );
        assert_ne!(
            FIXED_AUTHORITY_SOCKET_PATH,
            crate::direct_tool_call_high_water::FIXED_AUTHORITY_SOCKET_PATH
        );
        let source = include_str!("high_water.rs");
        assert!(source.contains("SO_PEERCRED"));
        assert!(source.contains("SO_PEERSEC"));
        assert!(source.contains("RENAME_NOREPLACE"));
        assert!(!source.contains(&["unlink", "at("].concat()));
        assert!(!source.contains(&["std", "::", "env"].concat()));
        assert!(!source.contains(&["connect_product", "(path"].concat()));
    }
}
