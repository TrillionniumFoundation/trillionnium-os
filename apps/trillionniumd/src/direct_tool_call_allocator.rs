//! Inert daemon-owned durable logical tool-call allocator.
//!
//! The allocator gives each OS-observed provider delivery one root-authored
//! `(os_tool_call_id, adapter_effect_ordinal)` and durably binds the eventual
//! canonical request digest to that identity. Equal canonical bytes under a
//! new delivery are a new logical effect; an exact retry of one delivery
//! recovers the original allocation.
//!
//! The adapter-side capabilities are constructible only by the dedicated
//! kernel-authenticated session handler. A fixed external high-water client,
//! move-only product allocator constructor and capability-gated listener bind
//! now exist, but the upstream logical-delivery capability remains
//! product-uninhabited and main instantiates none of them. Current Codex MCP
//! provider transports therefore cannot preissue a delivery, so product
//! calls remain pre-effect HOLD. Unit tests exercise the full persistence
//! state machine without treating provider/model IDs as authority.
//! The capability-lease replay-sync binary is unrelated: it does not activate
//! Android System API or Accessibility operation epochs and is not accepted as
//! an allocation, replay, acknowledgement, or high-water authority here.

use std::collections::HashSet;
use std::convert::Infallible;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trillionnium_os_types::direct_operation::{
    DirectOperationAdapter, DirectOperationBinding, DirectOperationOuterEvidence,
    DirectOperationToolCallAllocationRequestV3, DirectOperationToolCallCommitReceiptV3,
    DirectOperationToolCallDeliveryV3, DirectOperationToolCallEnvelopeV3,
    DirectOperationToolCallPreparedAckV3, MAX_OUTER_ACK_EVIDENCE, OS_TOOL_CALL_ID_PREFIX,
    TOOL_CALL_ENVELOPE_V3_SCHEMA,
};
use trillionnium_os_types::direct_operation_tool_call_transport as transport_contract;
use trillionnium_os_types::sha256_bytes;

#[cfg(test)]
use crate::direct_tool_call_high_water::TestDirectToolCallHighWaterAuthority;
use crate::direct_tool_call_high_water::{
    DirectToolCallHighWaterHeadV1, DirectToolCallHighWaterRouteV1, VerifiedDirectToolCallHighWater,
};

const STORE_SCHEMA: &str = "trillionnium.direct-tool-call-allocator-store.v1";
const RECORD_SCHEMA: &str = "trillionnium.direct-tool-call-allocator-record.v1";
const MAX_STORE_BYTES: usize = 2 * 1024 * 1024;
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const STORE_DIGEST_DOMAIN: &[u8] = b"trillionnium.direct-tool-call-allocator-store.v1";
const RECORD_DIGEST_DOMAIN: &[u8] = b"trillionnium.direct-tool-call-allocator-record.v1";
const TOKEN_DIGEST_DOMAIN: &[u8] = b"trillionnium.direct-tool-call-os-token.v1";
const ROLLBACK_HIGH_WATER_AUTHORITY_ABSENT_PRODUCT_HOLD: &str = "absent_product_hold";
const ROLLBACK_HIGH_WATER_AUTHORITY_FIXED_SOCKET_V1: &str =
    "fixed_os_owned_direct_operation_high_water_socket_v1";
#[cfg(feature = "p0-launch-package-device-conformance")]
const P0_USERDEBUG_PREDISPATCH_CUSTODY_AUTHORITY_V1: &str =
    "p0_userdebug_predispatch_custody_authority_v1";
const PRODUCT_ALLOCATOR_ROOT: &str =
    "/var/lib/trillionnium/agent-tools/direct-operation-tool-call-allocator-v1";
const PRODUCT_OWNER_UID: u32 = 0;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// No safe product constructor exists yet. A future provider bridge must
/// authenticate one exact OS-observed logical delivery before it may obtain
/// this capability. A provider/model call ID cannot construct it.
#[allow(dead_code)]
enum VerifiedDaemonLogicalDeliverySource {
    Product {
        _unconstructible: Infallible,
    },
    #[cfg(feature = "p0-launch-package-device-conformance")]
    P0UserdebugPredispatch {
        custody_head_sha256: String,
        binding_publication_sha256: String,
    },
    #[cfg(test)]
    Test,
}

#[allow(dead_code)]
pub(crate) struct VerifiedDaemonLogicalDelivery {
    binding_sha256: String,
    adapter: DirectOperationAdapter,
    _source: VerifiedDaemonLogicalDeliverySource,
}

impl VerifiedDaemonLogicalDelivery {
    fn validate_for(&self, binding_sha256: &str, adapter: DirectOperationAdapter) -> Result<()> {
        if self.binding_sha256 != binding_sha256
            || self.adapter != adapter
            || !valid_nonzero_sha256(&self.binding_sha256)
        {
            bail!("direct_tool_call_allocator_provider_delivery_capability_drift_denied");
        }
        Ok(())
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn from_p0_predispatch_publication(
        publication: crate::direct_operation_custody::VerifiedP0PredispatchBindingPublication,
        adapter: DirectOperationAdapter,
    ) -> Result<Self> {
        let binding = publication.binding();
        binding
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        if !binding.authorized_adapter_set.authorizes(adapter) {
            bail!("direct_tool_call_allocator_p0_delivery_adapter_denied");
        }
        let binding_sha256 = binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let custody_head_sha256 = domain_digest(
            b"trillionnium.p0-predispatch-custody-head.v1",
            publication.committed_head(),
        )?;
        let binding_publication_sha256 = publication.publication_sha256().to_string();
        if !valid_nonzero_sha256(&custody_head_sha256)
            || !valid_nonzero_sha256(&binding_publication_sha256)
        {
            bail!("direct_tool_call_allocator_p0_delivery_publication_denied");
        }
        Ok(Self {
            binding_sha256,
            adapter,
            _source: VerifiedDaemonLogicalDeliverySource::P0UserdebugPredispatch {
                custody_head_sha256,
                binding_publication_sha256,
            },
        })
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    fn into_p0_userdebug_admission(
        self,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> Result<String> {
        self.validate_for(binding_sha256, adapter)?;
        let (custody_head_sha256, binding_publication_sha256) = match self._source {
            VerifiedDaemonLogicalDeliverySource::P0UserdebugPredispatch {
                custody_head_sha256,
                binding_publication_sha256,
            } => (custody_head_sha256, binding_publication_sha256),
            VerifiedDaemonLogicalDeliverySource::Product { _unconstructible } => {
                match _unconstructible {}
            }
            #[cfg(test)]
            VerifiedDaemonLogicalDeliverySource::Test => {
                bail!("direct_tool_call_allocator_p0_delivery_source_denied")
            }
        };
        let mut hasher = Sha256::new();
        hash_field(
            &mut hasher,
            b"domain",
            b"trillionnium.p0-userdebug-tool-call-admission.v1",
        );
        hash_field(&mut hasher, b"binding_sha256", binding_sha256.as_bytes());
        hash_field(&mut hasher, b"adapter", adapter.adapter_id().as_bytes());
        hash_field(
            &mut hasher,
            b"custody_head_sha256",
            custody_head_sha256.as_bytes(),
        );
        hash_field(
            &mut hasher,
            b"binding_publication_sha256",
            binding_publication_sha256.as_bytes(),
        );
        Ok(lower_hex(&hasher.finalize()))
    }

    #[cfg(test)]
    pub(crate) fn for_test(binding_sha256: String, adapter: DirectOperationAdapter) -> Self {
        Self {
            binding_sha256,
            adapter,
            _source: VerifiedDaemonLogicalDeliverySource::Test,
        }
    }

    #[cfg(all(test, feature = "p0-launch-package-device-conformance"))]
    pub(crate) fn for_p0_userdebug_test(
        binding_sha256: String,
        adapter: DirectOperationAdapter,
    ) -> Self {
        Self {
            binding_sha256,
            adapter,
            _source: VerifiedDaemonLogicalDeliverySource::P0UserdebugPredispatch {
                custody_head_sha256: sha256_bytes(b"fixture-p0-custody-head"),
                binding_publication_sha256: sha256_bytes(b"fixture-p0-publication"),
            },
        }
    }
}

/// Constructible only inside the fixed adapter session after exact kernel
/// peer, launch-custody, binding, and delivery validation.
#[allow(dead_code)]
pub(crate) struct VerifiedAdapterAllocationRequest {
    _authenticated_transport_peer_sha256: String,
}

/// A PREPARED acknowledgement may enter the daemon ledger only after a fixed
/// transport has authenticated the adapter peer and kept its pidfd/custody
/// identity live for the whole session.
#[allow(dead_code)]
pub(crate) struct VerifiedAdapterPreparedAcknowledgement {
    _authenticated_transport_peer_sha256: String,
}

impl VerifiedAdapterAllocationRequest {
    pub(crate) fn from_authenticated_transport(
        peer: &crate::direct_tool_call_transport::VerifiedAdapterTransportPeer,
    ) -> Self {
        Self {
            _authenticated_transport_peer_sha256: peer.identity_sha256().to_string(),
        }
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn from_p0_userdebug_authenticated_transport(
        peer: &crate::direct_tool_call_transport::VerifiedP0UserdebugAdapterTransportPeer,
    ) -> Self {
        Self {
            _authenticated_transport_peer_sha256: peer.identity_sha256().to_string(),
        }
    }
}

impl VerifiedAdapterPreparedAcknowledgement {
    pub(crate) fn from_authenticated_transport(
        peer: &crate::direct_tool_call_transport::VerifiedAdapterTransportPeer,
    ) -> Self {
        Self {
            _authenticated_transport_peer_sha256: peer.identity_sha256().to_string(),
        }
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn from_p0_userdebug_authenticated_transport(
        peer: &crate::direct_tool_call_transport::VerifiedP0UserdebugAdapterTransportPeer,
    ) -> Self {
        Self {
            _authenticated_transport_peer_sha256: peer.identity_sha256().to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AllocationStage {
    DeliveryIssued,
    CanonicalAllocated,
    AdapterPrepared,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllocationRecordV1 {
    schema: String,
    stage: AllocationStage,
    delivery: DirectOperationToolCallDeliveryV3,
    canonical_request_sha256: Option<String>,
    envelope: Option<DirectOperationToolCallEnvelopeV3>,
    prepared_acknowledgement: Option<DirectOperationToolCallPreparedAckV3>,
    acknowledged_generation: Option<u64>,
    predecessor_record_sha256: String,
    record_sha256: String,
}

impl AllocationRecordV1 {
    fn issued(
        delivery: DirectOperationToolCallDeliveryV3,
        predecessor_record_sha256: String,
    ) -> Result<Self> {
        let mut record = Self {
            schema: RECORD_SCHEMA.to_string(),
            stage: AllocationStage::DeliveryIssued,
            delivery,
            canonical_request_sha256: None,
            envelope: None,
            prepared_acknowledgement: None,
            acknowledged_generation: None,
            predecessor_record_sha256,
            record_sha256: String::new(),
        };
        record.record_sha256 = record.digest_sha256()?;
        Ok(record)
    }

    fn digest_sha256(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            stage: &'a AllocationStage,
            delivery: &'a DirectOperationToolCallDeliveryV3,
            canonical_request_sha256: &'a Option<String>,
            envelope: &'a Option<DirectOperationToolCallEnvelopeV3>,
            prepared_acknowledgement: &'a Option<DirectOperationToolCallPreparedAckV3>,
            acknowledged_generation: &'a Option<u64>,
            predecessor_record_sha256: &'a str,
        }
        domain_digest(
            RECORD_DIGEST_DOMAIN,
            &Preimage {
                schema: &self.schema,
                stage: &self.stage,
                delivery: &self.delivery,
                canonical_request_sha256: &self.canonical_request_sha256,
                envelope: &self.envelope,
                prepared_acknowledgement: &self.prepared_acknowledgement,
                acknowledged_generation: &self.acknowledged_generation,
                predecessor_record_sha256: &self.predecessor_record_sha256,
            },
        )
    }

    fn validate_for(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        expected_ordinal: u64,
        expected_predecessor: &str,
    ) -> Result<()> {
        if self.schema != RECORD_SCHEMA
            || self.predecessor_record_sha256 != expected_predecessor
            || self.record_sha256 != self.digest_sha256()?
            || self.delivery.adapter_effect_ordinal != expected_ordinal
        {
            bail!("direct_tool_call_allocator_record_chain_or_ordinal_denied");
        }
        self.delivery
            .validate_for(binding, binding_sha256, adapter)
            .map_err(|error| anyhow!(error.to_string()))?;
        match (
            &self.stage,
            &self.canonical_request_sha256,
            &self.envelope,
            &self.prepared_acknowledgement,
            self.acknowledged_generation,
        ) {
            (AllocationStage::DeliveryIssued, None, None, None, None) => Ok(()),
            (
                AllocationStage::CanonicalAllocated,
                Some(canonical_request_sha256),
                Some(envelope),
                None,
                None,
            ) if valid_nonzero_sha256(canonical_request_sha256) => {
                let request = DirectOperationToolCallAllocationRequestV3::derive(
                    &self.delivery,
                    binding,
                    binding_sha256,
                    adapter,
                    canonical_request_sha256.clone(),
                )
                .map_err(|error| anyhow!(error.to_string()))?;
                envelope
                    .validate_for_allocation_request_v3(&request)
                    .map_err(|error| anyhow!(error.to_string()))
            }
            (
                AllocationStage::AdapterPrepared,
                Some(canonical_request_sha256),
                Some(envelope),
                Some(acknowledgement),
                Some(acknowledged_generation),
            ) if valid_nonzero_sha256(canonical_request_sha256) && acknowledged_generation > 0 => {
                let request = DirectOperationToolCallAllocationRequestV3::derive(
                    &self.delivery,
                    binding,
                    binding_sha256,
                    adapter,
                    canonical_request_sha256.clone(),
                )
                .map_err(|error| anyhow!(error.to_string()))?;
                envelope
                    .validate_for_allocation_request_v3(&request)
                    .map_err(|error| anyhow!(error.to_string()))?;
                acknowledgement
                    .validate_for_envelope(envelope)
                    .map_err(|error| anyhow!(error.to_string()))
            }
            _ => bail!("direct_tool_call_allocator_record_stage_denied"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllocatorFileV1 {
    schema: String,
    binding: DirectOperationBinding,
    binding_sha256: String,
    adapter: DirectOperationAdapter,
    /// A local hash chain cannot detect replacement by an older, internally
    /// valid complete file. Product activation therefore remains HOLD until a
    /// rollback-resistant external high-water authority is bound and checked.
    rollback_high_water_authority: String,
    generation: u64,
    predecessor_store_sha256: String,
    records: Vec<AllocationRecordV1>,
    store_sha256: String,
}

impl AllocatorFileV1 {
    fn empty(
        binding: DirectOperationBinding,
        adapter: DirectOperationAdapter,
        rollback_high_water_authority: &'static str,
    ) -> Result<Self> {
        binding
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        if !valid_rollback_high_water_authority(rollback_high_water_authority) {
            bail!("direct_tool_call_allocator_high_water_authority_marker_denied");
        }
        let binding_sha256 = binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        Ok(Self {
            schema: STORE_SCHEMA.to_string(),
            binding,
            binding_sha256,
            adapter,
            rollback_high_water_authority: rollback_high_water_authority.to_string(),
            generation: 0,
            predecessor_store_sha256: ZERO_SHA256.to_string(),
            records: Vec::new(),
            store_sha256: String::new(),
        })
    }

    fn digest_sha256(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            binding: &'a DirectOperationBinding,
            binding_sha256: &'a str,
            adapter: DirectOperationAdapter,
            rollback_high_water_authority: &'a str,
            generation: u64,
            predecessor_store_sha256: &'a str,
            records: &'a [AllocationRecordV1],
        }
        domain_digest(
            STORE_DIGEST_DOMAIN,
            &Preimage {
                schema: &self.schema,
                binding: &self.binding,
                binding_sha256: &self.binding_sha256,
                adapter: self.adapter,
                rollback_high_water_authority: &self.rollback_high_water_authority,
                generation: self.generation,
                predecessor_store_sha256: &self.predecessor_store_sha256,
                records: &self.records,
            },
        )
    }

    fn validate(&self, persisted: bool) -> Result<()> {
        self.binding
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        if self.schema != STORE_SCHEMA
            || self
                .binding
                .digest_sha256()
                .map_err(|error| anyhow!(error.to_string()))?
                != self.binding_sha256
            || !valid_rollback_high_water_authority(&self.rollback_high_water_authority)
            || self.records.len() > MAX_OUTER_ACK_EVIDENCE
            || (persisted && (self.generation == 0 || self.records.is_empty()))
            || (!persisted
                && (self.generation != 0
                    || !self.records.is_empty()
                    || self.predecessor_store_sha256 != ZERO_SHA256
                    || !self.store_sha256.is_empty()))
            || (persisted && self.store_sha256 != self.digest_sha256()?)
            || (self.generation == 1 && self.predecessor_store_sha256 != ZERO_SHA256)
            || (self.generation > 1 && !valid_nonzero_sha256(&self.predecessor_store_sha256))
        {
            bail!("direct_tool_call_allocator_store_header_denied");
        }

        let mut predecessor = ZERO_SHA256;
        let mut tokens = HashSet::with_capacity(self.records.len());
        let mut saw_uncommitted = false;
        let mut journal_epoch: Option<&str> = None;
        let mut operation_epoch_authority_sha256: Option<&str> = None;
        let mut previous_journal_sequence: Option<u64> = None;
        let mut previous_acknowledged_generation: Option<u64> = None;
        for (index, record) in self.records.iter().enumerate() {
            record.validate_for(
                &self.binding,
                &self.binding_sha256,
                self.adapter,
                index as u64,
                predecessor,
            )?;
            if !tokens.insert(record.delivery.os_tool_call_id.as_str()) {
                bail!("direct_tool_call_allocator_duplicate_token_denied");
            }
            match record.stage {
                AllocationStage::DeliveryIssued | AllocationStage::CanonicalAllocated => {
                    if saw_uncommitted || index + 1 != self.records.len() {
                        bail!("direct_tool_call_allocator_nonterminal_pending_delivery_denied");
                    }
                    saw_uncommitted = true;
                }
                AllocationStage::AdapterPrepared if saw_uncommitted => {
                    bail!("direct_tool_call_allocator_acknowledgement_after_pending_denied")
                }
                AllocationStage::AdapterPrepared => {
                    let acknowledgement =
                        record.prepared_acknowledgement.as_ref().ok_or_else(|| {
                            anyhow!("direct_tool_call_allocator_prepared_ack_missing")
                        })?;
                    let acknowledged_generation =
                        record.acknowledged_generation.ok_or_else(|| {
                            anyhow!("direct_tool_call_allocator_acknowledged_generation_missing")
                        })?;
                    if journal_epoch
                        .replace(&acknowledgement.journal_epoch)
                        .is_some_and(|epoch| epoch != acknowledgement.journal_epoch.as_str())
                        || operation_epoch_authority_sha256
                            .replace(&acknowledgement.operation_epoch_authority_sha256)
                            .is_some_and(|authority| {
                                authority
                                    != acknowledgement.operation_epoch_authority_sha256.as_str()
                            })
                        || previous_journal_sequence.is_some_and(|previous| {
                            previous
                                .checked_add(1)
                                .is_none_or(|next| next != acknowledgement.journal_sequence)
                        })
                        || acknowledged_generation > self.generation
                        || previous_acknowledged_generation
                            .is_some_and(|previous| previous >= acknowledged_generation)
                    {
                        bail!("direct_tool_call_allocator_operation_epoch_or_sequence_denied");
                    }
                    previous_journal_sequence = Some(acknowledgement.journal_sequence);
                    previous_acknowledged_generation = Some(acknowledged_generation);
                }
            }
            predecessor = &record.record_sha256;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    size: i64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
}

struct NamedFile {
    bytes: Vec<u8>,
    identity: FileIdentity,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
            size: metadata.len() as i64,
            mtime_seconds: metadata.mtime(),
            mtime_nanoseconds: metadata.mtime_nsec(),
            ctime_seconds: metadata.ctime(),
            ctime_nanoseconds: metadata.ctime_nsec(),
        }
    }

    fn from_stat(stat: &libc::stat) -> Self {
        Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
            nlink: normalized_nlink(stat.st_nlink),
            size: stat.st_size,
            mtime_seconds: stat.st_mtime,
            mtime_nanoseconds: stat.st_mtime_nsec,
            ctime_seconds: stat.st_ctime,
            ctime_nanoseconds: stat.st_ctime_nsec,
        }
    }
}

// Linux libc exposes `nlink_t` as `u64` on x86-64 and `u32` on AArch64.
// Widen the product-architecture value while retaining the exact host value.
#[allow(clippy::useless_conversion)]
fn normalized_nlink(value: libc::nlink_t) -> u64 {
    u64::from(value)
}

struct SecureParent {
    directory: File,
    identity: FileIdentity,
}

impl SecureParent {
    fn validate(&self, owner_uid: u32) -> Result<()> {
        let metadata = self.directory.metadata()?;
        let current = FileIdentity::from_metadata(&metadata);
        // Directory size and timestamps legitimately change when the atomic
        // writer creates/unlinks a temp or renames the destination. Custody is
        // the open directory inode plus its ownership/mode/link identity.
        if current.dev != self.identity.dev
            || current.ino != self.identity.ino
            || current.uid != self.identity.uid
            || current.gid != self.identity.gid
            || current.mode != self.identity.mode
            || current.nlink != self.identity.nlink
            || !metadata.is_dir()
            || metadata.uid() != owner_uid
            || metadata.permissions().mode() & 0o7777 != 0o700
            || metadata.nlink() == 0
        {
            bail!("direct_tool_call_allocator_parent_identity_changed");
        }
        Ok(())
    }
}

/// Locked local half of the durable allocator admission transaction.
struct OpenedAllocatorStore {
    parent: SecureParent,
    destination_name: CString,
    file: AllocatorFileV1,
    persisted_sha256: Option<String>,
    persisted_identity: Option<FileIdentity>,
    owner_uid: u32,
}

/// Move-only admission proof retaining the locked local store and the exact
/// freshly observed external authority session.  Neither JSON nor a caller
/// supplied generation/digest can construct this capability.
#[must_use = "verified allocator admission must be consumed by open_product"]
pub(crate) struct VerifiedProductAllocatorHighWater {
    opened: OpenedAllocatorStore,
    high_water: VerifiedDirectToolCallHighWater,
}

/// Borrowed, non-serializable proof that this exact allocator remains locally
/// locked and externally high-water verified while a fixed listener is bound.
#[must_use = "allocator listener custody must be consumed by bind_product"]
pub(crate) struct VerifiedProductAllocatorListener<'a> {
    allocator: &'a DirectToolCallAllocator,
    route: DirectToolCallHighWaterRouteV1,
}

impl VerifiedProductAllocatorListener<'_> {
    pub(crate) fn validate_delivery(&self, delivery: &VerifiedDaemonLogicalDelivery) -> Result<()> {
        self.allocator.ensure_live()?;
        if self.route != high_water_route(&self.allocator.file)? {
            bail!("direct_tool_call_allocator_listener_route_drift_denied");
        }
        delivery.validate_for(self.route.binding_sha256(), self.route.adapter())
    }

    pub(crate) fn route_sha256(&self) -> &str {
        self.route.route_sha256()
    }
}

/// Borrowed, non-serializable proof that one allocator commit is the exact
/// durable PREPARED ACK that an Android adapter may replay or correlate with
/// one outer journal evidence item.
///
/// This is deliberately narrower than product admission: it does not create
/// a delivery, contact Android, grant effect authority, or bypass the static
/// product transport/high-water gates.  The borrow keeps the allocator's
/// directory lock and lets every consumer re-check the persisted record before
/// accepting an ACK/replay correlation.
#[must_use = "allocator Android ACK proof must be consumed by the ACK/replay handoff"]
pub(crate) struct VerifiedAllocatorCommitForAndroidAck<'a> {
    allocator: &'a DirectToolCallAllocator,
    receipt: DirectOperationToolCallCommitReceiptV3,
    canonical_request_sha256: String,
    allocating_provider_attempt_id: String,
    journal_sequence: u64,
    backend_request_id_sha256: String,
}

impl VerifiedAllocatorCommitForAndroidAck<'_> {
    /// Return the exact daemon receipt that the adapter must replay, never a
    /// caller-supplied generation or digest.
    pub(crate) fn receipt(&self) -> &DirectOperationToolCallCommitReceiptV3 {
        &self.receipt
    }

    /// Correlate one structurally valid outer evidence item with the same
    /// persisted allocator commit and adapter PREPARED ACK.  Backend result
    /// bytes remain adapter-owned; only the request identity and journal
    /// sequence are bound here.
    pub(crate) fn validate_outer_evidence(
        &self,
        evidence: &DirectOperationOuterEvidence,
    ) -> Result<()> {
        self.allocator.ensure_live()?;
        let record = self
            .allocator
            .file
            .records
            .iter()
            .find(|record| record.delivery.os_tool_call_id == self.receipt.os_tool_call_id)
            .context("direct_tool_call_allocator_android_ack_record_missing_hold")?;
        if record.stage != AllocationStage::AdapterPrepared {
            bail!("direct_tool_call_allocator_android_ack_record_not_prepared_hold");
        }
        let current_receipt = receipt_for_record(record)?;
        if current_receipt != self.receipt {
            bail!("direct_tool_call_allocator_android_ack_replay_state_drift_hold");
        }
        let acknowledgement = record
            .prepared_acknowledgement
            .as_ref()
            .context("direct_tool_call_allocator_android_ack_missing_hold")?;
        self.receipt
            .validate_for_acknowledgement(acknowledgement)
            .map_err(|error| anyhow!(error.to_string()))?;
        evidence
            .validate_for_adapter(self.receipt.adapter)
            .map_err(|error| anyhow!(error.to_string()))?;
        if evidence.allocating_provider_attempt_id != self.allocating_provider_attempt_id {
            bail!("direct_tool_call_allocator_android_ack_attempt_denied");
        }
        if evidence.adapter_effect_ordinal != self.receipt.adapter_effect_ordinal {
            bail!("direct_tool_call_allocator_android_ack_ordinal_denied");
        }
        if evidence.journal_sequence != self.journal_sequence {
            bail!("direct_tool_call_allocator_android_ack_journal_sequence_denied");
        }
        if evidence.canonical_request_sha256 != self.canonical_request_sha256 {
            bail!("direct_tool_call_allocator_android_ack_canonical_digest_denied");
        }
        if evidence.backend_request_id_sha256 != self.backend_request_id_sha256 {
            bail!("direct_tool_call_allocator_android_ack_backend_request_denied");
        }
        Ok(())
    }
}

pub(crate) struct DirectToolCallAllocator {
    parent: SecureParent,
    destination_name: CString,
    file: AllocatorFileV1,
    persisted_sha256: Option<String>,
    persisted_identity: Option<FileIdentity>,
    publication_durability_uncertain: bool,
    owner_uid: u32,
    product_high_water_required: bool,
    #[cfg(feature = "p0-launch-package-device-conformance")]
    p0_userdebug_admission_sha256: Option<String>,
    high_water_permanent_hold: bool,
    high_water: Option<VerifiedDirectToolCallHighWater>,
    #[cfg(test)]
    fail_parent_fsync_after_rename_once: bool,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
#[must_use = "P0 userdebug allocator admission must be consumed by the fixed listener"]
pub(crate) struct VerifiedP0UserdebugAllocator {
    allocator: DirectToolCallAllocator,
    binding: DirectOperationBinding,
    adapter: DirectOperationAdapter,
    admission_sha256: String,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl VerifiedP0UserdebugAllocator {
    pub(crate) fn validate(&self) -> Result<()> {
        self.allocator.ensure_live()?;
        if self.adapter != DirectOperationAdapter::SystemApi
            || self.allocator.file.binding != self.binding
            || self.allocator.file.adapter != self.adapter
            || self.allocator.file.rollback_high_water_authority
                != P0_USERDEBUG_PREDISPATCH_CUSTODY_AUTHORITY_V1
            || self.allocator.product_high_water_required
            || self.allocator.p0_userdebug_admission_sha256.as_deref()
                != Some(self.admission_sha256.as_str())
            || !valid_nonzero_sha256(&self.admission_sha256)
            || self.allocator.file.records.last().is_none()
        {
            bail!("direct_tool_call_allocator_p0_listener_admission_denied");
        }
        Ok(())
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        DirectToolCallAllocator,
        DirectOperationBinding,
        DirectOperationAdapter,
    ) {
        (self.allocator, self.binding, self.adapter)
    }
}

impl DirectToolCallAllocator {
    /// Open the compile-time-fixed product store, retain its directory lock,
    /// reconcile/observe the compile-time-fixed external authority, and return
    /// a move-only capability. This does not bind the listener or admit a
    /// provider delivery.
    pub(crate) fn verify_product_high_water(
        binding: DirectOperationBinding,
        adapter: DirectOperationAdapter,
    ) -> Result<VerifiedProductAllocatorHighWater> {
        transport_contract::require_product_admission_contract()
            .map_err(|error| anyhow!(error.to_string()))?;
        let path = product_allocator_path(&binding, adapter)?;
        let opened = open_allocator_store(
            &path,
            PRODUCT_OWNER_UID,
            binding,
            adapter,
            ROLLBACK_HIGH_WATER_AUTHORITY_FIXED_SOCKET_V1,
        )?;
        let route = high_water_route(&opened.file)?;
        let local_head = high_water_head(&opened.file, opened.persisted_sha256.is_some())?;
        let high_water = VerifiedDirectToolCallHighWater::connect_product(route, local_head)?;
        Ok(VerifiedProductAllocatorHighWater { opened, high_water })
    }

    /// The only production constructor. It consumes retained local-store and
    /// external-authority custody; paths, generations, digests and booleans are
    /// not constructor arguments.
    pub(crate) fn open_product(verified: VerifiedProductAllocatorHighWater) -> Result<Self> {
        transport_contract::require_product_admission_contract()
            .map_err(|error| anyhow!(error.to_string()))?;
        Self::from_verified_product_admission(verified)
    }

    pub(crate) fn verified_product_listener(&self) -> Result<VerifiedProductAllocatorListener<'_>> {
        self.ensure_live()?;
        if !self.product_high_water_required
            || self.file.rollback_high_water_authority
                != ROLLBACK_HIGH_WATER_AUTHORITY_FIXED_SOCKET_V1
        {
            bail!("direct_tool_call_allocator_product_listener_high_water_required");
        }
        Ok(VerifiedProductAllocatorListener {
            allocator: self,
            route: high_water_route(&self.file)?,
        })
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        path: &Path,
        owner_uid: u32,
        binding: DirectOperationBinding,
        adapter: DirectOperationAdapter,
    ) -> Result<Self> {
        Self::open_at_path(path, owner_uid, binding, adapter)
    }

    #[cfg(test)]
    pub(crate) fn verify_high_water_for_test(
        path: &Path,
        owner_uid: u32,
        binding: DirectOperationBinding,
        adapter: DirectOperationAdapter,
        authority: &TestDirectToolCallHighWaterAuthority,
    ) -> Result<VerifiedProductAllocatorHighWater> {
        let opened = open_allocator_store(
            path,
            owner_uid,
            binding,
            adapter,
            ROLLBACK_HIGH_WATER_AUTHORITY_FIXED_SOCKET_V1,
        )?;
        let route = high_water_route(&opened.file)?;
        let local_head = high_water_head(&opened.file, opened.persisted_sha256.is_some())?;
        let high_water = authority.connect(route, local_head)?;
        Ok(VerifiedProductAllocatorHighWater { opened, high_water })
    }

    #[cfg(test)]
    pub(crate) fn open_verified_for_test(
        verified: VerifiedProductAllocatorHighWater,
    ) -> Result<Self> {
        Self::from_verified_product_admission(verified)
    }

    fn from_verified_product_admission(
        verified: VerifiedProductAllocatorHighWater,
    ) -> Result<Self> {
        let VerifiedProductAllocatorHighWater { opened, high_water } = verified;
        let OpenedAllocatorStore {
            parent,
            destination_name,
            file,
            persisted_sha256,
            persisted_identity,
            owner_uid,
        } = opened;
        if file.rollback_high_water_authority != ROLLBACK_HIGH_WATER_AUTHORITY_FIXED_SOCKET_V1
            || high_water.route() != &high_water_route(&file)?
            || high_water.committed_head() != &high_water_head(&file, persisted_sha256.is_some())?
        {
            bail!("direct_tool_call_allocator_verified_high_water_substitution_denied");
        }
        let allocator = Self {
            parent,
            destination_name,
            file,
            persisted_sha256,
            persisted_identity,
            publication_durability_uncertain: false,
            owner_uid,
            product_high_water_required: true,
            #[cfg(feature = "p0-launch-package-device-conformance")]
            p0_userdebug_admission_sha256: None,
            high_water_permanent_hold: false,
            high_water: Some(high_water),
            #[cfg(test)]
            fail_parent_fsync_after_rename_once: false,
        };
        allocator.ensure_live()?;
        Ok(allocator)
    }

    /// Consume the custody-derived P0 logical delivery, open the fixed durable
    /// allocator path, and preissue exactly one delivery before provider
    /// dispatch. This constructor is physically absent from product builds and
    /// does not claim the independent product rollback-high-water authority.
    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn open_p0_userdebug(
        binding: DirectOperationBinding,
        adapter: DirectOperationAdapter,
        verified_delivery: VerifiedDaemonLogicalDelivery,
    ) -> Result<VerifiedP0UserdebugAllocator> {
        let path = product_allocator_path(&binding, adapter)?;
        Self::open_p0_userdebug_at_path(
            &path,
            PRODUCT_OWNER_UID,
            binding,
            adapter,
            verified_delivery,
            kernel_entropy()?,
        )
    }

    #[cfg(all(test, feature = "p0-launch-package-device-conformance"))]
    pub(crate) fn open_p0_userdebug_for_test(
        path: &Path,
        owner_uid: u32,
        binding: DirectOperationBinding,
        adapter: DirectOperationAdapter,
        verified_delivery: VerifiedDaemonLogicalDelivery,
        entropy: [u8; 32],
    ) -> Result<VerifiedP0UserdebugAllocator> {
        Self::open_p0_userdebug_at_path(
            path,
            owner_uid,
            binding,
            adapter,
            verified_delivery,
            entropy,
        )
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    fn open_p0_userdebug_at_path(
        path: &Path,
        owner_uid: u32,
        binding: DirectOperationBinding,
        adapter: DirectOperationAdapter,
        verified_delivery: VerifiedDaemonLogicalDelivery,
        entropy: [u8; 32],
    ) -> Result<VerifiedP0UserdebugAllocator> {
        if adapter != DirectOperationAdapter::SystemApi {
            bail!("direct_tool_call_allocator_p0_adapter_denied");
        }
        binding
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        let binding_sha256 = binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let admission_sha256 =
            verified_delivery.into_p0_userdebug_admission(&binding_sha256, adapter)?;
        let OpenedAllocatorStore {
            parent,
            destination_name,
            file,
            persisted_sha256,
            persisted_identity,
            owner_uid,
        } = open_allocator_store(
            path,
            owner_uid,
            binding.clone(),
            adapter,
            P0_USERDEBUG_PREDISPATCH_CUSTODY_AUTHORITY_V1,
        )?;
        let mut allocator = Self {
            parent,
            destination_name,
            file,
            persisted_sha256,
            persisted_identity,
            publication_durability_uncertain: false,
            owner_uid,
            product_high_water_required: false,
            p0_userdebug_admission_sha256: Some(admission_sha256.clone()),
            high_water_permanent_hold: false,
            high_water: None,
            #[cfg(test)]
            fail_parent_fsync_after_rename_once: false,
        };
        allocator.issue_delivery(entropy)?;
        let verified = VerifiedP0UserdebugAllocator {
            allocator,
            binding,
            adapter,
            admission_sha256,
        };
        verified.validate()?;
        Ok(verified)
    }

    fn open_at_path(
        path: &Path,
        owner_uid: u32,
        binding: DirectOperationBinding,
        adapter: DirectOperationAdapter,
    ) -> Result<Self> {
        let OpenedAllocatorStore {
            parent,
            destination_name,
            file,
            persisted_sha256,
            persisted_identity,
            owner_uid,
        } = open_allocator_store(
            path,
            owner_uid,
            binding,
            adapter,
            ROLLBACK_HIGH_WATER_AUTHORITY_ABSENT_PRODUCT_HOLD,
        )?;
        Ok(Self {
            parent,
            destination_name,
            file,
            persisted_sha256,
            persisted_identity,
            publication_durability_uncertain: false,
            owner_uid,
            product_high_water_required: false,
            #[cfg(feature = "p0-launch-package-device-conformance")]
            p0_userdebug_admission_sha256: None,
            high_water_permanent_hold: false,
            high_water: None,
            #[cfg(test)]
            fail_parent_fsync_after_rename_once: false,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn issue_verified_delivery(
        &mut self,
        verified: VerifiedDaemonLogicalDelivery,
        entropy: [u8; 32],
    ) -> Result<DirectOperationToolCallDeliveryV3> {
        verified.validate_for(&self.file.binding_sha256, self.file.adapter)?;
        self.issue_delivery(entropy)
    }

    #[allow(dead_code)]
    pub(crate) fn allocate_verified_request(
        &mut self,
        _verified: VerifiedAdapterAllocationRequest,
        delivery: &DirectOperationToolCallDeliveryV3,
        canonical_request_sha256: &str,
    ) -> Result<DirectOperationToolCallEnvelopeV3> {
        self.allocate(delivery, canonical_request_sha256)
    }

    #[allow(dead_code)]
    pub(crate) fn acknowledge_verified_prepared(
        &mut self,
        _verified: VerifiedAdapterPreparedAcknowledgement,
        acknowledgement: &DirectOperationToolCallPreparedAckV3,
    ) -> Result<DirectOperationToolCallCommitReceiptV3> {
        self.acknowledge_prepared(acknowledgement)
    }

    /// Verify that a daemon commit receipt is backed by the exact persisted
    /// AdapterPrepared record and retain a locked, re-checkable ACK/replay
    /// correlation proof.  This source-only seam intentionally sits after the
    /// PREPARED transition; it does not open the product allocator or contact
    /// an Android transport.
    pub(crate) fn verify_commit_for_android_ack(
        &self,
        receipt: &DirectOperationToolCallCommitReceiptV3,
    ) -> Result<VerifiedAllocatorCommitForAndroidAck<'_>> {
        self.ensure_live()?;
        self.file.validate(self.persisted_sha256.is_some())?;
        receipt
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        if receipt.binding_sha256 != self.file.binding_sha256
            || receipt.invocation_id != self.file.binding.invocation_id
            || receipt.adapter != self.file.adapter
        {
            bail!("direct_tool_call_allocator_android_ack_binding_denied");
        }
        let record = self
            .file
            .records
            .iter()
            .find(|record| record.delivery.os_tool_call_id == receipt.os_tool_call_id)
            .context("direct_tool_call_allocator_android_ack_record_missing_hold")?;
        if record.stage != AllocationStage::AdapterPrepared {
            bail!("direct_tool_call_allocator_android_ack_record_not_prepared_hold");
        }
        let expected_receipt = receipt_for_record(record)?;
        if &expected_receipt != receipt {
            bail!("direct_tool_call_allocator_android_ack_receipt_mismatch_hold");
        }
        let acknowledgement = record
            .prepared_acknowledgement
            .as_ref()
            .context("direct_tool_call_allocator_android_ack_missing_hold")?;
        receipt
            .validate_for_acknowledgement(acknowledgement)
            .map_err(|error| anyhow!(error.to_string()))?;
        let canonical_request_sha256 = record
            .canonical_request_sha256
            .clone()
            .context("direct_tool_call_allocator_android_ack_canonical_missing_hold")?;
        if acknowledgement.canonical_request_sha256 != canonical_request_sha256
            || acknowledgement.adapter_effect_ordinal != receipt.adapter_effect_ordinal
            || acknowledgement.delivery_provider_attempt_id
                != self.file.binding.attempt.delivery_provider_attempt_id
        {
            bail!("direct_tool_call_allocator_android_ack_lineage_denied");
        }
        Ok(VerifiedAllocatorCommitForAndroidAck {
            allocator: self,
            receipt: receipt.clone(),
            canonical_request_sha256,
            allocating_provider_attempt_id: self
                .file
                .binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            journal_sequence: acknowledgement.journal_sequence,
            backend_request_id_sha256: acknowledgement.backend_request_id_sha256.clone(),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn recover_pending_verified_delivery(
        &mut self,
    ) -> Result<DirectOperationToolCallDeliveryV3> {
        self.ensure_live()?;
        self.file.validate(self.persisted_sha256.is_some())?;
        self.file
            .records
            .last()
            .map(|record| record.delivery.clone())
            .context("direct_tool_call_allocator_no_preissued_delivery_hold")
    }

    fn issue_delivery(&mut self, entropy: [u8; 32]) -> Result<DirectOperationToolCallDeliveryV3> {
        self.ensure_live()?;
        self.file.validate(self.persisted_sha256.is_some())?;
        if let Some(pending) = self
            .file
            .records
            .last()
            .filter(|record| record.stage != AllocationStage::AdapterPrepared)
        {
            // A crash before the adapter's durable PREPARED acknowledgement
            // must recover the same token. Allocation alone is not sufficient
            // to admit a later logical delivery because the envelope response
            // may have been lost before the adapter journaled it.
            return Ok(pending.delivery.clone());
        }
        if self.file.records.len() >= MAX_OUTER_ACK_EVIDENCE {
            bail!("direct_tool_call_allocator_capacity_exhausted");
        }
        if entropy.iter().all(|byte| *byte == 0) {
            bail!("direct_tool_call_allocator_zero_entropy_denied");
        }
        let ordinal = self.file.records.len() as u64;
        let predecessor_record_sha256 = self
            .file
            .records
            .last()
            .map_or(ZERO_SHA256, |record| record.record_sha256.as_str());
        let os_tool_call_id = derive_os_tool_call_id(
            &self.file.binding_sha256,
            self.file.adapter,
            ordinal,
            predecessor_record_sha256,
            &entropy,
        );
        let delivery = DirectOperationToolCallDeliveryV3::derive(
            &self.file.binding,
            &self.file.binding_sha256,
            self.file.adapter,
            os_tool_call_id,
            ordinal,
        )
        .map_err(|error| anyhow!(error.to_string()))?;
        let mut candidate = self.file.clone();
        candidate.records.push(AllocationRecordV1::issued(
            delivery.clone(),
            predecessor_record_sha256.to_string(),
        )?);
        self.commit(candidate)?;
        Ok(delivery)
    }

    fn allocate(
        &mut self,
        delivery: &DirectOperationToolCallDeliveryV3,
        canonical_request_sha256: &str,
    ) -> Result<DirectOperationToolCallEnvelopeV3> {
        self.ensure_live()?;
        self.file.validate(self.persisted_sha256.is_some())?;
        delivery
            .validate_for(
                &self.file.binding,
                &self.file.binding_sha256,
                self.file.adapter,
            )
            .map_err(|error| anyhow!(error.to_string()))?;
        if !valid_nonzero_sha256(canonical_request_sha256) {
            bail!("direct_tool_call_allocator_canonical_digest_denied");
        }
        let record_index = self
            .file
            .records
            .iter()
            .position(|record| record.delivery.os_tool_call_id == delivery.os_tool_call_id)
            .context("direct_tool_call_allocator_delivery_correlation_unavailable_hold")?;
        let record = &self.file.records[record_index];
        if &record.delivery != delivery || record_index as u64 != delivery.adapter_effect_ordinal {
            bail!("direct_tool_call_allocator_delivery_token_or_ordinal_drift_hold");
        }
        match record.stage {
            AllocationStage::CanonicalAllocated | AllocationStage::AdapterPrepared => {
                if record.canonical_request_sha256.as_deref() != Some(canonical_request_sha256) {
                    bail!("direct_tool_call_allocator_retry_digest_mismatch_hold");
                }
                let envelope = record
                    .envelope
                    .clone()
                    .context("direct_tool_call_allocator_allocated_envelope_missing")?;
                let request = DirectOperationToolCallAllocationRequestV3::derive(
                    delivery,
                    &self.file.binding,
                    &self.file.binding_sha256,
                    self.file.adapter,
                    canonical_request_sha256.to_string(),
                )
                .map_err(|error| anyhow!(error.to_string()))?;
                envelope
                    .validate_for_allocation_request_v3(&request)
                    .map_err(|error| anyhow!(error.to_string()))?;
                Ok(envelope)
            }
            AllocationStage::DeliveryIssued => {
                if record_index + 1 != self.file.records.len()
                    || self.file.records[..record_index]
                        .iter()
                        .any(|record| record.stage != AllocationStage::AdapterPrepared)
                {
                    bail!("direct_tool_call_allocator_ordinal_jump_or_rollback_hold");
                }
                let mut envelope = DirectOperationToolCallEnvelopeV3 {
                    schema: TOOL_CALL_ENVELOPE_V3_SCHEMA.to_string(),
                    binding_sha256: self.file.binding_sha256.clone(),
                    invocation_id: self.file.binding.invocation_id.clone(),
                    delivery_provider_attempt_id: self
                        .file
                        .binding
                        .attempt
                        .delivery_provider_attempt_id
                        .clone(),
                    provider_id: self.file.binding.stable_seed.provider_id.clone(),
                    agent_id: self.file.binding.stable_seed.agent_id.clone(),
                    adapter: self.file.adapter,
                    os_tool_call_id: delivery.os_tool_call_id.clone(),
                    adapter_effect_ordinal: delivery.adapter_effect_ordinal,
                    canonical_request_sha256: canonical_request_sha256.to_string(),
                    envelope_sha256: String::new(),
                };
                envelope.envelope_sha256 = envelope
                    .digest_sha256()
                    .map_err(|error| anyhow!(error.to_string()))?;
                let request = DirectOperationToolCallAllocationRequestV3::derive(
                    delivery,
                    &self.file.binding,
                    &self.file.binding_sha256,
                    self.file.adapter,
                    canonical_request_sha256.to_string(),
                )
                .map_err(|error| anyhow!(error.to_string()))?;
                envelope
                    .validate_for_allocation_request_v3(&request)
                    .map_err(|error| anyhow!(error.to_string()))?;

                let mut candidate = self.file.clone();
                let candidate_record = &mut candidate.records[record_index];
                candidate_record.stage = AllocationStage::CanonicalAllocated;
                candidate_record.canonical_request_sha256 =
                    Some(canonical_request_sha256.to_string());
                candidate_record.envelope = Some(envelope.clone());
                candidate_record.record_sha256 = candidate_record.digest_sha256()?;
                self.commit(candidate)?;
                Ok(envelope)
            }
        }
    }

    fn acknowledge_prepared(
        &mut self,
        acknowledgement: &DirectOperationToolCallPreparedAckV3,
    ) -> Result<DirectOperationToolCallCommitReceiptV3> {
        self.ensure_live()?;
        self.file.validate(self.persisted_sha256.is_some())?;
        let record_index = self
            .file
            .records
            .iter()
            .position(|record| record.delivery.os_tool_call_id == acknowledgement.os_tool_call_id)
            .context("direct_tool_call_allocator_prepared_ack_correlation_unavailable_hold")?;
        if record_index + 1 != self.file.records.len() {
            bail!("direct_tool_call_allocator_prepared_ack_not_latest_hold");
        }
        let record = &self.file.records[record_index];
        let envelope = record
            .envelope
            .as_ref()
            .context("direct_tool_call_allocator_prepared_ack_before_allocation_hold")?;
        acknowledgement
            .validate_for_envelope(envelope)
            .map_err(|error| anyhow!(error.to_string()))?;
        if record.delivery.adapter_effect_ordinal != record_index as u64
            || self.file.records[..record_index]
                .iter()
                .any(|record| record.stage != AllocationStage::AdapterPrepared)
        {
            bail!("direct_tool_call_allocator_prepared_ack_ordinal_or_predecessor_hold");
        }
        if let Some(previous) = self.file.records[..record_index]
            .iter()
            .rev()
            .find_map(|record| record.prepared_acknowledgement.as_ref())
            && (previous.journal_epoch != acknowledgement.journal_epoch
                || previous.operation_epoch_authority_sha256
                    != acknowledgement.operation_epoch_authority_sha256
                || previous
                    .journal_sequence
                    .checked_add(1)
                    .is_none_or(|next| next != acknowledgement.journal_sequence))
        {
            bail!("direct_tool_call_allocator_operation_epoch_or_sequence_hold");
        }
        if record.stage == AllocationStage::AdapterPrepared {
            if record.prepared_acknowledgement.as_ref() != Some(acknowledgement) {
                bail!("direct_tool_call_allocator_prepared_ack_retry_drift_hold");
            }
            return receipt_for_record(record);
        }
        if record.stage != AllocationStage::CanonicalAllocated {
            bail!("direct_tool_call_allocator_prepared_ack_before_allocation_hold");
        }

        let acknowledged_generation = self
            .file
            .generation
            .checked_add(1)
            .context("direct_tool_call_allocator_generation_overflow")?;
        let mut candidate = self.file.clone();
        let candidate_record = &mut candidate.records[record_index];
        candidate_record.stage = AllocationStage::AdapterPrepared;
        candidate_record.prepared_acknowledgement = Some(acknowledgement.clone());
        candidate_record.acknowledged_generation = Some(acknowledged_generation);
        candidate_record.record_sha256 = candidate_record.digest_sha256()?;
        self.commit(candidate)?;
        let committed = self
            .file
            .records
            .get(record_index)
            .context("direct_tool_call_allocator_committed_record_missing")?;
        receipt_for_record(committed)
    }

    fn ensure_live(&self) -> Result<()> {
        if self.publication_durability_uncertain {
            bail!("direct_tool_call_allocator_fail_stop_commit_unknown_reopen_required");
        }
        if self.high_water_permanent_hold {
            bail!("direct_tool_call_allocator_external_high_water_permanent_hold");
        }
        self.ensure_local_live()?;
        if self.product_high_water_required {
            let high_water = self
                .high_water
                .as_ref()
                .context("direct_tool_call_allocator_verified_high_water_capability_missing")?;
            if high_water.route() != &high_water_route(&self.file)?
                || high_water.committed_head()
                    != &high_water_head(&self.file, self.persisted_sha256.is_some())?
            {
                bail!("direct_tool_call_allocator_live_high_water_drift_hold");
            }
        } else if self.high_water.is_some() {
            bail!("direct_tool_call_allocator_unexpected_high_water_capability");
        }
        Ok(())
    }

    fn ensure_local_live(&self) -> Result<()> {
        self.parent.validate(self.owner_uid)?;
        let current = read_named_file(
            &self.parent.directory,
            &self.destination_name,
            self.owner_uid,
            MAX_STORE_BYTES,
        )?;
        match (
            &self.persisted_sha256,
            &self.persisted_identity,
            current.as_ref(),
        ) {
            (None, None, None) => Ok(()),
            (Some(expected_sha256), Some(expected_identity), Some(stored))
                if sha256_bytes(&stored.bytes) == *expected_sha256
                    && stored.identity == *expected_identity =>
            {
                Ok(())
            }
            _ => bail!("direct_tool_call_allocator_changed_outside_atomic_writer"),
        }
    }

    fn commit(&mut self, candidate: AllocatorFileV1) -> Result<()> {
        let (candidate, bytes, published_sha256) = self.finalize_candidate(candidate)?;
        if !self.product_high_water_required {
            return self.publish_finalized_candidate(candidate, &bytes, published_sha256);
        }

        let from_head = high_water_head(&self.file, self.persisted_sha256.is_some())?;
        let to_head = high_water_head(&candidate, true)?;
        let authority = self
            .high_water
            .take()
            .context("direct_tool_call_allocator_verified_high_water_capability_missing")?;
        let prepared = match authority.prepare(to_head.clone()) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.high_water_permanent_hold = true;
                return Err(error)
                    .context("direct_tool_call_allocator_high_water_prepare_permanent_hold");
            }
        };

        if let Err(local_error) =
            self.publish_finalized_candidate(candidate, &bytes, published_sha256)
        {
            if self.publication_durability_uncertain {
                self.high_water_permanent_hold = true;
                return Err(local_error).context(
                    "direct_tool_call_allocator_local_commit_unknown_high_water_session_hold",
                );
            }
            match prepared.reconcile_known_local(from_head) {
                Ok(reconciled) => self.high_water = Some(reconciled),
                Err(reconcile_error) => {
                    self.high_water_permanent_hold = true;
                    return Err(reconcile_error).context(
                        "direct_tool_call_allocator_known_local_abort_reconcile_permanent_hold",
                    );
                }
            }
            return Err(local_error)
                .context("direct_tool_call_allocator_known_local_commit_failure_reconciled");
        }

        let committed = match prepared.commit(&to_head) {
            Ok(committed) => committed,
            Err(error) => {
                self.high_water_permanent_hold = true;
                return Err(error)
                    .context("direct_tool_call_allocator_high_water_commit_permanent_hold");
            }
        };
        let reconciled = match committed.reconcile(&to_head) {
            Ok(reconciled) => reconciled,
            Err(error) => {
                self.high_water_permanent_hold = true;
                return Err(error)
                    .context("direct_tool_call_allocator_high_water_reconcile_permanent_hold");
            }
        };
        self.high_water = Some(reconciled);
        self.ensure_live()
    }

    fn finalize_candidate(
        &self,
        mut candidate: AllocatorFileV1,
    ) -> Result<(AllocatorFileV1, Vec<u8>, String)> {
        self.ensure_live()?;
        candidate.generation = self
            .file
            .generation
            .checked_add(1)
            .context("direct_tool_call_allocator_generation_overflow")?;
        candidate.predecessor_store_sha256 = self
            .persisted_sha256
            .clone()
            .unwrap_or_else(|| ZERO_SHA256.to_string());
        candidate.store_sha256 = String::new();
        candidate.store_sha256 = candidate.digest_sha256()?;
        candidate.validate(true)?;
        let bytes = encode_canonical_file(&candidate)?;
        let published_sha256 = sha256_bytes(&bytes);
        Ok((candidate, bytes, published_sha256))
    }

    fn publish_finalized_candidate(
        &mut self,
        candidate: AllocatorFileV1,
        bytes: &[u8],
        published_sha256: String,
    ) -> Result<()> {
        self.ensure_local_live()?;
        if encode_canonical_file(&candidate)? != bytes || sha256_bytes(bytes) != published_sha256 {
            bail!("direct_tool_call_allocator_finalized_candidate_substitution_denied");
        }
        let temporary_name = temporary_name()?;
        let mut temporary =
            openat_create_new(self.parent.directory.as_raw_fd(), &temporary_name, 0o600)?;
        let before_rename = (|| -> Result<()> {
            set_exact_mode(&temporary, 0o600)?;
            temporary.write_all(bytes)?;
            temporary.sync_all()?;
            validate_open_regular(&temporary, self.owner_uid, MAX_STORE_BYTES)?;
            temporary.seek(SeekFrom::Start(0))?;
            let mut readback = Vec::new();
            Read::by_ref(&mut temporary)
                .take(MAX_STORE_BYTES as u64 + 1)
                .read_to_end(&mut readback)?;
            if readback != bytes {
                bail!("direct_tool_call_allocator_temp_readback_mismatch");
            }
            renameat_same_parent(
                self.parent.directory.as_raw_fd(),
                &temporary_name,
                &self.destination_name,
            )
        })();
        if let Err(error) = before_rename {
            let _ = unlinkat_file(self.parent.directory.as_raw_fd(), &temporary_name);
            return Err(error);
        }
        let published_identity = FileIdentity::from_metadata(&temporary.metadata()?);

        // Rename has made the new state authoritative. Never roll the in-memory
        // state back after this point; fail-stop until reopen if durability is
        // uncertain.
        self.file = candidate;
        self.persisted_sha256 = Some(published_sha256);
        self.persisted_identity = Some(published_identity);
        #[cfg(test)]
        if std::mem::take(&mut self.fail_parent_fsync_after_rename_once) {
            self.publication_durability_uncertain = true;
            bail!("direct_tool_call_allocator_parent_fsync_commit_unknown_test_fault");
        }
        if let Err(error) = self.parent.directory.sync_all() {
            self.publication_durability_uncertain = true;
            return Err(error).context("direct_tool_call_allocator_parent_fsync_commit_unknown");
        }
        match read_named_file(
            &self.parent.directory,
            &self.destination_name,
            self.owner_uid,
            MAX_STORE_BYTES,
        ) {
            Ok(Some(readback))
                if self.persisted_sha256.as_deref()
                    == Some(sha256_bytes(&readback.bytes).as_str())
                    && self.persisted_identity.as_ref() == Some(&readback.identity) => {}
            Ok(_) => {
                self.publication_durability_uncertain = true;
                bail!("direct_tool_call_allocator_published_readback_mismatch");
            }
            Err(error) => {
                self.publication_durability_uncertain = true;
                return Err(error).context("direct_tool_call_allocator_published_readback_failed");
            }
        }
        if let Err(error) = self.ensure_local_live() {
            self.publication_durability_uncertain = true;
            return Err(error).context("direct_tool_call_allocator_parent_changed_after_publish");
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn issue_for_test(
        &mut self,
        entropy_byte: u8,
    ) -> Result<DirectOperationToolCallDeliveryV3> {
        self.issue_delivery([entropy_byte; 32])
    }

    #[cfg(test)]
    fn allocate_for_test(
        &mut self,
        delivery: &DirectOperationToolCallDeliveryV3,
        canonical_request_sha256: &str,
    ) -> Result<DirectOperationToolCallEnvelopeV3> {
        self.allocate(delivery, canonical_request_sha256)
    }

    #[cfg(test)]
    fn acknowledge_prepared_for_test(
        &mut self,
        acknowledgement: &DirectOperationToolCallPreparedAckV3,
    ) -> Result<DirectOperationToolCallCommitReceiptV3> {
        self.acknowledge_prepared(acknowledgement)
    }

    #[cfg(test)]
    fn fail_parent_fsync_after_rename_once_for_test(&mut self) {
        self.fail_parent_fsync_after_rename_once = true;
    }
}

fn product_allocator_path(
    binding: &DirectOperationBinding,
    adapter: DirectOperationAdapter,
) -> Result<PathBuf> {
    binding
        .validate()
        .map_err(|error| anyhow!(error.to_string()))?;
    let binding_sha256 = binding
        .digest_sha256()
        .map_err(|error| anyhow!(error.to_string()))?;
    if !valid_nonzero_sha256(&binding_sha256) {
        bail!("direct_tool_call_allocator_product_binding_digest_denied");
    }
    Ok(Path::new(PRODUCT_ALLOCATOR_ROOT)
        .join(format!("{}-{binding_sha256}.json", adapter.adapter_id())))
}

fn open_allocator_store(
    path: &Path,
    owner_uid: u32,
    binding: DirectOperationBinding,
    adapter: DirectOperationAdapter,
    expected_high_water_authority: &'static str,
) -> Result<OpenedAllocatorStore> {
    if !valid_rollback_high_water_authority(expected_high_water_authority) {
        bail!("direct_tool_call_allocator_expected_authority_denied");
    }
    let (parent, destination_name) = secure_open_parent(path, owner_uid)?;
    lock_exclusive(&parent.directory)?;
    let stored = read_named_file(
        &parent.directory,
        &destination_name,
        owner_uid,
        MAX_STORE_BYTES,
    )?;
    let binding_sha256 = binding
        .digest_sha256()
        .map_err(|error| anyhow!(error.to_string()))?;
    let (file, persisted_sha256, persisted_identity) = match stored {
        Some(stored) => {
            let file = decode_canonical_file(&stored.bytes)?;
            if file.binding != binding
                || file.binding_sha256 != binding_sha256
                || file.adapter != adapter
                || file.rollback_high_water_authority != expected_high_water_authority
            {
                bail!("direct_tool_call_allocator_open_identity_or_authority_mismatch");
            }
            // Re-durabilize a rename-visible state after any predecessor lost
            // the parent-fsync response. External reconciliation still must
            // match the exact semantic generation/digest before admission.
            parent
                .directory
                .sync_all()
                .context("direct_tool_call_allocator_reopen_parent_fsync_failed")?;
            (
                file,
                Some(sha256_bytes(&stored.bytes)),
                Some(stored.identity),
            )
        }
        None => (
            AllocatorFileV1::empty(binding, adapter, expected_high_water_authority)?,
            None,
            None,
        ),
    };
    Ok(OpenedAllocatorStore {
        parent,
        destination_name,
        file,
        persisted_sha256,
        persisted_identity,
        owner_uid,
    })
}

fn high_water_route(file: &AllocatorFileV1) -> Result<DirectToolCallHighWaterRouteV1> {
    file.validate(!file.store_sha256.is_empty())?;
    DirectToolCallHighWaterRouteV1::derive(
        file.binding_sha256.clone(),
        file.binding.stable_seed.provider_id.clone(),
        file.binding.stable_seed.agent_id.clone(),
        file.adapter,
    )
}

fn high_water_head(
    file: &AllocatorFileV1,
    persisted: bool,
) -> Result<DirectToolCallHighWaterHeadV1> {
    file.validate(persisted)?;
    DirectToolCallHighWaterHeadV1::new(
        file.generation,
        if persisted {
            file.store_sha256.clone()
        } else {
            ZERO_SHA256.to_string()
        },
    )
}

fn receipt_for_record(
    record: &AllocationRecordV1,
) -> Result<DirectOperationToolCallCommitReceiptV3> {
    if record.stage != AllocationStage::AdapterPrepared {
        bail!("direct_tool_call_allocator_commit_receipt_before_prepared_ack");
    }
    let acknowledgement = record
        .prepared_acknowledgement
        .as_ref()
        .context("direct_tool_call_allocator_commit_receipt_ack_missing")?;
    let acknowledged_generation = record
        .acknowledged_generation
        .context("direct_tool_call_allocator_commit_receipt_generation_missing")?;
    DirectOperationToolCallCommitReceiptV3::derive(
        acknowledgement,
        acknowledged_generation,
        record.record_sha256.clone(),
    )
    .map_err(|error| anyhow!(error.to_string()))
}

fn derive_os_tool_call_id(
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    ordinal: u64,
    predecessor_record_sha256: &str,
    entropy: &[u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"domain", TOKEN_DIGEST_DOMAIN);
    hash_field(&mut hasher, b"binding_sha256", binding_sha256.as_bytes());
    hash_field(&mut hasher, b"adapter", adapter.adapter_id().as_bytes());
    hash_field(
        &mut hasher,
        b"adapter_effect_ordinal",
        &ordinal.to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        b"predecessor_record_sha256",
        predecessor_record_sha256.as_bytes(),
    );
    hash_field(&mut hasher, b"daemon_entropy", entropy);
    format!("{OS_TOOL_CALL_ID_PREFIX}{:x}", hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"domain", domain);
    hash_field(&mut hasher, b"value", &bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value != ZERO_SHA256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn valid_rollback_high_water_authority(value: &str) -> bool {
    let ordinary = matches!(
        value,
        ROLLBACK_HIGH_WATER_AUTHORITY_ABSENT_PRODUCT_HOLD
            | ROLLBACK_HIGH_WATER_AUTHORITY_FIXED_SOCKET_V1
    );
    #[cfg(feature = "p0-launch-package-device-conformance")]
    let ordinary = ordinary || value == P0_USERDEBUG_PREDISPATCH_CUSTODY_AUTHORITY_V1;
    ordinary
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn kernel_entropy() -> Result<[u8; 32]> {
    let mut entropy = [0_u8; 32];
    let mut filled = 0;
    while filled < entropy.len() {
        let read = unsafe {
            libc::getrandom(
                entropy[filled..].as_mut_ptr().cast(),
                entropy.len() - filled,
                0,
            )
        };
        if read > 0 {
            filled += usize::try_from(read)
                .context("direct_tool_call_allocator_getrandom_length_denied")?;
            continue;
        }
        if read == 0 {
            bail!("direct_tool_call_allocator_getrandom_eof");
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error).context("direct_tool_call_allocator_getrandom_denied");
        }
    }
    if entropy.iter().all(|byte| *byte == 0) {
        bail!("direct_tool_call_allocator_zero_entropy_denied");
    }
    Ok(entropy)
}

fn encode_canonical_file(file: &AllocatorFileV1) -> Result<Vec<u8>> {
    file.validate(true)?;
    let mut bytes = serde_json::to_vec_pretty(file)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_STORE_BYTES {
        bail!("direct_tool_call_allocator_store_size_limit_exceeded");
    }
    Ok(bytes)
}

fn decode_canonical_file(bytes: &[u8]) -> Result<AllocatorFileV1> {
    if bytes.is_empty() || bytes.len() > MAX_STORE_BYTES {
        bail!("direct_tool_call_allocator_store_size_boundary_denied");
    }
    let file: AllocatorFileV1 = serde_json::from_slice(bytes)
        .context("direct_tool_call_allocator_closed_world_json_denied")?;
    file.validate(true)?;
    if encode_canonical_file(&file)? != bytes {
        bail!("direct_tool_call_allocator_noncanonical_json_denied");
    }
    Ok(file)
}

fn secure_open_parent(path: &Path, owner_uid: u32) -> Result<(SecureParent, CString)> {
    if !path.is_absolute() {
        bail!("direct_tool_call_allocator_path_must_be_absolute");
    }
    let destination = path
        .file_name()
        .context("direct_tool_call_allocator_destination_missing")?;
    if destination.as_bytes().is_empty() || destination.as_bytes().contains(&0) {
        bail!("direct_tool_call_allocator_destination_denied");
    }
    let destination_name = CString::new(destination.as_bytes())
        .context("direct_tool_call_allocator_destination_contains_nul")?;
    let parent_path = path
        .parent()
        .context("direct_tool_call_allocator_parent_missing")?;
    let root_name = c"/";
    let mut current = open_directory(libc::AT_FDCWD, root_name)?;
    validate_trusted_ancestor(Path::new("/"), &current.metadata()?, owner_uid)?;
    let mut current_path = PathBuf::from("/");
    let mut components = Vec::new();
    for component in parent_path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name.to_owned()),
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                bail!("direct_tool_call_allocator_parent_component_denied")
            }
        }
    }
    if components.is_empty() {
        bail!("direct_tool_call_allocator_root_parent_denied");
    }
    for (index, component) in components.iter().enumerate() {
        let component_name = CString::new(component.as_bytes())
            .context("direct_tool_call_allocator_parent_component_contains_nul")?;
        let next = open_directory(current.as_raw_fd(), &component_name)?;
        current_path.push(component);
        let metadata = next.metadata()?;
        if index + 1 == components.len() {
            if !metadata.is_dir()
                || metadata.uid() != owner_uid
                || metadata.permissions().mode() & 0o7777 != 0o700
                || metadata.nlink() == 0
            {
                bail!("direct_tool_call_allocator_parent_not_owner_private");
            }
        } else {
            validate_trusted_ancestor(&current_path, &metadata, owner_uid)?;
        }
        current = next;
    }
    let parent = SecureParent {
        identity: FileIdentity::from_metadata(&current.metadata()?),
        directory: current,
    };
    parent.validate(owner_uid)?;
    Ok((parent, destination_name))
}

fn validate_trusted_ancestor(
    path: &Path,
    metadata: &std::fs::Metadata,
    owner_uid: u32,
) -> Result<()> {
    let mode = metadata.mode() & 0o7777;
    let trusted_owner = metadata.uid() == 0 || metadata.uid() == owner_uid;
    let sticky_system_root = metadata.uid() == 0
        && mode & libc::S_ISVTX != 0
        && matches!(path.to_str(), Some("/tmp" | "/var/tmp" | "/dev/shm"));
    if !metadata.is_dir()
        || metadata.nlink() == 0
        || !trusted_owner
        || (mode & 0o022 != 0 && !sticky_system_root)
    {
        bail!(
            "direct_tool_call_allocator_unsafe_ancestor:{}:uid={}:expected_uid={}:mode={:o}",
            path.display(),
            metadata.uid(),
            owner_uid,
            mode
        );
    }
    Ok(())
}

fn lock_exclusive(directory: &File) -> Result<()> {
    let result = unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_allocator_single_writer_lock_failed");
    }
    Ok(())
}

fn open_directory(parent_fd: RawFd, name: &CStr) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_allocator_open_directory_failed");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_named_file(
    parent: &File,
    name: &CStr,
    owner_uid: u32,
    max_bytes: usize,
) -> Result<Option<NamedFile>> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).context("direct_tool_call_allocator_open_file_failed");
    }
    let mut input = unsafe { File::from_raw_fd(fd) };
    validate_open_regular(&input, owner_uid, max_bytes)?;
    let opened_before = FileIdentity::from_metadata(&input.metadata()?);
    let mut bytes = Vec::new();
    Read::by_ref(&mut input)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        bail!("direct_tool_call_allocator_file_size_limit_exceeded");
    }
    let opened_after = FileIdentity::from_metadata(&input.metadata()?);
    let named = statat_nofollow(parent.as_raw_fd(), name)?
        .context("direct_tool_call_allocator_file_disappeared_during_read")?;
    if opened_before != opened_after
        || opened_before != named
        || opened_before.size < 0
        || opened_before.size as usize != bytes.len()
    {
        bail!("direct_tool_call_allocator_file_identity_changed_during_read");
    }
    Ok(Some(NamedFile {
        bytes,
        identity: opened_before,
    }))
}

fn statat_nofollow(parent_fd: RawFd, name: &CStr) -> Result<Option<FileIdentity>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let result = unsafe {
        libc::fstatat(
            parent_fd,
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
        return Err(error).context("direct_tool_call_allocator_fstatat_failed");
    }
    let stat = unsafe { stat.assume_init() };
    Ok(Some(FileIdentity::from_stat(&stat)))
}

fn validate_open_regular(file: &File, owner_uid: u32, max_bytes: usize) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > max_bytes as u64
    {
        bail!("direct_tool_call_allocator_file_not_owner_private_single_link");
    }
    Ok(())
}

fn openat_create_new(parent_fd: RawFd, name: &CStr, mode: libc::mode_t) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_allocator_create_temp_failed");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn set_exact_mode(file: &File, mode: u32) -> Result<()> {
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .context("direct_tool_call_allocator_set_mode_failed")
}

fn renameat_same_parent(parent_fd: RawFd, old_name: &CStr, new_name: &CStr) -> Result<()> {
    let result =
        unsafe { libc::renameat(parent_fd, old_name.as_ptr(), parent_fd, new_name.as_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_allocator_atomic_rename_failed");
    }
    Ok(())
}

fn unlinkat_file(parent_fd: RawFd, name: &CStr) -> Result<()> {
    let result = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_allocator_unlink_temp_failed");
    }
    Ok(())
}

fn temporary_name() -> Result<CString> {
    CString::new(format!(
        ".direct-tool-call-allocator.tmp-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
    .context("direct_tool_call_allocator_temp_name_contains_nul")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use tempfile::TempDir;
    use trillionnium_os_types::direct_operation::{
        BINDING_SCHEMA, DirectOperationProviderAttempt, DirectOperationStableSeed,
        STABLE_SEED_SCHEMA,
    };

    fn digest(label: &str) -> String {
        sha256_bytes(label.as_bytes())
    }

    fn owner_uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn private_tempdir() -> TempDir {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temporary
    }

    fn binding() -> DirectOperationBinding {
        let seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            task_id: "task-durable-logical-call".to_string(),
            provider_invocation_id_sha256: digest("provider-invocation"),
            provider_session_id_sha256: digest("provider-session"),
            subject_uid: 10_100,
            subject_selinux_domain_sha256: digest("subject-domain"),
        };
        DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            invocation_id: seed.invocation_id().unwrap(),
            stable_seed: seed,
            workflow_id_sha256: digest("workflow"),
            agent_identity_key_sha256: digest("identity-key"),
            agent_executable_sha256: digest("executable"),
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(
                digest("lifecycle"),
                1,
                digest("attempt-context"),
            )
            .unwrap(),
        }
    }

    fn binding_for_adapter(adapter: DirectOperationAdapter) -> DirectOperationBinding {
        let mut binding = binding();
        if adapter == DirectOperationAdapter::Accessibility {
            binding.authorized_adapter_set = trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::future_system_api_and_accessibility();
        }
        binding
    }

    fn prepared_ack(
        envelope: &DirectOperationToolCallEnvelopeV3,
        journal_epoch: &str,
        journal_sequence: u64,
    ) -> DirectOperationToolCallPreparedAckV3 {
        DirectOperationToolCallPreparedAckV3::derive(
            envelope,
            journal_epoch.to_string(),
            journal_sequence,
            digest(&format!("backend-request-{journal_sequence}")),
            digest(&format!("journal-payload-{journal_sequence}")),
            digest(&format!("runtime-authority-{journal_epoch}")),
        )
        .unwrap()
    }

    struct Fixture {
        _temporary: TempDir,
        path: PathBuf,
        allocator: DirectToolCallAllocator,
        binding: DirectOperationBinding,
    }

    struct HighWaterFixture {
        _temporary: TempDir,
        path: PathBuf,
        allocator: DirectToolCallAllocator,
        binding: DirectOperationBinding,
        authority: TestDirectToolCallHighWaterAuthority,
        adapter: DirectOperationAdapter,
    }

    fn fixture(adapter: DirectOperationAdapter) -> Fixture {
        let temporary = private_tempdir();
        let path = temporary.path().join("allocator.json");
        let binding = binding_for_adapter(adapter);
        let allocator =
            DirectToolCallAllocator::open_for_test(&path, owner_uid(), binding.clone(), adapter)
                .unwrap();
        Fixture {
            _temporary: temporary,
            path,
            allocator,
            binding,
        }
    }

    fn high_water_fixture(adapter: DirectOperationAdapter) -> HighWaterFixture {
        let temporary = private_tempdir();
        let path = temporary.path().join("allocator.json");
        let binding = binding_for_adapter(adapter);
        let binding_sha256 = binding.digest_sha256().unwrap();
        let route = DirectToolCallHighWaterRouteV1::derive(
            binding_sha256,
            binding.stable_seed.provider_id.clone(),
            binding.stable_seed.agent_id.clone(),
            adapter,
        )
        .unwrap();
        let authority = TestDirectToolCallHighWaterAuthority::new(
            route,
            DirectToolCallHighWaterHeadV1::new(0, ZERO_SHA256.to_string()).unwrap(),
        );
        let verified = DirectToolCallAllocator::verify_high_water_for_test(
            &path,
            owner_uid(),
            binding.clone(),
            adapter,
            &authority,
        )
        .unwrap();
        let allocator = DirectToolCallAllocator::open_verified_for_test(verified).unwrap();
        HighWaterFixture {
            _temporary: temporary,
            path,
            allocator,
            binding,
            authority,
            adapter,
        }
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
    fn equal_canonical_content_under_two_os_deliveries_is_two_logical_calls() {
        let mut fixture = fixture(DirectOperationAdapter::SystemApi);
        let canonical = digest("same-scroll");
        let first_delivery = fixture.allocator.issue_for_test(1).unwrap();
        let first = fixture
            .allocator
            .allocate_for_test(&first_delivery, &canonical)
            .unwrap();
        fixture
            .allocator
            .acknowledge_prepared_for_test(&prepared_ack(&first, &"01".repeat(16), 1))
            .unwrap();
        let second_delivery = fixture.allocator.issue_for_test(2).unwrap();
        let second = fixture
            .allocator
            .allocate_for_test(&second_delivery, &canonical)
            .unwrap();

        assert_eq!(first.adapter_effect_ordinal, 0);
        assert_eq!(second.adapter_effect_ordinal, 1);
        assert_ne!(first.os_tool_call_id, second.os_tool_call_id);
        assert_eq!(first.canonical_request_sha256, canonical);
        assert_eq!(second.canonical_request_sha256, canonical);
        assert_eq!(fixture.allocator.file.records.len(), 2);
    }

    #[test]
    fn exact_retry_survives_restart_and_returns_identical_envelope_without_commit() {
        let mut fixture = fixture(DirectOperationAdapter::Accessibility);
        let delivery = fixture.allocator.issue_for_test(3).unwrap();
        let first = fixture
            .allocator
            .allocate_for_test(&delivery, &digest("gesture"))
            .unwrap();
        let generation = fixture.allocator.file.generation;
        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        drop(fixture.allocator);
        let mut reopened = DirectToolCallAllocator::open_for_test(
            &path,
            owner_uid(),
            binding,
            DirectOperationAdapter::Accessibility,
        )
        .unwrap();
        let retry = reopened
            .allocate_for_test(&delivery, &digest("gesture"))
            .unwrap();
        assert_eq!(retry, first);
        assert_eq!(reopened.file.generation, generation);
    }

    #[test]
    fn allocated_but_unacknowledged_delivery_replays_after_restart_and_blocks_next_call() {
        let mut fixture = fixture(DirectOperationAdapter::SystemApi);
        let delivery = fixture.allocator.issue_for_test(31).unwrap();
        let canonical = digest("allocated-response-may-be-lost");
        let envelope = fixture
            .allocator
            .allocate_for_test(&delivery, &canonical)
            .unwrap();
        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        drop(fixture.allocator);

        let mut reopened = DirectToolCallAllocator::open_for_test(
            &path,
            owner_uid(),
            binding,
            DirectOperationAdapter::SystemApi,
        )
        .unwrap();
        assert_eq!(reopened.issue_for_test(32).unwrap(), delivery);
        assert_eq!(
            reopened.allocate_for_test(&delivery, &canonical).unwrap(),
            envelope
        );
        assert!(
            reopened
                .allocate_for_test(&delivery, &digest("different-call"))
                .unwrap_err()
                .to_string()
                .contains("retry_digest_mismatch_hold")
        );
        assert_eq!(reopened.file.records.len(), 1);
    }

    #[test]
    fn durable_prepared_ack_replays_exact_receipt_and_then_admits_next_delivery() {
        let mut fixture = fixture(DirectOperationAdapter::Accessibility);
        let delivery = fixture.allocator.issue_for_test(33).unwrap();
        let envelope = fixture
            .allocator
            .allocate_for_test(&delivery, &digest("click"))
            .unwrap();
        let acknowledgement = prepared_ack(&envelope, &"04".repeat(16), 17);
        let receipt = fixture
            .allocator
            .acknowledge_prepared_for_test(&acknowledgement)
            .unwrap();
        let generation = fixture.allocator.file.generation;
        assert_eq!(receipt.allocator_generation, generation);

        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        drop(fixture.allocator);
        let mut reopened = DirectToolCallAllocator::open_for_test(
            &path,
            owner_uid(),
            binding,
            DirectOperationAdapter::Accessibility,
        )
        .unwrap();
        assert_eq!(
            reopened
                .acknowledge_prepared_for_test(&acknowledgement)
                .unwrap(),
            receipt
        );
        assert_eq!(reopened.file.generation, generation);
        let next = reopened.issue_for_test(34).unwrap();
        assert_eq!(next.adapter_effect_ordinal, 1);
        assert_ne!(next.os_tool_call_id, delivery.os_tool_call_id);
    }

    #[test]
    fn android_ack_replay_proof_binds_exact_commit_and_outer_evidence() {
        let mut fixture = fixture(DirectOperationAdapter::SystemApi);
        let delivery = fixture.allocator.issue_for_test(38).unwrap();
        let canonical = digest("android-ack-replay-canonical");
        let envelope = fixture
            .allocator
            .allocate_for_test(&delivery, &canonical)
            .unwrap();
        let acknowledgement = prepared_ack(&envelope, &"08".repeat(16), 1);
        let receipt = fixture
            .allocator
            .acknowledge_prepared_for_test(&acknowledgement)
            .unwrap();
        let evidence = DirectOperationOuterEvidence {
            allocating_provider_attempt_id: fixture
                .binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            adapter_effect_ordinal: receipt.adapter_effect_ordinal,
            journal_sequence: acknowledgement.journal_sequence,
            tool: DirectOperationAdapter::SystemApi.tool_name().to_string(),
            canonical_request_sha256: canonical.clone(),
            backend_request_id_sha256: acknowledgement.backend_request_id_sha256.clone(),
            backend_result_sha256: digest("android-ack-replay-result"),
            outcome: trillionnium_os_types::direct_operation::DirectOperationOuterOutcome::Success,
            backend_error_code: None,
        };
        {
            let proof = fixture
                .allocator
                .verify_commit_for_android_ack(&receipt)
                .unwrap();
            assert_eq!(proof.receipt(), &receipt);
            proof.validate_outer_evidence(&evidence).unwrap();

            let mut wrong_ordinal = evidence.clone();
            wrong_ordinal.adapter_effect_ordinal += 1;
            assert!(
                proof
                    .validate_outer_evidence(&wrong_ordinal)
                    .unwrap_err()
                    .to_string()
                    .contains("ordinal_denied")
            );

            let mut wrong_sequence = evidence.clone();
            wrong_sequence.journal_sequence += 1;
            assert!(
                proof
                    .validate_outer_evidence(&wrong_sequence)
                    .unwrap_err()
                    .to_string()
                    .contains("journal_sequence_denied")
            );

            let mut wrong_backend_request = evidence.clone();
            wrong_backend_request.backend_request_id_sha256 = digest("other-backend-request");
            assert!(
                proof
                    .validate_outer_evidence(&wrong_backend_request)
                    .unwrap_err()
                    .to_string()
                    .contains("backend_request_denied")
            );
        }

        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        drop(fixture.allocator);
        let mut reopened = DirectToolCallAllocator::open_for_test(
            &path,
            owner_uid(),
            binding,
            DirectOperationAdapter::SystemApi,
        )
        .unwrap();
        let replayed_receipt = reopened
            .acknowledge_prepared_for_test(&acknowledgement)
            .unwrap();
        assert_eq!(replayed_receipt, receipt);
        let replay_proof = reopened
            .verify_commit_for_android_ack(&replayed_receipt)
            .unwrap();
        replay_proof.validate_outer_evidence(&evidence).unwrap();
    }

    #[test]
    fn prepared_ack_epoch_sequence_and_authority_drift_fail_closed() {
        let mut fixture = fixture(DirectOperationAdapter::SystemApi);
        let first_delivery = fixture.allocator.issue_for_test(35).unwrap();
        let first_envelope = fixture
            .allocator
            .allocate_for_test(&first_delivery, &digest("first"))
            .unwrap();
        fixture
            .allocator
            .acknowledge_prepared_for_test(&prepared_ack(&first_envelope, &"05".repeat(16), 9))
            .unwrap();
        let second_delivery = fixture.allocator.issue_for_test(36).unwrap();
        let second_envelope = fixture
            .allocator
            .allocate_for_test(&second_delivery, &digest("second"))
            .unwrap();

        let wrong_epoch = prepared_ack(&second_envelope, &"06".repeat(16), 10);
        assert!(
            fixture
                .allocator
                .acknowledge_prepared_for_test(&wrong_epoch)
                .unwrap_err()
                .to_string()
                .contains("operation_epoch_or_sequence_hold")
        );
        let skipped_sequence = prepared_ack(&second_envelope, &"05".repeat(16), 11);
        assert!(
            fixture
                .allocator
                .acknowledge_prepared_for_test(&skipped_sequence)
                .unwrap_err()
                .to_string()
                .contains("operation_epoch_or_sequence_hold")
        );
        let mut absent_authority = prepared_ack(&second_envelope, &"05".repeat(16), 10);
        absent_authority.operation_epoch_authority_sha256 = ZERO_SHA256.to_string();
        assert!(
            fixture
                .allocator
                .acknowledge_prepared_for_test(&absent_authority)
                .is_err()
        );

        let mut changed_authority = prepared_ack(&second_envelope, &"05".repeat(16), 10);
        changed_authority.operation_epoch_authority_sha256 = digest("other-first-use-authority");
        changed_authority.prepared_ack_sha256 = changed_authority.digest_sha256().unwrap();
        assert!(
            fixture
                .allocator
                .acknowledge_prepared_for_test(&changed_authority)
                .unwrap_err()
                .to_string()
                .contains("operation_epoch_or_sequence_hold")
        );
        assert_eq!(
            fixture.allocator.file.records[1].stage,
            AllocationStage::CanonicalAllocated
        );

        let second_acknowledgement = prepared_ack(&second_envelope, &"05".repeat(16), 10);
        fixture
            .allocator
            .acknowledge_prepared_for_test(&second_acknowledgement)
            .unwrap();
        let mut self_consistent_drift = fixture.allocator.file.clone();
        let drifted = self_consistent_drift.records[1]
            .prepared_acknowledgement
            .as_mut()
            .unwrap();
        drifted.operation_epoch_authority_sha256 = digest("persisted-other-authority");
        drifted.prepared_ack_sha256 = drifted.digest_sha256().unwrap();
        self_consistent_drift.records[1].record_sha256 =
            self_consistent_drift.records[1].digest_sha256().unwrap();
        self_consistent_drift.store_sha256 = self_consistent_drift.digest_sha256().unwrap();
        assert!(
            self_consistent_drift
                .validate(true)
                .unwrap_err()
                .to_string()
                .contains("operation_epoch_or_sequence_denied")
        );
    }

    #[test]
    fn one_delivery_token_cannot_change_digest_or_ordinal() {
        let mut fixture = fixture(DirectOperationAdapter::SystemApi);
        let delivery = fixture.allocator.issue_for_test(4).unwrap();
        fixture
            .allocator
            .allocate_for_test(&delivery, &digest("launch-a"))
            .unwrap();
        let error = fixture
            .allocator
            .allocate_for_test(&delivery, &digest("launch-b"))
            .unwrap_err();
        assert!(error.to_string().contains("retry_digest_mismatch_hold"));

        let mut forged = delivery.clone();
        forged.adapter_effect_ordinal += 1;
        forged.delivery_sha256 = forged.digest_sha256().unwrap();
        let error = fixture
            .allocator
            .allocate_for_test(&forged, &digest("launch-a"))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("delivery_token_or_ordinal_drift_hold")
        );
    }

    #[test]
    fn unknown_or_cross_binding_delivery_is_held_before_allocation() {
        let mut fixture = fixture(DirectOperationAdapter::SystemApi);
        let delivery = fixture.allocator.issue_for_test(5).unwrap();
        let mut unknown = delivery.clone();
        unknown.os_tool_call_id = format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest("unknown-token"));
        unknown.delivery_sha256 = unknown.digest_sha256().unwrap();
        let error = fixture
            .allocator
            .allocate_for_test(&unknown, &digest("request"))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("delivery_correlation_unavailable_hold")
        );

        let mut cross_binding = delivery;
        cross_binding.binding_sha256 = digest("other-binding");
        cross_binding.delivery_sha256 = cross_binding.digest_sha256().unwrap();
        assert!(
            fixture
                .allocator
                .allocate_for_test(&cross_binding, &digest("request"))
                .is_err()
        );
        assert_eq!(fixture.allocator.file.records.len(), 1);
        assert_eq!(
            fixture.allocator.file.records[0].stage,
            AllocationStage::DeliveryIssued
        );
    }

    #[test]
    fn pending_delivery_is_recovered_and_blocks_ordinal_jump() {
        let mut fixture = fixture(DirectOperationAdapter::Accessibility);
        let pending = fixture.allocator.issue_for_test(6).unwrap();
        let recovered = fixture.allocator.issue_for_test(7).unwrap();
        assert_eq!(recovered, pending);
        assert_eq!(fixture.allocator.file.records.len(), 1);
        let envelope = fixture
            .allocator
            .allocate_for_test(&pending, &digest("first"))
            .unwrap();
        assert_eq!(fixture.allocator.issue_for_test(7).unwrap(), pending);
        fixture
            .allocator
            .acknowledge_prepared_for_test(&prepared_ack(&envelope, &"02".repeat(16), 1))
            .unwrap();
        let second = fixture.allocator.issue_for_test(7).unwrap();
        assert_eq!(second.adapter_effect_ordinal, 1);
    }

    #[test]
    fn cached_pending_or_allocated_identity_never_bypasses_named_store_revalidation() {
        let mut pending_fixture = fixture(DirectOperationAdapter::SystemApi);
        pending_fixture.allocator.issue_for_test(6).unwrap();
        fs::remove_file(&pending_fixture.path).unwrap();
        assert!(
            pending_fixture
                .allocator
                .issue_for_test(7)
                .unwrap_err()
                .to_string()
                .contains("changed_outside_atomic_writer")
        );

        let mut allocated_fixture = fixture(DirectOperationAdapter::Accessibility);
        let delivery = allocated_fixture.allocator.issue_for_test(8).unwrap();
        allocated_fixture
            .allocator
            .allocate_for_test(&delivery, &digest("terminal-retry"))
            .unwrap();
        let replacement = allocated_fixture.path.with_extension("replacement");
        fs::write(&replacement, fs::read(&allocated_fixture.path).unwrap()).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &allocated_fixture.path).unwrap();
        assert!(
            allocated_fixture
                .allocator
                .allocate_for_test(&delivery, &digest("terminal-retry"))
                .unwrap_err()
                .to_string()
                .contains("changed_outside_atomic_writer")
        );
    }

    #[test]
    fn parent_fsync_commit_unknown_fail_stops_and_reopen_recovers_same_token() {
        let mut fixture = fixture(DirectOperationAdapter::SystemApi);
        fixture
            .allocator
            .fail_parent_fsync_after_rename_once_for_test();
        let error = fixture.allocator.issue_for_test(8).unwrap_err();
        assert!(error.to_string().contains("parent_fsync_commit_unknown"));
        assert!(fixture.allocator.issue_for_test(9).is_err());

        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        let published = fixture.allocator.file.records[0].delivery.clone();
        drop(fixture.allocator);
        let mut reopened = DirectToolCallAllocator::open_for_test(
            &path,
            owner_uid(),
            binding,
            DirectOperationAdapter::SystemApi,
        )
        .unwrap();
        assert_eq!(reopened.issue_for_test(9).unwrap(), published);
        reopened
            .allocate_for_test(&published, &digest("recovered"))
            .unwrap();
    }

    #[test]
    fn allocated_envelope_parent_fsync_commit_unknown_reopens_as_exact_retry() {
        let mut fixture = fixture(DirectOperationAdapter::Accessibility);
        let delivery = fixture.allocator.issue_for_test(9).unwrap();
        fixture
            .allocator
            .fail_parent_fsync_after_rename_once_for_test();
        let canonical = digest("allocated-before-parent-fsync-unknown");
        let error = fixture
            .allocator
            .allocate_for_test(&delivery, &canonical)
            .unwrap_err();
        assert!(error.to_string().contains("parent_fsync_commit_unknown"));
        let published = fixture.allocator.file.records[0].envelope.clone().unwrap();
        assert!(
            fixture
                .allocator
                .allocate_for_test(&delivery, &canonical)
                .is_err()
        );

        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        drop(fixture.allocator);
        let mut reopened = DirectToolCallAllocator::open_for_test(
            &path,
            owner_uid(),
            binding,
            DirectOperationAdapter::Accessibility,
        )
        .unwrap();
        assert_eq!(
            reopened.allocate_for_test(&delivery, &canonical).unwrap(),
            published
        );
    }

    #[test]
    fn prepared_ack_parent_fsync_commit_unknown_reopens_as_exact_receipt() {
        let mut fixture = fixture(DirectOperationAdapter::SystemApi);
        let delivery = fixture.allocator.issue_for_test(37).unwrap();
        let envelope = fixture
            .allocator
            .allocate_for_test(&delivery, &digest("prepared-before-commit-unknown"))
            .unwrap();
        let acknowledgement = prepared_ack(&envelope, &"07".repeat(16), 1);
        fixture
            .allocator
            .fail_parent_fsync_after_rename_once_for_test();
        let error = fixture
            .allocator
            .acknowledge_prepared_for_test(&acknowledgement)
            .unwrap_err();
        assert!(error.to_string().contains("parent_fsync_commit_unknown"));
        assert!(
            fixture
                .allocator
                .acknowledge_prepared_for_test(&acknowledgement)
                .is_err()
        );

        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        drop(fixture.allocator);
        let mut reopened = DirectToolCallAllocator::open_for_test(
            &path,
            owner_uid(),
            binding,
            DirectOperationAdapter::SystemApi,
        )
        .unwrap();
        let receipt = reopened
            .acknowledge_prepared_for_test(&acknowledgement)
            .unwrap();
        receipt
            .validate_for_acknowledgement(&acknowledgement)
            .unwrap();
        assert_eq!(
            reopened.file.records[0].stage,
            AllocationStage::AdapterPrepared
        );
    }

    #[test]
    fn closed_world_store_rejects_tamper_symlink_and_wrong_binding() {
        let mut fixture = fixture(DirectOperationAdapter::SystemApi);
        let delivery = fixture.allocator.issue_for_test(10).unwrap();
        fixture
            .allocator
            .allocate_for_test(&delivery, &digest("back"))
            .unwrap();
        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        drop(fixture.allocator);

        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["unknown"] = serde_json::json!(true);
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert!(
            DirectToolCallAllocator::open_for_test(
                &path,
                owner_uid(),
                binding.clone(),
                DirectOperationAdapter::SystemApi,
            )
            .is_err()
        );

        fs::remove_file(&path).unwrap();
        let target = path.with_extension("target");
        fs::write(&target, b"{}\n").unwrap();
        symlink(&target, &path).unwrap();
        assert!(
            DirectToolCallAllocator::open_for_test(
                &path,
                owner_uid(),
                binding,
                DirectOperationAdapter::SystemApi,
            )
            .is_err()
        );
    }

    #[test]
    fn valid_historical_snapshot_demonstrates_external_high_water_product_hold() {
        let mut fixture = fixture(DirectOperationAdapter::SystemApi);
        let first_delivery = fixture.allocator.issue_for_test(11).unwrap();
        let first_envelope = fixture
            .allocator
            .allocate_for_test(&first_delivery, &digest("first"))
            .unwrap();
        fixture
            .allocator
            .acknowledge_prepared_for_test(&prepared_ack(&first_envelope, &"03".repeat(16), 1))
            .unwrap();
        let historical_bytes = fs::read(&fixture.path).unwrap();

        let second_delivery = fixture.allocator.issue_for_test(12).unwrap();
        let second_envelope = fixture
            .allocator
            .allocate_for_test(&second_delivery, &digest("second"))
            .unwrap();
        fixture
            .allocator
            .acknowledge_prepared_for_test(&prepared_ack(&second_envelope, &"03".repeat(16), 2))
            .unwrap();
        assert_eq!(fixture.allocator.file.records.len(), 2);
        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        drop(fixture.allocator);

        // This is an internally valid complete predecessor snapshot. The local
        // hash chain alone cannot distinguish it from a device-state rollback.
        // Only the test constructor may reopen it; product remains
        // unconstructible until an external rollback-resistant high-water
        // authority replaces the explicit absent marker.
        fs::write(&path, historical_bytes).unwrap();
        let reopened = DirectToolCallAllocator::open_for_test(
            &path,
            owner_uid(),
            binding,
            DirectOperationAdapter::SystemApi,
        )
        .unwrap();
        assert_eq!(reopened.file.records.len(), 1);
        assert_eq!(
            reopened.file.rollback_high_water_authority,
            ROLLBACK_HIGH_WATER_AUTHORITY_ABSENT_PRODUCT_HOLD
        );
    }

    #[test]
    fn verified_high_water_advances_with_each_local_commit_and_reopens_exactly() {
        let mut fixture = high_water_fixture(DirectOperationAdapter::SystemApi);
        let delivery = fixture.allocator.issue_for_test(41).unwrap();
        assert_eq!(fixture.allocator.file.generation, 1);
        assert_eq!(
            fixture.authority.committed_head(),
            high_water_head(&fixture.allocator.file, true).unwrap()
        );
        let envelope = fixture
            .allocator
            .allocate_for_test(&delivery, &digest("high-water-launch"))
            .unwrap();
        fixture
            .allocator
            .acknowledge_prepared_for_test(&prepared_ack(&envelope, &"0b".repeat(16), 1))
            .unwrap();
        assert_eq!(fixture.allocator.file.generation, 3);
        assert_eq!(
            fixture.authority.committed_head(),
            high_water_head(&fixture.allocator.file, true).unwrap()
        );

        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        let adapter = fixture.adapter;
        drop(fixture.allocator);
        let verified = DirectToolCallAllocator::verify_high_water_for_test(
            &path,
            owner_uid(),
            binding,
            adapter,
            &fixture.authority,
        )
        .unwrap();
        let mut reopened = DirectToolCallAllocator::open_verified_for_test(verified).unwrap();
        assert_eq!(
            reopened
                .acknowledge_prepared_for_test(&prepared_ack(&envelope, &"0b".repeat(16), 1))
                .unwrap()
                .allocator_generation,
            3
        );
        assert_eq!(
            reopened.issue_for_test(42).unwrap().adapter_effect_ordinal,
            1
        );
    }

    #[test]
    fn external_high_water_rejects_valid_local_generation_rollback_on_restart() {
        let mut fixture = high_water_fixture(DirectOperationAdapter::Accessibility);
        fixture.allocator.issue_for_test(43).unwrap();
        let historical = fs::read(&fixture.path).unwrap();
        let delivery = fixture
            .allocator
            .recover_pending_verified_delivery()
            .unwrap();
        fixture
            .allocator
            .allocate_for_test(&delivery, &digest("newer-local-head"))
            .unwrap();
        let committed = fixture.authority.committed_head();
        assert_eq!(committed.generation(), 2);
        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        let adapter = fixture.adapter;
        drop(fixture.allocator);

        fs::write(&path, historical).unwrap();
        assert!(
            DirectToolCallAllocator::verify_high_water_for_test(
                &path,
                owner_uid(),
                binding,
                adapter,
                &fixture.authority,
            )
            .err()
            .unwrap()
            .to_string()
            .contains("permanent_hold")
        );
        assert!(fixture.authority.is_permanent_hold());
    }

    #[test]
    fn external_high_water_rejects_same_generation_valid_digest_fork() {
        let mut first = high_water_fixture(DirectOperationAdapter::SystemApi);
        first.allocator.issue_for_test(44).unwrap();
        let first_head = first.authority.committed_head();
        let first_path = first.path.clone();
        let first_binding = first.binding.clone();
        let first_adapter = first.adapter;
        drop(first.allocator);

        let mut fork = high_water_fixture(DirectOperationAdapter::SystemApi);
        fork.allocator.issue_for_test(45).unwrap();
        assert_eq!(fork.allocator.file.generation, first_head.generation());
        assert_ne!(
            fork.allocator.file.store_sha256,
            first_head.allocator_store_sha256()
        );
        let fork_bytes = fs::read(&fork.path).unwrap();
        drop(fork.allocator);

        fs::write(&first_path, fork_bytes).unwrap();
        assert!(
            DirectToolCallAllocator::verify_high_water_for_test(
                &first_path,
                owner_uid(),
                first_binding,
                first_adapter,
                &first.authority,
            )
            .is_err()
        );
        assert!(first.authority.is_permanent_hold());
    }

    #[test]
    fn external_commit_outcome_unknown_is_permanent_hold_across_restart() {
        let mut fixture = high_water_fixture(DirectOperationAdapter::Accessibility);
        fixture
            .authority
            .inject_commit_outcome_unknown_after_apply();
        let error = fixture.allocator.issue_for_test(46).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("high_water_commit_permanent_hold")
        );
        assert!(fixture.authority.is_permanent_hold());
        assert!(
            fixture
                .allocator
                .issue_for_test(47)
                .unwrap_err()
                .to_string()
                .contains("external_high_water_permanent_hold")
        );
        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        let adapter = fixture.adapter;
        drop(fixture.allocator);
        assert!(
            DirectToolCallAllocator::verify_high_water_for_test(
                &path,
                owner_uid(),
                binding,
                adapter,
                &fixture.authority,
            )
            .is_err()
        );
    }

    #[test]
    fn local_parent_fsync_unknown_reconciles_exact_published_head_after_restart() {
        let mut fixture = high_water_fixture(DirectOperationAdapter::SystemApi);
        fixture
            .allocator
            .fail_parent_fsync_after_rename_once_for_test();
        let error = fixture.allocator.issue_for_test(48).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("local_commit_unknown_high_water_session_hold")
        );
        let published = fixture.allocator.file.records[0].delivery.clone();
        let path = fixture.path.clone();
        let binding = fixture.binding.clone();
        let adapter = fixture.adapter;
        drop(fixture.allocator);

        let verified = DirectToolCallAllocator::verify_high_water_for_test(
            &path,
            owner_uid(),
            binding,
            adapter,
            &fixture.authority,
        )
        .unwrap();
        let mut reopened = DirectToolCallAllocator::open_verified_for_test(verified).unwrap();
        assert_eq!(reopened.issue_for_test(49).unwrap(), published);
        assert_eq!(
            fixture.authority.committed_head(),
            high_water_head(&reopened.file, true).unwrap()
        );
    }

    #[test]
    fn product_route_has_no_constructor_and_provider_ids_are_not_ledger_inputs() {
        let source = include_str!("direct_tool_call_allocator.rs");
        assert!(source.contains("_unconstructible: Infallible"));
        assert!(source.contains("ROLLBACK_HIGH_WATER_AUTHORITY_ABSENT_PRODUCT_HOLD"));
        assert!(source.contains("pub(crate) fn open_product("));
        assert!(source.contains("VerifiedProductAllocatorHighWater"));
        assert!(source.contains(PRODUCT_ALLOCATOR_ROOT));
        for forbidden in [
            ["model_", "tool_call_id"].concat(),
            ["provider_json_", "rpc_id"].concat(),
            ["unregistered_", "tool_call_id"].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }

        let daemon_main = include_str!("main.rs");
        assert!(daemon_main.contains("mod direct_tool_call_allocator;"));
        assert!(!daemon_main.contains("DirectToolCallAllocator::open_at_path"));
    }

    #[test]
    fn product_allocator_holds_before_store_or_high_water_without_admission_contract() {
        assert!(!transport_contract::product_admission_contract_is_complete());
        let error = match DirectToolCallAllocator::verify_product_high_water(
            binding(),
            DirectOperationAdapter::SystemApi,
        ) {
            Ok(_) => panic!("product allocator unexpectedly crossed the admission boundary"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains(transport_contract::PRODUCTION_ADMISSION_HOLD_CODE),
            "unexpected product allocator admission error: {error:#}"
        );
    }
}
