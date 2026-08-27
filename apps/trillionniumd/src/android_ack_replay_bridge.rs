//! Source-only seam between the durable allocator PREPARED receipt and a
//! future Android ACK/replay adapter.
//!
//! `VerifiedAllocatorCommitForAndroidAck` is the only allocator value accepted
//! here.  It is borrowed from the locked allocator and can therefore not be
//! rebuilt from a path, generation, digest, or serialized boolean.  The
//! listener value is likewise the already-bound, kernel-authenticated
//! pre-effect transport capability.  This module deliberately stops at the
//! product-custody boundary: no Android connector, operation epoch, replay
//! high-water, KeyMint/Accessibility authority, or effect handoff exists.

use anyhow::{Result, bail};
use trillionnium_os_types::direct_operation::{
    DirectOperationOuterEvidence, DirectOperationToolCallCommitReceiptV3,
};
use trillionnium_os_types::direct_operation_tool_call_transport as transport_contract;

use crate::direct_tool_call_allocator::VerifiedAllocatorCommitForAndroidAck;
use crate::direct_tool_call_transport::ProductBoundDirectToolCallListener;

/// Stable source status for evidence and host-side contract checks.
pub(crate) const SOURCE_STATUS: &str =
    "source_only_allocator_commit_android_ack_replay_bridge_product_hold_v1";

/// The bridge must not be mistaken for an Android effect authority.  Keeping
/// this independent bit false makes a future transport/allocator wiring change
/// insufficient by itself to create an ACK handoff.
pub(crate) const ANDROID_ACK_REPLAY_HANDOFF_PRODUCT_WIRED: bool = false;

pub(crate) const PRODUCT_HOLD_CODE: &str =
    "direct_tool_call_android_ack_replay_product_custody_unavailable";

const _: () = {
    assert!(transport_contract::SOURCE_LISTENER_IMPLEMENTED);
    assert!(transport_contract::SOURCE_SESSION_HANDLER_IMPLEMENTED);
    assert!(!transport_contract::DAEMON_LISTENER_PRODUCT_WIRED);
    assert!(!transport_contract::ADAPTER_CONNECTOR_PRODUCT_WIRED);
    assert!(!transport_contract::PROVIDER_DELIVERY_PRODUCT_WIRED);
    assert!(!transport_contract::FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE);
    assert!(!transport_contract::ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE);
    assert!(!transport_contract::CONFERS_EFFECT_AUTHORITY);
    assert!(!ANDROID_ACK_REPLAY_HANDOFF_PRODUCT_WIRED);
};

/// Return the one product decision currently available at this boundary.
///
/// This function has no inputs which could be confused with authority.  A
/// caller must receive the HOLD before it can attempt to bind an Android
/// adapter, so a missing product contract cannot be treated as a retryable
/// transport error.
pub(crate) fn require_product_handoff() -> Result<()> {
    if !transport_contract::product_admission_contract_is_complete()
        || !ANDROID_ACK_REPLAY_HANDOFF_PRODUCT_WIRED
    {
        bail!(PRODUCT_HOLD_CODE);
    }
    Ok(())
}

/// Opaque custody retained between the fixed listener and the allocator ACK
/// proof.  Construction is intentionally impossible on the current product
/// lane: [`bind_product`] first requires every static product admission bit and
/// the independent Android ACK/replay handoff bit.
#[must_use = "Android ACK/replay custody must remain retained until handoff"]
pub(crate) struct AndroidAckReplayProductCustody<'a> {
    // Prefixes make the ownership intent explicit; neither value is exposed
    // as a standalone authority or serializable record.
    _listener: ProductBoundDirectToolCallListener<'a>,
    _allocator_commit: VerifiedAllocatorCommitForAndroidAck<'a>,
}

impl<'a> AndroidAckReplayProductCustody<'a> {
    /// Bind only an already-validated listener and exact allocator commit.
    ///
    /// The current result is always the stable product HOLD.  The success arm
    /// is intentionally kept in the source so a future implementation must
    /// supply both proof objects rather than adding a path/digest constructor.
    pub(crate) fn bind_product(
        listener: ProductBoundDirectToolCallListener<'a>,
        allocator_commit: VerifiedAllocatorCommitForAndroidAck<'a>,
    ) -> Result<Self> {
        require_product_handoff()?;
        Ok(Self {
            _listener: listener,
            _allocator_commit: allocator_commit,
        })
    }

    /// Revalidate the exact persisted allocator commit before any future ACK
    /// handoff.  The static HOLD is checked first, so evidence is never
    /// treated as an authority substitute while the Android connector is
    /// absent.
    pub(crate) fn validate_for_handoff(
        &self,
        evidence: &DirectOperationOuterEvidence,
    ) -> Result<()> {
        require_product_handoff()?;
        self._allocator_commit.validate_outer_evidence(evidence)
    }

    /// Expose only the daemon-derived receipt for a future adapter envelope;
    /// this does not grant permission to send it anywhere.
    pub(crate) fn receipt(&self) -> &DirectOperationToolCallCommitReceiptV3 {
        self._allocator_commit.receipt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_handoff_is_stable_fail_closed_hold() {
        assert_eq!(
            SOURCE_STATUS,
            "source_only_allocator_commit_android_ack_replay_bridge_product_hold_v1"
        );
        assert!(!ANDROID_ACK_REPLAY_HANDOFF_PRODUCT_WIRED);
        let error = require_product_handoff().unwrap_err();
        assert_eq!(error.to_string(), PRODUCT_HOLD_CODE);
    }

    #[test]
    fn daemon_main_does_not_instantiate_bridge_or_listener() {
        let source = include_str!("main.rs");
        assert!(source.contains("mod android_ack_replay_bridge;"));
        assert!(!source.contains("AndroidAckReplayProductCustody::bind_product("));
        assert!(!source.contains("FixedDirectToolCallListener::bind_product("));
    }
}
