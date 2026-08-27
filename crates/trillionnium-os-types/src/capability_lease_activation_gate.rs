//! Source-only activation gate for the Android capability-lease path.
//!
//! The first capability-lease slice has control-side identity binding, but it
//! does not yet have a product lease issuer/consumer, a hardware-backed
//! rollback anchor, or a closed Android Accessibility effect path.  This
//! module makes those three prerequisites one explicit, fail-closed contract.
//! It intentionally contains no Android I/O, KeyMint call, trust-manifest
//! loader, service registration, ACK publisher, or device mutation.
//!
//! A complete gate can only be produced by a future OS-owned authority.  No
//! production constructor is exposed here.  The test-only fixture is marked
//! synthetic and must never be treated as hardware evidence or product
//! enablement.

use std::error::Error;
use std::fmt;

pub const CONTRACT_SCHEMA: &str = "org.trillionnium.capabilitylease.activation-gate.contract.v1";
pub const CONTRACT_SHA256: &str =
    "428df18395bd5abb66107724262cbdeaa403af705f1dce54d8ca901822c1d21a";
pub const SOURCE_STATUS: &str = "source_only_no_product_authority_v1";

/// Whether this source tree exposes an OS-owned production gate constructor.
pub const PRODUCT_CONSTRUCTOR_AVAILABLE: bool = false;
/// Whether a root-owned product enablement token can be issued and consumed.
pub const PRODUCT_ENABLEMENT_TOKEN_AVAILABLE: bool = false;
/// Whether the gate itself can authorize an Android effect.
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

/// The issuer/consume evidence that must be supplied by a future trusted
/// authority.  Names are contract fields, not evidence values.
pub const REQUIRED_ISSUER_CONSUME_EVIDENCE: &[&str] = &[
    "root_trust_manifest_sha256",
    "issuer_identity_binding_sha256",
    "consumer_receipt_binding_sha256",
    "lease_epoch_high_water_proof_sha256",
];

/// The hardware rollback evidence that must be supplied by a future Android
/// KeyMint/Verified-Boot authority.  No value for any field exists here.
pub const REQUIRED_HARDWARE_ROLLBACK_EVIDENCE: &[&str] = &[
    "keymint_attestation_chain_sha256",
    "keymint_verified_boot_state",
    "avb_rollback_index_high_water",
    "rollback_index_persistence_proof_sha256",
];

/// The Accessibility closure evidence that must bind service ownership,
/// schema, operation epoch/replay, and the receipt/ACK terminal edge.
pub const REQUIRED_ACCESSIBILITY_CLOSURE_EVIDENCE: &[&str] = &[
    "accessibility_service_ownership_proof_sha256",
    "accessibility_mcp_schema_sha256",
    "accessibility_operation_epoch_replay_proof_sha256",
    "accessibility_receipt_ack_closure_sha256",
];

/// Aliases make the three release-gate names easy to discover at call sites.
pub const ISSUER_CONSUME_REQUIRED_EVIDENCE: &[&str] = REQUIRED_ISSUER_CONSUME_EVIDENCE;
pub const HARDWARE_ROLLBACK_REQUIRED_EVIDENCE: &[&str] = REQUIRED_HARDWARE_ROLLBACK_EVIDENCE;
pub const ACCESSIBILITY_CLOSURE_REQUIRED_EVIDENCE: &[&str] =
    REQUIRED_ACCESSIBILITY_CLOSURE_EVIDENCE;

/// The three independent prerequisites for capability-lease activation.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum CapabilityLeaseActivationComponentV1 {
    IssuerConsume,
    HardwareRollback,
    AccessibilityClosure,
}

impl CapabilityLeaseActivationComponentV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IssuerConsume => "issuer_consume",
            Self::HardwareRollback => "hardware_rollback",
            Self::AccessibilityClosure => "accessibility_closure",
        }
    }

    const fn missing_error_code(self) -> &'static str {
        match self {
            Self::IssuerConsume => "capability_lease_activation_issuer_consume_unavailable",
            Self::HardwareRollback => "capability_lease_activation_hardware_rollback_unavailable",
            Self::AccessibilityClosure => {
                "capability_lease_activation_accessibility_closure_unavailable"
            }
        }
    }
}

impl fmt::Display for CapabilityLeaseActivationComponentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Decision reported by the gate.  `Enabled` is unreachable from this source
/// tree because product authority is deliberately unavailable.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CapabilityLeaseActivationDecisionV1 {
    Hold,
    Enabled,
}

/// Fail-closed reasons returned before any capability-lease effect can run.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CapabilityLeaseActivationErrorV1 {
    MissingComponent(CapabilityLeaseActivationComponentV1),
    ProductAuthorityUnavailable,
    EffectAuthorityUnavailable,
}

impl CapabilityLeaseActivationErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingComponent(component) => component.missing_error_code(),
            Self::ProductAuthorityUnavailable => {
                "capability_lease_activation_product_authority_unavailable"
            }
            Self::EffectAuthorityUnavailable => {
                "capability_lease_activation_effect_authority_unavailable"
            }
        }
    }

    #[must_use]
    pub const fn component(self) -> Option<CapabilityLeaseActivationComponentV1> {
        match self {
            Self::MissingComponent(component) => Some(component),
            Self::ProductAuthorityUnavailable | Self::EffectAuthorityUnavailable => None,
        }
    }
}

impl fmt::Display for CapabilityLeaseActivationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for CapabilityLeaseActivationErrorV1 {}

pub type CapabilityLeaseActivationResult<T> = Result<T, CapabilityLeaseActivationErrorV1>;

// These proof markers are intentionally private.  A public value carrying
// one would be a forgeable production enablement path.  A future trusted
// authority may replace them with non-forgeable KeyMint/root-owned evidence.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct IssuerConsumeProofV1;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct HardwareRollbackProofV1;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct AccessibilityClosureProofV1;

/// The immutable source-side view of the three capability-lease gates.
///
/// The fields and all proof marker types are private, and this type does not
/// implement `Serialize`/`Deserialize`.  Consequently a caller cannot load a
/// JSON object, set booleans, and obtain an activation decision.  The only
/// production value currently constructible is [`Self::product_hold`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CapabilityLeaseActivationGateV1 {
    issuer_consume: Option<IssuerConsumeProofV1>,
    hardware_rollback: Option<HardwareRollbackProofV1>,
    accessibility_closure: Option<AccessibilityClosureProofV1>,
}

impl CapabilityLeaseActivationGateV1 {
    /// Return the product default.  It is an explicit HOLD and performs no
    /// I/O or device mutation.
    #[must_use]
    pub const fn product_hold() -> Self {
        Self {
            issuer_consume: None,
            hardware_rollback: None,
            accessibility_closure: None,
        }
    }

    /// Return the source-side gate used by the product entry point.  Keeping
    /// this helper separate makes accidental future caller-selected evidence
    /// impossible: the product route always starts at HOLD.
    pub fn require_product_activation()
    -> CapabilityLeaseActivationResult<CapabilityLeaseActivationPermitV1> {
        Self::product_hold().require_enabled()
    }

    /// Whether all three private component proofs are present.  This is only
    /// a completeness check; product authority is checked by [`Self::decision`]
    /// and [`Self::require_enabled`].
    #[must_use]
    pub const fn components_complete(&self) -> bool {
        self.issuer_consume.is_some()
            && self.hardware_rollback.is_some()
            && self.accessibility_closure.is_some()
    }

    /// List every missing component in stable contract order.
    #[must_use]
    pub fn missing_components(&self) -> Vec<CapabilityLeaseActivationComponentV1> {
        let mut missing = Vec::with_capacity(3);
        if self.issuer_consume.is_none() {
            missing.push(CapabilityLeaseActivationComponentV1::IssuerConsume);
        }
        if self.hardware_rollback.is_none() {
            missing.push(CapabilityLeaseActivationComponentV1::HardwareRollback);
        }
        if self.accessibility_closure.is_none() {
            missing.push(CapabilityLeaseActivationComponentV1::AccessibilityClosure);
        }
        missing
    }

    /// Return `Enabled` only when all proofs and all product authority flags
    /// are available.  The latter are deliberately false in this source tree.
    #[must_use]
    pub const fn decision(&self) -> CapabilityLeaseActivationDecisionV1 {
        if self.components_complete()
            && PRODUCT_CONSTRUCTOR_AVAILABLE
            && PRODUCT_ENABLEMENT_TOKEN_AVAILABLE
            && CONFERS_EFFECT_AUTHORITY
        {
            CapabilityLeaseActivationDecisionV1::Enabled
        } else {
            CapabilityLeaseActivationDecisionV1::Hold
        }
    }

    /// Convenience predicate for callers that need a single fail-closed bit.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        matches!(
            self.decision(),
            CapabilityLeaseActivationDecisionV1::Enabled
        )
    }

    /// Require every component and the unavailable product authority.  The
    /// returned permit is opaque and cannot be forged or deserialized.  It is
    /// not an Android effect capability; effect authority remains a separate
    /// explicit gate.
    pub fn require_enabled(
        &self,
    ) -> CapabilityLeaseActivationResult<CapabilityLeaseActivationPermitV1> {
        if let Some(component) = self.missing_components().into_iter().next() {
            return Err(CapabilityLeaseActivationErrorV1::MissingComponent(
                component,
            ));
        }
        if !PRODUCT_CONSTRUCTOR_AVAILABLE || !PRODUCT_ENABLEMENT_TOKEN_AVAILABLE {
            return Err(CapabilityLeaseActivationErrorV1::ProductAuthorityUnavailable);
        }
        if !CONFERS_EFFECT_AUTHORITY {
            return Err(CapabilityLeaseActivationErrorV1::EffectAuthorityUnavailable);
        }
        Ok(CapabilityLeaseActivationPermitV1 {
            issuer_consume: IssuerConsumeProofV1,
            hardware_rollback: HardwareRollbackProofV1,
            accessibility_closure: AccessibilityClosureProofV1,
        })
    }

    /// Build a complete fixture only inside this module's unit tests.  It is
    /// deliberately not available to integration/product builds and carries
    /// no hardware, KeyMint, trust-manifest, or Android-service evidence.
    #[cfg(test)]
    fn synthetic_for_test(
        issuer_consume: bool,
        hardware_rollback: bool,
        accessibility_closure: bool,
    ) -> Self {
        Self {
            issuer_consume: issuer_consume.then_some(IssuerConsumeProofV1),
            hardware_rollback: hardware_rollback.then_some(HardwareRollbackProofV1),
            accessibility_closure: accessibility_closure.then_some(AccessibilityClosureProofV1),
        }
    }
}

/// Opaque proof that a future trusted authority passed every activation gate.
/// It deliberately does not confer effect authority on its own.
#[derive(Debug, Eq, PartialEq)]
pub struct CapabilityLeaseActivationPermitV1 {
    issuer_consume: IssuerConsumeProofV1,
    hardware_rollback: HardwareRollbackProofV1,
    accessibility_closure: AccessibilityClosureProofV1,
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;
    use serde_json::Value;

    const CONTRACT_BYTES: &[u8] =
        include_bytes!("../contracts/capability-lease-activation-gate-v1.json");

    #[test]
    fn product_default_is_hold_and_has_no_authority() {
        let gate = CapabilityLeaseActivationGateV1::product_hold();
        assert_eq!(gate.decision(), CapabilityLeaseActivationDecisionV1::Hold);
        assert!(!gate.is_enabled());
        assert_eq!(
            gate.missing_components(),
            vec![
                CapabilityLeaseActivationComponentV1::IssuerConsume,
                CapabilityLeaseActivationComponentV1::HardwareRollback,
                CapabilityLeaseActivationComponentV1::AccessibilityClosure,
            ]
        );
        assert_eq!(
            gate.require_enabled().unwrap_err().code(),
            "capability_lease_activation_issuer_consume_unavailable"
        );
        assert_eq!(
            CapabilityLeaseActivationGateV1::require_product_activation()
                .unwrap_err()
                .code(),
            "capability_lease_activation_issuer_consume_unavailable"
        );
        assert!(!PRODUCT_CONSTRUCTOR_AVAILABLE);
        assert!(!PRODUCT_ENABLEMENT_TOKEN_AVAILABLE);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    }

    #[test]
    fn every_component_is_an_independent_fail_closed_gate() {
        let cases = [
            (
                CapabilityLeaseActivationGateV1::synthetic_for_test(false, true, true),
                "capability_lease_activation_issuer_consume_unavailable",
            ),
            (
                CapabilityLeaseActivationGateV1::synthetic_for_test(true, false, true),
                "capability_lease_activation_hardware_rollback_unavailable",
            ),
            (
                CapabilityLeaseActivationGateV1::synthetic_for_test(true, true, false),
                "capability_lease_activation_accessibility_closure_unavailable",
            ),
        ];
        for (gate, expected_code) in cases {
            assert!(!gate.is_enabled());
            assert_eq!(gate.require_enabled().unwrap_err().code(), expected_code);
        }
    }

    #[test]
    fn complete_synthetic_fixture_still_holds_without_product_authority() {
        let gate = CapabilityLeaseActivationGateV1::synthetic_for_test(true, true, true);
        assert!(gate.components_complete());
        assert!(gate.missing_components().is_empty());
        assert_eq!(gate.decision(), CapabilityLeaseActivationDecisionV1::Hold);
        assert_eq!(
            gate.require_enabled().unwrap_err(),
            CapabilityLeaseActivationErrorV1::ProductAuthorityUnavailable
        );
    }

    #[test]
    fn contract_is_hashed_and_declares_the_same_three_gates() {
        assert_eq!(crate::sha256_bytes(CONTRACT_BYTES), CONTRACT_SHA256);
        let contract: Value = serde_json::from_slice(CONTRACT_BYTES).unwrap();
        assert_eq!(contract["contract_schema"], CONTRACT_SCHEMA);
        assert_eq!(contract["source_status"], SOURCE_STATUS);
        assert_eq!(contract["decision"], "hold");
        assert_eq!(
            contract["gates"]["issuer_consume"]["required_evidence"],
            serde_json::json!(REQUIRED_ISSUER_CONSUME_EVIDENCE)
        );
        assert_eq!(
            contract["gates"]["hardware_rollback"]["required_evidence"],
            serde_json::json!(REQUIRED_HARDWARE_ROLLBACK_EVIDENCE)
        );
        assert_eq!(
            contract["gates"]["accessibility_closure"]["required_evidence"],
            serde_json::json!(REQUIRED_ACCESSIBILITY_CLOSURE_EVIDENCE)
        );
        assert_eq!(
            contract["product_authority"]["constructor_available"],
            PRODUCT_CONSTRUCTOR_AVAILABLE
        );
        assert_eq!(
            contract["product_authority"]["enablement_token_available"],
            PRODUCT_ENABLEMENT_TOKEN_AVAILABLE
        );
        assert_eq!(
            contract["product_authority"]["confers_effect_authority"],
            CONFERS_EFFECT_AUTHORITY
        );
        assert_eq!(contract["fail_closed"]["device_write_performed"], false);
        assert_eq!(
            contract["fail_closed"]["synthetic_test_proof"],
            "test_only_not_hardware_evidence"
        );
    }
}
