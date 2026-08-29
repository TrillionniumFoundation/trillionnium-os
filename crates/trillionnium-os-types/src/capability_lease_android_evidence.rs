//! Detached Android evidence shape gate for capability-lease promotion.
//!
//! This module is deliberately narrower than an issuer, a KeyMint client, or
//! an Accessibility service.  It validates the *shape* and binding of a
//! future evidence bundle only; it performs no Android I/O, reads no key
//! material, and cannot authorize an effect.  A complete synthetic bundle can
//! therefore be useful in source tests while the product decision remains
//! `Hold`.
//!
//! The production path has no constructor for an activation bearer here.  A
//! future OS-owned authority must replace the source HOLD with a separate,
//! non-forgeable capability after it has produced the required KeyMint,
//! Verified-Boot, issuer/consumer, and Accessibility ACK evidence.

use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::agent_principal_registry::ACCESSIBILITY_ENDPOINT;
use crate::is_nonzero_lower_sha256;

pub const CONTRACT_SCHEMA: &str =
    "org.trillionnium.capabilitylease.android-evidence-gate.contract.v1";
pub const CONTRACT_SHA256: &str =
    "b48c8dec046b4202d018153a32f8b0bf6fb53d87104e0503f8f9266677abd54e";
pub const SOURCE_STATUS: &str = "source_only_shape_validator_no_product_authority_v1";

/// These flags are intentionally compile-time false.  Evidence is not an
/// effect credential, and no local parser or fixture may turn it into one.
pub const PRODUCT_AUTHORITY_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

pub const REQUIRED_TARGET_BUILD_TYPE: &str = "user";
pub const REQUIRED_TARGET_BUILD_TAGS: &[&str] = &["release-keys"];
pub const REQUIRED_ACCESSIBILITY_PROTOCOL: &str = "org.trillionnium.agent-accessibility.v2";

pub const REQUIRED_ISSUER_CONSUME_FIELDS: &[&str] = &[
    "root_trust_manifest_sha256",
    "issuer_identity_binding_sha256",
    "consumer_receipt_binding_sha256",
    "lease_epoch_high_water_proof_sha256",
];

pub const REQUIRED_HARDWARE_ROLLBACK_FIELDS: &[&str] = &[
    "keymint_attestation_chain_sha256",
    "keymint_security_level",
    "verified_boot_state",
    "avb_rollback_index_high_water",
    "avb_rollback_index_location",
    "rollback_index_persistence_proof_sha256",
];

pub const REQUIRED_ACCESSIBILITY_CLOSURE_FIELDS: &[&str] = &[
    "service_ownership_proof_sha256",
    "mcp_schema_sha256",
    "protocol",
    "tool_selinux_domain",
    "operation_replay_sync_selinux_domain",
    "operation_epoch_replay_proof_sha256",
    "receipt_ack_closure_sha256",
];

pub const ACCESSIBILITY_ALLOWED_SECURITY_DOMAINS: (&str, &str) = (
    ACCESSIBILITY_ENDPOINT.tool_selinux_domain,
    ACCESSIBILITY_ENDPOINT.operation_replay_sync_selinux_domain,
);

pub type AndroidEvidenceResult<T> = Result<T, AndroidEvidenceErrorV1>;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AndroidEvidenceErrorV1 {
    ContractField(&'static str),
    TargetField(&'static str),
    IssuerConsumeField(&'static str),
    HardwareRollbackField(&'static str),
    AccessibilityClosureField(&'static str),
    ProductAuthorityUnavailable,
    EffectAuthorityUnavailable,
}

impl AndroidEvidenceErrorV1 {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ContractField(field) => field,
            Self::TargetField(field) => field,
            Self::IssuerConsumeField(field) => field,
            Self::HardwareRollbackField(field) => field,
            Self::AccessibilityClosureField(field) => field,
            Self::ProductAuthorityUnavailable => {
                "capability_lease_android_product_authority_unavailable"
            }
            Self::EffectAuthorityUnavailable => {
                "capability_lease_android_effect_authority_unavailable"
            }
        }
    }
}

impl fmt::Display for AndroidEvidenceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AndroidEvidenceErrorV1 {}

/// Detached build metadata required before any Android capability-lease
/// evidence can be considered.  These facts are observations, not release
/// authorization and not a substitute for cryptographic verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetReleaseEvidenceV1 {
    pub target_files_sha256: String,
    pub build_type: String,
    pub build_tags: Vec<String>,
    pub ota_keys_nonempty: bool,
}

/// Required root/issuer/consumer binding observations.  No lease token or
/// signing key is represented by this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConsumeEvidenceV1 {
    pub root_trust_manifest_sha256: String,
    pub issuer_identity_binding_sha256: String,
    pub consumer_receipt_binding_sha256: String,
    pub lease_epoch_high_water_proof_sha256: String,
    pub runtime_consumer_available: bool,
}

/// Hardware-backed KeyMint/Verified-Boot and rollback observations.  The
/// rollback index is intentionally not pinned to a development value: a
/// future release must bind its own monotonic high-water value and device
/// evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareRollbackEvidenceV1 {
    pub keymint_attestation_chain_sha256: String,
    pub keymint_security_level: String,
    pub verified_boot_state: String,
    pub avb_rollback_index_high_water: u64,
    pub avb_rollback_index_location: u32,
    pub rollback_index_persistence_proof_sha256: String,
}

/// Accessibility service ownership, protocol, replay and receipt/ACK closure
/// observations.  The exact endpoint SELinux domains are generated from the
/// product principal registry rather than caller input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessibilityClosureEvidenceV1 {
    pub service_ownership_proof_sha256: String,
    pub mcp_schema_sha256: String,
    pub protocol: String,
    pub tool_selinux_domain: String,
    pub operation_replay_sync_selinux_domain: String,
    pub operation_epoch_replay_proof_sha256: String,
    pub receipt_ack_closure_sha256: String,
    pub runtime_consumer_available: bool,
}

/// A detached, non-authorizing evidence bundle.  It is intentionally
/// serializable so a future host verifier can inspect a signed/detached
/// record, but no method on it yields an Android effect capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidCapabilityLeaseEvidenceV1 {
    pub schema: String,
    pub contract_sha256: String,
    pub source_status: String,
    pub target: TargetReleaseEvidenceV1,
    pub issuer_consume: IssuerConsumeEvidenceV1,
    pub hardware_rollback: HardwareRollbackEvidenceV1,
    pub accessibility_closure: AccessibilityClosureEvidenceV1,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AndroidCapabilityLeaseDecisionV1 {
    Hold,
    Enabled,
}

/// Opaque marker for a future product authority.  There is no production
/// constructor in this source tree; keeping it private prevents a validated
/// detached record from becoming an effect bearer by accident.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AndroidCapabilityLeaseActivationMarkerV1 {
    _private: (),
}

impl AndroidCapabilityLeaseEvidenceV1 {
    /// Validate only detached evidence shape and fixed identity bindings.
    /// `Ok(())` means the record is structurally complete; it never means
    /// hardware or product authority was proven.
    pub fn validate_shape(&self) -> AndroidEvidenceResult<()> {
        if self.schema != CONTRACT_SCHEMA {
            return Err(AndroidEvidenceErrorV1::ContractField(
                "capability_lease_android_schema_mismatch",
            ));
        }
        if self.contract_sha256 != CONTRACT_SHA256 {
            return Err(AndroidEvidenceErrorV1::ContractField(
                "capability_lease_android_contract_digest_mismatch",
            ));
        }
        if self.source_status != SOURCE_STATUS {
            return Err(AndroidEvidenceErrorV1::ContractField(
                "capability_lease_android_source_status_mismatch",
            ));
        }

        if !is_nonzero_lower_sha256(&self.target.target_files_sha256) {
            return Err(AndroidEvidenceErrorV1::TargetField(
                "capability_lease_android_target_files_digest_invalid",
            ));
        }
        if self.target.build_type != REQUIRED_TARGET_BUILD_TYPE {
            return Err(AndroidEvidenceErrorV1::TargetField(
                "capability_lease_android_target_build_type_not_user",
            ));
        }
        if self.target.build_tags
            != REQUIRED_TARGET_BUILD_TAGS
                .iter()
                .map(|tag| (*tag).to_string())
                .collect::<Vec<_>>()
        {
            return Err(AndroidEvidenceErrorV1::TargetField(
                "capability_lease_android_target_build_tags_not_release_keys",
            ));
        }
        if !self.target.ota_keys_nonempty {
            return Err(AndroidEvidenceErrorV1::TargetField(
                "capability_lease_android_ota_keys_empty",
            ));
        }

        for (value, code) in [
            (
                &self.issuer_consume.root_trust_manifest_sha256,
                "capability_lease_android_root_trust_manifest_digest_invalid",
            ),
            (
                &self.issuer_consume.issuer_identity_binding_sha256,
                "capability_lease_android_issuer_identity_binding_invalid",
            ),
            (
                &self.issuer_consume.consumer_receipt_binding_sha256,
                "capability_lease_android_consumer_receipt_binding_invalid",
            ),
            (
                &self.issuer_consume.lease_epoch_high_water_proof_sha256,
                "capability_lease_android_lease_epoch_high_water_invalid",
            ),
        ] {
            if !is_nonzero_lower_sha256(value) {
                return Err(AndroidEvidenceErrorV1::IssuerConsumeField(code));
            }
        }
        if !self.issuer_consume.runtime_consumer_available {
            return Err(AndroidEvidenceErrorV1::IssuerConsumeField(
                "capability_lease_android_issuer_consumer_unavailable",
            ));
        }

        let hardware = &self.hardware_rollback;
        if !is_nonzero_lower_sha256(&hardware.keymint_attestation_chain_sha256) {
            return Err(AndroidEvidenceErrorV1::HardwareRollbackField(
                "capability_lease_android_keymint_attestation_digest_invalid",
            ));
        }
        if !matches!(
            hardware.keymint_security_level.as_str(),
            "STRONGBOX" | "TRUSTED_ENVIRONMENT"
        ) {
            return Err(AndroidEvidenceErrorV1::HardwareRollbackField(
                "capability_lease_android_keymint_security_level_invalid",
            ));
        }
        if hardware.verified_boot_state != "VERIFIED" {
            return Err(AndroidEvidenceErrorV1::HardwareRollbackField(
                "capability_lease_android_verified_boot_not_verified",
            ));
        }
        if hardware.avb_rollback_index_high_water == 0 || hardware.avb_rollback_index_location > 31
        {
            return Err(AndroidEvidenceErrorV1::HardwareRollbackField(
                "capability_lease_android_rollback_index_invalid",
            ));
        }
        if !is_nonzero_lower_sha256(&hardware.rollback_index_persistence_proof_sha256) {
            return Err(AndroidEvidenceErrorV1::HardwareRollbackField(
                "capability_lease_android_rollback_persistence_proof_invalid",
            ));
        }

        let accessibility = &self.accessibility_closure;
        for (value, code) in [
            (
                &accessibility.service_ownership_proof_sha256,
                "capability_lease_android_accessibility_service_ownership_invalid",
            ),
            (
                &accessibility.mcp_schema_sha256,
                "capability_lease_android_accessibility_schema_digest_invalid",
            ),
            (
                &accessibility.operation_epoch_replay_proof_sha256,
                "capability_lease_android_accessibility_replay_proof_invalid",
            ),
            (
                &accessibility.receipt_ack_closure_sha256,
                "capability_lease_android_accessibility_receipt_ack_invalid",
            ),
        ] {
            if !is_nonzero_lower_sha256(value) {
                return Err(AndroidEvidenceErrorV1::AccessibilityClosureField(code));
            }
        }
        if accessibility.protocol != REQUIRED_ACCESSIBILITY_PROTOCOL {
            return Err(AndroidEvidenceErrorV1::AccessibilityClosureField(
                "capability_lease_android_accessibility_protocol_mismatch",
            ));
        }
        if accessibility.tool_selinux_domain != ACCESSIBILITY_ALLOWED_SECURITY_DOMAINS.0
            || accessibility.operation_replay_sync_selinux_domain
                != ACCESSIBILITY_ALLOWED_SECURITY_DOMAINS.1
        {
            return Err(AndroidEvidenceErrorV1::AccessibilityClosureField(
                "capability_lease_android_accessibility_security_domain_mismatch",
            ));
        }
        if !accessibility.runtime_consumer_available {
            return Err(AndroidEvidenceErrorV1::AccessibilityClosureField(
                "capability_lease_android_accessibility_consumer_unavailable",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn decision(&self) -> AndroidCapabilityLeaseDecisionV1 {
        if self.validate_shape().is_ok() && PRODUCT_AUTHORITY_AVAILABLE && CONFERS_EFFECT_AUTHORITY
        {
            AndroidCapabilityLeaseDecisionV1::Enabled
        } else {
            AndroidCapabilityLeaseDecisionV1::Hold
        }
    }

    /// Require both shape-complete evidence and the unavailable product
    /// authority.  This is a future seam only; current source always returns
    /// a fail-closed error for a complete record.
    pub fn require_activation(
        &self,
    ) -> AndroidEvidenceResult<AndroidCapabilityLeaseActivationMarkerV1> {
        self.validate_shape()?;
        if !PRODUCT_AUTHORITY_AVAILABLE {
            return Err(AndroidEvidenceErrorV1::ProductAuthorityUnavailable);
        }
        if !CONFERS_EFFECT_AUTHORITY {
            return Err(AndroidEvidenceErrorV1::EffectAuthorityUnavailable);
        }
        Ok(AndroidCapabilityLeaseActivationMarkerV1 { _private: () })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn digest(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    fn complete_fixture() -> AndroidCapabilityLeaseEvidenceV1 {
        AndroidCapabilityLeaseEvidenceV1 {
            schema: CONTRACT_SCHEMA.to_string(),
            contract_sha256: CONTRACT_SHA256.to_string(),
            source_status: SOURCE_STATUS.to_string(),
            target: TargetReleaseEvidenceV1 {
                target_files_sha256: digest('a'),
                build_type: "user".to_string(),
                build_tags: vec!["release-keys".to_string()],
                ota_keys_nonempty: true,
            },
            issuer_consume: IssuerConsumeEvidenceV1 {
                root_trust_manifest_sha256: digest('b'),
                issuer_identity_binding_sha256: digest('c'),
                consumer_receipt_binding_sha256: digest('d'),
                lease_epoch_high_water_proof_sha256: digest('e'),
                runtime_consumer_available: true,
            },
            hardware_rollback: HardwareRollbackEvidenceV1 {
                keymint_attestation_chain_sha256: digest('f'),
                keymint_security_level: "STRONGBOX".to_string(),
                verified_boot_state: "VERIFIED".to_string(),
                avb_rollback_index_high_water: 29,
                avb_rollback_index_location: 2,
                rollback_index_persistence_proof_sha256: digest('1'),
            },
            accessibility_closure: AccessibilityClosureEvidenceV1 {
                service_ownership_proof_sha256: digest('2'),
                mcp_schema_sha256: digest('3'),
                protocol: REQUIRED_ACCESSIBILITY_PROTOCOL.to_string(),
                tool_selinux_domain: ACCESSIBILITY_ALLOWED_SECURITY_DOMAINS.0.to_string(),
                operation_replay_sync_selinux_domain: ACCESSIBILITY_ALLOWED_SECURITY_DOMAINS
                    .1
                    .to_string(),
                operation_epoch_replay_proof_sha256: digest('4'),
                receipt_ack_closure_sha256: digest('5'),
                runtime_consumer_available: true,
            },
        }
    }

    #[test]
    fn contract_hash_and_product_authority_flags_are_closed() {
        assert_eq!(
            crate::sha256_bytes(include_bytes!(
                "../contracts/capability-lease-android-evidence-gate-v1.json"
            )),
            CONTRACT_SHA256
        );
        assert_eq!(
            CONTRACT_SCHEMA,
            "org.trillionnium.capabilitylease.android-evidence-gate.contract.v1"
        );
        assert_eq!(
            SOURCE_STATUS,
            "source_only_shape_validator_no_product_authority_v1"
        );
        const {
            assert!(!PRODUCT_AUTHORITY_AVAILABLE);
            assert!(!CONFERS_EFFECT_AUTHORITY);
        }
    }

    #[test]
    fn complete_shape_is_not_product_authority() {
        let fixture = complete_fixture();
        assert!(fixture.validate_shape().is_ok());
        assert_eq!(fixture.decision(), AndroidCapabilityLeaseDecisionV1::Hold);
        assert_eq!(
            fixture.require_activation().unwrap_err(),
            AndroidEvidenceErrorV1::ProductAuthorityUnavailable
        );
    }

    #[test]
    fn target_release_and_hardware_claims_fail_closed() {
        let mut fixture = complete_fixture();
        fixture.target.build_type = "userdebug".to_string();
        assert_eq!(
            fixture.validate_shape().unwrap_err().code(),
            "capability_lease_android_target_build_type_not_user"
        );

        let mut fixture = complete_fixture();
        fixture.target.build_tags = vec!["test-keys".to_string()];
        assert_eq!(
            fixture.validate_shape().unwrap_err().code(),
            "capability_lease_android_target_build_tags_not_release_keys"
        );

        let mut fixture = complete_fixture();
        fixture.hardware_rollback.verified_boot_state = "ORANGE".to_string();
        assert_eq!(
            fixture.validate_shape().unwrap_err().code(),
            "capability_lease_android_verified_boot_not_verified"
        );

        let mut fixture = complete_fixture();
        fixture.hardware_rollback.keymint_security_level = "SOFTWARE".to_string();
        assert_eq!(
            fixture.validate_shape().unwrap_err().code(),
            "capability_lease_android_keymint_security_level_invalid"
        );
    }

    #[test]
    fn accessibility_identity_and_closure_are_exactly_bound() {
        let mut fixture = complete_fixture();
        fixture.accessibility_closure.protocol = "wrong".to_string();
        assert_eq!(
            fixture.validate_shape().unwrap_err().code(),
            "capability_lease_android_accessibility_protocol_mismatch"
        );

        let mut fixture = complete_fixture();
        fixture.accessibility_closure.tool_selinux_domain = "u:r:untrusted_app:s0".to_string();
        assert_eq!(
            fixture.validate_shape().unwrap_err().code(),
            "capability_lease_android_accessibility_security_domain_mismatch"
        );

        let mut fixture = complete_fixture();
        fixture.accessibility_closure.receipt_ack_closure_sha256 = "0".repeat(64);
        assert_eq!(
            fixture.validate_shape().unwrap_err().code(),
            "capability_lease_android_accessibility_receipt_ack_invalid"
        );
    }

    #[test]
    fn detached_record_rejects_unknown_fields_and_has_no_key_material_field() {
        let fixture = complete_fixture();
        let value = serde_json::to_value(&fixture).unwrap();
        assert!(value.get("private_key").is_none());
        assert!(value.get("signing_key").is_none());
        let mut unknown = value;
        unknown["private_key"] = json!("must-not-exist");
        assert!(serde_json::from_value::<AndroidCapabilityLeaseEvidenceV1>(unknown).is_err());
    }
}
