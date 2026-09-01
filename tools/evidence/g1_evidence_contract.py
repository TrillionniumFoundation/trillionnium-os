"""Immutable constants for the Trillionnium G1 evidence contract."""
from __future__ import annotations

import re

PACKAGE_SCHEMA = "org.trillionnium.g1.evidence-package.v1"
PACKAGE_VERSION = "1"
GAP_REGISTER_SCHEMA = "org.trillionnium.gap-register.v2"
PROGRAM_REVISION = "2026-08-31-g1"
COMPLETE = "COMPLETE"
HOLD = "HOLD"
LEVEL_ORDER = {f"L{index}": index for index in range(7)}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+\[\]-]{0,511}$")
PACKAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

EVIDENCE_CLASS_LEVEL = {
    "source_qualification": "L1",
    "installed_rootlinux": "L2",
    "android_image": "L3",
    "physical_device": "L4",
    "destructive_fault": "L5",
    "signed_release": "L6",
}

CLASS_CLAIM_CEILING = {
    "source_qualification": "EXACT_SOURCE_AND_SYNTHETIC_MERGE_QUALIFIED_NOT_INSTALLED_TARGET",
    "installed_rootlinux": "INSTALLED_ROOTLINUX_QUALIFIED_NOT_ANDROID_IMAGE",
    "android_image": "ANDROID_IMAGE_QUALIFIED_NOT_PHYSICAL_DEVICE",
    "physical_device": "AUTHORIZED_PHYSICAL_DOGFOOD_QUALIFIED_NOT_DESTRUCTIVE_FAULT",
    "destructive_fault": "DESTRUCTIVE_FAULT_QUALIFIED_NOT_PUBLIC_RELEASE",
    "signed_release": "SIGNED_PUBLIC_RELEASE_AUTHORIZED",
}

CLASS_NEGATIVE_CLAIMS = {
    "source_qualification": {
        "installed_target_not_observed",
        "android_image_not_observed",
        "physical_device_not_observed",
        "destructive_faults_not_observed",
        "public_release_not_authorized",
    },
    "installed_rootlinux": {
        "android_image_not_observed",
        "physical_device_not_observed",
        "destructive_faults_not_observed",
        "public_release_not_authorized",
    },
    "android_image": {
        "physical_device_not_observed",
        "destructive_faults_not_observed",
        "public_release_not_authorized",
    },
    "physical_device": {
        "destructive_faults_not_observed",
        "public_release_not_authorized",
    },
    "destructive_fault": {"public_release_not_authorized"},
    "signed_release": set(),
}

CLASS_REQUIRED_TRUE = {
    "source_qualification": {
        "exact_head_checks_passed",
        "synthetic_merge_checks_passed",
        "source_merge_identity_bound",
        "independent_non_author_approval",
    },
    "installed_rootlinux": {
        "installed_manifest_verified",
        "executable_hashes_verified",
        "provider_identity_verified",
        "provider_authenticated",
        "namespace_cgroup_mounts_verified",
        "selinux_verified",
        "restart_recovery_verified",
        "emergency_inhibit_verified",
    },
    "android_image": {
        "clean_target_files_verified",
        "product_graph_verified",
        "init_lifecycle_verified",
        "selinux_policy_and_labels_verified",
        "fsverity_enabled_and_remeasured",
        "avb_chain_verified",
        "ota_install_and_rollback_verified",
        "legacy_nodes_absent",
    },
    "physical_device": {
        "authorized_physical_device",
        "device_identity_bound",
        "ordinary_adb_matrix_passed",
        "same_turn_shell_job_adb_passed",
        "visible_effect_observed",
        "target_failures_captured",
    },
    "destructive_fault": {
        "destructive_fault_authorized",
        "independent_fault_operator",
        "pre_cut_state_bound",
        "fault_matrix_completed",
        "post_restart_reconciled",
        "stale_writer_fenced",
    },
    "signed_release": {
        "artifact_signatures_verified",
        "transparency_record_verified",
        "avb_rollback_ota_verified",
        "key_custody_verified",
        "independent_release_authorization",
        "all_gaps_closed",
        "public_release_enabled",
    },
}

CLASS_REQUIRED_ZERO = {
    "source_qualification": set(),
    "installed_rootlinux": {"automatic_redispatch_count"},
    "android_image": {"automatic_redispatch_count"},
    "physical_device": {"automatic_redispatch_count"},
    "destructive_fault": {"automatic_redispatch_count"},
    "signed_release": {"automatic_redispatch_count"},
}

GAP_EVIDENCE_CLASS = {
    "GAP-DOC-SINGLE-TRUTH-001": "source_qualification",
    "GAP-GOVERNANCE-001": "source_qualification",
    "GAP-JOB-ADMISSION-001": "source_qualification",
    "GAP-PROCESS-LIFECYCLE-001": "installed_rootlinux",
    "GAP-STREAM-RECOVERY-001": "installed_rootlinux",
    "GAP-BROKER-CORRELATION-001": "installed_rootlinux",
    "GAP-CONC-BROKER-MUX-001": "installed_rootlinux",
    "GAP-CONC-JOB-START-HOTLOCK-001": "installed_rootlinux",
    "GAP-CONC-EVENT-STORE-001": "installed_rootlinux",
    "GAP-CONC-REGISTRY-001": "installed_rootlinux",
    "GAP-CONC-TURN-CANCEL-001": "installed_rootlinux",
    "GAP-PERF-SYSTEM-BASELINE-001": "installed_rootlinux",
    "GAP-CONTROL-PLANE-SHADOW-001": "installed_rootlinux",
    "GAP-INSTALLED-CODEX-001": "installed_rootlinux",
    "GAP-ROOTLINUX-PLACEMENT-001": "installed_rootlinux",
    "GAP-PRODUCT-ENTRYPOINT-001": "android_image",
    "GAP-ANDROID-GRAPH-001": "android_image",
    "GAP-PHYSICAL-ADB-001": "physical_device",
    "GAP-JOURNAL-CONVERGENCE-001": "destructive_fault",
    "GAP-FAULT-MATRIX-001": "destructive_fault",
    "GAP-RELEASE-001": "signed_release",
}

PACKAGE_KEYS = {
    "schema",
    "version",
    "package_id",
    "program_revision",
    "level",
    "evidence_class",
    "status",
    "source",
    "lineage",
    "gaps",
    "artifacts",
    "observations",
    "roles",
    "authorization",
    "created_at",
    "expires_at",
    "retention_days",
    "claim_ceiling",
    "negative_claims",
    "automatic_redispatch",
    "public_release",
    "holds",
}
SOURCE_KEYS = {
    "repository",
    "branch",
    "commit",
    "tree",
    "cargo_lock_sha256",
    "pull_request",
    "workflow_runs",
}
LINEAGE_KEYS = {"parent_package_ids", "predecessor_source_commit"}
ROLE_KEYS = {"producer", "operator", "reviewer", "authorizer"}
ROLE_VALUE_KEYS = {"principal", "identity_provider", "evidence_id"}
AUTHORIZATION_KEYS = {
    "status",
    "authority",
    "scope",
    "expires_at",
    "revoked",
    "evidence_id",
}
ARTIFACT_KEYS = {
    "name",
    "kind",
    "sha256",
    "bytes",
    "uri",
    "retention_expires_at",
}
WORKFLOW_RUN_KEYS = {
    "name",
    "run_id",
    "attempt",
    "result",
    "artifact_id",
    "artifact_name",
    "artifact_sha256",
}
HOLD_KEYS = {"field", "status", "reason"}
