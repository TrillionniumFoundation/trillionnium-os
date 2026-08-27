#[cfg(test)]
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(any(test, feature = "legacy-plan-conformance"))]
use trillionnium_dbus::ExecutionPayloadResolver;
#[cfg(any(test, feature = "legacy-plan-conformance"))]
use trillionnium_os_types::ToolCallInput;
use trillionnium_os_types::agent_principal_registry;
use trillionnium_os_types::direct_operation::DirectOperationBinding;
use trillionnium_os_types::{now_unix_ms, sha256_bytes, sha256_json};
#[cfg(any(test, feature = "legacy-plan-conformance"))]
use trillionnium_tool_runtime::ResolvedExecutionPayload;
use trillionnium_tool_runtime::{
    AndroidGatewayAdapter, android_authority_boot_peer_uid, commit_android_authority_boot_peer_pin,
};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::action_workflow::DirectPlanCustodyCandidate;

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_MEMORY_METADATA_PERSIST: Cell<bool> = const { Cell::new(false) };
    static FAIL_NEXT_EXPIRED_MEMORY_PAYLOAD_DELETE: Cell<bool> = const { Cell::new(false) };
    static FAIL_NEXT_PRIVATE_PARENT_FSYNC_DESTINATION: RefCell<Option<String>> = const { RefCell::new(None) };
}

const STORE_SCHEMA: &str = "trillionnium.context-memory-store.v2";
const LEGACY_STORE_SCHEMA: &str = "trillionnium.context-memory-store.v1";
const CONTEXT_SCHEMA: &str = "trillionnium.context-handle.v1";
const STORED_CONTEXT_SCHEMA: &str = "trillionnium.encrypted-ephemeral-context.v1";
const CONTEXT_JOURNAL_SCHEMA: &str = "trillionnium.encrypted-ephemeral-context-journal.v1";
const CONTEXT_JOURNAL_FILE: &str = "ephemeral-contexts.enc";
const CONTEXT_JOURNAL_AAD: &[u8] =
    b"trillionnium-encrypted-ephemeral-context-journal-xchacha20poly1305-v1";
const CONTEXT_IMPORT_RESERVATION_SCHEMA: &str =
    "trillionnium.context-import-capacity-reservation.v1";
const MAX_CONTEXT_JOURNAL_CLEAR_BYTES: usize =
    MAX_CONTEXTS * (MAX_CONTEXT_BYTES + 12 * 1024) + MAX_CONTEXT_TOMBSTONES * 8 * 1024;
const MEMORY_SCHEMA: &str = "trillionnium.memory-metadata.v2";
const LEGACY_MEMORY_SCHEMA: &str = "trillionnium.memory-metadata.v1";
const UI_MEMORY_PROVENANCE_SCHEMA: &str = "trillionnium.ui-result-memory-provenance.v1";
const ENCRYPTED_PAYLOAD_MAGIC: &[u8; 8] = b"TRMEM02\0";
const DEFAULT_ROOT: &str = "/var/lib/trillionnium/context-memory";
const MAX_CONTEXT_BYTES: usize = 65_536;
const MAX_SOURCE_ID_BYTES: usize = 512;
#[cfg(test)]
const MAX_SOURCE_KIND_BYTES: usize = 64;
#[cfg(test)]
const DEFAULT_CONTEXT_TTL_MS: u64 = 600_000;
const MAX_CONTEXT_TTL_MS: u64 = 900_000;
#[cfg_attr(not(test), allow(dead_code))]
const MAX_MEMORY_PLANNING_CONTEXT_TTL_MS: u64 = 10 * 60 * 1_000;
const DEFAULT_MEMORY_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const MAX_MEMORY_RETENTION_MS: u64 = 90 * 24 * 60 * 60 * 1_000;
const MAX_CONTEXTS: usize = 128;
const MAX_CONTEXT_TOMBSTONES: usize = 2_048;
const MAX_MEMORY_PER_SUBJECT: usize = 100;
const MAX_MEMORY_PAGE_ITEMS: usize = 20;
const MAX_MEMORY_GLOBAL: usize = 128;
const MEMORY_SAVE_TOMBSTONE_SCHEMA: &str = "trillionnium.memory-save-tombstone.v1";
const MAX_MEMORY_SAVE_TOMBSTONES: usize = 128;
const MEMORY_DELETION_TOMBSTONE_SCHEMA: &str = "trillionnium.memory-deletion-tombstone.v1";
const MAX_MEMORY_DELETION_TOMBSTONES: usize = 512;
const MAX_REPLAY_RECORDS: usize = 512;
const REPLAY_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const UI_REPLAY_SCHEMA: &str = "trillionnium.os-ui-request-replay.v3";
const LEGACY_V2_UI_REPLAY_SCHEMA: &str = "trillionnium.os-ui-request-replay.v2";
const LEGACY_UI_REPLAY_SCHEMA: &str = "trillionnium.os-ui-request-replay.v1";
const UI_REPLAY_POLICY_EPOCH: u64 = 3;
const UI_REPLAY_PROVIDER_ABI_EPOCH: u64 = 1;
const LEGACY_V2_UI_REPLAY_POLICY_EPOCH: u64 = 2;
const LEGACY_V2_UI_REPLAY_PROVIDER_ABI_EPOCH: u64 = 1;
const UI_REPLAY_COMPLETION_PROOF_SCHEMA: &str = "trillionnium.os-ui-completion-proof.v1";
const UI_REPLAY_CUSTODY_HANDOFF_SCHEMA: &str = "trillionnium.os-ui-custody-handoff.v1";
const UI_REPLAY_ARCHIVE_SCHEMA: &str = "trillionnium.os-ui-request-replay-archive.v1";
const UI_REPLAY_ARCHIVE_FILE: &str = "ui-replay-archive.json";
const UI_REPLAY_ARCHIVE_BYTES: usize = 128 * 1024;
const UI_REPLAY_ARCHIVE_HASH_COUNT: usize = 7;
const UI_REPLAY_ARCHIVE_MAX_SET_BITS: usize = UI_REPLAY_ARCHIVE_BYTES * 8 * 3 / 5;
const MAX_UI_REPLAY_ARCHIVE_FILE_BYTES: usize = 256 * 1024;
const STORE_FILE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const STORE_GROWTH_HEADROOM_BYTES: u64 = 512 * 1024;
const MAX_UI_REPLAY_OUTCOME_BYTES: usize = 262_144;
const DATA_GRANT_STORE_SCHEMA: &str = "trillionnium.agent-data-grant-store.v2";
const LEGACY_DATA_GRANT_STORE_SCHEMA: &str = "trillionnium.agent-data-grant-store.v1";
const DATA_GRANT_SCHEMA: &str = "trillionnium.agent-data-grant.v2";
const LEGACY_DATA_GRANT_SCHEMA: &str = "trillionnium.agent-data-grant.v1";
const DATA_GRANT_AUDIT_SCHEMA: &str = "trillionnium.agent-data-grant-audit.v1";
const MAX_DATA_GRANT_TTL_MS: u64 = 300_000;
const MAX_DATA_GRANTS: usize = 512;
const MAX_DATA_GRANT_AUDIT_EVENTS: usize = 4_096;
const MAX_DATA_GRANT_STORE_BYTES: usize = 2 * 1024 * 1024;
const DATA_GRANT_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const DATA_GRANT_STORE_AAD: &[u8] = b"trillionnium-agent-data-grant-store-xchacha20poly1305-v1";
const AUTHORITY_KEY_SCHEMA: &str = "org.trillionnium.ai-authority.receipt-key.v1";
const AUTHORITY_PIN_SCHEMA: &str = "trillionnium.authority-key-pin.v1";
const AUTHORITY_ROTATION_SCHEMA: &str = "trillionnium.authority-key-rotation.v1";
const AUTHORITY_ROTATION_CONTRACT: &str = "os_authorized_monotonic_epoch_and_pinned_key_id";
const AUTHORITY_ATTESTATION_CHALLENGE: &[u8] = b"org.trillionnium.ai-authority.receipt-key.v2";
const AUTHORITY_ATTESTED_KEY_PROFILE: &str = "keymint_attested_v1";
const AUTHORITY_USERDEBUG_LOCAL_HARDWARE_KEY_PROFILE: &str = "userdebug_local_hardware_v1";
const AUTHORITY_USERDEBUG_LOCAL_PROFILE_ENV: &str = "TRILLIONNIUM_P01_AUTHORITY_KEY_PROFILE";
const AUTHORITY_ATTESTATION_UNAVAILABLE: &str = "unavailable";
const AUTHORITY_ATTESTED_VERIFICATION_CONTRACT: &str = "pin key_id in OS-owned state; reject receipt self-asserted keys; accept rotation only with a higher OS-authorized epoch";
const AUTHORITY_USERDEBUG_LOCAL_VERIFICATION_CONTRACT: &str = "userdebug-only signed-image key/SPKI pin with hardware security level; attestation unavailable; public release ineligible";
const EXECUTION_PAYLOAD_SCHEMA: &str = "trillionnium.execution-payload.v2";
const EXECUTION_PAYLOAD_SHAPE: &str = "exact_https_url.v1";
const EXECUTION_PAYLOAD_INTEGRITY_SCHEMA: &str = "trillionnium.execution-payload-integrity.v1";
const EXECUTION_PAYLOAD_INVALID_ENTRY_EVENT: &str = "execution_payload_invalid_entry_quarantined";
#[cfg(test)]
const MAX_EXECUTION_PAYLOADS: usize = 128;
const MAX_EXECUTION_URL_BYTES: usize = 8 * 1024;
const MAX_EXECUTION_PAYLOAD_CLEAR_BYTES: usize = 24 * 1024;
const MAX_EXECUTION_PAYLOAD_FILE_BYTES: usize = 32 * 1024;
const MAX_EXECUTION_PAYLOAD_QUARANTINE_ENTRIES: usize = 32;
const MAX_EXECUTION_PAYLOAD_TTL_MS: u64 = 10 * 60 * 1_000;
const EXECUTION_PAYLOAD_AAD_PREFIX: &str = "trillionnium-execution-payload-xchacha20poly1305-v2:";
const MEMORY_KEY_ENVELOPE_SCHEMA: &str = "org.trillionnium.ai-authority.memory-key-envelope.v1";
const MEMORY_KEY_ENVELOPE_FILE: &str = "memory-key.envelope.json";
const LEGACY_PLAINTEXT_MEMORY_KEY_FILE: &str = "memory.key";
const MEMORY_KEY_SUBJECT_USER_ID: u32 = 0;
const MEMORY_KEY_EPOCH: u64 = 1;
const MEMORY_KEY_ALIAS: &str = "trillionnium.memory.master-wrap.u0.v1";
const MEMORY_KEY_AAD: &str = "org.trillionnium.ai-authority.memory-key-wrap.v1\n\
package=org.trillionnium.aiauthority\n\
subject_user_id=0\n\
key_alias=trillionnium.memory.master-wrap.u0.v1\n\
key_epoch=1\n";
const MEMORY_KEY_ANDROID_BACKEND: &str = "android_keystore";
const MEMORY_KEY_ANDROID_ALGORITHM: &str = "AES-256-GCM-AndroidKeyStore";
const DEFAULT_ANDROID_GATEWAY_SOCKET: &str = "@trillionnium-agent-gateway-v1";
const DEFAULT_ANDROID_AUTHORITY_SELINUX_DOMAIN: &str = "u:r:trillionnium_aiauthority:s0";
const MAX_MEMORY_KEY_ENVELOPE_BYTES: usize = 8 * 1024;
const MAX_WORKFLOW_BLOB_CLEAR_BYTES: usize = 4 * 1024 * 1024;
const EGRESS_RECOVERY_AAD_PREFIX: &[u8] =
    b"trillionnium-context-memory-egress-recovery-xchacha20poly1305-v1\0";
const MAX_EGRESS_RECOVERY_CLEAR_BYTES: usize = 512 * 1024;
const MAX_EGRESS_RECOVERY_CIPHERTEXT_BYTES: usize = MAX_EGRESS_RECOVERY_CLEAR_BYTES + 128;
const MAX_EGRESS_RECOVERY_FILES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct EgressRecoveryBlobRef {
    pub file_name: String,
    pub ciphertext_sha256: String,
    pub publication_durability_uncertain: bool,
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(super) struct ExecutionPayloadDescriptor {
    pub reference: String,
    pub payload_sha256: String,
    pub shape: String,
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(super) struct ExecutionPayloadBinding {
    pub owner_uid: u32,
    pub owner_selinux_domain: String,
    pub subject_user_id: u32,
    pub agent_id: String,
    pub agent_peer_uid: u32,
    pub agent_peer_gid: u32,
    pub agent_selinux_domain: String,
    pub agent_executable_sha256: String,
    pub task_id: String,
    pub session_id: String,
    pub plan_id: String,
    pub action_id: String,
    pub tool_call_id: String,
    pub tool_name: String,
    pub tool_manifest_sha256: String,
    pub accepted_plan_sha256: String,
    pub context_sha256: String,
    pub arguments_sha256: String,
    pub expires_at_ms: u64,
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct StoredExecutionPayload {
    schema: String,
    reference: String,
    payload_sha256: String,
    shape: String,
    owner_uid: u32,
    owner_selinux_domain: String,
    subject_user_id: u32,
    agent_id: String,
    agent_peer_uid: u32,
    agent_peer_gid: u32,
    agent_selinux_domain: String,
    agent_executable_sha256: String,
    task_id: String,
    session_id: String,
    plan_id: String,
    action_id: String,
    tool_call_id: String,
    tool_name: String,
    tool_manifest_sha256: String,
    accepted_plan_sha256: String,
    context_sha256: String,
    arguments_sha256: String,
    created_at_ms: u64,
    expires_at_ms: u64,
    url: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionPayloadIntegrityState {
    schema: String,
    event_code: String,
    total_events: u64,
    last_event_at_ms: u64,
}

impl Drop for StoredExecutionPayload {
    fn drop(&mut self) {
        self.url.zeroize();
        self.owner_selinux_domain.zeroize();
        self.agent_selinux_domain.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Subject {
    pub uid: u32,
    pub selinux_domain: String,
}

pub(super) struct UiRequestBinding<'a> {
    pub method: &'a str,
    pub request_id: &'a str,
    pub subject: &'a Subject,
    pub payload: &'a Value,
}

impl Subject {
    pub(super) fn new(uid: u32, selinux_domain: &str) -> Result<Self> {
        if uid < 10_000
            || selinux_domain.is_empty()
            || selinux_domain.len() > 256
            || selinux_domain.chars().any(char::is_control)
        {
            bail!("invalid_context_memory_subject");
        }
        Ok(Self {
            uid,
            selinux_domain: selinux_domain.to_string(),
        })
    }

    fn key(&self) -> String {
        format!(
            "{}:{}",
            self.uid,
            sha256_bytes(self.selinux_domain.as_bytes())
        )
    }
}

#[derive(Clone, Debug)]
pub(super) struct ContextSnapshot {
    pub source_id: String,
    pub source_kind: String,
    pub captured_at_ms: u64,
    pub expires_at_ms: u64,
    pub privacy_class: String,
    pub content_sha256: String,
    pub content: String,
}

pub(super) struct VerifiedContextCapture {
    pub capture_id: String,
    pub capture_receipt_id: String,
    pub capture_request_id: String,
    pub requesting_uid: u32,
    pub subject_user_id: u32,
    pub boot_id_sha256: String,
    pub source_id: String,
    pub source_kind: String,
    pub captured_at_ms: u64,
    pub expires_at_ms: u64,
    pub privacy_class: String,
    pub content_sha256: String,
    pub content_bytes: usize,
    pub content: String,
    pub source_metadata: Value,
    pub origin_request_id: String,
    pub resolution_sha256: String,
}

#[derive(Clone, Debug)]
pub(super) struct AgentGrantTarget {
    pub agent_id: String,
    pub peer_uid: u32,
    pub peer_gid: u32,
    pub selinux_domain: String,
    pub executable_sha256: String,
    pub task_id: String,
    pub subject_user_id: u32,
}

#[derive(Clone, Debug)]
pub(super) struct AgentGrantConsumer {
    pub agent_id: String,
    pub peer_uid: u32,
    pub peer_gid: u32,
    pub selinux_domain: String,
    pub executable_sha256: String,
    pub task_id: String,
    pub subject_user_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDataGrant {
    schema: String,
    grant_id: String,
    resource_kind: String,
    resource_id: String,
    resource_sha256: String,
    source_id: String,
    source_kind: String,
    privacy_class: String,
    owner_uid: u32,
    owner_selinux_domain: String,
    subject_user_id: u32,
    agent_id: String,
    agent_peer_uid: u32,
    #[serde(default)]
    agent_peer_gid: u32,
    agent_selinux_domain: String,
    agent_executable_sha256: String,
    task_id: String,
    raw_allowed: bool,
    egress_scope: String,
    egress_endpoint: String,
    single_use: bool,
    state: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    updated_at_ms: u64,
}

impl AgentDataGrant {
    fn public_json(&self) -> Value {
        json!({
            "schema": self.schema,
            "grant_id": self.grant_id,
            "resource_kind": self.resource_kind,
            "resource_id": self.resource_id,
            "resource_sha256": self.resource_sha256,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "privacy_class": self.privacy_class,
            "subject_user_id": self.subject_user_id,
            "agent_id": self.agent_id,
            "agent_peer_uid": self.agent_peer_uid,
            "agent_peer_gid": self.agent_peer_gid,
            "agent_selinux_domain": self.agent_selinux_domain,
            "agent_executable_sha256": self.agent_executable_sha256,
            "task_id": self.task_id,
            "raw_allowed": self.raw_allowed,
            "egress_scope": self.egress_scope,
            "egress_endpoint": self.egress_endpoint,
            "single_use": self.single_use,
            "state": self.state,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "updated_at_ms": self.updated_at_ms,
            "raw_payload_in_grant_ledger": false,
        })
    }

    fn matches_consumer(&self, consumer: &AgentGrantConsumer) -> bool {
        self.agent_id == consumer.agent_id
            && self.agent_peer_uid == consumer.peer_uid
            && self.agent_peer_gid == consumer.peer_gid
            && self.agent_selinux_domain == consumer.selinux_domain
            && self.agent_executable_sha256 == consumer.executable_sha256
            && self.task_id == consumer.task_id
            && self.subject_user_id == consumer.subject_user_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDataGrantAuditEvent {
    schema: String,
    event_id: String,
    event_type: String,
    grant_id: String,
    resource_kind: String,
    agent_id: String,
    task_id: String,
    subject_user_id: u32,
    created_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDataGrantStore {
    schema: String,
    grants: Vec<AgentDataGrant>,
    audit_events: Vec<AgentDataGrantAuditEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredContext {
    schema: String,
    subject_key: String,
    owner_uid: u32,
    owner_selinux_domain: String,
    subject_user_id: u32,
    boot_id_sha256: String,
    context_id: String,
    source_id: String,
    source_kind: String,
    captured_at_ms: u64,
    expires_at_ms: u64,
    privacy_class: String,
    content_sha256: String,
    content: String,
    capture_id: String,
    capture_receipt_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    capture_request_id: String,
    origin_method: String,
    origin_request_id: String,
    resolution_sha256: String,
    authority_import_state: String,
    #[serde(default)]
    parent_memory_id: String,
    #[serde(default)]
    parent_memory_payload_sha256: String,
    #[serde(default)]
    parent_memory_updated_at_ms: u64,
    revoked: bool,
    revoked_at_ms: u64,
    tombstone_until_ms: u64,
    source_metadata: Value,
}

impl StoredContext {
    fn metadata(&self) -> Value {
        let mut value = json!({
            "schema": CONTEXT_SCHEMA,
            "context_id": self.context_id,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "captured_at_ms": self.captured_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "freshness_ttl_ms": self.expires_at_ms.saturating_sub(self.captured_at_ms),
            "privacy_class": self.privacy_class,
            "content_sha256": self.content_sha256,
            "content_bytes": self.content.len(),
            "capture_id": self.capture_id,
            "capture_receipt_id": self.capture_receipt_id,
            "source_metadata": self.source_metadata,
            "origin_method": self.origin_method,
            "origin_request_id": self.origin_request_id,
            "encrypted_context_payload_persisted": true,
            "raw_cleartext_persisted": false,
            "raw_content_persisted": false,
            "revoked": self.revoked,
        });
        if !self.parent_memory_id.is_empty() {
            let object = value.as_object_mut().expect("context metadata object");
            object.insert(
                "selected_memory_id".to_string(),
                Value::String(self.parent_memory_id.clone()),
            );
            object.insert(
                "selected_memory_payload_sha256".to_string(),
                Value::String(self.parent_memory_payload_sha256.clone()),
            );
            object.insert(
                "selected_memory_updated_at_ms".to_string(),
                Value::from(self.parent_memory_updated_at_ms),
            );
        }
        value
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextJournal {
    schema: String,
    key_id: String,
    boot_id_sha256: String,
    contexts: Vec<StoredContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    reservations: Vec<ContextImportReservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextImportReservation {
    schema: String,
    reservation_id: String,
    subject_key: String,
    owner_uid: u32,
    owner_selinux_domain: String,
    subject_user_id: u32,
    boot_id_sha256: String,
    origin_request_id: String,
    capture_id: String,
    capture_receipt_id: String,
    capture_request_id: String,
    source_id: String,
    source_kind: String,
    content_sha256: String,
    expires_at_ms: u64,
    reserved_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MemoryMetadata {
    schema: String,
    memory_id: String,
    owner_uid: u32,
    owner_selinux_domain: String,
    context_id: String,
    source_id: String,
    source_kind: String,
    captured_at_ms: u64,
    privacy_class: String,
    context_sha256: String,
    payload_sha256: String,
    payload_bytes: usize,
    payload_file: String,
    encryption_key_id: String,
    encryption_algorithm: String,
    receipt_id: String,
    taint_lineage: String,
    #[serde(default)]
    provenance_kind: String,
    #[serde(default)]
    provenance_id: String,
    #[serde(default)]
    task_id: String,
    #[serde(default)]
    plan_id: String,
    retention_until_ms: u64,
    created_at_ms: u64,
    updated_at_ms: u64,
}

impl MemoryMetadata {
    fn public_json(&self) -> Value {
        json!({
            "schema": self.schema,
            "memory_id": self.memory_id,
            "context_id": self.context_id,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "captured_at_ms": self.captured_at_ms,
            "privacy_class": self.privacy_class,
            "context_sha256": self.context_sha256,
            "payload_sha256": self.payload_sha256,
            "payload_bytes": self.payload_bytes,
            "encryption_key_id": self.encryption_key_id,
            "encryption_algorithm": self.encryption_algorithm,
            "receipt_id": self.receipt_id,
            "taint_lineage": self.taint_lineage,
            "provenance_kind": if self.provenance_kind.is_empty() {
                "legacy_unverified"
            } else {
                self.provenance_kind.as_str()
            },
            "provenance_id": self.provenance_id,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "retention_until_ms": self.retention_until_ms,
            "created_at_ms": self.created_at_ms,
            "updated_at_ms": self.updated_at_ms,
            "raw_payload_encrypted_at_rest": true,
        })
    }

    fn owned_by(&self, subject: &Subject) -> bool {
        self.owner_uid == subject.uid && self.owner_selinux_domain == subject.selinux_domain
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedMemoryProvenance {
    kind: String,
    provenance_id: String,
    task_id: String,
    plan_id: String,
    receipt_id: String,
    taint_lineage: String,
}

#[derive(Clone, Debug)]
struct HeldUiMemoryProvenance {
    request_id: String,
    value: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReplayRecord {
    method: String,
    request_id: String,
    subject_key: String,
    payload_sha256: String,
    recorded_at_ms: u64,
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoreFile {
    schema: String,
    key_id: String,
    #[serde(default)]
    ui_replay_archive_initialized: bool,
    #[serde(default)]
    memory_generation: u64,
    memories: Vec<MemoryMetadata>,
    #[serde(default)]
    memory_saves: Vec<MemorySaveTombstone>,
    #[serde(default)]
    memory_deletions: Vec<MemoryDeletionTombstone>,
    replays: Vec<ReplayRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemorySaveTombstone {
    schema: String,
    request_id: String,
    subject_key: String,
    request_payload_sha256: String,
    memory_id: String,
    saved_at_ms: u64,
    result: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryDeletionTombstone {
    schema: String,
    request_id: String,
    subject_key: String,
    memory_id: String,
    deleted_payload_sha256: String,
    deleted_updated_at_ms: u64,
    deleted_at_ms: u64,
    result: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AuthorityKeyPin {
    schema: String,
    key_id: String,
    key_epoch: u64,
    #[serde(default = "default_authority_key_profile")]
    key_profile: String,
    public_key_spki: String,
    security_level: String,
    attestation_challenge_sha256: String,
    #[serde(default = "default_authority_attestation_chain_present")]
    attestation_chain_present: bool,
    rotation_contract: String,
    pinned_at_ms: u64,
    attestation_verified: bool,
}

#[derive(Clone, Debug)]
struct AuthorityKeyCandidate {
    key_id: String,
    key_epoch: u64,
    key_profile: String,
    public_key_spki: String,
    security_level: String,
    attestation_challenge_sha256: String,
    attestation_chain_present: bool,
    rotation_contract: String,
}

fn default_authority_key_profile() -> String {
    AUTHORITY_ATTESTED_KEY_PROFILE.to_string()
}

fn default_authority_attestation_chain_present() -> bool {
    true
}

#[derive(Clone, Debug)]
struct RuntimeReplay {
    payload_sha256: String,
    outcome: std::result::Result<Value, String>,
}

pub(super) enum UiRequestRecovery {
    Unresolved,
    Outcome(std::result::Result<Value, String>),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MemoryKeyEnvelope {
    schema: String,
    backend: String,
    subject_user_id: u32,
    key_alias: String,
    key_epoch: u64,
    aad: String,
    key_id: String,
    nonce_b64: String,
    wrapped_key_b64: String,
    wrapping_algorithm: String,
    security_level: String,
    hardware_backed: bool,
    unlocked_device_required: bool,
}

trait MemoryKeyCustody: Send + Sync {
    fn backend(&self) -> &'static str;
    fn wrap(&self, key: &[u8; 32]) -> Result<MemoryKeyEnvelope>;
    fn unwrap(&self, envelope: &MemoryKeyEnvelope) -> Result<Zeroizing<[u8; 32]>>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UiReplayRecord {
    schema: String,
    #[serde(default)]
    policy_epoch: u64,
    #[serde(default)]
    provider_abi_epoch: u64,
    request_id: String,
    method: String,
    subject_key: String,
    payload_sha256: String,
    state: String,
    recorded_at_ms: u64,
    #[serde(default)]
    outcome_file: String,
    #[serde(default)]
    outcome_ciphertext_sha256: String,
    #[serde(default)]
    outcome_semantic_sha256: String,
    #[serde(default)]
    custody_handoff_ack: Option<UiReplayCustodyHandoffAck>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct UiReplayCustodyHandoffAck {
    schema: String,
    owner_kind: String,
    owner_id: String,
    completion_proof_sha256: String,
    acknowledged_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct UiReplayCompletionProof {
    schema: String,
    policy_epoch: u64,
    provider_abi_epoch: u64,
    method: String,
    request_id: String,
    subject_key: String,
    payload_sha256: String,
    outcome_file: String,
    outcome_ciphertext_sha256: String,
    outcome_semantic_sha256: String,
    proof_sha256: String,
}

/// Sealed, read-only proof that one exact Direct `PlanReady` value has a
/// matching durable UI-replay pair.
///
/// This value is intentionally not serializable and has no constructor outside
/// [`ContextMemoryService::verified_direct_ui_replay_snapshot`].  It carries
/// only digests needed by the daemon custody store; neither the provider result
/// nor any UI text crosses this boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedDirectUiReplaySnapshot {
    // Kept private and never projected into the persisted UI proof. It only
    // prevents a sealed snapshot for binding A from being materialized into a
    // custody record for binding B.
    direct_binding_sha256: String,
    exact_plan_ready_semantic_sha256: String,
    direct_execution_receipt_sha256: String,
    ui_replay_completion_proof_sha256: String,
    ui_replay_semantic_sha256: String,
}

impl VerifiedDirectUiReplaySnapshot {
    pub(crate) fn validate_for_direct_binding(
        &self,
        binding: &DirectOperationBinding,
    ) -> Result<()> {
        binding
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if binding
            .digest_sha256()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            != self.direct_binding_sha256
        {
            bail!("direct_ui_snapshot_custody_binding_substitution_denied");
        }
        Ok(())
    }

    pub(crate) fn exact_plan_ready_semantic_sha256(&self) -> &str {
        &self.exact_plan_ready_semantic_sha256
    }

    pub(crate) fn direct_execution_receipt_sha256(&self) -> &str {
        &self.direct_execution_receipt_sha256
    }

    pub(crate) fn ui_replay_completion_proof_sha256(&self) -> &str {
        &self.ui_replay_completion_proof_sha256
    }

    pub(crate) fn ui_replay_semantic_sha256(&self) -> &str {
        &self.ui_replay_semantic_sha256
    }
}

impl UiReplayCompletionProof {
    pub(super) fn digest_sha256(&self) -> Result<String> {
        let expected = ui_replay_completion_proof_digest(self)?;
        if self.proof_sha256 != expected {
            bail!("ui_replay_completion_proof_self_digest_mismatch");
        }
        Ok(expected)
    }
}

#[derive(Clone, Debug)]
struct UiReplayArchive {
    bits: Vec<u8>,
    set_bits: usize,
    insertions: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UiReplayArchiveFile {
    schema: String,
    bit_count: usize,
    hash_count: usize,
    max_set_bits: usize,
    bits_b64: String,
    set_bits: usize,
    insertions: u64,
    updated_at_ms: u64,
}

impl UiReplayArchive {
    fn empty() -> Self {
        Self {
            bits: vec![0; UI_REPLAY_ARCHIVE_BYTES],
            set_bits: 0,
            insertions: 0,
        }
    }

    fn contains_request_id(&self, request_id: &str) -> bool {
        ui_replay_archive_indices(request_id)
            .into_iter()
            .all(|index| self.bits[index / 8] & (1 << (index % 8)) != 0)
    }

    fn insert_request_id(&mut self, request_id: &str) -> Result<()> {
        let mut indices = ui_replay_archive_indices(request_id);
        indices.sort_unstable();
        indices.dedup();
        let new_bits = indices
            .iter()
            .filter(|index| self.bits[**index / 8] & (1 << (**index % 8)) == 0)
            .count();
        if new_bits == 0 {
            return Ok(());
        }
        if self.set_bits.saturating_add(new_bits) > UI_REPLAY_ARCHIVE_MAX_SET_BITS {
            bail!("ui_replay_archive_capacity_exhausted_fail_closed");
        }
        for index in indices {
            self.bits[index / 8] |= 1 << (index % 8);
        }
        self.set_bits += new_bits;
        self.insertions = self
            .insertions
            .checked_add(1)
            .context("ui_replay_archive_insertion_counter_exhausted_fail_closed")?;
        Ok(())
    }
}

struct State {
    contexts: HashMap<String, StoredContext>,
    context_import_reservations: HashMap<String, ContextImportReservation>,
    store: StoreFile,
    grant_store: AgentDataGrantStore,
    runtime_replays: HashMap<String, RuntimeReplay>,
}

fn active_context_count(state: &State) -> usize {
    state
        .contexts
        .values()
        .filter(|context| !context.revoked)
        .count()
}

fn context_capacity_used(state: &State) -> usize {
    active_context_count(state).saturating_add(state.context_import_reservations.len())
}

pub(super) struct ContextMemoryService {
    root: PathBuf,
    payload_root: PathBuf,
    ui_replay_root: PathBuf,
    ui_replay_outcome_root: PathBuf,
    ui_replay_archive_path: PathBuf,
    execution_payload_root: PathBuf,
    execution_payload_quarantine_root: PathBuf,
    grant_store_path: PathBuf,
    context_journal_path: PathBuf,
    boot_id_sha256: String,
    key: Zeroizing<[u8; 32]>,
    key_envelope: MemoryKeyEnvelope,
    key_custody: Arc<dyn MemoryKeyCustody>,
    state: Mutex<State>,
    serial: Mutex<()>,
    ui_replay_serial: Mutex<()>,
    ui_replay_publication_durability_uncertain: AtomicBool,
    ui_replay_archive: Mutex<UiReplayArchive>,
    pin_serial: Mutex<()>,
    grant_serial: Mutex<()>,
    execution_payload_serial: Mutex<()>,
    egress_recovery_serial: Mutex<()>,
    context_journal_serial: Mutex<()>,
    context_journal_publication_durability_uncertain: AtomicBool,
    store_publication_durability_uncertain: AtomicBool,
    grant_store_publication_durability_uncertain: AtomicBool,
    #[cfg(test)]
    fail_next_grant_persist: AtomicBool,
}

impl ContextMemoryService {
    pub(super) fn context_journal_publication_is_uncertain(&self) -> bool {
        self.context_journal_publication_durability_uncertain
            .load(AtomicOrdering::Acquire)
    }

    pub(super) fn open_from_env() -> Result<Self> {
        let root = std::env::var_os("TRILLIONNIUM_CONTEXT_MEMORY_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT));
        ensure_private_directory(&root)?;
        validate_production_root_ancestor_chain(&root)?;
        let request_id = unique_memory_key_bootstrap_request_id()?;
        let observed = AndroidGatewayAdapter::discover_authority_key_metadata(&request_id)
            .map_err(anyhow::Error::msg)?;
        let candidate = prevalidate_authority_boot_key(&root, &observed.metadata)?;
        commit_android_authority_boot_peer_pin(
            observed.peer_uid,
            &observed.peer_selinux_domain,
            &candidate.key_id,
        )
        .map_err(anyhow::Error::msg)?;
        let custody = Arc::new(AndroidAuthorityMemoryKeyCustody::system_default()?);
        let service = Self::open_with_key_custody(root, custody)?;
        service.pin_authority_key_metadata(observed.metadata)?;
        Ok(service)
    }

    #[cfg(test)]
    pub(super) fn open(root: PathBuf) -> Result<Self> {
        Self::open_with_key_custody(root, Arc::new(SoftwareTestMemoryKeyCustody::default()))
    }

    fn open_with_key_custody(
        root: PathBuf,
        key_custody: Arc<dyn MemoryKeyCustody>,
    ) -> Result<Self> {
        let boot_id_sha256 = current_context_boot_id_sha256()?;
        Self::open_with_key_custody_and_boot(root, key_custody, boot_id_sha256)
    }

    fn open_with_key_custody_and_boot(
        root: PathBuf,
        key_custody: Arc<dyn MemoryKeyCustody>,
        boot_id_sha256: String,
    ) -> Result<Self> {
        if !is_lower_hex(&boot_id_sha256, 64) {
            bail!("context_journal_boot_id_digest_denied");
        }
        ensure_private_directory(&root)?;
        open_private_directory(&root)?
            .sync_all()
            .context("context_memory_root_startup_directory_fsync_failed")?;
        cleanup_private_atomic_temps(&root, root_atomic_temp_max_bytes)?;
        let payload_root = root.join("payloads");
        ensure_private_directory(&payload_root)?;
        let ui_replay_root = root.join("ui-replay");
        ensure_private_directory(&ui_replay_root)?;
        let ui_replay_outcome_root = root.join("ui-replay-outcomes");
        ensure_private_directory(&ui_replay_outcome_root)?;
        let ui_replay_archive_path = root.join(UI_REPLAY_ARCHIVE_FILE);
        let execution_payload_root = root.join("execution-payloads");
        ensure_private_directory(&execution_payload_root)?;
        let execution_payload_quarantine_root = root.join("execution-payload-quarantine");
        ensure_private_directory(&execution_payload_quarantine_root)?;
        let (key, key_envelope) = load_or_create_wrapped_key(&root, key_custody.as_ref())?;
        let key_id = format!("memory-key-{}", key_envelope.key_id);
        let context_journal_path = root.join(CONTEXT_JOURNAL_FILE);
        let (mut contexts, context_import_reservations) = load_context_journal(
            &context_journal_path,
            &key,
            &key_id,
            &boot_id_sha256,
            now_unix_ms(),
        )?;
        let grant_store_path = root.join("agent-data-grants.enc");
        let grant_store_existed = private_entry_exists(&grant_store_path)?;
        let mut grant_store = if grant_store_existed {
            let encrypted =
                read_private_bounded_file(&grant_store_path, MAX_DATA_GRANT_STORE_BYTES + 128)?;
            let clear = Zeroizing::new(decrypt_payload(
                &key,
                DATA_GRANT_STORE_AAD,
                &encrypted,
                MAX_DATA_GRANT_STORE_BYTES,
            )?);
            serde_json::from_slice(clear.as_slice())
                .context("invalid_encrypted_agent_data_grant_store")?
        } else {
            AgentDataGrantStore {
                schema: DATA_GRANT_STORE_SCHEMA.to_string(),
                grants: Vec::new(),
                audit_events: Vec::new(),
            }
        };
        let grant_store_migrated = migrate_legacy_agent_data_grants(&mut grant_store)?;
        validate_agent_data_grant_store(&grant_store)?;
        let grant_store_expired = expire_agent_data_grants(&mut grant_store, now_unix_ms())?;
        let grant_store_changed = grant_store_migrated || grant_store_expired;
        let store_path = root.join("metadata.json");
        let store_existed = private_entry_exists(&store_path)?;
        let mut store = if store_existed {
            load_store(&store_path)?
        } else {
            StoreFile {
                schema: STORE_SCHEMA.to_string(),
                key_id: key_id.clone(),
                ui_replay_archive_initialized: false,
                memory_generation: 1,
                memories: Vec::new(),
                memory_saves: Vec::new(),
                memory_deletions: Vec::new(),
                replays: Vec::new(),
            }
        };
        if !matches!(store.schema.as_str(), STORE_SCHEMA | LEGACY_STORE_SCHEMA)
            || store.key_id != key_id
            || (store.schema == LEGACY_STORE_SCHEMA && store.ui_replay_archive_initialized)
            || (store_existed
                && store.schema == STORE_SCHEMA
                && !store.ui_replay_archive_initialized)
        {
            bail!("context_memory_store_identity_mismatch");
        }
        validate_store(&store, &payload_root)?;
        contexts.retain(|_, context| {
            if context.origin_method != "select_memory_context" {
                return true;
            }
            store.memories.iter().any(|memory| {
                memory.memory_id == context.parent_memory_id
                    && memory.owner_uid == context.owner_uid
                    && memory.owner_selinux_domain == context.owner_selinux_domain
                    && memory.payload_sha256 == context.parent_memory_payload_sha256
                    && memory.updated_at_ms == context.parent_memory_updated_at_ms
                    && memory.retention_until_ms > now_unix_ms()
            })
        });
        let memory_generation_migrated = store.memory_generation == 0;
        if memory_generation_migrated {
            store.memory_generation = 1;
        }
        let now = now_unix_ms();
        let replay_count_before_expiry = store.replays.len();
        store
            .replays
            .retain(|item| item.recorded_at_ms.saturating_add(REPLAY_RETENTION_MS) > now);
        let deletion_count_before_expiry = store.memory_deletions.len();
        store
            .memory_deletions
            .retain(|item| item.deleted_at_ms.saturating_add(REPLAY_RETENTION_MS) > now);
        let expired = store
            .memories
            .iter()
            .filter(|item| item.retention_until_ms <= now)
            .map(|item| item.payload_file.clone())
            .collect::<Vec<_>>();
        store.memories.retain(|item| item.retention_until_ms > now);
        let live_memory_ids = store
            .memories
            .iter()
            .map(|memory| memory.memory_id.clone())
            .collect::<HashSet<_>>();
        let save_count_before_expiry = store.memory_saves.len();
        store.memory_saves.retain(|item| {
            item.saved_at_ms.saturating_add(REPLAY_RETENTION_MS) > now
                && live_memory_ids.contains(&item.memory_id)
        });
        if !expired.is_empty() {
            store.memory_generation = store
                .memory_generation
                .checked_add(1)
                .context("memory_generation_exhausted")?;
        }
        let mut metadata_changed = memory_generation_migrated
            || replay_count_before_expiry != store.replays.len()
            || save_count_before_expiry != store.memory_saves.len()
            || deletion_count_before_expiry != store.memory_deletions.len()
            || !expired.is_empty();
        let archive_was_initialized = store.ui_replay_archive_initialized;
        let ui_replay_archive =
            load_or_create_ui_replay_archive(&ui_replay_archive_path, archive_was_initialized)?;
        if !archive_was_initialized {
            if ui_replay_archive.set_bits != 0 || ui_replay_archive.insertions != 0 {
                bail!("legacy_ui_replay_archive_migration_is_not_empty");
            }
            // Migration is ordered: first durably publish the empty archive,
            // then atomically mark metadata initialized. Once this marker is
            // visible, an absent archive can never be recreated as empty.
            store.schema = STORE_SCHEMA.to_string();
            store.ui_replay_archive_initialized = true;
            metadata_changed = true;
        }
        // Expiry is a two-phase delete. The durable metadata transition is the
        // commit point: only after every expired payload has been unreferenced
        // may its ciphertext be removed. A crash or unlink failure after this
        // point leaves a harmless orphan that the next startup prunes.
        if metadata_changed
            && persist_store_file(&store_path, &store)?
                == PrivatePublishState::PublishedDurabilityUncertain
        {
            bail!("context_memory_startup_metadata_commit_unknown_parent_fsync_uncertain");
        }
        for file in &expired {
            remove_expired_payload_if_present(&payload_root, file)?;
        }
        prune_orphaned_memory_payloads(&payload_root, &store)?;
        let mut deletion_reconciled = false;
        for tombstone in &mut store.memory_deletions {
            if tombstone
                .result
                .get("primary_payload_deleted")
                .and_then(Value::as_bool)
                == Some(false)
                && !private_entry_exists(
                    &payload_root.join(format!("{}.enc", tombstone.memory_id)),
                )?
            {
                tombstone
                    .result
                    .as_object_mut()
                    .context("memory_deletion_tombstone_result_not_object")?
                    .insert("primary_payload_deleted".to_string(), Value::Bool(true));
                deletion_reconciled = true;
            }
        }
        if deletion_reconciled
            && persist_store_file(&store_path, &store)?
                == PrivatePublishState::PublishedDurabilityUncertain
        {
            bail!("context_memory_startup_reconciliation_commit_unknown_parent_fsync_uncertain");
        }
        let service = Self {
            root,
            payload_root,
            ui_replay_root,
            ui_replay_outcome_root,
            ui_replay_archive_path,
            execution_payload_root,
            execution_payload_quarantine_root,
            grant_store_path,
            context_journal_path,
            boot_id_sha256,
            key,
            key_envelope,
            key_custody,
            state: Mutex::new(State {
                contexts,
                context_import_reservations,
                store,
                grant_store,
                runtime_replays: HashMap::new(),
            }),
            serial: Mutex::new(()),
            ui_replay_serial: Mutex::new(()),
            ui_replay_publication_durability_uncertain: AtomicBool::new(false),
            ui_replay_archive: Mutex::new(ui_replay_archive),
            pin_serial: Mutex::new(()),
            grant_serial: Mutex::new(()),
            execution_payload_serial: Mutex::new(()),
            egress_recovery_serial: Mutex::new(()),
            context_journal_serial: Mutex::new(()),
            context_journal_publication_durability_uncertain: AtomicBool::new(false),
            store_publication_durability_uncertain: AtomicBool::new(false),
            grant_store_publication_durability_uncertain: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_grant_persist: AtomicBool::new(false),
        };
        service.reconcile_ui_replay_startup()?;
        service.persist_context_journal()?;
        service.prune_execution_payloads(now_unix_ms())?;
        if service.persist()? == PrivatePublishState::PublishedDurabilityUncertain {
            bail!("context_memory_open_final_store_commit_unknown_parent_fsync_uncertain");
        }
        if (!grant_store_existed || grant_store_changed)
            && service.persist_grant_store()? == PrivatePublishState::PublishedDurabilityUncertain
        {
            bail!("agent_data_grant_store_open_commit_unknown_parent_fsync_uncertain");
        }
        Ok(service)
    }

    fn reconcile_ui_replay_startup(&self) -> Result<()> {
        // A crash after either rename may leave visibility ahead of the
        // rename's parent-directory durability. Establish durability in
        // dependency order (outcome first, then referencing record) before
        // scanning, cleaning temps, decrypting or answering any query.
        open_private_directory(&self.ui_replay_outcome_root)?
            .sync_all()
            .context("ui_replay_startup_outcome_directory_fsync_failed")?;
        open_private_directory(&self.ui_replay_root)?
            .sync_all()
            .context("ui_replay_startup_record_directory_fsync_failed")?;
        cleanup_private_atomic_temps(&self.ui_replay_outcome_root, |destination| {
            is_ui_replay_outcome_file_name(destination)
                .then_some((MAX_UI_REPLAY_OUTCOME_BYTES + 128) as u64)
        })?;
        cleanup_private_atomic_temps(&self.ui_replay_root, |destination| {
            is_ui_replay_record_file_name(destination).then_some(STORE_FILE_MAX_BYTES)
        })?;

        let mut records = HashMap::new();
        for entry in fs::read_dir(&self.ui_replay_root)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("ui_replay_record_name_not_utf8"))?;
            if !is_ui_replay_record_file_name(&name) {
                bail!("unexpected_ui_replay_record_entry");
            }
            let record = load_ui_replay_record(&entry.path())?;
            let expected_name = format!("{}.json", sha256_bytes(record.request_id.as_bytes()));
            if name != expected_name || records.insert(record.request_id.clone(), record).is_some()
            {
                bail!("ui_replay_startup_record_file_binding_denied");
            }
        }

        let mut observed_outcomes = HashSet::new();
        for entry in fs::read_dir(&self.ui_replay_outcome_root)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("ui_replay_outcome_name_not_utf8"))?;
            if !is_ui_replay_outcome_file_name(&name) || !observed_outcomes.insert(name.clone()) {
                bail!("unexpected_ui_replay_outcome_entry");
            }
        }

        for record in records.values_mut() {
            let expected_outcome = format!("{}.enc", sha256_bytes(record.request_id.as_bytes()));
            if record.state == "completed" {
                if record.outcome_file != expected_outcome
                    || !observed_outcomes.remove(&expected_outcome)
                {
                    bail!("ui_replay_startup_completed_pair_missing");
                }
                if record.schema == UI_REPLAY_SCHEMA {
                    self.verify_completed_ui_replay_pair(record)?;
                } else if record.schema == LEGACY_V2_UI_REPLAY_SCHEMA {
                    self.decrypt_and_validate_ui_replay_outcome(record)?;
                } else {
                    // v1 is a retired fail-closed tombstone. Its legacy AAD is
                    // intentionally unavailable, but its referenced private
                    // ciphertext must still exist and pass file custody checks.
                    read_private_bounded_file(
                        &self.ui_replay_outcome_root.join(&expected_outcome),
                        MAX_UI_REPLAY_OUTCOME_BYTES + 128,
                    )?;
                }
            } else if observed_outcomes.remove(&expected_outcome) {
                // Outcome rename won but the completed record rename did not.
                // Outcome bytes are already authoritative. Complete the exact
                // pair from those bytes before any downstream recovery query;
                // never replace them with a fresh random-nonce encryption.
                if record.schema == UI_REPLAY_SCHEMA {
                    let (encrypted, envelope) =
                        self.decrypt_and_validate_ui_replay_outcome(record)?;
                    record.state = "completed".to_string();
                    record.outcome_file = expected_outcome.clone();
                    record.outcome_ciphertext_sha256 = sha256_bytes(&encrypted);
                    record.outcome_semantic_sha256 = sha256_json(&envelope);
                    record.custody_handoff_ack = None;
                    let record_path = self.ui_replay_root.join(format!(
                        "{}.json",
                        sha256_bytes(record.request_id.as_bytes())
                    ));
                    if atomic_write_private_staged(
                        &record_path,
                        &serde_json::to_vec_pretty(record)?,
                    )? == PrivatePublishState::PublishedDurabilityUncertain
                    {
                        self.ui_replay_publication_durability_uncertain
                            .store(true, AtomicOrdering::Release);
                        bail!("ui_replay_startup_pair_completion_parent_fsync_uncertain");
                    }
                    self.verify_completed_ui_replay_pair(record)?;
                } else if record.schema == LEGACY_V2_UI_REPLAY_SCHEMA {
                    self.decrypt_and_validate_ui_replay_outcome(record)?;
                } else {
                    bail!("ui_replay_legacy_in_progress_outcome_retired_hold");
                }
            }
        }
        if !observed_outcomes.is_empty() {
            bail!("ui_replay_startup_orphan_outcome_denied");
        }
        Ok(())
    }

    fn require_memory_key_unlocked(&self) -> Result<()> {
        let current = self
            .key_custody
            .unwrap(&self.key_envelope)
            .context("memory_key_custody_unavailable_or_subject_user_locked")?;
        if !constant_time_bytes_equal(current.as_slice(), self.key.as_slice())
            || sha256_bytes(current.as_slice()) != self.key_envelope.key_id
        {
            bail!("memory_key_custody_identity_changed");
        }
        Ok(())
    }

    /// Re-authorize every protected cleartext read with the custody backend.
    ///
    /// The cached key is used only after a fresh unwrap proves that the
    /// subject user is still unlocked and that custody returned the same key.
    fn decrypt_custody_gated(
        &self,
        associated_data: &[u8],
        encrypted: &[u8],
        max_clear_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.require_memory_key_unlocked()?;
        Ok(Zeroizing::new(decrypt_payload(
            &self.key,
            associated_data,
            encrypted,
            max_clear_len,
        )?))
    }

    /// Seal a bounded workflow envelope with the Context/Memory custody key.
    ///
    /// This deliberately exposes neither the key nor a generic cryptographic
    /// primitive. Callers must supply immutable AAD and an explicit size cap;
    /// every operation re-authorizes the wrapped key with the custody backend.
    pub(super) fn seal_workflow_blob(
        &self,
        associated_data: &[u8],
        clear: &[u8],
        max_clear_len: usize,
    ) -> Result<Vec<u8>> {
        if associated_data.is_empty()
            || associated_data.len() > 16 * 1024
            || max_clear_len == 0
            || max_clear_len > MAX_WORKFLOW_BLOB_CLEAR_BYTES
            || clear.len() > max_clear_len
        {
            bail!("invalid_workflow_seal_boundary");
        }
        self.require_memory_key_unlocked()?;
        encrypt_payload(&self.key, associated_data, clear)
    }

    pub(super) fn unseal_workflow_blob(
        &self,
        associated_data: &[u8],
        encrypted: &[u8],
        max_clear_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if associated_data.is_empty()
            || associated_data.len() > 16 * 1024
            || max_clear_len == 0
            || max_clear_len > MAX_WORKFLOW_BLOB_CLEAR_BYTES
            || encrypted.len() > max_clear_len.saturating_add(128)
        {
            bail!("invalid_workflow_unseal_boundary");
        }
        self.decrypt_custody_gated(associated_data, encrypted, max_clear_len)
    }

    pub(super) fn action_workflow_root(&self) -> Result<PathBuf> {
        let root = self.root.join("action-workflow");
        ensure_private_directory(&root)?;
        Ok(root)
    }

    /// Publish one bounded egress-recovery ciphertext under the Context/Memory
    /// custody key.  This is intentionally narrower than a generic file or
    /// encryption API: the domain separator is fixed here, the destination is
    /// derived from the OS-minted grant id, and replacement is denied.
    pub(super) fn publish_egress_recovery_blob(
        &self,
        grant_id: &str,
        associated_data: &[u8],
        canonical_cleartext: &[u8],
    ) -> Result<EgressRecoveryBlobRef> {
        validate_egress_recovery_grant_id(grant_id)?;
        validate_egress_recovery_boundary(associated_data, canonical_cleartext.len())?;
        let _serial = self
            .egress_recovery_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("egress_recovery_blob_lock_poisoned"))?;
        let root = self.egress_recovery_root()?;
        let file_name = egress_recovery_file_name(grant_id);
        let path = root.join(&file_name);
        if private_entry_exists(&path)? {
            bail!("egress_recovery_blob_already_exists");
        }
        if fs::read_dir(&root)?.count() >= MAX_EGRESS_RECOVERY_FILES {
            bail!("egress_recovery_blob_capacity_reached");
        }
        let aad = egress_recovery_domain_aad(associated_data)?;
        self.require_memory_key_unlocked()?;
        let encrypted = encrypt_payload(&self.key, &aad, canonical_cleartext)?;
        if encrypted.len() > MAX_EGRESS_RECOVERY_CIPHERTEXT_BYTES {
            bail!("egress_recovery_ciphertext_too_large");
        }
        let publication = atomic_write_private_staged(&path, &encrypted)?;
        Ok(EgressRecoveryBlobRef {
            file_name,
            ciphertext_sha256: sha256_bytes(&encrypted),
            publication_durability_uncertain: publication
                == PrivatePublishState::PublishedDurabilityUncertain,
        })
    }

    pub(super) fn read_egress_recovery_blob(
        &self,
        reference: &EgressRecoveryBlobRef,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        validate_egress_recovery_reference(reference)?;
        validate_egress_recovery_boundary(associated_data, 0)?;
        let _serial = self
            .egress_recovery_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("egress_recovery_blob_lock_poisoned"))?;
        let path = self.egress_recovery_root()?.join(&reference.file_name);
        let encrypted = read_private_bounded_file(&path, MAX_EGRESS_RECOVERY_CIPHERTEXT_BYTES)
            .context("invalid_egress_recovery_ciphertext")?;
        if sha256_bytes(&encrypted) != reference.ciphertext_sha256 {
            bail!("egress_recovery_ciphertext_digest_mismatch");
        }
        let aad = egress_recovery_domain_aad(associated_data)?;
        self.decrypt_custody_gated(&aad, &encrypted, MAX_EGRESS_RECOVERY_CLEAR_BYTES)
    }

    pub(super) fn delete_egress_recovery_blob(
        &self,
        reference: &EgressRecoveryBlobRef,
    ) -> Result<()> {
        validate_egress_recovery_reference(reference)?;
        let _serial = self
            .egress_recovery_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("egress_recovery_blob_lock_poisoned"))?;
        remove_private_regular_file(
            &self.egress_recovery_root()?.join(&reference.file_name),
            true,
        )
    }

    /// Remove only well-formed ciphertext entries not referenced by a
    /// PREPARED journal record. Unknown names, links, directories, or unsafe
    /// files fail closed instead of being opportunistically deleted.
    pub(super) fn prune_egress_recovery_orphans(
        &self,
        retained_file_names: &HashSet<String>,
    ) -> Result<usize> {
        let _serial = self
            .egress_recovery_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("egress_recovery_blob_lock_poisoned"))?;
        let root = self.egress_recovery_root()?;
        cleanup_private_atomic_temps(&root, |destination| {
            is_egress_recovery_file_name(destination)
                .then_some(MAX_EGRESS_RECOVERY_CIPHERTEXT_BYTES as u64)
        })?;
        let mut removed = 0usize;
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let file_name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid_egress_recovery_entry_name"))?;
            if !is_egress_recovery_file_name(&file_name) {
                bail!("unexpected_egress_recovery_entry");
            }
            let path = root.join(&file_name);
            open_private_regular_file(&path, MAX_EGRESS_RECOVERY_CIPHERTEXT_BYTES as u64, false)?;
            if !retained_file_names.contains(&file_name) {
                remove_private_regular_file(&path, false)?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    fn egress_recovery_root(&self) -> Result<PathBuf> {
        let root = self.root.join("egress-recovery");
        ensure_private_directory(&root)?;
        Ok(root)
    }

    pub(super) fn ui_request_completion_proof_exact(
        &self,
        method: &str,
        request_id: &str,
        subject_uid: u32,
        subject_selinux_domain: &str,
        payload_sha256: &str,
    ) -> Result<Option<UiReplayCompletionProof>> {
        if self
            .ui_replay_publication_durability_uncertain
            .load(AtomicOrdering::Acquire)
        {
            bail!("ui_replay_fail_stop_published_durability_uncertain");
        }
        validate_request_id(request_id)?;
        if method.is_empty() || !is_lower_hex(payload_sha256, 64) {
            bail!("invalid_ui_replay_completion_query");
        }
        let subject = Subject::new(subject_uid, subject_selinux_domain)?;
        let request_hash = sha256_bytes(request_id.as_bytes());
        let record_path = self.ui_replay_root.join(format!("{request_hash}.json"));
        // The record is published by atomic rename. A concurrent transition
        // can therefore expose only the complete old or complete new record;
        // observing `in_progress` merely delays compaction to a later pass.
        // Avoid taking ui_replay_serial here because workflow callers already
        // hold their journal lock and replay recovery takes the reverse order.
        if !private_entry_exists(&record_path)? {
            return Ok(None);
        }
        let record = load_ui_replay_record(&record_path)?;
        validate_ui_replay_identity(&record, method, request_id, &subject, payload_sha256)?;
        if record.state != "completed" {
            return Ok(None);
        }
        let (proof, _) = self.verify_completed_ui_replay_pair(&record)?;
        Ok(Some(proof))
    }

    /// Verify that a sealed Direct `PlanReady` candidate is represented by one
    /// exact, already-durable UI-replay pair.
    ///
    /// The action journal supplies the exact validated result, but it does not
    /// supply a trusted replay envelope.  This method applies the sole existing
    /// plan replay sanitizer, then compares that expected envelope byte-for-byte
    /// and semantically with the encrypted UI outcome.  It is query-only: no UI
    /// owner, handoff ACK, compaction, or archive mutation is performed.
    // This compiled seam intentionally remains inert until the reviewed
    // daemon custody coordinator is wired in a later stage.
    #[allow(dead_code)]
    pub(crate) fn verified_direct_ui_replay_snapshot(
        &self,
        candidate: &DirectPlanCustodyCandidate,
    ) -> Result<VerifiedDirectUiReplaySnapshot> {
        if self
            .ui_replay_publication_durability_uncertain
            .load(AtomicOrdering::Acquire)
        {
            bail!("ui_replay_fail_stop_published_durability_uncertain");
        }

        let direct_binding = candidate.direct_binding();
        direct_binding
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let direct_binding_sha256 = direct_binding
            .digest_sha256()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let workflow = candidate.workflow_binding();
        let expected_agent_id = agent_principal_registry::from_provider_id(&workflow.provider_id)
            .ok_or_else(|| anyhow::anyhow!("direct_ui_snapshot_provider_binding_denied"))?
            .agent_id;
        if candidate.direct_binding_sha256() != direct_binding_sha256
            || direct_binding.stable_seed.provider_id != workflow.provider_id
            || direct_binding.stable_seed.agent_id != expected_agent_id
            || direct_binding.stable_seed.task_id != workflow.task_id
            || direct_binding.stable_seed.provider_invocation_id_sha256
                != sha256_bytes(workflow.request_id.as_bytes())
            || direct_binding.stable_seed.subject_uid != workflow.subject_uid
            || direct_binding.stable_seed.subject_selinux_domain_sha256
                != sha256_bytes(workflow.subject_selinux_domain.as_bytes())
        {
            bail!("direct_ui_snapshot_cross_binding_drift_denied");
        }

        let request_id = candidate.request_id();
        let payload_sha256 = candidate.request_payload_sha256();
        validate_request_id(request_id)?;
        if !is_lower_hex(payload_sha256, 64) {
            bail!("direct_ui_snapshot_request_payload_digest_denied");
        }
        let subject = Subject::new(candidate.subject_uid(), candidate.subject_selinux_domain())?;
        let record_path = self
            .ui_replay_root
            .join(format!("{}.json", sha256_bytes(request_id.as_bytes())));
        if !private_entry_exists(&record_path)? {
            bail!("direct_ui_snapshot_completed_record_missing");
        }
        let record = load_ui_replay_record(&record_path)?;
        validate_ui_replay_identity(&record, "plan", request_id, &subject, payload_sha256)?;
        if record.state != "completed" {
            bail!("direct_ui_snapshot_requires_completed_record");
        }
        let (proof, actual_envelope) = self.verify_completed_ui_replay_pair(&record)?;
        let recorded_proof_sha256 = candidate
            .plan_ui_completion_proof_sha256()
            .context("direct_ui_snapshot_action_workflow_completion_proof_missing")?;
        let actual_proof_sha256 = proof.digest_sha256()?;
        if recorded_proof_sha256 != actual_proof_sha256 {
            bail!("direct_ui_snapshot_completion_proof_drift_denied");
        }

        let exact_plan_response = candidate.exact_plan_response();
        if exact_plan_response
            .get("execution_mode")
            .and_then(Value::as_str)
            != Some("agent_direct")
            || exact_plan_response.get("action").and_then(Value::as_str)
                != Some("agent_direct_result")
            || sha256_json(exact_plan_response) != candidate.exact_plan_response_semantic_sha256()
            || exact_plan_response
                .get("direct_execution_receipt_sha256")
                .and_then(Value::as_str)
                != Some(candidate.direct_execution_receipt_sha256())
            || !is_lower_hex(candidate.direct_execution_receipt_sha256(), 64)
        {
            bail!("direct_ui_snapshot_exact_plan_ready_binding_denied");
        }

        // AgentDirect results intentionally do not enter the retired planning
        // provenance vocabulary.  A null payload therefore makes any attempt
        // to synthesize provenance fail closed while preserving the one
        // production sanitizer for summary redaction.
        let expected_envelope =
            durable_ui_replay_envelope("plan", &Value::Null, &Ok(exact_plan_response.clone()));
        validate_canonical_ui_replay_envelope("plan", &expected_envelope)?;
        if expected_envelope.get("memory_provenance").is_some() {
            bail!("direct_ui_snapshot_unexpected_memory_provenance");
        }
        let expected_bytes = serde_json::to_vec(&expected_envelope)?;
        let actual_bytes = serde_json::to_vec(&actual_envelope)?;
        let expected_semantic_sha256 = sha256_json(&expected_envelope);
        if actual_bytes != expected_bytes
            || sha256_json(&actual_envelope) != expected_semantic_sha256
            || proof.outcome_semantic_sha256 != expected_semantic_sha256
        {
            bail!("direct_ui_snapshot_sanitized_envelope_drift_denied");
        }
        if self
            .ui_replay_publication_durability_uncertain
            .load(AtomicOrdering::Acquire)
        {
            bail!("ui_replay_fail_stop_published_durability_uncertain");
        }

        Ok(VerifiedDirectUiReplaySnapshot {
            direct_binding_sha256,
            exact_plan_ready_semantic_sha256: candidate
                .exact_plan_response_semantic_sha256()
                .to_string(),
            direct_execution_receipt_sha256: candidate
                .direct_execution_receipt_sha256()
                .to_string(),
            ui_replay_completion_proof_sha256: actual_proof_sha256,
            ui_replay_semantic_sha256: expected_semantic_sha256,
        })
    }

    #[cfg(test)]
    pub(crate) fn hold_ui_replay_lock_for_test<F, T>(&self, operation: F) -> T
    where
        F: FnOnce() -> T,
    {
        let _guard = self.ui_replay_serial.lock().unwrap();
        operation()
    }

    fn verify_completed_ui_replay_pair(
        &self,
        record: &UiReplayRecord,
    ) -> Result<(UiReplayCompletionProof, Value)> {
        if record.state != "completed" {
            bail!("ui_replay_completion_proof_requires_completed_record");
        }
        let expected_file = format!("{}.enc", sha256_bytes(record.request_id.as_bytes()));
        if record.outcome_file != expected_file
            || !is_lower_hex(&record.outcome_ciphertext_sha256, 64)
            || !is_lower_hex(&record.outcome_semantic_sha256, 64)
        {
            bail!("ui_replay_completed_record_pair_binding_invalid");
        }
        let (encrypted, envelope) = self.decrypt_and_validate_ui_replay_outcome(record)?;
        if sha256_bytes(&encrypted) != record.outcome_ciphertext_sha256 {
            bail!("ui_replay_outcome_ciphertext_digest_mismatch");
        }
        let semantic_sha256 = sha256_json(&envelope);
        if semantic_sha256 != record.outcome_semantic_sha256 {
            bail!("ui_replay_outcome_semantic_digest_mismatch");
        }
        let mut proof = UiReplayCompletionProof {
            schema: UI_REPLAY_COMPLETION_PROOF_SCHEMA.to_string(),
            policy_epoch: record.policy_epoch,
            provider_abi_epoch: record.provider_abi_epoch,
            method: record.method.clone(),
            request_id: record.request_id.clone(),
            subject_key: record.subject_key.clone(),
            payload_sha256: record.payload_sha256.clone(),
            outcome_file: record.outcome_file.clone(),
            outcome_ciphertext_sha256: record.outcome_ciphertext_sha256.clone(),
            outcome_semantic_sha256: record.outcome_semantic_sha256.clone(),
            proof_sha256: String::new(),
        };
        proof.proof_sha256 = ui_replay_completion_proof_digest(&proof)?;
        Ok((proof, envelope))
    }

    fn decrypt_and_validate_ui_replay_outcome(
        &self,
        record: &UiReplayRecord,
    ) -> Result<(Vec<u8>, Value)> {
        let outcome_path = self.ui_replay_outcome_root.join(format!(
            "{}.enc",
            sha256_bytes(record.request_id.as_bytes())
        ));
        let encrypted =
            read_private_bounded_file(&outcome_path, MAX_UI_REPLAY_OUTCOME_BYTES + 128)?;
        let aad = ui_replay_associated_data_for_record(record)?;
        let clear = self.decrypt_custody_gated(&aad, &encrypted, MAX_UI_REPLAY_OUTCOME_BYTES)?;
        let envelope: Value = serde_json::from_slice(clear.as_slice())
            .context("invalid_encrypted_ui_replay_outcome")?;
        if serde_json::to_vec(&envelope)? != clear.as_slice() {
            bail!("ui_replay_outcome_not_canonical_json");
        }
        validate_canonical_ui_replay_envelope_for_epochs(
            &record.method,
            &envelope,
            record.policy_epoch,
            record.provider_abi_epoch,
        )?;
        Ok((encrypted, envelope))
    }

    pub(super) fn acknowledge_ui_replay_custody_handoff(
        &self,
        proof: &UiReplayCompletionProof,
        subject_uid: u32,
        subject_selinux_domain: &str,
        owner_kind: &str,
        owner_id: &str,
    ) -> Result<()> {
        if self
            .ui_replay_publication_durability_uncertain
            .load(AtomicOrdering::Acquire)
        {
            bail!("ui_replay_fail_stop_published_durability_uncertain");
        }
        let proof_sha256 = proof.digest_sha256()?;
        let subject = Subject::new(subject_uid, subject_selinux_domain)?;
        let _guard = self
            .ui_replay_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("ui_replay_lock_poisoned"))?;
        let record_path = self.ui_replay_root.join(format!(
            "{}.json",
            sha256_bytes(proof.request_id.as_bytes())
        ));
        let mut record = load_ui_replay_record(&record_path)?;
        validate_ui_replay_identity(
            &record,
            &proof.method,
            &proof.request_id,
            &subject,
            &proof.payload_sha256,
        )?;
        let (verified, envelope) = self.verify_completed_ui_replay_pair(&record)?;
        if &verified != proof {
            bail!("ui_replay_custody_handoff_proof_substitution_denied");
        }
        validate_ui_replay_custody_owner(&record, &envelope, owner_kind, owner_id)?;
        let ack = UiReplayCustodyHandoffAck {
            schema: UI_REPLAY_CUSTODY_HANDOFF_SCHEMA.to_string(),
            owner_kind: owner_kind.to_string(),
            owner_id: owner_id.to_string(),
            completion_proof_sha256: proof_sha256,
            acknowledged_at_ms: now_unix_ms(),
        };
        validate_ui_replay_handoff_ack_shape(&ack)?;
        if let Some(existing) = &record.custody_handoff_ack {
            if existing.owner_kind != ack.owner_kind
                || existing.owner_id != ack.owner_id
                || existing.completion_proof_sha256 != ack.completion_proof_sha256
            {
                bail!("ui_replay_custody_handoff_changed");
            }
            return Ok(());
        }
        record.custody_handoff_ack = Some(ack);
        if atomic_write_private_staged(&record_path, &serde_json::to_vec_pretty(&record)?)?
            == PrivatePublishState::PublishedDurabilityUncertain
        {
            self.ui_replay_publication_durability_uncertain
                .store(true, AtomicOrdering::Release);
            bail!("ui_replay_custody_handoff_commit_unknown_parent_fsync_uncertain");
        }
        Ok(())
    }

    pub(super) fn spawn_execution_payload_reaper(service: &Arc<Self>) -> Result<()> {
        let weak = Arc::downgrade(service);
        std::thread::Builder::new()
            .name("trillionnium-execution-payload-reaper".to_string())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(30));
                    let Some(service) = weak.upgrade() else {
                        break;
                    };
                    if service.prune_execution_payloads(now_unix_ms()).is_err() {
                        eprintln!("protected execution payload reaper failed closed");
                    }
                }
            })
            .context("failed to start protected execution payload reaper")?;
        Ok(())
    }

    pub(super) fn call(
        &self,
        method: &str,
        request_id: &str,
        subject: &Subject,
        payload: Value,
    ) -> Result<Value> {
        self.ensure_store_publication_certain()?;
        validate_request_id(request_id)?;
        validate_context_memory_request_payload(method, &payload)?;
        let _serial = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_operation_lock_poisoned"))?;
        self.cleanup()?;
        let payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload)?);
        let replay_key = replay_key(method, request_id, subject);
        if let Some(outcome) = self.replay_outcome(&replay_key, &payload_sha256)? {
            return self
                .validate_method_aware_call_replay(
                    method,
                    request_id,
                    &payload_sha256,
                    subject,
                    outcome,
                )?
                .map_err(anyhow::Error::msg);
        }

        let persist_result = match method {
            "revoke_context" | "save_memory" | "delete_memory" => true,
            "list_memory" => false,
            _ => false,
        };
        let outcome = match method {
            "get_context" => bail!("caller_supplied_context_capture_denied"),
            "revoke_context" => self.revoke_context(subject, payload),
            "list_memory" => self.list_memory(subject, payload),
            "save_memory" => self.save_memory(subject, request_id, &payload_sha256, payload),
            "delete_memory" => self.delete_memory(subject, request_id, payload),
            _ => bail!("unknown_context_memory_method"),
        };
        self.record_replay(
            replay_key,
            method,
            request_id,
            subject,
            payload_sha256,
            &outcome,
            persist_result,
        )?;
        outcome
    }

    pub(super) fn query_call_replay_exact(
        &self,
        method: &str,
        request_id: &str,
        subject: &Subject,
        payload: &Value,
    ) -> Result<Option<std::result::Result<Value, String>>> {
        self.ensure_store_publication_certain()?;
        if !matches!(method, "save_memory" | "delete_memory" | "revoke_context") {
            bail!("context_memory_query_only_recovery_method_denied");
        }
        validate_request_id(request_id)?;
        validate_context_memory_request_payload(method, payload)?;
        let payload_sha256 = sha256_bytes(&serde_json::to_vec(payload)?);
        let replay_key = replay_key(method, request_id, subject);
        let mut outcome = self.replay_outcome(&replay_key, &payload_sha256)?;
        if let Some(replayed) = outcome.take() {
            outcome = Some(self.validate_method_aware_call_replay(
                method,
                request_id,
                &payload_sha256,
                subject,
                replayed,
            )?);
        }
        if outcome.is_none() && method == "save_memory" {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            if let Some(tombstone) = state
                .store
                .memory_saves
                .iter()
                .find(|item| item.request_id == request_id && item.subject_key == subject.key())
            {
                if tombstone.request_payload_sha256 != payload_sha256 {
                    bail!("memory_save_tombstone_payload_substitution_denied");
                }
                let memory = state
                    .store
                    .memories
                    .iter()
                    .find(|memory| memory.memory_id == tombstone.memory_id)
                    .context("memory_save_tombstone_result_no_longer_available")?;
                if memory.public_json() != tombstone.result {
                    bail!("memory_save_tombstone_result_binding_denied");
                }
                outcome = Some(Ok(tombstone.result.clone()));
            }
        }
        if outcome.is_none() && method == "delete_memory" {
            let memory_id = payload
                .get("memory_id")
                .and_then(Value::as_str)
                .context("memory_delete_recovery_memory_id_missing")?;
            let expected_payload_sha256 = payload
                .get("expected_payload_sha256")
                .and_then(Value::as_str)
                .context("memory_delete_recovery_payload_digest_missing")?;
            let expected_updated_at_ms = payload
                .get("expected_updated_at_ms")
                .and_then(Value::as_u64)
                .context("memory_delete_recovery_updated_at_missing")?;
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            if let Some(tombstone) = state.store.memory_deletions.iter().find(|item| {
                item.request_id == request_id
                    && item.subject_key == subject.key()
                    && item.memory_id == memory_id
                    && item.deleted_payload_sha256 == expected_payload_sha256
                    && item.deleted_updated_at_ms == expected_updated_at_ms
                    && item
                        .result
                        .get("primary_payload_deleted")
                        .and_then(Value::as_bool)
                        == Some(true)
            }) {
                outcome = Some(Ok(tombstone.result.clone()));
            }
        }
        if outcome.is_none() && method == "revoke_context" {
            let context_id = payload
                .get("context_id")
                .and_then(Value::as_str)
                .context("context_revoke_recovery_context_id_missing")?;
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            if state.contexts.get(context_id).is_some_and(|context| {
                context.subject_key == subject.key()
                    && context.revoked
                    && context.tombstone_until_ms > now_unix_ms()
            }) {
                outcome = Some(Ok(json!({
                    "context_id": context_id,
                    "revoked": true,
                    "raw_content_retained": false,
                })));
            }
        }
        if let Some(Ok(value)) = &outcome
            && method == "save_memory"
        {
            let memory_id = value
                .get("memory_id")
                .and_then(Value::as_str)
                .context("saved_memory_replay_missing_memory_id")?;
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            let memory = state
                .store
                .memories
                .iter()
                .find(|memory| memory.memory_id == memory_id && memory.owned_by(subject))
                .context("saved_memory_replay_resource_no_longer_available")?;
            if value.get("payload_sha256").and_then(Value::as_str)
                != Some(memory.payload_sha256.as_str())
                || value.get("updated_at_ms").and_then(Value::as_u64) != Some(memory.updated_at_ms)
            {
                bail!("saved_memory_replay_binding_changed");
            }
        }
        Ok(outcome)
    }

    fn ensure_store_publication_certain(&self) -> Result<()> {
        if self
            .store_publication_durability_uncertain
            .load(AtomicOrdering::Acquire)
        {
            bail!("context_memory_store_fail_stop_published_durability_uncertain_reopen_required");
        }
        Ok(())
    }

    fn validate_method_aware_call_replay(
        &self,
        method: &str,
        request_id: &str,
        request_payload_sha256: &str,
        subject: &Subject,
        outcome: std::result::Result<Value, String>,
    ) -> Result<std::result::Result<Value, String>> {
        let Ok(result) = &outcome else {
            return Ok(outcome);
        };
        if method != "save_memory" {
            return Ok(outcome);
        }
        let memory_id = result
            .get("memory_id")
            .and_then(Value::as_str)
            .context("memory_save_replay_result_memory_id_missing")?;
        validate_resource_id(memory_id, "memory-")?;
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        let Some(memory) = state
            .store
            .memories
            .iter()
            .find(|memory| memory.memory_id == memory_id && memory.owned_by(subject))
        else {
            return Ok(Err(
                "memory_save_result_invalidated_no_reexecution".to_string()
            ));
        };
        if memory.public_json() != *result {
            bail!("memory_save_replay_result_binding_denied");
        }
        if let Some(tombstone) = state
            .store
            .memory_saves
            .iter()
            .find(|item| item.request_id == request_id && item.subject_key == subject.key())
            && (tombstone.request_payload_sha256 != request_payload_sha256
                || tombstone.memory_id != memory_id
                || tombstone.result != *result)
        {
            bail!("memory_save_replay_tombstone_binding_denied");
        }
        Ok(outcome)
    }

    pub(super) fn run_ui_request<F>(
        &self,
        method: &str,
        request_id: &str,
        subject: &Subject,
        payload: &Value,
        operation: F,
    ) -> Result<Value>
    where
        F: FnOnce() -> Result<Value>,
    {
        self.run_ui_request_with_preflight(
            method,
            request_id,
            subject,
            payload,
            || Ok(()),
            |()| operation(),
        )
    }

    /// Run a UI request with a retry-safe, non-consuming authentication phase.
    ///
    /// Completed requests are replayed before authentication because their
    /// single-use capability may already be consumed.  A new replay record is
    /// created only after `preflight` succeeds, and the record is rechecked
    /// under the serial lock after preflight so concurrent valid requests can
    /// never both execute.  `preflight` must only authenticate immutable input;
    /// resource consumption and side effects belong in `operation`.
    pub(super) fn run_ui_request_with_preflight<P, O, T>(
        &self,
        method: &str,
        request_id: &str,
        subject: &Subject,
        payload: &Value,
        preflight: P,
        operation: O,
    ) -> Result<Value>
    where
        P: FnOnce() -> Result<T>,
        O: FnOnce(T) -> Result<Value>,
    {
        self.run_ui_request_with_preflight_and_recovery(
            UiRequestBinding {
                method,
                request_id,
                subject,
                payload,
            },
            || Ok(UiRequestRecovery::Unresolved),
            preflight,
            operation,
        )
    }

    /// Recover an exact request from an already durable downstream outcome.
    ///
    /// `recovery` is query-only: it must never dispatch the requested
    /// operation. It runs only after an exact durable `in_progress` record has
    /// matched method, request id, authenticated subject and payload digest.
    /// A recovered result is encrypted and committed as the original replay
    /// outcome before being returned.
    pub(super) fn run_ui_request_with_preflight_and_recovery<R, P, O, T>(
        &self,
        request: UiRequestBinding<'_>,
        recovery: R,
        preflight: P,
        operation: O,
    ) -> Result<Value>
    where
        R: Fn() -> Result<UiRequestRecovery>,
        P: FnOnce() -> Result<T>,
        O: FnOnce(T) -> Result<Value>,
    {
        let UiRequestBinding {
            method,
            request_id,
            subject,
            payload,
        } = request;
        if self
            .ui_replay_publication_durability_uncertain
            .load(AtomicOrdering::Acquire)
        {
            bail!("ui_replay_fail_stop_published_durability_uncertain");
        }
        validate_request_id(request_id)?;
        let payload_bytes = Zeroizing::new(serde_json::to_vec(payload)?);
        let payload_sha256 = sha256_bytes(payload_bytes.as_slice());
        let request_hash = sha256_bytes(request_id.as_bytes());
        let record_path = self.ui_replay_root.join(format!("{request_hash}.json"));
        let outcome_file = format!("{request_hash}.enc");
        let outcome_path = self.ui_replay_outcome_root.join(&outcome_file);
        let aad = ui_replay_associated_data(subject, method, request_id, &payload_sha256);
        let persist_outcome = |outcome: &Result<Value>| -> Result<()> {
            let envelope = durable_ui_replay_envelope(method, payload, outcome);
            validate_canonical_ui_replay_envelope(method, &envelope)?;
            let mut record = load_ui_replay_record(&record_path)?;
            validate_ui_replay_identity(&record, method, request_id, subject, &payload_sha256)?;
            if record.state == "completed" {
                if record.outcome_file != outcome_file {
                    bail!("ui_replay_completion_reference_mismatch");
                }
                let (_, existing) = self.verify_completed_ui_replay_pair(&record)?;
                if existing != envelope {
                    bail!("ui_replay_recovered_outcome_mismatch");
                }
                return Ok(());
            }
            if record.state != "in_progress" {
                bail!("ui_replay_completion_state_mismatch");
            }
            let (outcome_ciphertext_sha256, outcome_semantic_sha256) =
                if private_entry_exists(&outcome_path)? {
                    // A predecessor published the outcome but not the record.
                    // Preserve the authoritative ciphertext byte-for-byte and
                    // require the query-only downstream recovery to agree with
                    // its canonical semantic envelope.
                    let (existing_bytes, existing_envelope) =
                        self.decrypt_and_validate_ui_replay_outcome(&record)?;
                    if existing_envelope != envelope {
                        bail!("ui_replay_existing_outcome_semantic_mismatch");
                    }
                    (
                        sha256_bytes(&existing_bytes),
                        sha256_json(&existing_envelope),
                    )
                } else {
                    let mut clear = Zeroizing::new(serde_json::to_vec(&envelope)?);
                    if clear.len() > MAX_UI_REPLAY_OUTCOME_BYTES {
                        clear.zeroize();
                        bail!("ui_replay_outcome_too_large");
                    }
                    let encrypted = encrypt_payload(&self.key, &aad, clear.as_slice())?;
                    let ciphertext_sha256 = sha256_bytes(&encrypted);
                    let semantic_sha256 = sha256_json(&envelope);
                    clear.zeroize();
                    if atomic_write_private_staged(&outcome_path, &encrypted)?
                        == PrivatePublishState::PublishedDurabilityUncertain
                    {
                        self.ui_replay_publication_durability_uncertain
                            .store(true, AtomicOrdering::Release);
                        // Startup completes the visible candidate pair before
                        // any downstream query; this instance fails stop.
                        bail!("ui_replay_outcome_commit_unknown_parent_fsync_uncertain");
                    }
                    (ciphertext_sha256, semantic_sha256)
                };
            record.state = "completed".to_string();
            record.outcome_file = outcome_file.clone();
            record.outcome_ciphertext_sha256 = outcome_ciphertext_sha256;
            record.outcome_semantic_sha256 = outcome_semantic_sha256;
            record.custody_handoff_ack = None;
            if atomic_write_private_staged(&record_path, &serde_json::to_vec_pretty(&record)?)?
                == PrivatePublishState::PublishedDurabilityUncertain
            {
                self.ui_replay_publication_durability_uncertain
                    .store(true, AtomicOrdering::Release);
                bail!("ui_replay_completion_commit_unknown_parent_fsync_uncertain");
            }
            Ok(())
        };
        let replay_existing = || -> Result<Option<Value>> {
            if !private_entry_exists(&record_path)? {
                return Ok(None);
            }
            let record = load_ui_replay_record(&record_path)?;
            validate_ui_replay_identity(&record, method, request_id, subject, &payload_sha256)?;
            if record.state == "in_progress" {
                let recovered = match recovery()? {
                    UiRequestRecovery::Unresolved => {
                        bail!("ui_request_outcome_indeterminate_no_reexecution")
                    }
                    UiRequestRecovery::Outcome(Ok(value)) => Ok(value),
                    UiRequestRecovery::Outcome(Err(error)) => Err(anyhow::Error::msg(error)),
                };
                persist_outcome(&recovered)?;
                return recovered.map(Some);
            }
            if record.state != "completed" || record.outcome_file != outcome_file {
                bail!("invalid_ui_replay_state");
            }
            let (_, envelope) = self.verify_completed_ui_replay_pair(&record)?;
            let decoded = decode_ui_replay_outcome(&envelope)?;
            self.validate_replayed_ui_outcome(method, subject, &decoded)?;
            Ok(Some(decoded))
        };

        // Fast replay happens before preflight: a successful single-use
        // receipt cannot be authenticated again after its capability is gone.
        {
            let _guard = self
                .ui_replay_serial
                .lock()
                .map_err(|_| anyhow::anyhow!("ui_replay_lock_poisoned"))?;
            self.prune_ui_replays_locked()?;
            self.reject_archived_ui_request_id(request_id)?;
            if let Some(replayed) = replay_existing()? {
                return Ok(replayed);
            }
        }

        // Signature, key pin, caller, boot, task and immutable-plan binding
        // checks happen here.  An error leaves no replay tombstone.
        let validated = preflight()?;

        {
            let _guard = self
                .ui_replay_serial
                .lock()
                .map_err(|_| anyhow::anyhow!("ui_replay_lock_poisoned"))?;
            self.prune_ui_replays_locked()?;
            self.reject_archived_ui_request_id(request_id)?;
            // Another valid request may have completed while preflight ran.
            if let Some(replayed) = replay_existing()? {
                return Ok(replayed);
            }
            open_private_directory(&self.ui_replay_root)?;
            let record_count = fs::read_dir(&self.ui_replay_root)?.count();
            if record_count >= MAX_REPLAY_RECORDS {
                bail!("ui_replay_capacity_reached");
            }
            let record = UiReplayRecord {
                schema: UI_REPLAY_SCHEMA.to_string(),
                policy_epoch: UI_REPLAY_POLICY_EPOCH,
                provider_abi_epoch: UI_REPLAY_PROVIDER_ABI_EPOCH,
                request_id: request_id.to_string(),
                method: method.to_string(),
                subject_key: subject.key(),
                payload_sha256: payload_sha256.clone(),
                state: "in_progress".to_string(),
                recorded_at_ms: now_unix_ms(),
                outcome_file: String::new(),
                outcome_ciphertext_sha256: String::new(),
                outcome_semantic_sha256: String::new(),
                custody_handoff_ack: None,
            };
            if atomic_write_private_staged(&record_path, &serde_json::to_vec_pretty(&record)?)?
                == PrivatePublishState::PublishedDurabilityUncertain
            {
                self.ui_replay_publication_durability_uncertain
                    .store(true, AtomicOrdering::Release);
                // The in-progress tombstone is visible, but dispatch has not
                // happened. Return HOLD/commit-unknown; exact retry is
                // recovery-only and therefore cannot create a new side effect.
                bail!("ui_replay_begin_commit_unknown_parent_fsync_uncertain");
            }
        }

        let outcome = operation(validated);
        {
            let _guard = self
                .ui_replay_serial
                .lock()
                .map_err(|_| anyhow::anyhow!("ui_replay_lock_poisoned"))?;
            persist_outcome(&outcome)?;
        }
        outcome
    }

    fn validate_replayed_ui_outcome(
        &self,
        method: &str,
        subject: &Subject,
        outcome: &Value,
    ) -> Result<()> {
        if !matches!(
            method,
            "get_context"
                | "select_memory_context"
                | "recover_context_capture"
                | "recover_memory_context"
        ) {
            return Ok(());
        }
        let context_id = outcome
            .get("context_id")
            .and_then(Value::as_str)
            .context("ui_replay_context_result_missing_context_id")?;
        let current = self
            .context_metadata_exact(subject, context_id)
            .context("ui_replay_context_handle_invalidated_no_success")?;
        for field in [
            "context_id",
            "source_id",
            "source_kind",
            "captured_at_ms",
            "expires_at_ms",
            "privacy_class",
            "content_sha256",
            "content_bytes",
            "capture_id",
            "capture_receipt_id",
        ] {
            if outcome.get(field) != current.get(field) {
                bail!("ui_replay_context_metadata_changed_no_success");
            }
        }
        if outcome
            .get("raw_content_persisted")
            .and_then(Value::as_bool)
            != Some(false)
            || outcome
                .get("raw_cleartext_persisted")
                .and_then(Value::as_bool)
                != Some(false)
            || outcome
                .get("encrypted_context_payload_persisted")
                .and_then(Value::as_bool)
                != Some(true)
        {
            bail!("ui_replay_context_storage_flags_invalid");
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn describe_execution_payload(
        &self,
        url: &str,
    ) -> Result<ExecutionPayloadDescriptor> {
        let canonical = canonical_https_execution_url(url)?;
        if canonical != url {
            bail!("execution_payload_noncanonical_https_url_denied");
        }
        #[derive(Serialize)]
        struct UrlPayload<'a> {
            url: &'a str,
        }
        let encoded = Zeroizing::new(serde_json::to_vec(&UrlPayload { url })?);
        let mut nonce = [0u8; 32];
        fill_kernel_random(&mut nonce)?;
        Ok(ExecutionPayloadDescriptor {
            reference: format!("execution-payload-{}", sha256_bytes(&nonce)),
            payload_sha256: sha256_bytes(encoded.as_slice()),
            shape: EXECUTION_PAYLOAD_SHAPE.to_string(),
        })
    }

    #[cfg(test)]
    pub(super) fn stage_execution_payload(
        &self,
        descriptor: &ExecutionPayloadDescriptor,
        binding: ExecutionPayloadBinding,
        url: &str,
    ) -> Result<()> {
        validate_execution_payload_reference(&descriptor.reference)?;
        if descriptor.shape != EXECUTION_PAYLOAD_SHAPE
            || !valid_lower_sha256(&descriptor.payload_sha256)
            || !valid_lower_sha256(&binding.context_sha256)
            || !valid_lower_sha256(&binding.arguments_sha256)
            || !valid_lower_sha256(&binding.agent_executable_sha256)
            || !valid_lower_sha256(&binding.tool_manifest_sha256)
            || !valid_lower_sha256(&binding.accepted_plan_sha256)
            || binding.owner_uid < 10_000
            || binding.owner_selinux_domain.is_empty()
            || binding.agent_id.is_empty()
            || binding.agent_selinux_domain.is_empty()
            || binding.task_id.is_empty()
            || binding.session_id.is_empty()
            || binding.plan_id.is_empty()
            || binding.action_id.is_empty()
            || binding.tool_call_id.is_empty()
            || binding.tool_name.is_empty()
        {
            bail!("invalid_execution_payload_binding");
        }
        let described = self.describe_execution_payload(url)?;
        if described.payload_sha256 != descriptor.payload_sha256
            || sha256_bytes(url.as_bytes()) != binding.context_sha256
        {
            bail!("execution_payload_digest_mismatch");
        }
        let now = now_unix_ms();
        if binding.expires_at_ms <= now
            || binding.expires_at_ms > now.saturating_add(MAX_EXECUTION_PAYLOAD_TTL_MS)
        {
            bail!("invalid_execution_payload_expiry");
        }
        let _guard = self
            .execution_payload_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("execution_payload_lock_poisoned"))?;
        self.prune_execution_payloads_locked(now)?;
        open_private_directory(&self.execution_payload_root)?;
        let path = execution_payload_path(&self.execution_payload_root, &descriptor.reference)?;
        let existing = if private_entry_exists(&path)? {
            Some(self.read_execution_payload_record(&path, &descriptor.reference)?)
        } else {
            None
        };
        if existing.is_none()
            && fs::read_dir(&self.execution_payload_root)?.count() >= MAX_EXECUTION_PAYLOADS
        {
            bail!("execution_payload_store_full");
        }
        let record = StoredExecutionPayload {
            schema: EXECUTION_PAYLOAD_SCHEMA.to_string(),
            reference: descriptor.reference.clone(),
            payload_sha256: descriptor.payload_sha256.clone(),
            shape: descriptor.shape.clone(),
            owner_uid: binding.owner_uid,
            owner_selinux_domain: binding.owner_selinux_domain,
            subject_user_id: binding.subject_user_id,
            agent_id: binding.agent_id,
            agent_peer_uid: binding.agent_peer_uid,
            agent_peer_gid: binding.agent_peer_gid,
            agent_selinux_domain: binding.agent_selinux_domain,
            agent_executable_sha256: binding.agent_executable_sha256,
            task_id: binding.task_id,
            session_id: binding.session_id,
            plan_id: binding.plan_id,
            action_id: binding.action_id,
            tool_call_id: binding.tool_call_id,
            tool_name: binding.tool_name,
            tool_manifest_sha256: binding.tool_manifest_sha256,
            accepted_plan_sha256: binding.accepted_plan_sha256,
            context_sha256: binding.context_sha256,
            arguments_sha256: binding.arguments_sha256,
            created_at_ms: existing.as_ref().map_or(now, |value| value.created_at_ms),
            expires_at_ms: binding.expires_at_ms,
            url: url.to_string(),
        };
        if let Some(existing) = existing {
            if existing == record {
                return Ok(());
            }
            bail!("execution_payload_reference_reused_with_different_binding");
        }
        let clear = Zeroizing::new(serde_json::to_vec(&record)?);
        if clear.len() > MAX_EXECUTION_PAYLOAD_CLEAR_BYTES {
            bail!("execution_payload_cleartext_too_large");
        }
        let aad = execution_payload_aad(&descriptor.reference);
        let encrypted = encrypt_payload(&self.key, aad.as_bytes(), clear.as_slice())?;
        if encrypted.len() > MAX_EXECUTION_PAYLOAD_FILE_BYTES {
            bail!("execution_payload_envelope_too_large");
        }
        atomic_write_private(&path, &encrypted)
    }

    fn prune_execution_payloads(&self, now: u64) -> Result<()> {
        let _guard = self
            .execution_payload_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("execution_payload_lock_poisoned"))?;
        self.prune_execution_payloads_locked(now)
    }

    fn prune_execution_payloads_locked(&self, now: u64) -> Result<()> {
        // A locked subject is not an integrity failure. Refuse the scan before
        // touching any protected entry, and re-check before quarantining an
        // entry so a custody denial can never be mistaken for corruption.
        self.require_memory_key_unlocked()?;
        open_private_directory(&self.execution_payload_root)?;
        for entry in fs::read_dir(&self.execution_payload_root)? {
            let path = entry?.path();
            match self.inspect_execution_payload_entry(&path, now) {
                Ok(true) => remove_private_regular_file(&path, false)?,
                Ok(false) => {}
                Err(_) => {
                    self.require_memory_key_unlocked()?;
                    self.quarantine_invalid_execution_payload_entry(&path, now)?;
                }
            }
        }
        open_private_directory(&self.execution_payload_root)?.sync_all()?;
        Ok(())
    }

    fn inspect_execution_payload_entry(&self, path: &Path, now: u64) -> Result<bool> {
        let reference = path
            .file_name()
            .and_then(|value| value.to_str())
            .and_then(|value| value.strip_suffix(".enc"))
            .context("invalid_execution_payload_store_filename")?;
        validate_execution_payload_reference(reference)?;
        let record = self.read_execution_payload_record(path, reference)?;
        validate_stored_execution_payload(&record, reference)?;
        Ok(record.expires_at_ms <= now)
    }

    fn read_execution_payload_record(
        &self,
        path: &Path,
        reference: &str,
    ) -> Result<StoredExecutionPayload> {
        let encrypted = read_private_bounded_file(path, MAX_EXECUTION_PAYLOAD_FILE_BYTES)?;
        let clear = self.decrypt_custody_gated(
            execution_payload_aad(reference).as_bytes(),
            &encrypted,
            MAX_EXECUTION_PAYLOAD_CLEAR_BYTES,
        )?;
        serde_json::from_slice(clear.as_slice()).context("invalid_encrypted_execution_payload")
    }

    fn quarantine_invalid_execution_payload_entry(&self, path: &Path, now: u64) -> Result<()> {
        let mut nonce = [0u8; 32];
        fill_kernel_random(&mut nonce)?;
        let quarantine_path = self
            .execution_payload_quarantine_root
            .join(format!("invalid-entry-{}", sha256_bytes(&nonce)));
        rename_private_entry(path, &quarantine_path)?;
        self.record_execution_payload_integrity_event(now)?;
        self.prune_execution_payload_quarantine()?;
        Ok(())
    }

    fn record_execution_payload_integrity_event(&self, now: u64) -> Result<()> {
        let path = self.root.join("execution-payload-integrity.json");
        let total_events = if private_entry_exists(&path)? {
            read_private_bounded_file(&path, 4 * 1024)
                .ok()
                .and_then(|encoded| {
                    serde_json::from_slice::<ExecutionPayloadIntegrityState>(&encoded).ok()
                })
                .filter(|state| {
                    state.schema == EXECUTION_PAYLOAD_INTEGRITY_SCHEMA
                        && state.event_code == EXECUTION_PAYLOAD_INVALID_ENTRY_EVENT
                })
                .map(|state| state.total_events)
                .unwrap_or(0)
        } else {
            0
        };
        let state = ExecutionPayloadIntegrityState {
            schema: EXECUTION_PAYLOAD_INTEGRITY_SCHEMA.to_string(),
            event_code: EXECUTION_PAYLOAD_INVALID_ENTRY_EVENT.to_string(),
            total_events: total_events.saturating_add(1),
            last_event_at_ms: now,
        };
        atomic_write_private(&path, &serde_json::to_vec_pretty(&state)?)
    }

    fn prune_execution_payload_quarantine(&self) -> Result<()> {
        let parent = open_private_directory(&self.execution_payload_quarantine_root)?;
        let mut entries = fs::read_dir(&self.execution_payload_quarantine_root)?
            .filter_map(std::result::Result::ok)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        let remove_count = entries
            .len()
            .saturating_sub(MAX_EXECUTION_PAYLOAD_QUARANTINE_ENTRIES);
        for entry in entries.into_iter().take(remove_count) {
            let name = CString::new(entry.file_name().as_bytes())?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let stat = unsafe { stat.assume_init() };
            let flags = if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                libc::AT_REMOVEDIR
            } else {
                0
            };
            if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        parent.sync_all()?;
        Ok(())
    }

    fn prune_ui_replays_locked(&self) -> Result<()> {
        let cutoff = now_unix_ms().saturating_sub(REPLAY_RETENTION_MS);
        open_private_directory(&self.ui_replay_root)?;
        cleanup_private_atomic_temps(&self.ui_replay_root, |destination| {
            is_ui_replay_record_file_name(destination).then_some(STORE_FILE_MAX_BYTES)
        })?;
        cleanup_private_atomic_temps(&self.ui_replay_outcome_root, |destination| {
            is_ui_replay_outcome_file_name(destination)
                .then_some((MAX_UI_REPLAY_OUTCOME_BYTES + 128) as u64)
        })?;
        let mut expired = Vec::new();
        for entry in fs::read_dir(&self.ui_replay_root)? {
            let path = entry?.path();
            let record = load_ui_replay_record(&path)?;
            if record.recorded_at_ms < cutoff {
                if record.state == "completed" {
                    if record.schema != UI_REPLAY_SCHEMA {
                        if ui_replay_method_requires_custody_handoff(&record.method) {
                            // Legacy records have no typed proof/handoff and
                            // therefore retain their outcome indefinitely.
                            continue;
                        }
                    } else {
                        let (proof, envelope) = self.verify_completed_ui_replay_pair(&record)?;
                        if ui_replay_method_requires_custody_handoff(&record.method) {
                            let Some(ack) = record.custody_handoff_ack.as_ref() else {
                                continue;
                            };
                            validate_ui_replay_handoff_against_pair(
                                &record, &proof, &envelope, ack,
                            )?;
                        }
                    }
                }
                expired.push((path, record));
            }
        }
        if expired.is_empty() {
            return Ok(());
        }

        // Archive every request ID in one monotonic checkpoint before deleting
        // any hot record or encrypted outcome. If the finite Bloom archive has
        // reached its density limit, persistence fails and every hot record is
        // retained, making capacity exhaustion permanently fail closed.
        {
            let mut archive = self
                .ui_replay_archive
                .lock()
                .map_err(|_| anyhow::anyhow!("ui_replay_archive_lock_poisoned"))?;
            let mut next = archive.clone();
            for (_, record) in &expired {
                next.insert_request_id(&record.request_id)?;
            }
            persist_ui_replay_archive(&self.ui_replay_archive_path, &next)?;
            *archive = next;
        }

        for (path, record) in expired {
            remove_private_regular_file(&path, false)?;
            if !record.outcome_file.is_empty() {
                remove_replay_outcome_if_present(
                    &self.ui_replay_outcome_root,
                    &record.outcome_file,
                )?;
            }
        }
        Ok(())
    }

    fn reject_archived_ui_request_id(&self, request_id: &str) -> Result<()> {
        let archive = self
            .ui_replay_archive
            .lock()
            .map_err(|_| anyhow::anyhow!("ui_replay_archive_lock_poisoned"))?;
        if archive.contains_request_id(request_id) {
            bail!("ui_request_id_archived_no_reexecution");
        }
        Ok(())
    }

    pub(super) fn resolve_context(
        &self,
        subject: &Subject,
        context_id: &str,
    ) -> Result<ContextSnapshot> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_operation_lock_poisoned"))?;
        self.cleanup()?;
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        let context = state
            .contexts
            .get(context_id)
            .context("unknown_or_expired_context_handle")?;
        if context.subject_key != subject.key() {
            bail!("context_subject_binding_mismatch");
        }
        if context.boot_id_sha256 != self.boot_id_sha256
            || context.revoked
            || context.expires_at_ms <= now_unix_ms()
            || !matches!(
                context.authority_import_state.as_str(),
                "imported" | "local_only"
            )
        {
            bail!("context_handle_not_durably_available");
        }
        Ok(ContextSnapshot {
            source_id: context.source_id.clone(),
            source_kind: context.source_kind.clone(),
            captured_at_ms: context.captured_at_ms,
            expires_at_ms: context.expires_at_ms,
            privacy_class: context.privacy_class.clone(),
            content_sha256: context.content_sha256.clone(),
            content: context.content.clone(),
        })
    }

    fn context_metadata_exact(&self, subject: &Subject, context_id: &str) -> Result<Value> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        let context = state
            .contexts
            .get(context_id)
            .context("unknown_or_expired_context_handle")?;
        if context.subject_key != subject.key()
            || context.boot_id_sha256 != self.boot_id_sha256
            || context.revoked
            || context.expires_at_ms <= now_unix_ms()
            || !matches!(
                context.authority_import_state.as_str(),
                "imported" | "local_only"
            )
        {
            bail!("context_handle_not_durably_available");
        }
        Ok(context.metadata())
    }

    pub(super) fn recover_imported_context_exact(
        &self,
        subject: &Subject,
        original_request_id: &str,
        capture_id: &str,
        capture_receipt_id: &str,
        resolution_sha256: &str,
    ) -> Result<Option<Value>> {
        validate_request_id(original_request_id)?;
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        let mut matches = state.contexts.values().filter(|context| {
            context.subject_key == subject.key()
                && context.origin_method == "get_context"
                && context.origin_request_id == original_request_id
                && context.capture_id == capture_id
                && context.capture_receipt_id == capture_receipt_id
                && context.resolution_sha256 == resolution_sha256
                && context.authority_import_state == "imported"
                && context.boot_id_sha256 == self.boot_id_sha256
                && !context.revoked
                && context.expires_at_ms > now_unix_ms()
        });
        let result = matches.next().map(StoredContext::metadata);
        if matches.next().is_some() {
            bail!("ambiguous_context_capture_import_binding");
        }
        Ok(result)
    }

    pub(super) fn context_import_candidate_exact(
        &self,
        subject: &Subject,
        original_request_id: &str,
        capture_id: &str,
        capture_receipt_id: &str,
        resolution_sha256: &str,
    ) -> Result<Option<(String, String, Value)>> {
        validate_request_id(original_request_id)?;
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        let mut matches = state.contexts.values().filter(|context| {
            context.subject_key == subject.key()
                && context.origin_method == "get_context"
                && context.origin_request_id == original_request_id
                && context.capture_id == capture_id
                && context.capture_receipt_id == capture_receipt_id
                && context.resolution_sha256 == resolution_sha256
                && context.boot_id_sha256 == self.boot_id_sha256
                && !context.revoked
                && context.expires_at_ms > now_unix_ms()
        });
        let result = matches.next().map(|context| {
            (
                context.context_id.clone(),
                context.authority_import_state.clone(),
                context.metadata(),
            )
        });
        if matches.next().is_some() {
            bail!("ambiguous_context_capture_import_binding");
        }
        Ok(result)
    }

    pub(super) fn recover_memory_context_exact(
        &self,
        subject: &Subject,
        original_request_id: &str,
        memory_id: &str,
        expected_payload_sha256: &str,
        expected_updated_at_ms: u64,
    ) -> Result<Option<Value>> {
        validate_request_id(original_request_id)?;
        validate_resource_id(memory_id, "memory-")?;
        if !is_lower_hex(expected_payload_sha256, 64) || expected_updated_at_ms == 0 {
            bail!("memory_context_recovery_cas_binding_denied");
        }
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        let mut matches = state.contexts.values().filter(|context| {
            context.subject_key == subject.key()
                && context.origin_method == "select_memory_context"
                && context.origin_request_id == original_request_id
                && context.parent_memory_id == memory_id
                && context.parent_memory_payload_sha256 == expected_payload_sha256
                && context.parent_memory_updated_at_ms == expected_updated_at_ms
                && context.authority_import_state == "local_only"
                && context.boot_id_sha256 == self.boot_id_sha256
                && !context.revoked
                && context.expires_at_ms > now_unix_ms()
        });
        let result = matches.next().map(StoredContext::metadata);
        if matches.next().is_some() {
            bail!("ambiguous_memory_context_recovery_binding");
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn reserve_context_import_capacity(
        &self,
        subject: &Subject,
        origin_request_id: &str,
        capture_id: &str,
        capture_receipt_id: &str,
        capture_request_id: &str,
        source_id: &str,
        source_kind: &str,
        content_sha256: &str,
        expires_at_ms: u64,
    ) -> Result<()> {
        validate_request_id(origin_request_id)?;
        validate_request_id(capture_request_id)?;
        if !capture_id
            .strip_prefix("capture-")
            .is_some_and(valid_lower_sha256)
            || !is_lower_hex(capture_receipt_id, 64)
            || source_id.is_empty()
            || source_id.len() > MAX_SOURCE_ID_BYTES
            || !matches!(source_kind, "file" | "browser")
            || !is_lower_hex(content_sha256, 64)
            || expires_at_ms <= now_unix_ms()
        {
            bail!("context_import_capacity_reservation_binding_denied");
        }
        let _serial = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_operation_lock_poisoned"))?;
        self.cleanup()?;
        let now = now_unix_ms();
        if expires_at_ms <= now || expires_at_ms.saturating_sub(now) > MAX_CONTEXT_TTL_MS {
            bail!("context_import_capacity_reservation_expiry_denied");
        }
        let subject_key = subject.key();
        let reservation_id = context_import_reservation_id(
            &self.boot_id_sha256,
            &subject_key,
            origin_request_id,
            capture_id,
            capture_receipt_id,
            capture_request_id,
            source_id,
            content_sha256,
        );
        let reservation = ContextImportReservation {
            schema: CONTEXT_IMPORT_RESERVATION_SCHEMA.to_string(),
            reservation_id: reservation_id.clone(),
            subject_key: subject_key.clone(),
            owner_uid: subject.uid,
            owner_selinux_domain: subject.selinux_domain.clone(),
            subject_user_id: subject.uid / 100_000,
            boot_id_sha256: self.boot_id_sha256.clone(),
            origin_request_id: origin_request_id.to_string(),
            capture_id: capture_id.to_string(),
            capture_receipt_id: capture_receipt_id.to_string(),
            capture_request_id: capture_request_id.to_string(),
            source_id: source_id.to_string(),
            source_kind: source_kind.to_string(),
            content_sha256: content_sha256.to_string(),
            expires_at_ms,
            reserved_at_ms: now,
        };
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            if let Some(existing) = state.context_import_reservations.get(&reservation_id) {
                if existing == &reservation
                    || existing.subject_key == reservation.subject_key
                        && existing.origin_request_id == reservation.origin_request_id
                        && existing.capture_id == reservation.capture_id
                        && existing.capture_receipt_id == reservation.capture_receipt_id
                        && existing.capture_request_id == reservation.capture_request_id
                        && existing.source_id == reservation.source_id
                        && existing.source_kind == reservation.source_kind
                        && existing.content_sha256 == reservation.content_sha256
                        && existing.expires_at_ms == reservation.expires_at_ms
                {
                    return Ok(());
                }
                bail!("context_import_capacity_reservation_substitution_denied");
            }
            if state.context_import_reservations.values().any(|existing| {
                existing.subject_key == subject_key
                    && (existing.origin_request_id == origin_request_id
                        || existing.capture_id == capture_id
                            && existing.capture_receipt_id == capture_receipt_id)
            }) {
                bail!("context_import_capacity_reservation_substitution_denied");
            }
            if state.contexts.values().any(|context| {
                context.subject_key == subject_key
                    && context.origin_method == "get_context"
                    && context.origin_request_id == origin_request_id
                    && context.capture_id == capture_id
                    && context.capture_receipt_id == capture_receipt_id
                    && context.source_id == source_id
                    && context.source_kind == source_kind
                    && context.content_sha256 == content_sha256
                    && context.boot_id_sha256 == self.boot_id_sha256
                    && !context.revoked
            }) {
                return Ok(());
            }
            if context_capacity_used(&state) >= MAX_CONTEXTS {
                bail!("context_handle_capacity_reached_before_authority_consume");
            }
            state
                .context_import_reservations
                .insert(reservation_id.clone(), reservation.clone());
        }
        if let Err(error) = self.persist_context_journal() {
            if !self.context_journal_publication_is_uncertain() {
                self.state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?
                    .context_import_reservations
                    .remove(&reservation_id);
            }
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn insert_verified_context(
        &self,
        subject: &Subject,
        capture: VerifiedContextCapture,
    ) -> Result<Value> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_operation_lock_poisoned"))?;
        self.cleanup()?;
        self.store_verified_context(subject, capture, true)
    }

    /// Materialize one explicitly selected, OS-custodied Memory as a bounded
    /// planning Context. The returned metadata contains only an opaque
    /// Memory reference; the caller-supplied durable Memory ID and cleartext
    /// payload never cross this API boundary.
    // This is exposed only through the authenticated, user-0 Android UI
    // selection route; never expose it through the generic Memory RPC.
    #[cfg(test)]
    pub(super) fn materialize_memory_planning_context(
        &self,
        subject: &Subject,
        memory_id: &str,
    ) -> Result<Value> {
        let mut nonce = [0u8; 16];
        fill_kernel_random(&mut nonce)?;
        let request_id = format!("test-memory-selection-{}", &sha256_bytes(&nonce)[..32]);
        let (payload_sha256, updated_at_ms) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            let memory = state
                .store
                .memories
                .iter()
                .find(|item| item.memory_id == memory_id && item.owned_by(subject))
                .context("unknown_or_unavailable_memory_selection")?;
            (memory.payload_sha256.clone(), memory.updated_at_ms)
        };
        self.materialize_memory_planning_context_for_request(
            subject,
            &request_id,
            memory_id,
            &payload_sha256,
            updated_at_ms,
        )
    }

    pub(super) fn materialize_memory_planning_context_for_request(
        &self,
        subject: &Subject,
        request_id: &str,
        memory_id: &str,
        expected_payload_sha256: &str,
        expected_updated_at_ms: u64,
    ) -> Result<Value> {
        validate_request_id(request_id)?;
        validate_resource_id(memory_id, "memory-")?;
        if !is_lower_hex(expected_payload_sha256, 64) || expected_updated_at_ms == 0 {
            bail!("memory_selection_cas_binding_denied");
        }
        let _serial = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_operation_lock_poisoned"))?;
        self.cleanup()?;

        let memory = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            if context_capacity_used(&state) >= MAX_CONTEXTS {
                bail!("context_handle_capacity_reached");
            }
            state
                .store
                .memories
                .iter()
                .find(|item| item.memory_id == memory_id && item.owned_by(subject))
                .cloned()
                .context("unknown_or_unavailable_memory_selection")?
        };
        if memory.payload_sha256 != expected_payload_sha256
            || memory.updated_at_ms != expected_updated_at_ms
        {
            bail!("memory_selection_cas_changed");
        }
        let now_before_read = now_unix_ms();
        if memory.retention_until_ms <= now_before_read {
            bail!("memory_retention_expired");
        }

        let encrypted = read_private_bounded_file(
            &self.payload_root.join(&memory.payload_file),
            MAX_CONTEXT_BYTES * 2 + 256,
        )?;
        let associated_data = memory_associated_data(subject, &memory.memory_id);
        let clear = self.decrypt_custody_gated(&associated_data, &encrypted, MAX_CONTEXT_BYTES)?;
        if clear.is_empty()
            || clear.len() != memory.payload_bytes
            || sha256_bytes(clear.as_slice()) != memory.payload_sha256
        {
            bail!("memory_planning_context_payload_integrity_mismatch");
        }
        let clear_text = std::str::from_utf8(clear.as_slice())
            .map_err(|_| anyhow::anyhow!("memory_planning_context_payload_not_utf8"))?;
        let mut content = Zeroizing::new(clear_text.to_owned());
        if content.len() > MAX_CONTEXT_BYTES {
            bail!("memory_planning_context_payload_outside_bounded_contract");
        }

        // Re-read time after custody and payload verification so a Memory
        // that expires during decryption can never mint a fresh Context.
        let captured_at_ms = now_unix_ms();
        if memory.retention_until_ms <= captured_at_ms {
            bail!("memory_retention_expired");
        }
        let expires_at_ms = captured_at_ms
            .saturating_add(MAX_MEMORY_PLANNING_CONTEXT_TTL_MS)
            .min(memory.retention_until_ms);
        if expires_at_ms <= captured_at_ms {
            bail!("memory_planning_context_ttl_exhausted");
        }

        let subject_key = subject.key();
        let memory_ref = sha256_bytes(
            format!(
                "trillionnium-memory-planning-context-ref-v1\nsubject={subject_key}\nmemory_id={}\n",
                memory.memory_id
            )
            .as_bytes(),
        );
        let source_id = format!("memory-ref:{memory_ref}");
        let context_id = format!(
            "context-{}",
            sha256_bytes(
                [
                    b"trillionnium-memory-planning-context-v1".as_slice(),
                    self.boot_id_sha256.as_bytes(),
                    subject_key.as_bytes(),
                    request_id.as_bytes(),
                    memory_ref.as_bytes(),
                    memory.payload_sha256.as_bytes(),
                    memory.updated_at_ms.to_string().as_bytes(),
                ]
                .concat()
                .as_slice()
            )
        );
        let capture_id = format!(
            "memory-selection-{}",
            sha256_bytes(
                [
                    b"trillionnium-memory-planning-capture-v1".as_slice(),
                    request_id.as_bytes(),
                    context_id.as_bytes(),
                ]
                .concat()
                .as_slice()
            )
        );

        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        if context_capacity_used(&state) >= MAX_CONTEXTS {
            bail!("context_handle_capacity_reached");
        }
        if state.contexts.contains_key(&context_id) {
            bail!("memory_planning_context_id_collision");
        }
        let still_available = state.store.memories.iter().any(|item| {
            item.memory_id == memory.memory_id
                && item.owned_by(subject)
                && item.payload_file == memory.payload_file
                && item.payload_sha256 == memory.payload_sha256
                && item.updated_at_ms == memory.updated_at_ms
                && item.payload_bytes == memory.payload_bytes
                && item.retention_until_ms == memory.retention_until_ms
                && item.retention_until_ms > captured_at_ms
        });
        if !still_available {
            bail!("memory_selection_changed_before_context_insert");
        }
        let stored = StoredContext {
            schema: STORED_CONTEXT_SCHEMA.to_string(),
            subject_key,
            owner_uid: subject.uid,
            owner_selinux_domain: subject.selinux_domain.clone(),
            subject_user_id: subject.uid / 100_000,
            boot_id_sha256: self.boot_id_sha256.clone(),
            context_id: context_id.clone(),
            source_id: source_id.clone(),
            source_kind: "memory".to_string(),
            captured_at_ms,
            expires_at_ms,
            privacy_class: memory.privacy_class,
            content_sha256: memory.payload_sha256.clone(),
            content: std::mem::take(&mut *content),
            capture_id,
            capture_receipt_id: String::new(),
            capture_request_id: String::new(),
            origin_method: "select_memory_context".to_string(),
            origin_request_id: request_id.to_string(),
            resolution_sha256: String::new(),
            authority_import_state: "local_only".to_string(),
            parent_memory_id: memory.memory_id.clone(),
            parent_memory_payload_sha256: memory.payload_sha256.clone(),
            parent_memory_updated_at_ms: memory.updated_at_ms,
            revoked: false,
            revoked_at_ms: 0,
            tombstone_until_ms: 0,
            source_metadata: json!({
                "selection": "explicit_single_saved_memory",
                "memory_ref": source_id,
                "selected_memory_id": memory.memory_id,
                "selected_memory_payload_sha256": memory.payload_sha256,
                "selected_memory_updated_at_ms": memory.updated_at_ms,
                "snapshot_survives_source_deletion_until_ttl_or_revoke": false,
                "raw_cleartext_persisted": false,
                "encrypted_context_payload_persisted": true,
            }),
        };
        let result = stored.metadata();
        let mut result = result;
        let result_object = result
            .as_object_mut()
            .context("memory_selection_result_not_object")?;
        result_object.insert(
            "selected_memory_id".to_string(),
            Value::String(memory.memory_id.clone()),
        );
        result_object.insert(
            "selected_memory_payload_sha256".to_string(),
            Value::String(memory.payload_sha256.clone()),
        );
        result_object.insert(
            "selected_memory_updated_at_ms".to_string(),
            Value::from(memory.updated_at_ms),
        );
        state.contexts.insert(context_id, stored);
        drop(state);
        if let Err(error) = self.persist_context_journal() {
            if !self
                .context_journal_publication_durability_uncertain
                .load(AtomicOrdering::Acquire)
            {
                self.state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?
                    .contexts
                    .remove(result["context_id"].as_str().unwrap_or_default());
            }
            return Err(error);
        }
        Ok(result)
    }

    #[cfg(test)]
    pub(super) fn create_test_context(&self, subject: &Subject, payload: Value) -> Result<Value> {
        let _serial = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_operation_lock_poisoned"))?;
        self.cleanup()?;
        self.create_context_fixture(subject, payload)
    }

    /// Persist metadata only after the caller has already committed the exact
    /// UID/domain/key tuple for this daemon boot. This is used by the startup
    /// path after boot pinning; runtime metadata requests are read-only.
    fn pin_authority_key_metadata(&self, metadata: Value) -> Result<Value> {
        let _serial = self
            .pin_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("authority_key_pin_lock_poisoned"))?;
        let candidate = validate_authority_key_metadata(&metadata)?;
        let existing = self.load_authority_key_pin_locked()?;
        validate_authority_key_transition(existing.as_ref(), &candidate, validate_rotation_marker)?;
        self.persist_authority_key_candidate(candidate, existing)
    }

    /// Runtime metadata discovery may confirm the boot-frozen receipt key but
    /// can never rotate it. Cross-epoch rotation is admitted only during the
    /// next daemon startup, before that boot's UID/domain/key tuple is frozen.
    pub(super) fn prevalidate_authority_key_metadata_against_frozen_pin(
        &self,
        metadata: &Value,
    ) -> Result<Value> {
        let _serial = self
            .pin_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("authority_key_pin_lock_poisoned"))?;
        let candidate = validate_authority_key_metadata(metadata)?;
        let pin = self
            .load_authority_key_pin_locked()?
            .context("authority_key_pin_missing")?;
        if candidate.key_id != pin.key_id
            || candidate.key_epoch != pin.key_epoch
            || candidate.key_profile != pin.key_profile
            || candidate.public_key_spki != pin.public_key_spki
            || candidate.security_level != pin.security_level
            || candidate.attestation_challenge_sha256 != pin.attestation_challenge_sha256
            || candidate.attestation_chain_present != pin.attestation_chain_present
            || candidate.rotation_contract != pin.rotation_contract
        {
            bail!("authority_key_metadata_differs_from_boot_frozen_pin");
        }
        authority_key_pin_value(&pin)
    }

    fn load_authority_key_pin_locked(&self) -> Result<Option<AuthorityKeyPin>> {
        let pin_path = self.root.join("authority-key-pin.json");
        if !private_entry_exists(&pin_path)? {
            return Ok(None);
        }
        let bytes = read_private_bounded_file(&pin_path, 64 * 1024)?;
        let pin: AuthorityKeyPin =
            serde_json::from_slice(&bytes).context("invalid_authority_key_pin_json")?;
        validate_authority_key_pin_state(&pin)?;
        Ok(Some(pin))
    }

    fn persist_authority_key_candidate(
        &self,
        candidate: AuthorityKeyCandidate,
        existing: Option<AuthorityKeyPin>,
    ) -> Result<Value> {
        let pin_path = self.root.join("authority-key-pin.json");
        let pin = AuthorityKeyPin {
            schema: AUTHORITY_PIN_SCHEMA.to_string(),
            key_id: candidate.key_id,
            key_epoch: candidate.key_epoch,
            key_profile: candidate.key_profile,
            public_key_spki: candidate.public_key_spki,
            security_level: candidate.security_level,
            attestation_challenge_sha256: candidate.attestation_challenge_sha256,
            attestation_chain_present: candidate.attestation_chain_present,
            rotation_contract: candidate.rotation_contract,
            pinned_at_ms: existing
                .as_ref()
                .filter(|item| item.key_epoch == candidate.key_epoch)
                .map(|item| item.pinned_at_ms)
                .unwrap_or_else(now_unix_ms),
            // The daemon validates the expected challenge, hardware level,
            // key/SPKI digest and authenticated Authority gateway. It does not
            // yet carry an Android/Google root set for full KeyMint X.509 path
            // and attestationApplicationId verification.
            attestation_verified: false,
        };
        atomic_write_private(&pin_path, &serde_json::to_vec_pretty(&pin)?)?;
        authority_key_pin_value(&pin)
    }

    /// Read and fully revalidate the boot-frozen Authority receipt key without
    /// contacting Authority or rewriting any durable state. Receipt preflight
    /// uses only this view so a forged receipt cannot consume a gateway replay
    /// ID or rotate/rewrite the local pin.
    pub(super) fn authority_key_pin(&self) -> Result<Value> {
        let _serial = self
            .pin_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("authority_key_pin_lock_poisoned"))?;
        let pin_path = self.root.join("authority-key-pin.json");
        if !private_entry_exists(&pin_path)? {
            bail!("authority_key_pin_missing");
        }
        let bytes = read_private_bounded_file(&pin_path, 64 * 1024)?;
        let pin: AuthorityKeyPin =
            serde_json::from_slice(&bytes).context("invalid_authority_key_pin_json")?;
        validate_authority_key_pin_state(&pin)?;
        authority_key_pin_value(&pin)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn issue_context_grant(
        &self,
        owner: &Subject,
        target: AgentGrantTarget,
        context_id: &str,
        raw_allowed: bool,
        egress_scope: &str,
        egress_endpoint: &str,
        ttl_ms: u64,
    ) -> Result<Value> {
        validate_agent_grant_target(owner, &target)?;
        validate_data_grant_scope(egress_scope, egress_endpoint, ttl_ms)?;
        validate_resource_id(context_id, "context-")?;
        let _resource_guard = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_operation_lock_poisoned"))?;
        self.mutate_agent_grants(|state| {
            if state.grant_store.grants.len() >= MAX_DATA_GRANTS {
                bail!("agent_data_grant_capacity_reached");
            }
            let context = state
                .contexts
                .get(context_id)
                .context("unknown_or_expired_context_handle")?;
            if context.subject_key != owner.key() {
                bail!("context_subject_binding_mismatch");
            }
            let now = now_unix_ms();
            if context.expires_at_ms <= now {
                bail!("context_handle_expired");
            }
            let expires_at_ms = now.saturating_add(ttl_ms).min(context.expires_at_ms);
            let grant = new_agent_data_grant(
                owner,
                &target,
                "context",
                &context.context_id,
                &context.content_sha256,
                &context.source_id,
                &context.source_kind,
                &context.privacy_class,
                raw_allowed,
                egress_scope,
                egress_endpoint,
                now,
                expires_at_ms,
            )?;
            append_agent_data_grant_audit(&mut state.grant_store, "issue", &grant, now)?;
            let result = grant.public_json();
            state.grant_store.grants.push(grant);
            Ok(result)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn issue_memory_grant(
        &self,
        owner: &Subject,
        target: AgentGrantTarget,
        memory_id: &str,
        raw_allowed: bool,
        egress_scope: &str,
        egress_endpoint: &str,
        ttl_ms: u64,
    ) -> Result<Value> {
        validate_agent_grant_target(owner, &target)?;
        validate_data_grant_scope(egress_scope, egress_endpoint, ttl_ms)?;
        validate_resource_id(memory_id, "memory-")?;
        let _resource_guard = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_operation_lock_poisoned"))?;
        self.mutate_agent_grants(|state| {
            if state.grant_store.grants.len() >= MAX_DATA_GRANTS {
                bail!("agent_data_grant_capacity_reached");
            }
            let memory = state
                .store
                .memories
                .iter()
                .find(|item| item.memory_id == memory_id)
                .context("unknown_memory_id")?;
            if !memory.owned_by(owner) {
                bail!("memory_subject_binding_mismatch");
            }
            let now = now_unix_ms();
            if memory.retention_until_ms <= now {
                bail!("memory_retention_expired");
            }
            let grant = new_agent_data_grant(
                owner,
                &target,
                "memory",
                &memory.memory_id,
                &memory.payload_sha256,
                &memory.source_id,
                &memory.source_kind,
                &memory.privacy_class,
                raw_allowed,
                egress_scope,
                egress_endpoint,
                now,
                now.saturating_add(ttl_ms).min(memory.retention_until_ms),
            )?;
            append_agent_data_grant_audit(&mut state.grant_store, "issue", &grant, now)?;
            let result = grant.public_json();
            state.grant_store.grants.push(grant);
            Ok(result)
        })
    }

    pub(super) fn revoke_agent_data_grant(&self, owner: &Subject, grant_id: &str) -> Result<Value> {
        validate_resource_id(grant_id, "grant-")?;
        self.mutate_agent_grants(|state| {
            let now = now_unix_ms();
            let index = state
                .grant_store
                .grants
                .iter()
                .position(|grant| grant.grant_id == grant_id)
                .context("unknown_agent_data_grant")?;
            let grant = &state.grant_store.grants[index];
            if grant.owner_uid != owner.uid || grant.owner_selinux_domain != owner.selinux_domain {
                bail!("agent_data_grant_owner_mismatch");
            }
            if grant.state != "active" {
                bail!("agent_data_grant_not_active");
            }
            state.grant_store.grants[index].state = "revoked".to_string();
            state.grant_store.grants[index].updated_at_ms = now;
            let grant = state.grant_store.grants[index].clone();
            append_agent_data_grant_audit(&mut state.grant_store, "revoke", &grant, now)?;
            Ok(json!({
                "grant_id": grant_id,
                "revoked": true,
                "raw_content_retained_in_grant": false,
            }))
        })
    }

    pub(super) fn list_agent_data_grants(&self, consumer: &AgentGrantConsumer) -> Result<Value> {
        validate_agent_grant_consumer(consumer)?;
        self.mutate_agent_grants(|state| {
            let items = state
                .grant_store
                .grants
                .iter()
                .filter(|grant| grant.state == "active" && grant.matches_consumer(consumer))
                .map(AgentDataGrant::public_json)
                .collect::<Vec<_>>();
            Ok(json!({
                "items": items,
                "count": items.len(),
                "metadata_only": true,
                "raw_payload_in_listing": false,
            }))
        })
    }

    pub(super) fn read_agent_data_grant(
        &self,
        consumer: &AgentGrantConsumer,
        grant_id: &str,
        expected_kind: &str,
    ) -> Result<Value> {
        validate_agent_grant_consumer(consumer)?;
        validate_resource_id(grant_id, "grant-")?;
        if !matches!(expected_kind, "context" | "memory") {
            bail!("unsupported_agent_data_grant_kind");
        }
        let _resource_guard = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_operation_lock_poisoned"))?;
        self.mutate_agent_grants(|state| {
            let index = state
                .grant_store
                .grants
                .iter()
                .position(|grant| grant.grant_id == grant_id)
                .context("unknown_agent_data_grant")?;
            let grant = state.grant_store.grants[index].clone();
            if !grant.matches_consumer(consumer) {
                bail!("agent_data_grant_consumer_binding_mismatch");
            }
            if grant.resource_kind != expected_kind {
                bail!("agent_data_grant_kind_mismatch");
            }
            if grant.state != "active" || grant.expires_at_ms <= now_unix_ms() {
                bail!("agent_data_grant_not_active");
            }
            if !grant.raw_allowed || !grant.single_use {
                bail!("agent_data_grant_raw_read_denied");
            }

            let raw = if expected_kind == "context" {
                let context = state
                    .contexts
                    .get(&grant.resource_id)
                    .context("delegated_context_no_longer_available")?;
                if context.subject_key
                    != Subject::new(grant.owner_uid, &grant.owner_selinux_domain)?.key()
                    || context.content_sha256 != grant.resource_sha256
                    || context.expires_at_ms <= now_unix_ms()
                {
                    bail!("delegated_context_binding_or_freshness_mismatch");
                }
                Zeroizing::new(context.content.clone())
            } else {
                let memory = state
                    .store
                    .memories
                    .iter()
                    .find(|item| item.memory_id == grant.resource_id)
                    .context("delegated_memory_no_longer_available")?;
                let owner = Subject::new(grant.owner_uid, &grant.owner_selinux_domain)?;
                if !memory.owned_by(&owner)
                    || memory.payload_sha256 != grant.resource_sha256
                    || memory.retention_until_ms <= now_unix_ms()
                {
                    bail!("delegated_memory_binding_or_retention_mismatch");
                }
                let encrypted = read_private_bounded_file(
                    &self.payload_root.join(&memory.payload_file),
                    MAX_CONTEXT_BYTES * 2 + 256,
                )?;
                let associated_data = memory_associated_data(&owner, &memory.memory_id);
                let clear =
                    self.decrypt_custody_gated(&associated_data, &encrypted, MAX_CONTEXT_BYTES)?;
                if clear.len() != memory.payload_bytes
                    || sha256_bytes(clear.as_slice()) != memory.payload_sha256
                {
                    bail!("delegated_memory_payload_integrity_mismatch");
                }
                Zeroizing::new(
                    String::from_utf8(clear.to_vec()).context("delegated_memory_not_utf8")?,
                )
            };

            let now = now_unix_ms();
            state.grant_store.grants[index].state = "consumed".to_string();
            state.grant_store.grants[index].updated_at_ms = now;
            let consumed = state.grant_store.grants[index].clone();
            append_agent_data_grant_audit(&mut state.grant_store, "consume", &consumed, now)?;
            Ok(json!({
                "grant": consumed.public_json(),
                "content": raw.as_str(),
                "content_sha256": consumed.resource_sha256,
                "single_use_consumed": true,
                "network_authority_conferred": false,
            }))
        })
    }

    fn mutate_agent_grants<T>(&self, operation: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        self.ensure_grant_store_publication_certain()?;
        let _grant_guard = self
            .grant_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("agent_data_grant_lock_poisoned"))?;
        // The State mutex remains held through temp-file fsync, rename, and
        // parent-directory fsync. Thus no concurrent reader can observe a
        // candidate grant state before it is durable. Any operation or write
        // failure restores the exact previous in-memory ledger before unlock.
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        let before = state.grant_store.clone();
        if let Err(error) = expire_agent_data_grants(&mut state.grant_store, now_unix_ms()) {
            state.grant_store = before;
            return Err(error);
        }
        prune_agent_data_grants(&mut state.grant_store, now_unix_ms());
        let outcome = match operation(&mut state) {
            Ok(outcome) => outcome,
            Err(error) => {
                state.grant_store = before;
                return Err(error);
            }
        };
        if state.grant_store != before {
            match self.persist_grant_store_value(&state.grant_store) {
                Err(error) => {
                    state.grant_store = before;
                    return Err(error).context("agent_data_grant_persistence_failed");
                }
                Ok(PrivatePublishState::PublishedDurabilityUncertain) => {
                    self.grant_store_publication_durability_uncertain
                        .store(true, AtomicOrdering::Release);
                    bail!("agent_data_grant_commit_unknown_parent_fsync_uncertain_reopen_required");
                }
                Ok(PrivatePublishState::Durable) => {}
            }
        }
        Ok(outcome)
    }

    #[cfg(test)]
    fn create_context_fixture(&self, subject: &Subject, payload: Value) -> Result<Value> {
        let source_kind = bounded_string(&payload, "source_kind", MAX_SOURCE_KIND_BYTES)?;
        match source_kind.as_str() {
            "file" | "browser" | "browser_extract" | "notifications" | "current_app"
            | "memory_import" => {}
            _ => bail!("unsupported_context_kind"),
        }
        let source_id = bounded_string(&payload, "source_id", MAX_SOURCE_ID_BYTES)?;
        let mut content = bounded_string(&payload, "content", MAX_CONTEXT_BYTES)?;
        if source_kind == "browser" {
            content = canonical_https_execution_url(&content)?;
        }
        let privacy_class = payload
            .get("privacy_class")
            .and_then(Value::as_str)
            .unwrap_or("local_private");
        if !matches!(privacy_class, "public" | "local_private" | "sensitive") {
            bail!("unsupported_context_privacy_class");
        }
        let ttl_ms = payload
            .get("freshness_ttl_ms")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_CONTEXT_TTL_MS);
        if ttl_ms == 0 || ttl_ms > MAX_CONTEXT_TTL_MS {
            bail!("context_ttl_outside_bounded_contract");
        }
        let now = now_unix_ms();
        let mut random = [0u8; 32];
        fill_kernel_random(&mut random)?;
        let content_sha256 = sha256_bytes(content.as_bytes());
        let context_id = format!(
            "context-{}",
            sha256_bytes(
                [
                    random.as_slice(),
                    subject.key().as_bytes(),
                    source_id.as_bytes(),
                    content_sha256.as_bytes(),
                ]
                .concat()
                .as_slice()
            )
        );
        let stored = StoredContext {
            schema: STORED_CONTEXT_SCHEMA.to_string(),
            subject_key: subject.key(),
            owner_uid: subject.uid,
            owner_selinux_domain: subject.selinux_domain.clone(),
            subject_user_id: subject.uid / 100_000,
            boot_id_sha256: self.boot_id_sha256.clone(),
            context_id: context_id.clone(),
            source_id,
            source_kind,
            captured_at_ms: now,
            expires_at_ms: now + ttl_ms,
            privacy_class: privacy_class.to_string(),
            content_sha256,
            content,
            capture_id: "test-fixture".to_string(),
            capture_receipt_id: String::new(),
            capture_request_id: String::new(),
            origin_method: "test_fixture".to_string(),
            origin_request_id: format!("test-fixture-{}", &context_id["context-".len()..]),
            resolution_sha256: String::new(),
            authority_import_state: "local_only".to_string(),
            parent_memory_id: String::new(),
            parent_memory_payload_sha256: String::new(),
            parent_memory_updated_at_ms: 0,
            revoked: false,
            revoked_at_ms: 0,
            tombstone_until_ms: 0,
            source_metadata: json!({"test_fixture": true}),
        };
        let result = stored.metadata();
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        if context_capacity_used(&state) >= MAX_CONTEXTS {
            bail!("context_handle_capacity_reached");
        }
        state.contexts.insert(context_id, stored);
        drop(state);
        self.persist_context_journal()?;
        Ok(result)
    }

    fn store_verified_context(
        &self,
        subject: &Subject,
        capture: VerifiedContextCapture,
        require_authority_provenance: bool,
    ) -> Result<Value> {
        let now = now_unix_ms();
        let source_binding_valid = match capture.source_kind.as_str() {
            "file" => capture
                .source_id
                .strip_prefix("saf-provider:")
                .and_then(|value| value.split_once(":document:"))
                .is_some_and(|(authority, document)| {
                    is_lower_hex(authority, 64) && is_lower_hex(document, 64)
                }),
            "browser" => {
                let mut canonical = canonical_https_execution_url(&capture.content).ok();
                let valid = canonical.as_ref().is_some_and(|value| {
                    value == &capture.content
                        && capture.source_id == format!("authority-url:{}", capture.content_sha256)
                });
                if let Some(value) = &mut canonical {
                    value.zeroize();
                }
                valid
            }
            _ => false,
        };
        if !require_authority_provenance
            || capture.requesting_uid != subject.uid
            || capture.subject_user_id != subject.uid / 100_000
            || capture.boot_id_sha256 != self.boot_id_sha256
            || !capture
                .capture_id
                .strip_prefix("capture-")
                .is_some_and(|value| is_lower_hex(value, 64))
            || !is_lower_hex(&capture.capture_receipt_id, 64)
            || !source_binding_valid
            || capture.source_id.is_empty()
            || capture.source_id.len() > MAX_SOURCE_ID_BYTES
            || capture.privacy_class != "local_private"
            || capture.content.is_empty()
            || capture.content.len() > MAX_CONTEXT_BYTES
            || capture.content_bytes != capture.content.len()
            || capture.content_sha256 != sha256_bytes(capture.content.as_bytes())
            || capture.captured_at_ms > now.saturating_add(5_000)
            || capture.expires_at_ms <= now
            || capture.expires_at_ms <= capture.captured_at_ms
            || capture.expires_at_ms - capture.captured_at_ms > MAX_CONTEXT_TTL_MS
            || !capture.source_metadata.is_object()
            || validate_request_id(&capture.origin_request_id).is_err()
            || validate_request_id(&capture.capture_request_id).is_err()
            || !is_lower_hex(&capture.resolution_sha256, 64)
        {
            bail!("verified_context_capture_binding_denied");
        }
        let context_id = format!(
            "context-{}",
            sha256_bytes(
                [
                    b"trillionnium-authority-context-import-v1".as_slice(),
                    self.boot_id_sha256.as_bytes(),
                    subject.key().as_bytes(),
                    capture.capture_id.as_bytes(),
                    capture.capture_receipt_id.as_bytes(),
                    capture.resolution_sha256.as_bytes(),
                    capture.content_sha256.as_bytes(),
                ]
                .concat()
                .as_slice()
            )
        );
        let reservation_id = context_import_reservation_id(
            &self.boot_id_sha256,
            &subject.key(),
            &capture.origin_request_id,
            &capture.capture_id,
            &capture.capture_receipt_id,
            &capture.capture_request_id,
            &capture.source_id,
            &capture.content_sha256,
        );
        let stored = StoredContext {
            schema: STORED_CONTEXT_SCHEMA.to_string(),
            subject_key: subject.key(),
            owner_uid: subject.uid,
            owner_selinux_domain: subject.selinux_domain.clone(),
            subject_user_id: subject.uid / 100_000,
            boot_id_sha256: self.boot_id_sha256.clone(),
            context_id: context_id.clone(),
            source_id: capture.source_id,
            source_kind: capture.source_kind,
            captured_at_ms: capture.captured_at_ms,
            expires_at_ms: capture.expires_at_ms,
            privacy_class: capture.privacy_class,
            content_sha256: capture.content_sha256,
            content: capture.content,
            capture_id: capture.capture_id,
            capture_receipt_id: capture.capture_receipt_id,
            capture_request_id: capture.capture_request_id,
            origin_method: "get_context".to_string(),
            origin_request_id: capture.origin_request_id,
            resolution_sha256: capture.resolution_sha256,
            authority_import_state: "published_pending_ack".to_string(),
            parent_memory_id: String::new(),
            parent_memory_payload_sha256: String::new(),
            parent_memory_updated_at_ms: 0,
            revoked: false,
            revoked_at_ms: 0,
            tombstone_until_ms: 0,
            source_metadata: capture.source_metadata,
        };
        let result = stored.metadata();
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        if let Some(existing) = state.contexts.get(&context_id) {
            if existing == &stored {
                return Ok(existing.metadata());
            }
            bail!("context_import_identity_substitution_denied");
        }
        if state.contexts.values().any(|existing| {
            existing.capture_id == stored.capture_id
                && existing.capture_receipt_id == stored.capture_receipt_id
        }) {
            bail!("context_capture_already_imported_with_different_binding");
        }
        let reservation = state
            .context_import_reservations
            .get(&reservation_id)
            .cloned()
            .context("context_import_capacity_not_reserved_before_authority_consume")?;
        if reservation.subject_key != stored.subject_key
            || reservation.origin_request_id != stored.origin_request_id
            || reservation.capture_id != stored.capture_id
            || reservation.capture_receipt_id != stored.capture_receipt_id
            || reservation.capture_request_id != stored.capture_request_id
            || reservation.source_id != stored.source_id
            || reservation.source_kind != stored.source_kind
            || reservation.content_sha256 != stored.content_sha256
            || reservation.expires_at_ms != stored.expires_at_ms
        {
            bail!("context_import_capacity_reservation_binding_changed");
        }
        state.context_import_reservations.remove(&reservation_id);
        state.contexts.insert(context_id.clone(), stored);
        drop(state);
        if let Err(error) = self.persist_context_journal() {
            if !self
                .context_journal_publication_durability_uncertain
                .load(AtomicOrdering::Acquire)
            {
                self.state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?
                    .contexts
                    .remove(&context_id);
                self.state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?
                    .context_import_reservations
                    .insert(reservation_id, reservation);
            }
            return Err(error);
        }
        Ok(result)
    }

    pub(super) fn acknowledge_context_imported(
        &self,
        subject: &Subject,
        context_id: &str,
        resolution_sha256: &str,
    ) -> Result<Value> {
        validate_resource_id(context_id, "context-")?;
        if !is_lower_hex(resolution_sha256, 64) {
            bail!("context_import_resolution_digest_denied");
        }
        let _serial = self
            .serial
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_operation_lock_poisoned"))?;
        let before = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            let context = state
                .contexts
                .get_mut(context_id)
                .context("unknown_context_import_candidate")?;
            if context.subject_key != subject.key()
                || context.boot_id_sha256 != self.boot_id_sha256
                || context.resolution_sha256 != resolution_sha256
                || context.origin_method != "get_context"
                || !matches!(
                    context.authority_import_state.as_str(),
                    "published_pending_ack" | "imported"
                )
            {
                bail!("context_import_ack_binding_mismatch");
            }
            let before = context.clone();
            context.authority_import_state = "imported".to_string();
            before
        };
        if let Err(error) = self.persist_context_journal() {
            if !self
                .context_journal_publication_durability_uncertain
                .load(AtomicOrdering::Acquire)
            {
                self.state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?
                    .contexts
                    .insert(context_id.to_string(), before);
            }
            return Err(error);
        }
        self.context_metadata_exact(subject, context_id)
    }

    fn revoke_context(&self, subject: &Subject, payload: Value) -> Result<Value> {
        let context_id = bounded_string(&payload, "context_id", 96)?;
        let before = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            let revocation_tombstones = state
                .contexts
                .values()
                .filter(|context| context.revoked)
                .count();
            let context = state
                .contexts
                .get_mut(&context_id)
                .context("unknown_or_expired_context_handle")?;
            if context.subject_key != subject.key() {
                bail!("context_subject_binding_mismatch");
            }
            if context.revoked {
                return Ok(json!({
                    "context_id": context_id,
                    "revoked": true,
                    "raw_content_retained": false,
                }));
            }
            if revocation_tombstones >= MAX_CONTEXT_TOMBSTONES {
                bail!("context_revocation_tombstone_capacity_reached");
            }
            let before = context.clone();
            let now = now_unix_ms();
            context.content.zeroize();
            context.content.clear();
            context.revoked = true;
            context.revoked_at_ms = now;
            context.tombstone_until_ms = now.saturating_add(REPLAY_RETENTION_MS);
            before
        };
        if let Err(error) = self.persist_context_journal() {
            if !self.context_journal_publication_is_uncertain() {
                self.state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?
                    .contexts
                    .insert(context_id.clone(), before);
            }
            return Err(error);
        }
        Ok(json!({
            "context_id": context_id,
            "revoked": true,
            "raw_content_retained": false,
        }))
    }

    fn held_ui_memory_provenance(&self, subject: &Subject) -> Result<Vec<HeldUiMemoryProvenance>> {
        let _guard = self
            .ui_replay_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("ui_replay_lock_poisoned"))?;
        self.prune_ui_replays_locked()?;
        let mut held = Vec::new();
        open_private_directory(&self.ui_replay_root)?;
        for entry in fs::read_dir(&self.ui_replay_root)? {
            let path = entry?.path();
            let record = load_ui_replay_record(&path)?;
            if record.state != "completed"
                || record.subject_key != subject.key()
                || !matches!(
                    record.method.as_str(),
                    "prepare_egress" | "plan" | "approve"
                )
            {
                continue;
            }
            if record.schema != UI_REPLAY_SCHEMA {
                bail!("ui_replay_memory_provenance_legacy_record_retired_hold");
            }
            let (_, envelope) = self.verify_completed_ui_replay_pair(&record)?;
            if envelope.get("ok").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let Some(value) = envelope.get("memory_provenance") else {
                continue;
            };
            if value.get("schema").and_then(Value::as_str) != Some(UI_MEMORY_PROVENANCE_SCHEMA) {
                bail!("invalid_ui_memory_provenance_schema");
            }
            let kind = value.get("kind").and_then(Value::as_str);
            if !matches!(
                (record.method.as_str(), kind),
                ("prepare_egress", Some("egress_prepared"))
                    | ("plan", Some("planning_result"))
                    | ("approve", Some("action_result"))
            ) {
                bail!("ui_memory_provenance_method_mismatch");
            }
            held.push(HeldUiMemoryProvenance {
                request_id: record.request_id,
                value: value.clone(),
            });
        }
        Ok(held)
    }

    fn verify_memory_provenance(
        &self,
        subject: &Subject,
        context: &StoredContext,
        raw_payload: &str,
        claimed_receipt_id: &str,
        claimed_taint_lineage: &str,
    ) -> Result<VerifiedMemoryProvenance> {
        let payload_sha256 = sha256_bytes(raw_payload.as_bytes());
        if context.source_kind == "memory_import" {
            if claimed_taint_lineage != "user_imported"
                || !claimed_receipt_id.is_empty()
                || raw_payload != context.content
            {
                bail!("memory_user_import_provenance_mismatch");
            }
            return Ok(VerifiedMemoryProvenance {
                kind: "user_imported".to_string(),
                provenance_id: format!(
                    "provenance-{}",
                    sha256_bytes(
                        format!(
                            "user_imported\n{}\n{}\n{}\n",
                            subject.key(),
                            context.context_id,
                            context.content_sha256
                        )
                        .as_bytes()
                    )
                ),
                task_id: String::new(),
                plan_id: String::new(),
                receipt_id: String::new(),
                taint_lineage: "user_imported".to_string(),
            });
        }
        if claimed_taint_lineage != "untainted" {
            bail!("memory_result_taint_lineage_mismatch");
        }
        if !claimed_receipt_id.is_empty() && !valid_lower_sha256(claimed_receipt_id) {
            bail!("invalid_memory_receipt_id");
        }

        let held = self.held_ui_memory_provenance(subject)?;
        let mut candidates = Vec::new();
        for plan in held.iter().filter(|item| {
            item.value.get("kind").and_then(Value::as_str) == Some("planning_result")
        }) {
            let Some(result_payload_sha256) = plan
                .value
                .get("result_payload_sha256")
                .and_then(Value::as_str)
            else {
                continue;
            };
            if result_payload_sha256 != payload_sha256 || !valid_lower_sha256(result_payload_sha256)
            {
                continue;
            }
            let Some(workflow_id) = bounded_value(&plan.value, "workflow_id", 128) else {
                continue;
            };
            let Some(provider_id) = bounded_value(&plan.value, "provider_id", 64) else {
                continue;
            };
            let Some(egress_grant_id) = bounded_value(&plan.value, "egress_grant_id", 96) else {
                continue;
            };
            let Some(task_id) = bounded_value(&plan.value, "task_id", 128) else {
                continue;
            };
            let Some(plan_id) = plan.value.get("plan_id").and_then(Value::as_str) else {
                continue;
            };
            if plan_id.len() > 128 {
                continue;
            }
            let Some(action) = bounded_value(&plan.value, "action", 96) else {
                continue;
            };
            let Some(provider_output_sha256) = plan
                .value
                .get("provider_output_sha256")
                .and_then(Value::as_str)
            else {
                continue;
            };
            if !valid_lower_sha256(provider_output_sha256) {
                continue;
            }

            let prepared = held
                .iter()
                .filter(|item| {
                    item.value.get("kind").and_then(Value::as_str) == Some("egress_prepared")
                        && item.value.get("egress_grant_id").and_then(Value::as_str)
                            == Some(egress_grant_id)
                        && item.value.get("workflow_id").and_then(Value::as_str)
                            == Some(workflow_id)
                        && item.value.get("provider_id").and_then(Value::as_str)
                            == Some(provider_id)
                        && item.value.get("context_id").and_then(Value::as_str)
                            == Some(context.context_id.as_str())
                        && item.value.get("context_sha256").and_then(Value::as_str)
                            == Some(context.content_sha256.as_str())
                })
                .collect::<Vec<_>>();
            if prepared.len() != 1 {
                continue;
            }

            let (kind, receipt_id, action_request_id) = if claimed_receipt_id.is_empty() {
                ("planning_result", String::new(), String::new())
            } else {
                let actions = held
                    .iter()
                    .filter(|item| {
                        item.value.get("kind").and_then(Value::as_str) == Some("action_result")
                            && item.value.get("workflow_id").and_then(Value::as_str)
                                == Some(workflow_id)
                            && item.value.get("task_id").and_then(Value::as_str) == Some(task_id)
                            && item.value.get("plan_id").and_then(Value::as_str) == Some(plan_id)
                            && item.value.get("action").and_then(Value::as_str) == Some(action)
                            && item.value.get("context_sha256").and_then(Value::as_str)
                                == Some(context.content_sha256.as_str())
                            && item
                                .value
                                .get("provider_output_sha256")
                                .and_then(Value::as_str)
                                == Some(provider_output_sha256)
                            && item.value.get("receipt_id").and_then(Value::as_str)
                                == Some(claimed_receipt_id)
                            && item.value.get("origin_uid").and_then(Value::as_u64)
                                == Some(subject.uid as u64)
                            && item.value.get("subject_user_id").and_then(Value::as_u64)
                                == Some((subject.uid / 100_000) as u64)
                    })
                    .collect::<Vec<_>>();
                if actions.len() != 1 {
                    continue;
                }
                (
                    "planning_result_with_action_receipt",
                    claimed_receipt_id.to_string(),
                    actions[0].request_id.clone(),
                )
            };
            let provenance_id = format!(
                "provenance-{}",
                sha256_bytes(
                    format!(
                        "{}\n{}\n{}\n{}\n{}\n{}\n",
                        UI_MEMORY_PROVENANCE_SCHEMA,
                        subject.key(),
                        context.context_id,
                        plan.request_id,
                        action_request_id,
                        payload_sha256
                    )
                    .as_bytes()
                )
            );
            candidates.push(VerifiedMemoryProvenance {
                kind: kind.to_string(),
                provenance_id,
                task_id: task_id.to_string(),
                plan_id: plan_id.to_string(),
                receipt_id,
                taint_lineage: "untainted".to_string(),
            });
        }
        if candidates.is_empty() {
            bail!("memory_os_held_provenance_missing_or_mismatched");
        }
        if candidates.len() != 1 {
            bail!("memory_os_held_provenance_ambiguous");
        }
        Ok(candidates.remove(0))
    }

    fn save_memory(
        &self,
        subject: &Subject,
        request_id: &str,
        request_payload_sha256: &str,
        payload: Value,
    ) -> Result<Value> {
        let subject_key = subject.key();
        {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            if let Some(tombstone) = state
                .store
                .memory_saves
                .iter()
                .find(|item| item.request_id == request_id && item.subject_key == subject_key)
            {
                if tombstone.request_payload_sha256 != request_payload_sha256 {
                    bail!("memory_save_tombstone_payload_substitution_denied");
                }
                let memory = state
                    .store
                    .memories
                    .iter()
                    .find(|memory| memory.memory_id == tombstone.memory_id)
                    .context("memory_save_tombstone_result_no_longer_available")?;
                if memory.public_json() != tombstone.result {
                    bail!("memory_save_tombstone_result_binding_denied");
                }
                return Ok(tombstone.result.clone());
            }
        }
        self.require_memory_key_unlocked()?;
        let context_id = bounded_string(&payload, "context_id", 96)?;
        let raw_payload = Zeroizing::new(bounded_string(&payload, "payload", MAX_CONTEXT_BYTES)?);
        let receipt_id = payload
            .get("receipt_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let taint_lineage = payload
            .get("taint_lineage")
            .and_then(Value::as_str)
            .unwrap_or("untainted");
        let retention_ms = payload
            .get("retention_ms")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_MEMORY_RETENTION_MS);
        if retention_ms == 0 || retention_ms > MAX_MEMORY_RETENTION_MS {
            bail!("memory_retention_outside_bounded_contract");
        }
        let context = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            let context = state
                .contexts
                .get(&context_id)
                .context("unknown_or_expired_context_handle")?;
            if context.subject_key != subject.key() {
                bail!("context_subject_binding_mismatch");
            }
            context.clone()
        };
        let now = now_unix_ms();
        if context.expires_at_ms <= now {
            bail!("context_handle_expired");
        }
        let provenance = self.verify_memory_provenance(
            subject,
            &context,
            raw_payload.as_str(),
            receipt_id,
            taint_lineage,
        )?;
        let mut random = [0u8; 32];
        fill_kernel_random(&mut random)?;
        let memory_id = format!(
            "memory-{}",
            sha256_bytes(
                [
                    random.as_slice(),
                    subject.key().as_bytes(),
                    context_id.as_bytes(),
                    now.to_string().as_bytes(),
                ]
                .concat()
                .as_slice()
            )
        );
        let payload_file = format!("{memory_id}.enc");
        let associated_data = memory_associated_data(subject, &memory_id);
        let encrypted = encrypt_payload(&self.key, &associated_data, raw_payload.as_bytes())?;
        atomic_write_private(&self.payload_root.join(&payload_file), &encrypted)?;
        let metadata = MemoryMetadata {
            schema: MEMORY_SCHEMA.to_string(),
            memory_id: memory_id.clone(),
            owner_uid: subject.uid,
            owner_selinux_domain: subject.selinux_domain.clone(),
            context_id,
            source_id: context.source_id,
            source_kind: context.source_kind,
            captured_at_ms: context.captured_at_ms,
            privacy_class: context.privacy_class,
            context_sha256: context.content_sha256,
            payload_sha256: sha256_bytes(raw_payload.as_bytes()),
            payload_bytes: raw_payload.len(),
            payload_file: payload_file.clone(),
            encryption_key_id: format!("memory-key-{}", sha256_bytes(&*self.key)),
            encryption_algorithm: "XChaCha20Poly1305".to_string(),
            receipt_id: provenance.receipt_id.clone(),
            taint_lineage: provenance.taint_lineage.clone(),
            provenance_kind: provenance.kind.clone(),
            provenance_id: provenance.provenance_id.clone(),
            task_id: provenance.task_id.clone(),
            plan_id: provenance.plan_id.clone(),
            retention_until_ms: now + retention_ms,
            created_at_ms: now,
            updated_at_ms: now,
        };
        let result = metadata.public_json();
        let store_result = (|| -> Result<PrivatePublishState> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            let subject_count = state
                .store
                .memories
                .iter()
                .filter(|item| item.owned_by(subject))
                .count();
            if subject_count >= MAX_MEMORY_PER_SUBJECT
                || state.store.memories.len() >= MAX_MEMORY_GLOBAL
            {
                bail!("memory_capacity_reached");
            }
            if state.store.memory_saves.len() >= MAX_MEMORY_SAVE_TOMBSTONES {
                bail!("memory_save_tombstone_capacity_reached");
            }
            if state
                .store
                .memories
                .iter()
                .any(|item| item.provenance_id == provenance.provenance_id)
            {
                bail!("memory_provenance_already_consumed");
            }
            let mut candidate = state.store.clone();
            candidate.memory_generation = candidate
                .memory_generation
                .checked_add(1)
                .context("memory_generation_exhausted")?;
            candidate.memories.push(metadata.clone());
            candidate.memory_saves.push(MemorySaveTombstone {
                schema: MEMORY_SAVE_TOMBSTONE_SCHEMA.to_string(),
                request_id: request_id.to_string(),
                subject_key: subject_key.clone(),
                request_payload_sha256: request_payload_sha256.to_string(),
                memory_id: memory_id.clone(),
                saved_at_ms: now,
                result: result.clone(),
            });
            ensure_store_growth_budget(&candidate)?;
            let publish = persist_store_file(&self.root.join("metadata.json"), &candidate)?;
            // rename is the commit point. The staged publisher has already
            // reopened and compared the destination byte-for-byte, so both
            // durable and commit-unknown outcomes must keep the candidate in
            // memory and retain its referenced payload.
            state.store = candidate;
            Ok(publish)
        })();
        match store_result {
            Ok(PrivatePublishState::Durable) => {}
            Ok(PrivatePublishState::PublishedDurabilityUncertain) => {
                self.store_publication_durability_uncertain
                    .store(true, AtomicOrdering::Release);
                bail!("memory_save_metadata_commit_unknown_parent_fsync_uncertain_reopen_required");
            }
            Err(error) => {
                let _ = remove_payload_if_present(&self.payload_root, &payload_file);
                return Err(error);
            }
        }
        Ok(result)
    }

    fn list_memory(&self, subject: &Subject, payload: Value) -> Result<Value> {
        let include_payload = payload
            .get("include_payload")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if include_payload {
            bail!("memory_multi_item_raw_payload_retired");
        }
        let limit = payload
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(MAX_MEMORY_PAGE_ITEMS as u64);
        if limit == 0 || limit > MAX_MEMORY_PAGE_ITEMS as u64 {
            bail!("memory_list_limit_outside_bounded_contract");
        }
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        let mut owned = state
            .store
            .memories
            .iter()
            .filter(|item| item.owned_by(subject))
            .cloned()
            .collect::<Vec<_>>();
        owned.sort_by(|left, right| {
            right
                .created_at_ms
                .cmp(&left.created_at_ms)
                .then_with(|| left.memory_id.cmp(&right.memory_id))
        });
        let end = (limit as usize).min(owned.len());
        let page = &owned[..end];
        let items = page
            .iter()
            .map(MemoryMetadata::public_json)
            .collect::<Vec<_>>();
        if items.len() > MAX_MEMORY_PAGE_ITEMS {
            bail!("memory_list_page_internal_bound_exceeded");
        }
        let count = items.len();
        Ok(json!({
            "items": items,
            "count": count,
            "capacity": MAX_MEMORY_PER_SUBJECT,
            "payload_included": false,
        }))
    }

    fn delete_memory(&self, subject: &Subject, request_id: &str, payload: Value) -> Result<Value> {
        let memory_id = bounded_string(&payload, "memory_id", 96)?;
        let expected_payload_sha256 = bounded_string(&payload, "expected_payload_sha256", 64)?;
        let expected_updated_at_ms = payload
            .get("expected_updated_at_ms")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .context("memory_delete_expected_updated_at_denied")?;
        if !is_lower_hex(&expected_payload_sha256, 64) {
            bail!("memory_delete_expected_payload_digest_denied");
        }
        let subject_key = subject.key();

        // A tombstone is the durable commit/recovery authority if the outer
        // UI response was lost after the primary metadata transition.
        let existing = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            state
                .store
                .memory_deletions
                .iter()
                .find(|item| item.request_id == request_id && item.subject_key == subject_key)
                .cloned()
        };
        if let Some(existing) = existing {
            if existing.memory_id != memory_id
                || existing.deleted_payload_sha256 != expected_payload_sha256
                || existing.deleted_updated_at_ms != expected_updated_at_ms
            {
                bail!("memory_delete_tombstone_cas_substitution_denied");
            }
            if existing
                .result
                .get("primary_payload_deleted")
                .and_then(Value::as_bool)
                == Some(false)
            {
                remove_payload_if_present(&self.payload_root, &format!("{memory_id}.enc"))?;
                {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
                    let tombstone = state
                        .store
                        .memory_deletions
                        .iter_mut()
                        .find(|item| {
                            item.request_id == request_id && item.subject_key == subject_key
                        })
                        .context("memory_delete_tombstone_disappeared")?;
                    tombstone
                        .result
                        .as_object_mut()
                        .context("memory_delete_tombstone_result_not_object")?
                        .insert("primary_payload_deleted".to_string(), Value::Bool(true));
                }
                if self.persist()? == PrivatePublishState::PublishedDurabilityUncertain {
                    bail!(
                        "memory_delete_reconciliation_commit_unknown_parent_fsync_uncertain_reopen_required"
                    );
                }
            }
            return self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?
                .store
                .memory_deletions
                .iter()
                .find(|item| item.request_id == request_id && item.subject_key == subject_key)
                .map(|item| item.result.clone())
                .context("memory_delete_tombstone_missing_after_reconciliation");
        }

        let (removed, removed_contexts, before_store, before_grants) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            if state.store.memory_deletions.len() >= MAX_MEMORY_DELETION_TOMBSTONES {
                bail!("memory_deletion_tombstone_capacity_reached");
            }
            let index = state
                .store
                .memories
                .iter()
                .position(|item| item.memory_id == memory_id)
                .context("unknown_memory_id")?;
            if !state.store.memories[index].owned_by(subject) {
                bail!("memory_subject_binding_mismatch");
            }
            if state.store.memories[index].payload_sha256 != expected_payload_sha256
                || state.store.memories[index].updated_at_ms != expected_updated_at_ms
            {
                bail!("memory_delete_cas_changed");
            }
            let before_store = state.store.clone();
            let before_grants = state.grant_store.clone();
            let removed = state.store.memories.remove(index);
            state
                .store
                .memory_saves
                .retain(|item| item.memory_id != memory_id);
            state.store.memory_generation = state
                .store
                .memory_generation
                .checked_add(1)
                .context("memory_generation_exhausted")?;
            let derived_context_ids = state
                .contexts
                .values()
                .filter(|context| {
                    context.subject_key == subject_key
                        && context.parent_memory_id == memory_id
                        && context.parent_memory_payload_sha256 == expected_payload_sha256
                        && context.parent_memory_updated_at_ms == expected_updated_at_ms
                })
                .map(|context| context.context_id.clone())
                .collect::<HashSet<_>>();
            let mut removed_contexts = Vec::with_capacity(derived_context_ids.len());
            for context_id in &derived_context_ids {
                if let Some(context) = state.contexts.remove(context_id) {
                    removed_contexts.push(context);
                }
            }
            let now = now_unix_ms();
            let mut revoked_grants = Vec::new();
            for grant in &mut state.grant_store.grants {
                if grant.owner_uid == subject.uid
                    && grant.owner_selinux_domain == subject.selinux_domain
                    && grant.state == "active"
                    && (grant.resource_kind == "memory" && grant.resource_id == memory_id
                        || grant.resource_kind == "context"
                            && derived_context_ids.contains(&grant.resource_id))
                {
                    grant.state = "revoked".to_string();
                    grant.updated_at_ms = now;
                    revoked_grants.push(grant.clone());
                }
            }
            for grant in &revoked_grants {
                append_agent_data_grant_audit(&mut state.grant_store, "revoke", grant, now)?;
            }
            let result = json!({
                "memory_id": memory_id,
                "deleted_payload_sha256": expected_payload_sha256,
                "deleted_updated_at_ms": expected_updated_at_ms,
                "deleted": true,
                "primary_payload_deleted": false,
                "derived_contexts_revoked": removed_contexts.len(),
                "direct_data_grants_revoked": revoked_grants.len(),
                "derived_execution_payloads_revoked": 0,
                "derived_egress_grants_revoked": 0,
                "derived_external_artifacts_may_remain": true,
                "external_lineage_closure_status": "HOLD_EGRESS_AND_EXECUTION_LINEAGE_NOT_ATOMICALLY_INDEXED",
                "raw_payload_retained": false,
            });
            state.store.memory_deletions.push(MemoryDeletionTombstone {
                schema: MEMORY_DELETION_TOMBSTONE_SCHEMA.to_string(),
                request_id: request_id.to_string(),
                subject_key: subject_key.clone(),
                memory_id: memory_id.clone(),
                deleted_payload_sha256: expected_payload_sha256.clone(),
                deleted_updated_at_ms: expected_updated_at_ms,
                deleted_at_ms: now,
                result,
            });
            (removed, removed_contexts, before_store, before_grants)
        };

        if let Err(error) = self.persist_context_journal() {
            if self.context_journal_publication_is_uncertain() {
                self.store_publication_durability_uncertain
                    .store(true, AtomicOrdering::Release);
                for mut context in removed_contexts {
                    context.content.zeroize();
                }
                return Err(error)
                    .context("memory_delete_context_lineage_commit_unknown_reopen_required");
            }
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            state.store = before_store;
            state.grant_store = before_grants;
            for context in removed_contexts {
                state.contexts.insert(context.context_id.clone(), context);
            }
            return Err(error).context("memory_delete_context_lineage_persistence_failed");
        }
        match self.persist_grant_store() {
            Err(error) => {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
                state.store = before_store;
                state.grant_store = before_grants;
                for context in removed_contexts {
                    state.contexts.insert(context.context_id.clone(), context);
                }
                drop(state);
                let _ = self.persist_context_journal();
                return Err(error).context("memory_delete_grant_lineage_persistence_failed");
            }
            Ok(PrivatePublishState::PublishedDurabilityUncertain) => {
                self.store_publication_durability_uncertain
                    .store(true, AtomicOrdering::Release);
                for mut context in removed_contexts {
                    context.content.zeroize();
                }
                bail!("memory_delete_grant_lineage_commit_unknown_reopen_required");
            }
            Ok(PrivatePublishState::Durable) => {}
        }
        match self.persist() {
            Err(error) => {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
                state.store = before_store;
                state.grant_store = before_grants;
                for context in removed_contexts {
                    state.contexts.insert(context.context_id.clone(), context);
                }
                drop(state);
                let _ = self.persist_context_journal();
                let _ = self.persist_grant_store();
                return Err(error).context("memory_delete_primary_metadata_commit_failed");
            }
            Ok(PrivatePublishState::PublishedDurabilityUncertain) => {
                for mut context in removed_contexts {
                    context.content.zeroize();
                }
                bail!(
                    "memory_delete_primary_metadata_commit_unknown_parent_fsync_uncertain_reopen_required"
                );
            }
            Ok(PrivatePublishState::Durable) => {}
        }
        remove_payload_if_present(&self.payload_root, &removed.payload_file)?;
        let result = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            let tombstone = state
                .store
                .memory_deletions
                .iter_mut()
                .find(|item| item.request_id == request_id && item.subject_key == subject_key)
                .context("memory_delete_tombstone_disappeared")?;
            tombstone
                .result
                .as_object_mut()
                .context("memory_delete_tombstone_result_not_object")?
                .insert("primary_payload_deleted".to_string(), Value::Bool(true));
            tombstone.result.clone()
        };
        if self.persist()? == PrivatePublishState::PublishedDurabilityUncertain {
            for mut context in removed_contexts {
                context.content.zeroize();
            }
            bail!(
                "memory_delete_finalization_commit_unknown_parent_fsync_uncertain_reopen_required"
            );
        }
        for mut context in removed_contexts {
            context.content.zeroize();
        }
        Ok(result)
    }

    fn cleanup(&self) -> Result<()> {
        self.ensure_store_publication_certain()?;
        let now = now_unix_ms();
        let mut expired_files = Vec::new();
        let mut contexts_changed = false;
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            let expired_contexts = state
                .contexts
                .iter()
                .filter(|(_, item)| {
                    if item.revoked {
                        item.tombstone_until_ms <= now
                    } else {
                        item.expires_at_ms <= now
                    }
                })
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            for id in expired_contexts {
                if let Some(mut removed) = state.contexts.remove(&id) {
                    removed.content.zeroize();
                    contexts_changed = true;
                }
            }
            let expired_reservations = state
                .context_import_reservations
                .iter()
                .filter(|(_, reservation)| reservation.expires_at_ms <= now)
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            for id in expired_reservations {
                state.context_import_reservations.remove(&id);
                contexts_changed = true;
            }
            let mut candidate = state.store.clone();
            let before = candidate.memories.len();
            candidate.memories.retain(|item| {
                if item.retention_until_ms <= now {
                    expired_files.push(item.payload_file.clone());
                    false
                } else {
                    true
                }
            });
            let mut changed = before != candidate.memories.len();
            if changed {
                candidate.memory_generation = candidate
                    .memory_generation
                    .checked_add(1)
                    .context("memory_generation_exhausted")?;
            }
            let live_memory_ids = candidate
                .memories
                .iter()
                .map(|memory| memory.memory_id.clone())
                .collect::<HashSet<_>>();
            let before = candidate.memory_saves.len();
            candidate.memory_saves.retain(|item| {
                item.saved_at_ms.saturating_add(REPLAY_RETENTION_MS) > now
                    && live_memory_ids.contains(&item.memory_id)
            });
            changed |= before != candidate.memory_saves.len();
            let before = candidate.replays.len();
            candidate
                .replays
                .retain(|item| item.recorded_at_ms.saturating_add(REPLAY_RETENTION_MS) > now);
            changed |= before != candidate.replays.len();
            let before = candidate.memory_deletions.len();
            candidate
                .memory_deletions
                .retain(|item| item.deleted_at_ms.saturating_add(REPLAY_RETENTION_MS) > now);
            changed |= before != candidate.memory_deletions.len();
            if changed {
                // Keep the live state on the last durable version if the
                // metadata commit fails. Otherwise a later cleanup could see
                // the in-memory dereference and delete a payload still named
                // by the on-disk metadata.
                let publish = persist_store_file(&self.root.join("metadata.json"), &candidate)?;
                state.store = candidate;
                if publish == PrivatePublishState::PublishedDurabilityUncertain {
                    self.store_publication_durability_uncertain
                        .store(true, AtomicOrdering::Release);
                    bail!(
                        "context_memory_cleanup_commit_unknown_parent_fsync_uncertain_reopen_required"
                    );
                }
            }
        }
        if contexts_changed {
            self.persist_context_journal()?;
        }
        for file in &expired_files {
            remove_expired_payload_if_present(&self.payload_root, file)?;
        }
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        prune_orphaned_memory_payloads(&self.payload_root, &state.store)?;
        Ok(())
    }

    fn replay_outcome(
        &self,
        replay_key: &str,
        payload_sha256: &str,
    ) -> Result<Option<std::result::Result<Value, String>>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        if let Some(record) = state.runtime_replays.get(replay_key) {
            if record.payload_sha256 != payload_sha256 {
                bail!("request_id_replay_payload_mismatch");
            }
            return Ok(Some(record.outcome.clone()));
        }
        if let Some(record) = state.store.replays.iter().find(|record| {
            format!(
                "{}:{}:{}",
                record.subject_key, record.method, record.request_id
            ) == replay_key
        }) {
            if record.payload_sha256 != payload_sha256 {
                bail!("request_id_replay_payload_mismatch");
            }
            if record.ok {
                if let Some(result) = &record.result {
                    return Ok(Some(Ok(result.clone())));
                }
                bail!("request_id_replay_requires_fresh_id");
            }
            return Ok(Some(Err(record
                .error
                .clone()
                .unwrap_or_else(|| "context_memory_request_denied".to_string()))));
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    fn record_replay(
        &self,
        replay_key: String,
        method: &str,
        request_id: &str,
        subject: &Subject,
        payload_sha256: String,
        outcome: &Result<Value>,
        persist_result: bool,
    ) -> Result<()> {
        self.ensure_store_publication_certain()?;
        let runtime_outcome = match outcome {
            Ok(value) => Ok(value.clone()),
            Err(error) => Err(error.to_string()),
        };
        let record = ReplayRecord {
            method: method.to_string(),
            request_id: request_id.to_string(),
            subject_key: subject.key(),
            payload_sha256: payload_sha256.clone(),
            recorded_at_ms: now_unix_ms(),
            ok: outcome.is_ok(),
            result: outcome.as_ref().ok().filter(|_| persist_result).cloned(),
            error: outcome.as_ref().err().map(ToString::to_string),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        let mut candidate = state.store.clone();
        candidate.replays.push(record);
        if candidate.replays.len() > MAX_REPLAY_RECORDS {
            let remove = candidate.replays.len() - MAX_REPLAY_RECORDS;
            candidate.replays.drain(0..remove);
        }
        ensure_store_growth_budget(&candidate)?;
        // Publish the durable replay before exposing a runtime hit. A failed
        // metadata write therefore leaves neither a disk success nor a
        // process-only success that would disappear across restart.
        let publish = persist_store_file(&self.root.join("metadata.json"), &candidate)?;
        state.store = candidate;
        if publish == PrivatePublishState::PublishedDurabilityUncertain {
            self.store_publication_durability_uncertain
                .store(true, AtomicOrdering::Release);
            bail!("context_memory_replay_commit_unknown_parent_fsync_uncertain_reopen_required");
        }
        state.runtime_replays.insert(
            replay_key,
            RuntimeReplay {
                payload_sha256,
                outcome: runtime_outcome,
            },
        );
        Ok(())
    }

    fn persist(&self) -> Result<PrivatePublishState> {
        self.ensure_store_publication_certain()?;
        let store = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            state.store.clone()
        };
        let publish = persist_store_file(&self.root.join("metadata.json"), &store)?;
        if publish == PrivatePublishState::PublishedDurabilityUncertain {
            self.store_publication_durability_uncertain
                .store(true, AtomicOrdering::Release);
        }
        Ok(publish)
    }

    fn persist_context_journal(&self) -> Result<()> {
        if self
            .context_journal_publication_durability_uncertain
            .load(AtomicOrdering::Acquire)
        {
            bail!("context_journal_fail_stop_published_durability_uncertain");
        }
        let _journal_guard = self
            .context_journal_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("context_journal_lock_poisoned"))?;
        let (mut contexts, mut reservations) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
            (
                state.contexts.values().cloned().collect::<Vec<_>>(),
                state
                    .context_import_reservations
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        };
        contexts.sort_by(|left, right| left.context_id.cmp(&right.context_id));
        reservations.sort_by(|left, right| left.reservation_id.cmp(&right.reservation_id));
        let journal = ContextJournal {
            schema: CONTEXT_JOURNAL_SCHEMA.to_string(),
            key_id: format!("memory-key-{}", self.key_envelope.key_id),
            boot_id_sha256: self.boot_id_sha256.clone(),
            contexts,
            reservations,
        };
        validate_context_journal(&journal, &self.boot_id_sha256, now_unix_ms())?;
        let clear = Zeroizing::new(serde_json::to_vec(&journal)?);
        if clear.len() > MAX_CONTEXT_JOURNAL_CLEAR_BYTES {
            bail!("context_journal_cleartext_bound_exceeded");
        }
        let encrypted = encrypt_payload(&self.key, CONTEXT_JOURNAL_AAD, clear.as_slice())?;
        if atomic_write_private_staged(&self.context_journal_path, &encrypted)?
            == PrivatePublishState::PublishedDurabilityUncertain
        {
            self.context_journal_publication_durability_uncertain
                .store(true, AtomicOrdering::Release);
            bail!("context_journal_publish_commit_unknown_parent_fsync_uncertain");
        }
        Ok(())
    }

    fn ensure_grant_store_publication_certain(&self) -> Result<()> {
        if self
            .grant_store_publication_durability_uncertain
            .load(AtomicOrdering::Acquire)
        {
            bail!(
                "agent_data_grant_store_fail_stop_published_durability_uncertain_reopen_required"
            );
        }
        Ok(())
    }

    fn persist_grant_store(&self) -> Result<PrivatePublishState> {
        self.ensure_grant_store_publication_certain()?;
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("context_memory_state_poisoned"))?;
        self.persist_grant_store_value(&state.grant_store)
    }

    fn persist_grant_store_value(
        &self,
        grant_store: &AgentDataGrantStore,
    ) -> Result<PrivatePublishState> {
        let mut clear = Zeroizing::new(serde_json::to_vec(grant_store)?);
        if clear.len() > MAX_DATA_GRANT_STORE_BYTES {
            clear.zeroize();
            bail!("agent_data_grant_store_too_large");
        }
        let encrypted = encrypt_payload(&self.key, DATA_GRANT_STORE_AAD, clear.as_slice())?;
        clear.zeroize();
        #[cfg(test)]
        if self
            .fail_next_grant_persist
            .swap(false, AtomicOrdering::SeqCst)
        {
            bail!("injected_agent_data_grant_persistence_failure");
        }
        let publish = atomic_write_private_staged(&self.grant_store_path, &encrypted)?;
        if publish == PrivatePublishState::PublishedDurabilityUncertain {
            self.grant_store_publication_durability_uncertain
                .store(true, AtomicOrdering::Release);
        }
        Ok(publish)
    }

    #[cfg(test)]
    fn fail_next_grant_persist_for_test(&self) {
        self.fail_next_grant_persist
            .store(true, AtomicOrdering::SeqCst);
    }
}

#[cfg(any(test, feature = "legacy-plan-conformance"))]
impl ExecutionPayloadResolver for ContextMemoryService {
    fn resolve_and_consume(
        &self,
        call: &ToolCallInput,
    ) -> std::result::Result<Option<ResolvedExecutionPayload>, String> {
        match call.tool_name.as_str() {
            "android.browser.open_bounded" => self
                .resolve_execution_payload(call)
                .map(Some)
                .map_err(|error| error.to_string()),
            "android.notification.post_bounded" => Ok(None),
            _ => Err("execution_payload_tool_binding_mismatch".to_string()),
        }
    }
}

impl ContextMemoryService {
    #[cfg(any(test, feature = "legacy-plan-conformance"))]
    fn resolve_execution_payload(&self, call: &ToolCallInput) -> Result<ResolvedExecutionPayload> {
        let binding = call
            .agent_execution_binding
            .as_ref()
            .context("execution_payload_missing_os_binding")?;
        let safe_payload = call
            .arguments
            .get("payload")
            .and_then(Value::as_object)
            .context("execution_payload_reference_missing")?;
        if safe_payload.len() != 3 {
            bail!("execution_payload_safe_shape_invalid");
        }
        let reference = safe_payload
            .get("execution_payload_ref")
            .and_then(Value::as_str)
            .context("execution_payload_reference_missing")?;
        let payload_sha256 = safe_payload
            .get("execution_payload_sha256")
            .and_then(Value::as_str)
            .context("execution_payload_digest_missing")?;
        let shape = safe_payload
            .get("execution_payload_shape")
            .and_then(Value::as_str)
            .context("execution_payload_shape_missing")?;
        validate_execution_payload_reference(reference)?;
        if !valid_lower_sha256(payload_sha256) || shape != EXECUTION_PAYLOAD_SHAPE {
            bail!("execution_payload_descriptor_invalid");
        }
        let arguments_sha256 = sha256_json(&call.arguments);
        if binding.arguments_sha256 != arguments_sha256
            || binding.task_id != call.task_id
            || binding.tool_call_id != call.tool_call_id
            || binding.tool_name != call.tool_name
            || call.tool_name != "android.browser.open_bounded"
        {
            bail!("execution_payload_tool_binding_mismatch");
        }
        let context_sha256 = call
            .arguments
            .get("context_sha256")
            .and_then(Value::as_str)
            .context("execution_payload_context_digest_missing")?;
        let _guard = self
            .execution_payload_serial
            .lock()
            .map_err(|_| anyhow::anyhow!("execution_payload_lock_poisoned"))?;
        let path = execution_payload_path(&self.execution_payload_root, reference)?;
        let record = match self.read_execution_payload_record(&path, reference) {
            Ok(record) => record,
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                bail!("execution_payload_missing_or_invalid")
            }
            Err(_) => {
                // A custody denial is not ciphertext corruption. Re-check the
                // unlock gate before any destructive quarantine action.
                self.require_memory_key_unlocked()?;
                self.quarantine_invalid_execution_payload_entry(&path, now_unix_ms())?;
                bail!("execution_payload_corrupt_and_quarantined");
            }
        };
        if validate_stored_execution_payload(&record, reference).is_err() {
            drop(record);
            self.quarantine_invalid_execution_payload_entry(&path, now_unix_ms())?;
            bail!("execution_payload_corrupt_and_quarantined");
        }
        let now = now_unix_ms();
        if record.expires_at_ms <= now {
            remove_private_regular_file(&path, false)?;
            open_private_directory(&self.execution_payload_root)?.sync_all()?;
            bail!("execution_payload_expired_and_destroyed");
        }
        if record.schema != EXECUTION_PAYLOAD_SCHEMA
            || record.reference != reference
            || record.payload_sha256 != payload_sha256
            || record.shape != shape
            || record.owner_uid != binding.origin_uid
            || record.owner_selinux_domain != binding.origin_selinux_domain
            || record.subject_user_id != binding.subject_user_id
            || record.agent_id != binding.agent_id
            || record.agent_peer_uid != binding.peer_uid
            || record.agent_peer_gid != binding.peer_gid
            || record.agent_selinux_domain != binding.peer_selinux_domain
            || record.agent_executable_sha256 != binding.agent_executable_sha256
            || record.task_id != binding.task_id.0
            || record.session_id != binding.session_id
            || record.plan_id != binding.plan_id
            || record.action_id != binding.action_id
            || record.tool_call_id != binding.tool_call_id.0
            || record.tool_name != binding.tool_name
            || record.tool_manifest_sha256 != binding.tool_manifest_sha256
            || record.accepted_plan_sha256 != binding.accepted_plan_sha256
            || record.context_sha256 != context_sha256
            || record.arguments_sha256 != arguments_sha256
            || record.expires_at_ms
                > record
                    .created_at_ms
                    .saturating_add(MAX_EXECUTION_PAYLOAD_TTL_MS)
            || sha256_bytes(record.url.as_bytes()) != record.context_sha256
        {
            bail!("execution_payload_binding_mismatch_or_expired");
        }
        #[derive(Serialize)]
        struct UrlPayload<'a> {
            url: &'a str,
        }
        let encoded = Zeroizing::new(serde_json::to_vec(&UrlPayload { url: &record.url })?);
        if sha256_bytes(encoded.as_slice()) != record.payload_sha256 {
            bail!("execution_payload_cleartext_digest_mismatch");
        }
        let resolved = ResolvedExecutionPayload {
            execution_payload_ref: record.reference.clone(),
            payload_sha256: record.payload_sha256.clone(),
            payload_shape: record.shape.clone(),
            url: Zeroizing::new(record.url.clone()),
        };
        // Consume before the side effect. A crash or gateway failure can never
        // replay this payload; the user must create and approve a new plan.
        remove_private_regular_file(&path, false)?;
        open_private_directory(&self.execution_payload_root)?.sync_all()?;
        Ok(resolved)
    }
}

fn valid_lower_sha256(value: &str) -> bool {
    is_lower_hex(value, 64)
}

pub(super) fn canonical_https_execution_url(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > MAX_EXECUTION_URL_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'"' | b'\\' | b'\'')
        })
    {
        bail!("execution_payload_exact_https_url_required");
    }
    let parsed = Url::parse(value).context("execution_payload_exact_https_url_required")?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none_or(str::is_empty)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        bail!("execution_payload_exact_https_url_required");
    }
    let canonical = parsed.to_string();
    if canonical.len() > MAX_EXECUTION_URL_BYTES {
        bail!("execution_payload_exact_https_url_required");
    }
    Ok(canonical)
}

fn validate_stored_execution_payload(
    record: &StoredExecutionPayload,
    reference: &str,
) -> Result<()> {
    if record.schema != EXECUTION_PAYLOAD_SCHEMA
        || record.reference != reference
        || record.shape != EXECUTION_PAYLOAD_SHAPE
        || !valid_lower_sha256(&record.payload_sha256)
        || !valid_lower_sha256(&record.context_sha256)
        || !valid_lower_sha256(&record.arguments_sha256)
        || !valid_lower_sha256(&record.agent_executable_sha256)
        || !valid_lower_sha256(&record.tool_manifest_sha256)
        || !valid_lower_sha256(&record.accepted_plan_sha256)
        || record.owner_uid < 10_000
        || record.owner_selinux_domain.is_empty()
        || record.agent_id.is_empty()
        || record.agent_selinux_domain.is_empty()
        || record.task_id.is_empty()
        || record.session_id.is_empty()
        || record.plan_id.is_empty()
        || record.action_id.is_empty()
        || record.tool_call_id.is_empty()
        || record.tool_name.is_empty()
        || record.expires_at_ms <= record.created_at_ms
        || record.expires_at_ms
            > record
                .created_at_ms
                .saturating_add(MAX_EXECUTION_PAYLOAD_TTL_MS)
    {
        bail!("invalid_execution_payload_store_identity");
    }
    let canonical = canonical_https_execution_url(&record.url)?;
    if canonical != record.url || sha256_bytes(record.url.as_bytes()) != record.context_sha256 {
        bail!("invalid_execution_payload_cleartext_identity");
    }
    #[derive(Serialize)]
    struct UrlPayload<'a> {
        url: &'a str,
    }
    let encoded = Zeroizing::new(serde_json::to_vec(&UrlPayload { url: &record.url })?);
    if sha256_bytes(encoded.as_slice()) != record.payload_sha256 {
        bail!("invalid_execution_payload_cleartext_digest");
    }
    Ok(())
}

fn validate_execution_payload_reference(reference: &str) -> Result<()> {
    if reference
        .strip_prefix("execution-payload-")
        .is_none_or(|digest| !valid_lower_sha256(digest))
    {
        bail!("invalid_execution_payload_reference");
    }
    Ok(())
}

#[cfg(any(test, feature = "legacy-plan-conformance"))]
fn execution_payload_path(root: &Path, reference: &str) -> Result<PathBuf> {
    validate_execution_payload_reference(reference)?;
    Ok(root.join(format!("{reference}.enc")))
}

fn execution_payload_aad(reference: &str) -> String {
    format!("{EXECUTION_PAYLOAD_AAD_PREFIX}{reference}")
}

fn replay_key(method: &str, request_id: &str, subject: &Subject) -> String {
    format!("{}:{}:{}", subject.key(), method, request_id)
}

fn validate_agent_grant_target(owner: &Subject, target: &AgentGrantTarget) -> Result<()> {
    if target.agent_id.is_empty()
        || target.agent_id.len() > 128
        || target.agent_id.chars().any(char::is_control)
        || target.peer_uid < 10_000
        || target.peer_gid < 10_000
        || target.selinux_domain.is_empty()
        || target.selinux_domain.len() > 256
        || target.selinux_domain.chars().any(char::is_control)
        || !is_lower_hex(&target.executable_sha256, 64)
        || target.task_id.is_empty()
        || target.task_id.len() > 128
        || target.task_id.chars().any(char::is_control)
        || owner.uid / 100_000 != target.subject_user_id
    {
        bail!("invalid_agent_data_grant_target");
    }
    Ok(())
}

fn validate_agent_grant_consumer(consumer: &AgentGrantConsumer) -> Result<()> {
    if consumer.agent_id.is_empty()
        || consumer.agent_id.len() > 128
        || consumer.agent_id.chars().any(char::is_control)
        || consumer.peer_uid < 10_000
        || consumer.peer_gid < 10_000
        || consumer.selinux_domain.is_empty()
        || consumer.selinux_domain.len() > 256
        || consumer.selinux_domain.chars().any(char::is_control)
        || !is_lower_hex(&consumer.executable_sha256, 64)
        || consumer.task_id.is_empty()
        || consumer.task_id.len() > 128
        || consumer.task_id.chars().any(char::is_control)
    {
        bail!("invalid_agent_data_grant_consumer");
    }
    Ok(())
}

fn validate_data_grant_scope(scope: &str, endpoint: &str, ttl_ms: u64) -> Result<()> {
    if ttl_ms == 0 || ttl_ms > MAX_DATA_GRANT_TTL_MS {
        bail!("agent_data_grant_ttl_outside_bounded_contract");
    }
    match scope {
        "none" if endpoint == "none" => Ok(()),
        "provider_planning"
            if !endpoint.is_empty()
                && endpoint.len() <= 256
                && endpoint.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
                }) =>
        {
            Ok(())
        }
        _ => bail!("agent_data_grant_egress_scope_invalid"),
    }
}

fn validate_resource_id(value: &str, prefix: &str) -> Result<()> {
    if value.len() != prefix.len() + 64
        || !value.starts_with(prefix)
        || !is_lower_hex(&value[prefix.len()..], 64)
    {
        bail!("invalid_agent_data_grant_resource_id");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn new_agent_data_grant(
    owner: &Subject,
    target: &AgentGrantTarget,
    resource_kind: &str,
    resource_id: &str,
    resource_sha256: &str,
    source_id: &str,
    source_kind: &str,
    privacy_class: &str,
    raw_allowed: bool,
    egress_scope: &str,
    egress_endpoint: &str,
    issued_at_ms: u64,
    expires_at_ms: u64,
) -> Result<AgentDataGrant> {
    if !raw_allowed && (egress_scope != "none" || egress_endpoint != "none") {
        bail!("metadata_only_grant_cannot_carry_egress_scope");
    }
    if expires_at_ms <= issued_at_ms || !matches!(resource_kind, "context" | "memory") {
        bail!("invalid_agent_data_grant_lifetime_or_kind");
    }
    let mut random = [0u8; 32];
    fill_kernel_random(&mut random)?;
    let grant_id = format!(
        "grant-{}",
        sha256_bytes(
            [
                random.as_slice(),
                target.agent_id.as_bytes(),
                target.task_id.as_bytes(),
                resource_id.as_bytes(),
            ]
            .concat()
            .as_slice(),
        )
    );
    Ok(AgentDataGrant {
        schema: DATA_GRANT_SCHEMA.to_string(),
        grant_id,
        resource_kind: resource_kind.to_string(),
        resource_id: resource_id.to_string(),
        resource_sha256: resource_sha256.to_string(),
        source_id: source_id.to_string(),
        source_kind: source_kind.to_string(),
        privacy_class: privacy_class.to_string(),
        owner_uid: owner.uid,
        owner_selinux_domain: owner.selinux_domain.clone(),
        subject_user_id: target.subject_user_id,
        agent_id: target.agent_id.clone(),
        agent_peer_uid: target.peer_uid,
        agent_peer_gid: target.peer_gid,
        agent_selinux_domain: target.selinux_domain.clone(),
        agent_executable_sha256: target.executable_sha256.clone(),
        task_id: target.task_id.clone(),
        raw_allowed,
        egress_scope: egress_scope.to_string(),
        egress_endpoint: egress_endpoint.to_string(),
        single_use: raw_allowed,
        state: "active".to_string(),
        issued_at_ms,
        expires_at_ms,
        updated_at_ms: issued_at_ms,
    })
}

fn append_agent_data_grant_audit(
    store: &mut AgentDataGrantStore,
    event_type: &str,
    grant: &AgentDataGrant,
    created_at_ms: u64,
) -> Result<()> {
    if !matches!(
        event_type,
        "issue" | "consume" | "revoke" | "expire" | "identity_invalidate"
    ) {
        bail!("invalid_agent_data_grant_audit_event");
    }
    let mut random = [0u8; 16];
    fill_kernel_random(&mut random)?;
    let event_id = format!(
        "grant-event-{}",
        sha256_bytes(
            [
                random.as_slice(),
                event_type.as_bytes(),
                grant.grant_id.as_bytes(),
                created_at_ms.to_string().as_bytes(),
            ]
            .concat()
            .as_slice(),
        )
    );
    store.audit_events.push(AgentDataGrantAuditEvent {
        schema: DATA_GRANT_AUDIT_SCHEMA.to_string(),
        event_id,
        event_type: event_type.to_string(),
        grant_id: grant.grant_id.clone(),
        resource_kind: grant.resource_kind.clone(),
        agent_id: grant.agent_id.clone(),
        task_id: grant.task_id.clone(),
        subject_user_id: grant.subject_user_id,
        created_at_ms,
    });
    if store.audit_events.len() > MAX_DATA_GRANT_AUDIT_EVENTS {
        let remove = store.audit_events.len() - MAX_DATA_GRANT_AUDIT_EVENTS;
        store.audit_events.drain(0..remove);
    }
    Ok(())
}

fn migrate_legacy_agent_data_grants(store: &mut AgentDataGrantStore) -> Result<bool> {
    if store.schema == DATA_GRANT_STORE_SCHEMA {
        return Ok(false);
    }
    if store.schema != LEGACY_DATA_GRANT_STORE_SCHEMA {
        bail!("invalid_agent_data_grant_store_contract");
    }
    if store
        .grants
        .iter()
        .any(|grant| grant.schema != LEGACY_DATA_GRANT_SCHEMA || grant.agent_peer_gid != 0)
    {
        bail!("legacy_agent_data_grant_identity_migration_denied");
    }
    let now = now_unix_ms();
    let mut invalidated = Vec::with_capacity(store.grants.len());
    for grant in &mut store.grants {
        grant.schema = DATA_GRANT_SCHEMA.to_string();
        grant.state = "identity_invalidated".to_string();
        grant.updated_at_ms = now.max(grant.issued_at_ms);
        invalidated.push(grant.clone());
    }
    for grant in &invalidated {
        append_agent_data_grant_audit(store, "identity_invalidate", grant, now)?;
    }
    store.schema = DATA_GRANT_STORE_SCHEMA.to_string();
    Ok(true)
}

fn expire_agent_data_grants(store: &mut AgentDataGrantStore, now: u64) -> Result<bool> {
    let mut expired = Vec::new();
    for grant in &mut store.grants {
        if grant.state == "active" && grant.expires_at_ms <= now {
            grant.state = "expired".to_string();
            grant.updated_at_ms = now;
            expired.push(grant.clone());
        }
    }
    for grant in &expired {
        append_agent_data_grant_audit(store, "expire", grant, now)?;
    }
    Ok(!expired.is_empty())
}

fn prune_agent_data_grants(store: &mut AgentDataGrantStore, now: u64) {
    store.grants.retain(|grant| {
        grant.state == "active" || grant.updated_at_ms.saturating_add(DATA_GRANT_RETENTION_MS) > now
    });
    store
        .audit_events
        .retain(|event| event.created_at_ms.saturating_add(DATA_GRANT_RETENTION_MS) > now);
    while store.grants.len() >= MAX_DATA_GRANTS {
        let Some((index, _)) = store
            .grants
            .iter()
            .enumerate()
            .filter(|(_, grant)| grant.state != "active")
            .min_by_key(|(_, grant)| grant.updated_at_ms)
        else {
            break;
        };
        store.grants.remove(index);
    }
}

fn validate_agent_data_grant_store(store: &AgentDataGrantStore) -> Result<()> {
    if store.schema != DATA_GRANT_STORE_SCHEMA
        || store.grants.len() > MAX_DATA_GRANTS
        || store.audit_events.len() > MAX_DATA_GRANT_AUDIT_EVENTS
    {
        bail!("invalid_agent_data_grant_store_contract");
    }
    for grant in &store.grants {
        let complete_kernel_identity = grant.agent_peer_gid >= 10_000;
        let legacy_identity_invalidated =
            grant.state == "identity_invalidated" && grant.agent_peer_gid == 0;
        validate_resource_id(&grant.grant_id, "grant-")?;
        validate_resource_id(
            &grant.resource_id,
            if grant.resource_kind == "context" {
                "context-"
            } else if grant.resource_kind == "memory" {
                "memory-"
            } else {
                bail!("invalid_agent_data_grant_resource_kind")
            },
        )?;
        if grant.schema != DATA_GRANT_SCHEMA
            || !is_lower_hex(&grant.resource_sha256, 64)
            || grant.owner_uid < 10_000
            || grant.owner_selinux_domain.is_empty()
            || grant.subject_user_id != grant.owner_uid / 100_000
            || grant.agent_id.is_empty()
            || grant.agent_peer_uid < 10_000
            || (!complete_kernel_identity && !legacy_identity_invalidated)
            || grant.agent_selinux_domain.is_empty()
            || !is_lower_hex(&grant.agent_executable_sha256, 64)
            || grant.task_id.is_empty()
            || !matches!(
                grant.state.as_str(),
                "active" | "consumed" | "revoked" | "expired" | "identity_invalidated"
            )
            || (grant.state == "identity_invalidated" && !legacy_identity_invalidated)
            || grant.expires_at_ms <= grant.issued_at_ms
            || grant.updated_at_ms < grant.issued_at_ms
            || grant.single_use != grant.raw_allowed
        {
            bail!("invalid_agent_data_grant_record");
        }
        validate_data_grant_scope(
            &grant.egress_scope,
            &grant.egress_endpoint,
            grant.expires_at_ms.saturating_sub(grant.issued_at_ms),
        )?;
    }
    for event in &store.audit_events {
        if event.schema != DATA_GRANT_AUDIT_SCHEMA
            || !matches!(
                event.event_type.as_str(),
                "issue" | "consume" | "revoke" | "expire" | "identity_invalidate"
            )
            || !event.event_id.starts_with("grant-event-")
            || !is_lower_hex(event.event_id.trim_start_matches("grant-event-"), 64)
            || validate_resource_id(&event.grant_id, "grant-").is_err()
        {
            bail!("invalid_agent_data_grant_audit_record");
        }
    }
    Ok(())
}

fn ui_replay_associated_data(
    subject: &Subject,
    method: &str,
    request_id: &str,
    payload_sha256: &str,
) -> Vec<u8> {
    ui_replay_associated_data_for_subject_key(&subject.key(), method, request_id, payload_sha256)
}

fn ui_replay_associated_data_for_subject_key(
    subject_key: &str,
    method: &str,
    request_id: &str,
    payload_sha256: &str,
) -> Vec<u8> {
    format!(
        "trillionnium-os-ui-replay-v3\npolicy_epoch={}\nprovider_abi_epoch={}\nsubject={}\nmethod={}\nrequest_id={}\npayload_sha256={}\n",
        UI_REPLAY_POLICY_EPOCH,
        UI_REPLAY_PROVIDER_ABI_EPOCH,
        subject_key,
        method,
        request_id,
        payload_sha256
    )
    .into_bytes()
}

fn ui_replay_associated_data_for_record(record: &UiReplayRecord) -> Result<Vec<u8>> {
    let version = match record.schema.as_str() {
        UI_REPLAY_SCHEMA => "v3",
        LEGACY_V2_UI_REPLAY_SCHEMA => "v2",
        _ => bail!("ui_replay_legacy_v1_outcome_aad_retired"),
    };
    Ok(format!(
        "trillionnium-os-ui-replay-{version}\npolicy_epoch={}\nprovider_abi_epoch={}\nsubject={}\nmethod={}\nrequest_id={}\npayload_sha256={}\n",
        record.policy_epoch,
        record.provider_abi_epoch,
        record.subject_key,
        record.method,
        record.request_id,
        record.payload_sha256,
    )
    .into_bytes())
}

fn ui_replay_archive_indices(request_id: &str) -> Vec<usize> {
    let bit_count = UI_REPLAY_ARCHIVE_BYTES * 8;
    (0..UI_REPLAY_ARCHIVE_HASH_COUNT)
        .map(|ordinal| {
            let mut hasher = Sha256::new();
            hasher.update(b"trillionnium-ui-replay-archive-v1\n");
            hasher.update((ordinal as u64).to_be_bytes());
            hasher.update(request_id.as_bytes());
            let digest = hasher.finalize();
            let mut prefix = [0u8; 8];
            prefix.copy_from_slice(&digest[..8]);
            (u64::from_be_bytes(prefix) % bit_count as u64) as usize
        })
        .collect()
}

fn load_or_create_ui_replay_archive(
    path: &Path,
    archive_initialized: bool,
) -> Result<UiReplayArchive> {
    if !private_entry_exists(path)? {
        if archive_initialized {
            bail!("ui_replay_archive_missing_after_initialization_fail_closed");
        }
        let archive = UiReplayArchive::empty();
        persist_ui_replay_archive(path, &archive)?;
        return Ok(archive);
    }
    let encoded = read_private_bounded_file(path, MAX_UI_REPLAY_ARCHIVE_FILE_BYTES)?;
    let persisted: UiReplayArchiveFile =
        serde_json::from_slice(&encoded).context("invalid_ui_replay_archive_json")?;
    if persisted.schema != UI_REPLAY_ARCHIVE_SCHEMA
        || persisted.bit_count != UI_REPLAY_ARCHIVE_BYTES * 8
        || persisted.hash_count != UI_REPLAY_ARCHIVE_HASH_COUNT
        || persisted.max_set_bits != UI_REPLAY_ARCHIVE_MAX_SET_BITS
        || persisted.updated_at_ms > now_unix_ms().saturating_add(5 * 60 * 1_000)
    {
        bail!("invalid_ui_replay_archive_contract");
    }
    let bits = if persisted.set_bits == 0 && persisted.bits_b64.is_empty() {
        vec![0; UI_REPLAY_ARCHIVE_BYTES]
    } else {
        let decoded = BASE64_STANDARD
            .decode(&persisted.bits_b64)
            .context("invalid_ui_replay_archive_bits")?;
        if BASE64_STANDARD.encode(&decoded) != persisted.bits_b64 {
            bail!("invalid_ui_replay_archive_noncanonical_bits");
        }
        decoded
    };
    let actual_set_bits = bits
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum::<usize>();
    if bits.len() != UI_REPLAY_ARCHIVE_BYTES
        || actual_set_bits != persisted.set_bits
        || actual_set_bits > UI_REPLAY_ARCHIVE_MAX_SET_BITS
    {
        bail!("invalid_ui_replay_archive_density");
    }
    Ok(UiReplayArchive {
        bits,
        set_bits: actual_set_bits,
        insertions: persisted.insertions,
    })
}

fn persist_ui_replay_archive(path: &Path, archive: &UiReplayArchive) -> Result<()> {
    if archive.bits.len() != UI_REPLAY_ARCHIVE_BYTES
        || archive.set_bits
            != archive
                .bits
                .iter()
                .map(|byte| byte.count_ones() as usize)
                .sum::<usize>()
        || archive.set_bits > UI_REPLAY_ARCHIVE_MAX_SET_BITS
    {
        bail!("invalid_ui_replay_archive_state");
    }
    let persisted = UiReplayArchiveFile {
        schema: UI_REPLAY_ARCHIVE_SCHEMA.to_string(),
        bit_count: UI_REPLAY_ARCHIVE_BYTES * 8,
        hash_count: UI_REPLAY_ARCHIVE_HASH_COUNT,
        max_set_bits: UI_REPLAY_ARCHIVE_MAX_SET_BITS,
        // Keep the initialization checkpoint tiny. Once the first identity is
        // archived, the complete fixed-width bitset is always serialized.
        bits_b64: if archive.set_bits == 0 {
            String::new()
        } else {
            BASE64_STANDARD.encode(&archive.bits)
        },
        set_bits: archive.set_bits,
        insertions: archive.insertions,
        updated_at_ms: now_unix_ms(),
    };
    let encoded = serde_json::to_vec_pretty(&persisted)?;
    if encoded.len() > MAX_UI_REPLAY_ARCHIVE_FILE_BYTES {
        bail!("ui_replay_archive_file_bound_exceeded");
    }
    atomic_write_private(path, &encoded)
}

fn load_ui_replay_record(path: &Path) -> Result<UiReplayRecord> {
    let bytes = read_private_bounded_file(path, 16 * 1024)?;
    let record: UiReplayRecord =
        serde_json::from_slice(&bytes).context("invalid_ui_replay_record")?;
    if record.schema == UI_REPLAY_SCHEMA && serde_json::to_vec_pretty(&record)? != bytes {
        bail!("ui_replay_record_not_canonical_closed_world_json");
    }
    let schema_valid = matches!(
        record.schema.as_str(),
        UI_REPLAY_SCHEMA | LEGACY_V2_UI_REPLAY_SCHEMA | LEGACY_UI_REPLAY_SCHEMA
    );
    let epoch_shape_valid = if record.schema == UI_REPLAY_SCHEMA {
        record.policy_epoch == UI_REPLAY_POLICY_EPOCH
            && record.provider_abi_epoch == UI_REPLAY_PROVIDER_ABI_EPOCH
    } else if record.schema == LEGACY_V2_UI_REPLAY_SCHEMA {
        record.policy_epoch == LEGACY_V2_UI_REPLAY_POLICY_EPOCH
            && record.provider_abi_epoch == LEGACY_V2_UI_REPLAY_PROVIDER_ABI_EPOCH
    } else {
        record.policy_epoch == 0 && record.provider_abi_epoch == 0
    };
    let state_valid = matches!(record.state.as_str(), "in_progress" | "completed");
    let outcome_valid = if record.state == "completed" {
        let reference_valid = record.outcome_file.len() == 68
            && record.outcome_file.ends_with(".enc")
            && is_lower_hex(record.outcome_file.trim_end_matches(".enc"), 64);
        if record.schema == UI_REPLAY_SCHEMA {
            reference_valid
                && is_lower_hex(&record.outcome_ciphertext_sha256, 64)
                && is_lower_hex(&record.outcome_semantic_sha256, 64)
        } else {
            reference_valid
                && record.outcome_ciphertext_sha256.is_empty()
                && record.outcome_semantic_sha256.is_empty()
                && record.custody_handoff_ack.is_none()
        }
    } else {
        record.outcome_file.is_empty()
            && record.outcome_ciphertext_sha256.is_empty()
            && record.outcome_semantic_sha256.is_empty()
            && record.custody_handoff_ack.is_none()
    };
    if !schema_valid
        || !epoch_shape_valid
        || !state_valid
        || !outcome_valid
        || validate_request_id(&record.request_id).is_err()
        || !is_known_ui_replay_method(&record.method)
        || !is_valid_ui_replay_subject_key(&record.subject_key)
        || !is_lower_hex(&record.payload_sha256, 64)
        || record.recorded_at_ms == 0
        || record.recorded_at_ms > now_unix_ms().saturating_add(5 * 60 * 1_000)
    {
        bail!("invalid_ui_replay_record_contract");
    }
    if let Some(ack) = &record.custody_handoff_ack {
        validate_ui_replay_handoff_ack_shape(ack)?;
    }
    Ok(record)
}

fn is_known_ui_replay_method(method: &str) -> bool {
    matches!(
        method,
        "health"
            | "get_context"
            | "recover_context_capture"
            | "plan"
            | "prepare_egress"
            | "revoke_egress"
            | "approve"
            | "undo"
            | "provision_codex"
            | "authority_key_metadata"
            | "revoke_context"
            | "list_memory"
            | "save_memory"
            | "delete_memory"
            | "select_memory_context"
            | "recover_memory_context"
            | "recover_egress_prepare"
            | "grant_context_to_agent"
            | "grant_memory_to_agent"
            | "revoke_agent_data_grant"
            | "egress_status"
            | "cancel"
            | "agent.read_context_grant"
    )
}

fn is_valid_ui_replay_subject_key(subject_key: &str) -> bool {
    if subject_key.len() > 96 || subject_key.chars().any(char::is_control) {
        return false;
    }
    let Some((uid, domain_sha256)) = subject_key.split_once(':') else {
        return false;
    };
    if domain_sha256.contains(':') || !is_lower_hex(domain_sha256, 64) {
        return false;
    }
    let Ok(parsed_uid) = uid.parse::<u32>() else {
        return false;
    };
    parsed_uid >= 10_000 && parsed_uid.to_string() == uid
}

fn validate_ui_replay_handoff_ack_shape(ack: &UiReplayCustodyHandoffAck) -> Result<()> {
    if ack.schema != UI_REPLAY_CUSTODY_HANDOFF_SCHEMA
        || !matches!(
            ack.owner_kind.as_str(),
            "egress_lifecycle_journal" | "action_workflow_journal" | "ui_replay_self_terminal"
        )
        || ack.owner_id.is_empty()
        || ack.owner_id.len() > 160
        || ack.owner_id.chars().any(char::is_control)
        || !is_lower_hex(&ack.completion_proof_sha256, 64)
        || ack.acknowledged_at_ms == 0
    {
        bail!("invalid_ui_replay_custody_handoff_ack");
    }
    Ok(())
}

fn validate_ui_replay_custody_owner(
    record: &UiReplayRecord,
    envelope: &Value,
    owner_kind: &str,
    owner_id: &str,
) -> Result<()> {
    match record.method.as_str() {
        "prepare_egress" | "revoke_egress" => {
            if envelope.get("ok").and_then(Value::as_bool) == Some(false) {
                if owner_kind == "ui_replay_self_terminal" && owner_id == record.request_id {
                    return Ok(());
                }
                if owner_kind == "egress_lifecycle_journal"
                    && validate_resource_id(owner_id, "egress-").is_ok()
                {
                    // The caller may write this only after the exact lifecycle
                    // journal accepted the same completion-proof digest.
                    return Ok(());
                }
                bail!("ui_replay_egress_error_custody_owner_mismatch");
            }
            let grant_id = envelope
                .get("result")
                .and_then(|result| result.get("egress_grant_id"))
                .and_then(Value::as_str)
                .context("ui_replay_egress_owner_id_missing")?;
            validate_resource_id(grant_id, "egress-")?;
            if owner_kind != "egress_lifecycle_journal" || owner_id != grant_id {
                bail!("ui_replay_custody_handoff_owner_binding_mismatch");
            }
            Ok(())
        }
        "plan" | "approve" => {
            if owner_kind != "action_workflow_journal" || owner_id != record.request_id {
                bail!("ui_replay_custody_handoff_owner_binding_mismatch");
            }
            Ok(())
        }
        _ => bail!("ui_replay_method_has_no_downstream_custody_owner"),
    }
}

fn ui_replay_method_requires_custody_handoff(method: &str) -> bool {
    matches!(
        method,
        "prepare_egress" | "revoke_egress" | "plan" | "approve"
    )
}

fn validate_ui_replay_handoff_against_pair(
    record: &UiReplayRecord,
    proof: &UiReplayCompletionProof,
    envelope: &Value,
    ack: &UiReplayCustodyHandoffAck,
) -> Result<()> {
    validate_ui_replay_handoff_ack_shape(ack)?;
    let proof_sha256 = proof.digest_sha256()?;
    validate_ui_replay_custody_owner(record, envelope, &ack.owner_kind, &ack.owner_id)?;
    if ack.completion_proof_sha256 != proof_sha256 || ack.acknowledged_at_ms < record.recorded_at_ms
    {
        bail!("ui_replay_custody_handoff_pair_binding_mismatch");
    }
    Ok(())
}

fn validate_ui_replay_identity(
    record: &UiReplayRecord,
    method: &str,
    request_id: &str,
    subject: &Subject,
    payload_sha256: &str,
) -> Result<()> {
    if record.request_id != request_id
        || record.method != method
        || record.subject_key != subject.key()
        || record.payload_sha256 != payload_sha256
    {
        bail!("ui_request_id_replay_identity_or_payload_mismatch");
    }
    if record.schema != UI_REPLAY_SCHEMA
        || record.policy_epoch != UI_REPLAY_POLICY_EPOCH
        || record.provider_abi_epoch != UI_REPLAY_PROVIDER_ABI_EPOCH
    {
        // Never decrypt or return a success created under a retired provider
        // policy/ABI; historical results remain tombstoned without leaking
        // their grant or receipt.
        bail!("ui_request_policy_or_provider_abi_epoch_retired_hold");
    }
    Ok(())
}

fn decode_ui_replay_outcome(envelope: &Value) -> Result<Value> {
    if envelope.get("policy_epoch").and_then(Value::as_u64) != Some(UI_REPLAY_POLICY_EPOCH)
        || envelope.get("provider_abi_epoch").and_then(Value::as_u64)
            != Some(UI_REPLAY_PROVIDER_ABI_EPOCH)
    {
        bail!("ui_replay_outcome_policy_or_provider_abi_epoch_mismatch");
    }
    match envelope.get("ok").and_then(Value::as_bool) {
        Some(true) => envelope
            .get("result")
            .cloned()
            .context("ui_replay_success_result_missing"),
        Some(false) => Err(anyhow::Error::msg(
            envelope
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("ui_request_denied")
                .to_string(),
        )),
        None => bail!("invalid_ui_replay_outcome_contract"),
    }
}

fn validate_canonical_ui_replay_envelope(method: &str, envelope: &Value) -> Result<()> {
    validate_canonical_ui_replay_envelope_for_epochs(
        method,
        envelope,
        UI_REPLAY_POLICY_EPOCH,
        UI_REPLAY_PROVIDER_ABI_EPOCH,
    )
}

fn validate_canonical_ui_replay_envelope_for_epochs(
    method: &str,
    envelope: &Value,
    policy_epoch: u64,
    provider_abi_epoch: u64,
) -> Result<()> {
    let object = envelope
        .as_object()
        .context("ui_replay_outcome_envelope_not_object")?;
    let ok = object
        .get("ok")
        .and_then(Value::as_bool)
        .context("ui_replay_outcome_ok_missing")?;
    let mut expected = HashSet::from([
        "ok",
        "policy_epoch",
        "provider_abi_epoch",
        if ok { "result" } else { "error" },
    ]);
    if object.contains_key("memory_provenance") {
        expected.insert("memory_provenance");
    }
    if object.len() != expected.len()
        || object.keys().any(|key| !expected.contains(key.as_str()))
        || object.get("policy_epoch").and_then(Value::as_u64) != Some(policy_epoch)
        || object.get("provider_abi_epoch").and_then(Value::as_u64) != Some(provider_abi_epoch)
    {
        bail!("ui_replay_outcome_closed_world_contract_denied");
    }
    if ok {
        object
            .get("result")
            .context("ui_replay_success_result_missing")?;
    } else {
        let error = object
            .get("error")
            .and_then(Value::as_str)
            .context("ui_replay_error_string_missing")?;
        if error.is_empty() || error.len() > 16 * 1024 || error.chars().any(char::is_control) {
            bail!("ui_replay_error_string_boundary_denied");
        }
        if method == "plan" && error != "plan_request_failed" {
            bail!("ui_replay_plan_error_not_canonical");
        }
    }
    if let Some(provenance) = object.get("memory_provenance")
        && (!ok || !provenance.is_object())
    {
        bail!("ui_replay_memory_provenance_shape_denied");
    }
    Ok(())
}

fn ui_replay_completion_proof_digest(proof: &UiReplayCompletionProof) -> Result<String> {
    if proof.schema != UI_REPLAY_COMPLETION_PROOF_SCHEMA
        || proof.policy_epoch != UI_REPLAY_POLICY_EPOCH
        || proof.provider_abi_epoch != UI_REPLAY_PROVIDER_ABI_EPOCH
        || validate_request_id(&proof.request_id).is_err()
        || proof.method.is_empty()
        || proof.subject_key.is_empty()
        || !is_lower_hex(&proof.payload_sha256, 64)
        || !is_lower_hex(&proof.outcome_ciphertext_sha256, 64)
        || !is_lower_hex(&proof.outcome_semantic_sha256, 64)
        || proof.outcome_file != format!("{}.enc", sha256_bytes(proof.request_id.as_bytes()))
    {
        bail!("ui_replay_completion_proof_shape_denied");
    }
    Ok(sha256_json(&json!({
        "schema": proof.schema,
        "policy_epoch": proof.policy_epoch,
        "provider_abi_epoch": proof.provider_abi_epoch,
        "method": proof.method,
        "request_id": proof.request_id,
        "subject_key": proof.subject_key,
        "payload_sha256": proof.payload_sha256,
        "outcome_file": proof.outcome_file,
        "outcome_ciphertext_sha256": proof.outcome_ciphertext_sha256,
        "outcome_semantic_sha256": proof.outcome_semantic_sha256,
    })))
}

fn durable_ui_replay_envelope(method: &str, payload: &Value, outcome: &Result<Value>) -> Value {
    let mut envelope = match outcome {
        Ok(result) if method == "plan" => {
            let mut durable = result.clone();
            if let Some(object) = durable.as_object_mut()
                && object.contains_key("summary")
            {
                object.insert(
                    "summary".to_string(),
                    json!("Plan completed; sensitive provider text is not retained for replay."),
                );
            }
            json!({ "ok": true, "result": durable })
        }
        Ok(result) => json!({ "ok": true, "result": result }),
        Err(_) if method == "plan" => json!({
            "ok": false,
            "error": "plan_request_failed",
        }),
        Err(error) => json!({ "ok": false, "error": error.to_string() }),
    };
    if let Ok(result) = outcome
        && let Some(provenance) = ui_result_memory_provenance(method, payload, result)
        && let Some(object) = envelope.as_object_mut()
    {
        object.insert("memory_provenance".to_string(), provenance);
    }
    if let Some(object) = envelope.as_object_mut() {
        object.insert("policy_epoch".to_string(), json!(UI_REPLAY_POLICY_EPOCH));
        object.insert(
            "provider_abi_epoch".to_string(),
            json!(UI_REPLAY_PROVIDER_ABI_EPOCH),
        );
    }
    envelope
}

fn ui_result_memory_provenance(method: &str, payload: &Value, result: &Value) -> Option<Value> {
    match method {
        "prepare_egress" => {
            let workflow_id = bounded_value(payload, "workflow_id", 128)?;
            let provider_id = bounded_value(payload, "provider", 64)?;
            let context_id = bounded_value(result, "context_id", 96)?;
            let egress_grant_id = bounded_value(result, "egress_grant_id", 96)?;
            let context_sha256 = result.get("content_sha256")?.as_str()?;
            if payload.get("context_id")?.as_str()? != context_id
                || result.get("provider")?.as_str()? != provider_id
                || validate_resource_id(context_id, "context-").is_err()
                || validate_resource_id(egress_grant_id, "egress-").is_err()
                || !valid_lower_sha256(context_sha256)
            {
                return None;
            }
            Some(json!({
                "schema": UI_MEMORY_PROVENANCE_SCHEMA,
                "kind": "egress_prepared",
                "workflow_id": workflow_id,
                "provider_id": provider_id,
                "context_id": context_id,
                "context_sha256": context_sha256,
                "egress_grant_id": egress_grant_id,
            }))
        }
        "plan" => {
            let workflow_id = bounded_value(payload, "workflow_id", 128)?;
            let provider_id = bounded_value(payload, "provider", 64)?;
            let egress_grant_id = bounded_value(payload, "egress_grant_id", 96)?;
            let task_id = bounded_value(result, "task_id", 128)?;
            let plan_id = result.get("plan_id")?.as_str()?;
            let action = bounded_value(result, "action", 96)?;
            let summary = bounded_value(result, "summary", MAX_CONTEXT_BYTES)?;
            let provider_output_sha256 = result.get("provider_output_sha256")?.as_str()?;
            let execution_available = result.get("execution_available")?.as_bool()?;
            let result_provider_id = result.get("provider_id")?.as_str()?;
            if result_provider_id != provider_id
                || validate_resource_id(egress_grant_id, "egress-").is_err()
                || !valid_lower_sha256(provider_output_sha256)
                || (execution_available
                    && (plan_id.is_empty()
                        || plan_id.len() > 128
                        || !matches!(action, "browser_open_bounded" | "notification_post_bounded")))
                || (!execution_available
                    && (!plan_id.is_empty() || action != "context_summary_read_only"))
            {
                return None;
            }
            Some(json!({
                "schema": UI_MEMORY_PROVENANCE_SCHEMA,
                "kind": "planning_result",
                "workflow_id": workflow_id,
                "provider_id": provider_id,
                "egress_grant_id": egress_grant_id,
                "task_id": task_id,
                "plan_id": plan_id,
                "action": action,
                "provider_output_sha256": provider_output_sha256,
                "result_payload_sha256": sha256_bytes(summary.as_bytes()),
                "execution_available": execution_available,
            }))
        }
        "approve" => {
            let workflow_id = bounded_value(payload, "workflow_id", 128)?;
            let task_id = bounded_value(payload, "task_id", 128)?;
            let result_task_id = bounded_value(result, "task_id", 128)?;
            let action = bounded_value(result, "action", 96)?;
            let receipt_id = result.get("receipt_id")?.as_str()?;
            let receipt_json = result.get("receipt_json")?.as_str()?;
            let receipt: Value = serde_json::from_str(receipt_json).ok()?;
            let plan_id = bounded_value(&receipt, "plan_id", 128)?;
            let context_sha256 = receipt.get("context_sha256")?.as_str()?;
            let provider_output_sha256 = receipt.get("provider_output_sha256")?.as_str()?;
            let receipt_action = receipt.get("action")?.as_str()?;
            if result_task_id != task_id
                || action != receipt_action
                || !result.get("action_ok")?.as_bool()?
                || !result.get("explicit_approval")?.as_bool()?
                || !result.get("single_use_consumed")?.as_bool()?
                || receipt.get("schema")?.as_str()? != "org.trillionnium.ai-authority.receipt.v2"
                || receipt.get("decision")?.as_str()? != "PASS_BOUNDED_ACTION"
                || receipt.get("receipt_id")?.as_str()? != receipt_id
                || receipt.get("task_id")?.as_str()? != task_id
                || !valid_lower_sha256(receipt_id)
                || !valid_lower_sha256(context_sha256)
                || !valid_lower_sha256(provider_output_sha256)
            {
                return None;
            }
            Some(json!({
                "schema": UI_MEMORY_PROVENANCE_SCHEMA,
                "kind": "action_result",
                "workflow_id": workflow_id,
                "task_id": task_id,
                "plan_id": plan_id,
                "action": action,
                "context_sha256": context_sha256,
                "provider_output_sha256": provider_output_sha256,
                "receipt_id": receipt_id,
                "subject_user_id": receipt.get("subject_user_id")?.as_u64()?,
                "origin_uid": receipt.get("origin_uid")?.as_u64()?,
            }))
        }
        _ => None,
    }
}

fn bounded_value<'a>(value: &'a Value, key: &str, max: usize) -> Option<&'a str> {
    value
        .get(key)?
        .as_str()
        .filter(|text| !text.is_empty() && text.len() <= max && !text.as_bytes().contains(&0))
}

fn remove_replay_outcome_if_present(root: &Path, file: &str) -> Result<()> {
    if !file.ends_with(".enc")
        || file.len() != 68
        || !is_lower_hex(file.trim_end_matches(".enc"), 64)
    {
        bail!("invalid_ui_replay_outcome_reference");
    }
    let path = root.join(file);
    remove_private_regular_file(&path, true)
}

fn validate_authority_key_pin_state(pin: &AuthorityKeyPin) -> Result<()> {
    if pin.schema != AUTHORITY_PIN_SCHEMA
        || !is_lower_hex(&pin.key_id, 64)
        || pin.key_epoch == 0
        || pin.pinned_at_ms == 0
        || sha256_bytes(&base64_decode(&pin.public_key_spki)?) != pin.key_id
        || !matches!(
            pin.security_level.as_str(),
            "STRONGBOX" | "TRUSTED_ENVIRONMENT"
        )
        || pin.rotation_contract != AUTHORITY_ROTATION_CONTRACT
        || pin.attestation_verified
    {
        bail!("invalid_authority_key_pin_state");
    }
    match pin.key_profile.as_str() {
        AUTHORITY_ATTESTED_KEY_PROFILE
            if pin.attestation_chain_present
                && pin.attestation_challenge_sha256
                    == sha256_bytes(AUTHORITY_ATTESTATION_CHALLENGE) => {}
        AUTHORITY_USERDEBUG_LOCAL_HARDWARE_KEY_PROFILE
            if authority_userdebug_local_profile_enabled()
                && !pin.attestation_chain_present
                && pin.attestation_challenge_sha256 == AUTHORITY_ATTESTATION_UNAVAILABLE => {}
        _ => bail!("invalid_authority_key_pin_profile"),
    }
    Ok(())
}

fn authority_key_pin_value(pin: &AuthorityKeyPin) -> Result<Value> {
    validate_authority_key_pin_state(pin)?;
    Ok(json!({
        "schema": pin.schema,
        "key_id": pin.key_id,
        "key_epoch": pin.key_epoch,
        "key_profile": pin.key_profile,
        "public_key_spki": pin.public_key_spki,
        "security_level": pin.security_level,
        "hardware_backed": true,
        "attestation_challenge_sha256": pin.attestation_challenge_sha256,
        "attestation_chain_present": pin.attestation_chain_present,
        "rotation_contract": pin.rotation_contract,
        "pinned_at_ms": pin.pinned_at_ms,
        "internal_pin_verified": true,
        "attestation_verified": pin.attestation_verified,
        "public_release_eligible": false,
        "verification_status": match pin.key_profile.as_str() {
            AUTHORITY_ATTESTED_KEY_PROFILE =>
                "independent_os_pin_pass_full_keymint_chain_pending",
            AUTHORITY_USERDEBUG_LOCAL_HARDWARE_KEY_PROFILE =>
                "userdebug_local_hardware_pin_pass_attestation_unavailable_hold",
            _ => unreachable!("validated authority key profile"),
        },
    }))
}

fn validate_authority_key_metadata(metadata: &Value) -> Result<AuthorityKeyCandidate> {
    validate_authority_key_metadata_for_profile(
        metadata,
        authority_userdebug_local_profile_enabled(),
    )
}

fn validate_authority_key_metadata_for_profile(
    metadata: &Value,
    allow_userdebug_local_hardware: bool,
) -> Result<AuthorityKeyCandidate> {
    if metadata.get("schema").and_then(Value::as_str) != Some(AUTHORITY_KEY_SCHEMA)
        || metadata.get("package").and_then(Value::as_str) != Some("org.trillionnium.aiauthority")
        || metadata.get("signature_algorithm").and_then(Value::as_str) != Some("SHA256withECDSA")
        || metadata.get("pin_scope").and_then(Value::as_str) != Some("package+key_epoch+key_id")
        || metadata.get("hardware_backed").and_then(Value::as_bool) != Some(true)
        || metadata
            .get("public_key_spki_is_identity_root")
            .and_then(Value::as_bool)
            != Some(false)
    {
        bail!("authority_key_metadata_contract_denied");
    }
    let key_profile = metadata
        .get("key_profile")
        .and_then(Value::as_str)
        .context("authority_key_profile_missing")?;
    let key_id = metadata
        .get("key_id")
        .and_then(Value::as_str)
        .context("authority_key_id_missing")?;
    if !is_lower_hex(key_id, 64) {
        bail!("authority_key_id_invalid");
    }
    let key_epoch = metadata
        .get("key_epoch")
        .and_then(Value::as_u64)
        .filter(|epoch| *epoch > 0)
        .context("authority_key_epoch_invalid")?;
    let public_key_spki = metadata
        .get("public_key_spki")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
        .context("authority_public_key_spki_invalid")?;
    if sha256_bytes(&base64_decode(public_key_spki)?) != key_id {
        bail!("authority_public_key_digest_mismatch");
    }
    let security_level = metadata
        .get("security_level")
        .and_then(Value::as_str)
        .context("authority_security_level_missing")?;
    if !matches!(security_level, "STRONGBOX" | "TRUSTED_ENVIRONMENT") {
        bail!("authority_receipt_key_not_hardware_backed");
    }
    let challenge = metadata
        .get("attestation_challenge_sha256")
        .and_then(Value::as_str)
        .context("authority_attestation_challenge_missing")?;
    let challenge_base64 = metadata
        .get("attestation_challenge_base64")
        .and_then(Value::as_str)
        .context("authority_attestation_challenge_encoding_missing")?;
    let rotation_contract = metadata
        .get("rotation_contract")
        .and_then(Value::as_str)
        .context("authority_rotation_contract_missing")?;
    if rotation_contract != AUTHORITY_ROTATION_CONTRACT {
        bail!("authority_rotation_contract_mismatch");
    }
    let chain = metadata
        .get("certificate_chain_der")
        .and_then(Value::as_array)
        .context("authority_attestation_chain_missing")?;
    let attestation_chain_present = metadata
        .get("attestation_chain_present")
        .and_then(Value::as_bool)
        .context("authority_attestation_chain_presence_missing")?;
    match key_profile {
        AUTHORITY_ATTESTED_KEY_PROFILE => {
            if challenge != sha256_bytes(AUTHORITY_ATTESTATION_CHALLENGE) {
                bail!("authority_attestation_challenge_mismatch");
            }
            if base64_decode(challenge_base64)? != AUTHORITY_ATTESTATION_CHALLENGE {
                bail!("authority_attestation_challenge_encoding_mismatch");
            }
            if !attestation_chain_present
                || metadata
                    .get("attestation_required_for_new_pin")
                    .and_then(Value::as_bool)
                    != Some(true)
                || metadata
                    .get("attestation_application_id_required")
                    .and_then(Value::as_bool)
                    != Some(true)
                || metadata.get("attestation_format").and_then(Value::as_str)
                    != Some("android-keymint-x509-der-chain")
                || metadata
                    .get("verification_contract")
                    .and_then(Value::as_str)
                    != Some(AUTHORITY_ATTESTED_VERIFICATION_CONTRACT)
                || chain.len() < 2
                || chain.len() > 8
                || chain.iter().any(|certificate| {
                    certificate
                        .as_str()
                        .filter(|value| !value.is_empty() && value.len() <= 16_384)
                        .and_then(|value| base64_decode(value).ok())
                        .filter(|value| !value.is_empty())
                        .is_none()
                })
            {
                bail!("authority_attestation_chain_boundary_denied");
            }
        }
        AUTHORITY_USERDEBUG_LOCAL_HARDWARE_KEY_PROFILE => {
            if !allow_userdebug_local_hardware {
                bail!("authority_userdebug_local_key_profile_not_enabled");
            }
            if challenge != AUTHORITY_ATTESTATION_UNAVAILABLE
                || !challenge_base64.is_empty()
                || attestation_chain_present
                || metadata
                    .get("attestation_required_for_new_pin")
                    .and_then(Value::as_bool)
                    != Some(false)
                || metadata
                    .get("attestation_application_id_required")
                    .and_then(Value::as_bool)
                    != Some(false)
                || metadata.get("attestation_format").and_then(Value::as_str) != Some("none")
                || metadata
                    .get("verification_contract")
                    .and_then(Value::as_str)
                    != Some(AUTHORITY_USERDEBUG_LOCAL_VERIFICATION_CONTRACT)
                || !chain.is_empty()
            {
                bail!("authority_userdebug_local_key_metadata_denied");
            }
        }
        _ => bail!("authority_key_profile_denied"),
    }
    Ok(AuthorityKeyCandidate {
        key_id: key_id.to_string(),
        key_epoch,
        key_profile: key_profile.to_string(),
        public_key_spki: public_key_spki.to_string(),
        security_level: security_level.to_string(),
        attestation_challenge_sha256: challenge.to_string(),
        attestation_chain_present,
        rotation_contract: rotation_contract.to_string(),
    })
}

fn authority_userdebug_local_profile_enabled() -> bool {
    std::env::var(AUTHORITY_USERDEBUG_LOCAL_PROFILE_ENV).as_deref()
        == Ok(AUTHORITY_USERDEBUG_LOCAL_HARDWARE_KEY_PROFILE)
}

/// Validate the key against durable OS state before the first Memory key
/// unwrap.  The full pin is (re)written by `pin_authority_key_metadata` after
/// custody opens; this preflight prevents an existing pin from being bypassed
/// during bootstrapping.
fn prevalidate_authority_boot_key(root: &Path, metadata: &Value) -> Result<AuthorityKeyCandidate> {
    let candidate = validate_authority_key_metadata(metadata)?;
    let pin_path = root.join("authority-key-pin.json");
    if !private_entry_exists(&pin_path)? {
        return Ok(candidate);
    }
    let bytes = read_private_bounded_file(&pin_path, 64 * 1024)?;
    let existing: AuthorityKeyPin =
        serde_json::from_slice(&bytes).context("invalid_authority_key_pin_json")?;
    validate_authority_key_pin_state(&existing)?;
    validate_authority_key_transition(Some(&existing), &candidate, validate_rotation_marker)?;
    Ok(candidate)
}

fn validate_authority_key_transition<R>(
    existing: Option<&AuthorityKeyPin>,
    candidate: &AuthorityKeyCandidate,
    rotation_validator: R,
) -> Result<()>
where
    R: Fn(&AuthorityKeyPin, &AuthorityKeyCandidate) -> Result<()>,
{
    let Some(existing) = existing else {
        return Ok(());
    };
    if candidate.key_epoch < existing.key_epoch {
        bail!("authority_key_epoch_rollback_denied");
    }
    if candidate.key_epoch == existing.key_epoch
        && (candidate.key_id != existing.key_id
            || candidate.key_profile != existing.key_profile
            || candidate.public_key_spki != existing.public_key_spki
            || candidate.security_level != existing.security_level
            || candidate.attestation_challenge_sha256 != existing.attestation_challenge_sha256
            || candidate.attestation_chain_present != existing.attestation_chain_present
            || candidate.rotation_contract != existing.rotation_contract)
    {
        bail!("authority_same_epoch_key_substitution_denied");
    }
    if candidate.key_epoch > existing.key_epoch {
        rotation_validator(existing, candidate)?;
    }
    Ok(())
}

fn validate_rotation_marker(
    existing: &AuthorityKeyPin,
    candidate: &AuthorityKeyCandidate,
) -> Result<()> {
    let marker_path = std::env::var_os("TRILLIONNIUM_AUTHORITY_KEY_ROTATION_MARKER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/trillionnium/authority-key-rotation.json"));
    let marker: Value = serde_json::from_slice(&read_bounded_file(&marker_path, 16 * 1024)?)
        .context("invalid_authority_key_rotation_marker")?;
    if marker.get("schema").and_then(Value::as_str) != Some(AUTHORITY_ROTATION_SCHEMA)
        || marker.get("authorized").and_then(Value::as_bool) != Some(true)
        || marker.get("from_key_id").and_then(Value::as_str) != Some(&existing.key_id)
        || marker.get("from_key_epoch").and_then(Value::as_u64) != Some(existing.key_epoch)
        || marker.get("to_key_id").and_then(Value::as_str) != Some(&candidate.key_id)
        || marker.get("to_key_epoch").and_then(Value::as_u64) != Some(candidate.key_epoch)
    {
        bail!("authority_key_rotation_not_explicitly_authorized");
    }
    Ok(())
}

fn memory_associated_data(subject: &Subject, memory_id: &str) -> Vec<u8> {
    format!(
        "trillionnium-memory-xchacha20poly1305-v2\nuid={}\ndomain={}\nmemory_id={}\n",
        subject.uid, subject.selinux_domain, memory_id
    )
    .into_bytes()
}

fn validate_request_id(request_id: &str) -> Result<()> {
    if request_id.is_empty()
        || request_id.len() > 128
        || request_id
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        bail!("invalid_context_memory_request_id");
    }
    Ok(())
}

fn validate_context_memory_request_payload(method: &str, payload: &Value) -> Result<()> {
    let (required, optional): (&[&str], &[&str]) = match method {
        "revoke_context" => (&["context_id"], &[]),
        "save_memory" => (
            &["context_id", "payload"],
            &["receipt_id", "taint_lineage", "retention_ms"],
        ),
        "list_memory" => (&[], &["include_payload", "limit"]),
        "delete_memory" => (
            &[
                "memory_id",
                "expected_payload_sha256",
                "expected_updated_at_ms",
            ],
            &[],
        ),
        // This method is deliberately unavailable on the generic Memory
        // dispatcher. Preserve its explicit denial instead of reporting an
        // unrelated shape error first.
        "get_context" => return Ok(()),
        _ => bail!("unknown_context_memory_method"),
    };
    let object = payload
        .as_object()
        .context("context_memory_payload_not_object")?;
    if required.iter().any(|field| !object.contains_key(*field))
        || object
            .keys()
            .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        bail!("context_memory_payload_missing_or_unknown_fields");
    }
    match method {
        "save_memory" => {
            for field in ["context_id", "payload"] {
                if !object.get(field).is_some_and(Value::is_string) {
                    bail!("context_memory_payload_field_type_denied");
                }
            }
            for field in ["receipt_id", "taint_lineage"] {
                if object.get(field).is_some_and(|value| !value.is_string()) {
                    bail!("context_memory_payload_field_type_denied");
                }
            }
            if object
                .get("retention_ms")
                .is_some_and(|value| value.as_u64().is_none())
            {
                bail!("context_memory_payload_field_type_denied");
            }
        }
        "list_memory" => {
            if object
                .get("include_payload")
                .is_some_and(|value| !value.is_boolean())
                || object
                    .get("limit")
                    .is_some_and(|value| value.as_u64().is_none())
                || object.get("include_payload").and_then(Value::as_bool) == Some(true)
            {
                bail!("context_memory_payload_field_type_denied");
            }
        }
        "revoke_context" => {
            if !object.get("context_id").is_some_and(Value::is_string) {
                bail!("context_memory_payload_field_type_denied");
            }
        }
        "delete_memory" => {
            if !object.get("memory_id").is_some_and(Value::is_string)
                || !object
                    .get("expected_payload_sha256")
                    .is_some_and(Value::is_string)
                || object
                    .get("expected_updated_at_ms")
                    .and_then(Value::as_u64)
                    .is_none_or(|value| value == 0)
            {
                bail!("context_memory_payload_field_type_denied");
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn bounded_string(value: &Value, key: &str, max: usize) -> Result<String> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("{key}_required"))?;
    if text.is_empty() || text.len() > max || text.as_bytes().contains(&0) {
        bail!("{key}_outside_bounded_contract");
    }
    Ok(text.to_string())
}

fn validate_store(store: &StoreFile, payload_root: &Path) -> Result<()> {
    if store.memories.len() > MAX_MEMORY_GLOBAL
        || store.memory_saves.len() > MAX_MEMORY_SAVE_TOMBSTONES
        || store.memory_deletions.len() > MAX_MEMORY_DELETION_TOMBSTONES
        || store.replays.len() > MAX_REPLAY_RECORDS
    {
        bail!("context_memory_store_capacity_invalid");
    }
    for item in &store.memories {
        if !matches!(item.schema.as_str(), MEMORY_SCHEMA | LEGACY_MEMORY_SCHEMA)
            || item.owner_uid < 10_000
            || item.owner_selinux_domain.is_empty()
            || validate_resource_id(&item.memory_id, "memory-").is_err()
            || validate_resource_id(&item.context_id, "context-").is_err()
            || item.payload_file != format!("{}.enc", item.memory_id)
            || !is_lower_hex(&item.payload_sha256, 64)
            || !is_lower_hex(&item.context_sha256, 64)
            || item.payload_bytes > MAX_CONTEXT_BYTES
            || item.encryption_algorithm != "XChaCha20Poly1305"
            || item.retention_until_ms <= item.created_at_ms
        {
            bail!("invalid_context_memory_metadata");
        }
        if item.schema == MEMORY_SCHEMA {
            let provenance_id_valid = item
                .provenance_id
                .strip_prefix("provenance-")
                .is_some_and(valid_lower_sha256);
            let lineage_valid = match item.provenance_kind.as_str() {
                "user_imported" => {
                    item.taint_lineage == "user_imported"
                        && item.task_id.is_empty()
                        && item.plan_id.is_empty()
                        && item.receipt_id.is_empty()
                }
                "planning_result" => {
                    item.taint_lineage == "untainted"
                        && !item.task_id.is_empty()
                        && item.task_id.len() <= 128
                        && item.plan_id.len() <= 128
                        && item.receipt_id.is_empty()
                }
                "planning_result_with_action_receipt" => {
                    item.taint_lineage == "untainted"
                        && !item.task_id.is_empty()
                        && item.task_id.len() <= 128
                        && !item.plan_id.is_empty()
                        && item.plan_id.len() <= 128
                        && valid_lower_sha256(&item.receipt_id)
                }
                _ => false,
            };
            if !provenance_id_valid || !lineage_valid {
                bail!("invalid_memory_provenance_metadata");
            }
        } else if !item.provenance_kind.is_empty()
            || !item.provenance_id.is_empty()
            || !item.task_id.is_empty()
            || !item.plan_id.is_empty()
        {
            bail!("legacy_memory_provenance_spoof_denied");
        }
        let path = payload_root.join(&item.payload_file);
        open_private_regular_file(&path, (MAX_CONTEXT_BYTES * 2 + 256) as u64, false)
            .with_context(|| format!("missing encrypted memory payload {}", item.memory_id))?;
    }
    let mut save_ids = HashSet::new();
    for item in &store.memory_saves {
        let memory = store
            .memories
            .iter()
            .find(|memory| memory.memory_id == item.memory_id)
            .context("memory_save_tombstone_memory_missing")?;
        let expected_subject_key =
            Subject::new(memory.owner_uid, &memory.owner_selinux_domain)?.key();
        if item.schema != MEMORY_SAVE_TOMBSTONE_SCHEMA
            || validate_request_id(&item.request_id).is_err()
            || item.subject_key != expected_subject_key
            || !is_lower_hex(&item.request_payload_sha256, 64)
            || validate_resource_id(&item.memory_id, "memory-").is_err()
            || item.saved_at_ms == 0
            || item.saved_at_ms != memory.created_at_ms
            || item.result != memory.public_json()
            || !save_ids.insert((item.subject_key.clone(), item.request_id.clone()))
        {
            bail!("invalid_memory_save_tombstone");
        }
    }
    let mut deletion_ids = HashSet::new();
    for item in &store.memory_deletions {
        let expected_fields = [
            "memory_id",
            "deleted_payload_sha256",
            "deleted_updated_at_ms",
            "deleted",
            "primary_payload_deleted",
            "derived_contexts_revoked",
            "direct_data_grants_revoked",
            "derived_execution_payloads_revoked",
            "derived_egress_grants_revoked",
            "derived_external_artifacts_may_remain",
            "external_lineage_closure_status",
            "raw_payload_retained",
        ];
        let result = item
            .result
            .as_object()
            .context("memory_deletion_tombstone_result_not_object")?;
        if item.schema != MEMORY_DELETION_TOMBSTONE_SCHEMA
            || validate_request_id(&item.request_id).is_err()
            || item.subject_key.is_empty()
            || validate_resource_id(&item.memory_id, "memory-").is_err()
            || !is_lower_hex(&item.deleted_payload_sha256, 64)
            || item.deleted_updated_at_ms == 0
            || item.deleted_at_ms == 0
            || !deletion_ids.insert((item.subject_key.clone(), item.request_id.clone()))
            || result.len() != expected_fields.len()
            || expected_fields
                .iter()
                .any(|field| !result.contains_key(*field))
            || result.get("memory_id").and_then(Value::as_str) != Some(item.memory_id.as_str())
            || result.get("deleted_payload_sha256").and_then(Value::as_str)
                != Some(item.deleted_payload_sha256.as_str())
            || result.get("deleted_updated_at_ms").and_then(Value::as_u64)
                != Some(item.deleted_updated_at_ms)
            || result.get("deleted").and_then(Value::as_bool) != Some(true)
            || result
                .get("primary_payload_deleted")
                .and_then(Value::as_bool)
                .is_none()
            || result
                .get("derived_external_artifacts_may_remain")
                .and_then(Value::as_bool)
                != Some(true)
            || result.get("raw_payload_retained").and_then(Value::as_bool) != Some(false)
        {
            bail!("invalid_memory_deletion_tombstone");
        }
    }
    Ok(())
}

fn load_context_journal(
    path: &Path,
    key: &[u8; 32],
    expected_key_id: &str,
    current_boot_id_sha256: &str,
    now_ms: u64,
) -> Result<(
    HashMap<String, StoredContext>,
    HashMap<String, ContextImportReservation>,
)> {
    if !private_entry_exists(path)? {
        return Ok((HashMap::new(), HashMap::new()));
    }
    let encrypted = read_private_bounded_file(path, MAX_CONTEXT_JOURNAL_CLEAR_BYTES + 128)?;
    let clear = Zeroizing::new(
        decrypt_payload(
            key,
            CONTEXT_JOURNAL_AAD,
            &encrypted,
            MAX_CONTEXT_JOURNAL_CLEAR_BYTES,
        )
        .context("invalid_encrypted_context_journal")?,
    );
    let mut journal: ContextJournal =
        serde_json::from_slice(clear.as_slice()).context("invalid_context_journal_json")?;
    if serde_json::to_vec(&journal)? != clear.as_slice() {
        bail!("context_journal_not_canonical_closed_world_json");
    }
    if journal.schema != CONTEXT_JOURNAL_SCHEMA || journal.key_id != expected_key_id {
        bail!("context_journal_identity_mismatch");
    }
    if journal.boot_id_sha256 != current_boot_id_sha256 {
        for context in &mut journal.contexts {
            context.content.zeroize();
        }
        return Ok((HashMap::new(), HashMap::new()));
    }
    journal.contexts.retain(|context| {
        (context.revoked && context.tombstone_until_ms > now_ms
            || !context.revoked && context.expires_at_ms > now_ms)
            && matches!(
                context.authority_import_state.as_str(),
                "published_pending_ack" | "imported" | "local_only"
            )
    });
    journal.reservations.retain(|reservation| {
        reservation.boot_id_sha256 == current_boot_id_sha256 && reservation.expires_at_ms > now_ms
    });
    validate_context_journal(&journal, current_boot_id_sha256, now_ms)?;
    let mut contexts = HashMap::with_capacity(journal.contexts.len());
    for context in journal.contexts {
        let context_id = context.context_id.clone();
        if contexts.insert(context_id, context).is_some() {
            bail!("context_journal_duplicate_context_id");
        }
    }
    let mut reservations = HashMap::with_capacity(journal.reservations.len());
    for reservation in journal.reservations {
        let reservation_id = reservation.reservation_id.clone();
        if reservations.insert(reservation_id, reservation).is_some() {
            bail!("context_journal_duplicate_import_reservation_id");
        }
    }
    Ok((contexts, reservations))
}

fn validate_context_journal(
    journal: &ContextJournal,
    current_boot_id_sha256: &str,
    now_ms: u64,
) -> Result<()> {
    let live_contexts = journal
        .contexts
        .iter()
        .filter(|context| !context.revoked)
        .count();
    let context_tombstones = journal
        .contexts
        .iter()
        .filter(|context| context.revoked)
        .count();
    if journal.schema != CONTEXT_JOURNAL_SCHEMA
        || !journal.key_id.starts_with("memory-key-")
        || journal.boot_id_sha256 != current_boot_id_sha256
        || !is_lower_hex(&journal.boot_id_sha256, 64)
        || live_contexts > MAX_CONTEXTS
        || context_tombstones > MAX_CONTEXT_TOMBSTONES
        || journal.reservations.len() > MAX_CONTEXTS
        || live_contexts.saturating_add(journal.reservations.len()) > MAX_CONTEXTS
    {
        bail!("invalid_context_journal_contract");
    }
    let mut ids = HashSet::new();
    let mut origins = HashSet::new();
    for context in &journal.contexts {
        let expected_subject_key =
            Subject::new(context.owner_uid, &context.owner_selinux_domain)?.key();
        let source_kind_valid = match context.origin_method.as_str() {
            "get_context" => matches!(context.source_kind.as_str(), "file" | "browser"),
            "select_memory_context" => context.source_kind == "memory",
            "test_fixture" => matches!(
                context.source_kind.as_str(),
                "file"
                    | "browser"
                    | "browser_extract"
                    | "notifications"
                    | "current_app"
                    | "memory_import"
            ),
            _ => false,
        };
        let lifecycle_valid = if context.revoked {
            context.revoked_at_ms > 0
                && context.tombstone_until_ms > context.revoked_at_ms
                && context.tombstone_until_ms > now_ms
                && context.content.is_empty()
        } else {
            context.revoked_at_ms == 0
                && context.tombstone_until_ms == 0
                && context.expires_at_ms > now_ms
                && !context.content.is_empty()
                && context.content.len() <= MAX_CONTEXT_BYTES
                && sha256_bytes(context.content.as_bytes()) == context.content_sha256
        };
        if context.schema != STORED_CONTEXT_SCHEMA
            || context.subject_key.is_empty()
            || context.subject_key != expected_subject_key
            || context.owner_uid < 10_000
            || context.subject_user_id != context.owner_uid / 100_000
            || context.owner_selinux_domain.is_empty()
            || context.owner_selinux_domain.len() > 256
            || context.boot_id_sha256 != current_boot_id_sha256
            || !context
                .context_id
                .strip_prefix("context-")
                .is_some_and(|digest| is_lower_hex(digest, 64))
            || context.source_id.is_empty()
            || context.source_id.len() > MAX_SOURCE_ID_BYTES
            || !source_kind_valid
            || context.captured_at_ms == 0
            || context.expires_at_ms <= context.captured_at_ms
            || context.expires_at_ms.saturating_sub(context.captured_at_ms) > MAX_CONTEXT_TTL_MS
            || context.privacy_class.is_empty()
            || !is_lower_hex(&context.content_sha256, 64)
            || !lifecycle_valid
            || context.capture_id.is_empty()
            || context.origin_request_id.is_empty()
            || validate_request_id(&context.origin_request_id).is_err()
            || !context.source_metadata.is_object()
            || !matches!(
                context.origin_method.as_str(),
                "get_context" | "select_memory_context" | "test_fixture"
            )
            || !matches!(
                context.authority_import_state.as_str(),
                "published_pending_ack" | "imported" | "local_only"
            )
            || !ids.insert(context.context_id.clone())
            || !origins.insert((
                context.subject_key.clone(),
                context.origin_method.clone(),
                context.origin_request_id.clone(),
            ))
        {
            bail!("invalid_stored_context_contract");
        }
        match context.origin_method.as_str() {
            "get_context" => {
                if !context
                    .capture_id
                    .strip_prefix("capture-")
                    .is_some_and(|digest| is_lower_hex(digest, 64))
                    || !is_lower_hex(&context.capture_receipt_id, 64)
                    || validate_request_id(&context.capture_request_id).is_err()
                    || !is_lower_hex(&context.resolution_sha256, 64)
                    || context.authority_import_state == "local_only"
                    || !context.parent_memory_id.is_empty()
                    || !context.parent_memory_payload_sha256.is_empty()
                    || context.parent_memory_updated_at_ms != 0
                {
                    bail!("invalid_authority_context_lineage");
                }
            }
            "select_memory_context" => {
                if !context
                    .parent_memory_id
                    .strip_prefix("memory-")
                    .is_some_and(|digest| is_lower_hex(digest, 64))
                    || !is_lower_hex(&context.parent_memory_payload_sha256, 64)
                    || context.parent_memory_updated_at_ms == 0
                    || !context.capture_receipt_id.is_empty()
                    || !context.capture_request_id.is_empty()
                    || !context.resolution_sha256.is_empty()
                    || context.authority_import_state != "local_only"
                {
                    bail!("invalid_memory_context_lineage");
                }
            }
            "test_fixture" => {
                if context.authority_import_state != "local_only"
                    || !context.capture_request_id.is_empty()
                {
                    bail!("invalid_test_context_lineage");
                }
            }
            _ => unreachable!(),
        }
    }
    let mut reservation_ids = HashSet::new();
    for reservation in &journal.reservations {
        let expected_subject_key =
            Subject::new(reservation.owner_uid, &reservation.owner_selinux_domain)?.key();
        let expected_reservation_id = context_import_reservation_id(
            &reservation.boot_id_sha256,
            &reservation.subject_key,
            &reservation.origin_request_id,
            &reservation.capture_id,
            &reservation.capture_receipt_id,
            &reservation.capture_request_id,
            &reservation.source_id,
            &reservation.content_sha256,
        );
        let source_binding_valid = match reservation.source_kind.as_str() {
            "file" => reservation
                .source_id
                .strip_prefix("saf-provider:")
                .and_then(|value| value.split_once(":document:"))
                .is_some_and(|(authority, document)| {
                    is_lower_hex(authority, 64) && is_lower_hex(document, 64)
                }),
            "browser" => {
                reservation.source_id == format!("authority-url:{}", reservation.content_sha256)
            }
            _ => false,
        };
        if reservation.schema != CONTEXT_IMPORT_RESERVATION_SCHEMA
            || reservation.reservation_id != expected_reservation_id
            || !reservation_ids.insert(reservation.reservation_id.clone())
            || reservation.subject_key != expected_subject_key
            || reservation.owner_uid < 10_000
            || reservation.subject_user_id != reservation.owner_uid / 100_000
            || reservation.owner_selinux_domain.is_empty()
            || reservation.owner_selinux_domain.len() > 256
            || reservation.boot_id_sha256 != current_boot_id_sha256
            || validate_request_id(&reservation.origin_request_id).is_err()
            || !reservation
                .capture_id
                .strip_prefix("capture-")
                .is_some_and(valid_lower_sha256)
            || !is_lower_hex(&reservation.capture_receipt_id, 64)
            || validate_request_id(&reservation.capture_request_id).is_err()
            || !source_binding_valid
            || !is_lower_hex(&reservation.content_sha256, 64)
            || reservation.reserved_at_ms == 0
            || reservation.expires_at_ms <= now_ms
            || reservation.expires_at_ms <= reservation.reserved_at_ms
            || reservation
                .expires_at_ms
                .saturating_sub(reservation.reserved_at_ms)
                > MAX_CONTEXT_TTL_MS
            || !origins.insert((
                reservation.subject_key.clone(),
                "get_context".to_string(),
                reservation.origin_request_id.clone(),
            ))
            || journal.contexts.iter().any(|context| {
                context.origin_method == "get_context"
                    && context.subject_key == reservation.subject_key
                    && context.capture_id == reservation.capture_id
                    && context.capture_receipt_id == reservation.capture_receipt_id
            })
        {
            bail!("invalid_context_import_capacity_reservation");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn context_import_reservation_id(
    boot_id_sha256: &str,
    subject_key: &str,
    origin_request_id: &str,
    capture_id: &str,
    capture_receipt_id: &str,
    capture_request_id: &str,
    source_id: &str,
    content_sha256: &str,
) -> String {
    format!(
        "context-reservation-{}",
        sha256_bytes(
            [
                b"trillionnium-context-import-capacity-reservation-v1".as_slice(),
                boot_id_sha256.as_bytes(),
                subject_key.as_bytes(),
                origin_request_id.as_bytes(),
                capture_id.as_bytes(),
                capture_receipt_id.as_bytes(),
                capture_request_id.as_bytes(),
                source_id.as_bytes(),
                content_sha256.as_bytes(),
            ]
            .concat()
            .as_slice()
        )
    )
}

fn current_context_boot_id_sha256() -> Result<String> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("context_journal_current_boot_id_unavailable")?;
    let boot_id = boot_id.trim();
    if boot_id.len() != 36
        || !boot_id.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23) && byte == b'-'
                || !matches!(index, 8 | 13 | 18 | 23)
                    && (byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        bail!("context_journal_current_boot_id_invalid");
    }
    Ok(sha256_bytes(boot_id.as_bytes()))
}

fn prune_orphaned_memory_payloads(payload_root: &Path, store: &StoreFile) -> Result<()> {
    open_private_directory(payload_root)?;
    for entry in fs::read_dir(payload_root)? {
        let entry = entry?;
        let file_name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("memory_payload_file_name_not_utf8"))?;
        let path = payload_root.join(&file_name);
        if is_memory_payload_atomic_temporary(&file_name) {
            open_private_regular_file(&path, (MAX_CONTEXT_BYTES * 2 + 256) as u64, true)
                .context("invalid_temporary_memory_payload")?;
            remove_private_regular_file(&path, false)?;
            continue;
        }
        let Some(memory_id) = file_name.strip_suffix(".enc") else {
            bail!("unexpected_memory_payload_entry");
        };
        if validate_resource_id(memory_id, "memory-").is_err() {
            bail!("unexpected_memory_payload_entry");
        }
        open_private_regular_file(&path, (MAX_CONTEXT_BYTES * 2 + 256) as u64, false)
            .context("invalid_orphanable_memory_payload")?;
        if !store
            .memories
            .iter()
            .any(|item| item.payload_file == file_name)
        {
            remove_private_regular_file(&path, false)?;
        }
    }
    Ok(())
}

fn is_memory_payload_atomic_temporary(file_name: &str) -> bool {
    let Some((hidden_memory_id, temporary_identity)) = file_name.split_once(".enc.tmp-") else {
        return false;
    };
    let Some(memory_id) = hidden_memory_id.strip_prefix('.') else {
        return false;
    };
    let Some((pid, nonce_sha256)) = temporary_identity.split_once('-') else {
        return false;
    };
    validate_resource_id(memory_id, "memory-").is_ok()
        && !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && is_lower_hex(nonce_sha256, 64)
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match open_private_directory(path) {
        Ok(_) => return Ok(()),
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)?;
    open_private_directory(path).map(drop)
}

fn open_private_directory(path: &Path) -> Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
        || metadata.nlink() == 0
    {
        bail!("context_memory_directory_identity_or_permissions_denied");
    }
    Ok(directory)
}

fn validate_production_root_ancestor_chain(root: &Path) -> Result<()> {
    if !root.is_absolute() {
        bail!("context_memory_production_root_must_be_absolute");
    }
    let expected_uid = unsafe { libc::geteuid() };
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let root_metadata = directory.metadata()?;
    if !root_metadata.is_dir()
        || root_metadata.uid() != expected_uid
        || root_metadata.mode() & 0o022 != 0
        || root_metadata.nlink() == 0
    {
        bail!("context_memory_production_root_ancestor_permissions_denied");
    }
    let mut components = Vec::new();
    for component in root.components() {
        match component {
            std::path::Component::Normal(value) => components.push(value),
            std::path::Component::RootDir => {}
            _ => bail!("context_memory_production_root_component_denied"),
        }
    }
    if components.is_empty() {
        bail!("context_memory_production_root_cannot_be_filesystem_root");
    }
    for (index, component) in components.iter().enumerate() {
        let name = CString::new(component.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("context_memory_production_root_ancestor_open_denied");
        }
        let next = unsafe { File::from_raw_fd(fd) };
        let metadata = next.metadata()?;
        let final_component = index + 1 == components.len();
        if !metadata.is_dir()
            || metadata.uid() != expected_uid
            || metadata.nlink() == 0
            || if final_component {
                metadata.mode() & 0o7777 != 0o700
            } else {
                metadata.mode() & 0o022 != 0
            }
        {
            bail!("context_memory_production_root_ancestor_permissions_denied");
        }
        directory = next;
    }
    Ok(())
}

fn private_file_name(path: &Path) -> Result<CString> {
    let name = path
        .file_name()
        .context("private_file_name_missing")?
        .as_bytes();
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        bail!("private_file_name_denied");
    }
    CString::new(name).context("private_file_name_contains_nul")
}

fn is_ui_replay_record_file_name(file_name: &str) -> bool {
    file_name
        .strip_suffix(".json")
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

fn is_ui_replay_outcome_file_name(file_name: &str) -> bool {
    file_name
        .strip_suffix(".enc")
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

/// Parse only temp names minted by `atomic_write_private_staged`:
/// `.<destination>.tmp-<pid>-<64 lower-hex random digest>`.
fn private_atomic_temp_destination(file_name: &str) -> Option<&str> {
    let without_dot = file_name.strip_prefix('.')?;
    let (destination, suffix) = without_dot.rsplit_once(".tmp-")?;
    let (pid, random_digest) = suffix.split_once('-')?;
    if destination.is_empty()
        || pid.is_empty()
        || pid.len() > 20
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !is_lower_hex(random_digest, 64)
    {
        return None;
    }
    Some(destination)
}

/// Remove only bounded, owner-controlled regular temp files whose embedded
/// destination is valid for this exact store.  Lookalikes, links, directories
/// and unknown names remain fail-closed in the caller's normal directory scan.
fn cleanup_private_atomic_temps<F>(root: &Path, destination_max_bytes: F) -> Result<usize>
where
    F: Fn(&str) -> Option<u64>,
{
    let parent = open_private_directory(root)?;
    let mut removed = 0usize;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("private_atomic_temp_name_not_utf8"))?;
        let looks_like_atomic_temp = file_name.starts_with('.') && file_name.contains(".tmp-");
        let Some(destination) = private_atomic_temp_destination(&file_name) else {
            if looks_like_atomic_temp {
                bail!("private_atomic_temp_lookalike_denied");
            }
            continue;
        };
        let max_bytes = destination_max_bytes(destination)
            .context("private_atomic_temp_destination_not_in_closed_set")?;
        let name = CString::new(file_name.as_bytes())?;
        let file = open_private_regular_file_at(&parent, &name, max_bytes, true)?;
        let opened = file.metadata()?;
        let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                current.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let current = unsafe { current.assume_init() };
        if current.st_dev != opened.dev() || current.st_ino != opened.ino() || current.st_nlink != 1
        {
            bail!("private_atomic_temp_changed_before_cleanup");
        }
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        removed = removed.saturating_add(1);
    }
    if removed > 0 {
        parent.sync_all()?;
    }
    Ok(removed)
}

fn root_atomic_temp_max_bytes(destination: &str) -> Option<u64> {
    match destination {
        "metadata.json" => Some(STORE_FILE_MAX_BYTES),
        CONTEXT_JOURNAL_FILE => Some((MAX_CONTEXT_JOURNAL_CLEAR_BYTES + 128) as u64),
        "agent-data-grants.enc" => Some((MAX_DATA_GRANT_STORE_BYTES + 128) as u64),
        MEMORY_KEY_ENVELOPE_FILE => Some(MAX_MEMORY_KEY_ENVELOPE_BYTES as u64),
        "authority-key-pin.json" => Some(64 * 1024),
        "execution-payload-integrity.json" => Some(4 * 1024),
        UI_REPLAY_ARCHIVE_FILE => Some(MAX_UI_REPLAY_ARCHIVE_FILE_BYTES as u64),
        _ => None,
    }
}

fn validate_egress_recovery_grant_id(grant_id: &str) -> Result<()> {
    if grant_id.len() != "egress-".len() + 64
        || !grant_id.starts_with("egress-")
        || !is_lower_hex(&grant_id["egress-".len()..], 64)
    {
        bail!("invalid_egress_recovery_grant_id");
    }
    Ok(())
}

fn egress_recovery_file_name(grant_id: &str) -> String {
    format!("egress-recovery-{}.enc", sha256_bytes(grant_id.as_bytes()))
}

fn is_egress_recovery_file_name(file_name: &str) -> bool {
    file_name.len() == "egress-recovery-".len() + 64 + ".enc".len()
        && file_name.starts_with("egress-recovery-")
        && file_name.ends_with(".enc")
        && is_lower_hex(
            &file_name["egress-recovery-".len()..file_name.len() - ".enc".len()],
            64,
        )
}

fn validate_egress_recovery_reference(reference: &EgressRecoveryBlobRef) -> Result<()> {
    if !is_egress_recovery_file_name(&reference.file_name)
        || !is_lower_hex(&reference.ciphertext_sha256, 64)
    {
        bail!("invalid_egress_recovery_blob_reference");
    }
    Ok(())
}

fn validate_egress_recovery_boundary(associated_data: &[u8], clear_len: usize) -> Result<()> {
    if associated_data.is_empty()
        || associated_data.len() > 32 * 1024
        || clear_len > MAX_EGRESS_RECOVERY_CLEAR_BYTES
    {
        bail!("invalid_egress_recovery_blob_boundary");
    }
    Ok(())
}

fn egress_recovery_domain_aad(associated_data: &[u8]) -> Result<Vec<u8>> {
    validate_egress_recovery_boundary(associated_data, 0)?;
    let mut aad = Vec::with_capacity(EGRESS_RECOVERY_AAD_PREFIX.len() + associated_data.len());
    aad.extend_from_slice(EGRESS_RECOVERY_AAD_PREFIX);
    aad.extend_from_slice(associated_data);
    Ok(aad)
}

fn validate_private_regular_file(file: &File, max: u64, allow_empty: bool) -> Result<u64> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > max
        || (!allow_empty && metadata.len() == 0)
    {
        bail!("private_file_identity_permissions_or_link_count_denied");
    }
    Ok(metadata.len())
}

fn open_private_regular_file(path: &Path, max: u64, allow_empty: bool) -> Result<File> {
    let parent_path = path.parent().context("private_file_parent_missing")?;
    let parent = open_private_directory(parent_path)?;
    let name = private_file_name(path)?;
    open_private_regular_file_at(&parent, &name, max, allow_empty)
}

fn open_private_regular_file_at(
    parent: &File,
    name: &CString,
    max: u64,
    allow_empty: bool,
) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    validate_private_regular_file(&file, max, allow_empty)?;
    Ok(file)
}

fn private_entry_exists(path: &Path) -> Result<bool> {
    let parent = open_private_directory(path.parent().context("private_file_parent_missing")?)?;
    let name = private_file_name(path)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(error.into())
    }
}

fn remove_private_regular_file(path: &Path, missing_ok: bool) -> Result<()> {
    let parent = open_private_directory(path.parent().context("private_file_parent_missing")?)?;
    let name = private_file_name(path)?;
    let file = match open_private_regular_file_at(&parent, &name, u64::MAX, true) {
        Ok(file) => file,
        Err(error)
            if missing_ok
                && error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let opened = file.metadata()?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let current = unsafe { stat.assume_init() };
    if current.st_dev != opened.dev() || current.st_ino != opened.ino() || current.st_nlink != 1 {
        bail!("private_file_changed_before_unlink");
    }
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    parent.sync_all()?;
    Ok(())
}

fn rename_private_entry(source: &Path, destination: &Path) -> Result<()> {
    let source_parent = open_private_directory(
        source
            .parent()
            .context("private_rename_source_parent_missing")?,
    )?;
    let destination_parent = open_private_directory(
        destination
            .parent()
            .context("private_rename_destination_parent_missing")?,
    )?;
    let source_name = private_file_name(source)?;
    let destination_name = private_file_name(destination)?;
    if unsafe {
        libc::renameat(
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    source_parent.sync_all()?;
    destination_parent.sync_all()?;
    Ok(())
}

struct AndroidAuthorityMemoryKeyCustody {
    socket_path: PathBuf,
    expected_uid: Option<u32>,
    expected_selinux_domain: String,
}

impl AndroidAuthorityMemoryKeyCustody {
    fn system_default() -> Result<Self> {
        let expected_uid = match std::env::var("TRILLIONNIUM_ANDROID_AUTHORITY_UID") {
            Ok(value) if value == "boot-key-pinned" => android_authority_boot_peer_uid()
                .map_err(anyhow::Error::msg)?
                .context("android_authority_boot_peer_uid_not_pinned")?
                .into(),
            Ok(value) => Some(
                value
                    .parse::<u32>()
                    .context("invalid_TRILLIONNIUM_ANDROID_AUTHORITY_UID")?,
            ),
            Err(std::env::VarError::NotPresent) => {
                android_authority_boot_peer_uid().map_err(anyhow::Error::msg)?
            }
            Err(error) => return Err(error.into()),
        };
        let expected_selinux_domain =
            std::env::var("TRILLIONNIUM_ANDROID_AUTHORITY_SELINUX_DOMAIN")
                .unwrap_or_else(|_| DEFAULT_ANDROID_AUTHORITY_SELINUX_DOMAIN.to_string());
        if expected_uid.is_some_and(|uid| uid < 10_000)
            || expected_selinux_domain.is_empty()
            || expected_selinux_domain.len() > 256
            || expected_selinux_domain.chars().any(char::is_control)
        {
            bail!("invalid_android_authority_memory_key_peer_policy");
        }
        Ok(Self {
            socket_path: std::env::var_os("TRILLIONNIUM_ANDROID_GATEWAY_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|| DEFAULT_ANDROID_GATEWAY_SOCKET.into()),
            expected_uid,
            expected_selinux_domain,
        })
    }

    fn call(&self, request_id: &str, frame: &Value) -> Result<Value> {
        let mut stream = connect_android_authority_gateway(&self.socket_path)
            .context("memory_key_authority_gateway_unavailable")?;
        authenticate_android_authority_memory_key_peer(
            &stream,
            self.expected_uid,
            &self.expected_selinux_domain,
        )?;
        let timeout = Some(Duration::from_secs(15));
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        serde_json::to_writer(&mut stream, frame)?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        let mut response = Zeroizing::new(String::new());
        BufReader::new(stream)
            .take((MAX_MEMORY_KEY_ENVELOPE_BYTES * 4) as u64)
            .read_line(&mut response)?;
        if response.is_empty()
            || response.len() >= MAX_MEMORY_KEY_ENVELOPE_BYTES * 4
            || !response.ends_with('\n')
        {
            bail!("memory_key_authority_response_boundary_denied");
        }
        let value: Value = serde_json::from_str(response.as_str())
            .context("invalid_memory_key_authority_response")?;
        let object = value
            .as_object()
            .context("memory_key_authority_response_not_object")?;
        if object.len() != 4
            || value.get("protocol").and_then(Value::as_str)
                != Some("trillionnium.android-agent-gateway.v1")
            || value.get("request_id").and_then(Value::as_str) != Some(request_id)
        {
            bail!("memory_key_authority_response_identity_denied");
        }
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            if !object.contains_key("error") || object.contains_key("result") {
                bail!("invalid_memory_key_authority_denial_envelope");
            }
            bail!("memory_key_authority_denied_or_subject_user_locked");
        }
        if !object.contains_key("result") || object.contains_key("error") {
            bail!("invalid_memory_key_authority_success_envelope");
        }
        value
            .get("result")
            .cloned()
            .context("memory_key_authority_result_missing")
    }
}

impl MemoryKeyCustody for AndroidAuthorityMemoryKeyCustody {
    fn backend(&self) -> &'static str {
        MEMORY_KEY_ANDROID_BACKEND
    }

    fn wrap(&self, key: &[u8; 32]) -> Result<MemoryKeyEnvelope> {
        let request_id = new_memory_key_gateway_request_id("wrap")?;
        let mut frame = json!({
            "protocol": "trillionnium.android-agent-gateway.v1",
            "method": "memory_key_wrap",
            "request_id": request_id,
            "subject_user_id": MEMORY_KEY_SUBJECT_USER_ID,
            "key_alias": MEMORY_KEY_ALIAS,
            "key_epoch": MEMORY_KEY_EPOCH,
            "aad": MEMORY_KEY_AAD,
            "master_key_b64": BASE64_STANDARD.encode(key),
        });
        let result = self.call(&request_id, &frame);
        if let Some(Value::String(encoded)) = frame.get_mut("master_key_b64") {
            encoded.zeroize();
        }
        let result = result?;
        let envelope: MemoryKeyEnvelope =
            serde_json::from_value(result).context("invalid_memory_key_authority_wrap_envelope")?;
        validate_memory_key_envelope(&envelope, self.backend())?;
        if envelope.key_id != sha256_bytes(key) {
            bail!("memory_key_authority_wrap_identity_mismatch");
        }
        Ok(envelope)
    }

    fn unwrap(&self, envelope: &MemoryKeyEnvelope) -> Result<Zeroizing<[u8; 32]>> {
        validate_memory_key_envelope(envelope, self.backend())?;
        let request_id = new_memory_key_gateway_request_id("unwrap")?;
        let result = self.call(
            &request_id,
            &json!({
                "protocol": "trillionnium.android-agent-gateway.v1",
                "method": "memory_key_unwrap",
                "request_id": request_id,
                "envelope": envelope,
            }),
        )?;
        let mut object = match result {
            Value::Object(object) => object,
            _ => bail!("memory_key_authority_unwrap_result_not_object"),
        };
        if object.len() != 14 {
            bail!("memory_key_authority_unwrap_result_shape_denied");
        }
        let mut encoded = Zeroizing::new(
            object
                .remove("master_key_b64")
                .and_then(|value| value.as_str().map(str::to_string))
                .context("memory_key_authority_cleartext_missing")?,
        );
        let returned_envelope: MemoryKeyEnvelope = serde_json::from_value(Value::Object(object))
            .context("invalid_memory_key_authority_returned_envelope")?;
        if &returned_envelope != envelope {
            bail!("memory_key_authority_envelope_substitution_denied");
        }
        let mut decoded = Zeroizing::new(decode_canonical_base64_bounded(encoded.as_str(), 32)?);
        encoded.zeroize();
        let mut key = [0u8; 32];
        key.copy_from_slice(decoded.as_slice());
        decoded.zeroize();
        if sha256_bytes(&key) != envelope.key_id {
            key.zeroize();
            bail!("memory_key_authority_unwrapped_identity_mismatch");
        }
        Ok(Zeroizing::new(key))
    }
}

#[cfg(test)]
struct SoftwareTestMemoryKeyCustody {
    available: std::sync::atomic::AtomicBool,
    unlocked: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl Default for SoftwareTestMemoryKeyCustody {
    fn default() -> Self {
        Self {
            available: std::sync::atomic::AtomicBool::new(true),
            unlocked: std::sync::atomic::AtomicBool::new(true),
        }
    }
}

#[cfg(test)]
impl SoftwareTestMemoryKeyCustody {
    const WRAPPING_KEY: [u8; 32] = [0xa5; 32];

    fn set_available(&self, available: bool) {
        self.available
            .store(available, std::sync::atomic::Ordering::SeqCst);
    }

    fn set_unlocked(&self, unlocked: bool) {
        self.unlocked
            .store(unlocked, std::sync::atomic::Ordering::SeqCst);
    }

    fn require_available_and_unlocked(&self) -> Result<()> {
        if !self.available.load(std::sync::atomic::Ordering::SeqCst) {
            bail!("software_test_memory_key_custody_unavailable");
        }
        if !self.unlocked.load(std::sync::atomic::Ordering::SeqCst) {
            bail!("software_test_memory_key_subject_user_locked");
        }
        Ok(())
    }
}

#[cfg(test)]
impl MemoryKeyCustody for SoftwareTestMemoryKeyCustody {
    fn backend(&self) -> &'static str {
        "software_test_only"
    }

    fn wrap(&self, key: &[u8; 32]) -> Result<MemoryKeyEnvelope> {
        self.require_available_and_unlocked()?;
        let wrapped = encrypt_payload(&Self::WRAPPING_KEY, MEMORY_KEY_AAD.as_bytes(), key)?;
        let envelope = MemoryKeyEnvelope {
            schema: MEMORY_KEY_ENVELOPE_SCHEMA.to_string(),
            backend: self.backend().to_string(),
            subject_user_id: MEMORY_KEY_SUBJECT_USER_ID,
            key_alias: MEMORY_KEY_ALIAS.to_string(),
            key_epoch: MEMORY_KEY_EPOCH,
            aad: MEMORY_KEY_AAD.to_string(),
            key_id: sha256_bytes(key),
            nonce_b64: BASE64_STANDARD.encode(&wrapped[8..32]),
            wrapped_key_b64: BASE64_STANDARD.encode(&wrapped),
            wrapping_algorithm: "XChaCha20Poly1305-software-test-only".to_string(),
            security_level: "SOFTWARE_TEST_ONLY".to_string(),
            hardware_backed: false,
            unlocked_device_required: true,
        };
        validate_memory_key_envelope(&envelope, self.backend())?;
        Ok(envelope)
    }

    fn unwrap(&self, envelope: &MemoryKeyEnvelope) -> Result<Zeroizing<[u8; 32]>> {
        self.require_available_and_unlocked()?;
        validate_memory_key_envelope(envelope, self.backend())?;
        let wrapped = Zeroizing::new(decode_canonical_base64_bounded(
            &envelope.wrapped_key_b64,
            88,
        )?);
        if BASE64_STANDARD.encode(&wrapped[8..32]) != envelope.nonce_b64 {
            bail!("software_test_memory_key_nonce_mismatch");
        }
        let mut clear = Zeroizing::new(decrypt_payload(
            &Self::WRAPPING_KEY,
            MEMORY_KEY_AAD.as_bytes(),
            wrapped.as_slice(),
            32,
        )?);
        if clear.len() != 32 || sha256_bytes(clear.as_slice()) != envelope.key_id {
            bail!("software_test_memory_key_identity_mismatch");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(clear.as_slice());
        clear.zeroize();
        Ok(Zeroizing::new(key))
    }
}

fn load_or_create_wrapped_key(
    root: &Path,
    custody: &dyn MemoryKeyCustody,
) -> Result<(Zeroizing<[u8; 32]>, MemoryKeyEnvelope)> {
    if private_entry_exists(&root.join(LEGACY_PLAINTEXT_MEMORY_KEY_FILE))? {
        bail!("legacy_plaintext_memory_key_production_refused");
    }
    let envelope_path = root.join(MEMORY_KEY_ENVELOPE_FILE);
    if private_entry_exists(&envelope_path)? {
        let envelope = read_memory_key_envelope(&envelope_path)?;
        validate_memory_key_envelope(&envelope, custody.backend())?;
        let key = custody
            .unwrap(&envelope)
            .context("memory_key_unwrap_unavailable_or_subject_user_locked")?;
        if sha256_bytes(key.as_slice()) != envelope.key_id {
            bail!("memory_key_envelope_cleartext_identity_mismatch");
        }
        Ok((key, envelope))
    } else {
        let mut key = Zeroizing::new([0u8; 32]);
        fill_kernel_random(&mut *key)?;
        let envelope = custody
            .wrap(&key)
            .context("memory_key_wrap_unavailable_or_subject_user_locked")?;
        validate_memory_key_envelope(&envelope, custody.backend())?;
        if envelope.key_id != sha256_bytes(key.as_slice()) {
            bail!("memory_key_new_envelope_identity_mismatch");
        }
        write_new_memory_key_envelope(&envelope_path, &envelope)?;
        Ok((key, envelope))
    }
}

fn validate_memory_key_envelope(
    envelope: &MemoryKeyEnvelope,
    expected_backend: &str,
) -> Result<()> {
    if envelope.schema != MEMORY_KEY_ENVELOPE_SCHEMA
        || envelope.backend != expected_backend
        || envelope.subject_user_id != MEMORY_KEY_SUBJECT_USER_ID
        || envelope.key_alias != MEMORY_KEY_ALIAS
        || envelope.key_epoch != MEMORY_KEY_EPOCH
        || envelope.aad != MEMORY_KEY_AAD
        || !is_lower_hex(&envelope.key_id, 64)
        || !envelope.unlocked_device_required
    {
        bail!("memory_key_envelope_user_alias_epoch_or_aad_denied");
    }
    match expected_backend {
        MEMORY_KEY_ANDROID_BACKEND => {
            if envelope.wrapping_algorithm != MEMORY_KEY_ANDROID_ALGORITHM {
                bail!("memory_key_envelope_algorithm_denied");
            }
            decode_canonical_base64_bounded(&envelope.nonce_b64, 12)?;
            decode_canonical_base64_bounded(&envelope.wrapped_key_b64, 48)?;
            let hardware_level = matches!(
                envelope.security_level.as_str(),
                "STRONGBOX" | "TRUSTED_ENVIRONMENT" | "UNKNOWN_SECURE_HARDWARE"
            );
            if !hardware_level || !envelope.hardware_backed {
                bail!("memory_key_envelope_security_level_denied");
            }
        }
        #[cfg(test)]
        "software_test_only" => {
            if envelope.wrapping_algorithm != "XChaCha20Poly1305-software-test-only"
                || envelope.security_level != "SOFTWARE_TEST_ONLY"
                || envelope.hardware_backed
            {
                bail!("software_test_memory_key_envelope_contract_denied");
            }
            decode_canonical_base64_bounded(&envelope.nonce_b64, 24)?;
            decode_canonical_base64_bounded(&envelope.wrapped_key_b64, 88)?;
        }
        _ => bail!("memory_key_envelope_backend_denied"),
    }
    Ok(())
}

fn read_memory_key_envelope(path: &Path) -> Result<MemoryKeyEnvelope> {
    let file = open_private_regular_file(path, MAX_MEMORY_KEY_ENVELOPE_BYTES as u64, false)
        .context("invalid_memory_key_envelope_file_identity_or_permissions")?;
    let mut bytes = Vec::new();
    file.take(MAX_MEMORY_KEY_ENVELOPE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MEMORY_KEY_ENVELOPE_BYTES {
        bail!("memory_key_envelope_file_too_large");
    }
    serde_json::from_slice(&bytes).context("invalid_memory_key_envelope_json")
}

fn write_new_memory_key_envelope(path: &Path, envelope: &MemoryKeyEnvelope) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(envelope)?;
    if encoded.is_empty() || encoded.len() > MAX_MEMORY_KEY_ENVELOPE_BYTES {
        bail!("memory_key_envelope_encoding_boundary_denied");
    }
    let parent = open_private_directory(
        path.parent()
            .context("memory_key_envelope_parent_missing")?,
    )?;
    let name = private_file_name(path)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    validate_private_regular_file(&file, encoded.len() as u64, true)?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    if validate_private_regular_file(&file, encoded.len() as u64, false)? != encoded.len() as u64 {
        bail!("memory_key_envelope_length_changed");
    }
    parent.sync_all()?;
    Ok(())
}

fn decode_canonical_base64_bounded(value: &str, expected_bytes: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > 16 * 1024 {
        bail!("memory_key_envelope_base64_boundary_denied");
    }
    let decoded = BASE64_STANDARD
        .decode(value)
        .context("memory_key_envelope_base64_invalid")?;
    if decoded.len() != expected_bytes || BASE64_STANDARD.encode(&decoded) != value {
        bail!("memory_key_envelope_base64_noncanonical_or_wrong_length");
    }
    Ok(decoded)
}

fn new_memory_key_gateway_request_id(operation: &str) -> Result<String> {
    let mut random = [0u8; 32];
    fill_kernel_random(&mut random)?;
    Ok(format!("memory-key-{operation}-{}", sha256_bytes(&random)))
}

fn connect_android_authority_gateway(path: &Path) -> std::io::Result<UnixStream> {
    let rendered = path.to_string_lossy();
    if let Some(name) = rendered.strip_prefix('@') {
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
        UnixStream::connect_addr(&address)
    } else {
        UnixStream::connect(path)
    }
}

fn authenticate_android_authority_memory_key_peer(
    stream: &UnixStream,
    expected_uid: Option<u32>,
    expected_selinux_domain: &str,
) -> Result<()> {
    let fd = stream.as_raw_fd();
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut credentials_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut credentials_len,
        )
    };
    if status != 0
        || credentials_len as usize != std::mem::size_of::<libc::ucred>()
        || credentials.pid <= 0
        || credentials.uid < 10_000
        || expected_uid.is_some_and(|uid| uid != credentials.uid)
    {
        bail!("memory_key_authority_SO_PEERCRED_identity_denied");
    }
    let mut peer_security = [0u8; 512];
    let mut peer_security_len = peer_security.len() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            peer_security.as_mut_ptr().cast(),
            &mut peer_security_len,
        )
    };
    if status != 0 || peer_security_len == 0 || peer_security_len as usize > peer_security.len() {
        bail!("memory_key_authority_SO_PEERSEC_unavailable");
    }
    let peer_security = &peer_security[..peer_security_len as usize];
    let peer_security = peer_security.strip_suffix(&[0]).unwrap_or(peer_security);
    let actual =
        std::str::from_utf8(peer_security).context("memory_key_authority_SO_PEERSEC_not_utf8")?;
    if !selinux_security_context_matches(expected_selinux_domain, actual) {
        bail!("memory_key_authority_SO_PEERSEC_identity_denied");
    }
    Ok(())
}

fn selinux_security_context_matches(expected: &str, actual: &str) -> bool {
    if expected == actual {
        return true;
    }
    let Some(categories) = actual
        .strip_prefix(expected)
        .and_then(|suffix| suffix.strip_prefix(':'))
    else {
        return false;
    };
    !categories.is_empty()
        && categories.split(',').all(|category| {
            let category = category.strip_prefix('c').unwrap_or("");
            match category.split_once('.') {
                Some((start, end)) => start
                    .parse::<u16>()
                    .ok()
                    .zip(end.parse::<u16>().ok())
                    .is_some_and(|(start, end)| start <= end && end <= 1023),
                None => category
                    .parse::<u16>()
                    .ok()
                    .is_some_and(|category| category <= 1023),
            }
        })
}

fn constant_time_bytes_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn load_store(path: &Path) -> Result<StoreFile> {
    let file = open_private_regular_file(path, STORE_FILE_MAX_BYTES, false)
        .context("invalid_context_memory_store_file")?;
    let mut bytes = Vec::new();
    file.take(STORE_FILE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > STORE_FILE_MAX_BYTES {
        bail!("context_memory_store_file_too_large");
    }
    serde_json::from_slice(&bytes).context("invalid_context_memory_store_json")
}

fn persist_store_file(path: &Path, store: &StoreFile) -> Result<PrivatePublishState> {
    #[cfg(test)]
    if FAIL_NEXT_MEMORY_METADATA_PERSIST.with(|fail| fail.replace(false)) {
        bail!("injected_context_memory_metadata_persistence_failure");
    }
    let encoded = serde_json::to_vec_pretty(store)?;
    if encoded.len() as u64 > STORE_FILE_MAX_BYTES {
        bail!("context_memory_metadata_store_too_large");
    }
    atomic_write_private_staged(path, &encoded)
}

fn ensure_store_growth_budget(store: &StoreFile) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(store)?;
    if encoded.len() as u64 > STORE_FILE_MAX_BYTES.saturating_sub(STORE_GROWTH_HEADROOM_BYTES) {
        bail!("context_memory_store_growth_headroom_exhausted_cleanup_or_delete_required");
    }
    Ok(())
}

#[cfg(test)]
fn fail_next_memory_metadata_persist_for_test() {
    FAIL_NEXT_MEMORY_METADATA_PERSIST.with(|fail| fail.set(true));
}

#[cfg(test)]
fn fail_next_expired_memory_payload_delete_for_test() {
    FAIL_NEXT_EXPIRED_MEMORY_PAYLOAD_DELETE.with(|fail| fail.set(true));
}

#[cfg(test)]
fn fail_next_private_parent_fsync_for_test(destination_file_name: &str) {
    FAIL_NEXT_PRIVATE_PARENT_FSYNC_DESTINATION.with(|destination| {
        *destination.borrow_mut() = Some(destination_file_name.to_string());
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivatePublishState {
    Durable,
    PublishedDurabilityUncertain,
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    match atomic_write_private_staged(path, bytes)? {
        PrivatePublishState::Durable => Ok(()),
        PrivatePublishState::PublishedDurabilityUncertain => {
            bail!("private_file_publish_commit_unknown_parent_fsync_uncertain")
        }
    }
}

/// Atomically publish private bytes while preserving the rename commit point.
///
/// Before `renameat`, any error means the destination was not changed and the
/// owned temp is removed.  After `renameat`, the destination is reopened and
/// compared byte-for-byte; a parent-directory fsync failure is therefore an
/// explicit published-but-durability-uncertain result, never an invitation to
/// roll callers back to their old in-memory state.
fn atomic_write_private_staged(path: &Path, bytes: &[u8]) -> Result<PrivatePublishState> {
    let parent_path = path.parent().context("private_file_parent_missing")?;
    let parent = open_private_directory(parent_path)?;
    let destination = private_file_name(path)?;
    let mut random = [0u8; 16];
    fill_kernel_random(&mut random)?;
    let temporary_name = format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("private"),
        std::process::id(),
        sha256_bytes(&random)
    );
    let temporary = CString::new(temporary_name.as_bytes())?;
    let mut renamed = false;
    let result = (|| -> Result<PrivatePublishState> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        validate_private_regular_file(&file, bytes.len() as u64, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if validate_private_regular_file(&file, bytes.len() as u64, bytes.is_empty())?
            != bytes.len() as u64
        {
            bail!("private_file_temp_length_changed");
        }
        let rename_result = unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                parent.as_raw_fd(),
                destination.as_ptr(),
            )
        };
        if rename_result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        renamed = true;
        #[cfg(test)]
        let parent_sync = FAIL_NEXT_PRIVATE_PARENT_FSYNC_DESTINATION.with(|expected| {
            let mut expected = expected.borrow_mut();
            if expected.as_deref() == path.file_name().and_then(|name| name.to_str()) {
                *expected = None;
                Err(std::io::Error::other(
                    "injected_private_parent_fsync_failure_after_rename",
                ))
            } else {
                parent.sync_all()
            }
        });
        #[cfg(not(test))]
        let parent_sync = parent.sync_all();
        let published = open_private_regular_file_at(
            &parent,
            &destination,
            bytes.len() as u64,
            bytes.is_empty(),
        )?;
        if published.metadata()?.len() != bytes.len() as u64 {
            bail!("private_file_published_length_changed");
        }
        let mut observed = Vec::with_capacity(bytes.len());
        published
            .take(bytes.len() as u64 + 1)
            .read_to_end(&mut observed)?;
        if observed != bytes {
            bail!("private_file_published_bytes_changed");
        }
        match parent_sync {
            Ok(()) => Ok(PrivatePublishState::Durable),
            Err(_) => Ok(PrivatePublishState::PublishedDurabilityUncertain),
        }
    })();
    if result.is_err() && !renamed {
        unsafe {
            libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result
}

fn read_private_bounded_file(path: &Path, max: usize) -> Result<Vec<u8>> {
    let file = open_private_regular_file(path, max as u64, true)
        .context("invalid_encrypted_memory_payload_file")?;
    let mut value = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut value)?;
    if value.len() > max {
        bail!("encrypted_memory_payload_too_large");
    }
    Ok(value)
}

fn read_bounded_file(path: &Path, max: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
        || metadata.len() > max as u64
    {
        bail!("os_owned_bounded_file_identity_denied");
    }
    let mut value = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut value)?;
    if value.len() > max {
        bail!("os_owned_bounded_file_too_large");
    }
    Ok(value)
}

fn remove_payload_if_present(root: &Path, file: &str) -> Result<()> {
    if file.contains('/') || file.contains("..") || !file.starts_with("memory-") {
        bail!("invalid_memory_payload_reference");
    }
    let path = root.join(file);
    remove_private_regular_file(&path, true)
}

fn remove_expired_payload_if_present(root: &Path, file: &str) -> Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_EXPIRED_MEMORY_PAYLOAD_DELETE.with(|fail| fail.replace(false)) {
        bail!("injected_expired_memory_payload_delete_failure");
    }
    remove_payload_if_present(root, file)
}

fn encrypt_payload(key: &[u8; 32], associated_data: &[u8], clear: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 24];
    fill_kernel_random(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid_memory_aead_key"))?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: clear,
                aad: associated_data,
            },
        )
        .map_err(|_| anyhow::anyhow!("memory_aead_encrypt_failed"))?;
    let mut encoded =
        Vec::with_capacity(ENCRYPTED_PAYLOAD_MAGIC.len() + nonce.len() + 8 + cipher.len());
    encoded.extend_from_slice(ENCRYPTED_PAYLOAD_MAGIC);
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&(clear.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&cipher);
    Ok(encoded)
}

fn decrypt_payload(
    key: &[u8; 32],
    associated_data: &[u8],
    encoded: &[u8],
    max_clear_bytes: usize,
) -> Result<Vec<u8>> {
    const NONCE_BYTES: usize = 24;
    const TAG_BYTES: usize = 16;
    let overhead = ENCRYPTED_PAYLOAD_MAGIC.len() + NONCE_BYTES + 8 + TAG_BYTES;
    if encoded.len() < overhead
        || &encoded[..ENCRYPTED_PAYLOAD_MAGIC.len()] != ENCRYPTED_PAYLOAD_MAGIC
    {
        bail!("invalid_encrypted_memory_payload_envelope");
    }
    let nonce_start = ENCRYPTED_PAYLOAD_MAGIC.len();
    let nonce_end = nonce_start + NONCE_BYTES;
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&encoded[nonce_start..nonce_end]);
    let length_end = nonce_end + 8;
    let clear_len = u64::from_be_bytes(encoded[nonce_end..length_end].try_into()?) as usize;
    if clear_len > max_clear_bytes || encoded.len() != overhead + clear_len {
        bail!("invalid_encrypted_memory_payload_length");
    }
    XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid_memory_aead_key"))?
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &encoded[length_end..],
                aad: associated_data,
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypted_memory_payload_authentication_failed"))
}

fn base64_decode(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > 64 * 1024 || !value.len().is_multiple_of(4) {
        bail!("invalid_base64_boundary");
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    for (block_index, block) in value.as_bytes().chunks_exact(4).enumerate() {
        let last = block_index + 1 == value.len() / 4;
        let padding = usize::from(block[3] == b'=') + usize::from(block[2] == b'=');
        if padding > 2 || (!last && padding != 0) || (block[2] == b'=' && block[3] != b'=') {
            bail!("invalid_base64_padding");
        }
        let a = base64_value(block[0])?;
        let b = base64_value(block[1])?;
        let c = if block[2] == b'=' {
            0
        } else {
            base64_value(block[2])?
        };
        let d = if block[3] == b'=' {
            0
        } else {
            base64_value(block[3])?
        };
        if (padding == 2 && b & 0x0f != 0) || (padding == 1 && c & 0x03 != 0) {
            bail!("noncanonical_base64_padding");
        }
        output.push((a << 2) | (b >> 4));
        if padding < 2 {
            output.push((b << 4) | (c >> 2));
        }
        if padding == 0 {
            output.push((c << 6) | d);
        }
    }
    Ok(output)
}

fn base64_value(value: u8) -> Result<u8> {
    match value {
        b'A'..=b'Z' => Ok(value - b'A'),
        b'a'..=b'z' => Ok(value - b'a' + 26),
        b'0'..=b'9' => Ok(value - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => bail!("invalid_base64_character"),
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn fill_kernel_random(bytes: &mut [u8]) -> Result<()> {
    let mut filled = 0usize;
    while filled < bytes.len() {
        let read = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                bytes[filled..].as_mut_ptr(),
                bytes.len() - filled,
                0,
            )
        };
        if read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("kernel_random_failed");
        }
        if read == 0 {
            bail!("kernel_random_empty");
        }
        filled += usize::try_from(read)?;
    }
    Ok(())
}

fn unique_memory_key_bootstrap_request_id() -> Result<String> {
    let mut nonce = [0u8; 16];
    fill_kernel_random(&mut nonce)?;
    Ok(format!(
        "memory-key-bootstrap-{}-{}",
        now_unix_ms(),
        &sha256_bytes(&nonce)[..32]
    ))
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    use super::{
        AgentGrantConsumer, AgentGrantTarget, ContextMemoryService, ExecutionPayloadBinding,
        LEGACY_STORE_SCHEMA, MAX_REPLAY_RECORDS, STORE_SCHEMA, SoftwareTestMemoryKeyCustody,
        Subject, UI_REPLAY_ARCHIVE_FILE, UiRequestBinding, VerifiedContextCapture,
        atomic_write_private, decrypt_payload, encrypt_payload,
        fail_next_expired_memory_payload_delete_for_test,
        fail_next_memory_metadata_persist_for_test, fail_next_private_parent_fsync_for_test,
        load_store, load_ui_replay_record, persist_ui_replay_archive,
    };
    use crate::action_workflow::{DirectPlanCustodyCandidate, PlanRecoveryBinding};
    use serde_json::{Value, json};
    use trillionnium_os_types::direct_operation::{
        BINDING_SCHEMA, DirectOperationBinding, DirectOperationProviderAttempt,
        DirectOperationStableSeed, STABLE_SEED_SCHEMA,
    };
    use trillionnium_os_types::{
        AgentExecutionBinding, TaskId, ToolCallId, ToolCallInput, now_unix_ms, sha256_bytes,
        sha256_json,
    };

    fn service() -> (tempfile::TempDir, ContextMemoryService) {
        let root = tempfile::tempdir().unwrap();
        let service = ContextMemoryService::open(root.path().join("state")).unwrap();
        (root, service)
    }

    fn service_with_custody() -> (
        tempfile::TempDir,
        Arc<SoftwareTestMemoryKeyCustody>,
        ContextMemoryService,
    ) {
        let root = tempfile::tempdir().unwrap();
        let custody = Arc::new(SoftwareTestMemoryKeyCustody::default());
        let service =
            ContextMemoryService::open_with_key_custody(root.path().join("state"), custody.clone())
                .unwrap();
        (root, custody, service)
    }

    fn subject() -> Subject {
        Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap()
    }

    fn direct_ui_candidate_for_test(
        owner: &Subject,
        request_id: &str,
        payload: &Value,
        exact_plan_response: Value,
        completion_proof_sha256: Option<String>,
    ) -> DirectPlanCustodyCandidate {
        let workflow_binding = PlanRecoveryBinding {
            method: "plan".to_string(),
            request_id: request_id.to_string(),
            request_payload_sha256: sha256_bytes(&serde_json::to_vec(payload).unwrap()),
            subject_uid: owner.uid,
            subject_selinux_domain: owner.selinux_domain.clone(),
            provider_id: "openai-codex".to_string(),
            task_id: "task-direct-ui-snapshot".to_string(),
            plan_id: String::new(),
            action_id: String::new(),
            tool_call_id: String::new(),
            accepted_plan_sha256: String::new(),
            challenge_sha256: String::new(),
            challenge_expires_at_ms: 0,
        };
        let stable_seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: workflow_binding.provider_id.clone(),
            agent_id: "agent-codex-direct-v1".to_string(),
            task_id: workflow_binding.task_id.clone(),
            provider_invocation_id_sha256: sha256_bytes(request_id.as_bytes()),
            provider_session_id_sha256: sha256_bytes(b"direct-ui-provider-session"),
            subject_uid: owner.uid,
            subject_selinux_domain_sha256: sha256_bytes(owner.selinux_domain.as_bytes()),
        };
        let invocation_id = stable_seed.invocation_id().unwrap();
        let direct_binding = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            stable_seed,
            invocation_id,
            workflow_id_sha256: sha256_bytes(b"direct-ui-workflow"),
            agent_identity_key_sha256: sha256_bytes(b"direct-ui-agent-identity"),
            agent_executable_sha256: sha256_bytes(b"direct-ui-agent-executable"),
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(
                sha256_bytes(b"direct-ui-runtime-lifecycle"),
                1,
                sha256_bytes(b"direct-ui-daemon-attempt-context"),
            )
            .unwrap(),
        };
        DirectPlanCustodyCandidate::for_test(
            direct_binding,
            workflow_binding,
            sha256_bytes(b"direct-ui-action-record"),
            exact_plan_response,
            completion_proof_sha256,
        )
        .unwrap()
    }

    fn saved_memory_fixture(
        service: &ContextMemoryService,
        owner: &Subject,
        identity: &str,
    ) -> (String, std::path::PathBuf) {
        let content = format!("crash-consistent memory {identity}");
        let context = service
            .create_test_context(
                owner,
                json!({
                    "source_kind": "memory_import",
                    "source_id": format!("import:{identity}"),
                    "content": content,
                }),
            )
            .unwrap();
        let saved = service
            .call(
                "save_memory",
                &format!("save-{identity}"),
                owner,
                json!({
                    "context_id": context["context_id"],
                    "payload": content,
                    "receipt_id": "",
                    "taint_lineage": "user_imported",
                    "retention_ms": 60_000,
                }),
            )
            .unwrap();
        let memory_id = saved["memory_id"].as_str().unwrap().to_string();
        let payload_path = service.payload_root.join(format!("{memory_id}.enc"));
        (memory_id, payload_path)
    }

    fn expire_memory_fixture(service: &ContextMemoryService, memory_id: &str) {
        {
            let mut state = service.state.lock().unwrap();
            let updated = {
                let memory = state
                    .store
                    .memories
                    .iter_mut()
                    .find(|memory| memory.memory_id == memory_id)
                    .unwrap();
                memory.created_at_ms = 1;
                memory.updated_at_ms = 1;
                memory.retention_until_ms = 2;
                memory.public_json()
            };
            let tombstone = state
                .store
                .memory_saves
                .iter_mut()
                .find(|item| item.memory_id == memory_id)
                .unwrap();
            tombstone.saved_at_ms = 1;
            tombstone.result = updated;
        }
        service.persist().unwrap();
    }

    fn grant_target() -> AgentGrantTarget {
        AgentGrantTarget {
            agent_id: "agent-delegation-test".to_string(),
            peer_uid: 62_010,
            peer_gid: 62_011,
            selinux_domain: "u:r:trillionnium_test_agent:s0".to_string(),
            executable_sha256: "a".repeat(64),
            task_id: "task-delegation-test".to_string(),
            subject_user_id: 0,
        }
    }

    fn grant_consumer() -> AgentGrantConsumer {
        let target = grant_target();
        AgentGrantConsumer {
            agent_id: target.agent_id,
            peer_uid: target.peer_uid,
            peer_gid: target.peer_gid,
            selinux_domain: target.selinux_domain,
            executable_sha256: target.executable_sha256,
            task_id: target.task_id,
            subject_user_id: target.subject_user_id,
        }
    }

    fn record_held_plan(
        service: &ContextMemoryService,
        owner: &Subject,
        context: &Value,
        summary: &str,
        executable: bool,
    ) -> (String, String, String, String) {
        let workflow_id = "workflow-memory-provenance".to_string();
        let provider_id = "openai-codex".to_string();
        let egress_grant_id = format!("egress-{}", "e".repeat(64));
        let task_id = "task-memory-provenance".to_string();
        let plan_id = if executable {
            "plan-memory-provenance".to_string()
        } else {
            String::new()
        };
        let provider_output_sha256 = "b".repeat(64);
        let context_id = context["context_id"].as_str().unwrap().to_string();
        let context_sha256 = context["content_sha256"].as_str().unwrap().to_string();
        let prepare_payload = json!({
            "context_id": context_id,
            "workflow_id": workflow_id,
            "provider": provider_id,
        });
        let prepare_result = json!({
            "context_id": context_id,
            "egress_grant_id": egress_grant_id,
            "provider": provider_id,
            "content_sha256": context_sha256,
        });
        service
            .run_ui_request(
                "prepare_egress",
                "prepare-memory-provenance",
                owner,
                &prepare_payload,
                || Ok(prepare_result),
            )
            .unwrap();
        let plan_payload = json!({
            "egress_grant_id": egress_grant_id,
            "workflow_id": workflow_id,
            "provider": provider_id,
        });
        let action = if executable {
            "browser_open_bounded"
        } else {
            "context_summary_read_only"
        };
        let plan_result = json!({
            "task_id": task_id,
            "plan_id": plan_id,
            "action": action,
            "summary": summary,
            "provider_id": provider_id,
            "provider_output_sha256": provider_output_sha256,
            "execution_available": executable,
        });
        service
            .run_ui_request(
                "plan",
                "plan-memory-provenance",
                owner,
                &plan_payload,
                || Ok(plan_result),
            )
            .unwrap();
        (task_id, plan_id, workflow_id, provider_output_sha256)
    }

    #[allow(clippy::too_many_arguments)]
    fn record_held_action(
        service: &ContextMemoryService,
        owner: &Subject,
        context: &Value,
        task_id: &str,
        workflow_id: &str,
        provider_output_sha256: &str,
        receipt_plan_id: &str,
        request_id: &str,
        receipt_id: &str,
    ) -> String {
        let receipt = json!({
            "schema": "org.trillionnium.ai-authority.receipt.v2",
            "decision": "PASS_BOUNDED_ACTION",
            "receipt_id": receipt_id,
            "task_id": task_id,
            "plan_id": receipt_plan_id,
            "action": "browser_open_bounded",
            "context_sha256": context["content_sha256"],
            "provider_output_sha256": provider_output_sha256,
            "subject_user_id": owner.uid / 100_000,
            "origin_uid": owner.uid,
        });
        let approve_payload = json!({
            "task_id": task_id,
            "workflow_id": workflow_id,
            "approval_id": "approval-memory-provenance",
        });
        let approve_result = json!({
            "task_id": task_id,
            "action": "browser_open_bounded",
            "action_ok": true,
            "receipt_id": receipt_id,
            "receipt_json": receipt.to_string(),
            "explicit_approval": true,
            "single_use_consumed": true,
        });
        service
            .run_ui_request("approve", request_id, owner, &approve_payload, || {
                Ok(approve_result)
            })
            .unwrap();
        receipt_id.to_string()
    }

    fn staged_execution_payload(
        service: &ContextMemoryService,
        url: &str,
        ttl_ms: u64,
    ) -> (ToolCallInput, std::path::PathBuf) {
        let descriptor = service.describe_execution_payload(url).unwrap();
        let context_sha256 = sha256_bytes(url.as_bytes());
        let arguments = json!({
            "source_id": "context-ref:browser-test",
            "context_sha256": context_sha256,
            "payload": {
                "execution_payload_ref": descriptor.reference.clone(),
                "execution_payload_sha256": descriptor.payload_sha256.clone(),
                "execution_payload_shape": descriptor.shape.clone(),
            },
        });
        let arguments_sha256 = sha256_json(&arguments);
        let binding = AgentExecutionBinding {
            agent_id: "fixture-agent".to_string(),
            peer_uid: 5_901,
            peer_gid: 5_901,
            peer_selinux_domain: "u:r:trillionnium_codex_agent:s0".to_string(),
            agent_executable_sha256: "a".repeat(64),
            subject_user_id: 0,
            origin_uid: 10_123,
            origin_selinux_domain: "u:r:trillionnium_aishell:s0".to_string(),
            session_id: "session-browser-test".to_string(),
            task_id: TaskId("task-browser-test".to_string()),
            plan_id: "plan-browser-test".to_string(),
            action_id: "action-browser-test".to_string(),
            tool_call_id: ToolCallId("toolcall-browser-test".to_string()),
            tool_name: "android.browser.open_bounded".to_string(),
            tool_manifest_sha256: "b".repeat(64),
            accepted_plan_sha256: "c".repeat(64),
            arguments_sha256: arguments_sha256.clone(),
        };
        service
            .stage_execution_payload(
                &descriptor,
                ExecutionPayloadBinding {
                    owner_uid: binding.origin_uid,
                    owner_selinux_domain: binding.origin_selinux_domain.clone(),
                    subject_user_id: binding.subject_user_id,
                    agent_id: binding.agent_id.clone(),
                    agent_peer_uid: binding.peer_uid,
                    agent_peer_gid: binding.peer_gid,
                    agent_selinux_domain: binding.peer_selinux_domain.clone(),
                    agent_executable_sha256: binding.agent_executable_sha256.clone(),
                    task_id: binding.task_id.0.clone(),
                    session_id: binding.session_id.clone(),
                    plan_id: binding.plan_id.clone(),
                    action_id: binding.action_id.clone(),
                    tool_call_id: binding.tool_call_id.0.clone(),
                    tool_name: binding.tool_name.clone(),
                    tool_manifest_sha256: binding.tool_manifest_sha256.clone(),
                    accepted_plan_sha256: binding.accepted_plan_sha256.clone(),
                    context_sha256,
                    arguments_sha256,
                    expires_at_ms: now_unix_ms().saturating_add(ttl_ms),
                },
                url,
            )
            .unwrap();
        let path = service
            .execution_payload_root
            .join(format!("{}.enc", descriptor.reference));
        (
            ToolCallInput {
                task_id: binding.task_id.clone(),
                tool_call_id: binding.tool_call_id.clone(),
                tool_name: "android.browser.open_bounded".to_string(),
                arguments,
                agent_execution_binding: Some(binding),
            },
            path,
        )
    }

    #[test]
    fn execution_payload_ciphertext_survives_reopen_and_is_single_use() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        let sentinel = "https://example.com/private/sentinel-82941";
        let (call, path) = staged_execution_payload(&service, sentinel, 60_000);
        let encrypted = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains(sentinel));
        drop(service);

        let reopened = ContextMemoryService::open(state_root).unwrap();
        let resolved = reopened.resolve_execution_payload(&call).unwrap();
        assert_eq!(resolved.url.as_str(), sentinel);
        assert!(!path.exists());
        assert!(reopened.resolve_execution_payload(&call).is_err());
    }

    #[test]
    fn execution_payload_resolver_returns_none_only_for_bounded_notification() {
        let (_root, service) = service();
        let notification = ToolCallInput {
            task_id: TaskId("task-notification-resolver".to_string()),
            tool_call_id: ToolCallId("toolcall-notification-resolver".to_string()),
            tool_name: "android.notification.post_bounded".to_string(),
            arguments: json!({
                "payload": {"title": "Reminder", "body": "Exact body"}
            }),
            agent_execution_binding: None,
        };
        assert!(
            trillionnium_dbus::ExecutionPayloadResolver::resolve_and_consume(
                &service,
                &notification,
            )
            .unwrap()
            .is_none()
        );

        let mut unknown = notification;
        unknown.tool_name = "android.unknown".to_string();
        assert!(
            trillionnium_dbus::ExecutionPayloadResolver::resolve_and_consume(&service, &unknown)
                .is_err()
        );
    }

    #[test]
    fn planning_memory_provenance_accepts_bounded_notification_action() {
        let payload = json!({
            "workflow_id": "workflow-notification-provenance",
            "provider": "openai-codex",
            "egress_grant_id": format!("egress-{}", "e".repeat(64)),
        });
        let result = json!({
            "task_id": "task-notification-provenance",
            "plan_id": "plan-notification-provenance",
            "action": "notification_post_bounded",
            "summary": "Exact notification plan",
            "provider_id": "openai-codex",
            "provider_output_sha256": "a".repeat(64),
            "execution_available": true,
        });
        let provenance = super::ui_result_memory_provenance("plan", &payload, &result).unwrap();
        assert_eq!(provenance["action"], "notification_post_bounded");
        assert_eq!(provenance["execution_available"], true);
    }

    #[test]
    fn execution_payload_rejects_all_identity_and_plan_substitutions_without_consuming() {
        let (_root, service) = service();
        let url = "https://example.com/bound-plan";
        let (call, path) = staged_execution_payload(&service, url, 60_000);

        let mut substitutions = Vec::new();
        let mut changed = call.clone();
        changed.task_id = TaskId("task-substituted".to_string());
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.agent_execution_binding.as_mut().unwrap().plan_id = "plan-substituted".to_string();
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.agent_execution_binding.as_mut().unwrap().action_id =
            "action-substituted".to_string();
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.arguments["source_id"] = json!("context-ref:substituted");
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.agent_execution_binding.as_mut().unwrap().agent_id =
            "codex-substituted".to_string();
        substitutions.push(changed);
        let mut changed = call.clone();
        changed
            .agent_execution_binding
            .as_mut()
            .unwrap()
            .subject_user_id = 10;
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.arguments["payload"]["execution_payload_ref"] =
            json!(format!("execution-payload-{}", "b".repeat(64)));
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.agent_execution_binding.as_mut().unwrap().session_id =
            "session-substituted".to_string();
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.tool_call_id = ToolCallId("toolcall-substituted".to_string());
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.agent_execution_binding.as_mut().unwrap().origin_uid = 10_124;
        substitutions.push(changed);
        let mut changed = call.clone();
        changed
            .agent_execution_binding
            .as_mut()
            .unwrap()
            .origin_selinux_domain = "u:r:trillionnium_other_ui:s0".to_string();
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.agent_execution_binding.as_mut().unwrap().peer_uid = 5_903;
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.agent_execution_binding.as_mut().unwrap().peer_gid = 5_903;
        substitutions.push(changed);
        let mut changed = call.clone();
        changed
            .agent_execution_binding
            .as_mut()
            .unwrap()
            .peer_selinux_domain = "u:r:trillionnium_other_agent:s0".to_string();
        substitutions.push(changed);
        let mut changed = call.clone();
        changed
            .agent_execution_binding
            .as_mut()
            .unwrap()
            .agent_executable_sha256 = "d".repeat(64);
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.arguments["payload"]["execution_payload_sha256"] = json!("e".repeat(64));
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.arguments["payload"]["execution_payload_shape"] = json!("wrong_shape.v1");
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.arguments["context_sha256"] = json!("f".repeat(64));
        substitutions.push(changed);
        let mut changed = call.clone();
        changed
            .agent_execution_binding
            .as_mut()
            .unwrap()
            .arguments_sha256 = "0".repeat(64);
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.agent_execution_binding.as_mut().unwrap().tool_name =
            "android.file.write".to_string();
        substitutions.push(changed);
        let mut changed = call.clone();
        changed
            .agent_execution_binding
            .as_mut()
            .unwrap()
            .tool_manifest_sha256 = "1".repeat(64);
        substitutions.push(changed);
        let mut changed = call.clone();
        changed
            .agent_execution_binding
            .as_mut()
            .unwrap()
            .accepted_plan_sha256 = "2".repeat(64);
        substitutions.push(changed);
        let mut changed = call.clone();
        changed.tool_name = "android.file.write".to_string();
        substitutions.push(changed);

        for substituted in substitutions {
            assert!(service.resolve_execution_payload(&substituted).is_err());
            assert!(path.exists());
        }
        assert_eq!(
            service
                .resolve_execution_payload(&call)
                .unwrap()
                .url
                .as_str(),
            url
        );
        assert!(!path.exists());
    }

    #[test]
    fn execution_payload_expiry_destroys_ciphertext() {
        let (_root, service) = service();
        let (call, path) =
            staged_execution_payload(&service, "https://example.com/short-lived", 100);
        std::thread::sleep(std::time::Duration::from_millis(150));
        let error = service.resolve_execution_payload(&call).err().unwrap();
        assert!(error.to_string().contains("expired_and_destroyed"));
        assert!(!path.exists());
    }

    #[test]
    fn corrupt_execution_payload_is_quarantined_without_blocking_other_refs_or_reopen() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        let (corrupt_call, corrupt_path) =
            staged_execution_payload(&service, "https://example.com/corrupt", 60_000);
        let (valid_call, valid_path) =
            staged_execution_payload(&service, "https://example.com/still-valid", 60_000);
        let mut encrypted = std::fs::read(&corrupt_path).unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x80;
        std::fs::write(&corrupt_path, encrypted).unwrap();
        let error = service
            .resolve_execution_payload(&corrupt_call)
            .err()
            .unwrap();
        assert!(error.to_string().contains("corrupt_and_quarantined"));
        assert!(!corrupt_path.exists());
        assert!(
            std::fs::read_dir(state_root.join("execution-payload-quarantine"))
                .unwrap()
                .next()
                .is_some()
        );
        let integrity: Value = serde_json::from_slice(
            &std::fs::read(state_root.join("execution-payload-integrity.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            integrity["event_code"],
            "execution_payload_invalid_entry_quarantined"
        );
        assert_eq!(
            service
                .resolve_execution_payload(&valid_call)
                .unwrap()
                .url
                .as_str(),
            "https://example.com/still-valid"
        );
        assert!(!valid_path.exists());
        drop(service);
        ContextMemoryService::open(state_root).unwrap();
    }

    #[test]
    fn oversized_store_entry_isolated_during_open_instead_of_dos() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        drop(ContextMemoryService::open(state_root.clone()).unwrap());
        let bad = state_root
            .join("execution-payloads")
            .join(format!("execution-payload-{}.enc", "c".repeat(64)));
        std::fs::write(&bad, vec![0u8; super::MAX_EXECUTION_PAYLOAD_FILE_BYTES + 1]).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600)).unwrap();
        ContextMemoryService::open(state_root.clone()).unwrap();
        assert!(!bad.exists());
        assert!(
            std::fs::read_dir(state_root.join("execution-payload-quarantine"))
                .unwrap()
                .next()
                .is_some()
        );
    }

    #[test]
    fn execution_payload_url_is_canonical_bounded_and_escape_safe() {
        let (_root, service) = service();
        let prefix = "https://example.com/";
        let maximum = format!(
            "{prefix}{}",
            "a".repeat(super::MAX_EXECUTION_URL_BYTES - prefix.len())
        );
        service.describe_execution_payload(&maximum).unwrap();
        assert!(
            service
                .describe_execution_payload(&format!("{maximum}a"))
                .is_err()
        );
        for invalid in [
            "https://example.com/no\\escape",
            "https://example.com/no\"quote",
            "https://user@example.com/",
            "https://example.com/#fragment",
            "http://example.com/",
            "https://example.com",
        ] {
            assert!(
                service.describe_execution_payload(invalid).is_err(),
                "{invalid}"
            );
        }

        let metadata = service
            .create_test_context(
                &subject(),
                json!({
                    "source_kind": "browser",
                    "source_id": "browser:user-input",
                    "content": "https://example.com",
                }),
            )
            .unwrap();
        let snapshot = service
            .resolve_context(&subject(), metadata["context_id"].as_str().unwrap())
            .unwrap();
        assert_eq!(snapshot.content, "https://example.com/");
    }

    #[test]
    fn context_is_subject_bound_bounded_and_revocable() {
        let (_root, service) = service();
        let owner = subject();
        let metadata = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "file",
                    "source_id": "saf:documents",
                    "content": "private context",
                    "privacy_class": "local_private",
                    "freshness_ttl_ms": 60_000,
                }),
            )
            .unwrap();
        assert!(metadata.get("content").is_none());
        let context_id = metadata.get("context_id").and_then(Value::as_str).unwrap();
        let snapshot = service.resolve_context(&owner, context_id).unwrap();
        assert_eq!(snapshot.content, "private context");
        let other = Subject::new(10_124, "u:r:trillionnium_aishell:s0:c1,c2").unwrap();
        assert!(service.resolve_context(&other, context_id).is_err());
        service
            .call(
                "revoke_context",
                "context-revoke-1",
                &owner,
                json!({ "context_id": context_id }),
            )
            .unwrap();
        assert!(service.resolve_context(&owner, context_id).is_err());
    }

    #[test]
    fn context_memory_public_payloads_are_closed_world_and_typed() {
        let (_root, service) = service();
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "memory_import",
                    "source_id": "import:strict-memory-abi",
                    "content": "strict memory payload",
                }),
            )
            .unwrap();
        let context_id = context["context_id"].as_str().unwrap();
        for (request_id, method, payload) in [
            (
                "strict-memory-unknown",
                "save_memory",
                json!({
                    "context_id": context_id,
                    "payload": "strict memory payload",
                    "debug_override": true,
                }),
            ),
            (
                "strict-memory-retention-type",
                "save_memory",
                json!({
                    "context_id": context_id,
                    "payload": "strict memory payload",
                    "retention_ms": "60000",
                }),
            ),
            (
                "strict-memory-list-type",
                "list_memory",
                json!({"include_payload": "false"}),
            ),
            (
                "strict-context-revoke-extra",
                "revoke_context",
                json!({"context_id": context_id, "force": true}),
            ),
        ] {
            let error = service
                .call(method, request_id, &owner, payload)
                .expect_err("ambiguous Context/Memory ABI input must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("payload_missing_or_unknown_fields")
                    || error.to_string().contains("payload_field_type_denied"),
                "unexpected denial for {method}: {error:#}"
            );
        }
        assert_eq!(
            service.resolve_context(&owner, context_id).unwrap().content,
            "strict memory payload"
        );
        assert_eq!(
            service
                .call(
                    "list_memory",
                    "strict-memory-list-valid",
                    &owner,
                    json!({"include_payload": false, "limit": 1}),
                )
                .unwrap()["count"],
            0
        );
    }

    #[test]
    fn orphaned_memory_ciphertexts_are_removed_but_unknown_entries_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        drop(ContextMemoryService::open(state_root.clone()).unwrap());
        let payload_root = state_root.join("payloads");
        let orphan = payload_root.join(format!("memory-{}.enc", "a".repeat(64)));
        let interrupted_temporary = payload_root.join(format!(
            ".memory-{}.enc.tmp-1234-{}",
            "b".repeat(64),
            "c".repeat(64)
        ));
        std::fs::write(&orphan, b"crash-window-ciphertext").unwrap();
        std::fs::set_permissions(&orphan, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&interrupted_temporary, []).unwrap();
        std::fs::set_permissions(
            &interrupted_temporary,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        drop(ContextMemoryService::open(state_root.clone()).unwrap());
        assert!(!orphan.exists());
        assert!(!interrupted_temporary.exists());

        let unknown = payload_root.join("unexpected.enc");
        std::fs::write(&unknown, b"unexpected-private-entry").unwrap();
        std::fs::set_permissions(&unknown, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = ContextMemoryService::open(state_root)
            .err()
            .expect("unknown payload entries must prevent service startup");
        assert!(
            error
                .to_string()
                .contains("unexpected_memory_payload_entry")
        );
        assert!(unknown.exists());
    }

    #[test]
    fn cleanup_metadata_persist_failure_keeps_referenced_payload_for_reopen_retry() {
        let (root, service) = service();
        let owner = subject();
        let (memory_id, payload_path) =
            saved_memory_fixture(&service, &owner, "cleanup-persist-failure");
        expire_memory_fixture(&service, &memory_id);
        let metadata_path = root.path().join("state/metadata.json");
        let metadata_before = std::fs::read(&metadata_path).unwrap();

        fail_next_memory_metadata_persist_for_test();
        let error = service.cleanup().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected_context_memory_metadata_persistence_failure")
        );
        assert!(payload_path.exists());
        assert_eq!(std::fs::read(&metadata_path).unwrap(), metadata_before);
        assert!(
            service
                .state
                .lock()
                .unwrap()
                .store
                .memories
                .iter()
                .any(|memory| memory.memory_id == memory_id)
        );

        drop(service);
        let reopened = ContextMemoryService::open(root.path().join("state")).unwrap();
        assert!(!payload_path.exists());
        assert!(reopened.state.lock().unwrap().store.memories.is_empty());
    }

    #[test]
    fn cleanup_payload_delete_failure_leaves_dereferenced_orphan_for_reopen_prune() {
        let (root, service) = service();
        let owner = subject();
        let (memory_id, payload_path) =
            saved_memory_fixture(&service, &owner, "cleanup-delete-failure");
        expire_memory_fixture(&service, &memory_id);

        fail_next_expired_memory_payload_delete_for_test();
        let error = service.cleanup().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("injected_expired_memory_payload_delete_failure")
        );
        assert!(payload_path.exists());
        assert!(
            load_store(&root.path().join("state/metadata.json"))
                .unwrap()
                .memories
                .is_empty()
        );

        drop(service);
        let reopened = ContextMemoryService::open(root.path().join("state")).unwrap();
        assert!(!payload_path.exists());
        assert!(reopened.state.lock().unwrap().store.memories.is_empty());
    }

    #[test]
    fn startup_expiry_metadata_persist_failure_never_deletes_still_referenced_payload() {
        let (root, service) = service();
        let owner = subject();
        let (memory_id, payload_path) =
            saved_memory_fixture(&service, &owner, "startup-persist-failure");
        expire_memory_fixture(&service, &memory_id);
        let metadata_path = root.path().join("state/metadata.json");
        let metadata_before = std::fs::read(&metadata_path).unwrap();
        drop(service);

        fail_next_memory_metadata_persist_for_test();
        let error = ContextMemoryService::open(root.path().join("state"))
            .err()
            .expect("injected startup metadata commit must fail");
        assert!(
            error
                .to_string()
                .contains("injected_context_memory_metadata_persistence_failure")
        );
        assert!(payload_path.exists());
        assert_eq!(std::fs::read(&metadata_path).unwrap(), metadata_before);

        let reopened = ContextMemoryService::open(root.path().join("state")).unwrap();
        assert!(!payload_path.exists());
        assert!(reopened.state.lock().unwrap().store.memories.is_empty());
    }

    #[test]
    fn startup_expiry_payload_delete_failure_is_recoverable_after_dereference_commit() {
        let (root, service) = service();
        let owner = subject();
        let (memory_id, payload_path) =
            saved_memory_fixture(&service, &owner, "startup-delete-failure");
        expire_memory_fixture(&service, &memory_id);
        let metadata_path = root.path().join("state/metadata.json");
        drop(service);

        fail_next_expired_memory_payload_delete_for_test();
        let error = ContextMemoryService::open(root.path().join("state"))
            .err()
            .expect("injected startup payload deletion must fail");
        assert!(
            error
                .to_string()
                .contains("injected_expired_memory_payload_delete_failure")
        );
        assert!(payload_path.exists());
        assert!(load_store(&metadata_path).unwrap().memories.is_empty());

        let reopened = ContextMemoryService::open(root.path().join("state")).unwrap();
        assert!(!payload_path.exists());
        assert!(reopened.state.lock().unwrap().store.memories.is_empty());
    }

    #[test]
    fn verified_browser_context_requires_exact_authority_url_binding() {
        let (_root, service) = service();
        let owner = subject();
        let now = now_unix_ms();
        let url = "https://example.com/exact";
        let content_sha256 = sha256_bytes(url.as_bytes());
        service
            .reserve_context_import_capacity(
                &owner,
                "verified-browser-context-1",
                &format!("capture-{}", "a".repeat(64)),
                &"b".repeat(64),
                "authority-capture-request-1",
                &format!("authority-url:{content_sha256}"),
                "browser",
                &content_sha256,
                now + 120_000,
            )
            .unwrap();
        let metadata = service
            .insert_verified_context(
                &owner,
                VerifiedContextCapture {
                    capture_id: format!("capture-{}", "a".repeat(64)),
                    capture_receipt_id: "b".repeat(64),
                    capture_request_id: "authority-capture-request-1".to_string(),
                    requesting_uid: owner.uid,
                    subject_user_id: owner.uid / 100_000,
                    boot_id_sha256: service.boot_id_sha256.clone(),
                    source_id: format!("authority-url:{content_sha256}"),
                    source_kind: "browser".to_string(),
                    captured_at_ms: now.saturating_sub(1),
                    expires_at_ms: now + 120_000,
                    privacy_class: "local_private".to_string(),
                    content_sha256: content_sha256.clone(),
                    content_bytes: url.len(),
                    content: url.to_string(),
                    source_metadata: json!({
                        "capture_method": "android_authority_secure_https_url_entry",
                        "user_entered_in_authority_ui": true,
                    }),
                    origin_request_id: "verified-browser-context-1".to_string(),
                    resolution_sha256: sha256_bytes(b"verified-browser-resolution-1"),
                },
            )
            .unwrap();
        service
            .acknowledge_context_imported(
                &owner,
                metadata["context_id"].as_str().unwrap(),
                &sha256_bytes(b"verified-browser-resolution-1"),
            )
            .unwrap();
        let snapshot = service
            .resolve_context(&owner, metadata["context_id"].as_str().unwrap())
            .unwrap();
        assert_eq!(snapshot.source_kind, "browser");
        assert_eq!(snapshot.content, url);

        let error = service
            .insert_verified_context(
                &owner,
                VerifiedContextCapture {
                    capture_id: format!("capture-{}", "c".repeat(64)),
                    capture_receipt_id: "d".repeat(64),
                    capture_request_id: "authority-capture-request-2".to_string(),
                    requesting_uid: owner.uid,
                    subject_user_id: owner.uid / 100_000,
                    boot_id_sha256: service.boot_id_sha256.clone(),
                    source_id: format!("authority-url:{content_sha256}"),
                    source_kind: "browser".to_string(),
                    captured_at_ms: now.saturating_sub(1),
                    expires_at_ms: now + 120_000,
                    privacy_class: "local_private".to_string(),
                    content_sha256,
                    content_bytes: "https://EXAMPLE.com/exact".len(),
                    content: "https://EXAMPLE.com/exact".to_string(),
                    source_metadata: json!({"capture_method": "forged"}),
                    origin_request_id: "verified-browser-context-2".to_string(),
                    resolution_sha256: sha256_bytes(b"verified-browser-resolution-2"),
                },
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("verified_context_capture_binding_denied")
        );
    }

    #[test]
    fn memory_payload_is_encrypted_subject_scoped_and_deleted() {
        let (root, service) = service();
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "memory_import",
                    "source_id": "import:encrypted-memory-test",
                    "content": "derived private summary",
                }),
            )
            .unwrap();
        let context_id = context.get("context_id").and_then(Value::as_str).unwrap();
        let saved = service
            .call(
                "save_memory",
                "memory-save-1",
                &owner,
                json!({
                    "context_id": context_id,
                    "payload": "derived private summary",
                    "receipt_id": "",
                    "taint_lineage": "user_imported",
                }),
            )
            .unwrap();
        let memory_id = saved.get("memory_id").and_then(Value::as_str).unwrap();
        let encrypted = std::fs::read(
            root.path()
                .join("state/payloads")
                .join(format!("{memory_id}.enc")),
        )
        .unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains("derived private summary"));
        let listed = service
            .call(
                "list_memory",
                "memory-list-1",
                &owner,
                json!({ "include_payload": false }),
            )
            .unwrap();
        assert_eq!(listed["payload_included"], false);
        assert!(listed["items"][0].get("payload").is_none());
        service
            .call(
                "delete_memory",
                "memory-delete-1",
                &owner,
                json!({
                    "memory_id": memory_id,
                    "expected_payload_sha256": saved["payload_sha256"],
                    "expected_updated_at_ms": saved["updated_at_ms"],
                }),
            )
            .unwrap();
        assert!(
            !root
                .path()
                .join("state/payloads")
                .join(format!("{memory_id}.enc"))
                .exists()
        );
    }

    #[test]
    fn explicit_saved_memory_selection_materializes_opaque_bounded_planning_snapshots() {
        let (_root, service) = service();
        let owner = subject();
        let identity = "planning-selection-positive";
        let cleartext = format!("crash-consistent memory {identity}");
        let (memory_id, _) = saved_memory_fixture(&service, &owner, identity);
        let retention_until_ms = service
            .state
            .lock()
            .unwrap()
            .store
            .memories
            .iter()
            .find(|memory| memory.memory_id == memory_id)
            .unwrap()
            .retention_until_ms;

        let first = service
            .materialize_memory_planning_context(&owner, &memory_id)
            .unwrap();
        let second = service
            .materialize_memory_planning_context(&owner, &memory_id)
            .unwrap();
        let first_context_id = first["context_id"].as_str().unwrap();
        assert_ne!(first_context_id, second["context_id"].as_str().unwrap());
        assert_eq!(first["source_kind"], "memory");
        assert!(
            first["source_id"]
                .as_str()
                .unwrap()
                .strip_prefix("memory-ref:")
                .is_some_and(|digest| super::is_lower_hex(digest, 64))
        );
        assert_eq!(first["source_metadata"]["memory_ref"], first["source_id"]);
        assert_eq!(first["raw_content_persisted"], false);
        assert!(first["freshness_ttl_ms"].as_u64().unwrap() <= 10 * 60 * 1_000);
        assert!(first["expires_at_ms"].as_u64().unwrap() <= retention_until_ms);
        let public = serde_json::to_string(&first).unwrap();
        assert_eq!(first["selected_memory_id"], memory_id);
        assert!(!public.contains(&cleartext));

        let snapshot = service.resolve_context(&owner, first_context_id).unwrap();
        assert_eq!(snapshot.source_kind, "memory");
        assert_eq!(snapshot.content, cleartext);
        assert_eq!(snapshot.content_sha256, sha256_bytes(cleartext.as_bytes()));

        let (payload_sha256, updated_at_ms) = {
            let state = service.state.lock().unwrap();
            let memory = state
                .store
                .memories
                .iter()
                .find(|memory| memory.memory_id == memory_id)
                .unwrap();
            (memory.payload_sha256.clone(), memory.updated_at_ms)
        };
        let deleted = service
            .call(
                "delete_memory",
                "delete-materialized-memory-source",
                &owner,
                json!({
                    "memory_id": memory_id,
                    "expected_payload_sha256": payload_sha256,
                    "expected_updated_at_ms": updated_at_ms,
                }),
            )
            .unwrap();
        assert_eq!(deleted["derived_external_artifacts_may_remain"], true);
        assert_eq!(deleted["raw_payload_retained"], false);
        assert!(service.resolve_context(&owner, first_context_id).is_err());
    }

    #[test]
    fn saved_memory_selection_rejects_wrong_subject_id_expiry_and_capacity_without_insertion() {
        let (_root, binding_service) = service();
        let owner = subject();
        let (memory_id, _) = saved_memory_fixture(&binding_service, &owner, "selection-bindings");
        let other = Subject::new(10_124, "u:r:trillionnium_aishell:s0:c1").unwrap();
        let contexts_before = binding_service.state.lock().unwrap().contexts.len();
        assert!(
            binding_service
                .materialize_memory_planning_context(&other, &memory_id)
                .is_err()
        );
        assert!(
            binding_service
                .materialize_memory_planning_context(&owner, &format!("memory-{}", "f".repeat(64)),)
                .is_err()
        );
        assert_eq!(
            binding_service.state.lock().unwrap().contexts.len(),
            contexts_before
        );

        expire_memory_fixture(&binding_service, &memory_id);
        assert!(
            binding_service
                .materialize_memory_planning_context(&owner, &memory_id)
                .is_err()
        );
        assert_eq!(
            binding_service.state.lock().unwrap().contexts.len(),
            contexts_before
        );

        let (_capacity_root, capacity_service) = service();
        let (capacity_memory_id, _) =
            saved_memory_fixture(&capacity_service, &owner, "selection-capacity");
        for index in 1..super::MAX_CONTEXTS {
            capacity_service
                .create_test_context(
                    &owner,
                    json!({
                        "source_kind": "memory_import",
                        "source_id": format!("import:capacity-{index}"),
                        "content": format!("capacity fixture {index}"),
                        // Creating 127 durable fixtures can take longer than
                        // the ordinary test-context TTL on a busy host. Keep
                        // this capacity vector alive long enough to exercise
                        // the intended MAX_CONTEXTS guard deterministically.
                        "freshness_ttl_ms": super::MAX_CONTEXT_TTL_MS,
                    }),
                )
                .unwrap();
        }
        assert_eq!(
            capacity_service.state.lock().unwrap().contexts.len(),
            super::MAX_CONTEXTS
        );
        assert!(
            capacity_service
                .materialize_memory_planning_context(&owner, &capacity_memory_id)
                .unwrap_err()
                .to_string()
                .contains("context_handle_capacity_reached")
        );
        assert_eq!(
            capacity_service.state.lock().unwrap().contexts.len(),
            super::MAX_CONTEXTS
        );
    }

    #[test]
    fn saved_memory_selection_fails_closed_on_ciphertext_tamper_and_locked_custody() {
        let (_root, tamper_service) = service();
        let owner = subject();
        let (memory_id, payload_path) =
            saved_memory_fixture(&tamper_service, &owner, "selection-tamper");
        let contexts_before = tamper_service.state.lock().unwrap().contexts.len();
        let mut encrypted = std::fs::read(&payload_path).unwrap();
        *encrypted.last_mut().unwrap() ^= 0x01;
        std::fs::write(&payload_path, encrypted).unwrap();
        assert!(
            tamper_service
                .materialize_memory_planning_context(&owner, &memory_id)
                .is_err()
        );
        assert_eq!(
            tamper_service.state.lock().unwrap().contexts.len(),
            contexts_before
        );

        let (_utf8_root, utf8_service) = service();
        let (utf8_memory_id, utf8_payload_path) =
            saved_memory_fixture(&utf8_service, &owner, "selection-invalid-utf8");
        let invalid_utf8 = [0xff, 0xfe, 0xfd];
        let associated_data = super::memory_associated_data(&owner, &utf8_memory_id);
        let encrypted_invalid_utf8 =
            encrypt_payload(&utf8_service.key, &associated_data, &invalid_utf8).unwrap();
        atomic_write_private(&utf8_payload_path, &encrypted_invalid_utf8).unwrap();
        {
            let mut state = utf8_service.state.lock().unwrap();
            let memory = state
                .store
                .memories
                .iter_mut()
                .find(|memory| memory.memory_id == utf8_memory_id)
                .unwrap();
            memory.payload_bytes = invalid_utf8.len();
            memory.payload_sha256 = sha256_bytes(&invalid_utf8);
        }
        let utf8_contexts_before = utf8_service.state.lock().unwrap().contexts.len();
        assert!(
            utf8_service
                .materialize_memory_planning_context(&owner, &utf8_memory_id)
                .unwrap_err()
                .to_string()
                .contains("memory_planning_context_payload_not_utf8")
        );
        assert_eq!(
            utf8_service.state.lock().unwrap().contexts.len(),
            utf8_contexts_before
        );

        let (_locked_root, custody, locked_service) = service_with_custody();
        let (locked_memory_id, _) =
            saved_memory_fixture(&locked_service, &owner, "selection-locked");
        let locked_contexts_before = locked_service.state.lock().unwrap().contexts.len();
        custody.set_unlocked(false);
        assert!(
            locked_service
                .materialize_memory_planning_context(&owner, &locked_memory_id)
                .unwrap_err()
                .to_string()
                .contains("subject_user_locked")
        );
        assert_eq!(
            locked_service.state.lock().unwrap().contexts.len(),
            locked_contexts_before
        );
    }

    #[test]
    fn memory_import_requires_explicit_exact_unreceipted_lineage() {
        let (_root, service) = service();
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "memory_import",
                    "source_id": "import:explicit-provenance",
                    "content": "explicit imported memory",
                }),
            )
            .unwrap();
        let context_id = context["context_id"].as_str().unwrap();
        for (request_id, payload, receipt_id, taint_lineage) in [
            (
                "memory-import-wrong-payload",
                "substituted imported memory",
                "",
                "user_imported",
            ),
            (
                "memory-import-forged-receipt",
                "explicit imported memory",
                &"a".repeat(64),
                "user_imported",
            ),
            (
                "memory-import-wrong-lineage",
                "explicit imported memory",
                "",
                "untainted",
            ),
        ] {
            let error = service
                .call(
                    "save_memory",
                    request_id,
                    &owner,
                    json!({
                        "context_id": context_id,
                        "payload": payload,
                        "receipt_id": receipt_id,
                        "taint_lineage": taint_lineage,
                    }),
                )
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("memory_user_import_provenance_mismatch")
            );
        }
        let saved = service
            .call(
                "save_memory",
                "memory-import-exact",
                &owner,
                json!({
                    "context_id": context_id,
                    "payload": "explicit imported memory",
                    "receipt_id": "",
                    "taint_lineage": "user_imported",
                }),
            )
            .unwrap();
        assert_eq!(saved["provenance_kind"], "user_imported");
        assert_eq!(saved["receipt_id"], "");
        assert_eq!(saved["task_id"], "");
        assert_eq!(saved["plan_id"], "");
    }

    #[test]
    fn legacy_v1_memory_is_labeled_unverified_and_cannot_spoof_provenance() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let owner = subject();
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "memory_import",
                    "source_id": "import:legacy-metadata",
                    "content": "legacy memory payload",
                }),
            )
            .unwrap();
        service
            .call(
                "save_memory",
                "legacy-memory-save",
                &owner,
                json!({
                    "context_id": context["context_id"],
                    "payload": "legacy memory payload",
                    "receipt_id": "",
                    "taint_lineage": "user_imported",
                }),
            )
            .unwrap();
        drop(service);

        let metadata_path = state_root.join("metadata.json");
        let mut metadata: Value =
            serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
        metadata["memory_saves"] = json!([]);
        let memory = metadata["memories"][0].as_object_mut().unwrap();
        memory.insert("schema".to_string(), json!(super::LEGACY_MEMORY_SCHEMA));
        for field in ["provenance_kind", "provenance_id", "task_id", "plan_id"] {
            memory.remove(field);
        }
        std::fs::write(
            &metadata_path,
            serde_json::to_vec_pretty(&metadata).unwrap(),
        )
        .unwrap();

        let reopened = ContextMemoryService::open(state_root.clone()).unwrap();
        let listed = reopened
            .call(
                "list_memory",
                "legacy-memory-list",
                &owner,
                json!({ "include_payload": false }),
            )
            .unwrap();
        assert_eq!(listed["items"][0]["provenance_kind"], "legacy_unverified");
        drop(reopened);

        let mut spoofed: Value =
            serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
        spoofed["memories"][0]["provenance_kind"] = json!("planning_result");
        std::fs::write(&metadata_path, serde_json::to_vec_pretty(&spoofed).unwrap()).unwrap();
        assert!(
            ContextMemoryService::open(state_root)
                .err()
                .expect("legacy provenance spoof must fail closed")
                .to_string()
                .contains("legacy_memory_provenance_spoof_denied")
        );
    }

    #[test]
    fn arbitrary_memory_receipt_taint_and_payload_claims_fail_closed() {
        let (_root, service) = service();
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "browser_extract",
                    "source_id": "app:browser",
                    "content": "source context",
                }),
            )
            .unwrap();
        let context_id = context["context_id"].as_str().unwrap();
        for (request_id, receipt_id, taint_lineage) in [
            ("unbound-memory-no-receipt", "", "untainted"),
            (
                "unbound-memory-forged-receipt",
                &"f".repeat(64),
                "untainted",
            ),
            ("unbound-memory-forged-taint", "", "user_imported"),
        ] {
            assert!(
                service
                    .call(
                        "save_memory",
                        request_id,
                        &owner,
                        json!({
                            "context_id": context_id,
                            "payload": "client-authored summary",
                            "receipt_id": receipt_id,
                            "taint_lineage": taint_lineage,
                        }),
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn os_held_plan_and_action_lineage_binds_memory_exactly_once() {
        let (_root, service) = service();
        let owner = subject();
        let summary = "OS-held browser plan summary";
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "browser",
                    "source_id": "browser:user-input",
                    "content": "https://example.com/",
                }),
            )
            .unwrap();
        let (task_id, plan_id, workflow_id, provider_output_sha256) =
            record_held_plan(&service, &owner, &context, summary, true);
        let mismatched_plan_receipt = record_held_action(
            &service,
            &owner,
            &context,
            &task_id,
            &workflow_id,
            &provider_output_sha256,
            "plan-substituted",
            "approve-memory-provenance-wrong-plan",
            &"c".repeat(64),
        );
        let context_id = context["context_id"].as_str().unwrap();
        assert!(
            service
                .call(
                    "save_memory",
                    "memory-save-wrong-plan",
                    &owner,
                    json!({
                        "context_id": context_id,
                        "payload": summary,
                        "receipt_id": mismatched_plan_receipt,
                        "taint_lineage": "untainted",
                    }),
                )
                .unwrap_err()
                .to_string()
                .contains("provenance_missing_or_mismatched")
        );
        let receipt_id = record_held_action(
            &service,
            &owner,
            &context,
            &task_id,
            &workflow_id,
            &provider_output_sha256,
            &plan_id,
            "approve-memory-provenance-exact",
            &"d".repeat(64),
        );
        let other_context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "browser",
                    "source_id": "browser:other-input",
                    "content": "https://example.com/",
                }),
            )
            .unwrap();
        assert!(
            service
                .call(
                    "save_memory",
                    "memory-save-wrong-context",
                    &owner,
                    json!({
                        "context_id": other_context["context_id"],
                        "payload": summary,
                        "receipt_id": receipt_id,
                        "taint_lineage": "untainted",
                    }),
                )
                .is_err()
        );
        let other_subject = Subject::new(10_124, "u:r:trillionnium_aishell:s0:c1").unwrap();
        let other_subject_context = service
            .create_test_context(
                &other_subject,
                json!({
                    "source_kind": "browser",
                    "source_id": "browser:other-subject",
                    "content": "https://example.com/",
                }),
            )
            .unwrap();
        assert!(
            service
                .call(
                    "save_memory",
                    "memory-save-wrong-subject",
                    &other_subject,
                    json!({
                        "context_id": other_subject_context["context_id"],
                        "payload": summary,
                        "receipt_id": receipt_id,
                        "taint_lineage": "untainted",
                    }),
                )
                .is_err()
        );
        for (request_id, context_id, payload, receipt) in [
            (
                "memory-save-forged-receipt",
                context_id,
                summary,
                "e".repeat(64),
            ),
            (
                "memory-save-substituted-payload",
                context_id,
                "substituted summary",
                receipt_id.clone(),
            ),
        ] {
            assert!(
                service
                    .call(
                        "save_memory",
                        request_id,
                        &owner,
                        json!({
                            "context_id": context_id,
                            "payload": payload,
                            "receipt_id": receipt,
                            "taint_lineage": "untainted",
                        }),
                    )
                    .is_err()
            );
        }
        let saved = service
            .call(
                "save_memory",
                "memory-save-exact-action-lineage",
                &owner,
                json!({
                    "context_id": context_id,
                    "payload": summary,
                    "receipt_id": receipt_id,
                    "taint_lineage": "untainted",
                }),
            )
            .unwrap();
        assert_eq!(
            saved["provenance_kind"],
            "planning_result_with_action_receipt"
        );
        assert_eq!(saved["task_id"], task_id);
        assert_eq!(saved["plan_id"], plan_id);
        assert_eq!(saved["receipt_id"], receipt_id);
        assert!(
            service
                .call(
                    "save_memory",
                    "memory-save-action-lineage-duplicate",
                    &owner,
                    json!({
                        "context_id": context_id,
                        "payload": summary,
                        "receipt_id": receipt_id,
                        "taint_lineage": "untainted",
                    }),
                )
                .unwrap_err()
                .to_string()
                .contains("memory_provenance_already_consumed")
        );
    }

    #[test]
    fn os_held_read_only_plan_can_save_only_its_exact_result() {
        let (root, service) = service();
        let owner = subject();
        let summary = "OS-held read-only summary";
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "browser_extract",
                    "source_id": "app:browser",
                    "content": "read-only source context",
                }),
            )
            .unwrap();
        let (task_id, plan_id, _, _) = record_held_plan(&service, &owner, &context, summary, false);
        let request_hash = sha256_bytes("plan-memory-provenance".as_bytes());
        let record = super::load_ui_replay_record(
            &root
                .path()
                .join("state/ui-replay")
                .join(format!("{request_hash}.json")),
        )
        .unwrap();
        let encrypted = std::fs::read(
            root.path()
                .join("state/ui-replay-outcomes")
                .join(&record.outcome_file),
        )
        .unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains(summary));
        let aad = super::ui_replay_associated_data(
            &owner,
            "plan",
            "plan-memory-provenance",
            &record.payload_sha256,
        );
        let clear = decrypt_payload(
            &service.key,
            &aad,
            &encrypted,
            super::MAX_UI_REPLAY_OUTCOME_BYTES,
        )
        .unwrap();
        let clear = String::from_utf8(clear).unwrap();
        assert!(!clear.contains(summary));
        assert!(clear.contains(&sha256_bytes(summary.as_bytes())));
        let saved = service
            .call(
                "save_memory",
                "memory-save-read-only-plan",
                &owner,
                json!({
                    "context_id": context["context_id"],
                    "payload": summary,
                    "receipt_id": "",
                    "taint_lineage": "untainted",
                }),
            )
            .unwrap();
        assert_eq!(saved["provenance_kind"], "planning_result");
        assert_eq!(saved["task_id"], task_id);
        assert_eq!(saved["plan_id"], plan_id);
        assert_eq!(saved["receipt_id"], "");
    }

    #[test]
    fn caller_supplied_context_payload_is_always_rejected() {
        let (_root, service) = service();
        let owner = subject();
        for payload in [
            json!({
                "source_kind": "file",
                "source_id": "saf:caller-controlled",
                "content": "raw caller text",
            }),
            json!({
                "source_kind": "notifications",
                "source_id": "notifications:counts",
                "content": "mail=2",
                "privacy_class": "local_private",
                "freshness_ttl_ms": 60_000,
            }),
            json!({
                "capture_id": format!("capture-{}", "a".repeat(64)),
                "capture_receipt": {},
                "content": "smuggled raw text",
            }),
        ] {
            let error = service
                .call("get_context", "raw-context-denied", &owner, payload)
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("caller_supplied_context_capture_denied")
            );
        }
    }

    #[test]
    fn signed_receipt_preflight_failure_leaves_no_tombstone_and_valid_retry_replays() {
        let (_root, service) = service();
        let owner = subject();
        let live_context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "memory_import",
                    "source_id": "import:signed-preflight-replay",
                    "content": "signed preflight live context",
                }),
            )
            .unwrap();
        for method in ["get_context", "plan", "approve"] {
            let request_id = format!("signed-retry-{method}");
            let invalid_payload = json!({ "receipt": "invalid" });
            let valid_payload = json!({ "receipt": "hardware-signed-valid" });
            let invalid = service.run_ui_request_with_preflight(
                method,
                &request_id,
                &owner,
                &invalid_payload,
                || -> anyhow::Result<()> { anyhow::bail!("invalid_receipt_signature") },
                |()| panic!("invalid receipt must never reach resource consumption"),
            );
            assert!(
                invalid
                    .unwrap_err()
                    .to_string()
                    .contains("invalid_receipt_signature")
            );
            let request_hash = sha256_bytes(request_id.as_bytes());
            assert!(
                !service
                    .ui_replay_root
                    .join(format!("{request_hash}.json"))
                    .exists(),
                "{method} invalid preflight must not leave a replay record",
            );

            let executions = AtomicUsize::new(0);
            let first = service
                .run_ui_request_with_preflight(
                    method,
                    &request_id,
                    &owner,
                    &valid_payload,
                    || Ok("validated-binding"),
                    |binding| {
                        assert_eq!(binding, "validated-binding");
                        executions.fetch_add(1, Ordering::SeqCst);
                        Ok(if method == "get_context" {
                            live_context.clone()
                        } else {
                            json!({
                                "receipt_id": format!("receipt-{method}"),
                                "summary": "sensitive plan summary",
                            })
                        })
                    },
                )
                .unwrap();
            if method == "get_context" {
                assert_eq!(first["context_id"], live_context["context_id"]);
            } else {
                assert_eq!(first["receipt_id"], format!("receipt-{method}"));
            }
            let replay = service
                .run_ui_request_with_preflight(
                    method,
                    &request_id,
                    &owner,
                    &valid_payload,
                    || -> anyhow::Result<()> {
                        panic!("completed replay must precede single-use receipt preflight")
                    },
                    |()| panic!("completed replay must not reexecute"),
                )
                .unwrap();
            if method == "get_context" {
                assert_eq!(replay["context_id"], live_context["context_id"]);
            } else {
                assert_eq!(replay["receipt_id"], format!("receipt-{method}"));
            }
            assert_eq!(executions.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn memory_key_bootstrap_gateway_request_ids_are_kernel_randomized() {
        let first = super::unique_memory_key_bootstrap_request_id().unwrap();
        let second = super::unique_memory_key_bootstrap_request_id().unwrap();
        assert!(first.starts_with("memory-key-bootstrap-"));
        assert!(second.starts_with("memory-key-bootstrap-"));
        assert_ne!(first, second);
    }

    #[test]
    fn invalid_and_valid_receipt_race_executes_valid_operation_at_most_once() {
        let root = tempfile::tempdir().unwrap();
        let service = Arc::new(
            ContextMemoryService::open(root.path().join("state")).expect("context memory service"),
        );
        let owner = subject();
        let barrier = Arc::new(Barrier::new(2));
        let executions = Arc::new(AtomicUsize::new(0));
        let request_id = "signed-receipt-race";

        let invalid_service = Arc::clone(&service);
        let invalid_owner = owner.clone();
        let invalid_barrier = Arc::clone(&barrier);
        let invalid = std::thread::spawn(move || {
            invalid_service.run_ui_request_with_preflight(
                "approve",
                request_id,
                &invalid_owner,
                &json!({ "receipt": "invalid" }),
                || -> anyhow::Result<()> {
                    invalid_barrier.wait();
                    anyhow::bail!("invalid_receipt_signature")
                },
                |()| panic!("invalid receipt must not execute"),
            )
        });

        let valid_service = Arc::clone(&service);
        let valid_owner = owner.clone();
        let valid_barrier = Arc::clone(&barrier);
        let valid_executions = Arc::clone(&executions);
        let valid = std::thread::spawn(move || {
            valid_service.run_ui_request_with_preflight(
                "approve",
                request_id,
                &valid_owner,
                &json!({ "receipt": "hardware-signed-valid" }),
                || {
                    valid_barrier.wait();
                    Ok(())
                },
                |()| {
                    valid_executions.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({ "receipt_id": "receipt-race-success" }))
                },
            )
        });

        assert!(invalid.join().unwrap().is_err());
        assert_eq!(
            valid.join().unwrap().unwrap()["receipt_id"],
            "receipt-race-success"
        );
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        let replay = service
            .run_ui_request_with_preflight(
                "approve",
                request_id,
                &owner,
                &json!({ "receipt": "hardware-signed-valid" }),
                || -> anyhow::Result<()> { panic!("success replay must skip preflight") },
                |()| panic!("success replay must not execute twice"),
            )
            .unwrap();
        assert_eq!(replay["receipt_id"], "receipt-race-success");
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn two_valid_receipt_race_executes_once_then_replays_success() {
        let root = tempfile::tempdir().unwrap();
        let service = Arc::new(
            ContextMemoryService::open(root.path().join("state")).expect("context memory service"),
        );
        let owner = subject();
        let barrier = Arc::new(Barrier::new(2));
        let executions = Arc::new(AtomicUsize::new(0));
        let payload = json!({ "receipt": "same-hardware-signed-valid" });
        let mut threads = Vec::new();
        for _ in 0..2 {
            let service = Arc::clone(&service);
            let owner = owner.clone();
            let barrier = Arc::clone(&barrier);
            let executions = Arc::clone(&executions);
            let payload = payload.clone();
            threads.push(std::thread::spawn(move || {
                service.run_ui_request_with_preflight(
                    "approve",
                    "two-valid-receipt-race",
                    &owner,
                    &payload,
                    || {
                        barrier.wait();
                        Ok(())
                    },
                    |()| {
                        executions.fetch_add(1, Ordering::SeqCst);
                        Ok(json!({ "receipt_id": "receipt-two-valid-success" }))
                    },
                )
            }));
        }
        let outcomes = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        assert!(outcomes.iter().any(|outcome| outcome.is_ok()));
        assert!(outcomes.iter().all(|outcome| {
            match outcome {
                Ok(value) => value["receipt_id"] == "receipt-two-valid-success",
                Err(error) => error
                    .to_string()
                    .contains("ui_request_outcome_indeterminate_no_reexecution"),
            }
        }));

        let replay = service
            .run_ui_request_with_preflight(
                "approve",
                "two-valid-receipt-race",
                &owner,
                &payload,
                || -> anyhow::Result<()> { panic!("replay must skip preflight") },
                |()| panic!("replay must not execute twice"),
            )
            .unwrap();
        assert_eq!(replay["receipt_id"], "receipt-two-valid-success");
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ui_request_replay_is_durable_exactly_once_and_encrypted() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let owner = subject();
        let executions = AtomicUsize::new(0);
        let payload = json!({
            "workflow_id": "workflow-private-1",
            "summary": "private replay payload",
        });
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        let first = service
            .run_ui_request("plan", "ui-request-1", &owner, &payload, || {
                executions.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "summary": "private replay result" }))
            })
            .unwrap();
        let replay = service
            .run_ui_request("plan", "ui-request-1", &owner, &payload, || {
                executions.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "summary": "must not execute" }))
            })
            .unwrap();
        assert_eq!(first["summary"], "private replay result");
        assert_eq!(
            replay["summary"],
            "Plan completed; sensitive provider text is not retained for replay."
        );
        assert_eq!(executions.load(Ordering::SeqCst), 1);

        let outcome_path = std::fs::read_dir(state_root.join("ui-replay-outcomes"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let encrypted = std::fs::read(outcome_path).unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains("private replay result"));
        let payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload).unwrap());
        let aad = super::ui_replay_associated_data(&owner, "plan", "ui-request-1", &payload_sha256);
        let clear = decrypt_payload(
            &service.key,
            &aad,
            &encrypted,
            super::MAX_UI_REPLAY_OUTCOME_BYTES,
        )
        .unwrap();
        assert!(!String::from_utf8_lossy(&clear).contains("private replay result"));
        assert!(String::from_utf8_lossy(&clear).contains("sensitive provider text"));
        drop(service);

        let reopened = ContextMemoryService::open(state_root).unwrap();
        let durable = reopened
            .run_ui_request("plan", "ui-request-1", &owner, &payload, || {
                executions.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "summary": "must not execute after restart" }))
            })
            .unwrap();
        assert_eq!(durable, replay);
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ui_request_id_rejects_changed_payload_method_or_peer() {
        let (_root, service) = service();
        let owner = subject();
        let payload = json!({ "workflow_id": "workflow-1" });
        service
            .run_ui_request("plan", "ui-request-binding", &owner, &payload, || {
                Ok(json!({ "ok": true }))
            })
            .unwrap();

        for error in [
            service
                .run_ui_request(
                    "plan",
                    "ui-request-binding",
                    &owner,
                    &json!({ "workflow_id": "substituted" }),
                    || Ok(json!({})),
                )
                .unwrap_err(),
            service
                .run_ui_request("approve", "ui-request-binding", &owner, &payload, || {
                    Ok(json!({}))
                })
                .unwrap_err(),
            service
                .run_ui_request(
                    "plan",
                    "ui-request-binding",
                    &Subject::new(10_124, "u:r:trillionnium_aishell:s0:c1").unwrap(),
                    &payload,
                    || Ok(json!({})),
                )
                .unwrap_err(),
        ] {
            assert!(
                error
                    .to_string()
                    .contains("ui_request_id_replay_identity_or_payload_mismatch")
            );
        }
    }

    #[test]
    fn interrupted_ui_request_is_never_reexecuted_after_restart() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let owner = subject();
        let payload = json!({ "workflow_id": "workflow-crash" });
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = service.run_ui_request(
                "approve",
                "ui-request-crash",
                &owner,
                &payload,
                || -> anyhow::Result<Value> { panic!("simulated process interruption") },
            );
        }));
        assert!(panic.is_err());
        let record_path = service
            .ui_replay_root
            .join(format!("{}.json", sha256_bytes(b"ui-request-crash")));
        let mut aged = load_ui_replay_record(&record_path).unwrap();
        assert_eq!(aged.state, "in_progress");
        aged.recorded_at_ms = 1;
        atomic_write_private(&record_path, &serde_json::to_vec_pretty(&aged).unwrap()).unwrap();
        drop(service);

        let reopened = ContextMemoryService::open(state_root.clone()).unwrap();
        let executions = AtomicUsize::new(0);
        let error = reopened
            .run_ui_request("approve", "ui-request-crash", &owner, &payload, || {
                executions.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "must_not": "run" }))
            })
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ui_request_id_archived_no_reexecution")
        );
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        assert!(!record_path.exists());
        assert!(
            reopened
                .ui_replay_archive
                .lock()
                .unwrap()
                .contains_request_id("ui-request-crash")
        );
        drop(reopened);

        let reopened_again = ContextMemoryService::open(state_root).unwrap();
        let error = reopened_again
            .run_ui_request("approve", "ui-request-crash", &owner, &payload, || {
                executions.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "must_not": "run_after_second_restart" }))
            })
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ui_request_id_archived_no_reexecution")
        );
        assert_eq!(executions.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn interrupted_ui_request_recovers_only_a_query_owned_durable_outcome() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let owner = subject();
        let payload = json!({ "workflow_id": "workflow-recover" });
        let operation_attempts = AtomicUsize::new(0);
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = service.run_ui_request(
                "approve",
                "ui-request-recover",
                &owner,
                &payload,
                || -> anyhow::Result<Value> {
                    operation_attempts.fetch_add(1, Ordering::SeqCst);
                    panic!("simulated crash after downstream commit")
                },
            );
        }));
        assert!(panic.is_err());
        assert_eq!(operation_attempts.load(Ordering::SeqCst), 1);
        drop(service);

        let reopened = ContextMemoryService::open(state_root).unwrap();
        let recovery_queries = AtomicUsize::new(0);
        let mismatch = reopened
            .run_ui_request_with_preflight_and_recovery(
                UiRequestBinding {
                    method: "approve",
                    request_id: "ui-request-recover",
                    subject: &owner,
                    payload: &json!({ "workflow_id": "substituted" }),
                },
                || {
                    recovery_queries.fetch_add(1, Ordering::SeqCst);
                    Ok(super::UiRequestRecovery::Outcome(Ok(
                        json!({ "must_not": "recover" }),
                    )))
                },
                || Ok(()),
                |()| Ok(json!({ "must_not": "execute" })),
            )
            .unwrap_err();
        assert!(
            mismatch
                .to_string()
                .contains("ui_request_id_replay_identity_or_payload_mismatch")
        );
        assert_eq!(recovery_queries.load(Ordering::SeqCst), 0);

        let expected = json!({
            "receipt_id": "a".repeat(64),
            "receipt_json": "query-owned durable receipt",
        });
        let recovered = reopened
            .run_ui_request_with_preflight_and_recovery(
                UiRequestBinding {
                    method: "approve",
                    request_id: "ui-request-recover",
                    subject: &owner,
                    payload: &payload,
                },
                || {
                    recovery_queries.fetch_add(1, Ordering::SeqCst);
                    Ok(super::UiRequestRecovery::Outcome(Ok(expected.clone())))
                },
                || -> anyhow::Result<()> { panic!("recovery must skip consumed preflight") },
                |()| panic!("recovery must never dispatch the operation"),
            )
            .unwrap();
        assert_eq!(recovered, expected);
        assert_eq!(recovery_queries.load(Ordering::SeqCst), 1);
        assert_eq!(operation_attempts.load(Ordering::SeqCst), 1);

        let replay = reopened
            .run_ui_request("approve", "ui-request-recover", &owner, &payload, || {
                panic!("completed recovered outcome must replay")
            })
            .unwrap();
        assert_eq!(replay, expected);
        assert_eq!(recovery_queries.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expired_completed_ui_request_is_archived_before_body_deletion_and_restart() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let owner = subject();
        let payload = json!({});
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        service
            .run_ui_request("health", "ui-request-expired", &owner, &payload, || {
                Ok(json!({ "receipt_id": "receipt-expired" }))
            })
            .unwrap();
        let request_hash = sha256_bytes(b"ui-request-expired");
        let record_path = service.ui_replay_root.join(format!("{request_hash}.json"));
        let mut aged = load_ui_replay_record(&record_path).unwrap();
        assert_eq!(aged.state, "completed");
        let outcome_path = service.ui_replay_outcome_root.join(&aged.outcome_file);
        assert!(outcome_path.is_file());
        aged.recorded_at_ms = 1;
        atomic_write_private(&record_path, &serde_json::to_vec_pretty(&aged).unwrap()).unwrap();

        let preflights = AtomicUsize::new(0);
        let executions = AtomicUsize::new(0);
        let error = service
            .run_ui_request_with_preflight(
                "health",
                "ui-request-expired",
                &owner,
                &payload,
                || {
                    preflights.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                |()| {
                    executions.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({ "must_not": "reexecute" }))
                },
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ui_request_id_archived_no_reexecution")
        );
        assert_eq!(preflights.load(Ordering::SeqCst), 0);
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        assert!(!record_path.exists());
        assert!(!outcome_path.exists());
        assert!(
            service
                .ui_replay_archive
                .lock()
                .unwrap()
                .contains_request_id("ui-request-expired")
        );
        drop(service);

        let reopened = ContextMemoryService::open(state_root).unwrap();
        let error = reopened
            .run_ui_request("health", "ui-request-expired", &owner, &payload, || {
                executions.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "must_not": "reexecute_after_restart" }))
            })
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ui_request_id_archived_no_reexecution")
        );
        assert_eq!(executions.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ui_replay_parent_fsync_drop_reopens_the_same_authoritative_pair() {
        for failure_point in ["outcome", "record"] {
            let root = tempfile::tempdir().unwrap();
            let state_root = root.path().join("state");
            let owner = subject();
            let request_id = format!("ui-parent-fsync-{failure_point}");
            let request_hash = sha256_bytes(request_id.as_bytes());
            let record_name = format!("{request_hash}.json");
            let outcome_name = format!("{request_hash}.enc");
            let payload = json!({ "workflow_id": format!("workflow-{failure_point}") });
            let expected = json!({
                "receipt_id": "a".repeat(64),
                "receipt_json": format!("durable-{failure_point}"),
            });
            let service = ContextMemoryService::open(state_root.clone()).unwrap();
            if failure_point == "outcome" {
                fail_next_private_parent_fsync_for_test(&outcome_name);
            }
            let error = service
                .run_ui_request_with_preflight_and_recovery(
                    UiRequestBinding {
                        method: "approve",
                        request_id: &request_id,
                        subject: &owner,
                        payload: &payload,
                    },
                    || Ok(super::UiRequestRecovery::Unresolved),
                    || Ok(()),
                    |()| {
                        if failure_point == "record" {
                            fail_next_private_parent_fsync_for_test(&record_name);
                        }
                        Ok(expected.clone())
                    },
                )
                .unwrap_err();
            assert!(error.to_string().contains("parent_fsync_uncertain"));
            let outcome_path = service.ui_replay_outcome_root.join(&outcome_name);
            let original_ciphertext = std::fs::read(&outcome_path).unwrap();
            let original_ciphertext_sha256 = sha256_bytes(&original_ciphertext);
            drop(service);

            let reopened = ContextMemoryService::open(state_root).unwrap();
            let record =
                load_ui_replay_record(&reopened.ui_replay_root.join(&record_name)).unwrap();
            assert_eq!(record.state, "completed");
            assert_eq!(record.outcome_ciphertext_sha256, original_ciphertext_sha256);
            assert_eq!(std::fs::read(&outcome_path).unwrap(), original_ciphertext);
            let recovery_queries = AtomicUsize::new(0);
            let replayed = reopened
                .run_ui_request_with_preflight_and_recovery(
                    UiRequestBinding {
                        method: "approve",
                        request_id: &request_id,
                        subject: &owner,
                        payload: &payload,
                    },
                    || {
                        recovery_queries.fetch_add(1, Ordering::SeqCst);
                        Ok(super::UiRequestRecovery::Outcome(Ok(json!({
                            "must_not": "replace_authoritative_outcome"
                        }))))
                    },
                    || -> anyhow::Result<()> { panic!("completed pair must skip preflight") },
                    |()| panic!("completed pair must not reexecute"),
                )
                .unwrap();
            assert_eq!(replayed, expected);
            assert_eq!(recovery_queries.load(Ordering::SeqCst), 0);
            assert_eq!(std::fs::read(outcome_path).unwrap(), original_ciphertext);
        }
    }

    #[test]
    fn typed_ui_completion_pair_rejects_missing_truncated_swapped_and_cross_method_bytes() {
        for corruption in ["missing", "truncated", "cross_method"] {
            let root = tempfile::tempdir().unwrap();
            let state_root = root.path().join("state");
            let owner = subject();
            let request_id = format!("ui-pair-{corruption}");
            let payload = json!({ "case": corruption });
            let service = ContextMemoryService::open(state_root.clone()).unwrap();
            service
                .run_ui_request("approve", &request_id, &owner, &payload, || {
                    Ok(json!({ "receipt_id": "b".repeat(64) }))
                })
                .unwrap();
            let request_hash = sha256_bytes(request_id.as_bytes());
            let record_path = service.ui_replay_root.join(format!("{request_hash}.json"));
            let record = load_ui_replay_record(&record_path).unwrap();
            let outcome_path = service.ui_replay_outcome_root.join(&record.outcome_file);
            match corruption {
                "missing" => std::fs::remove_file(&outcome_path).unwrap(),
                "truncated" => {
                    let mut bytes = std::fs::read(&outcome_path).unwrap();
                    bytes.truncate(16);
                    std::fs::write(&outcome_path, bytes).unwrap();
                }
                "cross_method" => {
                    let mut changed = record;
                    changed.method = "plan".to_string();
                    atomic_write_private(
                        &record_path,
                        &serde_json::to_vec_pretty(&changed).unwrap(),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            drop(service);
            assert!(
                ContextMemoryService::open(state_root).is_err(),
                "{corruption}"
            );
        }

        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let owner = subject();
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        let mut outcome_paths = Vec::new();
        for request_id in ["ui-pair-swap-a", "ui-pair-swap-b"] {
            service
                .run_ui_request(
                    "approve",
                    request_id,
                    &owner,
                    &json!({ "request": request_id }),
                    || Ok(json!({ "receipt_id": sha256_bytes(request_id.as_bytes()) })),
                )
                .unwrap();
            let record = load_ui_replay_record(
                &service
                    .ui_replay_root
                    .join(format!("{}.json", sha256_bytes(request_id.as_bytes()))),
            )
            .unwrap();
            outcome_paths.push(service.ui_replay_outcome_root.join(record.outcome_file));
        }
        let first = std::fs::read(&outcome_paths[0]).unwrap();
        let second = std::fs::read(&outcome_paths[1]).unwrap();
        std::fs::write(&outcome_paths[0], &second).unwrap();
        std::fs::write(&outcome_paths[1], &first).unwrap();
        drop(service);
        assert!(ContextMemoryService::open(state_root).is_err());
    }

    #[test]
    fn ui_replay_record_is_closed_world_and_rejects_unknown_or_duplicate_fields() {
        for mutation in ["unknown", "duplicate"] {
            let root = tempfile::tempdir().unwrap();
            let state_root = root.path().join("state");
            let owner = subject();
            let request_id = format!("ui-record-{mutation}");
            let service = ContextMemoryService::open(state_root.clone()).unwrap();
            service
                .run_ui_request("health", &request_id, &owner, &json!({}), || {
                    Ok(json!({ "healthy": true }))
                })
                .unwrap();
            let record_path = service
                .ui_replay_root
                .join(format!("{}.json", sha256_bytes(request_id.as_bytes())));
            let bytes = std::fs::read(&record_path).unwrap();
            if mutation == "unknown" {
                let mut value: Value = serde_json::from_slice(&bytes).unwrap();
                value
                    .as_object_mut()
                    .unwrap()
                    .insert("unknown_field".to_string(), json!(true));
                std::fs::write(&record_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
            } else {
                let encoded = String::from_utf8(bytes).unwrap();
                let needle = format!("  \"schema\": \"{}\",", super::UI_REPLAY_SCHEMA);
                let duplicate = format!("{needle}\n{needle}");
                assert!(encoded.contains(&needle));
                std::fs::write(&record_path, encoded.replacen(&needle, &duplicate, 1)).unwrap();
            }
            drop(service);
            assert!(
                ContextMemoryService::open(state_root).is_err(),
                "{mutation}"
            );
        }
    }

    #[test]
    fn direct_ui_snapshot_is_sealed_exact_and_read_only_across_reopen() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let owner = subject();
        let request_id = "direct-ui-snapshot-exact";
        let payload = json!({
            "provider": "openai-codex",
            "workflow_id": "workflow-direct-ui-snapshot",
            "egress_grant_id": format!("egress-{}", "a".repeat(64)),
        });
        let receipt_sha256 = sha256_bytes(b"direct-ui-exact-receipt");
        let response = json!({
            "execution_mode": "agent_direct",
            "action": "agent_direct_result",
            "summary": "provider text that must not survive UI replay",
            "direct_execution_receipt_sha256": receipt_sha256,
        });
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        service
            .run_ui_request(
                "plan",
                request_id,
                &owner,
                &payload,
                || Ok(response.clone()),
            )
            .unwrap();
        let payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload).unwrap());
        let completion = service
            .ui_request_completion_proof_exact(
                "plan",
                request_id,
                owner.uid,
                &owner.selinux_domain,
                &payload_sha256,
            )
            .unwrap()
            .unwrap();
        let completion_sha256 = completion.digest_sha256().unwrap();
        let candidate = direct_ui_candidate_for_test(
            &owner,
            request_id,
            &payload,
            response.clone(),
            Some(completion_sha256.clone()),
        );
        let snapshot = service
            .verified_direct_ui_replay_snapshot(&candidate)
            .unwrap();
        assert_eq!(
            snapshot.exact_plan_ready_semantic_sha256(),
            sha256_json(&response)
        );
        assert_eq!(snapshot.direct_execution_receipt_sha256(), receipt_sha256);
        assert_eq!(
            snapshot.ui_replay_completion_proof_sha256(),
            completion_sha256
        );
        let first = snapshot.clone();
        assert_eq!(
            service
                .verified_direct_ui_replay_snapshot(&candidate)
                .unwrap(),
            first
        );

        drop(service);
        let reopened = ContextMemoryService::open(state_root).unwrap();
        assert_eq!(
            reopened
                .verified_direct_ui_replay_snapshot(&candidate)
                .unwrap(),
            first
        );
    }

    #[test]
    fn direct_ui_snapshot_rejects_missing_partial_drift_and_uncertain_custody() {
        for mutation in [
            "missing_action_proof",
            "proof_drift",
            "ui_identity_drift",
            "in_progress",
            "outcome_only",
            "record_only",
            "sanitized_summary_drift",
            "semantic_drift",
            "parent_fsync_uncertain",
        ] {
            let root = tempfile::tempdir().unwrap();
            let owner = subject();
            let request_id = format!("direct-ui-negative-{mutation}");
            let payload = json!({
                "provider": "openai-codex",
                "workflow_id": format!("workflow-{mutation}"),
                "egress_grant_id": format!("egress-{}", "b".repeat(64)),
            });
            let receipt_sha256 = sha256_bytes(format!("receipt-{mutation}").as_bytes());
            let mut actual_response = json!({
                "execution_mode": "agent_direct",
                "action": "agent_direct_result",
                "summary": "provider text",
                "direct_execution_receipt_sha256": receipt_sha256,
            });
            if mutation == "sanitized_summary_drift" {
                actual_response.as_object_mut().unwrap().remove("summary");
            }
            let service = ContextMemoryService::open(root.path().join("state")).unwrap();
            service
                .run_ui_request("plan", &request_id, &owner, &payload, || {
                    Ok(actual_response.clone())
                })
                .unwrap();
            let payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload).unwrap());
            let completion = service
                .ui_request_completion_proof_exact(
                    "plan",
                    &request_id,
                    owner.uid,
                    &owner.selinux_domain,
                    &payload_sha256,
                )
                .unwrap()
                .unwrap();
            let mut candidate_response = actual_response.clone();
            if mutation == "sanitized_summary_drift" {
                candidate_response["summary"] = json!("exact PlanReady provider text");
            } else if mutation == "semantic_drift" {
                candidate_response["unexpected_semantic_drift"] = json!(true);
            }
            let candidate_request_id = if mutation == "ui_identity_drift" {
                format!("{request_id}-other")
            } else {
                request_id.clone()
            };
            let candidate_proof = match mutation {
                "missing_action_proof" => None,
                "proof_drift" => Some(sha256_bytes(b"different-completion-proof")),
                _ => Some(completion.digest_sha256().unwrap()),
            };
            let candidate = direct_ui_candidate_for_test(
                &owner,
                &candidate_request_id,
                &payload,
                candidate_response,
                candidate_proof,
            );

            let record_path = service
                .ui_replay_root
                .join(format!("{}.json", sha256_bytes(request_id.as_bytes())));
            let mut record = load_ui_replay_record(&record_path).unwrap();
            let outcome_path = service
                .ui_replay_outcome_root
                .join(record.outcome_file.clone());
            match mutation {
                "in_progress" => {
                    record.state = "in_progress".to_string();
                    record.outcome_file.clear();
                    record.outcome_ciphertext_sha256.clear();
                    record.outcome_semantic_sha256.clear();
                    record.custody_handoff_ack = None;
                    atomic_write_private(
                        &record_path,
                        &serde_json::to_vec_pretty(&record).unwrap(),
                    )
                    .unwrap();
                }
                "outcome_only" => std::fs::remove_file(&record_path).unwrap(),
                "record_only" => std::fs::remove_file(&outcome_path).unwrap(),
                "parent_fsync_uncertain" => service
                    .ui_replay_publication_durability_uncertain
                    .store(true, std::sync::atomic::Ordering::Release),
                _ => {}
            }
            assert!(
                service
                    .verified_direct_ui_replay_snapshot(&candidate)
                    .is_err(),
                "{mutation}"
            );
        }
    }

    #[test]
    fn lifecycle_ui_outcomes_require_exact_handoff_before_prune() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let owner = subject();
        let request_id = "ui-handoff-success";
        let payload = json!({ "workflow_id": "workflow-handoff" });
        let grant_id = format!("egress-{}", "c".repeat(64));
        let wrong_grant_id = format!("egress-{}", "d".repeat(64));
        let service = ContextMemoryService::open(state_root).unwrap();
        service
            .run_ui_request("prepare_egress", request_id, &owner, &payload, || {
                Ok(json!({ "egress_grant_id": grant_id }))
            })
            .unwrap();
        let payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload).unwrap());
        let proof = service
            .ui_request_completion_proof_exact(
                "prepare_egress",
                request_id,
                owner.uid,
                &owner.selinux_domain,
                &payload_sha256,
            )
            .unwrap()
            .unwrap();
        assert!(
            service
                .acknowledge_ui_replay_custody_handoff(
                    &proof,
                    owner.uid,
                    &owner.selinux_domain,
                    "egress_lifecycle_journal",
                    &wrong_grant_id,
                )
                .is_err()
        );
        let record_path = service
            .ui_replay_root
            .join(format!("{}.json", sha256_bytes(request_id.as_bytes())));
        let mut aged = load_ui_replay_record(&record_path).unwrap();
        aged.recorded_at_ms = 1;
        atomic_write_private(&record_path, &serde_json::to_vec_pretty(&aged).unwrap()).unwrap();
        service.prune_ui_replays_locked().unwrap();
        assert!(
            record_path.exists(),
            "missing handoff must retain lifecycle outcome"
        );
        service
            .acknowledge_ui_replay_custody_handoff(
                &proof,
                owner.uid,
                &owner.selinux_domain,
                "egress_lifecycle_journal",
                &grant_id,
            )
            .unwrap();
        service.prune_ui_replays_locked().unwrap();
        assert!(!record_path.exists());
    }

    #[test]
    fn denied_egress_without_record_self_archives_but_error_with_record_handoffs() {
        for (suffix, owner_kind, owner_id) in [
            (
                "no-record",
                "ui_replay_self_terminal",
                "ui-egress-error-no-record".to_string(),
            ),
            (
                "with-record",
                "egress_lifecycle_journal",
                format!("egress-{}", "e".repeat(64)),
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let state_root = root.path().join("state");
            let owner = subject();
            let request_id = format!("ui-egress-error-{suffix}");
            let payload = json!({ "workflow_id": format!("workflow-{suffix}") });
            let service = ContextMemoryService::open(state_root).unwrap();
            assert!(
                service
                    .run_ui_request("prepare_egress", &request_id, &owner, &payload, || {
                        anyhow::bail!("egress_denied_or_commit_unknown")
                    })
                    .is_err()
            );
            let payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload).unwrap());
            let proof = service
                .ui_request_completion_proof_exact(
                    "prepare_egress",
                    &request_id,
                    owner.uid,
                    &owner.selinux_domain,
                    &payload_sha256,
                )
                .unwrap()
                .unwrap();
            let record_path = service
                .ui_replay_root
                .join(format!("{}.json", sha256_bytes(request_id.as_bytes())));
            let mut aged = load_ui_replay_record(&record_path).unwrap();
            aged.recorded_at_ms = 1;
            atomic_write_private(&record_path, &serde_json::to_vec_pretty(&aged).unwrap()).unwrap();
            service.prune_ui_replays_locked().unwrap();
            assert!(record_path.exists());
            service
                .acknowledge_ui_replay_custody_handoff(
                    &proof,
                    owner.uid,
                    &owner.selinux_domain,
                    owner_kind,
                    &owner_id,
                )
                .unwrap();
            service.prune_ui_replays_locked().unwrap();
            assert!(!record_path.exists());
        }
    }

    #[test]
    fn ui_replay_archive_accepts_unique_request_beyond_hot_record_lifetime_limit() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let owner = subject();
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        {
            let mut archive = service.ui_replay_archive.lock().unwrap();
            for index in 0..=MAX_REPLAY_RECORDS {
                archive
                    .insert_request_id(&format!("archived-lifecycle-{index}"))
                    .unwrap();
            }
            persist_ui_replay_archive(&service.ui_replay_archive_path, &archive).unwrap();
        }
        drop(service);

        let service = ContextMemoryService::open(state_root).unwrap();
        let archive = service.ui_replay_archive.lock().unwrap();
        assert!(archive.contains_request_id("archived-lifecycle-0"));
        assert!(archive.contains_request_id(&format!("archived-lifecycle-{MAX_REPLAY_RECORDS}")));
        drop(archive);

        let result = service
            .run_ui_request(
                "approve",
                "archived-lifecycle-after-hot-limit",
                &owner,
                &json!({ "workflow_id": "beyond-hot-limit" }),
                || Ok(json!({ "accepted_after_archival": true })),
            )
            .unwrap();
        assert_eq!(result["accepted_after_archival"], true);
    }

    #[test]
    fn ui_replay_archive_marker_migrates_once_then_missing_archive_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        drop(service);

        let metadata_path = state_root.join("metadata.json");
        let archive_path = state_root.join(UI_REPLAY_ARCHIVE_FILE);
        let mut legacy: Value =
            serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
        legacy["schema"] = json!(LEGACY_STORE_SCHEMA);
        legacy
            .as_object_mut()
            .unwrap()
            .remove("ui_replay_archive_initialized");
        atomic_write_private(&metadata_path, &serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
        std::fs::remove_file(&archive_path).unwrap();

        let migrated = ContextMemoryService::open(state_root.clone()).unwrap();
        drop(migrated);
        let metadata: Value =
            serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
        assert_eq!(metadata["schema"], STORE_SCHEMA);
        assert_eq!(metadata["ui_replay_archive_initialized"], true);
        assert!(archive_path.is_file());

        std::fs::remove_file(&archive_path).unwrap();
        let error = ContextMemoryService::open(state_root)
            .err()
            .expect("initialized metadata must never recreate a missing archive");
        assert!(
            error
                .to_string()
                .contains("ui_replay_archive_missing_after_initialization_fail_closed")
        );
    }

    #[test]
    fn delegated_context_is_task_bound_single_use_and_ledger_is_encrypted() {
        let (root, service) = service();
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "file",
                    "source_id": "saf:delegation-private",
                    "content": "delegated private context",
                }),
            )
            .unwrap();
        let context_id = context["context_id"].as_str().unwrap();
        let grant = service
            .issue_context_grant(
                &owner,
                grant_target(),
                context_id,
                true,
                "none",
                "none",
                60_000,
            )
            .unwrap();
        let grant_id = grant["grant_id"].as_str().unwrap();
        let listed = service.list_agent_data_grants(&grant_consumer()).unwrap();
        assert_eq!(listed["count"], 1);
        assert_eq!(listed["items"][0]["agent_peer_uid"], 62_010);
        assert_eq!(listed["items"][0]["agent_peer_gid"], 62_011);
        assert!(listed["items"][0].get("content").is_none());
        let raw = service
            .read_agent_data_grant(&grant_consumer(), grant_id, "context")
            .unwrap();
        assert_eq!(raw["content"], "delegated private context");
        assert_eq!(raw["single_use_consumed"], true);
        assert!(
            service
                .read_agent_data_grant(&grant_consumer(), grant_id, "context")
                .unwrap_err()
                .to_string()
                .contains("not_active")
        );
        let encrypted = std::fs::read(root.path().join("state/agent-data-grants.enc")).unwrap();
        let encoded = String::from_utf8_lossy(&encrypted);
        assert!(!encoded.contains("delegated private context"));
        assert!(!encoded.contains("task-delegation-test"));
        assert!(!encoded.contains("saf:delegation-private"));
    }

    #[test]
    fn legacy_gid_unbound_data_grants_migrate_to_permanent_invalidation() {
        let (root, service) = service();
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "file",
                    "source_id": "saf:legacy-gid-migration",
                    "content": "must never cross a gid migration",
                }),
            )
            .unwrap();
        service
            .issue_context_grant(
                &owner,
                grant_target(),
                context["context_id"].as_str().unwrap(),
                true,
                "none",
                "none",
                60_000,
            )
            .unwrap();
        let ledger_path = root.path().join("state/agent-data-grants.enc");
        let encrypted = std::fs::read(&ledger_path).unwrap();
        let clear = decrypt_payload(
            &service.key,
            super::DATA_GRANT_STORE_AAD,
            &encrypted,
            super::MAX_DATA_GRANT_STORE_BYTES,
        )
        .unwrap();
        let mut legacy: Value = serde_json::from_slice(&clear).unwrap();
        legacy["schema"] = json!(super::LEGACY_DATA_GRANT_STORE_SCHEMA);
        legacy["grants"][0]["schema"] = json!(super::LEGACY_DATA_GRANT_SCHEMA);
        legacy["grants"][0]
            .as_object_mut()
            .unwrap()
            .remove("agent_peer_gid");
        let migrated_input = encrypt_payload(
            &service.key,
            super::DATA_GRANT_STORE_AAD,
            &serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        drop(service);
        atomic_write_private(&ledger_path, &migrated_input).unwrap();

        let reopened = ContextMemoryService::open(root.path().join("state")).unwrap();
        assert_eq!(
            reopened.list_agent_data_grants(&grant_consumer()).unwrap()["count"],
            0
        );
        let persisted = std::fs::read(&ledger_path).unwrap();
        let clear = decrypt_payload(
            &reopened.key,
            super::DATA_GRANT_STORE_AAD,
            &persisted,
            super::MAX_DATA_GRANT_STORE_BYTES,
        )
        .unwrap();
        let migrated: Value = serde_json::from_slice(&clear).unwrap();
        assert_eq!(migrated["schema"], super::DATA_GRANT_STORE_SCHEMA);
        assert_eq!(migrated["grants"][0]["schema"], super::DATA_GRANT_SCHEMA);
        assert_eq!(migrated["grants"][0]["agent_peer_gid"], 0);
        assert_eq!(migrated["grants"][0]["state"], "identity_invalidated");
        assert!(
            migrated["audit_events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["event_type"] == "identity_invalidate")
        );
    }

    #[test]
    fn grant_issue_and_consume_are_never_visible_when_durable_publish_fails() {
        let (root, service) = service();
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "file",
                    "source_id": "saf:grant-transaction",
                    "content": "transaction protected context",
                }),
            )
            .unwrap();
        let context_id = context["context_id"].as_str().unwrap();
        let ledger_path = root.path().join("state/agent-data-grants.enc");
        let before_failed_issue = std::fs::read(&ledger_path).unwrap();

        service.fail_next_grant_persist_for_test();
        let issue_error = service
            .issue_context_grant(
                &owner,
                grant_target(),
                context_id,
                true,
                "none",
                "none",
                60_000,
            )
            .unwrap_err();
        assert!(
            issue_error
                .to_string()
                .contains("agent_data_grant_persistence_failed")
        );
        assert_eq!(
            service.list_agent_data_grants(&grant_consumer()).unwrap()["count"],
            0
        );
        assert_eq!(std::fs::read(&ledger_path).unwrap(), before_failed_issue);

        let grant = service
            .issue_context_grant(
                &owner,
                grant_target(),
                context_id,
                true,
                "none",
                "none",
                60_000,
            )
            .unwrap();
        let grant_id = grant["grant_id"].as_str().unwrap();
        let before_failed_consume = std::fs::read(&ledger_path).unwrap();
        service.fail_next_grant_persist_for_test();
        let consume_error = service
            .read_agent_data_grant(&grant_consumer(), grant_id, "context")
            .unwrap_err();
        assert!(
            consume_error
                .to_string()
                .contains("agent_data_grant_persistence_failed")
        );
        assert_eq!(std::fs::read(&ledger_path).unwrap(), before_failed_consume);
        assert_eq!(
            service
                .read_agent_data_grant(&grant_consumer(), grant_id, "context")
                .unwrap()["content"],
            "transaction protected context"
        );
        drop(service);

        let reopened = ContextMemoryService::open(root.path().join("state")).unwrap();
        assert_eq!(
            reopened.list_agent_data_grants(&grant_consumer()).unwrap()["count"],
            0
        );
    }

    #[test]
    fn delegated_data_denies_cross_agent_task_user_and_metadata_only_raw_read() {
        let (_root, service) = service();
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "memory_import",
                    "source_id": "import:delegation-negative",
                    "content": "memory remains metadata-only",
                }),
            )
            .unwrap();
        let context_id = context["context_id"].as_str().unwrap();
        let grant = service
            .issue_context_grant(
                &owner,
                grant_target(),
                context_id,
                true,
                "none",
                "none",
                60_000,
            )
            .unwrap();
        let grant_id = grant["grant_id"].as_str().unwrap();
        let mut wrong_agent = grant_consumer();
        wrong_agent.agent_id = "agent-attacker".to_string();
        let mut wrong_task = grant_consumer();
        wrong_task.task_id = "task-attacker".to_string();
        let mut wrong_gid = grant_consumer();
        wrong_gid.peer_gid = wrong_gid.peer_gid.saturating_add(1);
        let mut wrong_user = grant_consumer();
        wrong_user.subject_user_id = 10;
        for consumer in [wrong_agent, wrong_task, wrong_gid, wrong_user] {
            assert!(
                service
                    .read_agent_data_grant(&consumer, grant_id, "context")
                    .unwrap_err()
                    .to_string()
                    .contains("consumer_binding_mismatch")
            );
        }

        let saved = service
            .call(
                "save_memory",
                "delegation-negative-memory",
                &owner,
                json!({
                    "context_id": context_id,
                    "payload": "memory remains metadata-only",
                    "receipt_id": "",
                    "taint_lineage": "user_imported",
                }),
            )
            .unwrap();
        let memory_grant = service
            .issue_memory_grant(
                &owner,
                grant_target(),
                saved["memory_id"].as_str().unwrap(),
                false,
                "none",
                "none",
                60_000,
            )
            .unwrap();
        assert!(
            service
                .read_agent_data_grant(
                    &grant_consumer(),
                    memory_grant["grant_id"].as_str().unwrap(),
                    "memory",
                )
                .unwrap_err()
                .to_string()
                .contains("raw_read_denied")
        );
    }

    #[test]
    fn delegated_grant_revocation_and_expiry_fail_closed() {
        let (_root, service) = service();
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "browser_extract",
                    "source_id": "app:browser",
                    "content": "revocable",
                }),
            )
            .unwrap();
        let context_id = context["context_id"].as_str().unwrap();
        let revoked = service
            .issue_context_grant(
                &owner,
                grant_target(),
                context_id,
                true,
                "none",
                "none",
                60_000,
            )
            .unwrap();
        let revoked_id = revoked["grant_id"].as_str().unwrap();
        service.revoke_agent_data_grant(&owner, revoked_id).unwrap();
        assert!(
            service
                .read_agent_data_grant(&grant_consumer(), revoked_id, "context")
                .unwrap_err()
                .to_string()
                .contains("not_active")
        );

        let expiring = service
            .issue_context_grant(&owner, grant_target(), context_id, true, "none", "none", 1)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(
            service
                .read_agent_data_grant(
                    &grant_consumer(),
                    expiring["grant_id"].as_str().unwrap(),
                    "context",
                )
                .unwrap_err()
                .to_string()
                .contains("not_active")
        );
    }

    #[test]
    fn delegated_read_replay_covers_response_loss_and_crash_after_consume() {
        let (_root, service) = service();
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "file",
                    "source_id": "saf:replay",
                    "content": "single disclosure",
                }),
            )
            .unwrap();
        let context_id = context["context_id"].as_str().unwrap();
        let first_grant = service
            .issue_context_grant(
                &owner,
                grant_target(),
                context_id,
                true,
                "none",
                "none",
                60_000,
            )
            .unwrap();
        let first_id = first_grant["grant_id"].as_str().unwrap().to_string();
        let agent_subject =
            Subject::new(grant_consumer().peer_uid, &grant_consumer().selinux_domain).unwrap();
        let bound = json!({
            "agent_id": grant_consumer().agent_id,
            "peer_executable_sha256": grant_consumer().executable_sha256,
            "payload": {"task_id": grant_consumer().task_id, "grant_id": first_id},
        });
        let first = service
            .run_ui_request(
                "agent.read_context_grant",
                "agent-read-response-loss",
                &agent_subject,
                &bound,
                || service.read_agent_data_grant(&grant_consumer(), &first_id, "context"),
            )
            .unwrap();
        let replay = service
            .run_ui_request(
                "agent.read_context_grant",
                "agent-read-response-loss",
                &agent_subject,
                &bound,
                || panic!("completed delegated read must replay encrypted response"),
            )
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(replay["content"], "single disclosure");

        let crash_grant = service
            .issue_context_grant(
                &owner,
                grant_target(),
                context_id,
                true,
                "none",
                "none",
                60_000,
            )
            .unwrap();
        let crash_id = crash_grant["grant_id"].as_str().unwrap().to_string();
        let crash_bound = json!({
            "agent_id": grant_consumer().agent_id,
            "peer_executable_sha256": grant_consumer().executable_sha256,
            "payload": {"task_id": grant_consumer().task_id, "grant_id": crash_id},
        });
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = service.run_ui_request(
                "agent.read_context_grant",
                "agent-read-crash-after-consume",
                &agent_subject,
                &crash_bound,
                || -> anyhow::Result<Value> {
                    let _ =
                        service.read_agent_data_grant(&grant_consumer(), &crash_id, "context")?;
                    panic!("simulated crash after durable consume")
                },
            );
        }));
        assert!(interrupted.is_err());
        assert!(
            service
                .run_ui_request(
                    "agent.read_context_grant",
                    "agent-read-crash-after-consume",
                    &agent_subject,
                    &crash_bound,
                    || Ok(json!({"must_not": "execute"})),
                )
                .unwrap_err()
                .to_string()
                .contains("outcome_indeterminate_no_reexecution")
        );
        assert!(
            service
                .read_agent_data_grant(&grant_consumer(), &crash_id, "context")
                .unwrap_err()
                .to_string()
                .contains("not_active")
        );
    }

    #[test]
    fn memory_master_key_is_only_wrapped_on_disk_and_reopens() {
        use base64::Engine as _;

        let (root, custody, service) = service_with_custody();
        let state_root = root.path().join("state");
        let envelope_path = state_root.join(super::MEMORY_KEY_ENVELOPE_FILE);
        assert!(envelope_path.is_file());
        assert!(!state_root.join("memory.key").exists());
        let metadata = std::fs::symlink_metadata(&envelope_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        let encoded = std::fs::read(&envelope_path).unwrap();
        let encoded_text = String::from_utf8(encoded.clone()).unwrap();
        assert!(!encoded_text.contains(&super::BASE64_STANDARD.encode(service.key.as_slice())));
        let envelope: super::MemoryKeyEnvelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(envelope.schema, super::MEMORY_KEY_ENVELOPE_SCHEMA);
        assert_eq!(envelope.backend, "software_test_only");
        assert_eq!(envelope.subject_user_id, 0);
        assert_eq!(envelope.key_alias, super::MEMORY_KEY_ALIAS);
        assert_eq!(envelope.key_epoch, 1);
        assert_eq!(envelope.aad, super::MEMORY_KEY_AAD);
        let key_id = envelope.key_id.clone();
        drop(service);

        let reopened = ContextMemoryService::open_with_key_custody(
            state_root,
            custody as Arc<dyn super::MemoryKeyCustody>,
        )
        .unwrap();
        assert_eq!(super::sha256_bytes(reopened.key.as_slice()), key_id);
        assert!(!root.path().join("state/memory.key").exists());
    }

    #[test]
    fn production_memory_key_envelope_rejects_software_security_level() {
        use base64::Engine as _;

        let envelope = super::MemoryKeyEnvelope {
            schema: super::MEMORY_KEY_ENVELOPE_SCHEMA.to_string(),
            backend: super::MEMORY_KEY_ANDROID_BACKEND.to_string(),
            subject_user_id: super::MEMORY_KEY_SUBJECT_USER_ID,
            key_alias: super::MEMORY_KEY_ALIAS.to_string(),
            key_epoch: super::MEMORY_KEY_EPOCH,
            aad: super::MEMORY_KEY_AAD.to_string(),
            key_id: "a".repeat(64),
            nonce_b64: super::BASE64_STANDARD.encode([0u8; 12]),
            wrapped_key_b64: super::BASE64_STANDARD.encode([0u8; 48]),
            wrapping_algorithm: super::MEMORY_KEY_ANDROID_ALGORITHM.to_string(),
            security_level: "SOFTWARE".to_string(),
            hardware_backed: false,
            unlocked_device_required: true,
        };
        assert!(
            super::validate_memory_key_envelope(&envelope, super::MEMORY_KEY_ANDROID_BACKEND)
                .unwrap_err()
                .to_string()
                .contains("security_level_denied")
        );
    }

    #[test]
    fn memory_key_envelope_wrong_binding_corruption_symlink_and_permissions_fail_closed() {
        use base64::Engine as _;

        for mutation in ["user", "epoch", "aad", "ciphertext", "permissions"] {
            let (root, _custody, service) = service_with_custody();
            let state_root = root.path().join("state");
            let envelope_path = state_root.join(super::MEMORY_KEY_ENVELOPE_FILE);
            drop(service);
            if mutation == "permissions" {
                std::fs::set_permissions(&envelope_path, std::fs::Permissions::from_mode(0o644))
                    .unwrap();
            } else {
                let mut value: Value =
                    serde_json::from_slice(&std::fs::read(&envelope_path).unwrap()).unwrap();
                match mutation {
                    "user" => value["subject_user_id"] = json!(10),
                    "epoch" => value["key_epoch"] = json!(2),
                    "aad" => value["aad"] = json!("wrong-aad"),
                    "ciphertext" => {
                        let mut wrapped = super::BASE64_STANDARD
                            .decode(value["wrapped_key_b64"].as_str().unwrap())
                            .unwrap();
                        let last = wrapped.len() - 1;
                        wrapped[last] ^= 1;
                        value["wrapped_key_b64"] = json!(super::BASE64_STANDARD.encode(wrapped));
                    }
                    _ => unreachable!(),
                }
                std::fs::write(&envelope_path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
                std::fs::set_permissions(&envelope_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            let error = ContextMemoryService::open(state_root).err().unwrap();
            assert!(
                error.to_string().contains("memory_key")
                    || error
                        .to_string()
                        .contains("encrypted_memory_payload_authentication")
            );
        }

        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        std::fs::create_dir_all(&state_root).unwrap();
        std::fs::set_permissions(&state_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let outside = root.path().join("outside-envelope.json");
        std::fs::write(&outside, b"{}").unwrap();
        std::os::unix::fs::symlink(&outside, state_root.join(super::MEMORY_KEY_ENVELOPE_FILE))
            .unwrap();
        assert!(
            ContextMemoryService::open(state_root)
                .err()
                .unwrap()
                .to_string()
                .contains("memory_key")
        );
    }

    #[test]
    fn private_state_rejects_unsafe_directory_hardlink_symlink_owner_and_payload_mode() {
        let root = tempfile::tempdir().unwrap();
        let unsafe_root = root.path().join("unsafe-state");
        std::fs::create_dir(&unsafe_root).unwrap();
        std::fs::set_permissions(&unsafe_root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ContextMemoryService::open(unsafe_root).is_err());

        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        drop(service);
        let metadata = state_root.join("metadata.json");
        std::fs::hard_link(&metadata, root.path().join("metadata-hardlink.json")).unwrap();
        assert!(ContextMemoryService::open(state_root).is_err());

        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        drop(service);
        let ledger = state_root.join("agent-data-grants.enc");
        let displaced = root.path().join("displaced-ledger.enc");
        std::fs::rename(&ledger, &displaced).unwrap();
        std::os::unix::fs::symlink(&displaced, &ledger).unwrap();
        assert!(ContextMemoryService::open(state_root).is_err());

        if unsafe { libc::geteuid() } == 0 {
            let root = tempfile::tempdir().unwrap();
            let state_root = root.path().join("state");
            let service = ContextMemoryService::open(state_root.clone()).unwrap();
            drop(service);
            let metadata = state_root.join("metadata.json");
            let encoded = std::ffi::CString::new(metadata.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chown(encoded.as_ptr(), 65_534, u32::MAX) },
                0
            );
            assert!(ContextMemoryService::open(state_root).is_err());
        }

        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        let service = ContextMemoryService::open(state_root.clone()).unwrap();
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "memory_import",
                    "source_id": "import:unsafe-payload-mode",
                    "content": "payload mode must remain private",
                }),
            )
            .unwrap();
        let saved = service
            .call(
                "save_memory",
                "save-unsafe-payload-mode",
                &owner,
                json!({
                    "context_id": context["context_id"],
                    "payload": "payload mode must remain private",
                    "receipt_id": "",
                    "taint_lineage": "user_imported",
                }),
            )
            .unwrap();
        let payload = state_root
            .join("payloads")
            .join(format!("{}.enc", saved["memory_id"].as_str().unwrap()));
        drop(service);
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(ContextMemoryService::open(state_root).is_err());
    }

    #[test]
    fn pinned_parent_fd_defeats_stable_ancestor_swap_race() {
        let root = tempfile::tempdir().unwrap();
        let trusted = root.path().join("trusted");
        let attacker = root.path().join("attacker");
        std::fs::create_dir(&trusted).unwrap();
        std::fs::create_dir(&attacker).unwrap();
        for directory in [&trusted, &attacker] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let trusted_file = trusted.join("state.enc");
        let attacker_file = attacker.join("state.enc");
        std::fs::write(&trusted_file, b"trusted").unwrap();
        std::fs::write(&attacker_file, b"attacker").unwrap();
        for file in [&trusted_file, &attacker_file] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let parent = super::open_private_directory(&trusted).unwrap();
        let moved = root.path().join("trusted-moved");
        std::fs::rename(&trusted, &moved).unwrap();
        std::os::unix::fs::symlink(&attacker, &trusted).unwrap();
        let name = std::ffi::CString::new("state.enc").unwrap();
        let file = super::open_private_regular_file_at(&parent, &name, 32, false).unwrap();
        let mut bytes = Vec::new();
        file.take(33).read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"trusted");
    }

    #[test]
    fn production_root_walk_rejects_symlink_and_writable_ancestors() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let root = tempfile::Builder::new()
            .prefix("trillionnium-root-walk-")
            .tempdir_in("/root")
            .unwrap();
        let real = root.path().join("real");
        let real_state = real.join("state");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&real_state).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&real_state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let linked = root.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        assert!(super::validate_production_root_ancestor_chain(&linked.join("state")).is_err());

        let writable = root.path().join("writable");
        let writable_state = writable.join("state");
        std::fs::create_dir(&writable).unwrap();
        std::fs::create_dir(&writable_state).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::set_permissions(&writable_state, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(super::validate_production_root_ancestor_chain(&writable_state).is_err());
    }

    #[test]
    fn locked_or_unavailable_custody_denies_raw_memory_save_read_and_reopen() {
        let (root, custody, service) = service_with_custody();
        let state_root = root.path().join("state");
        let owner = subject();
        let context = service
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "memory_import",
                    "source_id": "import:key-custody-gate",
                    "content": "custody gated memory",
                }),
            )
            .unwrap();
        let saved = service
            .call(
                "save_memory",
                "memory-custody-save-unlocked",
                &owner,
                json!({
                    "context_id": context["context_id"],
                    "payload": "custody gated memory",
                    "receipt_id": "",
                    "taint_lineage": "user_imported",
                }),
            )
            .unwrap();
        assert!(saved["memory_id"].as_str().unwrap().starts_with("memory-"));
        let raw_grant = service
            .issue_memory_grant(
                &owner,
                grant_target(),
                saved["memory_id"].as_str().unwrap(),
                true,
                "none",
                "none",
                60_000,
            )
            .unwrap();

        custody.set_unlocked(false);
        let save_error = service
            .call(
                "save_memory",
                "memory-custody-save-locked",
                &owner,
                json!({"context_id": context["context_id"], "payload": "custody gated memory"}),
            )
            .unwrap_err();
        assert!(save_error.to_string().contains("subject_user_locked"));
        let read_error = service
            .call(
                "list_memory",
                "memory-custody-read-locked",
                &owner,
                json!({"include_payload": true}),
            )
            .unwrap_err();
        assert!(
            read_error
                .to_string()
                .contains("context_memory_payload_field_type_denied")
        );
        let metadata_only = service
            .call(
                "list_memory",
                "memory-custody-metadata-locked",
                &owner,
                json!({"include_payload": false}),
            )
            .unwrap();
        assert_eq!(metadata_only["payload_included"], false);
        assert!(
            service
                .read_agent_data_grant(
                    &grant_consumer(),
                    raw_grant["grant_id"].as_str().unwrap(),
                    "memory",
                )
                .unwrap_err()
                .to_string()
                .contains("subject_user_locked")
        );
        custody.set_unlocked(true);
        assert_eq!(
            service
                .read_agent_data_grant(
                    &grant_consumer(),
                    raw_grant["grant_id"].as_str().unwrap(),
                    "memory",
                )
                .unwrap()["content"],
            "custody gated memory"
        );
        custody.set_unlocked(false);
        drop(service);
        assert!(
            ContextMemoryService::open_with_key_custody(state_root.clone(), custody.clone())
                .err()
                .unwrap()
                .to_string()
                .contains("subject_user_locked")
        );

        custody.set_unlocked(true);
        custody.set_available(false);
        assert!(
            ContextMemoryService::open_with_key_custody(state_root, custody)
                .err()
                .unwrap()
                .to_string()
                .contains("unavailable")
        );
    }

    #[test]
    fn relock_immediately_denies_ui_replay_provenance_and_execution_decryption() {
        let (root, custody, service) = service_with_custody();
        let owner = subject();
        let executions = AtomicUsize::new(0);
        let payload = json!({"workflow_id": "workflow-relock-gate"});
        service
            .run_ui_request("plan", "ui-relock-gate", &owner, &payload, || {
                executions.fetch_add(1, Ordering::SeqCst);
                Ok(json!({"summary": "protected replay outcome"}))
            })
            .unwrap();
        let (call, execution_path) =
            staged_execution_payload(&service, "https://example.com/relock-gated", 60_000);

        custody.set_unlocked(false);
        let replay_error = service
            .run_ui_request("plan", "ui-relock-gate", &owner, &payload, || {
                executions.fetch_add(1, Ordering::SeqCst);
                Ok(json!({"must_not": "execute"}))
            })
            .unwrap_err();
        assert!(replay_error.to_string().contains("subject_user_locked"));
        assert_eq!(executions.load(Ordering::SeqCst), 1);
        assert!(
            service
                .held_ui_memory_provenance(&owner)
                .unwrap_err()
                .to_string()
                .contains("subject_user_locked")
        );
        assert!(
            service
                .resolve_execution_payload(&call)
                .err()
                .expect("locked execution payload must be denied")
                .to_string()
                .contains("subject_user_locked")
        );
        assert!(execution_path.exists());
        assert_eq!(
            std::fs::read_dir(root.path().join("state/execution-payload-quarantine"))
                .unwrap()
                .count(),
            0
        );

        custody.set_unlocked(true);
        assert_eq!(
            service
                .resolve_execution_payload(&call)
                .unwrap()
                .url
                .as_str(),
            "https://example.com/relock-gated"
        );
    }

    #[test]
    fn legacy_plaintext_memory_key_is_never_migrated_or_read() {
        let root = tempfile::tempdir().unwrap();
        let state_root = root.path().join("state");
        std::fs::create_dir_all(&state_root).unwrap();
        std::fs::set_permissions(&state_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let legacy = state_root.join("memory.key");
        std::fs::write(&legacy, [7u8; 32]).unwrap();
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = ContextMemoryService::open(state_root).err().unwrap();
        assert!(
            error
                .to_string()
                .contains("legacy_plaintext_memory_key_production_refused")
        );
    }

    #[test]
    fn xchacha20poly1305_roundtrip_tamper_wrong_key_aad_and_unique_nonce() {
        let key = [7u8; 32];
        let associated = b"subject-a";
        let first = encrypt_payload(&key, associated, b"secret").unwrap();
        let second = encrypt_payload(&key, associated, b"secret").unwrap();
        assert_ne!(&first[8..32], &second[8..32]);
        let mut encoded = first;
        assert_eq!(
            decrypt_payload(&key, associated, &encoded, super::MAX_CONTEXT_BYTES).unwrap(),
            b"secret"
        );
        encoded[48] ^= 1;
        assert!(decrypt_payload(&key, associated, &encoded, super::MAX_CONTEXT_BYTES).is_err());
        let encoded = encrypt_payload(&key, associated, b"secret").unwrap();
        assert!(decrypt_payload(&key, b"subject-b", &encoded, super::MAX_CONTEXT_BYTES).is_err());
        assert!(
            decrypt_payload(&[8u8; 32], associated, &encoded, super::MAX_CONTEXT_BYTES).is_err()
        );
    }

    #[test]
    fn authority_key_is_independently_pinned_and_same_epoch_substitution_fails() {
        let (_root, service) = service();
        let challenge_sha = super::sha256_bytes(super::AUTHORITY_ATTESTATION_CHALLENGE);
        let metadata = json!({
            "schema": "org.trillionnium.ai-authority.receipt-key.v1",
            "package": "org.trillionnium.aiauthority",
            "signature_algorithm": "SHA256withECDSA",
            "key_id": "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
            "key_epoch": 2,
            "key_profile": "keymint_attested_v1",
            "pin_scope": "package+key_epoch+key_id",
            "public_key_spki": "AQID",
            "public_key_spki_is_identity_root": false,
            "security_level": "TRUSTED_ENVIRONMENT",
            "hardware_backed": true,
            "attestation_challenge_sha256": challenge_sha,
            "attestation_challenge_base64": "b3JnLnRyaWxsaW9ubml1bS5haS1hdXRob3JpdHkucmVjZWlwdC1rZXkudjI=",
            "certificate_chain_der": ["AQ==", "Ag=="],
            "attestation_chain_present": true,
            "attestation_format": "android-keymint-x509-der-chain",
            "attestation_required_for_new_pin": true,
            "attestation_application_id_required": true,
            "rotation_contract": "os_authorized_monotonic_epoch_and_pinned_key_id",
            "verification_contract": "pin key_id in OS-owned state; reject receipt self-asserted keys; accept rotation only with a higher OS-authorized epoch",
        });
        let pin = service
            .pin_authority_key_metadata(metadata.clone())
            .unwrap();
        assert_eq!(pin["internal_pin_verified"], true);
        assert_eq!(pin["attestation_verified"], false);
        assert_eq!(
            service
                .pin_authority_key_metadata(metadata.clone())
                .unwrap()["key_epoch"],
            2
        );

        let mut metadata_drift = metadata;
        metadata_drift["security_level"] = json!("STRONGBOX");
        assert!(
            service
                .pin_authority_key_metadata(metadata_drift)
                .unwrap_err()
                .to_string()
                .contains("same_epoch_key_substitution")
        );

        let substituted = json!({
            "schema": "org.trillionnium.ai-authority.receipt-key.v1",
            "package": "org.trillionnium.aiauthority",
            "signature_algorithm": "SHA256withECDSA",
            "key_id": super::sha256_bytes(&[4u8, 5, 6]),
            "key_epoch": 2,
            "key_profile": "keymint_attested_v1",
            "pin_scope": "package+key_epoch+key_id",
            "public_key_spki": "BAUG",
            "public_key_spki_is_identity_root": false,
            "security_level": "TRUSTED_ENVIRONMENT",
            "hardware_backed": true,
            "attestation_challenge_sha256": super::sha256_bytes(super::AUTHORITY_ATTESTATION_CHALLENGE),
            "attestation_challenge_base64": "b3JnLnRyaWxsaW9ubml1bS5haS1hdXRob3JpdHkucmVjZWlwdC1rZXkudjI=",
            "certificate_chain_der": ["AQ==", "Ag=="],
            "attestation_chain_present": true,
            "attestation_format": "android-keymint-x509-der-chain",
            "attestation_required_for_new_pin": true,
            "attestation_application_id_required": true,
            "rotation_contract": "os_authorized_monotonic_epoch_and_pinned_key_id",
            "verification_contract": "pin key_id in OS-owned state; reject receipt self-asserted keys; accept rotation only with a higher OS-authorized epoch",
        });
        assert!(
            service
                .pin_authority_key_metadata(substituted)
                .unwrap_err()
                .to_string()
                .contains("same_epoch_key_substitution")
        );
    }

    #[test]
    fn same_boot_rotation_failure_never_changes_durable_or_receipt_key_pin() {
        let (_root, service) = service();
        let challenge_sha = super::sha256_bytes(super::AUTHORITY_ATTESTATION_CHALLENGE);
        let old_key_id = super::sha256_bytes(&[1u8, 2, 3]);
        let new_key_id = super::sha256_bytes(&[4u8, 5, 6]);
        let old_metadata = json!({
            "schema": "org.trillionnium.ai-authority.receipt-key.v1",
            "package": "org.trillionnium.aiauthority",
            "signature_algorithm": "SHA256withECDSA",
            "key_id": old_key_id,
            "key_epoch": 1,
            "key_profile": "keymint_attested_v1",
            "pin_scope": "package+key_epoch+key_id",
            "public_key_spki": "AQID",
            "public_key_spki_is_identity_root": false,
            "security_level": "TRUSTED_ENVIRONMENT",
            "hardware_backed": true,
            "attestation_challenge_sha256": challenge_sha,
            "attestation_challenge_base64": "b3JnLnRyaWxsaW9ubml1bS5haS1hdXRob3JpdHkucmVjZWlwdC1rZXkudjI=",
            "certificate_chain_der": ["AQ==", "Ag=="],
            "attestation_chain_present": true,
            "attestation_format": "android-keymint-x509-der-chain",
            "attestation_required_for_new_pin": true,
            "attestation_application_id_required": true,
            "rotation_contract": "os_authorized_monotonic_epoch_and_pinned_key_id",
            "verification_contract": "pin key_id in OS-owned state; reject receipt self-asserted keys; accept rotation only with a higher OS-authorized epoch",
        });
        service
            .pin_authority_key_metadata(old_metadata.clone())
            .unwrap();
        let pin_path = service.root.join("authority-key-pin.json");
        let durable_before = std::fs::read(&pin_path).unwrap();
        let exact_observation = service
            .prevalidate_authority_key_metadata_against_frozen_pin(&old_metadata)
            .unwrap();
        assert_eq!(exact_observation["key_id"], old_key_id);
        assert_eq!(exact_observation["key_epoch"], 1);

        let new_metadata = json!({
            "schema": "org.trillionnium.ai-authority.receipt-key.v1",
            "package": "org.trillionnium.aiauthority",
            "signature_algorithm": "SHA256withECDSA",
            "key_id": new_key_id,
            "key_epoch": 2,
            "key_profile": "keymint_attested_v1",
            "pin_scope": "package+key_epoch+key_id",
            "public_key_spki": "BAUG",
            "public_key_spki_is_identity_root": false,
            "security_level": "TRUSTED_ENVIRONMENT",
            "hardware_backed": true,
            "attestation_challenge_sha256": challenge_sha,
            "attestation_challenge_base64": "b3JnLnRyaWxsaW9ubml1bS5haS1hdXRob3JpdHkucmVjZWlwdC1rZXkudjI=",
            "certificate_chain_der": ["AQ==", "Ag=="],
            "attestation_chain_present": true,
            "attestation_format": "android-keymint-x509-der-chain",
            "attestation_required_for_new_pin": true,
            "attestation_application_id_required": true,
            "rotation_contract": "os_authorized_monotonic_epoch_and_pinned_key_id",
            "verification_contract": "pin key_id in OS-owned state; reject receipt self-asserted keys; accept rotation only with a higher OS-authorized epoch",
        });
        let error = service
            .prevalidate_authority_key_metadata_against_frozen_pin(&new_metadata)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("authority_key_metadata_differs_from_boot_frozen_pin")
        );
        assert_eq!(std::fs::read(&pin_path).unwrap(), durable_before);
        let receipt_pin = service.authority_key_pin().unwrap();
        assert_eq!(receipt_pin["key_id"], old_key_id);
        assert_eq!(receipt_pin["key_epoch"], 1);
    }

    #[test]
    fn userdebug_local_hardware_key_profile_requires_explicit_signed_image_gate() {
        let metadata = json!({
            "schema": "org.trillionnium.ai-authority.receipt-key.v1",
            "package": "org.trillionnium.aiauthority",
            "signature_algorithm": "SHA256withECDSA",
            "key_id": "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
            "key_epoch": 2,
            "key_profile": "userdebug_local_hardware_v1",
            "pin_scope": "package+key_epoch+key_id",
            "public_key_spki": "AQID",
            "public_key_spki_is_identity_root": false,
            "security_level": "TRUSTED_ENVIRONMENT",
            "hardware_backed": true,
            "attestation_challenge_sha256": "unavailable",
            "attestation_challenge_base64": "",
            "certificate_chain_der": [],
            "attestation_chain_present": false,
            "attestation_format": "none",
            "attestation_required_for_new_pin": false,
            "attestation_application_id_required": false,
            "rotation_contract": "os_authorized_monotonic_epoch_and_pinned_key_id",
            "verification_contract": "userdebug-only signed-image key/SPKI pin with hardware security level; attestation unavailable; public release ineligible",
        });
        assert!(
            super::validate_authority_key_metadata_for_profile(&metadata, false)
                .unwrap_err()
                .to_string()
                .contains("not_enabled")
        );
        let candidate =
            super::validate_authority_key_metadata_for_profile(&metadata, true).unwrap();
        assert_eq!(candidate.key_profile, "userdebug_local_hardware_v1");
        assert!(!candidate.attestation_chain_present);
        assert_eq!(candidate.attestation_challenge_sha256, "unavailable");
    }
}
