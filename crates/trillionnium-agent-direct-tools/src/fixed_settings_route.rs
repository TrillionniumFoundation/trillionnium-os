//! Source-only durable route for the first Android vertical slice.
//!
//! This module deliberately has one semantic operation: `launch_package` for
//! `com.android.settings` on Android user 0.  The model-facing request does
//! not contain a protocol, request id, epoch, or user.  Those values are
//! authored by this route and persisted before a backend callback is allowed
//! to run.
//!
//! The route is useful as a small host/daemon integration seam while the
//! hardware rollback and production mutation authorities are still being
//! brought up.  It is not an authority implementation and it does not make a
//! product build eligible for release.  A caller supplies an already
//! provisioned operation epoch and a typed backend callback; the callback is
//! invoked at most once for a given durable route.  After a restart, a
//! recorded response is replayed byte-for-byte and is never sent to Android a
//! second time.  Receipt and outer ACK are separate authenticated files so a
//! crash between either publication and the state transition is recoverable.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::system_api::{
    PROTOCOL, SystemApiRequest, SystemApiSemanticRequest,
    canonical_semantic_request_sha256_for_codex,
};
use crate::{
    DirectToolError, MAX_RESPONSE_BYTES, Result, reject_reserved_backend_fields,
    validate_response_binding,
};

pub const TARGET_PACKAGE: &str = "com.android.settings";
pub const TARGET_USER: u32 = 0;
pub const OPERATION_SEQUENCE: u64 = 1;
pub const ROUTE_SCHEMA: &str = "org.trillionnium.fixed-settings-route.v1";
pub const RECEIPT_SCHEMA: &str = "org.trillionnium.fixed-settings-receipt.v1";
pub const ACK_SCHEMA: &str = "org.trillionnium.fixed-settings-ack.v1";
pub const HOLD_SCHEMA: &str = "org.trillionnium.fixed-settings-hold.v1";

const STATE_FILE: &str = "settings-operation.v1.json";
const RECEIPT_FILE: &str = "settings-receipt.v1.json";
const ACK_FILE: &str = "settings-ack.v1.json";
const HOLD_FILE: &str = "settings-hold.v1.json";
const LOCK_FILE: &str = ".settings-route.v1.lock";
const MAX_ARTIFACT_BYTES: usize = 2 * 1024 * 1024;

/// The only request admitted by [`FixedSettingsRoute`].
pub fn fixed_request() -> SystemApiSemanticRequest {
    SystemApiSemanticRequest::LaunchPackage {
        package: TARGET_PACKAGE.to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePhase {
    Prepared,
    ResultRecorded,
    Acked,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedSettingsOutcome {
    pub operation_id: String,
    pub receipt_sha256: String,
    pub response_bytes: Vec<u8>,
    pub response: Value,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedSettingsReceiptV1 {
    pub schema: String,
    pub operation_id: String,
    pub request_id: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub response_bytes_base64: String,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedSettingsAckV1 {
    pub schema: String,
    pub operation_id: String,
    pub receipt_sha256: String,
    pub ack_sha256: String,
}

/// Durable fail-closed marker for a backend response/transport whose effect
/// cannot be classified.  A held operation is never retried automatically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedSettingsHoldV1 {
    pub schema: String,
    pub operation_id: String,
    pub request_id: String,
    pub request_sha256: String,
    pub reason_code: String,
    pub hold_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteStateV1 {
    schema: String,
    epoch: String,
    sequence: u64,
    operation_id: String,
    request_id: String,
    request_sha256: String,
    phase: RoutePhase,
    receipt_sha256: Option<String>,
    ack_sha256: Option<String>,
    hold_sha256: Option<String>,
    state_sha256: String,
}

pub struct FixedSettingsRoute {
    root: PathBuf,
    _lock: File,
    state: RouteStateV1,
}

impl FixedSettingsRoute {
    /// Open or initialize the fixed route in an OS-owned directory.
    ///
    /// `epoch` is an OS-authored, already provisioned value.  Once the state
    /// exists, a different epoch is rejected rather than silently starting a
    /// new replay namespace.  This prevents a local file from masquerading as
    /// a hardware rollback anchor.
    pub fn open(root: impl AsRef<Path>, epoch: &str) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        validate_root(&root)?;
        validate_epoch(epoch)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(root.join(LOCK_FILE))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(DirectToolError::BackendUnavailable(
                "fixed Settings route is already open".to_string(),
            ));
        }

        let state_path = root.join(STATE_FILE);
        let state_was_absent = !state_path.exists();
        let mut state = match read_json_optional::<RouteStateV1>(&state_path)? {
            Some(state) => state,
            None => new_state(epoch)?,
        };
        validate_state(&state, epoch)?;
        // PREPARED is itself a durable admission record. Persist it before
        // returning the route so a crash immediately before the backend call
        // cannot lose the operation identity and allocate a new effect after
        // the next daemon start.
        if state_was_absent {
            write_json_atomic(&root, STATE_FILE, &state)?;
        }

        // A crash may have persisted the receipt/ACK before the corresponding
        // state transition.  Promote only exact, independently authenticated
        // artifacts; never infer completion from a missing or malformed file.
        if let Some(receipt) =
            read_json_optional::<FixedSettingsReceiptV1>(&root.join(RECEIPT_FILE))?
        {
            validate_receipt(&receipt, &state)?;
            if state.phase == RoutePhase::Prepared {
                state.phase = RoutePhase::ResultRecorded;
                state.receipt_sha256 = Some(receipt.receipt_sha256.clone());
                state.state_sha256 = state_digest(&state)?;
                write_json_atomic(&root, STATE_FILE, &state)?;
            }
        }
        if let Some(ack) = read_json_optional::<FixedSettingsAckV1>(&root.join(ACK_FILE))? {
            validate_ack(&ack, &state)?;
            if state.phase == RoutePhase::ResultRecorded {
                state.phase = RoutePhase::Acked;
                state.ack_sha256 = Some(ack.ack_sha256.clone());
                state.state_sha256 = state_digest(&state)?;
                write_json_atomic(&root, STATE_FILE, &state)?;
            }
        }
        if let Some(hold) = read_json_optional::<FixedSettingsHoldV1>(&root.join(HOLD_FILE))? {
            validate_hold(&hold, &state)?;
            if state.phase == RoutePhase::Prepared {
                state.phase = RoutePhase::Indeterminate;
                state.hold_sha256 = Some(hold.hold_sha256.clone());
                state.state_sha256 = state_digest(&state)?;
                write_json_atomic(&root, STATE_FILE, &state)?;
            }
        }
        if matches!(state.phase, RoutePhase::ResultRecorded | RoutePhase::Acked)
            && read_json_optional::<FixedSettingsReceiptV1>(&root.join(RECEIPT_FILE))?.is_none()
        {
            return Err(DirectToolError::BackendUnavailable(
                "fixed Settings terminal state has no durable receipt".to_string(),
            ));
        }
        if state.phase == RoutePhase::Acked
            && read_json_optional::<FixedSettingsAckV1>(&root.join(ACK_FILE))?.is_none()
        {
            return Err(DirectToolError::BackendUnavailable(
                "fixed Settings ACK state has no durable ACK artifact".to_string(),
            ));
        }
        if state.phase == RoutePhase::Indeterminate
            && read_json_optional::<FixedSettingsHoldV1>(&root.join(HOLD_FILE))?.is_none()
        {
            return Err(DirectToolError::BackendUnavailable(
                "fixed Settings indeterminate state has no durable hold artifact".to_string(),
            ));
        }
        // A stale PREPARED record is deliberately not an automatic retry
        // permission.  Without a receipt, a daemon crash cannot distinguish
        // "backend was never called" from "Android applied the effect and
        // the response was lost". Returning a recovery error keeps this
        // source seam from ever re-effecting an ambiguous operation. A fresh
        // route (state_was_absent) may perform its first callback once.
        if !state_was_absent && state.phase == RoutePhase::Prepared {
            return Err(DirectToolError::BackendUnavailable(
                "fixed Settings PREPARED record has no durable outcome; external recovery required"
                    .to_string(),
            ));
        }
        validate_state(&state, epoch)?;
        Ok(Self {
            root,
            _lock: lock,
            state,
        })
    }

    #[must_use]
    pub fn phase(&self) -> RoutePhase {
        self.state.phase
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.state.operation_id
    }

    /// Execute the fixed request or replay the exact durable response.
    pub fn execute_once<F>(
        &mut self,
        semantic: &SystemApiSemanticRequest,
        backend: F,
    ) -> Result<FixedSettingsOutcome>
    where
        F: FnOnce(&SystemApiRequest) -> Result<Value>,
    {
        require_fixed_request(semantic)?;
        let expected_request_sha256 = canonical_semantic_request_sha256_for_codex(semantic)?;
        if expected_request_sha256 != self.state.request_sha256 {
            return Err(DirectToolError::BackendUnavailable(
                "fixed Settings route request identity changed".to_string(),
            ));
        }
        if self.state.phase == RoutePhase::Indeterminate {
            return Err(self.hold_error());
        }
        if matches!(
            self.state.phase,
            RoutePhase::ResultRecorded | RoutePhase::Acked
        ) {
            return self.replay_outcome();
        }

        let request = SystemApiRequest::LaunchPackage {
            protocol: PROTOCOL.to_string(),
            request_id: self.state.request_id.clone(),
            package: TARGET_PACKAGE.to_string(),
            user: TARGET_USER,
        };
        let response = match backend(&request) {
            Ok(response) => response,
            Err(error) => {
                self.persist_hold("backend_callback_error")?;
                return Err(error);
            }
        };
        let backend_outcome =
            match validate_response_binding(&response, PROTOCOL, &self.state.request_id) {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.persist_hold("backend_protocol_ambiguous")?;
                    return Err(error);
                }
            };
        if backend_outcome == crate::BackendOutcome::Error
            && response
                .get("error")
                .and_then(Value::as_str)
                .is_some_and(crate::is_indeterminate_backend_error_code)
        {
            self.persist_hold("indeterminate_backend_response")?;
            return Err(self.hold_error());
        }
        if let Err(error) = reject_reserved_backend_fields(
            &response,
            &[
                crate::OS_RAW_BACKEND_RESULT_SHA256_FIELD,
                crate::OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD,
            ],
        ) {
            self.persist_hold("backend_protocol_ambiguous")?;
            return Err(error);
        }
        let response_bytes = match serde_json::to_vec(&response) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.persist_hold("backend_protocol_ambiguous")?;
                return Err(error.into());
            }
        };
        if response_bytes.is_empty() || response_bytes.len() > MAX_RESPONSE_BYTES {
            self.persist_hold("backend_response_too_large")?;
            return Err(DirectToolError::BackendFailed(
                "fixed Settings backend response exceeds the durable bound".to_string(),
            ));
        }
        let receipt = match derive_receipt(&self.state, &response_bytes) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.persist_hold("backend_protocol_ambiguous")?;
                return Err(error);
            }
        };
        if let Err(error) = write_json_atomic(&self.root, RECEIPT_FILE, &receipt) {
            // Publication failure leaves the effect outcome uncertain.  A
            // later open will require the hold rather than retrying Android.
            self.persist_hold("receipt_publication_uncertain")?;
            return Err(error);
        }
        self.state.phase = RoutePhase::ResultRecorded;
        self.state.receipt_sha256 = Some(receipt.receipt_sha256.clone());
        self.state.state_sha256 = state_digest(&self.state)?;
        write_json_atomic(&self.root, STATE_FILE, &self.state)?;
        Ok(FixedSettingsOutcome {
            operation_id: self.state.operation_id.clone(),
            receipt_sha256: receipt.receipt_sha256,
            response_bytes,
            response,
            replayed: false,
        })
    }

    /// Publish the durable outer ACK. Repeating this call is idempotent.
    pub fn acknowledge(&mut self) -> Result<FixedSettingsAckV1> {
        if self.state.phase == RoutePhase::Indeterminate {
            return Err(self.hold_error());
        }
        if self.state.phase == RoutePhase::Prepared {
            return Err(DirectToolError::BackendUnavailable(
                "fixed Settings result is not durably recorded".to_string(),
            ));
        }
        let receipt_sha256 = self.state.receipt_sha256.clone().ok_or_else(|| {
            DirectToolError::BackendUnavailable("fixed Settings receipt missing".to_string())
        })?;
        // Re-validate the retained response before publishing an ACK. The ACK
        // must never advance a state whose receipt disappeared or no longer
        // binds to the exact backend response.
        let receipt: FixedSettingsReceiptV1 = read_json_required(&self.root.join(RECEIPT_FILE))?;
        validate_receipt(&receipt, &self.state)?;
        if receipt.receipt_sha256 != receipt_sha256 {
            return Err(DirectToolError::BackendUnavailable(
                "fixed Settings receipt changed before ACK".to_string(),
            ));
        }
        if let Some(existing) = read_json_optional::<FixedSettingsAckV1>(&self.root.join(ACK_FILE))?
        {
            validate_ack(&existing, &self.state)?;
            if existing.receipt_sha256 != receipt_sha256 {
                return Err(DirectToolError::BackendUnavailable(
                    "fixed Settings ACK receipt identity changed".to_string(),
                ));
            }
            self.state.phase = RoutePhase::Acked;
            self.state.ack_sha256 = Some(existing.ack_sha256.clone());
            self.state.state_sha256 = state_digest(&self.state)?;
            write_json_atomic(&self.root, STATE_FILE, &self.state)?;
            return Ok(existing);
        }
        let mut ack = FixedSettingsAckV1 {
            schema: ACK_SCHEMA.to_string(),
            operation_id: self.state.operation_id.clone(),
            receipt_sha256,
            ack_sha256: String::new(),
        };
        ack.ack_sha256 = ack_digest(&ack)?;
        write_json_atomic(&self.root, ACK_FILE, &ack)?;
        self.state.phase = RoutePhase::Acked;
        self.state.ack_sha256 = Some(ack.ack_sha256.clone());
        self.state.state_sha256 = state_digest(&self.state)?;
        write_json_atomic(&self.root, STATE_FILE, &self.state)?;
        Ok(ack)
    }

    fn hold_error(&self) -> DirectToolError {
        DirectToolError::BackendUnavailable(format!(
            "fixed Settings route is durably held; manual recovery required ({})",
            self.state
                .hold_sha256
                .as_deref()
                .unwrap_or("missing-hold-digest"),
        ))
    }

    fn persist_hold(&mut self, reason_code: &str) -> Result<()> {
        if self.state.phase == RoutePhase::Indeterminate {
            return Ok(());
        }
        let mut hold = FixedSettingsHoldV1 {
            schema: HOLD_SCHEMA.to_string(),
            operation_id: self.state.operation_id.clone(),
            request_id: self.state.request_id.clone(),
            request_sha256: self.state.request_sha256.clone(),
            reason_code: reason_code.to_string(),
            hold_sha256: String::new(),
        };
        hold.hold_sha256 = hold_digest(&hold)?;
        // Freeze the in-memory route before attempting either publication.
        // If the filesystem is already failing, a caller that retains this
        // object must still be unable to invoke the backend a second time.
        self.state.phase = RoutePhase::Indeterminate;
        self.state.hold_sha256 = Some(hold.hold_sha256.clone());
        self.state.state_sha256 = state_digest(&self.state)?;
        write_json_atomic(&self.root, HOLD_FILE, &hold)?;
        write_json_atomic(&self.root, STATE_FILE, &self.state)
    }

    /// Replay the exact response bytes retained by the durable receipt.
    pub fn replay_outcome(&self) -> Result<FixedSettingsOutcome> {
        if self.state.phase == RoutePhase::Indeterminate {
            return Err(self.hold_error());
        }
        if self.state.phase == RoutePhase::Prepared {
            return Err(DirectToolError::BackendUnavailable(
                "fixed Settings route needs recovery before replay".to_string(),
            ));
        }
        let receipt: FixedSettingsReceiptV1 = read_json_required(&self.root.join(RECEIPT_FILE))?;
        validate_receipt(&receipt, &self.state)?;
        let response_bytes = BASE64_STANDARD
            .decode(receipt.response_bytes_base64.as_bytes())
            .map_err(|_| {
                DirectToolError::BackendFailed(
                    "fixed Settings receipt payload is invalid".to_string(),
                )
            })?;
        let response: Value = serde_json::from_slice(&response_bytes)?;
        Ok(FixedSettingsOutcome {
            operation_id: self.state.operation_id.clone(),
            receipt_sha256: receipt.receipt_sha256,
            response_bytes,
            response,
            replayed: true,
        })
    }
}

fn require_fixed_request(request: &SystemApiSemanticRequest) -> Result<()> {
    if request == &fixed_request() {
        Ok(())
    } else {
        Err(DirectToolError::InvalidRequest(
            "fixed Settings route permits only launch_package(com.android.settings) on user 0"
                .to_string(),
        ))
    }
}

fn new_state(epoch: &str) -> Result<RouteStateV1> {
    let request = fixed_request();
    let request_sha256 = canonical_semantic_request_sha256_for_codex(&request)?;
    let operation_id = format!("op:{epoch}:{OPERATION_SEQUENCE}:{request_sha256}");
    let state = RouteStateV1 {
        schema: ROUTE_SCHEMA.to_string(),
        epoch: epoch.to_string(),
        sequence: OPERATION_SEQUENCE,
        operation_id: operation_id.clone(),
        request_id: operation_id,
        request_sha256,
        phase: RoutePhase::Prepared,
        receipt_sha256: None,
        ack_sha256: None,
        hold_sha256: None,
        state_sha256: String::new(),
    };
    let mut state = state;
    state.state_sha256 = state_digest(&state)?;
    Ok(state)
}

fn validate_state(state: &RouteStateV1, expected_epoch: &str) -> Result<()> {
    if state.schema != ROUTE_SCHEMA
        || state.epoch != expected_epoch
        || state.sequence != OPERATION_SEQUENCE
        || state.operation_id != state.request_id
        || state.request_sha256.len() != 64
        || state.state_sha256 != state_digest(state)?
    {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings route state is invalid".to_string(),
        ));
    }
    let expected = format!(
        "op:{}:{}:{}",
        state.epoch, state.sequence, state.request_sha256
    );
    if state.operation_id != expected {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings route operation identity is invalid".to_string(),
        ));
    }
    if !valid_lower_sha256(&state.request_sha256) {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings route request digest is invalid".to_string(),
        ));
    }
    if state.phase == RoutePhase::Prepared
        && (state.receipt_sha256.is_some()
            || state.ack_sha256.is_some()
            || state.hold_sha256.is_some())
    {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings prepared state has terminal artifacts".to_string(),
        ));
    }
    if state.phase == RoutePhase::ResultRecorded && state.receipt_sha256.is_none() {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings result state has no receipt digest".to_string(),
        ));
    }
    if state.phase == RoutePhase::ResultRecorded && state.hold_sha256.is_some() {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings result state has an indeterminate hold".to_string(),
        ));
    }
    if state.phase == RoutePhase::Acked
        && (state.receipt_sha256.is_none()
            || state.ack_sha256.is_none()
            || state.hold_sha256.is_some())
    {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings ACK state is incomplete".to_string(),
        ));
    }
    if state.phase == RoutePhase::Indeterminate
        && (state.hold_sha256.is_none()
            || state.receipt_sha256.is_some()
            || state.ack_sha256.is_some())
    {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings indeterminate state is incomplete".to_string(),
        ));
    }
    Ok(())
}

fn derive_receipt(state: &RouteStateV1, response_bytes: &[u8]) -> Result<FixedSettingsReceiptV1> {
    let mut receipt = FixedSettingsReceiptV1 {
        schema: RECEIPT_SCHEMA.to_string(),
        operation_id: state.operation_id.clone(),
        request_id: state.request_id.clone(),
        request_sha256: state.request_sha256.clone(),
        response_sha256: digest(response_bytes),
        response_bytes_base64: BASE64_STANDARD.encode(response_bytes),
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt_digest(&receipt)?;
    Ok(receipt)
}

fn validate_receipt(receipt: &FixedSettingsReceiptV1, state: &RouteStateV1) -> Result<()> {
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.operation_id != state.operation_id
        || receipt.request_id != state.request_id
        || receipt.request_sha256 != state.request_sha256
        || !valid_lower_sha256(&receipt.response_sha256)
        || receipt.receipt_sha256 != receipt_digest(receipt)?
    {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings receipt identity is invalid".to_string(),
        ));
    }
    let bytes = BASE64_STANDARD
        .decode(receipt.response_bytes_base64.as_bytes())
        .map_err(|_| {
            DirectToolError::BackendUnavailable(
                "fixed Settings receipt encoding is invalid".to_string(),
            )
        })?;
    if bytes.is_empty()
        || bytes.len() > MAX_RESPONSE_BYTES
        || digest(&bytes) != receipt.response_sha256
    {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings receipt response digest is invalid".to_string(),
        ));
    }
    let response: Value = serde_json::from_slice(&bytes)?;
    validate_response_binding(&response, PROTOCOL, &state.request_id)?;
    reject_reserved_backend_fields(
        &response,
        &[
            crate::OS_RAW_BACKEND_RESULT_SHA256_FIELD,
            crate::OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD,
        ],
    )?;
    Ok(())
}

fn validate_ack(ack: &FixedSettingsAckV1, state: &RouteStateV1) -> Result<()> {
    if ack.schema != ACK_SCHEMA
        || ack.operation_id != state.operation_id
        || state.receipt_sha256.as_deref() != Some(ack.receipt_sha256.as_str())
        || !valid_lower_sha256(&ack.receipt_sha256)
        || ack.ack_sha256 != ack_digest(ack)?
    {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings ACK identity is invalid".to_string(),
        ));
    }
    Ok(())
}

fn validate_hold(hold: &FixedSettingsHoldV1, state: &RouteStateV1) -> Result<()> {
    if hold.schema != HOLD_SCHEMA
        || hold.operation_id != state.operation_id
        || hold.request_id != state.request_id
        || hold.request_sha256 != state.request_sha256
        || !valid_hold_reason(&hold.reason_code)
        || hold.hold_sha256 != hold_digest(hold)?
    {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings hold identity is invalid".to_string(),
        ));
    }
    Ok(())
}

fn state_digest(state: &RouteStateV1) -> Result<String> {
    let mut unsigned = state.clone();
    unsigned.state_sha256.clear();
    Ok(digest(&serde_json::to_vec(&unsigned)?))
}

fn receipt_digest(receipt: &FixedSettingsReceiptV1) -> Result<String> {
    let mut unsigned = receipt.clone();
    unsigned.receipt_sha256.clear();
    Ok(digest(&serde_json::to_vec(&unsigned)?))
}

fn ack_digest(ack: &FixedSettingsAckV1) -> Result<String> {
    let mut unsigned = ack.clone();
    unsigned.ack_sha256.clear();
    Ok(digest(&serde_json::to_vec(&unsigned)?))
}

fn hold_digest(hold: &FixedSettingsHoldV1) -> Result<String> {
    let mut unsigned = hold.clone();
    unsigned.hold_sha256.clear();
    Ok(digest(&serde_json::to_vec(&unsigned)?))
}

fn digest(bytes: &[u8]) -> String {
    trillionnium_os_types::sha256_bytes(bytes)
}

fn validate_root(root: &Path) -> Result<()> {
    let metadata = fs::metadata(root)?;
    if !metadata.is_dir() {
        return Err(DirectToolError::BackendUnavailable(
            "fixed Settings route root is not a directory".to_string(),
        ));
    }
    Ok(())
}

fn validate_epoch(epoch: &str) -> Result<()> {
    if epoch.len() != 32
        || !epoch
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DirectToolError::InvalidRequest(
            "fixed Settings route epoch must be 32 lowercase hexadecimal characters".to_string(),
        ));
    }
    Ok(())
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte != b'0')
}

fn valid_hold_reason(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn read_json_optional<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
                return Err(DirectToolError::BackendUnavailable(
                    "fixed Settings durable artifact exceeds its bound".to_string(),
                ));
            }
            Ok(Some(serde_json::from_slice(&bytes)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_json_required<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    read_json_optional(path)?.ok_or_else(|| {
        DirectToolError::BackendUnavailable(
            "fixed Settings durable artifact is missing".to_string(),
        )
    })
}

fn write_json_atomic<T: Serialize>(root: &Path, name: &str, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(DirectToolError::BackendFailed(
            "fixed Settings durable artifact exceeds its bound".to_string(),
        ));
    }
    let temporary = root.join(format!(".{name}.tmp"));
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, root.join(name))?;
    File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;

    const EPOCH: &str = "0123456789abcdef0123456789abcdef";

    fn backend(request: &SystemApiRequest) -> Result<Value> {
        Ok(serde_json::json!({
            "protocol": PROTOCOL,
            "request_id": request.request_id(),
            "ok": true,
            "foreground_package": TARGET_PACKAGE,
        }))
    }

    #[test]
    fn fixed_request_rejects_model_selected_targets() {
        let temp = tempfile::tempdir().unwrap();
        let mut route = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
        assert!(temp.path().join(STATE_FILE).is_file());
        assert!(
            route
                .execute_once(
                    &SystemApiSemanticRequest::LaunchPackage {
                        package: "com.android.camera".to_string()
                    },
                    backend,
                )
                .is_err()
        );
        assert_eq!(route.phase(), RoutePhase::Prepared);
    }

    #[test]
    fn prepared_state_survives_restart_without_running_backend() {
        let temp = tempfile::tempdir().unwrap();
        {
            let route = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
            assert_eq!(route.phase(), RoutePhase::Prepared);
        }
        let error = match FixedSettingsRoute::open(temp.path(), EPOCH) {
            Ok(_) => panic!("a stale prepared operation must not be retried automatically"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("external recovery"));
    }

    #[test]
    fn open_persists_prepared_before_any_backend_dispatch() {
        let temp = tempfile::tempdir().unwrap();
        let route = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
        assert_eq!(route.phase(), RoutePhase::Prepared);
        assert!(temp.path().join(STATE_FILE).is_file());
        assert!(!temp.path().join(RECEIPT_FILE).exists());
        assert!(!temp.path().join(ACK_FILE).exists());
        drop(route);

        let error = match FixedSettingsRoute::open(temp.path(), EPOCH) {
            Ok(_) => panic!("a stale prepared operation must require external recovery"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("external recovery"));
    }

    #[test]
    fn restart_replays_receipt_without_second_backend_effect() {
        let temp = tempfile::tempdir().unwrap();
        let calls = Rc::new(Cell::new(0));
        let first = {
            let calls = Rc::clone(&calls);
            let mut route = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
            let outcome = route
                .execute_once(&fixed_request(), |request| {
                    calls.set(calls.get() + 1);
                    backend(request)
                })
                .unwrap();
            assert!(!outcome.replayed);
            route.acknowledge().unwrap();
            outcome
        };
        assert_eq!(calls.get(), 1);

        let mut reopened = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
        assert_eq!(reopened.phase(), RoutePhase::Acked);
        let replay = reopened
            .execute_once(&fixed_request(), |_request| {
                calls.set(calls.get() + 1);
                Err(DirectToolError::BackendFailed(
                    "must not re-effect".to_string(),
                ))
            })
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.operation_id, first.operation_id);
        assert_eq!(replay.receipt_sha256, first.receipt_sha256);
        assert_eq!(replay.response_bytes, first.response_bytes);
        assert_eq!(calls.get(), 1);
        let ack = reopened.acknowledge().unwrap();
        assert_eq!(ack.receipt_sha256, first.receipt_sha256);
    }

    #[test]
    fn receipt_publication_before_state_transition_is_promoted_on_restart() {
        let temp = tempfile::tempdir().unwrap();
        let route = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
        let response = backend(&SystemApiRequest::LaunchPackage {
            protocol: PROTOCOL.to_string(),
            request_id: route.operation_id().to_string(),
            package: TARGET_PACKAGE.to_string(),
            user: TARGET_USER,
        })
        .unwrap();
        let bytes = serde_json::to_vec(&response).unwrap();
        let receipt = derive_receipt(&route.state, &bytes).unwrap();
        write_json_atomic(temp.path(), RECEIPT_FILE, &receipt).unwrap();
        drop(route);

        let reopened = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
        assert_eq!(reopened.phase(), RoutePhase::ResultRecorded);
        assert_eq!(reopened.replay_outcome().unwrap().response_bytes, bytes);
    }

    #[test]
    fn epoch_change_is_fail_closed_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let route = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
        drop(route);
        assert!(FixedSettingsRoute::open(temp.path(), "fedcba9876543210fedcba9876543210").is_err());
    }

    #[test]
    fn callback_error_becomes_durable_hold_and_is_not_retried_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let calls = Rc::new(Cell::new(0));
        {
            let calls = Rc::clone(&calls);
            let mut route = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
            let error = route
                .execute_once(&fixed_request(), |_request| {
                    calls.set(calls.get() + 1);
                    Err(DirectToolError::BackendUnavailable(
                        "transport lost".to_string(),
                    ))
                })
                .unwrap_err();
            assert!(error.to_string().contains("transport lost"));
            assert_eq!(route.phase(), RoutePhase::Indeterminate);
            assert!(route.acknowledge().is_err());
        }
        let mut reopened = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
        assert_eq!(reopened.phase(), RoutePhase::Indeterminate);
        assert!(
            reopened
                .execute_once(&fixed_request(), |_request| {
                    calls.set(calls.get() + 1);
                    panic!("held operation must not invoke backend")
                })
                .is_err()
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn indeterminate_backend_response_is_held_before_receipt_or_ack() {
        let temp = tempfile::tempdir().unwrap();
        let mut route = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
        let error = route
            .execute_once(&fixed_request(), |request| {
                Ok(serde_json::json!({
                    "protocol": PROTOCOL,
                    "request_id": request.request_id(),
                    "ok": false,
                    "error": "request_in_flight"
                }))
            })
            .unwrap_err();
        assert!(error.to_string().contains("durably held"));
        assert_eq!(route.phase(), RoutePhase::Indeterminate);
        assert!(!temp.path().join(RECEIPT_FILE).exists());
        assert!(!temp.path().join(ACK_FILE).exists());
        drop(route);
        let reopened = FixedSettingsRoute::open(temp.path(), EPOCH).unwrap();
        assert_eq!(reopened.phase(), RoutePhase::Indeterminate);
        assert!(reopened.replay_outcome().is_err());
    }
}
