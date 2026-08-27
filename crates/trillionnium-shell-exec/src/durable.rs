use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use trillionnium_os_types::direct_effect::{
    BROKER_RESTART_BEFORE_DISPATCH_ERROR_CODE, DirectEffectBinaryOutputV1,
    DirectEffectDurableStateV1, DirectEffectIndeterminateReasonV1, DirectEffectPhaseV1,
    DirectEffectRequestV1, DirectEffectTerminalKindV1, DirectEffectTerminalResponseV1,
    DirectEffectTransitionV1, TERMINAL_RESPONSE_SCHEMA,
};

const SNAPSHOT_SCHEMA: &str = "org.trillionnium.shell-exec.durable-ledger.v1";
const SNAPSHOT_FILE: &str = "shell-exec-ledger.v1.json";
const TEMP_FILE: &str = ".shell-exec-ledger.v1.json.tmp";
const LOCK_FILE: &str = ".shell-exec-ledger.v1.lock";
const MAX_SNAPSHOT_BYTES: u64 = 32 * 1024 * 1024;
const TERMINAL_SERIALIZATION_MARGIN_BYTES: u64 = 4 * 1024;
const TERMINAL_FREE_SPACE_RESERVE_BYTES: u64 = 128 * 1024;
// One first-slice effect can contain 64 KiB of adversarial JSON-escaped argv
// plus a base64-wrapped 64 KiB terminal payload. These component bounds and
// their one-MiB sum are verified with the actual ledger and receipt encoders.
pub const MAX_DURABLE_LEDGER_RECORD_BYTES: u64 = 600 * 1024;
pub const MAX_DURABLE_RECEIPT_RECORD_BYTES: u64 = 424 * 1024;
pub const MAX_DURABLE_RECORD_RESERVATION_BYTES: u64 =
    MAX_DURABLE_LEDGER_RECORD_BYTES + MAX_DURABLE_RECEIPT_RECORD_BYTES;
pub const MAX_DURABLE_EFFECT_RECORDS: u64 = 30;

#[derive(Debug, Error)]
pub enum DurableError {
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("durable snapshot is invalid")]
    SnapshotInvalid,
    #[error("durable operation identity conflicts with existing bytes")]
    IdentityConflict,
    #[error("durable state transition is invalid")]
    TransitionInvalid,
    #[error("durable ledger has no admission capacity for another effect")]
    CapacityExhausted,
    #[error("another broker owns the durable ledger lock")]
    WriterLocked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerRecoveryV1 {
    FreshNotDispatched,
    AwaitSameAuthenticatedRetry,
    ReplayExactTerminal(Vec<u8>),
    DispatchedMustBecomeIndeterminate,
    HoldIndeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StableLedgerRecoveryV1 {
    Absent,
    NotDispatched(DirectEffectRequestV1),
    Dispatched(DirectEffectRequestV1),
    Terminal {
        request: DirectEffectRequestV1,
        terminal_response: Vec<u8>,
    },
    Indeterminate(DirectEffectRequestV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableEffectRecordV1 {
    pub request: DirectEffectRequestV1,
    pub state: DirectEffectDurableStateV1,
    pub terminal_response: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerRecordV1 {
    request: DirectEffectRequestV1,
    state: DirectEffectDurableStateV1,
    terminal_response_base64: Option<String>,
}

impl LedgerRecordV1 {
    fn validate(&self) -> Result<(), DurableError> {
        self.request
            .validate()
            .map_err(|_| DurableError::SnapshotInvalid)?;
        self.state
            .validate()
            .map_err(|_| DurableError::SnapshotInvalid)?;
        if self.state.effect_id != self.request.effect_id
            || self.state.request_sha256 != self.request.request_sha256
        {
            return Err(DurableError::SnapshotInvalid);
        }
        match self.state.phase {
            DirectEffectPhaseV1::Terminal => {
                let encoded = self
                    .terminal_response_base64
                    .as_deref()
                    .ok_or(DurableError::SnapshotInvalid)?;
                let bytes = BASE64_STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(|_| DurableError::SnapshotInvalid)?;
                let response: DirectEffectTerminalResponseV1 =
                    serde_json::from_slice(&bytes).map_err(|_| DurableError::SnapshotInvalid)?;
                if response
                    .canonical_bytes(&self.request)
                    .map_err(|_| DurableError::SnapshotInvalid)?
                    != bytes
                {
                    return Err(DurableError::SnapshotInvalid);
                }
                let observation = self
                    .state
                    .terminal_observation
                    .as_ref()
                    .ok_or(DurableError::SnapshotInvalid)?;
                if response
                    .to_terminal_observation(&self.request)
                    .map_err(|_| DurableError::SnapshotInvalid)?
                    != *observation
                {
                    return Err(DurableError::SnapshotInvalid);
                }
            }
            DirectEffectPhaseV1::NotDispatched
            | DirectEffectPhaseV1::Dispatched
            | DirectEffectPhaseV1::Indeterminate => {
                if self.terminal_response_base64.is_some() {
                    return Err(DurableError::SnapshotInvalid);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerBodyV1 {
    schema: String,
    generation: u64,
    records: BTreeMap<String, LedgerRecordV1>,
}

impl LedgerBodyV1 {
    fn empty() -> Self {
        Self {
            schema: SNAPSHOT_SCHEMA.to_string(),
            generation: 0,
            records: BTreeMap::new(),
        }
    }

    fn validate(&self) -> Result<(), DurableError> {
        if self.schema != SNAPSHOT_SCHEMA || (self.generation == 0 && !self.records.is_empty()) {
            return Err(DurableError::SnapshotInvalid);
        }
        for (effect_id, record) in &self.records {
            record.validate()?;
            if effect_id != &record.request.effect_id {
                return Err(DurableError::SnapshotInvalid);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerEnvelopeV1 {
    body: LedgerBodyV1,
    body_sha256: String,
}

impl LedgerEnvelopeV1 {
    fn derive(body: LedgerBodyV1) -> Result<Self, DurableError> {
        body.validate()?;
        let bytes = serde_json::to_vec(&body).map_err(|_| DurableError::SnapshotInvalid)?;
        Ok(Self {
            body,
            body_sha256: trillionnium_os_types::sha256_bytes(&bytes),
        })
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, DurableError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| DurableError::SnapshotInvalid)
    }

    fn validate(&self) -> Result<(), DurableError> {
        self.body.validate()?;
        let bytes = serde_json::to_vec(&self.body).map_err(|_| DurableError::SnapshotInvalid)?;
        if trillionnium_os_types::sha256_bytes(&bytes) != self.body_sha256 {
            return Err(DurableError::SnapshotInvalid);
        }
        Ok(())
    }
}

pub struct DurableShellExecLedgerV1 {
    root: PathBuf,
    directory: File,
    root_device: u64,
    root_inode: u64,
    _lock: File,
    body: LedgerBodyV1,
    published: bool,
}

impl DurableShellExecLedgerV1 {
    pub fn open(root: &Path) -> Result<Self, DurableError> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(root)?;
        let metadata = directory.metadata()?;
        validate_private_directory_metadata(&metadata)?;
        let root_device = metadata.dev();
        let root_inode = metadata.ino();
        let lock = openat_file(
            &directory,
            LOCK_FILE,
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )?;
        let locked = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if locked != 0 {
            return Err(DurableError::WriterLocked);
        }
        validate_private_regular_fd(&lock)?;

        match openat_file(
            &directory,
            TEMP_FILE,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        ) {
            Ok(file) => {
                validate_private_regular_fd(&file)?;
                unlinkat_name(&directory, TEMP_FILE)?;
                directory.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let snapshot = read_snapshot(&directory)?;
        let (body, published) = snapshot
            .map(|value| (value.body, true))
            .unwrap_or_else(|| (LedgerBodyV1::empty(), false));
        body.validate()?;
        Ok(Self {
            root: root.to_path_buf(),
            directory,
            root_device,
            root_inode,
            _lock: lock,
            body,
            published,
        })
    }

    pub fn prepare_or_recover(
        &mut self,
        request: &DirectEffectRequestV1,
    ) -> Result<LedgerRecoveryV1, DurableError> {
        request
            .validate()
            .map_err(|_| DurableError::SnapshotInvalid)?;
        if let Some(record) = self.body.records.get(&request.effect_id) {
            if record.request != *request {
                return Err(DurableError::IdentityConflict);
            }
            return Ok(match record.state.phase {
                DirectEffectPhaseV1::NotDispatched => LedgerRecoveryV1::AwaitSameAuthenticatedRetry,
                DirectEffectPhaseV1::Dispatched => {
                    LedgerRecoveryV1::DispatchedMustBecomeIndeterminate
                }
                DirectEffectPhaseV1::Terminal => LedgerRecoveryV1::ReplayExactTerminal(
                    BASE64_STANDARD
                        .decode(
                            record
                                .terminal_response_base64
                                .as_deref()
                                .ok_or(DurableError::SnapshotInvalid)?
                                .as_bytes(),
                        )
                        .map_err(|_| DurableError::SnapshotInvalid)?,
                ),
                DirectEffectPhaseV1::Indeterminate => LedgerRecoveryV1::HoldIndeterminate,
            });
        }
        let state = DirectEffectDurableStateV1::not_dispatched(request)
            .map_err(|_| DurableError::TransitionInvalid)?;
        let mut next = self.body.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(DurableError::SnapshotInvalid)?;
        next.records.insert(
            request.effect_id.clone(),
            LedgerRecordV1 {
                request: request.clone(),
                state,
                terminal_response_base64: None,
            },
        );
        self.publish(next)?;
        Ok(LedgerRecoveryV1::FreshNotDispatched)
    }

    /// Resolves the boot-independent adapter identity before a caller creates
    /// a new OS-owned request. This prevents a reboot from colliding with an
    /// already durable request whose boot/deadline/custody fields necessarily
    /// differ while its effect id remains stable.
    pub fn recover_stable_request(
        &self,
        binding_sha256: &str,
        adapter_effect_ordinal: u64,
        semantic_arguments_sha256: &str,
    ) -> Result<StableLedgerRecoveryV1, DurableError> {
        if !trillionnium_os_types::is_nonzero_lower_sha256(binding_sha256)
            || adapter_effect_ordinal == 0
            || !trillionnium_os_types::is_nonzero_lower_sha256(semantic_arguments_sha256)
        {
            return Err(DurableError::IdentityConflict);
        }
        let mut matched = None;
        for record in self.body.records.values() {
            if record.request.direct_binding_sha256 != binding_sha256
                || record.request.adapter_effect_ordinal != adapter_effect_ordinal
            {
                continue;
            }
            let observed_semantic = record
                .request
                .arguments
                .canonical_sha256()
                .map_err(|_| DurableError::SnapshotInvalid)?;
            if observed_semantic != semantic_arguments_sha256 || matched.is_some() {
                return Err(DurableError::IdentityConflict);
            }
            matched = Some(record);
        }
        let Some(record) = matched else {
            return Ok(StableLedgerRecoveryV1::Absent);
        };
        Ok(match record.state.phase {
            DirectEffectPhaseV1::NotDispatched => {
                StableLedgerRecoveryV1::NotDispatched(record.request.clone())
            }
            DirectEffectPhaseV1::Dispatched => {
                StableLedgerRecoveryV1::Dispatched(record.request.clone())
            }
            DirectEffectPhaseV1::Terminal => StableLedgerRecoveryV1::Terminal {
                request: record.request.clone(),
                terminal_response: decode_terminal_response(record)?,
            },
            DirectEffectPhaseV1::Indeterminate => {
                StableLedgerRecoveryV1::Indeterminate(record.request.clone())
            }
        })
    }

    pub fn records_for_binding(
        &self,
        binding_sha256: &str,
    ) -> Result<Vec<DurableEffectRecordV1>, DurableError> {
        if !trillionnium_os_types::is_nonzero_lower_sha256(binding_sha256) {
            return Err(DurableError::IdentityConflict);
        }
        let mut records = self
            .body
            .records
            .values()
            .filter(|record| record.request.direct_binding_sha256 == binding_sha256)
            .map(durable_record)
            .collect::<Result<Vec<_>, _>>()?;
        records.sort_by_key(|record| record.request.adapter_effect_ordinal);
        Ok(records)
    }

    pub fn records(&self) -> Result<Vec<DurableEffectRecordV1>, DurableError> {
        self.body.records.values().map(durable_record).collect()
    }

    #[cfg(feature = "android-product")]
    pub(crate) fn retained_root_device(&self) -> Result<u64, DurableError> {
        self.verify_directory_custody()?;
        Ok(self.root_device)
    }

    /// Reserves capacity for the remaining effects of one uniquely active
    /// registration. This is read-only: a rejected registration cannot grow
    /// the ledger or make the broker unready, while accepted registrations
    /// have room for every worst-case terminal copy-on-publish snapshot.
    pub fn admit_additional_record_capacity(
        &self,
        additional_records: u64,
    ) -> Result<(), DurableError> {
        self.verify_directory_custody()?;
        let current_records =
            u64::try_from(self.body.records.len()).map_err(|_| DurableError::CapacityExhausted)?;
        if current_records
            .checked_add(additional_records)
            .ok_or(DurableError::CapacityExhausted)?
            > MAX_DURABLE_EFFECT_RECORDS
        {
            return Err(DurableError::CapacityExhausted);
        }
        let current_snapshot = LedgerEnvelopeV1::derive(self.body.clone())?.canonical_bytes()?;
        let (projected_snapshot, required_free) =
            registration_capacity_projection(current_snapshot.len() as u64, additional_records)?;
        if projected_snapshot > MAX_SNAPSHOT_BYTES {
            return Err(DurableError::CapacityExhausted);
        }
        require_registration_free_bytes(available_bytes(&self.directory)?, required_free)?;
        Ok(())
    }

    pub fn record(&self, effect_id: &str) -> Result<Option<DurableEffectRecordV1>, DurableError> {
        self.body
            .records
            .get(effect_id)
            .map(durable_record)
            .transpose()
    }

    /// Converts every crash-visible DISPATCHED record before product READY.
    /// The exact original request is retained; no new-boot request is derived.
    pub fn recover_all_dispatched_after_restart(
        &mut self,
        observed_boottime_ms: u64,
    ) -> Result<(), DurableError> {
        let dispatched = self
            .body
            .records
            .values()
            .filter(|record| record.state.phase == DirectEffectPhaseV1::Dispatched)
            .map(|record| record.request.clone())
            .collect::<Vec<_>>();
        for request in dispatched {
            self.hold_restart_indeterminate(&request, observed_boottime_ms)?;
        }
        Ok(())
    }

    pub fn terminalize_old_boot_not_dispatched(
        &mut self,
        current_boot_id_sha256: &str,
        observed_boottime_ms: u64,
    ) -> crate::Result<()> {
        if !trillionnium_os_types::is_nonzero_lower_sha256(current_boot_id_sha256)
            || observed_boottime_ms == 0
        {
            return Err(crate::ShellExecError::RequestDenied(
                "boot_identity_unavailable",
            ));
        }
        let stale = self
            .body
            .records
            .values()
            .filter(|record| {
                record.state.phase == DirectEffectPhaseV1::NotDispatched
                    && record.request.boot_id_sha256 != current_boot_id_sha256
            })
            .map(|record| record.request.clone())
            .collect::<Vec<_>>();
        for request in stale {
            // CLOCK_BOOTTIME restarts at each boot, so the new observation
            // cannot be ordered against this old request's absolute deadline.
            self.finish_not_dispatched_policy(
                &request,
                BROKER_RESTART_BEFORE_DISPATCH_ERROR_CODE,
                observed_boottime_ms,
            )?;
        }
        Ok(())
    }

    /// Product broker restart retires the only reachable claimant for every
    /// crash-visible NOT_DISPATCHED record. Until sealed host replay exists,
    /// startup must terminalize all such records before listener/READY while
    /// the lower-level exact authenticated retry API remains available to
    /// host-conformance callers whose registry survived.
    pub fn terminalize_all_not_dispatched_after_product_restart(
        &mut self,
        observed_boottime_ms: u64,
    ) -> crate::Result<()> {
        if observed_boottime_ms == 0 {
            return Err(crate::ShellExecError::RequestDenied("boottime_unavailable"));
        }
        let retained = self
            .body
            .records
            .values()
            .filter(|record| record.state.phase == DirectEffectPhaseV1::NotDispatched)
            .map(|record| record.request.clone())
            .collect::<Vec<_>>();
        for request in retained {
            self.finish_not_dispatched_policy(
                &request,
                BROKER_RESTART_BEFORE_DISPATCH_ERROR_CODE,
                observed_boottime_ms,
            )?;
        }
        Ok(())
    }

    pub fn mark_dispatched(
        &mut self,
        request: &DirectEffectRequestV1,
        started_boottime_ms: u64,
        dispatch_binding_sha256: &str,
    ) -> Result<(), DurableError> {
        self.transition(
            request,
            DirectEffectTransitionV1::MarkDispatched {
                started_boottime_ms,
                dispatch_binding_sha256: dispatch_binding_sha256.to_string(),
            },
            None,
        )
    }

    /// Admit a dispatch only when the current ledger can represent the
    /// largest valid terminal response and the filesystem reports room for a
    /// complete copy-on-publish snapshot plus a fixed reserve. This cannot
    /// prevent a later ENOSPC race, so every post-DISPATCH persistence error
    /// is still publicly classified as indeterminate by the broker.
    pub fn admit_worst_case_terminal(
        &self,
        request: &DirectEffectRequestV1,
        started_boottime_ms: u64,
        dispatch_binding_sha256: &str,
    ) -> Result<u64, DurableError> {
        self.verify_directory_custody()?;
        let record = self
            .body
            .records
            .get(&request.effect_id)
            .ok_or(DurableError::TransitionInvalid)?;
        if record.request != *request || record.state.phase != DirectEffectPhaseV1::NotDispatched {
            return Err(DurableError::TransitionInvalid);
        }
        let dispatched = record
            .state
            .transition(
                request,
                DirectEffectTransitionV1::MarkDispatched {
                    started_boottime_ms,
                    dispatch_binding_sha256: dispatch_binding_sha256.to_string(),
                },
            )
            .map_err(|_| DurableError::TransitionInvalid)?;
        let mut maximum = 0_u64;
        for response in crate::terminal_budget_candidates(request, started_boottime_ms) {
            let bytes = response
                .canonical_bytes(request)
                .map_err(|_| DurableError::TransitionInvalid)?;
            let observation = response
                .to_terminal_observation(request)
                .map_err(|_| DurableError::TransitionInvalid)?;
            let terminal = dispatched
                .transition(
                    request,
                    DirectEffectTransitionV1::RecordTerminal { observation },
                )
                .map_err(|_| DurableError::TransitionInvalid)?;
            let mut next = self.body.clone();
            next.generation = next
                .generation
                .checked_add(2)
                .ok_or(DurableError::SnapshotInvalid)?;
            next.records.insert(
                request.effect_id.clone(),
                LedgerRecordV1 {
                    request: request.clone(),
                    state: terminal,
                    terminal_response_base64: Some(BASE64_STANDARD.encode(bytes)),
                },
            );
            let serialized = LedgerEnvelopeV1::derive(next)?.canonical_bytes()?;
            maximum = maximum.max(serialized.len() as u64);
        }
        let required_snapshot_bytes = maximum
            .checked_add(TERMINAL_SERIALIZATION_MARGIN_BYTES)
            .ok_or(DurableError::SnapshotInvalid)?;
        if required_snapshot_bytes > MAX_SNAPSHOT_BYTES {
            return Err(DurableError::CapacityExhausted);
        }
        let available = available_bytes(&self.directory)?;
        let required_free = required_snapshot_bytes
            .checked_add(TERMINAL_FREE_SPACE_RESERVE_BYTES)
            .ok_or(DurableError::SnapshotInvalid)?;
        if available < required_free {
            return Err(DurableError::Io(std::io::Error::from_raw_os_error(
                libc::ENOSPC,
            )));
        }
        Ok(required_snapshot_bytes)
    }

    pub fn finish_terminal(
        &mut self,
        request: &DirectEffectRequestV1,
        response: DirectEffectTerminalResponseV1,
    ) -> crate::Result<Vec<u8>> {
        let bytes = response
            .canonical_bytes(request)
            .map_err(|_| crate::ShellExecError::RequestDenied("terminal_response_invalid"))?;
        let observation = response
            .to_terminal_observation(request)
            .map_err(|_| crate::ShellExecError::RequestDenied("terminal_response_invalid"))?;
        self.transition(
            request,
            DirectEffectTransitionV1::RecordTerminal { observation },
            Some(bytes.clone()),
        )?;
        Ok(bytes)
    }

    pub fn finish_not_dispatched_cancelled(
        &mut self,
        request: &DirectEffectRequestV1,
        observed_boottime_ms: u64,
    ) -> crate::Result<Vec<u8>> {
        self.finish_not_dispatched(
            request,
            DirectEffectTerminalKindV1::CancelledBeforeDispatch,
            None,
            observed_boottime_ms,
        )
    }

    pub fn finish_not_dispatched_deadline(
        &mut self,
        request: &DirectEffectRequestV1,
        observed_boottime_ms: u64,
    ) -> crate::Result<Vec<u8>> {
        self.finish_not_dispatched(
            request,
            DirectEffectTerminalKindV1::DeadlineBeforeDispatch,
            None,
            observed_boottime_ms,
        )
    }

    pub fn finish_not_dispatched_policy(
        &mut self,
        request: &DirectEffectRequestV1,
        error_code: &str,
        observed_boottime_ms: u64,
    ) -> crate::Result<Vec<u8>> {
        self.finish_not_dispatched(
            request,
            DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch,
            Some(error_code.to_string()),
            observed_boottime_ms,
        )
    }

    fn finish_not_dispatched(
        &mut self,
        request: &DirectEffectRequestV1,
        kind: DirectEffectTerminalKindV1,
        backend_error_code: Option<String>,
        observed_boottime_ms: u64,
    ) -> crate::Result<Vec<u8>> {
        let response = DirectEffectTerminalResponseV1 {
            schema: TERMINAL_RESPONSE_SCHEMA.to_string(),
            effect_id: request.effect_id.clone(),
            request_sha256: request.request_sha256.clone(),
            dispatch_occurred: false,
            kind,
            exit_code: None,
            signal: None,
            backend_error_code,
            stdout: DirectEffectBinaryOutputV1::from_complete_bytes(b""),
            stderr: DirectEffectBinaryOutputV1::from_complete_bytes(b""),
            started_boottime_ms: observed_boottime_ms,
            finished_boottime_ms: observed_boottime_ms,
        };
        let bytes = response
            .canonical_bytes(request)
            .map_err(|_| crate::ShellExecError::RequestDenied("terminal_response_invalid"))?;
        let observation = response
            .to_terminal_observation(request)
            .map_err(|_| crate::ShellExecError::RequestDenied("terminal_response_invalid"))?;
        self.transition(
            request,
            DirectEffectTransitionV1::RecordNotDispatchedTerminal { observation },
            Some(bytes.clone()),
        )?;
        Ok(bytes)
    }

    pub fn hold_indeterminate(
        &mut self,
        request: &DirectEffectRequestV1,
        reason: DirectEffectIndeterminateReasonV1,
        observed_boottime_ms: u64,
    ) -> Result<(), DurableError> {
        self.transition(
            request,
            DirectEffectTransitionV1::HoldIndeterminate {
                reason,
                observed_boottime_ms,
            },
            None,
        )
    }

    pub fn hold_restart_indeterminate(
        &mut self,
        request: &DirectEffectRequestV1,
        observed_boottime_ms: u64,
    ) -> Result<(), DurableError> {
        let observed_boottime_ms = self
            .body
            .records
            .get(&request.effect_id)
            .and_then(|record| record.state.dispatch_started_boottime_ms)
            .map_or(observed_boottime_ms, |started| {
                observed_boottime_ms.max(started)
            });
        self.hold_indeterminate(
            request,
            DirectEffectIndeterminateReasonV1::BrokerRestartAfterDispatch,
            observed_boottime_ms,
        )
    }

    pub fn state(&self, effect_id: &str) -> Option<&DirectEffectDurableStateV1> {
        self.body.records.get(effect_id).map(|record| &record.state)
    }

    fn transition(
        &mut self,
        request: &DirectEffectRequestV1,
        transition: DirectEffectTransitionV1,
        terminal_response: Option<Vec<u8>>,
    ) -> Result<(), DurableError> {
        let record = self
            .body
            .records
            .get(&request.effect_id)
            .ok_or(DurableError::TransitionInvalid)?;
        if record.request != *request {
            return Err(DurableError::IdentityConflict);
        }
        let state = record
            .state
            .transition(request, transition)
            .map_err(|_| DurableError::TransitionInvalid)?;
        if (state.phase == DirectEffectPhaseV1::Terminal) != terminal_response.is_some() {
            return Err(DurableError::TransitionInvalid);
        }
        let mut next = self.body.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(DurableError::SnapshotInvalid)?;
        next.records.insert(
            request.effect_id.clone(),
            LedgerRecordV1 {
                request: request.clone(),
                state,
                terminal_response_base64: terminal_response
                    .map(|bytes| BASE64_STANDARD.encode(bytes)),
            },
        );
        self.publish(next)
    }

    fn publish(&mut self, next: LedgerBodyV1) -> Result<(), DurableError> {
        next.validate()?;
        self.verify_directory_custody()?;
        let observed = read_snapshot(&self.directory)?.map(|value| value.body);
        let expected = self.published.then_some(self.body.clone());
        if observed != expected {
            return Err(DurableError::IdentityConflict);
        }
        let envelope = LedgerEnvelopeV1::derive(next.clone())?;
        let bytes = envelope.canonical_bytes()?;
        if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(DurableError::CapacityExhausted);
        }
        let mut temporary = openat_file(
            &self.directory,
            TEMP_FILE,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )?;
        validate_private_regular_fd(&temporary)?;
        temporary.write_all(&bytes)?;
        temporary.sync_all()?;
        renameat_name(&self.directory, TEMP_FILE, SNAPSHOT_FILE)?;
        self.directory.sync_all()?;
        let readback = read_snapshot(&self.directory)?.ok_or(DurableError::SnapshotInvalid)?;
        if readback != envelope {
            return Err(DurableError::SnapshotInvalid);
        }
        // Detect a parent-path swap both before and after publication. All I/O
        // above remains anchored to the retained directory fd; a mismatch here
        // prevents the caller from treating an orphaned marker as dispatchable.
        self.verify_directory_custody()?;
        self.body = next;
        self.published = true;
        Ok(())
    }

    fn verify_directory_custody(&self) -> Result<(), DurableError> {
        let retained = self.directory.metadata()?;
        validate_private_directory_metadata(&retained)?;
        if retained.dev() != self.root_device || retained.ino() != self.root_inode {
            return Err(DurableError::SnapshotInvalid);
        }
        let reopened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.root)?;
        let observed = reopened.metadata()?;
        validate_private_directory_metadata(&observed)?;
        if observed.dev() != self.root_device || observed.ino() != self.root_inode {
            return Err(DurableError::SnapshotInvalid);
        }
        Ok(())
    }
}

fn registration_capacity_projection(
    current_snapshot_bytes: u64,
    additional_records: u64,
) -> Result<(u64, u64), DurableError> {
    let ledger_growth = additional_records
        .checked_mul(MAX_DURABLE_LEDGER_RECORD_BYTES)
        .ok_or(DurableError::CapacityExhausted)?;
    let receipt_growth = additional_records
        .checked_mul(MAX_DURABLE_RECEIPT_RECORD_BYTES)
        .ok_or(DurableError::CapacityExhausted)?;
    let projected_snapshot = current_snapshot_bytes
        .checked_add(ledger_growth)
        .and_then(|value| value.checked_add(TERMINAL_SERIALIZATION_MARGIN_BYTES))
        .ok_or(DurableError::CapacityExhausted)?;
    // fstatvfs excludes the current snapshot but each publish writes a
    // complete new snapshot before rename frees the old one. Reserve the final
    // full snapshot, all prior ledger growth, and all immutable receipts.
    // `current + 2*N*ledger + N*receipt` is conservative for every
    // intermediate publish/receipt ordering.
    let required_free = current_snapshot_bytes
        .checked_add(
            ledger_growth
                .checked_mul(2)
                .ok_or(DurableError::CapacityExhausted)?,
        )
        .and_then(|value| value.checked_add(receipt_growth))
        .and_then(|value| value.checked_add(TERMINAL_FREE_SPACE_RESERVE_BYTES))
        .ok_or(DurableError::CapacityExhausted)?;
    Ok((projected_snapshot, required_free))
}

fn require_registration_free_bytes(available: u64, required: u64) -> Result<(), DurableError> {
    if available < required {
        Err(DurableError::CapacityExhausted)
    } else {
        Ok(())
    }
}

fn decode_terminal_response(record: &LedgerRecordV1) -> Result<Vec<u8>, DurableError> {
    BASE64_STANDARD
        .decode(
            record
                .terminal_response_base64
                .as_deref()
                .ok_or(DurableError::SnapshotInvalid)?
                .as_bytes(),
        )
        .map_err(|_| DurableError::SnapshotInvalid)
}

fn durable_record(record: &LedgerRecordV1) -> Result<DurableEffectRecordV1, DurableError> {
    Ok(DurableEffectRecordV1 {
        request: record.request.clone(),
        state: record.state.clone(),
        terminal_response: match record.state.phase {
            DirectEffectPhaseV1::Terminal => Some(decode_terminal_response(record)?),
            DirectEffectPhaseV1::NotDispatched
            | DirectEffectPhaseV1::Dispatched
            | DirectEffectPhaseV1::Indeterminate => None,
        },
    })
}

fn read_snapshot(directory: &File) -> Result<Option<LedgerEnvelopeV1>, DurableError> {
    let file = match openat_file(
        directory,
        SNAPSHOT_FILE,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_private_regular_fd(&file)?;
    if file.metadata()?.len() > MAX_SNAPSHOT_BYTES {
        return Err(DurableError::SnapshotInvalid);
    }
    let mut bytes = Vec::new();
    file.take(MAX_SNAPSHOT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(DurableError::SnapshotInvalid);
    }
    let envelope: LedgerEnvelopeV1 =
        serde_json::from_slice(&bytes).map_err(|_| DurableError::SnapshotInvalid)?;
    envelope.validate()?;
    if envelope.canonical_bytes()? != bytes {
        return Err(DurableError::SnapshotInvalid);
    }
    Ok(Some(envelope))
}

fn available_bytes(directory: &File) -> Result<u64, DurableError> {
    // SAFETY: value is valid writable storage and the retained directory fd
    // remains live for the duration of fstatvfs.
    let mut value = unsafe { std::mem::zeroed::<libc::statvfs>() };
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((value.f_bavail as u64).saturating_mul(value.f_frsize as u64))
}

fn validate_private_directory_metadata(metadata: &std::fs::Metadata) -> Result<(), DurableError> {
    if !metadata.file_type().is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(DurableError::SnapshotInvalid);
    }
    Ok(())
}

fn openat_file(
    directory: &File,
    name: &str,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<File> {
    let name =
        CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: name is NUL-terminated, directory remains live, and ownership of
    // the returned descriptor transfers immediately to File on success.
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: descriptor is fresh and uniquely owned.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn unlinkat_name(directory: &File, name: &str) -> Result<(), DurableError> {
    let name = CString::new(name).map_err(|_| DurableError::SnapshotInvalid)?;
    // SAFETY: name is a single fixed basename and directory is retained.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn renameat_name(directory: &File, source: &str, destination: &str) -> Result<(), DurableError> {
    let source = CString::new(source).map_err(|_| DurableError::SnapshotInvalid)?;
    let destination = CString::new(destination).map_err(|_| DurableError::SnapshotInvalid)?;
    // SAFETY: both names are fixed basenames resolved relative to the same
    // retained private directory fd.
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            destination.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn validate_private_regular_fd(file: &File) -> Result<(), DurableError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(DurableError::SnapshotInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_projection_covers_copy_publish_and_receipts_at_exact_boundary() {
        let current_snapshot_bytes = 12_345;
        let additional_records = 16;
        let (projected_snapshot, required_free) =
            registration_capacity_projection(current_snapshot_bytes, additional_records).unwrap();
        assert_eq!(
            projected_snapshot,
            current_snapshot_bytes
                + additional_records * MAX_DURABLE_LEDGER_RECORD_BYTES
                + TERMINAL_SERIALIZATION_MARGIN_BYTES
        );
        assert_eq!(
            required_free,
            current_snapshot_bytes
                + 2 * additional_records * MAX_DURABLE_LEDGER_RECORD_BYTES
                + additional_records * MAX_DURABLE_RECEIPT_RECORD_BYTES
                + TERMINAL_FREE_SPACE_RESERVE_BYTES
        );
        assert!(matches!(
            require_registration_free_bytes(required_free - 1, required_free),
            Err(DurableError::CapacityExhausted)
        ));
        require_registration_free_bytes(required_free, required_free).unwrap();
    }
}
