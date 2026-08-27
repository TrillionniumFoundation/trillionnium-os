//! Host-runnable durable replay ledger for the standalone broker foundation.
//!
//! This module supplies storage semantics only. It does not construct product
//! authority, execute getprop, expose ADB, or install an Android listener.

#![allow(dead_code)] // The product workspace deliberately cannot import this foundation.

use std::collections::BTreeMap;
use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::broker::{
    BrokerError, PreparedReplayRecordV1, ReplayLedgerV1, ReplayRecordV1, TerminalReplayRecordV1,
};
use crate::protocol::sha256_bytes;

const DURABLE_LEDGER_SCHEMA: &str = "trillionnium.typed-broker-durable-ledger.v1";
const LEDGER_FILE_NAME: &str = "replay-ledger.v1.json";
const LOCK_FILE_NAME: &str = ".replay-ledger.v1.lock";
const TEMP_FILE_NAME: &str = ".replay-ledger.v1.json.tmp";
const MAX_LEDGER_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableLedgerBodyV1 {
    schema: String,
    generation: u64,
    records: BTreeMap<String, ReplayRecordV1>,
}

impl DurableLedgerBodyV1 {
    fn empty() -> Self {
        Self {
            schema: DURABLE_LEDGER_SCHEMA.to_string(),
            generation: 0,
            records: BTreeMap::new(),
        }
    }

    fn validate(&self) -> Result<(), DurableLedgerError> {
        if self.schema != DURABLE_LEDGER_SCHEMA {
            return Err(DurableLedgerError::SnapshotInvalid);
        }
        if self.generation == 0 && !self.records.is_empty() {
            return Err(DurableLedgerError::SnapshotInvalid);
        }
        for (identity, record) in &self.records {
            record
                .validate()
                .map_err(|_| DurableLedgerError::SnapshotInvalid)?;
            if identity != &record.prepared().request.operation_identity_sha256 {
                return Err(DurableLedgerError::SnapshotInvalid);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableLedgerEnvelopeV1 {
    body: DurableLedgerBodyV1,
    body_sha256: String,
}

impl DurableLedgerEnvelopeV1 {
    fn derive(body: DurableLedgerBodyV1) -> Result<Self, DurableLedgerError> {
        body.validate()?;
        let body_bytes =
            serde_json::to_vec(&body).map_err(|_| DurableLedgerError::SnapshotInvalid)?;
        Ok(Self {
            body,
            body_sha256: sha256_bytes(&body_bytes),
        })
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, DurableLedgerError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| DurableLedgerError::SnapshotInvalid)
    }

    fn validate(&self) -> Result<(), DurableLedgerError> {
        self.body.validate()?;
        let body_bytes =
            serde_json::to_vec(&self.body).map_err(|_| DurableLedgerError::SnapshotInvalid)?;
        if self.body_sha256 != sha256_bytes(&body_bytes) {
            return Err(DurableLedgerError::SnapshotInvalid);
        }
        Ok(())
    }

    fn parse_canonical(bytes: &[u8]) -> Result<Self, DurableLedgerError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| DurableLedgerError::SnapshotInvalid)?;
        value.validate()?;
        if value.canonical_bytes()? != bytes {
            return Err(DurableLedgerError::SnapshotInvalid);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CrashPointV1 {
    TempWriteBeforeFileFsync,
    TempFsyncBeforeRename,
    RenameBeforeDirectoryFsync,
    DirectoryFsyncBeforeReadback,
}

#[derive(Debug, Error)]
pub(super) enum DurableLedgerError {
    #[error("durable ledger filesystem operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("durable ledger path, mode, link count, owner, or bytes are invalid")]
    SnapshotInvalid,
    #[error("another durable ledger writer already owns the lock")]
    WriterAlreadyLocked,
    #[error("durable ledger compare-and-swap input no longer matches disk")]
    CompareAndSwapConflict,
    #[error("durable ledger operation identity conflicts with existing state")]
    OperationIdentityConflict,
    #[error("simulated crash at {0:?}")]
    SimulatedCrash(CrashPointV1),
}

pub(super) struct DurableReplayLedgerV1 {
    directory: File,
    _writer_lock: File,
    body: DurableLedgerBodyV1,
    published: bool,
    crash_once: Option<CrashPointV1>,
}

impl DurableReplayLedgerV1 {
    pub(super) fn open(root: &Path) -> Result<Self, DurableLedgerError> {
        let directory = open_directory_nofollow(root)?;
        let writer_lock = open_or_create_lock_file(&directory)?;
        lock_exclusive_nonblocking(&writer_lock)?;
        cleanup_unpublished_temp(&directory)?;
        let on_disk = read_snapshot(&directory)?;
        let (body, published) = match on_disk {
            Some(envelope) => (envelope.body, true),
            None => (DurableLedgerBodyV1::empty(), false),
        };
        body.validate()?;
        Ok(Self {
            directory,
            _writer_lock: writer_lock,
            body,
            published,
            crash_once: None,
        })
    }

    #[cfg(test)]
    fn crash_once_at(&mut self, point: CrashPointV1) {
        self.crash_once = Some(point);
    }

    fn maybe_crash(&mut self, point: CrashPointV1) -> Result<(), DurableLedgerError> {
        if self.crash_once == Some(point) {
            self.crash_once = None;
            return Err(DurableLedgerError::SimulatedCrash(point));
        }
        Ok(())
    }

    fn expected_disk_body(&self) -> Option<&DurableLedgerBodyV1> {
        self.published.then_some(&self.body)
    }

    fn publish(&mut self, next: DurableLedgerBodyV1) -> Result<(), DurableLedgerError> {
        next.validate()?;
        if read_snapshot(&self.directory)?
            .as_ref()
            .map(|value| &value.body)
            != self.expected_disk_body()
        {
            return Err(DurableLedgerError::CompareAndSwapConflict);
        }
        let envelope = DurableLedgerEnvelopeV1::derive(next.clone())?;
        let bytes = envelope.canonical_bytes()?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(DurableLedgerError::SnapshotInvalid);
        }

        let mut temporary = create_private_temp(&self.directory)?;
        temporary.write_all(&bytes)?;
        temporary.flush()?;
        self.maybe_crash(CrashPointV1::TempWriteBeforeFileFsync)?;
        temporary.sync_all()?;
        self.maybe_crash(CrashPointV1::TempFsyncBeforeRename)?;

        if read_snapshot(&self.directory)?
            .as_ref()
            .map(|value| &value.body)
            != self.expected_disk_body()
        {
            return Err(DurableLedgerError::CompareAndSwapConflict);
        }
        verify_path_matches_open_file(&self.directory, TEMP_FILE_NAME, &temporary)?;
        rename_at(&self.directory, TEMP_FILE_NAME, LEDGER_FILE_NAME)?;
        self.maybe_crash(CrashPointV1::RenameBeforeDirectoryFsync)?;
        self.directory.sync_all()?;
        self.maybe_crash(CrashPointV1::DirectoryFsyncBeforeReadback)?;

        let readback =
            read_snapshot(&self.directory)?.ok_or(DurableLedgerError::SnapshotInvalid)?;
        if readback != envelope {
            return Err(DurableLedgerError::SnapshotInvalid);
        }
        self.body = next;
        self.published = true;
        Ok(())
    }

    fn append_prepared(
        &mut self,
        prepared: PreparedReplayRecordV1,
    ) -> Result<(), DurableLedgerError> {
        prepared
            .validate()
            .map_err(|_| DurableLedgerError::SnapshotInvalid)?;
        let key = prepared.request.operation_identity_sha256.clone();
        if self.body.records.contains_key(&key) {
            return Err(DurableLedgerError::OperationIdentityConflict);
        }
        let mut next = self.body.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(DurableLedgerError::SnapshotInvalid)?;
        next.records.insert(
            key,
            ReplayRecordV1::Prepared {
                record: Box::new(prepared),
            },
        );
        self.publish(next)
    }

    fn compare_and_swap_terminal(
        &mut self,
        terminal: TerminalReplayRecordV1,
    ) -> Result<(), DurableLedgerError> {
        terminal
            .validate()
            .map_err(|_| DurableLedgerError::SnapshotInvalid)?;
        let key = terminal.prepared.request.operation_identity_sha256.clone();
        match self.body.records.get(&key) {
            Some(ReplayRecordV1::Prepared { record }) if record.as_ref() == &terminal.prepared => {}
            _ => return Err(DurableLedgerError::OperationIdentityConflict),
        }
        let mut next = self.body.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or(DurableLedgerError::SnapshotInvalid)?;
        next.records.insert(
            key,
            ReplayRecordV1::Terminal {
                record: Box::new(terminal),
            },
        );
        self.publish(next)
    }
}

impl ReplayLedgerV1 for DurableReplayLedgerV1 {
    fn lookup(&self, operation_identity_sha256: &str) -> Option<ReplayRecordV1> {
        self.body.records.get(operation_identity_sha256).cloned()
    }

    fn prepare(&mut self, prepared: PreparedReplayRecordV1) -> Result<(), BrokerError> {
        match self.append_prepared(prepared) {
            Ok(()) => Ok(()),
            Err(DurableLedgerError::OperationIdentityConflict) => {
                Err(BrokerError::OperationIdentityConflict)
            }
            Err(_) => Err(BrokerError::PreparePersistenceFailedHold),
        }
    }

    fn commit(&mut self, terminal: TerminalReplayRecordV1) -> Result<(), BrokerError> {
        match self.compare_and_swap_terminal(terminal) {
            Ok(()) => Ok(()),
            Err(DurableLedgerError::OperationIdentityConflict) => {
                Err(BrokerError::OperationIdentityConflict)
            }
            Err(_) => Err(BrokerError::TerminalPersistenceFailedHold),
        }
    }
}

fn c_string(value: &OsStr) -> Result<CString, DurableLedgerError> {
    CString::new(value.as_bytes()).map_err(|_| DurableLedgerError::SnapshotInvalid)
}

fn open_at(
    directory: &File,
    name: &OsStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> Result<File, DurableLedgerError> {
    let name = c_string(name)?;
    // SAFETY: directory is an owned open directory fd; name is NUL-terminated;
    // openat returns a new fd whose ownership is transferred exactly once.
    let raw = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if raw < 0 {
        return Err(DurableLedgerError::Io(io::Error::last_os_error()));
    }
    // SAFETY: raw is a newly returned, nonnegative fd and has no other owner.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    Ok(File::from(owned))
}

fn open_directory_nofollow(path: &Path) -> Result<File, DurableLedgerError> {
    if !path.is_absolute() {
        return Err(DurableLedgerError::SnapshotInvalid);
    }
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = open_at(
                    &current,
                    name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    0,
                )?;
            }
            _ => return Err(DurableLedgerError::SnapshotInvalid),
        }
    }
    Ok(current)
}

fn private_regular_file(metadata: &Metadata) -> bool {
    metadata.file_type().is_file()
        && metadata.nlink() == 1
        && metadata.mode() & 0o7777 == 0o600
        // SAFETY: geteuid is side-effect free and has no preconditions.
        && metadata.uid() == unsafe { libc::geteuid() }
}

fn validate_private_file(file: &File) -> Result<Metadata, DurableLedgerError> {
    let metadata = file.metadata()?;
    if !private_regular_file(&metadata) {
        return Err(DurableLedgerError::SnapshotInvalid);
    }
    Ok(metadata)
}

fn open_or_create_lock_file(directory: &File) -> Result<File, DurableLedgerError> {
    let exclusive = open_at(
        directory,
        OsStr::new(LOCK_FILE_NAME),
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    );
    let file = match exclusive {
        Ok(file) => {
            // SAFETY: file is an owned writable descriptor.
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                return Err(DurableLedgerError::Io(io::Error::last_os_error()));
            }
            file.sync_all()?;
            directory.sync_all()?;
            file
        }
        Err(DurableLedgerError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
            open_at(
                directory,
                OsStr::new(LOCK_FILE_NAME),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            )?
        }
        Err(error) => return Err(error),
    };
    validate_private_file(&file)?;
    Ok(file)
}

fn lock_exclusive_nonblocking(file: &File) -> Result<(), DurableLedgerError> {
    // SAFETY: flock only observes/updates the lock associated with this valid fd.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Err(DurableLedgerError::WriterAlreadyLocked)
    } else {
        Err(DurableLedgerError::Io(error))
    }
}

fn open_existing_private(directory: &File, name: &str) -> Result<Option<File>, DurableLedgerError> {
    match open_at(
        directory,
        OsStr::new(name),
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    ) {
        Ok(file) => {
            validate_private_file(&file)?;
            Ok(Some(file))
        }
        Err(DurableLedgerError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_snapshot(directory: &File) -> Result<Option<DurableLedgerEnvelopeV1>, DurableLedgerError> {
    let Some(mut file) = open_existing_private(directory, LEDGER_FILE_NAME)? else {
        return Ok(None);
    };
    let metadata = file.metadata()?;
    if metadata.len() == 0 || metadata.len() > MAX_LEDGER_BYTES {
        return Err(DurableLedgerError::SnapshotInvalid);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_LEDGER_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_LEDGER_BYTES {
        return Err(DurableLedgerError::SnapshotInvalid);
    }
    DurableLedgerEnvelopeV1::parse_canonical(&bytes).map(Some)
}

fn cleanup_unpublished_temp(directory: &File) -> Result<(), DurableLedgerError> {
    let Some(file) = open_existing_private(directory, TEMP_FILE_NAME)? else {
        return Ok(());
    };
    validate_private_file(&file)?;
    drop(file);
    unlink_at(directory, TEMP_FILE_NAME)?;
    directory.sync_all()?;
    Ok(())
}

fn create_private_temp(directory: &File) -> Result<File, DurableLedgerError> {
    let file = open_at(
        directory,
        OsStr::new(TEMP_FILE_NAME),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    )?;
    // SAFETY: file is an owned writable descriptor.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(DurableLedgerError::Io(io::Error::last_os_error()));
    }
    validate_private_file(&file)?;
    Ok(file)
}

fn verify_path_matches_open_file(
    directory: &File,
    name: &str,
    open_file: &File,
) -> Result<(), DurableLedgerError> {
    let path_file =
        open_existing_private(directory, name)?.ok_or(DurableLedgerError::SnapshotInvalid)?;
    let expected = validate_private_file(open_file)?;
    let observed = validate_private_file(&path_file)?;
    if (expected.dev(), expected.ino()) != (observed.dev(), observed.ino()) {
        return Err(DurableLedgerError::CompareAndSwapConflict);
    }
    Ok(())
}

fn rename_at(directory: &File, source: &str, destination: &str) -> Result<(), DurableLedgerError> {
    let source = CString::new(source).map_err(|_| DurableLedgerError::SnapshotInvalid)?;
    let destination = CString::new(destination).map_err(|_| DurableLedgerError::SnapshotInvalid)?;
    // SAFETY: both names are fixed NUL-terminated relative names and the same
    // owned directory fd is valid for the duration of the call.
    let result = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            destination.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(DurableLedgerError::Io(io::Error::last_os_error()))
    }
}

fn unlink_at(directory: &File, name: &str) -> Result<(), DurableLedgerError> {
    let name = CString::new(name).map_err(|_| DurableLedgerError::SnapshotInvalid)?;
    // SAFETY: name is a fixed NUL-terminated relative filename and directory is valid.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(DurableLedgerError::Io(io::Error::last_os_error()))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::protocol::{
        BINDING_IDENTITY_SCHEMA, BrokerBindingIdentityV1, CODEX, TypedBrokerOperationV1,
        TypedBrokerOutcomeV1, TypedBrokerRequestV1, TypedBrokerResponseV1,
    };

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        path: std::path::PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "trillionnium-typed-broker-ledger-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("test directory mode");
            Self { path }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn digest(seed: &str) -> String {
        sha256_bytes(seed.as_bytes())
    }

    fn request(ordinal: u64) -> TypedBrokerRequestV1 {
        let binding = BrokerBindingIdentityV1 {
            schema: BINDING_IDENTITY_SCHEMA.to_string(),
            provider_id: CODEX.provider_id.to_string(),
            agent_id: CODEX.agent_id.to_string(),
            direct_binding_sha256: digest("binding"),
            invocation_id: format!("inv:{}", digest("invocation")),
            delivery_provider_attempt_id: format!("attempt:{}", digest("attempt")),
            agent_executable_sha256: digest("agent-executable"),
        };
        TypedBrokerRequestV1::derive(
            &binding,
            ordinal,
            TypedBrokerOperationV1::ExecInspectBuildFingerprintUserdebugV1,
            15_000,
        )
        .expect("request")
    }

    fn prepared(request: &TypedBrokerRequestV1) -> PreparedReplayRecordV1 {
        PreparedReplayRecordV1::derive(request).expect("prepared")
    }

    fn terminal(request: &TypedBrokerRequestV1) -> TerminalReplayRecordV1 {
        let prepared = prepared(request);
        let response = TypedBrokerResponseV1::terminal(
            request,
            TypedBrokerOutcomeV1::Completed,
            Some(0),
            "fixture/fingerprint\n".to_string(),
            String::new(),
            3,
        )
        .expect("response");
        TerminalReplayRecordV1::derive(prepared, response).expect("terminal")
    }

    #[test]
    fn append_and_terminal_cas_survive_restart_with_exact_response() {
        let directory = TestDirectory::new();
        let request = request(1);
        let expected_terminal = terminal(&request);
        {
            let mut ledger = DurableReplayLedgerV1::open(&directory.path).expect("open");
            ledger.prepare(prepared(&request)).expect("prepare");
            ledger
                .commit(expected_terminal.clone())
                .expect("commit terminal");
        }
        let ledger = DurableReplayLedgerV1::open(&directory.path).expect("reopen");
        assert_eq!(
            ledger.lookup(&request.operation_identity_sha256),
            Some(ReplayRecordV1::Terminal {
                record: Box::new(expected_terminal)
            })
        );
        let metadata = fs::metadata(directory.path.join(LEDGER_FILE_NAME)).expect("metadata");
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }

    #[test]
    fn response_loss_reopens_and_replays_terminal_without_backend_authority() {
        let directory = TestDirectory::new();
        let request = request(2);
        let terminal = terminal(&request);
        let expected_wire = terminal.response_wire.clone();
        {
            let mut ledger = DurableReplayLedgerV1::open(&directory.path).unwrap();
            ledger.prepare(prepared(&request)).unwrap();
            ledger.commit(terminal).unwrap();
            // Simulate losing the response after the terminal fsync/readback.
        }
        let ledger = DurableReplayLedgerV1::open(&directory.path).unwrap();
        match ledger.lookup(&request.operation_identity_sha256).unwrap() {
            ReplayRecordV1::Terminal { record } => {
                assert_eq!(record.response_wire, expected_wire);
                record.validate().unwrap();
            }
            ReplayRecordV1::Prepared { .. } => panic!("terminal response was lost"),
        }
    }

    #[test]
    fn duplicate_and_conflicting_transitions_fail_closed() {
        let directory = TestDirectory::new();
        let request = request(3);
        let mut ledger = DurableReplayLedgerV1::open(&directory.path).unwrap();
        ledger.prepare(prepared(&request)).unwrap();
        assert!(matches!(
            ledger.prepare(prepared(&request)),
            Err(BrokerError::OperationIdentityConflict)
        ));
        ledger.commit(terminal(&request)).unwrap();
        assert!(matches!(
            ledger.commit(terminal(&request)),
            Err(BrokerError::OperationIdentityConflict)
        ));
    }

    #[test]
    fn prepared_record_survives_restart_as_indeterminate_not_retryable() {
        let directory = TestDirectory::new();
        let request = request(4);
        {
            let mut ledger = DurableReplayLedgerV1::open(&directory.path).unwrap();
            ledger.prepare(prepared(&request)).unwrap();
        }
        let ledger = DurableReplayLedgerV1::open(&directory.path).unwrap();
        assert!(matches!(
            ledger.lookup(&request.operation_identity_sha256),
            Some(ReplayRecordV1::Prepared { .. })
        ));
    }

    #[test]
    fn every_prepare_crash_point_recovers_only_none_or_prepared() {
        for (index, point) in [
            CrashPointV1::TempWriteBeforeFileFsync,
            CrashPointV1::TempFsyncBeforeRename,
            CrashPointV1::RenameBeforeDirectoryFsync,
            CrashPointV1::DirectoryFsyncBeforeReadback,
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new();
            let request = request(100 + index as u64);
            {
                let mut ledger = DurableReplayLedgerV1::open(&directory.path).unwrap();
                ledger.crash_once_at(point);
                assert!(matches!(
                    ledger.prepare(prepared(&request)),
                    Err(BrokerError::PreparePersistenceFailedHold)
                ));
            }
            let ledger = DurableReplayLedgerV1::open(&directory.path).unwrap();
            let recovered = ledger.lookup(&request.operation_identity_sha256);
            match point {
                CrashPointV1::TempWriteBeforeFileFsync | CrashPointV1::TempFsyncBeforeRename => {
                    assert!(recovered.is_none())
                }
                CrashPointV1::RenameBeforeDirectoryFsync
                | CrashPointV1::DirectoryFsyncBeforeReadback => {
                    assert!(matches!(recovered, Some(ReplayRecordV1::Prepared { .. })))
                }
            }
        }
    }

    #[test]
    fn every_terminal_crash_point_recovers_only_prepared_or_terminal() {
        for (index, point) in [
            CrashPointV1::TempWriteBeforeFileFsync,
            CrashPointV1::TempFsyncBeforeRename,
            CrashPointV1::RenameBeforeDirectoryFsync,
            CrashPointV1::DirectoryFsyncBeforeReadback,
        ]
        .into_iter()
        .enumerate()
        {
            let directory = TestDirectory::new();
            let request = request(200 + index as u64);
            {
                let mut ledger = DurableReplayLedgerV1::open(&directory.path).unwrap();
                ledger.prepare(prepared(&request)).unwrap();
                ledger.crash_once_at(point);
                assert!(matches!(
                    ledger.commit(terminal(&request)),
                    Err(BrokerError::TerminalPersistenceFailedHold)
                ));
            }
            let ledger = DurableReplayLedgerV1::open(&directory.path).unwrap();
            let recovered = ledger.lookup(&request.operation_identity_sha256);
            match point {
                CrashPointV1::TempWriteBeforeFileFsync | CrashPointV1::TempFsyncBeforeRename => {
                    assert!(matches!(recovered, Some(ReplayRecordV1::Prepared { .. })))
                }
                CrashPointV1::RenameBeforeDirectoryFsync
                | CrashPointV1::DirectoryFsyncBeforeReadback => {
                    assert!(matches!(recovered, Some(ReplayRecordV1::Terminal { .. })))
                }
            }
        }
    }

    #[test]
    fn symlinked_root_ledger_or_temp_is_rejected_without_following() {
        let outer = TestDirectory::new();
        let real = outer.path.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let linked = outer.path.join("linked");
        symlink(&real, &linked).unwrap();
        assert!(DurableReplayLedgerV1::open(&linked).is_err());

        let victim = outer.path.join("victim");
        fs::write(&victim, b"sentinel").unwrap();
        symlink(&victim, real.join(LEDGER_FILE_NAME)).unwrap();
        assert!(DurableReplayLedgerV1::open(&real).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"sentinel");
        fs::remove_file(real.join(LEDGER_FILE_NAME)).unwrap();

        symlink(&victim, real.join(TEMP_FILE_NAME)).unwrap();
        assert!(DurableReplayLedgerV1::open(&real).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"sentinel");
    }

    #[test]
    fn hardlinked_or_wrong_mode_ledger_is_rejected() {
        let directory = TestDirectory::new();
        let request = request(5);
        {
            let mut ledger = DurableReplayLedgerV1::open(&directory.path).unwrap();
            ledger.prepare(prepared(&request)).unwrap();
        }
        let ledger_path = directory.path.join(LEDGER_FILE_NAME);
        let alias = directory.path.join("ledger-alias");
        fs::hard_link(&ledger_path, &alias).unwrap();
        assert!(DurableReplayLedgerV1::open(&directory.path).is_err());
        fs::remove_file(alias).unwrap();
        fs::set_permissions(&ledger_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(DurableReplayLedgerV1::open(&directory.path).is_err());
    }

    #[test]
    fn concurrent_writer_is_rejected() {
        let directory = TestDirectory::new();
        let first = DurableReplayLedgerV1::open(&directory.path).unwrap();
        assert!(matches!(
            DurableReplayLedgerV1::open(&directory.path),
            Err(DurableLedgerError::WriterAlreadyLocked)
        ));
        drop(first);
        DurableReplayLedgerV1::open(&directory.path).expect("lock released");
    }

    #[test]
    fn noncanonical_or_corrupt_snapshot_is_rejected() {
        let directory = TestDirectory::new();
        let ledger_path = directory.path.join(LEDGER_FILE_NAME);
        fs::write(&ledger_path, b"{\"body\":{},\"body_sha256\":\"bad\"}").unwrap();
        fs::set_permissions(&ledger_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(DurableReplayLedgerV1::open(&directory.path).is_err());
    }
}
