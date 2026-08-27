use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_os_types::direct_effect::{
    DirectEffectDurableStateV1, DirectEffectPhaseV1, DirectEffectRequestV1,
};

use crate::DurableEffectRecordV1;

const RECEIPT_SCHEMA: &str = "org.trillionnium.shell-exec.effect-receipt.v1";
const CLEANUP_POLICY: &str = "fixed-cgroup-empty-thawed-and-effect-temporary-scope-absent.v1";
const NOT_DISPATCHED_CLEANUP: &str = "effect-temporary-scope-absent-not-dispatched.v1";
const DISPATCHED_CLEANUP: &str = "cgroup-empty-thawed-and-effect-temporary-scope-absent.v1";
const LOCK_FILE: &str = ".effect-receipts.v1.lock";
const MAX_RECEIPT_BYTES: u64 = 512 * 1024;

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("receipt I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("effect receipt is invalid")]
    Invalid,
    #[error("effect receipt collides with different durable evidence")]
    Collision,
    #[error("another broker owns the receipt store")]
    WriterLocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecEffectReceiptBodyV1 {
    pub schema: String,
    pub request: DirectEffectRequestV1,
    pub durable_state: DirectEffectDurableStateV1,
    pub terminal_response_sha256: Option<String>,
    pub terminal_response_bytes: Option<u64>,
    pub effect_custody_sha256: String,
    pub cleanup_policy_sha256: String,
    pub cleanup_class: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecEffectReceiptV1 {
    pub body: ShellExecEffectReceiptBodyV1,
    pub body_sha256: String,
}

impl ShellExecEffectReceiptV1 {
    fn derive(record: &DurableEffectRecordV1) -> Result<Self, ReceiptError> {
        validate_final_record(record)?;
        let (terminal_response_sha256, terminal_response_bytes) = match &record.terminal_response {
            Some(bytes) => (
                Some(trillionnium_os_types::sha256_bytes(bytes)),
                Some(u64::try_from(bytes.len()).map_err(|_| ReceiptError::Invalid)?),
            ),
            None => (None, None),
        };
        let cleanup_class = if record.state.dispatch_occurred {
            DISPATCHED_CLEANUP
        } else {
            NOT_DISPATCHED_CLEANUP
        };
        let dispatch_binding = record
            .state
            .dispatch_binding_sha256
            .as_deref()
            .unwrap_or("not-dispatched");
        let body = ShellExecEffectReceiptBodyV1 {
            schema: RECEIPT_SCHEMA.to_string(),
            request: record.request.clone(),
            durable_state: record.state.clone(),
            terminal_response_sha256,
            terminal_response_bytes,
            effect_custody_sha256: domain_digest(
                b"trillionnium.shell-exec.effect-receipt-custody.v1",
                &[
                    record.request.request_sha256.as_bytes(),
                    record.request.kernel_launch_custody_sha256.as_bytes(),
                    record.request.backend_identity_sha256.as_bytes(),
                    dispatch_binding.as_bytes(),
                ],
            ),
            cleanup_policy_sha256: trillionnium_os_types::sha256_bytes(CLEANUP_POLICY.as_bytes()),
            cleanup_class: cleanup_class.to_string(),
        };
        let body_bytes = serde_json::to_vec(&body).map_err(|_| ReceiptError::Invalid)?;
        let value = Self {
            body,
            body_sha256: trillionnium_os_types::sha256_bytes(&body_bytes),
        };
        value.validate(record)?;
        Ok(value)
    }

    fn validate(&self, record: &DurableEffectRecordV1) -> Result<(), ReceiptError> {
        let expected = Self::derive_unchecked(record)?;
        if self != &expected {
            return Err(ReceiptError::Collision);
        }
        Ok(())
    }

    fn derive_unchecked(record: &DurableEffectRecordV1) -> Result<Self, ReceiptError> {
        validate_final_record(record)?;
        let (terminal_response_sha256, terminal_response_bytes) = match &record.terminal_response {
            Some(bytes) => (
                Some(trillionnium_os_types::sha256_bytes(bytes)),
                Some(u64::try_from(bytes.len()).map_err(|_| ReceiptError::Invalid)?),
            ),
            None => (None, None),
        };
        let dispatch_binding = record
            .state
            .dispatch_binding_sha256
            .as_deref()
            .unwrap_or("not-dispatched");
        let body = ShellExecEffectReceiptBodyV1 {
            schema: RECEIPT_SCHEMA.to_string(),
            request: record.request.clone(),
            durable_state: record.state.clone(),
            terminal_response_sha256,
            terminal_response_bytes,
            effect_custody_sha256: domain_digest(
                b"trillionnium.shell-exec.effect-receipt-custody.v1",
                &[
                    record.request.request_sha256.as_bytes(),
                    record.request.kernel_launch_custody_sha256.as_bytes(),
                    record.request.backend_identity_sha256.as_bytes(),
                    dispatch_binding.as_bytes(),
                ],
            ),
            cleanup_policy_sha256: trillionnium_os_types::sha256_bytes(CLEANUP_POLICY.as_bytes()),
            cleanup_class: if record.state.dispatch_occurred {
                DISPATCHED_CLEANUP.to_string()
            } else {
                NOT_DISPATCHED_CLEANUP.to_string()
            },
        };
        let body_bytes = serde_json::to_vec(&body).map_err(|_| ReceiptError::Invalid)?;
        Ok(Self {
            body,
            body_sha256: trillionnium_os_types::sha256_bytes(&body_bytes),
        })
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ReceiptError> {
        let bytes = serde_json::to_vec(self).map_err(|_| ReceiptError::Invalid)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(ReceiptError::Invalid);
        }
        Ok(bytes)
    }
}

fn validate_final_record(record: &DurableEffectRecordV1) -> Result<(), ReceiptError> {
    record
        .request
        .validate()
        .map_err(|_| ReceiptError::Invalid)?;
    record.state.validate().map_err(|_| ReceiptError::Invalid)?;
    if record.state.effect_id != record.request.effect_id
        || record.state.request_sha256 != record.request.request_sha256
    {
        return Err(ReceiptError::Invalid);
    }
    match record.state.phase {
        DirectEffectPhaseV1::Terminal if record.terminal_response.is_some() => Ok(()),
        DirectEffectPhaseV1::Indeterminate if record.terminal_response.is_none() => Ok(()),
        DirectEffectPhaseV1::NotDispatched
        | DirectEffectPhaseV1::Dispatched
        | DirectEffectPhaseV1::Terminal
        | DirectEffectPhaseV1::Indeterminate => Err(ReceiptError::Invalid),
    }
}

pub struct DurableShellExecReceiptStoreV1 {
    root: PathBuf,
    directory: File,
    root_device: u64,
    root_inode: u64,
    _lock: File,
}

impl DurableShellExecReceiptStoreV1 {
    pub fn open(root: &Path) -> Result<Self, ReceiptError> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(root)?;
        validate_private_directory(&directory.metadata()?)?;
        let root_device = directory.metadata()?.dev();
        let root_inode = directory.metadata()?.ino();
        let lock = openat_file(
            &directory,
            LOCK_FILE,
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )?;
        validate_private_regular(&lock)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(ReceiptError::WriterLocked);
        }
        Ok(Self {
            root: root.to_path_buf(),
            directory,
            root_device,
            root_inode,
            _lock: lock,
        })
    }

    #[cfg(feature = "android-product")]
    pub(crate) fn retained_root_device(&self) -> Result<u64, ReceiptError> {
        self.verify_directory_custody()?;
        Ok(self.root_device)
    }

    /// Publishes one immutable receipt. A matching receipt is an idempotent
    /// replay; any different pre-existing bytes fail closed.
    pub fn ensure(&self, record: &DurableEffectRecordV1) -> Result<Vec<u8>, ReceiptError> {
        self.verify_directory_custody()?;
        let receipt = ShellExecEffectReceiptV1::derive(record)?;
        let expected = receipt.canonical_bytes()?;
        let final_name = receipt_file_name(&record.request.effect_id);
        let temporary_name = format!(".{final_name}.tmp");
        self.remove_stale_temporary(&temporary_name)?;
        if let Some(observed) = read_optional_receipt(&self.directory, &final_name)? {
            validate_receipt_bytes(&observed, record)?;
            if observed != expected {
                return Err(ReceiptError::Collision);
            }
            self.verify_directory_custody()?;
            return Ok(observed);
        }

        let mut temporary = openat_file(
            &self.directory,
            &temporary_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )?;
        validate_private_regular(&temporary)?;
        temporary.write_all(&expected)?;
        temporary.sync_all()?;
        rename_noreplace(&self.directory, &temporary_name, &final_name)?;
        self.directory.sync_all()?;
        let observed =
            read_optional_receipt(&self.directory, &final_name)?.ok_or(ReceiptError::Invalid)?;
        validate_receipt_bytes(&observed, record)?;
        if observed != expected {
            return Err(ReceiptError::Collision);
        }
        self.verify_directory_custody()?;
        Ok(observed)
    }

    /// Verifies that every final ledger record has exactly one receipt and
    /// that the directory contains no unbound receipt or stale temporary.
    pub fn verify_catalog(&self, records: &[DurableEffectRecordV1]) -> Result<(), ReceiptError> {
        self.verify_directory_custody()?;
        let mut expected_names = BTreeSet::new();
        for record in records {
            if matches!(
                record.state.phase,
                DirectEffectPhaseV1::Terminal | DirectEffectPhaseV1::Indeterminate
            ) {
                let name = receipt_file_name(&record.request.effect_id);
                if !expected_names.insert(name.clone()) {
                    return Err(ReceiptError::Invalid);
                }
                let bytes =
                    read_optional_receipt(&self.directory, &name)?.ok_or(ReceiptError::Invalid)?;
                validate_receipt_bytes(&bytes, record)?;
            }
        }
        for name in retained_directory_entry_names(&self.directory)? {
            if name != LOCK_FILE && !expected_names.contains(&name) {
                return Err(ReceiptError::Invalid);
            }
        }
        self.verify_directory_custody()
    }

    fn remove_stale_temporary(&self, name: &str) -> Result<(), ReceiptError> {
        match openat_file(
            &self.directory,
            name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        ) {
            Ok(file) => {
                validate_private_regular(&file)?;
                unlinkat_name(&self.directory, name)?;
                self.directory.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn verify_directory_custody(&self) -> Result<(), ReceiptError> {
        let retained = self.directory.metadata()?;
        validate_private_directory(&retained)?;
        if retained.dev() != self.root_device || retained.ino() != self.root_inode {
            return Err(ReceiptError::Invalid);
        }
        let reopened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.root)?;
        let observed = reopened.metadata()?;
        validate_private_directory(&observed)?;
        if observed.dev() != self.root_device || observed.ino() != self.root_inode {
            return Err(ReceiptError::Invalid);
        }
        Ok(())
    }
}

fn retained_directory_entry_names(directory: &File) -> Result<Vec<String>, ReceiptError> {
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(error.into());
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error().is_some_and(|value| value != 0) {
                return Err(error.into());
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_str()
            .map_err(|_| ReceiptError::Invalid)?;
        if !matches!(name, "." | "..") {
            names.push(name.to_string());
        }
    }
    names.sort();
    Ok(names)
}

fn validate_receipt_bytes(
    bytes: &[u8],
    record: &DurableEffectRecordV1,
) -> Result<(), ReceiptError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(ReceiptError::Invalid);
    }
    let receipt: ShellExecEffectReceiptV1 =
        serde_json::from_slice(bytes).map_err(|_| ReceiptError::Invalid)?;
    receipt.validate(record)?;
    if receipt.canonical_bytes()? != bytes {
        return Err(ReceiptError::Invalid);
    }
    Ok(())
}

fn receipt_file_name(effect_id: &str) -> String {
    format!(
        "receipt-{}.v1.json",
        trillionnium_os_types::sha256_bytes(effect_id.as_bytes())
    )
}

fn read_optional_receipt(directory: &File, name: &str) -> Result<Option<Vec<u8>>, ReceiptError> {
    let file = match openat_file(
        directory,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_private_regular(&file)?;
    if file.metadata()?.len() > MAX_RECEIPT_BYTES {
        return Err(ReceiptError::Invalid);
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECEIPT_BYTES + 1).read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn rename_noreplace(directory: &File, source: &str, destination: &str) -> Result<(), ReceiptError> {
    let source = CString::new(source).map_err(|_| ReceiptError::Invalid)?;
    let destination = CString::new(destination).map_err(|_| ReceiptError::Invalid)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EEXIST) {
            return Err(ReceiptError::Collision);
        }
        return Err(error.into());
    }
    Ok(())
}

fn openat_file(
    directory: &File,
    name: &str,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<File> {
    if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    let name =
        CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn unlinkat_name(directory: &File, name: &str) -> Result<(), ReceiptError> {
    let name = CString::new(name).map_err(|_| ReceiptError::Invalid)?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn validate_private_directory(metadata: &std::fs::Metadata) -> Result<(), ReceiptError> {
    if !metadata.file_type().is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(ReceiptError::Invalid);
    }
    Ok(())
}

fn validate_private_regular(file: &File) -> Result<(), ReceiptError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(ReceiptError::Invalid);
    }
    Ok(())
}

fn domain_digest(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    format!("{:x}", hasher.finalize())
}
