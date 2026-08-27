//! Fixed OS-owned activation gate shared by the production System API and
//! Root-Linux shell MCP adapters.
//!
//! Codex may know adapter argv before its final runtime image has been
//! admitted. Adapter startup therefore cannot treat argv, environment, or
//! provider-authored input as authority. The daemon removes the fixed record
//! before every supervised spawn and publishes a new, invocation-bound record
//! only after same-PID post-exec observation succeeds.

use std::ffi::{CStr, CString};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use serde::{Deserialize, Serialize};
use trillionnium_os_types::is_nonzero_lower_sha256;

use crate::{DirectToolError, Result};

pub const PRODUCT_POST_EXEC_ADMISSION_DIRECTORY: &str =
    "/var/lib/trillionnium/agent-tools/post-exec";
pub const PRODUCT_POST_EXEC_ADMISSION_FILE_NAME: &CStr = c"codex-adapters-active.v1";
pub const PRODUCT_POST_EXEC_ADMISSION_PATH: &str =
    "/var/lib/trillionnium/agent-tools/post-exec/codex-adapters-active.v1";
pub const POST_EXEC_ADMISSION_SCHEMA: &str =
    "org.trillionnium.codex-adapter-post-exec-admission.v2";
const MAX_RECORD_BYTES: u64 = 1024;
const PRODUCT_DIRECTORY_COMPONENTS: [&CStr; 5] = [
    c"var",
    c"lib",
    c"trillionnium",
    c"agent-tools",
    c"post-exec",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductPostExecAdmissionRecord {
    pub schema: String,
    pub runtime_lifecycle_binding_sha256: String,
    pub final_runtime_executable_sha256: String,
    pub provider_pid: u32,
    pub provider_start_time_ticks: u64,
    pub provider_executable_device: u64,
    pub provider_executable_inode: u64,
    pub provider_uid: u32,
    pub provider_gid: u32,
}

impl ProductPostExecAdmissionRecord {
    pub fn validate_shape(&self) -> bool {
        self.schema == POST_EXEC_ADMISSION_SCHEMA
            && is_nonzero_lower_sha256(&self.runtime_lifecycle_binding_sha256)
            && is_nonzero_lower_sha256(&self.final_runtime_executable_sha256)
            && self.provider_pid > 1
            && self.provider_start_time_ticks > 0
            && self.provider_executable_device > 0
            && self.provider_executable_inode > 0
            && self.provider_uid > 0
            && self.provider_gid > 0
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if !self.validate_shape() {
            return Err(gate_denied());
        }
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(gate_denied());
        }
        Ok(bytes)
    }
}

/// Require the exact fixed root-owned activation record before an adapter can
/// open transport, journal, or backend state. The record is bound to this
/// adapter's immediate provider parent PID/starttime and final executable
/// inode, so a stale record from another provider generation is inert.
pub fn require_product_post_exec_admission() -> Result<ProductPostExecAdmissionRecord> {
    let provider_uid = unsafe { libc::getuid() };
    let provider_gid = unsafe { libc::getgid() };
    if provider_uid == 0
        || provider_gid == 0
        || unsafe { libc::geteuid() } != provider_uid
        || unsafe { libc::getegid() } != provider_gid
    {
        return Err(gate_denied());
    }
    let parent = pinned_parent_pid()?;
    let directory = open_product_directory(provider_gid)?;
    require_admission_from_directory(&directory, 0, provider_uid, provider_gid, parent)
}

fn require_admission_from_directory(
    directory: &File,
    os_owner_uid: u32,
    provider_uid: u32,
    provider_gid: u32,
    parent: libc::pid_t,
) -> Result<ProductPostExecAdmissionRecord> {
    validate_activation_directory(directory, os_owner_uid, provider_gid)?;

    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            PRODUCT_POST_EXEC_ADMISSION_FILE_NAME.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(gate_denied());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let before = file.metadata().map_err(|_| gate_denied())?;
    if !closed_record_metadata(&before, os_owner_uid, provider_gid) {
        return Err(gate_denied());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| gate_denied())?;
    let after = file.metadata().map_err(|_| gate_denied())?;
    if bytes.len() as u64 != before.len() || !same_metadata(&before, &after) {
        return Err(gate_denied());
    }
    let record: ProductPostExecAdmissionRecord =
        serde_json::from_slice(&bytes).map_err(|_| gate_denied())?;
    if !record.validate_shape() || record.canonical_bytes()? != bytes {
        return Err(gate_denied());
    }
    if record.provider_uid != provider_uid || record.provider_gid != provider_gid {
        return Err(gate_denied());
    }
    require_current_parent(&record, parent)?;
    Ok(record)
}

fn pinned_parent_pid() -> Result<libc::pid_t> {
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return Err(gate_denied());
    }
    let mut signal = 0;
    if unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut signal, 0, 0, 0) } != 0
        || signal != libc::SIGKILL
        || unsafe { libc::getppid() } != parent
    {
        return Err(gate_denied());
    }
    Ok(parent)
}

fn open_product_directory(provider_gid: u32) -> Result<File> {
    let root = CString::new("/").map_err(|_| gate_denied())?;
    let descriptor = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(gate_denied());
    }
    let mut directory = unsafe { File::from_raw_fd(descriptor) };
    validate_guardian_directory(&directory)?;
    for (index, component) in PRODUCT_DIRECTORY_COMPONENTS.iter().enumerate() {
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(gate_denied());
        }
        let next = unsafe { File::from_raw_fd(descriptor) };
        if index + 1 == PRODUCT_DIRECTORY_COMPONENTS.len() {
            validate_activation_directory(&next, 0, provider_gid)?;
        } else {
            validate_guardian_directory(&next)?;
        }
        directory = next;
    }
    Ok(directory)
}

fn validate_guardian_directory(directory: &File) -> Result<()> {
    let metadata = directory.metadata().map_err(|_| gate_denied())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o0022 != 0 {
        return Err(gate_denied());
    }
    Ok(())
}

fn validate_activation_directory(
    directory: &File,
    os_owner_uid: u32,
    provider_gid: u32,
) -> Result<()> {
    let metadata = directory.metadata().map_err(|_| gate_denied())?;
    if !metadata.is_dir()
        || metadata.uid() != os_owner_uid
        || metadata.gid() != provider_gid
        || metadata.permissions().mode() & 0o7777 != 0o710
    {
        return Err(gate_denied());
    }
    Ok(())
}

fn closed_record_metadata(metadata: &Metadata, os_owner_uid: u32, provider_gid: u32) -> bool {
    metadata.is_file()
        && metadata.uid() == os_owner_uid
        && metadata.gid() == provider_gid
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == 0o440
        && metadata.len() > 0
        && metadata.len() <= MAX_RECORD_BYTES
}

fn same_metadata(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservedParentIdentity {
    start_time_ticks: u64,
    real_uid: u32,
    real_gid: u32,
    executable_device: u64,
    executable_inode: u64,
}

fn require_current_parent(
    record: &ProductPostExecAdmissionRecord,
    parent: libc::pid_t,
) -> Result<()> {
    if parent <= 1
        || unsafe { libc::getppid() } != parent
        || u32::try_from(parent).ok() != Some(record.provider_pid)
    {
        return Err(gate_denied());
    }
    let before = observe_parent(parent)?;
    if before.start_time_ticks != record.provider_start_time_ticks
        || before.real_uid != record.provider_uid
        || before.real_gid != record.provider_gid
        || before.executable_device != record.provider_executable_device
        || before.executable_inode != record.provider_executable_inode
    {
        return Err(gate_denied());
    }
    let after = observe_parent(parent)?;
    if before != after || unsafe { libc::getppid() } != parent {
        return Err(gate_denied());
    }
    Ok(())
}

fn observe_parent(parent: libc::pid_t) -> Result<ObservedParentIdentity> {
    let stat =
        std::fs::read_to_string(format!("/proc/{parent}/stat")).map_err(|_| gate_denied())?;
    let close = stat.rfind(')').ok_or_else(gate_denied)?;
    let fields = stat
        .get(close + 2..)
        .ok_or_else(gate_denied)?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let start_time_ticks = fields
        .get(19)
        .ok_or_else(gate_denied)?
        .parse::<u64>()
        .map_err(|_| gate_denied())?;
    let status =
        std::fs::read_to_string(format!("/proc/{parent}/status")).map_err(|_| gate_denied())?;
    let real_uid = parse_first_status_id(&status, "Uid:")?;
    let real_gid = parse_first_status_id(&status, "Gid:")?;
    let executable = std::fs::metadata(format!("/proc/{parent}/exe")).map_err(|_| gate_denied())?;
    Ok(ObservedParentIdentity {
        start_time_ticks,
        real_uid,
        real_gid,
        executable_device: executable.dev(),
        executable_inode: executable.ino(),
    })
}

fn parse_first_status_id(status: &str, key: &str) -> Result<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|value| value.split_ascii_whitespace().next())
        .ok_or_else(gate_denied)?
        .parse::<u32>()
        .map_err(|_| gate_denied())
}

fn gate_denied() -> DirectToolError {
    DirectToolError::BackendUnavailable(
        "OS post-exec adapter admission is not active for this provider invocation".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn open_test_directory(path: &std::path::Path) -> File {
        let encoded = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let descriptor = unsafe {
            libc::open(
                encoded.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        assert!(descriptor >= 0);
        unsafe { File::from_raw_fd(descriptor) }
    }

    fn parent_bound_record() -> ProductPostExecAdmissionRecord {
        let parent = unsafe { libc::getppid() };
        let identity = observe_parent(parent).unwrap();
        ProductPostExecAdmissionRecord {
            schema: POST_EXEC_ADMISSION_SCHEMA.to_string(),
            runtime_lifecycle_binding_sha256: "a".repeat(64),
            final_runtime_executable_sha256: "b".repeat(64),
            provider_pid: u32::try_from(parent).unwrap(),
            provider_start_time_ticks: identity.start_time_ticks,
            provider_executable_device: identity.executable_device,
            provider_executable_inode: identity.executable_inode,
            provider_uid: identity.real_uid,
            provider_gid: identity.real_gid,
        }
    }

    fn attempt_backend(
        directory: &File,
        record: &ProductPostExecAdmissionRecord,
        backend_called: &AtomicBool,
    ) -> bool {
        let admitted = require_admission_from_directory(
            directory,
            unsafe { libc::geteuid() },
            record.provider_uid,
            record.provider_gid,
            unsafe { libc::getppid() },
        )
        .is_ok();
        if admitted {
            backend_called.store(true, Ordering::SeqCst);
        }
        admitted
    }

    #[test]
    fn partial_publication_race_never_reaches_backend_before_activation() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o710)).unwrap();
        let directory = open_test_directory(temp.path());
        let record = parent_bound_record();
        assert_eq!(record.provider_uid, unsafe { libc::geteuid() });
        assert_eq!(record.provider_gid, unsafe { libc::getegid() });
        let backend_called = AtomicBool::new(false);

        assert!(!attempt_backend(&directory, &record, &backend_called));
        assert!(!backend_called.load(Ordering::SeqCst));

        let path = temp
            .path()
            .join(PRODUCT_POST_EXEC_ADMISSION_FILE_NAME.to_str().unwrap());
        let bytes = record.canonical_bytes().unwrap();
        let split = bytes.len() / 2;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&bytes[..split]).unwrap();
        file.sync_all().unwrap();
        assert!(!attempt_backend(&directory, &record, &backend_called));
        file.write_all(&bytes[split..]).unwrap();
        file.sync_all().unwrap();
        assert!(!attempt_backend(&directory, &record, &backend_called));
        assert!(!backend_called.load(Ordering::SeqCst));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        file.sync_all().unwrap();
        assert!(attempt_backend(&directory, &record, &backend_called));
        assert!(backend_called.load(Ordering::SeqCst));
    }

    #[test]
    fn stale_parent_symlink_and_hardlink_records_are_inert() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o710)).unwrap();
        let directory = open_test_directory(temp.path());
        let mut record = parent_bound_record();
        record.provider_start_time_ticks += 1;
        let path = temp
            .path()
            .join(PRODUCT_POST_EXEC_ADMISSION_FILE_NAME.to_str().unwrap());
        fs::write(&path, record.canonical_bytes().unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        assert!(
            require_admission_from_directory(
                &directory,
                unsafe { libc::geteuid() },
                record.provider_uid,
                record.provider_gid,
                unsafe { libc::getppid() },
            )
            .is_err()
        );

        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert!(
            require_admission_from_directory(
                &directory,
                unsafe { libc::geteuid() },
                record.provider_uid,
                record.provider_gid,
                unsafe { libc::getppid() },
            )
            .is_err()
        );

        fs::remove_file(&path).unwrap();
        let record = parent_bound_record();
        fs::write(&path, record.canonical_bytes().unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
        fs::hard_link(&path, temp.path().join("second-link")).unwrap();
        assert!(
            require_admission_from_directory(
                &directory,
                unsafe { libc::geteuid() },
                record.provider_uid,
                record.provider_gid,
                unsafe { libc::getppid() },
            )
            .is_err()
        );
    }
}
