//! Fixed one-shot operation replay synchronization helper.
//!
//! The measured daemon launches one endpoint-specific binary with no
//! arguments and an empty environment. Descriptor 3 is one read-only command
//! pipe and descriptor 4 is one write-only response pipe. The frame contains
//! no adapter, provider, UID/GID, SELinux domain, binary path, journal path,
//! inbox path, epoch or sequence selector; all of those are frozen by the
//! binary and [`TrustedReplaySyncContext`].
//!
//! Phase A intentionally remains product-HOLD: the context cannot construct a
//! daemon-sealed launch-challenge/replay authority. A syntactically valid FD 3
//! frame therefore never activates local or Android mutation by itself.

use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::time::{Duration, Instant};

use thiserror::Error;
#[cfg(test)]
use trillionnium_os_types::direct_operation::DirectOperationReplaySyncAckConfirmationV3;
use trillionnium_os_types::direct_operation::{
    DirectOperationAdapter, DirectOperationReplaySyncCommandV3,
};

use crate::operation_journal::OperationJournalError;
use crate::trusted_context::{TrustedContextError, TrustedReplaySyncContext};

pub const FRAME_MAGIC: [u8; 8] = *b"TROPSY01";
pub const FRAME_VERSION: u8 = 1;
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const HEADER_BYTES: usize = 16;
const OBSERVE_OPCODE: u8 = 1;
const APPLY_ACK_OPCODE: u8 = 2;
const OBSERVE_RESPONSE_OPCODE: u8 = 0x81;
const APPLY_ACK_RESPONSE_OPCODE: u8 = 0x82;
const COMMAND_FD: RawFd = 3;
const RESPONSE_FD: RawFd = 4;
const PIPE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUIRED_AGENTD_SECUREBITS: libc::c_int = 0x00c3;

pub type ReplaySyncResult<T> = Result<T, OperationReplaySyncError>;

#[derive(Debug, Error)]
pub enum OperationReplaySyncError {
    #[error("operation replay-sync launch contract HOLD: {0}")]
    Launch(&'static str),
    #[error("operation replay-sync frame HOLD: {0}")]
    Frame(&'static str),
    #[error("operation replay-sync trusted-context HOLD: {0}")]
    Context(#[from] TrustedContextError),
    #[error("operation replay-sync journal HOLD: {0}")]
    Journal(#[from] OperationJournalError),
    #[error("operation replay-sync Android ACK HOLD: {0}")]
    Android(String),
    #[error("operation replay-sync I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Fixed System API entry point. There is no runtime adapter selector.
pub fn run_system_api_one_shot() -> ReplaySyncResult<()> {
    run_fixed_one_shot(DirectOperationAdapter::SystemApi)
}

/// Fixed Accessibility entry point. There is no runtime adapter selector.
pub fn run_accessibility_one_shot() -> ReplaySyncResult<()> {
    run_fixed_one_shot(DirectOperationAdapter::Accessibility)
}

/// Post-exec self-hardening barrier observed by the measured daemon launcher.
/// The parent already installed the fixed UID/GID, SELinux exec transition,
/// empty capabilities and descendant-denial filter before `execveat`; this
/// barrier reapplies the exec-reset dumpability invariant and proves the exact
/// helper image reached its own code before any command byte is consumed.
pub fn enter_measured_parent_stop() -> ReplaySyncResult<()> {
    // setresuid/setresgid in the pre-exec launcher clear PDEATHSIG.  The
    // launcher sets it after those transitions; repeat and read it back in the
    // exact executable before accepting any possibility of a stop.
    let parent_before = unsafe { libc::getppid() };
    if parent_before <= 1 {
        return Err(OperationReplaySyncError::Launch(
            "measured replay-sync parent is absent",
        ));
    }
    // SAFETY: scalar prctl contracts and a live writable integer.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
        return Err(OperationReplaySyncError::Launch(
            "could not install measured-parent death signal",
        ));
    }
    let mut pdeathsig = 0;
    if unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut pdeathsig) } != 0
        || pdeathsig != libc::SIGKILL
        || unsafe { libc::getppid() } != parent_before
    {
        return Err(OperationReplaySyncError::Launch(
            "measured-parent death signal or parent identity drifted",
        ));
    }
    // SAFETY: prctl arguments are the documented scalar forms.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(OperationReplaySyncError::Launch(
            "could not retain no-new-privileges after exec",
        ));
    }
    // SAFETY: same scalar prctl contract.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(OperationReplaySyncError::Launch(
            "could not disable dumpability after exec",
        ));
    }
    // The seccomp descendant-denial filter must already be inherited from the
    // pre-exec ceremony.  A helper reached outside the exact TRACEME parent
    // returns an error; it never enters an ambient SIGSTOP hang.
    let status = fs::read_to_string("/proc/self/status")?;
    validate_measured_parent_status(&status, parent_before)?;
    if unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } != 2
        || unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } != REQUIRED_AGENTD_SECUREBITS
        || unsafe { libc::getppid() } != parent_before
    {
        return Err(OperationReplaySyncError::Launch(
            "measured-parent tracer or seccomp state changed before stop",
        ));
    }
    // SAFETY: raise targets only the current process.
    if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
        return Err(OperationReplaySyncError::Launch(
            "could not enter the measured parent stop",
        ));
    }
    Ok(())
}

fn validate_measured_parent_status(
    status: &str,
    expected_parent: libc::pid_t,
) -> ReplaySyncResult<()> {
    let expected_parent = u64::try_from(expected_parent)
        .map_err(|_| OperationReplaySyncError::Launch("measured-parent PID is invalid"))?;
    let decimal = |key: &'static str| -> ReplaySyncResult<u64> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|value| value.split_ascii_whitespace().next())
            .ok_or(OperationReplaySyncError::Launch(
                "measured-parent proc status field is absent",
            ))?
            .parse::<u64>()
            .map_err(|_| {
                OperationReplaySyncError::Launch("measured-parent proc status field is invalid")
            })
    };
    if decimal("PPid:")? != expected_parent
        || decimal("TracerPid:")? != expected_parent
        || decimal("NoNewPrivs:")? != 1
        || decimal("Seccomp:")? != 2
    {
        return Err(OperationReplaySyncError::Launch(
            "measured-parent tracer/parent/hardening identity is denied",
        ));
    }
    let hexadecimal = |key: &'static str| -> ReplaySyncResult<u64> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|value| value.split_ascii_whitespace().next())
            .ok_or(OperationReplaySyncError::Launch(
                "measured-parent capability status field is absent",
            ))
            .and_then(|value| {
                u64::from_str_radix(value, 16).map_err(|_| {
                    OperationReplaySyncError::Launch(
                        "measured-parent capability status field is invalid",
                    )
                })
            })
    };
    if ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
        .into_iter()
        .any(|key| !matches!(hexadecimal(key), Ok(0)))
    {
        return Err(OperationReplaySyncError::Launch(
            "measured helper retained a Linux capability",
        ));
    }
    Ok(())
}

fn run_fixed_one_shot(adapter: DirectOperationAdapter) -> ReplaySyncResult<()> {
    let transport = FixedOneShotTransport::open()?;
    transport.command().validate_product_lane().map_err(|_| {
        OperationReplaySyncError::Frame(
            "product command contains non-product daemon-custody material",
        )
    })?;
    let command = transport.command().clone();
    let context = TrustedReplaySyncContext::open_current_product(adapter)?;

    // Frame material is never authority. Phase A always stops here in product
    // until the daemon launches this helper with a sealed challenge and a
    // rollback-resistant replay capability.
    let launch_authority = context.require_product_launch_authority(
        command.binding_sha256(),
        command.launch_challenge_sha256(),
    )?;
    let mut journal = launch_authority.open_replay_sync_operation_journal()?;

    let (opcode, payload) = match command {
        DirectOperationReplaySyncCommandV3::ObserveDisposition { .. } => {
            let observation = journal.terminal_disposition(launch_authority)?;
            (
                OBSERVE_RESPONSE_OPCODE,
                observation
                    .canonical_json()
                    .map_err(|_| OperationReplaySyncError::Frame("observation is invalid"))?,
            )
        }
        DirectOperationReplaySyncCommandV3::ApplyAck {
            ack_intent_sha256, ..
        } => {
            let inbox = context
                .pending_outer_ack_v3()?
                .ok_or(OperationReplaySyncError::Launch(
                    "fixed root-owned outer ACK v3 inbox is absent",
                ))?;
            let prepared = journal.prepare_outer_ack_for_replay_sync(
                launch_authority,
                &inbox,
                &ack_intent_sha256,
            )?;
            // Exact Android ACK echo precedes every local reclamation.
            let android_ack =
                crate::android_operation_replay_ack::acknowledge_from_replay_sync_context(
                    &prepared,
                )
                .map_err(|error| OperationReplaySyncError::Android(error.to_string()))?;
            // This consumes the sealed preparation, compacts durably, reopens
            // the named journal, and returns the exact post-state proof.
            let confirmation = journal.apply_outer_ack_and_confirm(prepared, &android_ack)?;
            (
                APPLY_ACK_RESPONSE_OPCODE,
                confirmation
                    .canonical_json()
                    .map_err(|_| OperationReplaySyncError::Frame("ACK confirmation is invalid"))?,
            )
        }
    };
    transport.write_response(opcode, &payload)
}

/// One validated daemon-to-helper command and its distinct helper-to-daemon
/// response pipe.  The constructor is the single fixed-FD intake used by both
/// product replay-sync and the separately featured P0 device-conformance
/// replay helper.  It accepts no caller-selected descriptor, path, adapter,
/// environment value, or command-line field.
pub(crate) struct FixedOneShotTransport {
    command: DirectOperationReplaySyncCommandV3,
    response_pipe: File,
}

impl FixedOneShotTransport {
    pub(crate) fn open() -> ReplaySyncResult<Self> {
        require_closed_process_surface()?;
        let (mut command_pipe, response_pipe) = open_fixed_pipes()?;
        let command_bytes = read_pipe_to_exact_eof(&mut command_pipe)?;
        let command = decode_command_frame(&command_bytes)?;
        Ok(Self {
            command,
            response_pipe,
        })
    }

    #[must_use]
    pub(crate) const fn command(&self) -> &DirectOperationReplaySyncCommandV3 {
        &self.command
    }

    pub(crate) fn write_response(mut self, opcode: u8, payload: &[u8]) -> ReplaySyncResult<()> {
        let response = encode_response_frame(opcode, payload)?;
        write_pipe_before(
            &mut self.response_pipe,
            &response,
            Instant::now() + PIPE_TIMEOUT,
        )
    }
}

fn require_closed_process_surface() -> ReplaySyncResult<()> {
    if std::env::args_os().count() != 1 {
        return Err(OperationReplaySyncError::Launch(
            "operation replay-sync helper accepts no arguments",
        ));
    }
    if std::env::vars_os().next().is_some() {
        return Err(OperationReplaySyncError::Launch(
            "operation replay-sync helper requires an empty environment",
        ));
    }
    Ok(())
}

fn open_fixed_pipes() -> ReplaySyncResult<(File, File)> {
    let (command, command_identity) = duplicate_validated_pipe(COMMAND_FD, libc::O_RDONLY)?;
    let (response, response_identity) = duplicate_validated_pipe(RESPONSE_FD, libc::O_WRONLY)?;
    if command_identity == response_identity {
        return Err(OperationReplaySyncError::Launch(
            "command and response descriptors alias one pipe inode",
        ));
    }
    Ok((command, response))
}

fn duplicate_validated_pipe(
    inherited_fd: RawFd,
    access: libc::c_int,
) -> ReplaySyncResult<(File, (u64, u64))> {
    // Validate the inherited integer without first assuming ownership.
    // SAFETY: F_GETFL only inspects the descriptor table entry.
    let flags = unsafe { libc::fcntl(inherited_fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if flags & libc::O_ACCMODE != access {
        return Err(OperationReplaySyncError::Launch(
            "fixed inherited pipe has the wrong access direction",
        ));
    }
    let mut status = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: status points to writable storage for one libc::stat.
    if unsafe { libc::fstat(inherited_fd, status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: fstat succeeded and initialized the complete structure.
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFIFO || status.st_nlink == 0 {
        return Err(OperationReplaySyncError::Launch(
            "fixed inherited descriptor is not one live pipe",
        ));
    }
    // F_DUPFD_CLOEXEC returns a fresh descriptor owned only by this call, so
    // File may safely assume ownership without consuming the fixed inherited
    // descriptor itself.
    // SAFETY: fcntl duplicates one already validated live descriptor.
    let duplicated = unsafe { libc::fcntl(inherited_fd, libc::F_DUPFD_CLOEXEC, 5) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: duplicated is a fresh successful F_DUPFD_CLOEXEC result and is
    // transferred exactly once into File.
    let file = unsafe { File::from_raw_fd(duplicated) };
    let identity = validate_pipe(&file, access)?;
    if identity != (status.st_dev, status.st_ino) {
        return Err(OperationReplaySyncError::Launch(
            "fixed inherited pipe identity changed during duplication",
        ));
    }
    Ok((file, identity))
}

fn validate_pipe(file: &File, access: libc::c_int) -> ReplaySyncResult<(u64, u64)> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_fifo() || metadata.nlink() == 0 {
        return Err(OperationReplaySyncError::Launch(
            "fixed inherited descriptor is not one live pipe",
        ));
    }
    // SAFETY: F_GETFL reads flags from a live descriptor without mutation.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if flags & libc::O_ACCMODE != access {
        return Err(OperationReplaySyncError::Launch(
            "fixed inherited pipe has the wrong access direction",
        ));
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn read_pipe_to_exact_eof(input: &mut File) -> ReplaySyncResult<Vec<u8>> {
    let deadline = Instant::now() + PIPE_TIMEOUT;
    let maximum = HEADER_BYTES + MAX_PAYLOAD_BYTES;
    let mut bytes = Vec::with_capacity(HEADER_BYTES);
    let mut buffer = [0_u8; 4096];
    loop {
        poll_pipe(input.as_raw_fd(), deadline, libc::POLLIN | libc::POLLHUP)?;
        match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if bytes.len().saturating_add(count) > maximum {
                    return Err(OperationReplaySyncError::Frame(
                        "command frame exceeds the 64 KiB payload bound",
                    ));
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(bytes)
}

fn write_pipe_before(output: &mut File, bytes: &[u8], deadline: Instant) -> ReplaySyncResult<()> {
    // Use nonblocking writes plus a single absolute deadline. The duplicated
    // descriptor is private to this one-shot helper; no caller can observe or
    // depend on its file-status flags.
    // SAFETY: F_GETFL only inspects the live duplicated response descriptor.
    let original_flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
    if original_flags < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: F_SETFL changes only file-status flags on the live descriptor.
    if unsafe {
        libc::fcntl(
            output.as_raw_fd(),
            libc::F_SETFL,
            original_flags | libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let result = (|| {
        let mut offset = 0;
        while offset < bytes.len() {
            poll_pipe(output.as_raw_fd(), deadline, libc::POLLOUT)?;
            match output.write(&bytes[offset..]) {
                Ok(0) => {
                    return Err(OperationReplaySyncError::Launch(
                        "fixed response pipe stopped accepting bytes",
                    ));
                }
                Ok(written) => offset += written,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    })();
    // SAFETY: restore the original status flags on the same live descriptor.
    let restore = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, original_flags) };
    if restore < 0 && result.is_ok() {
        return Err(io::Error::last_os_error().into());
    }
    result
}

fn poll_pipe(fd: RawFd, deadline: Instant, events: libc::c_short) -> ReplaySyncResult<()> {
    loop {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(
            OperationReplaySyncError::Launch("fixed inherited pipe timed out"),
        )?;
        let timeout_ms = remaining
            .as_millis()
            .saturating_add(u128::from(
                !remaining.subsec_nanos().is_multiple_of(1_000_000),
            ))
            .min(libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: descriptor names one initialized pollfd for the live File.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            if descriptor.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
                return Err(OperationReplaySyncError::Launch(
                    "fixed inherited pipe descriptor reported an error",
                ));
            }
            if descriptor.revents & events != 0 {
                return Ok(());
            }
            return Err(OperationReplaySyncError::Launch(
                "fixed inherited pipe reported an invalid event",
            ));
        }
        if result == 0 {
            return Err(OperationReplaySyncError::Launch(
                "fixed inherited pipe timed out",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn decode_command_frame(bytes: &[u8]) -> ReplaySyncResult<DirectOperationReplaySyncCommandV3> {
    if bytes.len() < HEADER_BYTES || bytes[..8] != FRAME_MAGIC {
        return Err(OperationReplaySyncError::Frame(
            "command frame magic or header is invalid",
        ));
    }
    if bytes[8] != FRAME_VERSION {
        return Err(OperationReplaySyncError::Frame(
            "command frame version is invalid",
        ));
    }
    let opcode = bytes[9];
    if !matches!(opcode, OBSERVE_OPCODE | APPLY_ACK_OPCODE) {
        return Err(OperationReplaySyncError::Frame(
            "command frame opcode is invalid",
        ));
    }
    if bytes[10..12] != [0, 0] {
        return Err(OperationReplaySyncError::Frame(
            "command frame reserved bits are non-zero",
        ));
    }
    let payload_len =
        u32::from_be_bytes(bytes[12..16].try_into().expect("fixed header slice")) as usize;
    if payload_len == 0
        || payload_len > MAX_PAYLOAD_BYTES
        || bytes.len() != HEADER_BYTES + payload_len
    {
        return Err(OperationReplaySyncError::Frame(
            "command frame payload length is invalid",
        ));
    }
    let command = DirectOperationReplaySyncCommandV3::from_canonical_json(&bytes[HEADER_BYTES..])
        .map_err(|_| {
        OperationReplaySyncError::Frame("command JSON is not exact canonical v1")
    })?;
    if command.opcode() != opcode {
        return Err(OperationReplaySyncError::Frame(
            "command opcode and canonical payload disagree",
        ));
    }
    Ok(command)
}

/// Encode one already-validated closed daemon command. Framing is data only:
/// the helper still requires a measured fixed launch and its separately sealed
/// product launch authority before it can open or mutate a journal.
#[cfg(test)]
fn encode_command_frame(command: &DirectOperationReplaySyncCommandV3) -> ReplaySyncResult<Vec<u8>> {
    let payload = command
        .canonical_json()
        .map_err(|_| OperationReplaySyncError::Frame("command JSON is invalid"))?;
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
        return Err(OperationReplaySyncError::Frame(
            "command payload length is invalid",
        ));
    }
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| OperationReplaySyncError::Frame("command payload cannot be encoded"))?;
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.push(FRAME_VERSION);
    frame.push(command.opcode());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode the exact bounded response accepted by the daemon's measured
/// launcher. The caller must already have read through EOF; canonical response
/// bytes alone confer no launch or ACK authority.
#[cfg(test)]
fn decode_ack_confirmation_response_frame(
    bytes: &[u8],
) -> ReplaySyncResult<DirectOperationReplaySyncAckConfirmationV3> {
    if bytes.len() < HEADER_BYTES || bytes[..8] != FRAME_MAGIC {
        return Err(OperationReplaySyncError::Frame(
            "ACK confirmation magic or header is invalid",
        ));
    }
    if bytes[8] != FRAME_VERSION || bytes[9] != APPLY_ACK_RESPONSE_OPCODE {
        return Err(OperationReplaySyncError::Frame(
            "ACK confirmation version or opcode is invalid",
        ));
    }
    if bytes[10..12] != [0, 0] {
        return Err(OperationReplaySyncError::Frame(
            "ACK confirmation reserved bits are non-zero",
        ));
    }
    let payload_len =
        u32::from_be_bytes(bytes[12..16].try_into().expect("fixed header slice")) as usize;
    if payload_len == 0
        || payload_len > MAX_PAYLOAD_BYTES
        || bytes.len() != HEADER_BYTES + payload_len
    {
        return Err(OperationReplaySyncError::Frame(
            "ACK confirmation payload length is invalid",
        ));
    }
    DirectOperationReplaySyncAckConfirmationV3::from_canonical_json(&bytes[HEADER_BYTES..]).map_err(
        |_| OperationReplaySyncError::Frame("ACK confirmation JSON is not exact canonical v1"),
    )
}

fn encode_response_frame(opcode: u8, payload: &[u8]) -> ReplaySyncResult<Vec<u8>> {
    if !matches!(opcode, OBSERVE_RESPONSE_OPCODE | APPLY_ACK_RESPONSE_OPCODE)
        || payload.is_empty()
        || payload.len() > MAX_PAYLOAD_BYTES
    {
        return Err(OperationReplaySyncError::Frame(
            "response opcode or payload length is invalid",
        ));
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| {
        OperationReplaySyncError::Frame("response payload length cannot be encoded")
    })?;
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.push(FRAME_VERSION);
    frame.push(opcode);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use std::os::fd::FromRawFd as _;
    use std::thread;

    use super::*;
    use trillionnium_os_types::direct_operation::{
        ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA, DirectOperationAdapterTerminalDispositionV1,
        DirectOperationAdapterTerminalStateV1, DirectOperationJournalEvidenceSnapshotV1,
        DirectOperationOuterEvidence, DirectOperationOuterOutcome,
        DirectOperationReplaySyncObservationV3, JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA,
        MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE, OPERATION_REPLAY_SYNC_ACK_CONFIRMATION_V3_SCHEMA,
        OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA, OPERATION_REPLAY_SYNC_OBSERVATION_V3_SCHEMA,
    };

    fn digest(byte: u8) -> String {
        char::from(byte).to_string().repeat(64)
    }

    fn observe_command() -> DirectOperationReplaySyncCommandV3 {
        DirectOperationReplaySyncCommandV3::ObserveDisposition {
            schema: OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA.to_string(),
            binding_sha256: digest(b'1'),
            launch_challenge_sha256: digest(b'2'),
        }
    }

    fn command_frame(command: &DirectOperationReplaySyncCommandV3) -> Vec<u8> {
        let payload = command.canonical_json().unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&FRAME_MAGIC);
        frame.push(FRAME_VERSION);
        frame.push(command.opcode());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    fn pipe_pair() -> (File, File) {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors points to storage for exactly two returned FDs.
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: pipe2 initialized two distinct descriptors, each transferred
        // exactly once into its File.
        let reader = unsafe { File::from_raw_fd(descriptors[0]) };
        // SAFETY: same successful pipe2 ownership transfer for the write end.
        let writer = unsafe { File::from_raw_fd(descriptors[1]) };
        (reader, writer)
    }

    #[test]
    fn canonical_command_frame_is_exact_and_opcode_bound() {
        let command = observe_command();
        let frame = command_frame(&command);
        assert_eq!(decode_command_frame(&frame).unwrap(), command);
        assert_eq!(encode_command_frame(&command).unwrap(), frame);
        let response = encode_response_frame(OBSERVE_RESPONSE_OPCODE, b"{}").unwrap();
        assert_eq!(&response[..8], &FRAME_MAGIC);
        assert_eq!(response[8], FRAME_VERSION);
        assert_eq!(response[9], OBSERVE_RESPONSE_OPCODE);
        assert_eq!(&response[10..12], &[0, 0]);
        assert_eq!(u32::from_be_bytes(response[12..16].try_into().unwrap()), 2);
        assert_eq!(&response[16..], b"{}");
    }

    #[test]
    fn measured_parent_status_requires_exact_live_tracer_and_seccomp() {
        let exact = concat!(
            "PPid:\t4242\nTracerPid:\t4242\nNoNewPrivs:\t1\nSeccomp:\t2\n",
            "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n",
            "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n",
            "CapAmb:\t0000000000000000\n",
        );
        validate_measured_parent_status(exact, 4242).unwrap();
        for drift in [
            exact.replace("TracerPid:\t4242", "TracerPid:\t0"),
            exact.replace("PPid:\t4242", "PPid:\t1"),
            exact.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            exact.replace("Seccomp:\t2", "Seccomp:\t0"),
            exact.replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000001"),
        ] {
            assert!(validate_measured_parent_status(&drift, 4242).is_err());
        }
    }

    #[test]
    fn exact_ack_confirmation_response_decoder_rejects_trailing_and_opcode_drift() {
        let confirmation = DirectOperationReplaySyncAckConfirmationV3 {
            schema: OPERATION_REPLAY_SYNC_ACK_CONFIRMATION_V3_SCHEMA.to_string(),
            ack_intent_sha256: digest(b'1'),
            android_ack_echo_sha256: digest(b'2'),
            acknowledgement_sha256: digest(b'3'),
            authenticated_ack_chain_sha256: digest(b'4'),
            compacted_ack_watermark: 9,
            post_compaction_journal_sha256: digest(b'5'),
            journal_file_identity_sha256: digest(b'6'),
            mutation_cas_committed_head_sha256: digest(b'7'),
        };
        let payload = confirmation.canonical_json().unwrap();
        let frame = encode_response_frame(APPLY_ACK_RESPONSE_OPCODE, &payload).unwrap();
        assert_eq!(
            decode_ack_confirmation_response_frame(&frame).unwrap(),
            confirmation
        );
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(decode_ack_confirmation_response_frame(&trailing).is_err());
        let mut wrong_opcode = frame;
        wrong_opcode[9] = OBSERVE_RESPONSE_OPCODE;
        assert!(decode_ack_confirmation_response_frame(&wrong_opcode).is_err());
    }

    #[test]
    fn framing_rejects_header_length_canonicality_and_trailing_drift() {
        let golden = command_frame(&observe_command());
        for index in [0_usize, 8, 9, 10, 15] {
            let mut drifted = golden.clone();
            drifted[index] ^= 1;
            assert!(decode_command_frame(&drifted).is_err(), "index {index}");
        }
        let mut trailing = golden.clone();
        trailing.push(0);
        assert!(decode_command_frame(&trailing).is_err());

        let mut whitespace = golden.clone();
        *whitespace.get_mut(15).unwrap() += 1;
        whitespace.push(b'\n');
        assert!(decode_command_frame(&whitespace).is_err());

        let oversized = vec![0_u8; HEADER_BYTES + MAX_PAYLOAD_BYTES + 1];
        assert!(decode_command_frame(&oversized).is_err());
    }

    #[test]
    fn inherited_pipe_validation_checks_direction_identity_and_exact_eof() {
        let (mut reader, mut writer) = pipe_pair();
        let (reader_copy, reader_identity) =
            duplicate_validated_pipe(reader.as_raw_fd(), libc::O_RDONLY).unwrap();
        let (writer_copy, writer_identity) =
            duplicate_validated_pipe(writer.as_raw_fd(), libc::O_WRONLY).unwrap();
        assert_eq!(reader_identity, writer_identity);
        assert!(duplicate_validated_pipe(reader.as_raw_fd(), libc::O_WRONLY).is_err());
        assert!(duplicate_validated_pipe(writer.as_raw_fd(), libc::O_RDONLY).is_err());
        drop(reader_copy);
        drop(writer_copy);

        let expected = command_frame(&observe_command());
        let first = expected[..7].to_vec();
        let second = expected[7..].to_vec();
        let producer = thread::spawn(move || {
            writer.write_all(&first).unwrap();
            writer.write_all(&second).unwrap();
        });
        assert_eq!(read_pipe_to_exact_eof(&mut reader).unwrap(), expected);
        producer.join().unwrap();
    }

    #[test]
    fn response_pipe_backpressure_stops_at_the_absolute_deadline() {
        let (reader, mut writer) = pipe_pair();
        // Fill the pipe without a reader so the replay helper must exercise
        // POLLOUT timeout rather than blocking in write(2).
        // SAFETY: F_GETFL/F_SETFL operate on this live test-owned descriptor.
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK,) },
            0
        );
        let fill = [0_u8; 4096];
        loop {
            match writer.write(&fill) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("could not fill test pipe: {error}"),
            }
        }
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags) },
            0
        );
        let started = Instant::now();
        let result = write_pipe_before(
            &mut writer,
            b"bounded-response",
            Instant::now() + Duration::from_millis(25),
        );
        assert!(matches!(result, Err(OperationReplaySyncError::Launch(_))));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(reader);
    }

    #[test]
    fn worst_case_active_journal_observation_fits_one_bounded_response() {
        assert_eq!(crate::operation_journal::MAX_ACTIVE_OPERATIONS, 64);
        let count = crate::operation_journal::MAX_ACTIVE_OPERATIONS;
        let previous = MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE - count as u64;
        let attempt = format!("attempt:{}", "a".repeat(64));
        let evidence = (0..count)
            .map(|index| DirectOperationOuterEvidence {
                allocating_provider_attempt_id: attempt.clone(),
                adapter_effect_ordinal: index as u64,
                journal_sequence: previous + 1 + index as u64,
                tool: DirectOperationAdapter::Accessibility
                    .tool_name()
                    .to_string(),
                canonical_request_sha256: digest(b'b'),
                backend_request_id_sha256: digest(b'c'),
                backend_result_sha256: digest(b'd'),
                outcome: DirectOperationOuterOutcome::BackendError,
                backend_error_code: Some("e".repeat(128)),
            })
            .collect::<Vec<_>>();
        let mut snapshot = DirectOperationJournalEvidenceSnapshotV1 {
            schema: JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA.to_string(),
            allocation_binding_sha256: digest(b'f'),
            invocation_id: format!("inv:{}", "1".repeat(64)),
            provider_id: trillionnium_os_types::agent_principal_registry::CODEX_STABLE_PRINCIPAL
                .provider_id
                .to_string(),
            agent_id: trillionnium_os_types::agent_principal_registry::CODEX_STABLE_PRINCIPAL
                .agent_id
                .to_string(),
            allocating_provider_attempt_id: attempt.clone(),
            adapter: DirectOperationAdapter::Accessibility,
            journal_epoch: "2".repeat(32),
            journal_payload_sha256: digest(b'3'),
            previous_ack_watermark: previous,
            previous_ack_chain_sha256: digest(b'4'),
            journal_allocation_count: count as u32,
            journal_evidence_count: count as u32,
            first_journal_sequence: previous + 1,
            last_journal_sequence: MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE,
            evidence,
            evidence_sha256: String::new(),
        };
        snapshot.evidence_sha256 = snapshot.evidence_digest_sha256().unwrap();
        snapshot.validate().unwrap();
        let disposition = DirectOperationAdapterTerminalDispositionV1 {
            schema: ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA.to_string(),
            binding_sha256: digest(b'5'),
            invocation_id: format!("inv:{}", "1".repeat(64)),
            delivery_provider_attempt_id: attempt,
            provider_id: trillionnium_os_types::agent_principal_registry::CODEX_STABLE_PRINCIPAL
                .provider_id
                .to_string(),
            agent_id: trillionnium_os_types::agent_principal_registry::CODEX_STABLE_PRINCIPAL
                .agent_id
                .to_string(),
            adapter: DirectOperationAdapter::Accessibility,
            terminal_state: DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot: snapshot,
            },
        };
        let observation = DirectOperationReplaySyncObservationV3 {
            schema: OPERATION_REPLAY_SYNC_OBSERVATION_V3_SCHEMA.to_string(),
            terminal_disposition_sha256: disposition.digest_sha256().unwrap(),
            journal_state_sha256: digest(b'3'),
            journal_file_identity_sha256: digest(b'6'),
            terminal_disposition: disposition,
        };
        let payload = observation.canonical_json().unwrap();
        assert!(payload.len() <= MAX_PAYLOAD_BYTES);
        assert!(encode_response_frame(OBSERVE_RESPONSE_OPCODE, &payload).is_ok());
    }

    #[test]
    fn source_has_fixed_binaries_fds_and_android_before_local_compaction() {
        let source = include_str!("operation_replay_sync.rs");
        assert!(source.contains("const COMMAND_FD: RawFd = 3"));
        assert!(source.contains("const RESPONSE_FD: RawFd = 4"));
        let fixed_transport = source.find("FixedOneShotTransport::open").unwrap();
        let product_lane = source.find("validate_product_lane").unwrap();
        let product_context = source.find("open_current_product(adapter)").unwrap();
        assert!(fixed_transport < product_lane && product_lane < product_context);
        assert!(
            source.contains("let launch_authority = context.require_product_launch_authority(")
        );
        assert!(
            source.contains(
                "let mut journal = launch_authority.open_replay_sync_operation_journal()?"
            )
        );
        assert!(source.contains("journal.terminal_disposition(launch_authority)?"));
        assert!(source.contains(
            "journal.prepare_outer_ack_for_replay_sync(\n                launch_authority,"
        ));
        assert!(
            source
                .contains("acknowledge_from_replay_sync_context(\n                    &prepared,")
        );
        assert!(source.contains("journal.apply_outer_ack_and_confirm(prepared, &android_ack)?"));
        let environment_selector = ["std::env::", "var("].concat();
        let development_endpoint = ["production_", "endpoint"].concat();
        let adapter_parser = ["DirectOperationAdapter::", "from"].concat();
        assert!(!source.contains(&environment_selector));
        assert!(!source.contains(&development_endpoint));
        assert!(!source.contains(&adapter_parser));
        let prepare = source.find("prepare_outer_ack_for_replay_sync").unwrap();
        let android = source.find("acknowledge_from_replay_sync_context").unwrap();
        let compact = source.find("apply_outer_ack_and_confirm").unwrap();
        assert!(prepare < android && android < compact);
    }
}
