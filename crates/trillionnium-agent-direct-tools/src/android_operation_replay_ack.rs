//! Source-disabled one-shot Android operation replay ACK helpers.
//!
//! This module is deliberately separate from capability-lease root
//! publication and from adapter epoch activation. It accepts no ACK fields,
//! endpoint, path, role, argument, or environment selector. Each of its two
//! endpoint-typed entry points consumes a sealed daemon-pipe capability, reads
//! one exact canonical intent plus EOF, authenticates the fixed Android peer,
//! performs one ACK exchange, and requires an exact echo plus EOF.
//!
//! There is intentionally no production constructor for either sealed pipe
//! capability. The daemon currently has durable ACK intents, but no measured
//! inherited-pipe launcher/custody authority that can prove fixed descriptor
//! 3 came from the exact durable record. Until that separate authority exists,
//! these functions cannot be reached by product code. This module never opens,
//! deletes, rewrites, or otherwise mutates the daemon custody store; a pipe
//! close or any transport/protocol error leaves the durable intent untouched.

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_os_types::direct_operation::{
    DirectOperationAdapter, DirectOperationOuterAckInboxV3,
};

use crate::DirectToolError;
use crate::uds::{self, ExpectedBackendPeer};

const SOURCE_STATUS: &str = "source_disabled_missing_daemon_inherited_pipe_custody_and_launcher_v1";
const OPERATION_EPOCH_REPLAY_RUNTIME_WIRED: bool = false;
const DAEMON_ACK_INTENT_INHERITED_FD: RawFd = 3;

const SYSTEM_API_SOCKET: &str = "@trillionnium_system_api_replay_control";
const ACCESSIBILITY_SOCKET: &str = "@trillionnium_accessibility_replay_control";
const SYSTEM_API_MAGIC: [u8; 8] = *b"TRSYSC01";
const ACCESSIBILITY_MAGIC: [u8; 8] = *b"TRACSC01";

const VERSION: u8 = 1;
const ACK_OPERATION: u8 = 2;
const ACK_RESPONSE_OPERATION: u8 = 0x82;
const HEADER_BYTES: usize = 12;
const EPOCH_BYTES: usize = 32;
const SEQUENCE_BYTES: usize = 8;
const DIGEST_BYTES: usize = 64;
const ACK_INTENT_BYTES: usize = EPOCH_BYTES + SEQUENCE_BYTES + 2 * DIGEST_BYTES;
const ACK_FRAME_BYTES: usize = HEADER_BYTES + ACK_INTENT_BYTES;
const PIPE_READ_TIMEOUT: Duration = Duration::from_secs(5);
const BACKEND_READ_TIMEOUT: Duration = Duration::from_secs(5);
const BACKEND_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const BACKEND_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Error)]
pub(crate) enum AndroidOperationReplayAckError {
    #[error("Android operation replay ACK transport failed: {0}")]
    Transport(#[from] DirectToolError),
    #[error("Android operation replay ACK daemon-intent HOLD: {0}")]
    IntentHold(&'static str),
    #[error("Android operation replay ACK backend protocol HOLD: {0}")]
    BackendHold(&'static str),
}

type AckResult<T> = std::result::Result<T, AndroidOperationReplayAckError>;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalAckIntent {
    epoch: String,
    last_journal_sequence: u64,
    acknowledgement_sha256: String,
    authenticated_ack_chain_sha256: String,
}

impl CanonicalAckIntent {
    fn from_inbox(inbox: &DirectOperationOuterAckInboxV3) -> AckResult<Self> {
        inbox.validate().map_err(|_| {
            AndroidOperationReplayAckError::IntentHold("outer ACK v3 inbox is invalid")
        })?;
        let snapshot = &inbox.acknowledgement.journal_evidence_snapshot;
        Ok(Self {
            epoch: snapshot.journal_epoch.clone(),
            last_journal_sequence: snapshot.last_journal_sequence,
            acknowledgement_sha256: inbox.acknowledgement_sha256.clone(),
            authenticated_ack_chain_sha256: inbox.chain_step.authenticated_ack_chain_sha256.clone(),
        })
    }

    fn decode(bytes: &[u8]) -> AckResult<Self> {
        if bytes.len() != ACK_INTENT_BYTES {
            return Err(AndroidOperationReplayAckError::IntentHold(
                "daemon ACK intent is not exactly 168 bytes",
            ));
        }
        let epoch = parse_lower_hex(
            &bytes[..EPOCH_BYTES],
            EPOCH_BYTES,
            false,
            AndroidOperationReplayAckError::IntentHold("daemon ACK epoch is invalid"),
        )?;
        let mut sequence = [0_u8; SEQUENCE_BYTES];
        sequence.copy_from_slice(&bytes[EPOCH_BYTES..EPOCH_BYTES + SEQUENCE_BYTES]);
        let last_journal_sequence = u64::from_be_bytes(sequence);
        if last_journal_sequence == 0 || last_journal_sequence > i64::MAX as u64 {
            return Err(AndroidOperationReplayAckError::IntentHold(
                "daemon ACK sequence is outside the signed Android journal range",
            ));
        }
        let digest_offset = EPOCH_BYTES + SEQUENCE_BYTES;
        let acknowledgement_sha256 = parse_lower_hex(
            &bytes[digest_offset..digest_offset + DIGEST_BYTES],
            DIGEST_BYTES,
            false,
            AndroidOperationReplayAckError::IntentHold("daemon acknowledgement digest is invalid"),
        )?;
        let authenticated_ack_chain_sha256 = parse_lower_hex(
            &bytes[digest_offset + DIGEST_BYTES..],
            DIGEST_BYTES,
            false,
            AndroidOperationReplayAckError::IntentHold(
                "daemon authenticated ACK-chain digest is invalid",
            ),
        )?;
        Ok(Self {
            epoch,
            last_journal_sequence,
            acknowledgement_sha256,
            authenticated_ack_chain_sha256,
        })
    }

    fn encode_payload(&self) -> [u8; ACK_INTENT_BYTES] {
        let mut payload = [0_u8; ACK_INTENT_BYTES];
        payload[..EPOCH_BYTES].copy_from_slice(self.epoch.as_bytes());
        payload[EPOCH_BYTES..EPOCH_BYTES + SEQUENCE_BYTES]
            .copy_from_slice(&self.last_journal_sequence.to_be_bytes());
        let digest_offset = EPOCH_BYTES + SEQUENCE_BYTES;
        payload[digest_offset..digest_offset + DIGEST_BYTES]
            .copy_from_slice(self.acknowledgement_sha256.as_bytes());
        payload[digest_offset + DIGEST_BYTES..]
            .copy_from_slice(self.authenticated_ack_chain_sha256.as_bytes());
        payload
    }
}

fn parse_lower_hex(
    bytes: &[u8],
    exact_len: usize,
    allow_zero: bool,
    error: AndroidOperationReplayAckError,
) -> AckResult<String> {
    if bytes.len() != exact_len
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        || (!allow_zero && bytes.iter().all(|byte| *byte == b'0'))
    {
        return Err(error);
    }
    Ok(std::str::from_utf8(bytes)
        .expect("validated lower-hex is ASCII")
        .to_string())
}

struct SealedDaemonAckIntentPipe {
    input: File,
}

/// Consumed daemon pipe capability for the System API operation ACK helper.
///
/// Fields are private and there is no production constructor. A future
/// measured launcher must prove the fixed inherited descriptor and exact
/// durable System API intent before adding that constructor.
pub(crate) struct SealedSystemApiAckIntentPipe {
    pipe: SealedDaemonAckIntentPipe,
}

/// Consumed daemon pipe capability for the Accessibility operation ACK helper.
///
/// This distinct type prevents a System API pipe capability from being passed
/// to the Accessibility helper or vice versa.
pub(crate) struct SealedAccessibilityAckIntentPipe {
    pipe: SealedDaemonAckIntentPipe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifiedAckEndpoint {
    SystemApi,
    Accessibility,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VerifiedOperationReplayAck {
    endpoint: VerifiedAckEndpoint,
    intent: CanonicalAckIntent,
}

/// Opaque P0 capability proving that the fixed System API controller either
/// echoed the exact ACK in this process or exposed the exact post-ACK state
/// through a separately authenticated ACTIVATE exchange after response loss.
/// Callers cannot construct this from an inbox or digest alone.
#[cfg(feature = "device-launch-package-conformance")]
pub(crate) struct VerifiedDeviceConformanceReplayAck {
    verified: VerifiedOperationReplayAck,
}

#[cfg(feature = "device-launch-package-conformance")]
impl VerifiedDeviceConformanceReplayAck {
    pub(crate) fn validate_for_inbox(
        &self,
        inbox: &DirectOperationOuterAckInboxV3,
    ) -> AckResult<()> {
        let expected = CanonicalAckIntent::from_inbox(inbox)?;
        if self.verified.endpoint != VerifiedAckEndpoint::SystemApi
            || self.verified.intent != expected
        {
            return Err(AndroidOperationReplayAckError::BackendHold(
                "P0 verified Android ACK does not match the fixed outer inbox",
            ));
        }
        Ok(())
    }

    pub(crate) fn echo_sha256(&self) -> String {
        self.verified.echo_sha256()
    }
}

impl VerifiedOperationReplayAck {
    #[cfg(test)]
    pub(crate) fn for_replay_sync_test(
        prepared: &crate::operation_journal::PreparedReplaySyncOuterAck<'_>,
    ) -> AckResult<Self> {
        let context = prepared.context();
        let inbox = prepared.inbox();
        let endpoint = match context.adapter() {
            DirectOperationAdapter::SystemApi => VerifiedAckEndpoint::SystemApi,
            DirectOperationAdapter::Accessibility => VerifiedAckEndpoint::Accessibility,
        };
        let value = Self {
            endpoint,
            intent: CanonicalAckIntent::from_inbox(inbox)?,
        };
        value.validate_for(prepared)?;
        Ok(value)
    }

    pub(crate) fn validate_for(
        &self,
        prepared: &crate::operation_journal::PreparedReplaySyncOuterAck<'_>,
    ) -> AckResult<()> {
        let context = prepared.context();
        let inbox = prepared.inbox();
        let expected_endpoint = match context.adapter() {
            DirectOperationAdapter::SystemApi => VerifiedAckEndpoint::SystemApi,
            DirectOperationAdapter::Accessibility => VerifiedAckEndpoint::Accessibility,
        };
        let expected_intent = CanonicalAckIntent::from_inbox(inbox)?;
        if self.endpoint != expected_endpoint || self.intent != expected_intent {
            return Err(AndroidOperationReplayAckError::BackendHold(
                "verified Android ACK does not match the sealed replay-sync context",
            ));
        }
        Ok(())
    }

    pub(crate) fn echo_sha256(&self) -> String {
        let endpoint = match self.endpoint {
            VerifiedAckEndpoint::SystemApi => SYSTEM_API_ENDPOINT,
            VerifiedAckEndpoint::Accessibility => ACCESSIBILITY_ENDPOINT,
        };
        let mut frame = encode_ack_request(endpoint.magic, &self.intent);
        frame[9] = ACK_RESPONSE_OPERATION;
        lower_hex(&Sha256::digest(frame))
    }
}

#[derive(Clone, Copy)]
struct FixedAckEndpoint {
    socket: &'static str,
    magic: [u8; 8],
    expected_peer: ExpectedBackendPeer,
    verified_endpoint: VerifiedAckEndpoint,
}

const SYSTEM_API_ENDPOINT: FixedAckEndpoint = FixedAckEndpoint {
    socket: SYSTEM_API_SOCKET,
    magic: SYSTEM_API_MAGIC,
    expected_peer: ExpectedBackendPeer::SystemServer,
    verified_endpoint: VerifiedAckEndpoint::SystemApi,
};

const ACCESSIBILITY_ENDPOINT: FixedAckEndpoint = FixedAckEndpoint {
    socket: ACCESSIBILITY_SOCKET,
    magic: ACCESSIBILITY_MAGIC,
    expected_peer: ExpectedBackendPeer::AccessibilityService,
    verified_endpoint: VerifiedAckEndpoint::Accessibility,
};

/// Publish one System API operation replay ACK from one consumed sealed pipe.
pub(crate) fn acknowledge_system_api(
    pipe: SealedSystemApiAckIntentPipe,
) -> AckResult<VerifiedOperationReplayAck> {
    acknowledge_fixed(SYSTEM_API_ENDPOINT, pipe.pipe)
}

/// Publish one Accessibility operation replay ACK from one consumed sealed pipe.
pub(crate) fn acknowledge_accessibility(
    pipe: SealedAccessibilityAckIntentPipe,
) -> AckResult<VerifiedOperationReplayAck> {
    acknowledge_fixed(ACCESSIBILITY_ENDPOINT, pipe.pipe)
}

/// Publish an ACK only from the endpoint-specific operation replay-sync
/// context. This is distinct from the ordinary adapter domain and from the
/// legacy capability-publication replay-sync role.
pub(crate) fn acknowledge_from_replay_sync_context(
    prepared: &crate::operation_journal::PreparedReplaySyncOuterAck<'_>,
) -> AckResult<VerifiedOperationReplayAck> {
    let context = prepared.context();
    let inbox = prepared.inbox();
    let intent = CanonicalAckIntent::from_inbox(inbox)?;
    let endpoint = match context.adapter() {
        DirectOperationAdapter::SystemApi => SYSTEM_API_ENDPOINT,
        DirectOperationAdapter::Accessibility => ACCESSIBILITY_ENDPOINT,
    };
    let verified = acknowledge_fixed_intent(endpoint, intent)?;
    verified.validate_for(prepared)?;
    Ok(verified)
}

/// Perform the exact P0 System API ACK and return an opaque capability only
/// after the authenticated Android peer echoes the complete intent.
#[cfg(feature = "device-launch-package-conformance")]
pub(crate) fn acknowledge_system_api_for_device_conformance(
    inbox: &DirectOperationOuterAckInboxV3,
) -> AckResult<VerifiedDeviceConformanceReplayAck> {
    let intent = CanonicalAckIntent::from_inbox(inbox)?;
    let verified = acknowledge_fixed_intent(SYSTEM_API_ENDPOINT, intent)?;
    let capability = VerifiedDeviceConformanceReplayAck { verified };
    capability.validate_for_inbox(inbox)?;
    Ok(capability)
}

/// Recover the exact ACK capability after an ACK-response-loss or
/// compaction-response-loss restart. The consumed ACTIVATE result is opaque
/// and constructible only by the fixed, peer-authenticated System API client.
#[cfg(feature = "device-launch-package-conformance")]
pub(crate) fn recover_system_api_ack_for_device_conformance(
    inbox: &DirectOperationOuterAckInboxV3,
    activation: crate::android_operation_replay_control::DeviceConformanceActivation,
) -> AckResult<VerifiedDeviceConformanceReplayAck> {
    if !activation.android_ack_already_applied() {
        return Err(AndroidOperationReplayAckError::BackendHold(
            "P0 ACTIVATE did not prove the exact post-ACK state",
        ));
    }
    let verified = VerifiedOperationReplayAck {
        endpoint: VerifiedAckEndpoint::SystemApi,
        intent: CanonicalAckIntent::from_inbox(inbox)?,
    };
    let capability = VerifiedDeviceConformanceReplayAck { verified };
    capability.validate_for_inbox(inbox)?;
    Ok(capability)
}

fn acknowledge_fixed(
    endpoint: FixedAckEndpoint,
    pipe: SealedDaemonAckIntentPipe,
) -> AckResult<VerifiedOperationReplayAck> {
    let intent = read_canonical_intent(pipe)?;
    acknowledge_fixed_intent(endpoint, intent)
}

fn acknowledge_fixed_intent(
    endpoint: FixedAckEndpoint,
    intent: CanonicalAckIntent,
) -> AckResult<VerifiedOperationReplayAck> {
    let fixed_path = Path::new(endpoint.socket);
    let mut stream = connect_fixed_abstract_before(endpoint.socket, BACKEND_WRITE_TIMEOUT)?;
    uds::verify_connected_peer(fixed_path, &stream, endpoint.expected_peer)?;
    stream
        .set_read_timeout(Some(BACKEND_READ_TIMEOUT))
        .map_err(DirectToolError::from)?;
    stream
        .set_write_timeout(Some(BACKEND_WRITE_TIMEOUT))
        .map_err(DirectToolError::from)?;
    exchange_connected(endpoint, intent, &mut stream)
}

fn connect_fixed_abstract_before(
    socket: &str,
    timeout: Duration,
) -> std::result::Result<UnixStream, DirectToolError> {
    let name = socket.strip_prefix('@').ok_or_else(|| {
        DirectToolError::BackendUnavailable(
            "operation replay ACK endpoint is not one fixed abstract socket".to_string(),
        )
    })?;
    if name.is_empty() || name.as_bytes().contains(&0) {
        return Err(DirectToolError::BackendUnavailable(
            "operation replay ACK abstract socket name is invalid".to_string(),
        ));
    }
    // SAFETY: socket has no pointer arguments and returns one new descriptor.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw_fd < 0 {
        return Err(DirectToolError::BackendUnavailable(format!(
            "could not create bounded operation replay ACK socket: {}",
            io::Error::last_os_error()
        )));
    }
    // SAFETY: raw_fd is one successful socket result transferred exactly once.
    let socket_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let address = std::mem::MaybeUninit::<libc::sockaddr_un>::zeroed();
    // SAFETY: zeroed sockaddr_un is valid initialized storage before fields
    // and the exact bounded address length are populated below.
    let mut address = unsafe { address.assume_init() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if name.len() + 1 > address.sun_path.len() {
        return Err(DirectToolError::BackendUnavailable(
            "operation replay ACK abstract socket name is oversized".to_string(),
        ));
    }
    for (destination, source) in address.sun_path[1..].iter_mut().zip(name.bytes()) {
        *destination = source as libc::c_char;
    }
    let address_len = std::mem::offset_of!(libc::sockaddr_un, sun_path)
        .checked_add(1)
        .and_then(|length| length.checked_add(name.len()))
        .and_then(|length| libc::socklen_t::try_from(length).ok())
        .ok_or_else(|| {
            DirectToolError::BackendUnavailable(
                "operation replay ACK abstract address length overflowed".to_string(),
            )
        })?;
    let deadline = Instant::now() + timeout;
    // SAFETY: address points to an initialized AF_UNIX sockaddr and
    // address_len covers only the family, abstract NUL and exact name.
    let connected = unsafe {
        libc::connect(
            socket_fd.as_raw_fd(),
            (&raw const address).cast(),
            address_len,
        )
    };
    if connected != 0 {
        let error = io::Error::last_os_error();
        if !error
            .raw_os_error()
            .is_some_and(|code| code == libc::EINPROGRESS || code == libc::EAGAIN)
        {
            return Err(DirectToolError::BackendUnavailable(format!(
                "operation replay ACK connect failed: {error}"
            )));
        }
        poll_connect_before(socket_fd.as_raw_fd(), deadline)?;
    }
    let mut socket_error: libc::c_int = 0;
    let mut socket_error_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: socket_error and its length point to exact writable storage.
    if unsafe {
        libc::getsockopt(
            socket_fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut socket_error).cast(),
            &mut socket_error_len,
        )
    } != 0
        || socket_error_len as usize != std::mem::size_of::<libc::c_int>()
    {
        return Err(DirectToolError::BackendUnavailable(format!(
            "could not confirm operation replay ACK connect: {}",
            io::Error::last_os_error()
        )));
    }
    if socket_error != 0 {
        return Err(DirectToolError::BackendUnavailable(format!(
            "operation replay ACK connect failed: {}",
            io::Error::from_raw_os_error(socket_error)
        )));
    }
    // SAFETY: F_GETFL/F_SETFL operate on this live socket descriptor.
    let flags = unsafe { libc::fcntl(socket_fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe {
            libc::fcntl(
                socket_fd.as_raw_fd(),
                libc::F_SETFL,
                flags & !libc::O_NONBLOCK,
            )
        } < 0
    {
        return Err(DirectToolError::BackendUnavailable(format!(
            "could not seal operation replay ACK socket mode: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(UnixStream::from(socket_fd))
}

fn poll_connect_before(fd: RawFd, deadline: Instant) -> Result<(), DirectToolError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                DirectToolError::BackendUnavailable(
                    "operation replay ACK connect timed out".to_string(),
                )
            })?;
        let timeout_ms = remaining
            .as_millis()
            .saturating_add(u128::from(
                !remaining.subsec_nanos().is_multiple_of(1_000_000),
            ))
            .min(libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(DirectToolError::BackendUnavailable(
                    "operation replay ACK connect descriptor became invalid".to_string(),
                ));
            }
            if descriptor.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) != 0 {
                return Ok(());
            }
            return Err(DirectToolError::BackendUnavailable(
                "operation replay ACK connect reported an invalid event".to_string(),
            ));
        }
        if result == 0 {
            return Err(DirectToolError::BackendUnavailable(
                "operation replay ACK connect timed out".to_string(),
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(DirectToolError::BackendUnavailable(format!(
                "operation replay ACK connect poll failed: {error}"
            )));
        }
    }
}

fn read_canonical_intent(mut pipe: SealedDaemonAckIntentPipe) -> AckResult<CanonicalAckIntent> {
    validate_pipe_shape(&pipe.input)?;
    let deadline = Instant::now() + PIPE_READ_TIMEOUT;
    let mut frame = [0_u8; ACK_INTENT_BYTES];
    read_exact_pipe_before(&mut pipe.input, &mut frame, deadline)?;
    require_pipe_eof_before(&mut pipe.input, deadline)?;
    CanonicalAckIntent::decode(&frame)
}

fn validate_pipe_shape(input: &File) -> AckResult<()> {
    let metadata = input.metadata().map_err(DirectToolError::from)?;
    if !metadata.file_type().is_fifo() {
        return Err(AndroidOperationReplayAckError::IntentHold(
            "sealed daemon ACK descriptor is not a pipe",
        ));
    }
    // SAFETY: F_GETFL only reads descriptor flags from the live File.
    let flags = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(DirectToolError::from(io::Error::last_os_error()).into());
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(AndroidOperationReplayAckError::IntentHold(
            "sealed daemon ACK descriptor is not read-only",
        ));
    }
    Ok(())
}

fn read_exact_pipe_before(input: &mut File, output: &mut [u8], deadline: Instant) -> AckResult<()> {
    let mut offset = 0;
    while offset < output.len() {
        poll_pipe(input.as_raw_fd(), deadline)?;
        match input.read(&mut output[offset..]) {
            Ok(0) => {
                return Err(AndroidOperationReplayAckError::IntentHold(
                    "daemon ACK intent ended before 168 bytes",
                ));
            }
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(DirectToolError::from(error).into()),
        }
    }
    Ok(())
}

fn require_pipe_eof_before(input: &mut File, deadline: Instant) -> AckResult<()> {
    loop {
        poll_pipe(input.as_raw_fd(), deadline)?;
        let mut trailing = [0_u8; 1];
        match input.read(&mut trailing) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(AndroidOperationReplayAckError::IntentHold(
                    "daemon ACK intent has trailing bytes",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(DirectToolError::from(error).into()),
        }
    }
}

fn poll_pipe(fd: RawFd, deadline: Instant) -> AckResult<()> {
    loop {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(
            AndroidOperationReplayAckError::IntentHold("daemon ACK intent pipe timed out"),
        )?;
        let timeout_ms = remaining
            .as_millis()
            .saturating_add(u128::from(
                !remaining.subsec_nanos().is_multiple_of(1_000_000),
            ))
            .min(libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd for this live File.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(AndroidOperationReplayAckError::IntentHold(
                    "daemon ACK intent pipe descriptor is invalid",
                ));
            }
            if descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                return Ok(());
            }
            return Err(AndroidOperationReplayAckError::IntentHold(
                "daemon ACK intent pipe reported an invalid event",
            ));
        }
        if result == 0 {
            return Err(AndroidOperationReplayAckError::IntentHold(
                "daemon ACK intent pipe timed out",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(DirectToolError::from(error).into());
        }
    }
}

fn exchange_connected(
    endpoint: FixedAckEndpoint,
    intent: CanonicalAckIntent,
    stream: &mut UnixStream,
) -> AckResult<VerifiedOperationReplayAck> {
    let request = encode_ack_request(endpoint.magic, &intent);
    stream.write_all(&request).map_err(DirectToolError::from)?;
    stream.flush().map_err(DirectToolError::from)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(DirectToolError::from)?;
    let response = read_exact_backend_response(stream)?;
    let echoed = decode_ack_response(endpoint.magic, &response)?;
    if echoed != intent {
        return Err(AndroidOperationReplayAckError::BackendHold(
            "Android replay-control ACK echo differs from the durable daemon intent",
        ));
    }
    Ok(VerifiedOperationReplayAck {
        endpoint: endpoint.verified_endpoint,
        intent,
    })
}

fn encode_ack_request(magic: [u8; 8], intent: &CanonicalAckIntent) -> [u8; ACK_FRAME_BYTES] {
    let mut frame = [0_u8; ACK_FRAME_BYTES];
    frame[..8].copy_from_slice(&magic);
    frame[8] = VERSION;
    frame[9] = ACK_OPERATION;
    frame[10..12].copy_from_slice(&(ACK_INTENT_BYTES as u16).to_be_bytes());
    frame[HEADER_BYTES..].copy_from_slice(&intent.encode_payload());
    frame
}

fn read_exact_backend_response(stream: &mut UnixStream) -> AckResult<[u8; ACK_FRAME_BYTES]> {
    let mut frame = [0_u8; ACK_FRAME_BYTES];
    if let Err(error) = stream.read_exact(&mut frame) {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return Err(AndroidOperationReplayAckError::BackendHold(
                "Android replay-control ACK response is not exactly 180 bytes",
            ));
        }
        return Err(DirectToolError::from(error).into());
    }
    stream
        .set_read_timeout(Some(BACKEND_CLOSE_TIMEOUT))
        .map_err(DirectToolError::from)?;
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(frame),
        Ok(_) => Err(AndroidOperationReplayAckError::BackendHold(
            "Android replay-control ACK response has trailing bytes",
        )),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            Err(AndroidOperationReplayAckError::BackendHold(
                "Android replay-control ACK responder did not close",
            ))
        }
        Err(error) => Err(DirectToolError::from(error).into()),
    }
}

fn decode_ack_response(expected_magic: [u8; 8], frame: &[u8]) -> AckResult<CanonicalAckIntent> {
    if frame.len() != ACK_FRAME_BYTES {
        return Err(AndroidOperationReplayAckError::BackendHold(
            "Android replay-control ACK response is not exactly 180 bytes",
        ));
    }
    if frame[..8] != expected_magic {
        return Err(AndroidOperationReplayAckError::BackendHold(
            "Android replay-control ACK response magic mismatch",
        ));
    }
    if frame[8] != VERSION {
        return Err(AndroidOperationReplayAckError::BackendHold(
            "Android replay-control ACK response version mismatch",
        ));
    }
    if frame[9] != ACK_RESPONSE_OPERATION {
        return Err(AndroidOperationReplayAckError::BackendHold(
            "Android replay-control ACK response operation mismatch",
        ));
    }
    if u16::from_be_bytes([frame[10], frame[11]]) as usize != ACK_INTENT_BYTES {
        return Err(AndroidOperationReplayAckError::BackendHold(
            "Android replay-control ACK response payload length mismatch",
        ));
    }
    CanonicalAckIntent::decode(&frame[HEADER_BYTES..]).map_err(|_| {
        AndroidOperationReplayAckError::BackendHold(
            "Android replay-control ACK response payload is invalid",
        )
    })
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
impl SealedDaemonAckIntentPipe {
    fn for_test(input: File) -> Self {
        validate_pipe_shape(&input).unwrap();
        Self { input }
    }
}

#[cfg(test)]
impl SealedSystemApiAckIntentPipe {
    fn for_test(input: File) -> Self {
        Self {
            pipe: SealedDaemonAckIntentPipe::for_test(input),
        }
    }
}

#[cfg(test)]
impl SealedAccessibilityAckIntentPipe {
    fn for_test(input: File) -> Self {
        Self {
            pipe: SealedDaemonAckIntentPipe::for_test(input),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{FromRawFd as _, OwnedFd};
    use std::thread;

    use super::*;

    const EPOCH: &str = "0123456789abcdef0123456789abcdef";
    const ACK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CHAIN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const _: () = {
        assert!(DAEMON_ACK_INTENT_INHERITED_FD == 3);
        assert!(!OPERATION_EPOCH_REPLAY_RUNTIME_WIRED);
    };

    fn golden_intent_bytes() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ACK_INTENT_BYTES);
        bytes.extend_from_slice(EPOCH.as_bytes());
        bytes.extend_from_slice(&7_u64.to_be_bytes());
        bytes.extend_from_slice(ACK.as_bytes());
        bytes.extend_from_slice(CHAIN.as_bytes());
        assert_eq!(bytes.len(), ACK_INTENT_BYTES);
        bytes
    }

    fn golden_intent() -> CanonicalAckIntent {
        CanonicalAckIntent::decode(&golden_intent_bytes()).unwrap()
    }

    fn pipe_with_bytes(bytes: &[u8]) -> File {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors points to writable storage for the two pipe FDs.
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: pipe2 initialized both descriptors and ownership is split.
        let read_end = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        // SAFETY: pipe2 initialized both descriptors and ownership is split.
        let write_end = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        let mut writer = File::from(write_end);
        writer.write_all(bytes).unwrap();
        drop(writer);
        File::from(read_end)
    }

    fn response_frame(magic: [u8; 8], intent: &CanonicalAckIntent) -> Vec<u8> {
        let mut response = Vec::with_capacity(ACK_FRAME_BYTES);
        response.extend_from_slice(&magic);
        response.extend_from_slice(&[VERSION, ACK_RESPONSE_OPERATION, 0, ACK_INTENT_BYTES as u8]);
        response.extend_from_slice(&intent.encode_payload());
        assert_eq!(response.len(), ACK_FRAME_BYTES);
        response
    }

    fn assert_intent_hold(bytes: &[u8]) {
        assert!(matches!(
            CanonicalAckIntent::decode(bytes),
            Err(AndroidOperationReplayAckError::IntentHold(_))
        ));
    }

    fn assert_backend_hold(frame: &[u8]) {
        assert!(matches!(
            decode_ack_response(SYSTEM_API_MAGIC, frame),
            Err(AndroidOperationReplayAckError::BackendHold(_))
        ));
    }

    #[test]
    fn fixed_abstract_connect_is_nonblocking_and_deadline_bounded() {
        assert!(connect_fixed_abstract_before("pathname", Duration::from_millis(20)).is_err());
        assert!(
            connect_fixed_abstract_before(
                &format!("@{}", "x".repeat(108)),
                Duration::from_millis(20),
            )
            .is_err()
        );
        let absent = format!(
            "@trillionnium_operation_replay_ack_absent_{}",
            std::process::id()
        );
        let started = Instant::now();
        assert!(connect_fixed_abstract_before(&absent, Duration::from_millis(20)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));

        let source = include_str!("android_operation_replay_ack.rs");
        assert!(source.contains("libc::SOCK_NONBLOCK"));
        assert!(source.contains("poll_connect_before"));
        let legacy_blocking_connect = ["uds::", "connect(fixed_path)"].concat();
        assert!(!source.contains(&legacy_blocking_connect));
    }

    #[test]
    fn java_rust_dual_ack_golden_vectors_are_exact() {
        let payload = golden_intent_bytes();
        let intent = CanonicalAckIntent::decode(&payload).unwrap();
        assert_eq!(intent.epoch, EPOCH);
        assert_eq!(intent.last_journal_sequence, 7);
        assert_eq!(intent.acknowledgement_sha256, ACK);
        assert_eq!(intent.authenticated_ack_chain_sha256, CHAIN);

        for (magic, socket, peer) in [
            (
                SYSTEM_API_MAGIC,
                SYSTEM_API_SOCKET,
                ExpectedBackendPeer::SystemServer,
            ),
            (
                ACCESSIBILITY_MAGIC,
                ACCESSIBILITY_SOCKET,
                ExpectedBackendPeer::AccessibilityService,
            ),
        ] {
            let encoded = encode_ack_request(magic, &intent);
            let mut golden_request = Vec::with_capacity(ACK_FRAME_BYTES);
            golden_request.extend_from_slice(&magic);
            golden_request.extend_from_slice(&[1, 2, 0, 168]);
            golden_request.extend_from_slice(&payload);
            assert_eq!(encoded.as_slice(), golden_request);
            assert_eq!(encoded.len(), 180);

            let response = response_frame(magic, &intent);
            assert_eq!(decode_ack_response(magic, &response).unwrap(), intent);
            let endpoint = if magic == SYSTEM_API_MAGIC {
                SYSTEM_API_ENDPOINT
            } else {
                ACCESSIBILITY_ENDPOINT
            };
            assert_eq!(endpoint.socket, socket);
            assert_eq!(endpoint.magic, magic);
            assert_eq!(endpoint.expected_peer, peer);
        }

        let system = response_frame(SYSTEM_API_MAGIC, &intent);
        let accessibility = response_frame(ACCESSIBILITY_MAGIC, &intent);
        assert!(decode_ack_response(ACCESSIBILITY_MAGIC, &system).is_err());
        assert!(decode_ack_response(SYSTEM_API_MAGIC, &accessibility).is_err());
    }

    #[test]
    fn daemon_intent_and_backend_echo_reject_every_field_tamper() {
        let payload = golden_intent_bytes();
        assert_intent_hold(&payload[..payload.len() - 1]);
        let mut extra = payload.clone();
        extra.push(0);
        assert_intent_hold(&extra);

        let mut uppercase_epoch = payload.clone();
        uppercase_epoch[0] = b'A';
        assert_intent_hold(&uppercase_epoch);
        let mut zero_epoch = payload.clone();
        zero_epoch[..EPOCH_BYTES].fill(b'0');
        assert_intent_hold(&zero_epoch);
        let mut zero_sequence = payload.clone();
        zero_sequence[EPOCH_BYTES..EPOCH_BYTES + SEQUENCE_BYTES].fill(0);
        assert_intent_hold(&zero_sequence);
        let mut oversized_sequence = payload.clone();
        oversized_sequence[EPOCH_BYTES..EPOCH_BYTES + SEQUENCE_BYTES]
            .copy_from_slice(&u64::MAX.to_be_bytes());
        assert_intent_hold(&oversized_sequence);
        let mut zero_ack = payload.clone();
        zero_ack[EPOCH_BYTES + SEQUENCE_BYTES..EPOCH_BYTES + SEQUENCE_BYTES + DIGEST_BYTES]
            .fill(b'0');
        assert_intent_hold(&zero_ack);
        let mut zero_chain = payload.clone();
        zero_chain[EPOCH_BYTES + SEQUENCE_BYTES + DIGEST_BYTES..].fill(b'0');
        assert_intent_hold(&zero_chain);
        let mut uppercase_chain = payload;
        uppercase_chain[EPOCH_BYTES + SEQUENCE_BYTES + DIGEST_BYTES] = b'B';
        assert_intent_hold(&uppercase_chain);

        let pristine = response_frame(SYSTEM_API_MAGIC, &golden_intent());
        assert_backend_hold(&pristine[..pristine.len() - 1]);
        let mut trailing = pristine.clone();
        trailing.push(0);
        assert_backend_hold(&trailing);
        for index in [0, 8, 9, 10, 11] {
            let mut tampered = pristine.clone();
            tampered[index] ^= 1;
            assert_backend_hold(&tampered);
        }
        let mut payload_drift = pristine;
        payload_drift[HEADER_BYTES + EPOCH_BYTES + SEQUENCE_BYTES] = b'c';
        let decoded = decode_ack_response(SYSTEM_API_MAGIC, &payload_drift).unwrap();
        assert_ne!(decoded, golden_intent());
    }

    #[test]
    fn sealed_pipe_requires_one_exact_intent_and_eof() {
        let exact = SealedDaemonAckIntentPipe::for_test(pipe_with_bytes(&golden_intent_bytes()));
        assert_eq!(read_canonical_intent(exact).unwrap(), golden_intent());

        let short = SealedDaemonAckIntentPipe::for_test(pipe_with_bytes(
            &golden_intent_bytes()[..ACK_INTENT_BYTES - 1],
        ));
        assert!(matches!(
            read_canonical_intent(short),
            Err(AndroidOperationReplayAckError::IntentHold(_))
        ));

        let mut trailing = golden_intent_bytes();
        trailing.push(0);
        let extra = SealedDaemonAckIntentPipe::for_test(pipe_with_bytes(&trailing));
        assert!(matches!(
            read_canonical_intent(extra),
            Err(AndroidOperationReplayAckError::IntentHold(_))
        ));
    }

    #[test]
    fn backend_reader_requires_one_exact_180_byte_response_and_eof() {
        for (bytes, accepted) in [
            (response_frame(SYSTEM_API_MAGIC, &golden_intent()), true),
            (vec![0_u8; ACK_FRAME_BYTES - 1], false),
            (vec![0_u8; ACK_FRAME_BYTES + 1], false),
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let writer = thread::spawn(move || {
                server.write_all(&bytes).unwrap();
            });
            let result = read_exact_backend_response(&mut client);
            writer.join().unwrap();
            assert_eq!(result.is_ok(), accepted);
        }
    }

    #[test]
    fn one_shot_helpers_require_exact_echo_and_backend_eof() {
        for endpoint in [SYSTEM_API_ENDPOINT, ACCESSIBILITY_ENDPOINT] {
            let pipe = SealedDaemonAckIntentPipe::for_test(pipe_with_bytes(&golden_intent_bytes()));
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let server_endpoint = endpoint;
            let server_thread = thread::spawn(move || {
                let mut request = [0_u8; ACK_FRAME_BYTES];
                server.read_exact(&mut request).unwrap();
                let expected = encode_ack_request(server_endpoint.magic, &golden_intent());
                assert_eq!(request, expected);
                let mut trailing = [0_u8; 1];
                assert_eq!(server.read(&mut trailing).unwrap(), 0);
                server
                    .write_all(&response_frame(server_endpoint.magic, &golden_intent()))
                    .unwrap();
            });
            let intent = read_canonical_intent(pipe).unwrap();
            let verified = exchange_connected(endpoint, intent, &mut client).unwrap();
            assert_eq!(verified.endpoint, endpoint.verified_endpoint);
            assert_eq!(verified.intent, golden_intent());
            server_thread.join().unwrap();
        }

        let pipe = SealedDaemonAckIntentPipe::for_test(pipe_with_bytes(&golden_intent_bytes()));
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let server_thread = thread::spawn(move || {
            let mut request = [0_u8; ACK_FRAME_BYTES];
            server.read_exact(&mut request).unwrap();
            assert_eq!(server.read(&mut [0_u8; 1]).unwrap(), 0);
            let mut drifted = golden_intent();
            drifted.last_journal_sequence += 1;
            server
                .write_all(&response_frame(SYSTEM_API_MAGIC, &drifted))
                .unwrap();
        });
        let intent = read_canonical_intent(pipe).unwrap();
        assert!(matches!(
            exchange_connected(SYSTEM_API_ENDPOINT, intent, &mut client),
            Err(AndroidOperationReplayAckError::BackendHold(_))
        ));
        server_thread.join().unwrap();
    }

    #[test]
    fn android_ack_applied_but_response_lost_never_reports_local_success() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let server_thread = thread::spawn(move || {
            let mut request = [0_u8; ACK_FRAME_BYTES];
            server.read_exact(&mut request).unwrap();
            assert_eq!(
                request,
                encode_ack_request(SYSTEM_API_MAGIC, &golden_intent())
            );
            assert_eq!(server.read(&mut [0_u8; 1]).unwrap(), 0);
            // Simulate SystemServer durably applying the exact ACK and then
            // crashing before its echo reaches the adapter.
        });
        assert!(matches!(
            exchange_connected(SYSTEM_API_ENDPOINT, golden_intent(), &mut client),
            Err(AndroidOperationReplayAckError::BackendHold(_))
        ));
        server_thread.join().unwrap();
    }

    #[test]
    fn production_surface_is_operation_only_sealed_and_source_disabled() {
        assert!(SOURCE_STATUS.contains("source_disabled"));

        let source = include_str!("android_operation_replay_ack.rs");
        let crate_visibility = ["pub", "(crate)"].concat();
        let system_signature =
            [crate_visibility.as_str(), " fn acknowledge_", "system_api("].concat();
        let accessibility_signature = [
            crate_visibility.as_str(),
            " fn acknowledge_",
            "accessibility(",
        ]
        .concat();
        let replay_sync_signature = [
            crate_visibility.as_str(),
            " fn acknowledge_from_replay_sync_context(",
        ]
        .concat();
        let test_constructor = [crate_visibility.as_str(), " fn for_replay_sync_test("].concat();
        let crate_function = [crate_visibility.as_str(), " fn "].concat();
        let peer_verifier = ["uds::verify_", "connected_peer"].concat();
        let capability_publication = ["root_publication_", "transport"].concat();
        let custody_store = ["DirectOperation", "CustodyStore"].concat();
        let delete_api_needle = ["remove_", "file"].concat();
        let link_delete_needle = ["un", "link"].concat();
        assert_eq!(source.matches(&system_signature).count(), 1);
        assert_eq!(source.matches(&accessibility_signature).count(), 1);
        assert_eq!(source.matches(&replay_sync_signature).count(), 1);
        assert_eq!(source.matches(&test_constructor).count(), 1);
        assert_eq!(source.matches(&crate_function).count(), 10);
        assert_eq!(source.matches(&peer_verifier).count(), 1);
        assert!(!source.contains(&capability_publication));
        assert!(!source.contains(&custody_store));
        assert!(!source.contains(&delete_api_needle));
        assert!(!source.contains(&link_delete_needle));
        assert!(!source.contains(&["std::", "env"].concat()));
        assert!(!source.contains(&["args", "_os"].concat()));
        assert!(!source.contains(&["production_", "endpoint"].concat()));

        let system_pipe =
            SealedSystemApiAckIntentPipe::for_test(pipe_with_bytes(&golden_intent_bytes()));
        let accessibility_pipe =
            SealedAccessibilityAckIntentPipe::for_test(pipe_with_bytes(&golden_intent_bytes()));
        assert_eq!(
            read_canonical_intent(system_pipe.pipe).unwrap(),
            golden_intent()
        );
        assert_eq!(
            read_canonical_intent(accessibility_pipe.pipe).unwrap(),
            golden_intent()
        );
    }
}
