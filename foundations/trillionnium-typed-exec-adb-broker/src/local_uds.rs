//! Authenticated local Unix-seqpacket framing for the host foundation.
//!
//! The server core authenticates kernel `SO_PEERCRED`, then parses one
//! canonical, bounded request packet against a fixed supervisor-owned
//! allowlist. It does not bind a product socket or dispatch an execution
//! backend. Typed ADB and every mutation remain closed.

#![allow(dead_code)] // Intentionally not exported into the product workspace.

use std::collections::BTreeMap;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::{
    BrokerBindingIdentityV1, MAX_REQUEST_WIRE_BYTES, MAX_RESPONSE_WIRE_BYTES, ProtocolError,
    TypedBrokerOperationV1, TypedBrokerRequestV1, principal,
};

const LOCAL_REQUEST_ENVELOPE_SCHEMA: &str = "trillionnium.typed-broker-local-request.v1";
const MAX_LOCAL_REQUEST_BODY_BYTES: usize = MAX_REQUEST_WIRE_BYTES + 8 * 1024;
const FRAME_HEADER_BYTES: usize = 4;
const MAX_FRAME_IO_DEADLINE_MS: u64 = 5_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalRequestEnvelopeV1 {
    schema: String,
    binding: BrokerBindingIdentityV1,
    request: TypedBrokerRequestV1,
}

impl LocalRequestEnvelopeV1 {
    fn derive(
        binding: BrokerBindingIdentityV1,
        request: TypedBrokerRequestV1,
    ) -> Result<Self, LocalUdsError> {
        let value = Self {
            schema: LOCAL_REQUEST_ENVELOPE_SCHEMA.to_string(),
            binding,
            request,
        };
        value.validate_identity()?;
        Ok(value)
    }

    fn validate_identity(&self) -> Result<(), LocalUdsError> {
        if self.schema != LOCAL_REQUEST_ENVELOPE_SCHEMA {
            return Err(LocalUdsError::EnvelopeInvalid);
        }
        self.binding.validate()?;
        self.request.validate_identity_for(&self.binding)?;
        Ok(())
    }

    fn canonical_body(&self) -> Result<Vec<u8>, LocalUdsError> {
        self.validate_identity()?;
        let bytes = serde_json::to_vec(self).map_err(|_| LocalUdsError::EnvelopeInvalid)?;
        if bytes.is_empty() || bytes.len() > MAX_LOCAL_REQUEST_BODY_BYTES {
            return Err(LocalUdsError::FrameLengthDenied);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerCredentialsV1 {
    pid: u32,
    uid: u32,
    gid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixedPeerRuleV1 {
    provider_id: String,
    agent_id: String,
    pid: u32,
    uid: u32,
    gid: u32,
}

impl FixedPeerRuleV1 {
    fn validate(&self) -> bool {
        let Some(descriptor) = principal(&self.provider_id, &self.agent_id) else {
            return false;
        };
        self.pid != 0 && self.uid == descriptor.uid && self.gid == descriptor.gid
    }
}

#[derive(Clone, Debug)]
struct FixedPeerAllowlistV1 {
    rules: BTreeMap<(String, String), FixedPeerRuleV1>,
}

impl FixedPeerAllowlistV1 {
    fn new(rules: Vec<FixedPeerRuleV1>) -> Result<Self, LocalUdsError> {
        if rules.is_empty() {
            return Err(LocalUdsError::PeerAllowlistInvalid);
        }
        let mut indexed = BTreeMap::new();
        for rule in rules {
            if !rule.validate() {
                return Err(LocalUdsError::PeerAllowlistInvalid);
            }
            let key = (rule.provider_id.clone(), rule.agent_id.clone());
            if indexed.insert(key, rule).is_some() {
                return Err(LocalUdsError::PeerAllowlistInvalid);
            }
        }
        Ok(Self { rules: indexed })
    }

    fn authenticate(
        &self,
        binding: &BrokerBindingIdentityV1,
        observed: PeerCredentialsV1,
    ) -> Result<(), LocalUdsError> {
        let key = (binding.provider_id.clone(), binding.agent_id.clone());
        let expected = self
            .rules
            .get(&key)
            .ok_or(LocalUdsError::PeerCredentialDenied)?;
        if (expected.pid, expected.uid, expected.gid) != (observed.pid, observed.uid, observed.gid)
        {
            return Err(LocalUdsError::PeerCredentialDenied);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticatedLocalRequestV1 {
    peer: PeerCredentialsV1,
    binding: BrokerBindingIdentityV1,
    request: TypedBrokerRequestV1,
    canonical_body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct AuthenticatedLocalUdsServerCoreV1 {
    allowlist: FixedPeerAllowlistV1,
}

impl AuthenticatedLocalUdsServerCoreV1 {
    fn new(allowlist: FixedPeerAllowlistV1) -> Self {
        Self { allowlist }
    }

    fn read_one(
        &self,
        connection: BorrowedFd<'_>,
        now_boot_ms: u64,
        frame_deadline_boot_ms: u64,
    ) -> Result<AuthenticatedLocalRequestV1, LocalUdsError> {
        validate_frame_deadline(now_boot_ms, frame_deadline_boot_ms)?;
        validate_seqpacket_cloexec(connection)?;
        let peer = peer_credentials(connection)?;
        self.read_one_after_boundary_validation(
            connection,
            peer,
            now_boot_ms,
            frame_deadline_boot_ms,
        )
    }

    #[cfg(test)]
    fn read_one_with_fixture_peer_for_test(
        &self,
        connection: BorrowedFd<'_>,
        peer: PeerCredentialsV1,
        now_boot_ms: u64,
        frame_deadline_boot_ms: u64,
    ) -> Result<AuthenticatedLocalRequestV1, LocalUdsError> {
        validate_frame_deadline(now_boot_ms, frame_deadline_boot_ms)?;
        validate_seqpacket_cloexec(connection)?;
        self.read_one_after_boundary_validation(
            connection,
            peer,
            now_boot_ms,
            frame_deadline_boot_ms,
        )
    }

    fn read_one_after_boundary_validation(
        &self,
        connection: BorrowedFd<'_>,
        peer: PeerCredentialsV1,
        now_boot_ms: u64,
        frame_deadline_boot_ms: u64,
    ) -> Result<AuthenticatedLocalRequestV1, LocalUdsError> {
        let timeout = Duration::from_millis(frame_deadline_boot_ms - now_boot_ms);
        let packet = recv_one_packet(
            connection.as_raw_fd(),
            FRAME_HEADER_BYTES + MAX_LOCAL_REQUEST_BODY_BYTES,
            timeout,
        )?;
        let body = decode_length_prefixed_packet(&packet, MAX_LOCAL_REQUEST_BODY_BYTES)?;
        let envelope: LocalRequestEnvelopeV1 =
            serde_json::from_slice(body).map_err(|_| LocalUdsError::EnvelopeInvalid)?;
        envelope.validate_identity()?;
        if envelope.canonical_body()? != body {
            return Err(LocalUdsError::EnvelopeInvalid);
        }
        self.allowlist.authenticate(&envelope.binding, peer)?;
        envelope
            .request
            .validate_first_delivery_for(&envelope.binding, now_boot_ms)?;
        if envelope.request.operation_id
            != TypedBrokerOperationV1::ExecInspectBuildFingerprintUserdebugV1
        {
            return Err(LocalUdsError::OperationBackendHeld);
        }
        Ok(AuthenticatedLocalRequestV1 {
            peer,
            binding: envelope.binding,
            request: envelope.request,
            canonical_body: body.to_vec(),
        })
    }
}

fn validate_frame_deadline(now: u64, deadline: u64) -> Result<(), LocalUdsError> {
    let remaining = deadline
        .checked_sub(now)
        .ok_or(LocalUdsError::FrameDeadlineDenied)?;
    if remaining == 0 || remaining > MAX_FRAME_IO_DEADLINE_MS {
        return Err(LocalUdsError::FrameDeadlineDenied);
    }
    Ok(())
}

fn validate_seqpacket_cloexec(connection: BorrowedFd<'_>) -> Result<(), LocalUdsError> {
    let fd = connection.as_raw_fd();
    let mut socket_type: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: socket_type and length are valid writable storage and fd is borrowed.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::addr_of_mut!(socket_type).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    if result != 0 || length as usize != size_of::<libc::c_int>() {
        return Err(LocalUdsError::Io(io::Error::last_os_error()));
    }
    // SAFETY: F_GETFD reads descriptor flags and does not mutate memory.
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(LocalUdsError::Io(io::Error::last_os_error()));
    }
    if socket_type != libc::SOCK_SEQPACKET || descriptor_flags & libc::FD_CLOEXEC == 0 {
        return Err(LocalUdsError::SocketBoundaryDenied);
    }
    Ok(())
}

fn peer_credentials(connection: BorrowedFd<'_>) -> Result<PeerCredentialsV1, LocalUdsError> {
    // SAFETY: ucred is plain-old-data and zero is a valid initial representation.
    let mut credential: libc::ucred = unsafe { zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credential/length are valid writable storage and fd is borrowed.
    let result = unsafe {
        libc::getsockopt(
            connection.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credential).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    if result != 0 || length as usize != size_of::<libc::ucred>() {
        return Err(LocalUdsError::Io(io::Error::last_os_error()));
    }
    if credential.pid <= 0 {
        return Err(LocalUdsError::PeerCredentialDenied);
    }
    Ok(PeerCredentialsV1 {
        pid: credential.pid as u32,
        uid: credential.uid,
        gid: credential.gid,
    })
}

fn decode_length_prefixed_packet(
    packet: &[u8],
    maximum_body: usize,
) -> Result<&[u8], LocalUdsError> {
    if packet.len() < FRAME_HEADER_BYTES {
        return Err(LocalUdsError::FrameLengthDenied);
    }
    let declared = u32::from_be_bytes(
        packet[..FRAME_HEADER_BYTES]
            .try_into()
            .map_err(|_| LocalUdsError::FrameLengthDenied)?,
    ) as usize;
    if declared == 0 || declared > maximum_body || declared != packet.len() - FRAME_HEADER_BYTES {
        return Err(LocalUdsError::FrameLengthDenied);
    }
    Ok(&packet[FRAME_HEADER_BYTES..])
}

fn encode_length_prefixed_packet(body: &[u8], maximum: usize) -> Result<Vec<u8>, LocalUdsError> {
    if body.is_empty() || body.len() > maximum || body.len() > u32::MAX as usize {
        return Err(LocalUdsError::FrameLengthDenied);
    }
    let mut packet = Vec::with_capacity(FRAME_HEADER_BYTES + body.len());
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    packet.extend_from_slice(body);
    Ok(packet)
}

fn recv_one_packet(fd: RawFd, maximum: usize, timeout: Duration) -> Result<Vec<u8>, LocalUdsError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(LocalUdsError::FrameDeadlineDenied)?;
    let mut buffer = vec![0_u8; maximum + 1];
    loop {
        wait_ready(fd, libc::POLLIN, deadline)?;
        // SAFETY: buffer is writable for its full length; fd is an authenticated
        // seqpacket socket. MSG_TRUNC returns the complete packet length.
        let received = unsafe {
            libc::recv(
                fd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::Interrupted
            {
                continue;
            }
            return Err(LocalUdsError::Io(error));
        }
        if received == 0 {
            return Err(LocalUdsError::PeerClosed);
        }
        let received = received as usize;
        if received > maximum {
            return Err(LocalUdsError::FrameLengthDenied);
        }
        buffer.truncate(received);
        return Ok(buffer);
    }
}

fn send_one_packet(fd: RawFd, packet: &[u8], timeout: Duration) -> Result<(), LocalUdsError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(LocalUdsError::FrameDeadlineDenied)?;
    loop {
        wait_ready(fd, libc::POLLOUT, deadline)?;
        // SAFETY: packet is readable for its complete length and fd is a socket.
        let sent = unsafe {
            libc::send(
                fd,
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::Interrupted
            {
                continue;
            }
            return Err(LocalUdsError::Io(error));
        }
        if sent as usize != packet.len() {
            return Err(LocalUdsError::FrameLengthDenied);
        }
        return Ok(());
    }
}

fn wait_ready(fd: RawFd, events: libc::c_short, deadline: Instant) -> Result<(), LocalUdsError> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(LocalUdsError::FrameIoTimedOut);
        }
        let remaining = deadline.duration_since(now);
        let timeout_ms = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        let mut poll_fd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: poll_fd is valid writable storage for exactly one entry.
        let result = unsafe { libc::poll(std::ptr::addr_of_mut!(poll_fd), 1, timeout_ms) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(LocalUdsError::Io(error));
        }
        if result == 0 {
            return Err(LocalUdsError::FrameIoTimedOut);
        }
        if poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(LocalUdsError::SocketBoundaryDenied);
        }
        if poll_fd.revents & events != 0 {
            return Ok(());
        }
    }
}

fn send_request_envelope(
    connection: BorrowedFd<'_>,
    envelope: &LocalRequestEnvelopeV1,
    timeout: Duration,
) -> Result<(), LocalUdsError> {
    validate_seqpacket_cloexec(connection)?;
    let body = envelope.canonical_body()?;
    let packet = encode_length_prefixed_packet(&body, MAX_LOCAL_REQUEST_BODY_BYTES)?;
    send_one_packet(connection.as_raw_fd(), &packet, timeout)
}

fn send_response_wire(
    connection: BorrowedFd<'_>,
    response_wire: &[u8],
    timeout: Duration,
) -> Result<(), LocalUdsError> {
    validate_seqpacket_cloexec(connection)?;
    let packet = encode_length_prefixed_packet(response_wire, MAX_RESPONSE_WIRE_BYTES)?;
    send_one_packet(connection.as_raw_fd(), &packet, timeout)
}

#[derive(Debug, Error)]
enum LocalUdsError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("local request envelope is malformed or noncanonical")]
    EnvelopeInvalid,
    #[error("local request frame length is invalid")]
    FrameLengthDenied,
    #[error("local frame deadline is expired or exceeds the fixed bound")]
    FrameDeadlineDenied,
    #[error("local frame I/O timed out")]
    FrameIoTimedOut,
    #[error("local socket is not a CLOEXEC Unix seqpacket boundary")]
    SocketBoundaryDenied,
    #[error("fixed peer allowlist is invalid")]
    PeerAllowlistInvalid,
    #[error("SO_PEERCRED PID/UID/GID is not in the fixed allowlist")]
    PeerCredentialDenied,
    #[error("typed ADB and every non-getprop backend remain HOLD")]
    OperationBackendHeld,
    #[error("local peer closed before one complete request packet")]
    PeerClosed,
    #[error("local UDS operation failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};

    use crate::protocol::{
        BINDING_IDENTITY_SCHEMA, BrokerBindingIdentityV1, CODEX, PrincipalDescriptor,
        TypedBrokerOperationV1, TypedBrokerRequestV1, sha256_bytes,
    };

    use super::*;

    fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1, -1];
        // SAFETY: fds has room for exactly two descriptors; on success each fd
        // is transferred once into a separate OwnedFd.
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0, "socketpair: {}", io::Error::last_os_error());
        // SAFETY: socketpair returned two distinct owned descriptors.
        let first = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: socketpair returned two distinct owned descriptors.
        let second = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        (first, second)
    }

    fn digest(seed: &str) -> String {
        sha256_bytes(seed.as_bytes())
    }

    fn binding() -> BrokerBindingIdentityV1 {
        BrokerBindingIdentityV1 {
            schema: BINDING_IDENTITY_SCHEMA.to_string(),
            provider_id: CODEX.provider_id.to_string(),
            agent_id: CODEX.agent_id.to_string(),
            direct_binding_sha256: digest("binding"),
            invocation_id: format!("inv:{}", digest("invocation")),
            delivery_provider_attempt_id: format!("attempt:{}", digest("attempt")),
            agent_executable_sha256: digest("agent-executable"),
        }
    }

    fn request(
        binding: &BrokerBindingIdentityV1,
        operation: TypedBrokerOperationV1,
    ) -> TypedBrokerRequestV1 {
        TypedBrokerRequestV1::derive(binding, 1, operation, 15_000).unwrap()
    }

    fn credentials() -> PeerCredentialsV1 {
        PeerCredentialsV1 {
            pid: std::process::id(),
            // SAFETY: getuid/getgid are side-effect free and have no preconditions.
            uid: unsafe { libc::geteuid() },
            // SAFETY: getuid/getgid are side-effect free and have no preconditions.
            gid: unsafe { libc::getegid() },
        }
    }

    fn fixed_credentials(descriptor: PrincipalDescriptor, pid: u32) -> PeerCredentialsV1 {
        PeerCredentialsV1 {
            pid,
            uid: descriptor.uid,
            gid: descriptor.gid,
        }
    }

    fn rule(descriptor: PrincipalDescriptor, pid: u32) -> FixedPeerRuleV1 {
        FixedPeerRuleV1 {
            provider_id: descriptor.provider_id.to_string(),
            agent_id: descriptor.agent_id.to_string(),
            pid,
            uid: descriptor.uid,
            gid: descriptor.gid,
        }
    }

    fn server(pid: u32) -> AuthenticatedLocalUdsServerCoreV1 {
        AuthenticatedLocalUdsServerCoreV1::new(
            FixedPeerAllowlistV1::new(vec![rule(CODEX, pid)]).unwrap(),
        )
    }

    #[test]
    fn fixed_peer_rules_accept_exact_codex_provision() {
        for descriptor in [CODEX] {
            let provision = rule(descriptor, 4_242);
            assert!(provision.validate());
            assert!(FixedPeerAllowlistV1::new(vec![provision]).is_ok());
        }
    }

    #[test]
    fn fixed_peer_rules_reject_wrong_and_cross_principal_provisions() {
        let mut wrong_uid = rule(CODEX, 4_242);
        wrong_uid.uid = CODEX.uid + 1;
        let mut wrong_gid = rule(CODEX, 4_242);
        wrong_gid.gid = CODEX.gid + 1;
        let mut crossed_identity = rule(CODEX, 4_242);
        crossed_identity.agent_id = "unregistered-agent".to_string();
        let mut crossed_credentials = rule(CODEX, 4_242);
        crossed_credentials.uid = CODEX.uid + 1;
        crossed_credentials.gid = CODEX.gid + 1;

        for provision in [
            wrong_uid,
            wrong_gid,
            crossed_identity,
            crossed_credentials,
            rule(CODEX, 0),
        ] {
            assert!(!provision.validate());
            assert!(matches!(
                FixedPeerAllowlistV1::new(vec![provision]),
                Err(LocalUdsError::PeerAllowlistInvalid)
            ));
        }
    }

    #[test]
    fn seqpacket_frame_admits_exact_fixed_peer_and_getprop_request() {
        let (client, accepted) = seqpacket_pair();
        let binding = binding();
        let request = request(
            &binding,
            TypedBrokerOperationV1::ExecInspectBuildFingerprintUserdebugV1,
        );
        let envelope = LocalRequestEnvelopeV1::derive(binding.clone(), request.clone()).unwrap();
        send_request_envelope(client.as_fd(), &envelope, Duration::from_secs(1)).unwrap();
        let peer = fixed_credentials(CODEX, credentials().pid);
        let authenticated = server(peer.pid)
            .read_one_with_fixture_peer_for_test(accepted.as_fd(), peer, 10_001, 15_000)
            .unwrap();
        assert_eq!(authenticated.peer, peer);
        assert_eq!(authenticated.binding, binding);
        assert_eq!(authenticated.request, request);
        assert_eq!(
            authenticated.canonical_body,
            envelope.canonical_body().unwrap()
        );
    }

    #[test]
    fn pid_uid_and_gid_are_bound_to_fixed_allowlist() {
        let expected = fixed_credentials(CODEX, 4_242);
        let allowlist = FixedPeerAllowlistV1::new(vec![rule(CODEX, expected.pid)]).unwrap();
        assert!(allowlist.authenticate(&binding(), expected).is_ok());
        for wrong in [
            PeerCredentialsV1 {
                pid: expected.pid + 1,
                ..expected
            },
            PeerCredentialsV1 {
                uid: CODEX.uid + 1,
                ..expected
            },
            PeerCredentialsV1 {
                gid: CODEX.gid + 1,
                ..expected
            },
        ] {
            assert!(matches!(
                allowlist.authenticate(&binding(), wrong),
                Err(LocalUdsError::PeerCredentialDenied)
            ));
        }
    }

    #[test]
    fn typed_adb_frame_parses_but_backend_remains_hold() {
        let (client, accepted) = seqpacket_pair();
        let binding = binding();
        let envelope = LocalRequestEnvelopeV1::derive(
            binding.clone(),
            request(
                &binding,
                TypedBrokerOperationV1::AdbInspectPackageSettingsUserdebugV1,
            ),
        )
        .unwrap();
        send_request_envelope(client.as_fd(), &envelope, Duration::from_secs(1)).unwrap();
        let peer = fixed_credentials(CODEX, credentials().pid);
        assert!(matches!(
            server(peer.pid).read_one_with_fixture_peer_for_test(
                accepted.as_fd(),
                peer,
                10_001,
                15_000
            ),
            Err(LocalUdsError::OperationBackendHeld)
        ));
    }

    #[test]
    fn malformed_mismatched_and_oversized_frames_fail_closed() {
        for packet in [vec![0, 0, 0, 7, b'{', b'}'], {
            let mut value = vec![0_u8; FRAME_HEADER_BYTES + MAX_LOCAL_REQUEST_BODY_BYTES + 1];
            let body_length = value.len() - FRAME_HEADER_BYTES;
            value[..4].copy_from_slice(&(body_length as u32).to_be_bytes());
            value
        }] {
            let (client, accepted) = seqpacket_pair();
            send_one_packet(client.as_raw_fd(), &packet, Duration::from_secs(1)).unwrap();
            assert!(matches!(
                server(credentials().pid).read_one(accepted.as_fd(), 10_001, 15_000),
                Err(LocalUdsError::FrameLengthDenied)
            ));
        }
    }

    #[test]
    fn expired_and_overlong_frame_deadlines_are_rejected_before_read() {
        for deadline in [10_000, 15_002] {
            let (_client, accepted) = seqpacket_pair();
            assert!(matches!(
                server(credentials().pid).read_one(accepted.as_fd(), 10_001, deadline),
                Err(LocalUdsError::FrameDeadlineDenied)
            ));
        }
    }

    #[test]
    fn noncanonical_json_and_unknown_fields_are_denied() {
        let binding = binding();
        let request = request(
            &binding,
            TypedBrokerOperationV1::ExecInspectBuildFingerprintUserdebugV1,
        );
        let envelope = LocalRequestEnvelopeV1::derive(binding, request).unwrap();
        let mut value = serde_json::to_value(&envelope).unwrap();
        value["unexpected"] = serde_json::Value::Bool(true);
        let body = serde_json::to_vec_pretty(&value).unwrap();
        let packet = encode_length_prefixed_packet(&body, MAX_LOCAL_REQUEST_BODY_BYTES).unwrap();
        let (client, accepted) = seqpacket_pair();
        send_one_packet(client.as_raw_fd(), &packet, Duration::from_secs(1)).unwrap();
        assert!(matches!(
            server(credentials().pid).read_one(accepted.as_fd(), 10_001, 15_000),
            Err(LocalUdsError::EnvelopeInvalid)
        ));
    }

    #[test]
    fn response_framing_is_single_packet_and_bounded() {
        let (server_fd, client_fd) = seqpacket_pair();
        let response = b"{\"closed\":true}";
        send_response_wire(server_fd.as_fd(), response, Duration::from_secs(1)).unwrap();
        let packet = recv_one_packet(
            client_fd.as_raw_fd(),
            FRAME_HEADER_BYTES + MAX_RESPONSE_WIRE_BYTES,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            decode_length_prefixed_packet(&packet, MAX_RESPONSE_WIRE_BYTES).unwrap(),
            response
        );
        assert!(
            send_response_wire(
                server_fd.as_fd(),
                &vec![0; MAX_RESPONSE_WIRE_BYTES + 1],
                Duration::from_secs(1)
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_rules_are_not_a_fixed_allowlist() {
        assert!(matches!(
            FixedPeerAllowlistV1::new(vec![rule(CODEX, 4_242), rule(CODEX, 4_243)]),
            Err(LocalUdsError::PeerAllowlistInvalid)
        ));
    }
}
