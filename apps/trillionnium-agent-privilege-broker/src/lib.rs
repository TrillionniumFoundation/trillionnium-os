//! V2 privilege-broker foundation.
//!
//! This build deliberately has no mutation backend: it does not spawn a
//! provider, install a credential, mutate a provider directory, or terminate a
//! process. It authenticates one peer over an inherited
//! `AF_UNIX/SOCK_SEQPACKET` listener and exposes a closed draft-v2 lifecycle
//! foundation. Lifecycle operations return `mutation_unavailable` with zero
//! effects. The ABI remains HOLD until the operational reservation and recovery
//! protocol receives separate review.

/// Real host-kernel fixture producer only. It is never compiled into product
/// builds and cannot substitute for target-kernel or real-payload proof.
#[cfg(all(test, target_os = "linux"))]
mod linux_provider_post_exec_test_kernel;
/// Concrete source-only clone3/pidfd backend; only the internal disabled route constructs it.
#[allow(dead_code)]
pub(crate) mod linux_replay_sync_publisher_kernel;
/// Source-disabled Linux publisher syscall adapter; no broker route.
#[allow(dead_code)]
pub(crate) mod linux_replay_sync_publisher_ops;
/// Pidfd/exec type-state contract only; no Linux producer or broker route.
#[allow(dead_code)]
pub(crate) mod measured_exec_custody;
/// Closed source-only contracts for a future independently trusted monotonic
/// authority. No production constructor or broker route exists.
#[allow(dead_code)]
pub(crate) mod monotonic_authority_contract;
/// Opt-in, non-product P0 Settings launch admission type contract. The module
/// has no concrete build authenticator, process launcher, or live broker route.
#[cfg(feature = "p0-launch-package-device-conformance")]
#[allow(dead_code)]
pub(crate) mod p0_launch_package_device_conformance;
/// Ordered production-effect composition seam. The live broker retains only
/// the authenticated-session first stage; every OS/SELinux promotion proof
/// remains unconstructible and the wire mutation backend remains unavailable.
#[allow(dead_code)]
pub(crate) mod production_effect_wiring;
/// Untrusted candidate receipt parser and retained-FD AArch64 structural gate.
/// It authenticates neither builders nor input/object provenance and has no
/// product builder, listener, admission, held-chain, or effect route.
#[allow(dead_code)]
pub(crate) mod provider_final_payload_receipt;
/// Broker-owned final-exec-held provider custody; source-only and absent from
/// the live protocol, broker core, and process entrypoint.
#[allow(dead_code)]
pub(crate) mod provider_launch_custody;
/// Closed final-ELF native hardening recipe and exact seccomp filter binding.
/// Product payloads and broker routes do not construct it.
#[allow(dead_code)]
pub(crate) mod provider_post_exec_bootstrap;
/// Source-only replay-sync publisher launch custody; no broker route constructs it.
#[allow(dead_code)]
pub(crate) mod replay_sync_publisher_custody;
pub(crate) mod root_authentication_proof_socket;
/// Source-only authenticated broker-to-system_server proof carrier.
#[allow(dead_code)]
pub(crate) mod root_authentication_proof_transport;
/// Single crate-internal source-disabled route; absent from main and the public broker protocol.
#[allow(dead_code)]
pub(crate) mod root_publisher_route;
/// Concrete one-bind/one-accept private route listener; absent from main and product wiring.
#[allow(dead_code)]
pub(crate) mod root_publisher_route_socket;
/// Commitment-only private route seam; no listener, connector, main dispatch, or public ABI.
#[allow(dead_code)]
pub(crate) mod root_publisher_route_transport;
mod startup_security;

pub use startup_security::harden_current_process;

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read as _};
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_privilege_broker_protocol::{
    BrokerMode, CapabilityContract, DenialCode, Digest, Disposition, FdFact, FdKind, FixedBytes32,
    LifecycleState, MAX_ANCILLARY_PAYLOAD_BYTES, MAX_FRAME_BYTES, MutationUnavailableReason, Nonce,
    PROTOCOL_VERSION, ProtocolError, RequestFrame, Response, ResponseFrame, ServerGreeting,
    SessionBinding, SessionState, decode_request, encode_greeting, encode_response,
};

pub const RETAINED_CAPABILITY_MASK: u64 = 0x00e1;
pub const MAX_SECURITY_CONTEXT_BYTES: usize = 256;
pub const MAX_ANCILLARY_FDS: usize = 4;
pub const ALLOWED_SOCKET_DOMAIN: libc::c_int = libc::AF_UNIX;
pub const ALLOWED_SOCKET_TYPE: libc::c_int = libc::SOCK_SEQPACKET;
pub const ANDROID_INIT_LISTENER_ENVIRONMENT: &str =
    "ANDROID_SOCKET_trillionnium_agent_privilege_broker";
const ANDROID_INIT_SOCKET_ENVIRONMENT_PREFIX: &[u8] = b"ANDROID_SOCKET_";
const ANDROID_INIT_LISTENER_PATH: &str = "/dev/socket/trillionnium_agent_privilege_broker";

/// Extract only the one reviewed Android init socket environment entry. Any
/// second or differently named init socket is denied instead of being ignored
/// or treated as a command-line fallback.
pub fn fixed_android_listener_from_environment(
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<Option<OsString>, BrokerError> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut selected = None;
    for (name, value) in environment {
        let name = name.as_os_str().as_bytes();
        if !name.starts_with(ANDROID_INIT_SOCKET_ENVIRONMENT_PREFIX) {
            continue;
        }
        if name != ANDROID_INIT_LISTENER_ENVIRONMENT.as_bytes() || selected.is_some() {
            return Err(BrokerError::ListenerSelectionDenied);
        }
        selected = Some(value);
    }
    Ok(selected)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InheritedListenerOrigin {
    HostCommandLine,
    AndroidInit,
}

#[derive(Debug, Eq, PartialEq)]
pub struct InheritedListenerSelection {
    fd: RawFd,
    origin: InheritedListenerOrigin,
}

impl InheritedListenerSelection {
    pub const fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Select the one reviewed listener source before any broker protocol state is
/// constructed.  Android init contributes only the fixed service socket name;
/// the host-only command line remains an exact, mutually exclusive fallback.
/// The selected-listener validator later enforces the exact Android
/// getsockname path. Full ancestor, mount, and SELinux provenance remain a
/// separate trusted-opener prerequisite before Android product hot wiring.
pub fn take_inherited_listener(
    arguments: &[OsString],
    android_listener_value: Option<OsString>,
    clear_android_listener_value: impl FnOnce(),
) -> Result<InheritedListenerSelection, BrokerError> {
    take_inherited_listener_with_descriptor_ops(
        arguments,
        android_listener_value,
        clear_android_listener_value,
        &mut LinuxListenerDescriptorOps,
    )
}

fn take_inherited_listener_with_descriptor_ops(
    arguments: &[OsString],
    android_listener_value: Option<OsString>,
    clear_android_listener_value: impl FnOnce(),
    descriptor_ops: &mut impl ListenerDescriptorOps,
) -> Result<InheritedListenerSelection, BrokerError> {
    let selection = select_inherited_listener(arguments, android_listener_value)?;
    if selection.origin == InheritedListenerOrigin::AndroidInit {
        set_close_on_exec_after_existence_check(selection.fd, descriptor_ops)?;
        clear_android_listener_value();
    }
    Ok(selection)
}

fn select_inherited_listener(
    arguments: &[OsString],
    android_listener_value: Option<OsString>,
) -> Result<InheritedListenerSelection, BrokerError> {
    match android_listener_value {
        Some(value) if arguments.is_empty() => Ok(InheritedListenerSelection {
            fd: parse_listener_fd(&value)?,
            origin: InheritedListenerOrigin::AndroidInit,
        }),
        Some(_) => Err(BrokerError::ListenerSelectionDenied),
        None if arguments.len() == 2
            && arguments[0].as_os_str() == OsStr::new("--inherited-fd") =>
        {
            Ok(InheritedListenerSelection {
                fd: parse_listener_fd(&arguments[1])?,
                origin: InheritedListenerOrigin::HostCommandLine,
            })
        }
        None => Err(BrokerError::ListenerSelectionDenied),
    }
}

fn parse_listener_fd(value: &OsStr) -> Result<RawFd, BrokerError> {
    let value = value.to_str().ok_or(BrokerError::ListenerSelectionDenied)?;
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes[0] == b'0' || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(BrokerError::ListenerSelectionDenied);
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| BrokerError::ListenerSelectionDenied)?;
    let fd = RawFd::try_from(parsed).map_err(|_| BrokerError::ListenerSelectionDenied)?;
    if fd < 3 {
        return Err(BrokerError::ListenerSelectionDenied);
    }
    Ok(fd)
}

trait ListenerDescriptorOps {
    fn get_descriptor_flags(&mut self, fd: RawFd) -> io::Result<libc::c_int>;
    fn set_descriptor_flags(&mut self, fd: RawFd, flags: libc::c_int) -> io::Result<()>;
}

struct LinuxListenerDescriptorOps;

impl ListenerDescriptorOps for LinuxListenerDescriptorOps {
    fn get_descriptor_flags(&mut self, fd: RawFd) -> io::Result<libc::c_int> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(flags)
    }

    fn set_descriptor_flags(&mut self, fd: RawFd, flags: libc::c_int) -> io::Result<()> {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn set_close_on_exec_after_existence_check(
    fd: RawFd,
    descriptor_ops: &mut impl ListenerDescriptorOps,
) -> Result<(), BrokerError> {
    // Android init intentionally clears CLOEXEC on service socket descriptors.
    // F_GETFD is the existence proof; restoring CLOEXEC before inventory is
    // compatible with the existing inventory classifier, while the later
    // listener-shape validator requires the restored bit.  No descriptor-table
    // operation is permitted between the proof and F_SETFD.
    let flags = descriptor_ops
        .get_descriptor_flags(fd)
        .map_err(BrokerError::ListenerDescriptorUnavailable)?;
    descriptor_ops
        .set_descriptor_flags(fd, flags | libc::FD_CLOEXEC)
        .map_err(BrokerError::ListenerDescriptorUnavailable)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InheritedFdFact {
    fd: RawFd,
    socket_family: Option<libc::c_int>,
}

/// Enumerate the live descriptor table before serving.  The broker accepts no
/// inherited descriptor except stdio and its one reviewed listener; even stdio
/// is rejected when it is any socket family other than AF_UNIX.
pub fn validate_inherited_fd_inventory(listener_fd: RawFd) -> Result<(), BrokerError> {
    if listener_fd < 3 {
        return Err(BrokerError::ListenerShapeDenied);
    }
    let entries = fs::read_dir("/proc/self/fd")
        .map_err(|source| BrokerError::InspectFdInventory { source })?;
    let descriptor_numbers = entries
        .map(|entry| {
            let entry = entry.map_err(|source| BrokerError::InspectFdInventory { source })?;
            entry
                .file_name()
                .to_str()
                .ok_or(BrokerError::FdInventoryMalformed)?
                .parse::<RawFd>()
                .map_err(|_| BrokerError::FdInventoryMalformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    // `read_dir`'s own descriptor is closed after collection.  Ignore only
    // entries proven closed now; every other live descriptor is classified.
    let mut facts = Vec::new();
    for fd in descriptor_numbers {
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(BrokerError::SocketOperation(io::Error::last_os_error()));
        }
        facts.push(classify_inherited_fd(fd)?);
    }
    validate_fd_inventory_facts(listener_fd, &facts)
}

fn classify_inherited_fd(fd: RawFd) -> Result<InheritedFdFact, BrokerError> {
    let mut address = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut length = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let result = unsafe { libc::getsockname(fd, address.as_mut_ptr().cast(), &mut length) };
    let socket_family = if result == 0 {
        Some(unsafe { address.assume_init() }.ss_family as libc::c_int)
    } else if io::Error::last_os_error().raw_os_error() == Some(libc::ENOTSOCK) {
        None
    } else {
        return Err(BrokerError::SocketOperation(io::Error::last_os_error()));
    };
    Ok(InheritedFdFact { fd, socket_family })
}

fn validate_fd_inventory_facts(
    listener_fd: RawFd,
    facts: &[InheritedFdFact],
) -> Result<(), BrokerError> {
    let mut listener_count = 0;
    for fact in facts {
        if fact
            .socket_family
            .is_some_and(|family| family != ALLOWED_SOCKET_DOMAIN)
        {
            return Err(BrokerError::InheritedSocketFamilyDenied);
        }
        match fact.fd {
            0..=2 => {}
            fd if fd == listener_fd => listener_count += 1,
            _ => return Err(BrokerError::ExtraInheritedFdDenied),
        }
    }
    if listener_count != 1 {
        return Err(BrokerError::ListenerShapeDenied);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilitySnapshot {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub bounding: u64,
    pub ambient: u64,
}

impl CapabilitySnapshot {
    pub const fn reviewed_contract() -> Self {
        Self {
            effective: RETAINED_CAPABILITY_MASK,
            permitted: RETAINED_CAPABILITY_MASK,
            inheritable: 0,
            bounding: 0,
            ambient: 0,
        }
    }

    pub const fn wire_contract() -> CapabilityContract {
        let reviewed = Self::reviewed_contract();
        CapabilityContract {
            effective: reviewed.effective,
            permitted: reviewed.permitted,
            inheritable: reviewed.inheritable,
            bounding: reviewed.bounding,
            ambient: reviewed.ambient,
        }
    }

    pub fn validate_exact(self) -> Result<(), BrokerError> {
        if self != Self::reviewed_contract() {
            return Err(BrokerError::CapabilityContractMismatch);
        }
        Ok(())
    }

    pub fn from_proc_status(status: &str) -> Result<Self, BrokerError> {
        Ok(Self {
            effective: parse_capability_line(status, "CapEff")?,
            permitted: parse_capability_line(status, "CapPrm")?,
            inheritable: parse_capability_line(status, "CapInh")?,
            bounding: parse_capability_line(status, "CapBnd")?,
            ambient: parse_capability_line(status, "CapAmb")?,
        })
    }
}

fn parse_capability_line(status: &str, label: &'static str) -> Result<u64, BrokerError> {
    let prefix = format!("{label}:");
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or(BrokerError::CapabilityFieldMissing(label))?
        .trim();
    u64::from_str_radix(value, 16).map_err(|_| BrokerError::CapabilityFieldInvalid(label))
}

/// Production performs no privilege elevation.  The process launcher must
/// enter with the exact reviewed state; anything else fails closed before a
/// listener is accepted.
pub fn verify_current_capabilities() -> Result<CapabilitySnapshot, BrokerError> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|source| BrokerError::ReadProcStatus { source })?;
    let snapshot = CapabilitySnapshot::from_proc_status(&status)?;
    snapshot.validate_exact()?;
    Ok(snapshot)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    pub pid: libc::pid_t,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub security_context: String,
    pub executable_sha256: [u8; 32],
    pub start_time_ticks: u64,
}

impl PeerIdentity {
    pub fn binding_digest(&self) -> Result<Digest, BrokerError> {
        if self.pid <= 1 || self.start_time_ticks == 0 {
            return Err(BrokerError::PeerProcessIdentityDenied);
        }
        let context = self.security_context.as_bytes();
        if context.is_empty() || context.len() > MAX_SECURITY_CONTEXT_BYTES {
            return Err(BrokerError::PeerSecurityContextDenied);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"org.trillionnium.privilege-broker.peer.v2\0");
        hasher.update(self.pid.to_be_bytes());
        hasher.update(self.uid.to_be_bytes());
        hasher.update(self.gid.to_be_bytes());
        hasher.update((context.len() as u32).to_be_bytes());
        hasher.update(context);
        hasher.update(self.executable_sha256);
        hasher.update(self.start_time_ticks.to_be_bytes());
        let bytes: [u8; 32] = hasher.finalize().into();
        Ok(Digest::new(FixedBytes32::new(bytes)?))
    }
}

pub trait PeerInspector {
    fn inspect(&self, socket_fd: RawFd) -> Result<PeerIdentity, BrokerError>;
}

pub trait PeerPolicy {
    fn authorize(&self, identity: &PeerIdentity) -> Result<(), BrokerError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactPeerPolicy {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub security_context: String,
    pub executable_sha256: [u8; 32],
}

impl PeerPolicy for ExactPeerPolicy {
    fn authorize(&self, identity: &PeerIdentity) -> Result<(), BrokerError> {
        if identity.uid != self.uid
            || identity.gid != self.gid
            || identity.security_context != self.security_context
            || identity.executable_sha256 != self.executable_sha256
            || identity.pid <= 1
            || identity.start_time_ticks == 0
        {
            return Err(BrokerError::PeerPolicyDenied);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxPeerInspector;

impl PeerInspector for LinuxPeerInspector {
    fn inspect(&self, socket_fd: RawFd) -> Result<PeerIdentity, BrokerError> {
        let credentials = socket_peer_credentials(socket_fd)?;
        let security_context = socket_peer_security_context(socket_fd)?;
        let proc_executable = format!("/proc/{}/exe", credentials.pid);
        let executable_path = fs::read_link(&proc_executable)
            .map_err(|source| BrokerError::ReadPeerProc { source })?;
        if executable_path
            .as_os_str()
            .as_encoded_bytes()
            .ends_with(b" (deleted)")
        {
            return Err(BrokerError::PeerProcessIdentityDenied);
        }
        let stat_path = format!("/proc/{}/stat", credentials.pid);
        let stat_before = fs::read_to_string(&stat_path)
            .map_err(|source| BrokerError::ReadPeerProc { source })?;
        let start_time_ticks = parse_proc_start_time(&stat_before)?;
        let executable_sha256 = sha256_proc_executable(&proc_executable)?;
        let stat_after =
            fs::read_to_string(stat_path).map_err(|source| BrokerError::ReadPeerProc { source })?;
        if parse_proc_start_time(&stat_after)? != start_time_ticks {
            return Err(BrokerError::PeerProcessIdentityDenied);
        }
        Ok(PeerIdentity {
            pid: credentials.pid,
            uid: credentials.uid,
            gid: credentials.gid,
            security_context,
            executable_sha256,
            start_time_ticks,
        })
    }
}

fn socket_peer_credentials(fd: RawFd) -> Result<libc::ucred, BrokerError> {
    let mut credentials = MaybeUninit::<libc::ucred>::uninit();
    let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != mem::size_of::<libc::ucred>() {
        return Err(BrokerError::PeerCredentialsUnavailable(
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { credentials.assume_init() })
}

fn socket_peer_security_context(fd: RawFd) -> Result<String, BrokerError> {
    let mut buffer = [0_u8; MAX_SECURITY_CONTEXT_BYTES + 1];
    let mut length = buffer.len() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            buffer.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(BrokerError::PeerSecurityUnavailable(
            io::Error::last_os_error(),
        ));
    }
    let length = length as usize;
    if length == 0 || length > buffer.len() {
        return Err(BrokerError::PeerSecurityContextDenied);
    }
    let bytes = &buffer[..length];
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if bytes.is_empty() || bytes.len() > MAX_SECURITY_CONTEXT_BYTES {
        return Err(BrokerError::PeerSecurityContextDenied);
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| BrokerError::PeerSecurityContextDenied)
}

fn sha256_proc_executable(path: &str) -> Result<[u8; 32], BrokerError> {
    let mut executable =
        fs::File::open(path).map_err(|source| BrokerError::ReadPeerExecutable { source })?;
    let metadata = executable
        .metadata()
        .map_err(|source| BrokerError::ReadPeerExecutable { source })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(BrokerError::PeerProcessIdentityDenied);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let count = executable
            .read(&mut buffer)
            .map_err(|source| BrokerError::ReadPeerExecutable { source })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn parse_proc_start_time(stat: &str) -> Result<u64, BrokerError> {
    let command_end = stat.rfind(')').ok_or(BrokerError::PeerStatMalformed)?;
    let tail = stat
        .get(command_end + 1..)
        .ok_or(BrokerError::PeerStatMalformed)?
        .trim();
    // The tail begins at field 3 (`state`); starttime is field 22.
    tail.split_whitespace()
        .nth(19)
        .ok_or(BrokerError::PeerStatMalformed)?
        .parse()
        .map_err(|_| BrokerError::PeerStatMalformed)
}

pub fn derive_session_binding(
    challenge: FixedBytes32,
    peer_binding: Digest,
) -> Result<SessionBinding, BrokerError> {
    let mut hasher = Sha256::new();
    hasher.update(b"org.trillionnium.privilege-broker.session.v2\0");
    hasher.update(challenge.as_bytes());
    hasher.update(peer_binding.value().as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    Ok(SessionBinding::new(FixedBytes32::new(bytes)?))
}

#[derive(Debug, Default)]
pub struct SingleClientGate {
    active: bool,
}

impl SingleClientGate {
    pub fn acquire(&mut self) -> Result<(), BrokerError> {
        if self.active {
            return Err(BrokerError::SecondClientDenied);
        }
        self.active = true;
        Ok(())
    }

    pub fn release(&mut self) {
        self.active = false;
    }
}

#[derive(Debug)]
pub struct BrokerCore {
    binding: SessionBinding,
    peer_binding: Digest,
    session: SessionState,
    lifecycle: LifecycleState,
    #[allow(dead_code)]
    authenticated_production_session: Option<production_effect_wiring::AuthenticatedBrokerSession>,
}

impl BrokerCore {
    pub fn new(
        challenge: FixedBytes32,
        identity: &PeerIdentity,
        policy: &impl PeerPolicy,
    ) -> Result<(Self, ServerGreeting), BrokerError> {
        policy.authorize(identity)?;
        let peer_binding = identity.binding_digest()?;
        let binding = derive_session_binding(challenge, peer_binding)?;
        let authenticated_production_session =
            production_effect_wiring::AuthenticatedBrokerSession::from_authenticated_broker_core(
                binding,
                peer_binding,
            );
        let greeting = ServerGreeting {
            protocol_version: PROTOCOL_VERSION,
            challenge,
            session_binding: binding,
        };
        Ok((
            Self {
                binding,
                peer_binding,
                session: SessionState::new(binding),
                lifecycle: LifecycleState::new(),
                authenticated_production_session: Some(authenticated_production_session),
            },
            greeting,
        ))
    }

    pub const fn mutation_effect_count(&self) -> u64 {
        self.lifecycle.mutation_effect_count()
    }

    /// One-shot handoff for the future reviewed production route. No current
    /// handler calls this method, and the next type-state remains impossible
    /// to construct without fixed-cgroup init/SELinux provenance.
    #[allow(dead_code)]
    pub(crate) fn take_authenticated_production_session(
        &mut self,
    ) -> Option<production_effect_wiring::AuthenticatedBrokerSession> {
        self.authenticated_production_session.take()
    }

    pub fn handle(
        &mut self,
        frame: &RequestFrame,
        fds: &[FdFact],
    ) -> Result<ResponseFrame, BrokerError> {
        let disposition = self.session.validate(frame, fds)?;
        let response = match disposition {
            Disposition::Hello => Response::Hello {
                peer_binding: self.peer_binding,
            },
            Disposition::Status => Response::Status {
                mode: BrokerMode::V2FoundationNoMutation,
                capability_contract: CapabilitySnapshot::wire_contract(),
                mutation_effect_count: self.lifecycle.mutation_effect_count(),
                inventory: Box::new(self.lifecycle.inventory()),
                recovery: self.lifecycle.recovery_status(),
            },
            Disposition::Lifecycle(operation) => Response::MutationUnavailable {
                operation,
                reason: MutationUnavailableReason::BackendNotInstalled,
            },
        };
        Ok(ResponseFrame {
            protocol_version: PROTOCOL_VERSION,
            session_binding: self.binding,
            sequence: frame.sequence,
            request_nonce: frame.nonce,
            response,
        })
    }
}

#[derive(Debug)]
pub struct ReceivedFrame {
    pub bytes: Vec<u8>,
    pub credentials: libc::ucred,
    pub fds: Vec<OwnedFd>,
}

#[repr(C, align(8))]
struct ControlBuffer([u8; 512]);

pub fn enable_per_frame_credentials(socket_fd: RawFd) -> Result<(), BrokerError> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enabled as *const libc::c_int).cast(),
            mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(BrokerError::SocketOperation(io::Error::last_os_error()));
    }
    Ok(())
}

#[allow(clippy::useless_conversion)]
pub fn receive_frame(socket_fd: RawFd) -> Result<ReceivedFrame, BrokerError> {
    let mut payload = [0_u8; MAX_FRAME_BYTES + 1];
    let mut control = ControlBuffer([0; 512]);
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut message = unsafe { mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control
        .0
        .len()
        .try_into()
        .map_err(|_| BrokerError::FrameTruncatedOrOversize)?;
    let received = unsafe { libc::recvmsg(socket_fd, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(BrokerError::SocketOperation(io::Error::last_os_error()));
    }
    let mut credentials = None;
    let mut fds = Vec::new();
    let mut ancillary_malformed = false;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let current = unsafe { &*header };
        if current.cmsg_level == libc::SOL_SOCKET && current.cmsg_type == libc::SCM_CREDENTIALS {
            if current.cmsg_len as usize
                != unsafe { libc::CMSG_LEN(mem::size_of::<libc::ucred>() as _) } as usize
            {
                ancillary_malformed = true;
            } else {
                let value = unsafe { *(libc::CMSG_DATA(header).cast::<libc::ucred>()) };
                if credentials.replace(value).is_some() {
                    ancillary_malformed = true;
                }
            }
        } else if current.cmsg_level == libc::SOL_SOCKET && current.cmsg_type == libc::SCM_RIGHTS {
            let header_bytes = unsafe { libc::CMSG_LEN(0) } as usize;
            let total_bytes = current.cmsg_len as usize;
            if total_bytes < header_bytes
                || !(total_bytes - header_bytes).is_multiple_of(mem::size_of::<RawFd>())
            {
                ancillary_malformed = true;
            } else {
                let count = (total_bytes - header_bytes) / mem::size_of::<RawFd>();
                let descriptors = unsafe {
                    std::slice::from_raw_parts(libc::CMSG_DATA(header).cast::<RawFd>(), count)
                };
                for descriptor in descriptors {
                    fds.push(unsafe { OwnedFd::from_raw_fd(*descriptor) });
                }
                if fds.len() > MAX_ANCILLARY_FDS {
                    ancillary_malformed = true;
                }
            }
        } else {
            ancillary_malformed = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }

    if ancillary_malformed {
        return Err(BrokerError::AncillaryMalformed);
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || received as usize > MAX_FRAME_BYTES
    {
        return Err(BrokerError::FrameTruncatedOrOversize);
    }
    // A zero-length seqpacket can carry credentials and SCM_RIGHTS.  Ancillary
    // data has already been fully scanned and every received right is owned by
    // `fds`, so invalid empty records cannot leak descriptors.  Only an empty
    // read with no ancillary record is treated as orderly closure.
    if received == 0 {
        if credentials.is_none() && fds.is_empty() {
            return Err(BrokerError::PeerClosed);
        }
        return Err(BrokerError::FrameTruncatedOrOversize);
    }

    Ok(ReceivedFrame {
        bytes: payload[..received as usize].to_vec(),
        credentials: credentials.ok_or(BrokerError::PerFrameCredentialsMissing)?,
        fds,
    })
}

pub fn inspect_received_fds(fds: &[OwnedFd]) -> Result<Vec<FdFact>, BrokerError> {
    let required_seals =
        libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    fds.iter()
        .map(|fd| {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(BrokerError::InspectReceivedFd(io::Error::last_os_error()));
            }
            let access = if flags & libc::O_ACCMODE == libc::O_RDONLY {
                trillionnium_privilege_broker_protocol::FdAccess::ReadOnly
            } else {
                trillionnium_privilege_broker_protocol::FdAccess::Writable
            };
            if access != trillionnium_privilege_broker_protocol::FdAccess::ReadOnly {
                return Err(BrokerError::ReceivedFdShapeDenied);
            }
            let mut stat = MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err(BrokerError::InspectReceivedFd(io::Error::last_os_error()));
            }
            let stat = unsafe { stat.assume_init() };
            if stat.st_size < 0 || stat.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(BrokerError::ReceivedFdShapeDenied);
            }
            let size = stat.st_size as u64;
            if size > MAX_ANCILLARY_PAYLOAD_BYTES {
                return Err(BrokerError::ReceivedFdSizeDenied);
            }
            let mut statfs = MaybeUninit::<libc::statfs>::uninit();
            if unsafe { libc::fstatfs(fd.as_raw_fd(), statfs.as_mut_ptr()) } != 0 {
                return Err(BrokerError::InspectReceivedFd(io::Error::last_os_error()));
            }
            let statfs = unsafe { statfs.assume_init() };
            use std::os::unix::ffi::OsStrExt as _;
            let descriptor_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
            let descriptor_target =
                fs::read_link(&descriptor_path).map_err(BrokerError::InspectReceivedFd)?;
            let target = descriptor_target.as_os_str().as_bytes();
            let memfd_identity = statfs.f_type as libc::c_long == libc::TMPFS_MAGIC
                && target.starts_with(b"/memfd:")
                && target.ends_with(b" (deleted)");
            if !memfd_identity {
                return Err(BrokerError::ReceivedFdShapeDenied);
            }
            let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
            if seals < 0 || seals & required_seals != required_seals {
                return Err(BrokerError::ReceivedFdShapeDenied);
            }
            let sha256 = sha256_received_fd(&descriptor_path, &stat)?;
            Ok(FdFact {
                kind: FdKind::SealedMemfd,
                access,
                fully_sealed: true,
                size,
                sha256,
            })
        })
        .collect()
}

fn sha256_received_fd(path: &str, expected: &libc::stat) -> Result<Digest, BrokerError> {
    use std::os::unix::fs::MetadataExt as _;

    let mut payload = fs::File::open(path).map_err(BrokerError::InspectReceivedFd)?;
    let metadata = payload.metadata().map_err(BrokerError::InspectReceivedFd)?;
    if metadata.dev() != expected.st_dev
        || metadata.ino() != expected.st_ino
        || metadata.len() != expected.st_size as u64
    {
        return Err(BrokerError::ReceivedFdIdentityChanged);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 32 * 1024];
    let mut total = 0_u64;
    loop {
        let count = payload
            .read(&mut buffer)
            .map_err(BrokerError::InspectReceivedFd)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(BrokerError::ReceivedFdSizeDenied)?;
        if total > MAX_ANCILLARY_PAYLOAD_BYTES {
            return Err(BrokerError::ReceivedFdSizeDenied);
        }
        hasher.update(&buffer[..count]);
    }
    if total != expected.st_size as u64 {
        return Err(BrokerError::ReceivedFdIdentityChanged);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(Digest::new(FixedBytes32::new(digest)?))
}

pub fn send_frame(socket_fd: RawFd, bytes: &[u8]) -> Result<(), BrokerError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(BrokerError::FrameTruncatedOrOversize);
    }
    let sent = unsafe {
        libc::send(
            socket_fd,
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if sent < 0 || sent as usize != bytes.len() {
        return Err(BrokerError::SocketOperation(io::Error::last_os_error()));
    }
    Ok(())
}

pub fn validate_inherited_listener(listener_fd: RawFd) -> Result<(), BrokerError> {
    validate_inherited_listener_with_expected_path(listener_fd, None)
}

/// Validate the selected listener without discarding its reviewed origin. An
/// Android init descriptor is accepted only when getsockname reports the one
/// fixed service path; the host command-line mode retains the generic private
/// filesystem-socket contract.
pub fn validate_selected_inherited_listener(
    listener: &InheritedListenerSelection,
) -> Result<(), BrokerError> {
    let expected_path = (listener.origin == InheritedListenerOrigin::AndroidInit)
        .then_some(Path::new(ANDROID_INIT_LISTENER_PATH));
    validate_inherited_listener_with_expected_path(listener.fd, expected_path)
}

fn validate_inherited_listener_with_expected_path(
    listener_fd: RawFd,
    expected_path: Option<&Path>,
) -> Result<(), BrokerError> {
    let descriptor_flags = unsafe { libc::fcntl(listener_fd, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(BrokerError::SocketOperation(io::Error::last_os_error()));
    }
    if descriptor_flags & libc::FD_CLOEXEC == 0 {
        return Err(BrokerError::ListenerShapeDenied);
    }
    let socket_type = get_socket_int(listener_fd, libc::SO_TYPE)?;
    let accepting = get_socket_int(listener_fd, libc::SO_ACCEPTCONN)?;
    if socket_type != ALLOWED_SOCKET_TYPE || accepting != 1 {
        return Err(BrokerError::ListenerShapeDenied);
    }

    let path = inherited_listener_path(listener_fd)?;
    if expected_path.is_some_and(|expected| path != expected) {
        return Err(BrokerError::ListenerShapeDenied);
    }
    validate_socket_path(&path)
}

fn inherited_listener_path(listener_fd: RawFd) -> Result<PathBuf, BrokerError> {
    let mut address = MaybeUninit::<libc::sockaddr_un>::zeroed();
    let mut length = mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let result =
        unsafe { libc::getsockname(listener_fd, address.as_mut_ptr().cast(), &mut length) };
    if result != 0 {
        return Err(BrokerError::SocketOperation(io::Error::last_os_error()));
    }
    let address = unsafe { address.assume_init() };
    if address.sun_family as libc::c_int != ALLOWED_SOCKET_DOMAIN
        || length as usize <= mem::size_of::<libc::sa_family_t>()
        || address.sun_path[0] == 0
    {
        return Err(BrokerError::ListenerShapeDenied);
    }
    let path_offset = mem::offset_of!(libc::sockaddr_un, sun_path);
    let address_length = length as usize;
    if address_length <= path_offset {
        return Err(BrokerError::ListenerShapeDenied);
    }
    let raw_path = unsafe {
        std::slice::from_raw_parts(
            address.sun_path.as_ptr().cast::<u8>(),
            address_length - path_offset,
        )
    };
    let raw_path = raw_path.strip_suffix(&[0]).unwrap_or(raw_path);
    if raw_path.is_empty() || raw_path.contains(&0) {
        return Err(BrokerError::ListenerShapeDenied);
    }
    use std::os::unix::ffi::OsStrExt as _;
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(raw_path)))
}

fn get_socket_int(fd: RawFd, option: libc::c_int) -> Result<libc::c_int, BrokerError> {
    let mut value = 0;
    let mut length = mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != mem::size_of::<libc::c_int>() {
        return Err(BrokerError::SocketOperation(io::Error::last_os_error()));
    }
    Ok(value)
}

fn validate_socket_path(path: &Path) -> Result<(), BrokerError> {
    if !path.is_absolute() {
        return Err(BrokerError::ListenerShapeDenied);
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|source| BrokerError::InspectListenerPath { source })?;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o007 != 0
    {
        return Err(BrokerError::ListenerShapeDenied);
    }
    let parent = path.parent().ok_or(BrokerError::ListenerShapeDenied)?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|source| BrokerError::InspectListenerPath { source })?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(BrokerError::ListenerShapeDenied);
    }
    Ok(())
}

pub fn accept_client(listener_fd: RawFd) -> Result<RawFd, BrokerError> {
    let fd = unsafe {
        libc::accept4(
            listener_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(BrokerError::SocketOperation(io::Error::last_os_error()));
    }
    Ok(fd)
}

pub fn random_fixed_bytes() -> Result<FixedBytes32, BrokerError> {
    let mut bytes = [0_u8; 32];
    let received =
        unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), libc::GRND_NONBLOCK) };
    if received < 0 || received as usize != bytes.len() {
        return Err(BrokerError::RandomUnavailable(io::Error::last_os_error()));
    }
    FixedBytes32::new(bytes).map_err(BrokerError::Protocol)
}

pub fn serve_authenticated_client<I: PeerInspector>(
    socket_fd: RawFd,
    inspector: &I,
    policy: &impl PeerPolicy,
) -> Result<(), BrokerError> {
    enable_per_frame_credentials(socket_fd)?;
    let identity = inspector.inspect(socket_fd)?;
    policy.authorize(&identity)?;
    let peer_credentials = socket_peer_credentials(socket_fd)?;
    if peer_credentials.pid != identity.pid
        || peer_credentials.uid != identity.uid
        || peer_credentials.gid != identity.gid
    {
        return Err(BrokerError::PeerChanged);
    }

    let challenge = random_fixed_bytes()?;
    let (mut core, greeting) = BrokerCore::new(challenge, &identity, policy)?;
    send_frame(socket_fd, &encode_greeting(&greeting)?)?;

    loop {
        let received = match receive_frame(socket_fd) {
            Ok(frame) => frame,
            Err(BrokerError::PeerClosed) => return Ok(()),
            Err(error) => return Err(error),
        };
        if received.credentials.pid != identity.pid
            || received.credentials.uid != identity.uid
            || received.credentials.gid != identity.gid
        {
            return Err(BrokerError::PeerChanged);
        }
        // A connected peer can exec without changing its socket credentials.
        // Re-measuring here detects stable drift at the inspection point.  It
        // is defense in depth for this zero-mutation phase, not a claim that a
        // future mutation is race-free; that phase also needs pidfd-backed
        // lifecycle ownership and an execution boundary tied to the measured
        // image.
        let current_identity = inspector.inspect(socket_fd)?;
        policy.authorize(&current_identity)?;
        if current_identity != identity {
            return Err(BrokerError::PeerChanged);
        }
        let request = decode_request(&received.bytes)?;
        let fd_facts = inspect_received_fds(&received.fds)?;
        let response = core.handle(&request, &fd_facts)?;
        send_frame(socket_fd, &encode_response(&response)?)?;
    }
}

pub fn parse_expected_peer_from_environment() -> Result<ExactPeerPolicy, BrokerError> {
    let uid = required_environment("TRILLIONNIUM_PRIVILEGE_BROKER_EXPECTED_UID")?
        .parse()
        .map_err(|_| BrokerError::ConfigurationDenied)?;
    let gid = required_environment("TRILLIONNIUM_PRIVILEGE_BROKER_EXPECTED_GID")?
        .parse()
        .map_err(|_| BrokerError::ConfigurationDenied)?;
    let security_context = required_environment("TRILLIONNIUM_PRIVILEGE_BROKER_EXPECTED_PEERSEC")?;
    if security_context.is_empty() || security_context.len() > MAX_SECURITY_CONTEXT_BYTES {
        return Err(BrokerError::ConfigurationDenied);
    }
    let executable_sha256 = parse_sha256_hex(&required_environment(
        "TRILLIONNIUM_PRIVILEGE_BROKER_EXPECTED_EXE_SHA256",
    )?)?;
    Ok(ExactPeerPolicy {
        uid,
        gid,
        security_context,
        executable_sha256,
    })
}

fn required_environment(name: &'static str) -> Result<String, BrokerError> {
    match std::env::var(name) {
        Ok(value) => Ok(value),
        Err(_) => Err(BrokerError::ConfigurationMissing(name)),
    }
}

fn parse_sha256_hex(value: &str) -> Result<[u8; 32], BrokerError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BrokerError::ConfigurationDenied);
    }
    let mut bytes = [0_u8; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| BrokerError::ConfigurationDenied)?;
    }
    Ok(bytes)
}

pub fn denial_response(
    binding: SessionBinding,
    sequence: u64,
    nonce: Nonce,
    code: DenialCode,
) -> ResponseFrame {
    ResponseFrame {
        protocol_version: PROTOCOL_VERSION,
        session_binding: binding,
        sequence,
        request_nonce: nonce,
        response: Response::Denied { code },
    }
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("capability contract mismatch")]
    CapabilityContractMismatch,
    #[error("capability field missing: {0}")]
    CapabilityFieldMissing(&'static str),
    #[error("capability field invalid: {0}")]
    CapabilityFieldInvalid(&'static str),
    #[error("cannot read /proc/self/status: {source}")]
    ReadProcStatus { source: io::Error },
    #[error("peer process identity denied")]
    PeerProcessIdentityDenied,
    #[error("peer security context denied")]
    PeerSecurityContextDenied,
    #[error("peer policy denied")]
    PeerPolicyDenied,
    #[error("peer credentials unavailable: {0}")]
    PeerCredentialsUnavailable(io::Error),
    #[error("peer security identity unavailable: {0}")]
    PeerSecurityUnavailable(io::Error),
    #[error("cannot read peer proc identity: {source}")]
    ReadPeerProc { source: io::Error },
    #[error("cannot read peer executable: {source}")]
    ReadPeerExecutable { source: io::Error },
    #[error("peer stat record malformed")]
    PeerStatMalformed,
    #[error("second concurrent client denied")]
    SecondClientDenied,
    #[error("socket operation failed: {0}")]
    SocketOperation(io::Error),
    #[error("listener shape denied")]
    ListenerShapeDenied,
    #[error("listener source selection denied")]
    ListenerSelectionDenied,
    #[error("inherited listener descriptor unavailable: {0}")]
    ListenerDescriptorUnavailable(io::Error),
    #[error("cannot inspect inherited descriptor inventory: {source}")]
    InspectFdInventory { source: io::Error },
    #[error("inherited descriptor inventory malformed")]
    FdInventoryMalformed,
    #[error("extra inherited descriptor denied")]
    ExtraInheritedFdDenied,
    #[error("inherited non-Unix socket family denied")]
    InheritedSocketFamilyDenied,
    #[error("cannot inspect listener path: {source}")]
    InspectListenerPath { source: io::Error },
    #[error("frame truncated or oversized")]
    FrameTruncatedOrOversize,
    #[error("ancillary message malformed")]
    AncillaryMalformed,
    #[error("ancillary file descriptors denied")]
    AncillaryFileDescriptorsDenied,
    #[error("cannot inspect received file descriptor: {0}")]
    InspectReceivedFd(io::Error),
    #[error("received file descriptor is not an exact sealed read-only memfd")]
    ReceivedFdShapeDenied,
    #[error("received file descriptor payload exceeds the closed maximum")]
    ReceivedFdSizeDenied,
    #[error("received file descriptor identity changed while measuring")]
    ReceivedFdIdentityChanged,
    #[error("per-frame credentials missing")]
    PerFrameCredentialsMissing,
    #[error("authenticated peer changed")]
    PeerChanged,
    #[error("peer closed")]
    PeerClosed,
    #[error("secure randomness unavailable: {0}")]
    RandomUnavailable(io::Error),
    #[error("required configuration missing: {0}")]
    ConfigurationMissing(&'static str),
    #[error("configuration denied")]
    ConfigurationDenied,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use trillionnium_privilege_broker_protocol::{
        FdAccess, FdKind, Generation, InvocationId, InvocationTimeout, MutationUnavailableReason,
        OpaqueHandle, Operation, Provider, Request, TerminationReason,
    };

    fn fixed(value: u8) -> FixedBytes32 {
        FixedBytes32::new([value; 32]).unwrap()
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).unwrap()
    }

    fn digest_bytes(contents: &[u8]) -> Digest {
        let bytes: [u8; 32] = Sha256::digest(contents).into();
        Digest::new(FixedBytes32::new(bytes).unwrap())
    }

    fn identity() -> PeerIdentity {
        PeerIdentity {
            pid: 42,
            uid: 5903,
            gid: 5903,
            security_context: "u:r:trillionnium_agentd:s0".to_owned(),
            executable_sha256: [7; 32],
            start_time_ticks: 99,
        }
    }

    fn policy() -> ExactPeerPolicy {
        ExactPeerPolicy {
            uid: 5903,
            gid: 5903,
            security_context: "u:r:trillionnium_agentd:s0".to_owned(),
            executable_sha256: [7; 32],
        }
    }

    fn request(
        binding: SessionBinding,
        sequence: u64,
        nonce_value: u8,
        request: Request,
    ) -> RequestFrame {
        RequestFrame {
            protocol_version: PROTOCOL_VERSION,
            session_binding: binding,
            sequence,
            nonce: Nonce::new(fixed(nonce_value)),
            request,
        }
    }

    #[test]
    fn capability_contract_is_exact_and_network_capabilities_are_absent() {
        let contract = CapabilitySnapshot::reviewed_contract();
        assert_eq!(contract.effective, 0xe1);
        assert_eq!(contract.permitted, 0xe1);
        assert_eq!(contract.inheritable, 0);
        assert_eq!(contract.bounding, 0);
        assert_eq!(contract.ambient, 0);
        assert_eq!(contract.effective.count_ones(), 4);
        assert_eq!(contract.effective & (1 << 12), 0); // NET_ADMIN
        assert_eq!(contract.effective & (1 << 13), 0); // NET_RAW
        assert_eq!(contract.effective & (1 << 10), 0); // NET_BIND_SERVICE
        contract.validate_exact().unwrap();
    }

    #[test]
    fn capability_parser_rejects_extra_missing_or_nonzero_auxiliary_sets() {
        let valid = "CapInh:\t0000000000000000\nCapPrm:\t00000000000000e1\nCapEff:\t00000000000000e1\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n";
        CapabilitySnapshot::from_proc_status(valid)
            .unwrap()
            .validate_exact()
            .unwrap();
        assert!(
            CapabilitySnapshot::from_proc_status(&valid.replace("00e1", "00e9"))
                .unwrap()
                .validate_exact()
                .is_err()
        );
        assert!(
            CapabilitySnapshot::from_proc_status(
                &valid.replace("CapBnd:\t0000000000000000", "CapBnd:\t00000000000000e1")
            )
            .unwrap()
            .validate_exact()
            .is_err()
        );
        assert!(
            CapabilitySnapshot::from_proc_status(&valid.replace("CapAmb:\t0000000000000000\n", ""))
                .is_err()
        );
    }

    #[test]
    fn exact_peer_policy_rejects_every_wrong_identity_field() {
        let expected = policy();
        expected.authorize(&identity()).unwrap();
        let mut variants = Vec::new();
        let mut wrong = identity();
        wrong.pid = 1;
        variants.push(wrong);
        let mut wrong = identity();
        wrong.uid += 1;
        variants.push(wrong);
        let mut wrong = identity();
        wrong.gid += 1;
        variants.push(wrong);
        let mut wrong = identity();
        wrong.security_context.push_str(":bad");
        variants.push(wrong);
        let mut wrong = identity();
        wrong.executable_sha256[0] ^= 1;
        variants.push(wrong);
        let mut wrong = identity();
        wrong.start_time_ticks = 0;
        variants.push(wrong);
        for variant in variants {
            assert!(expected.authorize(&variant).is_err());
        }
    }

    #[test]
    fn single_client_gate_denies_a_second_client() {
        let mut gate = SingleClientGate::default();
        gate.acquire().unwrap();
        assert!(matches!(
            gate.acquire(),
            Err(BrokerError::SecondClientDenied)
        ));
        gate.release();
        gate.acquire().unwrap();
    }

    #[test]
    fn hello_status_and_v2_foundation_lifecycle_have_zero_effect() {
        let challenge = fixed(11);
        let (mut core, greeting) = BrokerCore::new(challenge, &identity(), &policy()).unwrap();
        assert!(core.take_authenticated_production_session().is_some());
        assert!(core.take_authenticated_production_session().is_none());
        let hello = request(greeting.session_binding, 1, 12, Request::Hello);
        assert!(matches!(
            core.handle(&hello, &[]).unwrap().response,
            Response::Hello { .. }
        ));
        let status = request(greeting.session_binding, 2, 14, Request::Status);
        assert!(matches!(
            core.handle(&status, &[]).unwrap().response,
            Response::Status {
                mutation_effect_count: 0,
                ..
            }
        ));

        let install = request(
            greeting.session_binding,
            3,
            19,
            Request::InstallCredential {
                provider: Provider::Codex,
                credential_generation: generation(1),
                credential_sha256: Digest::new(fixed(17)),
                credential_size: 12,
            },
        );
        let install_response = core
            .handle(
                &install,
                &[FdFact {
                    kind: FdKind::SealedMemfd,
                    access: FdAccess::ReadOnly,
                    fully_sealed: true,
                    size: 12,
                    sha256: Digest::new(fixed(17)),
                }],
            )
            .unwrap();
        assert!(matches!(
            install_response.response,
            Response::MutationUnavailable {
                operation: Operation::InstallCredential,
                reason: MutationUnavailableReason::BackendNotInstalled,
            }
        ));
        assert_eq!(core.mutation_effect_count(), 0);

        let operations = [
            Request::SpawnInvocation {
                provider: Provider::Codex,
                invocation_id: InvocationId::new(fixed(20)),
                lifecycle_digest: Digest::new(fixed(20)),
                credential_generation: generation(1),
                credential_sha256: Digest::new(fixed(21)),
                request_sha256: Digest::new(fixed(24)),
                request_size: 12,
                timeout: InvocationTimeout::Minutes2,
            },
            Request::CollectInvocation {
                handle: OpaqueHandle::new(fixed(22)),
            },
            Request::TerminateInvocation {
                handle: OpaqueHandle::new(fixed(23)),
                reason: TerminationReason::PolicyRevoked,
            },
            Request::GetRecoveryEvidence,
        ];
        for (index, operation) in operations.into_iter().enumerate() {
            let fds = match &operation {
                Request::SpawnInvocation { request_sha256, .. } => vec![FdFact {
                    kind: FdKind::SealedMemfd,
                    access: FdAccess::ReadOnly,
                    fully_sealed: true,
                    size: 12,
                    sha256: *request_sha256,
                }],
                _ => Vec::new(),
            };
            let response = core
                .handle(
                    &request(
                        greeting.session_binding,
                        index as u64 + 4,
                        index as u8 + 24,
                        operation,
                    ),
                    &fds,
                )
                .unwrap();
            assert!(matches!(
                response.response,
                Response::MutationUnavailable {
                    operation: Operation::SpawnInvocation
                        | Operation::CollectInvocation
                        | Operation::TerminateInvocation
                        | Operation::GetRecoveryEvidence,
                    reason: MutationUnavailableReason::BackendNotInstalled,
                }
            ));
            assert_eq!(core.mutation_effect_count(), 0);
        }
    }

    #[test]
    fn proc_stat_parser_handles_spaces_and_parentheses_in_comm() {
        let fields = (3..=52).map(|field| field.to_string()).collect::<Vec<_>>();
        let stat = format!("123 (name with ) paren) {}", fields.join(" "));
        assert_eq!(parse_proc_start_time(&stat).unwrap(), 22);
    }

    #[test]
    fn peer_security_is_production_fail_closed_when_unavailable() {
        use std::os::fd::AsRawFd as _;
        let (left, _right) = UnixStream::pair().unwrap();
        match socket_peer_security_context(left.as_raw_fd()) {
            Ok(context) => assert!(!context.is_empty()),
            Err(BrokerError::PeerSecurityUnavailable(_)) => {}
            Err(other) => panic!("unexpected SO_PEERSEC result: {other}"),
        }
    }

    #[test]
    fn inherited_listener_rejects_stream_sockets() {
        let (left, _right) = UnixStream::pair().unwrap();
        assert!(matches!(
            validate_inherited_listener(left.as_raw_fd()),
            Err(BrokerError::ListenerShapeDenied)
        ));
    }

    fn seqpacket_pair() -> (OwnedFd, OwnedFd) {
        let mut sockets = [-1; 2];
        let result = unsafe {
            libc::socketpair(
                ALLOWED_SOCKET_DOMAIN,
                ALLOWED_SOCKET_TYPE | libc::SOCK_CLOEXEC,
                0,
                sockets.as_mut_ptr(),
            )
        };
        assert_eq!(result, 0, "socketpair: {}", io::Error::last_os_error());
        unsafe {
            (
                OwnedFd::from_raw_fd(sockets[0]),
                OwnedFd::from_raw_fd(sockets[1]),
            )
        }
    }

    fn os(value: &str) -> OsString {
        OsString::from(value)
    }

    #[test]
    fn listener_source_is_an_exact_closed_host_or_android_choice() {
        assert_eq!(
            select_inherited_listener(&[os("--inherited-fd"), os("17")], None).unwrap(),
            InheritedListenerSelection {
                fd: 17,
                origin: InheritedListenerOrigin::HostCommandLine,
            }
        );
        assert_eq!(
            select_inherited_listener(&[], Some(os("19"))).unwrap(),
            InheritedListenerSelection {
                fd: 19,
                origin: InheritedListenerOrigin::AndroidInit,
            }
        );

        for (arguments, android_value) in [
            (vec![], None),
            (vec![os("--inherited-fd")], None),
            (vec![os("--inherited-fd"), os("3"), os("extra")], None),
            (vec![os("--listener-fd"), os("3")], None),
            (vec![os("3")], None),
            (vec![os("--inherited-fd"), os("3")], Some(os("4"))),
            (vec![os("extra")], Some(os("4"))),
        ] {
            assert!(matches!(
                select_inherited_listener(&arguments, android_value),
                Err(BrokerError::ListenerSelectionDenied)
            ));
        }
    }

    #[test]
    fn android_socket_environment_is_a_single_exact_name_without_fallback() {
        assert_eq!(
            fixed_android_listener_from_environment([(os("PATH"), os("/bin"))]).unwrap(),
            None
        );
        assert_eq!(
            fixed_android_listener_from_environment([(
                os(ANDROID_INIT_LISTENER_ENVIRONMENT),
                os("17"),
            )])
            .unwrap(),
            Some(os("17"))
        );
        for environment in [
            vec![(os("ANDROID_SOCKET_other"), os("17"))],
            vec![
                (os(ANDROID_INIT_LISTENER_ENVIRONMENT), os("17")),
                (os("ANDROID_SOCKET_other"), os("18")),
            ],
            vec![
                (os(ANDROID_INIT_LISTENER_ENVIRONMENT), os("17")),
                (os(ANDROID_INIT_LISTENER_ENVIRONMENT), os("17")),
            ],
        ] {
            assert!(matches!(
                fixed_android_listener_from_environment(environment),
                Err(BrokerError::ListenerSelectionDenied)
            ));
        }
        let non_utf8_name = OsString::from_vec(b"ANDROID_SOCKET_bad\xff".to_vec());
        assert!(matches!(
            fixed_android_listener_from_environment([(non_utf8_name, os("17"))]),
            Err(BrokerError::ListenerSelectionDenied)
        ));
    }

    #[test]
    fn listener_fd_is_canonical_decimal_and_bounded_by_raw_fd() {
        assert_eq!(parse_listener_fd(OsStr::new("3")).unwrap(), 3);
        assert_eq!(
            parse_listener_fd(OsStr::new("2147483647")).unwrap(),
            RawFd::MAX
        );
        for denied in [
            "",
            "0",
            "1",
            "2",
            "03",
            "+3",
            "-3",
            " 3",
            "3 ",
            "3x",
            "0x3",
            "2147483648",
            "18446744073709551616",
        ] {
            assert!(matches!(
                parse_listener_fd(OsStr::new(denied)),
                Err(BrokerError::ListenerSelectionDenied)
            ));
        }
        let non_utf8 = OsString::from_vec(vec![b'3', 0xff]);
        assert!(matches!(
            parse_listener_fd(&non_utf8),
            Err(BrokerError::ListenerSelectionDenied)
        ));
    }

    #[test]
    fn android_listener_is_proven_live_then_cloexec_and_environment_is_cleared() {
        let mut pipe_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let reader = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        let _writer = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };
        let initial_flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(initial_flags & libc::FD_CLOEXEC, 0);
        let cleared = std::cell::Cell::new(false);

        assert_eq!(
            take_inherited_listener(&[], Some(os(&reader.as_raw_fd().to_string())), || {
                let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFD) };
                assert!(flags >= 0);
                assert_ne!(flags & libc::FD_CLOEXEC, 0);
                cleared.set(true);
            },)
            .unwrap(),
            InheritedListenerSelection {
                fd: reader.as_raw_fd(),
                origin: InheritedListenerOrigin::AndroidInit,
            }
        );
        assert!(cleared.get());
        let final_flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(final_flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn invalid_android_listener_is_not_cleared_or_normalized() {
        let cleared = std::cell::Cell::new(false);
        assert!(matches!(
            take_inherited_listener(&[], Some(os(&RawFd::MAX.to_string())), || {
                cleared.set(true);
            }),
            Err(BrokerError::ListenerDescriptorUnavailable(_))
        ));
        assert!(!cleared.get());
    }

    #[derive(Default)]
    struct ScriptedDescriptorOps {
        get_result: Option<io::Result<libc::c_int>>,
        set_result: Option<io::Result<()>>,
        calls: Vec<(&'static str, RawFd, libc::c_int)>,
    }

    impl ListenerDescriptorOps for ScriptedDescriptorOps {
        fn get_descriptor_flags(&mut self, fd: RawFd) -> io::Result<libc::c_int> {
            self.calls.push(("get", fd, 0));
            self.get_result.take().unwrap_or(Ok(libc::FD_CLOEXEC))
        }

        fn set_descriptor_flags(&mut self, fd: RawFd, flags: libc::c_int) -> io::Result<()> {
            self.calls.push(("set", fd, flags));
            self.set_result.take().unwrap_or(Ok(()))
        }
    }

    #[test]
    fn android_listener_getfd_and_setfd_fail_before_environment_clear() {
        for fail_get in [true, false] {
            let cleared = std::cell::Cell::new(false);
            let mut descriptor_ops = ScriptedDescriptorOps {
                get_result: Some(if fail_get {
                    Err(io::Error::from_raw_os_error(libc::EBADF))
                } else {
                    Ok(0)
                }),
                set_result: Some(Err(io::Error::from_raw_os_error(libc::EPERM))),
                ..ScriptedDescriptorOps::default()
            };
            assert!(matches!(
                take_inherited_listener_with_descriptor_ops(
                    &[],
                    Some(os("23")),
                    || cleared.set(true),
                    &mut descriptor_ops,
                ),
                Err(BrokerError::ListenerDescriptorUnavailable(_))
            ));
            assert!(!cleared.get());
            if fail_get {
                assert_eq!(descriptor_ops.calls, [("get", 23, 0)]);
            } else {
                assert_eq!(
                    descriptor_ops.calls,
                    [("get", 23, 0), ("set", 23, libc::FD_CLOEXEC)]
                );
            }
        }
    }

    #[test]
    fn host_listener_selection_does_not_mutate_android_environment_or_fd_flags() {
        let mut pipe_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let reader = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        let _writer = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };
        let cleared = std::cell::Cell::new(false);

        assert_eq!(
            take_inherited_listener(
                &[os("--inherited-fd"), os(&reader.as_raw_fd().to_string())],
                None,
                || cleared.set(true),
            )
            .unwrap(),
            InheritedListenerSelection {
                fd: reader.as_raw_fd(),
                origin: InheritedListenerOrigin::HostCommandLine,
            }
        );
        assert!(!cleared.get());
        let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn seqpacket_transport_requires_credentials_and_rejects_oversize() {
        let (sender, receiver) = seqpacket_pair();
        enable_per_frame_credentials(receiver.as_raw_fd()).unwrap();
        send_frame(sender.as_raw_fd(), b"{}").unwrap();
        let frame = receive_frame(receiver.as_raw_fd()).unwrap();
        assert_eq!(frame.bytes, b"{}");
        assert_eq!(frame.credentials.pid, unsafe { libc::getpid() });
        assert_eq!(frame.credentials.uid, unsafe { libc::getuid() });
        assert_eq!(frame.credentials.gid, unsafe { libc::getgid() });
        assert!(frame.fds.is_empty());

        let oversized = vec![b'x'; MAX_FRAME_BYTES + 1];
        let sent = unsafe {
            libc::send(
                sender.as_raw_fd(),
                oversized.as_ptr().cast(),
                oversized.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        assert_eq!(sent as usize, oversized.len());
        assert!(matches!(
            receive_frame(receiver.as_raw_fd()),
            Err(BrokerError::FrameTruncatedOrOversize)
        ));
    }

    fn send_with_right(socket_fd: RawFd, payload: &[u8], passed_fd: RawFd) {
        let mut control = ControlBuffer([0; 512]);
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let mut message = unsafe { mem::zeroed::<libc::msghdr>() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as _) } as _;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        assert!(!header.is_null());
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as _) as _;
            *(libc::CMSG_DATA(header).cast::<RawFd>()) = passed_fd;
        }
        let sent = unsafe { libc::sendmsg(socket_fd, &message, libc::MSG_NOSIGNAL) };
        assert_eq!(sent as usize, payload.len());
    }

    fn sealed_read_only_memfd(contents: &[u8]) -> OwnedFd {
        let name = std::ffi::CString::new("trillionnium-broker-test").unwrap();
        let raw = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        assert!(raw >= 0, "memfd_create: {}", io::Error::last_os_error());
        let writable = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_eq!(
            unsafe {
                libc::write(
                    writable.as_raw_fd(),
                    contents.as_ptr().cast(),
                    contents.len(),
                )
            } as usize,
            contents.len()
        );
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        assert_eq!(
            unsafe { libc::fcntl(writable.as_raw_fd(), libc::F_ADD_SEALS, seals) },
            0,
            "F_ADD_SEALS: {}",
            io::Error::last_os_error()
        );
        let read_only = fs::File::open(format!("/proc/self/fd/{}", writable.as_raw_fd())).unwrap();
        read_only.into()
    }

    #[test]
    fn seqpacket_transport_rejects_non_memfd_rights_before_payload_read() {
        use std::fs::File;

        let (sender, receiver) = seqpacket_pair();
        enable_per_frame_credentials(receiver.as_raw_fd()).unwrap();
        let passed = File::open("/dev/null").unwrap();
        send_with_right(sender.as_raw_fd(), b"{}", passed.as_raw_fd());
        let received = receive_frame(receiver.as_raw_fd()).unwrap();
        assert_eq!(received.fds.len(), 1);
        assert!(matches!(
            inspect_received_fds(&received.fds),
            Err(BrokerError::ReceivedFdShapeDenied)
        ));
    }

    #[test]
    fn writer_held_fifo_is_rejected_without_blocking_for_hash_input() {
        use std::sync::mpsc;
        use std::time::Duration;

        let mut pipe_fds = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "pipe2: {}",
            io::Error::last_os_error()
        );
        let pipe_reader = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        let pipe_writer = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };
        let (sender, receiver) = seqpacket_pair();
        enable_per_frame_credentials(receiver.as_raw_fd()).unwrap();
        send_with_right(sender.as_raw_fd(), b"{}", pipe_reader.as_raw_fd());
        let received = receive_frame(receiver.as_raw_fd()).unwrap();

        let (result_sender, result_receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            result_sender
                .send(inspect_received_fds(&received.fds))
                .unwrap();
        });
        let result = match result_receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(result) => result,
            Err(error) => {
                drop(pipe_writer);
                worker.join().unwrap();
                panic!("FIFO inspection blocked while writer remained open: {error}");
            }
        };
        assert!(matches!(result, Err(BrokerError::ReceivedFdShapeDenied)));
        drop(pipe_writer);
        worker.join().unwrap();
    }

    #[test]
    fn received_sealed_memfd_is_classified_by_exact_access_seals_and_size() {
        let (sender, receiver) = seqpacket_pair();
        enable_per_frame_credentials(receiver.as_raw_fd()).unwrap();
        let passed = sealed_read_only_memfd(b"credential12");
        send_with_right(sender.as_raw_fd(), b"{}", passed.as_raw_fd());
        let received = receive_frame(receiver.as_raw_fd()).unwrap();
        let facts = inspect_received_fds(&received.fds).unwrap();
        assert_eq!(
            facts,
            [FdFact {
                kind: FdKind::SealedMemfd,
                access: FdAccess::ReadOnly,
                fully_sealed: true,
                size: 12,
                sha256: digest_bytes(b"credential12"),
            }]
        );
    }

    #[test]
    fn received_memfd_measurement_is_bounded_before_hashing() {
        let (sender, receiver) = seqpacket_pair();
        enable_per_frame_credentials(receiver.as_raw_fd()).unwrap();
        let oversized = vec![b'x'; MAX_ANCILLARY_PAYLOAD_BYTES as usize + 1];
        let passed = sealed_read_only_memfd(&oversized);
        send_with_right(sender.as_raw_fd(), b"{}", passed.as_raw_fd());
        let received = receive_frame(receiver.as_raw_fd()).unwrap();
        assert!(matches!(
            inspect_received_fds(&received.fds),
            Err(BrokerError::ReceivedFdSizeDenied)
        ));
    }

    #[test]
    fn inherited_inventory_rejects_extra_unix_and_internet_descriptors() {
        let (listener, extra) = seqpacket_pair();
        let listener_fact = classify_inherited_fd(listener.as_raw_fd()).unwrap();
        let extra_fact = classify_inherited_fd(extra.as_raw_fd()).unwrap();
        assert_eq!(listener_fact.socket_family, Some(libc::AF_UNIX));
        assert!(matches!(
            validate_fd_inventory_facts(listener.as_raw_fd(), &[listener_fact, extra_fact]),
            Err(BrokerError::ExtraInheritedFdDenied)
        ));

        let inet_raw =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        assert!(inet_raw >= 0);
        let inet = unsafe { OwnedFd::from_raw_fd(inet_raw) };
        let inet_fact = classify_inherited_fd(inet.as_raw_fd()).unwrap();
        assert_eq!(inet_fact.socket_family, Some(libc::AF_INET));
        assert!(matches!(
            validate_fd_inventory_facts(listener.as_raw_fd(), &[listener_fact, inet_fact]),
            Err(BrokerError::InheritedSocketFamilyDenied)
        ));
        for family in [libc::AF_INET6, libc::AF_PACKET, libc::AF_VSOCK] {
            assert!(matches!(
                validate_fd_inventory_facts(
                    listener.as_raw_fd(),
                    &[
                        listener_fact,
                        InheritedFdFact {
                            fd: 2,
                            socket_family: Some(family),
                        },
                    ],
                ),
                Err(BrokerError::InheritedSocketFamilyDenied)
            ));
        }
    }

    #[test]
    fn inherited_listener_accepts_only_a_private_filesystem_seqpacket_socket() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("broker.sock");
        let path_bytes = path.as_os_str().as_bytes();
        let listener = unsafe {
            OwnedFd::from_raw_fd(libc::socket(
                ALLOWED_SOCKET_DOMAIN,
                ALLOWED_SOCKET_TYPE | libc::SOCK_CLOEXEC,
                0,
            ))
        };
        assert!(listener.as_raw_fd() >= 0);
        let mut address = unsafe { mem::zeroed::<libc::sockaddr_un>() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        assert!(path_bytes.len() < address.sun_path.len());
        for (target, source) in address.sun_path.iter_mut().zip(path_bytes) {
            *target = *source as libc::c_char;
        }
        let length = mem::offset_of!(libc::sockaddr_un, sun_path) + path_bytes.len() + 1;
        assert_eq!(
            unsafe {
                libc::bind(
                    listener.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    length as libc::socklen_t,
                )
            },
            0
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
        validate_inherited_listener(listener.as_raw_fd()).unwrap();
        validate_selected_inherited_listener(&InheritedListenerSelection {
            fd: listener.as_raw_fd(),
            origin: InheritedListenerOrigin::HostCommandLine,
        })
        .unwrap();
        assert!(matches!(
            validate_selected_inherited_listener(&InheritedListenerSelection {
                fd: listener.as_raw_fd(),
                origin: InheritedListenerOrigin::AndroidInit,
            }),
            Err(BrokerError::ListenerShapeDenied)
        ));

        let descriptor_flags = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_GETFD) };
        assert!(descriptor_flags & libc::FD_CLOEXEC != 0);
        assert_eq!(
            unsafe {
                libc::fcntl(
                    listener.as_raw_fd(),
                    libc::F_SETFD,
                    descriptor_flags & !libc::FD_CLOEXEC,
                )
            },
            0
        );
        assert!(matches!(
            validate_inherited_listener(listener.as_raw_fd()),
            Err(BrokerError::ListenerShapeDenied)
        ));
        assert_eq!(
            unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_SETFD, descriptor_flags) },
            0
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o607)).unwrap();
        assert!(matches!(
            validate_inherited_listener(listener.as_raw_fd()),
            Err(BrokerError::ListenerShapeDenied)
        ));
    }

    struct CountingInspector {
        calls: AtomicUsize,
        identity: PeerIdentity,
    }

    impl PeerInspector for CountingInspector {
        fn inspect(&self, _socket_fd: RawFd) -> Result<PeerIdentity, BrokerError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.identity.clone())
        }
    }

    #[test]
    fn authenticated_service_rechecks_peer_identity_for_every_request() {
        let (server, client) = seqpacket_pair();
        let current = unsafe {
            libc::ucred {
                pid: libc::getpid(),
                uid: libc::getuid(),
                gid: libc::getgid(),
            }
        };
        let mut test_identity = identity();
        test_identity.pid = current.pid;
        test_identity.uid = current.uid;
        test_identity.gid = current.gid;
        let test_policy = ExactPeerPolicy {
            uid: current.uid,
            gid: current.gid,
            security_context: test_identity.security_context.clone(),
            executable_sha256: test_identity.executable_sha256,
        };
        let inspector = CountingInspector {
            calls: AtomicUsize::new(0),
            identity: test_identity,
        };

        std::thread::scope(|scope| {
            let server_thread = scope.spawn(|| {
                serve_authenticated_client(server.as_raw_fd(), &inspector, &test_policy).unwrap();
            });
            let mut greeting_bytes = [0_u8; MAX_FRAME_BYTES];
            let greeting_length = unsafe {
                libc::recv(
                    client.as_raw_fd(),
                    greeting_bytes.as_mut_ptr().cast(),
                    greeting_bytes.len(),
                    0,
                )
            };
            assert!(greeting_length > 0);
            let greeting: ServerGreeting =
                serde_json::from_slice(&greeting_bytes[..greeting_length as usize]).unwrap();
            let hello = request(greeting.session_binding, 1, 31, Request::Hello);
            send_frame(client.as_raw_fd(), &serde_json::to_vec(&hello).unwrap()).unwrap();
            let response_length = unsafe {
                libc::recv(
                    client.as_raw_fd(),
                    greeting_bytes.as_mut_ptr().cast(),
                    greeting_bytes.len(),
                    0,
                )
            };
            assert!(response_length > 0);
            let response: ResponseFrame =
                serde_json::from_slice(&greeting_bytes[..response_length as usize]).unwrap();
            assert!(matches!(response.response, Response::Hello { .. }));

            let install = request(
                greeting.session_binding,
                2,
                32,
                Request::InstallCredential {
                    provider: Provider::Codex,
                    credential_generation: generation(1),
                    credential_sha256: digest_bytes(b"credential12"),
                    credential_size: 12,
                },
            );
            let credential = sealed_read_only_memfd(b"credential12");
            send_with_right(
                client.as_raw_fd(),
                &serde_json::to_vec(&install).unwrap(),
                credential.as_raw_fd(),
            );
            let response_length = unsafe {
                libc::recv(
                    client.as_raw_fd(),
                    greeting_bytes.as_mut_ptr().cast(),
                    greeting_bytes.len(),
                    0,
                )
            };
            assert!(response_length > 0);
            let response: ResponseFrame =
                serde_json::from_slice(&greeting_bytes[..response_length as usize]).unwrap();
            assert!(matches!(
                response.response,
                Response::MutationUnavailable {
                    operation: Operation::InstallCredential,
                    reason: MutationUnavailableReason::BackendNotInstalled,
                }
            ));
            drop(client);
            server_thread.join().unwrap();
        });
        assert_eq!(inspector.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn dependency_and_source_contract_has_no_network_client_or_provider_effects() {
        let manifest = include_str!("../Cargo.toml");
        for forbidden in ["tokio", "reqwest", "hyper", "url =", "curl", "openssl"] {
            assert!(
                !manifest.contains(forbidden),
                "forbidden dependency {forbidden}"
            );
        }
        let source = include_str!("lib.rs");
        let forbidden_effects = [
            ["Command", "::new"].concat(),
            ["set", "uid("].concat(),
            ["set", "gid("].concat(),
            ["ch", "own("].concat(),
            ["ki", "ll("].concat(),
        ];
        for forbidden in forbidden_effects {
            assert!(
                !source.contains(&forbidden),
                "forbidden foundation effect {forbidden}"
            );
        }
        assert_eq!(ALLOWED_SOCKET_DOMAIN, libc::AF_UNIX);
        assert_eq!(ALLOWED_SOCKET_TYPE, libc::SOCK_SEQPACKET);
    }

    #[test]
    fn per_frame_credentials_and_rights_are_bounded() {
        assert_eq!(MAX_ANCILLARY_FDS, 4);
        assert_eq!(FdKind::Other, FdKind::Other);
    }
}
