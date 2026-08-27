//! Dedicated root-authenticated Direct operation tool-call session handler.
//!
//! The session is deliberately not the capability-lease root-publication
//! protocol. A provider-side path must have durably preissued one logical
//! delivery before the adapter can recover it here. The handler then performs
//! canonical allocation and accepts one adapter PREPARED acknowledgement only
//! after exact framing, binding, kernel peer custody, and EOF checks.
//!
//! A capability-gated `bind_product` seam now exists for pre-effect integration
//! tests, but it retains allocator/provider proof custody and has no product
//! accept/serve method. Main does not call it, the provider-delivery capability
//! is product-uninhabited, and every product/effect contract flag remains false.
#![allow(dead_code)]

use std::fs::File;
use std::io::{Read, Write};
use std::mem::{self, MaybeUninit};
#[cfg(target_os = "android")]
use std::os::android::net::SocketAddrExt as _;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt as _;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(feature = "p0-launch-package-device-conformance")]
use std::sync::Arc;
#[cfg(feature = "p0-launch-package-device-conformance")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use trillionnium_os_types::agent_principal_registry;
use trillionnium_os_types::direct_operation::{
    DirectOperationAdapter, DirectOperationBinding, DirectOperationKernelLaunchCustodyV3,
    DirectOperationToolCallAllocationRequestV3, DirectOperationToolCallCommitReceiptV3,
    DirectOperationToolCallPreparedAckV3,
};
#[cfg(feature = "p0-launch-package-device-conformance")]
use trillionnium_os_types::direct_operation::{
    DirectOperationAdapterTerminalDispositionV1, DirectOperationOuterEvidence,
};
#[cfg(test)]
use trillionnium_os_types::direct_operation::{
    DirectOperationToolCallDeliveryV3, DirectOperationToolCallEnvelopeV3,
};
#[cfg(feature = "p0-launch-package-device-conformance")]
use trillionnium_os_types::direct_operation_tool_call_transport::P0UserdebugAdapterTerminalCommitV1;
#[cfg(feature = "p0-launch-package-device-conformance")]
use trillionnium_os_types::direct_operation_tool_call_transport::P0UserdebugDirectOperationToolCallSessionHelloV1;
use trillionnium_os_types::direct_operation_tool_call_transport::{
    self as contract, DirectOperationToolCallSessionHelloV3,
};

#[cfg(feature = "p0-launch-package-device-conformance")]
use crate::direct_operation_custody::{DirectOperationCustodyStore, VerifiedAdapterDisposition};
#[cfg(feature = "p0-launch-package-device-conformance")]
use crate::direct_tool_call_allocator::VerifiedP0UserdebugAllocator;
use crate::direct_tool_call_allocator::{
    DirectToolCallAllocator, VerifiedAdapterAllocationRequest,
    VerifiedAdapterPreparedAcknowledgement, VerifiedDaemonLogicalDelivery,
    VerifiedProductAllocatorListener,
};

const SESSION_TIMEOUT: Duration = Duration::from_secs(5);
const PROC_SUPER_MAGIC: libc::c_long = 0x0000_9fa0;
const MAX_SECURITY_CONTEXT_BYTES: usize = 256;
const MAX_PROC_IDENTITY_BYTES: usize = 4096;
const MAX_ADAPTER_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "p0-launch-package-device-conformance")]
const P0_USERDEBUG_SESSION_TIMEOUT: Duration = Duration::from_secs(95);
#[cfg(feature = "p0-launch-package-device-conformance")]
const P0_USERDEBUG_SYSTEM_API_SHA256: Option<&str> =
    option_env!("TRILLIONNIUM_P01_SYSTEM_API_SHA256");

pub(crate) const SOURCE_STATUS: &str =
    "source_only_fixed_single_session_listener_no_main_dispatch_no_product_wiring_v1";

/// Fixed one-session listener for source verification only.
///
/// The listener is deliberately unavailable from `trillionniumd` main and
/// cannot construct either a durable allocator or a provider logical-delivery
/// capability. Keeping the bind/accept seam concrete lets the kernel peer and
/// launch-custody checks be reviewed and tested without claiming product
/// authority.
pub(crate) struct FixedDirectToolCallListener {
    listener: UnixListener,
}

/// A fixed listener whose lifetime retains both exact allocator high-water
/// custody and one verified provider-delivery capability.  There is
/// deliberately no product accept/serve method yet: binding proves only the
/// pre-effect transport admission boundary.
#[must_use = "product-bound listener admission must remain in retained custody"]
pub(crate) struct ProductBoundDirectToolCallListener<'a> {
    listener: FixedDirectToolCallListener,
    allocator: VerifiedProductAllocatorListener<'a>,
    provider_delivery: VerifiedDaemonLogicalDelivery,
    route_sha256: String,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
#[must_use = "P0 userdebug listener must be consumed by exactly one session"]
pub(crate) struct P0UserdebugBoundDirectToolCallListener {
    listener: FixedDirectToolCallListener,
    cancellation: P0UserdebugDirectToolCallCancellation,
    allocator: DirectToolCallAllocator,
    binding: DirectOperationBinding,
    binding_sha256: String,
    adapter: DirectOperationAdapter,
    expected_executable_sha256: String,
    custody_store: DirectOperationCustodyStore,
}

/// Explicit one-shot wakeup for the P0 listener's pre-tool accept wait.
///
/// The eventfd is retained by both the dispatch thread and listener thread, so
/// provider termination can synchronously wake and reap the listener without
/// closing an unrelated process-global socket or polling a shared flag.
#[cfg(feature = "p0-launch-package-device-conformance")]
#[derive(Clone)]
pub(crate) struct P0UserdebugDirectToolCallCancellation {
    descriptor: Arc<OwnedFd>,
    cancelled: Arc<AtomicBool>,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
pub(crate) enum P0UserdebugDirectToolCallSessionTermination {
    Completed(P0UserdebugDirectToolCallSessionOutcome),
    CancelledBeforeTool(P0UserdebugDirectToolCallCancelledBeforeTool),
}

#[cfg(feature = "p0-launch-package-device-conformance")]
pub(crate) struct P0UserdebugDirectToolCallCancelledBeforeTool {
    custody_store: DirectOperationCustodyStore,
    binding: DirectOperationBinding,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl P0UserdebugDirectToolCallCancelledBeforeTool {
    pub(crate) fn commit_no_dispatch(mut self) -> Result<()> {
        let expected = self.custody_store.head();
        let committed = self
            .custody_store
            .cancel_published_binding_before_tool(&expected, &self.binding)?;
        if committed != self.custody_store.head()
            || self.custody_store.publication_durability_uncertain()
        {
            bail!("direct_tool_call_listener_p0_cancel_custody_commit_denied");
        }
        Ok(())
    }
}

#[cfg(feature = "p0-launch-package-device-conformance")]
enum P0UserdebugAcceptOutcome {
    Accepted(UnixStream),
    CancelledBeforeTool,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
pub(crate) struct P0UserdebugDirectToolCallSessionOutcome {
    pub(crate) commit_receipt: DirectOperationToolCallCommitReceiptV3,
    pub(crate) terminal_evidence: DirectOperationOuterEvidence,
    pub(crate) custody_store: DirectOperationCustodyStore,
    pub(crate) delivery_binding: DirectOperationBinding,
    pub(crate) allocation_binding: DirectOperationBinding,
}

impl ProductBoundDirectToolCallListener<'_> {
    fn validate_pre_effect_admission(&self) -> Result<()> {
        self.listener.validate()?;
        self.allocator.validate_delivery(&self.provider_delivery)?;
        if self.allocator.route_sha256() != self.route_sha256 {
            bail!("direct_tool_call_listener_product_route_drift_denied");
        }
        Ok(())
    }
}

impl FixedDirectToolCallListener {
    pub(crate) fn bind_product<'a>(
        allocator: VerifiedProductAllocatorListener<'a>,
        provider_delivery: VerifiedDaemonLogicalDelivery,
    ) -> Result<ProductBoundDirectToolCallListener<'a>> {
        if !contract::SOURCE_LISTENER_IMPLEMENTED
            || !contract::SOURCE_SESSION_HANDLER_IMPLEMENTED
            || contract::DAEMON_LISTENER_PRODUCT_WIRED
            || contract::PROVIDER_DELIVERY_PRODUCT_WIRED
            || contract::FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE
            || contract::ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE
            || contract::CONFERS_EFFECT_AUTHORITY
        {
            bail!("direct_tool_call_listener_product_pre_effect_contract_denied");
        }
        allocator.validate_delivery(&provider_delivery)?;
        let route_sha256 = allocator.route_sha256().to_string();
        let listener = Self {
            listener: bind_fixed_listener()?,
        };
        listener.validate()?;
        Ok(ProductBoundDirectToolCallListener {
            listener,
            allocator,
            provider_delivery,
            route_sha256,
        })
    }

    pub(crate) fn bind_source_disabled() -> Result<Self> {
        if !contract::SOURCE_LISTENER_IMPLEMENTED
            || !contract::SOURCE_SESSION_HANDLER_IMPLEMENTED
            || contract::DAEMON_LISTENER_PRODUCT_WIRED
            || contract::PROVIDER_DELIVERY_PRODUCT_WIRED
            || contract::FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE
            || contract::ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE
            || contract::CONFERS_EFFECT_AUTHORITY
        {
            bail!("direct_tool_call_listener_source_disabled_contract_denied");
        }
        let listener = bind_fixed_listener()?;
        let fixed = Self { listener };
        fixed.validate()?;
        Ok(fixed)
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn bind_p0_userdebug(
        custody_store: DirectOperationCustodyStore,
        verified_allocator: VerifiedP0UserdebugAllocator,
    ) -> Result<(
        P0UserdebugBoundDirectToolCallListener,
        P0UserdebugDirectToolCallCancellation,
    )> {
        verified_allocator.validate()?;
        if option_env!("TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT") != Some("userdebug")
            || contract::DAEMON_LISTENER_PRODUCT_WIRED
            || contract::ADAPTER_CONNECTOR_PRODUCT_WIRED
            || contract::PROVIDER_DELIVERY_PRODUCT_WIRED
            || contract::FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE
            || contract::ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE
            || contract::CONFERS_EFFECT_AUTHORITY
        {
            bail!("direct_tool_call_listener_p0_userdebug_contract_denied");
        }
        let expected_executable_sha256 = P0_USERDEBUG_SYSTEM_API_SHA256
            .filter(|value| valid_nonzero_sha256(value))
            .context("direct_tool_call_listener_p0_system_api_measurement_unavailable")?
            .to_string();
        let (allocator, binding, adapter) = verified_allocator.into_parts();
        let binding_sha256 = binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let listener = Self {
            listener: bind_fixed_listener()?,
        };
        listener.validate()?;
        let cancellation = P0UserdebugDirectToolCallCancellation::new()?;
        Ok((
            P0UserdebugBoundDirectToolCallListener {
                listener,
                cancellation: cancellation.clone(),
                allocator,
                binding,
                binding_sha256,
                adapter,
                expected_executable_sha256,
                custody_store,
            },
            cancellation,
        ))
    }

    fn accept_once(self, timeout: Duration) -> Result<UnixStream> {
        self.validate()?;
        poll_readable(self.listener.as_raw_fd(), Instant::now() + timeout)?;
        self.validate()?;
        let (stream, peer_address) = self
            .listener
            .accept()
            .context("direct_tool_call_listener_accept_denied")?;
        if !peer_address.is_unnamed() {
            bail!("direct_tool_call_listener_named_peer_denied");
        }
        stream
            .set_nonblocking(false)
            .context("direct_tool_call_listener_stream_mode_denied")?;
        require_cloexec(stream.as_raw_fd())?;
        Ok(stream)
    }

    fn accept_source_disabled_once(self) -> Result<UnixStream> {
        self.accept_once(ACCEPT_TIMEOUT)
    }

    fn validate(&self) -> Result<()> {
        require_cloexec(self.listener.as_raw_fd())?;
        if fcntl(self.listener.as_raw_fd(), libc::F_GETFL)? & libc::O_NONBLOCK == 0
            || socket_option(self.listener.as_raw_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM
            || socket_option(self.listener.as_raw_fd(), libc::SO_ACCEPTCONN)? != 1
        {
            bail!("direct_tool_call_listener_shape_denied");
        }
        let address = self
            .listener
            .local_addr()
            .context("direct_tool_call_listener_address_denied")?;
        if address.as_abstract_name() != Some(contract::SOCKET_NAME.as_bytes()) {
            bail!("direct_tool_call_listener_address_denied");
        }
        Ok(())
    }

    /// Accept, authenticate, and serve exactly one source-only session.
    ///
    /// Authentication is completed before allocator state can be read or
    /// mutated. Consuming `self` makes retries create and revalidate a new
    /// fixed listener rather than retaining an ambient accepting descriptor.
    pub(crate) fn serve_source_disabled_once(
        self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
        allocator: &mut DirectToolCallAllocator,
    ) -> Result<DirectOperationToolCallCommitReceiptV3> {
        let stream = self.accept_source_disabled_once()?;
        let peer = authenticate_adapter_peer(&stream, binding, binding_sha256, adapter, custody)?;
        serve_authenticated_session(
            stream,
            &peer,
            binding,
            binding_sha256,
            adapter,
            custody,
            allocator,
        )
    }
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl P0UserdebugDirectToolCallCancellation {
    fn new() -> Result<Self> {
        let descriptor = unsafe {
            libc::eventfd(
                0,
                libc::EFD_CLOEXEC | libc::EFD_NONBLOCK | libc::EFD_SEMAPHORE,
            )
        };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error())
                .context("direct_tool_call_listener_p0_cancel_eventfd_denied");
        }
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        require_cloexec(descriptor.as_raw_fd())?;
        Ok(Self {
            descriptor: Arc::new(descriptor),
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(crate) fn cancel(&self) -> Result<()> {
        if self.cancelled.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let value = 1_u64.to_ne_bytes();
        loop {
            let written = unsafe {
                libc::write(
                    self.descriptor.as_raw_fd(),
                    value.as_ptr().cast(),
                    value.len(),
                )
            };
            if written == value.len() as isize {
                return Ok(());
            }
            if written >= 0 {
                bail!("direct_tool_call_listener_p0_cancel_short_write_denied");
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if error.raw_os_error() == Some(libc::EAGAIN) {
                // A saturated eventfd is already readable and therefore has
                // the required wakeup semantics.
                return Ok(());
            }
            return Err(error).context("direct_tool_call_listener_p0_cancel_signal_denied");
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl P0UserdebugBoundDirectToolCallListener {
    pub(crate) fn serve_once_until(
        mut self,
        invocation_deadline: Instant,
    ) -> Result<P0UserdebugDirectToolCallSessionTermination> {
        if self.adapter != DirectOperationAdapter::SystemApi {
            bail!("direct_tool_call_listener_p0_adapter_denied");
        }
        let stream = match accept_once_until_or_cancel(
            self.listener,
            &self.cancellation,
            invocation_deadline,
        )? {
            P0UserdebugAcceptOutcome::Accepted(stream) => stream,
            P0UserdebugAcceptOutcome::CancelledBeforeTool => {
                return Ok(
                    P0UserdebugDirectToolCallSessionTermination::CancelledBeforeTool(
                        P0UserdebugDirectToolCallCancelledBeforeTool {
                            custody_store: self.custody_store,
                            binding: self.binding,
                        },
                    ),
                );
            }
        };
        let peer = authenticate_p0_userdebug_adapter_peer(
            &stream,
            &self.binding,
            &self.binding_sha256,
            self.adapter,
            &self.expected_executable_sha256,
        )?;
        let binding_sha256 = self.binding_sha256.clone();
        let mut attach_disposition = |verified| {
            let expected = self.custody_store.head();
            self.custody_store
                .attach_authenticated_adapter_disposition(&expected, &binding_sha256, verified)?;
            Ok(())
        };
        let (commit_receipt, terminal_evidence) = serve_p0_userdebug_authenticated_session(
            stream,
            &peer,
            &self.binding,
            &self.binding_sha256,
            self.adapter,
            &mut self.allocator,
            &mut attach_disposition,
        )?;
        Ok(P0UserdebugDirectToolCallSessionTermination::Completed(
            P0UserdebugDirectToolCallSessionOutcome {
                commit_receipt,
                terminal_evidence,
                custody_store: self.custody_store,
                delivery_binding: self.binding.clone(),
                allocation_binding: self.binding,
            },
        ))
    }
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn accept_once_until_or_cancel(
    listener: FixedDirectToolCallListener,
    cancellation: &P0UserdebugDirectToolCallCancellation,
    invocation_deadline: Instant,
) -> Result<P0UserdebugAcceptOutcome> {
    listener.validate()?;
    match poll_readable_or_cancel(
        listener.listener.as_raw_fd(),
        cancellation,
        invocation_deadline,
    )? {
        P0UserdebugPollOutcome::Cancelled => {
            return Ok(P0UserdebugAcceptOutcome::CancelledBeforeTool);
        }
        P0UserdebugPollOutcome::Readable => {}
    }
    listener.validate()?;
    let (stream, peer_address) = listener
        .listener
        .accept()
        .context("direct_tool_call_listener_accept_denied")?;
    // Cancellation wins a simultaneous readiness race. The accepted stream is
    // dropped before authentication, delivery recovery, allocation, PREPARED,
    // or ACK can occur.
    if cancellation.is_cancelled() {
        return Ok(P0UserdebugAcceptOutcome::CancelledBeforeTool);
    }
    if !peer_address.is_unnamed() {
        bail!("direct_tool_call_listener_named_peer_denied");
    }
    stream
        .set_nonblocking(false)
        .context("direct_tool_call_listener_stream_mode_denied")?;
    require_cloexec(stream.as_raw_fd())?;
    Ok(P0UserdebugAcceptOutcome::Accepted(stream))
}

fn bind_fixed_listener() -> Result<UnixListener> {
    let descriptor = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_listener_socket_denied");
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let mut address = unsafe { mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let name = contract::SOCKET_NAME.as_bytes();
    if name.is_empty() || name.len() + 1 > address.sun_path.len() {
        bail!("direct_tool_call_listener_name_denied");
    }
    for (destination, source) in address.sun_path[1..].iter_mut().zip(name) {
        *destination = *source as libc::c_char;
    }
    let length = (mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len())
        .try_into()
        .context("direct_tool_call_listener_length_denied")?;
    if unsafe {
        libc::bind(
            descriptor.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    } != 0
        || unsafe { libc::listen(descriptor.as_raw_fd(), 1) } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_listener_bind_denied");
    }
    Ok(UnixListener::from(descriptor))
}

fn require_cloexec(fd: RawFd) -> Result<()> {
    if fcntl(fd, libc::F_GETFD)? & libc::FD_CLOEXEC == 0 {
        bail!("direct_tool_call_listener_cloexec_denied");
    }
    Ok(())
}

fn fcntl(fd: RawFd, command: libc::c_int) -> Result<libc::c_int> {
    let result = unsafe { libc::fcntl(fd, command) };
    if result < 0 {
        Err(std::io::Error::last_os_error()).context("direct_tool_call_listener_fcntl_denied")
    } else {
        Ok(result)
    }
}

fn socket_option(fd: RawFd, option: libc::c_int) -> Result<libc::c_int> {
    let mut value = 0;
    let mut length = mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
        || length as usize != mem::size_of::<libc::c_int>()
    {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_listener_socket_option_denied");
    }
    Ok(value)
}

fn poll_readable(fd: RawFd, deadline: Instant) -> Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("direct_tool_call_listener_accept_timeout")?;
        let timeout = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            if descriptor.revents == libc::POLLIN {
                return Ok(());
            }
            bail!("direct_tool_call_listener_poll_denied");
        }
        if result == 0 {
            bail!("direct_tool_call_listener_accept_timeout");
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(std::io::Error::last_os_error())
                .context("direct_tool_call_listener_poll_denied");
        }
    }
}

#[cfg(feature = "p0-launch-package-device-conformance")]
#[derive(Debug, Eq, PartialEq)]
enum P0UserdebugPollOutcome {
    Readable,
    Cancelled,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn poll_readable_or_cancel(
    fd: RawFd,
    cancellation: &P0UserdebugDirectToolCallCancellation,
    deadline: Instant,
) -> Result<P0UserdebugPollOutcome> {
    loop {
        if cancellation.is_cancelled() {
            return Ok(P0UserdebugPollOutcome::Cancelled);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("direct_tool_call_listener_p0_invocation_deadline_exceeded")?;
        let timeout = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptors = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: cancellation.descriptor.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result =
            unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, timeout) };
        if result > 0 {
            if cancellation.is_cancelled() || descriptors[1].revents & libc::POLLIN != 0 {
                return Ok(P0UserdebugPollOutcome::Cancelled);
            }
            if descriptors[1].revents != 0 {
                bail!("direct_tool_call_listener_p0_cancel_poll_denied");
            }
            if descriptors[0].revents == libc::POLLIN {
                return Ok(P0UserdebugPollOutcome::Readable);
            }
            bail!("direct_tool_call_listener_poll_denied");
        }
        if result == 0 {
            bail!("direct_tool_call_listener_p0_invocation_deadline_exceeded");
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(std::io::Error::last_os_error())
                .context("direct_tool_call_listener_poll_denied");
        }
    }
}

/// Sealed proof that this exact accepted socket peer remains the measured
/// adapter process named by the root-authored launch-custody envelope.
pub(crate) struct VerifiedAdapterTransportPeer {
    binding_sha256: String,
    adapter: DirectOperationAdapter,
    launch_custody_sha256: String,
    identity_sha256: String,
    observation: AdapterTransportPeerObservation,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
pub(crate) struct VerifiedP0UserdebugAdapterTransportPeer {
    binding_sha256: String,
    adapter: DirectOperationAdapter,
    expected_executable_sha256: String,
    identity_sha256: String,
    observation: AdapterTransportPeerObservation,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl VerifiedP0UserdebugAdapterTransportPeer {
    pub(crate) fn identity_sha256(&self) -> &str {
        &self.identity_sha256
    }

    fn validate_for(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> Result<()> {
        binding
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        if binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?
            != binding_sha256
            || self.binding_sha256 != binding_sha256
            || self.adapter != adapter
            || adapter != DirectOperationAdapter::SystemApi
            || !binding.authorized_adapter_set.authorizes(adapter)
            || !valid_nonzero_sha256(&self.expected_executable_sha256)
            || !valid_nonzero_sha256(&self.identity_sha256)
        {
            bail!("direct_tool_call_transport_p0_peer_binding_denied");
        }
        let (peer_pid, observed, pidfd_device, pidfd_inode) = match &self.observation {
            AdapterTransportPeerObservation::Kernel { peer_pid, pidfd } => {
                require_live_pidfd(pidfd)?;
                let observed = observe_process(*peer_pid)?;
                require_live_pidfd(pidfd)?;
                let metadata = pidfd
                    .metadata()
                    .context("direct_tool_call_transport_p0_pidfd_metadata_denied")?;
                (*peer_pid, observed, metadata.dev(), metadata.ino())
            }
            #[cfg(test)]
            AdapterTransportPeerObservation::HostFixture {
                peer_pid,
                observed,
                pidfd_device,
                pidfd_inode,
            } => (*peer_pid, observed.clone(), *pidfd_device, *pidfd_inode),
        };
        validate_p0_userdebug_observed_peer_identity(
            binding_sha256,
            adapter,
            peer_pid,
            &self.expected_executable_sha256,
            &observed,
            pidfd_device,
            pidfd_inode,
            &self.identity_sha256,
        )
    }

    #[cfg(test)]
    fn for_host_fixture_test(
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        expected_executable_sha256: &str,
    ) -> Result<Self> {
        if adapter != DirectOperationAdapter::SystemApi
            || !valid_nonzero_sha256(expected_executable_sha256)
        {
            bail!("direct_tool_call_transport_p0_fixture_denied");
        }
        let peer_pid = 42;
        let observed = ObservedProcess {
            start_time_ticks: 88,
            boot_id_sha256: trillionnium_os_types::sha256_bytes(b"fixture-p0-boot"),
            executable_sha256: expected_executable_sha256.to_string(),
            unified_cgroup_path: "/trillionnium/p0-userdebug/codex/system-api".to_string(),
            selinux_context: contract::adapter_selinux_domain(adapter).to_string(),
        };
        let pidfd_device = 91;
        let pidfd_inode = 93;
        let identity_sha256 = p0_userdebug_identity_digest(
            binding_sha256,
            adapter,
            peer_pid,
            expected_executable_sha256,
            &observed,
            pidfd_device,
            pidfd_inode,
        );
        let peer = Self {
            binding_sha256: binding_sha256.to_string(),
            adapter,
            expected_executable_sha256: expected_executable_sha256.to_string(),
            identity_sha256,
            observation: AdapterTransportPeerObservation::HostFixture {
                peer_pid,
                observed,
                pidfd_device,
                pidfd_inode,
            },
        };
        peer.validate_for(binding, binding_sha256, adapter)?;
        Ok(peer)
    }
}

enum AdapterTransportPeerObservation {
    Kernel {
        peer_pid: u32,
        pidfd: File,
    },
    #[cfg(test)]
    HostFixture {
        peer_pid: u32,
        observed: ObservedProcess,
        pidfd_device: u64,
        pidfd_inode: u64,
    },
}

impl VerifiedAdapterTransportPeer {
    pub(crate) fn identity_sha256(&self) -> &str {
        &self.identity_sha256
    }

    pub(crate) fn validate_for(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
    ) -> Result<()> {
        custody
            .validate_for(binding, binding_sha256, adapter)
            .map_err(|error| anyhow!(error.to_string()))?;
        if self.binding_sha256 != binding_sha256
            || self.adapter != adapter
            || self.launch_custody_sha256 != custody.launch_custody_sha256
            || !valid_nonzero_sha256(&self.identity_sha256)
        {
            bail!("direct_tool_call_transport_peer_binding_denied");
        }
        let (observed, pidfd_device, pidfd_inode) = match &self.observation {
            AdapterTransportPeerObservation::Kernel { peer_pid, pidfd } => {
                if *peer_pid != custody.adapter_pid {
                    bail!("direct_tool_call_transport_peer_binding_denied");
                }
                require_live_pidfd(pidfd)?;
                let observed = observe_process(*peer_pid)?;
                require_live_pidfd(pidfd)?;
                let pidfd_metadata = pidfd
                    .metadata()
                    .context("direct_tool_call_transport_pidfd_metadata_denied")?;
                (observed, pidfd_metadata.dev(), pidfd_metadata.ino())
            }
            #[cfg(test)]
            AdapterTransportPeerObservation::HostFixture {
                peer_pid,
                observed,
                pidfd_device,
                pidfd_inode,
            } => {
                if *peer_pid != custody.adapter_pid {
                    bail!("direct_tool_call_transport_peer_binding_denied");
                }
                (observed.clone(), *pidfd_device, *pidfd_inode)
            }
        };
        validate_observed_peer_identity(
            binding_sha256,
            adapter,
            custody,
            &observed,
            pidfd_device,
            pidfd_inode,
            &self.identity_sha256,
        )
    }

    #[cfg(test)]
    pub(crate) fn for_host_fixture_test(
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
    ) -> Result<Self> {
        custody
            .validate_for(binding, binding_sha256, adapter)
            .map_err(|error| anyhow!(error.to_string()))?;
        let observed = ObservedProcess::from_host_fixture(custody, adapter);
        let pidfd_device = 71;
        let pidfd_inode = 73;
        Ok(Self {
            binding_sha256: binding_sha256.to_string(),
            adapter,
            launch_custody_sha256: custody.launch_custody_sha256.clone(),
            identity_sha256: identity_digest(
                binding_sha256,
                adapter,
                custody,
                &observed,
                pidfd_device,
                pidfd_inode,
            ),
            observation: AdapterTransportPeerObservation::HostFixture {
                peer_pid: custody.adapter_pid,
                observed,
                pidfd_device,
                pidfd_inode,
            },
        })
    }
}

/// Authority-carrier-only ownership of one socket and the peer proof measured
/// from that exact socket. The fields have no crate-visible split operation;
/// the runtime-authority handler consumes this value and can only perform I/O
/// through its `Read`/`Write` implementation.
pub(crate) struct AuthenticatedAdapterAuthorityConnection {
    stream: UnixStream,
    peer: VerifiedAdapterTransportPeer,
}

impl AuthenticatedAdapterAuthorityConnection {
    pub(crate) fn authenticate(
        stream: UnixStream,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
    ) -> Result<Self> {
        let peer = authenticate_adapter_peer(&stream, binding, binding_sha256, adapter, custody)?;
        Ok(Self { stream, peer })
    }

    pub(crate) fn validate_for(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
    ) -> Result<()> {
        self.peer
            .validate_for(binding, binding_sha256, adapter, custody)
    }

    pub(crate) fn peer_identity_sha256(&self) -> &str {
        self.peer.identity_sha256()
    }

    pub(crate) fn set_session_timeouts(&self, timeout: Duration) -> Result<()> {
        self.stream
            .set_read_timeout(Some(timeout))
            .context("direct_runtime_authority_read_timeout_denied")?;
        self.stream
            .set_write_timeout(Some(timeout))
            .context("direct_runtime_authority_write_timeout_denied")
    }

    #[cfg(test)]
    pub(crate) fn for_host_fixture_test(
        stream: UnixStream,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
    ) -> Result<Self> {
        let peer = VerifiedAdapterTransportPeer::for_host_fixture_test(
            binding,
            binding_sha256,
            adapter,
            custody,
        )?;
        Ok(Self { stream, peer })
    }
}

impl Read for AuthenticatedAdapterAuthorityConnection {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(bytes)
    }
}

impl Write for AuthenticatedAdapterAuthorityConnection {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// Authenticate a live adapter connection from kernel state. The pidfd is
/// retained for the entire session so PID reuse cannot substitute a later
/// process after SO_PEERCRED observation.
#[allow(dead_code)]
pub(crate) fn authenticate_adapter_peer(
    stream: &UnixStream,
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    custody: &DirectOperationKernelLaunchCustodyV3,
) -> Result<VerifiedAdapterTransportPeer> {
    binding
        .validate()
        .map_err(|error| anyhow!(error.to_string()))?;
    custody
        .validate_for(binding, binding_sha256, adapter)
        .map_err(|error| anyhow!(error.to_string()))?;
    let descriptor = agent_principal_registry::from_provider_agent_pair(
        &binding.stable_seed.provider_id,
        &binding.stable_seed.agent_id,
    )
    .context("direct_tool_call_transport_descriptor_denied")?;
    let credentials = peer_credentials(stream.as_raw_fd())?;
    let peer_pid =
        u32::try_from(credentials.pid).context("direct_tool_call_transport_peer_pid_denied")?;
    if peer_pid == 0
        || peer_pid != custody.adapter_pid
        || credentials.uid != descriptor.uid
        || credentials.gid != descriptor.gid
        || peer_security_context(stream.as_raw_fd())? != contract::adapter_selinux_domain(adapter)
    {
        bail!("direct_tool_call_transport_peer_kernel_identity_denied");
    }

    let pidfd = open_pidfd(peer_pid)?;
    require_live_pidfd(&pidfd)?;
    let observed = observe_process(peer_pid)?;
    require_live_pidfd(&pidfd)?;
    let pidfd_metadata = pidfd.metadata()?;
    let identity_sha256 = identity_digest(
        binding_sha256,
        adapter,
        custody,
        &observed,
        pidfd_metadata.dev(),
        pidfd_metadata.ino(),
    );
    validate_observed_peer_identity(
        binding_sha256,
        adapter,
        custody,
        &observed,
        pidfd_metadata.dev(),
        pidfd_metadata.ino(),
        &identity_sha256,
    )?;
    Ok(VerifiedAdapterTransportPeer {
        binding_sha256: binding_sha256.to_string(),
        adapter,
        launch_custody_sha256: custody.launch_custody_sha256.clone(),
        identity_sha256,
        observation: AdapterTransportPeerObservation::Kernel { peer_pid, pidfd },
    })
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn authenticate_p0_userdebug_adapter_peer(
    stream: &UnixStream,
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    expected_executable_sha256: &str,
) -> Result<VerifiedP0UserdebugAdapterTransportPeer> {
    binding
        .validate()
        .map_err(|error| anyhow!(error.to_string()))?;
    if binding
        .digest_sha256()
        .map_err(|error| anyhow!(error.to_string()))?
        != binding_sha256
        || adapter != DirectOperationAdapter::SystemApi
        || !binding.authorized_adapter_set.authorizes(adapter)
        || !valid_nonzero_sha256(expected_executable_sha256)
    {
        bail!("direct_tool_call_transport_p0_binding_denied");
    }
    let descriptor = agent_principal_registry::from_provider_agent_pair(
        &binding.stable_seed.provider_id,
        &binding.stable_seed.agent_id,
    )
    .context("direct_tool_call_transport_p0_descriptor_denied")?;
    let credentials = peer_credentials(stream.as_raw_fd())?;
    let peer_pid =
        u32::try_from(credentials.pid).context("direct_tool_call_transport_p0_peer_pid_denied")?;
    if peer_pid <= 1
        || credentials.uid != descriptor.uid
        || credentials.gid != descriptor.gid
        || peer_security_context(stream.as_raw_fd())? != contract::adapter_selinux_domain(adapter)
    {
        bail!("direct_tool_call_transport_p0_peer_kernel_identity_denied");
    }
    let pidfd = open_pidfd(peer_pid)?;
    require_live_pidfd(&pidfd)?;
    let observed = observe_process(peer_pid)?;
    require_live_pidfd(&pidfd)?;
    let metadata = pidfd.metadata()?;
    let identity_sha256 = p0_userdebug_identity_digest(
        binding_sha256,
        adapter,
        peer_pid,
        expected_executable_sha256,
        &observed,
        metadata.dev(),
        metadata.ino(),
    );
    validate_p0_userdebug_observed_peer_identity(
        binding_sha256,
        adapter,
        peer_pid,
        expected_executable_sha256,
        &observed,
        metadata.dev(),
        metadata.ino(),
        &identity_sha256,
    )?;
    Ok(VerifiedP0UserdebugAdapterTransportPeer {
        binding_sha256: binding_sha256.to_string(),
        adapter,
        expected_executable_sha256: expected_executable_sha256.to_string(),
        identity_sha256,
        observation: AdapterTransportPeerObservation::Kernel { peer_pid, pidfd },
    })
}

/// Serve one already-authenticated session. No delivery can be minted here:
/// the provider-side daemon path must have preissued it first.
pub(crate) fn serve_authenticated_session(
    mut stream: UnixStream,
    peer: &VerifiedAdapterTransportPeer,
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    custody: &DirectOperationKernelLaunchCustodyV3,
    allocator: &mut DirectToolCallAllocator,
) -> Result<DirectOperationToolCallCommitReceiptV3> {
    peer.validate_for(binding, binding_sha256, adapter, custody)?;
    stream.set_read_timeout(Some(SESSION_TIMEOUT))?;
    stream.set_write_timeout(Some(SESSION_TIMEOUT))?;

    let hello: DirectOperationToolCallSessionHelloV3 = read_canonical_frame(&mut stream)?;
    hello
        .validate_for(binding, binding_sha256, adapter, custody)
        .map_err(|error| anyhow!(error.to_string()))?;
    peer.validate_for(binding, binding_sha256, adapter, custody)?;

    let delivery = allocator.recover_pending_verified_delivery()?;
    delivery
        .validate_for(binding, binding_sha256, adapter)
        .map_err(|error| anyhow!(error.to_string()))?;
    write_canonical_frame(&mut stream, &delivery)?;

    let request: DirectOperationToolCallAllocationRequestV3 = read_canonical_frame(&mut stream)?;
    request
        .validate_for(&delivery, binding, binding_sha256, adapter)
        .map_err(|error| anyhow!(error.to_string()))?;
    // Re-observe the exact pidfd-bound process immediately before the first
    // allocator mutation; session authentication alone is not sufficient.
    peer.validate_for(binding, binding_sha256, adapter, custody)?;
    let envelope = allocator.allocate_verified_request(
        VerifiedAdapterAllocationRequest::from_authenticated_transport(peer),
        &delivery,
        &request.canonical_request_sha256,
    )?;
    envelope
        .validate_for_allocation_request_v3(&request)
        .map_err(|error| anyhow!(error.to_string()))?;
    write_canonical_frame(&mut stream, &envelope)?;

    let acknowledgement: DirectOperationToolCallPreparedAckV3 = read_canonical_frame(&mut stream)?;
    acknowledgement
        .validate_for_envelope(&envelope)
        .map_err(|error| anyhow!(error.to_string()))?;
    require_peer_write_eof(&mut stream)?;
    // Re-observe again after the peer has sealed its write side and
    // immediately before the PREPARED acknowledgement mutates allocator state.
    peer.validate_for(binding, binding_sha256, adapter, custody)?;
    let receipt = allocator.acknowledge_verified_prepared(
        VerifiedAdapterPreparedAcknowledgement::from_authenticated_transport(peer),
        &acknowledgement,
    )?;
    receipt
        .validate_for_acknowledgement(&acknowledgement)
        .map_err(|error| anyhow!(error.to_string()))?;
    write_canonical_frame(&mut stream, &receipt)?;
    stream.flush()?;
    Ok(receipt)
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn serve_p0_userdebug_authenticated_session(
    mut stream: UnixStream,
    peer: &VerifiedP0UserdebugAdapterTransportPeer,
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    allocator: &mut DirectToolCallAllocator,
    attach_disposition: &mut impl FnMut(VerifiedAdapterDisposition) -> Result<()>,
) -> Result<(
    DirectOperationToolCallCommitReceiptV3,
    DirectOperationOuterEvidence,
)> {
    peer.validate_for(binding, binding_sha256, adapter)?;
    stream.set_read_timeout(Some(P0_USERDEBUG_SESSION_TIMEOUT))?;
    stream.set_write_timeout(Some(P0_USERDEBUG_SESSION_TIMEOUT))?;

    let hello: P0UserdebugDirectOperationToolCallSessionHelloV1 =
        read_canonical_frame(&mut stream)?;
    hello
        .validate_for(binding, binding_sha256, adapter)
        .map_err(|error| anyhow!(error.to_string()))?;
    peer.validate_for(binding, binding_sha256, adapter)?;

    let delivery = allocator.recover_pending_verified_delivery()?;
    delivery
        .validate_for(binding, binding_sha256, adapter)
        .map_err(|error| anyhow!(error.to_string()))?;
    write_canonical_frame(&mut stream, &delivery)?;

    let request: DirectOperationToolCallAllocationRequestV3 = read_canonical_frame(&mut stream)?;
    request
        .validate_for(&delivery, binding, binding_sha256, adapter)
        .map_err(|error| anyhow!(error.to_string()))?;
    peer.validate_for(binding, binding_sha256, adapter)?;
    let envelope = allocator.allocate_verified_request(
        VerifiedAdapterAllocationRequest::from_p0_userdebug_authenticated_transport(peer),
        &delivery,
        &request.canonical_request_sha256,
    )?;
    envelope
        .validate_for_allocation_request_v3(&request)
        .map_err(|error| anyhow!(error.to_string()))?;
    write_canonical_frame(&mut stream, &envelope)?;

    let acknowledgement: DirectOperationToolCallPreparedAckV3 = read_canonical_frame(&mut stream)?;
    acknowledgement
        .validate_for_envelope(&envelope)
        .map_err(|error| anyhow!(error.to_string()))?;
    peer.validate_for(binding, binding_sha256, adapter)?;
    let receipt = allocator.acknowledge_verified_prepared(
        VerifiedAdapterPreparedAcknowledgement::from_p0_userdebug_authenticated_transport(peer),
        &acknowledgement,
    )?;
    receipt
        .validate_for_acknowledgement(&acknowledgement)
        .map_err(|error| anyhow!(error.to_string()))?;
    write_canonical_frame(&mut stream, &receipt)?;
    stream.flush()?;

    let disposition: DirectOperationAdapterTerminalDispositionV1 =
        read_canonical_frame(&mut stream)?;
    disposition
        .validate_for_binding(binding, adapter)
        .map_err(|error| anyhow!(error.to_string()))?;
    let terminal_evidence = {
        let snapshot = disposition
            .ackable_snapshot()
            .map_err(|error| anyhow!(error.to_string()))?;
        let [evidence] = snapshot.evidence.as_slice() else {
            bail!("direct_tool_call_listener_p0_terminal_evidence_cardinality_denied");
        };
        evidence.clone()
    };
    require_peer_write_eof(&mut stream)?;
    peer.validate_for(binding, binding_sha256, adapter)?;
    let verified = VerifiedAdapterDisposition::from_p0_userdebug_authenticated_transport(
        peer,
        binding,
        &acknowledgement,
        &receipt,
        disposition.clone(),
    )?;
    attach_disposition(verified)?;
    let terminal_commit = P0UserdebugAdapterTerminalCommitV1::derive(&receipt, &disposition)
        .map_err(|error| anyhow!(error.to_string()))?;
    write_canonical_frame(&mut stream, &terminal_commit)?;
    stream.flush()?;
    Ok((receipt, terminal_evidence))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedProcess {
    start_time_ticks: u64,
    boot_id_sha256: String,
    executable_sha256: String,
    unified_cgroup_path: String,
    selinux_context: String,
}

impl ObservedProcess {
    #[cfg(test)]
    fn from_host_fixture(
        custody: &DirectOperationKernelLaunchCustodyV3,
        adapter: DirectOperationAdapter,
    ) -> Self {
        Self {
            start_time_ticks: custody.adapter_start_time_ticks,
            boot_id_sha256: custody.boot_id_sha256.clone(),
            executable_sha256: custody.adapter_executable_sha256.clone(),
            unified_cgroup_path: custody.unified_cgroup_path.clone(),
            selinux_context: contract::adapter_selinux_domain(adapter).to_string(),
        }
    }
}

fn observe_process(pid: u32) -> Result<ObservedProcess> {
    let stat = read_proc_file(pid, "stat", MAX_PROC_IDENTITY_BYTES)?;
    let stat =
        std::str::from_utf8(&stat).context("direct_tool_call_transport_peer_stat_not_utf8")?;
    let close = stat
        .rfind(')')
        .context("direct_tool_call_transport_peer_stat_malformed")?;
    let start_time_ticks = stat[close + 1..]
        .split_ascii_whitespace()
        .nth(19)
        .context("direct_tool_call_transport_peer_starttime_missing")?
        .parse::<u64>()
        .context("direct_tool_call_transport_peer_starttime_malformed")?;
    if start_time_ticks == 0 {
        bail!("direct_tool_call_transport_peer_starttime_zero");
    }

    let cgroup = read_proc_file(pid, "cgroup", MAX_PROC_IDENTITY_BYTES)?;
    let cgroup =
        std::str::from_utf8(&cgroup).context("direct_tool_call_transport_peer_cgroup_not_utf8")?;
    let mut unified = None;
    for line in cgroup.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 3 {
            bail!("direct_tool_call_transport_peer_cgroup_malformed");
        }
        if fields[0] == "0"
            && fields[1].is_empty()
            && (unified.replace(fields[2]).is_some() || fields[2].is_empty())
        {
            bail!("direct_tool_call_transport_peer_cgroup_ambiguous");
        }
    }
    let unified_cgroup_path = unified
        .context("direct_tool_call_transport_peer_unified_cgroup_missing")?
        .to_string();

    let boot_id =
        read_fixed_proc_file(c"/proc/sys/kernel/random/boot_id", MAX_PROC_IDENTITY_BYTES)?;
    let boot_id = boot_id.strip_suffix(b"\n").unwrap_or(&boot_id);
    if boot_id.len() != 36
        || boot_id
            .iter()
            .any(|byte| !byte.is_ascii_hexdigit() && *byte != b'-')
    {
        bail!("direct_tool_call_transport_boot_id_malformed");
    }
    let boot_id_sha256 = lower_hex(&Sha256::digest(boot_id));
    let executable_sha256 = hash_process_executable(pid)?;
    let selinux_context = process_security_context(pid)?;
    Ok(ObservedProcess {
        start_time_ticks,
        boot_id_sha256,
        executable_sha256,
        unified_cgroup_path,
        selinux_context,
    })
}

fn validate_observed_peer_identity(
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    custody: &DirectOperationKernelLaunchCustodyV3,
    observed: &ObservedProcess,
    pidfd_device: u64,
    pidfd_inode: u64,
    expected_identity_sha256: &str,
) -> Result<()> {
    if observed.start_time_ticks != custody.adapter_start_time_ticks
        || observed.boot_id_sha256 != custody.boot_id_sha256
        || observed.executable_sha256 != custody.adapter_executable_sha256
        || observed.unified_cgroup_path != custody.unified_cgroup_path
    {
        bail!("direct_tool_call_transport_peer_launch_custody_denied");
    }
    if observed.selinux_context != contract::adapter_selinux_domain(adapter) {
        bail!("direct_tool_call_transport_peer_current_security_context_denied");
    }
    if !valid_nonzero_sha256(expected_identity_sha256)
        || identity_digest(
            binding_sha256,
            adapter,
            custody,
            observed,
            pidfd_device,
            pidfd_inode,
        ) != expected_identity_sha256
    {
        bail!("direct_tool_call_transport_peer_identity_drift_denied");
    }
    Ok(())
}

#[cfg(feature = "p0-launch-package-device-conformance")]
#[allow(clippy::too_many_arguments)]
fn validate_p0_userdebug_observed_peer_identity(
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    peer_pid: u32,
    expected_executable_sha256: &str,
    observed: &ObservedProcess,
    pidfd_device: u64,
    pidfd_inode: u64,
    expected_identity_sha256: &str,
) -> Result<()> {
    if peer_pid <= 1
        || observed.executable_sha256 != expected_executable_sha256
        || observed.unified_cgroup_path.is_empty()
        || observed.unified_cgroup_path == "/"
        || observed.selinux_context != contract::adapter_selinux_domain(adapter)
        || !valid_nonzero_sha256(&observed.boot_id_sha256)
        || observed.start_time_ticks == 0
        || !valid_nonzero_sha256(expected_identity_sha256)
        || p0_userdebug_identity_digest(
            binding_sha256,
            adapter,
            peer_pid,
            expected_executable_sha256,
            observed,
            pidfd_device,
            pidfd_inode,
        ) != expected_identity_sha256
    {
        bail!("direct_tool_call_transport_p0_peer_identity_drift_denied");
    }
    Ok(())
}

fn peer_credentials(fd: RawFd) -> Result<libc::ucred> {
    let mut credentials = MaybeUninit::<libc::ucred>::zeroed();
    let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
        || length as usize != mem::size_of::<libc::ucred>()
    {
        bail!("direct_tool_call_transport_SO_PEERCRED_denied");
    }
    Ok(unsafe { credentials.assume_init() })
}

fn peer_security_context(fd: RawFd) -> Result<String> {
    let mut bytes = [0_u8; MAX_SECURITY_CONTEXT_BYTES];
    let mut length = bytes.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_transport_SO_PEERSEC_unavailable");
    }
    let length = length as usize;
    if length == 0 || length > bytes.len() {
        bail!("direct_tool_call_transport_SO_PEERSEC_malformed");
    }
    let context = bytes[..length]
        .strip_suffix(&[0])
        .unwrap_or(&bytes[..length]);
    if context.is_empty() || context.contains(&0) {
        bail!("direct_tool_call_transport_SO_PEERSEC_malformed");
    }
    let context =
        std::str::from_utf8(context).context("direct_tool_call_transport_SO_PEERSEC_not_utf8")?;
    if context.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("direct_tool_call_transport_SO_PEERSEC_malformed");
    }
    Ok(context.to_string())
}

fn process_security_context(pid: u32) -> Result<String> {
    let bytes = read_proc_file(pid, "attr/current", MAX_SECURITY_CONTEXT_BYTES)?;
    let context = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    if context.is_empty() || context.contains(&0) {
        bail!("direct_tool_call_transport_peer_current_security_context_malformed");
    }
    let context = std::str::from_utf8(context)
        .context("direct_tool_call_transport_peer_current_security_context_not_utf8")?;
    if context.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("direct_tool_call_transport_peer_current_security_context_malformed");
    }
    Ok(context.to_string())
}

fn open_pidfd(pid: u32) -> Result<File> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_transport_pidfd_open_failed");
    }
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn require_live_pidfd(pidfd: &File) -> Result<()> {
    let mut descriptor = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if result != 0 || descriptor.revents != 0 {
        bail!("direct_tool_call_transport_peer_pidfd_not_live");
    }
    Ok(())
}

fn read_proc_file(pid: u32, name: &str, maximum: usize) -> Result<Vec<u8>> {
    if !matches!(name, "stat" | "cgroup" | "attr/current") {
        bail!("direct_tool_call_transport_proc_name_denied");
    }
    let path = format!("/proc/{pid}/{name}");
    let path = std::ffi::CString::new(path)?;
    read_fixed_proc_file(&path, maximum)
}

fn read_fixed_proc_file(path: &std::ffi::CStr, maximum: usize) -> Result<Vec<u8>> {
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_transport_proc_open_failed");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut filesystem = MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0
        || unsafe { filesystem.assume_init() }.f_type != PROC_SUPER_MAGIC
    {
        bail!("direct_tool_call_transport_proc_filesystem_denied");
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum || bytes.contains(&0) {
        bail!("direct_tool_call_transport_proc_frame_denied");
    }
    Ok(bytes)
}

fn hash_process_executable(pid: u32) -> Result<String> {
    let path = format!("/proc/{pid}/exe");
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.mode() & 0o7777 != 0o755
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_ADAPTER_EXECUTABLE_BYTES
    {
        bail!("direct_tool_call_transport_peer_executable_denied");
    }
    let mut hasher = Sha256::new();
    let copied = std::io::copy(
        &mut Read::by_ref(&mut file).take(MAX_ADAPTER_EXECUTABLE_BYTES + 1),
        &mut hasher_writer(&mut hasher),
    )?;
    let after = file.metadata()?;
    if copied != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("direct_tool_call_transport_peer_executable_changed");
    }
    Ok(lower_hex(&hasher.finalize()))
}

struct HashWriter<'a>(&'a mut Sha256);

impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn hasher_writer(hasher: &mut Sha256) -> HashWriter<'_> {
    HashWriter(hasher)
}

fn identity_digest(
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    custody: &DirectOperationKernelLaunchCustodyV3,
    observed: &ObservedProcess,
    pidfd_device: u64,
    pidfd_inode: u64,
) -> String {
    let mut hasher = Sha256::new();
    for bytes in [
        b"trillionnium.direct-operation-tool-call-transport-peer.v3".as_slice(),
        binding_sha256.as_bytes(),
        adapter.adapter_id().as_bytes(),
        custody.launch_custody_sha256.as_bytes(),
        &custody.adapter_pid.to_be_bytes(),
        observed.boot_id_sha256.as_bytes(),
        observed.executable_sha256.as_bytes(),
        observed.unified_cgroup_path.as_bytes(),
        observed.selinux_context.as_bytes(),
        &observed.start_time_ticks.to_be_bytes(),
        &pidfd_device.to_be_bytes(),
        &pidfd_inode.to_be_bytes(),
    ] {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    lower_hex(&hasher.finalize())
}

#[cfg(feature = "p0-launch-package-device-conformance")]
#[allow(clippy::too_many_arguments)]
fn p0_userdebug_identity_digest(
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    peer_pid: u32,
    expected_executable_sha256: &str,
    observed: &ObservedProcess,
    pidfd_device: u64,
    pidfd_inode: u64,
) -> String {
    let mut hasher = Sha256::new();
    for bytes in [
        b"trillionnium.direct-operation-tool-call-p0-userdebug-peer.v1".as_slice(),
        binding_sha256.as_bytes(),
        adapter.adapter_id().as_bytes(),
        &peer_pid.to_be_bytes(),
        expected_executable_sha256.as_bytes(),
        observed.boot_id_sha256.as_bytes(),
        observed.executable_sha256.as_bytes(),
        observed.unified_cgroup_path.as_bytes(),
        observed.selinux_context.as_bytes(),
        &observed.start_time_ticks.to_be_bytes(),
        &pidfd_device.to_be_bytes(),
        &pidfd_inode.to_be_bytes(),
    ] {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    lower_hex(&hasher.finalize())
}

fn write_canonical_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() || payload.len() > contract::MAXIMUM_FRAME_BYTES {
        bail!("direct_tool_call_transport_output_frame_denied");
    }
    let length =
        u32::try_from(payload.len()).context("direct_tool_call_transport_output_length_denied")?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

fn read_canonical_frame<T: DeserializeOwned + Serialize>(stream: &mut UnixStream) -> Result<T> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .context("direct_tool_call_transport_input_prefix_denied")?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > contract::MAXIMUM_FRAME_BYTES {
        bail!("direct_tool_call_transport_input_length_denied");
    }
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .context("direct_tool_call_transport_input_payload_denied")?;
    let value: T =
        serde_json::from_slice(&payload).context("direct_tool_call_transport_input_json_denied")?;
    if serde_json::to_vec(&value)? != payload {
        bail!("direct_tool_call_transport_input_not_canonical");
    }
    Ok(value)
}

fn require_peer_write_eof(stream: &mut UnixStream) -> Result<()> {
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing)? != 0 {
        bail!("direct_tool_call_transport_trailing_frame_denied");
    }
    Ok(())
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value != "0000000000000000000000000000000000000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
mod tests {
    use super::*;
    use std::fs;
    use std::net::Shutdown;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::SocketAddr;
    use std::sync::Mutex;
    use std::thread;

    use tempfile::TempDir;
    #[cfg(feature = "p0-launch-package-device-conformance")]
    use trillionnium_os_types::direct_operation::{
        ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA, DirectOperationAdapterTerminalDispositionV1,
        DirectOperationAdapterTerminalStateV1, DirectOperationJournalEvidenceSnapshotV1,
        DirectOperationOuterEvidence, DirectOperationOuterOutcome,
        JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA,
    };
    use trillionnium_os_types::direct_operation::{
        BINDING_SCHEMA, DirectOperationProviderAttempt, DirectOperationStableSeed,
        KERNEL_LAUNCH_CUSTODY_KIND_V3, KERNEL_LAUNCH_CUSTODY_PRODUCER_V3,
        KERNEL_LAUNCH_CUSTODY_V3_SCHEMA, STABLE_SEED_SCHEMA, adapter_binary_kind,
        fixed_adapter_cgroup_path,
    };

    use crate::direct_tool_call_high_water::{
        DirectToolCallHighWaterHeadV1, DirectToolCallHighWaterRouteV1,
        TestDirectToolCallHighWaterAuthority,
    };

    static LISTENER_TEST_LOCK: Mutex<()> = Mutex::new(());
    const HOST_FIXTURE_PIDFD_DEVICE: u64 = 79;
    const HOST_FIXTURE_PIDFD_INODE: u64 = 83;
    const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn digest(label: &str) -> String {
        trillionnium_os_types::sha256_bytes(label.as_bytes())
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_provider_termination_before_tool_explicitly_wakes_listener() {
        let (wait_socket, _never_connected_peer) = UnixStream::pair().unwrap();
        let cancellation = P0UserdebugDirectToolCallCancellation::new().unwrap();
        let listener_cancellation = cancellation.clone();
        let started = Instant::now();
        let listener = thread::spawn(move || {
            poll_readable_or_cancel(
                wait_socket.as_raw_fd(),
                &listener_cancellation,
                Instant::now() + Duration::from_secs(5),
            )
        });

        cancellation.cancel().unwrap();
        cancellation.cancel().unwrap();
        assert_eq!(
            listener.join().unwrap().unwrap(),
            P0UserdebugPollOutcome::Cancelled
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_listener_cancellation_wins_simultaneous_readiness_race() {
        let (wait_socket, mut connecting_peer) = UnixStream::pair().unwrap();
        let cancellation = P0UserdebugDirectToolCallCancellation::new().unwrap();
        connecting_peer.write_all(b"tool-ready").unwrap();
        cancellation.cancel().unwrap();

        assert_eq!(
            poll_readable_or_cancel(
                wait_socket.as_raw_fd(),
                &cancellation,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap(),
            P0UserdebugPollOutcome::Cancelled
        );
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_listener_invocation_deadline_is_bounded_without_tool_or_cancel() {
        let (wait_socket, _never_connected_peer) = UnixStream::pair().unwrap();
        let cancellation = P0UserdebugDirectToolCallCancellation::new().unwrap();
        let started = Instant::now();
        let error = poll_readable_or_cancel(
            wait_socket.as_raw_fd(),
            &cancellation,
            Instant::now() + Duration::from_millis(25),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("direct_tool_call_listener_p0_invocation_deadline_exceeded")
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    fn binding() -> DirectOperationBinding {
        let seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            task_id: "task.transport-session".to_string(),
            provider_invocation_id_sha256: digest("provider-invocation"),
            provider_session_id_sha256: digest("provider-session"),
            subject_uid: 10_100,
            subject_selinux_domain_sha256: digest("subject-domain"),
        };
        DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            invocation_id: seed.invocation_id().unwrap(),
            stable_seed: seed,
            workflow_id_sha256: digest("workflow"),
            agent_identity_key_sha256: digest("identity"),
            agent_executable_sha256: digest("agent-executable"),
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(
                digest("lifecycle"),
                1,
                digest("attempt"),
            )
            .unwrap(),
        }
    }

    fn future_dual_binding() -> DirectOperationBinding {
        let mut binding = binding();
        binding.authorized_adapter_set = trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::future_system_api_and_accessibility();
        binding
    }

    fn custody(
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> DirectOperationKernelLaunchCustodyV3 {
        let mut custody = DirectOperationKernelLaunchCustodyV3 {
            schema: KERNEL_LAUNCH_CUSTODY_V3_SCHEMA.to_string(),
            kernel_custody_kind: KERNEL_LAUNCH_CUSTODY_KIND_V3.to_string(),
            custody_producer: KERNEL_LAUNCH_CUSTODY_PRODUCER_V3.to_string(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter,
            adapter_binary_kind: adapter_binary_kind(adapter).to_string(),
            binding_sha256: binding_sha256.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_subtree_generation: 41,
            provider_subtree_reservation_evidence_sha256: digest("reservation"),
            boot_id_sha256: digest("boot"),
            adapter_pid: 42,
            adapter_start_time_ticks: 88,
            adapter_executable_sha256: digest("adapter"),
            unified_cgroup_path: fixed_adapter_cgroup_path(
                &binding.stable_seed.provider_id,
                adapter,
            )
            .unwrap(),
            adapter_leaf_empty_proof_sha256: digest("empty"),
            measured_exec_proof_sha256: digest("exec"),
            launch_custody_sha256: String::new(),
        };
        custody.launch_custody_sha256 = custody.digest_sha256().unwrap();
        custody
    }

    fn observed_identity_fixture() -> (
        DirectOperationBinding,
        String,
        DirectOperationAdapter,
        DirectOperationKernelLaunchCustodyV3,
        ObservedProcess,
        String,
    ) {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let adapter = DirectOperationAdapter::SystemApi;
        let custody = custody(&binding, &binding_sha256, adapter);
        let observed = ObservedProcess::from_host_fixture(&custody, adapter);
        let identity_sha256 = identity_digest(
            &binding_sha256,
            adapter,
            &custody,
            &observed,
            HOST_FIXTURE_PIDFD_DEVICE,
            HOST_FIXTURE_PIDFD_INODE,
        );
        (
            binding,
            binding_sha256,
            adapter,
            custody,
            observed,
            identity_sha256,
        )
    }

    #[test]
    fn stable_observation_recomputes_same_transport_identity() {
        let (_binding, binding_sha256, adapter, custody, observed, identity_sha256) =
            observed_identity_fixture();
        validate_observed_peer_identity(
            &binding_sha256,
            adapter,
            &custody,
            &observed,
            HOST_FIXTURE_PIDFD_DEVICE,
            HOST_FIXTURE_PIDFD_INODE,
            &identity_sha256,
        )
        .unwrap();
    }

    #[test]
    fn executable_hash_drift_fails_closed() {
        let (_binding, binding_sha256, adapter, custody, mut observed, identity_sha256) =
            observed_identity_fixture();
        observed.executable_sha256 = digest("drifted-adapter-executable");
        assert!(
            validate_observed_peer_identity(
                &binding_sha256,
                adapter,
                &custody,
                &observed,
                HOST_FIXTURE_PIDFD_DEVICE,
                HOST_FIXTURE_PIDFD_INODE,
                &identity_sha256,
            )
            .unwrap_err()
            .to_string()
            .contains("peer_launch_custody_denied")
        );
    }

    #[test]
    fn unified_cgroup_drift_fails_closed() {
        let (_binding, binding_sha256, adapter, custody, mut observed, identity_sha256) =
            observed_identity_fixture();
        observed.unified_cgroup_path = "/trillionnium/direct/drifted".to_string();
        assert!(
            validate_observed_peer_identity(
                &binding_sha256,
                adapter,
                &custody,
                &observed,
                HOST_FIXTURE_PIDFD_DEVICE,
                HOST_FIXTURE_PIDFD_INODE,
                &identity_sha256,
            )
            .unwrap_err()
            .to_string()
            .contains("peer_launch_custody_denied")
        );
    }

    #[test]
    fn process_start_time_drift_fails_closed() {
        let (_binding, binding_sha256, adapter, custody, mut observed, identity_sha256) =
            observed_identity_fixture();
        observed.start_time_ticks = observed.start_time_ticks.checked_add(1).unwrap();
        assert!(
            validate_observed_peer_identity(
                &binding_sha256,
                adapter,
                &custody,
                &observed,
                HOST_FIXTURE_PIDFD_DEVICE,
                HOST_FIXTURE_PIDFD_INODE,
                &identity_sha256,
            )
            .unwrap_err()
            .to_string()
            .contains("peer_launch_custody_denied")
        );
    }

    #[test]
    fn current_security_context_and_cached_identity_drift_fail_closed() {
        let (_binding, binding_sha256, adapter, custody, observed, identity_sha256) =
            observed_identity_fixture();
        let mut security_drift = observed.clone();
        security_drift.selinux_context = "u:r:untrusted_app:s0".to_string();
        assert!(
            validate_observed_peer_identity(
                &binding_sha256,
                adapter,
                &custody,
                &security_drift,
                HOST_FIXTURE_PIDFD_DEVICE,
                HOST_FIXTURE_PIDFD_INODE,
                &identity_sha256,
            )
            .unwrap_err()
            .to_string()
            .contains("peer_current_security_context_denied")
        );
        assert!(
            validate_observed_peer_identity(
                &binding_sha256,
                adapter,
                &custody,
                &observed,
                HOST_FIXTURE_PIDFD_DEVICE,
                HOST_FIXTURE_PIDFD_INODE,
                &digest("drifted-cached-transport-identity"),
            )
            .unwrap_err()
            .to_string()
            .contains("peer_identity_drift_denied")
        );
    }

    fn allocator_fixture(
        binding: &DirectOperationBinding,
        adapter: DirectOperationAdapter,
    ) -> (TempDir, std::path::PathBuf, DirectToolCallAllocator) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("allocator.json");
        let allocator = DirectToolCallAllocator::open_for_test(
            &path,
            unsafe { libc::geteuid() },
            binding.clone(),
            adapter,
        )
        .unwrap();
        (directory, path, allocator)
    }

    fn client_until_envelope(
        stream: &mut UnixStream,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
        canonical: &str,
    ) -> (
        DirectOperationToolCallDeliveryV3,
        DirectOperationToolCallEnvelopeV3,
    ) {
        let hello = DirectOperationToolCallSessionHelloV3::derive(
            binding,
            binding_sha256,
            adapter,
            custody,
        )
        .unwrap();
        write_canonical_frame(stream, &hello).unwrap();
        let delivery: DirectOperationToolCallDeliveryV3 = read_canonical_frame(stream).unwrap();
        let request = DirectOperationToolCallAllocationRequestV3::derive(
            &delivery,
            binding,
            binding_sha256,
            adapter,
            canonical.to_string(),
        )
        .unwrap();
        write_canonical_frame(stream, &request).unwrap();
        let envelope: DirectOperationToolCallEnvelopeV3 = read_canonical_frame(stream).unwrap();
        (delivery, envelope)
    }

    #[test]
    fn disconnect_after_envelope_replays_same_delivery_then_commits_prepared_ack() {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let adapter = DirectOperationAdapter::SystemApi;
        let custody = custody(&binding, &binding_sha256, adapter);
        let (_directory, path, mut allocator) = allocator_fixture(&binding, adapter);
        let issued = allocator.issue_for_test(61).unwrap();

        let (server, mut client) = UnixStream::pair().unwrap();
        let peer = VerifiedAdapterTransportPeer::for_host_fixture_test(
            &binding,
            &binding_sha256,
            adapter,
            &custody,
        )
        .unwrap();
        let server_binding = binding.clone();
        let server_binding_sha256 = binding_sha256.clone();
        let server_custody = custody.clone();
        let first_server = thread::spawn(move || {
            let result = serve_authenticated_session(
                server,
                &peer,
                &server_binding,
                &server_binding_sha256,
                adapter,
                &server_custody,
                &mut allocator,
            );
            (allocator, result)
        });
        let canonical = digest("canonical-request");
        let (first_delivery, first_envelope) = client_until_envelope(
            &mut client,
            &binding,
            &binding_sha256,
            adapter,
            &custody,
            &canonical,
        );
        assert_eq!(first_delivery, issued);
        drop(client);
        let (allocator, result) = first_server.join().unwrap();
        assert!(result.is_err());
        drop(allocator);

        let mut reopened = DirectToolCallAllocator::open_for_test(
            &path,
            unsafe { libc::geteuid() },
            binding.clone(),
            adapter,
        )
        .unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        let peer = VerifiedAdapterTransportPeer::for_host_fixture_test(
            &binding,
            &binding_sha256,
            adapter,
            &custody,
        )
        .unwrap();
        let server_binding = binding.clone();
        let server_binding_sha256 = binding_sha256.clone();
        let server_custody = custody.clone();
        let second_server = thread::spawn(move || {
            let result = serve_authenticated_session(
                server,
                &peer,
                &server_binding,
                &server_binding_sha256,
                adapter,
                &server_custody,
                &mut reopened,
            );
            (reopened, result)
        });
        let (replayed_delivery, replayed_envelope) = client_until_envelope(
            &mut client,
            &binding,
            &binding_sha256,
            adapter,
            &custody,
            &canonical,
        );
        assert_eq!(replayed_delivery, first_delivery);
        assert_eq!(replayed_envelope, first_envelope);
        let acknowledgement = DirectOperationToolCallPreparedAckV3::derive(
            &replayed_envelope,
            "08".repeat(16),
            1,
            digest("backend-request"),
            digest("journal-payload"),
            digest("external-runtime-authority"),
        )
        .unwrap();
        write_canonical_frame(&mut client, &acknowledgement).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let receipt: DirectOperationToolCallCommitReceiptV3 =
            read_canonical_frame(&mut client).unwrap();
        receipt
            .validate_for_acknowledgement(&acknowledgement)
            .unwrap();
        let (mut allocator, result) = second_server.join().unwrap();
        assert_eq!(result.unwrap(), receipt);
        let next = allocator.issue_for_test(62).unwrap();
        assert_eq!(next.adapter_effect_ordinal, 1);
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_userdebug_session_consumes_custody_delivery_and_commits_prepared_ack() {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let adapter = DirectOperationAdapter::SystemApi;
        let expected_executable_sha256 = digest("p0-system-api-executable");
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("p0-allocator.json");
        let logical_delivery =
            VerifiedDaemonLogicalDelivery::for_p0_userdebug_test(binding_sha256.clone(), adapter);
        let verified_allocator = DirectToolCallAllocator::open_p0_userdebug_for_test(
            &path,
            unsafe { libc::geteuid() },
            binding.clone(),
            adapter,
            logical_delivery,
            [71; 32],
        )
        .unwrap();
        verified_allocator.validate().unwrap();
        let (mut allocator, server_binding, server_adapter) = verified_allocator.into_parts();
        assert_eq!(server_binding, binding);
        assert_eq!(server_adapter, adapter);

        let peer = VerifiedP0UserdebugAdapterTransportPeer::for_host_fixture_test(
            &binding,
            &binding_sha256,
            adapter,
            &expected_executable_sha256,
        )
        .unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        let server_binding_sha256 = binding_sha256.clone();
        let server_thread = thread::spawn(move || {
            let mut attached = false;
            serve_p0_userdebug_authenticated_session(
                server,
                &peer,
                &server_binding,
                &server_binding_sha256,
                server_adapter,
                &mut allocator,
                &mut |_| {
                    attached = true;
                    Ok(())
                },
            )
            .map(|(receipt, terminal_evidence)| (receipt, terminal_evidence, attached))
        });

        let hello = P0UserdebugDirectOperationToolCallSessionHelloV1::derive(
            &binding,
            &binding_sha256,
            adapter,
        )
        .unwrap();
        write_canonical_frame(&mut client, &hello).unwrap();
        let delivery: DirectOperationToolCallDeliveryV3 =
            read_canonical_frame(&mut client).unwrap();
        let request = DirectOperationToolCallAllocationRequestV3::derive(
            &delivery,
            &binding,
            &binding_sha256,
            adapter,
            digest("p0-canonical-request"),
        )
        .unwrap();
        write_canonical_frame(&mut client, &request).unwrap();
        let envelope: DirectOperationToolCallEnvelopeV3 =
            read_canonical_frame(&mut client).unwrap();
        let acknowledgement = DirectOperationToolCallPreparedAckV3::derive(
            &envelope,
            "09".repeat(16),
            1,
            digest("p0-backend-request"),
            digest("p0-journal-payload"),
            digest("p0-runtime-authority"),
        )
        .unwrap();
        write_canonical_frame(&mut client, &acknowledgement).unwrap();
        let receipt: DirectOperationToolCallCommitReceiptV3 =
            read_canonical_frame(&mut client).unwrap();
        receipt
            .validate_for_acknowledgement(&acknowledgement)
            .unwrap();
        let evidence = DirectOperationOuterEvidence {
            allocating_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            adapter_effect_ordinal: envelope.adapter_effect_ordinal,
            journal_sequence: acknowledgement.journal_sequence,
            tool: adapter.tool_name().to_string(),
            canonical_request_sha256: acknowledgement.canonical_request_sha256.clone(),
            backend_request_id_sha256: acknowledgement.backend_request_id_sha256.clone(),
            backend_result_sha256: digest("p0-backend-result"),
            outcome: DirectOperationOuterOutcome::Success,
            backend_error_code: None,
        };
        let mut snapshot = DirectOperationJournalEvidenceSnapshotV1 {
            schema: JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA.to_string(),
            allocation_binding_sha256: binding_sha256.clone(),
            invocation_id: binding.invocation_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            allocating_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            adapter,
            journal_epoch: acknowledgement.journal_epoch.clone(),
            journal_payload_sha256: acknowledgement.journal_payload_sha256.clone(),
            previous_ack_watermark: 0,
            previous_ack_chain_sha256: ZERO_SHA256.to_string(),
            journal_allocation_count: 1,
            journal_evidence_count: 1,
            first_journal_sequence: acknowledgement.journal_sequence,
            last_journal_sequence: acknowledgement.journal_sequence,
            evidence: vec![evidence],
            evidence_sha256: String::new(),
        };
        snapshot.evidence_sha256 = snapshot.evidence_digest_sha256().unwrap();
        let disposition = DirectOperationAdapterTerminalDispositionV1 {
            schema: ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA.to_string(),
            binding_sha256: binding_sha256.clone(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter,
            terminal_state: DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot: snapshot,
            },
        };
        write_canonical_frame(&mut client, &disposition).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let terminal_commit: P0UserdebugAdapterTerminalCommitV1 =
            read_canonical_frame(&mut client).unwrap();
        terminal_commit
            .validate_for(&receipt, &disposition)
            .unwrap();
        let (server_receipt, server_terminal_evidence, attached) =
            server_thread.join().unwrap().unwrap();
        assert_eq!(server_receipt, receipt);
        assert_eq!(
            server_terminal_evidence.backend_result_sha256,
            digest("p0-backend-result")
        );
        assert!(attached);
    }

    #[test]
    fn lost_commit_receipt_replays_exactly_after_daemon_restart() {
        let binding = future_dual_binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let adapter = DirectOperationAdapter::Accessibility;
        let custody = custody(&binding, &binding_sha256, adapter);
        let (_directory, path, mut allocator) = allocator_fixture(&binding, adapter);
        allocator.issue_for_test(71).unwrap();
        let canonical = digest("lost-receipt-canonical-request");

        let (server, mut client) = UnixStream::pair().unwrap();
        let peer = VerifiedAdapterTransportPeer::for_host_fixture_test(
            &binding,
            &binding_sha256,
            adapter,
            &custody,
        )
        .unwrap();
        let server_binding = binding.clone();
        let server_binding_sha256 = binding_sha256.clone();
        let server_custody = custody.clone();
        let first_server = thread::spawn(move || {
            let result = serve_authenticated_session(
                server,
                &peer,
                &server_binding,
                &server_binding_sha256,
                adapter,
                &server_custody,
                &mut allocator,
            );
            (allocator, result)
        });
        let (delivery, envelope) = client_until_envelope(
            &mut client,
            &binding,
            &binding_sha256,
            adapter,
            &custody,
            &canonical,
        );
        let acknowledgement = DirectOperationToolCallPreparedAckV3::derive(
            &envelope,
            "09".repeat(16),
            1,
            digest("lost-receipt-backend-request"),
            digest("lost-receipt-journal-payload"),
            digest("lost-receipt-operation-epoch-authority"),
        )
        .unwrap();
        write_canonical_frame(&mut client, &acknowledgement).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let (allocator, first_result) = first_server.join().unwrap();
        let first_receipt = first_result.unwrap();
        drop(client);
        drop(allocator);

        let mut reopened = DirectToolCallAllocator::open_for_test(
            &path,
            unsafe { libc::geteuid() },
            binding.clone(),
            adapter,
        )
        .unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        let peer = VerifiedAdapterTransportPeer::for_host_fixture_test(
            &binding,
            &binding_sha256,
            adapter,
            &custody,
        )
        .unwrap();
        let server_binding = binding.clone();
        let server_binding_sha256 = binding_sha256.clone();
        let server_custody = custody.clone();
        let second_server = thread::spawn(move || {
            let result = serve_authenticated_session(
                server,
                &peer,
                &server_binding,
                &server_binding_sha256,
                adapter,
                &server_custody,
                &mut reopened,
            );
            (reopened, result)
        });
        let (replayed_delivery, replayed_envelope) = client_until_envelope(
            &mut client,
            &binding,
            &binding_sha256,
            adapter,
            &custody,
            &canonical,
        );
        assert_eq!(replayed_delivery, delivery);
        assert_eq!(replayed_envelope, envelope);
        write_canonical_frame(&mut client, &acknowledgement).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let replayed_receipt: DirectOperationToolCallCommitReceiptV3 =
            read_canonical_frame(&mut client).unwrap();
        let (_allocator, second_result) = second_server.join().unwrap();
        assert_eq!(replayed_receipt, first_receipt);
        assert_eq!(second_result.unwrap(), first_receipt);
    }

    #[test]
    fn trailing_frame_is_rejected_before_prepared_ack_commit() {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let adapter = DirectOperationAdapter::SystemApi;
        let custody = custody(&binding, &binding_sha256, adapter);
        let (_directory, _path, mut allocator) = allocator_fixture(&binding, adapter);
        let issued = allocator.issue_for_test(81).unwrap();
        let canonical = digest("trailing-frame-canonical-request");
        let (server, mut client) = UnixStream::pair().unwrap();
        let peer = VerifiedAdapterTransportPeer::for_host_fixture_test(
            &binding,
            &binding_sha256,
            adapter,
            &custody,
        )
        .unwrap();
        let server_binding = binding.clone();
        let server_binding_sha256 = binding_sha256.clone();
        let server_custody = custody.clone();
        let server = thread::spawn(move || {
            let result = serve_authenticated_session(
                server,
                &peer,
                &server_binding,
                &server_binding_sha256,
                adapter,
                &server_custody,
                &mut allocator,
            );
            (allocator, result)
        });
        let (_delivery, envelope) = client_until_envelope(
            &mut client,
            &binding,
            &binding_sha256,
            adapter,
            &custody,
            &canonical,
        );
        let acknowledgement = DirectOperationToolCallPreparedAckV3::derive(
            &envelope,
            "0a".repeat(16),
            1,
            digest("trailing-frame-backend-request"),
            digest("trailing-frame-journal-payload"),
            digest("trailing-frame-operation-epoch-authority"),
        )
        .unwrap();
        write_canonical_frame(&mut client, &acknowledgement).unwrap();
        client.write_all(b"x").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let (mut allocator, result) = server.join().unwrap();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("trailing_frame_denied")
        );
        assert_eq!(
            allocator.recover_pending_verified_delivery().unwrap(),
            issued
        );
        assert_eq!(allocator.issue_for_test(82).unwrap(), issued);
    }

    #[test]
    fn no_preissued_delivery_fails_closed() {
        let binding = future_dual_binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let adapter = DirectOperationAdapter::Accessibility;
        let custody = custody(&binding, &binding_sha256, adapter);
        let (_directory, _path, mut allocator) = allocator_fixture(&binding, adapter);
        let (server, mut client) = UnixStream::pair().unwrap();
        let peer = VerifiedAdapterTransportPeer::for_host_fixture_test(
            &binding,
            &binding_sha256,
            adapter,
            &custody,
        )
        .unwrap();
        let hello = DirectOperationToolCallSessionHelloV3::derive(
            &binding,
            &binding_sha256,
            adapter,
            &custody,
        )
        .unwrap();
        write_canonical_frame(&mut client, &hello).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert!(
            serve_authenticated_session(
                server,
                &peer,
                &binding,
                &binding_sha256,
                adapter,
                &custody,
                &mut allocator,
            )
            .unwrap_err()
            .to_string()
            .contains("no_preissued_delivery_hold")
        );
    }

    #[test]
    fn fixed_listener_authenticates_before_allocator_state_is_observed() {
        let _guard = LISTENER_TEST_LOCK.lock().unwrap();
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let adapter = DirectOperationAdapter::SystemApi;
        let mut custody = custody(&binding, &binding_sha256, adapter);
        custody.adapter_pid = std::process::id().checked_add(1).unwrap_or(1);
        custody.launch_custody_sha256.clear();
        custody.launch_custody_sha256 = custody.digest_sha256().unwrap();
        let (_directory, _path, mut allocator) = allocator_fixture(&binding, adapter);
        let listener = FixedDirectToolCallListener::bind_source_disabled().unwrap();
        let client = thread::spawn(|| {
            let address = SocketAddr::from_abstract_name(contract::SOCKET_NAME.as_bytes()).unwrap();
            UnixStream::connect_addr(&address).unwrap()
        });

        let error = listener
            .serve_source_disabled_once(
                &binding,
                &binding_sha256,
                adapter,
                &custody,
                &mut allocator,
            )
            .unwrap_err();
        drop(client.join().unwrap());
        assert!(error.to_string().contains("peer_kernel_identity_denied"));
        assert!(
            allocator
                .recover_pending_verified_delivery()
                .unwrap_err()
                .to_string()
                .contains("no_preissued_delivery_hold")
        );
        assert!(FixedDirectToolCallListener::bind_source_disabled().is_ok());
    }

    #[test]
    fn bind_product_consumes_verified_allocator_and_provider_delivery_capabilities() {
        let _guard = LISTENER_TEST_LOCK.lock().unwrap();
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let adapter = DirectOperationAdapter::SystemApi;
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("allocator.json");
        let route = DirectToolCallHighWaterRouteV1::derive(
            binding_sha256.clone(),
            binding.stable_seed.provider_id.clone(),
            binding.stable_seed.agent_id.clone(),
            adapter,
        )
        .unwrap();
        let authority = TestDirectToolCallHighWaterAuthority::new(
            route,
            DirectToolCallHighWaterHeadV1::new(
                0,
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            )
            .unwrap(),
        );
        let admission = DirectToolCallAllocator::verify_high_water_for_test(
            &path,
            unsafe { libc::geteuid() },
            binding,
            adapter,
            &authority,
        )
        .unwrap();
        let allocator = DirectToolCallAllocator::open_verified_for_test(admission).unwrap();
        let wrong_allocator_capability = allocator.verified_product_listener().unwrap();
        let wrong_provider_delivery =
            VerifiedDaemonLogicalDelivery::for_test(digest("wrong-binding"), adapter);
        assert!(
            FixedDirectToolCallListener::bind_product(
                wrong_allocator_capability,
                wrong_provider_delivery,
            )
            .err()
            .unwrap()
            .to_string()
            .contains("provider_delivery_capability_drift_denied")
        );
        let allocator_capability = allocator.verified_product_listener().unwrap();
        let provider_delivery = VerifiedDaemonLogicalDelivery::for_test(binding_sha256, adapter);
        let bound =
            FixedDirectToolCallListener::bind_product(allocator_capability, provider_delivery)
                .unwrap();
        bound.validate_pre_effect_admission().unwrap();
        drop(bound);
        assert!(FixedDirectToolCallListener::bind_source_disabled().is_ok());
    }

    #[test]
    fn source_listener_contract_remains_absent_from_product_dispatch() {
        assert_eq!(
            SOURCE_STATUS,
            "source_only_fixed_single_session_listener_no_main_dispatch_no_product_wiring_v1"
        );
        assert_eq!(ACCEPT_TIMEOUT, Duration::from_secs(5));
        const {
            assert!(contract::SOURCE_LISTENER_IMPLEMENTED);
            assert!(contract::SOURCE_SESSION_HANDLER_IMPLEMENTED);
            assert!(!contract::DAEMON_LISTENER_PRODUCT_WIRED);
            assert!(!contract::ADAPTER_CONNECTOR_PRODUCT_WIRED);
            assert!(!contract::PROVIDER_DELIVERY_PRODUCT_WIRED);
            assert!(!contract::FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE);
            assert!(!contract::ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE);
            assert!(!contract::CONFERS_EFFECT_AUTHORITY);
        }
        let daemon_main = include_str!("main.rs");
        assert!(!daemon_main.contains("FixedDirectToolCallListener"));
        assert!(!daemon_main.contains("serve_source_disabled_once("));
        assert!(!daemon_main.contains("bind_product("));
    }
}
