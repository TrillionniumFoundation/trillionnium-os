use std::io::{Read as _, Write as _};
use std::mem::{self, MaybeUninit};
use std::net::Shutdown;
#[cfg(target_os = "android")]
use std::os::android::net::SocketAddrExt as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt as _;
#[cfg(test)]
use std::os::unix::net::SocketAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

use trillionnium_os_types::capability_lease_root_route_session as session_contract;
use trillionnium_os_types::capability_lease_root_route_socket_custody as custody;
use trillionnium_os_types::capability_lease_root_route_transport as transport;

use super::root_publisher_route_transport::{
    self, KernelPeer, RootPublicationResolver, RootPublisherRouteExecutor, RootRouteConnection,
    RootRouteTransportError,
};

pub(crate) const SOURCE_STATUS: &str =
    "source_only_concrete_private_route_listener_no_main_dispatch_no_product_wiring_v1";

const ACCEPT_TIMEOUT: Duration = Duration::from_millis(5_000);
const IO_TIMEOUT: Duration = Duration::from_millis(5_000);
const MAXIMUM_PEER_SECURITY_CONTEXT_BYTES: usize = 256;

pub(crate) struct FixedRootRouteListener {
    listener: UnixListener,
}

impl FixedRootRouteListener {
    pub(crate) fn bind_source_disabled() -> Result<Self, RootRouteTransportError> {
        let listener = bind_one_backlog_listener()?;
        let bound = Self { listener };
        bound.validate()?;
        Ok(bound)
    }

    pub(crate) fn accept_source_disabled_once(
        self,
    ) -> Result<FixedRootRouteConnection, RootRouteTransportError> {
        self.validate()?;
        poll_until(
            self.listener.as_raw_fd(),
            libc::POLLIN,
            libc::POLLIN,
            Instant::now() + ACCEPT_TIMEOUT,
        )?;
        self.validate()?;
        let (stream, peer_address) = self
            .listener
            .accept()
            .map_err(|_| RootRouteTransportError::TransportDenied)?;
        if !peer_address.is_unnamed() {
            return Err(RootRouteTransportError::PeerDenied);
        }
        stream
            .set_nonblocking(true)
            .map_err(|_| RootRouteTransportError::TransportDenied)?;
        require_cloexec(stream.as_raw_fd())?;
        if fcntl(stream.as_raw_fd(), libc::F_GETFL)? & libc::O_NONBLOCK == 0 {
            return Err(RootRouteTransportError::TransportDenied);
        }
        Ok(FixedRootRouteConnection { stream })
    }

    fn validate(&self) -> Result<(), RootRouteTransportError> {
        require_cloexec(self.listener.as_raw_fd())?;
        let flags = fcntl(self.listener.as_raw_fd(), libc::F_GETFL)?;
        if flags & libc::O_NONBLOCK == 0 {
            return Err(RootRouteTransportError::TransportDenied);
        }
        if socket_option(self.listener.as_raw_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM
            || socket_option(self.listener.as_raw_fd(), libc::SO_ACCEPTCONN)? != 1
        {
            return Err(RootRouteTransportError::TransportDenied);
        }
        let address = self
            .listener
            .local_addr()
            .map_err(|_| RootRouteTransportError::TransportDenied)?;
        if address.as_abstract_name() != Some(transport::SOCKET_NAME.as_bytes()) {
            return Err(RootRouteTransportError::TransportDenied);
        }
        Ok(())
    }
}

fn bind_one_backlog_listener() -> Result<UnixListener, RootRouteTransportError> {
    let descriptor = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        return Err(RootRouteTransportError::TransportDenied);
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let mut address = unsafe { mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let name = transport::SOCKET_NAME.as_bytes();
    if name.is_empty() || name.len() + 1 > address.sun_path.len() {
        return Err(RootRouteTransportError::TransportDenied);
    }
    address.sun_path[0] = 0;
    for (destination, source) in address.sun_path[1..].iter_mut().zip(name) {
        *destination = *source as libc::c_char;
    }
    let length = (mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len())
        .try_into()
        .map_err(|_| RootRouteTransportError::TransportDenied)?;
    let result = unsafe {
        libc::bind(
            descriptor.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    };
    if result != 0 || unsafe { libc::listen(descriptor.as_raw_fd(), 1) } != 0 {
        return Err(RootRouteTransportError::TransportDenied);
    }
    Ok(UnixListener::from(descriptor))
}

pub(crate) struct FixedRootRouteConnection {
    stream: UnixStream,
}

impl RootRouteConnection for FixedRootRouteConnection {
    fn kernel_peer(&mut self) -> Result<KernelPeer, RootRouteTransportError> {
        let credentials = peer_credentials(self.stream.as_raw_fd())?;
        if credentials.pid <= 1 {
            return Err(RootRouteTransportError::PeerDenied);
        }
        Ok(KernelPeer {
            pid: credentials.pid as u32,
            uid: credentials.uid,
            gid: credentials.gid,
            selinux_domain: peer_security_context(self.stream.as_raw_fd())?,
        })
    }

    fn read_exact_request_to_eof(&mut self) -> Result<Vec<u8>, RootRouteTransportError> {
        let deadline = Instant::now() + IO_TIMEOUT;
        let mut prefix = [0_u8; 4];
        read_exact_until(&mut self.stream, &mut prefix, deadline)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > transport::MAXIMUM_PAYLOAD_BYTES {
            return Err(RootRouteTransportError::RequestDenied);
        }
        let mut frame = Vec::with_capacity(4 + length);
        frame.extend_from_slice(&prefix);
        frame.resize(4 + length, 0);
        read_exact_until(&mut self.stream, &mut frame[4..], deadline)?;
        require_eof_until(&mut self.stream, deadline)?;
        Ok(frame)
    }

    fn write_exact_response_and_require_peer_eof(
        &mut self,
        frame: &[u8],
    ) -> Result<(), RootRouteTransportError> {
        if frame.len() < 5 || frame.len() > transport::MAXIMUM_PAYLOAD_BYTES + 4 {
            return Err(RootRouteTransportError::ResponseDenied);
        }
        let deadline = Instant::now() + IO_TIMEOUT;
        write_all_until(&mut self.stream, frame, deadline)?;
        self.stream
            .shutdown(Shutdown::Write)
            .map_err(|_| RootRouteTransportError::TransportDenied)?;
        require_eof_until(&mut self.stream, deadline)
    }
}

pub(crate) struct BoundRootRouteServerSessionV1 {
    listener: Option<FixedRootRouteListener>,
    terminal: bool,
}

impl BoundRootRouteServerSessionV1 {
    pub(crate) fn bind_source_disabled() -> Result<Self, RootRouteTransportError> {
        if !custody::SOURCE_LISTENER_IMPLEMENTED
            || custody::LISTENER_PRODUCT_WIRED
            || !session_contract::SOURCE_AGENTD_SESSION_CONSTRUCTOR_IMPLEMENTED
            || session_contract::CROSS_PROCESS_STARTUP_ORCHESTRATOR_AVAILABLE
            || session_contract::BROKER_MAIN_ROUTE_WIRED
            || session_contract::PRODUCT_STARTUP_WIRED
        {
            return Err(RootRouteTransportError::TransportDenied);
        }
        Ok(Self {
            listener: Some(FixedRootRouteListener::bind_source_disabled()?),
            terminal: false,
        })
    }

    pub(crate) fn serve_source_disabled_once<
        R: RootPublicationResolver,
        E: RootPublisherRouteExecutor,
    >(
        &mut self,
        resolver: &mut R,
        executor: &mut E,
    ) -> Result<(), RootRouteTransportError> {
        let listener = self.take_listener_once()?;
        let mut connection = listener.accept_source_disabled_once()?;
        root_publisher_route_transport::serve_source_disabled_once(
            &mut connection,
            resolver,
            executor,
        )
    }

    pub(crate) fn close_source_disabled(&mut self) {
        self.listener = None;
        self.terminal = true;
    }

    fn take_listener_once(&mut self) -> Result<FixedRootRouteListener, RootRouteTransportError> {
        if self.terminal {
            return Err(RootRouteTransportError::TransportDenied);
        }
        self.terminal = true;
        self.listener
            .take()
            .ok_or(RootRouteTransportError::TransportDenied)
    }

    #[cfg(test)]
    fn is_terminal_for_test(&self) -> bool {
        self.terminal && self.listener.is_none()
    }
}

pub(crate) fn bind_and_serve_source_disabled_once<
    R: RootPublicationResolver,
    E: RootPublisherRouteExecutor,
>(
    resolver: &mut R,
    executor: &mut E,
) -> Result<(), RootRouteTransportError> {
    let mut session = BoundRootRouteServerSessionV1::bind_source_disabled()?;
    session.serve_source_disabled_once(resolver, executor)
}

fn read_exact_until(
    stream: &mut UnixStream,
    output: &mut [u8],
    deadline: Instant,
) -> Result<(), RootRouteTransportError> {
    let mut offset = 0;
    while offset < output.len() {
        match stream.read(&mut output[offset..]) {
            Ok(0) => return Err(RootRouteTransportError::TransportDenied),
            Ok(length) => offset += length,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_until(
                    stream.as_raw_fd(),
                    libc::POLLIN | libc::POLLHUP,
                    libc::POLLIN | libc::POLLHUP,
                    deadline,
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(RootRouteTransportError::TransportDenied),
        }
    }
    Ok(())
}

fn write_all_until(
    stream: &mut UnixStream,
    input: &[u8],
    deadline: Instant,
) -> Result<(), RootRouteTransportError> {
    let mut offset = 0;
    while offset < input.len() {
        match stream.write(&input[offset..]) {
            Ok(0) => return Err(RootRouteTransportError::TransportDenied),
            Ok(length) => offset += length,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_until(stream.as_raw_fd(), libc::POLLOUT, libc::POLLOUT, deadline)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(RootRouteTransportError::TransportDenied),
        }
    }
    Ok(())
}

fn require_eof_until(
    stream: &mut UnixStream,
    deadline: Instant,
) -> Result<(), RootRouteTransportError> {
    let mut trailing = [0_u8; 1];
    loop {
        match stream.read(&mut trailing) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(RootRouteTransportError::TransportDenied),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_until(
                    stream.as_raw_fd(),
                    libc::POLLIN | libc::POLLHUP,
                    libc::POLLIN | libc::POLLHUP,
                    deadline,
                )?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(RootRouteTransportError::TransportDenied),
        }
    }
}

fn peer_credentials(fd: RawFd) -> Result<libc::ucred, RootRouteTransportError> {
    let mut credentials = MaybeUninit::<libc::ucred>::zeroed();
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
        return Err(RootRouteTransportError::TransportDenied);
    }
    Ok(unsafe { credentials.assume_init() })
}

fn peer_security_context(fd: RawFd) -> Result<String, RootRouteTransportError> {
    let mut bytes = [0_u8; MAXIMUM_PEER_SECURITY_CONTEXT_BYTES];
    let mut length = bytes.len() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    };
    let length = length as usize;
    if result != 0 || length == 0 || length > bytes.len() {
        return Err(RootRouteTransportError::TransportDenied);
    }
    let context = bytes[..length]
        .strip_suffix(&[0])
        .unwrap_or(&bytes[..length]);
    if context.is_empty() || context.contains(&0) {
        return Err(RootRouteTransportError::TransportDenied);
    }
    std::str::from_utf8(context)
        .map(str::to_owned)
        .map_err(|_| RootRouteTransportError::TransportDenied)
}

fn require_cloexec(fd: RawFd) -> Result<(), RootRouteTransportError> {
    if fcntl(fd, libc::F_GETFD)? & libc::FD_CLOEXEC == 0 {
        return Err(RootRouteTransportError::TransportDenied);
    }
    Ok(())
}

fn fcntl(fd: RawFd, command: libc::c_int) -> Result<libc::c_int, RootRouteTransportError> {
    let result = unsafe { libc::fcntl(fd, command) };
    if result < 0 {
        Err(RootRouteTransportError::TransportDenied)
    } else {
        Ok(result)
    }
}

fn socket_option(fd: RawFd, option: libc::c_int) -> Result<libc::c_int, RootRouteTransportError> {
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
        Err(RootRouteTransportError::TransportDenied)
    } else {
        Ok(value)
    }
}

fn poll_until(
    fd: RawFd,
    expected: libc::c_short,
    allowed: libc::c_short,
    deadline: Instant,
) -> Result<(), RootRouteTransportError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(RootRouteTransportError::TransportDenied)?;
        let timeout = remaining.as_millis().clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events: expected,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            if descriptor.revents & !allowed == 0 && descriptor.revents & expected != 0 {
                return Ok(());
            }
            return Err(RootRouteTransportError::TransportDenied);
        }
        if result == 0 {
            return Err(RootRouteTransportError::TransportDenied);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(RootRouteTransportError::TransportDenied);
        }
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::thread;

    static SOCKET_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn fixed_listener_accepts_one_exact_unnamed_peer_and_closes() {
        let _guard = SOCKET_TEST_LOCK.lock().unwrap();
        let listener = FixedRootRouteListener::bind_source_disabled().unwrap();
        let client = thread::spawn(|| {
            let address =
                SocketAddr::from_abstract_name(transport::SOCKET_NAME.as_bytes()).unwrap();
            let mut stream = UnixStream::connect_addr(&address).unwrap();
            stream
                .set_read_timeout(Some(IO_TIMEOUT))
                .expect("set client read timeout");
            stream.write_all(&[0, 0, 0, 2, b'{', b'}']).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).unwrap();
            response
        });
        let mut accepted = listener.accept_source_disabled_once().unwrap();
        let peer = accepted.kernel_peer().unwrap();
        assert!(peer.pid > 1);
        assert_eq!(
            accepted.read_exact_request_to_eof().unwrap(),
            [0, 0, 0, 2, b'{', b'}']
        );
        accepted
            .write_exact_response_and_require_peer_eof(&[0, 0, 0, 2, b'{', b'}'])
            .unwrap();
        assert_eq!(client.join().unwrap(), [0, 0, 0, 2, b'{', b'}']);
        assert!(FixedRootRouteListener::bind_source_disabled().is_ok());
    }

    #[test]
    fn listener_contract_is_fixed_and_absent_from_live_dispatch() {
        assert_eq!(
            SOURCE_STATUS,
            "source_only_concrete_private_route_listener_no_main_dispatch_no_product_wiring_v1"
        );
        assert_eq!(ACCEPT_TIMEOUT, Duration::from_millis(5_000));
        assert_eq!(IO_TIMEOUT, Duration::from_millis(5_000));
        let main = include_str!("main.rs");
        let protocol =
            include_str!("../../../crates/trillionnium-privilege-broker-protocol/src/lib.rs");
        assert!(!main.contains("bind_and_serve_source_disabled_once("));
        assert!(!protocol.contains("run_root_publisher_once"));
        assert!(!custody::LISTENER_PRODUCT_WIRED);
        assert!(!custody::BROKER_MAIN_ROUTE_WIRED);
        assert!(!session_contract::CROSS_PROCESS_STARTUP_ORCHESTRATOR_AVAILABLE);
        assert!(!session_contract::PRODUCT_STARTUP_WIRED);
    }

    #[test]
    fn bound_server_session_closes_before_serve_and_cannot_restart() {
        let _guard = SOCKET_TEST_LOCK.lock().unwrap();
        let mut session = BoundRootRouteServerSessionV1::bind_source_disabled().unwrap();
        session.close_source_disabled();
        assert!(session.is_terminal_for_test());
        assert!(matches!(
            session.take_listener_once(),
            Err(RootRouteTransportError::TransportDenied)
        ));
        assert!(FixedRootRouteListener::bind_source_disabled().is_ok());
    }
}
