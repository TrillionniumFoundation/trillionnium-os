use std::io::{Read as _, Write as _};
use std::mem::{self, MaybeUninit};
use std::net::Shutdown;
#[cfg(target_os = "android")]
use std::os::android::net::SocketAddrExt as _;
use std::os::fd::{AsRawFd as _, RawFd};
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt as _;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::time::Duration;

use trillionnium_os_types::capability_lease_root_proof_carrier as carrier;

use super::root_authentication_proof_transport::{
    KernelPeer, RootProofConnection, RootProofTransportError,
};

#[allow(dead_code)]
pub(crate) const SOURCE_STATUS: &str =
    "source_only_fixed_abstract_socket_connector_no_broker_route_no_product_constructor_v1";

const IO_TIMEOUT: Duration = Duration::from_millis(5_000);
const MAXIMUM_PEER_SECURITY_CONTEXT_BYTES: usize = 256;

pub(crate) struct FixedRootProofSocket {
    stream: UnixStream,
}

impl FixedRootProofSocket {
    pub(crate) fn connect_source_disabled() -> Result<Self, RootProofTransportError> {
        let address = SocketAddr::from_abstract_name(carrier::SOCKET_NAME.as_bytes())
            .map_err(|_| RootProofTransportError::TransportFailed)?;
        let stream = UnixStream::connect_addr(&address)
            .map_err(|_| RootProofTransportError::TransportFailed)?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|_| RootProofTransportError::TransportFailed)?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|_| RootProofTransportError::TransportFailed)?;
        Ok(Self { stream })
    }
}

impl RootProofConnection for FixedRootProofSocket {
    fn kernel_peer(&mut self) -> Result<KernelPeer, RootProofTransportError> {
        let credentials = peer_credentials(self.stream.as_raw_fd())?;
        let selinux_domain = peer_security_context(self.stream.as_raw_fd())?;
        Ok(KernelPeer {
            uid: credentials.uid,
            gid: credentials.gid,
            selinux_domain,
        })
    }

    fn write_exact_frame(&mut self, frame: &[u8]) -> Result<(), RootProofTransportError> {
        self.stream
            .write_all(frame)
            .and_then(|_| self.stream.flush())
            .map_err(|_| RootProofTransportError::TransportFailed)
    }

    fn shutdown_write_and_require_peer_eof(&mut self) -> Result<(), RootProofTransportError> {
        self.stream
            .shutdown(Shutdown::Write)
            .map_err(|_| RootProofTransportError::TransportFailed)?;
        let mut trailing = [0_u8; 1];
        if self
            .stream
            .read(&mut trailing)
            .map_err(|_| RootProofTransportError::TransportFailed)?
            != 0
        {
            return Err(RootProofTransportError::TransportFailed);
        }
        Ok(())
    }
}

fn peer_credentials(fd: RawFd) -> Result<libc::ucred, RootProofTransportError> {
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
        return Err(RootProofTransportError::TransportFailed);
    }
    Ok(unsafe { credentials.assume_init() })
}

fn peer_security_context(fd: RawFd) -> Result<String, RootProofTransportError> {
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
        return Err(RootProofTransportError::TransportFailed);
    }
    let context = bytes[..length]
        .strip_suffix(&[0])
        .unwrap_or(&bytes[..length]);
    if context.is_empty() || context.contains(&0) {
        return Err(RootProofTransportError::TransportFailed);
    }
    std::str::from_utf8(context)
        .map(str::to_owned)
        .map_err(|_| RootProofTransportError::TransportFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_is_fixed_to_the_contract_abstract_name() {
        let address = SocketAddr::from_abstract_name(carrier::SOCKET_NAME.as_bytes()).unwrap();
        assert_eq!(
            address.as_abstract_name(),
            Some(carrier::SOCKET_NAME.as_bytes())
        );
        assert_eq!(IO_TIMEOUT, Duration::from_millis(5_000));
    }
}
