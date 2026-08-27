//! Minimal Android property-service v2 client for the static musl broker.

use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::time::Duration;

use thiserror::Error;

const PROPERTY_SERVICE_PATH: &[u8] = b"/dev/socket/property_service\0";
const PROP_MSG_SETPROP2: u32 = 0x0002_0001;
const PROP_SUCCESS: u32 = 0;
const INIT_SELINUX_DOMAIN: &str = "u:r:init:s0";
const MAX_PROPERTY_NAME_BYTES: usize = 127;
const MAX_PROPERTY_VALUE_BYTES: usize = 91;

#[derive(Debug, Error)]
pub enum AndroidPropertyError {
    #[error("Android property request is invalid")]
    Invalid,
    #[error("Android property service peer is invalid")]
    InvalidPeer,
    #[error("Android property service rejected the update: {0}")]
    Rejected(u32),
    #[error("Android property service I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AndroidPropertyError>;

pub fn set_property(name: &str, value: &str) -> Result<()> {
    let request = encode_setprop2(name, value)?;
    let descriptor = connect_property_service(Duration::from_secs(2))?;
    require_init_peer(descriptor.as_raw_fd())?;
    write_complete(descriptor.as_raw_fd(), &request)?;
    let mut response = [0_u8; size_of::<u32>()];
    read_complete(descriptor.as_raw_fd(), &mut response)?;
    let response = u32::from_ne_bytes(response);
    if response != PROP_SUCCESS {
        return Err(AndroidPropertyError::Rejected(response));
    }
    Ok(())
}

fn encode_setprop2(name: &str, value: &str) -> Result<Vec<u8>> {
    if name.is_empty()
        || name.len() > MAX_PROPERTY_NAME_BYTES
        || value.len() > MAX_PROPERTY_VALUE_BYTES
        || name.as_bytes().contains(&0)
        || value.as_bytes().contains(&0)
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AndroidPropertyError::Invalid);
    }
    let name_length = u32::try_from(name.len()).map_err(|_| AndroidPropertyError::Invalid)?;
    let value_length = u32::try_from(value.len()).map_err(|_| AndroidPropertyError::Invalid)?;
    let mut request = Vec::with_capacity(12 + name.len() + value.len());
    request.extend_from_slice(&PROP_MSG_SETPROP2.to_ne_bytes());
    request.extend_from_slice(&name_length.to_ne_bytes());
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(&value_length.to_ne_bytes());
    request.extend_from_slice(value.as_bytes());
    Ok(request)
}

fn connect_property_service(timeout: Duration) -> Result<OwnedFd> {
    // SAFETY: fixed domain/type/protocol; ownership transfers on success.
    let descriptor =
        unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: socket returned a fresh descriptor.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    configure_timeout(descriptor.as_raw_fd(), timeout)?;
    // SAFETY: zero is a valid initial sockaddr_un representation.
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if PROPERTY_SERVICE_PATH.len() > address.sun_path.len() {
        return Err(AndroidPropertyError::Invalid);
    }
    for (destination, source) in address
        .sun_path
        .iter_mut()
        .zip(PROPERTY_SERVICE_PATH.iter().copied())
    {
        *destination = source as libc::c_char;
    }
    let length = (size_of::<libc::sa_family_t>() + PROPERTY_SERVICE_PATH.len()) as libc::socklen_t;
    // SAFETY: address contains the exact NUL-terminated property-service path.
    if unsafe {
        libc::connect(
            descriptor.as_raw_fd(),
            std::ptr::from_ref(&address).cast(),
            length,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(descriptor)
}

fn configure_timeout(descriptor: RawFd, timeout: Duration) -> Result<()> {
    let value = libc::timeval {
        tv_sec: timeout.as_secs() as _,
        tv_usec: timeout.subsec_micros() as _,
    };
    for option in [libc::SO_SNDTIMEO, libc::SO_RCVTIMEO] {
        // SAFETY: value has the exact timeval layout required by both options.
        if unsafe {
            libc::setsockopt(
                descriptor,
                libc::SOL_SOCKET,
                option,
                std::ptr::from_ref(&value).cast(),
                size_of::<libc::timeval>() as _,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn require_init_peer(descriptor: RawFd) -> Result<()> {
    // SAFETY: zero is valid and getsockopt initializes the complete ucred.
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut credential_length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials and length are writable for the exact option.
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut credentials).cast(),
            &mut credential_length,
        )
    } != 0
        || credential_length as usize != size_of::<libc::ucred>()
        || !valid_init_credentials(&credentials)
    {
        return Err(AndroidPropertyError::InvalidPeer);
    }
    let mut security = [0_u8; 128];
    let mut security_length = security.len() as libc::socklen_t;
    // SAFETY: security is writable and SO_PEERSEC returns at most its length.
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            security.as_mut_ptr().cast(),
            &mut security_length,
        )
    } != 0
        || security_length == 0
        || security_length as usize > security.len()
    {
        return Err(AndroidPropertyError::InvalidPeer);
    }
    let observed = &security[..security_length as usize];
    let observed = observed.strip_suffix(&[0]).unwrap_or(observed);
    if observed != INIT_SELINUX_DOMAIN.as_bytes() {
        return Err(AndroidPropertyError::InvalidPeer);
    }
    Ok(())
}

fn valid_init_credentials(credentials: &libc::ucred) -> bool {
    credentials.pid == 1 && credentials.uid == 0 && credentials.gid == 0
}

fn write_complete(descriptor: RawFd, bytes: &[u8]) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        // SAFETY: remaining payload is readable for this synchronous send.
        let sent = unsafe {
            libc::send(
                descriptor,
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
                libc::MSG_NOSIGNAL,
            )
        };
        if sent > 0 {
            offset += sent as usize;
            continue;
        }
        if sent == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    Ok(())
}

fn read_complete(descriptor: RawFd, bytes: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        // SAFETY: remaining response storage is writable for recv.
        let received = unsafe {
            libc::recv(
                descriptor,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
                libc::MSG_WAITALL,
            )
        };
        if received > 0 {
            offset += received as usize;
            continue;
        }
        if received == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setprop2_ready_request_matches_native_wire_golden() {
        let request = encode_setprop2("sys.trillionnium.shell_exec.ready", "ready").unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&0x0002_0001_u32.to_ne_bytes());
        expected.extend_from_slice(&33_u32.to_ne_bytes());
        expected.extend_from_slice(b"sys.trillionnium.shell_exec.ready");
        expected.extend_from_slice(&5_u32.to_ne_bytes());
        expected.extend_from_slice(b"ready");
        assert_eq!(request, expected);
    }

    #[test]
    fn property_wire_rejects_nul_and_oversize() {
        assert!(encode_setprop2("bad\0name", "ready").is_err());
        assert!(encode_setprop2("sys.ok", &"x".repeat(92)).is_err());
    }

    #[test]
    fn property_service_peer_is_exact_pid_one_root() {
        assert!(valid_init_credentials(&libc::ucred {
            pid: 1,
            uid: 0,
            gid: 0,
        }));
        for credentials in [
            libc::ucred {
                pid: 2,
                uid: 0,
                gid: 0,
            },
            libc::ucred {
                pid: 1,
                uid: 1000,
                gid: 0,
            },
            libc::ucred {
                pid: 1,
                uid: 0,
                gid: 1000,
            },
        ] {
            assert!(!valid_init_credentials(&credentials));
        }
    }
}
