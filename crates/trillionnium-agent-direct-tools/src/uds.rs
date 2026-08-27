use std::io::{BufRead, BufReader, Write};
use std::mem::{self, MaybeUninit};
use std::net::Shutdown;
#[cfg(target_os = "android")]
use std::os::android::net::SocketAddrExt;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{SocketAddr, UnixStream};
use std::path::Path;
use std::time::Duration;

#[cfg(any(
    test,
    feature = "development-compatibility-lane",
    feature = "device-launch-package-conformance"
))]
use serde::Serialize;
use serde_json::Value;

use crate::{DirectToolError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Result};

// Accessibility permits a deliberately bounded 60-second gesture/batch. Leave
// a small response margin while still guaranteeing a finite call.
const READ_TIMEOUT: Duration = Duration::from_secs(65);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_PEER_SECURITY_CONTEXT_BYTES: usize = 256;
const ANDROID_APP_ID_MODULUS: u32 = 100_000;
const ANDROID_APP_ID_MIN: u32 = 10_000;
const ANDROID_APP_ID_MAX: u32 = 19_999;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedBackendPeer {
    SystemServer,
    AccessibilityService,
    #[cfg(any(
        test,
        feature = "production-durable-hotpath",
        feature = "device-launch-package-conformance"
    ))]
    AgentDaemon,
}

pub(crate) enum CapturedBackendCall {
    Response {
        exact_response: Vec<u8>,
        value: Value,
    },
    Failure {
        exact_response: Vec<u8>,
        error: DirectToolError,
    },
}

struct CapturedReadFailure {
    observed: Vec<u8>,
    error: DirectToolError,
}

#[cfg(any(
    test,
    feature = "development-compatibility-lane",
    feature = "device-launch-package-conformance"
))]
pub fn call<T: Serialize>(
    path: &Path,
    expected_peer: ExpectedBackendPeer,
    request: &T,
) -> Result<Value> {
    let request = serde_json::to_vec(request)?;
    if request.len() > MAX_REQUEST_BYTES {
        return Err(DirectToolError::InvalidRequest(format!(
            "serialized backend request exceeds {MAX_REQUEST_BYTES} bytes"
        )));
    }
    match call_captured(path, expected_peer, &request) {
        CapturedBackendCall::Response { value, .. } => Ok(value),
        CapturedBackendCall::Failure { error, .. } => Err(error),
    }
}

pub(crate) fn call_captured(
    path: &Path,
    expected_peer: ExpectedBackendPeer,
    serialized_request: &[u8],
) -> CapturedBackendCall {
    match call_captured_inner(path, expected_peer, serialized_request) {
        Ok(call) => call,
        Err(error) => CapturedBackendCall::Failure {
            exact_response: Vec::new(),
            error,
        },
    }
}

fn call_captured_inner(
    path: &Path,
    expected_peer: ExpectedBackendPeer,
    serialized_request: &[u8],
) -> Result<CapturedBackendCall> {
    if serialized_request.len() > MAX_REQUEST_BYTES {
        return Err(DirectToolError::InvalidRequest(format!(
            "serialized backend request exceeds {MAX_REQUEST_BYTES} bytes"
        )));
    }
    let mut stream = connect(path)?;
    verify_connected_peer(path, &stream, expected_peer)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    stream.write_all(serialized_request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)?;

    let mut reader = BufReader::new(stream);
    let response = match read_bounded_line_captured(&mut reader, MAX_RESPONSE_BYTES) {
        Ok(Some(response)) => response,
        Ok(None) => {
            return Ok(CapturedBackendCall::Failure {
                exact_response: Vec::new(),
                error: DirectToolError::BackendFailed(
                    "backend returned no response frame".to_string(),
                ),
            });
        }
        Err(failure) => {
            return Ok(CapturedBackendCall::Failure {
                exact_response: failure.observed,
                error: failure.error,
            });
        }
    };
    if response.is_empty() {
        return Err(DirectToolError::BackendFailed(
            "backend returned an empty response frame".to_string(),
        ));
    }
    if let Err(failure) = require_single_frame_and_peer_close(&mut reader) {
        let mut exact_response = response;
        if !failure.observed.is_empty() {
            exact_response.push(b'\n');
            exact_response.extend_from_slice(&failure.observed);
        }
        return Ok(CapturedBackendCall::Failure {
            exact_response,
            error: failure.error,
        });
    }
    match serde_json::from_slice(&response) {
        Ok(value) => Ok(CapturedBackendCall::Response {
            exact_response: response,
            value,
        }),
        Err(error) => Ok(CapturedBackendCall::Failure {
            exact_response: response,
            error: error.into(),
        }),
    }
}

pub(crate) fn verify_connected_peer(
    path: &Path,
    stream: &UnixStream,
    expected_peer: ExpectedBackendPeer,
) -> Result<()> {
    // Host fixtures use a pathname socket owned by the test process. Product
    // endpoints are compile-time-fixed abstract sockets and can never take
    // this development-only bypass.
    #[cfg(any(test, feature = "dev-overrides"))]
    if !path.to_string_lossy().starts_with('@') {
        return Ok(());
    }
    let _ = path;

    let credentials = peer_credentials(stream.as_raw_fd())?;
    let security_context = peer_security_context(stream.as_raw_fd())?;
    validate_peer_identity(
        expected_peer,
        credentials.uid,
        credentials.gid,
        &security_context,
    )
}

fn peer_credentials(fd: RawFd) -> Result<libc::ucred> {
    let mut credentials = MaybeUninit::<libc::ucred>::zeroed();
    let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` points to writable storage of exactly `length`
    // bytes, and `fd` is a live connected AF_UNIX socket owned by `stream`.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(DirectToolError::BackendUnavailable(format!(
            "could not authenticate backend credentials: {}",
            std::io::Error::last_os_error()
        )));
    }
    if length as usize != mem::size_of::<libc::ucred>() {
        return Err(DirectToolError::BackendUnavailable(
            "backend returned malformed peer credentials".to_string(),
        ));
    }
    // SAFETY: getsockopt succeeded and reported the full initialized struct.
    Ok(unsafe { credentials.assume_init() })
}

fn peer_security_context(fd: RawFd) -> Result<String> {
    let mut bytes = [0_u8; MAX_PEER_SECURITY_CONTEXT_BYTES];
    let mut length = bytes.len() as libc::socklen_t;
    // SAFETY: `bytes` is writable for `length` bytes, and `fd` is a live
    // connected AF_UNIX socket. The returned length is checked before use.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(DirectToolError::BackendUnavailable(format!(
            "could not authenticate backend security context: {}",
            std::io::Error::last_os_error()
        )));
    }
    let length = length as usize;
    if length == 0 || length > bytes.len() {
        return Err(DirectToolError::BackendUnavailable(
            "backend returned malformed security context length".to_string(),
        ));
    }
    let context = &bytes[..length];
    let context = context.strip_suffix(&[0]).unwrap_or(context);
    if context.is_empty() || context.contains(&0) {
        return Err(DirectToolError::BackendUnavailable(
            "backend returned malformed security context".to_string(),
        ));
    }
    let context = std::str::from_utf8(context).map_err(|_| {
        DirectToolError::BackendUnavailable(
            "backend returned a non-UTF-8 security context".to_string(),
        )
    })?;
    if context.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(DirectToolError::BackendUnavailable(
            "backend returned a malformed security context".to_string(),
        ));
    }
    Ok(context.to_string())
}

fn validate_peer_identity(
    expected_peer: ExpectedBackendPeer,
    uid: u32,
    gid: u32,
    security_context: &str,
) -> Result<()> {
    let accepted = match expected_peer {
        ExpectedBackendPeer::SystemServer => {
            uid == 1000 && gid == 1000 && security_context == "u:r:system_server:s0"
        }
        ExpectedBackendPeer::AccessibilityService => {
            uid == gid
                && android_app_id(uid).is_some_and(|app_id| {
                    (ANDROID_APP_ID_MIN..=ANDROID_APP_ID_MAX).contains(&app_id)
                })
                && valid_accessibility_security_context(security_context)
        }
        #[cfg(any(
            test,
            feature = "production-durable-hotpath",
            feature = "device-launch-package-conformance"
        ))]
        ExpectedBackendPeer::AgentDaemon => {
            uid == trillionnium_os_types::direct_operation_tool_call_transport::DAEMON_UID
                && gid == trillionnium_os_types::direct_operation_tool_call_transport::DAEMON_GID
                && security_context
                    == trillionnium_os_types::direct_operation_tool_call_transport::DAEMON_SELINUX_DOMAIN
        }
    };
    if accepted {
        Ok(())
    } else {
        Err(DirectToolError::BackendUnavailable(
            "connected backend peer identity does not match the pinned service".to_string(),
        ))
    }
}

fn android_app_id(uid: u32) -> Option<u32> {
    (uid != 0).then_some(uid % ANDROID_APP_ID_MODULUS)
}

fn valid_accessibility_security_context(context: &str) -> bool {
    const BASE: &str = "u:r:trillionnium_agent_accessibility:s0";
    let Some(categories) = context.strip_prefix(BASE) else {
        return false;
    };
    if categories.is_empty() {
        return true;
    }
    let Some(categories) = categories.strip_prefix(':') else {
        return false;
    };
    !categories.is_empty()
        && categories.split(',').all(|category| {
            category.strip_prefix('c').is_some_and(|number| {
                !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
}

pub(crate) fn connect(path: &Path) -> Result<UnixStream> {
    let display = path.to_string_lossy();
    let stream = if let Some(name) = display.strip_prefix('@') {
        if name.is_empty() || name.len() > 107 || name.as_bytes().contains(&0) {
            return Err(DirectToolError::InvalidRequest(
                "invalid abstract socket name".to_string(),
            ));
        }
        UnixStream::connect_addr(&SocketAddr::from_abstract_name(name.as_bytes())?)
    } else {
        UnixStream::connect(path)
    };
    stream.map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))
}

/// Read exactly one newline-terminated frame without ever allocating more than
/// `maximum` bytes for its body. A peer that streams beyond the bound is
/// rejected while the buffer remains capped.
#[cfg(test)]
fn read_bounded_line<R: BufRead>(reader: &mut R, maximum: usize) -> Result<Option<Vec<u8>>> {
    read_bounded_line_captured(reader, maximum).map_err(|failure| failure.error)
}

fn read_bounded_line_captured<R: BufRead>(
    reader: &mut R,
    maximum: usize,
) -> std::result::Result<Option<Vec<u8>>, CapturedReadFailure> {
    let mut output = Vec::with_capacity(maximum.min(8 * 1024));
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) => {
                return Err(CapturedReadFailure {
                    observed: output,
                    error: error.into(),
                });
            }
        };
        if available.is_empty() {
            if output.is_empty() {
                return Ok(None);
            }
            return Err(CapturedReadFailure {
                observed: output,
                error: DirectToolError::BackendFailed(
                    "response frame is not newline terminated".to_string(),
                ),
            });
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            let Some(next_len) = output.len().checked_add(newline) else {
                return Err(CapturedReadFailure {
                    observed: output,
                    error: DirectToolError::BackendFailed("response size overflow".to_string()),
                });
            };
            if next_len > maximum {
                retain_bounded_observation(&mut output, &available[..newline], maximum);
                return Err(CapturedReadFailure {
                    observed: output,
                    error: DirectToolError::BackendFailed(format!(
                        "response exceeds {maximum} bytes"
                    )),
                });
            }
            output.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            return Ok(Some(output));
        }

        let Some(next_len) = output.len().checked_add(available.len()) else {
            return Err(CapturedReadFailure {
                observed: output,
                error: DirectToolError::BackendFailed("response size overflow".to_string()),
            });
        };
        if next_len > maximum {
            retain_bounded_observation(&mut output, available, maximum);
            return Err(CapturedReadFailure {
                observed: output,
                error: DirectToolError::BackendFailed(format!("response exceeds {maximum} bytes")),
            });
        }
        output.extend_from_slice(available);
        let consumed = available.len();
        reader.consume(consumed);
    }
}

fn retain_bounded_observation(output: &mut Vec<u8>, available: &[u8], maximum: usize) {
    let retained_limit = maximum.saturating_add(1);
    let remaining = retained_limit.saturating_sub(output.len());
    output.extend_from_slice(&available[..available.len().min(remaining)]);
}

fn require_single_frame_and_peer_close(
    reader: &mut BufReader<UnixStream>,
) -> std::result::Result<(), CapturedReadFailure> {
    if let Err(error) = reader
        .get_mut()
        .set_read_timeout(Some(RESPONSE_CLOSE_TIMEOUT))
    {
        return Err(CapturedReadFailure {
            observed: Vec::new(),
            error: error.into(),
        });
    }
    let mut observed = Vec::new();
    loop {
        match reader.fill_buf() {
            Ok([]) if observed.is_empty() => return Ok(()),
            Ok([]) => {
                return Err(CapturedReadFailure {
                    observed,
                    error: DirectToolError::BackendFailed(
                        "backend returned more than one response frame".to_string(),
                    ),
                });
            }
            Ok(available) => {
                let consumed = available.len();
                retain_bounded_observation(&mut observed, available, MAX_RESPONSE_BYTES);
                reader.consume(consumed);
                if observed.len() > MAX_RESPONSE_BYTES {
                    return Err(CapturedReadFailure {
                        observed,
                        error: DirectToolError::BackendFailed(
                            "backend returned more than one response frame".to_string(),
                        ),
                    });
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(CapturedReadFailure {
                    observed,
                    error: DirectToolError::BackendFailed(
                        "backend did not close after its single response frame".to_string(),
                    ),
                });
            }
            Err(error) => {
                return Err(CapturedReadFailure {
                    observed,
                    error: error.into(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Cursor, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use super::*;

    #[test]
    fn bounded_reader_never_accepts_an_oversized_line() {
        let mut bytes = vec![b'x'; 17];
        bytes.push(b'\n');
        let error = read_bounded_line(&mut Cursor::new(bytes), 16).unwrap_err();
        assert!(error.to_string().contains("exceeds 16 bytes"));
    }

    #[test]
    fn bounded_reader_requires_a_complete_frame() {
        let error = read_bounded_line(&mut Cursor::new(b"{}"), 16).unwrap_err();
        assert!(error.to_string().contains("newline terminated"));
    }

    #[test]
    fn oversized_request_is_rejected_before_connecting() {
        let request = serde_json::json!({"payload": "x".repeat(MAX_REQUEST_BYTES)});
        let error = call(
            Path::new("/path-that-must-not-be-contacted/request-too-large.sock"),
            ExpectedBackendPeer::SystemServer,
            &request,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("serialized backend request exceeds")
        );
    }

    #[test]
    fn captured_failure_retains_partial_and_extra_response_bytes() {
        for (name, response, expected, expected_error) in [
            (
                "partial",
                b"{\"partial\":true}".to_vec(),
                b"{\"partial\":true}".to_vec(),
                "newline terminated",
            ),
            (
                "extra",
                b"{}\n{\"extra\":true}\n".to_vec(),
                b"{}\n{\"extra\":true}\n".to_vec(),
                "more than one",
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join(format!("captured-{name}.sock"));
            let listener = UnixListener::bind(&socket).unwrap();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                stream.write_all(&response).unwrap();
            });
            let captured = call_captured(&socket, ExpectedBackendPeer::SystemServer, b"{}");
            server.join().unwrap();
            match captured {
                CapturedBackendCall::Failure {
                    exact_response,
                    error,
                } => {
                    assert_eq!(exact_response, expected);
                    assert!(error.to_string().contains(expected_error));
                }
                CapturedBackendCall::Response { .. } => {
                    panic!("invalid framing unexpectedly became a response")
                }
            }
        }
    }

    #[test]
    fn system_server_peer_requires_exact_credentials_and_context() {
        validate_peer_identity(
            ExpectedBackendPeer::SystemServer,
            1000,
            1000,
            "u:r:system_server:s0",
        )
        .unwrap();
        for (uid, gid, context) in [
            (1001, 1000, "u:r:system_server:s0"),
            (1000, 1001, "u:r:system_server:s0"),
            (1000, 1000, "u:r:system_server:s0:c1"),
            (1000, 1000, "u:r:untrusted_app:s0"),
        ] {
            assert!(
                validate_peer_identity(ExpectedBackendPeer::SystemServer, uid, gid, context)
                    .is_err()
            );
        }
    }

    #[test]
    fn accessibility_peer_accepts_only_its_app_domain_and_app_identity() {
        for (uid, context) in [
            (10_234, "u:r:trillionnium_agent_accessibility:s0"),
            (210_234, "u:r:trillionnium_agent_accessibility:s0:c123,c456"),
        ] {
            validate_peer_identity(ExpectedBackendPeer::AccessibilityService, uid, uid, context)
                .unwrap();
        }
        for (uid, gid, context) in [
            (1000, 1000, "u:r:trillionnium_agent_accessibility:s0"),
            (10_234, 10_235, "u:r:trillionnium_agent_accessibility:s0"),
            (
                10_234,
                10_234,
                "u:r:trillionnium_agent_accessibility:s0:c1.c2",
            ),
            (
                10_234,
                10_234,
                "u:r:trillionnium_agent_accessibility:s0:c1,",
            ),
            (10_234, 10_234, "u:r:trillionnium_agent_accessibility:s00"),
            (10_234, 10_234, "u:r:untrusted_app:s0:c1,c2"),
        ] {
            assert!(
                validate_peer_identity(
                    ExpectedBackendPeer::AccessibilityService,
                    uid,
                    gid,
                    context,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn direct_allocator_peer_is_exact_root_daemon_identity() {
        validate_peer_identity(
            ExpectedBackendPeer::AgentDaemon,
            0,
            0,
            "u:r:trillionnium_agentd:s0",
        )
        .unwrap();
        for (uid, gid, context) in [
            (1000, 0, "u:r:trillionnium_agentd:s0"),
            (0, 1000, "u:r:trillionnium_agentd:s0"),
            (0, 0, "u:r:trillionnium_agentd:s0:c1"),
            (0, 0, "u:r:system_server:s0"),
        ] {
            assert!(
                validate_peer_identity(ExpectedBackendPeer::AgentDaemon, uid, gid, context)
                    .is_err()
            );
        }
    }
}
