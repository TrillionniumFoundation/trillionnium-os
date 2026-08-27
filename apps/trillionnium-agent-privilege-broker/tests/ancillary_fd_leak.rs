use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::process::Command;

use trillionnium_agent_privilege_broker::{
    ALLOWED_SOCKET_DOMAIN, ALLOWED_SOCKET_TYPE, BrokerError, enable_per_frame_credentials,
    receive_frame,
};

const CHILD_ENV: &str = "TRILLIONNIUM_BROKER_FD_LEAK_CHILD";

#[repr(C, align(8))]
struct AlignedControl(Vec<libc::c_ulong>);

#[test]
fn zero_length_rights_never_escape_raii_on_any_error_shape() {
    if std::env::var_os(CHILD_ENV).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("zero_length_rights_never_escape_raii_on_any_error_shape")
            .arg("--test-threads=1")
            .env(CHILD_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    for rights_count in [1_usize, 4, 5, 128] {
        let (sender, receiver) = seqpacket_pair();
        enable_per_frame_credentials(receiver.as_raw_fd()).unwrap();
        let source = File::open("/dev/null").unwrap();
        let before = live_fd_set();
        send_zero_length_rights(sender.as_raw_fd(), &vec![source.as_raw_fd(); rights_count]);
        let error = receive_frame(receiver.as_raw_fd()).unwrap_err();
        assert!(
            !matches!(error, BrokerError::PeerClosed),
            "zero-length record with {rights_count} rights was misclassified as EOF"
        );
        assert_eq!(
            live_fd_set(),
            before,
            "received FD leaked for rights_count={rights_count}"
        );
    }
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

fn send_zero_length_rights(socket_fd: RawFd, rights: &[RawFd]) {
    let control_bytes =
        unsafe { libc::CMSG_SPACE(mem::size_of_val(rights).try_into().unwrap()) as usize };
    let words = control_bytes.div_ceil(mem::size_of::<libc::c_ulong>());
    let mut control = AlignedControl(vec![0; words]);
    let mut iov = libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    };
    let mut message = unsafe { mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control_bytes;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    assert!(!header.is_null());
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of_val(rights).try_into().unwrap()) as _;
        std::ptr::copy_nonoverlapping(
            rights.as_ptr(),
            libc::CMSG_DATA(header).cast::<RawFd>(),
            rights.len(),
        );
    }
    let sent = unsafe { libc::sendmsg(socket_fd, &message, libc::MSG_NOSIGNAL) };
    assert_eq!(sent, 0, "sendmsg: {}", io::Error::last_os_error());
}

fn live_fd_set() -> BTreeSet<RawFd> {
    let candidates = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .parse::<RawFd>()
                .unwrap()
        })
        .collect::<Vec<_>>();
    candidates
        .into_iter()
        .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
        .collect()
}
