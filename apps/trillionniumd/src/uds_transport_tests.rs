use super::*;

use std::io;
use std::process;
use std::sync::mpsc::sync_channel;
use std::thread;

fn short_deadline() -> AgentApiDeadline {
    AgentApiDeadline::from_now(Duration::from_secs(2)).expect("test deadline")
}

fn assert_current_process_credentials(credentials: UnixMessageCredentials) {
    assert_eq!(credentials.pid, process::id());
    assert_eq!(credentials.uid, unsafe { libc::geteuid() });
    assert_eq!(credentials.gid, unsafe { libc::getegid() });
}

fn send_frame_with_rights(stream: &UnixStream, frame: &[u8], fd: libc::c_int) -> io::Result<()> {
    let rights_bytes = std::mem::size_of::<libc::c_int>();
    let control_len = unsafe { libc::CMSG_SPACE(rights_bytes as libc::c_uint) as usize };
    let mut control = vec![0u8; control_len];
    let mut iovec = libc::iovec {
        iov_base: frame.as_ptr().cast_mut().cast(),
        iov_len: frame.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();

    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    assert!(!header.is_null());
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(rights_bytes as libc::c_uint) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), fd);
    }

    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != frame.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "SCM_RIGHTS test frame was only partially sent",
        ));
    }
    Ok(())
}

#[test]
fn production_reader_enforces_one_absolute_slowloris_deadline() {
    let (server, mut client) = UnixStream::pair().unwrap();
    enable_unix_message_credentials(&server).unwrap();
    let writer = thread::spawn(move || {
        for byte in b"{\"slowloris\":\"this frame never reaches its newline before the deadline\"}"
        {
            if client.write_all(&[*byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });

    let started = Instant::now();
    let error = read_agent_frame_with_credentials(
        &server,
        AgentApiDeadline::from_now(Duration::from_millis(120)).unwrap(),
    )
    .unwrap_err();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(70),
        "reader failed before exercising the absolute deadline: {elapsed:?}: {error:#}"
    );
    assert!(
        elapsed < Duration::from_millis(600),
        "byte drips reset the production reader deadline: {elapsed:?}: {error:#}"
    );
    drop(server);
    writer.join().unwrap();
}

#[test]
fn production_reader_rejects_oversize_before_newline() {
    let (server, mut client) = UnixStream::pair().unwrap();
    enable_unix_message_credentials(&server).unwrap();
    let writer = thread::spawn(move || {
        let oversized = vec![b'a'; MAX_AGENT_API_FRAME_BYTES + 1];
        let _ = client.write_all(&oversized);
        let _ = client.write_all(b"\n");
    });

    let error = read_agent_frame_with_credentials(&server, short_deadline()).unwrap_err();
    assert!(
        format!("{error:#}").contains("oversized Agent API frame"),
        "{error:#}"
    );
    drop(server);
    writer.join().unwrap();
}

#[test]
fn production_reader_accepts_split_frame_from_one_kernel_writer() {
    let (server, mut client) = UnixStream::pair().unwrap();
    enable_unix_message_credentials(&server).unwrap();
    let writer = thread::spawn(move || {
        client.write_all(b"{\"split\":").unwrap();
        thread::sleep(Duration::from_millis(20));
        client.write_all(b"true}\n").unwrap();
    });

    let (frame, credentials) =
        read_agent_frame_with_credentials(&server, short_deadline()).unwrap();
    assert_eq!(frame, b"{\"split\":true}");
    assert_current_process_credentials(credentials);
    writer.join().unwrap();
}

#[test]
fn production_reader_preserves_coalesced_frame_boundaries_and_credentials() {
    let (server, mut client) = UnixStream::pair().unwrap();
    enable_unix_message_credentials(&server).unwrap();
    client
        .write_all(b"{\"first\":1}\n{\"second\":2}\n")
        .unwrap();

    let (first, first_credentials) =
        read_agent_frame_with_credentials(&server, short_deadline()).unwrap();
    let (second, second_credentials) =
        read_agent_frame_with_credentials(&server, short_deadline()).unwrap();
    assert_eq!(first, b"{\"first\":1}");
    assert_eq!(second, b"{\"second\":2}");
    assert_current_process_credentials(first_credentials);
    assert_eq!(second_credentials, first_credentials);
}

#[test]
fn accepted_socket_rejects_data_queued_before_passcred_is_enabled() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("queued-before-passcred.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let (queued_tx, queued_rx) = sync_channel(0);
    let connector = thread::spawn(move || {
        let mut client = UnixStream::connect(socket_path).unwrap();
        client.write_all(b"{\"queued\":true}\n").unwrap();
        queued_tx.send(()).unwrap();
    });

    let (server, _) = listener.accept().unwrap();
    queued_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    enable_unix_message_credentials(&server).unwrap();
    match read_agent_frame_with_credentials(&server, short_deadline()) {
        Ok((frame, credentials)) => {
            assert_eq!(frame, b"{\"queued\":true}");
            assert_current_process_credentials(credentials);
        }
        Err(error) => assert!(
            format!("{error:#}").contains("invalid zero Agent API message pid"),
            "queued bytes failed for an unexpected reason: {error:#}"
        ),
    }
    connector.join().unwrap();
}

#[test]
fn production_reader_rejects_frame_without_scm_credentials() {
    let (server, mut client) = UnixStream::pair().unwrap();
    client.write_all(b"{}\n").unwrap();

    let error = read_agent_frame_with_credentials(&server, short_deadline()).unwrap_err();
    assert!(
        format!("{error:#}").contains("no kernel message credentials"),
        "{error:#}"
    );
}

#[test]
fn production_reader_rejects_truncated_ancillary_credentials() {
    let (server, client) = UnixStream::pair().unwrap();
    enable_unix_message_credentials(&server).unwrap();
    let transferred = File::open("/dev/null").unwrap();
    send_frame_with_rights(&client, b"{}\n", transferred.as_raw_fd()).unwrap();

    let error = read_agent_frame_with_credentials(&server, short_deadline()).unwrap_err();
    assert!(
        format!("{error:#}").contains("credentials were truncated"),
        "{error:#}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn production_reader_rejects_mixed_parent_and_inherited_fd_writers() {
    let (server, mut client) = UnixStream::pair().unwrap();
    enable_unix_message_credentials(&server).unwrap();
    client.write_all(b"{\"mixed\":").unwrap();

    let child_pid = unsafe { libc::fork() };
    assert!(
        child_pid >= 0,
        "fork failed: {}",
        io::Error::last_os_error()
    );
    if child_pid == 0 {
        let suffix = b"true}\n";
        let written = unsafe {
            libc::write(
                client.as_raw_fd(),
                suffix.as_ptr().cast::<libc::c_void>(),
                suffix.len(),
            )
        };
        let status = if written == suffix.len() as isize {
            0
        } else {
            111
        };
        unsafe { libc::_exit(status) };
    }

    let mut child_status = 0;
    let waited = unsafe { libc::waitpid(child_pid, &mut child_status, 0) };
    assert_eq!(waited, child_pid);
    assert!(libc::WIFEXITED(child_status));
    assert_eq!(libc::WEXITSTATUS(child_status), 0);

    let error = read_agent_frame_with_credentials(&server, short_deadline()).unwrap_err();
    assert!(
        format!("{error:#}").contains("changed kernel-authenticated writer"),
        "{error:#}"
    );
}
