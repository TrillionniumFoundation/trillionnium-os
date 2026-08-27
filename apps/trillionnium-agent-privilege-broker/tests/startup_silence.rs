use std::io;
use std::net::UdpSocket;
use std::os::fd::OwnedFd;
use std::process::{Command, Stdio};
use std::time::Duration;
use trillionnium_agent_privilege_broker::ANDROID_INIT_LISTENER_ENVIRONMENT;

#[test]
fn rejected_udp_stderr_receives_no_startup_diagnostic_bytes() {
    let receiver = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let sender = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    sender.connect(receiver.local_addr().unwrap()).unwrap();
    let sender_fd: OwnedFd = sender.into();

    let status = Command::new(env!("CARGO_BIN_EXE_trillionnium-agent-privilege-broker"))
        .args(["--inherited-fd", "3"])
        .env_remove(ANDROID_INIT_LISTENER_ENVIRONMENT)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(sender_fd))
        .status()
        .unwrap();
    assert!(!status.success());

    let mut buffer = [0_u8; 256];
    match receiver.recv(&mut buffer) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok(count) => panic!("startup leaked {count} diagnostic bytes through UDP fd2"),
        Err(error) => panic!("unexpected UDP receive error: {error}"),
    }
}

#[test]
fn rejected_android_and_unreviewed_socket_environment_are_silent() {
    for (name, value, arguments) in [
        (ANDROID_INIT_LISTENER_ENVIRONMENT, "2147483647", &[][..]),
        (
            "ANDROID_SOCKET_unreviewed_broker",
            "3",
            &["--inherited-fd", "3"][..],
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_trillionnium-agent-privilege-broker"))
            .args(arguments)
            .env_remove(ANDROID_INIT_LISTENER_ENVIRONMENT)
            .env(name, value)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}
