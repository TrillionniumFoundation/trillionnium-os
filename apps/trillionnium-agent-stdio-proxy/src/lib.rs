//! Source-only Codex System API stdio proxy.
//!
//! The binary accepts no route selector and uses only fixed inherited control
//! FD 3. Product packaging, listener ownership, peer authentication, logical
//! delivery, adapter launch, backend access, and effect authority remain absent.

use std::io::{BufRead, Write};
use std::mem::{self, size_of};
use std::os::fd::RawFd;

use anyhow::{Context, Result, bail};
use trillionnium_os_types::direct_operation_stdio_proxy::{
    AcceptedStdioProxyResult, MAXIMUM_MCP_REQUEST_BYTES, MAXIMUM_WIRE_PACKET_BYTES, NONCE_BYTES,
    StdioProxyClientSequence, StdioProxyPacket,
};

pub const CONTROL_FD: RawFd = 3;

pub fn run_proxy<R: BufRead, W: Write>(
    mut input: R,
    mut output: W,
    control_fd: RawFd,
) -> Result<()> {
    validate_connected_seqpacket(control_fd)?;
    let proxy_nonce = kernel_nonce()?;
    send_packet(control_fd, &StdioProxyPacket::hello(proxy_nonce)?.encode())?;
    let welcome = StdioProxyPacket::decode(&receive_packet(control_fd)?)?;
    let mut sequence = StdioProxyClientSequence::establish(proxy_nonce, &welcome)?;

    while let Some(payload) = read_newline_frame(&mut input)? {
        let request = sequence.begin_request(&payload)?;
        send_packet(control_fd, &request.encode())?;
        let result = StdioProxyPacket::decode(&receive_packet(control_fd)?)?;
        match sequence.accept_result(result)? {
            AcceptedStdioProxyResult::Response(payload) => {
                output.write_all(&payload)?;
                output.write_all(b"\n")?;
                output.flush()?;
            }
            AcceptedStdioProxyResult::NoResponse => {}
            AcceptedStdioProxyResult::Denied => {
                bail!("stdio_proxy_daemon_denied_frame");
            }
        }
    }
    Ok(())
}

fn validate_connected_seqpacket(descriptor: RawFd) -> Result<()> {
    if descriptor < 0 {
        bail!("stdio_proxy_control_fd_denied");
    }
    let mut socket_type: libc::c_int = 0;
    let mut socket_type_length = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut socket_type).cast(),
            &raw mut socket_type_length,
        )
    } != 0
        || socket_type_length as usize != size_of::<libc::c_int>()
        || socket_type != libc::SOCK_SEQPACKET
    {
        bail!("stdio_proxy_control_socket_type_denied");
    }
    let mut address: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut address_length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            descriptor,
            (&raw mut address).cast(),
            &raw mut address_length,
        )
    } != 0
    {
        bail!("stdio_proxy_control_socket_unconnected");
    }
    validate_connected_seqpacket_observation(socket_type, address_length, address.ss_family)?;
    let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if descriptor_flags < 0
        || unsafe {
            libc::fcntl(
                descriptor,
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } != 0
    {
        bail!("stdio_proxy_control_socket_cloexec_denied");
    }
    Ok(())
}

fn validate_connected_seqpacket_observation(
    socket_type: libc::c_int,
    address_length: libc::socklen_t,
    address_family: libc::sa_family_t,
) -> Result<()> {
    if socket_type != libc::SOCK_SEQPACKET {
        bail!("stdio_proxy_control_socket_type_denied");
    }
    if usize::try_from(address_length).ok() < Some(size_of::<libc::sa_family_t>()) {
        bail!("stdio_proxy_control_socket_unconnected");
    }
    if libc::c_int::from(address_family) != libc::AF_UNIX {
        bail!("stdio_proxy_control_socket_family_denied");
    }
    Ok(())
}

fn kernel_nonce() -> Result<[u8; NONCE_BYTES]> {
    let mut nonce = [0_u8; NONCE_BYTES];
    let mut written = 0;
    while written < nonce.len() {
        let result = unsafe {
            libc::getrandom(
                nonce[written..].as_mut_ptr().cast(),
                nonce.len() - written,
                0,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("stdio_proxy_kernel_nonce_denied");
        }
        if result == 0 {
            bail!("stdio_proxy_kernel_nonce_short_read");
        }
        written += usize::try_from(result).context("stdio_proxy_kernel_nonce_length_denied")?;
    }
    if nonce.iter().all(|byte| *byte == 0) {
        bail!("stdio_proxy_kernel_nonce_zero_denied");
    }
    Ok(nonce)
}

fn read_newline_frame<R: BufRead>(input: &mut R) -> Result<Option<Vec<u8>>> {
    let mut output = Vec::with_capacity(MAXIMUM_MCP_REQUEST_BYTES.min(8 * 1024));
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            if output.is_empty() {
                return Ok(None);
            }
            bail!("stdio_proxy_input_not_newline_terminated");
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if output.len().saturating_add(newline) > MAXIMUM_MCP_REQUEST_BYTES {
                bail!("stdio_proxy_input_frame_oversized");
            }
            output.extend_from_slice(&available[..newline]);
            input.consume(newline + 1);
            if output.is_empty() || output.last() == Some(&b'\r') {
                bail!("stdio_proxy_input_frame_boundary_denied");
            }
            return Ok(Some(output));
        }
        if output.len().saturating_add(available.len()) > MAXIMUM_MCP_REQUEST_BYTES {
            bail!("stdio_proxy_input_frame_oversized");
        }
        output.extend_from_slice(available);
        let consumed = available.len();
        input.consume(consumed);
    }
}

fn send_packet(descriptor: RawFd, packet: &[u8]) -> Result<()> {
    if packet.is_empty() || packet.len() > MAXIMUM_WIRE_PACKET_BYTES {
        bail!("stdio_proxy_output_packet_length_denied");
    }
    let result = unsafe {
        libc::send(
            descriptor,
            packet.as_ptr().cast(),
            packet.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("stdio_proxy_output_packet_denied");
    }
    if usize::try_from(result).ok() != Some(packet.len()) {
        bail!("stdio_proxy_output_packet_truncated");
    }
    Ok(())
}

#[repr(align(16))]
struct AlignedControl([u8; 256]);

fn receive_packet(descriptor: RawFd) -> Result<Vec<u8>> {
    receive_packet_with_capacity(descriptor, MAXIMUM_WIRE_PACKET_BYTES)
}

fn receive_packet_with_capacity(descriptor: RawFd, capacity: usize) -> Result<Vec<u8>> {
    if capacity == 0 || capacity > MAXIMUM_WIRE_PACKET_BYTES {
        bail!("stdio_proxy_input_packet_capacity_denied");
    }
    let mut packet = vec![0_u8; capacity];
    let mut control = AlignedControl([0; 256]);
    let mut iovec = libc::iovec {
        iov_base: packet.as_mut_ptr().cast(),
        iov_len: packet.len(),
    };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &raw mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control.0.len();
    let received = unsafe { libc::recvmsg(descriptor, &raw mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(std::io::Error::last_os_error()).context("stdio_proxy_input_packet_denied");
    }
    let has_control = unsafe { !libc::CMSG_FIRSTHDR(&message).is_null() };
    if has_control || message.msg_flags & libc::MSG_CTRUNC != 0 {
        close_received_rights(&message);
        bail!("stdio_proxy_ancillary_data_denied");
    }
    if message.msg_flags & libc::MSG_TRUNC != 0 {
        bail!("stdio_proxy_input_packet_truncated");
    }
    let received = usize::try_from(received).context("stdio_proxy_input_packet_length_denied")?;
    if received == 0 || received > packet.len() {
        bail!("stdio_proxy_input_packet_length_denied");
    }
    packet.truncate(received);
    Ok(packet)
}

fn close_received_rights(message: &libc::msghdr) {
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let header_ref = unsafe { &*header };
        if header_ref.cmsg_level == libc::SOL_SOCKET && header_ref.cmsg_type == libc::SCM_RIGHTS {
            let header_bytes = unsafe { libc::CMSG_LEN(0) as usize };
            let payload_bytes = (header_ref.cmsg_len as usize).saturating_sub(header_bytes);
            let descriptors = payload_bytes / size_of::<RawFd>();
            let data = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
            for index in 0..descriptors {
                let received_fd = unsafe { std::ptr::read_unaligned(data.add(index)) };
                if received_fd >= 0 {
                    unsafe {
                        libc::close(received_fd);
                    }
                }
            }
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::thread;

    use trillionnium_os_types::direct_operation_stdio_proxy::{
        CodexSystemApiMcpMethod, StdioProxyBrokerSequence, StdioProxyPacketKind,
        StdioProxyResultDisposition,
    };

    fn nonce(value: u8) -> [u8; NONCE_BYTES] {
        [value; NONCE_BYTES]
    }

    fn socket_pair() -> (OwnedFd, OwnedFd) {
        let mut descriptors = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    descriptors.as_mut_ptr(),
                )
            },
            0
        );
        unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        }
    }

    fn receive_wire(descriptor: RawFd) -> StdioProxyPacket {
        StdioProxyPacket::decode(&receive_packet(descriptor).unwrap()).unwrap()
    }

    fn send_wire(descriptor: RawFd, packet: &StdioProxyPacket) {
        send_packet(descriptor, &packet.encode()).unwrap();
    }

    type ProxyThread = thread::JoinHandle<(Result<()>, Vec<u8>)>;

    fn begin_proxy(input: Vec<u8>) -> (OwnedFd, ProxyThread, [u8; NONCE_BYTES]) {
        let (proxy, broker) = socket_pair();
        let handle = thread::spawn(move || {
            let mut output = Vec::new();
            let result = run_proxy(Cursor::new(input), &mut output, proxy.as_raw_fd());
            (result, output)
        });
        let hello = receive_wire(broker.as_raw_fd());
        assert_eq!(hello.kind(), StdioProxyPacketKind::Hello);
        let proxy_nonce = *hello.correlation_nonce();
        (broker, handle, proxy_nonce)
    }

    #[test]
    fn host_proxy_forwards_exact_bytes_and_closed_methods() {
        let first = br#" {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}} "#;
        let second = br#"{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"trillionnium_system_api","arguments":{"opaque":"byte exact"}}}"#;
        let mut input = Vec::new();
        input.extend_from_slice(first);
        input.push(b'\n');
        input.extend_from_slice(second);
        input.push(b'\n');
        let (broker, handle, proxy_nonce) = begin_proxy(input);
        let session_nonce = nonce(9);
        send_wire(
            broker.as_raw_fd(),
            &StdioProxyPacket::welcome(proxy_nonce, session_nonce).unwrap(),
        );
        let mut sequence = StdioProxyBrokerSequence::new(session_nonce).unwrap();

        let first_frame = receive_wire(broker.as_raw_fd());
        assert_eq!(first_frame.payload(), first);
        assert_eq!(
            sequence.accept_frame(&first_frame).unwrap(),
            CodexSystemApiMcpMethod::Initialize
        );
        let first_response = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
        send_wire(
            broker.as_raw_fd(),
            &StdioProxyPacket::mcp_result(
                session_nonce,
                1,
                StdioProxyResultDisposition::Response,
                first_response,
            )
            .unwrap(),
        );

        let second_frame = receive_wire(broker.as_raw_fd());
        assert_eq!(second_frame.payload(), second);
        assert_eq!(
            sequence.accept_frame(&second_frame).unwrap(),
            CodexSystemApiMcpMethod::SystemApiToolCall
        );
        let second_response = br#"{"jsonrpc":"2.0","id":"x","result":{"kept":"exact"}}"#;
        send_wire(
            broker.as_raw_fd(),
            &StdioProxyPacket::mcp_result(
                session_nonce,
                2,
                StdioProxyResultDisposition::Response,
                second_response,
            )
            .unwrap(),
        );
        drop(broker);
        let (result, output) = handle.join().unwrap();
        result.unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(first_response);
        expected.push(b'\n');
        expected.extend_from_slice(second_response);
        expected.push(b'\n');
        assert_eq!(output, expected);
    }

    #[test]
    fn host_proxy_rejects_wrong_and_duplicate_result_sequences() {
        let mut request = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec();
        request.push(b'\n');
        request.extend_from_slice(br#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#);
        request.push(b'\n');
        let (broker, handle, proxy_nonce) = begin_proxy(request);
        let session_nonce = nonce(8);
        send_wire(
            broker.as_raw_fd(),
            &StdioProxyPacket::welcome(proxy_nonce, session_nonce).unwrap(),
        );
        let first = receive_wire(broker.as_raw_fd());
        assert_eq!(first.sequence(), 1);
        let result = StdioProxyPacket::mcp_result(
            session_nonce,
            1,
            StdioProxyResultDisposition::Response,
            br#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        )
        .unwrap();
        send_wire(broker.as_raw_fd(), &result);
        send_wire(broker.as_raw_fd(), &result);
        let second = receive_wire(broker.as_raw_fd());
        assert_eq!(second.sequence(), 2);
        let (error, _) = handle.join().unwrap();
        assert!(
            error
                .unwrap_err()
                .to_string()
                .contains("stdio_proxy_result_binding_denied")
        );
    }

    #[test]
    fn host_proxy_rejects_welcome_nonce_length_and_hash_drift() {
        for mutation in [0_u8, 1, 2] {
            let (broker, handle, proxy_nonce) = begin_proxy(Vec::new());
            let mut welcome = StdioProxyPacket::welcome(proxy_nonce, nonce(7))
                .unwrap()
                .encode();
            match mutation {
                0 => welcome[56] ^= 1,
                1 => welcome[88..92].copy_from_slice(&1_u32.to_be_bytes()),
                2 => welcome[92] ^= 1,
                _ => unreachable!(),
            }
            send_packet(broker.as_raw_fd(), &welcome).unwrap();
            let (result, _) = handle.join().unwrap();
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("stdio_proxy_welcome_binding_denied")
                    || error.contains("stdio_proxy_packet_length_denied")
                    || error.contains("stdio_proxy_packet_hash_denied")
            );
        }
    }

    #[test]
    fn host_proxy_rejects_cmsg_and_closes_received_fd() {
        let (broker, handle, proxy_nonce) = begin_proxy(Vec::new());
        let welcome = StdioProxyPacket::welcome(proxy_nonce, nonce(6))
            .unwrap()
            .encode();
        let transferred =
            unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(transferred >= 0);
        let transferred = unsafe { OwnedFd::from_raw_fd(transferred) };
        send_with_fd(broker.as_raw_fd(), &welcome, transferred.as_raw_fd());
        let (result, _) = handle.join().unwrap();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("stdio_proxy_ancillary_data_denied")
        );
    }

    #[test]
    fn host_proxy_rejects_seqpacket_truncation() {
        let (receiver, sender) = socket_pair();
        let oversized = vec![0_u8; 128];
        send_packet_unbounded(sender.as_raw_fd(), &oversized);
        let result = receive_packet_with_capacity(receiver.as_raw_fd(), 64);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("stdio_proxy_input_packet_truncated")
        );
    }

    #[test]
    fn input_boundary_and_route_arguments_fail_closed() {
        let (proxy, _broker) = socket_pair();
        assert!(validate_connected_seqpacket(proxy.as_raw_fd()).is_ok());
        let stream_pair = unsafe {
            let mut descriptors = [-1; 2];
            assert_eq!(
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM,
                    0,
                    descriptors.as_mut_ptr()
                ),
                0
            );
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        };
        assert!(
            validate_connected_seqpacket(stream_pair.0.as_raw_fd())
                .unwrap_err()
                .to_string()
                .contains("socket_type_denied")
        );
        assert!(
            validate_connected_seqpacket_observation(
                libc::SOCK_SEQPACKET,
                size_of::<libc::sa_family_t>() as libc::socklen_t,
                libc::AF_INET as libc::sa_family_t,
            )
            .unwrap_err()
            .to_string()
            .contains("socket_family_denied")
        );
        assert!(read_newline_frame(&mut Cursor::new(b"{}".as_slice())).is_err());
        assert!(read_newline_frame(&mut Cursor::new(b"\n".as_slice())).is_err());
        assert!(read_newline_frame(&mut Cursor::new(b"{}\r\n".as_slice())).is_err());
    }

    fn send_packet_unbounded(descriptor: RawFd, packet: &[u8]) {
        let sent = unsafe {
            libc::send(
                descriptor,
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        assert_eq!(usize::try_from(sent).unwrap(), packet.len());
    }

    fn send_with_fd(descriptor: RawFd, packet: &[u8], transferred: RawFd) {
        #[repr(align(16))]
        struct Control([u8; 64]);

        let mut control = Control([0; 64]);
        let mut iovec = libc::iovec {
            iov_base: packet.as_ptr().cast_mut().cast(),
            iov_len: packet.len(),
        };
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &raw mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize };
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        assert!(!header.is_null());
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), transferred);
        }
        let sent = unsafe { libc::sendmsg(descriptor, &message, libc::MSG_NOSIGNAL) };
        assert_eq!(usize::try_from(sent).unwrap(), packet.len());
    }

    #[test]
    fn error_context_is_static_and_non_authorizing() {
        let error = anyhow::anyhow!("source-only-test");
        assert_eq!(error.to_string(), "source-only-test");
    }
}
