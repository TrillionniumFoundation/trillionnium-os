#![cfg(feature = "android-product")]

use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tempfile::tempfile;
use trillionnium_shell_exec::product_ipc::{
    STANDARD_EXECUTABLE_PATHS, StandardExecutablePolicyV1, WorkerReadyV1,
    effect_dispatch_binding_sha256, receive_frame, send_frame, seqpacket_pair,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestFrame {
    schema: String,
}

#[test]
fn worker_frame_transfers_exactly_three_cloexec_descriptors() {
    let (sender, receiver) = seqpacket_pair().unwrap();
    let files = [
        tempfile().unwrap(),
        tempfile().unwrap(),
        tempfile().unwrap(),
    ];
    send_frame(
        sender.as_raw_fd(),
        &TestFrame {
            schema: "test.v1".to_string(),
        },
        &files
            .iter()
            .map(|file| file.as_raw_fd())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let received = receive_frame::<TestFrame>(receiver.as_raw_fd()).unwrap();
    assert_eq!(received.value.schema, "test.v1");
    assert_eq!(received.descriptors.len(), 3);
    for descriptor in received.descriptors {
        let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
}

#[test]
fn worker_frame_rejects_more_than_three_descriptors() {
    let (sender, _receiver) = seqpacket_pair().unwrap();
    let files: Vec<OwnedFd> = (0..4).map(|_| tempfile().unwrap().into()).collect();
    assert!(
        send_frame(
            sender.as_raw_fd(),
            &TestFrame {
                schema: "test.v1".to_string(),
            },
            &files
                .iter()
                .map(|file| file.as_raw_fd())
                .collect::<Vec<_>>(),
        )
        .is_err()
    );
}

#[test]
fn truncated_rights_are_closed_before_receive_fails() {
    let (sender, receiver) = seqpacket_pair().unwrap();
    let files = [
        tempfile().unwrap(),
        tempfile().unwrap(),
        tempfile().unwrap(),
        tempfile().unwrap(),
    ];
    let payload = br#"{"schema":"test.v1"}"#;
    let mut vector = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let rights_bytes = files.len() * std::mem::size_of::<libc::c_int>();
    let mut ancillary = vec![0_u8; unsafe { libc::CMSG_SPACE(rights_bytes as u32) as usize }];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = ancillary.len();
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(rights_bytes as u32) as _;
        std::ptr::copy_nonoverlapping(
            files
                .iter()
                .map(|file| file.as_raw_fd())
                .collect::<Vec<_>>()
                .as_ptr()
                .cast::<u8>(),
            libc::CMSG_DATA(header),
            rights_bytes,
        );
        message.msg_controllen = (*header).cmsg_len;
        assert_eq!(
            libc::sendmsg(sender.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
            payload.len() as isize
        );
    }
    let identities = files
        .iter()
        .map(|file| descriptor_identity(file.as_raw_fd()))
        .collect::<Vec<_>>();
    let before = count_matching_descriptors(&identities);
    assert!(receive_frame::<TestFrame>(receiver.as_raw_fd()).is_err());
    let after = count_matching_descriptors(&identities);
    assert_eq!(after, before);
}

fn descriptor_identity(descriptor: RawFd) -> (libc::dev_t, libc::ino_t) {
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(descriptor, &mut status) }, 0);
    (status.st_dev, status.st_ino)
}

fn count_matching_descriptors(identities: &[(libc::dev_t, libc::ino_t)]) -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<RawFd>().ok())
        .filter(|descriptor| {
            let mut status: libc::stat = unsafe { std::mem::zeroed() };
            (unsafe { libc::fstat(*descriptor, &mut status) }) == 0
                && identities.contains(&(status.st_dev, status.st_ino))
        })
        .count()
}

#[test]
fn executable_policy_accepts_exact_packager_sorted_golden_bytes() {
    let paths = [
        "/bin/echo",
        "/bin/false",
        "/bin/sleep",
        "/bin/true",
        "/bin/uname",
        "/usr/bin/id",
        "/usr/bin/printf",
    ];
    let entries = paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            serde_json::json!({
                "path": path,
                "sha256": format!("{:064x}", index + 1),
            })
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "entries": entries,
        "profile": "standard",
        "schema": "org.trillionnium.shell-exec.standard-executable-policy.v1",
    }))
    .unwrap();
    assert_eq!(bytes.len(), 793);
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "1fc833c037c732038e177fc516a8484f1d1120742809b5a0568e111eac56989e"
    );
    let policy = StandardExecutablePolicyV1::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(policy.entries.len(), 7);
    assert_eq!(paths, STANDARD_EXECUTABLE_PATHS);
    for forbidden in [
        "/bin/cat",
        "/bin/mkdir",
        "/bin/pwd",
        "/usr/bin/stat",
        "/bin/touch",
        "/usr/bin/whoami",
    ] {
        let mut rejected = policy.clone();
        rejected.entries[0].path = forbidden.to_string();
        assert!(rejected.validate().is_err(), "forbidden {forbidden}");
    }

    let mut struct_order = serde_json::to_vec(&policy).unwrap();
    assert_ne!(struct_order, bytes);
    struct_order.push(b'\n');
    assert!(StandardExecutablePolicyV1::from_canonical_bytes(&struct_order).is_err());
}

#[test]
fn dispatch_binding_changes_with_worker_instance_while_request_stays_fixed() {
    let ready = WorkerReadyV1 {
        schema: "ready".to_string(),
        protocol: "protocol".to_string(),
        pid: 41,
        process_starttime_ticks: 7_001,
        uid: 5_903,
        gid: 5_903,
        supplementary_groups: Vec::new(),
        selinux_domain: "worker".to_string(),
        worker_executable_sha256: "1".repeat(64),
        rootfs_custody_sha256: "2".repeat(64),
        dev_null_custody_sha256: "3".repeat(64),
        workspace_parent_custody_sha256: "4".repeat(64),
        temporary_parent_custody_sha256: "5".repeat(64),
        cgroup_membership_sha256: "6".repeat(64),
        cgroup_policy_sha256: "7".repeat(64),
        isolation_policy_sha256: "8".repeat(64),
        executable_policy_sha256: "9".repeat(64),
        no_new_privileges: true,
        seccomp_mode: 2,
        effective_capabilities_hex: "0000000000000000".to_string(),
        umask: 0o007,
        kernel_launch_custody_sha256: "a".repeat(64),
        backend_identity_sha256: "b".repeat(64),
    };
    let binding = |ready: &WorkerReadyV1| {
        effect_dispatch_binding_sha256(
            &"c".repeat(64),
            ready,
            &"d".repeat(64),
            "/usr/bin/printf",
            &"e".repeat(64),
            &"f".repeat(64),
            &"1".repeat(64),
            "/tmp/effect",
            &"2".repeat(64),
        )
    };
    let first = binding(&ready);
    let mut fresh_worker = ready.clone();
    fresh_worker.pid += 1;
    fresh_worker.process_starttime_ticks += 99;
    let second = binding(&fresh_worker);
    assert_ne!(first, second);
}
