use std::io::{Read, Write};
use std::net::Shutdown;
use std::path::Path;
use std::time::Duration;

use trillionnium_os_types::agent_principal_registry;
use trillionnium_os_types::capability_lease_root_publication::{
    CapabilityLeaseRootTaskPublicationAckV1, CapabilityLeaseRootTaskPublicationV1,
    MAXIMUM_PAYLOAD_BYTES,
};
use trillionnium_os_types::capability_lease_root_publisher_launch as launch;

use crate::uds::{self, ExpectedBackendPeer};
use crate::{DirectToolError, Result};

pub const SOURCE_STATUS: &str = "source_only_binary_not_product_packaged_launcher_not_wired_v1";
pub const DEFAULT_SOCKET: &str = "@trillionnium_capability_lease_root_publication";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasuredParentStopDenied;

pub fn enter_measured_parent_stop() -> std::result::Result<(), MeasuredParentStopDenied> {
    let parent = unsafe { libc::getppid() };
    if parent <= 1
        || !has_exact_parent_tracer(parent)
        || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0
        || unsafe { libc::raise(libc::SIGSTOP) } != 0
    {
        return Err(MeasuredParentStopDenied);
    }
    Ok(())
}

fn has_exact_parent_tracer(parent: libc::pid_t) -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let mut values = status
        .lines()
        .filter_map(|line| line.strip_prefix("TracerPid:"));
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none() && value.trim().parse::<libc::pid_t>() == Ok(parent)
}

pub fn run_stdio() -> Result<()> {
    if std::env::args_os().len() != 1 || std::env::vars_os().next().is_some() {
        return Err(DirectToolError::InvalidRequest(
            "root publisher requires no arguments and an empty environment".to_string(),
        ));
    }
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let principal = agent_principal_registry::from_uid_gid(uid, gid).ok_or_else(|| {
        DirectToolError::BackendUnavailable(
            "root publisher UID/GID is not a generated stable Agent principal".to_string(),
        )
    })?;
    let security_context =
        std::fs::read_to_string("/proc/self/attr/current").map_err(DirectToolError::Io)?;
    let security_context = security_context.trim_end_matches('\0').trim_end();
    if security_context != launch::PUBLISHER_SELINUX_DOMAIN {
        return Err(DirectToolError::BackendUnavailable(
            "root publisher SELinux domain is not the fixed replay-sync domain".to_string(),
        ));
    }

    let mut stdin = std::io::stdin().lock();
    let request_frame = read_single_frame(&mut stdin)?;
    let publication = CapabilityLeaseRootTaskPublicationV1::decode_frame(&request_frame)
        .map_err(|error| DirectToolError::InvalidRequest(error.code().to_string()))?;
    if publication.registration.provider_id != principal.provider_id
        || publication.registration.agent_id != principal.agent_id
        || publication.transport_peer.uid != uid
        || publication.transport_peer.gid != gid
        || publication.transport_peer.selinux_domain != launch::PUBLISHER_SELINUX_DOMAIN
        || publication.transport_peer.executable_identity != launch::PUBLISHER_EXECUTABLE_IDENTITY
    {
        return Err(DirectToolError::InvalidRequest(
            "root publication does not match the launched replay-sync identity".to_string(),
        ));
    }
    let ack = exchange_on(Path::new(DEFAULT_SOCKET), &publication)?;
    let frame = ack
        .encode_frame()
        .map_err(|error| DirectToolError::BackendFailed(error.code().to_string()))?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&frame)?;
    stdout.flush()?;
    Ok(())
}

pub fn exchange(
    publication: &CapabilityLeaseRootTaskPublicationV1,
) -> Result<CapabilityLeaseRootTaskPublicationAckV1> {
    exchange_on(Path::new(DEFAULT_SOCKET), publication)
}

fn exchange_on(
    socket: &Path,
    publication: &CapabilityLeaseRootTaskPublicationV1,
) -> Result<CapabilityLeaseRootTaskPublicationAckV1> {
    publication
        .validate()
        .map_err(|error| DirectToolError::InvalidRequest(error.code().to_string()))?;
    let mut stream = uds::connect(socket)?;
    uds::verify_connected_peer(socket, &stream, ExpectedBackendPeer::SystemServer)?;
    stream.set_read_timeout(Some(Duration::from_millis(launch::READ_TIMEOUT_MS)))?;
    stream.set_write_timeout(Some(Duration::from_millis(launch::WRITE_TIMEOUT_MS)))?;
    let request = publication
        .encode_frame()
        .map_err(|error| DirectToolError::InvalidRequest(error.code().to_string()))?;
    stream.write_all(&request)?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)?;
    let response = read_single_frame(&mut stream)?;
    let ack = CapabilityLeaseRootTaskPublicationAckV1::decode_frame(&response)
        .map_err(|error| DirectToolError::BackendFailed(error.code().to_string()))?;
    if ack.publication_binding_sha256 != publication.publication_binding_sha256
        || ack.registration_binding_sha256 != publication.registration.registration_binding_sha256
        || ack.publisher_epoch != publication.registration.publisher_epoch
        || ack.publisher_sequence != publication.registration.publisher_sequence
        || ack.root_record_sha256 != publication.root_record_sha256
        || ack.root_record_proof_sha256 != publication.root_record_proof_sha256
    {
        return Err(DirectToolError::BackendFailed(
            "root publication ACK does not match the exact request".to_string(),
        ));
    }
    Ok(ack)
}

fn read_single_frame(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAXIMUM_PAYLOAD_BYTES {
        return Err(DirectToolError::BackendFailed(
            "root publication frame length is invalid".to_string(),
        ));
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    frame.resize(4 + length, 0);
    reader.read_exact(&mut frame[4..])?;
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(DirectToolError::BackendFailed(
            "root publication peer sent trailing bytes".to_string(),
        ));
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::thread;

    use trillionnium_os_types::agent_principal_registry::CODEX_STABLE_PRINCIPAL;
    use trillionnium_os_types::capability_lease_root_publication::{
        CapabilityLeaseRootPublisherTransportPeerV1, CapabilityLeaseRootTaskPublicationAckV1,
        CapabilityLeaseRootTaskPublicationV1,
    };
    use trillionnium_os_types::capability_lease_root_registration::{
        CapabilityLeaseRootPublisherEvidenceV1, CapabilityLeaseRootTaskContextV1,
        CapabilityLeaseRootTaskRegistrationV1,
    };

    use super::*;

    fn publication() -> CapabilityLeaseRootTaskPublicationV1 {
        let registration = CapabilityLeaseRootTaskRegistrationV1::derive(
            CODEX_STABLE_PRINCIPAL.provider_id.to_string(),
            CODEX_STABLE_PRINCIPAL.agent_id.to_string(),
            CODEX_STABLE_PRINCIPAL.replay_namespace.to_string(),
            CapabilityLeaseRootPublisherEvidenceV1 {
                boot_id_sha256: "1".repeat(64),
                publisher_epoch: "8".repeat(32),
                publisher_sequence: 10,
                root_journal_genesis_sha256: "a".repeat(64),
                epoch_proof_sha256: "b".repeat(64),
            },
            CapabilityLeaseRootTaskContextV1 {
                opaque_task_context_token: format!("task-context-{}", "2".repeat(64)),
                prepare_request_id: "prepare-token-registry".to_string(),
                prepare_canonical_request_sha256: "9".repeat(64),
                workflow_id: format!("req-{}", "4".repeat(32)),
                task_id: "task.token-registry".to_string(),
                authenticated_task_binding_sha256: "5".repeat(64),
            },
            "6".repeat(64),
        )
        .unwrap();
        CapabilityLeaseRootTaskPublicationV1::derive(
            CapabilityLeaseRootPublisherTransportPeerV1 {
                role: launch::PUBLISHER_ROLE.to_string(),
                uid: CODEX_STABLE_PRINCIPAL.uid,
                gid: CODEX_STABLE_PRINCIPAL.gid,
                selinux_domain: launch::PUBLISHER_SELINUX_DOMAIN.to_string(),
                executable_identity: launch::PUBLISHER_EXECUTABLE_IDENTITY.to_string(),
                executable_sha256: "c".repeat(64),
            },
            registration,
            "d".repeat(64),
            "e".repeat(64),
        )
        .unwrap()
    }

    #[test]
    fn one_exact_exchange_accepts_only_matching_ack() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("root-publication.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let publication = publication();
        let server_publication = publication.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_single_frame(&mut stream).unwrap();
            let decoded = CapabilityLeaseRootTaskPublicationV1::decode_frame(&request).unwrap();
            assert_eq!(decoded, server_publication);
            let ack =
                CapabilityLeaseRootTaskPublicationAckV1::derive(&decoded, "f".repeat(64)).unwrap();
            stream.write_all(&ack.encode_frame().unwrap()).unwrap();
        });
        let ack = exchange_on(&path, &publication).unwrap();
        assert_eq!(
            ack.publication_binding_sha256,
            publication.publication_binding_sha256
        );
        server.join().unwrap();
    }

    #[test]
    fn mismatched_or_trailing_ack_fails_closed() {
        let mut encoded =
            CapabilityLeaseRootTaskPublicationAckV1::derive(&publication(), "f".repeat(64))
                .unwrap()
                .encode_frame()
                .unwrap();
        encoded.push(0);
        assert!(read_single_frame(&mut encoded.as_slice()).is_err());
    }

    #[test]
    fn measured_binary_hardens_and_stops_before_stdio() {
        let binary = include_str!("bin/system_api_replay_sync.rs");
        let hardening = binary.find("enter_measured_parent_stop").unwrap();
        let transport = binary.find("run_stdio").unwrap();
        assert!(hardening < transport);
        assert!(binary.contains("std::process::exit(2)"));
    }

    #[test]
    fn untraced_test_process_cannot_enter_measured_stop() {
        assert!(!has_exact_parent_tracer(unsafe { libc::getppid() }));
    }
}
