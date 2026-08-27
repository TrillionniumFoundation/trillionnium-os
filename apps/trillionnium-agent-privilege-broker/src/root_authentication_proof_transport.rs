use thiserror::Error;
use trillionnium_os_types::capability_lease_root_authenticator::CapabilityLeaseRootPublisherAuthenticationV1;
use trillionnium_os_types::capability_lease_root_proof_carrier::{
    self as carrier, CapabilityLeaseRootProofDeliveryV1,
};

use super::replay_sync_publisher_custody::{
    ReplaySyncPublisherAuthenticationSink, ReplaySyncPublisherLaunchError,
};

pub(crate) const SOURCE_STATUS: &str =
    "source_only_single_delivery_concrete_socket_connector_no_broker_route_v2";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelPeer {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) selinux_domain: String,
}

pub(crate) trait RootProofConnection {
    fn kernel_peer(&mut self) -> Result<KernelPeer, RootProofTransportError>;
    fn write_exact_frame(&mut self, frame: &[u8]) -> Result<(), RootProofTransportError>;
    fn shutdown_write_and_require_peer_eof(&mut self) -> Result<(), RootProofTransportError>;
}

pub(crate) fn deliver_once<C: RootProofConnection>(
    authentication: CapabilityLeaseRootPublisherAuthenticationV1,
    connection: &mut C,
) -> Result<String, RootProofTransportError> {
    let first = connection.kernel_peer()?;
    require_server(&first)?;
    let delivery = CapabilityLeaseRootProofDeliveryV1::derive(authentication)
        .map_err(|_| RootProofTransportError::PayloadDenied)?;
    let frame = delivery
        .encode_frame()
        .map_err(|_| RootProofTransportError::PayloadDenied)?;
    connection.write_exact_frame(&frame)?;
    let second = connection.kernel_peer()?;
    if first != second {
        return Err(RootProofTransportError::PeerDrift);
    }
    connection.shutdown_write_and_require_peer_eof()?;
    Ok(delivery.delivery_binding_sha256)
}

pub(crate) struct RootProofAuthenticationSink<'a, C> {
    connection: &'a mut C,
}

impl<'a, C> RootProofAuthenticationSink<'a, C> {
    pub(crate) fn new(connection: &'a mut C) -> Self {
        Self { connection }
    }
}

impl<C: RootProofConnection> ReplaySyncPublisherAuthenticationSink
    for RootProofAuthenticationSink<'_, C>
{
    fn deliver(
        &mut self,
        authentication: &CapabilityLeaseRootPublisherAuthenticationV1,
    ) -> Result<(), ReplaySyncPublisherLaunchError> {
        deliver_once(authentication.clone(), self.connection)
            .map(|_| ())
            .map_err(|_| ReplaySyncPublisherLaunchError::AuthenticationDeliveryDenied)
    }
}

fn require_server(peer: &KernelPeer) -> Result<(), RootProofTransportError> {
    if peer.uid != carrier::SERVER_UID
        || peer.gid != carrier::SERVER_GID
        || peer.selinux_domain != carrier::SERVER_SELINUX_DOMAIN
    {
        return Err(RootProofTransportError::PeerDenied);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum RootProofTransportError {
    #[error("root proof payload denied")]
    PayloadDenied,
    #[error("root proof server peer denied")]
    PeerDenied,
    #[error("root proof server peer drifted")]
    PeerDrift,
    #[error("root proof transport failed")]
    TransportFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use trillionnium_os_types::capability_lease_root_authenticator::{self as authenticator};

    fn authentication() -> CapabilityLeaseRootPublisherAuthenticationV1 {
        serde_json::from_str(&format!(
            r#"{{"authentication_schema":"{}","root_authenticator_contract_sha256":"{}","root_publication_contract_sha256":"{}","root_publisher_launch_contract_sha256":"{}","provider_id":"openai-codex","agent_id":"agent-codex-direct-v1","replay_namespace":"agent-codex-v1","boot_id_sha256":"{}","publisher_pid":42,"publisher_start_time_ticks":99,"publisher_uid":5901,"publisher_gid":5901,"publisher_selinux_domain":"{}","publisher_executable_identity":"{}","publisher_executable_sha256":"{}","pidfd_identity_sha256":"{}","publication_binding_sha256":"14aa78a5bd303ca3cda70906298062a7ad4963005398ca456673899f2294a10d","registration_binding_sha256":"ac4ff17cb0f22710e90a0d34f5caae7805582162a50ad2ca3c7dc15797f31603","publisher_epoch":"{}","publisher_sequence":1,"root_journal_genesis_sha256":"{}","epoch_proof_sha256":"{}","root_record_sha256":"{}","root_record_proof_sha256":"{}","authentication_binding_sha256":"b6cb97987f06f48d4f0f53af2ae2957213bf7272119ddce6075236aa11d0c65b"}}"#,
            authenticator::AUTHENTICATION_SCHEMA,
            authenticator::CONTRACT_SHA256,
            trillionnium_os_types::capability_lease_root_publication::CONTRACT_SHA256,
            trillionnium_os_types::capability_lease_root_publisher_launch::CONTRACT_SHA256,
            "1".repeat(64),
            trillionnium_os_types::capability_lease_root_publisher_launch::PUBLISHER_SELINUX_DOMAIN,
            trillionnium_os_types::capability_lease_root_publisher_launch::PUBLISHER_EXECUTABLE_IDENTITY,
            "7".repeat(64), "a".repeat(64), "e".repeat(32), "2".repeat(64),
            "3".repeat(64), "8".repeat(64), "9".repeat(64)
        ))
        .unwrap()
    }

    struct Connection {
        peers: Vec<KernelPeer>,
        frame: Vec<u8>,
        eof: bool,
    }

    impl RootProofConnection for Connection {
        fn kernel_peer(&mut self) -> Result<KernelPeer, RootProofTransportError> {
            if self.peers.is_empty() {
                return Err(RootProofTransportError::TransportFailed);
            }
            Ok(self.peers.remove(0))
        }

        fn write_exact_frame(&mut self, frame: &[u8]) -> Result<(), RootProofTransportError> {
            self.frame.extend_from_slice(frame);
            Ok(())
        }

        fn shutdown_write_and_require_peer_eof(&mut self) -> Result<(), RootProofTransportError> {
            self.eof = true;
            Ok(())
        }
    }

    fn server() -> KernelPeer {
        KernelPeer {
            uid: carrier::SERVER_UID,
            gid: carrier::SERVER_GID,
            selinux_domain: carrier::SERVER_SELINUX_DOMAIN.to_string(),
        }
    }

    #[test]
    fn one_exact_delivery_authenticates_server_twice() {
        let mut connection = Connection {
            peers: vec![server(), server()],
            frame: Vec::new(),
            eof: false,
        };
        let binding = deliver_once(authentication(), &mut connection).unwrap();
        assert_eq!(
            CapabilityLeaseRootProofDeliveryV1::decode_frame(&connection.frame)
                .unwrap()
                .delivery_binding_sha256,
            binding
        );
        assert!(connection.eof);
    }

    #[test]
    fn wrong_or_drifting_server_fails_closed() {
        let mut wrong = server();
        wrong.uid += 1;
        let mut connection = Connection {
            peers: vec![wrong],
            frame: Vec::new(),
            eof: false,
        };
        assert_eq!(
            deliver_once(authentication(), &mut connection).unwrap_err(),
            RootProofTransportError::PeerDenied
        );
        let mut drift = server();
        drift.selinux_domain.push_str("-drift");
        let mut connection = Connection {
            peers: vec![server(), drift],
            frame: Vec::new(),
            eof: false,
        };
        assert_eq!(
            deliver_once(authentication(), &mut connection).unwrap_err(),
            RootProofTransportError::PeerDrift
        );
    }
}
