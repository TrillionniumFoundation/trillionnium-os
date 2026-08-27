use thiserror::Error;
use trillionnium_os_types::capability_lease_root_publication::CapabilityLeaseRootTaskPublicationV1;
use trillionnium_os_types::capability_lease_root_route_transport::{
    self as transport, CapabilityLeaseRootRouteCompletionV1, CapabilityLeaseRootRouteRequestV1,
    CapabilityLeaseRootRouteResponseV1,
};

use super::root_publisher_route;

pub(crate) const SOURCE_STATUS: &str =
    "source_only_injected_private_route_transport_no_listener_no_main_dispatch_v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelPeer {
    pub(crate) pid: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) selinux_domain: String,
}

pub(crate) trait RootRouteConnection {
    fn kernel_peer(&mut self) -> Result<KernelPeer, RootRouteTransportError>;
    fn read_exact_request_to_eof(&mut self) -> Result<Vec<u8>, RootRouteTransportError>;
    fn write_exact_response_and_require_peer_eof(
        &mut self,
        frame: &[u8],
    ) -> Result<(), RootRouteTransportError>;
}

pub(crate) trait RootPublicationResolver {
    fn resolve_once(
        &mut self,
        request: &CapabilityLeaseRootRouteRequestV1,
    ) -> Result<CapabilityLeaseRootTaskPublicationV1, RootRouteTransportError>;
}

pub(crate) trait RootPublisherRouteExecutor {
    fn run_once(
        &mut self,
        publication: &CapabilityLeaseRootTaskPublicationV1,
    ) -> Result<CapabilityLeaseRootRouteCompletionV1, RootRouteTransportError>;
}

pub(crate) struct ConcreteRootPublisherRouteExecutor;

impl RootPublisherRouteExecutor for ConcreteRootPublisherRouteExecutor {
    fn run_once(
        &mut self,
        publication: &CapabilityLeaseRootTaskPublicationV1,
    ) -> Result<CapabilityLeaseRootRouteCompletionV1, RootRouteTransportError> {
        let completed = root_publisher_route::run_source_disabled_once(publication)
            .map_err(|_| RootRouteTransportError::ExecutionDenied)?;
        Ok(CapabilityLeaseRootRouteCompletionV1 {
            publication_binding_sha256: completed.publication_binding_sha256,
            registration_binding_sha256: completed.registration_binding_sha256,
            token_record_sha256: completed.token_record_sha256,
            root_record_sha256: completed.root_record_sha256,
            root_record_proof_sha256: completed.root_record_proof_sha256,
            ack_binding_sha256: completed.ack_binding_sha256,
            authentication_binding_sha256: completed.authentication_binding_sha256,
        })
    }
}

pub(crate) fn serve_source_disabled_once<
    C: RootRouteConnection,
    R: RootPublicationResolver,
    E: RootPublisherRouteExecutor,
>(
    connection: &mut C,
    resolver: &mut R,
    executor: &mut E,
) -> Result<(), RootRouteTransportError> {
    let first = connection.kernel_peer()?;
    require_system_server(&first)?;
    let request_frame = connection.read_exact_request_to_eof()?;
    let second = connection.kernel_peer()?;
    if first != second {
        return Err(RootRouteTransportError::PeerDriftDenied);
    }
    let request = CapabilityLeaseRootRouteRequestV1::decode_frame(&request_frame)
        .map_err(|_| RootRouteTransportError::RequestDenied)?;
    let publication = resolver.resolve_once(&request)?;
    require_exact_publication(&request, &publication)?;
    let completion = executor.run_once(&publication)?;
    let response = CapabilityLeaseRootRouteResponseV1::derive(&request, completion)
        .map_err(|_| RootRouteTransportError::ResponseDenied)?;
    let third = connection.kernel_peer()?;
    if second != third {
        return Err(RootRouteTransportError::PeerDriftDenied);
    }
    connection.write_exact_response_and_require_peer_eof(
        &response
            .encode_frame()
            .map_err(|_| RootRouteTransportError::ResponseDenied)?,
    )?;
    let fourth = connection.kernel_peer()?;
    if third != fourth {
        return Err(RootRouteTransportError::PeerDriftDenied);
    }
    Ok(())
}

fn require_system_server(peer: &KernelPeer) -> Result<(), RootRouteTransportError> {
    if peer.pid <= 1
        || peer.uid != transport::CLIENT_UID
        || peer.gid != transport::CLIENT_GID
        || peer.selinux_domain != transport::CLIENT_SELINUX_DOMAIN
    {
        return Err(RootRouteTransportError::PeerDenied);
    }
    Ok(())
}

fn require_exact_publication(
    request: &CapabilityLeaseRootRouteRequestV1,
    publication: &CapabilityLeaseRootTaskPublicationV1,
) -> Result<(), RootRouteTransportError> {
    publication
        .validate()
        .map_err(|_| RootRouteTransportError::PublicationDenied)?;
    let registration = &publication.registration;
    if registration.provider_id != request.provider_id
        || registration.agent_id != request.agent_id
        || registration.replay_namespace != request.replay_namespace
        || registration.boot_id_sha256 != request.boot_id_sha256
        || registration.registration_binding_sha256 != request.registration_binding_sha256
    {
        return Err(RootRouteTransportError::PublicationDenied);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum RootRouteTransportError {
    #[error("root route peer denied")]
    PeerDenied,
    #[error("root route peer drift denied")]
    PeerDriftDenied,
    #[error("root route request denied")]
    RequestDenied,
    #[error("root route publication denied")]
    PublicationDenied,
    #[error("root route execution denied")]
    ExecutionDenied,
    #[error("root route response denied")]
    ResponseDenied,
    #[error("root route transport denied")]
    TransportDenied,
}

#[cfg(test)]
mod tests {
    use super::*;
    use trillionnium_os_types::agent_descriptor_registry::CODEX;
    use trillionnium_os_types::capability_lease_root_publication::{
        CapabilityLeaseRootPublisherTransportPeerV1, CapabilityLeaseRootTaskPublicationV1,
    };
    use trillionnium_os_types::capability_lease_root_publisher_launch as launch;
    use trillionnium_os_types::capability_lease_root_registration::{
        CapabilityLeaseRootPublisherEvidenceV1, CapabilityLeaseRootTaskContextV1,
        CapabilityLeaseRootTaskRegistrationV1,
    };

    fn publication() -> CapabilityLeaseRootTaskPublicationV1 {
        let registration = CapabilityLeaseRootTaskRegistrationV1::derive(
            CODEX.provider_id.to_string(),
            CODEX.agent_id.to_string(),
            CODEX.replay_namespace.to_string(),
            CapabilityLeaseRootPublisherEvidenceV1 {
                boot_id_sha256: "1".repeat(64),
                publisher_epoch: "e".repeat(32),
                publisher_sequence: 1,
                root_journal_genesis_sha256: "2".repeat(64),
                epoch_proof_sha256: "3".repeat(64),
            },
            CapabilityLeaseRootTaskContextV1 {
                opaque_task_context_token: format!("task-context-{}", "2".repeat(64)),
                prepare_request_id: "prepare-token-registry".to_string(),
                prepare_canonical_request_sha256: "4".repeat(64),
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
                uid: CODEX.uid,
                gid: CODEX.gid,
                selinux_domain: launch::PUBLISHER_SELINUX_DOMAIN.to_string(),
                executable_identity: launch::PUBLISHER_EXECUTABLE_IDENTITY.to_string(),
                executable_sha256: "7".repeat(64),
            },
            registration,
            "8".repeat(64),
            "9".repeat(64),
        )
        .unwrap()
    }

    fn request(
        publication: &CapabilityLeaseRootTaskPublicationV1,
    ) -> CapabilityLeaseRootRouteRequestV1 {
        CapabilityLeaseRootRouteRequestV1::derive(
            publication.registration.provider_id.clone(),
            publication.registration.agent_id.clone(),
            publication.registration.replay_namespace.clone(),
            publication.registration.boot_id_sha256.clone(),
            publication.registration.registration_binding_sha256.clone(),
        )
        .unwrap()
    }

    struct Connection {
        peers: Vec<KernelPeer>,
        request: Vec<u8>,
        response: Vec<u8>,
    }

    impl RootRouteConnection for Connection {
        fn kernel_peer(&mut self) -> Result<KernelPeer, RootRouteTransportError> {
            if self.peers.is_empty() {
                return Err(RootRouteTransportError::TransportDenied);
            }
            Ok(self.peers.remove(0))
        }

        fn read_exact_request_to_eof(&mut self) -> Result<Vec<u8>, RootRouteTransportError> {
            Ok(self.request.clone())
        }

        fn write_exact_response_and_require_peer_eof(
            &mut self,
            frame: &[u8],
        ) -> Result<(), RootRouteTransportError> {
            self.response = frame.to_vec();
            Ok(())
        }
    }

    struct Resolver(CapabilityLeaseRootTaskPublicationV1);

    impl RootPublicationResolver for Resolver {
        fn resolve_once(
            &mut self,
            _: &CapabilityLeaseRootRouteRequestV1,
        ) -> Result<CapabilityLeaseRootTaskPublicationV1, RootRouteTransportError> {
            Ok(self.0.clone())
        }
    }

    struct Executor;

    impl RootPublisherRouteExecutor for Executor {
        fn run_once(
            &mut self,
            publication: &CapabilityLeaseRootTaskPublicationV1,
        ) -> Result<CapabilityLeaseRootRouteCompletionV1, RootRouteTransportError> {
            Ok(CapabilityLeaseRootRouteCompletionV1 {
                publication_binding_sha256: publication.publication_binding_sha256.clone(),
                registration_binding_sha256: publication
                    .registration
                    .registration_binding_sha256
                    .clone(),
                token_record_sha256: "b".repeat(64),
                root_record_sha256: publication.root_record_sha256.clone(),
                root_record_proof_sha256: publication.root_record_proof_sha256.clone(),
                ack_binding_sha256: "c".repeat(64),
                authentication_binding_sha256: "d".repeat(64),
            })
        }
    }

    fn peer() -> KernelPeer {
        KernelPeer {
            pid: 42,
            uid: transport::CLIENT_UID,
            gid: transport::CLIENT_GID,
            selinux_domain: transport::CLIENT_SELINUX_DOMAIN.to_string(),
        }
    }

    #[test]
    fn one_exact_private_exchange_returns_commitments_only() {
        let publication = publication();
        let request = request(&publication);
        let mut connection = Connection {
            peers: vec![peer(), peer(), peer(), peer()],
            request: request.encode_frame().unwrap(),
            response: Vec::new(),
        };
        serve_source_disabled_once(&mut connection, &mut Resolver(publication), &mut Executor)
            .unwrap();
        let response =
            CapabilityLeaseRootRouteResponseV1::decode_frame_for(&connection.response, &request)
                .unwrap();
        assert_eq!(response.token_record_sha256, "b".repeat(64));
        let encoded = String::from_utf8(connection.response[4..].to_vec()).unwrap();
        assert!(!encoded.contains("opaque_task_context_token"));
        assert!(!encoded.contains("task.token-registry"));
    }

    #[test]
    fn peer_drift_and_resolver_substitution_fail_before_response() {
        let publication = publication();
        let request = request(&publication);
        let mut drifted = peer();
        drifted.uid += 1;
        let mut connection = Connection {
            peers: vec![peer(), drifted],
            request: request.encode_frame().unwrap(),
            response: Vec::new(),
        };
        assert_eq!(
            serve_source_disabled_once(
                &mut connection,
                &mut Resolver(publication.clone()),
                &mut Executor,
            ),
            Err(RootRouteTransportError::PeerDriftDenied)
        );
        let mut substituted = publication;
        substituted.registration.registration_binding_sha256 = "f".repeat(64);
        let mut connection = Connection {
            peers: vec![peer(), peer(), peer(), peer()],
            request: request.encode_frame().unwrap(),
            response: Vec::new(),
        };
        assert_eq!(
            serve_source_disabled_once(&mut connection, &mut Resolver(substituted), &mut Executor,),
            Err(RootRouteTransportError::PublicationDenied)
        );
        assert!(connection.response.is_empty());
    }

    #[test]
    fn source_has_no_listener_main_dispatch_or_public_protocol_operation() {
        assert_eq!(
            SOURCE_STATUS,
            "source_only_injected_private_route_transport_no_listener_no_main_dispatch_v1"
        );
        let main = include_str!("main.rs");
        let protocol =
            include_str!("../../../crates/trillionnium-privilege-broker-protocol/src/lib.rs");
        assert!(!main.contains("serve_source_disabled_once("));
        assert!(!protocol.contains("run_root_publisher_once"));
        let source = include_str!("root_publisher_route_transport.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!source.contains("UnixListener"));
    }
}
