use trillionnium_os_types::capability_lease_root_publication::CapabilityLeaseRootTaskPublicationV1;

use super::linux_replay_sync_publisher_kernel::{
    complete_concrete, launch_concrete_with_fixed_proof_socket,
};
use super::replay_sync_publisher_custody::{
    CompletedReplaySyncPublisher, ReplaySyncPublisherLaunchError, ReplaySyncPublisherLaunchSpec,
};

pub(crate) const SOURCE_STATUS: &str =
    "source_only_single_internal_route_absent_from_public_broker_protocol_and_main_v1";

pub(crate) fn run_source_disabled_once(
    publication: &CapabilityLeaseRootTaskPublicationV1,
) -> Result<CompletedReplaySyncPublisher, ReplaySyncPublisherLaunchError> {
    let spec = ReplaySyncPublisherLaunchSpec::derive(publication)?;
    let (running, mut ops) = launch_concrete_with_fixed_proof_socket(spec)?;
    complete_concrete(running, &mut ops)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_remains_internal_and_absent_from_live_broker_surfaces() {
        assert_eq!(
            SOURCE_STATUS,
            "source_only_single_internal_route_absent_from_public_broker_protocol_and_main_v1"
        );
        let broker_lib = include_str!("lib.rs");
        let broker_main = include_str!("main.rs");
        let public_protocol =
            include_str!("../../../crates/trillionnium-privilege-broker-protocol/src/lib.rs");
        assert!(!broker_main.contains("run_source_disabled_once("));
        assert!(!broker_lib.contains("run_source_disabled_once("));
        assert!(!public_protocol.contains("RootPublisher"));
        assert!(!public_protocol.contains("RootPublication"));
        let contract = include_bytes!(
            "../../../crates/trillionnium-os-types/contracts/capability-lease-root-route-coordinator-v1.json"
        );
        assert_eq!(
            trillionnium_os_types::sha256_bytes(contract),
            "260b90d2677b742843abcecd7bf1ed1f5ad949629175bb07318d96eef8f805c4"
        );
    }

    #[test]
    fn route_function_has_one_fixed_launch_and_one_exact_completion() {
        let source = include_str!("root_publisher_route.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert_eq!(
            source
                .matches("launch_concrete_with_fixed_proof_socket(spec)?")
                .count(),
            1
        );
        assert_eq!(
            source
                .matches("complete_concrete(running, &mut ops)")
                .count(),
            1
        );
        assert!(!source.contains("loop {"));
        assert!(!source.contains("retry"));
    }
}
