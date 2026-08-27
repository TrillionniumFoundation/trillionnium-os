pub const CONTRACT_SCHEMA: &str =
    "org.trillionnium.capabilitylease.root-route-socket-custody.contract.v1";
pub const CONTRACT_SHA256: &str =
    "1b275c7956a325f767d037ec0ce578a6dbb078ec42f71ef25a1097b8cf957930";
pub const SOURCE_STATUS: &str =
    "source_only_concrete_private_route_listener_connector_no_product_wiring_v1";
pub const SOURCE_LISTENER_IMPLEMENTED: bool = true;
pub const SOURCE_CONNECTOR_IMPLEMENTED: bool = true;
pub const PUBLIC_BROKER_PROTOCOL_EXTENDED: bool = false;
pub const LISTENER_PRODUCT_WIRED: bool = false;
pub const CONNECTOR_PRODUCT_WIRED: bool = false;
pub const BROKER_MAIN_ROUTE_WIRED: bool = false;
pub const COORDINATOR_ROUTE_ADAPTER_WIRED: bool = false;
pub const RUNTIME_CONSTRUCTOR_AVAILABLE: bool = false;
pub const TOKEN_MUTATION_AVAILABLE: bool = false;
pub const CONFERS_ACK_AUTHORITY: bool = false;
pub const CONFERS_LEASE_TRUST: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    #[test]
    fn contract_hash_and_product_authority_are_exact() {
        assert_eq!(
            crate::sha256_bytes(include_bytes!(
                "../contracts/capability-lease-root-route-socket-custody-v1.json"
            )),
            CONTRACT_SHA256
        );
        assert!(SOURCE_LISTENER_IMPLEMENTED);
        assert!(SOURCE_CONNECTOR_IMPLEMENTED);
        assert!(!PUBLIC_BROKER_PROTOCOL_EXTENDED);
        assert!(!LISTENER_PRODUCT_WIRED);
        assert!(!CONNECTOR_PRODUCT_WIRED);
        assert!(!BROKER_MAIN_ROUTE_WIRED);
        assert!(!COORDINATOR_ROUTE_ADAPTER_WIRED);
        assert!(!RUNTIME_CONSTRUCTOR_AVAILABLE);
        assert!(!TOKEN_MUTATION_AVAILABLE);
        assert!(!CONFERS_ACK_AUTHORITY);
        assert!(!CONFERS_LEASE_TRUST);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    }
}
