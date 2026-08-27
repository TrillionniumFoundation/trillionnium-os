pub const CONTRACT_SCHEMA: &str = "org.trillionnium.capabilitylease.root-route-session.contract.v1";
pub const CONTRACT_SHA256: &str =
    "a1352acf879e6c4e4b83956e6998ae540227446634a6f608f087f5a99ce65338";
pub const SOURCE_STATUS: &str =
    "source_only_private_root_route_session_constructors_no_product_wiring_v1";
pub const SOURCE_AGENTD_SESSION_CONSTRUCTOR_IMPLEMENTED: bool = true;
pub const SOURCE_SYSTEM_SERVER_SESSION_CONSTRUCTOR_IMPLEMENTED: bool = true;
pub const CROSS_PROCESS_STARTUP_ORCHESTRATOR_AVAILABLE: bool = false;
pub const PUBLIC_BROKER_PROTOCOL_EXTENDED: bool = false;
pub const BROKER_MAIN_ROUTE_WIRED: bool = false;
pub const SYSTEM_SERVER_RUNTIME_FACTORY_WIRED: bool = false;
pub const PRODUCT_STARTUP_WIRED: bool = false;
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
                "../contracts/capability-lease-root-route-session-v1.json"
            )),
            CONTRACT_SHA256
        );
        assert!(SOURCE_AGENTD_SESSION_CONSTRUCTOR_IMPLEMENTED);
        assert!(SOURCE_SYSTEM_SERVER_SESSION_CONSTRUCTOR_IMPLEMENTED);
        assert!(!CROSS_PROCESS_STARTUP_ORCHESTRATOR_AVAILABLE);
        assert!(!PUBLIC_BROKER_PROTOCOL_EXTENDED);
        assert!(!BROKER_MAIN_ROUTE_WIRED);
        assert!(!SYSTEM_SERVER_RUNTIME_FACTORY_WIRED);
        assert!(!PRODUCT_STARTUP_WIRED);
        assert!(!TOKEN_MUTATION_AVAILABLE);
        assert!(!CONFERS_ACK_AUTHORITY);
        assert!(!CONFERS_LEASE_TRUST);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    }
}
