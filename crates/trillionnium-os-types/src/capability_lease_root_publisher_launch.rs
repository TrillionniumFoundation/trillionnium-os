pub const CONTRACT_SCHEMA: &str =
    "org.trillionnium.capabilitylease.root-publisher-launch.contract.v1";
pub const CONTRACT_SHA256: &str =
    "1469b2f75f681b7224408e78e64ba6d2e7b7985e9c0d81a92e156147db89c9c2";
pub const SOURCE_STATUS: &str =
    "source_only_no_product_package_no_live_listener_no_effect_authority_v1";
pub const LAUNCHER_DOMAIN: &str = "u:r:trillionnium_agentd:s0";
pub const PUBLISHER_ROLE: &str = "system_api_replay_sync";
pub const PUBLISHER_EXECUTABLE_IDENTITY: &str =
    "system_ext/bin/trillionnium-system-api-replay-sync";
pub const PUBLISHER_SELINUX_DOMAIN: &str = "u:r:trillionnium_agent_system_api_replay_sync:s0";
pub const SERVER_SOCKET_NAME: &str = "trillionnium_capability_lease_root_publication";
pub const SERVER_UID: u32 = 1000;
pub const SERVER_GID: u32 = 1000;
pub const SERVER_SELINUX_DOMAIN: &str = "u:r:system_server:s0";
pub const READ_TIMEOUT_MS: u64 = 15_000;
pub const WRITE_TIMEOUT_MS: u64 = 5_000;
pub const PRODUCT_PACKAGE_AVAILABLE: bool = false;
pub const LAUNCHER_WIRED: bool = false;
pub const LISTENER_WIRED: bool = false;
pub const RUNTIME_CONSUMER_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;

    #[test]
    fn contract_hash_and_activation_flags_are_closed() {
        assert_eq!(
            crate::sha256_bytes(include_bytes!(
                "../contracts/capability-lease-root-publisher-launch-v1.json"
            )),
            CONTRACT_SHA256
        );
        assert!(!PRODUCT_PACKAGE_AVAILABLE);
        assert!(!LAUNCHER_WIRED);
        assert!(!LISTENER_WIRED);
        assert!(!RUNTIME_CONSUMER_AVAILABLE);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    }
}
