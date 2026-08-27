//! Standalone, non-product source closure for an OS-owned typed exec/ADB broker.
//!
//! The wire contract and closed descriptors are public data. The effect core,
//! its backend seam, and admission authority remain crate-private: no product
//! policy constructor, listener, Android package, or live backend exists in
//! this checkpoint. Parsing any public value therefore cannot mint authority.

mod broker;
mod durable;
mod local_uds;
pub mod protocol;

use std::convert::Infallible;

pub const SOURCE_PROTOCOL_IMPLEMENTED: bool = true;
pub const SOURCE_BROKER_STATE_MACHINE_IMPLEMENTED: bool = true;
pub const USERDEBUG_READ_ONLY_TYPED_EXEC_FIXTURE_CLOSURE_IMPLEMENTED: bool = true;
pub const HOST_DURABLE_REPLAY_LEDGER_CORE_IMPLEMENTED: bool = true;
pub const HOST_AUTHENTICATED_LOCAL_UDS_CORE_IMPLEMENTED: bool = true;
pub const HOST_GETPROP_EXECUTION_BACKEND_AVAILABLE: bool = false;
pub const USERDEBUG_TYPED_ADB_LIVE_BACKEND_AVAILABLE: bool = false;
pub const PRODUCT_LISTENER_WIRED: bool = false;
pub const PRODUCT_DURABLE_LEDGER_WIRED: bool = false;
pub const PRODUCT_SELINUX_CGROUP_SECCOMP_INSTALLED: bool = false;
pub const PRODUCT_EFFECT_AUTHORITY_AVAILABLE: bool = false;
pub const CONFERS_PRODUCT_EFFECT_AUTHORITY: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("typed exec/ADB product authority is unavailable")]
pub struct ProductAuthorityUnavailable;

/// There is no success value and no alternate constructor. Product promotion
/// must add an authenticated listener, provisioned catalog, durable ledger,
/// backend custody, and installed Android policy as a separate reviewed step.
pub fn require_product_authority() -> Result<Infallible, ProductAuthorityUnavailable> {
    Err(ProductAuthorityUnavailable)
}

/// Typed ADB remains descriptor/protocol-only even in the standalone
/// userdebug lane. No local adbd target, key, or transport can be acquired.
pub fn require_userdebug_typed_adb_backend() -> Result<Infallible, ProductAuthorityUnavailable> {
    Err(ProductAuthorityUnavailable)
}
