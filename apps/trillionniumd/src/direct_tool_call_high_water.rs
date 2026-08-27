//! Fixed-boundary external high-water authority for Direct tool-call allocation.
//!
//! This module is a pre-effect admission primitive.  The product transport is
//! one compile-time-fixed OS-owned Unix socket.  It authenticates the socket
//! inode, root peer credentials and the exact authority SELinux domain before
//! exchanging closed, canonical, challenge-bound records.  No caller path,
//! environment variable, boolean, serialized proof or digest can construct a
//! verified session.
//!
//! The move-only state machine is:
//!
//! `reconcile -> observe -> prepare -> local durable commit -> authority commit
//! -> reconcile`.
//!
//! A transport/protocol outcome that is not exact consumes the current state
//! and returns no replacement capability.  The external authority contract
//! requires an indeterminate prepare, commit or reconcile to enter its durable
//! permanent-HOLD state.  Reconciliation handles only known process-crash
//! boundaries around an already acknowledged PREPARE; it never converts an
//! indeterminate authority call into success.
//!
//! Nothing here creates provider-delivery, Android epoch, replay-ACK, outer-ACK
//! or effect authority, and `trillionniumd` main does not instantiate it.

use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trillionnium_os_types::direct_operation::DirectOperationAdapter;

pub(crate) const FIXED_AUTHORITY_SOCKET_PATH: &str =
    "/run/trillionnium/direct-operation-tool-call-high-water-v1.sock";
const FIXED_AUTHORITY_UID: u32 = 0;
const FIXED_AUTHORITY_GID: u32 = 0;
const FIXED_AUTHORITY_SOCKET_MODE: u32 = 0o600;
const FIXED_AUTHORITY_SELINUX_DOMAIN: &str = "u:r:trillionnium_direct_operation_high_water:s0";
const FIXED_AUTHORITY_IDENTITY_SHA256: &str =
    "d993870b654e840318b4cb4de7d424874480605a05194b25c50abb4e0ed2b27a";

const PROTOCOL: &str = "trillionnium.direct-tool-call-high-water.v1";
const ROUTE_SCHEMA: &str = "trillionnium.direct-tool-call-high-water-route.v1";
const HEAD_SCHEMA: &str = "trillionnium.direct-tool-call-high-water-head.v1";
const REQUEST_SCHEMA: &str = "trillionnium.direct-tool-call-high-water-request.v1";
const RESPONSE_SCHEMA: &str = "trillionnium.direct-tool-call-high-water-response.v1";
const ROUTE_DOMAIN: &[u8] = b"trillionnium.direct-tool-call-high-water-route.v1";
const TRANSACTION_DOMAIN: &[u8] = b"trillionnium.direct-tool-call-high-water-transition.v1";
const REQUEST_DOMAIN: &[u8] = b"trillionnium.direct-tool-call-high-water-request.v1";
const RESPONSE_DOMAIN: &[u8] = b"trillionnium.direct-tool-call-high-water-response.v1";
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_FRAME_BYTES: usize = 64 * 1024;
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectToolCallHighWaterRouteV1 {
    schema: String,
    protocol: String,
    binding_sha256: String,
    provider_id: String,
    agent_id: String,
    adapter: DirectOperationAdapter,
    route_sha256: String,
}

impl DirectToolCallHighWaterRouteV1 {
    pub(crate) fn derive(
        binding_sha256: String,
        provider_id: String,
        agent_id: String,
        adapter: DirectOperationAdapter,
    ) -> Result<Self> {
        let mut route = Self {
            schema: ROUTE_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            binding_sha256,
            provider_id,
            agent_id,
            adapter,
            route_sha256: String::new(),
        };
        route.route_sha256 = route.expected_sha256()?;
        route.validate()?;
        Ok(route)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != ROUTE_SCHEMA
            || self.protocol != PROTOCOL
            || !valid_nonzero_sha256(&self.binding_sha256)
            || self.provider_id.is_empty()
            || self.agent_id.is_empty()
            || self.expected_sha256()? != self.route_sha256
        {
            bail!("direct_tool_call_high_water_route_denied");
        }
        Ok(())
    }

    fn expected_sha256(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            protocol: &'a str,
            binding_sha256: &'a str,
            provider_id: &'a str,
            agent_id: &'a str,
            adapter: DirectOperationAdapter,
        }
        domain_digest(
            ROUTE_DOMAIN,
            &Preimage {
                schema: &self.schema,
                protocol: &self.protocol,
                binding_sha256: &self.binding_sha256,
                provider_id: &self.provider_id,
                agent_id: &self.agent_id,
                adapter: self.adapter,
            },
        )
    }

    pub(crate) fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }

    pub(crate) fn adapter(&self) -> DirectOperationAdapter {
        self.adapter
    }

    pub(crate) fn route_sha256(&self) -> &str {
        &self.route_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectToolCallHighWaterHeadV1 {
    schema: String,
    generation: u64,
    allocator_store_sha256: String,
}

impl DirectToolCallHighWaterHeadV1 {
    pub(crate) fn new(generation: u64, allocator_store_sha256: String) -> Result<Self> {
        let head = Self {
            schema: HEAD_SCHEMA.to_string(),
            generation,
            allocator_store_sha256,
        };
        head.validate()?;
        Ok(head)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != HEAD_SCHEMA
            || (self.generation == 0 && self.allocator_store_sha256 != ZERO_SHA256)
            || (self.generation > 0 && !valid_nonzero_sha256(&self.allocator_store_sha256))
        {
            bail!("direct_tool_call_high_water_head_denied");
        }
        Ok(())
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn allocator_store_sha256(&self) -> &str {
        &self.allocator_store_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthorityOperation {
    Reconcile,
    Observe,
    Prepare,
    Commit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuthorityDisposition {
    ReconciledExact,
    ObservedExact,
    PreparedExact,
    CommittedExact,
    PermanentHold,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityRequestV1 {
    schema: String,
    protocol: String,
    operation: AuthorityOperation,
    route: DirectToolCallHighWaterRouteV1,
    current_head: DirectToolCallHighWaterHeadV1,
    proposed_head: Option<DirectToolCallHighWaterHeadV1>,
    transition_sha256: Option<String>,
    request_nonce_sha256: String,
    request_sha256: String,
}

impl AuthorityRequestV1 {
    fn build(
        operation: AuthorityOperation,
        route: DirectToolCallHighWaterRouteV1,
        current_head: DirectToolCallHighWaterHeadV1,
        proposed_head: Option<DirectToolCallHighWaterHeadV1>,
        transition_sha256: Option<String>,
        request_nonce_sha256: String,
    ) -> Result<Self> {
        let mut request = Self {
            schema: REQUEST_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation,
            route,
            current_head,
            proposed_head,
            transition_sha256,
            request_nonce_sha256,
            request_sha256: String::new(),
        };
        request.request_sha256 = request.expected_sha256()?;
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<()> {
        self.route.validate()?;
        self.current_head.validate()?;
        if let Some(proposed) = &self.proposed_head {
            proposed.validate()?;
        }
        let transition_shape = match self.operation {
            AuthorityOperation::Reconcile | AuthorityOperation::Observe => {
                self.proposed_head.is_none() && self.transition_sha256.is_none()
            }
            AuthorityOperation::Prepare => {
                let Some(proposed) = self.proposed_head.as_ref() else {
                    return Err(anyhow!("direct_tool_call_high_water_prepare_shape_denied"));
                };
                let Some(expected_generation) = self.current_head.generation.checked_add(1) else {
                    return Err(anyhow!(
                        "direct_tool_call_high_water_generation_exhausted_permanent_hold"
                    ));
                };
                proposed.generation == expected_generation
                    && proposed.allocator_store_sha256 != self.current_head.allocator_store_sha256
                    && self.transition_sha256.as_deref()
                        == Some(
                            transition_sha256(&self.route, &self.current_head, proposed)?.as_str(),
                        )
            }
            AuthorityOperation::Commit => {
                self.proposed_head.as_ref() == Some(&self.current_head)
                    && self
                        .transition_sha256
                        .as_deref()
                        .is_some_and(valid_nonzero_sha256)
            }
        };
        if self.schema != REQUEST_SCHEMA
            || self.protocol != PROTOCOL
            || !transition_shape
            || !valid_nonzero_sha256(&self.request_nonce_sha256)
            || self.expected_sha256()? != self.request_sha256
        {
            bail!("direct_tool_call_high_water_request_denied");
        }
        Ok(())
    }

    fn expected_sha256(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            protocol: &'a str,
            operation: AuthorityOperation,
            route: &'a DirectToolCallHighWaterRouteV1,
            current_head: &'a DirectToolCallHighWaterHeadV1,
            proposed_head: &'a Option<DirectToolCallHighWaterHeadV1>,
            transition_sha256: &'a Option<String>,
            request_nonce_sha256: &'a str,
        }
        domain_digest(
            REQUEST_DOMAIN,
            &Preimage {
                schema: &self.schema,
                protocol: &self.protocol,
                operation: self.operation,
                route: &self.route,
                current_head: &self.current_head,
                proposed_head: &self.proposed_head,
                transition_sha256: &self.transition_sha256,
                request_nonce_sha256: &self.request_nonce_sha256,
            },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityResponseV1 {
    schema: String,
    protocol: String,
    operation: AuthorityOperation,
    disposition: AuthorityDisposition,
    authority_identity_sha256: String,
    route_sha256: String,
    request_sha256: String,
    committed_head: DirectToolCallHighWaterHeadV1,
    transition_sha256: Option<String>,
    response_sha256: String,
}

impl AuthorityResponseV1 {
    fn validate_for(&self, request: &AuthorityRequestV1) -> Result<()> {
        self.committed_head.validate()?;
        if self.schema != RESPONSE_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != request.operation
            || self.authority_identity_sha256 != FIXED_AUTHORITY_IDENTITY_SHA256
            || self.route_sha256 != request.route.route_sha256
            || self.request_sha256 != request.request_sha256
            || self.expected_sha256()? != self.response_sha256
        {
            bail!("direct_tool_call_high_water_response_binding_denied");
        }
        if self.disposition == AuthorityDisposition::PermanentHold {
            bail!("direct_tool_call_high_water_authority_permanent_hold");
        }
        let exact = match request.operation {
            AuthorityOperation::Reconcile => {
                self.disposition == AuthorityDisposition::ReconciledExact
                    && self.committed_head == request.current_head
                    && self.transition_sha256.is_none()
            }
            AuthorityOperation::Observe => {
                self.disposition == AuthorityDisposition::ObservedExact
                    && self.committed_head == request.current_head
                    && self.transition_sha256.is_none()
            }
            AuthorityOperation::Prepare => {
                self.disposition == AuthorityDisposition::PreparedExact
                    && self.committed_head == request.current_head
                    && self.transition_sha256 == request.transition_sha256
            }
            AuthorityOperation::Commit => {
                self.disposition == AuthorityDisposition::CommittedExact
                    && self.committed_head == request.current_head
                    && self.transition_sha256 == request.transition_sha256
            }
        };
        if !exact {
            bail!("direct_tool_call_high_water_response_state_denied");
        }
        Ok(())
    }

    fn expected_sha256(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            protocol: &'a str,
            operation: AuthorityOperation,
            disposition: AuthorityDisposition,
            authority_identity_sha256: &'a str,
            route_sha256: &'a str,
            request_sha256: &'a str,
            committed_head: &'a DirectToolCallHighWaterHeadV1,
            transition_sha256: &'a Option<String>,
        }
        domain_digest(
            RESPONSE_DOMAIN,
            &Preimage {
                schema: &self.schema,
                protocol: &self.protocol,
                operation: self.operation,
                disposition: self.disposition,
                authority_identity_sha256: &self.authority_identity_sha256,
                route_sha256: &self.route_sha256,
                request_sha256: &self.request_sha256,
                committed_head: &self.committed_head,
                transition_sha256: &self.transition_sha256,
            },
        )
    }
}

trait AuthorityTransport: Send {
    fn exchange(&mut self, request: &AuthorityRequestV1) -> Result<AuthorityResponseV1>;
}

/// Move-only freshly observed external high-water capability.
///
/// It deliberately has no `Clone`, `Serialize`, raw-record constructor or
/// public fields.  Its retained authenticated transport is the authority.
#[must_use = "verified high-water custody must be consumed by the allocator"]
pub(crate) struct VerifiedDirectToolCallHighWater {
    transport: Box<dyn AuthorityTransport>,
    route: DirectToolCallHighWaterRouteV1,
    committed_head: DirectToolCallHighWaterHeadV1,
}

#[must_use = "a prepared high-water transition must be resolved exactly"]
pub(crate) struct PreparedDirectToolCallHighWater {
    transport: Box<dyn AuthorityTransport>,
    route: DirectToolCallHighWaterRouteV1,
    from_head: DirectToolCallHighWaterHeadV1,
    to_head: DirectToolCallHighWaterHeadV1,
    transition_sha256: String,
}

#[must_use = "a committed authority response must be reconciled before reuse"]
pub(crate) struct CommittedDirectToolCallHighWater {
    transport: Box<dyn AuthorityTransport>,
    route: DirectToolCallHighWaterRouteV1,
    committed_head: DirectToolCallHighWaterHeadV1,
}

impl VerifiedDirectToolCallHighWater {
    pub(crate) fn connect_product(
        route: DirectToolCallHighWaterRouteV1,
        local_head: DirectToolCallHighWaterHeadV1,
    ) -> Result<Self> {
        let transport = FixedPathAuthorityTransport::connect()?;
        establish(Box::new(transport), route, local_head)
    }

    pub(crate) fn route(&self) -> &DirectToolCallHighWaterRouteV1 {
        &self.route
    }

    pub(crate) fn committed_head(&self) -> &DirectToolCallHighWaterHeadV1 {
        &self.committed_head
    }

    /// Fresh OBSERVE followed by PREPARE.  Either exact response is required;
    /// all other outcomes consume `self` and return no capability.
    pub(crate) fn prepare(
        mut self,
        to_head: DirectToolCallHighWaterHeadV1,
    ) -> Result<PreparedDirectToolCallHighWater> {
        to_head.validate()?;
        let observed = request_exact(
            self.transport.as_mut(),
            AuthorityOperation::Observe,
            &self.route,
            &self.committed_head,
            None,
            None,
        )?;
        // `request_exact` already checked the hidden challenge and complete
        // response binding. Retaining this comparison makes the typestate
        // dependency explicit without exposing the nonce as capability data.
        if observed.committed_head != self.committed_head {
            bail!("direct_tool_call_high_water_observe_drift_denied");
        }
        let transition = transition_sha256(&self.route, &self.committed_head, &to_head)?;
        request_exact(
            self.transport.as_mut(),
            AuthorityOperation::Prepare,
            &self.route,
            &self.committed_head,
            Some(to_head.clone()),
            Some(transition.clone()),
        )?;
        Ok(PreparedDirectToolCallHighWater {
            transport: self.transport,
            route: self.route,
            from_head: self.committed_head,
            to_head,
            transition_sha256: transition,
        })
    }
}

impl PreparedDirectToolCallHighWater {
    /// Commit only after the caller proves its durable local head is the exact
    /// prepared successor.  A missing/invalid response returns no capability.
    pub(crate) fn commit(
        mut self,
        durable_local_head: &DirectToolCallHighWaterHeadV1,
    ) -> Result<CommittedDirectToolCallHighWater> {
        if durable_local_head != &self.to_head {
            bail!("direct_tool_call_high_water_local_durability_mismatch");
        }
        request_exact(
            self.transport.as_mut(),
            AuthorityOperation::Commit,
            &self.route,
            &self.to_head,
            Some(self.to_head.clone()),
            Some(self.transition_sha256.clone()),
        )?;
        Ok(CommittedDirectToolCallHighWater {
            transport: self.transport,
            route: self.route,
            committed_head: self.to_head,
        })
    }

    /// Reconcile a known crash/abort after an acknowledged PREPARE.  The
    /// authority accepts only the exact old or exact proposed local head.
    pub(crate) fn reconcile_known_local(
        self,
        local_head: DirectToolCallHighWaterHeadV1,
    ) -> Result<VerifiedDirectToolCallHighWater> {
        if local_head != self.from_head && local_head != self.to_head {
            bail!("direct_tool_call_high_water_reconcile_local_fork_denied");
        }
        establish(self.transport, self.route, local_head)
    }
}

impl CommittedDirectToolCallHighWater {
    pub(crate) fn reconcile(
        self,
        local_head: &DirectToolCallHighWaterHeadV1,
    ) -> Result<VerifiedDirectToolCallHighWater> {
        if local_head != &self.committed_head {
            bail!("direct_tool_call_high_water_post_commit_local_drift_denied");
        }
        establish(self.transport, self.route, local_head.clone())
    }
}

fn establish(
    mut transport: Box<dyn AuthorityTransport>,
    route: DirectToolCallHighWaterRouteV1,
    local_head: DirectToolCallHighWaterHeadV1,
) -> Result<VerifiedDirectToolCallHighWater> {
    route.validate()?;
    local_head.validate()?;
    request_exact(
        transport.as_mut(),
        AuthorityOperation::Reconcile,
        &route,
        &local_head,
        None,
        None,
    )?;
    request_exact(
        transport.as_mut(),
        AuthorityOperation::Observe,
        &route,
        &local_head,
        None,
        None,
    )?;
    Ok(VerifiedDirectToolCallHighWater {
        transport,
        route,
        committed_head: local_head,
    })
}

fn request_exact(
    transport: &mut dyn AuthorityTransport,
    operation: AuthorityOperation,
    route: &DirectToolCallHighWaterRouteV1,
    current_head: &DirectToolCallHighWaterHeadV1,
    proposed_head: Option<DirectToolCallHighWaterHeadV1>,
    transition_sha256: Option<String>,
) -> Result<AuthorityResponseV1> {
    let request = AuthorityRequestV1::build(
        operation,
        route.clone(),
        current_head.clone(),
        proposed_head,
        transition_sha256,
        fresh_nonce_sha256()?,
    )?;
    let response = transport
        .exchange(&request)
        .context("direct_tool_call_high_water_authority_outcome_unknown_permanent_hold")?;
    response.validate_for(&request)?;
    Ok(response)
}

fn transition_sha256(
    route: &DirectToolCallHighWaterRouteV1,
    from: &DirectToolCallHighWaterHeadV1,
    to: &DirectToolCallHighWaterHeadV1,
) -> Result<String> {
    route.validate()?;
    from.validate()?;
    to.validate()?;
    let expected_generation = from.generation.checked_add(1).ok_or_else(|| {
        anyhow!("direct_tool_call_high_water_generation_exhausted_permanent_hold")
    })?;
    if to.generation != expected_generation
        || to.allocator_store_sha256 == from.allocator_store_sha256
    {
        bail!("direct_tool_call_high_water_transition_denied");
    }
    #[derive(Serialize)]
    struct Preimage<'a> {
        protocol: &'a str,
        route_sha256: &'a str,
        from: &'a DirectToolCallHighWaterHeadV1,
        to: &'a DirectToolCallHighWaterHeadV1,
    }
    domain_digest(
        TRANSACTION_DOMAIN,
        &Preimage {
            protocol: PROTOCOL,
            route_sha256: &route.route_sha256,
            from,
            to,
        },
    )
}

fn fresh_nonce_sha256() -> Result<String> {
    let mut nonce = [0u8; 32];
    let result =
        unsafe { libc::getrandom(nonce.as_mut_ptr().cast::<libc::c_void>(), nonce.len(), 0) };
    if result != nonce.len() as isize || nonce.iter().all(|byte| *byte == 0) {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_high_water_kernel_nonce_unavailable");
    }
    Ok(sha256_bytes(&nonce))
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"domain", domain);
    hash_field(&mut hasher, b"value", &bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value != ZERO_SHA256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SocketIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
}

impl SocketIdentity {
    fn fixed_path() -> Result<Self> {
        let metadata = fs::symlink_metadata(FIXED_AUTHORITY_SOCKET_PATH)
            .context("direct_tool_call_high_water_fixed_socket_metadata_denied")?;
        let identity = Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
        };
        if !metadata.file_type().is_socket()
            || metadata.uid() != FIXED_AUTHORITY_UID
            || metadata.gid() != FIXED_AUTHORITY_GID
            || metadata.permissions().mode() & 0o7777 != FIXED_AUTHORITY_SOCKET_MODE
            || metadata.nlink() != 1
        {
            bail!("direct_tool_call_high_water_fixed_socket_identity_denied");
        }
        Ok(identity)
    }
}

struct FixedPathAuthorityTransport {
    stream: UnixStream,
    socket_identity: SocketIdentity,
    peer_pid: libc::pid_t,
}

impl FixedPathAuthorityTransport {
    fn connect() -> Result<Self> {
        let before = SocketIdentity::fixed_path()?;
        let stream = UnixStream::connect(FIXED_AUTHORITY_SOCKET_PATH)
            .context("direct_tool_call_high_water_fixed_socket_connect_denied")?;
        stream
            .set_read_timeout(Some(CALL_TIMEOUT))
            .context("direct_tool_call_high_water_read_timeout_denied")?;
        stream
            .set_write_timeout(Some(CALL_TIMEOUT))
            .context("direct_tool_call_high_water_write_timeout_denied")?;
        require_cloexec(&stream)?;
        let after = SocketIdentity::fixed_path()?;
        if before != after {
            bail!("direct_tool_call_high_water_fixed_socket_replaced_during_connect");
        }
        let credentials = peer_credentials(&stream)?;
        if credentials.uid != FIXED_AUTHORITY_UID
            || credentials.gid != FIXED_AUTHORITY_GID
            || credentials.pid <= 0
        {
            bail!("direct_tool_call_high_water_peer_credentials_denied");
        }
        if peer_security_context(&stream)? != FIXED_AUTHORITY_SELINUX_DOMAIN {
            bail!("direct_tool_call_high_water_peer_selinux_domain_denied");
        }
        Ok(Self {
            stream,
            socket_identity: before,
            peer_pid: credentials.pid,
        })
    }

    fn revalidate(&self) -> Result<()> {
        require_cloexec(&self.stream)?;
        if SocketIdentity::fixed_path()? != self.socket_identity {
            bail!("direct_tool_call_high_water_fixed_socket_replaced");
        }
        let credentials = peer_credentials(&self.stream)?;
        if credentials.uid != FIXED_AUTHORITY_UID
            || credentials.gid != FIXED_AUTHORITY_GID
            || credentials.pid != self.peer_pid
            || peer_security_context(&self.stream)? != FIXED_AUTHORITY_SELINUX_DOMAIN
        {
            bail!("direct_tool_call_high_water_peer_identity_changed");
        }
        Ok(())
    }
}

fn require_cloexec(stream: &UnixStream) -> Result<()> {
    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_high_water_socket_fcntl_denied");
    }
    if flags & libc::FD_CLOEXEC == 0 {
        bail!("direct_tool_call_high_water_socket_cloexec_denied");
    }
    Ok(())
}

impl AuthorityTransport for FixedPathAuthorityTransport {
    fn exchange(&mut self, request: &AuthorityRequestV1) -> Result<AuthorityResponseV1> {
        request.validate()?;
        self.revalidate()?;
        let bytes = serde_json::to_vec(request)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            bail!("direct_tool_call_high_water_request_frame_denied");
        }
        let length = u32::try_from(bytes.len())?;
        self.stream
            .write_all(&length.to_be_bytes())
            .and_then(|()| self.stream.write_all(&bytes))
            .and_then(|()| self.stream.flush())
            .context("direct_tool_call_high_water_request_outcome_unknown")?;
        let mut prefix = [0u8; 4];
        self.stream
            .read_exact(&mut prefix)
            .context("direct_tool_call_high_water_response_outcome_unknown")?;
        let response_length = u32::from_be_bytes(prefix) as usize;
        if response_length == 0 || response_length > MAX_FRAME_BYTES {
            bail!("direct_tool_call_high_water_response_frame_denied");
        }
        let mut response_bytes = vec![0u8; response_length];
        self.stream
            .read_exact(&mut response_bytes)
            .context("direct_tool_call_high_water_response_outcome_unknown")?;
        self.revalidate()?;
        let response: AuthorityResponseV1 = serde_json::from_slice(&response_bytes)
            .context("direct_tool_call_high_water_response_json_denied")?;
        if serde_json::to_vec(&response)? != response_bytes {
            bail!("direct_tool_call_high_water_response_noncanonical_denied");
        }
        response.validate_for(request)?;
        Ok(response)
    }
}

fn peer_credentials(stream: &UnixStream) -> Result<libc::ucred> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast::<libc::c_void>(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_high_water_SO_PEERCRED_denied");
    }
    Ok(unsafe { credentials.assume_init() })
}

fn peer_security_context(stream: &UnixStream) -> Result<String> {
    let mut buffer = [0u8; 256];
    let mut length = buffer.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            &mut length,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("direct_tool_call_high_water_SO_PEERSEC_denied");
    }
    let length = length as usize;
    if length == 0 || length > buffer.len() {
        bail!("direct_tool_call_high_water_SO_PEERSEC_malformed");
    }
    let context = &buffer[..length];
    let context = context.strip_suffix(&[0]).unwrap_or(context);
    let context =
        std::str::from_utf8(context).context("direct_tool_call_high_water_SO_PEERSEC_not_utf8")?;
    if context.is_empty() || context.as_bytes().contains(&0) {
        bail!("direct_tool_call_high_water_SO_PEERSEC_malformed");
    }
    Ok(context.to_string())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestAuthorityFault {
    OutcomeUnknownBeforeApply(AuthorityOperation),
    OutcomeUnknownAfterApply(AuthorityOperation),
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestDirectToolCallHighWaterAuthority {
    state: std::sync::Arc<std::sync::Mutex<TestAuthorityState>>,
}

#[cfg(test)]
#[derive(Clone)]
struct TestPendingTransition {
    from: DirectToolCallHighWaterHeadV1,
    to: DirectToolCallHighWaterHeadV1,
    transition_sha256: String,
}

#[cfg(test)]
struct TestAuthorityState {
    route: DirectToolCallHighWaterRouteV1,
    committed: DirectToolCallHighWaterHeadV1,
    pending: Option<TestPendingTransition>,
    permanent_hold: bool,
    fault: Option<TestAuthorityFault>,
}

#[cfg(test)]
impl TestDirectToolCallHighWaterAuthority {
    pub(crate) fn new(
        route: DirectToolCallHighWaterRouteV1,
        committed: DirectToolCallHighWaterHeadV1,
    ) -> Self {
        Self {
            state: std::sync::Arc::new(std::sync::Mutex::new(TestAuthorityState {
                route,
                committed,
                pending: None,
                permanent_hold: false,
                fault: None,
            })),
        }
    }

    pub(crate) fn connect(
        &self,
        route: DirectToolCallHighWaterRouteV1,
        local_head: DirectToolCallHighWaterHeadV1,
    ) -> Result<VerifiedDirectToolCallHighWater> {
        establish(Box::new(self.clone()), route, local_head)
    }

    fn inject_fault(&self, fault: TestAuthorityFault) {
        self.state.lock().unwrap().fault = Some(fault);
    }

    pub(crate) fn inject_commit_outcome_unknown_after_apply(&self) {
        self.inject_fault(TestAuthorityFault::OutcomeUnknownAfterApply(
            AuthorityOperation::Commit,
        ));
    }

    pub(crate) fn committed_head(&self) -> DirectToolCallHighWaterHeadV1 {
        self.state.lock().unwrap().committed.clone()
    }

    pub(crate) fn is_permanent_hold(&self) -> bool {
        self.state.lock().unwrap().permanent_hold
    }
}

#[cfg(test)]
impl AuthorityTransport for TestDirectToolCallHighWaterAuthority {
    fn exchange(&mut self, request: &AuthorityRequestV1) -> Result<AuthorityResponseV1> {
        request.validate()?;
        let mut state = self.state.lock().unwrap();
        if request.route != state.route {
            state.permanent_hold = true;
        }
        if state.permanent_hold {
            return test_response(
                request,
                AuthorityDisposition::PermanentHold,
                state.committed.clone(),
                None,
            );
        }
        let fault_matches = state.fault.as_ref().is_some_and(|fault| match fault {
            TestAuthorityFault::OutcomeUnknownBeforeApply(operation)
            | TestAuthorityFault::OutcomeUnknownAfterApply(operation) => {
                *operation == request.operation
            }
        });
        let fault = if fault_matches {
            state.fault.take()
        } else {
            None
        };
        if matches!(
            fault,
            Some(TestAuthorityFault::OutcomeUnknownBeforeApply(_))
        ) {
            state.permanent_hold = true;
            bail!("test_high_water_outcome_unknown_before_apply");
        }

        let response = match request.operation {
            AuthorityOperation::Reconcile => {
                if let Some(pending) = state.pending.clone() {
                    if request.current_head == pending.from {
                        state.pending = None;
                    } else if request.current_head == pending.to {
                        state.committed = pending.to;
                        state.pending = None;
                    } else {
                        state.permanent_hold = true;
                    }
                } else if request.current_head != state.committed {
                    state.permanent_hold = true;
                }
                test_response(
                    request,
                    if state.permanent_hold {
                        AuthorityDisposition::PermanentHold
                    } else {
                        AuthorityDisposition::ReconciledExact
                    },
                    state.committed.clone(),
                    None,
                )?
            }
            AuthorityOperation::Observe => {
                let exact = state.pending.is_none() && request.current_head == state.committed;
                if !exact {
                    state.permanent_hold = true;
                }
                test_response(
                    request,
                    if exact {
                        AuthorityDisposition::ObservedExact
                    } else {
                        AuthorityDisposition::PermanentHold
                    },
                    state.committed.clone(),
                    None,
                )?
            }
            AuthorityOperation::Prepare => {
                let proposed = request.proposed_head.clone().unwrap();
                let transition = request.transition_sha256.clone().unwrap();
                let candidate = TestPendingTransition {
                    from: request.current_head.clone(),
                    to: proposed,
                    transition_sha256: transition.clone(),
                };
                let exact = request.current_head == state.committed
                    && state.pending.as_ref().is_none_or(|pending| {
                        pending.from == candidate.from
                            && pending.to == candidate.to
                            && pending.transition_sha256 == candidate.transition_sha256
                    });
                if exact {
                    state.pending = Some(candidate);
                } else {
                    state.permanent_hold = true;
                }
                test_response(
                    request,
                    if exact {
                        AuthorityDisposition::PreparedExact
                    } else {
                        AuthorityDisposition::PermanentHold
                    },
                    state.committed.clone(),
                    Some(transition),
                )?
            }
            AuthorityOperation::Commit => {
                let transition = request.transition_sha256.clone().unwrap();
                let exact = state.pending.as_ref().is_some_and(|pending| {
                    pending.to == request.current_head
                        && pending.transition_sha256 == transition
                        && pending.from == state.committed
                });
                if exact {
                    state.committed = request.current_head.clone();
                    state.pending = None;
                } else {
                    state.permanent_hold = true;
                }
                test_response(
                    request,
                    if exact {
                        AuthorityDisposition::CommittedExact
                    } else {
                        AuthorityDisposition::PermanentHold
                    },
                    state.committed.clone(),
                    Some(transition),
                )?
            }
        };

        if matches!(fault, Some(TestAuthorityFault::OutcomeUnknownAfterApply(_))) {
            state.permanent_hold = true;
            bail!("test_high_water_outcome_unknown_after_apply");
        }
        Ok(response)
    }
}

#[cfg(test)]
fn test_response(
    request: &AuthorityRequestV1,
    disposition: AuthorityDisposition,
    committed_head: DirectToolCallHighWaterHeadV1,
    transition_sha256: Option<String>,
) -> Result<AuthorityResponseV1> {
    let mut response = AuthorityResponseV1 {
        schema: RESPONSE_SCHEMA.to_string(),
        protocol: PROTOCOL.to_string(),
        operation: request.operation,
        disposition,
        authority_identity_sha256: FIXED_AUTHORITY_IDENTITY_SHA256.to_string(),
        route_sha256: request.route.route_sha256.clone(),
        request_sha256: request.request_sha256.clone(),
        committed_head,
        transition_sha256,
        response_sha256: String::new(),
    };
    response.response_sha256 = response.expected_sha256()?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> String {
        sha256_bytes(label.as_bytes())
    }

    fn route() -> DirectToolCallHighWaterRouteV1 {
        DirectToolCallHighWaterRouteV1::derive(
            digest("binding"),
            "openai-codex".to_string(),
            "agent-codex-direct-v1".to_string(),
            DirectOperationAdapter::SystemApi,
        )
        .unwrap()
    }

    fn head(generation: u64, label: &str) -> DirectToolCallHighWaterHeadV1 {
        DirectToolCallHighWaterHeadV1::new(
            generation,
            if generation == 0 {
                ZERO_SHA256.to_string()
            } else {
                digest(label)
            },
        )
        .unwrap()
    }

    #[test]
    fn exact_prepare_commit_reconcile_advances_one_generation() {
        let route = route();
        let initial = head(0, "unused");
        let authority = TestDirectToolCallHighWaterAuthority::new(route.clone(), initial.clone());
        let verified = authority.connect(route, initial).unwrap();
        let successor = head(1, "generation-one");
        let prepared = verified.prepare(successor.clone()).unwrap();
        let committed = prepared.commit(&successor).unwrap();
        let observed = committed.reconcile(&successor).unwrap();
        assert_eq!(observed.committed_head(), &successor);
        assert_eq!(authority.committed_head(), successor);
    }

    #[test]
    fn known_crashes_after_prepare_reconcile_old_or_new_local_state() {
        let route = route();
        let initial = head(0, "unused");
        let successor = head(1, "generation-one");

        let old_authority =
            TestDirectToolCallHighWaterAuthority::new(route.clone(), initial.clone());
        let prepared = old_authority
            .connect(route.clone(), initial.clone())
            .unwrap()
            .prepare(successor.clone())
            .unwrap();
        drop(prepared);
        let recovered = old_authority
            .connect(route.clone(), initial.clone())
            .unwrap();
        assert_eq!(recovered.committed_head(), &initial);

        let new_authority =
            TestDirectToolCallHighWaterAuthority::new(route.clone(), initial.clone());
        let prepared = new_authority
            .connect(route.clone(), initial)
            .unwrap()
            .prepare(successor.clone())
            .unwrap();
        drop(prepared);
        let recovered = new_authority.connect(route, successor.clone()).unwrap();
        assert_eq!(recovered.committed_head(), &successor);
        assert_eq!(new_authority.committed_head(), successor);
    }

    #[test]
    fn rollback_and_same_generation_fork_enter_permanent_hold() {
        for local in [head(1, "rolled-back"), head(2, "forked-digest")] {
            let route = route();
            let committed = head(2, "committed");
            let authority =
                TestDirectToolCallHighWaterAuthority::new(route.clone(), committed.clone());
            assert!(authority.connect(route.clone(), local).is_err());
            assert!(authority.is_permanent_hold());
            assert!(authority.connect(route, committed).is_err());
        }
    }

    #[test]
    fn maximum_generation_cannot_wrap_to_genesis() {
        let route = route();
        let exhausted = head(u64::MAX, "exhausted");
        let forged_genesis = head(0, "unused");

        assert!(transition_sha256(&route, &exhausted, &forged_genesis).is_err());
        assert!(
            AuthorityRequestV1::build(
                AuthorityOperation::Prepare,
                route,
                exhausted,
                Some(forged_genesis),
                Some(digest("forged-wrap-transition")),
                digest("nonce"),
            )
            .is_err()
        );
    }

    #[test]
    fn indeterminate_prepare_commit_or_reconcile_never_returns_capability() {
        for (operation, after_apply) in [
            (AuthorityOperation::Reconcile, false),
            (AuthorityOperation::Reconcile, true),
            (AuthorityOperation::Prepare, false),
            (AuthorityOperation::Prepare, true),
            (AuthorityOperation::Commit, false),
            (AuthorityOperation::Commit, true),
        ] {
            let route = route();
            let initial = head(0, "unused");
            let successor = head(1, "generation-one");
            let authority =
                TestDirectToolCallHighWaterAuthority::new(route.clone(), initial.clone());
            if operation == AuthorityOperation::Reconcile {
                authority.inject_fault(if after_apply {
                    TestAuthorityFault::OutcomeUnknownAfterApply(operation)
                } else {
                    TestAuthorityFault::OutcomeUnknownBeforeApply(operation)
                });
                assert!(authority.connect(route.clone(), initial.clone()).is_err());
            } else {
                let verified = authority.connect(route.clone(), initial.clone()).unwrap();
                if operation == AuthorityOperation::Prepare {
                    authority.inject_fault(if after_apply {
                        TestAuthorityFault::OutcomeUnknownAfterApply(operation)
                    } else {
                        TestAuthorityFault::OutcomeUnknownBeforeApply(operation)
                    });
                    assert!(verified.prepare(successor.clone()).is_err());
                } else {
                    let prepared = verified.prepare(successor.clone()).unwrap();
                    authority.inject_fault(if after_apply {
                        TestAuthorityFault::OutcomeUnknownAfterApply(operation)
                    } else {
                        TestAuthorityFault::OutcomeUnknownBeforeApply(operation)
                    });
                    assert!(prepared.commit(&successor).is_err());
                }
            }
            assert!(authority.is_permanent_hold());
            assert!(
                authority
                    .connect(route, authority.committed_head())
                    .is_err()
            );
        }
    }

    #[test]
    fn response_request_route_and_transition_substitution_are_rejected() {
        let route = route();
        let initial = head(0, "unused");
        let request = AuthorityRequestV1::build(
            AuthorityOperation::Observe,
            route,
            initial.clone(),
            None,
            None,
            digest("nonce"),
        )
        .unwrap();
        let mut response =
            test_response(&request, AuthorityDisposition::ObservedExact, initial, None).unwrap();
        response.request_sha256 = digest("other-request");
        response.response_sha256 = response.expected_sha256().unwrap();
        assert!(response.validate_for(&request).is_err());
    }

    #[test]
    fn product_transport_has_one_fixed_path_and_mandatory_kernel_identity_checks() {
        assert_eq!(
            FIXED_AUTHORITY_SOCKET_PATH,
            "/run/trillionnium/direct-operation-tool-call-high-water-v1.sock"
        );
        let source = include_str!("direct_tool_call_high_water.rs");
        assert!(source.contains("SO_PEERCRED"));
        assert!(source.contains("SO_PEERSEC"));
        assert!(!source.contains(&["std", "::", "env"].concat()));
        assert!(!source.contains(&["connect_product", "(path"].concat()));
    }
}
