//! Source-only adapter client for the independent Direct operation runtime
//! authority carrier.
//!
//! The source protocol deliberately has no successful product response. It
//! authenticates the fixed daemon peer, receives a daemon-first freshness
//! challenge on that exact stream, and seals the connection plus the complete
//! challenge/hello/probe request into one move-only transport handoff. The
//! handoff then accepts only the exact correlated HOLD as an error. Bare wire
//! records cannot reconstruct the retained daemon connection, and the
//! successful return type remains `Infallible`.

#[cfg(any(test, feature = "production-durable-hotpath"))]
use std::convert::Infallible;
#[cfg(any(test, feature = "production-durable-hotpath"))]
use std::fmt;
#[cfg(any(test, feature = "production-durable-hotpath"))]
use std::io::{Read, Write};
#[cfg(any(test, feature = "production-durable-hotpath"))]
use std::net::Shutdown;
#[cfg(any(test, feature = "production-durable-hotpath"))]
use std::os::unix::net::UnixStream;
#[cfg(any(test, feature = "production-durable-hotpath"))]
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(any(test, feature = "production-durable-hotpath"))]
use std::time::Duration;

#[cfg(any(test, feature = "production-durable-hotpath"))]
use serde::Serialize;
#[cfg(any(test, feature = "production-durable-hotpath"))]
use serde::de::DeserializeOwned;
#[cfg(any(test, feature = "production-durable-hotpath"))]
use trillionnium_os_types::direct_operation::{
    DirectOperationAdapter, DirectOperationBinding, DirectOperationKernelLaunchCustodyV3,
};
use trillionnium_os_types::direct_operation_runtime_authority as contract;
#[cfg(any(test, feature = "production-durable-hotpath"))]
use trillionnium_os_types::direct_operation_runtime_authority::{
    DirectOperationRuntimeAuthorityHoldV3, DirectOperationRuntimeAuthorityObservationV3,
    DirectOperationRuntimeAuthorityProbeV3, DirectOperationRuntimeAuthoritySessionChallengeV3,
    DirectOperationRuntimeAuthoritySessionHelloV3,
};

#[cfg(any(test, feature = "production-durable-hotpath"))]
use crate::{DirectToolError, Result};

#[cfg(any(test, feature = "production-durable-hotpath"))]
const SESSION_TIMEOUT: Duration = Duration::from_secs(5);

const _: () = {
    assert!(contract::SOURCE_CLIENT_IMPLEMENTED);
    assert!(!contract::SOURCE_LISTENER_IMPLEMENTED);
    assert!(contract::SOURCE_INJECTED_HANDLER_IMPLEMENTED);
    assert!(contract::SOURCE_HOLD_RESPONSE_IMPLEMENTED);
    assert!(!contract::EXTERNAL_RUNTIME_AUTHORITY_PRODUCT_AVAILABLE);
    assert!(!contract::DAEMON_LISTENER_PRODUCT_WIRED);
    assert!(!contract::ADAPTER_CONNECTOR_PRODUCT_WIRED);
    assert!(!contract::AUTHORITY_BACKEND_PRODUCT_WIRED);
    assert!(!contract::FIRST_USE_DECISION_PRODUCT_AVAILABLE);
    assert!(!contract::REPLAY_DECISION_PRODUCT_AVAILABLE);
    assert!(!contract::FIRST_USE_PRODUCT_WIRED);
    assert!(!contract::REPLAY_PRODUCT_WIRED);
    assert!(!contract::MUTATION_CAS_PRODUCT_AVAILABLE);
    assert!(!contract::ACTIVATION_PRODUCT_WIRED);
    assert!(!contract::ANDROID_ACTIVATION_PRODUCT_WIRED);
    assert!(!contract::ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE);
    assert!(!contract::CONFERS_EFFECT_AUTHORITY);
};

#[cfg(any(test, feature = "production-durable-hotpath"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectOperationRuntimeAuthorityPhase {
    FirstUse,
    Replay,
}

/// A source-carrier failure. An exact HOLD is preserved as structured data and
/// is never collapsed into a successful "unavailable" result that a caller
/// could accidentally discard with `?`.
#[cfg(any(test, feature = "production-durable-hotpath"))]
#[derive(Debug)]
pub(crate) enum DirectOperationRuntimeAuthorityFailure {
    Hold {
        phase: DirectOperationRuntimeAuthorityPhase,
        response: Box<DirectOperationRuntimeAuthorityHoldV3>,
    },
    Transport(DirectToolError),
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
impl fmt::Display for DirectOperationRuntimeAuthorityFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hold { phase, response } => write!(
                formatter,
                "operation runtime authority {phase:?} HOLD: {}",
                response.code
            ),
            Self::Transport(error) => error.fmt(formatter),
        }
    }
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
impl std::error::Error for DirectOperationRuntimeAuthorityFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Hold { .. } => None,
            Self::Transport(error) => Some(error),
        }
    }
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
impl From<DirectToolError> for DirectOperationRuntimeAuthorityFailure {
    fn from(error: DirectToolError) -> Self {
        Self::Transport(error)
    }
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
type AuthorityResult<T> = std::result::Result<T, DirectOperationRuntimeAuthorityFailure>;

#[cfg(any(test, feature = "production-durable-hotpath"))]
struct RuntimeAuthorityClientContext<'a> {
    binding: &'a DirectOperationBinding,
    binding_sha256: &'a str,
    adapter: DirectOperationAdapter,
    custody: &'a DirectOperationKernelLaunchCustodyV3,
}

/// Move-only pre-response handoff for one exact authenticated daemon stream.
///
/// This is deliberately not store or effect authority. It retains the peer-
/// authenticated connection together with the complete request context, so a
/// future successful response parser cannot accept a replacement stream,
/// process, binding, launch-custody record, or first-use/replay observation.
/// The current V3 vocabulary has no successful response and can consume this
/// handoff only into a correlated terminal HOLD.
#[cfg(any(test, feature = "production-durable-hotpath"))]
pub(crate) struct SealedRuntimeAuthorityTransportHandoff {
    connection: AuthenticatedAuthorityDaemonConnection,
    binding: DirectOperationBinding,
    binding_sha256: String,
    adapter: DirectOperationAdapter,
    custody: DirectOperationKernelLaunchCustodyV3,
    challenge: DirectOperationRuntimeAuthoritySessionChallengeV3,
    hello: DirectOperationRuntimeAuthoritySessionHelloV3,
    probe: DirectOperationRuntimeAuthorityProbeV3,
    phase: DirectOperationRuntimeAuthorityPhase,
}

/// Request independent first-use authority.
///
/// This source seam has no product caller while
/// `ADAPTER_CONNECTOR_PRODUCT_WIRED` is false, and its successful type is
/// uninhabited while the V3 response vocabulary contains only HOLD.
#[cfg(any(test, feature = "production-durable-hotpath"))]
pub(crate) fn request_first_use_authority(
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    custody: &DirectOperationKernelLaunchCustodyV3,
    state_directory_identity_sha256: &str,
) -> AuthorityResult<Infallible> {
    begin_first_use_authority_handoff(
        binding,
        binding_sha256,
        adapter,
        custody,
        state_directory_identity_sha256,
    )?
    .finish_source_disabled_hold()
}

/// Establish the exact first-use request and retain its authenticated daemon
/// stream for the future external-backend response boundary.
///
/// Returning this type does not make first-use authority available: the only
/// current consumer is the terminal HOLD path below.
#[cfg(any(test, feature = "production-durable-hotpath"))]
pub(crate) fn begin_first_use_authority_handoff(
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    custody: &DirectOperationKernelLaunchCustodyV3,
    state_directory_identity_sha256: &str,
) -> AuthorityResult<SealedRuntimeAuthorityTransportHandoff> {
    let context = RuntimeAuthorityClientContext {
        binding,
        binding_sha256,
        adapter,
        custody,
    };
    let mut connection = AuthenticatedAuthorityDaemonConnection::connect_fixed()?;
    let challenge = read_validated_challenge(&mut connection, &context)?;
    let hello = DirectOperationRuntimeAuthoritySessionHelloV3::derive(
        &challenge,
        binding,
        binding_sha256,
        adapter,
        custody,
    )
    .map_err(protocol_error)?;
    let probe = DirectOperationRuntimeAuthorityProbeV3::derive_first_use(
        &hello,
        state_directory_identity_sha256,
    )
    .map_err(protocol_error)?;
    SealedRuntimeAuthorityTransportHandoff::establish(
        connection,
        challenge,
        hello,
        probe,
        DirectOperationRuntimeAuthorityPhase::FirstUse,
        &context,
    )
}

/// Request independent restart/replay authority.
///
/// Every replay identity is already an exact digest or epoch supplied by a
/// future measured observation seam. No local state is read by this module,
/// and the successful type is uninhabited.
#[cfg(any(test, feature = "production-durable-hotpath"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn request_replay_authority(
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    custody: &DirectOperationKernelLaunchCustodyV3,
    state_directory_identity_sha256: &str,
    journal_epoch: &str,
    current_journal_identity_sha256: &str,
    current_journal_bytes_sha256: &str,
    sentinel_identity_sha256: &str,
    sentinel_bytes_sha256: &str,
    first_use_committed_result_binding_sha256: &str,
) -> AuthorityResult<Infallible> {
    begin_replay_authority_handoff(
        binding,
        binding_sha256,
        adapter,
        custody,
        state_directory_identity_sha256,
        journal_epoch,
        current_journal_identity_sha256,
        current_journal_bytes_sha256,
        sentinel_identity_sha256,
        sentinel_bytes_sha256,
        first_use_committed_result_binding_sha256,
    )?
    .finish_source_disabled_hold()
}

/// Establish the exact replay request and retain its authenticated daemon
/// stream for the future external-backend response boundary.
///
/// The sealed object owns both transport and observation; no API can attach
/// replay ABI records to a different daemon connection.
#[cfg(any(test, feature = "production-durable-hotpath"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn begin_replay_authority_handoff(
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    custody: &DirectOperationKernelLaunchCustodyV3,
    state_directory_identity_sha256: &str,
    journal_epoch: &str,
    current_journal_identity_sha256: &str,
    current_journal_bytes_sha256: &str,
    sentinel_identity_sha256: &str,
    sentinel_bytes_sha256: &str,
    first_use_committed_result_binding_sha256: &str,
) -> AuthorityResult<SealedRuntimeAuthorityTransportHandoff> {
    let context = RuntimeAuthorityClientContext {
        binding,
        binding_sha256,
        adapter,
        custody,
    };
    let mut connection = AuthenticatedAuthorityDaemonConnection::connect_fixed()?;
    let challenge = read_validated_challenge(&mut connection, &context)?;
    let hello = DirectOperationRuntimeAuthoritySessionHelloV3::derive(
        &challenge,
        binding,
        binding_sha256,
        adapter,
        custody,
    )
    .map_err(protocol_error)?;
    let probe = DirectOperationRuntimeAuthorityProbeV3::derive_replay(
        &hello,
        state_directory_identity_sha256,
        journal_epoch,
        current_journal_identity_sha256,
        current_journal_bytes_sha256,
        sentinel_identity_sha256,
        sentinel_bytes_sha256,
        first_use_committed_result_binding_sha256,
    )
    .map_err(protocol_error)?;
    SealedRuntimeAuthorityTransportHandoff::establish(
        connection,
        challenge,
        hello,
        probe,
        DirectOperationRuntimeAuthorityPhase::Replay,
        &context,
    )
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
struct AuthenticatedAuthorityDaemonConnection {
    stream: UnixStream,
    #[cfg(test)]
    endpoint: PathBuf,
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
impl AuthenticatedAuthorityDaemonConnection {
    fn connect_fixed() -> Result<Self> {
        let endpoint = Path::new(contract::SOCKET_ADDRESS);
        let stream = crate::uds::connect(endpoint)?;
        let connection = Self {
            stream,
            #[cfg(test)]
            endpoint: endpoint.to_path_buf(),
        };
        connection.initialize()
    }

    #[cfg(test)]
    fn connect_fixture(endpoint: &Path) -> Result<Self> {
        let stream = crate::uds::connect(endpoint)?;
        let connection = Self {
            stream,
            endpoint: endpoint.to_path_buf(),
        };
        connection.initialize()
    }

    fn initialize(self) -> Result<Self> {
        self.revalidate()?;
        self.stream.set_read_timeout(Some(SESSION_TIMEOUT))?;
        self.stream.set_write_timeout(Some(SESSION_TIMEOUT))?;
        Ok(self)
    }

    fn revalidate(&self) -> Result<()> {
        #[cfg(test)]
        let endpoint = self.endpoint.as_path();
        #[cfg(not(test))]
        let endpoint = Path::new(contract::SOCKET_ADDRESS);
        crate::uds::verify_connected_peer(
            endpoint,
            &self.stream,
            crate::uds::ExpectedBackendPeer::AgentDaemon,
        )
    }

    fn shutdown_write(&self) -> Result<()> {
        self.stream.shutdown(Shutdown::Write)?;
        Ok(())
    }
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
impl Read for AuthenticatedAuthorityDaemonConnection {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(bytes)
    }
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
impl Write for AuthenticatedAuthorityDaemonConnection {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
fn read_validated_challenge(
    connection: &mut AuthenticatedAuthorityDaemonConnection,
    context: &RuntimeAuthorityClientContext<'_>,
) -> AuthorityResult<DirectOperationRuntimeAuthoritySessionChallengeV3> {
    connection.revalidate()?;
    let challenge: DirectOperationRuntimeAuthoritySessionChallengeV3 =
        read_canonical_frame(connection)?;
    connection.revalidate()?;
    challenge
        .validate_client_context(
            context.binding,
            context.binding_sha256,
            context.adapter,
            context.custody,
        )
        .map_err(protocol_error)?;
    Ok(challenge)
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
impl SealedRuntimeAuthorityTransportHandoff {
    fn establish(
        mut connection: AuthenticatedAuthorityDaemonConnection,
        challenge: DirectOperationRuntimeAuthoritySessionChallengeV3,
        hello: DirectOperationRuntimeAuthoritySessionHelloV3,
        probe: DirectOperationRuntimeAuthorityProbeV3,
        phase: DirectOperationRuntimeAuthorityPhase,
        context: &RuntimeAuthorityClientContext<'_>,
    ) -> AuthorityResult<Self> {
        challenge
            .validate_client_context(
                context.binding,
                context.binding_sha256,
                context.adapter,
                context.custody,
            )
            .map_err(protocol_error)?;
        hello
            .validate_for(
                &challenge,
                context.binding,
                context.binding_sha256,
                context.adapter,
                context.custody,
            )
            .map_err(protocol_error)?;
        probe.validate_for_hello(&hello).map_err(protocol_error)?;
        require_observation_class(&probe, phase)?;
        connection.revalidate()?;
        write_canonical_frame(&mut connection, &hello)?;
        connection.revalidate()?;
        write_canonical_frame(&mut connection, &probe)?;
        connection.revalidate()?;
        let handoff = Self {
            connection,
            binding: context.binding.clone(),
            binding_sha256: context.binding_sha256.to_string(),
            adapter: context.adapter,
            custody: context.custody.clone(),
            challenge,
            hello,
            probe,
            phase,
        };
        handoff.revalidate_exact_request()?;
        Ok(handoff)
    }

    fn revalidate_exact_request(&self) -> AuthorityResult<()> {
        self.connection.revalidate()?;
        self.challenge
            .validate_client_context(
                &self.binding,
                &self.binding_sha256,
                self.adapter,
                &self.custody,
            )
            .map_err(protocol_error)?;
        self.hello
            .validate_for(
                &self.challenge,
                &self.binding,
                &self.binding_sha256,
                self.adapter,
                &self.custody,
            )
            .map_err(protocol_error)?;
        self.probe
            .validate_for_hello(&self.hello)
            .map_err(protocol_error)?;
        require_observation_class(&self.probe, self.phase)?;
        Ok(())
    }

    fn finish_source_disabled_hold(mut self) -> AuthorityResult<Infallible> {
        self.revalidate_exact_request()?;
        self.connection.shutdown_write()?;
        self.revalidate_exact_request()?;

        let hold: DirectOperationRuntimeAuthorityHoldV3 =
            read_canonical_frame(&mut self.connection)?;
        self.revalidate_exact_request()?;
        hold.validate_for(&self.hello, &self.probe)
            .map_err(protocol_error)?;
        require_peer_close(&mut self.connection)?;
        self.revalidate_exact_request()?;
        Err(DirectOperationRuntimeAuthorityFailure::Hold {
            phase: self.phase,
            response: Box::new(hold),
        })
    }

    #[cfg(test)]
    fn probe_for_test(&self) -> &DirectOperationRuntimeAuthorityProbeV3 {
        &self.probe
    }
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
fn require_observation_class(
    probe: &DirectOperationRuntimeAuthorityProbeV3,
    phase: DirectOperationRuntimeAuthorityPhase,
) -> Result<()> {
    let matches = matches!(
        (&probe.observation, phase),
        (
            DirectOperationRuntimeAuthorityObservationV3::FirstUse { .. },
            DirectOperationRuntimeAuthorityPhase::FirstUse
        ) | (
            DirectOperationRuntimeAuthorityObservationV3::Replay { .. },
            DirectOperationRuntimeAuthorityPhase::Replay
        )
    );
    if matches {
        Ok(())
    } else {
        Err(DirectToolError::BackendFailed(
            "operation runtime authority probe phase is not interchangeable".to_string(),
        ))
    }
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
fn write_canonical_frame<T: Serialize>(stream: &mut impl Write, value: &T) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() || payload.len() > contract::MAXIMUM_FRAME_BYTES {
        return Err(DirectToolError::BackendFailed(
            "operation runtime authority output frame is outside the fixed bound".to_string(),
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|_| {
        DirectToolError::BackendFailed(
            "operation runtime authority output length overflowed".to_string(),
        )
    })?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
fn read_canonical_frame<T: DeserializeOwned + Serialize>(stream: &mut impl Read) -> Result<T> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).map_err(|error| {
        DirectToolError::BackendFailed(format!(
            "operation runtime authority response prefix is unavailable: {error}"
        ))
    })?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > contract::MAXIMUM_FRAME_BYTES {
        return Err(DirectToolError::BackendFailed(
            "operation runtime authority response frame is outside the fixed bound".to_string(),
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).map_err(|error| {
        DirectToolError::BackendFailed(format!(
            "operation runtime authority response payload is incomplete: {error}"
        ))
    })?;
    let value: T = serde_json::from_slice(&payload).map_err(|error| {
        DirectToolError::BackendFailed(format!(
            "operation runtime authority response JSON is invalid: {error}"
        ))
    })?;
    if serde_json::to_vec(&value)? != payload {
        return Err(DirectToolError::BackendFailed(
            "operation runtime authority response is not canonical JSON".to_string(),
        ));
    }
    Ok(value)
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
fn require_peer_close(stream: &mut impl Read) -> Result<()> {
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(DirectToolError::BackendFailed(
            "operation runtime authority daemon returned trailing bytes".to_string(),
        )),
        Err(error) => Err(DirectToolError::BackendFailed(format!(
            "operation runtime authority daemon did not close after its HOLD: {error}"
        ))),
    }
}

#[cfg(any(test, feature = "production-durable-hotpath"))]
fn protocol_error(error: impl std::fmt::Display) -> DirectToolError {
    DirectToolError::BackendFailed(format!(
        "operation runtime authority protocol binding failed: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::thread;

    use trillionnium_os_types::direct_operation::{
        BINDING_SCHEMA, DirectOperationKernelLaunchCustodyV3, DirectOperationProviderAttempt,
        DirectOperationStableSeed, KERNEL_LAUNCH_CUSTODY_KIND_V3,
        KERNEL_LAUNCH_CUSTODY_PRODUCER_V3, KERNEL_LAUNCH_CUSTODY_V3_SCHEMA, STABLE_SEED_SCHEMA,
        adapter_binary_kind, fixed_adapter_cgroup_path,
    };
    use trillionnium_os_types::sha256_bytes;

    use super::*;

    fn digest(label: &str) -> String {
        sha256_bytes(label.as_bytes())
    }

    fn binding() -> DirectOperationBinding {
        let seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            task_id: "task.runtime-authority".to_string(),
            provider_invocation_id_sha256: digest("provider-invocation"),
            provider_session_id_sha256: digest("provider-session"),
            subject_uid: 10_100,
            subject_selinux_domain_sha256: digest("subject-domain"),
        };
        DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            invocation_id: seed.invocation_id().unwrap(),
            stable_seed: seed,
            workflow_id_sha256: digest("workflow"),
            agent_identity_key_sha256: digest("identity"),
            agent_executable_sha256: digest("agent-executable"),
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(
                digest("lifecycle"),
                1,
                digest("attempt"),
            )
            .unwrap(),
        }
    }

    fn custody(
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> DirectOperationKernelLaunchCustodyV3 {
        let mut custody = DirectOperationKernelLaunchCustodyV3 {
            schema: KERNEL_LAUNCH_CUSTODY_V3_SCHEMA.to_string(),
            kernel_custody_kind: KERNEL_LAUNCH_CUSTODY_KIND_V3.to_string(),
            custody_producer: KERNEL_LAUNCH_CUSTODY_PRODUCER_V3.to_string(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter,
            adapter_binary_kind: adapter_binary_kind(adapter).to_string(),
            binding_sha256: binding_sha256.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_subtree_generation: 41,
            provider_subtree_reservation_evidence_sha256: digest("reservation"),
            boot_id_sha256: digest("boot"),
            adapter_pid: 42,
            adapter_start_time_ticks: 88,
            adapter_executable_sha256: digest("adapter"),
            unified_cgroup_path: fixed_adapter_cgroup_path(
                &binding.stable_seed.provider_id,
                adapter,
            )
            .unwrap(),
            adapter_leaf_empty_proof_sha256: digest("empty"),
            measured_exec_proof_sha256: digest("exec"),
            launch_custody_sha256: String::new(),
        };
        custody.launch_custody_sha256 = custody.digest_sha256().unwrap();
        custody
    }

    struct RuntimeFixture {
        binding: DirectOperationBinding,
        binding_sha256: String,
        adapter: DirectOperationAdapter,
        custody: DirectOperationKernelLaunchCustodyV3,
    }

    fn runtime_fixture() -> RuntimeFixture {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let adapter = DirectOperationAdapter::SystemApi;
        let custody = custody(&binding, &binding_sha256, adapter);
        RuntimeFixture {
            binding,
            binding_sha256,
            adapter,
            custody,
        }
    }

    fn hello_and_probe(
        fixture: &RuntimeFixture,
        challenge: &DirectOperationRuntimeAuthoritySessionChallengeV3,
        replay: bool,
    ) -> (
        DirectOperationRuntimeAuthoritySessionHelloV3,
        DirectOperationRuntimeAuthorityProbeV3,
    ) {
        let hello = DirectOperationRuntimeAuthoritySessionHelloV3::derive(
            challenge,
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
        )
        .unwrap();
        let probe = if replay {
            DirectOperationRuntimeAuthorityProbeV3::derive_replay(
                &hello,
                &digest("state-directory"),
                &"01".repeat(16),
                &digest("journal-identity"),
                &digest("journal-bytes"),
                &digest("sentinel-identity"),
                &digest("sentinel-bytes"),
                &digest("first-use-binding"),
            )
            .unwrap()
        } else {
            DirectOperationRuntimeAuthorityProbeV3::derive_first_use(
                &hello,
                &digest("state-directory"),
            )
            .unwrap()
        };
        (hello, probe)
    }

    fn exchange_with_fixture(
        replay: bool,
        phase: DirectOperationRuntimeAuthorityPhase,
        response: impl FnOnce(
            &DirectOperationRuntimeAuthoritySessionHelloV3,
            &DirectOperationRuntimeAuthorityProbeV3,
        ) -> Vec<u8>
        + Send
        + 'static,
    ) -> AuthorityResult<Infallible> {
        let fixture = runtime_fixture();
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("runtime-authority.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server_binding = fixture.binding.clone();
        let server_binding_sha256 = fixture.binding_sha256.clone();
        let server_custody = fixture.custody.clone();
        let server_adapter = fixture.adapter;
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let challenge = DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
                &server_binding,
                &server_binding_sha256,
                server_adapter,
                &server_custody,
                &digest("daemon-observed-adapter-peer"),
                &digest("daemon-server-nonce"),
            )
            .unwrap();
            write_canonical_frame(&mut stream, &challenge).unwrap();
            let received_hello: DirectOperationRuntimeAuthoritySessionHelloV3 =
                read_canonical_frame(&mut stream).unwrap();
            let received_probe: DirectOperationRuntimeAuthorityProbeV3 =
                read_canonical_frame(&mut stream).unwrap();
            let mut eof = [0_u8; 1];
            assert_eq!(stream.read(&mut eof).unwrap(), 0);
            let encoded = response(&received_hello, &received_probe);
            stream.write_all(&encoded).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });
        let mut connection =
            AuthenticatedAuthorityDaemonConnection::connect_fixture(&socket).unwrap();
        let context = RuntimeAuthorityClientContext {
            binding: &fixture.binding,
            binding_sha256: &fixture.binding_sha256,
            adapter: fixture.adapter,
            custody: &fixture.custody,
        };
        let challenge = read_validated_challenge(&mut connection, &context).unwrap();
        let (hello, probe) = hello_and_probe(&fixture, &challenge, replay);
        let result = SealedRuntimeAuthorityTransportHandoff::establish(
            connection, challenge, hello, probe, phase, &context,
        )
        .and_then(SealedRuntimeAuthorityTransportHandoff::finish_source_disabled_hold);
        server.join().unwrap();
        result
    }

    fn encoded_frame<T: Serialize>(value: &T) -> Vec<u8> {
        let payload = serde_json::to_vec(value).unwrap();
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn exact_first_use_and_replay_holds_are_structured_errors() {
        for (replay, expected_phase) in [
            (false, DirectOperationRuntimeAuthorityPhase::FirstUse),
            (true, DirectOperationRuntimeAuthorityPhase::Replay),
        ] {
            let error = exchange_with_fixture(replay, expected_phase, |hello, probe| {
                encoded_frame(&DirectOperationRuntimeAuthorityHoldV3::derive(hello, probe).unwrap())
            })
            .unwrap_err();
            let DirectOperationRuntimeAuthorityFailure::Hold { phase, response } = error else {
                panic!("exact HOLD was not preserved as a structured error")
            };
            assert_eq!(phase, expected_phase);
            assert_eq!(response.code, contract::HOLD_CODE);
            assert!(!response.retryable);
        }
    }

    #[test]
    fn first_use_and_replay_probe_classes_are_not_interchangeable() {
        let fixture = runtime_fixture();
        let challenge = DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
            &digest("peer"),
            &digest("nonce"),
        )
        .unwrap();
        let (hello, replay_probe) = hello_and_probe(&fixture, &challenge, true);
        let (client, _server) = UnixStream::pair().unwrap();
        let connection = AuthenticatedAuthorityDaemonConnection {
            stream: client,
            endpoint: PathBuf::from("/host-fixture"),
        };
        let context = RuntimeAuthorityClientContext {
            binding: &fixture.binding,
            binding_sha256: &fixture.binding_sha256,
            adapter: fixture.adapter,
            custody: &fixture.custody,
        };
        let error = match SealedRuntimeAuthorityTransportHandoff::establish(
            connection,
            challenge,
            hello,
            replay_probe,
            DirectOperationRuntimeAuthorityPhase::FirstUse,
            &context,
        ) {
            Ok(_) => panic!("replay probe was accepted as first-use"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("not interchangeable"));
    }

    #[test]
    fn sealed_handoff_retains_the_exact_stream_context_and_probe() {
        let fixture = runtime_fixture();
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("runtime-authority-handoff.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server_binding = fixture.binding.clone();
        let server_binding_sha256 = fixture.binding_sha256.clone();
        let server_custody = fixture.custody.clone();
        let server_adapter = fixture.adapter;
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let challenge = DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
                &server_binding,
                &server_binding_sha256,
                server_adapter,
                &server_custody,
                &digest("daemon-observed-adapter-peer"),
                &digest("daemon-server-nonce"),
            )
            .unwrap();
            write_canonical_frame(&mut stream, &challenge).unwrap();
            let hello: DirectOperationRuntimeAuthoritySessionHelloV3 =
                read_canonical_frame(&mut stream).unwrap();
            let probe: DirectOperationRuntimeAuthorityProbeV3 =
                read_canonical_frame(&mut stream).unwrap();
            let mut eof = [0_u8; 1];
            assert_eq!(stream.read(&mut eof).unwrap(), 0);
            let hold = DirectOperationRuntimeAuthorityHoldV3::derive(&hello, &probe).unwrap();
            write_canonical_frame(&mut stream, &hold).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });

        let mut connection =
            AuthenticatedAuthorityDaemonConnection::connect_fixture(&socket).unwrap();
        let context = RuntimeAuthorityClientContext {
            binding: &fixture.binding,
            binding_sha256: &fixture.binding_sha256,
            adapter: fixture.adapter,
            custody: &fixture.custody,
        };
        let challenge = read_validated_challenge(&mut connection, &context).unwrap();
        let (hello, probe) = hello_and_probe(&fixture, &challenge, false);
        let expected_probe = probe.clone();
        let handoff = SealedRuntimeAuthorityTransportHandoff::establish(
            connection,
            challenge,
            hello,
            probe,
            DirectOperationRuntimeAuthorityPhase::FirstUse,
            &context,
        )
        .unwrap();
        assert_eq!(handoff.binding, fixture.binding);
        assert_eq!(handoff.binding_sha256, fixture.binding_sha256);
        assert_eq!(handoff.custody, fixture.custody);
        assert_eq!(handoff.probe_for_test(), &expected_probe);
        handoff.revalidate_exact_request().unwrap();
        let error = handoff.finish_source_disabled_hold().unwrap_err();
        assert!(matches!(
            error,
            DirectOperationRuntimeAuthorityFailure::Hold {
                phase: DirectOperationRuntimeAuthorityPhase::FirstUse,
                ..
            }
        ));
        server.join().unwrap();
    }

    #[test]
    fn response_correlation_mismatch_fails_closed() {
        let error = exchange_with_fixture(
            false,
            DirectOperationRuntimeAuthorityPhase::FirstUse,
            |hello, _| {
                let other_probe = DirectOperationRuntimeAuthorityProbeV3::derive_replay(
                    hello,
                    &digest("other-state-directory"),
                    &"02".repeat(16),
                    &digest("other-journal-identity"),
                    &digest("other-journal-bytes"),
                    &digest("other-sentinel-identity"),
                    &digest("other-sentinel-bytes"),
                    &digest("other-first-use-binding"),
                )
                .unwrap();
                encoded_frame(
                    &DirectOperationRuntimeAuthorityHoldV3::derive(hello, &other_probe).unwrap(),
                )
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("protocol binding failed"));
    }

    #[test]
    fn framing_rejects_short_oversized_noncanonical_unknown_and_trailing_responses() {
        let fixture = runtime_fixture();
        let challenge = DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
            &digest("peer"),
            &digest("nonce"),
        )
        .unwrap();
        let (hello, probe) = hello_and_probe(&fixture, &challenge, false);
        let hold = DirectOperationRuntimeAuthorityHoldV3::derive(&hello, &probe).unwrap();
        let canonical_payload = serde_json::to_vec(&hold).unwrap();

        let cases = [
            {
                let mut frame = Vec::new();
                frame.extend_from_slice(&(canonical_payload.len() as u32).to_be_bytes());
                frame.extend_from_slice(&canonical_payload[..canonical_payload.len() - 1]);
                frame
            },
            {
                let mut frame = Vec::new();
                frame
                    .extend_from_slice(&((contract::MAXIMUM_FRAME_BYTES + 1) as u32).to_be_bytes());
                frame
            },
            {
                let payload = format!(
                    " {} ",
                    String::from_utf8(canonical_payload.clone()).unwrap()
                )
                .into_bytes();
                let mut frame = Vec::new();
                frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                frame.extend_from_slice(&payload);
                frame
            },
            {
                let mut value = serde_json::to_value(&hold).unwrap();
                value
                    .as_object_mut()
                    .unwrap()
                    .insert("authorized".to_string(), serde_json::Value::Bool(true));
                encoded_frame(&value)
            },
            {
                let mut frame = encoded_frame(&hold);
                frame.push(0);
                frame
            },
        ];

        for response in cases {
            assert!(
                exchange_with_fixture(
                    false,
                    DirectOperationRuntimeAuthorityPhase::FirstUse,
                    move |_, _| response,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn duplicate_response_field_and_success_shape_are_rejected() {
        let fixture = runtime_fixture();
        let challenge = DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
            &digest("peer"),
            &digest("nonce"),
        )
        .unwrap();
        let (hello, probe) = hello_and_probe(&fixture, &challenge, false);
        let hold = DirectOperationRuntimeAuthorityHoldV3::derive(&hello, &probe).unwrap();
        let canonical = serde_json::to_string(&hold).unwrap();
        let duplicate = canonical.replacen(
            '{',
            &format!(
                "{{\"schema\":{},",
                serde_json::to_string(&hold.schema).unwrap()
            ),
            1,
        );
        for payload in [
            duplicate.into_bytes(),
            br#"{"authorized":true,"phase":"committed"}"#.to_vec(),
        ] {
            let mut frame = Vec::new();
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(&payload);
            assert!(
                exchange_with_fixture(
                    false,
                    DirectOperationRuntimeAuthorityPhase::FirstUse,
                    move |_, _| frame,
                )
                .is_err()
            );
        }
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn socket_and_activation_domains_remain_separate_and_unwired() {
        assert_eq!(
            contract::SOCKET_ADDRESS,
            format!("@{}", contract::SOCKET_NAME)
        );
        assert_ne!(
            contract::SOCKET_ADDRESS,
            crate::root_publication_transport::DEFAULT_SOCKET
        );
        assert_ne!(
            contract::SOCKET_ADDRESS,
            trillionnium_os_types::direct_operation_tool_call_transport::SOCKET_ADDRESS
        );
        assert!(!contract::SOURCE_LISTENER_IMPLEMENTED);
        assert!(contract::SOURCE_INJECTED_HANDLER_IMPLEMENTED);
        assert!(!contract::EXTERNAL_RUNTIME_AUTHORITY_PRODUCT_AVAILABLE);
        assert!(!contract::ADAPTER_CONNECTOR_PRODUCT_WIRED);
        assert!(!contract::FIRST_USE_PRODUCT_WIRED);
        assert!(!contract::REPLAY_PRODUCT_WIRED);
        assert!(!contract::ANDROID_ACTIVATION_PRODUCT_WIRED);
        assert!(!contract::ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE);
        assert!(!contract::CONFERS_EFFECT_AUTHORITY);
    }

    #[test]
    fn production_source_has_no_selector_or_effect_state_access_and_is_not_wired() {
        let source = include_str!("direct_operation_runtime_authority_transport.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for forbidden in [
            "UnixListener",
            "RawFd",
            "AsRawFd",
            "from_raw_fd",
            "std::env",
            "args_os",
            "vars_os",
            "connect_addr",
            "VerifiedAdapterPeerIdentitySha256",
            "session_nonce_sha256",
            "operation_journal",
            "direct_tool_call_allocator",
            "android_operation_replay",
        ] {
            assert!(
                !production.contains(forbidden),
                "production source unexpectedly contains {forbidden}"
            );
        }
        let handoff = production
            .split_once("pub(crate) struct SealedRuntimeAuthorityTransportHandoff")
            .unwrap()
            .1;
        let declaration = handoff.split_once('}').unwrap().0;
        assert!(declaration.contains("AuthenticatedAuthorityDaemonConnection"));
        assert!(declaration.contains("DirectOperationRuntimeAuthorityProbeV3"));
        let preceding = &production[..production
            .find("pub(crate) struct SealedRuntimeAuthorityTransportHandoff")
            .unwrap()];
        assert!(!preceding.ends_with("#[derive(Clone)]\n"));
        for forbidden in [
            "impl Clone for SealedRuntimeAuthorityTransportHandoff",
            "impl Serialize for SealedRuntimeAuthorityTransportHandoff",
            "from_abi",
            "from_probe",
            "into_parts",
        ] {
            assert!(!production.contains(forbidden), "{forbidden}");
        }

        let lib = include_str!("lib.rs");
        assert!(lib.contains("mod direct_operation_runtime_authority_transport;"));
        assert!(!lib.contains("pub mod direct_operation_runtime_authority_transport;"));
        for binary in [
            include_str!("bin/system_api.rs"),
            include_str!("bin/accessibility.rs"),
            include_str!("bin/adb.rs"),
            include_str!("bin/system_api_replay_sync.rs"),
        ] {
            assert!(!binary.contains("direct_operation_runtime_authority_transport"));
        }
    }

    #[test]
    fn client_rejects_a_canonical_challenge_for_another_context() {
        let fixture = runtime_fixture();
        let mut challenge = DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
            &digest("daemon-observed-peer"),
            &digest("daemon-nonce"),
        )
        .unwrap();
        challenge.binding_sha256 = digest("other-binding");
        challenge.challenge_sha256 = challenge.canonical_sha256().unwrap();

        let (mut daemon, client) = UnixStream::pair().unwrap();
        let server = thread::spawn(move || {
            write_canonical_frame(&mut daemon, &challenge).unwrap();
            daemon.shutdown(Shutdown::Write).unwrap();
        });
        let mut connection = AuthenticatedAuthorityDaemonConnection {
            stream: client,
            endpoint: PathBuf::from("/host-fixture"),
        };
        let context = RuntimeAuthorityClientContext {
            binding: &fixture.binding,
            binding_sha256: &fixture.binding_sha256,
            adapter: fixture.adapter,
            custody: &fixture.custody,
        };
        let error = read_validated_challenge(&mut connection, &context).unwrap_err();
        assert!(error.to_string().contains("protocol binding failed"));
        server.join().unwrap();
    }

    #[test]
    fn daemon_nonce_changes_the_challenge_and_client_echo() {
        let fixture = runtime_fixture();
        let challenge_one = DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
            &digest("daemon-observed-peer"),
            &digest("daemon-nonce-one"),
        )
        .unwrap();
        let challenge_two = DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
            &digest("daemon-observed-peer"),
            &digest("daemon-nonce-two"),
        )
        .unwrap();
        let (hello_one, _) = hello_and_probe(&fixture, &challenge_one, false);
        let (hello_two, _) = hello_and_probe(&fixture, &challenge_two, false);
        assert_ne!(
            challenge_one.challenge_sha256,
            challenge_two.challenge_sha256
        );
        assert_ne!(hello_one.hello_sha256, hello_two.hello_sha256);
        assert!(
            hello_one
                .validate_for(
                    &challenge_two,
                    &fixture.binding,
                    &fixture.binding_sha256,
                    fixture.adapter,
                    &fixture.custody,
                )
                .is_err()
        );
    }
}
