//! Source-only HOLD handler for the independent Direct operation-runtime
//! authority carrier.
//!
//! This module accepts only a single object which owns both an already-
//! connected stream and the peer proof measured from that exact stream. After
//! the closed challenge/hello/probe exchange, it seals that same connection,
//! peer proof, request context, and observation into one move-only backend
//! handoff. It never binds or connects a socket, constructs an external
//! authority, or reads allocator, journal, custody-store, or Android state.
//! The only product-shaped response in the V3 contract is the exact,
//! non-retryable external-authority-unavailable HOLD.

use std::io::{Read, Write};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use trillionnium_os_types::direct_operation::{
    DirectOperationAdapter, DirectOperationBinding, DirectOperationKernelLaunchCustodyV3,
};
use trillionnium_os_types::direct_operation_runtime_authority::{
    self as contract, DirectOperationRuntimeAuthorityHoldV3,
    DirectOperationRuntimeAuthorityProbeV3, DirectOperationRuntimeAuthoritySessionChallengeV3,
    DirectOperationRuntimeAuthoritySessionHelloV3,
};

use crate::direct_tool_call_transport::AuthenticatedAdapterAuthorityConnection;

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

/// Move-only input candidate for a future external runtime-authority backend.
///
/// The authenticated socket carrier remains embedded alongside the complete
/// daemon challenge and adapter request. Consequently, bare ABI records cannot
/// be replayed into a different process connection or launch-custody context.
/// This type is not store, first-use, replay, mutation, or effect authority;
/// the current contract can consume it only into a terminal HOLD.
pub(crate) struct AuthenticatedRuntimeAuthorityBackendHandoff {
    connection: AuthenticatedAdapterAuthorityConnection,
    binding: DirectOperationBinding,
    binding_sha256: String,
    adapter: DirectOperationAdapter,
    custody: DirectOperationKernelLaunchCustodyV3,
    challenge: DirectOperationRuntimeAuthoritySessionChallengeV3,
    hello: DirectOperationRuntimeAuthoritySessionHelloV3,
    probe: DirectOperationRuntimeAuthorityProbeV3,
}

/// Serve one injected, already-authenticated source session.
///
/// Revalidating the retained pidfd peer at every message boundary prevents a
/// connection authenticated before an exec, cgroup, SELinux, start-time, boot,
/// or executable transition from receiving even the fixed HOLD as if it were
/// still the measured adapter. There is deliberately no success response.
pub(crate) fn serve_source_disabled_hold(
    connection: AuthenticatedAdapterAuthorityConnection,
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    custody: &DirectOperationKernelLaunchCustodyV3,
) -> Result<DirectOperationRuntimeAuthorityHoldV3> {
    AuthenticatedRuntimeAuthorityBackendHandoff::receive_source_disabled(
        connection,
        binding,
        binding_sha256,
        adapter,
        custody,
    )?
    .finish_source_disabled_hold()
}

impl AuthenticatedRuntimeAuthorityBackendHandoff {
    /// Receive one complete request while retaining the exact authenticated
    /// connection. No constructor accepts a challenge, hello, probe, or peer
    /// digest without the live socket carrier that produced them.
    pub(crate) fn receive_source_disabled(
        mut connection: AuthenticatedAdapterAuthorityConnection,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
    ) -> Result<Self> {
        require_source_disabled_contract()?;
        connection.validate_for(binding, binding_sha256, adapter, custody)?;
        connection.set_session_timeouts(SESSION_TIMEOUT)?;

        let mut nonce = [0_u8; 32];
        fill_kernel_random(&mut nonce)?;
        let server_nonce_sha256 = trillionnium_os_types::sha256_bytes(&nonce);
        let adapter_peer_identity_sha256 = connection.peer_identity_sha256().to_string();
        let challenge = DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
            binding,
            binding_sha256,
            adapter,
            custody,
            &adapter_peer_identity_sha256,
            &server_nonce_sha256,
        )
        .map_err(|error| anyhow!(error.to_string()))?;
        write_canonical_frame(&mut connection, &challenge)?;
        connection.validate_for(binding, binding_sha256, adapter, custody)?;

        let hello: DirectOperationRuntimeAuthoritySessionHelloV3 =
            read_canonical_frame(&mut connection)?;
        hello
            .validate_for(&challenge, binding, binding_sha256, adapter, custody)
            .map_err(|error| anyhow!(error.to_string()))?;
        connection.validate_for(binding, binding_sha256, adapter, custody)?;

        let probe: DirectOperationRuntimeAuthorityProbeV3 = read_canonical_frame(&mut connection)?;
        probe
            .validate_for_hello(&hello)
            .map_err(|error| anyhow!(error.to_string()))?;
        require_peer_write_eof(&mut connection)?;
        connection.validate_for(binding, binding_sha256, adapter, custody)?;

        let handoff = Self {
            connection,
            binding: binding.clone(),
            binding_sha256: binding_sha256.to_string(),
            adapter,
            custody: custody.clone(),
            challenge,
            hello,
            probe,
        };
        handoff.revalidate_exact_request()?;
        Ok(handoff)
    }

    fn revalidate_exact_request(&self) -> Result<()> {
        self.connection.validate_for(
            &self.binding,
            &self.binding_sha256,
            self.adapter,
            &self.custody,
        )?;
        self.challenge
            .validate_for(
                &self.binding,
                &self.binding_sha256,
                self.adapter,
                &self.custody,
                self.connection.peer_identity_sha256(),
                &self.challenge.server_nonce_sha256,
            )
            .map_err(|error| anyhow!(error.to_string()))?;
        self.hello
            .validate_for(
                &self.challenge,
                &self.binding,
                &self.binding_sha256,
                self.adapter,
                &self.custody,
            )
            .map_err(|error| anyhow!(error.to_string()))?;
        self.probe
            .validate_for_hello(&self.hello)
            .map_err(|error| anyhow!(error.to_string()))
    }

    /// The only response transition available while the product backend and
    /// successful response vocabulary remain absent.
    fn finish_source_disabled_hold(mut self) -> Result<DirectOperationRuntimeAuthorityHoldV3> {
        self.revalidate_exact_request()?;
        let hold = DirectOperationRuntimeAuthorityHoldV3::derive(&self.hello, &self.probe)
            .map_err(|error| anyhow!(error.to_string()))?;
        write_canonical_frame(&mut self.connection, &hold)?;
        self.connection
            .flush()
            .context("direct_runtime_authority_hold_flush_denied")?;
        self.revalidate_exact_request()?;
        Ok(hold)
    }

    #[cfg(test)]
    fn probe_for_test(&self) -> &DirectOperationRuntimeAuthorityProbeV3 {
        &self.probe
    }
}

fn require_source_disabled_contract() -> Result<()> {
    if !contract::SOURCE_CLIENT_IMPLEMENTED
        || contract::SOURCE_LISTENER_IMPLEMENTED
        || !contract::SOURCE_INJECTED_HANDLER_IMPLEMENTED
        || !contract::SOURCE_HOLD_RESPONSE_IMPLEMENTED
        || contract::EXTERNAL_RUNTIME_AUTHORITY_PRODUCT_AVAILABLE
        || contract::DAEMON_LISTENER_PRODUCT_WIRED
        || contract::ADAPTER_CONNECTOR_PRODUCT_WIRED
        || contract::AUTHORITY_BACKEND_PRODUCT_WIRED
        || contract::FIRST_USE_DECISION_PRODUCT_AVAILABLE
        || contract::REPLAY_DECISION_PRODUCT_AVAILABLE
        || contract::FIRST_USE_PRODUCT_WIRED
        || contract::REPLAY_PRODUCT_WIRED
        || contract::MUTATION_CAS_PRODUCT_AVAILABLE
        || contract::ACTIVATION_PRODUCT_WIRED
        || contract::ANDROID_ACTIVATION_PRODUCT_WIRED
        || contract::ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE
        || contract::CONFERS_EFFECT_AUTHORITY
    {
        bail!("direct_runtime_authority_source_disabled_contract_denied");
    }
    Ok(())
}

fn write_canonical_frame<T: Serialize>(stream: &mut impl Write, value: &T) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    if payload.is_empty() || payload.len() > contract::MAXIMUM_FRAME_BYTES {
        bail!("direct_runtime_authority_output_frame_denied");
    }
    let length =
        u32::try_from(payload.len()).context("direct_runtime_authority_output_length_denied")?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

fn read_canonical_frame<T: DeserializeOwned + Serialize>(stream: &mut impl Read) -> Result<T> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .context("direct_runtime_authority_input_prefix_denied")?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > contract::MAXIMUM_FRAME_BYTES {
        bail!("direct_runtime_authority_input_length_denied");
    }
    let mut payload = vec![0_u8; length];
    stream
        .read_exact(&mut payload)
        .context("direct_runtime_authority_input_payload_denied")?;
    let value: T =
        serde_json::from_slice(&payload).context("direct_runtime_authority_input_json_denied")?;
    if serde_json::to_vec(&value)? != payload {
        bail!("direct_runtime_authority_input_not_canonical");
    }
    Ok(value)
}

fn require_peer_write_eof(stream: &mut impl Read) -> Result<()> {
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing)? != 0 {
        bail!("direct_runtime_authority_trailing_frame_denied");
    }
    Ok(())
}

fn fill_kernel_random(bytes: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < bytes.len() {
        let read = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if read > 0 {
            filled += usize::try_from(read)
                .context("direct_runtime_authority_getrandom_length_denied")?;
            continue;
        }
        if read == 0 {
            bail!("direct_runtime_authority_getrandom_eof");
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("direct_runtime_authority_getrandom_denied");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::thread;

    use trillionnium_os_types::direct_operation::{
        BINDING_SCHEMA, DirectOperationProviderAttempt, DirectOperationStableSeed,
        KERNEL_LAUNCH_CUSTODY_KIND_V3, KERNEL_LAUNCH_CUSTODY_PRODUCER_V3,
        KERNEL_LAUNCH_CUSTODY_V3_SCHEMA, STABLE_SEED_SCHEMA, adapter_binary_kind,
        fixed_adapter_cgroup_path,
    };
    use trillionnium_os_types::direct_operation_runtime_authority::{
        DirectOperationRuntimeAuthorityObservationV3, HOLD_CODE,
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
            task_id: "task.runtime-authority-daemon".to_string(),
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

    fn spawn_session(
        fixture: &RuntimeFixture,
    ) -> (
        UnixStream,
        thread::JoinHandle<Result<DirectOperationRuntimeAuthorityHoldV3>>,
    ) {
        let (client, server) = UnixStream::pair().unwrap();
        let connection = AuthenticatedAdapterAuthorityConnection::for_host_fixture_test(
            server,
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
        )
        .unwrap();
        let binding = fixture.binding.clone();
        let binding_sha256 = fixture.binding_sha256.clone();
        let adapter = fixture.adapter;
        let custody = fixture.custody.clone();
        let handle = thread::spawn(move || {
            serve_source_disabled_hold(connection, &binding, &binding_sha256, adapter, &custody)
        });
        (client, handle)
    }

    fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) {
        write_canonical_frame(stream, value).unwrap();
    }

    fn encoded_frame<T: Serialize>(value: &T) -> Vec<u8> {
        let payload = serde_json::to_vec(value).unwrap();
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    fn encoded_payload(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn injected_session_returns_only_exact_nonretryable_hold() {
        let mut prior_server_nonce = None;
        for replay in [false, true] {
            let fixture = runtime_fixture();
            let (mut client, server) = spawn_session(&fixture);
            let challenge: DirectOperationRuntimeAuthoritySessionChallengeV3 =
                read_canonical_frame(&mut client).unwrap();
            challenge
                .validate_client_context(
                    &fixture.binding,
                    &fixture.binding_sha256,
                    fixture.adapter,
                    &fixture.custody,
                )
                .unwrap();
            if let Some(prior) = prior_server_nonce.replace(challenge.server_nonce_sha256.clone()) {
                assert_ne!(prior, challenge.server_nonce_sha256);
            }
            let hello = DirectOperationRuntimeAuthoritySessionHelloV3::derive(
                &challenge,
                &fixture.binding,
                &fixture.binding_sha256,
                fixture.adapter,
                &fixture.custody,
            )
            .unwrap();
            let probe = if replay {
                DirectOperationRuntimeAuthorityProbeV3::derive_replay(
                    &hello,
                    &digest("directory"),
                    "0123456789abcdef0123456789abcdef",
                    &digest("journal-identity"),
                    &digest("journal-bytes"),
                    &digest("sentinel-identity"),
                    &digest("sentinel-bytes"),
                    &digest("first-use-result"),
                )
                .unwrap()
            } else {
                DirectOperationRuntimeAuthorityProbeV3::derive_first_use(
                    &hello,
                    &digest("directory"),
                )
                .unwrap()
            };
            write_frame(&mut client, &hello);
            write_frame(&mut client, &probe);
            client.shutdown(Shutdown::Write).unwrap();
            let hold: DirectOperationRuntimeAuthorityHoldV3 =
                read_canonical_frame(&mut client).unwrap();
            assert_eq!(hold.code, HOLD_CODE);
            assert!(!hold.retryable);
            hold.validate_for(&hello, &probe).unwrap();
            let mut trailing = [0_u8; 1];
            assert_eq!(client.read(&mut trailing).unwrap(), 0);
            assert_eq!(server.join().unwrap().unwrap(), hold);
            assert!(matches!(
                probe.observation,
                DirectOperationRuntimeAuthorityObservationV3::FirstUse { .. }
                    | DirectOperationRuntimeAuthorityObservationV3::Replay { .. }
            ));
        }
    }

    #[test]
    fn backend_handoff_retains_authenticated_stream_context_and_probe() {
        let fixture = runtime_fixture();
        let (mut client, server_stream) = UnixStream::pair().unwrap();
        let connection = AuthenticatedAdapterAuthorityConnection::for_host_fixture_test(
            server_stream,
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
        )
        .unwrap();
        let binding = fixture.binding.clone();
        let binding_sha256 = fixture.binding_sha256.clone();
        let adapter = fixture.adapter;
        let custody = fixture.custody.clone();
        let receiver = thread::spawn(move || {
            AuthenticatedRuntimeAuthorityBackendHandoff::receive_source_disabled(
                connection,
                &binding,
                &binding_sha256,
                adapter,
                &custody,
            )
        });

        let challenge: DirectOperationRuntimeAuthoritySessionChallengeV3 =
            read_canonical_frame(&mut client).unwrap();
        let hello = DirectOperationRuntimeAuthoritySessionHelloV3::derive(
            &challenge,
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
        )
        .unwrap();
        let probe =
            DirectOperationRuntimeAuthorityProbeV3::derive_first_use(&hello, &digest("directory"))
                .unwrap();
        write_frame(&mut client, &hello);
        write_frame(&mut client, &probe);
        client.shutdown(Shutdown::Write).unwrap();

        let handoff = receiver.join().unwrap().unwrap();
        assert_eq!(handoff.binding, fixture.binding);
        assert_eq!(handoff.binding_sha256, fixture.binding_sha256);
        assert_eq!(handoff.custody, fixture.custody);
        assert_eq!(handoff.probe_for_test(), &probe);
        handoff.revalidate_exact_request().unwrap();
        let hold = handoff.finish_source_disabled_hold().unwrap();
        let received: DirectOperationRuntimeAuthorityHoldV3 =
            read_canonical_frame(&mut client).unwrap();
        assert_eq!(received, hold);
        received.validate_for(&hello, &probe).unwrap();
        let mut trailing = [0_u8; 1];
        assert_eq!(client.read(&mut trailing).unwrap(), 0);
    }

    #[test]
    fn malformed_or_uncorrelated_messages_hold_before_response() {
        let fixture = runtime_fixture();
        let (mut client, server) = spawn_session(&fixture);
        let retained_challenge: DirectOperationRuntimeAuthoritySessionChallengeV3 =
            read_canonical_frame(&mut client).unwrap();
        let mut wrong_challenge = retained_challenge.clone();
        wrong_challenge.adapter_peer_identity_sha256 = digest("wrong-peer");
        wrong_challenge.challenge_sha256 = wrong_challenge.canonical_sha256().unwrap();
        let wrong_hello = DirectOperationRuntimeAuthoritySessionHelloV3::derive(
            &wrong_challenge,
            &fixture.binding,
            &fixture.binding_sha256,
            fixture.adapter,
            &fixture.custody,
        )
        .unwrap();
        let probe = DirectOperationRuntimeAuthorityProbeV3::derive_first_use(
            &wrong_hello,
            &digest("directory"),
        )
        .unwrap();
        write_frame(&mut client, &wrong_hello);
        write_frame(&mut client, &probe);
        client.shutdown(Shutdown::Write).unwrap();
        assert!(server.join().unwrap().is_err());
    }

    #[test]
    fn input_framing_rejects_short_oversized_noncanonical_unknown_and_trailing_bytes() {
        for case in 0..6 {
            let fixture = runtime_fixture();
            let (mut client, server) = spawn_session(&fixture);
            let challenge: DirectOperationRuntimeAuthoritySessionChallengeV3 =
                read_canonical_frame(&mut client).unwrap();
            let hello = DirectOperationRuntimeAuthoritySessionHelloV3::derive(
                &challenge,
                &fixture.binding,
                &fixture.binding_sha256,
                fixture.adapter,
                &fixture.custody,
            )
            .unwrap();
            let probe = DirectOperationRuntimeAuthorityProbeV3::derive_first_use(
                &hello,
                &digest("directory"),
            )
            .unwrap();
            let bytes = match case {
                0 => vec![0, 0, 0, 0],
                1 => ((contract::MAXIMUM_FRAME_BYTES + 1) as u32)
                    .to_be_bytes()
                    .to_vec(),
                2 => {
                    let mut frame = 10_u32.to_be_bytes().to_vec();
                    frame.extend_from_slice(b"{}");
                    frame
                }
                3 => {
                    let canonical_hello = serde_json::to_vec(&hello).unwrap();
                    let noncanonical_hello =
                        format!(" {} ", String::from_utf8(canonical_hello).unwrap()).into_bytes();
                    encoded_payload(&noncanonical_hello)
                }
                4 => {
                    let mut unknown_hello = serde_json::to_value(&hello).unwrap();
                    unknown_hello
                        .as_object_mut()
                        .unwrap()
                        .insert("authorized".to_string(), serde_json::Value::Bool(true));
                    encoded_frame(&unknown_hello)
                }
                5 => {
                    let mut trailing = encoded_frame(&hello);
                    trailing.extend_from_slice(&encoded_frame(&probe));
                    trailing.push(0);
                    trailing
                }
                _ => unreachable!(),
            };
            client.write_all(&bytes).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            assert!(server.join().unwrap().is_err());
        }
    }

    #[test]
    fn production_module_has_no_listener_selector_or_state_access() {
        let source = include_str!("direct_operation_runtime_authority_transport.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for forbidden in [
            "UnixListener",
            "bind(",
            "connect(",
            "std::env",
            "RawFd",
            "operation_journal",
            "direct_tool_call_allocator",
            "direct_operation_custody",
            "android_operation_replay",
        ] {
            assert!(
                !production.contains(forbidden),
                "source-only handler unexpectedly contains {forbidden}"
            );
        }
        let declaration = production
            .split_once("pub(crate) struct AuthenticatedRuntimeAuthorityBackendHandoff")
            .unwrap()
            .1
            .split_once('}')
            .unwrap()
            .0;
        assert!(declaration.contains("AuthenticatedAdapterAuthorityConnection"));
        assert!(declaration.contains("DirectOperationRuntimeAuthorityProbeV3"));
        for forbidden in [
            "impl Clone for AuthenticatedRuntimeAuthorityBackendHandoff",
            "impl Serialize for AuthenticatedRuntimeAuthorityBackendHandoff",
            "from_abi",
            "from_probe",
            "into_parts",
        ] {
            assert!(!production.contains(forbidden), "{forbidden}");
        }

        let main = include_str!("main.rs");
        assert!(main.contains("mod direct_operation_runtime_authority_transport;"));
        assert!(!main.contains("serve_source_disabled_hold("));
    }
}
