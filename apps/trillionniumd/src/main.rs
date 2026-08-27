use std::collections::HashMap;
use std::env;
use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
#[cfg(test)]
use std::io::{BufRead, BufReader};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use trillionnium_agent_api_uds::{
    AGENT_API_CHANNEL_AUTH_SCHEMA, AGENT_API_UDS_PROTOCOL, DEFAULT_AGENT_API_SOCKET,
    MAX_AGENT_API_FRAME_BYTES, is_enabled_agent_api_method, requires_channel_binding,
};
use trillionnium_audit_sqlite::AuditStore;
use trillionnium_dbus::AgentService;
use trillionnium_os_types::agent_principal_registry::CODEX_STABLE_PRINCIPAL as CODEX;
use trillionnium_os_types::direct_agent_host_abi;
use trillionnium_os_types::{
    AGENT_API_VERSION, AgentRegistration, TaskInput, TaskStatus, sha256_json, sha256_reader,
};
#[cfg(any(test, feature = "legacy-plan-conformance"))]
use trillionnium_os_types::{AgentExecutionRequest, AgentPlanSubmission};
use trillionnium_tool_runtime::supervised_codex::CodexCapabilityIdentity;
mod action_workflow;
mod android_agent_api;
mod builtin_provider_identity;
mod capability_hardening;
#[path = "providers/codex.rs"]
mod codex_adapter;
mod context_memory;
mod direct_operation_binding_inbox;
// Source-only allocator PREPARED receipt -> Android ACK/replay custody seam;
// production main deliberately does not bind or instantiate it.
#[allow(dead_code)]
mod android_ack_replay_bridge;
// Source-only injected HOLD carrier for the independent operation-runtime
// authority. There is deliberately no listener, dispatch, or product call.
#[allow(dead_code)]
mod direct_operation_runtime_authority_transport;
// Source-compiled pre-effect bridge to one fixed external rollback high-water
// authority. Production main deliberately does not connect, admit a provider
// delivery, bind the listener, or dispatch an effect.
#[allow(dead_code)]
mod direct_tool_call_high_water;
mod direct_tool_call_transport;
// Deliberately compiled but not opened or instantiated by production yet.
// The custody store remains inert until reviewed daemon-owned binding,
// terminal-egress, UI-replay, and authenticated adapter handoff sources exist.
#[allow(dead_code)]
mod direct_operation_custody;
// Durable logical-call identity is implemented and crash-tested, but remains
// inert until the Codex delivery transport carries a daemon-issued token
// over a root-authenticated channel. Capability-lease replay-sync is not an
// Android operation-epoch activation/ACK route and cannot enable this module.
#[allow(dead_code)]
mod direct_tool_call_allocator;
#[path = "providers/egress_journal.rs"]
mod egress_journal;
#[path = "providers/contract.rs"]
mod provider_contract;
#[path = "providers/replay.rs"]
mod replay_store;
#[cfg(test)]
mod uds_transport_tests;

use context_memory::{AgentGrantConsumer, ContextMemoryService, Subject};
use replay_store::{AgentApiReplayStore, ReplayDecision, ReplayIdentity};

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [] => run_agent_api_uds(),
        [flag] if flag == "--agent-api-uds" => run_agent_api_uds(),
        _ => bail!(
            "usage: trillionniumd [--agent-api-uds]\ndefault with no arguments serves the OS Agent API control plane"
        ),
    }
}

fn codex_provider(
    secret: [u8; 32],
    registration: &AgentRegistration,
) -> Result<codex_adapter::CodexAdapter> {
    let capability_identity = CodexCapabilityIdentity {
        agent_peer_uid: registration.peer_uid,
        agent_peer_gid: registration.peer_gid,
        agent_executable_sha256: registration.identity_key_sha256.clone(),
        final_runtime_executable_sha256: env!("TRILLIONNIUM_P01_CODEX_RUNTIME_SHA256").to_string(),
        agent_manifest_sha256: sha256_json(&serde_json::to_value(registration)?),
    };
    // The device-conformance feature selects the bounded tool action and
    // evidence lane only; it must never replace production provider admission.
    codex_adapter::CodexAdapter::new_bound(
        codex_adapter::config_from_env()?,
        secret,
        capability_identity,
    )
}

const DEFAULT_AGENT_MANIFEST_DIR: &str = "/system_ext/etc/trillionnium/agents";
#[cfg(test)]
const BUILTIN_CODEX_AGENT_ID: &str = CODEX.agent_id;
const MAX_AGENT_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_AGENT_MANIFESTS: usize = 256;
const MAX_AGENT_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const AGENT_API_WORKERS: usize = 8;
const AGENT_API_QUEUE_DEPTH: usize = 16;
const AGENT_API_PER_UID_CONNECTION_LIMIT: usize = 4;
const AGENT_API_READ_TIMEOUT: Duration = Duration::from_secs(10);
const AGENT_API_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const AGENT_API_SOCKET_MODE: u32 = 0o660;
const AGENT_API_SOCKET_PARENT_MODE: u32 = 0o750;
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 107;
const OS_SUPERVISED_AGENT_DISPATCH_ORIGIN: &str = "trillionnium.os-supervised-agent-dispatch.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentPeerIdentity {
    pid: u32,
    uid: u32,
    gid: u32,
    process_start_time_ticks: u64,
    selinux_domain: String,
    executable_dev: u64,
    executable_ino: u64,
    executable_uid: u32,
    executable_gid: u32,
    executable_mode: u32,
    executable_sha256: String,
}

/// Authentication evidence accepted by the provider-neutral Agent API state
/// dispatcher.
///
/// The UDS carrier supplies a kernel-measured process principal. The Android
/// built-in-provider workflow cannot honestly claim that carrier yet: the OS
/// daemon supervises the provider process and receives its plan through the
/// adapter. It therefore enters through an explicit OS-supervised port bound
/// to the exact provisioned AgentManifest. Both ports converge before any plan
/// is accepted or action is dispatched.
#[derive(Debug, Clone, Copy)]
enum AgentDispatchAuthentication<'a> {
    KernelUds {
        agent_id: &'a str,
        peer: &'a AgentPeerIdentity,
    },
    OsSupervisedProvider {
        registration: &'a AgentRegistration,
        executable: &'a AgentExecutableDispatchIdentity,
        origin: Option<AgentDispatchOrigin<'a>>,
    },
}

#[derive(Debug, Clone, Copy)]
struct AgentDispatchOrigin<'a> {
    uid: u32,
    selinux_domain: &'a str,
    subject_user_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenedExecutableIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    sha256: String,
    stability: ExecutableFileStability,
}

/// Immutable executable-path measurement used only by the transitional
/// OS-supervised dispatch port. This is a policy binding, not evidence that a
/// child executed this inode; the production Agent host must replace it with
/// kernel-authenticated UDS identity plus exact-FD supervisor evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentExecutableDispatchIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    sha256: String,
}

impl From<&OpenedExecutableIdentity> for AgentExecutableDispatchIdentity {
    fn from(value: &OpenedExecutableIdentity) -> Self {
        Self {
            dev: value.dev,
            ino: value.ino,
            uid: value.uid,
            gid: value.gid,
            mode: value.mode,
            sha256: value.sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutableFileStability {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[derive(Debug)]
struct MeasuredAgentPeer {
    identity: AgentPeerIdentity,
    executable_stability: ExecutableFileStability,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentApiUdsRequestEnvelope {
    protocol: String,
    request_id: String,
    method: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default = "empty_json_object")]
    payload: Value,
    #[serde(default)]
    channel_binding: Option<AgentApiChannelBinding>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentApiChannelBinding {
    schema: String,
    nonce: String,
    request_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnixMessageCredentials {
    pid: u32,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelTaskPayload {
    task_id: String,
}

fn empty_json_object() -> Value {
    Value::Object(serde_json::Map::new())
}

/// Parse a request frame without ever collapsing duplicate object members.
///
/// `serde_json::Value` normally keeps only the last copy of a duplicate key.
/// That is unsafe at an authorization boundary because two implementations can
/// bind different values from the same bytes. This parser preserves the normal
/// JSON number surface (including finite floats) while rejecting duplicate keys
/// recursively before any method-specific interpretation occurs.
fn parse_request_json(encoded: &[u8], boundary: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(encoded);
    let UniqueRequestJson(value) = UniqueRequestJson::deserialize(&mut deserializer)
        .map_err(|error| anyhow::anyhow!("{boundary}_invalid_or_duplicate_json: {error}"))?;
    deserializer
        .end()
        .map_err(|error| anyhow::anyhow!("{boundary}_trailing_data: {error}"))?;
    Ok(value)
}

struct UniqueRequestJson(Value);

impl<'de> Deserialize<'de> for UniqueRequestJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_any(UniqueRequestJsonVisitor)
            .map(UniqueRequestJson)
    }
}

struct UniqueRequestJsonVisitor;

impl<'de> Visitor<'de> for UniqueRequestJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueRequestJson::deserialize(deserializer).map(|value| value.0)
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueRequestJson>()? {
            output.push(value.0);
        }
        Ok(Value::Array(output))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if output.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate key {key}")));
            }
            let value = map.next_value::<UniqueRequestJson>()?;
            output.insert(key, value.0);
        }
        Ok(Value::Object(output))
    }
}

fn parse_agent_api_uds_request(frame: &[u8]) -> Result<AgentApiUdsRequestEnvelope> {
    let value = parse_request_json(frame, "agent_api_request")?;
    let request: AgentApiUdsRequestEnvelope = serde_json::from_value(value)
        .map_err(|error| anyhow::anyhow!("agent_api_request_envelope_denied: {error}"))?;
    if request.protocol != AGENT_API_UDS_PROTOCOL {
        bail!("unsupported Agent API UDS protocol");
    }
    if !request.payload.is_object() {
        bail!("agent_api_request_payload_not_object");
    }
    Ok(request)
}

fn parse_cancel_task_payload(payload: Value) -> Result<String> {
    let request: CancelTaskPayload = serde_json::from_value(payload)
        .map_err(|error| anyhow::anyhow!("cancel_task_payload_denied: {error}"))?;
    Ok(request.task_id)
}

type SharedReplayStore = Arc<Mutex<AgentApiReplayStore>>;

struct AgentConnectionPool {
    sender: SyncSender<QueuedAgentConnection>,
    per_uid_in_flight: Arc<Mutex<HashMap<u32, usize>>>,
    per_uid_limit: usize,
}

#[derive(Debug, Clone)]
struct AgentConnectionPoolConfig {
    workers: usize,
    queue_depth: usize,
    per_uid_limit: usize,
    read_timeout: Duration,
    write_timeout: Duration,
    #[cfg(test)]
    worker_test_barrier: Option<AgentPoolWorkerTestBarrier>,
}

struct QueuedAgentConnection {
    stream: UnixStream,
    _admission: AgentConnectionAdmission,
}

struct AgentConnectionAdmission {
    uid: u32,
    counts: Arc<Mutex<HashMap<u32, usize>>>,
}

impl Drop for AgentConnectionAdmission {
    fn drop(&mut self) {
        let Ok(mut counts) = self.counts.lock() else {
            return;
        };
        let Some(count) = counts.get_mut(&self.uid) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&self.uid);
        }
    }
}

#[derive(Debug)]
struct AgentConnectionRejection {
    stream: UnixStream,
    reason: &'static str,
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct AgentPoolWorkerTestBarrier {
    entered: SyncSender<()>,
    released: Arc<(Mutex<bool>, std::sync::Condvar)>,
}

#[cfg(test)]
struct InstalledAgentPoolWorkerTestBarrier {
    released: Arc<(Mutex<bool>, std::sync::Condvar)>,
}

#[cfg(test)]
impl Drop for InstalledAgentPoolWorkerTestBarrier {
    fn drop(&mut self) {
        let (released, condition) = &*self.released;
        if let Ok(mut released) = released.lock() {
            *released = true;
            condition.notify_all();
        }
    }
}

#[cfg(test)]
fn new_agent_pool_worker_test_barrier() -> (
    InstalledAgentPoolWorkerTestBarrier,
    AgentPoolWorkerTestBarrier,
    std::sync::mpsc::Receiver<()>,
) {
    let (entered, observed) = sync_channel(1);
    let released = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let barrier = AgentPoolWorkerTestBarrier {
        entered,
        released: Arc::clone(&released),
    };
    (
        InstalledAgentPoolWorkerTestBarrier { released },
        barrier,
        observed,
    )
}

#[cfg(test)]
fn wait_at_agent_pool_worker_test_barrier(barrier: Option<&AgentPoolWorkerTestBarrier>) {
    let Some(barrier) = barrier else {
        return;
    };
    let _ = barrier.entered.send(());
    let (released, condition) = &*barrier.released;
    if let Ok(released) = released.lock() {
        drop(condition.wait_while(released, |released| !*released));
    }
}

impl AgentConnectionPool {
    fn spawn(
        service: Arc<AgentService>,
        replay: SharedReplayStore,
        context_memory: Arc<ContextMemoryService>,
        config: AgentConnectionPoolConfig,
    ) -> Result<Self> {
        if config.workers == 0 || config.queue_depth == 0 || config.per_uid_limit == 0 {
            bail!("Agent API worker, queue, and per-UID bounds must be non-zero");
        }
        let (sender, receiver) = sync_channel::<QueuedAgentConnection>(config.queue_depth);
        let receiver = Arc::new(Mutex::new(receiver));
        let per_uid_in_flight = Arc::new(Mutex::new(HashMap::new()));
        for index in 0..config.workers {
            let service = Arc::clone(&service);
            let replay = Arc::clone(&replay);
            let context_memory = Arc::clone(&context_memory);
            let receiver = Arc::clone(&receiver);
            #[cfg(test)]
            let worker_test_barrier = config.worker_test_barrier.clone();
            let read_timeout = config.read_timeout;
            let write_timeout = config.write_timeout;
            std::thread::Builder::new()
                .name(format!("agent-api-{index}"))
                .spawn(move || {
                    loop {
                        let stream = match receiver.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        let Ok(connection) = stream else {
                            return;
                        };
                        let QueuedAgentConnection {
                            mut stream,
                            _admission,
                        } = connection;
                        #[cfg(test)]
                        wait_at_agent_pool_worker_test_barrier(worker_test_barrier.as_ref());
                        if let Err(error) = serve_agent_connection(
                            &service,
                            &replay,
                            &context_memory,
                            &mut stream,
                            read_timeout,
                            write_timeout,
                        ) {
                            eprintln!("Agent API connection failed closed: {error:#}");
                        }
                    }
                })
                .context("failed to spawn bounded Agent API worker")?;
        }
        Ok(Self {
            sender,
            per_uid_in_flight,
            per_uid_limit: config.per_uid_limit,
        })
    }

    fn submit(&self, stream: UnixStream) -> std::result::Result<(), AgentConnectionRejection> {
        let uid = match unix_peer_credentials(&stream) {
            Ok(credentials) => credentials.uid,
            Err(_) => {
                return Err(AgentConnectionRejection {
                    stream,
                    reason: "agent_api_peer_credentials_failed",
                });
            }
        };
        let admission = {
            let Ok(mut counts) = self.per_uid_in_flight.lock() else {
                return Err(AgentConnectionRejection {
                    stream,
                    reason: "agent_api_admission_state_failed",
                });
            };
            let count = counts.entry(uid).or_insert(0);
            if *count >= self.per_uid_limit {
                return Err(AgentConnectionRejection {
                    stream,
                    reason: "agent_api_uid_connection_limit",
                });
            }
            *count += 1;
            AgentConnectionAdmission {
                uid,
                counts: Arc::clone(&self.per_uid_in_flight),
            }
        };
        let connection = QueuedAgentConnection {
            stream,
            _admission: admission,
        };
        match self.sender.try_send(connection) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(connection) | TrySendError::Disconnected(connection)) => {
                Err(AgentConnectionRejection {
                    stream: connection.stream,
                    reason: "agent_api_busy",
                })
            }
        }
    }
}

fn run_agent_api_uds() -> Result<()> {
    if !builtin_provider_identity::compiled_measurement_is_exact() {
        bail!("compiled P0 daemon measurement does not match runtime identity and receipt pins");
    }
    capability_hardening::harden_android_agentd_from_env()?;
    let socket_path = env::var_os("TRILLIONNIUM_AGENT_API_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| DEFAULT_AGENT_API_SOCKET.into());
    let socket_gid = configured_agent_api_socket_gid()?;
    let listener = bind_agent_api_listener(&socket_path, socket_gid)?;
    let audit_path = default_audit_path()?;
    let service = Arc::new(
        AgentService::from_store_after_exclusive_startup(AuditStore::open(&audit_path)?)
            .context("failed to restore Agent API control plane")?,
    );
    let manifest_dir = env::var_os("TRILLIONNIUM_AGENT_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| DEFAULT_AGENT_MANIFEST_DIR.into());
    let provisioned = load_os_agent_manifests(&service, &manifest_dir, 0)?;
    let context_memory = Arc::new(ContextMemoryService::open_from_env()?);
    #[cfg(feature = "legacy-plan-conformance")]
    service
        .set_execution_payload_resolver(Arc::clone(&context_memory) as Arc<_>)
        .map_err(anyhow::Error::msg)?;
    ContextMemoryService::spawn_execution_payload_reaper(&context_memory)?;
    if env::var("TRILLIONNIUM_ANDROID_UI_AGENT_API").as_deref() == Ok("1") {
        require_android_builtin_manifests(&service)?;
        android_agent_api::spawn(Arc::clone(&service), Arc::clone(&context_memory));
    }
    let replay = Arc::new(Mutex::new(AgentApiReplayStore::open_from_env()?));
    let pool = AgentConnectionPool::spawn(
        Arc::clone(&service),
        replay,
        context_memory,
        AgentConnectionPoolConfig {
            workers: AGENT_API_WORKERS,
            queue_depth: AGENT_API_QUEUE_DEPTH,
            per_uid_limit: AGENT_API_PER_UID_CONNECTION_LIMIT,
            read_timeout: AGENT_API_READ_TIMEOUT,
            write_timeout: AGENT_API_WRITE_TIMEOUT,
            #[cfg(test)]
            worker_test_barrier: None,
        },
    )?;
    eprintln!(
        "trillionniumd owns {} at {} with UID/domain authorization, measured executable policy, nonce-bound state changes, {} OS-provisioned agents, and audit db {}",
        AGENT_API_UDS_PROTOCOL,
        socket_path.display(),
        provisioned,
        audit_path.display()
    );
    for accepted in listener.incoming() {
        match accepted {
            Ok(mut stream) => {
                if let Err(error) = enable_unix_message_credentials(&stream) {
                    let _ = stream.set_write_timeout(Some(AGENT_API_WRITE_TIMEOUT));
                    let _ = write_agent_response(
                        &mut stream,
                        &error_response(
                            Value::Null,
                            &format!("agent_api_message_credentials_failed: {error}"),
                        ),
                    );
                    continue;
                }
                if let Err(mut rejected) = pool.submit(stream) {
                    let _ = rejected
                        .stream
                        .set_write_timeout(Some(AGENT_API_WRITE_TIMEOUT));
                    let _ = write_agent_response(
                        &mut rejected.stream,
                        &error_response(Value::Null, rejected.reason),
                    );
                }
            }
            Err(error) => eprintln!("Agent API accept failed closed: {error}"),
        }
    }
    Ok(())
}

fn configured_agent_api_socket_gid() -> Result<u32> {
    match env::var("TRILLIONNIUM_AGENT_API_SOCKET_GID") {
        Ok(value) => value
            .parse::<u32>()
            .context("TRILLIONNIUM_AGENT_API_SOCKET_GID must be a numeric GID"),
        Err(env::VarError::NotPresent) => Ok(unsafe { libc::getegid() }),
        Err(env::VarError::NotUnicode(_)) => {
            bail!("TRILLIONNIUM_AGENT_API_SOCKET_GID must be valid UTF-8")
        }
    }
}

fn bind_agent_api_listener(socket_path: &Path, socket_gid: u32) -> Result<UnixListener> {
    validate_agent_api_socket_path(socket_path)?;
    let owner_uid = unsafe { libc::geteuid() };
    let parent_path = socket_path
        .parent()
        .context("Agent API socket must have a parent directory")?;
    let socket_name = socket_path
        .file_name()
        .context("Agent API socket must have a file name")?;
    let socket_name_c = secure_path_component(socket_name, "Agent API socket file name")?;
    let parent = open_or_create_agent_api_socket_parent(parent_path, owner_uid, socket_gid)?;
    validate_agent_api_socket_parent(&parent, owner_uid, socket_gid, parent_path)?;

    // Resolve the final entry relative to the already-open, O_NOFOLLOW-walked
    // parent. This prevents a pathname swap from redirecting unlink/bind to a
    // different directory. Linux and Android both expose directory fds here.
    let fd_relative_path =
        PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(socket_name);
    remove_stale_agent_api_socket(
        &parent,
        &fd_relative_path,
        &socket_name_c,
        owner_uid,
        socket_gid,
    )?;

    let listener = UnixListener::bind(&fd_relative_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;
    enable_unix_message_credentials(&listener)?;
    let cleanup = SocketEntryCleanup::new(parent.as_raw_fd(), socket_name_c.as_c_str());
    set_agent_api_socket_identity(&parent, &socket_name_c, owner_uid, socket_gid)?;
    let metadata = inspect_agent_api_socket_entry(&fd_relative_path)?
        .context("Agent API socket disappeared immediately after bind")?;
    validate_agent_api_socket_metadata(&metadata, owner_uid, socket_gid, true)?;

    // Re-open the configured parent after the bind and require it to identify
    // the same directory inode. The listener remains fail-closed if an ancestor
    // was renamed or substituted while startup was in progress.
    let reopened = open_existing_agent_api_socket_parent(parent_path, owner_uid, socket_gid)?;
    let original_metadata = parent.metadata()?;
    let reopened_metadata = reopened.metadata()?;
    if original_metadata.dev() != reopened_metadata.dev()
        || original_metadata.ino() != reopened_metadata.ino()
    {
        bail!("Agent API socket parent changed during bind")
    }
    cleanup.disarm();
    Ok(listener)
}

fn validate_agent_api_socket_path(socket_path: &Path) -> Result<()> {
    if !socket_path.is_absolute() {
        bail!("Agent API socket path must be absolute");
    }
    if socket_path.as_os_str().as_bytes().len() > MAX_UNIX_SOCKET_PATH_BYTES {
        bail!("Agent API socket path exceeds the Unix-domain path limit");
    }
    let mut normal_components = 0usize;
    for component in socket_path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => {
                secure_path_component(value, "Agent API socket path component")?;
                normal_components += 1;
            }
            _ => bail!("Agent API socket path contains a non-normal component"),
        }
    }
    if normal_components < 2 {
        bail!("Agent API socket requires a dedicated parent directory");
    }
    Ok(())
}

fn secure_path_component(value: &OsStr, label: &str) -> Result<CString> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        bail!("{label} is invalid");
    }
    CString::new(bytes).with_context(|| format!("{label} contains NUL"))
}

fn open_root_directory() -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .context("failed to open filesystem root for Agent API socket")
}

fn open_directory_at(parent: &File, name: &CString) -> std::io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn create_directory_at(parent: &File, name: &CString, socket_gid: u32) -> Result<File> {
    let created = unsafe {
        libc::mkdirat(
            parent.as_raw_fd(),
            name.as_ptr(),
            AGENT_API_SOCKET_PARENT_MODE as libc::mode_t,
        )
    };
    if created < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error).context("failed to create Agent API socket directory");
        }
    }
    let directory = open_directory_at(parent, name)
        .context("failed to open newly created Agent API socket directory")?;
    if created == 0 {
        if unsafe { libc::fchown(directory.as_raw_fd(), u32::MAX, socket_gid) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to set Agent API socket directory group");
        }
        if unsafe {
            libc::fchmod(
                directory.as_raw_fd(),
                AGENT_API_SOCKET_PARENT_MODE as libc::mode_t,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to set Agent API socket directory mode");
        }
    }
    Ok(directory)
}

fn socket_parent_components(path: &Path) -> Result<Vec<CString>> {
    if !path.is_absolute() {
        bail!("Agent API socket parent must be absolute");
    }
    path.components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(value) => Some(secure_path_component(
                value,
                "Agent API socket parent component",
            )),
            _ => Some(Err(anyhow::anyhow!(
                "Agent API socket parent contains a non-normal component"
            ))),
        })
        .collect()
}

fn open_or_create_agent_api_socket_parent(
    path: &Path,
    owner_uid: u32,
    socket_gid: u32,
) -> Result<File> {
    let components = socket_parent_components(path)?;
    if components.is_empty() {
        bail!("Agent API socket cannot use the filesystem root as its parent");
    }
    let mut directory = open_root_directory()?;
    validate_agent_api_socket_ancestor(&directory, owner_uid, Path::new("/"))?;
    let mut resolved = PathBuf::from("/");
    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        directory = match open_directory_at(&directory, component) {
            Ok(next) => next,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && final_component => {
                create_directory_at(&directory, component, socket_gid)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(error).context(format!(
                    "Agent API socket parent ancestor does not exist: {}",
                    path.display()
                ));
            }
            Err(error) => {
                return Err(error).context(format!(
                    "Agent API socket parent component is not a real directory: {}",
                    path.display()
                ));
            }
        };
        resolved.push(OsStr::from_bytes(component.as_bytes()));
        if final_component {
            validate_agent_api_socket_parent(&directory, owner_uid, socket_gid, path)?;
        } else {
            validate_agent_api_socket_ancestor(&directory, owner_uid, &resolved)?;
        }
    }
    Ok(directory)
}

fn open_existing_agent_api_socket_parent(
    path: &Path,
    owner_uid: u32,
    socket_gid: u32,
) -> Result<File> {
    let components = socket_parent_components(path)?;
    if components.is_empty() {
        bail!("Agent API socket cannot use the filesystem root as its parent");
    }
    let mut directory = open_root_directory()?;
    validate_agent_api_socket_ancestor(&directory, owner_uid, Path::new("/"))?;
    let mut resolved = PathBuf::from("/");
    for (index, component) in components.iter().enumerate() {
        directory = open_directory_at(&directory, component).with_context(|| {
            format!(
                "Agent API socket parent changed or became unsafe: {}",
                path.display()
            )
        })?;
        resolved.push(OsStr::from_bytes(component.as_bytes()));
        if index + 1 == components.len() {
            validate_agent_api_socket_parent(&directory, owner_uid, socket_gid, path)?;
        } else {
            validate_agent_api_socket_ancestor(&directory, owner_uid, &resolved)?;
        }
    }
    Ok(directory)
}

fn validate_agent_api_socket_ancestor(directory: &File, owner_uid: u32, path: &Path) -> Result<()> {
    let metadata = directory.metadata()?;
    let mode = metadata.mode() & 0o7777;
    let trusted_owner = metadata.uid() == 0 || metadata.uid() == owner_uid;
    let sticky_system_root = metadata.uid() == 0
        && mode & libc::S_ISVTX != 0
        && matches!(path.to_str(), Some("/tmp" | "/var/tmp" | "/dev/shm"));
    if !metadata.is_dir()
        || metadata.nlink() == 0
        || !trusted_owner
        || (mode & 0o022 != 0 && !sticky_system_root)
    {
        bail!(
            "Agent API socket ancestor must be root/service-owned and not group/world writable: {} (uid {}, expected root or {}, mode {:04o}, nlink {})",
            path.display(),
            metadata.uid(),
            owner_uid,
            mode,
            metadata.nlink(),
        );
    }
    Ok(())
}

fn validate_agent_api_socket_parent(
    directory: &File,
    owner_uid: u32,
    socket_gid: u32,
    path: &Path,
) -> Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != socket_gid
        || metadata.mode() & 0o7777 != AGENT_API_SOCKET_PARENT_MODE
        || metadata.nlink() == 0
    {
        bail!(
            "Agent API socket parent must be a stable UID {owner_uid}, GID {socket_gid}, mode {:04o} directory: {}",
            AGENT_API_SOCKET_PARENT_MODE,
            path.display()
        );
    }
    Ok(())
}

fn inspect_agent_api_socket_entry(path: &Path) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect Agent API socket entry {}",
                path.display()
            )
        }),
    }
}

fn validate_agent_api_socket_metadata(
    metadata: &std::fs::Metadata,
    owner_uid: u32,
    socket_gid: u32,
    require_exact_mode: bool,
) -> Result<()> {
    let mode = metadata.mode() & 0o7777;
    let mode_is_safe = if require_exact_mode {
        mode == AGENT_API_SOCKET_MODE
    } else {
        mode & !AGENT_API_SOCKET_MODE == 0 && mode & 0o600 == 0o600
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner_uid
        || metadata.gid() != socket_gid
        || !mode_is_safe
        || metadata.nlink() != 1
    {
        bail!(
            "existing Agent API socket must be a single-link UID {owner_uid}, GID {socket_gid}, owner-controlled socket"
        );
    }
    Ok(())
}

fn remove_stale_agent_api_socket(
    parent: &File,
    fd_relative_path: &Path,
    socket_name: &CString,
    owner_uid: u32,
    socket_gid: u32,
) -> Result<()> {
    let Some(before) = inspect_agent_api_socket_entry(fd_relative_path)? else {
        return Ok(());
    };
    validate_agent_api_socket_metadata(&before, owner_uid, socket_gid, false)?;
    match UnixStream::connect(fd_relative_path) {
        Ok(_) => bail!("Agent API socket is already served by a live daemon"),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Err(error) => {
            return Err(error).context(
                "existing Agent API socket could not be proven stale; refusing to unlink it",
            );
        }
    }
    let Some(after) = inspect_agent_api_socket_entry(fd_relative_path)? else {
        return Ok(());
    };
    validate_agent_api_socket_metadata(&after, owner_uid, socket_gid, false)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        bail!("Agent API socket changed during stale-socket validation");
    }
    if unsafe { libc::unlinkat(parent.as_raw_fd(), socket_name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to remove verified stale Agent API socket");
    }
    Ok(())
}

fn set_agent_api_socket_identity(
    parent: &File,
    socket_name: &CString,
    owner_uid: u32,
    socket_gid: u32,
) -> Result<()> {
    if unsafe {
        libc::fchownat(
            parent.as_raw_fd(),
            socket_name.as_ptr(),
            owner_uid,
            socket_gid,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to set Agent API socket owner/group");
    }
    if unsafe {
        libc::fchmodat(
            parent.as_raw_fd(),
            socket_name.as_ptr(),
            AGENT_API_SOCKET_MODE as libc::mode_t,
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("failed to set Agent API socket mode");
    }
    Ok(())
}

struct SocketEntryCleanup {
    parent_fd: i32,
    socket_name: CString,
    armed: std::cell::Cell<bool>,
}

impl SocketEntryCleanup {
    fn new(parent_fd: i32, socket_name: &std::ffi::CStr) -> Self {
        Self {
            parent_fd,
            socket_name: socket_name.to_owned(),
            armed: std::cell::Cell::new(true),
        }
    }

    fn disarm(&self) {
        self.armed.set(false);
    }
}

impl Drop for SocketEntryCleanup {
    fn drop(&mut self) {
        if self.armed.get() {
            unsafe {
                libc::unlinkat(self.parent_fd, self.socket_name.as_ptr(), 0);
            }
        }
    }
}

fn require_android_builtin_manifests(service: &AgentService) -> Result<()> {
    for (descriptor, adapter_version) in [(&CODEX, codex_adapter::CODEX_ADAPTER_VERSION)] {
        let agent_id = descriptor.agent_id;
        let registration = service
            .get_agent_local(agent_id)
            .map_err(anyhow::Error::msg)?
            .with_context(|| {
                format!("Android built-in provider {agent_id} requires an OS-owned AgentManifest")
            })?;
        if !registration.enabled
            || registration.api_version != AGENT_API_VERSION
            || registration.adapter_version != adapter_version
            || !builtin_provider_identity::matches_stable_registration(descriptor, &registration)
            || registration.network_policy != trillionnium_os_types::AgentNetworkPolicy::PerRequest
            || registration.health != trillionnium_os_types::AgentHealth::Ready
            || registration.registered_at_unix_ms == 0
            || registration.updated_at_unix_ms < registration.registered_at_unix_ms
        {
            bail!("Android built-in provider AgentManifest is disabled or incompatible");
        }
    }
    Ok(())
}

fn load_os_agent_manifests(
    service: &AgentService,
    directory: &std::path::Path,
    required_owner_uid: u32,
) -> Result<usize> {
    let directory_metadata = match std::fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", directory.display()));
        }
    };
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        bail!(
            "AgentManifest path is not a real directory: {}",
            directory.display()
        );
    }
    if directory_metadata.uid() != required_owner_uid || directory_metadata.mode() & 0o022 != 0 {
        bail!(
            "AgentManifest directory must be owned by UID {} and not group/world writable: {}",
            required_owner_uid,
            directory.display()
        );
    }
    let mut paths = std::fs::read_dir(directory)
        .with_context(|| format!("failed to read {}", directory.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    if paths.len() > MAX_AGENT_MANIFESTS {
        bail!("too many AgentManifest entries in {}", directory.display());
    }
    let mut loaded = 0usize;
    for path in paths {
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            bail!(
                "unexpected non-JSON AgentManifest entry: {}",
                path.display()
            );
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("failed to open AgentManifest {}", path.display()))?;
        let before = file.metadata().with_context(|| {
            format!("failed to inspect opened AgentManifest {}", path.display())
        })?;
        if !before.is_file()
            || before.uid() != required_owner_uid
            || before.mode() & 0o022 != 0
            || before.nlink() != 1
            || before.len() == 0
            || before.len() > MAX_AGENT_MANIFEST_BYTES
        {
            bail!(
                "AgentManifest must be a non-empty owner-controlled regular file: {}",
                path.display()
            );
        }
        let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
        std::io::Read::by_ref(&mut file)
            .take(MAX_AGENT_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("failed to read AgentManifest {}", path.display()))?;
        if bytes.len() as u64 != before.len() || bytes.len() as u64 > MAX_AGENT_MANIFEST_BYTES {
            bail!(
                "AgentManifest changed size while being read: {}",
                path.display()
            );
        }
        let after = file
            .metadata()
            .with_context(|| format!("failed to restat opened AgentManifest {}", path.display()))?;
        let before_identity = (
            before.dev(),
            before.ino(),
            before.uid(),
            before.gid(),
            before.mode(),
            before.nlink(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        );
        let after_identity = (
            after.dev(),
            after.ino(),
            after.uid(),
            after.gid(),
            after.mode(),
            after.nlink(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        );
        if before_identity != after_identity {
            bail!("AgentManifest changed while being read: {}", path.display());
        }
        let value = parse_request_json(&bytes, "agent_manifest")
            .with_context(|| format!("invalid AgentManifest JSON: {}", path.display()))?;
        let registration: AgentRegistration = serde_json::from_value(value)
            .with_context(|| format!("invalid AgentManifest fields: {}", path.display()))?;
        if registration.registered_at_unix_ms != 0 || registration.updated_at_unix_ms != 0 {
            bail!(
                "source AgentManifest timestamps must be zero and OS-authored: {}",
                path.display()
            );
        }
        service
            .provision_agent_local(registration)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("AgentManifest rejected: {}", path.display()))?;
        loaded += 1;
    }
    Ok(loaded)
}

fn serve_agent_connection(
    service: &AgentService,
    replay: &SharedReplayStore,
    context_memory: &ContextMemoryService,
    stream: &mut UnixStream,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<()> {
    let response = handle_agent_api_stream(service, replay, context_memory, stream, read_timeout)
        .unwrap_or_else(|error| error_response(Value::Null, &error.to_string()));
    stream.set_write_timeout(Some(write_timeout))?;
    write_agent_response(stream, &response)
}

#[derive(Debug, Clone, Copy)]
struct AgentApiDeadline {
    expires_at: Instant,
}

impl AgentApiDeadline {
    fn from_now(budget: Duration) -> Result<Self> {
        if budget.is_zero() {
            bail!("Agent API handshake deadline must be non-zero");
        }
        let expires_at = Instant::now()
            .checked_add(budget)
            .context("Agent API handshake deadline overflow")?;
        Ok(Self { expires_at })
    }

    fn remaining(self) -> Result<Duration> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .context("Agent API absolute handshake deadline exhausted")
    }

    fn arm_read(self, stream: &UnixStream) -> Result<()> {
        stream
            .set_read_timeout(Some(self.remaining()?))
            .context("failed to arm Agent API absolute read deadline")
    }

    fn arm_write(self, stream: &UnixStream) -> Result<()> {
        stream
            .set_write_timeout(Some(self.remaining()?))
            .context("failed to arm Agent API absolute write deadline")
    }
}

fn encode_agent_response(response: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(response)?;
    if bytes.is_empty() || bytes.len() > MAX_AGENT_API_FRAME_BYTES {
        bail!("Agent API response exceeds bounded frame size");
    }
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_agent_response(stream: &mut UnixStream, response: &Value) -> Result<()> {
    let bytes = encode_agent_response(response)?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn write_agent_response_before_deadline(
    stream: &mut UnixStream,
    response: &Value,
    deadline: AgentApiDeadline,
) -> Result<()> {
    let bytes = encode_agent_response(response)?;
    let mut written = 0usize;
    while written < bytes.len() {
        deadline.arm_write(stream)?;
        let count = stream
            .write(&bytes[written..])
            .context("failed to write Agent API challenge before absolute deadline")?;
        if count == 0 {
            bail!("Agent API challenge write made no progress");
        }
        written += count;
    }
    deadline.arm_write(stream)?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
fn read_agent_frame(stream: &UnixStream) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    BufReader::new(stream.try_clone()?)
        .take(MAX_AGENT_API_FRAME_BYTES as u64 + 2)
        .read_until(b'\n', &mut frame)?;
    if frame.last() != Some(&b'\n') {
        bail!("Agent API frame is not newline terminated");
    }
    if frame.len() <= 1 || frame.len() > MAX_AGENT_API_FRAME_BYTES + 1 {
        bail!("invalid or oversized Agent API frame");
    }
    frame.pop();
    Ok(frame)
}

fn enable_unix_message_credentials(socket: &impl AsRawFd) -> Result<()> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to require per-message Agent API credentials");
    }
    Ok(())
}

fn recv_agent_chunk_with_credentials(
    stream: &UnixStream,
    buffer: &mut [u8],
    deadline: AgentApiDeadline,
) -> Result<(usize, UnixMessageCredentials)> {
    let control_len =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as libc::c_uint) as usize };
    let mut control = vec![0u8; control_len];
    let mut iovec = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    deadline.arm_read(stream)?;
    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, 0) };
    if received < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to read credential-bound Agent API frame");
    }
    if received == 0 {
        bail!("Agent API peer closed before completing a credential-bound frame");
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        bail!("Agent API per-message credentials were truncated");
    }

    let mut credentials = None;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let header_ref = unsafe { &*header };
        if header_ref.cmsg_level == libc::SOL_SOCKET
            && header_ref.cmsg_type == libc::SCM_CREDENTIALS
        {
            if credentials.is_some()
                || header_ref.cmsg_len
                    < unsafe {
                        libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as libc::c_uint) as usize
                    }
            {
                bail!("invalid or duplicate Agent API per-message credentials");
            }
            let raw =
                unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>()) };
            let pid = u32::try_from(raw.pid).context("invalid Agent API message pid")?;
            if pid == 0 {
                bail!("invalid zero Agent API message pid");
            }
            credentials = Some(UnixMessageCredentials {
                pid,
                uid: raw.uid,
                gid: raw.gid,
            });
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    let credentials = credentials.context("Agent API frame has no kernel message credentials")?;
    Ok((
        usize::try_from(received).context("invalid Agent API frame read length")?,
        credentials,
    ))
}

fn read_agent_frame_with_credentials(
    stream: &UnixStream,
    deadline: AgentApiDeadline,
) -> Result<(Vec<u8>, UnixMessageCredentials)> {
    let mut frame = Vec::new();
    let mut writer = None;
    let mut chunk = [0u8; 8 * 1024];
    loop {
        if frame.len() > MAX_AGENT_API_FRAME_BYTES {
            bail!("invalid or oversized Agent API frame");
        }
        let remaining = (MAX_AGENT_API_FRAME_BYTES + 1).saturating_sub(frame.len());
        if remaining == 0 {
            bail!("invalid or oversized Agent API frame");
        }
        let probe_len = remaining.min(chunk.len());
        deadline.arm_read(stream)?;
        let peeked = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                chunk.as_mut_ptr().cast(),
                probe_len,
                libc::MSG_PEEK,
            )
        };
        if peeked < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect bounded Agent API frame");
        }
        if peeked == 0 {
            bail!("Agent API peer closed before a newline-terminated frame");
        }
        let peeked = usize::try_from(peeked).context("invalid Agent API probe length")?;
        let consume = chunk[..peeked]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(peeked, |index| index + 1);
        let (received, credentials) =
            recv_agent_chunk_with_credentials(stream, &mut chunk[..consume], deadline)?;
        if let Some(expected) = writer {
            if expected != credentials {
                bail!("Agent API frame changed kernel-authenticated writer");
            }
        } else {
            writer = Some(credentials);
        }
        frame.extend_from_slice(&chunk[..received]);
        if frame.last() == Some(&b'\n') {
            break;
        }
    }
    if frame.len() <= 1 || frame.len() > MAX_AGENT_API_FRAME_BYTES + 1 {
        bail!("invalid or oversized Agent API frame");
    }
    frame.pop();
    Ok((
        frame,
        writer.context("Agent API frame has no kernel-authenticated writer")?,
    ))
}

fn ensure_message_writer_matches_peer(
    writer: UnixMessageCredentials,
    peer: &AgentPeerIdentity,
) -> Result<()> {
    if writer.pid != peer.pid || writer.uid != peer.uid || writer.gid != peer.gid {
        bail!(
            "Agent API frame writer does not match the connected kernel peer: writer={}/{}/{}, peer={}/{}/{}",
            writer.pid,
            writer.uid,
            writer.gid,
            peer.pid,
            peer.uid,
            peer.gid,
        );
    }
    Ok(())
}

fn fill_agent_api_random(bytes: &mut [u8]) -> Result<()> {
    let mut filled = 0usize;
    while filled < bytes.len() {
        let read = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                bytes[filled..].as_mut_ptr(),
                bytes.len() - filled,
                0,
            )
        };
        if read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("Agent API state-change nonce generation failed");
        }
        if read == 0 {
            bail!("Agent API state-change nonce generation returned no bytes");
        }
        filled += usize::try_from(read).context("invalid Agent API random read length")?;
    }
    Ok(())
}

fn new_agent_api_channel_nonce() -> Result<String> {
    use std::fmt::Write as _;

    let mut random = [0u8; 32];
    fill_agent_api_random(&mut random)?;
    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

fn state_change_request_sha256(
    request: &AgentApiUdsRequestEnvelope,
    peer: &AgentPeerIdentity,
) -> String {
    sha256_json(&json!({
        "schema": AGENT_API_CHANNEL_AUTH_SCHEMA,
        "protocol": request.protocol,
        "request_id": request.request_id,
        "agent_id": request.agent_id,
        "method": request.method,
        "payload": request.payload,
        "peer_pid": peer.pid,
        "peer_uid": peer.uid,
        "peer_gid": peer.gid,
        "peer_process_start_time_ticks": peer.process_start_time_ticks,
        "peer_selinux_domain": peer.selinux_domain,
    }))
}

fn same_agent_api_request(
    initial: &AgentApiUdsRequestEnvelope,
    authenticated: &AgentApiUdsRequestEnvelope,
) -> bool {
    initial.protocol == authenticated.protocol
        && initial.request_id == authenticated.request_id
        && initial.method == authenticated.method
        && initial.agent_id == authenticated.agent_id
        && initial.payload == authenticated.payload
}

fn validate_state_change_channel_binding(
    initial: &AgentApiUdsRequestEnvelope,
    authenticated: &AgentApiUdsRequestEnvelope,
    nonce: &str,
    request_sha256: &str,
) -> Result<()> {
    if !same_agent_api_request(initial, authenticated) {
        bail!("Agent API state-change request changed after channel challenge");
    }
    let binding = authenticated
        .channel_binding
        .as_ref()
        .context("Agent API state-change request omitted its channel binding")?;
    if binding.schema != AGENT_API_CHANNEL_AUTH_SCHEMA
        || binding.nonce != nonce
        || binding.request_sha256 != request_sha256
    {
        bail!("Agent API state-change channel binding mismatch");
    }
    Ok(())
}

fn handle_agent_api_stream(
    service: &AgentService,
    replay: &SharedReplayStore,
    context_memory: &ContextMemoryService,
    stream: &UnixStream,
    handshake_budget: Duration,
) -> Result<Value> {
    // Executable sampling constrains the observed connector but cannot prove
    // which executable authored bytes queued before the sample. Require Linux
    // per-message credentials for every frame and, before any state change,
    // require the same process instance to answer a fresh server challenge on
    // this channel. The SELinux/UID process principal is the authenticated
    // author; the executable digest remains an additional measured policy gate.
    enable_unix_message_credentials(stream)?;
    let measured_peer = measure_unix_peer_identity(stream)?;
    let peer = &measured_peer.identity;
    // Executable hashing is bounded separately. Start one monotonic budget at
    // the first frame boundary and carry it unchanged through challenge write
    // and authenticated-frame receipt, so byte drips cannot reset the clock.
    let deadline = AgentApiDeadline::from_now(handshake_budget)?;
    let (frame, writer) = read_agent_frame_with_credentials(stream, deadline)?;
    ensure_message_writer_matches_peer(writer, peer)?;
    let initial_request = parse_agent_api_uds_request(&frame)?;
    if !is_enabled_agent_api_method(&initial_request.method) {
        bail!("unknown or agent-forbidden method");
    }
    recheck_unix_peer_identity(stream, &measured_peer)?;
    replay_store::validate_request_id(&initial_request.request_id)?;
    if requires_channel_binding(&initial_request.method) {
        // Reject an unprovisioned or mismatched principal before spending a
        // challenge nonce or holding the second-frame worker budget.
        authorize_agent_peer(service, &initial_request.agent_id, peer)?;
    }

    let request = if requires_channel_binding(&initial_request.method) {
        if initial_request.channel_binding.is_some() {
            bail!("Agent API channel binding cannot precede its server challenge");
        }
        let nonce = new_agent_api_channel_nonce()?;
        let channel_request_sha256 = state_change_request_sha256(&initial_request, peer);
        let challenge = json!({
            "protocol": AGENT_API_UDS_PROTOCOL,
            "request_id": initial_request.request_id,
            "type": "channel_binding_challenge",
            "challenge": {
                "schema": AGENT_API_CHANNEL_AUTH_SCHEMA,
                "nonce": nonce,
                "request_sha256": channel_request_sha256,
            }
        });
        let mut challenge_stream = stream.try_clone()?;
        write_agent_response_before_deadline(&mut challenge_stream, &challenge, deadline)?;

        let (authenticated_frame, authenticated_writer) =
            read_agent_frame_with_credentials(stream, deadline)?;
        ensure_message_writer_matches_peer(authenticated_writer, peer)?;
        let authenticated_request = parse_agent_api_uds_request(&authenticated_frame)?;
        validate_state_change_channel_binding(
            &initial_request,
            &authenticated_request,
            &nonce,
            &channel_request_sha256,
        )?;
        recheck_unix_peer_identity(stream, &measured_peer)?;
        authenticated_request
    } else {
        if initial_request.channel_binding.is_some() {
            bail!("Agent API channel binding is valid only for channel-bound methods");
        }
        initial_request
    };
    let AgentApiUdsRequestEnvelope {
        request_id,
        method,
        agent_id,
        payload,
        channel_binding: _,
        ..
    } = request;
    let request_sha256 = sha256_json(&json!({
        "protocol": AGENT_API_UDS_PROTOCOL,
        "agent_id": agent_id,
        "method": method,
        "payload": payload,
    }));
    let replay_identity = if uses_agent_replay_store(&method) {
        Some(replay_identity_for_authorized_agent(
            service, &agent_id, peer,
        )?)
    } else {
        None
    };
    if uses_agent_replay_store(&method) {
        let decision = replay
            .lock()
            .map_err(|_| anyhow::anyhow!("Agent API replay lock poisoned"))?
            .begin(
                replay_identity
                    .as_ref()
                    .expect("replay methods have an authorized stable identity"),
                &agent_id,
                &method,
                &request_id,
                &request_sha256,
            );
        match decision {
            Ok(ReplayDecision::Cached(response)) => return Ok(response),
            Ok(ReplayDecision::Execute) => {}
            Err(error) => return Ok(error_response(json!(request_id), &error.to_string())),
        }
    }
    let result = if is_delegated_agent_data_method(&method) {
        let subject = Subject::new(peer.uid, &peer.selinux_domain)?;
        let bound_payload = json!({
            "agent_id": agent_id,
            "peer_executable_sha256": peer.executable_sha256.clone(),
            "payload": payload.clone(),
        });
        context_memory.run_ui_request(
            &format!("agent.{method}"),
            &request_id,
            &subject,
            &bound_payload,
            || dispatch_agent_data_api(service, context_memory, peer, &agent_id, &method, payload),
        )
    } else {
        dispatch_agent_api_uds(service, peer, &agent_id, &method, payload)
    };
    let response = match result {
        Ok(result) => json!({
            "protocol": AGENT_API_UDS_PROTOCOL,
            "request_id": request_id,
            "ok": true,
            "result": result
        }),
        Err(error) => json!({
            "protocol": AGENT_API_UDS_PROTOCOL,
            "request_id": request_id,
            "ok": false,
            "error": error.to_string()
        }),
    };
    if uses_agent_replay_store(&method)
        && let Err(error) = replay
            .lock()
            .map_err(|_| anyhow::anyhow!("Agent API replay lock poisoned"))?
            .complete(
                replay_identity
                    .as_ref()
                    .expect("replay methods have an authorized stable identity"),
                &agent_id,
                &method,
                &request_id,
                &request_sha256,
                &response,
            )
    {
        return Ok(error_response(
            json!(request_id),
            &format!("request_id_replay_persistence_failed: {error}"),
        ));
    }
    Ok(response)
}

fn is_state_changing_method(method: &str) -> bool {
    match method {
        "register_agent"
        | direct_agent_host_abi::KERNEL_WIRE_METHOD_CREATE_TASK
        | direct_agent_host_abi::KERNEL_WIRE_METHOD_CANCEL_TASK => true,
        #[cfg(any(test, feature = "legacy-plan-conformance"))]
        "submit_plan" | "run_tool" => true,
        _ => false,
    }
}

fn uses_agent_replay_store(method: &str) -> bool {
    is_state_changing_method(method)
}

fn is_delegated_agent_data_method(method: &str) -> bool {
    matches!(
        method,
        "list_data_grants" | "read_context_grant" | "read_memory_grant"
    )
}

fn error_response(request_id: Value, error: &str) -> Value {
    json!({
        "protocol": AGENT_API_UDS_PROTOCOL,
        "request_id": request_id,
        "ok": false,
        "error": error,
    })
}

fn kernel_agent_health(peer: &AgentPeerIdentity) -> Value {
    json!({
        "api_version": AGENT_API_VERSION,
        "uds_protocol": AGENT_API_UDS_PROTOCOL,
        "direct_agent_host": direct_agent_host_abi::health_contract(),
        "peer_uid": peer.uid,
        "peer_gid": peer.gid,
        "peer_selinux_domain": peer.selinux_domain,
        "peer_executable_dev": peer.executable_dev,
        "peer_executable_ino": peer.executable_ino,
        "peer_executable_uid": peer.executable_uid,
        "peer_executable_gid": peer.executable_gid,
        "peer_executable_mode": peer.executable_mode,
        "peer_executable_sha256": peer.executable_sha256,
        "channel_bound_requests_require_fresh_channel_binding": true,
        "channel_bound_author_bound_to_kernel_message_process": true,
        "executable_measurement_alone_proves_request_authorship": false,
        "model_execution_owned_by_os": false,
        "tool_invocation_owned_by_agent": direct_agent_host_abi::TOOL_INVOCATION_OWNED_BY_AGENT,
        "tool_backend_owned_by_os": direct_agent_host_abi::TOOL_BACKEND_OWNED_BY_OS,
        "daemon_is_effect_executor": direct_agent_host_abi::DAEMON_IS_EFFECT_EXECUTOR,
        "contract_confers_effect_authority": direct_agent_host_abi::CONTRACT_CONFERS_EFFECT_AUTHORITY,
        "caller_supplied_context_acquisition": false,
        "task_bound_context_delegation": true,
        "memory_listing_metadata_only": true,
        "raw_data_requires_single_use_os_ui_grant": true
    })
}

fn dispatch_agent_api_uds(
    service: &AgentService,
    peer: &AgentPeerIdentity,
    agent_id: &str,
    method: &str,
    payload: Value,
) -> Result<Value> {
    match method {
        direct_agent_host_abi::KERNEL_WIRE_METHOD_HEALTH => Ok(kernel_agent_health(peer)),
        "register_agent" => {
            let registration: AgentRegistration = serde_json::from_value(payload)?;
            if registration.agent_id != agent_id {
                bail!("envelope agent_id does not match registration");
            }
            let provisioned = service
                .get_agent_local(agent_id)
                .map_err(anyhow::Error::msg)?
                .with_context(|| {
                    format!(
                        "agent identity must be provisioned by the OS before UDS attestation: {agent_id}"
                    )
                })?;
            if registration.peer_uid != peer.uid
                || registration.peer_gid != peer.gid
                || registration.selinux_domain != peer.selinux_domain
                || registration.identity_key_sha256 != peer.executable_sha256
            {
                bail!("agent registration does not match kernel-authenticated peer identity");
            }
            if provisioned.peer_uid != peer.uid
                || provisioned.peer_gid != peer.gid
                || provisioned.selinux_domain != peer.selinux_domain
                || provisioned.identity_key_sha256 != peer.executable_sha256
            {
                bail!("kernel-authenticated peer does not match OS-provisioned agent identity");
            }
            Ok(serde_json::to_value(
                service
                    .register_agent_local(registration)
                    .map_err(anyhow::Error::msg)?,
            )?)
        }
        "list_tools" => {
            authorize_agent_peer(service, agent_id, peer)?;
            Ok(json!({
                "tools": trillionnium_tool_runtime::production_agent_api_manifests()
            }))
        }
        direct_agent_host_abi::KERNEL_WIRE_METHOD_CREATE_TASK => dispatch_agent_state_change(
            service,
            AgentDispatchAuthentication::KernelUds { agent_id, peer },
            direct_agent_host_abi::KERNEL_WIRE_METHOD_CREATE_TASK,
            payload,
        ),
        #[cfg(any(test, feature = "legacy-plan-conformance"))]
        "submit_plan" => dispatch_agent_state_change(
            service,
            AgentDispatchAuthentication::KernelUds { agent_id, peer },
            "submit_plan",
            payload,
        ),
        #[cfg(any(test, feature = "legacy-plan-conformance"))]
        "run_tool" => dispatch_agent_state_change(
            service,
            AgentDispatchAuthentication::KernelUds { agent_id, peer },
            "run_tool",
            payload,
        ),
        direct_agent_host_abi::KERNEL_WIRE_METHOD_CANCEL_TASK => dispatch_agent_state_change(
            service,
            AgentDispatchAuthentication::KernelUds { agent_id, peer },
            direct_agent_host_abi::KERNEL_WIRE_METHOD_CANCEL_TASK,
            payload,
        ),
        _ => bail!("unknown or agent-forbidden method: {method}"),
    }
}

/// Provider-neutral Agent API state transition port.
///
/// Transport authentication happens before this function. Keeping every plan
/// task creation, plan submission, immutable-action dispatch, and cancellation
/// behind this one method-level validator prevents the built-in Android
/// workflow from growing a second set of Agent API semantics around
/// `AgentService::*_local` calls.
fn dispatch_agent_state_change(
    service: &AgentService,
    authentication: AgentDispatchAuthentication<'_>,
    method: &str,
    payload: Value,
) -> Result<Value> {
    let registration = authenticated_dispatch_registration(service, authentication)?;
    let agent_id = registration.agent_id.as_str();
    match method {
        "create_task" => {
            let mut input: TaskInput = serde_json::from_value(payload)
                .context("create_task requires an exact TaskInput")?;
            let metadata = input
                .metadata
                .as_object_mut()
                .context("task metadata must be an object")?;
            metadata.insert("agent_id".to_string(), json!(agent_id));
            metadata.insert("agent_peer_uid".to_string(), json!(registration.peer_uid));
            metadata.insert("agent_peer_gid".to_string(), json!(registration.peer_gid));
            metadata.insert(
                "agent_peer_selinux_domain".to_string(),
                json!(registration.selinux_domain),
            );
            metadata.insert(
                "agent_peer_executable_sha256".to_string(),
                json!(registration.identity_key_sha256),
            );
            let (
                origin,
                executable_dev,
                executable_ino,
                executable_uid,
                executable_gid,
                executable_mode,
            ) = match authentication {
                AgentDispatchAuthentication::KernelUds { peer, .. } => {
                    metadata.remove("agent_api_dispatch_origin");
                    (
                        AgentDispatchOrigin {
                            uid: peer.uid,
                            selinux_domain: &peer.selinux_domain,
                            subject_user_id: configured_agent_api_subject_user_id(peer.uid)?,
                        },
                        peer.executable_dev,
                        peer.executable_ino,
                        peer.executable_uid,
                        peer.executable_gid,
                        peer.executable_mode,
                    )
                }
                AgentDispatchAuthentication::OsSupervisedProvider {
                    executable, origin, ..
                } => {
                    metadata.insert(
                        "agent_api_dispatch_origin".to_string(),
                        json!(OS_SUPERVISED_AGENT_DISPATCH_ORIGIN),
                    );
                    (
                        origin.context(
                            "OS-supervised create_task requires an OS-authenticated origin",
                        )?,
                        executable.dev,
                        executable.ino,
                        executable.uid,
                        executable.gid,
                        executable.mode,
                    )
                }
            };
            if origin.uid / 100_000 != origin.subject_user_id
                || origin.selinux_domain.is_empty()
                || origin.selinux_domain.len() > 256
                || origin.selinux_domain.trim() != origin.selinux_domain
                || origin.selinux_domain.chars().any(char::is_control)
            {
                bail!("Agent API task origin is invalid");
            }
            metadata.insert("origin_uid".to_string(), json!(origin.uid));
            metadata.insert(
                "origin_selinux_domain".to_string(),
                json!(origin.selinux_domain),
            );
            metadata.insert("subject_user_id".to_string(), json!(origin.subject_user_id));
            metadata.insert(
                "agent_peer_executable_dev".to_string(),
                json!(executable_dev),
            );
            metadata.insert(
                "agent_peer_executable_ino".to_string(),
                json!(executable_ino),
            );
            metadata.insert(
                "agent_peer_executable_uid".to_string(),
                json!(executable_uid),
            );
            metadata.insert(
                "agent_peer_executable_gid".to_string(),
                json!(executable_gid),
            );
            metadata.insert(
                "agent_peer_executable_mode".to_string(),
                json!(executable_mode),
            );
            Ok(serde_json::to_value(
                service
                    .create_task_local(input)
                    .map_err(anyhow::Error::msg)?,
            )?)
        }
        #[cfg(any(test, feature = "legacy-plan-conformance"))]
        "submit_plan" => {
            let plan: AgentPlanSubmission = serde_json::from_value(payload)
                .context("submit_plan requires an exact AgentPlanSubmission")?;
            if plan.agent_id != agent_id {
                bail!("envelope agent_id does not match plan");
            }
            if plan.actions.iter().any(|action| {
                !trillionnium_tool_runtime::production_agent_tool_allowed(&action.tool_name)
            }) {
                bail!("plan requests a tool outside the production Agent API catalog");
            }
            ensure_dispatch_agent_owns_task(service, authentication, agent_id, &plan.task_id.0)?;
            Ok(serde_json::to_value(
                service
                    .submit_agent_plan_local(plan)
                    .map_err(anyhow::Error::msg)?,
            )?)
        }
        #[cfg(any(test, feature = "legacy-plan-conformance"))]
        "run_tool" => {
            let request: AgentExecutionRequest = serde_json::from_value(payload)
                .context("run_tool accepts only task_id, plan_id, and action_id")?;
            ensure_dispatch_agent_owns_task(service, authentication, agent_id, &request.task_id.0)?;
            let frozen_plan = service
                .get_agent_plan_local(&request.plan_id)
                .map_err(anyhow::Error::msg)?
                .context("unknown frozen plan")?;
            let frozen_action = frozen_plan
                .actions
                .iter()
                .find(|action| action.action_id == request.action_id)
                .context("unknown frozen plan action")?;
            if !trillionnium_tool_runtime::production_agent_tool_allowed(&frozen_action.tool_name) {
                bail!("frozen action is outside the production Agent API catalog");
            }
            Ok(service
                .run_agent_planned_action_local(
                    agent_id,
                    registration.peer_uid,
                    registration.peer_gid,
                    &registration.selinux_domain,
                    request,
                )
                .map_err(anyhow::Error::msg)?)
        }
        "cancel_task" => {
            let task_id = parse_cancel_task_payload(payload)?;
            ensure_dispatch_agent_owns_task(service, authentication, agent_id, &task_id)?;
            Ok(serde_json::to_value(
                service
                    .cancel_task_local(&task_id)
                    .map_err(anyhow::Error::msg)?,
            )?)
        }
        _ => bail!("method is not an Agent API state transition: {method}"),
    }
}

fn dispatch_agent_data_api(
    service: &AgentService,
    context_memory: &ContextMemoryService,
    peer: &AgentPeerIdentity,
    agent_id: &str,
    method: &str,
    payload: Value,
) -> Result<Value> {
    authorize_agent_peer(service, agent_id, peer)?;
    let object = payload
        .as_object()
        .context("delegated data payload must be an object")?;
    let task_id = object
        .get("task_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .context("task_id is required")?;
    ensure_agent_owns_task(service, agent_id, peer, task_id)?;
    let task = service
        .get_task_local(task_id)
        .map_err(anyhow::Error::msg)?
        .context("delegated data task does not exist")?;
    if !matches!(
        task.status,
        TaskStatus::Created | TaskStatus::Running | TaskStatus::WaitingForApproval
    ) {
        bail!("delegated data task is no longer active");
    }
    let subject_user_id = task
        .metadata
        .get("subject_user_id")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .context("delegated data task has no valid subject_user_id")?;
    let consumer = AgentGrantConsumer {
        agent_id: agent_id.to_string(),
        peer_uid: peer.uid,
        peer_gid: peer.gid,
        selinux_domain: peer.selinux_domain.clone(),
        executable_sha256: peer.executable_sha256.clone(),
        task_id: task_id.to_string(),
        subject_user_id,
    };
    match method {
        "list_data_grants" => {
            if object.len() != 1 {
                bail!("list_data_grants accepts only task_id");
            }
            context_memory.list_agent_data_grants(&consumer)
        }
        "read_context_grant" | "read_memory_grant" => {
            if object.len() != 2 {
                bail!("read data grant accepts only task_id and grant_id");
            }
            let grant_id = object
                .get("grant_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 96)
                .context("grant_id is required")?;
            context_memory.read_agent_data_grant(
                &consumer,
                grant_id,
                if method == "read_context_grant" {
                    "context"
                } else {
                    "memory"
                },
            )
        }
        _ => bail!("unknown delegated Agent data method"),
    }
}

fn configured_agent_api_subject_user_id(peer_uid: u32) -> Result<u32> {
    match env::var("TRILLIONNIUM_AGENT_API_SUBJECT_USER_ID") {
        Ok(value) => value
            .parse::<u32>()
            .context("TRILLIONNIUM_AGENT_API_SUBJECT_USER_ID must be a u32"),
        Err(env::VarError::NotPresent) => Ok(peer_uid / 100_000),
        Err(error) => Err(error).context("invalid Agent API subject user configuration"),
    }
}

fn authorize_agent_peer(
    service: &AgentService,
    agent_id: &str,
    peer: &AgentPeerIdentity,
) -> Result<()> {
    authorized_agent_registration(service, agent_id, peer).map(|_| ())
}

fn authorized_agent_registration(
    service: &AgentService,
    agent_id: &str,
    peer: &AgentPeerIdentity,
) -> Result<AgentRegistration> {
    let registration = service
        .get_agent_local(agent_id)
        .map_err(anyhow::Error::msg)?
        .with_context(|| format!("unregistered agent id: {agent_id}"))?;
    if !registration.enabled
        || registration.api_version != AGENT_API_VERSION
        || registration.peer_uid != peer.uid
        || registration.peer_gid != peer.gid
        || registration.selinux_domain != peer.selinux_domain
        || registration.identity_key_sha256 != peer.executable_sha256
    {
        bail!("agent identity is disabled or kernel-authenticated peer binding does not match");
    }
    Ok(registration)
}

fn authenticated_dispatch_registration(
    service: &AgentService,
    authentication: AgentDispatchAuthentication<'_>,
) -> Result<AgentRegistration> {
    match authentication {
        AgentDispatchAuthentication::KernelUds { agent_id, peer } => {
            authorized_agent_registration(service, agent_id, peer)
        }
        AgentDispatchAuthentication::OsSupervisedProvider {
            registration: expected,
            executable,
            origin: _,
        } => {
            let provisioned = service
                .get_agent_local(&expected.agent_id)
                .map_err(anyhow::Error::msg)?
                .with_context(|| {
                    format!(
                        "OS-supervised Agent is not provisioned: {}",
                        expected.agent_id
                    )
                })?;
            if !same_immutable_agent_manifest_binding(&provisioned, expected)
                || !provisioned.enabled
                || provisioned.health != trillionnium_os_types::AgentHealth::Ready
                || provisioned.api_version != AGENT_API_VERSION
                || executable.sha256 != provisioned.identity_key_sha256
            {
                bail!("OS-supervised Agent binding does not match the current AgentManifest");
            }
            Ok(provisioned)
        }
    }
}

/// Compare only fields authored by the immutable AgentManifest contract.
///
/// `registered_at_unix_ms` and `updated_at_unix_ms` are runtime audit facts
/// authored by `provision_agent_local`; the latter changes whenever the same
/// manifest is re-provisioned during a normal daemon restart. They must not
/// turn an otherwise identical manifest generation into a different Agent
/// principal. Current enabled/health/API state is checked separately by the
/// dispatcher immediately after this binding comparison.
fn same_immutable_agent_manifest_binding(
    current: &AgentRegistration,
    expected: &AgentRegistration,
) -> bool {
    current.api_version == expected.api_version
        && current.agent_id == expected.agent_id
        && current.adapter == expected.adapter
        && current.adapter_version == expected.adapter_version
        && current.identity_key_sha256 == expected.identity_key_sha256
        && current.peer_uid == expected.peer_uid
        && current.peer_gid == expected.peer_gid
        && current.selinux_domain == expected.selinux_domain
        && current.network_policy == expected.network_policy
        && current.enabled == expected.enabled
        && current.health == expected.health
}

fn replay_identity_for_authorized_agent(
    service: &AgentService,
    agent_id: &str,
    peer: &AgentPeerIdentity,
) -> Result<ReplayIdentity> {
    let registration = authorized_agent_registration(service, agent_id, peer)?;
    Ok(ReplayIdentity {
        uid: registration.peer_uid,
        gid: registration.peer_gid,
        selinux_domain: registration.selinux_domain,
        agent_generation_sha256: registration.identity_key_sha256,
    })
}

fn ensure_agent_owns_task(
    service: &AgentService,
    agent_id: &str,
    peer: &AgentPeerIdentity,
    task_id: &str,
) -> Result<()> {
    let task = service
        .get_task_local(task_id)
        .map_err(anyhow::Error::msg)?
        .with_context(|| format!("unknown task id: {task_id}"))?;
    if task.metadata.get("agent_id").and_then(Value::as_str) != Some(agent_id)
        || task.metadata.get("agent_peer_uid").and_then(Value::as_u64) != Some(peer.uid as u64)
        || task.metadata.get("agent_peer_gid").and_then(Value::as_u64) != Some(peer.gid as u64)
        || task
            .metadata
            .get("agent_peer_selinux_domain")
            .and_then(Value::as_str)
            != Some(peer.selinux_domain.as_str())
        || task
            .metadata
            .get("agent_peer_executable_sha256")
            .and_then(Value::as_str)
            != Some(peer.executable_sha256.as_str())
        || task
            .metadata
            .get("agent_peer_executable_dev")
            .and_then(Value::as_u64)
            != Some(peer.executable_dev)
        || task
            .metadata
            .get("agent_peer_executable_ino")
            .and_then(Value::as_u64)
            != Some(peer.executable_ino)
        || task
            .metadata
            .get("agent_peer_executable_uid")
            .and_then(Value::as_u64)
            != Some(u64::from(peer.executable_uid))
        || task
            .metadata
            .get("agent_peer_executable_gid")
            .and_then(Value::as_u64)
            != Some(u64::from(peer.executable_gid))
        || task
            .metadata
            .get("agent_peer_executable_mode")
            .and_then(Value::as_u64)
            != Some(u64::from(peer.executable_mode))
    {
        bail!("agent does not own task");
    }
    Ok(())
}

fn ensure_dispatch_agent_owns_task(
    service: &AgentService,
    authentication: AgentDispatchAuthentication<'_>,
    agent_id: &str,
    task_id: &str,
) -> Result<()> {
    match authentication {
        AgentDispatchAuthentication::KernelUds { agent_id: _, peer } => {
            ensure_agent_owns_task(service, agent_id, peer, task_id)
        }
        AgentDispatchAuthentication::OsSupervisedProvider {
            registration,
            executable,
            origin: _,
        } => {
            let task = service
                .get_task_local(task_id)
                .map_err(anyhow::Error::msg)?
                .with_context(|| format!("unknown task id: {task_id}"))?;
            if task.metadata.get("agent_id").and_then(Value::as_str) != Some(agent_id)
                || task.metadata.get("agent_peer_uid").and_then(Value::as_u64)
                    != Some(u64::from(registration.peer_uid))
                || task.metadata.get("agent_peer_gid").and_then(Value::as_u64)
                    != Some(u64::from(registration.peer_gid))
                || task
                    .metadata
                    .get("agent_peer_selinux_domain")
                    .and_then(Value::as_str)
                    != Some(registration.selinux_domain.as_str())
                || task
                    .metadata
                    .get("agent_peer_executable_sha256")
                    .and_then(Value::as_str)
                    != Some(registration.identity_key_sha256.as_str())
                || task
                    .metadata
                    .get("agent_api_dispatch_origin")
                    .and_then(Value::as_str)
                    != Some(OS_SUPERVISED_AGENT_DISPATCH_ORIGIN)
                || task
                    .metadata
                    .get("agent_peer_executable_dev")
                    .and_then(Value::as_u64)
                    != Some(executable.dev)
                || task
                    .metadata
                    .get("agent_peer_executable_ino")
                    .and_then(Value::as_u64)
                    != Some(executable.ino)
                || task
                    .metadata
                    .get("agent_peer_executable_uid")
                    .and_then(Value::as_u64)
                    != Some(u64::from(executable.uid))
                || task
                    .metadata
                    .get("agent_peer_executable_gid")
                    .and_then(Value::as_u64)
                    != Some(u64::from(executable.gid))
                || task
                    .metadata
                    .get("agent_peer_executable_mode")
                    .and_then(Value::as_u64)
                    != Some(u64::from(executable.mode))
            {
                bail!("OS-supervised Agent does not own task");
            }
            Ok(())
        }
    }
}

fn unix_peer_credentials(stream: &UnixStream) -> Result<UnixMessageCredentials> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if rc != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        bail!(
            "failed to read peer credentials: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(UnixMessageCredentials {
        pid: u32::try_from(credentials.pid).context("invalid peer pid")?,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

fn measure_unix_peer_identity(stream: &UnixStream) -> Result<MeasuredAgentPeer> {
    let credentials = unix_peer_credentials(stream)?;
    let pid = credentials.pid;
    let process_start_time_ticks = proc_start_time_ticks(pid)?;
    let selinux_domain = unix_peer_security_context(stream)?;
    let executable = File::open(format!("/proc/{pid}/exe"))
        .with_context(|| format!("failed to open executable for Agent API peer pid {pid}"))?;
    let executable = measure_open_executable(executable)
        .with_context(|| format!("failed to measure executable for Agent API peer pid {pid}"))?;
    if proc_start_time_ticks(pid)? != process_start_time_ticks {
        bail!("Agent API peer process generation changed while measuring its executable");
    }
    Ok(MeasuredAgentPeer {
        executable_stability: executable.stability,
        identity: AgentPeerIdentity {
            pid,
            uid: credentials.uid,
            gid: credentials.gid,
            process_start_time_ticks,
            selinux_domain,
            executable_dev: executable.dev,
            executable_ino: executable.ino,
            executable_uid: executable.uid,
            executable_gid: executable.gid,
            executable_mode: executable.mode,
            executable_sha256: executable.sha256,
        },
    })
}

fn measure_open_executable(mut executable: File) -> Result<OpenedExecutableIdentity> {
    let before = inspect_open_executable(&executable)?;
    let executable_sha256 =
        sha256_reader(&mut executable).context("failed to hash opened executable")?;
    let after = inspect_open_executable(&executable)?;
    if before != after {
        bail!("opened Agent executable changed while hashing");
    }
    Ok(OpenedExecutableIdentity {
        dev: before.dev,
        ino: before.ino,
        uid: before.uid,
        gid: before.gid,
        mode: before.mode & 0o7777,
        sha256: executable_sha256,
        stability: before,
    })
}

fn inspect_open_executable(executable: &File) -> Result<ExecutableFileStability> {
    let metadata = executable
        .metadata()
        .context("failed to stat opened executable")?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.is_file()
        || metadata.nlink() == 0
        || metadata.len() == 0
        || metadata.len() > MAX_AGENT_EXECUTABLE_BYTES
        || mode & 0o111 == 0
        || !opened_executable_mode_is_safe(&metadata, mode)
    {
        bail!(
            "opened Agent executable must be a linked, bounded, executable, non-group/world-writable regular file"
        );
    }
    Ok(ExecutableFileStability {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        nlink: metadata.nlink(),
        len: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    })
}

fn opened_executable_mode_is_safe(_metadata: &std::fs::Metadata, mode: u32) -> bool {
    if mode & 0o7022 == 0 {
        return true;
    }
    #[cfg(test)]
    {
        // Cargo preserves the invoking umask for test artifacts. With a 0002
        // umask, the immutable test harness itself is mode 0775. Permit only
        // that exact already-running inode, only in test builds, and only when
        // group-write is the sole otherwise-forbidden bit. This avoids chmod
        // races with parallel tests that hash /proc/self/exe; production builds
        // retain the exact owner-controlled mode gate above.
        if mode & 0o7002 == 0
            && mode & 0o0020 != 0
            && let Ok(current) = File::open("/proc/self/exe")
            && let Ok(current_metadata) = current.metadata()
        {
            return _metadata.dev() == current_metadata.dev()
                && _metadata.ino() == current_metadata.ino();
        }
    }
    false
}

fn recheck_unix_peer_identity(stream: &UnixStream, expected: &MeasuredAgentPeer) -> Result<()> {
    let credentials = unix_peer_credentials(stream)?;
    if credentials.pid != expected.identity.pid
        || credentials.uid != expected.identity.uid
        || credentials.gid != expected.identity.gid
    {
        bail!("Agent API kernel peer credentials changed while submitting the request");
    }
    let start_time_before = proc_start_time_ticks(credentials.pid)?;
    if start_time_before != expected.identity.process_start_time_ticks {
        bail!("Agent API peer process generation changed while submitting the request");
    }
    if unix_peer_security_context(stream)? != expected.identity.selinux_domain {
        bail!("Agent API peer security domain changed while submitting the request");
    }
    let executable = File::open(format!("/proc/{}/exe", credentials.pid)).with_context(|| {
        format!(
            "failed to reopen executable for Agent API peer pid {}",
            credentials.pid
        )
    })?;
    let executable_stability = inspect_open_executable(&executable)?;
    let start_time_after = proc_start_time_ticks(credentials.pid)?;
    if start_time_after != start_time_before
        || executable_stability != expected.executable_stability
    {
        bail!("Agent API peer identity changed while submitting the request");
    }
    Ok(())
}

#[cfg(test)]
fn ensure_agent_peer_identity_unchanged(
    before: &AgentPeerIdentity,
    after: &AgentPeerIdentity,
) -> Result<()> {
    if before != after {
        bail!("Agent API peer identity changed while submitting the request");
    }
    Ok(())
}

fn proc_start_time_ticks(pid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("failed to read Agent API peer stat for pid {pid}"))?;
    let command_end = stat
        .rfind(") ")
        .context("Agent API peer stat omitted command terminator")?;
    let start_time = stat[command_end + 2..]
        .split_whitespace()
        .nth(19)
        .context("Agent API peer stat omitted start time")?
        .parse::<u64>()
        .context("Agent API peer stat start time was invalid")?;
    if start_time == 0 {
        bail!("Agent API peer stat start time was zero");
    }
    Ok(start_time)
}

fn unix_peer_security_context(stream: &UnixStream) -> Result<String> {
    let mut buffer = vec![0u8; 4096];
    let mut length = buffer.len() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            buffer.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if rc != 0 {
        bail!(
            "failed to read mandatory peer security context: {}",
            std::io::Error::last_os_error()
        );
    }
    let length = usize::try_from(length).context("invalid peer security context length")?;
    if length == 0 || length > buffer.len() {
        bail!("invalid peer security context length");
    }
    buffer.truncate(length);
    while buffer.last() == Some(&0) {
        buffer.pop();
    }
    let context = String::from_utf8(buffer).context("peer security context is not UTF-8")?;
    if context.trim().is_empty() || context.len() > 256 || context.chars().any(char::is_control) {
        bail!("peer security context is empty or malformed");
    }
    Ok(context)
}

fn default_audit_path() -> Result<PathBuf> {
    let base = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("trillionnium-os");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create {}", dir.to_string_lossy()))?;
    Ok(dir.join("audit.sqlite"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::Instant;
    use trillionnium_os_types::{AgentHealth, AgentNetworkPolicy, now_unix_ms};

    #[test]
    fn device_conformance_feature_keeps_production_provider_constructor() {
        let source = include_str!("main.rs");
        let start = source.find("fn codex_provider(").unwrap();
        let end = source[start..]
            .find("\n}\n\nconst DEFAULT_AGENT_MANIFEST_DIR")
            .unwrap();
        let constructor = &source[start..start + end];
        assert!(constructor.contains("CodexAdapter::new_bound("));
        assert!(!constructor.contains("new_p0_launch_package_conformance"));
    }

    fn provision_connected_uds_agent(service: &AgentService, stream: &UnixStream, agent_id: &str) {
        let peer = measure_unix_peer_identity(stream).unwrap().identity;
        let now = now_unix_ms();
        service
            .provision_agent_local(AgentRegistration {
                api_version: AGENT_API_VERSION.to_string(),
                agent_id: agent_id.to_string(),
                adapter: "fixture-adapter".to_string(),
                adapter_version: "1".to_string(),
                identity_key_sha256: peer.executable_sha256,
                peer_uid: peer.uid,
                peer_gid: peer.gid,
                selinux_domain: peer.selinux_domain,
                network_policy: AgentNetworkPolicy::Deny,
                enabled: true,
                health: AgentHealth::Ready,
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
            })
            .unwrap();
    }

    fn agent_api_socket_test_path() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = directory.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket_path = directory
            .path()
            .join("runtime")
            .join("trillionnium")
            .join("agent-api-v2.sock");
        (directory, socket_path)
    }

    #[test]
    fn secure_uds_bind_creates_private_parent_and_explicit_socket_identity() {
        let (_directory, socket_path) = agent_api_socket_test_path();
        let gid = unsafe { libc::getegid() };
        let listener = bind_agent_api_listener(&socket_path, gid).unwrap();
        let client = UnixStream::connect(&socket_path).unwrap();
        let (_server, _) = listener.accept().unwrap();
        drop(client);

        let parent = std::fs::symlink_metadata(socket_path.parent().unwrap()).unwrap();
        assert_eq!(parent.uid(), unsafe { libc::geteuid() });
        assert_eq!(parent.gid(), gid);
        assert_eq!(parent.mode() & 0o7777, AGENT_API_SOCKET_PARENT_MODE);
        let socket = std::fs::symlink_metadata(&socket_path).unwrap();
        assert!(socket.file_type().is_socket());
        assert_eq!(socket.uid(), unsafe { libc::geteuid() });
        assert_eq!(socket.gid(), gid);
        assert_eq!(socket.mode() & 0o7777, AGENT_API_SOCKET_MODE);
        assert!(
            validate_agent_api_socket_metadata(
                &socket,
                unsafe { libc::geteuid() }.wrapping_add(1),
                gid,
                true,
            )
            .is_err()
        );
        assert!(
            validate_agent_api_socket_metadata(&socket, unsafe { libc::geteuid() }, gid ^ 1, true)
                .is_err()
        );
    }

    #[test]
    fn secure_uds_bind_replaces_only_a_verified_stale_socket() {
        let (_directory, socket_path) = agent_api_socket_test_path();
        let gid = unsafe { libc::getegid() };
        let first = bind_agent_api_listener(&socket_path, gid).unwrap();
        drop(first);

        let second = bind_agent_api_listener(&socket_path, gid).unwrap();
        let client = UnixStream::connect(&socket_path).unwrap();
        let (_server, _) = second.accept().unwrap();
        drop(client);
    }

    #[test]
    fn secure_uds_bind_refuses_to_unlink_a_live_socket() {
        let (_directory, socket_path) = agent_api_socket_test_path();
        let gid = unsafe { libc::getegid() };
        let listener = bind_agent_api_listener(&socket_path, gid).unwrap();
        let inode = std::fs::symlink_metadata(&socket_path).unwrap().ino();
        let error = bind_agent_api_listener(&socket_path, gid)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already served by a live daemon"));
        assert_eq!(
            std::fs::symlink_metadata(&socket_path).unwrap().ino(),
            inode
        );
        drop(listener);
    }

    #[test]
    fn secure_uds_bind_rejects_unsafe_parent_and_final_entries() {
        let (directory, socket_path) = agent_api_socket_test_path();
        let gid = unsafe { libc::getegid() };
        let parent = socket_path.parent().unwrap();
        std::fs::create_dir_all(parent).unwrap();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o770)).unwrap();
        let error = bind_agent_api_listener(&socket_path, gid)
            .unwrap_err()
            .to_string();
        assert!(error.contains("mode 0750 directory"));

        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::write(&socket_path, b"must not be unlinked").unwrap();
        let error = bind_agent_api_listener(&socket_path, gid)
            .unwrap_err()
            .to_string();
        assert!(error.contains("owner-controlled socket"));
        assert_eq!(
            std::fs::read(&socket_path).unwrap(),
            b"must not be unlinked"
        );

        std::fs::remove_file(&socket_path).unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, b"symlink target").unwrap();
        symlink(&target, &socket_path).unwrap();
        let error = bind_agent_api_listener(&socket_path, gid)
            .unwrap_err()
            .to_string();
        assert!(error.contains("owner-controlled socket"));
        assert!(
            std::fs::symlink_metadata(&socket_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn secure_uds_bind_rejects_a_writable_ancestor() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let unsafe_ancestor = directory.path().join("unsafe-ancestor");
        std::fs::create_dir(&unsafe_ancestor).unwrap();
        std::fs::set_permissions(&unsafe_ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();
        let socket_path = unsafe_ancestor
            .join("trillionnium")
            .join("agent-api-v2.sock");

        let error = bind_agent_api_listener(&socket_path, unsafe { libc::getegid() })
            .unwrap_err()
            .to_string();
        assert!(error.contains("ancestor must be root/service-owned"));
        assert!(!unsafe_ancestor.join("trillionnium").exists());
    }

    #[test]
    fn secure_uds_bind_rejects_symlinked_parent_and_unsafe_stale_mode() {
        let (directory, socket_path) = agent_api_socket_test_path();
        let gid = unsafe { libc::getegid() };
        let real_parent = directory.path().join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o750)).unwrap();
        symlink(
            &real_parent,
            directory.path().join("runtime").join("trillionnium"),
        )
        .unwrap();
        let error = bind_agent_api_listener(&socket_path, gid)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a real directory"));

        std::fs::remove_file(directory.path().join("runtime").join("trillionnium")).unwrap();
        let parent = socket_path.parent().unwrap();
        std::fs::create_dir(parent).unwrap();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750)).unwrap();
        let stale = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        drop(stale);
        let inode = std::fs::symlink_metadata(&socket_path).unwrap().ino();
        let error = bind_agent_api_listener(&socket_path, gid)
            .unwrap_err()
            .to_string();
        assert!(error.contains("owner-controlled socket"));
        assert_eq!(
            std::fs::symlink_metadata(&socket_path).unwrap().ino(),
            inode
        );
    }

    #[test]
    fn secure_uds_bind_requires_an_absolute_bounded_dedicated_path() {
        let gid = unsafe { libc::getegid() };
        assert!(
            bind_agent_api_listener(Path::new("relative.sock"), gid)
                .unwrap_err()
                .to_string()
                .contains("must be absolute")
        );
        assert!(
            bind_agent_api_listener(Path::new("/agent.sock"), gid)
                .unwrap_err()
                .to_string()
                .contains("dedicated parent")
        );
        let oversized = PathBuf::from(format!("/tmp/{}/agent.sock", "a".repeat(120)));
        assert!(
            bind_agent_api_listener(&oversized, gid)
                .unwrap_err()
                .to_string()
                .contains("path limit")
        );
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let missing_ancestor = directory
            .path()
            .join("missing")
            .join("parent")
            .join("agent.sock");
        assert!(
            bind_agent_api_listener(&missing_ancestor, gid)
                .unwrap_err()
                .to_string()
                .contains("ancestor does not exist")
        );
        assert!(!directory.path().join("missing").exists());
    }

    #[test]
    fn proc_start_time_parser_binds_the_current_process_generation() {
        assert!(proc_start_time_ticks(std::process::id()).unwrap() > 0);
    }

    #[test]
    fn agent_api_uds_envelope_is_closed_world_typed_and_backward_compatible() {
        let complete = parse_agent_api_uds_request(
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-closed-world","method":"cancel_task","agent_id":"agent-fixture","payload":{"task_id":"task-fixture"}}"#,
        )
        .unwrap();
        assert_eq!(complete.request_id, "request-closed-world");
        assert_eq!(complete.method, "cancel_task");
        assert_eq!(complete.agent_id, "agent-fixture");
        assert_eq!(complete.payload, json!({"task_id": "task-fixture"}));

        let legacy_optional_fields = parse_agent_api_uds_request(
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-health","method":"health"}"#,
        )
        .unwrap();
        assert_eq!(legacy_optional_fields.agent_id, "");
        assert_eq!(legacy_optional_fields.payload, json!({}));

        let unknown = parse_agent_api_uds_request(
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-extra","method":"health","payload":{},"debug_override":true}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(unknown.contains("agent_api_request_envelope_denied"));
        assert!(unknown.contains("unknown field"));

        for malformed in [
            br#"{"protocol":1,"request_id":"request-type","method":"health","payload":{}}"#.as_slice(),
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":[],"method":"health","payload":{}}"#.as_slice(),
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-type","method":{},"payload":{}}"#.as_slice(),
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-type","method":"health","agent_id":false,"payload":{}}"#.as_slice(),
        ] {
            assert!(
                parse_agent_api_uds_request(malformed)
                    .unwrap_err()
                    .to_string()
                    .contains("agent_api_request_envelope_denied")
            );
        }

        for confused_payload in [
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-scalar","method":"health","payload":"{}"}"#.as_slice(),
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-array","method":"health","payload":[]}"#.as_slice(),
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-null","method":"health","payload":null}"#.as_slice(),
        ] {
            assert_eq!(
                parse_agent_api_uds_request(confused_payload)
                    .unwrap_err()
                    .to_string(),
                "agent_api_request_payload_not_object"
            );
        }
    }

    #[test]
    fn agent_api_uds_parser_rejects_duplicate_members_before_dispatch() {
        for duplicate in [
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-one","request_id":"request-two","method":"health","payload":{}}"#.as_slice(),
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-payload","method":"cancel_task","payload":{"task_id":"task-one","task_id":"task-two"}}"#.as_slice(),
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-escaped","method":"cancel_task","payload":{"task_id":"task-one","task\u005fid":"task-two"}}"#.as_slice(),
        ] {
            let error = parse_agent_api_uds_request(duplicate)
                .unwrap_err()
                .to_string();
            assert!(error.contains("invalid_or_duplicate_json"), "{error}");
            assert!(error.contains("duplicate key"), "{error}");
        }
    }

    #[test]
    fn state_change_channel_binding_is_exact_and_request_bound() {
        let initial = parse_agent_api_uds_request(
            br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-channel-auth","method":"create_task","agent_id":"agent-fixture","payload":{"title":"bounded","description":null,"metadata":{}}}"#,
        )
        .unwrap();
        let peer = AgentPeerIdentity {
            pid: 41,
            uid: 5_901,
            gid: 5_901,
            process_start_time_ticks: 42,
            selinux_domain: "u:r:trillionnium_codex_agent:s0".to_string(),
            executable_dev: 1,
            executable_ino: 2,
            executable_uid: 0,
            executable_gid: 0,
            executable_mode: 0o555,
            executable_sha256: "a".repeat(64),
        };
        let nonce = "b".repeat(64);
        let request_sha256 = state_change_request_sha256(&initial, &peer);
        let authenticated = parse_agent_api_uds_request(
            &serde_json::to_vec(&json!({
                "protocol": AGENT_API_UDS_PROTOCOL,
                "request_id": "request-channel-auth",
                "method": "create_task",
                "agent_id": "agent-fixture",
                "payload": {"title": "bounded", "description": null, "metadata": {}},
                "channel_binding": {
                    "schema": AGENT_API_CHANNEL_AUTH_SCHEMA,
                    "nonce": nonce,
                    "request_sha256": request_sha256,
                }
            }))
            .unwrap(),
        )
        .unwrap();
        validate_state_change_channel_binding(&initial, &authenticated, &nonce, &request_sha256)
            .unwrap();

        let mut stale_nonce = authenticated;
        stale_nonce.channel_binding.as_mut().unwrap().nonce = "c".repeat(64);
        assert!(
            validate_state_change_channel_binding(&initial, &stale_nonce, &nonce, &request_sha256,)
                .unwrap_err()
                .to_string()
                .contains("channel binding mismatch")
        );

        let changed = parse_agent_api_uds_request(
            &serde_json::to_vec(&json!({
                "protocol": AGENT_API_UDS_PROTOCOL,
                "request_id": "request-channel-auth",
                "method": "create_task",
                "agent_id": "agent-fixture",
                "payload": {"title": "changed", "description": null, "metadata": {}},
                "channel_binding": {
                    "schema": AGENT_API_CHANNEL_AUTH_SCHEMA,
                    "nonce": nonce,
                    "request_sha256": request_sha256,
                }
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            validate_state_change_channel_binding(&initial, &changed, &nonce, &request_sha256)
                .unwrap_err()
                .to_string()
                .contains("changed after channel challenge")
        );

        let unknown_binding_field = br#"{"protocol":"trillionnium.agent-api.uds.v2","request_id":"request-channel-unknown","method":"cancel_task","agent_id":"agent-fixture","payload":{"task_id":"task-one"},"channel_binding":{"schema":"trillionnium.agent-api.state-change-auth.v1","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","request_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","debug":true}}"#;
        assert!(
            parse_agent_api_uds_request(unknown_binding_field)
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
    }

    #[test]
    fn single_use_grant_reads_require_channel_binding_without_agent_replay() {
        for method in ["read_context_grant", "read_memory_grant"] {
            assert!(requires_channel_binding(method));
            assert!(!uses_agent_replay_store(method));
        }
        assert!(!requires_channel_binding("list_data_grants"));
        assert!(!uses_agent_replay_store("list_data_grants"));
        assert!(requires_channel_binding("run_tool"));
        assert!(uses_agent_replay_store("run_tool"));
    }

    #[test]
    fn credential_bound_frame_reports_and_enforces_the_actual_writer() {
        let (server, mut client) = UnixStream::pair().unwrap();
        enable_unix_message_credentials(&server).unwrap();
        client.write_all(b"credential-bound\n").unwrap();
        let (frame, credentials) = read_agent_frame_with_credentials(
            &server,
            AgentApiDeadline::from_now(Duration::from_secs(1)).unwrap(),
        )
        .unwrap();
        assert_eq!(frame, b"credential-bound");
        assert_eq!(credentials.pid, std::process::id());
        assert_eq!(credentials.uid, unsafe { libc::geteuid() });
        assert_eq!(credentials.gid, unsafe { libc::getegid() });

        let peer = AgentPeerIdentity {
            pid: credentials.pid,
            uid: credentials.uid,
            gid: credentials.gid,
            process_start_time_ticks: 1,
            selinux_domain: "fixture".to_string(),
            executable_dev: 1,
            executable_ino: 2,
            executable_uid: credentials.uid,
            executable_gid: credentials.gid,
            executable_mode: 0o555,
            executable_sha256: "a".repeat(64),
        };
        ensure_message_writer_matches_peer(credentials, &peer).unwrap();
        let transferred_writer = UnixMessageCredentials {
            pid: credentials.pid.wrapping_add(1),
            ..credentials
        };
        assert!(
            ensure_message_writer_matches_peer(transferred_writer, &peer)
                .unwrap_err()
                .to_string()
                .contains("does not match the connected kernel peer")
        );
    }

    #[test]
    fn cancel_task_payload_is_exact_and_typed() {
        assert_eq!(
            parse_cancel_task_payload(json!({"task_id": "task-fixture"})).unwrap(),
            "task-fixture"
        );
        for denied in [
            json!({}),
            json!({"task_id": "task-fixture", "force": true}),
            json!({"task_id": 7}),
            json!({"task_id": {"value": "task-fixture"}}),
            json!({"task_id": ["task-fixture"]}),
        ] {
            assert!(
                parse_cancel_task_payload(denied)
                    .unwrap_err()
                    .to_string()
                    .contains("cancel_task_payload_denied")
            );
        }
    }

    fn provisioned_uds_agent(service: &AgentService) -> (AgentRegistration, AgentPeerIdentity) {
        let now = now_unix_ms();
        let peer = AgentPeerIdentity {
            pid: 4242,
            uid: 23001,
            gid: 23002,
            process_start_time_ticks: 1,
            selinux_domain: "u:r:trillionnium_test_agent:s0".to_string(),
            executable_dev: 11,
            executable_ino: 12,
            executable_uid: 0,
            executable_gid: 0,
            executable_mode: 0o755,
            executable_sha256: "a".repeat(64),
        };
        let registration = AgentRegistration {
            api_version: AGENT_API_VERSION.to_string(),
            agent_id: "agent-uds-security-test".to_string(),
            adapter: "fixture-adapter".to_string(),
            adapter_version: "1".to_string(),
            identity_key_sha256: peer.executable_sha256.clone(),
            peer_uid: peer.uid,
            peer_gid: peer.gid,
            selinux_domain: peer.selinux_domain.clone(),
            network_policy: AgentNetworkPolicy::Deny,
            enabled: true,
            health: AgentHealth::Ready,
            registered_at_unix_ms: now,
            updated_at_unix_ms: now,
        };
        service
            .provision_agent_local(registration.clone())
            .expect("OS provisioning should succeed");
        (registration, peer)
    }

    #[test]
    fn direct_agent_host_health_contract_is_identical_across_carriers() {
        let service = AgentService::in_memory().unwrap();
        let (registration, peer) = provisioned_uds_agent(&service);
        let kernel_health = dispatch_agent_api_uds(
            &service,
            &peer,
            &registration.agent_id,
            direct_agent_host_abi::KERNEL_WIRE_METHOD_HEALTH,
            json!({}),
        )
        .unwrap();
        let builtin_health =
            android_agent_api::android_ui_health(10_123, "u:r:trillionnium_aishell:s0");

        assert_eq!(
            kernel_health["direct_agent_host"],
            direct_agent_host_abi::health_contract()
        );
        assert_eq!(
            builtin_health["direct_agent_host"],
            kernel_health["direct_agent_host"]
        );
        for field in [
            "tool_invocation_owned_by_agent",
            "tool_backend_owned_by_os",
            "daemon_is_effect_executor",
            "contract_confers_effect_authority",
        ] {
            assert_eq!(builtin_health[field], kernel_health[field], "{field}");
        }
        assert!(kernel_health.get("tool_execution_owned_by_os").is_none());
        assert!(builtin_health.get("tool_execution_owned_by_os").is_none());
        assert_ne!(
            kernel_health["uds_protocol"], builtin_health["protocol"],
            "the shared ABI must not collapse distinct carrier trust domains"
        );
    }

    fn dispatch_identity_for_test_peer(
        peer: &AgentPeerIdentity,
    ) -> AgentExecutableDispatchIdentity {
        AgentExecutableDispatchIdentity {
            dev: peer.executable_dev,
            ino: peer.executable_ino,
            uid: peer.executable_uid,
            gid: peer.executable_gid,
            mode: peer.executable_mode,
            sha256: peer.executable_sha256.clone(),
        }
    }

    #[test]
    fn opened_executable_identity_rejects_same_digest_different_inode() {
        let directory = tempfile::tempdir().unwrap();
        let executable_a = directory.path().join("agent-a");
        let executable_b = directory.path().join("agent-b");
        std::fs::write(&executable_a, b"identical agent executable bytes").unwrap();
        std::fs::write(&executable_b, b"identical agent executable bytes").unwrap();
        std::fs::set_permissions(&executable_a, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(&executable_b, std::fs::Permissions::from_mode(0o555)).unwrap();

        let identity_a = measure_open_executable(File::open(&executable_a).unwrap()).unwrap();
        let identity_b = measure_open_executable(File::open(&executable_b).unwrap()).unwrap();
        assert_eq!(identity_a.sha256, identity_b.sha256);
        assert_ne!(
            (identity_a.dev, identity_a.ino),
            (identity_b.dev, identity_b.ino)
        );

        let service = AgentService::in_memory().unwrap();
        let (_, mut before) = provisioned_uds_agent(&service);
        before.executable_dev = identity_a.dev;
        before.executable_ino = identity_a.ino;
        before.executable_uid = identity_a.uid;
        before.executable_gid = identity_a.gid;
        before.executable_mode = identity_a.mode;
        before.executable_sha256 = identity_a.sha256;
        let mut after = before.clone();
        after.executable_dev = identity_b.dev;
        after.executable_ino = identity_b.ino;
        after.executable_uid = identity_b.uid;
        after.executable_gid = identity_b.gid;
        after.executable_mode = identity_b.mode;
        after.executable_sha256 = identity_b.sha256;
        let error = ensure_agent_peer_identity_unchanged(&before, &after)
            .unwrap_err()
            .to_string();
        assert!(error.contains("peer identity changed"));
    }

    #[test]
    fn peer_identity_guard_rejects_executable_device_substitution() {
        let service = AgentService::in_memory().unwrap();
        let (_, before) = provisioned_uds_agent(&service);
        ensure_agent_peer_identity_unchanged(&before, &before).unwrap();

        let mut after = before.clone();
        after.executable_dev = after.executable_dev.checked_add(1).unwrap();
        let error = ensure_agent_peer_identity_unchanged(&before, &after)
            .unwrap_err()
            .to_string();
        assert!(error.contains("peer identity changed"));

        let mut changed_owner = before.clone();
        changed_owner.executable_uid = changed_owner.executable_uid.wrapping_add(1);
        assert!(
            ensure_agent_peer_identity_unchanged(&before, &changed_owner)
                .unwrap_err()
                .to_string()
                .contains("peer identity changed")
        );

        let mut changed_mode = before.clone();
        changed_mode.executable_mode = 0o555;
        assert!(
            ensure_agent_peer_identity_unchanged(&before, &changed_mode)
                .unwrap_err()
                .to_string()
                .contains("peer identity changed")
        );
    }

    #[test]
    fn opened_executable_measurement_rejects_writable_or_non_executable_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent");
        std::fs::write(&path, b"agent executable bytes").unwrap();
        for mode in [0o644, 0o775, 0o4755] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let error = measure_open_executable(File::open(&path).unwrap())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("non-group/world-writable"),
                "{mode:o}: {error}"
            );
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).unwrap();
        let measured = measure_open_executable(File::open(&path).unwrap()).unwrap();
        assert_eq!(measured.mode, 0o555);
    }

    #[test]
    fn uds_registration_and_authorization_require_kernel_peer_binding() {
        let service = AgentService::in_memory().unwrap();
        let (registration, peer) = provisioned_uds_agent(&service);
        dispatch_agent_api_uds(
            &service,
            &peer,
            &registration.agent_id,
            "register_agent",
            json!(registration),
        )
        .expect("matching attestation should refresh provisioned registration");

        let mut wrong_group = peer.clone();
        wrong_group.gid += 1;
        let error = dispatch_agent_api_uds(
            &service,
            &wrong_group,
            &registration.agent_id,
            "list_tools",
            json!({}),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("kernel-authenticated peer binding does not match"));

        let mut impersonator = peer.clone();
        impersonator.executable_sha256 = "b".repeat(64);
        let error = dispatch_agent_api_uds(
            &service,
            &impersonator,
            "agent-uds-security-test",
            "list_tools",
            json!({}),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("kernel-authenticated peer binding does not match"));

        let unprovisioned = AgentRegistration {
            agent_id: "agent-unprovisioned-test".to_string(),
            ..service
                .get_agent_local("agent-uds-security-test")
                .unwrap()
                .unwrap()
        };
        let error = dispatch_agent_api_uds(
            &service,
            &peer,
            &unprovisioned.agent_id,
            "register_agent",
            json!(unprovisioned),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("must be provisioned by the OS"));
    }

    #[test]
    fn uds_run_tool_rejects_agent_supplied_tool_and_arguments() {
        let service = AgentService::in_memory().unwrap();
        let (registration, peer) = provisioned_uds_agent(&service);
        let error = dispatch_agent_api_uds(
            &service,
            &peer,
            &registration.agent_id,
            "run_tool",
            json!({
                "task_id": "task-attacker",
                "tool_name": "demo.approval_echo",
                "arguments": {"message": "substituted after preview"}
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("task_id, plan_id, and action_id"));
    }

    #[test]
    fn kernel_uds_and_os_supervised_ports_share_plan_validation() {
        let service = AgentService::in_memory().unwrap();
        let (registration, peer) = provisioned_uds_agent(&service);
        let uds_task = dispatch_agent_api_uds(
            &service,
            &peer,
            &registration.agent_id,
            "create_task",
            json!({
                "title": "UDS dispatch ABI fixture",
                "description": null,
                "metadata": {}
            }),
        )
        .unwrap();
        let uds_task_id = uds_task["id"].as_str().unwrap().to_string();
        let supervised_executable = dispatch_identity_for_test_peer(&peer);
        let supervised_authentication = AgentDispatchAuthentication::OsSupervisedProvider {
            registration: &registration,
            executable: &supervised_executable,
            origin: Some(AgentDispatchOrigin {
                uid: 10_123,
                selinux_domain: "u:r:trillionnium_aishell:s0",
                subject_user_id: 0,
            }),
        };
        let supervised_task = dispatch_agent_state_change(
            &service,
            supervised_authentication,
            "create_task",
            json!({
                "title": "OS-supervised dispatch ABI fixture",
                "description": null,
                "metadata": {
                    "android_ui_uid": 10_123,
                    "android_ui_domain": "u:r:trillionnium_aishell:s0"
                }
            }),
        )
        .unwrap();
        let supervised_task_id = supervised_task["id"].as_str().unwrap().to_string();
        let make_plan = |task_id: &str, plan_id: &str, tool_name: &str| {
            let arguments = json!({});
            AgentPlanSubmission {
                api_version: AGENT_API_VERSION.to_string(),
                plan_id: plan_id.to_string(),
                task_id: trillionnium_os_types::TaskId(task_id.to_string()),
                session_id: format!("session-{plan_id}"),
                agent_id: registration.agent_id.clone(),
                intent_sha256: "1".repeat(64),
                provider_output_sha256: "2".repeat(64),
                contexts: Vec::new(),
                actions: vec![trillionnium_os_types::AgentPlannedAction {
                    action_id: format!("action-{plan_id}"),
                    tool_name: tool_name.to_string(),
                    os_tool_manifest_sha256: None,
                    os_executor_sha256: None,
                    arguments_sha256: sha256_json(&arguments),
                    arguments,
                    rationale: "shared Agent API dispatch fixture".to_string(),
                    requires_approval: true,
                    network_scope: if tool_name == "android.browser.open_bounded" {
                        "per_request".to_string()
                    } else {
                        "none".to_string()
                    },
                    undo_contract: if tool_name == "android.browser.open_bounded" {
                        "no_undo_external_browser_launch".to_string()
                    } else {
                        "none".to_string()
                    },
                }],
                created_at_unix_ms: now_unix_ms(),
            }
        };

        let uds_error = dispatch_agent_api_uds(
            &service,
            &peer,
            &registration.agent_id,
            "submit_plan",
            json!(make_plan(
                &uds_task_id,
                "plan-uds-denied",
                "demo.approval_echo"
            )),
        )
        .unwrap_err()
        .to_string();
        let supervised_error = dispatch_agent_state_change(
            &service,
            AgentDispatchAuthentication::OsSupervisedProvider {
                registration: &registration,
                executable: &supervised_executable,
                origin: None,
            },
            "submit_plan",
            json!(make_plan(
                &supervised_task_id,
                "plan-supervised-denied",
                "demo.approval_echo"
            )),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(uds_error, supervised_error);
        assert!(uds_error.contains("outside the production Agent API catalog"));

        let mut substituted_executable = supervised_executable.clone();
        substituted_executable.ino = substituted_executable.ino.saturating_add(1);
        let substitution_error = dispatch_agent_state_change(
            &service,
            AgentDispatchAuthentication::OsSupervisedProvider {
                registration: &registration,
                executable: &substituted_executable,
                origin: None,
            },
            "submit_plan",
            json!(make_plan(
                &supervised_task_id,
                "plan-supervised-substituted-inode",
                "android.browser.open_bounded"
            )),
        )
        .unwrap_err()
        .to_string();
        assert!(substitution_error.contains("does not own task"));

        let uds_accepted = dispatch_agent_api_uds(
            &service,
            &peer,
            &registration.agent_id,
            "submit_plan",
            json!(make_plan(
                &uds_task_id,
                "plan-uds-accepted",
                "android.browser.open_bounded"
            )),
        )
        .unwrap();
        let supervised_accepted = dispatch_agent_state_change(
            &service,
            AgentDispatchAuthentication::OsSupervisedProvider {
                registration: &registration,
                executable: &supervised_executable,
                origin: None,
            },
            "submit_plan",
            json!(make_plan(
                &supervised_task_id,
                "plan-supervised-accepted",
                "android.browser.open_bounded"
            )),
        )
        .unwrap();
        assert_eq!(
            uds_accepted["actions"][0]["os_tool_manifest_sha256"],
            supervised_accepted["actions"][0]["os_tool_manifest_sha256"]
        );
        assert_eq!(
            uds_accepted["actions"][0]["os_executor_sha256"],
            supervised_accepted["actions"][0]["os_executor_sha256"]
        );
    }

    #[test]
    fn os_supervised_dispatch_rejects_unmarked_task_and_stale_manifest() {
        let service = AgentService::in_memory().unwrap();
        let (registration, peer) = provisioned_uds_agent(&service);
        let executable = dispatch_identity_for_test_peer(&peer);
        let task = service
            .create_task_local(TaskInput {
                title: "unmarked task".to_string(),
                description: None,
                metadata: json!({
                    "agent_id": registration.agent_id,
                    "agent_peer_uid": registration.peer_uid,
                    "agent_peer_gid": registration.peer_gid,
                    "agent_peer_selinux_domain": registration.selinux_domain,
                    "agent_peer_executable_sha256": registration.identity_key_sha256,
                    "agent_peer_executable_dev": executable.dev,
                    "agent_peer_executable_ino": executable.ino,
                    "agent_peer_executable_uid": executable.uid,
                    "agent_peer_executable_gid": executable.gid,
                    "agent_peer_executable_mode": executable.mode,
                    "subject_user_id": 0,
                    "origin_uid": 10_123,
                    "origin_selinux_domain": "u:r:trillionnium_aishell:s0",
                }),
            })
            .unwrap();
        let arguments = json!({});
        let plan = AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: "plan-unmarked-supervised-task".to_string(),
            task_id: task.id,
            session_id: "session-unmarked-supervised-task".to_string(),
            agent_id: registration.agent_id.clone(),
            intent_sha256: "3".repeat(64),
            provider_output_sha256: "4".repeat(64),
            contexts: Vec::new(),
            actions: vec![trillionnium_os_types::AgentPlannedAction {
                action_id: "action-unmarked-supervised-task".to_string(),
                tool_name: "android.browser.open_bounded".to_string(),
                os_tool_manifest_sha256: None,
                os_executor_sha256: None,
                arguments_sha256: sha256_json(&arguments),
                arguments,
                rationale: "negative task-origin fixture".to_string(),
                requires_approval: true,
                network_scope: "per_request".to_string(),
                undo_contract: "no_undo_external_browser_launch".to_string(),
            }],
            created_at_unix_ms: now_unix_ms(),
        };
        let error = dispatch_agent_state_change(
            &service,
            AgentDispatchAuthentication::OsSupervisedProvider {
                registration: &registration,
                executable: &executable,
                origin: None,
            },
            "submit_plan",
            json!(plan.clone()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not own task"));

        let mut stale = registration.clone();
        stale.adapter_version = "stale-generation".to_string();
        let error = dispatch_agent_state_change(
            &service,
            AgentDispatchAuthentication::OsSupervisedProvider {
                registration: &stale,
                executable: &executable,
                origin: None,
            },
            "submit_plan",
            json!(plan),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not match the current AgentManifest"));
    }

    #[test]
    fn immutable_manifest_binding_ignores_only_os_authored_timestamps() {
        let service = AgentService::in_memory().unwrap();
        let (registration, peer) = provisioned_uds_agent(&service);
        let mut reprovisioned = registration.clone();
        reprovisioned.registered_at_unix_ms =
            reprovisioned.registered_at_unix_ms.saturating_add(1_000);
        reprovisioned.updated_at_unix_ms = reprovisioned.updated_at_unix_ms.saturating_add(2_000);
        assert!(same_immutable_agent_manifest_binding(
            &reprovisioned,
            &registration
        ));

        let executable = dispatch_identity_for_test_peer(&peer);
        let mut stored = registration.clone();
        stored.registered_at_unix_ms = reprovisioned.registered_at_unix_ms;
        stored.updated_at_unix_ms = reprovisioned.updated_at_unix_ms;
        service.provision_agent_local(stored).unwrap();
        authenticated_dispatch_registration(
            &service,
            AgentDispatchAuthentication::OsSupervisedProvider {
                registration: &registration,
                executable: &executable,
                origin: None,
            },
        )
        .expect("runtime timestamp changes must not rotate the manifest principal");

        let mut changed_identity = reprovisioned;
        changed_identity.peer_gid = changed_identity.peer_gid.saturating_add(1);
        assert!(!same_immutable_agent_manifest_binding(
            &changed_identity,
            &registration
        ));
    }

    #[test]
    fn disabled_manifest_cannot_dispatch_over_kernel_or_supervised_carrier() {
        let service = AgentService::in_memory().unwrap();
        let (mut registration, peer) = provisioned_uds_agent(&service);
        registration.enabled = false;
        registration.health = AgentHealth::Disabled;
        service.provision_agent_local(registration.clone()).unwrap();

        let kernel_error = authorized_agent_registration(&service, &registration.agent_id, &peer)
            .unwrap_err()
            .to_string();
        assert!(kernel_error.contains("agent identity is disabled"));

        let executable = dispatch_identity_for_test_peer(&peer);
        let supervised_error = authenticated_dispatch_registration(
            &service,
            AgentDispatchAuthentication::OsSupervisedProvider {
                registration: &registration,
                executable: &executable,
                origin: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(supervised_error.contains("does not match the current AgentManifest"));
    }

    #[test]
    fn production_agent_api_catalog_rejects_descriptor_and_demo_tools() {
        let service = AgentService::in_memory().unwrap();
        let (registration, peer) = provisioned_uds_agent(&service);
        let catalog = dispatch_agent_api_uds(
            &service,
            &peer,
            &registration.agent_id,
            "list_tools",
            json!({}),
        )
        .unwrap();
        let names = catalog["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|manifest| manifest.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "android.browser.open_bounded",
                "android.notification.post_bounded"
            ]
        );

        let task = dispatch_agent_api_uds(
            &service,
            &peer,
            &registration.agent_id,
            "create_task",
            json!({
                "title": "production catalog negative",
                "description": null,
                "metadata": {}
            }),
        )
        .unwrap();
        let task_id = task.get("id").and_then(Value::as_str).unwrap();
        let arguments = json!({"message": "not a phone action"});
        let plan = AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: "plan-production-catalog-negative".to_string(),
            task_id: trillionnium_os_types::TaskId(task_id.to_string()),
            session_id: "session-production-catalog-negative".to_string(),
            agent_id: registration.agent_id.clone(),
            intent_sha256: "1".repeat(64),
            provider_output_sha256: "2".repeat(64),
            contexts: Vec::new(),
            actions: vec![trillionnium_os_types::AgentPlannedAction {
                action_id: "action-demo".to_string(),
                tool_name: "demo.approval_echo".to_string(),
                os_tool_manifest_sha256: None,
                os_executor_sha256: None,
                arguments_sha256: sha256_json(&arguments),
                arguments,
                rationale: "negative fixture".to_string(),
                requires_approval: true,
                network_scope: "none".to_string(),
                undo_contract: "none".to_string(),
            }],
            created_at_unix_ms: now_unix_ms(),
        };
        let error = dispatch_agent_api_uds(
            &service,
            &peer,
            &registration.agent_id,
            "submit_plan",
            json!(plan),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("outside the production Agent API catalog"));

        let browser_arguments = json!({});
        let browser_plan = AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: "plan-production-preview-contract".to_string(),
            task_id: trillionnium_os_types::TaskId(task_id.to_string()),
            session_id: "session-production-preview-contract".to_string(),
            agent_id: registration.agent_id.clone(),
            intent_sha256: "3".repeat(64),
            provider_output_sha256: "4".repeat(64),
            contexts: Vec::new(),
            actions: vec![trillionnium_os_types::AgentPlannedAction {
                action_id: "action-browser".to_string(),
                tool_name: "android.browser.open_bounded".to_string(),
                os_tool_manifest_sha256: None,
                os_executor_sha256: None,
                arguments_sha256: sha256_json(&browser_arguments),
                arguments: browser_arguments,
                rationale: "manifest contract fixture".to_string(),
                requires_approval: true,
                network_scope: "per_request".to_string(),
                undo_contract: "no_undo_external_browser_launch".to_string(),
            }],
            created_at_unix_ms: now_unix_ms(),
        };
        let mut approval_drift = browser_plan.clone();
        approval_drift.actions[0].requires_approval = false;
        let mut network_drift = browser_plan.clone();
        network_drift.actions[0].network_scope = "none".to_string();
        let mut undo_drift = browser_plan.clone();
        undo_drift.actions[0].undo_contract = "close_the_tab".to_string();
        for (candidate, expected_field) in [
            (approval_drift, "requires_approval"),
            (network_drift, "network_scope"),
            (undo_drift, "undo_contract"),
        ] {
            let error = dispatch_agent_api_uds(
                &service,
                &peer,
                &registration.agent_id,
                "submit_plan",
                json!(candidate),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains(expected_field), "{error}");
        }
        let accepted = dispatch_agent_api_uds(
            &service,
            &peer,
            &registration.agent_id,
            "submit_plan",
            json!(browser_plan),
        )
        .expect("exact OS manifest preview semantics must be accepted");
        assert_eq!(accepted["actions"][0]["requires_approval"], true);
        assert_eq!(accepted["actions"][0]["network_scope"], "per_request");
        assert!(
            accepted["actions"][0]["os_tool_manifest_sha256"]
                .as_str()
                .is_some_and(|digest| digest.len() == 64)
        );
        assert_eq!(
            accepted["actions"][0]["undo_contract"],
            "no_undo_external_browser_launch"
        );
    }

    #[test]
    fn delegated_data_api_enforces_agent_task_and_peer_binding() {
        let service = AgentService::in_memory().unwrap();
        let (registration, peer) = provisioned_uds_agent(&service);
        let temp = tempfile::tempdir().unwrap();
        let context_memory =
            ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let owner = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        let context = context_memory
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "file",
                    "source_id": "saf:generic-delegation",
                    "content": "generic delegated context",
                }),
            )
            .unwrap();
        let create_task = |title: &str| {
            dispatch_agent_api_uds(
                &service,
                &peer,
                &registration.agent_id,
                "create_task",
                json!({"title": title, "description": null, "metadata": {}}),
            )
            .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let task_id = create_task("delegated data owner task");
        let other_task_id = create_task("delegated data other task");
        let grant = context_memory
            .issue_context_grant(
                &owner,
                context_memory::AgentGrantTarget {
                    agent_id: registration.agent_id.clone(),
                    peer_uid: peer.uid,
                    peer_gid: peer.gid,
                    selinux_domain: peer.selinux_domain.clone(),
                    executable_sha256: peer.executable_sha256.clone(),
                    task_id: task_id.clone(),
                    subject_user_id: 0,
                },
                context["context_id"].as_str().unwrap(),
                true,
                "none",
                "none",
                60_000,
            )
            .unwrap();
        let grant_id = grant["grant_id"].as_str().unwrap();
        let listed = dispatch_agent_data_api(
            &service,
            &context_memory,
            &peer,
            &registration.agent_id,
            "list_data_grants",
            json!({"task_id": task_id.clone()}),
        )
        .unwrap();
        assert_eq!(listed["count"], 1);
        assert!(listed["items"][0].get("content").is_none());

        let wrong_task = dispatch_agent_data_api(
            &service,
            &context_memory,
            &peer,
            &registration.agent_id,
            "read_context_grant",
            json!({"task_id": other_task_id, "grant_id": grant_id}),
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_task.contains("consumer_binding_mismatch"));
        let mut impersonator = peer.clone();
        impersonator.executable_sha256 = "b".repeat(64);
        let wrong_peer = dispatch_agent_data_api(
            &service,
            &context_memory,
            &impersonator,
            &registration.agent_id,
            "read_context_grant",
            json!({"task_id": task_id.clone(), "grant_id": grant_id}),
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_peer.contains("kernel-authenticated peer binding"));
        let mut wrong_gid = peer.clone();
        wrong_gid.gid = wrong_gid.gid.saturating_add(1);
        let wrong_gid = dispatch_agent_data_api(
            &service,
            &context_memory,
            &wrong_gid,
            &registration.agent_id,
            "read_context_grant",
            json!({"task_id": task_id.clone(), "grant_id": grant_id}),
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_gid.contains("kernel-authenticated peer binding"));
        let raw = dispatch_agent_data_api(
            &service,
            &context_memory,
            &peer,
            &registration.agent_id,
            "read_context_grant",
            json!({"task_id": task_id, "grant_id": grant_id}),
        )
        .unwrap();
        assert_eq!(raw["content"], "generic delegated context");
    }

    #[test]
    fn os_owned_agent_manifest_loader_provisions_and_rejects_writable_files() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner_uid = std::fs::symlink_metadata(directory.path()).unwrap().uid();
        let service = AgentService::in_memory().unwrap();
        let registration = AgentRegistration {
            api_version: AGENT_API_VERSION.to_string(),
            agent_id: "agent-manifest-loader-test".to_string(),
            adapter: "fixture-adapter".to_string(),
            adapter_version: "1".to_string(),
            identity_key_sha256: "c".repeat(64),
            peer_uid: 25001,
            peer_gid: 25002,
            selinux_domain: "u:r:trillionnium_manifest_agent:s0".to_string(),
            network_policy: AgentNetworkPolicy::Deny,
            enabled: true,
            health: AgentHealth::Ready,
            registered_at_unix_ms: 0,
            updated_at_unix_ms: 0,
        };
        let manifest = directory.path().join("fixture.json");
        std::fs::write(&manifest, serde_json::to_vec(&registration).unwrap()).unwrap();
        std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            load_os_agent_manifests(&service, directory.path(), owner_uid).unwrap(),
            1
        );
        assert_eq!(
            service
                .get_agent_local(&registration.agent_id)
                .unwrap()
                .unwrap()
                .identity_key_sha256,
            registration.identity_key_sha256
        );
        let provisioned = service
            .get_agent_local(&registration.agent_id)
            .unwrap()
            .unwrap();
        assert!(provisioned.registered_at_unix_ms > 0);
        assert!(provisioned.updated_at_unix_ms >= provisioned.registered_at_unix_ms);

        std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o666)).unwrap();
        let error = load_os_agent_manifests(&service, directory.path(), owner_uid)
            .unwrap_err()
            .to_string();
        assert!(error.contains("owner-controlled regular file"));
    }

    #[test]
    fn os_owned_agent_manifest_loader_is_closed_world_and_rejects_duplicate_or_runtime_fields() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner_uid = std::fs::symlink_metadata(directory.path()).unwrap().uid();
        let service = AgentService::in_memory().unwrap();
        let path = directory.path().join("fixture.json");
        let base = json!({
            "api_version": AGENT_API_VERSION,
            "agent_id": "agent-manifest-closed-world",
            "adapter": "fixture-adapter",
            "adapter_version": "1",
            "identity_key_sha256": "c".repeat(64),
            "peer_uid": 25001,
            "peer_gid": 25002,
            "selinux_domain": "u:r:trillionnium_manifest_agent:s0",
            "network_policy": "deny",
            "enabled": true,
            "health": "ready",
            "registered_at_unix_ms": 0,
            "updated_at_unix_ms": 0
        });

        let mut extra = base.clone();
        extra["runtime_override"] = json!(true);
        std::fs::write(&path, serde_json::to_vec(&extra).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = load_os_agent_manifests(&service, directory.path(), owner_uid).unwrap_err();
        assert!(format!("{error:#}").contains("unknown field"));

        let duplicate = format!(
            "{{\"api_version\":\"{}\",\"agent_id\":\"agent-one\",\"agent_id\":\"agent-two\",\"adapter\":\"fixture\",\"adapter_version\":\"1\",\"identity_key_sha256\":\"{}\",\"peer_uid\":25001,\"peer_gid\":25002,\"selinux_domain\":\"u:r:test:s0\",\"network_policy\":\"deny\",\"enabled\":true,\"health\":\"ready\",\"registered_at_unix_ms\":0,\"updated_at_unix_ms\":0}}",
            AGENT_API_VERSION,
            "d".repeat(64)
        );
        std::fs::write(&path, duplicate).unwrap();
        let error = load_os_agent_manifests(&service, directory.path(), owner_uid).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate key"));

        let mut runtime_timestamp = base;
        runtime_timestamp["registered_at_unix_ms"] = json!(1);
        runtime_timestamp["updated_at_unix_ms"] = json!(1);
        std::fs::write(&path, serde_json::to_vec(&runtime_timestamp).unwrap()).unwrap();
        assert!(
            load_os_agent_manifests(&service, directory.path(), owner_uid)
                .unwrap_err()
                .to_string()
                .contains("timestamps must be zero")
        );
    }

    #[test]
    fn android_ui_api_requires_the_preprovisioned_codex_manifest() {
        let service = AgentService::in_memory().unwrap();
        assert!(
            require_android_builtin_manifests(&service)
                .unwrap_err()
                .to_string()
                .contains("requires an OS-owned AgentManifest")
        );
        let now = now_unix_ms();
        service
            .provision_agent_local(AgentRegistration {
                api_version: AGENT_API_VERSION.to_string(),
                agent_id: BUILTIN_CODEX_AGENT_ID.to_string(),
                adapter: codex_adapter::CODEX_ADAPTER_NAME.to_string(),
                adapter_version: codex_adapter::CODEX_ADAPTER_VERSION.to_string(),
                identity_key_sha256: builtin_provider_identity::active_launcher_identity(&CODEX)
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        trillionnium_os_types::sha256_bytes(
                            b"fixture-independently-measured-active-launcher",
                        )
                    }),
                peer_uid: CODEX.uid,
                peer_gid: CODEX.gid,
                selinux_domain: CODEX.agent_selinux_domain.to_string(),
                network_policy: AgentNetworkPolicy::PerRequest,
                enabled: true,
                health: AgentHealth::Ready,
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
            })
            .unwrap();
        require_android_builtin_manifests(&service).unwrap();
    }

    #[test]
    fn state_change_stream_requires_fresh_same_channel_challenge_response() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let service = AgentService::in_memory().unwrap();
        let replay = Arc::new(Mutex::new(
            AgentApiReplayStore::open(
                &directory.path().join("replay.json"),
                "boot-channel-auth-test",
            )
            .unwrap(),
        ));
        let context_memory =
            ContextMemoryService::open(directory.path().join("context-memory")).unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        enable_unix_message_credentials(&server).unwrap();
        provision_connected_uds_agent(&service, &server, "agent-channel-auth-test");
        let worker = std::thread::spawn(move || {
            handle_agent_api_stream(
                &service,
                &replay,
                &context_memory,
                &server,
                Duration::from_secs(5),
            )
        });

        let initial = json!({
            "protocol": AGENT_API_UDS_PROTOCOL,
            "request_id": "request-channel-auth-e2e",
            "method": "cancel_task",
            "agent_id": "agent-channel-auth-test",
            "payload": {"task_id": "task-unknown"},
        });
        let mut initial_frame = serde_json::to_vec(&initial).unwrap();
        initial_frame.push(b'\n');
        client.write_all(&initial_frame).unwrap();

        let challenge_frame = match read_agent_frame(&client) {
            Ok(frame) => frame,
            Err(client_error) => {
                let server_result = worker.join().unwrap();
                panic!("challenge read failed: {client_error:#}; server: {server_result:?}");
            }
        };
        let challenge = parse_request_json(&challenge_frame, "test_challenge").unwrap();
        assert_eq!(challenge["type"], "channel_binding_challenge");
        assert_eq!(challenge["request_id"], "request-channel-auth-e2e");
        let nonce = challenge["challenge"]["nonce"]
            .as_str()
            .expect("challenge nonce");
        let request_sha256 = challenge["challenge"]["request_sha256"]
            .as_str()
            .expect("challenge request digest");
        assert_eq!(nonce.len(), 64);
        assert_eq!(request_sha256.len(), 64);

        let mut authenticated = initial;
        authenticated.as_object_mut().unwrap().insert(
            "channel_binding".to_string(),
            json!({
                "schema": AGENT_API_CHANNEL_AUTH_SCHEMA,
                "nonce": nonce,
                "request_sha256": request_sha256,
            }),
        );
        let mut authenticated_frame = serde_json::to_vec(&authenticated).unwrap();
        authenticated_frame.push(b'\n');
        client.write_all(&authenticated_frame).unwrap();

        let response = worker.join().unwrap().unwrap();
        assert_eq!(response["ok"], false);
        assert!(
            response["error"]
                .as_str()
                .is_some_and(|error| error.contains("unknown task id"))
        );
    }

    #[test]
    fn state_change_stream_rejects_binding_supplied_before_server_challenge() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let service = AgentService::in_memory().unwrap();
        let replay = Arc::new(Mutex::new(
            AgentApiReplayStore::open(
                &directory.path().join("replay.json"),
                "boot-prebound-auth-test",
            )
            .unwrap(),
        ));
        let context_memory =
            ContextMemoryService::open(directory.path().join("context-memory")).unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        enable_unix_message_credentials(&server).unwrap();
        provision_connected_uds_agent(&service, &server, "agent-channel-prebound-test");
        let worker = std::thread::spawn(move || {
            handle_agent_api_stream(
                &service,
                &replay,
                &context_memory,
                &server,
                Duration::from_secs(5),
            )
        });
        let mut frame = serde_json::to_vec(&json!({
            "protocol": AGENT_API_UDS_PROTOCOL,
            "request_id": "request-channel-prebound",
            "method": "cancel_task",
            "agent_id": "agent-channel-prebound-test",
            "payload": {"task_id": "task-unknown"},
            "channel_binding": {
                "schema": AGENT_API_CHANNEL_AUTH_SCHEMA,
                "nonce": "a".repeat(64),
                "request_sha256": "b".repeat(64),
            },
        }))
        .unwrap();
        frame.push(b'\n');
        client.write_all(&frame).unwrap();
        let error = format!("{:#}", worker.join().unwrap().unwrap_err());
        assert!(
            error.contains("cannot precede its server challenge"),
            "{error}"
        );
    }

    #[test]
    fn channel_handshake_uses_one_deadline_across_both_frames() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let service = AgentService::in_memory().unwrap();
        let replay = Arc::new(Mutex::new(
            AgentApiReplayStore::open(
                &directory.path().join("replay.json"),
                "boot-absolute-channel-deadline-test",
            )
            .unwrap(),
        ));
        let context_memory =
            ContextMemoryService::open(directory.path().join("context-memory")).unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        enable_unix_message_credentials(&server).unwrap();
        provision_connected_uds_agent(&service, &server, "agent-channel-deadline-test");
        let worker = std::thread::spawn(move || {
            handle_agent_api_stream(
                &service,
                &replay,
                &context_memory,
                &server,
                Duration::from_secs(1),
            )
        });
        let mut frame = serde_json::to_vec(&json!({
            "protocol": AGENT_API_UDS_PROTOCOL,
            "request_id": "request-channel-deadline",
            "method": "cancel_task",
            "agent_id": "agent-channel-deadline-test",
            "payload": {"task_id": "task-unknown"},
        }))
        .unwrap();
        frame.push(b'\n');
        client.write_all(&frame).unwrap();
        let challenge = read_agent_frame(&client).unwrap();
        assert_eq!(
            parse_request_json(&challenge, "test_challenge").unwrap()["type"],
            "channel_binding_challenge"
        );
        let started = Instant::now();
        std::thread::sleep(Duration::from_millis(1_200));
        let error = format!("{:#}", worker.join().unwrap().unwrap_err());
        assert!(started.elapsed() < Duration::from_secs(2), "{error}");
        assert!(
            error.contains("deadline")
                || error.contains("timed out")
                || error.contains("temporarily unavailable"),
            "{error}"
        );
    }

    #[test]
    fn credential_bound_slowloris_is_cut_off_by_one_absolute_deadline() {
        let (server, mut client) = UnixStream::pair().unwrap();
        enable_unix_message_credentials(&server).unwrap();
        let writer = std::thread::spawn(move || {
            for byte in b"{\"protocol\":\"trillionnium.agent-api.uds.v2\"}" {
                if client.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        let error = read_agent_frame_with_credentials(
            &server,
            AgentApiDeadline::from_now(Duration::from_millis(90)).unwrap(),
        )
        .unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "{elapsed:?}: {error:#}"
        );
        drop(server);
        writer.join().unwrap();
    }

    #[test]
    fn generic_uds_pool_rejects_connections_when_workers_and_queue_are_full() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (_worker_barrier, worker_test_barrier, worker_entered) =
            new_agent_pool_worker_test_barrier();
        let replay = Arc::new(Mutex::new(
            AgentApiReplayStore::open(&temp.path().join("replay.json"), "boot-pool-test").unwrap(),
        ));
        let pool = AgentConnectionPool::spawn(
            Arc::new(AgentService::in_memory().unwrap()),
            replay,
            Arc::new(ContextMemoryService::open(temp.path().join("context-memory")).unwrap()),
            AgentConnectionPoolConfig {
                workers: 1,
                queue_depth: 1,
                per_uid_limit: 3,
                read_timeout: Duration::from_millis(250),
                write_timeout: Duration::from_millis(250),
                worker_test_barrier: Some(worker_test_barrier),
            },
        )
        .unwrap();
        let (first_server, _first_client) = UnixStream::pair().unwrap();
        pool.submit(first_server).unwrap();
        worker_entered
            .recv_timeout(Duration::from_secs(1))
            .expect("worker did not enter the explicit test barrier");
        let (second_server, _second_client) = UnixStream::pair().unwrap();
        pool.submit(second_server).unwrap();
        let (third_server, _third_client) = UnixStream::pair().unwrap();
        assert_eq!(
            pool.submit(third_server).unwrap_err().reason,
            "agent_api_busy"
        );
    }

    #[test]
    fn generic_uds_pool_limits_each_uid_across_workers_and_queue() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let replay = Arc::new(Mutex::new(
            AgentApiReplayStore::open(&temp.path().join("replay.json"), "boot-uid-limit-test")
                .unwrap(),
        ));
        let pool = AgentConnectionPool::spawn(
            Arc::new(AgentService::in_memory().unwrap()),
            replay,
            Arc::new(ContextMemoryService::open(temp.path().join("context-memory")).unwrap()),
            AgentConnectionPoolConfig {
                workers: 1,
                queue_depth: 4,
                per_uid_limit: 2,
                read_timeout: Duration::from_millis(250),
                write_timeout: Duration::from_millis(250),
                worker_test_barrier: None,
            },
        )
        .unwrap();
        let (first_server, _first_client) = UnixStream::pair().unwrap();
        pool.submit(first_server).unwrap();
        let (second_server, _second_client) = UnixStream::pair().unwrap();
        pool.submit(second_server).unwrap();
        let (third_server, _third_client) = UnixStream::pair().unwrap();
        assert_eq!(
            pool.submit(third_server).unwrap_err().reason,
            "agent_api_uid_connection_limit"
        );
    }

    #[test]
    fn generic_uds_requires_exact_bounded_newline_frame() {
        let (server, mut client) = UnixStream::pair().unwrap();
        client.write_all(b"{}\n").unwrap();
        assert_eq!(read_agent_frame(&server).unwrap(), b"{}");

        let (server, mut client) = UnixStream::pair().unwrap();
        let oversized = vec![b'a'; MAX_AGENT_API_FRAME_BYTES + 1];
        let writer = std::thread::spawn(move || {
            client.write_all(&oversized).unwrap();
            client.write_all(b"\n").unwrap();
        });
        assert!(read_agent_frame(&server).is_err());
        writer.join().unwrap();
    }
}
