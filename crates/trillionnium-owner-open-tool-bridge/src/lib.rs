//! Owner-open call-registry to direct process-runtime bridge.
//!
//! This crate performs the smallest reviewed W1/W2 handoff: one codec-authored
//! canonical request is bound to one scoped call ID, exactly one caller may
//! spawn it, registry cancellation is bridged to the process runtime, PID and
//! terminal observations are recorded, and all runtime events remain available
//! to the embedding Host. It never adds plan, risk, approval, Authority, typed
//! ADB or command allowlist semantics.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};
use trillionnium_owner_open_call_registry::{
    CallKey, CallRegistry, CallRequest, CallSnapshot, RegistryError, SpawnClaim, TerminalRecord,
};
use trillionnium_owner_open_runtime::{
    AdbExecRequest, CancellationToken as RuntimeCancellationToken, ExecutionEvent,
    ExecutionEventKind, ExecutionTerminal, MechanicalLimits, ShellExecRequest, StreamKind,
    execute_adb, execute_shell,
};

#[derive(Debug)]
pub enum BridgeError {
    InvalidRequest(String),
    ClaimedDigestMismatch {
        claimed: String,
        computed: String,
    },
    Registry(RegistryError),
    RegistryObservation(RegistryError),
    CancellationMonitorPanicked,
    ObservationStatePoisoned,
}

impl Display for BridgeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid owner-open tool bridge request: {message}")
            }
            Self::ClaimedDigestMismatch { claimed, computed } => write!(
                formatter,
                "claimed owner-open request digest {claimed} does not match computed {computed}",
            ),
            Self::Registry(error) => write!(formatter, "owner-open call registry failed: {error}"),
            Self::RegistryObservation(error) => write!(
                formatter,
                "owner-open runtime completed with a registry observation failure: {error}",
            ),
            Self::CancellationMonitorPanicked => {
                formatter.write_str("owner-open cancellation monitor panicked")
            }
            Self::ObservationStatePoisoned => {
                formatter.write_str("owner-open bridge observation state is poisoned")
            }
        }
    }
}

impl Error for BridgeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Registry(error) | Self::RegistryObservation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RegistryError> for BridgeError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

pub type Result<T> = std::result::Result<T, BridgeError>;

#[derive(Debug, Clone)]
pub enum DirectToolRequest {
    Shell(ShellExecRequest),
    Adb(AdbExecRequest),
}

impl DirectToolRequest {
    #[must_use]
    pub const fn tool_name(&self) -> &'static str {
        match self {
            Self::Shell(_) => "shell.exec",
            Self::Adb(_) => "adb.exec",
        }
    }
}

/// A call bound to exact canonical request bytes authored by the owner-open
/// codec layer.
///
/// The bridge hashes these bytes itself. The embedding codec is responsible for
/// producing the same canonical bytes that were validated into `request`; this
/// separation keeps process code independent from wire/JSON canonicalization.
#[derive(Debug, Clone)]
pub struct BoundToolCall {
    pub key: CallKey,
    pub binding_fingerprint: String,
    pub target_id: Option<String>,
    pub canonical_request: Vec<u8>,
    pub request_sha256: String,
    pub request: DirectToolRequest,
}

impl BoundToolCall {
    pub fn new(
        key: CallKey,
        binding_fingerprint: impl Into<String>,
        target_id: Option<String>,
        canonical_request: Vec<u8>,
        request: DirectToolRequest,
    ) -> Result<Self> {
        if canonical_request.is_empty() {
            return Err(invalid("canonical request bytes must not be empty"));
        }
        let request_sha256 = sha256_hex(&canonical_request);
        let value = Self {
            key,
            binding_fingerprint: binding_fingerprint.into(),
            target_id,
            canonical_request,
            request_sha256,
            request,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn with_claimed_digest(
        key: CallKey,
        binding_fingerprint: impl Into<String>,
        target_id: Option<String>,
        canonical_request: Vec<u8>,
        claimed_request_sha256: impl Into<String>,
        request: DirectToolRequest,
    ) -> Result<Self> {
        let claimed = claimed_request_sha256.into();
        require_sha256(&claimed, "claimed_request_sha256")?;
        let value = Self::new(
            key,
            binding_fingerprint,
            target_id,
            canonical_request,
            request,
        )?;
        if value.request_sha256 != claimed {
            return Err(BridgeError::ClaimedDigestMismatch {
                claimed,
                computed: value.request_sha256,
            });
        }
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        require_sha256(&self.binding_fingerprint, "binding_fingerprint")?;
        require_sha256(&self.request_sha256, "request_sha256")?;
        if self.canonical_request.len() > 1024 * 1024 {
            return Err(invalid("canonical request exceeds the bridge byte bound"));
        }
        if self
            .target_id
            .as_ref()
            .is_some_and(|value| value.len() > 4_096 || value.as_bytes().contains(&0))
        {
            return Err(invalid("target_id exceeds its mechanical bound"));
        }
        Ok(())
    }

    fn registry_request(&self) -> CallRequest {
        CallRequest::new(
            self.request_sha256.clone(),
            self.binding_fingerprint.clone(),
            self.request.tool_name(),
            self.target_id.clone(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct BridgeLimits {
    pub runtime: MechanicalLimits,
    pub cancellation_poll: Duration,
}

impl Default for BridgeLimits {
    fn default() -> Self {
        Self {
            runtime: MechanicalLimits::default(),
            cancellation_poll: Duration::from_millis(5),
        }
    }
}

impl BridgeLimits {
    pub fn validate(&self) -> Result<()> {
        if self.cancellation_poll.is_zero() || self.cancellation_poll > Duration::from_secs(1) {
            return Err(invalid(
                "cancellation poll must be non-zero and at most one second",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum DispatchResult {
    Executed {
        generation: u64,
        terminal: ExecutionTerminal,
        observation_sha256: String,
        snapshot: CallSnapshot,
    },
    Existing(CallSnapshot),
    Inhibited(CallSnapshot),
}

#[derive(Debug)]
pub struct DirectToolBridge {
    registry: Arc<CallRegistry>,
}

impl DirectToolBridge {
    #[must_use]
    pub fn new(registry: Arc<CallRegistry>) -> Self {
        Self { registry }
    }

    #[must_use]
    pub fn registry(&self) -> &Arc<CallRegistry> {
        &self.registry
    }

    pub fn execute(
        &self,
        call: BoundToolCall,
        limits: &BridgeLimits,
        mut event_sink: impl FnMut(ExecutionEvent),
    ) -> Result<DispatchResult> {
        limits.validate()?;
        call.validate()?;
        self.registry
            .begin(call.key.clone(), call.registry_request())?;
        let (generation, cancellation) = match self
            .registry
            .claim_spawn(&call.key, &call.request_sha256)?
        {
            SpawnClaim::Granted {
                generation,
                cancellation,
                ..
            } => (generation, cancellation),
            SpawnClaim::Existing(snapshot) => return Ok(DispatchResult::Existing(snapshot)),
            SpawnClaim::Inhibited(snapshot) => return Ok(DispatchResult::Inhibited(snapshot)),
        };

        let runtime_cancellation = RuntimeCancellationToken::new();
        let monitor_cancellation = runtime_cancellation.clone();
        let monitor_finished = Arc::new(AtomicBool::new(false));
        let monitor_finished_child = Arc::clone(&monitor_finished);
        let poll = limits.cancellation_poll;
        let monitor = thread::Builder::new()
            .name(format!("owner-open-cancel-{generation}"))
            .spawn(move || {
                while !monitor_finished_child.load(Ordering::SeqCst) {
                    if cancellation.is_cancelled() {
                        monitor_cancellation.cancel();
                        break;
                    }
                    thread::sleep(poll);
                }
            })
            .map_err(|error| invalid(format!("failed to spawn cancellation monitor: {error}")))?;

        let digest = Arc::new(Mutex::new(ObservationDigest::new(
            &call.key.call_id,
            call.request.tool_name(),
            call.target_id.as_deref(),
            generation,
        )));
        let registry_observation_error = Arc::new(Mutex::new(None::<RegistryError>));
        let digest_sink = Arc::clone(&digest);
        let registry_error_sink = Arc::clone(&registry_observation_error);
        let registry = Arc::clone(&self.registry);
        let key = call.key.clone();

        let mut sink = move |event: ExecutionEvent| {
            if let Ok(mut state) = digest_sink.lock() {
                state.update(&event);
            }
            if let ExecutionEventKind::Started { pid } = &event.kind
                && let Err(error) = registry.record_pid(&key, generation, *pid)
                && let Ok(mut slot) = registry_error_sink.lock()
                && slot.is_none()
            {
                *slot = Some(error);
            }
            event_sink(event);
        };

        let terminal = match call.request {
            DirectToolRequest::Shell(request) => execute_shell(
                request,
                &limits.runtime,
                &runtime_cancellation,
                &mut sink,
            ),
            DirectToolRequest::Adb(request) => execute_adb(
                request,
                &limits.runtime,
                &runtime_cancellation,
                &mut sink,
            ),
        }
        .map_err(|error| invalid(format!("direct process runtime rejected the call: {error}")))?;

        monitor_finished.store(true, Ordering::SeqCst);
        if monitor.join().is_err() {
            return Err(BridgeError::CancellationMonitorPanicked);
        }

        let observation_sha256 = digest
            .lock()
            .map_err(|_| BridgeError::ObservationStatePoisoned)?
            .finish();
        let terminal_record = terminal_record(&terminal, observation_sha256.clone())?;
        self.registry
            .complete(&call.key, generation, terminal_record)?;
        let snapshot = self.registry.snapshot(&call.key)?;

        let observation_error = registry_observation_error
            .lock()
            .map_err(|_| BridgeError::ObservationStatePoisoned)?
            .take();
        if let Some(error) = observation_error {
            return Err(BridgeError::RegistryObservation(error));
        }

        Ok(DispatchResult::Executed {
            generation,
            terminal,
            observation_sha256,
            snapshot,
        })
    }
}

#[derive(Debug)]
struct ObservationDigest {
    hasher: Option<Sha256>,
    next_ordinal: u64,
}

impl ObservationDigest {
    fn new(call_id: &str, tool: &str, target_id: Option<&str>, generation: u64) -> Self {
        let mut hasher = Sha256::new();
        field(&mut hasher, b"schema", b"trillionnium.owner-open.local-observation.v1");
        field(&mut hasher, b"call_id", call_id.as_bytes());
        field(&mut hasher, b"tool", tool.as_bytes());
        field(
            &mut hasher,
            b"target_id",
            target_id.unwrap_or_default().as_bytes(),
        );
        field(&mut hasher, b"spawn_generation", &generation.to_be_bytes());
        Self {
            hasher: Some(hasher),
            next_ordinal: 0,
        }
    }

    fn update(&mut self, event: &ExecutionEvent) {
        let Some(hasher) = self.hasher.as_mut() else {
            return;
        };
        field(hasher, b"event_ordinal", &self.next_ordinal.to_be_bytes());
        self.next_ordinal = self.next_ordinal.saturating_add(1);
        match &event.kind {
            ExecutionEventKind::Accepted => field(hasher, b"kind", b"accepted"),
            ExecutionEventKind::Started { pid } => {
                field(hasher, b"kind", b"started");
                field(hasher, b"pid", &pid.to_be_bytes());
            }
            ExecutionEventKind::Output { stream, bytes } => {
                field(hasher, b"kind", b"output");
                field(
                    hasher,
                    b"stream",
                    match stream {
                        StreamKind::Stdout => b"stdout",
                        StreamKind::Stderr => b"stderr",
                    },
                );
                field(hasher, b"bytes", bytes);
            }
            ExecutionEventKind::Terminal(terminal) => {
                field(hasher, b"kind", b"terminal");
                field(
                    hasher,
                    b"terminal_debug",
                    format!("{:?}", terminal.kind).as_bytes(),
                );
                field(
                    hasher,
                    b"exit_code",
                    &terminal.exit_code.unwrap_or(i32::MIN).to_be_bytes(),
                );
                field(
                    hasher,
                    b"signal",
                    &terminal.signal.unwrap_or(i32::MIN).to_be_bytes(),
                );
                field(hasher, b"stdout_bytes", &terminal.stdout_bytes.to_be_bytes());
                field(hasher, b"stderr_bytes", &terminal.stderr_bytes.to_be_bytes());
                field(
                    hasher,
                    b"output_truncated",
                    &[u8::from(terminal.output_truncated)],
                );
                field(hasher, b"elapsed_ms", &terminal.elapsed_ms.to_be_bytes());
                field(
                    hasher,
                    b"error",
                    terminal.error.as_deref().unwrap_or_default().as_bytes(),
                );
            }
        }
    }

    fn finish(&mut self) -> String {
        let hasher = self
            .hasher
            .take()
            .expect("observation digest is finalized exactly once");
        hex_lower(&hasher.finalize())
    }
}

fn terminal_record(terminal: &ExecutionTerminal, observation_sha256: String) -> Result<TerminalRecord> {
    require_sha256(&observation_sha256, "observation_sha256")?;
    Ok(TerminalRecord::new(
        format!("{:?}", terminal.kind).to_ascii_lowercase(),
        terminal.exit_code,
        terminal.signal,
        observation_sha256,
        terminal.stdout_bytes,
        terminal.stderr_bytes,
    ))
}

fn sha256_hex(value: &[u8]) -> String {
    hex_lower(&Sha256::digest(value))
}

fn field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_lower(value: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid(format!("{label} must be a lowercase SHA-256")));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> BridgeError {
    BridgeError::InvalidRequest(message.into())
}
