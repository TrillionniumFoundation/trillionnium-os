//! Owner-open call-registry to direct process-runtime bridge.
//!
//! One strict codec-authored request is bound to one scoped call ID. Exactly
//! one caller may spawn it, cancellation reaches the owned process group, PID
//! and terminal observations are recorded, and runtime events remain available
//! to the embedding Host. The bridge adds no plan, risk, approval, Authority,
//! typed ADB or command-allowlist semantics.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::os::unix::ffi::OsStrExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};
use trillionnium_owner_open_call_registry::{
    CallKey, CallRegistry, CallRequest, CallSnapshot, RegistryError, SpawnClaim, TerminalRecord,
};
use trillionnium_owner_open_runtime::{
    AdbExecRequest, CancellationToken as RuntimeCancellationToken, ExecutionEvent,
    ExecutionEventKind, ExecutionTerminal, MechanicalLimits, PtySize, ShellExecRequest,
    ShellInvocation, StreamKind, TerminalKind, ToolKind, execute_adb, execute_adb_pty,
    execute_shell, execute_shell_pty,
};

#[derive(Debug)]
pub enum BridgeError {
    InvalidRequest(String),
    ClaimedDigestMismatch { claimed: String, computed: String },
    Registry(RegistryError),
    RegistryObservation(RegistryError),
    EventSinkFailed(String),
    EventSinkPanicked,
    CancellationMonitorSpawnFailed(String),
    CancellationMonitorPanicked,
    RuntimeRejected(String),
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
            Self::EventSinkFailed(message) => {
                write!(formatter, "owner-open tool event sink failed: {message}")
            }
            Self::EventSinkPanicked => formatter.write_str(
                "owner-open tool event sink panicked; the process group was cancelled and the registry was closed",
            ),
            Self::CancellationMonitorSpawnFailed(message) => write!(
                formatter,
                "owner-open cancellation monitor could not start: {message}",
            ),
            Self::CancellationMonitorPanicked => formatter.write_str(
                "owner-open cancellation monitor panicked after the runtime terminal was recorded",
            ),
            Self::RuntimeRejected(message) => write!(
                formatter,
                "owner-open process runtime rejected a preflighted request: {message}",
            ),
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

    #[must_use]
    const fn tool_kind(&self) -> ToolKind {
        match self {
            Self::Shell(_) => ToolKind::ShellExec,
            Self::Adb(_) => ToolKind::AdbExec,
        }
    }
}

/// A call bound to exact canonical request bytes authored by the owner-open
/// codec layer. The bridge recomputes the digest before registry admission.
#[derive(Debug, Clone)]
pub struct BoundToolCall {
    pub key: CallKey,
    pub binding_fingerprint: String,
    pub target_id: Option<String>,
    pub canonical_request: Vec<u8>,
    pub request_sha256: String,
    pub request: DirectToolRequest,
    /// Optional foreground PTY transport. `None` retains the historical
    /// separate stdout/stderr pipe behavior; the option is mechanical and is
    /// included in the canonical request bytes by the codec layer.
    pub pty: Option<PtySize>,
}

impl BoundToolCall {
    pub fn new(
        key: CallKey,
        binding_fingerprint: impl Into<String>,
        target_id: Option<String>,
        canonical_request: Vec<u8>,
        request: DirectToolRequest,
    ) -> Result<Self> {
        Self::new_with_pty(
            key,
            binding_fingerprint,
            target_id,
            canonical_request,
            request,
            None,
        )
    }

    /// Build a call whose transport mode is bound at construction time.
    /// PTY-enabled calls must carry a matching normalized `pty` member in the
    /// canonical JSON preimage; this prevents a caller from reusing one digest
    /// while changing the actual process wiring.
    pub fn new_with_pty(
        key: CallKey,
        binding_fingerprint: impl Into<String>,
        target_id: Option<String>,
        canonical_request: Vec<u8>,
        request: DirectToolRequest,
        pty: Option<PtySize>,
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
            pty,
        };
        value.validate()?;
        value.validate_canonical_pty()?;
        Ok(value)
    }

    /// Attach an owner-selected PTY transport to this already-canonicalized
    /// call. The canonical bytes must contain the same PTY option; this method
    /// only carries the decoded mechanical form to the process bridge.
    pub fn with_pty(mut self, pty: Option<PtySize>) -> Result<Self> {
        if let Some(size) = pty
            && (size.rows == 0 || size.cols == 0)
        {
            return Err(invalid("PTY rows and cols must be non-zero"));
        }
        self.pty = pty;
        self.validate()?;
        self.validate_canonical_pty()?;
        Ok(self)
    }

    pub fn with_claimed_digest(
        key: CallKey,
        binding_fingerprint: impl Into<String>,
        target_id: Option<String>,
        canonical_request: Vec<u8>,
        claimed_request_sha256: impl Into<String>,
        request: DirectToolRequest,
    ) -> Result<Self> {
        Self::with_claimed_digest_and_pty(
            key,
            binding_fingerprint,
            target_id,
            canonical_request,
            claimed_request_sha256,
            request,
            None,
        )
    }

    pub fn with_claimed_digest_and_pty(
        key: CallKey,
        binding_fingerprint: impl Into<String>,
        target_id: Option<String>,
        canonical_request: Vec<u8>,
        claimed_request_sha256: impl Into<String>,
        request: DirectToolRequest,
        pty: Option<PtySize>,
    ) -> Result<Self> {
        let claimed = claimed_request_sha256.into();
        require_sha256(&claimed, "claimed_request_sha256")?;
        let value = Self::new_with_pty(
            key,
            binding_fingerprint,
            target_id,
            canonical_request,
            request,
            pty,
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
        if self
            .pty
            .is_some_and(|size| size.rows == 0 || size.cols == 0)
        {
            return Err(invalid("PTY rows and cols must be non-zero"));
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

    fn validate_canonical_pty(&self) -> Result<()> {
        let value: serde_json::Value = match serde_json::from_slice(&self.canonical_request) {
            Ok(value) => value,
            Err(error) if self.pty.is_some() => {
                return Err(invalid(format!(
                    "PTY-enabled canonical request is not JSON: {error}"
                )));
            }
            // Non-PTY callers may carry codec-owned canonical bytes whose
            // shape is validated by the upstream codec.  Preserve that
            // boundary while still enforcing every parseable PTY member.
            Err(_) => return Ok(()),
        };
        let Some(pty) = value.as_object().and_then(|object| object.get("pty")) else {
            if self.pty.is_some() {
                return Err(invalid("PTY-enabled canonical request omits pty"));
            }
            return Ok(());
        };
        let (enabled, rows, cols) = match pty {
            serde_json::Value::Bool(enabled) => (*enabled, 24, 80),
            serde_json::Value::Object(object) => {
                let enabled = match object.get("enabled") {
                    None => true,
                    Some(serde_json::Value::Bool(value)) => *value,
                    Some(_) => return Err(invalid("canonical pty.enabled is not boolean")),
                };
                let rows = canonical_pty_dimension(object.get("rows"), "rows", 24)?;
                let cols = canonical_pty_dimension(object.get("cols"), "cols", 80)?;
                (enabled, rows, cols)
            }
            _ => return Err(invalid("canonical pty must be boolean or object")),
        };
        match (self.pty, enabled) {
            (Some(expected), true) if rows == expected.rows && cols == expected.cols => Ok(()),
            (Some(_), _) => Err(invalid(
                "PTY transport does not match the canonical request dimensions",
            )),
            (None, false) => Ok(()),
            (None, true) => Err(invalid(
                "canonical request enables PTY but the bridge has no PTY transport",
            )),
        }
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
        self.runtime
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        if self.cancellation_poll.is_zero() || self.cancellation_poll > Duration::from_secs(1) {
            return Err(invalid(
                "cancellation poll must be non-zero and at most one second",
            ));
        }
        Ok(())
    }
}

fn canonical_pty_dimension(
    value: Option<&serde_json::Value>,
    label: &str,
    default: u16,
) -> Result<u16> {
    let Some(value) = value else {
        return Ok(default);
    };
    let Some(raw) = value.as_u64() else {
        return Err(invalid(format!("canonical pty.{label} is not an integer")));
    };
    let value = u16::try_from(raw)
        .map_err(|_| invalid(format!("canonical pty.{label} is outside the u16 bound")))?;
    if value == 0 {
        return Err(invalid(format!("canonical pty.{label} is zero")));
    }
    Ok(value)
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
        self.execute_fallible(call, limits, move |event| {
            event_sink(event);
            Ok::<(), String>(())
        })
    }

    /// Execute one direct call while guaranteeing registry terminal closure for
    /// every locally observed bridge/runtime/sink failure after spawn claim.
    pub fn execute_fallible<E>(
        &self,
        call: BoundToolCall,
        limits: &BridgeLimits,
        mut event_sink: impl FnMut(ExecutionEvent) -> std::result::Result<(), E>,
    ) -> Result<DispatchResult>
    where
        E: Display,
    {
        limits.validate()?;
        call.validate()?;
        validate_runtime_request(&call.request, call.pty, &limits.runtime)?;
        self.registry
            .begin(call.key.clone(), call.registry_request())?;
        let (generation, cancellation) =
            match self.registry.claim_spawn(&call.key, &call.request_sha256)? {
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

        let mut digest = ObservationDigest::new(
            &call.key.call_id,
            call.request.tool_name(),
            call.target_id.as_deref(),
            generation,
        );
        let mut registry_observation_error = None::<RegistryError>;
        let mut sink_failure = None::<SinkFailure>;
        let sink_cancellation = runtime_cancellation.clone();
        let key = call.key.clone();
        let registry = Arc::clone(&self.registry);
        let mut observe = |event: ExecutionEvent| {
            digest.update(&event);
            if let ExecutionEventKind::Started { pid } = &event.kind
                && let Err(error) = registry.record_pid(&key, generation, *pid)
                && registry_observation_error.is_none()
            {
                registry_observation_error = Some(error);
            }
            if sink_failure.is_none() {
                match catch_unwind(AssertUnwindSafe(|| event_sink(event.clone()))) {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        sink_failure = Some(SinkFailure::Failed(error.to_string()));
                        sink_cancellation.cancel();
                    }
                    Err(_) => {
                        sink_failure = Some(SinkFailure::Panicked);
                        sink_cancellation.cancel();
                    }
                }
            }
        };

        let monitor = match thread::Builder::new()
            .name(format!("owner-open-cancel-{generation}"))
            .spawn(move || {
                while !monitor_finished_child.load(Ordering::SeqCst) {
                    if cancellation.is_cancelled() {
                        monitor_cancellation.cancel();
                        break;
                    }
                    thread::sleep(poll);
                }
            }) {
            Ok(monitor) => monitor,
            Err(error) => {
                let terminal = synthetic_terminal(
                    TerminalKind::IoError,
                    format!("cancellation_monitor_spawn_failed: {error}"),
                );
                emit_synthetic_terminal(&call, &terminal, &mut observe);
                let observation_sha256 = digest.finish();
                self.registry.complete(
                    &call.key,
                    generation,
                    terminal_record(&terminal, observation_sha256)?,
                )?;
                return Err(BridgeError::CancellationMonitorSpawnFailed(
                    error.to_string(),
                ));
            }
        };

        let runtime_result = match (call.request.clone(), call.pty) {
            (DirectToolRequest::Shell(request), Some(size)) => execute_shell_pty(
                request,
                size,
                &limits.runtime,
                &runtime_cancellation,
                &mut observe,
            ),
            (DirectToolRequest::Adb(request), Some(size)) => execute_adb_pty(
                request,
                size,
                &limits.runtime,
                &runtime_cancellation,
                &mut observe,
            ),
            (DirectToolRequest::Shell(request), None) => execute_shell(
                request,
                &limits.runtime,
                &runtime_cancellation,
                &mut observe,
            ),
            (DirectToolRequest::Adb(request), None) => execute_adb(
                request,
                &limits.runtime,
                &runtime_cancellation,
                &mut observe,
            ),
        };
        monitor_finished.store(true, Ordering::SeqCst);
        let monitor_panicked = monitor.join().is_err();

        let (terminal, runtime_rejection) = match runtime_result {
            Ok(terminal) => (terminal, None),
            Err(error) => {
                let message = error.to_string();
                let terminal = synthetic_terminal(
                    TerminalKind::IoError,
                    format!("preflight_runtime_drift: {message}"),
                );
                emit_synthetic_terminal(&call, &terminal, &mut observe);
                (terminal, Some(message))
            }
        };

        let observation_sha256 = digest.finish();
        self.registry.complete(
            &call.key,
            generation,
            terminal_record(&terminal, observation_sha256.clone())?,
        )?;
        let snapshot = self.registry.snapshot(&call.key)?;

        if let Some(error) = registry_observation_error {
            return Err(BridgeError::RegistryObservation(error));
        }
        if let Some(failure) = sink_failure {
            return Err(match failure {
                SinkFailure::Failed(message) => BridgeError::EventSinkFailed(message),
                SinkFailure::Panicked => BridgeError::EventSinkPanicked,
            });
        }
        if monitor_panicked {
            return Err(BridgeError::CancellationMonitorPanicked);
        }
        if let Some(message) = runtime_rejection {
            return Err(BridgeError::RuntimeRejected(message));
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
enum SinkFailure {
    Failed(String),
    Panicked,
}

#[derive(Debug)]
struct ObservationDigest {
    hasher: Option<Sha256>,
    next_ordinal: u64,
}

impl ObservationDigest {
    fn new(call_id: &str, tool: &str, target_id: Option<&str>, generation: u64) -> Self {
        let mut hasher = Sha256::new();
        field(
            &mut hasher,
            b"schema",
            b"trillionnium.owner-open.local-observation.v1",
        );
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
                        StreamKind::Pty => b"pty",
                    },
                );
                field(hasher, b"bytes", bytes);
            }
            ExecutionEventKind::Terminal(terminal) => {
                field(hasher, b"kind", b"terminal");
                field(hasher, b"terminal_kind", terminal.kind.as_str().as_bytes());
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
                field(
                    hasher,
                    b"stdout_bytes",
                    &terminal.stdout_bytes.to_be_bytes(),
                );
                field(
                    hasher,
                    b"stderr_bytes",
                    &terminal.stderr_bytes.to_be_bytes(),
                );
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

fn emit_synthetic_terminal(
    call: &BoundToolCall,
    terminal: &ExecutionTerminal,
    observe: &mut dyn FnMut(ExecutionEvent),
) {
    observe(ExecutionEvent {
        call_id: call.key.call_id.clone(),
        target_id: call.target_id.clone(),
        tool: call.request.tool_kind(),
        seq: 0,
        elapsed_ms: 0,
        kind: ExecutionEventKind::Accepted,
    });
    observe(ExecutionEvent {
        call_id: call.key.call_id.clone(),
        target_id: call.target_id.clone(),
        tool: call.request.tool_kind(),
        seq: 1,
        elapsed_ms: terminal.elapsed_ms,
        kind: ExecutionEventKind::Terminal(terminal.clone()),
    });
}

fn synthetic_terminal(kind: TerminalKind, error: String) -> ExecutionTerminal {
    ExecutionTerminal {
        kind,
        exit_code: None,
        signal: None,
        stdout_bytes: 0,
        stderr_bytes: 0,
        output_truncated: false,
        elapsed_ms: 0,
        error: Some(error),
    }
}

fn terminal_record(
    terminal: &ExecutionTerminal,
    observation_sha256: String,
) -> Result<TerminalRecord> {
    require_sha256(&observation_sha256, "observation_sha256")?;
    Ok(TerminalRecord::new(
        terminal.kind.as_str(),
        terminal.exit_code,
        terminal.signal,
        observation_sha256,
        terminal.stdout_bytes,
        terminal.stderr_bytes,
    ))
}

fn validate_runtime_request(
    request: &DirectToolRequest,
    pty: Option<PtySize>,
    limits: &MechanicalLimits,
) -> Result<()> {
    limits
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    match request {
        DirectToolRequest::Shell(request) => {
            validate_common(
                &request.call_id,
                request.target_id.as_deref(),
                request.cwd.as_deref(),
                &request.env,
                &request.stdin,
                limits,
            )?;
            match &request.invocation {
                ShellInvocation::Command(command) => {
                    validate_text(
                        command,
                        "shell command",
                        limits.max_total_argument_bytes,
                        false,
                    )?;
                    validate_path(
                        &request.shell_executable,
                        "shell executable",
                        limits.max_cwd_bytes,
                        false,
                    )?;
                }
                ShellInvocation::Argv(argv) => validate_argv(argv, "shell argv", limits)?,
            }
        }
        DirectToolRequest::Adb(request) => {
            validate_common(
                &request.call_id,
                request.target_id.as_deref(),
                request.cwd.as_deref(),
                &request.env,
                &request.stdin,
                limits,
            )?;
            validate_argv(&request.argv, "adb argv", limits)?;
            validate_path(
                &request.adb_executable,
                "adb executable",
                limits.max_cwd_bytes,
                true,
            )?;
        }
    }
    if pty.is_some_and(|size| size.rows == 0 || size.cols == 0) {
        return Err(invalid("PTY rows and cols must be non-zero"));
    }
    Ok(())
}

fn validate_common(
    call_id: &str,
    target_id: Option<&str>,
    cwd: Option<&Path>,
    environment: &std::collections::BTreeMap<String, Option<String>>,
    stdin: &[u8],
    limits: &MechanicalLimits,
) -> Result<()> {
    if call_id.is_empty()
        || call_id.len() > limits.max_call_id_bytes
        || !call_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid("call_id is empty, oversized, or malformed"));
    }
    if let Some(target_id) = target_id {
        validate_text(target_id, "target_id", limits.max_target_id_bytes, false)?;
    }
    if let Some(cwd) = cwd {
        validate_path(cwd, "cwd", limits.max_cwd_bytes, false)?;
    }
    if stdin.len() > limits.max_stdin_bytes {
        return Err(invalid("stdin exceeds the configured byte bound"));
    }
    if environment.len() > limits.max_environment_items {
        return Err(invalid("environment delta has too many entries"));
    }
    let mut total = 0usize;
    for (key, value) in environment {
        if key.is_empty() || key.contains('=') || key.as_bytes().contains(&0) {
            return Err(invalid("environment key is empty or malformed"));
        }
        total = total
            .checked_add(key.len())
            .ok_or_else(|| invalid("environment byte count overflow"))?;
        if let Some(value) = value {
            if value.as_bytes().contains(&0) {
                return Err(invalid("environment value contains NUL"));
            }
            total = total
                .checked_add(value.len())
                .ok_or_else(|| invalid("environment byte count overflow"))?;
        }
    }
    if total > limits.max_environment_bytes {
        return Err(invalid(
            "environment delta exceeds the configured byte bound",
        ));
    }
    Ok(())
}

fn validate_argv(argv: &[String], label: &str, limits: &MechanicalLimits) -> Result<()> {
    if argv.is_empty() {
        return Err(invalid(format!("{label} must not be empty")));
    }
    if argv.len() > limits.max_argv_items {
        return Err(invalid(format!("{label} has too many elements")));
    }
    let mut total = 0usize;
    for argument in argv {
        validate_text(argument, label, limits.max_argument_bytes, true)?;
        total = total
            .checked_add(argument.len())
            .ok_or_else(|| invalid(format!("{label} byte count overflow")))?;
    }
    if total > limits.max_total_argument_bytes {
        return Err(invalid(format!("{label} exceeds the total byte bound")));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str, maximum: usize, allow_empty: bool) -> Result<()> {
    if (!allow_empty && value.is_empty()) || value.len() > maximum || value.as_bytes().contains(&0)
    {
        return Err(invalid(format!(
            "{label} is empty, oversized, or contains NUL"
        )));
    }
    Ok(())
}

fn validate_path(path: &Path, label: &str, maximum: usize, allow_empty: bool) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if (!allow_empty && bytes.is_empty()) || bytes.len() > maximum || bytes.contains(&0) {
        return Err(invalid(format!(
            "{label} is empty, oversized, or contains NUL"
        )));
    }
    Ok(())
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
