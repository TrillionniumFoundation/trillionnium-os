//! Closed `shell.exec.v1` broker/worker source implementation.
//!
//! The `android-product` feature contains the fixed socket, retained Root
//! Linux worker, cgroup, receipt, and Android-property wiring; promotion to
//! effect authority still requires a signed device build and conformance
//! evidence. The executable host worker exists only for tests or the explicit
//! `host-conformance` feature.

#[cfg(feature = "android-product")]
pub mod android_property;
pub mod authorization;
mod durable;
#[cfg(feature = "root-linux-mcp-adapter")]
pub mod mcp_adapter;
#[cfg(feature = "android-product")]
pub mod product_broker;
#[cfg(feature = "android-product")]
pub mod product_ipc;
#[cfg(feature = "android-product")]
pub mod product_paths;
#[cfg(feature = "android-product")]
pub mod product_worker;
mod receipt;
#[cfg(any(test, feature = "host-conformance"))]
mod worker;

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use thiserror::Error;
use trillionnium_os_types::direct_effect::{
    BROKER_RESTART_BEFORE_DISPATCH_ERROR_CODE, DirectEffectBinaryOutputV1,
    DirectEffectDurableStateV1, DirectEffectExecutionProfileV1, DirectEffectIndeterminateReasonV1,
    DirectEffectRequestV1, DirectEffectRiskClassV1, DirectEffectTerminalKindV1,
    DirectEffectTerminalResponseV1, DirectEffectToolV1, DirectEffectTransitionV1,
    TERMINAL_RESPONSE_SCHEMA,
};

pub use durable::{
    DurableEffectRecordV1, DurableShellExecLedgerV1, LedgerRecoveryV1, MAX_DURABLE_EFFECT_RECORDS,
    MAX_DURABLE_LEDGER_RECORD_BYTES, MAX_DURABLE_RECEIPT_RECORD_BYTES,
    MAX_DURABLE_RECORD_RESERVATION_BYTES, StableLedgerRecoveryV1,
};
pub use receipt::{
    DurableShellExecReceiptStoreV1, ReceiptError, ShellExecEffectReceiptBodyV1,
    ShellExecEffectReceiptV1,
};
#[cfg(any(test, feature = "host-conformance"))]
pub use worker::{HostConformanceWorkerV1, RootLinuxPathPolicyV1};

pub const TRANSPORT_PROTOCOL: &str = "org.trillionnium.shell-exec.transport.v1";
pub const RESPONSE_SCHEMA: &str = "org.trillionnium.shell-exec.response.v1";
pub const SOCKET_ADDRESS: &str = "@trillionnium_shell_exec";
pub const ROOT_LINUX_HOST_ROOT: &str = "/data/trillionnium/root-linux/rootfs";
pub const ROOT_LINUX_AGENT_TOOL_PATH: &str = "/usr/local/bin/trillionnium-agent-shell";
pub const ANDROID_BROKER_PATH: &str = "/system_ext/bin/trillionnium-shell-exec-broker-userdebug";
pub const ANDROID_WORKER_PATH: &str = "/system_ext/bin/trillionnium-shell-exec-worker-userdebug";
pub const ANDROID_LEDGER_ROOT: &str = "/data/trillionnium/shell-exec/ledger";
pub const ANDROID_RECEIPT_ROOT: &str = "/data/trillionnium/shell-exec/receipts";
pub const ANDROID_WORKER_CGROUP: &str = "/sys/fs/cgroup/system/trillionnium_shell_exec_worker";
pub const ROOT_LINUX_WORKSPACE_PARENT: &str = "/var/lib/trillionnium/shell-exec/workspace";
pub const ROOT_LINUX_TEMPORARY_PARENT: &str = "/var/lib/trillionnium/shell-exec/temporary";
pub const ROOT_LINUX_EXECUTABLE_POLICY: &str =
    "/etc/trillionnium/shell-exec-standard-allowlist.v1.json";
pub const ANDROID_READY_PROPERTY: &str = "sys.trillionnium.shell_exec.ready";
pub const ANDROID_DESIRED_PROPERTY: &str = "sys.trillionnium.shell_exec.desired";
pub const MCP_SERVER_NAME: &str = "trillionnium_shell_exec";
pub const MCP_TOOL_NAME: &str = "trillionnium_shell_exec";
pub const INVOCATION_TOKEN_ENV: &str = "TRILLIONNIUM_SHELL_EXEC_INVOCATION_TOKEN";
pub const AGENTD_UID: u32 = 0;
pub const AGENTD_GID: u32 = 0;
pub const AGENTD_SELINUX_DOMAIN: &str = "u:r:trillionnium_agentd:s0";
pub const SHELL_ADAPTER_UID: u32 = 5901;
pub const SHELL_ADAPTER_GID: u32 = 5901;
pub const SHELL_ADAPTER_SELINUX_DOMAIN: &str = "u:r:trillionnium_agent_shell_tool:s0";
/// The broker is an init-owned root service; retired integration identities
/// are deliberately never reused.
pub const SHELL_BROKER_UID: u32 = 0;
pub const SHELL_BROKER_SELINUX_DOMAIN: &str = "u:r:trillionnium_shell_exec_broker:s0";
pub const SHELL_WORKER_UID: u32 = 5903;
pub const SHELL_WORKER_GID: u32 = 5903;
pub const SHELL_WORKER_SELINUX_DOMAIN: &str = "u:r:trillionnium_shell_exec_worker:s0";

/// The generic direct-effect contract permits 1 MiB raw output. The first
/// product transport is one AF_UNIX SOCK_SEQPACKET record containing the
/// complete canonical response, and the same result must fit Codex's 1 MiB
/// CallToolResult. Keep the combined raw output at 64 KiB so the worst-case
/// response plus the complete request/state remains below the fixed 256 KiB
/// packet boundary without fragmentation. The broker additionally measures
/// the exact worst-case serialized response for every OS-authored request
/// before it may write DISPATCHED.
pub const MCP_CALL_TOOL_RESULT_BYTES_CAP: usize = 1024 * 1024;
pub const SHELL_EXEC_MAX_RAW_OUTPUT_BYTES: u64 = 64 * 1024;
pub const SHELL_EXEC_FIRST_SLICE_MAX_TIMEOUT_MS: u64 = 60_000;
pub const TRANSPORT_RESPONSE_PACKET_BYTES_CAP: usize = 256 * 1024;

pub const SOURCE_DURABLE_LEDGER_IMPLEMENTED: bool = true;
pub const SOURCE_BROKER_STATE_MACHINE_IMPLEMENTED: bool = true;
pub const HOST_CONFORMANCE_WORKER_IMPLEMENTED: bool = true;
pub const PRODUCT_ANDROID_LISTENER_WIRED: bool = true;
pub const PRODUCT_ACTIVE_INVOCATION_REGISTRATION_WIRED: bool = true;
pub const PRODUCT_PEER_DISCONNECT_CANCELLATION_WIRED: bool = true;
/// The first product worker enters the retained Root-Linux tree with chroot.
/// It deliberately does not claim an independent mount or PID namespace.
pub const PRODUCT_ROOT_LINUX_CHROOT_ENTRY_WIRED: bool = true;
pub const PRODUCT_CGROUP_SECCOMP_SELINUX_WIRED: bool = true;
pub const PRODUCT_ANDROID_READY_PROPERTY_WIRED: bool = true;
pub const PRODUCT_EFFECT_AUTHORITY_AVAILABLE: bool = false;

#[derive(Debug, Error)]
pub enum ShellExecError {
    #[error("shell exec request is denied: {0}")]
    RequestDenied(&'static str),
    #[error("shell exec durable ledger failed: {0}")]
    Durable(#[from] durable::DurableError),
    #[error("shell exec operation is indeterminate and cannot be retried")]
    Indeterminate,
    #[error("shell exec worker preflight failed fatally: {0}")]
    RuntimeFatal(String),
}

pub type Result<T> = std::result::Result<T, ShellExecError>;

#[derive(Debug, Default)]
pub struct CancellationTokenV1(AtomicBool);

impl CancellationTokenV1 {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "completion", rename_all = "snake_case", deny_unknown_fields)]
// Completion is a one-shot bounded value whose direct representation keeps
// receipt/IPC construction allocation-free. Do not box a public carrier only
// to equalize variant sizes.
#[allow(clippy::large_enum_variant)]
pub enum WorkerCompletionV1 {
    Terminal(DirectEffectTerminalResponseV1),
    Indeterminate {
        reason: DirectEffectIndeterminateReasonV1,
        observed_boottime_ms: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerPreflightErrorV1 {
    PolicyRejected(&'static str),
    RuntimeFatal(String),
}

pub trait ShellExecWorkerV1 {
    /// Completes all effect-specific fallible custody work while durable state
    /// is still NOT_DISPATCHED. Implementations must not expose request bytes
    /// to an execution worker from this method.
    fn preflight(
        &mut self,
        _request: &DirectEffectRequestV1,
    ) -> std::result::Result<(), WorkerPreflightErrorV1> {
        Ok(())
    }

    /// Returns the exact custody binding that will accompany this request in
    /// the worker dispatch. Product workers override this after `preflight`
    /// has retained every effect-specific descriptor. Host-conformance
    /// workers preserve the caller-supplied binding.
    fn dispatch_binding_sha256(
        &self,
        _request: &DirectEffectRequestV1,
        caller_binding_sha256: &str,
    ) -> std::result::Result<String, WorkerPreflightErrorV1> {
        if trillionnium_os_types::is_nonzero_lower_sha256(caller_binding_sha256) {
            Ok(caller_binding_sha256.to_string())
        } else {
            Err(WorkerPreflightErrorV1::PolicyRejected(
                "dispatch_binding_invalid",
            ))
        }
    }

    fn execute(
        &mut self,
        request: &DirectEffectRequestV1,
        dispatch_started_boottime_ms: u64,
        cancellation: &CancellationTokenV1,
    ) -> std::result::Result<WorkerCompletionV1, String>;
}

pub fn validate_first_slice_request(request: &DirectEffectRequestV1) -> Result<()> {
    request
        .validate()
        .map_err(|_| ShellExecError::RequestDenied("direct_effect_request_invalid"))?;
    validate_first_slice_policy(request)
}

fn validate_first_slice_policy(request: &DirectEffectRequestV1) -> Result<()> {
    if request.tool != DirectEffectToolV1::ShellExecV1
        || request.effective_profile != DirectEffectExecutionProfileV1::Standard
        || request.risk_class != DirectEffectRiskClassV1::Standard
        || request.confirmation_lease_receipt_sha256.is_some()
    {
        return Err(ShellExecError::RequestDenied("standard_shell_exec_only"));
    }
    validate_first_slice_arguments(&request.arguments)
}

pub fn validate_first_slice_arguments(
    arguments: &trillionnium_os_types::direct_effect::DirectEffectModelArgumentsV1,
) -> Result<()> {
    arguments
        .validate()
        .map_err(|_| ShellExecError::RequestDenied("direct_effect_arguments_invalid"))?;
    if arguments.requested_profile != DirectEffectExecutionProfileV1::Standard {
        return Err(ShellExecError::RequestDenied("standard_shell_exec_only"));
    }
    let executable = arguments
        .argv
        .first()
        .ok_or(ShellExecError::RequestDenied("argv_missing"))?;
    let executable_path = Path::new(executable);
    let components = executable_path.components().collect::<Vec<_>>();
    let normalized = components.iter().collect::<PathBuf>();
    if !executable_path.is_absolute()
        || executable_path.file_name().is_none()
        || components.first() != Some(&Component::RootDir)
        || components[1..]
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
        || normalized.as_os_str() != executable_path.as_os_str()
    {
        return Err(ShellExecError::RequestDenied(
            "absolute_normalized_argv0_required",
        ));
    }
    if requests_inline_shell_command(&arguments.argv) {
        return Err(ShellExecError::RequestDenied(
            "command_string_mode_not_in_v1",
        ));
    }
    if arguments.timeout_ms > SHELL_EXEC_FIRST_SLICE_MAX_TIMEOUT_MS {
        return Err(ShellExecError::RequestDenied(
            "first_slice_timeout_budget_exceeded",
        ));
    }
    if arguments.total_output_limit_bytes > SHELL_EXEC_MAX_RAW_OUTPUT_BYTES
        || arguments.stdout_limit_bytes > SHELL_EXEC_MAX_RAW_OUTPUT_BYTES
        || arguments.stderr_limit_bytes > SHELL_EXEC_MAX_RAW_OUTPUT_BYTES
    {
        return Err(ShellExecError::RequestDenied(
            "mcp_binary_output_budget_exceeded",
        ));
    }
    Ok(())
}

fn requests_inline_shell_command(argv: &[String]) -> bool {
    // Defense in depth for obvious model-authored command-string forms only.
    // It is intentionally not product authority: symlinks and renamed or
    // nested interpreters require the future broker to open beneath the
    // measured rootfs and decide on the opened executable digest before the
    // durable DISPATCHED marker.
    fn shell_name(value: &str) -> bool {
        let basename = Path::new(value)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(value);
        matches!(
            basename,
            "sh" | "ash" | "bash" | "dash" | "ksh" | "mksh" | "zsh"
        )
    }

    fn has_command_flag(arguments: &[String]) -> bool {
        arguments
            .iter()
            .take_while(|value| value.as_str() != "--")
            .any(|value| {
                value == "--command"
                    || (value.starts_with('-')
                        && !value.starts_with("--")
                        && value[1..].chars().any(|flag| flag == 'c'))
            })
    }

    let Some(executable) = argv.first() else {
        return false;
    };
    if shell_name(executable) {
        return has_command_flag(&argv[1..]);
    }
    let basename = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(executable);
    if matches!(basename, "busybox" | "env") {
        // Parsing every env/busybox option and applet form is not a stable
        // security boundary. V1 rejects both launchers completely. Product
        // promotion still requires the opened executable digest allowlist.
        return true;
    }
    false
}

#[derive(Serialize)]
struct TransportResponseBudgetEnvelopeV1<'a> {
    schema: &'static str,
    protocol: &'static str,
    request: &'a DirectEffectRequestV1,
    durable_state: &'a DirectEffectDurableStateV1,
    terminal_response: Option<&'a DirectEffectTerminalResponseV1>,
}

fn decimal_digits(value: u64) -> usize {
    if value == 0 {
        1
    } else {
        value.ilog10() as usize + 1
    }
}

fn base64_encoded_len(value: u64) -> u64 {
    value.saturating_add(2) / 3 * 4
}

fn maximum_size_output_split(request: &DirectEffectRequestV1) -> (usize, usize) {
    let total = request.arguments.total_output_limit_bytes;
    let lower = total.saturating_sub(request.arguments.stderr_limit_bytes);
    let upper = request.arguments.stdout_limit_bytes.min(total);
    let mut best = (lower, total - lower);
    let mut best_score = 0_u64;
    for stdout in lower..=upper {
        let stderr = total - stdout;
        let score = base64_encoded_len(stdout)
            .saturating_add(base64_encoded_len(stderr))
            .saturating_add((2 * decimal_digits(stdout) + 2 * decimal_digits(stderr)) as u64);
        if score > best_score {
            best_score = score;
            best = (stdout, stderr);
        }
    }
    (
        usize::try_from(best.0).expect("first-slice output cap fits usize"),
        usize::try_from(best.1).expect("first-slice output cap fits usize"),
    )
}

pub(crate) fn terminal_budget_candidates(
    request: &DirectEffectRequestV1,
    dispatch_started_boottime_ms: u64,
) -> Vec<DirectEffectTerminalResponseV1> {
    let (stdout_len, stderr_len) = maximum_size_output_split(request);
    let output_response = |kind, exit_code, signal| DirectEffectTerminalResponseV1 {
        schema: TERMINAL_RESPONSE_SCHEMA.to_string(),
        effect_id: request.effect_id.clone(),
        request_sha256: request.request_sha256.clone(),
        dispatch_occurred: true,
        kind,
        exit_code,
        signal,
        backend_error_code: None,
        stdout: DirectEffectBinaryOutputV1::from_complete_bytes(&vec![0xff; stdout_len]),
        stderr: DirectEffectBinaryOutputV1::from_complete_bytes(&vec![0xff; stderr_len]),
        started_boottime_ms: dispatch_started_boottime_ms,
        finished_boottime_ms: u64::MAX,
    };
    vec![
        output_response(DirectEffectTerminalKindV1::Exited, Some(i32::MIN), None),
        output_response(DirectEffectTerminalKindV1::Signaled, None, Some(64)),
        DirectEffectTerminalResponseV1 {
            schema: TERMINAL_RESPONSE_SCHEMA.to_string(),
            effect_id: request.effect_id.clone(),
            request_sha256: request.request_sha256.clone(),
            dispatch_occurred: true,
            kind: DirectEffectTerminalKindV1::LaunchRejected,
            exit_code: None,
            signal: None,
            backend_error_code: Some(format!("a{}", "z".repeat(127))),
            stdout: DirectEffectBinaryOutputV1::from_complete_bytes(b""),
            stderr: DirectEffectBinaryOutputV1::from_complete_bytes(b""),
            started_boottime_ms: dispatch_started_boottime_ms,
            finished_boottime_ms: u64::MAX,
        },
    ]
}

pub fn maximum_terminal_transport_packet_bytes(
    request: &DirectEffectRequestV1,
    dispatch_started_boottime_ms: u64,
    dispatch_binding_sha256: &str,
) -> Result<usize> {
    validate_first_slice_policy(request)?;
    let not_dispatched = DirectEffectDurableStateV1::not_dispatched(request)
        .map_err(|_| ShellExecError::RequestDenied("transport_budget_state_invalid"))?;
    let dispatched = not_dispatched
        .transition(
            request,
            DirectEffectTransitionV1::MarkDispatched {
                started_boottime_ms: dispatch_started_boottime_ms,
                dispatch_binding_sha256: dispatch_binding_sha256.to_string(),
            },
        )
        .map_err(|_| ShellExecError::RequestDenied("transport_budget_state_invalid"))?;
    let mut maximum = 0;
    for response in terminal_budget_candidates(request, dispatch_started_boottime_ms) {
        let observation = response
            .to_terminal_observation(request)
            .map_err(|_| ShellExecError::RequestDenied("transport_budget_response_invalid"))?;
        let terminal = dispatched
            .transition(
                request,
                DirectEffectTransitionV1::RecordTerminal { observation },
            )
            .map_err(|_| ShellExecError::RequestDenied("transport_budget_state_invalid"))?;
        let packet = serde_json::to_vec(&TransportResponseBudgetEnvelopeV1 {
            schema: "org.trillionnium.shell-exec.transport-response.v1",
            protocol: TRANSPORT_PROTOCOL,
            request,
            durable_state: &terminal,
            terminal_response: Some(&response),
        })
        .map_err(|_| ShellExecError::RequestDenied("transport_budget_encode_failed"))?;
        maximum = maximum.max(packet.len());
    }
    Ok(maximum)
}

pub struct ShellExecBrokerCoreV1<W> {
    ledger: DurableShellExecLedgerV1,
    worker: W,
}

impl<W: ShellExecWorkerV1> ShellExecBrokerCoreV1<W> {
    pub fn new(ledger: DurableShellExecLedgerV1, worker: W) -> Self {
        Self { ledger, worker }
    }

    pub fn execute_authenticated(
        &mut self,
        request: &DirectEffectRequestV1,
        now_boottime_ms: u64,
        dispatch_binding_sha256: &str,
        cancellation: &CancellationTokenV1,
    ) -> Result<Vec<u8>> {
        self.execute_authenticated_inner(
            request,
            now_boottime_ms,
            dispatch_binding_sha256,
            cancellation,
            || {
                boottime_ms()
                    .map(|observed| observed.max(now_boottime_ms))
                    .map_err(|_| ShellExecError::RuntimeFatal("boottime_unavailable".to_string()))
            },
        )
    }

    #[cfg(feature = "host-conformance")]
    pub fn execute_authenticated_with_post_dispatch_observer<F>(
        &mut self,
        request: &DirectEffectRequestV1,
        now_boottime_ms: u64,
        dispatch_binding_sha256: &str,
        cancellation: &CancellationTokenV1,
        post_dispatch_observer: F,
    ) -> Result<Vec<u8>>
    where
        F: FnOnce() -> u64,
    {
        self.execute_authenticated_inner(
            request,
            now_boottime_ms,
            dispatch_binding_sha256,
            cancellation,
            || Ok(post_dispatch_observer()),
        )
    }

    fn execute_authenticated_inner<F>(
        &mut self,
        request: &DirectEffectRequestV1,
        now_boottime_ms: u64,
        dispatch_binding_sha256: &str,
        cancellation: &CancellationTokenV1,
        post_dispatch_observer: F,
    ) -> Result<Vec<u8>>
    where
        F: FnOnce() -> Result<u64>,
    {
        request
            .validate()
            .map_err(|_| ShellExecError::RequestDenied("direct_effect_request_invalid"))?;
        match self.ledger.prepare_or_recover(request)? {
            LedgerRecoveryV1::FreshNotDispatched
            | LedgerRecoveryV1::AwaitSameAuthenticatedRetry => {}
            LedgerRecoveryV1::ReplayExactTerminal(bytes) => return Ok(bytes),
            LedgerRecoveryV1::DispatchedMustBecomeIndeterminate => {
                self.ledger
                    .hold_restart_indeterminate(request, now_boottime_ms)?;
                return Err(ShellExecError::Indeterminate);
            }
            LedgerRecoveryV1::HoldIndeterminate => return Err(ShellExecError::Indeterminate),
        }

        let current_boot_id_sha256 = current_boot_id_sha256()
            .map_err(|_| ShellExecError::RequestDenied("boot_identity_unavailable"))?;
        if request.boot_id_sha256 != current_boot_id_sha256 {
            // A reboot changes CLOCK_BOOTTIME and all boot-bound custody. An
            // old NOT_DISPATCHED record is therefore explicitly terminalized
            // without worker contact instead of remaining a permanent
            // identity collision or being silently replaced by a new request.
            // The new boot's CLOCK_BOOTTIME value is not comparable with the
            // old request's absolute deadline.
            return self.ledger.finish_not_dispatched_policy(
                request,
                BROKER_RESTART_BEFORE_DISPATCH_ERROR_CODE,
                now_boottime_ms,
            );
        }

        // Deadline wins when both observations are true.  A cancelled-before-
        // dispatch terminal is valid only while the absolute deadline is still
        // in the future; choosing cancellation first would construct a response
        // that the direct-effect contract correctly rejects as contradictory.
        if now_boottime_ms >= request.absolute_deadline_boottime_ms {
            return self
                .ledger
                .finish_not_dispatched_deadline(request, now_boottime_ms);
        }
        if cancellation.is_cancelled() {
            return self
                .ledger
                .finish_not_dispatched_cancelled(request, now_boottime_ms);
        }
        if let Err(ShellExecError::RequestDenied(code)) = validate_first_slice_policy(request) {
            return self
                .ledger
                .finish_not_dispatched_policy(request, code, now_boottime_ms);
        }
        if let Err(error) = self.worker.preflight(request) {
            return match error {
                WorkerPreflightErrorV1::PolicyRejected(code) => self
                    .ledger
                    .finish_not_dispatched_policy(request, code, now_boottime_ms),
                WorkerPreflightErrorV1::RuntimeFatal(detail) => {
                    Err(ShellExecError::RuntimeFatal(detail))
                }
            };
        }
        let dispatch_binding_sha256 = match self
            .worker
            .dispatch_binding_sha256(request, dispatch_binding_sha256)
        {
            Ok(value) => value,
            Err(error) => {
                return match error {
                    WorkerPreflightErrorV1::PolicyRejected(code) => self
                        .ledger
                        .finish_not_dispatched_policy(request, code, now_boottime_ms),
                    WorkerPreflightErrorV1::RuntimeFatal(detail) => {
                        Err(ShellExecError::RuntimeFatal(detail))
                    }
                };
            }
        };
        let budget_dispatch_boottime_ms = request.absolute_deadline_boottime_ms.saturating_sub(1);
        let packet_bytes = maximum_terminal_transport_packet_bytes(
            request,
            budget_dispatch_boottime_ms,
            &dispatch_binding_sha256,
        )?;
        if packet_bytes > TRANSPORT_RESPONSE_PACKET_BYTES_CAP {
            return self.ledger.finish_not_dispatched_policy(
                request,
                "seqpacket_response_budget_exceeded",
                now_boottime_ms,
            );
        }
        match self.ledger.admit_worst_case_terminal(
            request,
            budget_dispatch_boottime_ms,
            &dispatch_binding_sha256,
        ) {
            Ok(_) => {}
            Err(durable::DurableError::CapacityExhausted) => {
                return self.ledger.finish_not_dispatched_policy(
                    request,
                    "durable_capacity_exhausted",
                    now_boottime_ms,
                );
            }
            Err(error) => return Err(error.into()),
        }

        // Preflight and durable-capacity admission may be slow. Re-sample at
        // the final NOT_DISPATCHED boundary so cancellation/deadline remains a
        // true before-dispatch terminal and the dispatch timestamp/worker
        // timeout reflect the real dispatch instant.
        let pre_dispatch_boottime_ms = boottime_ms()
            .map_err(|_| ShellExecError::RuntimeFatal("boottime_unavailable".to_string()))?
            .max(now_boottime_ms);
        if pre_dispatch_boottime_ms >= request.absolute_deadline_boottime_ms {
            return self
                .ledger
                .finish_not_dispatched_deadline(request, pre_dispatch_boottime_ms);
        }
        if cancellation.is_cancelled() {
            return self
                .ledger
                .finish_not_dispatched_cancelled(request, pre_dispatch_boottime_ms);
        }

        // This call fsyncs, atomically renames, fsyncs the directory, and
        // read-verifies DISPATCHED before the worker trait can be contacted.
        self.ledger
            .mark_dispatched(request, pre_dispatch_boottime_ms, &dispatch_binding_sha256)?;
        // The durable marker can take long enough for cancellation/deadline to
        // change. Re-observe both after fsync/readback and before any worker
        // contact or fork. The marker already says DISPATCHED, so either case
        // is conservatively terminally held as INDETERMINATE, never rewound.
        let post_dispatch_boottime_ms = post_dispatch_observer()?.max(pre_dispatch_boottime_ms);
        if cancellation.is_cancelled() {
            self.ledger.hold_indeterminate(
                request,
                DirectEffectIndeterminateReasonV1::CancelledAfterDispatch,
                post_dispatch_boottime_ms,
            )?;
            return Err(ShellExecError::Indeterminate);
        }
        if post_dispatch_boottime_ms >= request.absolute_deadline_boottime_ms {
            self.ledger.hold_indeterminate(
                request,
                DirectEffectIndeterminateReasonV1::DeadlineAfterDispatch,
                post_dispatch_boottime_ms,
            )?;
            return Err(ShellExecError::Indeterminate);
        }
        match self
            .worker
            .execute(request, pre_dispatch_boottime_ms, cancellation)
        {
            Ok(WorkerCompletionV1::Terminal(response)) => {
                self.ledger.finish_terminal(request, response)
            }
            Ok(WorkerCompletionV1::Indeterminate {
                reason,
                observed_boottime_ms,
            }) => {
                self.ledger
                    .hold_indeterminate(request, reason, observed_boottime_ms)?;
                Err(ShellExecError::Indeterminate)
            }
            Err(_internal_error) => {
                self.ledger.hold_indeterminate(
                    request,
                    DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch,
                    pre_dispatch_boottime_ms,
                )?;
                // Once DISPATCHED is durable, no transport/internal failure
                // may look retryable to the caller. Detailed backend errors
                // belong in OS-private audit evidence, never in the public
                // retry classification.
                Err(ShellExecError::Indeterminate)
            }
        }
    }

    pub fn into_parts(self) -> (DurableShellExecLedgerV1, W) {
        (self.ledger, self.worker)
    }

    #[must_use]
    pub fn durable_state(&self, effect_id: &str) -> Option<&DirectEffectDurableStateV1> {
        self.ledger.state(effect_id)
    }
}

pub fn current_boot_id_sha256() -> std::io::Result<String> {
    let bytes = std::fs::read("/proc/sys/kernel/random/boot_id")?;
    if bytes.len() > 128 {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?
        .trim();
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if !valid {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    Ok(trillionnium_os_types::sha256_bytes(value.as_bytes()))
}

fn boottime_ms() -> std::io::Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is valid writable storage for CLOCK_BOOTTIME.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    let nanos = u64::try_from(value.tv_nsec)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    Ok(seconds
        .saturating_mul(1000)
        .saturating_add(nanos / 1_000_000))
}
