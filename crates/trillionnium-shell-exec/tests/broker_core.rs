use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;
use trillionnium_os_types::agent_descriptor_registry;
use trillionnium_os_types::direct_effect::{
    BROKER_RESTART_BEFORE_DISPATCH_ERROR_CODE, DirectEffectBinaryOutputV1,
    DirectEffectExecutionProfileV1, DirectEffectModelArgumentsV1, DirectEffectPhaseV1,
    DirectEffectRequestV1, DirectEffectRiskClassV1, DirectEffectTerminalKindV1,
    DirectEffectTerminalResponseV1, DirectEffectToolV1, INVOCATION_ID_PREFIX,
    OS_TOOL_CALL_ID_PREFIX, PROVIDER_ATTEMPT_ID_PREFIX, TERMINAL_RESPONSE_SCHEMA,
};
use trillionnium_shell_exec::{
    CancellationTokenV1, DurableShellExecLedgerV1, DurableShellExecReceiptStoreV1,
    HostConformanceWorkerV1, LedgerRecoveryV1, MAX_DURABLE_EFFECT_RECORDS,
    MAX_DURABLE_LEDGER_RECORD_BYTES, MAX_DURABLE_RECEIPT_RECORD_BYTES,
    MAX_DURABLE_RECORD_RESERVATION_BYTES, MCP_CALL_TOOL_RESULT_BYTES_CAP, RootLinuxPathPolicyV1,
    SHELL_EXEC_MAX_RAW_OUTPUT_BYTES, ShellExecBrokerCoreV1, ShellExecError, ShellExecWorkerV1,
    StableLedgerRecoveryV1, TRANSPORT_RESPONSE_PACKET_BYTES_CAP, WorkerCompletionV1,
    WorkerPreflightErrorV1, maximum_terminal_transport_packet_bytes, validate_first_slice_request,
};

fn digest(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn private_tempdir() -> TempDir {
    let directory = TempDir::new().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn reopen_ledger_after_drop(root: &Path) -> DurableShellExecLedgerV1 {
    // `flock` follows the open-file-description across a concurrent test
    // child's fork and is then released by that child's CLOEXEC. Allow that
    // bounded fork-to-exec window, but still fail if a writer remains live.
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match DurableShellExecLedgerV1::open(root) {
            Ok(ledger) => return ledger,
            Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("durable ledger did not unlock after drop: {error}"),
        }
    }
}

fn boottime_ms() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) },
        0
    );
    value.tv_sec as u64 * 1000 + value.tv_nsec as u64 / 1_000_000
}

fn request(
    argv: Vec<String>,
    now: u64,
    timeout_ms: u64,
    stdout_limit: u64,
    stderr_limit: u64,
    total_limit: u64,
) -> DirectEffectRequestV1 {
    request_with_boot_id(
        argv,
        now,
        timeout_ms,
        stdout_limit,
        stderr_limit,
        total_limit,
        trillionnium_shell_exec::current_boot_id_sha256().unwrap(),
    )
}

#[allow(clippy::too_many_arguments)]
fn request_with_boot_id(
    argv: Vec<String>,
    now: u64,
    timeout_ms: u64,
    stdout_limit: u64,
    stderr_limit: u64,
    total_limit: u64,
    boot_id_sha256: String,
) -> DirectEffectRequestV1 {
    DirectEffectRequestV1::derive_os_owned(
        agent_descriptor_registry::CODEX.provider_id.to_string(),
        agent_descriptor_registry::CODEX.agent_id.to_string(),
        digest('1'),
        format!("{INVOCATION_ID_PREFIX}{}", digest('2')),
        format!("{PROVIDER_ATTEMPT_ID_PREFIX}{}", digest('3')),
        format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('4')),
        1,
        digest('5'),
        digest('6'),
        boot_id_sha256,
        DirectEffectToolV1::ShellExecV1,
        DirectEffectModelArgumentsV1 {
            argv,
            cwd: None,
            timeout_ms,
            stdout_limit_bytes: stdout_limit,
            stderr_limit_bytes: stderr_limit,
            total_output_limit_bytes: total_limit,
            requested_profile: DirectEffectExecutionProfileV1::Standard,
        },
        now + timeout_ms,
        DirectEffectExecutionProfileV1::Standard,
        DirectEffectRiskClassV1::Standard,
        None,
        digest('8'),
        digest('9'),
    )
    .unwrap()
}

fn request_with_ordinal(now: u64, ordinal: u64) -> DirectEffectRequestV1 {
    DirectEffectRequestV1::derive_os_owned(
        agent_descriptor_registry::CODEX.provider_id.to_string(),
        agent_descriptor_registry::CODEX.agent_id.to_string(),
        digest('1'),
        format!("{INVOCATION_ID_PREFIX}{}", digest('2')),
        format!("{PROVIDER_ATTEMPT_ID_PREFIX}{}", digest('3')),
        format!("{OS_TOOL_CALL_ID_PREFIX}{ordinal:064x}"),
        ordinal,
        digest('5'),
        format!("{:064x}", ordinal + 100),
        trillionnium_shell_exec::current_boot_id_sha256().unwrap(),
        DirectEffectToolV1::ShellExecV1,
        DirectEffectModelArgumentsV1 {
            argv: vec!["/usr/bin/printf".to_string(), ordinal.to_string()],
            cwd: None,
            timeout_ms: 5_000,
            stdout_limit_bytes: 16,
            stderr_limit_bytes: 16,
            total_output_limit_bytes: 16,
            requested_profile: DirectEffectExecutionProfileV1::Standard,
        },
        now + 5_000,
        DirectEffectExecutionProfileV1::Standard,
        DirectEffectRiskClassV1::Standard,
        None,
        digest('8'),
        digest('9'),
    )
    .unwrap()
}

fn terminal_response(
    request: &DirectEffectRequestV1,
    started: u64,
    stdout: &[u8],
    stderr: &[u8],
) -> DirectEffectTerminalResponseV1 {
    DirectEffectTerminalResponseV1 {
        schema: TERMINAL_RESPONSE_SCHEMA.to_string(),
        effect_id: request.effect_id.clone(),
        request_sha256: request.request_sha256.clone(),
        dispatch_occurred: true,
        kind: DirectEffectTerminalKindV1::Exited,
        exit_code: Some(0),
        signal: None,
        backend_error_code: None,
        stdout: DirectEffectBinaryOutputV1::from_complete_bytes(stdout),
        stderr: DirectEffectBinaryOutputV1::from_complete_bytes(stderr),
        started_boottime_ms: started,
        finished_boottime_ms: started + 1,
    }
}

struct RecordingWorker {
    ledger_root: PathBuf,
    calls: usize,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl ShellExecWorkerV1 for RecordingWorker {
    fn execute(
        &mut self,
        request: &DirectEffectRequestV1,
        dispatch_started_boottime_ms: u64,
        _cancellation: &CancellationTokenV1,
    ) -> Result<WorkerCompletionV1, String> {
        self.calls += 1;
        let snapshot = fs::read(self.ledger_root.join("shell-exec-ledger.v1.json"))
            .map_err(|error| error.to_string())?;
        let value: Value = serde_json::from_slice(&snapshot).map_err(|error| error.to_string())?;
        let records = value["body"]["records"]
            .as_object()
            .ok_or_else(|| "records_missing".to_string())?;
        let record = records
            .get(&request.effect_id)
            .ok_or_else(|| "effect_missing".to_string())?;
        if record["state"]["phase"] != json!("dispatched")
            || record["state"]["dispatch_occurred"] != json!(true)
        {
            return Err("worker_contacted_before_durable_dispatched".to_string());
        }
        Ok(WorkerCompletionV1::Terminal(terminal_response(
            request,
            dispatch_started_boottime_ms,
            &self.stdout,
            &self.stderr,
        )))
    }
}

struct NeverWorker;

impl ShellExecWorkerV1 for NeverWorker {
    fn execute(
        &mut self,
        _request: &DirectEffectRequestV1,
        _dispatch_started_boottime_ms: u64,
        _cancellation: &CancellationTokenV1,
    ) -> Result<WorkerCompletionV1, String> {
        panic!("worker must not be contacted")
    }
}

struct ErrorWorker;

impl ShellExecWorkerV1 for ErrorWorker {
    fn execute(
        &mut self,
        _request: &DirectEffectRequestV1,
        _dispatch_started_boottime_ms: u64,
        _cancellation: &CancellationTokenV1,
    ) -> Result<WorkerCompletionV1, String> {
        Err("private_backend_detail".to_string())
    }
}

struct FailingPreflightWorker(WorkerPreflightErrorV1);

impl ShellExecWorkerV1 for FailingPreflightWorker {
    fn preflight(
        &mut self,
        _request: &DirectEffectRequestV1,
    ) -> Result<(), WorkerPreflightErrorV1> {
        Err(self.0.clone())
    }

    fn execute(
        &mut self,
        _request: &DirectEffectRequestV1,
        _dispatch_started_boottime_ms: u64,
        _cancellation: &CancellationTokenV1,
    ) -> Result<WorkerCompletionV1, String> {
        panic!("failed preflight must not execute")
    }
}

struct CancellingPreflightWorker {
    cancellation: Arc<CancellationTokenV1>,
    execute_calls: usize,
}

impl ShellExecWorkerV1 for CancellingPreflightWorker {
    fn preflight(
        &mut self,
        _request: &DirectEffectRequestV1,
    ) -> Result<(), WorkerPreflightErrorV1> {
        self.cancellation.cancel();
        Ok(())
    }

    fn execute(
        &mut self,
        _request: &DirectEffectRequestV1,
        _dispatch_started_boottime_ms: u64,
        _cancellation: &CancellationTokenV1,
    ) -> Result<WorkerCompletionV1, String> {
        self.execute_calls += 1;
        panic!("cancelled preflight must not dispatch")
    }
}

struct DelayedPreflightWorker {
    delay: Duration,
    preflight_completed_boottime_ms: Option<u64>,
    dispatch_started_boottime_ms: Option<u64>,
}

impl ShellExecWorkerV1 for DelayedPreflightWorker {
    fn preflight(
        &mut self,
        _request: &DirectEffectRequestV1,
    ) -> Result<(), WorkerPreflightErrorV1> {
        thread::sleep(self.delay);
        self.preflight_completed_boottime_ms = Some(boottime_ms());
        Ok(())
    }

    fn execute(
        &mut self,
        request: &DirectEffectRequestV1,
        dispatch_started_boottime_ms: u64,
        _cancellation: &CancellationTokenV1,
    ) -> Result<WorkerCompletionV1, String> {
        self.dispatch_started_boottime_ms = Some(dispatch_started_boottime_ms);
        Ok(WorkerCompletionV1::Terminal(terminal_response(
            request,
            dispatch_started_boottime_ms,
            b"",
            b"",
        )))
    }
}

#[test]
fn dispatched_is_durable_before_worker_and_terminal_replays_exact_bytes() {
    let root = private_tempdir();
    let now = boottime_ms();
    let request = request(
        vec!["/usr/bin/printf".into(), "%s".into(), "unused".into()],
        now,
        5_000,
        1024,
        1024,
        2048,
    );
    let ledger = DurableShellExecLedgerV1::open(root.path()).unwrap();
    let worker = RecordingWorker {
        ledger_root: root.path().to_path_buf(),
        calls: 0,
        stdout: vec![0xff, 0x00, 0xfe],
        stderr: vec![0x80, 0x00],
    };
    let mut broker = ShellExecBrokerCoreV1::new(ledger, worker);
    let first = broker
        .execute_authenticated(&request, now, &digest('d'), &CancellationTokenV1::default())
        .unwrap();
    let response: DirectEffectTerminalResponseV1 = serde_json::from_slice(&first).unwrap();
    assert_eq!(response.stdout.validate().unwrap(), [0xff, 0x00, 0xfe]);
    assert_eq!(response.stderr.validate().unwrap(), [0x80, 0x00]);

    let second = broker
        .execute_authenticated(
            &request,
            now + 1,
            &digest('d'),
            &CancellationTokenV1::default(),
        )
        .unwrap();
    assert_eq!(second, first);
    let (ledger, worker) = broker.into_parts();
    assert_eq!(worker.calls, 1);
    drop(ledger);

    let reopened = reopen_ledger_after_drop(root.path());
    let mut broker = ShellExecBrokerCoreV1::new(reopened, NeverWorker);
    let after_restart = broker
        .execute_authenticated(
            &request,
            now + 2,
            &digest('d'),
            &CancellationTokenV1::default(),
        )
        .unwrap();
    assert_eq!(after_restart, first);
}

#[test]
fn cancellation_and_deadline_before_dispatch_are_terminal_without_worker() {
    let root = private_tempdir();
    let now = boottime_ms();
    let cancelled_request = request(vec!["/usr/bin/printf".into()], now, 5_000, 16, 16, 16);
    let token = CancellationTokenV1::default();
    token.cancel();
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(root.path()).unwrap(),
        NeverWorker,
    );
    let bytes = broker
        .execute_authenticated(&cancelled_request, now, &digest('d'), &token)
        .unwrap();
    let response: DirectEffectTerminalResponseV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response.kind,
        DirectEffectTerminalKindV1::CancelledBeforeDispatch
    );
    assert!(!response.dispatch_occurred);
    let (ledger, _) = broker.into_parts();
    assert_eq!(
        ledger.state(&cancelled_request.effect_id).unwrap().phase,
        DirectEffectPhaseV1::Terminal
    );
    drop(ledger);

    let deadline_root = private_tempdir();
    let deadline_request = request(vec!["/usr/bin/printf".into()], now, 1, 16, 16, 16);
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(deadline_root.path()).unwrap(),
        NeverWorker,
    );
    let bytes = broker
        .execute_authenticated(
            &deadline_request,
            now + 1,
            &digest('d'),
            &CancellationTokenV1::default(),
        )
        .unwrap();
    let response: DirectEffectTerminalResponseV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response.kind,
        DirectEffectTerminalKindV1::DeadlineBeforeDispatch
    );
    assert!(!response.dispatch_occurred);

    let simultaneous_root = private_tempdir();
    let simultaneous_request = request(vec!["/usr/bin/printf".into()], now, 1, 16, 16, 16);
    let simultaneous_token = CancellationTokenV1::default();
    simultaneous_token.cancel();
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(simultaneous_root.path()).unwrap(),
        NeverWorker,
    );
    let bytes = broker
        .execute_authenticated(
            &simultaneous_request,
            now + 1,
            &digest('d'),
            &simultaneous_token,
        )
        .unwrap();
    let response: DirectEffectTerminalResponseV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response.kind,
        DirectEffectTerminalKindV1::DeadlineBeforeDispatch
    );
    response
        .validate_for_request(&simultaneous_request)
        .unwrap();
}

#[test]
fn cancellation_is_resampled_after_preflight_and_never_dispatches() {
    let root = private_tempdir();
    let now = boottime_ms();
    let request = request(vec!["/usr/bin/printf".into()], now, 5_000, 16, 16, 16);
    let cancellation = Arc::new(CancellationTokenV1::default());
    let worker = CancellingPreflightWorker {
        cancellation: Arc::clone(&cancellation),
        execute_calls: 0,
    };
    let mut broker =
        ShellExecBrokerCoreV1::new(DurableShellExecLedgerV1::open(root.path()).unwrap(), worker);
    let bytes = broker
        .execute_authenticated(&request, now, &digest('d'), &cancellation)
        .unwrap();
    let response: DirectEffectTerminalResponseV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response.kind,
        DirectEffectTerminalKindV1::CancelledBeforeDispatch
    );
    assert!(!response.dispatch_occurred);
    let (ledger, worker) = broker.into_parts();
    assert_eq!(worker.execute_calls, 0);
    assert_eq!(
        ledger.state(&request.effect_id).unwrap().phase,
        DirectEffectPhaseV1::Terminal
    );
}

#[test]
fn deadline_and_dispatch_timestamp_are_resampled_after_slow_preflight() {
    let deadline_root = private_tempdir();
    let now = boottime_ms();
    let deadline_request = request(vec!["/usr/bin/printf".into()], now, 40, 16, 16, 16);
    let worker = DelayedPreflightWorker {
        delay: Duration::from_millis(75),
        preflight_completed_boottime_ms: None,
        dispatch_started_boottime_ms: None,
    };
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(deadline_root.path()).unwrap(),
        worker,
    );
    let bytes = broker
        .execute_authenticated(
            &deadline_request,
            now,
            &digest('d'),
            &CancellationTokenV1::default(),
        )
        .unwrap();
    let response: DirectEffectTerminalResponseV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response.kind,
        DirectEffectTerminalKindV1::DeadlineBeforeDispatch
    );
    let (_, worker) = broker.into_parts();
    assert!(worker.preflight_completed_boottime_ms.unwrap() >= now + 40);
    assert_eq!(worker.dispatch_started_boottime_ms, None);

    let dispatch_root = private_tempdir();
    let now = boottime_ms();
    let dispatch_request = request(vec!["/usr/bin/printf".into()], now, 5_000, 16, 16, 16);
    let worker = DelayedPreflightWorker {
        delay: Duration::from_millis(20),
        preflight_completed_boottime_ms: None,
        dispatch_started_boottime_ms: None,
    };
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(dispatch_root.path()).unwrap(),
        worker,
    );
    broker
        .execute_authenticated(
            &dispatch_request,
            now,
            &digest('d'),
            &CancellationTokenV1::default(),
        )
        .unwrap();
    let (ledger, worker) = broker.into_parts();
    let completed = worker.preflight_completed_boottime_ms.unwrap();
    let dispatched = worker.dispatch_started_boottime_ms.unwrap();
    assert!(dispatched >= completed);
    assert_eq!(
        ledger
            .state(&dispatch_request.effect_id)
            .unwrap()
            .dispatch_started_boottime_ms,
        Some(dispatched)
    );
}

#[test]
fn valid_but_policy_denied_request_is_a_durable_not_dispatched_terminal() {
    let root = private_tempdir();
    let now = boottime_ms();
    let request = request(
        vec!["/usr/bin/printf".into()],
        now,
        5_000,
        SHELL_EXEC_MAX_RAW_OUTPUT_BYTES + 1,
        16,
        SHELL_EXEC_MAX_RAW_OUTPUT_BYTES + 1,
    );
    request.validate().unwrap();
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(root.path()).unwrap(),
        NeverWorker,
    );
    let first = broker
        .execute_authenticated(&request, now, &digest('d'), &CancellationTokenV1::default())
        .unwrap();
    let response: DirectEffectTerminalResponseV1 = serde_json::from_slice(&first).unwrap();
    assert_eq!(
        response.kind,
        DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch
    );
    assert_eq!(
        response.backend_error_code.as_deref(),
        Some("mcp_binary_output_budget_exceeded")
    );
    assert!(!response.dispatch_occurred);

    let replay = broker
        .execute_authenticated(
            &request,
            now + 1,
            &digest('d'),
            &CancellationTokenV1::default(),
        )
        .unwrap();
    assert_eq!(replay, first);
    let (ledger, _) = broker.into_parts();
    let state = ledger.state(&request.effect_id).unwrap();
    assert_eq!(state.phase, DirectEffectPhaseV1::Terminal);
    assert!(!state.dispatch_occurred);
}

#[test]
fn preflight_policy_is_durable_but_custody_failure_is_fatal() {
    let now = boottime_ms();
    let policy_root = private_tempdir();
    let policy_request = request(vec!["/not/allowlisted".into()], now, 5_000, 16, 16, 16);
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(policy_root.path()).unwrap(),
        FailingPreflightWorker(WorkerPreflightErrorV1::PolicyRejected(
            "executable_not_allowlisted",
        )),
    );
    let bytes = broker
        .execute_authenticated(
            &policy_request,
            now,
            &digest('d'),
            &CancellationTokenV1::default(),
        )
        .unwrap();
    let response: DirectEffectTerminalResponseV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        response.kind,
        DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch
    );
    assert_eq!(
        response.backend_error_code.as_deref(),
        Some("executable_not_allowlisted")
    );

    let fatal_root = private_tempdir();
    let fatal_request = request(vec!["/usr/bin/printf".into()], now, 5_000, 16, 16, 16);
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(fatal_root.path()).unwrap(),
        FailingPreflightWorker(WorkerPreflightErrorV1::RuntimeFatal(
            "allowlisted_executable_custody_drift".to_string(),
        )),
    );
    assert!(matches!(
        broker.execute_authenticated(
            &fatal_request,
            now,
            &digest('d'),
            &CancellationTokenV1::default(),
        ),
        Err(ShellExecError::RuntimeFatal(detail))
            if detail == "allowlisted_executable_custody_drift"
    ));
    let (ledger, _) = broker.into_parts();
    assert_eq!(
        ledger.state(&fatal_request.effect_id).unwrap().phase,
        DirectEffectPhaseV1::NotDispatched
    );
}

#[test]
fn restart_after_dispatched_never_calls_worker_or_automatically_retries() {
    let root = private_tempdir();
    let now = boottime_ms();
    let request = request(vec!["/usr/bin/printf".into()], now, 5_000, 16, 16, 16);
    let mut ledger = DurableShellExecLedgerV1::open(root.path()).unwrap();
    assert_eq!(
        ledger.prepare_or_recover(&request).unwrap(),
        LedgerRecoveryV1::FreshNotDispatched
    );
    ledger.mark_dispatched(&request, now, &digest('d')).unwrap();
    drop(ledger);

    let mut broker = ShellExecBrokerCoreV1::new(reopen_ledger_after_drop(root.path()), NeverWorker);
    assert!(matches!(
        broker.execute_authenticated(
            &request,
            now + 1,
            &digest('d'),
            &CancellationTokenV1::default(),
        ),
        Err(ShellExecError::Indeterminate)
    ));
    let (ledger, _) = broker.into_parts();
    assert_eq!(
        ledger.state(&request.effect_id).unwrap().phase,
        DirectEffectPhaseV1::Indeterminate
    );
}

#[test]
fn startup_recovery_converts_every_dispatched_record_before_admission() {
    let root = private_tempdir();
    let now = boottime_ms();
    let request = request(vec!["/usr/bin/printf".into()], now, 5_000, 16, 16, 16);
    let mut ledger = DurableShellExecLedgerV1::open(root.path()).unwrap();
    ledger.prepare_or_recover(&request).unwrap();
    ledger.mark_dispatched(&request, now, &digest('d')).unwrap();
    drop(ledger);

    let mut reopened = reopen_ledger_after_drop(root.path());
    reopened
        .recover_all_dispatched_after_restart(now + 1)
        .unwrap();
    let state = reopened.state(&request.effect_id).unwrap();
    assert_eq!(state.phase, DirectEffectPhaseV1::Indeterminate);
    assert_eq!(
        state.indeterminate_reason,
        Some(
            trillionnium_os_types::direct_effect::DirectEffectIndeterminateReasonV1::BrokerRestartAfterDispatch
        )
    );
}

#[test]
fn low_level_recovery_keeps_same_boot_not_dispatched_for_exact_authenticated_retry() {
    let root = private_tempdir();
    let request = request(vec!["/usr/bin/printf".into()], 1, 5, 16, 16, 16);
    let mut ledger = DurableShellExecLedgerV1::open(root.path()).unwrap();
    ledger.prepare_or_recover(&request).unwrap();
    ledger
        .terminalize_old_boot_not_dispatched(
            &trillionnium_shell_exec::current_boot_id_sha256().unwrap(),
            request.absolute_deadline_boottime_ms + 10,
        )
        .unwrap();
    assert_eq!(
        ledger.state(&request.effect_id).unwrap().phase,
        DirectEffectPhaseV1::NotDispatched
    );
    assert_eq!(
        ledger.prepare_or_recover(&request).unwrap(),
        LedgerRecoveryV1::AwaitSameAuthenticatedRetry
    );
}

#[test]
fn product_restart_terminalizes_same_and_old_boot_not_dispatched_before_receipt_repair() {
    let current_boot = trillionnium_shell_exec::current_boot_id_sha256().unwrap();
    for request_boot in [current_boot.clone(), digest('7')] {
        let outer = private_tempdir();
        let ledger_root = outer.path().join("ledger");
        let receipt_root = outer.path().join("receipts");
        fs::create_dir(&ledger_root).unwrap();
        fs::create_dir(&receipt_root).unwrap();
        fs::set_permissions(&ledger_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&receipt_root, fs::Permissions::from_mode(0o700)).unwrap();
        let request = request_with_boot_id(
            vec!["/usr/bin/printf".into()],
            1,
            5,
            16,
            16,
            16,
            request_boot,
        );

        let mut ledger = DurableShellExecLedgerV1::open(&ledger_root).unwrap();
        ledger.prepare_or_recover(&request).unwrap();
        let observed = request.absolute_deadline_boottime_ms + 10;
        ledger
            .terminalize_all_not_dispatched_after_product_restart(observed)
            .unwrap();
        let committed = ledger.record(&request.effect_id).unwrap().unwrap();
        let response: DirectEffectTerminalResponseV1 =
            serde_json::from_slice(committed.terminal_response.as_ref().unwrap()).unwrap();
        assert_eq!(
            response.kind,
            DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch
        );
        assert_eq!(
            response.backend_error_code.as_deref(),
            Some(BROKER_RESTART_BEFORE_DISPATCH_ERROR_CODE)
        );

        ledger
            .terminalize_all_not_dispatched_after_product_restart(observed + 1)
            .unwrap();
        assert_eq!(
            ledger.record(&request.effect_id).unwrap().unwrap(),
            committed
        );
        drop(ledger);

        let mut reopened = reopen_ledger_after_drop(&ledger_root);
        reopened
            .terminalize_all_not_dispatched_after_product_restart(observed + 2)
            .unwrap();
        let replayed = reopened.record(&request.effect_id).unwrap().unwrap();
        assert_eq!(replayed, committed);
        let receipts = DurableShellExecReceiptStoreV1::open(&receipt_root).unwrap();
        receipts.ensure(&replayed).unwrap();
        receipts
            .verify_catalog(&reopened.records().unwrap())
            .unwrap();
    }
}

#[test]
fn old_boot_not_dispatched_is_restart_terminal_for_both_clock_orderings_and_repairs_receipt() {
    let current_boot = trillionnium_shell_exec::current_boot_id_sha256().unwrap();
    for (request_boottime, timeout_ms, observed_boottime) in [(10_000, 5_000, 1), (1, 5, 10_000)] {
        let outer = private_tempdir();
        let ledger_root = outer.path().join("ledger");
        let receipt_root = outer.path().join("receipts");
        fs::create_dir(&ledger_root).unwrap();
        fs::create_dir(&receipt_root).unwrap();
        fs::set_permissions(&ledger_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&receipt_root, fs::Permissions::from_mode(0o700)).unwrap();
        let request = request_with_boot_id(
            vec!["/usr/bin/printf".into()],
            request_boottime,
            timeout_ms,
            16,
            16,
            16,
            digest('7'),
        );
        assert_ne!(request.boot_id_sha256, current_boot);

        let mut ledger = DurableShellExecLedgerV1::open(&ledger_root).unwrap();
        ledger.prepare_or_recover(&request).unwrap();
        ledger
            .terminalize_old_boot_not_dispatched(&current_boot, observed_boottime)
            .unwrap();
        let committed = ledger.record(&request.effect_id).unwrap().unwrap();
        let terminal = committed.terminal_response.as_ref().unwrap();
        let response: DirectEffectTerminalResponseV1 = serde_json::from_slice(terminal).unwrap();
        assert_eq!(
            response.kind,
            DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch
        );
        assert_eq!(
            response.backend_error_code.as_deref(),
            Some(BROKER_RESTART_BEFORE_DISPATCH_ERROR_CODE)
        );
        assert_eq!(response.started_boottime_ms, observed_boottime);

        // Repeating startup is a no-op and preserves the exact committed
        // terminal bytes. A missing immutable receipt is then repaired from
        // that ledger record, exactly as product startup does before READY.
        ledger
            .terminalize_old_boot_not_dispatched(&current_boot, observed_boottime + 1)
            .unwrap();
        assert_eq!(
            ledger.record(&request.effect_id).unwrap().unwrap(),
            committed
        );
        drop(ledger);

        let mut reopened = reopen_ledger_after_drop(&ledger_root);
        reopened
            .terminalize_old_boot_not_dispatched(&current_boot, observed_boottime + 2)
            .unwrap();
        let replayed = reopened.record(&request.effect_id).unwrap().unwrap();
        assert_eq!(replayed, committed);
        let receipts = DurableShellExecReceiptStoreV1::open(&receipt_root).unwrap();
        let first_receipt = receipts.ensure(&replayed).unwrap();
        assert_eq!(receipts.ensure(&replayed).unwrap(), first_receipt);
        receipts
            .verify_catalog(&reopened.records().unwrap())
            .unwrap();
    }
}

#[test]
fn reboot_epoch_terminalizes_old_not_dispatched_and_recovers_dispatched() {
    let root = private_tempdir();
    let now = boottime_ms();
    let old_boot_request = request_with_boot_id(
        vec!["/usr/bin/printf".into()],
        now,
        5_000,
        16,
        16,
        16,
        digest('7'),
    );
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(root.path()).unwrap(),
        NeverWorker,
    );
    let old_boot_terminal = broker
        .execute_authenticated(
            &old_boot_request,
            1,
            &digest('d'),
            &CancellationTokenV1::default(),
        )
        .unwrap();
    let old_boot_response: DirectEffectTerminalResponseV1 =
        serde_json::from_slice(&old_boot_terminal).unwrap();
    assert_eq!(
        old_boot_response.kind,
        DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch
    );
    assert_eq!(
        old_boot_response.backend_error_code.as_deref(),
        Some("broker_restart_before_dispatch")
    );
    let (ledger, _) = broker.into_parts();
    assert_eq!(
        ledger.state(&old_boot_request.effect_id).unwrap().phase,
        DirectEffectPhaseV1::Terminal
    );
    drop(ledger);

    let dispatched_root = private_tempdir();
    let dispatched = request(vec!["/usr/bin/printf".into()], now, 5_000, 16, 16, 16);
    let mut ledger = DurableShellExecLedgerV1::open(dispatched_root.path()).unwrap();
    ledger.prepare_or_recover(&dispatched).unwrap();
    ledger
        .mark_dispatched(&dispatched, now, &digest('d'))
        .unwrap();
    drop(ledger);
    let mut broker = ShellExecBrokerCoreV1::new(
        reopen_ledger_after_drop(dispatched_root.path()),
        NeverWorker,
    );
    assert!(matches!(
        broker.execute_authenticated(
            &dispatched,
            1,
            &digest('d'),
            &CancellationTokenV1::default(),
        ),
        Err(ShellExecError::Indeterminate)
    ));
    let (ledger, _) = broker.into_parts();
    let state = ledger.state(&dispatched.effect_id).unwrap();
    assert_eq!(state.phase, DirectEffectPhaseV1::Indeterminate);
    assert!(
        state.indeterminate_observed_boottime_ms.unwrap()
            >= state.dispatch_started_boottime_ms.unwrap()
    );
}

#[test]
fn stable_identity_finds_old_request_before_new_boot_materialization() {
    let root = private_tempdir();
    let now = boottime_ms();
    let old = request_with_boot_id(
        vec!["/usr/bin/printf".into()],
        now,
        5_000,
        16,
        16,
        16,
        digest('7'),
    );
    let new_boot = request_with_boot_id(
        vec!["/usr/bin/printf".into()],
        now,
        5_000,
        16,
        16,
        16,
        digest('a'),
    );
    assert_eq!(old.effect_id, new_boot.effect_id);
    assert_ne!(old.request_sha256, new_boot.request_sha256);
    let semantic_arguments_sha256 = old.arguments.canonical_sha256().unwrap();
    let mut ledger = DurableShellExecLedgerV1::open(root.path()).unwrap();
    ledger.prepare_or_recover(&old).unwrap();
    assert_eq!(
        ledger
            .recover_stable_request(
                &old.direct_binding_sha256,
                old.adapter_effect_ordinal,
                &semantic_arguments_sha256,
            )
            .unwrap(),
        StableLedgerRecoveryV1::NotDispatched(old.clone())
    );
    assert!(ledger.prepare_or_recover(&new_boot).is_err());
}

#[test]
fn worker_internal_error_is_publicly_indeterminate_and_never_retryable() {
    let root = private_tempdir();
    let now = boottime_ms();
    let request = request(vec!["/usr/bin/printf".into()], now, 5_000, 16, 16, 16);
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(root.path()).unwrap(),
        ErrorWorker,
    );
    assert!(matches!(
        broker.execute_authenticated(&request, now, &digest('d'), &CancellationTokenV1::default(),),
        Err(ShellExecError::Indeterminate)
    ));
    let (ledger, _) = broker.into_parts();
    assert_eq!(
        ledger.state(&request.effect_id).unwrap().phase,
        DirectEffectPhaseV1::Indeterminate
    );
    drop(ledger);

    let mut reopened =
        ShellExecBrokerCoreV1::new(reopen_ledger_after_drop(root.path()), NeverWorker);
    assert!(matches!(
        reopened.execute_authenticated(
            &request,
            now + 1,
            &digest('d'),
            &CancellationTokenV1::default(),
        ),
        Err(ShellExecError::Indeterminate)
    ));
}

#[test]
fn cancellation_and_deadline_are_resampled_after_durable_dispatch_before_worker() {
    let now = boottime_ms();
    let cancelled_root = private_tempdir();
    let cancelled_request = request(vec!["/usr/bin/printf".into()], now, 5_000, 16, 16, 16);
    let cancellation = CancellationTokenV1::default();
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(cancelled_root.path()).unwrap(),
        NeverWorker,
    );
    assert!(matches!(
        broker.execute_authenticated_with_post_dispatch_observer(
            &cancelled_request,
            now,
            &digest('d'),
            &cancellation,
            || {
                cancellation.cancel();
                now + 1
            },
        ),
        Err(ShellExecError::Indeterminate)
    ));
    let (ledger, _) = broker.into_parts();
    let state = ledger.state(&cancelled_request.effect_id).unwrap();
    assert_eq!(state.phase, DirectEffectPhaseV1::Indeterminate);
    assert_eq!(
        state.indeterminate_reason,
        Some(
            trillionnium_os_types::direct_effect::DirectEffectIndeterminateReasonV1::CancelledAfterDispatch
        )
    );

    let deadline_root = private_tempdir();
    let deadline_request = request(vec!["/usr/bin/printf".into()], now, 5_000, 16, 16, 16);
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(deadline_root.path()).unwrap(),
        NeverWorker,
    );
    assert!(matches!(
        broker.execute_authenticated_with_post_dispatch_observer(
            &deadline_request,
            now,
            &digest('d'),
            &CancellationTokenV1::default(),
            || deadline_request.absolute_deadline_boottime_ms,
        ),
        Err(ShellExecError::Indeterminate)
    ));
    let (ledger, _) = broker.into_parts();
    assert_eq!(
        ledger
            .state(&deadline_request.effect_id)
            .unwrap()
            .indeterminate_reason,
        Some(
            trillionnium_os_types::direct_effect::DirectEffectIndeterminateReasonV1::DeadlineAfterDispatch
        )
    );
}

#[test]
fn ledger_root_path_swap_fails_before_worker_contact_and_never_publishes_to_replacement() {
    let outer = private_tempdir();
    let root = outer.path().join("ledger");
    let moved = outer.path().join("ledger-moved");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let now = boottime_ms();
    let request = request(vec!["/usr/bin/printf".into()], now, 5_000, 16, 16, 16);
    let mut ledger = DurableShellExecLedgerV1::open(&root).unwrap();
    assert_eq!(
        ledger.prepare_or_recover(&request).unwrap(),
        LedgerRecoveryV1::FreshNotDispatched
    );
    fs::rename(&root, &moved).unwrap();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

    let mut broker = ShellExecBrokerCoreV1::new(ledger, NeverWorker);
    assert!(matches!(
        broker.execute_authenticated(
            &request,
            now + 1,
            &digest('d'),
            &CancellationTokenV1::default(),
        ),
        Err(ShellExecError::Durable(_))
    ));
    assert!(!root.join("shell-exec-ledger.v1.json").exists());
    let retained: Value =
        serde_json::from_slice(&fs::read(moved.join("shell-exec-ledger.v1.json")).unwrap())
            .unwrap();
    assert_eq!(
        retained["body"]["records"][&request.effect_id]["state"]["phase"],
        "not_dispatched"
    );
}

fn mcp_result_bytes(response_bytes: &[u8]) -> Vec<u8> {
    let structured: Value = serde_json::from_slice(response_bytes).unwrap();
    let binding = json!({
        "schema": "org.trillionnium.mcp.structured-content-binding.v1",
        "structured_content_sha256": trillionnium_os_types::sha256_bytes(response_bytes),
        "structured_content_bytes": response_bytes.len(),
    });
    serde_json::to_vec(&json!({
        "content": [{"type": "text", "text": serde_json::to_string(&binding).unwrap()}],
        "structuredContent": structured,
        "isError": false,
    }))
    .unwrap()
}

#[test]
fn mcp_binary_budget_accepts_max_rejects_plus_one_and_handles_split_non_utf8() {
    let now = boottime_ms();
    let max = SHELL_EXEC_MAX_RAW_OUTPUT_BYTES;
    let max_request = request(vec!["/usr/bin/printf".into()], now, 5_000, max, max, max);
    validate_first_slice_request(&max_request).unwrap();
    let packet_bytes =
        maximum_terminal_transport_packet_bytes(&max_request, now, &digest('d')).unwrap();
    assert!(
        packet_bytes <= TRANSPORT_RESPONSE_PACKET_BYTES_CAP,
        "worst terminal transport packet was {packet_bytes} bytes"
    );
    for (stdout_len, stderr_len) in [
        (max as usize, 0),
        (0, max as usize),
        (max as usize / 2 - 1, max as usize / 2 + 1),
    ] {
        let response = terminal_response(
            &max_request,
            now,
            &vec![0xff; stdout_len],
            &vec![0x00; stderr_len],
        );
        let response_bytes = response.canonical_bytes(&max_request).unwrap();
        let mcp = mcp_result_bytes(&response_bytes);
        assert!(
            mcp.len() <= MCP_CALL_TOOL_RESULT_BYTES_CAP,
            "CallToolResult was {} bytes for stdout={stdout_len}, stderr={stderr_len}",
            mcp.len()
        );
        assert_eq!(response.stdout.validate().unwrap().len(), stdout_len);
        assert_eq!(response.stderr.validate().unwrap().len(), stderr_len);
    }

    let plus_one = request(
        vec!["/usr/bin/printf".into()],
        now,
        5_000,
        max + 1,
        max + 1,
        max + 1,
    );
    assert!(matches!(
        validate_first_slice_request(&plus_one),
        Err(ShellExecError::RequestDenied(
            "mcp_binary_output_budget_exceeded"
        ))
    ));
}

#[test]
fn durable_registration_reservation_bounds_worst_first_slice_records() {
    let root = private_tempdir();
    let mut ledger = DurableShellExecLedgerV1::open(root.path()).unwrap();
    ledger
        .admit_additional_record_capacity(MAX_DURABLE_EFFECT_RECORDS)
        .unwrap();
    assert!(
        ledger
            .admit_additional_record_capacity(MAX_DURABLE_EFFECT_RECORDS + 1)
            .is_err()
    );

    let now = boottime_ms();
    let argv0 = "/usr/bin/printf".to_string();
    let remaining = 64 * 1024 - argv0.len();
    let mut argv = vec![argv0];
    for _ in 0..3 {
        argv.push("\u{1}".repeat(16 * 1024));
    }
    argv.push("\u{1}".repeat(remaining - 3 * 16 * 1024));
    let request = request(
        argv,
        now,
        60_000,
        SHELL_EXEC_MAX_RAW_OUTPUT_BYTES,
        SHELL_EXEC_MAX_RAW_OUTPUT_BYTES,
        SHELL_EXEC_MAX_RAW_OUTPUT_BYTES,
    );
    validate_first_slice_request(&request).unwrap();
    ledger.prepare_or_recover(&request).unwrap();
    let required = ledger
        .admit_worst_case_terminal(
            &request,
            request.absolute_deadline_boottime_ms - 1,
            &digest('d'),
        )
        .unwrap();
    let started = request.absolute_deadline_boottime_ms - 1;
    ledger
        .mark_dispatched(&request, started, &digest('d'))
        .unwrap();
    ledger
        .finish_terminal(
            &request,
            terminal_response(
                &request,
                started,
                &vec![0x01; SHELL_EXEC_MAX_RAW_OUTPUT_BYTES as usize],
                b"",
            ),
        )
        .unwrap();
    let receipt_root = private_tempdir();
    let receipt_store = DurableShellExecReceiptStoreV1::open(receipt_root.path()).unwrap();
    let receipt = receipt_store
        .ensure(&ledger.record(&request.effect_id).unwrap().unwrap())
        .unwrap();
    assert!(required <= MAX_DURABLE_LEDGER_RECORD_BYTES);
    assert!(receipt.len() as u64 <= MAX_DURABLE_RECEIPT_RECORD_BYTES);
    assert!(
        required + receipt.len() as u64 <= MAX_DURABLE_RECORD_RESERVATION_BYTES,
        "worst ledger snapshot {required} + receipt {} exceeded reservation",
        receipt.len()
    );
}

#[test]
fn durable_history_boundary_accepts_twenty_nine_plus_one_and_rejects_thirty() {
    let now = boottime_ms();
    for (history, expected_acceptance) in [(29_u64, true), (30_u64, false)] {
        let outer = private_tempdir();
        let ledger_root = outer.path().join("ledger");
        let receipt_root = outer.path().join("receipts");
        fs::create_dir(&ledger_root).unwrap();
        fs::create_dir(&receipt_root).unwrap();
        fs::set_permissions(&ledger_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&receipt_root, fs::Permissions::from_mode(0o700)).unwrap();
        let first = request_with_ordinal(now, 1);
        let mut ledger = DurableShellExecLedgerV1::open(&ledger_root).unwrap();
        let receipts = DurableShellExecReceiptStoreV1::open(&receipt_root).unwrap();
        for ordinal in 1..=history {
            let request = request_with_ordinal(now, ordinal);
            ledger.prepare_or_recover(&request).unwrap();
            ledger
                .finish_not_dispatched_policy(
                    &request,
                    "history_retired_before_capacity_boundary",
                    now + ordinal,
                )
                .unwrap();
            receipts
                .ensure(&ledger.record(&request.effect_id).unwrap().unwrap())
                .unwrap();
        }
        assert_eq!(ledger.records().unwrap().len(), history as usize);
        assert_eq!(
            ledger.admit_additional_record_capacity(1).is_ok(),
            expected_acceptance
        );
        receipts.verify_catalog(&ledger.records().unwrap()).unwrap();
        drop(receipts);
        drop(ledger);

        let mut reopened = reopen_ledger_after_drop(&ledger_root);
        assert_eq!(reopened.records().unwrap().len(), history as usize);
        assert_eq!(
            reopened.admit_additional_record_capacity(1).is_ok(),
            expected_acceptance
        );
        assert!(matches!(
            reopened.prepare_or_recover(&first).unwrap(),
            LedgerRecoveryV1::ReplayExactTerminal(_)
        ));
        if expected_acceptance {
            let receipts = DurableShellExecReceiptStoreV1::open(&receipt_root).unwrap();
            for ordinal in history + 1..=MAX_DURABLE_EFFECT_RECORDS {
                let request = request_with_ordinal(now, ordinal);
                reopened.prepare_or_recover(&request).unwrap();
                reopened
                    .finish_not_dispatched_policy(
                        &request,
                        "fresh_effect_after_capacity_reservation",
                        now + ordinal,
                    )
                    .unwrap();
                receipts
                    .ensure(&reopened.record(&request.effect_id).unwrap().unwrap())
                    .unwrap();
            }
            assert_eq!(
                reopened.records().unwrap().len(),
                MAX_DURABLE_EFFECT_RECORDS as usize
            );
            assert!(reopened.admit_additional_record_capacity(1).is_err());
            receipts
                .verify_catalog(&reopened.records().unwrap())
                .unwrap();
            drop(receipts);
            drop(reopened);
            let after_reboot = reopen_ledger_after_drop(&ledger_root);
            assert_eq!(
                after_reboot.records().unwrap().len(),
                MAX_DURABLE_EFFECT_RECORDS as usize
            );
            assert!(after_reboot.admit_additional_record_capacity(1).is_err());
        }
    }
}

#[test]
fn host_worker_preserves_exact_argv_and_never_invokes_a_shell() {
    if !Path::new("/usr/bin/printf").is_file() {
        return;
    }
    let root = private_tempdir();
    let workspace = root.path().join("workspace");
    let temporary = root.path().join("temporary");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&temporary).unwrap();
    let marker = root.path().join("must-not-exist");
    let literal = format!("$(touch {})", marker.display());
    let now = boottime_ms();
    let request = request(
        vec!["/usr/bin/printf".into(), "%s".into(), literal.clone()],
        now,
        5_000,
        4096,
        4096,
        4096,
    );
    let worker = HostConformanceWorkerV1::new(
        RootLinuxPathPolicyV1::for_host_conformance(&workspace, &temporary).unwrap(),
    );
    let mut broker =
        ShellExecBrokerCoreV1::new(DurableShellExecLedgerV1::open(root.path()).unwrap(), worker);
    let bytes = broker
        .execute_authenticated(&request, now, &digest('d'), &CancellationTokenV1::default())
        .unwrap();
    let response: DirectEffectTerminalResponseV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response.stdout.validate().unwrap(), literal.as_bytes());
    assert!(!marker.exists());
}

#[test]
fn host_worker_deadline_and_output_limit_are_indeterminate_after_dispatch() {
    let root = private_tempdir();
    let workspace = root.path().join("workspace");
    let temporary = root.path().join("temporary");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&temporary).unwrap();
    let policy = RootLinuxPathPolicyV1::for_host_conformance(&workspace, &temporary).unwrap();

    if Path::new("/bin/sleep").is_file() {
        let deadline_root = private_tempdir();
        let mut broker = ShellExecBrokerCoreV1::new(
            DurableShellExecLedgerV1::open(deadline_root.path()).unwrap(),
            HostConformanceWorkerV1::new(policy.clone()),
        );
        // Sample the deadline only after fixture construction.  Under a loaded
        // test runner, setup time must not turn this post-dispatch assertion
        // into a legitimate pre-dispatch expiry.
        let now = boottime_ms();
        let request = request(
            vec!["/bin/sleep".into(), "2".into()],
            now,
            1_000,
            1024,
            1024,
            1024,
        );
        assert!(matches!(
            broker.execute_authenticated(
                &request,
                now,
                &digest('d'),
                &CancellationTokenV1::default(),
            ),
            Err(ShellExecError::Indeterminate)
        ));
    }

    if Path::new("/usr/bin/yes").is_file() {
        let now = boottime_ms();
        let request = request(vec!["/usr/bin/yes".into()], now, 5_000, 1024, 1024, 1024);
        let output_root = private_tempdir();
        let mut broker = ShellExecBrokerCoreV1::new(
            DurableShellExecLedgerV1::open(output_root.path()).unwrap(),
            HostConformanceWorkerV1::new(policy),
        );
        assert!(matches!(
            broker.execute_authenticated(
                &request,
                now,
                &digest('d'),
                &CancellationTokenV1::default(),
            ),
            Err(ShellExecError::Indeterminate)
        ));
    }
}

#[test]
fn inherited_descendant_pipe_is_bounded_and_indeterminate() {
    let root = private_tempdir();
    let workspace = root.path().join("workspace");
    let temporary = root.path().join("temporary");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&temporary).unwrap();
    let now = boottime_ms();
    let fixture = env!("CARGO_BIN_EXE_shell-exec-host-fixture");
    // The dedicated fixture spawns one copy of itself without a shell. The
    // descendant intentionally inherits capture pipes after the requested
    // main process exits.
    let request = request(
        vec![fixture.into(), "spawn-inherited-descendant".into()],
        now,
        5_000,
        1024,
        1024,
        1024,
    );
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(root.path()).unwrap(),
        HostConformanceWorkerV1::new(
            RootLinuxPathPolicyV1::for_host_conformance(&workspace, &temporary).unwrap(),
        ),
    );
    let started = Instant::now();
    assert!(matches!(
        broker.execute_authenticated(&request, now, &digest('d'), &CancellationTokenV1::default(),),
        Err(ShellExecError::Indeterminate)
    ));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "escaped descendant kept the broker blocked for {:?}",
        started.elapsed()
    );
}

#[test]
fn inline_shell_command_modes_are_policy_denied_before_dispatch() {
    let now = boottime_ms();
    for argv in [
        vec!["/bin/sh".into(), "-c".into(), "true".into()],
        vec!["/usr/bin/bash".into(), "-lc".into(), "true".into()],
        vec![
            "/usr/bin/env".into(),
            "dash".into(),
            "-c".into(),
            "true".into(),
        ],
        vec![
            "/usr/bin/busybox".into(),
            "sh".into(),
            "-c".into(),
            "true".into(),
        ],
        vec![
            "/usr/bin/env".into(),
            "-u".into(),
            "X".into(),
            "sh".into(),
            "-c".into(),
            "true".into(),
        ],
        vec!["/usr/bin/env".into(), "-S".into(), "sh -c true".into()],
        vec![
            "/usr/bin/busybox".into(),
            "env".into(),
            "sh".into(),
            "-c".into(),
            "true".into(),
        ],
    ] {
        let request = request(argv, now, 5_000, 1024, 1024, 1024);
        assert!(matches!(
            validate_first_slice_request(&request),
            Err(ShellExecError::RequestDenied(
                "command_string_mode_not_in_v1"
            ))
        ));
    }

    for argv0 in ["/", "/usr/bin/", "/usr//bin/printf", "/usr/../bin/printf"] {
        let request = request(vec![argv0.into()], now, 5_000, 1024, 1024, 1024);
        assert!(matches!(
            validate_first_slice_request(&request),
            Err(ShellExecError::RequestDenied(
                "absolute_normalized_argv0_required"
            ))
        ));
    }
}

struct SwapRootTerminalWorker {
    root: PathBuf,
}

impl ShellExecWorkerV1 for SwapRootTerminalWorker {
    fn execute(
        &mut self,
        request: &DirectEffectRequestV1,
        dispatch_started_boottime_ms: u64,
        _cancellation: &CancellationTokenV1,
    ) -> Result<WorkerCompletionV1, String> {
        let retained = self.root.with_extension("retained-after-dispatch");
        fs::rename(&self.root, &retained).map_err(|error| error.to_string())?;
        fs::create_dir(&self.root).map_err(|error| error.to_string())?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        Ok(WorkerCompletionV1::Terminal(terminal_response(
            request,
            dispatch_started_boottime_ms,
            b"effect-happened",
            b"",
        )))
    }
}

#[test]
fn terminal_publish_failure_after_dispatch_is_a_fatal_durable_error() {
    let parent = private_tempdir();
    let root = parent.path().join("ledger");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let now = boottime_ms();
    let request = request(vec!["/usr/bin/printf".into()], now, 5_000, 64, 64, 64);
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(&root).unwrap(),
        SwapRootTerminalWorker { root: root.clone() },
    );
    assert!(matches!(
        broker.execute_authenticated(&request, now, &digest('d'), &CancellationTokenV1::default(),),
        Err(ShellExecError::Durable(_))
    ));
    assert!(!root.join("shell-exec-ledger.v1.json").exists());
}

struct DispatchSignalWorker {
    inner: HostConformanceWorkerV1,
    dispatched: mpsc::SyncSender<()>,
}

impl ShellExecWorkerV1 for DispatchSignalWorker {
    fn execute(
        &mut self,
        request: &DirectEffectRequestV1,
        dispatch_started_boottime_ms: u64,
        cancellation: &CancellationTokenV1,
    ) -> Result<WorkerCompletionV1, String> {
        self.dispatched
            .send(())
            .map_err(|_| "dispatch_test_receiver_lost".to_string())?;
        self.inner
            .execute(request, dispatch_started_boottime_ms, cancellation)
    }
}

#[test]
fn cancellation_after_dispatch_is_indeterminate() {
    if !Path::new("/bin/sleep").is_file() {
        return;
    }
    let root = private_tempdir();
    let workspace = root.path().join("workspace");
    let temporary = root.path().join("temporary");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&temporary).unwrap();
    let now = boottime_ms();
    let request = request(
        vec!["/bin/sleep".into(), "1".into()],
        now,
        5_000,
        1024,
        1024,
        1024,
    );
    let token = Arc::new(CancellationTokenV1::default());
    let signal = Arc::clone(&token);
    let (dispatched, observed) = mpsc::sync_channel(0);
    thread::spawn(move || {
        observed.recv().unwrap();
        signal.cancel();
    });
    let mut broker = ShellExecBrokerCoreV1::new(
        DurableShellExecLedgerV1::open(root.path()).unwrap(),
        DispatchSignalWorker {
            inner: HostConformanceWorkerV1::new(
                RootLinuxPathPolicyV1::for_host_conformance(&workspace, &temporary).unwrap(),
            ),
            dispatched,
        },
    );
    let result = broker.execute_authenticated(&request, now, &digest('d'), token.as_ref());
    assert!(
        matches!(result, Err(ShellExecError::Indeterminate)),
        "unexpected cancellation result: {result:?}"
    );
}
