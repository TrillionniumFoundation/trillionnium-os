use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use trillionnium_owner_open_call_registry::{CallKey, CallRegistry};
use trillionnium_owner_open_runtime::{ShellExecRequest, TerminalKind};
use trillionnium_owner_open_tool_bridge::{BoundToolCall, DirectToolRequest};
use trillionnium_owner_open_turn_loop::{
    ProviderEvent, ProviderHost, ProviderTerminal, ProviderTerminalStatus, SameTurnProvider,
    ToolOutcome, TurnCancellation, TurnEvent, TurnEventKind, TurnRequest, TurnRunner,
};

fn request() -> TurnRequest {
    TurnRequest {
        session_id: "session-streaming".to_string(),
        profile_id: "owner-open".to_string(),
        task_id: "task-streaming".to_string(),
        turn_id: "turn-streaming".to_string(),
        turn_stream_id: "stream-streaming".to_string(),
        user_input: "stream and cancel direct observations".to_string(),
    }
}

fn shell_call(request: &TurnRequest, call_id: &str, command: String) -> BoundToolCall {
    BoundToolCall::new(
        CallKey::new(request.scope(), call_id),
        "ab".repeat(32),
        Some("rootlinux".to_string()),
        format!("{{\"tool\":\"shell.exec\",\"command\":{command:?}}}").into_bytes(),
        DirectToolRequest::Shell(ShellExecRequest::command(call_id, command)),
    )
    .unwrap()
}

struct SinkAwareProvider {
    observed: Arc<AtomicBool>,
}

impl SameTurnProvider for SinkAwareProvider {
    fn run_turn(
        &mut self,
        _request: &TurnRequest,
        host: &mut ProviderHost<'_>,
    ) -> Result<ProviderTerminal, String> {
        host.emit(ProviderEvent::ModelDelta("stream-now".to_string()))
            .map_err(|error| error.to_string())?;
        if !self.observed.load(Ordering::SeqCst) {
            return Err("event sink did not run before ProviderHost::emit returned".to_string());
        }
        Ok(ProviderTerminal::completed("provider observed streaming delivery"))
    }
}

#[test]
fn provider_events_reach_the_sink_before_emit_returns() {
    let observed = Arc::new(AtomicBool::new(false));
    let sink_observed = Arc::clone(&observed);
    let mut sink = move |event: &TurnEvent| -> Result<(), String> {
        if matches!(
            &event.kind,
            TurnEventKind::Provider(ProviderEvent::ModelDelta(text)) if text == "stream-now"
        ) {
            sink_observed.store(true, Ordering::SeqCst);
        }
        Ok(())
    };
    let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
    let mut provider = SinkAwareProvider { observed };
    let run = runner
        .run_with_sink(request(), &mut provider, &mut sink)
        .unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Completed);
}

struct WaitsForStartedSink {
    marker: std::path::PathBuf,
}

impl SameTurnProvider for WaitsForStartedSink {
    fn run_turn(
        &mut self,
        request: &TurnRequest,
        host: &mut ProviderHost<'_>,
    ) -> Result<ProviderTerminal, String> {
        let command = format!(
            "i=0; while [ ! -f '{}' ]; do i=$((i + 1)); [ $i -lt 300 ] || exit 88; sleep 0.01; done; printf streamed",
            self.marker.display()
        );
        match host
            .invoke_tool(shell_call(request, "call-streaming-tool", command))
            .map_err(|error| error.to_string())?
        {
            ToolOutcome::Executed { terminal, .. } if terminal.success() => {
                Ok(ProviderTerminal::completed("runtime event sink was live"))
            }
            ToolOutcome::Executed { terminal, .. } => Err(format!(
                "streaming fixture terminal was not successful: {:?}",
                terminal.kind
            )),
            _ => Err("streaming fixture call was not executed".to_string()),
        }
    }
}

#[test]
fn runtime_started_event_reaches_the_sink_before_the_process_finishes() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("started-observed");
    let sink_marker = marker.clone();
    let mut sink = move |event: &TurnEvent| -> Result<(), String> {
        if matches!(
            &event.kind,
            TurnEventKind::ToolRuntime(runtime)
                if matches!(
                    &runtime.kind,
                    trillionnium_owner_open_runtime::ExecutionEventKind::Started { .. }
                )
        ) {
            fs::write(&sink_marker, b"started").map_err(|error| error.to_string())?;
        }
        Ok(())
    };
    let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
    let mut provider = WaitsForStartedSink { marker };
    let run = runner
        .run_with_sink(request(), &mut provider, &mut sink)
        .unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Completed);
}

struct LongRunningTool;

impl SameTurnProvider for LongRunningTool {
    fn run_turn(
        &mut self,
        request: &TurnRequest,
        host: &mut ProviderHost<'_>,
    ) -> Result<ProviderTerminal, String> {
        match host
            .invoke_tool(shell_call(
                request,
                "call-turn-cancel",
                "sleep 30".to_string(),
            ))
            .map_err(|error| error.to_string())?
        {
            ToolOutcome::Executed { terminal, .. }
                if terminal.kind == TerminalKind::Cancelled =>
            {
                Ok(ProviderTerminal::cancelled(
                    "turn cancellation reached the active process group",
                ))
            }
            ToolOutcome::Executed { terminal, .. } => Err(format!(
                "expected a cancelled runtime terminal, got {:?}",
                terminal.kind
            )),
            _ => Err("long-running tool call was not executed".to_string()),
        }
    }
}

#[test]
fn turn_cancellation_reaches_an_active_tool_process_group() {
    let directory = tempfile::tempdir().unwrap();
    let started = directory.path().join("tool-started");
    let sink_started = started.clone();
    let cancellation = TurnCancellation::new();
    let worker_cancellation = cancellation.clone();
    let worker = thread::spawn(move || {
        let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
        let mut provider = LongRunningTool;
        let mut sink = move |event: &TurnEvent| -> Result<(), String> {
            if matches!(
                &event.kind,
                TurnEventKind::ToolRuntime(runtime)
                    if matches!(
                        &runtime.kind,
                        trillionnium_owner_open_runtime::ExecutionEventKind::Started { .. }
                    )
            ) {
                fs::write(&sink_started, b"started").map_err(|error| error.to_string())?;
            }
            Ok(())
        };
        runner.run_with_sink_and_cancellation(
            request(),
            &mut provider,
            &worker_cancellation,
            &mut sink,
        )
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    while !started.exists() {
        assert!(Instant::now() < deadline, "tool never reached the started state");
        thread::sleep(Duration::from_millis(5));
    }
    assert!(cancellation.cancel());

    let run = worker.join().unwrap().unwrap();
    assert_eq!(run.terminal.status, ProviderTerminalStatus::Cancelled);
    assert!(run.events.iter().any(|event| {
        matches!(
            &event.kind,
            TurnEventKind::ToolRuntime(runtime)
                if matches!(
                    &runtime.kind,
                    trillionnium_owner_open_runtime::ExecutionEventKind::Terminal(terminal)
                        if terminal.kind == TerminalKind::Cancelled
                )
        )
    }));
}
