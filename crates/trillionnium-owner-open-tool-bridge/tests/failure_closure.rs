use std::sync::Arc;
use std::time::{Duration, Instant};

use trillionnium_owner_open_call_registry::{CallKey, CallRegistry, EffectiveState, TurnScope};
use trillionnium_owner_open_runtime::{ExecutionEventKind, ShellExecRequest};
use trillionnium_owner_open_tool_bridge::{
    BoundToolCall, BridgeError, BridgeLimits, DirectToolBridge, DirectToolRequest,
};

fn key(call_id: &str) -> CallKey {
    CallKey::new(
        TurnScope::new(
            "session-failure",
            "owner-open",
            "task-failure",
            "turn-failure",
            "stream-failure",
        ),
        call_id,
    )
}

fn shell_call(call_id: &str, command: &str) -> BoundToolCall {
    BoundToolCall::new(
        key(call_id),
        "ab".repeat(32),
        Some("rootlinux".to_string()),
        format!(r#"{{"tool":"shell.exec","command":{command:?}}}"#).into_bytes(),
        DirectToolRequest::Shell(ShellExecRequest::command(call_id, command)),
    )
    .unwrap()
}

#[test]
fn runtime_shape_is_rejected_before_registry_admission() {
    let registry = Arc::new(CallRegistry::default());
    let bridge = DirectToolBridge::new(Arc::clone(&registry));
    let call = BoundToolCall::new(
        key("call-empty-argv"),
        "ab".repeat(32),
        Some("rootlinux".to_string()),
        br#"{"tool":"shell.exec","argv":[]}"#.to_vec(),
        DirectToolRequest::Shell(ShellExecRequest::argv("call-empty-argv", Vec::new())),
    )
    .unwrap();

    let error = bridge
        .execute(call, &BridgeLimits::default(), |_| {})
        .unwrap_err();
    assert!(matches!(error, BridgeError::InvalidRequest(_)));
    assert!(registry.is_empty().unwrap());
}

#[test]
fn panicking_event_sink_cancels_process_and_closes_registry_terminal() {
    let registry = Arc::new(CallRegistry::default());
    let bridge = DirectToolBridge::new(Arc::clone(&registry));
    let call = shell_call("call-sink-panic", "sleep 30");
    let call_key = call.key.clone();
    let started = Instant::now();

    let error = bridge
        .execute(
            call,
            &BridgeLimits {
                cancellation_poll: Duration::from_millis(2),
                ..BridgeLimits::default()
            },
            |event| {
                if matches!(event.kind, ExecutionEventKind::Started { .. }) {
                    panic!("fixture sink panic");
                }
            },
        )
        .unwrap_err();

    assert!(matches!(error, BridgeError::EventSinkPanicked));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(matches!(
        registry.snapshot(&call_key).unwrap().state,
        EffectiveState::Terminal { .. }
    ));
}

#[test]
fn fallible_event_sink_error_is_reported_after_terminal_closure() {
    let registry = Arc::new(CallRegistry::default());
    let bridge = DirectToolBridge::new(Arc::clone(&registry));
    let call = shell_call("call-sink-error", "sleep 30");
    let call_key = call.key.clone();

    let error = bridge
        .execute_fallible(
            call,
            &BridgeLimits {
                cancellation_poll: Duration::from_millis(2),
                ..BridgeLimits::default()
            },
            |event| {
                if matches!(event.kind, ExecutionEventKind::Started { .. }) {
                    Err("fixture event sink unavailable")
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();

    assert!(matches!(error, BridgeError::EventSinkFailed(_)));
    assert!(matches!(
        registry.snapshot(&call_key).unwrap().state,
        EffectiveState::Terminal { .. }
    ));
}
