use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use trillionnium_owner_open_call_registry::{
    CallKey, CallRegistry, CallRequest, EffectiveState, TurnScope,
};
use trillionnium_owner_open_runtime::{MechanicalLimits, ShellExecRequest, reserve_shell_capacity};
use trillionnium_owner_open_tool_bridge::{
    BoundToolCall, BridgeLimits, DirectToolBridge, DirectToolRequest, DispatchResult,
};
fn call(id: &str, canonical: &[u8]) -> BoundToolCall {
    BoundToolCall::new(
        CallKey::new(TurnScope::new("s", "p", "t", "turn", "stream"), id),
        "a".repeat(64),
        None,
        canonical.to_vec(),
        DirectToolRequest::Shell(ShellExecRequest::command(id, ":")),
    )
    .unwrap()
}
#[test]
fn budget_pressure_rejects_new_admission_but_keeps_terminal_unknown_and_conflicts() {
    let registry = Arc::new(CallRegistry::default());
    let bridge = DirectToolBridge::new(Arc::clone(&registry));
    let done = call("done", b"done-canonical");
    assert!(matches!(
        bridge
            .execute(done.clone(), &BridgeLimits::default(), |_| {})
            .unwrap(),
        DispatchResult::Executed { .. }
    ));
    let uncertain = call("unknown", b"unknown-canonical");
    registry
        .begin(
            uncertain.key.clone(),
            CallRequest::new(
                uncertain.request_sha256.clone(),
                uncertain.binding_fingerprint.clone(),
                "shell.exec",
                None,
            ),
        )
        .unwrap();
    registry
        .claim_spawn(&uncertain.key, &uncertain.request_sha256)
        .unwrap();
    registry.mark_connection_lost(&uncertain.key).unwrap();
    let before = registry.snapshot(&uncertain.key).unwrap();
    assert!(matches!(
        before.state,
        EffectiveState::UnknownAfterDisconnect { .. }
    ));
    let mut reservations = Vec::new();
    for index in 0..2 {
        let mut request = ShellExecRequest::command(format!("reserve-{index}"), ":");
        request.stdin = Vec::with_capacity(27 * 1024 * 1024);
        reservations.push(reserve_shell_capacity(&request, &MechanicalLimits::default()).unwrap());
    }
    let new = call("refused", b"new-canonical");
    let refused_key = new.key.clone();
    assert!(
        bridge
            .execute(new, &BridgeLimits::default(), |_| panic!(
                "capacity refusal must publish no event"
            ))
            .unwrap_err()
            .to_string()
            .contains("shared process/buffer capacity")
    );
    assert!(registry.snapshot(&refused_key).is_err());
    assert!(matches!(
        bridge
            .execute(done.clone(), &BridgeLimits::default(), |_| panic!(
                "duplicate event"
            ))
            .unwrap(),
        DispatchResult::Existing(_)
    ));
    assert!(matches!(
        bridge
            .execute(uncertain.clone(), &BridgeLimits::default(), |_| panic!(
                "unknown redispatch"
            ))
            .unwrap(),
        DispatchResult::Existing(_)
    ));
    assert_eq!(registry.snapshot(&uncertain.key).unwrap(), before);
    assert!(
        bridge
            .execute(
                call("done", b"conflicting-canonical"),
                &BridgeLimits::default(),
                |_| {}
            )
            .unwrap_err()
            .to_string()
            .contains("call_id")
    );
    drop(reservations);
    assert!(matches!(
        bridge
            .execute(
                call("after-release", b"released"),
                &BridgeLimits::default(),
                |_| {}
            )
            .unwrap(),
        DispatchResult::Executed { .. }
    ));
}
#[test]
fn unbounded_flag_iterator_is_rejected_before_registry_admission() {
    let registry = Arc::new(CallRegistry::default());
    let bridge = DirectToolBridge::new(Arc::clone(&registry));
    let started = std::time::Instant::now();
    let flags = std::iter::repeat_with(|| Arc::new(AtomicBool::new(false)));
    assert!(
        bridge
            .execute_fallible_with_external_flags(
                call("flags", b"flags"),
                &BridgeLimits::default(),
                flags,
                |_| Ok::<(), String>(())
            )
            .unwrap_err()
            .to_string()
            .contains("cancellation flags")
    );
    assert!(registry.is_empty().unwrap());
    assert!(started.elapsed() < Duration::from_secs(1));
}
