use std::sync::{Arc, Barrier};
use std::thread;

use trillionnium_owner_open_call_registry::{
    BeginDisposition, CallKey, CallRegistry, CallRequest, EffectiveState, MutationOutcome,
    RegistryError, RegistryLimits, SpawnClaim, TerminalRecord, TurnScope,
};

fn scope(seed: usize) -> TurnScope {
    TurnScope::new(
        format!("session-{seed}"),
        "owner-open",
        format!("task-{seed}"),
        format!("turn-{seed}"),
        format!("stream-{seed}"),
    )
}

fn key(scope_seed: usize, call_id: &str) -> CallKey {
    CallKey::new(scope(scope_seed), call_id)
}

fn request(seed: u8) -> CallRequest {
    CallRequest::new(
        format!("{seed:02x}").repeat(32),
        "ab".repeat(32),
        "shell.exec",
        Some("rootlinux".to_string()),
    )
}

fn terminal(seed: u8) -> TerminalRecord {
    TerminalRecord::new(
        "exited",
        Some(i32::from(seed)),
        None,
        format!("{seed:02x}").repeat(32),
        u64::from(seed),
        0,
    )
}

#[test]
fn concurrent_exact_begin_has_one_new_and_the_rest_attach() {
    const THREADS: usize = 32;
    let registry = Arc::new(CallRegistry::default());
    let barrier = Arc::new(Barrier::new(THREADS));
    let call = key(1, "call-concurrent-begin");
    let request = request(1);

    let workers = (0..THREADS)
        .map(|_| {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            let call = call.clone();
            let request = request.clone();
            thread::spawn(move || {
                barrier.wait();
                registry.begin(call, request).unwrap().disposition
            })
        })
        .collect::<Vec<_>>();

    let dispositions = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        dispositions
            .iter()
            .filter(|value| **value == BeginDisposition::New)
            .count(),
        1
    );
    assert_eq!(
        dispositions
            .iter()
            .filter(|value| **value == BeginDisposition::Existing)
            .count(),
        THREADS - 1
    );
    assert_eq!(registry.len().unwrap(), 1);
}

#[test]
fn concurrent_spawn_claim_grants_exactly_one_generation() {
    const THREADS: usize = 32;
    let registry = Arc::new(CallRegistry::default());
    let call = key(1, "call-concurrent-spawn");
    let request = request(2);
    registry.begin(call.clone(), request.clone()).unwrap();
    let barrier = Arc::new(Barrier::new(THREADS));

    let workers = (0..THREADS)
        .map(|_| {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            let call = call.clone();
            let digest = request.request_sha256.clone();
            thread::spawn(move || {
                barrier.wait();
                registry.claim_spawn(&call, &digest).unwrap()
            })
        })
        .collect::<Vec<_>>();

    let claims = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    let granted = claims
        .iter()
        .filter_map(|claim| match claim {
            SpawnClaim::Granted { generation, .. } => Some(*generation),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(granted.len(), 1);
    assert!(granted[0] > 0);
    assert_eq!(
        claims
            .iter()
            .filter(|claim| matches!(claim, SpawnClaim::Existing(_)))
            .count(),
        THREADS - 1
    );
    assert_eq!(
        registry.snapshot(&call).unwrap().state,
        EffectiveState::Started {
            generation: granted[0],
            pid: None,
        }
    );
}

#[test]
fn concurrent_different_request_bytes_cannot_share_one_call_id() {
    let registry = Arc::new(CallRegistry::default());
    let barrier = Arc::new(Barrier::new(2));
    let call = key(1, "call-concurrent-conflict");

    let workers = [request(3), request(4)]
        .into_iter()
        .map(|request| {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            let call = call.clone();
            thread::spawn(move || {
                barrier.wait();
                registry.begin(call, request)
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|value| value.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|value| value
                .as_ref()
                .is_err_and(|error| **error == RegistryError::CallIdConflict))
            .count(),
        1
    );
    assert_eq!(registry.len().unwrap(), 1);
}

#[test]
fn identical_call_ids_in_different_turn_scopes_are_independent() {
    let registry = CallRegistry::default();
    let first = key(1, "call-shared-label");
    let second = key(2, "call-shared-label");
    assert_eq!(
        registry
            .begin(first.clone(), request(5))
            .unwrap()
            .disposition,
        BeginDisposition::New
    );
    assert_eq!(
        registry
            .begin(second.clone(), request(6))
            .unwrap()
            .disposition,
        BeginDisposition::New
    );
    let first_generation = match registry
        .claim_spawn(&first, &request(5).request_sha256)
        .unwrap()
    {
        SpawnClaim::Granted { generation, .. } => generation,
        other => panic!("unexpected first claim: {other:?}"),
    };
    let second_generation = match registry
        .claim_spawn(&second, &request(6).request_sha256)
        .unwrap()
    {
        SpawnClaim::Granted { generation, .. } => generation,
        other => panic!("unexpected second claim: {other:?}"),
    };
    assert_ne!(first_generation, second_generation);
    assert_eq!(registry.len().unwrap(), 2);
}

#[test]
fn pid_and_terminal_updates_are_generation_bound_and_idempotent() {
    let registry = CallRegistry::default();
    let call = key(1, "call-generation-binding");
    let request = request(7);
    registry.begin(call.clone(), request.clone()).unwrap();
    let generation = match registry
        .claim_spawn(&call, &request.request_sha256)
        .unwrap()
    {
        SpawnClaim::Granted { generation, .. } => generation,
        other => panic!("unexpected claim: {other:?}"),
    };

    assert_eq!(
        registry.record_pid(&call, generation, 321).unwrap(),
        MutationOutcome::Applied
    );
    assert_eq!(
        registry.record_pid(&call, generation, 321).unwrap(),
        MutationOutcome::Idempotent
    );
    assert_eq!(
        registry.record_pid(&call, generation, 322).unwrap_err(),
        RegistryError::PidConflict
    );
    assert_eq!(
        registry
            .record_pid(&call, generation.saturating_add(1), 321)
            .unwrap_err(),
        RegistryError::SpawnGenerationMismatch
    );

    let terminal = terminal(8);
    assert_eq!(
        registry
            .complete(&call, generation, terminal.clone())
            .unwrap(),
        MutationOutcome::Applied
    );
    assert_eq!(
        registry
            .complete(&call, generation, terminal.clone())
            .unwrap(),
        MutationOutcome::Idempotent
    );
    assert_eq!(
        registry
            .complete(&call, generation.saturating_add(1), terminal.clone())
            .unwrap_err(),
        RegistryError::TerminalConflict
    );
    assert_eq!(
        registry
            .complete(&call, generation, terminal(9))
            .unwrap_err(),
        RegistryError::TerminalConflict
    );
}

#[test]
fn cancellation_wins_before_spawn_but_started_calls_become_shared_cancel_requests() {
    let registry = CallRegistry::default();
    let before = key(1, "call-cancel-before");
    let before_request = request(10);
    let begin = registry
        .begin(before.clone(), before_request.clone())
        .unwrap();
    registry.request_cancel(&before).unwrap();
    assert!(begin.cancellation.is_cancelled());
    match registry
        .claim_spawn(&before, &before_request.request_sha256)
        .unwrap()
    {
        SpawnClaim::Inhibited(snapshot) => {
            assert_eq!(snapshot.state, EffectiveState::CancelledBeforeSpawn)
        }
        other => panic!("cancelled call unexpectedly spawned: {other:?}"),
    }

    let after = key(1, "call-cancel-after");
    let after_request = request(11);
    registry
        .begin(after.clone(), after_request.clone())
        .unwrap();
    let cancellation = match registry
        .claim_spawn(&after, &after_request.request_sha256)
        .unwrap()
    {
        SpawnClaim::Granted { cancellation, .. } => cancellation,
        other => panic!("unexpected started claim: {other:?}"),
    };
    assert!(!cancellation.is_cancelled());
    let snapshot = registry.request_cancel(&after).unwrap();
    assert!(cancellation.is_cancelled());
    assert!(matches!(snapshot.state, EffectiveState::Started { .. }));
}

#[test]
fn disconnect_uncertainty_and_late_terminal_are_monotonic() {
    let registry = CallRegistry::default();
    let call = key(1, "call-late-terminal");
    let request = request(12);
    registry.begin(call.clone(), request.clone()).unwrap();
    let generation = match registry
        .claim_spawn(&call, &request.request_sha256)
        .unwrap()
    {
        SpawnClaim::Granted { generation, .. } => generation,
        other => panic!("unexpected spawn claim: {other:?}"),
    };
    registry.record_pid(&call, generation, 777).unwrap();
    assert_eq!(
        registry.mark_connection_lost(&call).unwrap().state,
        EffectiveState::UnknownAfterDisconnect {
            generation,
            pid: Some(777),
        }
    );
    assert_eq!(
        registry.mark_connection_attached(&call).unwrap().state,
        EffectiveState::Started {
            generation,
            pid: Some(777),
        }
    );
    registry.mark_connection_lost(&call).unwrap();
    let terminal = terminal(13);
    registry
        .complete(&call, generation, terminal.clone())
        .unwrap();
    assert_eq!(
        registry.mark_connection_attached(&call).unwrap().state,
        EffectiveState::Terminal {
            generation,
            terminal,
        }
    );
}

#[test]
fn capacity_is_global_and_terminal_cleanup_is_explicit() {
    let registry = CallRegistry::new(RegistryLimits {
        max_entries: 1,
        ..RegistryLimits::default()
    })
    .unwrap();
    let first = key(1, "call-capacity-first");
    let request = request(14);
    registry.begin(first.clone(), request.clone()).unwrap();
    assert_eq!(
        registry
            .begin(key(2, "call-capacity-second"), request(15))
            .unwrap_err(),
        RegistryError::CapacityExhausted
    );
    assert!(!registry.remove_terminal(&first).unwrap());
    let generation = match registry
        .claim_spawn(&first, &request.request_sha256)
        .unwrap()
    {
        SpawnClaim::Granted { generation, .. } => generation,
        other => panic!("unexpected claim: {other:?}"),
    };
    registry.complete(&first, generation, terminal(16)).unwrap();
    assert!(registry.remove_terminal(&first).unwrap());
    assert!(registry.is_empty().unwrap());
    assert_eq!(
        registry
            .begin(key(2, "call-capacity-second"), request(15))
            .unwrap()
            .disposition,
        BeginDisposition::New
    );
}
