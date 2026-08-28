use trillionnium_owner_open_job_registry::{
    BeginDisposition, JobEffectiveState, JobKey, JobRegistry, JobRegistryError,
    JobRegistryLimits, JobRequest, JobScope, JobTerminal, MutationOutcome, SpawnClaim,
};

fn key(id: &str) -> JobKey {
    JobKey::new(
        JobScope::new("session", "owner-open", "task", "turn", "stream"),
        id,
    )
}

fn request(seed: char) -> JobRequest {
    JobRequest::new(
        seed.to_string().repeat(64),
        "b".repeat(64),
        "shell.job",
        "pty",
        Some("rootlinux".to_string()),
    )
}

fn terminal(seed: char) -> JobTerminal {
    JobTerminal {
        terminal_kind: "exited".to_string(),
        exit_code: Some(0),
        signal: None,
        observation_sha256: seed.to_string().repeat(64),
        stdout_bytes: 3,
        stderr_bytes: 0,
    }
}

#[test]
fn exact_begin_is_idempotent_and_drift_conflicts() {
    let registry = JobRegistry::default();
    let job = key("job-1");
    assert_eq!(
        registry.begin(job.clone(), request('a')).unwrap().disposition,
        BeginDisposition::New
    );
    assert_eq!(
        registry.begin(job.clone(), request('a')).unwrap().disposition,
        BeginDisposition::Existing
    );
    assert_eq!(
        registry.begin(job, request('c')).unwrap_err(),
        JobRegistryError::JobIdConflict
    );
}

#[test]
fn restart_never_redispatches_an_uncertain_running_job() {
    let registry = JobRegistry::default();
    let job = key("job-restart");
    registry.begin(job.clone(), request('a')).unwrap();
    let generation = match registry.claim_spawn(&job, &"a".repeat(64)).unwrap() {
        SpawnClaim::Granted { generation, .. } => generation,
        other => panic!("unexpected claim: {other:?}"),
    };
    registry.record_started(&job, generation, 42, true).unwrap();
    assert_eq!(
        registry.mark_restart_uncertain(&job).unwrap().state,
        JobEffectiveState::UnknownAfterRestart {
            generation,
            pid: Some(42),
            pty: Some(true)
        }
    );
    assert!(matches!(
        registry.claim_spawn(&job, &"a".repeat(64)).unwrap(),
        SpawnClaim::Existing(_)
    ));
}

#[test]
fn live_controls_and_terminal_history_are_bounded() {
    let registry = JobRegistry::new(JobRegistryLimits {
        max_history_per_job: 6,
        ..JobRegistryLimits::default()
    })
    .unwrap();
    let job = key("job-live");
    registry.begin(job.clone(), request('a')).unwrap();
    let generation = match registry.claim_spawn(&job, &"a".repeat(64)).unwrap() {
        SpawnClaim::Granted { generation, .. } => generation,
        other => panic!("unexpected claim: {other:?}"),
    };
    registry.record_started(&job, generation, 43, true).unwrap();
    registry
        .record_output(&job, generation, "pty", 3, "c".repeat(64))
        .unwrap();
    registry.record_input(&job, 2, "d".repeat(64)).unwrap();
    registry.record_resize(&job, 40, 120).unwrap();
    registry.attach(&job, "attachment-1").unwrap();
    assert_eq!(registry.close_stdin(&job).unwrap(), MutationOutcome::Applied);
    assert_eq!(registry.close_stdin(&job).unwrap(), MutationOutcome::Idempotent);
    registry.complete(&job, generation, terminal('e')).unwrap();
    let snapshot = registry.snapshot(&job).unwrap();
    assert!(matches!(snapshot.state, JobEffectiveState::Terminal { .. }));
    assert!(snapshot.stdin_closed);
    assert_eq!(snapshot.attachments, vec!["attachment-1"]);
    assert_eq!(registry.history_from(&job, 0).unwrap().len(), 6);
}

#[test]
fn pipe_job_rejects_resize() {
    let registry = JobRegistry::default();
    let job = key("job-pipe");
    registry.begin(job.clone(), request('a')).unwrap();
    let generation = match registry.claim_spawn(&job, &"a".repeat(64)).unwrap() {
        SpawnClaim::Granted { generation, .. } => generation,
        other => panic!("unexpected claim: {other:?}"),
    };
    registry.record_started(&job, generation, 44, false).unwrap();
    assert!(registry.record_resize(&job, 24, 80).is_err());
}
