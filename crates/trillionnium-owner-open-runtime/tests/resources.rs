use trillionnium_owner_open_runtime::{
    CancellationToken, ExecutionEventKind, MechanicalLimits, ShellExecRequest, TerminalKind,
    execute_shell,
};

#[test]
fn high_reader_profile_rejects_before_acceptance_or_effect() {
    let directory = tempfile::tempdir().unwrap();
    let mut request = ShellExecRequest::command("over-budget-reader", "touch must-not-run");
    request.cwd = Some(directory.path().to_path_buf());
    let limits = MechanicalLimits {
        stream_chunk_bytes: 16 * 1024 * 1024,
        reader_queue_depth: 64,
        ..MechanicalLimits::default()
    };
    let mut observations = Vec::new();
    let result = execute_shell(request, &limits, &CancellationToken::new(), |event| {
        observations.push(event)
    });
    assert!(result.is_err(), "one-GiB reader profile was admitted");
    assert!(observations.is_empty());
    assert!(!directory.path().join("must-not-run").exists());
}

#[test]
fn spare_stdin_capacity_rejects_before_acceptance_or_effect() {
    let directory = tempfile::tempdir().unwrap();
    let mut request = ShellExecRequest::command("over-budget-owned", "touch must-not-run");
    request.cwd = Some(directory.path().to_path_buf());
    request.stdin = Vec::with_capacity(64 * 1024 * 1024);
    let mut observations = Vec::new();
    let result = execute_shell(
        request,
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |event| observations.push(event),
    );
    assert!(result.is_err(), "spare owned capacity was admitted");
    assert!(observations.is_empty());
    assert!(!directory.path().join("must-not-run").exists());
}

#[test]
fn shared_reservations_reject_before_acceptance_and_release_after_cancelled_admission() {
    use std::{sync::mpsc, thread, time::Duration};
    let directory = tempfile::tempdir().unwrap();
    let (accepted, admitted) = mpsc::channel();
    let mut owners = Vec::new();
    for index in 0..2 {
        let (release, wait) = mpsc::channel();
        let accepted = accepted.clone();
        let cwd = directory.path().to_path_buf();
        let worker = thread::spawn(move || {
            let mut request =
                ShellExecRequest::command(format!("held-{index}"), "touch must-not-run");
            request.cwd = Some(cwd);
            request.stdin = Vec::with_capacity(27 * 1024 * 1024);
            let cancel = CancellationToken::new();
            let mut observations = Vec::new();
            let terminal = execute_shell(request, &MechanicalLimits::default(), &cancel, |event| {
                if matches!(event.kind, ExecutionEventKind::Accepted) {
                    accepted.send(()).unwrap();
                    wait.recv_timeout(Duration::from_secs(5)).unwrap();
                    cancel.cancel();
                }
                observations.push(event);
            })
            .unwrap();
            assert_eq!(terminal.kind, TerminalKind::Cancelled);
            assert_eq!(observations.len(), 2);
            assert!(
                !observations
                    .iter()
                    .any(|event| matches!(event.kind, ExecutionEventKind::Started { .. }))
            );
        });
        owners.push((release, worker));
    }
    for _ in 0..2 {
        admitted.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    let mut request = ShellExecRequest::command("capacity-refused", "touch must-not-run");
    request.cwd = Some(directory.path().to_path_buf());
    let mut events = Vec::new();
    let refused = execute_shell(
        request,
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |event| events.push(event),
    );
    // Release owners even if the assertion below fails, so a failed regression
    // does not leave admission callbacks parked until their timeout.
    for (release, _) in &owners {
        release.send(()).unwrap();
    }
    for (_, worker) in owners {
        worker.join().unwrap();
    }
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("shared process/buffer capacity")
    );
    assert!(events.is_empty());
    assert!(!directory.path().join("must-not-run").exists());
    let terminal = execute_shell(
        ShellExecRequest::command("after-release", "printf exact"),
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |_| {},
    )
    .unwrap();
    assert_eq!(terminal.kind, TerminalKind::Exited);
    assert_eq!(terminal.exit_code, Some(0));
    assert_eq!(terminal.stdout_bytes, 5);
}

#[test]
fn inherited_environment_is_bounded_before_acceptance() {
    let mut fixture = std::process::Command::new(std::env::current_exe().unwrap());
    fixture.args(["--exact", "inherited_environment_fixture", "--ignored"]);
    for index in 0..24 {
        fixture.env(
            format!("RUNTIME_RESOURCE_FIXTURE_{index}"),
            "x".repeat(64 * 1024),
        );
    }
    let output = fixture.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
#[test]
#[ignore = "subprocess fixture with an oversized inherited environment"]
fn inherited_environment_fixture() {
    let mut observed = false;
    let result = execute_shell(
        ShellExecRequest::command("inherited-budget", ":"),
        &MechanicalLimits::default(),
        &CancellationToken::new(),
        |_| observed = true,
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("inherited environment")
    );
    assert!(!observed);
}
