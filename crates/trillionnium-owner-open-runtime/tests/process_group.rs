use std::fs;
use std::thread;
use std::time::{Duration, Instant};

use trillionnium_owner_open_runtime::{
    CancellationToken, MechanicalLimits, ShellExecRequest, TerminalKind, execute_shell,
};

fn wait_until_gone(pid: i32) {
    assert!(pid > 1);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let result = unsafe { libc::kill(pid, 0) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return;
            }
            panic!("unexpected descendant liveness probe error: {error}");
        }
        assert!(
            Instant::now() < deadline,
            "forked descendant {pid} survived process-group cleanup"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn timeout_closes_a_forked_descendant_in_the_call_process_group() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("descendant.pid");
    let script = r#"
sleep 30 &
descendant=$!
printf '%s\n' "$descendant" >"$1"
wait "$descendant"
"#;
    let mut request = ShellExecRequest::argv(
        "call-forked-timeout",
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            script.to_string(),
            "owner-open-process-group-test".to_string(),
            pid_file.to_string_lossy().into_owned(),
        ],
    );
    request.timeout = Some(Duration::from_millis(100));
    let limits = MechanicalLimits {
        terminate_grace: Duration::from_millis(30),
        ..MechanicalLimits::default()
    };

    let terminal = execute_shell(request, &limits, &CancellationToken::new(), |_| {}).unwrap();
    assert_eq!(terminal.kind, TerminalKind::TimedOut);

    let descendant = fs::read_to_string(&pid_file)
        .expect("the shell must publish its descendant pid before timeout")
        .trim()
        .parse::<i32>()
        .expect("descendant pid must be decimal");
    wait_until_gone(descendant);
}

#[test]
fn leader_exit_with_inherited_pipes_is_bounded_and_reaps_the_descendant() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("leader-exit-descendant.pid");
    let script = r#"
sleep 30 &
descendant=$!
printf '%s\n' "$descendant" >"$1"
exit 0
"#;
    let mut request = ShellExecRequest::argv(
        "call-leader-exit",
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            script.to_string(),
            "owner-open-leader-exit-test".to_string(),
            pid_file.to_string_lossy().into_owned(),
        ],
    );
    request.timeout = Some(Duration::from_secs(5));
    let limits = MechanicalLimits {
        terminate_grace: Duration::from_millis(50),
        ..MechanicalLimits::default()
    };
    let started = Instant::now();

    let terminal = execute_shell(request, &limits, &CancellationToken::new(), |_| {}).unwrap();
    assert_eq!(terminal.kind, TerminalKind::IoError);
    assert!(
        terminal
            .error
            .as_deref()
            .is_some_and(|value| value.contains("leader_exited_with_live_descendants")),
        "terminal={terminal:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));

    let descendant = fs::read_to_string(&pid_file)
        .expect("the shell must publish its descendant pid before exit")
        .trim()
        .parse::<i32>()
        .expect("descendant pid must be decimal");
    wait_until_gone(descendant);
}
