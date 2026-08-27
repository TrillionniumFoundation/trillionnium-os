use std::fs;
use std::thread;
use std::time::{Duration, Instant};

use trillionnium_owner_open_runtime::{
    CancellationToken, MechanicalLimits, ShellExecRequest, TerminalKind, execute_shell,
};

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
    let mut limits = MechanicalLimits::default();
    limits.terminate_grace = Duration::from_millis(30);

    let terminal = execute_shell(
        request,
        &limits,
        &CancellationToken::new(),
        |_| {},
    )
    .unwrap();
    assert_eq!(terminal.kind, TerminalKind::TimedOut);

    let descendant = fs::read_to_string(&pid_file)
        .expect("the shell must publish its descendant pid before timeout")
        .trim()
        .parse::<i32>()
        .expect("descendant pid must be decimal");
    assert!(descendant > 1);

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let result = unsafe { libc::kill(descendant, 0) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                break;
            }
            panic!("unexpected descendant liveness probe error: {error}");
        }
        assert!(
            Instant::now() < deadline,
            "forked descendant {descendant} survived process-group cleanup"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
