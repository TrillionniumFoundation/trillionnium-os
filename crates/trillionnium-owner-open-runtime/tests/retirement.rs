#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use trillionnium_owner_open_runtime::{
    CancellationToken, ExecutionEventKind, MechanicalLimits, ShellExecRequest, TerminalKind,
    execute_shell,
};

const ISOLATED: &str = "OWNER_OPEN_RETIREMENT_ISOLATED";
const PID_PATH: &str = "OWNER_OPEN_RETIREMENT_PID_PATH";

fn count(path: &str) -> usize {
    fs::read_dir(path).unwrap().count()
}

struct EscapedFixtures(Vec<i32>);

impl Drop for EscapedFixtures {
    fn drop(&mut self) {
        // This isolated process is the subreaper of these exact fixture
        // children. The test never probes or reaps another test's children.
        for pid in &self.0 {
            unsafe {
                libc::kill(*pid, libc::SIGKILL);
                libc::waitpid(*pid, std::ptr::null_mut(), 0);
            }
        }
    }
}

#[test]
fn escaped_pipe_holders_do_not_retain_runtime_workers_or_descriptors() {
    if std::env::var_os(ISOLATED).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "escaped_pipe_holders_do_not_retain_runtime_workers_or_descriptors",
                "--nocapture",
            ])
            .env(ISOLATED, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let directory = tempfile::tempdir().unwrap();
    let mut escaped = EscapedFixtures(Vec::new());
    let baseline = (count("/proc/self/task"), count("/proc/self/fd"));
    for index in 0..3 {
        let pid_path = directory.path().join(format!("escaped-{index}.pid"));
        let mut request = ShellExecRequest::argv(
            format!("retire-{index}"),
            vec![
                std::env::current_exe()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                "--exact".into(),
                "spawn_escape_fixture".into(),
                "--ignored".into(),
                "--nocapture".into(),
            ],
        );
        request.env.insert(
            PID_PATH.into(),
            Some(pid_path.to_string_lossy().into_owned()),
        );
        request.stdin = vec![b'x'; 1024 * 1024];
        let limits = MechanicalLimits {
            terminate_grace: Duration::from_millis(10),
            ..MechanicalLimits::default()
        };
        let terminal = execute_shell(request, &limits, &CancellationToken::new(), |_| {}).unwrap();
        let pid = fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        escaped.0.push(pid);
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            0,
            "fixture must still hold pipes"
        );
        assert_eq!(terminal.kind, TerminalKind::IoError, "{terminal:?}");
        assert!(
            terminal
                .error
                .as_deref()
                .unwrap()
                .contains("output_pipes_remained_open_after_leader_exit")
        );
        assert!(terminal.elapsed_ms < 5000, "{terminal:?}");
        assert_eq!(
            (count("/proc/self/task"), count("/proc/self/fd")),
            baseline,
            "returned call {index} must have joined every reader/writer and closed their FDs"
        );
    }
}

#[test]
#[ignore = "subprocess fixture"]
fn spawn_escape_fixture() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "retained_pipe_fixture",
            "--ignored",
            "--nocapture",
        ])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    // Publish the exact live Child PID before returning. The outer isolated
    // fixture becomes its parent and retains cleanup authority via waitpid.
    fs::write(std::env::var_os(PID_PATH).unwrap(), child.id().to_string()).unwrap();
    drop(child);
}

#[test]
#[ignore = "subprocess fixture"]
fn retained_pipe_fixture() {
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
fn expired_deadline_rejects_spawn_and_active_deadline_preserves_timeout() {
    let limits = MechanicalLimits {
        terminate_grace: Duration::from_millis(10),
        ..MechanicalLimits::default()
    };
    let mut events = Vec::new();
    let expired = CancellationToken::new().with_deadline(Some(Instant::now()));
    let terminal = execute_shell(
        ShellExecRequest::command("expired", "exit 0"),
        &limits,
        &expired,
        |event| events.push(event),
    )
    .unwrap();
    assert_eq!(terminal.kind, TerminalKind::TimedOut);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.kind, ExecutionEventKind::Started { .. }))
    );
    assert_eq!(terminal.exit_code, None);

    let active =
        CancellationToken::new().with_deadline(Some(Instant::now() + Duration::from_millis(150)));
    let mut events = Vec::new();
    let terminal = execute_shell(
        ShellExecRequest::command("active", "sleep 2; printf must-not-occur"),
        &limits,
        &active,
        |event| events.push(event),
    )
    .unwrap();
    assert_eq!(terminal.kind, TerminalKind::TimedOut, "{terminal:?}");
    assert!(
        events
            .iter()
            .any(|event| matches!(event.kind, ExecutionEventKind::Started { .. }))
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.kind, ExecutionEventKind::Output { .. }))
    );
}

#[test]
fn enclosing_deadline_cannot_extend_a_shorter_runtime_deadline() {
    let first = Instant::now() + Duration::from_millis(10);
    let token = CancellationToken::new()
        .with_deadline(Some(first))
        .with_deadline(Some(first + Duration::from_secs(10)));
    assert_eq!(token.deadline(), Some(first));

    let token =
        CancellationToken::new().with_deadline(Some(Instant::now() + Duration::from_secs(5)));
    let mut request = ShellExecRequest::command("shorter-tool-budget", "exec sleep 2");
    request.timeout = Some(Duration::from_millis(50));
    let started = Instant::now();
    let terminal = execute_shell(request, &MechanicalLimits::default(), &token, |_| {}).unwrap();
    assert_eq!(terminal.kind, TerminalKind::TimedOut, "{terminal:?}");
    assert!(started.elapsed() < Duration::from_secs(1));
}
