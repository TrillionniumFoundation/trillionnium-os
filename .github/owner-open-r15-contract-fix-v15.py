from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"R15 {label} anchor is not exact")
    return text.replace(old, new, 1)


# Bind the Linux process identity tuple before the child becomes live and
# re-observe it before any numeric process-group signal.  A missing leader is
# idempotently gone; a reused/mismatched PID fails closed.
process_path = Path("crates/trillionnium-owner-open-job-runtime/src/process.rs")
process = process_path.read_text()
process = replace_once(
    process,
    "use std::fs::File;\n",
    "use std::fs::{self, File};\n",
    "process fs import",
)
process = replace_once(
    process,
    "    InternalProcessEvent, JobInvocation, JobRuntimeError, JobStartRequest, PtySize, Result,\n",
    "    InternalProcessEvent, JobInvocation, JobRuntimeError, JobStartRequest, ProcessIdentity,\n"
    "    PtySize, Result,\n",
    "process identity import",
)
process = replace_once(
    process,
    "pub(crate) struct ProcessControl {\n"
    "    pub pid: u32,\n"
    "    pub pty: bool,\n",
    "pub(crate) struct ProcessControl {\n"
    "    pub pid: u32,\n"
    "    pub pty: bool,\n"
    "    pub identity: ProcessIdentity,\n",
    "process control identity field",
)
process = replace_once(
    process,
    "    pub fn kill(&self, signal: i32) -> Result<()> {\n"
    "        send_process_group_signal(self.pid, signal).map_err(JobRuntimeError::Control)\n"
    "    }\n",
    "    pub fn kill(&self, signal: i32) -> Result<()> {\n"
    "        if !verify_process_identity(&self.identity).map_err(JobRuntimeError::Control)? {\n"
    "            return Ok(());\n"
    "        }\n"
    "        send_process_group_signal(self.pid, signal).map_err(JobRuntimeError::Control)\n"
    "    }\n",
    "identity-checked group signal",
)
process = replace_once(
    process,
    "    let pid = guard.pid;\n"
    "    let stdin = guard\n",
    "    let pid = guard.pid;\n"
    "    let identity = capture_process_identity(pid, false)?;\n"
    "    let stdin = guard\n",
    "pipe identity capture",
)
process = replace_once(
    process,
    "            pid,\n"
    "            pty: false,\n"
    "            input,\n",
    "            pid,\n"
    "            pty: false,\n"
    "            identity,\n"
    "            input,\n",
    "pipe identity ownership",
)
process = replace_once(
    process,
    "    let pid = guard.pid;\n"
    "    drop(slave);\n",
    "    let pid = guard.pid;\n"
    "    let identity = capture_process_identity(pid, true)?;\n"
    "    drop(slave);\n",
    "pty identity capture",
)
process = replace_once(
    process,
    "            pid,\n"
    "            pty: true,\n"
    "            input,\n",
    "            pid,\n"
    "            pty: true,\n"
    "            identity,\n"
    "            input,\n",
    "pty identity ownership",
)
identity_helpers = r'''
fn capture_process_identity(pid: u32, pty: bool) -> Result<ProcessIdentity> {
    let identity = observe_process_identity(pid)
        .map_err(JobRuntimeError::Control)?
        .ok_or_else(|| JobRuntimeError::Control("child exited before process identity binding".to_string()))?;
    let expected = i32::try_from(pid)
        .map_err(|_| JobRuntimeError::Control("child pid does not fit a POSIX identity".to_string()))?;
    if identity.process_group_id != expected {
        return Err(JobRuntimeError::Control(format!(
            "child process group was not bound to its pid: pid={pid}, pgid={}",
            identity.process_group_id
        )));
    }
    if pty && identity.session_id != expected {
        return Err(JobRuntimeError::Control(format!(
            "PTY child session was not bound to its pid: pid={pid}, sid={}",
            identity.session_id
        )));
    }
    Ok(identity)
}

fn verify_process_identity(identity: &ProcessIdentity) -> std::result::Result<bool, String> {
    let Some(observed) = observe_process_identity(identity.pid)? else {
        return Ok(false);
    };
    if observed != *identity {
        return Err(format!(
            "refusing numeric process-group control after identity changed: expected={identity:?}, observed={observed:?}"
        ));
    }
    Ok(true)
}

fn observe_process_identity(
    pid: u32,
) -> std::result::Result<Option<ProcessIdentity>, String> {
    let Some(start_time_ticks) = read_process_start_time(pid)? else {
        return Ok(None);
    };
    let process = i32::try_from(pid)
        .map_err(|_| "child pid does not fit a POSIX process identity".to_string())?;
    let process_group_id = unsafe { libc::getpgid(process) };
    if process_group_id == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return Err(format!("process-group identity probe failed: {error}"));
    }
    let session_id = unsafe { libc::getsid(process) };
    if session_id == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return Err(format!("session identity probe failed: {error}"));
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| format!("boot identity read failed: {error}"))?;
    let boot_id = boot_id.trim();
    if boot_id.is_empty() || boot_id.len() > 128 {
        return Err("boot identity is empty or oversized".to_string());
    }
    Ok(Some(ProcessIdentity {
        pid,
        process_group_id,
        session_id,
        boot_id: boot_id.to_string(),
        start_time_ticks,
    }))
}

fn read_process_start_time(pid: u32) -> std::result::Result<Option<u64>, String> {
    let path = format!("/proc/{pid}/stat");
    let stat = match fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("process start-time read failed for {path}: {error}")),
    };
    let command_end = stat
        .rfind(')')
        .ok_or_else(|| format!("process stat record has no command terminator: {path}"))?;
    let start_time = stat[command_end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| format!("process stat record has no start-time field: {path}"))?
        .parse::<u64>()
        .map_err(|error| format!("process start-time field is invalid for {path}: {error}"))?;
    if start_time == 0 {
        return Err(format!("process start-time field is zero for {path}"));
    }
    Ok(Some(start_time))
}

'''
process = replace_once(
    process,
    "fn base_command(request: &JobStartRequest) -> Result<Command> {\n",
    identity_helpers + "fn base_command(request: &JobStartRequest) -> Result<Command> {\n",
    "process identity helpers",
)
identity_tests = r'''

#[cfg(test)]
mod process_identity_tests {
    use super::*;

    #[test]
    fn current_process_identity_detects_stale_start_time() {
        let identity = observe_process_identity(std::process::id())
            .unwrap()
            .expect("test process must remain observable");
        assert!(verify_process_identity(&identity).unwrap());
        let mut stale = identity;
        stale.start_time_ticks = stale.start_time_ticks.saturating_add(1);
        assert!(
            verify_process_identity(&stale)
                .unwrap_err()
                .contains("identity changed")
        );
    }
}
'''
if "mod process_identity_tests" in process:
    raise SystemExit("R15 process identity tests already exist")
process += identity_tests
process_path.write_text(process)

# Expose the exact bound tuple in read-only runtime observations without
# changing the existing registry start event shape.
types_path = Path("crates/trillionnium-owner-open-job-runtime/src/types.rs")
types = types_path.read_text()
identity_type = r'''
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub process_group_id: i32,
    pub session_id: i32,
    pub boot_id: String,
    pub start_time_ticks: u64,
}

'''
types = replace_once(
    types,
    "#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\n"
    "#[serde(tag = \"kind\", rename_all = \"snake_case\")]\n"
    "pub enum RuntimeJobEventKind {\n",
    identity_type
    + "#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\n"
    + "#[serde(tag = \"kind\", rename_all = \"snake_case\")]\n"
    + "pub enum RuntimeJobEventKind {\n"
    + "    ProcessIdentityBound {\n"
    + "        generation: u64,\n"
    + "        identity: ProcessIdentity,\n"
    + "    },\n",
    "runtime process identity event",
)
types_path.write_text(types)

manager_path = Path("crates/trillionnium-owner-open-job-runtime/src/manager.rs")
manager = manager_path.read_text()
old_started = '''        let started = RuntimeJobEventKind::Started {
            generation,
            pid: running.control.pid,
            pty: running.control.pty,
        };
        if let Err(error) = self.push_runtime_event(&request.key, &request.request, started) {
            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());
            return Err(error);
        }
'''
new_started = '''        let identity_bound = RuntimeJobEventKind::ProcessIdentityBound {
            generation,
            identity: running.control.identity.clone(),
        };
        if let Err(error) =
            self.push_runtime_event(&request.key, &request.request, identity_bound)
        {
            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());
            return Err(error);
        }
        let started = RuntimeJobEventKind::Started {
            generation,
            pid: running.control.pid,
            pty: running.control.pty,
        };
        if let Err(error) = self.push_runtime_event(&request.key, &request.request, started) {
            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());
            return Err(error);
        }
'''
manager = replace_once(manager, old_started, new_started, "identity runtime observation")
manager = replace_once(
    manager,
    '                "pid": running.control.pid,\n'
    '                "pty": running.control.pty,\n'
    '                "automatic_redispatch": false\n',
    '                "pid": running.control.pid,\n'
    '                "pty": running.control.pty,\n'
    '                "process_group_id": running.control.identity.process_group_id,\n'
    '                "process_session_id": running.control.identity.session_id,\n'
    '                "boot_id": &running.control.identity.boot_id,\n'
    '                "process_start_time_ticks": running.control.identity.start_time_ticks,\n'
    '                "automatic_redispatch": false\n',
    "identity durable start result",
)
manager_path.write_text(manager)

source_test_path = Path("tools/tests/test_owner_open_r15_runtime_hardening.py")
source_test = source_test_path.read_text()
source_test = replace_once(
    source_test,
    '        self.assertNotIn("Err(_) => return", drop)\n',
    '        self.assertNotIn("Err(_) => return", drop)\n'
    '        self.assertIn("capture_process_identity(pid, false)", process)\n'
    '        self.assertIn("capture_process_identity(pid, true)", process)\n'
    '        self.assertIn("verify_process_identity(&self.identity)", process)\n'
    '        types = (ROOT / "crates/trillionnium-owner-open-job-runtime/src/types.rs").read_text()\n'
    '        self.assertIn("ProcessIdentityBound", types)\n'
    '        self.assertIn("start_time_ticks", types)\n'
    '        self.assertIn("process_group_id", types)\n'
    '        self.assertIn("boot_id", types)\n'
    '        self.assertIn("process_session_id", manager)\n',
    "process identity source assertions",
)
source_test_path.write_text(source_test)

doc_path = Path("docs/protocols/owner-open-jobs-v1.md")
doc = doc_path.read_text()
doc = replace_once(
    doc,
    "The parent-PID race is checked after configuring parent-death behavior.\n\n",
    "The parent-PID race is checked after configuring parent-death behavior. The\n"
    "runtime emits a `process_identity_bound` observation and records the same\n"
    "PID/PGID/SID/boot/start-time tuple in the durable start result before the\n"
    "dispatcher accepts live controls. Before sending a signal to a numeric\n"
    "process group, it re-observes the tuple; a missing leader is idempotently\n"
    "gone, while any reused or changed identity fails closed.\n\n",
    "process identity protocol truth",
)
doc_path.write_text(doc)
