from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"R15 {label} anchor is not exact")
    return text.replace(old, new, 1)


process_path = Path("crates/trillionnium-owner-open-provider-jsonl/src/process.rs")
process = process_path.read_text()
process = replace_once(
    process,
    "use std::io::{BufRead, BufReader, Read};\n",
    "use std::io::{BufRead, BufReader, Read};\n"
    "use std::ops::{Deref, DerefMut};\n",
    "provider guard deref imports",
)
process = replace_once(
    process,
    "use std::time::{Duration, Instant};\n\n",
    "use std::time::{Duration, Instant};\n\n"
    "const PROVIDER_GUARD_REAP_GRACE: Duration = Duration::from_millis(500);\n\n",
    "provider guard reap bound",
)
guard = r'''pub(crate) struct ProviderChildGuard {
    child: Option<Child>,
    pid: u32,
}

impl ProviderChildGuard {
    pub(crate) fn new(child: Child) -> Self {
        let pid = child.id();
        Self {
            child: Some(child),
            pid,
        }
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn child_mut(&mut self) -> Result<&mut Child, String> {
        self.child
            .as_mut()
            .ok_or_else(|| "provider child guard no longer owns its child".to_string())
    }

    pub(crate) fn finish(mut self, grace: Duration) -> Result<ExitStatus, String> {
        let pid = self.pid;
        let result = match self.child.as_mut() {
            Some(child) => finish_child(child, pid, grace),
            None => Err("provider child guard no longer owns its child".to_string()),
        };
        if result.is_ok() {
            self.child.take();
        }
        result
    }
}

impl Deref for ProviderChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        self.child
            .as_ref()
            .expect("provider child guard owns its child until finish")
    }
}

impl DerefMut for ProviderChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.child
            .as_mut()
            .expect("provider child guard owns its child until finish")
    }
}

impl Drop for ProviderChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = send_group_signal(self.pid, libc::SIGKILL);
        let _ = child.kill();

        let deadline = Instant::now()
            .checked_add(PROVIDER_GUARD_REAP_GRACE)
            .unwrap_or_else(Instant::now);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                Ok(None) | Err(_) => break,
            }
        }

        // A bounded error path must not discard wait(2) ownership. Transfer
        // the still-owned Child to a detached reaper rather than blocking Drop.
        let name = format!("owner-open-provider-abort-reaper-{}", self.pid);
        let owner = Arc::new(Mutex::new(Some(child)));
        let thread_owner = Arc::clone(&owner);
        if thread::Builder::new()
            .name(name)
            .spawn(move || {
                let Ok(mut slot) = thread_owner.lock() else {
                    return;
                };
                if let Some(mut child) = slot.take() {
                    let _ = child.wait();
                }
            })
            .is_err()
        {
            // Thread creation failure is exceptional, but ownership still
            // remains in this scope. SIGKILL was already sent, so wait cannot
            // silently leak a zombie into the long-lived provider process.
            if let Ok(mut slot) = owner.lock()
                && let Some(mut child) = slot.take()
            {
                let _ = child.wait();
            }
        }
    }
}

'''
process = replace_once(
    process,
    "#[derive(Debug)]\npub(crate) enum ProviderOutput {\n",
    guard + "#[derive(Debug)]\npub(crate) enum ProviderOutput {\n",
    "provider child guard",
)
provider_guard_test = r'''

    #[test]
    fn provider_guard_drop_kills_and_reaps_the_owned_group() {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("exec sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let guard = ProviderChildGuard::new(command.spawn().unwrap());
        let pid = i32::try_from(guard.pid()).unwrap();
        drop(guard);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if unsafe { libc::kill(pid, 0) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    break;
                }
                panic!("unexpected provider liveness probe error: {error}");
            }
            assert!(
                Instant::now() < deadline,
                "provider guard left its child observable"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
'''
if process.count("mod tests {") != 1 or "provider_guard_drop_kills" in process:
    raise SystemExit("R15 provider guard test module is not exact")
module_end = process.rfind("\n}")
if module_end < process.index("mod tests {"):
    raise SystemExit("R15 provider test module end is missing")
process = process[:module_end] + provider_guard_test + process[module_end:]
process_path.write_text(process)

lib_path = Path("crates/trillionnium-owner-open-provider-jsonl/src/lib.rs")
lib = lib_path.read_text()
lib = replace_once(
    lib,
    "    ProviderOutput, allow_natural_exit_grace, finish_child, spawn_stderr_reader,\n"
    "    spawn_stdout_reader,\n",
    "    ProviderChildGuard, ProviderOutput, allow_natural_exit_grace, spawn_stderr_reader,\n"
    "    spawn_stdout_reader,\n",
    "provider guard import",
)
lib = replace_once(
    lib,
    "        let mut child = command\n"
    "            .spawn()\n"
    "            .map_err(|error| JsonlProviderError::Spawn(error.to_string()))?;\n"
    "        let pid = child.id();\n",
    "        let child = command\n"
    "            .spawn()\n"
    "            .map_err(|error| JsonlProviderError::Spawn(error.to_string()))?;\n"
    "        let mut child = ProviderChildGuard::new(child);\n"
    "        let pid = child.pid();\n",
    "provider guard construction",
)
lib = replace_once(
    lib,
    "        let mut provider_stdin = child\n"
    "            .stdin\n"
    "            .take()\n",
    "        let mut provider_stdin = child\n"
    "            .child_mut()\n"
    "            .map_err(JsonlProviderError::Cleanup)?\n"
    "            .stdin\n"
    "            .take()\n",
    "provider stdin guarded take",
)
lib = replace_once(
    lib,
    "        let provider_stdout = child\n"
    "            .stdout\n"
    "            .take()\n",
    "        let provider_stdout = child\n"
    "            .child_mut()\n"
    "            .map_err(JsonlProviderError::Cleanup)?\n"
    "            .stdout\n"
    "            .take()\n",
    "provider stdout guarded take",
)
lib = replace_once(
    lib,
    "        let provider_stderr = child\n"
    "            .stderr\n"
    "            .take()\n",
    "        let provider_stderr = child\n"
    "            .child_mut()\n"
    "            .map_err(JsonlProviderError::Cleanup)?\n"
    "            .stderr\n"
    "            .take()\n",
    "provider stderr guarded take",
)
lib = replace_once(
    lib,
    "        let cleanup = finish_child(&mut child, pid, self.config.terminate_grace)\n"
    "            .map_err(JsonlProviderError::Cleanup);\n",
    "        let cleanup = child\n"
    "            .finish(self.config.terminate_grace)\n"
    "            .map_err(JsonlProviderError::Cleanup);\n",
    "provider guard finish",
)
lib_path.write_text(lib)

source_test_path = Path("tools/tests/test_owner_open_r15_runtime_hardening.py")
source_test = source_test_path.read_text()
method = r'''

    def test_provider_post_spawn_paths_have_one_total_child_owner(self) -> None:
        provider = (ROOT / "crates/trillionnium-owner-open-provider-jsonl/src/lib.rs").read_text()
        process = (ROOT / "crates/trillionnium-owner-open-provider-jsonl/src/process.rs").read_text()
        self.assertIn("ProviderChildGuard::new(child)", provider)
        self.assertIn(".finish(self.config.terminate_grace)", provider)
        self.assertIn("impl Drop for ProviderChildGuard", process)
        self.assertIn("PROVIDER_GUARD_REAP_GRACE", process)
        self.assertIn("owner-open-provider-abort-reaper", process)
        self.assertIn("let _ = child.wait();", process)
'''
source_test = replace_once(
    source_test,
    "\n\nclass WorkflowBoundaryGenerationTests(unittest.TestCase):\n",
    method + "\n\nclass WorkflowBoundaryGenerationTests(unittest.TestCase):\n",
    "provider guard source assertions",
)
source_test_path.write_text(source_test)

doc_path = Path("docs/protocols/owner-open-jobs-v1.md")
doc = doc_path.read_text()
doc = replace_once(
    doc,
    "Until the live state is committed, one lifecycle guard owns the child,\n"
    "reservation, FDs, registry and journal transitions. Every failure after spawn\n"
    "performs bounded process-group cleanup, leader reap, FD closure, reservation\n"
    "release and a truthful terminal/degraded state.\n",
    "Until the live state is committed, one lifecycle guard owns the child,\n"
    "reservation, FDs, registry and journal transitions. The external JSONL\n"
    "provider has the same post-spawn ownership rule: pipe extraction, protocol\n"
    "failure and cleanup errors cannot drop the only `wait(2)` owner. Every\n"
    "failure after spawn performs bounded process-group cleanup, leader reap, FD\n"
    "closure, reservation release and a truthful terminal/degraded state.\n",
    "provider lifecycle protocol truth",
)
doc_path.write_text(doc)
