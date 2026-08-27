use trillionnium_agent_direct_tools::{DirectToolError, Result};
use trillionnium_shell_exec::mcp_adapter::{self, ProductTransportBackendV1};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let expected_parent = harden_entry()?;
    trillionnium_agent_direct_tools::post_exec_admission::require_product_post_exec_admission()?;
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 || arguments[0] != "mcp" {
        return Err(DirectToolError::InvalidRequest(
            "usage: trillionnium-agent-shell mcp".to_string(),
        ));
    }
    let backend = ProductTransportBackendV1::from_process_environment()?;
    require_same_parent(expected_parent)?;
    mcp_adapter::serve_stdio(backend)
}

fn harden_entry() -> Result<libc::pid_t> {
    // Capture first: if the spawning host dies before PR_SET_PDEATHSIG, the
    // post-prctl getppid check detects reparenting and refuses to serve.
    let expected_parent = unsafe { libc::getppid() };
    if expected_parent <= 1 {
        return Err(entry_hardening_error());
    }
    // SAFETY: all prctl operations affect only this adapter process and use
    // constant options. They do not grant namespace or effect authority.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(entry_hardening_error());
    }
    let mut observed_parent_death_signal = 0;
    if unsafe {
        libc::prctl(
            libc::PR_GET_PDEATHSIG,
            &mut observed_parent_death_signal,
            0,
            0,
            0,
        )
    } != 0
        || observed_parent_death_signal != libc::SIGKILL
    {
        return Err(entry_hardening_error());
    }
    require_same_parent(expected_parent)?;
    Ok(expected_parent)
}

fn require_same_parent(expected_parent: libc::pid_t) -> Result<()> {
    if expected_parent <= 1 || unsafe { libc::getppid() } != expected_parent {
        return Err(entry_hardening_error());
    }
    Ok(())
}

fn entry_hardening_error() -> DirectToolError {
    DirectToolError::BackendUnavailable("shell MCP adapter entry hardening failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_sets_sigkill_parent_death_and_rechecks_parent() {
        let parent = harden_entry().unwrap();
        require_same_parent(parent).unwrap();
        assert!(require_same_parent(parent.saturating_add(1)).is_err());
        let mut signal = 0;
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut signal, 0, 0, 0) },
            0
        );
        assert_eq!(signal, libc::SIGKILL);
    }
}
