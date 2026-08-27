//! Active, irreversible process hardening for the privilege-broker startup.
//!
//! This boundary does not grant authority or make the inert mutation backend
//! reachable. It narrows the already-started broker before accepting a peer:
//! only one untraced thread may exist, the supervisor relationship is bound to
//! `PDEATHSIG=SIGKILL`, core dumps and dumpability are disabled, privilege gain
//! across exec is denied, and the filesystem creation mask becomes private.

use std::fs;
use std::io;

use thiserror::Error;

const PRIVATE_FILE_CREATION_MASK: libc::mode_t = 0o077;

#[derive(Debug, Error)]
pub enum StartupSecurityError {
    #[error("startup security operation failed at {stage}: {source}")]
    Operation {
        stage: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("startup process status field is missing, duplicated, or malformed: {0}")]
    StatusFieldDenied(&'static str),
    #[error("startup requires exactly one process thread")]
    ThreadCountDenied,
    #[error("startup under a tracer is denied")]
    TracerDenied,
    #[error("startup supervisor identity is unavailable")]
    ParentDenied,
    #[error("startup supervisor changed while parent-death custody was installed")]
    ParentChanged,
    #[error("startup parent-death signal contract mismatch")]
    ParentDeathSignalMismatch,
    #[error("startup private file-creation mask contract mismatch")]
    FileCreationMaskMismatch,
    #[error("startup core-dump resource limit contract mismatch")]
    CoreLimitMismatch,
    #[error("startup dumpability contract mismatch")]
    DumpableMismatch,
    #[error("startup no-new-privileges contract mismatch")]
    NoNewPrivilegesMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessObservation {
    thread_count: u64,
    tracer_pid: libc::pid_t,
}

trait StartupSecurityOps {
    fn observe_process(&mut self) -> io::Result<ProcessObservation>;
    fn parent_pid(&mut self) -> libc::pid_t;
    fn set_parent_death_signal(&mut self, signal: libc::c_int) -> io::Result<()>;
    fn parent_death_signal(&mut self) -> io::Result<libc::c_int>;
    fn set_file_creation_mask(&mut self, mask: libc::mode_t) -> libc::mode_t;
    fn set_core_limit_zero(&mut self) -> io::Result<()>;
    fn core_limit(&mut self) -> io::Result<libc::rlimit>;
    fn set_dumpable(&mut self, value: libc::c_int) -> io::Result<()>;
    fn dumpable(&mut self) -> io::Result<libc::c_int>;
    fn set_no_new_privileges(&mut self) -> io::Result<()>;
    fn no_new_privileges(&mut self) -> io::Result<libc::c_int>;
}

struct LinuxStartupSecurityOps;

impl StartupSecurityOps for LinuxStartupSecurityOps {
    fn observe_process(&mut self) -> io::Result<ProcessObservation> {
        let status = fs::read_to_string("/proc/self/status")?;
        parse_process_observation(&status).map_err(io::Error::other)
    }

    fn parent_pid(&mut self) -> libc::pid_t {
        unsafe { libc::getppid() }
    }

    fn set_parent_death_signal(&mut self, signal: libc::c_int) -> io::Result<()> {
        prctl_no_pointer(libc::PR_SET_PDEATHSIG, signal as libc::c_ulong)
    }

    fn parent_death_signal(&mut self) -> io::Result<libc::c_int> {
        let mut signal: libc::c_int = 0;
        let result = unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut signal) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(signal)
    }

    fn set_file_creation_mask(&mut self, mask: libc::mode_t) -> libc::mode_t {
        unsafe { libc::umask(mask) }
    }

    fn set_core_limit_zero(&mut self) -> io::Result<()> {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn core_limit(&mut self) -> io::Result<libc::rlimit> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(limit)
    }

    fn set_dumpable(&mut self, value: libc::c_int) -> io::Result<()> {
        prctl_no_pointer(libc::PR_SET_DUMPABLE, value as libc::c_ulong)
    }

    fn dumpable(&mut self) -> io::Result<libc::c_int> {
        prctl_get_scalar(libc::PR_GET_DUMPABLE)
    }

    fn set_no_new_privileges(&mut self) -> io::Result<()> {
        prctl_no_pointer(libc::PR_SET_NO_NEW_PRIVS, 1)
    }

    fn no_new_privileges(&mut self) -> io::Result<libc::c_int> {
        prctl_get_scalar(libc::PR_GET_NO_NEW_PRIVS)
    }
}

fn prctl_no_pointer(option: libc::c_int, argument: libc::c_ulong) -> io::Result<()> {
    if unsafe { libc::prctl(option, argument, 0, 0, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn prctl_get_scalar(option: libc::c_int) -> io::Result<libc::c_int> {
    let result = unsafe { libc::prctl(option, 0, 0, 0, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

/// Irreversibly narrow the current broker process before it accepts a client.
///
/// The caller must still be single-threaded. Any failed setter or mismatched
/// re-observation is fatal; there is no attempt to restore a partially applied
/// security profile.
pub fn harden_current_process() -> Result<(), StartupSecurityError> {
    harden_with_ops(&mut LinuxStartupSecurityOps)
}

fn harden_with_ops(ops: &mut impl StartupSecurityOps) -> Result<(), StartupSecurityError> {
    validate_observation(operation("observe-before", ops.observe_process())?)?;
    let parent = ops.parent_pid();
    if parent <= 0 {
        return Err(StartupSecurityError::ParentDenied);
    }

    operation(
        "set-parent-death-signal",
        ops.set_parent_death_signal(libc::SIGKILL),
    )?;
    if ops.parent_pid() != parent {
        return Err(StartupSecurityError::ParentChanged);
    }
    if operation("get-parent-death-signal", ops.parent_death_signal())? != libc::SIGKILL {
        return Err(StartupSecurityError::ParentDeathSignalMismatch);
    }

    ops.set_file_creation_mask(PRIVATE_FILE_CREATION_MASK);
    if ops.set_file_creation_mask(PRIVATE_FILE_CREATION_MASK) != PRIVATE_FILE_CREATION_MASK {
        return Err(StartupSecurityError::FileCreationMaskMismatch);
    }

    operation("set-core-limit", ops.set_core_limit_zero())?;
    let core_limit = operation("get-core-limit", ops.core_limit())?;
    if core_limit.rlim_cur != 0 || core_limit.rlim_max != 0 {
        return Err(StartupSecurityError::CoreLimitMismatch);
    }

    operation("set-dumpable", ops.set_dumpable(0))?;
    if operation("get-dumpable", ops.dumpable())? != 0 {
        return Err(StartupSecurityError::DumpableMismatch);
    }

    operation("set-no-new-privileges", ops.set_no_new_privileges())?;
    if operation("get-no-new-privileges", ops.no_new_privileges())? != 1 {
        return Err(StartupSecurityError::NoNewPrivilegesMismatch);
    }

    validate_observation(operation("observe-after", ops.observe_process())?)?;
    if ops.parent_pid() != parent {
        return Err(StartupSecurityError::ParentChanged);
    }
    Ok(())
}

fn operation<T>(stage: &'static str, result: io::Result<T>) -> Result<T, StartupSecurityError> {
    result.map_err(|source| StartupSecurityError::Operation { stage, source })
}

fn validate_observation(observation: ProcessObservation) -> Result<(), StartupSecurityError> {
    if observation.thread_count != 1 {
        return Err(StartupSecurityError::ThreadCountDenied);
    }
    if observation.tracer_pid != 0 {
        return Err(StartupSecurityError::TracerDenied);
    }
    Ok(())
}

fn parse_process_observation(status: &str) -> Result<ProcessObservation, StartupSecurityError> {
    let thread_count = parse_single_decimal(status, "Threads")?;
    let tracer_pid_raw = parse_single_decimal(status, "TracerPid")?;
    let tracer_pid = libc::pid_t::try_from(tracer_pid_raw)
        .map_err(|_| StartupSecurityError::StatusFieldDenied("TracerPid"))?;
    Ok(ProcessObservation {
        thread_count,
        tracer_pid,
    })
}

fn parse_single_decimal(status: &str, field: &'static str) -> Result<u64, StartupSecurityError> {
    let prefix = format!("{field}:");
    let mut values = status.lines().filter_map(|line| line.strip_prefix(&prefix));
    let value = values
        .next()
        .ok_or(StartupSecurityError::StatusFieldDenied(field))?;
    if values.next().is_some() {
        return Err(StartupSecurityError::StatusFieldDenied(field));
    }
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(StartupSecurityError::StatusFieldDenied(field));
    }
    value
        .parse()
        .map_err(|_| StartupSecurityError::StatusFieldDenied(field))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FakeOps {
        observation: ProcessObservation,
        parent: libc::pid_t,
        parent_after_set: libc::pid_t,
        parent_signal: libc::c_int,
        mask: libc::mode_t,
        core_limit: libc::rlimit,
        dumpable: libc::c_int,
        no_new_privileges: libc::c_int,
        calls: Vec<&'static str>,
    }

    impl Default for FakeOps {
        fn default() -> Self {
            Self {
                observation: ProcessObservation {
                    thread_count: 1,
                    tracer_pid: 0,
                },
                parent: 42,
                parent_after_set: 42,
                parent_signal: 0,
                mask: 0o022,
                core_limit: libc::rlimit {
                    rlim_cur: libc::RLIM_INFINITY,
                    rlim_max: libc::RLIM_INFINITY,
                },
                dumpable: 1,
                no_new_privileges: 0,
                calls: Vec::new(),
            }
        }
    }

    impl StartupSecurityOps for FakeOps {
        fn observe_process(&mut self) -> io::Result<ProcessObservation> {
            self.calls.push("observe");
            Ok(self.observation)
        }

        fn parent_pid(&mut self) -> libc::pid_t {
            self.calls.push("parent");
            if self.parent_signal == libc::SIGKILL {
                self.parent_after_set
            } else {
                self.parent
            }
        }

        fn set_parent_death_signal(&mut self, signal: libc::c_int) -> io::Result<()> {
            self.calls.push("set-pdeathsig");
            self.parent_signal = signal;
            Ok(())
        }

        fn parent_death_signal(&mut self) -> io::Result<libc::c_int> {
            self.calls.push("get-pdeathsig");
            Ok(self.parent_signal)
        }

        fn set_file_creation_mask(&mut self, mask: libc::mode_t) -> libc::mode_t {
            self.calls.push("umask");
            let previous = self.mask;
            self.mask = mask;
            previous
        }

        fn set_core_limit_zero(&mut self) -> io::Result<()> {
            self.calls.push("set-core");
            self.core_limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            Ok(())
        }

        fn core_limit(&mut self) -> io::Result<libc::rlimit> {
            self.calls.push("get-core");
            Ok(self.core_limit)
        }

        fn set_dumpable(&mut self, value: libc::c_int) -> io::Result<()> {
            self.calls.push("set-dumpable");
            self.dumpable = value;
            Ok(())
        }

        fn dumpable(&mut self) -> io::Result<libc::c_int> {
            self.calls.push("get-dumpable");
            Ok(self.dumpable)
        }

        fn set_no_new_privileges(&mut self) -> io::Result<()> {
            self.calls.push("set-nnp");
            self.no_new_privileges = 1;
            Ok(())
        }

        fn no_new_privileges(&mut self) -> io::Result<libc::c_int> {
            self.calls.push("get-nnp");
            Ok(self.no_new_privileges)
        }
    }

    #[test]
    fn exact_startup_profile_is_applied_and_reobserved() {
        let mut ops = FakeOps::default();
        harden_with_ops(&mut ops).unwrap();
        assert_eq!(ops.parent_signal, libc::SIGKILL);
        assert_eq!(ops.mask, PRIVATE_FILE_CREATION_MASK);
        assert_eq!(ops.core_limit.rlim_cur, 0);
        assert_eq!(ops.core_limit.rlim_max, 0);
        assert_eq!(ops.dumpable, 0);
        assert_eq!(ops.no_new_privileges, 1);
        assert_eq!(
            ops.calls,
            [
                "observe",
                "parent",
                "set-pdeathsig",
                "parent",
                "get-pdeathsig",
                "umask",
                "umask",
                "set-core",
                "get-core",
                "set-dumpable",
                "get-dumpable",
                "set-nnp",
                "get-nnp",
                "observe",
                "parent",
            ]
        );
    }

    #[test]
    fn thread_tracer_and_parent_drift_fail_closed() {
        let mut threaded = FakeOps::default();
        threaded.observation.thread_count = 2;
        assert!(matches!(
            harden_with_ops(&mut threaded),
            Err(StartupSecurityError::ThreadCountDenied)
        ));

        let mut traced = FakeOps::default();
        traced.observation.tracer_pid = 17;
        assert!(matches!(
            harden_with_ops(&mut traced),
            Err(StartupSecurityError::TracerDenied)
        ));

        let mut reparented = FakeOps {
            parent_after_set: 1,
            ..FakeOps::default()
        };
        assert!(matches!(
            harden_with_ops(&mut reparented),
            Err(StartupSecurityError::ParentChanged)
        ));
    }

    #[test]
    fn status_parser_is_closed_and_rejects_duplicates_or_type_drift() {
        assert_eq!(
            parse_process_observation("Name:\tt\nTracerPid:\t0\nThreads:\t1\n").unwrap(),
            ProcessObservation {
                thread_count: 1,
                tracer_pid: 0,
            }
        );
        for status in [
            "TracerPid:\t0\n",
            "Threads:\t1\n",
            "TracerPid:\t0\nTracerPid:\t0\nThreads:\t1\n",
            "TracerPid:\t-1\nThreads:\t1\n",
            "TracerPid:\t0\nThreads:\t1.0\n",
        ] {
            assert!(parse_process_observation(status).is_err());
        }
    }

    #[test]
    fn production_main_activates_hardening_before_final_inventory() {
        let source = include_str!("main.rs");
        let harden = source.find("harden_current_process()?;").unwrap();
        let final_capabilities = source.rfind("verify_current_capabilities()?;").unwrap();
        let clear = source.find("clear_startup_environment();").unwrap();
        let final_inventory = source
            .rfind("validate_inherited_fd_inventory(listener_fd)?;")
            .unwrap();
        assert!(
            harden < final_capabilities && final_capabilities < clear && clear < final_inventory
        );
    }
}
