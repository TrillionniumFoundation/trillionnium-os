//! Inert legacy childless-provider pidfd-atomic measured-exec custody contract.
//!
//! This module is compiled for review and tests, but no production entrypoint
//! implements [`AtomicMeasuredExecOps`] or constructs
//! [`VerifiedExecutablePolicy`].  It therefore cannot spawn a process.  The
//! Its `ProviderLeafAbortRequest` and fixed-leaf identity refer to the old
//! provider-parent-as-leaf layout. It cannot mint or satisfy canonical
//! provider-cgroup-topology-v2 evidence. The type-state ordering closes only
//! that legacy source contract for a future migration seam:
//! the exact executable FD is measured first, the child is created already
//! stopped in the fixed leaf with a pidfd returned by the same kernel clone
//! operation, `/proc` starttime and leaf identity are sampled while exec is
//! blocked, and a ptrace exec-stop is re-observed through that same pidfd
//! before the child is resumed.  Any ambiguity must kill and reap the child;
//! there is no numeric-PID, path re-open, or unmeasured spawn fallback.

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_privilege_broker_protocol::{
    Digest, FixedBytes32, Provider, ProviderLeafAbortRequest,
};

/// No live broker route may use this source-only controller.
pub(crate) const PIDFD_ATOMIC_MEASURED_EXEC_FOUNDATION_ENABLED: bool = false;
/// The controller retains only one legacy provider-parent leaf and therefore
/// cannot prove the v2 parent plus three exact child leaves.
pub(crate) const PIDFD_ATOMIC_MEASURED_EXEC_TOPOLOGY_V2_PROOF_AVAILABLE: bool = false;

/// Sealed executable and fixed-leaf policy.  A future constructor must consume
/// the generated AgentDescriptor plus the authenticated fixed-FD inventory;
/// accepting a digest or leaf identity from the broker wire is forbidden.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedExecutablePolicy {
    provider: Provider,
    expected_executable_sha256: Digest,
    expected_executable_fd_identity_sha256: Digest,
    fixed_leaf_fd_identity_sha256: Digest,
}

impl VerifiedExecutablePolicy {
    #[cfg(test)]
    pub(crate) const fn for_test(
        provider: Provider,
        expected_executable_sha256: Digest,
        expected_executable_fd_identity_sha256: Digest,
        fixed_leaf_fd_identity_sha256: Digest,
    ) -> Self {
        Self {
            provider,
            expected_executable_sha256,
            expected_executable_fd_identity_sha256,
            fixed_leaf_fd_identity_sha256,
        }
    }
}

/// Observation of the already-open FD that will be passed to
/// `execveat(AT_EMPTY_PATH)`.  The backend must hash and stat this same open
/// file description, not resolve the executable path twice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExactExecutableObservation {
    pub executable_sha256: Digest,
    pub executable_fd_identity_sha256: Digest,
    pub read_only_mount: bool,
    pub regular_single_link: bool,
    pub elf_image: bool,
}

/// Pre-exec observation taken while the new task is kernel-stopped and cannot
/// execute userspace instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PidfdPreExecObservation {
    pub tgid: u32,
    pub starttime_ticks: u64,
    pub pidfd_identity_sha256: Digest,
    pub fixed_leaf_fd_identity_sha256: Digest,
    pub executable_fd_identity_sha256: Digest,
    pub pidfd_returned_by_clone: bool,
    pub clone_into_fixed_leaf: bool,
    pub child_exec_blocked: bool,
    pub pidfd_not_exited: bool,
}

/// Observation at a kernel-reported ptrace exec event.  The task remains
/// stopped until [`AtomicMeasuredExecOps::resume_from_verified_exec`] succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PidfdExecStopObservation {
    pub tgid: u32,
    pub starttime_ticks: u64,
    pub pidfd_identity_sha256: Digest,
    pub fixed_leaf_fd_identity_sha256: Digest,
    pub proc_exe_fd_identity_sha256: Digest,
    pub proc_exe_sha256: Digest,
    pub ptrace_exec_event: bool,
    pub task_stopped: bool,
    pub pidfd_not_exited: bool,
    pub exec_event_identity_sha256: Digest,
}

/// Injectable seam for the future fixed Linux implementation.  `Child` is an
/// opaque owner of the clone-returned pidfd, trace stop and pre-exec barrier.
/// Neither observations nor the child handle cross the broker protocol.
pub(crate) trait AtomicMeasuredExecOps {
    type Child;

    fn measure_exact_executable(
        &mut self,
        policy: &VerifiedExecutablePolicy,
    ) -> Result<ExactExecutableObservation, MeasuredExecError>;
    fn clone_stopped_with_pidfd_into_fixed_leaf(
        &mut self,
        policy: &VerifiedExecutablePolicy,
        executable: &ExactExecutableObservation,
    ) -> Result<Self::Child, MeasuredExecError>;
    fn observe_pre_exec(
        &mut self,
        child: &Self::Child,
    ) -> Result<PidfdPreExecObservation, MeasuredExecError>;
    fn continue_to_ptrace_exec_stop(
        &mut self,
        child: &mut Self::Child,
    ) -> Result<(), MeasuredExecError>;
    fn observe_exec_stop(
        &mut self,
        child: &Self::Child,
    ) -> Result<PidfdExecStopObservation, MeasuredExecError>;
    fn resume_from_verified_exec(
        &mut self,
        child: &mut Self::Child,
    ) -> Result<(), MeasuredExecError>;
    fn kill_and_reap_fail_closed(&mut self, child: Self::Child) -> Result<(), MeasuredExecError>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum MeasuredExecError {
    #[error("exact executable measurement is unavailable or ambiguous")]
    ExecutableAmbiguous,
    #[error("clone/pidfd/fixed-leaf placement is unavailable or ambiguous")]
    CloneAmbiguous,
    #[error("pre-exec pidfd, starttime, or leaf identity is ambiguous")]
    PreExecAmbiguous,
    #[error("ptrace exec event or post-exec identity is ambiguous")]
    ExecStopAmbiguous,
    #[error("verified exec could not be resumed")]
    ResumeAmbiguous,
    #[error("fail-closed child cleanup could not be proved")]
    CleanupAmbiguous,
    #[error("measured-exec proof digest could not be constructed")]
    DigestConstructionFailed,
}

/// Opaque evidence enclosed by the non-Copy authority consumed by the
/// lifecycle `SpawnPrepared -> Running` transition. Fields are private, the
/// type is not deserializable, and its sole producer is the fixed controller
/// below.
#[derive(Debug, Eq, PartialEq)]
struct PidfdAtomicMeasuredExecProof {
    request: ProviderLeafAbortRequest,
    tgid: u32,
    starttime_ticks: u64,
    pidfd_identity_sha256: Digest,
    fixed_leaf_fd_identity_sha256: Digest,
    executable_fd_identity_sha256: Digest,
    executable_sha256: Digest,
    exec_event_identity_sha256: Digest,
    proof_sha256: Digest,
}

/// Retains the backend's clone-returned pidfd ownership after resume. A future
/// legacy orchestrator must move this value directly into legacy childless
/// provider-leaf custody and keep it for the entire
/// running/collection/drain lifecycle. It cannot enter the topology-v2 route.
/// The proof is deliberately not exposed as a separately transferable
/// authority.
#[must_use = "legacy running pidfd custody must be moved into legacy childless provider-leaf custody or cleaned up"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RunningPidfdAtomicMeasuredExec<Child> {
    proof: PidfdAtomicMeasuredExecProof,
    child: Child,
}

impl<Child> RunningPidfdAtomicMeasuredExec<Child> {
    pub(crate) const fn request(&self) -> ProviderLeafAbortRequest {
        self.proof.request()
    }

    pub(crate) const fn proof_sha256(&self) -> Digest {
        self.proof.proof_sha256()
    }

    pub(crate) fn validate_for(&self, request: ProviderLeafAbortRequest) -> bool {
        self.proof.validate_for(request)
    }

    #[cfg(test)]
    pub(crate) fn for_test(request: ProviderLeafAbortRequest, seed: u8, child: Child) -> Self {
        Self {
            proof: PidfdAtomicMeasuredExecProof::for_test(request, seed),
            child,
        }
    }

    #[cfg(test)]
    fn into_parts(self) -> (PidfdAtomicMeasuredExecProof, Child) {
        (self.proof, self.child)
    }
}

impl PidfdAtomicMeasuredExecProof {
    const fn request(&self) -> ProviderLeafAbortRequest {
        self.request
    }

    const fn proof_sha256(&self) -> Digest {
        self.proof_sha256
    }

    fn validate_for(&self, request: ProviderLeafAbortRequest) -> bool {
        self.request == request
            && self.tgid > 1
            && self.starttime_ticks != 0
            && derive_proof_digest(
                self.request,
                self.tgid,
                self.starttime_ticks,
                self.pidfd_identity_sha256,
                self.fixed_leaf_fd_identity_sha256,
                self.executable_fd_identity_sha256,
                self.executable_sha256,
                self.exec_event_identity_sha256,
            )
            .is_ok_and(|expected| expected == self.proof_sha256)
    }

    #[cfg(test)]
    fn for_test(request: ProviderLeafAbortRequest, seed: u8) -> Self {
        let digest = |offset: u8| {
            Digest::new(FixedBytes32::new([seed.wrapping_add(offset).max(1); 32]).unwrap())
        };
        let tgid = u32::from(seed).saturating_add(100);
        let starttime_ticks = u64::from(seed).saturating_add(1_000);
        let mut proof = Self {
            request,
            tgid,
            starttime_ticks,
            pidfd_identity_sha256: digest(1),
            fixed_leaf_fd_identity_sha256: digest(2),
            executable_fd_identity_sha256: digest(3),
            executable_sha256: digest(4),
            exec_event_identity_sha256: digest(5),
            proof_sha256: digest(6),
        };
        proof.proof_sha256 = derive_proof_digest(
            proof.request,
            proof.tgid,
            proof.starttime_ticks,
            proof.pidfd_identity_sha256,
            proof.fixed_leaf_fd_identity_sha256,
            proof.executable_fd_identity_sha256,
            proof.executable_sha256,
            proof.exec_event_identity_sha256,
        )
        .unwrap();
        proof
    }
}

/// Execute the closed measured-exec ceremony. Running pidfd custody is returned
/// only after the exact exec-stop identity was validated and that same stopped
/// child was successfully resumed. Every post-clone error consumes the child
/// through mandatory kill-and-reap cleanup.
pub(crate) fn launch_pidfd_atomic_measured_exec<O: AtomicMeasuredExecOps>(
    request: ProviderLeafAbortRequest,
    policy: VerifiedExecutablePolicy,
    ops: &mut O,
) -> Result<RunningPidfdAtomicMeasuredExec<O::Child>, MeasuredExecError> {
    if request.provider != policy.provider {
        return Err(MeasuredExecError::PreExecAmbiguous);
    }
    let executable = ops.measure_exact_executable(&policy)?;
    if executable.executable_sha256 != policy.expected_executable_sha256
        || executable.executable_fd_identity_sha256 != policy.expected_executable_fd_identity_sha256
        || !executable.read_only_mount
        || !executable.regular_single_link
        || !executable.elf_image
    {
        return Err(MeasuredExecError::ExecutableAmbiguous);
    }

    let mut child = ops.clone_stopped_with_pidfd_into_fixed_leaf(&policy, &executable)?;
    let ceremony = (|| {
        let pre = ops.observe_pre_exec(&child)?;
        if pre.tgid <= 1
            || pre.starttime_ticks == 0
            || pre.fixed_leaf_fd_identity_sha256 != policy.fixed_leaf_fd_identity_sha256
            || pre.executable_fd_identity_sha256 != executable.executable_fd_identity_sha256
            || !pre.pidfd_returned_by_clone
            || !pre.clone_into_fixed_leaf
            || !pre.child_exec_blocked
            || !pre.pidfd_not_exited
        {
            return Err(MeasuredExecError::PreExecAmbiguous);
        }

        ops.continue_to_ptrace_exec_stop(&mut child)?;
        let post = ops.observe_exec_stop(&child)?;
        if post.tgid != pre.tgid
            || post.starttime_ticks != pre.starttime_ticks
            || post.pidfd_identity_sha256 != pre.pidfd_identity_sha256
            || post.fixed_leaf_fd_identity_sha256 != pre.fixed_leaf_fd_identity_sha256
            || post.proc_exe_fd_identity_sha256 != executable.executable_fd_identity_sha256
            || post.proc_exe_sha256 != executable.executable_sha256
            || !post.ptrace_exec_event
            || !post.task_stopped
            || !post.pidfd_not_exited
        {
            return Err(MeasuredExecError::ExecStopAmbiguous);
        }
        let proof_sha256 = derive_proof_digest(
            request,
            post.tgid,
            post.starttime_ticks,
            post.pidfd_identity_sha256,
            post.fixed_leaf_fd_identity_sha256,
            post.proc_exe_fd_identity_sha256,
            post.proc_exe_sha256,
            post.exec_event_identity_sha256,
        )?;
        let proof = PidfdAtomicMeasuredExecProof {
            request,
            tgid: post.tgid,
            starttime_ticks: post.starttime_ticks,
            pidfd_identity_sha256: post.pidfd_identity_sha256,
            fixed_leaf_fd_identity_sha256: post.fixed_leaf_fd_identity_sha256,
            executable_fd_identity_sha256: post.proc_exe_fd_identity_sha256,
            executable_sha256: post.proc_exe_sha256,
            exec_event_identity_sha256: post.exec_event_identity_sha256,
            proof_sha256,
        };
        if !proof.validate_for(request) {
            return Err(MeasuredExecError::DigestConstructionFailed);
        }
        ops.resume_from_verified_exec(&mut child)?;
        Ok(proof)
    })();

    match ceremony {
        Ok(proof) => Ok(RunningPidfdAtomicMeasuredExec { proof, child }),
        Err(error) => match ops.kill_and_reap_fail_closed(child) {
            Ok(()) => Err(error),
            Err(_) => Err(MeasuredExecError::CleanupAmbiguous),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_proof_digest(
    request: ProviderLeafAbortRequest,
    tgid: u32,
    starttime_ticks: u64,
    pidfd_identity_sha256: Digest,
    fixed_leaf_fd_identity_sha256: Digest,
    executable_fd_identity_sha256: Digest,
    executable_sha256: Digest,
    exec_event_identity_sha256: Digest,
) -> Result<Digest, MeasuredExecError> {
    let mut hasher = Sha256::new();
    hasher.update(b"org.trillionnium.pidfd-atomic-measured-exec-proof.v1\0");
    hasher.update([match request.provider {
        Provider::Codex => 1,
    }]);
    hasher.update(request.broker_leaf_generation.value().to_be_bytes());
    hasher.update(request.operation_id.value().as_bytes());
    hasher.update(request.reservation_id.value().as_bytes());
    hasher.update(request.lifecycle_digest.value().as_bytes());
    hasher.update(tgid.to_be_bytes());
    hasher.update(starttime_ticks.to_be_bytes());
    for digest in [
        pidfd_identity_sha256,
        fixed_leaf_fd_identity_sha256,
        executable_fd_identity_sha256,
        executable_sha256,
        exec_event_identity_sha256,
    ] {
        hasher.update(digest.value().as_bytes());
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    FixedBytes32::new(bytes)
        .map(Digest::new)
        .map_err(|_| MeasuredExecError::DigestConstructionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trillionnium_privilege_broker_protocol::{
        BrokerLeafGeneration, LifecycleOperationId, LifecycleReservationId,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        Measure,
        Clone,
        PreExec,
        Continue,
        ExecStop,
        Resume,
        Cleanup,
    }

    struct FakeOps {
        calls: Vec<Call>,
        pre: PidfdPreExecObservation,
        post: PidfdExecStopObservation,
        fail_resume: bool,
        fail_cleanup: bool,
    }

    impl AtomicMeasuredExecOps for FakeOps {
        type Child = ();

        fn measure_exact_executable(
            &mut self,
            policy: &VerifiedExecutablePolicy,
        ) -> Result<ExactExecutableObservation, MeasuredExecError> {
            self.calls.push(Call::Measure);
            Ok(ExactExecutableObservation {
                executable_sha256: policy.expected_executable_sha256,
                executable_fd_identity_sha256: policy.expected_executable_fd_identity_sha256,
                read_only_mount: true,
                regular_single_link: true,
                elf_image: true,
            })
        }

        fn clone_stopped_with_pidfd_into_fixed_leaf(
            &mut self,
            _policy: &VerifiedExecutablePolicy,
            _executable: &ExactExecutableObservation,
        ) -> Result<Self::Child, MeasuredExecError> {
            self.calls.push(Call::Clone);
            Ok(())
        }

        fn observe_pre_exec(
            &mut self,
            _child: &Self::Child,
        ) -> Result<PidfdPreExecObservation, MeasuredExecError> {
            self.calls.push(Call::PreExec);
            Ok(self.pre)
        }

        fn continue_to_ptrace_exec_stop(
            &mut self,
            _child: &mut Self::Child,
        ) -> Result<(), MeasuredExecError> {
            self.calls.push(Call::Continue);
            Ok(())
        }

        fn observe_exec_stop(
            &mut self,
            _child: &Self::Child,
        ) -> Result<PidfdExecStopObservation, MeasuredExecError> {
            self.calls.push(Call::ExecStop);
            Ok(self.post)
        }

        fn resume_from_verified_exec(
            &mut self,
            _child: &mut Self::Child,
        ) -> Result<(), MeasuredExecError> {
            self.calls.push(Call::Resume);
            if self.fail_resume {
                Err(MeasuredExecError::ResumeAmbiguous)
            } else {
                Ok(())
            }
        }

        fn kill_and_reap_fail_closed(
            &mut self,
            _child: Self::Child,
        ) -> Result<(), MeasuredExecError> {
            self.calls.push(Call::Cleanup);
            if self.fail_cleanup {
                Err(MeasuredExecError::CleanupAmbiguous)
            } else {
                Ok(())
            }
        }
    }

    fn digest(value: u8) -> Digest {
        Digest::new(FixedBytes32::new([value; 32]).unwrap())
    }

    fn request(provider: Provider) -> ProviderLeafAbortRequest {
        ProviderLeafAbortRequest {
            provider,
            broker_leaf_generation: BrokerLeafGeneration::new(7).unwrap(),
            operation_id: LifecycleOperationId::new(FixedBytes32::new([11; 32]).unwrap()),
            reservation_id: LifecycleReservationId::new(FixedBytes32::new([12; 32]).unwrap()),
            lifecycle_digest: digest(13),
        }
    }

    fn fixture() -> (VerifiedExecutablePolicy, FakeOps) {
        let policy =
            VerifiedExecutablePolicy::for_test(Provider::Codex, digest(20), digest(21), digest(22));
        let pre = PidfdPreExecObservation {
            tgid: 401,
            starttime_ticks: 9_001,
            pidfd_identity_sha256: digest(23),
            fixed_leaf_fd_identity_sha256: digest(22),
            executable_fd_identity_sha256: digest(21),
            pidfd_returned_by_clone: true,
            clone_into_fixed_leaf: true,
            child_exec_blocked: true,
            pidfd_not_exited: true,
        };
        let post = PidfdExecStopObservation {
            tgid: pre.tgid,
            starttime_ticks: pre.starttime_ticks,
            pidfd_identity_sha256: pre.pidfd_identity_sha256,
            fixed_leaf_fd_identity_sha256: pre.fixed_leaf_fd_identity_sha256,
            proc_exe_fd_identity_sha256: pre.executable_fd_identity_sha256,
            proc_exe_sha256: digest(20),
            ptrace_exec_event: true,
            task_stopped: true,
            pidfd_not_exited: true,
            exec_event_identity_sha256: digest(24),
        };
        (
            policy,
            FakeOps {
                calls: Vec::new(),
                pre,
                post,
                fail_resume: false,
                fail_cleanup: false,
            },
        )
    }

    #[test]
    fn proof_requires_exact_pidfd_starttime_leaf_and_exec_stop_order() {
        let (policy, mut ops) = fixture();
        let request = request(Provider::Codex);
        let running = launch_pidfd_atomic_measured_exec(request, policy, &mut ops).unwrap();
        let proof_sha256 = running.proof_sha256();
        assert!(running.validate_for(request));
        assert_eq!(
            ops.calls,
            vec![
                Call::Measure,
                Call::Clone,
                Call::PreExec,
                Call::Continue,
                Call::ExecStop,
                Call::Resume,
            ]
        );
        let (retained_proof, retained_child) = running.into_parts();
        assert_eq!(retained_proof.proof_sha256(), proof_sha256);
        assert_eq!(retained_child, ());
    }

    #[test]
    fn every_identity_drift_is_killed_and_never_returns_authority() {
        let (policy, base) = fixture();
        let mut variants = Vec::new();
        let mut drift = base.post;
        drift.tgid += 1;
        variants.push(drift);
        let mut drift = base.post;
        drift.starttime_ticks += 1;
        variants.push(drift);
        let mut drift = base.post;
        drift.pidfd_identity_sha256 = digest(31);
        variants.push(drift);
        let mut drift = base.post;
        drift.fixed_leaf_fd_identity_sha256 = digest(32);
        variants.push(drift);
        let mut drift = base.post;
        drift.proc_exe_fd_identity_sha256 = digest(33);
        variants.push(drift);
        let mut drift = base.post;
        drift.proc_exe_sha256 = digest(34);
        variants.push(drift);
        let mut drift = base.post;
        drift.ptrace_exec_event = false;
        variants.push(drift);
        let mut drift = base.post;
        drift.task_stopped = false;
        variants.push(drift);
        let mut drift = base.post;
        drift.pidfd_not_exited = false;
        variants.push(drift);

        for post in variants {
            let (_, mut ops) = fixture();
            ops.post = post;
            assert_eq!(
                launch_pidfd_atomic_measured_exec(request(Provider::Codex), policy, &mut ops),
                Err(MeasuredExecError::ExecStopAmbiguous)
            );
            assert_eq!(ops.calls.last(), Some(&Call::Cleanup));
            assert!(!ops.calls.contains(&Call::Resume));
        }
    }

    #[test]
    fn resume_or_cleanup_uncertainty_fails_closed() {
        let (policy, mut ops) = fixture();
        ops.fail_resume = true;
        assert_eq!(
            launch_pidfd_atomic_measured_exec(request(Provider::Codex), policy, &mut ops),
            Err(MeasuredExecError::ResumeAmbiguous)
        );
        assert_eq!(ops.calls.last(), Some(&Call::Cleanup));

        let (policy, mut ops) = fixture();
        ops.fail_resume = true;
        ops.fail_cleanup = true;
        assert_eq!(
            launch_pidfd_atomic_measured_exec(request(Provider::Codex), policy, &mut ops),
            Err(MeasuredExecError::CleanupAmbiguous)
        );
    }
}
