//! Source-disabled Linux syscall adapter for replay-sync publisher custody.
//!
//! The concrete kernel backend remains source-only and is never constructed by
//! a broker route. This adapter fixes the required Linux ceremony
//! (`clone3(CLONE_PIDFD)`, stopped same-FD `execveat`, ptrace exec-stop, stable
//! `/proc` starttime and pidfd resume/kill/reap).

use super::replay_sync_publisher_custody::{
    MeasuredPublisherExecutable, ReplaySyncPublisherLaunchError, ReplaySyncPublisherLaunchOps,
    ReplaySyncPublisherLaunchSpec, VerifiedPublisherExec,
};
use trillionnium_os_types::capability_lease_root_publication::{
    CapabilityLeaseRootTaskPublicationAckV1, CapabilityLeaseRootTaskPublicationV1,
};

pub(crate) const SOURCE_STATUS: &str =
    "source_only_linux_syscall_adapter_concrete_backend_unwired_no_route_v2";

pub(crate) trait LinuxReplaySyncPublisherKernel {
    type Child;

    fn open_measure_readonly_elf_same_fd(
        &mut self,
        spec: &ReplaySyncPublisherLaunchSpec,
    ) -> Result<MeasuredPublisherExecutable, ReplaySyncPublisherLaunchError>;

    fn clone3_pidfd_stopped_execveat(
        &mut self,
        spec: &ReplaySyncPublisherLaunchSpec,
        executable: &MeasuredPublisherExecutable,
        exact_request_frame: &[u8],
    ) -> Result<Self::Child, ReplaySyncPublisherLaunchError>;

    fn observe_ptrace_exec_stop(
        &mut self,
        child: &mut Self::Child,
    ) -> Result<VerifiedPublisherExec, ReplaySyncPublisherLaunchError>;

    fn pidfd_resume(
        &mut self,
        child: &mut Self::Child,
    ) -> Result<(), ReplaySyncPublisherLaunchError>;

    fn collect_exact_ack_and_reap(
        &mut self,
        child: Self::Child,
        publication: &CapabilityLeaseRootTaskPublicationV1,
    ) -> Result<CapabilityLeaseRootTaskPublicationAckV1, ReplaySyncPublisherLaunchError>;

    fn pidfd_kill_and_reap(
        &mut self,
        child: Self::Child,
    ) -> Result<(), ReplaySyncPublisherLaunchError>;
}

pub(crate) struct LinuxReplaySyncPublisherLaunchOps<K> {
    kernel: K,
}

impl<K> LinuxReplaySyncPublisherLaunchOps<K> {
    pub(crate) fn source_disabled(kernel: K) -> Self {
        Self { kernel }
    }
}

impl<K: LinuxReplaySyncPublisherKernel> ReplaySyncPublisherLaunchOps
    for LinuxReplaySyncPublisherLaunchOps<K>
{
    type Child = K::Child;

    fn measure_exact_executable(
        &mut self,
        spec: &ReplaySyncPublisherLaunchSpec,
    ) -> Result<MeasuredPublisherExecutable, ReplaySyncPublisherLaunchError> {
        self.kernel.open_measure_readonly_elf_same_fd(spec)
    }

    fn spawn_stopped(
        &mut self,
        spec: &ReplaySyncPublisherLaunchSpec,
        executable: &MeasuredPublisherExecutable,
    ) -> Result<Self::Child, ReplaySyncPublisherLaunchError> {
        if spec.request_frame.is_empty() {
            return Err(ReplaySyncPublisherLaunchError::PublicationDenied);
        }
        self.kernel
            .clone3_pidfd_stopped_execveat(spec, executable, &spec.request_frame)
    }

    fn verify_post_exec(
        &mut self,
        child: &mut Self::Child,
    ) -> Result<VerifiedPublisherExec, ReplaySyncPublisherLaunchError> {
        self.kernel.observe_ptrace_exec_stop(child)
    }

    fn resume(&mut self, child: &mut Self::Child) -> Result<(), ReplaySyncPublisherLaunchError> {
        self.kernel.pidfd_resume(child)
    }

    fn collect_exact_ack_and_reap(
        &mut self,
        child: Self::Child,
        publication: &CapabilityLeaseRootTaskPublicationV1,
    ) -> Result<CapabilityLeaseRootTaskPublicationAckV1, ReplaySyncPublisherLaunchError> {
        self.kernel.collect_exact_ack_and_reap(child, publication)
    }

    fn kill_and_reap(&mut self, child: Self::Child) -> Result<(), ReplaySyncPublisherLaunchError> {
        self.kernel.pidfd_kill_and_reap(child)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Kernel {
        request_sha256: Option<String>,
        calls: Vec<&'static str>,
    }

    impl LinuxReplaySyncPublisherKernel for Kernel {
        type Child = u32;

        fn open_measure_readonly_elf_same_fd(
            &mut self,
            spec: &ReplaySyncPublisherLaunchSpec,
        ) -> Result<MeasuredPublisherExecutable, ReplaySyncPublisherLaunchError> {
            self.calls.push("open_measure");
            Ok(MeasuredPublisherExecutable {
                executable_identity: spec.executable_identity.clone(),
                executable_sha256: spec.expected_executable_sha256.clone(),
                same_fd_for_execveat: true,
                read_only_mount: true,
                regular_single_link: true,
                elf_image: true,
            })
        }

        fn clone3_pidfd_stopped_execveat(
            &mut self,
            _: &ReplaySyncPublisherLaunchSpec,
            _: &MeasuredPublisherExecutable,
            exact_request_frame: &[u8],
        ) -> Result<Self::Child, ReplaySyncPublisherLaunchError> {
            self.calls.push("clone3_execveat");
            self.request_sha256 = Some(trillionnium_os_types::sha256_bytes(exact_request_frame));
            Ok(41)
        }

        fn observe_ptrace_exec_stop(
            &mut self,
            _: &mut Self::Child,
        ) -> Result<VerifiedPublisherExec, ReplaySyncPublisherLaunchError> {
            self.calls.push("exec_stop");
            Err(ReplaySyncPublisherLaunchError::PostExecDenied)
        }

        fn pidfd_resume(
            &mut self,
            _: &mut Self::Child,
        ) -> Result<(), ReplaySyncPublisherLaunchError> {
            self.calls.push("resume");
            Ok(())
        }

        fn collect_exact_ack_and_reap(
            &mut self,
            _: Self::Child,
            publication: &CapabilityLeaseRootTaskPublicationV1,
        ) -> Result<CapabilityLeaseRootTaskPublicationAckV1, ReplaySyncPublisherLaunchError>
        {
            self.calls.push("collect_ack_reap");
            CapabilityLeaseRootTaskPublicationAckV1::derive(publication, "f".repeat(64))
                .map_err(|_| ReplaySyncPublisherLaunchError::ResultDenied)
        }

        fn pidfd_kill_and_reap(
            &mut self,
            _: Self::Child,
        ) -> Result<(), ReplaySyncPublisherLaunchError> {
            self.calls.push("kill_reap");
            Ok(())
        }
    }

    #[test]
    fn adapter_binds_exact_publication_frame_before_kernel_clone() {
        use trillionnium_os_types::agent_descriptor_registry::CODEX;
        use trillionnium_os_types::capability_lease_root_publication::{
            CapabilityLeaseRootPublisherTransportPeerV1, CapabilityLeaseRootTaskPublicationV1,
        };
        use trillionnium_os_types::capability_lease_root_publisher_launch as launch;
        use trillionnium_os_types::capability_lease_root_registration::{
            CapabilityLeaseRootPublisherEvidenceV1, CapabilityLeaseRootTaskContextV1,
            CapabilityLeaseRootTaskRegistrationV1,
        };

        let registration = CapabilityLeaseRootTaskRegistrationV1::derive(
            CODEX.provider_id.to_string(),
            CODEX.agent_id.to_string(),
            CODEX.replay_namespace.to_string(),
            CapabilityLeaseRootPublisherEvidenceV1 {
                boot_id_sha256: "1".repeat(64),
                publisher_epoch: "8".repeat(32),
                publisher_sequence: 1,
                root_journal_genesis_sha256: "2".repeat(64),
                epoch_proof_sha256: "3".repeat(64),
            },
            CapabilityLeaseRootTaskContextV1 {
                opaque_task_context_token: format!("task-context-{}", "4".repeat(64)),
                prepare_request_id: "prepare-token-registry".to_string(),
                prepare_canonical_request_sha256: "5".repeat(64),
                workflow_id: format!("req-{}", "6".repeat(32)),
                task_id: "task.token-registry".to_string(),
                authenticated_task_binding_sha256: "7".repeat(64),
            },
            "8".repeat(64),
        )
        .unwrap();
        let publication = CapabilityLeaseRootTaskPublicationV1::derive(
            CapabilityLeaseRootPublisherTransportPeerV1 {
                role: launch::PUBLISHER_ROLE.to_string(),
                uid: CODEX.uid,
                gid: CODEX.gid,
                selinux_domain: launch::PUBLISHER_SELINUX_DOMAIN.to_string(),
                executable_identity: launch::PUBLISHER_EXECUTABLE_IDENTITY.to_string(),
                executable_sha256: "9".repeat(64),
            },
            registration,
            "a".repeat(64),
            "b".repeat(64),
        )
        .unwrap();
        let spec = ReplaySyncPublisherLaunchSpec::derive(&publication).unwrap();
        let expected = trillionnium_os_types::sha256_bytes(&spec.request_frame);
        let kernel = Kernel::default();
        let mut ops = LinuxReplaySyncPublisherLaunchOps::source_disabled(kernel);
        let executable = ops.measure_exact_executable(&spec).unwrap();
        assert_eq!(ops.spawn_stopped(&spec, &executable).unwrap(), 41);
        assert_eq!(
            ops.kernel.request_sha256.as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(ops.kernel.calls, ["open_measure", "clone3_execveat"]);
    }
}
