use thiserror::Error;
use trillionnium_os_types::agent_descriptor_registry;
use trillionnium_os_types::capability_lease_root_authenticator::{
    CapabilityLeaseRootPublisherAuthenticationV1, PublisherKernelIdentityV1,
};
use trillionnium_os_types::capability_lease_root_publication::{
    CapabilityLeaseRootTaskPublicationAckV1, CapabilityLeaseRootTaskPublicationV1,
};
use trillionnium_os_types::capability_lease_root_publisher_launch as launch;

pub(crate) const SOURCE_STATUS: &str =
    "source_only_linux_ops_seam_concrete_backend_unwired_no_broker_route_no_product_constructor_v2";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplaySyncPublisherLaunchSpec {
    pub(crate) provider_id: String,
    pub(crate) agent_id: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) executable_identity: String,
    pub(crate) expected_executable_sha256: String,
    pub(crate) publication_binding_sha256: String,
    publication: CapabilityLeaseRootTaskPublicationV1,
    pub(crate) request_frame: Vec<u8>,
}

impl ReplaySyncPublisherLaunchSpec {
    pub(crate) fn derive(
        publication: &CapabilityLeaseRootTaskPublicationV1,
    ) -> Result<Self, ReplaySyncPublisherLaunchError> {
        publication
            .validate()
            .map_err(|_| ReplaySyncPublisherLaunchError::PublicationDenied)?;
        let descriptor = agent_descriptor_registry::from_provider_agent_pair(
            &publication.registration.provider_id,
            &publication.registration.agent_id,
        )
        .ok_or(ReplaySyncPublisherLaunchError::IdentityDenied)?;
        if publication.transport_peer.uid != descriptor.uid
            || publication.transport_peer.gid != descriptor.gid
            || publication.transport_peer.role != launch::PUBLISHER_ROLE
            || publication.transport_peer.selinux_domain != launch::PUBLISHER_SELINUX_DOMAIN
            || publication.transport_peer.executable_identity
                != launch::PUBLISHER_EXECUTABLE_IDENTITY
        {
            return Err(ReplaySyncPublisherLaunchError::IdentityDenied);
        }
        let request_frame = publication
            .encode_frame()
            .map_err(|_| ReplaySyncPublisherLaunchError::PublicationDenied)?;
        Ok(Self {
            provider_id: descriptor.provider_id.to_string(),
            agent_id: descriptor.agent_id.to_string(),
            uid: descriptor.uid,
            gid: descriptor.gid,
            executable_identity: launch::PUBLISHER_EXECUTABLE_IDENTITY.to_string(),
            expected_executable_sha256: publication.transport_peer.executable_sha256.clone(),
            publication_binding_sha256: publication.publication_binding_sha256.clone(),
            publication: publication.clone(),
            request_frame,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MeasuredPublisherExecutable {
    pub(crate) executable_identity: String,
    pub(crate) executable_sha256: String,
    pub(crate) same_fd_for_execveat: bool,
    pub(crate) read_only_mount: bool,
    pub(crate) regular_single_link: bool,
    pub(crate) elf_image: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPublisherExec {
    pub(crate) pid: u32,
    pub(crate) start_time_ticks: u64,
    pub(crate) pidfd_identity_sha256: String,
    pub(crate) pidfd_returned_by_clone3: bool,
    pub(crate) ptrace_exec_stop_observed: bool,
    pub(crate) post_exec_hardening_stop_observed: bool,
    pub(crate) start_time_stable_after_exec: bool,
    pub(crate) request_frame_bound_to_stdin: bool,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) selinux_domain: String,
    pub(crate) executable_sha256: String,
    pub(crate) stdin_pipe_only: bool,
    pub(crate) stdout_pipe_only: bool,
    pub(crate) stderr_closed: bool,
    pub(crate) other_fds_closed: bool,
    pub(crate) environment_empty: bool,
    pub(crate) arguments_empty: bool,
    pub(crate) pdeathsig_sigkill: bool,
    pub(crate) no_new_privs: bool,
    pub(crate) dumpable_disabled: bool,
    pub(crate) capabilities_empty: bool,
    pub(crate) descendants_forbidden: bool,
}

pub(crate) trait ReplaySyncPublisherLaunchOps {
    type Child;

    fn measure_exact_executable(
        &mut self,
        spec: &ReplaySyncPublisherLaunchSpec,
    ) -> Result<MeasuredPublisherExecutable, ReplaySyncPublisherLaunchError>;
    fn spawn_stopped(
        &mut self,
        spec: &ReplaySyncPublisherLaunchSpec,
        executable: &MeasuredPublisherExecutable,
    ) -> Result<Self::Child, ReplaySyncPublisherLaunchError>;
    fn verify_post_exec(
        &mut self,
        child: &mut Self::Child,
    ) -> Result<VerifiedPublisherExec, ReplaySyncPublisherLaunchError>;
    fn resume(&mut self, child: &mut Self::Child) -> Result<(), ReplaySyncPublisherLaunchError>;
    fn collect_exact_ack_and_reap(
        &mut self,
        child: Self::Child,
        publication: &CapabilityLeaseRootTaskPublicationV1,
    ) -> Result<CapabilityLeaseRootTaskPublicationAckV1, ReplaySyncPublisherLaunchError>;
    fn kill_and_reap(&mut self, child: Self::Child) -> Result<(), ReplaySyncPublisherLaunchError>;
}

pub(crate) trait ReplaySyncPublisherAuthenticationSink {
    fn deliver(
        &mut self,
        authentication: &CapabilityLeaseRootPublisherAuthenticationV1,
    ) -> Result<(), ReplaySyncPublisherLaunchError>;
}

#[must_use = "running replay-sync publisher custody must be retained or fail-closed cleaned"]
#[derive(Debug)]
pub(crate) struct RunningReplaySyncPublisher<Child> {
    spec: ReplaySyncPublisherLaunchSpec,
    authentication: CapabilityLeaseRootPublisherAuthenticationV1,
    child: Child,
}

impl<Child> RunningReplaySyncPublisher<Child> {
    pub(crate) fn publication_binding_sha256(&self) -> &str {
        &self.spec.publication_binding_sha256
    }

    pub(crate) fn authentication(&self) -> &CapabilityLeaseRootPublisherAuthenticationV1 {
        &self.authentication
    }

    #[cfg(test)]
    fn into_child(self) -> Child {
        self.child
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompletedReplaySyncPublisher {
    pub(crate) publication_binding_sha256: String,
    pub(crate) registration_binding_sha256: String,
    pub(crate) token_record_sha256: String,
    pub(crate) root_record_sha256: String,
    pub(crate) root_record_proof_sha256: String,
    pub(crate) ack_binding_sha256: String,
    pub(crate) authentication_binding_sha256: String,
}

pub(crate) fn complete_replay_sync_publisher<O: ReplaySyncPublisherLaunchOps>(
    running: RunningReplaySyncPublisher<O::Child>,
    ops: &mut O,
) -> Result<CompletedReplaySyncPublisher, ReplaySyncPublisherLaunchError> {
    let ack = ops.collect_exact_ack_and_reap(running.child, &running.spec.publication)?;
    ack.validate()
        .map_err(|_| ReplaySyncPublisherLaunchError::ResultDenied)?;
    if ack.publication_binding_sha256 != running.spec.publication.publication_binding_sha256
        || ack.registration_binding_sha256
            != running
                .spec
                .publication
                .registration
                .registration_binding_sha256
        || ack.publisher_epoch != running.spec.publication.registration.publisher_epoch
        || ack.publisher_sequence != running.spec.publication.registration.publisher_sequence
        || ack.root_record_sha256 != running.spec.publication.root_record_sha256
        || ack.root_record_proof_sha256 != running.spec.publication.root_record_proof_sha256
    {
        return Err(ReplaySyncPublisherLaunchError::ResultDenied);
    }
    Ok(CompletedReplaySyncPublisher {
        publication_binding_sha256: ack.publication_binding_sha256,
        registration_binding_sha256: ack.registration_binding_sha256,
        token_record_sha256: ack.token_record_sha256,
        root_record_sha256: ack.root_record_sha256,
        root_record_proof_sha256: ack.root_record_proof_sha256,
        ack_binding_sha256: ack.ack_binding_sha256,
        authentication_binding_sha256: running.authentication.authentication_binding_sha256,
    })
}

#[cfg(test)]
pub(crate) fn launch_replay_sync_publisher<O: ReplaySyncPublisherLaunchOps>(
    spec: ReplaySyncPublisherLaunchSpec,
    ops: &mut O,
) -> Result<RunningReplaySyncPublisher<O::Child>, ReplaySyncPublisherLaunchError> {
    struct TestOnlySink;

    impl ReplaySyncPublisherAuthenticationSink for TestOnlySink {
        fn deliver(
            &mut self,
            _: &CapabilityLeaseRootPublisherAuthenticationV1,
        ) -> Result<(), ReplaySyncPublisherLaunchError> {
            Ok(())
        }
    }

    launch_replay_sync_publisher_with_authentication_sink(spec, ops, &mut TestOnlySink)
}

pub(crate) fn launch_replay_sync_publisher_with_authentication_sink<
    O: ReplaySyncPublisherLaunchOps,
    S: ReplaySyncPublisherAuthenticationSink,
>(
    spec: ReplaySyncPublisherLaunchSpec,
    ops: &mut O,
    authentication_sink: &mut S,
) -> Result<RunningReplaySyncPublisher<O::Child>, ReplaySyncPublisherLaunchError> {
    let executable = ops.measure_exact_executable(&spec)?;
    if executable.executable_identity != spec.executable_identity
        || executable.executable_sha256 != spec.expected_executable_sha256
        || !executable.same_fd_for_execveat
        || !executable.read_only_mount
        || !executable.regular_single_link
        || !executable.elf_image
    {
        return Err(ReplaySyncPublisherLaunchError::MeasurementDenied);
    }
    let mut child = ops.spawn_stopped(&spec, &executable)?;
    let verified = match ops.verify_post_exec(&mut child) {
        Ok(verified) => verified,
        Err(error) => return cleanup(ops, child, error),
    };
    if !verified_matches(&spec, &verified) {
        return cleanup(ops, child, ReplaySyncPublisherLaunchError::PostExecDenied);
    }
    let authentication = match CapabilityLeaseRootPublisherAuthenticationV1::derive(
        &spec.publication,
        PublisherKernelIdentityV1 {
            pid: verified.pid,
            start_time_ticks: verified.start_time_ticks,
            uid: verified.uid,
            gid: verified.gid,
            selinux_domain: verified.selinux_domain.clone(),
            executable_identity: spec.executable_identity.clone(),
            executable_sha256: verified.executable_sha256.clone(),
            pidfd_identity_sha256: verified.pidfd_identity_sha256.clone(),
        },
    ) {
        Ok(authentication) => authentication,
        Err(_) => {
            return cleanup(
                ops,
                child,
                ReplaySyncPublisherLaunchError::AuthenticationDenied,
            );
        }
    };
    if let Err(error) = authentication_sink.deliver(&authentication) {
        return cleanup(ops, child, error);
    }
    if let Err(error) = ops.resume(&mut child) {
        return cleanup(ops, child, error);
    }
    Ok(RunningReplaySyncPublisher {
        spec,
        authentication,
        child,
    })
}

fn verified_matches(spec: &ReplaySyncPublisherLaunchSpec, value: &VerifiedPublisherExec) -> bool {
    value.pid > 0
        && value.start_time_ticks > 0
        && valid_digest(&value.pidfd_identity_sha256)
        && value.pidfd_returned_by_clone3
        && value.ptrace_exec_stop_observed
        && value.post_exec_hardening_stop_observed
        && value.start_time_stable_after_exec
        && value.request_frame_bound_to_stdin
        && !spec.request_frame.is_empty()
        && value.uid == spec.uid
        && value.gid == spec.gid
        && value.selinux_domain == launch::PUBLISHER_SELINUX_DOMAIN
        && value.executable_sha256 == spec.expected_executable_sha256
        && value.stdin_pipe_only
        && value.stdout_pipe_only
        && value.stderr_closed
        && value.other_fds_closed
        && value.environment_empty
        && value.arguments_empty
        && value.pdeathsig_sigkill
        && value.no_new_privs
        && value.dumpable_disabled
        && value.capabilities_empty
        && value.descendants_forbidden
}

fn cleanup<O: ReplaySyncPublisherLaunchOps, T>(
    ops: &mut O,
    child: O::Child,
    original: ReplaySyncPublisherLaunchError,
) -> Result<T, ReplaySyncPublisherLaunchError> {
    ops.kill_and_reap(child)
        .map_err(|_| ReplaySyncPublisherLaunchError::CleanupAmbiguous)?;
    Err(original)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ReplaySyncPublisherLaunchError {
    #[error("root publication is invalid")]
    PublicationDenied,
    #[error("replay-sync publisher identity is invalid")]
    IdentityDenied,
    #[error("replay-sync executable measurement is invalid")]
    MeasurementDenied,
    #[error("replay-sync child spawn failed")]
    SpawnFailed,
    #[error("replay-sync post-exec custody is invalid")]
    PostExecDenied,
    #[error("replay-sync publisher authentication could not be derived")]
    AuthenticationDenied,
    #[error("replay-sync publisher authentication delivery failed")]
    AuthenticationDeliveryDenied,
    #[error("replay-sync child resume failed")]
    ResumeFailed,
    #[error("replay-sync publisher result custody failed")]
    ResultDenied,
    #[error("replay-sync child cleanup is ambiguous")]
    CleanupAmbiguous,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !value.bytes().all(|byte| byte == b'0')
}

#[cfg(test)]
mod tests {
    use trillionnium_os_types::agent_descriptor_registry::CODEX;
    use trillionnium_os_types::capability_lease_root_publication::{
        CapabilityLeaseRootPublisherTransportPeerV1, CapabilityLeaseRootTaskPublicationV1,
    };
    use trillionnium_os_types::capability_lease_root_registration::{
        CapabilityLeaseRootPublisherEvidenceV1, CapabilityLeaseRootTaskContextV1,
        CapabilityLeaseRootTaskRegistrationV1,
    };

    use super::*;

    fn publication() -> CapabilityLeaseRootTaskPublicationV1 {
        let registration = CapabilityLeaseRootTaskRegistrationV1::derive(
            CODEX.provider_id.to_string(),
            CODEX.agent_id.to_string(),
            CODEX.replay_namespace.to_string(),
            CapabilityLeaseRootPublisherEvidenceV1 {
                boot_id_sha256: "1".repeat(64),
                publisher_epoch: "8".repeat(32),
                publisher_sequence: 10,
                root_journal_genesis_sha256: "a".repeat(64),
                epoch_proof_sha256: "b".repeat(64),
            },
            CapabilityLeaseRootTaskContextV1 {
                opaque_task_context_token: format!("task-context-{}", "2".repeat(64)),
                prepare_request_id: "prepare-token-registry".to_string(),
                prepare_canonical_request_sha256: "9".repeat(64),
                workflow_id: format!("req-{}", "4".repeat(32)),
                task_id: "task.token-registry".to_string(),
                authenticated_task_binding_sha256: "5".repeat(64),
            },
            "6".repeat(64),
        )
        .unwrap();
        CapabilityLeaseRootTaskPublicationV1::derive(
            CapabilityLeaseRootPublisherTransportPeerV1 {
                role: launch::PUBLISHER_ROLE.to_string(),
                uid: CODEX.uid,
                gid: CODEX.gid,
                selinux_domain: launch::PUBLISHER_SELINUX_DOMAIN.to_string(),
                executable_identity: launch::PUBLISHER_EXECUTABLE_IDENTITY.to_string(),
                executable_sha256: "c".repeat(64),
            },
            registration,
            "d".repeat(64),
            "e".repeat(64),
        )
        .unwrap()
    }

    struct FakeOps {
        drift_uid: bool,
        cleaned: bool,
        resumed: bool,
    }

    impl ReplaySyncPublisherLaunchOps for FakeOps {
        type Child = u32;

        fn measure_exact_executable(
            &mut self,
            spec: &ReplaySyncPublisherLaunchSpec,
        ) -> Result<MeasuredPublisherExecutable, ReplaySyncPublisherLaunchError> {
            Ok(MeasuredPublisherExecutable {
                executable_identity: spec.executable_identity.clone(),
                executable_sha256: spec.expected_executable_sha256.clone(),
                same_fd_for_execveat: true,
                read_only_mount: true,
                regular_single_link: true,
                elf_image: true,
            })
        }

        fn spawn_stopped(
            &mut self,
            _: &ReplaySyncPublisherLaunchSpec,
            _: &MeasuredPublisherExecutable,
        ) -> Result<Self::Child, ReplaySyncPublisherLaunchError> {
            Ok(42)
        }

        fn verify_post_exec(
            &mut self,
            _: &mut Self::Child,
        ) -> Result<VerifiedPublisherExec, ReplaySyncPublisherLaunchError> {
            Ok(VerifiedPublisherExec {
                pid: 42,
                start_time_ticks: 99,
                pidfd_identity_sha256: "f".repeat(64),
                pidfd_returned_by_clone3: true,
                ptrace_exec_stop_observed: true,
                post_exec_hardening_stop_observed: true,
                start_time_stable_after_exec: true,
                request_frame_bound_to_stdin: true,
                uid: if self.drift_uid {
                    CODEX.uid + 1
                } else {
                    CODEX.uid
                },
                gid: CODEX.gid,
                selinux_domain: launch::PUBLISHER_SELINUX_DOMAIN.to_string(),
                executable_sha256: "c".repeat(64),
                stdin_pipe_only: true,
                stdout_pipe_only: true,
                stderr_closed: true,
                other_fds_closed: true,
                environment_empty: true,
                arguments_empty: true,
                pdeathsig_sigkill: true,
                no_new_privs: true,
                dumpable_disabled: true,
                capabilities_empty: true,
                descendants_forbidden: true,
            })
        }

        fn resume(&mut self, _: &mut Self::Child) -> Result<(), ReplaySyncPublisherLaunchError> {
            self.resumed = true;
            Ok(())
        }

        fn collect_exact_ack_and_reap(
            &mut self,
            _: Self::Child,
            publication: &CapabilityLeaseRootTaskPublicationV1,
        ) -> Result<CapabilityLeaseRootTaskPublicationAckV1, ReplaySyncPublisherLaunchError>
        {
            CapabilityLeaseRootTaskPublicationAckV1::derive(publication, "7".repeat(64))
                .map_err(|_| ReplaySyncPublisherLaunchError::ResultDenied)
        }

        fn kill_and_reap(&mut self, _: Self::Child) -> Result<(), ReplaySyncPublisherLaunchError> {
            self.cleaned = true;
            Ok(())
        }
    }

    struct FakeSink {
        delivered: bool,
        deny: bool,
    }

    impl ReplaySyncPublisherAuthenticationSink for FakeSink {
        fn deliver(
            &mut self,
            _: &CapabilityLeaseRootPublisherAuthenticationV1,
        ) -> Result<(), ReplaySyncPublisherLaunchError> {
            self.delivered = true;
            if self.deny {
                Err(ReplaySyncPublisherLaunchError::AuthenticationDeliveryDenied)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn exact_measured_exec_yields_noncopy_running_custody() {
        let spec = ReplaySyncPublisherLaunchSpec::derive(&publication()).unwrap();
        let binding = spec.publication_binding_sha256.clone();
        let mut ops = FakeOps {
            drift_uid: false,
            cleaned: false,
            resumed: false,
        };
        let running = launch_replay_sync_publisher(spec, &mut ops).unwrap();
        assert_eq!(running.publication_binding_sha256(), binding);
        assert_eq!(running.authentication().publisher_pid, 42);
        assert_eq!(running.into_child(), 42);
        assert!(!ops.cleaned);
    }

    #[test]
    fn exact_ack_completion_returns_commitments_only() {
        let spec = ReplaySyncPublisherLaunchSpec::derive(&publication()).unwrap();
        let mut ops = FakeOps {
            drift_uid: false,
            cleaned: false,
            resumed: false,
        };
        let running = launch_replay_sync_publisher(spec, &mut ops).unwrap();
        let completed = complete_replay_sync_publisher(running, &mut ops).unwrap();
        assert_eq!(completed.token_record_sha256, "7".repeat(64));
        assert_eq!(completed.publication_binding_sha256.len(), 64);
        assert_eq!(completed.authentication_binding_sha256.len(), 64);
        assert!(ops.resumed);
        assert!(!ops.cleaned);
    }

    #[test]
    fn post_exec_identity_drift_is_killed_and_reaped() {
        let spec = ReplaySyncPublisherLaunchSpec::derive(&publication()).unwrap();
        let mut ops = FakeOps {
            drift_uid: true,
            cleaned: false,
            resumed: false,
        };
        assert_eq!(
            launch_replay_sync_publisher(spec, &mut ops).unwrap_err(),
            ReplaySyncPublisherLaunchError::PostExecDenied
        );
        assert!(ops.cleaned);
    }

    #[test]
    fn authentication_is_delivered_before_resume_and_failure_reaps() {
        let spec = ReplaySyncPublisherLaunchSpec::derive(&publication()).unwrap();
        let mut ops = FakeOps {
            drift_uid: false,
            cleaned: false,
            resumed: false,
        };
        let mut sink = FakeSink {
            delivered: false,
            deny: true,
        };
        assert_eq!(
            launch_replay_sync_publisher_with_authentication_sink(spec, &mut ops, &mut sink)
                .unwrap_err(),
            ReplaySyncPublisherLaunchError::AuthenticationDeliveryDenied
        );
        assert!(sink.delivered);
        assert!(!ops.resumed);
        assert!(ops.cleaned);
    }
}
