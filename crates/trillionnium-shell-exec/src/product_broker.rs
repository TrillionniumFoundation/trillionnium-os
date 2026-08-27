//! Android root broker for the product shell-exec lane.
//!
//! Startup is fail closed: it retains the measured Root Linux and worker ELF
//! descriptors, creates and measures the fixed cgroup-v2 profile, execs the
//! worker through its descriptor, authenticates the worker's pre/post-drop
//! frames, and only then binds the public abstract socket. The public listener
//! never exists in the worker process.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use thiserror::Error;
use trillionnium_os_types::direct_effect::{
    DirectEffectPhaseV1, DirectEffectRequestV1, DirectEffectWorkingDirectoryScopeV1,
};

use crate::authorization::{
    ShellExecAuthorizationRegistryV1, ShellExecHostControlV1, ShellExecRequestAdmissionV1,
};
use crate::mcp_adapter::{
    ProductSeqpacketListenerV1, ShellExecPeerRoleV1, ShellExecSeqpacketV1,
    ShellExecTransportResponseV1,
};
use crate::product_ipc::{
    AuthenticatedFrameV1, BrokerWorkerFrameV1, FixedWorkerCgroupPolicyV1,
    FixedWorkerIsolationPolicyV1, StandardExecutablePolicyV1, WORKER_BOOTSTRAP_SCHEMA,
    WORKER_CANCEL_SCHEMA, WORKER_COMPLETION_SCHEMA, WORKER_CONTROL_FD, WORKER_DEV_NULL_FD,
    WORKER_GO_SCHEMA, WORKER_IMAGE_FD, WORKER_PROTOCOL, WORKER_ROOTFS_FD, WorkerBootstrapV1,
    WorkerBrokerFrameV1, WorkerCancelV1, WorkerCompletionFrameV1, WorkerGoV1, WorkerHelloV1,
    WorkerIpcError, WorkerReadyV1, descriptor_custody_sha256, dev_null_custody_sha256,
    domain_digest, effect_dispatch_binding_sha256, effect_tmpdir_name, receive_frame, send_frame,
    seqpacket_pair, sha256_regular_descriptor,
};
use crate::product_paths::{RequiredFileTypeV1, RetainedPathError, open_beneath_component_walk};
use crate::{
    ANDROID_BROKER_PATH, ANDROID_LEDGER_ROOT, ANDROID_WORKER_CGROUP, ANDROID_WORKER_PATH,
    CancellationTokenV1, DurableShellExecLedgerV1, ROOT_LINUX_EXECUTABLE_POLICY,
    ROOT_LINUX_HOST_ROOT, ROOT_LINUX_TEMPORARY_PARENT, ROOT_LINUX_WORKSPACE_PARENT,
    SHELL_BROKER_SELINUX_DOMAIN, SHELL_WORKER_GID, SHELL_WORKER_SELINUX_DOMAIN, SHELL_WORKER_UID,
    ShellExecBrokerCoreV1, ShellExecError, ShellExecWorkerV1, StableLedgerRecoveryV1,
    WorkerCompletionV1, WorkerPreflightErrorV1, current_boot_id_sha256,
};

const ANDROID_SYSTEM_UID: u32 = 1000;
const ANDROID_SYSTEM_GID: u32 = 1000;
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const MAX_WORKER_ELF_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PROC_RECORD_BYTES: u64 = 16 * 1024;
const WORKER_CGROUP_PARENT: &str = "/sys/fs/cgroup/system";
const WORKER_CGROUP_LEAF: &str = "trillionnium_shell_exec_worker";
const WORKER_CGROUP_RELATIVE: &str = "/system/trillionnium_shell_exec_worker";
const BROKER_CAP_CHOWN: u64 = 1 << 0;
const BROKER_CAP_DAC_OVERRIDE: u64 = 1 << 1;
const BROKER_CAP_DAC_READ_SEARCH: u64 = 1 << 2;
const BROKER_CAP_KILL: u64 = 1 << 5;
const BROKER_CAP_SETGID: u64 = 1 << 6;
const BROKER_CAP_SETUID: u64 = 1 << 7;
const BROKER_CAP_SYS_CHROOT: u64 = 1 << 18;
const BROKER_EFFECTIVE_CAPABILITIES: u64 = BROKER_CAP_CHOWN
    | BROKER_CAP_KILL
    | BROKER_CAP_SETGID
    | BROKER_CAP_SETUID
    | BROKER_CAP_SYS_CHROOT;

#[derive(Debug, Error)]
pub enum ProductBrokerError {
    #[error("broker rejected an unauthenticated or invalid peer operation: {0}")]
    PeerRejected(&'static str),
    #[error("peer disconnected after the durable result was committed")]
    PeerGoneAfterCommit,
    #[error("broker policy rejected the request: {0}")]
    PolicyRejected(&'static str),
    #[error("broker startup or protocol failed: {0}")]
    Denied(&'static str),
    #[error("broker I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("broker worker IPC failed: {0}")]
    Ipc(#[from] WorkerIpcError),
    #[error("broker retained-path custody failed: {0}")]
    RetainedPath(#[from] RetainedPathError),
    #[error("broker durable ledger failed: {0}")]
    Durable(#[from] crate::durable::DurableError),
    #[error("broker authorization failed: {0}")]
    Authorization(#[from] crate::authorization::AuthorizationError),
    #[error("broker direct transport failed: {0}")]
    Direct(#[from] trillionnium_agent_direct_tools::DirectToolError),
    #[error("broker Android property publication failed: {0}")]
    Property(#[from] crate::android_property::AndroidPropertyError),
    #[error("broker durable receipt failed: {0}")]
    Receipt(#[from] crate::ReceiptError),
    #[error("broker execution recovery failed: {0}")]
    Execution(#[from] ShellExecError),
}

type Result<T> = std::result::Result<T, ProductBrokerError>;

fn peer_authorization_error(error: crate::authorization::AuthorizationError) -> ProductBrokerError {
    if matches!(&error, crate::authorization::AuthorizationError::Entropy(_)) {
        ProductBrokerError::Authorization(error)
    } else {
        ProductBrokerError::PeerRejected("authorization_invalid")
    }
}

fn registration_capacity_error(error: crate::durable::DurableError) -> ProductBrokerError {
    match error {
        crate::durable::DurableError::CapacityExhausted => {
            ProductBrokerError::PeerRejected("durable_registration_capacity_exhausted")
        }
        fatal => ProductBrokerError::Durable(fatal),
    }
}

fn require_shared_durable_capacity_device(ledger_device: u64, receipt_device: u64) -> Result<()> {
    if ledger_device != receipt_device {
        return Err(ProductBrokerError::Denied(
            "durable_capacity_roots_device_mismatch",
        ));
    }
    Ok(())
}

fn verify_shared_durable_capacity_device(
    ledger: &DurableShellExecLedgerV1,
    receipts: &crate::DurableShellExecReceiptStoreV1,
) -> Result<()> {
    require_shared_durable_capacity_device(
        ledger.retained_root_device()?,
        receipts.retained_root_device()?,
    )
}

fn classify_cwd_path_error(error: RetainedPathError) -> ProductBrokerError {
    match error {
        RetainedPathError::InvalidRelativePath
        | RetainedPathError::DeviceBoundary
        | RetainedPathError::WrongFileType => {
            ProductBrokerError::PolicyRejected("cwd_preflight_open_failed")
        }
        RetainedPathError::Io(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOENT) | Some(libc::ENOTDIR) | Some(libc::ELOOP)
            ) =>
        {
            ProductBrokerError::PolicyRejected("cwd_preflight_open_failed")
        }
        fatal => ProductBrokerError::RetainedPath(fatal),
    }
}

struct BrokerSignalsV1 {
    descriptor: OwnedFd,
}

impl BrokerSignalsV1 {
    fn install() -> Result<Self> {
        // SAFETY: zero is a valid initial sigset_t representation.
        let mut mask: libc::sigset_t = unsafe { zeroed() };
        // SAFETY: mask is writable and the three signals are valid.
        if unsafe { libc::sigemptyset(&mut mask) } != 0
            || unsafe { libc::sigaddset(&mut mask, libc::SIGTERM) } != 0
            || unsafe { libc::sigaddset(&mut mask, libc::SIGINT) } != 0
            || unsafe { libc::sigaddset(&mut mask, libc::SIGHUP) } != 0
            // SAFETY: broker is single-threaded here, before any watcher.
            || unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: mask remains live; flags request a private CLOEXEC descriptor.
        let descriptor =
            unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: signalfd returned a fresh descriptor.
        Ok(Self {
            descriptor: unsafe { OwnedFd::from_raw_fd(descriptor) },
        })
    }

    fn consume(&self) -> Result<()> {
        // SAFETY: zero is valid and read initializes a full signalfd record.
        let mut information: libc::signalfd_siginfo = unsafe { zeroed() };
        // SAFETY: information is writable for its exact size.
        let count = unsafe {
            libc::read(
                self.descriptor.as_raw_fd(),
                std::ptr::from_mut(&mut information).cast(),
                size_of::<libc::signalfd_siginfo>(),
            )
        };
        if count as usize != size_of::<libc::signalfd_siginfo>()
            || !matches!(
                information.ssi_signo as libc::c_int,
                libc::SIGTERM | libc::SIGINT | libc::SIGHUP
            )
        {
            return Err(ProductBrokerError::Denied("broker_signal_record_invalid"));
        }
        Ok(())
    }
}

struct ProductBrokerV1 {
    listener: ProductSeqpacketListenerV1,
    authorization: ShellExecAuthorizationRegistryV1,
    ledger: Option<DurableShellExecLedgerV1>,
    receipts: crate::DurableShellExecReceiptStoreV1,
    idle_worker: Option<ProductWorkerProxyV1>,
}

pub fn run() -> Result<()> {
    match run_inner() {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = crate::android_property::set_property(crate::ANDROID_READY_PROPERTY, "failed");
            Err(error)
        }
    }
}

/// Drains only the fixed worker cgroup after a failed/unclean service stop.
/// This mode never opens the ledger, starts a worker, binds the public socket,
/// or publishes READY, so init can invoke it as an independent oneshot before
/// restarting the full broker service.
pub fn run_cleanup_stale_only() -> Result<()> {
    match cleanup_stale_only_inner() {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = crate::android_property::set_property(crate::ANDROID_READY_PROPERTY, "failed");
            Err(error)
        }
    }
}

fn cleanup_stale_only_inner() -> Result<()> {
    verify_broker_identity()?;
    crate::android_property::set_property(crate::ANDROID_READY_PROPERTY, "failed")?;
    drop(FixedCgroupV1::open_and_configure()?);
    // Keep the externally visible state explicitly failed after cleanup; only
    // the full broker's sole READY publication point may change it to ready.
    crate::android_property::set_property(crate::ANDROID_READY_PROPERTY, "failed")?;
    Ok(())
}

fn run_inner() -> Result<()> {
    verify_broker_identity()?;
    crate::android_property::set_property(crate::ANDROID_READY_PROPERTY, "pending")?;
    let signals = BrokerSignalsV1::install()?;
    // Drain a prior broker's entire worker cgroup before changing any crash-
    // visible ledger record. No new worker is attached until all old records
    // and receipts have been repaired.
    drop(FixedCgroupV1::open_and_configure()?);
    let mut ledger = DurableShellExecLedgerV1::open(std::path::Path::new(ANDROID_LEDGER_ROOT))?;
    let receipts = crate::DurableShellExecReceiptStoreV1::open(std::path::Path::new(
        crate::ANDROID_RECEIPT_ROOT,
    ))?;
    // Registration capacity is reserved from the ledger filesystem for both
    // copy-on-publish snapshots and immutable receipts. Prove that this is one
    // shared allocation domain before any recovery mutation or READY.
    verify_shared_durable_capacity_device(&ledger, &receipts)?;
    let recovery_boottime_ms = boottime_ms()?;
    ledger.terminalize_all_not_dispatched_after_product_restart(recovery_boottime_ms)?;
    ledger.recover_all_dispatched_after_restart(recovery_boottime_ms)?;
    let worker = ProductWorkerProxyV1::prestart()?;
    repair_receipts_before_ready(&ledger, &receipts, &worker)?;
    let listener = ProductSeqpacketListenerV1::bind_fixed()?;
    let mut broker = ProductBrokerV1 {
        listener,
        authorization: ShellExecAuthorizationRegistryV1::default(),
        ledger: Some(ledger),
        receipts,
        idle_worker: Some(worker),
    };
    // This is the sole READY publication point: identity, signal custody,
    // stale-cgroup drain, generic request-unaware worker READY, durable-ledger
    // recovery, and the public listener have all completed successfully.
    crate::android_property::set_property(crate::ANDROID_READY_PROPERTY, "ready")?;
    broker.serve(&signals)?;
    broker.shutdown()?;
    crate::android_property::set_property(crate::ANDROID_READY_PROPERTY, "inactive")?;
    Ok(())
}

impl ProductBrokerV1 {
    fn serve(&mut self, signals: &BrokerSignalsV1) -> Result<()> {
        loop {
            let mut polls = [
                libc::pollfd {
                    fd: self.listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: signals.descriptor.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: polls names two live descriptors and remains writable.
            let observed = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as _, -1) };
            if observed < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if polls[1].revents & libc::POLLIN != 0 {
                signals.consume()?;
                return Ok(());
            }
            if polls[0].revents & libc::POLLIN == 0 {
                return Err(ProductBrokerError::Denied("broker_listener_poll_invalid"));
            }
            let (connection, peer) = self.listener.accept_authenticated()?;
            if let Err(error) = self.handle_connection(connection, peer) {
                if matches!(
                    error,
                    ProductBrokerError::PeerRejected(_) | ProductBrokerError::PeerGoneAfterCommit
                ) {
                    eprintln!("shell exec broker rejected one connection: {error}");
                    continue;
                }
                return Err(error);
            }
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        if let Some(mut worker) = self.idle_worker.take() {
            worker.finish_one_shot()?;
        }
        Ok(())
    }

    fn handle_connection(
        &mut self,
        connection: ShellExecSeqpacketV1,
        peer: crate::mcp_adapter::ShellExecPeerIdentityV1,
    ) -> Result<()> {
        // Classify the accepted kernel-authenticated peer before reading or
        // deserializing its packet. Each role has exactly one closed wire type.
        match peer
            .classify()
            .map_err(|_| ProductBrokerError::PeerRejected("peer_role_invalid"))?
        {
            ShellExecPeerRoleV1::AgentHostRegistration => {
                peer.require_agentd()
                    .map_err(|_| ProductBrokerError::PeerRejected("agentd_peer_invalid"))?;
                match connection
                    .receive_host_control()
                    .map_err(|_| ProductBrokerError::PeerRejected("host_control_invalid"))?
                {
                    ShellExecHostControlV1::Register { registration } => {
                        let now = boottime_ms()?;
                        registration
                            .validate_at(now)
                            .map_err(peer_authorization_error)?;
                        let binding_sha256 = registration.binding_sha256.clone();
                        let restored_records = self
                            .ledger
                            .as_ref()
                            .ok_or(ProductBrokerError::Denied("ledger_missing"))?
                            .records_for_binding(&binding_sha256)?;
                        let restored_high_water = restored_records
                            .iter()
                            .map(|record| record.request.adapter_effect_ordinal)
                            .max()
                            .unwrap_or(0);
                        let remaining = crate::authorization::MAX_EFFECTS_PER_INVOCATION
                            .checked_sub(restored_high_water)
                            .ok_or(ProductBrokerError::Denied(
                                "durable_ordinal_exceeds_registration_limit",
                            ))?;
                        self.ledger
                            .as_ref()
                            .ok_or(ProductBrokerError::Denied("ledger_missing"))?
                            .admit_additional_record_capacity(remaining)
                            .map_err(registration_capacity_error)?;
                        let receipt = self
                            .authorization
                            .register(registration, now)
                            .map_err(peer_authorization_error)?;
                        let restored = restored_records
                            .into_iter()
                            .map(|record| record.request)
                            .collect::<Vec<_>>();
                        self.authorization
                            .restore_durable_requests(&binding_sha256, &restored)?;
                        connection
                            .send_registration_receipt(&receipt)
                            .map_err(|_| {
                                ProductBrokerError::PeerRejected("registration_reply_lost")
                            })?;
                        Ok(())
                    }
                    ShellExecHostControlV1::Retire { retirement } => {
                        self.authorization
                            .retirement_has_ordinals(&retirement)
                            .map_err(peer_authorization_error)?;
                        let workspace_name = format!("w-{}", retirement.binding_sha256);
                        let marker_name = format!(".binding-{}", retirement.binding_sha256);
                        let worker = self
                            .idle_worker
                            .as_ref()
                            .ok_or(ProductBrokerError::Denied("idle_worker_missing"))?;
                        let complete_pair = reconcile_scope_pair(
                            worker.workspace_parent.as_raw_fd(),
                            &workspace_name,
                            &marker_name,
                            &retirement.binding_sha256,
                            OrphanLeafContentsV1::RequireEmpty,
                        )?;
                        if complete_pair {
                            let workspace = open_beneath_component_walk(
                                worker.workspace_parent.as_raw_fd(),
                                &workspace_name,
                                libc::O_RDONLY | libc::O_DIRECTORY,
                                RequiredFileTypeV1::Directory,
                            )
                            .map_err(|_| {
                                ProductBrokerError::Denied("workspace_retirement_open_failed")
                            })?;
                            validate_scope_marker(
                                worker.workspace_parent.as_raw_fd(),
                                &marker_name,
                                &retirement.binding_sha256,
                            )?;
                            retire_effect_tmpdir(
                                worker.workspace_parent.as_raw_fd(),
                                workspace.as_raw_fd(),
                                &workspace_name,
                                &marker_name,
                            )?;
                        } else {
                            require_entry_absent(
                                worker.workspace_parent.as_raw_fd(),
                                &workspace_name,
                            )?;
                            require_entry_absent(
                                worker.workspace_parent.as_raw_fd(),
                                &marker_name,
                            )?;
                        }
                        let receipt = self.authorization.retire(&retirement, boottime_ms()?)?;
                        connection
                            .send_retirement_receipt(&receipt)
                            .map_err(|_| ProductBrokerError::PeerGoneAfterCommit)?;
                        Ok(())
                    }
                }
            }
            ShellExecPeerRoleV1::ShellAdapterExecute => {
                peer.require_shell_adapter()
                    .map_err(|_| ProductBrokerError::PeerRejected("shell_peer_invalid"))?;
                let transport = connection
                    .receive_authenticated_execute()
                    .map_err(|_| ProductBrokerError::PeerRejected("execute_record_invalid"))?;
                transport
                    .validate()
                    .map_err(|_| ProductBrokerError::PeerRejected("execute_record_invalid"))?;
                let cancellation = Arc::new(CancellationTokenV1::default());
                let watcher = DisconnectWatcherV1::start(&connection, Arc::clone(&cancellation))?;
                let now = boottime_ms()?;
                let ready = &self
                    .idle_worker
                    .as_ref()
                    .ok_or(ProductBrokerError::Denied("idle_worker_missing"))?
                    .ready;
                let request = match self
                    .authorization
                    .begin_unique_active_request(
                        transport.adapter_effect_ordinal,
                        transport.arguments.clone(),
                        now,
                    )
                    .map_err(peer_authorization_error)?
                {
                    ShellExecRequestAdmissionV1::Existing(request) => request,
                    ShellExecRequestAdmissionV1::NeedsWorker(pending) => {
                        let identity = self.authorization.stable_identity_for_pending(&pending)?;
                        let recovered = self
                            .ledger
                            .as_ref()
                            .ok_or(ProductBrokerError::Denied("ledger_missing"))?
                            .recover_stable_request(
                                &identity.binding_sha256,
                                identity.adapter_effect_ordinal,
                                &identity.semantic_arguments_sha256,
                            )?;
                        match recovered {
                            StableLedgerRecoveryV1::Absent => {
                                self.authorization.materialize_request(
                                    pending,
                                    now,
                                    current_boot_id_sha256()?,
                                    ready.kernel_launch_custody_sha256.clone(),
                                    ready.backend_identity_sha256.clone(),
                                )?
                            }
                            StableLedgerRecoveryV1::NotDispatched(request)
                            | StableLedgerRecoveryV1::Dispatched(request)
                            | StableLedgerRecoveryV1::Indeterminate(request)
                            | StableLedgerRecoveryV1::Terminal { request, .. } => self
                                .authorization
                                .restore_materialized_request(pending, request)?,
                        }
                    }
                };
                let ledger = self
                    .ledger
                    .take()
                    .ok_or(ProductBrokerError::Denied("ledger_missing"))?;
                let worker = self
                    .idle_worker
                    .take()
                    .ok_or(ProductBrokerError::Denied("idle_worker_missing"))?;
                let mut core = ShellExecBrokerCoreV1::new(ledger, worker);
                let outcome = core.execute_authenticated(
                    &request,
                    now,
                    // ProductWorkerProxy replaces this host-compatible hint
                    // after preflight with the v2 worker-instance/fd custody
                    // binding before the durable DISPATCHED transition.
                    &request.request_sha256,
                    cancellation.as_ref(),
                );
                watcher.stop();
                let state = core
                    .durable_state(&request.effect_id)
                    .cloned()
                    .ok_or(ProductBrokerError::Denied("durable_state_missing"))?;
                let (ledger, mut worker) = core.into_parts();
                if worker.go_sent || state.dispatch_occurred {
                    worker.finish_one_shot()?;
                } else {
                    worker.cleanup_prepared_effect()?;
                }
                ensure_effect_temporary_scope_absent(
                    worker.temporary_parent.as_raw_fd(),
                    &request,
                    state.dispatch_occurred,
                )?;
                if matches!(
                    state.phase,
                    DirectEffectPhaseV1::Terminal | DirectEffectPhaseV1::Indeterminate
                ) {
                    let record = ledger
                        .record(&request.effect_id)?
                        .ok_or(ProductBrokerError::Denied("durable_record_missing"))?;
                    self.receipts.ensure(&record)?;
                }
                self.ledger = Some(ledger);
                if worker.retired {
                    self.idle_worker = Some(ProductWorkerProxyV1::prestart()?);
                } else {
                    self.idle_worker = Some(worker);
                }
                let response = match outcome {
                    Ok(terminal_bytes) => {
                        if state.phase != DirectEffectPhaseV1::Terminal {
                            return Err(ProductBrokerError::Denied(
                                "terminal_state_binding_invalid",
                            ));
                        }
                        ShellExecTransportResponseV1::terminal(request, state, &terminal_bytes)?
                    }
                    Err(ShellExecError::Indeterminate) => {
                        if state.phase != DirectEffectPhaseV1::Indeterminate {
                            return Err(ProductBrokerError::Denied(
                                "indeterminate_state_binding_invalid",
                            ));
                        }
                        ShellExecTransportResponseV1::indeterminate(request, state)?
                    }
                    Err(error) => {
                        return Err(ProductBrokerError::Execution(error));
                    }
                };
                connection
                    .send_response(&response)
                    .map_err(|_| ProductBrokerError::PeerGoneAfterCommit)?;
                Ok(())
            }
        }
    }
}

struct DisconnectWatcherV1 {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl DisconnectWatcherV1 {
    fn start(
        connection: &ShellExecSeqpacketV1,
        cancellation: Arc<CancellationTokenV1>,
    ) -> Result<Self> {
        let descriptor = connection.duplicate_descriptor()?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("shell-peer-watch".to_string())
            .spawn(move || {
                while !thread_stop.load(Ordering::SeqCst) {
                    let mut poll = libc::pollfd {
                        fd: descriptor.as_raw_fd(),
                        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP,
                        revents: 0,
                    };
                    // SAFETY: poll names one initialized descriptor record.
                    let observed = unsafe { libc::poll(&mut poll, 1, 25) };
                    if observed > 0
                        && poll.revents
                            & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP)
                            != 0
                    {
                        cancellation.cancel();
                        break;
                    }
                    if observed < 0
                        && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                    {
                        cancellation.cancel();
                        break;
                    }
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for DisconnectWatcherV1 {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct ProductWorkerProxyV1 {
    control: OwnedFd,
    pid: u32,
    pidfd: OwnedFd,
    rootfs: OwnedFd,
    workspace_parent: OwnedFd,
    temporary_parent: OwnedFd,
    executable_policy: StandardExecutablePolicyV1,
    cgroup: FixedCgroupV1,
    ready: WorkerReadyV1,
    prepared: Option<PreparedEffectV1>,
    go_sent: bool,
    retired: bool,
}

struct PreparedEffectV1 {
    request_sha256: String,
    dispatch_binding_sha256: String,
    executable: OwnedFd,
    cwd: OwnedFd,
    tmpdir: OwnedFd,
    tmpdir_parent: OwnedFd,
    tmpdir_name: String,
    tmpdir_marker_name: String,
    tmpdir_path: String,
    semantic_arguments_sha256: String,
    approved_executable_path: String,
    approved_executable_sha256: String,
    approved_executable_custody_sha256: String,
    cwd_custody_sha256: String,
    tmpdir_custody_sha256: String,
}

impl ProductWorkerProxyV1 {
    fn prestart() -> Result<Self> {
        let worker_executable = open_fixed_file(ANDROID_WORKER_PATH)?;
        validate_worker_executable(worker_executable.as_raw_fd())?;
        let worker_executable_sha256 =
            sha256_regular_descriptor(worker_executable.as_raw_fd(), MAX_WORKER_ELF_BYTES)?;
        let rootfs = open_fixed_directory(ROOT_LINUX_HOST_ROOT)?;
        validate_rootfs(rootfs.as_raw_fd())?;
        let rootfs_custody_sha256 = descriptor_custody_sha256(rootfs.as_raw_fd(), true)?;
        let dev_null = open_fixed_file("/dev/null")?;
        let dev_null_custody_sha256 = dev_null_custody_sha256(dev_null.as_raw_fd())?;
        let workspace_parent = open_beneath_component_walk(
            rootfs.as_raw_fd(),
            ROOT_LINUX_WORKSPACE_PARENT
                .strip_prefix('/')
                .ok_or(ProductBrokerError::Denied("workspace_path_invalid"))?,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            RequiredFileTypeV1::Directory,
        )
        .map_err(|_| ProductBrokerError::Denied("workspace_parent_open_invalid"))?;
        let temporary_parent = open_beneath_component_walk(
            rootfs.as_raw_fd(),
            ROOT_LINUX_TEMPORARY_PARENT
                .strip_prefix('/')
                .ok_or(ProductBrokerError::Denied("temporary_path_invalid"))?,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            RequiredFileTypeV1::Directory,
        )
        .map_err(|_| ProductBrokerError::Denied("temporary_parent_open_invalid"))?;
        validate_scope_parent(workspace_parent.as_raw_fd())?;
        validate_scope_parent(temporary_parent.as_raw_fd())?;
        let policy_descriptor = open_beneath_component_walk(
            rootfs.as_raw_fd(),
            ROOT_LINUX_EXECUTABLE_POLICY
                .strip_prefix('/')
                .ok_or(ProductBrokerError::Denied("executable_policy_path_invalid"))?,
            libc::O_RDONLY,
            RequiredFileTypeV1::Regular,
        )
        .map_err(|_| ProductBrokerError::Denied("executable_policy_open_invalid"))?;
        validate_root_owned_policy_file(policy_descriptor.as_raw_fd())?;
        let executable_policy = StandardExecutablePolicyV1::from_canonical_bytes(
            &read_bounded_descriptor(policy_descriptor.as_raw_fd(), 64 * 1024)?,
        )?;
        let executable_policy_sha256 = executable_policy.digest_sha256()?;
        let cgroup = FixedCgroupV1::open_and_configure()?;
        let (broker_control, child_control) = seqpacket_pair()?;
        let child_control = duplicate_at_least(child_control.as_raw_fd(), 10)?;
        let child_rootfs = duplicate_at_least(rootfs.as_raw_fd(), 10)?;
        let child_executable = duplicate_at_least(worker_executable.as_raw_fd(), 10)?;
        let child_dev_null = duplicate_at_least(dev_null.as_raw_fd(), 10)?;
        let expected_parent = current_pid()?;
        // SAFETY: broker startup is single-threaded; the child uses only
        // async-signal-safe syscalls before execveat/_exit.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if child == 0 {
            exec_worker_child(
                child_control.as_raw_fd(),
                child_rootfs.as_raw_fd(),
                child_executable.as_raw_fd(),
                child_dev_null.as_raw_fd(),
                expected_parent,
            );
        }
        drop(child_control);
        drop(child_rootfs);
        drop(child_executable);
        drop(child_dev_null);
        let pid =
            u32::try_from(child).map_err(|_| ProductBrokerError::Denied("worker_pid_invalid"))?;
        let pidfd = open_pidfd(child)?;
        cgroup.attach(pid)?;
        let cgroup_membership = read_process_record(pid, "cgroup")?;
        if cgroup_membership.trim_end() != format!("0::{WORKER_CGROUP_RELATIVE}") {
            return Err(ProductBrokerError::Denied(
                "worker_cgroup_membership_invalid",
            ));
        }
        let cgroup_membership_sha256 = domain_digest(
            b"trillionnium.shell-exec.worker-cgroup-membership.v1",
            &[cgroup_membership.as_bytes()],
        );
        let hello: AuthenticatedFrameV1<WorkerBrokerFrameV1> =
            receive_frame(broker_control.as_raw_fd())?;
        let WorkerBrokerFrameV1::Hello(hello_value) = &hello.value else {
            return Err(ProductBrokerError::Denied("worker_hello_expected"));
        };
        validate_hello(
            &hello,
            hello_value,
            pid,
            expected_parent,
            &worker_executable_sha256,
            &rootfs_custody_sha256,
            &dev_null_custody_sha256,
            &executable_policy_sha256,
        )?;
        let cgroup_policy_sha256 = FixedWorkerCgroupPolicyV1::fixed().digest_sha256()?;
        let isolation_policy_sha256 = FixedWorkerIsolationPolicyV1::fixed().digest_sha256()?;
        let bootstrap = BrokerWorkerFrameV1::Bootstrap(WorkerBootstrapV1 {
            schema: WORKER_BOOTSTRAP_SCHEMA.to_string(),
            protocol: WORKER_PROTOCOL.to_string(),
            pid,
            cgroup_membership_sha256,
            cgroup_policy_sha256,
            isolation_policy_sha256,
        });
        send_frame(broker_control.as_raw_fd(), &bootstrap, &[])?;
        let ready: AuthenticatedFrameV1<WorkerBrokerFrameV1> =
            receive_frame(broker_control.as_raw_fd())?;
        let WorkerBrokerFrameV1::Ready(ready_value) = &ready.value else {
            return Err(ProductBrokerError::Denied("worker_ready_expected"));
        };
        validate_ready(&ready, ready_value, hello_value, pid)?;
        Ok(Self {
            control: broker_control,
            pid,
            pidfd,
            rootfs,
            workspace_parent,
            temporary_parent,
            executable_policy,
            cgroup,
            ready: ready_value.clone(),
            prepared: None,
            go_sent: false,
            retired: false,
        })
    }

    fn prepare_effect(&mut self, request: &DirectEffectRequestV1) -> Result<()> {
        if self
            .prepared
            .as_ref()
            .is_some_and(|prepared| prepared.request_sha256 == request.request_sha256)
        {
            return Ok(());
        }
        if self.prepared.is_some() || self.go_sent {
            return Err(ProductBrokerError::Denied("worker_preflight_reuse_invalid"));
        }
        let executable_path = request
            .arguments
            .argv
            .first()
            .ok_or(ProductBrokerError::Denied("argv_missing"))?;
        if !self.executable_policy.contains_path(executable_path) {
            return Err(ProductBrokerError::PolicyRejected(
                "executable_not_allowlisted",
            ));
        }
        let executable = open_beneath_component_walk(
            self.rootfs.as_raw_fd(),
            executable_path
                .strip_prefix('/')
                .ok_or(ProductBrokerError::Denied("executable_path_invalid"))?,
            libc::O_RDONLY,
            RequiredFileTypeV1::Regular,
        )
        .map_err(|_| ProductBrokerError::Denied("executable_preflight_open_failed"))?;
        validate_approved_executable(executable.as_raw_fd())?;
        let approved_executable_sha256 =
            sha256_regular_descriptor(executable.as_raw_fd(), MAX_WORKER_ELF_BYTES)?;
        if !self
            .executable_policy
            .authorizes(executable_path, &approved_executable_sha256)
        {
            return Err(ProductBrokerError::Denied(
                "allowlisted_executable_digest_mismatch",
            ));
        }
        let workspace_name = format!("w-{}", request.direct_binding_sha256);
        let workspace_marker_name = format!(".binding-{}", request.direct_binding_sha256);
        let workspace = create_or_open_scope_leaf(
            self.workspace_parent.as_raw_fd(),
            &workspace_name,
            &workspace_marker_name,
            &request.direct_binding_sha256,
        )?;
        let tmpdir_name = effect_tmpdir_name(request)?;
        let tmpdir_marker_name = format!(".request-{}", request.request_sha256);
        let tmpdir = create_or_open_scope_leaf(
            self.temporary_parent.as_raw_fd(),
            &tmpdir_name,
            &tmpdir_marker_name,
            &request.request_sha256,
        )?;
        let cwd_result = match &request.arguments.cwd {
            None => duplicate_descriptor(workspace.as_raw_fd()),
            Some(cwd) => match cwd.scope {
                DirectEffectWorkingDirectoryScopeV1::Workspace => open_beneath_component_walk(
                    workspace.as_raw_fd(),
                    &cwd.relative,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    RequiredFileTypeV1::Directory,
                )
                .map_err(classify_cwd_path_error),
            },
        };
        let cwd = match cwd_result {
            Ok(value) => value,
            Err(error) => {
                retire_effect_tmpdir(
                    self.temporary_parent.as_raw_fd(),
                    tmpdir.as_raw_fd(),
                    &tmpdir_name,
                    &tmpdir_marker_name,
                )?;
                return Err(error);
            }
        };
        let semantic_arguments_sha256 = match request.arguments.canonical_sha256() {
            Ok(value) => value,
            Err(_) => {
                retire_effect_tmpdir(
                    self.temporary_parent.as_raw_fd(),
                    tmpdir.as_raw_fd(),
                    &tmpdir_name,
                    &tmpdir_marker_name,
                )?;
                return Err(ProductBrokerError::Denied("semantic_arguments_invalid"));
            }
        };
        let tmpdir_path = format!("{ROOT_LINUX_TEMPORARY_PARENT}/{tmpdir_name}");
        let custody = (|| {
            Ok::<_, ProductBrokerError>((
                descriptor_custody_sha256(executable.as_raw_fd(), false)?,
                descriptor_custody_sha256(cwd.as_raw_fd(), true)?,
                descriptor_custody_sha256(tmpdir.as_raw_fd(), true)?,
                duplicate_descriptor(self.temporary_parent.as_raw_fd())?,
            ))
        })();
        let (
            approved_executable_custody_sha256,
            cwd_custody_sha256,
            tmpdir_custody_sha256,
            tmpdir_parent,
        ) = match custody {
            Ok(value) => value,
            Err(error) => {
                retire_effect_tmpdir(
                    self.temporary_parent.as_raw_fd(),
                    tmpdir.as_raw_fd(),
                    &tmpdir_name,
                    &tmpdir_marker_name,
                )?;
                return Err(error);
            }
        };
        let dispatch_binding_sha256 = effect_dispatch_binding_sha256(
            &request.request_sha256,
            &self.ready,
            &semantic_arguments_sha256,
            executable_path,
            &approved_executable_sha256,
            &approved_executable_custody_sha256,
            &cwd_custody_sha256,
            &tmpdir_path,
            &tmpdir_custody_sha256,
        );
        self.prepared = Some(PreparedEffectV1 {
            request_sha256: request.request_sha256.clone(),
            dispatch_binding_sha256,
            approved_executable_custody_sha256,
            cwd_custody_sha256,
            tmpdir_custody_sha256,
            executable,
            cwd,
            tmpdir,
            tmpdir_parent,
            tmpdir_name,
            tmpdir_marker_name,
            tmpdir_path,
            semantic_arguments_sha256,
            approved_executable_path: executable_path.clone(),
            approved_executable_sha256,
        });
        Ok(())
    }

    fn retire_worker(&mut self) -> Result<bool> {
        if self.retired {
            return Ok(false);
        }
        let descendants_observed = self.cgroup.cleanup(Some(self.pid))?;
        self.cleanup_prepared_effect()?;
        self.retired = true;
        Ok(descendants_observed)
    }

    fn cleanup_prepared_effect(&mut self) -> Result<()> {
        if let Some(prepared) = self.prepared.take() {
            retire_effect_tmpdir(
                prepared.tmpdir_parent.as_raw_fd(),
                prepared.tmpdir.as_raw_fd(),
                &prepared.tmpdir_name,
                &prepared.tmpdir_marker_name,
            )?;
        }
        Ok(())
    }

    fn finish_one_shot(&mut self) -> Result<()> {
        self.retire_worker().map(|_| ())
    }
}

impl ShellExecWorkerV1 for ProductWorkerProxyV1 {
    fn preflight(
        &mut self,
        request: &DirectEffectRequestV1,
    ) -> std::result::Result<(), WorkerPreflightErrorV1> {
        self.prepare_effect(request).map_err(|error| match error {
            ProductBrokerError::PolicyRejected(code) => {
                WorkerPreflightErrorV1::PolicyRejected(code)
            }
            fatal => WorkerPreflightErrorV1::RuntimeFatal(fatal.to_string()),
        })
    }

    fn dispatch_binding_sha256(
        &self,
        request: &DirectEffectRequestV1,
        _caller_binding_sha256: &str,
    ) -> std::result::Result<String, WorkerPreflightErrorV1> {
        self.prepared
            .as_ref()
            .filter(|prepared| prepared.request_sha256 == request.request_sha256)
            .map(|prepared| prepared.dispatch_binding_sha256.clone())
            .ok_or_else(|| {
                WorkerPreflightErrorV1::RuntimeFatal("effect_preflight_missing".to_string())
            })
    }

    fn execute(
        &mut self,
        request: &DirectEffectRequestV1,
        dispatch_started_boottime_ms: u64,
        cancellation: &CancellationTokenV1,
    ) -> std::result::Result<WorkerCompletionV1, String> {
        let prepared = self
            .prepared
            .as_ref()
            .filter(|prepared| prepared.request_sha256 == request.request_sha256)
            .ok_or_else(|| "effect_preflight_missing".to_string())?;
        let remaining_ms = request
            .absolute_deadline_boottime_ms
            .saturating_sub(dispatch_started_boottime_ms);
        let cpu_limit_seconds = remaining_ms
            .saturating_add(999)
            .saturating_div(1000)
            .saturating_add(1)
            .clamp(1, crate::product_ipc::WORKER_RLIMIT_CPU_MAX_SECONDS);
        let go = BrokerWorkerFrameV1::Go(WorkerGoV1 {
            schema: WORKER_GO_SCHEMA.to_string(),
            protocol: WORKER_PROTOCOL.to_string(),
            request: request.clone(),
            dispatch_started_boottime_ms,
            dispatch_binding_sha256: prepared.dispatch_binding_sha256.clone(),
            semantic_arguments_sha256: prepared.semantic_arguments_sha256.clone(),
            approved_executable_path: prepared.approved_executable_path.clone(),
            approved_executable_sha256: prepared.approved_executable_sha256.clone(),
            approved_executable_custody_sha256: prepared.approved_executable_custody_sha256.clone(),
            cwd_custody_sha256: prepared.cwd_custody_sha256.clone(),
            tmpdir_path: prepared.tmpdir_path.clone(),
            tmpdir_custody_sha256: prepared.tmpdir_custody_sha256.clone(),
            cpu_limit_seconds,
        });
        send_frame(
            self.control.as_raw_fd(),
            &go,
            &[
                prepared.executable.as_raw_fd(),
                prepared.cwd.as_raw_fd(),
                prepared.tmpdir.as_raw_fd(),
            ],
        )
        .map_err(|error| error.to_string())?;
        self.go_sent = true;
        let mut cancel_sent = false;
        loop {
            let observed_boottime_ms = boottime_ms().map_err(|error| error.to_string())?;
            let forced_reason = if cancellation.is_cancelled() {
                Some(trillionnium_os_types::direct_effect::DirectEffectIndeterminateReasonV1::CancelledAfterDispatch)
            } else if observed_boottime_ms >= request.absolute_deadline_boottime_ms {
                Some(trillionnium_os_types::direct_effect::DirectEffectIndeterminateReasonV1::DeadlineAfterDispatch)
            } else {
                None
            };
            if forced_reason.is_some() && !cancel_sent {
                let cancel = BrokerWorkerFrameV1::Cancel(WorkerCancelV1 {
                    schema: WORKER_CANCEL_SCHEMA.to_string(),
                    protocol: WORKER_PROTOCOL.to_string(),
                    request_sha256: request.request_sha256.clone(),
                });
                send_frame(self.control.as_raw_fd(), &cancel, &[])
                    .map_err(|error| error.to_string())?;
                cancel_sent = true;
            }
            if let Some(reason) = forced_reason {
                self.retire_worker().map_err(|error| error.to_string())?;
                return Ok(WorkerCompletionV1::Indeterminate {
                    reason,
                    observed_boottime_ms: observed_boottime_ms.max(dispatch_started_boottime_ms),
                });
            }
            let remaining = request
                .absolute_deadline_boottime_ms
                .saturating_sub(observed_boottime_ms)
                .min(25);
            let mut polls = [
                libc::pollfd {
                    fd: self.control.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.pidfd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: polls points to two initialized descriptor records.
            let observed =
                unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as _, remaining as i32) };
            if observed < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.to_string());
            }
            if observed == 0 {
                continue;
            }
            if polls[1].revents & libc::POLLIN != 0 && polls[0].revents & libc::POLLIN == 0 {
                self.retire_worker().map_err(|error| error.to_string())?;
                return Err("worker_exited_without_completion".to_string());
            }
            if polls[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP) != 0 {
                self.retire_worker().map_err(|error| error.to_string())?;
                return Err("worker_control_disconnected".to_string());
            }
            let frame: AuthenticatedFrameV1<WorkerBrokerFrameV1> =
                receive_frame(self.control.as_raw_fd()).map_err(|error| error.to_string())?;
            if frame.credentials.pid != self.pid
                || frame.credentials.uid != SHELL_WORKER_UID
                || frame.credentials.gid != SHELL_WORKER_GID
                || !frame.descriptors.is_empty()
            {
                return Err("worker_completion_credentials_invalid".to_string());
            }
            let WorkerBrokerFrameV1::Completion(WorkerCompletionFrameV1 {
                schema,
                protocol,
                request_sha256,
                completion,
            }) = frame.value
            else {
                return Err("worker_completion_expected".to_string());
            };
            if schema != WORKER_COMPLETION_SCHEMA
                || protocol != WORKER_PROTOCOL
                || request_sha256 != request.request_sha256
            {
                return Err("worker_completion_binding_invalid".to_string());
            }
            match &completion {
                WorkerCompletionV1::Terminal(response) => response
                    .validate_for_request(request)
                    .map_err(|_| "worker_terminal_invalid".to_string())?,
                WorkerCompletionV1::Indeterminate {
                    observed_boottime_ms,
                    ..
                } if *observed_boottime_ms < dispatch_started_boottime_ms => {
                    return Err("worker_indeterminate_time_invalid".to_string());
                }
                WorkerCompletionV1::Indeterminate { .. } => {}
            }
            let descendants_observed = self.retire_worker().map_err(|error| error.to_string())?;
            if descendants_observed {
                return Ok(WorkerCompletionV1::Indeterminate {
                    reason: trillionnium_os_types::direct_effect::DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch,
                    observed_boottime_ms: boottime_ms()
                        .map_err(|error| error.to_string())?
                        .max(dispatch_started_boottime_ms),
                });
            }
            return Ok(completion);
        }
    }
}

struct FixedCgroupV1 {
    directory: File,
}

impl FixedCgroupV1 {
    fn open_and_configure() -> Result<Self> {
        if ANDROID_WORKER_CGROUP != format!("{WORKER_CGROUP_PARENT}/{WORKER_CGROUP_LEAF}") {
            return Err(ProductBrokerError::Denied("fixed_cgroup_path_drift"));
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(WORKER_CGROUP_PARENT)?;
        validate_cgroup2(parent.as_raw_fd())?;
        let metadata = parent.metadata()?;
        if metadata.uid() != ANDROID_SYSTEM_UID
            || metadata.gid() != ANDROID_SYSTEM_GID
            || metadata.mode() & 0o777 != 0o775
        {
            return Err(ProductBrokerError::Denied("cgroup_parent_custody_invalid"));
        }
        let name = CString::new(WORKER_CGROUP_LEAF)
            .map_err(|_| ProductBrokerError::Denied("cgroup_leaf_name_invalid"))?;
        // SAFETY: name is one fixed basename resolved under retained cgroup2.
        let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o750) };
        if created != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(std::io::Error::last_os_error().into());
        }
        let directory = openat_directory(&parent, WORKER_CGROUP_LEAF)?;
        if created == 0 {
            // SAFETY: directory is the newly-created empty cgroup leaf.
            if unsafe { libc::fchown(directory.as_raw_fd(), 0, ANDROID_SYSTEM_GID) } != 0
                // SAFETY: same retained new leaf.
                || unsafe { libc::fchmod(directory.as_raw_fd(), 0o750) } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let metadata = directory.metadata()?;
        if metadata.uid() != 0
            || metadata.gid() != ANDROID_SYSTEM_GID
            || metadata.mode() & 0o777 != 0o750
        {
            return Err(ProductBrokerError::Denied("cgroup_leaf_custody_invalid"));
        }
        write_cgroup_file(&directory, "memory.max", "536870912")?;
        require_cgroup_value(&directory, "memory.max", "536870912")?;
        write_cgroup_file(&directory, "memory.oom.group", "1")?;
        require_cgroup_value(&directory, "memory.oom.group", "1")?;
        match write_cgroup_file(&directory, "memory.swap.max", "0") {
            Ok(()) => require_cgroup_value(&directory, "memory.swap.max", "0")?,
            Err(ProductBrokerError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let value = Self { directory };
        // A broker restart must drain any stale worker/descendants before a
        // new READY can be admitted. Unsupported freeze/pidfd semantics fail
        // startup closed rather than falling back to process groups.
        let _ = value.cleanup(None)?;
        Ok(value)
    }

    fn attach(&self, pid: u32) -> Result<()> {
        write_cgroup_file(&self.directory, "cgroup.procs", &pid.to_string())?;
        let processes = read_cgroup_file(&self.directory, "cgroup.procs")?;
        if !processes
            .lines()
            .any(|value| value.trim().parse::<u32>().ok() == Some(pid))
        {
            return Err(ProductBrokerError::Denied("cgroup_attach_not_observed"));
        }
        Ok(())
    }

    fn cleanup(&self, owned_worker: Option<u32>) -> Result<bool> {
        let deadline = boottime_ms()?.saturating_add(2_000);
        let mut descendants_observed = false;
        loop {
            let populated = cgroup_event(&self.directory, "populated")?;
            let processes = stable_cgroup_processes(&self.directory, deadline)?;
            if !populated && processes.is_empty() {
                // A previous broker may have died after freeze=1 while its
                // members were exiting. Empty does not imply unfrozen on 5.4;
                // explicitly thaw and observe before attaching a new worker.
                write_cgroup_file(&self.directory, "cgroup.freeze", "0")?;
                wait_cgroup_event(&self.directory, "frozen", false, deadline)?;
                if cgroup_event(&self.directory, "populated")?
                    || !stable_cgroup_processes(&self.directory, deadline)?.is_empty()
                {
                    continue;
                }
                if let Some(pid) = owned_worker {
                    reap_owned_worker(pid, deadline)?;
                }
                return Ok(descendants_observed);
            }
            write_cgroup_file(&self.directory, "cgroup.freeze", "1")?;
            wait_cgroup_event(&self.directory, "frozen", true, deadline)?;
            let processes = stable_cgroup_processes(&self.directory, deadline)?;
            if processes
                .iter()
                .any(|pid| owned_worker.is_none_or(|owned| *pid != owned))
            {
                descendants_observed = true;
            }
            let mut pidfds = Vec::with_capacity(processes.len());
            for pid in processes {
                let before = process_starttime_ticks(pid)?;
                let pidfd = open_pidfd(pid as libc::pid_t)?;
                let after = process_starttime_ticks(pid)?;
                if before != after {
                    return Err(ProductBrokerError::Denied("cgroup_pid_identity_changed"));
                }
                // SAFETY: pidfd identifies the observed exact cgroup member;
                // null siginfo and flags zero are required for SIGKILL.
                if unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                } != 0
                {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        return Err(error.into());
                    }
                }
                pidfds.push(pidfd);
            }
            write_cgroup_file(&self.directory, "cgroup.freeze", "0")?;
            wait_cgroup_event(&self.directory, "frozen", false, deadline)?;
            wait_pidfds(&pidfds, deadline)?;
            if let Some(pid) = owned_worker {
                reap_owned_worker(pid, deadline)?;
            }
            wait_cgroup_event(&self.directory, "populated", false, deadline)?;
            if boottime_ms()? >= deadline {
                return Err(ProductBrokerError::Denied("cgroup_cleanup_deadline"));
            }
        }
    }
}

fn cgroup_event(directory: &File, key: &str) -> Result<bool> {
    let events = read_cgroup_file(directory, "cgroup.events")?;
    let mut found = None;
    for line in events.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(name) = fields.next() else { continue };
        let Some(value) = fields.next() else {
            return Err(ProductBrokerError::Denied("cgroup_events_invalid"));
        };
        if fields.next().is_some() || !matches!(value, "0" | "1") {
            return Err(ProductBrokerError::Denied("cgroup_events_invalid"));
        }
        if name == key {
            if found.is_some() {
                return Err(ProductBrokerError::Denied("cgroup_events_duplicate"));
            }
            found = Some(value == "1");
        }
    }
    found.ok_or(ProductBrokerError::Denied("cgroup_event_missing"))
}

fn wait_cgroup_event(directory: &File, key: &str, expected: bool, deadline: u64) -> Result<()> {
    loop {
        if cgroup_event(directory, key)? == expected {
            return Ok(());
        }
        if boottime_ms()? >= deadline {
            return Err(ProductBrokerError::Denied("cgroup_event_deadline"));
        }
        thread::sleep(std::time::Duration::from_millis(2));
    }
}

fn stable_cgroup_processes(directory: &File, deadline: u64) -> Result<Vec<u32>> {
    loop {
        let first = parse_cgroup_processes(&read_cgroup_file(directory, "cgroup.procs")?)?;
        std::sync::atomic::fence(Ordering::SeqCst);
        let second = parse_cgroup_processes(&read_cgroup_file(directory, "cgroup.procs")?)?;
        if first == second {
            return Ok(first);
        }
        if boottime_ms()? >= deadline {
            return Err(ProductBrokerError::Denied("cgroup_enumeration_unstable"));
        }
    }
}

fn parse_cgroup_processes(value: &str) -> Result<Vec<u32>> {
    let mut processes = value
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.trim()
                .parse::<u32>()
                .map_err(|_| ProductBrokerError::Denied("cgroup_process_invalid"))
        })
        .collect::<Result<Vec<_>>>()?;
    if processes.contains(&0) {
        return Err(ProductBrokerError::Denied("cgroup_process_invalid"));
    }
    processes.sort_unstable();
    processes.dedup();
    Ok(processes)
}

fn wait_pidfds(pidfds: &[OwnedFd], deadline: u64) -> Result<()> {
    let mut polls = pidfds
        .iter()
        .map(|pidfd| libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect::<Vec<_>>();
    while polls.iter().any(|poll| poll.revents & libc::POLLIN == 0) {
        if boottime_ms()? >= deadline {
            return Err(ProductBrokerError::Denied("pidfd_exit_deadline"));
        }
        // SAFETY: polls is writable for its exact length.
        let observed = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as _, 2) };
        if observed < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        if polls
            .iter()
            .any(|poll| poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0)
        {
            return Err(ProductBrokerError::Denied("pidfd_poll_invalid"));
        }
    }
    Ok(())
}

fn reap_owned_worker(pid: u32, deadline: u64) -> Result<()> {
    loop {
        let mut status = 0;
        // SAFETY: pid is the exact owned worker child and status is writable.
        let observed = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        if observed == pid as libc::pid_t
            || (observed < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
        {
            return Ok(());
        }
        if observed < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if boottime_ms()? >= deadline {
            return Err(ProductBrokerError::Denied("worker_reap_deadline"));
        }
        thread::sleep(std::time::Duration::from_millis(2));
    }
}

fn verify_broker_identity() -> Result<()> {
    // SAFETY: getters have no side effects.
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err(ProductBrokerError::Denied("broker_root_identity_missing"));
    }
    let domain = std::fs::read_to_string("/proc/self/attr/current")?;
    if domain.trim_end_matches(['\n', '\0']) != SHELL_BROKER_SELINUX_DOMAIN {
        return Err(ProductBrokerError::Denied("broker_selinux_domain_invalid"));
    }
    let executable = std::fs::read_link("/proc/self/exe")?;
    if executable != std::path::Path::new(ANDROID_BROKER_PATH) {
        return Err(ProductBrokerError::Denied("broker_executable_path_invalid"));
    }
    validate_broker_capabilities(&std::fs::read_to_string("/proc/self/status")?)?;
    Ok(())
}

fn validate_broker_capabilities(status: &str) -> Result<()> {
    let capability = |name: &'static str| -> Result<u64> {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or(ProductBrokerError::Denied(
                "broker_capability_record_missing",
            ))?;
        u64::from_str_radix(value.trim(), 16)
            .map_err(|_| ProductBrokerError::Denied("broker_capability_record_invalid"))
    };
    let effective = capability("CapEff:\t")?;
    let permitted = capability("CapPrm:\t")?;
    let inheritable = capability("CapInh:\t")?;
    let ambient = capability("CapAmb:\t")?;
    let mut groups = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:\t"))
        .ok_or(ProductBrokerError::Denied("broker_group_record_missing"))?
        .split_ascii_whitespace()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| ProductBrokerError::Denied("broker_group_record_invalid"))
        })
        .collect::<Result<Vec<_>>>()?;
    groups.sort_unstable();
    if effective != BROKER_EFFECTIVE_CAPABILITIES
        || permitted != BROKER_EFFECTIVE_CAPABILITIES
        || inheritable != 0
        || ambient != 0
        || effective & (BROKER_CAP_DAC_OVERRIDE | BROKER_CAP_DAC_READ_SEARCH) != 0
        || groups != [ANDROID_SYSTEM_GID, SHELL_WORKER_GID]
    {
        return Err(ProductBrokerError::Denied("broker_capability_set_invalid"));
    }
    Ok(())
}

// Keep each independently measured custody value visible at the authentication
// call site; hiding them in a generic context bag would make substitution
// review harder without improving the fixed one-shot path.
#[allow(clippy::too_many_arguments)]
fn validate_hello(
    frame: &AuthenticatedFrameV1<WorkerBrokerFrameV1>,
    hello: &WorkerHelloV1,
    pid: u32,
    parent: u32,
    worker_executable_sha256: &str,
    rootfs_custody_sha256: &str,
    dev_null_custody_sha256: &str,
    executable_policy_sha256: &str,
) -> Result<()> {
    if frame.credentials.pid != pid
        || frame.credentials.uid != 0
        || frame.credentials.gid != 0
        || !frame.descriptors.is_empty()
        || hello.schema != crate::product_ipc::WORKER_HELLO_SCHEMA
        || hello.protocol != WORKER_PROTOCOL
        || hello.pid != pid
        || hello.parent_pid != parent
        || hello.worker_executable_sha256 != worker_executable_sha256
        || hello.rootfs_custody_sha256 != rootfs_custody_sha256
        || hello.dev_null_custody_sha256 != dev_null_custody_sha256
        || hello.executable_policy_sha256 != executable_policy_sha256
        || hello.selinux_domain != SHELL_WORKER_SELINUX_DOMAIN
        || hello.process_starttime_ticks != process_starttime_ticks(pid)?
        || read_process_selinux(pid)? != SHELL_WORKER_SELINUX_DOMAIN
    {
        return Err(ProductBrokerError::Denied("worker_hello_binding_invalid"));
    }
    Ok(())
}

fn validate_ready(
    frame: &AuthenticatedFrameV1<WorkerBrokerFrameV1>,
    ready: &WorkerReadyV1,
    hello: &WorkerHelloV1,
    pid: u32,
) -> Result<()> {
    ready.validate()?;
    if frame.credentials.pid != pid
        || frame.credentials.uid != SHELL_WORKER_UID
        || frame.credentials.gid != SHELL_WORKER_GID
        || !frame.descriptors.is_empty()
        || ready.pid != pid
        || ready.process_starttime_ticks != hello.process_starttime_ticks
        || ready.worker_executable_sha256 != hello.worker_executable_sha256
        || ready.rootfs_custody_sha256 != hello.rootfs_custody_sha256
        || ready.dev_null_custody_sha256 != hello.dev_null_custody_sha256
        || ready.executable_policy_sha256 != hello.executable_policy_sha256
        || read_process_selinux(pid)? != SHELL_WORKER_SELINUX_DOMAIN
    {
        return Err(ProductBrokerError::Denied("worker_ready_binding_invalid"));
    }
    let status = read_process_record(pid, "status")?;
    for expected in [
        format!("Uid:\t{0}\t{0}\t{0}\t{0}", SHELL_WORKER_UID),
        format!("Gid:\t{0}\t{0}\t{0}\t{0}", SHELL_WORKER_GID),
        "Groups:\t".to_string(),
        "CapEff:\t0000000000000000".to_string(),
        "NoNewPrivs:\t1".to_string(),
        "Seccomp:\t2".to_string(),
    ] {
        if !status.lines().any(|line| line == expected) {
            return Err(ProductBrokerError::Denied(
                "worker_ready_kernel_observation_invalid",
            ));
        }
    }
    Ok(())
}

fn exec_worker_child(
    control: RawFd,
    rootfs: RawFd,
    executable: RawFd,
    dev_null: RawFd,
    parent: u32,
) -> ! {
    // SAFETY: single-threaded post-fork branch; all operations are
    // async-signal-safe and failure exits without unwinding.
    unsafe {
        let mut empty_mask: libc::sigset_t = zeroed();
        if libc::sigemptyset(&mut empty_mask) != 0
            // The broker deliberately blocks its lifecycle signals for
            // signalfd. A forked worker/model must not inherit that broker-only
            // mask across exec.
            || libc::sigprocmask(libc::SIG_SETMASK, &empty_mask, std::ptr::null_mut()) != 0
            || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
            || libc::getppid() != parent as libc::pid_t
            || duplicate_to_fixed(control, WORKER_CONTROL_FD) != 0
            || duplicate_to_fixed(rootfs, WORKER_ROOTFS_FD) != 0
            || duplicate_to_fixed(executable, WORKER_IMAGE_FD) != 0
            || duplicate_to_fixed(dev_null, WORKER_DEV_NULL_FD) != 0
        {
            libc::_exit(126);
        }
        let argument = c"trillionnium-shell-exec-worker-userdebug";
        let arguments = [argument.as_ptr(), std::ptr::null()];
        let environment = [std::ptr::null::<libc::c_char>()];
        let empty = c"";
        libc::syscall(
            libc::SYS_execveat,
            WORKER_IMAGE_FD,
            empty.as_ptr(),
            arguments.as_ptr(),
            environment.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
        libc::_exit(127);
    }
}

unsafe fn duplicate_to_fixed(source: RawFd, destination: RawFd) -> libc::c_int {
    if source == destination {
        // SAFETY: descriptor is live; clearing CLOEXEC is required for the
        // inherited worker control/rootfs descriptors and harmless for execfd.
        let flags = unsafe { libc::fcntl(source, libc::F_GETFD) };
        if flags < 0 {
            return -1;
        }
        // SAFETY: same live descriptor.
        return unsafe { libc::fcntl(source, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    }
    // SAFETY: dup3 atomically replaces only the fixed destination in child.
    unsafe { libc::dup3(source, destination, 0) }
}

fn duplicate_at_least(descriptor: RawFd, minimum: RawFd) -> Result<OwnedFd> {
    // SAFETY: returns a fresh close-on-exec descriptor or -1.
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, minimum) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: duplicate is fresh and uniquely owned.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn open_pidfd(pid: libc::pid_t) -> Result<OwnedFd> {
    // SAFETY: pid is the freshly-forked child and flags zero are required.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: pidfd_open returned a fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn open_fixed_file(path: &str) -> Result<OwnedFd> {
    open_fixed(path, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
}

fn open_fixed_directory(path: &str) -> Result<OwnedFd> {
    open_fixed(
        path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )
}

fn open_fixed(path: &str, flags: libc::c_int) -> Result<OwnedFd> {
    let path = CString::new(path).map_err(|_| ProductBrokerError::Denied("fixed_path_invalid"))?;
    // SAFETY: path is NUL-terminated and successful ownership transfers.
    let descriptor = unsafe { libc::open(path.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is fresh and uniquely owned.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn validate_worker_executable(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o022 != 0
        || metadata.st_mode & 0o111 == 0
    {
        return Err(ProductBrokerError::Denied(
            "worker_executable_custody_invalid",
        ));
    }
    Ok(())
}

fn validate_rootfs(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || metadata.st_mode & 0o022 != 0
    {
        return Err(ProductBrokerError::Denied("rootfs_custody_invalid"));
    }
    Ok(())
}

fn validate_scope_parent(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || metadata.st_mode & 0o777 != 0o711
    {
        return Err(ProductBrokerError::Denied("scope_parent_custody_invalid"));
    }
    Ok(())
}

fn validate_scope_leaf(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != 0
        || metadata.st_gid != SHELL_WORKER_GID
        || metadata.st_mode & 0o777 != 0o770
    {
        return Err(ProductBrokerError::Denied("scope_leaf_custody_invalid"));
    }
    Ok(())
}

fn validate_approved_executable(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o022 != 0
        || metadata.st_mode & 0o111 == 0
    {
        return Err(ProductBrokerError::Denied(
            "approved_executable_custody_invalid",
        ));
    }
    Ok(())
}

fn validate_root_owned_policy_file(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o777 != 0o444
    {
        return Err(ProductBrokerError::Denied(
            "executable_policy_custody_invalid",
        ));
    }
    Ok(())
}

fn read_bounded_descriptor(descriptor: RawFd, maximum: usize) -> Result<Vec<u8>> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_size <= 0 || metadata.st_size as usize > maximum {
        return Err(ProductBrokerError::Denied("bounded_file_size_invalid"));
    }
    let mut bytes = vec![0_u8; metadata.st_size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        // SAFETY: remaining buffer is writable and pread preserves fd offset.
        let count = unsafe {
            libc::pread(
                descriptor,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
                offset as i64,
            )
        };
        if count <= 0 {
            return Err(if count == 0 {
                ProductBrokerError::Denied("bounded_file_short_read")
            } else {
                std::io::Error::last_os_error().into()
            });
        }
        offset += count as usize;
    }
    Ok(bytes)
}

fn duplicate_descriptor(descriptor: RawFd) -> Result<OwnedFd> {
    // SAFETY: returns a fresh close-on-exec descriptor or -1.
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: duplicate is fresh and uniquely owned.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn create_or_open_scope_leaf(
    parent: RawFd,
    leaf_name: &str,
    marker_name: &str,
    marker_binding: &str,
) -> Result<OwnedFd> {
    if !trillionnium_os_types::is_nonzero_lower_sha256(marker_binding) {
        return Err(ProductBrokerError::Denied("scope_marker_invalid"));
    }
    let leaf_name_c = CString::new(leaf_name)
        .map_err(|_| ProductBrokerError::Denied("scope_leaf_name_invalid"))?;
    if leaf_name.contains('/') || leaf_name.is_empty() || matches!(leaf_name, "." | "..") {
        return Err(ProductBrokerError::Denied("scope_leaf_name_invalid"));
    }
    let complete = reconcile_scope_pair(
        parent,
        leaf_name,
        marker_name,
        marker_binding,
        OrphanLeafContentsV1::RequireEmpty,
    )?;
    let created = if complete {
        false
    } else {
        // SAFETY: reconciliation proved both exact entries absent under this
        // root-owned parent; no worker can create sibling names here.
        if unsafe { libc::mkdirat(parent, leaf_name_c.as_ptr(), 0o770) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        true
    };
    let leaf = match open_beneath_component_walk(
        parent,
        leaf_name,
        libc::O_RDONLY | libc::O_DIRECTORY,
        RequiredFileTypeV1::Directory,
    ) {
        Ok(leaf) => leaf,
        Err(error) => return Err(ProductBrokerError::RetainedPath(error)),
    };
    if created {
        // SAFETY: leaf is a newly-created retained directory.
        if unsafe { libc::fchown(leaf.as_raw_fd(), 0, SHELL_WORKER_GID) } != 0
            || unsafe { libc::fchmod(leaf.as_raw_fd(), 0o770) } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        // Ownership markers live as siblings in the root-owned 0711 parent,
        // never inside the gid5903-writable leaf where they could be renamed.
        write_scope_marker(parent, marker_name, marker_binding)?;
        sync_directory(leaf.as_raw_fd())?;
        sync_directory(parent)?;
    } else {
        validate_scope_marker(parent, marker_name, marker_binding)?;
    }
    validate_scope_leaf(leaf.as_raw_fd())?;
    Ok(leaf)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrphanLeafContentsV1 {
    RequireEmpty,
    RemoveAfterDispatch,
}

#[derive(Clone, Copy)]
struct ScopePairCustodyV1 {
    owner_uid: u32,
    initial_gid: u32,
    worker_gid: u32,
    marker_uid: u32,
    marker_gid: u32,
}

const PRODUCT_SCOPE_PAIR_CUSTODY: ScopePairCustodyV1 = ScopePairCustodyV1 {
    owner_uid: 0,
    initial_gid: 0,
    worker_gid: SHELL_WORKER_GID,
    marker_uid: 0,
    marker_gid: 0,
};

/// Repairs only the two crash intermediates that this broker can create for a
/// known ledger identity. A nonempty marker-less leaf is removable only after
/// durable DISPATCHED and the caller's cgroup-empty proof.
/// Returns true only when the complete, validated pair already exists.
fn reconcile_scope_pair(
    parent: RawFd,
    leaf_name: &str,
    marker_name: &str,
    marker_binding: &str,
    orphan_contents: OrphanLeafContentsV1,
) -> Result<bool> {
    reconcile_scope_pair_with_custody(
        parent,
        leaf_name,
        marker_name,
        marker_binding,
        orphan_contents,
        PRODUCT_SCOPE_PAIR_CUSTODY,
    )
}

fn reconcile_scope_pair_with_custody(
    parent: RawFd,
    leaf_name: &str,
    marker_name: &str,
    marker_binding: &str,
    orphan_contents: OrphanLeafContentsV1,
    custody: ScopePairCustodyV1,
) -> Result<bool> {
    let leaf_name_c = CString::new(leaf_name)
        .map_err(|_| ProductBrokerError::Denied("scope_leaf_name_invalid"))?;
    let marker_name_c = CString::new(marker_name)
        .map_err(|_| ProductBrokerError::Denied("scope_marker_name_invalid"))?;
    let leaf_metadata = optional_metadata_at(parent, &leaf_name_c)?;
    let marker_metadata = optional_metadata_at(parent, &marker_name_c)?;
    match (leaf_metadata, marker_metadata) {
        (None, None) => Ok(false),
        (Some(observed), Some(_)) => {
            let marker_value = read_scope_marker_with_custody(parent, marker_name, custody)?;
            if marker_value == marker_binding {
                validate_complete_scope_leaf(parent, leaf_name, observed, custody)?;
                return Ok(true);
            }
            // The only recoverable noncanonical marker is an empty/short
            // write beside the exact empty leaf created by this transaction.
            // A wrong complete 64-byte binding is a collision, never adopted.
            if marker_value.len() >= 64 {
                return Err(ProductBrokerError::Denied("scope_marker_binding_invalid"));
            }
            remove_recoverable_orphan_leaf(
                parent,
                &leaf_name_c,
                observed,
                leaf_name,
                OrphanLeafContentsV1::RequireEmpty,
                custody,
            )?;
            if unsafe { libc::unlinkat(parent, marker_name_c.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            sync_directory(parent)?;
            Ok(false)
        }
        (Some(observed), None) => {
            remove_recoverable_orphan_leaf(
                parent,
                &leaf_name_c,
                observed,
                leaf_name,
                orphan_contents,
                custody,
            )?;
            Ok(false)
        }
        (None, Some(_)) => {
            let marker_value = read_scope_marker_with_custody(parent, marker_name, custody)?;
            if marker_value != marker_binding && marker_value.len() >= 64 {
                return Err(ProductBrokerError::Denied("scope_marker_binding_invalid"));
            }
            if unsafe { libc::unlinkat(parent, marker_name_c.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            sync_directory(parent)?;
            Ok(false)
        }
    }
}

fn validate_complete_scope_leaf(
    parent: RawFd,
    leaf_name: &str,
    observed: libc::stat,
    custody: ScopePairCustodyV1,
) -> Result<()> {
    let leaf = open_beneath_component_walk(
        parent,
        leaf_name,
        libc::O_RDONLY | libc::O_DIRECTORY,
        RequiredFileTypeV1::Directory,
    )?;
    let opened = descriptor_metadata(leaf.as_raw_fd())?;
    if opened.st_dev != observed.st_dev
        || opened.st_ino != observed.st_ino
        || opened.st_uid != custody.owner_uid
        || opened.st_gid != custody.worker_gid
        || opened.st_mode & 0o777 != 0o770
    {
        return Err(ProductBrokerError::Denied("scope_leaf_custody_invalid"));
    }
    Ok(())
}

fn remove_recoverable_orphan_leaf(
    parent: RawFd,
    leaf_name_c: &std::ffi::CStr,
    observed: libc::stat,
    leaf_name: &str,
    orphan_contents: OrphanLeafContentsV1,
    custody: ScopePairCustodyV1,
) -> Result<()> {
    let leaf = open_beneath_component_walk(
        parent,
        leaf_name,
        libc::O_RDONLY | libc::O_DIRECTORY,
        RequiredFileTypeV1::Directory,
    )?;
    let opened = descriptor_metadata(leaf.as_raw_fd())?;
    let parent_metadata = descriptor_metadata(parent)?;
    let recoverable_mode = matches!(opened.st_mode & 0o777, 0o700 | 0o750 | 0o770);
    if opened.st_dev != parent_metadata.st_dev
        || opened.st_dev != observed.st_dev
        || opened.st_ino != observed.st_ino
        || opened.st_uid != custody.owner_uid
        || !matches!(opened.st_gid, gid if gid == custody.initial_gid || gid == custody.worker_gid)
        || !recoverable_mode
    {
        return Err(ProductBrokerError::Denied(
            "orphan_scope_leaf_custody_invalid",
        ));
    }
    match orphan_contents {
        OrphanLeafContentsV1::RequireEmpty => require_directory_empty(leaf.as_raw_fd())?,
        OrphanLeafContentsV1::RemoveAfterDispatch => {
            let deadline = boottime_ms()?.saturating_add(2_000);
            remove_directory_contents(
                leaf.as_raw_fd(),
                opened.st_dev,
                deadline,
                0,
                custody.owner_uid,
                custody.initial_gid,
            )?;
            sync_directory(leaf.as_raw_fd())?;
        }
    }
    if unsafe { libc::unlinkat(parent, leaf_name_c.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    sync_directory(parent)
}

fn descriptor_metadata(descriptor: RawFd) -> Result<libc::stat> {
    // SAFETY: zero is valid initial representation; fstat initializes it.
    let mut metadata: libc::stat = unsafe { zeroed() };
    // SAFETY: metadata is writable and descriptor remains live.
    if unsafe { libc::fstat(descriptor, &mut metadata) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(metadata)
}

fn openat_directory(parent: &File, name: &str) -> Result<File> {
    let name = CString::new(name).map_err(|_| ProductBrokerError::Denied("name_invalid"))?;
    // SAFETY: name is a fixed basename and ownership transfers on success.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is fresh and uniquely owned.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn validate_cgroup2(descriptor: RawFd) -> Result<()> {
    // SAFETY: zero is a valid initial representation and fstatfs initializes.
    let mut filesystem: libc::statfs = unsafe { zeroed() };
    // SAFETY: filesystem is writable and descriptor remains live.
    if unsafe { libc::fstatfs(descriptor, &mut filesystem) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if filesystem.f_type as u64 != CGROUP2_SUPER_MAGIC {
        return Err(ProductBrokerError::Denied("cgroup_v2_required"));
    }
    Ok(())
}

fn read_cgroup_file(directory: &File, name: &str) -> Result<String> {
    let name = CString::new(name).map_err(|_| ProductBrokerError::Denied("cgroup_name_invalid"))?;
    // SAFETY: name is a fixed basename under retained cgroup directory.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is fresh and uniquely owned.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let mut value = String::new();
    std::io::Read::by_ref(&mut file)
        .take(64 * 1024)
        .read_to_string(&mut value)?;
    Ok(value)
}

fn write_cgroup_file(directory: &File, name: &str, value: &str) -> Result<()> {
    let name = CString::new(name).map_err(|_| ProductBrokerError::Denied("cgroup_name_invalid"))?;
    // SAFETY: name is a fixed basename under retained cgroup directory.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is fresh and uniquely owned.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    file.write_all(value.as_bytes())?;
    Ok(())
}

fn require_cgroup_value(directory: &File, name: &str, expected: &str) -> Result<()> {
    if read_cgroup_file(directory, name)?.trim() != expected {
        return Err(ProductBrokerError::Denied("cgroup_value_not_observed"));
    }
    Ok(())
}

fn read_process_record(pid: u32, name: &str) -> Result<String> {
    let path = format!("/proc/{pid}/{name}");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let mut value = String::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_PROC_RECORD_BYTES + 1)
        .read_to_string(&mut value)?;
    if value.is_empty() || value.len() as u64 > MAX_PROC_RECORD_BYTES {
        return Err(ProductBrokerError::Denied("proc_record_invalid"));
    }
    Ok(value)
}

fn read_process_selinux(pid: u32) -> Result<String> {
    Ok(read_process_record(pid, "attr/current")?
        .trim_end_matches(['\n', '\0'])
        .to_string())
}

fn process_starttime_ticks(pid: u32) -> Result<u64> {
    let record = read_process_record(pid, "stat")?;
    let close = record
        .rfind(')')
        .ok_or(ProductBrokerError::Denied("proc_stat_invalid"))?;
    record
        .get(close + 2..)
        .ok_or(ProductBrokerError::Denied("proc_stat_invalid"))?
        .split_ascii_whitespace()
        .nth(19)
        .ok_or(ProductBrokerError::Denied("proc_stat_invalid"))?
        .parse()
        .map_err(|_| ProductBrokerError::Denied("proc_stat_invalid"))
}

fn write_scope_marker(directory: RawFd, marker: &str, binding_sha256: &str) -> Result<()> {
    if !trillionnium_os_types::is_nonzero_lower_sha256(binding_sha256) {
        return Err(ProductBrokerError::Denied("scope_marker_invalid"));
    }
    let name = CString::new(marker)
        .map_err(|_| ProductBrokerError::Denied("scope_marker_name_invalid"))?;
    // SAFETY: name is fixed and directory is a newly-created retained leaf.
    let descriptor = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is fresh and uniquely owned.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    file.write_all(binding_sha256.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn validate_scope_marker(directory: RawFd, marker: &str, binding_sha256: &str) -> Result<()> {
    if read_scope_marker(directory, marker)? != binding_sha256 {
        return Err(ProductBrokerError::Denied("scope_marker_binding_invalid"));
    }
    Ok(())
}

fn read_scope_marker(directory: RawFd, marker: &str) -> Result<String> {
    read_scope_marker_with_custody(directory, marker, PRODUCT_SCOPE_PAIR_CUSTODY)
}

fn read_scope_marker_with_custody(
    directory: RawFd,
    marker: &str,
    custody: ScopePairCustodyV1,
) -> Result<String> {
    let name = CString::new(marker)
        .map_err(|_| ProductBrokerError::Denied("scope_marker_name_invalid"))?;
    // SAFETY: name is fixed under the retained exact effect leaf.
    let descriptor = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is fresh and uniquely owned.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != custody.marker_uid
        || metadata.gid() != custody.marker_gid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > 64
    {
        return Err(ProductBrokerError::Denied("scope_marker_custody_invalid"));
    }
    let mut value = String::new();
    std::io::Read::by_ref(&mut file)
        .take(65)
        .read_to_string(&mut value)?;
    Ok(value)
}

fn retire_effect_tmpdir(
    parent: RawFd,
    leaf: RawFd,
    leaf_name: &str,
    marker_name: &str,
) -> Result<()> {
    let parent_metadata = descriptor_metadata(parent)?;
    let leaf_metadata = descriptor_metadata(leaf)?;
    if parent_metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || leaf_metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || parent_metadata.st_dev != leaf_metadata.st_dev
    {
        return Err(ProductBrokerError::Denied(
            "tmpdir_retirement_custody_invalid",
        ));
    }
    let deadline = boottime_ms()?.saturating_add(2_000);
    remove_directory_contents(leaf, leaf_metadata.st_dev, deadline, 0, 0, 0)?;
    sync_directory(leaf)?;
    let name =
        CString::new(leaf_name).map_err(|_| ProductBrokerError::Denied("tmpdir_name_invalid"))?;
    let observed = metadata_at(parent, &name)?;
    if observed.st_dev != leaf_metadata.st_dev || observed.st_ino != leaf_metadata.st_ino {
        return Err(ProductBrokerError::Denied("tmpdir_entry_renamed"));
    }
    // SAFETY: name identifies the exact empty retained leaf under parent.
    if unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let marker = CString::new(marker_name)
        .map_err(|_| ProductBrokerError::Denied("tmpdir_marker_name_invalid"))?;
    // SAFETY: the root-owned parent cannot be mutated by the worker and the
    // marker is one exact non-symlink owner record.
    if unsafe { libc::unlinkat(parent, marker.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    sync_directory(parent)
}

fn ensure_effect_temporary_scope_absent(
    temporary_parent: RawFd,
    request: &DirectEffectRequestV1,
    dispatch_occurred: bool,
) -> Result<()> {
    let leaf_name = effect_tmpdir_name(request)?;
    let marker_name = format!(".request-{}", request.request_sha256);
    if reconcile_scope_pair(
        temporary_parent,
        &leaf_name,
        &marker_name,
        &request.request_sha256,
        if dispatch_occurred {
            OrphanLeafContentsV1::RemoveAfterDispatch
        } else {
            OrphanLeafContentsV1::RequireEmpty
        },
    )? {
        let leaf = open_beneath_component_walk(
            temporary_parent,
            &leaf_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            RequiredFileTypeV1::Directory,
        )?;
        validate_scope_leaf(leaf.as_raw_fd())?;
        retire_effect_tmpdir(temporary_parent, leaf.as_raw_fd(), &leaf_name, &marker_name)?;
    }
    require_entry_absent(temporary_parent, &leaf_name)?;
    require_entry_absent(temporary_parent, &marker_name)?;
    sync_directory(temporary_parent)
}

fn repair_receipts_before_ready(
    ledger: &DurableShellExecLedgerV1,
    receipts: &crate::DurableShellExecReceiptStoreV1,
    worker: &ProductWorkerProxyV1,
) -> Result<()> {
    let records = ledger.records()?;
    let mut workspace_catalog = BTreeSet::new();
    for record in &records {
        let workspace_name = format!("w-{}", record.request.direct_binding_sha256);
        let workspace_marker = format!(".binding-{}", record.request.direct_binding_sha256);
        workspace_catalog.insert(workspace_name.clone());
        workspace_catalog.insert(workspace_marker.clone());
        reconcile_scope_pair(
            worker.workspace_parent.as_raw_fd(),
            &workspace_name,
            &workspace_marker,
            &record.request.direct_binding_sha256,
            OrphanLeafContentsV1::RequireEmpty,
        )?;
        // Any request that is still NOT_DISPATCHED can safely recreate its
        // per-effect temporary scope on authenticated retry. Clear both full
        // preflight leftovers and recoverable half-pairs before READY.
        ensure_effect_temporary_scope_absent(
            worker.temporary_parent.as_raw_fd(),
            &record.request,
            record.state.dispatch_occurred,
        )?;
        if matches!(
            record.state.phase,
            DirectEffectPhaseV1::Terminal | DirectEffectPhaseV1::Indeterminate
        ) {
            receipts.ensure(record)?;
        }
    }
    verify_scope_catalog(worker.workspace_parent.as_raw_fd(), &workspace_catalog)?;
    verify_scope_catalog(worker.temporary_parent.as_raw_fd(), &BTreeSet::new())?;
    receipts.verify_catalog(&records)?;
    Ok(())
}

fn verify_scope_catalog(directory: RawFd, expected_names: &BTreeSet<String>) -> Result<()> {
    for name in retained_directory_entry_names(directory)? {
        if !expected_names.contains(&name) {
            return Err(ProductBrokerError::Denied("unknown_scope_catalog_entry"));
        }
    }
    Ok(())
}

fn remove_directory_contents(
    directory: RawFd,
    device: libc::dev_t,
    deadline: u64,
    depth: usize,
    cleanup_uid: u32,
    cleanup_gid: u32,
) -> Result<()> {
    if depth > 256 {
        return Err(ProductBrokerError::Denied("tmpdir_depth_limit"));
    }
    let duplicate = duplicate_descriptor(directory)?;
    // SAFETY: fdopendir takes ownership of the duplicate only.
    let stream = unsafe { libc::fdopendir(duplicate.into_raw_fd()) };
    if stream.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            // SAFETY: pointer came from fdopendir and is owned exactly once.
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirectoryStream(stream);
    loop {
        if boottime_ms()? >= deadline {
            return Err(ProductBrokerError::Denied("tmpdir_retirement_deadline"));
        }
        // SAFETY: stream remains live and no other thread uses it.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            break;
        }
        // SAFETY: d_name is NUL-terminated within the live dirent.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let owned_name = name.to_owned();
        let before = metadata_at(directory, &owned_name)?;
        if before.st_dev != device {
            return Err(ProductBrokerError::Denied("tmpdir_device_boundary"));
        }
        if before.st_mode & libc::S_IFMT == libc::S_IFDIR {
            // The worker can create mode-000 directories. After the cgroup is
            // proven empty there is no concurrent mutator; use the broker's
            // retained CAP_CHOWN (never DAC_OVERRIDE) to take ownership and
            // make only this exact child traversable for deletion.
            if unsafe {
                libc::fchownat(
                    directory,
                    owned_name.as_ptr(),
                    cleanup_uid,
                    cleanup_gid,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
                || unsafe { libc::fchmodat(directory, owned_name.as_ptr(), 0o700, 0) } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: exact child basename, retained parent, and O_NOFOLLOW.
            let child = unsafe {
                libc::openat(
                    directory,
                    owned_name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if child < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: openat returned a fresh descriptor.
            let child = unsafe { OwnedFd::from_raw_fd(child) };
            let opened = descriptor_metadata(child.as_raw_fd())?;
            if opened.st_dev != before.st_dev || opened.st_ino != before.st_ino {
                return Err(ProductBrokerError::Denied("tmpdir_child_identity_changed"));
            }
            remove_directory_contents(
                child.as_raw_fd(),
                device,
                deadline,
                depth + 1,
                cleanup_uid,
                cleanup_gid,
            )?;
            let after = metadata_at(directory, &owned_name)?;
            if after.st_dev != opened.st_dev || after.st_ino != opened.st_ino {
                return Err(ProductBrokerError::Denied("tmpdir_child_renamed"));
            }
            // SAFETY: entry still identifies the retained empty child.
            if unsafe { libc::unlinkat(directory, owned_name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        } else {
            // SAFETY: unlinkat never follows a final symlink and is confined to
            // the retained directory. A concurrent writer is impossible after
            // the cgroup cleanup proof.
            if unsafe { libc::unlinkat(directory, owned_name.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }
    sync_directory(directory)
}

fn metadata_at(directory: RawFd, name: &std::ffi::CStr) -> Result<libc::stat> {
    // SAFETY: zero is a valid initial representation and fstatat initializes.
    let mut value: libc::stat = unsafe { zeroed() };
    // SAFETY: name is one NUL-terminated entry and AT_SYMLINK_NOFOLLOW keeps
    // the observation inside the retained directory.
    if unsafe {
        libc::fstatat(
            directory,
            name.as_ptr(),
            &mut value,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(value)
}

fn optional_metadata_at(directory: RawFd, name: &std::ffi::CStr) -> Result<Option<libc::stat>> {
    match metadata_at(directory, name) {
        Ok(value) => Ok(Some(value)),
        Err(ProductBrokerError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn retained_directory_entry_names(directory: RawFd) -> Result<Vec<String>> {
    let duplicate = duplicate_descriptor(directory)?;
    let duplicate = duplicate.into_raw_fd();
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(std::io::Error::last_os_error().into());
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error().is_some_and(|value| value != 0) {
                return Err(error.into());
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_str()
            .map_err(|_| ProductBrokerError::Denied("scope_entry_name_invalid"))?;
        if !matches!(name, "." | "..") {
            names.push(name.to_string());
        }
    }
    names.sort();
    Ok(names)
}

fn require_directory_empty(directory: RawFd) -> Result<()> {
    if retained_directory_entry_names(directory)?.is_empty() {
        Ok(())
    } else {
        Err(ProductBrokerError::Denied("orphan_scope_leaf_not_empty"))
    }
}

fn require_entry_absent(directory: RawFd, name: &str) -> Result<()> {
    let name =
        CString::new(name).map_err(|_| ProductBrokerError::Denied("absent_entry_name_invalid"))?;
    match metadata_at(directory, &name) {
        Ok(_) => Err(ProductBrokerError::Denied("unexpected_unowned_scope_entry")),
        Err(ProductBrokerError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn sync_directory(descriptor: RawFd) -> Result<()> {
    // SAFETY: descriptor is a retained directory; fsync does not retain it.
    if unsafe { libc::fsync(descriptor) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn current_pid() -> Result<u32> {
    // SAFETY: getter has no side effects.
    u32::try_from(unsafe { libc::getpid() })
        .map_err(|_| ProductBrokerError::Denied("broker_pid_invalid"))
}

fn boottime_ms() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is writable storage for CLOCK_BOOTTIME.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let seconds =
        u64::try_from(value.tv_sec).map_err(|_| ProductBrokerError::Denied("boottime_invalid"))?;
    let nanos =
        u64::try_from(value.tv_nsec).map_err(|_| ProductBrokerError::Denied("boottime_invalid"))?;
    Ok(seconds
        .saturating_mul(1000)
        .saturating_add(nanos / 1_000_000))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::Path;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::*;

    fn open_test_directory(path: &Path) -> OwnedFd {
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let descriptor = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        assert!(descriptor >= 0);
        unsafe { OwnedFd::from_raw_fd(descriptor) }
    }

    fn test_scope_custody() -> ScopePairCustodyV1 {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        ScopePairCustodyV1 {
            owner_uid: uid,
            initial_gid: gid,
            worker_gid: gid,
            marker_uid: uid,
            marker_gid: gid,
        }
    }

    fn seed_scope_leaf(root: &Path, name: &str, nonempty: bool) {
        let leaf = root.join(name);
        fs::create_dir(&leaf).unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o770)).unwrap();
        if nonempty {
            fs::write(leaf.join("effect-output"), b"owned").unwrap();
        }
    }

    fn seed_scope_marker(root: &Path, name: &str, value: &str) {
        let marker = root.join(name);
        fs::write(&marker, value.as_bytes()).unwrap();
        fs::set_permissions(marker, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn scope_pair_power_loss_states_are_reconciled_without_adoption() {
        let binding = "a".repeat(64);
        let custody = test_scope_custody();

        for marker_value in [binding.as_str(), "short-prefix"] {
            let root = TempDir::new().unwrap();
            seed_scope_marker(root.path(), ".marker", marker_value);
            let parent = open_test_directory(root.path());
            assert!(
                !reconcile_scope_pair_with_custody(
                    parent.as_raw_fd(),
                    "leaf",
                    ".marker",
                    &binding,
                    OrphanLeafContentsV1::RequireEmpty,
                    custody,
                )
                .unwrap()
            );
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        }

        let root = TempDir::new().unwrap();
        seed_scope_leaf(root.path(), "leaf", false);
        let parent = open_test_directory(root.path());
        assert!(
            !reconcile_scope_pair_with_custody(
                parent.as_raw_fd(),
                "leaf",
                ".marker",
                &binding,
                OrphanLeafContentsV1::RequireEmpty,
                custody,
            )
            .unwrap()
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);

        let root = TempDir::new().unwrap();
        seed_scope_leaf(root.path(), "leaf", false);
        seed_scope_marker(root.path(), ".marker", "short-prefix");
        let parent = open_test_directory(root.path());
        assert!(
            !reconcile_scope_pair_with_custody(
                parent.as_raw_fd(),
                "leaf",
                ".marker",
                &binding,
                OrphanLeafContentsV1::RequireEmpty,
                custody,
            )
            .unwrap()
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);

        let root = TempDir::new().unwrap();
        seed_scope_leaf(root.path(), "leaf", false);
        seed_scope_marker(root.path(), ".marker", &binding);
        let parent = open_test_directory(root.path());
        assert!(
            reconcile_scope_pair_with_custody(
                parent.as_raw_fd(),
                "leaf",
                ".marker",
                &binding,
                OrphanLeafContentsV1::RequireEmpty,
                custody,
            )
            .unwrap()
        );
        assert!(root.path().join("leaf").is_dir());
        assert!(root.path().join(".marker").is_file());
    }

    #[test]
    fn wrong_complete_marker_and_nonempty_undispatched_orphan_fail_closed() {
        let binding = "a".repeat(64);
        let custody = test_scope_custody();

        let root = TempDir::new().unwrap();
        seed_scope_marker(root.path(), ".marker", &"b".repeat(64));
        let parent = open_test_directory(root.path());
        assert!(
            reconcile_scope_pair_with_custody(
                parent.as_raw_fd(),
                "leaf",
                ".marker",
                &binding,
                OrphanLeafContentsV1::RequireEmpty,
                custody,
            )
            .is_err()
        );
        assert!(root.path().join(".marker").is_file());

        let root = TempDir::new().unwrap();
        seed_scope_leaf(root.path(), "leaf", true);
        let parent = open_test_directory(root.path());
        assert!(
            reconcile_scope_pair_with_custody(
                parent.as_raw_fd(),
                "leaf",
                ".marker",
                &binding,
                OrphanLeafContentsV1::RequireEmpty,
                custody,
            )
            .is_err()
        );
        assert!(root.path().join("leaf/effect-output").is_file());
    }

    #[test]
    fn dispatched_nonempty_markerless_scope_is_cleanup_only_and_idempotent() {
        let binding = "a".repeat(64);
        let custody = test_scope_custody();
        let root = TempDir::new().unwrap();
        seed_scope_leaf(root.path(), "leaf", true);
        let parent = open_test_directory(root.path());
        assert!(
            !reconcile_scope_pair_with_custody(
                parent.as_raw_fd(),
                "leaf",
                ".marker",
                &binding,
                OrphanLeafContentsV1::RemoveAfterDispatch,
                custody,
            )
            .unwrap()
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        assert!(
            !reconcile_scope_pair_with_custody(
                parent.as_raw_fd(),
                "leaf",
                ".marker",
                &binding,
                OrphanLeafContentsV1::RemoveAfterDispatch,
                custody,
            )
            .unwrap()
        );
    }

    #[test]
    fn broker_uses_exact_worker_group_and_forbids_both_dac_capabilities() {
        let exact = format!(
            "Groups:\t{1} {2}\nCapInh:\t0000000000000000\nCapPrm:\t{0:016x}\nCapEff:\t{0:016x}\nCapBnd:\tffffffffffffffff\nCapAmb:\t0000000000000000\n",
            BROKER_EFFECTIVE_CAPABILITIES, ANDROID_SYSTEM_GID, SHELL_WORKER_GID,
        );
        validate_broker_capabilities(&exact).unwrap();
        validate_broker_capabilities(&exact.replace(
            &format!("Groups:\t{ANDROID_SYSTEM_GID} {SHELL_WORKER_GID}"),
            &format!("Groups:\t{SHELL_WORKER_GID} {ANDROID_SYSTEM_GID}"),
        ))
        .unwrap();

        let with_read_search = exact.replace(
            &format!("{BROKER_EFFECTIVE_CAPABILITIES:016x}"),
            &format!(
                "{:016x}",
                BROKER_EFFECTIVE_CAPABILITIES | BROKER_CAP_DAC_READ_SEARCH
            ),
        );
        assert!(validate_broker_capabilities(&with_read_search).is_err());

        let with_override = exact.replace(
            &format!("{BROKER_EFFECTIVE_CAPABILITIES:016x}"),
            &format!(
                "{:016x}",
                BROKER_EFFECTIVE_CAPABILITIES | BROKER_CAP_DAC_OVERRIDE
            ),
        );
        assert!(validate_broker_capabilities(&with_override).is_err());
        assert!(
            validate_broker_capabilities(&exact.replace(
                &format!("Groups:\t{ANDROID_SYSTEM_GID} {SHELL_WORKER_GID}"),
                &format!("Groups:\t{SHELL_WORKER_GID}"),
            ))
            .is_err()
        );
        assert!(
            validate_broker_capabilities(&exact.replace(
                &format!("Groups:\t{ANDROID_SYSTEM_GID} {SHELL_WORKER_GID}"),
                &format!("Groups:\t{ANDROID_SYSTEM_GID} {SHELL_WORKER_GID} 6000"),
            ))
            .is_err()
        );
    }

    #[test]
    fn cwd_user_path_absence_is_policy_but_dac_or_io_drift_is_fatal() {
        assert!(matches!(
            classify_cwd_path_error(RetainedPathError::InvalidRelativePath),
            ProductBrokerError::PolicyRejected("cwd_preflight_open_failed")
        ));
        assert!(matches!(
            classify_cwd_path_error(RetainedPathError::Io(std::io::Error::from_raw_os_error(
                libc::ENOENT
            ))),
            ProductBrokerError::PolicyRejected("cwd_preflight_open_failed")
        ));
        assert!(matches!(
            classify_cwd_path_error(RetainedPathError::Io(std::io::Error::from_raw_os_error(
                libc::EACCES
            ))),
            ProductBrokerError::RetainedPath(_)
        ));
        assert!(matches!(
            classify_cwd_path_error(RetainedPathError::Io(std::io::Error::from_raw_os_error(
                libc::EIO
            ))),
            ProductBrokerError::RetainedPath(_)
        ));
    }

    #[test]
    fn predictable_registration_capacity_exhaustion_is_peer_local_only() {
        assert!(matches!(
            registration_capacity_error(crate::durable::DurableError::CapacityExhausted),
            ProductBrokerError::PeerRejected("durable_registration_capacity_exhausted")
        ));
        assert!(matches!(
            registration_capacity_error(crate::durable::DurableError::SnapshotInvalid),
            ProductBrokerError::Durable(crate::durable::DurableError::SnapshotInvalid)
        ));
    }

    #[test]
    fn durable_capacity_reservation_requires_one_shared_filesystem() {
        require_shared_durable_capacity_device(17, 17).unwrap();
        assert!(matches!(
            require_shared_durable_capacity_device(17, 18),
            Err(ProductBrokerError::Denied(
                "durable_capacity_roots_device_mismatch"
            ))
        ));

        let outer = TempDir::new().unwrap();
        let ledger_root = outer.path().join("ledger");
        let receipt_root = outer.path().join("receipts");
        fs::create_dir(&ledger_root).unwrap();
        fs::create_dir(&receipt_root).unwrap();
        fs::set_permissions(&ledger_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&receipt_root, fs::Permissions::from_mode(0o700)).unwrap();
        let ledger = DurableShellExecLedgerV1::open(&ledger_root).unwrap();
        let receipts = crate::DurableShellExecReceiptStoreV1::open(&receipt_root).unwrap();
        verify_shared_durable_capacity_device(&ledger, &receipts).unwrap();
    }

    #[test]
    fn cleanup_traverses_mode_zero_nested_tree_and_unlinks_symlink() {
        let root = TempDir::new().unwrap();
        let mut current = root.path().join("level-0");
        fs::create_dir(&current).unwrap();
        let mut directories = vec![current.clone()];
        for index in 1..32 {
            current = current.join(format!("level-{index}"));
            fs::create_dir(&current).unwrap();
            directories.push(current.clone());
        }
        fs::write(current.join("value"), b"effect-owned").unwrap();
        symlink("/", current.join("never-follow")).unwrap();
        for directory in directories.iter().rev() {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o000)).unwrap();
        }
        let root_path = CString::new(root.path().as_os_str().as_encoded_bytes()).unwrap();
        let root_fd = unsafe {
            libc::open(
                root_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(root_fd >= 0);
        let root_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };
        let metadata = descriptor_metadata(root_fd.as_raw_fd()).unwrap();
        remove_directory_contents(
            root_fd.as_raw_fd(),
            metadata.st_dev,
            boottime_ms().unwrap() + 30_000,
            0,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
        )
        .unwrap();
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn peer_disconnect_watcher_sets_request_cancellation() {
        let (watched, peer) = seqpacket_pair().unwrap();
        let connection = ShellExecSeqpacketV1::from_owned_descriptor_for_test(watched);
        let cancellation = Arc::new(CancellationTokenV1::default());
        let watcher = DisconnectWatcherV1::start(&connection, Arc::clone(&cancellation)).unwrap();
        drop(peer);
        let deadline = Instant::now() + Duration::from_secs(1);
        while !cancellation.is_cancelled() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
        assert!(cancellation.is_cancelled());
        watcher.stop();
    }
}
