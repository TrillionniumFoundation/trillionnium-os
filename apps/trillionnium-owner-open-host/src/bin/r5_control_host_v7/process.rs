#[derive(Debug)]
enum JobHostMessage {
    Input(Vec<u8>),
    InputEof,
    InputError(String),
    CoreLine(Vec<u8>),
    CoreComplete(Result<(), String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelloBarrierState {
    Open,
    AwaitingAck,
    AwaitingTurnAccepted,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeferredJobDisposition {
    Dispatch,
    ResourceExhausted,
}

#[derive(Debug)]
struct DeferredJob {
    frame: RunTurnFrame,
    disposition: DeferredJobDisposition,
}

#[derive(Debug)]
struct PendingProtocolError {
    code: String,
    message: String,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum DeferredAction {
    Job(DeferredJob),
    ProtocolError(PendingProtocolError),
}

#[derive(Debug, Clone)]
struct BarrierFailure {
    code: String,
    message: String,
}

#[derive(Debug)]
struct BarrierRelease {
    actions: VecDeque<DeferredAction>,
    dropped_jobs: u64,
    dropped_protocol_errors: u64,
    failure: Option<BarrierFailure>,
    control_seq: Option<Arc<AtomicU64>>,
    connection_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeferredAdmission {
    Dispatch,
    ResourceExhausted,
    Dropped,
}

#[derive(Debug)]
struct HelloJobBarrier {
    state: HelloBarrierState,
    hello_seen: bool,
    /// The optional hello is a connection preface, not a renegotiation point
    /// after a direct or previously completed turn.
    turn_started: bool,
    hello_ack_pending: bool,
    turn_accept_pending: bool,
    turn_active: bool,
    deferred: VecDeque<DeferredAction>,
    deferred_dispatch_count: usize,
    deferred_dispatch_bytes: usize,
    deferred_resource_error_count: usize,
    deferred_resource_error_bytes: usize,
    deferred_protocol_error_count: usize,
    deferred_protocol_error_bytes: usize,
    dropped_jobs: u64,
    dropped_protocol_errors: u64,
    failure: Option<BarrierFailure>,
    control_seq: Option<Arc<AtomicU64>>,
    connection_id: Option<String>,
}

impl Default for HelloJobBarrier {
    fn default() -> Self {
        Self {
            state: HelloBarrierState::Open,
            hello_seen: false,
            turn_started: false,
            hello_ack_pending: false,
            turn_accept_pending: false,
            turn_active: false,
            deferred: VecDeque::new(),
            deferred_dispatch_count: 0,
            deferred_dispatch_bytes: 0,
            deferred_resource_error_count: 0,
            deferred_resource_error_bytes: 0,
            deferred_protocol_error_count: 0,
            deferred_protocol_error_bytes: 0,
            dropped_jobs: 0,
            dropped_protocol_errors: 0,
            failure: None,
            control_seq: None,
            connection_id: None,
        }
    }
}

impl HelloJobBarrier {
    fn configure_control_seq(&mut self, control_seq: Arc<AtomicU64>, connection_id: String) {
        self.control_seq = Some(control_seq);
        self.connection_id = Some(connection_id);
    }

    /// Observe the first connection hello.  A connection has one hello
    /// boundary; subsequent hello frames are protocol errors and are never
    /// forwarded to the core (otherwise a peer could reopen the gate).
    fn observe_hello(&mut self) -> bool {
        if self.state == HelloBarrierState::Failed {
            self.defer_protocol_error(
                "hello_unavailable",
                "turn core is unavailable; a repeated hello was rejected",
            );
            return false;
        }
        if self.hello_seen {
            self.defer_protocol_error(
                "duplicate_hello",
                "only one hello is permitted on a Host connection",
            );
            return false;
        }
        if self.turn_started {
            self.defer_protocol_error(
                "hello_out_of_order",
                "hello is only permitted before the first turn.start on a Host connection",
            );
            return false;
        }
        self.hello_seen = true;
        self.hello_ack_pending = true;
        self.refresh_state();
        true
    }

    /// Mark a turn.start boundary before forwarding it to the turn core. This
    /// gate is independent of the hello gate, so a direct turn.start followed
    /// by pipelined job requests cannot let local effects leapfrog
    /// turn.accepted.
    fn observe_turn_start(&mut self) -> bool {
        if self.state == HelloBarrierState::Failed {
            self.defer_protocol_error(
                "turn_unavailable",
                "turn core is unavailable; turn.start was rejected",
            );
            return false;
        }
        if self.turn_active || self.turn_accept_pending {
            self.defer_protocol_error(
                "duplicate_turn_start",
                "only one active turn is permitted on a Host connection",
            );
            return false;
        }
        self.turn_started = true;
        self.turn_accept_pending = true;
        self.refresh_state();
        true
    }

    fn observe_turn_end(&mut self) {
        // A terminal core frame closes the active-turn admission window. A
        // subsequent turn.start may establish a fresh accepted gate.
        self.turn_active = false;
    }

    fn mark_turn_accepted(&mut self) -> Option<BarrierRelease> {
        if !self.turn_accept_pending {
            return None;
        }
        self.turn_accept_pending = false;
        self.turn_active = true;
        self.refresh_state();
        self.take_release_if_open()
    }

    fn acknowledge_turn(&mut self) -> Option<BarrierRelease> {
        self.mark_turn_accepted()
    }

    fn refresh_state(&mut self) {
        self.state = if self.state == HelloBarrierState::Failed {
            HelloBarrierState::Failed
        } else if self.hello_ack_pending {
            HelloBarrierState::AwaitingAck
        } else if self.turn_accept_pending {
            HelloBarrierState::AwaitingTurnAccepted
        } else {
            HelloBarrierState::Open
        };
    }

    fn awaiting_ack(&self) -> bool {
        self.hello_ack_pending
    }

    fn awaiting_turn_accepted(&self) -> bool {
        self.turn_accept_pending
    }

    fn pending(&self) -> bool {
        self.hello_ack_pending || self.turn_accept_pending
    }

    fn failed(&self) -> bool {
        self.state == HelloBarrierState::Failed
    }

    /// Retain a pipelined job when a handshake is pending.  The dispatch
    /// budget intentionally leaves a bounded tail for explicit
    /// `resource_exhausted` responses.  If both budgets are exhausted, only a
    /// saturating count is kept; the process remains alive and emits a summary
    /// error when the gate resolves.
    fn defer(&mut self, frame: RunTurnFrame, encoded_bytes: usize) -> DeferredAdmission {
        let dispatch_frame_limit = MAX_HELLO_DEFERRED_JOB_FRAMES
            .saturating_sub(MAX_HELLO_DEFERRED_RESOURCE_ERRORS);
        let dispatch_byte_limit = MAX_HELLO_DEFERRED_JOB_BYTES
            .saturating_sub(MAX_HELLO_DEFERRED_RESOURCE_ERROR_BYTES);
        if self.deferred_dispatch_count < dispatch_frame_limit
            && self
                .deferred_dispatch_bytes
                .checked_add(encoded_bytes)
                .is_some_and(|next| next <= dispatch_byte_limit)
        {
            self.deferred_dispatch_count = self.deferred_dispatch_count.saturating_add(1);
            self.deferred_dispatch_bytes = self
                .deferred_dispatch_bytes
                .saturating_add(encoded_bytes);
            self.deferred.push_back(DeferredAction::Job(DeferredJob {
                frame,
                disposition: DeferredJobDisposition::Dispatch,
            }));
            return DeferredAdmission::Dispatch;
        }

        if self.deferred.len() < MAX_HELLO_DEFERRED_JOB_FRAMES
            && self.deferred_resource_error_count < MAX_HELLO_DEFERRED_RESOURCE_ERRORS
            && self
                .deferred_resource_error_bytes
                .checked_add(encoded_bytes)
                .is_some_and(|next| next <= MAX_HELLO_DEFERRED_RESOURCE_ERROR_BYTES)
        {
            self.deferred_resource_error_count = self
                .deferred_resource_error_count
                .saturating_add(1);
            self.deferred_resource_error_bytes = self
                .deferred_resource_error_bytes
                .saturating_add(encoded_bytes);
            self.deferred.push_back(DeferredAction::Job(DeferredJob {
                frame,
                disposition: DeferredJobDisposition::ResourceExhausted,
            }));
            return DeferredAdmission::ResourceExhausted;
        }

        self.dropped_jobs = self.dropped_jobs.saturating_add(1);
        DeferredAdmission::Dropped
    }

    fn defer_protocol_error(&mut self, code: &str, message: &str) {
        let encoded_bytes = code.len().saturating_add(message.len());
        if self.deferred_protocol_error_count < MAX_HELLO_DEFERRED_PROTOCOL_ERRORS
            && self
                .deferred_protocol_error_bytes
                .checked_add(encoded_bytes)
                .is_some_and(|next| next <= MAX_HELLO_DEFERRED_PROTOCOL_ERROR_BYTES)
        {
            self.deferred_protocol_error_bytes = self
                .deferred_protocol_error_bytes
                .saturating_add(encoded_bytes);
            self.deferred_protocol_error_count = self
                .deferred_protocol_error_count
                .saturating_add(1);
            let error = PendingProtocolError {
                code: code.to_string(),
                message: message.to_string(),
            };
            self.deferred.push_back(DeferredAction::ProtocolError(error));
        } else {
            self.dropped_protocol_errors = self.dropped_protocol_errors.saturating_add(1);
        }
    }

    fn acknowledge_hello(&mut self) -> Option<BarrierRelease> {
        if !self.hello_ack_pending {
            return None;
        }
        self.hello_ack_pending = false;
        self.refresh_state();
        self.take_release_if_open()
    }

    fn take_release_if_open(&mut self) -> Option<BarrierRelease> {
        if self.pending() || self.state == HelloBarrierState::Failed {
            return None;
        }
        Some(self.drain_release(None))
    }

    fn failure_reason(&self) -> (&str, &str) {
        self.failure
            .as_ref()
            .map(|failure| (failure.code.as_str(), failure.message.as_str()))
            .unwrap_or((
                "hello_ack_unavailable",
                "turn core did not complete the handshake; job was not executed",
            ))
    }

    fn pending_failure_reason(&self) -> (&'static str, &'static str) {
        if self.hello_ack_pending {
            (
                "hello_ack_unavailable",
                "turn core did not complete hello.ack; deferred job was not executed",
            )
        } else if self.turn_accept_pending {
            (
                "turn_accept_unavailable",
                "turn core did not complete turn.accepted; deferred job was not executed",
            )
        } else {
            (
                "handshake_unavailable",
                "turn core did not complete the handshake; deferred job was not executed",
            )
        }
    }

    fn fail(&mut self, code: &str, message: &str) -> BarrierRelease {
        self.state = HelloBarrierState::Failed;
        self.hello_ack_pending = false;
        self.turn_accept_pending = false;
        self.failure = Some(BarrierFailure {
            code: code.to_string(),
            message: message.to_string(),
        });
        self.drain_release(self.failure.clone())
    }

    fn drain_release(&mut self, failure: Option<BarrierFailure>) -> BarrierRelease {
        let actions = self.deferred.drain(..).collect();
        let release = BarrierRelease {
            actions,
            dropped_jobs: self.dropped_jobs,
            dropped_protocol_errors: self.dropped_protocol_errors,
            failure,
            control_seq: self.control_seq.clone(),
            connection_id: self.connection_id.clone(),
        };
        self.deferred_dispatch_count = 0;
        self.deferred_dispatch_bytes = 0;
        self.deferred_resource_error_count = 0;
        self.deferred_resource_error_bytes = 0;
        self.deferred_protocol_error_count = 0;
        self.deferred_protocol_error_bytes = 0;
        self.dropped_jobs = 0;
        self.dropped_protocol_errors = 0;
        release
    }
}

struct CoreChannelWriter {
    sender: JobSender<JobHostMessage>,
    buffer: Vec<u8>,
}

impl CoreChannelWriter {
    fn new(sender: JobSender<JobHostMessage>) -> Self {
        Self {
            sender,
            buffer: Vec::new(),
        }
    }
}

impl IoWrite for CoreChannelWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(bytes);
        while let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let mut line = self.buffer.drain(..=position).collect::<Vec<_>>();
            line.pop();
            if line.is_empty() {
                continue;
            }
            self.sender
                .send(JobHostMessage::CoreLine(line))
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "job Host output receiver disconnected",
                    )
                })?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct JobDeliveryState {
    context: JobContext,
    next_wire_seq: u64,
    next_runtime_cursor: u64,
    /// Last runtime-retention gap announced to this client.  Keeping the
    /// range prevents a polling loop from emitting the same critical status
    /// frame indefinitely while still allowing a newly grown gap to surface.
    announced_gap: Option<(u64, u64)>,
}

// A source failure may contain filesystem/provider detail that is much larger
// than a bounded Host frame. Keep the diagnostic finite and retain one
// fingerprint per job so a polling loop cannot turn a persistent failure into
// an unbounded stream of duplicate status frames.
const MAX_SOURCE_ERROR_BYTES: usize = 512;

/// A read-only `job.wait` request that is being serviced by the Host loop.
///
/// Waits deliberately live outside `JobDeliveryState`: the latter tracks the
/// unsolicited live-delivery cursor, while a caller's wait cursor is an
/// independent observation position. Keeping a bounded queue here lets the
/// core continue receiving controls and forwarding turn traffic while one or
/// more callers are waiting for a later event.
#[derive(Debug, Clone)]
struct PendingJobWait {
    context: JobContext,
    operation_id: Option<String>,
    attachment_id: Option<String>,
    inclusive_cursor: u64,
    durable_inclusive_cursor: u64,
    limit: usize,
    poll_interval_ms: u64,
    deadline: Instant,
    next_poll: Instant,
    last_inspection: Option<JobInspection>,
}

fn spawn_job_input_reader(sender: JobSender<JobHostMessage>, max_frame_bytes: usize) {
    thread::Builder::new()
        .name("owner-open-v7-input".to_string())
        .spawn(move || {
            let stdin = std::io::stdin();
            let mut reader = BufReader::new(stdin.lock());
            loop {
                match read_bounded_frame(&mut reader, max_frame_bytes) {
                    Ok(Some(frame)) => {
                        if sender.send(JobHostMessage::Input(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = sender.send(JobHostMessage::InputEof);
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(JobHostMessage::InputError(error));
                        return;
                    }
                }
            }
        })
        .expect("spawn job-aware Host input reader");
}

fn process_job_host<W: IoWrite>(
    mut writer: W,
    receiver: JobReceiver<JobHostMessage>,
    core_sender: std::sync::mpsc::SyncSender<HostMessage>,
    manager: JobManager,
    shell_executable: PathBuf,
    control_seq: Arc<AtomicU64>,
    connection_id: String,
) -> Result<(), String> {
    let limits = MechanicalLimits::default();
    let mut input_open = true;
    let mut core_open = true;
    let mut delivery_attached = true;
    let mut delivery_error = None::<String>;
    let mut jobs = HashMap::<JobKey, JobDeliveryState>::new();
    // Polling failures are state, too: retain only a bounded fingerprint per
    // job so a persistent registry/journal outage produces one actionable
    // status frame instead of an unbounded duplicate stream.
    let mut source_error_fingerprints = HashMap::<JobKey, String>::new();
    let mut pending_waits = VecDeque::<PendingJobWait>::new();
    let mut hello_barrier = HelloJobBarrier::default();
    hello_barrier.configure_control_seq(control_seq, connection_id);

    loop {
        match receiver.recv_timeout(JOB_POLL_INTERVAL) {
            Ok(JobHostMessage::Input(encoded)) => match RunTurnFrame::decode(&encoded, &limits) {
                Ok(frame) if frame.kind == FRAME_HELLO => {
                    // The first hello is forwarded to the core; all later
                    // hellos are rejected locally and can never reopen the
                    // acknowledgement gate.
                    if hello_barrier.observe_hello()
                        && core_sender.send(HostMessage::Inbound(encoded)).is_err()
                    {
                        core_open = false;
                        let release = hello_barrier.fail(
                            "hello_ack_unavailable",
                            "turn core closed before hello.ack; deferred job was not executed",
                        );
                        flush_barrier_release(
                            release,
                            &manager,
                            &shell_executable,
                            &mut jobs,
                            &mut pending_waits,
                            &mut writer,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        );
                    } else if !hello_barrier.pending() {
                        flush_barrier_release(
                            hello_barrier.drain_release(None),
                            &manager,
                            &shell_executable,
                            &mut jobs,
                            &mut pending_waits,
                            &mut writer,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        );
                    }
                }
                Ok(frame) if frame.kind == FRAME_TURN_START => {
                    if hello_barrier.observe_turn_start() {
                        if core_sender.send(HostMessage::Inbound(encoded)).is_err() {
                            core_open = false;
                            let release = hello_barrier.fail(
                                "turn_accept_unavailable",
                                "turn core closed before turn.accepted; deferred job was not executed",
                            );
                            flush_barrier_release(
                                release,
                                &manager,
                                &shell_executable,
                                &mut jobs,
                                &mut pending_waits,
                                &mut writer,
                                limits.max_frame_bytes,
                                &mut delivery_attached,
                                &mut delivery_error,
                            );
                        }
                    } else if !hello_barrier.pending() {
                        flush_barrier_release(
                            hello_barrier.drain_release(None),
                            &manager,
                            &shell_executable,
                            &mut jobs,
                            &mut pending_waits,
                            &mut writer,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        );
                    }
                }
                Ok(frame) if is_job_frame(&frame.kind) => {
                    if hello_barrier.pending() {
                        // Admission is deliberately infallible at this
                        // boundary. Overflow is represented by a bounded
                        // resource_exhausted response and never tears down
                        // the Host process (or suppresses the core ack).
                        let _ = hello_barrier.defer(frame, encoded.len());
                    } else if hello_barrier.failed() {
                        let (code, message) = hello_barrier.failure_reason();
                        reject_job_frame(
                            frame,
                            &manager,
                            &shell_executable,
                            &mut writer,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                            code,
                            message,
                        );
                    } else {
                        dispatch_job_frame(
                            frame,
                            &manager,
                            &shell_executable,
                            &mut jobs,
                            &mut pending_waits,
                            &mut writer,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        );
                    }
                }
                Ok(_) | Err(_) => {
                    if core_sender.send(HostMessage::Inbound(encoded)).is_err() {
                        core_open = false;
                        if hello_barrier.pending() {
                            let (code, message) = hello_barrier.pending_failure_reason();
                            let release = hello_barrier.fail(code, message);
                            flush_barrier_release(
                                release,
                                &manager,
                                &shell_executable,
                                &mut jobs,
                                &mut pending_waits,
                                &mut writer,
                                limits.max_frame_bytes,
                                &mut delivery_attached,
                                &mut delivery_error,
                            );
                        }
                    }
                }
            },
            Ok(JobHostMessage::InputEof) => {
                input_open = false;
                if core_sender.send(HostMessage::InputEof).is_err() {
                    core_open = false;
                    if hello_barrier.pending() {
                        let (code, message) = hello_barrier.pending_failure_reason();
                        let release = hello_barrier.fail(code, message);
                        flush_barrier_release(
                            release,
                            &manager,
                            &shell_executable,
                            &mut jobs,
                            &mut pending_waits,
                            &mut writer,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        );
                    }
                }
            }
            Ok(JobHostMessage::InputError(error)) => {
                input_open = false;
                if core_sender.send(HostMessage::InputError(error)).is_err() {
                    core_open = false;
                    if hello_barrier.pending() {
                        let (code, message) = hello_barrier.pending_failure_reason();
                        let release = hello_barrier.fail(code, message);
                        flush_barrier_release(
                            release,
                            &manager,
                            &shell_executable,
                            &mut jobs,
                            &mut pending_waits,
                            &mut writer,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        );
                    }
                }
            }
            Ok(JobHostMessage::CoreLine(line)) => {
                let line = augment_core_line(line, &manager, &limits);
                let core_kind = RunTurnFrame::decode(&line, &limits)
                    .ok()
                    .map(|frame| frame.kind);
                if core_kind.as_deref() == Some(FRAME_TURN_END) && !hello_barrier.pending() {
                    hello_barrier.observe_turn_end();
                }
                if core_kind.as_deref() == Some(FRAME_HELLO_ACK)
                    && hello_barrier.hello_ack_pending
                {
                    // Always write the control acknowledgement before any
                    // deferred local response. If a turn.start is also
                    // pending, the queue remains closed until turn.accepted.
                    deliver_raw_line(
                        &mut writer,
                        &line,
                        &mut delivery_attached,
                        &mut delivery_error,
                    );
                    if let Some(release) = hello_barrier.acknowledge_hello() {
                        flush_barrier_release(
                            release,
                            &manager,
                            &shell_executable,
                            &mut jobs,
                            &mut pending_waits,
                            &mut writer,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        );
                    }
                } else if core_kind.as_deref() == Some(FRAME_TURN_ACCEPTED)
                    && hello_barrier.turn_accept_pending
                {
                    deliver_raw_line(
                        &mut writer,
                        &line,
                        &mut delivery_attached,
                        &mut delivery_error,
                    );
                    if let Some(release) = hello_barrier.acknowledge_turn() {
                        flush_barrier_release(
                            release,
                            &manager,
                            &shell_executable,
                            &mut jobs,
                            &mut pending_waits,
                            &mut writer,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        );
                    }
                } else if hello_barrier.pending() {
                    // Any non-ack/non-accepted core response resolves the
                    // pending boundary negatively. Preserve that response,
                    // then reject every deferred effect explicitly.
                    deliver_raw_line(
                        &mut writer,
                        &line,
                        &mut delivery_attached,
                        &mut delivery_error,
                    );
                    let (code, message) = hello_barrier.pending_failure_reason();
                    let release = hello_barrier.fail(code, message);
                    flush_barrier_release(
                        release,
                        &manager,
                        &shell_executable,
                        &mut jobs,
                        &mut pending_waits,
                        &mut writer,
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    );
                } else {
                    deliver_raw_line(
                        &mut writer,
                        &line,
                        &mut delivery_attached,
                        &mut delivery_error,
                    );
                }
            }
            Ok(JobHostMessage::CoreComplete(result)) => {
                core_open = false;
                if let Err(error) = result {
                    deliver_protocol_error(
                        "turn_core_failed",
                        &error,
                        hello_barrier.control_seq.as_ref(),
                        hello_barrier.connection_id.as_deref(),
                        &mut writer,
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    );
                }
                if hello_barrier.pending() {
                    let (code, message) = hello_barrier.pending_failure_reason();
                    let release = hello_barrier.fail(code, message);
                    flush_barrier_release(
                        release,
                        &manager,
                        &shell_executable,
                        &mut jobs,
                        &mut pending_waits,
                        &mut writer,
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    );
                }
            }
            Err(JobRecvTimeout::Timeout) => {}
            Err(JobRecvTimeout::Disconnected) => {
                input_open = false;
                core_open = false;
                if hello_barrier.pending() {
                    let (code, message) = hello_barrier.pending_failure_reason();
                    let release = hello_barrier.fail(code, message);
                    flush_barrier_release(
                        release,
                        &manager,
                        &shell_executable,
                        &mut jobs,
                        &mut pending_waits,
                        &mut writer,
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    );
                }
            }
        }

        // Do not generate unsolicited job output while either handshake gate
        // is unresolved. This also covers jobs already running in no-hello
        // mode when a later turn.start establishes a new boundary.
        if !hello_barrier.pending() {
            poll_job_events(
                &manager,
                &mut jobs,
                &mut source_error_fingerprints,
                &mut writer,
                limits.max_frame_bytes,
                &mut delivery_attached,
                &mut delivery_error,
            );

            poll_job_waits(
                &manager,
                &mut pending_waits,
                &mut jobs,
                &mut writer,
                limits.max_frame_bytes,
                &mut delivery_attached,
                &mut delivery_error,
            );
        }

        // Once the client side is detached there is no recipient for a
        // pending wait result. Drop those read-only requests so an unwritable
        // client cannot keep the Host process alive until every timeout.
        if !delivery_attached {
            pending_waits.clear();
        }

        if !input_open && !core_open && !jobs_are_live(&manager) && pending_waits.is_empty() {
            return Ok(());
        }
        if !delivery_attached
            && !core_open
            && !jobs_are_live(&manager)
            && pending_waits.is_empty()
        {
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_job_frame<W: IoWrite>(
    frame: RunTurnFrame,
    manager: &JobManager,
    shell_executable: &Path,
    jobs: &mut HashMap<JobKey, JobDeliveryState>,
    pending_waits: &mut VecDeque<PendingJobWait>,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    let error_context = job_error_context(&frame, manager, shell_executable);
    let error_operation_id = frame_string(&frame, "operation_id");
    let error_attachment_id = frame_string(&frame, "attachment_id");
    if let Err(error) = handle_job_frame(
        frame,
        manager,
        shell_executable,
        jobs,
        pending_waits,
        writer,
        max_frame_bytes,
        delivery_attached,
        delivery_error,
    ) {
        deliver_job_error(
            error_context.as_ref(),
            error_operation_id.as_deref(),
            error_attachment_id.as_deref(),
            "job_request_failed",
            &error,
            writer,
            max_frame_bytes,
            delivery_attached,
            delivery_error,
        );
    }
}

/// Flush a resolved handshake barrier.  The caller writes the corresponding
/// core acknowledgement (`hello.ack` or `turn.accepted`) first; this helper
/// then emits queued protocol errors and jobs in their retained FIFO order.
/// A failed barrier converts every retained job into an explicit, correlated
/// error.  A successful barrier dispatches ordinary entries and turns the
/// reserved overflow entries into bounded `resource_exhausted` errors.
#[allow(clippy::too_many_arguments)]
fn flush_barrier_release<W: IoWrite>(
    release: BarrierRelease,
    manager: &JobManager,
    shell_executable: &Path,
    jobs: &mut HashMap<JobKey, JobDeliveryState>,
    pending_waits: &mut VecDeque<PendingJobWait>,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    let control_seq = release.control_seq.as_ref();
    let connection_id = release.connection_id.as_deref();
    let failure = release.failure.as_ref();
    for action in release.actions {
        match action {
            DeferredAction::ProtocolError(error) => deliver_protocol_error(
                &error.code,
                &error.message,
                control_seq,
                connection_id,
                writer,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            ),
            DeferredAction::Job(deferred) => {
                if let Some(failure) = failure {
                    reject_job_frame(
                        deferred.frame,
                        manager,
                        shell_executable,
                        writer,
                        max_frame_bytes,
                        delivery_attached,
                        delivery_error,
                        &failure.code,
                        &failure.message,
                    );
                } else {
                    match deferred.disposition {
                        DeferredJobDisposition::Dispatch => dispatch_job_frame(
                            deferred.frame,
                            manager,
                            shell_executable,
                            jobs,
                            pending_waits,
                            writer,
                            max_frame_bytes,
                            delivery_attached,
                            delivery_error,
                        ),
                        DeferredJobDisposition::ResourceExhausted => reject_job_frame(
                            deferred.frame,
                            manager,
                            shell_executable,
                            writer,
                            max_frame_bytes,
                            delivery_attached,
                            delivery_error,
                            "resource_exhausted",
                            "handshake deferred-job queue is exhausted; request was not executed",
                        ),
                    }
                }
            }
        }
    }

    if release.dropped_jobs > 0 {
        if let Some(failure) = failure {
            deliver_protocol_error(
                &failure.code,
                &format!(
                    "{} additional deferred job request(s) were rejected: {}",
                    release.dropped_jobs, failure.message
                ),
                control_seq,
                connection_id,
                writer,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
        } else {
            deliver_protocol_error(
                "resource_exhausted",
                &format!(
                    "{} additional handshake-deferred job request(s) were dropped after bounded resource errors",
                    release.dropped_jobs
                ),
                control_seq,
                connection_id,
                writer,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
        }
    }

    if release.dropped_protocol_errors > 0 {
        deliver_protocol_error(
            "resource_exhausted",
            &format!(
                "{} additional deferred protocol error(s) were suppressed by the bounded handshake queue",
                release.dropped_protocol_errors
            ),
            control_seq,
            connection_id,
            writer,
            max_frame_bytes,
            delivery_attached,
            delivery_error,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn deliver_protocol_error<W: IoWrite>(
    code: &str,
    message: &str,
    control_seq: Option<&Arc<AtomicU64>>,
    connection_id: Option<&str>,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    // Keep this unscoped: a duplicate hello (or a handshake resource
    // summary) has no valid turn/job correlation.  The allocator is shared
    // with the v4 core thread so these outer-generated control frames cannot
    // collide with a core-generated hello/control error.
    let seq = control_seq
        .map(|allocator| allocator.fetch_add(1, Ordering::SeqCst))
        .unwrap_or(0);
    let event_id = connection_id.map(|id| format!("{id}-event-{seq}"));
    let frame = RunTurnFrame {
        kind: "host.error".to_string(),
        seq,
        payload: json!({
            "code": code,
            "message": message,
            "automatic_redispatch": false
        }),
        direction: Some("host_to_client".to_string()),
        client_seq: None,
        host_seq: None,
        frame_sha256: None,
        event_id,
        connection_id: connection_id.map(str::to_string),
        stream_id: None,
        turn_stream_id: None,
        session_id: None,
        profile_id: None,
        task_id: None,
        turn_id: None,
        call_id: None,
        job_id: None,
        tool: None,
        target: None,
        target_id: None,
        extensions: Default::default(),
    };
    let Ok(encoded) = serde_json::to_vec(&frame) else {
        *delivery_attached = false;
        *delivery_error = Some("failed to encode handshake protocol error".to_string());
        return;
    };
    if encoded.len() > max_frame_bytes {
        *delivery_attached = false;
        *delivery_error = Some("handshake protocol error exceeds the Host frame bound".to_string());
        return;
    }
    deliver_raw_line(writer, &encoded, delivery_attached, delivery_error);
}

#[allow(clippy::too_many_arguments)]
fn reject_job_frame<W: IoWrite>(
    frame: RunTurnFrame,
    manager: &JobManager,
    shell_executable: &Path,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
    code: &str,
    message: &str,
) {
    let context = job_error_context(&frame, manager, shell_executable);
    let operation_id = frame_string(&frame, "operation_id");
    let attachment_id = frame_string(&frame, "attachment_id");
    deliver_job_error(
        context.as_ref(),
        operation_id.as_deref(),
        attachment_id.as_deref(),
        code,
        message,
        writer,
        max_frame_bytes,
        delivery_attached,
        delivery_error,
    );
}


fn frame_string(frame: &RunTurnFrame, name: &str) -> Option<String> {
    if let Some(value) = frame
        .payload
        .get(name)
        .and_then(Value::as_str)
    {
        return Some(value.to_string());
    }
    let value = match name {
        "session_id" => frame.session_id.as_deref(),
        "profile_id" => frame.profile_id.as_deref(),
        "task_id" => frame.task_id.as_deref(),
        "turn_id" => frame.turn_id.as_deref(),
        "turn_stream_id" => frame
            .turn_stream_id
            .as_deref()
            .or(frame.stream_id.as_deref()),
        "call_id" => frame.call_id.as_deref(),
        "job_id" => frame.job_id.as_deref(),
        _ => None,
    };
    value.map(str::to_string)
}

fn job_error_context(
    frame: &RunTurnFrame,
    manager: &JobManager,
    shell_executable: &Path,
) -> Option<JobContext> {
    if frame.kind == FRAME_JOB_START
        && let Ok(decoded) = decode_job_start(frame, shell_executable)
    {
        return Some(decoded.context);
    }
    let session_id = frame_string(frame, "session_id")?;
    let profile_id = frame_string(frame, "profile_id")?;
    let task_id = frame_string(frame, "task_id")?;
    let turn_id = frame_string(frame, "turn_id")?;
    let turn_stream_id = frame_string(frame, "turn_stream_id")?;
    let job_id = frame_string(frame, "job_id")?;
    for (label, value) in [
        ("session_id", session_id.as_str()),
        ("profile_id", profile_id.as_str()),
        ("task_id", task_id.as_str()),
        ("turn_id", turn_id.as_str()),
        ("turn_stream_id", turn_stream_id.as_str()),
        ("job_id", job_id.as_str()),
    ] {
        validate_id(value, label).ok()?;
    }
    let key = JobKey::new(
        JobScope::new(
            session_id,
            profile_id,
            task_id,
            turn_id,
            turn_stream_id,
        ),
        job_id,
    );
    let context = JobContext {
        stream_id: job_stream_id(&key),
        key,
        request_sha256: frame_string(frame, "request_sha256"),
    };
    Some(resolve_job_context(manager, context.clone()).unwrap_or(context))
}

#[allow(clippy::too_many_arguments)]
fn handle_job_frame<W: IoWrite>(
    frame: RunTurnFrame,
    manager: &JobManager,
    shell_executable: &Path,
    jobs: &mut HashMap<JobKey, JobDeliveryState>,
    pending_waits: &mut VecDeque<PendingJobWait>,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) -> Result<(), String> {
    match frame.kind.as_str() {
        FRAME_JOB_START => {
            let decoded = decode_job_start(&frame, shell_executable)?;
            let context = decoded.context.clone();
            let operation_id = decoded.request.operation_id.clone();
            let result = manager
                .start(decoded.request)
                .map_err(|error| error.to_string())?;
            let state = jobs.entry(context.key.clone()).or_insert(JobDeliveryState {
                context,
                next_wire_seq: 0,
                next_runtime_cursor: 0,
                announced_gap: None,
            });
            let discriminator = format!("start-result-{operation_id}");
            let response = response_frame(
                state,
                FRAME_JOB_START_RESULT,
                &discriminator,
                start_payload(&result, &operation_id),
            );
            deliver_job_frame(
                writer,
                &response,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
        }
        FRAME_JOB_INSPECT | FRAME_JOB_ATTACH => {
            let decoded = decode_job_control(&frame)?;
            let context = resolve_job_context(manager, decoded.context)?;
            let response_operation_id = decoded.operation_id.clone();
            let response_attachment_id = decoded.attachment_id.clone();
            let inspection = if frame.kind == FRAME_JOB_ATTACH {
                let attachment_id = response_attachment_id
                    .as_deref()
                    .ok_or_else(|| "job.attach requires attachment_id".to_string())?;
                manager
                    .attach(
                        &context.key,
                        attachment_id,
                        decoded.inclusive_cursor,
                        decoded.limit,
                    )
                    .map_err(|error| error.to_string())?
            } else {
                manager
                    .inspect(
                        &context.key,
                        decoded.inclusive_cursor,
                        decoded.limit,
                    )
                    .map_err(|error| error.to_string())?
            };
            let durable_records = durable_records_for_job(manager, &context.key)?;
            let state = jobs.entry(context.key.clone()).or_insert(JobDeliveryState {
                context,
                next_wire_seq: 0,
                next_runtime_cursor: inspection.next_cursor,
                announced_gap: None,
            });
            let kind = if frame.kind == FRAME_JOB_ATTACH {
                FRAME_JOB_ATTACH_RESULT
            } else {
                FRAME_JOB_INSPECT_RESULT
            };
            let response = bounded_inspection_frame(
                state,
                kind,
                &inspection,
                &durable_records,
                decoded.durable_inclusive_cursor,
                response_operation_id.as_deref(),
                response_attachment_id.as_deref(),
                None,
                max_frame_bytes,
            )?;
            deliver_job_frame(
                writer,
                &response,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
        }
        FRAME_JOB_WAIT => {
            let decoded = decode_job_wait(&frame)?;
            let context = resolve_job_context(manager, decoded.context)?;
            if pending_waits.len() >= MAX_PENDING_JOB_WAITS {
                return Err("job.wait queue is exhausted".to_string());
            }
            let timeout_ms = decoded
                .timeout_ms
                .unwrap_or(DEFAULT_JOB_WAIT_TIMEOUT_MS);
            let poll_interval_ms = decoded
                .poll_interval_ms
                .unwrap_or(DEFAULT_JOB_WAIT_POLL_INTERVAL_MS);
            let now = Instant::now();
            let deadline = now
                .checked_add(Duration::from_millis(timeout_ms))
                .unwrap_or(now);
            pending_waits.push_back(PendingJobWait {
                context,
                operation_id: decoded.operation_id,
                attachment_id: decoded.attachment_id,
                inclusive_cursor: decoded.inclusive_cursor,
                durable_inclusive_cursor: decoded.durable_inclusive_cursor,
                limit: decoded.limit,
                poll_interval_ms,
                deadline,
                // Poll once immediately after this input batch. This makes a
                // terminal/already-available observation a synchronous
                // response while still keeping the main Host loop free for
                // other controls.
                next_poll: now,
                last_inspection: None,
            });
        }
        FRAME_JOB_DETACH => {
            let decoded = decode_job_control(&frame)?;
            let context = resolve_job_context(manager, decoded.context)?;
            let attachment_id = decoded
                .attachment_id
                .as_deref()
                .ok_or_else(|| "job.detach requires attachment_id".to_string())?;
            manager
                .detach(&context.key, attachment_id)
                .map_err(|error| error.to_string())?;
            let state = jobs.entry(context.key.clone()).or_insert(JobDeliveryState {
                context,
                next_wire_seq: 0,
                next_runtime_cursor: 0,
                announced_gap: None,
            });
            let discriminator = format!(
                "detach-{attachment_id}-{}",
                decoded.operation_id.as_deref().unwrap_or("no-operation")
            );
            let response = response_frame(
                state,
                FRAME_JOB_DETACH_RESULT,
                &discriminator,
                json!({
                    "status": "detached",
                    "operation_id": decoded.operation_id.as_deref(),
                    "attachment_id": attachment_id,
                    "automatic_redispatch": false
                }),
            );
            deliver_job_frame(
                writer,
                &response,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
        }
        FRAME_JOB_WRITE | FRAME_JOB_RESIZE | FRAME_JOB_CLOSE_STDIN | FRAME_JOB_KILL => {
            let decoded = decode_job_control(&frame)?;
            let context = resolve_job_context(manager, decoded.context)?;
            let operation_id = decoded
                .operation_id
                .as_deref()
                .ok_or_else(|| format!("{} requires operation_id", frame.kind))?;
            let disposition = match frame.kind.as_str() {
                FRAME_JOB_WRITE => manager.write(
                    &context.key,
                    operation_id,
                    decoded
                        .data
                        .as_deref()
                        .ok_or_else(|| "job.write requires data".to_string())?,
                ),
                FRAME_JOB_RESIZE => manager.resize(
                    &context.key,
                    operation_id,
                    decoded
                        .size
                        .ok_or_else(|| "job.resize requires rows and cols".to_string())?,
                ),
                FRAME_JOB_CLOSE_STDIN => manager.close_stdin(&context.key, operation_id),
                FRAME_JOB_KILL => manager.kill(
                    &context.key,
                    operation_id,
                    decoded.signal.unwrap_or(libc::SIGTERM),
                ),
                _ => unreachable!(),
            }
            .map_err(|error| error.to_string())?;
            let state = jobs.entry(context.key.clone()).or_insert(JobDeliveryState {
                context,
                next_wire_seq: 0,
                next_runtime_cursor: 0,
                announced_gap: None,
            });
            let response = response_frame(
                state,
                FRAME_JOB_CONTROL_RESULT,
                operation_id,
                json!({
                    "status": control_disposition(&disposition),
                    "operation": frame.kind,
                    "operation_id": operation_id,
                    "automatic_redispatch": false
                }),
            );
            deliver_job_frame(
                writer,
                &response,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
        }
        _ => return Err(format!("unsupported job frame {}", frame.kind)),
    }
    Ok(())
}

fn poll_job_events<W: IoWrite>(
    manager: &JobManager,
    jobs: &mut HashMap<JobKey, JobDeliveryState>,
    source_error_fingerprints: &mut HashMap<JobKey, String>,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    let mut keys = manager.registry().keys().unwrap_or_default();
    keys.sort_by(|first, second| {
        first
            .scope
            .turn_stream_id
            .cmp(&second.scope.turn_stream_id)
            .then_with(|| first.job_id.cmp(&second.job_id))
    });
    for key in keys {
        let snapshot = match manager.registry().snapshot(&key) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let state = jobs.entry(key.clone()).or_insert_with(|| JobDeliveryState {
                    context: JobContext {
                        stream_id: job_stream_id(&key),
                        key: key.clone(),
                        request_sha256: None,
                    },
                    next_wire_seq: 0,
                    next_runtime_cursor: 0,
                    announced_gap: None,
                });
                announce_source_unavailable(
                    state,
                    source_error_fingerprints,
                    &key,
                    "registry.snapshot",
                    &error.to_string(),
                    writer,
                    max_frame_bytes,
                    delivery_attached,
                    delivery_error,
                );
                continue;
            }
        };
        let state = jobs.entry(key.clone()).or_insert_with(|| JobDeliveryState {
            context: JobContext {
                stream_id: job_stream_id(&key),
                key: key.clone(),
                request_sha256: Some(snapshot.request.request_sha256.clone()),
            },
            next_wire_seq: 0,
            next_runtime_cursor: 0,
            announced_gap: None,
        });
        let inspection = match manager.inspect(&key, state.next_runtime_cursor, 128) {
            Ok(inspection) => inspection,
            Err(error) => {
                announce_source_unavailable(
                    state,
                    source_error_fingerprints,
                    &key,
                    "manager.inspect",
                    &error.to_string(),
                    writer,
                    max_frame_bytes,
                    delivery_attached,
                    delivery_error,
                );
                continue;
            }
        };
        // A successful read clears the prior diagnostic. If the source fails
        // again later, a fresh status is useful and will be emitted once.
        source_error_fingerprints.remove(&key);
        // A retained-observation prefix may have been evicted while the Host
        // was disconnected or back-pressured.  Never emit the first retained
        // event as if it followed the caller's cursor: announce the exact
        // missing range first, then resume at the oldest retained event only
        // after that explicit resync status has been produced.
        if inspection.resync_required || inspection.gap.is_some() {
            let gap = inspection
                .gap
                .as_ref()
                .map(|value| (value.first_missing_cursor, value.last_missing_cursor));
            if state.announced_gap != gap {
                let frame = job_resync_frame(&state.context, state.next_wire_seq, &inspection);
                state.next_wire_seq = state.next_wire_seq.saturating_add(1);
                deliver_job_frame(
                    writer,
                    &frame,
                    max_frame_bytes,
                    delivery_attached,
                    delivery_error,
                );
                state.announced_gap = gap;
            }
            // `oldest_available_cursor` is a runtime-event cursor.  Moving to
            // it here is intentional only because the preceding status frame
            // made the skipped range explicit; this is not a silent clamp.
            state.next_runtime_cursor = inspection.oldest_available_cursor;
            continue;
        }
        state.announced_gap = None;
        for event in &inspection.runtime_events {
            let frame = runtime_job_frame(&state.context, state.next_wire_seq, event);
            state.next_wire_seq = state.next_wire_seq.saturating_add(1);
            deliver_job_frame(
                writer,
                &frame,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
        }
        state.next_runtime_cursor = inspection.next_cursor;
    }
}

/// Emit one bounded, correlated diagnostic when the live job observation
/// source cannot be read. Polling is intentionally best-effort, but silently
/// dropping a registry/journal failure makes a client mistake missing data
/// for an idle job. The fingerprint map is capped and stores only a digest,
/// so a persistent failure cannot grow Host memory or output without bound.
#[allow(clippy::too_many_arguments)]
fn announce_source_unavailable<W: IoWrite>(
    state: &mut JobDeliveryState,
    fingerprints: &mut HashMap<JobKey, String>,
    key: &JobKey,
    source: &str,
    error: &str,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    let fingerprint = format!("{source}:{}", sha256_hex(error.as_bytes()));
    if fingerprints.get(key) == Some(&fingerprint) {
        return;
    }

    // Keep at most one diagnostic fingerprint per bounded job population. A
    // deterministic lexical eviction avoids making output/order depend on
    // HashMap iteration randomization if a pathological registry exceeds the
    // diagnostic budget.
    const MAX_SOURCE_ERROR_FINGERPRINTS: usize = 256;
    if !fingerprints.contains_key(key) && fingerprints.len() >= MAX_SOURCE_ERROR_FINGERPRINTS {
        let evicted = fingerprints
            .keys()
            .min_by_key(|candidate| {
                (
                    candidate.scope.session_id.as_str(),
                    candidate.scope.profile_id.as_str(),
                    candidate.scope.task_id.as_str(),
                    candidate.scope.turn_id.as_str(),
                    candidate.scope.turn_stream_id.as_str(),
                    candidate.job_id.as_str(),
                )
            })
            .cloned();
        if let Some(evicted) = evicted {
            fingerprints.remove(&evicted);
        }
    }
    fingerprints.insert(key.clone(), fingerprint);

    let bounded_error = bounded_source_error(error);
    let discriminator = format!(
        "source-unavailable-{source}-{}",
        sha256_hex(error.as_bytes())
    );
    let frame = response_frame(
        state,
        FRAME_JOB_STATUS,
        &discriminator,
        json!({
            "status": "source_unavailable",
            "source": source,
            "error": bounded_error.clone(),
            "degraded": true,
            "runtime_cursor_domain": RUNTIME_CURSOR_DOMAIN,
            "requested_inclusive_cursor": state.next_runtime_cursor,
            "next_cursor": state.next_runtime_cursor,
            // The source could not be verified, so advertise the conservative
            // non-durable state. Consumers (including the transport
            // readiness gate) must not infer replayability from an absent
            // journal error field.
            "event_log_status": "unavailable",
            "durable_fallback_available": false,
            "journal_error": bounded_error,
            "read_only": true,
            "side_effects": false,
            "automatic_redispatch": false
        }),
    );
    deliver_job_frame(
        writer,
        &frame,
        max_frame_bytes,
        delivery_attached,
        delivery_error,
    );
}

fn bounded_source_error(error: &str) -> String {
    if error.len() <= MAX_SOURCE_ERROR_BYTES {
        return error.to_string();
    }
    // Reserve room for an ASCII truncation marker and cut only at a UTF-8
    // boundary. Error text is diagnostic, never an input to authorization.
    const MARKER: &str = "...";
    let mut end = MAX_SOURCE_ERROR_BYTES.saturating_sub(MARKER.len());
    while end > 0 && !error.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &error[..end], MARKER)
}

/// Poll all admitted `job.wait` requests without blocking the multiplexed
/// Host loop.  Each request owns its caller-supplied cursor and deadline;
/// unsolicited delivery keeps using `JobDeliveryState` independently.
fn poll_job_waits<W: IoWrite>(
    manager: &JobManager,
    waits: &mut VecDeque<PendingJobWait>,
    jobs: &mut HashMap<JobKey, JobDeliveryState>,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    if waits.is_empty() {
        return;
    }
    let now = Instant::now();
    let mut remaining = VecDeque::with_capacity(waits.len());
    while let Some(mut wait) = waits.pop_front() {
        if !*delivery_attached {
            break;
        }
        if now < wait.next_poll && now < wait.deadline {
            remaining.push_back(wait);
            continue;
        }

        let inspection = match manager.inspect(
            &wait.context.key,
            wait.inclusive_cursor,
            wait.limit,
        ) {
            Ok(inspection) => inspection,
            Err(error @ JobRuntimeError::InvalidRequest(_)) => {
                // A cursor/limit violation is a rejected request, not an
                // unavailable observation source. Returning a synthetic
                // `source_unavailable` inspection here would make a client
                // believe its cursor was accepted and could cause an
                // indefinite retry loop.
                deliver_job_error(
                    Some(&wait.context),
                    wait.operation_id.as_deref(),
                    wait.attachment_id.as_deref(),
                    "job_wait_invalid_request",
                    &error.to_string(),
                    writer,
                    max_frame_bytes,
                    delivery_attached,
                    delivery_error,
                );
                continue;
            }
            Err(error @ JobRuntimeError::NotFound) => {
                // The context is normally resolved before admission. Keep a
                // race with registry/journal cleanup mechanically explicit if
                // it occurs while a wait is pending.
                deliver_job_error(
                    Some(&wait.context),
                    wait.operation_id.as_deref(),
                    wait.attachment_id.as_deref(),
                    "job_not_found",
                    &error.to_string(),
                    writer,
                    max_frame_bytes,
                    delivery_attached,
                    delivery_error,
                );
                continue;
            }
            Err(error) => {
                // A source failure is itself a bounded wait outcome. Preserve
                // the last verified inspection when possible, but never turn
                // the error into an optimistic terminal claim.
                let message = error.to_string();
                let mut inspection = wait
                    .last_inspection
                    .take()
                    .unwrap_or_else(|| unavailable_wait_inspection(&wait, message.clone()));
                inspection.event_log_status =
                    trillionnium_owner_open_job_runtime::EventLogStatus::Unavailable;
                inspection.journal_error = Some(message);
                emit_wait_result(
                    &wait,
                    &inspection,
                    Vec::new(),
                    "source_unavailable",
                    jobs,
                    writer,
                    max_frame_bytes,
                    delivery_attached,
                    delivery_error,
                );
                continue;
            }
        };

        let wait_status = wait_status_for_observation(
            manager,
            &wait.context.key,
            &inspection,
            now,
            wait.deadline,
        );
        let Some(wait_status) = wait_status else {
            wait.last_inspection = Some(inspection);
            wait.next_poll = now
                .checked_add(Duration::from_millis(wait.poll_interval_ms))
                .unwrap_or(now);
            remaining.push_back(wait);
            continue;
        };

        let durable_records = match durable_records_for_job(manager, &wait.context.key) {
            Ok(records) => records,
            Err(error) => {
                // Keep the resident inspection truthful and expose the
                // durable-source failure through its existing diagnostic
                // fields. A zero durable cursor is the only representable
                // page when the source cannot be read at all.
                let mut degraded = inspection;
                degraded.event_log_status =
                    trillionnium_owner_open_job_runtime::EventLogStatus::Unavailable;
                degraded.journal_error = Some(error.clone());
                emit_wait_result(
                    &wait,
                    &degraded,
                    Vec::new(),
                    "source_unavailable",
                    jobs,
                    writer,
                    max_frame_bytes,
                    delivery_attached,
                    delivery_error,
                );
                continue;
            }
        };
        if let Err(error) = validate_wait_durable_cursor(
            wait.durable_inclusive_cursor,
            &durable_records,
        ) {
            deliver_job_error(
                Some(&wait.context),
                wait.operation_id.as_deref(),
                wait.attachment_id.as_deref(),
                "job_wait_invalid_request",
                &error,
                writer,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
            continue;
        }
        emit_wait_result(
            &wait,
            &inspection,
            durable_records,
            wait_status,
            jobs,
            writer,
            max_frame_bytes,
            delivery_attached,
            delivery_error,
        );
    }
    waits.extend(remaining);
}

fn wait_status_for_observation(
    manager: &JobManager,
    key: &JobKey,
    inspection: &JobInspection,
    now: Instant,
    deadline: Instant,
) -> Option<&'static str> {
    classify_wait_status(manager, key, inspection)
        .or_else(|| (now >= deadline).then_some("timeout"))
}

/// Classify the first observed wait condition using only facts already
/// present in the read-only inspection. No branch mutates registry/journal
/// state or dispatches a process.
fn classify_wait_status(
    manager: &JobManager,
    key: &JobKey,
    inspection: &JobInspection,
) -> Option<&'static str> {
    let terminal_event = inspection
        .runtime_events
        .iter()
        .any(|event| matches!(event.event, RuntimeJobEventKind::Terminal { .. }));
    let terminal_snapshot = inspection.snapshot.as_ref().is_some_and(|snapshot| {
        matches!(
            snapshot.state,
            JobEffectiveState::Terminal { .. }
        )
    });
    let recovered_terminal = manager
        .journal()
        .recovered_job(key)
        .ok()
        .flatten()
        .is_some_and(|job| job.terminal.is_some());
    if terminal_event || terminal_snapshot || recovered_terminal {
        return Some("terminal_observed");
    }
    // `job.wait` is a terminal long-poll, not a replacement for the bounded
    // event page returned by `job.inspect`.  Intermediate started/output
    // observations must therefore be retained in `last_inspection` and
    // polled again; otherwise a fast producer can wake the waiter before its
    // terminal record is visible and make a request named "wait" return an
    // arbitrarily early event.  Resync/degraded outcomes below remain
    // explicit bounded wake-ups because replay truth cannot be obtained.
    let degraded_snapshot = inspection.snapshot.as_ref().is_some_and(|snapshot| {
        matches!(
            snapshot.state,
            JobEffectiveState::ProvenNotStartedAfterRestart
                | JobEffectiveState::UnknownAfterRestart { .. }
        )
    });
    let degraded_replay = matches!(
        inspection.replay_status,
        trillionnium_owner_open_job_runtime::ReplayStatus::BestEffortUnreplayable
            | trillionnium_owner_open_job_runtime::ReplayStatus::UnknownAfterRestart
    );
    if degraded_snapshot
        || degraded_replay
        || !matches!(
            inspection.event_log_status,
            trillionnium_owner_open_job_runtime::EventLogStatus::Durable
        )
    {
        // There is no separate `degraded_observed` wire status in v1. Use the
        // source-unavailable bucket while preserving the richer degraded
        // fields above. This wakes a waiter rather than making it spin until
        // its deadline against a source that cannot provide replay truth.
        return Some("source_unavailable");
    }
    None
}

fn unavailable_wait_inspection(wait: &PendingJobWait, error: String) -> JobInspection {
    JobInspection {
        snapshot: None,
        registry_events: Vec::new(),
        runtime_events: Vec::new(),
        inclusive_cursor: wait.inclusive_cursor,
        oldest_available_cursor: wait.inclusive_cursor,
        next_cursor: wait.inclusive_cursor,
        total_events: wait.inclusive_cursor,
        has_more: false,
        resync_required: false,
        gap: None,
        durable_fallback_available: false,
        event_log_status: trillionnium_owner_open_job_runtime::EventLogStatus::Unavailable,
        journal_error: Some(error),
        replay_status: trillionnium_owner_open_job_runtime::ReplayStatus::BestEffortUnreplayable,
    }
}

fn validate_wait_durable_cursor(
    durable_inclusive_cursor: u64,
    durable_records: &[Value],
) -> Result<(), String> {
    let start = usize::try_from(durable_inclusive_cursor).map_err(|_| {
        format!(
            "durable cursor {durable_inclusive_cursor} does not fit the journal-record domain"
        )
    })?;
    if start > durable_records.len() {
        return Err(format!(
            "durable cursor {durable_inclusive_cursor} is after {} journal records",
            durable_records.len()
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_wait_result<W: IoWrite>(
    wait: &PendingJobWait,
    inspection: &JobInspection,
    durable_records: Vec<Value>,
    wait_status: &str,
    jobs: &mut HashMap<JobKey, JobDeliveryState>,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    // `job.wait` has a caller-owned observation cursor. Build its response
    // with a temporary state so consuming a wait never advances the
    // unsolicited live-delivery cursor in `jobs`. We do carry the wire
    // sequence forward: direct and unsolicited frames for one job share a
    // monotonic sequence, while their observation positions remain
    // independent.
    let key = wait.context.key.clone();
    let mut response_state = jobs
        .get(&key)
        .map(|state| JobDeliveryState {
            context: state.context.clone(),
            next_wire_seq: state.next_wire_seq,
            next_runtime_cursor: state.next_runtime_cursor,
            announced_gap: state.announced_gap,
        })
        .unwrap_or_else(|| JobDeliveryState {
            context: wait.context.clone(),
            next_wire_seq: 0,
            next_runtime_cursor: 0,
            announced_gap: None,
        });
    let response = bounded_inspection_frame(
        &mut response_state,
        FRAME_JOB_INSPECT_RESULT,
        inspection,
        &durable_records,
        wait.durable_inclusive_cursor,
        wait.operation_id.as_deref(),
        wait.attachment_id.as_deref(),
        Some(wait_status),
        max_frame_bytes,
    );
    match response {
        Ok(frame) => {
            if let Some(state) = jobs.get_mut(&key) {
                state.next_wire_seq = response_state.next_wire_seq;
            } else {
                jobs.insert(
                    key,
                    JobDeliveryState {
                        context: response_state.context.clone(),
                        next_wire_seq: response_state.next_wire_seq,
                        // Do not seed live delivery from the wait cursor or
                        // response. A later unsolicited poll must still start
                        // at its own independently tracked cursor.
                        next_runtime_cursor: 0,
                        announced_gap: None,
                    },
                );
            }
            deliver_job_frame(
                writer,
                &frame,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
        }
        Err(error) => deliver_job_error(
            Some(&wait.context),
            wait.operation_id.as_deref(),
            wait.attachment_id.as_deref(),
            "job_wait_response_failed",
            &error,
            writer,
            max_frame_bytes,
            delivery_attached,
            delivery_error,
        ),
    }
}

fn resolve_job_context(manager: &JobManager, mut context: JobContext) -> Result<JobContext, String> {
    let actual = manager
        .registry()
        .snapshot(&context.key)
        .ok()
        .map(|snapshot| snapshot.request.request_sha256)
        .or_else(|| {
            manager
                .journal()
                .recovered_job(&context.key)
                .ok()
                .flatten()
                .map(|job| job.request.request_sha256)
        });
    let actual = actual.ok_or_else(|| "owner-open job is not registered".to_string())?;
    if context
        .request_sha256
        .as_deref()
        .is_some_and(|claimed| claimed != actual)
    {
        return Err("job request_sha256 conflicts with registered job".to_string());
    }
    context.request_sha256 = Some(actual);
    Ok(context)
}

fn durable_records_for_job(manager: &JobManager, key: &JobKey) -> Result<Vec<Value>, String> {
    // The durable event store is turn-scoped, so the metadata stream can
    // contain records for sibling jobs.  Resolve the canonical request from
    // the live registry (or, after a restart, the recovered journal) before
    // filtering.  This makes the request binding an integrity check rather
    // than merely trusting whichever envelope happens to appear first.
    let expected_request = manager
        .registry()
        .snapshot(key)
        .ok()
        .map(|snapshot| snapshot.request)
        .or_else(|| {
            manager
                .journal()
                .recovered_job(key)
                .ok()
                .flatten()
                .map(|job| job.request)
        })
        .ok_or_else(|| "job request binding is unavailable".to_string())?;
    let records = manager
        .durable_records_with_metadata(key)
        .map_err(|error| error.to_string())?;
    filter_durable_records_for_job(records, key, &expected_request)
}

fn filter_durable_records_for_job(
    records: Vec<Value>,
    key: &JobKey,
    expected_request: &JobRequest,
) -> Result<Vec<Value>, String> {
    let expected_scope = TurnScope::new(
        key.scope.session_id.clone(),
        key.scope.profile_id.clone(),
        key.scope.task_id.clone(),
        key.scope.turn_id.clone(),
        key.scope.turn_stream_id.clone(),
    );
    let mut matching = Vec::with_capacity(records.len());
    let mut expected_job_record_seq = 0_u64;
    for record in records {
        let mut event_record_value = record.clone();
        let event_record_object = event_record_value
            .as_object_mut()
            .ok_or_else(|| "durable journal metadata record must be an object".to_string())?;
        let job_record_seq = event_record_object
            .remove("job_record_seq")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| "durable journal record is missing job_record_seq".to_string())?;
        let event_record: EventRecord = serde_json::from_value(event_record_value)
            .map_err(|error| format!("durable journal metadata record is invalid: {error}"))?;
        if event_record.schema != EVENT_RECORD_SCHEMA {
            return Err("durable journal metadata record has an unknown schema".to_string());
        }
        if event_record.scope != expected_scope {
            return Err("durable journal metadata record scope does not match job".to_string());
        }
        let payload = event_record
            .payload
            .as_object()
            .ok_or_else(|| "durable journal record envelope must be an object".to_string())?;
        let payload_schema = payload
            .get("schema")
            .and_then(Value::as_str)
            .ok_or_else(|| "durable journal record envelope is missing schema".to_string())?;
        if payload_schema != JOB_JOURNAL_SCHEMA {
            return Err("durable journal record envelope has an unknown schema".to_string());
        }
        let record_job_id = payload
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "durable journal record envelope is missing job_id".to_string())?;
        if record_job_id == key.job_id {
            let request_value = payload.get("request").ok_or_else(|| {
                "durable journal record envelope is missing request binding".to_string()
            })?;
            let request: JobRequest = serde_json::from_value(request_value.clone())
                .map_err(|error| {
                    format!("durable journal record request binding is invalid: {error}")
                })?;
            if &request != expected_request {
                return Err(
                    "durable journal record request binding conflicts with registered job"
                        .to_string(),
                );
            }
            if job_record_seq != expected_job_record_seq {
                return Err(format!(
                    "durable journal record cursor is not contiguous for job (expected {}, got {})",
                    expected_job_record_seq, job_record_seq
                ));
            }
            matching.push(record);
            expected_job_record_seq = expected_job_record_seq
                .checked_add(1)
                .ok_or_else(|| "durable journal record cursor overflow".to_string())?;
        }
    }
    Ok(matching)
}

// The frame builder keeps each cursor/lineage field explicit at the call site
// so a future protocol change cannot silently omit one from the bounded
// response.  The argument count is intentional rather than a hidden policy
// context object.
#[allow(clippy::too_many_arguments)]
fn bounded_inspection_frame(
    state: &mut JobDeliveryState,
    kind: &str,
    inspection: &JobInspection,
    durable_records: &[Value],
    durable_inclusive_cursor: u64,
    operation_id: Option<&str>,
    attachment_id: Option<&str>,
    wait_status: Option<&str>,
    max_frame_bytes: usize,
) -> Result<RunTurnFrame, String> {
    let start = usize::try_from(durable_inclusive_cursor).map_err(|_| {
        format!(
            "durable cursor {durable_inclusive_cursor} does not fit the journal-record domain"
        )
    })?;
    if start > durable_records.len() {
        return Err(format!(
            "durable cursor {durable_inclusive_cursor} is after {} journal records",
            durable_records.len()
        ));
    }
    let mut count = inspection
        .runtime_events
        .len()
        .max(1)
        .min(durable_records.len().saturating_sub(start));
    loop {
        let end = start.saturating_add(count).min(durable_records.len());
        let mut payload = json!({
            "status": "found",
            "inspection": inspection,
            "durable_records": &durable_records[start..end],
            "runtime_cursor_domain": RUNTIME_CURSOR_DOMAIN,
            "durable_cursor_domain": DURABLE_CURSOR_DOMAIN,
            "durable_inclusive_cursor": start,
            "durable_next_cursor": end,
            "durable_total_records": durable_records.len(),
            "durable_has_more": end < durable_records.len(),
            "operation_id": operation_id,
            "attachment_id": attachment_id,
            "read_only": true,
            "side_effects": false,
            "automatic_redispatch": false
        });
        if let Some(wait_status) = wait_status {
            payload["wait_status"] = Value::String(wait_status.to_string());
        }
        let discriminator = format!(
            "runtime-{}-durable-{}-{start}-{end}-{}-{}-{}",
            inspection.inclusive_cursor,
            durable_inclusive_cursor,
            operation_id.unwrap_or("no-operation"),
            attachment_id.unwrap_or("no-attachment"),
            wait_status.unwrap_or("no-wait")
        );
        let frame = response_frame(state, kind, &discriminator, payload);
        let encoded = serde_json::to_vec(&frame).map_err(|error| error.to_string())?;
        if encoded.len() <= max_frame_bytes {
            return Ok(frame);
        }
        state.next_wire_seq = state.next_wire_seq.saturating_sub(1);
        if count == 0 {
            return Err("one job inspection item exceeds the Host frame bound".to_string());
        }
        count /= 2;
    }
}

fn response_frame(
    state: &mut JobDeliveryState,
    kind: &str,
    discriminator: &str,
    payload: Value,
) -> RunTurnFrame {
    let seq = state.next_wire_seq;
    state.next_wire_seq = state.next_wire_seq.saturating_add(1);
    build_job_frame(&state.context, kind, seq, discriminator, payload)
}

fn start_payload(result: &JobStartResult, operation_id: &str) -> Value {
    json!({
        "status": match &result.disposition {
            trillionnium_owner_open_job_runtime::StartDisposition::Started => "started",
            trillionnium_owner_open_job_runtime::StartDisposition::ExistingLive => "existing_live",
            trillionnium_owner_open_job_runtime::StartDisposition::ExistingTerminal => "existing_terminal",
            trillionnium_owner_open_job_runtime::StartDisposition::UnknownAfterRestart => "unknown_after_restart"
        },
        "snapshot": &result.snapshot,
        "replay_status": &result.replay_status,
        "operation_id": operation_id,
        "automatic_redispatch": false
    })
}

fn control_disposition(disposition: &ControlDisposition) -> &'static str {
    match disposition {
        ControlDisposition::Applied => "applied",
        ControlDisposition::Existing => "existing",
        ControlDisposition::UnknownAfterRestart => "unknown_after_restart",
    }
}

fn jobs_are_live(manager: &JobManager) -> bool {
    // A terminal registry state can be visible just before the dispatcher has
    // finished committing its durable `job.terminal` record.  Keep the Host
    // carrier alive for that short pending window; admission capacity is
    // already released by the registry transition itself.
    if manager.has_live_or_pending_jobs() {
        return true;
    }
    manager
        .registry()
        .keys()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|key| manager.registry().snapshot(&key).ok())
        .any(|snapshot| {
            matches!(
                snapshot.state,
                JobEffectiveState::Accepted
                    | JobEffectiveState::Starting { .. }
                    | JobEffectiveState::Running { .. }
            )
        })
}

fn augment_core_line(
    line: Vec<u8>,
    manager: &JobManager,
    limits: &MechanicalLimits,
) -> Vec<u8> {
    let Ok(mut frame) = RunTurnFrame::decode(&line, limits) else {
        return line;
    };
    if frame.kind != FRAME_HELLO_ACK {
        return line;
    }
    if let Some(payload) = frame.payload.as_object_mut() {
        payload.insert("long_running_jobs".to_string(), Value::Bool(true));
        payload.insert("job_modes".to_string(), json!(["pipe", "pty"]));
        payload.insert(
            "job_controls".to_string(),
            json!(["inspect", "wait", "attach", "detach", "write", "resize", "close_stdin", "kill"]),
        );
        payload.insert(
            "job_journal_status".to_string(),
            Value::String(
                match manager.journal().status() {
                    Ok(trillionnium_owner_open_job_runtime::JournalStatus::Durable) => "durable",
                    Ok(trillionnium_owner_open_job_runtime::JournalStatus::BestEffortMemoryOnly) => {
                        "best_effort_unreplayable"
                    }
                    Ok(trillionnium_owner_open_job_runtime::JournalStatus::Unavailable { .. })
                    | Err(_) => "unavailable",
                }
                .to_string(),
            ),
        );
        payload.insert("job_automatic_redispatch".to_string(), Value::Bool(false));
        payload.insert(
            "job_cursor_domains".to_string(),
            json!({
                "runtime": RUNTIME_CURSOR_DOMAIN,
                "durable_records": DURABLE_CURSOR_DOMAIN
            }),
        );
    }
    serde_json::to_vec(&frame).unwrap_or(line)
}

#[allow(clippy::too_many_arguments)]
fn deliver_job_error<W: IoWrite>(
    context: Option<&JobContext>,
    operation_id: Option<&str>,
    attachment_id: Option<&str>,
    code: &str,
    message: &str,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    let discriminator = format!(
        "{code}-{}-{}",
        operation_id.unwrap_or("no-operation"),
        attachment_id.unwrap_or("no-attachment")
    );
    let frame = match context {
        Some(context) => build_job_frame(
            context,
            "job.error",
            0,
            &discriminator,
            json!({
                "code": code,
                "message": message,
                "operation_id": operation_id,
                "attachment_id": attachment_id,
                "automatic_redispatch": false
            }),
        ),
        None => RunTurnFrame {
            kind: "job.error".to_string(),
            seq: 0,
            payload: json!({
                "code": code,
                "message": message,
                "operation_id": operation_id,
                "attachment_id": attachment_id,
                "automatic_redispatch": false
            }),
            direction: Some("host_to_client".to_string()),
            client_seq: None,
            host_seq: None,
            frame_sha256: None,
            event_id: None,
            connection_id: None,
            stream_id: None,
            turn_stream_id: None,
            session_id: None,
            profile_id: None,
            task_id: None,
            turn_id: None,
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: Default::default(),
        },
    };
    deliver_job_frame(
        writer,
        &frame,
        max_frame_bytes,
        delivery_attached,
        delivery_error,
    );
}

fn deliver_job_frame<W: IoWrite>(
    writer: &mut W,
    frame: &RunTurnFrame,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    if !*delivery_attached {
        return;
    }
    let encoded = match serde_json::to_vec(frame) {
        Ok(encoded) if !encoded.is_empty() && encoded.len() <= max_frame_bytes => encoded,
        Ok(_) => {
            *delivery_attached = false;
            *delivery_error = Some("job response exceeds the Host frame bound".to_string());
            return;
        }
        Err(error) => {
            *delivery_attached = false;
            *delivery_error = Some(error.to_string());
            return;
        }
    };
    deliver_raw_line(writer, &encoded, delivery_attached, delivery_error);
}

fn deliver_raw_line<W: IoWrite>(
    writer: &mut W,
    line: &[u8],
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    if !*delivery_attached {
        return;
    }
    if let Err(error) = writer
        .write_all(line)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
    {
        *delivery_attached = false;
        *delivery_error = Some(error.to_string());
    }
}

#[cfg(test)]
mod process_tests {
    use super::*;

    fn barrier_frame(seq: u64) -> RunTurnFrame {
        serde_json::from_value(json!({
            "kind": "job.start",
            "seq": seq,
            "payload": {}
        }))
        .expect("minimal barrier frame")
    }

    fn test_key(job_id: &str) -> JobKey {
        JobKey::new(
            JobScope::new("session-1", "owner-open", "task-1", "turn-1", "stream-1"),
            job_id,
        )
    }

    fn metadata_record(job_id: &str, job_record_seq: u64, turn_seq: u64) -> Value {
        json!({
            "schema": EVENT_RECORD_SCHEMA,
            "store_seq": turn_seq,
            "turn_seq": turn_seq,
            "scope": {
                "session_id": "session-1",
                "profile_id": "owner-open",
                "task_id": "task-1",
                "turn_id": "turn-1",
                "turn_stream_id": "stream-1"
            },
            "event_id": format!("event-{job_id}-{turn_seq}"),
            "kind": "job.observation",
            "payload": {
                "schema": JOB_JOURNAL_SCHEMA,
                "record": "observation",
                "job_id": job_id,
                "request": {
                    "request_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "binding_fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "tool": "shell.job",
                    "mode": "pipe",
                    "target_id": null
                },
                "event_seq": turn_seq,
                "payload": {"event": "test"}
            },
            "payload_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "previous_record_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "record_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "job_record_seq": job_record_seq
        })
    }

    fn metadata_request() -> JobRequest {
        JobRequest::new(
            "a".repeat(64),
            "b".repeat(64),
            "shell.job",
            "pipe",
            None,
        )
    }

    #[test]
    fn durable_records_are_scoped_to_the_requested_job() {
        let records = vec![
            metadata_record("job-a", 0, 0),
            metadata_record("job-b", 0, 1),
            metadata_record("job-a", 1, 2),
        ];
        let filtered = filter_durable_records_for_job(
            records,
            &test_key("job-a"),
            &metadata_request(),
        )
            .expect("well-formed journal envelopes should filter");
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0]["job_record_seq"], 0);
        assert_eq!(filtered[1]["job_record_seq"], 1);
        assert_eq!(filtered[0]["payload"]["job_id"], "job-a");
        assert_eq!(filtered[1]["payload"]["job_id"], "job-a");
    }

    #[test]
    fn malformed_durable_record_fails_closed_instead_of_being_dropped() {
        let error = filter_durable_records_for_job(
            vec![json!({"record": 1})],
            &test_key("job-a"),
            &metadata_request(),
        )
            .expect_err("missing job identity must be rejected");
        assert!(error.contains("missing job_record_seq"));
    }

    #[test]
    fn durable_job_cursor_must_be_contiguous_after_sibling_filtering() {
        let records = vec![metadata_record("job-a", 0, 0), metadata_record("job-a", 2, 1)];
        let error = filter_durable_records_for_job(
            records,
            &test_key("job-a"),
            &metadata_request(),
        )
            .expect_err("a skipped durable cursor must fail closed");
        assert!(error.contains("not contiguous"));
    }

    #[test]
    fn durable_job_records_must_preserve_the_registered_request_binding() {
        let mut record = metadata_record("job-a", 0, 0);
        record["payload"]["request"]["request_sha256"] = json!("c".repeat(64));
        let error = filter_durable_records_for_job(
            vec![record],
            &test_key("job-a"),
            &metadata_request(),
        )
        .expect_err("a request mutation must fail closed");
        assert!(error.contains("request binding"));
    }

    #[test]
    fn hello_barrier_releases_deferred_jobs_in_fifo_order_only_after_ack() {
        let mut barrier = HelloJobBarrier::default();
        assert!(!barrier.awaiting_ack());
        assert!(barrier.observe_hello());
        assert!(barrier.awaiting_ack());
        assert_eq!(
            barrier.defer(barrier_frame(1), 10),
            DeferredAdmission::Dispatch
        );
        assert_eq!(
            barrier.defer(barrier_frame(2), 10),
            DeferredAdmission::Dispatch
        );

        let released = barrier
            .acknowledge_hello()
            .expect("ack releases deferred jobs");
        assert!(!barrier.awaiting_ack());
        assert!(!barrier.failed());
        assert_eq!(
            released
                .actions
                .into_iter()
                .filter_map(|action| match action {
                    DeferredAction::Job(job) => Some(job.frame.seq),
                    DeferredAction::ProtocolError(_) => None,
                })
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn hello_barrier_has_finite_count_and_byte_bounds() {
        let mut count_limited = HelloJobBarrier::default();
        assert!(count_limited.observe_hello());
        let mut dispatch_count = 0;
        let mut resource_count = 0;
        for seq in 0..MAX_HELLO_DEFERRED_JOB_FRAMES as u64 {
            match count_limited.defer(barrier_frame(seq), 1) {
                DeferredAdmission::Dispatch => dispatch_count += 1,
                DeferredAdmission::ResourceExhausted => resource_count += 1,
                DeferredAdmission::Dropped => panic!("bounded queue dropped too early"),
            }
        }
        assert_eq!(dispatch_count, MAX_HELLO_DEFERRED_JOB_FRAMES - MAX_HELLO_DEFERRED_RESOURCE_ERRORS);
        assert_eq!(resource_count, MAX_HELLO_DEFERRED_RESOURCE_ERRORS);
        assert_eq!(
            count_limited.defer(barrier_frame(999), 1),
            DeferredAdmission::Dropped
        );

        let mut byte_limited = HelloJobBarrier::default();
        assert!(byte_limited.observe_hello());
        assert_eq!(
            byte_limited.defer(barrier_frame(1), MAX_HELLO_DEFERRED_JOB_BYTES),
            DeferredAdmission::Dropped
        );
        assert_eq!(
            byte_limited.defer(barrier_frame(2), 1),
            DeferredAdmission::Dispatch
        );
    }

    #[test]
    fn hello_barrier_failure_releases_requests_for_explicit_rejection() {
        let mut barrier = HelloJobBarrier::default();
        assert!(barrier.observe_hello());
        assert_eq!(
            barrier.defer(barrier_frame(7), 1),
            DeferredAdmission::Dispatch
        );
        let rejected = barrier.fail("hello_ack_unavailable", "ack unavailable");
        assert!(barrier.failed());
        assert_eq!(
            rejected
                .actions
                .into_iter()
                .filter_map(|action| match action {
                    DeferredAction::Job(job) => Some(job.frame.seq),
                    DeferredAction::ProtocolError(_) => None,
                })
                .collect::<Vec<_>>(),
            vec![7]
        );
    }

    #[test]
    fn turn_gate_keeps_jobs_queued_until_turn_accepted() {
        let mut barrier = HelloJobBarrier::default();
        assert!(barrier.observe_turn_start());
        assert!(barrier.awaiting_turn_accepted());
        assert_eq!(
            barrier.defer(barrier_frame(3), 10),
            DeferredAdmission::Dispatch
        );
        assert!(barrier.acknowledge_turn().is_some());
        assert!(!barrier.pending());
    }

    #[test]
    fn hello_and_turn_gates_must_both_resolve_before_fifo_release() {
        let mut barrier = HelloJobBarrier::default();
        assert!(barrier.observe_hello());
        assert!(barrier.observe_turn_start());
        assert!(barrier.awaiting_ack());
        barrier.defer(barrier_frame(1), 1);
        assert!(barrier.acknowledge_hello().is_none());
        assert!(barrier.awaiting_turn_accepted());
        let release = barrier
            .acknowledge_turn()
            .expect("both handshake gates resolved");
        assert_eq!(
            release
                .actions
                .iter()
                .filter(|action| matches!(action, DeferredAction::Job(_)))
                .count(),
            1
        );
    }

    #[test]
    fn repeated_hello_is_recorded_as_a_protocol_error_without_reopening_gate() {
        let mut barrier = HelloJobBarrier::default();
        assert!(barrier.observe_hello());
        assert!(!barrier.observe_hello());
        assert!(barrier.awaiting_ack());
        let release = barrier
            .acknowledge_hello()
            .expect("ack releases duplicate hello error");
        let errors = release
            .actions
            .iter()
            .filter_map(|action| match action {
                DeferredAction::ProtocolError(error) => Some(error),
                DeferredAction::Job(_) => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, "duplicate_hello");
    }

    #[test]
    fn duplicate_turn_start_is_rejected_until_the_active_turn_ends() {
        let mut barrier = HelloJobBarrier::default();
        assert!(barrier.observe_turn_start());
        assert!(!barrier.observe_turn_start());
        let release = barrier
            .acknowledge_turn()
            .expect("first turn acceptance resolves the gate");
        let errors = release
            .actions
            .iter()
            .filter_map(|action| match action {
                DeferredAction::ProtocolError(error) => Some(error),
                DeferredAction::Job(_) => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, "duplicate_turn_start");
        assert!(!barrier.observe_turn_start());
        barrier.observe_turn_end();
        assert!(barrier.observe_turn_start());
    }

    struct CaptureWriter(Vec<u8>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn deferred_job_rejection_is_explicit_and_non_effectful() {
        let manager = JobManager::new(
            JobRuntimeConfig::development_unsafe(),
            trillionnium_owner_open_job_runtime::JobJournal::memory_only(),
        )
        .expect("memory-only manager");
        let mut writer = CaptureWriter(Vec::new());
        let mut attached = true;
        let mut delivery_error = None;
        reject_job_frame(
            barrier_frame(1),
            &manager,
            Path::new("/bin/sh"),
            &mut writer,
            1024 * 1024,
            &mut attached,
            &mut delivery_error,
            "hello_ack_unavailable",
            "turn core closed before hello.ack",
        );
        assert!(attached);
        assert!(delivery_error.is_none());
        let frame: RunTurnFrame = serde_json::from_slice(
            writer.0.strip_suffix(b"\n").expect("rejection newline"),
        )
        .expect("job error frame");
        assert_eq!(frame.kind, "job.error");
        assert_eq!(frame.payload["code"], "hello_ack_unavailable");
        assert_eq!(frame.payload["automatic_redispatch"], false);
    }

    #[test]
    fn source_unavailable_status_is_bounded_and_deduplicated() {
        let context = test_context("job-source-error");
        let key = context.key.clone();
        let mut state = JobDeliveryState {
            context,
            next_wire_seq: 0,
            next_runtime_cursor: 17,
            announced_gap: None,
        };
        let mut fingerprints = HashMap::new();
        let mut writer = CaptureWriter(Vec::new());
        let mut attached = true;
        let mut delivery_error = None;
        let long_error = "界".repeat(MAX_SOURCE_ERROR_BYTES);

        announce_source_unavailable(
            &mut state,
            &mut fingerprints,
            &key,
            "manager.inspect",
            &long_error,
            &mut writer,
            1024 * 1024,
            &mut attached,
            &mut delivery_error,
        );
        // Repeating the same source/error must not wake the client again.
        announce_source_unavailable(
            &mut state,
            &mut fingerprints,
            &key,
            "manager.inspect",
            &long_error,
            &mut writer,
            1024 * 1024,
            &mut attached,
            &mut delivery_error,
        );
        assert!(attached);
        assert!(delivery_error.is_none());
        assert_eq!(state.next_wire_seq, 1);
        assert_eq!(fingerprints.len(), 1);
        let line = writer.0.strip_suffix(b"\n").expect("status newline");
        let frame: RunTurnFrame = serde_json::from_slice(line).expect("status frame");
        assert_eq!(frame.kind, FRAME_JOB_STATUS);
        assert_eq!(frame.payload["status"], "source_unavailable");
        assert_eq!(frame.payload["source"], "manager.inspect");
        assert_eq!(frame.payload["degraded"], true);
        assert_eq!(frame.payload["requested_inclusive_cursor"], 17);
        assert_eq!(frame.payload["event_log_status"], "unavailable");
        assert_eq!(frame.payload["durable_fallback_available"], false);
        assert!(frame.payload["error"].as_str().unwrap().len() <= MAX_SOURCE_ERROR_BYTES);

        // A changed source error is a new diagnostic, but still one frame.
        announce_source_unavailable(
            &mut state,
            &mut fingerprints,
            &key,
            "registry.snapshot",
            "different bounded error",
            &mut writer,
            1024 * 1024,
            &mut attached,
            &mut delivery_error,
        );
        assert_eq!(state.next_wire_seq, 2);
        assert_eq!(writer.0.iter().filter(|byte| **byte == b'\n').count(), 2);
    }

    fn test_context(job_id: &str) -> JobContext {
        let key = test_key(job_id);
        JobContext {
            stream_id: job_stream_id(&key),
            key,
            request_sha256: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
        }
    }

    fn empty_inspection() -> JobInspection {
        JobInspection {
            snapshot: None,
            registry_events: Vec::new(),
            runtime_events: Vec::new(),
            inclusive_cursor: 0,
            oldest_available_cursor: 0,
            next_cursor: 0,
            total_events: 0,
            has_more: false,
            resync_required: false,
            gap: None,
            durable_fallback_available: true,
            event_log_status: trillionnium_owner_open_job_runtime::EventLogStatus::Durable,
            journal_error: None,
            replay_status: trillionnium_owner_open_job_runtime::ReplayStatus::Durable,
        }
    }

    #[test]
    fn wait_timeout_is_observation_only() {
        let manager = JobManager::new(
            JobRuntimeConfig::development_unsafe(),
            trillionnium_owner_open_job_runtime::JobJournal::memory_only(),
        )
        .expect("memory-only manager");
        let now = Instant::now();
        let deadline = now.checked_sub(Duration::from_millis(1)).unwrap_or(now);
        let status = wait_status_for_observation(
            &manager,
            &test_key("job-timeout"),
            &empty_inspection(),
            now,
            deadline,
        );
        assert_eq!(status, Some("timeout"));
    }

    #[test]
    fn future_durable_cursor_is_rejected_as_a_request_error() {
        let error = validate_wait_durable_cursor(2, &[json!({"record": 0})])
            .expect_err("cursor after the durable end must be rejected");
        assert!(error.contains("after 1 journal records"));
    }

    #[test]
    fn wait_response_does_not_advance_unsolicited_runtime_cursor() {
        let context = test_context("job-independent-cursor");
        let key = context.key.clone();
        let mut jobs = HashMap::from([(
            key.clone(),
            JobDeliveryState {
                context: context.clone(),
                next_wire_seq: 4,
                next_runtime_cursor: 42,
                announced_gap: None,
            },
        )]);
        let now = Instant::now();
        let wait = PendingJobWait {
            context,
            operation_id: Some("wait-op".to_string()),
            attachment_id: None,
            inclusive_cursor: 0,
            durable_inclusive_cursor: 0,
            limit: 8,
            poll_interval_ms: 20,
            deadline: now,
            next_poll: now,
            last_inspection: None,
        };
        let mut writer = CaptureWriter(Vec::new());
        let mut attached = true;
        let mut delivery_error = None;
        emit_wait_result(
            &wait,
            &empty_inspection(),
            Vec::new(),
            "timeout",
            &mut jobs,
            &mut writer,
            1024 * 1024,
            &mut attached,
            &mut delivery_error,
        );
        assert!(attached);
        assert!(delivery_error.is_none());
        assert_eq!(jobs[&key].next_runtime_cursor, 42);
        assert_eq!(jobs[&key].next_wire_seq, 5);
        let frame: RunTurnFrame =
            serde_json::from_slice(writer.0.strip_suffix(b"\n").expect("newline"))
                .expect("wait response frame");
        assert_eq!(frame.kind, FRAME_JOB_INSPECT_RESULT);
        assert_eq!(frame.payload["wait_status"], "timeout");
    }
}
