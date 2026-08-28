use std::collections::HashMap;
use std::io::Write as IoWrite;
use std::sync::mpsc::{RecvTimeoutError as OuterRecvTimeout, SyncSender};

use trillionnium_owner_open_job_registry::{JobEffectiveState, JobKey};
use trillionnium_owner_open_job_runtime::{
    ControlDisposition, JobInspection, JobManager, JobStartResult,
};

#[derive(Debug)]
enum JobHostMessage {
    Input(Vec<u8>),
    InputEof,
    InputError(String),
    CoreLine(Vec<u8>),
    CoreComplete(Result<(), String>),
}

struct CoreChannelWriter {
    sender: OuterSender<JobHostMessage>,
    buffer: Vec<u8>,
}

impl CoreChannelWriter {
    fn new(sender: OuterSender<JobHostMessage>) -> Self {
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
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "job Host output receiver disconnected"))?;
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
}

fn spawn_job_input_reader(sender: OuterSender<JobHostMessage>, max_frame_bytes: usize) {
    thread::Builder::new()
        .name("owner-open-v6-input".to_string())
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
    receiver: OuterReceiver<JobHostMessage>,
    core_sender: SyncSender<HostMessage>,
    manager: JobManager,
    shell_executable: PathBuf,
) -> Result<(), String> {
    let limits = MechanicalLimits::default();
    let mut input_open = true;
    let mut core_open = true;
    let mut delivery_attached = true;
    let mut delivery_error = None::<String>;
    let mut jobs = HashMap::<JobKey, JobDeliveryState>::new();

    loop {
        match receiver.recv_timeout(JOB_POLL_INTERVAL) {
            Ok(JobHostMessage::Input(encoded)) => {
                match RunTurnFrame::decode(&encoded, &limits) {
                    Ok(frame) if is_job_frame(&frame.kind) => {
                        if let Err(error) = handle_job_frame(
                            frame,
                            &manager,
                            &shell_executable,
                            &mut jobs,
                            &mut writer,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        ) {
                            deliver_job_error(
                                None,
                                "job_request_failed",
                                &error,
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
                        }
                    }
                }
            }
            Ok(JobHostMessage::InputEof) => {
                input_open = false;
                let _ = core_sender.send(HostMessage::InputEof);
            }
            Ok(JobHostMessage::InputError(error)) => {
                input_open = false;
                let _ = core_sender.send(HostMessage::InputError(error));
            }
            Ok(JobHostMessage::CoreLine(line)) => {
                let line = augment_core_line(line, &manager, &limits);
                deliver_raw_line(
                    &mut writer,
                    &line,
                    &mut delivery_attached,
                    &mut delivery_error,
                );
            }
            Ok(JobHostMessage::CoreComplete(result)) => {
                core_open = false;
                if let Err(error) = result {
                    deliver_job_error(
                        None,
                        "turn_core_failed",
                        &error,
                        &mut writer,
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    );
                }
            }
            Err(OuterRecvTimeout::Timeout) => {}
            Err(OuterRecvTimeout::Disconnected) => {
                input_open = false;
                core_open = false;
            }
        }

        poll_job_events(
            &manager,
            &mut jobs,
            &mut writer,
            limits.max_frame_bytes,
            &mut delivery_attached,
            &mut delivery_error,
        );

        if !input_open && !core_open && !jobs_are_live(&manager) {
            return Ok(());
        }
        if !delivery_attached && !core_open && !jobs_are_live(&manager) {
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_job_frame<W: IoWrite>(
    frame: RunTurnFrame,
    manager: &JobManager,
    shell_executable: &Path,
    jobs: &mut HashMap<JobKey, JobDeliveryState>,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) -> Result<(), String> {
    match frame.kind.as_str() {
        FRAME_JOB_START => {
            let decoded = decode_job_start(&frame, shell_executable)?;
            let context = decoded.context.clone();
            let result = manager
                .start(decoded.request)
                .map_err(|error| error.to_string())?;
            let state = jobs.entry(context.key.clone()).or_insert(JobDeliveryState {
                context,
                next_wire_seq: 0,
                next_runtime_cursor: 0,
            });
            let response = response_frame(
                state,
                FRAME_JOB_START_RESULT,
                "start-result",
                start_payload(&result),
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
            let inspection = if frame.kind == FRAME_JOB_ATTACH {
                let attachment_id = decoded
                    .attachment_id
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
            let durable_records = manager
                .durable_records(&context.key)
                .map_err(|error| error.to_string())?;
            let state = jobs.entry(context.key.clone()).or_insert(JobDeliveryState {
                context,
                next_wire_seq: 0,
                next_runtime_cursor: inspection.next_cursor,
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
            });
            let response = response_frame(
                state,
                FRAME_JOB_DETACH_RESULT,
                attachment_id,
                json!({
                    "status": "detached",
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
            Err(_) => continue,
        };
        let state = jobs.entry(key.clone()).or_insert_with(|| JobDeliveryState {
            context: JobContext {
                stream_id: job_stream_id(&key),
                key: key.clone(),
                request_sha256: Some(snapshot.request.request_sha256.clone()),
            },
            next_wire_seq: 0,
            next_runtime_cursor: 0,
        });
        let inspection = match manager.inspect(&key, state.next_runtime_cursor, 128) {
            Ok(inspection) => inspection,
            Err(_) => continue,
        };
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

fn bounded_inspection_frame(
    state: &mut JobDeliveryState,
    kind: &str,
    inspection: &JobInspection,
    durable_records: &[Value],
    max_frame_bytes: usize,
) -> Result<RunTurnFrame, String> {
    let start = usize::try_from(inspection.inclusive_cursor)
        .unwrap_or(usize::MAX)
        .min(durable_records.len());
    let mut count = inspection
        .runtime_events
        .len()
        .max(1)
        .min(durable_records.len().saturating_sub(start));
    loop {
        let end = start.saturating_add(count).min(durable_records.len());
        let payload = json!({
            "status": "found",
            "inspection": inspection,
            "durable_records": &durable_records[start..end],
            "durable_inclusive_cursor": start,
            "durable_next_cursor": end,
            "durable_total_records": durable_records.len(),
            "durable_has_more": end < durable_records.len(),
            "read_only": true,
            "automatic_redispatch": false
        });
        let frame = response_frame(
            state,
            kind,
            &format!("{}-{start}-{end}", inspection.inclusive_cursor),
            payload,
        );
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

fn start_payload(result: &JobStartResult) -> Value {
    json!({
        "status": match result.disposition {
            trillionnium_owner_open_job_runtime::StartDisposition::Started => "started",
            trillionnium_owner_open_job_runtime::StartDisposition::ExistingLive => "existing_live",
            trillionnium_owner_open_job_runtime::StartDisposition::ExistingTerminal => "existing_terminal",
            trillionnium_owner_open_job_runtime::StartDisposition::UnknownAfterRestart => "unknown_after_restart"
        },
        "snapshot": &result.snapshot,
        "replay_status": &result.replay_status,
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
            json!(["inspect", "attach", "detach", "write", "resize", "close_stdin", "kill"]),
        );
        payload.insert(
            "job_journal_status".to_string(),
            Value::String(match manager.journal().status() {
                Ok(trillionnium_owner_open_job_runtime::JournalStatus::Durable) => "durable",
                Ok(trillionnium_owner_open_job_runtime::JournalStatus::BestEffortMemoryOnly) => "best_effort_memory_only",
                Ok(trillionnium_owner_open_job_runtime::JournalStatus::Unavailable { .. }) | Err(_) => "unavailable",
            }
            .to_string()),
        );
        payload.insert("job_automatic_redispatch".to_string(), Value::Bool(false));
    }
    serde_json::to_vec(&frame).unwrap_or(line)
}

#[allow(clippy::too_many_arguments)]
fn deliver_job_error<W: IoWrite>(
    context: Option<&JobContext>,
    code: &str,
    message: &str,
    writer: &mut W,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    let frame = match context {
        Some(context) => build_job_frame(
            context,
            "job.error",
            0,
            code,
            json!({
                "code": code,
                "message": message,
                "automatic_redispatch": false
            }),
        ),
        None => RunTurnFrame {
            kind: "job.error".to_string(),
            seq: 0,
            payload: json!({
                "code": code,
                "message": message,
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
