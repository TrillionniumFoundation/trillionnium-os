#[allow(clippy::too_many_arguments)]
fn deliver_bounded_inspection<W: Write>(
    writer: &mut W,
    output: &mut OutputState,
    response: RunTurnFrame,
    context: &TurnContext,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    let fits = serde_json::to_vec(&response)
        .map(|encoded| !encoded.is_empty() && encoded.len() <= max_frame_bytes)
        .unwrap_or(false);
    if !fits {
        deliver_host_error(
            writer,
            output,
            Some(context),
            "inspect_response_too_large",
            "inspect response exceeds the Host frame bound; retry with a smaller limit",
            max_frame_bytes,
            delivery_attached,
            delivery_error,
        );
        return;
    }
    deliver_frame(
        writer,
        &response,
        max_frame_bytes,
        delivery_attached,
        delivery_error,
    );
}

fn encode_call_snapshot(snapshot: &CallSnapshot) -> Value {
    json!({
        "call_id": &snapshot.key.call_id,
        "session_id": &snapshot.key.scope.session_id,
        "profile_id": &snapshot.key.scope.profile_id,
        "task_id": &snapshot.key.scope.task_id,
        "turn_id": &snapshot.key.scope.turn_id,
        "turn_stream_id": &snapshot.key.scope.turn_stream_id,
        "request_sha256": &snapshot.request.request_sha256,
        "binding_fingerprint": &snapshot.request.binding_fingerprint,
        "tool": &snapshot.request.tool,
        "target_id": &snapshot.request.target_id,
        "state": encode_effective_state(&snapshot.state),
        "cancellation_requested": snapshot.cancellation_requested,
        "connection_lost": snapshot.connection_lost,
        "earliest_history_seq": snapshot.earliest_history_seq,
        "next_event_seq": snapshot.next_event_seq
    })
}

fn encode_effective_state(state: &EffectiveState) -> Value {
    match state {
        EffectiveState::Accepted => json!({"kind": "accepted"}),
        EffectiveState::CancelledBeforeSpawn => {
            json!({"kind": "cancelled_before_spawn"})
        }
        EffectiveState::Started { generation, pid } => json!({
            "kind": "started",
            "generation": generation,
            "pid": pid
        }),
        EffectiveState::ProvenNotStartedAfterDisconnect => json!({
            "kind": "proven_not_started_after_disconnect"
        }),
        EffectiveState::UnknownAfterDisconnect { generation, pid } => json!({
            "kind": "unknown_after_disconnect",
            "generation": generation,
            "pid": pid
        }),
        EffectiveState::Terminal {
            generation,
            terminal,
        } => json!({
            "kind": "terminal",
            "generation": generation,
            "terminal_kind": &terminal.terminal_kind,
            "exit_code": terminal.exit_code,
            "signal": terminal.signal,
            "observation_sha256": &terminal.observation_sha256,
            "stdout_bytes": terminal.stdout_bytes,
            "stderr_bytes": terminal.stderr_bytes
        }),
    }
}

fn encode_call_event(event: &CallEvent) -> Value {
    let kind = match &event.kind {
        CallEventKind::Accepted => json!({"kind": "accepted"}),
        CallEventKind::SpawnInhibited => json!({"kind": "spawn_inhibited"}),
        CallEventKind::SpawnClaimed { generation } => json!({
            "kind": "spawn_claimed",
            "generation": generation
        }),
        CallEventKind::PidObserved { generation, pid } => json!({
            "kind": "pid_observed",
            "generation": generation,
            "pid": pid
        }),
        CallEventKind::CancelRequested => {
            json!({"kind": "cancel_requested"})
        }
        CallEventKind::ConnectionLost => json!({"kind": "connection_lost"}),
        CallEventKind::ConnectionAttached => {
            json!({"kind": "connection_attached"})
        }
        CallEventKind::TerminalRecorded {
            generation,
            terminal,
        } => json!({
            "kind": "terminal_recorded",
            "generation": generation,
            "terminal_kind": &terminal.terminal_kind,
            "exit_code": terminal.exit_code,
            "signal": terminal.signal,
            "observation_sha256": &terminal.observation_sha256,
            "stdout_bytes": terminal.stdout_bytes,
            "stderr_bytes": terminal.stderr_bytes
        }),
    };
    json!({"seq": event.seq, "event": kind})
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn hex_lower(value: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut output, "{byte:02x}")
            .expect("writing to String cannot fail");
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn write_hello<W: Write>(
    writer: &mut W,
    output: &mut OutputState,
    persistence: &Persistence,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    let connection_id = output.connection_id.clone();
    let frame = output.frame(
        FRAME_HELLO_ACK,
        json!({
            "protocol": PROTOCOL,
            "protocol_version": PROTOCOL_VERSION,
            "connection_id": connection_id,
            "host_implementation": HOST_IMPLEMENTATION_V4,
            "provider_status": "configured_external_jsonl",
            "runtime_ready": true,
            "same_turn_tool_callback": true,
            "streaming_turn_events": true,
            "streaming_event_persistence": persistence.is_durable(),
            "client_disconnect_cancels_turn": false,
            "durable_event_store": persistence.is_durable(),
            "event_log_status": persistence.status(),
            "event_log_error": persistence.error(),
            "completed_turn_replay": persistence.is_durable(),
            "incomplete_turn_redispatch": false,
            "turn_cancel": "serviceable_while_active",
            "tool_cancel": "serviceable_while_active_for_registered_calls",
            "turn_inspect": "read_only_inclusive_cursor",
            "call_inspect": "live_registry_or_durable_frames",
            "inspect_persists_response": false,
            "bounded_control_queue_depth": HOST_QUEUE_DEPTH,
            "max_wire_inspect_limit": MAX_WIRE_INSPECT_LIMIT,
            "asynchronous_control": true,
            "one_active_turn_per_connection": true
        }),
        None,
        EventCorrelation::default(),
    );
    deliver_frame(
        writer,
        &frame,
        max_frame_bytes,
        delivery_attached,
        delivery_error,
    );
}
