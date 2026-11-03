fn process_messages<W: Write>(
    writer: W,
    receiver: Receiver<HostMessage>,
    sender: SyncSender<HostMessage>,
    connection_id: String,
    provider_template: JsonlProvider,
    persistence: &mut Persistence,
) -> Result<(), String> {
    process_messages_with_control_seq(
        writer,
        receiver,
        sender,
        connection_id,
        provider_template,
        persistence,
        Arc::new(AtomicU64::new(0)),
    )
}

/// Control-sequence-aware variant used by the v7 job multiplexer.  Keeping
/// the implementation in v4 preserves its inspect/replay handlers while
/// allowing the outer v7 thread to share the connection-control allocator.
fn process_messages_with_control_seq<W: Write>(
    mut writer: W,
    receiver: Receiver<HostMessage>,
    sender: SyncSender<HostMessage>,
    connection_id: String,
    provider_template: JsonlProvider,
    persistence: &mut Persistence,
    control_seq: Arc<AtomicU64>,
) -> Result<(), String> {
    let limits = MechanicalLimits::default();
    let registry = Arc::new(CallRegistry::default());
    let mut output = OutputState::new_with_control_seq(connection_id, control_seq);
    let mut active = None::<ActiveTurn>;
    let mut input_open = true;
    let mut delivery_attached = true;
    let mut delivery_error = None::<String>;

    loop {
        if active.is_none() && (!input_open || !delivery_attached) {
            return Ok(());
        }
        match receiver.recv_timeout(HOST_POLL_INTERVAL) {
            Ok(HostMessage::Inbound(encoded)) => {
                let frame = match RunTurnFrame::decode(&encoded, &limits) {
                    Ok(frame) => frame,
                    Err(error) => {
                        deliver_host_error(
                            &mut writer,
                            &mut output,
                            None,
                            "invalid_frame",
                            &error.to_string(),
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        );
                        continue;
                    }
                };

                if let Some(active_turn) = active.as_mut() {
                    match frame.kind.as_str() {
                        FRAME_TURN_CANCEL => handle_turn_cancel(
                            frame,
                            active_turn,
                            &mut writer,
                            &mut output,
                            persistence,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        ),
                        FRAME_TOOL_CANCEL => handle_tool_cancel(
                            frame,
                            active_turn,
                            &registry,
                            &mut writer,
                            &mut output,
                            persistence,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        ),
                        FRAME_TURN_INSPECT => handle_turn_inspect(
                            frame,
                            Some(active_turn),
                            &mut writer,
                            &mut output,
                            persistence,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        ),
                        FRAME_CALL_INSPECT => handle_call_inspect(
                            frame,
                            Some(active_turn),
                            &registry,
                            &mut writer,
                            &mut output,
                            persistence,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        ),
                        other => deliver_host_error(
                            &mut writer,
                            &mut output,
                            Some(&active_turn.context),
                            "connection_state",
                            &format!("frame {other} is not valid while a turn is active"),
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        ),
                    }
                    continue;
                }

                match frame.kind.as_str() {
                    FRAME_HELLO => write_hello(
                        &mut writer,
                        &mut output,
                        persistence,
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    ),
                    FRAME_TURN_START => {
                        let request = match frame.turn_request(&limits) {
                            Ok(request) => request,
                            Err(error) => {
                                deliver_host_error(
                                    &mut writer,
                                    &mut output,
                                    None,
                                    "invalid_frame",
                                    &error.to_string(),
                                    limits.max_frame_bytes,
                                    &mut delivery_attached,
                                    &mut delivery_error,
                                );
                                continue;
                            }
                        };
                        let context = output.context(&request)?;
                        let digest = request_sha256(&request)?;
                        let durable_scope = event_scope(&request, &context.turn_stream_id);
                        if let Some(error) = persistence.effect_admission_error() {
                            deliver_unscoped_host_error_with_context(
                                &mut writer,
                                &mut output,
                                &context,
                                "turn_journal_unavailable",
                                &error,
                                limits.max_frame_bytes,
                                &mut delivery_attached,
                                &mut delivery_error,
                            );
                            continue;
                        }
                        match persistence.load(&durable_scope, &digest) {
                            StoredTurn::Complete(frames) => {
                                output.observe_replay(&frames);
                                deliver_replay(
                                    &mut writer,
                                    &frames,
                                    limits.max_frame_bytes,
                                    &mut delivery_attached,
                                    &mut delivery_error,
                                );
                                continue;
                            }
                            StoredTurn::Incomplete(mut frames) => {
                                output.observe_replay(&frames);
                                let terminal = output.frame(
                                    FRAME_TURN_END,
                                    json!({
                                        "status": "unknown_after_disconnect",
                                        "summary": Value::Null,
                                        "error": "a prior durable turn has no terminal observation; automatic redispatch is denied",
                                        "runtime_ready": persistence.effect_admission_error().is_none(),
                                        "reconciliation": true,
                                        "automatic_redispatch": false,
                                        "event_log_status": persistence.status(),
                                        "event_log_error": persistence.error()
                                    }),
                                    Some(&context),
                                    EventCorrelation::default(),
                                );
                                let terminal = persist_for_delivery(
                                    persistence,
                                    &durable_scope,
                                    &digest,
                                    terminal,
                                );
                                frames.push(terminal);
                                deliver_replay(
                                    &mut writer,
                                    &frames,
                                    limits.max_frame_bytes,
                                    &mut delivery_attached,
                                    &mut delivery_error,
                                );
                                continue;
                            }
                            StoredTurn::Conflict(error) | StoredTurn::Unavailable(error) => {
                                // A conflicting retry has no valid request
                                // context for this turn stream.  `context()`
                                // resets the per-turn host cursor, so emitting
                                // the error with it would rewind host_seq to
                                // zero and reuse the prior turn event id.
                                // Keep the diagnostic in the connection
                                // control domain instead; this allocator is
                                // shared with the outer v7 carrier.
                                deliver_unscoped_host_error_with_context(
                                    &mut writer,
                                    &mut output,
                                    &context,
                                    "turn_replay_conflict",
                                    &error,
                                    limits.max_frame_bytes,
                                    &mut delivery_attached,
                                    &mut delivery_error,
                                );
                                continue;
                            }
                            StoredTurn::Empty => {}
                        }

                        let accepted = output.frame(
                            FRAME_TURN_ACCEPTED,
                            json!({
                                "status": "accepted",
                                "provider_status": "starting",
                                "event_log_status": persistence.status(),
                                "event_log_error": persistence.error(),
                                "streaming_events": true,
                                "active_turn_controls": true,
                                "turn_request_sha256": &digest
                            }),
                            Some(&context),
                            EventCorrelation::default(),
                        );
                        let accepted = match persist_before_effect(
                            persistence,
                            &durable_scope,
                            &digest,
                            accepted,
                        ) {
                            Ok(frame) => frame,
                            Err(error) => {
                                deliver_unscoped_host_error_with_context(
                                    &mut writer,
                                    &mut output,
                                    &context,
                                    "turn_journal_unavailable",
                                    &error,
                                    limits.max_frame_bytes,
                                    &mut delivery_attached,
                                    &mut delivery_error,
                                );
                                continue;
                            }
                        };
                        deliver_frame(
                            &mut writer,
                            &accepted,
                            limits.max_frame_bytes,
                            &mut delivery_attached,
                            &mut delivery_error,
                        );

                        let loop_request = LoopTurnRequest {
                            session_id: context.session_id.clone(),
                            profile_id: context.profile_id.clone(),
                            task_id: context.task_id.clone(),
                            turn_id: context.turn_id.clone(),
                            turn_stream_id: context.turn_stream_id.clone(),
                            user_input: request.user_input,
                        };
                        let cancellation = TurnCancellation::new();
                        let worker_cancellation = cancellation.clone();
                        let worker_registry = Arc::clone(&registry);
                        let worker_sender = sender.clone();
                        let mut provider = provider_template.clone();
                        let worker = thread::Builder::new()
                            .name(format!("owner-open-turn-{}", context.turn_id))
                            .spawn(move || {
                                let runner = TurnRunner::new(worker_registry);
                                let event_sender = worker_sender.clone();
                                let mut sink = move |event: &TurnEvent| -> Result<(), String> {
                                    send_turn_event(&event_sender, event)
                                };
                                let result = runner
                                    .run_with_sink_and_cancellation(
                                        loop_request,
                                        &mut provider,
                                        &worker_cancellation,
                                        &mut sink,
                                    )
                                    .map(|run| run.terminal)
                                    .map_err(|error| error.to_string());
                                let _ = worker_sender.send(HostMessage::TurnComplete(result));
                            })
                            .map_err(|error| {
                                format!("failed to spawn active turn worker: {error}")
                            })?;
                        active = Some(ActiveTurn {
                            context,
                            request_digest: digest,
                            durable_scope,
                            cancellation,
                            worker: Some(worker),
                        });
                    }
                    FRAME_TURN_INSPECT => handle_turn_inspect(
                        frame,
                        None,
                        &mut writer,
                        &mut output,
                        persistence,
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    ),
                    FRAME_CALL_INSPECT => handle_call_inspect(
                        frame,
                        None,
                        &registry,
                        &mut writer,
                        &mut output,
                        persistence,
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    ),
                    FRAME_TURN_CANCEL | FRAME_TOOL_CANCEL => {
                        match no_active_cancel_reply(&frame, &mut output) {
                            Ok(reply) => deliver_frame(
                                &mut writer,
                                &reply,
                                limits.max_frame_bytes,
                                &mut delivery_attached,
                                &mut delivery_error,
                            ),
                            Err(error) => deliver_host_error(
                                &mut writer,
                                &mut output,
                                None,
                                "invalid_control_context",
                                &error,
                                limits.max_frame_bytes,
                                &mut delivery_attached,
                                &mut delivery_error,
                            ),
                        }
                    }
                    other => deliver_host_error(
                        &mut writer,
                        &mut output,
                        None,
                        "unsupported_frame",
                        &format!("unsupported client frame kind {other}"),
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    ),
                }
            }
            Ok(HostMessage::InputEof) => {
                input_open = false;
            }
            Ok(HostMessage::InputError(error)) => {
                input_open = false;
                delivery_error.get_or_insert(error);
            }
            Ok(HostMessage::TurnEvent { event, receipt }) => {
                let Some(active_turn) = active.as_ref() else {
                    let _ = receipt.send(Err("turn is no longer active".to_string()));
                    continue;
                };
                if let Some(frame) = map_turn_event(&mut output, &active_turn.context, &event) {
                    match persist_before_effect(
                        persistence,
                        &active_turn.durable_scope,
                        &active_turn.request_digest,
                        frame,
                    ) {
                        Ok(frame) => {
                            // Acknowledge journal custody before client delivery;
                            // slow or detached clients do not authorize cancellation.
                            let _ = receipt.send(Ok(()));
                            deliver_frame(
                                &mut writer,
                                &frame,
                                limits.max_frame_bytes,
                                &mut delivery_attached,
                                &mut delivery_error,
                            );
                        }
                        Err(error) => {
                            active_turn.cancellation.cancel();
                            let _ = receipt.send(Err(error));
                        }
                    }
                } else {
                    let result = persistence.effect_admission_error().map_or(Ok(()), Err);
                    if result.is_err() {
                        active_turn.cancellation.cancel();
                    }
                    let _ = receipt.send(result);
                }
            }
            Ok(HostMessage::TurnComplete(result)) => {
                let Some(mut active_turn) = active.take() else {
                    continue;
                };
                let worker_result = active_turn
                    .worker
                    .take()
                    .expect("active turn has a worker")
                    .join();
                let result = if worker_result.is_err() {
                    Err("active turn worker panicked".to_string())
                } else {
                    result
                };
                finish_active_turn(
                    active_turn,
                    result,
                    &mut writer,
                    &mut output,
                    persistence,
                    limits.max_frame_bytes,
                    &mut delivery_attached,
                    &mut delivery_error,
                );
            }
            Err(RecvTimeoutError::Timeout) => {
                let worker_finished = active
                    .as_ref()
                    .and_then(|active_turn| active_turn.worker.as_ref())
                    .is_some_and(JoinHandle::is_finished);
                if worker_finished {
                    let mut active_turn =
                        active.take().expect("finished worker has an active turn");
                    let worker_result = active_turn
                        .worker
                        .take()
                        .expect("active turn has a worker")
                        .join();
                    let result = match worker_result {
                        Ok(()) => {
                            Err("active turn worker exited without a terminal message".to_string())
                        }
                        Err(_) => Err("active turn worker panicked".to_string()),
                    };
                    finish_active_turn(
                        active_turn,
                        result,
                        &mut writer,
                        &mut output,
                        persistence,
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    );
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                input_open = false;
                if active.is_none() {
                    return Ok(());
                }
            }
        }
    }
}

/// A no-active rejection completes this control request, not the original turn.
/// Retain its exact broker tuple and full lineage in the connection-control
/// domain. Never append a duplicate turn terminal, reset its replay cursor, or
/// claim that a prior effect was cancelled or undone.
fn no_active_cancel_reply(
    frame: &RunTurnFrame,
    output: &mut OutputState,
) -> Result<RunTurnFrame, String> {
    if !matches!(frame.kind.as_str(), FRAME_TURN_CANCEL | FRAME_TOOL_CANCEL)
        || !frame.payload.is_object()
    {
        return Err("expected an object cancellation control".to_string());
    }
    let session_id = correlated_id(frame, "session_id", frame.session_id.as_deref())?;
    let profile_id = correlated_id(frame, "profile_id", frame.profile_id.as_deref())?;
    let task_id = correlated_id(frame, "task_id", frame.task_id.as_deref())?;
    let turn_id = correlated_id(frame, "turn_id", frame.turn_id.as_deref())?;
    for (name, value) in [
        ("session_id", &session_id), ("profile_id", &profile_id),
        ("task_id", &task_id), ("turn_id", &turn_id),
    ] {
        if !valid_id(value) { return Err(format!("{name} is malformed")); }
    }
    let turn_stream_id = optional_correlated_id(frame, "turn_stream_id", frame.turn_stream_id.as_deref())?;
    let stream_alias = optional_correlated_id(frame, "stream_id", frame.stream_id.as_deref())?;
    if let (Some(left), Some(right)) = (&turn_stream_id, &stream_alias)
        && left != right
    { return Err("conflicting cancellation stream aliases".to_string()); }
    let stream = turn_stream_id.or(stream_alias)
        .ok_or_else(|| "cancellation requires its complete stream scope".to_string())?;
    if stream != stable_stream_id(&session_id, &profile_id, &task_id, &turn_id)? {
        return Err("cancellation stream does not match its stable scope".to_string());
    }
    let call_id = optional_correlated_id(frame, "call_id", frame.call_id.as_deref())?;
    if frame.kind == FRAME_TOOL_CANCEL
        && !call_id.as_deref().is_some_and(valid_id)
    { return Err("tool.cancel requires a valid call_id".to_string()); }
    if frame.kind == FRAME_TURN_CANCEL && call_id.is_some() {
        return Err("turn.cancel cannot claim a call identity".to_string());
    }

    let mut broker = serde_json::Map::new();
    for name in ["broker_request_id", "broker_request_sha256", "broker_request_upstream_seq"] {
        let envelope = frame.extensions.get(name);
        let mirror = frame.payload.get(name);
        if let (Some(left), Some(right)) = (envelope, mirror)
            && left != right
        { return Err(format!("conflicting cancellation {name} mirrors")); }
        if let Some(value) = envelope.or(mirror) {
            let valid = match name {
                "broker_request_id" => value.as_str().is_some_and(valid_id),
                "broker_request_sha256" => value.as_str().is_some_and(valid_sha256),
                _ => value.as_u64().is_some(),
            };
            if !valid { return Err(format!("malformed cancellation {name}")); }
            broker.insert(name.to_string(), value.clone());
        }
    }
    if !broker.is_empty() && broker.len() != 3 {
        return Err("partial cancellation broker tuple".to_string());
    }
    let mut reply = output.frame(
        "host.error",
        json!({
            "code": "no_active_turn",
            "message": "the control frame has no active turn; no cancellation was requested",
            "request_kind": frame.kind,
            "session_id": session_id, "profile_id": profile_id,
            "task_id": task_id, "turn_id": turn_id, "turn_stream_id": stream,
            "automatic_redispatch": false, "cancel_requested": false,
            "prior_effect_outcome": "unknown",
        }),
        None,
        EventCorrelation { call_id, ..EventCorrelation::default() },
    );
    for (name, value) in broker {
        reply.extensions.insert(name.clone(), value.clone());
        reply.payload[name] = value;
    }
    Ok(reply)
}

#[cfg(test)]
mod inactive_cancel_tests {
    use super::*;

    fn request(kind: &str) -> RunTurnFrame {
        let stream = stable_stream_id("session-cancel", "owner-open", "task-cancel", "turn-cancel").unwrap();
        let mut value = json!({"kind":kind,"seq":7,"payload":{
            "session_id":"session-cancel","profile_id":"owner-open","task_id":"task-cancel",
            "turn_id":"turn-cancel","turn_stream_id":stream},
            "broker_request_id":"client:7","broker_request_sha256":"a".repeat(64),
            "broker_request_upstream_seq":17});
        if kind == "tool.cancel" { value["payload"]["call_id"] = json!("call-cancel"); }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn no_active_reply_preserves_exact_control_tuple_without_turn_terminal() {
        let mut output = OutputState::new("connection-inactive".to_string());
        output.next_host_seq = 42;
        for kind in ["turn.cancel", "tool.cancel"] {
            let request = request(kind);
            let reply = no_active_cancel_reply(&request,&mut output).unwrap();
            assert_eq!(reply.kind,"host.error");
            assert_eq!(reply.payload["code"],"no_active_turn");
            assert_eq!(reply.payload["request_kind"],kind);
            assert_eq!(reply.extensions["broker_request_id"],"client:7");
            assert_eq!(reply.extensions["broker_request_upstream_seq"],17);
            assert_eq!(reply.payload["broker_request_sha256"],"a".repeat(64));
            assert_eq!(reply.payload["cancel_requested"],false);
            assert_eq!(output.next_host_seq,42);
            assert_eq!(reply.call_id.as_deref(), if kind == "tool.cancel" { Some("call-cancel") } else { None });
        }
    }

    #[test]
    fn inactive_cancel_rejects_conflicting_scope_or_partial_control_tuple() {
        for field in ["session_id","profile_id","task_id","turn_id","turn_stream_id"] {
            let mut request = request("turn.cancel");
            request.payload[field] = json!("conflicting");
            assert!(no_active_cancel_reply(&request,&mut OutputState::new("c".into())).is_err());
        }
        let mut partial = request("turn.cancel");
        partial.extensions.remove("broker_request_sha256");
        assert!(no_active_cancel_reply(&partial,&mut OutputState::new("c".into())).is_err());
        let mut mirrored = request("turn.cancel");
        mirrored.payload["broker_request_id"] = json!("another-control");
        assert!(no_active_cancel_reply(&mirrored,&mut OutputState::new("c".into())).is_err());
        let mut aliases = request("turn.cancel");
        aliases.payload["stream_id"] = json!("different-stream");
        assert!(no_active_cancel_reply(&aliases,&mut OutputState::new("c".into())).is_err());
    }
}
