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
                        let durable_scope =
                            event_scope(&request, &context.turn_stream_id);
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
                                        "runtime_ready": true,
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
                            StoredTurn::Conflict(error) => {
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
                        let accepted = persist_for_delivery(
                            persistence,
                            &durable_scope,
                            &digest,
                            accepted,
                        );
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
                                let mut sink =
                                    move |event: &TurnEvent| -> Result<(), String> {
                                        event_sender
                                            .send(HostMessage::TurnEvent(Box::new(event.clone())))
                                            .map_err(|_| {
                                                "Host event receiver disconnected"
                                                    .to_string()
                                            })
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
                                let _ = worker_sender
                                    .send(HostMessage::TurnComplete(result));
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
                    FRAME_TURN_CANCEL | FRAME_TOOL_CANCEL => deliver_host_error(
                        &mut writer,
                        &mut output,
                        None,
                        "no_active_turn",
                        "the control frame has no active turn",
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    ),
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
            Ok(HostMessage::TurnEvent(event)) => {
                let Some(active_turn) = active.as_ref() else {
                    continue;
                };
                if let Some(frame) =
                    map_turn_event(&mut output, &active_turn.context, &event)
                {
                    let frame = persist_for_delivery(
                        persistence,
                        &active_turn.durable_scope,
                        &active_turn.request_digest,
                        frame,
                    );
                    deliver_frame(
                        &mut writer,
                        &frame,
                        limits.max_frame_bytes,
                        &mut delivery_attached,
                        &mut delivery_error,
                    );
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
                        Ok(()) => Err(
                            "active turn worker exited without a terminal message"
                                .to_string(),
                        ),
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
