fn next_transport_message(
    receiver: &Receiver<TransportMessage>,
    pending: &mut VecDeque<TransportMessage>,
    prioritize_client: bool,
    client_priority_streak: &mut usize,
) -> Result<TransportMessage, RecvTimeoutError> {
    if pending.is_empty() {
        pending.push_back(receiver.recv_timeout(TRANSPORT_POLL_INTERVAL)?);
    }
    // A core reader can publish an acknowledgement at the same instant that
    // the client reader publishes a pipelined turn.start.  Collect the
    // already-ready batch so admission state is observed before we release
    // any core frames; future messages are still handled in normal channel
    // order and the queue remains bounded by TRANSPORT_QUEUE_DEPTH.
    while pending.len() < TRANSPORT_QUEUE_DEPTH {
        let Ok(message) = receiver.try_recv() else {
            break;
        };
        pending.push_back(message);
    }
    // Once a lifecycle terminal has been published there is no safe write
    // left to forward to the core. Process that observation before a queued
    // client frame *only when it is the first pending core-domain message*.
    // The core reader publishes `CoreFrame` and then `CoreEof`/`CoreError` in
    // one thread, so skipping a frame here would violate that source FIFO and
    // could discard a valid hello.ack/turn.accepted. A `CoreExited` from the
    // waiter may legitimately arrive before a not-yet-published reader frame;
    // the normal drain grace handles that independent producer ordering.
    let terminal_index = {
        let mut terminal_index = None;
        for (index, message) in pending.iter().enumerate() {
            match message {
                // A core frame is the first core-domain event, so a later
                // terminal must wait until this frame has been handled.
                TransportMessage::CoreFrame(_) => break,
                TransportMessage::CoreEof
                | TransportMessage::CoreError(_)
                | TransportMessage::CoreExited(_) => {
                    terminal_index = Some(index);
                    break;
                }
                TransportMessage::ClientFrame(_)
                | TransportMessage::ClientEof
                | TransportMessage::ClientError(_) => {}
            }
        }
        terminal_index
    };
    if let Some(index) = terminal_index {
        *client_priority_streak = 0;
        return Ok(pending
            .remove(index)
            .expect("terminal core message index came from pending queue"));
    }
    if prioritize_client {
        let client_index = pending.iter().position(is_client_message);
        let core_index = pending.iter().position(is_core_message);

        // A pipelined client frame must get a short admission window ahead of
        // a concurrently published core acknowledgement.  Keep that window
        // bounded, however: a client-reader flood must not prevent the core
        // reader from making progress forever.
        if let Some(index) = client_index
            && (core_index.is_none() || *client_priority_streak < MAX_CLIENT_PRIORITY_BURST)
        {
            if core_index.is_none() {
                // No core event is waiting, so there is no starvation to
                // account for.  Start a fresh burst when one arrives.
                *client_priority_streak = 0;
            } else {
                *client_priority_streak = client_priority_streak.saturating_add(1);
            }
            return Ok(pending
                .remove(index)
                .expect("client message index came from pending queue"));
        }

        // The client burst budget is exhausted.  Select the oldest core
        // domain item (rather than blindly popping the front) so a core frame
        // cannot be buried under an unbounded client backlog.
        if let Some(index) = core_index {
            *client_priority_streak = 0;
            return Ok(pending
                .remove(index)
                .expect("core message index came from pending queue"));
        }
    }

    let message = pending
        .pop_front()
        .expect("recv or try_recv populated pending queue");
    if is_core_message(&message) {
        *client_priority_streak = 0;
    }
    Ok(message)
}

/// Keep the cross-thread staging queue bounded even when the synchronous
/// channel is drained in one pass.  Once the core is terminal or the
/// handshake has failed, client bytes have no safe destination and must not be
/// replayed into a closed stdin (or converted into an unbounded stream of
/// secondary forwarding errors).
fn discard_queued_client_messages(pending: &mut VecDeque<TransportMessage>) {
    pending.retain(|message| !is_client_message(message));
}

fn is_client_message(message: &TransportMessage) -> bool {
    matches!(
        message,
        TransportMessage::ClientFrame(_)
            | TransportMessage::ClientEof
            | TransportMessage::ClientError(_)
    )
}

fn is_core_message(message: &TransportMessage) -> bool {
    matches!(
        message,
        TransportMessage::CoreFrame(_)
            | TransportMessage::CoreEof
            | TransportMessage::CoreError(_)
            | TransportMessage::CoreExited(_)
    )
}

pub(crate) fn run() -> Result<(), String> {
    let options = Options::parse(env::args_os().skip(1).collect())?;
    if options.help {
        println!("{}", Options::usage());
        return Ok(());
    }

    let limits = MechanicalLimits::default();
    let (child, mut core_stdin, core_stdout, core_stderr) = spawn_core(&options)?;
    spawn_stderr_drain(core_stderr)?;

    let (sender, receiver) = sync_channel(TRANSPORT_QUEUE_DEPTH);
    spawn_client_reader(sender.clone(), limits.max_frame_bytes)?;
    spawn_core_reader(core_stdout, sender.clone(), limits.max_frame_bytes)?;
    spawn_core_waiter(child, sender)?;

    let stdout = io::stdout();
    let mut delivery = ClientDelivery::new(stdout.lock(), limits.max_frame_bytes);
    let mut output = TransportOutput::new();
    let mut flow = StreamDelivery::new(&options);
    let mut journal = TransportJournal::open(options.event_store.as_deref());
    let mut active = None::<TurnContext>;
    let mut handshake = TransportHandshake::default();
    let mut durable_ready = false;
    let mut client_open = true;
    let mut core_reader_open = true;
    let mut core_wait_open = true;
    let mut core_status = None::<ExitStatus>;
    let mut core_exit_deadline = None::<Instant>;
    let mut terminal_error = None::<String>;
    // Once any core lifecycle terminal has been observed, stdin is no longer
    // a valid destination.  The waiter may still be draining a final reader
    // event, but queued/future client frames must already be discarded.
    let mut core_input_open = true;
    // Client and core readers feed the same bounded channel from independent
    // threads.  Drain currently-ready messages and prioritize client ingress
    // before releasing a core acknowledgement; otherwise a pipelined
    // `turn.start` can lose the race with `hello.ack`, causing pre-accept
    // frames to consume host_seq zero.
    let mut pending_messages = VecDeque::<TransportMessage>::new();
    let mut client_priority_streak = 0usize;

    while core_reader_open || core_wait_open {
        if !core_input_open || handshake.failed() || !client_open {
            discard_queued_client_messages(&mut pending_messages);
        }
        match next_transport_message(
            &receiver,
            &mut pending_messages,
            handshake.awaiting_ack() || handshake.turn_pending(),
            &mut client_priority_streak,
        ) {
            Ok(TransportMessage::ClientFrame(encoded)) => {
                if !core_input_open || handshake.failed() || !client_open {
                    // The core has terminated (or the handshake has become
                    // terminal) before this queued frame reached the run
                    // loop. It has no safe forwarding destination and must
                    // not produce a secondary error for the upstream peer.
                    continue;
                }
                let frame = match RunTurnFrame::decode(&encoded, &limits) {
                    Ok(frame) => frame,
                    Err(error) => {
                        // Even an undecodable first line consumes the
                        // optional hello-preface position.  Do this before
                        // producing the local error so a later hello cannot
                        // reopen the connection gate or reuse seq=0.
                        handshake.consume_preface();
                        let broker_binding = binding_from_encoded_frame(&encoded, &limits);
                        write_local_error_or_defer(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            active.as_ref(),
                            "invalid_frame",
                            &error.to_string(),
                            broker_binding.as_ref(),
                        )?;
                        continue;
                    }
                };

                // A broker request envelope is transport metadata, not part
                // of the semantic turn payload.  Bind it at the ingress
                // boundary and let ClientDelivery echo the exact values on
                // every response generated while this request is active.
                // A frame without the metadata explicitly clears a prior
                // binding so an unrelated direct client frame can never
                // inherit a stale broker identity.
                let broker_binding = match BrokerRequestBinding::from_frame(&frame) {
                    Ok(binding) => binding,
                    Err(error) => {
                        // The bytes were a client frame even though their
                        // broker envelope was malformed; consume the
                        // preface slot before reporting the validation
                        // error.
                        handshake.consume_preface();
                        write_local_error_or_defer(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            active.as_ref(),
                            "invalid_frame",
                            &error,
                            None,
                        )?;
                        continue;
                    }
                };

                // Correlation aliases are part of the ingress contract even
                // when the frame is otherwise mechanically decodable.  In
                // particular, a payload carrying conflicting
                // `turn_stream_id`/`stream_id` values must not reach
                // `rewrite_core_with_context`, where choosing one spelling
                // could allocate a sequence under the wrong stream before
                // the broker router notices the ambiguity.  Report the
                // malformed request through its exact broker binding when
                // present, rather than allowing `register_broker_request`
                // to bubble the error out of the transport loop.
                if let Err(error) = BrokerLineage::from_frame(&frame) {
                    handshake.consume_preface();
                    write_local_error_or_defer(
                        &mut delivery,
                        &mut output,
                        &mut handshake,
                        active.as_ref(),
                        "invalid_frame",
                        &error,
                        broker_binding.as_ref(),
                    )?;
                    continue;
                }

                // Reject a bounded broker-router overflow before opening a
                // handshake gate. Otherwise a later `register` failure could
                // leave a retained hello binding behind and escalate through
                // the transport's process-level `Result` instead of producing
                // a correlated resource error.
                if frame.kind == FRAME_HELLO
                    && let Err(error) =
                        delivery.check_broker_request_capacity(&frame, broker_binding.as_ref())
                {
                    handshake.consume_preface();
                    write_local_error_or_defer(
                        &mut delivery,
                        &mut output,
                        &mut handshake,
                        None,
                        "resource_exhausted",
                        &error,
                        broker_binding.as_ref(),
                    )?;
                    continue;
                }

                if frame.kind == FRAME_HELLO {
                    if let Err(error) = handshake.begin_hello() {
                        write_local_error_or_defer(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            None,
                            "connection_state",
                            &error,
                            broker_binding.as_ref(),
                        )?;
                        continue;
                    }
                    // Keep the exact broker envelope beside the handshake
                    // gate.  If the core closes or emits malformed bytes
                    // before hello.ack, the router has no response frame to
                    // select and this retained binding is the only safe way
                    // to resolve the upstream request.
                    handshake.retain_hello_binding(broker_binding.clone());
                    let forwarded_binding = broker_binding.clone();
                    if let Err(error) =
                        delivery.register_broker_request(&frame, broker_binding.clone())
                    {
                        // Capacity was checked above; this defensive branch
                        // handles a future registration invariant without
                        // allowing it to become a process-level failure.
                        fail_pending_handshake(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            ("resource_exhausted", error.as_str()),
                            ("resource_exhausted", error.as_str()),
                        )?;
                        if let Some(binding) = forwarded_binding.as_ref() {
                            delivery.discard_broker_binding(binding);
                        }
                        core_input_open = false;
                        drop(core_stdin.take());
                        continue;
                    }
                    if let Err(error) = forward_to_core(&mut core_stdin, &encoded) {
                        fail_pending_handshake(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            ("core_forward_failed", error.as_str()),
                            ("core_forward_failed", error.as_str()),
                        )?;
                        core_input_open = false;
                        drop(core_stdin.take());
                        terminal_error.get_or_insert(error);
                        continue;
                    }
                    delivery.mark_broker_forwarded(forwarded_binding.as_ref());
                    continue;
                }

                // Every valid non-hello frame consumes the optional preface
                // position before any local branch can reject or forward it.
                handshake.consume_preface();

                if is_flow_control_kind(&frame.kind) {
                    let Some(context) = active.as_ref() else {
                        write_local_error_or_defer(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            None,
                            "no_active_turn",
                            "stream control has no active turn",
                            broker_binding.as_ref(),
                        )?;
                        continue;
                    };
                    if options.event_store.is_none() || !durable_ready {
                        write_local_error_or_defer(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            Some(context),
                            "flow_control_requires_durable_store",
                            "bounded pause/window delivery requires an available durable event store",
                            broker_binding.as_ref(),
                        )?;
                        continue;
                    }
                    handle_flow_control(
                        frame,
                        context,
                        &mut flow,
                        &mut output,
                        &mut delivery,
                        broker_binding.as_ref(),
                        &mut handshake,
                    )?;
                    continue;
                }

                if frame.kind == FRAME_TURN_START {
                    if active.is_some() {
                        write_local_error_or_defer(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            // The rejected request is not the active turn;
                            // using `active` here would attach the new
                            // broker envelope to the old turn's host cursor.
                            // Keep this connection-state rejection in the
                            // unscoped control domain.
                            None,
                            "connection_state",
                            "a second turn.start is not valid while a turn is active",
                            broker_binding.as_ref(),
                        )?;
                        continue;
                    }
                    match TurnContext::from_start(&frame, &limits) {
                        Ok(context) => {
                            // Perform the finite router-capacity check before
                            // opening the turn gate or resetting flow state;
                            // an overflow is a pre-acceptance rejection.
                            if let Err(error) = delivery
                                .check_broker_request_capacity(&frame, broker_binding.as_ref())
                            {
                                write_local_error_or_defer(
                                    &mut delivery,
                                    &mut output,
                                    &mut handshake,
                                    Some(&context),
                                    "resource_exhausted",
                                    &error,
                                    broker_binding.as_ref(),
                                )?;
                                continue;
                            }
                            if let Err(error) = handshake.begin_turn() {
                                write_local_error_or_defer(
                                    &mut delivery,
                                    &mut output,
                                    &mut handshake,
                                    Some(&context),
                                    "connection_state",
                                    &error,
                                    broker_binding.as_ref(),
                                )?;
                                continue;
                            }
                            // Retain the turn-start envelope until its
                            // acceptance (or a bounded pre-accept failure)
                            // has been observed.  EOF/core protocol failure
                            // paths use it for a correlated host.error.
                            handshake.retain_turn_binding(broker_binding.clone());
                            flow.begin_turn();
                            if let Err(error) =
                                delivery.register_broker_request(&frame, broker_binding.clone())
                            {
                                // Capacity was checked above; fail closed if
                                // another registration invariant is added in
                                // the future rather than propagating `?` out
                                // of the transport loop.
                                fail_pending_handshake(
                                    &mut delivery,
                                    &mut output,
                                    &mut handshake,
                                    ("resource_exhausted", error.as_str()),
                                    ("resource_exhausted", error.as_str()),
                                )?;
                                if let Some(binding) = broker_binding.as_ref() {
                                    delivery.discard_broker_binding(binding);
                                }
                                flow.finish_turn();
                                core_input_open = false;
                                drop(core_stdin.take());
                                continue;
                            }
                            active = Some(context);
                        }
                        Err(error) => {
                            write_local_error_or_defer(
                                &mut delivery,
                                &mut output,
                                &mut handshake,
                                None,
                                "invalid_frame",
                                &error,
                                broker_binding.as_ref(),
                            )?;
                            continue;
                        }
                    }
                }
                let forwarded_binding = broker_binding.clone();
                if frame.kind != FRAME_TURN_START
                    && let Err(error) =
                        delivery.register_broker_request(&frame, broker_binding.clone())
                {
                    // One-shot broker intents are bounded. Reject this
                    // request locally and keep the transport/core alive;
                    // a queue-cap error must not become process exit(2).
                    if let Some(binding) = broker_binding.as_ref() {
                        delivery.discard_broker_binding(binding);
                    }
                    write_local_error_or_defer(
                        &mut delivery,
                        &mut output,
                        &mut handshake,
                        active.as_ref(),
                        "resource_exhausted",
                        &error,
                        broker_binding.as_ref(),
                    )?;
                    continue;
                }
                if let Err(error) = forward_to_core(&mut core_stdin, &encoded) {
                    if handshake.awaiting_ack() || handshake.turn_pending() {
                        fail_pending_handshake(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            ("core_forward_failed", error.as_str()),
                            ("core_forward_failed", error.as_str()),
                        )?;
                    }
                    core_input_open = false;
                    drop(core_stdin.take());
                    terminal_error.get_or_insert(error);
                } else {
                    delivery.mark_broker_forwarded(forwarded_binding.as_ref());
                }
            }
            Ok(TransportMessage::ClientEof) => {
                if !core_input_open || handshake.failed() {
                    client_open = false;
                    continue;
                }
                client_open = false;
                core_input_open = false;
                drop(core_stdin.take());
            }
            Ok(TransportMessage::ClientError(error)) => {
                if !core_input_open || handshake.failed() {
                    client_open = false;
                    continue;
                }
                client_open = false;
                core_input_open = false;
                terminal_error.get_or_insert(error);
                drop(core_stdin.take());
            }
            Ok(TransportMessage::CoreFrame(encoded)) => {
                if handshake.failed() {
                    // A failed handshake has already emitted its single
                    // explicit rejection (or closed the client).  Late bytes
                    // from a draining core cannot be admitted as effects.
                    continue;
                }
                let mut frame = match RunTurnFrame::decode(&encoded, &limits) {
                    Ok(frame) => frame,
                    Err(error) => {
                        if handshake.late_turn_core_is_quarantined() {
                            // A pre-accept negative resolver already closed
                            // the generation. An undecodable late byte cannot
                            // prove that it belongs to a newer request.
                            continue;
                        }
                        if handshake.awaiting_ack() || handshake.turn_pending() {
                            let message = format!(
                                "core emitted an invalid Host frame before handshake acknowledgement: {error}"
                            );
                            fail_pending_handshake(
                                &mut delivery,
                                &mut output,
                                &mut handshake,
                                ("core_protocol_error", message.as_str()),
                                ("core_protocol_error", message.as_str()),
                            )?;
                            continue;
                        }
                        return Err(format!("core emitted an invalid Host frame: {error}"));
                    }
                };
                if handshake.should_drop_late_core(&frame, active.as_ref()) {
                    // A pre-accept negative resolver already closed the turn
                    // generation. Bytes still draining from that core are
                    // stale observations, not a new request, and must not be
                    // routed into a later active stream.
                    continue;
                }

                // Validate the stream aliases before any transport sequence
                // allocation.  `RunTurnFrame::validate_mechanical` checks the
                // top-level pair, but legacy Hosts may put both spellings in
                // the payload; selecting one of those values in
                // `rewrite_core_with_context` would otherwise assign the
                // frame to an arbitrary stream before the broker router can
                // reject it.  A malformed resolver closes the pending gate;
                // an ordinary malformed response gets one bound protocol
                // error and its exact broker intent is retired.
                if let Err(error) = correlated_stream_id(&frame) {
                    if handshake.awaiting_ack() || handshake.turn_pending() {
                        fail_pending_handshake(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            ("core_protocol_error", &error),
                            ("core_protocol_error", &error),
                        )?;
                    } else {
                        let binding = BrokerRequestBinding::from_frame(&frame)
                            .ok()
                            .flatten();
                        write_local_error_for_binding(
                            &mut delivery,
                            &mut output,
                            None,
                            "core_protocol_error",
                            &error,
                            binding.as_ref(),
                        )?;
                        if let Some(binding) = binding.as_ref() {
                            delivery.discard_broker_binding(binding);
                        }
                    }
                    continue;
                }

                // The core startup acknowledgement and turn acceptance are
                // single-generation lifecycle events.  A duplicate must not
                // be routed through the generic body (which would allocate a
                // second sequence and, worse, could reopen a broker intent).
                // The first unprompted hello.ack remains accepted for legacy
                // cores that always publish a startup preface.
                if frame.kind == FRAME_HELLO_ACK {
                    if handshake.hello_ack_seen() {
                        continue;
                    }
                    handshake.observe_hello_ack();
                }
                if frame.kind == FRAME_TURN_ACCEPTED {
                    if !handshake.can_accept_turn() {
                        continue;
                    }
                    let Some(context) = active.as_ref() else {
                        // An unsolicited acceptance is not a valid direct
                        // Host observation.  Drop it and let the lifecycle
                        // terminal/EOF path report the pending request, if
                        // any, without inventing a turn scope.
                        continue;
                    };
                    if !turn_frame_matches_context(&frame, context) {
                        // Do not let an old/sibling acceptance consume the
                        // current turn gate.  A later exact acceptance may
                        // still resolve this generation; otherwise EOF gives
                        // the caller a bounded unavailable error.
                        continue;
                    }
                }
                if handshake.turn_pending()
                    && turn_gate_resolution(&frame)
                    && !active
                        .as_ref()
                        .is_some_and(|context| turn_frame_matches_context(&frame, context))
                {
                    // A pre-accept terminal from another lineage is stale;
                    // it must not be rebound to the retained turn request.
                    continue;
                }

                // Record the arrival ordinal immediately, but postpone wire
                // sequence allocation while either handshake gate is open.
                // A deferred provider frame must not consume host_seq zero
                // before the core's `turn.accepted`; it is re-homed when the
                // queue is released.  Once no gate is pending, preserve the
                // core sequence before routing as usual.
                let handshake_gate_pending = handshake.awaiting_ack() || handshake.turn_pending();
                if handshake_gate_pending {
                    delivery.observe_core_frame(&mut frame);
                } else {
                    frame = output.rewrite_core_with_context(frame, active.as_ref());
                    delivery.observe_core_frame(&mut frame);
                }

                // A core acknowledgement is the only frame allowed to cross
                // the hello barrier.  Everything else is retained in a
                // bounded queue until the acknowledgement has been written.
                if handshake.awaiting_ack() && frame.kind != FRAME_HELLO_ACK {
                    let deferred = serde_json::to_vec(&frame)
                        .map_err(|error| format!("cannot defer core frame: {error}"))?;
                    if let Err(error) = handshake.defer_core(deferred) {
                        fail_pending_handshake(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            ("resource_exhausted", error.as_str()),
                            ("resource_exhausted", error.as_str()),
                        )?;
                    }
                    continue;
                }

                // A turn acknowledgement has a second, independent barrier.
                // This is what keeps a locally rejected flow-control request
                // (or any other transport-generated response) from consuming
                // host_seq zero before `turn.accepted`.
                if handshake.turn_pending()
                    && frame.kind != FRAME_TURN_ACCEPTED
                    && frame.kind != FRAME_HELLO_ACK
                    && !turn_gate_resolution(&frame)
                {
                    let deferred = serde_json::to_vec(&frame)
                        .map_err(|error| format!("cannot defer core frame: {error}"))?;
                    if let Err(error) = handshake.defer_core(deferred) {
                        fail_pending_handshake(
                            &mut delivery,
                            &mut output,
                            &mut handshake,
                            ("resource_exhausted", error.as_str()),
                            ("resource_exhausted", error.as_str()),
                        )?;
                    }
                    continue;
                }

                // The frame crossed a gate (acknowledgement, acceptance, or a
                // terminal rejection) and is now eligible for delivery.  Do
                // this exactly once; deferred frames were stored before this
                // point and are rewritten by `release_handshake_queues`.
                if handshake_gate_pending {
                    frame = output.rewrite_core_with_context(frame, active.as_ref());
                }

                if frame.kind == FRAME_HELLO_ACK && handshake.awaiting_ack() {
                    update_durable_ready(&frame, &mut durable_ready);
                    augment_core_frame(
                        &mut frame,
                        active.as_ref(),
                        &options,
                        &flow,
                        durable_ready,
                        &journal,
                    );
                    // The acknowledgement itself always precedes all queued
                    // local/core frames.
                    let hello_binding = handshake.hello_binding().cloned();
                    if let Some(binding) = hello_binding.as_ref() {
                        delivery.send_with_binding(&frame, Some(binding))?;
                    } else {
                        delivery.send(&frame)?;
                    }
                    handshake.clear_hello_binding();
                    let deferred = handshake.acknowledge();
                    // When a turn was pipelined before hello.ack, the state
                    // object intentionally retains its queues.  Take a
                    // snapshot for the resolver scan; it will be restored if
                    // no turn.accepted/terminal frame is present yet.
                    let deferred = if handshake.turn_pending() {
                        handshake.take_deferred()
                    } else {
                        deferred
                    };
                    release_handshake_queues(
                        deferred,
                        &limits,
                        &mut output,
                        &mut delivery,
                        &mut flow,
                        &mut active,
                        &mut durable_ready,
                        &options,
                        &mut journal,
                        &mut handshake,
                    )?;
                    continue;
                }

                if frame.kind == FRAME_TURN_ACCEPTED && handshake.turn_pending() {
                    update_durable_ready(&frame, &mut durable_ready);
                    augment_core_frame(
                        &mut frame,
                        active.as_ref(),
                        &options,
                        &flow,
                        durable_ready,
                        &journal,
                    );
                    // `turn.accepted` must be observable before releasing any
                    // deferred local error or provider frame.
                    let turn_binding = handshake.turn_binding().cloned();
                    if let Some(binding) = turn_binding.as_ref() {
                        delivery.send_with_binding(&frame, Some(binding))?;
                    } else {
                        delivery.send(&frame)?;
                    }
                    let deferred = handshake.release_after_turn_accept();
                    release_handshake_queues(
                        deferred,
                        &limits,
                        &mut output,
                        &mut delivery,
                        &mut flow,
                        &mut active,
                        &mut durable_ready,
                        &options,
                        &mut journal,
                        &mut handshake,
                    )?;
                    continue;
                }

                let resolves_turn_gate = handshake.turn_pending() && turn_gate_resolution(&frame);
                let resolver_is_turn_end = frame.kind == FRAME_TURN_END;
                let resolver_binding = if resolves_turn_gate {
                    handshake.turn_binding().cloned()
                } else {
                    None
                };
                if resolves_turn_gate {
                    // A pre-accept resolver may omit the broker envelope (or
                    // omit the request digest, preventing normal router
                    // selection). Attach the retained turn binding before
                    // the generic core processor emits the frame.
                    if let Some(binding) = resolver_binding.as_ref()
                        && let Err(error) = binding.apply(&mut frame)
                    {
                            let rejected_turn = active.clone();
                            let deferred = handshake.resolve_turn_failure(rejected_turn.as_ref());
                            write_local_error_for_binding(
                                &mut delivery,
                                &mut output,
                                None,
                                "core_protocol_error",
                                &error,
                                Some(binding),
                            )?;
                            reject_deferred_actions(
                                deferred,
                                &mut delivery,
                                &mut output,
                                "turn_rejected",
                                "turn core response carried a conflicting broker envelope",
                            )?;
                            delivery.discard_broker_binding(binding);
                            active = None;
                            flow.finish_turn();
                            continue;
                        }
                }
                let rejected_turn = active.clone();
                process_core_frame_body(
                    frame,
                    &mut output,
                    &mut delivery,
                    &mut flow,
                    &mut active,
                    &mut durable_ready,
                    &options,
                    &mut journal,
                    &mut handshake,
                )?;
                if resolves_turn_gate {
                    if let Some(binding) = resolver_binding.as_ref() {
                        // `process_core_frame_body` sends pre-accept errors
                        // through the normal router, which deliberately does
                        // not establish an unaccepted start intent. Remove
                        // that exact intent now that the gate is terminal so
                        // an identical retry cannot be shadowed by stale FIFO.
                        delivery.discard_broker_binding(binding);
                    }
                    let deferred = handshake.resolve_turn_failure(rejected_turn.as_ref());
                    if !resolver_is_turn_end {
                        active = None;
                        flow.finish_turn();
                    }
                    // A negative core response closes this turn boundary;
                    // late provider frames must not be delivered as if the
                    // turn had been accepted.
                    release_handshake_queues(
                        deferred,
                        &limits,
                        &mut output,
                        &mut delivery,
                        &mut flow,
                        &mut active,
                        &mut durable_ready,
                        &options,
                        &mut journal,
                        &mut handshake,
                    )?;
                }
            }
            Ok(TransportMessage::CoreEof) => {
                core_input_open = false;
                discard_queued_client_messages(&mut pending_messages);
                reject_pending_handshake(&mut delivery, &mut output, &mut handshake)?;
                delivery.reject_all_broker_requests(
                    &mut output,
                    "core_unavailable",
                    "turn core closed before the broker request received a terminal response",
                )?;
                core_reader_open = false;
                core_exit_deadline = None;
            }
            Ok(TransportMessage::CoreError(error)) => {
                core_input_open = false;
                discard_queued_client_messages(&mut pending_messages);
                reject_pending_handshake(&mut delivery, &mut output, &mut handshake)?;
                delivery.reject_all_broker_requests(
                    &mut output,
                    "core_unavailable",
                    "turn core reported a transport error before the broker request completed",
                )?;
                terminal_error.get_or_insert(error);
                core_reader_open = false;
                core_exit_deadline = None;
            }
            Ok(TransportMessage::CoreExited(result)) => {
                core_input_open = false;
                discard_queued_client_messages(&mut pending_messages);
                core_wait_open = false;
                drop(core_stdin.take());
                match result {
                    Ok(status) => core_status = Some(status),
                    Err(error) => {
                        terminal_error.get_or_insert(error);
                    }
                }
                if core_reader_open {
                    core_exit_deadline = Some(Instant::now() + CORE_READER_DRAIN_GRACE);
                } else {
                    // The reader has already delivered EOF, so no final core
                    // frame can still resolve the handshake.
                    reject_pending_handshake(&mut delivery, &mut output, &mut handshake)?;
                    delivery.reject_all_broker_requests(
                        &mut output,
                        "core_unavailable",
                        "turn core exited before the broker request received a terminal response",
                    )?;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if core_exit_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    core_input_open = false;
                    discard_queued_client_messages(&mut pending_messages);
                    reject_pending_handshake(&mut delivery, &mut output, &mut handshake)?;
                    delivery.reject_all_broker_requests(
                        &mut output,
                        "core_unavailable",
                        "turn core did not converge after process exit",
                    )?;
                    terminal_error.get_or_insert_with(|| {
                        "core Host stdout did not close after leader exit and process-group cleanup"
                            .to_string()
                    });
                    core_reader_open = false;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                core_input_open = false;
                discard_queued_client_messages(&mut pending_messages);
                reject_pending_handshake(&mut delivery, &mut output, &mut handshake)?;
                delivery.reject_all_broker_requests(
                    &mut output,
                    "core_unavailable",
                    "transport event channel disconnected before the broker request completed",
                )?;
                terminal_error.get_or_insert_with(|| {
                    "transport event channel disconnected before core lifecycle convergence"
                        .to_string()
                });
                core_reader_open = false;
                core_wait_open = false;
            }
        }
    }

    if let Some(error) = terminal_error {
        return Err(error);
    }
    let status = core_status.ok_or_else(|| "core Host exit status was not observed".to_string())?;
    if !status.success() {
        return Err(format!("core Host exited unsuccessfully: {status}"));
    }
    if client_open {
        delivery.flush_if_attached()?;
    }
    Ok(())
}

/// Update the transport's durable-store capability observation.  A negative
/// observation wins over an optimistic marker in the same frame; otherwise a
/// positive durable marker raises readiness and ordinary status frames leave
/// the previous value unchanged.
fn update_durable_ready(frame: &RunTurnFrame, durable_ready: &mut bool) {
    if frame_reports_unavailable(frame) {
        *durable_ready = false;
    } else if frame_reports_durable(frame) {
        *durable_ready = true;
    }
}

/// A turn can fail before the normal `turn.accepted` acknowledgement.  Such a
/// frame must cross the second handshake gate so the peer receives a bounded
/// terminal observation instead of waiting forever for an acknowledgement
/// that the core will never produce.
fn turn_gate_resolution(frame: &RunTurnFrame) -> bool {
    matches!(
        frame.kind.as_str(),
        FRAME_HOST_ERROR | FRAME_TURN_END | "turn.rejected" | "turn.failed" | "turn.cancelled"
    )
}

/// Close a handshake that can no longer receive its core acknowledgement.
/// Deferred requests are discarded rather than executed after an EOF/error;
/// one explicit transport error is the only observable outcome still safe to
/// emit on the client stream.
fn reject_pending_handshake<W: Write>(
    delivery: &mut ClientDelivery<W>,
    output: &mut TransportOutput,
    handshake: &mut TransportHandshake,
) -> Result<(), String> {
    fail_pending_handshake(
        delivery,
        output,
        handshake,
        (
            "hello_ack_unavailable",
            "turn core closed before hello.ack was observed",
        ),
        (
            "turn_accept_unavailable",
            "turn core closed before turn.accepted was observed",
        ),
    )
}

/// Fail one or both handshake gates while preserving the broker envelope of
/// every request that was waiting on a core acknowledgement.  A single
/// unbound error is retained for legacy/direct callers; brokered hello and
/// turn requests each receive their own exact envelope so neither request is
/// left unresolved when the core cannot produce a frame.
fn fail_pending_handshake<W: Write>(
    delivery: &mut ClientDelivery<W>,
    output: &mut TransportOutput,
    handshake: &mut TransportHandshake,
    hello_error: (&str, &str),
    turn_error: (&str, &str),
) -> Result<(), String> {
    let awaiting_ack = handshake.awaiting_ack();
    let awaiting_turn = handshake.turn_pending();
    if !awaiting_ack && !awaiting_turn {
        return Ok(());
    }

    // Capture before `fail`, which deliberately clears retained state and
    // quarantines all late core bytes.  Local actions in the queue represent
    // already-admitted broker requests; silently dropping them would leave
    // those upstream requests unresolved even though the gate failure is
    // observable.
    let hello_binding = handshake.hello_binding().cloned();
    let turn_binding = handshake.turn_binding().cloned();
    let deferred = handshake.fail();

    let mut emitted = false;
    if awaiting_ack {
        write_local_error_for_binding(
            delivery,
            output,
            None,
            hello_error.0,
            hello_error.1,
            hello_binding.as_ref(),
        )?;
        emitted = true;
    }
    // If both gates were pending, do not collapse two broker-owned requests
    // into one.  For direct/unbound traffic, one mechanical error is enough
    // to preserve the historical wire shape.
    if awaiting_turn && (turn_binding.is_some() || !emitted) {
        write_local_error_for_binding(
            delivery,
            output,
            None,
            turn_error.0,
            turn_error.1,
            turn_binding.as_ref(),
        )?;
    }
    reject_deferred_actions(
        deferred,
        delivery,
        output,
        if awaiting_turn {
            turn_error.0
        } else {
            hello_error.0
        },
        if awaiting_turn {
            turn_error.1
        } else {
            hello_error.1
        },
    )?;
    Ok(())
}

/// Resolve local actions that were admitted behind a handshake gate when the
/// core can no longer acknowledge them.  Success-only local frames (notably
/// flow-control ACKs) become explicit bound errors; raw core frames are
/// discarded because replaying them after a failed generation is unsafe.
fn reject_deferred_actions<W: Write>(
    actions: VecDeque<DeferredHandshakeAction>,
    delivery: &mut ClientDelivery<W>,
    output: &mut TransportOutput,
    code: &str,
    message: &str,
) -> Result<(), String> {
    for action in actions {
        match action {
            DeferredHandshakeAction::Local(error) => write_local_error_for_binding(
                delivery,
                output,
                error.context.as_ref(),
                code,
                message,
                error.binding.as_ref(),
            )?,
            DeferredHandshakeAction::LocalFrame(frame) => write_local_error_for_binding(
                delivery,
                output,
                frame.context.as_ref(),
                code,
                message,
                frame.binding.as_ref(),
            )?,
            DeferredHandshakeAction::Core(_) => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn deliver_turn_accepted<W: Write>(
    mut frame: RunTurnFrame,
    delivery: &mut ClientDelivery<W>,
    binding: Option<&BrokerRequestBinding>,
    flow: &StreamDelivery,
    active: Option<&TurnContext>,
    durable_ready: &mut bool,
    options: &Options,
    journal: &TransportJournal,
) -> Result<(), String> {
    update_durable_ready(&frame, durable_ready);
    augment_core_frame(&mut frame, active, options, flow, *durable_ready, journal);
    if let Some(binding) = binding {
        delivery.send_with_binding(&frame, Some(binding))
    } else {
        delivery.send(&frame)
    }
}

/// Process a core frame after it has crossed the handshake barriers.  Frames
/// placed in the deferred queue have already been observed by the broker
/// router (for arrival ordering), but their wire sequence is allocated by the
/// release path immediately before this function is called.
#[allow(clippy::too_many_arguments)]
fn process_core_frame_body<W: Write>(
    mut frame: RunTurnFrame,
    output: &mut TransportOutput,
    delivery: &mut ClientDelivery<W>,
    flow: &mut StreamDelivery,
    active: &mut Option<TurnContext>,
    durable_ready: &mut bool,
    options: &Options,
    journal: &mut TransportJournal,
    handshake: &mut TransportHandshake,
) -> Result<(), String> {
    update_durable_ready(&frame, durable_ready);

    if frame_reports_unavailable(&frame) && flow.is_active() {
        let released = flow.disable_and_release();
        let disabled = output.local_frame(
            FRAME_STREAM_FLOW_DISABLED,
            json!({
                "status": "disabled",
                "reason": "durable_event_store_unavailable",
                "released_buffered_frames": released.len(),
                "automatic_redispatch": false
            }),
            active.as_ref(),
        );
        delivery.send(&disabled)?;
        for queued in released {
            delivery.send(&queued)?;
        }
    }

    augment_core_frame(
        &mut frame,
        active.as_ref(),
        options,
        flow,
        *durable_ready,
        journal,
    );

    if frame.kind == FRAME_TURN_END {
        let retired_turn = active.clone();
        // Keep the exact broker identity before the terminal is emitted.  A
        // core revision may omit the request digest on `turn.end`, in which
        // case normal semantic routing cannot select the active intent.  The
        // handshake retains this tuple through acceptance so we can both
        // preserve the terminal's upstream ownership and retire only the
        // generation that actually ended.
        let terminal_binding = handshake.turn_binding().cloned();
        let resync_already_announced = flow.gap.is_some();
        if let Some(gap) = flow.terminal_gap() {
            if !resync_already_announced {
                write_resync_required(delivery, output, active.as_ref(), &gap)?;
            }
            attach_gap_to_payload(&mut frame.payload, &gap);
        }
        attach_delivery_status(&mut frame.payload, delivery);
        let send_result = if let Some(binding) = terminal_binding.as_ref() {
            // Explicit binding is required for a digest-less terminal.  It
            // also prevents a stale same-lineage intent earlier in the FIFO
            // from claiming a digest-bearing terminal that belongs to this
            // generation.
            delivery.send_with_binding(&frame, Some(binding))
        } else {
            delivery.send(&frame)
        };
        // Retire the exact generation even when writing the terminal fails;
        // otherwise a detached client can leave a stale active intent that
        // shadows a later retry on the same semantic scope.
        if let Some(binding) = terminal_binding.as_ref() {
            delivery.clear_turn_binding(binding);
        }
        send_result?;
        if let Some(context) = active.as_ref() {
            journal.append(
                context,
                "transport.delivery.terminal",
                json!({
                    "client_delivery_status": if delivery.attached { "attached" } else { "detached" },
                    "client_delivery_error": delivery.error.as_deref(),
                    "stream_gap": flow.gap.as_ref().map(ResyncGap::payload),
                    "automatic_redispatch": false
                }),
            );
        }
        *active = None;
        flow.finish_turn();
        // On a normal terminal the queue should already be empty.  Do not
        // clear a still-pending turn gate here: the caller may be resolving a
        // pre-accept rejection and must release its bounded queue explicitly.
        if !handshake.turn_pending() {
            handshake.finish_turn(retired_turn.as_ref());
        }
        return Ok(());
    }

    match flow.submit(frame) {
        Ok(SubmitResult::Deliver(frame)) => delivery.send(&frame)?,
        Ok(SubmitResult::Queued | SubmitResult::Suppressed) => {}
        Ok(SubmitResult::GapStarted(gap)) => {
            write_resync_required(delivery, output, active.as_ref(), &gap)?;
        }
        Err(error) => {
            let released = flow.disable_and_release();
            let disabled = output.local_frame(
                FRAME_STREAM_FLOW_DISABLED,
                json!({
                    "status": "disabled",
                    "reason": error,
                    "released_buffered_frames": released.len(),
                    "automatic_redispatch": false
                }),
                active.as_ref(),
            );
            delivery.send(&disabled)?;
            for queued in released {
                delivery.send(&queued)?;
            }
        }
    }
    Ok(())
}

/// Release frames held at the hello/turn barriers.  If hello is acknowledged
/// before turn acceptance, the queue is inspected for a resolving frame.  A
/// missing resolver is put back behind the turn gate; this avoids dropping a
/// pre-accepted `turn.accepted` that arrived in the same pipe burst as the
/// hello acknowledgement.
#[allow(clippy::too_many_arguments)]
fn release_handshake_queues<W: Write>(
    mut actions: VecDeque<DeferredHandshakeAction>,
    limits: &MechanicalLimits,
    output: &mut TransportOutput,
    delivery: &mut ClientDelivery<W>,
    flow: &mut StreamDelivery,
    active: &mut Option<TurnContext>,
    durable_ready: &mut bool,
    options: &Options,
    journal: &mut TransportJournal,
    handshake: &mut TransportHandshake,
) -> Result<(), String> {
    if handshake.turn_pending() {
        let mut before_resolution = VecDeque::new();
        let mut resolver = None::<RunTurnFrame>;
        while let Some(action) = actions.pop_front() {
            match action {
                DeferredHandshakeAction::Core(encoded) => {
                    let frame = RunTurnFrame::decode(&encoded, limits)
                        .map_err(|error| format!("deferred core frame became invalid: {error}"))?;
                    if turn_gate_resolution(&frame) || frame.kind == FRAME_TURN_ACCEPTED {
                        // A resolver is meaningful only for the currently
                        // admitted turn.  Do not let a delayed error or
                        // acceptance from another lineage consume this gate;
                        // keep scanning for a valid resolver (or let EOF
                        // produce the explicit unavailable error).
                        if !active
                            .as_ref()
                            .is_some_and(|context| turn_frame_matches_context(&frame, context))
                        {
                            continue;
                        }
                        resolver = Some(frame);
                        break;
                    }
                    before_resolution.push_back(DeferredHandshakeAction::Core(encoded));
                }
                local => before_resolution.push_back(local),
            }
        }

        let Some(resolver) = resolver else {
            before_resolution.extend(actions);
            handshake.restore_deferred(before_resolution)?;
            return Ok(());
        };

        if resolver.kind == FRAME_TURN_ACCEPTED {
            let Some(context) = active.as_ref() else {
                return Err("turn.accepted arrived without an active turn context".to_string());
            };
            if !turn_frame_matches_context(&resolver, context) {
                let rejected_turn = active.clone();
                let turn_binding = handshake.turn_binding().cloned();
                let mut rejected_actions = before_resolution;
                rejected_actions.extend(actions);
                rejected_actions.extend(handshake.resolve_turn_failure(rejected_turn.as_ref()));
                if let Some(binding) = turn_binding.as_ref() {
                    delivery.discard_broker_binding(binding);
                }
                reject_deferred_actions(
                    rejected_actions,
                    delivery,
                    output,
                    "core_protocol_error",
                    "turn.accepted did not match the admitted turn lineage",
                )?;
                *active = None;
                flow.finish_turn();
                return Ok(());
            }
            let turn_binding = handshake.turn_binding().cloned();
            let accepted = output.rewrite_core_with_context(resolver, active.as_ref());
            deliver_turn_accepted(
                accepted,
                delivery,
                turn_binding.as_ref(),
                flow,
                active.as_ref(),
                durable_ready,
                options,
                journal,
            )?;
            // The resolver itself is always sent first. The actions that
            // arrived before and after it retain their original relative
            // order once the turn gate opens.
            let mut released = before_resolution;
            released.extend(actions);
            released.extend(handshake.release_after_turn_accept());
            actions = released;
        } else {
            let was_pending = handshake.turn_pending();
            let resolver_kind = resolver.kind.clone();
            let mut resolver = output.rewrite_core_with_context(resolver, active.as_ref());
            let rejected_turn = active.clone();
            if was_pending
                && let Some(binding) = handshake.turn_binding().cloned()
            {
                // Preserve the retained request envelope even when the
                // negative resolver lacks a digest/lineage that the normal
                // router would require for selection.
                if let Err(error) = binding.apply(&mut resolver) {
                    let rejected_actions = handshake.resolve_turn_failure(rejected_turn.as_ref());
                    if resolver_kind != FRAME_TURN_END {
                        *active = None;
                        flow.finish_turn();
                    }
                    write_local_error_for_binding(
                        delivery,
                        output,
                        None,
                        "core_protocol_error",
                        &error,
                        Some(&binding),
                    )?;
                    reject_deferred_actions(
                        rejected_actions,
                        delivery,
                        output,
                        "turn_rejected",
                        "turn core response carried a conflicting broker envelope",
                    )?;
                    delivery.discard_broker_binding(&binding);
                    return Ok(());
                }
            }
            process_core_frame_body(
                resolver,
                output,
                delivery,
                flow,
                active,
                durable_ready,
                options,
                journal,
                handshake,
            )?;
            if was_pending {
                // A negative pre-accept response closes the turn boundary.
                // Do not replay provider/core frames that were emitted after
                // that failure. Every already-admitted local request still
                // receives a bound terminal error, including success-only
                // flow-control ACKs that were waiting in the same queue.
                let resolver_binding = handshake.turn_binding().cloned();
                let mut rejected_actions = before_resolution;
                rejected_actions.extend(actions);
                rejected_actions.extend(handshake.resolve_turn_failure(rejected_turn.as_ref()));
                if let Some(binding) = resolver_binding.as_ref() {
                    delivery.discard_broker_binding(binding);
                }
                if resolver_kind != FRAME_TURN_END {
                    *active = None;
                    flow.finish_turn();
                }
                reject_deferred_actions(
                    rejected_actions,
                    delivery,
                    output,
                    "turn_rejected",
                    "turn core rejected the turn before turn.accepted",
                )?;
                actions = VecDeque::new();
            }
        }
    }

    // Materialize actions in their original cross-domain FIFO. Raw core
    // frames are rewritten only at this point, so they receive a wire
    // host_seq after the resolver and cannot regress behind it.
    while let Some(action) = actions.pop_front() {
        match action {
            DeferredHandshakeAction::Local(error) => {
                flush_deferred_local_errors(
                    delivery,
                    output,
                    std::iter::once(error).collect(),
                )?;
            }
            DeferredHandshakeAction::LocalFrame(frame) => {
                let drain_flow = frame.drain_flow;
                let response = output.local_frame(
                    &frame.kind,
                    frame.payload,
                    frame.context.as_ref(),
                );
                delivery.send_with_binding(&response, frame.binding.as_ref())?;
                if drain_flow {
                    for queued in flow.drain()? {
                        delivery.send(&queued)?;
                    }
                }
            }
            DeferredHandshakeAction::Core(encoded) => {
                let frame = RunTurnFrame::decode(&encoded, limits)
                    .map_err(|error| format!("deferred core frame became invalid: {error}"))?;
                let frame = output.rewrite_core_with_context(frame, active.as_ref());
                process_core_frame_body(
                    frame,
                    output,
                    delivery,
                    flow,
                    active,
                    durable_ready,
                    options,
                    journal,
                    handshake,
                )?;
            }
        }
    }
    Ok(())
}

fn handle_flow_control<W: Write>(
    frame: RunTurnFrame,
    context: &TurnContext,
    flow: &mut StreamDelivery,
    output: &mut TransportOutput,
    delivery: &mut ClientDelivery<W>,
    broker_binding: Option<&BrokerRequestBinding>,
    handshake: &mut TransportHandshake,
) -> Result<(), String> {
    let parsed = match parse_flow_control(&frame, context, flow.max_credit_bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            return write_local_error_or_defer(
                delivery,
                output,
                handshake,
                Some(context),
                "invalid_flow_control",
                &error,
                broker_binding,
            );
        }
    };
    let (disposition, snapshot) = match flow.apply_control(&parsed) {
        Ok(result) => result,
        Err(error) => {
            return write_local_error_or_defer(
                delivery,
                output,
                handshake,
                Some(context),
                "flow_control_conflict",
                &error,
                broker_binding,
            );
        }
    };
    let ack_kind = flow_ack_kind(&parsed.command).to_string();
    let ack_payload = json!({
        "status": match disposition {
            ApplyDisposition::Applied => "applied",
            ApplyDisposition::Existing => "existing"
        },
        "control_seq": parsed.control_seq,
        "window": snapshot_payload(&snapshot),
        "buffered_frames": flow.queue.len(),
        "buffered_bytes": flow.queued_bytes,
        "resync_required": flow.gap.is_some(),
        "persist_before_flow": true,
        "automatic_redispatch": false
    });
    if handshake.holds_local_delivery() {
        let deferred = DeferredLocalFrame {
            kind: ack_kind,
            payload: ack_payload,
            context: Some(context.clone()),
            binding: broker_binding.cloned(),
            drain_flow: true,
        };
        if let Err(error) = handshake.defer_frame(deferred) {
            fail_pending_handshake(
                delivery,
                output,
                handshake,
                ("resource_exhausted", error.as_str()),
                ("resource_exhausted", error.as_str()),
            )?;
            return write_local_error_for_binding(
                delivery,
                output,
                None,
                "resource_exhausted",
                &error,
                broker_binding,
            );
        }
        return Ok(());
    }
    let ack = output.local_frame(&ack_kind, ack_payload, Some(context));
    delivery.send_with_binding(&ack, broker_binding)?;
    for queued in flow.drain()? {
        delivery.send(&queued)?;
    }
    Ok(())
}

#[cfg(test)]
mod run_tests {
    use super::*;

    fn binding(id: &str, upstream_seq: u64) -> BrokerRequestBinding {
        BrokerRequestBinding {
            request_id: id.to_string(),
            request_sha256: "a".repeat(64),
            upstream_seq,
        }
    }

    fn frames(delivery: &ClientDelivery<Vec<u8>>) -> Vec<Value> {
        String::from_utf8(delivery.writer.clone())
            .expect("delivery writer contains UTF-8 JSON")
            .lines()
            .map(|line| serde_json::from_str(line).expect("delivery line is JSON"))
            .collect()
    }

    #[test]
    fn handshake_failure_errors_retain_hello_and_turn_bindings() {
        let limits = MechanicalLimits::default();
        let mut delivery = ClientDelivery::new(Vec::new(), limits.max_frame_bytes);
        let mut output = TransportOutput::new();
        let mut handshake = TransportHandshake::default();
        handshake.begin_hello().expect("hello gate opens");
        handshake.retain_hello_binding(Some(binding("hello-request", 10)));
        handshake.begin_turn().expect("turn gate opens");
        handshake.retain_turn_binding(Some(binding("turn-request", 11)));

        fail_pending_handshake(
            &mut delivery,
            &mut output,
            &mut handshake,
            ("core_protocol_error", "malformed core"),
            ("core_protocol_error", "malformed core"),
        )
        .expect("failure errors are delivered");

        let frames = frames(&delivery);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0]["broker_request_id"], "hello-request");
        assert_eq!(frames[1]["broker_request_id"], "turn-request");
        assert!(handshake.failed());
        assert!(handshake.hello_binding().is_none());
        assert!(handshake.turn_binding().is_none());
    }

    #[test]
    fn core_terminal_does_not_overtake_a_prior_core_frame() {
        let (sender, receiver) = sync_channel(8);
        sender
            .send(TransportMessage::CoreFrame(b"first-core-frame".to_vec()))
            .expect("first core frame is queued");
        sender
            .send(TransportMessage::CoreEof)
            .expect("core EOF is queued");

        let mut pending = VecDeque::new();
        let mut client_priority_streak = 0;
        let first = next_transport_message(
            &receiver,
            &mut pending,
            true,
            &mut client_priority_streak,
        )
            .expect("a queued message is available");
        assert!(matches!(first, TransportMessage::CoreFrame(_)));

        // The EOF may preempt a client write once it is the first pending
        // core-domain event, but it must not have skipped the preceding core
        // frame. This preserves the core reader's source FIFO.
        let second = next_transport_message(
            &receiver,
            &mut pending,
            true,
            &mut client_priority_streak,
        )
            .expect("the queued core EOF is available");
        assert!(matches!(second, TransportMessage::CoreEof));
    }

    #[test]
    fn core_terminal_can_preempt_a_client_write_when_no_core_frame_precedes_it() {
        let (sender, receiver) = sync_channel(8);
        sender
            .send(TransportMessage::ClientFrame(b"client-frame".to_vec()))
            .expect("client frame is queued");
        sender
            .send(TransportMessage::CoreEof)
            .expect("core EOF is queued");

        let mut pending = VecDeque::new();
        let mut client_priority_streak = 0;
        let first = next_transport_message(
            &receiver,
            &mut pending,
            true,
            &mut client_priority_streak,
        )
            .expect("a queued message is available");
        assert!(matches!(first, TransportMessage::CoreEof));
        let second = next_transport_message(
            &receiver,
            &mut pending,
            true,
            &mut client_priority_streak,
        )
            .expect("the queued client frame is available");
        assert!(matches!(second, TransportMessage::ClientFrame(_)));
    }

    #[test]
    fn pending_staging_queue_is_bounded_when_channel_is_full() {
        let (sender, receiver) = sync_channel(TRANSPORT_QUEUE_DEPTH * 2);
        for index in 0..(TRANSPORT_QUEUE_DEPTH * 2) {
            sender
                .send(TransportMessage::ClientFrame(index.to_string().into_bytes()))
                .expect("test channel accepts the bounded batch");
        }

        let mut pending = VecDeque::new();
        let mut client_priority_streak = 0;
        let _ = next_transport_message(
            &receiver,
            &mut pending,
            false,
            &mut client_priority_streak,
        )
        .expect("the first batch item is available");
        assert!(pending.len() <= TRANSPORT_QUEUE_DEPTH);
    }

    #[test]
    fn handshake_client_priority_has_a_fair_core_burst_limit() {
        let (sender, receiver) = sync_channel(TRANSPORT_QUEUE_DEPTH);
        for index in 0..(MAX_CLIENT_PRIORITY_BURST * 2) {
            sender
                .send(TransportMessage::ClientFrame(index.to_string().into_bytes()))
                .expect("client frame is queued");
        }
        sender
            .send(TransportMessage::CoreFrame(b"core-ack".to_vec()))
            .expect("core frame is queued");

        let mut pending = VecDeque::new();
        let mut client_priority_streak = 0;
        let mut core_seen_at = None;
        for turn in 0..=MAX_CLIENT_PRIORITY_BURST {
            let message = next_transport_message(
                &receiver,
                &mut pending,
                true,
                &mut client_priority_streak,
            )
            .expect("a queued message is available");
            if matches!(message, TransportMessage::CoreFrame(_)) {
                core_seen_at = Some(turn);
                break;
            }
        }
        assert_eq!(core_seen_at, Some(MAX_CLIENT_PRIORITY_BURST));
    }

    #[test]
    fn queued_client_messages_are_discarded_after_core_terminal() {
        let mut pending = VecDeque::from([
            TransportMessage::ClientFrame(b"one".to_vec()),
            TransportMessage::CoreEof,
            TransportMessage::ClientFrame(b"two".to_vec()),
            TransportMessage::CoreFrame(b"late".to_vec()),
            TransportMessage::ClientEof,
        ]);
        discard_queued_client_messages(&mut pending);
        assert!(pending.iter().all(is_core_message));
        assert_eq!(pending.len(), 2);
    }
}
