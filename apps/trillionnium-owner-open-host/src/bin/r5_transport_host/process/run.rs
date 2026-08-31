pub(crate) fn run() -> Result<(), String> {
    let options = Options::parse(env::args_os().skip(1).collect())?;
    if options.help {
        println!("{}", Options::usage());
        return Ok(());
    }

    let limits = MechanicalLimits::default();
    let (child, mut core_stdin, core_stdout, core_stderr) = spawn_core(&options)?;
    let core_pid = child.id();
    spawn_stderr_drain(core_stderr);

    let (sender, receiver) = sync_channel(TRANSPORT_QUEUE_DEPTH);
    spawn_client_reader(sender.clone(), limits.max_frame_bytes);
    spawn_core_reader(core_stdout, sender.clone(), limits.max_frame_bytes);
    spawn_core_waiter(child, sender);

    let stdout = io::stdout();
    let mut delivery = ClientDelivery::new(stdout.lock(), limits.max_frame_bytes);
    let mut output = TransportOutput::new();
    let mut flow = StreamDelivery::new(&options);
    let mut journal = TransportJournal::open(options.event_store.as_deref());
    let mut active = None::<TurnContext>;
    let mut durable_ready = false;
    let mut client_open = true;
    let mut core_reader_open = true;
    let mut core_wait_open = true;
    let mut core_status = None::<ExitStatus>;
    let mut core_exit_deadline = None::<Instant>;
    let mut terminal_error = None::<String>;

    while core_reader_open || core_wait_open {
        match receiver.recv_timeout(TRANSPORT_POLL_INTERVAL) {
            Ok(TransportMessage::ClientFrame(encoded)) => {
                let frame = match RunTurnFrame::decode(&encoded, &limits) {
                    Ok(frame) => frame,
                    Err(error) => {
                        write_local_error(
                            &mut delivery,
                            &mut output,
                            active.as_ref(),
                            "invalid_frame",
                            &error.to_string(),
                        )?;
                        continue;
                    }
                };

                if is_flow_control_kind(&frame.kind) {
                    let Some(context) = active.as_ref() else {
                        write_local_error(
                            &mut delivery,
                            &mut output,
                            None,
                            "no_active_turn",
                            "stream control has no active turn",
                        )?;
                        continue;
                    };
                    if options.event_store.is_none() || !durable_ready {
                        write_local_error(
                            &mut delivery,
                            &mut output,
                            Some(context),
                            "flow_control_requires_durable_store",
                            "bounded pause/window delivery requires an available durable event store",
                        )?;
                        continue;
                    }
                    handle_flow_control(
                        frame,
                        context,
                        &mut flow,
                        &mut output,
                        &mut delivery,
                    )?;
                    continue;
                }

                if frame.kind == FRAME_TURN_START {
                    if active.is_some() {
                        write_local_error(
                            &mut delivery,
                            &mut output,
                            active.as_ref(),
                            "connection_state",
                            "a second turn.start is not valid while a turn is active",
                        )?;
                        continue;
                    }
                    match TurnContext::from_start(&frame, &limits) {
                        Ok(context) => {
                            flow.begin_turn();
                            active = Some(context);
                        }
                        Err(error) => {
                            write_local_error(
                                &mut delivery,
                                &mut output,
                                None,
                                "invalid_frame",
                                &error,
                            )?;
                            continue;
                        }
                    }
                }
                forward_to_core(&mut core_stdin, &encoded)?;
            }
            Ok(TransportMessage::ClientEof) => {
                client_open = false;
                drop(core_stdin.take());
            }
            Ok(TransportMessage::ClientError(error)) => {
                client_open = false;
                terminal_error.get_or_insert(error);
                drop(core_stdin.take());
            }
            Ok(TransportMessage::CoreFrame(encoded)) => {
                let mut frame = RunTurnFrame::decode(&encoded, &limits)
                    .map_err(|error| format!("core emitted an invalid Host frame: {error}"))?;

                if frame_reports_durable(&frame) {
                    durable_ready = true;
                } else if frame_reports_unavailable(&frame) && flow.is_active() {
                    durable_ready = false;
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

                frame = output.rewrite_core(frame);
                augment_core_frame(
                    &mut frame,
                    active.as_ref(),
                    &options,
                    &flow,
                    durable_ready,
                    &journal,
                );

                if frame.kind == FRAME_TURN_END {
                    let resync_already_announced = flow.gap.is_some();
                    if let Some(gap) = flow.terminal_gap() {
                        if !resync_already_announced {
                            write_resync_required(
                                &mut delivery,
                                &mut output,
                                active.as_ref(),
                                &gap,
                            )?;
                        }
                        attach_gap_to_payload(&mut frame.payload, &gap);
                    }
                    attach_delivery_status(&mut frame.payload, &delivery);
                    delivery.send(&frame)?;
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
                    active = None;
                    flow.finish_turn();
                    continue;
                }

                match flow.submit(frame) {
                    Ok(SubmitResult::Deliver(frame)) => delivery.send(&frame)?,
                    Ok(SubmitResult::Queued | SubmitResult::Suppressed) => {}
                    Ok(SubmitResult::GapStarted(gap)) => {
                        write_resync_required(
                            &mut delivery,
                            &mut output,
                            active.as_ref(),
                            &gap,
                        )?;
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
            }
            Ok(TransportMessage::CoreEof) => {
                core_reader_open = false;
                core_exit_deadline = None;
            }
            Ok(TransportMessage::CoreError(error)) => {
                terminal_error.get_or_insert(error);
                core_reader_open = false;
                core_exit_deadline = None;
            }
            Ok(TransportMessage::CoreExited(result)) => {
                core_wait_open = false;
                drop(core_stdin.take());
                match result {
                    Ok(status) => core_status = Some(status),
                    Err(error) => {
                        terminal_error.get_or_insert(error);
                    }
                }
                if let Err(error) = terminate_core_process_group(core_pid) {
                    terminal_error.get_or_insert(error);
                }
                if core_reader_open {
                    core_exit_deadline = Some(Instant::now() + CORE_READER_DRAIN_GRACE);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if core_exit_deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    terminal_error.get_or_insert_with(|| {
                        "core Host stdout did not close after leader exit and process-group cleanup"
                            .to_string()
                    });
                    core_reader_open = false;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
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
    let status = core_status
        .ok_or_else(|| "core Host exit status was not observed".to_string())?;
    if !status.success() {
        return Err(format!("core Host exited unsuccessfully: {status}"));
    }
    if client_open {
        delivery.flush_if_attached()?;
    }
    Ok(())
}

fn handle_flow_control<W: Write>(
    frame: RunTurnFrame,
    context: &TurnContext,
    flow: &mut StreamDelivery,
    output: &mut TransportOutput,
    delivery: &mut ClientDelivery<W>,
) -> Result<(), String> {
    let parsed = match parse_flow_control(&frame, context, flow.max_credit_bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            return write_local_error(
                delivery,
                output,
                Some(context),
                "invalid_flow_control",
                &error,
            );
        }
    };
    let (disposition, snapshot) = match flow.apply_control(&parsed) {
        Ok(result) => result,
        Err(error) => {
            return write_local_error(
                delivery,
                output,
                Some(context),
                "flow_control_conflict",
                &error,
            );
        }
    };
    let ack = output.local_frame(
        flow_ack_kind(&parsed.command),
        json!({
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
        }),
        Some(context),
    );
    delivery.send(&ack)?;
    for queued in flow.drain()? {
        delivery.send(&queued)?;
    }
    Ok(())
}
