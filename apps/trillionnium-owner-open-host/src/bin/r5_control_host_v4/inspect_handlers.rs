#[allow(clippy::too_many_arguments)]
fn handle_turn_inspect<W: Write>(
    frame: RunTurnFrame,
    active: Option<&ActiveTurn>,
    writer: &mut W,
    output: &mut OutputState,
    persistence: &Persistence,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    let request = match parse_inspect_request(&frame, active, false) {
        Ok(request) => request,
        Err(error) => {
            deliver_host_error(
                writer,
                output,
                active.map(|value| &value.context),
                "invalid_inspect_request",
                &error,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
            return;
        }
    };
    let scope = DurableTurnScope::new(
        request.context.session_id.clone(),
        request.context.profile_id.clone(),
        request.context.task_id.clone(),
        request.context.turn_id.clone(),
        request.context.turn_stream_id.clone(),
    );
    let payload = match persistence.inspect(
        &scope,
        &request.request_sha256,
        request.inclusive_cursor,
        request.limit,
    ) {
        StoredInspection::Unavailable { status, error } => json!({
            "status": "unavailable",
            "event_log_status": status,
            "event_log_error": error,
            "side_effects": false,
            "automatic_redispatch": false
        }),
        StoredInspection::Conflict(error) => {
            deliver_host_error(
                writer,
                output,
                Some(&request.context),
                "inspect_conflict",
                &error,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
            return;
        }
        StoredInspection::Found(inspection) => {
            let status = if inspection.total_events == 0 {
                "not_found"
            } else {
                "found"
            };
            json!({
                "status": status,
                "source": "durable_event_store",
                "request_sha256": &request.request_sha256,
                "inclusive_cursor": inspection.inclusive_cursor,
                "next_cursor": inspection.next_cursor,
                "total_events": inspection.total_events,
                "complete": inspection.complete,
                "has_more": inspection.has_more,
                "frames": inspection.frames,
                "side_effects": false,
                "automatic_redispatch": false
            })
        }
    };
    let response = inspection_frame(
        output,
        FRAME_TURN_INSPECT_RESULT,
        payload,
        &request.context,
        None,
    );
    deliver_bounded_inspection(
        writer,
        output,
        response,
        &request.context,
        max_frame_bytes,
        delivery_attached,
        delivery_error,
    );
}

#[allow(clippy::too_many_arguments)]
fn handle_call_inspect<W: Write>(
    frame: RunTurnFrame,
    active: Option<&ActiveTurn>,
    registry: &Arc<CallRegistry>,
    writer: &mut W,
    output: &mut OutputState,
    persistence: &Persistence,
    max_frame_bytes: usize,
    delivery_attached: &mut bool,
    delivery_error: &mut Option<String>,
) {
    let request = match parse_inspect_request(&frame, active, true) {
        Ok(request) => request,
        Err(error) => {
            deliver_host_error(
                writer,
                output,
                active.map(|value| &value.context),
                "invalid_inspect_request",
                &error,
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
            return;
        }
    };
    let call_id = request
        .call_id
        .as_deref()
        .expect("call.inspect parser requires call_id");
    let key = CallKey::new(request.context.registry_scope(), call_id);

    // The live registry has no turn-request digest of its own. It is therefore
    // safe to use only while the active turn has already bound and verified the
    // exact request digest. Once the turn is no longer active, inspection must
    // go through the durable request-bound path even if this process still has
    // a completed registry entry in memory.
    let live_snapshot = if active.is_some() {
        registry.snapshot(&key)
    } else {
        Err(RegistryError::NotFound)
    };

    let payload = match live_snapshot {
        Ok(snapshot) => {
            let history = match registry.history_from(&key, request.inclusive_cursor) {
                Ok(history) => history,
                Err(error) => {
                    deliver_host_error(
                        writer,
                        output,
                        Some(&request.context),
                        "inspect_state_error",
                        &error.to_string(),
                        max_frame_bytes,
                        delivery_attached,
                        delivery_error,
                    );
                    return;
                }
            };
            if request.inclusive_cursor > snapshot.next_event_seq {
                deliver_host_error(
                    writer,
                    output,
                    Some(&request.context),
                    "inspect_conflict",
                    &format!(
                        "inclusive cursor {} is after next call cursor {}",
                        request.inclusive_cursor, snapshot.next_event_seq
                    ),
                    max_frame_bytes,
                    delivery_attached,
                    delivery_error,
                );
                return;
            }
            if request.inclusive_cursor < snapshot.earliest_history_seq {
                json!({
                    "status": "history_truncated",
                    "source": "live_registry",
                    "snapshot": encode_call_snapshot(&snapshot),
                    "requested_cursor": request.inclusive_cursor,
                    "earliest_cursor": snapshot.earliest_history_seq,
                    "next_cursor": snapshot.next_event_seq,
                    "side_effects": false,
                    "automatic_redispatch": false
                })
            } else {
                let selected = history
                    .into_iter()
                    .take(request.limit)
                    .collect::<Vec<_>>();
                let next_cursor = selected
                    .last()
                    .map_or(request.inclusive_cursor, |event| {
                        event.seq.saturating_add(1)
                    });
                json!({
                    "status": "found",
                    "source": "live_registry",
                    "snapshot": encode_call_snapshot(&snapshot),
                    "inclusive_cursor": request.inclusive_cursor,
                    "next_cursor": next_cursor,
                    "has_more": next_cursor < snapshot.next_event_seq,
                    "events": selected.iter().map(encode_call_event).collect::<Vec<_>>(),
                    "raw_output_available": false,
                    "side_effects": false,
                    "automatic_redispatch": false
                })
            }
        }
        Err(RegistryError::NotFound) => match durable_call_inspection(
            persistence,
            &request,
            call_id,
        ) {
            Ok(payload) => payload,
            Err(error) => {
                deliver_host_error(
                    writer,
                    output,
                    Some(&request.context),
                    "inspect_conflict",
                    &error,
                    max_frame_bytes,
                    delivery_attached,
                    delivery_error,
                );
                return;
            }
        },
        Err(error) => {
            deliver_host_error(
                writer,
                output,
                Some(&request.context),
                "inspect_state_error",
                &error.to_string(),
                max_frame_bytes,
                delivery_attached,
                delivery_error,
            );
            return;
        }
    };
    let response = inspection_frame(
        output,
        FRAME_CALL_INSPECT_RESULT,
        payload,
        &request.context,
        Some(call_id.to_string()),
    );
    deliver_bounded_inspection(
        writer,
        output,
        response,
        &request.context,
        max_frame_bytes,
        delivery_attached,
        delivery_error,
    );
}

fn durable_call_inspection(
    persistence: &Persistence,
    request: &InspectRequest,
    call_id: &str,
) -> Result<Value, String> {
    let scope = DurableTurnScope::new(
        request.context.session_id.clone(),
        request.context.profile_id.clone(),
        request.context.task_id.clone(),
        request.context.turn_id.clone(),
        request.context.turn_stream_id.clone(),
    );
    match persistence.inspect(
        &scope,
        &request.request_sha256,
        0,
        MAX_DURABLE_CALL_SCAN,
    ) {
        StoredInspection::Unavailable { status, error } => Ok(json!({
            "status": "unavailable",
            "source": "durable_event_store",
            "event_log_status": status,
            "event_log_error": error,
            "side_effects": false,
            "automatic_redispatch": false
        })),
        StoredInspection::Conflict(error) => Err(error),
        StoredInspection::Found(inspection) => {
            if inspection.has_more {
                return Err(
                    "durable turn exceeds the bounded call-inspection scan".to_string(),
                );
            }
            let all = inspection
                .frames
                .into_iter()
                .filter(|frame| frame.call_id.as_deref() == Some(call_id))
                .collect::<Vec<_>>();
            let total = u64::try_from(all.len())
                .map_err(|_| "call event count does not fit cursor domain".to_string())?;
            if request.inclusive_cursor > total {
                return Err(format!(
                    "inclusive cursor {} is after next call cursor {total}",
                    request.inclusive_cursor
                ));
            }
            let start = usize::try_from(request.inclusive_cursor)
                .map_err(|_| "call cursor does not fit local index domain".to_string())?;
            let end = start.saturating_add(request.limit).min(all.len());
            let selected = all[start..end].to_vec();
            let next_cursor = u64::try_from(end)
                .map_err(|_| "next call cursor does not fit cursor domain".to_string())?;
            Ok(json!({
                "status": if total == 0 { "not_found" } else { "found" },
                "source": "durable_event_store",
                "request_sha256": &request.request_sha256,
                "call_id": call_id,
                "inclusive_cursor": request.inclusive_cursor,
                "next_cursor": next_cursor,
                "total_call_events": total,
                "turn_complete": inspection.complete,
                "has_more": end < all.len(),
                "frames": selected,
                "side_effects": false,
                "automatic_redispatch": false
            }))
        }
    }
}
