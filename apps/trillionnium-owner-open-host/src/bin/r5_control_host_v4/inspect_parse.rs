fn parse_inspect_request(
    frame: &RunTurnFrame,
    active: Option<&ActiveTurn>,
    require_call_id: bool,
) -> Result<InspectRequest, String> {
    if !frame.payload.is_object() {
        return Err("inspect payload must be an object".to_string());
    }
    let session_id = correlated_id(frame, "session_id", frame.session_id.as_deref())?;
    let task_id = correlated_id(frame, "task_id", frame.task_id.as_deref())?;
    let turn_id = correlated_id(frame, "turn_id", frame.turn_id.as_deref())?;
    let profile_id = optional_correlated_id(
        frame,
        "profile_id",
        frame.profile_id.as_deref(),
    )?
    .unwrap_or_else(|| {
        active
            .map(|value| value.context.profile_id.clone())
            .unwrap_or_else(|| {
                trillionnium_owner_open_types::DEFAULT_PROFILE_ID.to_string()
            })
    });
    for (label, value) in [
        ("session_id", session_id.as_str()),
        ("profile_id", profile_id.as_str()),
        ("task_id", task_id.as_str()),
        ("turn_id", turn_id.as_str()),
    ] {
        if !valid_id(value) {
            return Err(format!("{label} is malformed"));
        }
    }

    let supplied_stream = optional_correlated_id(
        frame,
        "turn_stream_id",
        frame
            .turn_stream_id
            .as_deref()
            .or(frame.stream_id.as_deref()),
    )?;
    let derived_stream =
        stable_stream_id(&session_id, &profile_id, &task_id, &turn_id)?;
    let turn_stream_id = match supplied_stream {
        Some(value) if value != derived_stream => {
            return Err(
                "turn_stream_id does not match the stable turn scope".to_string(),
            );
        }
        Some(value) => value,
        None => derived_stream,
    };

    let context = TurnContext {
        turn_stream_id,
        session_id,
        profile_id,
        task_id,
        turn_id,
    };
    if let Some(active) = active {
        if active.context.session_id != context.session_id
            || active.context.profile_id != context.profile_id
            || active.context.task_id != context.task_id
            || active.context.turn_id != context.turn_id
            || active.context.turn_stream_id != context.turn_stream_id
        {
            return Err(
                "inspect scope does not match the active turn".to_string(),
            );
        }
    }

    let claimed_digest =
        payload_string_alias(frame, "request_sha256", "turn_request_sha256")?;
    let request_sha256 = match (claimed_digest, active) {
        (Some(value), Some(active))
            if active.request_digest != value =>
        {
            return Err(
                "request_sha256 does not match the active turn".to_string(),
            );
        }
        (Some(value), _) => value,
        (None, Some(active)) => active.request_digest.clone(),
        (None, None) => {
            return Err(
                "inspect requires request_sha256 outside the active turn".to_string(),
            );
        }
    };
    if !valid_sha256(&request_sha256) {
        return Err("request_sha256 must be a lowercase SHA-256".to_string());
    }

    let inclusive_cursor = frame
        .payload
        .get("inclusive_cursor")
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| "inclusive_cursor must be a u64".to_string())
        })
        .transpose()?
        .unwrap_or(0);
    let limit_u64 = frame
        .payload
        .get("limit")
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| "limit must be a positive integer".to_string())
        })
        .transpose()?
        .unwrap_or(64);
    let limit = usize::try_from(limit_u64)
        .map_err(|_| "limit does not fit the local index domain".to_string())?;
    if limit == 0 || limit > MAX_WIRE_INSPECT_LIMIT {
        return Err(format!(
            "limit must be between 1 and {MAX_WIRE_INSPECT_LIMIT}"
        ));
    }

    let call_id = if require_call_id {
        let value = correlated_id(frame, "call_id", frame.call_id.as_deref())?;
        if !valid_id(&value) {
            return Err("call_id is malformed".to_string());
        }
        Some(value)
    } else {
        None
    };
    Ok(InspectRequest {
        context,
        request_sha256,
        inclusive_cursor,
        limit,
        call_id,
    })
}

fn correlated_id(
    frame: &RunTurnFrame,
    field: &str,
    envelope: Option<&str>,
) -> Result<String, String> {
    optional_correlated_id(frame, field, envelope)?
        .ok_or_else(|| format!("inspect requires {field}"))
}

fn optional_correlated_id(
    frame: &RunTurnFrame,
    field: &str,
    envelope: Option<&str>,
) -> Result<Option<String>, String> {
    let payload_value = frame.payload.get(field);
    let payload = match payload_value {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => return Err(format!("{field} must be a string")),
    };
    match (envelope, payload) {
        (Some(first), Some(second)) if first != second => {
            Err(format!("{field} envelope and payload values conflict"))
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value.to_string())),
        (None, None) => Ok(None),
    }
}

fn payload_string_alias(
    frame: &RunTurnFrame,
    first: &str,
    second: &str,
) -> Result<Option<String>, String> {
    let first_value = optional_payload_string(frame, first)?;
    let second_value = optional_payload_string(frame, second)?;
    match (first_value, second_value) {
        (Some(left), Some(right)) if left != right => {
            Err(format!("{first} and {second} conflict"))
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn optional_payload_string(
    frame: &RunTurnFrame,
    field: &str,
) -> Result<Option<String>, String> {
    match frame.payload.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.as_bytes().contains(&0) => {
            Ok(Some(value.clone()))
        }
        Some(_) => Err(format!("{field} must be a NUL-free string")),
    }
}

fn stable_stream_id(
    session_id: &str,
    profile_id: &str,
    task_id: &str,
    turn_id: &str,
) -> Result<String, String> {
    let encoded = serde_json::to_vec(&json!({
        "schema": "trillionnium.owner-open.turn-stream.v1",
        "session_id": session_id,
        "profile_id": profile_id,
        "task_id": task_id,
        "turn_id": turn_id
    }))
    .map_err(|error| error.to_string())?;
    Ok(format!(
        "r5-stream-{}",
        hex_lower(&Sha256::digest(encoded))
    ))
}

fn inspection_frame(
    output: &mut OutputState,
    kind: &str,
    payload: Value,
    context: &TurnContext,
    call_id: Option<String>,
) -> RunTurnFrame {
    let mut frame = output.frame(
        kind,
        payload,
        None,
        EventCorrelation {
            call_id,
            tool: None,
            target_id: None,
        },
    );
    frame.stream_id = Some(context.turn_stream_id.clone());
    frame.turn_stream_id = Some(context.turn_stream_id.clone());
    frame.session_id = Some(context.session_id.clone());
    frame.profile_id = Some(context.profile_id.clone());
    frame.task_id = Some(context.task_id.clone());
    frame.turn_id = Some(context.turn_id.clone());
    frame
}
