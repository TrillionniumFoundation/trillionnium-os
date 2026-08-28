#[derive(Debug, Clone, Deserialize)]
struct FlowControlPayload {
    control_seq: u64,
    session_id: String,
    turn_id: String,
    turn_stream_id: String,
    #[serde(default)]
    profile_id: Option<String>,
    #[serde(default)]
    task_id: Option<String>,
    #[serde(default)]
    credit_bytes: Option<u64>,
    #[serde(default)]
    resumed_through_cursor: Option<u64>,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
struct ParsedFlowControl {
    control_seq: u64,
    command: StreamControl,
    resumed_through_cursor: Option<u64>,
    request_fingerprint: String,
}

fn parse_flow_control(
    frame: &RunTurnFrame,
    context: &TurnContext,
    max_credit_bytes: u64,
) -> Result<ParsedFlowControl, String> {
    let payload: FlowControlPayload = serde_json::from_value(frame.payload.clone())
        .map_err(|error| format!("invalid {} payload: {error}", frame.kind))?;
    validate_control_correlation(frame, &payload, context)?;
    let command = match frame.kind.as_str() {
        FRAME_STREAM_WINDOW_UPDATE => {
            let credit_bytes = payload
                .credit_bytes
                .ok_or_else(|| "stream.window_update requires credit_bytes".to_string())?;
            if credit_bytes == 0 || credit_bytes > max_credit_bytes {
                return Err(format!(
                    "credit_bytes must be between 1 and {max_credit_bytes}"
                ));
            }
            if payload.resumed_through_cursor.is_some() {
                return Err(
                    "stream.window_update does not accept resumed_through_cursor".to_string(),
                );
            }
            StreamControl::WindowUpdate { credit_bytes }
        }
        FRAME_STREAM_PAUSE => {
            if payload.credit_bytes.is_some() || payload.resumed_through_cursor.is_some() {
                return Err(
                    "stream.pause accepts neither credit_bytes nor resumed_through_cursor"
                        .to_string(),
                );
            }
            StreamControl::Pause
        }
        FRAME_STREAM_RESUME => {
            if payload.credit_bytes.is_some() {
                return Err(
                    "stream.resume does not add credit; use stream.window_update".to_string(),
                );
            }
            StreamControl::Resume
        }
        other => return Err(format!("unsupported flow-control frame {other}")),
    };
    let encoded = serde_json::to_vec(&frame.payload)
        .map_err(|error| format!("cannot canonicalize flow-control payload: {error}"))?;
    let request_fingerprint = hex_sha256(&encoded);
    Ok(ParsedFlowControl {
        control_seq: payload.control_seq,
        command,
        resumed_through_cursor: payload.resumed_through_cursor,
        request_fingerprint,
    })
}

fn validate_control_correlation(
    frame: &RunTurnFrame,
    payload: &FlowControlPayload,
    context: &TurnContext,
) -> Result<(), String> {
    for (label, value) in [
        ("session_id", payload.session_id.as_str()),
        (
            "profile_id",
            payload
                .profile_id
                .as_deref()
                .unwrap_or(DEFAULT_PROFILE_ID),
        ),
        (
            "task_id",
            payload.task_id.as_deref().unwrap_or(context.task_id.as_str()),
        ),
        ("turn_id", payload.turn_id.as_str()),
        ("turn_stream_id", payload.turn_stream_id.as_str()),
    ] {
        if !valid_id(value) {
            return Err(format!("flow-control {label} is malformed"));
        }
    }
    let effective_profile = payload
        .profile_id
        .as_deref()
        .unwrap_or(DEFAULT_PROFILE_ID);
    let effective_task = payload
        .task_id
        .as_deref()
        .unwrap_or(context.task_id.as_str());
    if payload.session_id != context.session_id
        || effective_profile != context.profile_id
        || effective_task != context.task_id.as_str()
        || payload.turn_id != context.turn_id
        || payload.turn_stream_id != context.turn_stream_id
    {
        return Err("flow-control payload does not match the active turn".to_string());
    }
    for (label, envelope, expected) in [
        (
            "session_id",
            frame.session_id.as_deref(),
            context.session_id.as_str(),
        ),
        (
            "profile_id",
            frame.profile_id.as_deref(),
            context.profile_id.as_str(),
        ),
        ("task_id", frame.task_id.as_deref(), context.task_id.as_str()),
        ("turn_id", frame.turn_id.as_deref(), context.turn_id.as_str()),
        (
            "turn_stream_id",
            frame
                .turn_stream_id
                .as_deref()
                .or(frame.stream_id.as_deref()),
            context.turn_stream_id.as_str(),
        ),
    ] {
        if envelope.is_some_and(|value| value != expected) {
            return Err(format!(
                "flow-control envelope {label} does not match the active turn"
            ));
        }
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn flow_ack_kind(command: &StreamControl) -> &'static str {
    match command {
        StreamControl::WindowUpdate { .. } => FRAME_STREAM_WINDOW_ACK,
        StreamControl::Pause => FRAME_STREAM_PAUSE_ACK,
        StreamControl::Resume => FRAME_STREAM_RESUME_ACK,
        StreamControl::Close => "stream.close.ack",
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
