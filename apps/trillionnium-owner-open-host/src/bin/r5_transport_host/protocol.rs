#[derive(Debug, Clone, Deserialize)]
struct FlowControlPayload {
    control_seq: u64,
    session_id: String,
    turn_id: String,
    /// `turn_stream_id` is the canonical spelling.  Older clients used
    /// `stream_id` in the payload, so retain that alias explicitly instead
    /// of letting `flatten` silently discard it.  Both values are checked
    /// below before a control is admitted.
    #[serde(default)]
    turn_stream_id: Option<String>,
    #[serde(default)]
    stream_id: Option<String>,
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
    let turn_stream_id = validate_control_correlation(frame, &payload, context)?;
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
    // Alias spellings identify the same control.  Canonicalize the legacy
    // key before taking the duplicate-control fingerprint so a replay that
    // switches from `turn_stream_id` to `stream_id` remains an exact replay
    // rather than a false sequence conflict.
    let mut canonical_payload = frame.payload.clone();
    if let Some(object) = canonical_payload.as_object_mut() {
        object.remove("stream_id");
        object.insert(
            "turn_stream_id".to_string(),
            Value::String(turn_stream_id.clone()),
        );
    }
    let encoded = serde_json::to_vec(&canonical_payload)
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
) -> Result<String, String> {
    let payload_stream_id = match (
        payload.turn_stream_id.as_deref(),
        payload.stream_id.as_deref(),
    ) {
        (Some(canonical), Some(legacy)) if canonical != legacy => {
            return Err(
                "flow-control payload stream_id conflicts with turn_stream_id".to_string(),
            );
        }
        (Some(value), _) | (_, Some(value)) => value,
        (None, None) => {
            return Err(
                "flow-control payload requires turn_stream_id or legacy stream_id".to_string(),
            );
        }
    };
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
        ("turn_stream_id", payload_stream_id),
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
        || payload_stream_id != context.turn_stream_id
    {
        return Err("flow-control payload does not match the active turn".to_string());
    }
    let envelope_stream_id = match (
        frame.turn_stream_id.as_deref(),
        frame.stream_id.as_deref(),
    ) {
        (Some(canonical), Some(legacy)) if canonical != legacy => {
            return Err(
                "flow-control envelope stream_id conflicts with turn_stream_id".to_string(),
            );
        }
        (Some(value), _) | (_, Some(value)) => Some(value),
        (None, None) => None,
    };
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
        ("turn_stream_id", envelope_stream_id, context.turn_stream_id.as_str()),
    ] {
        if envelope.is_some_and(|value| value != expected) {
            return Err(format!(
                "flow-control envelope {label} does not match the active turn"
            ));
        }
    }
    if envelope_stream_id.is_some_and(|value| value != payload_stream_id) {
        return Err(
            "flow-control envelope and payload stream identifiers conflict".to_string(),
        );
    }
    Ok(payload_stream_id.to_string())
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

#[cfg(test)]
mod protocol_tests {
    use super::*;

    fn context() -> TurnContext {
        TurnContext {
            session_id: "session-flow-alias".to_string(),
            profile_id: DEFAULT_PROFILE_ID.to_string(),
            task_id: "task-flow-alias".to_string(),
            turn_id: "turn-flow-alias".to_string(),
            turn_stream_id: "stream-flow-alias".to_string(),
            request_sha256: "a".repeat(64),
        }
    }

    fn frame(payload_streams: Value) -> RunTurnFrame {
        RunTurnFrame {
            kind: FRAME_STREAM_PAUSE.to_string(),
            seq: 0,
            payload: payload_streams,
            direction: Some("client_to_host".to_string()),
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
            extensions: BTreeMap::new(),
        }
    }

    fn payload() -> Value {
        json!({
            "control_seq": 0,
            "session_id": "session-flow-alias",
            "turn_id": "turn-flow-alias"
        })
    }

    #[test]
    fn legacy_payload_stream_id_is_accepted_and_canonicalized() {
        let mut legacy = payload();
        legacy["stream_id"] = json!("stream-flow-alias");
        let mut canonical = payload();
        canonical["turn_stream_id"] = json!("stream-flow-alias");

        let parsed_legacy = parse_flow_control(
            &frame(legacy),
            &context(),
            DEFAULT_MAX_CREDIT_BYTES,
        )
        .expect("legacy stream_id alias should be accepted");
        let parsed_canonical = parse_flow_control(
            &frame(canonical),
            &context(),
            DEFAULT_MAX_CREDIT_BYTES,
        )
        .expect("canonical turn_stream_id should be accepted");
        assert_eq!(
            parsed_legacy.request_fingerprint,
            parsed_canonical.request_fingerprint,
            "alias spellings must identify the same control request"
        );
    }

    #[test]
    fn conflicting_payload_stream_aliases_fail_closed() {
        let mut payload = payload();
        payload["turn_stream_id"] = json!("stream-flow-alias");
        payload["stream_id"] = json!("other-stream");
        let error = parse_flow_control(&frame(payload), &context(), DEFAULT_MAX_CREDIT_BYTES)
            .expect_err("conflicting payload aliases must be rejected");
        assert!(error.contains("stream_id conflicts with turn_stream_id"));
    }

    #[test]
    fn conflicting_envelope_stream_aliases_fail_closed() {
        let mut frame = frame({
            let mut payload = payload();
            payload["turn_stream_id"] = json!("stream-flow-alias");
            payload
        });
        frame.turn_stream_id = Some("stream-flow-alias".to_string());
        frame.stream_id = Some("other-stream".to_string());
        let error = parse_flow_control(&frame, &context(), DEFAULT_MAX_CREDIT_BYTES)
            .expect_err("conflicting envelope aliases must be rejected");
        assert!(error.contains("envelope stream_id conflicts with turn_stream_id"));
    }
}
