fn augment_core_frame(
    frame: &mut RunTurnFrame,
    active: Option<&TurnContext>,
    options: &Options,
    flow: &StreamDelivery,
    durable_ready: bool,
    journal: &TransportJournal,
) {
    let Some(payload) = frame.payload.as_object_mut() else {
        return;
    };
    if frame.kind == FRAME_HELLO_ACK {
        payload.insert(
            "host_implementation".to_string(),
            Value::String(HOST_IMPLEMENTATION_V5.to_string()),
        );
        payload.insert("transport_flow_control".to_string(), Value::Bool(true));
        payload.insert(
            "flow_control_requires_durable_store".to_string(),
            Value::Bool(true),
        );
        payload.insert(
            "flow_controlled_frame_kinds".to_string(),
            json!(FLOW_CONTROLLED_FRAME_KINDS),
        );
        payload.insert(
            "transport_buffer_bytes".to_string(),
            json!(options.buffer_bytes),
        );
        payload.insert(
            "transport_max_credit_bytes".to_string(),
            json!(options.max_credit_bytes),
        );
        payload.insert(
            "transport_max_chunk_bytes".to_string(),
            json!(options.max_chunk_bytes),
        );
        payload.insert("persist_before_flow".to_string(), Value::Bool(true));
        payload.insert(
            "transport_journal_status".to_string(),
            Value::String(journal.status().to_string()),
        );
        payload.insert(
            "transport_journal_error".to_string(),
            journal
                .error()
                .map_or(Value::Null, |value| Value::String(value.to_string())),
        );
    }
    if frame.kind == FRAME_TURN_ACCEPTED {
        if let Some(context) = active {
            payload.insert(
                "turn_request_sha256".to_string(),
                Value::String(context.request_sha256.clone()),
            );
            payload.insert(
                "turn_stream_id".to_string(),
                Value::String(context.turn_stream_id.clone()),
            );
        }
        payload.insert(
            "flow_control_status".to_string(),
            Value::String(
                if flow.is_active() {
                    "active"
                } else {
                    "passthrough"
                }
                .to_string(),
            ),
        );
        payload.insert(
            "flow_control_available".to_string(),
            Value::Bool(durable_ready),
        );
    }
    if flow.gap.is_some() && matches!(frame.kind.as_str(), FRAME_TOOL_RESULT | FRAME_TOOL_STARTED) {
        payload.insert("stream_resync_required".to_string(), Value::Bool(true));
    }
}

fn attach_gap_to_payload(payload: &mut Value, gap: &ResyncGap) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    object.insert("stream_resync_required".to_string(), Value::Bool(true));
    object.insert("stream_gap".to_string(), gap.payload());
}

fn attach_delivery_status<W: Write>(payload: &mut Value, delivery: &ClientDelivery<W>) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    object.insert(
        "transport_client_delivery_status_before_terminal_attempt".to_string(),
        Value::String(
            if delivery.attached {
                "attached"
            } else {
                "detached"
            }
            .to_string(),
        ),
    );
    object.insert(
        "transport_client_delivery_error".to_string(),
        delivery
            .error
            .as_ref()
            .map_or(Value::Null, |value| Value::String(value.clone())),
    );
}

fn write_resync_required<W: Write>(
    delivery: &mut ClientDelivery<W>,
    output: &mut TransportOutput,
    context: Option<&TurnContext>,
    gap: &ResyncGap,
) -> Result<(), String> {
    let frame = output.local_frame(FRAME_STREAM_RESYNC_REQUIRED, gap.payload(), context);
    delivery.send(&frame)
}

fn write_local_error<W: Write>(
    delivery: &mut ClientDelivery<W>,
    output: &mut TransportOutput,
    context: Option<&TurnContext>,
    code: &str,
    message: &str,
) -> Result<(), String> {
    let frame = output.local_frame(
        FRAME_HOST_ERROR,
        json!({
            "code": code,
            "message": message,
            "transport_layer": true,
            "automatic_redispatch": false
        }),
        context,
    );
    delivery.send(&frame)
}

fn is_flow_control_kind(kind: &str) -> bool {
    matches!(
        kind,
        FRAME_STREAM_WINDOW_UPDATE | FRAME_STREAM_PAUSE | FRAME_STREAM_RESUME
    )
}

fn frame_reports_durable(frame: &RunTurnFrame) -> bool {
    frame
        .payload
        .get("durable_event_store")
        .and_then(Value::as_bool)
        == Some(true)
        || frame
            .payload
            .get("event_log_status")
            .and_then(Value::as_str)
            == Some("durable")
}

fn frame_reports_unavailable(frame: &RunTurnFrame) -> bool {
    matches!(
        frame
            .payload
            .get("event_log_status")
            .and_then(Value::as_str),
        Some("unavailable") | Some("best_effort_memory_only")
    )
}

fn forward_to_core(core_stdin: &mut Option<ChildStdin>, encoded: &[u8]) -> Result<(), String> {
    let writer = core_stdin
        .as_mut()
        .ok_or_else(|| "core Host stdin is closed".to_string())?;
    writer
        .write_all(encoded)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("failed to forward client frame to core Host: {error}"))
}

struct ClientDelivery<W: Write> {
    writer: W,
    max_frame_bytes: usize,
    attached: bool,
    error: Option<String>,
}

impl<W: Write> ClientDelivery<W> {
    fn new(writer: W, max_frame_bytes: usize) -> Self {
        Self {
            writer,
            max_frame_bytes,
            attached: true,
            error: None,
        }
    }

    fn send(&mut self, frame: &RunTurnFrame) -> Result<(), String> {
        let encoded = serde_json::to_vec(frame).map_err(|error| error.to_string())?;
        if encoded.is_empty() || encoded.len() > self.max_frame_bytes {
            return Err("transport response frame exceeds the Host frame bound".to_string());
        }
        if !self.attached {
            return Ok(());
        }
        if let Err(error) = self
            .writer
            .write_all(&encoded)
            .and_then(|_| self.writer.write_all(b"\n"))
            .and_then(|_| self.writer.flush())
        {
            self.attached = false;
            self.error = Some(error.to_string());
        }
        Ok(())
    }

    fn flush_if_attached(&mut self) -> Result<(), String> {
        if self.attached {
            self.writer.flush().map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}
