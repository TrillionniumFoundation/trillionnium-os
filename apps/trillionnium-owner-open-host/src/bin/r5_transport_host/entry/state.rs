#[derive(Debug, Clone)]
struct TurnContext {
    session_id: String,
    profile_id: String,
    task_id: String,
    turn_id: String,
    turn_stream_id: String,
    request_sha256: String,
}

impl TurnContext {
    fn from_start(frame: &RunTurnFrame, limits: &MechanicalLimits) -> Result<Self, String> {
        let request = frame.turn_request(limits).map_err(|error| error.to_string())?;
        Ok(Self {
            session_id: request.session_id.clone(),
            profile_id: request.effective_profile_id().to_string(),
            task_id: request.task_id.clone(),
            turn_id: request.turn_id.clone(),
            turn_stream_id: stable_turn_stream_id(&request)?,
            request_sha256: request_sha256(&request)?,
        })
    }
}

#[derive(Debug)]
enum TransportMessage {
    ClientFrame(Vec<u8>),
    ClientEof,
    ClientError(String),
    CoreFrame(Vec<u8>),
    CoreEof,
    CoreError(String),
}

#[derive(Debug)]
struct TransportOutput {
    connection_id: String,
    next_seq: u64,
}

impl TransportOutput {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        Self {
            connection_id: format!("r5-transport-{}-{nanos}", std::process::id()),
            next_seq: 0,
        }
    }

    fn rewrite_core(&mut self, mut frame: RunTurnFrame) -> RunTurnFrame {
        let core_seq = frame.seq;
        let core_host_seq = frame.host_seq;
        let core_connection_id = frame.connection_id.clone();
        frame.extensions.insert("core_seq".to_string(), json!(core_seq));
        if let Some(value) = core_host_seq {
            frame
                .extensions
                .insert("core_host_seq".to_string(), json!(value));
        }
        if let Some(value) = core_connection_id {
            frame
                .extensions
                .insert("core_connection_id".to_string(), json!(value));
        }
        let seq = self.take_seq();
        frame.seq = seq;
        frame.host_seq = Some(seq);
        frame.connection_id = Some(self.connection_id.clone());
        frame.direction = Some("host_to_client".to_string());
        frame
    }

    fn local_frame(
        &mut self,
        kind: &str,
        payload: Value,
        context: Option<&TurnContext>,
    ) -> RunTurnFrame {
        let seq = self.take_seq();
        RunTurnFrame {
            kind: kind.to_string(),
            seq,
            payload,
            direction: Some("host_to_client".to_string()),
            client_seq: None,
            host_seq: Some(seq),
            frame_sha256: None,
            event_id: Some(format!("{}-event-{seq}", self.connection_id)),
            connection_id: Some(self.connection_id.clone()),
            stream_id: context.map(|value| value.turn_stream_id.clone()),
            turn_stream_id: context.map(|value| value.turn_stream_id.clone()),
            session_id: context.map(|value| value.session_id.clone()),
            profile_id: context.map(|value| value.profile_id.clone()),
            task_id: context.map(|value| value.task_id.clone()),
            turn_id: context.map(|value| value.turn_id.clone()),
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: BTreeMap::new(),
        }
    }

    fn take_seq(&mut self) -> u64 {
        let value = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        value
    }
}
