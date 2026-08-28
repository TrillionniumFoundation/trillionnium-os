#[derive(Debug, Clone)]
struct BufferedFrame {
    frame: RunTurnFrame,
    encoded_bytes: u64,
    cursor: Option<u64>,
    event_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ResyncGap {
    first_cursor: Option<u64>,
    last_cursor: Option<u64>,
    first_event_id: Option<String>,
    last_event_id: Option<String>,
    suppressed_frames: u64,
}

impl ResyncGap {
    fn from_buffer(buffer: &VecDeque<BufferedFrame>, current: &BufferedFrame) -> Self {
        let first = buffer.front().unwrap_or(current);
        Self {
            first_cursor: first.cursor,
            last_cursor: current.cursor,
            first_event_id: first.event_id.clone(),
            last_event_id: current.event_id.clone(),
            suppressed_frames: u64::try_from(buffer.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        }
    }

    fn extend(&mut self, frame: &BufferedFrame) {
        if self.first_cursor.is_none() {
            self.first_cursor = frame.cursor;
        }
        if self.first_event_id.is_none() {
            self.first_event_id = frame.event_id.clone();
        }
        if frame.cursor.is_some() {
            self.last_cursor = frame.cursor;
        }
        if frame.event_id.is_some() {
            self.last_event_id = frame.event_id.clone();
        }
        self.suppressed_frames = self.suppressed_frames.saturating_add(1);
    }

    fn required_resume_cursor(&self) -> Option<u64> {
        self.last_cursor.and_then(|value| value.checked_add(1))
    }

    fn payload(&self) -> Value {
        json!({
            "status": "resync_required",
            "first_missing_cursor": self.first_cursor,
            "last_missing_cursor": self.last_cursor,
            "required_resume_cursor": self.required_resume_cursor(),
            "first_missing_event_id": &self.first_event_id,
            "last_missing_event_id": &self.last_event_id,
            "suppressed_frames": self.suppressed_frames,
            "recovery": "use turn.inspect, then stream.resume with resumed_through_cursor",
            "automatic_redispatch": false
        })
    }
}

#[derive(Debug)]
struct StreamDelivery {
    window: Option<StreamWindow>,
    queue: VecDeque<BufferedFrame>,
    queued_bytes: usize,
    max_buffer_bytes: usize,
    max_credit_bytes: u64,
    max_chunk_bytes: u64,
    control_history: usize,
    gap: Option<ResyncGap>,
    control_fingerprints: VecDeque<(u64, String)>,
}

#[derive(Debug)]
enum SubmitResult {
    Deliver(RunTurnFrame),
    Queued,
    GapStarted(ResyncGap),
    Suppressed,
}
