// Keep the wire capability advertisement and the delivery classifier bound to
// one table. A client must not be told that a bounded stream is pass-through
// (or vice versa), especially for unbounded durable job output.
const FLOW_CONTROLLED_FRAME_KINDS: &[&str] = &[
    FRAME_MODEL_DELTA,
    FRAME_MODEL_MESSAGE,
    FRAME_TOOL_PTY,
    FRAME_TOOL_STDOUT,
    FRAME_TOOL_STDERR,
    "provider.opaque",
    "job.output",
];

// Cursor numbers are only meaningful inside their declared domain.  In
// particular, a job runtime observation sequence must never be compared with
// a durable journal-record offset (or with the parent transport sequence).
const TRANSPORT_CURSOR_DOMAIN: &str = "transport_event";
const RUNTIME_CURSOR_DOMAIN: &str = "job_runtime_event";
const JOURNAL_CURSOR_DOMAIN: &str = "job_journal_record";

#[derive(Debug, Clone)]
struct BufferedFrame {
    frame: RunTurnFrame,
    encoded_bytes: u64,
    cursor: Option<u64>,
    cursor_domain: Option<String>,
    event_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ResyncGap {
    cursor_domain: Option<String>,
    first_cursor: Option<u64>,
    last_cursor: Option<u64>,
    /// Numeric bounds are publishable only when every suppressed frame has a
    /// cursor in the same domain.  A domain label by itself is not enough:
    /// one opaque frame in the run would make a partial range unsafe to
    /// resume from.
    cursor_range_complete: bool,
    first_event_id: Option<String>,
    last_event_id: Option<String>,
    suppressed_frames: u64,
    mixed_cursor_domains: bool,
}

impl ResyncGap {
    fn from_buffer(buffer: &VecDeque<BufferedFrame>, current: &BufferedFrame) -> Self {
        let first = buffer.front().unwrap_or(current);
        let same_domain = first.cursor_domain == current.cursor_domain;
        let all_cursored = buffer.iter().all(|frame| frame.cursor.is_some())
            && current.cursor.is_some();
        let cursor_range_complete = same_domain && all_cursored;
        Self {
            cursor_domain: same_domain.then(|| first.cursor_domain.clone()).flatten(),
            first_cursor: cursor_range_complete.then_some(first.cursor).flatten(),
            last_cursor: cursor_range_complete.then_some(current.cursor).flatten(),
            cursor_range_complete,
            first_event_id: first.event_id.clone(),
            last_event_id: current.event_id.clone(),
            suppressed_frames: u64::try_from(buffer.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
            mixed_cursor_domains: !same_domain,
        }
    }

    fn extend(&mut self, frame: &BufferedFrame) {
        if self.cursor_domain != frame.cursor_domain {
            // A single transport gap cannot describe two independent cursor
            // spaces.  Clear numeric bounds and force the peer to restart
            // inspection from an explicit domain instead of accepting a
            // misleading resume cursor.
            self.cursor_domain = None;
            self.first_cursor = None;
            self.last_cursor = None;
            self.cursor_range_complete = false;
            self.mixed_cursor_domains = true;
        }
        if !self.mixed_cursor_domains && frame.cursor.is_none() {
            self.cursor_range_complete = false;
            self.first_cursor = None;
            self.last_cursor = None;
        }
        if self.first_event_id.is_none() {
            self.first_event_id = frame.event_id.clone();
        }
        if frame.cursor.is_some()
            && !self.mixed_cursor_domains
            && self.cursor_range_complete
        {
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
            "cursor_domain": &self.cursor_domain,
            "first_missing_cursor": self.first_cursor,
            "last_missing_cursor": self.last_cursor,
            "required_resume_cursor": self.required_resume_cursor(),
            "cursor_range_complete": self.cursor_range_complete,
            "first_missing_event_id": &self.first_event_id,
            "last_missing_event_id": &self.last_event_id,
            "suppressed_frames": self.suppressed_frames,
            "mixed_cursor_domains": self.mixed_cursor_domains,
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
    Deliver(Box<RunTurnFrame>),
    Queued,
    GapStarted(ResyncGap),
    Suppressed,
}
