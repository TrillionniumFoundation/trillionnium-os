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
const SCOPED_RESYNC_PROTOCOL: &str = "scoped_cursor_v1";
const MAX_RESYNC_CURSOR_SCOPES: usize = 64;

/// Cursor domains also include the owning state partition. Two jobs can
/// emit the same runtime ordinal while referring to unrelated observations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorScope {
    session_id: String,
    profile_id: String,
    task_id: String,
    turn_id: String,
    turn_stream_id: String,
    job_id: Option<String>,
}

impl CursorScope {
    fn from_frame(frame: &RunTurnFrame, domain: Option<&str>) -> Option<Box<Self>> {
        let job_id = if matches!(domain, Some(RUNTIME_CURSOR_DOMAIN | JOURNAL_CURSOR_DOMAIN)) {
            Some(frame.job_id.clone()?)
        } else {
            None
        };
        Some(Box::new(Self {
            session_id: frame.session_id.clone()?,
            profile_id: frame.profile_id.clone()?,
            task_id: frame.task_id.clone()?,
            turn_id: frame.turn_id.clone()?,
            turn_stream_id: frame
                .turn_stream_id
                .clone()
                .or_else(|| frame.stream_id.clone())?,
            job_id,
        }))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumedCursor {
    cursor_domain: String,
    cursor_scope: Box<CursorScope>,
    resumed_through_cursor: u64,
}

#[derive(Debug, Clone)]
struct MissingCursorRange {
    cursor_domain: String,
    cursor_scope: Box<CursorScope>,
    first_cursor: u64,
    last_cursor: u64,
    inspected_through: Option<u64>,
}

impl MissingCursorRange {
    fn payload(&self) -> Value {
        json!({
            "cursor_domain": self.cursor_domain,
            "cursor_scope": self.cursor_scope,
            "first_missing_cursor": self.first_cursor,
            "last_missing_cursor": self.last_cursor,
            "required_resume_cursor": self.last_cursor.checked_add(1),
        })
    }
}

#[derive(Debug)]
struct BufferedFrame {
    performance_wait: Option<trillionnium_owner_open_trace::Span>,
    frame: RunTurnFrame,
    encoded_bytes: u64,
    cursor: Option<u64>,
    cursor_domain: Option<String>,
    cursor_scope: Option<Box<CursorScope>>,
    event_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ResyncGap {
    cursor_domain: Option<String>,
    cursor_scope: Option<Box<CursorScope>>,
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
    cursor_ranges: Vec<MissingCursorRange>,
    cursor_scopes_complete: bool,
}

impl ResyncGap {
    fn from_buffer(buffer: &VecDeque<BufferedFrame>, current: &BufferedFrame) -> Self {
        let first = buffer.front().unwrap_or(current);
        // Overflow can discard a queue whose endpoints have one domain but
        // whose middle contains another. Validate the entire missing run,
        // exactly as terminal_gap does, before publishing numeric cursors.
        let same_domain = first.cursor_domain == current.cursor_domain
            && first.cursor_scope == current.cursor_scope
            && buffer.iter().all(|frame| {
                frame.cursor_domain == first.cursor_domain
                    && frame.cursor_scope == first.cursor_scope
            });
        let all_cursored =
            buffer.iter().all(|frame| frame.cursor.is_some()) && current.cursor.is_some();
        let cursor_range_complete = same_domain && all_cursored && first.cursor_scope.is_some();
        let mut gap = Self {
            cursor_domain: same_domain.then(|| first.cursor_domain.clone()).flatten(),
            cursor_scope: same_domain.then(|| first.cursor_scope.clone()).flatten(),
            first_cursor: cursor_range_complete.then_some(first.cursor).flatten(),
            last_cursor: cursor_range_complete.then_some(current.cursor).flatten(),
            cursor_range_complete,
            first_event_id: first.event_id.clone(),
            last_event_id: current.event_id.clone(),
            suppressed_frames: u64::try_from(buffer.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
            mixed_cursor_domains: !same_domain,
            cursor_ranges: Vec::new(),
            cursor_scopes_complete: true,
        };
        for frame in buffer.iter().chain(std::iter::once(current)) {
            gap.record_missing_cursor(frame);
        }
        gap
    }

    fn extend(&mut self, frame: &BufferedFrame) {
        self.record_missing_cursor(frame);
        if self.cursor_domain != frame.cursor_domain || self.cursor_scope != frame.cursor_scope {
            // A single transport gap cannot describe two independent cursor
            // spaces.  Clear numeric bounds and force the peer to restart
            // inspection from an explicit domain instead of accepting a
            // misleading resume cursor.
            self.cursor_domain = None;
            self.cursor_scope = None;
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
        if frame.cursor.is_some() && !self.mixed_cursor_domains && self.cursor_range_complete {
            self.last_cursor = frame.cursor;
        }
        if frame.event_id.is_some() {
            self.last_event_id = frame.event_id.clone();
        }
        self.suppressed_frames = self.suppressed_frames.saturating_add(1);
    }

    fn record_missing_cursor(&mut self, frame: &BufferedFrame) {
        let (Some(domain), Some(scope), Some(cursor)) =
            (&frame.cursor_domain, &frame.cursor_scope, frame.cursor)
        else {
            self.cursor_scopes_complete = false;
            return;
        };
        if cursor == u64::MAX {
            self.cursor_scopes_complete = false;
        }
        if let Some(range) = self
            .cursor_ranges
            .iter_mut()
            .find(|range| &range.cursor_domain == domain && &range.cursor_scope == scope)
        {
            // Bounds describe every missing ordinal, including interleaved jobs.
            // A late earlier ordinal invalidates prior prefix coverage.
            if cursor < range.first_cursor {
                range.inspected_through = None;
            }
            range.first_cursor = range.first_cursor.min(cursor);
            range.last_cursor = range.last_cursor.max(cursor);
        } else if self.cursor_ranges.len() < MAX_RESYNC_CURSOR_SCOPES {
            self.cursor_ranges.push(MissingCursorRange {
                cursor_domain: domain.clone(),
                cursor_scope: scope.clone(),
                first_cursor: cursor,
                last_cursor: cursor,
                inspected_through: None,
            });
        } else {
            self.cursor_scopes_complete = false;
        }
    }

    fn validate_resume(&self, parsed: &ParsedFlowControl) -> Result<(), String> {
        if parsed.resync_protocol.as_deref() != Some(SCOPED_RESYNC_PROTOCOL) {
            return Err("delivery gap requires negotiated scoped_cursor_v1 recovery".to_string());
        }
        if parsed.resumed_through_cursor.is_some() {
            return Err(
                "bare resumed_through_cursor cannot acknowledge a scoped delivery gap".to_string(),
            );
        }
        if !self.cursor_scopes_complete || self.cursor_ranges.is_empty() {
            return Err("delivery gap has unknown or excessive cursor scopes; explicit reconciliation is required".to_string());
        }
        if parsed.resumed_cursors.len() != self.cursor_ranges.len() {
            return Err(
                "resume must acknowledge every missing cursor scope exactly once".to_string(),
            );
        }
        for range in &self.cursor_ranges {
            let mut matches = parsed.resumed_cursors.iter().filter(|cursor| {
                cursor.cursor_domain == range.cursor_domain
                    && cursor.cursor_scope == range.cursor_scope
            });
            let received = matches.next().ok_or_else(|| {
                "resume cursor domain/scope does not match the delivery gap".to_string()
            })?;
            if matches.next().is_some() {
                return Err("duplicate resume cursor domain/scope".to_string());
            }
            let required = range
                .last_cursor
                .checked_add(1)
                .ok_or_else(|| "missing cursor range is exhausted".to_string())?;
            if received.resumed_through_cursor < required
                || range
                    .inspected_through
                    .is_none_or(|next| received.resumed_through_cursor > next)
            {
                return Err("resume requires contiguous read-only inspection through each missing cursor range".to_string());
            }
        }
        Ok(())
    }

    fn required_resume_cursor(&self) -> Option<u64> {
        self.last_cursor.and_then(|value| value.checked_add(1))
    }

    fn payload(&self) -> Value {
        json!({
            "status": "resync_required",
            "resync_protocol": SCOPED_RESYNC_PROTOCOL,
            "cursor_scope": &self.cursor_scope,
            "cursor_scopes_complete": self.cursor_scopes_complete,
            "required_resumes": self.cursor_ranges.iter().map(MissingCursorRange::payload).collect::<Vec<_>>(),
            "max_cursor_scopes": MAX_RESYNC_CURSOR_SCOPES,
            "cursor_domain": &self.cursor_domain,
            "first_missing_cursor": self.first_cursor,
            "last_missing_cursor": self.last_cursor,
            "required_resume_cursor": self.required_resume_cursor(),
            "cursor_range_complete": self.cursor_range_complete,
            "first_missing_event_id": &self.first_event_id,
            "last_missing_event_id": &self.last_event_id,
            "suppressed_frames": self.suppressed_frames,
            "mixed_cursor_domains": self.mixed_cursor_domains,
            "recovery": "read each scope with turn.inspect or job.inspect, then stream.resume with resumed_cursors; unknown or retention gaps require explicit reconciliation",
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
