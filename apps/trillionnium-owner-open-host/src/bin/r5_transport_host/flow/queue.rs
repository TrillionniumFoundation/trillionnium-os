impl StreamDelivery {
    fn submit(&mut self, frame: RunTurnFrame) -> Result<SubmitResult, String> {
        if !is_flow_controlled_kind(&frame.kind) || self.window.is_none() {
            return Ok(SubmitResult::Deliver(Box::new(frame)));
        }
        let buffered = BufferedFrame::new(frame)?;
        if let Some(gap) = &mut self.gap {
            gap.extend(&buffered);
            return Ok(SubmitResult::Suppressed);
        }
        if buffered.encoded_bytes > self.max_chunk_bytes {
            let gap = ResyncGap::from_buffer(&self.queue, &buffered);
            self.queue.clear();
            self.queued_bytes = 0;
            self.gap = Some(gap.clone());
            return Ok(SubmitResult::GapStarted(gap));
        }
        match self.reserve(buffered.encoded_bytes)? {
            ReserveDisposition::Granted { .. } => {
                Ok(SubmitResult::Deliver(Box::new(buffered.frame)))
            }
            ReserveDisposition::Blocked(_) => {
                let encoded = usize::try_from(buffered.encoded_bytes)
                    .map_err(|_| "encoded frame length does not fit usize".to_string())?;
                if encoded > self.max_buffer_bytes
                    || self.queued_bytes.saturating_add(encoded) > self.max_buffer_bytes
                {
                    let gap = ResyncGap::from_buffer(&self.queue, &buffered);
                    self.queue.clear();
                    self.queued_bytes = 0;
                    self.gap = Some(gap.clone());
                    Ok(SubmitResult::GapStarted(gap))
                } else {
                    self.queued_bytes += encoded;
                    self.queue.push_back(buffered);
                    Ok(SubmitResult::Queued)
                }
            }
        }
    }

    fn drain(&mut self) -> Result<Vec<RunTurnFrame>, String> {
        if self.gap.is_some() || self.window.is_none() {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        while let Some(front) = self.queue.front() {
            match self.reserve(front.encoded_bytes)? {
                ReserveDisposition::Granted { .. } => {
                    let item = self.queue.pop_front().expect("front exists");
                    let encoded = usize::try_from(item.encoded_bytes)
                        .map_err(|_| "encoded frame length does not fit usize".to_string())?;
                    self.queued_bytes = self.queued_bytes.saturating_sub(encoded);
                    output.push(item.frame);
                }
                ReserveDisposition::Blocked(_) => break,
            }
        }
        Ok(output)
    }

    fn disable_and_release(&mut self) -> Vec<RunTurnFrame> {
        self.window = None;
        // Preserve an existing gap through turn terminal. Losing durable
        // storage cannot make already-suppressed delivery magically complete.
        self.control_fingerprints.clear();
        self.queued_bytes = 0;
        self.queue.drain(..).map(|item| item.frame).collect()
    }

    fn terminal_gap(&mut self) -> Option<ResyncGap> {
        if self.gap.is_none() && !self.queue.is_empty() {
            let first = self.queue.front().cloned().expect("queue is not empty");
            let last = self.queue.back().cloned().expect("queue is not empty");
            let gap = ResyncGap {
                first_cursor: first.cursor,
                last_cursor: last.cursor,
                first_event_id: first.event_id,
                last_event_id: last.event_id,
                suppressed_frames: u64::try_from(self.queue.len()).unwrap_or(u64::MAX),
            };
            self.queue.clear();
            self.queued_bytes = 0;
            self.gap = Some(gap);
        }
        self.gap.clone()
    }

    fn finish_turn(&mut self) {
        self.begin_turn();
    }

    fn snapshot(&self) -> Option<StreamWindowSnapshot> {
        self.window
            .as_ref()
            .and_then(|window| window.snapshot().ok())
    }

    fn reserve(&self, bytes: u64) -> Result<ReserveDisposition, String> {
        self.window
            .as_ref()
            .expect("reserve requires an active window")
            .try_reserve(bytes)
            .map_err(|error| error.to_string())
    }
}

impl BufferedFrame {
    fn new(frame: RunTurnFrame) -> Result<Self, String> {
        let encoded_bytes = u64::try_from(
            serde_json::to_vec(&frame)
                .map_err(|error| error.to_string())?
                .len()
                .saturating_add(1),
        )
        .map_err(|_| "encoded frame length does not fit u64".to_string())?;
        let cursor = frame.event_id.as_deref().and_then(cursor_from_event_id);
        let event_id = frame.event_id.clone();
        Ok(Self {
            frame,
            encoded_bytes,
            cursor,
            event_id,
        })
    }
}

fn is_flow_controlled_kind(kind: &str) -> bool {
    matches!(
        kind,
        FRAME_MODEL_DELTA
            | FRAME_MODEL_MESSAGE
            | FRAME_TOOL_STDOUT
            | FRAME_TOOL_STDERR
            | "provider.opaque"
            | "job.output"
    )
}

fn cursor_from_event_id(event_id: &str) -> Option<u64> {
    event_id
        .rsplit_once("-event-")
        .and_then(|(_, value)| value.parse::<u64>().ok())
}

fn snapshot_payload(snapshot: &StreamWindowSnapshot) -> Value {
    json!({
        "available_credit_bytes": snapshot.available_credit_bytes,
        "max_credit_bytes": snapshot.max_credit_bytes,
        "max_chunk_bytes": snapshot.max_chunk_bytes,
        "paused": snapshot.paused,
        "closed": snapshot.closed,
        "total_granted_bytes": snapshot.total_granted_bytes,
        "earliest_control_seq": snapshot.earliest_control_seq,
        "next_control_seq": snapshot.next_control_seq
    })
}
