impl StreamDelivery {
    fn submit(&mut self, frame: RunTurnFrame) -> Result<SubmitResult, String> {
        if !is_flow_controlled_kind(&frame.kind) || self.window.is_none() {
            return Ok(SubmitResult::Deliver(Box::new(frame)));
        }
        let mut buffered = BufferedFrame::new(frame)?;
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
                    buffered.performance_wait = Some(trillionnium_owner_open_trace::deferred(
                        trillionnium_owner_open_trace::Stage::DeliveryQueueWait,
                        buffered
                            .event_id
                            .as_deref()
                            .unwrap_or("transport.queued-frame"),
                    ));
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
                    let mut item = self.queue.pop_front().expect("front exists");
                    if let Some(trace) = item.performance_wait.take() {
                        trace.finish();
                    }
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
        self.queue
            .drain(..)
            .map(|mut item| {
                if let Some(trace) = item.performance_wait.take() {
                    trace.finish();
                }
                item.frame
            })
            .collect()
    }

    fn terminal_gap(&mut self) -> Option<ResyncGap> {
        if self.gap.is_none() && !self.queue.is_empty() {
            let first = self.queue.front().expect("queue is not empty");
            let empty = VecDeque::new();
            let mut gap = ResyncGap::from_buffer(&empty, first);
            for frame in self.queue.iter().skip(1) {
                gap.extend(frame);
            }
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
        // A numeric cursor is valid only with an explicit domain.  Older
        // transport frames may derive the parent transport domain from their
        // event ID; a job runtime frame must carry `cursor_domain=job_runtime_event`.
        // Never treat the historical `durable_cursor` field as a journal
        // offset by name alone: doing so aliases runtime and durable domains.
        let explicit_domain = match frame.extensions.get("cursor_domain") {
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or_else(|| "cursor_domain extension must be a string".to_string())?
                    .to_string(),
            ),
            None => None,
        };
        if let Some(domain) = explicit_domain.as_deref()
            && !matches!(
                domain,
                RUNTIME_CURSOR_DOMAIN | JOURNAL_CURSOR_DOMAIN | TRANSPORT_CURSOR_DOMAIN
            )
        {
            return Err(format!("unsupported cursor domain {domain}"));
        }
        let cursor = match frame.extensions.get("durable_cursor") {
            Some(value) => {
                explicit_domain.as_deref().ok_or_else(|| {
                    "durable_cursor requires an explicit cursor_domain".to_string()
                })?;
                Some(value.as_u64().ok_or_else(|| {
                    "durable_cursor extension must be a nonnegative integer".to_string()
                })?)
            }
            // Event IDs encode only the parent transport cursor.  An explicit
            // runtime/journal domain without a durable cursor is therefore an
            // intentionally non-numeric observation, even when its opaque ID
            // happens to end in `-event-<number>`.
            None if explicit_domain
                .as_deref()
                .is_some_and(|domain| domain != TRANSPORT_CURSOR_DOMAIN) =>
            {
                None
            }
            None if frame
                .extensions
                .get("transport_generated_event_id")
                .and_then(Value::as_bool)
                == Some(true) =>
            {
                None
            }
            None => frame.event_id.as_deref().and_then(cursor_from_event_id),
        };
        let cursor_domain = match (cursor, explicit_domain) {
            (Some(_), Some(domain)) => Some(domain),
            (Some(_), None) => Some(TRANSPORT_CURSOR_DOMAIN.to_string()),
            (None, domain) => domain,
        };
        let cursor_scope = CursorScope::from_frame(&frame, cursor_domain.as_deref());
        let event_id = frame.event_id.clone();
        Ok(Self {
            performance_wait: None,
            frame,
            encoded_bytes,
            cursor,
            cursor_domain,
            cursor_scope,
            event_id,
        })
    }
}

fn is_flow_controlled_kind(kind: &str) -> bool {
    FLOW_CONTROLLED_FRAME_KINDS.contains(&kind)
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
