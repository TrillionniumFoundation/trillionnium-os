impl StreamDelivery {
    fn new(options: &Options) -> Self {
        Self {
            window: None,
            queue: VecDeque::new(),
            queued_bytes: 0,
            max_buffer_bytes: options.buffer_bytes,
            max_credit_bytes: options.max_credit_bytes,
            max_chunk_bytes: options.max_chunk_bytes,
            control_history: options.control_history,
            gap: None,
            control_fingerprints: VecDeque::new(),
        }
    }

    fn begin_turn(&mut self) {
        self.window = None;
        self.queue.clear();
        self.queued_bytes = 0;
        self.gap = None;
        self.control_fingerprints.clear();
    }

    fn is_active(&self) -> bool {
        self.window.is_some()
    }

    fn apply_control(
        &mut self,
        parsed: &ParsedFlowControl,
    ) -> Result<(ApplyDisposition, StreamWindowSnapshot), String> {
        let candidate_window = if self.window.is_none() {
            Some(
                StreamWindow::new(StreamWindowConfig {
                    initial_credit_bytes: 0,
                    max_credit_bytes: self.max_credit_bytes,
                    max_chunk_bytes: self.max_chunk_bytes,
                    max_control_history: self.control_history,
                })
                .map_err(|error| error.to_string())?,
            )
        } else {
            None
        };
        let window = self
            .window
            .as_ref()
            .or(candidate_window.as_ref())
            .expect("window candidate exists");
        let before = window.snapshot().map_err(|error| error.to_string())?;
        if parsed.control_seq < before.next_control_seq {
            let fingerprint = self
                .control_fingerprints
                .iter()
                .find(|(seq, _)| *seq == parsed.control_seq)
                .map(|(_, value)| value);
            match fingerprint {
                Some(value) if value == &parsed.request_fingerprint => {}
                Some(_) => {
                    return Err(
                        "stream control sequence is already bound to different payload bytes"
                            .to_string(),
                    );
                }
                None => {
                    return window
                        .apply_control(parsed.control_seq, parsed.command.clone())
                        .map(|result| (result.disposition, result.snapshot))
                        .map_err(|error| error.to_string());
                }
            }
            return window
                .apply_control(parsed.control_seq, parsed.command.clone())
                .map(|result| (result.disposition, result.snapshot))
                .map_err(|error| error.to_string());
        }

        let clear_gap_after_apply = if matches!(parsed.command, StreamControl::Resume) {
            if let Some(gap) = &self.gap {
                gap.validate_resume(parsed)?;
                true
            } else {
                if parsed.resumed_through_cursor.is_some() || !parsed.resumed_cursors.is_empty() {
                    return Err(
                        "resumed_through_cursor is valid only after stream.resync_required"
                            .to_string(),
                    );
                }
                false
            }
        } else {
            if parsed.resumed_through_cursor.is_some() || !parsed.resumed_cursors.is_empty() {
                return Err("resumed_through_cursor is accepted only by stream.resume".to_string());
            }
            false
        };
        let result = window
            .apply_control(parsed.control_seq, parsed.command.clone())
            .map_err(|error| error.to_string())?;
        if result.disposition == ApplyDisposition::Applied {
            if let Some(window) = candidate_window {
                self.window = Some(window);
            }
            if self.control_fingerprints.len() == self.control_history {
                self.control_fingerprints.pop_front();
            }
            self.control_fingerprints
                .push_back((parsed.control_seq, parsed.request_fingerprint.clone()));
            if clear_gap_after_apply {
                self.gap = None;
            }
        }
        Ok((result.disposition, result.snapshot))
    }
}
