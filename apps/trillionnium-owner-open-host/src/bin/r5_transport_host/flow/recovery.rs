impl StreamDelivery {
    /// Credit is not evidence of recovery. Only pages actually returned by the
    /// read-only core inspector can cover a missing cursor range.
    fn observe_inspection(&mut self, frame: &RunTurnFrame) {
        let Some(gap) = self.gap.as_mut() else {
            return;
        };
        let payload = &frame.payload;
        if payload.get("status").and_then(Value::as_str) != Some("found")
            || payload.get("side_effects").and_then(Value::as_bool) != Some(false)
            || payload.get("automatic_redispatch").and_then(Value::as_bool) != Some(false)
        {
            return;
        }
        for range in &mut gap.cursor_ranges {
            if CursorScope::from_frame(frame, Some(&range.cursor_domain)).as_ref()
                != Some(&range.cursor_scope)
            {
                continue;
            }
            let page = match (frame.kind.as_str(), range.cursor_domain.as_str()) {
                ("turn.inspect.result", TRANSPORT_CURSOR_DOMAIN) => {
                    if payload.get("source").and_then(Value::as_str) != Some("durable_event_store")
                    {
                        continue;
                    }
                    let page =
                        inspection_page(payload, "inclusive_cursor", "next_cursor", "frames");
                    if let Some((start, _)) = page
                        && !payload["frames"].as_array().is_some_and(|frames| {
                            frames.iter().enumerate().all(|(offset, frame)| {
                                frame
                                    .get("event_id")
                                    .and_then(Value::as_str)
                                    .and_then(cursor_from_event_id)
                                    == start.checked_add(offset as u64)
                            })
                        })
                    {
                        continue;
                    }
                    page
                }
                ("job.inspect.result", RUNTIME_CURSOR_DOMAIN) => {
                    let inspection = &payload["inspection"];
                    if payload.get("runtime_cursor_domain").and_then(Value::as_str)
                        != Some(RUNTIME_CURSOR_DOMAIN)
                        || inspection.get("resync_required").and_then(Value::as_bool) != Some(false)
                        || !inspection.get("gap").is_some_and(Value::is_null)
                    {
                        continue;
                    }
                    let page = inspection_page(
                        inspection,
                        "inclusive_cursor",
                        "next_cursor",
                        "runtime_events",
                    );
                    // Retention may remove an unobserved prefix. Inspecting a
                    // retained suffix never proves recovery of that prefix.
                    if let Some((start, _)) = page
                        && (inspection
                            .get("oldest_available_cursor")
                            .and_then(Value::as_u64)
                            .is_none_or(|oldest| oldest > start)
                            || !inspection["runtime_events"]
                                .as_array()
                                .is_some_and(|events| {
                                    events.iter().enumerate().all(|(offset, event)| {
                                        event.get("seq").and_then(Value::as_u64)
                                            == start.checked_add(offset as u64)
                                    })
                                }))
                    {
                        continue;
                    }
                    page
                }
                ("job.inspect.result", JOURNAL_CURSOR_DOMAIN) => {
                    if payload.get("durable_cursor_domain").and_then(Value::as_str)
                        != Some(JOURNAL_CURSOR_DOMAIN)
                        || payload["inspection"]
                            .get("event_log_status")
                            .and_then(Value::as_str)
                            != Some("durable")
                    {
                        continue;
                    }
                    let page = inspection_page(
                        payload,
                        "durable_inclusive_cursor",
                        "durable_next_cursor",
                        "durable_records",
                    );
                    if let Some((start, _)) = page
                        && !payload["durable_records"]
                            .as_array()
                            .is_some_and(|records| {
                                records.iter().enumerate().all(|(offset, record)| {
                                    record.get("job_record_seq").and_then(Value::as_u64)
                                        == start.checked_add(offset as u64)
                                })
                            })
                    {
                        continue;
                    }
                    page
                }
                _ => continue,
            };
            if let Some((start, next)) = page {
                let expected = range.inspected_through.unwrap_or(range.first_cursor);
                if start <= expected && next >= expected {
                    range.inspected_through = Some(next.max(expected));
                }
            }
        }
    }
}

fn inspection_page(payload: &Value, start: &str, next: &str, records: &str) -> Option<(u64, u64)> {
    let start = payload.get(start)?.as_u64()?;
    let next = payload.get(next)?.as_u64()?;
    let count = u64::try_from(payload.get(records)?.as_array()?.len()).ok()?;
    (next.checked_sub(start)? == count).then_some((start, next))
}
