//! Preflight/commit telemetry admission and explicit event-time retention.
use super::*;

impl CatalogIngestor {
    /// Admit one event atomically. Every returned error leaves all retained state
    /// unchanged, including gaps, cardinality, watermarks and duplicate metadata.
    pub fn ingest(&self, event: MetricEvent) -> Result<IngestReceipt> {
        let definition = self
            .catalog
            .definition(&event.metric)
            .ok_or_else(|| TelemetryError::Invalid("unknown metric event name".into()))?;
        event.validate(definition, &self.catalog)?;
        let event_digest = event.digest()?;
        let stream_key = StreamKey {
            metric: event.metric.clone(),
            module_instance_id: event.module_instance_id.clone(),
            control_epoch: event.control_epoch,
        };
        let dimensions_bytes = serde_json::to_vec(&event.dimensions).map_err(|error| {
            TelemetryError::Invalid(format!("metric dimensions encode: {error}"))
        })?;
        let series_digest = hex_digest(&dimensions_bytes);
        let series_key = SeriesKey {
            metric: event.metric.clone(),
            dimensions_digest: series_digest.clone(),
        };
        let window_ns = retention_ns(definition)?;
        let cutoff = event.monotonic_ns.saturating_sub(window_ns);
        let sample_limit = self
            .max_samples_per_series
            .min(definition.retention.max_samples as usize);
        let mut state = self
            .state
            .lock()
            .map_err(|_| TelemetryError::Invalid("catalog ingestor lock poisoned".into()))?;
        if state
            .latest_epoch
            .get(&event.module_instance_id)
            .is_some_and(|epoch| event.control_epoch < *epoch)
        {
            return invalid("metric event control epoch regressed");
        }
        let mut pending_gaps = Vec::new();
        if let Some(last) = state.last_events.get(&stream_key) {
            if event.sequence == last.sequence {
                if event_digest == last.digest {
                    return Ok(IngestReceipt {
                        accepted: false,
                        idempotent_duplicate: true,
                        event_digest,
                        series_digest,
                        coverage_complete: !state.gaps.iter().any(|gap| gap.metric == event.metric),
                        semantic_authority: false,
                        automatic_redispatch: false,
                    });
                }
                return invalid("metric event sequence conflicts with retained bytes");
            }
            if event.sequence < last.sequence {
                return invalid("LATE_OBSERVATION: metric sequence regressed");
            }
            if event.monotonic_ns <= last.monotonic_ns {
                return invalid("CLOCK_REGRESSION: metric monotonic clock did not advance");
            }
            let expected = last.sequence.checked_add(1).ok_or_else(|| {
                TelemetryError::Invalid("metric event sequence exhausted".into())
            })?;
            if event.sequence > expected {
                pending_gaps.push(coverage_gap(
                    &stream_key,
                    CoverageGapKind::MissingSequence,
                    expected,
                    event.sequence,
                ));
            }
            if event.monotonic_ns - last.monotonic_ns > window_ns {
                // A long observation interval, not proof that a hardware clock jumped.
                pending_gaps.push(coverage_gap(
                    &stream_key,
                    CoverageGapKind::ClockJump,
                    expected,
                    event.sequence,
                ));
            }
        }
        if state
            .watermarks
            .get(&stream_key)
            .is_some_and(|watermark| event.monotonic_ns < *watermark)
        {
            return invalid("LATE_OBSERVATION: event precedes the observed watermark");
        }
        if !state.last_events.contains_key(&stream_key)
            && state.last_events.len() >= self.max_series
        {
            return invalid("metric stream metadata capacity reached");
        }
        if !state.latest_epoch.contains_key(&event.module_instance_id)
            && state.latest_epoch.len() >= self.max_series
        {
            return invalid("metric instance metadata capacity reached");
        }
        for (name, value) in &event.dimensions {
            let dimension = self
                .catalog
                .dimension_catalog
                .iter()
                .find(|dimension| dimension.name == *name)
                .ok_or_else(|| TelemetryError::Invalid("unknown metric dimension".into()))?;
            if let Some(values) = state.dimension_values.get(name)
                && !values.contains(value)
                && values.len() >= dimension.cardinality_ceiling as usize
            {
                return invalid("metric dimension cardinality ceiling reached");
            }
        }
        let metric_series = state.series_by_metric.get(&event.metric);
        let is_new_series = metric_series.is_none_or(|series| !series.contains(&series_digest));
        if is_new_series
            && (metric_series.map_or(0, BTreeSet::len) >= definition.cardinality_ceiling as usize
                || state.windows.len() >= self.max_series)
        {
            return invalid("metric series cardinality ceiling reached");
        }
        let expired = expired_samples(&state, &stream_key, cutoff)?;
        let retained_here = state.windows.get(&series_key).map_or(0, |window| {
            window.iter().filter(|sample| !expired_sample(sample, &stream_key, cutoff)).count()
        });
        let count_evicted = retained_here.saturating_add(1).saturating_sub(sample_limit);
        if expired != 0 {
            pending_gaps.push(coverage_gap(
                &stream_key,
                CoverageGapKind::TimeWindowEviction,
                event.sequence,
                event.sequence,
            ));
        }
        if count_evicted != 0 {
            pending_gaps.push(coverage_gap(
                &stream_key,
                CoverageGapKind::WindowEviction,
                event.sequence,
                event.sequence,
            ));
        }
        let dropped = checked_drop_total(&state, &event.metric, expired, count_evicted)?;
        check_gap_capacity(&state, self.max_gaps, pending_gaps.len())?;

        // Commit: no Result-returning operation follows the first mutation.
        // No full-state clone, external I/O or fsync is performed under this lock.
        expire_samples(&mut state, &stream_key, cutoff);
        state
            .series_by_metric
            .entry(event.metric.clone())
            .or_default()
            .insert(series_digest.clone());
        for (name, value) in &event.dimensions {
            state.dimension_values.entry(name.clone()).or_default().insert(value.clone());
        }
        let window = state.windows.entry(series_key).or_default();
        for _ in 0..count_evicted {
            window.pop_front();
        }
        window.push_back(event.clone());
        if expired != 0 || count_evicted != 0 {
            state.dropped_by_metric.insert(event.metric.clone(), dropped);
        }
        state.gaps.extend(pending_gaps);
        state.latest_epoch.insert(event.module_instance_id.clone(), event.control_epoch);
        state.watermarks.insert(stream_key.clone(), event.monotonic_ns);
        state.last_events.insert(
            stream_key,
            LastEvent {
                sequence: event.sequence,
                monotonic_ns: event.monotonic_ns,
                digest: event_digest.clone(),
            },
        );
        Ok(IngestReceipt {
            accepted: true,
            idempotent_duplicate: false,
            event_digest,
            series_digest,
            coverage_complete: !state.gaps.iter().any(|gap| gap.metric == event.metric),
            semantic_authority: false,
            automatic_redispatch: false,
        })
    }

    /// Advance an existing stream's observed monotonic clock, including when it
    /// is idle. The caller supplies a time from that exact instance/epoch domain.
    /// Timer failure must remain unavailable, not an invented complete window.
    pub fn advance_watermark(
        &self,
        metric: &str,
        module_instance_id: &str,
        control_epoch: u64,
        monotonic_ns: u64,
    ) -> Result<()> {
        let definition = self
            .catalog
            .definition(metric)
            .ok_or_else(|| TelemetryError::Invalid("unknown metric watermark name".into()))?;
        let cutoff = monotonic_ns.saturating_sub(retention_ns(definition)?);
        let key = StreamKey {
            metric: metric.to_string(),
            module_instance_id: module_instance_id.to_string(),
            control_epoch,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| TelemetryError::Invalid("catalog ingestor lock poisoned".into()))?;
        let previous = state.watermarks.get(&key).ok_or_else(|| {
            TelemetryError::Invalid("watermark has no admitted stream identity".into())
        })?;
        if monotonic_ns < *previous {
            return invalid("CLOCK_REGRESSION: watermark regressed");
        }
        let expired = expired_samples(&state, &key, cutoff)?;
        let dropped = checked_drop_total(&state, metric, expired, 0)?;
        let gap = if expired != 0 {
            let last = state.last_events.get(&key).ok_or_else(|| {
                TelemetryError::Invalid("watermark stream metadata is absent".into())
            })?;
            check_gap_capacity(&state, self.max_gaps, 1)?;
            Some(coverage_gap(
                &key,
                CoverageGapKind::TimeWindowEviction,
                last.sequence,
                last.sequence,
            ))
        } else {
            None
        };
        expire_samples(&mut state, &key, cutoff);
        state.watermarks.insert(key, monotonic_ns);
        if let Some(gap) = gap {
            state.dropped_by_metric.insert(metric.to_string(), dropped);
            state.gaps.push_back(gap);
        }
        Ok(())
    }
}

fn retention_ns(definition: &MetricDefinition) -> Result<u64> {
    definition.retention.window_seconds.checked_mul(1_000_000_000).ok_or_else(|| {
        TelemetryError::Invalid("metric retention clock overflow".into())
    })
}

fn coverage_gap(
    key: &StreamKey,
    kind: CoverageGapKind,
    expected_sequence: u64,
    observed_sequence: u64,
) -> CoverageGap {
    CoverageGap {
        schema: COVERAGE_GAP_SCHEMA.to_string(),
        metric: key.metric.clone(),
        module_instance_id: key.module_instance_id.clone(),
        control_epoch: key.control_epoch,
        kind,
        expected_sequence,
        observed_sequence,
    }
}

fn expired_sample(sample: &MetricEvent, key: &StreamKey, cutoff: u64) -> bool {
    sample.metric == key.metric
        && sample.module_instance_id == key.module_instance_id
        && sample.control_epoch == key.control_epoch
        && sample.monotonic_ns < cutoff
}

fn expired_samples(state: &IngestState, key: &StreamKey, cutoff: u64) -> Result<usize> {
    state.windows.iter().filter(|(series, _)| series.metric == key.metric).try_fold(
        0usize,
        |total, (_, window)| {
            let count = window.iter().filter(|sample| expired_sample(sample, key, cutoff)).count();
            total.checked_add(count).ok_or_else(|| {
                TelemetryError::Invalid("metric expired sample count overflow".into())
            })
        },
    )
}

fn expire_samples(state: &mut IngestState, key: &StreamKey, cutoff: u64) {
    for (series, window) in &mut state.windows {
        if series.metric == key.metric {
            window.retain(|sample| !expired_sample(sample, key, cutoff));
        }
    }
}

fn checked_drop_total(
    state: &IngestState,
    metric: &str,
    expired: usize,
    evicted: usize,
) -> Result<u64> {
    let delta = expired.checked_add(evicted).and_then(|value| u64::try_from(value).ok());
    delta
        .and_then(|value| state.dropped_by_metric.get(metric).unwrap_or(&0).checked_add(value))
        .ok_or_else(|| TelemetryError::Invalid("metric drop count overflow".into()))
}

fn check_gap_capacity(state: &IngestState, maximum: usize, additional: usize) -> Result<()> {
    if state.gaps.len().checked_add(additional).is_none_or(|size| size > maximum) {
        return invalid("metric coverage gap capacity reached");
    }
    Ok(())
}

