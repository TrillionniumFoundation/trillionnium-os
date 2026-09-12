//! Preflight one finite transition, then commit with no fallible operations.
//! No whole-store clone, external I/O, or semantic action occurs under the lock.
use super::*;

fn receipt(
    event_digest: String,
    series_digest: String,
    accepted: bool,
    idempotent_duplicate: bool,
    coverage_complete: bool,
) -> IngestReceipt {
    IngestReceipt {
        accepted,
        idempotent_duplicate,
        event_digest,
        series_digest,
        coverage_complete,
        semantic_authority: false,
        automatic_redispatch: false,
    }
}

fn gap(event: &MetricEvent, kind: CoverageGapKind, expected_sequence: u64) -> CoverageGap {
    CoverageGap {
        schema: COVERAGE_GAP_SCHEMA.to_string(),
        metric: event.metric.clone(),
        module_instance_id: event.module_instance_id.clone(),
        control_epoch: event.control_epoch,
        kind,
        expected_sequence,
        observed_sequence: event.sequence,
    }
}

pub(super) fn ingest(ingestor: &CatalogIngestor, event: MetricEvent) -> Result<IngestReceipt> {
    let definition = ingestor
        .catalog
        .definition(&event.metric)
        .ok_or_else(|| TelemetryError::Invalid("unknown metric event name".into()))?;
    event.validate(definition, &ingestor.dimensions)?;
    let event_digest = event.digest()?;
    let stream_key = StreamKey {
        metric: event.metric.clone(),
        module_instance_id: event.module_instance_id.clone(),
        control_epoch: event.control_epoch,
    };
    // Different producer clocks/epochs must not evict each other's samples.
    let series_bytes = serde_json::to_vec(&(
        &event.module_instance_id,
        event.control_epoch,
        &event.dimensions,
    ))
    .map_err(|error| TelemetryError::Invalid(format!("metric series encode: {error}")))?;
    let series_digest = hex_digest(&series_bytes);
    let series_key = SeriesKey {
        metric: event.metric.clone(),
        dimensions_digest: series_digest.clone(),
    };
    let mut state = ingestor
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
    let last = state.last_events.get(&stream_key);
    if let Some(last) = last
        && event.sequence == last.sequence
    {
        if event_digest != last.digest {
            return invalid("metric event sequence conflicts with retained bytes");
        }
        return Ok(receipt(
            event_digest,
            series_digest,
            false,
            true,
            !state.gaps.iter().any(|item| item.metric == event.metric),
        ));
    }
    if state.last_rejections.get(&stream_key) == Some(&event_digest) {
        return Ok(receipt(event_digest, series_digest, false, true, false));
    }
    let temporal_rejection = last.and_then(|last| {
        if event.sequence < last.sequence {
            Some(CoverageGapKind::LateObservation)
        } else if event.monotonic_ns <= last.monotonic_ns {
            Some(CoverageGapKind::ClockRegression)
        } else {
            None
        }
    });
    if let Some(kind) = temporal_rejection {
        // This is an explicit diagnostic transaction, not a rejected Result
        // that silently changes the store. The receipt reports no sample
        // acceptance. Only already-admitted streams can reach this branch.
        if state.gaps.len() >= ingestor.max_gaps {
            return invalid("metric coverage gap capacity reached");
        }
        let expected = last.map_or(0, |item| item.sequence.saturating_add(1));
        let observation = gap(&event, kind, expected);
        state.gaps.push_back(observation);
        state
            .last_rejections
            .insert(stream_key, event_digest.clone());
        return Ok(receipt(event_digest, series_digest, false, false, false));
    }

    // Admission maps are lifetime bounded, including epoch and instance churn.
    // No entry()/insert()/eviction occurs before every check below succeeds.
    if !state.last_events.contains_key(&stream_key)
        && state.last_events.len() >= ingestor.max_series
    {
        return invalid("metric stream identity capacity reached");
    }
    if !state.latest_epoch.contains_key(&event.module_instance_id)
        && state.latest_epoch.len() >= ingestor.max_series
    {
        return invalid("metric instance identity capacity reached");
    }
    let metric_series = state.series_by_metric.get(&event.metric);
    let is_new_series = metric_series.is_none_or(|set| !set.contains(&series_digest));
    if is_new_series
        && (metric_series.map_or(0, BTreeSet::len) >= definition.cardinality_ceiling as usize
            || state.windows.len() >= ingestor.max_series)
    {
        return invalid("metric series cardinality ceiling reached");
    }
    for (name, value) in &event.dimensions {
        // validate() resolved every key against the immutable allowed catalog.
        let maximum = ingestor.dimensions[name].cardinality_ceiling as usize;
        if state
            .dimension_values
            .get(name)
            .is_some_and(|values| !values.contains(value) && values.len() >= maximum)
        {
            return invalid("metric dimension cardinality ceiling reached");
        }
    }

    let window_ns = definition
        .retention
        .window_seconds
        .checked_mul(1_000_000_000)
        .ok_or_else(|| TelemetryError::Invalid("metric time window overflow".into()))?;
    let sample_limit = ingestor
        .max_samples_per_series
        .min(definition.retention.max_samples as usize);
    let window = state.windows.get(&series_key);
    let cutoff = event.monotonic_ns.saturating_sub(window_ns);
    let expired = window.map_or(0, |window| {
        window
            .iter()
            .take_while(|old| old.monotonic_ns <= cutoff)
            .count()
    });
    let retained = window.map_or(0, VecDeque::len) - expired;
    let capacity_evicted = usize::from(retained >= sample_limit);
    let removed = expired + capacity_evicted;
    let next_dropped = state
        .dropped_by_metric
        .get(&event.metric)
        .copied()
        .unwrap_or(0)
        .checked_add(
            u64::try_from(removed)
                .map_err(|_| TelemetryError::Invalid("metric removed count overflow".into()))?,
        )
        .ok_or_else(|| TelemetryError::Invalid("metric drop count overflow".into()))?;
    let expected = last.map_or(0, |last| last.sequence.saturating_add(1));
    let mut pending_gaps = Vec::with_capacity(4);
    if event.sequence > expected {
        pending_gaps.push(gap(&event, CoverageGapKind::MissingSequence, expected));
    }
    if last.is_some_and(|last| event.monotonic_ns - last.monotonic_ns > window_ns) {
        pending_gaps.push(gap(&event, CoverageGapKind::ClockJump, expected));
    }
    if expired != 0 {
        pending_gaps.push(gap(
            &event,
            CoverageGapKind::TimeWindowEviction,
            event.sequence,
        ));
    }
    if capacity_evicted != 0 {
        pending_gaps.push(gap(&event, CoverageGapKind::WindowEviction, event.sequence));
    }
    if pending_gaps.len() > ingestor.max_gaps - state.gaps.len() {
        return invalid("metric coverage gap capacity reached");
    }
    let coverage_complete =
        pending_gaps.is_empty() && !state.gaps.iter().any(|item| item.metric == event.metric);
    let result = receipt(
        event_digest.clone(),
        series_digest.clone(),
        true,
        false,
        coverage_complete,
    );
    let last_event = LastEvent {
        sequence: event.sequence,
        monotonic_ns: event.monotonic_ns,
        digest: event_digest,
    };

    // Commit: all recoverable failure conditions were checked against this
    // same locked state. Allocator abort/panic is not reported as a clean Err.
    for (name, value) in &event.dimensions {
        state
            .dimension_values
            .entry(name.clone())
            .or_default()
            .insert(value.clone());
    }
    state
        .series_by_metric
        .entry(event.metric.clone())
        .or_default()
        .insert(series_digest);
    let window = state.windows.entry(series_key).or_default();
    for _ in 0..removed {
        window.pop_front();
    }
    window.push_back(event.clone());
    if removed != 0 {
        state
            .dropped_by_metric
            .insert(event.metric.clone(), next_dropped);
    }
    state.gaps.extend(pending_gaps);
    state
        .latest_epoch
        .insert(event.module_instance_id, event.control_epoch);
    state.last_rejections.remove(&stream_key);
    state.last_events.insert(stream_key, last_event);
    Ok(result)
}
