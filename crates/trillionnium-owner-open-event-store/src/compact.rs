//! Segmented-only authenticated read model. WAL/public record schemas do not change.
use super::*;

/// One immutable full-content scope allocation is shared by this map and every
/// authenticated header in its turn. Event IDs share their Arc allocation
/// between this map and the header; locations are stored only in the header.
#[derive(Debug, Default)]
pub(crate) struct ScopeIndex {
    pub(crate) by_event: HashMap<Arc<str>, usize>,
    pub(crate) records: Vec<usize>,
}

impl ScopeIndex {
    pub(crate) fn reserve_event(&mut self) -> Result<()> {
        self.by_event
            .try_reserve(1)
            .map_err(|_| EventStoreError::CapacityExhausted)?;
        self.records
            .try_reserve(1)
            .map_err(|_| EventStoreError::CapacityExhausted)
    }
}

pub(crate) fn next_sequence(scope: Option<&ScopeIndex>, headers: &[Header]) -> Result<u64> {
    match scope {
        None => Ok(0),
        // An admitted scope is never empty. Do not guess its first sequence
        // when an internal index is inconsistent.
        Some(scope) if scope.records.is_empty() => Err(EventStoreError::StatePoisoned),
        Some(scope) => {
            let last = headers
                .get(*scope.records.last().ok_or(EventStoreError::StatePoisoned)?)
                .ok_or(EventStoreError::StatePoisoned)?;
            let next = last
                .turn_seq
                .checked_add(1)
                .ok_or(EventStoreError::CapacityExhausted)?;
            if next
                != u64::try_from(scope.records.len())
                    .map_err(|_| EventStoreError::CapacityExhausted)?
            {
                return Err(EventStoreError::StatePoisoned);
            }
            Ok(next)
        }
    }
}

#[derive(Debug)]
pub(crate) struct Header {
    pub(crate) store_seq: u64,
    pub(crate) turn_seq: u64,
    pub(crate) scope: Arc<TurnScope>,
    pub(crate) event_id: Arc<str>,
    kind: Box<str>,
    payload_sha256: [u8; 32],
    previous_record_sha256: [u8; 32],
    record_sha256: [u8; 32],
    pub(crate) location: SegmentLocation,
    pub(crate) working_bytes: usize,
}

/// Field order keeps all owned header allocations alive under their credit
/// until drop. A pre-write error must not release credit before those Arcs.
#[derive(Debug)]
pub(crate) struct ReservedHeader {
    pub(crate) header: Header,
    pub(crate) credit: resources::ResidentLease,
}

impl Header {
    /// The caller acquires the complete compact reservation before any of
    /// these resident allocations. `scope` is a previously admitted Arc or
    /// the one new full-content scope charged by that reservation.
    pub(crate) fn new(
        record: &EventRecord,
        scope: Arc<TurnScope>,
        working_bytes: usize,
    ) -> Result<Self> {
        Ok(Self {
            store_seq: record.store_seq,
            turn_seq: record.turn_seq,
            scope,
            event_id: Arc::from(record.event_id.as_str()),
            kind: record.kind.as_str().into(),
            payload_sha256: digest(&record.payload_sha256)?,
            previous_record_sha256: digest(&record.previous_record_sha256)?,
            record_sha256: digest(&record.record_sha256)?,
            location: SegmentLocation {
                segment_id: 0,
                offset: 0,
                byte_len: 0,
                store_seq: record.store_seq,
            },
            working_bytes,
        })
    }

    /// Match all authenticated fields, including the full scope and three
    /// exact SHA-256 values. A header never substitutes for payload validation.
    pub(crate) fn matches(&self, record: &EventRecord) -> Result<bool> {
        Ok(record.schema == EVENT_RECORD_SCHEMA
            && self.store_seq == record.store_seq
            && self.turn_seq == record.turn_seq
            && self.scope.as_ref() == &record.scope
            && self.event_id.as_ref() == record.event_id
            && self.kind.as_ref() == record.kind
            && self.payload_sha256 == digest(&record.payload_sha256)?
            && self.previous_record_sha256 == digest(&record.previous_record_sha256)?
            && self.record_sha256 == digest(&record.record_sha256)?)
    }

    pub(crate) fn record_digest(&self) -> String {
        let mut out = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in self.record_sha256 {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
        out
    }
}

fn digest(raw: &str) -> Result<[u8; 32]> {
    require_sha256(raw, "compact authenticated digest")?;
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("require_sha256 admits lowercase hexadecimal only"),
    };
    let mut value = [0_u8; 32];
    for (slot, pair) in value.iter_mut().zip(raw.as_bytes().as_chunks::<2>().0) {
        *slot = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, SegmentedEventStore) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = SegmentedEventStore::open(
            directory.path().join("wal"),
            SegmentedEventStoreConfig {
                sync_policy: SyncPolicy::None,
                ..SegmentedEventStoreConfig::default()
            },
        )
        .unwrap();
        (directory, store)
    }

    fn input(scope: TurnScope, event_id: &str) -> EventInput {
        EventInput {
            scope,
            event_id: event_id.into(),
            kind: "observation".into(),
            payload: serde_json::json!({"ordinary": true}),
        }
    }

    #[test]
    fn full_scope_identity_is_shared_without_aliasing_another_turn() {
        let (_directory, store) = store();
        let a = TurnScope::new("session", "profile", "task", "turn", "stream-a");
        let b = TurnScope::new("session", "profile", "task", "turn", "stream-b");
        let first = store.append(input(a.clone(), "same-id")).unwrap().record;
        store.append(input(a.clone(), "next-id")).unwrap();
        let other = store.append(input(b.clone(), "same-id")).unwrap().record;
        assert_eq!((first.turn_seq, other.turn_seq), (0, 0));
        assert_eq!(store.get(&a, "same-id").unwrap(), Some(first));
        assert_eq!(store.get(&b, "same-id").unwrap(), Some(other));
        assert_eq!(
            store
                .append(input(a.clone(), "same-id"))
                .unwrap()
                .disposition,
            AppendDisposition::Existing
        );
        let state = store.read_state().unwrap();
        let a_arc = state.by_scope.get_key_value(&a).unwrap().0;
        assert!(Arc::ptr_eq(a_arc, &state.records[0].scope));
        assert!(Arc::ptr_eq(a_arc, &state.records[1].scope));
        assert!(!Arc::ptr_eq(a_arc, &state.records[2].scope));
        let event_arc = state
            .by_scope
            .get(&a)
            .unwrap()
            .by_event
            .get_key_value("same-id")
            .unwrap()
            .0;
        assert!(Arc::ptr_eq(event_arc, &state.records[0].event_id));
    }

    #[test]
    fn compact_match_rejects_every_authenticated_field_change() {
        let (_directory, store) = store();
        let record = store
            .append(input(TurnScope::new("s", "p", "t", "u", "v"), "event"))
            .unwrap()
            .record;
        let state = store.read_state().unwrap();
        let header = &state.records[0];
        assert!(header.matches(&record).unwrap());
        let mut changed = Vec::new();
        let mut r = record.clone();
        r.schema.push('x');
        changed.push(r);
        let mut r = record.clone();
        r.store_seq += 1;
        changed.push(r);
        let mut r = record.clone();
        r.turn_seq += 1;
        changed.push(r);
        let mut r = record.clone();
        r.scope.turn_stream_id.push('x');
        changed.push(r);
        let mut r = record.clone();
        r.event_id.push('x');
        changed.push(r);
        let mut r = record.clone();
        r.kind.push('x');
        changed.push(r);
        let mut r = record.clone();
        r.payload_sha256 = "0".repeat(64);
        changed.push(r);
        let mut r = record.clone();
        r.previous_record_sha256 = "1".repeat(64);
        changed.push(r);
        let mut r = record.clone();
        r.record_sha256 = "0".repeat(64);
        changed.push(r);
        for r in changed {
            assert!(!header.matches(&r).unwrap());
        }
        let mut r = record;
        r.record_sha256 = "A".repeat(64);
        assert!(matches!(
            header.matches(&r),
            Err(EventStoreError::InvalidRecord(_))
        ));
    }

    #[test]
    fn next_sequence_refuses_empty_broken_or_overflowed_scope() {
        assert_eq!(next_sequence(None, &[]).unwrap(), 0);
        assert!(matches!(
            next_sequence(Some(&ScopeIndex::default()), &[]),
            Err(EventStoreError::StatePoisoned)
        ));
        let (_directory, store) = store();
        let scope = TurnScope::new("s", "p", "t", "u", "v");
        store.append(input(scope.clone(), "event")).unwrap();
        let mut state = store.write_state().unwrap();
        assert_eq!(
            next_sequence(state.by_scope.get(&scope), &state.records).unwrap(),
            1
        );
        state.records[0].turn_seq = 7;
        assert!(matches!(
            next_sequence(state.by_scope.get(&scope), &state.records),
            Err(EventStoreError::StatePoisoned)
        ));
        state.records[0].turn_seq = u64::MAX;
        assert!(matches!(
            next_sequence(state.by_scope.get(&scope), &state.records),
            Err(EventStoreError::CapacityExhausted)
        ));
    }

    #[test]
    fn public_record_does_not_export_internal_arcs() {
        let (_directory, store) = store();
        let scope = TurnScope::new("s", "p", "t", "u", "v");
        store.append(input(scope.clone(), "event")).unwrap();
        let before = {
            let state = store.read_state().unwrap();
            (
                Arc::strong_count(&state.records[0].scope),
                Arc::strong_count(&state.records[0].event_id),
            )
        };
        let mut public = store.get(&scope, "event").unwrap().unwrap();
        let clones = [public.clone(), public.clone()];
        public.scope.turn_id.push('x');
        public.event_id.push('x');
        let state = store.read_state().unwrap();
        assert_eq!(
            before,
            (
                Arc::strong_count(&state.records[0].scope),
                Arc::strong_count(&state.records[0].event_id)
            )
        );
        assert_eq!(state.records[0].scope.turn_id, "u");
        assert_eq!(clones.len(), 2);
    }

    #[test]
    fn authenticated_header_mismatch_still_poisoned_public_read() {
        let (_directory, store) = store();
        let scope = TurnScope::new("s", "p", "t", "u", "v");
        store.append(input(scope.clone(), "event")).unwrap();
        let path = store.segment_paths().unwrap().remove(0);
        let before = std::fs::read(&path).unwrap();
        store.write_state().unwrap().records[0].kind = "other".into();
        assert!(matches!(
            store.get(&scope, "event"),
            Err(EventStoreError::EventConflict)
        ));
        assert!(matches!(store.snapshot(), Err(EventStoreError::Poisoned)));
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
}
