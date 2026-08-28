use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde_json::json;
use trillionnium_owner_open_event_store::{
    AppendDisposition, DurableEventStore, EventInput, EventStoreError, EventStoreLimits,
    SyncPolicy, TurnScope,
};

fn path(directory: &tempfile::TempDir) -> std::path::PathBuf {
    directory.path().join("events.jsonl")
}

fn scope(turn: &str) -> TurnScope {
    TurnScope::new(
        "session-1",
        "owner-open",
        "task-1",
        turn,
        format!("stream-{turn}"),
    )
}

fn input(turn: &str, event_id: &str, kind: &str, value: i64) -> EventInput {
    EventInput {
        scope: scope(turn),
        event_id: event_id.to_string(),
        kind: kind.to_string(),
        payload: json!({"value": value}),
    }
}

#[test]
fn append_reopen_and_inclusive_replay_preserve_exact_records() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = path(&directory);
    let store = DurableEventStore::open(&store_path, EventStoreLimits::default(), SyncPolicy::Full)
        .unwrap();
    let first = store
        .append(input("turn-a", "event-0", "turn.accepted", 0))
        .unwrap();
    let second = store
        .append(input("turn-a", "event-1", "model.delta", 1))
        .unwrap();
    let other = store
        .append(input("turn-b", "event-0", "turn.accepted", 2))
        .unwrap();
    assert_eq!(first.record.store_seq, 0);
    assert_eq!(first.record.turn_seq, 0);
    assert_eq!(second.record.store_seq, 1);
    assert_eq!(second.record.turn_seq, 1);
    assert_eq!(other.record.store_seq, 2);
    assert_eq!(other.record.turn_seq, 0);
    drop(store);

    let reopened =
        DurableEventStore::open(&store_path, EventStoreLimits::default(), SyncPolicy::Full)
            .unwrap();
    let replay = reopened.replay(&scope("turn-a"), 1).unwrap();
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].event_id, "event-1");
    assert_eq!(reopened.snapshot().unwrap().record_count, 3);
}

#[test]
fn exact_duplicate_is_idempotent_and_drift_conflicts() {
    let directory = tempfile::tempdir().unwrap();
    let store = DurableEventStore::open(
        path(&directory),
        EventStoreLimits::default(),
        SyncPolicy::Data,
    )
    .unwrap();
    let request = input("turn-a", "event-0", "tool.result", 7);
    let first = store.append(request.clone()).unwrap();
    let again = store.append(request).unwrap();
    assert_eq!(first.disposition, AppendDisposition::Appended);
    assert_eq!(again.disposition, AppendDisposition::Existing);
    assert_eq!(again.record.record_sha256, first.record.record_sha256);
    assert_eq!(store.snapshot().unwrap().record_count, 1);

    let error = store
        .append(input("turn-a", "event-0", "tool.result", 8))
        .unwrap_err();
    assert!(matches!(error, EventStoreError::EventConflict));
}

#[test]
fn the_same_event_id_is_independent_in_another_turn_scope() {
    let directory = tempfile::tempdir().unwrap();
    let store = DurableEventStore::open(
        path(&directory),
        EventStoreLimits::default(),
        SyncPolicy::None,
    )
    .unwrap();
    store
        .append(input("turn-a", "event-0", "turn.accepted", 1))
        .unwrap();
    store
        .append(input("turn-b", "event-0", "turn.accepted", 2))
        .unwrap();
    assert_eq!(store.snapshot().unwrap().record_count, 2);
}

#[test]
fn a_second_writer_is_rejected_without_mutating_the_store() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = path(&directory);
    let first = DurableEventStore::open(&store_path, EventStoreLimits::default(), SyncPolicy::Data)
        .unwrap();
    let error = DurableEventStore::open(&store_path, EventStoreLimits::default(), SyncPolicy::Data)
        .unwrap_err();
    assert!(matches!(error, EventStoreError::WriterBusy));
    drop(first);
    DurableEventStore::open(&store_path, EventStoreLimits::default(), SyncPolicy::Data).unwrap();
}

#[test]
fn truncated_or_tampered_records_fail_closed_on_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = path(&directory);
    {
        let store =
            DurableEventStore::open(&store_path, EventStoreLimits::default(), SyncPolicy::Full)
                .unwrap();
        store
            .append(input("turn-a", "event-0", "turn.accepted", 1))
            .unwrap();
    }
    let original = fs::read(&store_path).unwrap();
    fs::write(&store_path, &original[..original.len() - 1]).unwrap();
    let truncated =
        DurableEventStore::open(&store_path, EventStoreLimits::default(), SyncPolicy::Full)
            .unwrap_err();
    assert!(matches!(truncated, EventStoreError::TruncatedRecord));

    fs::write(&store_path, original).unwrap();
    let text = fs::read_to_string(&store_path).unwrap();
    let tampered = text.replace("\"value\":1", "\"value\":2");
    fs::write(&store_path, tampered).unwrap();
    let digest_error =
        DurableEventStore::open(&store_path, EventStoreLimits::default(), SyncPolicy::Full)
            .unwrap_err();
    assert!(matches!(digest_error, EventStoreError::InvalidRecord(_)));
}

#[test]
fn duplicate_json_members_and_unsafe_modes_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let store_path = path(&directory);
    fs::write(&store_path, b"{\"schema\":\"x\",\"schema\":\"y\"}\n").unwrap();
    fs::set_permissions(&store_path, fs::Permissions::from_mode(0o600)).unwrap();
    let duplicate =
        DurableEventStore::open(&store_path, EventStoreLimits::default(), SyncPolicy::None)
            .unwrap_err();
    assert!(matches!(duplicate, EventStoreError::InvalidRecord(_)));

    fs::write(&store_path, b"").unwrap();
    fs::set_permissions(&store_path, fs::Permissions::from_mode(0o644)).unwrap();
    let mode = DurableEventStore::open(&store_path, EventStoreLimits::default(), SyncPolicy::None)
        .unwrap_err();
    assert!(matches!(mode, EventStoreError::UnsafePath(_)));
}

#[test]
fn record_and_store_capacity_are_enforced_before_append() {
    let directory = tempfile::tempdir().unwrap();
    let store = DurableEventStore::open(
        path(&directory),
        EventStoreLimits {
            max_store_bytes: 4096,
            max_record_bytes: 2048,
            max_records: 1,
            ..EventStoreLimits::default()
        },
        SyncPolicy::None,
    )
    .unwrap();
    store
        .append(input("turn-a", "event-0", "turn.accepted", 1))
        .unwrap();
    let error = store
        .append(input("turn-a", "event-1", "model.delta", 2))
        .unwrap_err();
    assert!(matches!(error, EventStoreError::CapacityExhausted));
}
