use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use trillionnium_owner_open_event_store::{
    DurableEventStore, EventInput, EventStoreError, EventStoreLimits, RecoveryPolicy,
    SegmentedEventStore, SegmentedEventStoreConfig, SyncPolicy, TurnScope,
};

fn secure_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
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

fn input(turn: &str, event_id: &str, value: i64) -> EventInput {
    EventInput {
        scope: scope(turn),
        event_id: event_id.to_string(),
        kind: "observation".to_string(),
        payload: json!({"value": value}),
    }
}

fn config() -> SegmentedEventStoreConfig {
    SegmentedEventStoreConfig {
        limits: EventStoreLimits {
            max_store_bytes: 1024 * 1024,
            max_record_bytes: 4096,
            max_records: 10_000,
            ..EventStoreLimits::default()
        },
        max_segment_bytes: 600,
        max_segment_records: 2,
        group_commit_records: 64,
        group_commit_bytes: 1024 * 1024,
        group_commit_interval: Duration::from_secs(3600),
        sync_policy: SyncPolicy::Data,
        recovery: RecoveryPolicy::Strict,
    }
}

fn rewrite_json(path: &std::path::Path, mutate: impl FnOnce(&mut Value)) {
    let bytes = fs::read(path).unwrap();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    mutate(&mut value);
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

#[test]
fn segmented_store_rotates_and_indexes_replay() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let store = SegmentedEventStore::open(&root, config()).unwrap();
    for value in 0..7 {
        store
            .append(input("turn-a", &format!("event-{value}"), value))
            .unwrap();
    }
    store.flush().unwrap();

    let snapshot = store.snapshot().unwrap();
    assert!(snapshot.segment_count >= 3);
    assert_eq!(snapshot.record_count, 7);
    assert_eq!(snapshot.indexed_count, 7);
    assert!(store.index_path().is_file());
    let location = store
        .location(&scope("turn-a"), "event-5")
        .unwrap()
        .unwrap();
    assert!(location.segment_id >= 1);
    assert!(location.byte_len > 0);
    let replay = store.replay(&scope("turn-a"), 4).unwrap();
    assert_eq!(replay.len(), 3);
    assert_eq!(replay[0].event_id, "event-4");
}

#[test]
fn recovery_prunes_an_orphaned_empty_rotation_tail() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let store = SegmentedEventStore::open(&root, config()).unwrap();
    store.append(input("turn-a", "event-0", 70)).unwrap();
    store.flush().unwrap();
    drop(store);

    // Model a process cut immediately after rotation publishes the next
    // segment pathname but before its first record reaches the WAL.
    let orphan = root.join("segment-00000000000000000002.jsonl");
    let orphan_tail = root.join("segment-00000000000000000003.jsonl");
    for path in [&orphan, &orphan_tail] {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
    }

    let reopened = SegmentedEventStore::open(&root, config()).unwrap();
    assert_eq!(reopened.snapshot().unwrap().segment_count, 1);
    assert_eq!(reopened.all_records().unwrap().len(), 1);
    assert!(!orphan.exists());
    assert!(!orphan_tail.exists());

    // The next real rotation still creates a non-empty segment and keeps the
    // sequence contiguous after the orphan is removed.
    reopened.append(input("turn-a", "event-1", 71)).unwrap();
    reopened.append(input("turn-a", "event-2", 72)).unwrap();
    let paths = reopened.segment_paths().unwrap();
    assert!(paths.iter().any(|path| {
        path.file_name()
            .is_some_and(|name| name == "segment-00000000000000000002.jsonl")
    }));
    assert!(fs::metadata(&orphan).unwrap().len() > 0);
}

#[test]
fn a_present_index_sidecar_is_parsed_and_checked_against_the_wal() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let store = SegmentedEventStore::open(&root, config()).unwrap();
    store.append(input("turn-a", "event-0", 1)).unwrap();
    store.flush().unwrap();
    drop(store);

    rewrite_json(&root.join("index.v2.json"), |value| {
        value["entries"][0]["location"]["offset"] = json!(999_999_u64);
    });
    let error = SegmentedEventStore::open(&root, config()).unwrap_err();
    assert!(
        matches!(error, EventStoreError::InvalidRecord(message) if message.contains("event index"))
    );
}

#[test]
fn a_present_snapshot_sidecar_is_parsed_and_checked_against_the_wal() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let store = SegmentedEventStore::open(&root, config()).unwrap();
    store.append(input("turn-a", "event-0", 2)).unwrap();
    store.checkpoint().unwrap();
    drop(store);

    rewrite_json(&root.join("snapshot.v2.json"), |value| {
        value["last_record_sha256"] = json!("f".repeat(64));
    });
    let error = SegmentedEventStore::open(&root, config()).unwrap_err();
    assert!(
        matches!(error, EventStoreError::InvalidRecord(message) if message.contains("event snapshot"))
    );
}

#[test]
fn stale_sidecars_are_accepted_only_as_a_valid_wal_prefix() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let store = SegmentedEventStore::open(&root, config()).unwrap();
    store.append(input("turn-a", "event-0", 3)).unwrap();
    store.flush().unwrap();
    // The second record is visible in the WAL but the derived index still
    // describes the first-record high-water prefix.
    store.append(input("turn-a", "event-1", 4)).unwrap();
    drop(store);

    let reopened = SegmentedEventStore::open(&root, config()).unwrap();
    assert_eq!(reopened.snapshot().unwrap().record_count, 2);
    assert_eq!(reopened.snapshot().unwrap().indexed_count, 2);
}

#[test]
fn segmented_store_has_one_process_writer_lease() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let first = SegmentedEventStore::open(&root, config()).unwrap();
    let error = SegmentedEventStore::open(&root, config()).unwrap_err();
    assert!(matches!(error, EventStoreError::WriterBusy));
    drop(first);
    SegmentedEventStore::open(&root, config()).unwrap();
}

#[test]
fn group_commit_keeps_a_bounded_pending_batch_and_flushes_it() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let mut store_config = config();
    store_config.max_segment_records = 100;
    store_config.max_segment_bytes = 1024 * 1024;
    store_config.group_commit_records = 3;
    let store = SegmentedEventStore::open(&root, store_config).unwrap();

    store.append(input("turn-a", "event-0", 0)).unwrap();
    store.append(input("turn-a", "event-1", 1)).unwrap();
    assert_eq!(store.pending().unwrap().0, 2);
    store.append(input("turn-a", "event-2", 2)).unwrap();
    assert_eq!(store.pending().unwrap(), (0, 0));

    store.append(input("turn-a", "event-3", 3)).unwrap();
    assert_eq!(store.snapshot().unwrap().pending_records, 1);
    store.checkpoint().unwrap();
    assert_eq!(store.snapshot().unwrap().pending_records, 0);
    assert!(store.index_path().is_file());
    assert!(store.snapshot_path().is_file());
}

#[test]
fn append_durable_drains_a_pending_batch_before_returning() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let mut store_config = config();
    store_config.max_segment_records = 100;
    store_config.max_segment_bytes = 1024 * 1024;
    store_config.group_commit_records = 128;
    store_config.group_commit_bytes = 1024 * 1024;
    let store = SegmentedEventStore::open(&root, store_config).unwrap();
    store
        .append_durable(input("turn-a", "event-durable", 99))
        .unwrap();
    assert_eq!(store.pending().unwrap(), (0, 0));
}

#[test]
fn strict_recovery_rejects_partial_but_repair_mode_discards_only_the_suffix() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let store = SegmentedEventStore::open(&root, config()).unwrap();
    store.append(input("turn-a", "event-0", 0)).unwrap();
    store.flush().unwrap();
    let segment = store.segment_paths().unwrap().pop().unwrap();
    drop(store);

    fs::OpenOptions::new()
        .append(true)
        .open(&segment)
        .unwrap()
        .write_all(b"{\"partial\":")
        .unwrap();
    let strict_error = SegmentedEventStore::open(&root, config()).unwrap_err();
    assert!(matches!(
        strict_error,
        trillionnium_owner_open_event_store::EventStoreError::TruncatedRecord
    ));

    let mut repair_config = config();
    repair_config.recovery = RecoveryPolicy::RepairTrailingPartial;
    let repaired = SegmentedEventStore::open(&root, repair_config).unwrap();
    assert_eq!(repaired.snapshot().unwrap().record_count, 1);
    assert_eq!(repaired.all_records().unwrap()[0].event_id, "event-0");
    // The repaired high-water mark is durable and remains valid when the
    // store is reopened under strict recovery semantics.
    drop(repaired);
    let strict_after_repair = SegmentedEventStore::open(&root, config()).unwrap();
    assert_eq!(strict_after_repair.snapshot().unwrap().record_count, 1);
}

#[test]
fn legacy_migration_preserves_the_v1_record_sequence_and_is_idempotent() {
    let directory = secure_tempdir();
    let legacy_path = directory.path().join("events.jsonl");
    let legacy =
        DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::Full)
            .unwrap();
    legacy.append(input("turn-a", "event-0", 10)).unwrap();
    legacy.append(input("turn-a", "event-1", 11)).unwrap();
    let expected = legacy.all_records().unwrap();
    drop(legacy);

    let root = directory.path().join("events-v2");
    let migrated = SegmentedEventStore::migrate_legacy(&legacy_path, &root, config()).unwrap();
    assert_eq!(migrated.all_records().unwrap(), expected);
    migrated.flush().unwrap();
    drop(migrated);

    let migrated_again =
        SegmentedEventStore::migrate_legacy(&legacy_path, &root, config()).unwrap();
    assert_eq!(migrated_again.all_records().unwrap(), expected);
}

#[test]
fn legacy_migration_resumes_a_valid_prefix_after_an_interrupted_copy() {
    let directory = secure_tempdir();
    let legacy_path = directory.path().join("events.jsonl");
    let legacy =
        DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::Full)
            .unwrap();
    legacy.append(input("turn-a", "event-0", 20)).unwrap();
    legacy.append(input("turn-a", "event-1", 21)).unwrap();
    let expected = legacy.all_records().unwrap();
    drop(legacy);

    let root = directory.path().join("events-v2");
    let partial = SegmentedEventStore::open(&root, config()).unwrap();
    partial.append(input("turn-a", "event-0", 20)).unwrap();
    partial.flush().unwrap();
    drop(partial);

    let resumed = SegmentedEventStore::migrate_legacy(&legacy_path, &root, config()).unwrap();
    assert_eq!(resumed.all_records().unwrap(), expected);
}

#[test]
fn rolling_prefix_migration_copies_a_tail_added_after_preflight_snapshot() {
    let directory = secure_tempdir();
    let legacy_path = directory.path().join("events.jsonl");
    let root = directory.path().join("events-v2");

    // Establish a v1 prefix and a partially-created v2 destination, matching
    // the state seen when a rolling upgrade is interrupted after its first
    // copy pass.
    let legacy =
        DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::Full)
            .unwrap();
    legacy.append(input("turn-a", "event-0", 80)).unwrap();
    drop(legacy);
    let partial = SegmentedEventStore::open(&root, config()).unwrap();
    partial.append(input("turn-a", "event-0", 80)).unwrap();
    partial.flush().unwrap();
    drop(partial);

    // Model a legacy writer appending after an earlier source preflight.  The
    // migration helper must take a fresh, fenced source snapshot and copy
    // this tail rather than returning the already-open partial destination.
    let preflight =
        DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::Full)
            .unwrap();
    assert_eq!(preflight.all_records().unwrap().len(), 1);
    drop(preflight);
    let legacy_tail =
        DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::Full)
            .unwrap();
    legacy_tail.append(input("turn-a", "event-1", 81)).unwrap();
    drop(legacy_tail);

    let migrated =
        SegmentedEventStore::open_or_migrate_with_legacy_prefix(&root, &legacy_path, config())
            .unwrap();
    let records = migrated.all_records().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].event_id, "event-1");
    assert_eq!(records[1].payload, json!({"value": 81}));
}

#[test]
fn open_or_migrate_rejects_an_extra_or_divergent_destination_sequence() {
    let directory = secure_tempdir();
    let legacy_path = directory.path().join("events.jsonl");
    let legacy =
        DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::Full)
            .unwrap();
    legacy.append(input("turn-a", "event-0", 50)).unwrap();
    drop(legacy);

    let root = directory.path().join("events-v2");
    let destination = SegmentedEventStore::open(&root, config()).unwrap();
    destination.append(input("turn-a", "event-0", 50)).unwrap();
    destination.append(input("turn-a", "event-1", 51)).unwrap();
    destination.flush().unwrap();
    drop(destination);

    let error = SegmentedEventStore::open_or_migrate(&root, &legacy_path, config()).unwrap_err();
    assert!(matches!(error, EventStoreError::EventConflict));
}

#[test]
fn sidecar_temp_hardlinks_are_rejected_without_truncating_the_target_inode() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let store = SegmentedEventStore::open(&root, config()).unwrap();
    store.append(input("turn-a", "event-0", 60)).unwrap();

    let sentinel = directory.path().join("sentinel");
    fs::write(&sentinel, b"must-survive").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&sentinel, root.join(".index.v2.json.tmp")).unwrap();

    let error = store.flush().unwrap_err();
    assert!(matches!(error, EventStoreError::UnsafePath(_)));
    assert_eq!(fs::read(&sentinel).unwrap(), b"must-survive");
}

#[test]
fn segmented_store_can_export_a_legacy_rollback_view() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let store = SegmentedEventStore::open(&root, config()).unwrap();
    store.append(input("turn-a", "event-0", 30)).unwrap();
    store.append(input("turn-b", "event-0", 31)).unwrap();
    let legacy_path = directory.path().join("rollback.jsonl");
    store.export_legacy(&legacy_path, SyncPolicy::Full).unwrap();

    let legacy =
        DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::Full)
            .unwrap();
    assert_eq!(legacy.all_records().unwrap(), store.all_records().unwrap());
}

#[test]
fn independent_append_callers_share_ordered_hash_chain_and_index() {
    let directory = secure_tempdir();
    let root = directory.path().join("events-v2");
    let store = Arc::new(SegmentedEventStore::open(&root, config()).unwrap());
    let mut workers = Vec::new();
    for worker in 0..4 {
        let store = Arc::clone(&store);
        workers.push(thread::spawn(move || {
            for event in 0..8 {
                store
                    .append(input(
                        &format!("turn-{worker}"),
                        &format!("event-{event}"),
                        i64::from(worker * 100 + event),
                    ))
                    .unwrap();
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    store.flush().unwrap();
    let records = store.all_records().unwrap();
    assert_eq!(records.len(), 32);
    for (expected, record) in records.iter().enumerate() {
        assert_eq!(record.store_seq, expected as u64);
        if expected > 0 {
            assert_eq!(
                record.previous_record_sha256,
                records[expected - 1].record_sha256
            );
        }
        assert!(
            store
                .location(&record.scope, &record.event_id)
                .unwrap()
                .is_some()
        );
    }
}
