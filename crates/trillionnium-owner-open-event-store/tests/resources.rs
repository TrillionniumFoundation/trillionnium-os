use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt};
use trillionnium_owner_open_event_store::{
    AppendDisposition, DurableEventStore, EventInput, EventStoreError, EventStoreLimits,
    MAX_EVENT_RESIDENT_BYTES, SegmentedEventStore, SegmentedEventStoreConfig, SyncPolicy,
    TurnScope,
};

fn input(id: &str, payload: serde_json::Value) -> EventInput {
    EventInput {
        scope: TurnScope::new("s", "p", "t", "turn", "stream"),
        event_id: id.into(),
        kind: "fixture".into(),
        payload,
    }
}
fn secure_dir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn dense_json_is_rejected_before_either_wal_changes_and_identity_remains() {
    let directory = secure_dir();
    let v1 = DurableEventStore::open(
        directory.path().join("legacy"),
        EventStoreLimits::default(),
        SyncPolicy::Data,
    )
    .unwrap();
    let v2 = SegmentedEventStore::open(
        directory.path().join("segments"),
        SegmentedEventStoreConfig::default(),
    )
    .unwrap();
    for store in [&v1 as &dyn TestStore, &v2 as &dyn TestStore] {
        store
            .append(input("accepted-uncertain", json!({"accepted": true})))
            .unwrap();
        let before = store.records().unwrap();
        assert!(matches!(
            store.append(input("too-dense", json!({"bytes": vec![0u8; 500_000]}))),
            Err(EventStoreError::CapacityExhausted)
        ));
        assert_eq!(store.records().unwrap(), before);
        let object = (0..80_000)
            .map(|index| (format!("k-{index}"), json!(0)))
            .collect::<serde_json::Map<_, _>>();
        assert!(matches!(
            store.append(input("too-many-members", serde_json::Value::Object(object))),
            Err(EventStoreError::CapacityExhausted)
        ));
        assert_eq!(store.records().unwrap(), before);
        assert_eq!(
            store
                .append(input("accepted-uncertain", json!({"accepted": true})))
                .unwrap()
                .disposition,
            AppendDisposition::Existing
        );
        assert!(matches!(
            store.append(input("accepted-uncertain", json!({"accepted": false}))),
            Err(EventStoreError::EventConflict)
        ));
    }
}

trait TestStore {
    fn append(
        &self,
        input: EventInput,
    ) -> trillionnium_owner_open_event_store::Result<
        trillionnium_owner_open_event_store::AppendResult,
    >;
    fn records(
        &self,
    ) -> trillionnium_owner_open_event_store::Result<
        Vec<trillionnium_owner_open_event_store::EventRecord>,
    >;
}
impl TestStore for DurableEventStore {
    fn append(
        &self,
        input: EventInput,
    ) -> trillionnium_owner_open_event_store::Result<
        trillionnium_owner_open_event_store::AppendResult,
    > {
        self.append(input)
    }
    fn records(
        &self,
    ) -> trillionnium_owner_open_event_store::Result<
        Vec<trillionnium_owner_open_event_store::EventRecord>,
    > {
        self.all_records()
    }
}
impl TestStore for SegmentedEventStore {
    fn append(
        &self,
        input: EventInput,
    ) -> trillionnium_owner_open_event_store::Result<
        trillionnium_owner_open_event_store::AppendResult,
    > {
        self.append(input)
    }
    fn records(
        &self,
    ) -> trillionnium_owner_open_event_store::Result<
        Vec<trillionnium_owner_open_event_store::EventRecord>,
    > {
        self.all_records()
    }
}

#[test]
fn on_demand_history_survives_restart_and_full_vec_is_rejected_before_allocation() {
    let directory = secure_dir();
    let root = directory.path().join("store");
    let store = SegmentedEventStore::open(&root, SegmentedEventStoreConfig::default()).unwrap();
    for index in 0..80 {
        store
            .append(input(
                &format!("event-{index}"),
                json!({"value": "x".repeat(512 * 1024)}),
            ))
            .unwrap();
    }
    assert!(store.resident_bytes().unwrap() < 2 * 1024 * 1024);
    assert!(matches!(
        store.all_records(),
        Err(EventStoreError::CapacityExhausted)
    ));
    let mut visited = 0;
    assert_eq!(
        store
            .visit_records(|_| {
                visited += 1;
                Err("stop")
            })
            .unwrap(),
        Err("stop")
    );
    assert_eq!(visited, 1);
    store
        .visit_records(|record| {
            assert_eq!(record.store_seq, visited as u64 - 1);
            visited += 1;
            Ok::<_, ()>(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(visited, 81);
    assert!(matches!(
        store.checkpoint(),
        Err(EventStoreError::CapacityExhausted)
    ));
    store.flush().unwrap();
    drop(store);
    let reopened = SegmentedEventStore::open(&root, SegmentedEventStoreConfig::default()).unwrap();
    assert_eq!(reopened.snapshot().unwrap().record_count, 80);
    assert!(matches!(
        reopened.all_records(),
        Err(EventStoreError::CapacityExhausted)
    ));
    assert_eq!(
        reopened
            .append(input("event-0", json!({"value": "x".repeat(512 * 1024)})))
            .unwrap()
            .disposition,
        AppendDisposition::Existing
    );
    assert_eq!(
        reopened
            .get(&input("unused", json!({})).scope, "event-79")
            .unwrap()
            .unwrap()
            .payload["value"]
            .as_str()
            .unwrap()
            .len(),
        512 * 1024
    );
}

#[test]
fn index_and_long_id_capacity_never_evict_accepted_identity() {
    isolated_fixture("index_long_id_fixture");
}

#[test]
#[ignore = "real linked-module long-identity capacity fixture"]
fn index_long_id_fixture() {
    let directory = secure_dir();
    // Keep genuine resident pressure below the independent sidecar codec
    // ceiling. Compact headers admit more long IDs than the old duplicated
    // model; this test targets shared resident refusal, not sidecar refusal.
    let pressure = DurableEventStore::open(
        directory.path().join("pressure-v1"),
        EventStoreLimits::default(),
        SyncPolicy::None,
    )
    .unwrap();
    for index in 0..12 {
        pressure
            .append(input(
                &format!("pressure-{index}"),
                json!({"value": "x".repeat(512 * 1024)}),
            ))
            .unwrap();
    }
    let root = directory.path().join("store");
    let mut config = SegmentedEventStoreConfig::default();
    config.limits.max_id_bytes = 4096;
    let store = SegmentedEventStore::open(&root, config.clone()).unwrap();
    let make = |index| EventInput {
        scope: TurnScope::new(
            "s".repeat(4096),
            "p".repeat(4096),
            "t".repeat(4096),
            format!("{index:04096}"),
            "a".repeat(4096),
        ),
        event_id: "e".repeat(4096),
        kind: "fixture".into(),
        payload: json!({"accepted": true}),
    };
    let mut accepted = 0;
    let mut last_delta = None;
    for index in 0..1024 {
        let before = store.snapshot().unwrap();
        let resident_before = store.resident_bytes().unwrap();
        match store.append(make(index)) {
            Ok(_) => {
                accepted += 1;
                let delta = store.resident_bytes().unwrap() - resident_before;
                if let Some(previous) = last_delta {
                    assert_eq!(delta, previous);
                }
                last_delta = Some(delta);
            }
            Err(EventStoreError::CapacityExhausted) => {
                assert_eq!(store.snapshot().unwrap(), before);
                let shared = resident_before + pressure.resident_bytes().unwrap();
                let next_credit = last_delta.expect("an accepted measured delta");
                assert!(MAX_EVENT_RESIDENT_BYTES - shared < next_credit);
                println!(
                    "long_id_resident_before={shared} next_credit={next_credit} maximum={MAX_EVENT_RESIDENT_BYTES} accepted={accepted}"
                );
                break;
            }
            Err(error) => panic!("unexpected {error}"),
        }
    }
    assert!((2..1024).contains(&accepted));
    assert!(
        store.resident_bytes().unwrap() + pressure.resident_bytes().unwrap()
            <= MAX_EVENT_RESIDENT_BYTES
    );
    assert_eq!(
        store.append(make(0)).unwrap().disposition,
        AppendDisposition::Existing
    );
    store.flush().unwrap();
    drop(store);
    let reopened = SegmentedEventStore::open(&root, config).unwrap();
    assert_eq!(reopened.snapshot().unwrap().record_count, accepted);
    assert_eq!(
        reopened.append(make(0)).unwrap().disposition,
        AppendDisposition::Existing
    );
}

#[test]
fn dense_array_capacity_accounting_is_stable_after_restart() {
    let directory = secure_dir();
    let root = directory.path().join("store");
    let store = SegmentedEventStore::open(&root, SegmentedEventStoreConfig::default()).unwrap();
    let record = store
        .append(input("dense", json!({"bytes": vec![0u8; 250_000]})))
        .unwrap()
        .record;
    let resident = store.resident_bytes().unwrap();
    store.checkpoint().unwrap();
    drop(store);
    let reopened = SegmentedEventStore::open(&root, SegmentedEventStoreConfig::default()).unwrap();
    assert_eq!(reopened.resident_bytes().unwrap(), resident);
    assert_eq!(reopened.all_records().unwrap(), vec![record]);
}

#[test]
fn spare_input_capacity_is_charged_before_encoding() {
    let directory = secure_dir();
    let store = DurableEventStore::open(
        directory.path().join("store"),
        EventStoreLimits::default(),
        SyncPolicy::None,
    )
    .unwrap();
    let mut value = String::with_capacity(MAX_EVENT_RESIDENT_BYTES);
    value.push('x');
    assert!(matches!(
        store.append(input(
            "spare",
            serde_json::Value::Object(
                [("value".to_string(), serde_json::Value::String(value))]
                    .into_iter()
                    .collect()
            )
        )),
        Err(EventStoreError::CapacityExhausted)
    ));
    assert_eq!(store.snapshot().unwrap().byte_count, 0);
}

#[test]
fn escaped_record_decode_budget_is_checked_before_wal_and_round_trips_near_the_bound() {
    isolated_fixture("escaped_record_fixture");
}

#[test]
#[ignore = "real linked-module large escaped-codec capacity fixture"]
fn escaped_record_fixture() {
    let directory = secure_dir();
    let v1_path = directory.path().join("legacy");
    let v2_root = directory.path().join("segments");
    let v1 =
        DurableEventStore::open(&v1_path, EventStoreLimits::default(), SyncPolicy::None).unwrap();
    let v2 = SegmentedEventStore::open(&v2_root, SegmentedEventStoreConfig::default()).unwrap();
    let segment = v2.segment_paths().unwrap().pop().unwrap();
    for (store, path) in [
        (&v1 as &dyn TestStore, &v1_path),
        (&v2 as &dyn TestStore, &segment),
    ] {
        let before = fs::read(path).unwrap();
        assert!(
            matches!(
                store.append(input(
                    "escaped-too-large",
                    json!({"value": "\u{0001}".repeat(2 * 1024 * 1024)})
                )),
                Err(EventStoreError::CapacityExhausted)
            ),
            "record whose decoding exceeds temporary capacity must not enter the WAL"
        );
        assert_eq!(fs::read(path).unwrap(), before);
        store
            .append(input(
                "escaped-readable",
                json!({"value": "\u{0001}".repeat(1536 * 1024)}),
            ))
            .unwrap();
    }
    let before = fs::read(&segment).unwrap();
    let mut padded = String::with_capacity(12 * 1024 * 1024);
    padded.push_str(&"\u{0001}".repeat(1536 * 1024));
    let payload = serde_json::Value::Object(
        [("value".to_owned(), serde_json::Value::String(padded))]
            .into_iter()
            .collect(),
    );
    assert!(matches!(
        v2.append(input("escaped-readable", payload)),
        Err(EventStoreError::CapacityExhausted)
    ));
    assert_eq!(fs::read(&segment).unwrap(), before);
    assert_eq!(v2.snapshot().unwrap().record_count, 1);
    assert_eq!(
        v2.append(input(
            "escaped-readable",
            json!({"value": "\u{0001}".repeat(1536 * 1024)})
        ))
        .unwrap()
        .disposition,
        AppendDisposition::Existing
    );
    drop(v1);
    drop(v2);
    let reopened =
        DurableEventStore::open(&v1_path, EventStoreLimits::default(), SyncPolicy::None).unwrap();
    assert_eq!(reopened.snapshot().unwrap().record_count, 1);
    drop(reopened);
    let reopened =
        SegmentedEventStore::open(&v2_root, SegmentedEventStoreConfig::default()).unwrap();
    assert_eq!(
        reopened
            .get(&input("unused", json!({})).scope, "escaped-readable")
            .unwrap()
            .unwrap()
            .payload["value"]
            .as_str()
            .unwrap()
            .len(),
        1536 * 1024
    );
}

#[test]
fn on_demand_read_authenticates_same_length_payload_drift_and_poison_is_sticky() {
    let directory = secure_dir();
    let root = directory.path().join("store");
    let store = SegmentedEventStore::open(&root, SegmentedEventStoreConfig::default()).unwrap();
    let request = input("accepted-uncertain", json!({"value": 0}));
    store.append(request.clone()).unwrap();
    let path = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("segment-")
        })
        .unwrap();
    let mut bytes = fs::read(&path).unwrap();
    let target = b"\"value\":0";
    let offset = bytes
        .windows(target.len())
        .position(|window| window == target)
        .unwrap()
        + target.len()
        - 1;
    bytes[offset] = b'9';
    fs::write(path, bytes).unwrap();
    assert!(matches!(
        store.get(&request.scope, &request.event_id),
        Err(EventStoreError::InvalidRecord(_))
    ));
    assert!(matches!(store.snapshot(), Err(EventStoreError::Poisoned)));
    assert!(matches!(
        store.append(input("next", json!({}))),
        Err(EventStoreError::Poisoned)
    ));
}

#[test]
fn same_length_dense_payload_drift_poison_is_sticky() {
    isolated_fixture("same_length_dense_payload_drift_fixture");
}

#[test]
#[ignore = "isolated large-record decode-integrity fixture"]
fn same_length_dense_payload_drift_fixture() {
    // Cover both an encoded+DOM overflow below the lexical scanner's own
    // ceiling and a dense DOM that exceeds that scanner ceiling directly.
    // Dense zeros cost two Value slots plus six encoded/input bytes per
    // element. Target a 40 MiB combined reservation without assuming a
    // 32-byte Value; its lexical estimate stays below the 64 MiB ceiling.
    let elements = (40 * 1024 * 1024) / (2 * std::mem::size_of::<serde_json::Value>() + 6);
    let combined_overflow_bytes = 2 * elements - 1;
    for (string_bytes, duplicate_read) in [
        (combined_overflow_bytes, false),
        (8 * 1024 * 1024 - 1, false),
        (8 * 1024 * 1024 - 1, true),
    ] {
        assert_same_length_dense_payload_drift(string_bytes, duplicate_read);
    }
}

fn assert_same_length_dense_payload_drift(string_bytes: usize, duplicate_read: bool) {
    use std::os::unix::fs::MetadataExt;

    let directory = secure_dir();
    let store = SegmentedEventStore::open(
        directory.path().join("store"),
        SegmentedEventStoreConfig::default(),
    )
    .unwrap();
    let scope = input("unused", json!({})).scope;
    store
        .append(input(
            "accepted",
            json!({"value": "x".repeat(string_bytes)}),
        ))
        .expect("the original sparse record must pass every append budget");
    assert!(store.get(&scope, "accepted").unwrap().is_some());
    let path = store.segment_paths().unwrap().pop().unwrap();
    let metadata = fs::metadata(&path).unwrap();
    let mut bytes = fs::read(&path).unwrap();
    let original = bytes.clone();
    let marker = b"\"value\":";
    let start = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap()
        + marker.len();
    let end = start + string_bytes + 2;
    assert_eq!(bytes[start], b'"');
    assert_eq!(bytes[end - 1], b'"');
    assert!(bytes[start + 1..end - 1].iter().all(|byte| *byte == b'x'));
    // A quoted odd-length string and this array occupy exactly the same
    // bytes. Preserve all stored hashes and metadata; the raw decode budget
    // must reject this drift before building its DOM.
    bytes[start] = b'[';
    bytes[end - 1] = b']';
    for (index, byte) in bytes[start + 1..end - 1].iter_mut().enumerate() {
        *byte = if index % 2 == 0 { b'0' } else { b',' };
    }
    fs::write(&path, &bytes).unwrap();
    let changed = fs::metadata(&path).unwrap();
    assert_eq!(changed.ino(), metadata.ino());
    assert_eq!(changed.len(), metadata.len());

    let error = if duplicate_read {
        // Existing-identity lookup reads the WAL before comparing this small
        // input's payload, so it must classify the same corruption identically.
        store.append(input("accepted", json!({}))).unwrap_err()
    } else {
        store.get(&scope, "accepted").unwrap_err()
    };
    assert!(matches!(
        error,
        EventStoreError::InvalidRecord(message)
            if message.contains("authenticated decode budget")
    ));
    assert!(matches!(store.snapshot(), Err(EventStoreError::Poisoned)));
    assert!(matches!(
        store.append(input("next", json!({}))),
        Err(EventStoreError::Poisoned)
    ));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    // Restoring bytes cannot clear the original handle's sticky poison.
    fs::write(&path, &original).unwrap();
    assert!(matches!(
        store.get(&scope, "accepted"),
        Err(EventStoreError::Poisoned)
    ));
    drop(store);
    let reopened = SegmentedEventStore::open(
        directory.path().join("store"),
        SegmentedEventStoreConfig::default(),
    )
    .unwrap();
    assert!(reopened.get(&scope, "accepted").unwrap().is_some());
}

#[test]
fn retained_duplicate_decode_capacity_refusal_keeps_store_usable() {
    isolated_fixture("retained_duplicate_decode_capacity_fixture");
}

#[test]
#[ignore = "isolated retained-input decode-capacity fixture"]
fn retained_duplicate_decode_capacity_fixture() {
    const STRING_BYTES: usize = 6 * 1024 * 1024 - 1;
    let directory = secure_dir();
    let store = SegmentedEventStore::open(
        directory.path().join("store"),
        SegmentedEventStoreConfig::default(),
    )
    .unwrap();
    let scope = input("unused", json!({})).scope;
    store
        .append(input(
            "accepted",
            json!({"value": "x".repeat(STRING_BYTES)}),
        ))
        .unwrap();
    let path = store.segment_paths().unwrap().pop().unwrap();
    let before = fs::read(&path).unwrap();
    let mut padded = String::with_capacity(15 * 1024 * 1024);
    padded.extend(std::iter::repeat_n('x', STRING_BYTES));
    let payload = serde_json::Value::Object(
        [("value".to_owned(), serde_json::Value::String(padded))]
            .into_iter()
            .collect(),
    );
    // The WAL alone fits its decode budget. Only its overlap with this
    // caller-owned spare capacity exceeds the temporary envelope.
    assert!(matches!(
        store.append(input("accepted", payload)),
        Err(EventStoreError::CapacityExhausted)
    ));
    assert_eq!(store.snapshot().unwrap().record_count, 1);
    assert_eq!(
        store.get(&scope, "accepted").unwrap().unwrap().payload["value"]
            .as_str()
            .unwrap()
            .len(),
        STRING_BYTES
    );
    assert_eq!(
        store
            .append(input(
                "accepted",
                json!({"value": "x".repeat(STRING_BYTES)})
            ))
            .unwrap()
            .disposition,
        AppendDisposition::Existing
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    store.append(input("next", json!({}))).unwrap();
    assert_eq!(store.snapshot().unwrap().record_count, 2);
}

#[test]
fn shared_descriptor_budget_is_retained_until_last_store_owner_drops() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "shared_descriptor_fixture", "--ignored"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
#[test]
#[ignore = "full process descriptor-budget subprocess fixture"]
fn shared_descriptor_fixture() {
    use std::sync::Arc;
    let directory = secure_dir();
    let config = SegmentedEventStoreConfig {
        max_segment_records: 1,
        group_commit_records: 1,
        ..SegmentedEventStoreConfig::default()
    };
    let a =
        Arc::new(SegmentedEventStore::open(directory.path().join("a"), config.clone()).unwrap());
    for index in 0..170 {
        a.append(input(&format!("a-{index}"), json!({"accepted":index})))
            .unwrap();
    }
    let retained = Arc::clone(&a);
    let b = SegmentedEventStore::open(directory.path().join("b"), config.clone()).unwrap();
    for index in 0..54 {
        b.append(input(&format!("b-{index}"), json!({"value":index})))
            .unwrap();
    }
    assert_eq!(
        a.snapshot().unwrap().segment_count + 16 + b.snapshot().unwrap().segment_count + 16,
        256
    );
    let before = b.snapshot().unwrap();
    assert!(matches!(
        b.append(input("no-space", json!({"value":0}))),
        Err(EventStoreError::CapacityExhausted)
    ));
    assert_eq!(before, b.snapshot().unwrap());
    assert!(
        !directory
            .path()
            .join("b/segment-00000000000000000055.jsonl")
            .exists()
    );
    assert!(matches!(
        SegmentedEventStore::open(directory.path().join("c"), config.clone()),
        Err(EventStoreError::CapacityExhausted)
    ));
    assert!(!directory.path().join("c").exists());
    assert!(matches!(
        DurableEventStore::open(
            directory.path().join("legacy"),
            EventStoreLimits::default(),
            SyncPolicy::Data
        ),
        Err(EventStoreError::CapacityExhausted)
    ));
    assert!(!directory.path().join("legacy").exists());
    assert_eq!(
        a.get(&input("a-0", json!(null)).scope, "a-0")
            .unwrap()
            .unwrap()
            .payload,
        json!({"accepted":0})
    );
    assert_eq!(
        a.append(input("a-0", json!({"accepted":0})))
            .unwrap()
            .disposition,
        AppendDisposition::Existing
    );
    drop(a);
    assert!(matches!(
        SegmentedEventStore::open(directory.path().join("c"), config.clone()),
        Err(EventStoreError::CapacityExhausted)
    ));
    drop(retained);
    drop(b);
    let c = SegmentedEventStore::open(directory.path().join("c"), config.clone()).unwrap();
    let reopened = SegmentedEventStore::open(directory.path().join("a"), config).unwrap();
    assert_eq!(
        reopened
            .get(&input("a-0", json!(null)).scope, "a-0")
            .unwrap()
            .unwrap()
            .payload,
        json!({"accepted":0})
    );
    assert_eq!(
        reopened
            .append(input("a-0", json!({"accepted":0})))
            .unwrap()
            .disposition,
        AppendDisposition::Existing
    );
    drop(c);
}

#[test]
fn shared_resident_budget_fences_cross_backend_growth_until_last_owner_drops() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "shared_resident_fixture", "--ignored"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "real linked-module resident-pressure subprocess fixture"]
fn shared_resident_fixture() {
    use std::sync::Arc;
    let directory = secure_dir();
    let a = Arc::new(
        DurableEventStore::open(
            directory.path().join("a"),
            EventStoreLimits::default(),
            SyncPolicy::None,
        )
        .unwrap(),
    );
    for index in 0..20 {
        a.append(input(
            &format!("a-{index}"),
            json!({"value": "x".repeat(512 * 1024)}),
        ))
        .unwrap();
    }
    let retained = Arc::clone(&a);
    let mut config = SegmentedEventStoreConfig::default();
    config.limits.max_id_bytes = 4096;
    let b = SegmentedEventStore::open(directory.path().join("b"), config.clone()).unwrap();
    let make = |index| EventInput {
        scope: TurnScope::new(
            "s".repeat(4096),
            "p".repeat(4096),
            "t".repeat(4096),
            format!("{index:04096}"),
            "a".repeat(4096),
        ),
        event_id: "e".repeat(4096),
        kind: "fixture".into(),
        payload: json!({"accepted": true}),
    };
    let mut accepted = 0;
    let mut last_delta = None;
    for index in 0..1024 {
        let before = b.snapshot().unwrap();
        let resident_before = b.resident_bytes().unwrap();
        let bytes = fs::read(b.segment_paths().unwrap().last().unwrap()).unwrap();
        match b.append(make(index)) {
            Ok(_) => {
                accepted += 1;
                let delta = b.resident_bytes().unwrap() - resident_before;
                if let Some(previous) = last_delta {
                    assert_eq!(delta, previous);
                }
                last_delta = Some(delta);
            }
            Err(EventStoreError::CapacityExhausted) => {
                assert_eq!(b.snapshot().unwrap(), before);
                let shared = resident_before + a.resident_bytes().unwrap();
                let next_credit = last_delta.expect("an accepted measured delta");
                assert!(MAX_EVENT_RESIDENT_BYTES - shared < next_credit);
                println!(
                    "shared_resident_before={shared} next_credit={next_credit} maximum={MAX_EVENT_RESIDENT_BYTES} accepted={accepted}"
                );
                assert_eq!(
                    fs::read(b.segment_paths().unwrap().last().unwrap()).unwrap(),
                    bytes
                );
                break;
            }
            Err(error) => panic!("unexpected {error}"),
        }
    }
    assert!(accepted > 0);
    assert!(
        a.resident_bytes().unwrap() + b.resident_bytes().unwrap() <= MAX_EVENT_RESIDENT_BYTES,
        "legal per-store read models multiplied the shared memory ceiling"
    );
    assert!(matches!(
        DurableEventStore::open(
            directory.path().join("unadmitted-v1"),
            EventStoreLimits::default(),
            SyncPolicy::None
        ),
        Err(EventStoreError::CapacityExhausted)
    ));
    assert!(!directory.path().join("unadmitted-v1").exists());
    assert!(matches!(
        SegmentedEventStore::open(directory.path().join("unadmitted-v2"), config.clone()),
        Err(EventStoreError::CapacityExhausted)
    ));
    assert!(!directory.path().join("unadmitted-v2").exists());
    assert_eq!(
        a.append(input("a-0", json!({"value": "x".repeat(512 * 1024)})))
            .unwrap()
            .disposition,
        AppendDisposition::Existing
    );
    assert_eq!(
        b.append(make(0)).unwrap().disposition,
        AppendDisposition::Existing
    );
    assert!(matches!(
        b.append(make(accepted)),
        Err(EventStoreError::CapacityExhausted)
    ));
    drop(a);
    assert!(matches!(
        b.append(make(accepted)),
        Err(EventStoreError::CapacityExhausted)
    ));
    drop(retained);
    b.append(make(accepted)).unwrap();
    drop(b);
    let reopened = DurableEventStore::open(
        directory.path().join("a"),
        EventStoreLimits::default(),
        SyncPolicy::None,
    )
    .unwrap();
    assert_eq!(reopened.snapshot().unwrap().record_count, 20);
    assert_eq!(
        reopened
            .append(input("a-0", json!({"value": "x".repeat(512 * 1024)})))
            .unwrap()
            .disposition,
        AppendDisposition::Existing
    );
}

fn isolated_fixture(name: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--ignored"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn failed_cross_store_recovery_returns_every_partial_lease_and_preserves_wals() {
    isolated_fixture("partial_recovery_fixture");
}

#[test]
fn migration_and_rollback_stream_histories_without_a_second_full_payload_lineage() {
    isolated_fixture("streaming_migration_fixture");
}

#[test]
#[ignore = "real linked-module large-history migration/export fixture"]
fn streaming_migration_fixture() {
    let directory = secure_dir();
    let path = directory.path().join("legacy");
    let legacy =
        DurableEventStore::open(&path, EventStoreLimits::default(), SyncPolicy::None).unwrap();
    for index in 0..20 {
        legacy
            .append(input(
                &format!("event-{index}"),
                json!({"value": "x".repeat(512 * 1024)}),
            ))
            .unwrap();
    }
    drop(legacy);
    let before = fs::read(&path).unwrap();
    let root = directory.path().join("segments");
    let migrated =
        SegmentedEventStore::migrate_legacy(&path, &root, SegmentedEventStoreConfig::default())
            .expect("valid history must not require retaining another full payload lineage");
    assert_eq!(migrated.snapshot().unwrap().record_count, 20);
    assert_eq!(fs::read(&path).unwrap(), before);
    migrated
        .export_legacy(directory.path().join("rollback"), SyncPolicy::None)
        .unwrap();
    assert_eq!(fs::read(directory.path().join("rollback")).unwrap(), before);
    // Resume/idempotency must not add bytes or abandon either writer fence.
    migrated
        .export_legacy(directory.path().join("rollback"), SyncPolicy::None)
        .unwrap();
    assert_eq!(fs::read(directory.path().join("rollback")).unwrap(), before);
    drop(migrated);
    let migrated =
        SegmentedEventStore::migrate_legacy(&path, &root, SegmentedEventStoreConfig::default())
            .unwrap();
    assert_eq!(
        migrated
            .append(input("event-0", json!({"value": "x".repeat(512 * 1024)})))
            .unwrap()
            .disposition,
        AppendDisposition::Existing
    );
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
#[ignore = "real linked-module partial-recovery pressure fixture"]
fn partial_recovery_fixture() {
    let directory = secure_dir();
    let legacy_path = directory.path().join("history-v1");
    let legacy =
        DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::None)
            .unwrap();
    for index in 0..16 {
        legacy
            .append(input(
                &format!("old-{index}"),
                json!({"value": "x".repeat(512 * 1024)}),
            ))
            .unwrap();
    }
    drop(legacy);
    let legacy_bytes = fs::read(&legacy_path).unwrap();
    let root = directory.path().join("history-v2");
    let mut config = SegmentedEventStoreConfig::default();
    config.limits.max_id_bytes = 4096;
    let history = SegmentedEventStore::open(&root, config.clone()).unwrap();
    let make = |index| EventInput {
        scope: TurnScope::new(
            "s".repeat(4096),
            "p".repeat(4096),
            "t".repeat(4096),
            format!("{index:04096}"),
            "a".repeat(4096),
        ),
        event_id: "e".repeat(4096),
        kind: "fixture".into(),
        payload: json!({"accepted": true}),
    };
    for index in 0..320 {
        history.append(make(index)).unwrap();
    }
    let history_reservation = history.resident_bytes().unwrap();
    history.flush().unwrap();
    let segment = history.segment_paths().unwrap().pop().unwrap();
    drop(history);
    let segment_bytes = fs::read(&segment).unwrap();
    let sidecar_bytes = fs::read(root.join("index.v2.json")).unwrap();
    let blocker = DurableEventStore::open(
        directory.path().join("blocker"),
        EventStoreLimits::default(),
        SyncPolicy::None,
    )
    .unwrap();
    for index in 0..20 {
        blocker
            .append(input(
                &format!("held-{index}"),
                json!({"value": "x".repeat(512 * 1024)}),
            ))
            .unwrap();
    }
    assert!(
        history_reservation + blocker.resident_bytes().unwrap() > MAX_EVENT_RESIDENT_BYTES,
        "fixture must cause genuine shared-pool recovery pressure"
    );
    println!(
        "recovery_history_credit={history_reservation} blocker_credit={} maximum={MAX_EVENT_RESIDENT_BYTES}",
        blocker.resident_bytes().unwrap()
    );
    for _ in 0..3 {
        assert!(matches!(
            DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::None),
            Err(EventStoreError::CapacityExhausted)
        ));
        assert!(matches!(
            SegmentedEventStore::open(&root, config.clone()),
            Err(EventStoreError::CapacityExhausted)
        ));
        assert_eq!(fs::read(&legacy_path).unwrap(), legacy_bytes);
        assert_eq!(fs::read(&segment).unwrap(), segment_bytes);
        assert_eq!(fs::read(root.join("index.v2.json")).unwrap(), sidecar_bytes);
        assert_eq!(
            blocker
                .append(input("held-0", json!({"value": "x".repeat(512 * 1024)})))
                .unwrap()
                .disposition,
            AppendDisposition::Existing
        );
    }
    drop(blocker);
    let recovered =
        DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::None)
            .unwrap();
    assert_eq!(recovered.snapshot().unwrap().record_count, 16);
    drop(recovered);
    let recovered = SegmentedEventStore::open(&root, config).unwrap();
    assert_eq!(recovered.snapshot().unwrap().record_count, 320);
    assert_eq!(
        recovered.append(make(0)).unwrap().disposition,
        AppendDisposition::Existing
    );
}

#[test]
fn queued_owned_inputs_share_capacity_before_waiting_for_the_codec_lane() {
    isolated_fixture("queued_input_fixture");
}

#[test]
#[ignore = "real linked-module pending-input capacity fixture"]
fn queued_input_fixture() {
    use std::{
        sync::{Arc, mpsc},
        time::Duration,
    };
    let directory = secure_dir();
    let store = Arc::new(
        SegmentedEventStore::open(
            directory.path().join("store"),
            SegmentedEventStoreConfig::default(),
        )
        .unwrap(),
    );
    store
        .append(input("accepted", json!({"value": 0})))
        .unwrap();
    let (entered_send, entered_receive) = mpsc::channel();
    let (release_send, release_receive) = mpsc::channel();
    let reader = Arc::clone(&store);
    let held = std::thread::spawn(move || {
        reader
            .visit_records(|_| {
                entered_send.send(()).unwrap();
                release_receive
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
                Ok::<_, ()>(())
            })
            .unwrap()
            .unwrap()
    });
    entered_receive
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    let (rejected_send, rejected_receive) = mpsc::channel();
    let threads = (0..12)
        .map(|index| {
            let store = Arc::clone(&store);
            let rejected = rejected_send.clone();
            std::thread::spawn(move || {
                let mut text = String::with_capacity(4 * 1024 * 1024);
                text.push('x');
                let payload = serde_json::Value::Object(
                    [("value".to_owned(), serde_json::Value::String(text))]
                        .into_iter()
                        .collect(),
                );
                let result = store.append(input(&format!("queued-{index}"), payload));
                match result {
                    Ok(record) => {
                        drop(record);
                        true
                    }
                    Err(EventStoreError::CapacityExhausted) => {
                        rejected.send(()).unwrap();
                        false
                    }
                    Err(error) => panic!("unexpected {error}"),
                }
            })
        })
        .collect::<Vec<_>>();
    // Rejection must happen while another callback owns the temporary lane;
    // waiting threads therefore cannot hold arbitrary uncharged spare input.
    rejected_receive
        .recv_timeout(Duration::from_secs(5))
        .expect("shared pending-input pressure was not enforced");
    release_send.send(()).unwrap();
    held.join().unwrap();
    let accepted = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(|accepted| *accepted)
        .count();
    assert!(accepted > 0 && accepted < 12);
    assert_eq!(store.snapshot().unwrap().record_count, accepted + 1);
    assert_eq!(
        store
            .append(input("accepted", json!({"value": 0})))
            .unwrap()
            .disposition,
        AppendDisposition::Existing
    );
}

#[test]
fn scoped_visits_filter_sequence_and_keep_full_chain_recovery_required() {
    let directory = secure_dir();
    let root = directory.path().join("store");
    let store = SegmentedEventStore::open(&root, SegmentedEventStoreConfig::default()).unwrap();
    let a = input("a-0", json!({"value": 0}));
    let mut b = input("b-0", json!({"value": 1}));
    b.scope.turn_id = "other".into();
    store.append(a.clone()).unwrap();
    store.append(b.clone()).unwrap();
    store.append(input("a-1", json!({"value": 2}))).unwrap();
    let mut visited = Vec::new();
    store
        .visit_scope_records(&a.scope, 1, |record| {
            visited.push(record.event_id.clone());
            Ok::<_, ()>(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(visited, ["a-1"]);
    assert_eq!(
        store
            .visit_scope_records(&a.scope, 0, |_| Err("stop"))
            .unwrap(),
        Err("stop")
    );
    let path = store.segment_paths().unwrap().pop().unwrap();
    let mut bytes = fs::read(&path).unwrap();
    let token = b"\"value\":1";
    let position = bytes
        .windows(token.len())
        .position(|window| window == token)
        .unwrap()
        + token.len()
        - 1;
    bytes[position] = b'9';
    fs::write(&path, bytes).unwrap();
    // No unrelated payload decode on this scoped inspection. The selected
    // records still authenticate freshly against the startup headers.
    store
        .visit_scope_records(&a.scope, 0, |_| Ok::<_, ()>(()))
        .unwrap()
        .unwrap();
    assert!(matches!(
        store.visit_scope_records(&b.scope, 0, |_| Ok::<_, ()>(())),
        Err(EventStoreError::InvalidRecord(_))
    ));
    assert!(matches!(
        store.visit_scope_records(&a.scope, 0, |_| Ok::<_, ()>(())),
        Err(EventStoreError::Poisoned)
    ));
    drop(store);
    assert!(matches!(
        SegmentedEventStore::open(&root, SegmentedEventStoreConfig::default()),
        Err(EventStoreError::InvalidRecord(_))
    ));
    let legacy = DurableEventStore::open(
        directory.path().join("v1"),
        EventStoreLimits::default(),
        SyncPolicy::None,
    )
    .unwrap();
    legacy.append(a.clone()).unwrap();
    legacy.append(b).unwrap();
    legacy.append(input("a-1", json!({"value": 2}))).unwrap();
    let mut visited = Vec::new();
    legacy
        .visit_scope_records(&a.scope, 1, |record| {
            visited.push(record.event_id.clone());
            Ok::<_, ()>(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(visited, ["a-1"]);
}

#[test]
fn callback_reentry_refuses_and_unwind_releases_the_shared_working_lane() {
    let directory = secure_dir();
    let a = SegmentedEventStore::open(
        directory.path().join("a"),
        SegmentedEventStoreConfig::default(),
    )
    .unwrap();
    let b = DurableEventStore::open(
        directory.path().join("b"),
        EventStoreLimits::default(),
        SyncPolicy::None,
    )
    .unwrap();
    a.append(input("a-0", json!({"value": 0}))).unwrap();
    a.visit_records(|_| {
        assert!(matches!(
            b.all_records(),
            Err(EventStoreError::CapacityExhausted)
        ));
        Err("exit callback")
    })
    .unwrap()
    .unwrap_err();
    b.append(input("b-0", json!({"value": 0}))).unwrap();
    assert!(
        std::panic::catch_unwind(|| {
            let _ = a.visit_records::<()>(|_| panic!("fixture callback unwind"));
        })
        .is_err()
    );
    b.append(input("b-1", json!({"value": 1}))).unwrap();
    assert_eq!(b.snapshot().unwrap().record_count, 2);
}
