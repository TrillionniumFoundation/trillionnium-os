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
    let directory = secure_dir();
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
    for index in 0..256 {
        match store.append(make(index)) {
            Ok(_) => accepted += 1,
            Err(EventStoreError::CapacityExhausted) => break,
            Err(error) => panic!("unexpected {error}"),
        }
    }
    assert!((2..256).contains(&accepted));
    assert!(store.resident_bytes().unwrap() <= MAX_EVENT_RESIDENT_BYTES);
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
