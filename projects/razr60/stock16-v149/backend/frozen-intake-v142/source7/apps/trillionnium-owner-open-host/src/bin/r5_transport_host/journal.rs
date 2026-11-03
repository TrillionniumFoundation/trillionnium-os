#[derive(Debug)]
struct TransportJournal {
    // The transport journal follows the v2 segmented layout used by the v7
    // turn and job stores.  The old `.transport` JSONL file is retained only
    // as a migration source; it is never used as the active writer.
    store: Option<SegmentedEventStore>,
    error: Option<String>,
    next_event: u64,
    event_prefix: String,
}

impl TransportJournal {
    fn open(core_event_store: Option<&Path>) -> Self {
        let Some(core_path) = core_event_store else {
            return Self {
                store: None,
                error: None,
                next_event: 0,
                event_prefix: new_transport_event_prefix(),
            };
        };
        let path = transport_journal_path(core_path);
        let root = transport_journal_root(core_path);
        match open_transport_store(&root, &path) {
            Ok(store) => Self {
                store: Some(store),
                error: None,
                next_event: 0,
                event_prefix: new_transport_event_prefix(),
            },
            Err(error) => Self {
                store: None,
                error: Some(error.to_string()),
                next_event: 0,
                event_prefix: new_transport_event_prefix(),
            },
        }
    }

    fn status(&self) -> &'static str {
        match (&self.store, &self.error) {
            (Some(_), _) => "durable",
            (None, Some(_)) => "unavailable",
            (None, None) => "not_configured",
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    fn append(&mut self, context: &TurnContext, kind: &str, payload: Value) {
        let Some(store) = &self.store else {
            return;
        };
        let event_id = format!("{}-{}", self.event_prefix, self.next_event);
        self.next_event = self.next_event.saturating_add(1);
        let scope = DurableTurnScope::new(
            context.session_id.clone(),
            context.profile_id.clone(),
            context.task_id.clone(),
            context.turn_id.clone(),
            context.turn_stream_id.clone(),
        );
        if let Err(error) = store.append_durable(EventInput {
            scope,
            event_id,
            kind: kind.to_string(),
            payload: json!({
                "request_sha256": &context.request_sha256,
                "transport": payload
            }),
        }) {
            self.store = None;
            self.error = Some(error.to_string());
        }
    }
}

fn transport_journal_path(core_path: &Path) -> PathBuf {
    let mut value = core_path.as_os_str().to_os_string();
    value.push(".transport");
    PathBuf::from(value)
}

fn transport_journal_root(core_path: &Path) -> PathBuf {
    let mut value = core_path.as_os_str().to_os_string();
    value.push(".transport.segments");
    PathBuf::from(value)
}

/// Open the segmented transport journal and converge a legacy v1 source when
/// one is present.  The event-store helper fences the source writer across
/// the complete snapshot/copy window.  The legacy file is intentionally
/// allowed to be a stale prefix after the first migrated append: keeping it as
/// a source makes rolling readers possible without reintroducing a second
/// active writer.
fn open_transport_store(
    root: &Path,
    legacy_path: &Path,
) -> trillionnium_owner_open_event_store::Result<SegmentedEventStore> {
    let config = SegmentedEventStoreConfig {
        // Transport delivery records are part of the restart/reconnect
        // boundary, so preserve the historical full-sync guarantee while
        // still using segmented/indexed storage.
        sync_policy: SyncPolicy::Full,
        ..SegmentedEventStoreConfig::default()
    };

    SegmentedEventStore::open_or_migrate_with_legacy_prefix(root, legacy_path, config)
}

fn new_transport_event_prefix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("transport-{}-{nanos}", std::process::id())
}

#[cfg(test)]
mod transport_journal_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn secure_tempdir() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("temporary directory permissions");
        directory
    }

    #[test]
    fn transport_journal_migrates_legacy_and_accepts_a_stale_source_prefix() {
        let directory = secure_tempdir();
        let core_path = directory.path().join("events.jsonl");
        let legacy_path = transport_journal_path(&core_path);
        let legacy =
            DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::Full)
                .expect("legacy transport store");
        let scope = DurableTurnScope::new("session", "profile", "task", "turn", "stream");
        legacy
            .append(EventInput {
                scope,
                event_id: "legacy-event".to_string(),
                kind: "transport.test".to_string(),
                payload: json!({"legacy": true}),
            })
            .expect("legacy event");
        drop(legacy);

        let context = TurnContext {
            session_id: "session".to_string(),
            profile_id: "profile".to_string(),
            task_id: "task".to_string(),
            turn_id: "turn".to_string(),
            turn_stream_id: "stream".to_string(),
            request_sha256: "0".repeat(64),
        };
        let mut journal = TransportJournal::open(Some(&core_path));
        assert_eq!(journal.status(), "durable");
        journal.append(&context, "transport.test", json!({"segmented": true}));
        drop(journal);

        // The legacy source remains a one-record prefix.  Reopening must not
        // mistake the newer segmented tail for a split-brain conflict.
        let reopened = TransportJournal::open(Some(&core_path));
        assert_eq!(reopened.status(), "durable");
        drop(reopened);
        let root = transport_journal_root(&core_path);
        let store = SegmentedEventStore::open(
            root,
            SegmentedEventStoreConfig {
                sync_policy: SyncPolicy::Full,
                ..SegmentedEventStoreConfig::default()
            },
        )
        .expect("segmented transport store");
        assert_eq!(store.all_records().expect("records").len(), 2);
    }
}
