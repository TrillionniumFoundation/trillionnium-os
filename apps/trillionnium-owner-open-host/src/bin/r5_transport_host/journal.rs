#[derive(Debug)]
struct TransportJournal {
    store: Option<DurableEventStore>,
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
        match DurableEventStore::open(&path, EventStoreLimits::default(), SyncPolicy::Full) {
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
        if let Err(error) = store.append(EventInput {
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

fn new_transport_event_prefix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("transport-{}-{nanos}", std::process::id())
}
