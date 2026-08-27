use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trillionnium_owner_open_event_store::{
    DurableEventStore, EventInput, EventStoreLimits, SyncPolicy, TurnScope,
};
use trillionnium_owner_open_types::{RunTurnFrame, RunTurnRequest};

#[derive(Debug, Clone)]
pub enum StoredTurn {
    Empty,
    Complete(Vec<RunTurnFrame>),
    Incomplete(Vec<RunTurnFrame>),
    Conflict(String),
}

#[derive(Debug)]
pub struct Persistence {
    store: Option<DurableEventStore>,
    configured: bool,
    error: Option<String>,
}

impl Persistence {
    #[must_use]
    pub fn memory_only() -> Self {
        Self {
            store: None,
            configured: false,
            error: None,
        }
    }

    #[must_use]
    pub fn open_best_effort(path: Option<&Path>) -> Self {
        let Some(path) = path else {
            return Self::memory_only();
        };
        match DurableEventStore::open(path, EventStoreLimits::default(), SyncPolicy::Full) {
            Ok(store) => Self {
                store: Some(store),
                configured: true,
                error: None,
            },
            Err(error) => Self {
                store: None,
                configured: true,
                error: Some(error.to_string()),
            },
        }
    }

    #[must_use]
    pub fn status(&self) -> &'static str {
        match (&self.store, self.configured) {
            (Some(_), _) => "durable",
            (None, true) => "unavailable",
            (None, false) => "best_effort_memory_only",
        }
    }

    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.store.is_some()
    }

    pub fn load(&self, scope: &TurnScope, request_sha256: &str) -> StoredTurn {
        let Some(store) = &self.store else {
            return StoredTurn::Empty;
        };
        let records = match store.replay(scope, 0) {
            Ok(records) => records,
            Err(error) => return StoredTurn::Conflict(error.to_string()),
        };
        if records.is_empty() {
            return StoredTurn::Empty;
        }
        let first_request = records
            .first()
            .and_then(|record| record.payload.get("request_sha256"))
            .and_then(Value::as_str);
        if first_request != Some(request_sha256) {
            return StoredTurn::Conflict(
                "stored turn request digest conflicts with the incoming turn".to_string(),
            );
        }
        let mut frames = Vec::with_capacity(records.len());
        for record in records {
            let Some(frame_value) = record.payload.get("frame").cloned() else {
                return StoredTurn::Conflict(
                    "stored event payload has no Host frame".to_string(),
                );
            };
            let frame = match serde_json::from_value::<RunTurnFrame>(frame_value) {
                Ok(frame) => frame,
                Err(error) => return StoredTurn::Conflict(error.to_string()),
            };
            if frame.kind != record.kind || frame.event_id.as_deref() != Some(&record.event_id) {
                return StoredTurn::Conflict(
                    "stored Host frame does not match its event record identity".to_string(),
                );
            }
            frames.push(frame);
        }
        if frames.iter().any(|frame| frame.kind == "turn.end") {
            StoredTurn::Complete(frames)
        } else {
            StoredTurn::Incomplete(frames)
        }
    }

    /// Returns true only when the frame is durably present or an exact
    /// duplicate was already present. A failure disables further durable use;
    /// the caller may continue the owner-open turn as unreplayable.
    pub fn append_frame(
        &mut self,
        scope: &TurnScope,
        request_sha256: &str,
        frame: &RunTurnFrame,
    ) -> bool {
        let Some(store) = &self.store else {
            return false;
        };
        let Some(event_id) = frame.event_id.clone() else {
            self.disable("Host frame has no event_id".to_string());
            return false;
        };
        let frame_value = match serde_json::to_value(frame) {
            Ok(value) => value,
            Err(error) => {
                self.disable(error.to_string());
                return false;
            }
        };
        let payload = json!({
            "request_sha256": request_sha256,
            "frame": frame_value
        });
        match store.append(EventInput {
            scope: scope.clone(),
            event_id,
            kind: frame.kind.clone(),
            payload,
        }) {
            Ok(_) => true,
            Err(error) => {
                self.disable(error.to_string());
                false
            }
        }
    }

    fn disable(&mut self, error: String) {
        self.store = None;
        self.configured = true;
        self.error = Some(error);
    }
}

#[must_use]
pub fn event_scope(request: &RunTurnRequest, turn_stream_id: &str) -> TurnScope {
    TurnScope::new(
        request.session_id.clone(),
        request.effective_profile_id().to_string(),
        request.task_id.clone(),
        request.turn_id.clone(),
        turn_stream_id.to_string(),
    )
}

pub fn request_sha256(request: &RunTurnRequest) -> Result<String, String> {
    let encoded = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    Ok(hex_lower(&Sha256::digest(encoded)))
}

pub fn stable_turn_stream_id(request: &RunTurnRequest) -> Result<String, String> {
    let encoded = serde_json::to_vec(&json!({
        "schema": "trillionnium.owner-open.turn-stream.v1",
        "session_id": request.session_id,
        "profile_id": request.effective_profile_id(),
        "task_id": request.task_id,
        "turn_id": request.turn_id
    }))
    .map_err(|error| error.to_string())?;
    Ok(format!("r5-stream-{}", hex_lower(&Sha256::digest(encoded))))
}

fn hex_lower(value: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
