use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trillionnium_owner_open_event_store::{
    DurableEventStore, EventInput, EventStoreLimits, SyncPolicy, TurnScope,
};
use trillionnium_owner_open_types::{RunTurnFrame, RunTurnRequest};

const TURN_REQUEST_DIGEST_SCHEMA: &str = "trillionnium.owner-open.turn-request-digest.v1";
const TURN_STREAM_SCHEMA: &str = "trillionnium.owner-open.turn-stream.v1";
const MAX_INSPECT_FRAMES: usize = 4096;

#[derive(Debug, Clone)]
pub enum StoredTurn {
    Empty,
    Complete(Vec<RunTurnFrame>),
    Incomplete(Vec<RunTurnFrame>),
    Conflict(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TurnInspection {
    pub frames: Vec<RunTurnFrame>,
    pub inclusive_cursor: u64,
    pub next_cursor: u64,
    pub total_events: u64,
    pub complete: bool,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StoredInspection {
    Unavailable {
        status: String,
        error: Option<String>,
    },
    Found(TurnInspection),
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

        let mut frames = Vec::with_capacity(records.len());
        let mut terminal_index = None;
        for (index, record) in records.into_iter().enumerate() {
            let stored_request = record
                .payload
                .get("request_sha256")
                .and_then(Value::as_str);
            if stored_request != Some(request_sha256) {
                return StoredTurn::Conflict(
                    "stored event request digest conflicts with the incoming turn".to_string(),
                );
            }
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
            if frame.turn_stream_id.as_deref() != Some(scope.turn_stream_id.as_str())
                || frame.session_id.as_deref() != Some(scope.session_id.as_str())
                || frame.profile_id.as_deref() != Some(scope.profile_id.as_str())
                || frame.task_id.as_deref() != Some(scope.task_id.as_str())
                || frame.turn_id.as_deref() != Some(scope.turn_id.as_str())
            {
                return StoredTurn::Conflict(
                    "stored Host frame does not match its event-store turn scope".to_string(),
                );
            }
            if frame.kind == "turn.end" {
                if terminal_index.replace(index).is_some() {
                    return StoredTurn::Conflict(
                        "stored turn has more than one terminal frame".to_string(),
                    );
                }
            }
            frames.push(frame);
        }

        match terminal_index {
            Some(index) if index + 1 == frames.len() => StoredTurn::Complete(frames),
            Some(_) => StoredTurn::Conflict(
                "stored turn contains events after its terminal frame".to_string(),
            ),
            None => StoredTurn::Incomplete(frames),
        }
    }

    /// Inspect already-validated durable frames using an inclusive turn-event
    /// cursor. Inspection is read-only: it never appends, reconciles, starts a
    /// provider, claims a call, or dispatches an effect.
    pub fn inspect(
        &self,
        scope: &TurnScope,
        request_sha256: &str,
        inclusive_cursor: u64,
        limit: usize,
    ) -> StoredInspection {
        if self.store.is_none() {
            return StoredInspection::Unavailable {
                status: self.status().to_string(),
                error: self.error.clone(),
            };
        }
        if limit == 0 || limit > MAX_INSPECT_FRAMES {
            return StoredInspection::Conflict(format!(
                "inspect limit must be between 1 and {MAX_INSPECT_FRAMES}"
            ));
        }

        let (frames, complete) = match self.load(scope, request_sha256) {
            StoredTurn::Empty => (Vec::new(), false),
            StoredTurn::Complete(frames) => (frames, true),
            StoredTurn::Incomplete(frames) => (frames, false),
            StoredTurn::Conflict(error) => return StoredInspection::Conflict(error),
        };
        let total_events = match u64::try_from(frames.len()) {
            Ok(value) => value,
            Err(_) => {
                return StoredInspection::Conflict(
                    "stored turn event count does not fit the cursor domain".to_string(),
                );
            }
        };
        if inclusive_cursor > total_events {
            return StoredInspection::Conflict(format!(
                "inclusive cursor {inclusive_cursor} is after next cursor {total_events}"
            ));
        }
        let start = match usize::try_from(inclusive_cursor) {
            Ok(value) => value,
            Err(_) => {
                return StoredInspection::Conflict(
                    "inclusive cursor does not fit the local index domain".to_string(),
                );
            }
        };
        let end = start.saturating_add(limit).min(frames.len());
        let next_cursor = match u64::try_from(end) {
            Ok(value) => value,
            Err(_) => {
                return StoredInspection::Conflict(
                    "next cursor does not fit the cursor domain".to_string(),
                );
            }
        };
        StoredInspection::Found(TurnInspection {
            frames: frames[start..end].to_vec(),
            inclusive_cursor,
            next_cursor,
            total_events,
            complete,
            has_more: end < frames.len(),
        })
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
        if self.store.is_none() {
            return false;
        }
        let Some(event_id) = frame.event_id.clone() else {
            self.disable("Host frame has no event_id".to_string());
            return false;
        };
        if frame.turn_stream_id.as_deref() != Some(scope.turn_stream_id.as_str())
            || frame.session_id.as_deref() != Some(scope.session_id.as_str())
            || frame.profile_id.as_deref() != Some(scope.profile_id.as_str())
            || frame.task_id.as_deref() != Some(scope.task_id.as_str())
            || frame.turn_id.as_deref() != Some(scope.turn_id.as_str())
        {
            self.disable("Host frame does not match the durable turn scope".to_string());
            return false;
        }
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
        let result = self
            .store
            .as_ref()
            .expect("store presence checked")
            .append(EventInput {
                scope: scope.clone(),
                event_id,
                kind: frame.kind.clone(),
                payload,
            });
        match result {
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

/// Digest only stable turn request semantics. Correlation-only request IDs,
/// resume transport fields and a caller-supplied digest are deliberately
/// excluded so reconnect/replay does not create a recursive or connection-bound
/// identity.
pub fn request_sha256(request: &RunTurnRequest) -> Result<String, String> {
    let encoded = serde_json::to_vec(&json!({
        "schema": TURN_REQUEST_DIGEST_SCHEMA,
        "protocol": &request.protocol,
        "protocol_version": &request.protocol_version,
        "session_id": &request.session_id,
        "profile_id": request.effective_profile_id(),
        "task_id": &request.task_id,
        "turn_id": &request.turn_id,
        "config_generation": &request.config_generation,
        "user_input": &request.user_input,
        "context_ref": &request.context_ref
    }))
    .map_err(|error| error.to_string())?;
    Ok(hex_lower(&Sha256::digest(encoded)))
}

pub fn stable_turn_stream_id(request: &RunTurnRequest) -> Result<String, String> {
    let encoded = serde_json::to_vec(&json!({
        "schema": TURN_STREAM_SCHEMA,
        "session_id": &request.session_id,
        "profile_id": request.effective_profile_id(),
        "task_id": &request.task_id,
        "turn_id": &request.turn_id
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
