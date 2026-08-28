#[allow(dead_code)]
#[path = "../src/r5_persistence.rs"]
mod r5_persistence;

use std::collections::BTreeMap;

use r5_persistence::{
    Persistence, StoredInspection, event_scope, request_sha256, stable_turn_stream_id,
};
use serde_json::json;
use trillionnium_owner_open_types::{PROTOCOL, PROTOCOL_VERSION, RunTurnFrame, RunTurnRequest};

fn request() -> RunTurnRequest {
    RunTurnRequest {
        protocol: PROTOCOL.to_string(),
        protocol_version: json!(PROTOCOL_VERSION),
        session_id: "session-inspect".to_string(),
        task_id: "task-inspect".to_string(),
        turn_id: "turn-inspect".to_string(),
        user_input: "inspect this turn".to_string(),
        profile_id: Some("owner-open".to_string()),
        context_ref: None,
        config_generation: Some(json!(9)),
        client_request_id: None,
        server_request_id: None,
        turn_request_sha256: None,
        resume_cursor: None,
        resume_token: None,
        prior_connection_id: None,
        parent_turn_id: None,
        continuation_of: None,
        extensions: BTreeMap::new(),
    }
}

fn frame(request: &RunTurnRequest, stream: &str, kind: &str, seq: u64) -> RunTurnFrame {
    RunTurnFrame {
        kind: kind.to_string(),
        seq,
        payload: json!({"fixture": kind, "ordinal": seq}),
        direction: Some("host_to_client".to_string()),
        client_seq: None,
        host_seq: Some(seq),
        frame_sha256: None,
        event_id: Some(format!("{stream}-event-{seq}")),
        connection_id: Some("connection-inspect".to_string()),
        stream_id: Some(stream.to_string()),
        turn_stream_id: Some(stream.to_string()),
        session_id: Some(request.session_id.clone()),
        profile_id: Some(request.effective_profile_id().to_string()),
        task_id: Some(request.task_id.clone()),
        turn_id: Some(request.turn_id.clone()),
        call_id: None,
        job_id: None,
        tool: None,
        target: None,
        target_id: None,
        extensions: BTreeMap::new(),
    }
}

#[test]
fn inclusive_cursor_returns_a_bounded_read_only_slice() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.jsonl");
    let request = request();
    let stream = stable_turn_stream_id(&request).unwrap();
    let digest = request_sha256(&request).unwrap();
    let scope = event_scope(&request, &stream);
    let frames = vec![
        frame(&request, &stream, "turn.accepted", 0),
        frame(&request, &stream, "model.delta", 1),
        frame(&request, &stream, "model.message", 2),
        frame(&request, &stream, "turn.end", 3),
    ];

    let mut persistence = Persistence::open_best_effort(Some(&path));
    for frame in &frames {
        assert!(persistence.append_frame(&scope, &digest, frame));
    }
    let before = std::fs::read(&path).unwrap();

    match persistence.inspect(&scope, &digest, 1, 2) {
        StoredInspection::Found(inspection) => {
            assert_eq!(inspection.frames, frames[1..3].to_vec());
            assert_eq!(inspection.inclusive_cursor, 1);
            assert_eq!(inspection.next_cursor, 3);
            assert_eq!(inspection.total_events, 4);
            assert!(inspection.complete);
            assert!(inspection.has_more);
        }
        other => panic!("unexpected inspection result: {other:?}"),
    }
    match persistence.inspect(&scope, &digest, 3, 8) {
        StoredInspection::Found(inspection) => {
            assert_eq!(inspection.frames, frames[3..4].to_vec());
            assert_eq!(inspection.next_cursor, 4);
            assert!(!inspection.has_more);
        }
        other => panic!("unexpected tail inspection result: {other:?}"),
    }
    match persistence.inspect(&scope, &digest, 4, 8) {
        StoredInspection::Found(inspection) => {
            assert!(inspection.frames.is_empty());
            assert_eq!(inspection.next_cursor, 4);
            assert!(!inspection.has_more);
            assert!(inspection.complete);
        }
        other => panic!("unexpected end-cursor inspection result: {other:?}"),
    }

    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "inspect mutated the store"
    );
}

#[test]
fn invalid_cursor_limit_and_request_binding_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.jsonl");
    let request = request();
    let stream = stable_turn_stream_id(&request).unwrap();
    let digest = request_sha256(&request).unwrap();
    let scope = event_scope(&request, &stream);
    let accepted = frame(&request, &stream, "turn.accepted", 0);
    let mut persistence = Persistence::open_best_effort(Some(&path));
    assert!(persistence.append_frame(&scope, &digest, &accepted));

    assert!(matches!(
        persistence.inspect(&scope, &digest, 2, 1),
        StoredInspection::Conflict(message) if message.contains("after next cursor")
    ));
    assert!(matches!(
        persistence.inspect(&scope, &digest, 0, 0),
        StoredInspection::Conflict(message) if message.contains("inspect limit")
    ));
    assert!(matches!(
        persistence.inspect(&scope, &"f".repeat(64), 0, 1),
        StoredInspection::Conflict(message) if message.contains("request digest")
    ));
}

#[test]
fn inspection_reports_unavailable_without_creating_state() {
    let request = request();
    let stream = stable_turn_stream_id(&request).unwrap();
    let digest = request_sha256(&request).unwrap();
    let scope = event_scope(&request, &stream);
    let persistence = Persistence::memory_only();
    assert!(matches!(
        persistence.inspect(&scope, &digest, 0, 1),
        StoredInspection::Unavailable { status, error }
            if status == "best_effort_memory_only" && error.is_none()
    ));
}
