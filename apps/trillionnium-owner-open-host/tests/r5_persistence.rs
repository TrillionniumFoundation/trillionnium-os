#[path = "../src/r5_persistence.rs"]
mod r5_persistence;

use std::collections::BTreeMap;

use r5_persistence::{
    Persistence, StoredTurn, event_scope, request_sha256, stable_turn_stream_id,
};
use serde_json::json;
use trillionnium_owner_open_types::{
    PROTOCOL, PROTOCOL_VERSION, RunTurnFrame, RunTurnRequest,
};

fn request() -> RunTurnRequest {
    RunTurnRequest {
        protocol: PROTOCOL.to_string(),
        protocol_version: json!(PROTOCOL_VERSION),
        session_id: "session-persist".to_string(),
        task_id: "task-persist".to_string(),
        turn_id: "turn-persist".to_string(),
        user_input: "persist this turn".to_string(),
        profile_id: Some("owner-open".to_string()),
        context_ref: Some("context-1".to_string()),
        config_generation: Some(json!(7)),
        client_request_id: Some("client-request-a".to_string()),
        server_request_id: Some("server-request-a".to_string()),
        turn_request_sha256: None,
        resume_cursor: None,
        resume_token: None,
        prior_connection_id: None,
        parent_turn_id: None,
        continuation_of: None,
        extensions: BTreeMap::new(),
    }
}

fn frame(
    request: &RunTurnRequest,
    stream: &str,
    kind: &str,
    seq: u64,
) -> RunTurnFrame {
    RunTurnFrame {
        kind: kind.to_string(),
        seq,
        payload: json!({"fixture": kind}),
        direction: Some("host_to_client".to_string()),
        client_seq: None,
        host_seq: Some(seq),
        frame_sha256: None,
        event_id: Some(format!("{stream}-event-{seq}")),
        connection_id: Some("connection-original".to_string()),
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
fn request_digest_excludes_transport_correlation_but_binds_semantics() {
    let first = request();
    let mut correlated = first.clone();
    correlated.client_request_id = Some("client-request-b".to_string());
    correlated.server_request_id = Some("server-request-b".to_string());
    correlated.turn_request_sha256 = Some("ab".repeat(32));
    correlated.resume_token = Some("resume-token".to_string());
    correlated.prior_connection_id = Some("prior-connection".to_string());
    assert_eq!(request_sha256(&first).unwrap(), request_sha256(&correlated).unwrap());

    let mut changed = first.clone();
    changed.user_input = "different semantic input".to_string();
    assert_ne!(request_sha256(&first).unwrap(), request_sha256(&changed).unwrap());
    assert_eq!(
        stable_turn_stream_id(&first).unwrap(),
        stable_turn_stream_id(&changed).unwrap(),
        "turn stream identity is scoped to the turn, while request bytes conflict separately"
    );
}

#[test]
fn complete_turn_reopens_and_replays_exact_frames() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.jsonl");
    let request = request();
    let stream = stable_turn_stream_id(&request).unwrap();
    let digest = request_sha256(&request).unwrap();
    let scope = event_scope(&request, &stream);
    let accepted = frame(&request, &stream, "turn.accepted", 0);
    let terminal = frame(&request, &stream, "turn.end", 1);

    {
        let mut persistence = Persistence::open_best_effort(Some(&path));
        assert!(persistence.is_durable());
        assert!(persistence.append_frame(&scope, &digest, &accepted));
        assert!(persistence.append_frame(&scope, &digest, &terminal));
    }

    let persistence = Persistence::open_best_effort(Some(&path));
    match persistence.load(&scope, &digest) {
        StoredTurn::Complete(frames) => assert_eq!(frames, vec![accepted, terminal]),
        other => panic!("unexpected recovered turn: {other:?}"),
    }
}

#[test]
fn incomplete_turn_is_never_misclassified_as_complete() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.jsonl");
    let request = request();
    let stream = stable_turn_stream_id(&request).unwrap();
    let digest = request_sha256(&request).unwrap();
    let scope = event_scope(&request, &stream);
    let accepted = frame(&request, &stream, "turn.accepted", 0);

    {
        let mut persistence = Persistence::open_best_effort(Some(&path));
        assert!(persistence.append_frame(&scope, &digest, &accepted));
    }

    let persistence = Persistence::open_best_effort(Some(&path));
    match persistence.load(&scope, &digest) {
        StoredTurn::Incomplete(frames) => assert_eq!(frames, vec![accepted]),
        other => panic!("unexpected recovered turn: {other:?}"),
    }
}

#[test]
fn request_drift_and_events_after_terminal_are_conflicts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.jsonl");
    let request = request();
    let stream = stable_turn_stream_id(&request).unwrap();
    let digest = request_sha256(&request).unwrap();
    let scope = event_scope(&request, &stream);

    {
        let mut persistence = Persistence::open_best_effort(Some(&path));
        assert!(persistence.append_frame(
            &scope,
            &digest,
            &frame(&request, &stream, "turn.accepted", 0),
        ));
        assert!(persistence.append_frame(
            &scope,
            &digest,
            &frame(&request, &stream, "turn.end", 1),
        ));
        assert!(persistence.append_frame(
            &scope,
            &digest,
            &frame(&request, &stream, "model.message", 2),
        ));
    }

    let persistence = Persistence::open_best_effort(Some(&path));
    assert!(matches!(
        persistence.load(&scope, &digest),
        StoredTurn::Conflict(_)
    ));
    assert!(matches!(
        persistence.load(&scope, &"cd".repeat(32)),
        StoredTurn::Conflict(_)
    ));
}

#[test]
fn scope_mismatch_disables_durable_use_instead_of_writing_ambiguous_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.jsonl");
    let request = request();
    let stream = stable_turn_stream_id(&request).unwrap();
    let digest = request_sha256(&request).unwrap();
    let scope = event_scope(&request, &stream);
    let mut wrong = frame(&request, &stream, "turn.accepted", 0);
    wrong.turn_id = Some("different-turn".to_string());

    let mut persistence = Persistence::open_best_effort(Some(&path));
    assert!(!persistence.append_frame(&scope, &digest, &wrong));
    assert_eq!(persistence.status(), "unavailable");
    assert!(persistence.error().is_some());
}
