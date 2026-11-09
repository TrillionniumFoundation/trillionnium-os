// Execute the actual primary Host implementation, not a second copy of its algorithm.
#[allow(dead_code)]
#[path = "../src/r5_persistence.rs"]
mod primary;

#[test]
fn android_client_digest_shared_vectors_match_actual_primary_host() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/android_client_turn_request_digest_v1.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let input = vector["input_unit"]
            .as_str()
            .unwrap()
            .repeat(usize::try_from(vector["repeat"].as_u64().unwrap()).unwrap());
        let request: trillionnium_owner_open_types::RunTurnRequest =
            serde_json::from_value(serde_json::json!({
                "protocol": "trillionnium.agent.turn.v1", "protocol_version": 1,
                "session_id": vector["session_id"], "task_id": vector["task_id"],
                "turn_id": vector["turn_id"], "user_input": input
            }))
            .unwrap();
        request.validate_mechanical(&Default::default()).unwrap();
        assert_eq!(
            primary::stable_turn_stream_id(&request).unwrap(),
            vector["turn_stream_id"].as_str().unwrap()
        );
        assert_eq!(
            primary::request_sha256(&request).unwrap(),
            vector["request_sha256"].as_str().unwrap(),
            "{}",
            vector["name"]
        );
    }
}
