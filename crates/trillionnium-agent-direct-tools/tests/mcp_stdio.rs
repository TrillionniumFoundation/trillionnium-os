use std::io::Write;
#[cfg(feature = "development-compatibility-lane")]
use std::io::{BufRead, BufReader};
#[cfg(any(
    feature = "production-durable-hotpath",
    all(
        not(feature = "production-durable-hotpath"),
        not(feature = "development-compatibility-lane")
    )
))]
use std::io::{Seek, SeekFrom};
#[cfg(any(
    feature = "development-compatibility-lane",
    all(
        not(feature = "production-durable-hotpath"),
        not(feature = "development-compatibility-lane")
    )
))]
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
#[cfg(feature = "development-compatibility-lane")]
use std::thread;

#[cfg(feature = "development-compatibility-lane")]
use serde_json::{Value, json};
#[cfg(feature = "development-compatibility-lane")]
use sha2::{Digest, Sha256};

#[cfg(feature = "development-compatibility-lane")]
const STRUCTURED_CONTENT_BINDING_SCHEMA: &str =
    "org.trillionnium.mcp.structured-content-binding.v1";

#[cfg(feature = "development-compatibility-lane")]
fn assert_structured_content_binding(result: &Value, expected: &Value) {
    assert_eq!(result["structuredContent"], *expected);
    let content = result["content"].as_array().unwrap();
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["type"], "text");
    assert_eq!(content[0].as_object().unwrap().len(), 2);
    let text = content[0]["text"].as_str().unwrap();
    let structured_bytes = serde_json::to_vec(expected).unwrap();
    let expected_sha256 = format!("{:x}", Sha256::digest(&structured_bytes));
    let expected_text = format!(
        "{{\"schema\":\"{STRUCTURED_CONTENT_BINDING_SCHEMA}\",\"structured_content_sha256\":\"{expected_sha256}\",\"structured_content_bytes\":{}}}",
        structured_bytes.len()
    );
    assert_eq!(text, expected_text);
    let binding = serde_json::from_str::<Value>(text).unwrap();
    assert_eq!(binding.as_object().unwrap().len(), 3);
}

#[cfg(feature = "development-compatibility-lane")]
fn assert_one_tool(binary: &str, expected_tool: &str) {
    let mut child = Command::new(binary)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for request in [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "integration-test", "version": "1"}
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    ] {
        serde_json::to_writer(&mut stdin, &request).unwrap();
        stdin.write_all(b"\n").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "MCP server failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 2);
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], expected_tool);
}

#[cfg(feature = "development-compatibility-lane")]
#[test]
fn system_api_binary_exposes_only_its_direct_mcp_tool() {
    assert_one_tool(
        env!("CARGO_BIN_EXE_trillionnium-agent-system-api"),
        "trillionnium_system_api",
    );
}

#[cfg(feature = "development-compatibility-lane")]
#[test]
fn accessibility_binary_exposes_only_its_direct_mcp_tool() {
    assert_one_tool(
        env!("CARGO_BIN_EXE_trillionnium-agent-accessibility"),
        "trillionnium_accessibility",
    );
}

#[cfg(all(
    not(feature = "production-durable-hotpath"),
    not(feature = "development-compatibility-lane")
))]
fn assert_unselected_effect_lane_holds_before_input_or_backend(
    binary: &str,
    endpoint_variable: &str,
    expected_adapter: &str,
) {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("must-not-connect.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();

    let mut input = tempfile::tempfile().unwrap();
    input
        .write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"sentinel":"must-not-be-consumed"}}"#,
        )
        .unwrap();
    input.seek(SeekFrom::Start(0)).unwrap();
    let output = Command::new(binary)
        .arg("mcp")
        .env(endpoint_variable, &socket)
        .stdin(Stdio::from(input.try_clone().unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert_eq!(
        input.stream_position().unwrap(),
        0,
        "no-feature adapter consumed stdin before rejecting its absent effect lane"
    );
    assert!(
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "no-feature adapter connected to a backend before rejecting its absent effect lane"
    );
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "no-feature adapter emitted output before effect-lane admission: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(&format!(
            "backend unavailable: {expected_adapter} effect lane is not compiled"
        )),
        "unexpected no-feature admission failure: {stderr}"
    );
    assert!(
        stderr.contains("explicit development-compatibility-lane"),
        "no-feature failure did not identify the only development opt-in: {stderr}"
    );
}

#[cfg(all(
    not(feature = "production-durable-hotpath"),
    not(feature = "development-compatibility-lane")
))]
#[test]
fn system_api_no_feature_binary_holds_before_nonempty_stdin_and_backend() {
    assert_unselected_effect_lane_holds_before_input_or_backend(
        env!("CARGO_BIN_EXE_trillionnium-agent-system-api"),
        "TRILLIONNIUM_SYSTEM_API_SOCKET",
        "System API",
    );
}

#[cfg(all(
    not(feature = "production-durable-hotpath"),
    not(feature = "development-compatibility-lane")
))]
#[test]
fn accessibility_no_feature_binary_holds_before_nonempty_stdin_and_backend() {
    assert_unselected_effect_lane_holds_before_input_or_backend(
        env!("CARGO_BIN_EXE_trillionnium-agent-accessibility"),
        "TRILLIONNIUM_ACCESSIBILITY_SOCKET",
        "Accessibility",
    );
}

#[cfg(feature = "production-durable-hotpath")]
fn assert_product_binary_requires_entry_checkpoint_before_reading_stdin(binary: &str) {
    let mut input = tempfile::tempfile().unwrap();
    input
        .write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"sentinel":"must-not-be-consumed"}}"#,
        )
        .unwrap();
    input.seek(SeekFrom::Start(0)).unwrap();
    let output = Command::new(binary)
        .arg("mcp")
        .stdin(Stdio::from(input.try_clone().unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        input.stream_position().unwrap(),
        0,
        "product adapter consumed non-empty stdin before its entry checkpoint"
    );
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "hotpath adapter emitted MCP output before its entry checkpoint: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("backend unavailable: product Direct Tool entry checkpoint"),
        "unexpected hotpath adapter entry failure: {stderr}"
    );
}

#[cfg(feature = "production-durable-hotpath")]
#[test]
fn system_api_product_binary_holds_before_nonempty_mcp_stdin() {
    assert_product_binary_requires_entry_checkpoint_before_reading_stdin(env!(
        "CARGO_BIN_EXE_trillionnium-agent-system-api"
    ));
}

#[cfg(feature = "production-durable-hotpath")]
#[test]
fn accessibility_product_binary_holds_before_nonempty_mcp_stdin() {
    assert_product_binary_requires_entry_checkpoint_before_reading_stdin(env!(
        "CARGO_BIN_EXE_trillionnium-agent-accessibility"
    ));
}

#[cfg(feature = "production-durable-hotpath")]
fn assert_product_binary_rejects_raw_wire_before_input(binary: &str) {
    let mut input = tempfile::tempfile().unwrap();
    input
        .write_all(br#"{"protocol":"caller-selected","request_id":"caller-selected"}"#)
        .unwrap();
    input.seek(SeekFrom::Start(0)).unwrap();
    let output = Command::new(binary)
        .stdin(Stdio::from(input.try_clone().unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        input.stream_position().unwrap(),
        0,
        "product adapter consumed raw backend-wire input before its entry checkpoint"
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("backend unavailable: product Direct Tool entry checkpoint"),
        "unexpected product pre-argv entry denial: {stderr}"
    );
}

#[cfg(feature = "production-durable-hotpath")]
#[test]
fn system_api_product_binary_holds_before_raw_wire_mode() {
    assert_product_binary_rejects_raw_wire_before_input(env!(
        "CARGO_BIN_EXE_trillionnium-agent-system-api"
    ));
}

#[cfg(feature = "production-durable-hotpath")]
#[test]
fn accessibility_product_binary_holds_before_raw_wire_mode() {
    assert_product_binary_rejects_raw_wire_before_input(env!(
        "CARGO_BIN_EXE_trillionnium-agent-accessibility"
    ));
}

#[cfg(feature = "development-compatibility-lane")]
#[test]
fn one_shot_preserves_structured_backend_error_and_exits_normally() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("accessibility-one-shot.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let backend_response = json!({
        "protocol": "org.trillionnium.agent-accessibility.v2",
        "request_id": "req-one-shot-1",
        "action": "snapshot",
        "snapshot_mode": "metadata_only",
        "ok": false,
        "backend": "accessibility",
        "idempotency_capacity_entries_per_peer": 128,
        "idempotency_capacity_reserved_bytes_per_peer": 48 * 1024 * 1024,
        "idempotency_reclamation_status":
            "inactive_backend_foundation_requires_trusted_adapter_journal_v1",
        "error": "request_outcome_indeterminate",
        "replay_scope": "read_only_resampled"
    });
    let server_response = backend_response.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request)
            .unwrap();
        let request = serde_json::from_str::<Value>(&request).unwrap();
        assert_eq!(request["request_id"], "req-one-shot-1");
        serde_json::to_writer(&mut stream, &server_response).unwrap();
        stream.write_all(b"\n").unwrap();
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-agent-accessibility"))
        .env("TRILLIONNIUM_ACCESSIBILITY_SOCKET", &socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(
        child.stdin.as_mut().unwrap(),
        &json!({
            "protocol": "org.trillionnium.agent-accessibility.v2",
            "request_id": "req-one-shot-1",
            "action": "snapshot",
            "window_id": null,
            "snapshot_mode": "metadata_only"
        }),
    )
    .unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();

    assert!(
        output.status.success(),
        "one-shot adapter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        backend_response
    );
}

#[cfg(feature = "development-compatibility-lane")]
#[test]
fn semantic_mode_os_authors_the_unchanged_system_api_wire_envelope() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("system-api-semantic.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request)
            .unwrap();
        let request = serde_json::from_str::<Value>(&request).unwrap();
        let mut keys = request
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(
            keys,
            ["action", "package", "protocol", "request_id", "user"]
        );
        assert_eq!(request["protocol"], "org.trillionnium.agent-system-api.v1");
        assert!(request["request_id"].as_str().unwrap().starts_with("os:"));
        assert_eq!(request["action"], "launch_package");
        assert_eq!(request["package"], "com.example");
        assert_eq!(request["user"], 0);
        serde_json::to_writer(
            &mut stream,
            &json!({
                "protocol": request["protocol"],
                "request_id": request["request_id"],
                "ok": true,
            }),
        )
        .unwrap();
        stream.write_all(b"\n").unwrap();
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-agent-system-api"))
        .arg("semantic")
        .env("TRILLIONNIUM_SYSTEM_API_SOCKET", &socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(
        child.stdin.as_mut().unwrap(),
        &json!({"action": "launch_package", "package": "com.example"}),
    )
    .unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "semantic adapter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response = serde_json::from_slice::<Value>(&output.stdout).unwrap();
    assert_eq!(response["protocol"], "org.trillionnium.agent-system-api.v1");
    assert!(response["request_id"].as_str().unwrap().starts_with("os:"));
    assert_eq!(response["ok"], true);
}

#[cfg(feature = "development-compatibility-lane")]
#[test]
fn mcp_preserves_four_recovery_outcomes_from_real_mock_uds() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("system-api-mcp.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let recovery_codes = [
        "request_id_conflict",
        "request_in_flight",
        "effect_outcome_indeterminate",
        "idempotency_capacity_exhausted",
    ];
    let server = thread::spawn(move || {
        for (index, error) in recovery_codes.into_iter().enumerate() {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            let request = serde_json::from_str::<Value>(&request).unwrap();
            let request_id = request["request_id"].as_str().unwrap().to_string();
            assert!(request_id.starts_with("os:"));
            assert_eq!(request["protocol"], "org.trillionnium.agent-system-api.v1");
            assert_eq!(request["user"], 0);
            serde_json::to_writer(
                &mut stream,
                &json!({
                    "protocol": "org.trillionnium.agent-system-api.v1",
                    "request_id": request_id,
                    "ok": false,
                    "error": error,
                    "backend": "system_api",
                    "recovery_index": index
                }),
            )
            .unwrap();
            stream.write_all(b"\n").unwrap();
        }
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_trillionnium-agent-system-api"))
        .arg("mcp")
        .env("TRILLIONNIUM_SYSTEM_API_SOCKET", &socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    serde_json::to_writer(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"}
        }),
    )
    .unwrap();
    stdin.write_all(b"\n").unwrap();
    for index in 0..recovery_codes.len() {
        serde_json::to_writer(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": index + 2,
                "method": "tools/call",
                "params": {
                    "name": "trillionnium_system_api",
                    "arguments": {
                        "action": "launch_package",
                        "package": "com.example"
                    }
                }
            }),
        )
        .unwrap();
        stdin.write_all(b"\n").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();

    assert!(
        output.status.success(),
        "MCP adapter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), recovery_codes.len() + 1);
    for (index, error) in recovery_codes.into_iter().enumerate() {
        let result = &responses[index + 1]["result"];
        assert_eq!(result["isError"], true);
        let structured = &result["structuredContent"];
        assert_eq!(
            structured["protocol"],
            "org.trillionnium.agent-system-api.v1"
        );
        assert!(
            structured["request_id"]
                .as_str()
                .unwrap()
                .starts_with("os:")
        );
        assert_eq!(structured["ok"], false);
        assert_eq!(structured["error"], error);
        assert_eq!(structured["backend"], "system_api");
        assert_eq!(structured["recovery_index"], index);
        assert_structured_content_binding(result, structured);
        assert_ne!(result["structuredContent"]["error"], "direct_tool_error");
    }
}
