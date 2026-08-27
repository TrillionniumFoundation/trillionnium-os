//! Minimal MCP stdio transport for the two direct Android backends.
//!
//! Each process exposes exactly one tool. This module implements framing and
//! JSON-RPC mechanics only; it never selects or dispatches between backends.

use std::io::{self, BufRead, BufReader, Write};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::{
    DirectToolError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Result, validate_backend_outcome,
};

pub const PROTOCOL_VERSION: &str = "2025-06-18";
pub const STRUCTURED_CONTENT_BINDING_SCHEMA: &str =
    "org.trillionnium.mcp.structured-content-binding.v1";
pub const CODEX_CALL_TOOL_RESULT_BYTES_CAP: usize = 1024 * 1024;
pub const MAX_CALL_TOOL_RESULT_OVERHEAD_BYTES: usize = 512;
pub const GUARANTEED_STRUCTURED_CONTENT_BYTES: usize =
    CODEX_CALL_TOOL_RESULT_BYTES_CAP - MAX_CALL_TOOL_RESULT_OVERHEAD_BYTES;
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26", PROTOCOL_VERSION];
const MAX_MCP_RESPONSE_BYTES: usize = MAX_RESPONSE_BYTES * 4 + 256 * 1024;

#[derive(Debug, Clone)]
pub struct McpTool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

pub fn serve_stdio<F>(server_name: &'static str, tool: McpTool, execute: F) -> Result<()>
where
    F: FnMut(Value) -> Result<Value>,
{
    let stdin = io::stdin();
    let stdout = io::stdout();
    serve(
        BufReader::new(stdin.lock()),
        stdout.lock(),
        server_name,
        tool,
        execute,
    )
}

pub fn serve<R, W, F>(
    mut reader: R,
    mut writer: W,
    server_name: &'static str,
    tool: McpTool,
    mut execute: F,
) -> Result<()>
where
    R: BufRead,
    W: Write,
    F: FnMut(Value) -> Result<Value>,
{
    let mut initialized = false;
    while let Some(frame) = read_frame(&mut reader)? {
        let value: Value = match serde_json::from_slice(&frame) {
            Ok(value) => value,
            Err(error) => {
                write_frame(
                    &mut writer,
                    &json_rpc_error(Value::Null, -32700, format!("parse error: {error}")),
                )?;
                continue;
            }
        };
        if let Some(response) =
            handle_message(value, server_name, &tool, &mut initialized, &mut execute)?
        {
            write_frame(&mut writer, &response)?;
        }
    }
    Ok(())
}

fn handle_message<F>(
    value: Value,
    server_name: &'static str,
    tool: &McpTool,
    initialized: &mut bool,
    execute: &mut F,
) -> Result<Option<Value>>
where
    F: FnMut(Value) -> Result<Value>,
{
    let Some(object) = value.as_object() else {
        return Ok(Some(json_rpc_error(
            Value::Null,
            -32600,
            "request must be an object",
        )));
    };
    let id = object.get("id").cloned();
    if object.get("jsonrpc") != Some(&Value::String("2.0".to_string())) {
        return Ok(id.map(|id| json_rpc_error(id, -32600, "jsonrpc must be 2.0")));
    }
    if id
        .as_ref()
        .is_some_and(|id| !id.is_null() && !id.is_string() && !id.is_i64() && !id.is_u64())
    {
        return Ok(Some(json_rpc_error(
            Value::Null,
            -32600,
            "id must be a string, integer, or null",
        )));
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Ok(id.map(|id| json_rpc_error(id, -32600, "method must be a string")));
    };

    if method == "notifications/initialized" {
        return Ok(None);
    }
    let Some(id) = id else {
        // JSON-RPC notifications never receive a response, including unknown
        // notifications.
        return Ok(None);
    };
    let response = match method {
        "initialize" => {
            let requested = object
                .get("params")
                .and_then(Value::as_object)
                .and_then(|params| params.get("protocolVersion"))
                .and_then(Value::as_str);
            let selected = requested
                .filter(|version| SUPPORTED_PROTOCOL_VERSIONS.contains(version))
                .unwrap_or(PROTOCOL_VERSION);
            *initialized = true;
            json_rpc_result(
                id,
                json!({
                    "protocolVersion": selected,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {
                        "name": server_name,
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            )
        }
        "ping" => json_rpc_result(id, json!({})),
        "tools/list" if !*initialized => not_initialized(id),
        "tools/list" => json_rpc_result(
            id,
            json!({
                "tools": [{
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                    "annotations": {
                        "readOnlyHint": false,
                        "destructiveHint": true,
                        "idempotentHint": false,
                        "openWorldHint": false
                    }
                }]
            }),
        ),
        "tools/call" if !*initialized => not_initialized(id),
        "tools/call" => handle_tool_call(id, object, tool, execute)?,
        _ => json_rpc_error(id, -32601, "method not found"),
    };
    Ok(Some(response))
}

fn handle_tool_call<F>(
    id: Value,
    request: &Map<String, Value>,
    tool: &McpTool,
    execute: &mut F,
) -> Result<Value>
where
    F: FnMut(Value) -> Result<Value>,
{
    let Some(params) = request.get("params").and_then(Value::as_object) else {
        return Ok(json_rpc_error(
            id,
            -32602,
            "tools/call params must be an object",
        ));
    };
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return Ok(json_rpc_error(
            id,
            -32602,
            "tools/call name must be a string",
        ));
    };
    if name != tool.name {
        return Ok(json_rpc_error(id, -32602, "unknown tool name"));
    }
    let Some(arguments) = params.get("arguments").cloned() else {
        return Ok(json_rpc_error(
            id,
            -32602,
            "tools/call arguments are required",
        ));
    };
    if !arguments.is_object() {
        return Ok(json_rpc_error(
            id,
            -32602,
            "tools/call arguments must be an object",
        ));
    }
    let (structured, is_error) = match execute(arguments) {
        Ok(value) => match validate_backend_outcome(&value) {
            Ok(outcome) => (value, outcome.is_error()),
            Err(error) => generic_tool_failure(error),
        },
        Err(error) => generic_tool_failure(error),
    };
    let result = call_tool_result(structured, is_error)?;
    Ok(json_rpc_result(id, result))
}

fn call_tool_result(structured: Value, is_error: bool) -> Result<Value> {
    let encoded = encode_call_tool_result(structured, is_error)?;
    let overhead = encoded
        .serialized_bytes
        .checked_sub(encoded.structured_content_bytes)
        .ok_or_else(|| {
            DirectToolError::BackendFailed(
                "MCP CallToolResult size accounting underflow".to_string(),
            )
        })?;
    if overhead > MAX_CALL_TOOL_RESULT_OVERHEAD_BYTES {
        return Err(DirectToolError::BackendFailed(format!(
            "MCP CallToolResult overhead {overhead} exceeds audited bound {MAX_CALL_TOOL_RESULT_OVERHEAD_BYTES}; no replacement result emitted; caller_delivery_indeterminate; semantic caller must not invent or retry a backend request identity; durable journal recovery remains authoritative when enabled"
        )));
    }
    if encoded.serialized_bytes > CODEX_CALL_TOOL_RESULT_BYTES_CAP {
        return Err(DirectToolError::BackendFailed(format!(
            "MCP CallToolResult exceeds audited size budget: serialized_bytes={} structured_content_bytes={} structured_content_sha256={} guaranteed_structured_content_bytes={} codex_call_tool_result_bytes_cap={}; no replacement result emitted; caller_delivery_indeterminate; semantic caller must not invent or retry a backend request identity; durable journal recovery remains authoritative when enabled",
            encoded.serialized_bytes,
            encoded.structured_content_bytes,
            encoded.structured_content_sha256,
            GUARANTEED_STRUCTURED_CONTENT_BYTES,
            CODEX_CALL_TOOL_RESULT_BYTES_CAP
        )));
    }
    Ok(encoded.value)
}

struct EncodedCallToolResult {
    value: Value,
    structured_content_bytes: usize,
    structured_content_sha256: String,
    serialized_bytes: usize,
}

fn encode_call_tool_result(structured: Value, is_error: bool) -> Result<EncodedCallToolResult> {
    if !structured.is_object() {
        return Err(DirectToolError::BackendFailed(
            "MCP structuredContent must be an object".to_string(),
        ));
    }
    let structured_bytes = serde_json::to_vec(&structured)?;
    let structured_sha256 = format!("{:x}", Sha256::digest(&structured_bytes));
    let binding_text = format!(
        "{{\"schema\":\"{STRUCTURED_CONTENT_BINDING_SCHEMA}\",\"structured_content_sha256\":\"{structured_sha256}\",\"structured_content_bytes\":{}}}",
        structured_bytes.len()
    );
    let result = json!({
        "content": [{"type": "text", "text": binding_text}],
        "structuredContent": structured,
        "isError": is_error
    });
    let serialized_bytes = serde_json::to_vec(&result)?.len();
    Ok(EncodedCallToolResult {
        value: result,
        structured_content_bytes: structured_bytes.len(),
        structured_content_sha256: structured_sha256,
        serialized_bytes,
    })
}

fn generic_tool_failure(error: DirectToolError) -> (Value, bool) {
    (
        json!({
            "ok": false,
            "error": {
                "code": "direct_tool_error",
                "message": error.to_string()
            }
        }),
        true,
    )
}

fn not_initialized(id: Value) -> Value {
    json_rpc_error(id, -32002, "server is not initialized")
}

fn json_rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn json_rpc_error(id: Value, code: i32, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message.into()}
    })
}

fn read_frame<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut output = Vec::with_capacity(MAX_REQUEST_BYTES.min(8 * 1024));
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if output.is_empty() {
                return Ok(None);
            }
            return Err(DirectToolError::InvalidRequest(
                "MCP stdio frame is not newline terminated".to_string(),
            ));
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if output.len().saturating_add(newline) > MAX_REQUEST_BYTES {
                return Err(DirectToolError::InvalidRequest(format!(
                    "MCP request exceeds {MAX_REQUEST_BYTES} bytes"
                )));
            }
            output.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            if output.is_empty() {
                return Err(DirectToolError::InvalidRequest(
                    "MCP request frame is empty".to_string(),
                ));
            }
            return Ok(Some(output));
        }
        if output.len().saturating_add(available.len()) > MAX_REQUEST_BYTES {
            return Err(DirectToolError::InvalidRequest(format!(
                "MCP request exceeds {MAX_REQUEST_BYTES} bytes"
            )));
        }
        output.extend_from_slice(available);
        let consumed = available.len();
        reader.consume(consumed);
    }
}

fn write_frame<W: Write>(writer: &mut W, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_MCP_RESPONSE_BYTES {
        return Err(DirectToolError::BackendFailed(format!(
            "MCP response exceeds {MAX_MCP_RESPONSE_BYTES} bytes"
        )));
    }
    writer.write_all(&bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::*;

    fn tool() -> McpTool {
        McpTool {
            name: "closed_tool",
            description: "fixture",
            input_schema: json!({
                "type": "object",
                "required": ["value"],
                "properties": {"value": {"type": "integer"}},
                "additionalProperties": false
            }),
        }
    }

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
        assert_eq!(binding["schema"], STRUCTURED_CONTENT_BINDING_SCHEMA);
        assert_eq!(binding["structured_content_sha256"], expected_sha256);
        assert_eq!(binding["structured_content_bytes"], structured_bytes.len());
    }

    fn structured_with_serialized_len(target: usize) -> Value {
        let empty = json!({"ok": true, "payload": ""});
        let empty_len = serde_json::to_vec(&empty).unwrap().len();
        assert!(target >= empty_len);
        let structured = json!({
            "ok": true,
            "payload": "x".repeat(target - empty_len)
        });
        assert_eq!(serde_json::to_vec(&structured).unwrap().len(), target);
        structured
    }

    fn structured_for_call_tool_result_len(target: usize, is_error: bool) -> Value {
        let mut structured_target = target - MAX_CALL_TOOL_RESULT_OVERHEAD_BYTES;
        for _ in 0..4 {
            let structured = structured_with_serialized_len(structured_target);
            let actual = encode_call_tool_result(structured.clone(), is_error)
                .unwrap()
                .serialized_bytes;
            if actual == target {
                return structured;
            }
            if actual < target {
                structured_target += target - actual;
            } else {
                structured_target -= actual - target;
            }
        }
        panic!("could not construct exact serialized CallToolResult length {target}");
    }

    #[test]
    fn stdio_server_initializes_lists_one_tool_and_calls_it() {
        let input = [
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                           "clientInfo": {"name": "test", "version": "1"}}
            }),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "closed_tool", "arguments": {"value": 7}}
            }),
        ]
        .into_iter()
        .map(|value| format!("{}\n", serde_json::to_string(&value).unwrap()))
        .collect::<String>();
        let mut output = Vec::new();
        serve(
            BufReader::new(Cursor::new(input)),
            &mut output,
            "fixture-server",
            tool(),
            |arguments| Ok(json!({"ok": true, "arguments": arguments})),
        )
        .unwrap();
        let responses = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(responses[1]["result"]["tools"].as_array().unwrap().len(), 1);
        assert_eq!(
            responses[1]["result"]["tools"][0]["inputSchema"]["additionalProperties"],
            false
        );
        assert_eq!(responses[2]["result"]["structuredContent"]["ok"], true);
        assert_structured_content_binding(
            &responses[2]["result"],
            &json!({"ok": true, "arguments": {"value": 7}}),
        );
        assert_eq!(responses[2]["result"]["isError"], false);
    }

    #[test]
    fn initialize_and_list_do_not_require_a_logical_call_allocation() {
        let input = [
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION}
            }),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "closed_tool", "arguments": {"value": 7}}
            }),
        ]
        .into_iter()
        .map(|value| format!("{}\n", serde_json::to_string(&value).unwrap()))
        .collect::<String>();
        let mut allocation_attempts = 0_u64;
        let mut output = Vec::new();
        serve(
            BufReader::new(Cursor::new(input)),
            &mut output,
            "fixture-server",
            tool(),
            |_| {
                allocation_attempts += 1;
                Err(DirectToolError::BackendUnavailable(
                    "OS-owned per-logical-call allocation authority is unavailable".to_string(),
                ))
            },
        )
        .unwrap();

        assert_eq!(allocation_attempts, 1);
        let responses = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["id"], 1);
        assert_eq!(responses[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(responses[1]["id"], 2);
        assert_eq!(responses[1]["result"]["tools"].as_array().unwrap().len(), 1);
        assert_eq!(responses[2]["id"], 3);
        assert_eq!(responses[2]["result"]["isError"], true);
        assert!(
            responses[2]["result"]["structuredContent"]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("per-logical-call allocation authority is unavailable")
        );
    }

    #[test]
    fn tool_failure_is_a_standard_mcp_error_result_not_a_server_crash() {
        let input = [
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION}
            }),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "closed_tool", "arguments": {"value": 7}}
            }),
        ]
        .into_iter()
        .map(|value| format!("{}\n", serde_json::to_string(&value).unwrap()))
        .collect::<String>();
        let mut output = Vec::new();
        serve(
            BufReader::new(Cursor::new(input)),
            &mut output,
            "fixture-server",
            tool(),
            |_| {
                Err(DirectToolError::BackendUnavailable(
                    "fixture unavailable".to_string(),
                ))
            },
        )
        .unwrap();
        let last = String::from_utf8(output).unwrap();
        let last = serde_json::from_str::<Value>(last.lines().last().unwrap()).unwrap();
        assert_eq!(last["result"]["isError"], true);
        assert_eq!(
            last["result"]["structuredContent"]["error"]["code"],
            "direct_tool_error"
        );
        assert_structured_content_binding(&last["result"], &last["result"]["structuredContent"]);
    }

    #[test]
    fn structured_backend_error_is_preserved_as_an_mcp_error_result() {
        let input = [
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION}
            }),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "closed_tool", "arguments": {"value": 7}}
            }),
        ]
        .into_iter()
        .map(|value| format!("{}\n", serde_json::to_string(&value).unwrap()))
        .collect::<String>();
        let backend_response = json!({
            "ok": false,
            "error": "request_in_flight",
            "request_id": "request-7",
            "recovery": {"retry_same_id": true}
        });
        let mut output = Vec::new();
        serve(
            BufReader::new(Cursor::new(input)),
            &mut output,
            "fixture-server",
            tool(),
            |_| Ok(backend_response.clone()),
        )
        .unwrap();
        let last = String::from_utf8(output).unwrap();
        let last = serde_json::from_str::<Value>(last.lines().last().unwrap()).unwrap();
        assert_eq!(last["result"]["isError"], true);
        assert_eq!(last["result"]["structuredContent"], backend_response);
        assert_structured_content_binding(&last["result"], &backend_response);
    }

    #[test]
    fn large_structured_result_avoids_legacy_duplicate_body_truncation() {
        let structured = json!({
            "ok": true,
            "payload": "x".repeat(600 * 1024)
        });
        let legacy = json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string(&structured).unwrap()
            }],
            "structuredContent": structured.clone(),
            "isError": false
        });
        assert!(serde_json::to_vec(&legacy).unwrap().len() > CODEX_CALL_TOOL_RESULT_BYTES_CAP);

        let result = call_tool_result(structured.clone(), false).unwrap();
        assert!(serde_json::to_vec(&result).unwrap().len() <= CODEX_CALL_TOOL_RESULT_BYTES_CAP);
        assert!(result["content"][0]["text"].as_str().unwrap().len() < 256);
        assert_structured_content_binding(&result, &structured);
    }

    #[test]
    fn audited_structured_limit_and_envelope_overhead_stay_below_codex_cap() {
        let structured = structured_with_serialized_len(GUARANTEED_STRUCTURED_CONTENT_BYTES);
        let structured_len = serde_json::to_vec(&structured).unwrap().len();
        let result = call_tool_result(structured, false).unwrap();
        let serialized_len = serde_json::to_vec(&result).unwrap().len();
        let overhead = serialized_len - structured_len;
        assert!(overhead <= MAX_CALL_TOOL_RESULT_OVERHEAD_BYTES);
        assert!(serialized_len <= CODEX_CALL_TOOL_RESULT_BYTES_CAP);
    }

    #[test]
    fn serialized_cap_minus_one_cap_and_cap_plus_one_are_exact() {
        for target in [
            CODEX_CALL_TOOL_RESULT_BYTES_CAP - 1,
            CODEX_CALL_TOOL_RESULT_BYTES_CAP,
        ] {
            let structured = structured_for_call_tool_result_len(target, false);
            let result = call_tool_result(structured, false).unwrap();
            assert_eq!(serde_json::to_vec(&result).unwrap().len(), target);
        }

        let above_cap =
            structured_for_call_tool_result_len(CODEX_CALL_TOOL_RESULT_BYTES_CAP + 1, false);
        let encoded = encode_call_tool_result(above_cap.clone(), false).unwrap();
        assert_eq!(
            encoded.serialized_bytes,
            CODEX_CALL_TOOL_RESULT_BYTES_CAP + 1
        );
        let error = call_tool_result(above_cap, false).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("exceeds audited size budget"));
        assert!(message.contains("no replacement result emitted"));
        assert!(message.contains("caller_delivery_indeterminate"));
        assert!(message.contains("semantic caller must not invent or retry"));
        assert!(message.contains("durable journal recovery remains authoritative"));
    }

    #[test]
    fn post_backend_size_failure_is_fail_stop_not_a_generic_tool_result() {
        let request = json!({
            "params": {
                "name": "closed_tool",
                "arguments": {"value": 7}
            }
        });
        let mut effects = 0;
        let error = handle_tool_call(json!(1), request.as_object().unwrap(), &tool(), &mut |_| {
            effects += 1;
            Ok(structured_with_serialized_len(
                CODEX_CALL_TOOL_RESULT_BYTES_CAP,
            ))
        })
        .unwrap_err();
        assert_eq!(effects, 1);
        assert!(error.to_string().contains("no replacement result emitted"));
    }

    #[test]
    fn stdio_size_failure_writes_no_replacement_result_after_backend_return() {
        let input = [
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION}
            }),
            json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "closed_tool", "arguments": {"value": 7}}
            }),
        ]
        .into_iter()
        .map(|value| format!("{}\n", serde_json::to_string(&value).unwrap()))
        .collect::<String>();
        let mut effects = 0;
        let mut output = Vec::new();
        let error = serve(
            BufReader::new(Cursor::new(input)),
            &mut output,
            "fixture-server",
            tool(),
            |_| {
                effects += 1;
                Ok(structured_with_serialized_len(
                    CODEX_CALL_TOOL_RESULT_BYTES_CAP,
                ))
            },
        )
        .unwrap_err();
        assert_eq!(effects, 1);
        assert!(error.to_string().contains("no replacement result emitted"));
        let responses = String::from_utf8(output).unwrap();
        assert_eq!(responses.lines().count(), 1);
        let initialize = serde_json::from_str::<Value>(responses.lines().next().unwrap()).unwrap();
        assert_eq!(initialize["id"], 1);
    }
}
