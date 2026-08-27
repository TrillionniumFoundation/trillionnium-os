//! Strict client contract for the Root-Linux Agent API v2 UDS carrier.
//!
//! The semantic Agent API remains `trillionnium.agent-api.v1`. This crate
//! versions only its UDS framing/authentication carrier. There is deliberately
//! no v1 socket fallback: a legacy one-response client must fail at connect
//! instead of interpreting a v2 channel-binding challenge as a final response.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;
pub use trillionnium_os_types::direct_agent_host_abi::{
    KERNEL_AGENT_API_PROTOCOL as AGENT_API_UDS_PROTOCOL,
    KERNEL_AGENT_API_SOCKET as DEFAULT_AGENT_API_SOCKET,
};
use trillionnium_os_types::{direct_agent_host_abi, is_lower_sha256};

pub const AGENT_API_CHANNEL_AUTH_SCHEMA: &str = "trillionnium.agent-api.state-change-auth.v1";
pub const MAX_AGENT_API_FRAME_BYTES: usize = 262_144;
pub const DEFAULT_AGENT_API_CALL_TIMEOUT: Duration = Duration::from_secs(20);
const CHANNEL_BINDING_CHALLENGE_TYPE: &str = "channel_binding_challenge";

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentApiRequest {
    pub protocol: &'static str,
    pub request_id: String,
    pub method: String,
    pub agent_id: String,
    pub payload: Value,
}

impl AgentApiRequest {
    pub fn new(
        request_id: impl Into<String>,
        method: impl Into<String>,
        agent_id: impl Into<String>,
        payload: Value,
    ) -> Result<Self, AgentApiUdsClientError> {
        let request = Self {
            protocol: AGENT_API_UDS_PROTOCOL,
            request_id: request_id.into(),
            method: method.into(),
            agent_id: agent_id.into(),
            payload,
        };
        if !valid_request_id(&request.request_id) {
            return Err(AgentApiUdsClientError::InvalidRequest(
                "invalid request_id".to_string(),
            ));
        }
        if !is_enabled_agent_api_method(&request.method) {
            return Err(AgentApiUdsClientError::InvalidRequest(
                "invalid method".to_string(),
            ));
        }
        if !request.agent_id.is_empty() && !valid_agent_id(&request.agent_id) {
            return Err(AgentApiUdsClientError::InvalidRequest(
                "invalid agent_id".to_string(),
            ));
        }
        if request.method != direct_agent_host_abi::KERNEL_WIRE_METHOD_HEALTH
            && request.agent_id.is_empty()
        {
            return Err(AgentApiUdsClientError::InvalidRequest(
                "agent_id is required for this method".to_string(),
            ));
        }
        if !request.payload.is_object() {
            return Err(AgentApiUdsClientError::InvalidRequest(
                "payload must be an object".to_string(),
            ));
        }
        Ok(request)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentApiResponse {
    pub protocol: String,
    pub request_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Error)]
pub enum AgentApiUdsClientError {
    #[error("invalid Agent API request: {0}")]
    InvalidRequest(String),
    #[error("failed to connect to Agent API v2 socket {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Agent API v2 I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Agent API v2 absolute call deadline exhausted")]
    DeadlineExceeded,
    #[error("Agent API v2 frame is empty, truncated, or exceeds the byte bound")]
    FrameBoundary,
    #[error("invalid Agent API v2 JSON frame: {0}")]
    InvalidFrame(#[from] serde_json::Error),
    #[error("Agent API v2 response binding mismatch: {0}")]
    ResponseBinding(&'static str),
    #[error("Agent API v2 challenge is invalid: {0}")]
    InvalidChallenge(&'static str),
    #[error("Agent API method {0} received an unexpected channel-binding challenge")]
    UnexpectedChallenge(String),
    #[error("Agent API method {0} succeeded without its required channel-binding challenge")]
    MissingChallenge(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeFrame {
    protocol: String,
    request_id: String,
    #[serde(rename = "type")]
    frame_type: String,
    challenge: ChannelBinding,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChannelBinding {
    schema: String,
    nonce: String,
    request_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalFrame {
    protocol: String,
    request_id: String,
    ok: bool,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ServerFrame {
    Challenge(ChallengeFrame),
    Final(FinalFrame),
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundAgentApiRequest<'a> {
    protocol: &'static str,
    request_id: &'a str,
    method: &'a str,
    agent_id: &'a str,
    payload: &'a Value,
    channel_binding: &'a ChannelBinding,
}

pub fn requires_channel_binding(method: &str) -> bool {
    match method {
        "register_agent" | "create_task" | "cancel_task" | "read_context_grant"
        | "read_memory_grant" => true,
        #[cfg(feature = "legacy-plan-methods")]
        "submit_plan" | "run_tool" => true,
        _ => false,
    }
}

pub fn call(
    socket_path: impl AsRef<Path>,
    request: &AgentApiRequest,
    timeout: Duration,
) -> Result<AgentApiResponse, AgentApiUdsClientError> {
    let path = socket_path.as_ref();
    let stream = UnixStream::connect(path).map_err(|source| AgentApiUdsClientError::Connect {
        path: path.to_path_buf(),
        source,
    })?;
    call_on_stream(stream, request, timeout)
}

pub fn call_on_stream(
    stream: UnixStream,
    request: &AgentApiRequest,
    timeout: Duration,
) -> Result<AgentApiResponse, AgentApiUdsClientError> {
    if timeout.is_zero() {
        return Err(AgentApiUdsClientError::DeadlineExceeded);
    }
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(AgentApiUdsClientError::DeadlineExceeded)?;
    let mut framed = DeadlineFramedStream::new(stream, deadline);
    framed.write_json(request)?;
    match framed.read_server_frame()? {
        ServerFrame::Challenge(challenge) => {
            validate_challenge(request, &challenge)?;
            if !requires_channel_binding(&request.method) {
                return Err(AgentApiUdsClientError::UnexpectedChallenge(
                    request.method.clone(),
                ));
            }
            let bound = BoundAgentApiRequest {
                protocol: AGENT_API_UDS_PROTOCOL,
                request_id: &request.request_id,
                method: &request.method,
                agent_id: &request.agent_id,
                payload: &request.payload,
                channel_binding: &challenge.challenge,
            };
            framed.write_json(&bound)?;
            match framed.read_server_frame()? {
                ServerFrame::Challenge(_) => Err(AgentApiUdsClientError::InvalidChallenge(
                    "a second challenge is forbidden",
                )),
                ServerFrame::Final(response) => validate_final(request, response),
            }
        }
        ServerFrame::Final(response) => {
            let response = validate_final(request, response)?;
            if response.ok && requires_channel_binding(&request.method) {
                return Err(AgentApiUdsClientError::MissingChallenge(
                    request.method.clone(),
                ));
            }
            Ok(response)
        }
    }
}

fn validate_challenge(
    request: &AgentApiRequest,
    challenge: &ChallengeFrame,
) -> Result<(), AgentApiUdsClientError> {
    if challenge.protocol != AGENT_API_UDS_PROTOCOL {
        return Err(AgentApiUdsClientError::ResponseBinding("protocol"));
    }
    if challenge.request_id != request.request_id {
        return Err(AgentApiUdsClientError::ResponseBinding("request_id"));
    }
    if challenge.frame_type != CHANNEL_BINDING_CHALLENGE_TYPE {
        return Err(AgentApiUdsClientError::InvalidChallenge("type"));
    }
    if challenge.challenge.schema != AGENT_API_CHANNEL_AUTH_SCHEMA {
        return Err(AgentApiUdsClientError::InvalidChallenge("schema"));
    }
    if !is_lower_sha256(&challenge.challenge.nonce) {
        return Err(AgentApiUdsClientError::InvalidChallenge("nonce"));
    }
    if !is_lower_sha256(&challenge.challenge.request_sha256) {
        return Err(AgentApiUdsClientError::InvalidChallenge("request_sha256"));
    }
    Ok(())
}

fn validate_final(
    request: &AgentApiRequest,
    response: FinalFrame,
) -> Result<AgentApiResponse, AgentApiUdsClientError> {
    if response.protocol != AGENT_API_UDS_PROTOCOL {
        return Err(AgentApiUdsClientError::ResponseBinding("protocol"));
    }
    if response.request_id != request.request_id {
        return Err(AgentApiUdsClientError::ResponseBinding("request_id"));
    }
    if response.ok {
        if response.result.is_none() || response.error.is_some() {
            return Err(AgentApiUdsClientError::ResponseBinding(
                "successful response shape",
            ));
        }
    } else if response.result.is_some() || response.error.as_deref().is_none_or(str::is_empty) {
        return Err(AgentApiUdsClientError::ResponseBinding(
            "error response shape",
        ));
    }
    Ok(AgentApiResponse {
        protocol: response.protocol,
        request_id: response.request_id,
        ok: response.ok,
        result: response.result,
        error: response.error,
    })
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_agent_id(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub fn is_product_agent_api_method(method: &str) -> bool {
    matches!(
        method,
        direct_agent_host_abi::KERNEL_WIRE_METHOD_HEALTH
            | "register_agent"
            | "list_tools"
            | direct_agent_host_abi::KERNEL_WIRE_METHOD_CREATE_TASK
            | direct_agent_host_abi::KERNEL_WIRE_METHOD_CANCEL_TASK
            | "list_data_grants"
            | "read_context_grant"
            | "read_memory_grant"
    )
}

pub fn is_enabled_agent_api_method(method: &str) -> bool {
    is_product_agent_api_method(method)
        || cfg!(feature = "legacy-plan-methods") && matches!(method, "submit_plan" | "run_tool")
}

/// Recursive JSON decoder that rejects duplicate object members before a
/// typed server-frame decoder can observe last-wins `serde_json::Value` data.
struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_string())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJson>()? {
            output.push(value.0);
        }
        Ok(UniqueJson(Value::Array(output)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if output.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate key {key}")));
            }
            let value = map.next_value::<UniqueJson>()?;
            output.insert(key, value.0);
        }
        Ok(UniqueJson(Value::Object(output)))
    }
}

fn decode_server_frame(encoded: &[u8]) -> Result<ServerFrame, AgentApiUdsClientError> {
    let mut deserializer = serde_json::Deserializer::from_slice(encoded);
    let UniqueJson(value) = UniqueJson::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(serde_json::from_value(value)?)
}

struct DeadlineFramedStream {
    stream: UnixStream,
    deadline: Instant,
    pending: Vec<u8>,
}

impl DeadlineFramedStream {
    fn new(stream: UnixStream, deadline: Instant) -> Self {
        Self {
            stream,
            deadline,
            pending: Vec::new(),
        }
    }

    fn remaining(&self) -> Result<Duration, AgentApiUdsClientError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(AgentApiUdsClientError::DeadlineExceeded)
    }

    fn write_json<T: Serialize>(&mut self, value: &T) -> Result<(), AgentApiUdsClientError> {
        let mut encoded = serde_json::to_vec(value)?;
        if encoded.is_empty() || encoded.len() > MAX_AGENT_API_FRAME_BYTES {
            return Err(AgentApiUdsClientError::FrameBoundary);
        }
        encoded.push(b'\n');
        let mut written = 0;
        while written < encoded.len() {
            self.stream.set_write_timeout(Some(self.remaining()?))?;
            match self.stream.write(&encoded[written..]) {
                Ok(0) => return Err(AgentApiUdsClientError::FrameBoundary),
                Ok(count) => written += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Err(AgentApiUdsClientError::DeadlineExceeded);
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush()?;
        Ok(())
    }

    fn read_server_frame(&mut self) -> Result<ServerFrame, AgentApiUdsClientError> {
        loop {
            if let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                if end == 0 || end > MAX_AGENT_API_FRAME_BYTES {
                    return Err(AgentApiUdsClientError::FrameBoundary);
                }
                let encoded = self.pending[..end].to_vec();
                self.pending.drain(..=end);
                return decode_server_frame(&encoded);
            }
            if self.pending.len() > MAX_AGENT_API_FRAME_BYTES {
                return Err(AgentApiUdsClientError::FrameBoundary);
            }
            self.stream.set_read_timeout(Some(self.remaining()?))?;
            let mut buffer = [0u8; 8192];
            match self.stream.read(&mut buffer) {
                Ok(0) => return Err(AgentApiUdsClientError::FrameBoundary),
                Ok(count) => self.pending.extend_from_slice(&buffer[..count]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Err(AgentApiUdsClientError::DeadlineExceeded);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::thread;

    use serde_json::{Value, json};

    use super::*;

    fn read_json(reader: &mut BufReader<UnixStream>) -> Value {
        let mut encoded = String::new();
        reader.read_line(&mut encoded).unwrap();
        serde_json::from_str(&encoded).unwrap()
    }

    fn write_json(stream: &mut UnixStream, value: &Value) {
        stream.write_all(value.to_string().as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
    }

    fn request(method: &str) -> AgentApiRequest {
        AgentApiRequest::new(
            format!("request-{method}"),
            method,
            "agent-fixture",
            json!({"task_id":"task-fixture"}),
        )
        .unwrap()
    }

    #[test]
    fn direct_health_response_is_strict_and_bound() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server_thread = thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let first = read_json(&mut reader);
            assert_eq!(first["protocol"], AGENT_API_UDS_PROTOCOL);
            write_json(
                &mut server,
                &json!({
                    "protocol": AGENT_API_UDS_PROTOCOL,
                    "request_id": first["request_id"],
                    "ok": true,
                    "result": {"api_version":"trillionnium.agent-api.v1"}
                }),
            );
        });
        let response = call_on_stream(client, &request("health"), Duration::from_secs(2)).unwrap();
        assert!(response.ok);
        server_thread.join().unwrap();
    }

    fn assert_challenge_exchange(method: &'static str) {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server_thread = thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let first = read_json(&mut reader);
            assert!(first.get("channel_binding").is_none());
            let challenge = json!({
                "protocol": AGENT_API_UDS_PROTOCOL,
                "request_id": first["request_id"],
                "type": CHANNEL_BINDING_CHALLENGE_TYPE,
                "challenge": {
                    "schema": AGENT_API_CHANNEL_AUTH_SCHEMA,
                    "nonce": "a".repeat(64),
                    "request_sha256": "b".repeat(64)
                }
            });
            write_json(&mut server, &challenge);
            let bound = read_json(&mut reader);
            assert_eq!(bound["protocol"], first["protocol"]);
            assert_eq!(bound["request_id"], first["request_id"]);
            assert_eq!(bound["method"], first["method"]);
            assert_eq!(bound["agent_id"], first["agent_id"]);
            assert_eq!(bound["payload"], first["payload"]);
            assert_eq!(bound["channel_binding"], challenge["challenge"]);
            write_json(
                &mut server,
                &json!({
                    "protocol": AGENT_API_UDS_PROTOCOL,
                    "request_id": first["request_id"],
                    "ok": true,
                    "result": {"accepted":true}
                }),
            );
        });
        let response = call_on_stream(client, &request(method), Duration::from_secs(2)).unwrap();
        assert!(response.ok);
        server_thread.join().unwrap();
    }

    #[test]
    fn mutation_uses_two_frame_v2_exchange() {
        assert_challenge_exchange("cancel_task");
    }

    #[test]
    fn consuming_grant_reads_use_two_frame_v2_exchange() {
        assert_challenge_exchange("read_context_grant");
        assert_challenge_exchange("read_memory_grant");
    }

    #[test]
    fn v1_response_has_no_fallback() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server_thread = thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let first = read_json(&mut reader);
            write_json(
                &mut server,
                &json!({
                    "protocol": "trillionnium.agent-api.uds.v1",
                    "request_id": first["request_id"],
                    "ok": true,
                    "result": {}
                }),
            );
        });
        let error = call_on_stream(client, &request("health"), Duration::from_secs(2)).unwrap_err();
        assert!(matches!(
            error,
            AgentApiUdsClientError::ResponseBinding("protocol")
        ));
        server_thread.join().unwrap();
    }

    #[test]
    fn readonly_method_rejects_unsolicited_challenge() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server_thread = thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let first = read_json(&mut reader);
            write_json(
                &mut server,
                &json!({
                    "protocol": AGENT_API_UDS_PROTOCOL,
                    "request_id": first["request_id"],
                    "type": CHANNEL_BINDING_CHALLENGE_TYPE,
                    "challenge": {
                        "schema": AGENT_API_CHANNEL_AUTH_SCHEMA,
                        "nonce": "a".repeat(64),
                        "request_sha256": "b".repeat(64)
                    }
                }),
            );
        });
        let error = call_on_stream(client, &request("health"), Duration::from_secs(2)).unwrap_err();
        assert!(
            matches!(error, AgentApiUdsClientError::UnexpectedChallenge(method) if method == "health")
        );
        server_thread.join().unwrap();
    }

    #[test]
    fn success_without_required_challenge_is_rejected() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server_thread = thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let first = read_json(&mut reader);
            write_json(
                &mut server,
                &json!({
                    "protocol": AGENT_API_UDS_PROTOCOL,
                    "request_id": first["request_id"],
                    "ok": true,
                    "result": {}
                }),
            );
        });
        let error =
            call_on_stream(client, &request("cancel_task"), Duration::from_secs(2)).unwrap_err();
        assert!(
            matches!(error, AgentApiUdsClientError::MissingChallenge(method) if method == "cancel_task")
        );
        server_thread.join().unwrap();
    }

    #[test]
    fn request_identifiers_use_the_server_grammar() {
        assert!(AgentApiRequest::new("req:one-2_3.4", "health", "", json!({})).is_ok());
        assert!(AgentApiRequest::new("req/one", "health", "", json!({})).is_err());
        assert!(AgentApiRequest::new("req-one", "unknown", "agent-fixture", json!({})).is_err());
        assert!(AgentApiRequest::new("req-one", "list_tools", "agent/bad", json!({})).is_err());
        assert!(AgentApiRequest::new("req-one", "list_tools", "", json!({})).is_err());
    }

    #[cfg(not(feature = "legacy-plan-methods"))]
    #[test]
    fn production_contract_rejects_retired_plan_execution_methods() {
        for method in ["submit_plan", "run_tool"] {
            assert!(!is_product_agent_api_method(method));
            assert!(!is_enabled_agent_api_method(method));
            assert!(!requires_channel_binding(method));
            assert!(
                AgentApiRequest::new("req-retired", method, "agent-fixture", json!({})).is_err()
            );
        }
    }

    #[cfg(feature = "legacy-plan-methods")]
    #[test]
    fn explicit_legacy_feature_retains_historical_method_vectors() {
        for method in ["submit_plan", "run_tool"] {
            assert!(!is_product_agent_api_method(method));
            assert!(is_enabled_agent_api_method(method));
            assert!(requires_channel_binding(method));
            assert!(AgentApiRequest::new("req-legacy", method, "agent-fixture", json!({})).is_ok());
        }
    }

    #[test]
    fn duplicate_keys_are_rejected_recursively() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let server_thread = thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let first = read_json(&mut reader);
            let encoded = format!(
                "{{\"protocol\":\"{}\",\"request_id\":\"{}\",\"ok\":true,\"result\":{{\"value\":1,\"value\":2}}}}\n",
                AGENT_API_UDS_PROTOCOL,
                first["request_id"].as_str().unwrap(),
            );
            server.write_all(encoded.as_bytes()).unwrap();
        });
        let error = call_on_stream(client, &request("health"), Duration::from_secs(2)).unwrap_err();
        assert!(matches!(error, AgentApiUdsClientError::InvalidFrame(_)));
        server_thread.join().unwrap();
    }
}
