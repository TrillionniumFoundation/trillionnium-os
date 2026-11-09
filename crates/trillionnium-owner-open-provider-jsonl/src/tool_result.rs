//! Borrowed serialization of tool observations; base64 never builds a whole DOM.
use crate::protocol::{encode_snapshot, encode_terminal};
use crate::{MAX_JSONL_PROVIDER_OUTBOUND_LINE_BYTES, PROVIDER_PROTOCOL, encoded_line_size};
use base64::{display::Base64Display, engine::general_purpose::STANDARD};
use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};
use serde_json::{Value, json};
use trillionnium_owner_open_runtime::{ExecutionEvent, ExecutionEventKind, StreamKind};
use trillionnium_owner_open_turn_loop::ToolOutcome;

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Response {
    Tool(Box<ToolResult>),
    Value(Value),
}

pub(crate) struct ToolResult {
    seq: u64,
    call_id: String,
    outcome: ToolOutcome,
    truncated: bool,
}
impl ToolResult {
    pub(crate) fn new(seq: u64, call_id: &str, outcome: ToolOutcome) -> Self {
        let mut result = Self {
            seq,
            call_id: call_id.to_owned(),
            outcome,
            truncated: false,
        };
        // Observation overflow must not erase effectful terminal/identity truth
        // or invent runtime truncation. Publish an explicit event-domain gap.
        if encoded_line_size(&result, MAX_JSONL_PROVIDER_OUTBOUND_LINE_BYTES).is_err() {
            result.truncated = true;
        }
        result
    }
}
impl Serialize for ToolResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("protocol", PROVIDER_PROTOCOL)?;
        map.serialize_entry("kind", "tool.result")?;
        map.serialize_entry("seq", &self.seq)?;
        map.serialize_entry("call_id", &self.call_id)?;
        match &self.outcome {
            ToolOutcome::Executed {
                generation,
                events,
                terminal,
                observation_sha256,
                snapshot,
            } => {
                map.serialize_entry("status", "terminal")?;
                map.serialize_entry("generation", generation)?;
                map.serialize_entry("events", &Events(if self.truncated { &[] } else { events }))?;
                map.serialize_entry("terminal", &encode_terminal(terminal))?;
                map.serialize_entry("observation_sha256", observation_sha256)?;
                map.serialize_entry("registry", &encode_snapshot(snapshot))?;
                if self.truncated {
                    let bytes: u64 = events
                        .iter()
                        .filter_map(|event| match &event.kind {
                            ExecutionEventKind::Output { bytes, .. } => Some(bytes.len() as u64),
                            _ => None,
                        })
                        .fold(0, u64::saturating_add);
                    map.serialize_entry("events_truncated", &true)?;
                    map.serialize_entry(
                        "observation_gap",
                        &json!({
                            "domain": "tool_execution_event", "call_id": &self.call_id,
                            "first_seq": events.first().map(|event| event.seq),
                            "last_seq": events.last().map(|event| event.seq),
                            "event_count": events.len(), "output_bytes": bytes,
                            "reason": "provider_outbound_observation_budget"
                        }),
                    )?;
                }
            }
            ToolOutcome::Existing(snapshot) | ToolOutcome::Inhibited(snapshot) => {
                map.serialize_entry(
                    "status",
                    if matches!(&self.outcome, ToolOutcome::Existing(_)) {
                        "existing"
                    } else {
                        "inhibited"
                    },
                )?;
                map.serialize_entry("registry", &encode_snapshot(snapshot))?;
            }
        }
        map.end()
    }
}
struct Events<'a>(&'a [ExecutionEvent]);
impl Serialize for Events<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for event in self.0 {
            sequence.serialize_element(&Event(event))?;
        }
        sequence.end()
    }
}
struct Event<'a>(&'a ExecutionEvent);
impl Serialize for Event<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("call_id", &self.0.call_id)?;
        map.serialize_entry("target_id", &self.0.target_id)?;
        map.serialize_entry("tool", self.0.tool.as_str())?;
        map.serialize_entry("seq", &self.0.seq)?;
        map.serialize_entry("elapsed_ms", &self.0.elapsed_ms)?;
        map.serialize_entry("event", &Body(&self.0.kind))?;
        map.end()
    }
}
struct Body<'a>(&'a ExecutionEventKind);
impl Serialize for Body<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        match self.0 {
            ExecutionEventKind::Accepted => {
                map.serialize_entry("kind", "accepted")?;
            }
            ExecutionEventKind::Started { pid } => {
                map.serialize_entry("kind", "started")?;
                map.serialize_entry("pid", pid)?;
            }
            ExecutionEventKind::Output { stream, bytes } => {
                map.serialize_entry("kind", "output")?;
                map.serialize_entry(
                    "stream",
                    match stream {
                        StreamKind::Stdout => "stdout",
                        StreamKind::Stderr => "stderr",
                        StreamKind::Pty => "pty",
                    },
                )?;
                map.serialize_entry("encoding", "base64")?;
                map.serialize_entry("data", &EncodedBytes(bytes))?;
                map.serialize_entry("byte_count", &bytes.len())?;
            }
            ExecutionEventKind::Terminal(terminal) => {
                map.serialize_entry("kind", "terminal")?;
                map.serialize_entry("terminal", &encode_terminal(terminal))?;
            }
        }
        map.end()
    }
}
struct EncodedBytes<'a>(&'a [u8]);
impl Serialize for EncodedBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&Base64Display::new(self.0, &STANDARD))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use trillionnium_owner_open_call_registry::{
        CallKey, CallRequest, CallSnapshot, EffectiveState, TurnScope,
    };
    use trillionnium_owner_open_runtime::{ExecutionTerminal, TerminalKind, ToolKind};

    fn fixture(bytes: Vec<u8>) -> ToolOutcome {
        let count = bytes.len() as u64;
        let terminal = ExecutionTerminal {
            kind: TerminalKind::Exited,
            exit_code: Some(0),
            signal: None,
            stdout_bytes: count,
            stderr_bytes: 0,
            output_truncated: false,
            elapsed_ms: 1,
            error: None,
        };
        ToolOutcome::Executed {
            generation: 7,
            events: vec![ExecutionEvent {
                call_id: "call".into(),
                target_id: None,
                tool: ToolKind::ShellExec,
                seq: 3,
                elapsed_ms: 1,
                kind: ExecutionEventKind::Output {
                    stream: StreamKind::Stdout,
                    bytes,
                },
            }],
            terminal,
            observation_sha256: "b".repeat(64),
            snapshot: CallSnapshot {
                key: CallKey::new(TurnScope::new("s", "p", "t", "turn", "stream"), "call"),
                request: CallRequest::new("a".repeat(64), "b".repeat(64), "shell.exec", None),
                state: EffectiveState::Started {
                    generation: 7,
                    pid: Some(123),
                },
                cancellation_requested: false,
                connection_lost: false,
                earliest_history_seq: 0,
                next_event_seq: 4,
            },
        }
    }

    #[test]
    fn borrowed_base64_preserves_exact_bytes_and_default_full_output_fits() {
        let bytes = (0..=255).collect::<Vec<u8>>();
        let expected = STANDARD.encode(&bytes);
        let response = ToolResult::new(1, "call", fixture(bytes));
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["events"][0]["event"]["data"], expected);
        assert_eq!(value["terminal"]["output_truncated"], false);
        assert!(value.get("events_truncated").is_none());
        let response = ToolResult::new(1, "call", fixture(vec![0x42; 16 * 1024 * 1024]));
        assert!(!response.truncated);
        assert!(
            encoded_line_size(&response, MAX_JSONL_PROVIDER_OUTBOUND_LINE_BYTES).unwrap()
                < MAX_JSONL_PROVIDER_OUTBOUND_LINE_BYTES
        );
    }

    #[test]
    fn oversized_observations_preserve_terminal_and_duplicate_identity_with_explicit_gap() {
        let response = ToolResult::new(2, "call", fixture(vec![0x42; 26 * 1024 * 1024]));
        assert!(response.truncated);
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["status"], "terminal");
        assert_eq!(value["generation"], 7);
        assert_eq!(value["registry"]["call_id"], "call");
        assert_eq!(value["registry"]["request_sha256"], "a".repeat(64));
        assert_eq!(value["terminal"]["exit_code"], 0);
        assert_eq!(value["terminal"]["output_truncated"], false);
        assert_eq!(value["terminal"]["stdout_bytes"], 26 * 1024 * 1024);
        assert_eq!(value["events_truncated"], true);
        assert_eq!(value["observation_gap"]["first_seq"], 3);
        assert_eq!(value["observation_gap"]["last_seq"], 3);
        assert_eq!(value["observation_gap"]["output_bytes"], 26 * 1024 * 1024);
        assert_eq!(value["events"], json!([]));
        assert!(
            encoded_line_size(&response, MAX_JSONL_PROVIDER_OUTBOUND_LINE_BYTES).unwrap() < 4096
        );
    }
}
