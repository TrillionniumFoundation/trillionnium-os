//! Borrowed serialization of tool observations; base64 never builds a whole DOM.
use crate::protocol::{encode_snapshot, encode_terminal};
use crate::{MAX_JSONL_PROVIDER_OUTBOUND_LINE_BYTES, PROVIDER_PROTOCOL};
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
        let mut counter = CallbackCounter::default();
        if serde_json::to_writer(&mut counter, &result).is_err() || !counter.fits() {
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
// Admission against the shipped Python callback reader, not a second JSON
// decoder. serde_json owns syntax/Unicode/numeric validity; this fixed-size
// observer counts actual serialized bytes without allocating a result DOM.
const CALLBACK_JSON_BYTES: u64 = 256 * 1024;
const CALLBACK_JSON_WORK_BYTES: u64 = 16 * 1024 * 1024;
const CALLBACK_VALUE_NODES: u64 = 32768;
const CALLBACK_KEY_WORK_BYTES: u64 = 4 * 1024 * 1024;
const CALLBACK_STRING_ESCAPES: u64 = 32768;
const CALLBACK_DEPTH: usize = 64;

struct JsonBudget {
    bytes: u64,
    nodes: u64,
    owned: u64,
    non_ascii: bool,
    depth: usize,
    max_depth: usize,
    quoted: bool,
    escaped: bool,
    scalar: bool,
    scalar_bytes: u64,
    max_scalar_bytes: u64,
    string_bytes: u64,
    last_string_bytes: u64,
    keys: u64,
    key_work: u64,
    max_key_bytes: u64,
    object_keys: [u64; CALLBACK_DEPTH + 1],
    max_object_keys: u64,
    escapes: u64,
}
impl Default for JsonBudget {
    fn default() -> Self {
        Self {
            bytes: 0,
            nodes: 0,
            owned: 0,
            non_ascii: false,
            depth: 0,
            max_depth: 0,
            quoted: false,
            escaped: false,
            scalar: false,
            scalar_bytes: 0,
            max_scalar_bytes: 0,
            string_bytes: 0,
            last_string_bytes: 0,
            keys: 0,
            key_work: 0,
            max_key_bytes: 0,
            object_keys: [0; CALLBACK_DEPTH + 1],
            max_object_keys: 0,
            escapes: 0,
        }
    }
}
impl JsonBudget {
    fn observe(&mut self, byte: u8) {
        // The writer stops at 32 MiB, so all u64 counters stay finite even for
        // the densest possible token stream. No input-sized storage is kept.
        self.bytes += 1;
        self.non_ascii |= byte >= 128;
        if self.quoted {
            self.owned += 4;
            self.string_bytes += 1;
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
                self.escapes += 1;
            } else if byte == b'"' {
                self.quoted = false;
                self.last_string_bytes = self.string_bytes;
            }
            return;
        }
        match byte {
            b'"' => {
                self.quoted = true;
                self.scalar = false;
                self.string_bytes = 1;
                self.nodes += 1;
                self.owned += 256;
            }
            b'[' | b'{' => {
                self.scalar = false;
                self.depth += 1;
                self.max_depth = self.max_depth.max(self.depth);
                if self.depth <= CALLBACK_DEPTH {
                    self.object_keys[self.depth] = 0;
                }
                self.nodes += 1;
                self.owned += 512;
            }
            b']' | b'}' => {
                self.depth = self.depth.saturating_sub(1);
                self.scalar = false;
            }
            b':' => {
                self.scalar = false;
                self.keys += 1;
                self.key_work += self.last_string_bytes * 4 + 128;
                self.max_key_bytes = self.max_key_bytes.max(self.last_string_bytes);
                if self.depth <= CALLBACK_DEPTH {
                    self.object_keys[self.depth] += 1;
                    self.max_object_keys = self.max_object_keys.max(self.object_keys[self.depth]);
                }
            }
            b',' | b' ' | b'\t' | b'\r' | b'\n' => self.scalar = false,
            _ => {
                if !self.scalar {
                    self.scalar = true;
                    self.scalar_bytes = 0;
                    self.nodes += 1;
                    self.owned += 128;
                }
                self.scalar_bytes += 1;
                self.max_scalar_bytes = self.max_scalar_bytes.max(self.scalar_bytes);
            }
        }
    }
    fn scanner_fits(&self) -> bool {
        self.max_depth <= CALLBACK_DEPTH
            && self.nodes.saturating_sub(self.keys) <= CALLBACK_VALUE_NODES
            && self.key_work <= CALLBACK_KEY_WORK_BYTES
            && self.max_key_bytes <= 16 * 1024
            && self.max_object_keys <= 4096
            && self.escapes <= CALLBACK_STRING_ESCAPES
            && self.max_scalar_bytes <= 128
    }
    fn generic_fits(&self) -> bool {
        self.max_depth <= CALLBACK_DEPTH
            && self.nodes <= CALLBACK_VALUE_NODES
            && self.bytes * (if self.non_ascii { 5 } else { 2 }) + 2 * self.owned
                <= CALLBACK_JSON_WORK_BYTES
    }
}

#[derive(Default)]
struct CallbackCounter {
    full: JsonBudget,
    metadata: JsonBudget,
    root_string: [u8; 6],
    root_string_bytes: usize,
    capturing_root_string: bool,
    last_root_string_is_events: bool,
    events_value_pending: bool,
    omitted_array_depth: Option<usize>,
}
impl CallbackCounter {
    fn fits(&self) -> bool {
        self.full.scanner_fits()
            // The final raw size selects the consumer route. A short prefix's
            // generic budget cannot reject a later valid borrowed large frame.
            && if self.full.bytes <= CALLBACK_JSON_BYTES {
                self.full.generic_fits()
            } else {
                self.metadata.bytes <= CALLBACK_JSON_BYTES && self.metadata.generic_fits()
            }
    }
    fn observe(&mut self, byte: u8) {
        let quoted = self.full.quoted;
        let escaped = self.full.escaped;
        let depth = self.full.depth;
        if !quoted && byte == b'"' && depth == 1 {
            self.capturing_root_string = true;
            self.root_string_bytes = 0;
        } else if quoted && self.capturing_root_string {
            if byte == b'"' && !escaped {
                self.last_root_string_is_events =
                    self.root_string_bytes == 6 && self.root_string == *b"events";
                self.capturing_root_string = false;
            } else {
                if self.root_string_bytes < self.root_string.len() {
                    self.root_string[self.root_string_bytes] = byte;
                }
                self.root_string_bytes += 1;
            }
        }
        if !quoted && depth == 1 && byte == b':' {
            self.events_value_pending = self.last_root_string_is_events;
        }
        let omit = match self.omitted_array_depth {
            Some(array_depth) if !quoted && depth == array_depth && byte == b']' => {
                self.omitted_array_depth = None;
                false
            }
            Some(_) => true,
            None => false,
        };
        if !omit {
            self.metadata.observe(byte);
        }
        if self.events_value_pending && !quoted && byte != b':' && !byte.is_ascii_whitespace() {
            if byte == b'[' {
                // Keep an empty events array in the metadata reservation. The
                // consumer drops that member entirely, so this is conservative.
                self.omitted_array_depth = Some(depth + 1);
            }
            self.events_value_pending = false;
        }
        self.full.observe(byte);
    }
}
impl std::io::Write for CallbackCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        for &byte in bytes {
            if self.full.bytes + 1 >= MAX_JSONL_PROVIDER_OUTBOUND_LINE_BYTES as u64 {
                return Err(std::io::Error::other(
                    "provider outbound observation exceeds its bound",
                ));
            }
            self.observe(byte);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
    use crate::encoded_line_size;
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
    fn fragmented_fixture(count: usize, bytes: usize) -> ToolOutcome {
        let mut outcome = fixture(Vec::new());
        if let ToolOutcome::Executed {
            events, terminal, ..
        } = &mut outcome
        {
            terminal.stdout_bytes = (count * bytes) as u64;
            events.clear();
            let mut push = |kind| {
                events.push(ExecutionEvent {
                    call_id: "call".into(),
                    target_id: None,
                    tool: trillionnium_owner_open_runtime::ToolKind::ShellExec,
                    seq: events.len() as u64,
                    elapsed_ms: 1,
                    kind,
                });
            };
            push(ExecutionEventKind::Accepted);
            push(ExecutionEventKind::Started { pid: 123 });
            for _ in 0..count {
                push(ExecutionEventKind::Output {
                    stream: StreamKind::Stdout,
                    bytes: vec![b'x'; bytes],
                });
            }
            push(ExecutionEventKind::Terminal(terminal.clone()));
        }
        outcome
    }

    fn assert_native_consumer_preserves_metadata(response: &impl Serialize, should_accept: bool) {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let program = r#"
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve().parents[1]
sys.path[:0] = [str(root / 'tools/owner-open'), str(root / 'crates/trillionnium-owner-open-provider-jsonl/python')]
import codex_callback_observation as observation
raw = sys.stdin.buffer.read(32 * 1024 * 1024 + 1)
source = json.loads(raw)
projected = observation.decode_host_observation(raw)
reply = observation.native_tool_result_reply(17, projected)
result = json.loads(json.loads(reply)['result']['contentItems'][0]['text'])
for key, value in source.items():
    if key != 'events':
        assert result[key] == value, key
if source.get('events_truncated'):
    assert source['events'] == []
    assert source['observation_gap']['domain'] == 'tool_execution_event'
    assert source['observation_gap']['call_id'] == source['call_id']
assert len(reply) <= observation.MAX_NATIVE_REPLY_BYTES
"#;
        let mut child = Command::new("python3")
            .args(["-c", program])
            .arg(source)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Python consumer fixture");
        let mut input = child.stdin.take().unwrap();
        input
            .write_all(&serde_json::to_vec(response).unwrap())
            .unwrap();
        drop(input);
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.success(),
            should_accept,
            "native callback consumer: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn fragmented_callback_observations_fit_both_native_decoder_routes() {
        for (count, bytes) in [
            (1274, 1),
            (1275, 1),
            (1400, 1),
            (1500, 1),
            (2356, 64),
            (2357, 64),
            (3000, 64),
            (4093, 1),
        ] {
            let response = ToolResult::new(1, "call", fragmented_fixture(count, bytes));
            assert_native_consumer_preserves_metadata(&response, true);
            if response.truncated {
                let value = serde_json::to_value(&response).unwrap();
                assert_eq!(value["observation_gap"]["event_count"], count + 3);
                assert_eq!(value["observation_gap"]["output_bytes"], count * bytes);
                assert_eq!(value["terminal"]["output_truncated"], false);
            }
        }
    }

    #[test]
    fn default_fragmented_sixteen_mib_remains_complete_on_the_provider_wire() {
        for (count, bytes) in [(1024, 16384), (2048, 8192)] {
            let response = ToolResult::new(1, "call", fragmented_fixture(count, bytes));
            assert!(!response.truncated);
            assert_native_consumer_preserves_metadata(&response, true);
        }
    }

    #[test]
    fn callback_unicode_escaped_identity_and_long_metadata_keep_terminal_truth() {
        let mut outcome = fragmented_fixture(1400, 1);
        if let ToolOutcome::Executed {
            events,
            snapshot,
            terminal,
            ..
        } = &mut outcome
        {
            snapshot.request.target_id = Some("目标\\\"".repeat(100));
            terminal.error = Some("literal \"\\\n终端".repeat(32));
            for event in events {
                event.target_id.clone_from(&snapshot.request.target_id);
            }
        }
        let response = ToolResult::new(1, "call", outcome);
        assert_native_consumer_preserves_metadata(&response, true);

        let mut outcome = fragmented_fixture(3000, 1);
        if let ToolOutcome::Executed { terminal, .. } = &mut outcome {
            terminal.error = Some("M".repeat(300 * 1024));
        }
        let response = ToolResult::new(1, "call", outcome);
        assert_native_consumer_preserves_metadata(&response, false);
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            value["terminal"]["error"].as_str().unwrap().len(),
            300 * 1024
        );
        assert_eq!(value["terminal"]["output_truncated"], false);
    }
    #[test]
    fn callback_counter_uses_final_route_and_does_not_skip_nested_or_escaped_keys() {
        let mut value = serde_json::to_value(ToolResult::new(1, "call", fixture(vec![1]))).unwrap();
        value["unknown_metadata"] = json!({
            "escaped\"键": "literal \\\"events\": [ and Unicode 🙂",
            "nested": {"events": [1, 2, 3]}
        });
        let mut counter = CallbackCounter::default();
        serde_json::to_writer(&mut counter, &value).unwrap();
        assert!(counter.fits());
        assert!(counter.full.non_ascii);
        assert!(counter.metadata.non_ascii);
        assert_native_consumer_preserves_metadata(&value, true);

        value["unknown_metadata"]["nested"]["events"] = json!("M".repeat(300 * 1024));
        let mut counter = CallbackCounter::default();
        serde_json::to_writer(&mut counter, &value).unwrap();
        assert!(counter.metadata.bytes > CALLBACK_JSON_BYTES);
        assert!(!counter.fits());
        assert_native_consumer_preserves_metadata(&value, false);
    }

    #[test]
    fn callback_counter_checks_every_structural_ceiling() {
        fn fits(value: Value) -> bool {
            let mut counter = CallbackCounter::default();
            serde_json::to_writer(&mut counter, &value).unwrap();
            counter.fits()
        }
        assert!(!fits(json!({"key": "\\".repeat(32769)})));
        assert!(!fits(json!({"key": vec![0; 32769]})));
        assert!(!fits(Value::Object(
            [("K".repeat(16 * 1024), Value::Null)].into_iter().collect()
        )));
        let dense = (0..4097)
            .map(|index| (index.to_string(), Value::Null))
            .collect::<serde_json::Map<_, _>>();
        assert!(!fits(Value::Object(dense)));
        let mut nested = Value::Null;
        for _ in 0..65 {
            nested = json!([nested]);
        }
        assert!(!fits(nested));
    }
    #[test]
    fn callback_counter_constants_match_the_shipped_consumer() {
        use std::process::Command;
        let program = r#"
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve().parents[1]
sys.path[:0] = [str(root / 'tools/owner-open'), str(root / 'crates/trillionnium-owner-open-provider-jsonl/python')]
import codex_callback_observation as observation
import jsonl_provider_runtime as runtime
print(json.dumps([observation.MAX_HOST_FRAME_BYTES, observation.MAX_NATIVE_REPLY_BYTES, runtime.MAX_JSON_DECODE_WORKING_BYTES,
 observation.MAX_VALUE_NODES, runtime.MAX_JSON_VALUE_COUNT, observation.MAX_KEY_WORKING_BYTES,
 observation.MAX_STRING_ESCAPES, observation.MAX_DEPTH, observation.MAX_METADATA_BYTES,
 observation.MAX_KEY_BYTES, observation.MAX_OBJECT_KEYS, observation.MAX_NUMBER_BYTES]))
"#;
        let output = Command::new("python3")
            .args(["-c", program, env!("CARGO_MANIFEST_DIR")])
            .output()
            .expect("Python callback constants");
        assert!(output.status.success());
        let actual: Vec<u64> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            actual,
            vec![
                MAX_JSONL_PROVIDER_OUTBOUND_LINE_BYTES as u64,
                CALLBACK_JSON_BYTES,
                CALLBACK_JSON_WORK_BYTES,
                CALLBACK_VALUE_NODES,
                CALLBACK_VALUE_NODES,
                CALLBACK_KEY_WORK_BYTES,
                CALLBACK_STRING_ESCAPES,
                CALLBACK_DEPTH as u64,
                CALLBACK_JSON_BYTES,
                16 * 1024,
                4096,
                128,
            ]
        );
    }
}
