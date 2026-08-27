use std::env;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::{Value, json};
use trillionnium_owner_open_call_registry::{CallRegistry, CallSnapshot};
use trillionnium_owner_open_provider_jsonl::{JsonlProvider, JsonlProviderConfig};
use trillionnium_owner_open_runtime::{ExecutionEvent, ExecutionEventKind, StreamKind};
use trillionnium_owner_open_turn_loop::{
    ProviderEvent, ProviderTerminal, ToolOutcome, TurnEvent, TurnEventKind,
    TurnRequest as LoopTurnRequest, TurnRunner,
};
use trillionnium_owner_open_types::{
    FRAME_HELLO, FRAME_HELLO_ACK, FRAME_MODEL_DELTA, FRAME_MODEL_MESSAGE,
    FRAME_PROVIDER_STATUS, FRAME_TOOL_ACCEPTED, FRAME_TOOL_RESULT, FRAME_TOOL_STARTED,
    FRAME_TOOL_STDERR, FRAME_TOOL_STDOUT, FRAME_TURN_ACCEPTED, FRAME_TURN_END,
    FRAME_TURN_START, MechanicalLimits, PROTOCOL, PROTOCOL_VERSION, RunTurnFrame,
};

const FRAME_HOST_ERROR: &str = "host.error";
const HOST_IMPLEMENTATION: &str = "trillionnium-owner-open-r5-host-source";
static CONNECTION_ORDINAL: AtomicU64 = AtomicU64::new(1);

fn main() {
    if let Err(error) = run() {
        eprintln!("trillionnium-owner-open-r5-host: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let options = Options::parse(env::args_os().skip(1).collect())?;
    if options.help {
        println!("{}", Options::usage());
        return Ok(());
    }
    let mut provider = JsonlProvider::new(JsonlProviderConfig {
        executable: options.provider,
        args: options.provider_args,
        shell_executable: options.shell,
        adb_executable: options.adb,
        cwd: options.provider_cwd,
        timeout: options.provider_timeout,
        ..JsonlProviderConfig::default()
    })
    .map_err(|error| error.to_string())?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    process_connection(
        BufReader::new(stdin.lock()),
        stdout.lock(),
        new_connection_id(),
        &mut provider,
    )
}

#[derive(Debug)]
struct Options {
    provider: PathBuf,
    provider_args: Vec<String>,
    shell: PathBuf,
    adb: PathBuf,
    provider_cwd: Option<PathBuf>,
    provider_timeout: Duration,
    help: bool,
}

impl Options {
    fn parse(args: Vec<OsString>) -> Result<Self, String> {
        if args.iter().any(|value| value == "--help" || value == "-h") {
            return Ok(Self {
                provider: PathBuf::new(),
                provider_args: Vec::new(),
                shell: PathBuf::from("/bin/sh"),
                adb: PathBuf::from("adb"),
                provider_cwd: None,
                provider_timeout: Duration::from_secs(300),
                help: true,
            });
        }
        let mut provider = None;
        let mut provider_args = Vec::new();
        let mut shell = PathBuf::from("/bin/sh");
        let mut adb = PathBuf::from("adb");
        let mut provider_cwd = None;
        let mut provider_timeout = Duration::from_secs(300);
        let mut index = 0usize;
        while index < args.len() {
            let option = args[index]
                .to_str()
                .ok_or_else(|| "command-line options must be UTF-8".to_string())?;
            index = index.saturating_add(1);
            let value = |index: &mut usize| -> Result<&OsString, String> {
                let value = args
                    .get(*index)
                    .ok_or_else(|| format!("{option} requires a value"))?;
                *index = index.saturating_add(1);
                Ok(value)
            };
            match option {
                "--provider" => {
                    if provider.is_some() {
                        return Err("--provider may be supplied only once".to_string());
                    }
                    provider = Some(PathBuf::from(value(&mut index)?));
                }
                "--provider-arg" => {
                    provider_args.push(
                        value(&mut index)?
                            .to_str()
                            .ok_or_else(|| "--provider-arg must be UTF-8".to_string())?
                            .to_string(),
                    );
                }
                "--shell" => shell = PathBuf::from(value(&mut index)?),
                "--adb" => adb = PathBuf::from(value(&mut index)?),
                "--provider-cwd" => provider_cwd = Some(PathBuf::from(value(&mut index)?)),
                "--provider-timeout-ms" => {
                    let milliseconds = value(&mut index)?
                        .to_str()
                        .ok_or_else(|| "--provider-timeout-ms must be UTF-8".to_string())?
                        .parse::<u64>()
                        .map_err(|error| format!("invalid --provider-timeout-ms: {error}"))?;
                    if milliseconds == 0 {
                        return Err("--provider-timeout-ms must be non-zero".to_string());
                    }
                    provider_timeout = Duration::from_millis(milliseconds);
                }
                other => return Err(format!("unknown option {other}\n{}", Self::usage())),
            }
        }
        Ok(Self {
            provider: provider.ok_or_else(|| "--provider is required".to_string())?,
            provider_args,
            shell,
            adb,
            provider_cwd,
            provider_timeout,
            help: false,
        })
    }

    fn usage() -> &'static str {
        "usage: trillionnium-owner-open-r5-host --provider PATH [--provider-arg ARG]... [--shell PATH] [--adb PATH] [--provider-cwd DIR] [--provider-timeout-ms MS]\n\nThe R5 source host uses newline-delimited owner-open frames on stdin/stdout."
    }
}

#[derive(Debug, Clone)]
struct TurnContext {
    connection_id: String,
    turn_stream_id: String,
    session_id: String,
    profile_id: String,
    task_id: String,
    turn_id: String,
}

#[derive(Debug, Default)]
struct EventCorrelation {
    call_id: Option<String>,
    tool: Option<String>,
    target_id: Option<String>,
}

struct OutputState {
    connection_id: String,
    next_host_seq: u64,
    next_stream_ordinal: u64,
}

impl OutputState {
    fn new(connection_id: String) -> Self {
        Self {
            connection_id,
            next_host_seq: 0,
            next_stream_ordinal: 0,
        }
    }

    fn allocate_context(
        &mut self,
        request: &trillionnium_owner_open_types::RunTurnRequest,
    ) -> Result<TurnContext, String> {
        self.next_stream_ordinal = self
            .next_stream_ordinal
            .checked_add(1)
            .ok_or_else(|| "turn stream ordinal overflow".to_string())?;
        Ok(TurnContext {
            connection_id: self.connection_id.clone(),
            turn_stream_id: format!(
                "{}-turn-stream-{}",
                self.connection_id, self.next_stream_ordinal
            ),
            session_id: request.session_id.clone(),
            profile_id: request.effective_profile_id().to_string(),
            task_id: request.task_id.clone(),
            turn_id: request.turn_id.clone(),
        })
    }

    fn frame(
        &mut self,
        kind: impl Into<String>,
        payload: Value,
        context: Option<&TurnContext>,
        correlation: EventCorrelation,
    ) -> RunTurnFrame {
        let seq = self.next_host_seq;
        self.next_host_seq = self.next_host_seq.saturating_add(1);
        RunTurnFrame {
            kind: kind.into(),
            seq,
            payload,
            direction: Some("host_to_client".to_string()),
            client_seq: None,
            host_seq: Some(seq),
            frame_sha256: None,
            event_id: Some(format!("{}-event-{seq}", self.connection_id)),
            connection_id: Some(self.connection_id.clone()),
            stream_id: context.map(|value| value.turn_stream_id.clone()),
            turn_stream_id: context.map(|value| value.turn_stream_id.clone()),
            session_id: context.map(|value| value.session_id.clone()),
            profile_id: context.map(|value| value.profile_id.clone()),
            task_id: context.map(|value| value.task_id.clone()),
            turn_id: context.map(|value| value.turn_id.clone()),
            call_id: correlation.call_id,
            job_id: None,
            tool: correlation.tool,
            target: None,
            target_id: correlation.target_id,
            extensions: Default::default(),
        }
    }
}

fn process_connection<R: BufRead, W: Write>(
    mut reader: R,
    mut writer: W,
    connection_id: String,
    provider: &mut JsonlProvider,
) -> Result<(), String> {
    let limits = MechanicalLimits::default();
    let runner = TurnRunner::new(Arc::new(CallRegistry::default()));
    let mut output = OutputState::new(connection_id);
    loop {
        let Some(encoded) = read_bounded_frame(&mut reader, limits.max_frame_bytes)? else {
            return Ok(());
        };
        let frame = match RunTurnFrame::decode(&encoded, &limits) {
            Ok(frame) => frame,
            Err(error) => {
                write_frame(
                    &mut writer,
                    &output.frame(
                        FRAME_HOST_ERROR,
                        json!({"code": "invalid_frame", "message": error.to_string()}),
                        None,
                        EventCorrelation::default(),
                    ),
                    limits.max_frame_bytes,
                )?;
                continue;
            }
        };
        match frame.kind.as_str() {
            FRAME_HELLO => {
                write_frame(
                    &mut writer,
                    &output.frame(
                        FRAME_HELLO_ACK,
                        json!({
                            "protocol": PROTOCOL,
                            "protocol_version": PROTOCOL_VERSION,
                            "connection_id": output.connection_id,
                            "host_implementation": HOST_IMPLEMENTATION,
                            "provider_status": "configured_external_jsonl",
                            "runtime_ready": true,
                            "same_turn_tool_callback": true,
                            "durable_event_store": false,
                            "asynchronous_control": false,
                            "one_active_turn_per_connection": true
                        }),
                        None,
                        EventCorrelation::default(),
                    ),
                    limits.max_frame_bytes,
                )?;
            }
            FRAME_TURN_START => {
                let request = match frame.turn_request(&limits) {
                    Ok(request) => request,
                    Err(error) => {
                        write_frame(
                            &mut writer,
                            &output.frame(
                                FRAME_HOST_ERROR,
                                json!({"code": "invalid_frame", "message": error.to_string()}),
                                None,
                                EventCorrelation::default(),
                            ),
                            limits.max_frame_bytes,
                        )?;
                        continue;
                    }
                };
                let context = output.allocate_context(&request)?;
                write_frame(
                    &mut writer,
                    &output.frame(
                        FRAME_TURN_ACCEPTED,
                        json!({
                            "status": "accepted",
                            "provider_status": "starting",
                            "event_log_status": "best_effort_memory_only"
                        }),
                        Some(&context),
                        EventCorrelation::default(),
                    ),
                    limits.max_frame_bytes,
                )?;
                let loop_request = LoopTurnRequest {
                    session_id: context.session_id.clone(),
                    profile_id: context.profile_id.clone(),
                    task_id: context.task_id.clone(),
                    turn_id: context.turn_id.clone(),
                    turn_stream_id: context.turn_stream_id.clone(),
                    user_input: request.user_input,
                };
                let run = runner
                    .run(loop_request, provider)
                    .map_err(|error| error.to_string())?;
                for event in &run.events {
                    if let Some(frame) = map_turn_event(&mut output, &context, event) {
                        write_frame(&mut writer, &frame, limits.max_frame_bytes)?;
                    }
                }
                write_frame(
                    &mut writer,
                    &output.frame(
                        FRAME_TURN_END,
                        json!({
                            "status": run.terminal.status.as_str(),
                            "summary": run.terminal.summary,
                            "error": run.terminal.error,
                            "runtime_ready": true,
                            "event_log_status": "best_effort_memory_only"
                        }),
                        Some(&context),
                        EventCorrelation::default(),
                    ),
                    limits.max_frame_bytes,
                )?;
            }
            other => {
                write_frame(
                    &mut writer,
                    &output.frame(
                        FRAME_HOST_ERROR,
                        json!({
                            "code": "unsupported_frame",
                            "message": format!("unsupported client frame kind {other}"),
                            "asynchronous_control": false
                        }),
                        None,
                        EventCorrelation::default(),
                    ),
                    limits.max_frame_bytes,
                )?;
            }
        }
    }
}

fn map_turn_event(
    output: &mut OutputState,
    context: &TurnContext,
    event: &TurnEvent,
) -> Option<RunTurnFrame> {
    match &event.kind {
        TurnEventKind::TurnAccepted | TurnEventKind::TurnTerminal(_) => None,
        TurnEventKind::Provider(provider) => {
            let (kind, payload) = match provider {
                ProviderEvent::Status { status, detail } => (
                    FRAME_PROVIDER_STATUS,
                    json!({"status": status, "detail": detail, "turn_event_seq": event.seq}),
                ),
                ProviderEvent::ModelDelta(text) => (
                    FRAME_MODEL_DELTA,
                    json!({"text": text, "turn_event_seq": event.seq}),
                ),
                ProviderEvent::ModelMessage(text) => (
                    FRAME_MODEL_MESSAGE,
                    json!({"text": text, "turn_event_seq": event.seq}),
                ),
                ProviderEvent::Opaque { kind, payload } => (
                    "provider.opaque",
                    json!({"provider_kind": kind, "raw": payload, "turn_event_seq": event.seq}),
                ),
            };
            Some(output.frame(
                kind,
                payload,
                Some(context),
                EventCorrelation::default(),
            ))
        }
        TurnEventKind::ToolRuntime(runtime) => Some(map_runtime_event(
            output,
            context,
            event.seq,
            runtime,
        )),
        TurnEventKind::ToolExisting(snapshot) => Some(map_snapshot(
            output,
            context,
            event.seq,
            "existing",
            snapshot,
        )),
        TurnEventKind::ToolInhibited(snapshot) => Some(map_snapshot(
            output,
            context,
            event.seq,
            "inhibited",
            snapshot,
        )),
    }
}

fn map_runtime_event(
    output: &mut OutputState,
    context: &TurnContext,
    turn_event_seq: u64,
    runtime: &ExecutionEvent,
) -> RunTurnFrame {
    let correlation = EventCorrelation {
        call_id: Some(runtime.call_id.clone()),
        tool: Some(runtime.tool.as_str().to_string()),
        target_id: runtime.target_id.clone(),
    };
    match &runtime.kind {
        ExecutionEventKind::Accepted => output.frame(
            FRAME_TOOL_ACCEPTED,
            json!({
                "status": "accepted",
                "runtime_seq": runtime.seq,
                "turn_event_seq": turn_event_seq,
                "elapsed_ms": runtime.elapsed_ms
            }),
            Some(context),
            correlation,
        ),
        ExecutionEventKind::Started { pid } => output.frame(
            FRAME_TOOL_STARTED,
            json!({
                "status": "started",
                "pid": pid,
                "runtime_seq": runtime.seq,
                "turn_event_seq": turn_event_seq,
                "elapsed_ms": runtime.elapsed_ms
            }),
            Some(context),
            correlation,
        ),
        ExecutionEventKind::Output { stream, bytes } => output.frame(
            match stream {
                StreamKind::Stdout => FRAME_TOOL_STDOUT,
                StreamKind::Stderr => FRAME_TOOL_STDERR,
            },
            json!({
                "encoding": "base64",
                "data": BASE64_STANDARD.encode(bytes),
                "byte_count": bytes.len(),
                "runtime_seq": runtime.seq,
                "turn_event_seq": turn_event_seq,
                "elapsed_ms": runtime.elapsed_ms
            }),
            Some(context),
            correlation,
        ),
        ExecutionEventKind::Terminal(terminal) => output.frame(
            FRAME_TOOL_RESULT,
            terminal_payload(terminal, runtime.seq, turn_event_seq),
            Some(context),
            correlation,
        ),
    }
}

fn terminal_payload(
    terminal: &trillionnium_owner_open_runtime::ExecutionTerminal,
    runtime_seq: u64,
    turn_event_seq: u64,
) -> Value {
    json!({
        "status": "terminal",
        "terminal_kind": terminal.kind.as_str(),
        "exit_code": terminal.exit_code,
        "signal": terminal.signal,
        "stdout_bytes": terminal.stdout_bytes,
        "stderr_bytes": terminal.stderr_bytes,
        "output_truncated": terminal.output_truncated,
        "elapsed_ms": terminal.elapsed_ms,
        "error": terminal.error,
        "runtime_seq": runtime_seq,
        "turn_event_seq": turn_event_seq
    })
}

fn map_snapshot(
    output: &mut OutputState,
    context: &TurnContext,
    turn_event_seq: u64,
    status: &str,
    snapshot: &CallSnapshot,
) -> RunTurnFrame {
    output.frame(
        FRAME_TOOL_RESULT,
        json!({
            "status": status,
            "state": format!("{:?}", snapshot.state),
            "request_sha256": snapshot.request.request_sha256,
            "binding_fingerprint": snapshot.request.binding_fingerprint,
            "cancellation_requested": snapshot.cancellation_requested,
            "connection_lost": snapshot.connection_lost,
            "turn_event_seq": turn_event_seq
        }),
        Some(context),
        EventCorrelation {
            call_id: Some(snapshot.key.call_id.clone()),
            tool: Some(snapshot.request.tool.clone()),
            target_id: snapshot.request.target_id.clone(),
        },
    )
}

fn read_bounded_frame<R: BufRead>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> Result<Option<Vec<u8>>, String> {
    let mut frame = Vec::new();
    let read = reader
        .take(max_frame_bytes as u64 + 2)
        .read_until(b'\n', &mut frame)
        .map_err(|error| format!("failed to read frame: {error}"))?;
    if read == 0 {
        return Ok(None);
    }
    if frame.last() != Some(&b'\n') {
        return Err("frame is not newline terminated or exceeds the configured bound".to_string());
    }
    frame.pop();
    if frame.is_empty() || frame.len() > max_frame_bytes {
        return Err("frame is empty or exceeds the configured bound".to_string());
    }
    Ok(Some(frame))
}

fn write_frame<W: Write>(
    writer: &mut W,
    frame: &RunTurnFrame,
    max_frame_bytes: usize,
) -> Result<(), String> {
    let encoded = serde_json::to_vec(frame)
        .map_err(|error| format!("failed to encode response frame: {error}"))?;
    if encoded.is_empty() || encoded.len() > max_frame_bytes {
        return Err("response frame is empty or exceeds the configured bound".to_string());
    }
    writer
        .write_all(&encoded)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("failed to write response frame: {error}"))
}

fn new_connection_id() -> String {
    let ordinal = CONNECTION_ORDINAL.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("r5-connection-{}-{nanos}-{ordinal}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_does_not_require_a_provider_path() {
        let options = Options::parse(vec![OsString::from("--help")]).unwrap();
        assert!(options.help);
    }

    #[test]
    fn provider_is_required_for_runtime_start() {
        let error = Options::parse(Vec::new()).unwrap_err();
        assert!(error.contains("--provider is required"));
    }
}
