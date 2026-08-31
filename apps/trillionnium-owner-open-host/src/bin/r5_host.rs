#[path = "../r5_persistence.rs"]
mod r5_persistence;

use std::env;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use r5_persistence::{
    Persistence, StoredTurn, event_scope, request_sha256, stable_turn_stream_id,
};
use serde_json::{Value, json};
use trillionnium_owner_open_call_registry::{CallRegistry, CallSnapshot};
use trillionnium_owner_open_event_store::TurnScope as DurableTurnScope;
use trillionnium_owner_open_provider_jsonl::{JsonlProvider, JsonlProviderConfig};
use trillionnium_owner_open_runtime::{ExecutionEvent, ExecutionEventKind, StreamKind};
use trillionnium_owner_open_turn_loop::{
    ProviderEvent, TurnEvent, TurnEventKind, TurnRequest as LoopTurnRequest, TurnRunner,
};
use trillionnium_owner_open_types::{
    FRAME_HELLO, FRAME_HELLO_ACK, FRAME_MODEL_DELTA, FRAME_MODEL_MESSAGE,
    FRAME_PROVIDER_STATUS, FRAME_TOOL_ACCEPTED, FRAME_TOOL_PTY, FRAME_TOOL_RESULT,
    FRAME_TOOL_STARTED, FRAME_TOOL_STDERR, FRAME_TOOL_STDOUT, FRAME_TURN_ACCEPTED, FRAME_TURN_END,
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
    let mut persistence = Persistence::open_best_effort(options.event_store.as_deref());
    let stdin = io::stdin();
    let stdout = io::stdout();
    process_connection(
        BufReader::new(stdin.lock()),
        stdout.lock(),
        new_connection_id(),
        &mut provider,
        &mut persistence,
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
    event_store: Option<PathBuf>,
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
                event_store: None,
                help: true,
            });
        }
        let mut provider = None;
        let mut provider_args = Vec::new();
        let mut shell = PathBuf::from("/bin/sh");
        let mut adb = PathBuf::from("adb");
        let mut provider_cwd = None;
        let mut provider_timeout = Duration::from_secs(300);
        let mut event_store = None;
        let mut index = 0usize;
        while index < args.len() {
            let option = args[index]
                .to_str()
                .ok_or_else(|| "command-line options must be UTF-8".to_string())?
                .to_string();
            index = index.saturating_add(1);
            match option.as_str() {
                "--provider" => {
                    if provider.is_some() {
                        return Err("--provider may be supplied only once".to_string());
                    }
                    provider = Some(PathBuf::from(take_value(&args, &mut index, &option)?));
                }
                "--provider-arg" => {
                    provider_args.push(
                        take_value(&args, &mut index, &option)?
                            .to_str()
                            .ok_or_else(|| "--provider-arg must be UTF-8".to_string())?
                            .to_string(),
                    );
                }
                "--shell" => {
                    shell = PathBuf::from(take_value(&args, &mut index, &option)?);
                }
                "--adb" => {
                    adb = PathBuf::from(take_value(&args, &mut index, &option)?);
                }
                "--provider-cwd" => {
                    provider_cwd = Some(PathBuf::from(take_value(&args, &mut index, &option)?));
                }
                "--provider-timeout-ms" => {
                    let milliseconds = take_value(&args, &mut index, &option)?
                        .to_str()
                        .ok_or_else(|| "--provider-timeout-ms must be UTF-8".to_string())?
                        .parse::<u64>()
                        .map_err(|error| format!("invalid --provider-timeout-ms: {error}"))?;
                    if milliseconds == 0 {
                        return Err("--provider-timeout-ms must be non-zero".to_string());
                    }
                    provider_timeout = Duration::from_millis(milliseconds);
                }
                "--event-store" => {
                    if event_store.is_some() {
                        return Err("--event-store may be supplied only once".to_string());
                    }
                    event_store = Some(PathBuf::from(take_value(&args, &mut index, &option)?));
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
            event_store,
            help: false,
        })
    }

    fn usage() -> &'static str {
        "usage: trillionnium-owner-open-r5-host --provider PATH [--provider-arg ARG]... [--shell PATH] [--adb PATH] [--provider-cwd DIR] [--provider-timeout-ms MS] [--event-store /absolute/path/events.jsonl]\n\nThe R5 source host uses newline-delimited owner-open frames on stdin/stdout. Event-store failure is reported as unavailable and does not become semantic denial."
    }
}

fn take_value<'a>(
    args: &'a [OsString],
    index: &mut usize,
    option: &str,
) -> Result<&'a OsString, String> {
    let value = args
        .get(*index)
        .ok_or_else(|| format!("{option} requires a value"))?;
    *index = index.saturating_add(1);
    Ok(value)
}

#[derive(Debug, Clone)]
struct TurnContext {
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
    next_control_seq: u64,
    next_host_seq: u64,
    next_turn_event_ordinal: u64,
}

impl OutputState {
    fn new(connection_id: String) -> Self {
        Self {
            connection_id,
            next_control_seq: 0,
            next_host_seq: 0,
            next_turn_event_ordinal: 0,
        }
    }

    fn context(
        &mut self,
        request: &trillionnium_owner_open_types::RunTurnRequest,
    ) -> Result<TurnContext, String> {
        self.next_turn_event_ordinal = 0;
        Ok(TurnContext {
            turn_stream_id: stable_turn_stream_id(request)?,
            session_id: request.session_id.clone(),
            profile_id: request.effective_profile_id().to_string(),
            task_id: request.task_id.clone(),
            turn_id: request.turn_id.clone(),
        })
    }

    fn observe_replay(&mut self, frames: &[RunTurnFrame]) {
        if let Some(next) = frames
            .iter()
            .filter_map(|frame| frame.host_seq)
            .max()
            .and_then(|value| value.checked_add(1))
        {
            self.next_host_seq = self.next_host_seq.max(next);
        }
        self.next_turn_event_ordinal = u64::try_from(frames.len()).unwrap_or(u64::MAX);
    }

    fn frame(
        &mut self,
        kind: impl Into<String>,
        payload: Value,
        context: Option<&TurnContext>,
        correlation: EventCorrelation,
    ) -> RunTurnFrame {
        let (seq, host_seq) = if context.is_some() {
            let value = self.next_host_seq;
            self.next_host_seq = self.next_host_seq.saturating_add(1);
            (value, Some(value))
        } else {
            let value = self.next_control_seq;
            self.next_control_seq = self.next_control_seq.saturating_add(1);
            (value, None)
        };
        let event_id = if let Some(context) = context {
            let ordinal = self.next_turn_event_ordinal;
            self.next_turn_event_ordinal = self.next_turn_event_ordinal.saturating_add(1);
            format!("{}-event-{ordinal}", context.turn_stream_id)
        } else {
            format!("{}-event-{seq}", self.connection_id)
        };
        RunTurnFrame {
            kind: kind.into(),
            seq,
            payload,
            direction: Some("host_to_client".to_string()),
            client_seq: None,
            host_seq,
            frame_sha256: None,
            event_id: Some(event_id),
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
    persistence: &mut Persistence,
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
                write_hello(&mut writer, &mut output, persistence, limits.max_frame_bytes)?;
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
                let context = output.context(&request)?;
                let digest = request_sha256(&request)?;
                let scope = event_scope(&request, &context.turn_stream_id);
                match persistence.load(&scope, &digest) {
                    StoredTurn::Complete(frames) => {
                        output.observe_replay(&frames);
                        write_replay(&mut writer, &frames, limits.max_frame_bytes)?;
                        continue;
                    }
                    StoredTurn::Incomplete(mut frames) => {
                        output.observe_replay(&frames);
                        let terminal = output.frame(
                            FRAME_TURN_END,
                            json!({
                                "status": "unknown_after_disconnect",
                                "summary": Value::Null,
                                "error": "a prior durable turn has no terminal observation; automatic redispatch is denied",
                                "runtime_ready": true,
                                "reconciliation": true,
                                "automatic_redispatch": false,
                                "event_log_status": persistence.status(),
                                "event_log_error": persistence.error()
                            }),
                            Some(&context),
                            EventCorrelation::default(),
                        );
                        let terminal =
                            persist_for_delivery(persistence, &scope, &digest, terminal);
                        frames.push(terminal);
                        write_replay(&mut writer, &frames, limits.max_frame_bytes)?;
                        continue;
                    }
                    StoredTurn::Conflict(error) => {
                        write_frame(
                            &mut writer,
                            &output.frame(
                                FRAME_HOST_ERROR,
                                json!({
                                    "code": "turn_replay_conflict",
                                    "message": error,
                                    "automatic_redispatch": false
                                }),
                                Some(&context),
                                EventCorrelation::default(),
                            ),
                            limits.max_frame_bytes,
                        )?;
                        continue;
                    }
                    StoredTurn::Empty => {}
                }

                let accepted = output.frame(
                    FRAME_TURN_ACCEPTED,
                    json!({
                        "status": "accepted",
                        "provider_status": "starting",
                        "event_log_status": persistence.status(),
                        "event_log_error": persistence.error()
                    }),
                    Some(&context),
                    EventCorrelation::default(),
                );
                let accepted = persist_for_delivery(persistence, &scope, &digest, accepted);
                write_frame(&mut writer, &accepted, limits.max_frame_bytes)?;

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
                        let frame = persist_for_delivery(persistence, &scope, &digest, frame);
                        write_frame(&mut writer, &frame, limits.max_frame_bytes)?;
                    }
                }
                let terminal = output.frame(
                    FRAME_TURN_END,
                    json!({
                        "status": run.terminal.status.as_str(),
                        "summary": &run.terminal.summary,
                        "error": &run.terminal.error,
                        "runtime_ready": true,
                        "event_log_status": persistence.status(),
                        "event_log_error": persistence.error()
                    }),
                    Some(&context),
                    EventCorrelation::default(),
                );
                let terminal = persist_for_delivery(persistence, &scope, &digest, terminal);
                write_frame(&mut writer, &terminal, limits.max_frame_bytes)?;
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

fn write_hello<W: Write>(
    writer: &mut W,
    output: &mut OutputState,
    persistence: &Persistence,
    max_frame_bytes: usize,
) -> Result<(), String> {
    let connection_id = output.connection_id.clone();
    let frame = output.frame(
        FRAME_HELLO_ACK,
        json!({
            "protocol": PROTOCOL,
            "protocol_version": PROTOCOL_VERSION,
            "connection_id": connection_id,
            "host_implementation": HOST_IMPLEMENTATION,
            "provider_status": "configured_external_jsonl",
            "runtime_ready": true,
            "same_turn_tool_callback": true,
            "durable_event_store": persistence.is_durable(),
            "event_log_status": persistence.status(),
            "event_log_error": persistence.error(),
            "completed_turn_replay": persistence.is_durable(),
            "incomplete_turn_redispatch": false,
            "asynchronous_control": false,
            "one_active_turn_per_connection": true
        }),
        None,
        EventCorrelation::default(),
    );
    write_frame(writer, &frame, max_frame_bytes)
}

fn persist_for_delivery(
    persistence: &mut Persistence,
    scope: &DurableTurnScope,
    request_digest: &str,
    mut frame: RunTurnFrame,
) -> RunTurnFrame {
    decorate_log_status(&mut frame.payload, persistence);
    if !persistence.append_frame(scope, request_digest, &frame) {
        decorate_log_status(&mut frame.payload, persistence);
    }
    frame
}

fn decorate_log_status(payload: &mut Value, persistence: &Persistence) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    if object.contains_key("event_log_status") {
        object.insert(
            "event_log_status".to_string(),
            Value::String(persistence.status().to_string()),
        );
        match persistence.error() {
            Some(error) => {
                object.insert(
                    "event_log_error".to_string(),
                    Value::String(error.to_string()),
                );
            }
            None => {
                object.insert("event_log_error".to_string(), Value::Null);
            }
        }
    }
}

fn write_replay<W: Write>(
    writer: &mut W,
    frames: &[RunTurnFrame],
    max_frame_bytes: usize,
) -> Result<(), String> {
    for frame in frames {
        write_frame(writer, frame, max_frame_bytes)?;
    }
    Ok(())
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
                StreamKind::Pty => FRAME_TOOL_PTY,
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
        "error": &terminal.error,
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
            "request_sha256": &snapshot.request.request_sha256,
            "binding_fingerprint": &snapshot.request.binding_fingerprint,
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

    #[test]
    fn event_store_is_optional_and_unique() {
        let options = Options::parse(vec![
            OsString::from("--provider"),
            OsString::from("/tmp/provider"),
            OsString::from("--event-store"),
            OsString::from("/tmp/events.jsonl"),
        ])
        .unwrap();
        assert_eq!(
            options.event_store,
            Some(PathBuf::from("/tmp/events.jsonl"))
        );
        let error = Options::parse(vec![
            OsString::from("--provider"),
            OsString::from("/tmp/provider"),
            OsString::from("--event-store"),
            OsString::from("/tmp/a"),
            OsString::from("--event-store"),
            OsString::from("/tmp/b"),
        ])
        .unwrap_err();
        assert!(error.contains("only once"));
    }
}
