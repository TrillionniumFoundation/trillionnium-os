const FRAME_JOB_START: &str = "job.start";
const FRAME_JOB_START_RESULT: &str = "job.start.result";
const FRAME_JOB_INSPECT: &str = "job.inspect";
const FRAME_JOB_INSPECT_RESULT: &str = "job.inspect.result";
const FRAME_JOB_ATTACH: &str = "job.attach";
const FRAME_JOB_ATTACH_RESULT: &str = "job.attach.result";
const FRAME_JOB_WAIT: &str = "job.wait";
const FRAME_JOB_DETACH: &str = "job.detach";
const FRAME_JOB_DETACH_RESULT: &str = "job.detach.result";
const FRAME_JOB_WRITE: &str = "job.write";
const FRAME_JOB_RESIZE: &str = "job.resize";
const FRAME_JOB_CLOSE_STDIN: &str = "job.close_stdin";
const FRAME_JOB_KILL: &str = "job.kill";
const FRAME_JOB_CONTROL_RESULT: &str = "job.control.result";
const FRAME_JOB_STARTED: &str = "job.started";
const FRAME_JOB_IDENTITY_BOUND: &str = "job.process_identity_bound";
const FRAME_JOB_OUTPUT: &str = "job.output";
const FRAME_JOB_RESULT: &str = "job.result";
const FRAME_JOB_STATUS: &str = "job.status";

// Runtime observations and durable journal records are intentionally
// different cursor domains.  Keep the labels on the wire so a caller cannot
// accidentally use a runtime event sequence as a journal-record offset.
const RUNTIME_CURSOR_DOMAIN: &str = "job_runtime_event";
const DURABLE_CURSOR_DOMAIN: &str = "job_journal_record";

// `job.wait` is a read-only bounded long-poll. Keep its defaults and ceiling
// finite at the wire boundary so a malformed peer cannot pin the multiplexed
// Host loop indefinitely. The timeout starts when the request is admitted by
// the v7 core; it never authorizes a process effect or retry.
const DEFAULT_JOB_WAIT_TIMEOUT_MS: u64 = 60_000;
const MAX_JOB_WAIT_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_JOB_WAIT_POLL_INTERVAL_MS: u64 = 20;
const MAX_JOB_WAIT_POLL_INTERVAL_MS: u64 = 5_000;
const MAX_PENDING_JOB_WAITS: usize = 256;

#[derive(Debug, Clone)]
struct JobContext {
    key: JobKey,
    request_sha256: Option<String>,
    stream_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PtyWire {
    rows: u16,
    cols: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JobStartWire {
    session_id: String,
    #[serde(default = "default_profile")]
    profile_id: String,
    task_id: String,
    turn_id: String,
    turn_stream_id: String,
    job_id: String,
    operation_id: String,
    tool: String,
    #[serde(default)]
    target_id: Option<String>,
    mode: String,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    argv: Option<Vec<String>>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, Option<String>>,
    #[serde(default)]
    stdin: Option<Value>,
    #[serde(default)]
    pty: Option<PtyWire>,
    #[serde(default)]
    request_sha256: Option<String>,
    #[serde(default)]
    binding_fingerprint: Option<String>,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JobControlWire {
    session_id: String,
    #[serde(default = "default_profile")]
    profile_id: String,
    task_id: String,
    turn_id: String,
    turn_stream_id: String,
    job_id: String,
    #[serde(default)]
    request_sha256: Option<String>,
    #[serde(default)]
    operation_id: Option<String>,
    #[serde(default)]
    attachment_id: Option<String>,
    #[serde(default)]
    inclusive_cursor: Option<u64>,
    /// Cursor into the durable journal-record sequence.  This is independent
    /// from `inclusive_cursor`, which addresses retained runtime events.
    #[serde(default)]
    durable_inclusive_cursor: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    rows: Option<u16>,
    #[serde(default)]
    cols: Option<u16>,
    #[serde(default)]
    signal: Option<i32>,
    /// Maximum monotonic wait duration. Meaningful only for `job.wait`; it is
    /// additive on the shared control shape so older decoders can ignore it
    /// on other read/control frames.
    #[serde(default)]
    timeout_ms: Option<u64>,
    /// Optional polling cadence for `job.wait`.
    #[serde(default)]
    poll_interval_ms: Option<u64>,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
struct DecodedJobStart {
    context: JobContext,
    request: JobStartRequest,
}

#[derive(Debug, Clone)]
struct DecodedJobControl {
    context: JobContext,
    operation_id: Option<String>,
    attachment_id: Option<String>,
    inclusive_cursor: u64,
    durable_inclusive_cursor: u64,
    limit: usize,
    data: Option<Vec<u8>>,
    size: Option<PtySize>,
    signal: Option<i32>,
    timeout_ms: Option<u64>,
    poll_interval_ms: Option<u64>,
}

fn is_job_frame(kind: &str) -> bool {
    matches!(
        kind,
        FRAME_JOB_START
            | FRAME_JOB_INSPECT
            | FRAME_JOB_ATTACH
            | FRAME_JOB_WAIT
            | FRAME_JOB_DETACH
            | FRAME_JOB_WRITE
            | FRAME_JOB_RESIZE
            | FRAME_JOB_CLOSE_STDIN
            | FRAME_JOB_KILL
    )
}

fn decode_job_start(frame: &RunTurnFrame, shell: &Path) -> Result<DecodedJobStart, String> {
    if frame.kind != FRAME_JOB_START {
        return Err("frame is not job.start".to_string());
    }
    let wire: JobStartWire = serde_json::from_value(frame.payload.clone())
        .map_err(|error| format!("invalid job.start payload: {error}"))?;
    validate_scope(frame, wire_scope(&wire), &wire.job_id)?;
    validate_id(&wire.operation_id, "operation_id")?;
    if wire.tool != "shell.job" {
        return Err("job.start currently requires tool=shell.job".to_string());
    }
    let invocation = match (&wire.command, &wire.argv) {
        (Some(command), None) if !command.is_empty() && !command.as_bytes().contains(&0) => {
            JobInvocation::Command {
                command: command.clone(),
            }
        }
        (None, Some(argv))
            if !argv.is_empty()
                && argv
                    .iter()
                    .all(|item| !item.is_empty() && !item.as_bytes().contains(&0)) =>
        {
            JobInvocation::Argv { argv: argv.clone() }
        }
        _ => {
            return Err(
                "job.start requires exactly one nonempty command or argv representation"
                    .to_string(),
            );
        }
    };
    let pty = match wire.mode.as_str() {
        "pipe" => {
            if wire.pty.is_some() {
                return Err("pipe job must not carry PTY dimensions".to_string());
            }
            None
        }
        "pty" => {
            let size = wire.pty.clone().unwrap_or(PtyWire { rows: 24, cols: 80 });
            if size.rows == 0 || size.cols == 0 {
                return Err("PTY rows and cols must be non-zero".to_string());
            }
            Some(PtySize {
                rows: size.rows,
                cols: size.cols,
            })
        }
        _ => return Err("job mode must be pipe or pty".to_string()),
    };
    let stdin = decode_bytes(wire.stdin.as_ref())?;
    let key = JobKey::new(
        JobScope::new(
            wire.session_id.clone(),
            wire.profile_id.clone(),
            wire.task_id.clone(),
            wire.turn_id.clone(),
            wire.turn_stream_id.clone(),
        ),
        wire.job_id.clone(),
    );
    let request_sha256 = job_request_sha256(&wire, &stdin)?;
    if wire
        .request_sha256
        .as_deref()
        .is_some_and(|claimed| claimed != request_sha256)
    {
        return Err("job.start request_sha256 does not match canonical request bytes".to_string());
    }
    let binding_fingerprint = job_binding_fingerprint(&wire, shell);
    if wire
        .binding_fingerprint
        .as_deref()
        .is_some_and(|claimed| claimed != binding_fingerprint)
    {
        return Err(
            "job.start binding_fingerprint does not match resolved configuration".to_string(),
        );
    }
    let request = JobRequest::new(
        request_sha256.clone(),
        binding_fingerprint,
        wire.tool,
        wire.mode,
        wire.target_id,
    );
    let context = JobContext {
        stream_id: job_stream_id(&key),
        key: key.clone(),
        request_sha256: Some(request_sha256),
    };
    Ok(DecodedJobStart {
        context,
        request: JobStartRequest {
            key,
            request,
            operation_id: wire.operation_id,
            invocation,
            shell_executable: shell.to_path_buf(),
            cwd: wire.cwd.map(PathBuf::from),
            env: wire.env,
            initial_stdin: stdin,
            pty,
        },
    })
}

fn decode_job_control(frame: &RunTurnFrame) -> Result<DecodedJobControl, String> {
    let wire: JobControlWire = serde_json::from_value(frame.payload.clone())
        .map_err(|error| format!("invalid {} payload: {error}", frame.kind))?;
    validate_scope(
        frame,
        (
            wire.session_id.as_str(),
            wire.profile_id.as_str(),
            wire.task_id.as_str(),
            wire.turn_id.as_str(),
            wire.turn_stream_id.as_str(),
        ),
        &wire.job_id,
    )?;
    if let Some(operation_id) = &wire.operation_id {
        validate_id(operation_id, "operation_id")?;
    }
    if let Some(attachment_id) = &wire.attachment_id {
        validate_id(attachment_id, "attachment_id")?;
    }
    if wire.limit.is_some_and(|value| value == 0 || value > MAX_JOB_INSPECT_LIMIT) {
        return Err(format!(
            "job inspect limit must be between 1 and {MAX_JOB_INSPECT_LIMIT}"
        ));
    }
    let key = JobKey::new(
        JobScope::new(
            wire.session_id,
            wire.profile_id,
            wire.task_id,
            wire.turn_id,
            wire.turn_stream_id,
        ),
        wire.job_id,
    );
    Ok(DecodedJobControl {
        context: JobContext {
            stream_id: job_stream_id(&key),
            key,
            request_sha256: wire.request_sha256,
        },
        operation_id: wire.operation_id,
        attachment_id: wire.attachment_id,
        inclusive_cursor: wire.inclusive_cursor.unwrap_or(0),
        durable_inclusive_cursor: wire.durable_inclusive_cursor.unwrap_or(0),
        limit: wire.limit.unwrap_or(DEFAULT_JOB_INSPECT_LIMIT),
        data: match wire.data.as_ref() {
            Some(value) => Some(decode_bytes(Some(value))?),
            None => None,
        },
        size: match (wire.rows, wire.cols) {
            (None, None) => None,
            (Some(rows), Some(cols)) if rows > 0 && cols > 0 => Some(PtySize { rows, cols }),
            _ => return Err("job.resize requires non-zero rows and cols".to_string()),
        },
        signal: wire.signal,
        timeout_ms: wire.timeout_ms,
        poll_interval_ms: wire.poll_interval_ms,
    })
}

/// Decode and validate the read-only long-poll fields for `job.wait`.
///
/// The common control decoder performs scope, cursor, byte and identifier
/// validation. This wrapper adds the wait-specific finite timeout/cadence
/// policy while preserving the same decoded shape used by inspection and
/// attachment responses.
fn decode_job_wait(frame: &RunTurnFrame) -> Result<DecodedJobControl, String> {
    if frame.kind != FRAME_JOB_WAIT {
        return Err("frame is not job.wait".to_string());
    }
    let decoded = decode_job_control(frame)?;
    if decoded
        .timeout_ms
        .is_some_and(|value| value > MAX_JOB_WAIT_TIMEOUT_MS)
    {
        return Err(format!(
            "job.wait timeout_ms must be at most {MAX_JOB_WAIT_TIMEOUT_MS}"
        ));
    }
    if decoded
        .poll_interval_ms
        .is_some_and(|value| value == 0 || value > MAX_JOB_WAIT_POLL_INTERVAL_MS)
    {
        return Err(format!(
            "job.wait poll_interval_ms must be between 1 and {MAX_JOB_WAIT_POLL_INTERVAL_MS}"
        ));
    }
    Ok(decoded)
}

fn validate_scope(
    frame: &RunTurnFrame,
    scope: (&str, &str, &str, &str, &str),
    job_id: &str,
) -> Result<(), String> {
    let (session_id, profile_id, task_id, turn_id, turn_stream_id) = scope;
    for (label, value) in [
        ("session_id", session_id),
        ("profile_id", profile_id),
        ("task_id", task_id),
        ("turn_id", turn_id),
        ("turn_stream_id", turn_stream_id),
        ("job_id", job_id),
    ] {
        validate_id(value, label)?;
    }
    for (label, envelope, payload) in [
        ("session_id", frame.session_id.as_deref(), session_id),
        ("profile_id", frame.profile_id.as_deref(), profile_id),
        ("task_id", frame.task_id.as_deref(), task_id),
        ("turn_id", frame.turn_id.as_deref(), turn_id),
        ("job_id", frame.job_id.as_deref(), job_id),
    ] {
        if envelope.is_some_and(|value| value != payload) {
            return Err(format!("job frame envelope {label} conflicts with payload"));
        }
    }
    if frame
        .turn_stream_id
        .as_deref()
        .or(frame.stream_id.as_deref())
        .is_some_and(|value| value != turn_stream_id)
    {
        return Err("job frame stream correlation conflicts with payload".to_string());
    }
    Ok(())
}

fn wire_scope(wire: &JobStartWire) -> (&str, &str, &str, &str, &str) {
    (
        &wire.session_id,
        &wire.profile_id,
        &wire.task_id,
        &wire.turn_id,
        &wire.turn_stream_id,
    )
}

fn validate_id(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format!("{label} is empty, oversized or malformed"));
    }
    Ok(())
}

fn decode_bytes(value: Option<&Value>) -> Result<Vec<u8>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(value) => Ok(value.as_bytes().to_vec()),
        Value::Object(object) => {
            let encoding = object
                .get("encoding")
                .and_then(Value::as_str)
                .ok_or_else(|| "job byte object has no encoding".to_string())?;
            let data = object
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| "job byte object has no data".to_string())?;
            match encoding {
                "utf8" | "utf-8" => Ok(data.as_bytes().to_vec()),
                "base64" => JOB_BASE64
                    .decode(data)
                    .map_err(|error| format!("job base64 bytes are invalid: {error}")),
                _ => Err(format!("job byte encoding {encoding} is unsupported")),
            }
        }
        _ => Err("job bytes have an unsupported shape".to_string()),
    }
}

fn job_request_sha256(wire: &JobStartWire, stdin: &[u8]) -> Result<String, String> {
    let encoded = serde_json::to_vec(&json!({
        "schema": "trillionnium.owner-open.job-request.v1",
        "session_id": &wire.session_id,
        "profile_id": &wire.profile_id,
        "task_id": &wire.task_id,
        "turn_id": &wire.turn_id,
        "turn_stream_id": &wire.turn_stream_id,
        "job_id": &wire.job_id,
        "tool": &wire.tool,
        "target_id": &wire.target_id,
        "mode": &wire.mode,
        "command": &wire.command,
        "argv": &wire.argv,
        "cwd": &wire.cwd,
        "env": &wire.env,
        "stdin_sha256": sha256_hex(stdin),
        "stdin_bytes": stdin.len(),
        "pty": &wire.pty,
        "extensions": &wire.extensions
    }))
    .map_err(|error| error.to_string())?;
    Ok(sha256_hex(&encoded))
}

fn job_binding_fingerprint(wire: &JobStartWire, shell: &Path) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"schema", b"trillionnium.owner-open.job-binding.v1");
    hash_field(&mut hasher, b"tool", wire.tool.as_bytes());
    hash_field(&mut hasher, b"mode", wire.mode.as_bytes());
    hash_field(&mut hasher, b"shell", shell.as_os_str().as_bytes());
    hex_lower(&hasher.finalize())
}

fn job_stream_id(key: &JobKey) -> String {
    // `stream_id` is an alias of `turn_stream_id` in the canonical direct
    // Host envelope.  Jobs are distinguished by their required `job_id` and
    // their durable/runtime cursor domains; minting a second stream alias
    // here makes the frame fail the shared codec (and the transport broker)
    // before it can be delivered.  Keep this helper at the call sites so the
    // job context construction remains explicit, but return the canonical
    // parent turn lineage.
    key.scope.turn_stream_id.clone()
}

fn job_event_id(key: &JobKey, kind: &str, discriminator: &str) -> String {
    let encoded = serde_json::to_vec(&json!({
        "schema": "trillionnium.owner-open.job-wire-event.v1",
        "scope": &key.scope,
        "job_id": &key.job_id,
        "kind": kind,
        "discriminator": discriminator
    }))
    .expect("job event identity serialization cannot fail");
    format!("job-event-{}", sha256_hex(&encoded))
}

fn build_job_frame(
    context: &JobContext,
    kind: &str,
    seq: u64,
    discriminator: &str,
    payload: Value,
) -> RunTurnFrame {
    let mut payload = payload;
    if let Some(request_sha256) = context.request_sha256.as_ref()
        && let Some(object) = payload.as_object_mut()
    {
        object.insert(
            "request_sha256".to_string(),
            Value::String(request_sha256.clone()),
        );
    }
    RunTurnFrame {
        kind: kind.to_string(),
        seq,
        payload,
        direction: Some("host_to_client".to_string()),
        client_seq: None,
        host_seq: None,
        frame_sha256: None,
        event_id: Some(job_event_id(&context.key, kind, discriminator)),
        connection_id: None,
        stream_id: Some(context.stream_id.clone()),
        turn_stream_id: Some(context.key.scope.turn_stream_id.clone()),
        session_id: Some(context.key.scope.session_id.clone()),
        profile_id: Some(context.key.scope.profile_id.clone()),
        task_id: Some(context.key.scope.task_id.clone()),
        turn_id: Some(context.key.scope.turn_id.clone()),
        call_id: None,
        job_id: Some(context.key.job_id.clone()),
        tool: Some("shell.job".to_string()),
        target: None,
        target_id: None,
        extensions: BTreeMap::new(),
    }
}

fn runtime_job_frame(context: &JobContext, seq: u64, event: &RuntimeJobEvent) -> RunTurnFrame {
    let (kind, payload) = match &event.event {
        RuntimeJobEventKind::ProcessIdentityBound {
            generation,
            identity,
        } => (
            FRAME_JOB_IDENTITY_BOUND,
            json!({
                "status": "process_identity_bound",
                "generation": generation,
                // Keep the tuple nested to mirror the library event and also
                // expose its fields at the frame level for older job clients
                // that only decode status payloads.
                "identity": {
                    "pid": identity.pid,
                    "process_group_id": identity.process_group_id,
                    "session_id": identity.session_id,
                    "boot_id": identity.boot_id,
                    "start_time_ticks": identity.start_time_ticks
                },
                "pid": identity.pid,
                "process_group_id": identity.process_group_id,
                "session_id": identity.session_id,
                "boot_id": identity.boot_id,
                "start_time_ticks": identity.start_time_ticks,
                "cursor_domain": RUNTIME_CURSOR_DOMAIN,
                "automatic_redispatch": false
            }),
        ),
        RuntimeJobEventKind::Started {
            generation,
            pid,
            pty,
        } => (
            FRAME_JOB_STARTED,
            json!({
                "status": "started",
                "generation": generation,
                "pid": pid,
                "pty": pty,
                "request_sha256": &context.request_sha256,
                "cursor_domain": RUNTIME_CURSOR_DOMAIN,
                "automatic_redispatch": false
            }),
        ),
        RuntimeJobEventKind::Output {
            generation,
            output_seq,
            stream,
            bytes,
            sha256,
        } => (
            FRAME_JOB_OUTPUT,
            json!({
                "status": "output",
                "generation": generation,
                "output_seq": output_seq,
                "stream": stream,
                "encoding": "base64",
                "data": JOB_BASE64.encode(bytes),
                "byte_count": bytes.len(),
                "sha256": sha256,
                "cursor_domain": RUNTIME_CURSOR_DOMAIN,
                "automatic_redispatch": false
            }),
        ),
        RuntimeJobEventKind::Terminal {
            generation,
            terminal_kind,
            exit_code,
            signal,
            observation_sha256,
            stdout_bytes,
            stderr_bytes,
        } => (
            FRAME_JOB_RESULT,
            json!({
                "status": "terminal",
                "generation": generation,
                "terminal_kind": terminal_kind,
                "exit_code": exit_code,
                "signal": signal,
                "observation_sha256": observation_sha256,
                "stdout_bytes": stdout_bytes,
                "stderr_bytes": stderr_bytes,
                "cursor_domain": RUNTIME_CURSOR_DOMAIN,
                "automatic_redispatch": false
            }),
        ),
        RuntimeJobEventKind::ProcessFault { phase, error } => (
            FRAME_JOB_STATUS,
            json!({
                "status": "process_fault",
                "phase": phase,
                "error": error,
                "automatic_redispatch": false
            }),
        ),
        RuntimeJobEventKind::JournalUnavailable { error } => (
            FRAME_JOB_STATUS,
            json!({
                "status": "journal_unavailable",
                "error": error,
                "automatic_redispatch": false
            }),
        ),
    };
    let mut frame = build_job_frame(context, kind, seq, &event.seq.to_string(), payload);
    // `event_id` is intentionally opaque and content-bound.  Carry the
    // runtime inspection cursor separately so the outer bounded transport can
    // report an exact recovery range without parsing the event ID.  The
    // transport field retains its historical name (`durable_cursor`) for wire
    // compatibility, while `cursor_domain` makes clear that this is a runtime
    // event sequence and is not a journal-record offset.
    frame
        .extensions
        .insert("durable_cursor".to_string(), json!(event.seq));
    frame.extensions.insert(
        "cursor_domain".to_string(),
        Value::String(RUNTIME_CURSOR_DOMAIN.to_string()),
    );
    if let Some(object) = frame.payload.as_object_mut() {
        object.insert("cursor".to_string(), json!(event.seq));
    }
    frame
}

fn job_resync_payload(inspection: &JobInspection) -> Value {
    let gap = inspection.gap.as_ref();
    json!({
        "status": "resync_required",
        "resync_required": true,
        "runtime_cursor_domain": RUNTIME_CURSOR_DOMAIN,
        "requested_inclusive_cursor": inspection.inclusive_cursor,
        "oldest_available_cursor": inspection.oldest_available_cursor,
        "next_cursor": inspection.next_cursor,
        "total_events": inspection.total_events,
        "has_more": inspection.has_more,
        "first_missing_cursor": gap.map(|value| value.first_missing_cursor),
        "last_missing_cursor": gap.map(|value| value.last_missing_cursor),
        "required_resume_cursor": gap.map(|value| value.last_missing_cursor.saturating_add(1)),
        "gap": gap,
        "durable_fallback_available": inspection.durable_fallback_available,
        "event_log_status": &inspection.event_log_status,
        "journal_error": &inspection.journal_error,
        "read_only": true,
        "side_effects": false,
        "automatic_redispatch": false
    })
}

fn job_resync_frame(
    context: &JobContext,
    seq: u64,
    inspection: &JobInspection,
) -> RunTurnFrame {
    let discriminator = inspection
        .gap
        .as_ref()
        .map(|gap| {
            format!(
                "resync-{}-{}",
                gap.first_missing_cursor, gap.last_missing_cursor
            )
        })
        .unwrap_or_else(|| format!("resync-{}", inspection.inclusive_cursor));
    build_job_frame(
        context,
        FRAME_JOB_STATUS,
        seq,
        &discriminator,
        job_resync_payload(inspection),
    )
}

fn default_profile() -> String {
    DEFAULT_PROFILE_ID.to_string()
}

fn hash_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    fn context() -> JobContext {
        let key = JobKey::new(
            JobScope::new("session", "profile", "task", "turn", "stream"),
            "job",
        );
        JobContext {
            stream_id: job_stream_id(&key),
            key,
            request_sha256: Some("request-digest".to_string()),
        }
    }

    fn inspection() -> JobInspection {
        JobInspection {
            snapshot: None,
            registry_events: Vec::new(),
            runtime_events: Vec::new(),
            inclusive_cursor: 99,
            oldest_available_cursor: 99,
            next_cursor: 99,
            total_events: 0,
            has_more: false,
            resync_required: false,
            gap: None,
            durable_fallback_available: true,
            event_log_status: trillionnium_owner_open_job_runtime::EventLogStatus::Durable,
            journal_error: None,
            replay_status: trillionnium_owner_open_job_runtime::ReplayStatus::Durable,
        }
    }

    #[test]
    fn process_identity_bound_frame_preserves_the_bound_tuple() {
        let event = RuntimeJobEvent {
            seq: 4,
            job_id: "job".to_string(),
            event: RuntimeJobEventKind::ProcessIdentityBound {
                generation: 2,
                identity: trillionnium_owner_open_job_runtime::ProcessIdentity {
                    pid: 1234,
                    process_group_id: 1234,
                    session_id: 1234,
                    boot_id: "a".repeat(64),
                    start_time_ticks: 9876,
                },
            },
        };
        let frame = runtime_job_frame(&context(), 0, &event);
        assert_eq!(frame.kind, FRAME_JOB_IDENTITY_BOUND);
        assert_eq!(frame.payload["status"], "process_identity_bound");
        assert_eq!(frame.payload["identity"]["pid"], 1234);
        assert_eq!(frame.payload["identity"]["process_group_id"], 1234);
        assert_eq!(frame.payload["identity"]["session_id"], 1234);
        assert_eq!(frame.payload["identity"]["start_time_ticks"], 9876);
        assert_eq!(frame.payload["identity"]["boot_id"], "a".repeat(64));
        frame
            .validate_mechanical(&MechanicalLimits::default())
            .expect("identity-bound frame must pass the shared envelope validator");
    }

    #[test]
    fn durable_inspection_cursor_is_not_derived_from_runtime_cursor() {
        let mut state = JobDeliveryState {
            context: context(),
            next_wire_seq: 0,
            next_runtime_cursor: 99,
            announced_gap: None,
        };
        let records = vec![
            json!({"record": 0}),
            json!({"record": 1}),
            json!({"record": 2}),
            json!({"record": 3}),
        ];
        let frame = bounded_inspection_frame(
            &mut state,
            FRAME_JOB_INSPECT_RESULT,
            &inspection(),
            &records,
            2,
            None,
            None,
            None,
            1024 * 1024,
        )
        .expect("bounded inspection should encode");
        assert_eq!(frame.payload["runtime_cursor_domain"], RUNTIME_CURSOR_DOMAIN);
        assert_eq!(frame.payload["durable_cursor_domain"], DURABLE_CURSOR_DOMAIN);
        assert_eq!(frame.payload["durable_inclusive_cursor"], 2);
        assert_eq!(frame.payload["durable_next_cursor"], 3);
        assert_eq!(frame.payload["durable_records"][0]["record"], 2);
    }

    #[test]
    fn durable_inspection_cursor_after_end_fails_closed() {
        let mut state = JobDeliveryState {
            context: context(),
            next_wire_seq: 0,
            next_runtime_cursor: 0,
            announced_gap: None,
        };
        let error = bounded_inspection_frame(
            &mut state,
            FRAME_JOB_INSPECT_RESULT,
            &inspection(),
            &[json!({"record": 0})],
            2,
            None,
            None,
            None,
            1024 * 1024,
        )
        .expect_err("cursor past journal end must be rejected");
        assert!(error.contains("after 1 journal records"));
        assert_eq!(state.next_wire_seq, 0);
    }

    #[test]
    fn job_frames_use_the_canonical_turn_stream_alias() {
        let context = context();
        let frame = build_job_frame(
            &context,
            FRAME_JOB_STATUS,
            0,
            "alias-check",
            json!({"status": "process_fault"}),
        );
        assert_eq!(frame.stream_id, frame.turn_stream_id);
        frame
            .validate_mechanical(&MechanicalLimits::default())
            .expect("job frame must pass the shared envelope validator");
    }

    #[test]
    fn resync_payload_carries_exact_runtime_gap() {
        let mut inspection = inspection();
        inspection.oldest_available_cursor = 7;
        inspection.next_cursor = 10;
        inspection.total_events = 10;
        inspection.has_more = true;
        inspection.resync_required = true;
        inspection.gap = Some(trillionnium_owner_open_job_runtime::JobObservationGap {
            first_missing_cursor: 0,
            last_missing_cursor: 6,
        });
        let payload = job_resync_payload(&inspection);
        assert_eq!(payload["status"], "resync_required");
        assert_eq!(payload["runtime_cursor_domain"], RUNTIME_CURSOR_DOMAIN);
        assert_eq!(payload["first_missing_cursor"], 0);
        assert_eq!(payload["last_missing_cursor"], 6);
        assert_eq!(payload["required_resume_cursor"], 7);
        assert_eq!(payload["gap"]["first_missing_cursor"], 0);
        assert_eq!(payload["automatic_redispatch"], false);

        let frame = job_resync_frame(&context(), 4, &inspection);
        assert_eq!(frame.kind, FRAME_JOB_STATUS);
        assert_eq!(frame.seq, 4);
        assert_eq!(frame.payload["required_resume_cursor"], 7);
    }

    #[test]
    fn job_wait_is_a_bounded_read_only_job_frame() {
        let encoded = serde_json::to_vec(&json!({
            "kind": FRAME_JOB_WAIT,
            "seq": 1,
            "direction": "client_to_host",
            "payload": {
                "session_id": "session",
                "profile_id": "profile",
                "task_id": "task",
                "turn_id": "turn",
                "turn_stream_id": "stream",
                "job_id": "job",
                "inclusive_cursor": 3,
                "durable_inclusive_cursor": 2,
                "limit": 8,
                "timeout_ms": 1234,
                "poll_interval_ms": 7
            }
        }))
        .expect("encode wait frame");
        let frame = RunTurnFrame::decode(&encoded, &MechanicalLimits::default())
            .expect("decode wait frame");
        assert!(is_job_frame(&frame.kind));
        let decoded = decode_job_wait(&frame).expect("decode wait control");
        assert_eq!(decoded.inclusive_cursor, 3);
        assert_eq!(decoded.durable_inclusive_cursor, 2);
        assert_eq!(decoded.timeout_ms, Some(1234));
        assert_eq!(decoded.poll_interval_ms, Some(7));
    }

    #[test]
    fn job_wait_rejects_unbounded_timeout_and_zero_poll_interval() {
        let base = json!({
            "kind": FRAME_JOB_WAIT,
            "seq": 1,
            "direction": "client_to_host",
            "payload": {
                "session_id": "session",
                "profile_id": "profile",
                "task_id": "task",
                "turn_id": "turn",
                "turn_stream_id": "stream",
                "job_id": "job"
            }
        });
        let mut timeout = base.clone();
        timeout["payload"]["timeout_ms"] = json!(MAX_JOB_WAIT_TIMEOUT_MS + 1);
        let timeout = RunTurnFrame::decode(
            &serde_json::to_vec(&timeout).expect("encode timeout"),
            &MechanicalLimits::default(),
        )
        .expect("mechanical timeout frame");
        assert!(decode_job_wait(&timeout)
            .expect_err("timeout ceiling must be enforced")
            .contains("timeout_ms"));

        let mut poll = base;
        poll["payload"]["poll_interval_ms"] = json!(0);
        let poll = RunTurnFrame::decode(
            &serde_json::to_vec(&poll).expect("encode poll"),
            &MechanicalLimits::default(),
        )
        .expect("mechanical poll frame");
        assert!(decode_job_wait(&poll)
            .expect_err("zero poll interval must be rejected")
            .contains("poll_interval_ms"));
    }
}
