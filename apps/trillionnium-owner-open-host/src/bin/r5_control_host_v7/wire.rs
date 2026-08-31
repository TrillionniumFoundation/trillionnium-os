const FRAME_JOB_START: &str = "job.start";
const FRAME_JOB_START_RESULT: &str = "job.start.result";
const FRAME_JOB_INSPECT: &str = "job.inspect";
const FRAME_JOB_INSPECT_RESULT: &str = "job.inspect.result";
const FRAME_JOB_ATTACH: &str = "job.attach";
const FRAME_JOB_ATTACH_RESULT: &str = "job.attach.result";
const FRAME_JOB_DETACH: &str = "job.detach";
const FRAME_JOB_DETACH_RESULT: &str = "job.detach.result";
const FRAME_JOB_WRITE: &str = "job.write";
const FRAME_JOB_RESIZE: &str = "job.resize";
const FRAME_JOB_CLOSE_STDIN: &str = "job.close_stdin";
const FRAME_JOB_KILL: &str = "job.kill";
const FRAME_JOB_CONTROL_RESULT: &str = "job.control.result";
const FRAME_JOB_STARTED: &str = "job.started";
const FRAME_JOB_OUTPUT: &str = "job.output";
const FRAME_JOB_RESULT: &str = "job.result";
const FRAME_JOB_STATUS: &str = "job.status";

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
    limit: usize,
    data: Option<Vec<u8>>,
    size: Option<PtySize>,
    signal: Option<i32>,
}

fn is_job_frame(kind: &str) -> bool {
    matches!(
        kind,
        FRAME_JOB_START
            | FRAME_JOB_INSPECT
            | FRAME_JOB_ATTACH
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
    })
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
    let encoded = serde_json::to_vec(&json!({
        "schema": "trillionnium.owner-open.job-stream.v1",
        "scope": &key.scope,
        "job_id": &key.job_id
    }))
    .expect("job stream identity serialization cannot fail");
    format!("job-stream-{}", sha256_hex(&encoded))
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
    // report an exact recovery range without parsing the event ID.
    frame
        .extensions
        .insert("durable_cursor".to_string(), json!(event.seq));
    if let Some(object) = frame.payload.as_object_mut() {
        object.insert("cursor".to_string(), json!(event.seq));
    }
    frame
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
