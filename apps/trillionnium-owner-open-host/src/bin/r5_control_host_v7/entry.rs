const JOB_HOST_QUEUE_DEPTH: usize = 256;
const JOB_POLL_INTERVAL: Duration = Duration::from_millis(20);
const DEFAULT_JOB_INSPECT_LIMIT: usize = 256;
const MAX_JOB_INSPECT_LIMIT: usize = 4096;

pub(crate) fn run() -> Result<(), String> {
    let parsed = JobHostOptions::parse(std::env::args_os().skip(1).collect())?;
    if parsed.base.help {
        println!("{}", JobHostOptions::usage());
        return Ok(());
    }

    let shell_executable = parsed.base.shell.clone();
    let provider = JsonlProvider::new(JsonlProviderConfig {
        executable: parsed.base.provider,
        args: parsed.base.provider_args,
        shell_executable: parsed.base.shell,
        adb_executable: parsed.base.adb,
        cwd: parsed.base.provider_cwd,
        timeout: parsed.base.provider_timeout,
        ..JsonlProviderConfig::default()
    })
    .map_err(|error| error.to_string())?;

    let mut persistence = Persistence::open_best_effort(parsed.base.event_store.as_deref());
    let derived_job_store = parsed.job_store.or_else(|| {
        parsed.base.event_store.as_ref().map(|path| {
            let mut derived = path.clone();
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .map_or_else(|| "jobs.jsonl".to_string(), |value| format!("{value}.jobs"));
            derived.set_extension(extension);
            derived
        })
    });
    let manager = JobManager::open(
        JobRuntimeConfig {
            allow_unjournaled_effects: parsed.allow_unjournaled_effects,
            ..JobRuntimeConfig::default()
        },
        derived_job_store.as_deref(),
    )
    .map_err(|error| error.to_string())?;

    let (outer_sender, outer_receiver) =
        std::sync::mpsc::sync_channel::<JobHostMessage>(JOB_HOST_QUEUE_DEPTH);
    spawn_job_input_reader(
        outer_sender.clone(),
        MechanicalLimits::default().max_frame_bytes,
    );

    let (core_sender, core_receiver) = sync_channel(HOST_QUEUE_DEPTH);
    let core_sender_for_worker = core_sender.clone();
    let outer_for_core = outer_sender.clone();
    let connection_id = new_connection_id();
    thread::Builder::new()
        .name("owner-open-v7-turn-core".to_string())
        .spawn(move || {
            let writer = CoreChannelWriter::new(outer_for_core.clone());
            let result = process_messages(
                writer,
                core_receiver,
                core_sender_for_worker,
                connection_id,
                provider,
                &mut persistence,
            );
            let _ = outer_for_core.send(JobHostMessage::CoreComplete(result));
        })
        .map_err(|error| format!("failed to spawn v4 turn core: {error}"))?;

    let stdout = std::io::stdout();
    process_job_host(
        stdout.lock(),
        outer_receiver,
        core_sender,
        manager,
        shell_executable,
    )
}

#[derive(Debug)]
struct JobHostOptions {
    base: Options,
    job_store: Option<PathBuf>,
    allow_unjournaled_effects: bool,
}

impl JobHostOptions {
    fn parse(args: Vec<OsString>) -> Result<Self, String> {
        let mut forwarded = Vec::new();
        let mut job_store = None;
        let mut require_job_journal = false;
        let mut allow_unjournaled_effects = false;
        let mut index = 0usize;
        while index < args.len() {
            let option = args[index]
                .to_str()
                .ok_or_else(|| "command-line options must be UTF-8".to_string())?;
            index = index.saturating_add(1);
            match option {
                "--job-store" => {
                    if job_store.is_some() {
                        return Err("--job-store may be supplied only once".to_string());
                    }
                    let value = args
                        .get(index)
                        .ok_or_else(|| "--job-store requires a value".to_string())?;
                    index = index.saturating_add(1);
                    job_store = Some(PathBuf::from(value));
                }
                "--require-job-journal" => {
                    require_job_journal = true;
                }
                "--allow-unjournaled-effects-for-development" => {
                    allow_unjournaled_effects = true;
                }
                _ => forwarded.push(args[index.saturating_sub(1)].clone()),
            }
        }
        if require_job_journal && allow_unjournaled_effects {
            return Err(
                "--require-job-journal conflicts with --allow-unjournaled-effects-for-development"
                    .to_string(),
            );
        }
        Ok(Self {
            base: Options::parse(forwarded)?,
            job_store,
            allow_unjournaled_effects,
        })
    }

    fn usage() -> String {
        format!(
            "{}\n\nLong-running job options:\n  --job-store /absolute/path/jobs.jsonl\n  --require-job-journal\n  --allow-unjournaled-effects-for-development\n\nDurable journaling is required by default. The development-only override permits unreplayable effects and must not appear in an installed product profile.\n\nThe job-aware v7 core multiplexes job.start/inspect/attach/detach/write/resize/close_stdin/kill with the existing v4 turn core. The selected v5 transport remains responsible for bounded persisted delivery flow control.",
            Options::usage()
        )
    }
}
