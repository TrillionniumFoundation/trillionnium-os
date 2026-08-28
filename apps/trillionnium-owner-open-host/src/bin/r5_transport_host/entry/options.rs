#[derive(Debug)]
struct Options {
    core: PathBuf,
    core_args: Vec<OsString>,
    event_store: Option<PathBuf>,
    buffer_bytes: usize,
    max_credit_bytes: u64,
    max_chunk_bytes: u64,
    control_history: usize,
    help: bool,
}

impl Options {
    fn parse(args: Vec<OsString>) -> Result<Self, String> {
        let mut core = None;
        let mut core_args = Vec::new();
        let mut event_store = None;
        let mut buffer_bytes = DEFAULT_BUFFER_BYTES;
        let mut max_credit_bytes = DEFAULT_MAX_CREDIT_BYTES;
        let mut max_chunk_bytes = DEFAULT_MAX_CHUNK_BYTES;
        let mut control_history = DEFAULT_CONTROL_HISTORY;
        let mut help = false;
        let mut index = 0usize;
        while index < args.len() {
            let option = args[index]
                .to_str()
                .ok_or_else(|| "command-line options must be UTF-8".to_string())?;
            match option {
                "--transport-core" => {
                    index += 1;
                    let value = args
                        .get(index)
                        .ok_or_else(|| "--transport-core requires a path".to_string())?;
                    core = Some(PathBuf::from(value));
                }
                "--transport-buffer-bytes" => {
                    index += 1;
                    buffer_bytes = parse_usize(&args, index, option)?;
                }
                "--transport-max-credit-bytes" => {
                    index += 1;
                    max_credit_bytes = parse_u64(&args, index, option)?;
                }
                "--transport-max-chunk-bytes" => {
                    index += 1;
                    max_chunk_bytes = parse_u64(&args, index, option)?;
                }
                "--transport-control-history" => {
                    index += 1;
                    control_history = parse_usize(&args, index, option)?;
                }
                "--transport-help" => help = true,
                "--help" | "-h" => help = true,
                "--event-store" => {
                    core_args.push(args[index].clone());
                    index += 1;
                    let value = args
                        .get(index)
                        .ok_or_else(|| "--event-store requires a path".to_string())?;
                    event_store = Some(PathBuf::from(value));
                    core_args.push(value.clone());
                }
                _ => core_args.push(args[index].clone()),
            }
            index += 1;
        }
        if buffer_bytes == 0 || buffer_bytes > 64 * 1024 * 1024 {
            return Err("--transport-buffer-bytes must be between 1 and 67108864".to_string());
        }
        if max_credit_bytes == 0
            || max_credit_bytes > 1024 * 1024 * 1024
            || max_chunk_bytes == 0
            || max_chunk_bytes > max_credit_bytes
            || control_history == 0
            || control_history > 4096
        {
            return Err("transport credit, chunk, or history bounds are invalid".to_string());
        }
        Ok(Self {
            core: core.unwrap_or(default_core_path()?),
            core_args,
            event_store,
            buffer_bytes,
            max_credit_bytes,
            max_chunk_bytes,
            control_history,
            help,
        })
    }

    fn usage() -> &'static str {
        "usage: trillionnium-owner-open-r5-host [transport options] --provider PATH [core options]\n\nTransport options:\n  --transport-core PATH\n  --transport-buffer-bytes N\n  --transport-max-credit-bytes N\n  --transport-max-chunk-bytes N\n  --transport-control-history N\n\nFlow control is opt-in per turn through stream.window_update, stream.pause and stream.resume. It requires a durable --event-store so bounded delivery never becomes silent observation loss."
    }
}

fn parse_u64(args: &[OsString], index: usize, option: &str) -> Result<u64, String> {
    args.get(index)
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("{option} requires a UTF-8 integer"))?
        .parse::<u64>()
        .map_err(|error| format!("invalid {option}: {error}"))
}

fn parse_usize(args: &[OsString], index: usize, option: &str) -> Result<usize, String> {
    let value = parse_u64(args, index, option)?;
    usize::try_from(value).map_err(|_| format!("{option} does not fit usize"))
}

fn default_core_path() -> Result<PathBuf, String> {
    let mut path = env::current_exe().map_err(|error| error.to_string())?;
    path.set_file_name("trillionnium-owner-open-r5-core");
    Ok(path)
}
