use super::*;
use super::r5_persistence::StoredInspection;
use sha2::{Digest, Sha256};
use trillionnium_owner_open_call_registry::{
    CallEvent, CallEventKind, CallSnapshot, EffectiveState,
};

use trillionnium_owner_open_types::{
    FRAME_CALL_INSPECT, FRAME_CALL_INSPECT_RESULT, FRAME_TURN_INSPECT,
    FRAME_TURN_INSPECT_RESULT,
};
const MAX_WIRE_INSPECT_LIMIT: usize = 256;
const MAX_DURABLE_CALL_SCAN: usize = 4096;
const HOST_IMPLEMENTATION_V4: &str =
    "trillionnium-owner-open-r5-inspect-control-host-source";

#[derive(Debug, Clone)]
struct InspectRequest {
    context: TurnContext,
    request_sha256: String,
    inclusive_cursor: u64,
    limit: usize,
    call_id: Option<String>,
}

pub(crate) fn run() -> Result<(), String> {
    let options = Options::parse(env::args_os().skip(1).collect())?;
    if options.help {
        println!(
            "{}\n\nAdditional read-only control frames: turn.inspect and call.inspect.",
            Options::usage()
        );
        return Ok(());
    }
    let provider = JsonlProvider::new(JsonlProviderConfig {
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
    let (sender, receiver) = sync_channel(HOST_QUEUE_DEPTH);
    spawn_stdin_reader(sender.clone(), MechanicalLimits::default().max_frame_bytes);
    let stdout = io::stdout();
    process_messages(
        stdout.lock(),
        receiver,
        sender,
        new_connection_id(),
        provider,
        &mut persistence,
    )
}
