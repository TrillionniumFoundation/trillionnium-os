use super::r5_persistence::{request_sha256, stable_turn_stream_id};

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::env;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trillionnium_owner_open_event_store::{
    DurableEventStore, EventInput, EventStoreLimits, SyncPolicy, TurnScope as DurableTurnScope,
};
use trillionnium_owner_open_stream_window::{
    ApplyDisposition, BlockedReason, ReserveDisposition, StreamControl, StreamWindow,
    StreamWindowConfig, StreamWindowSnapshot,
};
use trillionnium_owner_open_types::{
    DEFAULT_PROFILE_ID, FRAME_HELLO, FRAME_HELLO_ACK, FRAME_MODEL_DELTA, FRAME_MODEL_MESSAGE,
    FRAME_PROVIDER_STATUS, FRAME_STREAM_PAUSE, FRAME_STREAM_RESUME,
    FRAME_STREAM_WINDOW_UPDATE, FRAME_TOOL_PTY, FRAME_TOOL_RESULT, FRAME_TOOL_STARTED,
    FRAME_TOOL_STDERR, FRAME_TOOL_STDOUT, FRAME_TURN_ACCEPTED, FRAME_TURN_END, FRAME_TURN_START,
    MechanicalLimits, PROTOCOL, PROTOCOL_VERSION, RunTurnFrame, decode_strict_value,
};

const HOST_IMPLEMENTATION_V5: &str =
    "trillionnium-owner-open-r5-inspect-flow-transport-source";
const FRAME_HOST_ERROR: &str = "host.error";
const FRAME_STREAM_WINDOW_ACK: &str = "stream.window_update.ack";
const FRAME_STREAM_PAUSE_ACK: &str = "stream.pause.ack";
const FRAME_STREAM_RESUME_ACK: &str = "stream.resume.ack";
const FRAME_STREAM_RESYNC_REQUIRED: &str = "stream.resync_required";
const FRAME_STREAM_FLOW_DISABLED: &str = "stream.flow_disabled";
const TRANSPORT_QUEUE_DEPTH: usize = 256;
/// Maximum number of consecutive client-domain messages admitted ahead of a
/// ready core-domain message while a handshake gate is open.  This preserves
/// pipelined hello/turn admission without allowing a client flood to starve
/// the core reader.
const MAX_CLIENT_PRIORITY_BURST: usize = 8;
const TRANSPORT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const CORE_READER_DRAIN_GRACE: Duration = Duration::from_secs(2);
const DEFAULT_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_CREDIT_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_MAX_CHUNK_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_CONTROL_HISTORY: usize = 256;
