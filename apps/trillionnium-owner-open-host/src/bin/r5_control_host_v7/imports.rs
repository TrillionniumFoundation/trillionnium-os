use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ffi::OsString;
use std::io::{BufReader, Write as IoWrite};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{
    Receiver as JobReceiver, RecvTimeoutError as JobRecvTimeout, SyncSender as JobSender,
};
use std::sync::atomic::{AtomicU64, Ordering};

use std::thread;
use std::time::{Duration, Instant};

use crate::base::read_bounded_frame;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as JOB_BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trillionnium_owner_open_event_store::{EventRecord, TurnScope, EVENT_RECORD_SCHEMA};
use trillionnium_owner_open_job_registry::{
    JobEffectiveState, JobKey, JobRequest, JobScope,
};
use trillionnium_owner_open_job_runtime::{
    ControlDisposition, JOB_JOURNAL_SCHEMA, JobInspection, JobInvocation, JobManager,
    JobRuntimeConfig, JobRuntimeError, JobStartRequest, JobStartResult, PtySize,
    RuntimeJobEvent, RuntimeJobEventKind,
};
use trillionnium_owner_open_types::{
    DEFAULT_PROFILE_ID, FRAME_HELLO, FRAME_HELLO_ACK, FRAME_TURN_ACCEPTED, FRAME_TURN_END,
    FRAME_TURN_START,
};
