use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::io::Write as IoWrite;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{
    Receiver as JobReceiver, RecvTimeoutError as JobRecvTimeout, SyncSender as JobSender,
};
use std::thread;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as JOB_BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trillionnium_owner_open_job_registry::{
    JobEffectiveState, JobKey, JobRequest, JobScope,
};
use trillionnium_owner_open_job_runtime::{
    ControlDisposition, JobInspection, JobInvocation, JobManager, JobRuntimeConfig,
    JobStartRequest, JobStartResult, PtySize, RuntimeJobEvent, RuntimeJobEventKind,
};
