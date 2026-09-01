//! Durable owner-open observation event store.
//!
//! This append-only store records correlation and raw observation payloads for
//! replay and conservative restart analysis. It is not an authorization
//! journal: append failure is reported to the embedding Host, which decides
//! whether the owner-open lineage continues as best-effort/unreplayable.

mod strict_json;

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::hash::Hash;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const EVENT_RECORD_SCHEMA: &str = "trillionnium.owner-open.event-record.v1";
/// The on-disk layout introduced by [`SegmentedEventStore`].
pub const SEGMENTED_EVENT_STORE_SCHEMA: &str = "trillionnium.owner-open.event-store.v2";
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error)]
pub enum EventStoreError {
    #[error("invalid owner-open event-store configuration: {0}")]
    InvalidConfiguration(String),
    #[error("owner-open event-store path is unsafe: {0}")]
    UnsafePath(String),
    #[error("owner-open event-store is already owned by another writer")]
    WriterBusy,
    #[error("owner-open event-store I/O failed: {0}")]
    Io(String),
    #[error("owner-open event-store record is invalid: {0}")]
    InvalidRecord(String),
    #[error("owner-open event-store contains a truncated final record")]
    TruncatedRecord,
    #[error("owner-open event ID conflicts with previously stored bytes")]
    EventConflict,
    #[error("owner-open event-store capacity is exhausted")]
    CapacityExhausted,
    #[error("owner-open event-store entered an indeterminate write state")]
    Poisoned,
    #[error("owner-open event-store state lock is poisoned")]
    StatePoisoned,
}

pub type Result<T> = std::result::Result<T, EventStoreError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPolicy {
    None,
    Data,
    Full,
}

/// Schema-level ceiling for the total bytes retained by one event-store
/// lineage. The value is intentionally above the default (512 MiB), while
/// still keeping descriptor checks, recovery and derived-sidecar reads within
/// a finite envelope when configuration crosses a trust boundary.
pub const MAX_EVENT_STORE_BYTES: u64 = 1024 * 1024 * 1024;
/// Schema-level ceiling for one encoded JSON event record. Recovery uses this
/// value as a read-ahead bound, so it must remain a finite, addressable
/// allocation rather than an arbitrary `usize` supplied by a caller.
pub const MAX_EVENT_RECORD_BYTES: usize = 64 * 1024 * 1024;
/// Schema-level ceiling for the in-memory recovered record/index set.
pub const MAX_EVENT_RECORDS: usize = 1_048_576;
/// Schema-level ceiling for event identifiers and scope identifiers.
pub const MAX_EVENT_ID_BYTES: usize = 4 * 1024;
/// Schema-level ceiling for the event kind string.
pub const MAX_EVENT_KIND_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventStoreLimits {
    pub max_store_bytes: u64,
    pub max_record_bytes: usize,
    pub max_records: usize,
    pub max_id_bytes: usize,
    pub max_kind_bytes: usize,
}

impl Default for EventStoreLimits {
    fn default() -> Self {
        Self {
            max_store_bytes: 512 * 1024 * 1024,
            max_record_bytes: 32 * 1024 * 1024,
            max_records: 1_000_000,
            max_id_bytes: 256,
            max_kind_bytes: 256,
        }
    }
}

impl EventStoreLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_store_bytes == 0
            || self.max_record_bytes == 0
            || self.max_records == 0
            || self.max_id_bytes == 0
            || self.max_kind_bytes == 0
        {
            return Err(invalid_config("event-store limits must be non-zero"));
        }
        if self.max_store_bytes > MAX_EVENT_STORE_BYTES
            || self.max_record_bytes > MAX_EVENT_RECORD_BYTES
            || self.max_records > MAX_EVENT_RECORDS
            || self.max_id_bytes > MAX_EVENT_ID_BYTES
            || self.max_kind_bytes > MAX_EVENT_KIND_BYTES
        {
            return Err(invalid_config(format!(
                "event-store limits exceed hard bounds (store <= {MAX_EVENT_STORE_BYTES}, record <= {MAX_EVENT_RECORD_BYTES}, records <= {MAX_EVENT_RECORDS}, id <= {MAX_EVENT_ID_BYTES}, kind <= {MAX_EVENT_KIND_BYTES})"
            )));
        }
        let max_record_bytes = u64::try_from(self.max_record_bytes)
            .map_err(|_| invalid_config("event record bound is not addressable"))?;
        if max_record_bytes > self.max_store_bytes {
            return Err(invalid_config(
                "event record bound cannot exceed the store byte bound",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnScope {
    pub session_id: String,
    pub profile_id: String,
    pub task_id: String,
    pub turn_id: String,
    pub turn_stream_id: String,
}

impl TurnScope {
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        profile_id: impl Into<String>,
        task_id: impl Into<String>,
        turn_id: impl Into<String>,
        turn_stream_id: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            profile_id: profile_id.into(),
            task_id: task_id.into(),
            turn_id: turn_id.into(),
            turn_stream_id: turn_stream_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EventInput {
    pub scope: TurnScope,
    pub event_id: String,
    pub kind: String,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRecord {
    pub schema: String,
    pub store_seq: u64,
    pub turn_seq: u64,
    pub scope: TurnScope,
    pub event_id: String,
    pub kind: String,
    pub payload: Value,
    pub payload_sha256: String,
    pub previous_record_sha256: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendDisposition {
    Appended,
    Existing,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AppendResult {
    pub disposition: AppendDisposition,
    pub record: EventRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventStoreSnapshot {
    pub record_count: usize,
    pub byte_count: u64,
    pub last_record_sha256: String,
    pub poisoned: bool,
}

/// Recovery behavior for the active segment.
///
/// A process can be interrupted after writing part of the final line.  Strict
/// mode preserves the v1 fail-closed behavior.  Repair mode only discards a
/// non-newline-terminated suffix of the final segment; every complete record
/// is still checked for schema, sequence and hash-chain validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPolicy {
    Strict,
    RepairTrailingPartial,
}

/// Hard ceiling for a single segmented WAL file.
pub const MAX_SEGMENT_BYTES: u64 = MAX_EVENT_STORE_BYTES;
/// Hard ceiling for records retained in one segmented WAL file.
pub const MAX_SEGMENT_RECORDS: usize = MAX_EVENT_RECORDS;
/// Hard ceiling for open WAL segments. Completed segments currently retain a
/// read descriptor, so a record-count bound alone is not an FD bound when a
/// caller configures one-record or very small segments.
pub const MAX_EVENT_SEGMENTS: usize = 1024;
/// Hard ceiling for records awaiting one group-commit boundary.
pub const MAX_GROUP_COMMIT_RECORDS: usize = MAX_EVENT_RECORDS;
/// Hard ceiling for bytes awaiting one group-commit boundary.
pub const MAX_GROUP_COMMIT_BYTES: u64 = 256 * 1024 * 1024;
/// Hard ceiling for time between append-driven group-commit checks.
pub const MAX_GROUP_COMMIT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Configuration for the v2 segmented event store.
///
/// The existing [`DurableEventStore`] remains the compatibility API for the
/// v1 single-file format.  New users can opt into this layout explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentedEventStoreConfig {
    pub limits: EventStoreLimits,
    /// Soft upper bound for one segment.  A single record may exceed this
    /// value when it is otherwise valid and fits the store limit.
    pub max_segment_bytes: u64,
    pub max_segment_records: usize,
    /// Group-commit bounds.  A pending batch is synced when any bound is hit,
    /// or when `group_commit_interval` has elapsed at the next append.
    pub group_commit_records: usize,
    pub group_commit_bytes: u64,
    pub group_commit_interval: Duration,
    pub sync_policy: SyncPolicy,
    pub recovery: RecoveryPolicy,
}

impl Default for SegmentedEventStoreConfig {
    fn default() -> Self {
        Self {
            limits: EventStoreLimits::default(),
            max_segment_bytes: 64 * 1024 * 1024,
            max_segment_records: 100_000,
            group_commit_records: 64,
            group_commit_bytes: 1024 * 1024,
            group_commit_interval: Duration::from_millis(10),
            sync_policy: SyncPolicy::Data,
            recovery: RecoveryPolicy::Strict,
        }
    }
}

impl SegmentedEventStoreConfig {
    #[must_use]
    pub fn new(limits: EventStoreLimits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// Construct the default segmented configuration and validate every
    /// caller-controlled bound immediately. Existing callers can continue to
    /// use [`Self::new`]; every store-opening API also validates before any
    /// filesystem discovery or recovery allocation.
    pub fn try_new(limits: EventStoreLimits) -> Result<Self> {
        let config = Self::new(limits);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        if self.max_segment_bytes == 0
            || self.max_segment_records == 0
            || self.group_commit_records == 0
            || self.group_commit_bytes == 0
            || self.group_commit_interval.is_zero()
        {
            return Err(invalid_config(
                "segmented event-store bounds must all be non-zero",
            ));
        }
        if self.max_segment_bytes > MAX_SEGMENT_BYTES
            || self.max_segment_records > MAX_SEGMENT_RECORDS
            || self.group_commit_records > MAX_GROUP_COMMIT_RECORDS
            || self.group_commit_bytes > MAX_GROUP_COMMIT_BYTES
            || self.group_commit_interval > MAX_GROUP_COMMIT_INTERVAL
        {
            return Err(invalid_config(format!(
                "segmented event-store bounds exceed hard limits (segment bytes <= {MAX_SEGMENT_BYTES}, segment records <= {MAX_SEGMENT_RECORDS}, group records <= {MAX_GROUP_COMMIT_RECORDS}, group bytes <= {MAX_GROUP_COMMIT_BYTES}, group interval <= {MAX_GROUP_COMMIT_INTERVAL:?})"
            )));
        }
        if self.max_segment_bytes > self.limits.max_store_bytes {
            return Err(invalid_config(
                "segment byte bound cannot exceed the store byte bound",
            ));
        }
        Ok(())
    }
}

/// Physical location of an indexed event record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentLocation {
    pub segment_id: u64,
    pub offset: u64,
    pub byte_len: u64,
    pub store_seq: u64,
}

/// Read/write health and bounded-queue counters for a segmented store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentedEventStoreSnapshot {
    pub segment_count: usize,
    pub record_count: usize,
    pub indexed_count: usize,
    pub byte_count: u64,
    pub pending_records: usize,
    pub pending_bytes: u64,
    pub last_record_sha256: String,
    pub poisoned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EventKey {
    scope: TurnScope,
    event_id: String,
}

impl EventKey {
    fn new(scope: TurnScope, event_id: String) -> Self {
        Self { scope, event_id }
    }
}

#[derive(Debug)]
struct State {
    file: File,
    records: Vec<EventRecord>,
    by_key: HashMap<EventKey, usize>,
    next_turn_seq: HashMap<TurnScope, u64>,
    byte_count: u64,
    last_record_sha256: String,
    poisoned: bool,
}

#[derive(Debug)]
pub struct DurableEventStore {
    path: PathBuf,
    limits: EventStoreLimits,
    sync_policy: SyncPolicy,
    state: Mutex<State>,
}

impl DurableEventStore {
    pub fn open(
        path: impl AsRef<Path>,
        limits: EventStoreLimits,
        sync_policy: SyncPolicy,
    ) -> Result<Self> {
        limits.validate()?;
        let path = path.as_ref().to_path_buf();
        validate_store_path(&path)?;
        let parent = path
            .parent()
            .ok_or_else(|| EventStoreError::UnsafePath("store path has no parent".to_string()))?;
        let parent_before = validate_store_parent(parent)?;
        let path_before = regular_path_metadata(&path, "store entry")?;
        let (mut file, existed, identity_before) = match path_before {
            Some(metadata) => {
                let file = OpenOptions::new()
                    .read(true)
                    .append(true)
                    .mode(0o600)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                    .open(&path)
                    .map_err(|error| EventStoreError::Io(error.to_string()))?;
                (file, true, Some(metadata))
            }
            None => {
                let created = OpenOptions::new()
                    .read(true)
                    .append(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                    .open(&path);
                match created {
                    Ok(file) => (file, false, None),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        // Another opener won the create race.  Snapshot the
                        // inode that we are about to open and require the FD
                        // to identify that exact inode below.
                        let raced =
                            regular_path_metadata(&path, "store entry")?.ok_or_else(|| {
                                EventStoreError::UnsafePath(
                                    "store entry disappeared after create race".to_string(),
                                )
                            })?;
                        let file = OpenOptions::new()
                            .read(true)
                            .append(true)
                            .mode(0o600)
                            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                            .open(&path)
                            .map_err(|error| EventStoreError::Io(error.to_string()))?;
                        (file, true, Some(raced))
                    }
                    Err(error) => return Err(EventStoreError::Io(error.to_string())),
                }
            }
        };
        if !existed {
            set_mode_on_descriptor(&file, 0o600, "store file")?;
        }
        let (descriptor_metadata, path_metadata) =
            validate_opened_path_identity(&path, identity_before.as_ref(), &file, "store file")?;
        lock_writer(&file)?;
        validate_store_file_metadata(&descriptor_metadata, "store file")?;
        validate_store_file_metadata(&path_metadata, "store file")?;
        // A pathname replacement while the writer lease was being acquired
        // must not leave this instance writing an inode that is no longer the
        // configured store entry.
        let (descriptor_metadata, path_metadata) =
            validate_opened_path_identity(&path, identity_before.as_ref(), &file, "store file")?;
        validate_store_file_metadata(&descriptor_metadata, "store file")?;
        validate_store_file_metadata(&path_metadata, "store file")?;
        let parent_after = validate_store_parent(parent)?;
        if parent_before != parent_after {
            return Err(EventStoreError::UnsafePath(
                "store parent changed while the file was opened".to_string(),
            ));
        }
        if !existed {
            sync_directory(parent)?;
        }

        if descriptor_metadata.len() > limits.max_store_bytes {
            return Err(EventStoreError::CapacityExhausted);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|error| EventStoreError::Io(error.to_string()))?;
        let recovered = recover_records(&file, &limits)?;
        file.seek(SeekFrom::End(0))
            .map_err(|error| EventStoreError::Io(error.to_string()))?;

        Ok(Self {
            path,
            limits,
            sync_policy,
            state: Mutex::new(State {
                file,
                records: recovered.records,
                by_key: recovered.by_key,
                next_turn_seq: recovered.next_turn_seq,
                byte_count: recovered.byte_count,
                last_record_sha256: recovered.last_record_sha256,
                poisoned: false,
            }),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, input: EventInput) -> Result<AppendResult> {
        validate_event_input(&input, &self.limits)?;
        let payload_bytes = serde_json::to_vec(&input.payload)
            .map_err(|error| EventStoreError::InvalidRecord(error.to_string()))?;
        let payload_sha256 = sha256_hex(&payload_bytes);
        let key = EventKey::new(input.scope.clone(), input.event_id.clone());
        let mut state = self.lock()?;
        if state.poisoned {
            return Err(EventStoreError::Poisoned);
        }
        if let Some(index) = state.by_key.get(&key).copied() {
            let existing = state
                .records
                .get(index)
                .ok_or(EventStoreError::StatePoisoned)?;
            if existing.kind == input.kind
                && existing.payload_sha256 == payload_sha256
                && existing.payload == input.payload
            {
                return Ok(AppendResult {
                    disposition: AppendDisposition::Existing,
                    record: existing.clone(),
                });
            }
            return Err(EventStoreError::EventConflict);
        }
        if state.records.len() >= self.limits.max_records {
            return Err(EventStoreError::CapacityExhausted);
        }
        let store_seq =
            u64::try_from(state.records.len()).map_err(|_| EventStoreError::CapacityExhausted)?;
        let turn_seq = state.next_turn_seq.get(&input.scope).copied().unwrap_or(0);
        let previous_record_sha256 = state.last_record_sha256.clone();
        let record_sha256 = record_digest(&RecordPreimage {
            schema: EVENT_RECORD_SCHEMA,
            store_seq,
            turn_seq,
            scope: &input.scope,
            event_id: &input.event_id,
            kind: &input.kind,
            payload: &input.payload,
            payload_sha256: &payload_sha256,
            previous_record_sha256: &previous_record_sha256,
        })?;
        let record = EventRecord {
            schema: EVENT_RECORD_SCHEMA.to_string(),
            store_seq,
            turn_seq,
            scope: input.scope,
            event_id: input.event_id,
            kind: input.kind,
            payload: input.payload,
            payload_sha256,
            previous_record_sha256,
            record_sha256,
        };
        validate_record(&record, &self.limits)?;
        let mut encoded = serde_json::to_vec(&record)
            .map_err(|error| EventStoreError::InvalidRecord(error.to_string()))?;
        if encoded.is_empty() || encoded.len() > self.limits.max_record_bytes {
            return Err(EventStoreError::CapacityExhausted);
        }
        encoded.push(b'\n');
        let encoded_len =
            u64::try_from(encoded.len()).map_err(|_| EventStoreError::CapacityExhausted)?;
        let expected_len = state
            .byte_count
            .checked_add(encoded_len)
            .filter(|value| *value <= self.limits.max_store_bytes)
            .ok_or(EventStoreError::CapacityExhausted)?;

        if let Err(error) = append_record_bytes(&mut state.file, &encoded, self.sync_policy) {
            state.poisoned = true;
            return Err(error);
        }
        let actual_len = match state.file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                state.poisoned = true;
                return Err(EventStoreError::Io(error.to_string()));
            }
        };
        if actual_len != expected_len {
            state.poisoned = true;
            return Err(EventStoreError::Poisoned);
        }

        let index = state.records.len();
        state.by_key.insert(key, index);
        state
            .next_turn_seq
            .insert(record.scope.clone(), turn_seq.saturating_add(1));
        state.byte_count = expected_len;
        state.last_record_sha256 = record.record_sha256.clone();
        state.records.push(record.clone());
        Ok(AppendResult {
            disposition: AppendDisposition::Appended,
            record,
        })
    }

    pub fn replay(&self, scope: &TurnScope, inclusive_turn_seq: u64) -> Result<Vec<EventRecord>> {
        validate_scope(scope, &self.limits)?;
        let state = self.lock()?;
        Ok(state
            .records
            .iter()
            .filter(|record| &record.scope == scope && record.turn_seq >= inclusive_turn_seq)
            .cloned()
            .collect())
    }

    pub fn get(&self, scope: &TurnScope, event_id: &str) -> Result<Option<EventRecord>> {
        validate_scope(scope, &self.limits)?;
        validate_id("event_id", event_id, self.limits.max_id_bytes)?;
        let state = self.lock()?;
        let key = EventKey::new(scope.clone(), event_id.to_string());
        Ok(state
            .by_key
            .get(&key)
            .and_then(|index| state.records.get(*index))
            .cloned())
    }

    pub fn all_records(&self) -> Result<Vec<EventRecord>> {
        Ok(self.lock()?.records.clone())
    }

    pub fn snapshot(&self) -> Result<EventStoreSnapshot> {
        let state = self.lock()?;
        Ok(EventStoreSnapshot {
            record_count: state.records.len(),
            byte_count: state.byte_count,
            last_record_sha256: state.last_record_sha256.clone(),
            poisoned: state.poisoned,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| EventStoreError::StatePoisoned)
    }
}

const SEGMENT_FILE_PREFIX: &str = "segment-";
const SEGMENT_FILE_SUFFIX: &str = ".jsonl";
const SEGMENT_LOCK_FILE: &str = ".writer.lock";
const SEGMENT_INDEX_FILE: &str = "index.v2.json";
const SEGMENT_INDEX_TEMP_FILE: &str = ".index.v2.json.tmp";
const SEGMENT_INDEX_SCHEMA: &str = "trillionnium.owner-open.event-index.v2";
const SEGMENT_SNAPSHOT_FILE: &str = "snapshot.v2.json";
const SEGMENT_SNAPSHOT_TEMP_FILE: &str = ".snapshot.v2.json.tmp";
const SEGMENT_SNAPSHOT_SCHEMA: &str = "trillionnium.owner-open.event-snapshot.v2";

#[derive(Debug)]
struct SegmentMeta {
    id: u64,
    path: PathBuf,
    file: Arc<Mutex<File>>,
    byte_count: u64,
    record_count: usize,
    pending_records: usize,
    pending_bytes: u64,
}

#[derive(Debug)]
struct SegmentedState {
    segments: BTreeMap<u64, SegmentMeta>,
    active_id: u64,
    records: Vec<EventRecord>,
    by_key: HashMap<EventKey, usize>,
    by_scope: HashMap<TurnScope, Vec<usize>>,
    locations: HashMap<EventKey, SegmentLocation>,
    next_turn_seq: HashMap<TurnScope, u64>,
    byte_count: u64,
    last_record_sha256: String,
    pending_records: usize,
    pending_bytes: u64,
    last_sync: Instant,
    poisoned: bool,
}

#[derive(Debug)]
struct OpenSegment {
    id: u64,
    path: PathBuf,
    file: Arc<Mutex<File>>,
}

/// Segmented, indexed v2 event durability.
///
/// v1 callers continue to use [`DurableEventStore`] unchanged.  This type
/// stores the same v1 event-record bytes in numbered WAL segments and keeps a
/// key/scope index in memory (with a rebuildable, atomically-written sidecar).
/// Sequence reservation and index publication are short `RwLock` operations;
/// filesystem writes and syncs happen without holding that state lock.  The
/// active segment has a serialized writer, while completed segments are
/// immutable and can be read concurrently.
#[derive(Debug)]
pub struct SegmentedEventStore {
    root: PathBuf,
    index_path: PathBuf,
    config: SegmentedEventStoreConfig,
    // Keeping this descriptor alive holds the process-wide writer lease.
    _writer_lock: File,
    state: RwLock<SegmentedState>,
    append_gate: Mutex<()>,
}

/// Compatibility alias for callers that prefer an explicit v2 name.
pub type EventStoreV2 = SegmentedEventStore;
/// Compatibility alias for the v2 configuration.
pub type EventStoreV2Config = SegmentedEventStoreConfig;
/// Alternate spelling used by a few integration callers.
pub type RecoveryMode = RecoveryPolicy;

#[derive(Debug, Serialize)]
struct IndexManifest<'a> {
    schema: &'static str,
    record_count: usize,
    byte_count: u64,
    last_record_sha256: &'a str,
    segments: Vec<IndexManifestSegment>,
    entries: Vec<IndexManifestEntry>,
}

#[derive(Debug, Serialize)]
struct IndexManifestSegment {
    id: u64,
    byte_count: u64,
    record_count: usize,
}

#[derive(Debug, Serialize)]
struct IndexManifestEntry {
    scope: TurnScope,
    event_id: String,
    location: SegmentLocation,
}

#[derive(Debug, Serialize)]
struct SnapshotManifest<'a> {
    schema: &'static str,
    record_count: usize,
    byte_count: u64,
    last_record_sha256: &'a str,
    records: Vec<EventRecord>,
}

// Read-side manifests own their strings so they can be decoded through the
// duplicate-key rejecting `strict_json` codec.  The write-side manifests above
// intentionally borrow the current high-water values and remain allocation
// light on the flush/checkpoint path.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexManifestOwned {
    schema: String,
    record_count: usize,
    byte_count: u64,
    last_record_sha256: String,
    segments: Vec<IndexManifestSegmentOwned>,
    entries: Vec<IndexManifestEntryOwned>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexManifestSegmentOwned {
    id: u64,
    byte_count: u64,
    record_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexManifestEntryOwned {
    scope: TurnScope,
    event_id: String,
    location: SegmentLocation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotManifestOwned {
    schema: String,
    record_count: usize,
    byte_count: u64,
    last_record_sha256: String,
    records: Vec<EventRecord>,
}

impl SegmentedEventStore {
    /// Open or create a v2 store rooted at a dedicated service-owned directory.
    pub fn open(root: impl AsRef<Path>, config: SegmentedEventStoreConfig) -> Result<Self> {
        config.validate()?;
        let root = prepare_segment_root(root.as_ref())?;
        let lock_path = root.join(SEGMENT_LOCK_FILE);
        let writer_lock = open_writer_lock(&lock_path)?;
        validate_optional_sidecar(&root.join(SEGMENT_INDEX_FILE), "event index")?;
        validate_optional_sidecar(
            &root.join(SEGMENT_INDEX_TEMP_FILE),
            "event index temporary file",
        )?;
        validate_optional_sidecar(&root.join(SEGMENT_SNAPSHOT_FILE), "event snapshot")?;
        validate_optional_sidecar(
            &root.join(SEGMENT_SNAPSHOT_TEMP_FILE),
            "event snapshot temporary file",
        )?;
        let mut segments = discover_segments(&root)?;
        // Rotation publishes the next segment pathname before the first
        // record is written.  A process cut in that small window can leave a
        // zero-byte tail segment behind.  It is not an event and must not be
        // allowed to turn a restart into a permanent recovery failure.  Only
        // the contiguous empty tail is pruned: an empty segment in the middle
        // of the WAL remains a fail-closed corruption signal, and one empty
        // segment is retained for a genuinely new store.
        prune_empty_segment_tail(&root, &mut segments)?;
        if segments.is_empty() {
            segments.push(create_segment(&root, 1)?);
        }

        let recovered = recover_segmented_segments(&segments, &config)?;
        // Sidecars are rebuildable read-models, but an on-disk sidecar that is
        // present must still be authenticated against the WAL.  Accepting a
        // valid stale prefix keeps crash recovery idempotent; malformed or
        // divergent contents fail closed instead of being silently ignored.
        validate_recovery_sidecars(&root, &recovered, &config)?;
        let active_id = segments
            .last()
            .map(|segment| segment.id)
            .ok_or_else(|| invalid_config("segmented store has no active segment"))?;
        let mut segment_meta = BTreeMap::new();
        for segment in segments {
            let summary = recovered
                .segment_summaries
                .get(&segment.id)
                .ok_or(EventStoreError::StatePoisoned)?;
            segment_meta.insert(
                segment.id,
                SegmentMeta {
                    id: segment.id,
                    path: segment.path,
                    file: segment.file,
                    byte_count: summary.byte_count,
                    record_count: summary.record_count,
                    pending_records: 0,
                    pending_bytes: 0,
                },
            );
        }

        Ok(Self {
            root: root.clone(),
            index_path: root.join(SEGMENT_INDEX_FILE),
            config,
            _writer_lock: writer_lock,
            state: RwLock::new(SegmentedState {
                segments: segment_meta,
                active_id,
                records: recovered.records,
                by_key: recovered.by_key,
                by_scope: recovered.by_scope,
                locations: recovered.locations,
                next_turn_seq: recovered.next_turn_seq,
                byte_count: recovered.byte_count,
                last_record_sha256: recovered.last_record_sha256,
                pending_records: 0,
                pending_bytes: 0,
                last_sync: Instant::now(),
                poisoned: false,
            }),
            append_gate: Mutex::new(()),
        })
    }

    /// Convenience constructor retaining the v1 limits/sync call shape while
    /// selecting the v2 directory layout and default segment/commit bounds.
    pub fn open_with_limits(
        root: impl AsRef<Path>,
        limits: EventStoreLimits,
        sync_policy: SyncPolicy,
    ) -> Result<Self> {
        let mut config = SegmentedEventStoreConfig::new(limits);
        config.sync_policy = sync_policy;
        Self::open(root, config)
    }

    /// Convenience constructor for deployments using all v2 defaults.
    pub fn open_default(root: impl AsRef<Path>) -> Result<Self> {
        Self::open(root, SegmentedEventStoreConfig::default())
    }

    /// Migrate a validated v1 JSONL store into a fresh v2 segmented directory.
    ///
    /// The operation is idempotent and resumable: an exact legacy sequence is
    /// returned unchanged, while a valid legacy prefix is completed. Divergent
    /// bytes fail with [`EventStoreError::EventConflict`].
    pub fn migrate_legacy(
        legacy_path: impl AsRef<Path>,
        root: impl AsRef<Path>,
        config: SegmentedEventStoreConfig,
    ) -> Result<Self> {
        let legacy_path = legacy_path.as_ref();
        if !legacy_path.exists() {
            return Err(EventStoreError::Io(format!(
                "legacy event-store path does not exist: {}",
                legacy_path.display()
            )));
        }
        // Keep the v1 writer lease until the destination has been opened and
        // the complete source prefix has been copied.  Dropping this handle
        // after `all_records()` creates a split-brain window in which an old
        // writer can append a tail that the v2 snapshot never sees.
        let legacy = DurableEventStore::open(legacy_path, config.limits.clone(), SyncPolicy::Full)?;
        let legacy_records = legacy.all_records()?;
        let store = Self::open(root, config)?;
        reconcile_legacy_prefix(&store, &legacy_records, false)?;
        Ok(store)
    }

    /// Open a v2 store while fencing the retained v1 writer for the entire
    /// source-to-destination reconciliation.  Unlike [`Self::migrate_legacy`]
    /// this rolling-upgrade form accepts a destination that is already ahead
    /// of the v1 source, provided the source is an exact prefix.  That state
    /// is expected after the v2 writer has taken authority and the old JSONL
    /// file is intentionally retained as a read-only compatibility prefix.
    ///
    /// The source `DurableEventStore` remains alive until this function
    /// returns, so every writer using the v1 API is fenced while the source is
    /// snapshotted, the v2 writer lease is acquired, and any missing tail is
    /// appended.  A competing writer therefore receives `WriterBusy` instead
    /// of being able to append an unobserved migration tail.
    pub fn open_or_migrate_with_legacy_prefix(
        root: impl AsRef<Path>,
        legacy_path: impl AsRef<Path>,
        config: SegmentedEventStoreConfig,
    ) -> Result<Self> {
        Self::open_or_migrate_with_legacy_prefix_inner(
            root.as_ref(),
            legacy_path.as_ref(),
            config,
            || {},
        )
    }

    fn open_or_migrate_with_legacy_prefix_inner(
        root: &Path,
        legacy_path: &Path,
        config: SegmentedEventStoreConfig,
        after_source_snapshot: impl FnOnce(),
    ) -> Result<Self> {
        if !legacy_path.exists() {
            return Self::open(root, config);
        }

        // Deliberately retain this guard through destination open/reconcile;
        // see the method-level safety contract above.
        let legacy = DurableEventStore::open(legacy_path, config.limits.clone(), SyncPolicy::Full)?;
        let legacy_records = legacy.all_records()?;
        // Test callers use this hook to exercise the exact interleaving that
        // previously allowed a legacy append between snapshot and destination
        // open.  Production passes a no-op, while the source lease remains
        // held across the callback and all reconciliation below.
        after_source_snapshot();
        let store = Self::open(root, config)?;
        reconcile_legacy_prefix(&store, &legacy_records, true)?;
        Ok(store)
    }

    /// Alias that makes the source schema transition explicit at call sites.
    pub fn migrate_from_v1(
        legacy_path: impl AsRef<Path>,
        root: impl AsRef<Path>,
        config: SegmentedEventStoreConfig,
    ) -> Result<Self> {
        Self::migrate_legacy(legacy_path, root, config)
    }

    /// Export the authoritative v2 sequence to a v1 JSONL file for rollback
    /// or a rolling reader that has not learned the directory layout yet.
    /// Existing destination prefixes are resumed idempotently and divergent
    /// records fail with [`EventStoreError::EventConflict`].
    pub fn export_legacy(
        &self,
        legacy_path: impl AsRef<Path>,
        sync_policy: SyncPolicy,
    ) -> Result<()> {
        self.flush()?;
        let records = self.all_records()?;
        let legacy = DurableEventStore::open(legacy_path, self.config.limits.clone(), sync_policy)?;
        let existing = legacy.all_records()?;
        if existing.len() > records.len()
            || existing
                .iter()
                .zip(records.iter())
                .any(|(actual, expected)| actual != expected)
        {
            return Err(EventStoreError::EventConflict);
        }
        for record in records.iter().skip(existing.len()) {
            let result = legacy.append(EventInput {
                scope: record.scope.clone(),
                event_id: record.event_id.clone(),
                kind: record.kind.clone(),
                payload: record.payload.clone(),
            })?;
            if result.record != *record {
                return Err(EventStoreError::InvalidRecord(
                    "legacy export changed an event record".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Alias for callers that name the reverse migration explicitly.
    pub fn migrate_to_legacy(
        &self,
        legacy_path: impl AsRef<Path>,
        sync_policy: SyncPolicy,
    ) -> Result<()> {
        self.export_legacy(legacy_path, sync_policy)
    }

    /// Open a v2 store, importing the legacy file when the destination is empty.
    pub fn open_or_migrate(
        root: impl AsRef<Path>,
        legacy_path: impl AsRef<Path>,
        config: SegmentedEventStoreConfig,
    ) -> Result<Self> {
        if legacy_path.as_ref().exists() {
            // Always run the convergent migration when a v1 source exists.
            // `migrate_legacy` compares the complete existing destination
            // prefix and fails closed on extra or divergent v2 records.  The
            // previous empty-only shortcut silently accepted a split-brain
            // destination whenever the v2 directory already contained data.
            return Self::migrate_legacy(legacy_path, root, config);
        }
        Self::open(root, config)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn index_path(&self) -> &Path {
        &self.index_path
    }

    #[must_use]
    pub fn snapshot_path(&self) -> PathBuf {
        self.root.join(SEGMENT_SNAPSHOT_FILE)
    }

    #[must_use]
    pub fn manifest_path(&self) -> &Path {
        &self.index_path
    }

    /// Return the numbered WAL paths in ascending sequence order.
    pub fn segment_paths(&self) -> Result<Vec<PathBuf>> {
        Ok(self
            .read_state()?
            .segments
            .values()
            .map(|segment| segment.path.clone())
            .collect())
    }

    pub fn append(&self, input: EventInput) -> Result<AppendResult> {
        validate_event_input(&input, &self.config.limits)?;
        let payload_bytes = serde_json::to_vec(&input.payload)
            .map_err(|error| EventStoreError::InvalidRecord(error.to_string()))?;
        let payload_sha256 = sha256_hex(&payload_bytes);
        let key = EventKey::new(input.scope.clone(), input.event_id.clone());

        // The gate orders global sequence/hash reservations.  It is separate
        // from the read/write state lock, so no state lock spans file I/O or
        // fsync.  Completed segments remain readable while the active segment
        // is being committed.
        let _gate = self
            .append_gate
            .lock()
            .map_err(|_| EventStoreError::StatePoisoned)?;
        let (record, encoded, key) = {
            let state = self.read_state()?;
            if state.poisoned {
                return Err(EventStoreError::Poisoned);
            }
            if let Some(index) = state.by_key.get(&key).copied() {
                let existing = state
                    .records
                    .get(index)
                    .ok_or(EventStoreError::StatePoisoned)?;
                if existing.kind == input.kind
                    && existing.payload_sha256 == payload_sha256
                    && existing.payload == input.payload
                {
                    return Ok(AppendResult {
                        disposition: AppendDisposition::Existing,
                        record: existing.clone(),
                    });
                }
                return Err(EventStoreError::EventConflict);
            }
            if state.records.len() >= self.config.limits.max_records {
                return Err(EventStoreError::CapacityExhausted);
            }
            let store_seq = u64::try_from(state.records.len())
                .map_err(|_| EventStoreError::CapacityExhausted)?;
            let turn_seq = state.next_turn_seq.get(&input.scope).copied().unwrap_or(0);
            let previous_record_sha256 = state.last_record_sha256.clone();
            let record_sha256 = record_digest(&RecordPreimage {
                schema: EVENT_RECORD_SCHEMA,
                store_seq,
                turn_seq,
                scope: &input.scope,
                event_id: &input.event_id,
                kind: &input.kind,
                payload: &input.payload,
                payload_sha256: &payload_sha256,
                previous_record_sha256: &previous_record_sha256,
            })?;
            let record = EventRecord {
                schema: EVENT_RECORD_SCHEMA.to_string(),
                store_seq,
                turn_seq,
                scope: input.scope,
                event_id: input.event_id,
                kind: input.kind,
                payload: input.payload,
                payload_sha256,
                previous_record_sha256,
                record_sha256,
            };
            validate_record(&record, &self.config.limits)?;
            let mut encoded = serde_json::to_vec(&record)
                .map_err(|error| EventStoreError::InvalidRecord(error.to_string()))?;
            if encoded.is_empty() || encoded.len() > self.config.limits.max_record_bytes {
                return Err(EventStoreError::CapacityExhausted);
            }
            encoded.push(b'\n');
            let encoded_len =
                u64::try_from(encoded.len()).map_err(|_| EventStoreError::CapacityExhausted)?;
            state
                .byte_count
                .checked_add(encoded_len)
                .filter(|value| *value <= self.config.limits.max_store_bytes)
                .ok_or(EventStoreError::CapacityExhausted)?;
            (record, encoded, key)
        };

        self.ensure_active_segment(encoded.len())?;
        let (segment_id, offset, file) = {
            let state = self.read_state()?;
            let segment = state
                .segments
                .get(&state.active_id)
                .ok_or(EventStoreError::StatePoisoned)?;
            (segment.id, segment.byte_count, Arc::clone(&segment.file))
        };
        if let Err(error) = append_segment_bytes(&file, offset, &encoded) {
            self.mark_poisoned();
            return Err(error);
        }

        let encoded_len =
            u64::try_from(encoded.len()).map_err(|_| EventStoreError::CapacityExhausted)?;
        let should_sync = {
            let mut state = self.write_state()?;
            if state.poisoned {
                return Err(EventStoreError::Poisoned);
            }
            let segment_byte_count = state
                .segments
                .get(&segment_id)
                .ok_or(EventStoreError::StatePoisoned)?
                .byte_count;
            if segment_byte_count != offset {
                state.poisoned = true;
                return Err(EventStoreError::Poisoned);
            }
            let index = state.records.len();
            state.by_key.insert(key.clone(), index);
            state
                .by_scope
                .entry(record.scope.clone())
                .or_default()
                .push(index);
            state
                .next_turn_seq
                .insert(record.scope.clone(), record.turn_seq.saturating_add(1));
            state.locations.insert(
                key,
                SegmentLocation {
                    segment_id,
                    offset,
                    byte_len: encoded_len,
                    store_seq: record.store_seq,
                },
            );
            state.byte_count = state
                .byte_count
                .checked_add(encoded_len)
                .ok_or(EventStoreError::CapacityExhausted)?;
            state.last_record_sha256 = record.record_sha256.clone();
            state.records.push(record.clone());
            let segment = state
                .segments
                .get_mut(&segment_id)
                .ok_or(EventStoreError::StatePoisoned)?;
            segment.byte_count = segment
                .byte_count
                .checked_add(encoded_len)
                .ok_or(EventStoreError::CapacityExhausted)?;
            segment.record_count = segment.record_count.saturating_add(1);
            segment.pending_records = segment.pending_records.saturating_add(1);
            segment.pending_bytes = segment.pending_bytes.saturating_add(encoded_len);
            state.pending_records = state.pending_records.saturating_add(1);
            state.pending_bytes = state.pending_bytes.saturating_add(encoded_len);
            let elapsed = state.last_sync.elapsed();
            state.pending_records >= self.config.group_commit_records
                || state.pending_bytes >= self.config.group_commit_bytes
                || elapsed >= self.config.group_commit_interval
        };

        if should_sync {
            self.sync_pending_under_gate()?;
        }
        Ok(AppendResult {
            disposition: AppendDisposition::Appended,
            record,
        })
    }

    pub fn replay(&self, scope: &TurnScope, inclusive_turn_seq: u64) -> Result<Vec<EventRecord>> {
        validate_scope(scope, &self.config.limits)?;
        let state = self.read_state()?;
        Ok(state
            .by_scope
            .get(scope)
            .into_iter()
            .flat_map(|indexes| indexes.iter())
            .filter_map(|index| state.records.get(*index))
            .filter(|record| record.turn_seq >= inclusive_turn_seq)
            .cloned()
            .collect())
    }

    pub fn get(&self, scope: &TurnScope, event_id: &str) -> Result<Option<EventRecord>> {
        validate_scope(scope, &self.config.limits)?;
        validate_id("event_id", event_id, self.config.limits.max_id_bytes)?;
        let state = self.read_state()?;
        let key = EventKey::new(scope.clone(), event_id.to_string());
        Ok(state
            .by_key
            .get(&key)
            .and_then(|index| state.records.get(*index))
            .cloned())
    }

    pub fn location(&self, scope: &TurnScope, event_id: &str) -> Result<Option<SegmentLocation>> {
        validate_scope(scope, &self.config.limits)?;
        validate_id("event_id", event_id, self.config.limits.max_id_bytes)?;
        let state = self.read_state()?;
        Ok(state
            .locations
            .get(&EventKey::new(scope.clone(), event_id.to_string()))
            .copied())
    }

    pub fn all_records(&self) -> Result<Vec<EventRecord>> {
        Ok(self.read_state()?.records.clone())
    }

    pub fn snapshot(&self) -> Result<SegmentedEventStoreSnapshot> {
        let state = self.read_state()?;
        Ok(SegmentedEventStoreSnapshot {
            segment_count: state.segments.len(),
            record_count: state.records.len(),
            indexed_count: state.locations.len(),
            byte_count: state.byte_count,
            pending_records: state.pending_records,
            pending_bytes: state.pending_bytes,
            last_record_sha256: state.last_record_sha256.clone(),
            poisoned: state.poisoned,
        })
    }

    /// Sync pending segment bytes and atomically publish the rebuildable index.
    pub fn flush(&self) -> Result<()> {
        let _gate = self
            .append_gate
            .lock()
            .map_err(|_| EventStoreError::StatePoisoned)?;
        self.sync_pending_under_gate()?;
        self.write_index_manifest()
    }

    /// Append and wait for the configured filesystem durability barrier. This
    /// is the operation-authority boundary used by job acceptance/terminal
    /// records; ordinary observations may use [`Self::append`] and group
    /// commit for higher throughput.
    pub fn append_durable(&self, input: EventInput) -> Result<AppendResult> {
        if self.config.sync_policy == SyncPolicy::None {
            return Err(invalid_config(
                "append_durable requires Data or Full sync policy",
            ));
        }
        let result = self.append(input)?;
        self.sync_pending()?;
        Ok(result)
    }

    /// Drain pending WAL bytes without rewriting the derived index sidecar.
    pub fn sync_pending(&self) -> Result<()> {
        let _gate = self
            .append_gate
            .lock()
            .map_err(|_| EventStoreError::StatePoisoned)?;
        self.sync_pending_under_gate()
    }

    /// Alias used by integrations that call the operation `sync`.
    pub fn sync(&self) -> Result<()> {
        self.flush()
    }

    /// Persist a validated high-water snapshot and the derived key index.
    ///
    /// Snapshots are an optimization/read-model artifact; the segmented WAL
    /// remains authoritative and is always revalidated during recovery. This
    /// method is explicit so deployments can choose a checkpoint cadence
    /// appropriate to their recovery budget without inflating every append.
    pub fn checkpoint(&self) -> Result<SegmentedEventStoreSnapshot> {
        let _gate = self
            .append_gate
            .lock()
            .map_err(|_| EventStoreError::StatePoisoned)?;
        self.sync_pending_under_gate()?;
        let (record_count, byte_count, last_hash, records) = {
            let state = self.read_state()?;
            (
                state.records.len(),
                state.byte_count,
                state.last_record_sha256.clone(),
                state.records.clone(),
            )
        };
        let manifest = SnapshotManifest {
            schema: SEGMENT_SNAPSHOT_SCHEMA,
            record_count,
            byte_count,
            last_record_sha256: &last_hash,
            records,
        };
        let encoded = serde_json::to_vec(&manifest)
            .map_err(|error| EventStoreError::InvalidRecord(error.to_string()))?;
        self.atomic_sidecar_write(
            SEGMENT_SNAPSHOT_FILE,
            SEGMENT_SNAPSHOT_TEMP_FILE,
            &encoded,
            "event snapshot",
        )?;
        self.write_index_manifest()?;
        self.snapshot()
    }

    /// Alias for callers that use checkpoint terminology.
    pub fn persist_snapshot(&self) -> Result<SegmentedEventStoreSnapshot> {
        self.checkpoint()
    }

    pub fn pending(&self) -> Result<(usize, u64)> {
        let state = self.read_state()?;
        Ok((state.pending_records, state.pending_bytes))
    }

    fn ensure_active_segment(&self, encoded_len: usize) -> Result<()> {
        let encoded_len =
            u64::try_from(encoded_len).map_err(|_| EventStoreError::CapacityExhausted)?;
        let (active_bytes, active_records) = {
            let state = self.read_state()?;
            let segment = state
                .segments
                .get(&state.active_id)
                .ok_or(EventStoreError::StatePoisoned)?;
            (segment.byte_count, segment.record_count)
        };
        let rotate = active_records > 0
            && (active_records >= self.config.max_segment_records
                || active_bytes
                    .checked_add(encoded_len)
                    .is_some_and(|value| value > self.config.max_segment_bytes));
        if !rotate {
            return Ok(());
        }

        // A completed segment is immutable.  Commit any pending bytes before
        // publishing a new active segment so a crash cannot leave an
        // acknowledged segment behind an unsynced rotation.
        self.sync_pending_under_gate()?;
        let mut state = self.write_state()?;
        if state.segments.len() >= MAX_EVENT_SEGMENTS {
            return Err(EventStoreError::CapacityExhausted);
        }
        let next_id = state
            .segments
            .keys()
            .next_back()
            .copied()
            .and_then(|id| id.checked_add(1))
            .ok_or(EventStoreError::CapacityExhausted)?;
        let segment = create_segment(&self.root, next_id)?;
        state.active_id = next_id;
        state.segments.insert(
            next_id,
            SegmentMeta {
                id: next_id,
                path: segment.path,
                file: segment.file,
                byte_count: 0,
                record_count: 0,
                pending_records: 0,
                pending_bytes: 0,
            },
        );
        Ok(())
    }

    fn sync_pending_under_gate(&self) -> Result<()> {
        let targets: Vec<(u64, Arc<Mutex<File>>)> = {
            let state = self.read_state()?;
            if state.poisoned {
                return Err(EventStoreError::Poisoned);
            }
            state
                .segments
                .values()
                .filter(|segment| segment.pending_records > 0)
                .map(|segment| (segment.id, Arc::clone(&segment.file)))
                .collect()
        };
        if self.config.sync_policy != SyncPolicy::None {
            for (_, file) in &targets {
                let result = lock_file(file)?.sync_for(self.config.sync_policy);
                if let Err(error) = result {
                    self.mark_poisoned();
                    return Err(error);
                }
            }
        }
        let mut state = self.write_state()?;
        for (id, _) in targets {
            let Some((pending_records, pending_bytes)) = state
                .segments
                .get(&id)
                .map(|segment| (segment.pending_records, segment.pending_bytes))
            else {
                continue;
            };
            state.pending_records = state.pending_records.saturating_sub(pending_records);
            state.pending_bytes = state.pending_bytes.saturating_sub(pending_bytes);
            if let Some(segment) = state.segments.get_mut(&id) {
                segment.pending_records = 0;
                segment.pending_bytes = 0;
            }
        }
        state.last_sync = Instant::now();
        Ok(())
    }

    fn write_index_manifest(&self) -> Result<()> {
        let (mut entries, segments, record_count, byte_count, last_hash) = {
            let state = self.read_state()?;
            let mut entries = state
                .locations
                .iter()
                .map(|(key, location)| IndexManifestEntry {
                    scope: key.scope.clone(),
                    event_id: key.event_id.clone(),
                    location: *location,
                })
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.location.store_seq);
            let segments = state
                .segments
                .values()
                .map(|segment| IndexManifestSegment {
                    id: segment.id,
                    byte_count: segment.byte_count,
                    record_count: segment.record_count,
                })
                .collect::<Vec<_>>();
            (
                entries,
                segments,
                state.records.len(),
                state.byte_count,
                state.last_record_sha256.clone(),
            )
        };
        let manifest = IndexManifest {
            schema: SEGMENT_INDEX_SCHEMA,
            record_count,
            byte_count,
            last_record_sha256: &last_hash,
            segments,
            entries: std::mem::take(&mut entries),
        };
        let encoded = serde_json::to_vec(&manifest)
            .map_err(|error| EventStoreError::InvalidRecord(error.to_string()))?;
        self.atomic_sidecar_write(
            SEGMENT_INDEX_FILE,
            SEGMENT_INDEX_TEMP_FILE,
            &encoded,
            "event index",
        )
    }

    fn atomic_sidecar_write(
        &self,
        final_name: &str,
        temp_name: &str,
        bytes: &[u8],
        label: &str,
    ) -> Result<()> {
        let final_path = self.root.join(final_name);
        let temp_path = self.root.join(temp_name);
        validate_optional_sidecar(&final_path, label)?;
        validate_optional_sidecar(&temp_path, &format!("{label} temporary file"))?;
        // Never open a newly-created temp path with `create + truncate` after
        // a path-only existence check.  An attacker can insert a hardlink in
        // that window and make the truncate destroy an unrelated file.  The
        // create-new branch closes that TOCTOU; the existing branch validates
        // metadata on the opened descriptor before truncating it.
        let mut temp = open_sidecar_temp(&temp_path, label)?;
        temp.write_all(bytes)
            .and_then(|_| temp.write_all(b"\n"))
            .and_then(|_| temp.flush())
            .and_then(|_| temp.sync_all())
            .map_err(|error| EventStoreError::Io(error.to_string()))?;
        drop(temp);
        std::fs::rename(&temp_path, &final_path)
            .map_err(|error| EventStoreError::Io(error.to_string()))?;
        sync_directory(&self.root)
    }

    fn read_state(&self) -> Result<RwLockReadGuard<'_, SegmentedState>> {
        self.state
            .read()
            .map_err(|_| EventStoreError::StatePoisoned)
    }

    fn write_state(&self) -> Result<RwLockWriteGuard<'_, SegmentedState>> {
        self.state
            .write()
            .map_err(|_| EventStoreError::StatePoisoned)
    }

    fn mark_poisoned(&self) {
        if let Ok(mut state) = self.state.write() {
            state.poisoned = true;
        }
    }
}

/// Reconcile a segmented destination against a stable v1 source snapshot.
///
/// `allow_destination_tail` is used only by rolling-upgrade callers: once the
/// v2 writer has taken authority, the retained v1 file may legitimately be a
/// shorter prefix.  A strict migration still rejects that state so callers
/// using [`SegmentedEventStore::migrate_legacy`] retain the historical
/// contract.  The source writer lease is held by the caller for the complete
/// duration of this function.
fn reconcile_legacy_prefix(
    store: &SegmentedEventStore,
    legacy_records: &[EventRecord],
    allow_destination_tail: bool,
) -> Result<()> {
    let existing = store.all_records()?;
    let prefix_matches = existing
        .iter()
        .zip(legacy_records.iter())
        .all(|(actual, expected)| actual == expected);

    if existing.len() > legacy_records.len() {
        if allow_destination_tail && prefix_matches {
            return Ok(());
        }
        return Err(EventStoreError::EventConflict);
    }
    if !prefix_matches {
        return Err(EventStoreError::EventConflict);
    }

    // A crash during migration leaves a valid prefix in the destination.
    // Resume from that prefix rather than silently replacing or re-appending
    // it; divergent bytes have already failed closed above.
    for record in legacy_records.iter().skip(existing.len()) {
        let result = store.append(EventInput {
            scope: record.scope.clone(),
            event_id: record.event_id.clone(),
            kind: record.kind.clone(),
            payload: record.payload.clone(),
        })?;
        if result.record != *record {
            return Err(EventStoreError::InvalidRecord(
                "legacy migration changed an event record".to_string(),
            ));
        }
    }
    store.flush()
}

/// Open the sidecar temporary file without a path-check/truncate race.
///
/// `create_new` is important here: `O_NOFOLLOW` blocks symlinks but does not
/// block hardlinks, and a plain `create(true).truncate(true)` can therefore
/// truncate an attacker-selected inode between two path metadata checks.
fn open_sidecar_temp(path: &Path, label: &str) -> Result<File> {
    let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW;
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(flags)
        .open(path)
    {
        Ok(file) => {
            // Set mode through the descriptor, never through the pathname.
            // This also closes a rename race after the initial path check.
            set_mode_on_descriptor(&file, 0o600, label)?;
            let (metadata, path_metadata) =
                validate_opened_path_identity(path, None, &file, label)?;
            validate_store_file_metadata(&metadata, &format!("{label} temporary file"))?;
            validate_store_file_metadata(&path_metadata, &format!("{label} temporary file"))?;
            Ok(file)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // The path existed (possibly because it was inserted after the
            // caller's path-only validation).  Open the inode, validate its
            // descriptor metadata, and only then truncate that same inode.
            let path_before = regular_path_metadata(path, label)?.ok_or_else(|| {
                EventStoreError::UnsafePath(format!(
                    "{label} temporary file disappeared after create race"
                ))
            })?;
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(flags)
                .open(path)
                .map_err(|error| EventStoreError::Io(error.to_string()))?;
            let (metadata, path_metadata) =
                validate_opened_path_identity(path, Some(&path_before), &file, label)?;
            validate_store_file_metadata(&metadata, &format!("{label} temporary file"))?;
            validate_store_file_metadata(&path_metadata, &format!("{label} temporary file"))?;
            file.set_len(0)
                .map_err(|error| EventStoreError::Io(error.to_string()))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|error| EventStoreError::Io(error.to_string()))?;
            Ok(file)
        }
        Err(error) => Err(EventStoreError::Io(error.to_string())),
    }
}

#[derive(Debug)]
struct SegmentSummary {
    byte_count: u64,
    record_count: usize,
}

#[derive(Debug)]
struct SegmentedRecovered {
    records: Vec<EventRecord>,
    by_key: HashMap<EventKey, usize>,
    by_scope: HashMap<TurnScope, Vec<usize>>,
    locations: HashMap<EventKey, SegmentLocation>,
    next_turn_seq: HashMap<TurnScope, u64>,
    segment_summaries: BTreeMap<u64, SegmentSummary>,
    byte_count: u64,
    last_record_sha256: String,
}

// A sidecar is derived state, but it is still untrusted input at startup.
// Bound the descriptor read before allocating so a forged file cannot turn
// recovery into an unbounded memory operation.  The bound is deliberately
// larger than the WAL limit because an index repeats scope/key metadata.
const MAX_SIDECAR_BYTES: u64 = 2 * 1024 * 1024 * 1024;

fn sidecar_byte_limit(config: &SegmentedEventStoreConfig) -> u64 {
    config
        .limits
        .max_store_bytes
        .saturating_mul(2)
        .saturating_add(16 * 1024 * 1024)
        .clamp(16 * 1024 * 1024, MAX_SIDECAR_BYTES)
}

fn validate_recovery_sidecars(
    root: &Path,
    recovered: &SegmentedRecovered,
    config: &SegmentedEventStoreConfig,
) -> Result<()> {
    let maximum = sidecar_byte_limit(config);
    if let Some(encoded) = read_sidecar(&root.join(SEGMENT_INDEX_FILE), "event index", maximum)? {
        let manifest: IndexManifestOwned =
            strict_json::decode(&encoded).map_err(|error| invalid_sidecar("event index", error))?;
        validate_index_manifest(&manifest, recovered, config)?;
    }
    if let Some(encoded) =
        read_sidecar(&root.join(SEGMENT_SNAPSHOT_FILE), "event snapshot", maximum)?
    {
        let manifest: SnapshotManifestOwned = strict_json::decode(&encoded)
            .map_err(|error| invalid_sidecar("event snapshot", error))?;
        validate_snapshot_manifest(&manifest, recovered, config)?;
    }
    Ok(())
}

fn read_sidecar(path: &Path, label: &str, maximum: u64) -> Result<Option<Vec<u8>>> {
    let path_before = regular_path_metadata(path, label)?;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if path_before.is_none() {
                return Ok(None);
            }
            return Err(EventStoreError::UnsafePath(format!(
                "{label} disappeared while being opened"
            )));
        }
        Err(error) => return Err(EventStoreError::Io(error.to_string())),
    };
    let (metadata, path_metadata) =
        validate_opened_path_identity(path, path_before.as_ref(), &file, label)?;
    validate_store_file_metadata(&metadata, label)?;
    validate_store_file_metadata(&path_metadata, label)?;
    let length = metadata.len();
    if length > maximum {
        return Err(invalid_sidecar(
            label,
            format!("sidecar exceeds the {maximum}-byte bound"),
        ));
    }
    let capacity = usize::try_from(length).map_err(|_| {
        invalid_sidecar(label, "sidecar length is not addressable on this platform")
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    let reader = file
        .try_clone()
        .map_err(|error| EventStoreError::Io(error.to_string()))?;
    let read = reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| EventStoreError::Io(error.to_string()))?;
    if u64::try_from(read).unwrap_or(u64::MAX) > maximum
        || u64::try_from(read).unwrap_or(0) != length
    {
        return Err(invalid_sidecar(
            label,
            "sidecar changed or exceeded its bound while being read",
        ));
    }
    let (final_metadata, final_path_metadata) =
        validate_opened_path_identity(path, path_before.as_ref(), &file, label)?;
    validate_store_file_metadata(&final_metadata, label)?;
    validate_store_file_metadata(&final_path_metadata, label)?;
    let final_length = final_metadata.len();
    if final_length != length {
        return Err(invalid_sidecar(label, "sidecar changed while being read"));
    }
    debug_assert_eq!(read, bytes.len());
    Ok(Some(bytes))
}

fn validate_index_manifest(
    manifest: &IndexManifestOwned,
    recovered: &SegmentedRecovered,
    config: &SegmentedEventStoreConfig,
) -> Result<()> {
    if manifest.schema != SEGMENT_INDEX_SCHEMA {
        return Err(invalid_sidecar("event index", "schema does not match"));
    }
    if manifest.record_count > recovered.records.len() {
        return Err(invalid_sidecar(
            "event index",
            "record count is ahead of the recovered WAL",
        ));
    }
    if manifest.entries.len() != manifest.record_count {
        return Err(invalid_sidecar(
            "event index",
            "entry count does not match record count",
        ));
    }
    require_sha256(
        &manifest.last_record_sha256,
        "event index last_record_sha256",
    )?;
    let (expected_bytes, expected_hash) =
        recovered_prefix_metadata(recovered, manifest.record_count)?;
    if manifest.byte_count != expected_bytes || manifest.last_record_sha256 != expected_hash {
        return Err(invalid_sidecar(
            "event index",
            "high-water metadata does not match the recovered WAL prefix",
        ));
    }

    if manifest.segments.is_empty() {
        return Err(invalid_sidecar(
            "event index",
            "segment summary list must contain segment one",
        ));
    }
    if manifest.segments.len() > recovered.segment_summaries.len() {
        return Err(invalid_sidecar(
            "event index",
            "segment summary list is ahead of the recovered WAL",
        ));
    }

    let mut listed = BTreeMap::<u64, (usize, u64)>::new();
    for (position, segment) in manifest.segments.iter().enumerate() {
        let expected_id = u64::try_from(position + 1)
            .map_err(|_| invalid_sidecar("event index", "segment ID overflow"))?;
        if segment.id != expected_id {
            return Err(invalid_sidecar(
                "event index",
                "segment IDs are not contiguous",
            ));
        }
        let actual = recovered
            .segment_summaries
            .get(&segment.id)
            .ok_or_else(|| invalid_sidecar("event index", "segment is absent from the WAL"))?;
        if segment.record_count > actual.record_count || segment.byte_count > actual.byte_count {
            return Err(invalid_sidecar(
                "event index",
                "segment summary is ahead of the recovered WAL",
            ));
        }
        listed.insert(segment.id, (segment.record_count, segment.byte_count));
    }

    // Entries are emitted in store-sequence order.  Requiring that order and
    // checking every location against the recovered map prevents a forged
    // sidecar from redirecting a lookup to an arbitrary byte range.
    let mut per_segment = BTreeMap::<u64, (usize, u64)>::new();
    for (position, entry) in manifest.entries.iter().enumerate() {
        validate_scope(&entry.scope, &config.limits)?;
        validate_id(
            "event index event_id",
            &entry.event_id,
            config.limits.max_id_bytes,
        )?;
        let expected_seq = u64::try_from(position)
            .map_err(|_| invalid_sidecar("event index", "store sequence overflow"))?;
        if entry.location.store_seq != expected_seq {
            return Err(invalid_sidecar(
                "event index",
                "entries are not a contiguous store-sequence prefix",
            ));
        }
        let key = EventKey::new(entry.scope.clone(), entry.event_id.clone());
        let expected_location = recovered
            .locations
            .get(&key)
            .ok_or_else(|| invalid_sidecar("event index", "entry key is absent from the WAL"))?;
        if expected_location != &entry.location {
            return Err(invalid_sidecar(
                "event index",
                "entry location does not match the WAL",
            ));
        }
        let record = recovered
            .records
            .get(position)
            .ok_or_else(|| invalid_sidecar("event index", "entry points beyond the WAL"))?;
        if record.scope != entry.scope || record.event_id != entry.event_id {
            return Err(invalid_sidecar(
                "event index",
                "entry identity does not match the WAL sequence",
            ));
        }
        listed
            .get(&entry.location.segment_id)
            .ok_or_else(|| invalid_sidecar("event index", "entry segment is not listed"))?;
        let actual = recovered
            .segment_summaries
            .get(&entry.location.segment_id)
            .ok_or_else(|| invalid_sidecar("event index", "entry segment is absent"))?;
        if entry.location.byte_len == 0
            || entry
                .location
                .offset
                .checked_add(entry.location.byte_len)
                .is_none_or(|end| end > actual.byte_count)
        {
            return Err(invalid_sidecar(
                "event index",
                "entry byte range is outside its segment",
            ));
        }
        let aggregate = per_segment
            .entry(entry.location.segment_id)
            .or_insert((0, 0));
        aggregate.0 = aggregate.0.saturating_add(1);
        aggregate.1 = aggregate.1.saturating_add(entry.location.byte_len);
    }
    for segment in &manifest.segments {
        let aggregate = per_segment.get(&segment.id).copied().unwrap_or((0, 0));
        if aggregate != (segment.record_count, segment.byte_count) {
            return Err(invalid_sidecar(
                "event index",
                "segment summary does not match its entries",
            ));
        }
    }
    Ok(())
}

fn validate_snapshot_manifest(
    manifest: &SnapshotManifestOwned,
    recovered: &SegmentedRecovered,
    config: &SegmentedEventStoreConfig,
) -> Result<()> {
    if manifest.schema != SEGMENT_SNAPSHOT_SCHEMA {
        return Err(invalid_sidecar("event snapshot", "schema does not match"));
    }
    if manifest.records.len() != manifest.record_count {
        return Err(invalid_sidecar(
            "event snapshot",
            "record count does not match the record array",
        ));
    }
    if manifest.record_count > recovered.records.len() {
        return Err(invalid_sidecar(
            "event snapshot",
            "record count is ahead of the recovered WAL",
        ));
    }
    require_sha256(
        &manifest.last_record_sha256,
        "event snapshot last_record_sha256",
    )?;
    let (expected_bytes, expected_hash) =
        recovered_prefix_metadata(recovered, manifest.record_count)?;
    if manifest.byte_count != expected_bytes || manifest.last_record_sha256 != expected_hash {
        return Err(invalid_sidecar(
            "event snapshot",
            "high-water metadata does not match the recovered WAL prefix",
        ));
    }
    for (position, record) in manifest.records.iter().enumerate() {
        // Equality to a recovered record also authenticates all of the record
        // fields and the hash chain; validating explicitly gives a useful
        // bounded failure if a future recovery implementation changes shape.
        validate_record(record, &config.limits)?;
        if recovered.records.get(position) != Some(record) {
            return Err(invalid_sidecar(
                "event snapshot",
                "record array diverges from the WAL prefix",
            ));
        }
    }
    Ok(())
}

fn recovered_prefix_metadata(
    recovered: &SegmentedRecovered,
    count: usize,
) -> Result<(u64, String)> {
    if count > recovered.records.len() {
        return Err(EventStoreError::StatePoisoned);
    }
    let mut byte_count = 0_u64;
    for record in recovered.records.iter().take(count) {
        let key = EventKey::new(record.scope.clone(), record.event_id.clone());
        let location = recovered
            .locations
            .get(&key)
            .ok_or(EventStoreError::StatePoisoned)?;
        if location.store_seq != record.store_seq {
            return Err(EventStoreError::StatePoisoned);
        }
        byte_count = byte_count
            .checked_add(location.byte_len)
            .ok_or(EventStoreError::CapacityExhausted)?;
    }
    let last_hash = count
        .checked_sub(1)
        .and_then(|index| recovered.records.get(index))
        .map_or_else(
            || ZERO_SHA256.to_string(),
            |record| record.record_sha256.clone(),
        );
    Ok((byte_count, last_hash))
}

fn invalid_sidecar(label: &str, message: impl Into<String>) -> EventStoreError {
    EventStoreError::InvalidRecord(format!("{label} is invalid: {}", message.into()))
}

fn prepare_segment_root(root: &Path) -> Result<PathBuf> {
    validate_store_path(root)?;
    let parent = root
        .parent()
        .ok_or_else(|| EventStoreError::UnsafePath("segment root has no parent".to_string()))?;
    let parent_before = validate_store_parent(parent)?;
    match std::fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(EventStoreError::UnsafePath(
                    "segment root must be a regular non-symlink directory".to_string(),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(root) {
                Ok(()) => {
                    // Apply the mode through a descriptor.  A pathname-based
                    // chmod could follow a same-UID rename/recreate and
                    // change an unrelated directory.
                    let created_metadata = std::fs::symlink_metadata(root).map_err(|error| {
                        EventStoreError::Io(format!("unable to inspect new segment root: {error}"))
                    })?;
                    let directory = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
                        .open(root)
                        .map_err(|error| EventStoreError::Io(error.to_string()))?;
                    let (descriptor_metadata, path_metadata) = validate_opened_path_identity(
                        root,
                        Some(&created_metadata),
                        &directory,
                        "segment root",
                    )?;
                    if !descriptor_metadata.is_dir() || !path_metadata.is_dir() {
                        return Err(EventStoreError::UnsafePath(
                            "new segment root is not a directory".to_string(),
                        ));
                    }
                    set_mode_on_descriptor(&directory, 0o700, "segment root")?;
                    sync_directory(parent)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(EventStoreError::Io(error.to_string())),
            }
        }
        Err(error) => return Err(EventStoreError::Io(error.to_string())),
    }
    validate_service_directory(root)?;
    let parent_after = validate_store_parent(parent)?;
    if parent_before != parent_after {
        return Err(EventStoreError::UnsafePath(
            "segment root parent changed while it was opened".to_string(),
        ));
    }
    Ok(root.to_path_buf())
}

fn validate_service_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| EventStoreError::UnsafePath(error.to_string()))?;
    let effective_uid = unsafe { libc::geteuid() };
    let mode = metadata.mode() & 0o7777;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.nlink() == 0
        || metadata.uid() != effective_uid
        || mode & 0o022 != 0
    {
        return Err(EventStoreError::UnsafePath(format!(
            "segment root must be service-owned and not group/world writable (uid {}, mode {:04o})",
            metadata.uid(),
            mode
        )));
    }
    Ok(())
}

fn validate_store_file_metadata(metadata: &std::fs::Metadata, label: &str) -> Result<()> {
    let effective_uid = unsafe { libc::geteuid() };
    let mode = metadata.mode() & 0o7777;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || mode != 0o600
    {
        return Err(EventStoreError::UnsafePath(format!(
            "{label} must be service-owned regular 0600 with one link (uid {}, mode {:04o}, nlink {})",
            metadata.uid(),
            mode,
            metadata.nlink()
        )));
    }
    Ok(())
}

fn open_writer_lock(path: &Path) -> Result<File> {
    let path_before = regular_path_metadata(path, "segment writer lock")?;
    let (file, existed, identity_before) = match path_before {
        Some(metadata) => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .map_err(|error| EventStoreError::Io(error.to_string()))?;
            (file, true, Some(metadata))
        }
        None => {
            let created = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path);
            match created {
                Ok(file) => (file, false, None),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let raced =
                        regular_path_metadata(path, "segment writer lock")?.ok_or_else(|| {
                            EventStoreError::UnsafePath(
                                "segment writer lock disappeared after create race".to_string(),
                            )
                        })?;
                    let file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .mode(0o600)
                        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                        .open(path)
                        .map_err(|error| EventStoreError::Io(error.to_string()))?;
                    (file, true, Some(raced))
                }
                Err(error) => return Err(EventStoreError::Io(error.to_string())),
            }
        }
    };
    if !existed {
        set_mode_on_descriptor(&file, 0o600, "segment writer lock")?;
    }
    let (descriptor_metadata, path_metadata) = validate_opened_path_identity(
        path,
        identity_before.as_ref(),
        &file,
        "segment writer lock",
    )?;
    validate_store_file_metadata(&descriptor_metadata, "segment writer lock")?;
    validate_store_file_metadata(&path_metadata, "segment writer lock")?;
    lock_writer(&file)?;
    // Re-check after taking the lease: a pathname replacement while the
    // non-blocking flock was being acquired must not leave us believing that
    // the lease protects the current pathname.
    let (descriptor_metadata, path_metadata) = validate_opened_path_identity(
        path,
        identity_before.as_ref(),
        &file,
        "segment writer lock",
    )?;
    validate_store_file_metadata(&descriptor_metadata, "segment writer lock")?;
    validate_store_file_metadata(&path_metadata, "segment writer lock")?;
    if !existed {
        sync_directory(
            path.parent()
                .ok_or_else(|| EventStoreError::UnsafePath("lock has no parent".to_string()))?,
        )?;
    }
    Ok(file)
}

fn validate_optional_sidecar(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(EventStoreError::UnsafePath(format!(
                    "{label} must not be a symlink"
                )));
            }
            validate_store_file_metadata(&metadata, label)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(EventStoreError::Io(error.to_string())),
    }
}

fn segment_file_name(id: u64) -> String {
    format!("{SEGMENT_FILE_PREFIX}{id:020}{SEGMENT_FILE_SUFFIX}")
}

fn parse_segment_file_name(name: &str) -> Option<u64> {
    let body = name
        .strip_prefix(SEGMENT_FILE_PREFIX)?
        .strip_suffix(SEGMENT_FILE_SUFFIX)?;
    if body.is_empty() || !body.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    body.parse().ok().filter(|id| *id > 0)
}

fn discover_segments(root: &Path) -> Result<Vec<OpenSegment>> {
    let mut paths = Vec::<(u64, PathBuf, std::fs::Metadata)>::new();
    for entry in std::fs::read_dir(root).map_err(|error| EventStoreError::Io(error.to_string()))? {
        let entry = entry.map_err(|error| EventStoreError::Io(error.to_string()))?;
        let path = entry.path();
        let name = entry.file_name().into_string().map_err(|_| {
            EventStoreError::UnsafePath("segment filename is not UTF-8".to_string())
        })?;
        if let Some(id) = parse_segment_file_name(&name) {
            if paths.len() >= MAX_EVENT_SEGMENTS {
                return Err(EventStoreError::CapacityExhausted);
            }
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| EventStoreError::Io(error.to_string()))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(EventStoreError::UnsafePath(
                    "segment entry must be a regular non-symlink file".to_string(),
                ));
            }
            paths.push((id, path, metadata));
        } else if name.starts_with(SEGMENT_FILE_PREFIX) {
            return Err(EventStoreError::InvalidRecord(format!(
                "malformed segment filename: {name}"
            )));
        }
    }
    paths.sort_by_key(|(id, _, _)| *id);
    for (expected, (id, _, _)) in paths.iter().enumerate() {
        let expected =
            u64::try_from(expected + 1).map_err(|_| EventStoreError::CapacityExhausted)?;
        if *id != expected {
            return Err(EventStoreError::InvalidRecord(
                "segment IDs are not contiguous".to_string(),
            ));
        }
    }
    let mut segments = Vec::with_capacity(paths.len());
    for (id, path, path_metadata) in paths {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| EventStoreError::Io(error.to_string()))?;
        let (descriptor_metadata, current_path_metadata) =
            validate_opened_path_identity(&path, Some(&path_metadata), &file, "segment")?;
        validate_store_file_metadata(&descriptor_metadata, "segment")?;
        validate_store_file_metadata(&current_path_metadata, "segment")?;
        segments.push(OpenSegment {
            id,
            path,
            file: Arc::new(Mutex::new(file)),
        });
    }
    Ok(segments)
}

/// Remove crash-orphaned zero-byte segment files at the end of a WAL.
///
/// `ensure_active_segment` creates a new pathname before the append reaches
/// the filesystem.  If the process is interrupted after creation, that file
/// is a harmless, uncommitted segment.  The writer lease held by `open()`
/// excludes another store instance while we validate and unlink it.  We
/// re-check the descriptor and pathname metadata immediately before removal so
/// a replacement inode cannot be mistaken for the descriptor discovered at
/// startup.  Empty segments before a non-empty segment are deliberately not
/// removed: preserving their IDs and rejecting that impossible layout keeps
/// corruption fail-closed rather than silently rewriting locations.
fn prune_empty_segment_tail(root: &Path, segments: &mut Vec<OpenSegment>) -> Result<()> {
    while segments.len() > 1 {
        let Some(segment) = segments.last() else {
            break;
        };
        let descriptor_metadata = {
            let file = lock_file(&segment.file)?;
            file.metadata()
                .map_err(|error| EventStoreError::Io(error.to_string()))?
        };
        if descriptor_metadata.len() != 0 {
            break;
        }
        validate_store_file_metadata(&descriptor_metadata, "segment")?;

        let path_metadata = std::fs::symlink_metadata(&segment.path)
            .map_err(|error| EventStoreError::Io(error.to_string()))?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.dev() != descriptor_metadata.dev()
            || path_metadata.ino() != descriptor_metadata.ino()
        {
            return Err(EventStoreError::UnsafePath(
                "segment pathname changed while pruning an empty tail".to_string(),
            ));
        }
        validate_store_file_metadata(&path_metadata, "segment")?;

        let path = segment.path.clone();
        std::fs::remove_file(&path).map_err(|error| EventStoreError::Io(error.to_string()))?;
        segments.pop();
        sync_directory(root)?;
    }
    Ok(())
}

fn create_segment(root: &Path, id: u64) -> Result<OpenSegment> {
    let path = root.join(segment_file_name(id));
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| EventStoreError::Io(error.to_string()))?;
    set_mode_on_descriptor(&file, 0o600, "segment")?;
    let (descriptor_metadata, path_metadata) =
        validate_opened_path_identity(&path, None, &file, "segment")?;
    validate_store_file_metadata(&descriptor_metadata, "segment")?;
    validate_store_file_metadata(&path_metadata, "segment")?;
    sync_directory(root)?;
    Ok(OpenSegment {
        id,
        path,
        file: Arc::new(Mutex::new(file)),
    })
}

fn lock_file(file: &Arc<Mutex<File>>) -> Result<std::sync::MutexGuard<'_, File>> {
    file.lock().map_err(|_| EventStoreError::StatePoisoned)
}

trait SyncFile {
    fn sync_for(&self, policy: SyncPolicy) -> Result<()>;
}

impl SyncFile for File {
    fn sync_for(&self, policy: SyncPolicy) -> Result<()> {
        match policy {
            SyncPolicy::None => Ok(()),
            SyncPolicy::Data => self
                .sync_data()
                .map_err(|error| EventStoreError::Io(error.to_string())),
            SyncPolicy::Full => self
                .sync_all()
                .map_err(|error| EventStoreError::Io(error.to_string())),
        }
    }
}

fn append_segment_bytes(file: &Arc<Mutex<File>>, expected_offset: u64, bytes: &[u8]) -> Result<()> {
    let mut file = lock_file(file)?;
    let actual_offset = file
        .metadata()
        .map_err(|error| EventStoreError::Io(error.to_string()))?
        .len();
    if actual_offset != expected_offset {
        return Err(EventStoreError::Poisoned);
    }
    file.write_all(bytes)
        .and_then(|_| file.flush())
        .map_err(|error| EventStoreError::Io(error.to_string()))
}

fn recover_segmented_segments(
    segments: &[OpenSegment],
    config: &SegmentedEventStoreConfig,
) -> Result<SegmentedRecovered> {
    let mut records = Vec::new();
    let mut by_key = HashMap::new();
    let mut by_scope = HashMap::<TurnScope, Vec<usize>>::new();
    let mut locations = HashMap::new();
    let mut next_turn_seq = HashMap::<TurnScope, u64>::new();
    let mut segment_summaries = BTreeMap::new();
    let mut byte_count = 0_u64;
    let mut previous = ZERO_SHA256.to_string();

    for (segment_index, segment) in segments.iter().enumerate() {
        let is_last = segment_index + 1 == segments.len();
        let file = lock_file(&segment.file)?;
        let mut reader = BufReader::new(
            file.try_clone()
                .map_err(|error| EventStoreError::Io(error.to_string()))?,
        );
        let mut offset = 0_u64;
        let mut segment_records = 0_usize;
        while let Some((line, consumed, terminated)) =
            read_segment_line(&mut reader, config.limits.max_record_bytes)?
        {
            if !terminated {
                if !(is_last && config.recovery == RecoveryPolicy::RepairTrailingPartial) {
                    return Err(EventStoreError::TruncatedRecord);
                }
                // A non-terminated suffix is the only repairable condition.
                // Complete records are always newline-delimited in v2, so the
                // suffix is conservatively discarded rather than guessed.
                file.set_len(offset)
                    .map_err(|error| EventStoreError::Io(error.to_string()))?;
                // The truncation itself is part of recovery state.  Persist
                // it before returning so a subsequent power loss cannot
                // resurrect the discarded suffix and make the next restart
                // disagree with this repair decision.
                file.sync_data()
                    .map_err(|error| EventStoreError::Io(error.to_string()))?;
                break;
            }
            let consumed_u64 =
                u64::try_from(consumed).map_err(|_| EventStoreError::CapacityExhausted)?;
            byte_count = byte_count
                .checked_add(consumed_u64)
                .filter(|value| *value <= config.limits.max_store_bytes)
                .ok_or(EventStoreError::CapacityExhausted)?;
            if records.len() >= config.limits.max_records
                || segment_records >= config.max_segment_records
            {
                return Err(EventStoreError::CapacityExhausted);
            }
            let record: EventRecord =
                strict_json::decode(&line).map_err(EventStoreError::InvalidRecord)?;
            validate_record(&record, &config.limits)?;
            let expected_store_seq =
                u64::try_from(records.len()).map_err(|_| EventStoreError::CapacityExhausted)?;
            if record.store_seq != expected_store_seq {
                return Err(EventStoreError::InvalidRecord(
                    "store sequence is not contiguous across segments".to_string(),
                ));
            }
            let expected_turn_seq = next_turn_seq.get(&record.scope).copied().unwrap_or(0);
            if record.turn_seq != expected_turn_seq {
                return Err(EventStoreError::InvalidRecord(
                    "turn sequence is not contiguous".to_string(),
                ));
            }
            if record.previous_record_sha256 != previous {
                return Err(EventStoreError::InvalidRecord(
                    "previous record digest does not match the chain".to_string(),
                ));
            }
            let key = EventKey::new(record.scope.clone(), record.event_id.clone());
            if by_key.contains_key(&key) {
                return Err(EventStoreError::InvalidRecord(
                    "event identity is duplicated on disk".to_string(),
                ));
            }
            let index = records.len();
            by_key.insert(key.clone(), index);
            by_scope
                .entry(record.scope.clone())
                .or_default()
                .push(index);
            locations.insert(
                key,
                SegmentLocation {
                    segment_id: segment.id,
                    offset,
                    byte_len: consumed_u64,
                    store_seq: record.store_seq,
                },
            );
            next_turn_seq.insert(record.scope.clone(), expected_turn_seq.saturating_add(1));
            previous = record.record_sha256.clone();
            records.push(record);
            segment_records = segment_records.saturating_add(1);
            offset = offset
                .checked_add(consumed_u64)
                .ok_or(EventStoreError::CapacityExhausted)?;
        }
        let actual_len = file
            .metadata()
            .map_err(|error| EventStoreError::Io(error.to_string()))?
            .len();
        if actual_len != offset {
            return Err(EventStoreError::InvalidRecord(
                "segment length changed during recovery".to_string(),
            ));
        }
        if !is_last && segment_records == 0 {
            return Err(EventStoreError::InvalidRecord(
                "non-active segment is empty".to_string(),
            ));
        }
        segment_summaries.insert(
            segment.id,
            SegmentSummary {
                byte_count: offset,
                record_count: segment_records,
            },
        );
    }
    Ok(SegmentedRecovered {
        records,
        by_key,
        by_scope,
        locations,
        next_turn_seq,
        segment_summaries,
        byte_count,
        last_record_sha256: previous,
    })
}

fn read_segment_line(
    reader: &mut impl BufRead,
    maximum: usize,
) -> Result<Option<(Vec<u8>, usize, bool)>> {
    let mut line = Vec::new();
    let read_ahead = read_ahead_limit(maximum)?;
    let read = std::io::Read::take(reader, read_ahead)
        .read_until(b'\n', &mut line)
        .map_err(|error| EventStoreError::Io(error.to_string()))?;
    if read == 0 {
        return Ok(None);
    }
    let terminated = line.last() == Some(&b'\n');
    if !terminated && line.len() > maximum {
        return Err(EventStoreError::InvalidRecord(
            "event record is oversized".to_string(),
        ));
    }
    if terminated {
        line.pop();
        if line.is_empty() || line.len() > maximum {
            return Err(EventStoreError::InvalidRecord(
                "event record is empty or oversized".to_string(),
            ));
        }
    }
    Ok(Some((line, read, terminated)))
}

#[derive(Debug)]
struct Recovered {
    records: Vec<EventRecord>,
    by_key: HashMap<EventKey, usize>,
    next_turn_seq: HashMap<TurnScope, u64>,
    byte_count: u64,
    last_record_sha256: String,
}

fn recover_records(file: &File, limits: &EventStoreLimits) -> Result<Recovered> {
    let mut reader = BufReader::new(
        file.try_clone()
            .map_err(|error| EventStoreError::Io(error.to_string()))?,
    );
    let mut records = Vec::new();
    let mut by_key = HashMap::new();
    let mut next_turn_seq = HashMap::<TurnScope, u64>::new();
    let mut byte_count = 0_u64;
    let mut previous = ZERO_SHA256.to_string();
    while let Some((encoded, consumed)) = read_record_line(&mut reader, limits.max_record_bytes)? {
        byte_count = byte_count
            .checked_add(consumed)
            .filter(|value| *value <= limits.max_store_bytes)
            .ok_or(EventStoreError::CapacityExhausted)?;
        if records.len() >= limits.max_records {
            return Err(EventStoreError::CapacityExhausted);
        }
        let record: EventRecord =
            strict_json::decode(&encoded).map_err(EventStoreError::InvalidRecord)?;
        validate_record(&record, limits)?;
        let expected_store_seq =
            u64::try_from(records.len()).map_err(|_| EventStoreError::CapacityExhausted)?;
        if record.store_seq != expected_store_seq {
            return Err(EventStoreError::InvalidRecord(
                "store sequence is not contiguous".to_string(),
            ));
        }
        let expected_turn_seq = next_turn_seq.get(&record.scope).copied().unwrap_or(0);
        if record.turn_seq != expected_turn_seq {
            return Err(EventStoreError::InvalidRecord(
                "turn sequence is not contiguous".to_string(),
            ));
        }
        if record.previous_record_sha256 != previous {
            return Err(EventStoreError::InvalidRecord(
                "previous record digest does not match the chain".to_string(),
            ));
        }
        let key = EventKey::new(record.scope.clone(), record.event_id.clone());
        if by_key.contains_key(&key) {
            return Err(EventStoreError::InvalidRecord(
                "event identity is duplicated on disk".to_string(),
            ));
        }
        let index = records.len();
        by_key.insert(key, index);
        next_turn_seq.insert(record.scope.clone(), expected_turn_seq.saturating_add(1));
        previous = record.record_sha256.clone();
        records.push(record);
    }
    Ok(Recovered {
        records,
        by_key,
        next_turn_seq,
        byte_count,
        last_record_sha256: previous,
    })
}

fn read_record_line(reader: &mut impl BufRead, maximum: usize) -> Result<Option<(Vec<u8>, u64)>> {
    let mut line = Vec::new();
    let read_ahead = read_ahead_limit(maximum)?;
    let mut limited = std::io::Read::take(reader, read_ahead);
    let read = limited
        .read_until(b'\n', &mut line)
        .map_err(|error| EventStoreError::Io(error.to_string()))?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        return Err(EventStoreError::TruncatedRecord);
    }
    let consumed = u64::try_from(line.len()).map_err(|_| EventStoreError::CapacityExhausted)?;
    line.pop();
    if line.is_empty() || line.len() > maximum {
        return Err(EventStoreError::InvalidRecord(
            "event record is empty or oversized".to_string(),
        ));
    }
    Ok(Some((line, consumed)))
}

/// Compute the bounded read-ahead allowance used to distinguish an oversized
/// line from a valid newline-terminated record. Keep the check here as well as
/// in configuration validation so a future recovery caller cannot reintroduce
/// an overflowing `maximum + 2` conversion.
fn read_ahead_limit(maximum: usize) -> Result<u64> {
    if maximum == 0 || maximum > MAX_EVENT_RECORD_BYTES {
        return Err(EventStoreError::CapacityExhausted);
    }
    u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(2))
        .ok_or(EventStoreError::CapacityExhausted)
}

fn append_record_bytes(file: &mut File, bytes: &[u8], policy: SyncPolicy) -> Result<()> {
    file.write_all(bytes)
        .and_then(|_| file.flush())
        .map_err(|error| EventStoreError::Io(error.to_string()))?;
    match policy {
        SyncPolicy::None => Ok(()),
        SyncPolicy::Data => file
            .sync_data()
            .map_err(|error| EventStoreError::Io(error.to_string())),
        SyncPolicy::Full => file
            .sync_all()
            .map_err(|error| EventStoreError::Io(error.to_string())),
    }
}

fn validate_event_input(input: &EventInput, limits: &EventStoreLimits) -> Result<()> {
    validate_scope(&input.scope, limits)?;
    validate_id("event_id", &input.event_id, limits.max_id_bytes)?;
    validate_text("kind", &input.kind, limits.max_kind_bytes)?;
    if !input.payload.is_object() {
        return Err(EventStoreError::InvalidRecord(
            "event payload must be a JSON object".to_string(),
        ));
    }
    Ok(())
}

fn validate_record(record: &EventRecord, limits: &EventStoreLimits) -> Result<()> {
    if record.schema != EVENT_RECORD_SCHEMA {
        return Err(EventStoreError::InvalidRecord(
            "event record schema does not match".to_string(),
        ));
    }
    validate_scope(&record.scope, limits)?;
    validate_id("event_id", &record.event_id, limits.max_id_bytes)?;
    validate_text("kind", &record.kind, limits.max_kind_bytes)?;
    if !record.payload.is_object() {
        return Err(EventStoreError::InvalidRecord(
            "event payload must be a JSON object".to_string(),
        ));
    }
    require_sha256(&record.payload_sha256, "payload_sha256")?;
    require_sha256(&record.previous_record_sha256, "previous_record_sha256")?;
    require_sha256(&record.record_sha256, "record_sha256")?;
    let payload_bytes = serde_json::to_vec(&record.payload)
        .map_err(|error| EventStoreError::InvalidRecord(error.to_string()))?;
    if sha256_hex(&payload_bytes) != record.payload_sha256 {
        return Err(EventStoreError::InvalidRecord(
            "payload digest does not match".to_string(),
        ));
    }
    let expected = record_digest(&RecordPreimage {
        schema: EVENT_RECORD_SCHEMA,
        store_seq: record.store_seq,
        turn_seq: record.turn_seq,
        scope: &record.scope,
        event_id: &record.event_id,
        kind: &record.kind,
        payload: &record.payload,
        payload_sha256: &record.payload_sha256,
        previous_record_sha256: &record.previous_record_sha256,
    })?;
    if expected != record.record_sha256 {
        return Err(EventStoreError::InvalidRecord(
            "record digest does not match".to_string(),
        ));
    }
    Ok(())
}

fn validate_scope(scope: &TurnScope, limits: &EventStoreLimits) -> Result<()> {
    for (label, value) in [
        ("session_id", scope.session_id.as_str()),
        ("profile_id", scope.profile_id.as_str()),
        ("task_id", scope.task_id.as_str()),
        ("turn_id", scope.turn_id.as_str()),
        ("turn_stream_id", scope.turn_stream_id.as_str()),
    ] {
        validate_id(label, value, limits.max_id_bytes)?;
    }
    Ok(())
}

fn validate_id(label: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(EventStoreError::InvalidRecord(format!(
            "{label} is empty, oversized or malformed"
        )));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(EventStoreError::InvalidRecord(format!(
            "{label} is empty, oversized or malformed"
        )));
    }
    Ok(())
}

#[derive(Serialize)]
struct RecordPreimage<'a> {
    schema: &'static str,
    store_seq: u64,
    turn_seq: u64,
    scope: &'a TurnScope,
    event_id: &'a str,
    kind: &'a str,
    payload: &'a Value,
    payload_sha256: &'a str,
    previous_record_sha256: &'a str,
}

fn record_digest(preimage: &RecordPreimage<'_>) -> Result<String> {
    let encoded = serde_json::to_vec(preimage)
        .map_err(|error| EventStoreError::InvalidRecord(error.to_string()))?;
    Ok(sha256_hex(&encoded))
}

fn sha256_hex(value: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(value);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(EventStoreError::InvalidRecord(format!(
            "{label} must be a lowercase SHA-256"
        )));
    }
    Ok(())
}

fn validate_store_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(EventStoreError::UnsafePath(
            "store path must be absolute".to_string(),
        ));
    }
    let mut normal = 0usize;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) if !value.is_empty() => normal = normal.saturating_add(1),
            _ => {
                return Err(EventStoreError::UnsafePath(
                    "store path contains a non-normal component".to_string(),
                ));
            }
        }
    }
    if normal < 2 {
        return Err(EventStoreError::UnsafePath(
            "store path requires a dedicated parent directory".to_string(),
        ));
    }
    Ok(())
}

fn validate_store_parent(parent: &Path) -> Result<(u64, u64)> {
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| EventStoreError::UnsafePath(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.nlink() == 0 {
        return Err(EventStoreError::UnsafePath(
            "store parent must be a stable real directory".to_string(),
        ));
    }
    let effective_uid = unsafe { libc::geteuid() };
    let mode = metadata.mode() & 0o7777;
    if metadata.uid() != effective_uid || mode & 0o022 != 0 {
        return Err(EventStoreError::UnsafePath(format!(
            "store parent must be service-owned and not group/world writable (uid {}, mode {:04o})",
            metadata.uid(),
            mode
        )));
    }
    Ok((metadata.dev(), metadata.ino()))
}

/// Return whether two metadata snapshots identify the same inode.
///
/// `O_NOFOLLOW` prevents opening a symlink, but it does not make a pathname
/// stable across a rename/recreate.  Comparing both device and inode numbers
/// closes that remaining path-to-descriptor substitution window.
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

/// Verify that an opened descriptor still denotes the pathname that was
/// checked before opening it.  `before` is `None` for a file created with
/// `O_EXCL`; in that case the post-open pathname check still detects a
/// replacement before the caller starts using the descriptor.
fn validate_opened_path_identity(
    path: &Path,
    before: Option<&std::fs::Metadata>,
    file: &File,
    label: &str,
) -> Result<(std::fs::Metadata, std::fs::Metadata)> {
    let descriptor = file
        .metadata()
        .map_err(|error| EventStoreError::Io(error.to_string()))?;
    if let Some(before) = before
        && !same_file_identity(before, &descriptor)
    {
        return Err(EventStoreError::UnsafePath(format!(
            "{label} inode changed between pathname validation and open"
        )));
    }
    let current = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            EventStoreError::UnsafePath(format!("{label} pathname disappeared while opening"))
        } else {
            EventStoreError::Io(error.to_string())
        }
    })?;
    if current.file_type().is_symlink() {
        return Err(EventStoreError::UnsafePath(format!(
            "{label} pathname must not be a symlink"
        )));
    }
    if !same_file_identity(&current, &descriptor) {
        return Err(EventStoreError::UnsafePath(format!(
            "{label} pathname does not identify the opened inode"
        )));
    }
    Ok((descriptor, current))
}

fn regular_path_metadata(path: &Path, label: &str) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(EventStoreError::UnsafePath(format!(
                    "{label} is not a regular non-symlink file"
                )));
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(EventStoreError::Io(error.to_string())),
    }
}

fn set_mode_on_descriptor(file: &File, mode: u32, label: &str) -> Result<()> {
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|error| EventStoreError::Io(format!("unable to set {label} mode: {error}")))
}

fn lock_writer(file: &File) -> Result<()> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error
        .raw_os_error()
        .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
    {
        Err(EventStoreError::WriterBusy)
    } else {
        Err(EventStoreError::Io(error.to_string()))
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| EventStoreError::Io(error.to_string()))
}

fn invalid_config(message: impl Into<String>) -> EventStoreError {
    EventStoreError::InvalidConfiguration(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn event_store_limits_reject_unbounded_resource_values() {
        let oversized = vec![
            EventStoreLimits {
                max_store_bytes: u64::MAX,
                ..EventStoreLimits::default()
            },
            EventStoreLimits {
                max_record_bytes: usize::MAX,
                ..EventStoreLimits::default()
            },
            EventStoreLimits {
                max_records: usize::MAX,
                ..EventStoreLimits::default()
            },
            EventStoreLimits {
                max_id_bytes: usize::MAX,
                ..EventStoreLimits::default()
            },
            EventStoreLimits {
                max_kind_bytes: usize::MAX,
                ..EventStoreLimits::default()
            },
        ];

        for limits in oversized {
            assert!(
                limits.validate().is_err(),
                "unbounded event-store limit must fail closed"
            );
        }
        assert!(EventStoreLimits::default().validate().is_ok());
    }

    #[test]
    fn segmented_config_rejects_unbounded_resource_values() {
        let oversized = vec![
            SegmentedEventStoreConfig {
                max_segment_bytes: u64::MAX,
                ..SegmentedEventStoreConfig::default()
            },
            SegmentedEventStoreConfig {
                max_segment_records: usize::MAX,
                ..SegmentedEventStoreConfig::default()
            },
            SegmentedEventStoreConfig {
                group_commit_records: usize::MAX,
                ..SegmentedEventStoreConfig::default()
            },
            SegmentedEventStoreConfig {
                group_commit_bytes: u64::MAX,
                ..SegmentedEventStoreConfig::default()
            },
            SegmentedEventStoreConfig {
                group_commit_interval: Duration::MAX,
                ..SegmentedEventStoreConfig::default()
            },
        ];

        for config in oversized {
            assert!(
                config.validate().is_err(),
                "unbounded segmented event-store bound must fail closed"
            );
        }
        assert!(SegmentedEventStoreConfig::default().validate().is_ok());
        assert!(SegmentedEventStoreConfig::try_new(EventStoreLimits::default()).is_ok());
    }

    #[test]
    fn read_ahead_bound_rejects_integer_overflow() {
        let mut record_reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        assert!(matches!(
            read_record_line(&mut record_reader, usize::MAX),
            Err(EventStoreError::CapacityExhausted)
        ));

        let mut segment_reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        assert!(matches!(
            read_segment_line(&mut segment_reader, usize::MAX),
            Err(EventStoreError::CapacityExhausted)
        ));
    }

    #[test]
    fn opened_path_identity_rejects_a_recreated_pathname() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("entry");
        let moved = directory.path().join("entry.old");
        std::fs::write(&path, b"original").expect("write original");
        let before = std::fs::symlink_metadata(&path).expect("metadata");
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("open original");

        std::fs::rename(&path, &moved).expect("move original");
        std::fs::write(&path, b"replacement").expect("write replacement");

        let error = validate_opened_path_identity(&path, Some(&before), &file, "test entry")
            .expect_err("replacement must fail closed");
        assert!(matches!(error, EventStoreError::UnsafePath(message) if message.contains("inode")));
    }

    #[test]
    fn opened_path_identity_rejects_a_descriptor_from_another_inode() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("entry");
        let other = directory.path().join("other");
        std::fs::write(&path, b"expected").expect("write expected");
        std::fs::write(&other, b"unexpected").expect("write unexpected");
        let before = std::fs::symlink_metadata(&path).expect("metadata");
        let file = OpenOptions::new()
            .read(true)
            .open(&other)
            .expect("open other");

        let error = validate_opened_path_identity(&path, Some(&before), &file, "test entry")
            .expect_err("descriptor substitution must fail closed");
        assert!(matches!(error, EventStoreError::UnsafePath(message) if message.contains("inode")));
    }

    #[test]
    fn legacy_migration_fences_source_through_destination_open() {
        let directory = tempfile::tempdir().expect("temporary directory");
        // The production path deliberately rejects group/world-writable
        // ancestors.  `tempdir` inherits the process umask here, so tighten
        // the fixture before opening the legacy store.
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure temporary directory");
        let legacy_path = directory.path().join("events.jsonl");
        let root = directory.path().join("events-v2");
        let scope = TurnScope::new("session", "profile", "task", "turn", "stream");
        let legacy =
            DurableEventStore::open(&legacy_path, EventStoreLimits::default(), SyncPolicy::Full)
                .expect("legacy store");
        legacy
            .append(EventInput {
                scope,
                event_id: "event-0".to_string(),
                kind: "observation".to_string(),
                payload: serde_json::json!({"value": 0}),
            })
            .expect("legacy record");
        drop(legacy);

        let mut source_was_fenced = false;
        let migrated = SegmentedEventStore::open_or_migrate_with_legacy_prefix_inner(
            &root,
            &legacy_path,
            SegmentedEventStoreConfig::default(),
            || {
                // This callback stands at the old snapshot→destination-open
                // race boundary.  The source lease must still be held here;
                // an old writer attempting to append is rejected instead of
                // creating a tail that the migration cannot observe.
                let competing = DurableEventStore::open(
                    &legacy_path,
                    EventStoreLimits::default(),
                    SyncPolicy::Full,
                );
                assert!(matches!(competing, Err(EventStoreError::WriterBusy)));
                source_was_fenced = true;
            },
        )
        .expect("migration succeeds while source is fenced");
        assert!(source_was_fenced);
        assert_eq!(migrated.all_records().expect("migrated records").len(), 1);
    }
}
