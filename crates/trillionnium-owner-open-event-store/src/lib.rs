//! Durable owner-open observation event store.
//!
//! This append-only store records correlation and raw observation payloads for
//! replay and conservative restart analysis. It is not an authorization
//! journal: append failure is reported to the embedding Host, which decides
//! whether the owner-open lineage continues as best-effort/unreplayable.

mod strict_json;

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::hash::Hash;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const EVENT_RECORD_SCHEMA: &str = "trillionnium.owner-open.event-record.v1";
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
            || self.max_record_bytes as u64 > self.max_store_bytes
        {
            return Err(invalid_config("event-store limits are invalid"));
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
        let existed = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(EventStoreError::UnsafePath(
                        "store entry is not a regular non-symlink file".to_string(),
                    ));
                }
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(EventStoreError::Io(error.to_string())),
        };

        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| EventStoreError::Io(error.to_string()))?;
        lock_writer(&file)?;
        validate_store_file(&file)?;
        let parent_after = validate_store_parent(parent)?;
        if parent_before != parent_after {
            return Err(EventStoreError::UnsafePath(
                "store parent changed while the file was opened".to_string(),
            ));
        }
        if !existed {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| EventStoreError::Io(error.to_string()))?;
            sync_directory(parent)?;
        }

        let metadata = file
            .metadata()
            .map_err(|error| EventStoreError::Io(error.to_string()))?;
        if metadata.len() > limits.max_store_bytes {
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
        let record_sha256 = record_digest(
            store_seq,
            turn_seq,
            &input.scope,
            &input.event_id,
            &input.kind,
            &input.payload,
            &payload_sha256,
            &previous_record_sha256,
        )?;
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
    loop {
        let Some((encoded, consumed)) = read_record_line(&mut reader, limits.max_record_bytes)?
        else {
            break;
        };
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
    let mut limited = (&mut *reader).take(maximum as u64 + 2);
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
    let expected = record_digest(
        record.store_seq,
        record.turn_seq,
        &record.scope,
        &record.event_id,
        &record.kind,
        &record.payload,
        &record.payload_sha256,
        &record.previous_record_sha256,
    )?;
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

fn record_digest(
    store_seq: u64,
    turn_seq: u64,
    scope: &TurnScope,
    event_id: &str,
    kind: &str,
    payload: &Value,
    payload_sha256: &str,
    previous_record_sha256: &str,
) -> Result<String> {
    let encoded = serde_json::to_vec(&RecordPreimage {
        schema: EVENT_RECORD_SCHEMA,
        store_seq,
        turn_seq,
        scope,
        event_id,
        kind,
        payload,
        payload_sha256,
        previous_record_sha256,
    })
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

fn validate_store_file(file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| EventStoreError::Io(error.to_string()))?;
    let effective_uid = unsafe { libc::geteuid() };
    let mode = metadata.mode() & 0o7777;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || mode != 0o600
    {
        return Err(EventStoreError::UnsafePath(format!(
            "store file must be service-owned regular 0600 with one link (uid {}, mode {:04o}, nlink {})",
            metadata.uid(),
            mode,
            metadata.nlink()
        )));
    }
    Ok(())
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
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| EventStoreError::Io(error.to_string()))
}

fn invalid_config(message: impl Into<String>) -> EventStoreError {
    EventStoreError::InvalidConfiguration(message.into())
}
