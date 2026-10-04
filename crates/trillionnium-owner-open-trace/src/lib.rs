//! Off-default bounded stage evidence. This is not an installed qualifier.
//!
//! Hooks append fixed records to memory with a nonblocking lock. They never
//! write files, wait for an exporter or change effect admission. Export only
//! after the owning service has released its locks and stopped its workers.
//! Loss, unfinished deferred spans and clock failure make the trace incomplete.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
mod stream;

pub const MAX_RECORDS: usize = 8192;
pub const MAX_EXPORT_BYTES: usize = 8 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 4096;
static ACTIVE: OnceLock<Arc<Recorder>> = OnceLock::new();

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    BrokerAccept,
    BrokerAuth,
    BrokerQueueWait,
    BrokerForward,
    HostDecode,
    HostCapacityWait,
    JournalAppend,
    JournalFsync,
    ProviderSpawn,
    ProviderFirstEvent,
    ProviderWait,
    CallbackAdmission,
    ToolSpawn,
    ToolOutput,
    ToolExit,
    ToolCleanup,
    TerminalPersistence,
    DeliveryQueueWait,
    ClientDelivery,
}

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub sequence: u64,
    pub stage: Stage,
    pub scope_sha256: String,
    pub pid: u32,
    pub tid: i64,
    pub start_ns: u64,
    pub end_ns: u64,
    /// Physical scope completion is not a semantic success assertion.
    pub end: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub schema: &'static str,
    pub sample_id: String,
    pub producer_role: String,
    pub clock: &'static str,
    pub capacity_records: usize,
    pub loss_observed: bool,
    pub lost_records: Option<u64>,
    pub lost_count_semantics: &'static str,
    pub open_spans: u64,
    pub snapshot_without_observed_loss: bool,
    pub snapshot_only: bool,
    pub producer_quiescence_proven: bool,
    pub trace_complete: bool,
    pub installed_qualified: bool,
    pub records: Vec<Record>,
}

#[derive(Debug)]
pub struct Recorder {
    sample_id: String,
    role: String,
    capacity: usize,
    // A claimed slot belongs to one span for this recorder's entire lifetime.
    // Producers never contend for another producer's publication mutex.
    slots: Vec<Mutex<Option<Record>>>,
    next: AtomicU64,
    lost: AtomicU64,
    open: AtomicU64,
    stream: Option<stream::Stream>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/-".contains(&b))
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}

fn monotonic_ns() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Same Linux CLOCK_MONOTONIC epoch as Python time.monotonic_ns(). No file I/O.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return None;
    }
    u64::try_from(ts.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(ts.tv_nsec).ok()?)
}

impl Recorder {
    pub fn new(sample_id: &str, role: &str, capacity: usize) -> Result<Arc<Self>, String> {
        if !identifier(sample_id)
            || !identifier(role)
            || role == "."
            || role == ".."
            || !role
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || !(1..=MAX_RECORDS).contains(&capacity)
        {
            return Err("trace identifier/capacity outside fixed bounds".into());
        }
        Ok(Arc::new(Self {
            sample_id: sample_id.into(),
            role: role.into(),
            capacity,
            slots: (0..capacity).map(|_| Mutex::new(None)).collect(),
            next: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            open: AtomicU64::new(0),
            stream: None,
        }))
    }

    fn new_stream(sample_id: &str, role: &str, prefix: &Path) -> Result<Arc<Self>, String> {
        let stream = stream::Stream::new(sample_id, role, prefix)?;
        Ok(Arc::new(Self {
            sample_id: sample_id.into(),
            role: role.into(),
            capacity: 2 * stream::BANK_SLOTS,
            slots: Vec::new(),
            next: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            open: AtomicU64::new(0),
            stream: Some(stream),
        }))
    }

    fn record_loss(&self) {
        increment(&self.lost);
        if let Some(stream) = &self.stream {
            stream.record_loss();
        }
    }

    pub fn start(self: &Arc<Self>, stage: Stage, key: &str, deferred: bool) -> Span {
        if key.len() > MAX_KEY_BYTES {
            self.record_loss();
            return Span(None);
        }
        let Some(start_ns) = monotonic_ns() else {
            self.record_loss();
            return Span(None);
        };
        let Some(sequence) = self
            .stream
            .as_ref()
            .map_or_else(|| self.claim_slot(), |s| s.claim())
        else {
            // Stream claim already preserves its own lower-bound loss.
            increment(&self.lost);
            return Span(None);
        };
        increment(&self.open);
        Span(Some(Box::new(Pending {
            recorder: Arc::clone(self),
            deferred,
            record: Record {
                sequence,
                stage,
                scope_sha256: format!("{:x}", Sha256::digest(key.as_bytes())),
                pid: std::process::id(),
                tid: unsafe { libc::syscall(libc::SYS_gettid) },
                start_ns,
                end_ns: 0,
                end: "unfinished",
            },
        })))
    }

    fn claim_slot(&self) -> Option<u64> {
        let mut next = self.next.load(Ordering::Acquire);
        // A failed strong CAS witnesses a different successful claim. There
        // can be at most capacity claims; this loop has a fixed iteration bound.
        for _ in 0..self.capacity {
            if next >= self.capacity as u64 {
                return None;
            }
            match self
                .next
                .compare_exchange(next, next + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(next),
                Err(observed) => next = observed,
            }
        }
        None
    }

    /// Call outside all product locks. Refuses to block behind a hook.
    pub fn snapshot(&self) -> Result<Snapshot, String> {
        if self.stream.is_some() {
            return Err("streaming evidence is not snapshot v1".into());
        }
        let claimed = self.next.load(Ordering::Acquire) as usize;
        let mut records = Vec::with_capacity(claimed);
        for slot in &self.slots[..claimed] {
            let guard = slot
                .try_lock()
                .map_err(|_| "trace snapshot busy/poisoned")?;
            if let Some(record) = guard.as_ref() {
                records.push(record.clone());
            }
        }
        let lost = self.lost.load(Ordering::Acquire);
        let open = self.open.load(Ordering::Acquire);
        // A slot read before publication stays missing from this snapshot even
        // if its producer closes before the counters are read. Never call that
        // captured prefix loss-free. Claims after `claimed` are outside it.
        let prefix_published = records.len() == claimed;
        Ok(Snapshot {
            schema: "org.trillionnium.actual-monotonic-stage-trace.v1",
            sample_id: self.sample_id.clone(),
            producer_role: self.role.clone(),
            clock: "CLOCK_MONOTONIC",
            capacity_records: self.capacity,
            loss_observed: lost > 0,
            lost_records: Some(lost),
            lost_count_semantics: "lower_bound",
            open_spans: open,
            snapshot_without_observed_loss: lost == 0 && open == 0 && prefix_published,
            snapshot_only: true,
            producer_quiescence_proven: false,
            trace_complete: false,
            installed_qualified: false,
            records,
        })
    }
}

#[derive(Debug)]
struct Pending {
    recorder: Arc<Recorder>,
    record: Record,
    deferred: bool,
}

#[derive(Debug)]
pub struct Span(Option<Box<Pending>>);
impl Span {
    pub fn finish(mut self) {
        self.close("observed_boundary");
    }
    pub fn abandon(mut self) {
        self.close("abandoned");
    }
    fn close(&mut self, end: &'static str) {
        let Some(p) = self.0.take() else {
            return;
        };
        let mut p = *p;
        let recorder = p.recorder;
        let now = monotonic_ns();
        if end == "abandoned" || now.is_none() || now.is_some_and(|n| n < p.record.start_ns) {
            recorder.record_loss();
        }
        p.record.end_ns = now.unwrap_or(p.record.start_ns);
        p.record.end = end;
        if let Some(stream) = &recorder.stream {
            if !stream.publish(p.record) {
                increment(&recorder.lost);
            }
            recorder.open.fetch_sub(1, Ordering::Release);
            return;
        }
        match recorder.slots[p.record.sequence as usize].try_lock() {
            Ok(mut slot) => {
                if slot.is_none() {
                    *slot = Some(p.record);
                } else {
                    increment(&recorder.lost);
                }
                recorder.open.fetch_sub(1, Ordering::Release);
            }
            _ => {
                increment(&recorder.lost);
                recorder.open.fetch_sub(1, Ordering::Release);
            }
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let end = if self.0.as_ref().is_some_and(|p| p.deferred) || std::thread::panicking() {
            "abandoned"
        } else {
            "scope_exit_unclassified"
        };
        self.close(end);
    }
}

/// No clocks, key hashing, allocation or syscalls inside this primitive when
/// unconfigured. Rust still evaluates caller arguments before entering it.
pub fn span(stage: Stage, key: &str) -> Span {
    ACTIVE
        .get()
        .map_or(Span(None), |r| r.start(stage, key, false))
}
pub fn deferred(stage: Stage, key: &str) -> Span {
    ACTIVE
        .get()
        .map_or(Span(None), |r| r.start(stage, key, true))
}
pub fn measure<T>(stage: Stage, key: &str, f: impl FnOnce() -> T) -> T {
    let _span = span(stage, key);
    f()
}
pub fn configure_from_env(role: &str) -> Result<(), String> {
    let mode = std::env::var("TRILLIONNIUM_OWNER_TRACE_MODE").ok();
    let stream_output = std::env::var_os("TRILLIONNIUM_OWNER_TRACE_STREAM_OUTPUT");
    if mode
        .as_deref()
        .is_some_and(|m| m != "snapshot" && m != "streaming-completion")
    {
        return Err("invalid explicit trace mode".into());
    }
    if stream_output.is_some() && mode.as_deref() != Some("streaming-completion") {
        return Err("stream output requires explicit streaming mode".into());
    }
    let Some(sample) = std::env::var_os("TRILLIONNIUM_OWNER_TRACE_SAMPLE") else {
        if mode.is_some() || stream_output.is_some() {
            return Err("explicit trace mode/output requires sample".into());
        }
        return Ok(());
    };
    let sample = sample.to_str().ok_or("non-UTF8 trace sample")?;
    let recorder = if mode.as_deref() == Some("streaming-completion") {
        let path = stream_output.ok_or("streaming mode requires dedicated output prefix")?;
        Recorder::new_stream(sample, role, Path::new(&path))?
    } else {
        Recorder::new(sample, role, MAX_RECORDS)?
    };
    install(recorder)
}
pub fn install(recorder: Arc<Recorder>) -> Result<(), String> {
    ACTIVE
        .set(recorder)
        .map_err(|_| "trace already configured".into())
}
pub fn active_snapshot() -> Result<Option<Snapshot>, String> {
    ACTIVE.get().map(|r| r.snapshot()).transpose()
}

/// Call only at an explicitly reviewed outer boundary with product locks
/// released. This is off-default, never invoked by a stage hook.
pub fn drain_stream_from_env() -> Result<(), String> {
    ACTIVE
        .get()
        .and_then(|r| r.stream.as_ref())
        .map_or(Ok(()), |s| s.drain(false))
}
pub fn streaming_enabled() -> bool {
    ACTIVE.get().is_some_and(|r| r.stream.is_some())
}

/// The source integrations call this only between product operations, with
/// their mutexes and stdout guards released. Sticky export failure is reported
/// by final export; it never rewrites the independent effect result.
pub fn drain_stream_at_caller_boundary() {
    let _ = drain_stream_from_env();
}

/// The snapshot/default path retains its original whole-run stdout guard.
/// Streaming uses the same sole writer but releases the standard stdout mutex
/// after each write/flush, before the outer caller can perform durable drain.
pub enum CallerStdout {
    Snapshot(std::io::StdoutLock<'static>),
    Streaming(std::io::Stdout),
}
impl std::io::Write for CallerStdout {
    fn write(&mut self, raw: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Snapshot(w) => w.write(raw),
            Self::Streaming(w) => w.write(raw),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Snapshot(w) => w.flush(),
            Self::Streaming(w) => w.flush(),
        }
    }
}
pub fn caller_stdout() -> CallerStdout {
    if streaming_enabled() {
        CallerStdout::Streaming(std::io::stdout())
    } else {
        CallerStdout::Snapshot(std::io::stdout().lock())
    }
}

/// Optional evidence export; not called by hooks. Existing private parent only.
/// Every ancestor is opened no-follow, output is a fresh owned inode. A failure
/// may leave a partial file, which cannot qualify without caller zero/complete.
pub fn export_from_env() -> Result<(), String> {
    if let Some(stream) = ACTIVE.get().and_then(|r| r.stream.as_ref()) {
        return stream.drain(true);
    }
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let started = std::time::Instant::now();
    let budget = || {
        if started.elapsed() < std::time::Duration::from_secs(5) {
            Ok(())
        } else {
            Err("trace export deadline exceeded".to_string())
        }
    };
    let Some(snapshot) = active_snapshot()? else {
        return Ok(());
    };
    let Some(mut path) = std::env::var_os("TRILLIONNIUM_OWNER_TRACE_OUTPUT") else {
        return Ok(());
    };
    path.push(format!(".{}", snapshot.producer_role));
    let path = Path::new(&path);
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || path.components().count() > 64
        || path.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err("trace output must be a bounded physical absolute path".into());
    }
    let mut parents = vec![File::open("/").map_err(|e| e.to_string())?];
    let mut names = Vec::new();
    for component in path.parent().ok_or("trace parent missing")?.components() {
        if let std::path::Component::Normal(name) = component {
            budget()?;
            let name = std::ffi::CString::new(name.as_bytes()).map_err(|e| e.to_string())?;
            let fd = unsafe {
                libc::openat(
                    parents.last().unwrap().as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            // Register every directory owner before any prior owner closes.
            parents.push(unsafe { File::from_raw_fd(fd) });
            names.push(name);
        }
    }
    let parent = parents.last().unwrap();
    let meta = parent.metadata().map_err(|e| e.to_string())?;
    if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err("trace parent must be private and owned".into());
    }
    let payload = serde_json::to_vec(&snapshot).map_err(|e| e.to_string())?;
    if payload.len() > MAX_EXPORT_BYTES {
        return Err("trace export exceeds fixed cap".into());
    }
    let name = std::ffi::CString::new(path.file_name().ok_or("trace name missing")?.as_bytes())
        .map_err(|e| e.to_string())?;
    budget()?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&payload)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())?;
    // Bind the final inode and all retained parent entries after publication.
    // This is sequential evidence, not protection against arbitrary later edits.
    let actual = file.metadata().map_err(|e| e.to_string())?;
    let mut leaf = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            leaf.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let leaf = unsafe { leaf.assume_init() };
    if actual.dev() != leaf.st_dev
        || actual.ino() != leaf.st_ino
        || actual.nlink() != 1
        || actual.uid() != unsafe { libc::geteuid() }
        || actual.mode() & 0o777 != 0o600
        || actual.len() != payload.len() as u64
        || actual.mode() != leaf.st_mode
        || actual.uid() != leaf.st_uid
        || actual.gid() != leaf.st_gid
        || actual.len() != leaf.st_size as u64
    {
        return Err("trace output identity/size changed".into());
    }
    for (i, name) in names.iter().enumerate() {
        budget()?;
        let held = parents[i + 1].metadata().map_err(|e| e.to_string())?;
        let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parents[i].as_raw_fd(),
                name.as_ptr(),
                entry.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let entry = unsafe { entry.assume_init() };
        if (held.dev(), held.ino(), held.mode(), held.uid(), held.gid())
            != (
                entry.st_dev,
                entry.st_ino,
                entry.st_mode,
                entry.st_uid,
                entry.st_gid,
            )
        {
            return Err("trace parent entry changed".into());
        }
    }
    drop(file);
    drop(parents);
    // Late regular-file I/O/cleanup is rejected; this is not a hard I/O quota.
    budget()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn layout_and_encoded_record_have_explicit_local_bounds() {
        // Bound addressed payload, not allocator/RSS or all producer processes.
        assert!(std::mem::size_of::<Record>() <= 128);
        assert!(std::mem::size_of::<Mutex<Option<Record>>>() <= 160);
        assert!(std::mem::size_of::<Pending>() <= 160);
        assert!(std::mem::size_of::<Span>() <= 8);
        let record = Record {
            sequence: u64::MAX,
            stage: Stage::TerminalPersistence,
            scope_sha256: "f".repeat(64),
            pid: u32::MAX,
            tid: i64::MIN,
            start_ns: u64::MAX,
            end_ns: u64::MAX,
            end: "scope_exit_unclassified",
        };
        let encoded = serde_json::to_vec(&record).unwrap();
        assert!(encoded.len() < 512);
        println!(
            "trace local layout Record={} Slot={} Pending={} Span={} encoded_worst_record={}",
            std::mem::size_of::<Record>(),
            std::mem::size_of::<Mutex<Option<Record>>>(),
            std::mem::size_of::<Pending>(),
            std::mem::size_of::<Span>(),
            encoded.len()
        );
    }

    #[test]
    fn actual_clock_and_deferred_boundary_are_retained() {
        let r = Recorder::new("actual-clock", "test", 4).unwrap();
        let s = r.start(Stage::ToolExit, "same-generation", true);
        assert!(!r.snapshot().unwrap().snapshot_without_observed_loss);
        std::thread::sleep(std::time::Duration::from_millis(10));
        s.finish();
        let snapshot = r.snapshot().unwrap();
        assert!(snapshot.snapshot_without_observed_loss);
        assert!(!snapshot.trace_complete);
        assert!(snapshot.records[0].end_ns - snapshot.records[0].start_ns >= 10_000_000);
        assert!(!snapshot.installed_qualified);
    }
    #[test]
    fn bounded_loss_does_not_overwrite_or_report_complete() {
        let r = Recorder::new("capacity", "test", 1).unwrap();
        r.start(Stage::ToolSpawn, "first", false).finish();
        r.start(Stage::ToolCleanup, "second", false).finish();
        let s = r.snapshot().unwrap();
        assert_eq!(s.records.len(), 1);
        assert_eq!(s.lost_records, Some(1));
        assert!(!s.snapshot_without_observed_loss);
    }
    #[test]
    fn actual_contention_and_abandoned_span_are_fail_closed() {
        let r = Recorder::new("contention", "test", 4).unwrap();
        // Synthetic snapshot-reader scheduling, using a real owned slot lock.
        // Another producer cannot own this slot's publication mutex.
        let guard = r.slots[0].lock().unwrap();
        let other = Arc::clone(&r);
        std::thread::spawn(move || {
            other
                .start(Stage::JournalFsync, "actual-lock", false)
                .finish()
        })
        .join()
        .unwrap();
        drop(guard);
        drop(r.start(Stage::ToolExit, "unfinished", true));
        let s = r.snapshot().unwrap();
        assert_eq!(s.lost_records, Some(2));
        assert!(!s.snapshot_without_observed_loss);
    }
    #[test]
    fn simultaneous_producers_have_unique_slots_without_publication_loss() {
        let r = Recorder::new("synthetic-producer-burst", "test", MAX_RECORDS).unwrap();
        let ready = Arc::new(std::sync::Barrier::new(8));
        let workers = (0..8)
            .map(|_| {
                let r = Arc::clone(&r);
                let ready = Arc::clone(&ready);
                std::thread::spawn(move || {
                    for _ in 0..512 {
                        ready.wait();
                        let span = r.start(Stage::ToolOutput, "synthetic-owned-burst", false);
                        ready.wait();
                        span.finish();
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        let snapshot = r.snapshot().unwrap();
        assert_eq!(snapshot.records.len(), 4096);
        assert_eq!(snapshot.lost_records, Some(0));
        assert_eq!(snapshot.open_spans, 0);
        assert!(snapshot.snapshot_without_observed_loss);
        for (sequence, record) in snapshot.records.iter().enumerate() {
            assert_eq!(record.sequence, sequence as u64);
            assert!(record.end_ns >= record.start_ns);
        }
        assert!(!snapshot.trace_complete);
        assert!(!snapshot.producer_quiescence_proven);
    }
    #[test]
    fn publication_holes_never_claim_a_complete_captured_prefix() {
        let r = Recorder::new("synthetic-hole", "test", 4).unwrap();
        let pending = r.start(Stage::ToolExit, "pending-first", true);
        r.start(Stage::ToolOutput, "completed-second", false)
            .finish();
        let early = r.snapshot().unwrap();
        assert_eq!(early.records.len(), 1);
        assert_eq!(early.records[0].sequence, 1);
        assert_eq!(early.open_spans, 1);
        assert_eq!(early.lost_records, Some(0));
        assert!(!early.snapshot_without_observed_loss);
        pending.finish();
        let later = r.snapshot().unwrap();
        assert_eq!(later.records.len(), 2);
        assert_eq!(later.records[0].sequence, 0);
        assert_eq!(later.records[1].sequence, 1);
        assert!(later.snapshot_without_observed_loss);
        assert!(!later.trace_complete);
    }
    #[test]
    fn snapshot_reader_contention_loses_a_record_without_reusing_its_slot() {
        let r = Recorder::new("synthetic-reader-contention", "test", 2).unwrap();
        let pending = r.start(Stage::ToolExit, "first-slot", true);
        let reader = r.slots[0].lock().unwrap();
        assert!(r.snapshot().is_err());
        std::thread::spawn(move || pending.finish()).join().unwrap();
        drop(reader);
        r.start(Stage::ToolOutput, "second-slot", false).finish();
        let partial = r.snapshot().unwrap();
        assert_eq!(partial.records.len(), 1);
        assert_eq!(partial.records[0].sequence, 1);
        assert_eq!(partial.lost_records, Some(1));
        assert_eq!(partial.open_spans, 0);
        assert!(!partial.snapshot_without_observed_loss);
        r.start(Stage::ToolSpawn, "cannot-reuse-first", false)
            .finish();
        assert_eq!(r.snapshot().unwrap().lost_records, Some(2));
    }
    #[test]
    fn default_off_and_closed_identifiers() {
        assert!(active_snapshot().unwrap().is_none());
        span(Stage::ProviderSpawn, "unused").finish();
        assert!(active_snapshot().unwrap().is_none());
        assert!(Recorder::new("unicode-λ", "test", 1).is_err());
        assert!(Recorder::new("valid", "test", MAX_RECORDS + 1).is_err());
    }
}
