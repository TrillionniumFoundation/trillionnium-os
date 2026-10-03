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
    records: Mutex<Vec<Record>>,
    next: AtomicU64,
    lost: AtomicU64,
    open: AtomicU64,
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
            records: Mutex::new(Vec::with_capacity(capacity)),
            next: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            open: AtomicU64::new(0),
        }))
    }

    pub fn start(self: &Arc<Self>, stage: Stage, key: &str, deferred: bool) -> Span {
        if key.len() > MAX_KEY_BYTES {
            increment(&self.lost);
            return Span(None);
        }
        let Some(start_ns) = monotonic_ns() else {
            increment(&self.lost);
            return Span(None);
        };
        // Reserve bounded in-flight capacity under the same nonblocking gate
        // used by snapshot/close. A producer never waits for an exporter.
        let Ok(records) = self.records.try_lock() else {
            increment(&self.lost);
            return Span(None);
        };
        if records
            .len()
            .saturating_add(self.open.load(Ordering::Acquire) as usize)
            >= self.capacity
        {
            increment(&self.lost);
            return Span(None);
        }
        let Ok(sequence) = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        else {
            increment(&self.lost);
            return Span(None);
        };
        increment(&self.open);
        drop(records);
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

    /// Call outside all product locks. Refuses to block behind a hook.
    pub fn snapshot(&self) -> Result<Snapshot, String> {
        let guard = self
            .records
            .try_lock()
            .map_err(|_| "trace snapshot busy/poisoned")?;
        let records = guard.clone();
        let lost = self.lost.load(Ordering::Acquire);
        let open = self.open.load(Ordering::Acquire);
        drop(guard);
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
            snapshot_without_observed_loss: lost == 0 && open == 0,
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
            increment(&recorder.lost);
        }
        p.record.end_ns = now.unwrap_or(p.record.start_ns);
        p.record.end = end;
        match recorder.records.try_lock() {
            Ok(mut records) => {
                if records.len() < recorder.capacity {
                    records.push(p.record);
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

/// No clocks, key hashing, allocation or syscalls when unconfigured.
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
    let Some(sample) = std::env::var_os("TRILLIONNIUM_OWNER_TRACE_SAMPLE") else {
        return Ok(());
    };
    let sample = sample.to_str().ok_or("non-UTF8 trace sample")?;
    let recorder = Recorder::new(sample, role, MAX_RECORDS)?;
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

/// Optional evidence export; not called by hooks. Existing private parent only.
/// Every ancestor is opened no-follow, output is a fresh owned inode. A failure
/// may leave a partial file, which cannot qualify without caller zero/complete.
pub fn export_from_env() -> Result<(), String> {
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
            "trace local layout Record={} Pending={} Span={} encoded_worst_record={}",
            std::mem::size_of::<Record>(),
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
        let guard = r.records.lock().unwrap();
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
    fn default_off_and_closed_identifiers() {
        assert!(active_snapshot().unwrap().is_none());
        span(Stage::ProviderSpawn, "unused").finish();
        assert!(active_snapshot().unwrap().is_none());
        assert!(Recorder::new("unicode-λ", "test", 1).is_err());
        assert!(Recorder::new("valid", "test", MAX_RECORDS + 1).is_err());
    }
}
