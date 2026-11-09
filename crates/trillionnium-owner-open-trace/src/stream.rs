//! Explicit streaming evidence, separate from the unchanged snapshot v1 mode.
//! Two banks are reusable only after their immutable chunk and ACK are durable.
//! A start retains a resident credit and identity, not a completion bank.
//! Completion sequence is closed-publication admission order, not end timestamp order.
use super::{Record, identifier, increment};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub(crate) const BANK_SLOTS: usize = 512;
const COUNTER_MASK: u64 = 1023;
const OPEN_SHIFT: u32 = 10;
const SEALED: u64 = 1 << 62;
const FREE: u64 = 1 << 63;
const MAX_EPOCHS: u64 = 256;
const MAX_STARTED: u64 = 65_536;
const RESIDENT_LIMIT: u64 = 1024;
const START_MASK: u64 = (1 << 17) - 1;
const RESIDENT_SHIFT: u32 = 17;
const PENDING_SHIFT: u32 = 28;
const CREDIT_MASK: u64 = (1 << 11) - 1;
const SOURCE_CLOSED: u64 = 1 << 63;
const MAX_FILES: u64 = MAX_EPOCHS * 2 + 2; // context, chunk/ACK pairs, terminator
const MAX_DISK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHUNK_BYTES: usize = 512 * 1024;
const MAX_DESCRIPTOR_BYTES: usize = 4096;

fn claimed(state: u64) -> usize {
    (state & COUNTER_MASK) as usize
}
fn open(state: u64) -> u64 {
    (state >> OPEN_SHIFT) & COUNTER_MASK
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

struct Bank {
    // A completed record claims and increments unpublished together. A long
    // span lives outside these slots; sealing cannot acknowledge a publish hole.
    state: AtomicU64,
    epoch: AtomicU64,
    slots: Vec<Mutex<Option<CompletedRecord>>>,
}

#[cfg(test)]
mod tests;
impl Bank {
    fn new(state: u64) -> Self {
        Self {
            state: AtomicU64::new(state),
            epoch: AtomicU64::new(0),
            slots: (0..BANK_SLOTS).map(|_| Mutex::new(None)).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct CompletedRecord {
    start_claim_id: u64,
    completion_sequence: u64,
    stage: super::Stage,
    scope_sha256: String,
    pid: u32,
    tid: i64,
    start_ns: u64,
    end_ns: u64,
    end: &'static str,
}
fn resident(state: u64) -> u64 {
    (state >> RESIDENT_SHIFT) & CREDIT_MASK
}
fn pending(state: u64) -> u64 {
    (state >> PENDING_SHIFT) & CREDIT_MASK
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Generation {
    pid: u32,
    start_time_ticks: u64,
    boot_id_sha256: String,
}
impl Generation {
    fn observe() -> Result<Self, String> {
        let mut stat = String::new();
        File::open("/proc/self/stat")
            .map_err(err)?
            .take(8193)
            .read_to_string(&mut stat)
            .map_err(err)?;
        if stat.len() > 8192 {
            return Err("trace generation stat bound".into());
        }
        let end = stat.rfind(')').ok_or("trace generation stat shape")?;
        let fields: Vec<_> = stat[end + 1..].split_whitespace().collect();
        let start: u64 = fields
            .get(19)
            .ok_or("trace generation start missing")?
            .parse()
            .map_err(err)?;
        let mut boot = String::new();
        File::open("/proc/sys/kernel/random/boot_id")
            .map_err(err)?
            .take(65)
            .read_to_string(&mut boot)
            .map_err(err)?;
        let boot = boot.trim();
        if start == 0
            || boot.len() != 36
            || !boot.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
        {
            return Err("trace generation identity invalid".into());
        }
        Ok(Self {
            pid: std::process::id(),
            start_time_ticks: start,
            boot_id_sha256: format!("{:x}", Sha256::digest(boot.as_bytes())),
        })
    }
}

#[derive(Serialize)]
struct Context<'a> {
    schema: &'static str,
    sample_id: &'a str,
    producer_role: &'a str,
    generation: &'a Generation,
    bank_count: usize,
    slots_per_bank: usize,
    lifetime_epochs: u64,
    lifetime_files: u64,
    lifetime_disk_bytes: u64,
    lost_count_semantics: &'static str,
    lifetime_started: u64,
    resident_credits: u64,
    completion_order: &'static str,
    trace_complete: bool,
    installed_qualified: bool,
}
#[derive(Serialize)]
struct Chunk<'a> {
    schema: &'static str,
    sample_id: &'a str,
    producer_role: &'a str,
    generation: &'a Generation,
    epoch: u64,
    claimed_start: u64,
    claimed_end_exclusive: u64,
    declared_unused_tail_start: u64,
    declared_unused_tail_end_exclusive: u64,
    loss_observed: bool,
    lost_records_lower_bound: u64,
    records: &'a [CompletedRecord],
    lost_count_semantics: &'static str,
    previous_ack_sha256: &'a str,
    trace_complete: bool,
    installed_qualified: bool,
}
#[derive(Serialize)]
struct Ack<'a> {
    schema: &'static str,
    sample_id: &'a str,
    producer_role: &'a str,
    generation: &'a Generation,
    epoch: u64,
    chunk_file: &'a str,
    chunk_bytes: u64,
    chunk_sha256: &'a str,
    chunk_fd9: [i128; 9],
    claimed_start: u64,
    claimed_end_exclusive: u64,
    previous_ack_sha256: &'a str,
    trace_complete: bool,
    installed_qualified: bool,
}

// This owner retains every physical directory until final export. Mutable
// directory times/sizes may change through our writes; dev/ino/mode/uid/gid may not.
struct Output {
    parents: Vec<File>,
    names: Vec<std::ffi::CString>,
    parent_fixed: Vec<(u64, u64, u32, u32, u32)>,
    base: String,
    bytes: u64,
    files: u64,
    previous_ack: String,
    phase: String,
    failure: Option<String>,
}
fn fd9(m: &std::fs::Metadata) -> [i128; 9] {
    [
        m.dev() as i128,
        m.ino() as i128,
        m.mode() as i128,
        m.nlink() as i128,
        m.uid() as i128,
        m.gid() as i128,
        m.len() as i128,
        m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
        m.ctime() as i128 * 1_000_000_000 + m.ctime_nsec() as i128,
    ]
}
impl Output {
    fn new(prefix: &Path, role: &str, generation: &Generation) -> Result<Self, String> {
        if !prefix.is_absolute()
            || prefix.as_os_str().len() > 4096
            || prefix.components().count() > 64
            || prefix.components().any(|c| {
                !matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            return Err("stream output physical absolute bound".into());
        }
        let mut parents = vec![File::open("/").map_err(err)?];
        let mut names = Vec::new();
        for c in prefix.parent().ok_or("stream parent missing")?.components() {
            if let std::path::Component::Normal(name) = c {
                let name = std::ffi::CString::new(name.as_bytes()).map_err(err)?;
                let n = unsafe {
                    libc::openat(
                        parents.last().unwrap().as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if n < 0 {
                    return Err(err(std::io::Error::last_os_error()));
                }
                parents.push(unsafe { File::from_raw_fd(n) });
                names.push(name);
            }
        }
        let m = parents.last().unwrap().metadata().map_err(err)?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err("stream parent must be private owned".into());
        }
        let stem = prefix
            .file_name()
            .ok_or("stream stem missing")?
            .to_str()
            .ok_or("stream stem utf8")?;
        if !identifier(stem) || stem.contains('/') {
            return Err("stream stem identifier bound".into());
        }
        let base = format!(
            "{stem}.{role}.{}.{}.{}",
            generation.pid,
            generation.start_time_ticks,
            &generation.boot_id_sha256[..16]
        );
        if base.len() > 200 {
            return Err("stream generated leaf name bound".into());
        }
        let parent_fixed = parents
            .iter()
            .map(|p| {
                p.metadata()
                    .map(|m| (m.dev(), m.ino(), m.mode(), m.uid(), m.gid()))
                    .map_err(err)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            parents,
            names,
            parent_fixed,
            base,
            bytes: 0,
            files: 0,
            previous_ack: String::new(),
            phase: "context.configure".into(),
            failure: None,
        })
    }
    fn check_parents(&self) -> Result<(), String> {
        for (p, expected) in self.parents.iter().zip(&self.parent_fixed) {
            let m = p.metadata().map_err(err)?;
            if (m.dev(), m.ino(), m.mode(), m.uid(), m.gid()) != *expected {
                return Err("stream held parent identity changed".into());
            }
        }
        for (i, name) in self.names.iter().enumerate() {
            let m = self.parents[i + 1].metadata().map_err(err)?;
            let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe {
                libc::fstatat(
                    self.parents[i].as_raw_fd(),
                    name.as_ptr(),
                    s.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(err(std::io::Error::last_os_error()));
            }
            let s = unsafe { s.assume_init() };
            if (m.dev(), m.ino(), m.mode(), m.uid(), m.gid())
                != (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)
            {
                return Err("stream parent custody changed".into());
            }
        }
        Ok(())
    }
    fn write(
        &mut self,
        kind: &str,
        name: &str,
        raw: &[u8],
        maximum: usize,
        deadline: Instant,
    ) -> Result<[i128; 9], String> {
        self.phase = format!("{kind}.bounds");
        if self.failure.is_some() || raw.len() > maximum || Instant::now() >= deadline {
            return Err("stream write failed/bound/deadline".into());
        }
        self.bytes = self
            .bytes
            .checked_add(raw.len() as u64)
            .ok_or("stream bytes overflow")?;
        self.files = self.files.checked_add(1).ok_or("stream files overflow")?;
        if self.bytes > MAX_DISK_BYTES || self.files > MAX_FILES {
            return Err("stream lifetime disk bound".into());
        }
        self.phase = format!("{kind}.parent_before");
        self.check_parents()?;
        let parent = self.parents.last().unwrap();
        let name = std::ffi::CString::new(name).map_err(err)?;
        self.phase = format!("{kind}.open_exclusive");
        let n = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if n < 0 {
            return Err(err(std::io::Error::last_os_error()));
        }
        let mut f = unsafe { File::from_raw_fd(n) };
        self.phase = format!("{kind}.write");
        f.write_all(raw).map_err(err)?;
        self.phase = format!("{kind}.file_fsync");
        f.sync_all().map_err(err)?;
        self.phase = format!("{kind}.fd_verify");
        let before = f.metadata().map_err(err)?;
        if before.nlink() != 1
            || before.mode() & 0o777 != 0o600
            || before.uid() != unsafe { libc::geteuid() }
            || before.len() != raw.len() as u64
        {
            return Err("stream output regular custody invalid".into());
        }
        f.seek(SeekFrom::Start(0)).map_err(err)?;
        let mut digest = Sha256::new();
        let mut remaining = raw.len();
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            if Instant::now() >= deadline {
                return Err("stream verify deadline".into());
            }
            let bound = remaining.min(buf.len());
            let count = f.read(&mut buf[..bound]).map_err(err)?;
            if count == 0 {
                return Err("stream output short verification".into());
            }
            digest.update(&buf[..count]);
            remaining -= count;
        }
        let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                s.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(err(std::io::Error::last_os_error()));
        }
        let s = unsafe { s.assume_init() };
        let after = f.metadata().map_err(err)?;
        let entry = [
            s.st_dev as i128,
            s.st_ino as i128,
            s.st_mode as i128,
            s.st_nlink as i128,
            s.st_uid as i128,
            s.st_gid as i128,
            s.st_size as i128,
            s.st_mtime as i128 * 1_000_000_000 + s.st_mtime_nsec as i128,
            s.st_ctime as i128 * 1_000_000_000 + s.st_ctime_nsec as i128,
        ];
        if fd9(&before) != fd9(&after)
            || fd9(&after) != entry
            || digest.finalize().as_slice() != Sha256::digest(raw).as_slice()
        {
            return Err("stream leaf custody/hash changed".into());
        }
        self.phase = format!("{kind}.parent_fsync");
        parent.sync_all().map_err(err)?;
        self.phase = format!("{kind}.parent_after");
        self.check_parents()?;
        if Instant::now() >= deadline {
            return Err("stream publication late".into());
        }
        Ok(fd9(&after))
    }
}

pub(crate) struct Stream {
    sample: String,
    role: String,
    generation: Generation,
    banks: [Bank; 2],
    active: AtomicUsize,
    next_epoch: AtomicU64,
    // start ID, resident credit, pending count and close gate change in one CAS.
    // Credits include both pending spans and completed records until durable ACK.
    claims: AtomicU64,
    published: AtomicU64,
    acked: AtomicU64,
    lost: AtomicU64,
    first_loss: AtomicU64,
    first_failure: AtomicU64, // 1 final acquire busy, 2 poisoned, 3 owner-held physical failure
    output: Mutex<Output>,
}
impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletionStream")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}
impl Stream {
    pub(crate) fn new(sample: &str, role: &str, prefix: &Path) -> Result<Self, String> {
        if !identifier(sample)
            || !identifier(role)
            || role == "."
            || role == ".."
            || !role
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            return Err("stream sample/role identifier bound".into());
        }
        let generation = Generation::observe()?;
        let mut output = Output::new(prefix, role, &generation)?;
        let context = Context {
            schema: "org.trillionnium.actual-monotonic-completion-stream-context.v2",
            sample_id: sample,
            producer_role: role,
            generation: &generation,
            bank_count: 2,
            slots_per_bank: BANK_SLOTS,
            lifetime_epochs: MAX_EPOCHS,
            lifetime_files: MAX_FILES,
            lifetime_disk_bytes: MAX_DISK_BYTES,
            lost_count_semantics: "saturating_lower_bound",
            lifetime_started: MAX_STARTED,
            resident_credits: RESIDENT_LIMIT,
            completion_order: "closed_publication_admission",
            trace_complete: false,
            installed_qualified: false,
        };
        let raw = serde_json::to_vec(&context).map_err(err)?;
        output
            .write(
                "context",
                &format!("{}.context.json", output.base),
                &raw,
                MAX_DESCRIPTOR_BYTES,
                Instant::now() + Duration::from_secs(5),
            )
            .map_err(|error| format!("{}: {error}", output.phase))?;
        Ok(Self {
            sample: sample.into(),
            role: role.into(),
            generation,
            banks: [Bank::new(0), Bank::new(FREE)],
            active: AtomicUsize::new(0),
            next_epoch: AtomicU64::new(1),
            claims: AtomicU64::new(0),
            published: AtomicU64::new(0),
            acked: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            first_loss: AtomicU64::new(0),
            first_failure: AtomicU64::new(0),
            output: Mutex::new(output),
        })
    }
    pub(crate) fn claim(&self) -> Option<u64> {
        let mut state = self.claims.load(Ordering::Acquire);
        // Finite retries, never wait for an exporter or another producer.
        for _ in 0..RESIDENT_LIMIT {
            if state & SOURCE_CLOSED != 0
                || state & START_MASK >= MAX_STARTED
                || resident(state) >= RESIDENT_LIMIT
            {
                let reason = if state & SOURCE_CLOSED != 0 {
                    2
                } else if state & START_MASK >= MAX_STARTED {
                    4
                } else {
                    3
                };
                self.mark_loss(reason);
                return None;
            }
            match self.claims.compare_exchange(
                state,
                state + 1 + (1 << RESIDENT_SHIFT) + (1 << PENDING_SHIFT),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(state & START_MASK),
                Err(actual) => state = actual,
            }
        }
        self.mark_loss(5);
        None
    }
    pub(crate) fn publish(&self, record: Record) -> bool {
        let result = self.publish_completed(record);
        // Once this actual close returns, it is not pending. If publication
        // failed its credit remains retained and loss forbids ACK/final scope.
        let prior = self.claims.fetch_sub(1 << PENDING_SHIFT, Ordering::AcqRel);
        debug_assert!(pending(prior) > 0);
        result
    }
    fn publish_completed(&self, record: Record) -> bool {
        self.publish_completed_from(record, self.active.load(Ordering::Acquire))
    }
    fn publish_completed_from(&self, record: Record, initial: usize) -> bool {
        let mut bank_index = initial;
        let mut state = self.banks[bank_index].state.load(Ordering::Acquire);
        let mut owner = None;
        // A preempted producer may retain the former active index while the
        // exporter seals it and opens the other bank. Re-select actual state,
        // never wait for ACK or retry an effect. Total CAS attempts remain 512.
        for _ in 0..BANK_SLOTS {
            if state & (FREE | SEALED) != 0 || claimed(state) >= BANK_SLOTS {
                bank_index = 1 - bank_index;
                state = self.banks[bank_index].state.load(Ordering::Acquire);
                if state & (FREE | SEALED) != 0 || claimed(state) >= BANK_SLOTS {
                    break;
                }
            }
            let bank = &self.banks[bank_index];
            match bank.state.compare_exchange(
                state,
                state + 1 + (1 << OPEN_SHIFT),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    owner = Some((bank_index, claimed(state)));
                    break;
                }
                Err(actual) => state = actual,
            }
        }
        let Some((bank_index, index)) = owner else {
            self.mark_loss(6);
            return false;
        };
        let bank = &self.banks[bank_index];
        // epoch cannot be reused while this unpublished claim pins the bank.
        let completion_sequence =
            bank.epoch.load(Ordering::Acquire) * BANK_SLOTS as u64 + index as u64;
        let value = CompletedRecord {
            start_claim_id: record.sequence,
            completion_sequence,
            stage: record.stage,
            scope_sha256: record.scope_sha256,
            pid: record.pid,
            tid: record.tid,
            start_ns: record.start_ns,
            end_ns: record.end_ns,
            end: record.end,
        };
        let result = match bank.slots[index].try_lock() {
            Ok(mut slot) if slot.is_none() => {
                *slot = Some(value);
                self.published.fetch_add(1, Ordering::Release);
                true
            }
            _ => {
                self.mark_loss(7);
                false
            }
        };
        let prior = bank.state.fetch_sub(1 << OPEN_SHIFT, Ordering::AcqRel);
        debug_assert!(open(prior) > 0);
        result
    }
    pub(crate) fn lost(&self) -> u64 {
        self.lost.load(Ordering::Acquire)
    }
    pub(crate) fn record_loss(&self) {
        self.mark_loss(1);
    }
    fn mark_loss(&self, phase: u64) {
        let _ = self
            .first_loss
            .compare_exchange(0, phase, Ordering::AcqRel, Ordering::Acquire);
        increment(&self.lost);
    }
    fn loss_observed(&self) -> bool {
        self.first_loss.load(Ordering::Acquire) != 0 || self.lost() != 0
    }
    fn first_loss_label(&self) -> &'static str {
        match self.first_loss.load(Ordering::Acquire) {
            1 => "span.invalid_or_abandoned",
            2 => "start.source_closed",
            3 => "start.resident_capacity",
            4 => "start.lifetime_capacity",
            5 => "start.CAS_retry_bound",
            6 => "completion.bank_capacity_or_retry",
            7 => "completion.slot_publication",
            8 => "exporter.acquire",
            _ => "none",
        }
    }
    fn retained_failure(&self, output: &Output) -> Option<String> {
        match self.first_failure.load(Ordering::Acquire) {
            0 => None,
            1 => Some("exporter.acquire: final busy".into()),
            2 => Some("exporter.acquire: poisoned".into()),
            _ => Some(
                output
                    .failure
                    .clone()
                    .unwrap_or_else(|| "exporter.owner: physical failure details pending".into()),
            ),
        }
    }
    #[cfg(test)]
    pub(crate) fn open(&self) -> u64 {
        pending(self.claims.load(Ordering::Acquire))
    }
    pub(crate) fn drain(&self, final_scope: bool) -> Result<(), String> {
        let mut output = match self.output.try_lock() {
            Ok(value) => value,
            Err(std::sync::TryLockError::WouldBlock) if !final_scope => return Ok(()),
            Err(error) => {
                let code = match error {
                    std::sync::TryLockError::WouldBlock => 1,
                    _ => 2,
                };
                let _ = self.first_failure.compare_exchange(
                    0,
                    code,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                self.mark_loss(8);
                return Err(match self.first_failure.load(Ordering::Acquire) {
                    1 => "exporter.acquire: final busy",
                    2 => "exporter.acquire: poisoned",
                    _ => "exporter.owner: retained physical failure",
                }
                .into());
            }
        };
        if let Some(failure) = self.retained_failure(&output) {
            return Err(format!("stream retains first failure: {failure}"));
        }
        let result = self.drain_under_owner(&mut output, final_scope);
        if let Err(error) = &result {
            let _ = self
                .first_failure
                .compare_exchange(0, 3, Ordering::AcqRel, Ordering::Acquire);
            let message: String = error.chars().take(512).collect();
            output.failure = Some(format!("{}: {message}", output.phase));
        }
        if let Some(failure) = self.retained_failure(&output) {
            return Err(failure);
        }
        result
    }
    fn activate(&self, index: usize) -> Result<(), String> {
        let epoch = self.next_epoch.load(Ordering::Acquire);
        if epoch >= MAX_EPOCHS {
            return Err("stream lifetime epoch bound".into());
        }
        self.banks[index].epoch.store(epoch, Ordering::Release);
        self.banks[index].state.store(0, Ordering::Release);
        self.next_epoch.store(epoch + 1, Ordering::Release);
        self.active.store(index, Ordering::Release);
        Ok(())
    }
    fn drain_under_owner(&self, output: &mut Output, final_scope: bool) -> Result<(), String> {
        output.phase = "drain.seal".into();
        if final_scope {
            self.claims.fetch_or(SOURCE_CLOSED, Ordering::AcqRel);
        }
        let active = self.active.load(Ordering::Acquire);
        let bank = &self.banks[active];
        let state = bank.state.load(Ordering::Acquire);
        if final_scope || claimed(state) >= BANK_SLOTS / 2 {
            bank.state.fetch_or(SEALED, Ordering::AcqRel);
            if !final_scope && self.banks[1 - active].state.load(Ordering::Acquire) == FREE {
                self.activate(1 - active)?;
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut closed_banks: Vec<_> = self
            .banks
            .iter()
            .filter(|b| {
                let s = b.state.load(Ordering::Acquire);
                s & SEALED != 0 && s & FREE == 0 && open(s) == 0
            })
            .collect();
        closed_banks.sort_by_key(|b| b.epoch.load(Ordering::Acquire));
        for bank in closed_banks {
            output.phase = "drain.closed_slots".into();
            let state = bank.state.load(Ordering::Acquire);
            let count = claimed(state);
            let epoch = bank.epoch.load(Ordering::Acquire);
            if self.banks.iter().any(|b| {
                b.state.load(Ordering::Acquire) & FREE == 0
                    && b.epoch.load(Ordering::Acquire) < epoch
            }) {
                continue;
            }
            let mut owners = bank.slots[..count]
                .iter()
                .map(|slot| {
                    slot.try_lock()
                        .map_err(|_| "closed slot busy/poisoned".to_string())
                })
                .collect::<Result<Vec<_>, String>>()?;
            let records = owners
                .iter()
                .map(|slot| {
                    slot.as_ref()
                        .cloned()
                        .ok_or("claimed publication hole".to_string())
                })
                .collect::<Result<Vec<_>, String>>()?;
            if self.loss_observed() {
                return Err(format!(
                    "loss prevents ACK/reuse; first observed loss {}",
                    self.first_loss_label()
                ));
            }
            let start = epoch * BANK_SLOTS as u64;
            let chunk = Chunk {
                schema: "org.trillionnium.actual-monotonic-completion-stream-chunk.v2",
                sample_id: &self.sample,
                producer_role: &self.role,
                generation: &self.generation,
                epoch,
                claimed_start: start,
                claimed_end_exclusive: start + count as u64,
                declared_unused_tail_start: start + count as u64,
                declared_unused_tail_end_exclusive: start + BANK_SLOTS as u64,
                loss_observed: false,
                lost_records_lower_bound: self.lost(),
                records: &records,
                lost_count_semantics: "saturating_lower_bound",
                previous_ack_sha256: &output.previous_ack,
                trace_complete: false,
                installed_qualified: false,
            };
            output.phase = "chunk.serialize".into();
            let raw = serde_json::to_vec(&chunk).map_err(err)?;
            let name = format!("{}.e{epoch}.chunk.json", output.base);
            let digest = format!("{:x}", Sha256::digest(&raw));
            let custody = output.write("chunk", &name, &raw, MAX_CHUNK_BYTES, deadline)?;
            let ack = Ack {
                schema: "org.trillionnium.actual-monotonic-completion-stream-ack.v2",
                sample_id: &self.sample,
                producer_role: &self.role,
                generation: &self.generation,
                epoch,
                chunk_file: &name,
                chunk_bytes: raw.len() as u64,
                chunk_sha256: &digest,
                chunk_fd9: custody,
                claimed_start: start,
                claimed_end_exclusive: start + count as u64,
                previous_ack_sha256: &output.previous_ack,
                trace_complete: false,
                installed_qualified: false,
            };
            output.phase = "ack.serialize".into();
            let raw_ack = serde_json::to_vec(&ack).map_err(err)?;
            if self.loss_observed() {
                return Err("concurrent loss prevents ACK".into());
            }
            output.write(
                "ack",
                &format!("{}.e{epoch}.ack.json", output.base),
                &raw_ack,
                MAX_DESCRIPTOR_BYTES,
                deadline,
            )?;
            output.phase = "ack.release_credits".into();
            if self.loss_observed() {
                return Err("late concurrent loss retains bank".into());
            }
            // Sole owner holds every slot. Only after immutable ACK durability
            // and late checks may retained memory and resident credits be reused.
            output.previous_ack = format!("{:x}", Sha256::digest(&raw_ack));
            for slot in &mut owners {
                **slot = None;
            }
            let prior = self
                .claims
                .fetch_sub((count as u64) << RESIDENT_SHIFT, Ordering::AcqRel);
            debug_assert!(resident(prior) >= count as u64);
            self.acked.fetch_add(count as u64, Ordering::Release);
            drop(owners); // publish FREE only after every closed slot guard is gone
            bank.state.store(FREE, Ordering::Release);
        }
        output.phase = "drain.reactivate".into();
        if !final_scope
            && self.banks[self.active.load(Ordering::Acquire)]
                .state
                .load(Ordering::Acquire)
                == FREE
        {
            self.activate(self.active.load(Ordering::Acquire))?;
        }
        if final_scope {
            output.phase = "terminator.closure".into();
            let state = self.claims.load(Ordering::Acquire);
            let started = state & START_MASK;
            let published = self.published.load(Ordering::Acquire);
            let acked = self.acked.load(Ordering::Acquire);
            if pending(state) != 0
                || resident(state) != 0
                || self.loss_observed()
                || self
                    .banks
                    .iter()
                    .any(|b| b.state.load(Ordering::Acquire) != FREE)
                || started != published
                || started != acked
            {
                return Err("final pending/lost/unACKed/start closure".into());
            }
            #[derive(Serialize)]
            struct End<'a> {
                schema: &'static str,
                sample_id: &'a str,
                producer_role: &'a str,
                generation: &'a Generation,
                last_ack_sha256: &'a str,
                epochs: u64,
                files_before_terminator: u64,
                bytes_before_terminator: u64,
                started_count: u64,
                published_count: u64,
                acknowledged_count: u64,
                pending_count: u64,
                resident_count: u64,
                source_stream_closed: bool,
                producer_quiescence_proven: bool,
                trace_complete: bool,
                installed_qualified: bool,
            }
            output.phase = "terminator.serialize".into();
            let raw = serde_json::to_vec(&End {
                schema: "org.trillionnium.actual-monotonic-completion-stream-terminator.v2",
                sample_id: &self.sample,
                producer_role: &self.role,
                generation: &self.generation,
                last_ack_sha256: &output.previous_ack,
                epochs: self.next_epoch.load(Ordering::Acquire),
                files_before_terminator: output.files,
                bytes_before_terminator: output.bytes,
                started_count: started,
                published_count: published,
                acknowledged_count: acked,
                pending_count: 0,
                resident_count: 0,
                source_stream_closed: true,
                producer_quiescence_proven: false,
                trace_complete: false,
                installed_qualified: false,
            })
            .map_err(err)?;
            output.write(
                "terminator",
                &format!("{}.terminator.json", output.base),
                &raw,
                MAX_DESCRIPTOR_BYTES,
                deadline,
            )?;
            output.phase = "terminator.late_closure".into();
            if self.claims.load(Ordering::Acquire) != state || self.loss_observed() {
                return Err("source changed during final publication".into());
            }
        }
        Ok(())
    }
}
