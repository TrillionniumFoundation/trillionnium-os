//! Narrow adapter for bounded event-store writer-lease handoff on journal reopen.
//!
//! `O_CLOEXEC` closes a descriptor at `exec`, not at `fork`. A concurrently
//! forked child can therefore retain a writer lease for the short fork-to-exec
//! interval after the original journal owner exits. Reopening a configured
//! journal waits only for that bounded handoff and still fails closed when a
//! genuine writer remains active.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ::trillionnium_owner_open_event_store as upstream;

pub use upstream::{
    EVENT_RECORD_SCHEMA, EventInput, EventRecord, EventStoreError, EventStoreLimits,
    SegmentedEventStoreConfig, SyncPolicy, TurnScope,
};
pub type Result<T> = upstream::Result<T>;

const WRITER_HANDOFF_WAIT: Duration = Duration::from_secs(1);
const WRITER_HANDOFF_POLL: Duration = Duration::from_millis(5);

fn open_with_bounded_writer_handoff<T>(mut open: impl FnMut() -> Result<T>) -> Result<T> {
    let deadline = Instant::now().checked_add(WRITER_HANDOFF_WAIT);
    loop {
        match open() {
            Ok(value) => return Ok(value),
            Err(EventStoreError::WriterBusy)
                if deadline.is_some_and(|deadline| Instant::now() < deadline) =>
            {
                std::thread::sleep(WRITER_HANDOFF_POLL);
            }
            Err(error) => return Err(error),
        }
    }
}

#[derive(Debug)]
pub struct DurableEventStore(upstream::DurableEventStore);

impl DurableEventStore {
    pub fn open(
        path: impl AsRef<Path>,
        limits: EventStoreLimits,
        sync_policy: SyncPolicy,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        open_with_bounded_writer_handoff(|| {
            upstream::DurableEventStore::open(&path, limits.clone(), sync_policy).map(Self)
        })
    }

    pub fn append(&self, input: EventInput) -> Result<upstream::AppendResult> {
        self.0.append(input)
    }

    pub fn replay(
        &self,
        scope: &TurnScope,
        inclusive_turn_seq: u64,
    ) -> Result<Vec<EventRecord>> {
        self.0.replay(scope, inclusive_turn_seq)
    }

    pub fn all_records(&self) -> Result<Vec<EventRecord>> {
        self.0.all_records()
    }
}

#[derive(Debug)]
pub struct SegmentedEventStore(upstream::SegmentedEventStore);

impl SegmentedEventStore {
    pub fn open(root: impl AsRef<Path>, config: SegmentedEventStoreConfig) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        open_with_bounded_writer_handoff(|| {
            upstream::SegmentedEventStore::open(&root, config.clone()).map(Self)
        })
    }

    pub fn open_or_migrate_with_legacy_prefix(
        root: impl AsRef<Path>,
        legacy_path: impl AsRef<Path>,
        config: SegmentedEventStoreConfig,
    ) -> Result<Self> {
        let root: PathBuf = root.as_ref().to_path_buf();
        let legacy_path: PathBuf = legacy_path.as_ref().to_path_buf();
        open_with_bounded_writer_handoff(|| {
            upstream::SegmentedEventStore::open_or_migrate_with_legacy_prefix(
                &root,
                &legacy_path,
                config.clone(),
            )
            .map(Self)
        })
    }

    pub fn append(&self, input: EventInput) -> Result<upstream::AppendResult> {
        self.0.append(input)
    }

    pub fn append_durable(&self, input: EventInput) -> Result<upstream::AppendResult> {
        self.0.append_durable(input)
    }

    pub fn replay(
        &self,
        scope: &TurnScope,
        inclusive_turn_seq: u64,
    ) -> Result<Vec<EventRecord>> {
        self.0.replay(scope, inclusive_turn_seq)
    }

    pub fn all_records(&self) -> Result<Vec<EventRecord>> {
        self.0.all_records()
    }

    pub fn flush(&self) -> Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn legacy_reopen_waits_for_a_short_lived_inherited_writer_lease() {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("secure temporary directory");
        let path = directory.path().join("events.jsonl");

        let store = DurableEventStore::open(
            &path,
            EventStoreLimits::default(),
            SyncPolicy::Full,
        )
        .expect("initial event store");
        drop(store);

        let inherited = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .expect("open inherited descriptor fixture");
        let locked = unsafe {
            libc::flock(
                inherited.as_raw_fd(),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        };
        assert_eq!(locked, 0);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            drop(inherited);
        });

        let reopened = DurableEventStore::open(
            &path,
            EventStoreLimits::default(),
            SyncPolicy::Full,
        )
        .expect("reopen after inherited writer handoff");
        release.join().expect("descriptor release thread");
        assert!(reopened.all_records().expect("replayed records").is_empty());
    }
}
