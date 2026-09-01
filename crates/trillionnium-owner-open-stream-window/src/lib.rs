//! Bounded byte-credit and pause/resume mechanics for owner-open streams.
//!
//! This crate is deliberately semantic-free. It does not decide whether a
//! provider, tool, command, target or observation is allowed. It only tracks a
//! finite delivery window, exact control-frame sequencing and terminal closure
//! so a carrier can apply backpressure without dropping or reinterpreting
//! persisted observations.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StreamWindowError {
    #[error("invalid owner-open stream-window configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid owner-open stream-window request: {0}")]
    InvalidRequest(String),
    #[error("stream control sequence gap: expected {expected}, received {received}")]
    SequenceGap { expected: u64, received: u64 },
    #[error("stream control sequence {sequence} is older than retained history {earliest}")]
    StaleControl { sequence: u64, earliest: u64 },
    #[error("stream control sequence is already bound to different bytes")]
    ControlConflict,
    #[error("stream credit update exceeds the configured maximum")]
    CreditOverflow,
    #[error("stream control sequence is exhausted")]
    SequenceExhausted,
    #[error("stream is already closed")]
    Closed,
    #[error("owner-open stream-window state lock is poisoned")]
    StatePoisoned,
}

pub type Result<T> = std::result::Result<T, StreamWindowError>;

/// Schema ceilings for stream credit and retained control history. A caller
/// may select smaller windows, but cannot turn a credit/history profile into
/// an unbounded counter or `VecDeque`.
pub const MAX_STREAM_CREDIT_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_STREAM_CHUNK_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_STREAM_CONTROL_HISTORY: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWindowConfig {
    pub initial_credit_bytes: u64,
    pub max_credit_bytes: u64,
    pub max_chunk_bytes: u64,
    pub max_control_history: usize,
}

impl Default for StreamWindowConfig {
    fn default() -> Self {
        Self {
            initial_credit_bytes: 256 * 1024,
            max_credit_bytes: 16 * 1024 * 1024,
            max_chunk_bytes: 1024 * 1024,
            max_control_history: 256,
        }
    }
}

impl StreamWindowConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_credit_bytes == 0
            || self.max_chunk_bytes == 0
            || self.max_control_history == 0
            || self.initial_credit_bytes > self.max_credit_bytes
            || self.max_chunk_bytes > self.max_credit_bytes
        {
            return Err(StreamWindowError::InvalidConfiguration(
                "credit, chunk and history bounds are inconsistent".to_string(),
            ));
        }
        if self.max_credit_bytes > MAX_STREAM_CREDIT_BYTES {
            return Err(StreamWindowError::InvalidConfiguration(format!(
                "max_credit_bytes exceeds hard bound {MAX_STREAM_CREDIT_BYTES}"
            )));
        }
        if self.max_chunk_bytes > MAX_STREAM_CHUNK_BYTES {
            return Err(StreamWindowError::InvalidConfiguration(format!(
                "max_chunk_bytes exceeds hard bound {MAX_STREAM_CHUNK_BYTES}"
            )));
        }
        if self.max_control_history > MAX_STREAM_CONTROL_HISTORY {
            return Err(StreamWindowError::InvalidConfiguration(format!(
                "max_control_history exceeds hard bound {MAX_STREAM_CONTROL_HISTORY}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamControl {
    WindowUpdate { credit_bytes: u64 },
    Pause,
    Resume,
    Close,
}

impl StreamControl {
    fn validate(&self, config: &StreamWindowConfig) -> Result<()> {
        if let Self::WindowUpdate { credit_bytes } = self
            && (*credit_bytes == 0 || *credit_bytes > config.max_credit_bytes)
        {
            return Err(StreamWindowError::InvalidRequest(
                "window update must be non-zero and no larger than max credit".to_string(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::WindowUpdate { .. } => "stream.window_update",
            Self::Pause => "stream.pause",
            Self::Resume => "stream.resume",
            Self::Close => "stream.close",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRecord {
    pub seq: u64,
    pub command: StreamControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyDisposition {
    Applied,
    Existing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyResult {
    pub disposition: ApplyDisposition,
    pub snapshot: StreamWindowSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockedReason {
    Paused,
    InsufficientCredit { available_credit_bytes: u64 },
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveDisposition {
    Granted {
        granted_bytes: u64,
        remaining_credit_bytes: u64,
    },
    Blocked(BlockedReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamWindowSnapshot {
    pub available_credit_bytes: u64,
    pub max_credit_bytes: u64,
    pub max_chunk_bytes: u64,
    pub paused: bool,
    pub closed: bool,
    pub total_granted_bytes: u64,
    pub earliest_control_seq: u64,
    pub next_control_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlHistory {
    pub records: Vec<ControlRecord>,
    pub inclusive_cursor: u64,
    pub next_cursor: u64,
    pub earliest_cursor: u64,
    pub latest_cursor: u64,
    pub has_more: bool,
}

#[derive(Debug)]
struct State {
    available_credit_bytes: u64,
    paused: bool,
    closed: bool,
    total_granted_bytes: u64,
    next_control_seq: u64,
    history: VecDeque<ControlRecord>,
}

#[derive(Debug)]
pub struct StreamWindow {
    config: StreamWindowConfig,
    state: Mutex<State>,
}

impl StreamWindow {
    pub fn new(config: StreamWindowConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            state: Mutex::new(State {
                available_credit_bytes: config.initial_credit_bytes,
                paused: false,
                closed: false,
                total_granted_bytes: 0,
                next_control_seq: 0,
                history: VecDeque::new(),
            }),
            config,
        })
    }

    pub fn apply_control(&self, seq: u64, command: StreamControl) -> Result<ApplyResult> {
        command.validate(&self.config)?;
        let mut state = self.lock()?;

        if seq < state.next_control_seq {
            if let Some(existing) = state.history.iter().find(|record| record.seq == seq) {
                if existing.command == command {
                    return Ok(ApplyResult {
                        disposition: ApplyDisposition::Existing,
                        snapshot: self.snapshot_locked(&state),
                    });
                }
                return Err(StreamWindowError::ControlConflict);
            }
            let earliest = state
                .history
                .front()
                .map_or(state.next_control_seq, |record| record.seq);
            return Err(StreamWindowError::StaleControl {
                sequence: seq,
                earliest,
            });
        }
        if seq > state.next_control_seq {
            return Err(StreamWindowError::SequenceGap {
                expected: state.next_control_seq,
                received: seq,
            });
        }
        if state.next_control_seq == u64::MAX {
            return Err(StreamWindowError::SequenceExhausted);
        }
        if state.closed && command != StreamControl::Close {
            return Err(StreamWindowError::Closed);
        }

        match command {
            StreamControl::WindowUpdate { credit_bytes } => {
                state.available_credit_bytes = state
                    .available_credit_bytes
                    .checked_add(credit_bytes)
                    .filter(|value| *value <= self.config.max_credit_bytes)
                    .ok_or(StreamWindowError::CreditOverflow)?;
            }
            StreamControl::Pause => state.paused = true,
            StreamControl::Resume => state.paused = false,
            StreamControl::Close => {
                state.closed = true;
                state.paused = true;
                state.available_credit_bytes = 0;
            }
        }

        let record = ControlRecord { seq, command };
        state.next_control_seq += 1;
        if state.history.len() == self.config.max_control_history {
            state.history.pop_front();
        }
        state.history.push_back(record);
        Ok(ApplyResult {
            disposition: ApplyDisposition::Applied,
            snapshot: self.snapshot_locked(&state),
        })
    }

    pub fn try_reserve(&self, bytes: u64) -> Result<ReserveDisposition> {
        if bytes == 0 || bytes > self.config.max_chunk_bytes {
            return Err(StreamWindowError::InvalidRequest(format!(
                "reservation must be between 1 and {} bytes",
                self.config.max_chunk_bytes
            )));
        }
        let mut state = self.lock()?;
        if state.closed {
            return Ok(ReserveDisposition::Blocked(BlockedReason::Closed));
        }
        if state.paused {
            return Ok(ReserveDisposition::Blocked(BlockedReason::Paused));
        }
        if state.available_credit_bytes < bytes {
            return Ok(ReserveDisposition::Blocked(
                BlockedReason::InsufficientCredit {
                    available_credit_bytes: state.available_credit_bytes,
                },
            ));
        }
        let total_granted_bytes =
            state
                .total_granted_bytes
                .checked_add(bytes)
                .ok_or_else(|| {
                    StreamWindowError::InvalidRequest(
                        "total granted byte counter overflow".to_string(),
                    )
                })?;
        state.available_credit_bytes -= bytes;
        state.total_granted_bytes = total_granted_bytes;
        Ok(ReserveDisposition::Granted {
            granted_bytes: bytes,
            remaining_credit_bytes: state.available_credit_bytes,
        })
    }

    pub fn control_history_from(
        &self,
        inclusive_cursor: u64,
        limit: usize,
    ) -> Result<ControlHistory> {
        if limit == 0 || limit > self.config.max_control_history {
            return Err(StreamWindowError::InvalidRequest(format!(
                "history limit must be between 1 and {}",
                self.config.max_control_history
            )));
        }
        let state = self.lock()?;
        let earliest = state
            .history
            .front()
            .map_or(state.next_control_seq, |record| record.seq);
        if inclusive_cursor < earliest {
            return Err(StreamWindowError::StaleControl {
                sequence: inclusive_cursor,
                earliest,
            });
        }
        if inclusive_cursor > state.next_control_seq {
            return Err(StreamWindowError::SequenceGap {
                expected: state.next_control_seq,
                received: inclusive_cursor,
            });
        }
        let records = state
            .history
            .iter()
            .filter(|record| record.seq >= inclusive_cursor)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_cursor = records
            .last()
            .map_or(inclusive_cursor, |record| record.seq.saturating_add(1));
        Ok(ControlHistory {
            records,
            inclusive_cursor,
            next_cursor,
            earliest_cursor: earliest,
            latest_cursor: state.next_control_seq,
            has_more: next_cursor < state.next_control_seq,
        })
    }

    pub fn snapshot(&self) -> Result<StreamWindowSnapshot> {
        let state = self.lock()?;
        Ok(self.snapshot_locked(&state))
    }

    fn snapshot_locked(&self, state: &State) -> StreamWindowSnapshot {
        StreamWindowSnapshot {
            available_credit_bytes: state.available_credit_bytes,
            max_credit_bytes: self.config.max_credit_bytes,
            max_chunk_bytes: self.config.max_chunk_bytes,
            paused: state.paused,
            closed: state.closed,
            total_granted_bytes: state.total_granted_bytes,
            earliest_control_seq: state
                .history
                .front()
                .map_or(state.next_control_seq, |record| record.seq),
            next_control_seq: state.next_control_seq,
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| StreamWindowError::StatePoisoned)
    }
}

impl Default for StreamWindow {
    fn default() -> Self {
        Self::new(StreamWindowConfig::default())
            .expect("default stream-window configuration is valid")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use super::*;

    fn config(initial: u64, max: u64, chunk: u64, history: usize) -> StreamWindowConfig {
        StreamWindowConfig {
            initial_credit_bytes: initial,
            max_credit_bytes: max,
            max_chunk_bytes: chunk,
            max_control_history: history,
        }
    }

    #[test]
    fn credit_pause_resume_and_close_are_exact() {
        let window = StreamWindow::new(config(5, 10, 5, 8)).unwrap();
        assert!(matches!(
            window.try_reserve(3).unwrap(),
            ReserveDisposition::Granted {
                remaining_credit_bytes: 2,
                ..
            }
        ));
        window.apply_control(0, StreamControl::Pause).unwrap();
        assert_eq!(
            window.try_reserve(1).unwrap(),
            ReserveDisposition::Blocked(BlockedReason::Paused)
        );
        window.apply_control(1, StreamControl::Resume).unwrap();
        window
            .apply_control(2, StreamControl::WindowUpdate { credit_bytes: 4 })
            .unwrap();
        assert_eq!(window.snapshot().unwrap().available_credit_bytes, 6);
        window.apply_control(3, StreamControl::Close).unwrap();
        assert_eq!(
            window.try_reserve(1).unwrap(),
            ReserveDisposition::Blocked(BlockedReason::Closed)
        );
    }

    #[test]
    fn duplicate_control_is_idempotent_but_drift_conflicts() {
        let window = StreamWindow::new(config(0, 10, 5, 8)).unwrap();
        let command = StreamControl::WindowUpdate { credit_bytes: 3 };
        assert_eq!(
            window
                .apply_control(0, command.clone())
                .unwrap()
                .disposition,
            ApplyDisposition::Applied
        );
        assert_eq!(
            window.apply_control(0, command).unwrap().disposition,
            ApplyDisposition::Existing
        );
        assert_eq!(
            window.apply_control(0, StreamControl::Pause).unwrap_err(),
            StreamWindowError::ControlConflict
        );
    }

    #[test]
    fn sequence_gap_and_trimmed_history_fail_without_mutation() {
        let window = StreamWindow::new(config(0, 10, 5, 2)).unwrap();
        assert!(matches!(
            window.apply_control(1, StreamControl::Pause),
            Err(StreamWindowError::SequenceGap { .. })
        ));
        window.apply_control(0, StreamControl::Pause).unwrap();
        window.apply_control(1, StreamControl::Resume).unwrap();
        window.apply_control(2, StreamControl::Pause).unwrap();
        assert!(matches!(
            window.apply_control(0, StreamControl::Pause),
            Err(StreamWindowError::StaleControl { earliest: 1, .. })
        ));
        let history = window.control_history_from(1, 1).unwrap();
        assert_eq!(history.next_cursor, 2);
        assert!(history.has_more);
    }

    #[test]
    fn concurrent_reservations_never_overdraw_credit() {
        let window = Arc::new(StreamWindow::new(config(100, 100, 1, 8)).unwrap());
        let granted = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let window = Arc::clone(&window);
            let granted = Arc::clone(&granted);
            workers.push(thread::spawn(move || {
                loop {
                    match window.try_reserve(1).unwrap() {
                        ReserveDisposition::Granted { .. } => {
                            granted.fetch_add(1, Ordering::SeqCst);
                        }
                        ReserveDisposition::Blocked(BlockedReason::InsufficientCredit {
                            ..
                        }) => break,
                        other => panic!("unexpected reservation result: {other:?}"),
                    }
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(granted.load(Ordering::SeqCst), 100);
        assert_eq!(window.snapshot().unwrap().available_credit_bytes, 0);
    }

    #[test]
    fn invalid_limits_and_credit_overflow_are_rejected_transactionally() {
        assert!(StreamWindow::new(config(2, 1, 1, 1)).is_err());
        let window = StreamWindow::new(config(9, 10, 5, 8)).unwrap();
        assert_eq!(
            window
                .apply_control(0, StreamControl::WindowUpdate { credit_bytes: 2 })
                .unwrap_err(),
            StreamWindowError::CreditOverflow
        );
        assert_eq!(window.snapshot().unwrap().next_control_seq, 0);
    }

    #[test]
    fn schema_ceilings_reject_unbounded_stream_profiles() {
        let oversized = [
            StreamWindowConfig {
                max_credit_bytes: MAX_STREAM_CREDIT_BYTES + 1,
                ..StreamWindowConfig::default()
            },
            StreamWindowConfig {
                max_chunk_bytes: MAX_STREAM_CHUNK_BYTES + 1,
                ..StreamWindowConfig::default()
            },
            StreamWindowConfig {
                max_control_history: MAX_STREAM_CONTROL_HISTORY + 1,
                ..StreamWindowConfig::default()
            },
        ];
        for config in oversized {
            assert!(
                StreamWindow::new(config).is_err(),
                "stream profile above schema ceiling must fail closed"
            );
        }
        StreamWindowConfig::default()
            .validate()
            .expect("default stream profile remains valid");
    }
}
