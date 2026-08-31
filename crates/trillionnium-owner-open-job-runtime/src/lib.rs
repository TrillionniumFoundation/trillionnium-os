//! Direct owner-open runtime for long-running pipe and PTY jobs.
//!
//! Effects are request-bound and operation-bound. Durable operation acceptance
//! is recorded before start/write/resize/close/kill effects when a journal is
//! available. A pre-existing nonterminal operation is never redispatched after
//! restart; it is reported as uncertain for explicit inspection.

mod journal;
mod manager;
mod process;
mod types;
mod validate;

pub use journal::{JOB_JOURNAL_SCHEMA, JobJournal, JournalStatus, OperationBegin, RecoveredJob};
pub use manager::JobManager;
pub use types::*;
