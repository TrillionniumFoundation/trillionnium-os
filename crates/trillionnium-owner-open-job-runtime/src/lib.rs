//! Direct owner-open runtime for long-running pipe and PTY jobs.
//!
//! Effects are request-bound and operation-bound. Durable operation acceptance
//! is recorded before start/write/resize/close/kill effects when a journal is
//! available. A pre-existing nonterminal operation is never redispatched after
//! restart; it is reported as uncertain for explicit inspection.

mod event_store_adapter;
mod journal {
    // Bind the journal implementation to the narrow reopen adapter without
    // changing its public surface or the event-store contract used elsewhere.
    use crate::event_store_adapter as trillionnium_owner_open_event_store;

    include!("journal.rs");
}
mod manager;
mod process;
mod types;
mod validate;

pub use journal::{JOB_JOURNAL_SCHEMA, JobJournal, JournalStatus, OperationBegin, RecoveredJob};
pub use manager::JobManager;
pub use types::*;
