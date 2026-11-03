//! Mechanism-only registry for owner-open long-running jobs.
//!
//! The registry binds one scoped job ID to one exact request, grants at most
//! one local spawn generation, records bounded lifecycle/control observations
//! and converts process restart into conservative uncertainty. It never
//! authorizes commands or automatically redispatches an uncertain effect.

mod registry;
mod types;
mod validate;

pub use registry::JobRegistry;
pub use types::*;
