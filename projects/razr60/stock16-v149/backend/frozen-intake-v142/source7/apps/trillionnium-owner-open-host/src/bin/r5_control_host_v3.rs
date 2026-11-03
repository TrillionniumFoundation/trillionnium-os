#![allow(unused_must_use)]

// The bounded stdin/control reader intentionally lives for the process
// lifetime. Channel closure is its shutdown signal; the selected Host does not
// join a thread that may be blocked in a kernel stdin read during normal exit.
include!("r5_control_host_v2.rs");
