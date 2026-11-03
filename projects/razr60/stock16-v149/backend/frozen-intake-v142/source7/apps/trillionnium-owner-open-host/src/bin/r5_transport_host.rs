#![allow(dead_code, unused_imports, unused_must_use)]

#[path = "../r5_persistence.rs"]
mod r5_persistence;

mod transport {
    include!("r5_transport_host/entry.rs");
    include!("r5_transport_host/protocol.rs");
    include!("r5_transport_host/flow.rs");
    include!("r5_transport_host/journal.rs");
    include!("r5_transport_host/process.rs");
}

fn main() {
    if let Err(error) = transport::run() {
        eprintln!("trillionnium-owner-open-r5-host: {error}");
        std::process::exit(2);
    }
}
