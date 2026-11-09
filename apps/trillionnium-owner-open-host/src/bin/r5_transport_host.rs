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
    if let Err(error) = trillionnium_owner_open_trace::configure_from_env("transport") {
        eprintln!("trace configuration refused: {error}");
        std::process::exit(2);
    }
    let result = transport::run();
    if let Err(error) = trillionnium_owner_open_trace::export_from_env() {
        eprintln!("trace export unavailable: {error}");
        std::process::exit(2);
    }
    if let Err(error) = result {
        eprintln!("trillionnium-owner-open-r5-host: {error}");
        std::process::exit(2);
    }
}
