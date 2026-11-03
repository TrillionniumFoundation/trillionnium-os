#![allow(dead_code, unused_imports, unused_must_use)]

// Keep the previous active-control carrier as an implementation module while
// selecting a wire layer that adds read-only turn/call inspection.
#[allow(dead_code, unused_imports, unused_must_use)]
mod base {
    include!("r5_control_host_v2.rs");

    pub(crate) mod v4 {
        include!("r5_control_host_v4/entry.rs");
        include!("r5_control_host_v4/process.rs");
        include!("r5_control_host_v4/inspect_handlers.rs");
        include!("r5_control_host_v4/inspect_parse.rs");
        include!("r5_control_host_v4/inspect_encode.rs");
    }
}

fn main() {
    if let Err(error) = base::v4::run() {
        eprintln!("trillionnium-owner-open-r5-host: {error}");
        std::process::exit(2);
    }
}
