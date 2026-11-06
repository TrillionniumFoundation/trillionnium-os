mod base {
    #![allow(dead_code)]
    include!("r5_control_host_v2.rs");

    pub(crate) mod v4 {
        include!("r5_control_host_v4/entry.rs");
        include!("r5_control_host_v4/process.rs");
        include!("r5_control_host_v4/inspect_handlers.rs");
        include!("r5_control_host_v4/inspect_parse.rs");
        include!("r5_control_host_v4/inspect_encode.rs");

        pub(crate) mod jobs {
            use super::*;
            include!("r5_control_host_v7/imports.rs");
            include!("r5_control_host_v7/entry.rs");
            include!("r5_control_host_v7/wire.rs");
            include!("r5_control_host_v7/process.rs");
        }
    }
}

fn main() {
    if let Err(error) = trillionnium_owner_open_trace::configure_from_env("core") {
        eprintln!("trace configuration refused: {error}");
        std::process::exit(2);
    }
    let result = base::v4::jobs::run();
    if let Err(error) = trillionnium_owner_open_trace::export_from_env() {
        eprintln!("trace export unavailable: {error}");
        std::process::exit(2);
    }
    if let Err(error) = result {
        eprintln!("trillionnium-owner-open-r5-core: {error}");
        std::process::exit(2);
    }
}
