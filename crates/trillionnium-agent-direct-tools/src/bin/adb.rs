#[cfg(feature = "dev-overrides")]
use std::path::Path;

#[cfg(feature = "dev-overrides")]
use trillionnium_agent_direct_tools::production_endpoint;
use trillionnium_agent_direct_tools::{adb, read_request, write_response};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> trillionnium_agent_direct_tools::Result<()> {
    let request = read_request()?;
    #[cfg(feature = "dev-overrides")]
    let response = {
        let adb_path = production_endpoint(adb::DEFAULT_ADB_EXECUTABLE, "TRILLIONNIUM_ADB_PATH");
        adb::execute_development(Path::new(&adb_path), &request)?
    };
    #[cfg(not(feature = "dev-overrides"))]
    let response = adb::execute_production(&request)?;
    write_response(&response)
}
