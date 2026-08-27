fn main() {
    if let Err(error) =
        trillionnium_agent_direct_tools::device_launch_package_conformance::run_system_api()
    {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
