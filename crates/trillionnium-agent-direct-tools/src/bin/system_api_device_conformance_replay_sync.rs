fn main() {
    if let Err(error) =
        trillionnium_agent_direct_tools::operation_replay_sync::enter_measured_parent_stop()
    {
        eprintln!("{error}");
        std::process::exit(2);
    }
    if let Err(error) = trillionnium_agent_direct_tools::
        device_launch_package_conformance_replay_sync::run_system_api_replay_sync()
    {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
