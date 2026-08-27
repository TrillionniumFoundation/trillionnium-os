fn main() {
    if let Err(error) =
        trillionnium_agent_direct_tools::operation_replay_sync::enter_measured_parent_stop()
            .and_then(|()| {
                trillionnium_agent_direct_tools::operation_replay_sync::run_system_api_one_shot()
            })
    {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
