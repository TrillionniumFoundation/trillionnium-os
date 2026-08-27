use std::env;

use trillionnium_agent_privilege_broker::{
    ANDROID_INIT_LISTENER_ENVIRONMENT, LinuxPeerInspector, SingleClientGate, accept_client,
    fixed_android_listener_from_environment, harden_current_process,
    parse_expected_peer_from_environment, serve_authenticated_client, take_inherited_listener,
    validate_inherited_fd_inventory, validate_selected_inherited_listener,
    verify_current_capabilities,
};

fn main() {
    if run().is_err() {
        // Startup denial is deliberately silent: stdio is untrusted until the
        // inherited-FD inventory proves it is not a non-Unix socket.
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let android_listener = fixed_android_listener_from_environment(env::vars_os())?;
    let listener = take_inherited_listener(&arguments, android_listener, || {
        // SAFETY: this runs during single-threaded startup, before any thread
        // or library worker can concurrently inspect or mutate the process
        // environment.
        unsafe { env::remove_var(ANDROID_INIT_LISTENER_ENVIRONMENT) };
    })?;
    let listener_fd = listener.raw_fd();
    validate_inherited_fd_inventory(listener_fd)?;
    verify_current_capabilities()?;
    validate_selected_inherited_listener(&listener)?;
    let policy = parse_expected_peer_from_environment()?;
    harden_current_process()?;
    verify_current_capabilities()?;
    clear_startup_environment();
    validate_inherited_fd_inventory(listener_fd)?;

    // The v2 foundation accepts exactly one client per process lifetime. A supervised
    // restart is required for a fresh session, so a queued second connection
    // can never become an authenticated peer after the first disconnects.
    let mut client_gate = SingleClientGate::default();
    client_gate.acquire()?;
    let client_fd = accept_client(listener_fd)?;
    let result = serve_authenticated_client(client_fd, &LinuxPeerInspector, &policy);
    unsafe { libc::close(client_fd) };
    result?;
    Ok(())
}

fn clear_startup_environment() {
    let names = env::vars_os().map(|(name, _)| name).collect::<Vec<_>>();
    for name in names {
        // SAFETY: this remains in the single-threaded startup path, before any
        // library worker or provider child exists. Future exec paths must build
        // a closed environment instead of inheriting launcher authority.
        unsafe { env::remove_var(name) };
    }
}
