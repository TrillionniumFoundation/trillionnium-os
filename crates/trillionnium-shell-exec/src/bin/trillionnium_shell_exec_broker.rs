fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let outcome = match arguments.as_slice() {
        [] => trillionnium_shell_exec::product_broker::run(),
        [flag] if flag == "--cleanup-stale-only" => {
            trillionnium_shell_exec::product_broker::run_cleanup_stale_only()
        }
        _ => {
            eprintln!(
                "shell exec broker rejected invalid arguments; only --cleanup-stale-only is accepted"
            );
            std::process::exit(2);
        }
    };
    if let Err(error) = outcome {
        eprintln!("shell exec broker failed closed: {error}");
        std::process::exit(1);
    }
}
