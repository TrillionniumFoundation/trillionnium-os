fn main() {
    if let Err(error) = trillionnium_shell_exec::product_worker::run() {
        eprintln!("shell exec worker failed closed: {error}");
        std::process::exit(1);
    }
}
