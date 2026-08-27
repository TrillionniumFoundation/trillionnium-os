use std::io::{BufReader, stdin, stdout};
use std::process::ExitCode;

fn main() -> ExitCode {
    if std::env::args_os().count() != 1 {
        eprintln!("fixed Codex System API stdio proxy accepts no arguments");
        return ExitCode::FAILURE;
    }
    let input = stdin();
    let output = stdout();
    match trillionnium_agent_stdio_proxy::run_proxy(
        BufReader::new(input.lock()),
        output.lock(),
        trillionnium_agent_stdio_proxy::CONTROL_FD,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Codex System API stdio proxy failed closed: {error:#}");
            ExitCode::FAILURE
        }
    }
}
