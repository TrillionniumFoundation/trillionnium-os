use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use std::{io, io::Write as _};

// The inherited-pipe fixture deliberately lets its descendant outlive the
// immediate process so the supervisor test can prove cgroup/process-tree
// cleanup. Waiting here would destroy the condition under test.
#[allow(clippy::zombie_processes)]
fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "spawn-inherited-descendant" => {
            let executable = std::env::current_exe().expect("fixture executable");
            Command::new(executable)
                .arg("hold-inherited-pipes")
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn inherited-pipe fixture");
        }
        "hold-inherited-pipes" => thread::sleep(Duration::from_secs(10)),
        "emit-binary" => {
            io::stdout().write_all(&[0xff, 0x00, 0xfe]).unwrap();
            io::stderr().write_all(&[0x80, 0x00]).unwrap();
        }
        _ => std::process::exit(64),
    }
}
