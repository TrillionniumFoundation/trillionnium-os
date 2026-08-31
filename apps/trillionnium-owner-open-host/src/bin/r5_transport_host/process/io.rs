fn spawn_core(
    options: &Options,
) -> Result<(Child, Option<ChildStdin>, ChildStdout, std::process::ChildStderr), String> {
    let mut command = Command::new(&options.core);
    command
        .args(&options.core_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot spawn core Host {}: {error}", options.core.display()))?;
    let stdin = child.stdin.take();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "core Host stdout was not piped".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "core Host stderr was not piped".to_string())?;
    Ok((child, stdin, stdout, stderr))
}

fn spawn_core_waiter(mut child: Child, sender: SyncSender<TransportMessage>) {
    thread::Builder::new()
        .name("owner-open-transport-core-waiter".to_string())
        .spawn(move || {
            let result = child
                .wait()
                .map_err(|error| format!("cannot wait for core Host: {error}"));
            let _ = sender.send(TransportMessage::CoreExited(result));
        })
        .expect("spawn transport core waiter");
}

fn terminate_core_process_group(pid: u32) -> Result<(), String> {
    let process_group = i32::try_from(pid)
        .map_err(|_| format!("core Host pid {pid} does not fit a process-group id"))?;
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(format!(
            "cannot terminate descendants in core Host process group {process_group}: {error}"
        ))
    }
}

fn spawn_client_reader(sender: SyncSender<TransportMessage>, max_frame_bytes: usize) {
    thread::Builder::new()
        .name("owner-open-transport-client-reader".to_string())
        .spawn(move || {
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin.lock());
            loop {
                match read_bounded_line(&mut reader, max_frame_bytes) {
                    Ok(Some(frame)) => {
                        if sender.send(TransportMessage::ClientFrame(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = sender.send(TransportMessage::ClientEof);
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(TransportMessage::ClientError(error));
                        return;
                    }
                }
            }
        })
        .expect("spawn transport client reader");
}

fn spawn_core_reader(
    stdout: ChildStdout,
    sender: SyncSender<TransportMessage>,
    max_frame_bytes: usize,
) {
    thread::Builder::new()
        .name("owner-open-transport-core-reader".to_string())
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_bounded_line(&mut reader, max_frame_bytes) {
                    Ok(Some(frame)) => {
                        if sender.send(TransportMessage::CoreFrame(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = sender.send(TransportMessage::CoreEof);
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(TransportMessage::CoreError(error));
                        return;
                    }
                }
            }
        })
        .expect("spawn transport core reader");
}

fn spawn_stderr_drain(stderr: std::process::ChildStderr) {
    thread::Builder::new()
        .name("owner-open-transport-core-stderr".to_string())
        .spawn(move || {
            let mut output = io::stderr().lock();
            let _ = io::copy(&mut stderr.take(1024 * 1024), &mut output);
        })
        .expect("spawn core stderr drain");
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    max_frame_bytes: usize,
) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    let read = reader
        .take(max_frame_bytes as u64 + 2)
        .read_until(b'\n', &mut line)
        .map_err(|error| error.to_string())?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        return Err("frame is not newline terminated or exceeds its bound".to_string());
    }
    line.pop();
    if line.is_empty() || line.len() > max_frame_bytes {
        return Err("frame is empty or exceeds its bound".to_string());
    }
    Ok(Some(line))
}
