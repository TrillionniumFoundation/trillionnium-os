use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use trillionnium_owner_open_host::{ConnectionEngine, HostError, UnavailableProvider};
use trillionnium_owner_open_types::MechanicalLimits;

static CONNECTION_ORDINAL: AtomicU64 = AtomicU64::new(1);

fn main() {
    if let Err(error) = run() {
        eprintln!("trillionnium-owner-open-host: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [] => serve_stdio(),
        [flag] if flag == "--stdio" => serve_stdio(),
        [flag, path] if flag == "--unix" => serve_unix(Path::new(path)),
        _ => Err(
            "usage: trillionnium-owner-open-host [--stdio | --unix /absolute/socket/path]"
                .to_string(),
        ),
    }
}

fn serve_stdio() -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    process_connection(
        BufReader::new(stdin.lock()),
        stdout.lock(),
        new_connection_id(),
    )
}

fn serve_unix(path: &Path) -> Result<(), String> {
    validate_socket_path(path)?;
    if path.exists() {
        return Err(format!(
            "refusing to replace existing socket path {}; remove a proven stale entry explicitly",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| "Unix socket path has no parent".to_string())?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect socket parent {}: {error}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err("Unix socket parent must be a real directory".to_string());
    }
    let listener = UnixListener::bind(path)
        .map_err(|error| format!("cannot bind Unix socket {}: {error}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("cannot set Unix socket mode on {}: {error}", path.display()))?;
    for accepted in listener.incoming() {
        match accepted {
            Ok(stream) => {
                if let Err(error) = serve_stream(stream) {
                    eprintln!("owner-open connection closed: {error}");
                }
            }
            Err(error) => eprintln!("owner-open accept failed: {error}"),
        }
    }
    Ok(())
}

fn serve_stream(stream: UnixStream) -> Result<(), String> {
    let writer = stream
        .try_clone()
        .map_err(|error| format!("cannot clone Unix stream: {error}"))?;
    process_connection(BufReader::new(stream), writer, new_connection_id())
}

fn process_connection<R: BufRead, W: Write>(
    mut reader: R,
    mut writer: W,
    connection_id: String,
) -> Result<(), String> {
    let limits = MechanicalLimits::default();
    let mut engine = ConnectionEngine::new(connection_id, UnavailableProvider::default())
        .map_err(|error| error.to_string())?
        .with_limits(limits.clone());
    loop {
        let Some(frame) = read_bounded_frame(&mut reader, limits.max_frame_bytes)? else {
            return Ok(());
        };
        match engine.handle_encoded(&frame) {
            Ok(output) => {
                for frame in output {
                    write_frame(&mut writer, &frame, limits.max_frame_bytes)?;
                }
            }
            Err(error) => {
                let response = engine.error_frame(&error);
                write_frame(&mut writer, &response, limits.max_frame_bytes)?;
            }
        }
    }
}

fn read_bounded_frame<R: BufRead>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> Result<Option<Vec<u8>>, String> {
    let mut frame = Vec::new();
    let read = reader
        .take(max_frame_bytes as u64 + 2)
        .read_until(b'\n', &mut frame)
        .map_err(|error| format!("failed to read frame: {error}"))?;
    if read == 0 {
        return Ok(None);
    }
    if frame.last() != Some(&b'\n') {
        return Err("frame is not newline terminated or exceeds the configured bound".to_string());
    }
    frame.pop();
    if frame.is_empty() || frame.len() > max_frame_bytes {
        return Err("frame is empty or exceeds the configured bound".to_string());
    }
    Ok(Some(frame))
}

fn write_frame<W: Write>(
    writer: &mut W,
    frame: &impl serde::Serialize,
    max_frame_bytes: usize,
) -> Result<(), String> {
    let encoded = serde_json::to_vec(frame)
        .map_err(|error| format!("failed to encode response frame: {error}"))?;
    if encoded.is_empty() || encoded.len() > max_frame_bytes {
        return Err("response frame is empty or exceeds the configured bound".to_string());
    }
    writer
        .write_all(&encoded)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("failed to write response frame: {error}"))
}

fn validate_socket_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("Unix socket path must be absolute".to_string());
    }
    if path.as_os_str().as_bytes().first() == Some(&b'@') {
        return Err(
            "Android abstract sockets require the W6 Android carrier; use --stdio or a filesystem UDS in the foundation build"
                .to_string(),
        );
    }
    if path.as_os_str().as_bytes().len() > 100 {
        return Err("Unix socket path exceeds the portable byte bound".to_string());
    }
    Ok(())
}

fn new_connection_id() -> String {
    let ordinal = CONNECTION_ORDINAL.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("connection-{}-{nanos}-{ordinal}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::io::Cursor;

    #[test]
    fn stdio_protocol_emits_hello_ack_and_honest_provider_hold() {
        let input = concat!(
            "{\"kind\":\"hello\",\"seq\":0,\"payload\":{}}\n",
            "{\"kind\":\"turn.start\",\"seq\":1,\"payload\":{",
            "\"protocol\":\"trillionnium.agent.turn.v1\",",
            "\"protocol_version\":1,",
            "\"session_id\":\"session-1\",",
            "\"task_id\":\"task-1\",",
            "\"turn_id\":\"turn-1\",",
            "\"user_input\":\"pwd\"}}\n"
        );
        let mut output = Vec::new();
        process_connection(
            BufReader::new(Cursor::new(input.as_bytes())),
            &mut output,
            "connection-test".to_string(),
        )
        .unwrap();
        let frames = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(frames[0]["kind"], "hello.ack");
        assert_eq!(frames[1]["kind"], "turn.accepted");
        assert_eq!(frames.last().unwrap()["kind"], "turn.end");
        assert_eq!(
            frames.last().unwrap()["payload"]["status"],
            "provider_unavailable"
        );
    }

    #[test]
    fn oversized_or_unterminated_frames_are_rejected() {
        let mut reader = BufReader::new(Cursor::new(b"abcd"));
        assert!(read_bounded_frame(&mut reader, 3).is_err());
    }

    #[test]
    fn foundation_refuses_to_guess_an_android_abstract_socket() {
        assert!(validate_socket_path(Path::new("@abstract")).is_err());
        assert!(validate_socket_path(Path::new("relative.sock")).is_err());
        assert!(validate_socket_path(Path::new("/tmp/owner-open.sock")).is_ok());
    }
}
