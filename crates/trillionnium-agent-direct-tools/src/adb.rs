#[cfg(any(test, feature = "dev-overrides"))]
use std::ffi::OsString;
#[cfg(feature = "dev-overrides")]
use std::fs;
#[cfg(any(test, feature = "dev-overrides"))]
use std::io::Read;
#[cfg(feature = "dev-overrides")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(any(test, feature = "dev-overrides"))]
use std::os::unix::io::AsRawFd;
#[cfg(any(test, feature = "dev-overrides"))]
use std::path::{Component, Path};
#[cfg(any(test, feature = "dev-overrides"))]
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;
#[cfg(any(test, feature = "dev-overrides"))]
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::{DirectToolError, Result, valid_request_id};

#[cfg(any(test, feature = "dev-overrides"))]
mod linux_ffi {
    pub const F_GETFL: i32 = 3;
    pub const F_SETFL: i32 = 4;
    pub const O_NONBLOCK: i32 = 0o4000;

    unsafe extern "C" {
        pub fn fcntl(fd: i32, command: i32, ...) -> i32;
        #[cfg(feature = "dev-overrides")]
        pub fn geteuid() -> u32;
    }
}

pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_ADB_EXECUTABLE: &str = "/usr/lib/android-sdk/platform-tools/adb";
pub const ENG_USERDEBUG_ENABLE_TOKEN: &str = "trillionnium-adb-eng-userdebug-v1";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdbBuildType {
    Eng,
    Userdebug,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdbRequest {
    Devices {
        version: u32,
        request_id: String,
        build_type: AdbBuildType,
        enable_token: String,
    },
    Shell {
        version: u32,
        request_id: String,
        build_type: AdbBuildType,
        enable_token: String,
        serial: String,
        argv: Vec<String>,
    },
    Push {
        version: u32,
        request_id: String,
        build_type: AdbBuildType,
        enable_token: String,
        serial: String,
        local: String,
        remote: String,
    },
    Pull {
        version: u32,
        request_id: String,
        build_type: AdbBuildType,
        enable_token: String,
        serial: String,
        remote: String,
        local: String,
    },
    Install {
        version: u32,
        request_id: String,
        build_type: AdbBuildType,
        enable_token: String,
        serial: String,
        apk: String,
        replace: bool,
    },
    Reboot {
        version: u32,
        request_id: String,
        build_type: AdbBuildType,
        enable_token: String,
        serial: String,
        target: Option<AdbRebootTarget>,
    },
}

impl AdbRequest {
    fn version(&self) -> u32 {
        match self {
            Self::Devices { version, .. }
            | Self::Shell { version, .. }
            | Self::Push { version, .. }
            | Self::Pull { version, .. }
            | Self::Install { version, .. }
            | Self::Reboot { version, .. } => *version,
        }
    }

    fn request_id(&self) -> &str {
        match self {
            Self::Devices { request_id, .. }
            | Self::Shell { request_id, .. }
            | Self::Push { request_id, .. }
            | Self::Pull { request_id, .. }
            | Self::Install { request_id, .. }
            | Self::Reboot { request_id, .. } => request_id,
        }
    }

    fn enable_token(&self) -> &str {
        match self {
            Self::Devices { enable_token, .. }
            | Self::Shell { enable_token, .. }
            | Self::Push { enable_token, .. }
            | Self::Pull { enable_token, .. }
            | Self::Install { enable_token, .. }
            | Self::Reboot { enable_token, .. } => enable_token,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdbRebootTarget {
    Bootloader,
    Recovery,
    Sideload,
    SideloadAutoReboot,
}

impl AdbRebootTarget {
    #[cfg(any(test, feature = "dev-overrides"))]
    fn as_str(&self) -> &'static str {
        match self {
            Self::Bootloader => "bootloader",
            Self::Recovery => "recovery",
            Self::Sideload => "sideload",
            Self::SideloadAutoReboot => "sideload-auto-reboot",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AdbResponse {
    pub version: u32,
    pub request_id: String,
    pub ok: bool,
    pub backend: &'static str,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Product builds fail closed until a same-device adbd transport, its build
/// property proof, and its key custody are defined. Merely finding a host adb
/// executable is not sufficient evidence that the Agent is controlling its own
/// Android instance.
pub fn execute_production(request: &AdbRequest) -> Result<AdbResponse> {
    validate_request(request)?;
    Err(DirectToolError::BackendUnavailable(format!(
        "device-local ADB transport is undefined; fixed executable {DEFAULT_ADB_EXECUTABLE} was not started"
    )))
}

#[cfg(any(test, feature = "dev-overrides"))]
pub fn command(adb: &Path, request: &AdbRequest) -> Result<Command> {
    validate_request(request)?;
    validate_adb_executable_path(adb)?;
    let mut command = Command::new(adb);
    match request {
        AdbRequest::Devices { .. } => {
            command.arg("devices");
        }
        AdbRequest::Shell { serial, argv, .. } => {
            serial_args(&mut command, serial)?;
            validate_argv(argv)?;
            command.arg("shell").args(argv);
        }
        AdbRequest::Push {
            serial,
            local,
            remote,
            ..
        } => {
            serial_args(&mut command, serial)?;
            validate_transfer_path(local, "local push path")?;
            validate_transfer_path(remote, "remote push path")?;
            command.args(["push", local, remote]);
        }
        AdbRequest::Pull {
            serial,
            remote,
            local,
            ..
        } => {
            serial_args(&mut command, serial)?;
            validate_transfer_path(remote, "remote pull path")?;
            validate_transfer_path(local, "local pull path")?;
            command.args(["pull", remote, local]);
        }
        AdbRequest::Install {
            serial,
            apk,
            replace,
            ..
        } => {
            serial_args(&mut command, serial)?;
            validate_transfer_path(apk, "APK path")?;
            if !apk.ends_with(".apk") {
                return Err(DirectToolError::InvalidRequest(
                    "install path must end in .apk".to_string(),
                ));
            }
            command.arg("install");
            if *replace {
                command.arg("-r");
            }
            command.arg(apk);
        }
        AdbRequest::Reboot { serial, target, .. } => {
            serial_args(&mut command, serial)?;
            command.arg("reboot");
            if let Some(target) = target {
                command.arg(target.as_str());
            }
        }
    }
    command.env_clear();
    Ok(command)
}

#[cfg(feature = "dev-overrides")]
pub fn execute_development(adb: &Path, request: &AdbRequest) -> Result<AdbResponse> {
    validate_adb_executable_file(adb)?;
    execute_command(command(adb, request)?, request, DEFAULT_TIMEOUT)
}

fn validate_request(request: &AdbRequest) -> Result<()> {
    if request.version() != PROTOCOL_VERSION {
        return Err(DirectToolError::InvalidRequest(format!(
            "ADB version must be {PROTOCOL_VERSION}"
        )));
    }
    if !valid_request_id(request.request_id()) {
        return Err(DirectToolError::InvalidRequest(
            "invalid ADB request_id".to_string(),
        ));
    }
    if request.enable_token() != ENG_USERDEBUG_ENABLE_TOKEN {
        return Err(DirectToolError::InvalidRequest(
            "missing exact eng/userdebug ADB enable token".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(test, feature = "dev-overrides"))]
fn validate_adb_executable_path(adb: &Path) -> Result<()> {
    if !adb.is_absolute()
        || adb.as_os_str().as_encoded_bytes().is_empty()
        || adb.as_os_str().as_encoded_bytes().len() > 4096
        || adb
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(DirectToolError::InvalidRequest(
            "adb executable must be a normalized absolute path".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "dev-overrides")]
fn validate_adb_executable_file(adb: &Path) -> Result<()> {
    validate_adb_executable_path(adb)?;
    let metadata = fs::symlink_metadata(adb).map_err(|error| {
        DirectToolError::BackendUnavailable(format!("cannot inspect adb executable: {error}"))
    })?;
    // SAFETY: geteuid has no arguments and no memory preconditions.
    let current_uid = unsafe { linux_ffi::geteuid() };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
        || (metadata.uid() != 0 && metadata.uid() != current_uid)
    {
        return Err(DirectToolError::BackendUnavailable(
            "adb executable is not an owner-controlled regular executable".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(test, feature = "dev-overrides"))]
fn serial_args(command: &mut Command, serial: &str) -> Result<()> {
    if serial.is_empty()
        || serial.len() > 128
        || serial.starts_with('-')
        || !serial.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'[' | b']')
        })
    {
        return Err(DirectToolError::InvalidRequest(
            "invalid adb serial".to_string(),
        ));
    }
    command.args(["-s", serial]);
    Ok(())
}

#[cfg(any(test, feature = "dev-overrides"))]
fn validate_argv(argv: &[String]) -> Result<()> {
    let total_bytes = argv.iter().try_fold(0_usize, |total, argument| {
        total.checked_add(argument.len()).ok_or(())
    });
    if argv.is_empty()
        || argv.len() > 256
        || total_bytes.is_err()
        || total_bytes.is_ok_and(|bytes| bytes > 64 * 1024)
        || argv.iter().any(|argument| {
            argument.len() > 16_384 || argument.chars().any(|character| character.is_control())
        })
    {
        return Err(DirectToolError::InvalidRequest(
            "invalid adb shell argv".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(test, feature = "dev-overrides"))]
fn validate_transfer_path(value: &str, field: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.chars().any(|character| character.is_control())
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(DirectToolError::InvalidRequest(format!(
            "{field} must be a normalized absolute non-option path"
        )));
    }
    Ok(())
}

#[cfg(any(test, feature = "dev-overrides"))]
fn execute_command(
    mut command: Command,
    request: &AdbRequest,
    timeout: Duration,
) -> Result<AdbResponse> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        DirectToolError::BackendUnavailable(format!("cannot start adb: {error}"))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        DirectToolError::BackendFailed("adb stdout pipe is unavailable".to_string())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        DirectToolError::BackendFailed("adb stderr pipe is unavailable".to_string())
    })?;
    set_nonblocking(&stdout)?;
    set_nonblocking(&stderr)?;
    let mut stdout = Some(stdout);
    let mut stderr = Some(stderr);
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let started = Instant::now();
    let mut status = None;
    loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        pump_output(&mut stdout, &mut stdout_bytes)?;
        pump_output(&mut stderr, &mut stderr_bytes)?;
        if stdout_bytes.len() > MAX_OUTPUT_BYTES || stderr_bytes.len() > MAX_OUTPUT_BYTES {
            if status.is_none() {
                child.kill()?;
                let _ = child.wait();
            }
            return Err(DirectToolError::BackendFailed(format!(
                "adb output exceeds {MAX_OUTPUT_BYTES} bytes"
            )));
        }
        if let Some(status) = status
            && stdout.is_none()
            && stderr.is_none()
        {
            let response = response(request, status, stdout_bytes, stderr_bytes);
            if !response.ok {
                return Err(DirectToolError::BackendFailed(format!(
                    "adb command exited unsuccessfully with code {}",
                    response.exit_code
                )));
            }
            return Ok(response);
        }
        if started.elapsed() >= timeout {
            if status.is_none() {
                if let Err(error) = child.kill()
                    && error.kind() != std::io::ErrorKind::InvalidInput
                {
                    return Err(error.into());
                }
                let _ = child.wait();
            }
            return Err(DirectToolError::BackendTimedOut(format!(
                "adb exceeded {} ms",
                timeout.as_millis()
            )));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(any(test, feature = "dev-overrides"))]
fn set_nonblocking(file: &impl AsRawFd) -> Result<()> {
    let descriptor = file.as_raw_fd();
    // SAFETY: descriptor is borrowed from a live pipe and F_GETFL takes no
    // variadic argument.
    let flags = unsafe { linux_ffi::fcntl(descriptor, linux_ffi::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor remains live and F_SETFL consumes one integer flag
    // argument as required by fcntl(2).
    let set_result = unsafe {
        linux_ffi::fcntl(
            descriptor,
            linux_ffi::F_SETFL,
            flags | linux_ffi::O_NONBLOCK,
        )
    };
    if set_result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(any(test, feature = "dev-overrides"))]
fn pump_output<R: Read>(reader: &mut Option<R>, output: &mut Vec<u8>) -> Result<()> {
    let Some(pipe) = reader.as_mut() else {
        return Ok(());
    };
    loop {
        let remaining = MAX_OUTPUT_BYTES
            .saturating_add(1)
            .saturating_sub(output.len());
        if remaining == 0 {
            return Ok(());
        }
        let mut buffer = [0_u8; 16 * 1024];
        let wanted = buffer.len().min(remaining);
        match pipe.read(&mut buffer[..wanted]) {
            Ok(0) => {
                reader.take();
                return Ok(());
            }
            Ok(read) => output.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(any(test, feature = "dev-overrides"))]
fn response(
    request: &AdbRequest,
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> AdbResponse {
    AdbResponse {
        version: PROTOCOL_VERSION,
        request_id: request.request_id().to_string(),
        ok: status.success(),
        backend: "adb",
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

#[cfg(any(test, feature = "dev-overrides"))]
pub fn command_argv(command: &Command) -> Vec<OsString> {
    std::iter::once(command.get_program().to_os_string())
        .chain(command.get_args().map(|argument| argument.to_os_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn devices() -> AdbRequest {
        AdbRequest::Devices {
            version: PROTOCOL_VERSION,
            request_id: "req-adb-1".to_string(),
            build_type: AdbBuildType::Userdebug,
            enable_token: ENG_USERDEBUG_ENABLE_TOKEN.to_string(),
        }
    }

    fn shell(argv: Vec<String>) -> AdbRequest {
        AdbRequest::Shell {
            version: PROTOCOL_VERSION,
            request_id: "req-adb-1".to_string(),
            build_type: AdbBuildType::Userdebug,
            enable_token: ENG_USERDEBUG_ENABLE_TOKEN.to_string(),
            serial: "ZY32JLVHGN".to_string(),
            argv,
        }
    }

    fn push(local: &str, remote: &str) -> AdbRequest {
        AdbRequest::Push {
            version: PROTOCOL_VERSION,
            request_id: "req-adb-1".to_string(),
            build_type: AdbBuildType::Userdebug,
            enable_token: ENG_USERDEBUG_ENABLE_TOKEN.to_string(),
            serial: "device-1".to_string(),
            local: local.to_string(),
            remote: remote.to_string(),
        }
    }

    fn pull(remote: &str, local: &str) -> AdbRequest {
        AdbRequest::Pull {
            version: PROTOCOL_VERSION,
            request_id: "req-adb-1".to_string(),
            build_type: AdbBuildType::Userdebug,
            enable_token: ENG_USERDEBUG_ENABLE_TOKEN.to_string(),
            serial: "device-1".to_string(),
            remote: remote.to_string(),
            local: local.to_string(),
        }
    }

    #[test]
    fn shell_is_direct_argv_not_host_shell() {
        let command = command(
            Path::new("/usr/bin/adb"),
            &shell(vec![
                "input".to_string(),
                "tap".to_string(),
                "10".to_string(),
                "20".to_string(),
            ]),
        )
        .unwrap();
        assert_eq!(
            command_argv(&command),
            [
                "/usr/bin/adb",
                "-s",
                "ZY32JLVHGN",
                "shell",
                "input",
                "tap",
                "10",
                "20"
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn requires_exact_enable_token_absolute_executable_and_paths() {
        let mut missing_token = devices();
        if let AdbRequest::Devices { enable_token, .. } = &mut missing_token {
            *enable_token = "wrong".to_string();
        }
        assert!(command(Path::new("/usr/bin/adb"), &missing_token).is_err());
        assert!(command(Path::new("adb"), &devices()).is_err());
        assert!(
            command(
                Path::new("/usr/bin/adb"),
                &push("-p", "/data/local/tmp/file"),
            )
            .is_err()
        );
        assert!(
            command(
                Path::new("/usr/bin/adb"),
                &pull("/sdcard/../data/private", "/tmp/file"),
            )
            .is_err()
        );
    }

    #[test]
    fn production_transport_is_honestly_unavailable() {
        let error = execute_production(&devices()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("device-local ADB transport is undefined")
        );
    }

    #[test]
    fn bounded_process_execution_times_out() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 1"]);
        let error = execute_command(command, &devices(), Duration::from_millis(30)).unwrap_err();
        assert!(matches!(error, DirectToolError::BackendTimedOut(_)));
    }

    #[test]
    fn bounded_process_rejects_oversized_output() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "head -c 1048577 /dev/zero"]);
        let error = execute_command(command, &devices(), Duration::from_secs(2)).unwrap_err();
        assert!(error.to_string().contains("output exceeds"));
    }

    #[test]
    fn descendant_that_holds_a_pipe_cannot_extend_the_deadline() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "(sleep 0.2) & exit 0"]);
        let error = execute_command(command, &devices(), Duration::from_millis(30)).unwrap_err();
        assert!(matches!(error, DirectToolError::BackendTimedOut(_)));
    }

    #[test]
    fn unsuccessful_adb_exit_is_never_a_success_response() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf denied >&2; exit 7"]);
        let error = execute_command(command, &devices(), Duration::from_secs(2)).unwrap_err();
        assert!(matches!(error, DirectToolError::BackendFailed(_)));
        assert!(error.to_string().contains("code 7"));
    }
}
