use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use crate::types::{
    AdbExecRequest, EnvironmentDelta, MechanicalLimits, ProcessSpec, Result, RuntimeError,
    ShellExecRequest, ShellInvocation, ToolKind,
};

pub(crate) fn shell_spec(
    request: ShellExecRequest,
    limits: &MechanicalLimits,
) -> Result<ProcessSpec> {
    limits.validate()?;
    validate_common_request(
        &request.call_id,
        request.target_id.as_deref(),
        request.cwd.as_ref(),
        &request.env,
        &request.stdin,
        limits,
    )?;

    let (program, args) = match &request.invocation {
        ShellInvocation::Command(command) => {
            validate_scalar(
                command,
                "shell command",
                limits.max_total_argument_bytes,
                false,
            )?;
            validate_os_value(
                request.shell_executable.as_os_str(),
                "shell executable",
                limits.max_cwd_bytes,
                false,
            )?;
            (
                request.shell_executable.clone().into_os_string(),
                vec![OsString::from("-c"), OsString::from(command)],
            )
        }
        ShellInvocation::Argv(argv) => {
            validate_argv(argv, limits, "shell argv")?;
            (
                OsString::from(&argv[0]),
                argv[1..].iter().map(OsString::from).collect(),
            )
        }
    };

    Ok(ProcessSpec {
        call_id: request.call_id,
        target_id: request.target_id,
        tool: ToolKind::ShellExec,
        program,
        args,
        cwd: request.cwd,
        env: request.env,
        stdin: request.stdin,
        timeout: normalized_timeout(request.timeout, limits),
    })
}

pub(crate) fn adb_spec(request: AdbExecRequest, limits: &MechanicalLimits) -> Result<ProcessSpec> {
    limits.validate()?;
    validate_common_request(
        &request.call_id,
        request.target_id.as_deref(),
        request.cwd.as_ref(),
        &request.env,
        &request.stdin,
        limits,
    )?;
    validate_argv(&request.argv, limits, "adb argv")?;
    validate_os_value(
        request.adb_executable.as_os_str(),
        "adb executable",
        limits.max_cwd_bytes,
        false,
    )?;

    Ok(ProcessSpec {
        call_id: request.call_id,
        target_id: request.target_id,
        tool: ToolKind::AdbExec,
        program: request.adb_executable.into_os_string(),
        args: request.argv.into_iter().map(OsString::from).collect(),
        cwd: request.cwd,
        env: request.env,
        stdin: request.stdin,
        timeout: normalized_timeout(request.timeout, limits),
    })
}

fn normalized_timeout(timeout: Option<Duration>, limits: &MechanicalLimits) -> Duration {
    timeout
        .filter(|value| !value.is_zero())
        .unwrap_or(limits.default_timeout)
}

fn validate_common_request(
    call_id: &str,
    target_id: Option<&str>,
    cwd: Option<&PathBuf>,
    env: &EnvironmentDelta,
    stdin: &[u8],
    limits: &MechanicalLimits,
) -> Result<()> {
    if call_id.is_empty()
        || call_id.len() > limits.max_call_id_bytes
        || !call_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid("call_id is empty, oversized, or malformed"));
    }
    if let Some(target_id) = target_id {
        validate_scalar(target_id, "target_id", limits.max_target_id_bytes, false)?;
    }
    if let Some(cwd) = cwd {
        validate_os_value(cwd.as_os_str(), "cwd", limits.max_cwd_bytes, false)?;
    }
    if stdin.len() > limits.max_stdin_bytes {
        return Err(invalid("stdin exceeds the configured byte bound"));
    }
    if env.len() > limits.max_environment_items {
        return Err(invalid("environment delta has too many entries"));
    }

    let mut environment_bytes = 0usize;
    for (key, value) in env {
        if key.is_empty() || key.contains('=') || key.as_bytes().contains(&0) {
            return Err(invalid("environment key is empty or malformed"));
        }
        environment_bytes = environment_bytes
            .checked_add(key.len())
            .ok_or_else(|| invalid("environment byte count overflow"))?;
        if let Some(value) = value {
            if value.as_bytes().contains(&0) {
                return Err(invalid("environment value contains NUL"));
            }
            environment_bytes = environment_bytes
                .checked_add(value.len())
                .ok_or_else(|| invalid("environment byte count overflow"))?;
        }
    }
    if environment_bytes > limits.max_environment_bytes {
        return Err(invalid(
            "environment delta exceeds the configured byte bound",
        ));
    }
    Ok(())
}

fn validate_argv(argv: &[String], limits: &MechanicalLimits, field: &str) -> Result<()> {
    if argv.is_empty() {
        return Err(invalid(format!("{field} must not be empty")));
    }
    if argv.len() > limits.max_argv_items {
        return Err(invalid(format!("{field} has too many elements")));
    }
    let mut total = 0usize;
    for argument in argv {
        validate_scalar(argument, field, limits.max_argument_bytes, true)?;
        total = total
            .checked_add(argument.len())
            .ok_or_else(|| invalid(format!("{field} byte count overflow")))?;
    }
    if total > limits.max_total_argument_bytes {
        return Err(invalid(format!("{field} exceeds the total byte bound")));
    }
    Ok(())
}

fn validate_scalar(value: &str, field: &str, max_bytes: usize, allow_empty: bool) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > max_bytes
        || value.as_bytes().contains(&0)
    {
        return Err(invalid(format!(
            "{field} is empty, oversized, or contains NUL"
        )));
    }
    Ok(())
}

fn validate_os_value(
    value: &OsStr,
    field: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<()> {
    let bytes = value.as_bytes();
    if (!allow_empty && bytes.is_empty()) || bytes.len() > max_bytes || bytes.contains(&0) {
        return Err(invalid(format!(
            "{field} is empty, oversized, or contains NUL"
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> RuntimeError {
    RuntimeError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ShellExecRequest;

    #[test]
    fn invalid_requests_are_rejected_before_acceptance() {
        let limits = MechanicalLimits::default();
        let error =
            shell_spec(ShellExecRequest::argv("call-empty", Vec::new()), &limits).unwrap_err();
        assert!(error.to_string().contains("must not be empty"));
    }

    #[test]
    fn zero_request_timeout_uses_owner_default() {
        let limits = MechanicalLimits::default();
        assert_eq!(
            normalized_timeout(Some(Duration::ZERO), &limits),
            limits.default_timeout
        );
    }
}
