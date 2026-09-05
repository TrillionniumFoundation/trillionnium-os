use crate::{JobRegistryError, JobTerminal, Result};

pub(crate) fn invalid(message: impl Into<String>) -> JobRegistryError {
    JobRegistryError::InvalidRequest(message.into())
}

pub(crate) fn require_id(value: &str, label: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid(format!("{label} is empty, oversized or malformed")));
    }
    Ok(())
}

pub(crate) fn require_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid(format!("{label} must be a lowercase SHA-256")));
    }
    Ok(())
}

pub(crate) fn require_text(
    value: &str,
    label: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(invalid(format!("{label} is empty, oversized or malformed")));
    }
    Ok(())
}

pub(crate) fn validate_terminal(terminal: &JobTerminal) -> Result<()> {
    require_text(&terminal.terminal_kind, "terminal_kind", 128, false)?;
    require_sha256(&terminal.observation_sha256, "observation_sha256")?;
    if terminal.exit_code.is_some() && terminal.signal.is_some() {
        return Err(invalid("terminal cannot contain exit_code and signal"));
    }
    if terminal
        .signal
        .is_some_and(|signal| !(1..=128).contains(&signal))
    {
        return Err(invalid("terminal signal is outside the supported range"));
    }
    Ok(())
}
