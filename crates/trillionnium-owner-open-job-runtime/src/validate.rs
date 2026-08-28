use crate::{JobRuntimeError, Result};

pub(crate) fn require_id(value: &str, label: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(JobRuntimeError::InvalidRequest(format!(
            "{label} is empty, oversized or malformed"
        )));
    }
    Ok(())
}

pub(crate) fn require_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(JobRuntimeError::InvalidRequest(format!(
            "{label} must be a lowercase SHA-256"
        )));
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
        return Err(JobRuntimeError::InvalidRequest(format!(
            "{label} is empty, oversized or malformed"
        )));
    }
    Ok(())
}
