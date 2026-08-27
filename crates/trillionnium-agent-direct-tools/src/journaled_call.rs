//! Shared durable-before-effect execution for trusted direct adapters.

use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use crate::operation_journal::{
    OperationJournal, OperationJournalError, PreparedOperation, Sha256Digest,
};
use crate::uds::{CapturedBackendCall, ExpectedBackendPeer};
use crate::{BackendCompletion, DirectToolError, Result};

pub(crate) fn execute<T, V>(
    path: &Path,
    peer: ExpectedBackendPeer,
    backend_request: &T,
    journal: &mut OperationJournal,
    prepared: &PreparedOperation,
    validate_response: V,
) -> Result<Value>
where
    T: Serialize,
    V: FnOnce(&Value) -> Result<()>,
{
    if let Some(exact_response) = journal
        .replay_terminal_result(prepared)
        .map_err(journal_error)?
    {
        let mut value = serde_json::from_slice(&exact_response).map_err(|error| {
            DirectToolError::BackendFailed(format!(
                "durable terminal result JSON failed closed: {error}"
            ))
        })?;
        validate_response(&value)?;
        bind_os_backend_result_sha256s(&mut value, &exact_response)?;
        return Ok(value);
    }
    let serialized_request = match serde_json::to_vec(backend_request) {
        Ok(serialized) => serialized,
        Err(error) => {
            let error = DirectToolError::Json(error);
            record_failure(journal, prepared, &[], &error)?;
            return Err(error);
        }
    };
    match crate::uds::call_captured(path, peer, &serialized_request) {
        CapturedBackendCall::Response {
            exact_response,
            mut value,
        } => {
            if let Err(error) = validate_response(&value) {
                record_failure(journal, prepared, &exact_response, &error)?;
                return Err(error);
            }
            journal
                .record_result(prepared, &exact_response, BackendCompletion::Response)
                .map_err(journal_error)?;
            bind_os_backend_result_sha256s(&mut value, &exact_response)?;
            Ok(value)
        }
        CapturedBackendCall::Failure {
            exact_response,
            error,
        } => {
            record_failure(journal, prepared, &exact_response, &error)?;
            Err(error)
        }
    }
}

fn bind_os_backend_result_sha256s(value: &mut Value, exact_response: &[u8]) -> Result<()> {
    let semantic_result_sha256 = crate::semantic_result::canonical_semantic_result_sha256(value)?;
    let object = value.as_object_mut().ok_or_else(|| {
        DirectToolError::BackendFailed("validated backend response is not an object".to_string())
    })?;
    if object.contains_key(crate::OS_RAW_BACKEND_RESULT_SHA256_FIELD)
        || object.contains_key(crate::OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD)
    {
        return Err(DirectToolError::BackendFailed(
            "backend response attempted to author an OS result digest".to_string(),
        ));
    }
    object.insert(
        crate::OS_RAW_BACKEND_RESULT_SHA256_FIELD.to_string(),
        Value::String(Sha256Digest::of_bytes(exact_response).to_hex()),
    );
    object.insert(
        crate::OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD.to_string(),
        Value::String(semantic_result_sha256),
    );
    Ok(())
}

fn record_failure(
    journal: &mut OperationJournal,
    prepared: &PreparedOperation,
    exact_response: &[u8],
    error: &DirectToolError,
) -> Result<()> {
    journal
        .record_result(prepared, exact_response, BackendCompletion::Failure(error))
        .map(|_| ())
        .map_err(journal_error)
}

pub(crate) fn journal_error(error: OperationJournalError) -> DirectToolError {
    DirectToolError::BackendFailed(format!("trusted operation journal failed closed: {error}"))
}
