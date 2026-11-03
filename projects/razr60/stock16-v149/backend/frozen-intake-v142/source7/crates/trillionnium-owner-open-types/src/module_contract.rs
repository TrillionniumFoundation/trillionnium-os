use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{MechanicalLimits, ProtocolError, decode_strict_value};

pub const MODULE_CONTRACT_VERSION: u32 = 1;
pub const MAX_MODULE_CONTRACT_JSON_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MODULE_CONTRACT_JSON_DEPTH: usize = 32;
pub const MAX_MODULE_CONTRACT_ID_BYTES: usize = 256;
pub const MAX_MODULE_CONTRACT_KEY_BYTES: usize = 512;
pub const MAX_MODULE_CONTRACT_CAUSE_BYTES: usize = 4096;
pub const MAX_MODULE_CONTRACT_PAYLOAD_PROPERTIES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleLifecycleStateV1 {
    Received,
    Validated,
    CapacityReserved,
    AcceptedDurable,
    EffectAttempting,
    EffectStartedObserved,
    TerminalObserved,
    TerminalDurable,
    DeliveryPending,
    Delivered,
    Acknowledged,
    RejectedBeforeEffect,
    UnknownReconciliationRequired,
    Fenced,
    Closed,
    Stateless,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleErrorClassV1 {
    RejectedBeforeEffect,
    TransientBeforeEffect,
    EffectUncertain,
    TerminalFailure,
    InternalInvariant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleRetryDispositionV1 {
    MayRetryBeforeEffect,
    ReconcileRequiredNoAutomaticRedispatch,
    DoNotRetry,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleApiEnvelopeV1 {
    pub schema: String,
    pub module_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub ordering_key: String,
    pub host_epoch: u64,
    pub writer_epoch: u64,
    pub fencing_token: String,
    pub payload: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleStateEnvelopeV1 {
    pub schema: String,
    pub module_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub state: ModuleLifecycleStateV1,
    pub host_epoch: u64,
    pub writer_epoch: u64,
    pub fencing_token: String,
    pub durable_sequence: u64,
    pub monotonic_ns: u64,
    pub payload: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleErrorEnvelopeV1 {
    pub schema: String,
    pub module_id: String,
    pub operation_id: String,
    pub request_digest: String,
    pub code: String,
    pub class: ModuleErrorClassV1,
    pub retry_disposition: ModuleRetryDispositionV1,
    pub effect_uncertain: bool,
    pub original_cause: String,
}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::InvalidFrame(message.into())
}

pub fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn validate_depth(value: &Value, depth: usize) -> Result<(), ProtocolError> {
    if depth > MAX_MODULE_CONTRACT_JSON_DEPTH {
        return Err(invalid("module contract exceeds JSON depth bound"));
    }
    match value {
        Value::Array(values) => {
            for value in values {
                validate_depth(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_depth(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn strict_value(encoded: &[u8]) -> Result<Value, ProtocolError> {
    let limits = MechanicalLimits {
        max_frame_bytes: MAX_MODULE_CONTRACT_JSON_BYTES,
        ..MechanicalLimits::default()
    };
    let value = decode_strict_value(encoded, &limits)?;
    validate_depth(&value, 1)?;
    Ok(value)
}

fn validate_common(
    schema: &str,
    module_id: &str,
    operation_id: &str,
    request_digest: &str,
    expected_schema: &str,
    expected_module_id: &str,
) -> Result<(), ProtocolError> {
    if schema != expected_schema {
        return Err(invalid("module contract schema identity differs"));
    }
    if module_id != expected_module_id || !module_id.starts_with("MOD-") {
        return Err(invalid("module contract module identity differs"));
    }
    if !valid_text(operation_id, MAX_MODULE_CONTRACT_ID_BYTES) {
        return Err(invalid("module contract operation identity is invalid"));
    }
    if !is_lower_hex_64(request_digest) {
        return Err(invalid("module contract request digest is invalid"));
    }
    Ok(())
}

fn validate_payload(payload: &Value) -> Result<(), ProtocolError> {
    match payload {
        Value::Object(values) if values.len() <= MAX_MODULE_CONTRACT_PAYLOAD_PROPERTIES => Ok(()),
        Value::Object(_) => Err(invalid("module contract payload has too many properties")),
        _ => Err(invalid("module contract payload must be an object")),
    }
}

impl ModuleApiEnvelopeV1 {
    pub fn validate_binding(
        &self,
        expected_schema: &str,
        expected_module_id: &str,
    ) -> Result<(), ProtocolError> {
        validate_common(
            &self.schema,
            &self.module_id,
            &self.operation_id,
            &self.request_digest,
            expected_schema,
            expected_module_id,
        )?;
        if !valid_text(&self.ordering_key, MAX_MODULE_CONTRACT_KEY_BYTES)
            || !valid_text(&self.fencing_token, MAX_MODULE_CONTRACT_KEY_BYTES)
        {
            return Err(invalid(
                "module contract ordering or fencing identity is invalid",
            ));
        }
        validate_payload(&self.payload)
    }
}

impl ModuleStateEnvelopeV1 {
    pub fn validate_binding(
        &self,
        expected_schema: &str,
        expected_module_id: &str,
    ) -> Result<(), ProtocolError> {
        validate_common(
            &self.schema,
            &self.module_id,
            &self.operation_id,
            &self.request_digest,
            expected_schema,
            expected_module_id,
        )?;
        if !valid_text(&self.fencing_token, MAX_MODULE_CONTRACT_KEY_BYTES) {
            return Err(invalid("module contract fencing identity is invalid"));
        }
        validate_payload(&self.payload)
    }
}

impl ModuleErrorEnvelopeV1 {
    pub fn validate_binding(
        &self,
        expected_schema: &str,
        expected_module_id: &str,
    ) -> Result<(), ProtocolError> {
        validate_common(
            &self.schema,
            &self.module_id,
            &self.operation_id,
            &self.request_digest,
            expected_schema,
            expected_module_id,
        )?;
        if !valid_text(&self.code, 128)
            || !valid_text(&self.original_cause, MAX_MODULE_CONTRACT_CAUSE_BYTES)
        {
            return Err(invalid("module contract error fields are invalid"));
        }
        let uncertain = matches!(self.class, ModuleErrorClassV1::EffectUncertain);
        let reconcile = matches!(
            self.retry_disposition,
            ModuleRetryDispositionV1::ReconcileRequiredNoAutomaticRedispatch
        );
        if uncertain != self.effect_uncertain || reconcile != self.effect_uncertain {
            return Err(invalid("effect uncertainty and retry disposition differ"));
        }
        Ok(())
    }
}

pub fn parse_module_api(encoded: &[u8]) -> Result<ModuleApiEnvelopeV1, ProtocolError> {
    serde_json::from_value(strict_value(encoded)?)
        .map_err(|error| invalid(format!("invalid module API envelope: {error}")))
}

pub fn parse_module_state(encoded: &[u8]) -> Result<ModuleStateEnvelopeV1, ProtocolError> {
    serde_json::from_value(strict_value(encoded)?)
        .map_err(|error| invalid(format!("invalid module state envelope: {error}")))
}

pub fn parse_module_error(encoded: &[u8]) -> Result<ModuleErrorEnvelopeV1, ProtocolError> {
    serde_json::from_value(strict_value(encoded)?)
        .map_err(|error| invalid(format!("invalid module error envelope: {error}")))
}
