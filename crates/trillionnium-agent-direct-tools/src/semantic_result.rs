//! Canonical, adapter-authored backend-result identities.
//!
//! The durable operation journal retains and hashes the exact backend response
//! bytes for byte-identical replay.  Evidence crossing the adapter boundary
//! uses the separate digest defined here: request/replay identity and the two
//! OS-authored digest carrier fields are removed, object keys are recursively
//! sorted, and the resulting semantic JSON is hashed in an explicit domain.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    DirectToolError, OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD, OS_RAW_BACKEND_RESULT_SHA256_FIELD,
    Result, valid_request_id,
};

pub const CANONICAL_SEMANTIC_RESULT_DOMAIN_V1: &[u8] =
    b"trillionnium.direct-backend-semantic-result.v1";
const MAX_CANONICAL_JSON_DEPTH: usize = 64;
const MAX_CANONICAL_JSON_NODES: usize = 65_536;

/// Encode JSON with recursively sorted object keys and no insignificant
/// whitespace. Array order and every scalar value remain significant.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    fn encode(value: &Value, output: &mut Vec<u8>, depth: usize, nodes: &mut usize) -> Result<()> {
        *nodes = nodes.saturating_add(1);
        if depth > MAX_CANONICAL_JSON_DEPTH || *nodes > MAX_CANONICAL_JSON_NODES {
            return Err(DirectToolError::BackendFailed(
                "canonical backend-result JSON exceeded its structural bound".to_string(),
            ));
        }
        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                output.extend_from_slice(&serde_json::to_vec(value)?);
            }
            Value::Array(values) => {
                output.push(b'[');
                for (index, child) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    encode(child, output, depth + 1, nodes)?;
                }
                output.push(b']');
            }
            Value::Object(object) => {
                output.push(b'{');
                let mut keys = object.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    output.extend_from_slice(&serde_json::to_vec(key)?);
                    output.push(b':');
                    encode(&object[key], output, depth + 1, nodes)?;
                }
                output.push(b'}');
            }
        }
        Ok(())
    }

    let mut bytes = Vec::new();
    let mut nodes = 0;
    encode(value, &mut bytes, 0, &mut nodes)?;
    Ok(bytes)
}

/// Hash canonical JSON without adding an adapter/result domain. This is
/// exported so every direct MCP result canonicalizer uses exactly one JSON
/// algorithm rather than carrying a subtly different local implementation.
pub fn canonical_json_sha256(value: &Value) -> Result<String> {
    Ok(lower_sha256(&canonical_json_bytes(value)?))
}

/// Compute the canonical semantic identity of one already validated System
/// API or Accessibility backend response.
///
/// `request_id` is excluded because its hash is carried independently as the
/// backend request identity. The exact raw response digest remains independent
/// journal/replay evidence. Both OS-authored carrier fields are excluded so
/// inserting them does not make this digest self-referential.
pub fn canonical_semantic_result_sha256(response: &Value) -> Result<String> {
    let object = response.as_object().ok_or_else(|| {
        DirectToolError::BackendFailed(
            "canonical backend semantic result must be an object".to_string(),
        )
    })?;
    let protocol = object
        .get("protocol")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            DirectToolError::BackendFailed(
                "canonical backend semantic result omitted protocol".to_string(),
            )
        })?;
    if !matches!(
        protocol,
        crate::system_api::PROTOCOL | crate::accessibility::PROTOCOL
    ) {
        return Err(DirectToolError::BackendFailed(
            "canonical backend semantic result protocol is not a closed direct adapter".to_string(),
        ));
    }
    let request_id = object
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|value| valid_request_id(value))
        .ok_or_else(|| {
            DirectToolError::BackendFailed(
                "canonical backend semantic result request_id is malformed".to_string(),
            )
        })?;
    let _ = request_id;
    crate::validate_backend_outcome(response)?;

    let mut semantic = object.clone();
    semantic.remove("request_id");
    semantic.remove(OS_RAW_BACKEND_RESULT_SHA256_FIELD);
    semantic.remove(OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD);
    let canonical = canonical_json_bytes(&Value::Object(semantic))?;

    let mut hasher = Sha256::new();
    hash_field(&mut hasher, CANONICAL_SEMANTIC_RESULT_DOMAIN_V1);
    hash_field(&mut hasher, &canonical);
    Ok(lower_hex(&hasher.finalize()))
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn lower_sha256(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(ALPHABET[(byte >> 4) as usize] as char);
        encoded.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_package_success_and_typed_error_are_format_stable() {
        for (compact, reordered, golden) in [
            (
                br#"{"protocol":"org.trillionnium.agent-system-api.v1","request_id":"op:00112233445566778899aabbccddeeff:1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ok":true}"#.as_slice(),
                br#"{
                    "ok" : true,
                    "request_id" : "op:00112233445566778899aabbccddeeff:1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "protocol" : "org.trillionnium.agent-system-api.v1"
                }"#.as_slice(),
                "9b8d295653814c2c4666f6f8d4287d1658766993cbb911fb4996f715f63c17f0",
            ),
            (
                br#"{"protocol":"org.trillionnium.agent-system-api.v1","request_id":"op:00112233445566778899aabbccddeeff:1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","ok":false,"error":"request_id_conflict","retry_with_same_id":false}"#.as_slice(),
                br#"{ "retry_with_same_id" : false, "error" : "request_id_conflict", "ok" : false, "request_id" : "op:00112233445566778899aabbccddeeff:1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "protocol" : "org.trillionnium.agent-system-api.v1" }"#.as_slice(),
                "d98dbfaf56bc5b0a67df60c0f94c366c9d2a31a594aacbfde4068ac5acfe3f74",
            ),
        ] {
            let compact_value: Value = serde_json::from_slice(compact).unwrap();
            let reordered_value: Value = serde_json::from_slice(reordered).unwrap();
            assert_ne!(lower_sha256(compact), lower_sha256(reordered));
            let compact_digest = canonical_semantic_result_sha256(&compact_value).unwrap();
            assert_eq!(compact_digest, golden);
            assert_eq!(
                compact_digest,
                canonical_semantic_result_sha256(&reordered_value).unwrap()
            );
        }
    }

    #[test]
    fn request_identity_and_os_digest_carriers_are_not_semantic_result_material() {
        let first = serde_json::json!({
            "protocol": crate::system_api::PROTOCOL,
            "request_id": "request-one",
            "ok": true,
        });
        let mut second = serde_json::json!({
            "ok": true,
            "request_id": "request-two",
            "protocol": crate::system_api::PROTOCOL,
        });
        second.as_object_mut().unwrap().insert(
            OS_RAW_BACKEND_RESULT_SHA256_FIELD.to_string(),
            Value::String("a".repeat(64)),
        );
        second.as_object_mut().unwrap().insert(
            OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD.to_string(),
            Value::String("b".repeat(64)),
        );
        assert_eq!(
            canonical_semantic_result_sha256(&first).unwrap(),
            canonical_semantic_result_sha256(&second).unwrap()
        );
    }
}
