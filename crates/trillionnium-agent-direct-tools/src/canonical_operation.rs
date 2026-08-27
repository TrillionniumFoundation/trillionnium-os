//! Cross-language canonical request bytes used by reserved durable operation IDs.
//!
//! The Android backends already persist and verify these identities. The trusted
//! Rust adapter must hash the exact same peer-bound bytes before it creates an
//! `op:<epoch>:<sequence>:<sha256>` request ID. Epoch and sequence stay in the
//! trusted journal; neither is accepted from MCP/model request JSON.

use crate::accessibility::{
    AccessibilityBatchAction, AccessibilityRequest, GesturePoint, GlobalAction, ScrollDirection,
};
use crate::risk_guard::AgentIdentity;
use crate::system_api::SystemApiRequest;
use crate::{DirectToolError, Result};

mod contract {
    include!("canonical_operation_contract.rs");
}

pub(crate) fn system_api_request(
    agent: AgentIdentity,
    request: &SystemApiRequest,
) -> Result<Vec<u8>> {
    let (action, user, target) = match request {
        SystemApiRequest::LaunchPackage { package, user, .. } => {
            ("launch_package", *user, package.as_str())
        }
        SystemApiRequest::OpenUri { uri, user, .. } => ("open_uri", *user, uri.as_str()),
    };
    if crate::system_api::PROTOCOL != contract::SYSTEM_API_PROTOCOL {
        return Err(contract_drift("System API protocol"));
    }
    let user = user.to_string();
    let fields = [
        contract::SYSTEM_API_IDENTITY_VERSION,
        replay_namespace(agent),
        contract::SYSTEM_API_PROTOCOL,
        action,
        user.as_str(),
        target,
    ];
    let capacity = fields
        .iter()
        .try_fold(fields.len() - 1, |total, field| {
            total.checked_add(field.len())
        })
        .ok_or_else(|| canonical_too_large("System API"))?;
    let mut output = Vec::with_capacity(capacity);
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            output.push(0);
        }
        output.extend_from_slice(field.as_bytes());
    }
    Ok(output)
}

pub(crate) fn accessibility_request(
    agent: AgentIdentity,
    request: &AccessibilityRequest,
) -> Result<Vec<u8>> {
    if crate::accessibility::PROTOCOL != contract::ACCESSIBILITY_PROTOCOL {
        return Err(contract_drift("Accessibility protocol"));
    }
    let mut output = Vec::with_capacity(4096);
    write_string(&mut output, contract::ACCESSIBILITY_IDENTITY_VERSION)?;
    write_string(&mut output, replay_namespace(agent))?;
    write_string(&mut output, contract::ACCESSIBILITY_PROTOCOL)?;
    match request {
        AccessibilityRequest::Snapshot {
            window_id,
            snapshot_mode,
            ..
        } => {
            write_string(&mut output, "snapshot")?;
            write_string(&mut output, snapshot_mode.as_str())?;
            output.push(u8::from(window_id.is_some()));
            if let Some(window_id) = window_id {
                output.extend_from_slice(&window_id.to_be_bytes());
            }
        }
        AccessibilityRequest::Click { node_id, .. } => {
            write_string(&mut output, "click")?;
            write_string(&mut output, node_id)?;
        }
        AccessibilityRequest::SetText { node_id, text, .. } => {
            write_string(&mut output, "set_text")?;
            write_string(&mut output, node_id)?;
            write_string(&mut output, text)?;
        }
        AccessibilityRequest::Scroll {
            node_id, direction, ..
        } => {
            write_string(&mut output, "scroll")?;
            write_string(&mut output, node_id)?;
            write_string(&mut output, scroll_direction(direction))?;
        }
        AccessibilityRequest::GlobalAction { global_action, .. } => {
            write_string(&mut output, "global_action")?;
            write_string(&mut output, global_action_name(global_action))?;
        }
        AccessibilityRequest::Gesture {
            points,
            duration_ms,
            ..
        } => write_gesture(&mut output, points, *duration_ms)?,
        AccessibilityRequest::Batch { actions, .. } => {
            write_string(&mut output, "batch")?;
            write_count(&mut output, actions.len(), "Accessibility batch")?;
            for action in actions {
                write_batch_action(&mut output, action)?;
            }
        }
    }
    if output.is_empty() || output.len() > crate::MAX_REQUEST_BYTES {
        return Err(canonical_too_large("Accessibility"));
    }
    Ok(output)
}

fn write_batch_action(output: &mut Vec<u8>, action: &AccessibilityBatchAction) -> Result<()> {
    match action {
        AccessibilityBatchAction::Click { node_id } => {
            write_string(output, "click")?;
            write_string(output, node_id)
        }
        AccessibilityBatchAction::SetText { node_id, text } => {
            write_string(output, "set_text")?;
            write_string(output, node_id)?;
            write_string(output, text)
        }
        AccessibilityBatchAction::Scroll { node_id, direction } => {
            write_string(output, "scroll")?;
            write_string(output, node_id)?;
            write_string(output, scroll_direction(direction))
        }
        AccessibilityBatchAction::GlobalAction { global_action } => {
            write_string(output, "global_action")?;
            write_string(output, global_action_name(global_action))
        }
        AccessibilityBatchAction::Gesture {
            points,
            duration_ms,
        } => write_gesture(output, points, *duration_ms),
    }
}

fn write_gesture(output: &mut Vec<u8>, points: &[GesturePoint], duration_ms: u64) -> Result<()> {
    write_string(output, "gesture")?;
    output.extend_from_slice(&duration_ms.to_be_bytes());
    write_count(output, points.len(), "Accessibility gesture")?;
    for point in points {
        output.extend_from_slice(&point.x.to_bits().to_be_bytes());
        output.extend_from_slice(&point.y.to_bits().to_be_bytes());
        output.extend_from_slice(&point.at_ms.to_be_bytes());
    }
    Ok(())
}

fn write_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| canonical_too_large("string"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn write_count(output: &mut Vec<u8>, value: usize, kind: &'static str) -> Result<()> {
    let value = u32::try_from(value).map_err(|_| canonical_too_large(kind))?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

const fn replay_namespace(agent: AgentIdentity) -> &'static str {
    match agent {
        AgentIdentity::Codex => contract::CODEX_REPLAY_NAMESPACE,
    }
}

const fn scroll_direction(direction: &ScrollDirection) -> &'static str {
    match direction {
        ScrollDirection::Forward => "forward",
        ScrollDirection::Backward => "backward",
        ScrollDirection::Up => "up",
        ScrollDirection::Down => "down",
        ScrollDirection::Left => "left",
        ScrollDirection::Right => "right",
    }
}

const fn global_action_name(action: &GlobalAction) -> &'static str {
    match action {
        GlobalAction::Back => "back",
        GlobalAction::Home => "home",
        GlobalAction::Recents => "recents",
        GlobalAction::Notifications => "notifications",
        GlobalAction::QuickSettings => "quick_settings",
        GlobalAction::PowerDialog => "power_dialog",
        GlobalAction::LockScreen => "lock_screen",
        GlobalAction::TakeScreenshot => "take_screenshot",
    }
}

fn canonical_too_large(kind: &str) -> DirectToolError {
    DirectToolError::InvalidRequest(format!("{kind} canonical operation identity is too large"))
}

fn contract_drift(kind: &str) -> DirectToolError {
    DirectToolError::BackendUnavailable(format!(
        "{kind} canonical operation contract drifted from the compiled binding"
    ))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    use super::*;

    const CONTRACT_BYTES: &[u8] =
        include_bytes!("../contracts/canonical-operation-binding-v1.json");

    #[derive(Deserialize)]
    struct GoldenContract {
        schema: String,
        fixed_epoch: String,
        agents: GoldenAgents,
        system_api: GoldenAdapter,
        accessibility: GoldenAdapter,
        vectors: Vec<GoldenVector>,
    }

    #[derive(Deserialize)]
    struct GoldenAgents {
        codex: String,
    }

    #[derive(Deserialize)]
    struct GoldenAdapter {
        protocol: String,
        identity_version: String,
    }

    #[derive(Deserialize)]
    struct GoldenVector {
        name: String,
        adapter: String,
        agent: String,
        sequence: u64,
        request: Value,
        canonical_hex: String,
        canonical_sha256: String,
        operation_id: String,
    }

    #[test]
    fn machine_readable_contract_and_generated_constants_are_exact() {
        let contract: GoldenContract = serde_json::from_slice(CONTRACT_BYTES).unwrap();
        assert_eq!(contract.schema, contract::CONTRACT_SCHEMA);
        assert_eq!(
            hex(Sha256::digest(CONTRACT_BYTES)),
            contract::CONTRACT_SHA256
        );
        assert_eq!(contract.agents.codex, contract::CODEX_REPLAY_NAMESPACE);
        assert_eq!(contract.system_api.protocol, contract::SYSTEM_API_PROTOCOL);
        assert_eq!(
            contract.system_api.identity_version,
            contract::SYSTEM_API_IDENTITY_VERSION
        );
        assert_eq!(
            contract.accessibility.protocol,
            contract::ACCESSIBILITY_PROTOCOL
        );
        assert_eq!(
            contract.accessibility.identity_version,
            contract::ACCESSIBILITY_IDENTITY_VERSION
        );
    }

    #[test]
    fn rust_encoders_match_every_cross_language_golden_operation_id() {
        let contract: GoldenContract = serde_json::from_slice(CONTRACT_BYTES).unwrap();
        assert_eq!(contract.vectors.len(), 3);
        for vector in contract.vectors {
            let agent = match vector.agent.as_str() {
                "codex" => AgentIdentity::Codex,
                unknown => panic!("unknown golden agent {unknown}"),
            };
            let canonical = match vector.adapter.as_str() {
                "system_api" => {
                    let request: SystemApiRequest =
                        serde_json::from_value(vector.request.clone()).unwrap();
                    crate::system_api::validate(&request).unwrap();
                    system_api_request(agent, &request).unwrap()
                }
                "accessibility" => {
                    let request: AccessibilityRequest =
                        serde_json::from_value(vector.request.clone()).unwrap();
                    crate::accessibility::validate(&request).unwrap();
                    accessibility_request(agent, &request).unwrap()
                }
                unknown => panic!("unknown golden adapter {unknown}"),
            };
            assert_eq!(hex(&canonical), vector.canonical_hex, "{}", vector.name);
            let digest = hex(Sha256::digest(&canonical));
            assert_eq!(digest, vector.canonical_sha256, "{}", vector.name);
            assert_eq!(
                format!("op:{}:{}:{}", contract.fixed_epoch, vector.sequence, digest),
                vector.operation_id,
                "{}",
                vector.name
            );
        }
    }

    #[test]
    fn peer_namespace_is_bound_and_reserved_fields_are_not_model_inputs() {
        let request = SystemApiRequest::LaunchPackage {
            protocol: crate::system_api::PROTOCOL.to_string(),
            request_id: "model-visible-id".to_string(),
            package: "org.example.calendar".to_string(),
            user: 0,
        };
        let codex = system_api_request(AgentIdentity::Codex, &request).unwrap();
        assert!(
            !codex
                .windows("model-visible-id".len())
                .any(|window| { window == "model-visible-id".as_bytes() })
        );
        assert!(!codex.windows(3).any(|window| window == b"op:"));
    }

    fn hex(bytes: impl AsRef<[u8]>) -> String {
        const ALPHABET: &[u8; 16] = b"0123456789abcdef";
        let bytes = bytes.as_ref();
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(ALPHABET[(byte >> 4) as usize]));
            output.push(char::from(ALPHABET[(byte & 0x0f) as usize]));
        }
        output
    }
}
