//! Pure control-side binding for the first capability-lease action slice.
//!
//! This module resolves only the Agent identity tuple consumed by Android's
//! future `CapabilityLeaseChallengeEncoderV1.AgentBinding` seam. It accepts a
//! validated Direct-operation binding inbox plus OS-authored request identity,
//! and performs no I/O, URI parsing, receipt verification, acknowledgement,
//! service registration, or effect dispatch.

use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::agent_descriptor_registry;
use crate::direct_operation::{DirectOperationAdapter, DirectOperationBindingInbox};
use crate::sha256_bytes;

pub const CAPABILITY_LEASE_OPEN_URI_ACTION_KIND: &str = "open_uri";

pub type CapabilityLeaseAgentBindingResult<T> = Result<T, CapabilityLeaseAgentBindingError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityLeaseAgentBindingError(&'static str);

impl CapabilityLeaseAgentBindingError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for CapabilityLeaseAgentBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for CapabilityLeaseAgentBindingError {}

/// Exact seven-field identity tuple expected by the Android challenge encoder.
///
/// The type deliberately excludes raw URIs, lease or receipt IDs, nonces,
/// prompts, results, and any backend-control material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityLeaseAgentBinding {
    pub provider_id: String,
    pub agent_id: String,
    pub identity_key_sha256: String,
    pub peer_uid: u32,
    pub peer_gid: u32,
    pub selinux_domain: String,
    pub executable_sha256: String,
}

impl CapabilityLeaseAgentBinding {
    /// Revalidate a retained or transported tuple against the generated product
    /// registry. This is not a signature or an independently trusted identity
    /// authority.
    pub fn validate(&self) -> CapabilityLeaseAgentBindingResult<()> {
        let descriptor =
            agent_descriptor_registry::from_provider_agent_pair(&self.provider_id, &self.agent_id)
                .ok_or_else(|| invalid("capability_lease_agent_binding_output_denied"))?;
        if self.identity_key_sha256 != descriptor.identity_key_sha256
            || self.peer_uid != descriptor.uid
            || self.peer_gid != descriptor.gid
            || self.selinux_domain != descriptor.agent_selinux_domain
            || self.executable_sha256 != descriptor.identity_key_sha256
            || self.executable_sha256 != self.identity_key_sha256
        {
            return Err(invalid("capability_lease_agent_binding_output_denied"));
        }
        Ok(())
    }
}

/// Resolve the first, closed `system_api/open_uri` capability-lease Agent
/// binding from an exact root-authored Direct binding inbox.
///
/// `workflow_id`, `task_id`, `provider_id`, `adapter`, and `action_kind` are
/// expected to be OS-authored typed request context. This function intentionally
/// has no caller-selected path or fallback and cannot activate a lease path.
pub fn resolve_system_api_open_uri_agent_binding(
    inbox: &DirectOperationBindingInbox,
    workflow_id: &str,
    task_id: &str,
    provider_id: &str,
    adapter: DirectOperationAdapter,
    action_kind: &str,
) -> CapabilityLeaseAgentBindingResult<CapabilityLeaseAgentBinding> {
    inbox
        .validate()
        .map_err(|_| invalid("capability_lease_agent_binding_inbox_denied"))?;
    if adapter != DirectOperationAdapter::SystemApi
        || action_kind != CAPABILITY_LEASE_OPEN_URI_ACTION_KIND
    {
        return Err(invalid("capability_lease_agent_binding_action_denied"));
    }

    let binding = &inbox.binding;
    if binding
        .authorized_adapter_set
        .validate_p0_system_api()
        .is_err()
        || !valid_workflow_id(workflow_id)
        || binding.workflow_id_sha256 != sha256_bytes(workflow_id.as_bytes())
    {
        return Err(invalid("capability_lease_agent_binding_workflow_denied"));
    }
    if binding.stable_seed.task_id != task_id || binding.stable_seed.provider_id != provider_id {
        return Err(invalid("capability_lease_agent_binding_request_denied"));
    }

    let descriptor = agent_descriptor_registry::from_provider_agent_pair(
        provider_id,
        &binding.stable_seed.agent_id,
    )
    .ok_or_else(|| invalid("capability_lease_agent_binding_descriptor_denied"))?;
    if binding.agent_identity_key_sha256 != descriptor.identity_key_sha256
        || binding.agent_executable_sha256 != descriptor.identity_key_sha256
        || binding.agent_identity_key_sha256 != binding.agent_executable_sha256
    {
        return Err(invalid("capability_lease_agent_binding_descriptor_denied"));
    }

    let resolved = CapabilityLeaseAgentBinding {
        provider_id: descriptor.provider_id.to_string(),
        agent_id: descriptor.agent_id.to_string(),
        identity_key_sha256: descriptor.identity_key_sha256.to_string(),
        peer_uid: descriptor.uid,
        peer_gid: descriptor.gid,
        selinux_domain: descriptor.agent_selinux_domain.to_string(),
        executable_sha256: binding.agent_executable_sha256.clone(),
    };
    resolved.validate()?;
    Ok(resolved)
}

fn valid_workflow_id(value: &str) -> bool {
    value.strip_prefix("req-").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

const fn invalid(code: &'static str) -> CapabilityLeaseAgentBindingError {
    CapabilityLeaseAgentBindingError(code)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::*;
    use crate::agent_descriptor_registry::{AgentDescriptor, CODEX, PRODUCT_ALLOWLIST};
    use crate::direct_operation::{
        BINDING_INBOX_SCHEMA, BINDING_SCHEMA, DirectOperationBinding,
        DirectOperationProviderAttempt, DirectOperationStableSeed, STABLE_SEED_SCHEMA,
    };

    const WORKFLOW_ID: &str = "req-0123456789abcdef0123456789abcdef";
    const TASK_ID: &str = "task.capability-lease-binding-test";

    fn fixture_inbox(descriptor: &AgentDescriptor) -> DirectOperationBindingInbox {
        let stable_seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: descriptor.provider_id.to_string(),
            agent_id: descriptor.agent_id.to_string(),
            task_id: TASK_ID.to_string(),
            provider_invocation_id_sha256: sha256_bytes(b"provider-invocation"),
            provider_session_id_sha256: sha256_bytes(b"provider-session"),
            subject_uid: 10_123,
            subject_selinux_domain_sha256: sha256_bytes(b"aishell-domain"),
        };
        let invocation_id = stable_seed.invocation_id().unwrap();
        let binding = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            stable_seed,
            invocation_id,
            workflow_id_sha256: sha256_bytes(WORKFLOW_ID.as_bytes()),
            agent_identity_key_sha256: descriptor.identity_key_sha256.to_string(),
            agent_executable_sha256: descriptor.identity_key_sha256.to_string(),
            authorized_adapter_set:
                crate::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(
                sha256_bytes(b"runtime-lifecycle"),
                1,
                sha256_bytes(b"daemon-attempt-context"),
            )
            .unwrap(),
        };
        let binding_sha256 = binding.digest_sha256().unwrap();
        DirectOperationBindingInbox {
            schema: BINDING_INBOX_SCHEMA.to_string(),
            binding,
            binding_sha256,
        }
    }

    fn refresh_inbox_digest(inbox: &mut DirectOperationBindingInbox) {
        inbox.binding_sha256 = inbox.binding.digest_sha256().unwrap();
    }

    fn resolve(
        inbox: &DirectOperationBindingInbox,
    ) -> CapabilityLeaseAgentBindingResult<CapabilityLeaseAgentBinding> {
        resolve_system_api_open_uri_agent_binding(
            inbox,
            WORKFLOW_ID,
            TASK_ID,
            &inbox.binding.stable_seed.provider_id,
            DirectOperationAdapter::SystemApi,
            CAPABILITY_LEASE_OPEN_URI_ACTION_KIND,
        )
    }

    fn assert_code<T>(expected: &'static str, result: CapabilityLeaseAgentBindingResult<T>) {
        match result {
            Ok(_) => panic!("expected capability-lease Agent-binding rejection"),
            Err(error) => assert_eq!(error.code(), expected),
        }
    }

    #[test]
    fn resolves_exact_codex_product_binding() {
        for descriptor in PRODUCT_ALLOWLIST {
            let resolved = resolve(&fixture_inbox(descriptor)).unwrap();
            assert_eq!(resolved.provider_id, descriptor.provider_id);
            assert_eq!(resolved.agent_id, descriptor.agent_id);
            assert_eq!(resolved.identity_key_sha256, descriptor.identity_key_sha256);
            assert_eq!(resolved.peer_uid, descriptor.uid);
            assert_eq!(resolved.peer_gid, descriptor.gid);
            assert_eq!(resolved.selinux_domain, descriptor.agent_selinux_domain);
            assert_eq!(resolved.executable_sha256, descriptor.identity_key_sha256);
            resolved.validate().unwrap();
        }
    }

    #[test]
    fn rejects_non_system_api_or_non_open_uri_action() {
        let inbox = fixture_inbox(&CODEX);
        assert_code(
            "capability_lease_agent_binding_action_denied",
            resolve_system_api_open_uri_agent_binding(
                &inbox,
                WORKFLOW_ID,
                TASK_ID,
                CODEX.provider_id,
                DirectOperationAdapter::Accessibility,
                CAPABILITY_LEASE_OPEN_URI_ACTION_KIND,
            ),
        );
        assert_code(
            "capability_lease_agent_binding_action_denied",
            resolve_system_api_open_uri_agent_binding(
                &inbox,
                WORKFLOW_ID,
                TASK_ID,
                CODEX.provider_id,
                DirectOperationAdapter::SystemApi,
                "launch_package",
            ),
        );
    }

    #[test]
    fn rejects_workflow_task_or_provider_request_drift() {
        let inbox = fixture_inbox(&CODEX);
        assert_code(
            "capability_lease_agent_binding_workflow_denied",
            resolve_system_api_open_uri_agent_binding(
                &inbox,
                "req-fedcba9876543210fedcba9876543210",
                TASK_ID,
                CODEX.provider_id,
                DirectOperationAdapter::SystemApi,
                CAPABILITY_LEASE_OPEN_URI_ACTION_KIND,
            ),
        );
        assert_code(
            "capability_lease_agent_binding_workflow_denied",
            resolve_system_api_open_uri_agent_binding(
                &inbox,
                "req-0123456789ABCDEF0123456789ABCDEF",
                TASK_ID,
                CODEX.provider_id,
                DirectOperationAdapter::SystemApi,
                CAPABILITY_LEASE_OPEN_URI_ACTION_KIND,
            ),
        );
        assert_code(
            "capability_lease_agent_binding_request_denied",
            resolve_system_api_open_uri_agent_binding(
                &inbox,
                WORKFLOW_ID,
                "task.other",
                CODEX.provider_id,
                DirectOperationAdapter::SystemApi,
                CAPABILITY_LEASE_OPEN_URI_ACTION_KIND,
            ),
        );
        assert_code(
            "capability_lease_agent_binding_request_denied",
            resolve_system_api_open_uri_agent_binding(
                &inbox,
                WORKFLOW_ID,
                TASK_ID,
                "unregistered-provider",
                DirectOperationAdapter::SystemApi,
                CAPABILITY_LEASE_OPEN_URI_ACTION_KIND,
            ),
        );
    }

    #[test]
    fn rejects_descriptor_identity_or_executable_drift_after_valid_rehash() {
        let mut identity = fixture_inbox(&CODEX);
        identity.binding.agent_identity_key_sha256 = sha256_bytes(b"other-identity-key");
        refresh_inbox_digest(&mut identity);
        assert_code(
            "capability_lease_agent_binding_descriptor_denied",
            resolve(&identity),
        );

        let mut executable = fixture_inbox(&CODEX);
        executable.binding.agent_executable_sha256 = sha256_bytes(b"other-executable");
        refresh_inbox_digest(&mut executable);
        assert_code(
            "capability_lease_agent_binding_descriptor_denied",
            resolve(&executable),
        );
    }

    #[test]
    fn rejects_inbox_digest_schema_or_provider_agent_drift() {
        let mut digest = fixture_inbox(&CODEX);
        digest.binding_sha256 = sha256_bytes(b"other-binding");
        assert_code(
            "capability_lease_agent_binding_inbox_denied",
            resolve(&digest),
        );

        let mut schema = fixture_inbox(&CODEX);
        schema.schema = "trillionnium.direct-operation-binding-inbox.v1".to_string();
        assert_code(
            "capability_lease_agent_binding_inbox_denied",
            resolve(&schema),
        );

        let mut pair = fixture_inbox(&CODEX);
        pair.binding.stable_seed.agent_id = "unregistered-agent".to_string();
        assert_code(
            "capability_lease_agent_binding_inbox_denied",
            resolve(&pair),
        );
    }

    #[test]
    fn retained_output_rejects_every_descriptor_field_drift() {
        let resolved = resolve(&fixture_inbox(&CODEX)).unwrap();
        let mut variants = Vec::new();

        let mut value = resolved.clone();
        value.provider_id = "model-authored-provider".to_string();
        variants.push(value);
        let mut value = resolved.clone();
        value.agent_id.push_str("-drift");
        variants.push(value);
        let mut value = resolved.clone();
        value.identity_key_sha256 = sha256_bytes(b"other-identity");
        variants.push(value);
        let mut value = resolved.clone();
        value.peer_uid += 1;
        variants.push(value);
        let mut value = resolved.clone();
        value.peer_gid += 1;
        variants.push(value);
        let mut value = resolved.clone();
        value.selinux_domain.push_str("-drift");
        variants.push(value);
        let mut value = resolved;
        value.executable_sha256 = sha256_bytes(b"other-executable");
        variants.push(value);

        for invalid in variants {
            assert_code(
                "capability_lease_agent_binding_output_denied",
                invalid.validate(),
            );
        }
    }

    #[test]
    fn serialized_agent_binding_is_closed_and_contains_no_lease_material() {
        let resolved = resolve(&fixture_inbox(&CODEX)).unwrap();
        let encoded = serde_json::to_value(&resolved).unwrap();
        let keys = encoded
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from([
                "agent_id",
                "executable_sha256",
                "identity_key_sha256",
                "peer_gid",
                "peer_uid",
                "provider_id",
                "selinux_domain",
            ])
        );
        for forbidden in [
            "uri",
            "lease_id",
            "receipt",
            "nonce",
            "prompt",
            "result",
            "binding_inbox",
        ] {
            assert!(!encoded.as_object().unwrap().contains_key(forbidden));
        }

        let mut unknown = encoded;
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_string(), json!(true));
        assert!(serde_json::from_value::<CapabilityLeaseAgentBinding>(unknown).is_err());
    }
}
