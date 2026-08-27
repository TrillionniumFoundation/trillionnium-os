//! OS-host registration and one-invocation authorization for `shell.exec.v1`.
//!
//! This is deliberately parallel to the existing System API
//! `DirectOperationAuthorizedAdapterSetV3`: it validates the already-published
//! binding but never adds shell to that older closed adapter enum.  The model
//! sees only [`DirectEffectModelArgumentsV1`].  The invocation token and
//! ordinal are adapter/broker transport material and must never enter MCP
//! arguments or the prompt.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_os_types::direct_effect::{
    DirectEffectExecutionProfileV1, DirectEffectModelArgumentsV1, DirectEffectRequestV1,
    DirectEffectRiskClassV1, DirectEffectToolV1, OS_TOOL_CALL_ID_PREFIX,
};
use trillionnium_os_types::direct_operation::DirectOperationBinding;

use crate::{
    SHELL_EXEC_FIRST_SLICE_MAX_TIMEOUT_MS, SHELL_EXEC_MAX_RAW_OUTPUT_BYTES,
    validate_first_slice_arguments,
};

pub const HOST_REGISTRATION_SCHEMA: &str = "org.trillionnium.shell-exec.host-registration.v1";
pub const HOST_REGISTRATION_RECEIPT_SCHEMA: &str =
    "org.trillionnium.shell-exec.host-registration-receipt.v1";
pub const HOST_RETIREMENT_SCHEMA: &str = "org.trillionnium.shell-exec.host-retirement.v1";
pub const HOST_RETIREMENT_RECEIPT_SCHEMA: &str =
    "org.trillionnium.shell-exec.host-retirement-receipt.v1";
pub const STANDARD_POLICY_SCHEMA: &str = "org.trillionnium.shell-exec.standard-policy.v1";
pub const INVOCATION_TOKEN_PREFIX: &str = "shell-inv:";
pub const MAX_INVOCATION_LIFETIME_MS: u64 = 120_000;
// The first vertical slice is one exact-argv effect per provider turn.  This
// bound is enforced by broker authorization before request materialization;
// it is not a post-effect evidence-size check.
pub const MAX_EFFECTS_PER_INVOCATION: u64 = 1;

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("shell registration is invalid: {0}")]
    Registration(&'static str),
    #[error("shell invocation authorization is invalid: {0}")]
    Authorization(&'static str),
    #[error("shell request identity conflicts with an existing ordinal")]
    IdentityConflict,
    #[error("shell invocation entropy is unavailable: {0}")]
    Entropy(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AuthorizationError>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedStandardShellPolicyV1 {
    pub schema: String,
    pub tool: DirectEffectToolV1,
    pub effective_profile: DirectEffectExecutionProfileV1,
    pub risk_class: DirectEffectRiskClassV1,
    pub timeout_maximum_ms: u64,
    pub stdout_maximum_bytes: u64,
    pub stderr_maximum_bytes: u64,
    pub combined_output_maximum_bytes: u64,
    pub exact_argv_only: bool,
    pub command_string_mode: bool,
}

impl FixedStandardShellPolicyV1 {
    #[must_use]
    pub fn fixed() -> Self {
        Self {
            schema: STANDARD_POLICY_SCHEMA.to_string(),
            tool: DirectEffectToolV1::ShellExecV1,
            effective_profile: DirectEffectExecutionProfileV1::Standard,
            risk_class: DirectEffectRiskClassV1::Standard,
            timeout_maximum_ms: SHELL_EXEC_FIRST_SLICE_MAX_TIMEOUT_MS,
            stdout_maximum_bytes: SHELL_EXEC_MAX_RAW_OUTPUT_BYTES,
            stderr_maximum_bytes: SHELL_EXEC_MAX_RAW_OUTPUT_BYTES,
            combined_output_maximum_bytes: SHELL_EXEC_MAX_RAW_OUTPUT_BYTES,
            exact_argv_only: true,
            command_string_mode: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self != &Self::fixed() {
            return Err(AuthorizationError::Registration(
                "fixed_standard_shell_policy_mismatch",
            ));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| {
            AuthorizationError::Registration("fixed_standard_shell_policy_encode_failed")
        })?;
        Ok(trillionnium_os_types::sha256_bytes(&bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecHostRegistrationV1 {
    pub schema: String,
    pub binding: DirectOperationBinding,
    pub binding_sha256: String,
    pub issued_boottime_ms: u64,
    pub expires_boottime_ms: u64,
    pub policy: FixedStandardShellPolicyV1,
    pub policy_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
// Boxing Register would add an internal allocation and churn every constructor
// solely to reduce stack size; the closed serde carrier is bounded to one
// authenticated broker record, so retain the direct representation.
#[allow(clippy::large_enum_variant)]
pub enum ShellExecHostControlV1 {
    Register {
        registration: ShellExecHostRegistrationV1,
    },
    Retire {
        retirement: ShellExecHostRetirementV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecHostRetirementV1 {
    pub schema: String,
    pub binding_sha256: String,
    pub registration_sha256: String,
}

impl ShellExecHostRetirementV1 {
    pub fn derive(registration: &ShellExecHostRegistrationV1) -> Result<Self> {
        let value = Self {
            schema: HOST_RETIREMENT_SCHEMA.to_string(),
            binding_sha256: registration.binding_sha256.clone(),
            registration_sha256: registration.digest_sha256()?,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != HOST_RETIREMENT_SCHEMA
            || !trillionnium_os_types::is_nonzero_lower_sha256(&self.binding_sha256)
            || !trillionnium_os_types::is_nonzero_lower_sha256(&self.registration_sha256)
        {
            return Err(AuthorizationError::Registration("host_retirement_invalid"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecHostRetirementReceiptV1 {
    pub schema: String,
    pub binding_sha256: String,
    pub registration_sha256: String,
    pub retired_boottime_ms: u64,
}

impl ShellExecHostRetirementReceiptV1 {
    pub fn validate_for(&self, retirement: &ShellExecHostRetirementV1) -> Result<()> {
        retirement.validate()?;
        if self.schema != HOST_RETIREMENT_RECEIPT_SCHEMA
            || self.binding_sha256 != retirement.binding_sha256
            || self.registration_sha256 != retirement.registration_sha256
            || self.retired_boottime_ms == 0
        {
            return Err(AuthorizationError::Authorization(
                "host_retirement_receipt_invalid",
            ));
        }
        Ok(())
    }
}

impl ShellExecHostRegistrationV1 {
    pub fn derive(
        binding: DirectOperationBinding,
        issued_boottime_ms: u64,
        expires_boottime_ms: u64,
    ) -> Result<Self> {
        binding
            .validate()
            .map_err(|_| AuthorizationError::Registration("direct_binding_invalid"))?;
        let binding_sha256 = binding
            .digest_sha256()
            .map_err(|_| AuthorizationError::Registration("direct_binding_digest_invalid"))?;
        let policy = FixedStandardShellPolicyV1::fixed();
        let policy_sha256 = policy.digest_sha256()?;
        let value = Self {
            schema: HOST_REGISTRATION_SCHEMA.to_string(),
            binding,
            binding_sha256,
            issued_boottime_ms,
            expires_boottime_ms,
            policy,
            policy_sha256,
        };
        value.validate_at(issued_boottime_ms)?;
        Ok(value)
    }

    pub fn validate_at(&self, now_boottime_ms: u64) -> Result<()> {
        self.binding
            .validate()
            .map_err(|_| AuthorizationError::Registration("direct_binding_invalid"))?;
        self.policy.validate()?;
        let expected_binding = self
            .binding
            .digest_sha256()
            .map_err(|_| AuthorizationError::Registration("direct_binding_digest_invalid"))?;
        if self.schema != HOST_REGISTRATION_SCHEMA
            || self.binding_sha256 != expected_binding
            || self.policy_sha256 != self.policy.digest_sha256()?
            || self.issued_boottime_ms == 0
            || self.expires_boottime_ms <= self.issued_boottime_ms
            || self
                .expires_boottime_ms
                .saturating_sub(self.issued_boottime_ms)
                > MAX_INVOCATION_LIFETIME_MS
            || now_boottime_ms < self.issued_boottime_ms
            || now_boottime_ms >= self.expires_boottime_ms
        {
            return Err(AuthorizationError::Registration(
                "registration_identity_or_lifetime_invalid",
            ));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> Result<String> {
        self.validate_at(self.issued_boottime_ms)?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| AuthorizationError::Registration("host_registration_encode_failed"))?;
        Ok(trillionnium_os_types::sha256_bytes(&bytes))
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecHostRegistrationReceiptV1 {
    pub schema: String,
    #[serde(skip)]
    invocation_token: String,
    pub invocation_token_sha256: String,
    pub binding_sha256: String,
    pub registration_sha256: String,
    pub policy_sha256: String,
    pub expires_boottime_ms: u64,
    pub authorization_sha256: String,
}

impl std::fmt::Debug for ShellExecHostRegistrationReceiptV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ShellExecHostRegistrationReceiptV1")
            .field("schema", &self.schema)
            .field("invocation_token", &"<redacted>")
            .field("invocation_token_sha256", &self.invocation_token_sha256)
            .field("binding_sha256", &self.binding_sha256)
            .field("registration_sha256", &self.registration_sha256)
            .field("policy_sha256", &self.policy_sha256)
            .field("expires_boottime_ms", &self.expires_boottime_ms)
            .field("authorization_sha256", &self.authorization_sha256)
            .finish()
    }
}

impl ShellExecHostRegistrationReceiptV1 {
    #[must_use]
    pub fn invocation_token(&self) -> &str {
        &self.invocation_token
    }

    pub fn validate_for(&self, registration: &ShellExecHostRegistrationV1) -> Result<()> {
        if !trillionnium_os_types::is_nonzero_lower_sha256(&self.invocation_token_sha256) {
            return Err(AuthorizationError::Authorization(
                "registration_receipt_token_digest_invalid",
            ));
        }
        if !self.invocation_token.is_empty()
            && invocation_token_sha256(&self.invocation_token)? != self.invocation_token_sha256
        {
            return Err(AuthorizationError::Authorization(
                "registration_receipt_token_digest_invalid",
            ));
        }
        let registration_sha256 = registration.digest_sha256()?;
        let expected_authorization = authorization_digest(
            &registration_sha256,
            &self.invocation_token_sha256,
            registration.expires_boottime_ms,
        );
        if self.schema != HOST_REGISTRATION_RECEIPT_SCHEMA
            || self.binding_sha256 != registration.binding_sha256
            || self.registration_sha256 != registration_sha256
            || self.policy_sha256 != registration.policy_sha256
            || self.expires_boottime_ms != registration.expires_boottime_ms
            || self.authorization_sha256 != expected_authorization
        {
            return Err(AuthorizationError::Authorization(
                "registration_receipt_binding_invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct OrdinalRecordV1 {
    semantic_arguments_sha256: String,
    request: Option<DirectEffectRequestV1>,
}

#[derive(Clone)]
struct ActiveRegistrationV1 {
    registration: ShellExecHostRegistrationV1,
    receipt: ShellExecHostRegistrationReceiptV1,
    ordinals: BTreeMap<u64, OrdinalRecordV1>,
}

#[derive(Clone)]
struct RetiredRegistrationV1 {
    receipt: ShellExecHostRetirementReceiptV1,
}

#[derive(Clone)]
pub struct PendingShellExecRequestV1 {
    token_sha256: String,
    adapter_effect_ordinal: u64,
    semantic_arguments_sha256: String,
    arguments: DirectEffectModelArgumentsV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellExecStableRequestIdentityV1 {
    pub binding_sha256: String,
    pub adapter_effect_ordinal: u64,
    pub semantic_arguments_sha256: String,
}

// This short-lived internal typestate is consumed immediately by the broker.
// Keep ownership direct so admission cannot accidentally share or outlive its
// exact request merely to satisfy a size-style lint.
#[allow(clippy::large_enum_variant)]
pub enum ShellExecRequestAdmissionV1 {
    Existing(DirectEffectRequestV1),
    NeedsWorker(PendingShellExecRequestV1),
}

#[derive(Default)]
pub struct ShellExecAuthorizationRegistryV1 {
    by_token_sha256: BTreeMap<String, ActiveRegistrationV1>,
    token_by_registration_sha256: BTreeMap<String, String>,
    // The lane permits one active invocation, so retaining the most recent
    // retirement is sufficient to make a lost retirement reply replay exact
    // without growing broker memory over its lifetime.
    last_retirement: Option<RetiredRegistrationV1>,
}

impl ShellExecAuthorizationRegistryV1 {
    pub fn register(
        &mut self,
        registration: ShellExecHostRegistrationV1,
        now_boottime_ms: u64,
    ) -> Result<ShellExecHostRegistrationReceiptV1> {
        let mut entropy = [0_u8; 32];
        fill_entropy(&mut entropy)?;
        self.register_with_entropy(registration, now_boottime_ms, entropy)
    }

    pub fn register_with_entropy(
        &mut self,
        registration: ShellExecHostRegistrationV1,
        now_boottime_ms: u64,
        entropy: [u8; 32],
    ) -> Result<ShellExecHostRegistrationReceiptV1> {
        self.purge_expired(now_boottime_ms);
        registration.validate_at(now_boottime_ms)?;
        let registration_sha256 = registration.digest_sha256()?;
        if self
            .last_retirement
            .as_ref()
            .is_some_and(|retired| retired.receipt.registration_sha256 == registration_sha256)
        {
            return Err(AuthorizationError::Registration(
                "registration_already_retired",
            ));
        }
        if let Some(token_sha256) = self
            .token_by_registration_sha256
            .get(&registration_sha256)
            .cloned()
            && let Some(existing) = self.by_token_sha256.get(&token_sha256)
        {
            existing.receipt.validate_for(&registration)?;
            return Ok(existing.receipt.clone());
        }
        if !self.by_token_sha256.is_empty() {
            return Err(AuthorizationError::Registration(
                "another_shell_invocation_is_active",
            ));
        }
        let invocation_token = derive_token(&registration_sha256, &entropy);
        let invocation_token_sha256 = invocation_token_sha256(&invocation_token)?;
        if self.by_token_sha256.contains_key(&invocation_token_sha256) {
            return Err(AuthorizationError::Registration(
                "invocation_token_collision",
            ));
        }
        let receipt = ShellExecHostRegistrationReceiptV1 {
            schema: HOST_REGISTRATION_RECEIPT_SCHEMA.to_string(),
            invocation_token,
            invocation_token_sha256: invocation_token_sha256.clone(),
            binding_sha256: registration.binding_sha256.clone(),
            registration_sha256: registration_sha256.clone(),
            policy_sha256: registration.policy_sha256.clone(),
            expires_boottime_ms: registration.expires_boottime_ms,
            authorization_sha256: authorization_digest(
                &registration_sha256,
                &invocation_token_sha256,
                registration.expires_boottime_ms,
            ),
        };
        receipt.validate_for(&registration)?;
        self.by_token_sha256.insert(
            invocation_token_sha256.clone(),
            ActiveRegistrationV1 {
                registration,
                receipt: receipt.clone(),
                ordinals: BTreeMap::new(),
            },
        );
        self.token_by_registration_sha256
            .insert(registration_sha256, invocation_token_sha256);
        Ok(receipt)
    }

    pub fn begin_request(
        &mut self,
        invocation_token: &str,
        adapter_effect_ordinal: u64,
        arguments: DirectEffectModelArgumentsV1,
        now_boottime_ms: u64,
    ) -> Result<ShellExecRequestAdmissionV1> {
        validate_first_slice_arguments(&arguments)
            .map_err(|_| AuthorizationError::Authorization("semantic_arguments_invalid"))?;
        if adapter_effect_ordinal == 0 || adapter_effect_ordinal > MAX_EFFECTS_PER_INVOCATION {
            return Err(AuthorizationError::Authorization(
                "adapter_effect_ordinal_invalid",
            ));
        }
        let token_sha256 = invocation_token_sha256(invocation_token)?;
        self.begin_request_by_token_sha256(
            token_sha256,
            adapter_effect_ordinal,
            arguments,
            now_boottime_ms,
        )
    }

    pub fn begin_unique_active_request(
        &mut self,
        adapter_effect_ordinal: u64,
        arguments: DirectEffectModelArgumentsV1,
        now_boottime_ms: u64,
    ) -> Result<ShellExecRequestAdmissionV1> {
        self.purge_expired(now_boottime_ms);
        if self.by_token_sha256.len() != 1 {
            return Err(AuthorizationError::Authorization(
                "unique_active_invocation_missing",
            ));
        }
        let token_sha256 = self
            .by_token_sha256
            .first_key_value()
            .map(|(token, _)| token.clone())
            .ok_or(AuthorizationError::Authorization(
                "unique_active_invocation_missing",
            ))?;
        self.begin_request_by_token_sha256(
            token_sha256,
            adapter_effect_ordinal,
            arguments,
            now_boottime_ms,
        )
    }

    fn begin_request_by_token_sha256(
        &mut self,
        token_sha256: String,
        adapter_effect_ordinal: u64,
        arguments: DirectEffectModelArgumentsV1,
        now_boottime_ms: u64,
    ) -> Result<ShellExecRequestAdmissionV1> {
        validate_first_slice_arguments(&arguments)
            .map_err(|_| AuthorizationError::Authorization("semantic_arguments_invalid"))?;
        if adapter_effect_ordinal == 0 || adapter_effect_ordinal > MAX_EFFECTS_PER_INVOCATION {
            return Err(AuthorizationError::Authorization(
                "adapter_effect_ordinal_invalid",
            ));
        }
        let active = self.by_token_sha256.get_mut(&token_sha256).ok_or(
            AuthorizationError::Authorization("invocation_token_unknown"),
        )?;
        active.registration.validate_at(now_boottime_ms)?;
        let semantic_arguments_sha256 = arguments
            .canonical_sha256()
            .map_err(|_| AuthorizationError::Authorization("semantic_arguments_invalid"))?;
        if let Some(existing) = active.ordinals.get(&adapter_effect_ordinal) {
            if existing.semantic_arguments_sha256 != semantic_arguments_sha256 {
                return Err(AuthorizationError::IdentityConflict);
            }
            return match &existing.request {
                Some(request) => Ok(ShellExecRequestAdmissionV1::Existing(request.clone())),
                None => Ok(ShellExecRequestAdmissionV1::NeedsWorker(
                    PendingShellExecRequestV1 {
                        token_sha256,
                        adapter_effect_ordinal,
                        semantic_arguments_sha256,
                        arguments,
                    },
                )),
            };
        }
        let expected_next = active
            .ordinals
            .last_key_value()
            .map_or(1, |(ordinal, _)| ordinal.saturating_add(1));
        if adapter_effect_ordinal != expected_next {
            return Err(AuthorizationError::Authorization(
                "adapter_effect_ordinal_not_sequential",
            ));
        }
        active.ordinals.insert(
            adapter_effect_ordinal,
            OrdinalRecordV1 {
                semantic_arguments_sha256: semantic_arguments_sha256.clone(),
                request: None,
            },
        );
        Ok(ShellExecRequestAdmissionV1::NeedsWorker(
            PendingShellExecRequestV1 {
                token_sha256,
                adapter_effect_ordinal,
                semantic_arguments_sha256,
                arguments,
            },
        ))
    }

    pub fn retire_registration(
        &mut self,
        registration_sha256: &str,
        binding_sha256: &str,
    ) -> Result<()> {
        let token_sha256 = self.validate_retirement(registration_sha256, binding_sha256)?;
        self.by_token_sha256.remove(&token_sha256);
        self.token_by_registration_sha256
            .remove(registration_sha256);
        Ok(())
    }

    pub fn validate_retirement(
        &self,
        registration_sha256: &str,
        binding_sha256: &str,
    ) -> Result<String> {
        let token_sha256 = self
            .token_by_registration_sha256
            .get(registration_sha256)
            .cloned()
            .ok_or(AuthorizationError::Authorization(
                "registration_retirement_unknown",
            ))?;
        let active =
            self.by_token_sha256
                .get(&token_sha256)
                .ok_or(AuthorizationError::Authorization(
                    "registration_retirement_unknown",
                ))?;
        if active.registration.binding_sha256 != binding_sha256 {
            return Err(AuthorizationError::Authorization(
                "registration_retirement_binding_invalid",
            ));
        }
        Ok(token_sha256)
    }

    pub fn retirement_has_ordinals(&self, retirement: &ShellExecHostRetirementV1) -> Result<bool> {
        retirement.validate()?;
        match self.validate_retirement(&retirement.registration_sha256, &retirement.binding_sha256)
        {
            Ok(token) => Ok(self
                .by_token_sha256
                .get(&token)
                .is_some_and(|active| !active.ordinals.is_empty())),
            Err(_error)
                if self.last_retirement.as_ref().is_some_and(|retired| {
                    retired.receipt.registration_sha256 == retirement.registration_sha256
                        && retired.receipt.binding_sha256 == retirement.binding_sha256
                }) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    pub fn retire(
        &mut self,
        retirement: &ShellExecHostRetirementV1,
        now_boottime_ms: u64,
    ) -> Result<ShellExecHostRetirementReceiptV1> {
        retirement.validate()?;
        if let Some(retired) = &self.last_retirement
            && retired.receipt.registration_sha256 == retirement.registration_sha256
            && retired.receipt.binding_sha256 == retirement.binding_sha256
        {
            retired.receipt.validate_for(retirement)?;
            return Ok(retired.receipt.clone());
        }
        self.retire_registration(&retirement.registration_sha256, &retirement.binding_sha256)?;
        let receipt = ShellExecHostRetirementReceiptV1 {
            schema: HOST_RETIREMENT_RECEIPT_SCHEMA.to_string(),
            binding_sha256: retirement.binding_sha256.clone(),
            registration_sha256: retirement.registration_sha256.clone(),
            retired_boottime_ms: now_boottime_ms,
        };
        receipt.validate_for(retirement)?;
        self.last_retirement = Some(RetiredRegistrationV1 {
            receipt: receipt.clone(),
        });
        Ok(receipt)
    }

    fn purge_expired(&mut self, now_boottime_ms: u64) {
        self.by_token_sha256
            .retain(|_, active| active.registration.expires_boottime_ms > now_boottime_ms);
        self.token_by_registration_sha256
            .retain(|_, token| self.by_token_sha256.contains_key(token));
    }

    pub fn materialize_request(
        &mut self,
        pending: PendingShellExecRequestV1,
        now_boottime_ms: u64,
        boot_id_sha256: String,
        kernel_launch_custody_sha256: String,
        backend_identity_sha256: String,
    ) -> Result<DirectEffectRequestV1> {
        let active = self.by_token_sha256.get_mut(&pending.token_sha256).ok_or(
            AuthorizationError::Authorization("invocation_token_unknown"),
        )?;
        active.registration.validate_at(now_boottime_ms)?;
        let ordinal = active
            .ordinals
            .get_mut(&pending.adapter_effect_ordinal)
            .ok_or(AuthorizationError::IdentityConflict)?;
        if ordinal.semantic_arguments_sha256 != pending.semantic_arguments_sha256 {
            return Err(AuthorizationError::IdentityConflict);
        }
        if let Some(request) = &ordinal.request {
            return Ok(request.clone());
        }
        let binding = &active.registration.binding;
        let os_tool_call_id = format!(
            "{OS_TOOL_CALL_ID_PREFIX}{}",
            domain_digest(
                b"trillionnium.shell-exec.os-tool-call-id.v1",
                &[
                    active.registration.binding_sha256.as_bytes(),
                    &pending.adapter_effect_ordinal.to_be_bytes(),
                ],
            )
        );
        let allocation_record_sha256 = domain_digest(
            b"trillionnium.shell-exec.allocation-record.v1",
            &[
                active.registration.binding_sha256.as_bytes(),
                os_tool_call_id.as_bytes(),
                &pending.adapter_effect_ordinal.to_be_bytes(),
                pending.semantic_arguments_sha256.as_bytes(),
            ],
        );
        let requested_deadline = now_boottime_ms
            .checked_add(pending.arguments.timeout_ms)
            .ok_or(AuthorizationError::Authorization("deadline_overflow"))?;
        let absolute_deadline_boottime_ms =
            requested_deadline.min(active.registration.expires_boottime_ms);
        if absolute_deadline_boottime_ms <= now_boottime_ms {
            return Err(AuthorizationError::Authorization(
                "invocation_expired_before_request_materialization",
            ));
        }
        let request = DirectEffectRequestV1::derive_os_owned(
            binding.stable_seed.provider_id.clone(),
            binding.stable_seed.agent_id.clone(),
            active.registration.binding_sha256.clone(),
            binding.invocation_id.clone(),
            binding.attempt.delivery_provider_attempt_id.clone(),
            os_tool_call_id,
            pending.adapter_effect_ordinal,
            allocation_record_sha256,
            kernel_launch_custody_sha256,
            boot_id_sha256,
            DirectEffectToolV1::ShellExecV1,
            pending.arguments,
            absolute_deadline_boottime_ms,
            DirectEffectExecutionProfileV1::Standard,
            DirectEffectRiskClassV1::Standard,
            None,
            active.registration.policy_sha256.clone(),
            backend_identity_sha256,
        )
        .map_err(|_| AuthorizationError::Authorization("os_owned_request_derivation_failed"))?;
        ordinal.request = Some(request.clone());
        Ok(request)
    }

    pub fn stable_identity_for_pending(
        &self,
        pending: &PendingShellExecRequestV1,
    ) -> Result<ShellExecStableRequestIdentityV1> {
        let active = self.by_token_sha256.get(&pending.token_sha256).ok_or(
            AuthorizationError::Authorization("invocation_token_unknown"),
        )?;
        let ordinal = active
            .ordinals
            .get(&pending.adapter_effect_ordinal)
            .ok_or(AuthorizationError::IdentityConflict)?;
        if ordinal.semantic_arguments_sha256 != pending.semantic_arguments_sha256 {
            return Err(AuthorizationError::IdentityConflict);
        }
        Ok(ShellExecStableRequestIdentityV1 {
            binding_sha256: active.registration.binding_sha256.clone(),
            adapter_effect_ordinal: pending.adapter_effect_ordinal,
            semantic_arguments_sha256: pending.semantic_arguments_sha256.clone(),
        })
    }

    pub fn restore_materialized_request(
        &mut self,
        pending: PendingShellExecRequestV1,
        request: DirectEffectRequestV1,
    ) -> Result<DirectEffectRequestV1> {
        let active = self.by_token_sha256.get_mut(&pending.token_sha256).ok_or(
            AuthorizationError::Authorization("invocation_token_unknown"),
        )?;
        validate_restored_request(active, &request)?;
        if request.adapter_effect_ordinal != pending.adapter_effect_ordinal
            || request.arguments != pending.arguments
            || request
                .arguments
                .canonical_sha256()
                .map_err(|_| AuthorizationError::Authorization("semantic_arguments_invalid"))?
                != pending.semantic_arguments_sha256
        {
            return Err(AuthorizationError::IdentityConflict);
        }
        let ordinal = active
            .ordinals
            .get_mut(&pending.adapter_effect_ordinal)
            .ok_or(AuthorizationError::IdentityConflict)?;
        if ordinal.semantic_arguments_sha256 != pending.semantic_arguments_sha256 {
            return Err(AuthorizationError::IdentityConflict);
        }
        if let Some(existing) = &ordinal.request
            && existing != &request
        {
            return Err(AuthorizationError::IdentityConflict);
        }
        ordinal.request = Some(request.clone());
        Ok(request)
    }

    /// Restores the ordinal high-water mark after broker restart. The host
    /// still has to register the same binding; no authority is created from
    /// ledger bytes alone.
    pub fn restore_durable_requests(
        &mut self,
        binding_sha256: &str,
        requests: &[DirectEffectRequestV1],
    ) -> Result<()> {
        if self.by_token_sha256.len() != 1 {
            return Err(AuthorizationError::Authorization(
                "unique_active_invocation_missing",
            ));
        }
        let active = self
            .by_token_sha256
            .first_entry()
            .ok_or(AuthorizationError::Authorization(
                "unique_active_invocation_missing",
            ))?
            .into_mut();
        if active.registration.binding_sha256 != binding_sha256 {
            return Err(AuthorizationError::IdentityConflict);
        }
        for request in requests {
            validate_restored_request(active, request)?;
            let semantic_arguments_sha256 = request
                .arguments
                .canonical_sha256()
                .map_err(|_| AuthorizationError::Authorization("semantic_arguments_invalid"))?;
            if let Some(existing) = active.ordinals.get(&request.adapter_effect_ordinal) {
                if existing.semantic_arguments_sha256 != semantic_arguments_sha256
                    || existing.request.as_ref() != Some(request)
                {
                    return Err(AuthorizationError::IdentityConflict);
                }
                continue;
            }
            let expected = active
                .ordinals
                .last_key_value()
                .map_or(1, |(ordinal, _)| ordinal.saturating_add(1));
            if request.adapter_effect_ordinal != expected {
                return Err(AuthorizationError::IdentityConflict);
            }
            active.ordinals.insert(
                request.adapter_effect_ordinal,
                OrdinalRecordV1 {
                    semantic_arguments_sha256,
                    request: Some(request.clone()),
                },
            );
        }
        Ok(())
    }
}

fn validate_restored_request(
    active: &ActiveRegistrationV1,
    request: &DirectEffectRequestV1,
) -> Result<()> {
    request
        .validate()
        .map_err(|_| AuthorizationError::IdentityConflict)?;
    let binding = &active.registration.binding;
    let expected_os_tool_call_id = format!(
        "{OS_TOOL_CALL_ID_PREFIX}{}",
        domain_digest(
            b"trillionnium.shell-exec.os-tool-call-id.v1",
            &[
                active.registration.binding_sha256.as_bytes(),
                &request.adapter_effect_ordinal.to_be_bytes(),
            ],
        )
    );
    let semantic_arguments_sha256 = request
        .arguments
        .canonical_sha256()
        .map_err(|_| AuthorizationError::IdentityConflict)?;
    let expected_allocation = domain_digest(
        b"trillionnium.shell-exec.allocation-record.v1",
        &[
            active.registration.binding_sha256.as_bytes(),
            expected_os_tool_call_id.as_bytes(),
            &request.adapter_effect_ordinal.to_be_bytes(),
            semantic_arguments_sha256.as_bytes(),
        ],
    );
    if request.direct_binding_sha256 != active.registration.binding_sha256
        || request.provider_id != binding.stable_seed.provider_id
        || request.agent_id != binding.stable_seed.agent_id
        || request.invocation_id != binding.invocation_id
        || request.delivery_provider_attempt_id != binding.attempt.delivery_provider_attempt_id
        || request.os_tool_call_id != expected_os_tool_call_id
        || request.allocation_record_sha256 != expected_allocation
        || request.policy_sha256 != active.registration.policy_sha256
    {
        return Err(AuthorizationError::IdentityConflict);
    }
    Ok(())
}

fn derive_token(registration_sha256: &str, entropy: &[u8; 32]) -> String {
    format!(
        "{INVOCATION_TOKEN_PREFIX}{}",
        domain_digest(
            b"trillionnium.shell-exec.invocation-token.v1",
            &[registration_sha256.as_bytes(), entropy],
        )
    )
}

pub fn invocation_token_sha256(token: &str) -> Result<String> {
    let digest = token
        .strip_prefix(INVOCATION_TOKEN_PREFIX)
        .filter(|digest| trillionnium_os_types::is_nonzero_lower_sha256(digest))
        .ok_or(AuthorizationError::Authorization(
            "invocation_token_shape_invalid",
        ))?;
    let _ = digest;
    Ok(trillionnium_os_types::sha256_bytes(token.as_bytes()))
}

fn authorization_digest(
    registration_sha256: &str,
    invocation_token_sha256: &str,
    expires_boottime_ms: u64,
) -> String {
    domain_digest(
        b"trillionnium.shell-exec.authorization.v1",
        &[
            registration_sha256.as_bytes(),
            invocation_token_sha256.as_bytes(),
            &expires_boottime_ms.to_be_bytes(),
        ],
    )
}

fn domain_digest(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hash_part(&mut hasher, domain);
    for field in fields {
        hash_part(&mut hasher, field);
    }
    format!("{:x}", hasher.finalize())
}

fn hash_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn fill_entropy(output: &mut [u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < output.len() {
        // SAFETY: the remaining output slice is valid writable storage and no
        // pointer is retained after getrandom returns.
        let result = unsafe {
            libc::getrandom(
                output[offset..].as_mut_ptr().cast(),
                output.len() - offset,
                0,
            )
        };
        if result > 0 {
            offset += result as usize;
            continue;
        }
        if result == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}
