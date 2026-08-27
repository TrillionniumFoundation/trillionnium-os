//! Inert contracts for an external provider-leaf custody freshness authority.
//!
//! The local custody store has an authenticated hash chain and a cooperating
//! single-writer OFD lock, but neither prevents rollback of a valid file pair
//! across broker restart.  Promotion therefore requires an independently
//! trusted, rollback-resistant authority.  This module freezes the closed
//! canonical payloads and the prepare/commit CAS semantics for that future
//! boundary without pretending that an authority already exists.
//!
//! There is deliberately no production constructor, transport, filesystem
//! access, product path, signature verifier, or broker entrypoint here.  The
//! in-memory authority and all value builders are test-only.  A future product
//! implementation must authenticate the authority and provision anchor,
//! provide real monotonic storage, and translate commit-unknown into a
//! permanent HOLD before these contracts can authorize any custody mutation.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_privilege_broker_protocol::{Digest, FixedBytes32};

const PROVISION_ANCHOR_SCHEMA: &str = "org.trillionnium.provider-leaf-provision-anchor-payload.v1";
const MONOTONIC_HEAD_SCHEMA: &str = "org.trillionnium.provider-leaf-monotonic-head.v1";
const HEAD_TRANSITION_SCHEMA: &str = "org.trillionnium.provider-leaf-head-transition.v1";
const LOCAL_TRANSITION_INTENT_SCHEMA: &str =
    "org.trillionnium.provider-leaf-local-transition-intent.v1";

const PROVISION_ANCHOR_DOMAIN: &[u8] =
    b"org.trillionnium.provider-leaf-provision-anchor-payload.v1\0";
const MONOTONIC_HEAD_DOMAIN: &[u8] = b"org.trillionnium.provider-leaf-monotonic-head.v1\0";
const HEAD_TRANSITION_DOMAIN: &[u8] = b"org.trillionnium.provider-leaf-head-transition.v1\0";
const LOCAL_TRANSITION_INTENT_DOMAIN: &[u8] =
    b"org.trillionnium.provider-leaf-local-transition-intent.v1\0";

/// This source checkpoint cannot authorize production mutation.
pub(crate) const EXTERNAL_MONOTONIC_AUTHORITY_FOUNDATION_ENABLED: bool = false;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
enum ContractError {
    #[error("external monotonic authority closed JSON denied")]
    ClosedJsonDenied,
    #[error("external monotonic authority noncanonical JSON denied")]
    NoncanonicalJsonDenied,
    #[error("external monotonic authority provision anchor denied")]
    ProvisionAnchorDenied,
    #[error("external monotonic authority head denied")]
    HeadDenied,
    #[error("external monotonic authority local intent denied")]
    LocalIntentDenied,
    #[error("external monotonic authority head transition denied")]
    HeadTransitionDenied,
    #[error("external monotonic authority stale or rolled-back head denied")]
    StaleHeadDenied,
    #[error("external monotonic authority forked head denied")]
    ForkedHeadDenied,
    #[error("external monotonic authority prepared transition conflict")]
    PreparedTransitionConflict,
    #[error("external monotonic authority local durability proof mismatch")]
    LocalDurabilityMismatch,
    #[error("external monotonic authority operation failed before mutation")]
    KnownNoMutation,
    #[error("external monotonic authority commit status is unknown")]
    CommitUnknown,
    #[error("external monotonic authority is permanently fail-stopped")]
    FailStopped,
}

type ContractResult<T> = Result<T, ContractError>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionAnchorPayloadV1 {
    schema: String,
    authority_identity_sha256: Digest,
    provision_epoch: u64,
    store_instance_id_sha256: Digest,
    manifest_sha256: Digest,
    genesis_payload_sha256: Digest,
    state_directory_identity_sha256: Digest,
    writer_lock_file_identity_sha256: Digest,
    initial_local_state_sequence: u64,
    initial_local_state_sha256: Digest,
    provision_anchor_sha256: Digest,
}

#[cfg(test)]
struct ProvisionAnchorInputs {
    authority_identity_sha256: Digest,
    provision_epoch: u64,
    store_instance_id_sha256: Digest,
    manifest_sha256: Digest,
    genesis_payload_sha256: Digest,
    state_directory_identity_sha256: Digest,
    writer_lock_file_identity_sha256: Digest,
    initial_local_state_sha256: Digest,
}

impl ProvisionAnchorPayloadV1 {
    #[cfg(test)]
    fn build(inputs: ProvisionAnchorInputs) -> ContractResult<Self> {
        let mut value = Self {
            schema: PROVISION_ANCHOR_SCHEMA.to_string(),
            authority_identity_sha256: inputs.authority_identity_sha256,
            provision_epoch: inputs.provision_epoch,
            store_instance_id_sha256: inputs.store_instance_id_sha256,
            manifest_sha256: inputs.manifest_sha256,
            genesis_payload_sha256: inputs.genesis_payload_sha256,
            state_directory_identity_sha256: inputs.state_directory_identity_sha256,
            writer_lock_file_identity_sha256: inputs.writer_lock_file_identity_sha256,
            initial_local_state_sequence: 1,
            initial_local_state_sha256: inputs.initial_local_state_sha256,
            provision_anchor_sha256: inputs.initial_local_state_sha256,
        };
        value.provision_anchor_sha256 = value.expected_sha256()?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> ContractResult<()> {
        if self.schema != PROVISION_ANCHOR_SCHEMA
            || self.provision_epoch == 0
            || self.initial_local_state_sequence != 1
            || self.expected_sha256()? != self.provision_anchor_sha256
        {
            return Err(ContractError::ProvisionAnchorDenied);
        }
        Ok(())
    }

    fn expected_sha256(&self) -> ContractResult<Digest> {
        domain_digest(
            PROVISION_ANCHOR_DOMAIN,
            &canonical_json(&ProvisionAnchorPreimage {
                schema: &self.schema,
                authority_identity_sha256: self.authority_identity_sha256,
                provision_epoch: self.provision_epoch,
                store_instance_id_sha256: self.store_instance_id_sha256,
                manifest_sha256: self.manifest_sha256,
                genesis_payload_sha256: self.genesis_payload_sha256,
                state_directory_identity_sha256: self.state_directory_identity_sha256,
                writer_lock_file_identity_sha256: self.writer_lock_file_identity_sha256,
                initial_local_state_sequence: self.initial_local_state_sequence,
                initial_local_state_sha256: self.initial_local_state_sha256,
            })?,
        )
    }
}

#[derive(Serialize)]
struct ProvisionAnchorPreimage<'a> {
    schema: &'a str,
    authority_identity_sha256: Digest,
    provision_epoch: u64,
    store_instance_id_sha256: Digest,
    manifest_sha256: Digest,
    genesis_payload_sha256: Digest,
    state_directory_identity_sha256: Digest,
    writer_lock_file_identity_sha256: Digest,
    initial_local_state_sequence: u64,
    initial_local_state_sha256: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MonotonicHeadV1 {
    schema: String,
    authority_identity_sha256: Digest,
    provision_anchor_sha256: Digest,
    store_instance_id_sha256: Digest,
    generation: u64,
    local_state_sequence: u64,
    local_state_sha256: Digest,
    predecessor_head_sha256: Option<Digest>,
    transition_sha256: Option<Digest>,
    head_sha256: Digest,
}

impl MonotonicHeadV1 {
    #[cfg(test)]
    fn genesis(anchor: &ProvisionAnchorPayloadV1) -> ContractResult<Self> {
        anchor.validate()?;
        let mut value = Self {
            schema: MONOTONIC_HEAD_SCHEMA.to_string(),
            authority_identity_sha256: anchor.authority_identity_sha256,
            provision_anchor_sha256: anchor.provision_anchor_sha256,
            store_instance_id_sha256: anchor.store_instance_id_sha256,
            generation: 1,
            local_state_sequence: anchor.initial_local_state_sequence,
            local_state_sha256: anchor.initial_local_state_sha256,
            predecessor_head_sha256: None,
            transition_sha256: None,
            head_sha256: anchor.initial_local_state_sha256,
        };
        value.head_sha256 = value.expected_sha256()?;
        value.validate(anchor)?;
        Ok(value)
    }

    fn validate(&self, anchor: &ProvisionAnchorPayloadV1) -> ContractResult<()> {
        anchor.validate()?;
        let genesis = self.generation == 1;
        if self.schema != MONOTONIC_HEAD_SCHEMA
            || self.authority_identity_sha256 != anchor.authority_identity_sha256
            || self.provision_anchor_sha256 != anchor.provision_anchor_sha256
            || self.store_instance_id_sha256 != anchor.store_instance_id_sha256
            || self.generation == 0
            || self.local_state_sequence < self.generation
            || genesis != self.predecessor_head_sha256.is_none()
            || genesis != self.transition_sha256.is_none()
            || (genesis
                && (self.local_state_sequence != anchor.initial_local_state_sequence
                    || self.local_state_sha256 != anchor.initial_local_state_sha256))
            || self.expected_sha256()? != self.head_sha256
        {
            return Err(ContractError::HeadDenied);
        }
        Ok(())
    }

    fn expected_sha256(&self) -> ContractResult<Digest> {
        domain_digest(
            MONOTONIC_HEAD_DOMAIN,
            &canonical_json(&MonotonicHeadPreimage {
                schema: &self.schema,
                authority_identity_sha256: self.authority_identity_sha256,
                provision_anchor_sha256: self.provision_anchor_sha256,
                store_instance_id_sha256: self.store_instance_id_sha256,
                generation: self.generation,
                local_state_sequence: self.local_state_sequence,
                local_state_sha256: self.local_state_sha256,
                predecessor_head_sha256: self.predecessor_head_sha256,
                transition_sha256: self.transition_sha256,
            })?,
        )
    }
}

#[derive(Serialize)]
struct MonotonicHeadPreimage<'a> {
    schema: &'a str,
    authority_identity_sha256: Digest,
    provision_anchor_sha256: Digest,
    store_instance_id_sha256: Digest,
    generation: u64,
    local_state_sequence: u64,
    local_state_sha256: Digest,
    predecessor_head_sha256: Option<Digest>,
    transition_sha256: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalTransitionIntentV1 {
    schema: String,
    authority_identity_sha256: Digest,
    provision_anchor_sha256: Digest,
    store_instance_id_sha256: Digest,
    from_generation: u64,
    from_head_sha256: Digest,
    from_local_state_sequence: u64,
    from_local_state_sha256: Digest,
    to_generation: u64,
    candidate_local_state_sequence: u64,
    candidate_local_state_sha256: Digest,
    intent_nonce_sha256: Digest,
    intent_sha256: Digest,
}

fn next_generation(generation: u64) -> ContractResult<u64> {
    generation
        .checked_add(1)
        .ok_or(ContractError::LocalIntentDenied)
}

impl LocalTransitionIntentV1 {
    #[cfg(test)]
    fn build(
        anchor: &ProvisionAnchorPayloadV1,
        head: &MonotonicHeadV1,
        candidate_local_state_sequence: u64,
        candidate_local_state_sha256: Digest,
        intent_nonce_sha256: Digest,
    ) -> ContractResult<Self> {
        head.validate(anchor)?;
        let to_generation = next_generation(head.generation)?;
        let mut value = Self {
            schema: LOCAL_TRANSITION_INTENT_SCHEMA.to_string(),
            authority_identity_sha256: anchor.authority_identity_sha256,
            provision_anchor_sha256: anchor.provision_anchor_sha256,
            store_instance_id_sha256: anchor.store_instance_id_sha256,
            from_generation: head.generation,
            from_head_sha256: head.head_sha256,
            from_local_state_sequence: head.local_state_sequence,
            from_local_state_sha256: head.local_state_sha256,
            to_generation,
            candidate_local_state_sequence,
            candidate_local_state_sha256,
            intent_nonce_sha256,
            intent_sha256: intent_nonce_sha256,
        };
        value.intent_sha256 = value.expected_sha256()?;
        value.validate(anchor, head)?;
        Ok(value)
    }

    fn validate(
        &self,
        anchor: &ProvisionAnchorPayloadV1,
        head: &MonotonicHeadV1,
    ) -> ContractResult<()> {
        anchor.validate()?;
        head.validate(anchor)?;
        let expected_to_generation = next_generation(self.from_generation)?;
        if self.schema != LOCAL_TRANSITION_INTENT_SCHEMA
            || self.authority_identity_sha256 != anchor.authority_identity_sha256
            || self.provision_anchor_sha256 != anchor.provision_anchor_sha256
            || self.store_instance_id_sha256 != anchor.store_instance_id_sha256
            || self.from_generation != head.generation
            || self.from_head_sha256 != head.head_sha256
            || self.from_local_state_sequence != head.local_state_sequence
            || self.from_local_state_sha256 != head.local_state_sha256
            || self.to_generation != expected_to_generation
            || self.candidate_local_state_sequence <= self.from_local_state_sequence
            || self.expected_sha256()? != self.intent_sha256
        {
            return Err(ContractError::LocalIntentDenied);
        }
        Ok(())
    }

    fn expected_sha256(&self) -> ContractResult<Digest> {
        domain_digest(
            LOCAL_TRANSITION_INTENT_DOMAIN,
            &canonical_json(&LocalTransitionIntentPreimage {
                schema: &self.schema,
                authority_identity_sha256: self.authority_identity_sha256,
                provision_anchor_sha256: self.provision_anchor_sha256,
                store_instance_id_sha256: self.store_instance_id_sha256,
                from_generation: self.from_generation,
                from_head_sha256: self.from_head_sha256,
                from_local_state_sequence: self.from_local_state_sequence,
                from_local_state_sha256: self.from_local_state_sha256,
                to_generation: self.to_generation,
                candidate_local_state_sequence: self.candidate_local_state_sequence,
                candidate_local_state_sha256: self.candidate_local_state_sha256,
                intent_nonce_sha256: self.intent_nonce_sha256,
            })?,
        )
    }
}

#[derive(Serialize)]
struct LocalTransitionIntentPreimage<'a> {
    schema: &'a str,
    authority_identity_sha256: Digest,
    provision_anchor_sha256: Digest,
    store_instance_id_sha256: Digest,
    from_generation: u64,
    from_head_sha256: Digest,
    from_local_state_sequence: u64,
    from_local_state_sha256: Digest,
    to_generation: u64,
    candidate_local_state_sequence: u64,
    candidate_local_state_sha256: Digest,
    intent_nonce_sha256: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadTransitionV1 {
    schema: String,
    authority_identity_sha256: Digest,
    provision_anchor_sha256: Digest,
    store_instance_id_sha256: Digest,
    from_generation: u64,
    from_head_sha256: Digest,
    from_local_state_sequence: u64,
    from_local_state_sha256: Digest,
    to_generation: u64,
    to_local_state_sequence: u64,
    to_local_state_sha256: Digest,
    local_transition_intent_sha256: Digest,
    transition_sha256: Digest,
}

impl HeadTransitionV1 {
    #[cfg(test)]
    fn build(
        anchor: &ProvisionAnchorPayloadV1,
        head: &MonotonicHeadV1,
        intent: &LocalTransitionIntentV1,
    ) -> ContractResult<Self> {
        intent.validate(anchor, head)?;
        let mut value = Self {
            schema: HEAD_TRANSITION_SCHEMA.to_string(),
            authority_identity_sha256: anchor.authority_identity_sha256,
            provision_anchor_sha256: anchor.provision_anchor_sha256,
            store_instance_id_sha256: anchor.store_instance_id_sha256,
            from_generation: intent.from_generation,
            from_head_sha256: intent.from_head_sha256,
            from_local_state_sequence: intent.from_local_state_sequence,
            from_local_state_sha256: intent.from_local_state_sha256,
            to_generation: intent.to_generation,
            to_local_state_sequence: intent.candidate_local_state_sequence,
            to_local_state_sha256: intent.candidate_local_state_sha256,
            local_transition_intent_sha256: intent.intent_sha256,
            transition_sha256: intent.intent_sha256,
        };
        value.transition_sha256 = value.expected_sha256()?;
        value.validate(anchor, head, intent)?;
        Ok(value)
    }

    fn validate(
        &self,
        anchor: &ProvisionAnchorPayloadV1,
        head: &MonotonicHeadV1,
        intent: &LocalTransitionIntentV1,
    ) -> ContractResult<()> {
        intent.validate(anchor, head)?;
        if self.schema != HEAD_TRANSITION_SCHEMA
            || self.authority_identity_sha256 != anchor.authority_identity_sha256
            || self.provision_anchor_sha256 != anchor.provision_anchor_sha256
            || self.store_instance_id_sha256 != anchor.store_instance_id_sha256
            || self.from_generation != intent.from_generation
            || self.from_head_sha256 != intent.from_head_sha256
            || self.from_local_state_sequence != intent.from_local_state_sequence
            || self.from_local_state_sha256 != intent.from_local_state_sha256
            || self.to_generation != intent.to_generation
            || self.to_local_state_sequence != intent.candidate_local_state_sequence
            || self.to_local_state_sha256 != intent.candidate_local_state_sha256
            || self.local_transition_intent_sha256 != intent.intent_sha256
            || self.expected_sha256()? != self.transition_sha256
        {
            return Err(ContractError::HeadTransitionDenied);
        }
        Ok(())
    }

    fn expected_sha256(&self) -> ContractResult<Digest> {
        domain_digest(
            HEAD_TRANSITION_DOMAIN,
            &canonical_json(&HeadTransitionPreimage {
                schema: &self.schema,
                authority_identity_sha256: self.authority_identity_sha256,
                provision_anchor_sha256: self.provision_anchor_sha256,
                store_instance_id_sha256: self.store_instance_id_sha256,
                from_generation: self.from_generation,
                from_head_sha256: self.from_head_sha256,
                from_local_state_sequence: self.from_local_state_sequence,
                from_local_state_sha256: self.from_local_state_sha256,
                to_generation: self.to_generation,
                to_local_state_sequence: self.to_local_state_sequence,
                to_local_state_sha256: self.to_local_state_sha256,
                local_transition_intent_sha256: self.local_transition_intent_sha256,
            })?,
        )
    }
}

#[derive(Serialize)]
struct HeadTransitionPreimage<'a> {
    schema: &'a str,
    authority_identity_sha256: Digest,
    provision_anchor_sha256: Digest,
    store_instance_id_sha256: Digest,
    from_generation: u64,
    from_head_sha256: Digest,
    from_local_state_sequence: u64,
    from_local_state_sha256: Digest,
    to_generation: u64,
    to_local_state_sequence: u64,
    to_local_state_sha256: Digest,
    local_transition_intent_sha256: Digest,
}

fn canonical_json<T: Serialize>(value: &T) -> ContractResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| ContractError::ClosedJsonDenied)
}

fn decode_canonical<T>(bytes: &[u8]) -> ContractResult<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|_| ContractError::ClosedJsonDenied)?;
    if canonical_json(&value)? != bytes {
        return Err(ContractError::NoncanonicalJsonDenied);
    }
    Ok(value)
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> ContractResult<Digest> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload);
    FixedBytes32::new(hasher.finalize().into())
        .map(Digest::new)
        .map_err(|_| ContractError::ClosedJsonDenied)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InjectedFault {
    None,
    BeforeDurableMutation,
    AfterDurableMutation,
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
struct VerifiedLocalDurableState {
    sequence: u64,
    sha256: Digest,
}

#[cfg(test)]
impl VerifiedLocalDurableState {
    fn for_test(sequence: u64, sha256: Digest) -> Self {
        Self { sequence, sha256 }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedTransition {
    intent: LocalTransitionIntentV1,
    transition: HeadTransitionV1,
}

#[cfg(test)]
#[derive(Debug)]
struct InMemoryMonotonicAuthority {
    anchor: ProvisionAnchorPayloadV1,
    committed_head: MonotonicHeadV1,
    prepared: Option<PreparedTransition>,
    last_committed: Option<PreparedTransition>,
    fail_stopped: bool,
}

#[cfg(test)]
impl InMemoryMonotonicAuthority {
    fn for_test(
        anchor: ProvisionAnchorPayloadV1,
        committed_head: MonotonicHeadV1,
    ) -> ContractResult<Self> {
        anchor.validate()?;
        committed_head.validate(&anchor)?;
        if committed_head.generation != 1 {
            return Err(ContractError::HeadDenied);
        }
        Ok(Self {
            anchor,
            committed_head,
            prepared: None,
            last_committed: None,
            fail_stopped: false,
        })
    }

    fn current_head(&self) -> ContractResult<MonotonicHeadV1> {
        self.ensure_available()?;
        Ok(self.committed_head.clone())
    }

    fn require_current_head(&self, candidate: &MonotonicHeadV1) -> ContractResult<()> {
        self.ensure_available()?;
        candidate.validate(&self.anchor)?;
        if candidate.generation < self.committed_head.generation {
            return Err(ContractError::StaleHeadDenied);
        }
        if candidate.generation == self.committed_head.generation
            && candidate.head_sha256 != self.committed_head.head_sha256
        {
            return Err(ContractError::ForkedHeadDenied);
        }
        if candidate != &self.committed_head {
            return Err(ContractError::StaleHeadDenied);
        }
        Ok(())
    }

    fn prepare(
        &mut self,
        intent: &LocalTransitionIntentV1,
        transition: &HeadTransitionV1,
        fault: InjectedFault,
    ) -> ContractResult<PreparedTransition> {
        self.ensure_available()?;
        intent.validate(&self.anchor, &self.committed_head)?;
        transition.validate(&self.anchor, &self.committed_head, intent)?;
        let candidate = PreparedTransition {
            intent: intent.clone(),
            transition: transition.clone(),
        };
        if let Some(prepared) = &self.prepared {
            if prepared == &candidate {
                return Ok(prepared.clone());
            }
            return Err(ContractError::PreparedTransitionConflict);
        }
        if fault == InjectedFault::BeforeDurableMutation {
            return Err(ContractError::KnownNoMutation);
        }
        self.prepared = Some(candidate.clone());
        if fault == InjectedFault::AfterDurableMutation {
            self.fail_stopped = true;
            return Err(ContractError::CommitUnknown);
        }
        Ok(candidate)
    }

    fn commit(
        &mut self,
        prepared: &PreparedTransition,
        durable_local_state: VerifiedLocalDurableState,
        fault: InjectedFault,
    ) -> ContractResult<MonotonicHeadV1> {
        self.ensure_available()?;
        if let Some(last) = &self.last_committed
            && last == prepared
            && durable_local_state.sequence == self.committed_head.local_state_sequence
            && durable_local_state.sha256 == self.committed_head.local_state_sha256
        {
            return Ok(self.committed_head.clone());
        }
        let Some(current) = self.prepared.as_ref() else {
            return Err(ContractError::PreparedTransitionConflict);
        };
        if current != prepared {
            return Err(ContractError::PreparedTransitionConflict);
        }
        if durable_local_state.sequence != prepared.transition.to_local_state_sequence
            || durable_local_state.sha256 != prepared.transition.to_local_state_sha256
        {
            return Err(ContractError::LocalDurabilityMismatch);
        }
        if fault == InjectedFault::BeforeDurableMutation {
            return Err(ContractError::KnownNoMutation);
        }
        let next = self.successor_from_prepared(prepared)?;
        self.committed_head = next.clone();
        self.last_committed = Some(prepared.clone());
        self.prepared = None;
        if fault == InjectedFault::AfterDurableMutation {
            self.fail_stopped = true;
            return Err(ContractError::CommitUnknown);
        }
        Ok(next)
    }

    fn successor_from_prepared(
        &self,
        prepared: &PreparedTransition,
    ) -> ContractResult<MonotonicHeadV1> {
        let mut value = MonotonicHeadV1 {
            schema: MONOTONIC_HEAD_SCHEMA.to_string(),
            authority_identity_sha256: self.anchor.authority_identity_sha256,
            provision_anchor_sha256: self.anchor.provision_anchor_sha256,
            store_instance_id_sha256: self.anchor.store_instance_id_sha256,
            generation: prepared.transition.to_generation,
            local_state_sequence: prepared.transition.to_local_state_sequence,
            local_state_sha256: prepared.transition.to_local_state_sha256,
            predecessor_head_sha256: Some(self.committed_head.head_sha256),
            transition_sha256: Some(prepared.transition.transition_sha256),
            head_sha256: self.committed_head.head_sha256,
        };
        value.head_sha256 = value.expected_sha256()?;
        value.validate(&self.anchor)?;
        Ok(value)
    }

    fn ensure_available(&self) -> ContractResult<()> {
        if self.fail_stopped {
            return Err(ContractError::FailStopped);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> Digest {
        Digest::new(FixedBytes32::new([value; 32]).unwrap())
    }

    fn fixture() -> (
        ProvisionAnchorPayloadV1,
        MonotonicHeadV1,
        LocalTransitionIntentV1,
        HeadTransitionV1,
    ) {
        let anchor = ProvisionAnchorPayloadV1::build(ProvisionAnchorInputs {
            authority_identity_sha256: digest(1),
            provision_epoch: 7,
            store_instance_id_sha256: digest(2),
            manifest_sha256: digest(3),
            genesis_payload_sha256: digest(4),
            state_directory_identity_sha256: digest(5),
            writer_lock_file_identity_sha256: digest(6),
            initial_local_state_sha256: digest(7),
        })
        .unwrap();
        let head = MonotonicHeadV1::genesis(&anchor).unwrap();
        let intent =
            LocalTransitionIntentV1::build(&anchor, &head, 2, digest(8), digest(9)).unwrap();
        let transition = HeadTransitionV1::build(&anchor, &head, &intent).unwrap();
        (anchor, head, intent, transition)
    }

    fn authority() -> (
        InMemoryMonotonicAuthority,
        LocalTransitionIntentV1,
        HeadTransitionV1,
    ) {
        let (anchor, head, intent, transition) = fixture();
        (
            InMemoryMonotonicAuthority::for_test(anchor, head).unwrap(),
            intent,
            transition,
        )
    }

    fn mutate_json<T: Serialize>(value: &T) -> serde_json::Value {
        serde_json::to_value(value).unwrap()
    }

    #[test]
    fn four_contracts_are_canonical_closed_world_and_self_bound() {
        let (anchor, head, intent, transition) = fixture();
        anchor.validate().unwrap();
        head.validate(&anchor).unwrap();
        intent.validate(&anchor, &head).unwrap();
        transition.validate(&anchor, &head, &intent).unwrap();

        let anchor_bytes = canonical_json(&anchor).unwrap();
        let head_bytes = canonical_json(&head).unwrap();
        let intent_bytes = canonical_json(&intent).unwrap();
        let transition_bytes = canonical_json(&transition).unwrap();
        assert_eq!(
            decode_canonical::<ProvisionAnchorPayloadV1>(&anchor_bytes).unwrap(),
            anchor
        );
        assert_eq!(
            decode_canonical::<MonotonicHeadV1>(&head_bytes).unwrap(),
            head
        );
        assert_eq!(
            decode_canonical::<LocalTransitionIntentV1>(&intent_bytes).unwrap(),
            intent
        );
        assert_eq!(
            decode_canonical::<HeadTransitionV1>(&transition_bytes).unwrap(),
            transition
        );
    }

    #[test]
    fn generation_exhaustion_is_a_permanent_local_intent_denial() {
        assert_eq!(
            next_generation(u64::MAX),
            Err(ContractError::LocalIntentDenied)
        );
    }

    #[test]
    fn unknown_missing_and_type_drift_are_rejected_for_every_schema() {
        let (anchor, head, intent, transition) = fixture();
        let cases = [
            mutate_json(&anchor),
            mutate_json(&head),
            mutate_json(&intent),
            mutate_json(&transition),
        ];
        for mut value in cases {
            let object = value.as_object_mut().unwrap();
            object.insert("unknown".to_string(), serde_json::json!(true));
            assert!(serde_json::from_value::<ProvisionAnchorPayloadV1>(value.clone()).is_err());
            assert!(serde_json::from_value::<MonotonicHeadV1>(value.clone()).is_err());
            assert!(serde_json::from_value::<LocalTransitionIntentV1>(value.clone()).is_err());
            assert!(serde_json::from_value::<HeadTransitionV1>(value).is_err());
        }

        let mut missing = mutate_json(&intent);
        missing
            .as_object_mut()
            .unwrap()
            .remove("candidate_local_state_sha256");
        assert!(serde_json::from_value::<LocalTransitionIntentV1>(missing).is_err());
        let mut type_drift = mutate_json(&transition);
        type_drift["to_generation"] = serde_json::json!(2.0);
        assert!(serde_json::from_value::<HeadTransitionV1>(type_drift).is_err());
    }

    #[test]
    fn noncanonical_bytes_are_rejected() {
        let (anchor, _, _, _) = fixture();
        let mut bytes = canonical_json(&anchor).unwrap();
        bytes.push(b'\n');
        assert_eq!(
            decode_canonical::<ProvisionAnchorPayloadV1>(&bytes),
            Err(ContractError::NoncanonicalJsonDenied)
        );
    }

    #[test]
    fn stale_generation_digest_and_rollback_are_rejected() {
        let (mut authority, intent, transition) = authority();
        let old_head = authority.current_head().unwrap();
        let prepared = authority
            .prepare(&intent, &transition, InjectedFault::None)
            .unwrap();
        let new_head = authority
            .commit(
                &prepared,
                VerifiedLocalDurableState::for_test(2, digest(8)),
                InjectedFault::None,
            )
            .unwrap();
        authority.require_current_head(&new_head).unwrap();
        assert_eq!(
            authority.require_current_head(&old_head),
            Err(ContractError::StaleHeadDenied)
        );

        let mut stale = intent.clone();
        stale.from_generation = new_head.generation;
        stale.intent_sha256 = stale.expected_sha256().unwrap();
        assert_eq!(
            authority.prepare(&stale, &transition, InjectedFault::None),
            Err(ContractError::LocalIntentDenied)
        );
        let mut digest_drift = new_head.clone();
        digest_drift.local_state_sha256 = digest(42);
        assert_eq!(
            authority.require_current_head(&digest_drift),
            Err(ContractError::HeadDenied)
        );
    }

    #[test]
    fn same_generation_fork_is_rejected_even_when_self_consistent() {
        let (mut authority, intent, transition) = authority();
        let prepared = authority
            .prepare(&intent, &transition, InjectedFault::None)
            .unwrap();
        authority
            .commit(
                &prepared,
                VerifiedLocalDurableState::for_test(2, digest(8)),
                InjectedFault::None,
            )
            .unwrap();
        let mut fork = authority.current_head().unwrap();
        fork.local_state_sha256 = digest(31);
        fork.head_sha256 = fork.expected_sha256().unwrap();
        assert_eq!(
            authority.require_current_head(&fork),
            Err(ContractError::ForkedHeadDenied)
        );
    }

    #[test]
    fn prepare_and_commit_exact_retry_are_idempotent() {
        let (mut authority, intent, transition) = authority();
        let first = authority
            .prepare(&intent, &transition, InjectedFault::None)
            .unwrap();
        let retry = authority
            .prepare(&intent, &transition, InjectedFault::None)
            .unwrap();
        assert_eq!(first, retry);
        let local = VerifiedLocalDurableState::for_test(2, digest(8));
        let committed = authority
            .commit(&first, local, InjectedFault::None)
            .unwrap();
        let retry = authority
            .commit(
                &first,
                VerifiedLocalDurableState::for_test(2, digest(8)),
                InjectedFault::None,
            )
            .unwrap();
        assert_eq!(committed, retry);
    }

    #[test]
    fn competing_prepare_is_rejected_without_replacing_pending_cas() {
        let (mut authority, intent, transition) = authority();
        let prepared = authority
            .prepare(&intent, &transition, InjectedFault::None)
            .unwrap();
        let mut forked_intent = intent.clone();
        forked_intent.intent_nonce_sha256 = digest(55);
        forked_intent.intent_sha256 = forked_intent.expected_sha256().unwrap();
        let forked_transition =
            HeadTransitionV1::build(&authority.anchor, &authority.committed_head, &forked_intent)
                .unwrap();
        assert_eq!(
            authority.prepare(&forked_intent, &forked_transition, InjectedFault::None),
            Err(ContractError::PreparedTransitionConflict)
        );
        assert_eq!(authority.prepared.as_ref(), Some(&prepared));
    }

    #[test]
    fn local_durability_mismatch_cannot_commit() {
        let (mut authority, intent, transition) = authority();
        let prepared = authority
            .prepare(&intent, &transition, InjectedFault::None)
            .unwrap();
        assert_eq!(
            authority.commit(
                &prepared,
                VerifiedLocalDurableState::for_test(2, digest(99)),
                InjectedFault::None,
            ),
            Err(ContractError::LocalDurabilityMismatch)
        );
        assert_eq!(authority.committed_head.generation, 1);
        assert_eq!(authority.prepared.as_ref(), Some(&prepared));
    }

    #[test]
    fn prepare_fault_boundaries_are_known_no_mutation_or_fail_stop() {
        let (mut before, intent, transition) = authority();
        let original = before.current_head().unwrap();
        assert_eq!(
            before.prepare(&intent, &transition, InjectedFault::BeforeDurableMutation,),
            Err(ContractError::KnownNoMutation)
        );
        assert!(before.prepared.is_none());
        assert_eq!(before.current_head().unwrap(), original);

        let (mut after, intent, transition) = authority();
        assert_eq!(
            after.prepare(&intent, &transition, InjectedFault::AfterDurableMutation,),
            Err(ContractError::CommitUnknown)
        );
        assert!(after.prepared.is_some());
        assert_eq!(after.current_head(), Err(ContractError::FailStopped));
        assert_eq!(
            after.prepare(&intent, &transition, InjectedFault::None),
            Err(ContractError::FailStopped)
        );
    }

    #[test]
    fn commit_fault_boundaries_preserve_retry_or_fail_stop() {
        let (mut before, intent, transition) = authority();
        let prepared = before
            .prepare(&intent, &transition, InjectedFault::None)
            .unwrap();
        assert_eq!(
            before.commit(
                &prepared,
                VerifiedLocalDurableState::for_test(2, digest(8)),
                InjectedFault::BeforeDurableMutation,
            ),
            Err(ContractError::KnownNoMutation)
        );
        assert_eq!(before.committed_head.generation, 1);
        assert_eq!(before.prepared.as_ref(), Some(&prepared));
        before
            .commit(
                &prepared,
                VerifiedLocalDurableState::for_test(2, digest(8)),
                InjectedFault::None,
            )
            .unwrap();

        let (mut after, intent, transition) = authority();
        let prepared = after
            .prepare(&intent, &transition, InjectedFault::None)
            .unwrap();
        assert_eq!(
            after.commit(
                &prepared,
                VerifiedLocalDurableState::for_test(2, digest(8)),
                InjectedFault::AfterDurableMutation,
            ),
            Err(ContractError::CommitUnknown)
        );
        assert_eq!(after.committed_head.generation, 2);
        assert!(after.prepared.is_none());
        assert_eq!(after.current_head(), Err(ContractError::FailStopped));
    }

    #[test]
    fn altered_schema_and_anchor_binding_are_denied_even_with_recomputed_digest() {
        let (anchor, head, intent, transition) = fixture();
        let mut altered_anchor = anchor.clone();
        altered_anchor.schema =
            "org.trillionnium.provider-leaf-provision-anchor-payload.v2".to_string();
        altered_anchor.provision_anchor_sha256 = altered_anchor.expected_sha256().unwrap();
        assert_eq!(
            altered_anchor.validate(),
            Err(ContractError::ProvisionAnchorDenied)
        );

        let mut altered_transition = transition;
        altered_transition.provision_anchor_sha256 = digest(77);
        altered_transition.transition_sha256 = altered_transition.expected_sha256().unwrap();
        assert_eq!(
            altered_transition.validate(&anchor, &head, &intent),
            Err(ContractError::HeadTransitionDenied)
        );
    }

    #[test]
    fn production_authority_and_mutation_gate_remain_absent() {
        const {
            assert!(!EXTERNAL_MONOTONIC_AUTHORITY_FOUNDATION_ENABLED);
        }
        let source = include_str!("lib.rs");
        assert!(!source.contains("InMemoryMonotonicAuthority"));
        assert!(!source.contains("prepare_monotonic"));
        assert!(!source.contains("commit_monotonic"));
    }
}
