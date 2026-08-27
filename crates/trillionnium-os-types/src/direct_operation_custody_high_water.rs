//! Closed wire types for daemon Direct-operation custody high-water.
//!
//! These records are data, never authority. Product authority is retained by
//! the authenticated fixed-path transport and durable client journal in
//! `trillionniumd`; deserializing any record below cannot open a store or
//! authorize an effect.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL: &str =
    "trillionnium.direct-operation-custody-high-water.v2";
pub const DIRECT_OPERATION_CUSTODY_HIGH_WATER_ROUTE_SCHEMA: &str =
    "trillionnium.direct-operation-custody-high-water-route.v2";
pub const DIRECT_OPERATION_CUSTODY_HIGH_WATER_REQUEST_SCHEMA: &str =
    "trillionnium.direct-operation-custody-high-water-request.v2";
pub const DIRECT_OPERATION_CUSTODY_HIGH_WATER_RESPONSE_SCHEMA: &str =
    "trillionnium.direct-operation-custody-high-water-response.v2";
pub const DIRECT_OPERATION_CUSTODY_HIGH_WATER_CONFIRMATION_SCHEMA: &str =
    "trillionnium.direct-operation-custody-high-water-response-confirmation.v2";
pub const DIRECT_OPERATION_CUSTODY_HIGH_WATER_CONFIRMATION_ACK_SCHEMA: &str =
    "trillionnium.direct-operation-custody-high-water-response-confirmation-ack.v2";
pub const DIRECT_OPERATION_CUSTODY_ZERO_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

const ROUTE_DOMAIN: &[u8] = b"trillionnium.direct-operation-custody-high-water-route.v2";
const TRANSITION_DOMAIN: &[u8] = b"trillionnium.direct-operation-custody-high-water-transition.v2";
const OPERATION_ID_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-custody-high-water-operation-id.v2";
const REQUEST_DOMAIN: &[u8] = b"trillionnium.direct-operation-custody-high-water-request.v2";
const RESPONSE_DOMAIN: &[u8] = b"trillionnium.direct-operation-custody-high-water-response.v2";
const CONFIRMATION_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-custody-high-water-response-confirmation.v2";
const CONFIRMATION_ACK_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-custody-high-water-response-confirmation-ack.v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationCustodyHead {
    pub generation: u64,
    pub store_sha256: String,
}

impl DirectOperationCustodyHead {
    pub fn new(generation: u64, store_sha256: String) -> Result<Self, &'static str> {
        let head = Self {
            generation,
            store_sha256,
        };
        head.validate()?;
        Ok(head)
    }

    pub fn genesis() -> Self {
        Self {
            generation: 0,
            store_sha256: DIRECT_OPERATION_CUSTODY_ZERO_SHA256.to_string(),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if (self.generation == 0 && self.store_sha256 != DIRECT_OPERATION_CUSTODY_ZERO_SHA256)
            || (self.generation > 0 && !valid_nonzero_sha256(&self.store_sha256))
        {
            return Err("direct_operation_custody_high_water_head_denied");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationCustodyHighWaterRouteV1 {
    pub schema: String,
    pub protocol: String,
    pub custody_store_path_sha256: String,
    pub client_journal_path_sha256: String,
    pub authority_socket_path_sha256: String,
    pub authority_selinux_domain_sha256: String,
    pub route_sha256: String,
}

impl DirectOperationCustodyHighWaterRouteV1 {
    pub fn derive(
        custody_store_path_sha256: String,
        client_journal_path_sha256: String,
        authority_socket_path_sha256: String,
        authority_selinux_domain_sha256: String,
    ) -> Result<Self, &'static str> {
        let mut route = Self {
            schema: DIRECT_OPERATION_CUSTODY_HIGH_WATER_ROUTE_SCHEMA.to_string(),
            protocol: DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL.to_string(),
            custody_store_path_sha256,
            client_journal_path_sha256,
            authority_socket_path_sha256,
            authority_selinux_domain_sha256,
            route_sha256: String::new(),
        };
        route.route_sha256 = route.expected_sha256();
        route.validate()?;
        Ok(route)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != DIRECT_OPERATION_CUSTODY_HIGH_WATER_ROUTE_SCHEMA
            || self.protocol != DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL
            || !valid_nonzero_sha256(&self.custody_store_path_sha256)
            || !valid_nonzero_sha256(&self.client_journal_path_sha256)
            || !valid_nonzero_sha256(&self.authority_socket_path_sha256)
            || !valid_nonzero_sha256(&self.authority_selinux_domain_sha256)
            || self.expected_sha256() != self.route_sha256
        {
            return Err("direct_operation_custody_high_water_route_denied");
        }
        Ok(())
    }

    fn expected_sha256(&self) -> String {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            protocol: &'a str,
            custody_store_path_sha256: &'a str,
            client_journal_path_sha256: &'a str,
            authority_socket_path_sha256: &'a str,
            authority_selinux_domain_sha256: &'a str,
        }
        domain_digest(
            ROUTE_DOMAIN,
            &Preimage {
                schema: &self.schema,
                protocol: &self.protocol,
                custody_store_path_sha256: &self.custody_store_path_sha256,
                client_journal_path_sha256: &self.client_journal_path_sha256,
                authority_socket_path_sha256: &self.authority_socket_path_sha256,
                authority_selinux_domain_sha256: &self.authority_selinux_domain_sha256,
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectOperationCustodyHighWaterOperation {
    Reconcile,
    Observe,
    Prepare,
    Commit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectOperationCustodyHighWaterDisposition {
    ReconciledExact,
    ObservedExact,
    PreparedExact,
    CommittedExact,
    PermanentHold,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectOperationCustodyHighWaterConfirmationDisposition {
    ResponseConfirmedExact,
    PermanentHold,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationCustodyHighWaterRequestV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: DirectOperationCustodyHighWaterOperation,
    pub route: DirectOperationCustodyHighWaterRouteV1,
    pub current_head: DirectOperationCustodyHead,
    pub proposed_head: Option<DirectOperationCustodyHead>,
    pub transition_sha256: Option<String>,
    pub request_nonce_sha256: String,
    pub operation_id_sha256: String,
    pub request_sha256: String,
}

impl DirectOperationCustodyHighWaterRequestV1 {
    pub fn build(
        operation: DirectOperationCustodyHighWaterOperation,
        route: DirectOperationCustodyHighWaterRouteV1,
        current_head: DirectOperationCustodyHead,
        proposed_head: Option<DirectOperationCustodyHead>,
        transition_sha256: Option<String>,
        request_nonce_sha256: String,
    ) -> Result<Self, &'static str> {
        let mut request = Self {
            schema: DIRECT_OPERATION_CUSTODY_HIGH_WATER_REQUEST_SCHEMA.to_string(),
            protocol: DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL.to_string(),
            operation,
            route,
            current_head,
            proposed_head,
            transition_sha256,
            request_nonce_sha256,
            operation_id_sha256: String::new(),
            request_sha256: String::new(),
        };
        request.operation_id_sha256 = request.expected_operation_id_sha256();
        request.request_sha256 = request.expected_request_sha256();
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        self.route.validate()?;
        self.current_head.validate()?;
        if let Some(proposed) = &self.proposed_head {
            proposed.validate()?;
        }
        let transition_shape = match self.operation {
            DirectOperationCustodyHighWaterOperation::Reconcile
            | DirectOperationCustodyHighWaterOperation::Observe => {
                self.proposed_head.is_none() && self.transition_sha256.is_none()
            }
            DirectOperationCustodyHighWaterOperation::Prepare => {
                let Some(next_generation) = self.current_head.generation.checked_add(1) else {
                    return Err("direct_operation_custody_high_water_generation_overflow");
                };
                self.proposed_head.as_ref().is_some_and(|proposed| {
                    proposed.generation == next_generation
                        && proposed.store_sha256 != self.current_head.store_sha256
                        && self.transition_sha256.as_deref()
                            == Some(
                                transition_sha256(&self.route, &self.current_head, proposed)
                                    .as_str(),
                            )
                })
            }
            DirectOperationCustodyHighWaterOperation::Commit => {
                self.proposed_head.as_ref() == Some(&self.current_head)
                    && self
                        .transition_sha256
                        .as_deref()
                        .is_some_and(valid_nonzero_sha256)
            }
        };
        if self.schema != DIRECT_OPERATION_CUSTODY_HIGH_WATER_REQUEST_SCHEMA
            || self.protocol != DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL
            || !transition_shape
            || !valid_nonzero_sha256(&self.request_nonce_sha256)
            || self.expected_operation_id_sha256() != self.operation_id_sha256
            || self.expected_request_sha256() != self.request_sha256
        {
            return Err("direct_operation_custody_high_water_request_denied");
        }
        Ok(())
    }

    fn expected_operation_id_sha256(&self) -> String {
        #[derive(Serialize)]
        struct Preimage<'a> {
            protocol: &'a str,
            operation: DirectOperationCustodyHighWaterOperation,
            route_sha256: &'a str,
            current_head: &'a DirectOperationCustodyHead,
            proposed_head: &'a Option<DirectOperationCustodyHead>,
            transition_sha256: &'a Option<String>,
            request_nonce_sha256: &'a str,
        }
        domain_digest(
            OPERATION_ID_DOMAIN,
            &Preimage {
                protocol: &self.protocol,
                operation: self.operation,
                route_sha256: &self.route.route_sha256,
                current_head: &self.current_head,
                proposed_head: &self.proposed_head,
                transition_sha256: &self.transition_sha256,
                request_nonce_sha256: &self.request_nonce_sha256,
            },
        )
    }

    fn expected_request_sha256(&self) -> String {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            protocol: &'a str,
            operation: DirectOperationCustodyHighWaterOperation,
            route: &'a DirectOperationCustodyHighWaterRouteV1,
            current_head: &'a DirectOperationCustodyHead,
            proposed_head: &'a Option<DirectOperationCustodyHead>,
            transition_sha256: &'a Option<String>,
            request_nonce_sha256: &'a str,
            operation_id_sha256: &'a str,
        }
        domain_digest(
            REQUEST_DOMAIN,
            &Preimage {
                schema: &self.schema,
                protocol: &self.protocol,
                operation: self.operation,
                route: &self.route,
                current_head: &self.current_head,
                proposed_head: &self.proposed_head,
                transition_sha256: &self.transition_sha256,
                request_nonce_sha256: &self.request_nonce_sha256,
                operation_id_sha256: &self.operation_id_sha256,
            },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationCustodyHighWaterResponseV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: DirectOperationCustodyHighWaterOperation,
    pub disposition: DirectOperationCustodyHighWaterDisposition,
    pub authority_identity_sha256: String,
    pub route_sha256: String,
    pub operation_id_sha256: String,
    pub request_sha256: String,
    pub committed_head: DirectOperationCustodyHead,
    pub transition_sha256: Option<String>,
    pub response_sha256: String,
}

impl DirectOperationCustodyHighWaterResponseV1 {
    pub fn seal(&mut self) {
        self.response_sha256 = self.expected_sha256();
    }

    pub fn validate_binding_for(
        &self,
        request: &DirectOperationCustodyHighWaterRequestV1,
        expected_authority_identity_sha256: &str,
    ) -> Result<(), &'static str> {
        self.committed_head.validate()?;
        if self.schema != DIRECT_OPERATION_CUSTODY_HIGH_WATER_RESPONSE_SCHEMA
            || self.protocol != DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL
            || self.operation != request.operation
            || self.authority_identity_sha256 != expected_authority_identity_sha256
            || self.route_sha256 != request.route.route_sha256
            || self.operation_id_sha256 != request.operation_id_sha256
            || self.request_sha256 != request.request_sha256
            || self.expected_sha256() != self.response_sha256
        {
            return Err("direct_operation_custody_high_water_response_binding_denied");
        }
        let exact = if self.disposition == DirectOperationCustodyHighWaterDisposition::PermanentHold
        {
            self.transition_sha256 == request.transition_sha256
        } else {
            match request.operation {
                DirectOperationCustodyHighWaterOperation::Reconcile => {
                    self.disposition == DirectOperationCustodyHighWaterDisposition::ReconciledExact
                        && self.committed_head == request.current_head
                        && self.transition_sha256.is_none()
                }
                DirectOperationCustodyHighWaterOperation::Observe => {
                    self.disposition == DirectOperationCustodyHighWaterDisposition::ObservedExact
                        && self.committed_head == request.current_head
                        && self.transition_sha256.is_none()
                }
                DirectOperationCustodyHighWaterOperation::Prepare => {
                    self.disposition == DirectOperationCustodyHighWaterDisposition::PreparedExact
                        && self.committed_head == request.current_head
                        && self.transition_sha256 == request.transition_sha256
                }
                DirectOperationCustodyHighWaterOperation::Commit => {
                    self.disposition == DirectOperationCustodyHighWaterDisposition::CommittedExact
                        && self.committed_head == request.current_head
                        && self.transition_sha256 == request.transition_sha256
                }
            }
        };
        if !exact {
            return Err("direct_operation_custody_high_water_response_state_denied");
        }
        Ok(())
    }

    pub fn require_success(&self) -> Result<(), &'static str> {
        if self.disposition == DirectOperationCustodyHighWaterDisposition::PermanentHold {
            return Err("direct_operation_custody_high_water_authority_permanent_hold");
        }
        Ok(())
    }

    fn expected_sha256(&self) -> String {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            protocol: &'a str,
            operation: DirectOperationCustodyHighWaterOperation,
            disposition: DirectOperationCustodyHighWaterDisposition,
            authority_identity_sha256: &'a str,
            route_sha256: &'a str,
            operation_id_sha256: &'a str,
            request_sha256: &'a str,
            committed_head: &'a DirectOperationCustodyHead,
            transition_sha256: &'a Option<String>,
        }
        domain_digest(
            RESPONSE_DOMAIN,
            &Preimage {
                schema: &self.schema,
                protocol: &self.protocol,
                operation: self.operation,
                disposition: self.disposition,
                authority_identity_sha256: &self.authority_identity_sha256,
                route_sha256: &self.route_sha256,
                operation_id_sha256: &self.operation_id_sha256,
                request_sha256: &self.request_sha256,
                committed_head: &self.committed_head,
                transition_sha256: &self.transition_sha256,
            },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationCustodyHighWaterResponseConfirmationV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: DirectOperationCustodyHighWaterOperation,
    pub route_sha256: String,
    pub operation_id_sha256: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub client_response_receipt_sha256: String,
    pub confirmation_sha256: String,
}

impl DirectOperationCustodyHighWaterResponseConfirmationV1 {
    pub fn derive(
        request: &DirectOperationCustodyHighWaterRequestV1,
        response: &DirectOperationCustodyHighWaterResponseV1,
        client_response_receipt_sha256: String,
    ) -> Result<Self, &'static str> {
        response.validate_binding_for(request, &response.authority_identity_sha256)?;
        if !valid_nonzero_sha256(&client_response_receipt_sha256) {
            return Err("direct_operation_custody_high_water_client_receipt_denied");
        }
        let mut confirmation = Self {
            schema: DIRECT_OPERATION_CUSTODY_HIGH_WATER_CONFIRMATION_SCHEMA.to_string(),
            protocol: DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL.to_string(),
            operation: request.operation,
            route_sha256: request.route.route_sha256.clone(),
            operation_id_sha256: request.operation_id_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            response_sha256: response.response_sha256.clone(),
            client_response_receipt_sha256,
            confirmation_sha256: String::new(),
        };
        confirmation.confirmation_sha256 = confirmation.expected_sha256();
        confirmation.validate()?;
        Ok(confirmation)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != DIRECT_OPERATION_CUSTODY_HIGH_WATER_CONFIRMATION_SCHEMA
            || self.protocol != DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL
            || !valid_nonzero_sha256(&self.route_sha256)
            || !valid_nonzero_sha256(&self.operation_id_sha256)
            || !valid_nonzero_sha256(&self.request_sha256)
            || !valid_nonzero_sha256(&self.response_sha256)
            || !valid_nonzero_sha256(&self.client_response_receipt_sha256)
            || self.expected_sha256() != self.confirmation_sha256
        {
            return Err("direct_operation_custody_high_water_confirmation_denied");
        }
        Ok(())
    }

    fn expected_sha256(&self) -> String {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            protocol: &'a str,
            operation: DirectOperationCustodyHighWaterOperation,
            route_sha256: &'a str,
            operation_id_sha256: &'a str,
            request_sha256: &'a str,
            response_sha256: &'a str,
            client_response_receipt_sha256: &'a str,
        }
        domain_digest(
            CONFIRMATION_DOMAIN,
            &Preimage {
                schema: &self.schema,
                protocol: &self.protocol,
                operation: self.operation,
                route_sha256: &self.route_sha256,
                operation_id_sha256: &self.operation_id_sha256,
                request_sha256: &self.request_sha256,
                response_sha256: &self.response_sha256,
                client_response_receipt_sha256: &self.client_response_receipt_sha256,
            },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationCustodyHighWaterResponseConfirmationAckV1 {
    pub schema: String,
    pub protocol: String,
    pub disposition: DirectOperationCustodyHighWaterConfirmationDisposition,
    pub authority_identity_sha256: String,
    pub route_sha256: String,
    pub operation_id_sha256: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub client_response_receipt_sha256: String,
    pub confirmation_sha256: String,
    pub confirmation_ack_sha256: String,
}

impl DirectOperationCustodyHighWaterResponseConfirmationAckV1 {
    pub fn seal(&mut self) {
        self.confirmation_ack_sha256 = self.expected_sha256();
    }

    pub fn validate_for(
        &self,
        confirmation: &DirectOperationCustodyHighWaterResponseConfirmationV1,
        expected_authority_identity_sha256: &str,
    ) -> Result<(), &'static str> {
        confirmation.validate()?;
        if self.schema != DIRECT_OPERATION_CUSTODY_HIGH_WATER_CONFIRMATION_ACK_SCHEMA
            || self.protocol != DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL
            || self.authority_identity_sha256 != expected_authority_identity_sha256
            || self.route_sha256 != confirmation.route_sha256
            || self.operation_id_sha256 != confirmation.operation_id_sha256
            || self.request_sha256 != confirmation.request_sha256
            || self.response_sha256 != confirmation.response_sha256
            || self.client_response_receipt_sha256 != confirmation.client_response_receipt_sha256
            || self.confirmation_sha256 != confirmation.confirmation_sha256
            || self.expected_sha256() != self.confirmation_ack_sha256
        {
            return Err("direct_operation_custody_high_water_confirmation_ack_binding_denied");
        }
        if self.disposition == DirectOperationCustodyHighWaterConfirmationDisposition::PermanentHold
        {
            return Err("direct_operation_custody_high_water_confirmation_permanent_hold");
        }
        if self.disposition
            != DirectOperationCustodyHighWaterConfirmationDisposition::ResponseConfirmedExact
        {
            return Err("direct_operation_custody_high_water_confirmation_ack_state_denied");
        }
        Ok(())
    }

    fn expected_sha256(&self) -> String {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            protocol: &'a str,
            disposition: DirectOperationCustodyHighWaterConfirmationDisposition,
            authority_identity_sha256: &'a str,
            route_sha256: &'a str,
            operation_id_sha256: &'a str,
            request_sha256: &'a str,
            response_sha256: &'a str,
            client_response_receipt_sha256: &'a str,
            confirmation_sha256: &'a str,
        }
        domain_digest(
            CONFIRMATION_ACK_DOMAIN,
            &Preimage {
                schema: &self.schema,
                protocol: &self.protocol,
                disposition: self.disposition,
                authority_identity_sha256: &self.authority_identity_sha256,
                route_sha256: &self.route_sha256,
                operation_id_sha256: &self.operation_id_sha256,
                request_sha256: &self.request_sha256,
                response_sha256: &self.response_sha256,
                client_response_receipt_sha256: &self.client_response_receipt_sha256,
                confirmation_sha256: &self.confirmation_sha256,
            },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "frame", content = "payload", rename_all = "snake_case")]
pub enum DirectOperationCustodyHighWaterClientFrameV1 {
    Operation(DirectOperationCustodyHighWaterRequestV1),
    ConfirmResponse(DirectOperationCustodyHighWaterResponseConfirmationV1),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "frame", content = "payload", rename_all = "snake_case")]
pub enum DirectOperationCustodyHighWaterServerFrameV1 {
    OperationResponse(DirectOperationCustodyHighWaterResponseV1),
    ConfirmResponseAck(DirectOperationCustodyHighWaterResponseConfirmationAckV1),
}

pub fn transition_sha256(
    route: &DirectOperationCustodyHighWaterRouteV1,
    from: &DirectOperationCustodyHead,
    to: &DirectOperationCustodyHead,
) -> String {
    #[derive(Serialize)]
    struct Preimage<'a> {
        protocol: &'a str,
        route_sha256: &'a str,
        from: &'a DirectOperationCustodyHead,
        to: &'a DirectOperationCustodyHead,
    }
    domain_digest(
        TRANSITION_DOMAIN,
        &Preimage {
            protocol: DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL,
            route_sha256: &route.route_sha256,
            from,
            to,
        },
    )
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("closed high-water record serializes");
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"domain", domain);
    hash_field(&mut hasher, b"value", &bytes);
    format!("{:x}", hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value != DIRECT_OPERATION_CUSTODY_ZERO_SHA256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> String {
        format!("{:x}", Sha256::digest(label.as_bytes()))
    }

    fn route() -> DirectOperationCustodyHighWaterRouteV1 {
        DirectOperationCustodyHighWaterRouteV1::derive(
            digest("custody-path"),
            digest("journal-path"),
            digest("authority-socket"),
            digest("authority-domain"),
        )
        .unwrap()
    }

    #[test]
    fn operation_response_confirmation_and_ack_are_exactly_cross_bound() {
        let from = DirectOperationCustodyHead::genesis();
        let to = DirectOperationCustodyHead::new(1, digest("store")).unwrap();
        let route = route();
        let transition = transition_sha256(&route, &from, &to);
        let request = DirectOperationCustodyHighWaterRequestV1::build(
            DirectOperationCustodyHighWaterOperation::Prepare,
            route.clone(),
            from.clone(),
            Some(to),
            Some(transition.clone()),
            digest("nonce"),
        )
        .unwrap();
        let mut response = DirectOperationCustodyHighWaterResponseV1 {
            schema: DIRECT_OPERATION_CUSTODY_HIGH_WATER_RESPONSE_SCHEMA.to_string(),
            protocol: DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL.to_string(),
            operation: request.operation,
            disposition: DirectOperationCustodyHighWaterDisposition::PreparedExact,
            authority_identity_sha256: digest("authority"),
            route_sha256: request.route.route_sha256.clone(),
            operation_id_sha256: request.operation_id_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            committed_head: from,
            transition_sha256: Some(transition),
            response_sha256: String::new(),
        };
        response.seal();
        response
            .validate_binding_for(&request, &digest("authority"))
            .unwrap();
        let confirmation = DirectOperationCustodyHighWaterResponseConfirmationV1::derive(
            &request,
            &response,
            digest("durable-client-response-receipt"),
        )
        .unwrap();
        let mut ack = DirectOperationCustodyHighWaterResponseConfirmationAckV1 {
            schema: DIRECT_OPERATION_CUSTODY_HIGH_WATER_CONFIRMATION_ACK_SCHEMA.to_string(),
            protocol: DIRECT_OPERATION_CUSTODY_HIGH_WATER_PROTOCOL.to_string(),
            disposition:
                DirectOperationCustodyHighWaterConfirmationDisposition::ResponseConfirmedExact,
            authority_identity_sha256: digest("authority"),
            route_sha256: confirmation.route_sha256.clone(),
            operation_id_sha256: confirmation.operation_id_sha256.clone(),
            request_sha256: confirmation.request_sha256.clone(),
            response_sha256: confirmation.response_sha256.clone(),
            client_response_receipt_sha256: confirmation.client_response_receipt_sha256.clone(),
            confirmation_sha256: confirmation.confirmation_sha256.clone(),
            confirmation_ack_sha256: String::new(),
        };
        ack.seal();
        ack.validate_for(&confirmation, &digest("authority"))
            .unwrap();

        let mut drift = confirmation;
        drift.response_sha256 = digest("other-response");
        assert!(drift.validate().is_err());
    }

    #[test]
    fn generation_overflow_unknown_fields_and_route_domain_replay_are_rejected() {
        let max = DirectOperationCustodyHead::new(u64::MAX, digest("max-store")).unwrap();
        let proposed = DirectOperationCustodyHead::new(1, digest("wrapped-store")).unwrap();
        assert!(
            DirectOperationCustodyHighWaterRequestV1::build(
                DirectOperationCustodyHighWaterOperation::Prepare,
                route(),
                max,
                Some(proposed),
                Some(digest("fake-transition")),
                digest("nonce"),
            )
            .is_err()
        );

        let mut drifted_route = route();
        drifted_route.client_journal_path_sha256 = digest("other-journal-domain");
        assert!(drifted_route.validate().is_err());

        let mut value = serde_json::to_value(
            DirectOperationCustodyHighWaterRequestV1::build(
                DirectOperationCustodyHighWaterOperation::Observe,
                route(),
                DirectOperationCustodyHead::genesis(),
                None,
                None,
                digest("nonce"),
            )
            .unwrap(),
        )
        .unwrap();
        value["ambient_authority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<DirectOperationCustodyHighWaterRequestV1>(value).is_err());
    }
}
