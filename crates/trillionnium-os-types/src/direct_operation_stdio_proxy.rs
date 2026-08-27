//! Closed byte-exact contract for the source-only Codex System API stdio proxy.
//!
//! The fixed route has no provider, adapter, executable, package, action, PID,
//! credential, cgroup, path, argv, environment, delivery-token, or effect
//! selector on the wire. The proxy classifies only the outer MCP JSON-RPC
//! method and the fixed System API tool name. `tools/call.arguments` remains an
//! opaque [`serde_json::value::RawValue`] and the original request bytes are
//! forwarded without normalization or reserialization.
//!
//! These data and sequence checks confer no authority. There is no product
//! listener, daemon broker, logical-delivery producer, adapter launch, backend,
//! or acknowledgement wiring in this checkpoint.

use std::borrow::Cow;
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Deserializer};
use serde_json::Value;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use crate::agent_descriptor_registry::CODEX;

pub const PROTOCOL: &str = "trillionnium.codex-system-api-stdio-proxy.v1";
pub const FIXED_PROVIDER_ID: &str = CODEX.provider_id;
pub const FIXED_AGENT_ID: &str = CODEX.agent_id;
pub const FIXED_TOOL_NAME: &str = "trillionnium_system_api";
pub const FIXED_ADAPTER_ID: &str = "system_api";

pub const MAXIMUM_MCP_REQUEST_BYTES: usize = 256 * 1024;
pub const MAXIMUM_MCP_RESPONSE_BYTES: usize = 1024 * 1024;
pub const NONCE_BYTES: usize = 32;

pub const SOURCE_PROTOCOL_IMPLEMENTED: bool = true;
pub const SOURCE_PROXY_IMPLEMENTED: bool = true;
pub const PRODUCT_PROXY_PACKAGED: bool = false;
pub const PRODUCT_ENTRY_CONFINEMENT_WIRED: bool = false;
pub const PRODUCT_LISTENER_WIRED: bool = false;
pub const PRODUCT_DAEMON_BROKER_WIRED: bool = false;
pub const PRODUCT_LOGICAL_DELIVERY_WIRED: bool = false;
pub const PRODUCT_ADAPTER_LAUNCH_WIRED: bool = false;
pub const FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE: bool = false;
pub const ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

const WIRE_MAGIC: [u8; 8] = *b"TRSPX001";
const WIRE_VERSION: u8 = 1;
const WIRE_HEADER_BYTES: usize = 124;
const ZERO_NONCE: [u8; NONCE_BYTES] = [0; NONCE_BYTES];
#[cfg(test)]
const EMPTY_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

pub const MAXIMUM_WIRE_PACKET_BYTES: usize = WIRE_HEADER_BYTES + MAXIMUM_MCP_RESPONSE_BYTES;

pub type StdioProxyResult<T> = Result<T, StdioProxyProtocolError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdioProxyProtocolError(&'static str);

impl StdioProxyProtocolError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for StdioProxyProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for StdioProxyProtocolError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdioProxyPacketKind {
    Hello,
    Welcome,
    McpFrame,
    McpResult,
}

impl StdioProxyPacketKind {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Hello => 1,
            Self::Welcome => 2,
            Self::McpFrame => 3,
            Self::McpResult => 4,
        }
    }

    fn from_wire(value: u8) -> StdioProxyResult<Self> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Welcome),
            3 => Ok(Self::McpFrame),
            4 => Ok(Self::McpResult),
            _ => Err(denied("stdio_proxy_packet_kind_denied")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdioProxyResultDisposition {
    Response,
    NoResponse,
    Denied,
}

impl StdioProxyResultDisposition {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Response => 1,
            Self::NoResponse => 2,
            Self::Denied => 3,
        }
    }

    fn from_wire(value: u8) -> StdioProxyResult<Self> {
        match value {
            1 => Ok(Self::Response),
            2 => Ok(Self::NoResponse),
            3 => Ok(Self::Denied),
            _ => Err(denied("stdio_proxy_result_disposition_denied")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexSystemApiMcpMethod {
    Initialize,
    InitializedNotification,
    Ping,
    ToolsList,
    SystemApiToolCall,
}

/// A borrowed view proving only the fixed outer MCP route. The payload accessor
/// returns the exact caller bytes; there is no arguments accessor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ValidatedCodexSystemApiMcpFrame<'a> {
    payload: &'a [u8],
    method: CodexSystemApiMcpMethod,
}

impl fmt::Debug for ValidatedCodexSystemApiMcpFrame<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedCodexSystemApiMcpFrame")
            .field("payload_bytes", &self.payload.len())
            .field("method", &self.method)
            .finish()
    }
}

impl<'a> ValidatedCodexSystemApiMcpFrame<'a> {
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }

    #[must_use]
    pub const fn method(self) -> CodexSystemApiMcpMethod {
        self.method
    }
}

/// One validated wire packet. Fields remain private so callers must use the
/// fixed constructors or the closed decoder.
#[derive(Clone, Eq, PartialEq)]
pub struct StdioProxyPacket {
    kind: StdioProxyPacketKind,
    disposition: Option<StdioProxyResultDisposition>,
    sequence: u64,
    session_nonce: [u8; NONCE_BYTES],
    correlation_nonce: [u8; NONCE_BYTES],
    payload: Vec<u8>,
}

impl fmt::Debug for StdioProxyPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdioProxyPacket")
            .field("kind", &self.kind)
            .field("disposition", &self.disposition)
            .field("sequence", &self.sequence)
            .field("session_nonce", &"<redacted>")
            .field("correlation_nonce", &"<redacted>")
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

impl StdioProxyPacket {
    pub fn hello(proxy_nonce: [u8; NONCE_BYTES]) -> StdioProxyResult<Self> {
        require_nonzero_nonce(&proxy_nonce)?;
        let value = Self {
            kind: StdioProxyPacketKind::Hello,
            disposition: None,
            sequence: 0,
            session_nonce: ZERO_NONCE,
            correlation_nonce: proxy_nonce,
            payload: Vec::new(),
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn welcome(
        proxy_nonce: [u8; NONCE_BYTES],
        daemon_session_nonce: [u8; NONCE_BYTES],
    ) -> StdioProxyResult<Self> {
        require_nonzero_nonce(&proxy_nonce)?;
        require_nonzero_nonce(&daemon_session_nonce)?;
        if proxy_nonce == daemon_session_nonce {
            return Err(denied("stdio_proxy_nonce_alias_denied"));
        }
        let value = Self {
            kind: StdioProxyPacketKind::Welcome,
            disposition: None,
            sequence: 0,
            session_nonce: daemon_session_nonce,
            correlation_nonce: proxy_nonce,
            payload: Vec::new(),
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn mcp_frame(
        daemon_session_nonce: [u8; NONCE_BYTES],
        sequence: u64,
        payload: &[u8],
    ) -> StdioProxyResult<Self> {
        require_nonzero_nonce(&daemon_session_nonce)?;
        validate_codex_system_api_mcp_frame(payload)?;
        let value = Self {
            kind: StdioProxyPacketKind::McpFrame,
            disposition: None,
            sequence,
            session_nonce: daemon_session_nonce,
            correlation_nonce: ZERO_NONCE,
            payload: payload.to_vec(),
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn mcp_result(
        daemon_session_nonce: [u8; NONCE_BYTES],
        sequence: u64,
        disposition: StdioProxyResultDisposition,
        payload: &[u8],
    ) -> StdioProxyResult<Self> {
        require_nonzero_nonce(&daemon_session_nonce)?;
        let value = Self {
            kind: StdioProxyPacketKind::McpResult,
            disposition: Some(disposition),
            sequence,
            session_nonce: daemon_session_nonce,
            correlation_nonce: ZERO_NONCE,
            payload: payload.to_vec(),
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn decode(bytes: &[u8]) -> StdioProxyResult<Self> {
        if bytes.len() < WIRE_HEADER_BYTES || bytes.len() > MAXIMUM_WIRE_PACKET_BYTES {
            return Err(denied("stdio_proxy_packet_length_denied"));
        }
        if bytes[..8] != WIRE_MAGIC
            || bytes[8] != WIRE_VERSION
            || bytes[11] != 0
            || bytes[12..16].iter().any(|byte| *byte != 0)
        {
            return Err(denied("stdio_proxy_packet_header_denied"));
        }
        let kind = StdioProxyPacketKind::from_wire(bytes[9])?;
        let disposition = if bytes[10] == 0 {
            None
        } else {
            Some(StdioProxyResultDisposition::from_wire(bytes[10])?)
        };
        let sequence = u64::from_be_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| denied("stdio_proxy_packet_header_denied"))?,
        );
        let session_nonce = bytes[24..56]
            .try_into()
            .map_err(|_| denied("stdio_proxy_packet_header_denied"))?;
        let correlation_nonce = bytes[56..88]
            .try_into()
            .map_err(|_| denied("stdio_proxy_packet_header_denied"))?;
        let payload_length = u32::from_be_bytes(
            bytes[88..92]
                .try_into()
                .map_err(|_| denied("stdio_proxy_packet_header_denied"))?,
        ) as usize;
        let expected_length = WIRE_HEADER_BYTES
            .checked_add(payload_length)
            .ok_or_else(|| denied("stdio_proxy_packet_length_denied"))?;
        if bytes.len() != expected_length {
            return Err(denied("stdio_proxy_packet_length_denied"));
        }
        let expected_payload_sha256: [u8; 32] = bytes[92..124]
            .try_into()
            .map_err(|_| denied("stdio_proxy_packet_header_denied"))?;
        let payload = bytes[WIRE_HEADER_BYTES..].to_vec();
        if sha256(&payload) != expected_payload_sha256 {
            return Err(denied("stdio_proxy_packet_hash_denied"));
        }
        let value = Self {
            kind,
            disposition,
            sequence,
            session_nonce,
            correlation_nonce,
            payload,
        };
        value.validate_shape()?;
        Ok(value)
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(WIRE_HEADER_BYTES + self.payload.len());
        bytes.extend_from_slice(&WIRE_MAGIC);
        bytes.push(WIRE_VERSION);
        bytes.push(self.kind.wire_value());
        bytes.push(self.disposition.map_or(0, |value| value.wire_value()));
        bytes.push(0);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.session_nonce);
        bytes.extend_from_slice(&self.correlation_nonce);
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&sha256(&self.payload));
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    #[must_use]
    pub const fn kind(&self) -> StdioProxyPacketKind {
        self.kind
    }

    #[must_use]
    pub const fn disposition(&self) -> Option<StdioProxyResultDisposition> {
        self.disposition
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn session_nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.session_nonce
    }

    #[must_use]
    pub const fn correlation_nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.correlation_nonce
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn validate_shape(&self) -> StdioProxyResult<()> {
        match self.kind {
            StdioProxyPacketKind::Hello => {
                if self.disposition.is_some()
                    || self.sequence != 0
                    || self.session_nonce != ZERO_NONCE
                    || !self.payload.is_empty()
                {
                    return Err(denied("stdio_proxy_hello_shape_denied"));
                }
                require_nonzero_nonce(&self.correlation_nonce)
            }
            StdioProxyPacketKind::Welcome => {
                if self.disposition.is_some()
                    || self.sequence != 0
                    || !self.payload.is_empty()
                    || self.session_nonce == self.correlation_nonce
                {
                    return Err(denied("stdio_proxy_welcome_shape_denied"));
                }
                require_nonzero_nonce(&self.session_nonce)?;
                require_nonzero_nonce(&self.correlation_nonce)
            }
            StdioProxyPacketKind::McpFrame => {
                if self.disposition.is_some()
                    || self.sequence == 0
                    || self.correlation_nonce != ZERO_NONCE
                {
                    return Err(denied("stdio_proxy_mcp_frame_shape_denied"));
                }
                require_nonzero_nonce(&self.session_nonce)?;
                validate_codex_system_api_mcp_frame(&self.payload).map(|_| ())
            }
            StdioProxyPacketKind::McpResult => {
                if self.sequence == 0 || self.correlation_nonce != ZERO_NONCE {
                    return Err(denied("stdio_proxy_mcp_result_shape_denied"));
                }
                require_nonzero_nonce(&self.session_nonce)?;
                match self.disposition {
                    Some(StdioProxyResultDisposition::Response) => {
                        validate_json_response_payload(&self.payload)
                    }
                    Some(StdioProxyResultDisposition::NoResponse)
                    | Some(StdioProxyResultDisposition::Denied) => {
                        if self.payload.is_empty() {
                            Ok(())
                        } else {
                            Err(denied("stdio_proxy_mcp_result_payload_denied"))
                        }
                    }
                    None => Err(denied("stdio_proxy_result_disposition_denied")),
                }
            }
        }
    }
}

pub enum AcceptedStdioProxyResult {
    Response(Vec<u8>),
    NoResponse,
    Denied,
}

impl fmt::Debug for AcceptedStdioProxyResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Response(payload) => formatter
                .debug_tuple("Response")
                .field(&format_args!("<{} bytes>", payload.len()))
                .finish(),
            Self::NoResponse => formatter.write_str("NoResponse"),
            Self::Denied => formatter.write_str("Denied"),
        }
    }
}

/// Non-authorizing client-side sequence state. It rejects concurrent, wrong,
/// repeated, or overflowing request/result sequences.
pub struct StdioProxyClientSequence {
    session_nonce: [u8; NONCE_BYTES],
    next_sequence: u64,
    in_flight: Option<StdioProxyInFlight>,
}

#[derive(Clone, Copy)]
struct StdioProxyInFlight {
    sequence: u64,
    method: CodexSystemApiMcpMethod,
}

impl fmt::Debug for StdioProxyClientSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdioProxyClientSequence")
            .field("session_nonce", &"<redacted>")
            .field("next_sequence", &self.next_sequence)
            .field(
                "in_flight_sequence",
                &self.in_flight.map(|value| value.sequence),
            )
            .field(
                "in_flight_method",
                &self.in_flight.map(|value| value.method),
            )
            .finish()
    }
}

impl StdioProxyClientSequence {
    pub fn establish(
        proxy_nonce: [u8; NONCE_BYTES],
        welcome: &StdioProxyPacket,
    ) -> StdioProxyResult<Self> {
        require_nonzero_nonce(&proxy_nonce)?;
        welcome.validate_shape()?;
        if welcome.kind != StdioProxyPacketKind::Welcome
            || welcome.correlation_nonce != proxy_nonce
            || welcome.session_nonce == proxy_nonce
        {
            return Err(denied("stdio_proxy_welcome_binding_denied"));
        }
        Ok(Self {
            session_nonce: welcome.session_nonce,
            next_sequence: 1,
            in_flight: None,
        })
    }

    pub fn begin_request(&mut self, payload: &[u8]) -> StdioProxyResult<StdioProxyPacket> {
        if self.in_flight.is_some() || self.next_sequence == u64::MAX {
            return Err(denied("stdio_proxy_sequence_state_denied"));
        }
        let sequence = self.next_sequence;
        let method = validate_codex_system_api_mcp_frame(payload)?.method();
        let packet = StdioProxyPacket::mcp_frame(self.session_nonce, sequence, payload)?;
        self.in_flight = Some(StdioProxyInFlight { sequence, method });
        Ok(packet)
    }

    pub fn accept_result(
        &mut self,
        result: StdioProxyPacket,
    ) -> StdioProxyResult<AcceptedStdioProxyResult> {
        result.validate_shape()?;
        let expected = self
            .in_flight
            .ok_or_else(|| denied("stdio_proxy_duplicate_result_sequence_denied"))?;
        if result.kind != StdioProxyPacketKind::McpResult
            || result.session_nonce != self.session_nonce
            || result.sequence != expected.sequence
        {
            return Err(denied("stdio_proxy_result_binding_denied"));
        }
        let accepted = match result.disposition {
            Some(StdioProxyResultDisposition::Response)
                if expected.method != CodexSystemApiMcpMethod::InitializedNotification =>
            {
                AcceptedStdioProxyResult::Response(result.payload)
            }
            Some(StdioProxyResultDisposition::NoResponse)
                if expected.method == CodexSystemApiMcpMethod::InitializedNotification =>
            {
                AcceptedStdioProxyResult::NoResponse
            }
            Some(StdioProxyResultDisposition::Denied) => AcceptedStdioProxyResult::Denied,
            Some(StdioProxyResultDisposition::Response)
            | Some(StdioProxyResultDisposition::NoResponse) => {
                return Err(denied("stdio_proxy_result_disposition_binding_denied"));
            }
            None => return Err(denied("stdio_proxy_result_disposition_denied")),
        };
        self.next_sequence = expected
            .sequence
            .checked_add(1)
            .ok_or_else(|| denied("stdio_proxy_sequence_overflow_denied"))?;
        self.in_flight = None;
        Ok(accepted)
    }
}

/// Non-authorizing broker-side sequence checker for host protocol tests.
///
/// It rejects every duplicate rather than implementing retry reconciliation.
/// A C2 daemon consumer must durably bind the ingress session, sequence, and
/// exact payload before advancing this state, and must reconcile a retry from
/// that durable record. This source-only checker does not issue a delivery,
/// advance a durable high-water mark, or launch an adapter.
pub struct StdioProxyBrokerSequence {
    session_nonce: [u8; NONCE_BYTES],
    next_sequence: u64,
}

impl StdioProxyBrokerSequence {
    pub fn new(session_nonce: [u8; NONCE_BYTES]) -> StdioProxyResult<Self> {
        require_nonzero_nonce(&session_nonce)?;
        Ok(Self {
            session_nonce,
            next_sequence: 1,
        })
    }

    pub fn accept_frame(
        &mut self,
        frame: &StdioProxyPacket,
    ) -> StdioProxyResult<CodexSystemApiMcpMethod> {
        frame.validate_shape()?;
        if frame.kind != StdioProxyPacketKind::McpFrame
            || frame.session_nonce != self.session_nonce
            || frame.sequence != self.next_sequence
        {
            return Err(denied("stdio_proxy_frame_sequence_denied"));
        }
        let validated = validate_codex_system_api_mcp_frame(&frame.payload)?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| denied("stdio_proxy_sequence_overflow_denied"))?;
        Ok(validated.method())
    }
}

pub fn validate_codex_system_api_mcp_frame(
    payload: &[u8],
) -> StdioProxyResult<ValidatedCodexSystemApiMcpFrame<'_>> {
    validate_payload_bytes(payload, MAXIMUM_MCP_REQUEST_BYTES)?;
    let first = payload
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .ok_or_else(|| denied("stdio_proxy_mcp_empty_denied"))?;
    if first == b'[' {
        return Err(denied("stdio_proxy_mcp_batch_denied"));
    }
    if first != b'{' {
        return Err(denied("stdio_proxy_mcp_object_denied"));
    }
    let envelope: BorrowedMcpEnvelope<'_> =
        serde_json::from_slice(payload).map_err(|_| denied("stdio_proxy_mcp_envelope_denied"))?;
    if envelope.jsonrpc != "2.0" {
        return Err(denied("stdio_proxy_mcp_version_denied"));
    }
    if let Some(id) = envelope.id.present() {
        validate_json_rpc_id(id)?;
    }
    let method = match envelope.method.as_ref() {
        "initialize" => {
            require_request_id(envelope.id.present(), CodexSystemApiMcpMethod::Initialize)?
        }
        "notifications/initialized" => {
            if envelope.id.is_present() {
                return Err(denied("stdio_proxy_mcp_notification_id_denied"));
            }
            CodexSystemApiMcpMethod::InitializedNotification
        }
        "ping" => require_request_id(envelope.id.present(), CodexSystemApiMcpMethod::Ping)?,
        "tools/list" => {
            require_request_id(envelope.id.present(), CodexSystemApiMcpMethod::ToolsList)?
        }
        "tools/call" => {
            require_request_id(
                envelope.id.present(),
                CodexSystemApiMcpMethod::SystemApiToolCall,
            )?;
            validate_fixed_tool_call(
                envelope
                    .params
                    .present()
                    .ok_or_else(|| denied("stdio_proxy_mcp_tool_params_denied"))?,
            )?;
            CodexSystemApiMcpMethod::SystemApiToolCall
        }
        _ => return Err(denied("stdio_proxy_mcp_unknown_method_denied")),
    };
    Ok(ValidatedCodexSystemApiMcpFrame { payload, method })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BorrowedMcpEnvelope<'a> {
    #[serde(borrow)]
    jsonrpc: Cow<'a, str>,
    #[serde(default, borrow)]
    id: BorrowedRawField<'a>,
    #[serde(borrow)]
    method: Cow<'a, str>,
    #[serde(default, borrow)]
    params: BorrowedRawField<'a>,
}

#[derive(Clone, Copy, Default)]
enum BorrowedRawField<'a> {
    #[default]
    Missing,
    Present(&'a RawValue),
}

impl<'a> BorrowedRawField<'a> {
    const fn present(self) -> Option<&'a RawValue> {
        match self {
            Self::Missing => None,
            Self::Present(value) => Some(value),
        }
    }

    const fn is_present(self) -> bool {
        matches!(self, Self::Present(_))
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for BorrowedRawField<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        <&'de RawValue>::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BorrowedToolCall<'a> {
    #[serde(borrow)]
    name: Cow<'a, str>,
    #[serde(borrow)]
    arguments: &'a RawValue,
}

fn validate_fixed_tool_call(raw: &RawValue) -> StdioProxyResult<()> {
    let call: BorrowedToolCall<'_> = serde_json::from_str(raw.get())
        .map_err(|_| denied("stdio_proxy_mcp_tool_params_denied"))?;
    if call.name != FIXED_TOOL_NAME {
        return Err(denied("stdio_proxy_mcp_tool_name_denied"));
    }
    let first = call
        .arguments
        .get()
        .bytes()
        .find(|byte| !byte.is_ascii_whitespace())
        .ok_or_else(|| denied("stdio_proxy_mcp_tool_arguments_denied"))?;
    if first != b'{' {
        return Err(denied("stdio_proxy_mcp_tool_arguments_denied"));
    }
    Ok(())
}

fn require_request_id(
    id: Option<&RawValue>,
    method: CodexSystemApiMcpMethod,
) -> StdioProxyResult<CodexSystemApiMcpMethod> {
    if id.is_none() {
        return Err(denied("stdio_proxy_mcp_request_id_denied"));
    }
    Ok(method)
}

fn validate_json_rpc_id(raw: &RawValue) -> StdioProxyResult<()> {
    let value: Value =
        serde_json::from_str(raw.get()).map_err(|_| denied("stdio_proxy_mcp_request_id_denied"))?;
    if value.is_string() || value.as_i64().is_some() || value.as_u64().is_some() {
        Ok(())
    } else {
        Err(denied("stdio_proxy_mcp_request_id_denied"))
    }
}

fn validate_json_response_payload(payload: &[u8]) -> StdioProxyResult<()> {
    validate_payload_bytes(payload, MAXIMUM_MCP_RESPONSE_BYTES)?;
    let value: Value =
        serde_json::from_slice(payload).map_err(|_| denied("stdio_proxy_mcp_response_denied"))?;
    if value.is_object() {
        Ok(())
    } else {
        Err(denied("stdio_proxy_mcp_response_denied"))
    }
}

fn validate_payload_bytes(payload: &[u8], maximum: usize) -> StdioProxyResult<()> {
    if payload.is_empty()
        || payload.len() > maximum
        || payload.iter().any(|byte| matches!(byte, b'\n' | b'\r'))
    {
        return Err(denied("stdio_proxy_payload_boundary_denied"));
    }
    Ok(())
}

fn require_nonzero_nonce(nonce: &[u8; NONCE_BYTES]) -> StdioProxyResult<()> {
    if nonce == &ZERO_NONCE {
        Err(denied("stdio_proxy_nonce_denied"))
    } else {
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

const fn denied(code: &'static str) -> StdioProxyProtocolError {
    StdioProxyProtocolError(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: () = {
        assert!(SOURCE_PROTOCOL_IMPLEMENTED);
        assert!(SOURCE_PROXY_IMPLEMENTED);
        assert!(!PRODUCT_PROXY_PACKAGED);
        assert!(!PRODUCT_ENTRY_CONFINEMENT_WIRED);
        assert!(!PRODUCT_LISTENER_WIRED);
        assert!(!PRODUCT_DAEMON_BROKER_WIRED);
        assert!(!PRODUCT_LOGICAL_DELIVERY_WIRED);
        assert!(!PRODUCT_ADAPTER_LAUNCH_WIRED);
        assert!(!FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE);
        assert!(!ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    };

    fn nonce(value: u8) -> [u8; NONCE_BYTES] {
        [value; NONCE_BYTES]
    }

    fn request(method: &str) -> Vec<u8> {
        format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{}}}}"#).into_bytes()
    }

    fn tool_call(name: &str, arguments: &str) -> Vec<u8> {
        format!(
            r#"{{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{{"name":"{name}","arguments":{arguments}}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn fixed_route_has_no_alternate_provider_or_accessibility_selector() {
        assert_eq!(FIXED_PROVIDER_ID, CODEX.provider_id);
        assert_eq!(FIXED_AGENT_ID, CODEX.agent_id);
        assert_eq!(FIXED_ADAPTER_ID, "system_api");
        assert_eq!(FIXED_TOOL_NAME, "trillionnium_system_api");
        assert!(!PROTOCOL.contains("alternate_provider"));
        assert!(!PROTOCOL.contains("accessibility"));
    }

    #[test]
    fn outer_classifier_preserves_exact_arguments_bytes() {
        let payload = br#" {"jsonrpc":"2.0","id":"opaque","method":"tools/call","params":{"name":"trillionnium_system_api","arguments":{"opaque":[3,2,1],"spacing":"kept"}}} "#;
        let validated = validate_codex_system_api_mcp_frame(payload).unwrap();
        assert_eq!(
            validated.method(),
            CodexSystemApiMcpMethod::SystemApiToolCall
        );
        assert_eq!(validated.payload(), payload);
        let packet = StdioProxyPacket::mcp_frame(nonce(2), 7, payload).unwrap();
        let decoded = StdioProxyPacket::decode(&packet.encode()).unwrap();
        assert_eq!(decoded.payload(), payload);
    }

    #[test]
    fn batch_unknown_method_and_non_system_api_tools_are_denied() {
        for (payload, code) in [
            (
                br#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#.as_slice(),
                "stdio_proxy_mcp_batch_denied",
            ),
            (
                br#"{"jsonrpc":"2.0","id":1,"method":"resources/list"}"#.as_slice(),
                "stdio_proxy_mcp_unknown_method_denied",
            ),
        ] {
            assert_eq!(
                validate_codex_system_api_mcp_frame(payload)
                    .unwrap_err()
                    .code(),
                code
            );
        }
        for name in ["trillionnium_accessibility", "trillionnium_other_provider"] {
            assert_eq!(
                validate_codex_system_api_mcp_frame(&tool_call(name, "{}"))
                    .unwrap_err()
                    .code(),
                "stdio_proxy_mcp_tool_name_denied"
            );
        }
    }

    #[test]
    fn malformed_ids_arguments_and_newline_frames_are_denied() {
        assert_eq!(
            validate_codex_system_api_mcp_frame(br#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#)
                .unwrap_err()
                .code(),
            "stdio_proxy_mcp_request_id_denied"
        );
        assert_eq!(
            validate_codex_system_api_mcp_frame(&tool_call(FIXED_TOOL_NAME, "[]"))
                .unwrap_err()
                .code(),
            "stdio_proxy_mcp_tool_arguments_denied"
        );
        assert_eq!(
            validate_codex_system_api_mcp_frame(
                br#"{"jsonrpc":"2.0","id":null,"method":"notifications/initialized"}"#
            )
            .unwrap_err()
            .code(),
            "stdio_proxy_mcp_request_id_denied"
        );
        let mut with_newline = request("ping");
        with_newline.push(b'\n');
        assert_eq!(
            validate_codex_system_api_mcp_frame(&with_newline)
                .unwrap_err()
                .code(),
            "stdio_proxy_payload_boundary_denied"
        );
    }

    #[test]
    fn packet_decode_rejects_length_hash_nonce_and_header_drift() {
        let hello = StdioProxyPacket::hello(nonce(1)).unwrap().encode();
        let mut truncated = hello.clone();
        truncated.pop();
        assert_eq!(
            StdioProxyPacket::decode(&truncated).unwrap_err().code(),
            "stdio_proxy_packet_length_denied"
        );

        let mut hash_drift = StdioProxyPacket::mcp_frame(nonce(2), 1, &request("ping"))
            .unwrap()
            .encode();
        *hash_drift.last_mut().unwrap() ^= 1;
        assert_eq!(
            StdioProxyPacket::decode(&hash_drift).unwrap_err().code(),
            "stdio_proxy_packet_hash_denied"
        );

        let mut zero_nonce = StdioProxyPacket::welcome(nonce(1), nonce(2))
            .unwrap()
            .encode();
        zero_nonce[24..56].fill(0);
        assert_eq!(
            StdioProxyPacket::decode(&zero_nonce).unwrap_err().code(),
            "stdio_proxy_nonce_denied"
        );

        let mut header_drift = hello;
        header_drift[12] = 1;
        assert_eq!(
            StdioProxyPacket::decode(&header_drift).unwrap_err().code(),
            "stdio_proxy_packet_header_denied"
        );
    }

    #[test]
    fn client_and_broker_reject_wrong_duplicate_and_nonce_drift() {
        let proxy_nonce = nonce(1);
        let session_nonce = nonce(2);
        let welcome = StdioProxyPacket::welcome(proxy_nonce, session_nonce).unwrap();
        let mut client = StdioProxyClientSequence::establish(proxy_nonce, &welcome).unwrap();
        let frame = client.begin_request(&request("ping")).unwrap();
        assert_eq!(
            client.begin_request(&request("ping")).unwrap_err().code(),
            "stdio_proxy_sequence_state_denied"
        );

        let mut broker = StdioProxyBrokerSequence::new(session_nonce).unwrap();
        assert_eq!(
            broker.accept_frame(&frame).unwrap(),
            CodexSystemApiMcpMethod::Ping
        );
        assert_eq!(
            broker.accept_frame(&frame).unwrap_err().code(),
            "stdio_proxy_frame_sequence_denied"
        );

        let wrong_nonce = StdioProxyPacket::mcp_result(
            nonce(3),
            1,
            StdioProxyResultDisposition::Response,
            br#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        )
        .unwrap();
        assert_eq!(
            client.accept_result(wrong_nonce).unwrap_err().code(),
            "stdio_proxy_result_binding_denied"
        );

        let wrong_sequence = StdioProxyPacket::mcp_result(
            session_nonce,
            2,
            StdioProxyResultDisposition::Response,
            br#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        )
        .unwrap();
        assert_eq!(
            client.accept_result(wrong_sequence).unwrap_err().code(),
            "stdio_proxy_result_binding_denied"
        );

        let result = StdioProxyPacket::mcp_result(
            session_nonce,
            1,
            StdioProxyResultDisposition::Response,
            br#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        )
        .unwrap();
        assert!(matches!(
            client.accept_result(result.clone()).unwrap(),
            AcceptedStdioProxyResult::Response(_)
        ));
        assert_eq!(
            client.accept_result(result).unwrap_err().code(),
            "stdio_proxy_duplicate_result_sequence_denied"
        );
    }

    #[test]
    fn result_disposition_is_bound_to_the_classified_method() {
        let proxy_nonce = nonce(1);
        let session_nonce = nonce(2);
        let welcome = StdioProxyPacket::welcome(proxy_nonce, session_nonce).unwrap();

        let mut request_client =
            StdioProxyClientSequence::establish(proxy_nonce, &welcome).unwrap();
        request_client.begin_request(&request("ping")).unwrap();
        let no_response = StdioProxyPacket::mcp_result(
            session_nonce,
            1,
            StdioProxyResultDisposition::NoResponse,
            &[],
        )
        .unwrap();
        assert_eq!(
            request_client
                .accept_result(no_response)
                .unwrap_err()
                .code(),
            "stdio_proxy_result_disposition_binding_denied"
        );

        let mut notification_client =
            StdioProxyClientSequence::establish(proxy_nonce, &welcome).unwrap();
        notification_client
            .begin_request(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .unwrap();
        let response = StdioProxyPacket::mcp_result(
            session_nonce,
            1,
            StdioProxyResultDisposition::Response,
            br#"{"jsonrpc":"2.0","id":null,"result":{}}"#,
        )
        .unwrap();
        assert_eq!(
            notification_client
                .accept_result(response)
                .unwrap_err()
                .code(),
            "stdio_proxy_result_disposition_binding_denied"
        );
        let no_response = StdioProxyPacket::mcp_result(
            session_nonce,
            1,
            StdioProxyResultDisposition::NoResponse,
            &[],
        )
        .unwrap();
        assert!(matches!(
            notification_client.accept_result(no_response).unwrap(),
            AcceptedStdioProxyResult::NoResponse
        ));
    }

    #[test]
    fn welcome_rejects_echo_drift_and_nonce_alias() {
        assert_eq!(
            StdioProxyPacket::welcome(nonce(1), nonce(1))
                .unwrap_err()
                .code(),
            "stdio_proxy_nonce_alias_denied"
        );
        let welcome = StdioProxyPacket::welcome(nonce(2), nonce(3)).unwrap();
        assert_eq!(
            StdioProxyClientSequence::establish(nonce(1), &welcome)
                .unwrap_err()
                .code(),
            "stdio_proxy_welcome_binding_denied"
        );
    }

    #[test]
    fn supported_control_methods_are_closed() {
        for (method, expected) in [
            ("initialize", CodexSystemApiMcpMethod::Initialize),
            ("ping", CodexSystemApiMcpMethod::Ping),
            ("tools/list", CodexSystemApiMcpMethod::ToolsList),
        ] {
            assert_eq!(
                validate_codex_system_api_mcp_frame(&request(method))
                    .unwrap()
                    .method(),
                expected
            );
        }
        let initialized = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert_eq!(
            validate_codex_system_api_mcp_frame(initialized)
                .unwrap()
                .method(),
            CodexSystemApiMcpMethod::InitializedNotification
        );
    }

    #[test]
    fn empty_payload_digest_is_frozen() {
        assert_eq!(sha256(&[]), EMPTY_SHA256);
    }
}
