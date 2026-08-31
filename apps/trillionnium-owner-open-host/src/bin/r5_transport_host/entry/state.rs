#[derive(Debug, Clone, PartialEq, Eq)]
struct TurnContext {
    session_id: String,
    profile_id: String,
    task_id: String,
    turn_id: String,
    turn_stream_id: String,
    request_sha256: String,
}

/// Broker-owned request identity carried through the transport boundary.
///
/// The connection broker adds these members to a client frame before it is
/// forwarded to the core.  They are not semantic request fields and must not
/// be interpreted by the core; the transport merely echoes the exact values
/// on every corresponding host frame so the broker can reject stale or
/// same-kind responses from another request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BrokerRequestBinding {
    request_id: String,
    request_sha256: String,
    upstream_seq: u64,
}

/// The semantic scope used to keep a broker envelope attached to the request
/// that created it.  Broker identity is deliberately separate from this
/// scope: two retries can have identical semantic fields but must never share
/// an envelope.  Every populated member must match before a response is
/// eligible for the binding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BrokerLineage {
    session_id: Option<String>,
    profile_id: Option<String>,
    task_id: Option<String>,
    turn_id: Option<String>,
    turn_stream_id: Option<String>,
    call_id: Option<String>,
    job_id: Option<String>,
}

impl BrokerLineage {
    fn from_frame(frame: &RunTurnFrame) -> Result<Self, String> {
        Ok(Self {
            session_id: correlated_string(frame, "session_id")?,
            profile_id: correlated_string(frame, "profile_id")?,
            task_id: correlated_string(frame, "task_id")?,
            turn_id: correlated_string(frame, "turn_id")?,
            turn_stream_id: correlated_stream_id(frame)?,
            call_id: correlated_string(frame, "call_id")?,
            job_id: correlated_string(frame, "job_id")?,
        })
    }

    fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// Return true only when the request has at least one semantic member and
    /// every member supplied by the request is echoed identically by the
    /// response.  An omitted optional member is not made mandatory here; the
    /// semantic protocol validators remain responsible for required fields.
    fn matches(&self, frame: &RunTurnFrame) -> bool {
        let Ok(actual) = Self::from_frame(frame) else {
            return false;
        };
        if self.is_empty() {
            return false;
        }
        [
            (&self.session_id, &actual.session_id),
            (&self.profile_id, &actual.profile_id),
            (&self.task_id, &actual.task_id),
            (&self.turn_id, &actual.turn_id),
            (&self.turn_stream_id, &actual.turn_stream_id),
            (&self.call_id, &actual.call_id),
            (&self.job_id, &actual.job_id),
        ]
        .into_iter()
        .all(|(expected, actual)| expected.is_none() || expected == actual)
    }
}

fn correlated_stream_id(frame: &RunTurnFrame) -> Result<Option<String>, String> {
    let envelope = match (frame.turn_stream_id.as_deref(), frame.stream_id.as_deref()) {
        (Some(first), Some(second)) if first != second => {
            return Err("turn_stream_id envelope aliases conflict".to_string());
        }
        (Some(value), _) | (_, Some(value)) => Some(value),
        (None, None) => None,
    };
    let object = frame.payload.as_object();
    let payload_first = optional_string_value(
        object.and_then(|object| object.get("turn_stream_id")),
        "turn_stream_id",
    )?;
    let payload_second = optional_string_value(
        object.and_then(|object| object.get("stream_id")),
        "stream_id",
    )?;
    let payload = match (payload_first, payload_second) {
        (Some(first), Some(second)) if first != second => {
            return Err("turn_stream_id payload aliases conflict".to_string());
        }
        (Some(value), _) | (_, Some(value)) => Some(value),
        (None, None) => None,
    };
    match (envelope, payload) {
        (Some(first), Some(second)) if first != second => {
            Err("turn_stream_id envelope and payload values conflict".to_string())
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value.to_string())),
        (None, None) => Ok(None),
    }
}

fn optional_string_value<'a>(
    value: Option<&'a Value>,
    name: &str,
) -> Result<Option<&'a str>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.as_str())),
        _ => Err(format!("{name} must be a string")),
    }
}

fn correlated_string(frame: &RunTurnFrame, name: &str) -> Result<Option<String>, String> {
    let envelope = match name {
        "session_id" => frame.session_id.as_deref(),
        "profile_id" => frame.profile_id.as_deref(),
        "task_id" => frame.task_id.as_deref(),
        "turn_id" => frame.turn_id.as_deref(),
        "call_id" => frame.call_id.as_deref(),
        "job_id" => frame.job_id.as_deref(),
        _ => None,
    };
    let payload = frame
        .payload
        .as_object()
        .and_then(|object| object.get(name));
    correlated_value(name, envelope, payload)
}

fn correlated_value(
    name: &str,
    envelope: Option<&str>,
    payload: Option<&Value>,
) -> Result<Option<String>, String> {
    let payload = match payload {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => return Err(format!("{name} must be a string")),
    };
    match (envelope, payload) {
        (Some(first), Some(second)) if first != second => {
            Err(format!("{name} envelope and payload values conflict"))
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value.to_string())),
        (None, None) => Ok(None),
    }
}

impl BrokerRequestBinding {
    fn from_frame(frame: &RunTurnFrame) -> Result<Option<Self>, String> {
        let request_id = frame.extensions.get("broker_request_id");
        let request_sha256 = frame.extensions.get("broker_request_sha256");
        let upstream_seq = frame.extensions.get("broker_request_upstream_seq");
        let payload = frame.payload.as_object();
        let payload_has_binding = payload.is_some_and(|payload| {
            [
                "broker_request_id",
                "broker_request_sha256",
                "broker_request_upstream_seq",
            ]
            .into_iter()
            .any(|name| payload.contains_key(name))
        });
        if request_id.is_none()
            && request_sha256.is_none()
            && upstream_seq.is_none()
            && !payload_has_binding
        {
            return Ok(None);
        }
        if request_id.is_none() || request_sha256.is_none() || upstream_seq.is_none() {
            return Err(
                "broker request identity must be present in the top-level frame envelope"
                    .to_string(),
            );
        }
        let request_id = request_id
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "broker_request_id must be a non-empty string".to_string())?;
        if !valid_id(request_id) {
            return Err("broker_request_id is malformed".to_string());
        }
        let request_sha256 = request_sha256
            .and_then(Value::as_str)
            .ok_or_else(|| "broker_request_sha256 must be a string".to_string())?;
        if request_sha256.len() != 64
            || !request_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err("broker_request_sha256 is not a lowercase SHA-256 digest".to_string());
        }
        let upstream_seq = upstream_seq.and_then(Value::as_u64).ok_or_else(|| {
            "broker_request_upstream_seq must be a nonnegative integer".to_string()
        })?;
        let expected = [
            (
                "broker_request_id",
                Value::String(request_id.to_string()),
            ),
            (
                "broker_request_sha256",
                Value::String(request_sha256.to_string()),
            ),
            (
                "broker_request_upstream_seq",
                Value::Number(upstream_seq.into()),
            ),
        ];
        if let Some(payload) = payload {
            for (name, expected) in expected {
                if let Some(actual) = payload.get(name)
                    && actual != &expected
                {
                    return Err(format!(
                        "broker request payload mirror field {name} conflicts with the top-level envelope"
                    ));
                }
            }
        }
        Ok(Some(Self {
            request_id: request_id.to_string(),
            request_sha256: request_sha256.to_string(),
            upstream_seq,
        }))
    }

    fn apply(&self, frame: &mut RunTurnFrame) -> Result<(), String> {
        let fields = [
            ("broker_request_id", Value::String(self.request_id.clone())),
            (
                "broker_request_sha256",
                Value::String(self.request_sha256.clone()),
            ),
            (
                "broker_request_upstream_seq",
                Value::Number(self.upstream_seq.into()),
            ),
        ];
        let payload = frame
            .payload
            .as_object()
            .ok_or_else(|| "core response payload must be an object for broker binding".to_string())?;
        for (name, expected) in fields {
            if let Some(actual) = frame.extensions.get(name)
                && actual != &expected
            {
                return Err(format!(
                    "core response broker envelope field {name} conflicts with the forwarded request"
                ));
            }
            if let Some(actual) = payload.get(name)
                && actual != &expected
            {
                return Err(format!(
                    "core response broker payload mirror field {name} conflicts with the forwarded request"
                ));
            }
            frame.extensions.insert(name.to_string(), expected);
        }
        Ok(())
    }
}

/// Recover only the broker-owned envelope from a frame whose semantic or
/// mechanical validation failed.  The strict value decoder still rejects
/// duplicate JSON members, while deserializing the outer frame without
/// calling `validate_mechanical` lets a malformed payload receive one
/// correlated `host.error` instead of leaving the broker request unresolved.
fn binding_from_encoded_frame(
    encoded: &[u8],
    limits: &MechanicalLimits,
) -> Option<BrokerRequestBinding> {
    let value = decode_strict_value(encoded, limits).ok()?;
    let frame = serde_json::from_value::<RunTurnFrame>(value).ok()?;
    BrokerRequestBinding::from_frame(&frame).ok().flatten()
}

impl TurnContext {
    fn from_start(frame: &RunTurnFrame, limits: &MechanicalLimits) -> Result<Self, String> {
        let request = frame
            .turn_request(limits)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            session_id: request.session_id.clone(),
            profile_id: request.effective_profile_id().to_string(),
            task_id: request.task_id.clone(),
            turn_id: request.turn_id.clone(),
            turn_stream_id: stable_turn_stream_id(&request)?,
            request_sha256: request_sha256(&request)?,
        })
    }
}

#[derive(Debug)]
enum TransportMessage {
    ClientFrame(Vec<u8>),
    ClientEof,
    ClientError(String),
    CoreFrame(Vec<u8>),
    CoreEof,
    CoreError(String),
    CoreExited(std::result::Result<ExitStatus, String>),
}

#[derive(Debug)]
struct TransportOutput {
    connection_id: String,
    /// Connection-control sequence (hello and unscoped local errors). It is
    /// intentionally outside the persisted turn cursor.
    next_control_seq: u64,
    /// Next transport sequence per semantic turn stream.  The map is keyed by
    /// the echoed `turn_stream_id` (with `None` as the bounded default bucket
    /// for a scoped core frame that carries no stream alias).  Keeping the
    /// cursor here, rather than globally on the connection, lets independent
    /// streams each begin at zero while preserving FIFO for mixed core/job
    /// frames that share one stream.
    next_stream_seq: HashMap<Option<String>, u64>,
    /// Event identities are connection-global even though wire host
    /// sequences are scoped per turn stream. Keeping a separate ordinal
    /// prevents two streams that both start at host_seq=0 from producing the
    /// same transport-generated `event_id`.
    next_local_event_ordinal: u64,
}

/// The transport has a small amount of work it can reject locally (flow
/// controls, malformed frames and broker-envelope validation).  When a
/// client sends those bytes immediately after a `hello`, their local error
/// must not leapfrog the core's `hello.ack`.  Keep the barrier explicit and
/// bounded; it is a delivery/order mechanism, not a semantic policy gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportHandshakeState {
    Open,
    AwaitingAck,
    Failed,
}

#[derive(Debug, Clone)]
struct DeferredLocalError {
    context: Option<TurnContext>,
    code: String,
    message: String,
    binding: Option<BrokerRequestBinding>,
}

/// A transport-generated success response that must wait behind a handshake
/// acknowledgement (currently a stream-control ACK).  It is kept separate
/// from `DeferredLocalError` so releasing a valid control command does not
/// turn it into a synthetic failure frame.
#[derive(Debug)]
struct DeferredLocalFrame {
    kind: String,
    payload: Value,
    context: Option<TurnContext>,
    binding: Option<BrokerRequestBinding>,
    /// Flow-control ACKs historically drain any now-credit-eligible buffered
    /// frames immediately after the ACK.  Preserve that atomic ordering when
    /// the ACK is released from the handshake queue.
    drain_flow: bool,
}

/// A handshake queue item retains the original arrival domain. Keeping local
/// transport errors and raw core frames in one FIFO is necessary: two
/// independent queues cannot reproduce wire order when the core and client
/// reader race while an acknowledgement gate is pending.
#[derive(Debug)]
enum DeferredHandshakeAction {
    Local(DeferredLocalError),
    LocalFrame(DeferredLocalFrame),
    /// Raw (strictly decoded and router-ordinal-stamped) core frame. The
    /// transport wire sequence is allocated only when this action is released.
    Core(Vec<u8>),
}

impl DeferredHandshakeAction {
    fn estimated_bytes(&self) -> usize {
        match self {
            Self::Local(error) => error
                .code
                .len()
                .saturating_add(error.message.len())
                .saturating_add(estimated_context_bytes(error.context.as_ref()))
                .saturating_add(estimated_binding_bytes(error.binding.as_ref()))
                .saturating_add(128),
            Self::LocalFrame(frame) => frame
                .kind
                .len()
                .saturating_add(frame.payload.to_string().len())
                .saturating_add(estimated_context_bytes(frame.context.as_ref()))
                .saturating_add(estimated_binding_bytes(frame.binding.as_ref()))
                .saturating_add(128),
            Self::Core(encoded) => encoded.len(),
        }
    }

    fn is_local_error(&self) -> bool {
        matches!(self, Self::Local(_))
    }
}

fn estimated_context_bytes(context: Option<&TurnContext>) -> usize {
    context.map_or(0, |context| {
        context
            .session_id
            .len()
            .saturating_add(context.profile_id.len())
            .saturating_add(context.task_id.len())
            .saturating_add(context.turn_id.len())
            .saturating_add(context.turn_stream_id.len())
            .saturating_add(context.request_sha256.len())
    })
}

fn estimated_binding_bytes(binding: Option<&BrokerRequestBinding>) -> usize {
    binding.map_or(0, |binding| {
        binding
            .request_id
            .len()
            .saturating_add(binding.request_sha256.len())
            .saturating_add(std::mem::size_of::<u64>())
    })
}

#[derive(Debug)]
struct TransportHandshake {
    state: TransportHandshakeState,
    hello_seen: bool,
    /// A core may emit its startup acknowledgement even when the client did
    /// not send the optional hello preface.  Accept that first acknowledgement
    /// for compatibility, but never emit a second one on the same carrier.
    hello_ack_seen: bool,
    /// Once any client frame has been consumed, the optional hello preface
    /// is no longer admissible.  This is distinct from `turn_started`: job,
    /// control, unknown and even malformed first frames must not permit a
    /// later hello.  Otherwise a late `hello.ack` can reuse connection
    /// control sequence zero after an earlier local error.
    preface_consumed: bool,
    /// A hello is an optional first-frame preface, never a mid-connection
    /// renegotiation.  Keep this sticky even after a turn ends so a late hello
    /// cannot reopen the core barrier for a subsequent turn.
    turn_started: bool,
    turn_pending: bool,
    /// Exactly one acceptance belongs to each admitted turn generation.
    /// Keeping this bit after the gate opens lets the transport discard a
    /// duplicated/late acceptance instead of allocating a second wire
    /// sequence or reopening broker routing.
    turn_accepted_seen: bool,
    /// Broker envelopes for requests whose core acknowledgement has not yet
    /// crossed the transport barrier.  The normal router can discover these
    /// bindings from correlated core frames, but EOF, malformed core bytes,
    /// and bounded-queue overflow have no frame for the router to inspect.
    /// Retaining the envelopes here lets those terminal errors still resolve
    /// the exact upstream request instead of becoming an uncorrelated stream
    /// error.
    hello_binding: Option<BrokerRequestBinding>,
    turn_binding: Option<BrokerRequestBinding>,
    /// A negative pre-accept turn resolver closes that turn generation.  Core
    /// readers may still publish already-buffered bytes after the resolver;
    /// those bytes must be ignored until a new turn boundary is admitted.
    drop_late_turn_core: bool,
    /// The semantic lineage of the rejected generation. Keep it across a
    /// retry so already-buffered old frames cannot be relabelled merely
    /// because a new `turn.start` arrived first.
    quarantined_turn: Option<TurnContext>,
    deferred: VecDeque<DeferredHandshakeAction>,
    deferred_bytes: usize,
}

const MAX_HANDSHAKE_DEFERRED_FRAMES: usize = 64;
const MAX_HANDSHAKE_DEFERRED_BYTES: usize = 4 * 1024 * 1024;

impl Default for TransportHandshake {
    fn default() -> Self {
        Self {
            state: TransportHandshakeState::Open,
            hello_seen: false,
            hello_ack_seen: false,
            preface_consumed: false,
            turn_started: false,
            turn_pending: false,
            turn_accepted_seen: false,
            hello_binding: None,
            turn_binding: None,
            drop_late_turn_core: false,
            quarantined_turn: None,
            deferred: VecDeque::new(),
            deferred_bytes: 0,
        }
    }
}

impl TransportHandshake {
    fn awaiting_ack(&self) -> bool {
        self.state == TransportHandshakeState::AwaitingAck
    }

    fn turn_pending(&self) -> bool {
        self.turn_pending
    }

    fn hello_ack_seen(&self) -> bool {
        self.hello_ack_seen
    }

    fn observe_hello_ack(&mut self) {
        self.hello_ack_seen = true;
    }

    fn turn_accepted_seen(&self) -> bool {
        self.turn_accepted_seen
    }

    fn can_accept_turn(&self) -> bool {
        self.turn_pending && !self.turn_accepted_seen
    }

    fn failed(&self) -> bool {
        self.state == TransportHandshakeState::Failed
    }

    fn late_turn_core_is_quarantined(&self) -> bool {
        self.drop_late_turn_core
    }

    /// Decide whether a core frame belongs to a rejected pre-accept
    /// generation. A frame from a different, identified stream may be a
    /// legitimate retry. A frame with no lineage cannot be proven new and is
    /// therefore dropped while quarantine is active. For a same-lineage retry,
    /// only a digest-bearing acceptance matching the new request may open the
    /// gate; all other bytes remain stale until then.
    fn should_drop_late_core(
        &self,
        frame: &RunTurnFrame,
        active: Option<&TurnContext>,
    ) -> bool {
        if !self.drop_late_turn_core {
            return false;
        }
        let Some(rejected) = self.quarantined_turn.as_ref() else {
            return true;
        };
        let Some(active) = active else {
            // A completed turn may still receive a read-only inspection (or
            // an explicit control failure) before the client closes the
            // carrier. Those response kinds are independent of the retired
            // provider stream and must remain serviceable; ordinary output
            // and duplicate terminal frames stay quarantined below.
            if is_post_turn_control_response(&frame.kind) {
                return false;
            }
            // There is no admitted replacement generation to which this
            // frame could belong. Keep the completed/rejected lineage
            // quarantined until a new turn's own acceptance opens the gate.
            return true;
        };
        let Ok(lineage) = BrokerLineage::from_frame(frame) else {
            return true;
        };
        if lineage.is_empty() || !strong_lineage_matches_context(&lineage, active) {
            return true;
        }

        // A retry that changes semantic scope is distinguishable from the
        // retired generation by lineage alone. When the scope is identical,
        // a digest is mandatory: an old frame with omitted aliases must never
        // be allowed to open the new gate.
        if context_scope_equal(rejected, active) {
            return response_digest(frame) != Some(active.request_sha256.as_str());
        }
        false
    }

    fn holds_local_delivery(&self) -> bool {
        self.state == TransportHandshakeState::AwaitingAck || self.turn_pending
    }

    /// Mark a non-hello client frame as having consumed the optional preface
    /// slot.  Callers invoke this before local validation/dispatch so a
    /// malformed first frame cannot be followed by a valid hello.
    fn consume_preface(&mut self) {
        self.preface_consumed = true;
    }

    fn begin_hello(&mut self) -> Result<(), String> {
        if self.failed() {
            return Err("transport handshake is unavailable".to_string());
        }
        if self.hello_seen {
            return Err("duplicate hello is not valid on one transport connection".to_string());
        }
        if self.hello_ack_seen {
            return Err(
                "hello cannot arrive after the core startup acknowledgement on one transport connection"
                    .to_string(),
            );
        }
        if self.preface_consumed {
            return Err(
                "hello must be the first client frame on one transport connection".to_string(),
            );
        }
        self.hello_seen = true;
        self.preface_consumed = true;
        self.state = TransportHandshakeState::AwaitingAck;
        Ok(())
    }

    fn begin_turn(&mut self) -> Result<(), String> {
        if self.failed() {
            return Err("transport handshake is unavailable".to_string());
        }
        if self.turn_pending {
            return Err("a turn is already awaiting turn.accepted".to_string());
        }
        // The first direct turn.start also consumes the optional hello
        // preface slot. Keep this invariant in the state object itself so
        // callers cannot reopen hello merely by bypassing the run-loop hook.
        self.preface_consumed = true;
        self.turn_started = true;
        self.turn_accepted_seen = false;
        // A new admitted turn starts a fresh core generation. Retain the
        // previous rejected lineage until this generation's own acceptance;
        // otherwise already-buffered old frames could be relabelled as the
        // retry simply because `turn.start` arrived first.
        self.turn_binding = None;
        self.turn_pending = true;
        Ok(())
    }

    fn retain_hello_binding(&mut self, binding: Option<BrokerRequestBinding>) {
        self.hello_binding = binding;
    }

    fn retain_turn_binding(&mut self, binding: Option<BrokerRequestBinding>) {
        self.turn_binding = binding;
    }

    fn hello_binding(&self) -> Option<&BrokerRequestBinding> {
        self.hello_binding.as_ref()
    }

    fn turn_binding(&self) -> Option<&BrokerRequestBinding> {
        self.turn_binding.as_ref()
    }

    fn clear_hello_binding(&mut self) {
        self.hello_binding = None;
    }

    fn clear_turn_binding(&mut self) {
        self.turn_binding = None;
    }

    fn observe_turn_accepted(&mut self) {
        self.turn_accepted_seen = true;
        self.turn_pending = false;
        self.state = TransportHandshakeState::Open;
        self.drop_late_turn_core = false;
        self.quarantined_turn = None;
    }

    fn finish_turn(&mut self, retired_turn: Option<&TurnContext>) {
        self.turn_pending = false;
        self.state = TransportHandshakeState::Open;
        self.turn_binding = None;
        if let Some(retired_turn) = retired_turn {
            // Keep the completed generation around while the core reader
            // drains.  A provider byte published after turn.end is stale and
            // must not be relabelled as a fresh streamless event (which would
            // otherwise reuse host_seq=0 in the default bucket).
            self.drop_late_turn_core = true;
            self.quarantined_turn = Some(retired_turn.clone());
        }
        self.deferred.clear();
        self.deferred_bytes = 0;
    }

    fn defer_local(&mut self, error: DeferredLocalError) -> Result<(), String> {
        let action = DeferredHandshakeAction::Local(error);
        self.reserve(action.estimated_bytes())?;
        self.deferred.push_back(action);
        Ok(())
    }

    fn defer_core(&mut self, encoded: Vec<u8>) -> Result<(), String> {
        let action = DeferredHandshakeAction::Core(encoded);
        self.reserve(action.estimated_bytes())?;
        self.deferred.push_back(action);
        Ok(())
    }

    fn defer_frame(&mut self, frame: DeferredLocalFrame) -> Result<(), String> {
        let action = DeferredHandshakeAction::LocalFrame(frame);
        self.reserve(action.estimated_bytes())?;
        self.deferred.push_back(action);
        Ok(())
    }

    fn reserve(&mut self, bytes: usize) -> Result<(), String> {
        let total = self
            .deferred_bytes
            .checked_add(bytes)
            .ok_or_else(|| "transport handshake deferred byte count overflowed".to_string())?;
        if self.deferred.len() >= MAX_HANDSHAKE_DEFERRED_FRAMES {
            return Err("transport handshake deferred-frame bound exhausted".to_string());
        }
        if total > MAX_HANDSHAKE_DEFERRED_BYTES {
            return Err("transport handshake deferred-byte bound exhausted".to_string());
        }
        self.deferred_bytes = total;
        Ok(())
    }

    fn acknowledge(&mut self) -> VecDeque<DeferredHandshakeAction> {
        self.state = TransportHandshakeState::Open;
        if self.turn_pending {
            // Keep the queue behind the independent turn.accepted gate. The
            // caller may inspect it through `take_deferred` to locate a
            // pre-acknowledged acceptance, but hello.ack alone never releases
            // turn-scoped effects.
            return VecDeque::new();
        }
        self.take_deferred()
    }

    fn release_after_turn_accept(&mut self) -> VecDeque<DeferredHandshakeAction> {
        self.turn_accepted_seen = true;
        self.turn_pending = false;
        self.state = TransportHandshakeState::Open;
        self.turn_binding = None;
        self.drop_late_turn_core = false;
        self.take_deferred()
    }

    fn take_deferred(&mut self) -> VecDeque<DeferredHandshakeAction> {
        self.deferred_bytes = 0;
        std::mem::take(&mut self.deferred)
    }

    /// Put a queue snapshot back behind the current handshake gate.  This is
    /// used when `hello.ack` arrives before the core's `turn.accepted`: the
    /// acknowledgement opens the connection gate, but the turn gate still
    /// owns every deferred effect until its own acceptance (or a terminal
    /// rejection) is observed.
    fn restore_deferred(
        &mut self,
        actions: VecDeque<DeferredHandshakeAction>,
    ) -> Result<(), String> {
        for action in actions {
            let bytes = action.estimated_bytes();
            self.reserve(bytes)?;
            self.deferred.push_back(action);
        }
        Ok(())
    }

    fn resolve_turn_failure(
        &mut self,
        rejected_turn: Option<&TurnContext>,
    ) -> VecDeque<DeferredHandshakeAction> {
        self.turn_accepted_seen = false;
        self.turn_pending = false;
        self.state = TransportHandshakeState::Open;
        self.turn_binding = None;
        self.drop_late_turn_core = true;
        self.quarantined_turn = rejected_turn.cloned();
        self.take_deferred()
    }

    fn fail(&mut self) -> VecDeque<DeferredHandshakeAction> {
        self.state = TransportHandshakeState::Failed;
        self.turn_pending = false;
        self.hello_binding = None;
        self.turn_binding = None;
        self.drop_late_turn_core = true;
        self.quarantined_turn = None;
        self.deferred_bytes = 0;
        std::mem::take(&mut self.deferred)
    }
}

fn is_post_turn_control_response(kind: &str) -> bool {
    matches!(
        kind,
        "turn.inspect.result"
            | "call.inspect.result"
            | "job.inspect.result"
            | "job.wait.result"
            | "job.attach.result"
            | "job.detach.result"
            | "job.control.result"
            | "job.start.result"
            | "job.error"
            | "turn.cancel.accepted"
            | "tool.cancel.accepted"
            | FRAME_HOST_ERROR
    )
}

impl TransportOutput {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        Self {
            connection_id: format!("r5-transport-{}-{nanos}", std::process::id()),
            // Reserve control sequence zero for an optional hello.ack.  A
            // peer is allowed to send a direct frame without a preface; if
            // that frame is rejected locally before a later hello arrives,
            // its error must not collide with the deterministic hello seq=0.
            next_control_seq: 1,
            next_stream_seq: HashMap::new(),
            // Preserve the historical first local event suffix (`event-1`)
            // while making subsequent identities independent of stream seq.
            next_local_event_ordinal: 1,
        }
    }

    /// Re-home every core frame into the transport connection's single wire
    /// sequence domain.  The v7 job multiplexer may use a per-job `seq`, and
    /// the turn core may restart its own counter across a reconnect; neither
    /// value is suitable as the externally visible host sequence.  Preserve
    /// both values as diagnostic extensions while allocating the only
    /// client-facing `seq`/`host_seq` here.
    fn rewrite_core(&mut self, frame: RunTurnFrame) -> RunTurnFrame {
        self.rewrite_core_with_context(frame, None)
    }

    /// Rewrite a core frame while allowing the active turn to supply the
    /// stream key when a legacy core omits both stream aliases from its
    /// envelope.  `None` remains the deterministic default bucket for an
    /// unscoped/streamless scoped frame when no active context is available.
    fn rewrite_core_with_context(
        &mut self,
        mut frame: RunTurnFrame,
        active: Option<&TurnContext>,
    ) -> RunTurnFrame {
        let core_seq = frame.seq;
        let core_host_seq = frame.host_seq;
        let core_connection_id = frame.connection_id.clone();
        frame
            .extensions
            .insert("core_seq".to_string(), json!(core_seq));
        if let Some(value) = core_host_seq {
            frame
                .extensions
                .insert("core_host_seq".to_string(), json!(value));
        }
        if let Some(value) = core_connection_id {
            frame
                .extensions
                .insert("core_connection_id".to_string(), json!(value));
        }
        if frame.kind == FRAME_HELLO_ACK {
            // Reserve sequence zero for the optional connection preface.
            // `TransportOutput::new` starts ordinary control errors at one,
            // so a late acknowledgement can still use the contract-defined
            // hello/hello.ack seq=0 without colliding with an earlier error.
            frame.seq = 0;
            frame.host_seq = None;
            self.next_control_seq = self.next_control_seq.max(1);
        } else if !frame_is_turn_scoped(&frame, core_host_seq.is_some()) {
            // hello/hello.ack and unscoped core errors are connection-control
            // frames. They must not consume turn-stream host_seq zero or
            // appear in the persisted replay cursor. Advancing the control
            // allocator here is important: a deferred/local error released
            // after hello.ack must not reuse the acknowledgement's seq.
            frame.seq = self.take_control_seq();
            frame.host_seq = None;
        } else {
            // The core cursor is retained above as a diagnostic extension,
            // but it is not the transport wire sequence. Core/job producers
            // may reset their local counters or share one cursor across
            // connections; all turn-scoped frames therefore consume the
            // single monotonically allocated transport host sequence here.
            // A durable core cursor is still a lower bound when reconnecting,
            // so an old/replayed frame can never make the fresh transport
            // cursor move backwards.
            let stream_key = stream_key_for_frame(&frame)
                .or_else(|| active.map(|context| context.turn_stream_id.clone()));
            let seq = self.take_stream_seq(stream_key, core_host_seq);
            frame.seq = seq;
            frame.host_seq = Some(seq);
        }
        frame.connection_id = Some(self.connection_id.clone());
        frame.direction = Some("host_to_client".to_string());
        if frame.event_id.is_none() {
            // A legacy core may omit the stable event identity.  The
            // transport cannot reconstruct a durable replay id, but it can
            // still guarantee a unique, connection-local observation rather
            // than emitting an invalid null event_id.
            let ordinal = self.take_local_event_ordinal();
            frame.event_id = Some(format!("{}-event-{ordinal}", self.connection_id));
        }
        frame
    }

    fn local_frame(
        &mut self,
        kind: &str,
        mut payload: Value,
        context: Option<&TurnContext>,
    ) -> RunTurnFrame {
        let event_ordinal = self.take_local_event_ordinal();
        let (seq, host_seq) = if context.is_some() {
            let stream_key = context.map(|value| value.turn_stream_id.clone());
            let seq = self.take_stream_seq(stream_key, None);
            (seq, Some(seq))
        } else {
            let seq = self.next_control_seq;
            self.next_control_seq = self.next_control_seq.saturating_add(1);
            (seq, None)
        };
        // Transport-generated frames are routed through the same broker
        // binding selector as core frames.  Preserve the active turn's
        // request digest in their payload so a scoped local observation (for
        // example stream.resync.required or stream.flow.disabled) cannot be
        // mistaken for a delayed frame from an earlier retry.
        if let Some(context) = context
            && let Some(object) = payload.as_object_mut()
        {
            object.insert(
                "turn_request_sha256".to_string(),
                Value::String(context.request_sha256.clone()),
            );
        }
        RunTurnFrame {
            kind: kind.to_string(),
            seq,
            payload,
            direction: Some("host_to_client".to_string()),
            client_seq: None,
            host_seq,
            frame_sha256: None,
            event_id: Some(format!("{}-event-{event_ordinal}", self.connection_id)),
            connection_id: Some(self.connection_id.clone()),
            stream_id: context.map(|value| value.turn_stream_id.clone()),
            turn_stream_id: context.map(|value| value.turn_stream_id.clone()),
            session_id: context.map(|value| value.session_id.clone()),
            profile_id: context.map(|value| value.profile_id.clone()),
            task_id: context.map(|value| value.task_id.clone()),
            turn_id: context.map(|value| value.turn_id.clone()),
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: BTreeMap::new(),
        }
    }

    fn take_stream_seq(&mut self, key: Option<String>, floor: Option<u64>) -> u64 {
        use std::collections::hash_map::Entry;

        // An unseen stream always starts at zero.  Once an entry exists, a
        // durable core cursor is a lower bound for reconnect/replay and may
        // advance that stream's local allocator without affecting any other
        // key.
        match self.next_stream_seq.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(1);
                0
            }
            Entry::Occupied(mut entry) => {
                let cursor = entry.get_mut();
                if let Some(floor) = floor {
                    *cursor = (*cursor).max(floor);
                }
                let value = *cursor;
                *cursor = cursor.saturating_add(1);
                value
            }
        }
    }

    fn take_control_seq(&mut self) -> u64 {
        let value = self.next_control_seq;
        self.next_control_seq = self.next_control_seq.saturating_add(1);
        value
    }

    fn take_local_event_ordinal(&mut self) -> u64 {
        let value = self.next_local_event_ordinal;
        self.next_local_event_ordinal = self.next_local_event_ordinal.saturating_add(1);
        value
    }
}

/// Core frames carry turn scope in the transport envelope.  Only a scoped
/// frame belongs to the persisted turn host-sequence domain; an unscoped
/// `host.error` must remain in the connection-control sequence domain.  Do not
/// infer scope from arbitrary payload metadata: a diagnostic session/job
/// field does not establish a transport lineage.
fn frame_is_turn_scoped(frame: &RunTurnFrame, core_host_seq_present: bool) -> bool {
    if frame.kind == FRAME_HELLO_ACK {
        return false;
    }
    if core_host_seq_present {
        return true;
    }
    frame.turn_stream_id.is_some()
        || frame.stream_id.is_some()
        || frame.turn_id.is_some()
        || frame.session_id.is_some()
        || frame.task_id.is_some()
        || frame
            .payload
            .get("turn_stream_id")
            .and_then(Value::as_str)
            .is_some()
        || frame
            .payload
            .get("stream_id")
            .and_then(Value::as_str)
            .is_some()
        || frame
            .payload
            .get("turn_id")
            .and_then(Value::as_str)
            .is_some()
        || frame
            .payload
            .get("session_id")
            .and_then(Value::as_str)
            .is_some()
        || frame
            .payload
            .get("task_id")
            .and_then(Value::as_str)
            .is_some()
}

/// Resolve the transport cursor key from the canonical stream aliases.  A
/// payload-only alias is accepted for legacy core/job frames whose envelope
/// omitted the mirrored field; conflicting top-level aliases are rejected by
/// the mechanism codec before this helper is reached.
fn stream_key_for_frame(frame: &RunTurnFrame) -> Option<String> {
    frame
        .turn_stream_id
        .clone()
        .or_else(|| frame.stream_id.clone())
        .or_else(|| {
            frame
                .payload
                .get("turn_stream_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| {
            frame
                .payload
                .get("stream_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
}

/// Match only the semantic members actually echoed by a core frame, while
/// requiring at least one member so an unscoped frame cannot be attributed to
/// an active turn by accident.  Payload aliases are already normalized by
/// `BrokerLineage::from_frame` and conflicting aliases fail closed there.
fn lineage_matches_context(lineage: &BrokerLineage, context: &TurnContext) -> bool {
    let pairs = [
        (
            context.session_id.as_str(),
            lineage.session_id.as_deref(),
        ),
        (
            context.profile_id.as_str(),
            lineage.profile_id.as_deref(),
        ),
        (context.task_id.as_str(), lineage.task_id.as_deref()),
        (context.turn_id.as_str(), lineage.turn_id.as_deref()),
        (
            context.turn_stream_id.as_str(),
            lineage.turn_stream_id.as_deref(),
        ),
    ];
    let mut compared = false;
    pairs.into_iter().all(|(expected, actual)| {
        let Some(actual) = actual else {
            return true;
        };
        compared = true;
        actual == expected
    }) && compared
}

fn strong_lineage_matches_context(lineage: &BrokerLineage, context: &TurnContext) -> bool {
    lineage.turn_id.as_deref() == Some(context.turn_id.as_str())
        && lineage.turn_stream_id.as_deref() == Some(context.turn_stream_id.as_str())
        && lineage_matches_context(lineage, context)
}

fn context_scope_equal(first: &TurnContext, second: &TurnContext) -> bool {
    first.session_id == second.session_id
        && first.profile_id == second.profile_id
        && first.task_id == second.task_id
        && first.turn_id == second.turn_id
        && first.turn_stream_id == second.turn_stream_id
}

/// Validate that a core lifecycle frame belongs to the currently admitted
/// turn before transport augmentation adds any fallback digest or broker
/// envelope.  A frame must echo at least one canonical lineage member; an
/// entirely unscoped acceptance/error is not allowed to steal a pending turn.
/// If the core supplies a request digest it must be the exact active digest.
fn turn_frame_matches_context(frame: &RunTurnFrame, context: &TurnContext) -> bool {
    let Ok(lineage) = BrokerLineage::from_frame(frame) else {
        return false;
    };
    // Lifecycle resolvers need the two strongest turn identifiers, not just a
    // shared session/task prefix. Ordinary streaming frames may use a legacy
    // partial echo, but accepting a partial echo here would let a sibling turn
    // steal the pending acceptance/error gate.
    strong_lineage_matches_context(&lineage, context)
        && response_digest(frame).is_none_or(|digest| digest == context.request_sha256)
}

#[cfg(test)]
mod handshake_tests {
    use super::*;

    #[test]
    fn correlated_stream_id_rejects_conflicting_payload_aliases_before_routing() {
        let frame: RunTurnFrame = serde_json::from_value(json!({
            "kind": "job.inspect",
            "seq": 0,
            "payload": {
                "turn_stream_id": "stream-canonical",
                "stream_id": "stream-legacy"
            }
        }))
        .expect("minimal frame envelope is decodable");
        let error = correlated_stream_id(&frame)
            .expect_err("conflicting payload aliases must fail before router registration");
        assert_eq!(error, "turn_stream_id payload aliases conflict");
    }

    #[test]
    fn handshake_ack_keeps_deferred_frames_until_turn_acceptance() {
        let mut handshake = TransportHandshake::default();
        handshake.begin_hello().expect("first hello opens ack gate");
        handshake.begin_turn().expect("turn opens acceptance gate");
        handshake
            .defer_core(br#"{"kind":"model.delta"}"#.to_vec())
            .expect("core frame fits bounded queue");
        handshake
            .defer_local(DeferredLocalError {
                context: None,
                code: "invalid_frame".to_string(),
                message: "deferred".to_string(),
                binding: None,
            })
            .expect("local error fits bounded queue");

        let after_hello = handshake.acknowledge();
        assert!(handshake.holds_local_delivery());

        // Implementations may retain the queue internally or return a
        // snapshot for the caller to inspect (the transport uses the latter
        // to locate a same-burst turn.accepted).  In either form, no deferred
        // frame may be lost across the hello transition.
        let released = if after_hello.is_empty() {
            handshake.release_after_turn_accept()
        } else {
            let count = after_hello.len();
            handshake
                .restore_deferred(after_hello)
                .expect("queue snapshot can be restored");
            let released = handshake.release_after_turn_accept();
            assert_eq!(released.len(), count);
            released
        };
        assert_eq!(
            released
                .iter()
                .filter(|action| action.is_local_error())
                .count(),
            1
        );
        assert_eq!(
            released
                .iter()
                .filter(|action| matches!(action, DeferredHandshakeAction::Core(_)))
                .count(),
            1
        );
        assert!(!handshake.holds_local_delivery());
    }

    #[test]
    fn hello_is_rejected_after_a_turn_has_started_even_when_it_finished() {
        let mut handshake = TransportHandshake::default();
        handshake.begin_turn().expect("first turn starts");
        assert!(handshake.begin_hello().is_err());

        handshake.release_after_turn_accept();
        handshake.finish_turn(None);
        assert!(handshake.begin_hello().is_err());
    }

    #[test]
    fn non_hello_first_frame_permanently_consumes_the_preface_slot() {
        let mut handshake = TransportHandshake::default();
        handshake.consume_preface();

        let error = handshake
            .begin_hello()
            .expect_err("a later hello cannot reopen the optional preface");
        assert!(error.contains("first client frame"));

        // Gate cleanup and turn cleanup must not make a connection-level
        // preface available again.
        handshake.finish_turn(None);
        assert!(handshake.begin_hello().is_err());
    }

    #[test]
    fn accepted_hello_itself_consumes_the_only_preface_slot() {
        let mut handshake = TransportHandshake::default();
        handshake
            .begin_hello()
            .expect("the first client frame may be hello");
        assert!(handshake.preface_consumed);

        let error = handshake
            .begin_hello()
            .expect_err("the preface is single-use");
        assert!(error.contains("duplicate hello"));
    }

    #[test]
    fn duplicate_core_acknowledgements_are_not_reusable() {
        let mut handshake = TransportHandshake::default();
        assert!(!handshake.hello_ack_seen());
        handshake.observe_hello_ack();
        assert!(handshake.hello_ack_seen());
        // The run loop uses this sticky bit to discard a second hello.ack.
        assert!(handshake.hello_ack_seen());

        handshake.begin_turn().expect("turn starts");
        assert!(handshake.can_accept_turn());
        handshake.observe_turn_accepted();
        assert!(!handshake.can_accept_turn());
    }

    #[test]
    fn normal_turn_completion_keeps_a_retired_lineage_quarantined() {
        let mut handshake = TransportHandshake::default();
        handshake.begin_turn().expect("turn starts");
        let context = TurnContext {
            session_id: "session-retired".to_string(),
            profile_id: DEFAULT_PROFILE_ID.to_string(),
            task_id: "task-retired".to_string(),
            turn_id: "turn-retired".to_string(),
            turn_stream_id: "stream-retired".to_string(),
            request_sha256: "a".repeat(64),
        };
        handshake.observe_turn_accepted();
        handshake.finish_turn(Some(&context));
        let mut late = RunTurnFrame {
            kind: "model.delta".to_string(),
            seq: 0,
            payload: json!({
                "session_id": context.session_id,
                "task_id": context.task_id,
                "turn_id": context.turn_id,
                "turn_stream_id": context.turn_stream_id
            }),
            direction: None,
            client_seq: None,
            host_seq: None,
            frame_sha256: None,
            event_id: None,
            connection_id: None,
            stream_id: None,
            turn_stream_id: Some(context.turn_stream_id.clone()),
            session_id: Some(context.session_id.clone()),
            profile_id: Some(context.profile_id.clone()),
            task_id: Some(context.task_id.clone()),
            turn_id: Some(context.turn_id.clone()),
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: BTreeMap::new(),
        };
        assert!(handshake.should_drop_late_core(&late, None));
        // Keep the mutable construction explicit so this test also exercises
        // the payload/envelope lineage normalizer.
        late.payload["turn_request_sha256"] = json!(context.request_sha256);
    }

    #[test]
    fn deferred_actions_keep_cross_domain_arrival_order() {
        let mut handshake = TransportHandshake::default();
        handshake
            .defer_local(DeferredLocalError {
                context: None,
                code: "first".to_string(),
                message: "local".to_string(),
                binding: None,
            })
            .expect("first local action fits");
        handshake
            .defer_core(br#"{"kind":"model.delta"}"#.to_vec())
            .expect("core action fits");
        handshake
            .defer_local(DeferredLocalError {
                context: None,
                code: "last".to_string(),
                message: "local".to_string(),
                binding: None,
            })
            .expect("last local action fits");

        let actions = handshake.take_deferred();
        assert!(matches!(
            actions.front(),
            Some(DeferredHandshakeAction::Local(_))
        ));
        assert!(matches!(
            actions.get(1),
            Some(DeferredHandshakeAction::Core(_))
        ));
        assert!(matches!(
            actions.get(2),
            Some(DeferredHandshakeAction::Local(_))
        ));
    }

    #[test]
    fn pending_handshake_bindings_survive_until_ack_or_failure() {
        let hello = BrokerRequestBinding {
            request_id: "hello-request".to_string(),
            request_sha256: "a".repeat(64),
            upstream_seq: 7,
        };
        let turn = BrokerRequestBinding {
            request_id: "turn-request".to_string(),
            request_sha256: "b".repeat(64),
            upstream_seq: 8,
        };
        let mut handshake = TransportHandshake::default();
        handshake.begin_hello().expect("hello gate opens");
        handshake.retain_hello_binding(Some(hello.clone()));
        handshake.begin_turn().expect("turn gate opens");
        handshake.retain_turn_binding(Some(turn.clone()));
        assert_eq!(handshake.hello_binding(), Some(&hello));
        assert_eq!(handshake.turn_binding(), Some(&turn));

        // A failed handshake clears retained secrets along with its deferred
        // actions; callers must snapshot them before emitting the failure.
        let _ = handshake.fail();
        assert!(handshake.hello_binding().is_none());
        assert!(handshake.turn_binding().is_none());
    }

    #[test]
    fn pre_accept_failure_quarantines_late_core_until_new_turn() {
        let mut handshake = TransportHandshake::default();
        handshake.begin_turn().expect("turn gate opens");
        let rejected = TurnContext {
            session_id: "session".to_string(),
            profile_id: "owner-open".to_string(),
            task_id: "task".to_string(),
            turn_id: "turn".to_string(),
            turn_stream_id: "stream".to_string(),
            request_sha256: "a".repeat(64),
        };
        let _ = handshake.resolve_turn_failure(Some(&rejected));
        assert!(handshake.late_turn_core_is_quarantined());

        handshake.begin_turn().expect("new turn starts a new generation");
        assert!(handshake.late_turn_core_is_quarantined());
        handshake.observe_turn_accepted();
        assert!(!handshake.late_turn_core_is_quarantined());
    }
}
