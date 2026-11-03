fn augment_core_frame(
    frame: &mut RunTurnFrame,
    active: Option<&TurnContext>,
    options: &Options,
    flow: &StreamDelivery,
    durable_ready: bool,
    journal: &TransportJournal,
) {
    let Some(payload) = frame.payload.as_object_mut() else {
        return;
    };
    if frame.kind == FRAME_HELLO_ACK {
        payload.insert(
            "host_implementation".to_string(),
            Value::String(HOST_IMPLEMENTATION_V5.to_string()),
        );
        payload.insert("transport_flow_control".to_string(), Value::Bool(true));
        payload.insert(
            "flow_control_requires_durable_store".to_string(),
            Value::Bool(true),
        );
        payload.insert(
            "flow_controlled_frame_kinds".to_string(),
            json!(FLOW_CONTROLLED_FRAME_KINDS),
        );
        payload.insert(
            "transport_buffer_bytes".to_string(),
            json!(options.buffer_bytes),
        );
        payload.insert(
            "transport_max_credit_bytes".to_string(),
            json!(options.max_credit_bytes),
        );
        payload.insert(
            "transport_max_chunk_bytes".to_string(),
            json!(options.max_chunk_bytes),
        );
        payload.insert("persist_before_flow".to_string(), Value::Bool(true));
        payload.insert(
            "transport_journal_status".to_string(),
            Value::String(journal.status().to_string()),
        );
        payload.insert(
            "transport_journal_error".to_string(),
            journal
                .error()
                .map_or(Value::Null, |value| Value::String(value.to_string())),
        );
    }
    if frame.kind == FRAME_TURN_ACCEPTED {
        if let Some(context) = active {
            payload.insert(
                "turn_request_sha256".to_string(),
                Value::String(context.request_sha256.clone()),
            );
            payload.insert(
                "turn_stream_id".to_string(),
                Value::String(context.turn_stream_id.clone()),
            );
        }
        payload.insert(
            "flow_control_status".to_string(),
            Value::String(
                if flow.is_active() {
                    "active"
                } else {
                    "passthrough"
                }
                .to_string(),
            ),
        );
        payload.insert(
            "flow_control_available".to_string(),
            Value::Bool(durable_ready),
        );
    }
    if flow.gap.is_some() && matches!(frame.kind.as_str(), FRAME_TOOL_RESULT | FRAME_TOOL_STARTED) {
        payload.insert("stream_resync_required".to_string(), Value::Bool(true));
    }
}

fn attach_gap_to_payload(payload: &mut Value, gap: &ResyncGap) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    object.insert("stream_resync_required".to_string(), Value::Bool(true));
    object.insert("stream_gap".to_string(), gap.payload());
}

fn attach_delivery_status<W: Write>(payload: &mut Value, delivery: &ClientDelivery<W>) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    object.insert(
        "transport_client_delivery_status_before_terminal_attempt".to_string(),
        Value::String(
            if delivery.attached {
                "attached"
            } else {
                "detached"
            }
            .to_string(),
        ),
    );
    object.insert(
        "transport_client_delivery_error".to_string(),
        delivery
            .error
            .as_ref()
            .map_or(Value::Null, |value| Value::String(value.clone())),
    );
}

fn write_resync_required<W: Write>(
    delivery: &mut ClientDelivery<W>,
    output: &mut TransportOutput,
    context: Option<&TurnContext>,
    gap: &ResyncGap,
) -> Result<(), String> {
    let frame = output.local_frame(FRAME_STREAM_RESYNC_REQUIRED, gap.payload(), context);
    delivery.send(&frame)
}

fn write_local_error_for_binding<W: Write>(
    delivery: &mut ClientDelivery<W>,
    output: &mut TransportOutput,
    context: Option<&TurnContext>,
    code: &str,
    message: &str,
    binding: Option<&BrokerRequestBinding>,
) -> Result<(), String> {
    let frame = output.local_frame(
        FRAME_HOST_ERROR,
        json!({
            "code": code,
            "message": message,
            "transport_layer": true,
            "automatic_redispatch": false
        }),
        context,
    );
    delivery.send_with_binding(&frame, binding)
}

/// Deliver a transport-generated error, or hold it until the core's
/// connection preface has been acknowledged.  The frame is materialized only
/// when it is released so a deferred turn error cannot consume host_seq zero
/// before `turn.accepted`.
fn write_local_error_or_defer<W: Write>(
    delivery: &mut ClientDelivery<W>,
    output: &mut TransportOutput,
    handshake: &mut TransportHandshake,
    context: Option<&TurnContext>,
    code: &str,
    message: &str,
    binding: Option<&BrokerRequestBinding>,
) -> Result<(), String> {
    // Both handshake barriers hold transport-generated responses.  A turn
    // can be admitted before `hello.ack` arrives, so checking only the hello
    // state would let a local turn error consume host_seq zero before the
    // core's `turn.accepted` frame.
    if handshake.holds_local_delivery() {
        let deferred = DeferredLocalError {
            context: context.cloned(),
            code: code.to_string(),
            message: message.to_string(),
            binding: binding.cloned(),
        };
        if let Err(error) = handshake.defer_local(deferred) {
            // A bounded liveness queue must never turn peer backpressure into
            // a process crash.  Close the unresolved gate and emit one
            // explicit mechanical resource error for both the pending gate
            // request(s) and the request that could not be retained; late
            // core bytes are ignored by the failed handshake state.
            fail_pending_handshake(
                delivery,
                output,
                handshake,
                ("resource_exhausted", error.as_str()),
                ("resource_exhausted", error.as_str()),
            )?;
            return write_local_error_for_binding(
                delivery,
                output,
                None,
                "resource_exhausted",
                &error,
                binding,
            );
        }
        return Ok(());
    }
    write_local_error_for_binding(delivery, output, context, code, message, binding)
}

fn flush_deferred_local_errors<W: Write>(
    delivery: &mut ClientDelivery<W>,
    output: &mut TransportOutput,
    deferred: VecDeque<DeferredLocalError>,
) -> Result<(), String> {
    for error in deferred {
        let frame = output.local_frame(
            FRAME_HOST_ERROR,
            json!({
                "code": error.code,
                "message": error.message,
                "transport_layer": true,
                "automatic_redispatch": false
            }),
            error.context.as_ref(),
        );
        delivery.send_with_binding(&frame, error.binding.as_ref())?;
    }
    Ok(())
}

fn is_flow_control_kind(kind: &str) -> bool {
    matches!(
        kind,
        FRAME_STREAM_WINDOW_UPDATE | FRAME_STREAM_PAUSE | FRAME_STREAM_RESUME
    )
}

fn frame_reports_durable(frame: &RunTurnFrame) -> bool {
    frame
        .payload
        .get("durable_event_store")
        .and_then(Value::as_bool)
        == Some(true)
        || frame
            .payload
            .get("event_log_status")
            .and_then(Value::as_str)
            == Some("durable")
}

fn frame_reports_unavailable(frame: &RunTurnFrame) -> bool {
    let payload = &frame.payload;
    // `durable_event_store=false` is an explicit negative capability and must
    // not be outweighed by a stale/optimistic status field in the same frame.
    if payload.get("durable_event_store").and_then(Value::as_bool) == Some(false) {
        return true;
    }

    // Core and job-runtime revisions use different names for the same
    // degraded observation.  Treat all known non-durable values as a hard
    // readiness reset.  In particular, `job.status` with
    // `status=journal_unavailable` may be the first indication that the job
    // observation source failed; it does not carry `event_log_status`.
    let status_is_unavailable = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .is_some_and(|status| status != "durable")
    };
    status_is_unavailable(payload.get("event_log_status"))
        || status_is_unavailable(payload.get("job_journal_status"))
        || payload.get("status").and_then(Value::as_str) == Some("journal_unavailable")
}

fn forward_to_core(core_stdin: &mut Option<ChildStdin>, encoded: &[u8]) -> Result<(), String> {
    let writer = core_stdin
        .as_mut()
        .ok_or_else(|| "core Host stdin is closed".to_string())?;
    writer
        .write_all(encoded)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("failed to forward client frame to core Host: {error}"))
}

#[derive(Debug, Clone)]
struct BrokerBindingIntent {
    binding: BrokerRequestBinding,
    request_kind: String,
    lineage: BrokerLineage,
    request_digest: Option<String>,
    operation_id: Option<String>,
    core_floor: Option<u64>,
    /// A pending control is not eligible to claim a core `host.error` until
    /// its request has actually crossed the core stdin boundary.  Before
    /// that point an error with the same lineage can only belong to the
    /// already-active turn (or another earlier request).
    forwarded: bool,
    established: bool,
}

#[derive(Debug, Default)]
struct BrokerBindingRouter {
    /// Turn/job requests remain active for the lifetime of their stream so
    /// asynchronous output is tied to the request that created it.
    active: Vec<BrokerBindingIntent>,
    /// One-shot requests (hello, inspect, and controls) consume the first
    /// matching response.  FIFO is important when several controls are
    /// queued while a turn worker is producing output.
    pending: VecDeque<BrokerBindingIntent>,
    /// Monotonic arrival high-water mark at the transport/core boundary.  The
    /// core's own `seq` is not suitable here because the job multiplexer uses
    /// a per-job sequence domain and may reset it for every job.
    last_core_ordinal: Option<u64>,
    next_core_ordinal: u64,
}

const MAX_BROKER_ACTIVE_BINDINGS: usize = 1024;
const MAX_BROKER_PENDING_BINDINGS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrokerResponseRoute {
    Pending(usize),
    Active(usize),
}

impl BrokerBindingRouter {
    /// Check the finite routing-state budget before a client frame mutates
    /// handshake/turn state. The transport ingress queue is bounded, but a
    /// long-lived connection can otherwise accumulate one-shot broker intents
    /// until `register` returns an error. That condition is a protocol-level
    /// `resource_exhausted` rejection, not a reason for the Host process to
    /// terminate.
    fn check_registration_capacity(
        &self,
        frame: &RunTurnFrame,
        binding: Option<&BrokerRequestBinding>,
    ) -> Result<(), String> {
        if binding.is_none() {
            return Ok(());
        }
        if frame.kind == "turn.start" || frame.kind == "job.start" {
            if self.active.len() >= MAX_BROKER_ACTIVE_BINDINGS {
                return Err("broker active response binding queue is exhausted".to_string());
            }
        } else if self.pending.len() >= MAX_BROKER_PENDING_BINDINGS {
            return Err("broker response binding queue is exhausted".to_string());
        }
        Ok(())
    }

    fn register(
        &mut self,
        frame: &RunTurnFrame,
        binding: Option<BrokerRequestBinding>,
    ) -> Result<(), String> {
        let Some(binding) = binding else {
            return Ok(());
        };
        let lineage = BrokerLineage::from_frame(frame)?;
        self.check_registration_capacity(frame, Some(&binding))?;
        let intent = BrokerBindingIntent {
            binding,
            request_kind: frame.kind.clone(),
            lineage,
            request_digest: request_digest(frame),
            operation_id: operation_id(frame),
            core_floor: self.last_core_ordinal,
            forwarded: false,
            established: false,
        };
        if intent.request_kind == "turn.start" || intent.request_kind == "job.start" {
            self.active.push(intent);
        } else {
            // The transport queue is bounded; retain a second finite bound so
            // malformed peers cannot grow routing state indefinitely.
            self.pending.push_back(intent);
        }
        Ok(())
    }

    fn observe_core(&mut self, frame: &mut RunTurnFrame) {
        let ordinal = self.next_core_ordinal;
        self.next_core_ordinal = self.next_core_ordinal.saturating_add(1);
        frame
            .extensions
            .insert("transport_core_ordinal".to_string(), json!(ordinal));
        self.last_core_ordinal = Some(ordinal);
    }

    /// Mark the exact request identity after the transport has completed its
    /// write to core stdin.  This bit is intentionally separate from
    /// registration: a client frame may be admitted and queued while a
    /// previously active turn is still producing output.
    fn mark_forwarded(&mut self, binding: Option<&BrokerRequestBinding>) {
        let Some(binding) = binding else {
            return;
        };
        let same = |intent: &BrokerBindingIntent| {
            intent.binding.request_id == binding.request_id
                && intent.binding.request_sha256 == binding.request_sha256
                && intent.binding.upstream_seq == binding.upstream_seq
        };
        if let Some(intent) = self.pending.iter_mut().find(|intent| same(intent)) {
            intent.forwarded = true;
        }
        if let Some(intent) = self.active.iter_mut().find(|intent| same(intent)) {
            intent.forwarded = true;
        }
    }

    fn matching_pending_index(&self, frame: &RunTurnFrame) -> Option<usize> {
        self.pending.iter().position(|intent| {
            // A pending intent is only eligible for a core-produced response
            // after its exact request bytes crossed the core stdin boundary.
            // Before that point a same-lineage frame can be stale output from
            // an earlier generation (or a response to a request whose write
            // failed); consuming the binding would falsely terminalize the
            // unforwarded request and could misdeliver the effect result.
            intent.forwarded
                && intent_lineage_matches(intent, frame)
                && core_seq_after(frame, intent.core_floor)
                && direct_response_matches(intent, frame)
                && operation_matches(intent, frame)
                && digest_matches(intent, frame)
        })
    }

    fn matching_active_index(&self, frame: &RunTurnFrame) -> Option<usize> {
        self.active.iter().enumerate().find_map(|(index, intent)| {
            // As with one-shot intents, an active start request cannot own a
            // core response until its exact bytes were successfully written.
            // This matters on non-handshake job.start paths where a failed
            // write otherwise leaves an active binding behind for stale core
            // output to consume.
            if !intent.forwarded
                || !intent_lineage_matches(intent, frame)
                || !core_seq_after(frame, intent.core_floor)
                || !active_frame_matches(intent, frame)
                || !digest_matches(intent, frame)
            {
                return None;
            }
            // An unestablished start intent may consume only its own
            // acceptance/error. Skip it for ordinary output so a stale
            // pre-accept intent cannot shadow a newer retry in the active
            // FIFO. `select` still performs the final activation check.
            if !intent.established && !activation_proven(intent, frame) {
                return None;
            }
            Some(index)
        })
    }

    /// Choose one owner for a response without allowing a generic
    /// `host.error` to consume whichever FIFO entry happens to be first.
    ///
    /// A turn-start intent remains active while controls such as
    /// `turn.cancel` are pending.  Those requests deliberately share the
    /// same semantic lineage, so lineage alone cannot identify an error's
    /// owner.  Prefer an explicit broker/request-kind marker when the Host
    /// supplies one.  Otherwise a cancel error is attributable to the
    /// cancel only after that exact request crossed stdin; before forwarding,
    /// the active turn is the only request that could have produced it.
    fn response_route(&self, frame: &RunTurnFrame) -> Option<BrokerResponseRoute> {
        let pending = self.matching_pending_index(frame);
        let active = self.matching_active_index(frame);
        if frame.kind == FRAME_HOST_ERROR
            && let (Some(pending), Some(active)) = (pending, active)
        {
            let pending_intent = &self.pending[pending];
            let active_intent = &self.active[active];
            if host_error_explicitly_targets(
                frame,
                &pending_intent.binding,
                &pending_intent.request_kind,
            ) {
                return Some(BrokerResponseRoute::Pending(pending));
            }
            if host_error_explicitly_targets(
                frame,
                &active_intent.binding,
                &active_intent.request_kind,
            ) {
                return Some(BrokerResponseRoute::Active(active));
            }
            if matches!(
                pending_intent.request_kind.as_str(),
                "turn.cancel" | "tool.cancel"
            ) {
                return Some(if pending_intent.forwarded {
                    BrokerResponseRoute::Pending(pending)
                } else {
                    BrokerResponseRoute::Active(active)
                });
            }
        }
        pending
            .map(BrokerResponseRoute::Pending)
            .or_else(|| active.map(BrokerResponseRoute::Active))
    }

    /// Inspect the response binding without mutating routing state.  The
    /// transport uses this before applying broker-envelope mirrors so a
    /// malformed response cannot consume the only pending intent.
    fn peek(&self, frame: &RunTurnFrame) -> Option<BrokerRequestBinding> {
        match self.response_route(frame)? {
            BrokerResponseRoute::Pending(index) => {
                self.pending.get(index).map(|intent| intent.binding.clone())
            }
            BrokerResponseRoute::Active(index) => {
                let intent = self.active.get(index)?;
                if !intent.established && !activation_proven(intent, frame) {
                    return None;
                }
                Some(intent.binding.clone())
            }
        }
    }

    fn select(&mut self, frame: &RunTurnFrame) -> Option<BrokerRequestBinding> {
        // Direct responses are checked before ordinary stream output.  The
        // route helper adds an explicit host.error tie-breaker for the case
        // where a live turn and a pending cancel share one lineage.
        match self.response_route(frame)? {
            BrokerResponseRoute::Pending(index) => {
                self.pending.remove(index).map(|intent| intent.binding)
            }
            BrokerResponseRoute::Active(index) => {
                let intent = &mut self.active[index];
                if !intent.established {
                    if !activation_proven(intent, frame) {
                        // In particular, a delayed old turn.accepted/stream
                        // frame is deliberately left unbound until the new
                        // request's own digest-bearing acceptance is observed.
                        return None;
                    }
                    intent.established = true;
                }
                let binding = intent.binding.clone();
                if active_terminal(intent, frame) {
                    self.active.remove(index);
                }
                Some(binding)
            }
        }
    }

    /// Consume a one-shot binding whose response was generated locally.
    ///
    /// Local validation/flow-control failures still have to echo the broker
    /// envelope, but they do not pass through the core response selector.  If
    /// the pending intent were left behind, a later unrelated core frame could
    /// be attributed to that already-terminal request.
    fn consume_explicit(&mut self, binding: &BrokerRequestBinding, frame: &RunTurnFrame) {
        if let Some(index) = self.pending.iter().position(|intent| {
            intent.binding.request_id == binding.request_id
                && intent.binding.request_sha256 == binding.request_sha256
                && intent.binding.upstream_seq == binding.upstream_seq
        }) {
            self.pending.remove(index);
        }
        // An explicitly retained turn binding is also used for a core
        // acknowledgement when normal router selection cannot prove the
        // response (for example a malformed/missing digest on a revisioned
        // core). Mark that active start as established here; otherwise the
        // first subsequent model/tool frame would still see an
        // `established=false` intent and remain unbound forever.
        if let Some(index) = self.active.iter().position(|intent| {
            intent.binding.request_id == binding.request_id
                && intent.binding.request_sha256 == binding.request_sha256
                && intent.binding.upstream_seq == binding.upstream_seq
        }) {
            let intent = &mut self.active[index];
            if activation_proven(intent, frame) {
                intent.established = true;
                if active_terminal(intent, frame) {
                    self.active.remove(index);
                }
            }
        }
    }

    /// Remove a request whose lifecycle was resolved locally (for example a
    /// pre-accept core rejection). Unlike `consume_explicit`, this does not
    /// require the response to prove activation: the retained binding is the
    /// exact admission identity and the caller has already decided that the
    /// generation is terminal.
    fn discard_binding(&mut self, binding: &BrokerRequestBinding) {
        let same = |candidate: &BrokerBindingIntent| {
            candidate.binding.request_id == binding.request_id
                && candidate.binding.request_sha256 == binding.request_sha256
                && candidate.binding.upstream_seq == binding.upstream_seq
        };
        self.pending.retain(|intent| !same(intent));
        self.active.retain(|intent| !same(intent));
    }

    fn take_all_bindings(&mut self) -> Vec<BrokerRequestBinding> {
        let mut bindings = Vec::with_capacity(self.pending.len() + self.active.len());
        bindings.extend(self.pending.drain(..).map(|intent| intent.binding));
        bindings.extend(self.active.drain(..).map(|intent| intent.binding));
        // A request can be represented in both queues during a transition;
        // retain one terminal response per exact broker identity.
        let mut unique = Vec::with_capacity(bindings.len());
        for binding in bindings {
            if !unique.iter().any(|candidate: &BrokerRequestBinding| {
                candidate == &binding
            }) {
                unique.push(binding);
            }
        }
        unique
    }

    /// Retire exactly one admitted turn generation.
    ///
    /// A terminal frame may omit the semantic request digest.  Lineage is
    /// therefore insufficient to identify its owner: an identical retry can
    /// already be resident in `active`.  The transport handshake retains the
    /// immutable broker tuple for the current generation and supplies it
    /// here, so cleanup cannot consume a same-scope retry (or any unrelated
    /// request that happens to share the lineage).
    fn clear_turn_binding(&mut self, binding: &BrokerRequestBinding) {
        self.discard_binding(binding);
    }
}

/// Match the semantic lineage of a response to one ingress intent.  `hello`
/// is intentionally the one unscoped Host request, so its empty lineage is a
/// valid exact match rather than a wildcard.  Every scoped request still
/// requires all supplied correlation members to be echoed exactly.
fn intent_lineage_matches(intent: &BrokerBindingIntent, frame: &RunTurnFrame) -> bool {
    let Ok(actual) = BrokerLineage::from_frame(frame) else {
        return false;
    };
    if intent.request_kind == "hello" {
        // `hello.ack` allocates a provisional stream on some Host revisions.
        // That transport stream is not semantic turn lineage, so allow it
        // while still rejecting an unsolicited session/turn/job identity.
        return actual.session_id.is_none()
            && actual.profile_id.is_none()
            && actual.task_id.is_none()
            && actual.turn_id.is_none()
            && actual.call_id.is_none()
            && actual.job_id.is_none();
    }
    intent.lineage.matches_lineage(&actual)
}

impl BrokerLineage {
    fn matches_lineage(&self, actual: &BrokerLineage) -> bool {
        !self.is_empty()
            && [
                (&self.session_id, &actual.session_id),
                (&self.profile_id, &actual.profile_id),
                (&self.task_id, &actual.task_id),
                (&self.turn_id, &actual.turn_id),
                (&self.turn_stream_id, &actual.turn_stream_id),
                (&self.call_id, &actual.call_id),
                (&self.job_id, &actual.job_id),
            ]
            .into_iter()
            .all(|(expected, actual)| match expected {
                Some(expected) => actual.as_ref() == Some(expected),
                None => true,
            })
    }
}

fn operation_id(frame: &RunTurnFrame) -> Option<String> {
    frame
        .payload
        .get("operation_id")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Return true when a `host.error` carries an explicit identity for the
/// candidate request.  Core revisions that echo broker metadata can use the
/// immutable broker tuple; revisions that expose a semantic marker can use
/// `request_kind`/`broker_request_kind`.  Missing markers intentionally do
/// not count as explicit evidence and are resolved by the forwarding-order
/// rule in `BrokerBindingRouter::response_route`.
fn host_error_explicitly_targets(
    frame: &RunTurnFrame,
    binding: &BrokerRequestBinding,
    request_kind: &str,
) -> bool {
    if frame.kind != FRAME_HOST_ERROR {
        return false;
    }
    let binding_names = [
        "broker_request_id",
        "broker_request_sha256",
        "broker_request_upstream_seq",
    ];
    let mut saw_binding = false;
    for name in binding_names {
        for value in [
            frame.extensions.get(name),
            frame.payload.as_object().and_then(|object| object.get(name)),
        ] {
            let Some(value) = value else {
                continue;
            };
            saw_binding = true;
            let matches = match name {
                "broker_request_id" => value.as_str() == Some(binding.request_id.as_str()),
                "broker_request_sha256" => {
                    value.as_str() == Some(binding.request_sha256.as_str())
                }
                "broker_request_upstream_seq" => value.as_u64() == Some(binding.upstream_seq),
                _ => false,
            };
            if !matches {
                return false;
            }
        }
    }
    if saw_binding {
        return true;
    }

    for name in ["request_kind", "broker_request_kind", "for_request_kind"] {
        for value in [
            frame.extensions.get(name),
            frame.payload.as_object().and_then(|object| object.get(name)),
        ] {
            if value.and_then(Value::as_str) == Some(request_kind) {
                return true;
            }
        }
    }
    false
}

fn request_digest(frame: &RunTurnFrame) -> Option<String> {
    if frame.kind == "turn.start" {
        let request = frame.turn_request(&MechanicalLimits::default()).ok()?;
        return request_sha256(&request).ok();
    }
    frame
        .payload
        .get("request_sha256")
        .and_then(Value::as_str)
        .or_else(|| {
            frame
                .payload
                .get("turn_request_sha256")
                .and_then(Value::as_str)
        })
        .map(str::to_string)
}

fn response_digest(frame: &RunTurnFrame) -> Option<&str> {
    frame
        .payload
        .get("request_sha256")
        .and_then(Value::as_str)
        .or_else(|| {
            frame
                .payload
                .get("turn_request_sha256")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            frame
                .payload
                .get("snapshot")
                .and_then(|value| value.get("request_sha256"))
                .and_then(Value::as_str)
        })
}

fn digest_matches(intent: &BrokerBindingIntent, frame: &RunTurnFrame) -> bool {
    match (intent.request_digest.as_deref(), response_digest(frame)) {
        (Some(expected), Some(actual)) => expected == actual,
        // Once a request has a semantic digest, accepting a response without
        // that digest would make a delayed frame from an earlier retry
        // indistinguishable from the current one.  Leave it unbound until the
        // Host supplies the exact digest; requests without a digest retain the
        // legacy lineage/operation matching path above.
        (Some(_), None) => false,
        (None, _) => true,
    }
}

fn core_seq_after(frame: &RunTurnFrame, floor: Option<u64>) -> bool {
    match (
        floor,
        frame
            .extensions
            .get("transport_core_ordinal")
            .and_then(Value::as_u64),
    ) {
        (Some(floor), Some(seq)) => seq > floor,
        (Some(_), None) => false,
        (None, _) => true,
    }
}

fn direct_response_matches(intent: &BrokerBindingIntent, frame: &RunTurnFrame) -> bool {
    let kind = frame.kind.as_str();
    match intent.request_kind.as_str() {
        "hello" => kind == "hello.ack",
        "turn.cancel" => matches!(kind, "turn.cancel.accepted" | "host.error"),
        "tool.cancel" => matches!(kind, "tool.cancel.accepted" | "host.error"),
        "turn.inspect" => matches!(kind, "turn.inspect.result" | "host.error"),
        "call.inspect" => matches!(kind, "call.inspect.result" | "host.error"),
        "job.start" => matches!(kind, "job.start.result" | "job.error"),
        "job.inspect" | "job.wait" => matches!(kind, "job.inspect.result" | "job.error"),
        "job.attach" => matches!(kind, "job.attach.result" | "job.error"),
        "job.detach" => matches!(kind, "job.detach.result" | "job.error"),
        "job.write" | "job.resize" | "job.close_stdin" | "job.kill" => {
            matches!(kind, "job.control.result" | "job.error")
        }
        _ => false,
    }
}

fn operation_matches(intent: &BrokerBindingIntent, frame: &RunTurnFrame) -> bool {
    let Some(expected) = intent.operation_id.as_deref() else {
        return true;
    };
    frame
        .payload
        .get("operation_id")
        .and_then(Value::as_str)
        .is_some_and(|actual| actual == expected)
}

fn active_frame_matches(intent: &BrokerBindingIntent, frame: &RunTurnFrame) -> bool {
    let kind = frame.kind.as_str();
    if matches!(
        kind,
        "turn.cancel.accepted"
            | "tool.cancel.accepted"
            | "turn.inspect.result"
            | "call.inspect.result"
    ) {
        return false;
    }
    match intent.request_kind.as_str() {
        "turn.start" => !matches!(kind, "hello.ack" | "job.start.result" | "job.error"),
        "job.start" => kind.starts_with("job."),
        _ => false,
    }
}

fn activation_proven(intent: &BrokerBindingIntent, frame: &RunTurnFrame) -> bool {
    // A start request may fail before its normal acceptance/result frame.  A
    // correlated error is still the direct terminal observation for that
    // request and must carry its broker envelope rather than remaining
    // unbound forever.
    if (intent.request_kind == "turn.start" && frame.kind == "host.error")
        || (intent.request_kind == "job.start" && frame.kind == "job.error")
    {
        return true;
    }
    let expected_kind = match intent.request_kind.as_str() {
        "turn.start" => frame.kind == FRAME_TURN_ACCEPTED,
        "job.start" => frame.kind == "job.start.result",
        _ => false,
    };
    if !expected_kind {
        return false;
    }
    match intent.request_digest.as_deref() {
        Some(expected) => response_digest(frame) == Some(expected),
        None => true,
    }
}

fn active_terminal(intent: &BrokerBindingIntent, frame: &RunTurnFrame) -> bool {
    match intent.request_kind.as_str() {
        "turn.start" => matches!(frame.kind.as_str(), FRAME_TURN_END | "host.error"),
        "job.start" => matches!(frame.kind.as_str(), "job.result" | "job.error"),
        _ => false,
    }
}

struct ClientDelivery<W: Write> {
    writer: W,
    max_frame_bytes: usize,
    attached: bool,
    error: Option<String>,
    broker_router: BrokerBindingRouter,
}

impl<W: Write> ClientDelivery<W> {
    fn new(writer: W, max_frame_bytes: usize) -> Self {
        Self {
            writer,
            max_frame_bytes,
            attached: true,
            error: None,
            broker_router: BrokerBindingRouter::default(),
        }
    }

    fn register_broker_request(
        &mut self,
        frame: &RunTurnFrame,
        binding: Option<BrokerRequestBinding>,
    ) -> Result<(), String> {
        self.broker_router.register(frame, binding)
    }

    fn check_broker_request_capacity(
        &self,
        frame: &RunTurnFrame,
        binding: Option<&BrokerRequestBinding>,
    ) -> Result<(), String> {
        self.broker_router
            .check_registration_capacity(frame, binding)
    }

    fn observe_core_frame(&mut self, frame: &mut RunTurnFrame) {
        self.broker_router.observe_core(frame);
    }

    fn mark_broker_forwarded(&mut self, binding: Option<&BrokerRequestBinding>) {
        self.broker_router.mark_forwarded(binding);
    }

    fn clear_turn_binding(&mut self, binding: &BrokerRequestBinding) {
        self.broker_router.clear_turn_binding(binding);
    }

    fn discard_broker_binding(&mut self, binding: &BrokerRequestBinding) {
        self.broker_router.discard_binding(binding);
    }

    fn reject_all_broker_requests(
        &mut self,
        output: &mut TransportOutput,
        code: &str,
        message: &str,
    ) -> Result<(), String> {
        for binding in self.broker_router.take_all_bindings() {
            write_local_error_for_binding(self, output, None, code, message, Some(&binding))?;
        }
        Ok(())
    }

    fn send(&mut self, frame: &RunTurnFrame) -> Result<(), String> {
        // Validate a candidate envelope before `select` mutates the pending
        // or active router intent.  If a core response carries a conflicting
        // payload mirror, the intent remains available for a corrected frame
        // or an explicit mechanical failure response.
        let candidate = self.broker_router.peek(frame);
        if let Some(binding) = candidate.as_ref() {
            let mut validated = frame.clone();
            binding.apply(&mut validated)?;
            let selected = self.broker_router.select(&validated);
            return self.send_with_selected_binding(&validated, selected.as_ref());
        }
        self.send_with_selected_binding(frame, None)
    }

    fn send_with_binding(
        &mut self,
        frame: &RunTurnFrame,
        binding: Option<&BrokerRequestBinding>,
    ) -> Result<(), String> {
        if let Some(binding) = binding {
            // Validate all top-level and payload mirrors before consuming the
            // one-shot router intent.  A conflicting payload must leave the
            // pending binding intact so the caller can emit a correlated
            // mechanical error instead of silently orphaning the request.
            let mut validated = frame.clone();
            binding.apply(&mut validated)?;
            self.broker_router.consume_explicit(binding, &validated);
            return self.send_with_selected_binding(&validated, Some(binding));
        }
        self.send_with_selected_binding(frame, binding)
    }

    fn send_with_selected_binding(
        &mut self,
        frame: &RunTurnFrame,
        binding: Option<&BrokerRequestBinding>,
    ) -> Result<(), String> {
        let mut frame = frame.clone();
        if let Some(binding) = binding {
            binding.apply(&mut frame)?;
        }
        let encoded = serde_json::to_vec(&frame).map_err(|error| error.to_string())?;
        if encoded.is_empty() || encoded.len() > self.max_frame_bytes {
            return Err("transport response frame exceeds the Host frame bound".to_string());
        }
        if !self.attached {
            return Ok(());
        }
        if let Err(error) = self
            .writer
            .write_all(&encoded)
            .and_then(|_| self.writer.write_all(b"\n"))
            .and_then(|_| self.writer.flush())
        {
            self.attached = false;
            self.error = Some(error.to_string());
        }
        Ok(())
    }

    fn flush_if_attached(&mut self) -> Result<(), String> {
        if self.attached {
            self.writer.flush().map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(id: &str, upstream_seq: u64) -> BrokerRequestBinding {
        BrokerRequestBinding {
            request_id: id.to_string(),
            request_sha256: "a".repeat(64),
            upstream_seq,
        }
    }

    fn turn_start(turn_id: &str, user_input: &str) -> RunTurnFrame {
        RunTurnFrame {
            kind: "turn.start".to_string(),
            seq: 0,
            payload: json!({
                "protocol": PROTOCOL,
                "protocol_version": PROTOCOL_VERSION,
                "session_id": "session-router",
                "task_id": "task-router",
                "turn_id": turn_id,
                "user_input": user_input
            }),
            direction: Some("client_to_host".to_string()),
            client_seq: None,
            host_seq: None,
            frame_sha256: None,
            event_id: None,
            connection_id: None,
            stream_id: None,
            turn_stream_id: None,
            session_id: None,
            profile_id: None,
            task_id: None,
            turn_id: None,
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: BTreeMap::new(),
        }
    }

    fn core_frame(kind: &str, turn_id: &str, digest: &str) -> RunTurnFrame {
        RunTurnFrame {
            kind: kind.to_string(),
            seq: 0,
            payload: json!({"turn_request_sha256": digest}),
            direction: Some("host_to_client".to_string()),
            client_seq: None,
            host_seq: None,
            frame_sha256: None,
            event_id: None,
            connection_id: None,
            stream_id: None,
            turn_stream_id: None,
            session_id: Some("session-router".to_string()),
            profile_id: None,
            task_id: Some("task-router".to_string()),
            turn_id: Some(turn_id.to_string()),
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: BTreeMap::new(),
        }
    }

    fn encoded_frames(delivery: &ClientDelivery<Vec<u8>>) -> Vec<Value> {
        String::from_utf8(delivery.writer.clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn delayed_old_turn_frame_does_not_inherit_new_request_binding() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let start_a = turn_start("turn-router", "request-a");
        let digest_a = request_digest(&start_a).unwrap();
        let binding_a = binding("request-a", 10);
        delivery
            .register_broker_request(&start_a, Some(binding_a.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&binding_a));

        let mut accepted_a = core_frame(FRAME_TURN_ACCEPTED, "turn-router", &digest_a);
        delivery.observe_core_frame(&mut accepted_a);
        delivery.send(&accepted_a).unwrap();
        let mut terminal_a = core_frame(FRAME_TURN_END, "turn-router", &digest_a);
        delivery.observe_core_frame(&mut terminal_a);
        delivery.send(&terminal_a).unwrap();

        let start_b = turn_start("turn-router", "request-b");
        let digest_b = request_digest(&start_b).unwrap();
        let binding_b = binding("request-b", 11);
        delivery
            .register_broker_request(&start_b, Some(binding_b.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&binding_b));

        // This frame is from A and arrives after A's terminal while B is
        // waiting for its own digest-bearing acceptance.  It must stay
        // unbound, even though the semantic turn scope is identical.
        let mut delayed_a = core_frame("model.delta", "turn-router", &digest_a);
        delivery.observe_core_frame(&mut delayed_a);
        delivery.send(&delayed_a).unwrap();

        let mut accepted_b = core_frame(FRAME_TURN_ACCEPTED, "turn-router", &digest_b);
        delivery.observe_core_frame(&mut accepted_b);
        delivery.send(&accepted_b).unwrap();

        // A delayed event after B's acceptance is rejected by the digest
        // guard as well; it cannot be relabelled as B.
        let mut delayed_a_after = core_frame("model.delta", "turn-router", &digest_a);
        delivery.observe_core_frame(&mut delayed_a_after);
        delivery.send(&delayed_a_after).unwrap();

        let frames = encoded_frames(&delivery);
        assert_eq!(frames[0]["broker_request_id"], "request-a");
        assert_eq!(frames[1]["broker_request_id"], "request-a");
        assert!(frames[2].get("broker_request_id").is_none());
        assert_eq!(frames[3]["broker_request_id"], "request-b");
        assert!(frames[4].get("broker_request_id").is_none());
    }

    #[test]
    fn missing_digest_terminal_clears_exact_turn_before_same_scope_retry() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let start = turn_start("turn-terminal-retry", "same-request");
        let digest = request_digest(&start).unwrap();
        let current_binding = binding("current-turn", 12);
        delivery
            .register_broker_request(&start, Some(current_binding.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&current_binding));

        let mut accepted = core_frame(FRAME_TURN_ACCEPTED, "turn-terminal-retry", &digest);
        delivery.observe_core_frame(&mut accepted);
        delivery.send(&accepted).unwrap();

        // Model a retry admitted before the old terminal's cleanup callback
        // runs.  It intentionally has the same semantic lineage and digest;
        // only the immutable broker tuple distinguishes the generations.
        let retry = turn_start("turn-terminal-retry", "same-request");
        let retry_binding = binding("same-scope-retry", 13);
        delivery
            .register_broker_request(&retry, Some(retry_binding.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&retry_binding));

        // This legacy terminal carries the turn lineage but no request
        // digest.  Generic routing must leave it unowned until the caller
        // supplies the exact current binding.
        let mut terminal = core_frame(FRAME_TURN_END, "turn-terminal-retry", "");
        terminal.payload = json!({"status": "completed"});
        delivery.observe_core_frame(&mut terminal);
        delivery.send(&terminal).unwrap();
        delivery.clear_turn_binding(&current_binding);

        let mut accepted_retry =
            core_frame(FRAME_TURN_ACCEPTED, "turn-terminal-retry", &digest);
        delivery.observe_core_frame(&mut accepted_retry);
        delivery.send(&accepted_retry).unwrap();

        let frames = encoded_frames(&delivery);
        assert_eq!(frames[0]["broker_request_id"], "current-turn");
        assert!(frames[1].get("broker_request_id").is_none());
        assert_eq!(frames[2]["broker_request_id"], "same-scope-retry");
        assert_eq!(delivery.broker_router.active.len(), 1);
        assert_eq!(
            delivery.broker_router.active[0].binding,
            retry_binding,
            "exact terminal cleanup must not erase the same-scope retry"
        );
    }

    #[test]
    fn control_ack_uses_control_binding_not_active_turn_binding() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let start = turn_start("turn-control-router", "request");
        let digest = request_digest(&start).unwrap();
        let turn_binding = binding("turn-request", 20);
        delivery
            .register_broker_request(&start, Some(turn_binding.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&turn_binding));
        let mut accepted = core_frame(FRAME_TURN_ACCEPTED, "turn-control-router", &digest);
        delivery.observe_core_frame(&mut accepted);
        delivery.send(&accepted).unwrap();

        let mut cancel = core_frame("turn.cancel", "turn-control-router", "");
        cancel.payload = json!({"session_id": "session-router", "turn_id": "turn-control-router"});
        let cancel_binding = binding("cancel-request", 21);
        delivery
            .register_broker_request(&cancel, Some(cancel_binding.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&cancel_binding));
        let mut ack = core_frame("turn.cancel.accepted", "turn-control-router", "");
        delivery.observe_core_frame(&mut ack);
        delivery.send(&ack).unwrap();
        let frames = encoded_frames(&delivery);
        assert_eq!(frames[0]["broker_request_id"], "turn-request");
        assert_eq!(frames[1]["broker_request_id"], "cancel-request");
    }

    #[test]
    fn host_error_does_not_let_an_unforwarded_cancel_shadow_active_turn() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let start = turn_start("turn-error-route", "request");
        let digest = request_digest(&start).unwrap();
        let turn_binding = binding("turn-request", 201);
        delivery
            .register_broker_request(&start, Some(turn_binding.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&turn_binding));
        let mut accepted = core_frame(FRAME_TURN_ACCEPTED, "turn-error-route", &digest);
        delivery.observe_core_frame(&mut accepted);
        delivery.send(&accepted).unwrap();

        let mut cancel = core_frame("turn.cancel", "turn-error-route", "");
        cancel.payload = json!({
            "session_id": "session-router",
            "turn_id": "turn-error-route"
        });
        let cancel_binding = binding("cancel-request", 202);
        delivery
            .register_broker_request(&cancel, Some(cancel_binding.clone()))
            .unwrap();

        // No cancel bytes have crossed the core boundary yet.  A generic
        // same-lineage error therefore belongs to the established turn;
        // pending-FIFO order must not consume the cancel envelope.
        let mut error = core_frame("host.error", "turn-error-route", &digest);
        error.payload["code"] = json!("turn_failed");
        delivery.observe_core_frame(&mut error);
        delivery.send(&error).unwrap();
        let frames = encoded_frames(&delivery);
        assert_eq!(frames[0]["broker_request_id"], "turn-request");
        assert_eq!(frames[1]["broker_request_id"], "turn-request");

        // Once the simulated write path reports that the cancel crossed the
        // core boundary, its late acknowledgement may claim the pending
        // envelope.  Without this proof the fail-closed router must leave an
        // otherwise identical acknowledgement unowned (see the dedicated
        // unforwarded-pending test below).
        delivery.mark_broker_forwarded(Some(&cancel_binding));
        let mut ack = core_frame("turn.cancel.accepted", "turn-error-route", "");
        delivery.observe_core_frame(&mut ack);
        delivery.send(&ack).unwrap();
        let frames = encoded_frames(&delivery);
        assert_eq!(frames[2]["broker_request_id"], "cancel-request");
    }

    #[test]
    fn unforwarded_pending_response_cannot_consume_broker_binding() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let mut cancel = core_frame("turn.cancel", "turn-unforwarded", "");
        cancel.payload = json!({
            "session_id": "session-router",
            "turn_id": "turn-unforwarded"
        });
        let cancel_binding = binding("unforwarded-cancel", 207);
        delivery
            .register_broker_request(&cancel, Some(cancel_binding.clone()))
            .unwrap();

        // The response shape and lineage are otherwise exact, but no client
        // bytes have crossed core stdin. It must remain an unowned core frame
        // and leave the pending binding available for a later terminal path.
        let mut premature = core_frame("turn.cancel.accepted", "turn-unforwarded", "");
        delivery.observe_core_frame(&mut premature);
        delivery.send(&premature).unwrap();
        let frames = encoded_frames(&delivery);
        assert!(frames[0].get("broker_request_id").is_none());

        // Once forwarding is recorded, a subsequent exact response may claim
        // the binding and retire the one-shot intent.
        delivery.mark_broker_forwarded(Some(&cancel_binding));
        let mut accepted = core_frame("turn.cancel.accepted", "turn-unforwarded", "");
        delivery.observe_core_frame(&mut accepted);
        delivery.send(&accepted).unwrap();
        let frames = encoded_frames(&delivery);
        assert_eq!(frames[1]["broker_request_id"], "unforwarded-cancel");
    }

    #[test]
    fn unforwarded_active_response_cannot_consume_broker_binding() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let start = turn_start("turn-unforwarded-active", "request");
        let digest = request_digest(&start).unwrap();
        let start_binding = binding("unforwarded-start", 208);
        delivery
            .register_broker_request(&start, Some(start_binding.clone()))
            .unwrap();

        let mut premature = core_frame(
            FRAME_TURN_ACCEPTED,
            "turn-unforwarded-active",
            &digest,
        );
        delivery.observe_core_frame(&mut premature);
        delivery.send(&premature).unwrap();
        let frames = encoded_frames(&delivery);
        assert!(frames[0].get("broker_request_id").is_none());

        delivery.mark_broker_forwarded(Some(&start_binding));
        let mut accepted = core_frame(FRAME_TURN_ACCEPTED, "turn-unforwarded-active", &digest);
        delivery.observe_core_frame(&mut accepted);
        delivery.send(&accepted).unwrap();
        let frames = encoded_frames(&delivery);
        assert_eq!(frames[1]["broker_request_id"], "unforwarded-start");
    }

    #[test]
    fn forwarded_cancel_may_explicitly_own_a_host_error() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let start = turn_start("turn-error-route-forwarded", "request");
        let digest = request_digest(&start).unwrap();
        delivery
            .register_broker_request(&start, Some(binding("turn-request", 203)))
            .unwrap();
        let mut accepted = core_frame(
            FRAME_TURN_ACCEPTED,
            "turn-error-route-forwarded",
            &digest,
        );
        delivery.observe_core_frame(&mut accepted);
        delivery.send(&accepted).unwrap();

        let mut cancel = core_frame("turn.cancel", "turn-error-route-forwarded", "");
        cancel.payload = json!({
            "session_id": "session-router",
            "turn_id": "turn-error-route-forwarded"
        });
        let cancel_binding = binding("cancel-request", 204);
        delivery
            .register_broker_request(&cancel, Some(cancel_binding.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&cancel_binding));

        let mut error = core_frame("host.error", "turn-error-route-forwarded", &digest);
        error.payload["code"] = json!("control_correlation_mismatch");
        delivery.observe_core_frame(&mut error);
        delivery.send(&error).unwrap();
        let frames = encoded_frames(&delivery);
        assert_eq!(frames[1]["broker_request_id"], "cancel-request");
    }

    #[test]
    fn explicit_host_error_request_kind_overrides_forwarding_order() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let start = turn_start("turn-error-route-explicit", "request");
        let digest = request_digest(&start).unwrap();
        let turn_binding = binding("turn-request", 205);
        delivery
            .register_broker_request(&start, Some(turn_binding.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&turn_binding));
        let mut accepted = core_frame(
            FRAME_TURN_ACCEPTED,
            "turn-error-route-explicit",
            &digest,
        );
        delivery.observe_core_frame(&mut accepted);
        delivery.send(&accepted).unwrap();

        let mut cancel = core_frame("turn.cancel", "turn-error-route-explicit", "");
        cancel.payload = json!({
            "session_id": "session-router",
            "turn_id": "turn-error-route-explicit"
        });
        let cancel_binding = binding("cancel-request", 206);
        delivery
            .register_broker_request(&cancel, Some(cancel_binding.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&cancel_binding));

        let mut error = core_frame("host.error", "turn-error-route-explicit", &digest);
        error.payload["request_kind"] = json!("turn.cancel");
        delivery.observe_core_frame(&mut error);
        delivery.send(&error).unwrap();
        let frames = encoded_frames(&delivery);
        assert_eq!(frames[1]["broker_request_id"], "cancel-request");
    }

    #[test]
    fn wait_binding_accepts_inspection_result_or_correlated_error_only() {
        let mut wait = core_frame("job.wait", "turn-wait-router", "");
        wait.turn_stream_id = Some("stream-wait-router".to_string());
        wait.stream_id = Some("stream-wait-router".to_string());
        wait.job_id = Some("job-wait-router".to_string());
        wait.payload = json!({
            "session_id": "session-router",
            "task_id": "task-router",
            "turn_id": "turn-wait-router",
            "turn_stream_id": "stream-wait-router",
            "job_id": "job-wait-router",
            "operation_id": "wait-operation"
        });
        let intent = BrokerBindingIntent {
            binding: binding("wait-request", 40),
            request_kind: "job.wait".to_string(),
            lineage: BrokerLineage::from_frame(&wait).expect("wait lineage"),
            request_digest: None,
            operation_id: Some("wait-operation".to_string()),
            core_floor: None,
            forwarded: false,
            established: false,
        };

        let mut result = wait.clone();
        result.kind = "job.inspect.result".to_string();
        result.payload["wait_status"] = json!("timeout");
        assert!(direct_response_matches(&intent, &result));

        let mut error = wait.clone();
        error.kind = "job.error".to_string();
        assert!(direct_response_matches(&intent, &error));

        let mut unrelated = wait;
        unrelated.kind = "job.result".to_string();
        assert!(!direct_response_matches(&intent, &unrelated));
    }

    #[test]
    fn hello_ack_may_allocate_a_provisional_stream_without_losing_binding() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let hello = RunTurnFrame {
            kind: "hello".to_string(),
            seq: 0,
            payload: json!({"protocol": PROTOCOL, "protocol_version": PROTOCOL_VERSION}),
            direction: Some("client_to_host".to_string()),
            client_seq: None,
            host_seq: None,
            frame_sha256: None,
            event_id: None,
            connection_id: None,
            stream_id: None,
            turn_stream_id: None,
            session_id: None,
            profile_id: None,
            task_id: None,
            turn_id: None,
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: BTreeMap::new(),
        };
        let hello_binding = binding("hello-request", 30);
        delivery
            .register_broker_request(&hello, Some(hello_binding.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&hello_binding));
        let mut ack = core_frame("hello.ack", "unused", "");
        ack.session_id = None;
        ack.task_id = None;
        ack.turn_id = None;
        ack.turn_stream_id = Some("provisional-stream".to_string());
        ack.stream_id = Some("provisional-stream".to_string());
        ack.payload = json!({"turn_stream_id": "provisional-stream"});
        delivery.observe_core_frame(&mut ack);
        delivery.send(&ack).unwrap();
        let frames = encoded_frames(&delivery);
        assert_eq!(frames[0]["broker_request_id"], "hello-request");
    }

    #[test]
    fn explicit_local_response_consumes_its_pending_binding() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let mut control = core_frame("turn.cancel", "turn-local", "");
        control.payload = json!({
            "session_id": "session-router",
            "turn_id": "turn-local"
        });
        let binding = binding("local-control", 31);
        delivery
            .register_broker_request(&control, Some(binding.clone()))
            .unwrap();
        let mut error = core_frame("host.error", "turn-local", "");
        error.payload = json!({"code": "invalid_frame"});
        delivery.send_with_binding(&error, Some(&binding)).unwrap();
        // A later same-lineage frame cannot consume the already-terminal
        // one-shot request's envelope.
        let mut delayed = core_frame("turn.cancel.accepted", "turn-local", "");
        delayed.payload = json!({"turn_id": "turn-local"});
        delivery.observe_core_frame(&mut delayed);
        delivery.send(&delayed).unwrap();
        let frames = encoded_frames(&delivery);
        assert_eq!(frames[0]["broker_request_id"], "local-control");
        assert!(frames[1].get("broker_request_id").is_none());
    }

    #[test]
    fn broker_binding_rejects_conflicting_payload_mirror() {
        let binding = binding("expected", 32);
        let mut frame = core_frame("host.error", "turn-local", "");
        frame.payload = json!({
            "broker_request_id": "stale",
            "broker_request_sha256": "a".repeat(64),
            "broker_request_upstream_seq": 32
        });
        let error = binding
            .apply(&mut frame)
            .expect_err("conflicting payload broker mirror must fail closed");
        assert!(error.contains("payload mirror field broker_request_id"));

        let mut matching = core_frame("host.error", "turn-local", "");
        matching.payload = json!({
            "broker_request_id": "expected",
            "broker_request_sha256": "a".repeat(64),
            "broker_request_upstream_seq": 32
        });
        binding
            .apply(&mut matching)
            .expect("an exact payload mirror is valid");
        assert_eq!(matching.extensions["broker_request_id"], json!("expected"));
    }

    #[test]
    fn conflicting_explicit_mirror_does_not_consume_pending_binding() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let mut request = core_frame("turn.cancel", "turn-pending", "");
        request.payload = json!({
            "session_id": "session-router",
            "turn_id": "turn-pending"
        });
        let request_binding = binding("pending-request", 33);
        delivery
            .register_broker_request(&request, Some(request_binding.clone()))
            .unwrap();

        let mut conflicting = core_frame("host.error", "turn-pending", "");
        conflicting.payload = json!({"broker_request_id": "other"});
        assert!(delivery
            .send_with_binding(&conflicting, Some(&request_binding))
            .is_err());

        let mut matching = core_frame("host.error", "turn-pending", "");
        matching.payload = json!({"code": "cancelled"});
        delivery
            .send_with_binding(&matching, Some(&request_binding))
            .expect("the still-pending binding can resolve a corrected response");
        let frames = encoded_frames(&delivery);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["broker_request_id"], "pending-request");
    }

    #[test]
    fn conflicting_core_mirror_does_not_consume_selected_pending_binding() {
        let mut delivery = ClientDelivery::new(Vec::new(), 1024 * 1024);
        let mut request = core_frame("turn.cancel", "turn-pending-core", "");
        request.payload = json!({
            "session_id": "session-router",
            "turn_id": "turn-pending-core"
        });
        let request_binding = binding("pending-core-request", 34);
        delivery
            .register_broker_request(&request, Some(request_binding.clone()))
            .unwrap();
        delivery.mark_broker_forwarded(Some(&request_binding));

        let mut conflicting = core_frame("turn.cancel.accepted", "turn-pending-core", "");
        conflicting.payload = json!({
            "turn_id": "turn-pending-core",
            "broker_request_id": "stale"
        });
        assert!(delivery.send(&conflicting).is_err());

        let mut corrected = core_frame("turn.cancel.accepted", "turn-pending-core", "");
        corrected.payload = json!({"turn_id": "turn-pending-core"});
        delivery
            .send(&corrected)
            .expect("pending binding remains after mirror conflict");
        let frames = encoded_frames(&delivery);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["broker_request_id"], "pending-core-request");
    }

    #[test]
    fn malformed_frame_can_recover_broker_binding_for_correlated_error() {
        let encoded = br#"{
            "kind":"turn.start",
            "seq":0,
            "direction":"client_to_host",
            "payload":"not-an-object",
            "broker_request_id":"malformed-request",
            "broker_request_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "broker_request_upstream_seq":42
        }"#;
        let recovered = binding_from_encoded_frame(encoded, &MechanicalLimits::default())
            .expect("valid broker envelope should survive semantic decode failure");
        assert_eq!(recovered.request_id, "malformed-request");
        assert_eq!(recovered.upstream_seq, 42);
    }

    #[test]
    fn broker_registration_capacity_rejects_without_mutating_router() {
        let pending = core_frame("job.inspect", "turn-router", "");
        let mut router = BrokerBindingRouter::default();
        for index in 0..MAX_BROKER_PENDING_BINDINGS {
            router
                .register(
                    &pending,
                    Some(binding(&format!("pending-{index}"), index as u64)),
                )
                .expect("entries below the pending cap are accepted");
        }
        let overflow = binding("pending-overflow", MAX_BROKER_PENDING_BINDINGS as u64);
        let error = router
            .check_registration_capacity(&pending, Some(&overflow))
            .expect_err("pending cap must be reported before mutation");
        assert!(error.contains("response binding queue is exhausted"));
        assert_eq!(router.pending.len(), MAX_BROKER_PENDING_BINDINGS);
        assert!(router.register(&pending, Some(overflow)).is_err());
        assert_eq!(router.pending.len(), MAX_BROKER_PENDING_BINDINGS);

        let active = turn_start("turn-cap", "capacity");
        let mut active_router = BrokerBindingRouter::default();
        for index in 0..MAX_BROKER_ACTIVE_BINDINGS {
            active_router
                .register(
                    &active,
                    Some(binding(&format!("active-{index}"), index as u64)),
                )
                .expect("entries below the active cap are accepted");
        }
        let active_overflow = binding("active-overflow", MAX_BROKER_ACTIVE_BINDINGS as u64);
        let error = active_router
            .check_registration_capacity(&active, Some(&active_overflow))
            .expect_err("active cap must be reported before mutation");
        assert!(error.contains("active response binding queue is exhausted"));
        assert_eq!(active_router.active.len(), MAX_BROKER_ACTIVE_BINDINGS);
        assert!(active_router
            .register(&active, Some(active_overflow))
            .is_err());
        assert_eq!(active_router.active.len(), MAX_BROKER_ACTIVE_BINDINGS);
    }

    #[test]
    fn degraded_status_wins_over_an_optimistic_durable_marker() {
        let mut frame = core_frame("job.status", "turn-router", "");
        frame.payload = json!({
            "durable_event_store": true,
            "event_log_status": "unavailable"
        });
        assert!(frame_reports_durable(&frame));
        assert!(frame_reports_unavailable(&frame));
    }

    #[test]
    fn explicit_negative_and_job_journal_statuses_clear_readiness() {
        for payload in [
            json!({"durable_event_store": false}),
            json!({"job_journal_status": "best_effort_unreplayable"}),
            json!({"status": "journal_unavailable"}),
            json!({"event_log_status": "not_configured"}),
        ] {
            let mut frame = core_frame("job.status", "turn-router", "");
            frame.payload = payload;
            assert!(frame_reports_unavailable(&frame));
        }
    }

    #[test]
    fn ordinary_status_without_durability_claim_is_not_a_degradation_signal() {
        let mut frame = core_frame("provider.status", "turn-router", "");
        frame.payload = json!({"status": "running"});
        assert!(!frame_reports_unavailable(&frame));
    }

    #[test]
    fn transport_rehomes_mixed_turn_and_job_sequences_into_one_wire_domain() {
        let mut output = TransportOutput::new();
        let mut hello = core_frame(FRAME_HELLO_ACK, "", "");
        hello.seq = 99;
        hello.host_seq = Some(99);
        let rewritten_hello = output.rewrite_core(hello);
        assert_eq!(rewritten_hello.seq, 0);
        assert_eq!(rewritten_hello.host_seq, None);

        // A core-level error without turn lineage belongs to the connection
        // control domain.  It must not consume the first turn host_seq or
        // acquire a synthetic host_seq merely because it arrived between
        // otherwise scoped job/turn frames.
        let mut host_error = core_frame("host.error", "", "");
        host_error.session_id = None;
        host_error.profile_id = None;
        host_error.task_id = None;
        host_error.turn_id = None;
        host_error.turn_stream_id = None;
        host_error.stream_id = None;
        host_error.payload = json!({"code": "core_failed"});
        let rewritten_error = output.rewrite_core(host_error);
        assert_eq!(rewritten_error.host_seq, None);
        assert_eq!(rewritten_error.seq, 1);

        let mut job_frame = core_frame("job.output", "turn-router", "");
        job_frame.seq = 41;
        job_frame.host_seq = None;
        let rewritten_job = output.rewrite_core(job_frame);

        let mut turn_frame = core_frame("model.delta", "turn-router", "");
        // A turn/job core can independently restart or reuse its local
        // sequence counter.  The transport sequence must nevertheless keep
        // advancing monotonically on the client wire.
        turn_frame.seq = 0;
        turn_frame.host_seq = Some(0);
        let rewritten_turn = output.rewrite_core(turn_frame);

        assert_eq!(rewritten_job.seq, 0);
        assert_eq!(rewritten_job.host_seq, Some(0));
        assert_eq!(rewritten_job.extensions["core_seq"], json!(41));
        assert_eq!(rewritten_turn.seq, 1);
        assert_eq!(rewritten_turn.host_seq, Some(1));
        assert_eq!(rewritten_turn.extensions["core_seq"], json!(0));
        assert_eq!(rewritten_turn.extensions["core_host_seq"], json!(0));
    }

    #[test]
    fn transport_sequences_restart_per_stream_and_mix_core_job_fifo() {
        let mut output = TransportOutput::new();

        let mut stream_a_core = core_frame("model.delta", "turn-a", "");
        stream_a_core.stream_id = Some("stream-a".to_string());
        stream_a_core.turn_stream_id = Some("stream-a".to_string());
        stream_a_core.host_seq = Some(99);
        let stream_a_core = output.rewrite_core(stream_a_core);

        let mut stream_b_core = core_frame("model.delta", "turn-b", "");
        stream_b_core.stream_id = Some("stream-b".to_string());
        stream_b_core.turn_stream_id = Some("stream-b".to_string());
        stream_b_core.host_seq = Some(77);
        let stream_b_core = output.rewrite_core(stream_b_core);

        // A job frame and a normal turn frame sharing stream A consume one
        // FIFO cursor, even though their producer-local host sequences differ.
        let mut stream_a_job = core_frame("job.output", "turn-a", "");
        stream_a_job.stream_id = Some("stream-a".to_string());
        stream_a_job.turn_stream_id = Some("stream-a".to_string());
        stream_a_job.host_seq = None;
        let stream_a_job = output.rewrite_core(stream_a_job);

        let mut stream_a_replay = core_frame("model.message", "turn-a", "");
        stream_a_replay.stream_id = Some("stream-a".to_string());
        stream_a_replay.turn_stream_id = Some("stream-a".to_string());
        stream_a_replay.host_seq = Some(5);
        let stream_a_replay = output.rewrite_core(stream_a_replay);

        assert_eq!(stream_a_core.seq, 0);
        assert_eq!(stream_a_core.host_seq, Some(0));
        assert_eq!(stream_b_core.seq, 0);
        assert_eq!(stream_b_core.host_seq, Some(0));
        assert_eq!(stream_a_job.seq, 1);
        assert_eq!(stream_a_job.host_seq, Some(1));
        assert_eq!(stream_a_replay.seq, 5);
        assert_eq!(stream_a_replay.host_seq, Some(5));
        assert_eq!(stream_a_core.extensions["core_host_seq"], json!(99));
        assert_eq!(stream_b_core.extensions["core_host_seq"], json!(77));
    }

    #[test]
    fn streamless_scoped_core_uses_active_stream_cursor() {
        let mut output = TransportOutput::new();
        let context = TurnContext {
            session_id: "session-active".to_string(),
            profile_id: DEFAULT_PROFILE_ID.to_string(),
            task_id: "task-active".to_string(),
            turn_id: "turn-active".to_string(),
            turn_stream_id: "stream-active".to_string(),
            request_sha256: "a".repeat(64),
        };
        let mut core = core_frame("model.delta", "turn-active", "");
        core.session_id = Some(context.session_id.clone());
        core.task_id = Some(context.task_id.clone());
        core.turn_id = Some(context.turn_id.clone());
        core.host_seq = Some(42);
        let rewritten = output.rewrite_core_with_context(core, Some(&context));
        let local = output.local_frame("stream.pause.ack", json!({}), Some(&context));
        assert_eq!(rewritten.seq, 0);
        assert_eq!(rewritten.host_seq, Some(0));
        assert_eq!(local.seq, 1);
        assert_eq!(local.host_seq, Some(1));
    }

    #[test]
    fn local_event_ids_are_connection_global_across_stream_cursors() {
        let mut output = TransportOutput::new();
        let context_a = TurnContext {
            session_id: "session-a".to_string(),
            profile_id: DEFAULT_PROFILE_ID.to_string(),
            task_id: "task-a".to_string(),
            turn_id: "turn-a".to_string(),
            turn_stream_id: "stream-a".to_string(),
            request_sha256: "a".repeat(64),
        };
        let context_b = TurnContext {
            session_id: "session-b".to_string(),
            profile_id: DEFAULT_PROFILE_ID.to_string(),
            task_id: "task-b".to_string(),
            turn_id: "turn-b".to_string(),
            turn_stream_id: "stream-b".to_string(),
            request_sha256: "b".repeat(64),
        };

        let first = output.local_frame("host.error", json!({}), Some(&context_a));
        let second = output.local_frame("host.error", json!({}), Some(&context_b));

        // Both streams begin their wire cursor at zero, but their transport
        // event identities must remain unique within this connection.
        assert_eq!(first.host_seq, Some(0));
        assert_eq!(second.host_seq, Some(0));
        assert_ne!(first.event_id, second.event_id);
        assert_eq!(
            first.event_id.as_deref().unwrap().split("-event-").last(),
            Some("1")
        );
        assert_eq!(
            second.event_id.as_deref().unwrap().split("-event-").last(),
            Some("2")
        );
    }

    #[test]
    fn preface_control_reservation_prevents_late_hello_collision() {
        let mut output = TransportOutput::new();
        let early = output.local_frame("host.error", json!({"code": "invalid_frame"}), None);
        let mut hello = core_frame(FRAME_HELLO_ACK, "", "");
        hello.seq = 17;
        let rewritten_hello = output.rewrite_core(hello);
        assert_eq!(early.host_seq, None);
        assert_eq!(early.seq, 1);
        assert_eq!(rewritten_hello.seq, 0);
        assert_ne!(early.seq, rewritten_hello.seq);
    }
}
