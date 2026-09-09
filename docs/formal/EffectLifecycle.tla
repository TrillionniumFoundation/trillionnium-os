---- MODULE EffectLifecycle ----
EXTENDS Naturals, Sequences, FiniteSets

(*
Source-only formal projection of docs/machine/effect-lifecycle.v1.json.
The executable Python verifier checks this projection byte-semantically against
all 27 machine transitions and explores the finite state/knowledge product.
It does not claim installed-target, device, destructive-fault or release proof.
*)

States == {
  "RECEIVED",
  "VALIDATED",
  "CAPACITY_RESERVED",
  "ACCEPTED_DURABLE",
  "EFFECT_ATTEMPTING",
  "EFFECT_STARTED_OBSERVED",
  "TERMINAL_OBSERVED",
  "TERMINAL_DURABLE",
  "DELIVERY_PENDING",
  "DELIVERED",
  "ACKNOWLEDGED",
  "REJECTED_BEFORE_EFFECT",
  "UNKNOWN_RECONCILIATION_REQUIRED",
  "FENCED",
  "CLOSED"
}

Edges == {
  <<"RECEIVED", "VALIDATED">>,
  <<"RECEIVED", "REJECTED_BEFORE_EFFECT">>,
  <<"VALIDATED", "CAPACITY_RESERVED">>,
  <<"VALIDATED", "REJECTED_BEFORE_EFFECT">>,
  <<"CAPACITY_RESERVED", "ACCEPTED_DURABLE">>,
  <<"CAPACITY_RESERVED", "REJECTED_BEFORE_EFFECT">>,
  <<"CAPACITY_RESERVED", "FENCED">>,
  <<"ACCEPTED_DURABLE", "EFFECT_ATTEMPTING">>,
  <<"ACCEPTED_DURABLE", "TERMINAL_OBSERVED">>,
  <<"ACCEPTED_DURABLE", "FENCED">>,
  <<"EFFECT_ATTEMPTING", "EFFECT_STARTED_OBSERVED">>,
  <<"EFFECT_ATTEMPTING", "TERMINAL_OBSERVED">>,
  <<"EFFECT_ATTEMPTING", "UNKNOWN_RECONCILIATION_REQUIRED">>,
  <<"EFFECT_STARTED_OBSERVED", "TERMINAL_OBSERVED">>,
  <<"EFFECT_STARTED_OBSERVED", "UNKNOWN_RECONCILIATION_REQUIRED">>,
  <<"TERMINAL_OBSERVED", "TERMINAL_DURABLE">>,
  <<"TERMINAL_OBSERVED", "UNKNOWN_RECONCILIATION_REQUIRED">>,
  <<"TERMINAL_DURABLE", "DELIVERY_PENDING">>,
  <<"DELIVERY_PENDING", "DELIVERED">>,
  <<"DELIVERY_PENDING", "DELIVERY_PENDING">>,
  <<"DELIVERED", "ACKNOWLEDGED">>,
  <<"DELIVERED", "DELIVERY_PENDING">>,
  <<"ACKNOWLEDGED", "CLOSED">>,
  <<"REJECTED_BEFORE_EFFECT", "CLOSED">>,
  <<"UNKNOWN_RECONCILIATION_REQUIRED", "TERMINAL_OBSERVED">>,
  <<"UNKNOWN_RECONCILIATION_REQUIRED", "FENCED">>,
  <<"FENCED", "CLOSED">>
}

VARIABLES state, accepted, attempted, terminalDurable, delivered, acknowledged,
          automaticRedispatch

vars == <<state, accepted, attempted, terminalDurable, delivered, acknowledged,
          automaticRedispatch>>

Init ==
  /\ state = "RECEIVED"
  /\ accepted = FALSE
  /\ attempted = FALSE
  /\ terminalDurable = FALSE
  /\ delivered = FALSE
  /\ acknowledged = FALSE
  /\ automaticRedispatch = FALSE

Next ==
  \E edge \in Edges:
    /\ edge[1] = state
    /\ state' = edge[2]
    /\ accepted' = (accepted \/ edge[2] = "ACCEPTED_DURABLE")
    /\ attempted' = (attempted \/ edge = <<"ACCEPTED_DURABLE", "EFFECT_ATTEMPTING">>)
    /\ terminalDurable' = (terminalDurable \/ edge[2] = "TERMINAL_DURABLE")
    /\ delivered' = (delivered \/ edge[2] = "DELIVERED")
    /\ acknowledged' = (acknowledged \/ edge[2] = "ACKNOWLEDGED")
    /\ automaticRedispatch' = FALSE

TypeOK ==
  /\ state \in States
  /\ accepted \in BOOLEAN
  /\ attempted \in BOOLEAN
  /\ terminalDurable \in BOOLEAN
  /\ delivered \in BOOLEAN
  /\ acknowledged \in BOOLEAN
  /\ automaticRedispatch \in BOOLEAN

NoAutomaticRedispatch == automaticRedispatch = FALSE

EffectRequiresDurableAcceptance ==
  (state = "EFFECT_ATTEMPTING") => accepted

DeliveryRequiresDurableTerminal ==
  (state \in {"DELIVERY_PENDING", "DELIVERED", "ACKNOWLEDGED"}) => terminalDurable

AcknowledgementRequiresDelivery ==
  (state = "ACKNOWLEDGED") => delivered

Spec == Init /\ [][Next]_vars

====
