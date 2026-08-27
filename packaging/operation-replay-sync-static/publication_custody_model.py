#!/usr/bin/env python3
"""Pure source-only model of held replay-sync publication transitions.

This module performs no I/O and is not a publisher.  It consumes observations
that a future outer-owned custody implementation would first have to
authenticate and retain.  It therefore does not establish fixed custody,
durability, an external permanent-HOLD acknowledgement, or authority.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum


class Placement(str, Enum):
    """Exact retained-inode placement after a named-edge revalidation."""

    STAGE_ONLY = "stage-only"
    FINAL_ONLY = "final-only"
    BOTH = "both"
    NEITHER = "neither"


class Action(str, Enum):
    """The only actions admitted by the closed source model."""

    CREATE_INTENT = "create-intent"
    CREATE_RENAME_ATTEMPTED = "create-rename-attempted"
    RENAME_NOREPLACE = "rename-noreplace"
    VERIFY_AND_RESOLVE_COMMITTED = "verify-and-resolve-committed"
    RESOLVE_ABORTED = "resolve-aborted"
    RETURN_COMMITTED = "return-committed"
    RETURN_ABORTED = "return-aborted"
    HOLD = "hold"


@dataclass(frozen=True)
class JournalState:
    """Observed immutable record state for one already-bound operation."""

    intent: bool
    rename_attempted: bool
    resolved: str | None = None


@dataclass(frozen=True)
class BarrierFacts:
    """Facts a future outer implementation must freshly prove at each step.

    The model cannot produce these facts.  A caller must re-establish every
    fact immediately before each external effect and again before every
    terminal return; stale facts are not reusable across a transition.
    """

    fixed_journal_root_retained: bool
    fixed_external_hold_root_retained: bool
    external_hold_absent: bool
    target_lock_retained: bool
    target_binding_revalidated: bool
    canonical_records_revalidated: bool
    candidate_identity_revalidated: bool
    named_placement_revalidated: bool

    def all_exact_true(self) -> bool:
        """Reject integer truthiness and every partial or stale observation."""

        return all(
            type(getattr(self, item.name)) is bool and getattr(self, item.name)
            for item in fields(self)
        )


def _valid_state(state: object) -> bool:
    if type(state) is not JournalState:
        return False
    if type(state.intent) is not bool or type(state.rename_attempted) is not bool:
        return False
    if state.resolved is not None and (
        type(state.resolved) is not str
        or state.resolved not in ("committed", "aborted")
    ):
        return False
    if state.rename_attempted and not state.intent:
        return False
    if state.resolved is not None and not (state.intent and state.rename_attempted):
        return False
    return True


def next_action(
    state: object,
    placement: object,
    barrier: object,
) -> Action:
    """Return the sole allowed next action, or fail closed with ``HOLD``.

    ``barrier`` represents a fresh pre-effect or pre-return observation.  The
    function is deliberately total over malformed Python inputs so schema
    drift, integer/boolean confusion, ambiguous placement, and missing custody
    evidence cannot accidentally select an effect.
    """

    if (
        not _valid_state(state)
        or type(placement) is not Placement
        or type(barrier) is not BarrierFacts
        or not barrier.all_exact_true()
    ):
        return Action.HOLD

    assert type(state) is JournalState
    if state.resolved == "committed":
        return (
            Action.RETURN_COMMITTED
            if placement is Placement.FINAL_ONLY
            else Action.HOLD
        )
    if state.resolved == "aborted":
        return (
            Action.RETURN_ABORTED
            if placement is Placement.STAGE_ONLY
            else Action.HOLD
        )
    if not state.intent:
        return (
            Action.CREATE_INTENT
            if placement is Placement.STAGE_ONLY
            else Action.HOLD
        )
    if not state.rename_attempted:
        return (
            Action.CREATE_RENAME_ATTEMPTED
            if placement is Placement.STAGE_ONLY
            else Action.HOLD
        )
    if placement is Placement.STAGE_ONLY:
        return Action.RENAME_NOREPLACE
    if placement is Placement.FINAL_ONLY:
        return Action.VERIFY_AND_RESOLVE_COMMITTED
    return Action.HOLD


def classify_rename_return(
    state: object,
    syscall_succeeded: object,
    placement: object,
    barrier: object,
) -> Action:
    """Classify the retained names after ``RENAME_NOREPLACE`` returns.

    Only an exact attempted-but-unresolved journal state is admissible.  A
    returned error may still have committed.  Only exact final-only placement
    can enter committed verification.  Exact stage-only placement can resolve
    aborted only after an error.  Success with stage-only, and all both/
    neither/malformed observations, are permanently ambiguous here.
    """

    if (
        not _valid_state(state)
        or state != JournalState(True, True, None)
        or type(syscall_succeeded) is not bool
        or type(placement) is not Placement
        or type(barrier) is not BarrierFacts
        or not barrier.all_exact_true()
    ):
        return Action.HOLD
    if placement is Placement.FINAL_ONLY:
        return Action.VERIFY_AND_RESOLVE_COMMITTED
    if not syscall_succeeded and placement is Placement.STAGE_ONLY:
        return Action.RESOLVE_ABORTED
    return Action.HOLD
