#!/usr/bin/env python3

from __future__ import annotations

import dataclasses
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
PACKAGE_ROOT = HERE.parent
sys.path.insert(0, str(PACKAGE_ROOT))

import publication_custody_model as model  # noqa: E402


def complete_barrier() -> model.BarrierFacts:
    return model.BarrierFacts(
        **{item.name: True for item in dataclasses.fields(model.BarrierFacts)}
    )


class PublicationCustodyModelTests(unittest.TestCase):
    def test_transition_table_is_exhaustive_and_closed(self) -> None:
        barrier = complete_barrier()
        admitted = {
            (False, False, None, model.Placement.STAGE_ONLY): model.Action.CREATE_INTENT,
            (True, False, None, model.Placement.STAGE_ONLY): model.Action.CREATE_RENAME_ATTEMPTED,
            (True, True, None, model.Placement.STAGE_ONLY): model.Action.RENAME_NOREPLACE,
            (True, True, None, model.Placement.FINAL_ONLY): model.Action.VERIFY_AND_RESOLVE_COMMITTED,
            (True, True, "committed", model.Placement.FINAL_ONLY): model.Action.RETURN_COMMITTED,
            (True, True, "aborted", model.Placement.STAGE_ONLY): model.Action.RETURN_ABORTED,
        }
        observed = 0
        for intent in (False, True):
            for attempted in (False, True):
                for resolved in (None, "committed", "aborted", "unknown"):
                    for placement in model.Placement:
                        with self.subTest(
                            intent=intent,
                            attempted=attempted,
                            resolved=resolved,
                            placement=placement,
                        ):
                            state = model.JournalState(intent, attempted, resolved)
                            expected = admitted.get(
                                (intent, attempted, resolved, placement),
                                model.Action.HOLD,
                            )
                            self.assertEqual(
                                model.next_action(state, placement, barrier),
                                expected,
                            )
                            observed += 1
        self.assertEqual(observed, 64)

    def test_each_missing_or_non_boolean_barrier_fact_holds(self) -> None:
        state = model.JournalState(False, False)
        complete = complete_barrier()
        self.assertEqual(
            model.next_action(state, model.Placement.STAGE_ONLY, complete),
            model.Action.CREATE_INTENT,
        )
        for field in dataclasses.fields(model.BarrierFacts):
            for invalid in (False, 0, 1, None):
                with self.subTest(field=field.name, invalid=invalid):
                    changed = dataclasses.replace(complete, **{field.name: invalid})
                    self.assertEqual(
                        model.next_action(
                            state,
                            model.Placement.STAGE_ONLY,
                            changed,
                        ),
                        model.Action.HOLD,
                    )

    def test_malformed_state_and_placement_hold(self) -> None:
        class ForgedString(str):
            pass

        class AlwaysEqual:
            def __eq__(self, _other: object) -> bool:
                return True

        barrier = complete_barrier()
        malformed = (
            None,
            {},
            model.JournalState(0, False),
            model.JournalState(False, 0),
            model.JournalState(False, False, 0),
            model.JournalState(False, False, False),
            model.JournalState(False, True),
            model.JournalState(False, False, "committed"),
            model.JournalState(True, False, "aborted"),
            model.JournalState(True, True, ForgedString("committed")),
            model.JournalState(True, True, AlwaysEqual()),
        )
        for state in malformed:
            with self.subTest(state=state):
                self.assertEqual(
                    model.next_action(state, model.Placement.STAGE_ONLY, barrier),
                    model.Action.HOLD,
                )
        for placement in (None, "stage-only", 0):
            with self.subTest(placement=placement):
                self.assertEqual(
                    model.next_action(
                        model.JournalState(False, False),
                        placement,
                        barrier,
                    ),
                    model.Action.HOLD,
                )

    def test_rename_return_table_covers_success_error_and_ambiguity(self) -> None:
        barrier = complete_barrier()
        state = model.JournalState(True, True)
        expected = {
            (True, model.Placement.FINAL_ONLY): model.Action.VERIFY_AND_RESOLVE_COMMITTED,
            (False, model.Placement.FINAL_ONLY): model.Action.VERIFY_AND_RESOLVE_COMMITTED,
            (False, model.Placement.STAGE_ONLY): model.Action.RESOLVE_ABORTED,
        }
        for succeeded in (False, True):
            for placement in model.Placement:
                with self.subTest(succeeded=succeeded, placement=placement):
                    self.assertEqual(
                        model.classify_rename_return(
                            state,
                            succeeded,
                            placement,
                            barrier,
                        ),
                        expected.get((succeeded, placement), model.Action.HOLD),
                    )

    def test_rename_classification_requires_attempted_unresolved_state(self) -> None:
        barrier = complete_barrier()
        for intent in (False, True):
            for attempted in (False, True):
                for resolved in (None, "committed", "aborted", "unknown"):
                    state = model.JournalState(intent, attempted, resolved)
                    expected = (
                        model.Action.RESOLVE_ABORTED
                        if (intent, attempted, resolved) == (True, True, None)
                        else model.Action.HOLD
                    )
                    with self.subTest(state=state):
                        self.assertEqual(
                            model.classify_rename_return(
                                state,
                                False,
                                model.Placement.STAGE_ONLY,
                                barrier,
                            ),
                            expected,
                        )

    def test_rename_classification_rejects_malformed_or_stale_facts(self) -> None:
        complete = complete_barrier()
        stale = dataclasses.replace(complete, external_hold_absent=False)
        valid_state = model.JournalState(True, True)
        for state, succeeded, placement, barrier in (
            (None, False, model.Placement.STAGE_ONLY, complete),
            (
                model.JournalState(False, False),
                False,
                model.Placement.STAGE_ONLY,
                complete,
            ),
            (valid_state, 1, model.Placement.FINAL_ONLY, complete),
            (valid_state, 0, model.Placement.FINAL_ONLY, complete),
            (valid_state, None, model.Placement.FINAL_ONLY, complete),
            (valid_state, False, "stage-only", complete),
            (valid_state, False, model.Placement.STAGE_ONLY, stale),
            (valid_state, False, model.Placement.STAGE_ONLY, None),
        ):
            with self.subTest(
                state=state,
                succeeded=succeeded,
                placement=placement,
                barrier=barrier,
            ):
                self.assertEqual(
                    model.classify_rename_return(
                        state,
                        succeeded,
                        placement,
                        barrier,
                    ),
                    model.Action.HOLD,
                )

    def test_module_has_no_publisher_or_effect_surface(self) -> None:
        for forbidden in (
            "CustodyPublisher",
            "publish_bundle",
            "renameat2",
            "write_record",
            "arm_hold",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertFalse(hasattr(model, forbidden))


if __name__ == "__main__":
    unittest.main()
