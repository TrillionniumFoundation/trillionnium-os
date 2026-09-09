"""Hostile regressions for the machine-authoritative effect lifecycle."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.docs import verify_effect_lifecycle as verifier

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY = ROOT / "docs/machine/effect-lifecycle.v1.json"
MODEL = ROOT / "docs/formal/EffectLifecycle.tla"
CONFIG = ROOT / "docs/formal/EffectLifecycle.cfg"


def authority() -> dict:
    return json.loads(AUTHORITY.read_text(encoding="utf-8"))


class LegalAndIllegalTransitionExhaustionTests(unittest.TestCase):
    def test_checked_in_model_exhausts_every_ordered_pair(self) -> None:
        report = verifier.verify_authority(authority(), root=ROOT, model_check=True)
        self.assertEqual(report["state_count"], 15)
        self.assertEqual(report["transition_count"], 27)
        self.assertEqual(report["exhaustive_ordered_pair_count"], 225)
        self.assertEqual(report["legal_ordered_pair_count"], 27)
        self.assertEqual(report["illegal_ordered_pair_count"], 198)
        self.assertGreater(report["reachable_product_state_count"], 15)
        self.assertFalse(report["automatic_redispatch"])

    def test_duplicate_ordered_pair_fails_closed(self) -> None:
        value = authority()
        value["transitions"][-1]["from"] = value["transitions"][-2]["from"]
        value["transitions"][-1]["to"] = value["transitions"][-2]["to"]
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate ordered transition"):
            verifier.verify_authority(value, root=ROOT)

    def test_effect_boundary_from_pre_durable_state_fails(self) -> None:
        value = authority()
        value["transitions"][7]["from"] = "CAPACITY_RESERVED"
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_authority(value, root=ROOT)

    def test_delivery_before_terminal_durability_fails(self) -> None:
        value = authority()
        value["transitions"][17]["from"] = "TERMINAL_OBSERVED"
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_authority(value, root=ROOT)


class DuplicateAndConflictMutationTests(unittest.TestCase):
    def test_changed_bytes_cannot_attach_or_replay(self) -> None:
        value = authority()
        value["duplicate_policy"]["exact_identity_changed_bytes"] = (
            "ATTACH_OR_REPLAY_KNOWN_STATE"
        )
        with self.assertRaisesRegex(verifier.VerificationError, "changed-byte duplicate"):
            verifier.verify_authority(value, root=ROOT)

    def test_alias_cannot_preserve_effect_identity(self) -> None:
        value = authority()
        value["duplicate_policy"]["field_aliases_change_identity"] = False
        with self.assertRaisesRegex(verifier.VerificationError, "aliases"):
            verifier.verify_authority(value, root=ROOT)

    def test_transition_cannot_drop_request_digest(self) -> None:
        value = authority()
        value["transitions"][7]["bindings"].remove("request_digest")
        with self.assertRaisesRegex(verifier.VerificationError, "binding set/order"):
            verifier.verify_authority(value, root=ROOT)


class CancelTerminalLinearizationTests(unittest.TestCase):
    def test_linearization_field_is_durable_sequence(self) -> None:
        value = authority()
        value["race_policy"]["linearization_field"] = "monotonic_timestamp_ns"
        with self.assertRaisesRegex(verifier.VerificationError, "linearize"):
            verifier.verify_authority(value, root=ROOT)

    def test_cleanup_error_cannot_become_primary(self) -> None:
        value = authority()
        value["race_policy"]["cleanup_error_role"] = "OVERWRITE_PRIMARY_OUTCOME"
        with self.assertRaisesRegex(verifier.VerificationError, "cleanup"):
            verifier.verify_authority(value, root=ROOT)

    def test_race_policy_never_enables_redispatch(self) -> None:
        value = authority()
        value["race_policy"]["automatic_redispatch"] = True
        with self.assertRaisesRegex(verifier.VerificationError, "redispatch"):
            verifier.verify_authority(value, root=ROOT)


class CrashCutRecoveryTests(unittest.TestCase):
    def test_attempt_cut_cannot_recover_to_validated(self) -> None:
        value = authority()
        cut = next(item for item in value["crash_cuts"] if item["after"] == "EFFECT_ATTEMPTING")
        cut["legal_recovery"].append("VALIDATED")
        with self.assertRaisesRegex(verifier.VerificationError, "pre-effect state"):
            verifier.verify_authority(value, root=ROOT)

    def test_unknown_cut_must_forbid_safe_retry(self) -> None:
        value = authority()
        cut = next(
            item
            for item in value["crash_cuts"]
            if item["after"] == "UNKNOWN_RECONCILIATION_REQUIRED"
        )
        cut["forbidden_inference"] = ["cancelled_without_proof"]
        with self.assertRaisesRegex(verifier.VerificationError, "safe/not-started"):
            verifier.verify_authority(value, root=ROOT)

    def test_crash_cut_cannot_enable_automatic_redispatch(self) -> None:
        value = authority()
        value["crash_cuts"][4]["automatic_redispatch"] = True
        with self.assertRaisesRegex(verifier.VerificationError, "redispatch"):
            verifier.verify_authority(value, root=ROOT)


class FormalProjectionEquivalenceTests(unittest.TestCase):
    def test_checked_in_tla_projection_is_exact(self) -> None:
        report = verifier.verify_authority(authority(), root=ROOT, model_check=True)
        self.assertEqual(report["formal_state_count"], 15)
        self.assertEqual(report["formal_edge_count"], 27)

    def test_formal_edge_drift_fails_closed(self) -> None:
        model = MODEL.read_text(encoding="utf-8").replace(
            '<<"RECEIVED", "VALIDATED">>',
            '<<"RECEIVED", "CLOSED">>',
            1,
        )
        with self.assertRaisesRegex(verifier.VerificationError, "formal edge projection"):
            verifier.verify_authority(authority(), root=ROOT, formal_text=model)

    def test_missing_formal_invariant_fails_closed(self) -> None:
        config = CONFIG.read_text(encoding="utf-8").replace(
            "INVARIANT NoAutomaticRedispatch\n", "", 1
        )
        with self.assertRaisesRegex(verifier.VerificationError, "formal config invariants"):
            verifier.verify_authority(authority(), root=ROOT, config_text=config)


class ImplementationBindingTotalityTests(unittest.TestCase):
    def test_every_transition_has_a_real_source_and_test_binding(self) -> None:
        report = verifier.verify_authority(authority(), root=ROOT)
        self.assertEqual(report["implementation_transition_coverage"], 27)
        self.assertEqual(report["implementation_binding_count"], 9)

    def test_dropped_mapping_fails_closed(self) -> None:
        value = authority()
        for binding in value["implementation_bindings"]:
            if "TR-27" in binding["transitions"]:
                binding["transitions"].remove("TR-27")
        with self.assertRaisesRegex(verifier.VerificationError, "mapping is not total"):
            verifier.verify_authority(value, root=ROOT)

    def test_missing_symbol_fails_closed(self) -> None:
        value = authority()
        value["implementation_bindings"][0]["symbol"] = "definitely_not_a_real_symbol"
        with self.assertRaisesRegex(verifier.VerificationError, "symbol not found"):
            verifier.verify_authority(value, root=ROOT)

    def test_unknown_module_fails_closed(self) -> None:
        value = authority()
        value["implementation_bindings"][0]["modules"].append("MOD-NOT-REAL")
        with self.assertRaisesRegex(verifier.VerificationError, "unknown modules"):
            verifier.verify_authority(value, root=ROOT)


class GlobalNoRedispatchTests(unittest.TestCase):
    def test_any_transition_redispatch_flag_fails(self) -> None:
        value = authority()
        value["transitions"][12]["automatic_redispatch"] = True
        with self.assertRaisesRegex(verifier.VerificationError, "redispatch"):
            verifier.verify_authority(value, root=ROOT)

    def test_top_level_redispatch_flag_fails(self) -> None:
        value = authority()
        value["automatic_redispatch"] = True
        with self.assertRaisesRegex(verifier.VerificationError, "redispatch"):
            verifier.verify_authority(value, root=ROOT)


if __name__ == "__main__":
    unittest.main()
