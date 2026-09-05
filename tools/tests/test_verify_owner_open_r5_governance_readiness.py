from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-r5-governance-readiness.py"
spec = importlib.util.spec_from_file_location("governance_readiness", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

HEAD = "a" * 40
BASE = "b" * 40
POLICY = {
    "required_checks": ["check-a", "check-b"],
    "minimum_approvals": 1,
    "require_conversation_resolution": True,
    "require_signed_commit": True,
}


class GovernanceReadinessTest(unittest.TestCase):
    def base(self):
        branch = {"protected": True, "commit": {"sha": BASE}}
        protection = {
            "required_status_checks": {"contexts": ["check-a", "check-b"]},
            "required_pull_request_reviews": {"required_approving_review_count": 1},
            "required_conversation_resolution": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
        }
        pull = {
            "state": "open",
            "draft": False,
            "mergeable": True,
            "mergeable_state": "clean",
            "head": {"sha": HEAD},
            "base": {"sha": BASE},
            "user": {"login": "author"},
        }
        reviews = [
            {
                "id": 1,
                "user": {"login": "reviewer"},
                "state": "APPROVED",
                "commit_id": HEAD,
                "submitted_at": "2026-08-30T00:00:00Z",
            }
        ]
        checks = {
            "check_runs": [
                {
                    "id": 1,
                    "name": "check-a",
                    "head_sha": HEAD,
                    "status": "completed",
                    "conclusion": "success",
                    "completed_at": "2026-08-30T00:00:00Z",
                },
                {
                    "id": 2,
                    "name": "check-b",
                    "head_sha": HEAD,
                    "status": "completed",
                    "conclusion": "success",
                    "completed_at": "2026-08-30T00:00:00Z",
                },
            ]
        }
        threads = [{"isResolved": True}]
        commit = {"sha": HEAD, "verification": {"verified": True}}
        comparison = {"status": "ahead"}
        return branch, protection, pull, reviews, checks, threads, commit, comparison

    def evaluate(self, *, policy=POLICY, mutate=None):
        values = list(self.base())
        if mutate is not None:
            mutate(values)
        branch, protection, pull, reviews, checks, threads, commit, comparison = values
        return module.evaluate(
            policy,
            branch,
            protection,
            [],
            pull,
            reviews,
            checks,
            HEAD,
            threads=threads,
            commit=commit,
            comparison=comparison,
        )

    def test_complete_observations_never_claim_integration_authority(self):
        result = self.evaluate()
        self.assertFalse(result["readiness_claimed"])
        self.assertFalse(result["ready_for_protected_integration"])
        self.assertFalse(result["promotion_authorized"])
        self.assertEqual(result["blockers"], [])

    def test_unprotected_or_unobservable_main_fails_closed(self):
        result = self.evaluate(mutate=lambda values: values.__setitem__(0, {}))
        self.assertIn("UNOBSERVED:protected_base", result["blockers"])
        self.assertFalse(result["ready_for_protected_integration"])

    def test_latest_failed_or_queued_check_cannot_reuse_older_success(self):
        def mutate(values):
            checks = values[4]["check_runs"]
            checks.append(
                {
                    "id": 9,
                    "name": "check-b",
                    "head_sha": HEAD,
                    "status": "completed",
                    "conclusion": "failure",
                    "completed_at": "2026-08-30T00:01:00Z",
                }
            )
        result = self.evaluate(mutate=mutate)
        self.assertIn(
            "UNSATISFIED:required_checks_successful_on_exact_head",
            result["blockers"],
        )

    def test_required_approval_count_and_stale_reviews_are_observed(self):
        def mutate(values):
            values[1]["required_pull_request_reviews"]["required_approving_review_count"] = 2
            values[3][0]["commit_id"] = "c" * 40
        result = self.evaluate(mutate=mutate)
        self.assertEqual(result["facts"]["approvals_required"], 2)
        self.assertIn(
            "UNSATISFIED:independent_exact_head_approvals", result["blockers"]
        )

    def test_current_head_change_request_blocks_observed_subset(self):
        def mutate(values):
            values[3].append(
                {
                    "id": 2,
                    "user": {"login": "security-reviewer"},
                    "state": "CHANGES_REQUESTED",
                    "commit_id": HEAD,
                    "submitted_at": "2026-08-30T00:02:00Z",
                }
            )
        result = self.evaluate(mutate=mutate)
        self.assertIn(
            "UNSATISFIED:independent_exact_head_approvals", result["blockers"]
        )

    def test_unresolved_thread_unsigned_commit_conflict_and_stale_base_are_explicit(self):
        def mutate(values):
            values[2]["mergeable"] = False
            values[2]["mergeable_state"] = "dirty"
            values[2]["base"]["sha"] = "d" * 40
            values[5][0]["isResolved"] = False
            values[6]["verification"]["verified"] = False
        result = self.evaluate(mutate=mutate)
        expected = {
            "UNSATISFIED:no_unresolved_review_threads",
            "UNSATISFIED:signed_exact_head",
            "UNSATISFIED:mergeable_clean_exact_head",
            "UNSATISFIED:base_tip_matches_pull_snapshot",
        }
        self.assertTrue(expected <= set(result["blockers"]))

    def test_missing_thread_and_signature_snapshots_are_unknown_not_success(self):
        branch, protection, pull, reviews, checks, _, _, comparison = self.base()
        result = module.evaluate(
            POLICY,
            branch,
            protection,
            [],
            pull,
            reviews,
            checks,
            HEAD,
            threads=None,
            commit=None,
            comparison=comparison,
        )
        self.assertIn("UNOBSERVED:no_unresolved_review_threads", result["blockers"])
        self.assertIn("UNOBSERVED:signed_exact_head", result["blockers"])


    def observe_commit(self, snapshot):
        result = self.evaluate(mutate=lambda values: values.__setitem__(6, snapshot))
        for key in ("readiness_claimed", "ready_for_protected_integration",
                    "promotion_authorized", "public_release"):
            self.assertIs(result[key], False)
        self.assertEqual(result["decision"], "NO_INTEGRATION_AUTHORITY")
        return result

    def test_rest_commit_response_observes_nested_verification(self):
        result = self.observe_commit({"sha": HEAD, "commit": {
            "verification": {"verified": True, "reason": "valid"}}})
        self.assertIs(result["facts"]["commit_signature_verified"], True)
        self.assertEqual(result["blockers"], [])

    def test_rest_unsigned_response_is_unsatisfied_not_unobserved(self):
        result = self.observe_commit({"sha": HEAD, "commit": {
            "verification": {"verified": False, "reason": "unsigned"}}})
        self.assertIs(result["facts"]["commit_signature_verified"], False)
        self.assertIn("UNSATISFIED:signed_exact_head", result["blockers"])
        self.assertNotIn("UNOBSERVED:signed_exact_head", result["blockers"])

    def test_git_database_response_observes_flat_verification(self):
        result = self.observe_commit({"sha": HEAD, "verification": {"verified": True}})
        self.assertIs(result["facts"]["commit_signature_verified"], True)

    def test_verification_for_another_commit_cannot_qualify_head(self):
        for value in ({"verification": {"verified": True}},
                      {"commit": {"verification": {"verified": True}}}):
            with self.subTest(value=value):
                result = self.observe_commit({"sha": BASE, **value})
                self.assertIsNone(result["facts"]["commit_signature_verified"])
                self.assertIn("UNOBSERVED:signed_exact_head", result["blockers"])

    def test_verification_without_commit_identity_is_unknown(self):
        result = self.observe_commit({"verification": {"verified": True}})
        self.assertIsNone(result["facts"]["commit_signature_verified"])
        self.assertIn("UNOBSERVED:signed_exact_head", result["blockers"])

    def test_malformed_commit_identity_cannot_be_coerced(self):
        for sha in (None, 1, [], HEAD.upper(), HEAD + "\n", "a" * 39):
            with self.subTest(sha=sha):
                result = self.observe_commit({"sha": sha, "verification": {"verified": True}})
                self.assertIsNone(result["facts"]["commit_signature_verified"])

    def test_conflicting_verification_representations_are_unknown(self):
        for flat, nested in ((True, False), (False, True)):
            result = self.observe_commit({"sha": HEAD, "verification": {"verified": flat},
                "commit": {"verification": {"verified": nested}}})
            self.assertIsNone(result["facts"]["commit_signature_verified"])
            self.assertIn("UNOBSERVED:signed_exact_head", result["blockers"])

    def test_matching_representations_preserve_boolean_observation(self):
        for verified in (True, False):
            result = self.observe_commit({"sha": HEAD, "verification": {"verified": verified},
                "commit": {"verification": {"verified": verified}}})
            self.assertIs(result["facts"]["commit_signature_verified"], verified)

    def test_non_boolean_verification_is_not_truthy_success(self):
        for verified in (1, 0, "true", "false", [], None, {"enabled": True}):
            for nested in (False, True):
                with self.subTest(verified=verified, nested=nested):
                    value = {"verification": {"verified": verified}}
                    result = self.observe_commit({"sha": HEAD, **({"commit": value} if nested else value)})
                    self.assertIsNone(result["facts"]["commit_signature_verified"])

    def test_malformed_duplicate_representation_cannot_fall_back_to_true(self):
        for nested in (None, [], "bad", {"verification": None},
                       {"verification": {"verified": "true"}}):
            with self.subTest(nested=nested):
                result = self.observe_commit({"sha": HEAD, "verification": {"verified": True},
                    "commit": nested})
                self.assertIsNone(result["facts"]["commit_signature_verified"])

    def test_missing_verification_is_unknown(self):
        for snapshot in ({"sha": HEAD}, {"sha": HEAD, "commit": {}}, None, []):
            with self.subTest(snapshot=snapshot):
                result = self.observe_commit(snapshot)
                self.assertIn("UNOBSERVED:signed_exact_head", result["blockers"])

    def test_malformed_flat_representation_cannot_fall_back_to_nested_true(self):
        result = self.observe_commit({"sha": HEAD, "verification": None,
            "commit": {"verification": {"verified": True}}})
        self.assertIsNone(result["facts"]["commit_signature_verified"])


if __name__ == "__main__":
    unittest.main()
