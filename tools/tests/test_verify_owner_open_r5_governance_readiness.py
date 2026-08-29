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
POLICY = {
    "required_checks": ["check-a", "check-b"],
    "minimum_approvals": 1,
    "require_conversation_resolution": True,
}


class GovernanceReadinessTest(unittest.TestCase):
    def base(self):
        branch = {"protected": True}
        protection = {
            "required_status_checks": {"contexts": ["check-a", "check-b"]},
            "required_pull_request_reviews": {"required_approving_review_count": 1},
            "required_conversation_resolution": {"enabled": True},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
        }
        pull = {"head": {"sha": HEAD}, "user": {"login": "author"}}
        reviews = [
            {
                "user": {"login": "reviewer"},
                "state": "APPROVED",
                "commit_id": HEAD,
                "submitted_at": "2026-08-30T00:00:00Z",
            }
        ]
        checks = {
            "check_runs": [
                {"name": "check-a", "head_sha": HEAD, "status": "completed", "conclusion": "success"},
                {"name": "check-b", "head_sha": HEAD, "status": "completed", "conclusion": "success"},
            ]
        }
        return branch, protection, pull, reviews, checks

    def test_complete_controls_are_ready(self):
        branch, protection, pull, reviews, checks = self.base()
        result = module.evaluate(POLICY, branch, protection, [], pull, reviews, checks, HEAD)
        self.assertTrue(result["ready"])
        self.assertTrue(result["observations"]["independent_exact_head_approval"])

    def test_unprotected_main_fails_closed(self):
        branch, protection, pull, reviews, checks = self.base()
        branch["protected"] = False
        result = module.evaluate(POLICY, branch, {}, [], pull, reviews, checks, HEAD)
        self.assertFalse(result["ready"])
        self.assertFalse(result["observations"]["main_protected"])

    def test_stale_or_author_review_is_not_independent(self):
        branch, protection, pull, reviews, checks = self.base()
        reviews[0]["commit_id"] = "b" * 40
        reviews.append(
            {
                "user": {"login": "author"},
                "state": "APPROVED",
                "commit_id": HEAD,
                "submitted_at": "2026-08-30T00:01:00Z",
            }
        )
        result = module.evaluate(POLICY, branch, protection, [], pull, reviews, checks, HEAD)
        self.assertFalse(result["ready"])
        self.assertFalse(result["observations"]["independent_exact_head_approval"])

    def test_missing_exact_head_check_fails(self):
        branch, protection, pull, reviews, checks = self.base()
        checks["check_runs"][1]["conclusion"] = "failure"
        result = module.evaluate(POLICY, branch, protection, [], pull, reviews, checks, HEAD)
        self.assertFalse(result["ready"])
        self.assertFalse(result["observations"]["required_checks_enforced"])


if __name__ == "__main__":
    unittest.main()
