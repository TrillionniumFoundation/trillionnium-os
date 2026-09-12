"""A source-closed gap is not a qualified target; the display must say so."""
from __future__ import annotations
import copy
import unittest
from tools.docs.generate_global_docs import load, summarize_gaps, gap_status, current_state

class GapStatusSummaryTests(unittest.TestCase):
    def fixture(self):
        return {"status_vocabulary": ["OPEN", "SOURCE_CLOSED_PENDING_EVIDENCE", "EXTERNAL_HOLD", "CLOSED"],
                "gaps": [{"id":"a","status":"CLOSED","exit_level":"L1"},
                         {"id":"b","status":"SOURCE_CLOSED_PENDING_EVIDENCE","exit_level":"L2"},
                         {"id":"c","status":"EXTERNAL_HOLD","exit_level":"L5"}]}

    def test_pending_and_held_gaps_are_unresolved(self):
        result = summarize_gaps(self.fixture())
        self.assertEqual(result["statuses"]["OPEN"], 0)
        self.assertEqual(result["unresolved"], 2)
        self.assertEqual(result["total"], 3)
        self.assertEqual(result["closed"], 1)
        self.assertEqual(sum(result["unresolved_by_exit_level"].values()), 2)

    def test_only_explicit_closed_counts_as_resolved(self):
        value = self.fixture()
        for gap in value["gaps"]:
            gap["status"] = "CLOSED"
        result = summarize_gaps(value)
        self.assertEqual(result["unresolved"], 0)
        self.assertEqual(sum(result["unresolved_by_exit_level"].values()), 0)

    def test_summary_does_not_mutate_the_register(self):
        value=self.fixture();before=copy.deepcopy(value)
        summarize_gaps(value)
        self.assertEqual(value,before)

    def test_empty_register_is_not_a_release_authorization(self):
        value=self.fixture();value["gaps"]=[]
        result=summarize_gaps(value)
        self.assertEqual(result["unresolved"],0)
        self.assertNotIn("public_release",result)
        self.assertNotIn("promotion_authorized",result)

    def test_unknown_status_level_or_duplicate_fails(self):
        for field,value in (("status","SOURCE_DONE"),("status",True),("exit_level","L7"),("exit_level",[]),("id","a"),("id",None)):
            with self.subTest(field=field,value=value):
                data=self.fixture();data["gaps"][1][field]=value
                with self.assertRaises(ValueError):summarize_gaps(data)

    def test_bad_vocabulary_or_nonobject_fails(self):
        for vocabulary in ([],["OPEN"]*4,None,[{},"CLOSED"]):
            data=self.fixture();data["status_vocabulary"]=vocabulary
            with self.assertRaises(ValueError):summarize_gaps(data)
        data=self.fixture();data["gaps"][0]=None
        with self.assertRaises(ValueError):summarize_gaps(data)

    def test_checked_in_views_show_exact_unresolved_total(self):
        summary=summarize_gaps(load("gap-register.v2.json"))
        self.assertIn(f"- Unresolved: `{summary['unresolved']}`",gap_status())
        self.assertIn(f"- Unresolved gaps: `{summary['unresolved']}`",current_state())
        self.assertIn("OPEN=0 does not mean",gap_status())
        self.assertEqual(summary["total"],sum(summary["statuses"].values()))

if __name__=="__main__":unittest.main()
