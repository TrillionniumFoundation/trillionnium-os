"""Recognize the actual production prompt GBNFs from a saved failure and boundary cases."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "action-grammar"))
from gbnf_recognizer import Recognizer

directory = Path(sys.argv[1])
cases = json.loads((directory / "CASES.json").read_text())
assert cases["schema"] == "hepta.text-only-click-host.v1"
assert cases["phone_contacted"] is False
grammars = {}
for row in cases["cases"]:
    assert row["grammar"] in {"actual.gbnf", "boundary.gbnf"}
    if row["grammar"] not in grammars:
        grammars[row["grammar"]] = Recognizer((directory / row["grammar"]).read_text())
    actual = grammars[row["grammar"]].accepts(row["json"])
    assert actual is row["accepted"], (row["name"], actual, row["accepted"])
assert len(cases["cases"]) == 16
print(json.dumps({"text_only_click_grammar_cases": len(cases["cases"]),
    "saved_failure_fixture_sha256": cases["saved_failure_fixture_sha256"],
    "native_grammar_executed": False, "phone_contacted": False}))
