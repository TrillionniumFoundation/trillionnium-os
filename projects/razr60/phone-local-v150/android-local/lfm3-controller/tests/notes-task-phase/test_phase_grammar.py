"""Recognize emitted production phase grammars; no phone or model involved."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "action-grammar"))
from gbnf_recognizer import Recognizer

cases = json.loads(Path(sys.argv[1]).read_text())
for case in cases:
    actual = Recognizer(case["grammar"]).accepts(case["json"])
    if actual is not case["accepted"]:
        raise AssertionError(case["name"])
print(f"PASS {len(cases)} production phase grammar cases; phone_tested=false")
