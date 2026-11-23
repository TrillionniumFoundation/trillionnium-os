"""Independent recognizer consumes actual production-generated GBNF."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "action-grammar"))
from gbnf_recognizer import Recognizer

root = Path(sys.argv[1])
grammars = {name: Recognizer((root / name).read_text()) for name in
            ("submit.gbnf", "submit-denied.gbnf", "submit-background.gbnf")}
cases = 0
for node in ("n1", "n2", "n3", "n99"):
    for label in ("query", "", "other"):
        action = dict(reason="当前字段实际提供查询动作", action="submit",
                      observation_id="f91c685bf5f04f5c9a6a3197eade1fed",
                      package="com.example.search", node_label=label, node_id=node)
        raw = json.dumps(action, ensure_ascii=False, separators=(",", ":"))
        for name, grammar in grammars.items():
            expected = name != "submit-denied.gbnf" and node == "n1" and label == "query"
            assert grammar.accepts(raw) == expected, (name, node, label)
            cases += 1
        for field, value in (("keycode", 66), ("text", "query"), ("display_id", 9)):
            extra = dict(action, **{field: value})
            assert not grammars["submit.gbnf"].accepts(json.dumps(extra, ensure_ascii=False, separators=(",", ":")))
            cases += 1
print(json.dumps({"grammar_cases": cases, "passed": True, "native_grammar_model_executed": False}))
